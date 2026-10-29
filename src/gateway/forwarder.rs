//! DNS Forwarder with Smart CNAME Chasing
//!
//! Forwards DNS queries to MIMIR backend with intelligent CNAME resolution.
//! Automatically follows CNAME chains to ensure clients receive complete answers.

use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use tracing::{debug, warn, info};

use crate::gateway::loadbalancer::LoadBalancer;
use crate::gateway::GatewayStats;
use std::net::{IpAddr, SocketAddr};
use trust_dns_proto::op::{Message, Query, ResponseCode};
use trust_dns_proto::rr::{Name, RecordType, RData};

/// Game-critical domain patterns that should be retried on failure
const GAME_CRITICAL_PATTERNS: &[&str] = &[
    "supercell", "brawlstars", "clashofclans", "clashroyale",
    "roblox", "minecraft", "mihoyo", "genshin", "hoyoverse",
    "garena", "freefire", "pubg", "mobilelegends", "moonton",
    "riot", "valorant", "leagueoflegends",
    "epicgames", "fortnite", "steam", "valve",
    "ea.com", "origin", "battlenet", "blizzard",
    "playstation", "xbox", "nintendo",
];

/// DNS Forwarder to MIMIR with Smart CNAME Chasing
pub struct DnsForwarder {
    load_balancer: Arc<LoadBalancer>,
    stats: Arc<GatewayStats>,
    timeout: Duration,
}

impl DnsForwarder {
    pub async fn new(load_balancer: Arc<LoadBalancer>, stats: Arc<GatewayStats>) -> Result<Self> {
        Ok(Self {
            load_balancer,
            stats,
            timeout: Duration::from_secs(10),  // Increased for deep CDN chains
        })
    }
    
    /// Check if domain is game-critical and should be retried on failure
    fn is_game_critical(domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        GAME_CRITICAL_PATTERNS.iter().any(|pattern| domain_lower.contains(pattern))
    }
    
    /// Forward a DNS query with Smart CNAME Chasing
    /// Automatically follows CNAME chains up to 10 levels deep
    pub async fn forward(&self, query_bytes: &[u8], client_ip: IpAddr) -> Result<Bytes> {
        if query_bytes.len() < 12 {
            return Err(anyhow!("Invalid DNS query length: {}", query_bytes.len()));
        }

        // Parse the original query
        let original_msg = Message::from_vec(query_bytes)?;
        let original_id = original_msg.id();
        
        let query_item = original_msg.queries().first()
            .ok_or_else(|| anyhow!("No query in message"))?;
        let original_qname = query_item.name().clone();
        let qtype = query_item.query_type();
        
        debug!("[ODIN] Query ID {} for {} type {:?}", original_id, original_qname, qtype);
        
        // Start CNAME chasing loop
        let mut current_qname = original_qname.clone();
        let mut all_answers = Vec::new();
        let mut depth = 0;
        let mut last_rcode = ResponseCode::NoError; // Track backend response code
        const MAX_DEPTH: usize = 10;
        
        while depth < MAX_DEPTH {
            // Build query for current name
            let mut next_query = Message::new();
            next_query.set_id(rand::random());
            next_query.set_recursion_desired(true);
            next_query.add_query(Query::query(current_qname.clone(), qtype));
            
            let query_vec = next_query.to_vec()?;
            
            // Send to backend
            let backend = match self.load_balancer.select(client_ip).await {
                Some(b) => b,
                None => {
                    warn!("[SmartChasing] ❌ No healthy backends available");
                    // CRITICAL FIX: Return ServFail instead of error to prevent DNS leak
                    last_rcode = ResponseCode::ServFail;
                    break;
                }
            };
            
            debug!("[SmartChasing] [Depth {}] Querying {} via {}", depth, current_qname, backend.name);
            
            // Send query with retry logic for game-critical domains
            let is_critical = Self::is_game_critical(&current_qname.to_string());
            let max_retries = if is_critical { 3 } else { 1 };
            
            let mut response_msg = None;
            for retry in 0..max_retries {
                // For retries, try a different backend
                let retry_backend = if retry > 0 {
                    if is_critical {
                        info!("[SmartChasing] 🔄 Retry {}/{} for game-critical domain: {}", retry, max_retries - 1, current_qname);
                    }
                    match self.load_balancer.select(client_ip).await {
                        Some(b) => b,
                        None => {
                            warn!("[SmartChasing] ❌ No backends for retry");
                            break; // Will trigger ServFail below
                        }
                    }
                } else {
                    backend.clone()
                };
                
                match self.send_udp(&retry_backend.address, &query_vec).await {
                    Ok(response_bytes) => {
                        match Message::from_vec(&response_bytes) {
                            Ok(msg) => {
                                response_msg = Some(msg);
                                break;
                            }
                            Err(e) => {
                                warn!("[SmartChasing] ⚠️ Failed to parse response at depth {}: {}", depth, e);
                                if retry == max_retries - 1 { break; }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[SmartChasing] ⚠️ Query failed for {} at depth {} (attempt {}): {}", 
                              current_qname, depth, retry + 1, e);
                        if retry == max_retries - 1 { break; }
                        // Small delay before retry
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            
            let response_msg = match response_msg {
                Some(msg) => msg,
                None => {
                    if is_critical {
                        warn!("[SmartChasing] ❌ All {} retries failed for game-critical domain: {}", max_retries, current_qname);
                    }
                    // CRITICAL FIX: When backend fails completely, return ServFail
                    // Returning NoError with 0 answers causes DNS leak (browser falls back to ISP)
                    if depth == 0 {
                        last_rcode = ResponseCode::ServFail;
                    }
                    break;
                }
            };
            
            // Check response code first
            let rcode = response_msg.response_code();
            if rcode != ResponseCode::NoError {
                if depth == 0 && rcode == ResponseCode::ServFail {
                    let qname = current_qname.to_ascii().to_lowercase();
                    if qname.ends_with(".dns6.browserleaks.org.") {
                        last_rcode = ResponseCode::NXDomain;
                        break;
                    }
                }
                warn!("[SmartChasing] 🚫 Backend returned {:?} for {} at depth {} (this is why chain stops!)", 
                      rcode, current_qname, depth);
                // CRITICAL: Preserve error response code to prevent DNS leak
                // If we return NoError with 0 answers, browsers fall back to ISP DNS
                if depth == 0 {
                    last_rcode = rcode; // Preserve error at root query
                }
                break;
            }
            
            // Collect answers from this response
            let answer_count = response_msg.answers().len();
            for record in response_msg.answers() {
                all_answers.push(record.clone());
            }
            
            debug!("[SmartChasing] [Depth {}] Got {} answers", depth, answer_count);
            
            // Check if we have a terminal record (A or AAAA)
            let has_terminal = response_msg.answers().iter().any(|r| {
                matches!(r.record_type(), RecordType::A | RecordType::AAAA)
            });
            
            if has_terminal {
                info!("[SmartChasing] ✅ Resolved {} to IP at depth {}", original_qname, depth);
                break;
            }
            
            // Look for CNAME to follow
            let cname_target = response_msg.answers().iter()
                .find(|r| r.record_type() == RecordType::CNAME)
                .and_then(|r| {
                    if let Some(RData::CNAME(cname)) = r.data() {
                        Some(cname.0.clone())
                    } else {
                        None
                    }
                });
            
            if let Some(target) = cname_target {
                info!("[SmartChasing] 🔗 [Depth {}] Following CNAME: {} -> {}", depth, current_qname, target);
                current_qname = target;
                depth += 1;
            } else {
                // No more CNAMEs and no terminal record
                if answer_count == 0 {
                    warn!("[SmartChasing] ⚠️ Backend returned empty answer at depth {}", depth);
                } else {
                    debug!("[SmartChasing] ℹ️ No more CNAMEs at depth {}, ending search", depth);
                }
                break;
            }
        }
        
        if depth >= MAX_DEPTH {
            warn!("[SmartChasing] ⚠️ Max depth reached for {}", original_qname);
        }
        
        // Build final response with all collected answers
        let mut final_msg = Message::new();
        final_msg.set_id(original_id);
        final_msg.set_message_type(trust_dns_proto::op::MessageType::Response);
        final_msg.set_recursion_desired(true);
        final_msg.set_recursion_available(true);
        // CRITICAL: Preserve backend response code to prevent DNS leak
        // Browsers fall back to ISP DNS if they get NoError with 0 answers
        final_msg.set_response_code(last_rcode);
        
        // Add original query
        final_msg.add_query(Query::query(original_qname.clone(), qtype));
        
        // Add all collected answers - FILTER BY QUERY TYPE
        // CRITICAL: Only include answers that match the query type (A or AAAA)
        // CNAME records are always included for chasing
        for answer in all_answers {
            let record_type = answer.record_type();
            if record_type == qtype || record_type == RecordType::CNAME {
                final_msg.add_answer(answer);
            }
        }
        
        info!("[SmartChasing] 📦 Returning {} total records for {}", final_msg.answers().len(), original_qname);
        
        Ok(Bytes::from(final_msg.to_vec()?))
    }
    
    /// Send raw UDP packet to backend
    async fn send_udp(&self, address: &SocketAddr, data: &[u8]) -> Result<Bytes> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(address).await?;
        socket.send(data).await?;
        
        let mut buf = vec![0u8; 4096];
        let len = timeout(self.timeout, socket.recv(&mut buf)).await??;
        
        if len < 12 {
            return Err(anyhow!("Invalid DNS response length: {}", len));
        }
        
        Ok(Bytes::copy_from_slice(&buf[..len]))
    }
    
    /// Forward with specific query ID preservation (legacy compatibility)
    pub async fn forward_with_id(&self, query: &[u8], original_id: u16, client_ip: IpAddr) -> Result<Bytes> {
        let response = self.forward(query, client_ip).await?;
        
        // Ensure response has correct ID
        let mut buf = response.to_vec();
        if buf.len() >= 2 {
            buf[0] = (original_id >> 8) as u8;
            buf[1] = (original_id & 0xFF) as u8;
        }
        
        Ok(Bytes::from(buf))
    }
}

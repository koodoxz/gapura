//! DNS-over-TLS (DoT) Server
//!
//! RFC 7858 compliant DNS-over-TLS implementation.
//! Listens on port 853 by default.

use super::{DnsForwarder, GatewayStats};
use anyhow::Result;
use bytes::Bytes;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

/// Run the DoT server
pub async fn run_dot_server(
    addr: &str,
    forwarder: Arc<DnsForwarder>,
    stats: Arc<GatewayStats>,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(tls_config);
    
    info!("🔐 DoT server listening on {}", addr);
    
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let forwarder = forwarder.clone();
        let stats = stats.clone();
        
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    debug!("DoT connection from {}", peer);
                    if let Err(e) = handle_dot_connection(tls_stream, forwarder, stats, peer.ip()).await {
                        debug!("DoT connection error from {}: {}", peer, e);
                    }
                }
                Err(e) => {
                    debug!("TLS handshake failed from {}: {}", peer, e);
                }
            }
        });
    }
}

/// Handle a single DoT connection (supports connection reuse)
async fn handle_dot_connection<S>(
    mut stream: S,
    forwarder: Arc<DnsForwarder>,
    stats: Arc<GatewayStats>,
    client_ip: std::net::IpAddr,
) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Set connection timeout for idle connections
    let idle_timeout = std::time::Duration::from_secs(60);
    
    loop {
        // Read length prefix (2 bytes) with timeout
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(idle_timeout, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => break, // Connection closed or timeout
        }
        
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len < 12 || msg_len > 65535 {
            break; // Invalid DNS message length
        }
        
        // Read DNS message
        let mut msg_buf = vec![0u8; msg_len];
        if stream.read_exact(&mut msg_buf).await.is_err() {
            break;
        }
        
        // Forward to MIMIR
        stats.inc_dot();
        let response = match forwarder.forward(&msg_buf, client_ip).await {
            Ok(resp) => resp,
            Err(e) => {
                debug!("Forward error: {}, sending ServFail", e);
                // CRITICAL FIX: Send ServFail response instead of closing connection
                // Closing connection causes browser to fall back to ISP DNS (leak!)
                build_servfail_response(&msg_buf)
            }
        };
        
        // Send response with length prefix
        let resp_len = (response.len() as u16).to_be_bytes();
        if stream.write_all(&resp_len).await.is_err() {
            break;
        }
        if stream.write_all(&response).await.is_err() {
            break;
        }
        if stream.flush().await.is_err() {
            break;
        }
    }
    
    Ok(())
}

/// Build a minimal ServFail response from the original query
/// CRITICAL: This prevents DNS leak by returning a proper error response
/// instead of closing the connection (which causes browser fallback to ISP DNS)
fn build_servfail_response(query: &[u8]) -> Bytes {
    // Extract query ID from original message (first 2 bytes)
    let id = if query.len() >= 2 {
        [query[0], query[1]]
    } else {
        [0, 0]
    };
    
    // Build minimal ServFail response
    // Format: ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
    let mut response = Vec::with_capacity(12 + query.len().saturating_sub(12));
    
    // Transaction ID (preserve from query)
    response.extend_from_slice(&id);
    
    // Flags: QR=1 (response), OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=2 (ServFail)
    // 0x8182 = 1000_0001_1000_0010
    response.extend_from_slice(&[0x81, 0x82]);
    
    // QDCOUNT = 1 (copy question from query)
    response.extend_from_slice(&[0x00, 0x01]);
    
    // ANCOUNT = 0
    response.extend_from_slice(&[0x00, 0x00]);
    
    // NSCOUNT = 0
    response.extend_from_slice(&[0x00, 0x00]);
    
    // ARCOUNT = 0
    response.extend_from_slice(&[0x00, 0x00]);
    
    // Copy question section from original query (starts at byte 12)
    if query.len() > 12 {
        response.extend_from_slice(&query[12..]);
    }
    
    Bytes::from(response)
}

//! Load Balancer
//!
//! Manages multiple backends with health checks and selection strategies.

use crate::config::{MimirBackend, UpstreamConfig, GeoIpConfig};
use crate::gateway::geoip::GeoIpReader;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A backend with its health status
#[derive(Debug)]
pub struct Backend {
    pub name: String,
    pub address: SocketAddr,
    pub weight: u8,
    pub region: Option<String>,
    pub healthy: Arc<RwLock<bool>>,
}

/// Selection strategies
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Strategy {
    Primary,
    RoundRobin,
    Weighted,
    GeoIP,
}

impl From<&str> for Strategy {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "primary" => Strategy::Primary,
            "round_robin" | "roundrobin" => Strategy::RoundRobin,
            "weighted" => Strategy::Weighted,
            "geoip" => Strategy::GeoIP,
            _ => Strategy::Primary,
        }
    }
}

pub struct LoadBalancer {
    backends: Vec<Backend>,
    strategy: Strategy,
    rr_index: AtomicUsize,
    geoip: Option<GeoIpReader>,
}

impl LoadBalancer {
    pub fn new(config: &UpstreamConfig, geoip_config: &GeoIpConfig) -> Self {
        let strategy = Strategy::from(config.strategy.as_str());
        let backends = config.backends.iter().filter_map(|b| {
            match b.address.parse() {
                Ok(addr) => Some(Backend {
                    name: b.name.clone(),
                    address: addr,
                    weight: b.weight,
                    region: b.region.clone(),
                    healthy: Arc::new(RwLock::new(true)),
                }),
                Err(e) => {
                    warn!("Invalid backend address {}: {}", b.address, e);
                    None
                }
            }
        }).collect();

        let geoip = if geoip_config.enabled {
            match GeoIpReader::load(&geoip_config.database_path) {
                Ok(reader) => {
                    info!("🌍 GeoIP enabled | db={}", geoip_config.database_path);
                    Some(reader)
                }
                Err(e) => {
                    warn!("Failed to load GeoIP database: {}", e);
                    None
                }
            }
        } else {
            None
        };

        info!("⚖️ Load Balancer ready | strategy={:?} | backends={}", strategy, config.backends.len());

        Self {
            backends,
            strategy,
            rr_index: AtomicUsize::new(0),
            geoip,
        }
    }

    /// Select a healthy backend based on the configured strategy
    pub async fn select(&self, client_ip: IpAddr) -> Option<&Backend> {
        if self.backends.is_empty() {
            return None;
        }

        // Always check GeoIP if available regardless of main strategy
        // This provides location-aware routing as an overlay
        if let Some(ref geoip) = self.geoip {
            if let Some(loc) = geoip.lookup(client_ip) {
                debug!("Client IP {} is from {}", client_ip, loc.country_code);
                // Simple logic: If backend region matches country_code (or starts with it), prefer it
                for b in &self.backends {
                    if let Some(ref reg) = b.region {
                        if (reg == &loc.country_code || reg.starts_with(&format!("{}-", loc.country_code))) && *b.healthy.read().await {
                            return Some(b);
                        }
                    }
                }
            }
        }

        match self.strategy {
            Strategy::Primary => self.select_primary().await,
            Strategy::RoundRobin => self.select_round_robin().await,
            Strategy::Weighted => self.select_weighted().await,
            Strategy::GeoIP => self.select_primary().await, // TODO: Implement GeoIP selection
        }
    }

    async fn select_primary(&self) -> Option<&Backend> {
        for backend in &self.backends {
            if *backend.healthy.read().await {
                return Some(backend);
            }
        }
        None
    }

    async fn select_round_robin(&self) -> Option<&Backend> {
        let len = self.backends.is_empty();
        if len { return None; }
        
        let start = self.rr_index.fetch_add(1, Ordering::SeqCst) % self.backends.len();
        
        for i in 0..self.backends.len() {
            let idx = (start + i) % self.backends.len();
            let b = &self.backends[idx];
            if *b.healthy.read().await {
                return Some(b);
            }
        }
        None
    }

    async fn select_weighted(&self) -> Option<&Backend> {
        // Simple weighted random selection among healthy backends
        let mut healthy_backends = Vec::new();
        let mut total_weight = 0u32;

        for b in &self.backends {
            if *b.healthy.read().await {
                healthy_backends.push(b);
                total_weight += b.weight as u32;
            }
        }

        if healthy_backends.is_empty() {
            return None;
        }

        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut r = rng.gen_range(0..total_weight);

        for b in healthy_backends {
            if r < b.weight as u32 {
                return Some(b);
            }
            r -= b.weight as u32;
        }

        self.backends.get(0) // Fallback
    }

    pub fn get_all_backends(&self) -> &[Backend] {
        &self.backends
    }
}

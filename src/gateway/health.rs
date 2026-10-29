//! Health Checker
//!
//! Periodically checks backends by sending DNS queries.

use crate::gateway::loadbalancer::LoadBalancer;
use crate::gateway::GatewayStats;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tokio::net::UdpSocket;
use tracing::{warn, debug, info};

pub struct HealthChecker {
    load_balancer: Arc<LoadBalancer>,
    stats: Arc<GatewayStats>,
    interval: Duration,
}

impl HealthChecker {
    pub fn new(load_balancer: Arc<LoadBalancer>, stats: Arc<GatewayStats>, interval_secs: u64) -> Self {
        Self {
            load_balancer,
            stats,
            interval: Duration::from_secs(interval_secs),
        }
    }

    /// Run the health check loop
    pub async fn run(&self) {
        info!("🩺 Starting health checker | interval={:?}", self.interval);
        
        // Simple DNS query for google.com (A)
        let query = hex::decode("00010100000100000000000006676f6f676c6503636f6d0000010001").unwrap();
        
        loop {
            sleep(self.interval).await;
            
            for backend in self.load_balancer.get_all_backends() {
                let is_healthy = self.check_backend(backend.address, &query).await;
                
                let mut status = backend.healthy.write().await;
                if *status != is_healthy {
                    if is_healthy {
                        info!("💚 Backend {} is back ONLINE", backend.name);
                    } else {
                        warn!("💔 Backend {} is now OFFLINE", backend.name);
                        self.stats.inc_healthcheck_fail();
                    }
                    *status = is_healthy;
                }
            }
        }
    }

    async fn check_backend(&self, addr: std::net::SocketAddr, query: &[u8]) -> bool {
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => return false,
        };

        if let Err(_) = socket.connect(addr).await {
            return false;
        }

        if let Err(_) = socket.send(query).await {
            return false;
        }

        let mut buf = [0u8; 512];
        match tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => true,
            _ => false,
        }
    }
}

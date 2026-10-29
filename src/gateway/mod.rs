//! ODIN-RS Gateway Module
//!
//! Orchestrates all DNS gateway servers:
//! - DoT (DNS-over-TLS) on port 853
//! - DoH (DNS-over-HTTPS) on port 443
//! - DoQ (DNS-over-QUIC) on port 8853
//! - HTTP redirect/ACME on port 80

mod forwarder;
mod dot;
mod doh;
mod doq;
mod loadbalancer;
mod health;
mod geoip;
pub mod metrics;

pub use forwarder::DnsForwarder;
pub use metrics::{GatewayStats, run_metrics_server};

use crate::config::Config;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use loadbalancer::LoadBalancer;
use health::HealthChecker;

/// Main Gateway structure
pub struct Gateway {
    config: Config,
    stats: Arc<GatewayStats>,
    forwarder: Arc<DnsForwarder>,
    load_balancer: Arc<LoadBalancer>,
    tls_config_doh: Option<Arc<rustls::ServerConfig>>,
    tls_config_dot: Option<Arc<rustls::ServerConfig>>,
}

impl Gateway {
    /// Create a new gateway
    pub async fn new(config: Config, stats: Arc<GatewayStats>) -> Result<Self> {
        info!("🔧 Initializing gateway...");
        
        // Create Load Balancer
        let load_balancer = Arc::new(LoadBalancer::new(&config.upstreams, &config.geoip));
        
        // Create DNS forwarder
        let forwarder = Arc::new(DnsForwarder::new(load_balancer.clone(), stats.clone()).await?);
        
        // Load TLS configs if certs are provided
        let (tls_config_doh, tls_config_dot) = if !config.tls.cert_file.is_empty() && !config.tls.key_file.is_empty() {
            (
                Some(Arc::new(load_tls_config_doh(&config.tls.cert_file, &config.tls.key_file)?)),
                Some(Arc::new(load_tls_config_dot(&config.tls.cert_file, &config.tls.key_file)?)),
            )
        } else {
            warn!("⚠️ No TLS certs configured - DoT/DoH will be disabled");
            (None, None)
        };
        
        Ok(Self {
            config,
            stats,
            forwarder,
            load_balancer,
            tls_config_doh,
            tls_config_dot,
        })
    }
    
    /// Run all gateway servers
    pub async fn run(&self) -> Result<()> {
        info!("🚀 Starting all gateway servers...");
        
        let mut handles = Vec::new();
        
        // Start Health Checker
        let health_checker = HealthChecker::new(
            self.load_balancer.clone(),
            self.stats.clone(),
            self.config.upstreams.health_check_interval_secs,
        );
        handles.push(tokio::spawn(async move {
            health_checker.run().await;
        }));

        // Start DoT server
        if let Some(ref tls) = self.tls_config_dot {
            let dot_addr = self.config.dot_addr.clone();
            let forwarder = self.forwarder.clone();
            let stats = self.stats.clone();
            let tls_config = tls.clone();
            
            handles.push(tokio::spawn(async move {
                if let Err(e) = dot::run_dot_server(&dot_addr, forwarder, stats, tls_config).await {
                    warn!("DoT server error: {}", e);
                }
            }));
        }
        
        // Start DoH server
        if let Some(ref tls) = self.tls_config_doh {
            let doh_addr = self.config.https_addr.clone();
            let forwarder = self.forwarder.clone();
            let stats = self.stats.clone();
            let tls_config = tls.clone();
            
            handles.push(tokio::spawn(async move {
                if let Err(e) = doh::run_doh_server(&doh_addr, forwarder, stats, tls_config).await {
                    warn!("DoH server error: {}", e);
                }
            }));
        }
        
        // Start DoQ server
        if let Some(ref _tls) = self.tls_config_doh {
            let doq_addr = self.config.doq_addr.clone();
            let forwarder = self.forwarder.clone();
            let stats = self.stats.clone();
            let cert_file = self.config.tls.cert_file.clone();
            let key_file = self.config.tls.key_file.clone();
            
            handles.push(tokio::spawn(async move {
                if let Err(e) = doq::run_doq_server(&doq_addr, forwarder, stats, &cert_file, &key_file).await {
                    warn!("DoQ server error: {}", e);
                }
            }));
        }
        
        // Start HTTP redirect server
        let http_addr = self.config.http_addr.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = run_http_redirect(&http_addr).await {
                warn!("HTTP redirect server error: {}", e);
            }
        }));
        
        info!("✅ All gateway servers started");
        
        // Wait for all servers
        for handle in handles {
            let _ = handle.await;
        }
        
        Ok(())
    }
}

/// Load TLS configuration for DoH (with ALPN for HTTP/2)
fn load_tls_config_doh(cert_path: &str, key_path: &str) -> Result<rustls::ServerConfig> {
    use rustls_pemfile::{certs, pkcs8_private_keys};
    use std::fs::File;
    use std::io::BufReader;
    
    let cert_file = File::open(cert_path)?;
    let key_file = File::open(key_path)?;
    
    let certs: Vec<_> = certs(&mut BufReader::new(cert_file))
        .filter_map(|r| r.ok())
        .collect();
    
    let keys: Vec<_> = pkcs8_private_keys(&mut BufReader::new(key_file))
        .filter_map(|r| r.ok())
        .collect();
    
    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", cert_path);
    }
    if keys.is_empty() {
        anyhow::bail!("No private key found in {}", key_path);
    }
    
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, keys.into_iter().next().unwrap().into())?;
    
    // 🔥 CRITICAL: Add ALPN protocols for HTTP/2 (browser DoH requirement)
    config.alpn_protocols = vec![
        b"h2".to_vec(),       // HTTP/2 - required by Chrome/Edge DoH
        b"http/1.1".to_vec(), // HTTP/1.1 fallback
    ];
    
    Ok(config)
}

/// Load TLS configuration for DoT
fn load_tls_config_dot(cert_path: &str, key_path: &str) -> Result<rustls::ServerConfig> {
    use rustls_pemfile::{certs, pkcs8_private_keys};
    use std::fs::File;
    use std::io::BufReader;
    
    let cert_file = File::open(cert_path)?;
    let key_file = File::open(key_path)?;
    
    let certs: Vec<_> = certs(&mut BufReader::new(cert_file))
        .filter_map(|r| r.ok())
        .collect();
    
    let keys: Vec<_> = pkcs8_private_keys(&mut BufReader::new(key_file))
        .filter_map(|r| r.ok())
        .collect();
    
    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", cert_path);
    }
    if keys.is_empty() {
        anyhow::bail!("No private key found in {}", key_path);
    }
    
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, keys.into_iter().next().unwrap().into())?;

    config.alpn_protocols = vec![b"dot".to_vec()];
    
    Ok(config)
}

/// Run HTTP redirect server (port 80 → 443)
async fn run_http_redirect(addr: &str) -> Result<()> {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use http_body_util::Full;
    use hyper_util::rt::TokioIo;
    use bytes::Bytes;
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("🔀 HTTP redirect server listening on {}", addr);
    
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        
        tokio::spawn(async move {
            let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                let host = req.headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("localhost");
                let path = req.uri().path();
                let target = format!("https://{}{}", host, path);
                
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::MOVED_PERMANENTLY)
                        .header("Location", target)
                        .body(Full::new(Bytes::from("Redirecting to HTTPS")))
                        .unwrap()
                )
            });
            
            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                tracing::debug!("HTTP connection error: {}", e);
            }
        });
    }
}

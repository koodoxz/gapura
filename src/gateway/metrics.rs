//! Prometheus Metrics Module for ODIN-RS
//!
//! Exposes HTTP endpoint for Prometheus scraping.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use anyhow::Result;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use bytes::Bytes;
use tokio::net::TcpListener;
use tracing::{info, debug};

/// Server statistics for Prometheus
#[derive(Debug)]
pub struct GatewayStats {
    pub dot_requests: AtomicU64,
    pub doh_requests: AtomicU64,
    pub doq_requests: AtomicU64,
    pub total_requests: AtomicU64,
    pub geoip_matches: AtomicU64,
    pub backend_failovers: AtomicU64,
    pub healthcheck_failures: AtomicU64,
}

impl GatewayStats {
    pub fn new() -> Self {
        Self {
            dot_requests: AtomicU64::new(0),
            doh_requests: AtomicU64::new(0),
            doq_requests: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
            geoip_matches: AtomicU64::new(0),
            backend_failovers: AtomicU64::new(0),
            healthcheck_failures: AtomicU64::new(0),
        }
    }

    pub fn inc_dot(&self) {
        self.dot_requests.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_doh(&self) {
        self.doh_requests.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_doq(&self) {
        self.doq_requests.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_geoip_match(&self) {
        self.geoip_matches.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_failover(&self) {
        self.backend_failovers.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_healthcheck_fail(&self) {
        self.healthcheck_failures.fetch_add(1, Ordering::Relaxed);
    }
}

/// Run Prometheus metrics HTTP server
pub async fn run_metrics_server(addr: SocketAddr, stats: Arc<GatewayStats>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("📊 Prometheus metrics at http://{}/metrics", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let stats = stats.clone();

        tokio::spawn(async move {
            let service = service_fn(move |_req: Request<hyper::body::Incoming>| {
                let stats = stats.clone();
                async move {
                    let body = format!(
                        "# HELP odin_requests_total Total DNS requests\n\
                         # TYPE odin_requests_total counter\n\
                         odin_requests_total {}\n\
                         # HELP odin_dot_requests DoT requests\n\
                         # TYPE odin_dot_requests counter\n\
                         odin_dot_requests {}\n\
                         # HELP odin_doh_requests DoH requests\n\
                         # TYPE odin_doh_requests counter\n\
                         odin_doh_requests {}\n\
                         # HELP odin_doq_requests DoQ requests\n\
                         # TYPE odin_doq_requests counter\n\
                         odin_doq_requests {}\n\
                         # HELP odin_geoip_matches GeoIP routing matches\n\
                         # TYPE odin_geoip_matches counter\n\
                         odin_geoip_matches {}\n\
                         # HELP odin_backend_failovers Backend failover count\n\
                         # TYPE odin_backend_failovers counter\n\
                         odin_backend_failovers {}\n\
                         # HELP odin_healthcheck_failures Healthcheck failures\n\
                         # TYPE odin_healthcheck_failures counter\n\
                         odin_healthcheck_failures {}\n",
                        stats.total_requests.load(Ordering::Relaxed),
                        stats.dot_requests.load(Ordering::Relaxed),
                        stats.doh_requests.load(Ordering::Relaxed),
                        stats.doq_requests.load(Ordering::Relaxed),
                        stats.geoip_matches.load(Ordering::Relaxed),
                        stats.backend_failovers.load(Ordering::Relaxed),
                        stats.healthcheck_failures.load(Ordering::Relaxed),
                    );
                    Ok::<_, std::convert::Infallible>(
                        Response::new(Full::new(Bytes::from(body)))
                    )
                }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                debug!("Metrics connection error: {}", e);
            }
        });
    }
}

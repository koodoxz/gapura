//! ODIN-RS: High-Performance DNS Gateway
//!
//! Provides:
//! - DoT (DNS-over-TLS) on port 853
//! - DoH (DNS-over-HTTPS) on port 443
//! - DoQ (DNS-over-QUIC) on port 8853
//! - TLS termination with auto-renewal
//! - API Gateway for AEGIS services

mod config;
mod gateway;

use anyhow::Result;
use clap::Parser;
use tracing::{info, Level};

#[derive(Parser, Debug)]
#[command(name = "odin")]
#[command(about = "ODIN-RS: High-Performance DNS Gateway")]
#[command(version = "0.1.0")]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "configs/odin.yaml")]
    config: String,
    
    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,
}

fn print_banner() {
    let banner = r#"
    ██████╗ ██████╗ ██╗███╗   ██╗      ██████╗ ███████╗
   ██╔═══██╗██╔══██╗██║████╗  ██║      ██╔══██╗██╔════╝
   ██║   ██║██║  ██║██║██╔██╗ ██║█████╗██████╔╝███████╗
   ██║   ██║██║  ██║██║██║╚██╗██║╚════╝██╔══██╗╚════██║
   ╚██████╔╝██████╔╝██║██║ ╚████║      ██║  ██║███████║
    ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝      ╚═╝  ╚═╝╚══════╝
    
    High-Performance DNS Gateway - AEGIS Ecosystem
    DoT | DoH | DoQ - Rust Edition
"#;
    println!("{}", banner);
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    
    print_banner();
    
    // Load configuration first to get log level
    let args = Args::parse();
    let config = config::Config::load(&args.config)?;
    
    // Determine log level
    let log_level = if args.debug {
        Level::DEBUG
    } else {
        match config.log_level.to_lowercase().as_str() {
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        }
    };
    
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .compact()
        .init();
    
    info!("🚀 ODIN-RS starting...");
    info!("📁 Loaded config from {}", args.config);
    
    // Initialize metrics
    let stats = std::sync::Arc::new(gateway::GatewayStats::new());
    let stats_clone = stats.clone();

    // Create and start gateway
    let gw = gateway::Gateway::new(config.clone(), stats.clone()).await?;
    
    // Start metrics server
    let metrics_addr: std::net::SocketAddr = config.metrics_addr.parse()?;
    tokio::spawn(async move {
        if let Err(e) = gateway::run_metrics_server(metrics_addr, stats_clone).await {
            tracing::warn!("Metrics server error: {}", e);
        }
    });
    
    // Handle shutdown signal
    let shutdown = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C handler");
        info!("🛑 Shutdown signal received");
    };
    
    // Run gateway until shutdown
    tokio::select! {
        result = gw.run() => {
            if let Err(e) = result {
                tracing::error!("Gateway error: {}", e);
            }
        }
        _ = shutdown => {
            info!("👋 Shutting down gracefully...");
        }
    }
    
    info!("✅ ODIN-RS shutdown complete");
    Ok(())
}

//! ODIN-RS Configuration
//!
//! Loads and manages gateway configuration from YAML files.

use anyhow::Result;
use serde::Deserialize;
use std::fs;
use std::time::Duration;

/// Main configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// HTTP listen address (for ACME and redirects)
    #[serde(default = "default_http_addr")]
    pub http_addr: String,
    
    /// HTTPS listen address (DoH endpoint)
    #[serde(default = "default_https_addr")]
    pub https_addr: String,
    
    /// DoT listen address
    #[serde(default = "default_dot_addr")]
    pub dot_addr: String,
    
    /// DoQ listen address
    #[serde(default = "default_doq_addr")]
    pub doq_addr: String,
    
    /// Prometheus metrics listen address
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: String,
    
    /// TLS configuration
    #[serde(default)]
    pub tls: TlsConfig,
    
    /// Upstream services
    #[serde(default)]
    pub upstreams: UpstreamConfig,
    
    /// Rate limiting
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    
    /// GeoIP configuration
    #[serde(default)]
    pub geoip: GeoIpConfig,
    
    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

/// GeoIP configuration
#[derive(Debug, Clone, Deserialize, Default)]
pub struct GeoIpConfig {
    #[serde(default)]
    pub enabled: bool,
    
    #[serde(default = "default_geojson_db")]
    pub database_path: String,
}

fn default_geojson_db() -> String { "data/GeoLite2-Country.mmdb".to_string() }

/// TLS configuration
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TlsConfig {
    /// Auto-renew via ACME (Let's Encrypt)
    #[serde(default)]
    pub auto_cert: bool,
    
    /// Domains for certificate
    #[serde(default)]
    pub domains: Vec<String>,
    
    /// Manual cert path
    #[serde(default)]
    pub cert_file: String,
    
    /// Manual key path
    #[serde(default)]
    pub key_file: String,
    
    /// ACME directory URL
    #[serde(default = "default_acme_directory")]
    pub acme_directory: String,
    
    /// Cache directory for certs
    #[serde(default = "default_cache_dir")]
    pub cache_dir: String,
}

/// Upstream services configuration
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    /// Strategy: "primary", "round_robin", "weighted", "geoip"
    #[serde(default = "default_strategy")]
    pub strategy: String,
    
    /// Multiple MIMIR backends
    #[serde(default)]
    pub backends: Vec<MimirBackend>,
    
    /// Health check interval
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval_secs: u64,

    /// SVALINN WAF address
    #[serde(default)]
    pub svalinn: Option<String>,
    
    /// HEIMDALL monitor address
    #[serde(default)]
    pub heimdall: Option<String>,
}

/// A specific MIMIR backend
#[derive(Debug, Clone, Deserialize)]
pub struct MimirBackend {
    pub name: String,
    pub address: String,
    #[serde(default = "default_weight")]
    pub weight: u8,
    pub region: Option<String>,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            strategy: default_strategy(),
            backends: vec![
                MimirBackend {
                    name: "mimir-new".to_string(),
                    address: "127.0.0.1:53".to_string(),
                    weight: 100,
                    region: Some("ID-JKT".to_string()),
                }
            ],
            health_check_interval_secs: default_health_check_interval(),
            svalinn: None,
            heimdall: None,
        }
    }
}

fn default_strategy() -> String { "primary".to_string() }
fn default_health_check_interval() -> u64 { 5 }
fn default_weight() -> u8 { 50 }

/// Rate limiting configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    #[serde(default = "default_true")]
    pub enabled: bool,
    
    /// Requests per second per client
    #[serde(default = "default_rps")]
    pub requests_per_second: u32,
    
    /// Burst size
    #[serde(default = "default_burst")]
    pub burst_size: u32,
    
    /// Client TTL in seconds
    #[serde(default = "default_client_ttl")]
    pub client_ttl_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 100,
            burst_size: 200,
            client_ttl_secs: 300,
        }
    }
}

impl RateLimitConfig {
    pub fn client_ttl(&self) -> Duration {
        Duration::from_secs(self.client_ttl_secs)
    }
}

// Default value functions
fn default_http_addr() -> String { "0.0.0.0:80".to_string() }
fn default_https_addr() -> String { "0.0.0.0:443".to_string() }
fn default_dot_addr() -> String { "0.0.0.0:853".to_string() }
fn default_doq_addr() -> String { "0.0.0.0:8853".to_string() }
fn default_metrics_addr() -> String { "0.0.0.0:9090".to_string() }
fn default_log_level() -> String { "info".to_string() }
fn default_mimir() -> String { "127.0.0.1:53".to_string() }
fn default_acme_directory() -> String { 
    "https://acme-v02.api.letsencrypt.org/directory".to_string() 
}
fn default_cache_dir() -> String { "data/certs".to_string() }
fn default_true() -> bool { true }
fn default_rps() -> u32 { 100 }
fn default_burst() -> u32 { 200 }
fn default_client_ttl() -> u64 { 300 }

impl Config {
    /// Load configuration from YAML file
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }
    
    /// Create default configuration
    pub fn default() -> Self {
        Self {
            http_addr: default_http_addr(),
            https_addr: default_https_addr(),
            dot_addr: default_dot_addr(),
            doq_addr: default_doq_addr(),
            metrics_addr: default_metrics_addr(),
            tls: TlsConfig::default(),
            upstreams: UpstreamConfig::default(),
            rate_limit: RateLimitConfig::default(),
            geoip: GeoIpConfig::default(),
            log_level: default_log_level(),
        }
    }
}

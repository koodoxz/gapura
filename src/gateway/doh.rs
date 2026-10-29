//! DNS-over-HTTPS (DoH) Server
//!
//! RFC 8484 compliant DNS-over-HTTPS implementation.
//! Supports both GET (?dns=base64url) and POST (application/dns-message) methods.

use super::{DnsForwarder, GatewayStats};
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioExecutor};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};
use rand::Rng;

/// Run the DoH server
pub async fn run_doh_server(
    addr: &str,
    forwarder: Arc<DnsForwarder>,
    stats: Arc<GatewayStats>,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(tls_config);
    
    info!("🌐 DoH server listening on {}", addr);
    info!("   Endpoints: /dns-query (GET/POST), /.well-known/dns-query");
    info!("   HTTP/2 + HTTP/1.1 ALPN enabled");
    
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let forwarder = forwarder.clone();
        let stats = stats.clone();
        
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);
                    let stats = stats.clone();
                    
                    let service = service_fn(move |req| {
                        let forwarder = forwarder.clone();
                        let stats = stats.clone();
                        let client_ip = peer.ip();
                        async move {
                            handle_doh_request(req, forwarder, stats, client_ip).await
                        }
                    });
                    
                    // 🔥 Use auto builder for HTTP/1.1 + HTTP/2 support
                    if let Err(e) = AutoBuilder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await
                    {
                        debug!("DoH connection error from {}: {}", peer, e);
                    }
                }
                Err(e) => {
                    debug!("TLS handshake failed from {}: {}", peer, e);
                }
            }
        });
    }
}


/// Handle a DoH request
async fn handle_doh_request(
    req: Request<hyper::body::Incoming>,
    forwarder: Arc<DnsForwarder>,
    stats: Arc<GatewayStats>,
    client_ip: std::net::IpAddr,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let path = req.uri().path();
    
    // Route based on path
    match path {
        "/dns-query" | "/.well-known/dns-query" => {
            stats.inc_doh();
            match handle_dns_query(req, forwarder, client_ip).await {
                Ok(response) => Ok(response),
                Err(e) => Ok(error_response(StatusCode::BAD_REQUEST, &e.to_string())),
            }
        }
        "/health" => {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from("OK")))
                .unwrap())
        }
        "/api/v1/status" => {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(r#"{"status":"ok","version":"0.1.0"}"#)))
                .unwrap())
        }
        _ => {
            Ok(error_response(StatusCode::NOT_FOUND, "Not found"))
        }
    }
}

/// Handle DNS query endpoint
async fn handle_dns_query(
    req: Request<hyper::body::Incoming>,
    forwarder: Arc<DnsForwarder>,
    client_ip: std::net::IpAddr,
) -> Result<Response<Full<Bytes>>> {
    let query_bytes = match *req.method() {
        Method::GET => {
            // GET can be either:
            // 1. RFC 8484: ?dns=base64url encoded query
            // 2. JSON API: ?name=domain&type=A (browser compatibility)
            let query = req.uri().query().unwrap_or("");
            
            // Check for dns= parameter first (RFC 8484)
            if let Some(dns_param) = query
                .split('&')
                .find(|p| p.starts_with("dns="))
                .map(|p| &p[4..])
            {
                URL_SAFE_NO_PAD.decode(dns_param)?
            } else if let Some(name) = extract_param(query, "name") {
                // JSON API format: ?name=domain&type=A
                let qtype = extract_param(query, "type").unwrap_or_else(|| "A".to_string());
                build_dns_query(&name, &qtype)?
            } else {
                anyhow::bail!("Missing dns or name parameter");
            }
        }
        Method::POST => {
            // POST with application/dns-message body
            let content_type = req.headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            
            if content_type != "application/dns-message" {
                anyhow::bail!("Invalid content type: {}", content_type);
            }
            
            // Read body
            let body = req.into_body();
            let bytes = body.collect().await?.to_bytes();
            bytes.to_vec()
        }
        _ => {
            anyhow::bail!("Method not allowed");
        }
    };
    
    // Forward to MIMIR
    let response = forwarder.forward(&query_bytes, client_ip).await?;
    
    // Return DNS response with browser-required headers
    // GPT/Gemini/DeepSeek: Content-Length is CRITICAL for browsers
    let response_len = response.len();
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/dns-message")
        .header("Content-Length", response_len.to_string())
        .header("Cache-Control", "no-cache, no-store, must-revalidate")
        .header("Pragma", "no-cache")
        .header("Expires", "0")
        .body(Full::new(response))
        .unwrap())
}

/// Create an error response
fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(message.to_string())))
        .unwrap()
}

/// Extract a query parameter value from a query string
fn extract_param<'a>(query: &'a str, name: &str) -> Option<String> {
    let prefix = format!("{}=", name);
    query
        .split('&')
        .find(|p| p.starts_with(&prefix))
        .map(|p| {
            // URL decode the value
            let raw = &p[prefix.len()..];
            urlencoding_decode(raw)
        })
}

/// Simple URL decoding (handles %XX and +)
fn urlencoding_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    
    while let Some(c) = chars.next() {
        match c {
            '%' => {
                let hex: String = chars.by_ref().take(2).collect();
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                } else {
                    result.push('%');
                    result.push_str(&hex);
                }
            }
            '+' => result.push(' '),
            _ => result.push(c),
        }
    }
    result
}

/// Build a DNS query message from name and type
fn build_dns_query(name: &str, qtype: &str) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    
    // Transaction ID - must be random per GPT/Kimik2 recommendations
    // Browsers validate that response TXID matches request TXID
    // The forwarder handles TXID preservation correctly
    let txid: u16 = rand::random();
    buf.extend_from_slice(&txid.to_be_bytes());
    
    // Flags: Standard query, RD=1 (recursion desired)
    buf.extend_from_slice(&[0x01, 0x00]);
    
    // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    
    // QNAME
    for label in name.split('.').filter(|s| !s.is_empty()) {
        if label.len() > 63 {
            anyhow::bail!("Label too long: {}", label);
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // Root label
    
    // QTYPE - Comprehensive support for modern DNS including DoH/DoT/DoQ
    let qtype_num: u16 = match qtype.to_uppercase().as_str() {
        // Standard record types
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "HINFO" => 13,
        "MX" => 15,
        "TXT" => 16,
        "RP" => 17,
        "AFSDB" => 18,
        "SIG" => 24,
        "KEY" => 25,
        "AAAA" => 28,
        "LOC" => 29,
        "SRV" => 33,
        "NAPTR" => 35,
        "KX" => 36,
        "CERT" => 37,
        "DNAME" => 39,
        "OPT" => 41,
        "APL" => 42,
        "DS" => 43,           // DNSSEC Delegation Signer
        "SSHFP" => 44,        // SSH Key Fingerprint
        "IPSECKEY" => 45,
        "RRSIG" => 46,        // DNSSEC signature
        "NSEC" => 47,         // DNSSEC next secure
        "DNSKEY" => 48,       // DNSSEC key
        "DHCID" => 49,
        "NSEC3" => 50,        // DNSSEC
        "NSEC3PARAM" => 51,   // DNSSEC
        "TLSA" => 52,         // TLS Authentication (DANE)
        "SMIMEA" => 53,
        "HIP" => 55,
        "CDS" => 59,          // DNSSEC child DS
        "CDNSKEY" => 60,      // DNSSEC child key
        "OPENPGPKEY" => 61,
        "CSYNC" => 62,
        "ZONEMD" => 63,
        "SVCB" => 64,         // Service Binding (modern browsers)
        "HTTPS" => 65,        // HTTPS Service Binding (CRITICAL for modern browsers!)
        "SPF" => 99,
        "EUI48" => 108,
        "EUI64" => 109,
        "TKEY" => 249,
        "TSIG" => 250,
        "IXFR" => 251,
        "AXFR" => 252,
        "ANY" | "*" => 255,
        "URI" => 256,
        "CAA" => 257,         // Certificate Authority Authorization
        "TA" => 32768,
        "DLV" => 32769,
        // Parse numeric type directly (e.g., "65" for HTTPS)
        _ => qtype.parse::<u16>().unwrap_or(1),
    };
    buf.extend_from_slice(&qtype_num.to_be_bytes());
    
    // QCLASS = IN
    buf.extend_from_slice(&[0x00, 0x01]);
    
    Ok(buf)
}


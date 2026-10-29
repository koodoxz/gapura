//! DNS-over-QUIC (DoQ) Server
//!
//! RFC 9250 compliant DNS-over-QUIC implementation.
//! Uses QUIC protocol for low-latency, encrypted DNS transport.
//! Listens on port 8853 by default.

use super::{DnsForwarder, GatewayStats};
use anyhow::Result;
use bytes::Bytes;
use quinn::{Endpoint, ServerConfig};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

/// Run the DoQ server
pub async fn run_doq_server(
    addr: &str,
    forwarder: Arc<DnsForwarder>,
    stats: Arc<GatewayStats>,
    cert_path: &str,
    key_path: &str,
) -> Result<()> {
    // Load certificates
    let (cert_chain, key) = load_certs_and_key(cert_path, key_path)?;
    
    // Build QUIC server config
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    
    // Set ALPN for DoQ (RFC 9250)
    server_crypto.alpn_protocols = vec![b"doq".to_vec()];
    
    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?
    ));
    
    // Create QUIC endpoint
    let endpoint = Endpoint::server(server_config, addr.parse()?)?;
    
    info!("⚡ DoQ server listening on {}", addr);
    info!("   Protocol: QUIC with 0-RTT support");
    info!("   ALPN: doq");
    
    // Accept connections
    while let Some(incoming) = endpoint.accept().await {
        let forwarder = forwarder.clone();
        let stats = stats.clone();
        
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    let client_ip = conn.remote_address().ip();
                    debug!("DoQ connection from {}", client_ip);
                    if let Err(e) = handle_doq_connection(conn, forwarder, stats, client_ip).await {
                        debug!("DoQ connection error: {}", e);
                    }
                }
                Err(e) => {
                    debug!("DoQ connection failed: {}", e);
                }
            }
        });
    }
    
    Ok(())
}

/// Handle a DoQ connection
async fn handle_doq_connection(
    conn: quinn::Connection,
    forwarder: Arc<DnsForwarder>,
    stats: Arc<GatewayStats>,
    client_ip: std::net::IpAddr,
) -> Result<()> {
    // DoQ uses bidirectional streams for each query
    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let forwarder = forwarder.clone();
                let stats = stats.clone();
                
                tokio::spawn(async move {
                    if let Err(e) = handle_doq_stream(&mut send, &mut recv, forwarder, stats, client_ip).await {
                        debug!("DoQ stream error: {}", e);
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
            Err(e) => {
                debug!("DoQ accept error: {}", e);
                break;
            }
        }
    }
    
    Ok(())
}

/// Handle a single DoQ stream (one query-response pair)
async fn handle_doq_stream(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    forwarder: Arc<DnsForwarder>,
    stats: Arc<GatewayStats>,
    client_ip: std::net::IpAddr,
) -> Result<()> {
    stats.inc_doq();
    // Read length prefix (2 bytes) - same as DoT
    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf).await?;
    let msg_len = u16::from_be_bytes(len_buf) as usize;
    
    if msg_len < 12 || msg_len > 65535 {
        anyhow::bail!("Invalid DNS message length: {}", msg_len);
    }
    
    // Read DNS query
    let mut query = vec![0u8; msg_len];
    recv.read_exact(&mut query).await?;
    
    // Forward to MIMIR
    let response = forwarder.forward(&query, client_ip).await?;
    
    // Send response with length prefix
    let resp_len = (response.len() as u16).to_be_bytes();
    send.write_all(&resp_len).await?;
    send.write_all(&response).await?;
    send.finish()?;
    
    Ok(())
}

/// Load certificates and private key from files
fn load_certs_and_key(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>)> {
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
    
    Ok((certs, keys.into_iter().next().unwrap().into()))
}

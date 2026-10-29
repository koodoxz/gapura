# Gapura (GAPURA) ᚷᚨᛈᚢᚱᚨ

> **High-Performance Encrypted DNS Ingress Gateway — Engineered in Rust**  
> Line-rate protocol termination (DoQ / DoH / DoT), token-bucket abuse shaping, zero-copy backend routing, and zero public port 53.

[![CI](https://github.com/koodoxz/gapura/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/koodoxz/gapura/actions)
[![Rust](https://img.shields.io/badge/Rust-1.75+-000000?style=flat&logo=rust)](https://www.rust-lang.org/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Protocols](https://img.shields.io/badge/Protocols-DoQ%20%7C%20DoH%20%7C%20DoT%20%7C%20HTTP-green.svg)](#core-capabilities)
[![Ecosystem](https://img.shields.io/badge/Ecosystem-Architecture%20Portal-00f2fe.svg)](https://koodoxz.github.io)

---

## Executive Summary

**Gapura** (Indonesian / Sanskrit: *"ceremonial gateway / monumental entrance portal"*) is a high-concurrency public ingress gateway engineered in pure Rust. It serves as the authoritative front gate for modern DNS infrastructure, shielding backend recursive resolvers (such as [Runut](https://github.com/koodoxz/runut)) from direct exposure to the public Internet.

Traditional DNS infrastructure exposes plaintext UDP port 53 directly to public WAN interfaces, leaving servers vulnerable to volumetric reflection attacks, cache poisoning, and spoofed amplification vectors. **Gapura eliminates public port 53 exposure entirely**: it terminates modern encrypted client sessions (DNS over QUIC, DNS over HTTPS, DNS over TLS), applies per-client token-bucket rate limiting, and forwards validated queries to local backend resolvers over air-gapped private IPC or loopback sockets.

---

## The Defense Ecosystem

Gapura operates as the public perimeter gateway within the unified MECOB defense infrastructure:

```
[ Client / Edge Devices ]
           │
           ▼ (Plaintext DNS on localhost)
   ┌──────────────┐
   │    Caraka    │  Lightweight DNS over QUIC (DoQ) Edge Forwarder
   └──────┬───────┘
          │ (Encrypted DoQ / QUIC - Port 8853)
          ▼
   ┌──────────────┐   eBPF / XDP Kernel Firewall
   │    Gapura    │◄───[ Kalas ] (Layer 3 & Layer 4 Anti-DDoS Filter)
   └──────┬───────┘   Public Ingress Gateway (Rate-Limiting & TLS Termination)
          │
          │ (Air-Gapped Unix Domain Socket / IPC)
          ▼
   ┌──────────────┐   Real-Time Threat Feeds
   │    Runut     │◄─────────────────────────► [ Tameng ]
   └──────┬───────┘   Authoritative Root DNS   Autonomous L7 WAF
          │
          ▼ (Direct iterative queries)
[ 13 Internet Root Servers (A.ROOT .. M.ROOT) ]
```

| Component | Layer / Scope | Role in Ecosystem |
| :--- | :--- | :--- |
| **[Kalas](https://github.com/koodoxz/kalas)** | Layer 3 & 4 (Kernel) | eBPF/XDP kernel firewall dropping packet floods at NIC wire-speed |
| **[Caraka](https://github.com/koodoxz/caraka)** | Client / Edge | Zero-round-trip local proxy forwarding endpoint queries over DoQ |
| **[Gapura](https://github.com/koodoxz/gapura)** | Ingress Gateway | Public entry portal terminating DoH, DoT, and DoQ with token-bucket rate limiting |
| **[Runut](https://github.com/koodoxz/runut)** | Layer 7 (DNS Core) | High-performance zero-GC recursive root resolver |
| **[Tameng](https://github.com/koodoxz/tameng)** | Layer 7 (Application) | Autonomous ML-assisted Web Application Firewall & threat intelligence hub |
| **[Architecture Portal](https://koodoxz.github.io)** | Web Overview | Interactive architectural pipeline visualization and telemetry specs |

---

## Core Capabilities

- **Multi-Protocol Encrypted Termination**:
  - **DoQ (DNS over QUIC - RFC 9250)**: Native QUIC implementation via `quinn` with 0-RTT session resumption and connection migration immunity.
  - **DoH (DNS over HTTPS - RFC 8484)**: High-concurrency HTTP/2 pipeline via `hyper` supporting GET, POST, and base64url wireformat payloads.
  - **DoT (DNS over TLS - RFC 7858)**: Low-latency TLS 1.3 pipeline via `tokio-rustls`.
  - **HTTP to HTTPS Redirect**: Seamless redirect on port 80 to encrypted endpoints.
- **Zero Public Port 53**: Backend resolvers operate strictly on internal loopback interfaces or Unix Domain Sockets, eliminating DNS amplification attack surfaces.
- **Token-Bucket Rate Limiter**: Independent burst allowances and replenishment tracking per client IP to mitigate abusive flood patterns.
- **Intelligent Upstream Load Balancing**:
  - `primary`: Deterministic primary backend with automatic failover upon health check timeout.
  - `round_robin`: Equal distribution across active backend nodes.
  - `weighted`: Proportional traffic distribution based on server capacity weights.
  - `geoip`: MaxMind GeoLite2 routing dispatching queries to the geographically closest backend resolver instance.
- **Automated Health Checking**: Active background polling detecting upstream degradation and evicting failed backends within configurable intervals.
- **Observability**: Native Prometheus metrics exporter (`:9090/metrics`) exposing active sessions, request throughput, and upstream latency.

---

## Configuration Reference

Gapura is configured via a single YAML manifest. A typical production deployment:

```yaml
# Listen addresses
http_addr: "0.0.0.0:80"        # HTTP (auto-redirect to HTTPS)
https_addr: "0.0.0.0:443"      # DoH (HTTPS)
dot_addr: "0.0.0.0:853"        # DoT (TLS)
doq_addr: "0.0.0.0:8853"       # DoQ (QUIC)
metrics_addr: "0.0.0.0:9090"   # Prometheus metrics

# TLS Configuration
tls:
  cert_file: "/etc/ssl/certs/gapura.pem"
  key_file: "/etc/ssl/private/gapura.key"

# Backend Upstream Resolvers (e.g. Runut)
upstreams:
  strategy: primary            # primary | round_robin | weighted | geoip
  health_check_interval_secs: 5
  backends:
    - name: runut-core
      address: "127.0.0.1:5353"
      weight: 100
      region: "ID-JKT"

# Token-Bucket Rate Limiting
rate_limit:
  enabled: true
  requests_per_second: 150
  burst_size: 300
  client_ttl_secs: 300

# GeoIP Routing (Optional)
geoip:
  enabled: false
  database_path: "data/GeoLite2-Country.mmdb"

log_level: info
```

---

## Build & Quickstart

### Prerequisites
- Rust 1.75 or later
- Clang / LLVM (if compiling with native cryptographic extensions)

### Compilation
```bash
# Clone the repository
git clone https://github.com/koodoxz/gapura.git
cd gapura

# Build optimized release binary
cargo build --release

# Inspect compiled binary
./target/release/gapura --version
```

### Running the Gateway
```bash
./target/release/gapura --config configs/odin.yaml
```

---

## License

Licensed under the GNU Affero General Public License v3.0 or later ([AGPL-3.0-or-later](LICENSE)).

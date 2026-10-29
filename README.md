# Gapura (GAPURA)

> High-Performance Ingress Gateway for Encrypted DNS Protocols (DoH / DoT / DoQ)
> Zero-trust entry point, traffic shaper, and TLS terminator.

[![Rust](https://img.shields.io/badge/Rust-1.75+-000000?style=flat&logo=rust)](https://www.rust-lang.org/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Protocols](https://img.shields.io/badge/Protocols-DoH%20%7C%20DoT%20%7C%20DoQ-green.svg)](#protocols)

---

## Executive Summary

**Gapura** (Indonesian: "monumental gateway / entrance portal") is the public-facing gateway designed to shield recursive DNS resolvers (like [Runut](https://github.com/koodoxz/runut)). It terminates client connections over modern encrypted transports, enforces rate-limiting, and intelligently routes queries to backend resolvers.

## Key Features

- Encrypted Protocol Termination: Native DoQ (QUIC:8853), DoH (HTTP/2:443), and DoT (TLS:853).
- Rate Limiting & Abuse Prevention: Token-bucket limiter per client IP.
- Zero Public Port 53: Protects downstream resolvers from direct UDP amplification attacks.
- GeoIP-Aware Backend Routing: Routes DNS queries to nearest backend resolver instance.

## License

Licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).

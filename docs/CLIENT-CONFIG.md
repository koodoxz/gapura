# ODIN-RS Client Configuration Guide

> **Last Updated:** 2026-01-02

## 🔗 Connection URLs

| Protocol | URL | Port |
|----------|-----|------|
| **DoT** | `tls://dns.example.com` | 853 |
| **DoH** | `https://dns.example.com/dns-query` | 443 |
| **DoQ** | `quic://dns.example.com:8853` | 8853 |

---

## 🔧 Bootstrap DNS

**Apa itu Bootstrap DNS?**

Bootstrap DNS digunakan untuk resolve hostname DoQ/DoH server sebelum koneksi encrypted.

```
Client → Bootstrap DNS (plain UDP:53) → resolve "dns.example.com"
                ↓
Client ← IP: 103.150.197.159
                ↓
Client → QUIC connection ke 103.150.197.159:8853
```

**Recommended Bootstrap DNS:**

| Server | IP | Notes |
|--------|-----|-------|
| **MIMIR-OLD** | `103.31.205.42` | ✅ Recommended (our SecDNS) |
| **MIMIR-NEW** | `127.0.0.1` | ✅ Alternative (our primary) |

> ⚠️ **Jangan pakai IP ODIN** (103.150.197.159) sebagai Bootstrap karena ODIN tidak serve plain DNS (UDP:53).

---

## 🔐 DNSSEC

**Status:** Recommended **ON**

DNSSEC (Domain Name System Security Extensions) memvalidasi keaslian response DNS.

| Setting | Recommendation |
|---------|----------------|
| **DNSSEC Validation** | ✅ ON |

**Kenapa ON?**
- Mencegah DNS spoofing/cache poisoning
- Kompatibel dengan DoQ/DoH/DoT
- MIMIR-RS sudah support DNSSEC validation
- Tidak ada performance penalty signifikan

---

## 🌍 ECS (EDNS Client Subnet)

**Status:** Recommended **OFF** (default) atau **ON** dengan pertimbangan

ECS mengirim partial IP client ke upstream untuk geo-optimized responses.

| Setting | Recommendation |
|---------|----------------|
| **ECS** | ⚠️ OFF (privacy) atau ON (performance) |

**Trade-off:**

| ECS ON | ECS OFF |
|--------|---------|
| ✅ CDN responses lebih optimal (geo-aware) | ✅ Privacy lebih baik |
| ⚠️ Partial IP dikirim ke authoritative NS | ✅ Tidak ada info lokasi bocor |
| ✅ Netflix, YouTube, dll lebih cepat | ⚠️ CDN mungkin return jauh server |

**Rekomendasi untuk AEGIS:**
- **Home users**: OFF (privacy priority)
- **Performance critical**: ON (CDN optimization)

> MIMIR-RS sebagai recursive resolver akan forward ECS ke authoritative jika client mengirimnya.

---

## 📱 Example: DNS Relay App Config

```
DoQ Server: quic://dns.example.com:8853
Bootstrap DNS: 103.31.205.42
DNSSEC: ON
ECS: OFF (atau ON sesuai preferensi)
```

---

## 🛡️ Security Stack

```
Client (DoQ) → ODIN Gateway → MIMIR-RS → Internet
                  ↓              ↓
              HEIMDALL       HEIMDALL
              (L3/L4)        + XDP Chain
```

Semua node dilindungi HEIMDALL XDP firewall untuk defense-in-depth.

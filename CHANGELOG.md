# Changelog

## 1.0.0 — 2026-08-17

Final initial release.

### Edge / transport

- raw multi-record TLS ClientHello parser before termination;
- JA3, JA4, normalized `ZTLS`, order-sensitive `ZTLS-WIRE`;
- extended TLS extension/PSK/ECH/ALPS/GREASE/padding/cert-compression telemetry;
- Linux `TCP_INFO` runtime telemetry;
- optional XDP/eBPF SYN sensor and `ZTCP`;
- decrypted wire-tap before Hyper for exact H1 header order/casing;
- HTTP/2 preface/SETTINGS/WINDOW_UPDATE/frame-shape capture and `ZH2`;
- native Quinn + h3 HTTP/3 listener, `ZQUIC`/`ZH3`, Alt-Svc discovery.

### Browser

- expanded dependency-free browser probe;
- full/security/essential collection modes;
- UA-CH, display/input, Intl, WebGL/WebGPU, Canvas, Audio, fonts, media, storage,
  permissions, network, battery, performance, capability, automation and voice signals;
- explicit opt-in sensitive collection API;
- `ZCI.observe()` integration helper;
- referrer sanitization.

### Correlation / SaaS

- persistent tenant-scoped client graph;
- weighted probabilistic observation matching with ambiguity state;
- observed/claimed/inferred/enriched evidence model;
- network CIDR enrichment loader;
- site/admin tenant keys;
- trusted-proxy CIDR verification with right-to-left forwarded-chain resolution;
- CORS allowlist;
- Prometheus metrics;
- retention cleanup;
- client summary API;
- URI query-value redaction and credential header redaction.

### Operations

- PostgreSQL migrations;
- Docker Compose TCP+UDP deployment;
- optional Linux sensor compose profile;
- smoke test and release-check script;
- Rust/JS/eBPF CI;
- deployment, API, signal, privacy and security documentation.

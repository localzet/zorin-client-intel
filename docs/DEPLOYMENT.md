# Deployment

## Ports

Default listeners:

```text
8080/tcp  plain HTTP development/health endpoint
8443/tcp  HTTPS + HTTP/1.1 + HTTP/2
8443/udp  QUIC + HTTP/3
```

TLS and QUIC listeners start only when both `ZCI_TLS_CERT` and `ZCI_TLS_KEY` are configured.

## Native

Requirements:

- Rust 1.88 toolchain;
- certificate/private key for TLS/H3;
- optional PostgreSQL;
- Linux only for enhanced TCP_INFO/XDP telemetry.

```bash
./scripts/dev-cert.sh
export ZCI_TLS_CERT=certs/cert.pem
export ZCI_TLS_KEY=certs/key.pem
export DATABASE_URL='postgres://zci:zci@127.0.0.1:5432/zci'
cargo run --release -p client-intel-collector
```

Without `DATABASE_URL`, collector uses ephemeral in-memory storage.

## Docker Compose

```bash
cp .env.example .env
./scripts/dev-cert.sh
docker compose up --build
```

Expose both TCP and UDP 8443 through firewall/security group/load balancer if HTTP/3 is required.

## Tenant keys

Example:

```env
ZCI_SITE_KEYS=shop:pk_shop_random;account:pk_account_random
ZCI_ADMIN_KEYS=shop:sk_shop_random;account:sk_account_random
```

Global admin example:

```env
ZCI_ADMIN_KEYS=*:sk_global_random
```

Use long random values. A site key may be visible in frontend code; an admin key may not.

## CORS

Example:

```env
ZCI_CORS_ORIGINS=https://www.example.com,https://account.example.com
```

Do not use a permissive wildcard when browser observations are tenant-scoped.

## Reverse proxy / CDN

If collector does **not** terminate original TLS, it cannot recover the visitor's original raw TLS ClientHello through a normal HTTP reverse proxy. In that topology, TLS wire fingerprint represents proxy → collector unless original metadata is forwarded by a trusted integration.

For maximum transport visibility, terminate public TLS/QUIC directly at ZCI edge or route transport transparently.

If an HTTP reverse proxy supplies real client IP:

```env
TRUST_PROXY_HEADERS=true
ZCI_TRUSTED_PROXY_CIDRS=10.0.0.0/8,2001:db8:abcd::/48
```

Only those direct peers are allowed to influence the stored client IP. For `X-Forwarded-For`, ZCI walks the chain from the socket peer backwards and strips only explicitly trusted proxy hops; this avoids trusting a spoofed left-most address merely because the immediate proxy is trusted.

## Enrichment

ZCI deliberately avoids hidden network calls to IP-intelligence providers. Build/import a local JSON database in the documented format and configure:

```env
ZCI_ENRICHMENT_DB=/data/enrichment.json
```

`data/enrichment.example.json` uses documentation addresses and is not a production database.

Lookup is longest-prefix-match over configured CIDRs.

## Linux XDP sensor

Native:

```bash
make -C sensors/linux-tcp
sudo ./sensors/linux-tcp/tcp-sensor eth0 /tmp/zci-tcp-sensor.sock
```

Compose:

```bash
ZCI_SENSOR_INTERFACE=eth0 docker compose --profile sensor up --build
```

The sensor profile is privileged because attaching XDP requires elevated kernel capabilities. It never intentionally drops traffic.

## Retention

```env
RETENTION_DAYS=30
```

An hourly task removes older observations and cleans client summaries with no remaining observations.

Historical matching has a separate window:

```env
ZCI_GRAPH_WINDOW_DAYS=90
ZCI_GRAPH_CANDIDATE_LIMIT=1500
ZCI_GRAPH_MATCH_THRESHOLD=0.76
ZCI_GRAPH_MIN_CONFIDENCE=0.42
```

Tuning thresholds changes false-link/false-split tradeoffs. Validate against your own population before treating a client graph result as a security control.

## Metrics

```text
GET /metrics
```

If metrics should not be public, restrict this route at ingress/firewall level.

## Health and smoke test

```bash
curl -fsS http://127.0.0.1:8080/health
./scripts/smoke.sh
```

## Release verification

Run the complete repository verification on a machine with Rust 1.88, Node.js and the required C/eBPF build dependencies:

```bash
./scripts/release-check.sh
make -C sensors/linux-tcp
```

## Production TLS

Development `scripts/dev-cert.sh` creates a self-signed certificate only for local testing. Use a normal trusted certificate and key in production.

HTTP/3 discovery uses `Alt-Svc` with the configured QUIC listener port. If external NAT/ingress maps it to a different public port, keep public and bound ports aligned or terminate H3 at a component that advertises the correct public authority.

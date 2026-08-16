# ZCI HTTP API

Base URL examples:

```text
http://127.0.0.1:8080
https://127.0.0.1:8443
```

HTTP/3 uses the same HTTPS authority over UDP when configured.

## Authentication model

### Ingestion

If `ZCI_SITE_KEYS` is non-empty:

```http
X-ZCI-Site-Key: <tenant-site-key>
```

A matched key determines `tenant_id`.

If no site keys are configured, development mode uses tenant `local`.

### Administrative reads

If `ZCI_ADMIN_KEYS` is non-empty:

```http
X-ZCI-Admin-Key: <secret-admin-key>
```

Each admin key is tenant-scoped. Tenant `*` can be configured as a global administrative scope.

If no admin keys are configured, local development reads are open.

## `GET /health`

Example:

```json
{
  "status": "ok",
  "storage": "postgres",
  "tls_collector": true,
  "quic_http3_collector": true,
  "wire_http_fingerprinting": true,
  "enrichment": false,
  "enrichment_source": null,
  "tcp_sensor_socket": "/run/zci/tcp-sensor.sock",
  "site_key_required": true,
  "admin_key_required": true,
  "configured_tenants": 2,
  "retention_days": 30,
  "graph_window_days": 90
}
```

## `GET /metrics`

Prometheus text exposition.

Current counters include observations, graph result states, sensor events and storage errors.

## `GET /api/v1/schema`

Returns advertised observation/browser schemas, implemented layers and fingerprint names.

## `GET /probe.js`

Serves the first-party browser SDK.

## `GET /inspect`

Self-inspection UI. It can run collection modes and display the returned profile/client graph result.

## `POST /api/v1/observe`

Request body: `BrowserProbe` with schema `zci-browser-probe/2`.

Typical browser usage:

```js
const result = await ZCI.observe({
  endpoint: "https://intel.example.com/api/v1/observe",
  siteKey: "PUBLIC_SITE_KEY",
  mode: "security",
});
```

Conceptual response:

```json
{
  "id": "5f5a9e9d-...",
  "tenant_id": "example",
  "client_id": "ee2886cf-...",
  "created_at": "2026-08-17T00:00:00Z",
  "connection": {
    "remote_ip": "203.0.113.10",
    "transport": "tcp+tls",
    "tcp": {},
    "tls": {},
    "http1_wire": {},
    "http2": null,
    "quic": null
  },
  "http": {},
  "browser": {},
  "fingerprints": {},
  "profile": {},
  "resolution": {
    "kind": "matched_client",
    "client_id": "ee2886cf-...",
    "probability": 0.93,
    "confidence": 0.88,
    "matched_observation_id": "...",
    "matching_components": ["tls_stable", "browser", "gpu"],
    "conflicting_components": ["http"]
  },
  "raw": {}
}
```

### URI storage behavior

Incoming URI:

```text
/callback?code=SECRET&state=SECRET2
```

stored as:

```text
/callback?code&state
```

Header values that may contain credentials are replaced with `<redacted>`.

## `GET /api/v1/observations/{id}`

Returns one observation if it exists inside caller admin scope.

## `GET /api/v1/compare/{left}/{right}`

Returns component-level comparison:

```json
{
  "left": "...",
  "right": "...",
  "match": {
    "same_client_probability": 0.88,
    "confidence": 0.74,
    "available_weight": 0.81,
    "matching_components": ["tls_stable", "gpu"],
    "conflicting_components": ["browser"]
  }
}
```

The numbers are heuristic evidence scores, not authentication assertions.

## `GET /api/v1/clients/{id}`

Returns materialized client summary:

- tenant/client IDs;
- first/last seen;
- observation count;
- latest profile/fingerprints;
- recent observation IDs.

## CORS

Cross-origin access is disabled unless `ZCI_CORS_ORIGINS` contains explicit origins. Allowed browser request headers are:

- `Content-Type`;
- `X-ZCI-Site-Key`;
- `X-ZCI-Admin-Key`.

Do not put an admin key in browser code even though the header is technically accepted by the API layer.

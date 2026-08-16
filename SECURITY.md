# Security

ZCI processes security-sensitive telemetry. Do not log or persist authentication secrets.

The default collector redacts values of:

- Authorization
- Proxy-Authorization
- Cookie
- Set-Cookie

`TRUST_PROXY_HEADERS` is disabled by default. Enable it only when the collector is behind a reverse proxy that you control and which overwrites untrusted forwarding headers.

For a public deployment, add tenant authentication, rate limiting, retention enforcement and access controls before exposing observation lookup endpoints.

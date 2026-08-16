# Privacy and data boundary

ZCI intentionally has a large fingerprinting surface. That makes the data useful for fraud/security/client diagnostics, but also means deployment must have a defined purpose, retention policy and access boundary.

This document describes software behavior, not legal advice.

## 1. Identity semantics

`client_id` means:

> ZCI linked a set of observations inside one tenant because their independent evidence components were sufficiently similar.

It does **not** mean:

- a verified real-world person;
- a cryptographic hardware identity;
- an account authentication result;
- proof that two people sharing a browser/device are the same person.

## 2. Collection modes

### `essential`

Minimizes high-entropy/rendering fields while keeping basic platform/security metadata.

### `security`

Keeps most consistency-relevant features, omits some high-variance/nonessential fields.

### `full`

Collects all non-permission-gated probes implemented by SDK.

The integrating application chooses a mode explicitly.

## 3. Permission-gated sensitive probes

The default `ZCI.collect()` does not request permissions.

`ZCI.collectSensitive()` can explicitly request/collect selected categories:

- geolocation;
- local fonts;
- media devices;
- keyboard layout;
- WebRTC candidates.

Integrators should surface clear UX and collect only categories needed for the intended purpose.

## 4. Secrets minimization

Server-side:

- credential header values are redacted;
- query values are removed;
- site/admin API key values are not persisted as request header values.

Browser-side:

- referrer query/fragment/credentials are removed;
- media device identifiers are hashed before return by explicit sensitive helper.

## 5. IP and enrichment

Peer IP may be personal/security-sensitive data. ZCI keeps observed IP separate from enrichment source/result.

No third-party enrichment request is performed automatically by the collector. Operators choose and load an offline dataset.

## 6. Historical linkage

Historical client graph can increase identifiability even when individual signals appear innocuous. Configure:

- finite `RETENTION_DAYS`;
- finite graph window;
- tenant isolation;
- admin API controls.

Do not share client IDs across unrelated tenants unless that is an explicit, justified architecture choice outside this collector.

## 7. Cross-origin embedding

CORS is allowlist-based. Avoid turning one ZCI deployment into an invisible cross-site identifier shared by unrelated origins.

## 8. Raw packet policy

The included XDP sensor captures SYN metadata only and does not persist packet payload. ZCI 1.0 has no raw PCAP archive path.

## 9. Recommended operational controls

- document collection purpose;
- choose the least invasive SDK mode that meets it;
- gate explicit sensitive probes;
- minimize retention;
- protect admin APIs and database backups;
- expose confidence/ambiguity instead of presenting inferred identity as certainty;
- provide appropriate user transparency/controls where required for the deployment context.

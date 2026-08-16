# Zorin Client Intelligence

**Zorin Client Intelligence (ZCI)** — self-hosted client-intelligence и device-fingerprinting engine, который объединяет сетевые, TLS, HTTP, QUIC и browser-side сигналы в единый evidence profile.

ZCI не сводит клиента к одному «visitor hash». Каждый observation хранит происхождение данных и независимые component fingerprints, а historical client graph оценивает вероятность того, что новый observation относится к ранее наблюдавшемуся client entity.

## Возможности финального релиза 1.0

### Network / transport

- реальный peer IPv4/IPv6 и socket metadata;
- trusted-proxy mode с allowlist CIDR;
- offline CIDR enrichment: Geo/ASN/organization/network type/VPN/proxy/Tor flags;
- Linux TCP runtime telemetry через `TCP_INFO`;
- optional XDP/eBPF SYN sensor: TTL/Hop Limit, MSS, window, scale, SACK, timestamps, ECN, TCP option order;
- `ZTCP` fingerprint.

### TLS

Collector смотрит исходные ClientHello bytes **до** rustls termination:

- ClientHello через один или несколько TLS records;
- record/legacy/supported TLS versions;
- cipher suites и их порядок;
- extension IDs и детали;
- groups, EC point formats, signature algorithms;
- certificate signature algorithms;
- key shares;
- ALPN и SNI;
- PSK modes, session ticket, early data;
- padding;
- certificate compression;
- GREASE;
- ECH/ALPS indicators;
- raw ClientHello SHA-256;
- JA3;
- JA4;
- `ZTLS` — нормализованный fingerprint;
- `ZTLS-WIRE` — order-sensitive fingerprint;
- negotiated TLS version/ALPN.

Случайные/секретные TLS values не сохраняются как fingerprint material.

### HTTP/1.1 и HTTP/2

После TLS termination используется wire-tap до Hyper parser:

- H1 request line;
- точный wire-order заголовков;
- исходный header casing;
- duplicate header observations;
- `ZH1-WIRE`;
- HTTP/2 client preface;
- SETTINGS values и wire-order;
- SETTINGS ACK;
- initial WINDOW_UPDATE;
- последовательность первых frames;
- `ZH2`;
- нормализованный application-level `ZHTTP`.

Credential-bearing header values redacted до хранения.

### Native QUIC / HTTP/3

Отдельный listener на Quinn + h3:

- UDP peer/local metadata;
- address-validation state;
- original destination connection ID length;
- negotiated H3 ALPN;
- runtime RTT;
- max datagram size;
- `ZQUIC`;
- `ZH3` для доступного H3/runtime material;
- `Alt-Svc` discovery с HTTPS endpoint.

ZCI не выдумывает QUIC-поля, которых выбранный userspace QUIC API не предоставляет. TCP/TLS listener остаётся источником сырого TLS ClientHello/JA3/JA4.

### Browser probe

`web/probe.js` — dependency-free first-party SDK с режимами `essential`, `security`, `full`:

- User-Agent + UA Client Hints/high-entropy values;
- navigator/platform/languages/hardwareConcurrency/deviceMemory/touch;
- screen, viewport, DPR, orientation;
- Intl/timezone/formatting;
- media queries/input/display/privacy preferences;
- WebGL/WebGL2/WebGPU;
- Canvas;
- OfflineAudio;
- font metric inference;
- codecs/media capabilities;
- storage/permissions;
- Network Information API;
- Battery API;
- Performance API;
- browser/platform capability matrix;
- automation indicators;
- speech voices;
- component fingerprints `ZBROWSER`, `ZGPU`, `ZCANVAS`, `ZAUDIO`, `ZFONTS`, `ZINTL`, `ZCAP`, `ZSCREEN`, `ZMEDIA`, `ZAUTO`.

Permission-gated/особенно чувствительные probes вынесены в отдельный explicit opt-in: geolocation, Local Font Access, media devices, keyboard layout, WebRTC candidate collection.

### Correlation / client graph

Каждый POST `/api/v1/observe` получает:

- immutable `observation.id`;
- tenant-scoped `client_id`;
- resolution `new_client`, `matched_client` или `ambiguous`;
- weighted similarity probability;
- confidence по доступному evidence;
- matching/conflicting component list;
- consistency/anomaly profile;
- automation/privacy/network risk scores.

Смена IP или одной нестабильной browser/TLS части не обязана создавать нового client entity.

### SaaS / operations

- PostgreSQL JSONB + in-memory development mode;
- tenant-scoped public site keys и secret admin keys;
- CORS allowlist;
- observation retention;
- Prometheus text metrics;
- self-inspection UI `/inspect`;
- health/schema endpoints;
- Docker Compose;
- optional eBPF sidecar compose profile;
- CI для Rust, JS и Linux sensor;
- smoke test.

## Быстрый запуск

### 1. Native HTTP-only

```bash
cargo run -p client-intel-collector
```

Открыть:

```text
http://localhost:8080/inspect
```

В этом режиме browser/HTTP/IP сигналы работают, но TLS и HTTP/3 отсутствуют.

### 2. HTTPS + HTTP/2 + HTTP/3

```bash
./scripts/dev-cert.sh

ZCI_TLS_CERT=certs/cert.pem \
ZCI_TLS_KEY=certs/key.pem \
cargo run -p client-intel-collector
```

Открыть:

```text
https://localhost:8443/inspect
```

HTTPS listener использует TCP `:8443`, native HTTP/3 — UDP `:8443`. После первого HTTPS-ответа ZCI публикует `Alt-Svc` для H3 discovery.

### 3. Docker Compose

```bash
cp .env.example .env
./scripts/dev-cert.sh
docker compose up --build
```

С Linux SYN sensor:

```bash
ZCI_SENSOR_INTERFACE=eth0 docker compose --profile sensor up --build
```

XDP sidecar требует Linux, BTF и privileged access для attach.

### Smoke test

```bash
./scripts/smoke.sh
```

Полная release-проверка на машине с Rust toolchain:

```bash
./scripts/release-check.sh
```

Или для другого endpoint:

```bash
ZCI_BASE_URL=https://example.test ./scripts/smoke.sh
```

## Browser SDK

Минимально:

```html
<script src="https://intel.example.com/probe.js"></script>
<script>
  const observation = await ZCI.observe({
    endpoint: "https://intel.example.com/api/v1/observe",
    siteKey: "PUBLIC_SITE_KEY",
    mode: "security"
  });

  console.log(observation.client_id, observation.resolution);
</script>
```

`siteKey` предназначен для first-party браузерной интеграции и не считается секретом. Чтение сохранённых observations защищается отдельным admin key.

Explicit sensitive collection запускается только интегратором:

```js
const sensitive = await ZCI.collectSensitive({
  geolocation: true,
  localFonts: true,
  mediaDevices: true,
  keyboardLayout: true,
  webRtcCandidates: true,
});
```

Не включайте эти probes без подходящего UX/consent/legal basis.

## API

Основные endpoints:

```text
GET  /health
GET  /metrics
GET  /api/v1/schema
GET  /probe.js
GET  /inspect

POST /api/v1/observe
GET  /api/v1/observations/:id
GET  /api/v1/compare/:left/:right
GET  /api/v1/clients/:id
```

- `POST /api/v1/observe` использует `X-ZCI-Site-Key`, если настроены site keys.
- read/compare/client endpoints используют `X-ZCI-Admin-Key`, если настроены admin keys.

Подробнее: [`docs/API.md`](docs/API.md).

## Data model

ZCI принципиально различает:

- **observed** — сервер увидел сам;
- **claimed** — клиент сообщил о себе;
- **inferred** — движок сделал вероятностный вывод;
- **enriched** — данные пришли из явно подключённой внешней/offline базы.

Это не позволяет эвристике тихо превратиться в «факт».

## Privacy/security defaults

По умолчанию ZCI:

- не сохраняет значения `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, ZCI/API keys;
- не сохраняет query values: остаются только path + имена/порядок параметров;
- очищает browser `document.referrer` от credentials/query/fragment;
- не доверяет `X-Forwarded-For`, пока trusted-proxy mode явно не включён;
- не запускает permission-gated browser probes автоматически;
- использует finite retention;
- не называет fingerprint криптографическим доказательством личности.

См. [`SECURITY.md`](SECURITY.md) и [`docs/PRIVACY.md`](docs/PRIVACY.md).

## Структура

```text
crates/client-intel-core/     parser, fingerprints, models, correlation
services/collector/           HTTP/TLS/QUIC edge + API + storage
sensors/linux-tcp/            optional XDP/eBPF SYN sensor
web/probe.js                  browser SDK
web/inspect.html              self-inspection console
migrations/                   PostgreSQL schema
data/                         offline enrichment example
docs/                         architecture/API/deployment/privacy/catalog
scripts/                      development/smoke helpers
```


## Документация

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/SIGNAL_CATALOG.md`](docs/SIGNAL_CATALOG.md)
- [`docs/API.md`](docs/API.md)
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)
- [`docs/PRIVACY.md`](docs/PRIVACY.md)

## License

Copyright © 2026 Ivan Zorin. All rights reserved. См. [`LICENSE`](LICENSE).

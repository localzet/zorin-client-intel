# Zorin Client Intelligence

Zorin Client Intelligence (ZCI) — первый фундамент client-intelligence / device-fingerprinting SaaS. Он объединяет наблюдаемые сетевые признаки с браузерными сигналами и хранит не один «магический visitor ID», а полный evidence profile.

## Что уже есть

- Rust collector с HTTP и собственным HTTPS edge.
- Byte-level разбор исходного TLS ClientHello до TLS-терминации.
- JA3, JA4 и собственный стабильный `ZTLS` fingerprint.
- HTTP fingerprint по версии протокола, набору заголовков и browser fetch characteristics.
- Browser probe без внешних зависимостей.
- UA / UA-CH high entropy values.
- Screen / viewport / DPR / orientation.
- Intl / timezone / locale formatting fingerprint.
- Media queries и input/display capabilities.
- WebGL / WebGPU capabilities.
- Canvas и OfflineAudio fingerprints.
- Font metric probe + отдельный Local Font Access API по явному разрешению.
- Codec / MediaSource capabilities.
- Storage, Permissions, Network Information, Battery и Performance signals.
- Automation indicators.
- Speech synthesis voices.
- Component fingerprints вместо одного общего hash.
- `observed / claimed / inferred` модель.
- Consistency/anomaly engine.
- Сравнение двух observations через `/api/v1/compare/:left/:right`.
- PostgreSQL JSONB storage с in-memory fallback.
- Self-inspection UI `/inspect`.
- Docker Compose.

## Быстрый запуск

### Вариант 1: только HTTP, без PostgreSQL

```bash
cargo run -p client-intel-collector
```

Открыть:

```text
http://localhost:8080/inspect
```

TLS/JA3/JA4 в этом режиме отсутствуют, потому что браузер не делает TLS handshake с collector.

### Вариант 2: полноценный HTTPS collector

Создать development certificate:

```bash
./scripts/dev-cert.sh
```

Запустить:

```bash
ZCI_TLS_CERT=certs/cert.pem \
ZCI_TLS_KEY=certs/key.pem \
cargo run -p client-intel-collector
```

Открыть:

```text
https://localhost:8443/inspect
```

Для self-signed сертификата браузеру потребуется вручную подтвердить доверие.

### Docker Compose

```bash
./scripts/dev-cert.sh
docker compose up --build
```

## API

### `GET /health`

Состояние collector/storage.

### `POST /api/v1/observe`

Тело — объект `zci-browser-probe/1`, который создаёт `/probe.js`.

Ответ — полная observation:

```json
{
  "id": "...",
  "connection": {
    "remote_ip": "...",
    "transport": "tcp+tls",
    "tls": {
      "ja3": "...",
      "ja4": "...",
      "stable_tls_fp": "ztls1_..."
    }
  },
  "http": {},
  "browser": {},
  "fingerprints": {},
  "profile": {}
}
```

### `GET /api/v1/observations/:id`

Возвращает сохранённую observation.

### `GET /api/v1/compare/:left/:right`

Сравнивает component fingerprints двух observations и возвращает вероятностное сходство.

## Принцип модели

ZCI принципиально различает:

- **observed** — сервер увидел сам: IP, ClientHello, negotiated TLS, HTTP request;
- **claimed** — клиент сообщил о себе: User-Agent, UA-CH, navigator/platform;
- **inferred** — движок сделал вывод: probable OS/browser/device, automation probability, anomalies.

Это позволяет не выдавать эвристику за факт и строить граф согласованности.

## Почему Cookie и Authorization не сохраняются

ZCI сохраняет присутствие и имя HTTP-заголовка, но значения `Cookie`, `Set-Cookie`, `Authorization` и `Proxy-Authorization` заменяет на `<redacted>`. Секреты почти никогда не добавляют полезной fingerprint entropy, зато превращают телеметрию в хранилище учётных данных.

## Ограничения v0.1

- HTTP header order берётся после разбора Hyper и не считается точным wire-order fingerprint. Для точного H1 order нужен raw HTTP tap перед parser.
- TCP SYN fingerprint пока не реализован: обычный userspace TCP socket получает соединение уже после handshake. Для него нужен eBPF/AF_PACKET/pcap sidecar.
- QUIC/HTTP3 отсутствуют; следующий edge должен использовать `quinn` и собственный QUIC transport-parameter fingerprint.
- ASN/Geo/VPN/hosting enrichment не включён в ядро. Его следует подключать отдельными providers, чтобы не смешивать наблюдаемые данные и сторонние базы.
- Risk scores сейчас намеренно консервативны: один fingerprint не объявляется доказательством бота, VPN или личности.

## Следующие технические слои

См. `docs/ARCHITECTURE.md` и `docs/SIGNAL_CATALOG.md`.

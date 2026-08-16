# ZCI Architecture 1.0

## 1. Design goal

ZCI отвечает не на вопрос «какой hash у клиента?», а на четыре независимых вопроса:

1. Что сервер **наблюдал** на транспортном/TLS/HTTP уровне?
2. Что клиент **заявил** через HTTP/browser APIs?
3. Что движок может **вывести** из комбинации сигналов?
4. Насколько новый observation **похож на исторические observations** того же tenant?

Каждый вывод хранится отдельно от первичного evidence.

## 2. End-to-end flow

```text
                           ┌───────────────────────┐
                           │      Browser SDK      │
                           │  navigator/render/etc │
                           └───────────┬───────────┘
                                       │ POST probe
                                       ▼
Client ── TCP SYN ──► optional XDP sensor ─────┐
  │                                             │ tuple cache
  ├─ TCP socket ──► TCP_INFO ──────────────────┤
  │                                             │
  ├─ TLS records ─► raw ClientHello parser ────┤
  │                                             │
  ├─ decrypted H1/H2 ─► wire tap ──────────────┤
  │                                             │
  └─ QUIC/H3 ─────► native Quinn/h3 listener ──┤
                                                ▼
                                      ConnectionContext
                                                │
                              ┌─────────────────┼─────────────────┐
                              ▼                 ▼                 ▼
                         enrichment        normalization      redaction
                              │                 │                 │
                              └─────────────────┴─────────────────┘
                                                ▼
                                      component fingerprints
                                                │
                                                ▼
                                       consistency engine
                                                │
                                                ▼
                                       historical matcher
                                                │
                                    ┌───────────┴───────────┐
                                    ▼                       ▼
                              Observation              Client entity
                                    │                       │
                                    └───────────┬───────────┘
                                                ▼
                                        PostgreSQL / API
```

## 3. Components

### `client-intel-core`

Pure/domain layer:

- serializable models;
- TLS ClientHello parser;
- JA3/JA4;
- ZCI component fingerprints;
- consistency/profile engine;
- observation similarity calculation;
- IP metadata helpers.

Core не зависит от Axum/PostgreSQL/Quinn.

### `client-intel-collector`

Runtime/edge layer:

- HTTP development listener;
- TCP/TLS edge;
- decrypted wire tap;
- native QUIC/H3 edge;
- browser ingestion API;
- tenant/auth boundary;
- storage/client graph;
- enrichment loader;
- metrics/retention;
- transport-sensor correlation.

### `linux-tcp sensor`

Опциональный Linux-only XDP observer. Userspace TCP socket уже не имеет доступа к исходному SYN packet, поэтому SYN fingerprint material собирается до TCP stack и join-ится по tuple.

### `probe.js`

First-party browser collector без внешних runtime dependencies. SDK ничего не отправляет сам по себе: интегратор вызывает `ZCI.collect()` или `ZCI.observe()`.

## 4. TLS path

TCP/TLS listener делает `TcpStream::peek()` до rustls handshake.

Parser:

1. читает один или несколько TLS records;
2. собирает handshake stream;
3. находит ClientHello;
4. извлекает структурные поля;
5. считает raw ClientHello SHA-256;
6. строит JA3/JA4/ZTLS/ZTLS-WIRE;
7. не потребляет bytes из socket;
8. отдаёт тот же stream rustls.

После handshake negotiated TLS metadata объединяется с pre-handshake observation.

### `ZTLS`

Нормализованный fingerprint. Volatile/GREASE элементы исключаются или нормализуются, списки, где порядок не должен определять identity, сортируются.

### `ZTLS-WIRE`

Order-sensitive fingerprint. Сохраняет wire shape ClientHello и полезен для определения конкретной реализации/маскировки.

Использовать их следует вместе: `ZTLS` устойчивее, `ZTLS-WIRE` дискриминирует точнее.

## 5. HTTP wire path

Hyper должен получить уже разобранный transport stream, но ZCI нужен wire shape. Поэтому `TapIo` стоит **между TLS/plain stream и Hyper** и копирует только bounded prefix.

### HTTP/1

Из tap извлекаются:

- request line;
- exact header sequence;
- original casing;
- duplicate entries;
- wire header fingerprint.

Body не нужен для wire fingerprint.

### HTTP/2

Tap распознаёт connection preface и разбирает bounded sequence frames:

- SETTINGS IDs/values/order;
- SETTINGS ACK;
- WINDOW_UPDATE;
- первые frame type/flags/stream/length tuples.

HPACK payload не сохраняется.

## 6. QUIC / HTTP/3 path

QUIC использует отдельный UDP listener на Quinn.

До handshake сохраняются metadata `Incoming`, после handshake — runtime metadata `Connection`, negotiated ALPN и H3 request handling через `h3`/`h3-axum`.

QUIC observation намеренно содержит только то, что runtime реально раскрывает. Он не подменяет TCP/TLS ClientHello parser и не утверждает, что видел raw CRYPTO frames, если их не видел.

`Alt-Svc` на HTTPS UI/SDK responses позволяет браузеру обнаружить H3 endpoint.

## 7. TCP sensor correlation

```text
SYN packet
   │
   ▼
XDP parser
   │
   ├─ remote IP
   ├─ remote port
   ├─ local port
   └─ TCP traits
          │
          ▼
Unix datagram
          │
          ▼
30s tuple cache
          │
          └── join ─► accepted application connection
```

Runtime `TCP_INFO` поля сохраняются при merge с sensor event.

## 8. Evidence model

### Observed

Источник: socket/TLS/HTTP/QUIC/browser request transport.

### Claimed

Источник: User-Agent, UA-CH, navigator и другие значения, сообщённые client runtime.

### Inferred

Источник: правила/эвристики consistency engine.

Каждый inference содержит confidence и evidence refs.

### Enriched

Источник: явно подключённая offline CIDR database. Enrichment никогда не маскируется под observed fact.

## 9. Fingerprint strategy

ZCI хранит независимые components:

```text
JA3 / JA4
ZTLS / ZTLS-WIRE
ZTCP
ZHTTP
ZH1-WIRE / ZH2
ZQUIC / ZH3
ZBROWSER
ZGPU
ZCANVAS
ZAUDIO
ZFONTS
ZINTL
ZCAP
ZSCREEN
ZMEDIA
ZAUTO
```

Нельзя использовать один component как identity proof. Исторический matcher учитывает доступность каждого component и разные веса.

## 10. Client graph

При новом observation:

1. выбираются recent candidate observations того же tenant за `graph_window_days`;
2. рассчитывается component-level similarity;
3. строятся probability + confidence;
4. лучший candidate сравнивается с configurable threshold;
5. близкий второй candidate с другим `client_id` переводит результат в `ambiguous`;
6. иначе создаётся новый или используется существующий `client_id`.

Это intentionally probabilistic linkage, не криптографическая идентичность.

## 11. Storage

### PostgreSQL

`observations` хранит:

- индексируемые top-level fields;
- полную immutable JSONB document representation.

`clients` хранит materialized summary:

- first/last seen;
- observation count;
- latest profile/fingerprints.

Migrations idempotent и выполняются collector при старте. Docker image PostgreSQL также может применить их на пустом volume.

### In-memory

Без `DATABASE_URL` collector работает в memory mode. Он поддерживает тот же API/client graph, но всё теряется после restart.

## 12. Tenancy

Site/admin keys задаются через env mapping:

```text
tenant-a:key-a;tenant-b:key-b
```

- site key → ingestion tenant;
- admin key → read scope tenant;
- tenant `*` у admin key даёт global read scope;
- отсутствие настроенных keys сохраняет local-development behavior.

## 13. Privacy boundary

Collector удаляет credential values до persistence. Browser sensitive APIs отделены explicit method. Historical `client_id` означает связь observations в рамках tenant и не должен называться реальной личностью.

## 14. Scaling boundary

Текущий 1.0 collector — самодостаточный deployable unit. Для очень большого трафика его state boundaries уже позволяют разнести без изменения data model:

- stateless edge collectors;
- external sensor tuple cache;
- PostgreSQL control/client state;
- columnar observation/event warehouse;
- standalone enrichment service.

Такое разбиение является deployment optimization, а не требованием для корректности 1.0.

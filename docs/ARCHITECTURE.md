# Architecture

## 1. Цель

ZCI должен отвечать не на вопрос «какой один hash у клиента?», а на четыре разных вопроса:

1. Что мы **наблюдали** на сети и HTTP?
2. Что клиент **заявил** о себе?
3. Что мы можем **вывести** из этих признаков?
4. Насколько признаки **согласованы** между собой и с предыдущими observations?

## 2. Data flow

```text
Client
  │
  ├── TCP socket
  │     └── future: eBPF SYN observer -> ZTCP
  │
  ├── TLS ClientHello
  │     └── raw peek parser -> JA3 / JA4 / ZTLS
  │
  ├── HTTP/1.1 or HTTP/2
  │     └── request metadata -> ZHTTP
  │
  └── browser probe.js
        ├── UA / UA-CH
        ├── rendering
        ├── graphics
        ├── media
        ├── locale
        ├── storage / permissions
        ├── capabilities
        └── behavioral/environment signals
              │
              ▼
        Normalization
              │
              ▼
        Component fingerprints
              │
              ▼
        Consistency engine
              │
              ▼
        Observation document
              │
        ┌─────┴─────┐
        ▼           ▼
    PostgreSQL    API/UI
```

## 3. Почему несколько fingerprints

Полный hash ломается после любого обновления. Поэтому ZCI хранит независимые компоненты:

```text
JA3
JA4
ZTLS
ZHTTP
ZBROWSER
ZGPU
ZCANVAS
ZAUDIO
ZFONTS
ZINTL
ZCAP
```

При сравнении observations компоненты получают разные веса. Смена сети или minor browser update не должна автоматически означать новое устройство.

## 4. TLS edge

`services/collector/src/server.rs` делает `TcpStream::peek()` до rustls handshake. Peek не потребляет данные, поэтому:

1. ZCI видит оригинальные bytes ClientHello.
2. Собственный parser извлекает fingerprint material.
3. Тот же сокет передаётся rustls.
4. После handshake Hyper обслуживает HTTP/1.1 или HTTP/2.

Так исходный ClientHello не теряется за reverse proxy.

### ClientHello parser

Текущая версия извлекает:

- TLS record version;
- legacy ClientHello version;
- supported_versions;
- cipher suites;
- extension IDs;
- supported groups;
- EC point formats;
- signature algorithms;
- key_share groups;
- ALPN;
- SNI;
- session ID length;
- compression methods;
- record / ClientHello lengths.

GREASE исключается из JA3/JA4 material.

## 5. HTTP layer

Текущий ZHTTP содержит:

- HTTP version;
- header names;
- Accept;
- Accept-Encoding;
- Accept-Language;
- Sec-Fetch-*;
- Sec-CH-UA-*;
- Priority.

В будущем raw H1 observer должен дополнительно сохранить:

- точный wire order;
- исходный casing;
- whitespace style;
- duplicate header behavior;
- malformed/edge-case behavior.

HTTP/2 observer должен добавить:

- SETTINGS values/order;
- pseudo-header order;
- initial window behavior;
- PRIORITY / PRIORITY_UPDATE;
- frame sequencing;
- HPACK dynamic-table behavior.

## 6. TCP layer

Userspace listener не видит исходный SYN после `accept()`. Поэтому production ZTCP проектируется как отдельный Linux observer:

```text
XDP/eBPF or AF_PACKET
        │
        ├── src/dst tuple
        ├── TTL
        ├── MSS
        ├── window
        ├── window scale
        ├── SACK
        ├── timestamps
        ├── ECN
        └── option order
              │
              ▼
        short-lived tuple cache
              │
              ▼
        collector joins by 5-tuple
```

Это позволит сопоставлять TCP stack с TLS/HTTP легендой клиента.

## 7. QUIC / HTTP3

Следующий transport edge:

- QUIC version;
- Initial packet size/pattern;
- Connection ID lengths;
- TLS ClientHello inside QUIC CRYPTO frames;
- QUIC transport parameters;
- parameter ordering;
- HTTP/3 SETTINGS;
- QPACK behavior.

Форматы: `ZQUIC` и `ZH3`.

## 8. Storage model

PostgreSQL используется как простой source of truth на раннем этапе. Observation хранится как полноценный JSONB document плюс отдельные индексируемые поля.

Для high-volume SaaS логично разделить:

- PostgreSQL — tenants, API keys, policies, client entities;
- ClickHouse — immutable observations/event telemetry;
- Redis — short-lived tuple/session correlation;
- object storage — опциональные raw packet captures в debug/research режиме.

## 9. Privacy boundary

SDK не запускает collection автоматически. `collect()` должен вызываться интегратором осознанно. Permission-gated API (например Local Font Access) вынесены в отдельные методы и не вызываются тихо.

По умолчанию collector также не сохраняет значения credential-bearing headers.

## 10. Production decomposition

```text
zci-edge-tcp      eBPF/TCP observer
zci-edge-tls      TLS/H1/H2 collector
zci-edge-quic     QUIC/H3 collector
zci-browser-sdk   first-party JS SDK
zci-correlator    observation/session joining
zci-identity      probabilistic client graph
zci-enrichment    ASN/Geo/VPN/provider adapters
zci-api           tenant-facing API
zci-console       dashboard / inspector
```

Сейчас они намеренно собраны компактнее, чтобы core-модель можно было быстро гонять локально.

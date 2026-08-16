# Security policy

ZCI обрабатывает телеметрию, которая может быть security-sensitive и/или персональными данными. Collector проектируется по принципу «собрать fingerprint material, но не собирать credentials».

## Что редактируется до хранения

HTTP values для следующих заголовков заменяются на `<redacted>`:

- `Authorization`;
- `Proxy-Authorization`;
- `Cookie`;
- `Set-Cookie`;
- `X-ZCI-Admin-Key`;
- `X-ZCI-Site-Key`;
- `X-API-Key`.

URI query values не сохраняются. Collector оставляет path и имена query parameters в исходном порядке.

Browser SDK очищает `document.referrer` от username/password/query/fragment.

## Tenant keys

`ZCI_SITE_KEYS` — publishable ingestion keys. Они разделяют tenants, но **не являются секретом**, если находятся в browser SDK.

`ZCI_ADMIN_KEYS` — secret credentials для observation/client read API. Не встраивайте их в браузер.

В памяти collector хранит SHA-256 representation настроенных keys и сравнивает digest без early-exit по содержимому.

## Trusted proxy

`TRUST_PROXY_HEADERS=false` по умолчанию.

При включении `X-Forwarded-For` применяется только если непосредственный socket peer входит в `ZCI_TRUSTED_PROXY_CIDRS`. Reverse proxy должен перезаписывать входные forwarding headers, а не дописывать недоверенное значение вслепую.

## Browser permission boundary

`ZCI.collect()` никогда автоматически не запрашивает geolocation/local-font/media/keyboard permissions.

Такие probes доступны только через `ZCI.collectSensitive(...)` и должны вызываться после подходящего UX/consent flow.

## Network sensor

Linux XDP sensor:

- всегда возвращает `XDP_PASS`;
- не модифицирует пакеты;
- не сохраняет payload;
- экспортирует только SYN metadata в локальный Unix datagram socket.

Docker profile для sensor privileged по необходимости XDP attach. Не запускайте его на недоверенном host.

## Production recommendations

- используйте реальные TLS certificates;
- задайте `ZCI_SITE_KEYS` и `ZCI_ADMIN_KEYS`;
- ограничьте `ZCI_CORS_ORIGINS`;
- держите `/metrics` и HTTP development listener за внутренним ingress/firewall при необходимости;
- задайте подходящий retention;
- шифруйте database/storage volumes согласно threat model;
- применяйте ingress rate limiting/DDoS protection;
- логируйте административный доступ на внешнем gateway, если это требуется вашей модели аудита;
- не трактуйте `client_id` как доказательство физической личности.

## Reporting

Не публикуйте секреты, production dumps или реальные client observations в issue tracker. Передавайте security report владельцу репозитория по приватному каналу.

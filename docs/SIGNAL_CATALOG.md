# Signal Catalog

Ниже каталог сигналов, который служит roadmap. `[x]` означает, что сигнал уже собирается в v0.1, `[~]` — частично, `[ ]` — запланирован.

## Network / IP

- [x] remote IP address
- [x] remote port
- [x] local collector port
- [~] trusted X-Forwarded-For mode
- [ ] IPv4/IPv6 prefix traits
- [ ] ASN
- [ ] ISP / organization
- [ ] country / region / city coarse GeoIP
- [ ] hosting / residential classification
- [ ] VPN/proxy/Tor provider enrichment
- [ ] reverse DNS
- [ ] IP reputation
- [ ] observed RTT distribution

## TCP

- [ ] IP TTL / inferred initial TTL
- [ ] MSS
- [ ] receive window
- [ ] window scale
- [ ] SACK permitted
- [ ] timestamps
- [ ] ECN
- [ ] TCP option order
- [ ] SYN packet size
- [ ] IP DF behavior
- [ ] ZTCP fingerprint
- [ ] probable OS/kernel TCP stack

## TLS

- [x] record version
- [x] ClientHello legacy_version
- [x] supported_versions
- [x] cipher suites + order
- [x] extensions + order
- [x] supported groups
- [x] EC point formats
- [x] signature algorithms
- [x] key share groups
- [x] ALPN list
- [x] SNI
- [x] session ID length
- [x] compression methods
- [x] ClientHello length
- [x] record length
- [x] JA3 string/hash
- [x] JA4
- [x] ZTLS stable fingerprint
- [x] negotiated ALPN
- [x] negotiated TLS version
- [ ] PSK/session-resumption traits
- [ ] padding extension details
- [ ] ECH outer ClientHello classification
- [ ] fragmentation / multi-record behavior
- [ ] handshake timing

## HTTP/1

- [x] method
- [x] URI
- [x] HTTP version
- [~] header names/order after Hyper parsing
- [x] common browser header values
- [x] sensitive credential headers redacted
- [x] ZHTTP fingerprint
- [ ] exact wire header order
- [ ] original casing
- [ ] whitespace formatting
- [ ] duplicate headers
- [ ] connection reuse behavior

## HTTP/2

- [x] protocol detection via request version
- [ ] SETTINGS order
- [ ] SETTINGS values
- [ ] pseudo-header order
- [ ] initial WINDOW_UPDATE
- [ ] stream/window behavior
- [ ] priority behavior
- [ ] HPACK behavior
- [ ] frame order
- [ ] ZH2 fingerprint

## QUIC / HTTP3

- [ ] QUIC version
- [ ] Connection ID characteristics
- [ ] Initial packet characteristics
- [ ] QUIC transport parameters
- [ ] transport parameter order
- [ ] QUIC RTT
- [ ] H3 SETTINGS
- [ ] QPACK behavior
- [ ] ZQUIC
- [ ] ZH3

## Browser / navigator

- [x] User-Agent
- [x] platform/vendor/product
- [x] language/languages
- [x] DNT/GPC
- [x] webdriver
- [x] maxTouchPoints
- [x] hardwareConcurrency
- [x] deviceMemory
- [x] plugins
- [x] MIME types
- [x] PDF viewer state
- [x] UA Client Hints
- [x] UA-CH high entropy values

## Display / input

- [x] screen dimensions
- [x] available dimensions
- [x] color/pixel depth
- [x] devicePixelRatio
- [x] screen orientation
- [x] viewport / visualViewport
- [x] pointer/hover media queries
- [x] touch support
- [x] color gamut
- [x] HDR/dynamic range hints
- [x] prefers-* settings

## Graphics

- [x] WebGL/WebGL2 availability
- [x] vendor / renderer
- [x] unmasked vendor / renderer when exposed
- [x] GL version / shader version
- [x] texture/render limits
- [x] extension list
- [x] WebGPU availability
- [x] WebGPU features/limits/info when exposed
- [x] ZGPU component fingerprint

## Rendering

- [x] Canvas pixel hash
- [x] Canvas data URL hash
- [x] Text metrics
- [x] OfflineAudioContext sample hash
- [x] Audio numeric aggregate

## Fonts

- [x] metric-based common-font detection
- [x] Local Font Access capability detection
- [x] explicit permission-gated local font enumeration helper
- [x] ZFONTS component fingerprint

## Locale / Intl

- [x] timezone
- [x] timezone offset
- [x] locale
- [x] calendar
- [x] numbering system
- [x] hour cycle
- [x] DateTime formatting sample
- [x] Number/Currency formatting samples
- [x] plural rules
- [x] list/relative-time formatting
- [x] ZINTL component fingerprint

## Media

- [x] canPlayType codec matrix
- [x] MediaSource codec matrix
- [x] Picture-in-Picture capability
- [x] MediaCapabilities availability
- [ ] hardware decode performance probes
- [ ] DRM/key-system capability matrix

## Storage / privacy

- [x] cookie enabled
- [x] localStorage/sessionStorage
- [x] IndexedDB
- [x] CacheStorage
- [x] StorageManager estimate
- [x] persisted storage
- [x] permission states without requesting grants
- [ ] partitioning behavior probes
- [ ] third-party cookie policy probe

## Network Information API

- [x] effectiveType
- [x] connection type when exposed
- [x] downlink
- [x] RTT
- [x] saveData

## Battery

- [x] API support
- [x] charging state
- [x] battery level
- [x] charge/discharge time when exposed

## Performance

- [x] timeOrigin / timer values
- [x] navigation protocol
- [x] transfer sizes
- [x] DNS/connect/TLS/response timings
- [x] Chromium heap metrics when exposed
- [ ] calibrated CPU microbenchmarks
- [ ] WASM performance classes
- [ ] rendering timing distribution

## Browser capabilities

- [x] Secure Context
- [x] crossOriginIsolated
- [x] SharedArrayBuffer
- [x] WebAssembly
- [x] WebGPU/WebGL2
- [x] WebRTC/WebSocket/WebTransport
- [x] ServiceWorker
- [x] Bluetooth/USB/HID/Serial/NFC presence
- [x] File System Access
- [x] Local Font Access
- [x] CSS.supports matrix
- [ ] JS syntax/runtime quirk matrix
- [ ] WebAssembly proposal support matrix

## Automation

- [x] navigator.webdriver
- [x] common Selenium globals
- [x] plugin/MIME counts
- [x] chrome object presence
- [x] error stack shape sample
- [ ] CDP side-effect probes
- [ ] headless rendering discrepancies
- [ ] interaction/timing behavior

## Speech

- [x] SpeechSynthesis support
- [x] voice names/languages/default/local-service list

## Correlation

- [x] independent component fingerprints
- [x] weighted observation comparison
- [x] basic UA / UA-CH platform consistency
- [x] automation heuristic
- [ ] historical client graph
- [ ] probabilistic Bayesian matching
- [ ] feature stability learning per browser version
- [ ] contradiction graph across TCP/TLS/H2/JS

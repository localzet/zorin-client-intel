# Signal Catalog — ZCI 1.0

Legend:

- `[x]` — реализовано;
- `[~]` — реализовано в ограниченной форме/зависит от platform API;
- `[-]` — намеренно не собирается либо недоступно без иной trust boundary.

## Network / IP

- [x] socket peer IPv4/IPv6
- [x] remote/local port
- [x] local IP when runtime exposes it
- [x] IP version
- [x] private/loopback/link-local/multicast classification
- [x] trusted `X-Forwarded-For` behind explicit CIDR allowlist
- [x] offline CIDR longest-prefix enrichment
- [x] country/region/city fields from configured database
- [x] timezone from configured database
- [x] ASN / organization from configured database
- [x] network type from configured database
- [x] hosting/mobile/VPN/proxy/Tor flags from configured database
- [x] enrichment tags/confidence/source
- [-] implicit third-party GeoIP calls from collector
- [-] automatic reverse DNS

## TCP

### Runtime socket

- [x] RTT / RTT variance on Linux
- [x] send/receive MSS on Linux
- [x] congestion window on Linux
- [x] retransmit counters on Linux

### XDP SYN sensor

- [x] IPv4 TTL
- [x] IPv6 Hop Limit for direct TCP next-header
- [x] MSS
- [x] receive window
- [x] window scale
- [x] SACK permitted
- [x] timestamps
- [x] ECN
- [x] TCP option order
- [x] SYN payload length
- [x] ZTCP fingerprint
- [~] IPv6: extension-header chain packets are passed but not parsed
- [-] packet payload capture

## TLS over TCP

- [x] TLS record version
- [x] ClientHello legacy version
- [x] supported versions
- [x] cipher suites + wire order
- [x] extension IDs + wire order
- [x] extension lengths/details
- [x] supported groups
- [x] EC point formats
- [x] signature algorithms
- [x] certificate signature algorithms
- [x] key-share groups
- [x] ALPN list
- [x] SNI presence/value
- [x] session ID length
- [x] compression methods
- [x] PSK key-exchange modes
- [x] pre-shared-key presence
- [x] session-ticket presence
- [x] early-data presence
- [x] padding length
- [x] certificate-compression algorithms
- [x] GREASE cipher/extension/group counts
- [x] ECH extension presence
- [x] ALPS extension presence
- [x] multi-record ClientHello reassembly
- [x] record count
- [x] ClientHello/handshake size
- [x] raw ClientHello SHA-256
- [x] JA3 string/hash
- [x] JA4
- [x] ZTLS normalized fingerprint
- [x] ZTLS-WIRE order-sensitive fingerprint
- [x] negotiated TLS version
- [x] negotiated ALPN
- [-] PSK identities/binders stored as values
- [-] key-share public key bytes stored as fingerprint material

## HTTP generic

- [x] method
- [x] sanitized URI path
- [x] query parameter names/order
- [-] query parameter values
- [x] HTTP version
- [x] normalized header names
- [x] common browser header values
- [x] User-Agent
- [x] Accept / Accept-Encoding / Accept-Language
- [x] Sec-Fetch-*
- [x] Sec-CH-UA / platform
- [x] Priority
- [x] credential header presence/name
- [-] credential header values
- [x] ZHTTP

## HTTP/1 wire

- [x] request line
- [x] exact header wire order
- [x] original casing
- [x] duplicate header entries
- [x] bounded raw-header shape parser
- [x] ZH1-WIRE

## HTTP/2 wire

- [x] protocol preface detection
- [x] SETTINGS values
- [x] SETTINGS order
- [x] SETTINGS ACK observation
- [x] initial WINDOW_UPDATE
- [x] first frame type/flags/stream/length sequence
- [x] ZH2
- [-] HPACK-decoded secret-bearing header payload copied by wire tap

## QUIC / HTTP/3

- [x] native UDP/QUIC listener
- [x] peer address
- [x] local IP when exposed
- [x] remote-address-validation state
- [x] original destination CID length
- [x] runtime RTT
- [x] max datagram size
- [x] negotiated H3 ALPN
- [x] ZQUIC over runtime-visible properties
- [x] ZH3 over runtime-visible H3/ALPN properties
- [~] H3 settings model supports settings when available to collector integration
- [-] fabricated raw QUIC transport parameters
- [-] fabricated raw QUIC ClientHello

## Browser / navigator

- [x] User-Agent
- [x] platform/vendor/product/subproduct
- [x] language/languages
- [x] DNT / GPC when exposed
- [x] `navigator.webdriver`
- [x] maxTouchPoints
- [x] hardwareConcurrency
- [x] deviceMemory
- [x] plugins
- [x] MIME types
- [x] PDF viewer state
- [x] UA Client Hints
- [x] UA-CH high-entropy values when browser exposes them

## Display / input

- [x] screen/available dimensions
- [x] color/pixel depth
- [x] devicePixelRatio
- [x] orientation
- [x] viewport / visualViewport
- [x] pointer/hover media queries
- [x] touch capability
- [x] color gamut
- [x] dynamic range hints
- [x] reduced motion/transparency/data
- [x] contrast/color-scheme preferences

## Graphics

- [x] WebGL/WebGL2 availability
- [x] vendor/renderer
- [x] unmasked vendor/renderer when exposed
- [x] GL/shader versions
- [x] implementation limits
- [x] extension list
- [x] WebGPU availability
- [~] WebGPU adapter info/features/limits as exposed by browser
- [x] ZGPU

## Rendering

- [x] Canvas pixel hash
- [x] Canvas encoded-data hash
- [x] text metrics
- [x] OfflineAudio sample hash
- [x] audio numeric aggregate
- [x] ZCANVAS
- [x] ZAUDIO

## Fonts

- [x] metric-based common-font inference
- [x] Local Font Access capability detection
- [x] explicit permission-gated local font enumeration
- [x] ZFONTS

## Locale / Intl

- [x] timezone
- [x] timezone offset
- [x] locale
- [x] calendar
- [x] numbering system
- [x] hour cycle
- [x] date/number/currency formatting samples
- [x] plural rules
- [x] list/relative-time formatting
- [x] ZINTL

## Media

- [x] `canPlayType` codec matrix
- [x] MediaSource codec matrix
- [x] Picture-in-Picture capability
- [x] MediaCapabilities presence
- [x] ZMEDIA
- [-] DRM license acquisition

## Storage / privacy

- [x] cookie enabled state
- [x] local/session storage capability
- [x] IndexedDB
- [x] CacheStorage
- [x] StorageManager estimate
- [x] persisted-storage state
- [x] existing permission states without requesting grants

## Network Information API

- [x] effective type
- [x] connection type when exposed
- [x] downlink
- [x] RTT
- [x] saveData

## Battery

- [x] API support
- [x] charging state
- [x] level
- [x] charge/discharge time when exposed

## Performance

- [x] time origin/timer values
- [x] navigation protocol
- [x] transfer sizes
- [x] DNS/connect/TLS/response timings
- [x] Chromium heap fields when exposed

## Browser capability matrix

- [x] secure context
- [x] crossOriginIsolated
- [x] SharedArrayBuffer
- [x] WebAssembly
- [x] WebGPU/WebGL2
- [x] WebRTC/WebSocket/WebTransport presence
- [x] ServiceWorker
- [x] Bluetooth/USB/HID/Serial/NFC API presence
- [x] File System Access
- [x] Local Font Access
- [x] CSS.supports matrix
- [x] ZCAP

## Automation

- [x] webdriver
- [x] common Selenium globals
- [x] plugin/MIME counts
- [x] Chromium global object presence
- [x] error stack shape
- [x] ZAUTO

## Speech

- [x] SpeechSynthesis availability
- [x] voice name/language/default/local-service list

## Explicit sensitive collection

Only through `ZCI.collectSensitive()`:

- [x] geolocation + accuracy/altitude/heading/speed if permission granted
- [x] Local Font Access enumeration if permission granted
- [x] media-device kind/label + hashed device/group IDs as exposed
- [x] keyboard layout map if exposed/granted
- [x] WebRTC ICE candidate strings if explicitly requested

## Correlation

- [x] independent component fingerprints
- [x] weighted observation comparison
- [x] probability + confidence
- [x] historical tenant-scoped client graph
- [x] new/matched/ambiguous resolution
- [x] matching/conflicting component evidence
- [x] UA/UA-CH consistency checks
- [x] TLS/HTTP protocol consistency checks
- [x] network risk enrichment
- [x] automation heuristic
- [x] retention-aware graph window
- [-] claim that `client_id` identifies a human with certainty

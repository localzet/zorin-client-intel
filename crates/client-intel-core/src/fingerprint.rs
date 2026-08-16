use crate::canonical::canonical_json;
use crate::{
    BrowserProbe, Http1WireObservation, Http2Observation, HttpObservation, QuicObservation,
    TcpObservation, TlsObservation,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    let mut digest = Sha256::new();
    digest.update(data.as_ref());
    hex::encode(digest.finalize())
}

fn is_grease(value: u16) -> bool {
    let high = (value >> 8) as u8;
    let low = value as u8;
    high == low && high & 0x0f == 0x0a
}

fn short_hash(value: &Value) -> String {
    sha256_hex(canonical_json(value))[..24].to_string()
}

pub fn fingerprint_tls_stable(tls: &TlsObservation) -> String {
    let mut ciphers = tls
        .cipher_suites
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect::<Vec<_>>();
    ciphers.sort_unstable();
    ciphers.dedup();

    let mut extensions = tls
        .extensions
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .filter(|value| !matches!(*value, 0x0015 | 0x0029))
        .collect::<Vec<_>>();
    extensions.sort_unstable();
    extensions.dedup();

    let mut groups = tls
        .supported_groups
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect::<Vec<_>>();
    groups.sort_unstable();
    groups.dedup();

    let value = json!({
        "supported_versions": tls.supported_versions,
        "cipher_suites": ciphers,
        "extensions": extensions,
        "supported_groups": groups,
        "signature_algorithms": tls.signature_algorithms,
        "signature_algorithms_cert": tls.signature_algorithms_cert,
        "certificate_compression_algorithms": tls.certificate_compression_algorithms,
        "psk_key_exchange_modes": tls.psk_key_exchange_modes,
        "alpn": tls.alpn,
        "sni_present": tls.sni.is_some(),
        "ech": tls.has_ech,
        "alps": tls.has_alps,
    });

    format!("ztls1_{}", short_hash(&value))
}

pub fn fingerprint_tls_wire(tls: &TlsObservation) -> String {
    let value = json!({
        "legacy_version": tls.legacy_version,
        "supported_versions": tls.supported_versions,
        "cipher_suites": tls.cipher_suites,
        "extensions": tls.extension_details,
        "groups": tls.supported_groups,
        "signature_algorithms": tls.signature_algorithms,
        "key_share_groups": tls.key_share_groups,
        "alpn": tls.alpn,
        "session_id_len": tls.session_id_len,
        "record_count": tls.record_count,
        "client_hello_len": tls.client_hello_len,
    });

    format!("ztlsw1_{}", short_hash(&value))
}

pub fn fingerprint_tcp(tcp: &TcpObservation) -> String {
    let value = json!({
        "ip_version": tcp.ip_version,
        "ttl": tcp.ttl,
        "hop_limit": tcp.hop_limit,
        "window_size": tcp.window_size,
        "mss": tcp.mss,
        "window_scale": tcp.window_scale,
        "sack": tcp.sack_permitted,
        "timestamps": tcp.timestamps,
        "ecn": tcp.ecn,
        "options_order": tcp.options_order,
        "syn_payload_len": tcp.syn_payload_len,
    });

    format!("ztcp1_{}", short_hash(&value))
}

pub fn fingerprint_http(http: &HttpObservation) -> String {
    let value = json!({
        "version": http.version,
        "header_names": http.header_names,
        "accept": http.accept,
        "accept_encoding": http.accept_encoding,
        "accept_language": http.accept_language,
        "sec_fetch_site": http.sec_fetch_site,
        "sec_fetch_mode": http.sec_fetch_mode,
        "sec_fetch_dest": http.sec_fetch_dest,
        "sec_ch_ua": http.sec_ch_ua,
        "sec_ch_ua_platform": http.sec_ch_ua_platform,
        "priority": http.priority,
    });

    format!("zhttp1_{}", short_hash(&value))
}

pub fn fingerprint_http1_wire(http: &Http1WireObservation) -> String {
    let value = json!({
        "request_line": http.request_line,
        "header_names": http.header_names,
        "header_count": http.header_count,
        "header_bytes": http.header_bytes,
    });

    format!("zh1w1_{}", short_hash(&value))
}

pub fn fingerprint_http2(http2: &Http2Observation) -> String {
    let frame_shape = http2
        .first_frames
        .iter()
        .take(16)
        .map(|frame| json!([frame.frame_type, frame.flags, frame.stream_id == 0, frame.length]))
        .collect::<Vec<_>>();

    let value = json!({
        "settings": http2.settings,
        "connection_window_update": http2.connection_window_update,
        "frame_shape": frame_shape,
    });

    format!("zh2_{}", short_hash(&value))
}

pub fn fingerprint_quic(quic: &QuicObservation) -> String {
    let value = json!({
        "version": quic.version,
        "odcid_len": quic.original_destination_connection_id_len,
        "scid_len": quic.source_connection_id_len,
        "alpn": quic.alpn,
        "transport_parameters": quic.transport_parameters,
        "tls_stable": quic.tls.as_ref().and_then(|tls| tls.stable_tls_fp.clone()),
    });

    format!("zquic1_{}", short_hash(&value))
}

pub fn fingerprint_http3(quic: &QuicObservation) -> Option<String> {
    if quic.http3_settings.is_empty() && !quic.alpn.iter().any(|value| value.starts_with("h3")) {
        return None;
    }

    let value = json!({
        "alpn": quic.alpn,
        "settings": quic.http3_settings,
    });
    Some(format!("zh3_{}", short_hash(&value)))
}

pub fn fingerprint_browser(browser: &BrowserProbe) -> String {
    // В основной browser fingerprint не включаем время, батарею и performance timings.
    // Эти сигналы полезны для анализа, но намеренно нестабильны между сессиями.
    let value = json!({
        "navigator": browser.navigator,
        "ua_ch": browser.user_agent_client_hints,
        "screen": browser.screen,
        "intl": browser.intl,
        "media_queries": browser.media_queries,
        "webgl": browser.webgl,
        "webgpu": browser.webgpu,
        "canvas": browser.canvas,
        "audio": browser.audio,
        "fonts": browser.fonts,
        "media": browser.media,
        "capabilities": browser.capabilities,
        "automation": browser.automation,
        "voices": browser.voices,
    });

    format!("zbrowser1_{}", short_hash(&value))
}

pub fn fingerprint_component(prefix: &str, value: &Value) -> Option<String> {
    if value.is_null() || value == &json!({}) || value == &json!([]) {
        return None;
    }

    Some(format!("{prefix}_{}", short_hash(value)))
}

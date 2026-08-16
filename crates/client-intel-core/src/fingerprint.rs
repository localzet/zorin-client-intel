use crate::canonical::canonical_json;
use crate::{BrowserProbe, HttpObservation, TlsObservation};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn sha256_hex(data: impl AsRef<[u8]>) -> String {
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
        "alpn": tls.alpn,
        "sni_present": tls.sni.is_some(),
    });

    format!("ztls1_{}", short_hash(&value))
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

pub fn fingerprint_browser(browser: &BrowserProbe) -> String {
    // В основной browser fingerprint не включаем время сбора и performance timings.
    // Они полезны как сигналы, но слишком изменчивы для стабильного идентификатора.
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

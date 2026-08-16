use crate::fingerprint::fingerprint_component;
use crate::{
    BrowserProbe, ClientProfile, ConnectionMeta, Evidence, Fingerprints, HttpObservation, Inference,
    MatchResult, RiskScores, SignalSource,
};
use serde_json::{json, Value};

fn value_str<'a>(root: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut value = root;
    for part in path {
        value = value.get(*part)?;
    }
    value.as_str()
}

fn value_bool(root: &Value, path: &[&str]) -> Option<bool> {
    let mut value = root;
    for part in path {
        value = value.get(*part)?;
    }
    value.as_bool()
}

fn ua_browser(ua: &str) -> Option<&'static str> {
    if ua.contains("Edg/") {
        Some("Microsoft Edge")
    } else if ua.contains("OPR/") || ua.contains("Opera/") {
        Some("Opera")
    } else if ua.contains("Firefox/") || ua.contains("FxiOS/") {
        Some("Firefox")
    } else if ua.contains("Chrome/") || ua.contains("CriOS/") {
        Some("Chrome")
    } else if ua.contains("Safari/") && ua.contains("Version/") {
        Some("Safari")
    } else {
        None
    }
}

fn ua_os(ua: &str) -> Option<&'static str> {
    if ua.contains("Windows NT") {
        Some("Windows")
    } else if ua.contains("Android") {
        Some("Android")
    } else if ua.contains("iPhone") || ua.contains("iPad") || ua.contains("CPU iPhone OS") {
        Some("iOS/iPadOS")
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        Some("macOS")
    } else if ua.contains("Linux") {
        Some("Linux")
    } else {
        None
    }
}

fn inferred(value: impl Into<String>, confidence: f32, evidence: Vec<Evidence>) -> Inference {
    Inference {
        value: Some(value.into()),
        confidence: confidence.clamp(0.0, 1.0),
        evidence,
    }
}

fn add_anomaly(anomalies: &mut Vec<String>, message: impl Into<String>) {
    let message = message.into();
    if !anomalies.contains(&message) {
        anomalies.push(message);
    }
}

fn probability_from_flag(value: Option<bool>, positive: f32) -> f32 {
    match value {
        Some(true) => positive,
        Some(false) => 0.01,
        None => 0.0,
    }
}

pub fn build_profile(
    connection: &ConnectionMeta,
    http: &HttpObservation,
    browser: Option<&BrowserProbe>,
) -> (ClientProfile, Fingerprints) {
    let tls = connection.tls.as_ref();
    let mut anomalies = Vec::new();
    let mut fingerprints = Fingerprints {
        ja3: tls.and_then(|value| value.ja3.clone()),
        ja4: tls.and_then(|value| value.ja4.clone()),
        tls_stable: tls.and_then(|value| value.stable_tls_fp.clone()),
        tls_wire: tls.and_then(|value| value.wire_tls_fp.clone()),
        tcp: connection.tcp.as_ref().and_then(|value| value.fingerprint.clone()),
        http: http.http_fp.clone(),
        http1_wire: connection
            .http1_wire
            .as_ref()
            .and_then(|value| value.fingerprint.clone()),
        http2: connection
            .http2
            .as_ref()
            .and_then(|value| value.fingerprint.clone()),
        quic: connection.quic.as_ref().and_then(|value| value.fingerprint.clone()),
        http3: connection
            .quic
            .as_ref()
            .and_then(|value| value.http3_fingerprint.clone()),
        ..Fingerprints::default()
    };

    let mut browser_inference = Inference::default();
    let mut os_inference = Inference::default();
    let mut device_inference = Inference::default();
    let mut network_inference = Inference::default();
    let mut automation_probability: f32 = 0.0;
    let mut privacy_resistance: f32 = 0.0;
    let mut signal_count = 0usize;
    let mut available_signal_count = 0usize;

    if let Some(ua) = &http.user_agent {
        signal_count += 1;
        available_signal_count += 1;

        if let Some(name) = ua_browser(ua) {
            browser_inference = inferred(
                name,
                0.55,
                vec![Evidence {
                    signal: "http.user_agent".to_string(),
                    source: SignalSource::Claimed,
                    value: json!(ua),
                    weight: 0.55,
                    note: Some("User-Agent является заявленным клиентом значением".to_string()),
                }],
            );
        }

        if let Some(name) = ua_os(ua) {
            os_inference = inferred(
                name,
                0.52,
                vec![Evidence {
                    signal: "http.user_agent".to_string(),
                    source: SignalSource::Claimed,
                    value: json!(ua),
                    weight: 0.52,
                    note: None,
                }],
            );
        }
    }

    if let Some(tls) = tls {
        signal_count += 12;
        available_signal_count += usize::from(!tls.cipher_suites.is_empty())
            + usize::from(!tls.extensions.is_empty())
            + usize::from(!tls.supported_groups.is_empty())
            + usize::from(!tls.signature_algorithms.is_empty())
            + usize::from(!tls.alpn.is_empty())
            + usize::from(tls.sni.is_some())
            + usize::from(tls.ja3.is_some())
            + usize::from(tls.ja4.is_some())
            + usize::from(tls.stable_tls_fp.is_some())
            + usize::from(tls.wire_tls_fp.is_some())
            + usize::from(tls.client_hello_len.is_some())
            + usize::from(tls.raw_client_hello_hash.is_some());
    }

    if let Some(tcp) = &connection.tcp {
        signal_count += 10;
        available_signal_count += usize::from(tcp.window_size.is_some())
            + usize::from(tcp.mss.is_some())
            + usize::from(tcp.window_scale.is_some())
            + usize::from(tcp.sack_permitted.is_some())
            + usize::from(tcp.timestamps.is_some())
            + usize::from(tcp.ecn.is_some())
            + usize::from(!tcp.options_order.is_empty())
            + usize::from(tcp.runtime_rtt_us.is_some())
            + usize::from(tcp.runtime_snd_cwnd.is_some())
            + usize::from(tcp.fingerprint.is_some());
    }

    if let Some(enrichment) = &connection.enrichment {
        signal_count += 8;
        available_signal_count += usize::from(enrichment.country_code.is_some())
            + usize::from(enrichment.asn.is_some())
            + usize::from(enrichment.organization.is_some())
            + usize::from(enrichment.network_type.is_some())
            + usize::from(enrichment.is_hosting.is_some())
            + usize::from(enrichment.is_vpn.is_some())
            + usize::from(enrichment.is_proxy.is_some())
            + usize::from(enrichment.is_tor.is_some());

        if let Some(network_type) = &enrichment.network_type {
            network_inference = inferred(
                network_type,
                enrichment.confidence.max(0.40),
                vec![Evidence {
                    signal: "network.enrichment.network_type".to_string(),
                    source: SignalSource::Enriched,
                    value: json!(network_type),
                    weight: enrichment.confidence.max(0.40),
                    note: enrichment.source.clone(),
                }],
            );
        }
    }

    if let Some(browser) = browser {
        signal_count += 20;
        let sections = [
            &browser.navigator,
            &browser.user_agent_client_hints,
            &browser.screen,
            &browser.viewport,
            &browser.intl,
            &browser.media_queries,
            &browser.webgl,
            &browser.webgpu,
            &browser.canvas,
            &browser.audio,
            &browser.fonts,
            &browser.media,
            &browser.storage,
            &browser.permissions,
            &browser.network,
            &browser.battery,
            &browser.capabilities,
            &browser.automation,
            &browser.voices,
            &browser.misc,
        ];
        available_signal_count += sections
            .iter()
            .filter(|value| {
                let value: &Value = *value;
                !value.is_null() && value != &json!({})
            })
            .count();

        fingerprints.browser = Some(crate::fingerprint::fingerprint_browser(browser));
        fingerprints.graphics = fingerprint_component("zgpu1", &browser.webgl);
        fingerprints.canvas = fingerprint_component("zcanvas1", &browser.canvas);
        fingerprints.audio = fingerprint_component("zaudio1", &browser.audio);
        fingerprints.fonts = fingerprint_component("zfonts1", &browser.fonts);
        fingerprints.intl = fingerprint_component("zintl1", &browser.intl);
        fingerprints.capabilities = fingerprint_component("zcap1", &browser.capabilities);
        fingerprints.screen = fingerprint_component("zscreen1", &browser.screen);
        fingerprints.media = fingerprint_component("zmedia1", &browser.media);
        fingerprints.automation = fingerprint_component("zauto1", &browser.automation);

        if value_bool(&browser.automation, &["webdriver"]) == Some(true)
            || value_bool(&browser.navigator, &["webdriver"]) == Some(true)
        {
            automation_probability = automation_probability.max(0.92);
            add_anomaly(&mut anomalies, "navigator.webdriver=true");
        }

        let suspicious_globals = browser
            .automation
            .get("suspicious_globals")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        if suspicious_globals > 0 {
            automation_probability = automation_probability.max(0.88);
            add_anomaly(
                &mut anomalies,
                format!("automation globals detected: {suspicious_globals}"),
            );
        }

        if value_bool(&browser.capabilities, &["cookie_enabled"]) == Some(false) {
            privacy_resistance = privacy_resistance.max(0.35);
        }

        let platform = value_str(&browser.user_agent_client_hints, &["platform"])
            .or_else(|| value_str(&browser.navigator, &["platform"]));

        if let (Some(platform), Some(current_os)) = (platform, os_inference.value.as_deref()) {
            let lower = platform.to_ascii_lowercase();
            let agrees = match current_os {
                "Windows" => lower.contains("win"),
                "macOS" => lower.contains("mac"),
                "Android" => lower.contains("android"),
                "Linux" => lower.contains("linux"),
                "iOS/iPadOS" => lower.contains("iphone") || lower.contains("ipad") || lower.contains("ios"),
                _ => true,
            };

            if agrees {
                os_inference.confidence = (os_inference.confidence + 0.22).min(0.95);
                os_inference.evidence.push(Evidence {
                    signal: "browser.platform".to_string(),
                    source: SignalSource::Claimed,
                    value: json!(platform),
                    weight: 0.22,
                    note: Some("Платформа браузера согласуется с User-Agent".to_string()),
                });
            } else {
                add_anomaly(
                    &mut anomalies,
                    format!("UA reports {current_os}, browser platform reports {platform}"),
                );
            }
        }

        if let Some(mobile) = browser
            .user_agent_client_hints
            .get("mobile")
            .and_then(Value::as_bool)
        {
            device_inference = inferred(
                if mobile {
                    "Mobile device"
                } else {
                    "Desktop-class device"
                },
                0.72,
                vec![Evidence {
                    signal: "ua_ch.mobile".to_string(),
                    source: SignalSource::Claimed,
                    value: json!(mobile),
                    weight: 0.72,
                    note: None,
                }],
            );
        } else if let Some(touch_points) = browser
            .navigator
            .get("max_touch_points")
            .and_then(Value::as_u64)
        {
            device_inference = inferred(
                if touch_points > 1 {
                    "Touch-capable device"
                } else {
                    "Desktop-class device"
                },
                0.38,
                vec![Evidence {
                    signal: "navigator.maxTouchPoints".to_string(),
                    source: SignalSource::Observed,
                    value: json!(touch_points),
                    weight: 0.38,
                    note: None,
                }],
            );
        }

        if let Some(ua_ch_brands) = browser
            .user_agent_client_hints
            .get("brands")
            .and_then(Value::as_array)
        {
            let brand_text = ua_ch_brands
                .iter()
                .filter_map(|entry| entry.get("brand").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join(" ");

            let expected = browser_inference.value.as_deref().unwrap_or_default();
            if expected == "Chrome" && !brand_text.contains("Chrom") && !brand_text.contains("Google") {
                add_anomaly(&mut anomalies, "Chrome User-Agent is inconsistent with UA-CH brands");
            }
        }

        if let (Some(browser_tz), Some(enrichment)) = (
            value_str(&browser.intl, &["timezone"]),
            connection.enrichment.as_ref(),
        ) {
            if let Some(network_tz) = enrichment.timezone.as_deref() {
                if browser_tz != network_tz {
                    add_anomaly(
                        &mut anomalies,
                        format!("browser timezone {browser_tz} differs from network timezone {network_tz}"),
                    );
                }
            }
        }

        if value_bool(&browser.capabilities, &["cross_origin_isolated"]) == Some(false)
            && value_bool(&browser.capabilities, &["shared_array_buffer"]) == Some(false)
        {
            privacy_resistance = privacy_resistance.max(0.08);
        }
    }

    if http.version.contains("HTTP/2") && connection.http2.is_none() {
        add_anomaly(&mut anomalies, "HTTP/2 request observed without wire SETTINGS fingerprint");
    }

    if let (Some(alpn), version) = (
        tls.and_then(|value| value.negotiated_alpn.as_deref()),
        http.version.as_str(),
    ) {
        if alpn == "h2" && !version.contains("HTTP/2") {
            add_anomaly(&mut anomalies, "ALPN negotiated h2 but request was not parsed as HTTP/2");
        }
    }

    let enrichment = connection.enrichment.as_ref();
    let vpn_probability = enrichment
        .map(|value| probability_from_flag(value.is_vpn, value.confidence.max(0.80)))
        .unwrap_or(0.0);
    let tor_probability = enrichment
        .map(|value| probability_from_flag(value.is_tor, value.confidence.max(0.95)))
        .unwrap_or(0.0);
    let hosting_probability = enrichment
        .map(|value| probability_from_flag(value.is_hosting, value.confidence.max(0.75)))
        .unwrap_or(0.0);
    let proxy_from_db = enrichment
        .map(|value| probability_from_flag(value.is_proxy, value.confidence.max(0.75)))
        .unwrap_or(0.0);
    let proxy_probability = proxy_from_db.max(vpn_probability * 0.65).max(tor_probability);

    let inconsistency = (anomalies.len() as f32 * 0.12).min(1.0);
    let coverage = if signal_count > 0 {
        available_signal_count as f32 / signal_count as f32
    } else {
        0.0
    };
    let consistency_score = ((1.0 - inconsistency) * (0.70 + coverage.min(1.0) * 0.30)).clamp(0.0, 1.0);

    if browser_inference.value.is_none() {
        browser_inference = inferred("Unknown", 0.05, Vec::new());
    }
    if os_inference.value.is_none() {
        os_inference = inferred("Unknown", 0.05, Vec::new());
    }
    if device_inference.value.is_none() {
        device_inference = inferred("Unknown", 0.05, Vec::new());
    }
    if network_inference.value.is_none() {
        network_inference = inferred("Unknown", 0.05, Vec::new());
    }

    (
        ClientProfile {
            probable_browser: browser_inference,
            probable_os: os_inference,
            probable_device: device_inference,
            probable_network: network_inference,
            consistency_score,
            risks: RiskScores {
                automation_probability,
                proxy_probability,
                vpn_probability,
                tor_probability,
                hosting_probability,
                privacy_resistance,
                inconsistency,
            },
            anomalies,
            signal_count,
            available_signal_count,
        },
        fingerprints,
    )
}

pub fn compare_observations(a: &Fingerprints, b: &Fingerprints) -> MatchResult {
    let components = [
        ("tls_stable", &a.tls_stable, &b.tls_stable, 0.13_f32),
        ("tls_wire", &a.tls_wire, &b.tls_wire, 0.05),
        ("tcp", &a.tcp, &b.tcp, 0.07),
        ("http", &a.http, &b.http, 0.06),
        ("http1_wire", &a.http1_wire, &b.http1_wire, 0.04),
        ("http2", &a.http2, &b.http2, 0.07),
        ("quic", &a.quic, &b.quic, 0.07),
        ("http3", &a.http3, &b.http3, 0.04),
        ("browser", &a.browser, &b.browser, 0.14),
        ("graphics", &a.graphics, &b.graphics, 0.08),
        ("canvas", &a.canvas, &b.canvas, 0.05),
        ("audio", &a.audio, &b.audio, 0.04),
        ("fonts", &a.fonts, &b.fonts, 0.05),
        ("intl", &a.intl, &b.intl, 0.03),
        ("capabilities", &a.capabilities, &b.capabilities, 0.03),
        ("screen", &a.screen, &b.screen, 0.02),
        ("media", &a.media, &b.media, 0.02),
        ("automation", &a.automation, &b.automation, 0.01),
    ];

    let mut matched_weight = 0.0;
    let mut conflicting_weight = 0.0;
    let mut available_weight = 0.0;
    let mut matching_components = Vec::new();
    let mut conflicting_components = Vec::new();

    for (name, left, right, weight) in components {
        let (Some(left), Some(right)) = (left, right) else {
            continue;
        };

        available_weight += weight;
        if left == right {
            matched_weight += weight;
            matching_components.push(name.to_string());
        } else {
            conflicting_weight += weight;
            conflicting_components.push(name.to_string());
        }
    }

    let raw_match = if available_weight > 0.0 {
        matched_weight / available_weight
    } else {
        0.0
    };

    // Конфликт по доступным устойчивым компонентам должен снижать итог сильнее,
    // чем простое отсутствие сигнала. Confidence отражает именно покрытие сравнением.
    let conflict_ratio = if available_weight > 0.0 {
        conflicting_weight / available_weight
    } else {
        1.0
    };
    let probability = (raw_match * (1.0 - conflict_ratio * 0.35)).clamp(0.0, 1.0);
    let confidence = (available_weight / 0.85_f32).clamp(0.0, 1.0);

    MatchResult {
        same_client_probability: probability,
        confidence,
        available_weight,
        matching_weight: matched_weight,
        conflicting_weight,
        matching_components,
        conflicting_components,
    }
}

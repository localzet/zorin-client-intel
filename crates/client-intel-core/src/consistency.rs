use crate::fingerprint::fingerprint_component;
use crate::{
    BrowserProbe, ClientProfile, Evidence, Fingerprints, HttpObservation, Inference, MatchResult,
    RiskScores, SignalSource, TlsObservation,
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
    } else if ua.contains("Firefox/") {
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

pub fn build_profile(
    http: &HttpObservation,
    tls: Option<&TlsObservation>,
    browser: Option<&BrowserProbe>,
) -> (ClientProfile, Fingerprints) {
    let mut anomalies = Vec::new();
    let mut fingerprints = Fingerprints {
        ja3: tls.and_then(|value| value.ja3.clone()),
        ja4: tls.and_then(|value| value.ja4.clone()),
        tls_stable: tls.and_then(|value| value.stable_tls_fp.clone()),
        http: http.http_fp.clone(),
        ..Fingerprints::default()
    };

    let mut browser_inference = Inference::default();
    let mut os_inference = Inference::default();
    let mut device_inference = Inference::default();
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
        signal_count += 8;
        available_signal_count += usize::from(!tls.cipher_suites.is_empty())
            + usize::from(!tls.extensions.is_empty())
            + usize::from(!tls.supported_groups.is_empty())
            + usize::from(!tls.signature_algorithms.is_empty())
            + usize::from(!tls.alpn.is_empty())
            + usize::from(tls.sni.is_some())
            + usize::from(tls.ja3.is_some())
            + usize::from(tls.ja4.is_some());
    }

    if let Some(browser) = browser {
        signal_count += 18;
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
            &browser.capabilities,
            &browser.automation,
            &browser.voices,
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

        if value_bool(&browser.automation, &["webdriver"]) == Some(true)
            || value_bool(&browser.navigator, &["webdriver"]) == Some(true)
        {
            automation_probability = automation_probability.max(0.92);
            add_anomaly(&mut anomalies, "navigator.webdriver=true");
        }

        if value_bool(&browser.capabilities, &["cookie_enabled"]) == Some(false) {
            privacy_resistance = privacy_resistance.max(0.35);
        }

        let platform = value_str(&browser.user_agent_client_hints, &["platform"])
            .or_else(|| value_str(&browser.navigator, &["platform"]));

        if let (Some(platform), Some(current_os)) = (platform, os_inference.value.as_deref()) {
            let agrees = match current_os {
                "Windows" => platform.to_ascii_lowercase().contains("win"),
                "macOS" => platform.to_ascii_lowercase().contains("mac"),
                "Android" => platform.to_ascii_lowercase().contains("android"),
                "Linux" => platform.to_ascii_lowercase().contains("linux"),
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
                if mobile { "Mobile device" } else { "Desktop-class device" },
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
    }

    let inconsistency = (anomalies.len() as f32 * 0.16).min(1.0);
    let consistency_score = (1.0 - inconsistency).clamp(0.0, 1.0);

    if browser_inference.value.is_none() {
        browser_inference = inferred("Unknown", 0.05, Vec::new());
    }
    if os_inference.value.is_none() {
        os_inference = inferred("Unknown", 0.05, Vec::new());
    }
    if device_inference.value.is_none() {
        device_inference = inferred("Unknown", 0.05, Vec::new());
    }

    (
        ClientProfile {
            probable_browser: browser_inference,
            probable_os: os_inference,
            probable_device: device_inference,
            consistency_score,
            risks: RiskScores {
                automation_probability,
                proxy_probability: 0.0,
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
        ("tls_stable", &a.tls_stable, &b.tls_stable, 0.20_f32),
        ("http", &a.http, &b.http, 0.10),
        ("browser", &a.browser, &b.browser, 0.25),
        ("graphics", &a.graphics, &b.graphics, 0.12),
        ("canvas", &a.canvas, &b.canvas, 0.08),
        ("audio", &a.audio, &b.audio, 0.07),
        ("fonts", &a.fonts, &b.fonts, 0.08),
        ("intl", &a.intl, &b.intl, 0.05),
        ("capabilities", &a.capabilities, &b.capabilities, 0.05),
    ];

    let mut matched_weight = 0.0;
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
            conflicting_components.push(name.to_string());
        }
    }

    let probability = if available_weight > 0.0 {
        matched_weight / available_weight
    } else {
        0.0
    };

    MatchResult {
        same_client_probability: probability,
        matching_components,
        conflicting_components,
    }
}

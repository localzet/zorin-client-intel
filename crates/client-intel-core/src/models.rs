use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionMeta {
    pub remote_ip: Option<String>,
    pub ip: Option<IpObservation>,
    pub remote_port: Option<u16>,
    pub local_port: Option<u16>,
    pub transport: String,
    pub tls: Option<TlsObservation>,
}


#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpObservation {
    pub version: u8,
    pub scope: String,
    pub is_loopback: bool,
    pub is_private_or_unique_local: bool,
    pub is_link_local: bool,
    pub is_multicast: bool,
    pub is_unspecified: bool,
    pub is_documentation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsObservation {
    pub record_version: Option<u16>,
    pub legacy_version: Option<u16>,
    pub supported_versions: Vec<u16>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub key_share_groups: Vec<u16>,
    pub alpn: Vec<String>,
    pub sni: Option<String>,
    pub session_id_len: Option<u8>,
    pub compression_methods: Vec<u8>,
    pub client_hello_len: Option<usize>,
    pub record_len: Option<usize>,
    pub ja3_string: Option<String>,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub stable_tls_fp: Option<String>,
    pub negotiated_alpn: Option<String>,
    pub negotiated_tls_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpObservation {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: Vec<HttpHeaderObservation>,
    pub header_names: Vec<String>,
    pub user_agent: Option<String>,
    pub accept: Option<String>,
    pub accept_encoding: Option<String>,
    pub accept_language: Option<String>,
    pub sec_fetch_site: Option<String>,
    pub sec_fetch_mode: Option<String>,
    pub sec_fetch_dest: Option<String>,
    pub sec_ch_ua: Option<String>,
    pub sec_ch_ua_platform: Option<String>,
    pub priority: Option<String>,
    pub http_fp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeaderObservation {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BrowserProbe {
    pub schema: String,
    pub collected_at: Option<String>,
    pub navigator: Value,
    pub user_agent_client_hints: Value,
    pub screen: Value,
    pub viewport: Value,
    pub intl: Value,
    pub media_queries: Value,
    pub webgl: Value,
    pub webgpu: Value,
    pub canvas: Value,
    pub audio: Value,
    pub fonts: Value,
    pub media: Value,
    pub storage: Value,
    pub permissions: Value,
    pub network: Value,
    pub battery: Value,
    pub performance: Value,
    pub capabilities: Value,
    pub automation: Value,
    pub voices: Value,
    pub misc: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Fingerprints {
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub tls_stable: Option<String>,
    pub http: Option<String>,
    pub browser: Option<String>,
    pub graphics: Option<String>,
    pub canvas: Option<String>,
    pub audio: Option<String>,
    pub fonts: Option<String>,
    pub intl: Option<String>,
    pub capabilities: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub signal: String,
    pub source: SignalSource,
    pub value: Value,
    pub weight: f32,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalSource {
    Observed,
    Claimed,
    Inferred,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Inference {
    pub value: Option<String>,
    pub confidence: f32,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiskScores {
    pub automation_probability: f32,
    pub proxy_probability: f32,
    pub privacy_resistance: f32,
    pub inconsistency: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientProfile {
    pub probable_browser: Inference,
    pub probable_os: Inference,
    pub probable_device: Inference,
    pub consistency_score: f32,
    pub risks: RiskScores,
    pub anomalies: Vec<String>,
    pub signal_count: usize,
    pub available_signal_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub connection: ConnectionMeta,
    pub http: HttpObservation,
    pub browser: Option<BrowserProbe>,
    pub fingerprints: Fingerprints,
    pub profile: ClientProfile,
    pub raw: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MatchResult {
    pub same_client_probability: f32,
    pub matching_components: Vec<String>,
    pub conflicting_components: Vec<String>,
}

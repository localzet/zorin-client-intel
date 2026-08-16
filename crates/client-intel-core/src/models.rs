use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionMeta {
    pub remote_ip: Option<String>,
    pub ip: Option<IpObservation>,
    pub enrichment: Option<NetworkEnrichment>,
    pub remote_port: Option<u16>,
    pub local_ip: Option<String>,
    pub local_port: Option<u16>,
    pub transport: String,
    pub tcp: Option<TcpObservation>,
    pub tls: Option<TlsObservation>,
    pub http1_wire: Option<Http1WireObservation>,
    pub http2: Option<Http2Observation>,
    pub quic: Option<QuicObservation>,
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
pub struct NetworkEnrichment {
    pub source: Option<String>,
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub network_type: Option<String>,
    pub is_hosting: Option<bool>,
    pub is_mobile: Option<bool>,
    pub is_vpn: Option<bool>,
    pub is_proxy: Option<bool>,
    pub is_tor: Option<bool>,
    pub tags: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TcpObservation {
    pub source: String,
    pub ip_version: Option<u8>,
    pub ttl: Option<u8>,
    pub hop_limit: Option<u8>,
    pub window_size: Option<u16>,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: Option<bool>,
    pub timestamps: Option<bool>,
    pub ecn: Option<bool>,
    pub options_order: Vec<u8>,
    pub syn_payload_len: Option<u16>,
    pub runtime_rtt_us: Option<u32>,
    pub runtime_rtt_var_us: Option<u32>,
    pub runtime_snd_mss: Option<u32>,
    pub runtime_rcv_mss: Option<u32>,
    pub runtime_snd_cwnd: Option<u32>,
    pub runtime_retransmits: Option<u32>,
    pub runtime_total_retrans: Option<u32>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsExtensionObservation {
    pub kind: u16,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TlsObservation {
    pub record_version: Option<u16>,
    pub legacy_version: Option<u16>,
    pub supported_versions: Vec<u16>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub extension_details: Vec<TlsExtensionObservation>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub signature_algorithms_cert: Vec<u16>,
    pub key_share_groups: Vec<u16>,
    pub psk_key_exchange_modes: Vec<u8>,
    pub certificate_compression_algorithms: Vec<u16>,
    pub alpn: Vec<String>,
    pub sni: Option<String>,
    pub session_id_len: Option<u8>,
    pub compression_methods: Vec<u8>,
    pub client_hello_len: Option<usize>,
    pub record_len: Option<usize>,
    pub record_count: usize,
    pub padding_len: Option<usize>,
    pub grease_cipher_count: usize,
    pub grease_extension_count: usize,
    pub grease_group_count: usize,
    pub has_session_ticket: bool,
    pub has_pre_shared_key: bool,
    pub has_early_data: bool,
    pub has_ech: bool,
    pub has_alps: bool,
    pub raw_client_hello_hash: Option<String>,
    pub ja3_string: Option<String>,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub stable_tls_fp: Option<String>,
    pub wire_tls_fp: Option<String>,
    pub negotiated_alpn: Option<String>,
    pub negotiated_tls_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Http1WireObservation {
    pub request_line: Option<String>,
    pub header_names: Vec<String>,
    pub normalized_header_names: Vec<String>,
    pub header_count: usize,
    pub header_bytes: usize,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Http2Setting {
    pub id: u16,
    pub value: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Http2FrameObservation {
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
    pub length: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Http2Observation {
    pub client_preface_seen: bool,
    pub settings: Vec<Http2Setting>,
    pub settings_ack_seen: bool,
    pub connection_window_update: Option<u32>,
    pub first_frames: Vec<Http2FrameObservation>,
    pub bytes_observed: usize,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuicTransportParameter {
    pub id: u64,
    pub value_length: usize,
    pub integer_value: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Http3Setting {
    pub id: u64,
    pub value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct QuicObservation {
    pub source: String,
    pub version: Option<u32>,
    pub runtime_rtt_us: Option<u64>,
    pub remote_address_validated: Option<bool>,
    pub max_datagram_size: Option<usize>,
    pub original_destination_connection_id_len: Option<usize>,
    pub source_connection_id_len: Option<usize>,
    pub alpn: Vec<String>,
    pub transport_parameters: Vec<QuicTransportParameter>,
    pub http3_settings: Vec<Http3Setting>,
    pub tls: Option<TlsObservation>,
    pub fingerprint: Option<String>,
    pub http3_fingerprint: Option<String>,
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
#[serde(default)]
pub struct BrowserProbe {
    pub schema: String,
    pub collection_mode: Option<String>,
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
    pub sensitive: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Fingerprints {
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub tls_stable: Option<String>,
    pub tls_wire: Option<String>,
    pub tcp: Option<String>,
    pub http: Option<String>,
    pub http1_wire: Option<String>,
    pub http2: Option<String>,
    pub quic: Option<String>,
    pub http3: Option<String>,
    pub browser: Option<String>,
    pub graphics: Option<String>,
    pub canvas: Option<String>,
    pub audio: Option<String>,
    pub fonts: Option<String>,
    pub intl: Option<String>,
    pub capabilities: Option<String>,
    pub screen: Option<String>,
    pub media: Option<String>,
    pub automation: Option<String>,
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
    Enriched,
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
    pub vpn_probability: f32,
    pub tor_probability: f32,
    pub hosting_probability: f32,
    pub privacy_resistance: f32,
    pub inconsistency: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientProfile {
    pub probable_browser: Inference,
    pub probable_os: Inference,
    pub probable_device: Inference,
    pub probable_network: Inference,
    pub consistency_score: f32,
    pub risks: RiskScores,
    pub anomalies: Vec<String>,
    pub signal_count: usize,
    pub available_signal_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MatchResult {
    pub same_client_probability: f32,
    pub confidence: f32,
    pub available_weight: f32,
    pub matching_weight: f32,
    pub conflicting_weight: f32,
    pub matching_components: Vec<String>,
    pub conflicting_components: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionKind {
    NewClient,
    MatchedClient,
    Ambiguous,
}

impl Default for ResolutionKind {
    fn default() -> Self {
        Self::NewClient
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientResolution {
    pub kind: ResolutionKind,
    pub client_id: Uuid,
    pub probability: f32,
    pub confidence: f32,
    pub matched_observation_id: Option<Uuid>,
    pub matching_components: Vec<String>,
    pub conflicting_components: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub id: Uuid,
    pub tenant_id: String,
    pub client_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub connection: ConnectionMeta,
    pub http: HttpObservation,
    pub browser: Option<BrowserProbe>,
    pub fingerprints: Fingerprints,
    pub profile: ClientProfile,
    pub resolution: ClientResolution,
    pub raw: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientSummary {
    pub tenant_id: String,
    pub client_id: Uuid,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub observation_count: u64,
    pub latest_profile: Option<ClientProfile>,
    pub latest_fingerprints: Option<Fingerprints>,
    pub recent_observation_ids: Vec<Uuid>,
}

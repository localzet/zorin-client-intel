use crate::sensor::default_sensor_socket;
use ipnet::IpNet;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub http_bind: SocketAddr,
    pub quic_bind: SocketAddr,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub database_url: Option<String>,
    pub trust_proxy_headers: bool,
    pub trusted_proxy_cidrs: Vec<IpNet>,
    pub retention_days: u32,
    pub graph_window_days: u32,
    pub graph_candidate_limit: i64,
    pub graph_match_threshold: f32,
    pub graph_min_confidence: f32,
    pub enrichment_db: Option<PathBuf>,
    pub sensor_socket: PathBuf,
    pub site_keys: Vec<(String, String)>,
    pub admin_keys: Vec<(String, String)>,
    pub max_probe_bytes: usize,
    pub cors_origins: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid socket address in {name}: {value}")]
    InvalidAddress { name: &'static str, value: String },
    #[error("invalid integer in {name}: {value}")]
    InvalidInteger { name: &'static str, value: String },
    #[error("invalid float in {name}: {value}")]
    InvalidFloat { name: &'static str, value: String },
    #[error("invalid key mapping in {name}; expected tenant:key entries separated by semicolons")]
    InvalidKeyMapping { name: &'static str },
    #[error("invalid CIDR in {name}: {value}")]
    InvalidCidr { name: &'static str, value: String },
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            bind: parse_addr("ZCI_BIND", "0.0.0.0:8443")?,
            http_bind: parse_addr("ZCI_HTTP_BIND", "0.0.0.0:8080")?,
            quic_bind: parse_addr("ZCI_QUIC_BIND", "0.0.0.0:8443")?,
            tls_cert: env::var_os("ZCI_TLS_CERT").map(PathBuf::from),
            tls_key: env::var_os("ZCI_TLS_KEY").map(PathBuf::from),
            database_url: env::var("DATABASE_URL").ok().filter(|value| !value.is_empty()),
            trust_proxy_headers: env_bool("TRUST_PROXY_HEADERS", false),
            trusted_proxy_cidrs: parse_cidrs("ZCI_TRUSTED_PROXY_CIDRS")?,
            retention_days: parse_u32("RETENTION_DAYS", 30)?.max(1),
            graph_window_days: parse_u32("ZCI_GRAPH_WINDOW_DAYS", 90)?.max(1),
            graph_candidate_limit: parse_i64("ZCI_GRAPH_CANDIDATE_LIMIT", 1500)?.max(1),
            graph_match_threshold: parse_f32("ZCI_GRAPH_MATCH_THRESHOLD", 0.76)?,
            graph_min_confidence: parse_f32("ZCI_GRAPH_MIN_CONFIDENCE", 0.42)?,
            enrichment_db: env::var_os("ZCI_ENRICHMENT_DB").map(PathBuf::from),
            sensor_socket: env::var_os("ZCI_SENSOR_SOCKET")
                .map(PathBuf::from)
                .unwrap_or_else(|| default_sensor_socket().to_path_buf()),
            site_keys: parse_key_map("ZCI_SITE_KEYS")?,
            admin_keys: parse_key_map("ZCI_ADMIN_KEYS")?,
            max_probe_bytes: parse_usize("ZCI_MAX_PROBE_BYTES", 1_048_576)?.max(1024),
            cors_origins: parse_list("ZCI_CORS_ORIGINS"),
        })
    }

    pub fn tls_enabled(&self) -> bool {
        self.tls_cert.is_some() && self.tls_key.is_some()
    }

    pub fn quic_enabled(&self) -> bool {
        self.tls_enabled()
    }
}

fn parse_addr(name: &'static str, default: &str) -> Result<SocketAddr, ConfigError> {
    let value = env::var(name).unwrap_or_else(|_| default.to_string());
    value
        .parse()
        .map_err(|_| ConfigError::InvalidAddress { name, value })
}

fn parse_u32(name: &'static str, default: u32) -> Result<u32, ConfigError> {
    let value = env::var(name).unwrap_or_else(|_| default.to_string());
    value
        .parse()
        .map_err(|_| ConfigError::InvalidInteger { name, value })
}

fn parse_i64(name: &'static str, default: i64) -> Result<i64, ConfigError> {
    let value = env::var(name).unwrap_or_else(|_| default.to_string());
    value
        .parse()
        .map_err(|_| ConfigError::InvalidInteger { name, value })
}

fn parse_usize(name: &'static str, default: usize) -> Result<usize, ConfigError> {
    let value = env::var(name).unwrap_or_else(|_| default.to_string());
    value
        .parse()
        .map_err(|_| ConfigError::InvalidInteger { name, value })
}

fn parse_f32(name: &'static str, default: f32) -> Result<f32, ConfigError> {
    let value = env::var(name).unwrap_or_else(|_| default.to_string());
    value
        .parse::<f32>()
        .map(|value| value.clamp(0.0, 1.0))
        .map_err(|_| ConfigError::InvalidFloat { name, value })
}

fn parse_key_map(name: &'static str) -> Result<Vec<(String, String)>, ConfigError> {
    let Some(value) = env::var(name).ok().filter(|value| !value.trim().is_empty()) else {
        return Ok(Vec::new());
    };

    value
        .split(';')
        .filter(|entry| !entry.trim().is_empty())
        .map(|entry| {
            let (tenant, key) = entry
                .split_once(':')
                .ok_or(ConfigError::InvalidKeyMapping { name })?;
            let tenant = tenant.trim();
            let key = key.trim();
            if tenant.is_empty() || key.is_empty() {
                return Err(ConfigError::InvalidKeyMapping { name });
            }
            Ok((tenant.to_string(), key.to_string()))
        })
        .collect()
}

fn parse_cidrs(name: &'static str) -> Result<Vec<IpNet>, ConfigError> {
    let value = env::var(name).unwrap_or_default();
    if value.trim().is_empty() {
        return Ok(vec![
            "127.0.0.0/8".parse().expect("static CIDR"),
            "::1/128".parse().expect("static CIDR"),
        ]);
    }

    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<IpNet>()
                .map_err(|_| ConfigError::InvalidCidr {
                    name,
                    value: value.to_string(),
                })
        })
        .collect()
}

fn env_bool(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(value) => matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

fn parse_list(name: &str) -> Vec<String> {
    env::var(name)
        .ok()
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

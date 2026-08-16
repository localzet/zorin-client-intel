use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub http_bind: SocketAddr,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub database_url: Option<String>,
    pub trust_proxy_headers: bool,
    pub retention_days: u32,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid socket address in {name}: {value}")]
    InvalidAddress { name: &'static str, value: String },
    #[error("invalid integer in RETENTION_DAYS: {0}")]
    InvalidRetention(String),
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind = parse_addr("ZCI_BIND", "0.0.0.0:8443")?;
        let http_bind = parse_addr("ZCI_HTTP_BIND", "0.0.0.0:8080")?;
        let tls_cert = env::var_os("ZCI_TLS_CERT").map(PathBuf::from);
        let tls_key = env::var_os("ZCI_TLS_KEY").map(PathBuf::from);
        let database_url = env::var("DATABASE_URL").ok().filter(|value| !value.is_empty());
        let trust_proxy_headers = env_bool("TRUST_PROXY_HEADERS", false);
        let retention_days = env::var("RETENTION_DAYS")
            .unwrap_or_else(|_| "30".to_string())
            .parse::<u32>()
            .map_err(|_| ConfigError::InvalidRetention(
                env::var("RETENTION_DAYS").unwrap_or_default(),
            ))?;

        Ok(Self {
            bind,
            http_bind,
            tls_cert,
            tls_key,
            database_url,
            trust_proxy_headers,
            retention_days,
        })
    }

    pub fn tls_enabled(&self) -> bool {
        self.tls_cert.is_some() && self.tls_key.is_some()
    }
}

fn parse_addr(name: &'static str, default: &str) -> Result<SocketAddr, ConfigError> {
    let value = env::var(name).unwrap_or_else(|_| default.to_string());
    value
        .parse()
        .map_err(|_| ConfigError::InvalidAddress { name, value })
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

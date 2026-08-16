use crate::metrics::Metrics;
use client_intel_core::{fingerprint_tcp, ConnectionMeta, TcpObservation};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    remote_ip: String,
    remote_port: u16,
    local_port: u16,
}

#[derive(Debug, Clone)]
struct CachedTcp {
    seen_at: Instant,
    observation: TcpObservation,
}

#[derive(Debug, Deserialize)]
struct TcpSensorEvent {
    remote_ip: String,
    remote_port: u16,
    local_port: u16,
    tcp: TcpObservation,
}

#[derive(Clone, Default)]
pub struct TransportCache {
    tcp: Arc<RwLock<HashMap<FlowKey, CachedTcp>>>,
}

impl TransportCache {
    pub async fn insert_tcp(
        &self,
        remote_ip: String,
        remote_port: u16,
        local_port: u16,
        mut observation: TcpObservation,
    ) {
        if observation.fingerprint.is_none() {
            observation.fingerprint = Some(fingerprint_tcp(&observation));
        }

        let key = FlowKey {
            remote_ip,
            remote_port,
            local_port,
        };
        self.tcp.write().await.insert(
            key,
            CachedTcp {
                seen_at: Instant::now(),
                observation,
            },
        );
    }

    pub async fn enrich_connection(&self, connection: &mut ConnectionMeta) {
        let (Some(remote_ip), Some(remote_port), Some(local_port)) = (
            connection.remote_ip.as_deref(),
            connection.remote_port,
            connection.local_port,
        ) else {
            return;
        };

        let key = FlowKey {
            remote_ip: remote_ip.to_string(),
            remote_port,
            local_port,
        };

        let mut cache = self.tcp.write().await;
        if let Some(cached) = cache.remove(&key) {
            if cached.seen_at.elapsed() <= Duration::from_secs(30) {
                merge_tcp(&mut connection.tcp, cached.observation);
            }
        }
        cache.retain(|_, value| value.seen_at.elapsed() <= Duration::from_secs(60));
    }
}

fn merge_tcp(current: &mut Option<TcpObservation>, sensor: TcpObservation) {
    if let Some(existing) = current {
        let runtime_rtt_us = existing.runtime_rtt_us;
        let runtime_rtt_var_us = existing.runtime_rtt_var_us;
        let runtime_snd_mss = existing.runtime_snd_mss;
        let runtime_rcv_mss = existing.runtime_rcv_mss;
        let runtime_snd_cwnd = existing.runtime_snd_cwnd;
        let runtime_retransmits = existing.runtime_retransmits;
        let runtime_total_retrans = existing.runtime_total_retrans;
        *existing = sensor;
        existing.runtime_rtt_us = runtime_rtt_us;
        existing.runtime_rtt_var_us = runtime_rtt_var_us;
        existing.runtime_snd_mss = runtime_snd_mss;
        existing.runtime_rcv_mss = runtime_rcv_mss;
        existing.runtime_snd_cwnd = runtime_snd_cwnd;
        existing.runtime_retransmits = runtime_retransmits;
        existing.runtime_total_retrans = runtime_total_retrans;
        if existing.fingerprint.is_none() {
            existing.fingerprint = Some(fingerprint_tcp(existing));
        }
    } else {
        *current = Some(sensor);
    }
}

#[cfg(unix)]
pub async fn run_sensor_socket(
    path: PathBuf,
    cache: TransportCache,
    metrics: Arc<Metrics>,
) -> std::io::Result<()> {
    use tokio::net::UnixDatagram;

    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let socket = UnixDatagram::bind(&path)?;
    info!(socket = %path.display(), "transport sensor socket listening");
    let mut buffer = vec![0_u8; 16 * 1024];

    loop {
        let read = socket.recv(&mut buffer).await?;
        let event: TcpSensorEvent = match serde_json::from_slice(&buffer[..read]) {
            Ok(event) => event,
            Err(error) => {
                debug!(?error, "invalid transport sensor event");
                continue;
            }
        };

        if event.remote_ip.parse::<IpAddr>().is_err() {
            warn!(remote_ip = %event.remote_ip, "sensor sent invalid remote IP");
            continue;
        }

        cache
            .insert_tcp(
                event.remote_ip,
                event.remote_port,
                event.local_port,
                event.tcp,
            )
            .await;
        metrics.sensor_event();
    }
}

#[cfg(not(unix))]
pub async fn run_sensor_socket(
    _path: PathBuf,
    _cache: TransportCache,
    _metrics: Arc<Metrics>,
) -> std::io::Result<()> {
    Ok(())
}

pub fn default_sensor_socket() -> &'static Path {
    Path::new("/tmp/zci-tcp-sensor.sock")
}

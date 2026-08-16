mod app;
mod config;
mod enrichment;
mod metrics;
mod quic;
mod sensor;
mod server;
mod store;
mod tenancy;
mod wire;

use crate::app::build_router;
use crate::config::Config;
use crate::enrichment::EnrichmentDb;
use crate::metrics::Metrics;
use crate::quic::run_quic_server;
use crate::sensor::{run_sensor_socket, TransportCache};
use crate::server::{run_http_server, run_tls_server};
use crate::store::Store;
use crate::tenancy::Tenancy;
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Фиксируем единый crypto provider, чтобы TCP/TLS и QUIC использовали одну конфигурацию rustls.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("client_intel_collector=info,tower_http=info")),
        )
        .init();

    let config = Arc::new(Config::from_env()?);
    let store = Arc::new(Store::connect(config.database_url.as_deref()).await?);
    let enrichment = Arc::new(EnrichmentDb::load(config.enrichment_db.as_deref())?);
    let tenancy = Arc::new(Tenancy::new(&config.site_keys, &config.admin_keys));
    let transport_cache = TransportCache::default();
    let metrics = Arc::new(Metrics::default());

    if config.trust_proxy_headers {
        info!(
            trusted_proxy_cidrs = ?config.trusted_proxy_cidrs,
            "trusted proxy headers enabled"
        );
    }
    if enrichment.enabled() {
        info!(source = ?enrichment.source_path(), "network enrichment enabled");
    }

    let router = build_router(
        config.clone(),
        store.clone(),
        enrichment,
        tenancy,
        transport_cache.clone(),
        metrics.clone(),
    );

    let retention_task = {
        let store = store.clone();
        let retention_days = config.retention_days;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                match store.purge_older_than(retention_days).await {
                    Ok(deleted) if deleted > 0 => {
                        info!(deleted, retention_days, "expired observations removed");
                    }
                    Ok(_) => {}
                    Err(error) => warn!(?error, "retention cleanup failed"),
                }
            }
        })
    };

    let sensor_task = {
        let socket = config.sensor_socket.clone();
        let cache = transport_cache;
        let metrics = metrics.clone();
        Some(tokio::spawn(async move {
            if let Err(error) = run_sensor_socket(socket, cache, metrics).await {
                warn!(?error, "transport sensor socket stopped");
            }
        }))
    };

    let http_task = {
        let config = config.clone();
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(error) = run_http_server(config, router).await {
                error!(?error, "HTTP server stopped");
            }
        })
    };

    let tls_task = if config.tls_enabled() {
        let config = config.clone();
        let router = router.clone();
        Some(tokio::spawn(async move {
            if let Err(error) = run_tls_server(config, router).await {
                error!(?error, "TLS server stopped");
            }
        }))
    } else {
        info!("TLS certificate/key are not configured; HTTPS collector is disabled");
        None
    };

    let quic_task = if config.quic_enabled() {
        let config = config.clone();
        let router = router.clone();
        Some(tokio::spawn(async move {
            if let Err(error) = run_quic_server(config, router).await {
                error!(?error, "QUIC/HTTP3 server stopped");
            }
        }))
    } else {
        info!("TLS certificate/key are not configured; QUIC/HTTP3 collector is disabled");
        None
    };

    tokio::signal::ctrl_c().await?;
    info!("shutdown requested");

    retention_task.abort();
    http_task.abort();
    if let Some(sensor_task) = sensor_task {
        sensor_task.abort();
    }
    if let Some(tls_task) = tls_task {
        tls_task.abort();
    }
    if let Some(quic_task) = quic_task {
        quic_task.abort();
    }

    Ok(())
}

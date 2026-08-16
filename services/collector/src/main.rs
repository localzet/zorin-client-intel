mod app;
mod config;
mod server;
mod store;

use crate::app::build_router;
use crate::config::Config;
use crate::server::{run_http_server, run_tls_server};
use crate::store::Store;
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("client_intel_collector=info,tower_http=info")),
        )
        .init();

    let config = Arc::new(Config::from_env()?);
    let store = Arc::new(Store::connect(config.database_url.as_deref()).await?);
    let router = build_router(config.clone(), store.clone());

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

    tokio::signal::ctrl_c().await?;
    info!("shutdown requested");

    retention_task.abort();
    http_task.abort();
    if let Some(tls_task) = tls_task {
        tls_task.abort();
    }

    Ok(())
}

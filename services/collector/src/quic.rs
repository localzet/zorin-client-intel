use crate::config::Config;
use crate::server::ConnectionContext;
use crate::wire::WireState;
use axum::extract::Extension;
use axum::Router;
use client_intel_core::{
    describe_ip, fingerprint_http3, fingerprint_quic, ConnectionMeta, QuicObservation,
};
use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
use rustls::pki_types::CertificateDer;
use std::fs::File;
use std::io::{self, BufReader};
use std::sync::Arc;
use tracing::{debug, info};

pub async fn run_quic_server(
    config: Arc<Config>,
    router: Router,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server_config = load_quic_config(&config)?;
    let endpoint = quinn::Endpoint::server(server_config, config.quic_bind)?;
    info!(address = %config.quic_bind, "QUIC/HTTP3 collector listening");

    while let Some(incoming) = endpoint.accept().await {
        let router = router.clone();
        let local_port = config.quic_bind.port();
        tokio::spawn(async move {
            let remote_address_validated = incoming.remote_address_validated();
            let original_destination_connection_id_len = Some(incoming.orig_dst_cid().len());

            match incoming.await {
                Ok(connection) => {
                    if let Err(error) = handle_connection(
                        connection,
                        router,
                        local_port,
                        remote_address_validated,
                        original_destination_connection_id_len,
                    )
                    .await
                    {
                        debug!(?error, "QUIC/H3 connection ended with error");
                    }
                }
                Err(error) => debug!(?error, "QUIC handshake failed"),
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    connection: quinn::Connection,
    router: Router,
    local_port: u16,
    remote_address_validated: bool,
    original_destination_connection_id_len: Option<usize>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let remote_addr = connection.remote_address();
    let local_ip = connection.local_ip();
    let alpn = negotiated_alpn(&connection);

    let mut quic = QuicObservation {
        source: "quinn-h3".to_string(),
        runtime_rtt_us: Some(
            connection
                .rtt()
                .as_micros()
                .try_into()
                .unwrap_or(u64::MAX),
        ),
        remote_address_validated: Some(remote_address_validated),
        max_datagram_size: connection.max_datagram_size(),
        original_destination_connection_id_len,
        alpn,
        ..QuicObservation::default()
    };
    quic.fingerprint = Some(fingerprint_quic(&quic));
    quic.http3_fingerprint = fingerprint_http3(&quic);

    let meta = ConnectionMeta {
        remote_ip: Some(remote_addr.ip().to_string()),
        ip: Some(describe_ip(remote_addr.ip())),
        remote_port: Some(remote_addr.port()),
        local_ip: local_ip.map(|value| value.to_string()),
        local_port: Some(local_port),
        transport: "udp+quic+h3".to_string(),
        quic: Some(quic),
        ..ConnectionMeta::default()
    };
    let context = ConnectionContext::new(meta, WireState::default());

    let h3_connection = h3::server::builder()
        .build(h3_quinn::Connection::new(connection))
        .await?;
    tokio::pin!(h3_connection);

    loop {
        match h3_connection.accept().await {
            Ok(Some(resolver)) => {
                let app = router.clone().layer(Extension(context.clone()));
                tokio::spawn(async move {
                    if let Err(error) = h3_axum::serve_h3_with_axum(app, resolver).await {
                        debug!(?error, "HTTP/3 request failed");
                    }
                });
            }
            Ok(None) => break,
            Err(error) => {
                if !h3_axum::is_graceful_h3_close(&error) {
                    debug!(?error, "HTTP/3 connection failed");
                }
                break;
            }
        }
    }

    Ok(())
}

fn negotiated_alpn(connection: &quinn::Connection) -> Vec<String> {
    connection
        .handshake_data()
        .and_then(|data| data.downcast::<HandshakeData>().ok())
        .and_then(|data| data.protocol)
        .map(|protocol| vec![String::from_utf8_lossy(&protocol).into_owned()])
        .unwrap_or_default()
}

fn load_quic_config(
    config: &Config,
) -> Result<quinn::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let cert_path = config
        .tls_cert
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ZCI_TLS_CERT is not set"))?;
    let key_path = config
        .tls_key
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ZCI_TLS_KEY is not set"))?;

    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()?;

    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key found"))?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let crypto = QuicServerConfig::try_from(tls_config)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let transport = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| io::Error::other("QUIC transport config is unexpectedly shared"))?;
    transport
        .max_concurrent_bidi_streams(256_u32.into())
        .max_concurrent_uni_streams(256_u32.into())
        .max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into()?));

    Ok(server_config)
}

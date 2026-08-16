use crate::config::Config;
use axum::extract::Extension;
use axum::Router;
use client_intel_core::{describe_ip, parse_client_hello, ConnectionMeta};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use std::fs::File;
use std::io::{self, BufReader};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

pub async fn run_http_server(
    config: Arc<Config>,
    router: Router,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(config.http_bind).await?;
    info!(address = %config.http_bind, "HTTP collector listening");

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let router = router.clone();
        let local_addr = stream.local_addr().ok();

        tokio::spawn(async move {
            let meta = ConnectionMeta {
                remote_ip: Some(remote_addr.ip().to_string()),
                ip: Some(describe_ip(remote_addr.ip())),
                remote_port: Some(remote_addr.port()),
                local_port: local_addr.map(|value| value.port()),
                transport: "tcp".to_string(),
                tls: None,
            };

            if let Err(error) = serve_plain(stream, router, meta).await {
                debug!(?error, "plain HTTP connection ended with error");
            }
        });
    }
}

pub async fn run_tls_server(
    config: Arc<Config>,
    router: Router,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tls_config = Arc::new(load_tls_config(&config)?);
    let acceptor = TlsAcceptor::from(tls_config);
    let listener = TcpListener::bind(config.bind).await?;
    info!(address = %config.bind, "TLS collector listening");

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        let local_addr = stream.local_addr().ok();

        tokio::spawn(async move {
            let tls_observation = peek_client_hello(&stream).await;

            let tls_stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    debug!(?error, "TLS handshake failed");
                    return;
                }
            };

            let (_, connection) = tls_stream.get_ref();
            let negotiated_alpn = connection
                .alpn_protocol()
                .map(|value| String::from_utf8_lossy(value).to_string());
            let negotiated_tls_version = connection
                .protocol_version()
                .map(|value| format!("{value:?}"));

            let mut tls_observation = tls_observation.unwrap_or_default();
            tls_observation.negotiated_alpn = negotiated_alpn;
            tls_observation.negotiated_tls_version = negotiated_tls_version;

            let meta = ConnectionMeta {
                remote_ip: Some(remote_addr.ip().to_string()),
                ip: Some(describe_ip(remote_addr.ip())),
                remote_port: Some(remote_addr.port()),
                local_port: local_addr.map(|value| value.port()),
                transport: "tcp+tls".to_string(),
                tls: Some(tls_observation),
            };

            if let Err(error) = serve_tls(tls_stream, router, meta).await {
                debug!(?error, "HTTPS connection ended with error");
            }
        });
    }
}

async fn peek_client_hello(stream: &TcpStream) -> Option<client_intel_core::TlsObservation> {
    let result = tokio::time::timeout(Duration::from_millis(500), async {
        let mut buffer = vec![0_u8; 65_535];

        loop {
            let read = match stream.peek(&mut buffer).await {
                Ok(read) if read > 0 => read,
                Ok(_) => return None,
                Err(error) => {
                    debug!(?error, "unable to peek TLS connection");
                    return None;
                }
            };

            // Первые 5 байт TLS record дают точную длину первой записи.
            // Ждём её целиком, чтобы TCP segmentation не превращала ClientHello в ложный parse error.
            if read < 5 {
                tokio::time::sleep(Duration::from_millis(2)).await;
                continue;
            }

            let record_len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
            let needed = 5usize.saturating_add(record_len);
            if read < needed && read < buffer.len() {
                tokio::time::sleep(Duration::from_millis(2)).await;
                continue;
            }

            return match parse_client_hello(&buffer[..read]) {
                Ok(value) => Some(value),
                Err(error) => {
                    debug!(?error, bytes = read, "unable to parse ClientHello");
                    None
                }
            };
        }
    })
    .await;

    match result {
        Ok(value) => value,
        Err(_) => {
            debug!("ClientHello peek timed out");
            None
        }
    }
}

async fn serve_plain(
    stream: TcpStream,
    router: Router,
    meta: ConnectionMeta,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let io = TokioIo::new(stream);
    let service = router.layer(Extension(meta));
    let service = TowerToHyperService::new(service);
    let builder = Builder::new(TokioExecutor::new());
    builder.serve_connection(io, service).await?;
    Ok(())
}

async fn serve_tls(
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    router: Router,
    meta: ConnectionMeta,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let io = TokioIo::new(stream);
    let service = router.layer(Extension(meta));
    let service = TowerToHyperService::new(service);
    let builder = Builder::new(TokioExecutor::new());
    builder.serve_connection(io, service).await?;
    Ok(())
}

fn load_tls_config(config: &Config) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
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

    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(tls_config)
}

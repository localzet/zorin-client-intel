use crate::config::Config;
use crate::wire::{TapIo, WireState};
use axum::extract::Extension;
use axum::Router;
use client_intel_core::{
    describe_ip, parse_client_hello, ClientHelloParseError, ConnectionMeta, TcpObservation,
};
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

#[derive(Clone)]
pub struct ConnectionContext {
    base: ConnectionMeta,
    wire: WireState,
}

impl ConnectionContext {
    pub fn new(base: ConnectionMeta, wire: WireState) -> Self {
        Self { base, wire }
    }

    pub fn snapshot(&self) -> ConnectionMeta {
        let mut result = self.base.clone();
        let wire = self.wire.snapshot();
        result.http1_wire = wire.http1;
        result.http2 = wire.http2;
        result
    }
}

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
        let tcp = tcp_runtime_observation(&stream);

        tokio::spawn(async move {
            let wire = WireState::default();
            let meta = ConnectionMeta {
                remote_ip: Some(remote_addr.ip().to_string()),
                ip: Some(describe_ip(remote_addr.ip())),
                remote_port: Some(remote_addr.port()),
                local_ip: local_addr.map(|value| value.ip().to_string()),
                local_port: local_addr.map(|value| value.port()),
                transport: "tcp".to_string(),
                tcp,
                ..ConnectionMeta::default()
            };
            let context = ConnectionContext::new(meta, wire.clone());

            if let Err(error) = serve_plain(TapIo::new(stream, wire), router, context).await {
                debug!(?error, "HTTP connection ended with error");
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
        let tcp = tcp_runtime_observation(&stream);

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

            let wire = WireState::default();
            let meta = ConnectionMeta {
                remote_ip: Some(remote_addr.ip().to_string()),
                ip: Some(describe_ip(remote_addr.ip())),
                remote_port: Some(remote_addr.port()),
                local_ip: local_addr.map(|value| value.ip().to_string()),
                local_port: local_addr.map(|value| value.port()),
                transport: "tcp+tls".to_string(),
                tcp,
                tls: Some(tls_observation),
                ..ConnectionMeta::default()
            };
            let context = ConnectionContext::new(meta, wire.clone());

            if let Err(error) = serve_tls(TapIo::new(tls_stream, wire), router, context).await {
                debug!(?error, "HTTPS connection ended with error");
            }
        });
    }
}

async fn peek_client_hello(stream: &TcpStream) -> Option<client_intel_core::TlsObservation> {
    let result = tokio::time::timeout(Duration::from_secs(1), async {
        let mut buffer = vec![0_u8; 256 * 1024];

        loop {
            let read = match stream.peek(&mut buffer).await {
                Ok(read) if read > 0 => read,
                Ok(_) => return None,
                Err(error) => {
                    debug!(?error, "unable to peek TLS connection");
                    return None;
                }
            };

            match parse_client_hello(&buffer[..read]) {
                Ok(value) => return Some(value),
                Err(ClientHelloParseError::Incomplete) if read < buffer.len() => {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                Err(error) => {
                    debug!(?error, bytes = read, "unable to parse ClientHello");
                    return None;
                }
            }
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

async fn serve_plain<T>(
    stream: T,
    router: Router,
    context: ConnectionContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let service = router.layer(Extension(context));
    let service = TowerToHyperService::new(service);
    let builder = Builder::new(TokioExecutor::new());
    builder.serve_connection(io, service).await?;
    Ok(())
}

async fn serve_tls<T>(
    stream: T,
    router: Router,
    context: ConnectionContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    serve_plain(stream, router, context).await
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

#[cfg(target_os = "linux")]
fn tcp_runtime_observation(stream: &TcpStream) -> Option<TcpObservation> {
    use std::mem::{size_of, zeroed};
    use std::os::fd::AsRawFd;

    unsafe {
        let mut info: libc::tcp_info = zeroed();
        let mut len = size_of::<libc::tcp_info>() as libc::socklen_t;
        let rc = libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if rc != 0 {
            return None;
        }

        Some(TcpObservation {
            source: "linux-tcp-info".to_string(),
            runtime_rtt_us: Some(info.tcpi_rtt),
            runtime_rtt_var_us: Some(info.tcpi_rttvar),
            runtime_snd_mss: Some(info.tcpi_snd_mss),
            runtime_rcv_mss: Some(info.tcpi_rcv_mss),
            runtime_snd_cwnd: Some(info.tcpi_snd_cwnd),
            runtime_retransmits: Some(info.tcpi_retransmits as u32),
            runtime_total_retrans: Some(info.tcpi_total_retrans),
            ..TcpObservation::default()
        })
    }
}

#[cfg(not(target_os = "linux"))]
fn tcp_runtime_observation(_stream: &TcpStream) -> Option<TcpObservation> {
    None
}

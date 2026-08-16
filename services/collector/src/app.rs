use crate::config::Config;
use crate::enrichment::EnrichmentDb;
use crate::metrics::Metrics;
use crate::sensor::TransportCache;
use crate::server::ConnectionContext;
use crate::store::Store;
use crate::tenancy::Tenancy;
use axum::extract::{DefaultBodyLimit, Extension, Path, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use client_intel_core::{
    build_profile, compare_observations, describe_ip, fingerprint_http, BrowserProbe, ClientSummary,
    ConnectionMeta, HttpHeaderObservation, HttpObservation, Observation, ResolutionKind,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<Store>,
    pub enrichment: Arc<EnrichmentDb>,
    pub tenancy: Arc<Tenancy>,
    pub transport_cache: TransportCache,
    pub metrics: Arc<Metrics>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    storage: &'static str,
    tls_collector: bool,
    quic_http3_collector: bool,
    wire_http_fingerprinting: bool,
    enrichment: bool,
    enrichment_source: Option<String>,
    tcp_sensor_socket: String,
    site_key_required: bool,
    admin_key_required: bool,
    configured_tenants: usize,
    retention_days: u32,
    graph_window_days: u32,
}

pub fn build_router(
    config: Arc<Config>,
    store: Arc<Store>,
    enrichment: Arc<EnrichmentDb>,
    tenancy: Arc<Tenancy>,
    transport_cache: TransportCache,
    metrics: Arc<Metrics>,
) -> Router {
    let max_probe_bytes = config.max_probe_bytes;
    let cors_origins = config.cors_origins.clone();
    let state = AppState {
        config,
        store,
        enrichment,
        tenancy,
        transport_cache,
        metrics,
    };

    let mut router = Router::new()
        .route("/", get(inspect))
        .route("/inspect", get(inspect))
        .route("/probe.js", get(probe_script))
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/api/v1/schema", get(schema))
        .route("/api/v1/observe", post(observe))
        .route("/api/v1/observations/{id}", get(get_observation))
        .route("/api/v1/compare/{left}/{right}", get(compare))
        .route("/api/v1/clients/{id}", get(get_client))
        .layer(DefaultBodyLimit::max(max_probe_bytes))
        .layer(TraceLayer::new_for_http());

    let allowed_origins = cors_origins
        .iter()
        .filter_map(|origin| origin.parse::<HeaderValue>().ok())
        .collect::<Vec<_>>();
    if !allowed_origins.is_empty() {
        router = router.layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(allowed_origins))
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([
                    header::CONTENT_TYPE,
                    HeaderName::from_static("x-zci-site-key"),
                    HeaderName::from_static("x-zci-admin-key"),
                ]),
        );
    }

    router.with_state(state)
}

async fn inspect(State(state): State<AppState>) -> Response {
    let mut response = Html(include_str!("../../../web/inspect.html")).into_response();
    add_transport_discovery_headers(&state, &mut response);
    response
}

async fn probe_script(State(state): State<AppState>) -> Response {
    let mut response = (
        [
            ("content-type", "application/javascript; charset=utf-8"),
            ("cache-control", "public, max-age=300"),
        ],
        include_str!("../../../web/probe.js"),
    )
        .into_response();
    add_transport_discovery_headers(&state, &mut response);
    response
}

fn add_transport_discovery_headers(state: &AppState, response: &mut Response) {
    if !state.config.quic_enabled() {
        return;
    }

    // Alt-Svc позволяет браузеру обнаружить наш HTTP/3 endpoint после первого HTTPS-ответа.
    let value = format!("h3=\":{}\"; ma=86400", state.config.quic_bind.port());
    if let Ok(value) = HeaderValue::from_str(&value) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("alt-svc"), value);
    }
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        storage: state.store.backend_name(),
        tls_collector: state.config.tls_enabled(),
        quic_http3_collector: state.config.quic_enabled(),
        wire_http_fingerprinting: true,
        enrichment: state.enrichment.enabled(),
        enrichment_source: state.enrichment.source_path().map(str::to_string),
        tcp_sensor_socket: state.config.sensor_socket.display().to_string(),
        site_key_required: state.tenancy.site_keys_required(),
        admin_key_required: state.tenancy.admin_keys_required(),
        configured_tenants: state.tenancy.tenants().len(),
        retention_days: state.config.retention_days,
        graph_window_days: state.config.graph_window_days,
    })
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        state.metrics.prometheus(),
    )
}

async fn schema() -> Json<Value> {
    Json(json!({
        "schema": "zci-observation/2",
        "browser_probe": "zci-browser-probe/2",
        "layers": [
            "ip", "network_enrichment", "tcp_runtime", "tcp_syn_sensor", "tls_client_hello",
            "http1_wire", "http2_wire", "http", "quic_http3_native",
            "browser", "client_graph"
        ],
        "fingerprints": [
            "JA3", "JA4", "ZTLS", "ZTLS-WIRE", "ZTCP", "ZHTTP", "ZH1-WIRE", "ZH2",
            "ZQUIC", "ZH3", "ZBROWSER", "ZGPU", "ZCANVAS", "ZAUDIO", "ZFONTS",
            "ZINTL", "ZCAP", "ZSCREEN", "ZMEDIA", "ZAUTO"
        ],
        "model": ["observed", "claimed", "inferred", "enriched"],
    }))
}

async fn observe(
    State(state): State<AppState>,
    Extension(context): Extension<ConnectionContext>,
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    Json(browser): Json<BrowserProbe>,
) -> Result<Json<Observation>, ApiError> {
    if browser.schema != "zci-browser-probe/2" {
        return Err(ApiError::BadRequest("unsupported_browser_probe_schema"));
    }

    let tenant_id = site_tenant(&state, &headers)?;
    let mut connection = context.snapshot();
    state.transport_cache.enrich_connection(&mut connection).await;

    let socket_peer_ip = connection.remote_ip.clone();
    connection = apply_trusted_proxy_ip(connection, &headers, &state.config);
    if let Some(ip) = connection
        .remote_ip
        .as_deref()
        .and_then(|value| value.parse::<IpAddr>().ok())
    {
        connection.enrichment = state.enrichment.lookup(ip);
    }

    let mut http = collect_http(&method, &uri, version, &headers);
    http.http_fp = Some(fingerprint_http(&http));

    let (profile, fingerprints) = build_profile(&connection, &http, Some(&browser));
    let resolution = state
        .store
        .resolve_client(
            &tenant_id,
            &fingerprints,
            state.config.graph_window_days,
            state.config.graph_candidate_limit,
            state.config.graph_match_threshold,
            state.config.graph_min_confidence,
        )
        .await?;

    match resolution.kind {
        ResolutionKind::MatchedClient => state.metrics.graph_match(),
        ResolutionKind::NewClient => state.metrics.graph_new_client(),
        ResolutionKind::Ambiguous => state.metrics.graph_ambiguous(),
    }

    let mut raw = BTreeMap::<String, Value>::new();
    raw.insert("collector_schema".to_string(), json!("zci-observation/2"));
    raw.insert(
        "trust_proxy_headers".to_string(),
        json!(state.config.trust_proxy_headers),
    );
    raw.insert("socket_peer_ip".to_string(), json!(socket_peer_ip));

    let observation = Observation {
        id: Uuid::new_v4(),
        tenant_id,
        client_id: resolution.client_id,
        created_at: Utc::now(),
        connection,
        http,
        browser: Some(browser),
        fingerprints,
        profile,
        resolution,
        raw,
    };

    if let Err(error) = state.store.save(&observation).await {
        state.metrics.storage_error();
        return Err(ApiError::Database(error));
    }
    state.metrics.observation();
    Ok(Json(observation))
}

async fn get_observation(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Observation>, ApiError> {
    let tenant = admin_tenant(&state, &headers)?;
    state
        .store
        .get(id, tenant.as_deref())
        .await?
        .map(Json)
        .ok_or(ApiError::NotFound)
}

async fn compare(
    State(state): State<AppState>,
    Path((left, right)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let tenant = admin_tenant(&state, &headers)?;
    let left_observation = state
        .store
        .get(left, tenant.as_deref())
        .await?
        .ok_or(ApiError::NotFound)?;
    let right_observation = state
        .store
        .get(right, tenant.as_deref())
        .await?
        .ok_or(ApiError::NotFound)?;
    let result = compare_observations(
        &left_observation.fingerprints,
        &right_observation.fingerprints,
    );

    Ok(Json(json!({
        "left": left,
        "right": right,
        "match": result,
    })))
}

async fn get_client(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ClientSummary>, ApiError> {
    let tenant = admin_tenant(&state, &headers)?;
    state
        .store
        .get_client(tenant.as_deref(), id)
        .await?
        .map(Json)
        .ok_or(ApiError::NotFound)
}

fn site_tenant(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let key = header_value(headers, "x-zci-site-key");
    state
        .tenancy
        .resolve_site(key.as_deref())
        .ok_or(ApiError::Unauthorized)
}

fn admin_tenant(state: &AppState, headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    let key = header_value(headers, "x-zci-admin-key");
    let tenant = state
        .tenancy
        .resolve_admin(key.as_deref())
        .ok_or(ApiError::Unauthorized)?;
    Ok((tenant != "*").then_some(tenant))
}

fn apply_trusted_proxy_ip(
    mut connection: ConnectionMeta,
    headers: &HeaderMap,
    config: &Config,
) -> ConnectionMeta {
    if !config.trust_proxy_headers {
        return connection;
    }

    let trusted_peer = connection
        .remote_ip
        .as_deref()
        .and_then(|value| value.parse::<IpAddr>().ok())
        .is_some_and(|ip| config.trusted_proxy_cidrs.iter().any(|cidr| cidr.contains(&ip)));
    if !trusted_peer {
        return connection;
    }

    let peer_ip = connection
        .remote_ip
        .as_deref()
        .and_then(|value| value.parse::<IpAddr>().ok());
    if let Some(peer_ip) = peer_ip {
        if let Some(ip) = forwarded_client_ip(headers, peer_ip, &config.trusted_proxy_cidrs) {
            connection.remote_ip = Some(ip.to_string());
            connection.ip = Some(describe_ip(ip));
        }
    }

    connection
}

fn forwarded_client_ip(
    headers: &HeaderMap,
    peer_ip: IpAddr,
    trusted: &[ipnet::IpNet],
) -> Option<IpAddr> {
    let value = headers.get("x-forwarded-for")?.to_str().ok()?;
    let mut chain = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::parse::<IpAddr>)
        .collect::<Result<Vec<_>, _>>()?;

    if chain.is_empty() {
        return None;
    }

    // X-Forwarded-For строится слева направо: client, proxy1, proxy2, ...
    // Immediate socket peer не входит в header, поэтому добавляем его сами и
    // идём справа налево, снимая только явно доверенные proxy hops.
    chain.push(peer_ip);
    for ip in chain.iter().rev() {
        if trusted.iter().any(|cidr| cidr.contains(ip)) {
            continue;
        }
        return Some(*ip);
    }

    // Если вся цепочка находится внутри доверенной сети, исходным считаем
    // самый левый адрес, а не socket peer.
    chain.first().copied()
}

fn collect_http(method: &Method, uri: &Uri, version: Version, headers: &HeaderMap) -> HttpObservation {
    let mut header_observations = Vec::new();
    let mut header_names = Vec::new();

    for (name, value) in headers {
        let name_string = name.as_str().to_string();
        header_names.push(name_string.clone());

        let value_string = if is_sensitive_header(name.as_str()) {
            "<redacted>".to_string()
        } else {
            value
                .to_str()
                .map(str::to_string)
                .unwrap_or_else(|_| format!("<{} raw bytes>", value.as_bytes().len()))
        };

        header_observations.push(HttpHeaderObservation {
            name: name_string,
            value: value_string,
        });
    }

    HttpObservation {
        method: method.to_string(),
        uri: sanitize_uri(uri),
        version: format!("{version:?}"),
        headers: header_observations,
        header_names,
        user_agent: header_value(headers, "user-agent"),
        accept: header_value(headers, "accept"),
        accept_encoding: header_value(headers, "accept-encoding"),
        accept_language: header_value(headers, "accept-language"),
        sec_fetch_site: header_value(headers, "sec-fetch-site"),
        sec_fetch_mode: header_value(headers, "sec-fetch-mode"),
        sec_fetch_dest: header_value(headers, "sec-fetch-dest"),
        sec_ch_ua: header_value(headers, "sec-ch-ua"),
        sec_ch_ua_platform: header_value(headers, "sec-ch-ua-platform"),
        priority: header_value(headers, "priority"),
        http_fp: None,
    }
}


fn sanitize_uri(uri: &Uri) -> String {
    let path = uri.path();
    let Some(query) = uri.query() else {
        return path.to_string();
    };

    // Значения query-параметров могут содержать OAuth-коды, токены и другие секреты.
    // Для fingerprinting достаточно сохранить форму запроса — имена и порядок параметров.
    let names = query
        .split('&')
        .map(|part| part.split_once('=').map_or(part, |(name, _)| name))
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    if names.is_empty() {
        path.to_string()
    } else {
        format!("{}?{}", path, names.join("&"))
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-zci-admin-key"
            | "x-zci-site-key"
            | "x-api-key"
    )
}

#[derive(Debug)]
enum ApiError {
    BadRequest(&'static str),
    NotFound,
    Unauthorized,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for ApiError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest(code) => (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": code })),
            )
                .into_response(),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "not_found" })),
            )
                .into_response(),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "unauthorized" })),
            )
                .into_response(),
            Self::Database(error) => {
                tracing::error!(?error, "storage operation failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "storage_error" })),
                )
                    .into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_query_values_but_preserves_shape() {
        let uri: Uri = "/callback?code=secret&state=another&flag".parse().expect("URI");
        assert_eq!(sanitize_uri(&uri), "/callback?code&state&flag");
    }

    #[test]
    fn recognizes_credential_headers_case_insensitively() {
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("COOKIE"));
        assert!(is_sensitive_header("x-zci-admin-key"));
        assert!(!is_sensitive_header("accept-language"));
    }


    #[test]
    fn forwarded_chain_stops_at_first_untrusted_hop_from_the_right() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.200, 203.0.113.25, 10.0.0.2"),
        );
        let trusted = vec!["10.0.0.0/8".parse().expect("CIDR")];
        let peer: IpAddr = "10.0.0.3".parse().expect("IP");

        assert_eq!(
            forwarded_client_ip(&headers, peer, &trusted),
            Some("203.0.113.25".parse().expect("IP"))
        );
    }

    #[test]
    fn forwarded_chain_returns_leftmost_when_every_hop_is_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.1, 10.0.0.2"),
        );
        let trusted = vec!["10.0.0.0/8".parse().expect("CIDR")];
        let peer: IpAddr = "10.0.0.3".parse().expect("IP");

        assert_eq!(
            forwarded_client_ip(&headers, peer, &trusted),
            Some("10.0.0.1".parse().expect("IP"))
        );
    }
}

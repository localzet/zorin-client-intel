use crate::config::Config;
use crate::store::Store;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, Version};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use client_intel_core::{
    build_profile, compare_observations, describe_ip, fingerprint_http, BrowserProbe, ConnectionMeta,
    HttpHeaderObservation, HttpObservation, Observation,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<Store>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    storage: &'static str,
    tls_collector: bool,
    retention_days: u32,
}

pub fn build_router(config: Arc<Config>, store: Arc<Store>) -> Router {
    let state = AppState { config, store };

    Router::new()
        .route("/", get(inspect))
        .route("/inspect", get(inspect))
        .route("/probe.js", get(probe_script))
        .route("/health", get(health))
        .route("/api/v1/observe", post(observe))
        .route("/api/v1/observations/{id}", get(get_observation))
        .route("/api/v1/compare/{left}/{right}", get(compare))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn inspect() -> Html<&'static str> {
    Html(include_str!("../../../web/inspect.html"))
}

async fn probe_script() -> impl IntoResponse {
    (
        [("content-type", "application/javascript; charset=utf-8")],
        include_str!("../../../web/probe.js"),
    )
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        storage: state.store.backend_name(),
        tls_collector: state.config.tls_enabled(),
        retention_days: state.config.retention_days,
    })
}

async fn observe(
    State(state): State<AppState>,
    Extension(connection): Extension<ConnectionMeta>,
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    Json(browser): Json<BrowserProbe>,
) -> Result<Json<Observation>, ApiError> {
    let connection = apply_trusted_proxy_ip(connection, &headers, state.config.trust_proxy_headers);
    let mut http = collect_http(&method, &uri, version, &headers);
    http.http_fp = Some(fingerprint_http(&http));

    let (profile, fingerprints) = build_profile(&http, connection.tls.as_ref(), Some(&browser));

    let mut raw = BTreeMap::<String, Value>::new();
    raw.insert("collector_schema".to_string(), json!("zci-observation/1"));
    raw.insert("trust_proxy_headers".to_string(), json!(state.config.trust_proxy_headers));

    let observation = Observation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        connection,
        http,
        browser: Some(browser),
        fingerprints,
        profile,
        raw,
    };

    state.store.save(&observation).await?;
    Ok(Json(observation))
}

async fn get_observation(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Observation>, ApiError> {
    state
        .store
        .get(id)
        .await?
        .map(Json)
        .ok_or(ApiError::NotFound)
}

async fn compare(
    State(state): State<AppState>,
    Path((left, right)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, ApiError> {
    let left_observation = state.store.get(left).await?.ok_or(ApiError::NotFound)?;
    let right_observation = state.store.get(right).await?.ok_or(ApiError::NotFound)?;
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

fn apply_trusted_proxy_ip(
    mut connection: ConnectionMeta,
    headers: &HeaderMap,
    trust_proxy_headers: bool,
) -> ConnectionMeta {
    if !trust_proxy_headers {
        return connection;
    }

    if let Some(ip) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        connection.remote_ip = Some(ip.to_string());
        connection.ip = ip.parse().ok().map(describe_ip);
    }

    connection
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
        uri: uri.to_string(),
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

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
    )
}

#[derive(Debug)]
enum ApiError {
    NotFound,
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
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "observation_not_found" })),
            )
                .into_response(),
            Self::Database(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "storage_error",
                    "message": error.to_string(),
                })),
            )
                .into_response(),
        }
    }
}

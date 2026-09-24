// SPDX-License-Identifier: Apache-2.0

//! The HTTP application: health, readiness, RFC 9728 metadata, and the MCP
//! endpoint behind the resource-server middleware.
//!
//! Only the MCP endpoint is protected. It is served by rmcp's streamable HTTP
//! service in stateless JSON mode, so the gateway keeps no MCP session: every
//! request is authenticated, rate limited, and acted on for the citizen its
//! own token names.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    middleware::from_fn_with_state,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use registry_platform_httpsec::{request_body_limit, security_headers, CspBuilder};
use rmcp::transport::streamable_http_server::{
    session::never::NeverSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use serde_json::json;
use url::Url;

use crate::{
    config::MCP_PATH,
    gateway::Gateway,
    handler::GatewayHandler,
    inbound::{require_caller, ResourceServer, METADATA_PREFIX},
};

pub(crate) struct ServerOptions<'a> {
    /// The configured resource URL, whose authority is the only `Host` the
    /// MCP endpoint accepts.
    pub(crate) resource: &'a Url,
    pub(crate) max_request_body_bytes: usize,
    /// Whether to send `Strict-Transport-Security`. Off only for the
    /// loopback development listener, which is plain HTTP.
    pub(crate) hsts: bool,
}

/// The hosts the MCP endpoint answers for: the configured resource's
/// authority, with and without an explicit port.
fn allowed_hosts(resource: &Url) -> Vec<String> {
    let Some(host) = resource.host_str() else {
        return Vec::new();
    };
    let mut hosts = vec![host.to_owned()];
    if let Some(port) = resource.port() {
        hosts.push(format!("{host}:{port}"));
    }
    hosts
}

pub(crate) fn router(
    gateway: Arc<Gateway>,
    resource_server: Arc<ResourceServer>,
    options: &ServerOptions<'_>,
) -> Router {
    let handler_gateway = Arc::clone(&gateway);
    // No Origin is accepted: the endpoint serves chat-host back ends, not
    // browser pages, so any request a browser page makes is refused.
    let mcp = StreamableHttpService::new(
        move || Ok(GatewayHandler::new(Arc::clone(&handler_gateway))),
        Arc::new(NeverSessionManager::default()),
        StreamableHttpServerConfig::default()
            .with_allowed_hosts(allowed_hosts(options.resource))
            .enforce_origin_validation()
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_sse_keep_alive(None)
            .with_max_request_body_bytes(options.max_request_body_bytes),
    );
    let protected = Router::new()
        .route_service(MCP_PATH, mcp)
        .layer(from_fn_with_state(
            Arc::clone(&resource_server),
            require_caller,
        ));
    let metadata_path = format!("{METADATA_PREFIX}{MCP_PATH}");
    let public = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready).with_state(gateway))
        .route(METADATA_PREFIX, get(metadata))
        .route(&metadata_path, get(metadata))
        .with_state(resource_server);
    let headers = security_headers(CspBuilder::restrictive());
    let headers = if options.hsts {
        headers
    } else {
        headers.without_hsts()
    };
    public
        .merge(protected)
        .fallback(not_found)
        .layer(request_body_limit(options.max_request_body_bytes))
        .layer(headers)
}

async fn health() -> Response {
    no_store((StatusCode::OK, Json(json!({"status": "ok"}))).into_response())
}

async fn ready(State(gateway): State<Arc<Gateway>>) -> Response {
    let (status, body) = if gateway.ready().await {
        (StatusCode::OK, json!({"status": "ready"}))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "unavailable"}),
        )
    };
    no_store((status, Json(body)).into_response())
}

async fn metadata(State(server): State<Arc<ResourceServer>>) -> Response {
    Json(server.metadata().clone()).into_response()
}

async fn not_found() -> Response {
    no_store((StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response())
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

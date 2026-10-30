// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, uri::Authority, HeaderMap, HeaderValue, StatusCode, Uri},
    middleware::{from_fn_with_state, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use registry_platform_httpsec::{request_body_limit, security_headers, CspBuilder, Problem};
use rmcp::transport::streamable_http_server::{
    session::never::NeverSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use serde_json::json;
use url::Url;

use crate::{handler::GatewayHandler, inbound::require_caller, GatewayCore, ResourceServer};

pub const MCP_PATH: &str = "/mcp";
pub const METADATA_PREFIX: &str = "/.well-known/oauth-protected-resource";

#[derive(Clone, Debug)]
pub struct ServerOptions {
    pub resource: Url,
    pub maximum_request_bytes: usize,
    pub hsts: bool,
}

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

#[derive(Debug)]
struct ResourceAuthority {
    host: String,
    port: u16,
    default_port: u16,
}

impl ResourceAuthority {
    fn of(resource: &Url) -> Option<Self> {
        let default_port = match resource.scheme() {
            "https" => 443,
            "http" => 80,
            _ => return None,
        };
        Some(Self {
            host: resource.host_str()?.to_owned(),
            port: resource.port().unwrap_or(default_port),
            default_port,
        })
    }

    fn admits(&self, uri: &Uri, headers: &HeaderMap) -> bool {
        let authority = match headers.get(header::HOST) {
            Some(value) => match value.to_str().map(Authority::try_from) {
                Ok(Ok(authority)) => authority,
                _ => return false,
            },
            None => match uri.authority() {
                Some(authority) => authority.clone(),
                None => return false,
            },
        };
        !authority.as_str().contains('@')
            && authority.host().eq_ignore_ascii_case(&self.host)
            && authority.port_u16().unwrap_or(self.default_port) == self.port
    }
}

async fn require_resource_host(
    State(authority): State<Arc<Option<ResourceAuthority>>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let admitted = authority
        .as_ref()
        .as_ref()
        .is_some_and(|authority| authority.admits(request.uri(), request.headers()));
    if !admitted || request.headers().contains_key(header::ORIGIN) {
        return forbidden();
    }
    next.run(request).await
}

pub fn router(
    gateway: Arc<GatewayCore>,
    resource_server: Arc<ResourceServer>,
    options: &ServerOptions,
) -> Router {
    let handler_gateway = Arc::clone(&gateway);
    let mcp = StreamableHttpService::new(
        move || Ok(GatewayHandler::new(Arc::clone(&handler_gateway))),
        Arc::new(NeverSessionManager::default()),
        StreamableHttpServerConfig::default()
            .with_allowed_hosts(allowed_hosts(&options.resource))
            .enforce_origin_validation()
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_sse_keep_alive(None)
            .with_max_request_body_bytes(options.maximum_request_bytes),
    );
    let protected = Router::new()
        .route_service(MCP_PATH, mcp)
        .layer(from_fn_with_state(
            Arc::clone(&resource_server),
            require_caller,
        ))
        .layer(from_fn_with_state(
            Arc::new(ResourceAuthority::of(&options.resource)),
            require_resource_host,
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
        .layer(request_body_limit(options.maximum_request_bytes))
        .layer(headers)
}

async fn health() -> Response {
    no_store((StatusCode::OK, Json(json!({"status": "alive"}))).into_response())
}

async fn ready(State(gateway): State<Arc<GatewayCore>>) -> Response {
    let (status, body) = if gateway.ready().await {
        (StatusCode::OK, json!({"status": "ready"}))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "not-ready"}),
        )
    };
    no_store((status, Json(body)).into_response())
}

async fn metadata(State(server): State<Arc<ResourceServer>>) -> Response {
    Json(server.metadata().clone()).into_response()
}

fn forbidden() -> Response {
    problem(
        StatusCode::FORBIDDEN,
        "forbidden",
        "The request's host or origin is not accepted.",
    )
}

async fn not_found() -> Response {
    problem(
        StatusCode::NOT_FOUND,
        "not-found",
        "The gateway serves no such route.",
    )
}

pub(crate) fn problem(status: StatusCode, code: &'static str, detail: &'static str) -> Response {
    no_store(
        Problem::new(
            "about:blank",
            status.canonical_reason().unwrap_or_default(),
            status,
        )
        .detail(detail)
        .with_extra("code", json!(code))
        .into_response(),
    )
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

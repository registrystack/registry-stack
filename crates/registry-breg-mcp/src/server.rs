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
    body::Body,
    extract::{Request, State},
    http::{header, uri::Authority, HeaderMap, HeaderValue, StatusCode, Uri},
    middleware::{from_fn_with_state, Next},
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

/// The one authority the MCP endpoint answers for: the configured resource's
/// host and port, with the port a `Host` header may leave implicit.
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

    /// Whether a request's `Host` names this authority. A `Host` without a
    /// port names the scheme's default one, so `host`, `host:443` for an
    /// https resource and `host:80` for an http one are the same authority,
    /// and a host on any other port is not.
    fn admits(&self, uri: &Uri, headers: &HeaderMap) -> bool {
        let authority = match headers.get(header::HOST) {
            Some(value) => match value.to_str().map(Authority::try_from) {
                Ok(Ok(authority)) => authority,
                _ => return false,
            },
            // HTTP/2 carries the host in `:authority`.
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

/// The outermost layer of the MCP endpoint: a request for another host, or
/// any request a browser page makes, is refused before its token is verified
/// or either rate limit is charged. rmcp repeats both checks inside.
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
        return forbidden().await;
    }
    next.run(request).await
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
    // Added last, so it runs first. The configuration admits only an http or
    // https resource with a host, so the authority is always known; were it
    // not, the guard would admit nothing.
    let protected = protected.layer(from_fn_with_state(
        Arc::new(ResourceAuthority::of(options.resource)),
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

async fn forbidden() -> Response {
    no_store((StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"}))).into_response())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn admits(resource: &str, host: &str) -> bool {
        let authority =
            ResourceAuthority::of(&Url::parse(resource).expect("url")).expect("authority");
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_str(host).expect("header"));
        authority.admits(&Uri::from_static("/mcp"), &headers)
    }

    #[test]
    fn the_resource_host_is_admitted_with_or_without_its_default_port() {
        let https = "https://gateway.example.test/mcp";
        for host in [
            "gateway.example.test",
            "gateway.example.test:443",
            "Gateway.Example.Test",
        ] {
            assert!(admits(https, host), "{host}");
        }
        for host in [
            "gateway.example.test:80",
            "gateway.example.test:8443",
            "attacker.example.test",
            "attacker.example.test:443",
            "user@gateway.example.test",
            "gateway.example.test.attacker.example.test",
            "",
        ] {
            assert!(!admits(https, host), "{host}");
        }
        let http = "http://gateway.example.test/mcp";
        assert!(admits(http, "gateway.example.test:80"));
        assert!(!admits(http, "gateway.example.test:443"));
    }

    #[test]
    fn an_explicit_resource_port_must_be_named() {
        let resource = "http://127.0.0.1:8095/mcp";
        assert!(admits(resource, "127.0.0.1:8095"));
        assert!(!admits(resource, "127.0.0.1"));
        assert!(!admits(resource, "127.0.0.1:80"));
        assert!(!admits(resource, "localhost:8095"));
        let ipv6 = "https://[::1]:8443/mcp";
        assert!(admits(ipv6, "[::1]:8443"));
        assert!(!admits(ipv6, "[::1]"));
    }

    #[test]
    fn an_http2_authority_stands_in_for_a_missing_host() {
        let authority =
            ResourceAuthority::of(&Url::parse("https://gateway.example.test/mcp").expect("url"))
                .expect("authority");
        let headers = HeaderMap::new();
        assert!(authority.admits(
            &Uri::from_static("https://gateway.example.test/mcp"),
            &headers
        ));
        assert!(!authority.admits(
            &Uri::from_static("https://attacker.example.test/mcp"),
            &headers
        ));
        assert!(!authority.admits(&Uri::from_static("/mcp"), &headers));
    }
}

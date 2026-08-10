// SPDX-License-Identifier: Apache-2.0
//! Relay V2 HTTP service composition and process-local resource bounds.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::routing::{get, post};
use axum::Router;
use axum::{body::Body, http::Request};
use registry_platform_httpsec::{security_headers, CspBuilder};
use tower_http::trace::TraceLayer;

use crate::artifacts::ArtifactSet;
use crate::audit::RelayAudit;
use crate::auth::RelayAuthenticator;
use crate::cursor::CursorKey;
use crate::model::CompiledRegistry;
use crate::sqlite_runtime::SqliteRuntime;

const MAXIMUM_URI_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct InstitutionMetadata {
    pub identifier: String,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct AlignmentMetadata {
    pub name: String,
    pub version: String,
    pub status: String,
    pub cfr_target: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ServiceMetadata {
    pub authority: InstitutionMetadata,
    pub operator: Option<InstitutionMetadata>,
    pub authoritative_scope: String,
    pub alignment_targets: Vec<AlignmentMetadata>,
}

#[derive(Clone, Debug)]
pub struct QuotaConfig {
    pub requests_per_minute: u32,
    pub burst: u32,
}

#[derive(Clone)]
pub struct RelayService {
    pub registry: Arc<CompiledRegistry>,
    pub artifacts: Arc<ArtifactSet>,
    pub sqlite: Arc<SqliteRuntime>,
    pub authenticator: Option<RelayAuthenticator>,
    pub audit: RelayAudit,
    pub cursor_key: Option<Arc<CursorKey>>,
    pub cursor_maximum_age: Duration,
    pub request_timeout: Duration,
    pub metadata: ServiceMetadata,
    pub(crate) quota: Option<Arc<QuotaLimiter>>,
}

impl RelayService {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        registry: Arc<CompiledRegistry>,
        artifacts: Arc<ArtifactSet>,
        sqlite: Arc<SqliteRuntime>,
        authenticator: Option<RelayAuthenticator>,
        audit: RelayAudit,
        cursor_key: Option<Arc<CursorKey>>,
        cursor_maximum_age: Duration,
        request_timeout: Duration,
        quota: Option<QuotaConfig>,
        metadata: ServiceMetadata,
    ) -> Self {
        Self {
            registry,
            artifacts,
            sqlite,
            authenticator,
            audit,
            cursor_key,
            cursor_maximum_age,
            request_timeout,
            metadata,
            quota: quota.map(|config| Arc::new(QuotaLimiter::new(config))),
        }
    }

    #[must_use]
    pub async fn is_ready(&self) -> bool {
        let audit = self.audit.ready();
        let source = self.sqlite.is_ready();
        let issuer = async {
            match &self.authenticator {
                Some(authenticator) => authenticator.is_ready().await,
                None => true,
            }
        };
        let (audit_ready, source_ready, issuer_ready) = tokio::join!(audit, source, issuer);
        audit_ready && source_ready && issuer_ready
    }
}

/// Construct the fixed V2 route inventory. Individual data operations remain
/// compiler-confined by handler dispatch against the immutable model.
pub fn router(service: Arc<RelayService>) -> Router {
    let has_statistical_datasets = !service.registry.statistical_datasets.is_empty();
    let router = Router::new()
        .route("/health", get(crate::api::health))
        .route("/ready", get(crate::api::ready))
        .route("/openapi.json", get(crate::api::openapi))
        .route("/v2", get(crate::api::service_metadata))
        .route("/v2/resources", get(crate::api::resource_list))
        .route(
            "/v2/resources/{resource}",
            get(crate::api::resource_metadata),
        )
        .route(
            "/v2/resources/{resource}/records",
            get(crate::api::record_list),
        )
        .route(
            "/v2/resources/{resource}/records/{record_identifier}",
            get(crate::api::record_read),
        )
        .route(
            "/v2/resources/{resource}/lookups/{lookup}",
            post(crate::api::record_lookup),
        )
        .route(
            "/v2/artifacts/{artifact_identifier}",
            get(crate::api::artifact),
        )
        .route(
            "/sdmx/v2/data/{context}/{agency}/{resource}/{version}/{key}",
            get(crate::sdmx::data),
        )
        .route(
            "/sdmx/v2/data/{context}/{agency}/{resource}/{version}",
            get(crate::sdmx::data_without_key),
        )
        .route(
            "/sdmx/v2/structure/{artefact_type}/{agency}/{resource}/{version}",
            get(crate::sdmx::structure),
        );
    let router = if has_statistical_datasets {
        router
            .route(
                "/sdmx/v2/schema/{context}/{agency}/{resource}/{version}",
                get(crate::sdmx::schema),
            )
            .route("/sdmx/v2/availability", get(crate::sdmx::unsupported))
            .route(
                "/sdmx/v2/availability/{*rest}",
                get(crate::sdmx::unsupported),
            )
    } else {
        router
    };
    router
        .fallback(crate::api::not_found)
        .with_state(service)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<Body>| {
                    tracing::info_span!(
                        target: "registry_relay_v2::http",
                        "http.request",
                        method = operational_method(request.method()),
                        route = operational_route(request.uri()),
                    )
                })
                .on_response(
                    |response: &http::Response<Body>, latency: Duration, span: &tracing::Span| {
                        tracing::info!(
                            parent: span,
                            status = response.status().as_u16(),
                            latency_milliseconds = bounded_milliseconds(latency),
                            trace_id = response_trace_id(response.headers()).unwrap_or("none"),
                            "request completed"
                        );
                    },
                ),
        )
        .layer(security_headers(CspBuilder::restrictive()))
}

fn operational_method(method: &http::Method) -> &'static str {
    match method.as_str() {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "PATCH" => "PATCH",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        "CONNECT" => "CONNECT",
        "TRACE" => "TRACE",
        _ => "OTHER",
    }
}

/// Classify only the fixed route shape. Dynamic identifiers and query values
/// never cross the operational logging boundary.
fn operational_route(uri: &http::Uri) -> &'static str {
    if uri.path() == "/sdmx/v2/availability" || uri.path().starts_with("/sdmx/v2/availability/") {
        return "/sdmx/v2/availability/{*rest}";
    }
    let mut segments = uri.path().trim_start_matches('/').split('/');
    let parts = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    );
    if segments.next().is_some() {
        return "unmatched";
    }
    match parts {
        (Some("health"), None, None, None, None, None, None, None) => "/health",
        (Some("ready"), None, None, None, None, None, None, None) => "/ready",
        (Some("openapi.json"), None, None, None, None, None, None, None) => "/openapi.json",
        (Some("v2"), None, None, None, None, None, None, None) => "/v2",
        (Some("v2"), Some("resources"), None, None, None, None, None, None) => "/v2/resources",
        (Some("v2"), Some("resources"), Some(resource), None, None, None, None, None)
            if !resource.is_empty() =>
        {
            "/v2/resources/{resource}"
        }
        (
            Some("v2"),
            Some("resources"),
            Some(resource),
            Some("records"),
            None,
            None,
            None,
            None,
        ) if !resource.is_empty() => "/v2/resources/{resource}/records",
        (
            Some("v2"),
            Some("resources"),
            Some(resource),
            Some("records"),
            Some(record_identifier),
            None,
            None,
            None,
        ) if !resource.is_empty() && !record_identifier.is_empty() => {
            "/v2/resources/{resource}/records/{record_identifier}"
        }
        (
            Some("v2"),
            Some("resources"),
            Some(resource),
            Some("lookups"),
            Some(lookup),
            None,
            None,
            None,
        ) if !resource.is_empty() && !lookup.is_empty() => {
            "/v2/resources/{resource}/lookups/{lookup}"
        }
        (
            Some("v2"),
            Some("artifacts"),
            Some(artifact_identifier),
            None,
            None,
            None,
            None,
            None,
        ) if !artifact_identifier.is_empty() => "/v2/artifacts/{artifact_identifier}",
        (
            Some("sdmx"),
            Some("v2"),
            Some("data"),
            Some(context),
            Some(agency),
            Some(resource),
            Some(version),
            Some(key),
        ) if !context.is_empty()
            && !agency.is_empty()
            && !resource.is_empty()
            && !version.is_empty()
            && !key.is_empty() =>
        {
            "/sdmx/v2/data/{context}/{agency}/{resource}/{version}/{key}"
        }
        (
            Some("sdmx"),
            Some("v2"),
            Some("data"),
            Some(context),
            Some(agency),
            Some(resource),
            Some(version),
            None,
        ) if !context.is_empty()
            && !agency.is_empty()
            && !resource.is_empty()
            && !version.is_empty() =>
        {
            "/sdmx/v2/data/{context}/{agency}/{resource}/{version}"
        }
        (
            Some("sdmx"),
            Some("v2"),
            Some("structure"),
            Some(context),
            Some(agency),
            Some(resource),
            Some(version),
            None,
        ) if !context.is_empty()
            && !agency.is_empty()
            && !resource.is_empty()
            && !version.is_empty() =>
        {
            "/sdmx/v2/structure/{context}/{agency}/{resource}/{version}"
        }
        (
            Some("sdmx"),
            Some("v2"),
            Some("schema"),
            Some(context),
            Some(agency),
            Some(resource),
            Some(version),
            None,
        ) if !context.is_empty()
            && !agency.is_empty()
            && !resource.is_empty()
            && !version.is_empty() =>
        {
            "/sdmx/v2/schema/{context}/{agency}/{resource}/{version}"
        }
        _ => "unmatched",
    }
}

fn response_trace_id(headers: &http::HeaderMap) -> Option<&str> {
    let value = headers.get("traceparent")?.to_str().ok()?;
    let mut members = value.split('-');
    let version = members.next()?;
    let trace_id = members.next()?;
    let parent_id = members.next()?;
    let flags = members.next()?;
    if members.next().is_some()
        || version.len() != 2
        || trace_id.len() != 32
        || parent_id.len() != 16
        || flags.len() != 2
        || !trace_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    Some(trace_id)
}

fn bounded_milliseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Debug)]
pub(crate) struct QuotaLimiter {
    requests_per_minute: f64,
    burst: f64,
    states: Mutex<BTreeMap<String, QuotaState>>,
}

#[derive(Debug)]
struct QuotaState {
    tokens: f64,
    observed_at: Instant,
}

impl QuotaLimiter {
    fn new(config: QuotaConfig) -> Self {
        let burst = f64::from(config.burst.max(1));
        Self {
            requests_per_minute: f64::from(config.requests_per_minute.max(1)),
            burst,
            states: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn admit(&self, operation: &str) -> bool {
        let now = Instant::now();
        let mut states = self
            .states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = states.entry(operation.to_owned()).or_insert(QuotaState {
            tokens: self.burst,
            observed_at: now,
        });
        let elapsed = now.duration_since(state.observed_at).as_secs_f64();
        state.observed_at = now;
        state.tokens = (state.tokens + elapsed * self.requests_per_minute / 60.0).min(self.burst);
        if state.tokens < 1.0 {
            return false;
        }
        state.tokens -= 1.0;
        true
    }
}

#[must_use]
pub(crate) fn uri_within_bound(uri: &http::Uri) -> bool {
    uri.to_string().len() <= MAXIMUM_URI_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_is_scoped_to_the_compiled_operation() {
        let limiter = QuotaLimiter::new(QuotaConfig {
            requests_per_minute: 1,
            burst: 1,
        });

        assert!(limiter.admit("resource-a.read"));
        assert!(!limiter.admit("resource-a.read"));
        assert!(limiter.admit("resource-b.read"));
    }

    #[test]
    fn operational_dimensions_never_include_request_values() {
        let uri = "/v2/resources/private-registry/records/protected-record?fields=secret"
            .parse()
            .expect("URI");
        assert_eq!(
            operational_route(&uri),
            "/v2/resources/{resource}/records/{record_identifier}"
        );
        assert!(!operational_route(&uri).contains("private-registry"));
        assert!(!operational_route(&uri).contains("protected-record"));
        let availability = "/sdmx/v2/availability/dataflow/PRIVATE/SECRET/1.0.0/*/REF_AREA"
            .parse()
            .expect("availability URI");
        assert_eq!(
            operational_route(&availability),
            "/sdmx/v2/availability/{*rest}"
        );
        assert!(!operational_route(&availability).contains("SECRET"));
        assert_eq!(
            operational_method(&http::Method::from_bytes(b"ATTACKER-CONTROLLED").expect("method")),
            "OTHER"
        );
    }

    #[test]
    fn operational_trace_identifier_is_closed_and_bounded() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
                .parse()
                .expect("header"),
        );
        assert_eq!(
            response_trace_id(&headers),
            Some("0123456789abcdef0123456789abcdef")
        );
        headers.insert(
            "traceparent",
            "attacker-controlled-protected-value"
                .parse()
                .expect("header"),
        );
        assert_eq!(response_trace_id(&headers), None);
    }
}

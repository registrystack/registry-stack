// SPDX-License-Identifier: Apache-2.0
//! Audit core: trait, record schema, JSONL envelope, and helpers.
//!
//! V1 ships the in-process trait, the `AuditRecord` struct, stdout/file
//! / syslog sinks, optional chaining, and the request-scoped middleware.
//!
//! Forward compatibility:
//! - `FileSink` and `SyslogSink` are production audit destinations.
//! - Chained-hash tamper-evidence injects `prev_hash` / `record_hash`
//!   envelope fields while keeping the core `AuditRecord` stable.
//!
//! Integration:
//! - The middleware reads `Principal` from request extensions when
//!   present and projects its identity into `principal_id`, `auth_mode`,
//!   and `scopes_used`.
//! - The error module attaches a stable error code on failure
//!   responses via the `ErrorCodeExt` response extension defined in
//!   this module; the audit middleware reads it and records it.

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::Body;
use axum::extract::{ConnectInfo, Extension};
use axum::http::{HeaderMap, Request};
use axum::middleware::Next;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;
use tracing::error;
use ulid::Ulid;

pub mod chain;
pub mod file;
pub mod middleware;
pub mod redact;
pub mod stdout;
pub mod syslog;

pub use chain::ChainingSink;
pub use file::FileSink;
pub use redact::{redact_query_with_sensitive_fields, sensitive_value_hash, QueryRedactor};
pub use stdout::StdoutSink;
pub use syslog::SyslogSink;

/// Response extension carrying the stable error code emitted by failing
/// handlers (typically `crate::error::Error::into_response`). The audit
/// middleware reads this on the way out and records it as
/// `AuditRecord::error_code`. The marker lives here so other modules
/// can attach a code without depending on audit internals.
#[derive(Debug, Clone)]
pub struct ErrorCodeExt(pub String);

/// Runtime knobs used by the audit middleware. Production installs this
/// from `Config`; unit tests may omit it and get secure defaults.
#[derive(Debug, Clone, Default)]
pub struct AuditSettings {
    pub include_health: bool,
    pub trust_proxy_enabled: bool,
    pub trusted_proxies: Vec<String>,
    pub sensitive_fields: Vec<String>,
}

/// Optional structured context projected by handlers that have
/// resolved entity-layer state. The middleware falls back to path
/// parsing when this extension is absent.
#[derive(Debug, Clone, Default)]
pub struct AuditContextExt {
    pub dataset_id: Option<String>,
    pub entity_name: Option<String>,
    pub table_id: Option<String>,
    pub relationship: Option<String>,
    pub aggregate_id: Option<String>,
    pub underlying_kind: Option<String>,
    pub collection_id: Option<String>,
    pub primary_key: Option<String>,
    pub offering_id: Option<String>,
    pub verification_id: Option<String>,
    pub verification_decision: Option<String>,
    pub claim_hash: Option<String>,
    pub evidence_hash: Option<String>,
    pub null_geometry_count: Option<u64>,
    pub invalid_geometry_count: Option<u64>,
    pub row_count: Option<u64>,
    pub suppressed_groups: Option<u64>,
}

/// Response-extension marker emitted by handlers that signed a VC for
/// the response. The audit middleware embeds the issuance metadata
/// alongside the regular request audit record.
///
/// Fields mirror the spec verbatim. `validity` is exposed as three
/// separate Unix-seconds timestamps; the audit envelope serializer
/// wraps them into the `{iat, nbf, exp}` object.
#[derive(Debug, Clone)]
pub struct ProvenanceIssuanceExt {
    pub iss: String,
    pub kid: String,
    pub jti: String,
    pub claim_type: String,
    pub subject: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
}

/// Endpoint family for an audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    Health,
    Ready,
    Catalog,
    Dataset,
    Schema,
    Verify,
    EvidenceVerification,
    Rows,
    AggregateList,
    Aggregate,
    OgcCollectionItems,
    OgcFeature,
    Admin,
    Openapi,
    /// Catch-all for routes that don't match a documented family.
    Other,
}

/// Outcome classification for a request, derived from the HTTP status.
/// Distinct from `error_code`: this is the high-level bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Ok,
    Denied,
    Error,
}

impl AuditOutcome {
    /// 2xx/3xx -> `Ok`, 401/403 -> `Denied`, everything else -> `Error`.
    #[must_use]
    pub fn from_status(status: u16) -> Self {
        match status {
            200..=399 => AuditOutcome::Ok,
            401 | 403 => AuditOutcome::Denied,
            _ => AuditOutcome::Error,
        }
    }
}

/// One audit record. Field order in this struct matches the JSONL
/// output order for readability; serde preserves declaration order.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    /// ISO-8601 UTC with millisecond precision and trailing `Z`.
    pub ts: String,
    /// ULID, 26 chars Crockford Base32; identical to `X-Request-Id`.
    pub request_id: String,
    /// Stable identifier of the authenticated caller. Source depends
    /// on the provider that authenticated the request (`auth_mode`):
    /// the API-key entry id for `api_key`, the JWT `sub`/`client_id`
    /// for `oidc`. `null` only when auth failed before identification.
    pub principal_id: Option<String>,
    /// `api_key` or `oidc`. `None` matches `principal_id = None` to
    /// preserve null-coupling.
    pub auth_mode: Option<String>,
    /// Client IP textual form (post-proxy when the trust policy resolves).
    pub remote_addr: String,
    /// HTTP method.
    pub method: String,
    /// Path only; query string lives in `query_params`.
    pub path: String,
    /// Family for grouping and noise gating.
    pub endpoint_kind: EndpointKind,
    /// Set on dataset/schema/rows/aggregate_list/aggregate.
    pub dataset_id: Option<String>,
    /// Set when path includes an entity.
    pub entity_name: Option<String>,
    /// Internal backing table when known by the handler.
    pub table_id: Option<String>,
    /// Relationship traversed by a nested entity request.
    pub relationship: Option<String>,
    /// Set on aggregate only.
    pub aggregate_id: Option<String>,
    /// Underlying entity route family for compatibility with row-read
    /// alerting, e.g. `entity_collection` for OGC collection reads.
    pub underlying_kind: Option<String>,
    /// OGC collection id when a request resolves a spatial collection.
    pub collection_id: Option<String>,
    /// Primary key for single-record reads when known.
    pub primary_key: Option<String>,
    /// Evidence offering checked by an evidence-verification request.
    pub offering_id: Option<String>,
    /// Verification correlation id emitted by an evidence-verification request.
    pub verification_id: Option<String>,
    /// Evidence-verification decision, when the endpoint produced one.
    pub verification_decision: Option<String>,
    /// HMAC binding for submitted claims, never raw claims.
    pub claim_hash: Option<String>,
    /// HMAC binding for submitted evidence metadata, never raw evidence.
    pub evidence_hash: Option<String>,
    /// Scopes actually checked on this request, in declaration order.
    pub scopes_used: Vec<String>,
    /// Redacted parameter inventory (names + ops, never values).
    pub query_params: Value,
    /// Verbatim `Data-Purpose` header value when present.
    pub purpose: Option<String>,
    /// HTTP status returned.
    pub status_code: u16,
    /// Rows on `rows`, group count on `aggregate`.
    pub row_count: Option<u64>,
    /// Features returned with `geometry: null`.
    pub null_geometry_count: Option<u64>,
    /// Features rejected because their geometry was malformed.
    pub invalid_geometry_count: Option<u64>,
    /// Groups removed/masked by disclosure control.
    pub suppressed_groups: Option<u64>,
    /// Server-side handling time, milliseconds.
    pub duration_ms: u64,
    /// Stable taxonomy code on 4xx/5xx; `null` on 2xx/3xx.
    pub error_code: Option<String>,
    /// Present when the response carried a signed VC. `None` for plain
    /// JSON responses and deployments without provenance enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ProvenanceIssuanceRecord>,
}

/// Provenance issuance metadata embedded in an `AuditRecord` when the
/// response carried a signed VC.
#[derive(Debug, Clone, Serialize)]
pub struct ProvenanceIssuanceRecord {
    /// Always `"provenance.vc.issued"`; pinned here so a consumer can
    /// filter on this discriminator without inspecting the rest of
    /// the record.
    pub event: &'static str,
    pub iss: String,
    pub kid: String,
    pub jti: String,
    pub claim_type: String,
    pub subject: String,
    pub validity: ProvenanceValidity,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProvenanceValidity {
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
}

impl From<&ProvenanceIssuanceExt> for ProvenanceIssuanceRecord {
    fn from(ext: &ProvenanceIssuanceExt) -> Self {
        Self {
            event: "provenance.vc.issued",
            iss: ext.iss.clone(),
            kid: ext.kid.clone(),
            jti: ext.jti.clone(),
            claim_type: ext.claim_type.clone(),
            subject: ext.subject.clone(),
            validity: ProvenanceValidity {
                iat: ext.iat,
                nbf: ext.nbf,
                exp: ext.exp,
            },
        }
    }
}

/// JSONL envelope handed to a sink. The chaining wrapper attaches
/// `prev_hash` / `record_hash` here before serialising, so the inner
/// record schema never changes.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEnvelope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_hash: Option<String>,
    #[serde(flatten)]
    pub record: AuditRecord,
}

impl From<AuditRecord> for AuditEnvelope {
    fn from(record: AuditRecord) -> Self {
        Self {
            prev_hash: None,
            record_hash: None,
            record,
        }
    }
}

impl AuditEnvelope {
    /// Serialise as a single JSON line terminated by `\n`. Returns
    /// `Err` only if serialisation fails; callers should log and
    /// continue so audit I/O cannot break request handling.
    pub fn to_jsonl(&self) -> Result<String, AuditError> {
        let mut s = serde_json::to_string(self).map_err(AuditError::Serialize)?;
        s.push('\n');
        Ok(s)
    }
}

/// Errors surfaced by sinks. The middleware logs and swallows these;
/// the request path must not fail because of audit-write failures.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit record serialization failed: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("audit sink I/O failure: {0}")]
    Io(#[source] std::io::Error),
}

/// Future returned by [`AuditSink::write`] / [`AuditSink::flush`].
/// Manually typed so the trait stays dyn-compatible without depending
/// on `async-trait` (which is a transitive, not a direct, dep).
pub type AuditFuture<'a> =
    Pin<Box<dyn std::future::Future<Output = Result<(), AuditError>> + Send + 'a>>;

/// Destination for audit records. Errors from `write` MUST never break
/// the request path: the caller logs the failure and continues serving.
///
pub trait AuditSink: Send + Sync + 'static {
    /// Write a single envelope. Implementations should be non-blocking
    /// on the request path; long I/O belongs behind an internal channel.
    fn write<'a>(&'a self, envelope: AuditEnvelope) -> AuditFuture<'a>;

    /// Best-effort flush on graceful shutdown. Idempotent.
    fn flush<'a>(&'a self) -> AuditFuture<'a>;
}

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

/// ISO-8601 with explicit millisecond precision and `Z` suffix.
/// Example: `2026-05-15T10:00:00.123Z`.
const ISO8601_MS: &[FormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

/// Format the current UTC instant per the Section 5 contract. The
/// helper is public so the middleware and tests share the same path.
#[must_use]
pub fn now_iso8601_millis() -> String {
    let now = OffsetDateTime::now_utc();
    // `format_description` `subsecond digits:3` truncates rather than
    // panicking, and the format string above does not contain any
    // tokens that can fail at formatting time. We still propagate via
    // a fallback rather than `unwrap()` to obey the project's no-panic
    // rule in non-test code.
    match now.format(ISO8601_MS) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "audit timestamp formatting failed; substituting epoch");
            "1970-01-01T00:00:00.000Z".to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Query redaction
// ---------------------------------------------------------------------------

/// Redact a URL-encoded query string into the canonical `query_params`
/// JSON shape with no field-specific hashing. Kept as a public helper
/// for tests and callers that do not have entity config context.
#[must_use]
pub fn redact_query(query: &str) -> Value {
    QueryRedactor::default().redact_query(query)
}

#[cfg(test)]
fn is_sensitive_param(name: &str) -> bool {
    redact::is_secret_param_name(name)
}

fn context_sensitive_fields(settings: &AuditSettings, context: &AuditContextExt) -> Vec<String> {
    let mut fields = Vec::new();
    for field in &settings.sensitive_fields {
        let parts = field.split(':').collect::<Vec<_>>();
        match parts.as_slice() {
            [dataset, entity, name]
                if context.dataset_id.as_deref() == Some(*dataset)
                    && context.entity_name.as_deref() == Some(*entity) =>
            {
                fields.push((*name).to_string());
            }
            [entity, name] if context.entity_name.as_deref() == Some(*entity) => {
                fields.push((*name).to_string());
            }
            [name] => fields.push((*name).to_string()),
            _ => {}
        }
    }
    fields
}

// ---------------------------------------------------------------------------
// In-memory sink (test/diagnostic helper)
// ---------------------------------------------------------------------------

/// Thread-safe in-memory sink. Useful in tests and in admin
/// diagnostics. Not intended for production use: it grows without
/// bound.
#[derive(Debug, Default, Clone)]
pub struct InMemorySink {
    inner: Arc<Mutex<Vec<String>>>,
}

impl InMemorySink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a copy of all captured lines so far.
    #[must_use]
    pub fn snapshot(&self) -> Vec<String> {
        match self.inner.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }
}

impl AuditSink for InMemorySink {
    fn write<'a>(&'a self, envelope: AuditEnvelope) -> AuditFuture<'a> {
        Box::pin(async move {
            let line = envelope.to_jsonl()?;
            match self.inner.lock() {
                Ok(mut g) => g.push(line),
                Err(p) => p.into_inner().push(line),
            }
            Ok(())
        })
    }

    fn flush<'a>(&'a self) -> AuditFuture<'a> {
        Box::pin(async move { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/// Axum `from_fn_with_state` handler that captures request metadata,
/// awaits the inner service, and emits one audit record to the
/// configured sink. Errors writing the audit record are logged via
/// `tracing::error!` and do not affect the response.
///
/// State is `Arc<dyn AuditSink>` so the same layer factory works with
/// any sink choice (stdout, file, tee, chain).
pub async fn audit_layer(
    Extension(sink): Extension<Arc<dyn AuditSink>>,
    settings: Option<Extension<AuditSettings>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let settings = settings.map(|Extension(s)| s).unwrap_or_default();
    let start = Instant::now();
    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or("").to_string();
    let headers = request.headers().clone();
    let purpose = extract_purpose(&headers);
    // `ConnectInfo` is propagated by axum when the server is started with
    // `into_make_service_with_connect_info`. In unit tests using
    // `oneshot`, no such extension is present, so we fall back to
    // unspecified. When trust-proxy support is enabled, a trusted socket
    // peer may project the first `X-Forwarded-For` address into audit.
    let remote_addr = resolve_remote_addr(
        &headers,
        request
            .extensions()
            .get::<ConnectInfo<std::net::SocketAddr>>(),
        &settings,
    )
    .to_string();

    // Adopt the upstream `x-request-id` when present so the audit
    // record's `request_id`, `tower-http`'s tracing spans, and the
    // response header propagated by `PropagateRequestIdLayer` all carry
    // the same value. Falls back to a freshly minted ULID when no
    // upstream layer set the header (e.g. unit-test `oneshot` calls).
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Ulid::new().to_string());

    // Make the id available to downstream handlers via request
    // extensions, and ensure the request header carries it for the rest
    // of the chain (covers the fallback-mint case where no upstream set
    // the header). Response-header propagation is owned by
    // `PropagateRequestIdLayer` in `crate::server`; the audit middleware
    // does not write `x-request-id` on the way out.
    let mut request = request;
    request
        .extensions_mut()
        .insert(RequestIdExt(request_id.clone()));
    if let Ok(value) = request_id.parse() {
        request.headers_mut().insert("x-request-id", value);
    }

    // Capture any principal that an outer layer may have attached to
    // the request. In the production stack (`crate::server`) audit
    // sits OUTSIDE auth, so this is `None` for protected routes and
    // the canonical read happens post-`next.run` from the response
    // extensions below. The request-side read remains as a fallback
    // for unit tests that inject a principal via an outer-to-audit
    // middleware.
    let principal_on_req = request
        .extensions()
        .get::<crate::auth::Principal>()
        .cloned();

    let response = next.run(request).await;
    let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let status_code = response.status().as_u16();
    let error_code = response
        .extensions()
        .get::<ErrorCodeExt>()
        .map(|c| c.0.clone());
    let context = response
        .extensions()
        .get::<AuditContextExt>()
        .cloned()
        .unwrap_or_else(|| infer_context_from_path(&path));
    let provenance = response
        .extensions()
        .get::<ProvenanceIssuanceExt>()
        .map(ProvenanceIssuanceRecord::from);

    // Auth middleware (inner) attaches `Principal` to the response on
    // success after the handler returns. Prefer that as the canonical
    // source; fall back to the request-side read above. When a
    // principal is present, its auth mode supplies the audit label.
    let principal = response
        .extensions()
        .get::<crate::auth::Principal>()
        .cloned()
        .or(principal_on_req);
    let principal_id = principal.as_ref().map(|p| p.principal_id.clone());
    let auth_mode = principal
        .as_ref()
        .map(|p| auth_mode_label(p.auth_mode).to_string());
    let scopes_used: Vec<String> = principal
        .as_ref()
        .map(|p| p.scopes.iter().map(|s| s.to_string()).collect())
        .unwrap_or_default();

    let endpoint_kind = classify_endpoint(&path);
    if matches!(endpoint_kind, EndpointKind::Health | EndpointKind::Ready)
        && !settings.include_health
    {
        return response;
    }

    let query_params =
        redact_query_with_sensitive_fields(&query, context_sensitive_fields(&settings, &context));

    let record = AuditRecord {
        ts: now_iso8601_millis(),
        request_id,
        principal_id,
        auth_mode,
        remote_addr,
        method,
        path,
        endpoint_kind,
        dataset_id: context.dataset_id,
        entity_name: context.entity_name,
        table_id: context.table_id,
        relationship: context.relationship,
        aggregate_id: context.aggregate_id,
        underlying_kind: context.underlying_kind,
        collection_id: context.collection_id,
        primary_key: context.primary_key,
        offering_id: context.offering_id,
        verification_id: context.verification_id,
        verification_decision: context.verification_decision,
        claim_hash: context.claim_hash,
        evidence_hash: context.evidence_hash,
        scopes_used,
        query_params,
        purpose,
        status_code,
        row_count: context.row_count,
        null_geometry_count: context.null_geometry_count,
        invalid_geometry_count: context.invalid_geometry_count,
        suppressed_groups: context.suppressed_groups,
        duration_ms,
        error_code,
        provenance,
    };

    // Fire and await the write; the sink is responsible for making
    // this cheap. We do NOT wrap in `tokio::spawn` so that ordering
    // is preserved within a single client's traffic.
    if let Err(e) = sink.write(AuditEnvelope::from(record)).await {
        // Audit failures never fail the request: log and continue.
        error!(error = %e, "audit.write_failed");
    }

    response
}

/// Marker attached to request extensions so downstream handlers (and
/// future audit-aware code paths) can read the request id without
/// reaching into the response header map.
#[derive(Debug, Clone)]
pub struct RequestIdExt(pub String);

fn extract_purpose(headers: &HeaderMap) -> Option<String> {
    headers
        .get("data-purpose")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

fn resolve_remote_addr(
    headers: &HeaderMap,
    connect_info: Option<&ConnectInfo<std::net::SocketAddr>>,
    settings: &AuditSettings,
) -> IpAddr {
    let peer = connect_info
        .map(|ConnectInfo(addr)| addr.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

    if !settings.trust_proxy_enabled || !trusted_proxy_contains(peer, &settings.trusted_proxies) {
        return peer;
    }

    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .and_then(|v| v.parse::<IpAddr>().ok())
        .unwrap_or(peer)
}

fn trusted_proxy_contains(peer: IpAddr, trusted_proxies: &[String]) -> bool {
    trusted_proxies
        .iter()
        .any(|spec| trusted_proxy_spec_matches(peer, spec))
}

fn trusted_proxy_spec_matches(peer: IpAddr, spec: &str) -> bool {
    let trimmed = spec.trim();
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return ip == peer;
    }
    let Some((addr, prefix)) = trimmed.split_once('/') else {
        return false;
    };
    let Ok(network) = addr.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match (peer, network) {
        (IpAddr::V4(peer), IpAddr::V4(network)) if prefix <= 32 => {
            let peer = u32::from(peer);
            let network = u32::from(network);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (peer & mask) == (network & mask)
        }
        (IpAddr::V6(peer), IpAddr::V6(network)) if prefix <= 128 => {
            let peer = u128::from(peer);
            let network = u128::from(network);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (peer & mask) == (network & mask)
        }
        _ => false,
    }
}

fn auth_mode_label(mode: crate::auth::AuthMode) -> &'static str {
    match mode {
        crate::auth::AuthMode::ApiKey => "api_key",
        crate::auth::AuthMode::Oidc => "oidc",
    }
}

fn classify_endpoint(path: &str) -> EndpointKind {
    if path == "/health" {
        EndpointKind::Health
    } else if path == "/ready" {
        EndpointKind::Ready
    } else if path == "/datasets" || path == "/metadata" || path.starts_with("/metadata/") {
        EndpointKind::Catalog
    } else if path.starts_with("/admin") {
        EndpointKind::Admin
    } else if path == "/openapi.json" || path.starts_with("/openapi") {
        EndpointKind::Openapi
    } else if matches!(
        path,
        "/claims"
            | "/claims/evaluate"
            | "/claims/batch-evaluate"
            | "/formats"
            | "/evidence/render"
            | "/credentials/issue"
            | "/.well-known/evidence-service"
            | "/.well-known/evidence/jwks.json"
    ) || path.starts_with("/claims/")
    {
        EndpointKind::EvidenceVerification
    } else if path.starts_with("/evidence-offerings/") {
        classify_evidence_offering_endpoint(path)
    } else if path.starts_with("/ogc/v1/") {
        classify_ogc_endpoint(path)
    } else if path.starts_with("/datasets/") {
        classify_dataset_endpoint(path)
    } else {
        EndpointKind::Other
    }
}

fn classify_evidence_offering_endpoint(path: &str) -> EndpointKind {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match segments.as_slice() {
        ["evidence-offerings", _offering, "verifications"] => EndpointKind::EvidenceVerification,
        _ => EndpointKind::Other,
    }
}

fn classify_ogc_endpoint(path: &str) -> EndpointKind {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match segments.as_slice() {
        ["ogc", "v1", "datasets", _dataset, "collections", _collection, "items"] => {
            EndpointKind::OgcCollectionItems
        }
        ["ogc", "v1", "datasets", _dataset, "collections", _collection, "items", _feature] => {
            EndpointKind::OgcFeature
        }
        _ => EndpointKind::Catalog,
    }
}

fn classify_dataset_endpoint(path: &str) -> EndpointKind {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match segments.as_slice() {
        ["datasets", _dataset] => EndpointKind::Dataset,
        ["datasets", _dataset, _entity, "schema"] => EndpointKind::Schema,
        ["datasets", _dataset, _entity, "aggregates"] => EndpointKind::AggregateList,
        ["datasets", _dataset, _entity, "aggregates", _aggregate] => EndpointKind::Aggregate,
        ["datasets", _dataset, _entity, "verify"] => EndpointKind::Verify,
        ["datasets", _dataset, _entity] => EndpointKind::Rows,
        ["datasets", _dataset, _entity, _id] => EndpointKind::Rows,
        ["datasets", _dataset, _entity, _id, _relationship] => EndpointKind::Rows,
        _ => EndpointKind::Dataset,
    }
}

fn infer_context_from_path(path: &str) -> AuditContextExt {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match segments.as_slice() {
        ["datasets", dataset] => AuditContextExt {
            dataset_id: Some((*dataset).to_string()),
            ..AuditContextExt::default()
        },
        ["datasets", dataset, entity, "aggregates"] => AuditContextExt {
            dataset_id: Some((*dataset).to_string()),
            entity_name: Some((*entity).to_string()),
            ..AuditContextExt::default()
        },
        ["datasets", dataset, entity, "aggregates", aggregate] => AuditContextExt {
            dataset_id: Some((*dataset).to_string()),
            entity_name: Some((*entity).to_string()),
            aggregate_id: Some((*aggregate).to_string()),
            ..AuditContextExt::default()
        },
        ["datasets", dataset, entity]
        | ["datasets", dataset, entity, "schema"]
        | ["datasets", dataset, entity, "verify"]
        | ["datasets", dataset, entity, _] => AuditContextExt {
            dataset_id: Some((*dataset).to_string()),
            entity_name: Some((*entity).to_string()),
            ..AuditContextExt::default()
        },
        ["datasets", dataset, entity, _id, relationship] => AuditContextExt {
            dataset_id: Some((*dataset).to_string()),
            entity_name: Some((*entity).to_string()),
            relationship: Some((*relationship).to_string()),
            ..AuditContextExt::default()
        },
        ["ogc", "v1", "datasets", dataset, "collections", collection, "items"] => AuditContextExt {
            dataset_id: Some((*dataset).to_string()),
            collection_id: Some((*collection).to_string()),
            underlying_kind: Some("entity_collection".to_string()),
            ..AuditContextExt::default()
        },
        ["ogc", "v1", "datasets", dataset, "collections", collection, "items", feature] => {
            AuditContextExt {
                dataset_id: Some((*dataset).to_string()),
                collection_id: Some((*collection).to_string()),
                primary_key: Some((*feature).to_string()),
                underlying_kind: Some("entity_record".to_string()),
                ..AuditContextExt::default()
            }
        }
        _ => AuditContextExt::default(),
    }
}

// Re-export the middleware helper at this module level for tests and
// for the server scaffold to consume without reaching into submodules.
pub use self::audit_layer as audit_middleware;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_helper_emits_24_chars_ending_in_z() {
        let s = now_iso8601_millis();
        assert_eq!(s.len(), 24, "got {s:?}");
        assert!(s.ends_with('Z'));
    }

    #[test]
    fn sensitive_names_are_case_insensitive() {
        assert!(is_sensitive_param("Token"));
        assert!(is_sensitive_param("API_KEY"));
        assert!(!is_sensitive_param("limit"));
    }

    #[test]
    fn classify_endpoint_buckets() {
        assert_eq!(classify_endpoint("/health"), EndpointKind::Health);
        assert_eq!(classify_endpoint("/ready"), EndpointKind::Ready);
        assert_eq!(classify_endpoint("/datasets"), EndpointKind::Catalog);
        assert_eq!(
            classify_endpoint("/metadata/dcat/bregdcat-ap"),
            EndpointKind::Catalog
        );
        assert_eq!(classify_endpoint("/admin/reload"), EndpointKind::Admin);
        assert_eq!(
            classify_endpoint("/ogc/v1/datasets/civic/collections/facilities/items"),
            EndpointKind::OgcCollectionItems
        );
        assert_eq!(
            classify_endpoint("/ogc/v1/datasets/civic/collections/facilities/items/FAC-1"),
            EndpointKind::OgcFeature
        );
        assert_eq!(
            classify_endpoint("/datasets/x/individual/verify"),
            EndpointKind::Verify
        );
        assert_eq!(
            classify_endpoint("/evidence-offerings/person-evidence/verifications"),
            EndpointKind::EvidenceVerification
        );
        assert_eq!(
            classify_endpoint("/claims/evaluate"),
            EndpointKind::EvidenceVerification
        );
        assert_eq!(
            classify_endpoint("/credentials/issue"),
            EndpointKind::EvidenceVerification
        );
        assert_eq!(classify_endpoint("/datasets/x/rows"), EndpointKind::Rows);
        assert_eq!(classify_endpoint("/anything-else"), EndpointKind::Other);
    }

    #[test]
    fn trusted_proxy_cidr_matching_supports_v4_and_v6() {
        assert!(trusted_proxy_spec_matches(
            "10.1.2.3".parse().unwrap(),
            "10.0.0.0/8"
        ));
        assert!(!trusted_proxy_spec_matches(
            "11.1.2.3".parse().unwrap(),
            "10.0.0.0/8"
        ));
        assert!(trusted_proxy_spec_matches(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::/32"
        ));
    }
}

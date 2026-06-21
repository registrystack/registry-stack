// SPDX-License-Identifier: Apache-2.0
//! Audit core: record schema, platform audit pipeline, and helpers.
//!
//! V1 ships the `AuditRecord` struct, stdout/file/syslog platform
//! sinks, chained envelopes, and the request-scoped middleware.
//!
//! Forward compatibility:
//! - `FileSink` and `SyslogSink` are production audit destinations.
//! - Platform audit sinks wrap the core `AuditRecord` in chained
//!   `registry-platform-audit` envelopes.
//!
//! Integration:
//! - The middleware reads `Principal` from request extensions when
//!   present and projects its identity into `principal_id`, `auth_mode`,
//!   and `scopes_used`.
//! - The error module attaches a stable error code on failure
//!   responses via the `ErrorCodeExt` response extension defined in
//!   this module; the audit middleware reads it and records it.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::Body;
use axum::extract::{ConnectInfo, Extension};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use registry_platform_ops::AuditWritePolicy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;
use tokio::sync::OnceCell;
use tracing::error;
use ulid::Ulid;

use crate::runtime_config::RuntimeSnapshot;

pub mod file;
pub mod middleware;
pub mod redact;
pub mod stdout;
pub mod syslog;

pub use file::FileSink;
pub use redact::{
    redact_query_with_secret_and_fields, redact_query_with_sensitive_fields, sensitive_value_hash,
    sensitive_value_hash_keyed, AuditHashSecret, QueryRedactor,
};
pub use registry_platform_audit::AuditKeyHasher;
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
///
/// `hash_hasher` is the per-deploy keyed hasher used for sensitive
/// audit lookup values. Production loads it through
/// `registry-platform-audit` from `audit.hash_secret_env`; tests and
/// explicit local development use `AuditKeyHasher::unkeyed_dev_only()`.
#[derive(Debug, Clone)]
pub struct AuditSettings {
    pub include_health: bool,
    pub trust_proxy_enabled: bool,
    pub trusted_proxies: Vec<String>,
    pub sensitive_fields: Vec<String>,
    pub hash_hasher: AuditKeyHasher,
    /// Behavior when the audit record write fails. `availability_first`
    /// (default) logs and continues; `fail_closed` fails the request with a
    /// stable error code.
    pub write_policy: AuditWritePolicy,
}

impl Default for AuditSettings {
    fn default() -> Self {
        Self {
            include_health: false,
            trust_proxy_enabled: false,
            trusted_proxies: Vec::new(),
            sensitive_fields: Vec::new(),
            hash_hasher: AuditKeyHasher::unkeyed_dev_only(),
            write_policy: AuditWritePolicy::AvailabilityFirst,
        }
    }
}

/// Stable error code returned when `audit.write_policy` is `fail_closed` and
/// an audit record cannot be written. Documented in `docs/configuration.md`.
pub const AUDIT_WRITE_FAILED_CODE: &str = "audit.write_failed";

/// A wrapper for sensitive string values that prints `[REDACTED]` via
/// `Debug` and `Display`, defending against accidental inclusion in logs
/// or panic messages. Convert from `String` or `&str` via `From`/`Into`.
#[derive(Clone, Default)]
pub struct Sensitive(pub String);

impl std::fmt::Debug for Sensitive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl std::fmt::Display for Sensitive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl From<String> for Sensitive {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Sensitive {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl Sensitive {
    /// Expose the raw value. Call sites must ensure the value is not logged.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
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
    pub pdp_policy_id: Option<String>,
    pub pdp_policy_hash: Option<String>,
    pub pdp_evaluated_rule_ids: Option<Vec<String>>,
    pub pdp_stable_problem_code: Option<String>,
    pub pdp_ecosystem_binding_id: Option<String>,
    pub pdp_ecosystem_binding_version: Option<String>,
    pub pdp_route_identity: Option<String>,
    pub pdp_source_binding: Option<String>,
    pub pdp_checked_scopes: Option<Vec<String>>,
    pub pdp_trust_provenance: Option<Vec<String>>,
    pub null_geometry_count: Option<u64>,
    pub invalid_geometry_count: Option<u64>,
    pub geometry_vertex_count: Option<u64>,
    pub row_count: Option<u64>,
    pub suppressed_groups: Option<u64>,
    // --- Attribute-release fields (set by the attribute-release handler) ---
    /// Profile id for this release request.
    pub ar_profile_id: Option<String>,
    /// Profile version for this release request.
    pub ar_profile_version: Option<String>,
    /// Subject id type (e.g. "national_id"). Used as part of the hash domain.
    pub ar_subject_id_type: Option<String>,
    /// Raw subject identifier. CONTEXT ONLY — never serialized into AuditRecord.
    /// Wrapped in `Sensitive` so `derive(Debug)` cannot leak it.
    pub ar_subject_id_raw: Option<Sensitive>,
    /// Claim names requested by the caller (names only, never values).
    pub ar_requested_claims: Option<Vec<String>>,
    /// Claim names actually released (names only, never values).
    pub ar_released_claims: Option<Vec<String>>,
    /// Fine-grained internal outcome label (from `ReleaseError::audit_code()`).
    pub ar_internal_outcome: Option<String>,
    /// Cardinality outcome from the subject lookup step.
    pub ar_source_cardinality_outcome: Option<String>,
    /// Availability class of the backing source.
    pub ar_source_availability_class: Option<String>,
}

/// Redacted config-governance metadata attached by admin config handlers.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigAuditExt {
    pub action: &'static str,
    pub source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    #[serde(rename = "bundle_sequence", skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    pub signer_kids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_config_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    pub product_validation_result: &'static str,
    pub apply_result: &'static str,
    pub posture_result: &'static str,
    pub applied: bool,
    pub restart_required: bool,
    pub change_classes: Vec<String>,
    pub break_glass: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub break_glass_approval_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub break_glass_approved_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub break_glass_reason_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub break_glass_emergency_change_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub break_glass_expires_at_unix_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub break_glass_rate_limit_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_approval_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_approval_approved_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_approval_reason_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_approval_change_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_approval_expires_at_unix_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_approval_rate_limit_identity: Option<String>,
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
    Rows,
    AggregateList,
    Aggregate,
    OgcEdrArea,
    OgcCollectionItems,
    OgcFeature,
    Admin,
    Openapi,
    /// Identity attribute release endpoint family (discovery + resolve).
    AttributeRelease,
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
    /// Precomputed audit hash for the internal backing table when known by the handler.
    #[serde(
        rename = "table_id_hash",
        serialize_with = "serialize_optional_table_id_hash"
    )]
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
    /// PDP policy identifier used for governed access decisions.
    pub pdp_policy_id: Option<String>,
    /// PDP policy hash used for governed access decisions.
    pub pdp_policy_hash: Option<String>,
    /// PDP rule ids evaluated for governed access decisions.
    pub pdp_evaluated_rule_ids: Option<Vec<String>>,
    /// Stable PDP denial code, present on governed denials.
    pub pdp_stable_problem_code: Option<String>,
    /// Selected governed ecosystem binding id when applicable.
    pub pdp_ecosystem_binding_id: Option<String>,
    /// Selected governed ecosystem binding version when applicable.
    pub pdp_ecosystem_binding_version: Option<String>,
    /// PDP route identity evaluated for governed access decisions.
    pub pdp_route_identity: Option<String>,
    /// PDP source binding evaluated for governed access decisions.
    pub pdp_source_binding: Option<String>,
    /// Scopes PDP was told had actually been checked.
    pub pdp_checked_scopes: Option<Vec<String>>,
    /// Redacted inventory of trust assertions PDP evaluated.
    pub pdp_trust_provenance: Option<Vec<String>>,
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
    /// Vertices in a submitted query geometry, never the raw geometry.
    pub geometry_vertex_count: Option<u64>,
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
    /// Present on governed config verify, dry-run, and apply attempts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<ConfigAuditExt>,
    // --- Attribute-release fields ---
    /// Profile id for this release request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ar_profile_id: Option<String>,
    /// Profile version for this release request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ar_profile_version: Option<String>,
    /// Subject id type (e.g. "national_id").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ar_subject_id_type: Option<String>,
    /// Keyed HMAC/SHA-256 hash of the raw subject id, scoped to the profile.
    /// The raw value is NEVER stored here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ar_subject_id_hash: Option<String>,
    /// Claim names requested by the caller (names only, never values).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ar_requested_claims: Option<Vec<String>>,
    /// Claim names actually released (names only, never values).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ar_released_claims: Option<Vec<String>>,
    /// Fine-grained internal outcome label for denied/collapsed outcomes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ar_internal_outcome: Option<String>,
    /// Cardinality outcome from the subject lookup step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ar_source_cardinality_outcome: Option<String>,
    /// Availability class of the backing source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ar_source_availability_class: Option<String>,
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

/// Errors surfaced by sinks. The middleware logs and swallows these;
/// the request path must not fail because of audit-write failures.
pub type AuditError = registry_platform_audit::AuditError;

/// A non-request operational event that still belongs in the chained audit
/// stream.
#[derive(Debug, Clone)]
pub struct OperationalAuditEvent {
    pub event: &'static str,
    pub error_code: Option<&'static str>,
    pub status_code: u16,
    pub dataset_id: Option<String>,
    pub table_id_hash: Option<String>,
}

impl OperationalAuditEvent {
    #[must_use]
    pub fn new(event: &'static str, error_code: &'static str) -> Self {
        Self {
            event,
            error_code: Some(error_code),
            status_code: 500,
            dataset_id: None,
            table_id_hash: None,
        }
    }

    #[must_use]
    pub fn success(event: &'static str) -> Self {
        Self {
            event,
            error_code: None,
            status_code: 200,
            dataset_id: None,
            table_id_hash: None,
        }
    }

    #[must_use]
    pub fn for_dataset(mut self, dataset_id: String) -> Self {
        self.dataset_id = Some(dataset_id);
        self
    }

    /// Sets a precomputed audit hash for the backing table identifier.
    ///
    /// `table_id_hash` must already use the `sha256:` or `hmac-sha256:`
    /// audit-hash format. Request handlers that have a plaintext table id
    /// should set [`AuditContextExt::table_id`] instead and let the audit
    /// middleware hash it with the configured audit hasher.
    #[must_use]
    pub fn with_table_id_hash(mut self, table_id_hash: String) -> Self {
        debug_assert!(
            is_audit_hash(&table_id_hash),
            "with_table_id_hash expects a precomputed audit hash"
        );
        self.table_id_hash = Some(table_id_hash);
        self
    }

    fn into_record(self) -> AuditRecord {
        AuditRecord {
            ts: now_iso8601_millis(),
            request_id: Ulid::new().to_string(),
            principal_id: None,
            auth_mode: None,
            remote_addr: "background".to_string(),
            method: "BACKGROUND".to_string(),
            path: format!("/__events/{}", self.event),
            endpoint_kind: EndpointKind::Other,
            dataset_id: self.dataset_id,
            entity_name: None,
            table_id: self.table_id_hash,
            relationship: None,
            aggregate_id: None,
            underlying_kind: None,
            collection_id: None,
            primary_key: None,
            offering_id: None,
            verification_id: None,
            verification_decision: None,
            claim_hash: None,
            evidence_hash: None,
            pdp_policy_id: None,
            pdp_policy_hash: None,
            pdp_evaluated_rule_ids: None,
            pdp_stable_problem_code: None,
            pdp_ecosystem_binding_id: None,
            pdp_ecosystem_binding_version: None,
            pdp_route_identity: None,
            pdp_source_binding: None,
            pdp_checked_scopes: None,
            pdp_trust_provenance: None,
            scopes_used: Vec::new(),
            query_params: json!({}),
            purpose: None,
            status_code: self.status_code,
            row_count: None,
            null_geometry_count: None,
            invalid_geometry_count: None,
            geometry_vertex_count: None,
            suppressed_groups: None,
            duration_ms: 0,
            error_code: self.error_code.map(ToString::to_string),
            provenance: None,
            config: None,
            ar_profile_id: None,
            ar_profile_version: None,
            ar_subject_id_type: None,
            ar_subject_id_hash: None,
            ar_requested_claims: None,
            ar_released_claims: None,
            ar_internal_outcome: None,
            ar_source_cardinality_outcome: None,
            ar_source_availability_class: None,
        }
    }
}

/// Chained writer for relay audit records.
///
/// Concrete sinks implement `registry-platform-audit::AuditSink`; this
/// pipeline owns the per-sink chain state, bootstraps it from the sink
/// tail on first write, and serializes relay's typed `AuditRecord` into
/// the platform envelope record body.
#[derive(Clone)]
pub struct AuditPipeline {
    sink: Arc<dyn registry_platform_audit::AuditSink>,
    chain: Arc<OnceCell<registry_platform_audit::ChainState>>,
    profile: registry_platform_audit::AuditChainProfile,
}

impl std::fmt::Debug for AuditPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditPipeline").finish_non_exhaustive()
    }
}

impl AuditPipeline {
    #[must_use]
    pub fn new(sink: Arc<dyn registry_platform_audit::AuditSink>) -> Self {
        Self::new_with_chain_profile(
            sink,
            registry_platform_audit::AuditChainProfile::dev_unkeyed(),
        )
    }

    #[must_use]
    pub fn new_with_chain_profile(
        sink: Arc<dyn registry_platform_audit::AuditSink>,
        profile: registry_platform_audit::AuditChainProfile,
    ) -> Self {
        Self {
            sink,
            chain: Arc::new(OnceCell::new()),
            profile,
        }
    }

    #[must_use]
    pub fn from_sink<S>(sink: S) -> Arc<Self>
    where
        S: registry_platform_audit::AuditSink + 'static,
    {
        Arc::new(Self::new(Arc::new(sink)))
    }

    pub async fn write_record(&self, record: AuditRecord) -> Result<(), AuditError> {
        let chain = self
            .chain
            .get_or_try_init(|| async {
                self.profile
                    .bootstrap_or_start_empty(self.sink.as_ref())
                    .await
            })
            .await?;
        chain.append(self.sink.as_ref(), record).await?;
        Ok(())
    }

    pub async fn write_operational_event(
        &self,
        event: OperationalAuditEvent,
    ) -> Result<(), AuditError> {
        self.write_record(event.into_record()).await
    }

    /// Best-effort flush hook kept for shutdown symmetry. Platform
    /// sinks flush per write today, so there is no additional work.
    pub async fn flush(&self) -> Result<(), AuditError> {
        Ok(())
    }
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

#[async_trait::async_trait]
impl registry_platform_audit::AuditSink for InMemorySink {
    async fn write(
        &self,
        envelope: &registry_platform_audit::AuditEnvelope,
    ) -> Result<(), AuditError> {
        let line = envelope.to_jsonl()?;
        match self.inner.lock() {
            Ok(mut g) => g.push(line),
            Err(p) => p.into_inner().push(line),
        }
        Ok(())
    }

    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        self.tail_hash_with_hasher(&registry_platform_audit::AuditChainHasher::unkeyed_dev_only())
            .await
    }

    async fn tail_hash_with_hasher(
        &self,
        hasher: &registry_platform_audit::AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        let lines = self.snapshot();
        if lines.is_empty() {
            return Ok(None);
        }
        let verification =
            registry_platform_audit::verify_jsonl_lines_with_hasher(lines.iter(), hasher)
                .map_err(AuditError::ChainVerification)?;
        Ok(verification.last_hash)
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
/// State is `Arc<AuditPipeline>` so the same layer factory works with
/// any sink choice (stdout, file, tee, chain).
pub async fn audit_layer(
    runtime: RuntimeSnapshot,
    settings: Option<Extension<AuditSettings>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(sink) = runtime.audit_sink() else {
        error!("audit pipeline unavailable in request runtime");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
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
    // unspecified. When trust-proxy support is enabled and the socket peer
    // is trusted, audit records the rightmost `X-Forwarded-For` hop that is
    // not itself a trusted proxy, falling back to the socket peer when every
    // hop in the chain is trusted.
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
    let inferred_context = infer_context_from_path(&path);
    let context = response
        .extensions()
        .get::<AuditContextExt>()
        .cloned()
        .map(|context| merge_inferred_context(context, inferred_context.clone()))
        .unwrap_or(inferred_context);
    let provenance = response
        .extensions()
        .get::<ProvenanceIssuanceExt>()
        .map(ProvenanceIssuanceRecord::from);
    let config_audit = response.extensions().get::<ConfigAuditExt>().cloned();

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

    let query_params = redact_query_with_secret_and_fields(
        settings.hash_hasher.clone(),
        &query,
        context_sensitive_fields(&settings, &context),
    );
    let primary_key = audit_primary_key_hash(&context, &settings.hash_hasher);
    let table_id_hash = audit_table_id_hash(&context, &settings.hash_hasher);
    let record_path = audit_path(&path, &context, endpoint_kind);

    // Compute the keyed subject hash for attribute-release requests.
    // The raw value must NEVER be written to the record or logged here.
    let ar_subject_id_hash = audit_ar_subject_id_hash(&context, &settings.hash_hasher);

    let record = AuditRecord {
        ts: now_iso8601_millis(),
        request_id,
        principal_id,
        auth_mode,
        remote_addr,
        method,
        path: record_path,
        endpoint_kind,
        dataset_id: context.dataset_id,
        entity_name: context.entity_name,
        table_id: table_id_hash,
        relationship: context.relationship,
        aggregate_id: context.aggregate_id,
        underlying_kind: context.underlying_kind,
        collection_id: context.collection_id,
        primary_key,
        offering_id: context.offering_id,
        verification_id: context.verification_id,
        verification_decision: context.verification_decision,
        claim_hash: context.claim_hash,
        evidence_hash: context.evidence_hash,
        pdp_policy_id: context.pdp_policy_id,
        pdp_policy_hash: context.pdp_policy_hash,
        pdp_evaluated_rule_ids: context.pdp_evaluated_rule_ids,
        pdp_stable_problem_code: context.pdp_stable_problem_code,
        pdp_ecosystem_binding_id: context.pdp_ecosystem_binding_id,
        pdp_ecosystem_binding_version: context.pdp_ecosystem_binding_version,
        pdp_route_identity: context.pdp_route_identity,
        pdp_source_binding: context.pdp_source_binding,
        pdp_checked_scopes: context.pdp_checked_scopes,
        pdp_trust_provenance: context.pdp_trust_provenance,
        scopes_used,
        query_params,
        purpose,
        status_code,
        row_count: context.row_count,
        null_geometry_count: context.null_geometry_count,
        invalid_geometry_count: context.invalid_geometry_count,
        geometry_vertex_count: context.geometry_vertex_count,
        suppressed_groups: context.suppressed_groups,
        duration_ms,
        error_code,
        provenance,
        config: config_audit,
        ar_profile_id: context.ar_profile_id,
        ar_profile_version: context.ar_profile_version,
        ar_subject_id_type: context.ar_subject_id_type,
        ar_subject_id_hash,
        ar_requested_claims: context.ar_requested_claims,
        ar_released_claims: context.ar_released_claims,
        ar_internal_outcome: context.ar_internal_outcome,
        ar_source_cardinality_outcome: context.ar_source_cardinality_outcome,
        ar_source_availability_class: context.ar_source_availability_class,
    };

    // Fire and await the write; the sink is responsible for making
    // this cheap. We do NOT wrap in `tokio::spawn` so that ordering
    // is preserved within a single client's traffic.
    if let Err(e) = sink.write_record(record).await {
        error!(error = %e, "audit.write_failed");
        // Under the default `availability_first` policy, audit failures never
        // fail the request: the error is logged and the original response is
        // returned unchanged. Under `fail_closed`, the request fails with a
        // stable error code so no outcome is returned without a durable audit
        // record.
        if settings.write_policy == AuditWritePolicy::FailClosed {
            return audit_write_failed_response();
        }
    }

    response
}

/// Stable `fail_closed` response: a 503 problem+json carrying the
/// [`AUDIT_WRITE_FAILED_CODE`] error code. The code is also attached as a
/// response extension so downstream layers (and operational logging) see the
/// same stable value.
pub fn audit_write_failed_response() -> Response {
    let body = json!({
        "type": format!("{}audit/write_failed", crate::error::PROBLEM_TYPE_BASE),
        "title": "Audit record write failed",
        "status": 503,
        "code": AUDIT_WRITE_FAILED_CODE,
        "detail": "the request was not completed because its audit record could not be written",
    });
    let mut response = (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/problem+json"),
    );
    response
        .extensions_mut()
        .insert(ErrorCodeExt(AUDIT_WRITE_FAILED_CODE.to_string()));
    response
}

fn merge_inferred_context(
    mut context: AuditContextExt,
    inferred: AuditContextExt,
) -> AuditContextExt {
    if context.dataset_id.is_none() {
        context.dataset_id = inferred.dataset_id;
    }
    if context.entity_name.is_none() {
        context.entity_name = inferred.entity_name;
    }
    if context.relationship.is_none() {
        context.relationship = inferred.relationship;
    }
    if context.aggregate_id.is_none() {
        context.aggregate_id = inferred.aggregate_id;
    }
    if context.underlying_kind.is_none() {
        context.underlying_kind = inferred.underlying_kind;
    }
    if context.collection_id.is_none() {
        context.collection_id = inferred.collection_id;
    }
    if context.primary_key.is_none() {
        context.primary_key = inferred.primary_key;
    }
    context
}

fn audit_primary_key_hash(context: &AuditContextExt, hasher: &AuditKeyHasher) -> Option<String> {
    let value = context.primary_key.as_deref()?;
    Some(sensitive_value_hash_keyed(
        hasher,
        &primary_key_hash_field(context),
        value,
    ))
}

fn audit_table_id_hash(context: &AuditContextExt, hasher: &AuditKeyHasher) -> Option<String> {
    let value = context.table_id.as_deref()?;
    Some(sensitive_value_hash_keyed(
        hasher,
        &table_id_hash_field(context),
        value,
    ))
}

/// Compute a profile-scoped keyed hash of the raw subject id for attribute-release
/// audit records. Returns `None` when any of the three required context fields
/// (`ar_subject_id_raw`, `ar_profile_id`, `ar_subject_id_type`) is absent.
///
/// The hash field domain is `"ar_subject_id:{profile_id}:{id_type}"` which
/// prevents cross-profile collisions for the same raw subject value.
fn audit_ar_subject_id_hash(context: &AuditContextExt, hasher: &AuditKeyHasher) -> Option<String> {
    let raw = context.ar_subject_id_raw.as_ref()?.as_str();
    let profile_id = context.ar_profile_id.as_deref()?;
    let id_type = context.ar_subject_id_type.as_deref()?;
    let field = format!("ar_subject_id:{profile_id}:{id_type}");
    Some(sensitive_value_hash_keyed(hasher, &field, raw))
}

fn serialize_optional_table_id_hash<S>(
    value: &Option<String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value.as_deref() {
        Some(value) if is_audit_hash(value) => serializer.serialize_some(value),
        Some(_) => Err(serde::ser::Error::custom(
            "table_id must be pre-hashed before audit record serialization",
        )),
        None => serializer.serialize_none(),
    }
}

fn is_audit_hash(value: &str) -> bool {
    value.starts_with("sha256:") || value.starts_with("hmac-sha256:")
}

fn table_id_hash_field(context: &AuditContextExt) -> String {
    let mut field = String::from("table_id");
    if let Some(dataset_id) = context.dataset_id.as_deref().filter(|s| !s.is_empty()) {
        field.push(':');
        field.push_str(dataset_id);
    }
    if let Some(entity_or_collection) = context
        .entity_name
        .as_deref()
        .or(context.collection_id.as_deref())
        .filter(|s| !s.is_empty())
    {
        field.push(':');
        field.push_str(entity_or_collection);
    }
    field
}

fn primary_key_hash_field(context: &AuditContextExt) -> String {
    let mut field = String::from("primary_key");
    if let Some(dataset_id) = context.dataset_id.as_deref().filter(|s| !s.is_empty()) {
        field.push(':');
        field.push_str(dataset_id);
    }
    if let Some(entity_or_collection) = context
        .entity_name
        .as_deref()
        .or(context.collection_id.as_deref())
        .filter(|s| !s.is_empty())
    {
        field.push(':');
        field.push_str(entity_or_collection);
    }
    field
}

fn audit_path(path: &str, context: &AuditContextExt, endpoint_kind: EndpointKind) -> String {
    if context.primary_key.is_none()
        && !matches!(endpoint_kind, EndpointKind::Rows | EndpointKind::OgcFeature)
    {
        return path.to_string();
    }

    redacted_single_record_path(path).unwrap_or_else(|| path.to_string())
}

fn redacted_single_record_path(path: &str) -> Option<String> {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match segments.as_slice() {
        ["v1", "datasets", dataset, "entities", entity, "records", id]
            if !dataset.is_empty()
                && !entity.is_empty()
                && !id.is_empty()
                && *id != "schema"
                && *id != "verify" =>
        {
            Some(format!(
                "/v1/datasets/{dataset}/entities/{entity}/records/{{id}}"
            ))
        }
        [
            "v1",
            "datasets",
            dataset,
            "entities",
            entity,
            "records",
            id,
            "relationships",
            relationship,
        ]
            if !dataset.is_empty()
                && !entity.is_empty()
                && !id.is_empty()
                && !relationship.is_empty() =>
        {
            Some(format!(
                "/v1/datasets/{dataset}/entities/{entity}/records/{{id}}/relationships/{relationship}"
            ))
        }
        ["ogc", "v1", "datasets", dataset, "collections", collection, "items", feature]
            if !dataset.is_empty() && !collection.is_empty() && !feature.is_empty() =>
        {
            Some(format!(
                "/ogc/v1/datasets/{dataset}/collections/{collection}/items/{{feature_id}}"
            ))
        }
        _ => None,
    }
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
        .map(str::trim)
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

    x_forwarded_for_chain(headers)
        .map(|mut chain| {
            chain.push(peer);
            chain
                .iter()
                .rev()
                .find(|hop| !trusted_proxy_contains(**hop, &settings.trusted_proxies))
                .copied()
                .unwrap_or(peer)
        })
        .unwrap_or(peer)
}

fn x_forwarded_for_chain(headers: &HeaderMap) -> Option<Vec<IpAddr>> {
    let mut chain = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        let value = value.to_str().ok()?;
        for hop in value.split(',') {
            let hop = hop.trim();
            if hop.is_empty() {
                return None;
            }
            chain.push(hop.parse::<IpAddr>().ok()?);
        }
    }
    if chain.is_empty() {
        None
    } else {
        Some(chain)
    }
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
    if path == "/healthz" {
        EndpointKind::Health
    } else if path == "/ready" {
        EndpointKind::Ready
    } else if path == "/v1/datasets" || path == "/metadata" || path.starts_with("/metadata/") {
        EndpointKind::Catalog
    } else if path.starts_with("/admin") {
        EndpointKind::Admin
    } else if path == "/openapi.json" || path.starts_with("/openapi") {
        EndpointKind::Openapi
    } else if path.starts_with("/ogc/edr/v1/") {
        classify_edr_endpoint(path)
    } else if path.starts_with("/ogc/v1/") {
        classify_ogc_endpoint(path)
    } else if path.starts_with("/v1/attribute-releases") {
        EndpointKind::AttributeRelease
    } else if path.starts_with("/v1/datasets/") {
        classify_dataset_endpoint(path)
    } else {
        EndpointKind::Other
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

fn classify_edr_endpoint(path: &str) -> EndpointKind {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match segments.as_slice() {
        ["ogc", "edr", "v1", "collections", _collection, "area"] => EndpointKind::OgcEdrArea,
        _ => EndpointKind::Catalog,
    }
}

fn classify_dataset_endpoint(path: &str) -> EndpointKind {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match segments.as_slice() {
        ["v1", "datasets", _dataset] => EndpointKind::Dataset,
        ["v1", "datasets", _dataset, "entities", _entity, "schema"] => EndpointKind::Schema,
        ["v1", "datasets", _dataset, "aggregates"] => EndpointKind::AggregateList,
        ["v1", "datasets", _dataset, "aggregates", _aggregate]
        | ["v1", "datasets", _dataset, "aggregates", _aggregate, "query"] => {
            EndpointKind::Aggregate
        }
        ["v1", "datasets", _dataset, "aggregates", _aggregate, "metadata"] => {
            EndpointKind::AggregateList
        }
        ["v1", "datasets", _dataset, "entities", _entity, "records"] => EndpointKind::Rows,
        ["v1", "datasets", _dataset, "entities", _entity, "records", _id] => EndpointKind::Rows,
        ["v1", "datasets", _dataset, "entities", _entity, "records", _id, "relationships", _relationship] => {
            EndpointKind::Rows
        }
        _ => EndpointKind::Dataset,
    }
}

fn infer_context_from_path(path: &str) -> AuditContextExt {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match segments.as_slice() {
        ["v1", "datasets", dataset] => AuditContextExt {
            dataset_id: Some((*dataset).to_string()),
            ..AuditContextExt::default()
        },
        ["v1", "datasets", dataset, "aggregates"] => AuditContextExt {
            dataset_id: Some((*dataset).to_string()),
            ..AuditContextExt::default()
        },
        ["v1", "datasets", dataset, "aggregates", aggregate]
        | ["v1", "datasets", dataset, "aggregates", aggregate, "query"]
        | ["v1", "datasets", dataset, "aggregates", aggregate, "metadata"] => AuditContextExt {
            dataset_id: Some((*dataset).to_string()),
            aggregate_id: Some((*aggregate).to_string()),
            ..AuditContextExt::default()
        },
        ["v1", "datasets", dataset, "entities", entity, "records"]
        | ["v1", "datasets", dataset, "entities", entity, "schema"] => AuditContextExt {
            dataset_id: Some((*dataset).to_string()),
            entity_name: Some((*entity).to_string()),
            ..AuditContextExt::default()
        },
        ["v1", "datasets", dataset, "entities", entity, "records", id] => AuditContextExt {
            dataset_id: Some((*dataset).to_string()),
            entity_name: Some((*entity).to_string()),
            primary_key: Some((*id).to_string()),
            ..AuditContextExt::default()
        },
        ["v1", "datasets", dataset, "entities", entity, "records", id, "relationships", relationship] => {
            AuditContextExt {
                dataset_id: Some((*dataset).to_string()),
                entity_name: Some((*entity).to_string()),
                primary_key: Some((*id).to_string()),
                relationship: Some((*relationship).to_string()),
                ..AuditContextExt::default()
            }
        }
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

/// Public wrapper around `classify_endpoint` exposed for integration tests.
/// Not part of the stable API surface; callers should use `EndpointKind`
/// directly for production logic.
#[doc(hidden)]
#[must_use]
pub fn classify_endpoint_pub(path: &str) -> EndpointKind {
    classify_endpoint(path)
}

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
        assert_eq!(classify_endpoint("/healthz"), EndpointKind::Health);
        assert_eq!(classify_endpoint("/ready"), EndpointKind::Ready);
        assert_eq!(classify_endpoint("/v1/datasets"), EndpointKind::Catalog);
        assert_eq!(
            classify_endpoint("/metadata/dcat/bregdcat-ap"),
            EndpointKind::Catalog
        );
        assert_eq!(classify_endpoint("/admin/v1/reload"), EndpointKind::Admin);
        assert_eq!(
            classify_endpoint("/ogc/v1/datasets/civic/collections/facilities/items"),
            EndpointKind::OgcCollectionItems
        );
        assert_eq!(
            classify_endpoint("/ogc/v1/datasets/civic/collections/facilities/items/FAC-1"),
            EndpointKind::OgcFeature
        );
        // The native verify route is not mounted anywhere; its path must
        // fall back to the generic dataset bucket instead of a dedicated kind.
        assert_eq!(
            classify_endpoint("/v1/datasets/x/entities/individual/verify"),
            EndpointKind::Dataset
        );
        assert_eq!(
            classify_endpoint("/evidence-offerings/person-evidence/verifications"),
            EndpointKind::Other
        );
        assert_eq!(classify_endpoint("/claims/evaluate"), EndpointKind::Other);
        assert_eq!(classify_endpoint("/credentials/issue"), EndpointKind::Other);
        assert_eq!(
            classify_endpoint("/v1/datasets/x/entities/rows/records"),
            EndpointKind::Rows
        );
        assert_eq!(classify_endpoint("/anything-else"), EndpointKind::Other);
    }

    #[test]
    fn measures_and_dimensions_routes_classify_as_dataset() {
        // /v1/datasets/{id}/measures and /v1/datasets/{id}/dimensions have no
        // dedicated EndpointKind variant; they fall through classify_dataset_endpoint's
        // wildcard arm and land in Dataset. Pin this so a future refactor cannot
        // silently drop them into Other.
        assert_eq!(
            classify_endpoint("/v1/datasets/hdx/measures"),
            EndpointKind::Dataset
        );
        assert_eq!(
            classify_endpoint("/v1/datasets/hdx/measures/population"),
            EndpointKind::Dataset
        );
        assert_eq!(
            classify_endpoint("/v1/datasets/hdx/dimensions"),
            EndpointKind::Dataset
        );
        assert_eq!(
            classify_endpoint("/v1/datasets/hdx/dimensions/region"),
            EndpointKind::Dataset
        );
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

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
//!   and privacy-preserving `scopes_used`.
//! - The error module attaches a stable error code on failure
//!   responses via the `ErrorCodeExt` response extension defined in
//!   this module; the audit middleware reads it and records it.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::Body;
use axum::extract::{ConnectInfo, Extension, MatchedPath};
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

use crate::auth::scopes::{
    format_trust_context_scope, parse_trust_context_scope, ParsedTrustContextScope,
};
use crate::consultation::{
    ConsultationDenialReason, ConsultationDenialRecorded, ConsultationDenialRoute,
};
use crate::error::{ConsultationError, Error};
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
    /// Behavior when the audit record write fails. `fail_closed` is the
    /// default; `availability_first` is an explicit best-effort opt-out.
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
            write_policy: AuditWritePolicy::FailClosed,
        }
    }
}

/// Stable error code returned when `audit.write_policy` is `fail_closed` and
/// an audit record cannot be written. Documented in `docs/configuration.md`.
pub const AUDIT_WRITE_FAILED_CODE: &str = "audit.write_failed";

const TRUST_SCOPE_HASH_FIELD_PREFIX: &str = "trust_scope:";

fn scopes_used_for_audit(
    principal: Option<&crate::auth::Principal>,
    hasher: &AuditKeyHasher,
) -> Option<Vec<String>> {
    let Some(principal) = principal else {
        return Some(Vec::new());
    };
    principal
        .scopes
        .iter()
        .map(|scope| redact_scope_for_audit(scope, hasher))
        .collect()
}

fn redact_scope_for_audit(scope: &str, hasher: &AuditKeyHasher) -> Option<String> {
    let (field, value) = match parse_trust_context_scope(scope) {
        ParsedTrustContextScope::NotReserved => return Some(scope.to_string()),
        ParsedTrustContextScope::Malformed => return None,
        ParsedTrustContextScope::Canonical { field, value } => (field, value),
    };
    if !matches!(hasher, AuditKeyHasher::Keyed(_)) {
        return None;
    }
    let hash_field = format!("{TRUST_SCOPE_HASH_FIELD_PREFIX}{}", field.as_str());
    let handle = sensitive_value_hash_keyed(hasher, &hash_field, value);
    debug_assert!(handle.starts_with("hmac-sha256:"));
    format_trust_context_scope(field, &handle)
}

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
    pub previous_hash_matched: Option<bool>,
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
    /// Scopes present on the authenticated principal, in stable scope-set order.
    /// Exact-value trust scopes use canonical
    /// `registry:trust:<field>:hmac-sha256:<digest>` handles so their raw values
    /// are not disclosed while their authorization evidence remains linkable
    /// under the deployment audit key.
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
    pub config: Option<ConfigAuditExt>,
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
            config: None,
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
            config: None,
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

    #[must_use]
    pub fn with_config(mut self, config: ConfigAuditExt) -> Self {
        self.config = Some(config);
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
            config: self.config,
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

/// Stable readiness code reported by `/ready` when the retained audit chain
/// failed startup verification and needs operator recovery (#196). Documented
/// alongside [`AUDIT_WRITE_FAILED_CODE`].
pub const AUDIT_CHAIN_INCONSISTENT_CODE: &str = "audit.chain.inconsistent";

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
    tail_init_in_progress: Arc<std::sync::atomic::AtomicBool>,
    /// Retained-chain integrity health, reflected in `/ready` (#196, #299).
    /// Starts healthy and permanently flips to `false` when startup verification
    /// or a write-time tail self-check finds the chain inconsistent. The brick
    /// then surfaces as an actionable readiness signal instead of a confusing
    /// per-request 503.
    chain_healthy: Arc<std::sync::atomic::AtomicBool>,
}

struct TailInitReset(Arc<std::sync::atomic::AtomicBool>);

impl Drop for TailInitReset {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
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
            tail_init_in_progress: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            chain_healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
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
        let result = async {
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
        .await;
        self.mark_chain_unhealthy_on_integrity_error(&result);
        result
    }

    /// Return the live keyed chain tail used to bind an off-host ack cursor
    /// without letting a cold bootstrap or stalled append block public probes.
    pub async fn current_tail_hash_bounded(&self) -> Option<[u8; 32]> {
        const DEADLINE: std::time::Duration = std::time::Duration::from_millis(500);
        if let Some(chain) = self.chain.get() {
            return chain.try_last_hash().flatten();
        }
        if self
            .tail_init_in_progress
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }
        let pipeline = self.clone();
        let worker = tokio::spawn(async move {
            let _reset = TailInitReset(Arc::clone(&pipeline.tail_init_in_progress));
            let result = pipeline
                .chain
                .get_or_try_init(|| async {
                    pipeline
                        .profile
                        .bootstrap_or_start_empty(pipeline.sink.as_ref())
                        .await
                })
                .await
                .map(|chain| chain.try_last_hash().flatten());
            result
        });
        match tokio::time::timeout(DEADLINE, worker).await {
            Ok(Ok(Ok(tail))) => tail,
            Ok(Ok(Err(error))) => {
                tracing::error!(error = %error, "failed to read current audit chain tail");
                None
            }
            Ok(Err(error)) => {
                tracing::error!(error = %error, "audit chain tail worker failed");
                None
            }
            Err(_) => None,
        }
    }

    /// Eagerly bootstrap and verify the retained chain at startup (#196).
    ///
    /// On an integrity failure the pipeline is marked unhealthy so
    /// `/ready` reports not-ready ([`AUDIT_CHAIN_INCONSISTENT_CODE`]); startup
    /// is intentionally NOT aborted, so a bricked chain becomes an actionable
    /// readiness signal (recover with `registry-relay audit quarantine`) rather
    /// than a boot crash-loop. Transient non-verification errors (e.g. I/O) do
    /// not flip readiness. Returns the bootstrap result for the caller to log.
    pub async fn verify_chain_eager(&self) -> Result<(), AuditError> {
        let result = self
            .chain
            .get_or_try_init(|| async {
                self.profile
                    .bootstrap_or_start_empty(self.sink.as_ref())
                    .await
            })
            .await
            .map(|_| ());
        self.mark_chain_unhealthy_on_integrity_error(&result);
        result
    }

    fn mark_chain_unhealthy_on_integrity_error(&self, result: &Result<(), AuditError>) {
        if matches!(
            result,
            Err(AuditError::ChainForkDetected { .. } | AuditError::ChainVerification(_))
        ) {
            // This is a one-way latch for the process lifetime. Repair requires
            // operator recovery and a restarted process, never an automatic
            // readiness transition after a later successful operation.
            self.chain_healthy
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Whether the retained chain has remained consistent for this process
    /// lifetime. `/ready` reports not-ready when this is `false`.
    #[must_use]
    pub fn chain_healthy(&self) -> bool {
        self.chain_healthy.load(std::sync::atomic::Ordering::SeqCst)
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
    let consultation_route = consultation_audit_route(&request);
    let consultation_service = consultation_route.and_then(|_| runtime.consultation());
    let Some(sink) = runtime.audit_sink() else {
        error!("audit pipeline unavailable in request runtime");
        return audit_failure_response(consultation_service.is_some());
    };
    let settings = settings.map(|Extension(s)| s).unwrap_or_default();
    let start = Instant::now();
    let method = request.method().as_str().to_string();
    let path = consultation_route
        .map(ConsultationDenialRoute::as_str)
        .unwrap_or_else(|| request.uri().path())
        .to_string();
    let query = if consultation_route.is_some() {
        String::new()
    } else {
        request.uri().query().unwrap_or("").to_string()
    };
    // Consultation purpose is request data until the dedicated service has
    // canonicalized and authorized it. Its durable state-plane audit owns the
    // canonical value; the generic HTTP record must never retain the raw
    // header, path segments, or query supplied before that boundary.
    // Extract only the bounded audit inputs needed after the inner service.
    // Never retain a cloned HeaderMap containing bearer tokens or cookies
    // across `next.run`.
    let (purpose, remote_addr, request_id) = {
        let headers = request.headers();
        let purpose = if consultation_route.is_some() {
            None
        } else {
            extract_purpose(headers)
        };
        // `ConnectInfo` is propagated by axum when the server is started with
        // `into_make_service_with_connect_info`. In unit tests using
        // `oneshot`, no such extension is present, so we fall back to
        // unspecified. When trust-proxy support is enabled and the socket peer
        // is trusted, audit records the rightmost `X-Forwarded-For` hop that is
        // not itself a trusted proxy, falling back to the socket peer when every
        // hop in the chain is trusted.
        let remote_addr = crate::net::resolve_remote_addr(
            headers,
            request
                .extensions()
                .get::<ConnectInfo<std::net::SocketAddr>>(),
            settings.trust_proxy_enabled,
            &settings.trusted_proxies,
        )
        .to_string();
        // Adopt the upstream `x-request-id` when present so the audit record,
        // trace span, and propagated response header share one value.
        let request_id = headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| Ulid::new().to_string());
        (purpose, remote_addr, request_id)
    };

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
    let principal_on_req = if consultation_route.is_some() {
        None
    } else {
        request
            .extensions()
            .get::<crate::auth::Principal>()
            .cloned()
    };

    let mut response = next.run(request).await;
    if consultation_route.is_some() {
        // Auth attaches this response extension for the outer audit layer.
        // Consultation audit deliberately does not consume it, so drop the
        // raw principal and scopes before any durable denial await.
        response.extensions_mut().remove::<crate::auth::Principal>();
    }
    if let Some(route) = consultation_route {
        if let (Some(service), Some(reason)) = (
            consultation_service.as_ref(),
            pending_consultation_denial(&response),
        ) {
            let status = response.status();
            if service
                .record_denial(route, status.as_u16(), reason)
                .await
                .is_err()
            {
                response = consultation_unavailable_response();
            }
        }
    }
    let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let status_code = response.status().as_u16();
    // A successful execute response can only be assembled after the
    // consultation state plane has durably completed the exact attempt. The
    // generic HTTP audit pipeline is an operational export at that point. Its
    // failure must not replace the authoritative result with a retryable 503
    // that could repeat a protected source effect.
    let authoritative_consultation_completion =
        preserves_authoritative_consultation_completion(consultation_route, response.status());
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
    let config_audit = response.extensions().get::<ConfigAuditExt>().cloned();

    // Auth middleware (inner) attaches `Principal` to the response on
    // success after the handler returns. Prefer that as the canonical
    // source; fall back to the request-side read above. When a
    // principal is present, its auth mode supplies the audit label.
    let principal = if consultation_route.is_some() {
        None
    } else {
        response
            .extensions()
            .get::<crate::auth::Principal>()
            .cloned()
            .or(principal_on_req)
    };
    // The generic layer cannot prove the fixed authorized consultation workload. Never retain
    // an unrelated or attacker-selected OIDC principal/scope on consultation
    // traffic; the dedicated durable consultation audit owns verified
    // workload identity after exact binding.
    let principal_id = if consultation_route.is_some() {
        None
    } else {
        principal.as_ref().map(|p| p.principal_id.clone())
    };
    let auth_mode = if consultation_route.is_some() {
        None
    } else {
        principal
            .as_ref()
            .map(|p| auth_mode_label(p.auth_mode).to_string())
    };
    let endpoint_kind = classify_endpoint(&path);
    // Readiness is never self-audited. Evidence-grade shipping requires the
    // cursor watermark to equal the live audit tail, so appending the probe
    // after that comparison would make every successful probe invalidate the
    // next one. `include_health` continues to control liveness records.
    if endpoint_kind == EndpointKind::Ready
        || (endpoint_kind == EndpointKind::Health && !settings.include_health)
    {
        return response;
    }

    let scopes_used = if consultation_route.is_some() {
        Vec::new()
    } else {
        match scopes_used_for_audit(principal.as_ref(), &settings.hash_hasher) {
            Some(scopes) => scopes,
            None => {
                error!("audit trust-scope redaction requires a keyed hasher and a canonical scope");
                return audit_write_failed_response();
            }
        }
    };

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
        // Under explicit `availability_first`, audit failures never fail the
        // request: the error is logged and the original response is returned
        // unchanged. Under the default `fail_closed`, the request fails with a
        // stable error code so no outcome is returned without a durable audit
        // record.
        if settings.write_policy == AuditWritePolicy::FailClosed
            && !authoritative_consultation_completion
        {
            return audit_failure_response(consultation_service.is_some());
        }
    }

    response
}

fn preserves_authoritative_consultation_completion(
    route: Option<ConsultationDenialRoute>,
    status: StatusCode,
) -> bool {
    route == Some(ConsultationDenialRoute::Execute) && status.is_success()
}

fn pending_consultation_denial(response: &Response) -> Option<ConsultationDenialReason> {
    if response
        .extensions()
        .get::<ConsultationDenialRecorded>()
        .is_some()
    {
        return None;
    }
    consultation_denial_reason(
        response.status(),
        response
            .extensions()
            .get::<ErrorCodeExt>()
            .map(|code| code.0.as_str()),
    )
}

fn consultation_denial_reason(
    status: StatusCode,
    stable_error_code: Option<&str>,
) -> Option<ConsultationDenialReason> {
    if !status.is_client_error() {
        return None;
    }
    let code_reason = match stable_error_code {
        Some(
            "auth.invalid_credentials"
            | "auth.missing_credential"
            | "auth.invalid_credential"
            | "auth.malformed_credential"
            | "auth.token_expired"
            | "auth.token_not_yet_valid"
            | "auth.token_signature_invalid"
            | "auth.issuer_mismatch"
            | "auth.audience_mismatch"
            | "auth.kid_unknown"
            | "auth.algorithm_not_allowed",
        ) => Some(ConsultationDenialReason::InvalidCredentials),
        Some("consultation.invalid_request" | "auth.purpose_required") => {
            Some(ConsultationDenialReason::InvalidRequest)
        }
        Some(
            "consultation.denied"
            | "auth.scope_denied"
            | "auth.purpose_denied"
            | "auth.admin_required"
            | "auth.client_not_allowed",
        ) => Some(ConsultationDenialReason::Denied),
        Some("consultation.profile_not_found") => Some(ConsultationDenialReason::NotFound),
        Some("consultation.rate_limited" | "auth.rate_limited") => {
            Some(ConsultationDenialReason::RateLimited)
        }
        _ => None,
    };
    code_reason
        .filter(|reason| reason.accepts_status(status.as_u16()))
        .or(match status {
            // These statuses can be emitted by unrelated handler or transport
            // code. Durable classification requires the stable consultation
            // or auth code above, never status alone.
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS => {
                None
            }
            StatusCode::NOT_FOUND => Some(ConsultationDenialReason::NotFound),
            _ => Some(ConsultationDenialReason::InvalidRequest),
        })
}

fn audit_failure_response(consultation_service_active: bool) -> Response {
    if consultation_service_active {
        consultation_unavailable_response()
    } else {
        audit_write_failed_response()
    }
}

fn consultation_unavailable_response() -> Response {
    let mut response = Error::from(ConsultationError::Unavailable).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-store"),
    );
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

fn consultation_audit_route(request: &Request<Body>) -> Option<ConsultationDenialRoute> {
    match request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
    {
        Some(crate::api::consultation::PROFILE_ROUTE) => Some(ConsultationDenialRoute::Profile),
        Some(crate::api::consultation::EXECUTE_ROUTE) => Some(ConsultationDenialRoute::Execute),
        _ if is_consultation_path(request.uri().path()) => Some(ConsultationDenialRoute::Unmatched),
        _ => None,
    }
}

fn is_consultation_path(path: &str) -> bool {
    path == "/v1/consultations" || path.starts_with("/v1/consultations/")
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

    #[derive(Clone)]
    struct SlowTailSink {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        started: Arc<tokio::sync::Semaphore>,
        release: Arc<tokio::sync::Semaphore>,
    }

    impl Default for SlowTailSink {
        fn default() -> Self {
            Self {
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                started: Arc::new(tokio::sync::Semaphore::new(0)),
                release: Arc::new(tokio::sync::Semaphore::new(0)),
            }
        }
    }

    #[async_trait::async_trait]
    impl registry_platform_audit::AuditSink for SlowTailSink {
        async fn write(
            &self,
            _envelope: &registry_platform_audit::AuditEnvelope,
        ) -> Result<(), AuditError> {
            Ok(())
        }

        async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(None)
        }

        async fn tail_hash_with_hasher(
            &self,
            _hasher: &registry_platform_audit::AuditChainHasher,
        ) -> Result<Option<[u8; 32]>, AuditError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.started.add_permits(1);
            self.release
                .acquire()
                .await
                .expect("test release semaphore stays open")
                .forget();
            Ok(None)
        }
    }

    #[derive(Clone, Default)]
    struct VerificationFailureSink;

    #[async_trait::async_trait]
    impl registry_platform_audit::AuditSink for VerificationFailureSink {
        async fn write(
            &self,
            _envelope: &registry_platform_audit::AuditEnvelope,
        ) -> Result<(), AuditError> {
            Err(AuditError::ChainVerification(
                registry_platform_audit::ChainVerificationError::RecordHashMismatch { line: 1 },
            ))
        }

        async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(None)
        }

        async fn tail_hash_with_hasher(
            &self,
            _hasher: &registry_platform_audit::AuditChainHasher,
        ) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(None)
        }
    }

    #[test]
    fn timestamp_helper_emits_24_chars_ending_in_z() {
        let s = now_iso8601_millis();
        assert_eq!(s.len(), 24, "got {s:?}");
        assert!(s.ends_with('Z'));
    }

    #[test]
    fn exact_trust_scope_redaction_requires_a_keyed_field_bound_handle() {
        let scope = "registry:trust:subject_ref:subject:123";
        assert_eq!(
            redact_scope_for_audit(scope, &AuditKeyHasher::unkeyed_dev_only()),
            None
        );

        let hasher = AuditKeyHasher::Keyed(
            AuditHashSecret::new(b"audit-module-trust-scope-test-secret".to_vec())
                .expect("test audit secret is strong enough"),
        );
        let redacted = redact_scope_for_audit(scope, &hasher).expect("keyed redaction succeeds");
        assert!(redacted.starts_with("registry:trust:subject_ref:hmac-sha256:"));
        assert!(!redacted.contains("subject:123"));
        assert_ne!(
            redacted,
            redact_scope_for_audit("registry:trust:on_behalf_of:subject:123", &hasher,)
                .expect("other field redaction succeeds")
        );
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
    fn consultation_denial_mapping_is_closed_and_never_classifies_503() {
        assert_eq!(
            consultation_denial_reason(StatusCode::UNAUTHORIZED, Some("auth.invalid_credentials")),
            Some(ConsultationDenialReason::InvalidCredentials)
        );
        assert_eq!(
            consultation_denial_reason(StatusCode::BAD_REQUEST, Some("auth.purpose_required")),
            Some(ConsultationDenialReason::InvalidRequest)
        );
        assert_eq!(
            consultation_denial_reason(StatusCode::FORBIDDEN, Some("consultation.denied")),
            Some(ConsultationDenialReason::Denied)
        );
        assert_eq!(
            consultation_denial_reason(
                StatusCode::NOT_FOUND,
                Some("consultation.profile_not_found")
            ),
            Some(ConsultationDenialReason::NotFound)
        );
        assert_eq!(
            consultation_denial_reason(
                StatusCode::TOO_MANY_REQUESTS,
                Some("consultation.rate_limited")
            ),
            Some(ConsultationDenialReason::RateLimited)
        );
        assert_eq!(
            consultation_denial_reason(
                StatusCode::SERVICE_UNAVAILABLE,
                Some("consultation.unavailable")
            ),
            None
        );
        assert_eq!(
            consultation_denial_reason(StatusCode::SERVICE_UNAVAILABLE, None),
            None
        );
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            assert_eq!(consultation_denial_reason(status, None), None);
            assert_eq!(
                consultation_denial_reason(status, Some("handler.unrelated")),
                None
            );
        }

        let mut tracked_denial = consultation_unavailable_response();
        *tracked_denial.status_mut() = StatusCode::FORBIDDEN;
        tracked_denial
            .extensions_mut()
            .insert(ErrorCodeExt("consultation.denied".to_string()));
        assert_eq!(
            pending_consultation_denial(&tracked_denial),
            Some(ConsultationDenialReason::Denied)
        );
        tracked_denial
            .extensions_mut()
            .insert(ConsultationDenialRecorded::for_test());
        assert_eq!(pending_consultation_denial(&tracked_denial), None);
    }

    #[test]
    fn consultation_audit_failures_use_the_frozen_public_taxonomy_only_when_active() {
        let active = audit_failure_response(true);
        assert_eq!(active.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            active
                .extensions()
                .get::<ErrorCodeExt>()
                .map(|code| code.0.as_str()),
            Some("consultation.unavailable")
        );
        assert_eq!(
            active.headers().get(header::CACHE_CONTROL),
            Some(&axum::http::HeaderValue::from_static("private, no-store"))
        );

        let inactive = audit_failure_response(false);
        assert_eq!(inactive.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            inactive
                .extensions()
                .get::<ErrorCodeExt>()
                .map(|code| code.0.as_str()),
            Some(AUDIT_WRITE_FAILED_CODE)
        );
    }

    #[test]
    fn operational_export_cannot_replace_an_authoritative_consultation_completion() {
        for status in [StatusCode::OK, StatusCode::CREATED, StatusCode::NO_CONTENT] {
            assert!(preserves_authoritative_consultation_completion(
                Some(ConsultationDenialRoute::Execute),
                status,
            ));
        }
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::FORBIDDEN,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert!(!preserves_authoritative_consultation_completion(
                Some(ConsultationDenialRoute::Execute),
                status,
            ));
        }
        assert!(!preserves_authoritative_consultation_completion(
            Some(ConsultationDenialRoute::Profile),
            StatusCode::OK,
        ));
        assert!(!preserves_authoritative_consultation_completion(
            None,
            StatusCode::OK,
        ));
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

    #[tokio::test]
    async fn verify_chain_eager_accepts_a_valid_chain() {
        // #196: a healthy retained chain leaves the pipeline ready.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        {
            let pipeline = AuditPipeline::from_sink(FileSink::new(&path, 10, 50).expect("sink"));
            pipeline
                .write_operational_event(OperationalAuditEvent::success("test.one"))
                .await
                .expect("write one");
            pipeline
                .write_operational_event(OperationalAuditEvent::success("test.two"))
                .await
                .expect("write two");
        }

        let pipeline =
            AuditPipeline::from_sink(FileSink::new(&path, 10, 50).expect("restart sink"));
        pipeline
            .verify_chain_eager()
            .await
            .expect("valid chain verifies at startup");
        assert!(pipeline.chain_healthy());
    }

    #[tokio::test]
    async fn current_tail_hash_tracks_successful_appends() {
        let pipeline = AuditPipeline::from_sink(InMemorySink::new());
        assert_eq!(pipeline.current_tail_hash_bounded().await, None);
        pipeline
            .verify_chain_eager()
            .await
            .expect("empty chain initializes");
        assert_eq!(pipeline.current_tail_hash_bounded().await, None);
        pipeline
            .write_operational_event(OperationalAuditEvent::success("test.shipping-tail"))
            .await
            .expect("audit event writes");
        assert!(pipeline.current_tail_hash_bounded().await.is_some());
    }

    #[tokio::test]
    async fn current_tail_hash_bounds_cold_bootstrap_to_one_initializer() {
        let sink = SlowTailSink::default();
        let pipeline = AuditPipeline::from_sink(sink.clone());
        let first = tokio::spawn({
            let pipeline = Arc::clone(&pipeline);
            async move { pipeline.current_tail_hash_bounded().await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), sink.started.acquire())
            .await
            .expect("tail bootstrap starts within the test deadline")
            .expect("test started semaphore stays open")
            .forget();

        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                pipeline.current_tail_hash_bounded(),
            )
            .await
            .expect("a concurrent probe fails before the owner deadline"),
            None
        );
        assert_eq!(sink.calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), first)
                .await
                .expect("the first probe observes its deadline")
                .expect("first probe task joins"),
            None
        );
        sink.release.add_permits(1);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while pipeline.chain.get().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached initializer completes after release");
        assert_eq!(sink.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn verify_chain_eager_flags_a_tampered_chain_as_not_ready() {
        // #196: a retained chain that no longer verifies flips readiness to
        // not-ready so the brick is visible on /ready.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        {
            let pipeline = AuditPipeline::from_sink(FileSink::new(&path, 10, 50).expect("sink"));
            pipeline
                .write_operational_event(OperationalAuditEvent::success("test.one"))
                .await
                .expect("write one");
            pipeline
                .write_operational_event(OperationalAuditEvent::success("test.two"))
                .await
                .expect("write two");
        }

        // Tamper the second record's body so its record_hash no longer matches.
        let contents = std::fs::read_to_string(&path).expect("audit file");
        std::fs::write(&path, contents.replace("test.two", "tampered")).expect("tamper");

        let pipeline =
            AuditPipeline::from_sink(FileSink::new(&path, 10, 50).expect("restart sink"));
        assert!(pipeline.chain_healthy(), "pipeline starts healthy");
        let result = pipeline.verify_chain_eager().await;
        assert!(result.is_err(), "tampered chain fails verification");
        assert!(
            !pipeline.chain_healthy(),
            "readiness must flip to not-ready on an inconsistent chain"
        );

        // Restoring the file lets a new bootstrap succeed, but cannot restore
        // readiness in this process. Operator recovery requires a restart.
        std::fs::write(&path, contents).expect("restore valid chain");
        pipeline
            .verify_chain_eager()
            .await
            .expect("repaired retained chain verifies");
        assert!(
            !pipeline.chain_healthy(),
            "audit-chain readiness must remain latched after an integrity failure"
        );
    }

    #[tokio::test]
    async fn write_time_chain_verification_failure_latches_readiness() {
        let pipeline = AuditPipeline::new(Arc::new(VerificationFailureSink));

        let error = pipeline
            .write_operational_event(OperationalAuditEvent::success("test.verification-failure"))
            .await
            .expect_err("verification failure must reject the audit write");
        assert!(matches!(error, AuditError::ChainVerification(_)));
        assert!(
            !pipeline.chain_healthy(),
            "write-time verification failures must latch audit readiness"
        );
    }
}

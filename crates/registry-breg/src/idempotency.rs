// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-backed mutation idempotency binding and exact held responses.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::history_reference::SnapshotReference;
use crate::model::HttpMethod;
use crate::postgres::{ActionClaimContext, ClaimContext, RowBoundaryContext};
use crate::stored_bytes;

// Every compiled effect mutates at least one field, so this also bounds the
// number of separately named references in an immediate-action receipt.
pub(crate) const MAX_IMMEDIATE_ACTION_RESULTS: u16 =
    crate::change_request::MAX_CHANGE_REQUEST_FIELD_MUTATIONS;

pub(crate) const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;
// Held mutation bodies keep encrypted members as tagged, base64-encoded
// AES-GCM envelopes until the authorized serve edge opens them. Reserve half
// again as much space as the prior 2 MiB held-body budget for that
// internal expansion while retaining a hard cache and replay-read bound.
pub(crate) const MAX_HELD_BODY_BYTES: usize = 3 * 1024 * 1024;
// Overwrites the held bytes of a key whose record history was erased. The table
// requires a nonempty body and a 2xx status on every row, so an erased key keeps
// a minimal placeholder instead of the response it cached. Replay refuses on the
// `erased` result kind, so this placeholder never reaches a caller.
const ERASED_TOMBSTONE_BODY: &[u8] = br#"{"kind":"erased"}"#;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PermittedResponseHeader {
    ContentType,
    Etag,
    Link,
    Location,
    ReprDigest,
}

impl PermittedResponseHeader {
    fn as_str(self) -> &'static str {
        match self {
            Self::ContentType => "content-type",
            Self::Etag => "etag",
            Self::Link => "link",
            Self::Location => "location",
            Self::ReprDigest => "repr-digest",
        }
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ContentType),
            2 => Some(Self::Etag),
            3 => Some(Self::Location),
            4 => Some(Self::Link),
            5 => Some(Self::ReprDigest),
            _ => None,
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Self::ContentType => 1,
            Self::Etag => 2,
            Self::Location => 3,
            Self::Link => 4,
            Self::ReprDigest => 5,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HeldResponse {
    status: u16,
    body: Vec<u8>,
    headers: BTreeMap<PermittedResponseHeader, Vec<u8>>,
}

impl HeldResponse {
    pub(crate) fn from_json(
        status: u16,
        body: &serde_json::Value,
        headers: BTreeMap<PermittedResponseHeader, Vec<u8>>,
    ) -> Result<Self, IdempotencyError> {
        if !(200..=299).contains(&status)
            || headers.values().any(|value| !valid_header_value(value))
        {
            return Err(IdempotencyError::InvalidInput);
        }
        let body = canonicalize_json(body).map_err(|_| IdempotencyError::InvalidInput)?;
        if body.is_empty() || body.len() > MAX_HELD_BODY_BYTES {
            return Err(IdempotencyError::InvalidInput);
        }
        Ok(Self {
            status,
            body,
            headers,
        })
    }

    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    #[must_use]
    pub fn headers(&self) -> &BTreeMap<PermittedResponseHeader, Vec<u8>> {
        &self.headers
    }
}

/// The namespace of every issuer the engine scopes keys under itself.
/// [`IdempotencyPolicy::new`] refuses any issuer in it, so a configured
/// issuer never shares a scope with the engine's own keys.
const RESERVED_ISSUER_PREFIX: &str = "urn:registry-breg:";
/// The issuer a coordinator scopes caller keys under when no verified token
/// issuer is configured, as in an embedded coordinator that serves no HTTP
/// surface. A runtime started from its configuration always scopes keys under
/// its configured OIDC issuer instead.
pub const EMBEDDED_CALLER_ISSUER: &str = "urn:registry-breg:embedded-issuer";
/// The issuer hook proposal keys are scoped under. No token verifier accepts
/// it, so no caller can reach a hook delivery's key.
const HOOK_DELIVERY_ISSUER: &str = "urn:registry-breg:hook-delivery";
/// How many days a held response is kept when the runtime configuration does
/// not choose.
pub const DEFAULT_RECEIPT_RETENTION_DAYS: u16 = 7;
/// The longest receipt horizon a runtime configuration may choose.
pub const MAX_RECEIPT_RETENTION_DAYS: u16 = 365;

/// Who a spent key belongs to and how long its held response is kept.
///
/// A key is spent per caller: the verified token issuer and subject, the key
/// scope, and the key itself find the spent row. Every ordinary write shares
/// one scope, so a key is not spent per operation. Nothing that finds
/// or binds a row is derived from the audit hash key, so rotating
/// `audit.hashKeyRef` changes pseudonyms only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyPolicy {
    caller_issuer: String,
    receipt_retention_days: u16,
}

impl IdempotencyPolicy {
    /// Scope caller keys under `caller_issuer` and keep each held response
    /// for `receipt_retention_days` days after its commit. Every issuer the
    /// engine reserves for its own keys is refused; the embedded policy is
    /// [`IdempotencyPolicy::default`].
    pub fn new(
        caller_issuer: impl Into<String>,
        receipt_retention_days: u16,
    ) -> Result<Self, IdempotencyError> {
        let caller_issuer = caller_issuer.into();
        if caller_issuer.is_empty()
            || caller_issuer.starts_with(RESERVED_ISSUER_PREFIX)
            || !(1..=MAX_RECEIPT_RETENTION_DAYS).contains(&receipt_retention_days)
        {
            return Err(IdempotencyError::InvalidInput);
        }
        Ok(Self {
            caller_issuer,
            receipt_retention_days,
        })
    }

    #[must_use]
    pub fn caller_issuer(&self) -> &str {
        &self.caller_issuer
    }

    #[must_use]
    pub fn receipt_retention_days(&self) -> u16 {
        self.receipt_retention_days
    }
}

impl Default for IdempotencyPolicy {
    fn default() -> Self {
        Self {
            caller_issuer: EMBEDDED_CALLER_ISSUER.to_owned(),
            receipt_retention_days: DEFAULT_RECEIPT_RETENTION_DAYS,
        }
    }
}

pub(crate) struct IdempotencyBinding<'a> {
    pub key: &'a str,
    pub context: &'a ClaimContext,
    pub method: HttpMethod,
    pub route: &'a str,
    pub target_record: Option<&'a str>,
    pub package_revision: &'a str,
    pub response_fields: &'a BTreeSet<String>,
    pub canonical_request_digest: [u8; 32],
    /// The key scope the key is spent in. Every ordinary write route shares
    /// one scope. Server-derived ingestion keys carry their own, so no
    /// caller-supplied key, however derived, can reserve, preseed, or replay
    /// a run chunk's cached result through the ordinary mutation routes.
    pub key_domain: IdempotencyKeyDomain,
}

/// The key scope one idempotency key is spent in. It separates caller keys
/// from server-derived ones, not one write route from another.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum IdempotencyKeyDomain {
    /// Keys callers supply on ordinary mutation routes.
    Caller,
    /// Keys the run API derives for one ingestion chunk attempt.
    IngestionChunk,
}

impl IdempotencyKeyDomain {
    fn scope(self) -> &'static str {
        match self {
            Self::Caller => KEY_SCOPE_MUTATION,
            Self::IngestionChunk => KEY_SCOPE_INGESTION_CHUNK,
        }
    }
}

const KEY_SCOPE_MUTATION: &str = "mutation";
const KEY_SCOPE_INGESTION_CHUNK: &str = "ingestion_chunk";
const KEY_SCOPE_HOOK_PROPOSAL: &str = "hook_proposal";

pub(crate) struct ActionIdempotencyBinding<'a> {
    pub key: &'a str,
    pub context: &'a ActionClaimContext,
    pub method: HttpMethod,
    pub route: &'a str,
    pub package_revision: &'a str,
    pub action_contract_fingerprint: &'a str,
    pub target_authority: &'a BTreeMap<String, Vec<RowBoundaryContext>>,
    pub result_effects: &'a BTreeSet<String>,
    pub canonical_request_digest: [u8; 32],
    /// The digest of exactly the handler answer an application settles, set
    /// only by the hook proposal path. It belongs to the binding reference,
    /// never the key: one delivery is one application whatever answer a later
    /// attempt carries, and a changed answer surfaces as an idempotency
    /// conflict rather than a second application.
    pub answer_digest: Option<&'a [u8; 32]>,
}

pub(crate) struct ResolvedIdempotencyBinding {
    /// A SHA-256 digest of the caller, the key scope, and the key. It
    /// keys the spent row, its dependents, and the advisory lock.
    pub key_reference: String,
    /// A SHA-256 digest of the exact verified authority and request the key
    /// was spent on. A retry replays only when it matches.
    pub binding_reference: String,
    /// The audit-keyed pseudonym of the same binding, published in revisions
    /// and the audit journal. It changes when `audit.hashKeyRef` rotates and
    /// is never used to find or bind a spent key.
    pub request_reference: String,
    pub principal_reference: String,
    pub record_reference: String,
    pub handler_answer_digest: Option<[u8; 32]>,
    pub caller: SpentKeyCaller,
}

/// The identity a spent row is stored under, and its receipt horizon.
pub(crate) struct SpentKeyCaller {
    pub issuer: String,
    pub subject: String,
    pub scope: &'static str,
    pub key: String,
    pub receipt_retention_days: u16,
}

pub(crate) struct StoredMutationResult {
    pub response: HeldResponse,
    pub metadata: StoredResultMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StoredResultMetadata {
    Record {
        record_reference: String,
        record_revision: i64,
    },
    Batch {
        result_count: u16,
    },
    Application {
        record_reference: String,
        record_revision: i64,
        proposal_version: i64,
        result_count: u16,
    },
    ImmediateAction {
        result_count: u16,
    },
    Release {
        release_reference: String,
        release_version: i64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IdempotencyError {
    #[error("mutation request is invalid")]
    InvalidInput,
    #[error("idempotency key is already bound to another request")]
    Conflict,
    /// The key was spent on this request and its held response is past the
    /// receipt horizon. The key stays spent, so the request never executes
    /// again.
    #[error("idempotency key is spent and its held response has expired")]
    Expired,
    #[error("a cached mutation response holds bytes no JSON reader accepts")]
    CachedResponseUnreadable,
    #[error("mutation state operation timed out")]
    Timeout,
    #[error("mutation state is unavailable")]
    Unavailable,
}

fn map_database_error(error: tokio_postgres::Error) -> IdempotencyError {
    if error
        .code()
        .is_some_and(|code| code == &tokio_postgres::error::SqlState::QUERY_CANCELED)
    {
        IdempotencyError::Timeout
    } else {
        IdempotencyError::Unavailable
    }
}

pub(crate) fn resolve_binding(
    profile: &AuditProfile,
    policy: &IdempotencyPolicy,
    binding: &IdempotencyBinding<'_>,
) -> Result<ResolvedIdempotencyBinding, IdempotencyError> {
    if binding.route.is_empty()
        || binding.package_revision.is_empty()
        || binding.response_fields.iter().any(|field| field.is_empty())
        || binding.target_record.is_some_and(str::is_empty)
    {
        return Err(IdempotencyError::InvalidInput);
    }
    let subject = binding
        .context
        .principal()
        .ok_or(IdempotencyError::InvalidInput)?;
    let caller = SpentKeyCaller::new(
        policy,
        policy.caller_issuer(),
        subject,
        binding.key_domain.scope(),
        binding.key,
    )?;

    let key_hasher = profile.key_hasher();
    let principal_reference = key_hasher
        .audit_reference_hash("breg-principal-v1", binding.package_revision, subject)
        .map_err(|_| IdempotencyError::InvalidInput)?;
    let record_reference = binding
        .target_record
        .map(|target_record| {
            key_hasher
                .audit_reference_hash("breg-record-v1", binding.package_revision, target_record)
                .map_err(|_| IdempotencyError::InvalidInput)
        })
        .transpose()?;

    let mut pseudonymous_binding = json!({
        "context": canonical_claim_context(profile, binding.context, binding.package_revision)?,
        "method": method_name(binding.method),
        "route": binding.route,
        "targetRecordReference": record_reference,
        "packageRevision": binding.package_revision,
        "responseFields": binding.response_fields,
        "canonicalRequestDigest": hex(&binding.canonical_request_digest),
    });
    let mut exact_binding = json!({
        "context": binding_claim_context(binding.context)?,
        "method": method_name(binding.method),
        "route": binding.route,
        "targetRecord": binding.target_record,
        "packageRevision": binding.package_revision,
        "responseFields": binding.response_fields,
        "canonicalRequestDigest": hex(&binding.canonical_request_digest),
    });
    if let Some(grant) = binding.context.task_grant() {
        let grant = serde_json::to_value(grant).map_err(|_| IdempotencyError::InvalidInput)?;
        pseudonymous_binding["taskGrant"] = grant.clone();
        exact_binding["taskGrant"] = grant;
    }

    Ok(ResolvedIdempotencyBinding {
        key_reference: caller.key_reference(),
        binding_reference: sha256_reference(
            "breg-idempotency-binding-v2",
            &[&canonical_text(&exact_binding)?],
        ),
        request_reference: audit_reference(
            profile,
            "breg-idempotency-binding-v1",
            binding.package_revision,
            &pseudonymous_binding,
        )?,
        principal_reference,
        record_reference: record_reference.unwrap_or_default(),
        handler_answer_digest: None,
        caller,
    })
}

pub(crate) fn resolve_action_binding(
    profile: &AuditProfile,
    policy: &IdempotencyPolicy,
    binding: &ActionIdempotencyBinding<'_>,
) -> Result<ResolvedIdempotencyBinding, IdempotencyError> {
    let caller = SpentKeyCaller::new(
        policy,
        policy.caller_issuer(),
        binding.context.principal(),
        KEY_SCOPE_MUTATION,
        binding.key,
    )?;
    resolve_action_binding_for_caller(profile, binding, caller)
}

/// Resolve the binding of one hook proposal application. The key is spent by
/// the hook delivery itself, under an issuer no token verifier accepts and the
/// compiled delivery as the subject, so no caller can reserve, replay, or
/// collide with a delivery's application.
pub(crate) fn resolve_hook_action_binding(
    profile: &AuditProfile,
    policy: &IdempotencyPolicy,
    compiled_delivery_id: &str,
    binding: &ActionIdempotencyBinding<'_>,
) -> Result<ResolvedIdempotencyBinding, IdempotencyError> {
    let caller = SpentKeyCaller::new(
        policy,
        HOOK_DELIVERY_ISSUER,
        compiled_delivery_id,
        KEY_SCOPE_HOOK_PROPOSAL,
        binding.key,
    )?;
    resolve_action_binding_for_caller(profile, binding, caller)
}

fn resolve_action_binding_for_caller(
    profile: &AuditProfile,
    binding: &ActionIdempotencyBinding<'_>,
    caller: SpentKeyCaller,
) -> Result<ResolvedIdempotencyBinding, IdempotencyError> {
    if binding.route.is_empty()
        || binding.package_revision.is_empty()
        || binding.action_contract_fingerprint.is_empty()
        || binding
            .result_effects
            .iter()
            .any(|effect| effect.is_empty())
        || binding
            .target_authority
            .keys()
            .any(|entity_id| entity_id.is_empty())
    {
        return Err(IdempotencyError::InvalidInput);
    }
    let principal_reference = profile
        .key_hasher()
        .audit_reference_hash(
            "breg-principal-v1",
            binding.package_revision,
            binding.context.principal(),
        )
        .map_err(|_| IdempotencyError::InvalidInput)?;
    let pseudonymous_authority = binding
        .target_authority
        .iter()
        .map(|(entity_id, boundaries)| {
            Ok(json!({
                "entityId": entity_id,
                "rowBoundaries": canonical_boundary_references(
                    profile,
                    binding.package_revision,
                    boundaries,
                )?,
            }))
        })
        .collect::<Result<Vec<_>, IdempotencyError>>()?;
    let exact_authority = binding
        .target_authority
        .iter()
        .map(|(entity_id, boundaries)| {
            json!({
                "entityId": entity_id,
                "rowBoundaries": binding_boundaries(boundaries),
            })
        })
        .collect::<Vec<_>>();
    let mut pseudonymous_binding = json!({
        "context": canonical_action_context(profile, binding.context, binding.package_revision)?,
        "method": method_name(binding.method),
        "route": binding.route,
        "packageRevision": binding.package_revision,
        "actionContractFingerprint": binding.action_contract_fingerprint,
        "targetAuthority": pseudonymous_authority,
        "resultEffects": binding.result_effects,
        "canonicalRequestDigest": hex(&binding.canonical_request_digest),
    });
    let mut exact_binding = json!({
        "context": binding_action_context(binding.context),
        "method": method_name(binding.method),
        "route": binding.route,
        "packageRevision": binding.package_revision,
        "actionContractFingerprint": binding.action_contract_fingerprint,
        "targetAuthority": exact_authority,
        "resultEffects": binding.result_effects,
        "canonicalRequestDigest": hex(&binding.canonical_request_digest),
    });
    if let Some(answer_digest) = binding.answer_digest {
        let answer_digest = Value::String(hex(answer_digest.as_slice()));
        pseudonymous_binding["handlerAnswerDigest"] = answer_digest.clone();
        exact_binding["handlerAnswerDigest"] = answer_digest;
    }
    Ok(ResolvedIdempotencyBinding {
        key_reference: caller.key_reference(),
        binding_reference: sha256_reference(
            "breg-action-idempotency-binding-v2",
            &[&canonical_text(&exact_binding)?],
        ),
        request_reference: audit_reference(
            profile,
            "breg-action-idempotency-binding-v1",
            binding.package_revision,
            &pseudonymous_binding,
        )?,
        principal_reference,
        record_reference: String::new(),
        handler_answer_digest: binding.answer_digest.copied(),
        caller,
    })
}

/// The key reference of one hook delivery's proposal application, the same
/// reference `resolve_hook_action_binding` spends.
pub(crate) fn resolve_hook_key_reference(
    compiled_delivery_id: &str,
    key: &str,
) -> Result<String, IdempotencyError> {
    SpentKeyCaller::new(
        &IdempotencyPolicy::default(),
        HOOK_DELIVERY_ISSUER,
        compiled_delivery_id,
        KEY_SCOPE_HOOK_PROPOSAL,
        key,
    )
    .map(|caller| caller.key_reference())
}

impl SpentKeyCaller {
    fn new(
        policy: &IdempotencyPolicy,
        issuer: &str,
        subject: &str,
        scope: &'static str,
        key: &str,
    ) -> Result<Self, IdempotencyError> {
        if issuer.is_empty()
            || subject.is_empty()
            || key.is_empty()
            || key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        {
            return Err(IdempotencyError::InvalidInput);
        }
        Ok(Self {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
            scope,
            key: key.to_owned(),
            receipt_retention_days: policy.receipt_retention_days(),
        })
    }

    /// One fixed-length handle for the spent row: its primary key, the target
    /// of its dependents, and the advisory lock that serializes the key.
    fn key_reference(&self) -> String {
        sha256_reference(
            "breg-idempotency-key-v2",
            &[self.scope, &self.issuer, &self.subject, &self.key],
        )
    }
}

/// A SHA-256 digest over a domain and length-prefixed parts, so no two
/// distinct part sequences share a preimage.
fn sha256_reference(domain: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in std::iter::once(domain).chain(parts.iter().copied()) {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("sha256:{}", hex(&hasher.finalize()))
}

fn canonical_text(value: &Value) -> Result<String, IdempotencyError> {
    let canonical = canonicalize_json(value).map_err(|_| IdempotencyError::InvalidInput)?;
    String::from_utf8(canonical).map_err(|_| IdempotencyError::InvalidInput)
}

fn audit_reference(
    profile: &AuditProfile,
    domain: &str,
    package_revision: &str,
    value: &Value,
) -> Result<String, IdempotencyError> {
    profile
        .key_hasher()
        .audit_reference_hash(domain, package_revision, &canonical_text(value)?)
        .map_err(|_| IdempotencyError::InvalidInput)
}

/// The exact verified authority one protected operation ran under, as the
/// spent-key binding records it. It holds raw verified values, which the
/// binding reference digests together with the canonical request digest.
fn binding_claim_context(context: &ClaimContext) -> Result<Value, IdempotencyError> {
    let principal = context.principal().ok_or(IdempotencyError::InvalidInput)?;
    let mut value = json!({
        "entityId": context.entity_id(),
        "principal": principal,
        "selectedAccessProfile": context.access_profile(),
        "verifiedPurpose": context.purpose(),
        "rowBoundaries": binding_boundaries(context.row_boundaries()),
    });
    if !context.submitter_targets().is_empty() {
        value["submitterTargets"] = context
            .submitter_targets()
            .iter()
            .map(|(id, target)| Ok((id.clone(), binding_claim_context(target)?)))
            .collect::<Result<serde_json::Map<String, Value>, IdempotencyError>>()?
            .into();
    }
    Ok(value)
}

fn binding_action_context(context: &ActionClaimContext) -> Value {
    json!({
        "actionId": context.action_id(),
        "principal": context.principal(),
        "selectedAccessProfile": context.access_profile(),
        "verifiedPurpose": context.purpose(),
    })
}

fn binding_boundaries(boundaries: &[RowBoundaryContext]) -> Vec<Value> {
    boundaries
        .iter()
        .map(|boundary| {
            json!({
                "field": boundary.field(),
                "operator": boundary.operator().as_str(),
                "values": boundary.values(),
            })
        })
        .collect()
}

/// Canonical, value-safe identity of every verified authorization input that
/// PostgreSQL receives for one protected operation.
pub(crate) fn canonical_claim_context(
    profile: &AuditProfile,
    context: &ClaimContext,
    package_revision: &str,
) -> Result<Value, IdempotencyError> {
    let principal = context.principal().ok_or(IdempotencyError::InvalidInput)?;
    let key_hasher = profile.key_hasher();
    let principal_reference = key_hasher
        .audit_reference_hash("breg-principal-v1", package_revision, principal)
        .map_err(|_| IdempotencyError::InvalidInput)?;
    let row_boundaries = context
        .row_boundaries()
        .iter()
        .map(|boundary| {
            let reference_context = format!(
                "{package_revision}:{}:{}",
                boundary.field(),
                boundary.operator().as_str()
            );
            let value_references = boundary
                .values()
                .into_iter()
                .map(|value| {
                    key_hasher.audit_reference_hash(
                        "breg-row-boundary-value-v1",
                        &reference_context,
                        value,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| IdempotencyError::InvalidInput)?;
            Ok(json!({
                "field": boundary.field(),
                "operator": boundary.operator().as_str(),
                "valueReferences": value_references,
            }))
        })
        .collect::<Result<Vec<_>, IdempotencyError>>()?;
    let mut value = json!({
        "entityId": context.entity_id(),
        "principalReference": principal_reference,
        "selectedAccessProfile": context.access_profile(),
        "verifiedPurpose": context.purpose(),
        "rowBoundaries": row_boundaries,
    });
    if !context.submitter_targets().is_empty() {
        value["submitterTargets"] = context
            .submitter_targets()
            .iter()
            .map(|(id, target)| {
                Ok((
                    id.clone(),
                    canonical_claim_context(profile, target, package_revision)?,
                ))
            })
            .collect::<Result<serde_json::Map<String, Value>, IdempotencyError>>()?
            .into();
    }
    Ok(value)
}

pub(crate) fn canonical_action_context(
    profile: &AuditProfile,
    context: &ActionClaimContext,
    package_revision: &str,
) -> Result<Value, IdempotencyError> {
    let key_hasher = profile.key_hasher();
    let principal_reference = key_hasher
        .audit_reference_hash("breg-principal-v1", package_revision, context.principal())
        .map_err(|_| IdempotencyError::InvalidInput)?;
    Ok(json!({
        "actionId": context.action_id(),
        "principalReference": principal_reference,
        "selectedAccessProfile": context.access_profile(),
        "verifiedPurpose": context.purpose(),
    }))
}

fn canonical_boundary_references(
    profile: &AuditProfile,
    package_revision: &str,
    boundaries: &[RowBoundaryContext],
) -> Result<Vec<Value>, IdempotencyError> {
    let key_hasher = profile.key_hasher();
    boundaries
        .iter()
        .map(|boundary| {
            let reference_context = format!(
                "{package_revision}:{}:{}",
                boundary.field(),
                boundary.operator().as_str()
            );
            let value_references = boundary
                .values()
                .into_iter()
                .map(|value| {
                    key_hasher.audit_reference_hash(
                        "breg-row-boundary-value-v1",
                        &reference_context,
                        value,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| IdempotencyError::InvalidInput)?;
            Ok(json!({
                "field": boundary.field(),
                "operator": boundary.operator().as_str(),
                "valueReferences": value_references,
            }))
        })
        .collect()
}

pub(crate) async fn lock_and_load(
    transaction: &Transaction<'_>,
    binding: &ResolvedIdempotencyBinding,
) -> Result<Option<StoredMutationResult>, IdempotencyError> {
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))",
            &[&binding.key_reference],
        )
        .await
        .map_err(map_database_error)?;
    let Some(row) = transaction
        .query_opt(
            "SELECT binding_reference, result_kind, record_revision, response_status,
                    response_body, response_headers, record_reference, result_count,
                    proposal_version, erased_at,
                    receipt_dropped_at IS NOT NULL
                        OR receipt_expires_at <= transaction_timestamp()
             FROM registry_internal.registry_idempotency
             WHERE key_reference = $1",
            &[&binding.key_reference],
        )
        .await
        .map_err(map_database_error)?
    else {
        return Ok(None);
    };
    if row.get::<_, String>(0) != binding.binding_reference {
        return Err(IdempotencyError::Conflict);
    }
    if row.get::<_, Option<std::time::SystemTime>>(9).is_some() {
        // Erasure is permanent. Keep the consumed key reserved and refuse
        // replay without presenting a transient outage to retrying clients.
        return Err(IdempotencyError::Conflict);
    }
    let result_kind = row.get::<_, String>(1);
    if result_kind == "erased" {
        // Erasure is irreversible, so the consumed key answers with the same
        // terminal conflict the erased-at path answers with. A transient outage
        // would invite a client to retry a key that can never succeed.
        return Err(IdempotencyError::Conflict);
    }
    if row.get::<_, bool>(10) {
        // Past the receipt horizon the held response is gone or about to be
        // dropped, but the key stays spent: the exact retry is refused rather
        // than executed again.
        return Err(IdempotencyError::Expired);
    }
    let metadata = match result_kind.as_str() {
        "record" => {
            let record_revision = row
                .get::<_, Option<i64>>(2)
                .filter(|revision| *revision > 0)
                .ok_or(IdempotencyError::Unavailable)?;
            let record_reference = row
                .get::<_, Option<String>>(6)
                .filter(|reference| !reference.is_empty())
                .ok_or(IdempotencyError::Unavailable)?;
            if row.get::<_, Option<i16>>(7).is_some() || row.get::<_, Option<i64>>(8).is_some() {
                return Err(IdempotencyError::Unavailable);
            }
            StoredResultMetadata::Record {
                record_reference,
                record_revision,
            }
        }
        "batch" => {
            if row.get::<_, Option<i64>>(2).is_some()
                || row.get::<_, Option<String>>(6).is_some()
                || row.get::<_, Option<i64>>(8).is_some()
            {
                return Err(IdempotencyError::Unavailable);
            }
            let result_count = row
                .get::<_, Option<i16>>(7)
                .and_then(|count| u16::try_from(count).ok())
                .filter(|count| *count > 0)
                .ok_or(IdempotencyError::Unavailable)?;
            StoredResultMetadata::Batch { result_count }
        }
        "application" => {
            let record_revision = row
                .get::<_, Option<i64>>(2)
                .filter(|revision| *revision > 0)
                .ok_or(IdempotencyError::Unavailable)?;
            let record_reference = row
                .get::<_, Option<String>>(6)
                .filter(|reference| !reference.is_empty())
                .ok_or(IdempotencyError::Unavailable)?;
            let result_count = row
                .get::<_, Option<i16>>(7)
                .and_then(|count| u16::try_from(count).ok())
                .filter(|count| (1..=16).contains(count))
                .ok_or(IdempotencyError::Unavailable)?;
            let proposal_version = row
                .get::<_, Option<i64>>(8)
                .filter(|version| *version > 0)
                .ok_or(IdempotencyError::Unavailable)?;
            StoredResultMetadata::Application {
                record_reference,
                record_revision,
                proposal_version,
                result_count,
            }
        }
        "immediate_action" => {
            if row.get::<_, Option<i64>>(2).is_some()
                || row.get::<_, Option<String>>(6).is_some()
                || row.get::<_, Option<i64>>(8).is_some()
            {
                return Err(IdempotencyError::Unavailable);
            }
            let result_count = row
                .get::<_, Option<i16>>(7)
                .and_then(|count| u16::try_from(count).ok())
                .filter(|count| *count <= MAX_IMMEDIATE_ACTION_RESULTS)
                .ok_or(IdempotencyError::Unavailable)?;
            StoredResultMetadata::ImmediateAction { result_count }
        }
        "release" => {
            let release_version = row
                .get::<_, Option<i64>>(2)
                .filter(|version| *version > 0)
                .ok_or(IdempotencyError::Unavailable)?;
            let release_reference = row
                .get::<_, Option<String>>(6)
                .filter(|reference| !reference.is_empty())
                .ok_or(IdempotencyError::Unavailable)?;
            if row.get::<_, Option<i16>>(7).is_some() || row.get::<_, Option<i64>>(8).is_some() {
                return Err(IdempotencyError::Unavailable);
            }
            StoredResultMetadata::Release {
                release_reference,
                release_version,
            }
        }
        _ => return Err(IdempotencyError::Unavailable),
    };
    let status = u16::try_from(row.get::<_, i16>(3)).map_err(|_| IdempotencyError::Unavailable)?;
    let body = row
        .get::<_, Option<Vec<u8>>>(4)
        .ok_or(IdempotencyError::Unavailable)?;
    if body.is_empty() || body.len() > MAX_HELD_BODY_BYTES {
        return Err(IdempotencyError::Unavailable);
    }
    let parsed = parse_json_strict(&body).map_err(|_| IdempotencyError::Unavailable)?;
    if canonicalize_json(&parsed).map_err(|_| IdempotencyError::Unavailable)? != body {
        return Err(IdempotencyError::Unavailable);
    }
    let headers = decode_headers(&row.get::<_, Vec<u8>>(5))?;
    Ok(Some(StoredMutationResult {
        response: HeldResponse {
            status,
            body,
            headers,
        },
        metadata,
    }))
}

pub(crate) async fn insert_result(
    transaction: &Transaction<'_>,
    binding: &ResolvedIdempotencyBinding,
    metadata: &StoredResultMetadata,
    response: &HeldResponse,
) -> Result<(), IdempotencyError> {
    let status = i16::try_from(response.status).map_err(|_| IdempotencyError::InvalidInput)?;
    let headers = encode_headers(&response.headers)?;
    let (result_kind, record_revision, record_reference, result_count, proposal_version) =
        match metadata {
            StoredResultMetadata::Record {
                record_reference,
                record_revision,
            } if !record_reference.is_empty() && *record_revision > 0 => (
                "record",
                Some(*record_revision),
                Some(record_reference.as_str()),
                None,
                None,
            ),
            StoredResultMetadata::Batch { result_count } if *result_count > 0 => (
                "batch",
                None,
                None,
                Some(i16::try_from(*result_count).map_err(|_| IdempotencyError::InvalidInput)?),
                None,
            ),
            StoredResultMetadata::Application {
                record_reference,
                record_revision,
                proposal_version,
                result_count,
            } if !record_reference.is_empty()
                && *record_revision > 0
                && *proposal_version > 0
                && (1..=16).contains(result_count) =>
            {
                (
                    "application",
                    Some(*record_revision),
                    Some(record_reference.as_str()),
                    Some(i16::try_from(*result_count).map_err(|_| IdempotencyError::InvalidInput)?),
                    Some(*proposal_version),
                )
            }
            StoredResultMetadata::ImmediateAction { result_count }
                if *result_count <= MAX_IMMEDIATE_ACTION_RESULTS =>
            {
                (
                    "immediate_action",
                    None,
                    None,
                    Some(i16::try_from(*result_count).map_err(|_| IdempotencyError::InvalidInput)?),
                    None,
                )
            }
            StoredResultMetadata::Release {
                release_reference,
                release_version,
            } if !release_reference.is_empty() && *release_version > 0 => (
                "release",
                Some(*release_version),
                Some(release_reference.as_str()),
                None,
                None,
            ),
            _ => return Err(IdempotencyError::InvalidInput),
        };
    let caller = &binding.caller;
    let receipt_retention_days = i32::from(caller.receipt_retention_days);
    let changed = transaction
        .execute(
            "INSERT INTO registry_internal.registry_idempotency
                 (key_reference, binding_reference, result_kind, record_revision,
                  response_status, response_body, response_headers, record_reference, result_count,
                  proposal_version, caller_issuer, caller_subject, key_scope, idempotency_key,
                  receipt_expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                     transaction_timestamp() + pg_catalog.make_interval(days => $15))",
            &[
                &binding.key_reference,
                &binding.binding_reference,
                &result_kind,
                &record_revision,
                &status,
                &response.body,
                &headers,
                &record_reference,
                &result_count,
                &proposal_version,
                &caller.issuer,
                &caller.subject,
                &caller.scope,
                &caller.key,
                &receipt_retention_days,
            ],
        )
        .await
        .map_err(map_database_error)?;
    if changed != 1 {
        return Err(IdempotencyError::Unavailable);
    }
    Ok(())
}

/// Replace exact cached mutation responses that could replay erased historical
/// bytes with a minimal tombstone row. The idempotency key and binding remain
/// durable so an old retry cannot re-execute the mutation.
pub(crate) async fn tombstone_erased_cached_responses(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    erase_through_revision: i64,
    affected_positions: &[i64],
) -> Result<u64, IdempotencyError> {
    if entity_id.is_empty() || erase_through_revision <= 0 {
        return Err(IdempotencyError::InvalidInput);
    }
    let snapshot_references = affected_snapshot_references(transaction, affected_positions).await?;
    let record_id_text = record_id.hyphenated().to_string();
    let headers = encode_headers(&BTreeMap::new())?;
    transaction
        .execute(
            "WITH target_revision_refs AS (
                 SELECT record_reference, record_revision
                   FROM registry_internal.registry_revisions
                  WHERE entity_id = $1
                    AND record_id = $2
                    AND record_revision <= $3
             ),
             batch_candidates AS (
                 SELECT idempotency.key_reference
                   FROM registry_internal.registry_idempotency AS idempotency
                   CROSS JOIN LATERAL (
                       SELECT pg_catalog.convert_from(idempotency.response_body, 'UTF8')::jsonb
                           AS body
                   ) AS decoded
                  WHERE idempotency.result_kind = 'batch'
                    AND (
                        decoded.body->>'snapshot' = ANY($4::text[])
                        OR EXISTS (
                            SELECT 1
                              FROM jsonb_array_elements(
                                       CASE
                                           WHEN jsonb_typeof(decoded.body->'results') = 'array'
                                           THEN decoded.body->'results'
                                           ELSE '[]'::jsonb
                                       END
                                   ) AS item
                             WHERE item->>'id' = $5
                               AND item->>'revision' ~ '^[1-9][0-9]*$'
                               AND (item->>'revision')::bigint <= $3
                        )
                    )
             ),
             record_candidates AS (
                 SELECT idempotency.key_reference
                   FROM registry_internal.registry_idempotency AS idempotency
                  WHERE idempotency.result_kind = 'record'
                    AND EXISTS (
                        SELECT 1
                          FROM target_revision_refs AS target
                         WHERE target.record_reference = idempotency.record_reference
                           AND target.record_revision = idempotency.record_revision
                    )
             )
             UPDATE registry_internal.registry_idempotency AS idempotency
                SET result_kind = 'erased',
                    record_reference = NULL,
                    record_revision = NULL,
                    result_count = NULL,
                    response_status = 200,
                    response_body = CASE
                        WHEN idempotency.response_body IS NULL THEN NULL
                        ELSE $6::bytea
                    END,
                    response_headers = $7
              WHERE idempotency.result_kind IN ('record', 'batch')
                AND idempotency.key_reference IN (
                    SELECT key_reference FROM record_candidates
                    UNION
                    SELECT key_reference FROM batch_candidates
                )",
            &[
                &entity_id,
                &record_id,
                &erase_through_revision,
                &snapshot_references,
                &record_id_text,
                &ERASED_TOMBSTONE_BODY,
                &headers,
            ],
        )
        .await
        .map_err(|error| {
            // A cached batch body is read back as JSON here. Bytes no reader
            // accepts are the row's own state, not an outage, and are named so
            // rather than retried behind a transport failure.
            if error
                .code()
                .is_some_and(|code| code == &tokio_postgres::error::SqlState::QUERY_CANCELED)
            {
                IdempotencyError::Timeout
            } else if stored_bytes::unreadable(&error, stored_bytes::Reader::IdempotencyCache) {
                IdempotencyError::CachedResponseUnreadable
            } else {
                IdempotencyError::Unavailable
            }
        })
}

async fn affected_snapshot_references(
    transaction: &Transaction<'_>,
    affected_positions: &[i64],
) -> Result<Vec<String>, IdempotencyError> {
    let rows = transaction
        .query(
            "SELECT snapshot_reference
               FROM registry_internal.registry_revision_commits
              WHERE commit_position = ANY($1::bigint[])
              ORDER BY commit_position",
            &[&affected_positions],
        )
        .await
        .map_err(map_database_error)?;
    Ok(rows
        .into_iter()
        .map(|row| SnapshotReference::for_uuid(row.get::<_, Uuid>(0)).to_string())
        .collect())
}

/// Drop the receipt of every spent key whose horizon passed at or before
/// `before`: its held response, and the raw issuer, subject, and key. The row
/// keeps its key reference, binding, scope, result references, and times, so
/// the key stays spent by its digest and an exact retry is still refused as
/// expired. A row whose held response an erasure already removed is dropped
/// the same way, so no raw caller outlives its horizon.
#[cfg(feature = "tooling")]
pub(crate) async fn drop_expired_receipts(
    transaction: &Transaction<'_>,
    before: chrono::DateTime<chrono::Utc>,
) -> Result<u64, IdempotencyError> {
    let headers = encode_headers(&BTreeMap::new())?;
    transaction
        .execute(
            "UPDATE registry_internal.registry_idempotency
                SET response_body = NULL,
                    response_headers = $2,
                    receipt_dropped_at = transaction_timestamp(),
                    caller_issuer = NULL,
                    caller_subject = NULL,
                    idempotency_key = NULL
              WHERE receipt_expires_at <= LEAST($1, transaction_timestamp())
                AND receipt_dropped_at IS NULL",
            &[&before, &headers],
        )
        .await
        .map_err(map_database_error)
}

/// Whether a receipt past its horizon at `cutoff` remains undropped.
#[cfg(feature = "tooling")]
pub(crate) async fn expired_receipts_remain(
    client: &tokio_postgres::Client,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> Result<bool, IdempotencyError> {
    client
        .query_one(
            "SELECT EXISTS (
                 SELECT 1 FROM registry_internal.registry_idempotency
                  WHERE receipt_expires_at <= $1
                    AND receipt_dropped_at IS NULL
             )",
            &[&cutoff],
        )
        .await
        .map_err(map_database_error)?
        .try_get(0)
        .map_err(|_| IdempotencyError::Unavailable)
}

fn encode_headers(
    headers: &BTreeMap<PermittedResponseHeader, Vec<u8>>,
) -> Result<Vec<u8>, IdempotencyError> {
    let count = u16::try_from(headers.len()).map_err(|_| IdempotencyError::InvalidInput)?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&count.to_be_bytes());
    for (name, value) in headers {
        let length = u32::try_from(value.len()).map_err(|_| IdempotencyError::InvalidInput)?;
        encoded.push(name.to_u8());
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(value);
    }
    Ok(encoded)
}

fn decode_headers(
    encoded: &[u8],
) -> Result<BTreeMap<PermittedResponseHeader, Vec<u8>>, IdempotencyError> {
    let Some(count) = encoded.get(..2) else {
        return Err(IdempotencyError::Unavailable);
    };
    let count = usize::from(u16::from_be_bytes([count[0], count[1]]));
    let mut offset = 2;
    let mut headers = BTreeMap::new();
    for _ in 0..count {
        let name = encoded
            .get(offset)
            .copied()
            .and_then(PermittedResponseHeader::from_u8)
            .ok_or(IdempotencyError::Unavailable)?;
        offset += 1;
        let length = encoded
            .get(offset..offset + 4)
            .ok_or(IdempotencyError::Unavailable)?;
        let length = u32::from_be_bytes([length[0], length[1], length[2], length[3]]) as usize;
        offset += 4;
        let value = encoded
            .get(offset..offset + length)
            .ok_or(IdempotencyError::Unavailable)?
            .to_vec();
        offset += length;
        if !valid_header_value(&value) || headers.insert(name, value).is_some() {
            return Err(IdempotencyError::Unavailable);
        }
    }
    if offset != encoded.len() {
        return Err(IdempotencyError::Unavailable);
    }
    Ok(headers)
}

fn valid_header_value(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= MAX_HEADER_VALUE_BYTES
        && value.iter().all(|byte| matches!(byte, b'\t' | 0x20..=0x7e))
}

fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Delete => "DELETE",
        HttpMethod::Get => "GET",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Post => "POST",
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

impl std::fmt::Display for PermittedResponseHeader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::fmt::Debug for HeldResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HeldResponse")
            .field("status", &self.status)
            .field(
                "body",
                &format_args!("<redacted:{} bytes>", self.body.len()),
            )
            .field("headers", &self.headers.keys())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_policy_refuses_every_issuer_the_engine_reserves() {
        for reserved in [
            "",
            EMBEDDED_CALLER_ISSUER,
            HOOK_DELIVERY_ISSUER,
            "urn:registry-breg:any-later-use",
        ] {
            assert_eq!(
                IdempotencyPolicy::new(reserved, DEFAULT_RECEIPT_RETENTION_DAYS),
                Err(IdempotencyError::InvalidInput),
                "{reserved}"
            );
        }
        assert!(IdempotencyPolicy::new(
            "https://issuer.example.test",
            DEFAULT_RECEIPT_RETENTION_DAYS
        )
        .is_ok());
        assert_eq!(
            IdempotencyPolicy::default().caller_issuer(),
            EMBEDDED_CALLER_ISSUER,
            "the embedded policy is built without the configured-issuer check"
        );
    }
}

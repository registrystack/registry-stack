// SPDX-License-Identifier: Apache-2.0

//! Base Registry Engine audit entries and the pre-I/O release gate.
//!
//! Every audited request writes a `request` entry before protected I/O and a
//! `response` entry with its outcome, both through the one platform
//! [`AuditWriter`] the process opened at startup and both correlated by the
//! request id Base Registry Engine minted. A refusal is one `response` entry.
//! A request that goes on to protected I/O holds its attempt as an
//! [`AuditRequest`] until its terminal or refusal entry answers it; one that
//! ends first writes an `unfinished` response, so no attempt stays unpaired.
//! Entries carry keyed references and closed-vocabulary terms, never a raw
//! principal, record id, selector, token, or free text.

use registry_platform_audit::{
    AuditEntry, AuditKeyHasher, AuditProfile, AuditRequest, AuditWriter,
};
use registry_platform_hooks::delivery::{hook_audit_entry, DeliveryAuditRecord};
use serde_json::{json, Value};
#[cfg(test)]
use uuid::Uuid;

use crate::correlation::RequestCorrelation;
use crate::model::HttpMethod;
use crate::postgres::{ActionClaimContext, ClaimContext, ExpectedRegistryIdentity};

/// Schema of request, read, mutation, action, and refusal entries.
pub const AUDIT_SCHEMA: &str = "breg-audit/v3";
/// Schema of hook delivery entries.
pub const HOOK_AUDIT_SCHEMA: &str = "breg-hook-audit/v1";
/// The `event` every hook delivery entry carries.
pub const HOOK_AUDIT_EVENT: &str = "breg.hook-delivery";
/// Keyed-reference domain of the event a hook delivery belongs to.
const HOOK_EVENT_REFERENCE_DOMAIN: &str = "breg-hook-event-v1";
/// Keyed-reference domain of one compiled hook delivery.
const HOOK_DELIVERY_REFERENCE_DOMAIN: &str = "breg-hook-delivery-v1";
/// The process role operator commands append under, beside the runtime's
/// destination.
pub const COMPANION_PROCESS_ROLE: &str = "bregctl";

/// The keyed reference profile and the audit writer one process audits with.
///
/// The profile derives every keyed reference an entry carries; the writer is
/// the single destination this process appends to. Clones share the writer.
#[derive(Clone)]
pub struct RegistryAudit {
    profile: AuditProfile,
    writer: AuditWriter,
}

impl std::fmt::Debug for RegistryAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryAudit")
            .field("profile", &"<redacted>")
            .field("writer", &self.writer)
            .finish()
    }
}

impl RegistryAudit {
    #[must_use]
    pub fn new(profile: AuditProfile, writer: AuditWriter) -> Self {
        Self { profile, writer }
    }

    #[must_use]
    pub fn profile(&self) -> &AuditProfile {
        &self.profile
    }

    #[must_use]
    pub fn writer(&self) -> &AuditWriter {
        &self.writer
    }

    /// Open the audit handle an operator command appends to while the runtime
    /// may hold the configured destination. A file destination becomes its
    /// `bregctl` sibling (`audit.jsonl` becomes `audit.bregctl.jsonl`) under
    /// its own single-writer lock; `stdout` becomes `stderr`, so the
    /// command's own report keeps stdout.
    pub async fn open_companion(
        config: &crate::runtime_config::RuntimeConfig,
    ) -> Result<Self, RegistryAuditError> {
        let profile = config
            .audit_profile()
            .map_err(|_| RegistryAuditError::Unavailable)?;
        let destination = config
            .audit()
            .destination()
            .for_process(COMPANION_PROCESS_ROLE)
            .map_err(|_| RegistryAuditError::Unavailable)?;
        let writer = AuditWriter::open(destination)
            .await
            .map_err(|_| RegistryAuditError::Unavailable)?;
        Ok(Self::new(profile, writer))
    }

    /// Append a `request` entry and return the handle that owes its
    /// `response`. Dropped unanswered, the handle writes `unfinished` as the
    /// response under the entry's schema and correlation.
    pub(crate) async fn begin(
        &self,
        entry: AuditEntry,
        unfinished: Value,
    ) -> Result<AuditRequest, RegistryAuditError> {
        if entry.phase() != registry_platform_audit::AuditPhase::Request {
            return Err(RegistryAuditError::InvalidContext);
        }
        self.writer
            .begin(
                entry.schema(),
                entry.correlation(),
                entry.record().clone(),
                unfinished,
            )
            .await
            .map_err(|_| RegistryAuditError::Unavailable)
    }

    /// Append one entry. A refused append is the audit-unavailable refusal:
    /// the caller performs no protected I/O and releases no disclosure.
    pub async fn append(&self, entry: AuditEntry) -> Result<(), RegistryAuditError> {
        self.writer
            .append(entry)
            .await
            .map_err(|_| RegistryAuditError::Unavailable)
    }
}

/// Verified task grant or delegated actor retained only for minimized, keyed
/// audit projection.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct GrantAuditContext {
    actor_kind: registry_platform_oidc::ActorKind,
    authority: AuditedAuthority,
}
#[derive(Clone, Eq, PartialEq)]
enum AuditedAuthority {
    Grant {
        grant: registry_platform_oidc::GrantClaims,
        actor: Option<String>,
    },
    Delegated {
        principal: String,
        client: String,
        actor: String,
    },
}
impl std::fmt::Debug for GrantAuditContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GrantAuditContext(<redacted>)")
    }
}
impl GrantAuditContext {
    /// Retains a task grant, a verified trusted actor, or both. A direct token
    /// carrying neither yields nothing, so its audit is unchanged.
    pub(crate) fn from_claims(claims: &crate::api::VerifiedRequestClaims) -> Option<Self> {
        let actor = claims.actor_subject().map(str::to_owned);
        let authority = match (claims.grant(), actor) {
            (Some(grant), actor) => AuditedAuthority::Grant {
                grant: grant.clone(),
                actor,
            },
            (None, Some(actor)) => AuditedAuthority::Delegated {
                principal: claims.principal()?.to_owned(),
                client: claims.requester_client()?.to_owned(),
                actor,
            },
            (None, None) => return None,
        };
        Some(Self {
            actor_kind: claims.actor_kind()?,
            authority,
        })
    }

    fn record(
        &self,
        profile: &AuditProfile,
        scope: &str,
        operation: &str,
        allowed: bool,
    ) -> Result<Value, RegistryAuditError> {
        use registry_platform_audit::{AuthorizationAuditEvent, AuthorizationOutcome};
        let hasher = profile.key_hasher();
        let pseudonym = |domain, value| {
            hasher
                .audit_reference_hash(domain, scope, value)
                .map_err(|_| RegistryAuditError::InvalidContext)
        };
        let (principal, client, grant, actor) = match &self.authority {
            AuditedAuthority::Grant { grant, actor } => (
                grant.principal(),
                grant.client(),
                Some(grant),
                actor.as_deref(),
            ),
            AuditedAuthority::Delegated {
                principal,
                client,
                actor,
            } => (
                principal.as_str(),
                client.as_str(),
                None,
                Some(actor.as_str()),
            ),
        };
        // BREG records purpose presence, never the purpose value.
        let event = AuthorizationAuditEvent::without_purpose(
            self.actor_kind.as_str(),
            pseudonym("breg-principal-v1", principal)?,
            pseudonym("breg-client-v1", client)?,
            grant
                .map(|grant| pseudonym("breg-grant-v1", grant.id()))
                .transpose()?,
            grant
                .map(|grant| pseudonym("breg-approver-v1", grant.approver()))
                .transpose()?,
            operation,
            if allowed {
                AuthorizationOutcome::Allowed
            } else {
                AuthorizationOutcome::Denied
            },
            if allowed {
                "authorization.allowed"
            } else {
                "authorization.refused"
            },
        )
        .map_err(|_| RegistryAuditError::InvalidContext)?;
        let mut value =
            serde_json::to_value(event).map_err(|_| RegistryAuditError::InvalidContext)?;
        if let Some(grant) = grant {
            value["sourceIssuer"] = json!(grant.source_issuer());
            value["expiresAt"] = json!(grant.exp());
        }
        // The verified caller acting for the principal, never its raw subject.
        if let Some(actor) = actor {
            value["actorPseudonym"] = json!(pseudonym("breg-actor-v1", actor)?);
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreIoAuditKind {
    Attempt,
    Refusal,
}

pub struct PreIoAudit<'a> {
    pub kind: PreIoAuditKind,
    pub method: HttpMethod,
    pub operation_id: &'a str,
    pub target_record: Option<&'a str>,
    /// Why the refusal happened, drawn from a closed vocabulary the caller
    /// owns. It is a fixed term, never a value read from the request or the
    /// record.
    pub refusal_reason: Option<&'a str>,
    pub correlation: &'a RequestCorrelation,
}

/// Closed method vocabulary for refusals, including methods with no governed
/// route. Extension-method text is caller input and is minimized to `OTHER`.
#[derive(Clone, Copy)]
pub(crate) enum RefusalHttpMethod {
    Governed(HttpMethod),
    Head,
    Put,
    Options,
    Connect,
    Trace,
    Other,
}

impl From<HttpMethod> for RefusalHttpMethod {
    fn from(method: HttpMethod) -> Self {
        Self::Governed(method)
    }
}

impl RefusalHttpMethod {
    pub(crate) fn from_request(method: &axum::http::Method) -> Self {
        match *method {
            axum::http::Method::GET => HttpMethod::Get.into(),
            axum::http::Method::POST => HttpMethod::Post.into(),
            axum::http::Method::PATCH => HttpMethod::Patch.into(),
            axum::http::Method::DELETE => HttpMethod::Delete.into(),
            axum::http::Method::HEAD => Self::Head,
            axum::http::Method::PUT => Self::Put,
            axum::http::Method::OPTIONS => Self::Options,
            axum::http::Method::CONNECT => Self::Connect,
            axum::http::Method::TRACE => Self::Trace,
            _ => Self::Other,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Governed(method) => method_name(method),
            Self::Head => "HEAD",
            Self::Put => "PUT",
            Self::Options => "OPTIONS",
            Self::Connect => "CONNECT",
            Self::Trace => "TRACE",
            Self::Other => "OTHER",
        }
    }
}

/// Closed, value-free causes for a concealed read refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadRefusalReason {
    SurfaceUnavailable,
    ProfileAdmission,
    SelectOverreach,
}

impl ReadRefusalReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SurfaceUnavailable => "surface_unavailable",
            Self::ProfileAdmission => "profile_admission",
            Self::SelectOverreach => "select_overreach",
        }
    }
}

pub(crate) struct HttpRefusalAudit<'a> {
    pub refusal_reason: Option<ReadRefusalReason>,
    pub grant: Option<GrantAuditContext>,
    pub method: RefusalHttpMethod,
    pub operation_id: &'a str,
    pub target_record: Option<&'a str>,
    pub action_id: Option<&'a str>,
    pub principal: Option<&'a str>,
    pub selected_access_profile: Option<&'a str>,
    pub purpose_present: bool,
    pub correlation: &'a RequestCorrelation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RegistryAuditError {
    #[error("audit context is invalid")]
    InvalidContext,
    #[error("audit destination is unavailable")]
    Unavailable,
}

pub(crate) struct TerminalAudit {
    pub grant: Option<GrantAuditContext>,
    pub outcome: TerminalAuditOutcome,
    pub method: HttpMethod,
    pub operation_id: String,
    pub entity_id: Option<String>,
    pub action_id: Option<String>,
    // Legacy internal name: callers supply the activation UUID. Preserve
    // this value as the reference-hash context; emit it as activationId.
    pub package_revision: String,
    pub selected_access_profile: String,
    pub purpose_present: bool,
    pub principal_reference: Option<String>,
    pub record_reference: Option<String>,
    pub record_revision: Option<i64>,
    pub result_count: Option<usize>,
    pub field_set_reference: Option<String>,
    pub correlation: RequestCorrelation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalAuditOutcome {
    Committed,
    Replayed,
    Returned,
    Empty,
    Unresolved,
    Refused,
}

/// Append one minimized refusal before protected record I/O: the single
/// `response` entry of a request that performs no protected I/O, or the one
/// that answers the attempt a request holds. An attempt goes through
/// [`begin_pre_io_audit`], which owes its response, so this refuses one.
pub async fn record_pre_io_audit(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    claims: &ClaimContext,
    event: PreIoAudit<'_>,
) -> Result<(), RegistryAuditError> {
    if event.kind != PreIoAuditKind::Refusal {
        return Err(RegistryAuditError::InvalidContext);
    }
    let record = pre_io_record(audit, expected, claims, &event)?;
    audit
        .append(pre_io_entry(event.kind, event.correlation, record))
        .await
}

/// Append the attempt `request` entry of a request that goes on to protected
/// I/O, and return the handle that owes its `response`. The terminal or
/// refusal entry the request writes under its request id answers it; a
/// request that returns, fails, or is canceled first writes an `unfinished`
/// response naming only the operation and the request when the handle is
/// dropped, so no attempt is left unpaired.
pub(crate) async fn begin_pre_io_audit(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    claims: &ClaimContext,
    event: PreIoAudit<'_>,
) -> Result<AuditRequest, RegistryAuditError> {
    if event.kind != PreIoAuditKind::Attempt {
        return Err(RegistryAuditError::InvalidContext);
    }
    let record = pre_io_record(audit, expected, claims, &event)?;
    begin_attempt(audit, event.correlation, record).await
}

/// Statistics readers may have no entity grant. Their admitted profile is an
/// HTTP authority, not a forged record-read claim context.
pub(crate) async fn begin_statistics_pre_io_audit(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    context: &crate::api::AuthorizedRequestContext,
    event: PreIoAudit<'_>,
) -> Result<AuditRequest, RegistryAuditError> {
    if event.kind != PreIoAuditKind::Attempt
        || event.target_record.is_some()
        || event.operation_id.is_empty()
        || context.principal().is_none()
        || !profile_is_keyed(audit.profile())
    {
        return Err(RegistryAuditError::InvalidContext);
    }
    expected
        .validate()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let principal_reference = context
        .principal()
        .map(|principal| {
            audit.profile().key_hasher().audit_reference_hash(
                "breg-principal-v1",
                &expected.activation_id,
                principal,
            )
        })
        .transpose()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    begin_attempt(
        audit,
        event.correlation,
        json!({
            "phase":"attempt", "method":method_name(event.method),
            "operationId":event.operation_id,
            "requestId":event.correlation.request_id().to_string(),
            "traceId":event.correlation.trace_id().as_str(),
            "activationId":expected.activation_id,
            "selectedAccessProfile":context.selected_profile(),
            "purposePresent":context.purpose().is_some(),
            "principalReference":principal_reference,
            "recordReference":null,
        }),
    )
    .await
}

pub(crate) struct StatisticsTerminalAudit<'a> {
    pub read: ReadTerminalAudit,
    pub dataset_id: &'a str,
    pub period_code: Option<&'a str>,
    pub version: Option<i64>,
    pub status: Option<&'a str>,
    pub content_digest: Option<&'a str>,
}

/// Statistical audit summaries carry references and lifecycle metadata only.
/// Cell values never enter the audit serializer.
pub(crate) fn statistics_terminal_entry(
    profile: &AuditProfile,
    summary: StatisticsTerminalAudit<'_>,
) -> Result<AuditEntry, RegistryAuditError> {
    let correlation = summary.read.terminal.correlation.request_id().to_string();
    let package_revision = summary.read.terminal.package_revision.clone();
    let mut record = terminal_record(summary.read.terminal, profile)?;
    let hasher = profile.key_hasher();
    let dataset_reference = hasher
        .audit_reference_hash(
            "breg-statistical-dataset-v1",
            &package_revision,
            summary.dataset_id,
        )
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    record.insert(
        "statisticalDatasetReference".to_owned(),
        json!(dataset_reference),
    );
    if let Some(period) = summary.period_code {
        let reference = hasher
            .audit_reference_hash("breg-statistical-period-v1", &package_revision, period)
            .map_err(|_| RegistryAuditError::InvalidContext)?;
        record.insert("periodReference".to_owned(), json!(reference));
    }
    for (field, value) in [
        ("version", summary.version.map(|v| json!(v))),
        ("status", summary.status.map(|v| json!(v))),
        ("contentDigest", summary.content_digest.map(|v| json!(v))),
        (
            "queryReference",
            summary.read.query_reference.map(|v| json!(v)),
        ),
        (
            "rowBoundaryReference",
            summary.read.row_boundary_reference.map(|v| json!(v)),
        ),
    ] {
        if let Some(value) = value {
            record.insert(field.to_owned(), value);
        }
    }
    Ok(response_entry(correlation, record))
}

fn pre_io_record(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    claims: &ClaimContext,
    event: &PreIoAudit<'_>,
) -> Result<Value, RegistryAuditError> {
    let profile = audit.profile();
    if event.operation_id.is_empty() || !profile_is_keyed(profile) {
        return Err(RegistryAuditError::InvalidContext);
    }
    expected
        .validate()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let key_hasher = profile.key_hasher();
    let principal_reference = claims
        .principal()
        .map(|principal| {
            key_hasher.audit_reference_hash("breg-principal-v1", &expected.activation_id, principal)
        })
        .transpose()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let record_reference = event
        .target_record
        .map(|record| {
            key_hasher.audit_reference_hash("breg-record-v1", &expected.activation_id, record)
        })
        .transpose()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let mut record = json!({
        "phase": pre_io_phase_name(event.kind),
        "method": method_name(event.method),
        "operationId": event.operation_id,
        "requestId": event.correlation.request_id().to_string(),
        "traceId": event.correlation.trace_id().as_str(),
        "activationId": expected.activation_id,
        "selectedAccessProfile": claims.access_profile(),
        "purposePresent": claims.purpose().is_some(),
        "principalReference": principal_reference,
        "recordReference": record_reference,
    });
    if event.kind == PreIoAuditKind::Refusal {
        if let Some(grant) = claims.grant_audit() {
            record["authorization"] =
                grant.record(profile, &expected.activation_id, event.operation_id, false)?;
        }
    }
    insert_refusal_reason(&mut record, event.refusal_reason);
    Ok(record)
}

/// [`record_pre_io_audit`] for a governed action request.
pub(crate) async fn record_action_pre_io_audit(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    claims: &ActionClaimContext,
    event: PreIoAudit<'_>,
) -> Result<(), RegistryAuditError> {
    if event.kind != PreIoAuditKind::Refusal {
        return Err(RegistryAuditError::InvalidContext);
    }
    let record = action_pre_io_record(audit, expected, claims, &event)?;
    audit
        .append(pre_io_entry(event.kind, event.correlation, record))
        .await
}

/// [`begin_pre_io_audit`] for a governed action request.
pub(crate) async fn begin_action_pre_io_audit(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    claims: &ActionClaimContext,
    event: PreIoAudit<'_>,
) -> Result<AuditRequest, RegistryAuditError> {
    if event.kind != PreIoAuditKind::Attempt {
        return Err(RegistryAuditError::InvalidContext);
    }
    let record = action_pre_io_record(audit, expected, claims, &event)?;
    begin_attempt(audit, event.correlation, record).await
}

fn action_pre_io_record(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    claims: &ActionClaimContext,
    event: &PreIoAudit<'_>,
) -> Result<Value, RegistryAuditError> {
    if event.method != HttpMethod::Post {
        return Err(RegistryAuditError::InvalidContext);
    }
    action_resource_pre_io_record(audit, expected, claims, event)
}

fn proposal_pre_io_record(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    claims: &ActionClaimContext,
    event: &PreIoAudit<'_>,
) -> Result<Value, RegistryAuditError> {
    let prefix = format!("proposals.{}.", claims.action_id());
    let operation = event
        .operation_id
        .strip_prefix(&prefix)
        .ok_or(RegistryAuditError::InvalidContext)?;
    let allowed = match event.method {
        HttpMethod::Get => matches!(
            operation,
            "get" | "list" | "get-review-context" | "get-review-status"
        ),
        HttpMethod::Post => matches!(
            operation,
            "start"
                | "edit"
                | "submit"
                | "revise"
                | "rebase"
                | "retry"
                | "cancel"
                | "apply"
                | "get-task-grant-context"
        ),
        HttpMethod::Patch | HttpMethod::Delete => operation == "edit",
    };
    if !allowed {
        return Err(RegistryAuditError::InvalidContext);
    }
    action_resource_pre_io_record(audit, expected, claims, event)
}

pub(crate) async fn begin_proposal_pre_io_audit(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    claims: &ActionClaimContext,
    event: PreIoAudit<'_>,
) -> Result<AuditRequest, RegistryAuditError> {
    if event.kind != PreIoAuditKind::Attempt {
        return Err(RegistryAuditError::InvalidContext);
    }
    let record = proposal_pre_io_record(audit, expected, claims, &event)?;
    begin_attempt(audit, event.correlation, record).await
}

pub(crate) async fn record_proposal_pre_io_audit(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    claims: &ActionClaimContext,
    event: PreIoAudit<'_>,
) -> Result<(), RegistryAuditError> {
    if event.kind != PreIoAuditKind::Refusal {
        return Err(RegistryAuditError::InvalidContext);
    }
    let record = proposal_pre_io_record(audit, expected, claims, &event)?;
    audit
        .append(pre_io_entry(event.kind, event.correlation, record))
        .await
}

fn action_resource_pre_io_record(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    claims: &ActionClaimContext,
    event: &PreIoAudit<'_>,
) -> Result<Value, RegistryAuditError> {
    let profile = audit.profile();
    if event.operation_id.is_empty() || event.target_record.is_some() || !profile_is_keyed(profile)
    {
        return Err(RegistryAuditError::InvalidContext);
    }
    expected
        .validate()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let key_hasher = profile.key_hasher();
    let principal_reference = key_hasher
        .audit_reference_hash(
            "breg-principal-v1",
            &expected.activation_id,
            claims.principal(),
        )
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let mut record = json!({
        "phase": pre_io_phase_name(event.kind),
        "method": method_name(event.method),
        "operationId": event.operation_id,
        "requestId": event.correlation.request_id().to_string(),
        "traceId": event.correlation.trace_id().as_str(),
        "activationId": expected.activation_id,
        "selectedAccessProfile": claims.access_profile(),
        "purposePresent": claims.purpose().is_some(),
        "principalReference": principal_reference,
        "actionId": claims.action_id(),
    });
    insert_refusal_reason(&mut record, event.refusal_reason);
    Ok(record)
}

/// Append `record` as the attempt `request` entry of `correlation`.
async fn begin_attempt(
    audit: &RegistryAudit,
    correlation: &RequestCorrelation,
    record: Value,
) -> Result<AuditRequest, RegistryAuditError> {
    let unfinished = unfinished_record(&record);
    audit
        .writer()
        .begin(
            AUDIT_SCHEMA,
            correlation.request_id().to_string(),
            record,
            unfinished,
        )
        .await
        .map_err(|_| RegistryAuditError::Unavailable)
}

/// The `response` an attempt writes when its request ends without a
/// terminal or refusal entry: the operation and request it answers, and
/// nothing the request read or was about to write.
fn unfinished_record(attempt: &Value) -> Value {
    let mut record = serde_json::Map::new();
    record.insert("phase".to_owned(), json!("unfinished"));
    for field in [
        "method",
        "operationId",
        "requestId",
        "traceId",
        "activationId",
        "actionId",
    ] {
        if let Some(value) = attempt.get(field) {
            record.insert(field.to_owned(), value.clone());
        }
    }
    Value::Object(record)
}

fn pre_io_phase_name(kind: PreIoAuditKind) -> &'static str {
    match kind {
        PreIoAuditKind::Attempt => "attempt",
        PreIoAuditKind::Refusal => "refusal",
    }
}

fn pre_io_entry(
    kind: PreIoAuditKind,
    correlation: &RequestCorrelation,
    record: Value,
) -> AuditEntry {
    let correlation = correlation.request_id().to_string();
    match kind {
        PreIoAuditKind::Attempt => AuditEntry::request(AUDIT_SCHEMA, correlation, record),
        PreIoAuditKind::Refusal => AuditEntry::response(AUDIT_SCHEMA, correlation, record),
    }
}

/// Append a minimized HTTP-layer mutation refusal when authorization failed
/// before a forged `ClaimContext` would be safe to construct. It is the single
/// `response` entry of a request that performs no protected I/O.
pub(crate) async fn record_http_refusal_audit(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    event: HttpRefusalAudit<'_>,
) -> Result<(), RegistryAuditError> {
    record_http_refusal_audit_inner(audit, expected, event, None).await
}

async fn record_http_refusal_audit_inner(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    event: HttpRefusalAudit<'_>,
    attachment_slot: Option<&str>,
) -> Result<(), RegistryAuditError> {
    let profile = audit.profile();
    if event.operation_id.is_empty()
        || event.action_id.is_some_and(str::is_empty)
        || !profile_is_keyed(profile)
    {
        return Err(RegistryAuditError::InvalidContext);
    }
    expected
        .validate()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let key_hasher = profile.key_hasher();
    let principal_reference = event
        .principal
        .map(|principal| {
            key_hasher.audit_reference_hash("breg-principal-v1", &expected.activation_id, principal)
        })
        .transpose()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let record_reference = event
        .target_record
        .map(|record| {
            key_hasher.audit_reference_hash("breg-record-v1", &expected.activation_id, record)
        })
        .transpose()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let mut record = serde_json::Map::from_iter([
        ("phase".to_owned(), Value::String("refusal".to_owned())),
        (
            "method".to_owned(),
            Value::String(event.method.name().to_owned()),
        ),
        (
            "operationId".to_owned(),
            Value::String(event.operation_id.to_owned()),
        ),
        (
            "requestId".to_owned(),
            Value::String(event.correlation.request_id().to_string()),
        ),
        (
            "traceId".to_owned(),
            Value::String(event.correlation.trace_id().as_str().to_owned()),
        ),
        (
            "activationId".to_owned(),
            Value::String(expected.activation_id.clone()),
        ),
        (
            "purposePresent".to_owned(),
            Value::Bool(event.purpose_present),
        ),
    ]);
    if let Some(grant) = &event.grant {
        record.insert(
            "authorization".to_owned(),
            grant.record(profile, &expected.activation_id, event.operation_id, false)?,
        );
    }
    if let Some(reason) = event.refusal_reason {
        record.insert(
            "refusalReason".to_owned(),
            Value::String(reason.as_str().to_owned()),
        );
    }
    if let Some(slot_id) = attachment_slot {
        record.insert(
            "attachment".to_owned(),
            serde_json::json!({"slotId": slot_id}),
        );
    }
    if let Some(selected_access_profile) = event.selected_access_profile {
        record.insert(
            "selectedAccessProfile".to_owned(),
            Value::String(selected_access_profile.to_owned()),
        );
    }
    if let Some(principal_reference) = principal_reference {
        record.insert(
            "principalReference".to_owned(),
            Value::String(principal_reference),
        );
    }
    if let Some(record_reference) = record_reference {
        record.insert(
            "recordReference".to_owned(),
            Value::String(record_reference),
        );
    }
    if let Some(action_id) = event.action_id {
        record.insert("actionId".to_owned(), Value::String(action_id.to_owned()));
    }
    audit
        .append(response_entry(
            event.correlation.request_id().to_string(),
            record,
        ))
        .await
}

/// Whether the profile derives keyed references. Base Registry Engine refuses
/// to audit, and therefore to serve, under an unkeyed development profile.
pub(crate) fn profile_is_keyed(profile: &AuditProfile) -> bool {
    matches!(profile.key_hasher(), AuditKeyHasher::Keyed(_))
}

fn response_entry(correlation: String, record: serde_json::Map<String, Value>) -> AuditEntry {
    AuditEntry::response(AUDIT_SCHEMA, correlation, Value::Object(record))
}

/// The `response` entry of an entity or action outcome. A mutation builds it
/// inside its transaction and appends it after the commit; a read builds it
/// once the result is held and appends it before the result is returned.
pub(crate) fn terminal_entry(
    profile: &AuditProfile,
    terminal: TerminalAudit,
) -> Result<AuditEntry, RegistryAuditError> {
    if !matches!(
        (&terminal.entity_id, &terminal.action_id),
        (Some(_), None) | (None, Some(_))
    ) || terminal.entity_id.as_deref().is_some_and(str::is_empty)
        || terminal.action_id.as_deref().is_some_and(str::is_empty)
    {
        return Err(RegistryAuditError::InvalidContext);
    }
    let correlation = terminal.correlation.request_id().to_string();
    Ok(response_entry(
        correlation,
        terminal_record(terminal, profile)?,
    ))
}

/// Link an action commit or replay to its retained application provenance.
/// The reference is derived by the server, never copied from an HTTP input.
pub(crate) fn action_terminal_entry(
    profile: &AuditProfile,
    terminal: TerminalAudit,
    application_reference: &str,
) -> Result<AuditEntry, RegistryAuditError> {
    let correlation = terminal.correlation.request_id().to_string();
    let record = action_terminal_record(terminal, application_reference, profile)?;
    Ok(response_entry(correlation, record))
}

fn action_terminal_record(
    terminal: TerminalAudit,
    application_reference: &str,
    profile: &AuditProfile,
) -> Result<serde_json::Map<String, Value>, RegistryAuditError> {
    if terminal.entity_id.is_some()
        || terminal.action_id.as_deref().is_none_or(|id| id.is_empty())
        || !matches!(
            terminal.outcome,
            TerminalAuditOutcome::Committed | TerminalAuditOutcome::Replayed
        )
        || application_reference.is_empty()
        || application_reference.len() > 512
    {
        return Err(RegistryAuditError::InvalidContext);
    }
    let mut record = terminal_record(terminal, profile)?;
    record.insert(
        "applicationReference".to_owned(),
        Value::String(application_reference.to_owned()),
    );
    Ok(record)
}

/// The entry of one hook delivery transition. The attempt is the `request`
/// entry of one delivery attempt; its terminal outcome and an operator replay
/// or discard are `response` entries. The correlation is the attempt
/// identity: the keyed event and delivery references, the generation, and the
/// attempt number. The shared delivery core owns the record shape and the
/// request or response filing; this adds the keyed references.
pub(crate) fn hook_entry(
    profile: &AuditProfile,
    record: &DeliveryAuditRecord<'_>,
) -> Result<AuditEntry, RegistryAuditError> {
    if !record.has_valid_shape() || !profile_is_keyed(profile) {
        return Err(RegistryAuditError::InvalidContext);
    }
    let key_hasher = profile.key_hasher();
    let event_reference = key_hasher
        .audit_reference_hash(
            HOOK_EVENT_REFERENCE_DOMAIN,
            record.package_revision,
            &record.event_id.to_string(),
        )
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let delivery_reference = key_hasher
        .audit_reference_hash(
            HOOK_DELIVERY_REFERENCE_DOMAIN,
            record.package_revision,
            record.compiled_delivery_id,
        )
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let correlation_base = format!(
        "{event_reference}.{delivery_reference}.{}.{}",
        record.generation, record.attempt
    );
    let fields = serde_json::Map::from_iter([
        (
            "activationId".to_owned(),
            Value::String(record.package_revision.to_owned()),
        ),
        ("eventReference".to_owned(), Value::String(event_reference)),
        (
            "deliveryReference".to_owned(),
            Value::String(delivery_reference),
        ),
    ]);
    hook_audit_entry(
        HOOK_AUDIT_SCHEMA,
        HOOK_AUDIT_EVENT,
        &correlation_base,
        fields,
        record,
    )
    .map_err(|_| RegistryAuditError::InvalidContext)
}

fn terminal_record(
    terminal: TerminalAudit,
    profile: &AuditProfile,
) -> Result<serde_json::Map<String, Value>, RegistryAuditError> {
    let authorization = terminal
        .grant
        .as_ref()
        .map(|grant| {
            grant.record(
                profile,
                &terminal.package_revision,
                &terminal.operation_id,
                terminal.outcome != TerminalAuditOutcome::Refused,
            )
        })
        .transpose()?;
    let mut record = serde_json::Map::from_iter([
        ("phase".to_owned(), Value::String("terminal".to_owned())),
        (
            "outcome".to_owned(),
            Value::String(
                match terminal.outcome {
                    TerminalAuditOutcome::Committed => "committed",
                    TerminalAuditOutcome::Replayed => "replayed",
                    TerminalAuditOutcome::Returned => "returned",
                    TerminalAuditOutcome::Empty => "empty",
                    TerminalAuditOutcome::Unresolved => "unresolved",
                    TerminalAuditOutcome::Refused => "refused",
                }
                .to_owned(),
            ),
        ),
        (
            "method".to_owned(),
            Value::String(method_name(terminal.method).to_owned()),
        ),
        (
            "operationId".to_owned(),
            Value::String(terminal.operation_id),
        ),
        (
            "requestId".to_owned(),
            Value::String(terminal.correlation.request_id().to_string()),
        ),
        (
            "traceId".to_owned(),
            Value::String(terminal.correlation.trace_id().as_str().to_owned()),
        ),
        (
            "activationId".to_owned(),
            Value::String(terminal.package_revision),
        ),
        (
            "selectedAccessProfile".to_owned(),
            Value::String(terminal.selected_access_profile),
        ),
        (
            "purposePresent".to_owned(),
            Value::Bool(terminal.purpose_present),
        ),
    ]);
    if let Some(authorization) = authorization {
        record.insert("authorization".to_owned(), authorization);
    }
    if let Some(entity_id) = terminal.entity_id {
        record.insert("entityId".to_owned(), Value::String(entity_id));
    }
    if let Some(action_id) = terminal.action_id {
        record.insert("actionId".to_owned(), Value::String(action_id));
    }
    if let Some(principal_reference) = terminal.principal_reference {
        record.insert(
            "principalReference".to_owned(),
            Value::String(principal_reference),
        );
    }
    if let Some(record_reference) = terminal.record_reference {
        record.insert(
            "recordReference".to_owned(),
            Value::String(record_reference),
        );
    }
    if let Some(record_revision) = terminal.record_revision {
        record.insert("recordRevision".to_owned(), json!(record_revision));
    }
    if let Some(result_count) = terminal.result_count {
        record.insert("resultCount".to_owned(), json!(result_count));
    }
    if let Some(field_set_reference) = terminal.field_set_reference {
        record.insert(
            "fieldSetReference".to_owned(),
            Value::String(field_set_reference),
        );
    }
    Ok(record)
}

pub(crate) struct ReadTerminalAudit {
    pub terminal: TerminalAudit,
    pub query_reference: Option<String>,
    pub row_boundary_reference: Option<String>,
}

pub(crate) fn read_terminal_entry(
    profile: &AuditProfile,
    read_terminal: ReadTerminalAudit,
) -> Result<AuditEntry, RegistryAuditError> {
    let correlation = read_terminal.terminal.correlation.request_id().to_string();
    let mut terminal = terminal_record(read_terminal.terminal, profile)?;
    if let Some(query_reference) = read_terminal.query_reference {
        terminal.insert("queryReference".to_owned(), Value::String(query_reference));
    }
    if let Some(row_boundary_reference) = read_terminal.row_boundary_reference {
        terminal.insert(
            "rowBoundaryReference".to_owned(),
            Value::String(row_boundary_reference),
        );
    }
    Ok(response_entry(correlation, terminal))
}

/// Name why a refusal happened, when the caller has a closed-vocabulary term
/// for it. The audit entry stays minimized: the term is fixed by the code
/// that raised the refusal and carries no request or record value.
fn insert_refusal_reason(record: &mut Value, reason: Option<&str>) {
    let Some(reason) = reason else {
        return;
    };
    if let Some(object) = record.as_object_mut() {
        object.insert("refusalReason".to_owned(), Value::String(reason.to_owned()));
    }
}

fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Delete => "DELETE",
        HttpMethod::Get => "GET",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Post => "POST",
    }
}

/// In-memory audit destinations for tests: a capture that records every
/// accepted entry and can be told to refuse appends from a chosen point.
#[cfg(any(test, feature = "postgres-test"))]
#[doc(hidden)]
pub mod test_support {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use registry_platform_audit::{AuditProfile, AuditWriter};
    use serde_json::Value;

    use super::RegistryAudit;

    #[derive(Default)]
    struct CaptureState {
        bytes: Vec<u8>,
        /// Entries still accepted before every later append fails. `None`
        /// accepts every entry.
        remaining: Option<usize>,
        /// The envelope schema and record phase of the first entry refused
        /// regardless of `remaining`.
        refuse: Option<(String, String)>,
        /// Number of configured schema/phase refusals actually reached. Tests
        /// use this to prove a protected operation attempted its audit gate
        /// before a deliberately denied database read.
        matched_refusals: usize,
        /// Every writer recording here, so a read can wait for the entries
        /// they write when a request handle is dropped.
        writers: Vec<AuditWriter>,
    }

    /// The entries one [`RegistryAudit`] accepted, in append order.
    #[derive(Clone, Default)]
    pub struct AuditCapture(Arc<Mutex<CaptureState>>);

    struct CaptureSink(Arc<Mutex<CaptureState>>);

    impl Write for CaptureSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut state = self.0.lock().expect("audit capture lock");
            let lines = bytes.iter().filter(|byte| **byte == b'\n').count();
            if let Some((schema, phase)) = &state.refuse {
                let refused = bytes
                    .split(|byte| *byte == b'\n')
                    .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
                    .any(|entry| entry["schema"] == *schema && entry["record"]["phase"] == *phase);
                if refused {
                    state.refuse = None;
                    state.remaining = Some(0);
                    state.matched_refusals += 1;
                    return Err(io::Error::other("audit capture refuses this entry"));
                }
            }
            match state.remaining {
                Some(remaining) if remaining < lines.max(1) => {
                    state.remaining = Some(0);
                    Err(io::Error::other("audit capture refuses this entry"))
                }
                Some(remaining) => {
                    state.remaining = Some(remaining - lines);
                    state.bytes.extend_from_slice(bytes);
                    Ok(bytes.len())
                }
                None => {
                    state.bytes.extend_from_slice(bytes);
                    Ok(bytes.len())
                }
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl AuditCapture {
        /// Every accepted entry, parsed.
        #[must_use]
        pub fn entries(&self) -> Vec<Value> {
            let writers = self.0.lock().expect("audit capture lock").writers.clone();
            for writer in &writers {
                writer.wait_for_detached_entries();
            }
            let state = self.0.lock().expect("audit capture lock");
            String::from_utf8(state.bytes.clone())
                .expect("audit lines are UTF-8")
                .lines()
                .map(|line| serde_json::from_str(line).expect("audit line is JSON"))
                .collect()
        }

        /// Accept `accepted` more entries, then refuse every later append.
        /// The writer stops at its first refused append, as it does when a
        /// real destination fails.
        pub fn fail_after(&self, accepted: usize) {
            self.0.lock().expect("audit capture lock").remaining = Some(accepted);
        }

        /// Accept every later entry again. A writer that already refused an
        /// append stays failed; only a writer opened afterwards appends.
        pub fn restore(&self) {
            let mut state = self.0.lock().expect("audit capture lock");
            state.remaining = None;
            state.refuse = None;
        }

        /// Accept entries until the first one carrying envelope `schema` and
        /// record `phase`, then refuse it and every later append.
        pub fn fail_on(&self, schema: &str, phase: &str) {
            self.0.lock().expect("audit capture lock").refuse =
                Some((schema.to_owned(), phase.to_owned()));
        }

        /// Configured schema/phase refusals the capture actually reached.
        #[must_use]
        pub fn matched_refusal_count(&self) -> usize {
            self.0.lock().expect("audit capture lock").matched_refusals
        }

        /// Another [`RegistryAudit`] recording into this capture, as a second
        /// process appending to the same destination would.
        #[must_use]
        pub fn audit(&self, profile: AuditProfile) -> RegistryAudit {
            let writer = AuditWriter::from_line_sink(Box::new(CaptureSink(Arc::clone(&self.0))));
            self.0
                .lock()
                .expect("audit capture lock")
                .writers
                .push(writer.clone());
            RegistryAudit::new(profile, writer)
        }
    }

    /// A [`RegistryAudit`] whose writer records to memory.
    #[must_use]
    pub fn capturing(profile: AuditProfile) -> (RegistryAudit, AuditCapture) {
        let capture = AuditCapture::default();
        (capture.audit(profile), capture)
    }
}

#[cfg(test)]
mod action_terminal_tests {
    use super::*;

    fn profile() -> AuditProfile {
        AuditProfile::production_from_secret_bytes(vec![9; 32].into()).unwrap()
    }

    fn terminal(outcome: TerminalAuditOutcome) -> TerminalAudit {
        TerminalAudit {
            grant: None,
            outcome,
            method: HttpMethod::Post,
            operation_id: "actions.register.invoke".to_owned(),
            entity_id: None,
            action_id: Some("register".to_owned()),
            package_revision: "package-revision".to_owned(),
            selected_access_profile: "registrar".to_owned(),
            purpose_present: true,
            principal_reference: Some("protected-principal".to_owned()),
            record_reference: None,
            record_revision: None,
            result_count: Some(0),
            field_set_reference: None,
            correlation: RequestCorrelation::breg_created(),
        }
    }

    #[test]
    fn action_commit_and_replay_audits_retain_application_without_response_or_record_data() {
        for outcome in [
            TerminalAuditOutcome::Committed,
            TerminalAuditOutcome::Replayed,
        ] {
            let record =
                action_terminal_record(terminal(outcome), "protected-application", &profile())
                    .expect("action terminal has protected application provenance");
            assert_eq!(record["applicationReference"], "protected-application");
            assert_eq!(record["actionId"], "register");
            assert_eq!(record["resultCount"], 0);
            for excluded in ["response", "input", "recordId", "entityId", "applicationId"] {
                assert!(!record.contains_key(excluded));
            }
        }
    }

    #[test]
    fn action_application_audit_rejects_entity_or_uncommitted_context() {
        let mut entity = terminal(TerminalAuditOutcome::Committed);
        entity.entity_id = Some("item".to_owned());
        assert_eq!(
            action_terminal_record(entity, "protected-application", &profile()),
            Err(RegistryAuditError::InvalidContext)
        );
        assert_eq!(
            action_terminal_record(
                terminal(TerminalAuditOutcome::Returned),
                "protected-application",
                &profile()
            ),
            Err(RegistryAuditError::InvalidContext)
        );
        assert_eq!(
            action_terminal_record(terminal(TerminalAuditOutcome::Committed), "", &profile()),
            Err(RegistryAuditError::InvalidContext)
        );
    }

    #[test]
    fn terminal_entry_is_a_response_correlated_by_the_request_id_without_a_record_schema() {
        let outcome = terminal(TerminalAuditOutcome::Committed);
        let request_id = outcome.correlation.request_id().to_string();
        let entry = action_terminal_entry(&profile(), outcome, "protected-application")
            .expect("action terminal entry");
        assert_eq!(entry.schema(), AUDIT_SCHEMA);
        assert_eq!(entry.phase(), registry_platform_audit::AuditPhase::Response);
        assert_eq!(entry.correlation(), request_id);
        assert!(entry.record().get("schema").is_none());
        assert_eq!(entry.record()["phase"], "terminal");
        assert_eq!(entry.record()["outcome"], "committed");
    }

    #[test]
    fn hook_attempt_and_terminal_share_the_attempt_identity() {
        use registry_platform_hooks::delivery::{
            DeliveryAuditDisposition as D, DeliveryAuditOutcome as O, DeliveryAuditPhase as P,
        };
        let event_id = Uuid::new_v4();
        let event = |phase, outcome, disposition| DeliveryAuditRecord {
            event_id,
            compiled_delivery_id: "delivery",
            package_revision: "package-revision",
            generation: 1,
            attempt: 2,
            phase,
            outcome,
            disposition,
        };
        let attempt = hook_entry(&profile(), &event(P::Attempt, O::AttemptStarted, D::Leased))
            .expect("attempt entry");
        let terminal = hook_entry(&profile(), &event(P::Terminal, O::Delivered, D::Delivered))
            .expect("terminal entry");
        assert_eq!(
            attempt.phase(),
            registry_platform_audit::AuditPhase::Request
        );
        assert_eq!(
            terminal.phase(),
            registry_platform_audit::AuditPhase::Response
        );
        assert_eq!(attempt.correlation(), terminal.correlation());
        assert_eq!(attempt.schema(), HOOK_AUDIT_SCHEMA);
        assert_eq!(attempt.record()["event"], HOOK_AUDIT_EVENT);
        assert_eq!(attempt.record()["activationId"], "package-revision");
        assert!(!attempt.correlation().contains(&event_id.to_string()));
        assert!(!attempt.correlation().contains("delivery."));
    }

    #[test]
    fn hook_discard_is_answered_under_a_phase_scoped_identity() {
        use registry_platform_hooks::delivery::{
            DeliveryAuditDisposition as D, DeliveryAuditOutcome as O, DeliveryAuditPhase as P,
        };
        let event_id = Uuid::new_v4();
        let event = |phase, outcome, disposition| DeliveryAuditRecord {
            event_id,
            compiled_delivery_id: "delivery",
            package_revision: "package-revision",
            generation: 2,
            attempt: 1,
            phase,
            outcome,
            disposition,
        };
        let request = hook_entry(
            &profile(),
            &event(P::Discard, O::DiscardRequested, D::DiscardPending),
        )
        .expect("discard request entry");
        let response = hook_entry(
            &profile(),
            &event(P::Discard, O::DiscardCommitted, D::Discarded),
        )
        .expect("discard response entry");
        let delivery_attempt =
            hook_entry(&profile(), &event(P::Attempt, O::AttemptStarted, D::Leased))
                .expect("delivery attempt entry");

        assert_eq!(request.correlation(), response.correlation());
        assert!(request.correlation().ends_with(".discard"));
        assert_ne!(request.correlation(), delivery_attempt.correlation());
    }

    #[test]
    fn an_interrupted_hook_terminal_of_unknown_fate_is_recorded_only_as_unknown() {
        use registry_platform_hooks::delivery::{
            DeliveryAuditDisposition as D, DeliveryAuditOutcome as O, DeliveryAuditPhase as P,
        };
        let event = |outcome, disposition| DeliveryAuditRecord {
            event_id: Uuid::new_v4(),
            compiled_delivery_id: "delivery",
            package_revision: "package-revision",
            generation: 1,
            attempt: 1,
            phase: P::Terminal,
            outcome,
            disposition,
        };
        let entry = hook_entry(&profile(), &event(O::WorkerInterrupted, D::Unknown))
            .expect("interrupted terminal of unknown fate");
        assert_eq!(entry.record()["disposition"], "unknown");
        // Only an interruption may leave the disposition unknown.
        assert_eq!(
            hook_entry(&profile(), &event(O::Delivered, D::Unknown)).err(),
            Some(RegistryAuditError::InvalidContext)
        );
    }

    #[test]
    fn a_hook_entry_is_refused_under_an_unkeyed_profile() {
        use registry_platform_hooks::delivery::{
            DeliveryAuditDisposition as D, DeliveryAuditOutcome as O, DeliveryAuditPhase as P,
        };
        let record = DeliveryAuditRecord {
            event_id: Uuid::new_v4(),
            compiled_delivery_id: "delivery",
            package_revision: "package-revision",
            generation: 1,
            attempt: 1,
            phase: P::Attempt,
            outcome: O::AttemptStarted,
            disposition: D::Leased,
        };
        assert_eq!(
            hook_entry(&AuditProfile::unkeyed_dev_only(), &record).err(),
            Some(RegistryAuditError::InvalidContext)
        );
    }

    #[test]
    fn unkeyed_profile_is_refused_by_the_key_hasher_check_alone() {
        assert!(profile_is_keyed(&profile()));
        assert!(!profile_is_keyed(&AuditProfile::unkeyed_dev_only()));
    }

    #[tokio::test]
    async fn capture_refuses_appends_after_its_budget_and_the_writer_stays_stopped() {
        let (audit, capture) = test_support::capturing(profile());
        capture.fail_after(1);
        let entry = || {
            registry_platform_audit::AuditEntry::request(
                AUDIT_SCHEMA,
                "c",
                json!({"phase": "attempt"}),
            )
        };
        assert_eq!(audit.append(entry()).await, Ok(()));
        assert_eq!(
            audit.append(entry()).await,
            Err(RegistryAuditError::Unavailable)
        );
        assert_eq!(
            audit.append(entry()).await,
            Err(RegistryAuditError::Unavailable)
        );
        assert_eq!(capture.entries().len(), 1);
    }
}

#[cfg(test)]
mod delegated_actor_audit_tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::api::VerifiedRequestClaims;

    const ACTOR: &str = "00000000-0000-4000-8000-0000000000aa";
    const REVISION: &str = "package-revision";

    fn profile() -> AuditProfile {
        AuditProfile::production_from_secret_bytes(vec![9; 32].into()).unwrap()
    }

    fn claims(actor: Option<&str>) -> VerifiedRequestClaims {
        VerifiedRequestClaims::authenticated(
            "sub",
            "citizen-subject",
            BTreeSet::new(),
            Some("citizen-self-service".to_owned()),
            BTreeMap::new(),
        )
        .unwrap()
        .with_contextual_authority(
            Some(registry_platform_oidc::ActorKind::Agent),
            Some("agent-client".to_owned()),
            actor.map(str::to_owned),
            None,
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn terminal(grant: Option<GrantAuditContext>, outcome: TerminalAuditOutcome) -> TerminalAudit {
        TerminalAudit {
            grant,
            outcome,
            method: HttpMethod::Post,
            operation_id: "records.correction-request.create".to_owned(),
            entity_id: Some("correction-request".to_owned()),
            action_id: None,
            package_revision: REVISION.to_owned(),
            selected_access_profile: "standing-agent".to_owned(),
            purpose_present: true,
            principal_reference: None,
            record_reference: None,
            record_revision: Some(1),
            result_count: None,
            field_set_reference: None,
            correlation: RequestCorrelation::breg_created(),
        }
    }

    #[test]
    fn delegated_actor_is_recorded_as_a_keyed_pseudonym_with_its_kind() {
        let profile = profile();
        let hasher = profile.key_hasher();
        let context = GrantAuditContext::from_claims(&claims(Some(ACTOR)))
            .expect("a verified trusted actor is retained for audit");
        for (outcome, expected) in [
            (TerminalAuditOutcome::Committed, "allowed"),
            (TerminalAuditOutcome::Refused, "denied"),
        ] {
            let record = terminal_record(terminal(Some(context.clone()), outcome), &profile)
                .expect("delegated terminal record");
            let authorization = &record["authorization"];
            assert_eq!(
                authorization["actorPseudonym"],
                hasher
                    .audit_reference_hash("breg-actor-v1", REVISION, ACTOR)
                    .unwrap()
            );
            assert_eq!(
                authorization["principalPseudonym"],
                hasher
                    .audit_reference_hash("breg-principal-v1", REVISION, "citizen-subject")
                    .unwrap()
            );
            assert_eq!(
                authorization["clientPseudonym"],
                hasher
                    .audit_reference_hash("breg-client-v1", REVISION, "agent-client")
                    .unwrap()
            );
            assert_eq!(authorization["actorKind"], "agent");
            assert_eq!(authorization["outcome"], expected);
            for absent in [
                "grantPseudonym",
                "approverPseudonym",
                "sourceIssuer",
                "expiresAt",
                "purpose",
            ] {
                assert!(authorization.get(absent).is_none(), "{absent} is absent");
            }
            let rendered = Value::Object(record).to_string();
            for raw in [
                ACTOR,
                "citizen-subject",
                "agent-client",
                "citizen-self-service",
            ] {
                assert!(!rendered.contains(raw), "audit must not contain {raw}");
            }
        }
    }

    #[test]
    fn direct_token_without_grant_or_actor_records_no_authorization() {
        assert!(GrantAuditContext::from_claims(&claims(None)).is_none());
        let record = terminal_record(terminal(None, TerminalAuditOutcome::Committed), &profile())
            .expect("direct terminal record");
        assert!(!record.contains_key("authorization"));
    }
}

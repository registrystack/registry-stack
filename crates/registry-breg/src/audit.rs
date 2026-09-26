// SPDX-License-Identifier: Apache-2.0

//! Base Registry Engine audit entries and the pre-I/O release gate.
//!
//! Every audited request writes a `request` entry before protected I/O and a
//! `response` entry with its outcome, both through the one platform
//! [`AuditWriter`] the process opened at startup and both correlated by the
//! request id Base Registry Engine minted. A refusal is one `response` entry.
//! Entries carry keyed references and closed-vocabulary terms, never a raw
//! principal, record id, selector, token, or free text.

use registry_platform_audit::{AuditEntry, AuditKeyHasher, AuditProfile, AuditWriter};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::correlation::RequestCorrelation;
use crate::model::HttpMethod;
use crate::postgres::{ActionClaimContext, ClaimContext, ExpectedRegistryIdentity};

/// Schema of request, read, mutation, action, and refusal entries.
pub const AUDIT_SCHEMA: &str = "breg-audit/v2";
/// Schema of event delivery entries.
pub const WEBHOOK_AUDIT_SCHEMA: &str = "breg-webhook-audit/v2";
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

    /// Append one entry. A refused append is the audit-unavailable refusal:
    /// the caller performs no protected I/O and releases no disclosure.
    pub async fn append(&self, entry: AuditEntry) -> Result<(), RegistryAuditError> {
        self.writer
            .append(entry)
            .await
            .map_err(|_| RegistryAuditError::Unavailable)
    }
}

/// Verified grant context retained only for minimized, keyed audit projection.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct GrantAuditContext {
    actor_kind: registry_platform_oidc::ActorKind,
    grant: registry_platform_oidc::GrantClaims,
}
impl std::fmt::Debug for GrantAuditContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GrantAuditContext(<redacted>)")
    }
}
impl GrantAuditContext {
    pub(crate) fn from_claims(claims: &crate::api::VerifiedRequestClaims) -> Option<Self> {
        Some(Self {
            actor_kind: claims.actor_kind()?,
            grant: claims.grant()?.clone(),
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
        let event = AuthorizationAuditEvent::new(
            self.actor_kind.as_str(),
            pseudonym("breg-principal-v1", self.grant.principal())?,
            pseudonym("breg-client-v1", self.grant.client())?,
            Some(pseudonym("breg-grant-v1", self.grant.id())?),
            Some(pseudonym("breg-approver-v1", self.grant.approver())?),
            self.grant.purpose(),
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
        // BREG records purpose presence, never the purpose value.
        value
            .as_object_mut()
            .ok_or(RegistryAuditError::InvalidContext)?
            .remove("purpose");
        value["sourceIssuer"] = json!(self.grant.source_issuer());
        value["expiresAt"] = json!(self.grant.exp());
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

pub(crate) struct HttpRefusalAudit<'a> {
    pub grant: Option<GrantAuditContext>,
    pub method: HttpMethod,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WebhookAuditPhase {
    Attempt,
    Terminal,
    Replay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WebhookAuditOutcome {
    AttemptStarted,
    Delivered,
    HttpNonSuccess,
    DestinationTimeout,
    DestinationResolutionRefused,
    DestinationTransportUnavailable,
    DestinationPolicyRefused,
    DestinationBindingRefused,
    /// The delivery row named a local handler the running package does not
    /// hold, or holds under a different identity digest or budget.
    HandlerBindingRefused,
    /// The handler ran out of its attempt budget.
    HandlerDeadline,
    /// The handler exceeded a fuel, memory, or input or output ceiling.
    HandlerResource,
    /// The handler trapped, or its script failed.
    HandlerExecution,
    /// The handler program or its answer was refused as unusable.
    HandlerSource,
    /// The handler could not be reached.
    HandlerUnavailable,
    PayloadRefused,
    PayloadExpired,
    WorkerInterrupted,
    ReplayRequested,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WebhookAuditDisposition {
    Leased,
    Delivered,
    RetryPending,
    DeadLettered,
    Expired,
    ReplayPending,
}

pub(crate) struct WebhookAudit<'a> {
    pub event_id: Uuid,
    pub compiled_delivery_id: &'a str,
    pub package_revision: &'a str,
    pub generation: i64,
    pub attempt: i16,
    pub phase: WebhookAuditPhase,
    pub outcome: WebhookAuditOutcome,
    pub disposition: WebhookAuditDisposition,
}

/// Append one minimized attempt or refusal before protected record I/O.
///
/// An attempt is the `request` entry of the request it names and must be
/// accepted before any protected read or write starts. A refusal is the single
/// `response` entry of a request that performs no protected I/O.
pub async fn record_pre_io_audit(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    claims: &ClaimContext,
    event: PreIoAudit<'_>,
) -> Result<(), RegistryAuditError> {
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
            key_hasher.audit_reference_hash(
                "breg-principal-v1",
                &expected.package_revision,
                principal,
            )
        })
        .transpose()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let record_reference = event
        .target_record
        .map(|record| {
            key_hasher.audit_reference_hash("breg-record-v1", &expected.package_revision, record)
        })
        .transpose()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let mut record = json!({
        "phase": pre_io_phase_name(event.kind),
        "method": method_name(event.method),
        "operationId": event.operation_id,
        "requestId": event.correlation.request_id().to_string(),
        "traceId": event.correlation.trace_id().as_str(),
        "packageRevision": expected.package_revision,
        "selectedAccessProfile": claims.access_profile(),
        "purposePresent": claims.purpose().is_some(),
        "principalReference": principal_reference,
        "recordReference": record_reference,
    });
    if event.kind == PreIoAuditKind::Refusal {
        if let Some(grant) = claims.grant_audit() {
            record["authorization"] = grant.record(
                profile,
                &expected.package_revision,
                event.operation_id,
                false,
            )?;
        }
    }
    insert_refusal_reason(&mut record, event.refusal_reason);
    audit
        .append(pre_io_entry(event.kind, event.correlation, record))
        .await
}

pub(crate) async fn record_action_pre_io_audit(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    claims: &ActionClaimContext,
    event: PreIoAudit<'_>,
) -> Result<(), RegistryAuditError> {
    let profile = audit.profile();
    if event.operation_id.is_empty()
        || event.target_record.is_some()
        || event.method != HttpMethod::Post
        || !profile_is_keyed(profile)
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
            &expected.package_revision,
            claims.principal(),
        )
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let mut record = json!({
        "phase": pre_io_phase_name(event.kind),
        "method": method_name(event.method),
        "operationId": event.operation_id,
        "requestId": event.correlation.request_id().to_string(),
        "traceId": event.correlation.trace_id().as_str(),
        "packageRevision": expected.package_revision,
        "selectedAccessProfile": claims.access_profile(),
        "purposePresent": claims.purpose().is_some(),
        "principalReference": principal_reference,
        "actionId": claims.action_id(),
    });
    insert_refusal_reason(&mut record, event.refusal_reason);
    audit
        .append(pre_io_entry(event.kind, event.correlation, record))
        .await
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

pub(crate) async fn record_attachment_http_refusal_audit(
    audit: &RegistryAudit,
    expected: &ExpectedRegistryIdentity,
    event: HttpRefusalAudit<'_>,
    slot_id: &str,
) -> Result<(), RegistryAuditError> {
    record_http_refusal_audit_inner(audit, expected, event, Some(slot_id)).await
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
            key_hasher.audit_reference_hash(
                "breg-principal-v1",
                &expected.package_revision,
                principal,
            )
        })
        .transpose()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let record_reference = event
        .target_record
        .map(|record| {
            key_hasher.audit_reference_hash("breg-record-v1", &expected.package_revision, record)
        })
        .transpose()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let mut record = serde_json::Map::from_iter([
        ("phase".to_owned(), Value::String("refusal".to_owned())),
        (
            "method".to_owned(),
            Value::String(method_name(event.method).to_owned()),
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
            "packageRevision".to_owned(),
            Value::String(expected.package_revision.clone()),
        ),
        (
            "purposePresent".to_owned(),
            Value::Bool(event.purpose_present),
        ),
    ]);
    if let Some(grant) = &event.grant {
        record.insert(
            "authorization".to_owned(),
            grant.record(
                profile,
                &expected.package_revision,
                event.operation_id,
                false,
            )?,
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

/// Bind an attachment outcome to its exact request proposal without treating
/// the slot as an independently declared action.
pub(crate) fn attachment_terminal_entry(
    profile: &AuditProfile,
    terminal: TerminalAudit,
    slot: &str,
    proposal_version: i64,
) -> Result<AuditEntry, RegistryAuditError> {
    if terminal.entity_id.as_deref().is_none_or(str::is_empty)
        || terminal.action_id.is_some()
        || slot.is_empty()
        || proposal_version <= 0
    {
        return Err(RegistryAuditError::InvalidContext);
    }
    let correlation = terminal.correlation.request_id().to_string();
    let mut record = terminal_record(terminal, profile)?;
    record.insert(
        "attachment".to_owned(),
        serde_json::json!({"slotId": slot, "proposalVersion": proposal_version}),
    );
    Ok(response_entry(correlation, record))
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

/// The entry of one delivery transition. The attempt is the `request` entry of
/// one delivery attempt; its terminal outcome and an operator replay are
/// `response` entries. The correlation is the attempt identity: the keyed
/// event and delivery references, the generation, and the attempt number.
pub(crate) fn webhook_entry(
    profile: &AuditProfile,
    event: WebhookAudit<'_>,
) -> Result<AuditEntry, RegistryAuditError> {
    let shape_is_valid = match (event.phase, event.outcome, event.disposition) {
        (
            WebhookAuditPhase::Attempt,
            WebhookAuditOutcome::AttemptStarted,
            WebhookAuditDisposition::Leased,
        ) => event.attempt > 0,
        (
            WebhookAuditPhase::Terminal,
            WebhookAuditOutcome::Delivered,
            WebhookAuditDisposition::Delivered,
        )
        // A delivered answer whose proposal dead-lettered: the egress attempt
        // succeeded, and the deterministic proposal refusal is what made the
        // row terminal.
        | (
            WebhookAuditPhase::Terminal,
            WebhookAuditOutcome::Delivered,
            WebhookAuditDisposition::DeadLettered,
        )
        | (
            WebhookAuditPhase::Terminal,
            WebhookAuditOutcome::HttpNonSuccess
            | WebhookAuditOutcome::DestinationTimeout
            | WebhookAuditOutcome::DestinationResolutionRefused
            | WebhookAuditOutcome::DestinationTransportUnavailable
            | WebhookAuditOutcome::DestinationPolicyRefused
            | WebhookAuditOutcome::DestinationBindingRefused
            | WebhookAuditOutcome::HandlerBindingRefused
            | WebhookAuditOutcome::HandlerDeadline
            | WebhookAuditOutcome::HandlerResource
            | WebhookAuditOutcome::HandlerExecution
            | WebhookAuditOutcome::HandlerSource
            | WebhookAuditOutcome::HandlerUnavailable
            | WebhookAuditOutcome::PayloadRefused
            | WebhookAuditOutcome::WorkerInterrupted,
            WebhookAuditDisposition::RetryPending | WebhookAuditDisposition::DeadLettered,
        ) => event.attempt > 0,
        (
            WebhookAuditPhase::Terminal,
            WebhookAuditOutcome::PayloadExpired,
            WebhookAuditDisposition::Expired,
        ) => event.attempt >= 0,
        (
            WebhookAuditPhase::Replay,
            WebhookAuditOutcome::ReplayRequested,
            WebhookAuditDisposition::ReplayPending,
        ) => event.attempt == 0,
        _ => false,
    };
    if !shape_is_valid
        || event.generation <= 0
        || event.compiled_delivery_id.is_empty()
        || event.compiled_delivery_id.len() > 256
        || event.package_revision.is_empty()
        || !profile_is_keyed(profile)
    {
        return Err(RegistryAuditError::InvalidContext);
    }
    let key_hasher = profile.key_hasher();
    let event_reference = key_hasher
        .audit_reference_hash(
            "breg-webhook-event-v1",
            event.package_revision,
            &event.event_id.to_string(),
        )
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let delivery_reference = key_hasher
        .audit_reference_hash(
            "breg-webhook-delivery-v1",
            event.package_revision,
            event.compiled_delivery_id,
        )
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let correlation = format!(
        "{event_reference}.{delivery_reference}.{}.{}",
        event.generation, event.attempt
    );
    let record = json!({
        "phase": webhook_phase_name(event.phase),
        "outcome": webhook_outcome_name(event.outcome),
        "disposition": webhook_disposition_name(event.disposition),
        "packageRevision": event.package_revision,
        "eventReference": event_reference,
        "deliveryReference": delivery_reference,
        "generation": event.generation,
        "attempt": event.attempt,
    });
    Ok(match event.phase {
        WebhookAuditPhase::Attempt => {
            AuditEntry::request(WEBHOOK_AUDIT_SCHEMA, correlation, record)
        }
        WebhookAuditPhase::Terminal | WebhookAuditPhase::Replay => {
            AuditEntry::response(WEBHOOK_AUDIT_SCHEMA, correlation, record)
        }
    })
}

fn webhook_phase_name(phase: WebhookAuditPhase) -> &'static str {
    match phase {
        WebhookAuditPhase::Attempt => "attempt",
        WebhookAuditPhase::Terminal => "terminal",
        WebhookAuditPhase::Replay => "replay",
    }
}

fn webhook_outcome_name(outcome: WebhookAuditOutcome) -> &'static str {
    match outcome {
        WebhookAuditOutcome::AttemptStarted => "attempt_started",
        WebhookAuditOutcome::Delivered => "delivered",
        WebhookAuditOutcome::HttpNonSuccess => "http_non_success",
        WebhookAuditOutcome::DestinationTimeout => "destination_timeout",
        WebhookAuditOutcome::DestinationResolutionRefused => "destination_resolution_refused",
        WebhookAuditOutcome::DestinationTransportUnavailable => "destination_transport_unavailable",
        WebhookAuditOutcome::DestinationPolicyRefused => "destination_policy_refused",
        WebhookAuditOutcome::DestinationBindingRefused => "destination_binding_refused",
        WebhookAuditOutcome::HandlerBindingRefused => "handler_binding_refused",
        WebhookAuditOutcome::HandlerDeadline => "handler_deadline",
        WebhookAuditOutcome::HandlerResource => "handler_resource",
        WebhookAuditOutcome::HandlerExecution => "handler_execution",
        WebhookAuditOutcome::HandlerSource => "handler_source",
        WebhookAuditOutcome::HandlerUnavailable => "handler_unavailable",
        WebhookAuditOutcome::PayloadRefused => "payload_refused",
        WebhookAuditOutcome::PayloadExpired => "payload_expired",
        WebhookAuditOutcome::WorkerInterrupted => "worker_interrupted",
        WebhookAuditOutcome::ReplayRequested => "replay_requested",
    }
}

fn webhook_disposition_name(disposition: WebhookAuditDisposition) -> &'static str {
    match disposition {
        WebhookAuditDisposition::Leased => "leased",
        WebhookAuditDisposition::Delivered => "delivered",
        WebhookAuditDisposition::RetryPending => "retry_pending",
        WebhookAuditDisposition::DeadLettered => "dead_lettered",
        WebhookAuditDisposition::Expired => "expired",
        WebhookAuditDisposition::ReplayPending => "replay_pending",
    }
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
            "packageRevision".to_owned(),
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

        /// Another [`RegistryAudit`] recording into this capture, as a second
        /// process appending to the same destination would.
        #[must_use]
        pub fn audit(&self, profile: AuditProfile) -> RegistryAudit {
            let writer = AuditWriter::from_line_sink(Box::new(CaptureSink(Arc::clone(&self.0))));
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
    fn webhook_attempt_and_terminal_share_the_attempt_identity() {
        let event_id = Uuid::new_v4();
        let event = |phase, outcome, disposition| WebhookAudit {
            event_id,
            compiled_delivery_id: "delivery",
            package_revision: "package-revision",
            generation: 1,
            attempt: 2,
            phase,
            outcome,
            disposition,
        };
        let attempt = webhook_entry(
            &profile(),
            event(
                WebhookAuditPhase::Attempt,
                WebhookAuditOutcome::AttemptStarted,
                WebhookAuditDisposition::Leased,
            ),
        )
        .expect("attempt entry");
        let terminal = webhook_entry(
            &profile(),
            event(
                WebhookAuditPhase::Terminal,
                WebhookAuditOutcome::Delivered,
                WebhookAuditDisposition::Delivered,
            ),
        )
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
        assert_eq!(attempt.schema(), WEBHOOK_AUDIT_SCHEMA);
        assert!(!attempt.correlation().contains(&event_id.to_string()));
        assert!(!attempt.correlation().contains("delivery."));
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

// SPDX-License-Identifier: Apache-2.0

//! Database-owned Registry Server audit chain and pre-I/O release gate.

use std::time::Duration;

use deadpool_postgres::Client;
use registry_platform_audit::{AuditChainHasher, AuditEnvelope, AuditKeyHasher, AuditProfile};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Value};
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::correlation::RequestCorrelation;
use crate::model::HttpMethod;
use crate::postgres::{
    begin_action_transaction, begin_record_transaction, ActionClaimContext, ClaimContext,
    ExpectedRegistryIdentity, RegistryLockKey,
};

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
    pub correlation: &'a RequestCorrelation,
}

pub(crate) struct HttpRefusalAudit<'a> {
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
    #[error("audit journal is unavailable")]
    Unavailable,
}

pub(crate) struct TerminalAudit {
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

/// Persist one minimized attempt or refusal before protected record I/O.
///
/// This deliberately owns and commits a transaction separate from any later
/// mutation. A successful return is therefore durable evidence even when the
/// protected operation subsequently fails or rolls back.
pub async fn record_pre_io_audit(
    client: &mut Client,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    expected: &ExpectedRegistryIdentity,
    claims: &ClaimContext,
    profile: &AuditProfile,
    event: PreIoAudit<'_>,
) -> Result<(), RegistryAuditError> {
    if event.operation_id.is_empty() || !profile_is_keyed(profile) {
        return Err(RegistryAuditError::InvalidContext);
    }
    let key_hasher = profile.key_hasher();
    let principal_reference = claims
        .principal()
        .map(|principal| {
            key_hasher.audit_reference_hash(
                "registry-server-principal-v1",
                &expected.package_revision,
                principal,
            )
        })
        .transpose()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let record_reference = event
        .target_record
        .map(|record| {
            key_hasher.audit_reference_hash(
                "registry-server-record-v1",
                &expected.package_revision,
                record,
            )
        })
        .transpose()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let transaction = begin_record_transaction(client, lock_key, lock_timeout, expected, claims)
        .await
        .map_err(|_| RegistryAuditError::Unavailable)?;
    let record = json!({
        "schema": "registry-server-audit/v1",
        "phase": match event.kind {
            PreIoAuditKind::Attempt => "attempt",
            PreIoAuditKind::Refusal => "refusal",
        },
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
    append_envelope(transaction.transaction(), profile, record).await?;
    transaction
        .commit()
        .await
        .map_err(|_| RegistryAuditError::Unavailable)
}

pub(crate) async fn record_action_pre_io_audit(
    client: &mut Client,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    expected: &ExpectedRegistryIdentity,
    claims: &ActionClaimContext,
    profile: &AuditProfile,
    event: PreIoAudit<'_>,
) -> Result<(), RegistryAuditError> {
    if event.operation_id.is_empty()
        || event.target_record.is_some()
        || event.method != HttpMethod::Post
        || !profile_is_keyed(profile)
    {
        return Err(RegistryAuditError::InvalidContext);
    }
    let key_hasher = profile.key_hasher();
    let principal_reference = key_hasher
        .audit_reference_hash(
            "registry-server-principal-v1",
            &expected.package_revision,
            claims.principal(),
        )
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let transaction = begin_action_transaction(client, lock_key, lock_timeout, expected, claims)
        .await
        .map_err(|_| RegistryAuditError::Unavailable)?;
    let record = json!({
        "schema": "registry-server-audit/v1",
        "phase": match event.kind {
            PreIoAuditKind::Attempt => "attempt",
            PreIoAuditKind::Refusal => "refusal",
        },
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
    append_envelope(transaction.transaction(), profile, record).await?;
    transaction
        .commit()
        .await
        .map_err(|_| RegistryAuditError::Unavailable)
}

/// Persist a minimized HTTP-layer mutation refusal when authorization failed
/// before a forged `ClaimContext` would be safe to construct.
pub(crate) async fn record_http_refusal_audit(
    client: &mut Client,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    expected: &ExpectedRegistryIdentity,
    profile: &AuditProfile,
    event: HttpRefusalAudit<'_>,
) -> Result<(), RegistryAuditError> {
    if event.operation_id.is_empty()
        || event.action_id.is_some_and(str::is_empty)
        || !profile_is_keyed(profile)
        || lock_timeout.is_zero()
        || lock_timeout > Duration::from_secs(30)
    {
        return Err(RegistryAuditError::InvalidContext);
    }
    expected
        .validate()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let transaction = client
        .transaction()
        .await
        .map_err(|_| RegistryAuditError::Unavailable)?;
    let timeout_millis =
        i32::try_from(lock_timeout.as_millis()).map_err(|_| RegistryAuditError::InvalidContext)?;
    transaction
        .execute(
            "SELECT set_config('lock_timeout', $1::text, true)",
            &[&format!("{timeout_millis}ms")],
        )
        .await
        .map_err(|_| RegistryAuditError::Unavailable)?;
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock_shared($1)",
            &[&lock_key.get()],
        )
        .await
        .map_err(|_| RegistryAuditError::Unavailable)?;
    let state = transaction
        .query_opt(
            "SELECT package_id, environment, instance_id, database_id,
                    active_package_revision, schema_fingerprint, package_sequence,
                    maintenance_status
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await
        .map_err(|_| RegistryAuditError::Unavailable)?
        .ok_or(RegistryAuditError::Unavailable)?;
    let ready = state.get::<_, String>(7) == "ready"
        && state.get::<_, String>(0) == expected.package_id
        && state.get::<_, String>(1) == expected.environment
        && state.get::<_, String>(2) == expected.instance_id
        && state.get::<_, String>(3) == expected.database_id
        && state.get::<_, String>(4) == expected.package_revision
        && state.get::<_, String>(5) == expected.schema_fingerprint
        && state.get::<_, i64>(6) == expected.package_sequence;
    if !ready {
        return Err(RegistryAuditError::Unavailable);
    }
    let key_hasher = profile.key_hasher();
    let principal_reference = event
        .principal
        .map(|principal| {
            key_hasher.audit_reference_hash(
                "registry-server-principal-v1",
                &expected.package_revision,
                principal,
            )
        })
        .transpose()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let record_reference = event
        .target_record
        .map(|record| {
            key_hasher.audit_reference_hash(
                "registry-server-record-v1",
                &expected.package_revision,
                record,
            )
        })
        .transpose()
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let mut record = serde_json::Map::from_iter([
        (
            "schema".to_owned(),
            Value::String("registry-server-audit/v1".to_owned()),
        ),
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
    append_envelope(&transaction, profile, Value::Object(record)).await?;
    transaction
        .commit()
        .await
        .map_err(|_| RegistryAuditError::Unavailable)
}

pub(crate) fn profile_is_keyed(profile: &AuditProfile) -> bool {
    matches!(profile.chain_hasher(), AuditChainHasher::Keyed(_))
        && matches!(profile.key_hasher(), AuditKeyHasher::Keyed(_))
}

pub(crate) async fn append_terminal_audit(
    transaction: &Transaction<'_>,
    profile: &AuditProfile,
    terminal: TerminalAudit,
) -> Result<(), RegistryAuditError> {
    if !matches!(
        (&terminal.entity_id, &terminal.action_id),
        (Some(_), None) | (None, Some(_))
    ) || terminal.entity_id.as_deref().is_some_and(str::is_empty)
        || terminal.action_id.as_deref().is_some_and(str::is_empty)
    {
        return Err(RegistryAuditError::InvalidContext);
    }
    append_envelope(
        transaction,
        profile,
        Value::Object(terminal_record(terminal)),
    )
    .await
}

/// Link an action commit or replay to its retained application provenance.
/// The reference is derived by the server, never copied from an HTTP input.
pub(crate) async fn append_action_terminal_audit(
    transaction: &Transaction<'_>,
    profile: &AuditProfile,
    terminal: TerminalAudit,
    application_reference: &str,
) -> Result<(), RegistryAuditError> {
    let record = action_terminal_record(terminal, application_reference)?;
    append_envelope(transaction, profile, Value::Object(record)).await
}

fn action_terminal_record(
    terminal: TerminalAudit,
    application_reference: &str,
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
    let mut record = terminal_record(terminal);
    record.insert(
        "applicationReference".to_owned(),
        Value::String(application_reference.to_owned()),
    );
    Ok(record)
}

pub(crate) async fn append_webhook_audit(
    transaction: &Transaction<'_>,
    profile: &AuditProfile,
    event: WebhookAudit<'_>,
) -> Result<(), RegistryAuditError> {
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
        | (
            WebhookAuditPhase::Terminal,
            WebhookAuditOutcome::HttpNonSuccess
            | WebhookAuditOutcome::DestinationTimeout
            | WebhookAuditOutcome::DestinationResolutionRefused
            | WebhookAuditOutcome::DestinationTransportUnavailable
            | WebhookAuditOutcome::DestinationPolicyRefused
            | WebhookAuditOutcome::DestinationBindingRefused
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
            "registry-server-webhook-event-v1",
            event.package_revision,
            &event.event_id.to_string(),
        )
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    let delivery_reference = key_hasher
        .audit_reference_hash(
            "registry-server-webhook-delivery-v1",
            event.package_revision,
            event.compiled_delivery_id,
        )
        .map_err(|_| RegistryAuditError::InvalidContext)?;
    append_envelope(
        transaction,
        profile,
        json!({
            "schema": "registry-server-webhook-audit/v1",
            "phase": webhook_phase_name(event.phase),
            "outcome": webhook_outcome_name(event.outcome),
            "disposition": webhook_disposition_name(event.disposition),
            "packageRevision": event.package_revision,
            "eventReference": event_reference,
            "deliveryReference": delivery_reference,
            "generation": event.generation,
            "attempt": event.attempt,
        }),
    )
    .await
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

fn terminal_record(terminal: TerminalAudit) -> serde_json::Map<String, Value> {
    let mut record = serde_json::Map::from_iter([
        (
            "schema".to_owned(),
            Value::String("registry-server-audit/v1".to_owned()),
        ),
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
    record
}

pub(crate) struct ReadTerminalAudit {
    pub terminal: TerminalAudit,
    pub query_reference: Option<String>,
    pub row_boundary_reference: Option<String>,
}

pub(crate) async fn append_read_terminal_audit(
    transaction: &Transaction<'_>,
    profile: &AuditProfile,
    read_terminal: ReadTerminalAudit,
) -> Result<(), RegistryAuditError> {
    let mut terminal = terminal_record(read_terminal.terminal);
    if let Some(query_reference) = read_terminal.query_reference {
        terminal.insert("queryReference".to_owned(), Value::String(query_reference));
    }
    if let Some(row_boundary_reference) = read_terminal.row_boundary_reference {
        terminal.insert(
            "rowBoundaryReference".to_owned(),
            Value::String(row_boundary_reference),
        );
    }
    append_envelope(transaction, profile, Value::Object(terminal)).await
}

async fn append_envelope(
    transaction: &Transaction<'_>,
    profile: &AuditProfile,
    record: Value,
) -> Result<(), RegistryAuditError> {
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_audit_head (singleton, last_hash)
             VALUES (true, NULL)
             ON CONFLICT (singleton) DO NOTHING",
            &[],
        )
        .await
        .map_err(|_| RegistryAuditError::Unavailable)?;
    let row = transaction
        .query_one(
            "SELECT last_hash
             FROM registry_internal.registry_audit_head
             WHERE singleton
             FOR UPDATE",
            &[],
        )
        .await
        .map_err(|_| RegistryAuditError::Unavailable)?;
    let previous = row
        .get::<_, Option<Vec<u8>>>(0)
        .map(|bytes| <[u8; 32]>::try_from(bytes).map_err(|_| RegistryAuditError::Unavailable))
        .transpose()?;
    let envelope = AuditEnvelope::new_with_hasher(record, previous, &profile.chain_hasher())
        .map_err(|_| RegistryAuditError::Unavailable)?;
    let envelope_value =
        serde_json::to_value(&envelope).map_err(|_| RegistryAuditError::Unavailable)?;
    let envelope_bytes =
        canonicalize_json(&envelope_value).map_err(|_| RegistryAuditError::Unavailable)?;
    let changed = transaction
        .execute(
            "INSERT INTO registry_internal.registry_audit
                 (envelope_id, record_hash, envelope)
             VALUES ($1, $2, $3)",
            &[
                &envelope.envelope_id,
                &envelope.record_hash.as_slice(),
                &envelope_bytes,
            ],
        )
        .await
        .map_err(|_| RegistryAuditError::Unavailable)?;
    if changed != 1 {
        return Err(RegistryAuditError::Unavailable);
    }
    let changed = transaction
        .execute(
            "UPDATE registry_internal.registry_audit_head
             SET last_hash = $1
             WHERE singleton",
            &[&envelope.record_hash.as_slice()],
        )
        .await
        .map_err(|_| RegistryAuditError::Unavailable)?;
    if changed != 1 {
        return Err(RegistryAuditError::Unavailable);
    }
    Ok(())
}

fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Delete => "DELETE",
        HttpMethod::Get => "GET",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Post => "POST",
    }
}

#[cfg(test)]
mod action_terminal_tests {
    use super::*;

    fn terminal(outcome: TerminalAuditOutcome) -> TerminalAudit {
        TerminalAudit {
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
            correlation: RequestCorrelation::server_created(),
        }
    }

    #[test]
    fn action_commit_and_replay_audits_retain_application_without_response_or_record_data() {
        for outcome in [
            TerminalAuditOutcome::Committed,
            TerminalAuditOutcome::Replayed,
        ] {
            let record = action_terminal_record(terminal(outcome), "protected-application")
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
            action_terminal_record(entity, "protected-application"),
            Err(RegistryAuditError::InvalidContext)
        );
        assert_eq!(
            action_terminal_record(
                terminal(TerminalAuditOutcome::Returned),
                "protected-application"
            ),
            Err(RegistryAuditError::InvalidContext)
        );
        assert_eq!(
            action_terminal_record(terminal(TerminalAuditOutcome::Committed), ""),
            Err(RegistryAuditError::InvalidContext)
        );
    }
}

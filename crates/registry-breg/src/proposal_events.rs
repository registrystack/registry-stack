// SPDX-License-Identifier: Apache-2.0

//! Value-free engine-owned lifecycle events, captured with the transition.
use crate::event_destination::ActivatedEventDestinationRegistry;
use crate::model::{CompiledAction, CompiledActionExecution, CompiledRegistry};
use crate::outbox::{
    activate_delivery, capture_envelope, capture_time, envelope_payload, insert_hook_delivery,
    CapturedEvent, EnvelopeBinding, HookCapture, OutboxError,
};
use registry_platform_hooks::{EnvelopeLimits, HookEnvelope};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tokio_postgres::Transaction;
use uuid::Uuid;

pub(crate) struct ProposalLifecycleEvent<'a> {
    pub action_id: &'a str,
    pub action_revision: &'a str,
    pub proposal_id: Uuid,
    pub version: u32,
    pub revision: u64,
    pub from_state: &'a str,
    pub state: &'a str,
    pub transition: &'a str,
    pub effect_digest: Option<&'a str>,
    pub authority_kind: &'a str,
    pub system_grant_revision: Option<&'a str>,
    pub turn: &'a str,
    pub reference: &'a str,
    pub package_revision: &'a str,
    pub schema_fingerprint: &'a str,
    pub source: &'a str,
}

pub(crate) async fn insert_proposal_lifecycle_event(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    action: &CompiledAction,
    destinations: Option<&ActivatedEventDestinationRegistry>,
    event: ProposalLifecycleEvent<'_>,
) -> Result<(), OutboxError> {
    let deliveries = crate::proposal_hooks::exact_deliveries(registry, action)?;
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        return Err(OutboxError::Unavailable);
    };
    if event.version == 0
        || event.revision == 0
        || event.action_id.is_empty()
        || !matches!(
            event.transition,
            "started"
                | "edited"
                | "submitted"
                | "revised"
                | "rebased"
                | "retried"
                | "cancelled"
                | "applied"
                | "rejected"
                | "review-returned"
        )
    {
        return Err(OutboxError::InvalidProjection);
    }
    let event_type = format!("proposal.{}", event.transition);
    let canonical = registry_platform_canonical_json::canonicalize_json(&json!({
        "actionId":event.action_id,"proposalId":event.proposal_id,
        "revision":event.revision,"transition":event.transition,
    }))
    .map_err(|_| OutboxError::InvalidProjection)?;
    let digest = Sha256::digest(canonical);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let event_id = Uuid::from_bytes(bytes);
    let created = capture_time(transaction).await?;
    let schemas = BTreeMap::from([(
        event_type.clone(),
        crate::proposal_hooks::PROPOSAL_EVENT_SCHEMA.to_owned(),
    )]);
    let envelope = capture_envelope(
        &EnvelopeBinding {
            source: event.source,
            data_schemas: &schemas,
            causation: None,
        },
        CapturedEvent {
            event_id,
            event_type: &event_type,
            created_at: created.into(),
            record_reference: event.reference,
            record_revision: i64::try_from(event.revision).map_err(|_| OutboxError::Unavailable)?,
            data: json!({"actionId":event.action_id,"actionRevision":event.action_revision,
                "proposalId":event.proposal_id,"submissionVersion":event.version,"revision":event.revision,
                "fromState":event.from_state,"state":event.state,"transition":event.transition,
                "effectDigest":event.effect_digest,"authorityKind":event.authority_kind,
                "systemApplyGrantRevision":event.system_grant_revision,"turn":event.turn}),
        },
    )?;
    let payload = envelope_payload(
        &envelope,
        Some(crate::proposal_hooks::MAX_PROPOSAL_EVENT_PAYLOAD_BYTES),
    )?;
    let active = deliveries
        .iter()
        .filter(|delivery| {
            proposal
                .hooks
                .iter()
                .find(|hook| hook.id == delivery.event_id)
                .is_some_and(|hook| {
                    crate::proposal_hooks::matching_transitions(&hook.transitions)
                        .any(|transition| transition.as_str() == event.transition)
                })
        })
        .map(|delivery| activate_delivery(delivery, destinations))
        .collect::<Result<Vec<_>, _>>()?;
    let retention = destinations.map_or(
        std::time::Duration::from_secs(7 * 86400),
        ActivatedEventDestinationRegistry::payload_retention,
    );
    let retention_milliseconds =
        i64::try_from(retention.as_millis()).map_err(|_| OutboxError::Unavailable)?;
    let inserted = transaction
        .execute(
            "INSERT INTO registry_internal.registry_outbox
         (event_id,event_type,trigger,entity_id,record_reference,record_revision,
          package_revision,schema_fingerprint,payload,created_at,payload_expires_at)
         VALUES ($1,$2,'proposal-lifecycle',$3,$4,$5,$6,$7,$8,$9,$9::timestamptz+$10::bigint*interval '1 millisecond')
         ON CONFLICT (event_id) DO NOTHING",
            &[
                &event_id,
                &event_type,
                &event.action_id,
                &event.reference,
                &i64::try_from(event.revision).map_err(|_| OutboxError::Unavailable)?,
                &event.package_revision,
                &event.schema_fingerprint,
                &payload,
                &created,
                &retention_milliseconds,
            ],
        )
        .await
        .map_err(|_| OutboxError::Unavailable)?;
    if inserted == 0 {
        let row = transaction
            .query_one(
                "SELECT payload,package_revision,schema_fingerprint,event_type,trigger,entity_id,record_reference,record_revision FROM registry_internal.registry_outbox WHERE event_id=$1",
                &[&event_id],
            )
            .await
            .map_err(|_| OutboxError::Unavailable)?;
        if row.get::<_, String>(1) != event.package_revision
            || row.get::<_, String>(2) != event.schema_fingerprint
            || row.get::<_, String>(3) != event_type
            || row.get::<_, String>(4) != "proposal-lifecycle"
            || row.get::<_, String>(5) != event.action_id
            || row.get::<_, String>(6) != event.reference
            || row.get::<_, i64>(7)
                != i64::try_from(event.revision).map_err(|_| OutboxError::Unavailable)?
        {
            return Err(OutboxError::Unavailable);
        }
        let retained = row
            .get::<_, Option<Vec<u8>>>(0)
            .ok_or(OutboxError::Unavailable)?;
        let mut prior = HookEnvelope::from_canonical_bytes(&retained, &EnvelopeLimits::default())
            .map_err(|_| OutboxError::Unavailable)?;
        prior.time = envelope.time;
        if prior != envelope {
            return Err(OutboxError::Unavailable);
        }
    } else {
        for activated in &active {
            insert_hook_delivery(
                transaction,
                event_id,
                HookCapture {
                    activated,
                    payload: &payload,
                    package_revision: event.package_revision,
                    schema_fingerprint: event.schema_fingerprint,
                },
            )
            .await?;
        }
    }
    Ok(())
}

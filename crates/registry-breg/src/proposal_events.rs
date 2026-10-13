// SPDX-License-Identifier: Apache-2.0

//! Value-free engine-owned lifecycle events, captured with the transition.
use std::collections::BTreeMap;
use registry_platform_hooks::{EnvelopeLimits, HookEnvelope};
use serde_json::json;
use sha2::{Digest,Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;
use crate::outbox::{capture_envelope,capture_time,envelope_payload,CapturedEvent,EnvelopeBinding,OutboxError};

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
    pub reference: &'a str,
    pub package_revision: &'a str,
    pub schema_fingerprint: &'a str,
    pub source: &'a str,
}

pub(crate) async fn insert_proposal_lifecycle_event(
    transaction: &Transaction<'_>, event: ProposalLifecycleEvent<'_>,
) -> Result<(),OutboxError> {
    if event.version == 0 || event.revision == 0 || event.action_id.is_empty()
        || !matches!(event.transition,"started"|"submitted"|"revised"|"cancelled"|"applied") {
        return Err(OutboxError::InvalidProjection);
    }
    let event_type = format!("proposal.{}",event.transition);
    let canonical = registry_platform_canonical_json::canonicalize_json(&json!({
        "actionId":event.action_id,"proposalId":event.proposal_id,
        "revision":event.revision,"transition":event.transition,
    })).map_err(|_|OutboxError::InvalidProjection)?;
    let digest = Sha256::digest(canonical);
    let mut bytes = [0u8;16]; bytes.copy_from_slice(&digest[..16]);
    bytes[6]=(bytes[6]&0x0f)|0x50; bytes[8]=(bytes[8]&0x3f)|0x80;
    let event_id = Uuid::from_bytes(bytes);
    let created = capture_time(transaction).await?;
    let schemas = BTreeMap::from([(event_type.clone(),
        "https://id.registrystack.org/contracts/breg/proposal-event/v1".to_owned())]);
    let envelope = capture_envelope(&EnvelopeBinding {source:event.source,data_schemas:&schemas,causation:None},
        CapturedEvent {event_id,event_type:&event_type,created_at:created.into(),
            record_reference:event.reference,record_revision:i64::try_from(event.revision).map_err(|_|OutboxError::Unavailable)?,
            data:json!({"actionId":event.action_id,"actionRevision":event.action_revision,
                "proposalId":event.proposal_id,"version":event.version,"revision":event.revision,
                "fromState":event.from_state,"state":event.state,"transition":event.transition,
                "effectDigest":event.effect_digest}),
        })?;
    let payload = envelope_payload(&envelope,None)?;
    let inserted = transaction.execute(
        "INSERT INTO registry_internal.registry_outbox
         (event_id,event_type,trigger,entity_id,record_reference,record_revision,
          package_revision,schema_fingerprint,payload,created_at,payload_expires_at)
         VALUES ($1,$2,'proposal-lifecycle',$3,$4,$5,$6,$7,$8,$9,$9::timestamptz+interval '7 days')
         ON CONFLICT (event_id) DO NOTHING",
        &[&event_id,&event_type,&event.action_id,&event.reference,
            &i64::try_from(event.revision).map_err(|_|OutboxError::Unavailable)?,
            &event.package_revision,&event.schema_fingerprint,&payload,&created],
    ).await.map_err(|_|OutboxError::Unavailable)?;
    if inserted == 0 {
        let row=transaction.query_one("SELECT payload FROM registry_internal.registry_outbox WHERE event_id=$1",&[&event_id])
            .await.map_err(|_|OutboxError::Unavailable)?;
        let retained=row.get::<_,Option<Vec<u8>>>(0).ok_or(OutboxError::Unavailable)?;
        let mut prior=HookEnvelope::from_canonical_bytes(&retained,&EnvelopeLimits::default()).map_err(|_|OutboxError::Unavailable)?;
        prior.time=envelope.time;
        if prior!=envelope {return Err(OutboxError::Unavailable);}
    }
    Ok(())
}

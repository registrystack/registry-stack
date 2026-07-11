// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use async_trait::async_trait;
use registry_platform_audit::{
    AuditChainHasher, AuditEnvelope, CanonicalSafeAuditPayloadDigest, DurableAuditOperationId,
    DurableAuditOperationKey, DurableAuditPhase, DurableAuditSink, DurableAuditStoredIdentity,
    DurableAuditStreamKind, DurableAuditWrite, DurableAuditWriteError, DurableAuditWriteOutcome,
    DURABLE_AUDIT_RECORD_SCHEMA_V1,
};
use serde_json::{json, Value};

struct StoredPhase {
    digest: CanonicalSafeAuditPayloadDigest,
    identity: DurableAuditStoredIdentity,
    envelope: AuditEnvelope,
}

#[derive(Default)]
struct TinyState {
    phases: BTreeMap<DurableAuditOperationKey, StoredPhase>,
    chain_head: Option<[u8; 32]>,
}

struct TinyAtomicSink {
    hasher: AuditChainHasher,
    state: tokio::sync::Mutex<TinyState>,
}

impl Default for TinyAtomicSink {
    fn default() -> Self {
        Self {
            hasher: AuditChainHasher::unkeyed_dev_only(),
            state: tokio::sync::Mutex::new(TinyState::default()),
        }
    }
}

#[async_trait]
impl DurableAuditSink for TinyAtomicSink {
    async fn write_phase(
        &self,
        write: &DurableAuditWrite,
    ) -> Result<DurableAuditWriteOutcome, DurableAuditWriteError> {
        let mut state = self.state.lock().await;
        if let Some(stored) = state.phases.get(write.key()) {
            return if stored.digest == write.payload_digest() {
                Ok(DurableAuditWriteOutcome::IdenticalDuplicate(
                    stored.identity.clone(),
                ))
            } else {
                Ok(DurableAuditWriteOutcome::ConflictingDuplicate(
                    stored.identity.clone(),
                ))
            };
        }

        let envelope = write
            .build_envelope_at_chain_head(state.chain_head, &self.hasher)
            .map_err(|_| DurableAuditWriteError::StoreFailure)?;
        let identity = DurableAuditStoredIdentity::from_envelope(&envelope)
            .map_err(|_| DurableAuditWriteError::StoreFailure)?;
        state.chain_head = Some(envelope.record_hash);
        state.phases.insert(
            write.key().clone(),
            StoredPhase {
                digest: write.payload_digest(),
                identity: identity.clone(),
                envelope,
            },
        );
        Ok(DurableAuditWriteOutcome::Inserted(identity))
    }
}

fn write(payload: Value) -> DurableAuditWrite {
    DurableAuditWrite::new(
        DurableAuditStreamKind::Consultation,
        DurableAuditOperationId::parse("01J5K8M0000000000000000000")
            .expect("canonical operation id"),
        DurableAuditPhase::Attempt,
        payload,
    )
    .expect("public write constructor accepts canonical safe object")
}

#[tokio::test]
async fn external_sink_can_build_envelope_and_resolve_all_outcomes() {
    let sink = TinyAtomicSink::default();
    let original = write(json!({"event": "consultation.attempt"}));
    let replay = write(json!({"event": "consultation.attempt"}));
    let conflict = write(json!({"event": "consultation.attempt.changed"}));

    let inserted = sink.write_phase(&original).await.expect("insert succeeds");
    let duplicate = sink.write_phase(&replay).await.expect("replay succeeds");
    let conflicting = sink
        .write_phase(&conflict)
        .await
        .expect("conflict is an outcome");

    assert!(matches!(inserted, DurableAuditWriteOutcome::Inserted(_)));
    assert_eq!(
        duplicate,
        DurableAuditWriteOutcome::IdenticalDuplicate(inserted.stored_identity().clone())
    );
    assert_eq!(
        conflicting,
        DurableAuditWriteOutcome::ConflictingDuplicate(inserted.stored_identity().clone())
    );
    let state = sink.state.lock().await;
    assert_eq!(state.phases.len(), 1);
    let stored = state.phases.values().next().expect("one stored phase");
    assert!(stored.envelope.prev_hash.is_none());
    assert_eq!(
        stored.envelope.record,
        json!({
            "schema": DURABLE_AUDIT_RECORD_SCHEMA_V1,
            "stream_kind": "consultation",
            "operation_id": "01J5K8M0000000000000000000",
            "phase": "attempt",
            "payload_digest": format!("sha256:{}", original.payload_digest().to_lower_hex()),
            "payload": {"event": "consultation.attempt"},
        })
    );
}

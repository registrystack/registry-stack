// SPDX-License-Identifier: Apache-2.0
//! Fail-closed materialization attempt and publication orchestration.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use datafusion::catalog::TableProvider;
use registry_platform_audit::{
    DurableAuditOperationId, DurableAuditPhase, DurableAuditSink, DurableAuditStreamKind,
    DurableAuditWrite, DurableAuditWriteOutcome,
};
use serde_json::json;
use thiserror::Error;
use ulid::Ulid;

use crate::config::FieldType;
use crate::ingest::declared_schema::DeclaredSchema;
use crate::source_plan::{CompiledConsultationRegistry, SourcePlanKind};
use crate::state_plane::{
    CompletionAttemptReference, ConsultationStatePlaneRuntime, MaterializationGenerationId,
    MaterializationPublicationBindingId, MaterializationPublicationOutcome,
    MaterializationPublicationRequest, MaterializationSourceRevision,
    RestrictedMaterializationContentDigest,
};

use super::{
    PublishedSnapshotHandle, PublishedSnapshotRegistry, SnapshotContentDigest,
    SnapshotPublicationGuard,
};

struct MaterializationFacts {
    binding_id: MaterializationPublicationBindingId,
    key_physical_field: Box<str>,
    required_physical_fields: BTreeSet<Box<str>>,
    profile_id: Box<str>,
    profile_version: Box<str>,
    profile_hash: Box<str>,
    integration_pack_id: Box<str>,
    integration_pack_version: Box<str>,
    integration_pack_hash: Box<str>,
    acquisition_fields: Box<[Box<str>]>,
    max_source_records: u64,
    max_source_bytes: u64,
    max_data_exchanges: u8,
    max_credential_exchanges: u8,
    max_data_destinations: u8,
    snapshot_retention_generations: u16,
    max_snapshot_age_ms: u64,
}

/// Shared publisher installed into configured ingest plans after the state
/// plane and exact artifact closure have both activated.
pub(crate) struct SnapshotMaterializationCoordinator {
    facts: BTreeMap<Box<str>, Arc<MaterializationFacts>>,
    snapshots: Arc<PublishedSnapshotRegistry>,
    state_plane: Arc<ConsultationStatePlaneRuntime>,
}

impl SnapshotMaterializationCoordinator {
    pub(crate) fn compile(
        registry: &CompiledConsultationRegistry,
        snapshots: Arc<PublishedSnapshotRegistry>,
        state_plane: Arc<ConsultationStatePlaneRuntime>,
    ) -> Result<Arc<Self>, SnapshotMaterializationError> {
        let mut facts = BTreeMap::new();
        for plan in registry
            .plans_for_concrete_activation()
            .filter(|plan| plan.kind() == SourcePlanKind::SnapshotExact)
        {
            let binding = plan
                .snapshot_binding()
                .ok_or(SnapshotMaterializationError::InvalidConfiguration)?;
            let binding_id = MaterializationPublicationBindingId::parse(plan.binding_hash())
                .map_err(|_| SnapshotMaterializationError::InvalidConfiguration)?;
            let profile = plan.profile();
            let pack = plan.integration_pack();
            let mut required_physical_fields = binding
                .projection()
                .map(|(_, physical)| physical.into())
                .collect::<BTreeSet<Box<str>>>();
            if let Some((_, physical)) = binding.source_observed_at_extraction() {
                required_physical_fields.insert(physical.into());
            }
            if let Some((_, physical, _)) = binding.source_revision_extraction() {
                required_physical_fields.insert(physical.into());
            }
            let entry = Arc::new(MaterializationFacts {
                binding_id,
                key_physical_field: binding.key_physical_field().into(),
                required_physical_fields,
                profile_id: profile.id().as_str().into(),
                profile_version: profile.version().to_string().into(),
                profile_hash: profile.contract_hash().as_str().into(),
                integration_pack_id: pack.id().as_str().into(),
                integration_pack_version: pack.version().to_string().into(),
                integration_pack_hash: pack.hash().as_str().into(),
                acquisition_fields: plan
                    .runtime_profile()
                    .acquisition()
                    .fields()
                    .map(|field| field.name().into())
                    .collect(),
                max_source_records: binding.max_source_records(),
                max_source_bytes: binding.max_source_bytes(),
                max_data_exchanges: binding.max_refresh_data_exchanges(),
                max_credential_exchanges: binding.max_refresh_credential_exchanges(),
                max_data_destinations: binding.max_refresh_data_destinations(),
                snapshot_retention_generations: binding.snapshot_retention_generations(),
                max_snapshot_age_ms: binding.max_snapshot_age_ms(),
            });
            if facts
                .insert(binding.table_provider().into(), entry)
                .is_some()
            {
                return Err(SnapshotMaterializationError::InvalidConfiguration);
            }
        }
        Ok(Arc::new(Self {
            facts,
            snapshots,
            state_plane,
        }))
    }

    pub(crate) fn providers(&self) -> impl ExactSizeIterator<Item = &str> {
        self.facts.keys().map(AsRef::as_ref)
    }

    pub(crate) fn retention_generations(&self, table_provider: &str) -> Option<u16> {
        self.facts
            .get(table_provider)
            .map(|facts| facts.snapshot_retention_generations)
    }

    pub(crate) fn footprint_limits(&self, table_provider: &str) -> Option<(u64, u64)> {
        self.facts
            .get(table_provider)
            .map(|facts| (facts.max_source_records, facts.max_source_bytes))
    }

    pub(crate) fn validates_declared_schema(
        &self,
        table_provider: &str,
        schema: &DeclaredSchema,
    ) -> bool {
        let Some(facts) = self.facts.get(table_provider) else {
            return false;
        };
        schema
            .field(&facts.key_physical_field)
            .is_some_and(|field| field.ty == FieldType::String)
            && schema.fields.len() == facts.required_physical_fields.len()
            && facts
                .required_physical_fields
                .iter()
                .all(|field| schema.field(field).is_some())
    }

    /// Persist the attempt before the connector can be polled for source data.
    pub(crate) async fn begin(
        &self,
        table_provider: &str,
        connector_kind: &'static str,
    ) -> Result<SnapshotMaterializationAttempt, SnapshotMaterializationError> {
        let facts = self
            .facts
            .get(table_provider)
            .cloned()
            .ok_or(SnapshotMaterializationError::UnknownProvider)?;
        let publication = self
            .snapshots
            .begin_publication(table_provider)
            .map_err(|_| SnapshotMaterializationError::Unavailable)?;
        let acquisition_id = Ulid::new();
        let operation_id = DurableAuditOperationId::parse(&acquisition_id.to_string())
            .map_err(|_| SnapshotMaterializationError::InvalidState)?;
        let write = DurableAuditWrite::new(
            DurableAuditStreamKind::Materialization,
            operation_id.clone(),
            DurableAuditPhase::Attempt,
            json!({
                "schema": "registry.relay.materialization-attempt/v1",
                "profile": {
                    "id": facts.profile_id,
                    "version": facts.profile_version,
                    "contract_hash": facts.profile_hash,
                },
                "integration_pack": {
                    "id": facts.integration_pack_id,
                    "version": facts.integration_pack_version,
                    "hash": facts.integration_pack_hash,
                },
                "private_binding_hash": facts.binding_id.as_str(),
                "connector_kind": connector_kind,
                "acquisition_fields": facts.acquisition_fields,
                "refresh_bounds": {
                    "max_source_records": facts.max_source_records,
                    "max_source_bytes": facts.max_source_bytes,
                    "max_data_exchanges": facts.max_data_exchanges,
                    "max_credential_exchanges": facts.max_credential_exchanges,
                    "max_data_destinations": facts.max_data_destinations,
                },
                "snapshot_retention_generations": facts.snapshot_retention_generations,
                "max_snapshot_age_ms": facts.max_snapshot_age_ms,
                "source_access": "pending",
            }),
        )
        .map_err(|_| SnapshotMaterializationError::InvalidState)?;
        let stored = match self.state_plane.audit().write_phase(&write).await {
            Ok(DurableAuditWriteOutcome::Inserted(stored))
            | Ok(DurableAuditWriteOutcome::IdenticalDuplicate(stored)) => stored,
            Ok(DurableAuditWriteOutcome::ConflictingDuplicate(_)) | Err(_) => {
                return Err(SnapshotMaterializationError::AuditUnavailable);
            }
        };
        Ok(SnapshotMaterializationAttempt {
            operation_id,
            attempt: CompletionAttemptReference::from_stored_attempt(&stored),
            facts,
            publication,
        })
    }

    pub(crate) async fn publish(
        &self,
        attempt: SnapshotMaterializationAttempt,
        candidate: SnapshotMaterializationCandidate,
    ) -> Result<PendingLocalSnapshotPublication, SnapshotMaterializationError> {
        if candidate.row_count > attempt.facts.max_source_records
            || candidate.byte_count > attempt.facts.max_source_bytes
        {
            let _ = self.fail(attempt, "footprint_exceeded").await;
            return Err(SnapshotMaterializationError::FootprintExceeded);
        }
        let request = (|| {
            let generation_id =
                MaterializationGenerationId::parse(&candidate.generation.to_string())
                    .map_err(|_| SnapshotMaterializationError::InvalidState)?;
            let source_revision = candidate
                .source_revision
                .as_deref()
                .map(MaterializationSourceRevision::parse)
                .transpose()
                .map_err(|_| SnapshotMaterializationError::InvalidState)?;
            MaterializationPublicationRequest::new(
                attempt.facts.binding_id.clone(),
                generation_id,
                RestrictedMaterializationContentDigest::from_sha256(candidate.digest),
                source_revision,
                candidate.source_observed_at_unix_ms,
            )
            .map_err(|_| SnapshotMaterializationError::InvalidState)
        })();
        let request = match request {
            Ok(request) => request,
            Err(error) => {
                let _ = self.fail(attempt, "invalid_candidate").await;
                return Err(error);
            }
        };
        let completion = DurableAuditWrite::new(
            DurableAuditStreamKind::Materialization,
            attempt.operation_id.clone(),
            DurableAuditPhase::Completion,
            json!({
                "schema": "registry.relay.materialization-completion/v1",
                "attempt_event": attempt.attempt.to_safe_payload_value(),
                "outcome": "published",
                "private_binding_hash": attempt.facts.binding_id.as_str(),
                "snapshot_generation": candidate.generation.to_string(),
                "restricted_content_digest": format!("sha256:{}", encode_hex(&candidate.digest)),
                "source_revision": candidate.source_revision,
                "source_observed_at_unix_ms": candidate.source_observed_at_unix_ms,
                "row_count": candidate.row_count,
                "byte_count": candidate.byte_count,
                "acquisition_fields": attempt.facts.acquisition_fields,
            }),
        );
        let completion = match completion {
            Ok(completion) => completion,
            Err(_) => {
                let _ = self.fail(attempt, "invalid_completion").await;
                return Err(SnapshotMaterializationError::InvalidState);
            }
        };
        let active = match self
            .state_plane
            .audit()
            .publish_materialization(&completion, &request)
            .await
        {
            Ok(MaterializationPublicationOutcome::Inserted(active))
            | Ok(MaterializationPublicationOutcome::IdenticalDuplicate(active)) => active,
            Err(_) => {
                let _ = self.fail(attempt, "publication_rejected").await;
                return Err(SnapshotMaterializationError::PublicationRejected);
            }
        };
        let generation = Ulid::from_string(active.generation_id().as_str())
            .map_err(|_| SnapshotMaterializationError::InvalidState)?;
        let handle = PublishedSnapshotHandle::new(
            generation,
            SnapshotContentDigest::from_bytes(*active.content_digest().as_bytes()),
            active.published_at_unix_ms(),
            active
                .source_revision()
                .map(|revision| revision.as_str().to_owned()),
            active.source_observed_at_unix_ms(),
            candidate.provider,
        )
        .map_err(|_| SnapshotMaterializationError::InvalidState)?;
        Ok(PendingLocalSnapshotPublication {
            publication: attempt.publication,
            handle: Some(handle),
        })
    }

    pub(crate) async fn fail(
        &self,
        attempt: SnapshotMaterializationAttempt,
        failure: &'static str,
    ) -> Result<(), SnapshotMaterializationError> {
        let write = DurableAuditWrite::new(
            DurableAuditStreamKind::Materialization,
            attempt.operation_id,
            DurableAuditPhase::Completion,
            json!({
                "schema": "registry.relay.materialization-completion/v1",
                "attempt_event": attempt.attempt.to_safe_payload_value(),
                "outcome": "failed",
                "failure_class": failure,
                "private_binding_hash": attempt.facts.binding_id.as_str(),
            }),
        )
        .map_err(|_| SnapshotMaterializationError::InvalidState)?;
        match self.state_plane.audit().write_phase(&write).await {
            Ok(DurableAuditWriteOutcome::Inserted(_))
            | Ok(DurableAuditWriteOutcome::IdenticalDuplicate(_)) => Ok(()),
            Ok(DurableAuditWriteOutcome::ConflictingDuplicate(_)) | Err(_) => {
                Err(SnapshotMaterializationError::AuditUnavailable)
            }
        }
    }

    pub(crate) async fn active_candidate(
        &self,
        table_provider: &str,
    ) -> Result<Option<ActiveSnapshotCandidate>, SnapshotMaterializationError> {
        let facts = self
            .facts
            .get(table_provider)
            .ok_or(SnapshotMaterializationError::UnknownProvider)?;
        let active = self
            .state_plane
            .audit()
            .active_materialization(&facts.binding_id)
            .await
            .map_err(|_| SnapshotMaterializationError::Unavailable)?;
        active
            .map(|active| {
                Ok(ActiveSnapshotCandidate {
                    generation: Ulid::from_string(active.generation_id().as_str())
                        .map_err(|_| SnapshotMaterializationError::InvalidState)?,
                    digest: *active.content_digest().as_bytes(),
                    source_revision: active
                        .source_revision()
                        .map(|revision| revision.as_str().to_owned()),
                    source_observed_at_unix_ms: active.source_observed_at_unix_ms(),
                })
            })
            .transpose()
    }

    pub(crate) async fn reconcile(
        &self,
        table_provider: &str,
        candidate: SnapshotMaterializationCandidate,
    ) -> Result<PendingLocalSnapshotPublication, SnapshotMaterializationError> {
        let facts = self
            .facts
            .get(table_provider)
            .ok_or(SnapshotMaterializationError::UnknownProvider)?;
        let publication = self
            .snapshots
            .begin_publication(table_provider)
            .map_err(|_| SnapshotMaterializationError::Unavailable)?;
        let request = MaterializationPublicationRequest::new(
            facts.binding_id.clone(),
            MaterializationGenerationId::parse(&candidate.generation.to_string())
                .map_err(|_| SnapshotMaterializationError::InvalidState)?,
            RestrictedMaterializationContentDigest::from_sha256(candidate.digest),
            candidate
                .source_revision
                .as_deref()
                .map(MaterializationSourceRevision::parse)
                .transpose()
                .map_err(|_| SnapshotMaterializationError::InvalidState)?,
            candidate.source_observed_at_unix_ms,
        )
        .map_err(|_| SnapshotMaterializationError::InvalidState)?;
        let active = self
            .state_plane
            .audit()
            .reconcile_materialization(&request)
            .await
            .map_err(|_| SnapshotMaterializationError::PublicationRejected)?;
        let handle = PublishedSnapshotHandle::new(
            candidate.generation,
            SnapshotContentDigest::from_bytes(candidate.digest),
            active.published_at_unix_ms(),
            candidate.source_revision,
            candidate.source_observed_at_unix_ms,
            candidate.provider,
        )
        .map_err(|_| SnapshotMaterializationError::InvalidState)?;
        Ok(PendingLocalSnapshotPublication {
            publication,
            handle: Some(handle),
        })
    }
}

pub(crate) struct SnapshotMaterializationAttempt {
    operation_id: DurableAuditOperationId,
    attempt: CompletionAttemptReference,
    facts: Arc<MaterializationFacts>,
    publication: SnapshotPublicationGuard,
}

pub(crate) struct SnapshotMaterializationCandidate {
    pub(crate) generation: Ulid,
    pub(crate) digest: [u8; 32],
    pub(crate) source_revision: Option<String>,
    pub(crate) source_observed_at_unix_ms: Option<i64>,
    pub(crate) row_count: u64,
    pub(crate) byte_count: u64,
    pub(crate) provider: Arc<dyn TableProvider>,
}

pub(crate) struct ActiveSnapshotCandidate {
    pub(crate) generation: Ulid,
    pub(crate) digest: [u8; 32],
    pub(crate) source_revision: Option<String>,
    pub(crate) source_observed_at_unix_ms: Option<i64>,
}

#[must_use = "durably published snapshot must be installed or remain unavailable"]
pub(crate) struct PendingLocalSnapshotPublication {
    publication: SnapshotPublicationGuard,
    handle: Option<PublishedSnapshotHandle>,
}

impl PendingLocalSnapshotPublication {
    pub(crate) fn finish(mut self) {
        let handle = self
            .handle
            .take()
            .expect("pending publication always retains its exact handle");
        self.publication.publish(handle);
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum SnapshotMaterializationError {
    #[error("snapshot materialization configuration is invalid")]
    InvalidConfiguration,
    #[error("snapshot materialization provider is unknown")]
    UnknownProvider,
    #[error("snapshot materialization audit is unavailable")]
    AuditUnavailable,
    #[error("snapshot materialization publication is unavailable")]
    Unavailable,
    #[error("snapshot materialization state is invalid")]
    InvalidState,
    #[error("snapshot materialization footprint was exceeded")]
    FootprintExceeded,
    #[error("snapshot materialization publication was rejected")]
    PublicationRejected,
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

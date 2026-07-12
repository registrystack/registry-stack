// SPDX-License-Identifier: Apache-2.0
//! Fail-closed materialization attempt and publication orchestration.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use datafusion::catalog::TableProvider;
use registry_platform_audit::{
    DurableAuditOperationId, DurableAuditPhase, DurableAuditSink, DurableAuditStreamKind,
    DurableAuditWrite, DurableAuditWriteOutcome,
};
use registry_platform_crypto::canonicalize_json;
use serde_json::json;
use sha2::{Digest, Sha256};
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
    table_provider: Box<str>,
    key_physical_fields: BTreeSet<Box<str>>,
    required_physical_fields: BTreeSet<Box<str>>,
    dependent_profiles: BTreeSet<MaterializationDependentProfile>,
    acquisition_fields: Box<[Box<str>]>,
    max_source_records: u64,
    max_source_bytes: u64,
    max_data_exchanges: u8,
    max_credential_exchanges: u8,
    max_data_destinations: u8,
    snapshot_retention_generations: u16,
    max_snapshot_age_ms: u64,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MaterializationDependentProfile {
    profile_id: Box<str>,
    profile_version: Box<str>,
    profile_hash: Box<str>,
    integration_pack_id: Box<str>,
    integration_pack_version: Box<str>,
    integration_pack_hash: Box<str>,
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
        let facts = compile_materialization_facts(registry)?;
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
        facts.key_physical_fields.iter().all(|field| {
            schema
                .field(field)
                .is_some_and(|field| field.ty == FieldType::String)
        }) && facts
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
            materialization_attempt_payload(&facts, connector_kind),
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

fn materialization_attempt_payload(
    facts: &MaterializationFacts,
    connector_kind: &'static str,
) -> serde_json::Value {
    json!({
        "schema": "registry.relay.materialization-attempt/v1",
        "materialization": {
            "private_binding_hash": facts.binding_id.as_str(),
        },
        "dependent_profiles": dependent_profile_payloads(&facts.dependent_profiles),
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
    })
}

fn compile_materialization_facts(
    registry: &CompiledConsultationRegistry,
) -> Result<BTreeMap<Box<str>, Arc<MaterializationFacts>>, SnapshotMaterializationError> {
    let mut facts = BTreeMap::<Box<str>, MaterializationFacts>::new();
    for plan in registry
        .plans_for_concrete_activation()
        .filter(|plan| plan.kind() == SourcePlanKind::SnapshotExact)
    {
        let binding = plan
            .snapshot_binding()
            .ok_or(SnapshotMaterializationError::InvalidConfiguration)?;
        let profile = plan.profile();
        let pack = plan.integration_pack();
        let dependent_profile = MaterializationDependentProfile {
            profile_id: profile.id().as_str().into(),
            profile_version: profile.version().to_string().into(),
            profile_hash: profile.contract_hash().as_str().into(),
            integration_pack_id: pack.id().as_str().into(),
            integration_pack_version: pack.version().to_string().into(),
            integration_pack_hash: pack.hash().as_str().into(),
        };
        if let Some(existing) = facts.get_mut(binding.table_provider()) {
            let candidate = MaterializationFacts {
                binding_id: materialization_binding_id(binding)?,
                table_provider: binding.table_provider().into(),
                key_physical_fields: binding.keys().map(|(_, field)| field.into()).collect(),
                required_physical_fields: required_physical_fields(binding),
                dependent_profiles: BTreeSet::new(),
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
            };
            if !materialization_facts_compatible(existing, &candidate)
                || !existing.dependent_profiles.insert(dependent_profile)
            {
                return Err(SnapshotMaterializationError::InvalidConfiguration);
            }
            continue;
        }
        facts.insert(
            binding.table_provider().into(),
            MaterializationFacts {
                binding_id: materialization_binding_id(binding)?,
                table_provider: binding.table_provider().into(),
                key_physical_fields: binding.keys().map(|(_, field)| field.into()).collect(),
                required_physical_fields: required_physical_fields(binding),
                dependent_profiles: BTreeSet::from([dependent_profile]),
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
            },
        );
    }
    Ok(facts
        .into_iter()
        .map(|(provider, facts)| (provider, Arc::new(facts)))
        .collect())
}

fn required_physical_fields(
    binding: &crate::source_plan::CompiledSnapshotBinding,
) -> BTreeSet<Box<str>> {
    let mut fields = binding
        .projection()
        .map(|(_, physical)| physical.into())
        .collect::<BTreeSet<Box<str>>>();
    fields.extend(binding.keys().map(|(_, physical)| physical.into()));
    if let Some((_, physical)) = binding.source_observed_at_extraction() {
        fields.insert(physical.into());
    }
    if let Some((_, physical, _)) = binding.source_revision_extraction() {
        fields.insert(physical.into());
    }
    fields
}

fn dependent_profile_payloads(
    profiles: &BTreeSet<MaterializationDependentProfile>,
) -> Vec<serde_json::Value> {
    profiles
        .iter()
        .map(|profile| {
            json!({
                "profile": {
                    "id": profile.profile_id,
                    "version": profile.profile_version,
                    "contract_hash": profile.profile_hash,
                },
                "integration_pack": {
                    "id": profile.integration_pack_id,
                    "version": profile.integration_pack_version,
                    "hash": profile.integration_pack_hash,
                }
            })
        })
        .collect()
}

fn materialization_facts_compatible(
    left: &MaterializationFacts,
    right: &MaterializationFacts,
) -> bool {
    left.binding_id == right.binding_id
        && left.table_provider == right.table_provider
        && left.key_physical_fields == right.key_physical_fields
        && left.required_physical_fields == right.required_physical_fields
        && left.acquisition_fields == right.acquisition_fields
        && left.max_source_records == right.max_source_records
        && left.max_source_bytes == right.max_source_bytes
        && left.max_data_exchanges == right.max_data_exchanges
        && left.max_credential_exchanges == right.max_credential_exchanges
        && left.max_data_destinations == right.max_data_destinations
        && left.snapshot_retention_generations == right.snapshot_retention_generations
        && left.max_snapshot_age_ms == right.max_snapshot_age_ms
}

fn materialization_binding_id(
    binding: &crate::source_plan::CompiledSnapshotBinding,
) -> Result<MaterializationPublicationBindingId, SnapshotMaterializationError> {
    let value = json!({
        "schema": "registry.relay.materialization-identity.v1",
        "table_provider": binding.table_provider(),
        "keys": binding.keys().map(|(input, physical)| json!({
            "input": input,
            "physical_field": physical,
            "physical_type": "utf8",
            "comparison": "binary_equality",
        })).collect::<Vec<_>>(),
        "projection": binding.projection().collect::<BTreeMap<_, _>>(),
        "limits": {
            "max_snapshot_age_ms": binding.max_snapshot_age_ms(),
            "max_source_records": binding.max_source_records(),
            "max_source_bytes": binding.max_source_bytes(),
            "max_data_exchanges": binding.max_refresh_data_exchanges(),
            "max_credential_exchanges": binding.max_refresh_credential_exchanges(),
            "max_data_destinations": binding.max_refresh_data_destinations(),
            "snapshot_retention_generations": binding.snapshot_retention_generations(),
        }
    });
    let canonical = canonicalize_json(&value)
        .map_err(|_| SnapshotMaterializationError::InvalidConfiguration)?;
    let mut hasher = Sha256::new();
    hasher.update(b"registry.relay.materialization-identity.v1\0");
    hasher.update(canonical);
    let digest: [u8; 32] = hasher.finalize().into();
    MaterializationPublicationBindingId::parse(&format!("sha256:{}", encode_hex(&digest)))
        .map_err(|_| SnapshotMaterializationError::InvalidConfiguration)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_materialization_audit_facts_bind_the_complete_sorted_profile_closure() {
        let registry = crate::source_plan::shared_snapshot_registry_fixture();
        let facts = compile_materialization_facts(&registry).expect("shared materialization facts");
        assert_eq!(facts.len(), 1);
        let facts = facts.values().next().expect("one shared provider");
        assert_eq!(facts.dependent_profiles.len(), 2);
        let profile_ids = facts
            .dependent_profiles
            .iter()
            .map(|profile| profile.profile_id.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(
            profile_ids,
            [
                "synthetic.person-status.exact",
                "synthetic.person-status.snapshot-second",
            ]
        );
        let payload = dependent_profile_payloads(&facts.dependent_profiles);
        assert_eq!(payload.len(), 2);
        assert_eq!(payload[0]["profile"]["id"], "synthetic.person-status.exact");
        assert_eq!(
            payload[1]["profile"]["id"],
            "synthetic.person-status.snapshot-second"
        );
        assert!(payload.iter().all(|entry| {
            entry["profile"]["contract_hash"]
                .as_str()
                .is_some_and(|value| value.starts_with("sha256:"))
                && entry["integration_pack"]["hash"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("sha256:"))
        }));

        let private_provider = facts.table_provider.as_ref();
        let attempt = materialization_attempt_payload(facts, "fixture");
        let encoded = serde_json::to_string(&attempt).expect("serialize audit payload");
        assert!(!attempt["materialization"]
            .as_object()
            .unwrap()
            .contains_key("table_provider"));
        assert!(!encoded.contains(private_provider));
        assert_eq!(
            attempt["materialization"]["private_binding_hash"],
            facts.binding_id.as_str()
        );
    }
}

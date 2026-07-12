// SPDX-License-Identifier: Apache-2.0
//! Immutable, typed consultation facts consumed after startup compilation.
//!
//! This module deliberately has no deserializer and retains no canonical JSON,
//! request selector, predicate, destination origin, credential, deployment
//! parameter, or script source. Runtime admission and state-plane construction
//! consume only the already validated values in [`CompiledRuntimeProfile`].

use std::fmt;

use crate::consultation::{
    AcquiredField, DeclaredOperationFootprint, IntegrationPackHash, IntegrationPackIdentity,
    OperationId, PolicyIdentity, ProfileIdentity, RegistryInstanceId, RequiredConsultationScope,
    SelectorProvenance, TenantId, WorkloadId,
};

use super::artifact::{
    ConsentRevocationDocument, OutputTypeDocument, PrivateBindingHash, PublicContractArtifact,
    SourceCardinality, SourceObservedAtDocument, SourcePlanKind, SourcePlanLimits,
    SourceRevisionDocument,
};
#[cfg(test)]
use super::compiler::CompiledScalarShape;
use super::compiler::{
    compile_runtime_response_schema, CompiledInputCanonicalization, CompiledOperation,
    CompiledResponseSchema, CompiledSnapshotBinding, CompiledSourceAuth, CompiledStep,
    RhaiWorkerLimits, SourcePlanCompileError,
};
use super::completion_seed::{compile_runtime_commitment_digests, CompiledCompletionSeedTemplate};
use super::identifiers::{CanonicalPurpose, LegalBasisId, SourceDestinationId};

/// Canonical completion-intent seed ceiling enforced by both compiler and SQL.
pub(crate) const MAX_COMPLETION_SEED_CANONICAL_BYTES_V1: usize = 256 * 1024;

macro_rules! compiled_digest {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub(crate) struct $name(Box<str>);

        impl $name {
            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }

            pub(super) fn from_compiled_label(
                label: Box<str>,
            ) -> Result<Self, SourcePlanCompileError> {
                IntegrationPackHash::try_from(label.as_ref())
                    .map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
                Ok(Self(label))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&"sha256:<redacted>")
                    .finish()
            }
        }
    };
}

compiled_digest!(
    /// Digest of the exact typed compiled predicate-plan v1 preimage.
    PredicatePlanDigest
);
compiled_digest!(
    /// Digest of the fixed physical projection and cardinality mechanisms.
    PhysicalProjectionDigest
);

/// Safe Rhai identity borrowed from the already validated integration pack.
///
/// The script source is intentionally absent. This value is consumed while
/// deriving the predicate-plan digest and is not retained in the runtime
/// profile.
pub(super) struct RhaiPredicateIdentity {
    script_hash: Box<str>,
    entrypoint: Box<str>,
}

impl RhaiPredicateIdentity {
    pub(super) fn from_validated_artifact(
        script_hash: &str,
        entrypoint: &str,
    ) -> Result<Self, SourcePlanCompileError> {
        let mut entrypoint_bytes = entrypoint.bytes();
        let valid_entrypoint = matches!(entrypoint_bytes.next(), Some(b'a'..=b'z'))
            && entrypoint.len() <= 96
            && entrypoint_bytes.all(|byte| {
                matches!(
                    byte,
                    b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'-'
                )
            });
        if IntegrationPackHash::try_from(script_hash).is_err() || !valid_entrypoint {
            return Err(SourcePlanCompileError::CompilerInvariant);
        }
        Ok(Self {
            script_hash: script_hash.into(),
            entrypoint: entrypoint.into(),
        })
    }

    pub(super) fn script_hash(&self) -> &str {
        &self.script_hash
    }

    pub(super) fn entrypoint(&self) -> &str {
        &self.entrypoint
    }
}

/// The typed, immutable consultation profile used by runtime layers.
pub(crate) struct CompiledRuntimeProfile {
    profile: ProfileIdentity,
    integration_pack: IntegrationPackIdentity,
    private_binding_hash: PrivateBindingHash,
    workload_id: WorkloadId,
    required_scope: RequiredConsultationScope,
    tenant: TenantId,
    registry_instance: RegistryInstanceId,
    subject: CompiledSubjectDescriptor,
    inputs: Box<[CompiledRuntimeInputDescriptor]>,
    purposes: Box<[CanonicalPurpose]>,
    legal_basis: LegalBasisId,
    authorization: CompiledAuthorizationProfile,
    public_limits: SourcePlanLimits,
    effective_limits: SourcePlanLimits,
    acquisition: CompiledAcquisitionSchema,
    acquisition_provenance: CompiledAcquisitionProvenanceContract,
    output: Box<[CompiledOutputField]>,
    outcomes: Box<[CompiledPublicOutcome]>,
    provenance: CompiledSourceProvenance,
    footprint: DeclaredOperationFootprint,
    kind: SourcePlanKind,
    cardinality: SourceCardinality,
    dispatch: CompiledDispatchProfile,
    operations: Box<[CompiledDataOperationDescriptor]>,
    predicate_plan_digest: PredicatePlanDigest,
    physical_projection_digest: PhysicalProjectionDigest,
    completion_seed_template: CompiledCompletionSeedTemplate,
    completion_seed_canonical_bytes_max: usize,
    completion_audit_canonical_bytes_max: usize,
}

impl fmt::Debug for CompiledRuntimeProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledRuntimeProfile")
            .field("profile", &self.profile)
            .field("integration_pack", &self.integration_pack)
            .field("kind", &self.kind)
            .field("cardinality", &self.cardinality)
            .field("input_count", &self.inputs.len())
            .field("operation_count", &self.operations.len())
            .field("acquired_field_count", &self.acquisition.fields.len())
            .field("output_field_count", &self.output.len())
            .finish_non_exhaustive()
    }
}

impl CompiledRuntimeProfile {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::source_plan) fn from_compiled_artifacts(
        contract: &PublicContractArtifact,
        integration_pack: IntegrationPackIdentity,
        private_binding_hash: PrivateBindingHash,
        tenant: TenantId,
        registry_instance: RegistryInstanceId,
        footprint: DeclaredOperationFootprint,
        effective_limits: SourcePlanLimits,
        operations: &[CompiledOperation],
        steps: &[CompiledStep],
        data_destination_id: Option<&SourceDestinationId>,
        rhai_worker_limits: Option<RhaiWorkerLimits>,
        rhai_predicate_identity: Option<RhaiPredicateIdentity>,
        completion_seed_template: CompiledCompletionSeedTemplate,
        completion_seed_canonical_bytes_max: usize,
        completion_audit_canonical_bytes_max: usize,
        product_family: &str,
        supported_version_evidence: &[String],
        logical_operation: OperationId,
        kind: SourcePlanKind,
        snapshot: Option<&CompiledSnapshotBinding>,
    ) -> Result<Self, SourcePlanCompileError> {
        let authorization_document = &contract.document.spec.authorization;
        let consent = if authorization_document.consent.required {
            let (verifier, contract_hash) = contract
                .consent_verifier
                .as_ref()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            CompiledConsentProfile::Required {
                verifier: verifier.clone(),
                contract_hash: contract_hash.clone(),
                max_age_ms: authorization_document
                    .consent
                    .max_age_ms
                    .ok_or(SourcePlanCompileError::CompilerInvariant)?,
                online_revocation_required: matches!(
                    authorization_document.consent.revocation,
                    Some(ConsentRevocationDocument::OnlineRequired)
                ),
                deny_when_unavailable: authorization_document.consent.unavailable.is_some(),
            }
        } else {
            CompiledConsentProfile::NotRequired
        };
        let authorization = CompiledAuthorizationProfile {
            policy: contract.policy_identity.clone(),
            decision_cache_disabled: true,
            max_decision_age_ms: authorization_document.policy.max_decision_age_ms,
            deny_when_unavailable: true,
            consent,
            mandatory_obligations: CompiledMandatoryObligationsV1,
        };
        let subject = CompiledSubjectDescriptor {
            mode: CompiledSubjectMode::SingleSubject,
            selector_provenance: contract.selector_provenance.clone(),
        };
        let inputs = contract
            .document
            .spec
            .inputs
            .iter()
            .map(|(name, input)| CompiledRuntimeInputDescriptor {
                name: name.as_str().into(),
                max_bytes: input.max_bytes,
                canonicalization: match input.canonicalization {
                    super::artifact::CanonicalizationDocument::Identity => {
                        CompiledInputCanonicalization::Identity
                    }
                    super::artifact::CanonicalizationDocument::AsciiLowercase => {
                        CompiledInputCanonicalization::AsciiLowercase
                    }
                },
            })
            .collect();
        let acquisition = CompiledAcquisitionSchema {
            fields: contract
                .document
                .spec
                .acquisition
                .fields
                .iter()
                .map(|(name, schema)| {
                    Ok(CompiledAcquisitionField {
                        name: AcquiredField::try_from(name.as_str())
                            .map_err(|_| SourcePlanCompileError::CompilerInvariant)?,
                        schema: compile_runtime_response_schema(schema),
                    })
                })
                .collect::<Result<_, SourcePlanCompileError>>()?,
        };
        let output = contract
            .document
            .spec
            .output
            .iter()
            .map(|(name, field)| {
                Ok(CompiledOutputField {
                    name: AcquiredField::try_from(name.as_str())
                        .map_err(|_| SourcePlanCompileError::CompilerInvariant)?,
                    shape: match field.output_type {
                        OutputTypeDocument::String => CompiledOutputShape::String {
                            nullable: field.nullable,
                        },
                        OutputTypeDocument::Boolean => CompiledOutputShape::Boolean {
                            nullable: field.nullable,
                        },
                        OutputTypeDocument::Integer => CompiledOutputShape::Integer {
                            nullable: field.nullable,
                        },
                        OutputTypeDocument::Number => CompiledOutputShape::Number {
                            nullable: field.nullable,
                        },
                    },
                })
            })
            .collect::<Result<_, SourcePlanCompileError>>()?;
        let outcomes = contract
            .document
            .spec
            .public_behavior
            .outcomes
            .iter()
            .map(|outcome| match outcome {
                super::artifact::OutcomeDocument::Match => CompiledPublicOutcome::Match,
                super::artifact::OutcomeDocument::NoMatch => CompiledPublicOutcome::NoMatch,
                super::artifact::OutcomeDocument::Ambiguous => CompiledPublicOutcome::Ambiguous,
            })
            .collect();
        let operation_descriptors = operations
            .iter()
            .map(|operation| CompiledDataOperationDescriptor {
                id: operation.id().clone(),
                kind: CompiledDataOperationKind::Http {
                    method: operation.method(),
                },
                destination_id: data_destination_id.cloned(),
                auth: operation.auth(),
                acquisition_class: operation.acquisition_class(),
                cardinality: operation.cardinality(),
                response_schema: operation.response().schema().clone(),
                bounds: CompiledDataOperationBounds {
                    max_calls: operation.max_source_calls(),
                    max_source_records: operation.max_source_records(),
                    max_response_bytes: operation.response_max_bytes(),
                    request_timeout_ms: operation.request_timeout_ms(),
                    request_max_in_flight: operation.request_max_in_flight(),
                },
            })
            .collect();
        let dispatch = match (kind, rhai_worker_limits) {
            (SourcePlanKind::SandboxedRhai, Some(limits)) => {
                let mut callable_operations = operations
                    .iter()
                    .map(|operation| operation.id().clone())
                    .collect::<Vec<_>>();
                callable_operations.sort();
                CompiledDispatchProfile::SandboxedRhai {
                    callable_operations: callable_operations.into_boxed_slice(),
                    worker_limits: CompiledRhaiWorkerLimits::from(limits),
                }
            }
            (SourcePlanKind::SnapshotExact, None) if operations.is_empty() && steps.is_empty() => {
                CompiledDispatchProfile::SnapshotExact
            }
            (SourcePlanKind::BoundedHttp, None) => CompiledDispatchProfile::BoundedHttp {
                ordered_operations: {
                    let mut ordered = Vec::new();
                    for step in steps {
                        let operation = operations
                            .get(step.operation_index())
                            .ok_or(SourcePlanCompileError::CompilerInvariant)?;
                        if let Some(jwks) = operation.embedded_open_crvs_jwks() {
                            ordered.push(jwks.id().clone());
                        }
                        ordered.push(operation.id().clone());
                    }
                    ordered.into_boxed_slice()
                },
            },
            _ => return Err(SourcePlanCompileError::CompilerInvariant),
        };
        let (predicate_plan_digest, physical_projection_digest) =
            compile_runtime_commitment_digests(
                kind,
                contract
                    .document
                    .spec
                    .inputs
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .as_slice(),
                operations,
                steps,
                &dispatch,
                rhai_predicate_identity.as_ref(),
                snapshot,
            )?;
        let (observed, revision) = (
            &contract.document.spec.source_provenance.source_observed_at,
            &contract.document.spec.source_provenance.source_revision,
        );
        let acquisition_provenance = CompiledAcquisitionProvenanceContract {
            source_observed_at: match observed {
                SourceObservedAtDocument::Absent => CompiledSourceObservedAtContract::Absent,
                SourceObservedAtDocument::AcquiredRfc3339 { field } => {
                    let (_, physical_field) = snapshot
                        .and_then(CompiledSnapshotBinding::source_observed_at_extraction)
                        .filter(|(logical, _)| *logical == field)
                        .ok_or(SourcePlanCompileError::CompilerInvariant)?;
                    CompiledSourceObservedAtContract::AcquiredRfc3339 {
                        field: AcquiredField::try_from(field.as_str())
                            .map_err(|_| SourcePlanCompileError::CompilerInvariant)?,
                        physical_field: physical_field.into(),
                    }
                }
            },
            source_revision: match revision {
                SourceRevisionDocument::Absent => CompiledSourceRevisionContract::Absent,
                SourceRevisionDocument::AcquiredString { field, max_bytes } => {
                    let (_, physical_field, compiled_max) = snapshot
                        .and_then(CompiledSnapshotBinding::source_revision_extraction)
                        .filter(|(logical, _, _)| *logical == field)
                        .ok_or(SourcePlanCompileError::CompilerInvariant)?;
                    if compiled_max != *max_bytes {
                        return Err(SourcePlanCompileError::CompilerInvariant);
                    }
                    CompiledSourceRevisionContract::AcquiredString {
                        field: AcquiredField::try_from(field.as_str())
                            .map_err(|_| SourcePlanCompileError::CompilerInvariant)?,
                        physical_field: physical_field.into(),
                        max_bytes: *max_bytes,
                    }
                }
            },
            snapshot_generation_required: kind == SourcePlanKind::SnapshotExact,
            snapshot_published_at_required: kind == SourcePlanKind::SnapshotExact,
        };
        Ok(Self {
            profile: contract.identity().clone(),
            integration_pack,
            private_binding_hash,
            workload_id: contract.workload_id.clone(),
            required_scope: contract.required_scope.clone(),
            tenant,
            registry_instance,
            subject,
            inputs,
            purposes: contract.purposes.clone(),
            legal_basis: contract.legal_basis.clone(),
            authorization,
            public_limits: SourcePlanLimits::from_document(contract.public_limits),
            effective_limits,
            acquisition,
            acquisition_provenance,
            output,
            outcomes,
            provenance: CompiledSourceProvenance {
                product_family: product_family.into(),
                supported_version_evidence: supported_version_evidence
                    .iter()
                    .map(|value| value.as_str().into())
                    .collect(),
                logical_operation,
            },
            footprint,
            kind,
            cardinality: contract.cardinality,
            dispatch,
            operations: operation_descriptors,
            predicate_plan_digest,
            physical_projection_digest,
            completion_seed_template,
            completion_seed_canonical_bytes_max,
            completion_audit_canonical_bytes_max,
        })
    }

    pub(crate) const fn profile(&self) -> &ProfileIdentity {
        &self.profile
    }

    pub(crate) const fn integration_pack(&self) -> &IntegrationPackIdentity {
        &self.integration_pack
    }

    pub(crate) fn private_binding_hash(&self) -> &str {
        self.private_binding_hash.as_str()
    }

    pub(crate) const fn workload_id(&self) -> &WorkloadId {
        &self.workload_id
    }

    pub(crate) const fn required_scope(&self) -> &RequiredConsultationScope {
        &self.required_scope
    }

    pub(crate) const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub(crate) const fn registry_instance(&self) -> &RegistryInstanceId {
        &self.registry_instance
    }

    pub(crate) const fn subject(&self) -> &CompiledSubjectDescriptor {
        &self.subject
    }

    pub(crate) fn inputs(&self) -> impl ExactSizeIterator<Item = &CompiledRuntimeInputDescriptor> {
        self.inputs.iter()
    }

    pub(crate) fn purposes(&self) -> impl ExactSizeIterator<Item = &str> {
        self.purposes.iter().map(CanonicalPurpose::as_str)
    }

    pub(crate) fn legal_basis(&self) -> &str {
        self.legal_basis.as_str()
    }

    pub(crate) const fn authorization(&self) -> &CompiledAuthorizationProfile {
        &self.authorization
    }

    pub(crate) const fn public_limits(&self) -> SourcePlanLimits {
        self.public_limits
    }

    pub(crate) const fn effective_limits(&self) -> SourcePlanLimits {
        self.effective_limits
    }

    pub(crate) const fn acquisition(&self) -> &CompiledAcquisitionSchema {
        &self.acquisition
    }

    pub(crate) const fn acquisition_provenance(&self) -> &CompiledAcquisitionProvenanceContract {
        &self.acquisition_provenance
    }

    pub(crate) fn output(&self) -> impl ExactSizeIterator<Item = &CompiledOutputField> {
        self.output.iter()
    }

    pub(crate) fn outcomes(&self) -> impl ExactSizeIterator<Item = CompiledPublicOutcome> + '_ {
        self.outcomes.iter().copied()
    }

    pub(crate) const fn provenance(&self) -> &CompiledSourceProvenance {
        &self.provenance
    }

    pub(crate) const fn footprint(&self) -> &DeclaredOperationFootprint {
        &self.footprint
    }

    pub(crate) const fn kind(&self) -> SourcePlanKind {
        self.kind
    }

    pub(crate) const fn cardinality(&self) -> SourceCardinality {
        self.cardinality
    }

    pub(crate) const fn dispatch(&self) -> &CompiledDispatchProfile {
        &self.dispatch
    }

    pub(crate) fn operations(
        &self,
    ) -> impl ExactSizeIterator<Item = &CompiledDataOperationDescriptor> {
        self.operations.iter()
    }

    pub(crate) const fn predicate_plan_digest(&self) -> &PredicatePlanDigest {
        &self.predicate_plan_digest
    }

    pub(crate) const fn physical_projection_digest(&self) -> &PhysicalProjectionDigest {
        &self.physical_projection_digest
    }

    pub(crate) fn authorized_operation_union(
        &self,
    ) -> impl ExactSizeIterator<Item = (&'static str, &str)> {
        self.completion_seed_template
            .authorized_operation_union()
            .map(|operation| (operation.kind().as_str(), operation.operation_id()))
    }

    pub(crate) fn permit_bindings(
        &self,
    ) -> impl ExactSizeIterator<Item = (&'static str, u8, Vec<&str>)> {
        self.completion_seed_template
            .permit_bindings()
            .map(|binding| {
                (
                    binding.kind().as_str(),
                    binding.ordinal(),
                    binding.allowed_operation_ids().collect(),
                )
            })
    }

    pub(crate) fn credential_destination_id(&self) -> Option<&str> {
        self.completion_seed_template.credential_destination_id()
    }

    pub(crate) fn data_destination_id(&self) -> Option<&str> {
        self.completion_seed_template.data_destination_id()
    }

    pub(crate) fn credential_reference(&self) -> Option<&str> {
        self.completion_seed_template.credential_reference()
    }

    pub(crate) const fn credential_generation(&self) -> Option<u64> {
        self.completion_seed_template.credential_generation()
    }

    pub(crate) const fn credential_token_lifetime_ms(&self) -> Option<u32> {
        self.completion_seed_template.credential_token_lifetime_ms()
    }

    pub(crate) const fn completion_seed_canonical_bytes_max(&self) -> usize {
        self.completion_seed_canonical_bytes_max
    }

    pub(crate) const fn completion_audit_canonical_bytes_max(&self) -> usize {
        self.completion_audit_canonical_bytes_max
    }

    #[cfg(test)]
    pub(in crate::source_plan) fn install_maximum_recursive_schema_fixture(
        &mut self,
        schema: CompiledResponseSchema,
    ) -> Result<(), SourcePlanCompileError> {
        let mut acquired_fields = Vec::with_capacity(64);
        acquired_fields.push(CompiledAcquisitionField {
            name: AcquiredField::try_from("recursive_max")
                .map_err(|_| SourcePlanCompileError::CompilerInvariant)?,
            schema: schema.clone(),
        });
        for index in 1..64 {
            acquired_fields.push(CompiledAcquisitionField {
                name: AcquiredField::try_from(format!("scalar_{index:02}").as_str())
                    .map_err(|_| SourcePlanCompileError::CompilerInvariant)?,
                schema: CompiledResponseSchema::Scalar(CompiledScalarShape::String {
                    nullable: false,
                    max_bytes: 65_536,
                }),
            });
        }
        self.footprint = DeclaredOperationFootprint::try_new(
            self.provenance.logical_operation.as_str(),
            self.footprint.acquisition_class(),
            acquired_fields.iter().map(CompiledAcquisitionField::name),
            self.footprint.bounds(),
        )
        .map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
        self.acquisition.fields = acquired_fields.into_boxed_slice();
        let mut output = Vec::with_capacity(64);
        output.push(CompiledOutputField {
            name: AcquiredField::try_from("recursive_leaf")
                .map_err(|_| SourcePlanCompileError::CompilerInvariant)?,
            shape: CompiledOutputShape::String { nullable: false },
        });
        for index in 1..64 {
            output.push(CompiledOutputField {
                name: AcquiredField::try_from(format!("scalar_{index:02}").as_str())
                    .map_err(|_| SourcePlanCompileError::CompilerInvariant)?,
                shape: CompiledOutputShape::String { nullable: false },
            });
        }
        self.output = output.into_boxed_slice();
        let operation = self
            .operations
            .first_mut()
            .ok_or(SourcePlanCompileError::CompilerInvariant)?;
        operation.response_schema = schema;
        self.completion_seed_canonical_bytes_max = MAX_COMPLETION_SEED_CANONICAL_BYTES_V1;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledSubjectDescriptor {
    mode: CompiledSubjectMode,
    selector_provenance: SelectorProvenance,
}

impl CompiledSubjectDescriptor {
    pub(crate) const fn mode(&self) -> CompiledSubjectMode {
        self.mode
    }

    pub(crate) const fn selector_provenance(&self) -> &SelectorProvenance {
        &self.selector_provenance
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledSubjectMode {
    SingleSubject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledRuntimeInputDescriptor {
    name: Box<str>,
    max_bytes: u16,
    canonicalization: CompiledInputCanonicalization,
}

impl CompiledRuntimeInputDescriptor {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) const fn max_bytes(&self) -> u16 {
        self.max_bytes
    }

    pub(crate) const fn canonicalization(&self) -> CompiledInputCanonicalization {
        self.canonicalization
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledAuthorizationProfile {
    policy: PolicyIdentity,
    decision_cache_disabled: bool,
    max_decision_age_ms: u32,
    deny_when_unavailable: bool,
    consent: CompiledConsentProfile,
    mandatory_obligations: CompiledMandatoryObligationsV1,
}

impl CompiledAuthorizationProfile {
    pub(crate) const fn policy(&self) -> &PolicyIdentity {
        &self.policy
    }

    pub(crate) const fn decision_cache_disabled(&self) -> bool {
        self.decision_cache_disabled
    }

    pub(crate) const fn max_decision_age_ms(&self) -> u32 {
        self.max_decision_age_ms
    }

    pub(crate) const fn deny_when_unavailable(&self) -> bool {
        self.deny_when_unavailable
    }

    pub(crate) const fn consent(&self) -> &CompiledConsentProfile {
        &self.consent
    }

    pub(crate) const fn mandatory_obligations(&self) -> CompiledMandatoryObligationsV1 {
        self.mandatory_obligations
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompiledConsentProfile {
    NotRequired,
    Required {
        verifier: OperationId,
        contract_hash: IntegrationPackHash,
        max_age_ms: u32,
        online_revocation_required: bool,
        deny_when_unavailable: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompiledMandatoryObligationsV1;

impl CompiledMandatoryObligationsV1 {
    pub(crate) const fn is_empty(self) -> bool {
        true
    }
}

/// Dedicated acquisition-union envelope. It is not a response object node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledAcquisitionSchema {
    fields: Box<[CompiledAcquisitionField]>,
}

impl CompiledAcquisitionSchema {
    pub(crate) fn fields(&self) -> impl ExactSizeIterator<Item = &CompiledAcquisitionField> {
        self.fields.iter()
    }

    pub(crate) fn field(&self, name: &str) -> Option<&CompiledAcquisitionField> {
        self.fields
            .binary_search_by(|field| field.name().cmp(name))
            .ok()
            .map(|index| &self.fields[index])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledAcquisitionField {
    name: AcquiredField,
    schema: CompiledResponseSchema,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledAcquisitionProvenanceContract {
    source_observed_at: CompiledSourceObservedAtContract,
    source_revision: CompiledSourceRevisionContract,
    snapshot_generation_required: bool,
    snapshot_published_at_required: bool,
}

impl CompiledAcquisitionProvenanceContract {
    pub(crate) const fn source_observed_at(&self) -> &CompiledSourceObservedAtContract {
        &self.source_observed_at
    }

    pub(crate) const fn source_revision(&self) -> &CompiledSourceRevisionContract {
        &self.source_revision
    }

    pub(crate) const fn snapshot_generation_required(&self) -> bool {
        self.snapshot_generation_required
    }

    pub(crate) const fn snapshot_published_at_required(&self) -> bool {
        self.snapshot_published_at_required
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompiledSourceObservedAtContract {
    Absent,
    AcquiredRfc3339 {
        field: AcquiredField,
        physical_field: Box<str>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompiledSourceRevisionContract {
    Absent,
    AcquiredString {
        field: AcquiredField,
        physical_field: Box<str>,
        max_bytes: u16,
    },
}

impl CompiledAcquisitionField {
    pub(crate) fn name(&self) -> &str {
        self.name.as_str()
    }

    pub(crate) const fn schema(&self) -> &CompiledResponseSchema {
        &self.schema
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledOutputField {
    name: AcquiredField,
    shape: CompiledOutputShape,
}

impl CompiledOutputField {
    pub(crate) fn name(&self) -> &str {
        self.name.as_str()
    }

    pub(crate) const fn shape(&self) -> CompiledOutputShape {
        self.shape
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledOutputShape {
    String { nullable: bool },
    Boolean { nullable: bool },
    Integer { nullable: bool },
    Number { nullable: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledPublicOutcome {
    Match,
    NoMatch,
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledSourceProvenance {
    product_family: Box<str>,
    supported_version_evidence: Box<[Box<str>]>,
    logical_operation: OperationId,
}

impl CompiledSourceProvenance {
    pub(crate) fn product_family(&self) -> &str {
        &self.product_family
    }

    pub(crate) fn supported_version_evidence(&self) -> impl ExactSizeIterator<Item = &str> {
        self.supported_version_evidence.iter().map(AsRef::as_ref)
    }

    pub(crate) const fn logical_operation(&self) -> &OperationId {
        &self.logical_operation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompiledDispatchProfile {
    SnapshotExact,
    BoundedHttp {
        ordered_operations: Box<[OperationId]>,
    },
    SandboxedRhai {
        callable_operations: Box<[OperationId]>,
        worker_limits: CompiledRhaiWorkerLimits,
    },
}

impl CompiledDispatchProfile {
    pub(crate) fn bounded_http_operations(&self) -> Option<&[OperationId]> {
        match self {
            Self::BoundedHttp { ordered_operations } => Some(ordered_operations),
            Self::SnapshotExact | Self::SandboxedRhai { .. } => None,
        }
    }

    pub(crate) fn sandboxed_rhai_operations(&self) -> Option<&[OperationId]> {
        match self {
            Self::SandboxedRhai {
                callable_operations,
                ..
            } => Some(callable_operations),
            Self::SnapshotExact | Self::BoundedHttp { .. } => None,
        }
    }

    pub(crate) const fn sandboxed_rhai_limits(&self) -> Option<CompiledRhaiWorkerLimits> {
        match self {
            Self::SandboxedRhai { worker_limits, .. } => Some(*worker_limits),
            Self::SnapshotExact | Self::BoundedHttp { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompiledRhaiWorkerLimits {
    max_calls: u8,
    memory_bytes: u64,
    cpu_ms: u32,
    ipc_frame_bytes: u32,
    instructions: u64,
    call_depth: u8,
    string_bytes: u32,
    array_items: u32,
    map_entries: u32,
    output_bytes: u32,
    concurrency: u16,
}

impl From<RhaiWorkerLimits> for CompiledRhaiWorkerLimits {
    fn from(limits: RhaiWorkerLimits) -> Self {
        Self {
            max_calls: limits.max_calls,
            memory_bytes: limits.memory_bytes,
            cpu_ms: limits.cpu_ms,
            ipc_frame_bytes: limits.ipc_frame_bytes,
            instructions: limits.instructions,
            call_depth: limits.call_depth,
            string_bytes: limits.string_bytes,
            array_items: limits.array_items,
            map_entries: limits.map_entries,
            output_bytes: limits.output_bytes,
            concurrency: limits.concurrency,
        }
    }
}

impl CompiledRhaiWorkerLimits {
    pub(crate) const fn max_calls(self) -> u8 {
        self.max_calls
    }

    pub(crate) const fn memory_bytes(self) -> u64 {
        self.memory_bytes
    }

    pub(crate) const fn cpu_ms(self) -> u32 {
        self.cpu_ms
    }

    pub(crate) const fn ipc_frame_bytes(self) -> u32 {
        self.ipc_frame_bytes
    }

    pub(crate) const fn instructions(self) -> u64 {
        self.instructions
    }

    pub(crate) const fn call_depth(self) -> u8 {
        self.call_depth
    }

    pub(crate) const fn string_bytes(self) -> u32 {
        self.string_bytes
    }

    pub(crate) const fn array_items(self) -> u32 {
        self.array_items
    }

    pub(crate) const fn map_entries(self) -> u32 {
        self.map_entries
    }

    pub(crate) const fn output_bytes(self) -> u32 {
        self.output_bytes
    }

    pub(crate) const fn concurrency(self) -> u16 {
        self.concurrency
    }
}

pub(crate) struct CompiledDataOperationDescriptor {
    id: OperationId,
    kind: CompiledDataOperationKind,
    destination_id: Option<SourceDestinationId>,
    auth: CompiledSourceAuth,
    acquisition_class: crate::consultation::AcquisitionClass,
    cardinality: SourceCardinality,
    response_schema: CompiledResponseSchema,
    bounds: CompiledDataOperationBounds,
}

impl fmt::Debug for CompiledDataOperationDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledDataOperationDescriptor")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("auth", &self.auth)
            .field("acquisition_class", &self.acquisition_class)
            .field("cardinality", &self.cardinality)
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

impl CompiledDataOperationDescriptor {
    pub(crate) const fn id(&self) -> &OperationId {
        &self.id
    }

    pub(crate) const fn kind(&self) -> CompiledDataOperationKind {
        self.kind
    }

    pub(crate) fn destination_id(&self) -> Option<&str> {
        self.destination_id
            .as_ref()
            .map(SourceDestinationId::as_str)
    }

    pub(crate) const fn auth(&self) -> CompiledSourceAuth {
        self.auth
    }

    pub(crate) const fn acquisition_class(&self) -> crate::consultation::AcquisitionClass {
        self.acquisition_class
    }

    pub(crate) const fn cardinality(&self) -> SourceCardinality {
        self.cardinality
    }

    pub(crate) const fn response_schema(&self) -> &CompiledResponseSchema {
        &self.response_schema
    }

    pub(crate) const fn bounds(&self) -> CompiledDataOperationBounds {
        self.bounds
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledDataOperationKind {
    Http { method: super::artifact::ReadMethod },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompiledDataOperationBounds {
    max_calls: u8,
    max_source_records: u8,
    max_response_bytes: u32,
    request_timeout_ms: u32,
    request_max_in_flight: u16,
}

impl CompiledDataOperationBounds {
    pub(crate) const fn max_calls(self) -> u8 {
        self.max_calls
    }

    pub(crate) const fn max_source_records(self) -> u8 {
        self.max_source_records
    }

    pub(crate) const fn max_response_bytes(self) -> u32 {
        self.max_response_bytes
    }

    pub(crate) const fn request_timeout_ms(self) -> u32 {
        self.request_timeout_ms
    }

    pub(crate) const fn request_max_in_flight(self) -> u16 {
        self.request_max_in_flight
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Private, compiled source-plan capabilities used by Relay consultations.

#[allow(
    dead_code,
    reason = "WP1B stages the closed artifact compiler before the executor integration"
)]
mod artifact;
#[allow(
    dead_code,
    reason = "WP1B stages the closed artifact compiler before the executor integration"
)]
mod compiler;
mod completion_seed;
mod credentials;
mod identifiers;
mod registry;
#[allow(
    dead_code,
    reason = "the typed runtime profile is consumed by the admission/state integration slice"
)]
pub(crate) mod runtime_profile;

pub(crate) mod codec;

pub use artifact::{
    EvidenceClass, ReadMethod, SourceCardinality, SourcePlanArtifactError, SourcePlanKind,
    SourcePlanLimits,
};
pub use compiler::{
    CompiledBodyTemplate, CompiledCardinalityMechanism, CompiledInputCanonicalization,
    CompiledInputMatcher, CompiledInputSlot, CompiledInputValue, CompiledJsonPointer,
    CompiledNamedBodyField, CompiledNamedExpression, CompiledOperation, CompiledOutputMapping,
    CompiledPriorOutputSlot, CompiledProjectionMechanism, CompiledRequestCodec,
    CompiledRequestSigner, CompiledResponse, CompiledResponseField, CompiledResponseNormalization,
    CompiledResponseSchema, CompiledScalarShape, CompiledSelectorBinding, CompiledSelectorLocation,
    CompiledSelectorSource, CompiledSnapshotBinding, CompiledSnapshotRefreshClass,
    CompiledSourceAuth, CompiledSourcePlan, CompiledSourcePlanRegistry, CompiledStep,
    CompiledStepPredicate, CompiledValueExpression, PinnedEvidenceArtifact,
    PinnedSourcePlanArtifact, RhaiWorkerCapability, SourcePlanArtifactBundle,
    SourcePlanCompileError,
};
#[allow(
    unused_imports,
    reason = "consumed by the consultation executor integration immediately following this slice"
)]
pub(crate) use credentials::{
    BasicAuthorizationCapability, CompiledBasicSourceCredentialProvider,
    SourceCredentialProviderError,
};
pub use registry::{
    CompiledConsultationRegistry, CompiledConsultationRegistryError,
    InitializedConsentVerifierRegistry,
};

#[cfg(test)]
#[allow(unused_imports, reason = "consumed by cross-layer state-plane tests")]
pub(crate) use compiler::{
    bounded_runtime_vector_plan_fixture, consent_runtime_vector_plan_fixture,
    maximum_completion_seed_fixture, maximum_runtime_profile_fixture,
    normal_completion_seed_fixture, rhai_five_operation_two_slot_completion_seed_fixture,
    rhai_runtime_vector_plan_fixture, semantic_alias_completion_seed_fixture,
};

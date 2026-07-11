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

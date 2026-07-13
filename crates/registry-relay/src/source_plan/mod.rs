// SPDX-License-Identifier: Apache-2.0
//! Private, compiled source-plan capabilities used by Relay consultations.

#[allow(
    dead_code,
    reason = "WP1B stages the closed artifact compiler before the executor integration"
)]
mod artifact;
pub mod authoring;
#[allow(
    dead_code,
    reason = "WP1B stages the closed artifact compiler before the executor integration"
)]
mod compiler;
mod completion_seed;
mod credentials;
mod identifiers;
mod private_transport;
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
    CompiledInputMatcher, CompiledInputRole, CompiledInputSlot, CompiledInputType,
    CompiledInputValue, CompiledJsonPointer, CompiledNamedBodyField, CompiledNamedExpression,
    CompiledOperation, CompiledOutputMapping, CompiledPriorOutputSlot, CompiledProjectionMechanism,
    CompiledRequestCodec, CompiledRequestSigner, CompiledResponse, CompiledResponseField,
    CompiledResponseFormat, CompiledResponseNormalization, CompiledResponseSchema,
    CompiledScalarShape, CompiledSelectorBinding, CompiledSelectorLocation, CompiledSelectorSource,
    CompiledSnapshotBinding, CompiledSnapshotRefreshClass, CompiledSourceAuth, CompiledSourcePlan,
    CompiledSourcePlanRegistry, CompiledStatusOutcome, CompiledStep, CompiledStepPredicate,
    CompiledValueExpression, PinnedEvidenceArtifact, PinnedSourcePlanArtifact,
    RhaiWorkerCapability, SourcePlanArtifactBundle, SourcePlanCompileError,
};
pub(crate) use compiler::{CompiledDciSelector, CompiledRhaiFactType, ParsedOAuth2AccessToken};
#[allow(
    unused_imports,
    reason = "consumed by the consultation executor integration immediately following this slice"
)]
pub(crate) use credentials::{
    validate_source_credential_catalog, BasicAuthorizationCapability,
    CompiledBasicSourceCredentialProvider, CompiledOAuthSourceCredentialProvider,
    CompiledStaticBearerSourceCredentialProvider, OAuthClientCredentialsCapability,
    SourceCredentialProviderError, StaticBearerAuthorizationCapability,
};
pub(crate) use registry::initialize_rhai_worker_capabilities;
pub use registry::{
    CompiledConsultationRegistry, CompiledConsultationRegistryError,
    InitializedConsentVerifierRegistry,
};

pub(crate) const CONSULTATION_INPUT_NAME_MAX_BYTES: usize = 64;

pub(crate) fn valid_consultation_input_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && name.len() <= CONSULTATION_INPUT_NAME_MAX_BYTES
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

#[cfg(test)]
#[allow(unused_imports, reason = "consumed by cross-layer state-plane tests")]
pub(crate) use compiler::{
    bounded_runtime_vector_plan_fixture, consent_runtime_vector_plan_fixture,
    dhis2_completion_seed_fixture, dhis2_duplicate_selector_runtime_vector_plan_fixture,
    dhis2_runtime_vector_plan_fixture, maintained_open_crvs_runtime_plan_fixture,
    maximum_completion_seed_fixture, maximum_runtime_profile_fixture,
    normal_completion_seed_fixture, open_crvs_completion_seed_fixture,
    open_crvs_runtime_vector_plan_fixture, open_crvs_runtime_vector_registry_fixture,
    rhai_five_operation_two_slot_completion_seed_fixture, rhai_runtime_vector_plan_fixture,
    semantic_alias_completion_seed_fixture, shared_snapshot_registry_fixture,
    signed_dci_expiring_oauth_runtime_plan_fixture, snapshot_completion_seed_fixture,
};

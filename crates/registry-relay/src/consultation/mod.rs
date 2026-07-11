// SPDX-License-Identifier: Apache-2.0
//! Closed domain types for purpose-aware Relay consultations.
//!
//! This module deliberately contains no HTTP parsing or source dispatch. It
//! establishes parsed values and validated declarations that the consultation
//! service will later bind to a profile, authorization decision, durable audit,
//! and fenced dispatch grant. Raw request values and native source controls are
//! not backend capabilities.

#[allow(
    dead_code,
    reason = "the production audit builders precede consultation service integration"
)]
pub(crate) mod audit;
#[allow(
    dead_code,
    reason = "the typed commitment foundation precedes consultation service integration"
)]
pub(crate) mod commitments;
mod identifiers;
#[allow(
    dead_code,
    reason = "the bounded provider foundation precedes consultation runtime integration"
)]
pub(crate) mod pseudonym;
mod types;
mod workload;

pub use identifiers::{
    ConsultationId, ConsultationIdentifierError, ConsultationKey, NotaryEvaluationId,
    ResolvedConsultationProfile,
};
pub use types::{
    AcquiredField, AcquisitionClass, AssertionContractHash, AssertionContractId,
    AssertionContractIdentity, ConsultationOutcome, ConsultationValidationError,
    DeclaredOperationFootprint, IntegrationPackHash, IntegrationPackId, IntegrationPackIdentity,
    OperationBounds, OperationId, ParsedPurpose, ParsedSingleStringInput, PolicyHash, PolicyId,
    PolicyIdentity, PreAuthorizationConsultationCore, ProfileContractHash, ProfileId,
    ProfileIdentity, ProfileVersion, SelectorProvenance, SnapshotGenerationId,
};
pub use workload::{
    AuthenticatedConsultationWorkload, AuthenticatedNotaryWorkload, ClientClaimSelector,
    ConfiguredAudience, ConfiguredClientBinding, ConfiguredIssuer, ConfiguredOidcWorkloadProof,
    ConfiguredPrincipalId, ConsultationAuthMode, ConsultationWorkloadBinding,
    ConsultationWorkloadRole, ExpectedClientValue, RegistryInstanceId, RequiredConsultationScope,
    TenantId, WorkloadBindingError, WorkloadId,
};

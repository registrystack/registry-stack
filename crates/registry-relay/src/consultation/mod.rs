// SPDX-License-Identifier: Apache-2.0
//! Closed domain types and the concrete Basic GET service for Relay consultations.
//!
//! HTTP parsing remains in `api::consultation`. This module binds its parsed
//! values to exact compiled profiles, authorization, durable audit, and fenced
//! Basic GET dispatch. Raw request values and native source controls are never
//! standalone backend capabilities.

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
#[allow(
    dead_code,
    reason = "the concrete Basic GET executor is activated by the consultation service slice"
)]
pub(crate) mod executor;
mod identifiers;
pub mod operator;
#[allow(
    dead_code,
    reason = "the compiled policy adapter is consumed by the consultation service integration"
)]
pub(crate) mod policy;
#[allow(
    dead_code,
    reason = "the bounded provider foundation precedes consultation runtime integration"
)]
pub(crate) mod pseudonym;
#[allow(
    dead_code,
    reason = "the sealed response is consumed by the concrete consultation executor integration"
)]
pub(crate) mod response;
mod service;
mod types;
mod workload;

pub use identifiers::{
    ConsultationId, ConsultationIdentifierError, ConsultationKey, NotaryEvaluationId,
    ResolvedConsultationProfile,
};
#[allow(
    unused_imports,
    reason = "reachable crate-private service return and error member types for the HTTP boundary"
)]
pub(crate) use service::{
    ConsultationDenialReason, ConsultationDenialRecorded, ConsultationDenialRoute,
    ConsultationExecutionError, ConsultationRetryAfter, ConsultationServiceError,
    ResolvedConsultationContext,
};
pub use service::{
    ConsultationService, ConsultationServiceActivationError, ConsultationServiceReadiness,
    ConsultationServiceShutdownError,
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

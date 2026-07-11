// SPDX-License-Identifier: Apache-2.0
//! Relay-owned durable operational state.
//!
//! This module is deliberately separate from registry source connectors. The
//! PostgreSQL instance behind it is an operational control plane and must not
//! contain registry rows, source credentials, raw selectors, or source URLs.
//!
//! This private module is compiled into Relay for the bounded WP1A capability.
//! Compilation is not startup activation or authority evidence. The WP1B
//! consultation runtime/compiler must explicitly bind signed configuration,
//! readiness, fencing/quota, and this durable sink before any route can use it.

mod audit;
mod consultation;
mod fence;
mod migration;
mod pseudonym_keyring;
mod quota;

#[cfg(test)]
mod postgres_tests;

pub(crate) use audit::{
    CompletionAttemptReference, PostgresDurableAuditStatePlane,
    PseudonymBoundDuplicateRecoveryOutcome, StatePlaneInitializationError, StatePlaneReadiness,
};
pub(crate) use consultation::{
    AttemptPseudonymBundle, ConsultationCompletionOutcome, ConsultationCompletionReceipt,
    ConsultationCompletionSeed, ConsultationPersistenceError, ConsultationPublicationGrant,
    KnownCompletionDisposition, KnownConsultationCompletionFacts, KnownFailureClass,
    PublicConsultationOutcome, RecoveredConsultationCompletion,
};
pub(crate) use fence::{
    AuditedConsultationDispatch, ConsultationDispatchPermit, ConsultationPermitSet,
    DispatchOperationId, DispatchPermitBudget, DispatchPermitKind,
    FencedConsultationAttemptAuthority, PostgresServingFence, ServingFenceError,
    ServingFenceLockKey, ServingFenceReadiness, TakeoverCompletionRecoveryAuthority,
};
pub(crate) use migration::install_postgres_state_plane_v1;
pub(crate) use migration::{
    AuditChainKeyEpochId, AuditPseudonymKeyringLockKey, AuditPseudonymMaintenanceDatabaseRole,
    AuditPseudonymReaderDatabaseRole, RuntimeDatabaseRole, StatePlaneInstallError,
    AUDIT_PSEUDONYM_KEYRING_CAPABILITY_V1, DURABLE_AUDIT_CAPABILITY_V1,
    PERSISTENT_QUOTA_CAPABILITY_V1, POSTGRES_STATE_PLANE_MIGRATION_V1, SERVING_FENCE_CAPABILITY_V1,
    STATE_PLANE_SCHEMA_FINGERPRINT_V1,
};
pub(crate) use pseudonym_keyring::{
    ActiveAuditPseudonymWriteEpoch, AuditPseudonymLookupEpoch, AuditPseudonymLookupSnapshot,
    AuditPseudonymWriteAuthority, AuthorizedAuditPseudonymLookupSubset,
    KeyringInitializationOutcome, KeyringReadiness, PostgresAuditPseudonymKeyringMaintenance,
    PostgresAuditPseudonymKeyringReader, PostgresAuditPseudonymKeyringRuntime,
    PostgresKeyringError,
};
pub(crate) use quota::{
    EffectiveQuotaLimits, PostgresQuotaStatePlane, PublicQuotaLimits, QuotaError, QuotaExhaustion,
    QuotaGrant, QuotaKey, QuotaReadiness, QuotaReservation,
};

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
mod migration;

#[cfg(test)]
mod postgres_tests;

pub(crate) use audit::{
    CompletionAttemptReference, PostgresDurableAuditStatePlane, StatePlaneInitializationError,
    StatePlaneReadiness,
};
pub(crate) use migration::{
    install_postgres_state_plane_v1, AuditChainKeyEpochId, RuntimeDatabaseRole,
    StatePlaneInstallError, DURABLE_AUDIT_CAPABILITY_V1, POSTGRES_STATE_PLANE_MIGRATION_V1,
    STATE_PLANE_SCHEMA_FINGERPRINT_V1,
};

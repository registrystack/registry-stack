// SPDX-License-Identifier: Apache-2.0
//! Notary-owned PostgreSQL correctness state.
//!
//! This module deliberately exposes only the installation and attestation
//! contract needed by the `registry-notary` operator CLI. Runtime domain
//! queries remain private to the server crate when they are integrated.

mod handle;
mod migration;
mod runtime;
mod sensitive;

pub use handle::attest_postgres_state_plane_runtime;
pub(crate) use handle::NotaryStatePlaneHandle;
pub(crate) use sensitive::{
    IssuanceReserveOutcome, LoginReserveOutcome, PostgresSensitiveState, SensitiveStateKeyConfig,
    SensitiveStateKeys,
};

pub use migration::{
    attest_postgres_state_plane_v1, install_postgres_state_plane_v1, OwnerDatabaseRole,
    PostgresStatePlaneAttestation, RuntimeDatabaseRole, StatePlaneMigrationError,
    POSTGRES_STATE_PLANE_MIGRATION_V1, STATE_PLANE_CAPABILITY_V1,
    STATE_PLANE_SCHEMA_FINGERPRINT_V1, STATE_PLANE_SCHEMA_VERSION_V1,
};
pub use runtime::{
    NotaryPostgresOperatorConnection, NotaryPostgresStatePlaneError,
    NotaryPostgresStatePlaneReadiness, NotaryPostgresStatePlaneRuntime, PostgresStatePlaneConfig,
};
pub use sensitive::SensitiveStateError;

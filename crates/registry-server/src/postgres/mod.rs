// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-only runtime and migration safety kernel.

mod catalog;
mod config;
mod context;
mod history_read;
mod interlock;
mod migration_ledger;
mod mutation;
mod read;
mod revision_read;
mod roles;
mod schema;

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub use catalog::{
    initialize_compiled_registry_state_for_test, initialize_kernel_registry_state_for_test,
    initialize_registry_state_for_catalog_test, legacy_schema_fingerprint_for_test,
    RegistryStateTestIdentity,
};
pub use catalog::{
    install_kernel_schema, kernel_schema_fingerprint, managed_schema_fingerprint,
    verify_catalog_identity, verify_catalog_identity_for_catalog, CatalogIdentity,
    ExpectedManagedCatalog, ExpectedRegistryIdentity,
};
pub use config::{ConnectionConfig, PoolBounds, RuntimePool, TlsPolicy};
pub(crate) use context::{
    begin_action_transaction, ActionClaimContext, ChangeRequestActionContext,
    ChangeRequestTargetBinding, ChangeRequestTargetContext, ImmediateActionLinkBinding,
    ImmediateActionLinkContext, ImmediateActionTargetBinding, ImmediateActionTargetContext,
};
pub use context::{
    begin_record_transaction, ClaimContext, GuardedTransaction, RowBoundaryContext,
    RowBoundaryOperator,
};
pub(crate) use context::{install_spatial_bbox_context, validate_field_value, SpatialBboxContext};
pub use history_read::PostgresSnapshotReadService;
#[cfg(feature = "postgres-test")]
pub use history_read::SnapshotReadFaultPoint;
#[cfg(feature = "postgres-test")]
pub use interlock::DedicatedApplyConnection;
pub use interlock::RegistryLockKey;
pub(crate) use interlock::{
    set_force_row_security, DedicatedApplyConnection as VerifiedPackageApplyConnection,
    MaintenanceAuditRecord, MaintenanceSnapshot, MaintenanceTransition, PackageDdlStatement,
    ReviewedExecutionOutcome, ReviewedMigrationProgress, ReviewedPackageExecutionRequest,
};
pub(crate) use migration_ledger::{
    statement_checksum, MigrationArtifactBinding, MigrationLedgerEntry, MigrationLedgerStep,
    MigrationLedgerStepKind, MigrationPlanKind,
};
pub use mutation::PostgresRecordMutationService;
pub use read::PostgresRecordReadService;
#[cfg(feature = "postgres-test")]
pub use read::ReadFaultPoint;
pub use revision_read::PostgresRevisionReadService;
#[cfg(feature = "postgres-test")]
pub use revision_read::RevisionReadFaultPoint;
pub use roles::{
    provision_managed_schemas, provision_postgis_prerequisites, provision_spatial_bbox_role,
    spatial_bbox_role, verify_btree_gist, verify_migration_role, verify_postgis,
    verify_runtime_role, SqlIdentifier,
};
pub use schema::install_compiled_schema;
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub use schema::reconcile_compiled_runtime_acl_for_test;
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub(crate) use schema::rehearse_schema_fingerprint_with_connection;
pub(crate) use schema::verify_postgres_15_or_newer;
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub(crate) use schema::PreparedSchemaTestCatalogVerifier;
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub use schema::{
    prepare_schema_test_database_with_connections, PreparedSchemaTestDatabase,
    SchemaTestDatabaseIdentity,
};

use thiserror::Error;

/// A value-free PostgreSQL kernel error suitable for an operational boundary.
#[derive(Debug, Error)]
pub enum PostgresKernelError {
    #[error("invalid PostgreSQL configuration: {0}")]
    Configuration(&'static str),
    #[error("PostgreSQL connection failed")]
    Connection,
    #[error("PostgreSQL pool operation failed")]
    Pool,
    #[error("PostgreSQL pool construction failed")]
    PoolBuild,
    #[error("PostgreSQL role invariant failed: {0}")]
    RoleInvariant(&'static str),
    #[error("PostgreSQL catalog invariant failed: {0}")]
    CatalogInvariant(&'static str),
    #[error("Registry is unavailable for record operations")]
    RegistryUnavailable,
}

impl From<tokio_postgres::Error> for PostgresKernelError {
    fn from(_error: tokio_postgres::Error) -> Self {
        Self::Connection
    }
}

/// Result returned by PostgreSQL kernel operations.
pub type Result<T> = std::result::Result<T, PostgresKernelError>;

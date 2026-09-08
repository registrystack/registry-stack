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
pub(crate) use schema::compiled_pattern_field;
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

use crate::api::ReadServiceError;

/// Classify a failed statement that reads stored snapshot bytes as JSON, for
/// the reader named by `reader`.
///
/// The read cannot answer from a row the JSON reader will not accept. That is
/// the row's own state, so the refusal names it. Reporting it as an outage
/// would hide the corrupted row behind a failure callers retry.
#[must_use]
pub(crate) fn snapshot_read_error(
    error: &tokio_postgres::Error,
    reader: crate::stored_bytes::Reader,
) -> ReadServiceError {
    if crate::stored_bytes::unreadable(error, reader) {
        ReadServiceError::SnapshotUnreadable
    } else {
        ReadServiceError::Unavailable
    }
}

/// A session-private table holding one stored value, so a test can run the
/// expression a read builds over bytes the JSON reader cannot accept.
#[cfg(all(test, feature = "postgres-test"))]
pub(crate) mod stored_bytes_probe {
    use std::env;
    use std::str::FromStr;

    use tokio_postgres::{Config, NoTls};

    /// The two ways stored bytes stop being readable: a sequence no UTF-8
    /// decoder accepts, and text that decodes but is not JSON.
    pub(crate) const UNREADABLE: [&[u8]; 2] = [&[0xf0, 0x28, 0x8c, 0x28], b"{\"unterminated\""];

    /// Hold `stored` in a session-private `revision` row and return the error
    /// `expression` raises over it. Text parameters bind from `$1` in the order
    /// given, matching the numbering the read's own builder emits.
    pub(crate) async fn expression_error(
        expression: &str,
        stored: &[u8],
        text_parameters: &[&str],
    ) -> tokio_postgres::Error {
        let url = env::var("BREG_TEST_DATABASE_URL")
            .expect("BREG_TEST_DATABASE_URL is required for the stored-bytes probe");
        let config =
            Config::from_str(&url).expect("BREG_TEST_DATABASE_URL must be a valid PostgreSQL URL");
        let (client, connection) = config
            .connect(NoTls)
            .await
            .expect("stored-bytes probe connects");
        // The connection ends when the client drops at the end of the probe.
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        client
            .batch_execute(
                "CREATE TEMPORARY TABLE revision (
                     snapshot bytea NOT NULL,
                     package_revision text NOT NULL,
                     record_id uuid NOT NULL
                 )",
            )
            .await
            .expect("stored-bytes probe creates its session-private table");
        client
            .execute(
                "INSERT INTO revision (snapshot, package_revision, record_id)
                 VALUES ($1, 'probe-package', '00000000-0000-4000-8000-000000000001')",
                &[&stored],
            )
            .await
            .expect("stored-bytes probe stores the unreadable row");
        let parameters = text_parameters
            .iter()
            .map(|value| value as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        let error = client
            .query(&format!("SELECT {expression} FROM revision"), &parameters)
            .await
            .expect_err("the expression cannot read the stored bytes");
        task.abort();
        error
    }
}

/// A value-free PostgreSQL kernel error suitable for an operational boundary.
#[derive(Debug, Error)]
pub enum PostgresKernelError {
    #[error("invalid PostgreSQL configuration: {0}")]
    Configuration(&'static str),
    /// Only authored identifiers are retained; the expression and database error are discarded.
    #[error("a persisted field pattern has invalid PostgreSQL syntax")]
    FieldPatternSyntax { entity_id: String, field_id: String },
    #[error("existing rows do not conform to a persisted field pattern")]
    FieldPatternExistingRows { entity_id: String, field_id: String },
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

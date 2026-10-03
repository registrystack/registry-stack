// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-only runtime and migration safety kernel.

mod baseline;
mod cancellation;
mod catalog;
mod config;
mod context;
mod failure;
mod history_read;
mod interlock;
mod migration_ledger;
mod mutation;
mod read;
#[cfg(all(feature = "runtime", feature = "tooling"))]
mod rehearsal;
mod revision_read;
mod roles;
mod schema;

pub use baseline::{
    advise, inspect_baseline, AdvisorySeverity, BaselineAdvisory, BaselineSettings,
};
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub use catalog::{
    initialize_compiled_registry_state_for_test, initialize_kernel_registry_state_for_test,
    initialize_registry_state_for_catalog_test, test_activation_id, test_package_digest,
    RegistryStateTestIdentity,
};
pub use catalog::{
    install_kernel_schema, kernel_schema_fingerprint, managed_schema_fingerprint,
    verify_catalog_identity, verify_catalog_identity_for_catalog, CatalogIdentity,
    ExpectedManagedCatalog, ExpectedRegistryIdentity,
};
pub(crate) use catalog::{
    installed_managed_catalog, registry_state_shape, runtime_grants_missing, RegistryStateShape,
};
pub(crate) use config::MAX_POOL_TIMEOUT;
pub use config::{set_application_name, ConnectionConfig, PoolBounds, RuntimePool, TlsPolicy};
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
pub use failure::PostgresFailure;
pub use history_read::PostgresSnapshotReadService;
#[cfg(feature = "postgres-test")]
pub use history_read::SnapshotReadFaultPoint;
#[cfg(feature = "postgres-test")]
pub use interlock::DedicatedApplyConnection;
pub use interlock::RegistryLockKey;
pub(crate) use interlock::{
    covered_field_encryption_fields, field_plaintext_string, lock_wait_ended,
    prepare_unique_blind_index_preflight, prior_plaintext_projection, read_activation_status,
    record_unique_blind_index_page, recursive_member_path, set_force_row_security,
    ActivationStatusRead, DedicatedApplyConnection as VerifiedPackageApplyConnection,
    FieldEncryptionCoveredField, MaintenanceSnapshot, MaintenanceTransition, PackageDdlStatement,
    ReviewedExecutionOutcome, ReviewedFieldEncryptionContext, ReviewedMigrationProgress,
    ReviewedPackageExecutionRequest,
};
pub(crate) use migration_ledger::{
    statement_checksum, BackupReference, MigrationArtifactBinding, MigrationKind,
    MigrationLedgerEntry, MigrationLedgerStep, MigrationLedgerStepKind,
};
pub use migration_ledger::{ActivationPlanKind, RoleMode};
pub use mutation::{
    IngestionChunkSubmitInput, IngestionRunCreateInput, IngestionRunListQuery,
    IngestionServiceError, PostgresRecordMutationService,
};
pub use read::PostgresRecordReadService;
#[cfg(feature = "postgres-test")]
pub use read::ReadFaultPoint;
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub use rehearsal::{
    rehearse_successor_migration, BaselineFingerprintDrift, MigrationRehearsalError,
    RehearsalAssertionPhase, RehearsalOutcome, SuccessorMigrationRehearsal,
};
pub use revision_read::PostgresRevisionReadService;
#[cfg(feature = "postgres-test")]
pub use revision_read::RevisionReadFaultPoint;
pub(crate) use roles::find_runtime_write_authority;
#[doc(hidden)]
pub use roles::RuntimeRevoke;
pub use roles::{
    provision_managed_schemas, provision_postgis_prerequisites, provision_spatial_bbox_role,
    spatial_bbox_role, verify_btree_gist, verify_migration_role, verify_postgis,
    verify_runtime_role, RuntimeWriteAuthority, SqlIdentifier,
};
pub(crate) use schema::compiled_pattern_field;
pub use schema::install_compiled_schema;
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub use schema::reconcile_compiled_runtime_acl_for_test;
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub(crate) use schema::rehearse_schema_fingerprint_with_connection;
pub(crate) use schema::verify_postgres_17_or_newer;
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
    /// Authored record identifiers only; field values never cross this boundary.
    #[error("field-encryption backfill would collide blind indexes of existing records")]
    FieldEncryptionBlindCollision {
        entity_id: String,
        record_ids: Vec<String>,
    },
    #[error(
        "retain-plaintext-history requires clearing retained request snapshots before encrypting the field"
    )]
    FieldEncryptionRetainedRequestSnapshots { entity_id: String, field_id: String },
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
    /// Another session held the registry's exclusive migration lock until
    /// this session's wait for it timed out: an apply or a reconciliation is
    /// in progress.
    #[error("another session holds the registry migration lock")]
    MigrationLockHeld,
    /// Retained history coverage does not admit a successor package.
    #[error("retained history coverage does not admit a successor package")]
    HistoryCoverageIncomplete,
    /// PostgreSQL refused a migration statement. Only the SQLSTATE and the
    /// object names the server reported are retained.
    #[error("PostgreSQL refused a migration statement: {0}")]
    Statement(PostgresFailure),
}

impl PostgresKernelError {
    /// Classifies the error of one migration statement. A server refusal
    /// keeps its SQLSTATE and object names; a lost connection, whether the
    /// client lost it or the server ended the session, stays
    /// [`Self::Connection`].
    pub(crate) fn from_statement_error(error: &tokio_postgres::Error) -> Self {
        match error.as_db_error() {
            Some(db_error) if !sqlstate_ends_the_session(db_error.code().code()) => {
                Self::Statement(PostgresFailure::from_error(error))
            }
            _ => Self::Connection,
        }
    }
}

/// Whether a server-reported SQLSTATE ends the session rather than refusing
/// one statement: a connection exception (class `08`), an administrator or
/// crash shutdown, a server not accepting connections, a dropped database,
/// or an idle-session or idle-in-transaction timeout.
fn sqlstate_ends_the_session(code: &str) -> bool {
    code.starts_with("08")
        || matches!(
            code,
            "57P01" | "57P02" | "57P03" | "57P04" | "57P05" | "25P03"
        )
}

impl From<tokio_postgres::Error> for PostgresKernelError {
    fn from(_error: tokio_postgres::Error) -> Self {
        Self::Connection
    }
}

/// Result returned by PostgreSQL kernel operations.
pub type Result<T> = std::result::Result<T, PostgresKernelError>;

#[cfg(test)]
mod tests {
    use super::sqlstate_ends_the_session;

    #[test]
    fn a_server_ended_session_is_a_connection_failure_not_a_refused_statement() {
        for code in [
            "08000", "08003", "08006", "57P01", "57P02", "57P03", "57P04", "57P05", "25P03",
        ] {
            assert!(sqlstate_ends_the_session(code), "{code} ends the session");
        }
        for code in [
            "57014", "55P03", "22P02", "23502", "42703", "25P02", "40001",
        ] {
            assert!(
                !sqlstate_ends_the_session(code),
                "{code} refuses one statement"
            );
        }
    }
}

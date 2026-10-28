// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-only runtime and migration safety kernel.

mod baseline;
pub(crate) mod cancellation;
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
mod statistics;
mod timer;
mod timer_activation_preview;
mod timer_operator_read;
mod timer_operator_store;
mod timer_operator_transition;
mod timer_retention;

pub use baseline::{
    advise, inspect_baseline, AdvisorySeverity, BaselineAdvisory, BaselineSettings,
};
pub use catalog::{
    catalog_drift_objects, managed_schema_fingerprint, verify_catalog_identity_for_catalog,
    CatalogIdentity, ExpectedManagedCatalog, ExpectedRegistryIdentity,
};
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub use catalog::{
    initialize_compiled_registry_state_for_test, initialize_registry_state_for_catalog_test,
    test_activation_id, test_package_digest, RegistryStateTestIdentity,
};
pub(crate) use catalog::{
    pre_1_0_attachment_verification_present, registry_state_shape, runtime_grants_missing,
    RegistryStateShape,
};
pub(crate) use config::MAX_POOL_TIMEOUT;
pub use config::{
    set_application_name, ConnectionConfig, DatabaseConnectionCause, PoolBounds, RuntimePool,
    TlsPolicy,
};
pub(crate) use context::{
    begin_action_transaction, begin_timer_action_transaction, snapshot_matches_boundaries,
    ActionClaimContext, ImmediateActionLinkBinding, ImmediateActionLinkContext,
    ImmediateActionTargetBinding, ImmediateActionTargetContext,
};
pub(crate) use context::{
    begin_proposal_transaction, ProposalAuthority, ProposalAuthorityOperation, ProposalTargetPhase,
};
pub use context::{
    begin_record_transaction, ClaimContext, GuardedTransaction, RowBoundaryContext,
    RowBoundaryOperator,
};
pub(crate) use context::{
    begin_registry_read_transaction_with_reason, begin_registry_transaction,
    begin_registry_transaction_with_reason, RegistryLockFailure, RegistryTransactionError,
};
pub(crate) use context::{install_spatial_bbox_context, validate_field_value, SpatialBboxContext};
pub use failure::PostgresFailure;
pub use history_read::PostgresSnapshotReadService;
#[cfg(feature = "postgres-test")]
pub use history_read::SnapshotReadFaultPoint;
pub(crate) use interlock::retained_local_hook_deliveries;
#[cfg(feature = "postgres-test")]
pub use interlock::DedicatedApplyConnection;
#[cfg(feature = "postgres-test")]
pub async fn set_force_row_security_for_test(
    client: &impl tokio_postgres::GenericClient,
    tables: &[String],
    forced: bool,
) -> Result<()> {
    interlock::set_force_row_security(client, tables, forced).await
}
pub(crate) use interlock::{
    covered_field_encryption_fields, field_plaintext_string, lock_wait_ended,
    prepare_unique_blind_index_preflight, prior_plaintext_projection, read_activation_status,
    record_unique_blind_index_page, recursive_member_path, set_force_row_security,
    ActivationStatusRead, DedicatedApplyConnection as VerifiedPackageApplyConnection,
    FieldEncryptionCoveredField, MaintenanceSnapshot, MaintenanceTransition, PackageDdlStatement,
    ReviewedExecutionOutcome, ReviewedFieldEncryptionContext, ReviewedMigrationProgress,
    ReviewedPackageExecutionRequest,
};
pub use interlock::{RegistryLockKey, RetainedLocalHookDeliveries};
pub(crate) use migration_ledger::{
    statement_checksum, BackupReference, MigrationArtifactBinding, MigrationKind,
    MigrationLedgerEntry, MigrationLedgerStep, MigrationLedgerStepKind,
};
pub use migration_ledger::{ActivationPlanKind, RoleMode};
pub(crate) use mutation::api_boundary;
pub use mutation::{
    IngestionChunkSubmitInput, IngestionRunCreateInput, IngestionRunListQuery,
    IngestionServiceError, PostgresRecordMutationService,
};
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub fn timer_create_target_id_for_test(
    occurrence_id: uuid::Uuid,
    action_revision: &str,
    effect_id: &str,
    target_entity_id: &str,
) -> uuid::Uuid {
    crate::mutation::timer_create_target_id(
        occurrence_id,
        action_revision,
        effect_id,
        target_entity_id,
    )
}
pub(crate) use read::compiled_api_name;
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
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub use roles::find_runtime_write_authority as find_runtime_write_authority_for_test;
#[doc(hidden)]
pub use roles::RuntimeRevoke;
pub(crate) use timer_activation_preview::read_timer_activation_previews;

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn install_statistics_store_for_test(
    migration: &impl tokio_postgres::GenericClient,
    runtime_role: &SqlIdentifier,
) -> std::result::Result<(), tokio_postgres::Error> {
    crate::statistics_store::install(migration, runtime_role).await
}
/// Index fixture revisions through the same allocator the runtime uses.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn index_revisions_for_test(
    transaction: &tokio_postgres::Transaction<'_>,
    package_revision: &str,
    revisions: &[(&str, uuid::Uuid, i64)],
) -> Result<i64> {
    let members = revisions
        .iter()
        .map(|(entity_id, record_id, record_revision)| {
            crate::history_commit::RevisionCommitMember {
                entity_id,
                record_id: *record_id,
                record_revision: *record_revision,
            }
        })
        .collect::<Vec<_>>();
    crate::history_commit::allocate_revision_commit(
        transaction,
        crate::history_commit::CommitAllocation {
            package_revision,
            origin: crate::history_context::CommitOrigin::Mutation {
                actor_reference: "fixture-actor",
                request_reference: "fixture-request",
            },
            change_context: None,
            members: &members,
        },
    )
    .await
    .map(|committed| committed.position)
    .map_err(|_| PostgresKernelError::RegistryUnavailable)
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn prune_record_timer_retention_batch_for_test(
    pool: &RuntimePool,
    expected: &ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: std::time::Duration,
    limit: u32,
) -> Result<(u64, u64)> {
    let mut client = pool.get().await.map_err(|_| PostgresKernelError::Pool)?;
    let transaction =
        begin_registry_transaction(&mut client, lock_key, lock_timeout, expected).await?;
    transaction
        .set_statement_budget(std::time::Duration::from_secs(10))
        .await?;
    let removed = timer_retention::prune_timer_retention_batch(&transaction, limit).await?;
    transaction.commit().await?;
    Ok((removed.attempts_pruned, removed.generations_pruned))
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub fn strong_record_etag_for_test(
    profile: &registry_platform_audit::AuditProfile,
    claims: &crate::postgres::ClaimContext,
    package_revision: &str,
    record_id: &str,
    record_revision: i64,
    response_fields: &std::collections::BTreeSet<String>,
) -> std::result::Result<String, crate::mutation::MutationError> {
    crate::mutation::strong_record_etag(
        profile,
        claims,
        package_revision,
        record_id,
        record_revision,
        response_fields,
    )
}

pub use roles::{
    provision_managed_schemas, provision_postgis_prerequisites, provision_spatial_bbox_role,
    spatial_bbox_role, verify_btree_gist, verify_migration_role, verify_postgis,
    RuntimeWriteAuthority, SqlIdentifier,
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
pub use statistics::{
    PostgresStatisticsService, StatisticsLiveRequest, StatisticsMutationOutcome,
    StatisticsPublishRequest, StatisticsReleaseListCursor, StatisticsReleaseListRequest,
    StatisticsReleasePage, StatisticsReleaseRefusal, StatisticsReleaseSelection,
    StatisticsSeriesRequest, StatisticsServiceError, StatisticsStoredDocument,
    StatisticsVersionReadRequest, StatisticsWithdrawalRequest,
};
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub use statistics::{StatisticsPublishPause, StatisticsWithdrawalPause};
#[cfg(not(feature = "postgres-test"))]
pub(crate) use timer::RecordTimerWorker;
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub use timer::{
    install_record_timer_clock_fixture_for_test, reconcile_record_timer_runtime_acl_for_test,
    set_record_timer_clock_for_test, RecordTimerWorker,
};
pub(crate) use timer::{
    production_timer_limits, read_timer_protocol, retained_record_timer_state_exists,
    SUPPORTED_TIMER_PROTOCOL_VERSION,
};
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn retained_record_timer_state_exists_for_test(
    pool: &RuntimePool,
    expected: &ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: std::time::Duration,
) -> Result<bool> {
    timer::retained_record_timer_state_exists(pool, expected, lock_key, lock_timeout).await
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn record_timer_operator_detail_for_test(
    pool: &RuntimePool,
    expected: &ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: std::time::Duration,
    occurrence_id: uuid::Uuid,
    audit: &registry_platform_audit::AuditProfile,
) -> std::result::Result<
    crate::timer_operator::TimerOccurrenceDetail,
    crate::timer_operator::TimerOperatorError,
> {
    let store = TimerOperatorStore::new(
        pool.clone(),
        expected.clone(),
        lock_key,
        lock_timeout,
        operator_read_statement_budget(),
        production_timer_limits(),
    )?;
    store
        .show(occurrence_id)
        .await?
        .ok_or(crate::timer_operator::TimerOperatorError::OccurrenceNotFound)?
        .project(audit, &expected.activation_id)
}
pub(crate) use timer_operator_store::{operator_read_statement_budget, TimerOperatorStore};

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
        "retain-plaintext-history requires clearing retained Proposal snapshots before encrypting the field"
    )]
    FieldEncryptionRetainedProposalSnapshots { entity_id: String, field_id: String },
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
    #[error(
        "the package declares schema fingerprint {declared}, but the catalog measures {measured}"
    )]
    SchemaFingerprintMismatch { declared: String, measured: String },
    #[error("Registry is unavailable for record operations")]
    RegistryUnavailable,
    /// Another session held the registry's exclusive migration lock until
    /// this session's wait for it timed out: an apply, an instance claim
    /// adoption, or a reconciliation is in progress.
    #[error("another session holds the registry migration lock")]
    MigrationLockHeld,
    /// Retained history coverage does not admit a successor package.
    #[error("retained history coverage does not admit a successor package")]
    HistoryCoverageIncomplete,
    /// Local work must finish under its capturing activation before go-live.
    #[error("retained local hook deliveries prevent activation")]
    RetainedLocalHooks(RetainedLocalHookDeliveries),
    /// More than one retained run occupies the same import authority. The
    /// creators must recover that legacy state before activation can begin.
    #[error("multiple non-terminal import runs share one import authority")]
    ConflictingImportRuns,
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

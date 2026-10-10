// SPDX-License-Identifier: Apache-2.0
//! Verified package apply coordinator.

use std::{
    collections::BTreeMap,
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
    time::Duration,
};

use registry_platform_audit::{AuditEntry, AuditRequest};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::audit::RegistryAudit;
use crate::event_destination::EventDestinationCompatibilityInventory;
use crate::generated_ddl::DdlStatement;
use crate::history_schema::HistorySchemaDescriptor;
use crate::migration_plan::{
    read_backup_binding_document, ExternalBackupBinding, ReviewedMigrationStepDescriptor,
    ValidatedReviewedMigrationPlan,
};
use crate::package::{
    CompiledRegistryChangeClass, CompiledRegistryMigrationBaseline, MigrationPlan, PackageFileRole,
    VerifiedPackage, VerifiedPredecessorPackage,
};
use crate::postgres::{
    statement_checksum, ActivationPlanKind, BackupReference, ConnectionConfig,
    ExpectedManagedCatalog, ExpectedRegistryIdentity, MaintenanceTransition,
    MigrationArtifactBinding, MigrationKind, MigrationLedgerEntry, MigrationLedgerStep,
    MigrationLedgerStepKind, PackageDdlStatement, PostgresFailure, RegistryLockKey,
    ReviewedExecutionOutcome, ReviewedFieldEncryptionContext, ReviewedPackageExecutionRequest,
    RoleMode, SqlIdentifier, VerifiedPackageApplyConnection,
};

const MAX_LOCK_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_STATEMENT_TIMEOUT: Duration = Duration::from_secs(60 * 60);
pub(crate) const MAX_BACKUP_AGE_SECONDS: u64 = 31 * 24 * 60 * 60;
const MAX_BACKUP_BINDING_BYTES: u64 = 64 * 1024;
const MAX_OPERATOR_REFERENCE_BYTES: usize = 512;
const ACTIVATION_AUDIT_OPERATION_ID: &str = "breg.activation";
/// The audit schema of each activation's request and response entries.
pub const ACTIVATION_AUDIT_SCHEMA: &str = "breg-activation-audit/v1";

/// Value-free apply failures. Authored identifiers cross this boundary, and
/// a refused statement adds its SQLSTATE and the object names PostgreSQL
/// reported; SQL, PostgreSQL messages, and stored values do not.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum MigrationError {
    #[error("the verified package is not a valid activation successor")]
    PackageBinding,
    /// The database already records this package digest as active.
    #[error("the database already records this package as active")]
    AlreadyActive,
    /// The runtime identity names a different database than the one the
    /// registry state records.
    #[error("the runtime identity names a different database than the registry records")]
    DatabaseMismatch,
    #[error("the verified package has no additive migration work")]
    EmptyPlan,
    #[error("the Registry package apply failed")]
    ApplyFailed,
    /// PostgreSQL refused a statement after maintenance began. The target
    /// stays pinned in maintenance, as for [`Self::ApplyFailed`].
    #[error("PostgreSQL refused an apply statement: {0}")]
    StatementFailed(PostgresFailure),
    /// The database, read under the exclusive apply lock, does not record the
    /// presented package as its active package with maintenance ready.
    #[error("the database does not record this package as its active, ready package")]
    ActivePackageMismatch,
    /// Refused before maintenance began: retained history coverage does not
    /// admit a successor until an erasure lifecycle finishes or a rebaseline
    /// restores it.
    #[error("retained history coverage does not admit a successor package")]
    HistoryCoverage,
    /// Refused before maintenance began: the migration database could not be
    /// reached. Nothing was changed, so the same apply may simply be retried.
    #[error("the migration database was unavailable before maintenance began")]
    DatabaseUnavailable,
    /// Refused before maintenance began: another session held the exclusive
    /// migration lock past the lock timeout, so an apply, an instance claim
    /// adoption, or a reconciliation is in progress. Nothing was changed, so
    /// the same apply may be retried once that session releases the lock.
    #[error("another session held the migration lock before maintenance began")]
    MigrationLockHeld,
    #[error("a persisted field pattern has invalid PostgreSQL syntax")]
    FieldPatternSyntax { entity_id: String, field_id: String },
    #[error("existing rows do not conform to a persisted field pattern")]
    FieldPatternExistingRows { entity_id: String, field_id: String },
    /// Authored record identifiers only; field values never cross this boundary.
    #[error("field-encryption backfill would collide blind indexes of existing records")]
    FieldEncryptionLookupCollision {
        entity_id: String,
        record_ids: Vec<String>,
    },
    #[error(
        "retain-plaintext-history requires clearing retained request snapshots before encrypting field `{field_id}` on entity `{entity_id}`"
    )]
    FieldEncryptionRetainedRequestSnapshots { entity_id: String, field_id: String },
    #[error("active request proposals require rebase or cancellation before this package can be activated")]
    ActiveRequestProposals,
    #[error("destructive backup evidence is invalid")]
    BackupEvidence,
    /// The shared reader refused the backup binding document; the report
    /// carries each diagnostic with its position.
    #[error("the backup binding is not a valid document")]
    BackupBindingDocument(Box<registry_platform_yaml::Report>),
    /// The activation committed, but the audit refused a record it owed:
    /// the activation stands and its audit trail is incomplete.
    #[error("the activation committed but the audit refused a record it owed")]
    ActivationAuditIncomplete,
    /// Refused before the activation changed any state: the audit refused
    /// the activation's request entry.
    #[error("the audit refused the activation's request entry")]
    ActivationAuditUnavailable,
    /// The operator reference is empty, longer than 512 bytes, or carries a
    /// control character, or the audit profile derives no keyed hash to
    /// record it under.
    #[error("the operator reference is refused")]
    OperatorReference,
    /// The database holds registry state this release does not recognise,
    /// such as the state a release before the activation ledger installed.
    /// A release reads only the state its predecessor wrote. Nothing was
    /// changed.
    #[error("the database holds registry state this release does not recognise")]
    UnrecognizedDatabase,
    /// The split-role runtime role could write the activation ledger or the
    /// registry state; the finding names the statement that removes it.
    #[error("{0}")]
    RuntimeWriteAuthority(crate::postgres::RuntimeWriteAuthority),
    /// Refused before the retry changed anything: the unfinished activation
    /// of this package was started with other database roles. Only the role
    /// mode and the runtime role name cross this boundary.
    #[error(
        "the unfinished activation of this package was started with {role_mode} database roles and runtime role `{runtime_role}`; rerun the apply with the database roles it started with, or, for a new package, assess it with `bregctl migration reconcile`"
    )]
    ResumeRolesDiffer {
        role_mode: String,
        runtime_role: String,
    },
    /// Refused before maintenance: a successor serves with the roles the
    /// active activation records, because only a role change retires a
    /// recorded runtime role. Only the role mode and the runtime role name
    /// cross this boundary.
    #[error(
        "the active activation serves with {role_mode} database roles and runtime role `{runtime_role}`; apply the active package with the new roles first, then apply this successor"
    )]
    SuccessorRolesDiffer {
        role_mode: String,
        runtime_role: String,
    },
}

pub type Result<T> = std::result::Result<T, MigrationError>;

/// Whether a package applied as a successor has nothing to apply: its plan has
/// no schema statement and no reviewed migration, and it is not an access or
/// disclosure change alone. This reads only the package, so a caller can refuse
/// it before opening the database.
pub fn successor_plan_is_empty(package: &VerifiedPackage) -> bool {
    let plan = &package.manifest().migration_plan;
    plan.statements.is_empty()
        && package.reviewed_migration_plan().is_none()
        && !verified_metadata_only_plan(plan)
}

/// Whether a verified successor remains empty after accounting for an
/// engine-owned capability absent from its verified predecessor. The sole
/// compatibility exception installs an engine capability, such as the
/// statistical release store or caller-scoped idempotency, that the current
/// compiler declares and the predecessor's manifest does not; every ordinary
/// empty successor is still refused.
pub fn successor_plan_is_empty_for_predecessor(
    package: &VerifiedPackage,
    predecessor: &VerifiedPredecessorPackage,
) -> bool {
    successor_plan_is_empty(package) && !installs_engine_capability(package, predecessor)
}

fn installs_engine_capability(
    package: &VerifiedPackage,
    predecessor: &VerifiedPredecessorPackage,
) -> bool {
    package.manifest().package_id == predecessor.package_id()
        && package
            .manifest()
            .migration_plan
            .from_package_digest
            .as_deref()
            == Some(predecessor.package_digest())
        && package
            .manifest()
            .engine_features
            .difference(predecessor.engine_features())
            .next()
            .is_some()
}

fn verified_metadata_only_plan(plan: &MigrationPlan) -> bool {
    !plan.changes.is_empty()
        && plan.statements.is_empty()
        && plan.reviewed_descriptors.is_empty()
        && plan
            .changes
            .iter()
            .all(|change| change.class == CompiledRegistryChangeClass::AccessOrDisclosureChange)
}

/// Where one package activates: the runtime identity's environment,
/// instance, and database. A package names none of them, so the same package
/// activates into every environment of its chain.
#[derive(Clone, Copy, Debug)]
pub struct ActivationDeployment<'a> {
    environment: &'a str,
    instance_id: &'a str,
    database_id: &'a str,
}

impl<'a> ActivationDeployment<'a> {
    #[must_use]
    pub fn new(environment: &'a str, instance_id: &'a str, database_id: &'a str) -> Self {
        Self {
            environment,
            instance_id,
            database_id,
        }
    }

    #[must_use]
    pub fn database_id(&self) -> &'a str {
        self.database_id
    }

    #[must_use]
    pub fn environment(&self) -> &'a str {
        self.environment
    }

    #[must_use]
    pub fn instance_id(&self) -> &'a str {
        self.instance_id
    }
}

/// The exact registry identity one verified package activates to: the
/// database the runtime identity names, the package digest, and the
/// activation the apply lock resolved for it.
pub(crate) fn target_package_identity(
    package: &VerifiedPackage,
    database_id: &str,
    activation_id: uuid::Uuid,
) -> ExpectedRegistryIdentity {
    let manifest = package.manifest();
    ExpectedRegistryIdentity {
        package_id: manifest.package_id.clone(),
        database_id: database_id.to_owned(),
        package_digest: package.package_digest().to_owned(),
        activation_id: activation_id.hyphenated().to_string(),
        schema_fingerprint: manifest.schema_fingerprint.clone(),
    }
}

/// Confirms a verified package is the exact activation successor of one active
/// identity, so no other package can be presented as that identity's target.
///
/// Threat: an operator presents a package that skips a link of the chain, an
/// older package, the active package again, a package of another registry,
/// or the right package against the wrong database. Enforcement: the
/// deployment names the database the active identity records, the package
/// digest differs from the active digest, the registry package id is equal,
/// and the package's `fromPackageDigest` is the active digest.
pub(crate) fn verify_successor_package_binding(
    package: &VerifiedPackage,
    database_id: &str,
    current: &ExpectedRegistryIdentity,
) -> Result<()> {
    current
        .validate()
        .map_err(|_| MigrationError::PackageBinding)?;
    if database_id != current.database_id {
        return Err(MigrationError::DatabaseMismatch);
    }
    if package.package_digest() == current.package_digest {
        return Err(MigrationError::AlreadyActive);
    }
    let manifest = package.manifest();
    if manifest.package_id != current.package_id
        || manifest.migration_plan.from_package_digest.as_deref()
            != Some(current.package_digest.as_str())
    {
        return Err(MigrationError::PackageBinding);
    }
    Ok(())
}

/// Binds a role change to the active package: the same database, the same
/// package id, and the very package the database records as active.
fn verify_role_change_binding(
    package: &VerifiedPackage,
    database_id: &str,
    current: &ExpectedRegistryIdentity,
) -> Result<()> {
    current
        .validate()
        .map_err(|_| MigrationError::PackageBinding)?;
    if database_id != current.database_id {
        return Err(MigrationError::DatabaseMismatch);
    }
    if package.package_digest() != current.package_digest
        || package.manifest().package_id != current.package_id
    {
        return Err(MigrationError::PackageBinding);
    }
    Ok(())
}

/// The ledger entry of a role change: a metadata-only successor of the
/// active package to itself, under the roles the apply names.
fn role_change_ledger_entry(
    package: &VerifiedPackage,
    current: &ExpectedRegistryIdentity,
    roles: ApplyRoles<'_>,
) -> MigrationLedgerEntry {
    MigrationLedgerEntry {
        activation_id: uuid::Uuid::nil(),
        package_digest: package.package_digest().to_owned(),
        predecessor_package_digest: Some(current.package_digest.clone()),
        registry_revision: package.registry().revision().to_owned(),
        plan_kind: ActivationPlanKind::Successor,
        migration_kind: MigrationKind::MetadataOnly,
        role_mode: RoleMode::from_roles(roles.migration, roles.runtime),
        runtime_role: roles.runtime.as_str().to_owned(),
        operator_reference_hash: None,
        statement_checksums: Vec::new(),
        artifact_bindings: Vec::new(),
        backup_references: Vec::new(),
        steps: Vec::new(),
    }
}

/// The checksums of the compiler-owned DDL statements, in plan order.
pub(crate) fn compiler_statement_checksums(statements: &[DdlStatement]) -> Vec<String> {
    statements
        .iter()
        .map(|statement| statement_checksum(&statement.sql))
        .collect()
}

/// The durable ledger entry one verified package binds for its activation.
/// Its activation id is left nil: the apply resolves it under the apply lock,
/// where a retry of the same target finds the activation it resumes.
pub(crate) fn package_ledger_entry(
    package: &VerifiedPackage,
    current: Option<&ExpectedRegistryIdentity>,
    roles: ApplyRoles<'_>,
    compiler_checksums: &[String],
) -> Result<MigrationLedgerEntry> {
    let mut ledger = MigrationLedgerEntry {
        activation_id: uuid::Uuid::nil(),
        package_digest: package.package_digest().to_owned(),
        predecessor_package_digest: current.map(|identity| identity.package_digest.clone()),
        registry_revision: package.registry().revision().to_owned(),
        plan_kind: if current.is_some() {
            ActivationPlanKind::Successor
        } else {
            ActivationPlanKind::Initial
        },
        migration_kind: if current.is_some()
            && verified_metadata_only_plan(&package.manifest().migration_plan)
        {
            MigrationKind::MetadataOnly
        } else {
            MigrationKind::CompiledAdditive
        },
        role_mode: RoleMode::from_roles(roles.migration, roles.runtime),
        runtime_role: roles.runtime.as_str().to_owned(),
        operator_reference_hash: None,
        statement_checksums: compiler_checksums.to_vec(),
        artifact_bindings: Vec::new(),
        backup_references: Vec::new(),
        steps: Vec::new(),
    };
    if let (Some(plan), Some(current)) = (package.reviewed_migration_plan(), current) {
        reviewed_ledger(package, current, plan, &mut ledger)?;
    }
    Ok(ledger)
}

/// Exact durable precondition under which a verified package may be applied.
pub enum ApplyPrecondition<'a> {
    InitialActivation,
    Successor {
        current: &'a ExpectedRegistryIdentity,
    },
    /// Activate the active package again under different roles: a change of
    /// role mode or of runtime role is its own activation, with no DDL, and
    /// the runtime role it retires keeps no privilege.
    RoleChange {
        current: &'a ExpectedRegistryIdentity,
    },
}

/// The configured least-privilege database roles used by one apply.
#[derive(Clone, Copy)]
pub struct ApplyRoles<'a> {
    migration: &'a SqlIdentifier,
    runtime: &'a SqlIdentifier,
}

impl<'a> ApplyRoles<'a> {
    #[must_use]
    pub fn new(migration: &'a SqlIdentifier, runtime: &'a SqlIdentifier) -> Self {
        Self { migration, runtime }
    }
}

/// Bounded lock and per-statement execution timeouts for one apply.
#[derive(Clone, Copy)]
pub struct ApplyTimeouts {
    lock: Duration,
    statement: Duration,
}

/// One local backup binding file supplied for the reviewed migration whose
/// descriptor names `binding_path`. The binding describes one database's
/// backup, so it is an apply input and never a package file. The path grants
/// authority only to read that binding and the backup file it names for this
/// apply; it cannot add SQL, a checkpoint, or a migration target.
#[derive(Clone, Copy)]
pub struct DestructiveBackupEvidence<'a> {
    binding_path: &'a str,
    local_path: &'a Path,
}

impl<'a> DestructiveBackupEvidence<'a> {
    #[must_use]
    pub fn new(binding_path: &'a str, local_path: &'a Path) -> Self {
        Self {
            binding_path,
            local_path,
        }
    }
}

#[cfg(feature = "postgres-test")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum ReviewedMigrationFaultPoint {
    AfterCommittedChunk(u64),
}

impl ApplyTimeouts {
    pub fn new(lock: Duration, statement: Duration) -> Result<Self> {
        if lock < Duration::from_millis(1)
            || lock > MAX_LOCK_TIMEOUT
            || statement < Duration::from_millis(1)
            || statement > MAX_STATEMENT_TIMEOUT
        {
            return Err(MigrationError::ApplyFailed);
        }
        Ok(Self { lock, statement })
    }
}

/// What the database records for one registry: its active identity and
/// whether maintenance is ready, read under the exclusive apply lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedRegistryState {
    pub identity: ExpectedRegistryIdentity,
    pub ready: bool,
    /// Whether the ledger records the active activation as applied. It is
    /// false only while an initial activation is unfinished: its state row
    /// names its own target, which no applied activation made active.
    pub activation_applied: bool,
}

/// Reads the registry state the database records for one registry package
/// id, under the exclusive apply lock, and writes nothing. `None` means the
/// database has never been activated.
///
/// The database is the only record of which package is active and of its
/// place in the apply order; a caller binds a package and a deployment to
/// what this returns with [`bind_active_package`].
pub async fn read_recorded_registry_state(
    config: &ConnectionConfig,
    package_id: &str,
    migration_role: &SqlIdentifier,
    timeouts: ApplyTimeouts,
) -> Result<Option<RecordedRegistryState>> {
    let lock_key = RegistryLockKey::derive(package_id).map_err(|_| MigrationError::ApplyFailed)?;
    let mut connection = VerifiedPackageApplyConnection::acquire_for_verified_package(
        config,
        lock_key,
        migration_role,
        timeouts.lock,
        timeouts.statement,
    )
    .await
    .map_err(refusal_before_maintenance)?;
    let shape = connection.registry_state_shape().await;
    if matches!(shape, Ok(crate::postgres::RegistryStateShape::Unrecognized)) {
        connection
            .release()
            .await
            .map_err(refusal_before_maintenance)?;
        return Err(MigrationError::UnrecognizedDatabase);
    }
    let snapshot = match shape {
        Ok(_) => match connection.maintenance_snapshot().await {
            Ok(snapshot) => connection
                .active_activation_roles()
                .await
                .map(|roles| (snapshot, roles.is_some())),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    connection
        .release()
        .await
        .map_err(refusal_before_maintenance)?;
    match snapshot {
        Ok((snapshot, activation_applied)) => Ok(Some(RecordedRegistryState {
            ready: snapshot.maintenance_status == "ready"
                && snapshot.maintenance_target_package_digest.is_none(),
            identity: snapshot.identity,
            activation_applied,
        })),
        Err(crate::postgres::PostgresKernelError::RegistryUnavailable) => Ok(None),
        Err(error) => Err(refusal_before_maintenance(error)),
    }
}

/// The activation state the database records, as `bregctl status` reports
/// it. It names no value, SQL, credential, or operator reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationStatus {
    pub identity: ExpectedRegistryIdentity,
    /// `ready`, `applying`, or `failed`.
    pub maintenance_status: String,
    /// The exact target an unfinished activation pinned.
    pub maintenance_target_package_digest: Option<String>,
    /// Every recorded activation, in apply order.
    pub ledger: Vec<ActivationLedgerEntry>,
}

impl ActivationStatus {
    /// The ledger entry of the active activation.
    #[must_use]
    pub fn active_entry(&self) -> Option<&ActivationLedgerEntry> {
        self.ledger
            .iter()
            .find(|entry| entry.activation_id == self.identity.activation_id)
    }
}

/// One recorded activation. Timestamps are RFC 3339 in UTC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationLedgerEntry {
    pub activation_id: String,
    pub apply_order: i64,
    pub package_digest: String,
    pub predecessor_package_digest: Option<String>,
    pub registry_revision: String,
    /// `initial` or `successor`, or `adopted` for the first activation of a
    /// database an earlier release adopted from before the activation ledger.
    pub plan_kind: String,
    /// `compiled_additive`, `metadata_only`, or `reviewed`.
    pub migration_kind: String,
    /// `applying`, `failed`, `applied`, or `reverted`.
    pub outcome: String,
    /// `single` or `split`.
    pub role_mode: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub applied_at: Option<String>,
}

/// Reads the activation state the database records, as the migration role,
/// in one read-only transaction, and writes nothing. It takes no apply lock,
/// so it answers while an apply runs. `None` means the database has never
/// been activated; a database holding registry state this release does not
/// recognise is refused as [`MigrationError::UnrecognizedDatabase`].
pub async fn read_activation_status(
    config: &ConnectionConfig,
    migration_role: &SqlIdentifier,
    timeouts: ApplyTimeouts,
) -> Result<Option<ActivationStatus>> {
    let read = crate::postgres::read_activation_status(config, migration_role, timeouts.statement)
        .await
        .map_err(refusal_before_maintenance)?;
    let recorded = match read {
        crate::postgres::ActivationStatusRead::Uninitialized => return Ok(None),
        crate::postgres::ActivationStatusRead::Unrecognized => {
            return Err(MigrationError::UnrecognizedDatabase)
        }
        crate::postgres::ActivationStatusRead::Recorded(recorded) => recorded,
    };
    Ok(Some(ActivationStatus {
        identity: recorded.snapshot.identity,
        maintenance_status: recorded.snapshot.maintenance_status,
        maintenance_target_package_digest: recorded.snapshot.maintenance_target_package_digest,
        ledger: recorded
            .ledger
            .into_iter()
            .map(|entry| ActivationLedgerEntry {
                activation_id: entry.activation_id,
                apply_order: entry.apply_order,
                package_digest: entry.package_digest,
                predecessor_package_digest: entry.predecessor_package_digest,
                registry_revision: entry.registry_revision,
                plan_kind: entry.plan_kind,
                migration_kind: entry.migration_kind,
                outcome: entry.outcome,
                role_mode: entry.role_mode,
                started_at: entry.started_at,
                completed_at: entry.completed_at,
                applied_at: entry.applied_at,
            })
            .collect(),
    }))
}

/// Binds one package and the runtime deployment to the identity the database
/// records as active.
///
/// Threat: a lifecycle acting on the active registry could run against a
/// database the runtime identity does not name, or with a package the
/// database does not run. Enforcement: the recorded database id equals the
/// deployment's, and the recorded active digest equals the package digest.
pub fn bind_active_package(
    recorded: &ExpectedRegistryIdentity,
    package_digest: &str,
    deployment: ActivationDeployment<'_>,
) -> Result<()> {
    if recorded.database_id != deployment.database_id {
        return Err(MigrationError::DatabaseMismatch);
    }
    if recorded.package_digest != package_digest {
        return Err(MigrationError::ActivePackageMismatch);
    }
    Ok(())
}

/// Maps a failure to reach the migration database or to take the apply lock,
/// before maintenance begins, to the refusal it is: nothing was changed, so a
/// lost connection or an apply lock held past the lock timeout may simply be
/// retried. A held lock stays distinct from an unreachable database. Every
/// other failure keeps its exact-target reconciliation path.
fn refusal_before_maintenance(error: crate::postgres::PostgresKernelError) -> MigrationError {
    match error {
        crate::postgres::PostgresKernelError::Connection
        | crate::postgres::PostgresKernelError::RegistryUnavailable => {
            MigrationError::DatabaseUnavailable
        }
        crate::postgres::PostgresKernelError::MigrationLockHeld => {
            MigrationError::MigrationLockHeld
        }
        _ => MigrationError::ApplyFailed,
    }
}

/// Closed library request for applying one already verified package. There is
/// no raw path, arbitrary SQL, down-migration, backfill, or destructive-plan
/// entry point in this lifecycle.
pub struct ApplyVerifiedPackageRequest<'a> {
    config: &'a ConnectionConfig,
    package: &'a VerifiedPackage,
    deployment: ActivationDeployment<'a>,
    precondition: ApplyPrecondition<'a>,
    roles: ApplyRoles<'a>,
    timeouts: ApplyTimeouts,
    backup_evidence: &'a [DestructiveBackupEvidence<'a>],
    predecessor_history_descriptor: Option<&'a HistorySchemaDescriptor>,
    predecessor_migration_baseline: Option<&'a CompiledRegistryMigrationBaseline>,
    predecessor_engine_capabilities: Option<&'a VerifiedPredecessorPackage>,
    event_destination_compatibility_inventory: Option<&'a EventDestinationCompatibilityInventory>,
    field_encryption: Option<AppliedFieldEncryptionKeySource<'a>>,
    fault_after_committed_chunks: Option<u64>,
    audit: Option<RegistryAudit>,
    operator_reference: Option<&'a str>,
}

/// The key source one apply resolves field-encryption data keys through. It
/// borrows the already-configured provider and secret resolver; it opens no
/// connection and carries no authority beyond the apply it is bound to.
pub struct AppliedFieldEncryptionKeySource<'a> {
    provider: &'a crate::field_encryption::FieldEncryptionProvider,
    secrets: &'a registry_platform_config::SecretResolver,
}

impl<'a> AppliedFieldEncryptionKeySource<'a> {
    #[must_use]
    pub fn new(
        provider: &'a crate::field_encryption::FieldEncryptionProvider,
        secrets: &'a registry_platform_config::SecretResolver,
    ) -> Self {
        Self { provider, secrets }
    }
}

impl<'a> ApplyVerifiedPackageRequest<'a> {
    #[must_use]
    pub fn new(
        config: &'a ConnectionConfig,
        package: &'a VerifiedPackage,
        deployment: ActivationDeployment<'a>,
        precondition: ApplyPrecondition<'a>,
        roles: ApplyRoles<'a>,
        timeouts: ApplyTimeouts,
        audit: RegistryAudit,
    ) -> Self {
        Self {
            config,
            package,
            deployment,
            precondition,
            roles,
            timeouts,
            backup_evidence: &[],
            predecessor_history_descriptor: None,
            predecessor_migration_baseline: None,
            predecessor_engine_capabilities: None,
            event_destination_compatibility_inventory: None,
            field_encryption: None,
            fault_after_committed_chunks: None,
            audit: Some(audit),
            operator_reference: None,
        }
    }

    /// A request [`plan_verified_package`] reads. It carries no audit: a plan
    /// writes nothing, so it records no activation.
    #[must_use]
    pub fn plan(
        config: &'a ConnectionConfig,
        package: &'a VerifiedPackage,
        deployment: ActivationDeployment<'a>,
        precondition: ApplyPrecondition<'a>,
        roles: ApplyRoles<'a>,
        timeouts: ApplyTimeouts,
    ) -> Self {
        Self {
            config,
            package,
            deployment,
            precondition,
            roles,
            timeouts,
            backup_evidence: &[],
            predecessor_history_descriptor: None,
            predecessor_migration_baseline: None,
            predecessor_engine_capabilities: None,
            event_destination_compatibility_inventory: None,
            field_encryption: None,
            fault_after_committed_chunks: None,
            audit: None,
            operator_reference: None,
        }
    }

    /// Bind the operator's reference for this activation. The ledger and the
    /// activation audit record only its keyed hash, never the text.
    #[must_use]
    pub fn with_operator_reference(mut self, operator_reference: &'a str) -> Self {
        self.operator_reference = Some(operator_reference);
        self
    }

    #[must_use]
    pub fn with_destructive_backup_evidence(
        mut self,
        evidence: &'a [DestructiveBackupEvidence<'a>],
    ) -> Self {
        self.backup_evidence = evidence;
        self
    }

    /// Bind successor history readiness to the already verified, read-only
    /// predecessor schema descriptor. This descriptor can be retained and used
    /// to decode historical snapshots, but it never grants runtime authority or
    /// permission to execute predecessor SQL.
    #[must_use]
    pub fn with_predecessor_history_descriptor(
        mut self,
        descriptor: &'a HistorySchemaDescriptor,
    ) -> Self {
        self.predecessor_history_descriptor = Some(descriptor);
        self
    }

    /// Bind successor history readiness to the verified predecessor baseline
    /// when the target manifest cannot carry one. The baseline only describes
    /// historical storage shape; it does not grant startup, runtime, or SQL
    /// execution authority.
    #[must_use]
    pub fn with_predecessor_migration_baseline(
        mut self,
        baseline: &'a CompiledRegistryMigrationBaseline,
    ) -> Self {
        self.predecessor_migration_baseline = Some(baseline);
        self
    }

    /// Bind engine-owned successor work to the hash-covered capabilities of
    /// the verified predecessor package. This grants no predecessor SQL or
    /// runtime authority; it only distinguishes a closed legacy capability
    /// transition from an ordinary empty package plan.
    #[must_use]
    pub fn with_predecessor_engine_capabilities(
        mut self,
        predecessor: &'a VerifiedPredecessorPackage,
    ) -> Self {
        self.predecessor_engine_capabilities = Some(predecessor);
        self
    }

    /// Bind successor activation to the target runtime's activated,
    /// non-secret logical destination inventory. Omitting this inventory is
    /// equivalent to an empty inventory and therefore fails closed when any
    /// retained non-terminal webhook work exists.
    #[must_use]
    pub fn with_event_destination_compatibility_inventory(
        mut self,
        inventory: &'a EventDestinationCompatibilityInventory,
    ) -> Self {
        self.event_destination_compatibility_inventory = Some(inventory);
        self
    }

    /// Bind the field-encryption key source a reviewed field-encryption
    /// backfill resolves its data-encryption key through. The key source never
    /// grants SQL or package authority; a plan that needs it and does not get
    /// it fails closed.
    #[must_use]
    pub fn with_field_encryption_key_source(
        mut self,
        key_source: AppliedFieldEncryptionKeySource<'a>,
    ) -> Self {
        self.field_encryption = Some(key_source);
        self
    }

    #[cfg(feature = "postgres-test")]
    #[must_use]
    #[doc(hidden)]
    pub fn with_fault_for_test(mut self, fault: ReviewedMigrationFaultPoint) -> Self {
        self.fault_after_committed_chunks = match fault {
            ReviewedMigrationFaultPoint::AfterCommittedChunk(chunks) => Some(chunks),
        };
        self
    }
}

/// Apply the exact plan already rederived by the package verifier, verify the
/// resulting managed catalog and the package's schema fingerprint, and atomically
/// activate its identity with an immutable applied-ledger outcome.
///
/// Threat: a caller might try to run SQL outside the reviewed package, apply a
/// startup package, skip sequence/prior checks, clear failed maintenance with a
/// different target, or race record work. Enforcement is this package-only
/// coordinator plus the exact-role dedicated session lock and ledger. Failures
/// after the control plane begins leave applying or failed state, so records
/// remain unavailable and recovery is exact-target fix-forward only.
pub async fn apply_verified_package(
    request: ApplyVerifiedPackageRequest<'_>,
) -> Result<ExpectedRegistryIdentity> {
    match activate(request, ApplyMode::Activate).await? {
        Activated::Applied(identity) => Ok(identity),
        Activated::Planned(_) => Err(MigrationError::ApplyFailed),
    }
}

/// Run every check [`apply_verified_package`] runs before it writes, under
/// the same apply lock and migration credential, and report the activation
/// the package would make. Nothing is written: the checks apply makes inside
/// its begin transaction run in one this plan rolls back, and no
/// audit entry is appended.
///
/// Threat: a plan that checks less than apply reports a package as ready
/// that apply then refuses, or a plan that writes changes the database it
/// only reports on. Enforcement: plan and apply are one coordinator that
/// branches only after the last check before the activation's first
/// durable write. The active package with the roles its activation serves
/// with is not a refusal here: it is an activation with nothing pending.
pub async fn plan_verified_package(
    request: ApplyVerifiedPackageRequest<'_>,
) -> Result<ActivationPlan> {
    let role_mode = RoleMode::from_roles(request.roles.migration, request.roles.runtime);
    match activate(request, ApplyMode::Plan).await {
        Ok(Activated::Planned(plan)) => Ok(plan),
        Ok(Activated::Applied(_)) => Err(MigrationError::ApplyFailed),
        Err(MigrationError::AlreadyActive) => Ok(ActivationPlan {
            activation: PlannedActivation::AlreadyActive,
            role_mode: role_mode.as_str(),
            resumes_activation_id: None,
            required_backups: Vec::new(),
            checks: PlannedActivation::AlreadyActive.checks(),
        }),
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplyMode {
    Activate,
    Plan,
}

enum Activated {
    Applied(ExpectedRegistryIdentity),
    Planned(ActivationPlan),
}

/// The activation a package would make, as [`plan_verified_package`]
/// reports it. It names no value, SQL, or credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationPlan {
    pub activation: PlannedActivation,
    /// `single` or `split`, as the configured roles make it.
    pub role_mode: &'static str,
    /// The activation an interrupted apply of the same package recorded,
    /// which the next apply resumes instead of starting another.
    pub resumes_activation_id: Option<String>,
    /// The reviewed migrations' backup binding paths, in plan order, that
    /// apply requires `--backup` for and the plan did not verify.
    pub required_backups: Vec<String>,
    /// The database checks that passed, in the order they ran.
    pub checks: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlannedActivation {
    Initial,
    Successor,
    RoleChange,
    /// The package is active with the roles its activation serves with.
    AlreadyActive,
}

impl PlannedActivation {
    /// Whether apply would record an activation.
    #[must_use]
    pub fn is_pending(self) -> bool {
        self != Self::AlreadyActive
    }

    // Each list names the checks the coordinator runs for this activation,
    // in order; reaching the plan's report means every one passed.
    fn checks(self) -> &'static [&'static str] {
        match self {
            Self::Initial => &[
                "migration-role",
                "runtime-write-authority",
                "prerequisites",
                "uninitialized-database",
            ],
            Self::Successor => &[
                "successor-binding",
                "migration-role",
                "runtime-write-authority",
                "prerequisites",
                "request-proposals",
                "history-coverage",
                "webhook-bindings",
                "active-state",
            ],
            Self::RoleChange => &[
                "active-binding",
                "migration-role",
                "runtime-write-authority",
                "prerequisites",
                "active-roles",
                "history-coverage",
                "webhook-bindings",
                "active-state",
            ],
            Self::AlreadyActive => &[
                "active-binding",
                "migration-role",
                "runtime-write-authority",
                "prerequisites",
                "active-roles",
            ],
        }
    }
}

async fn activate(request: ApplyVerifiedPackageRequest<'_>, mode: ApplyMode) -> Result<Activated> {
    let manifest = request.package.manifest();
    let role_change = matches!(request.precondition, ApplyPrecondition::RoleChange { .. });
    let current = match request.precondition {
        ApplyPrecondition::InitialActivation => None,
        ApplyPrecondition::Successor { current } => {
            verify_successor_package_binding(
                request.package,
                request.deployment.database_id(),
                current,
            )?;
            Some(current)
        }
        ApplyPrecondition::RoleChange { current } => {
            verify_role_change_binding(request.package, request.deployment.database_id(), current)?;
            Some(current)
        }
    };
    // An uninitialized database accepts any package of a chain: it installs
    // the package's full compiled catalog, so neither the package's successor
    // plan nor its reviewed migrations apply to it.
    // A role change runs no DDL: the active package's catalog is already in
    // place, and only the runtime ACL changes.
    let compiler_statements: &[DdlStatement] = match current {
        Some(_) if role_change => &[],
        Some(_) => &manifest.migration_plan.statements,
        None => &request.package.registry().ddl().statements,
    };
    let reviewed_plan = current
        .filter(|_| !role_change)
        .and(request.package.reviewed_migration_plan());
    let declares_encrypted_fields = request
        .package
        .registry()
        .entities()
        .values()
        .any(|entity| {
            entity
                .fields
                .values()
                .any(|field| field.encryption.is_some())
        });
    if declares_encrypted_fields && request.field_encryption.is_none() {
        return Err(MigrationError::PackageBinding);
    }
    if current.is_some()
        && !role_change
        && manifest.migration_plan.reviewed_descriptors.is_empty() != reviewed_plan.is_none()
    {
        return Err(MigrationError::PackageBinding);
    }
    let rescoped_descriptor;
    let successor_history = if let Some(plan_current) = current.filter(|_| !role_change) {
        let predecessor_baseline = bind_predecessor_baseline(
            manifest.migration_plan.prior_baseline.as_ref(),
            request.predecessor_migration_baseline,
        )?;
        if predecessor_baseline
            .is_some_and(|baseline| baseline.package_digest != plan_current.package_digest)
            || request
                .predecessor_history_descriptor
                .is_some_and(|descriptor| {
                    descriptor.package_revision != plan_current.package_digest
                })
        {
            return Err(MigrationError::PackageBinding);
        }
        // A package names its predecessor's history descriptor by package
        // digest; the database retains it under the activation that made the
        // predecessor active.
        rescoped_descriptor =
            request
                .predecessor_history_descriptor
                .map(|descriptor| HistorySchemaDescriptor {
                    package_revision: plan_current.activation_id.clone(),
                    ..descriptor.clone()
                });
        Some((predecessor_baseline, rescoped_descriptor.as_ref()))
    } else {
        None
    };
    let engine_capability_only_upgrade = successor_plan_is_empty(request.package)
        && request
            .predecessor_engine_capabilities
            .is_some_and(|predecessor| installs_engine_capability(request.package, predecessor));
    let empty_successor =
        successor_plan_is_empty(request.package) && !engine_capability_only_upgrade;
    if current.is_some() && !role_change && empty_successor {
        return Err(MigrationError::EmptyPlan);
    }

    let compiler_checksums = compiler_statement_checksums(compiler_statements);
    let mut ledger = match current {
        Some(current) if role_change => {
            role_change_ledger_entry(request.package, current, request.roles)
        }
        _ => package_ledger_entry(request.package, current, request.roles, &compiler_checksums)?,
    };
    if engine_capability_only_upgrade {
        // The package binds a successor activation but carries no authored
        // compiler statement: the engine reconciles its own control plane and
        // the final activation verifies the exact expanded catalog. Record it
        // with the same no-statement ledger shape as other package-only
        // capability changes, never with a synthetic DDL checksum.
        ledger.migration_kind = MigrationKind::MetadataOnly;
    }
    ledger
        .validate_plan()
        .map_err(|_| MigrationError::PackageBinding)?;
    let statements = compiler_statements
        .iter()
        .zip(&compiler_checksums)
        .enumerate()
        .map(|(ordinal, (statement, checksum))| {
            Ok(PackageDdlStatement {
                sql: &statement.sql,
                checksum,
                kind: statement.kind,
                pattern_field: crate::postgres::compiled_pattern_field(
                    request.package.registry(),
                    &statement.id,
                ),
                ordinal: i32::try_from(ordinal).map_err(|_| MigrationError::PackageBinding)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // Threat: a path-only backup check could be swapped between validation
    // and the maintenance transition. The library opens with NOFOLLOW, checks
    // the binding's metadata and bytes, and retains every descriptor
    // through activation. It never interprets backup contents or grants them
    // package or migration authority.
    // A plan verifies backup evidence only when it is given some; without
    // it, the plan reports the bindings apply will require.
    let required_backups = reviewed_plan
        .map(required_backup_binding_paths)
        .unwrap_or_default()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let (_retained_backup_evidence, backup_references) = if mode == ApplyMode::Plan
        && request.backup_evidence.is_empty()
    {
        (Vec::new(), Vec::new())
    } else {
        verify_destructive_backup_evidence(reviewed_plan, current, request.backup_evidence).await?
    };
    ledger.backup_references = backup_references;

    if let Some(reference) = request.operator_reference {
        if !operator_reference_is_well_formed(reference)
            || !request
                .audit
                .as_ref()
                .is_some_and(|audit| crate::audit::profile_is_keyed(audit.profile()))
        {
            return Err(MigrationError::OperatorReference);
        }
    }

    let lock_key =
        RegistryLockKey::derive(&manifest.package_id).map_err(|_| MigrationError::ApplyFailed)?;
    let mut connection = VerifiedPackageApplyConnection::acquire_for_verified_package(
        request.config,
        lock_key,
        request.roles.migration,
        request.timeouts.lock,
        request.timeouts.statement,
    )
    .await
    .map_err(refusal_before_maintenance)?;
    // Registry state this release does not recognise is refused before any
    // check reads it as the ledger's.
    match connection.registry_state_shape().await {
        Ok(crate::postgres::RegistryStateShape::Unrecognized) => {
            let _ = connection.release().await;
            return Err(MigrationError::UnrecognizedDatabase);
        }
        Ok(_) => {}
        Err(error) => {
            let _ = connection.release().await;
            return Err(refusal_before_maintenance(error));
        }
    }
    if let Err(error) = refuse_runtime_write_authority(&mut connection, request.roles).await {
        let _ = connection.release().await;
        return Err(error);
    }
    // Prerequisites are administrator-owned. Refuse a missing extension or
    // spatial role before the existing registry enters maintenance.
    if connection
        .verify_compiled_prerequisites(request.package.registry(), request.roles.runtime)
        .await
        .is_err()
    {
        let _ = connection.release().await;
        return Err(MigrationError::ApplyFailed);
    }
    // A retry of the same target resumes the activation its first attempt
    // recorded, with the roles that attempt started with; any other apply is
    // a fresh activation.
    let mut resumes_activation_id = None;
    ledger.activation_id = match connection
        .in_flight_activation(request.package.package_digest())
        .await
    {
        Ok(Some(activation)) => {
            if activation.role_mode != ledger.role_mode.as_str()
                || activation.runtime_role != ledger.runtime_role
            {
                let _ = connection.release().await;
                return Err(MigrationError::ResumeRolesDiffer {
                    role_mode: activation.role_mode,
                    runtime_role: activation.runtime_role,
                });
            }
            resumes_activation_id = Some(activation.activation_id.hyphenated().to_string());
            activation.activation_id
        }
        Ok(None) => uuid::Uuid::new_v4(),
        Err(error) => {
            let _ = connection.release().await;
            return Err(refusal_before_maintenance(error));
        }
    };
    // The ledger keeps the operator's reference only as a keyed hash scoped
    // to this activation, so the text never reaches the database.
    if let Some(reference) = request.operator_reference {
        match request
            .audit
            .as_ref()
            .ok_or(MigrationError::OperatorReference)
            .and_then(|audit| operator_reference_hash(audit, ledger.activation_id, reference))
        {
            Ok(hash) => ledger.operator_reference_hash = Some(hash),
            Err(error) => {
                let _ = connection.release().await;
                return Err(error);
            }
        }
    }
    // A re-apply of the active package is an activation only when it changes
    // the roles the active activation serves with.
    let retired_runtime_role = if role_change {
        match connection.active_activation_roles().await {
            Ok(Some((role_mode, runtime_role))) => {
                if role_mode == ledger.role_mode.as_str() && runtime_role == ledger.runtime_role {
                    // Unchanged roles leave nothing to activate unless the
                    // split-role runtime role lost a grant, as reassigning
                    // an object's ownership back strips them: the apply then
                    // reissues them.
                    let grants_missing = if ledger.role_mode == RoleMode::Split {
                        connection
                            .runtime_grants_missing(
                                request.roles.runtime,
                                &ExpectedManagedCatalog::compiled(request.package.registry()),
                            )
                            .await
                    } else {
                        Ok(false)
                    };
                    match grants_missing {
                        Ok(true) => {}
                        Ok(false) => {
                            let _ = connection.release().await;
                            return Err(MigrationError::AlreadyActive);
                        }
                        Err(error) => {
                            let _ = connection.release().await;
                            return Err(refusal_before_maintenance(error));
                        }
                    }
                }
                SqlIdentifier::parse(&runtime_role)
                    .ok()
                    .filter(|retired| retired != request.roles.runtime)
            }
            Ok(None) | Err(_) => {
                let _ = connection.release().await;
                return Err(MigrationError::ApplyFailed);
            }
        }
    } else if current.is_some() {
        // Only a role change retires the runtime role the active activation
        // records, so a successor serves with the roles that activation
        // records.
        match connection.active_activation_roles().await {
            Ok(Some((role_mode, runtime_role)))
                if role_mode == ledger.role_mode.as_str()
                    && runtime_role == ledger.runtime_role =>
            {
                None
            }
            Ok(Some((role_mode, runtime_role))) => {
                let _ = connection.release().await;
                return Err(MigrationError::SuccessorRolesDiffer {
                    role_mode,
                    runtime_role,
                });
            }
            Ok(None) | Err(_) => {
                let _ = connection.release().await;
                return Err(MigrationError::ApplyFailed);
            }
        }
    } else {
        None
    };
    let target = target_package_identity(
        request.package,
        request.deployment.database_id(),
        ledger.activation_id,
    );
    if mode == ApplyMode::Plan {
        let rehearsed = rehearse_begin(&mut connection, &request, current, &target, &ledger).await;
        let released = connection.release().await;
        rehearsed?;
        released.map_err(|_| MigrationError::ApplyFailed)?;
        let activation = match current {
            None => PlannedActivation::Initial,
            Some(_) if role_change => PlannedActivation::RoleChange,
            Some(_) => PlannedActivation::Successor,
        };
        return Ok(Activated::Planned(ActivationPlan {
            activation,
            role_mode: ledger.role_mode.as_str(),
            resumes_activation_id,
            required_backups,
            checks: activation.checks(),
        }));
    }
    let Some(audit) = request.audit.as_ref() else {
        let _ = connection.release().await;
        return Err(MigrationError::ActivationAuditUnavailable);
    };
    let attempt = match ActivationAttempt::begin(
        audit,
        request.deployment,
        current,
        &target,
        &ledger,
    )
    .await
    {
        Ok(attempt) => attempt,
        Err(error) => {
            let _ = connection.release().await;
            return Err(error);
        }
    };
    if current.is_some() {
        // Existing registries may have been initialized by a binary that
        // predates newer product-owned control tables. Reconcile them while
        // the verified migration session holds the apply lock and before the
        // successor can enter durable maintenance. A role change reconciles
        // them for the runtime role still serving: the role it activates
        // receives its grants inside the activation transaction, so a
        // refusal before maintenance leaves that role nothing. When the role
        // the ledger names no longer exists, nothing serves to reconcile for.
        let control_plane_role = match retired_runtime_role.as_ref() {
            None => Some(request.roles.runtime),
            Some(retired) => match connection.role_exists(retired).await {
                Ok(true) => Some(retired),
                Ok(false) => None,
                Err(_) => {
                    return refuse_and_release(
                        connection,
                        attempt,
                        &target,
                        MigrationError::ApplyFailed,
                    )
                    .await;
                }
            },
        };
        if let Some(control_plane_role) = control_plane_role {
            if connection
                .reconcile_successor_control_plane(control_plane_role)
                .await
                .is_err()
            {
                return refuse_and_release(
                    connection,
                    attempt,
                    &target,
                    MigrationError::ApplyFailed,
                )
                .await;
            }
        }
        // A role change keeps the compiled model, so no request proposal
        // needs a rebase.
        let proposals_guarded = if role_change {
            Ok(())
        } else {
            crate::request_retention::guard_successor_activation(
                connection.client_for_request_retention_guard(),
                request.package.registry(),
            )
            .await
        };
        if let Err(error) = proposals_guarded {
            let refused = match error {
                crate::request_retention::RequestRetentionError::ActiveProposalRequiresRebase => {
                    MigrationError::ActiveRequestProposals
                }
                _ => MigrationError::ApplyFailed,
            };
            return refuse_and_release(connection, attempt, &target, refused).await;
        }
    }
    let began = if let Some(current) = current {
        connection
            .begin_successor_package(
                current,
                &target,
                &ledger,
                request.event_destination_compatibility_inventory,
            )
            .await
    } else {
        connection
            .begin_initial_package(&target, &ledger, request.roles.runtime)
            .await
    };
    if let Err(error) = began {
        // The coverage check runs inside the begin transaction before its
        // first write, so a coverage refusal leaves maintenance state as it was.
        let refused = match error {
            crate::postgres::PostgresKernelError::HistoryCoverageIncomplete => {
                MigrationError::HistoryCoverage
            }
            _ => MigrationError::ApplyFailed,
        };
        return refuse_and_release(connection, attempt, &target, refused).await;
    }

    if declares_encrypted_fields {
        let key_source = request
            .field_encryption
            .as_ref()
            .ok_or(MigrationError::PackageBinding)?;
        if connection
            .activate_field_encryption_key_state(
                &ReviewedFieldEncryptionContext {
                    provider: key_source.provider,
                    secrets: key_source.secrets,
                },
                request.package.registry(),
                &target.activation_id,
            )
            .await
            .is_err()
        {
            return fail_and_release(connection, attempt, &target, &ledger).await;
        }
    }

    if let Some((predecessor_baseline, predecessor_descriptor)) = successor_history {
        if connection
            .ensure_successor_history_ready(
                current.ok_or(MigrationError::PackageBinding)?,
                predecessor_baseline,
                predecessor_descriptor,
                request.roles.runtime,
            )
            .await
            .is_err()
        {
            return fail_and_release(connection, attempt, &target, &ledger).await;
        }
        if connection
            .retain_target_history_descriptor(request.package.registry(), &target.activation_id)
            .await
            .is_err()
        {
            return fail_and_release(connection, attempt, &target, &ledger).await;
        }
    }

    let expected_catalog = ExpectedManagedCatalog::compiled(request.package.registry());
    if role_change {
        if connection
            .retain_target_history_descriptor(request.package.registry(), &target.activation_id)
            .await
            .is_err()
        {
            return fail_and_release(connection, attempt, &target, &ledger).await;
        }
        // The runtime grants, the retirement of the role the activation
        // stops serving with, and the activation commit together, so a
        // refused activation leaves the serving runtime role its grants.
        let superseded = match connection
            .activate_role_change(
                request.package.registry(),
                current,
                &target,
                MaintenanceTransition {
                    ledger: &ledger,
                    expected_catalog: &expected_catalog,
                    migration_role: request.roles.migration,
                    runtime_role: request.roles.runtime,
                },
                retired_runtime_role.as_ref(),
            )
            .await
        {
            Ok(superseded) => superseded,
            Err(error) => {
                return fail_with_error_and_release(connection, attempt, &target, &ledger, error)
                    .await;
            }
        };
        return finish_activation(connection, audit, attempt, superseded, target)
            .await
            .map(Activated::Applied);
    }
    if let Some(plan) = reviewed_plan {
        let prior_tables = successor_history
            .and_then(|(baseline, _)| baseline)
            .ok_or(MigrationError::PackageBinding)?
            .entities
            .values()
            .map(|entity| entity.physical_table.clone())
            .collect::<Vec<_>>();
        let candidate_tables = request
            .package
            .registry()
            .entities()
            .values()
            .map(|entity| entity.physical_table.clone())
            .collect::<Vec<_>>();
        let execution = connection
            .execute_reviewed_package_plan(ReviewedPackageExecutionRequest {
                registry: request.package.registry(),
                current: current.ok_or(MigrationError::PackageBinding)?,
                target_package_revision: &target.activation_id,
                plan,
                predecessor_baseline: successor_history.and_then(|(baseline, _)| baseline),
                predecessor_history_descriptor: successor_history
                    .and_then(|(_, descriptor)| descriptor),
                field_encryption: request.field_encryption.as_ref().map(|key_source| {
                    ReviewedFieldEncryptionContext {
                        provider: key_source.provider,
                        secrets: key_source.secrets,
                    }
                }),
                runtime_role: request.roles.runtime,
                compiler_statements: &statements,
                ledger: &ledger,
                prior_tables: &prior_tables,
                candidate_tables: &candidate_tables,
                compiler_lock_timeout: request.timeouts.lock,
                compiler_statement_timeout: request.timeouts.statement,
                fault_after_committed_chunks: request.fault_after_committed_chunks,
            })
            .await;
        match execution {
            Ok(ReviewedExecutionOutcome::Complete) => {}
            Ok(ReviewedExecutionOutcome::Interrupted) => {
                return refuse_and_release(
                    connection,
                    attempt,
                    &target,
                    MigrationError::ApplyFailed,
                )
                .await;
            }
            Err(error) => {
                return fail_with_error_and_release(connection, attempt, &target, &ledger, error)
                    .await;
            }
        }
        if let Err(error) = connection
            .reconcile_runtime_acl(request.package.registry(), request.roles.runtime)
            .await
        {
            return fail_with_error_and_release(connection, attempt, &target, &ledger, error).await;
        }
        let Ok(superseded) = connection
            .activate_verified_package(
                current,
                &target,
                MaintenanceTransition {
                    ledger: &ledger,
                    expected_catalog: &expected_catalog,
                    migration_role: request.roles.migration,
                    runtime_role: request.roles.runtime,
                },
            )
            .await
        else {
            return fail_and_release(connection, attempt, &target, &ledger).await;
        };
        return finish_activation(connection, audit, attempt, superseded, target)
            .await
            .map(Activated::Applied);
    }

    if connection
        .reconcile_runtime_acl(request.package.registry(), request.roles.runtime)
        .await
        .is_ok()
    {
        if let Ok(superseded) = connection
            .activate_verified_package(
                current,
                &target,
                MaintenanceTransition {
                    ledger: &ledger,
                    expected_catalog: &expected_catalog,
                    migration_role: request.roles.migration,
                    runtime_role: request.roles.runtime,
                },
            )
            .await
        {
            return finish_activation(connection, audit, attempt, superseded, target)
                .await
                .map(Activated::Applied);
        }
    }

    let ddl_result = if current.is_some() {
        connection
            .execute_successor_package_ddl(
                &statements,
                request.roles.runtime,
                request.timeouts.statement,
            )
            .await
    } else {
        connection
            .execute_initial_package_ddl(
                request.package.registry(),
                &target.activation_id,
                &statements,
                request.roles.runtime,
                request.timeouts.statement,
            )
            .await
    };
    if let Err(error) = ddl_result {
        return fail_with_error_and_release(connection, attempt, &target, &ledger, error).await;
    }
    let acl_result = connection
        .reconcile_runtime_acl(request.package.registry(), request.roles.runtime)
        .await;
    if let Err(error) = acl_result {
        return fail_with_error_and_release(connection, attempt, &target, &ledger, error).await;
    }
    let activation_result = connection
        .activate_verified_package(
            current,
            &target,
            MaintenanceTransition {
                ledger: &ledger,
                expected_catalog: &expected_catalog,
                migration_role: request.roles.migration,
                runtime_role: request.roles.runtime,
            },
        )
        .await;
    let Ok(superseded) = activation_result else {
        return fail_and_release(connection, attempt, &target, &ledger).await;
    };
    finish_activation(connection, audit, attempt, superseded, target)
        .await
        .map(Activated::Applied)
}

/// Run the checks apply's successor or initial begin makes, in the order
/// apply makes them, in transactions that roll back.
async fn rehearse_begin(
    connection: &mut VerifiedPackageApplyConnection,
    request: &ApplyVerifiedPackageRequest<'_>,
    current: Option<&ExpectedRegistryIdentity>,
    target: &ExpectedRegistryIdentity,
    ledger: &MigrationLedgerEntry,
) -> Result<()> {
    let role_change = matches!(request.precondition, ApplyPrecondition::RoleChange { .. });
    let Some(current) = current else {
        return connection
            .rehearse_initial_package(target, ledger, request.roles.runtime)
            .await
            .map_err(|_| MigrationError::ApplyFailed);
    };
    // The guard reads only request tables, which the control-plane
    // reconciliation apply runs before it never changes.
    if !role_change {
        crate::request_retention::guard_successor_activation(
            connection.client_for_request_retention_guard(),
            request.package.registry(),
        )
        .await
        .map_err(|error| match error {
            crate::request_retention::RequestRetentionError::ActiveProposalRequiresRebase => {
                MigrationError::ActiveRequestProposals
            }
            _ => MigrationError::ApplyFailed,
        })?;
    }
    connection
        .rehearse_successor_package(
            current,
            target,
            ledger,
            request.event_destination_compatibility_inventory,
            request.roles.runtime,
        )
        .await
        .map_err(|error| match error {
            crate::postgres::PostgresKernelError::HistoryCoverageIncomplete => {
                MigrationError::HistoryCoverage
            }
            _ => MigrationError::ApplyFailed,
        })
}

/// The keyed hash the ledger records for an operator reference, scoped to one
/// activation so the same reference never links two activations.
fn operator_reference_hash(
    audit: &RegistryAudit,
    activation_id: uuid::Uuid,
    reference: &str,
) -> Result<String> {
    audit
        .profile()
        .key_hasher()
        .audit_reference_hash(
            "breg-activation-operator-reference-v1",
            &activation_id.to_string(),
            reference,
        )
        .map_err(|_| MigrationError::OperatorReference)
}

/// Refuse a split-role runtime role that could write the activation ledger
/// or the registry state, before the registry enters maintenance, by the one
/// fix that removes the finding.
async fn refuse_runtime_write_authority(
    connection: &mut VerifiedPackageApplyConnection,
    roles: ApplyRoles<'_>,
) -> Result<()> {
    if RoleMode::from_roles(roles.migration, roles.runtime) == RoleMode::Single {
        return Ok(());
    }
    match connection
        .runtime_write_authority(roles.migration, roles.runtime)
        .await
    {
        Ok(None) => Ok(()),
        Ok(Some(finding)) => Err(MigrationError::RuntimeWriteAuthority(finding)),
        Err(error) => Err(refusal_before_maintenance(error)),
    }
}

/// Answer the activation's audit request with its applied outcome and append
/// the records of the import authorities it superseded, then release the
/// lock. The activation stands either way; a refused entry is reported so
/// the operator knows the audit trail is missing records, and the lock is
/// still released.
async fn finish_activation(
    connection: VerifiedPackageApplyConnection,
    audit: &RegistryAudit,
    attempt: ActivationAttempt,
    superseded: Vec<serde_json::Value>,
    target: ExpectedRegistryIdentity,
) -> Result<ExpectedRegistryIdentity> {
    let answered = attempt.respond("applied").await;
    let appended = crate::import_authority::append_transitions(audit, superseded).await;
    connection
        .release()
        .await
        .map_err(|_| MigrationError::ApplyFailed)?;
    if answered.is_err() || appended.is_err() {
        return Err(MigrationError::ActivationAuditIncomplete);
    }
    Ok(target)
}

/// One activation's audit request, accepted before the activation changes
/// any state and answered once the durable state shows how it ended.
///
/// Threat: an activation the audit trail does not account for. The audit
/// journal is a file, so no entry can share the activation's transaction.
/// Enforcement: the request entry is accepted before the first activation
/// write, and a refused request refuses the activation; the response follows
/// the commit (`applied`) or durable state that shows the target did not
/// become active or that maintenance failed (`failed`). An attempt whose end
/// the durable state cannot show is answered `unfinished` when its handle is
/// dropped.
struct ActivationAttempt {
    request: AuditRequest,
    record: Value,
}

impl ActivationAttempt {
    /// Records identities, the plan shape, the role mode, and the keyed
    /// operator reference; no package, catalog, or record value. Request
    /// and response share the activation id as their correlation.
    async fn begin(
        audit: &RegistryAudit,
        deployment: ActivationDeployment<'_>,
        prior: Option<&ExpectedRegistryIdentity>,
        target: &ExpectedRegistryIdentity,
        ledger: &MigrationLedgerEntry,
    ) -> Result<Self> {
        let record = json!({
            "operationId": ACTIVATION_AUDIT_OPERATION_ID,
            "activationId": target.activation_id,
            "priorActivationId": prior.map(|prior| &prior.activation_id),
            "packageDigest": target.package_digest,
            "predecessorPackageDigest": ledger.predecessor_package_digest,
            "registryRevision": ledger.registry_revision,
            "planKind": ledger.plan_kind.as_str(),
            "databaseId": deployment.database_id(),
            "environment": deployment.environment(),
            "instanceId": deployment.instance_id(),
            "roleMode": ledger.role_mode.as_str(),
            "operatorReference": ledger.operator_reference_hash,
        });
        let request = audit
            .begin(
                AuditEntry::request(
                    ACTIVATION_AUDIT_SCHEMA,
                    target.activation_id.clone(),
                    outcome_record(&record, "attempt", "started"),
                ),
                outcome_record(&record, "terminal", "unfinished"),
            )
            .await
            .map_err(|_| MigrationError::ActivationAuditUnavailable)?;
        Ok(Self { request, record })
    }

    async fn respond(mut self, outcome: &'static str) -> Result<()> {
        let record = outcome_record(&self.record, "terminal", outcome);
        self.request
            .respond(record)
            .await
            .map_err(|_| MigrationError::ActivationAuditIncomplete)
    }

    /// The activation already failed, so a refused entry is only logged;
    /// the dropped handle then writes its `unfinished` outcome instead.
    async fn respond_failed(self) {
        if self.respond("failed").await.is_err() {
            tracing::error!("the failed activation's response audit entry was not recorded");
        }
    }
}

fn outcome_record(record: &Value, phase: &'static str, outcome: &'static str) -> Value {
    let mut record = record.clone();
    record["phase"] = phase.into();
    record["outcome"] = outcome.into();
    record
}

/// Answer the audit request of an activation that returned an error:
/// `failed` when the durable state shows maintenance failed, or the target
/// is not active and no longer applying, or no registry state exists;
/// otherwise the dropped handle answers `unfinished`. A failed initial
/// activation leaves the state row naming its own target, so the failed
/// status alone decides it. An error does not prove the transaction rolled
/// back, so the durable state decides.
async fn answer_unlanded(
    connection: &mut VerifiedPackageApplyConnection,
    attempt: ActivationAttempt,
    target: &ExpectedRegistryIdentity,
) {
    let failed = match connection.maintenance_snapshot().await {
        Ok(snapshot) => {
            snapshot.maintenance_status == "failed"
                || (snapshot.identity.activation_id != target.activation_id
                    && snapshot.maintenance_status != "applying")
        }
        Err(crate::postgres::PostgresKernelError::RegistryUnavailable) => true,
        Err(_) => false,
    };
    if failed {
        attempt.respond_failed().await;
    }
}

/// Refuse an activation after its audit request was accepted but before it
/// pinned a failed target: answer the request as the durable state shows,
/// then release the lock.
async fn refuse_and_release<T>(
    mut connection: VerifiedPackageApplyConnection,
    attempt: ActivationAttempt,
    target: &ExpectedRegistryIdentity,
    refused: MigrationError,
) -> Result<T> {
    answer_unlanded(&mut connection, attempt, target).await;
    let _ = connection.release().await;
    Err(refused)
}

async fn fail_and_release<T>(
    mut connection: VerifiedPackageApplyConnection,
    attempt: ActivationAttempt,
    target: &ExpectedRegistryIdentity,
    ledger: &MigrationLedgerEntry,
) -> Result<T> {
    let marked_failed = connection
        .mark_verified_package_failed(target, ledger)
        .await
        .is_ok();
    answer_unlanded(&mut connection, attempt, target).await;
    let released = connection.release().await.is_ok();
    let _ = (marked_failed, released);
    Err(MigrationError::ApplyFailed)
}

async fn fail_with_error_and_release<T>(
    connection: VerifiedPackageApplyConnection,
    attempt: ActivationAttempt,
    target: &ExpectedRegistryIdentity,
    ledger: &MigrationLedgerEntry,
    error: crate::postgres::PostgresKernelError,
) -> Result<T> {
    let _: Result<()> = fail_and_release(connection, attempt, target, ledger).await;
    Err(match error {
        crate::postgres::PostgresKernelError::FieldPatternSyntax {
            entity_id,
            field_id,
        } => MigrationError::FieldPatternSyntax {
            entity_id,
            field_id,
        },
        crate::postgres::PostgresKernelError::FieldPatternExistingRows {
            entity_id,
            field_id,
        } => MigrationError::FieldPatternExistingRows {
            entity_id,
            field_id,
        },
        crate::postgres::PostgresKernelError::FieldEncryptionBlindCollision {
            entity_id,
            record_ids,
        } => MigrationError::FieldEncryptionLookupCollision {
            entity_id,
            record_ids,
        },
        crate::postgres::PostgresKernelError::FieldEncryptionRetainedRequestSnapshots {
            entity_id,
            field_id,
        } => MigrationError::FieldEncryptionRetainedRequestSnapshots {
            entity_id,
            field_id,
        },
        crate::postgres::PostgresKernelError::Statement(failure) => {
            MigrationError::StatementFailed(failure)
        }
        _ => MigrationError::ApplyFailed,
    })
}

/// Binds a reviewed plan's checksums, artifacts, and steps into `ledger`.
fn reviewed_ledger(
    package: &VerifiedPackage,
    current: &ExpectedRegistryIdentity,
    plan: &ValidatedReviewedMigrationPlan,
    ledger: &mut MigrationLedgerEntry,
) -> Result<()> {
    let manifest = package.manifest();
    if plan.migrations().is_empty()
        || manifest.migration_plan.prior_schema_fingerprint.as_deref()
            != Some(current.schema_fingerprint.as_str())
    {
        return Err(MigrationError::PackageBinding);
    }

    let mut statement_checksums = Vec::new();
    for migration in plan.migrations() {
        if migration.rehearsal_receipt.prior_package_digest != current.package_digest
            || migration.rehearsal_receipt.prior_schema_fingerprint != current.schema_fingerprint
            || migration.rehearsal_receipt.final_schema_fingerprint != manifest.schema_fingerprint
        {
            return Err(MigrationError::PackageBinding);
        }
        statement_checksums.extend(
            migration
                .pre_assertions
                .iter()
                .map(|assertion| assertion.sha256.clone()),
        );
    }
    statement_checksums.extend(
        manifest
            .migration_plan
            .statements
            .iter()
            .map(|statement| statement_checksum(&statement.sql)),
    );
    for migration in plan.migrations() {
        statement_checksums.extend(migration.steps.iter().map(|step| step.sha256.clone()));
    }
    for migration in plan.migrations() {
        statement_checksums.extend(
            migration
                .post_assertions
                .iter()
                .map(|assertion| assertion.sha256.clone()),
        );
    }

    let artifact_bindings = manifest
        .files
        .iter()
        .filter(|file| {
            matches!(
                file.role,
                PackageFileRole::ReviewedMigrationDescriptor
                    | PackageFileRole::ReviewedMigrationStepSql
                    | PackageFileRole::ReviewedMigrationAssertionSql
                    | PackageFileRole::MigrationRehearsalReceipt
                    | PackageFileRole::MigrationRehearsalFixture
            )
        })
        .map(|file| MigrationArtifactBinding {
            path: file.path.clone(),
            checksum: file.sha256.clone(),
        })
        .collect::<Vec<_>>();

    let mut steps = Vec::new();
    for (step_index, statement) in manifest.migration_plan.statements.iter().enumerate() {
        steps.push(MigrationLedgerStep {
            migration_ordinal: 0,
            step_ordinal: i32::try_from(step_index).map_err(|_| MigrationError::PackageBinding)?,
            step_id: format!("compiler-{step_index:04}"),
            kind: MigrationLedgerStepKind::CompilerDdl,
            checksum: statement_checksum(&statement.sql),
        });
    }
    for (migration_index, migration) in plan.migrations().iter().enumerate() {
        let migration_ordinal =
            i32::try_from(migration_index + 1).map_err(|_| MigrationError::PackageBinding)?;
        for (step_index, step) in migration.steps.iter().enumerate() {
            let (step_id, kind) = match &step.descriptor {
                ReviewedMigrationStepDescriptor::TransactionalSql { id, .. } => {
                    (id.clone(), MigrationLedgerStepKind::TransactionalSql)
                }
                ReviewedMigrationStepDescriptor::ChunkedBackfill { id, .. } => {
                    (id.clone(), MigrationLedgerStepKind::ChunkedBackfill)
                }
                ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { id, .. } => {
                    (id.clone(), MigrationLedgerStepKind::FieldEncryptionBackfill)
                }
            };
            steps.push(MigrationLedgerStep {
                migration_ordinal,
                step_ordinal: i32::try_from(step_index)
                    .map_err(|_| MigrationError::PackageBinding)?,
                step_id,
                kind,
                checksum: step.sha256.clone(),
            });
        }
    }

    ledger.migration_kind = MigrationKind::Reviewed;
    ledger.statement_checksums = statement_checksums;
    ledger.artifact_bindings = artifact_bindings;
    ledger.steps = steps;
    ledger
        .validate_plan()
        .map_err(|_| MigrationError::PackageBinding)
}

fn bind_predecessor_baseline<'a>(
    target_baseline: Option<&'a CompiledRegistryMigrationBaseline>,
    verified_baseline: Option<&'a CompiledRegistryMigrationBaseline>,
) -> Result<Option<&'a CompiledRegistryMigrationBaseline>> {
    match (target_baseline, verified_baseline) {
        (Some(target), Some(verified)) => {
            if !predecessor_baselines_match(target, verified) {
                return Err(MigrationError::PackageBinding);
            }
            Ok(Some(verified))
        }
        (Some(target), None) => Ok(Some(target)),
        (None, Some(verified)) => Ok(Some(verified)),
        (None, None) => Ok(None),
    }
}

fn predecessor_baselines_match(
    target: &CompiledRegistryMigrationBaseline,
    verified: &CompiledRegistryMigrationBaseline,
) -> bool {
    target.package_digest == verified.package_digest
        && target.registry_id == verified.registry_id
        && target.registry_version == verified.registry_version
        && target.entities == verified.entities
        && target.physical_names == verified.physical_names
        && target.routes == verified.routes
        && target.access == verified.access
        && target.queries == verified.queries
}

/// Whether an operator reference is one to 512 bytes without a control
/// character, the shape an activation records a keyed hash of.
#[must_use]
pub fn operator_reference_is_well_formed(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= MAX_OPERATOR_REFERENCE_BYTES
        && !reference.chars().any(char::is_control)
}

/// The binding paths an apply of this plan requires backup evidence for, in
/// plan order, so a caller that refuses evidence can name the exact set an
/// operator has to supply.
#[must_use]
pub fn required_backup_binding_paths(plan: &ValidatedReviewedMigrationPlan) -> Vec<&str> {
    plan.migrations()
        .iter()
        .filter_map(|migration| migration.descriptor.backup_binding_path.as_deref())
        .collect()
}

/// Pairs every required binding path with the supplied evidence that names
/// it, so the order evidence arrives in carries no meaning. The supplied
/// binding paths must be exactly the required set, each named once, and the
/// pairs keep the plan order of the requirement.
fn pair_backup_evidence<'a>(
    required: &[&'a str],
    evidence: &[DestructiveBackupEvidence<'a>],
) -> Result<Vec<&'a Path>> {
    if required.len() != evidence.len() {
        return Err(MigrationError::BackupEvidence);
    }
    let mut supplied = BTreeMap::new();
    for entry in evidence {
        if supplied
            .insert(entry.binding_path, entry.local_path)
            .is_some()
        {
            return Err(MigrationError::BackupEvidence);
        }
    }
    required
        .iter()
        .map(|binding_path| {
            supplied
                .remove(binding_path)
                .ok_or(MigrationError::BackupEvidence)
        })
        .collect()
}

/// Reads one bounded, closed backup binding document.
fn read_backup_binding(path: &Path) -> Result<ExternalBackupBinding> {
    if !path.is_absolute() {
        return Err(MigrationError::BackupEvidence);
    }
    let file = File::open(path).map_err(|_| MigrationError::BackupEvidence)?;
    let mut bytes = Vec::new();
    file.take(MAX_BACKUP_BINDING_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| MigrationError::BackupEvidence)?;
    if u64::try_from(bytes.len()).map_err(|_| MigrationError::BackupEvidence)?
        > MAX_BACKUP_BINDING_BYTES
    {
        return Err(MigrationError::BackupEvidence);
    }
    read_backup_binding_document(&path.display().to_string(), &bytes)
        .map_err(|report| MigrationError::BackupBindingDocument(Box::new(report)))
}

/// Checks one backup binding against the identity the database records as
/// active: the same database, the active package digest and schema
/// fingerprint, a bounded freshness window that has not elapsed, and an
/// absolute backup file.
fn check_backup_binding(
    binding: &ExternalBackupBinding,
    current: &ExpectedRegistryIdentity,
    now: OffsetDateTime,
) -> Result<()> {
    let created = OffsetDateTime::parse(&binding.created_at, &Rfc3339)
        .map_err(|_| MigrationError::BackupEvidence)?;
    let max_age =
        i64::try_from(binding.max_age_seconds).map_err(|_| MigrationError::BackupEvidence)?;
    if binding.database_id != current.database_id
        || binding.prior_package_digest != current.package_digest
        || binding.prior_schema_fingerprint != current.schema_fingerprint
        || !Path::new(&binding.backup_file).is_absolute()
        || binding.byte_length == 0
        || binding.max_age_seconds == 0
        || binding.max_age_seconds > MAX_BACKUP_AGE_SECONDS
        || created > now
        || (now - created).whole_seconds() > max_age
    {
        return Err(MigrationError::BackupEvidence);
    }
    Ok(())
}

async fn verify_destructive_backup_evidence(
    plan: Option<&ValidatedReviewedMigrationPlan>,
    current: Option<&ExpectedRegistryIdentity>,
    evidence: &[DestructiveBackupEvidence<'_>],
) -> Result<(Vec<File>, Vec<BackupReference>)> {
    let Some(plan) = plan else {
        return if evidence.is_empty() {
            Ok((Vec::new(), Vec::new()))
        } else {
            Err(MigrationError::BackupEvidence)
        };
    };
    let current = current.ok_or(MigrationError::PackageBinding)?;
    let required = required_backup_binding_paths(plan);
    let paired = pair_backup_evidence(&required, evidence)?;

    let mut retained = Vec::with_capacity(paired.len());
    let mut references = Vec::with_capacity(paired.len());
    for (binding_path, local_path) in required.into_iter().zip(paired) {
        let binding = read_backup_binding(local_path)?;
        check_backup_binding(&binding, current, OffsetDateTime::now_utc())?;
        references.push(BackupReference {
            binding_path: binding_path.to_owned(),
            backup_file: binding.backup_file.clone(),
            sha256: binding.sha256.clone(),
            byte_length: binding.byte_length,
            created_at: binding.created_at.clone(),
        });
        let path = PathBuf::from(&binding.backup_file);
        retained.push(
            tokio::task::spawn_blocking(move || open_bound_backup(path, &binding))
                .await
                .map_err(|_| MigrationError::BackupEvidence)??,
        );
    }
    Ok((retained, references))
}

#[cfg(unix)]
fn open_bound_backup(path: PathBuf, binding: &ExternalBackupBinding) -> Result<File> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use rustix::fs::{Mode, OFlags};

    let before = std::fs::symlink_metadata(&path).map_err(|_| MigrationError::BackupEvidence)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(MigrationError::BackupEvidence);
    }
    let descriptor = rustix::fs::open(
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| MigrationError::BackupEvidence)?;
    let file = File::from(descriptor);
    let opened = file
        .metadata()
        .map_err(|_| MigrationError::BackupEvidence)?;
    let after = std::fs::symlink_metadata(&path).map_err(|_| MigrationError::BackupEvidence)?;
    if !opened.is_file()
        || after.file_type().is_symlink()
        || !same_backup_file(&before, &opened)
        || !same_backup_file(&opened, &after)
        || opened.uid() != rustix::process::geteuid().as_raw()
        || opened.permissions().mode() & 0o7777 != 0o600
        || opened.nlink() != 1
        || opened.len() != binding.byte_length
    {
        return Err(MigrationError::BackupEvidence);
    }
    verify_backup_digest(file, binding)
}

#[cfg(unix)]
fn same_backup_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(not(unix))]
fn open_bound_backup(_path: PathBuf, _binding: &ExternalBackupBinding) -> Result<File> {
    // The reviewed destructive path requires owner and link-count proofs that
    // this runtime currently obtains only from Unix descriptor metadata.
    Err(MigrationError::BackupEvidence)
}

fn verify_backup_digest(mut file: File, binding: &ExternalBackupBinding) -> Result<File> {
    let mut reader = (&mut file).take(binding.byte_length.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut read = 0_u64;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| MigrationError::BackupEvidence)?;
        if count == 0 {
            break;
        }
        read = read
            .checked_add(u64::try_from(count).map_err(|_| MigrationError::BackupEvidence)?)
            .ok_or(MigrationError::BackupEvidence)?;
        hasher.update(&buffer[..count]);
    }
    let mut checksum = String::from("sha256:");
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        write!(&mut checksum, "{byte:02x}").expect("writing to a String cannot fail");
    }
    if read != binding.byte_length || checksum != binding.sha256 {
        return Err(MigrationError::BackupEvidence);
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::model::{
        CompiledAccessInventory, CompiledActionInventory, CompiledQueryInventory,
        CompiledRouteInventory,
    };
    use crate::package::CompiledRegistryMigrationBaseline;
    use crate::physical_names::PhysicalNameInventory;

    use super::*;

    fn baseline(package_digest: &str, registry_id: &str) -> CompiledRegistryMigrationBaseline {
        CompiledRegistryMigrationBaseline {
            package_digest: package_digest.to_owned(),
            registry_id: registry_id.to_owned(),
            registry_version: "1".to_owned(),
            registry_revision: "ignored-descriptor-revision".to_owned(),
            entities: BTreeMap::new(),
            statistical_datasets: BTreeMap::new(),
            physical_names: PhysicalNameInventory {
                entities: BTreeMap::new(),
            },
            routes: CompiledRouteInventory { routes: Vec::new() },
            access: CompiledAccessInventory {
                entries: Vec::new(),
            },
            queries: CompiledQueryInventory {
                operations: Vec::new(),
            },
            actions: CompiledActionInventory::default(),
            recipients: Default::default(),
        }
    }

    #[test]
    fn verified_predecessor_baseline_overrides_only_matching_target_baseline() {
        let target = baseline("package-a", "registry-a");
        let mut verified = baseline("package-a", "registry-a");
        verified.registry_revision = "verified-effective-model-digest".to_owned();
        assert!(std::ptr::eq(
            bind_predecessor_baseline(Some(&target), Some(&verified))
                .expect("matching baselines bind")
                .expect("baseline is retained"),
            &verified
        ));

        let forged = baseline("package-a", "registry-b");
        assert_eq!(
            bind_predecessor_baseline(Some(&forged), Some(&verified)),
            Err(MigrationError::PackageBinding)
        );
    }

    fn active_identity() -> ExpectedRegistryIdentity {
        ExpectedRegistryIdentity {
            package_id: "registry-a".to_owned(),
            database_id: "database-a".to_owned(),
            package_digest: format!("sha256:{}", "a".repeat(64)),
            activation_id: "3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b".to_owned(),
            schema_fingerprint: format!("sha256:{}", "f".repeat(64)),
        }
    }

    fn backup_binding(database_id: &str) -> ExternalBackupBinding {
        let active = active_identity();
        ExternalBackupBinding {
            database_id: database_id.to_owned(),
            prior_package_digest: active.package_digest,
            prior_schema_fingerprint: active.schema_fingerprint,
            backup_file: "/backups/registry.dump".to_owned(),
            sha256: "sha256:11".to_owned(),
            byte_length: 1,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            max_age_seconds: 3600,
        }
    }

    fn shortly_after_backup() -> OffsetDateTime {
        OffsetDateTime::parse("2026-01-01T00:10:00Z", &Rfc3339).expect("fixed instant parses")
    }

    #[test]
    fn a_backup_binding_of_the_active_database_and_package_is_accepted() {
        assert_eq!(
            check_backup_binding(
                &backup_binding("database-a"),
                &active_identity(),
                shortly_after_backup()
            ),
            Ok(())
        );
    }

    #[test]
    fn a_backup_binding_of_another_database_is_refused() {
        assert_eq!(
            check_backup_binding(
                &backup_binding("database-b"),
                &active_identity(),
                shortly_after_backup()
            ),
            Err(MigrationError::BackupEvidence)
        );
    }

    #[test]
    fn a_backup_binding_of_another_active_package_is_refused() {
        let mut binding = backup_binding("database-a");
        binding.prior_package_digest = format!("sha256:{}", "b".repeat(64));
        assert_eq!(
            check_backup_binding(&binding, &active_identity(), shortly_after_backup()),
            Err(MigrationError::BackupEvidence)
        );
    }

    #[test]
    fn a_stale_or_future_backup_binding_is_refused() {
        let binding = backup_binding("database-a");
        let stale = OffsetDateTime::parse("2026-01-01T02:00:00Z", &Rfc3339).expect("parses");
        let future = OffsetDateTime::parse("2025-12-31T23:00:00Z", &Rfc3339).expect("parses");
        assert_eq!(
            check_backup_binding(&binding, &active_identity(), stale),
            Err(MigrationError::BackupEvidence)
        );
        assert_eq!(
            check_backup_binding(&binding, &active_identity(), future),
            Err(MigrationError::BackupEvidence)
        );
    }

    #[test]
    fn a_backup_binding_naming_a_relative_backup_file_is_refused() {
        let mut binding = backup_binding("database-a");
        binding.backup_file = "registry.dump".to_owned();
        assert_eq!(
            check_backup_binding(&binding, &active_identity(), shortly_after_backup()),
            Err(MigrationError::BackupEvidence)
        );
    }

    #[test]
    fn a_written_backup_binding_reads_back_through_the_shared_reader() {
        let mut binding = backup_binding("database-a");
        binding.sha256 = format!("sha256:{}", "1".repeat(64));
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("backup.json");
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&binding).expect("binding serializes"),
        )
        .expect("binding writes");
        assert_eq!(read_backup_binding(&path), Ok(binding));
    }

    #[test]
    fn a_backup_binding_in_its_previous_spelling_is_refused_with_positioned_diagnostics() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("backup.json");
        let active = active_identity();
        let previous = json!({
            "apiVersion": crate::migration_plan::BACKUP_BINDING_API_VERSION,
            "kind": crate::migration_plan::BACKUP_BINDING_KIND,
            "databaseId": "database-a",
            "priorPackageDigest": active.package_digest,
            "priorSchemaFingerprint": active.schema_fingerprint,
            "backupFile": "/backups/registry.dump",
            "sha256": format!("sha256:{}", "1".repeat(64)),
            "byteLength": 1,
            "createdAt": "2026-01-01T00:00:00Z",
            "maxAgeSeconds": 3600,
        });
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&previous).expect("document serializes"),
        )
        .expect("binding writes");
        let Err(MigrationError::BackupBindingDocument(report)) = read_backup_binding(&path) else {
            panic!("the previous spelling is refused as a document");
        };
        let removed = report
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == "config.removed-key")
            .map(|diagnostic| {
                assert!(
                    diagnostic
                        .source
                        .as_ref()
                        .is_some_and(|source| source.line.is_some()),
                    "{diagnostic:?}"
                );
                diagnostic.path.as_str()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            removed,
            ["/byteLength", "/databaseId", "/maxAgeSeconds", "/sha256"]
        );
        assert!(!format!("{report:?}").contains("database-a"));
    }

    #[test]
    fn backup_evidence_pairs_with_the_binding_path_it_names_in_any_order() {
        let required = [
            "migrations/first/backup.json",
            "migrations/second/backup.json",
        ];
        let first_binding = Path::new("/backups/first.json");
        let second_binding = Path::new("/backups/second.json");
        let reversed = [
            DestructiveBackupEvidence::new("migrations/second/backup.json", second_binding),
            DestructiveBackupEvidence::new("migrations/first/backup.json", first_binding),
        ];
        assert_eq!(
            pair_backup_evidence(&required, &reversed),
            Ok(vec![first_binding, second_binding])
        );
    }

    #[test]
    fn backup_evidence_naming_an_unrequired_binding_path_is_refused() {
        let required = ["migrations/first/backup.json"];
        let misnamed = [DestructiveBackupEvidence::new(
            "migrations/typo/backup.json",
            Path::new("/backups/first.json"),
        )];
        assert_eq!(
            pair_backup_evidence(&required, &misnamed),
            Err(MigrationError::BackupEvidence)
        );
        let duplicated = [
            DestructiveBackupEvidence::new(
                "migrations/first/backup.json",
                Path::new("/backups/first.json"),
            ),
            DestructiveBackupEvidence::new(
                "migrations/first/backup.json",
                Path::new("/backups/second.json"),
            ),
        ];
        assert_eq!(
            pair_backup_evidence(&required, &duplicated),
            Err(MigrationError::BackupEvidence)
        );
        assert!(pair_backup_evidence(&required, &[]).is_err());
    }
}

// SPDX-License-Identifier: Apache-2.0

//! Guarded, expiring external projections, separate from Record custody.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;
use serde_json::Value;
use tokio_postgres::GenericClient;
use uuid::Uuid;

use super::{ExpectedRegistryIdentity, GuardedTransaction, RuntimeRevoke, SqlIdentifier};

pub(crate) const BIND_ONCE_FUNCTION: &str = "registry_internal.bind_external_projection_once(text,uuid,text,text,bigint,bigint,text,text,uuid)";
pub(crate) const MAINTENANCE_FUNCTION:&str="registry_internal.maintain_external_projection_scope(text,text,uuid,text,uuid,text,text,bigint,bigint)";
/// Withdrawal stays with migration authority: the runtime role holds no
/// EXECUTE grant on it, so a compromised runtime cannot purge a scope.
pub(crate) const WITHDRAW_FUNCTION: &str =
    "registry_internal.withdraw_external_projection(text,uuid,text,text)";
/// Exact catalog identities include PostgreSQL argument names and spacing.
/// ACL/install signatures above remain type-only SQL call signatures.
/// Entries are (identity, result type, returns set, security definer, runtime execute).
pub(crate) const MANAGED_FUNCTIONS: &[(&str,&str,bool,bool,bool)] = &[
    ("registry_internal.allocate_external_projection_refresh(p_projection text, p_epoch uuid, p_binding text, p_grant text, p_subject text)","bigint",false,true,true),
    ("registry_internal.publish_external_projection(p_projection text, p_epoch uuid, p_binding text, p_grant text, p_sequence bigint, p_subject text, p_snapshot text, p_observed bigint, p_expires bigint, p_purge bigint, p_kind text, p_rows jsonb)","text",false,true,true),
    ("registry_internal.fail_external_projection_refresh(p_projection text, p_epoch uuid, p_sequence bigint, p_subject text, p_reason text)","boolean",false,true,true),
    ("registry_internal.withdraw_external_projection(p_projection text, p_epoch uuid, p_binding text, p_grant text)","boolean",false,true,false),
    ("registry_internal.purge_external_projections(p_limit integer)","record",true,true,true),
    ("registry_internal.lock_external_projection_generation(p_projection text, p_epoch uuid, p_binding text, p_grant text)","bigint",false,true,true),
    ("registry_internal.bind_external_projection_once(p_projection text, p_epoch uuid, p_binding text, p_grant text, p_ttl bigint, p_retention bigint, p_contract text, p_package text, p_activation uuid)","uuid",false,true,true),
    ("registry_internal.maintain_external_projection_scope(p_action text, p_projection text, p_epoch uuid, p_package text, p_activation uuid, p_binding text, p_grant text, p_ttl bigint, p_retention bigint)","jsonb",false,false,false),
];

pub(crate) const INDEXES: &[&str] = &[
    "registry_internal.registry_external_projection_expiry_idx",
    "registry_internal.registry_external_projection_refresh_expiry_idx",
    "registry_internal.registry_external_projection_refresh_subject_idx",
    "registry_internal.registry_external_projection_allocated_idx",
];

pub(crate) fn enabled(registry: &crate::model::CompiledRegistry) -> bool {
    registry
        .external_views()
        .projections
        .values()
        .any(|projection| projection.mode == crate::external_views::ExternalProjectionMode::Indexed)
}

/// Scope identity includes the reviewed external inventory, so changing a hop,
/// field, grant or eligible acquisition path invalidates retained associations.
pub(crate) fn scope_contract_digest(
    registry: &crate::model::CompiledRegistry,
    projection_id: &str,
) -> Result<String, ProjectionError> {
    let projection = registry
        .external_views()
        .projections
        .get(projection_id)
        .ok_or(ProjectionError::InvalidScope)?;
    let value = serde_json::to_value((registry.external_views(), projection))
        .map_err(|_| ProjectionError::InvalidScope)?;
    let canonical = registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| ProjectionError::InvalidScope)?;
    Ok(registry_platform_config::sha256_uri(&canonical))
}

/// Migration-only reconciliation under the existing exclusive package guard.
/// Featureless registries install no store. Removing the feature removes only
/// its rebuildable cache and fixed runtime authority in the same transaction.
pub(crate) async fn reconcile(
    migration: &impl GenericClient,
    registry: &crate::model::CompiledRegistry,
    runtime_role: &SqlIdentifier,
) -> Result<(), ProjectionError> {
    if !enabled(registry) {
        let exists: bool=migration.query_one("SELECT to_regclass('registry_internal.registry_external_projection_scopes') IS NOT NULL",&[]).await.map_err(|_|ProjectionError::Unavailable)?.get(0);
        if exists {
            for function in RUNTIME_FUNCTIONS.iter().copied().chain([
                WITHDRAW_FUNCTION,
                BIND_ONCE_FUNCTION,
                MAINTENANCE_FUNCTION,
            ]) {
                migration
                    .batch_execute(&format!("DROP FUNCTION IF EXISTS {function};"))
                    .await
                    .map_err(|_| ProjectionError::Unavailable)?;
            }
            for table in [VALUES_TABLE, SNAPSHOTS_TABLE, REFRESHES_TABLE, SCOPES_TABLE] {
                migration
                    .batch_execute(&format!("DROP TABLE {table};"))
                    .await
                    .map_err(|_| ProjectionError::Unavailable)?;
            }
        }
        return Ok(());
    }
    install(migration, runtime_role).await?;
    let mut allowlist = serde_json::Map::new();
    for (id, projection) in &registry.external_views().projections {
        if projection.mode != crate::external_views::ExternalProjectionMode::Indexed {
            continue;
        }
        let ttl = projection
            .cache_ttl_seconds
            .ok_or(ProjectionError::InvalidScope)?;
        allowlist.insert(
            id.clone(),
            serde_json::json!({"contract":scope_contract_digest(registry,id)?,"ttl":ttl}),
        );
    }
    let allowed = Value::Object(allowlist);
    // Source facts never enter this generated function. Its fixed allowlist is
    // part of the managed catalog fingerprint and survives a data-only restore.
    let declaration = format!("'{}'::jsonb", allowed.to_string().replace('\'', "''"));
    let sql = BIND_ONCE_SQL.replace("__COMPILED_EXTERNAL_ALLOWLIST__", &declaration);
    migration
        .batch_execute(&sql)
        .await
        .map_err(|_| ProjectionError::Unavailable)?;
    let lock_key = super::RegistryLockKey::derive(registry.registry_id())
        .map_err(|_| ProjectionError::InvalidScope)?
        .get();
    let maintenance = MAINTENANCE_SQL
        .replace("__COMPILED_EXTERNAL_ALLOWLIST__", &declaration)
        .replace("__COMPILED_REGISTRY_LOCK__", &lock_key.to_string());
    migration
        .batch_execute(&maintenance)
        .await
        .map_err(|_| ProjectionError::Unavailable)?;
    let revoke = RuntimeRevoke::detect(migration, runtime_role)
        .await
        .map_err(|_| ProjectionError::Unavailable)?
        .with_public();
    migration.batch_execute(&format!("REVOKE ALL ON FUNCTION {BIND_ONCE_FUNCTION} FROM {revoke}; GRANT EXECUTE ON FUNCTION {BIND_ONCE_FUNCTION} TO {};",runtime_role.quoted())).await.map_err(|_|ProjectionError::Unavailable)?;
    migration
        .batch_execute(&format!(
            "REVOKE ALL ON FUNCTION {MAINTENANCE_FUNCTION} FROM {revoke};"
        ))
        .await
        .map_err(|_| ProjectionError::Unavailable)?;
    let ids = allowed
        .as_object()
        .ok_or(ProjectionError::InvalidScope)?
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    for table in [SNAPSHOTS_TABLE, REFRESHES_TABLE, SCOPES_TABLE] {
        migration
            .execute(
                &format!("DELETE FROM {table} WHERE NOT (projection_id=ANY($1::text[]))"),
                &[&ids],
            )
            .await
            .map_err(|_| ProjectionError::Unavailable)?;
    }
    for (id, entry) in allowed.as_object().ok_or(ProjectionError::InvalidScope)? {
        let contract = entry["contract"]
            .as_str()
            .ok_or(ProjectionError::InvalidScope)?;
        migration
            .execute(
                "UPDATE registry_internal.registry_external_projection_scopes
             SET contract_digest=$2,epoch='00000000-0000-0000-0000-000000000000'::uuid,
                 binding_digest='',grant_digest='',active=false,generation=generation+1
             WHERE projection_id=$1 AND contract_digest<>$2",
                &[&id, &contract],
            )
            .await
            .map_err(|_| ProjectionError::Unavailable)?;
    }
    Ok(())
}

/// Initialize only a migration-allowlisted empty slot under the exact active
/// package. Same bindings reuse their stored epoch; withdrawal or mismatched
/// bindings require explicit migration authority and cannot reactivate here.
pub(crate) async fn bind_initial_scope(
    transaction: &GuardedTransaction<'_>,
    registry: &crate::model::CompiledRegistry,
    expected: &ExpectedRegistryIdentity,
    requested: &ProjectionScope,
) -> Result<ProjectionScope, ProjectionError> {
    let contract = scope_contract_digest(registry, &requested.projection_id)?;
    let activation =
        Uuid::parse_str(&expected.activation_id).map_err(|_| ProjectionError::InvalidScope)?;
    let row = transaction
        .transaction()
        .query_one(
            "SELECT registry_internal.bind_external_projection_once($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[
                &requested.projection_id,
                &requested.epoch,
                &requested.binding_digest,
                &requested.grant_digest,
                &requested.cache_ttl_seconds,
                &requested.retention_seconds,
                &contract,
                &expected.package_digest,
                &activation,
            ],
        )
        .await
        .map_err(|_| ProjectionError::Unavailable)?;
    let epoch = row
        .get::<_, Option<Uuid>>(0)
        .ok_or(ProjectionError::ScopeChanged)?;
    Ok(ProjectionScope {
        epoch,
        ..requested.clone()
    })
}

const MAX_ROWS: usize = 10_000;
const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_KEY_BYTES: usize = 1024;

/// These tables are rebuildable, and must all be excluded from backups.
/// Restore provisioning installs empty tables before a current grant can
/// reacquire data. Restoring an old scope or refresh receipt is unsupported.
pub(crate) const BACKUP_EXCLUDED_TABLES: &[&str] = &[
    "registry_internal.registry_external_projection_scopes",
    "registry_internal.registry_external_projection_refreshes",
    "registry_internal.registry_external_projection_snapshots",
    "registry_internal.registry_external_projection_values",
];

pub(crate) const SCOPES_TABLE: &str = BACKUP_EXCLUDED_TABLES[0];
pub(crate) const REFRESHES_TABLE: &str = BACKUP_EXCLUDED_TABLES[1];
pub(crate) const SNAPSHOTS_TABLE: &str = BACKUP_EXCLUDED_TABLES[2];
pub(crate) const VALUES_TABLE: &str = BACKUP_EXCLUDED_TABLES[3];

pub(crate) const RUNTIME_FUNCTIONS: &[&str] = &[
    "registry_internal.allocate_external_projection_refresh(text,uuid,text,text,text)",
    "registry_internal.publish_external_projection(text,uuid,text,text,bigint,text,text,bigint,bigint,bigint,text,jsonb)",
    "registry_internal.fail_external_projection_refresh(text,uuid,bigint,text,text)",
    "registry_internal.purge_external_projections(integer)",
    "registry_internal.lock_external_projection_generation(text,uuid,text,text)",
];

/// Errors are deliberately closed and value-free, including database failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProjectionError {
    #[error("indexed external projections require separate migration and runtime database roles")]
    RoleSeparationRequired,
    #[error("external projection scope is invalid")]
    InvalidScope,
    #[error("external projection snapshot is invalid")]
    InvalidSnapshot,
    #[error("external projection retention is not permitted")]
    RetentionRefused,
    #[error("external projection scope is no longer active")]
    ScopeChanged,
    #[error("external projection refresh is stale or unavailable")]
    StaleRefresh,
    #[error("external projection store is unavailable")]
    Unavailable,
}

pub(crate) fn kernel_error(error: ProjectionError) -> super::PostgresKernelError {
    match error {
        ProjectionError::RoleSeparationRequired => super::PostgresKernelError::Configuration(
            "indexed external projections require separate migration and runtime database roles",
        ),
        _ => super::PostgresKernelError::Connection,
    }
}

/// Current deployment authority. An epoch is never reused after withdrawal or
/// a changed source grant, binding, acquisition scope, or retention policy.
#[derive(Clone)]
pub(crate) struct ProjectionScope {
    pub(crate) projection_id: String,
    pub(crate) epoch: Uuid,
    pub(crate) binding_digest: String,
    pub(crate) grant_digest: String,
    pub(crate) cache_ttl_seconds: i64,
    /// Maximum retention from snapshot time, not extra time after expiry.
    pub(crate) retention_seconds: i64,
}

impl fmt::Debug for ProjectionScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProjectionScope(<redacted>)")
    }
}

impl ProjectionScope {
    pub(crate) fn new(
        projection_id: &str,
        epoch: Uuid,
        binding_digest: &str,
        grant_digest: &str,
        cache_ttl_seconds: i64,
        retention_seconds: i64,
    ) -> Result<Self, ProjectionError> {
        if !valid_key(projection_id)
            || !valid_key(binding_digest)
            || !valid_key(grant_digest)
            || cache_ttl_seconds < 1
            || retention_seconds < cache_ttl_seconds
            || retention_seconds > 31_536_000
        {
            return Err(ProjectionError::InvalidScope);
        }
        Ok(Self {
            projection_id: projection_id.to_owned(),
            epoch,
            binding_digest: binding_digest.to_owned(),
            grant_digest: grant_digest.to_owned(),
            cache_ttl_seconds,
            retention_seconds,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetentionPermission {
    // Retain an explicit refusal variant even though the source adapter also rejects it.
    #[allow(dead_code)]
    NoStore,
    /// Source-approved absolute last retention time, as Unix seconds.
    PermittedUntil(i64),
}

#[derive(Clone, Serialize)]
pub(crate) struct ProjectionRow {
    source_key: String,
    fields: Value,
}

impl fmt::Debug for ProjectionRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProjectionRow(<redacted>)")
    }
}

impl ProjectionRow {
    /// Call only after the source contract validates the approved field names,
    /// field types, classification ceiling and requested-key binding.
    pub(crate) fn new(source_key: &str, fields: Value) -> Result<Self, ProjectionError> {
        if !valid_key(source_key) || fields.as_object().is_none_or(|fields| fields.len() > 256) {
            return Err(ProjectionError::InvalidSnapshot);
        }
        Ok(Self {
            source_key: source_key.to_owned(),
            fields,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotKind {
    One,
    Absent,
    CompleteCollection,
}

impl SnapshotKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::One => "one",
            Self::Absent => "absent",
            Self::CompleteCollection => "complete-collection",
        }
    }
}

/// A source-contract-validated complete snapshot. There is deliberately no
/// constructor for denied, ambiguous, failed, or partial source outcomes.
pub(crate) struct AcceptedSnapshot {
    subject_key: String,
    snapshot_id: String,
    observed_at: i64,
    source_expires_at: i64,
    retain_until: i64,
    kind: SnapshotKind,
    rows: Vec<ProjectionRow>,
}

impl fmt::Debug for AcceptedSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AcceptedSnapshot(<redacted>)")
    }
}

impl AcceptedSnapshot {
    pub(crate) fn one(
        subject_key: &str,
        snapshot_id: &str,
        observed_at: i64,
        source_expires_at: i64,
        retention: RetentionPermission,
        row: ProjectionRow,
    ) -> Result<Self, ProjectionError> {
        if row.source_key != subject_key {
            return Err(ProjectionError::InvalidSnapshot);
        }
        Self::accepted(
            subject_key,
            snapshot_id,
            observed_at,
            source_expires_at,
            retention,
            SnapshotKind::One,
            vec![row],
        )
    }

    /// Only an authoritative, disclosure-permitted absence reaches this
    /// constructor. A source's protected-existence response never does.
    pub(crate) fn authorized_absence(
        subject_key: &str,
        snapshot_id: &str,
        observed_at: i64,
        source_expires_at: i64,
        retention: RetentionPermission,
    ) -> Result<Self, ProjectionError> {
        Self::accepted(
            subject_key,
            snapshot_id,
            observed_at,
            source_expires_at,
            retention,
            SnapshotKind::Absent,
            vec![],
        )
    }

    /// The caller has verified every bounded page and the final completeness
    /// marker for this exact parent. Empty membership is an accepted snapshot.
    pub(crate) fn complete_collection(
        subject_key: &str,
        snapshot_id: &str,
        observed_at: i64,
        source_expires_at: i64,
        retention: RetentionPermission,
        rows: Vec<ProjectionRow>,
    ) -> Result<Self, ProjectionError> {
        Self::accepted(
            subject_key,
            snapshot_id,
            observed_at,
            source_expires_at,
            retention,
            SnapshotKind::CompleteCollection,
            rows,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn accepted(
        subject_key: &str,
        snapshot_id: &str,
        observed_at: i64,
        source_expires_at: i64,
        retention: RetentionPermission,
        kind: SnapshotKind,
        mut rows: Vec<ProjectionRow>,
    ) -> Result<Self, ProjectionError> {
        let RetentionPermission::PermittedUntil(retain_until) = retention else {
            return Err(ProjectionError::RetentionRefused);
        };
        if retain_until < source_expires_at {
            return Err(ProjectionError::RetentionRefused);
        }
        if !valid_key(subject_key)
            || !valid_key(snapshot_id)
            || observed_at < 0
            || source_expires_at <= observed_at
            || rows.len() > MAX_ROWS
            || rows
                .iter()
                .map(|row| &row.source_key)
                .collect::<BTreeSet<_>>()
                .len()
                != rows.len()
        {
            return Err(ProjectionError::InvalidSnapshot);
        }
        rows.sort_by(|a, b| a.source_key.cmp(&b.source_key));
        if serde_json::to_vec(&rows)
            .map_err(|_| ProjectionError::InvalidSnapshot)?
            .len()
            > MAX_BYTES
        {
            return Err(ProjectionError::InvalidSnapshot);
        }
        Ok(Self {
            subject_key: subject_key.to_owned(),
            snapshot_id: snapshot_id.to_owned(),
            observed_at,
            source_expires_at,
            retain_until,
            kind,
            rows,
        })
    }

    fn bounds(&self, scope: &ProjectionScope) -> Result<(i64, i64), ProjectionError> {
        let expires_at = self
            .observed_at
            .checked_add(scope.cache_ttl_seconds)
            .ok_or(ProjectionError::InvalidSnapshot)?
            .min(self.source_expires_at);
        let purge_at = self
            .observed_at
            .checked_add(scope.retention_seconds)
            .ok_or(ProjectionError::InvalidSnapshot)?
            .min(self.retain_until);
        Ok((expires_at, purge_at))
    }
}

pub(crate) struct RefreshTicket {
    scope: ProjectionScope,
    subject_key: String,
    sequence: i64,
}

impl fmt::Debug for RefreshTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RefreshTicket(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Publication {
    Ineligible,
    Published,
    Replay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProjectionGeneration {
    pub(crate) epoch: Uuid,
    pub(crate) generation: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefreshFailure {
    Abandoned,
    Unavailable,
    Denied,
    Incomplete,
    InvalidBinding,
    RetentionRefused,
}

impl RefreshFailure {
    fn as_str(self) -> &'static str {
        match self {
            Self::Abandoned => "abandoned",
            Self::Unavailable => "unavailable",
            Self::Denied => "denied",
            Self::Incomplete => "incomplete",
            Self::InvalidBinding => "invalid-binding",
            Self::RetentionRefused => "retention-refused",
        }
    }
}

fn valid_key(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_KEY_BYTES && !value.chars().any(char::is_control)
}

/// Called only by the verified migration role. The runtime has SELECT and
/// fixed-function EXECUTE privileges, never direct projection-table DML.
pub(crate) async fn install(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), ProjectionError> {
    let migration_role: String = migration
        .query_one("SELECT current_user", &[])
        .await
        .map_err(|_| ProjectionError::Unavailable)?
        .get(0);
    if migration_role == runtime_role.as_str() {
        return Err(ProjectionError::RoleSeparationRequired);
    }
    migration
        .batch_execute(INSTALL_SQL)
        .await
        .map_err(|_| ProjectionError::Unavailable)?;
    migration
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_internal TO {};",
            runtime_role.quoted()
        ))
        .await
        .map_err(|_| ProjectionError::Unavailable)?;
    let revoke = RuntimeRevoke::detect(migration, runtime_role)
        .await
        .map_err(|_| ProjectionError::Unavailable)?
        .with_public();
    for table in BACKUP_EXCLUDED_TABLES {
        migration
            .batch_execute(&format!(
                "REVOKE ALL ON TABLE {table} FROM {revoke}; GRANT SELECT ON TABLE {table} TO {};",
                runtime_role.quoted()
            ))
            .await
            .map_err(|_| ProjectionError::Unavailable)?;
    }
    for function in RUNTIME_FUNCTIONS {
        migration.batch_execute(&format!("REVOKE ALL ON FUNCTION {function} FROM {revoke}; GRANT EXECUTE ON FUNCTION {function} TO {};", runtime_role.quoted())).await.map_err(|_| ProjectionError::Unavailable)?;
    }
    migration
        .batch_execute(&format!(
            "REVOKE ALL ON FUNCTION {WITHDRAW_FUNCTION} FROM {revoke};"
        ))
        .await
        .map_err(|_| ProjectionError::Unavailable)?;
    Ok(())
}

/// Apply only under the migration/package guard. A withdrawn epoch cannot be
/// reactivated; recovery requires a fresh epoch and authorized acquisition.
#[cfg(all(test, feature = "postgres-test"))]
pub(crate) async fn configure_scope(
    migration: &impl GenericClient,
    scope: &ProjectionScope,
) -> Result<(), ProjectionError> {
    let changed = migration.execute(
        "INSERT INTO registry_internal.registry_external_projection_scopes
            (projection_id,epoch,binding_digest,grant_digest,cache_ttl_seconds,retention_seconds)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (projection_id) DO UPDATE SET
            epoch=EXCLUDED.epoch,binding_digest=EXCLUDED.binding_digest,grant_digest=EXCLUDED.grant_digest,
            cache_ttl_seconds=EXCLUDED.cache_ttl_seconds,retention_seconds=EXCLUDED.retention_seconds,
            active=true,generation=registry_internal.registry_external_projection_scopes.generation +
                CASE WHEN registry_internal.registry_external_projection_scopes.epoch=EXCLUDED.epoch THEN 0 ELSE 1 END
         WHERE registry_internal.registry_external_projection_scopes.epoch <> EXCLUDED.epoch
            OR (registry_internal.registry_external_projection_scopes.active
                AND registry_internal.registry_external_projection_scopes.binding_digest=EXCLUDED.binding_digest
                AND registry_internal.registry_external_projection_scopes.grant_digest=EXCLUDED.grant_digest
                AND registry_internal.registry_external_projection_scopes.cache_ttl_seconds=EXCLUDED.cache_ttl_seconds
                AND registry_internal.registry_external_projection_scopes.retention_seconds=EXCLUDED.retention_seconds)",
        &[&scope.projection_id,&scope.epoch,&scope.binding_digest,&scope.grant_digest,&scope.cache_ttl_seconds,&scope.retention_seconds],
    ).await.map_err(|_| ProjectionError::Unavailable)?;
    if changed != 1 {
        return Err(ProjectionError::ScopeChanged);
    }
    Ok(())
}

pub(crate) async fn allocate_refresh(
    transaction: &GuardedTransaction<'_>,
    scope: &ProjectionScope,
    subject_key: &str,
) -> Result<RefreshTicket, ProjectionError> {
    allocate_inner(transaction.transaction(), scope, subject_key).await
}

/// Read the operator-provisioned binding after the ordinary exact-package
/// guard. A runtime cannot create or rotate scope authority through this API.
pub(crate) async fn load_active_scope(
    transaction: &GuardedTransaction<'_>,
    projection_id: &str,
    binding_digest: &str,
    grant_digest: &str,
) -> Result<ProjectionScope, ProjectionError> {
    let row = transaction
        .transaction()
        .query_opt(
            "SELECT epoch,cache_ttl_seconds,retention_seconds
         FROM registry_internal.registry_external_projection_scopes
         WHERE projection_id=$1 AND binding_digest=$2 AND grant_digest=$3 AND active",
            &[&projection_id, &binding_digest, &grant_digest],
        )
        .await
        .map_err(|_| ProjectionError::Unavailable)?
        .ok_or(ProjectionError::ScopeChanged)?;
    ProjectionScope::new(
        projection_id,
        row.get(0),
        binding_digest,
        grant_digest,
        row.get(1),
        row.get(2),
    )
}

/// Capture once at the beginning of a sweep, then bind this sequence into its
/// continuation. A separate manual sweep gets a fresh acquisition baseline.
pub(crate) async fn next_refresh_sequence(
    transaction: &GuardedTransaction<'_>,
    scope: &ProjectionScope,
) -> Result<i64, ProjectionError> {
    let row = transaction
        .transaction()
        .query_opt(
            "SELECT next_sequence+1 FROM registry_internal.registry_external_projection_scopes
         WHERE projection_id=$1 AND epoch=$2 AND binding_digest=$3 AND grant_digest=$4 AND active",
            &[
                &scope.projection_id,
                &scope.epoch,
                &scope.binding_digest,
                &scope.grant_digest,
            ],
        )
        .await
        .map_err(|_| ProjectionError::Unavailable)?
        .ok_or(ProjectionError::ScopeChanged)?;
    Ok(row.get(0))
}

/// One active-scope-bound lookup for a bounded root page. Source keys are
/// parameters and never enter SQL diagnostics; duplicates are returned once.
pub(crate) async fn refresh_due_keys(
    transaction: &GuardedTransaction<'_>,
    scope: &ProjectionScope,
    subject_keys: &[String],
    minimum_sequence: i64,
    now: i64,
) -> Result<BTreeSet<String>, ProjectionError> {
    if subject_keys.len() > 1000
        || subject_keys.iter().any(|key| !valid_key(key))
        || now < 0
        || minimum_sequence < 1
    {
        return Err(ProjectionError::InvalidScope);
    }
    let row = transaction
        .transaction()
        .query_one(
            REFRESH_DUE_KEYS_SQL,
            &[
                &scope.projection_id,
                &scope.epoch,
                &scope.binding_digest,
                &scope.grant_digest,
                &subject_keys,
                &now,
                &minimum_sequence,
            ],
        )
        .await
        .map_err(|_| ProjectionError::Unavailable)?;
    if !row.get::<_, bool>(0) {
        return Err(ProjectionError::ScopeChanged);
    }
    Ok(row.get::<_, Vec<String>>(1).into_iter().collect())
}

const REFRESH_DUE_KEYS_SQL: &str = r#"
WITH active_scope AS MATERIALIZED (
    SELECT projection_id,epoch FROM registry_internal.registry_external_projection_scopes
    WHERE projection_id=$1 AND epoch=$2 AND binding_digest=$3 AND grant_digest=$4 AND active
), requested AS (SELECT DISTINCT unnest($5::text[]) AS subject_key), due AS (
    SELECT requested.subject_key FROM requested CROSS JOIN active_scope AS scope
    LEFT JOIN registry_internal.registry_external_projection_snapshots AS snapshot
        ON snapshot.projection_id=scope.projection_id AND snapshot.epoch=scope.epoch AND snapshot.subject_key=requested.subject_key
    WHERE snapshot.subject_key IS NULL OR snapshot.expires_at<=$6 OR snapshot.refresh_sequence<$7
)
SELECT EXISTS(SELECT 1 FROM active_scope),COALESCE((SELECT array_agg(subject_key ORDER BY subject_key COLLATE "C") FROM due),ARRAY[]::text[])
"#;

async fn allocate_inner(
    client: &impl GenericClient,
    scope: &ProjectionScope,
    subject_key: &str,
) -> Result<RefreshTicket, ProjectionError> {
    if !valid_key(subject_key) {
        return Err(ProjectionError::InvalidSnapshot);
    }
    let row = client
        .query_one(
            "SELECT registry_internal.allocate_external_projection_refresh($1,$2,$3,$4,$5)",
            &[
                &scope.projection_id,
                &scope.epoch,
                &scope.binding_digest,
                &scope.grant_digest,
                &subject_key,
            ],
        )
        .await
        .map_err(|_| ProjectionError::Unavailable)?;
    let sequence: Option<i64> = row.get(0);
    Ok(RefreshTicket {
        scope: scope.clone(),
        subject_key: subject_key.to_owned(),
        sequence: sequence.ok_or(ProjectionError::StaleRefresh)?,
    })
}

/// Evaluate only a trusted compiled root-read query in the publication statement.
/// Its parameters are $13::uuid[] for local roots and $6::text for the source key.
/// Ineligibility does not invalidate values shared by other authorized roots.
pub(crate) async fn publish_for_roots(
    transaction: &GuardedTransaction<'_>,
    ticket: &RefreshTicket,
    snapshot: &AcceptedSnapshot,
    eligibility_sql: &str,
    root_ids: &[Uuid],
) -> Result<Publication, ProjectionError> {
    if ticket.subject_key != snapshot.subject_key {
        return Err(ProjectionError::InvalidSnapshot);
    }
    let scope = &ticket.scope;
    let (expires_at, purge_at) = snapshot.bounds(scope)?;
    let rows =
        serde_json::to_value(&snapshot.rows).map_err(|_| ProjectionError::InvalidSnapshot)?;
    let kind = snapshot.kind.as_str();
    let sql = publication_statement(eligibility_sql);
    let result = transaction
        .transaction()
        .query_one(
            &sql,
            &[
                &scope.projection_id,
                &scope.epoch,
                &scope.binding_digest,
                &scope.grant_digest,
                &ticket.sequence,
                &ticket.subject_key,
                &snapshot.snapshot_id,
                &snapshot.observed_at,
                &expires_at,
                &purge_at,
                &kind,
                &rows,
                &root_ids,
            ],
        )
        .await
        .map_err(|_| ProjectionError::Unavailable)?;
    match result.get::<_, String>(0).as_str() {
        "ineligible" => Ok(Publication::Ineligible),
        "published" => Ok(Publication::Published),
        "replay" => Ok(Publication::Replay),
        "scope-changed" => Err(ProjectionError::ScopeChanged),
        _ => Err(ProjectionError::StaleRefresh),
    }
}

pub(super) fn publication_statement(eligibility_sql: &str) -> String {
    format!("SELECT CASE WHEN EXISTS ({eligibility_sql}) THEN registry_internal.publish_external_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ELSE 'ineligible' END")
}

#[cfg(all(test, feature = "postgres-test"))]
async fn publish_inner(
    client: &impl GenericClient,
    ticket: &RefreshTicket,
    snapshot: &AcceptedSnapshot,
) -> Result<Publication, ProjectionError> {
    if ticket.subject_key != snapshot.subject_key {
        return Err(ProjectionError::InvalidSnapshot);
    }
    let scope = &ticket.scope;
    let (expires_at, purge_at) = snapshot.bounds(scope)?;
    let rows =
        serde_json::to_value(&snapshot.rows).map_err(|_| ProjectionError::InvalidSnapshot)?;
    let kind = snapshot.kind.as_str();
    let row = client.query_one("SELECT registry_internal.publish_external_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)", &[&scope.projection_id,&scope.epoch,&scope.binding_digest,&scope.grant_digest,&ticket.sequence,&ticket.subject_key,&snapshot.snapshot_id,&snapshot.observed_at,&expires_at,&purge_at,&kind,&rows]).await.map_err(|_| ProjectionError::Unavailable)?;
    match row.get::<_, String>(0).as_str() {
        "published" => Ok(Publication::Published),
        "replay" => Ok(Publication::Replay),
        "scope-changed" => Err(ProjectionError::ScopeChanged),
        _ => Err(ProjectionError::StaleRefresh),
    }
}

/// The scope row lock fences publication and withdrawal until the caller has
/// checked coverage, selected its page, rechecked expiry and audited release.
/// Query headers and values by this epoch AND current expiry in one statement.
pub(crate) async fn lock_generation(
    transaction: &GuardedTransaction<'_>,
    scope: &ProjectionScope,
) -> Result<ProjectionGeneration, ProjectionError> {
    let row = transaction
        .transaction()
        .query_one(
            "SELECT registry_internal.lock_external_projection_generation($1,$2,$3,$4)",
            &[
                &scope.projection_id,
                &scope.epoch,
                &scope.binding_digest,
                &scope.grant_digest,
            ],
        )
        .await
        .map_err(|_| ProjectionError::Unavailable)?;
    let generation = row
        .get::<_, Option<i64>>(0)
        .ok_or(ProjectionError::ScopeChanged)?;
    Ok(ProjectionGeneration {
        epoch: scope.epoch,
        generation,
    })
}

/// Tests withdraw under migration authority; operators use the maintenance
/// function, and the runtime role holds no EXECUTE grant on either.
#[cfg(all(test, feature = "postgres-test"))]
pub(crate) async fn withdraw_scope(
    migration: &impl GenericClient,
    scope: &ProjectionScope,
) -> Result<(), ProjectionError> {
    let row = migration
        .query_one(
            "SELECT registry_internal.withdraw_external_projection($1,$2,$3,$4)",
            &[
                &scope.projection_id,
                &scope.epoch,
                &scope.binding_digest,
                &scope.grant_digest,
            ],
        )
        .await
        .map_err(|_| ProjectionError::Unavailable)?;
    if !row.get::<_, bool>(0) {
        return Err(ProjectionError::ScopeChanged);
    }
    Ok(())
}

/// Exact-key failures invalidate coverage. Generic collection interruption
/// preserves its prior complete snapshot; denial and no-store invalidate both.
pub(crate) async fn fail_refresh(
    transaction: &GuardedTransaction<'_>,
    ticket: &RefreshTicket,
    failure: RefreshFailure,
) -> Result<(), ProjectionError> {
    let row = transaction
        .transaction()
        .query_one(
            "SELECT registry_internal.fail_external_projection_refresh($1,$2,$3,$4,$5)",
            &[
                &ticket.scope.projection_id,
                &ticket.scope.epoch,
                &ticket.sequence,
                &ticket.subject_key,
                &failure.as_str(),
            ],
        )
        .await
        .map_err(|_| ProjectionError::Unavailable)?;
    if !row.get::<_, bool>(0) {
        return Err(ProjectionError::StaleRefresh);
    }
    Ok(())
}

/// Each lane removes at most `limit` rows, with values cascading only from the
/// selected bounded snapshot headers. No expired value is made readable.
pub(crate) async fn purge(
    transaction: &GuardedTransaction<'_>,
    limit: u32,
) -> Result<(u64, u64), ProjectionError> {
    if !(1..=1000).contains(&limit) {
        return Err(ProjectionError::InvalidScope);
    }
    let limit = i32::try_from(limit).map_err(|_| ProjectionError::InvalidScope)?;
    let row = transaction
        .transaction()
        .query_one(
            "SELECT * FROM registry_internal.purge_external_projections($1)",
            &[&limit],
        )
        .await
        .map_err(|_| ProjectionError::Unavailable)?;
    Ok((
        u64::try_from(row.get::<_, i64>(0)).map_err(|_| ProjectionError::Unavailable)?,
        u64::try_from(row.get::<_, i64>(1)).map_err(|_| ProjectionError::Unavailable)?,
    ))
}

pub(crate) const INSTALL_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS registry_internal.registry_external_projection_scopes (
    projection_id text PRIMARY KEY CHECK (octet_length(projection_id) BETWEEN 1 AND 1024),
    contract_digest text NOT NULL DEFAULT '',
    epoch uuid NOT NULL,
    binding_digest text NOT NULL,
    grant_digest text NOT NULL,
    cache_ttl_seconds bigint NOT NULL CHECK (cache_ttl_seconds BETWEEN 1 AND 31536000),
    retention_seconds bigint NOT NULL CHECK (retention_seconds BETWEEN cache_ttl_seconds AND 31536000),
    active boolean NOT NULL DEFAULT true,
    next_sequence bigint NOT NULL DEFAULT 0 CHECK (next_sequence >= 0),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0)
);
CREATE TABLE IF NOT EXISTS registry_internal.registry_external_projection_refreshes (
    projection_id text NOT NULL REFERENCES registry_internal.registry_external_projection_scopes(projection_id),
    sequence bigint NOT NULL CHECK (sequence > 0),
    epoch uuid NOT NULL,
    subject_key text NOT NULL CHECK (octet_length(subject_key) BETWEEN 1 AND 1024),
    started_at bigint NOT NULL,
    lease_expires_at bigint NOT NULL,
    state text NOT NULL CHECK (state IN ('allocated','published','unavailable','denied','incomplete','invalid-binding','retention-refused')),
    PRIMARY KEY (projection_id,sequence)
);
CREATE TABLE IF NOT EXISTS registry_internal.registry_external_projection_snapshots (
    projection_id text NOT NULL REFERENCES registry_internal.registry_external_projection_scopes(projection_id),
    epoch uuid NOT NULL,
    subject_key text NOT NULL CHECK (octet_length(subject_key) BETWEEN 1 AND 1024),
    snapshot_id text NOT NULL CHECK (octet_length(snapshot_id) BETWEEN 1 AND 1024),
    observed_at bigint NOT NULL CHECK (observed_at >= 0),
    expires_at bigint NOT NULL CHECK (expires_at > observed_at),
    purge_at bigint NOT NULL CHECK (purge_at >= expires_at),
    refresh_sequence bigint NOT NULL CHECK (refresh_sequence > 0),
    kind text NOT NULL CHECK (kind IN ('one','absent','complete-collection')),
    PRIMARY KEY (projection_id,epoch,subject_key)
);
CREATE TABLE IF NOT EXISTS registry_internal.registry_external_projection_values (
    projection_id text NOT NULL,
    epoch uuid NOT NULL,
    subject_key text NOT NULL,
    source_key text NOT NULL CHECK (octet_length(source_key) BETWEEN 1 AND 1024),
    fields jsonb NOT NULL CHECK (jsonb_typeof(fields)='object'),
    PRIMARY KEY (projection_id,epoch,subject_key,source_key),
    FOREIGN KEY (projection_id,epoch,subject_key)
        REFERENCES registry_internal.registry_external_projection_snapshots(projection_id,epoch,subject_key) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS registry_external_projection_expiry_idx
    ON registry_internal.registry_external_projection_snapshots(expires_at,projection_id,epoch,subject_key);
CREATE INDEX IF NOT EXISTS registry_external_projection_refresh_expiry_idx
    ON registry_internal.registry_external_projection_refreshes(lease_expires_at,projection_id,sequence);
CREATE INDEX IF NOT EXISTS registry_external_projection_refresh_subject_idx
    ON registry_internal.registry_external_projection_refreshes(projection_id,epoch,subject_key,sequence)
    INCLUDE (state,lease_expires_at);
CREATE INDEX IF NOT EXISTS registry_external_projection_allocated_idx
    ON registry_internal.registry_external_projection_refreshes(projection_id,lease_expires_at)
    WHERE state='allocated';

CREATE OR REPLACE FUNCTION registry_internal.allocate_external_projection_refresh(
    p_projection text,p_epoch uuid,p_binding text,p_grant text,p_subject text
) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, registry_internal AS $body$
DECLARE scope registry_internal.registry_external_projection_scopes; projection_now bigint; allocated bigint;
BEGIN
    projection_now := floor(extract(epoch FROM clock_timestamp()))::bigint;
    SELECT * INTO scope FROM registry_internal.registry_external_projection_scopes
        WHERE projection_id=p_projection FOR UPDATE;
    IF NOT FOUND OR p_epoch IS NULL OR p_binding IS NULL OR p_grant IS NULL OR NOT scope.active OR scope.epoch<>p_epoch
        OR scope.binding_digest<>p_binding OR scope.grant_digest<>p_grant
        OR p_subject IS NULL OR octet_length(p_subject) NOT BETWEEN 1 AND 1024 THEN RETURN NULL; END IF;
    IF (SELECT count(*) FROM registry_internal.registry_external_projection_refreshes
        WHERE projection_id=p_projection AND state='allocated' AND lease_expires_at>projection_now) >= 1024 THEN RETURN NULL; END IF;
    UPDATE registry_internal.registry_external_projection_scopes SET next_sequence=next_sequence+1
        WHERE projection_id=p_projection RETURNING next_sequence INTO allocated;
    INSERT INTO registry_internal.registry_external_projection_refreshes
        (projection_id,sequence,epoch,subject_key,started_at,lease_expires_at,state)
        VALUES (p_projection,allocated,p_epoch,p_subject,projection_now,projection_now+120,'allocated');
    RETURN allocated;
END $body$;

CREATE OR REPLACE FUNCTION registry_internal.publish_external_projection(
    p_projection text,p_epoch uuid,p_binding text,p_grant text,p_sequence bigint,p_subject text,
    p_snapshot text,p_observed bigint,p_expires bigint,p_purge bigint,p_kind text,p_rows jsonb
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, registry_internal AS $body$
DECLARE scope registry_internal.registry_external_projection_scopes;
    attempt registry_internal.registry_external_projection_refreshes;
    previous registry_internal.registry_external_projection_snapshots;
    projection_now bigint; previous_rows jsonb; has_previous boolean;
BEGIN
    projection_now := floor(extract(epoch FROM clock_timestamp()))::bigint;
    SELECT * INTO scope FROM registry_internal.registry_external_projection_scopes
        WHERE projection_id=p_projection FOR UPDATE;
    IF NOT FOUND OR p_epoch IS NULL OR p_binding IS NULL OR p_grant IS NULL OR NOT scope.active OR scope.epoch<>p_epoch
        OR scope.binding_digest<>p_binding OR scope.grant_digest<>p_grant THEN RETURN 'scope-changed'; END IF;
    SELECT * INTO attempt FROM registry_internal.registry_external_projection_refreshes
        WHERE projection_id=p_projection AND sequence=p_sequence AND epoch=p_epoch AND subject_key=p_subject FOR UPDATE;
    IF NOT FOUND OR attempt.state NOT IN ('allocated','published') OR attempt.lease_expires_at<=projection_now THEN RETURN 'stale'; END IF;
    -- Final receipts fence older results even when denial or no-store removed
    -- the snapshot. Scope locking serializes this check with finalization.
    IF EXISTS (SELECT 1 FROM registry_internal.registry_external_projection_refreshes
        WHERE projection_id=p_projection AND epoch=p_epoch AND subject_key=p_subject
            AND sequence>p_sequence AND state<>'allocated') THEN RETURN 'stale'; END IF;
    IF p_snapshot IS NULL OR octet_length(p_snapshot) NOT BETWEEN 1 AND 1024
        OR p_observed IS NULL OR p_observed<0 OR p_observed>projection_now
        OR p_expires IS NULL OR p_expires<=projection_now OR p_expires<=p_observed
        OR p_expires-p_observed>scope.cache_ttl_seconds
        OR p_purge IS NULL OR p_purge<p_expires OR p_purge-p_observed>scope.retention_seconds
        OR p_kind IS NULL OR p_kind NOT IN ('one','absent','complete-collection')
        OR p_rows IS NULL OR jsonb_typeof(p_rows)<>'array'
        OR octet_length(p_rows::text)>2097152 THEN RETURN 'invalid'; END IF;
    IF jsonb_array_length(p_rows)>10000
        OR (p_kind='one' AND jsonb_array_length(p_rows)<>1)
        OR (p_kind='absent' AND jsonb_array_length(p_rows)<>0) THEN RETURN 'invalid'; END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(p_rows) AS r
        WHERE jsonb_typeof(r)<>'object' OR r - 'source_key' - 'fields' <> '{}'::jsonb
            OR jsonb_typeof(r->'source_key') IS DISTINCT FROM 'string'
            OR octet_length(r->>'source_key') NOT BETWEEN 1 AND 1024
            OR jsonb_typeof(r->'fields') IS DISTINCT FROM 'object'
            OR (p_kind='one' AND r->>'source_key'<>p_subject))
        OR (SELECT count(*)<>count(DISTINCT r->>'source_key') FROM jsonb_array_elements(p_rows) AS r)
        THEN RETURN 'invalid'; END IF;
    SELECT * INTO previous FROM registry_internal.registry_external_projection_snapshots
        WHERE projection_id=p_projection AND epoch=p_epoch AND subject_key=p_subject FOR UPDATE;
    has_previous := FOUND;
    IF has_previous AND previous.snapshot_id=p_snapshot THEN
        SELECT COALESCE(jsonb_agg(jsonb_build_object('source_key',source_key,'fields',fields) ORDER BY source_key COLLATE "C"),'[]'::jsonb)
            INTO previous_rows FROM registry_internal.registry_external_projection_values
            WHERE projection_id=p_projection AND epoch=p_epoch AND subject_key=p_subject;
        IF previous.kind<>p_kind OR previous.observed_at<>p_observed OR previous_rows<>p_rows THEN RETURN 'invalid'; END IF;
        IF previous.expires_at<=projection_now THEN RETURN 'stale'; END IF;
        UPDATE registry_internal.registry_external_projection_snapshots
            SET refresh_sequence=greatest(refresh_sequence,p_sequence)
            WHERE projection_id=p_projection AND epoch=p_epoch AND subject_key=p_subject;
        UPDATE registry_internal.registry_external_projection_refreshes SET state='published'
            WHERE projection_id=p_projection AND sequence=p_sequence;
        RETURN 'replay';
    END IF;
    IF attempt.state<>'allocated' OR (has_previous AND
        (previous.refresh_sequence>=p_sequence OR previous.observed_at>p_observed)) THEN RETURN 'stale'; END IF;
    INSERT INTO registry_internal.registry_external_projection_snapshots
        (projection_id,epoch,subject_key,snapshot_id,observed_at,expires_at,purge_at,refresh_sequence,kind)
        VALUES (p_projection,p_epoch,p_subject,p_snapshot,p_observed,p_expires,p_purge,p_sequence,p_kind)
        ON CONFLICT (projection_id,epoch,subject_key) DO UPDATE SET
            snapshot_id=EXCLUDED.snapshot_id,observed_at=EXCLUDED.observed_at,
            expires_at=EXCLUDED.expires_at,purge_at=EXCLUDED.purge_at,
            refresh_sequence=EXCLUDED.refresh_sequence,kind=EXCLUDED.kind;
    DELETE FROM registry_internal.registry_external_projection_values
        WHERE projection_id=p_projection AND epoch=p_epoch AND subject_key=p_subject;
    INSERT INTO registry_internal.registry_external_projection_values
        (projection_id,epoch,subject_key,source_key,fields)
        SELECT p_projection,p_epoch,p_subject,r->>'source_key',r->'fields' FROM jsonb_array_elements(p_rows) AS r;
    UPDATE registry_internal.registry_external_projection_refreshes SET state='published'
        WHERE projection_id=p_projection AND sequence=p_sequence;
    UPDATE registry_internal.registry_external_projection_scopes SET generation=generation+1 WHERE projection_id=p_projection;
    RETURN 'published';
END $body$;

CREATE OR REPLACE FUNCTION registry_internal.fail_external_projection_refresh(
    p_projection text,p_epoch uuid,p_sequence bigint,p_subject text,p_reason text
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, registry_internal AS $body$
DECLARE current_epoch uuid; allocated boolean; removed bigint;
BEGIN
    IF p_reason IS NULL OR p_reason NOT IN ('abandoned','unavailable','denied','incomplete','invalid-binding','retention-refused') THEN RETURN false; END IF;
    SELECT epoch INTO current_epoch FROM registry_internal.registry_external_projection_scopes
        WHERE projection_id=p_projection AND active FOR UPDATE;
    IF NOT FOUND OR p_epoch IS NULL OR current_epoch<>p_epoch THEN RETURN false; END IF;
    IF p_reason='abandoned' THEN
        DELETE FROM registry_internal.registry_external_projection_refreshes
            WHERE projection_id=p_projection AND epoch=p_epoch AND sequence=p_sequence AND subject_key=p_subject AND state='allocated';
        RETURN true;
    END IF;
    SELECT state='allocated' INTO allocated FROM registry_internal.registry_external_projection_refreshes
        WHERE projection_id=p_projection AND epoch=p_epoch AND sequence=p_sequence AND subject_key=p_subject
            AND lease_expires_at>floor(extract(epoch FROM clock_timestamp()))::bigint FOR UPDATE;
    IF NOT FOUND OR NOT allocated THEN RETURN false; END IF;
    IF p_reason IN ('retention-refused','denied','unavailable','incomplete','invalid-binding') THEN
        DELETE FROM registry_internal.registry_external_projection_snapshots
            WHERE projection_id=p_projection AND epoch=p_epoch AND subject_key=p_subject AND refresh_sequence<=p_sequence
                AND (p_reason IN ('retention-refused','denied') OR kind IN ('one','absent'));
        GET DIAGNOSTICS removed=ROW_COUNT;
        IF removed>0 THEN
            UPDATE registry_internal.registry_external_projection_scopes SET generation=generation+1 WHERE projection_id=p_projection;
        END IF;
    END IF;
    UPDATE registry_internal.registry_external_projection_refreshes SET state=p_reason
        WHERE projection_id=p_projection AND epoch=p_epoch AND sequence=p_sequence AND subject_key=p_subject AND state='allocated';
    RETURN FOUND;
END $body$;

CREATE OR REPLACE FUNCTION registry_internal.withdraw_external_projection(
    p_projection text,p_epoch uuid,p_binding text,p_grant text
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, registry_internal AS $body$
BEGIN
    UPDATE registry_internal.registry_external_projection_scopes SET active=false,generation=generation+1
        WHERE projection_id=p_projection AND epoch=p_epoch AND binding_digest=p_binding AND grant_digest=p_grant AND active;
    RETURN FOUND;
END $body$;

CREATE OR REPLACE FUNCTION registry_internal.purge_external_projections(p_limit integer)
RETURNS TABLE (snapshots_pruned bigint,refreshes_pruned bigint) LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, registry_internal AS $body$
DECLARE projection_now bigint;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='external projection purge limit is invalid';
    END IF;
    projection_now := floor(extract(epoch FROM clock_timestamp()))::bigint;
    WITH expired AS MATERIALIZED (
        SELECT o.projection_id,o.epoch,o.subject_key
        FROM registry_internal.registry_external_projection_snapshots AS o
        JOIN registry_internal.registry_external_projection_scopes AS s USING (projection_id)
        WHERE o.expires_at<=projection_now OR o.epoch<>s.epoch OR NOT s.active
        ORDER BY o.expires_at,o.projection_id,o.epoch,o.subject_key LIMIT p_limit FOR UPDATE OF o SKIP LOCKED
    ), removed AS (
        DELETE FROM registry_internal.registry_external_projection_snapshots AS o USING expired AS e
        WHERE o.projection_id=e.projection_id AND o.epoch=e.epoch AND o.subject_key=e.subject_key RETURNING 1
    ) SELECT count(*) INTO snapshots_pruned FROM removed;
    WITH expired AS MATERIALIZED (
        SELECT r.projection_id,r.sequence
        FROM registry_internal.registry_external_projection_refreshes AS r
        JOIN registry_internal.registry_external_projection_scopes AS s USING (projection_id)
        WHERE r.epoch<>s.epoch OR NOT s.active OR (r.lease_expires_at<=projection_now
            AND (r.state='allocated' OR NOT EXISTS (
                SELECT 1 FROM registry_internal.registry_external_projection_refreshes AS earlier
                WHERE earlier.projection_id=r.projection_id AND earlier.epoch=r.epoch
                    AND earlier.subject_key=r.subject_key AND earlier.sequence<r.sequence
                    AND earlier.state IN ('allocated','published') AND earlier.lease_expires_at>projection_now)))
        ORDER BY r.lease_expires_at,r.projection_id,r.sequence LIMIT p_limit FOR UPDATE OF r SKIP LOCKED
    ), removed AS (
        DELETE FROM registry_internal.registry_external_projection_refreshes AS r USING expired AS e
        WHERE r.projection_id=e.projection_id AND r.sequence=e.sequence RETURNING 1
    ) SELECT count(*) INTO refreshes_pruned FROM removed;
    RETURN NEXT;
END $body$;

CREATE OR REPLACE FUNCTION registry_internal.lock_external_projection_generation(
    p_projection text,p_epoch uuid,p_binding text,p_grant text
) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, registry_internal AS $body$
DECLARE result bigint;
BEGIN
    SELECT generation INTO result FROM registry_internal.registry_external_projection_scopes
        WHERE projection_id=p_projection AND epoch=p_epoch AND binding_digest=p_binding AND grant_digest=p_grant AND active
        FOR SHARE;
    RETURN result;
END $body$;
"#;

const MAINTENANCE_SQL: &str = r#"
CREATE OR REPLACE FUNCTION registry_internal.maintain_external_projection_scope(
    p_action text,p_projection text,p_epoch uuid,p_package text,p_activation uuid,
    p_binding text,p_grant text,p_ttl bigint,p_retention bigint
) RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, registry_internal AS $body$
DECLARE allowed jsonb := __COMPILED_EXTERNAL_ALLOWLIST__;
    expected jsonb; scope registry_internal.registry_external_projection_scopes;
    package_digest text; activation_id uuid; current_status text; counters jsonb := '{}'::jsonb;
BEGIN
    IF p_action IS NULL OR p_action NOT IN ('inspect','withdraw','rotate') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='external projection maintenance action is invalid';
    END IF;
    IF p_action='inspect' THEN
        PERFORM pg_advisory_xact_lock_shared(__COMPILED_REGISTRY_LOCK__::bigint);
    ELSE
        PERFORM pg_advisory_xact_lock(__COMPILED_REGISTRY_LOCK__::bigint);
    END IF;
    expected := allowed -> p_projection;
    IF expected IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='external projection is not installed';
    END IF;
    SELECT active_package_digest,active_activation_id,maintenance_status
        INTO package_digest,activation_id,current_status FROM registry_internal.registry_state WHERE singleton;
    IF NOT FOUND OR current_status<>'ready' THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='external projection package is not ready';
    END IF;
    SELECT * INTO scope FROM registry_internal.registry_external_projection_scopes
        WHERE projection_id=p_projection FOR UPDATE;
    IF p_action<>'inspect' THEN
        IF p_package IS DISTINCT FROM package_digest OR p_activation IS DISTINCT FROM activation_id
            OR p_epoch IS DISTINCT FROM scope.epoch THEN
            RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='external projection maintenance identity changed';
        END IF;
        IF p_action='withdraw' THEN
            IF scope.projection_id IS NULL THEN
                RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='external projection scope is not bound';
            END IF;
            UPDATE registry_internal.registry_external_projection_scopes SET active=false,generation=generation+1
                WHERE projection_id=p_projection RETURNING * INTO scope;
        ELSE
            IF p_binding IS NULL OR octet_length(p_binding) NOT BETWEEN 1 AND 1024
                OR p_grant IS NULL OR octet_length(p_grant) NOT BETWEEN 1 AND 1024
                OR p_ttl IS NULL OR p_ttl NOT BETWEEN 1 AND (expected->>'ttl')::bigint
                OR p_retention IS NULL OR p_retention NOT BETWEEN p_ttl AND 31536000 THEN
                RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='external projection maintenance binding is invalid';
            END IF;
            INSERT INTO registry_internal.registry_external_projection_scopes AS current
                (projection_id,contract_digest,epoch,binding_digest,grant_digest,cache_ttl_seconds,retention_seconds)
                VALUES (p_projection,expected->>'contract',gen_random_uuid(),p_binding,p_grant,p_ttl,p_retention)
                ON CONFLICT (projection_id) DO UPDATE SET contract_digest=EXCLUDED.contract_digest,
                    epoch=EXCLUDED.epoch,binding_digest=EXCLUDED.binding_digest,grant_digest=EXCLUDED.grant_digest,
                    cache_ttl_seconds=EXCLUDED.cache_ttl_seconds,retention_seconds=EXCLUDED.retention_seconds,
                    active=true,generation=current.generation+1
                RETURNING * INTO scope;
        END IF;
        DELETE FROM registry_internal.registry_external_projection_snapshots WHERE projection_id=p_projection;
        DELETE FROM registry_internal.registry_external_projection_refreshes WHERE projection_id=p_projection;
    END IF;
    IF p_action='inspect' THEN
        -- These are physical cache/receipt counts, never caller-visible root
        -- readiness. Fixed state names and integers disclose no source values.
        WITH outcomes(state) AS (VALUES ('allocated'),('published'),('unavailable'),('denied'),('incomplete'),('invalid-binding'),('retention-refused')),
        receipts AS (SELECT state,count(*) AS total FROM registry_internal.registry_external_projection_refreshes
            WHERE projection_id=p_projection GROUP BY state),
        snapshots AS (SELECT
            count(*) FILTER (WHERE epoch=scope.epoch AND scope.active AND expires_at>floor(extract(epoch FROM statement_timestamp()))::bigint) AS fresh,
            count(*) FILTER (WHERE expires_at<=floor(extract(epoch FROM statement_timestamp()))::bigint) AS expired,
            count(*) FILTER (WHERE (epoch<>scope.epoch OR NOT scope.active) AND expires_at>floor(extract(epoch FROM statement_timestamp()))::bigint) AS invalidated
            FROM registry_internal.registry_external_projection_snapshots WHERE projection_id=p_projection)
        SELECT jsonb_build_object('refreshCounts',(SELECT jsonb_object_agg(outcomes.state,COALESCE(receipts.total,0)) FROM outcomes LEFT JOIN receipts USING (state)),
            'snapshotCounts',jsonb_build_object('fresh',fresh,'expired',expired,'invalidated',invalidated)) INTO counters FROM snapshots;
    END IF;
    RETURN jsonb_build_object('projection',p_projection,'epoch',scope.epoch,'active',COALESCE(scope.active,false),
        'bindingDigest',scope.binding_digest,'grantDigest',scope.grant_digest,'cacheTtlSeconds',scope.cache_ttl_seconds,
        'retentionSeconds',scope.retention_seconds,'packageDigest',package_digest,'activationId',activation_id) || counters;
END $body$;
"#;

const BIND_ONCE_SQL: &str = r#"
CREATE OR REPLACE FUNCTION registry_internal.bind_external_projection_once(
    p_projection text,p_epoch uuid,p_binding text,p_grant text,p_ttl bigint,p_retention bigint,
    p_contract text,p_package text,p_activation uuid
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, registry_internal AS $body$
DECLARE allowed jsonb := __COMPILED_EXTERNAL_ALLOWLIST__;
    expected jsonb; scope registry_internal.registry_external_projection_scopes;
BEGIN
    expected := allowed -> p_projection;
    IF expected IS NULL OR p_contract IS NULL OR expected->>'contract'<>p_contract
        OR p_epoch IS NULL OR p_epoch='00000000-0000-0000-0000-000000000000'::uuid
        OR p_binding IS NULL OR octet_length(p_binding) NOT BETWEEN 1 AND 1024
        OR p_grant IS NULL OR octet_length(p_grant) NOT BETWEEN 1 AND 1024
        OR p_ttl IS NULL OR p_ttl NOT BETWEEN 1 AND (expected->>'ttl')::bigint
        OR p_retention IS NULL OR p_retention NOT BETWEEN p_ttl AND 31536000
        OR p_package IS NULL OR p_activation IS NULL THEN RETURN NULL; END IF;
    IF NOT EXISTS (SELECT 1 FROM registry_internal.registry_state WHERE singleton
        AND active_package_digest=p_package AND active_activation_id=p_activation AND maintenance_status='ready') THEN RETURN NULL; END IF;
    INSERT INTO registry_internal.registry_external_projection_scopes
        (projection_id,contract_digest,epoch,binding_digest,grant_digest,cache_ttl_seconds,retention_seconds)
        VALUES (p_projection,p_contract,p_epoch,p_binding,p_grant,p_ttl,p_retention)
        ON CONFLICT (projection_id) DO NOTHING;
    SELECT * INTO scope FROM registry_internal.registry_external_projection_scopes WHERE projection_id=p_projection FOR UPDATE;
    IF scope.active AND scope.contract_digest=p_contract AND scope.binding_digest=p_binding AND scope.grant_digest=p_grant
        AND scope.cache_ttl_seconds=p_ttl AND scope.retention_seconds=p_retention THEN RETURN scope.epoch; END IF;
    IF NOT scope.active AND scope.epoch='00000000-0000-0000-0000-000000000000'::uuid
        AND scope.binding_digest='' AND scope.grant_digest='' AND scope.contract_digest=p_contract THEN
        UPDATE registry_internal.registry_external_projection_scopes
            SET epoch=p_epoch,binding_digest=p_binding,grant_digest=p_grant,cache_ttl_seconds=p_ttl,retention_seconds=p_retention,active=true,generation=generation+1
            WHERE projection_id=p_projection;
        RETURN p_epoch;
    END IF;
    RETURN NULL;
END $body$;
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scope() -> ProjectionScope {
        ProjectionScope::new(
            "people",
            Uuid::nil(),
            "sha256:binding",
            "sha256:grant",
            60,
            120,
        )
        .unwrap()
    }

    fn row(key: &str) -> ProjectionRow {
        ProjectionRow::new(key, json!({"label":"PRIVATE_SOURCE_CANARY"})).unwrap()
    }

    #[test]
    fn no_store_and_unbounded_retention_are_refused() {
        assert_eq!(
            AcceptedSnapshot::one(
                "key",
                "snapshot",
                100,
                160,
                RetentionPermission::NoStore,
                row("key")
            )
            .unwrap_err(),
            ProjectionError::RetentionRefused
        );
        assert!(ProjectionScope::new("people", Uuid::nil(), "binding", "grant", 60, 59).is_err());
        let snapshot = AcceptedSnapshot::one(
            "key",
            "snapshot",
            100,
            160,
            RetentionPermission::PermittedUntil(150),
            row("key"),
        );
        assert_eq!(snapshot.unwrap_err(), ProjectionError::RetentionRefused);
    }

    #[test]
    fn exact_identity_and_complete_collection_membership_are_bounded() {
        assert_eq!(
            AcceptedSnapshot::one(
                "key",
                "snapshot",
                100,
                160,
                RetentionPermission::PermittedUntil(220),
                row("other")
            )
            .unwrap_err(),
            ProjectionError::InvalidSnapshot
        );
        assert!(AcceptedSnapshot::complete_collection(
            "parent",
            "snapshot",
            100,
            160,
            RetentionPermission::PermittedUntil(220),
            vec![row("same"), row("same")]
        )
        .is_err());
        let empty = AcceptedSnapshot::complete_collection(
            "parent",
            "snapshot",
            100,
            160,
            RetentionPermission::PermittedUntil(220),
            vec![],
        )
        .unwrap();
        assert_eq!(empty.kind, SnapshotKind::CompleteCollection);
        let absent = AcceptedSnapshot::authorized_absence(
            "key",
            "snapshot",
            100,
            160,
            RetentionPermission::PermittedUntil(220),
        )
        .unwrap();
        assert_eq!(absent.kind, SnapshotKind::Absent);
    }

    #[test]
    fn original_snapshot_bounds_expiry_and_purge() {
        let accepted = AcceptedSnapshot::one(
            "key",
            "snapshot",
            100,
            300,
            RetentionPermission::PermittedUntil(400),
            row("key"),
        )
        .unwrap();
        assert_eq!(accepted.bounds(&scope()).unwrap(), (160, 220));
        let accepted = AcceptedSnapshot::one(
            "key",
            "snapshot",
            100,
            150,
            RetentionPermission::PermittedUntil(180),
            row("key"),
        )
        .unwrap();
        assert_eq!(accepted.bounds(&scope()).unwrap(), (150, 180));
    }

    #[test]
    fn source_values_and_keys_are_redacted_in_debug() {
        let accepted = AcceptedSnapshot::one(
            "PRIVATE_KEY_CANARY",
            "PRIVATE_OBSERVATION_CANARY",
            100,
            160,
            RetentionPermission::PermittedUntil(220),
            row("PRIVATE_KEY_CANARY"),
        )
        .unwrap();
        for debug in [
            format!("{accepted:?}"),
            format!("{:?}", row("PRIVATE_KEY_CANARY")),
        ] {
            assert!(!debug.contains("PRIVATE_"));
        }
        assert_eq!(
            ProjectionError::InvalidSnapshot.to_string(),
            "external projection snapshot is invalid"
        );
    }

    #[test]
    fn backup_policy_excludes_every_projection_table() {
        assert_eq!(BACKUP_EXCLUDED_TABLES.len(), 4);
        for table in BACKUP_EXCLUDED_TABLES {
            assert!(table.starts_with("registry_internal.registry_external_projection_"));
            assert!(INSTALL_SQL.contains(table));
        }
    }
}

#[cfg(test)]
#[cfg(feature = "postgres-test")]
mod postgres_tests {
    use super::*;
    use serde_json::json;
    use tokio_postgres::{Client, NoTls};

    #[allow(dead_code)]
    mod harness {
        use crate as registry_breg;
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/postgres_harness.rs"
        ));
    }

    fn scope(epoch: Uuid) -> ProjectionScope {
        ProjectionScope::new("projection", epoch, "binding", "grant", 60, 120).unwrap()
    }

    fn record(key: &str, value: &str) -> ProjectionRow {
        ProjectionRow::new(key, json!({"label":value})).unwrap()
    }

    fn snapshot(id: &str, at: i64, value: &str) -> AcceptedSnapshot {
        AcceptedSnapshot::one(
            "subject",
            id,
            at,
            at + 60,
            RetentionPermission::PermittedUntil(at + 120),
            record("subject", value),
        )
        .unwrap()
    }

    async fn clock(migration: &Client, now: i64) {
        let sql = INSTALL_SQL.replace(
            "floor(extract(epoch FROM clock_timestamp()))::bigint",
            &now.to_string(),
        );
        migration
            .batch_execute(&sql)
            .await
            .expect("fixture clock installs");
    }

    #[tokio::test]
    async fn package_catalog_and_bind_once_keep_operator_authority_separate() {
        use super::super::{ExpectedManagedCatalog, RegistryLockKey, RegistryStateTestIdentity};
        let database = harness::TestDatabase::create(2).await;
        let (migration, migration_task) = database.connect_migration().await;
        let registry = super::super::external_view_query::tests::registry();
        super::super::install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .unwrap();
        let expected = super::super::initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &registry,
            RegistryStateTestIdentity {
                package_id: "projection-package",
                database_id: "projection-database",
                label: "projection-catalog",
            },
        )
        .await
        .unwrap();
        let catalog = ExpectedManagedCatalog::compiled(&registry);
        for (identity, result, returns_set, security_definer, _) in MANAGED_FUNCTIONS {
            let row=migration.query_one("SELECT p.prorettype::regtype::text,p.proretset,p.prosecdef,r.rolname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname||'.'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||')'=$1",&[identity]).await.unwrap();
            assert_eq!(row.get::<_, String>(0), *result);
            assert_eq!(row.get::<_, bool>(1), *returns_set);
            assert_eq!(row.get::<_, bool>(2), *security_definer);
            assert_eq!(row.get::<_, String>(3), database.migration_role.as_str());
        }
        super::super::verify_catalog_identity_for_catalog(
            &migration,
            &expected,
            &catalog,
            &database.migration_role,
            &database.runtime_role,
        )
        .await
        .unwrap();
        let pool = database.runtime_config.build_pool().unwrap();
        let mut runtime = pool.get().await.unwrap();
        let transaction = super::super::begin_registry_transaction(
            &mut runtime,
            RegistryLockKey::derive(registry.registry_id()).unwrap(),
            std::time::Duration::from_secs(2),
            &expected,
        )
        .await
        .unwrap();
        let mut requested = scope(Uuid::new_v4());
        requested.cache_ttl_seconds = 30;
        let bound = bind_initial_scope(&transaction, &registry, &expected, &requested)
            .await
            .unwrap();
        let restarted = bind_initial_scope(&transaction, &registry, &expected, &requested)
            .await
            .unwrap();
        assert_eq!(bound.epoch, restarted.epoch);
        let mut substituted = scope(Uuid::new_v4());
        substituted.binding_digest = "another-binding".to_owned();
        assert_eq!(
            bind_initial_scope(&transaction, &registry, &expected, &substituted)
                .await
                .unwrap_err(),
            ProjectionError::ScopeChanged
        );
        assert!(
            load_active_scope(&transaction, "projection", "binding", "grant")
                .await
                .is_ok()
        );
        let baseline = next_refresh_sequence(&transaction, &bound).await.unwrap();
        let now: i64 = transaction
            .transaction()
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert!(
            refresh_due_keys(&transaction, &bound, &["subject".to_owned()], baseline, now)
                .await
                .unwrap()
                .contains("subject")
        );
        let ticket = allocate_refresh(&transaction, &bound, "subject")
            .await
            .unwrap();
        let accepted = AcceptedSnapshot::one(
            "subject",
            "sweep",
            now,
            now + 60,
            RetentionPermission::PermittedUntil(now + 120),
            record("subject", "fresh"),
        )
        .unwrap();
        let eligibility = "SELECT 1 WHERE $6::text='subject' AND cardinality($13::uuid[])>0";
        assert_eq!(
            publish_for_roots(&transaction, &ticket, &accepted, eligibility, &[])
                .await
                .unwrap(),
            Publication::Ineligible
        );
        assert!(
            refresh_due_keys(&transaction, &bound, &["subject".to_owned()], baseline, now)
                .await
                .unwrap()
                .contains("subject")
        );
        assert_eq!(
            publish_for_roots(
                &transaction,
                &ticket,
                &accepted,
                eligibility,
                &[Uuid::new_v4()]
            )
            .await
            .unwrap(),
            Publication::Published
        );
        assert!(
            !refresh_due_keys(&transaction, &bound, &["subject".to_owned()], baseline, now)
                .await
                .unwrap()
                .contains("subject")
        );
        assert_eq!(
            refresh_due_keys(
                &transaction,
                &bound,
                &[
                    "subject".to_owned(),
                    "missing".to_owned(),
                    "missing".to_owned()
                ],
                baseline,
                now
            )
            .await
            .unwrap(),
            BTreeSet::from(["missing".to_owned()])
        );
        assert!(refresh_due_keys(&transaction, &bound, &[], baseline, now)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            refresh_due_keys(
                &transaction,
                &bound,
                &["subject".to_owned()],
                baseline,
                now + 30
            )
            .await
            .unwrap(),
            BTreeSet::from(["subject".to_owned()])
        );
        assert_eq!(
            refresh_due_keys(
                &transaction,
                &bound,
                &vec!["subject".to_owned(); 1001],
                baseline,
                now
            )
            .await
            .unwrap_err(),
            ProjectionError::InvalidScope
        );
        assert_eq!(
            refresh_due_keys(&transaction, &bound, &[String::new()], baseline, now)
                .await
                .unwrap_err(),
            ProjectionError::InvalidScope
        );
        let next_sweep = next_refresh_sequence(&transaction, &bound).await.unwrap();
        assert!(refresh_due_keys(
            &transaction,
            &bound,
            &["subject".to_owned()],
            next_sweep,
            now
        )
        .await
        .unwrap()
        .contains("subject"));
        transaction.commit().await.unwrap();
        withdraw_scope(&migration, &bound).await.unwrap();
        let transaction = super::super::begin_registry_transaction(
            &mut runtime,
            RegistryLockKey::derive(registry.registry_id()).unwrap(),
            std::time::Duration::from_secs(2),
            &expected,
        )
        .await
        .unwrap();
        assert_eq!(
            refresh_due_keys(&transaction, &bound, &[], baseline, now)
                .await
                .unwrap_err(),
            ProjectionError::ScopeChanged
        );
        assert_eq!(
            bind_initial_scope(&transaction, &registry, &expected, &requested)
                .await
                .unwrap_err(),
            ProjectionError::ScopeChanged
        );
        transaction.commit().await.unwrap();
        drop(runtime);
        // Reapplying an unchanged compiled inventory cannot undo withdrawal.
        reconcile(&migration, &registry, &database.runtime_role)
            .await
            .unwrap();
        assert!(!migration.query_one("SELECT active FROM registry_internal.registry_external_projection_scopes WHERE projection_id='projection'",&[]).await.unwrap().get::<_,bool>(0));
        migration
            .batch_execute(&format!(
                "GRANT UPDATE ON registry_internal.registry_external_projection_values TO {}",
                database.runtime_role.quoted()
            ))
            .await
            .unwrap();
        assert!(super::super::verify_catalog_identity_for_catalog(
            &migration,
            &expected,
            &catalog,
            &database.migration_role,
            &database.runtime_role
        )
        .await
        .is_err());
        migration
            .batch_execute(&format!(
                "REVOKE UPDATE ON registry_internal.registry_external_projection_values FROM {}",
                database.runtime_role.quoted()
            ))
            .await
            .unwrap();
        super::super::verify_catalog_identity_for_catalog(
            &migration,
            &expected,
            &catalog,
            &database.migration_role,
            &database.runtime_role,
        )
        .await
        .unwrap();
        let maintenance="SELECT registry_internal.maintain_external_projection_scope($1,$2,$3,$4,$5,$6,$7,$8,$9)";
        let activation = Uuid::parse_str(&expected.activation_id).unwrap();
        let package = expected.package_digest.as_str();
        let runtime = pool.get().await.unwrap();
        assert!(runtime
            .query_one(
                maintenance,
                &[
                    &"inspect",
                    &"projection",
                    &Some(bound.epoch),
                    &package,
                    &activation,
                    &"renewed-binding",
                    &"renewed-grant",
                    &20_i64,
                    &120_i64
                ]
            )
            .await
            .is_err());
        drop(runtime);
        let rotated: Value = migration
            .query_one(
                maintenance,
                &[
                    &"rotate",
                    &"projection",
                    &Some(bound.epoch),
                    &package,
                    &activation,
                    &"renewed-binding",
                    &"renewed-grant",
                    &20_i64,
                    &120_i64,
                ],
            )
            .await
            .unwrap()
            .get(0);
        let new_epoch = Uuid::parse_str(rotated["epoch"].as_str().unwrap()).unwrap();
        assert_ne!(bound.epoch, new_epoch);
        assert_eq!(rotated["active"], true);
        let inspected: Value = migration
            .query_one(
                maintenance,
                &[
                    &"inspect",
                    &"projection",
                    &Some(new_epoch),
                    &package,
                    &activation,
                    &"",
                    &"",
                    &20_i64,
                    &120_i64,
                ],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            inspected["snapshotCounts"],
            json!({"fresh":0,"expired":0,"invalidated":0})
        );
        assert_eq!(inspected["refreshCounts"].as_object().unwrap().len(), 7);
        assert!(inspected["refreshCounts"]
            .as_object()
            .unwrap()
            .values()
            .all(|count| count == 0));
        assert!(migration
            .query_one(
                maintenance,
                &[
                    &"withdraw",
                    &"projection",
                    &Some(bound.epoch),
                    &package,
                    &activation,
                    &"",
                    &"",
                    &20_i64,
                    &120_i64
                ]
            )
            .await
            .is_err());
        let withdrawn: Value = migration
            .query_one(
                maintenance,
                &[
                    &"withdraw",
                    &"projection",
                    &Some(new_epoch),
                    &package,
                    &activation,
                    &"",
                    &"",
                    &20_i64,
                    &120_i64,
                ],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(withdrawn["active"], false);
        let without = super::super::external_view_query::tests::registry_with_external(false);
        reconcile(&migration, &without, &database.runtime_role)
            .await
            .unwrap();
        assert!(!migration.query_one("SELECT to_regclass('registry_internal.registry_external_projection_scopes') IS NOT NULL",&[]).await.unwrap().get::<_,bool>(0));
        reconcile(&migration, &without, &database.runtime_role)
            .await
            .unwrap();
        drop(pool);
        migration_task.abort();
        drop(migration);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn projection_publication_fences_scope_sequence_replay_and_atomic_membership() {
        let database = harness::TestDatabase::create(2).await;
        let (migration, migration_task) = database.connect_migration().await;
        assert_eq!(
            install(&migration, &database.migration_role)
                .await
                .unwrap_err(),
            ProjectionError::RoleSeparationRequired
        );
        install(&migration, &database.runtime_role).await.unwrap();
        clock(&migration, 1000).await;
        let scope = scope(Uuid::new_v4());
        configure_scope(&migration, &scope).await.unwrap();
        let (runtime, connection) = database
            .runtime_config
            .postgres()
            .connect(NoTls)
            .await
            .unwrap();
        let runtime_task = tokio::spawn(async move {
            connection.await.expect("fixture runtime connection");
        });

        // Direct DML is unavailable even though the runtime can execute the
        // bounded publication function and select its retained projection.
        assert!(runtime
            .execute(
                "UPDATE registry_internal.registry_external_projection_scopes SET active=false",
                &[]
            )
            .await
            .is_err());
        assert!(runtime
            .execute(
                "DELETE FROM registry_internal.registry_external_projection_values",
                &[]
            )
            .await
            .is_err());
        let older = allocate_inner(&runtime, &scope, "subject").await.unwrap();
        let newer = allocate_inner(&runtime, &scope, "subject").await.unwrap();
        let fresh = snapshot("newer", 999, "fresh");
        assert_eq!(
            publish_inner(&runtime, &newer, &fresh).await.unwrap(),
            Publication::Published
        );
        assert_eq!(
            publish_inner(&runtime, &older, &snapshot("older", 998, "stale"))
                .await
                .unwrap_err(),
            ProjectionError::StaleRefresh
        );
        let expiry_before: i64 = runtime.query_one("SELECT expires_at FROM registry_internal.registry_external_projection_snapshots WHERE subject_key='subject'", &[]).await.unwrap().get(0);
        assert_eq!(
            publish_inner(&runtime, &newer, &fresh).await.unwrap(),
            Publication::Replay
        );
        let expiry_after: i64 = runtime.query_one("SELECT expires_at FROM registry_internal.registry_external_projection_snapshots WHERE subject_key='subject'", &[]).await.unwrap().get(0);
        assert_eq!(expiry_before, expiry_after);
        let substitution = snapshot("newer", 999, "substitution");
        assert!(publish_inner(&runtime, &newer, &substitution)
            .await
            .is_err());
        assert!(runtime.query_one("SELECT registry_internal.fail_external_projection_refresh($1,$2,$3,$4,'retention-refused')",&[&scope.projection_id,&scope.epoch,&older.sequence,&older.subject_key]).await.unwrap().get::<_,bool>(0));
        assert_eq!(runtime.query_one("SELECT count(*) FROM registry_internal.registry_external_projection_snapshots WHERE subject_key='subject'",&[]).await.unwrap().get::<_,i64>(0),1);
        let failed = allocate_inner(&runtime, &scope, "subject").await.unwrap();
        assert!(runtime.query_one("SELECT registry_internal.fail_external_projection_refresh($1,$2,$3,$4,'unavailable')",&[&scope.projection_id,&scope.epoch,&failed.sequence,&failed.subject_key]).await.unwrap().get::<_,bool>(0));
        assert_eq!(runtime.query_one("SELECT count(*) FROM registry_internal.registry_external_projection_snapshots WHERE subject_key='subject'",&[]).await.unwrap().get::<_,i64>(0),0);
        let restore = allocate_inner(&runtime, &scope, "subject").await.unwrap();
        publish_inner(&runtime, &restore, &fresh).await.unwrap();
        let no_store = allocate_inner(&runtime, &scope, "subject").await.unwrap();
        assert!(runtime.query_one("SELECT registry_internal.fail_external_projection_refresh($1,$2,$3,$4,'retention-refused')",&[&scope.projection_id,&scope.epoch,&no_store.sequence,&no_store.subject_key]).await.unwrap().get::<_,bool>(0));
        assert_eq!(runtime.query_one("SELECT count(*) FROM registry_internal.registry_external_projection_snapshots WHERE subject_key='subject'",&[]).await.unwrap().get::<_,i64>(0),0);

        let first = allocate_inner(&runtime, &scope, "parent").await.unwrap();
        let collection = AcceptedSnapshot::complete_collection(
            "parent",
            "members-1",
            998,
            1058,
            RetentionPermission::PermittedUntil(1118),
            vec![record("a", "first"), record("b", "second")],
        )
        .unwrap();
        publish_inner(&runtime, &first, &collection).await.unwrap();
        let count = || async {
            runtime.query_one("SELECT count(*) FROM registry_internal.registry_external_projection_values WHERE subject_key='parent'", &[]).await.unwrap().get::<_,i64>(0)
        };
        assert_eq!(count().await, 2);
        let interrupted = allocate_inner(&runtime, &scope, "parent").await.unwrap();
        runtime.query_one("SELECT registry_internal.fail_external_projection_refresh($1,$2,$3,$4,'incomplete')", &[&scope.projection_id,&scope.epoch,&interrupted.sequence,&interrupted.subject_key]).await.unwrap();
        assert_eq!(count().await, 2);
        let next = allocate_inner(&runtime, &scope, "parent").await.unwrap();
        let empty = AcceptedSnapshot::complete_collection(
            "parent",
            "members-2",
            999,
            1059,
            RetentionPermission::PermittedUntil(1119),
            vec![],
        )
        .unwrap();
        publish_inner(&runtime, &next, &empty).await.unwrap();
        assert_eq!(count().await, 0);
        assert_eq!(runtime.query_one("SELECT kind FROM registry_internal.registry_external_projection_snapshots WHERE subject_key='parent'", &[]).await.unwrap().get::<_,String>(0), "complete-collection");

        let pending = allocate_inner(&runtime, &scope, "subject").await.unwrap();
        // Withdrawal is operator authority: a runtime credential cannot end a
        // scope, and so cannot force the next start to rebind it.
        let refused = runtime
            .query_one(
                "SELECT registry_internal.withdraw_external_projection($1,$2,$3,$4)",
                &[
                    &scope.projection_id,
                    &scope.epoch,
                    &scope.binding_digest,
                    &scope.grant_digest,
                ],
            )
            .await
            .unwrap_err();
        assert_eq!(
            refused.code(),
            Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE)
        );
        assert!(migration.query_one("SELECT active FROM registry_internal.registry_external_projection_scopes WHERE projection_id=$1",&[&scope.projection_id]).await.unwrap().get::<_,bool>(0));
        withdraw_scope(&migration, &scope).await.unwrap();
        assert_eq!(
            publish_inner(
                &runtime,
                &pending,
                &snapshot("after-withdrawal", 1000, "forbidden")
            )
            .await
            .unwrap_err(),
            ProjectionError::ScopeChanged
        );
        assert!(configure_scope(&migration, &scope).await.is_err());
        let replacement = super::postgres_tests::scope(Uuid::new_v4());
        configure_scope(&migration, &replacement).await.unwrap();
        assert_eq!(
            publish_inner(&runtime, &pending, &fresh).await.unwrap_err(),
            ProjectionError::ScopeChanged
        );

        runtime_task.abort();
        migration_task.abort();
        drop(runtime);
        drop(migration);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn allocation_abandonment_preserves_snapshots_without_a_terminal_fence() {
        let database = harness::TestDatabase::create(2).await;
        let (migration, migration_task) = database.connect_migration().await;
        install(&migration, &database.runtime_role).await.unwrap();
        clock(&migration, 1000).await;
        let scope = scope(Uuid::new_v4());
        configure_scope(&migration, &scope).await.unwrap();
        let initial = allocate_inner(&migration, &scope, "subject").await.unwrap();
        publish_inner(&migration, &initial, &snapshot("initial", 999, "retained"))
            .await
            .unwrap();
        let older = allocate_inner(&migration, &scope, "subject").await.unwrap();
        let abandoned = allocate_inner(&migration, &scope, "subject").await.unwrap();
        let fail = "SELECT registry_internal.fail_external_projection_refresh($1,$2,$3,$4,$5)";
        assert!(migration
            .query_one(
                fail,
                &[
                    &scope.projection_id,
                    &scope.epoch,
                    &abandoned.sequence,
                    &"other",
                    &RefreshFailure::Abandoned.as_str()
                ]
            )
            .await
            .unwrap()
            .get::<_, bool>(0));
        assert!(migration
            .query_one(
                fail,
                &[
                    &scope.projection_id,
                    &scope.epoch,
                    &abandoned.sequence,
                    &abandoned.subject_key,
                    &RefreshFailure::Abandoned.as_str()
                ]
            )
            .await
            .unwrap()
            .get::<_, bool>(0));
        assert_eq!(migration.query_one("SELECT count(*) FROM registry_internal.registry_external_projection_refreshes WHERE projection_id=$1 AND sequence=$2",&[&scope.projection_id,&abandoned.sequence]).await.unwrap().get::<_,i64>(0),0);
        assert_eq!(migration.query_one("SELECT snapshot_id,expires_at FROM registry_internal.registry_external_projection_snapshots WHERE projection_id=$1 AND subject_key='subject'",&[&scope.projection_id]).await.unwrap().get::<_,String>(0),"initial");
        publish_inner(&migration, &older, &snapshot("older", 999, "accepted"))
            .await
            .unwrap();
        assert!(migration
            .query_one(
                fail,
                &[
                    &scope.projection_id,
                    &scope.epoch,
                    &older.sequence,
                    &older.subject_key,
                    &RefreshFailure::Abandoned.as_str()
                ]
            )
            .await
            .unwrap()
            .get::<_, bool>(0));
        assert_eq!(migration.query_one("SELECT lease_expires_at-started_at FROM registry_internal.registry_external_projection_refreshes WHERE projection_id=$1 AND sequence=$2",&[&scope.projection_id,&older.sequence]).await.unwrap().get::<_,i64>(0),120);
        migration_task.abort();
        drop(migration);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn terminal_receipts_fence_older_results_after_snapshot_removal() {
        let database = harness::TestDatabase::create(2).await;
        let (migration, migration_task) = database.connect_migration().await;
        install(&migration, &database.runtime_role).await.unwrap();
        clock(&migration, 1000).await;
        let scope = scope(Uuid::new_v4());
        configure_scope(&migration, &scope).await.unwrap();
        for reason in [
            "denied",
            "retention-refused",
            "unavailable",
            "incomplete",
            "invalid-binding",
        ] {
            let initial = allocate_inner(&migration, &scope, "subject").await.unwrap();
            let accepted = snapshot(reason, 999, "retained");
            publish_inner(&migration, &initial, &accepted)
                .await
                .unwrap();
            let older = allocate_inner(&migration, &scope, "subject").await.unwrap();
            let newer = allocate_inner(&migration, &scope, "subject").await.unwrap();
            assert!(migration
                .query_one(
                    "SELECT registry_internal.fail_external_projection_refresh($1,$2,$3,$4,$5)",
                    &[
                        &scope.projection_id,
                        &scope.epoch,
                        &newer.sequence,
                        &newer.subject_key,
                        &reason
                    ]
                )
                .await
                .unwrap()
                .get::<_, bool>(0));
            assert!(migration.query_one("SELECT registry_internal.fail_external_projection_refresh($1,$2,$3,$4,'abandoned')",&[&scope.projection_id,&scope.epoch,&newer.sequence,&newer.subject_key]).await.unwrap().get::<_,bool>(0));
            assert_eq!(
                publish_inner(&migration, &older, &snapshot("older", 999, "forbidden"))
                    .await
                    .unwrap_err(),
                ProjectionError::StaleRefresh
            );
            assert_eq!(
                publish_inner(&migration, &initial, &accepted)
                    .await
                    .unwrap_err(),
                ProjectionError::StaleRefresh
            );
            // Even an expired barrier must survive while an earlier attempt
            // remains live, independently of wall-clock lease ordering.
            migration.execute("UPDATE registry_internal.registry_external_projection_refreshes SET lease_expires_at=999 WHERE projection_id=$1 AND sequence=$2",&[&scope.projection_id,&newer.sequence]).await.unwrap();
            migration
                .query_one(
                    "SELECT * FROM registry_internal.purge_external_projections(1000)",
                    &[],
                )
                .await
                .unwrap();
            assert_eq!(
                publish_inner(&migration, &older, &accepted)
                    .await
                    .unwrap_err(),
                ProjectionError::StaleRefresh
            );
            let later = allocate_inner(&migration, &scope, "subject").await.unwrap();
            publish_inner(&migration, &later, &accepted).await.unwrap();
            migration.query_one("SELECT registry_internal.fail_external_projection_refresh($1,$2,$3,$4,'retention-refused')",&[&scope.projection_id,&scope.epoch,&older.sequence,&older.subject_key]).await.unwrap();
            assert_eq!(migration.query_one("SELECT refresh_sequence FROM registry_internal.registry_external_projection_snapshots WHERE projection_id=$1 AND subject_key='subject'",&[&scope.projection_id]).await.unwrap().get::<_,i64>(0),later.sequence);
        }
        migration_task.abort();
        drop(migration);
        database.cleanup().await;
    }

    #[tokio::test]
    async fn projection_expiry_purge_and_excluded_backup_restore_are_closed() {
        let database = harness::TestDatabase::create(2).await;
        let (migration, migration_task) = database.connect_migration().await;
        assert_eq!(
            install(&migration, &database.migration_role)
                .await
                .unwrap_err(),
            ProjectionError::RoleSeparationRequired
        );
        install(&migration, &database.runtime_role).await.unwrap();
        clock(&migration, 1000).await;
        let scope = scope(Uuid::new_v4());
        configure_scope(&migration, &scope).await.unwrap();
        let ticket = allocate_inner(&migration, &scope, "subject").await.unwrap();
        let observed = snapshot("original", 990, "retained");
        publish_inner(&migration, &ticket, &observed).await.unwrap();
        clock(&migration, 1050).await;
        let visible: i64 = migration.query_one("SELECT count(*) FROM registry_internal.registry_external_projection_snapshots WHERE expires_at>1050", &[]).await.unwrap().get(0);
        assert_eq!(visible, 0);
        assert!(publish_inner(&migration, &ticket, &observed).await.is_err());
        // Purge at freshness expiry leaves retention headroom.
        let pruned = migration
            .query_one(
                "SELECT * FROM registry_internal.purge_external_projections(100)",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(pruned.get::<_, i64>(0), 1);
        assert_eq!(
            migration
                .query_one(
                    "SELECT count(*) FROM registry_internal.registry_external_projection_values",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );

        // A projection-excluding backup restores the table definitions only.
        // Model that exact boundary using a second empty disposable database,
        // not by restoring expired authority from the first database.
        let restored = harness::TestDatabase::create(1).await;
        let (restore_migration, restore_task) = restored.connect_migration().await;
        install(&restore_migration, &restored.runtime_role)
            .await
            .unwrap();
        for table in BACKUP_EXCLUDED_TABLES {
            let count = restore_migration
                .query_one(&format!("SELECT count(*) FROM {table}"), &[])
                .await
                .unwrap()
                .get::<_, i64>(0);
            assert_eq!(count, 0);
        }
        assert!(allocate_inner(&restore_migration, &scope, "subject")
            .await
            .is_err());
        restore_task.abort();
        migration_task.abort();
        drop(restore_migration);
        drop(migration);
        restored.cleanup().await;
        database.cleanup().await;
    }
}

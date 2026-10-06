// SPDX-License-Identifier: Apache-2.0
//! Transactional package activation and runtime-role enforcement.

use registry_platform_activation::{
    self as platform, Activation, DatabaseIdCheck, Layout, NewActivation, PlanKind, RoleMode,
};
use registry_platform_audit::AuditRequest;
use serde::Serialize;
use serde_json::json;
use thiserror::Error;
use uuid::Uuid;

use crate::audit::MessagingAudit;
use crate::store::{migrate_in, PostgresStore, StoreError, MIGRATIONS, MIGRATION_LOCK_KEY};

const MAX_BACKUPS: usize = 16;

fn layout() -> Layout {
    Layout::new(
        "messaging",
        "messaging_activations",
        "messaging_schema_migrations",
        &[],
        false,
    )
    .expect("static Messaging activation identifiers")
}

fn platform_error(error: platform::Error) -> StoreError {
    match error {
        platform::Error::Database(error) => error.into(),
        platform::Error::UnsupportedPostgres => StoreError::UnsupportedPostgres,
        platform::Error::InvalidLayout | platform::Error::Corrupt => StoreError::SchemaVersion,
    }
}

fn known_schema_versions() -> Vec<i64> {
    MIGRATIONS.iter().map(|(version, _)| *version).collect()
}

fn schema_history_refusal(schema: &platform::SchemaState) -> Option<ActivationRefusal> {
    let known = known_schema_versions();
    let unexpected = schema
        .applied
        .iter()
        .enumerate()
        .find_map(|(index, version)| (known.get(index) != Some(version)).then_some(*version))?;
    if known.last().is_some_and(|latest| unexpected > *latest) {
        Some(ActivationRefusal::new(
            "messagingctl.activation.schema-newer",
            "database",
            format!(
                "the database schema contains version {unexpected}, which is newer than this Messaging release"
            ),
        ))
    } else {
        Some(ActivationRefusal::new(
            "messagingctl.activation.schema-invalid",
            "database",
            format!(
                "the database schema history is not an ordered prefix of this Messaging release at version {unexpected}"
            ),
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ActivationChange {
    None,
    Activate,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationPlan {
    pub package_digest: String,
    pub active_digest: Option<String>,
    pub change: ActivationChange,
    pub database_id: DatabaseIdCheck,
    pub plan_kind: PlanKind,
    pub pending_schema_versions: Vec<i64>,
    pub runtime_role_mode: Option<RoleMode>,
    pub grants_current: Option<bool>,
    pub refusals: Vec<ActivationRefusal>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationStatus {
    pub active: Option<Activation>,
    pub history: Vec<Activation>,
    pub schema_version: Option<i64>,
    pub runtime_role_mode: Option<RoleMode>,
    pub grants_current: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationApplied {
    pub activation: Activation,
    pub schema_versions_applied: Vec<i64>,
    pub recorded: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationRefusal {
    pub code: &'static str,
    pub path: &'static str,
    pub message: String,
}

impl ActivationRefusal {
    fn new(code: &'static str, path: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            path,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ApplyRequest {
    pub operator_reference: Option<String>,
    pub backup_references: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ActivationError {
    #[error("the Messaging package activation was refused")]
    Refused(Vec<ActivationRefusal>),
    #[error("package {package_digest} is active as activation {activation_id}, but its audit response was not accepted; restore the audit destination and confirm with `messagingctl status --runtime-config FILE`")]
    AppliedUnaudited {
        activation_id: Uuid,
        package_digest: String,
    },
    #[error("the Messaging activation outcome is unknown; confirm activation {activation_id} with `messagingctl status --runtime-config FILE`")]
    OutcomeUnknown { activation_id: Uuid },
    #[error("the Messaging database has no active package; run `messagingctl plan --runtime-config FILE` then `messagingctl apply --runtime-config FILE`")]
    NotActivated,
    #[error("identity.databaseId does not match the database activation ledger")]
    DatabaseIdMismatch,
    #[error("the configured package is not active; run `messagingctl plan --runtime-config FILE` then `messagingctl apply --runtime-config FILE`")]
    PackageNotActive,
    #[error("the runtime credential has gained authority over the activation boundary; restore the split-role boundary, then apply again")]
    RoleModeWeakened,
    #[error("the runtime credential is missing required grants; run `messagingctl apply --runtime-config FILE` with the migration credential")]
    GrantsStale,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("the Messaging activation audit failed: {0}")]
    Audit(String),
}

impl From<tokio_postgres::Error> for ActivationError {
    fn from(error: tokio_postgres::Error) -> Self {
        Self::Store(StoreError::Query(error))
    }
}

pub async fn plan(
    store: &PostgresStore,
    database_id: &str,
    package_digest: &str,
) -> Result<ActivationPlan, ActivationError> {
    let mut client = store.client().await?;
    let tx = client.build_transaction().read_only(true).start().await?;
    if platform::unreadable_ledger(&*tx, &layout())
        .await
        .map_err(platform_error)?
        .is_some()
    {
        return Err(ActivationError::Refused(vec![ActivationRefusal::new(
            "messagingctl.activation.ledger-unreadable",
            "database.runtimeUrlRef",
            "the runtime credential cannot read the activation ledger; run messagingctl apply with the migration credential",
        )]));
    }
    let schema = platform::schema_state(&*tx, &layout(), &known_schema_versions())
        .await
        .map_err(platform_error)?;
    let active = platform::active_activation(&*tx, &layout())
        .await
        .map_err(platform_error)?;
    let observation = platform::observe_role(&*tx, &layout(), None, &[])
        .await
        .map_err(platform_error)?;
    let database_id_check = platform::database_id_check(active.as_ref(), database_id);
    let mut refusals = Vec::new();
    if database_id_check == DatabaseIdCheck::Differs {
        refusals.push(ActivationRefusal::new(
            "messagingctl.activation.database-id-mismatch",
            "identity.databaseId",
            "the database belongs to another deployment",
        ));
    }
    if let Some(refusal) = schema_history_refusal(&schema) {
        refusals.push(refusal);
    }
    if let (Some(active), Some(role)) = (&active, observation) {
        if active.role_mode == RoleMode::Split && role.mode == RoleMode::Single {
            refusals.push(ActivationRefusal::new(
                "messagingctl.activation.role-mode-weakened",
                "database.runtimeUrlRef",
                "the runtime credential gained authority over the activation boundary; restore split-role ownership and apply again",
            ));
        } else if role.mode == RoleMode::Split && !role.grants_current {
            refusals.push(ActivationRefusal::new(
                "messagingctl.activation.grants-stale",
                "database.runtimeUrlRef",
                "the runtime credential is missing required grants; apply the package again",
            ));
        }
    }
    let active_digest = active.as_ref().map(|row| row.package_digest.clone());
    let change = if active_digest.as_deref() == Some(package_digest)
        && schema.pending.is_empty()
        && refusals.is_empty()
        && observation.is_none_or(|role| role.grants_current)
    {
        ActivationChange::None
    } else {
        ActivationChange::Activate
    };
    let result = ActivationPlan {
        package_digest: package_digest.to_owned(),
        active_digest,
        change,
        database_id: database_id_check,
        plan_kind: if active.is_some() {
            PlanKind::Successor
        } else {
            PlanKind::Initial
        },
        pending_schema_versions: schema.pending,
        runtime_role_mode: observation.map(|role| role.mode),
        grants_current: observation.map(|role| role.grants_current),
        refusals,
    };
    tx.commit().await?;
    Ok(result)
}

pub async fn status(store: &PostgresStore) -> Result<ActivationStatus, ActivationError> {
    let mut client = store.client().await?;
    let tx = client.build_transaction().read_only(true).start().await?;
    if platform::unreadable_ledger(&*tx, &layout())
        .await
        .map_err(platform_error)?
        .is_some()
    {
        return Err(ActivationError::Refused(vec![ActivationRefusal::new(
            "messagingctl.activation.ledger-unreadable",
            "database.runtimeUrlRef",
            "the runtime credential cannot read the activation ledger; run messagingctl apply with the migration credential",
        )]));
    }
    let schema = platform::schema_state(&*tx, &layout(), &known_schema_versions())
        .await
        .map_err(platform_error)?;
    let history = platform::activation_history(&*tx, &layout())
        .await
        .map_err(platform_error)?;
    let active = history.last().cloned();
    let observation = platform::observe_role(&*tx, &layout(), None, &[])
        .await
        .map_err(platform_error)?;
    let result = ActivationStatus {
        active,
        history,
        schema_version: schema.current(),
        runtime_role_mode: observation.map(|role| role.mode),
        grants_current: observation.map(|role| role.grants_current),
    };
    tx.commit().await?;
    Ok(result)
}

pub async fn apply(
    migration: &PostgresStore,
    runtime_role: &str,
    database_id: &str,
    package_digest: &str,
    request: &ApplyRequest,
    audit: &MessagingAudit,
) -> Result<ActivationApplied, ActivationError> {
    if request.backup_references.len() > MAX_BACKUPS
        || request
            .operator_reference
            .as_ref()
            .is_some_and(|value| !valid_operator_text(value))
        || request
            .backup_references
            .iter()
            .any(|value| !valid_operator_text(value))
    {
        return Err(ActivationError::Refused(vec![ActivationRefusal::new(
            "messagingctl.activation.invalid-reference",
            "arguments",
            "operator references must be non-empty, free of control characters, at most 256 bytes, with at most 16 backups",
        )]));
    }
    let activation_id = Uuid::new_v4();
    let mut audit_request = audit
        .begin(json!({
            "event": "messaging.package.activation.requested",
            "packageDigest": package_digest,
            "activationId": activation_id,
        }))
        .await
        .map_err(|error| ActivationError::Audit(error.to_string()))?;
    let mut client = migration.client().await?;
    let tx = client.transaction().await?;
    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_KEY])
        .await?;
    let schema = platform::schema_state(&*tx, &layout(), &known_schema_versions())
        .await
        .map_err(platform_error)?;
    if let Some(refusal) = schema_history_refusal(&schema) {
        let refusals = vec![refusal];
        drop(tx);
        respond_refused(&mut audit_request, activation_id, package_digest, &refusals).await?;
        return Err(ActivationError::Refused(refusals));
    }
    let migration_role: String = tx.query_one("SELECT current_user::text", &[]).await?.get(0);
    let split = migration_role != runtime_role;
    let current_active = platform::active_activation(&*tx, &layout())
        .await
        .map_err(platform_error)?;
    if platform::database_id_check(current_active.as_ref(), database_id) == DatabaseIdCheck::Differs
    {
        let refusals = vec![ActivationRefusal::new(
            "messagingctl.activation.database-id-mismatch",
            "identity.databaseId",
            "the database belongs to another deployment",
        )];
        drop(tx);
        respond_refused(&mut audit_request, activation_id, package_digest, &refusals).await?;
        return Err(ActivationError::Refused(refusals));
    }
    if split {
        let mut stray = platform::stray_authority(&*tx, &layout(), Some(runtime_role))
            .await
            .map_err(platform_error)?;
        if let Some(grant) = platform::default_trigger_grant(&*tx, runtime_role)
            .await
            .map_err(platform_error)?
        {
            stray.push(grant.statement());
        }
        if !stray.is_empty() {
            let refusals = vec![ActivationRefusal::new(
                "messagingctl.activation.role-mode-weakened",
                "database.runtimeUrlRef",
                format!(
                    "the runtime role has migration authority; apply these corrections first: {}",
                    stray.join("; ")
                ),
            )];
            drop(tx);
            respond_refused(&mut audit_request, activation_id, package_digest, &refusals).await?;
            return Err(ActivationError::Refused(refusals));
        }
    }
    let schema_versions_applied = migrate_in(&tx).await?;
    // Observed before granting: a reapply that restores stale grants is a
    // change, recorded as a new activation like any other.
    let grants_were_current = !split
        || platform::observe_role(&*tx, &layout(), Some(runtime_role), &[])
            .await
            .map_err(platform_error)?
            .is_some_and(|role| role.grants_current);
    let (role_mode, grants_current, readable) = if split {
        platform::grant_runtime_role(&*tx, &layout(), runtime_role, &[])
            .await
            .map_err(platform_error)?;
        platform::observe_role(&*tx, &layout(), Some(runtime_role), &[])
            .await
            .map_err(platform_error)?
            .map_or((RoleMode::Single, false, false), |role| {
                (role.mode, role.grants_current, role.readable)
            })
    } else {
        (RoleMode::Single, true, true)
    };
    if role_mode == RoleMode::Single && split || !grants_current || !readable {
        let refusals = vec![ActivationRefusal::new(
            "messagingctl.activation.role-mode-weakened",
            "database.runtimeUrlRef",
            "the runtime role retains activation authority or lacks the complete runtime grants",
        )];
        drop(tx);
        respond_refused(&mut audit_request, activation_id, package_digest, &refusals).await?;
        return Err(ActivationError::Refused(refusals));
    }
    if schema_versions_applied.is_empty()
        && grants_were_current
        && current_active.as_ref().is_some_and(|active| {
            active.package_digest == package_digest
                && active.database_id == database_id
                && active.role_mode == role_mode
        })
    {
        let activation = current_active.expect("checked as present");
        tx.commit().await?;
        audit_request
            .respond(json!({
                "event": "messaging.package.activation.finished",
                "activationId": activation_id,
                "activeActivationId": activation.activation_id,
                "packageDigest": activation.package_digest,
                "planKind": activation.plan_kind.as_str(),
                "roleMode": activation.role_mode.as_str(),
                "applied": false,
                "outcome": "unchanged",
            }))
            .await
            .map_err(|_| ActivationError::AppliedUnaudited {
                activation_id: activation.activation_id,
                package_digest: package_digest.to_owned(),
            })?;
        return Ok(ActivationApplied {
            activation,
            schema_versions_applied,
            recorded: false,
        });
    }
    let operator_reference_hash = request
        .operator_reference
        .as_deref()
        .map(|value| audit.activation_reference(activation_id, value))
        .transpose()
        .map_err(|error| ActivationError::Audit(error.to_string()))?;
    let activation = platform::append_activation(
        &*tx,
        &layout(),
        &NewActivation {
            activation_id,
            package_digest,
            database_id,
            operator_reference_hash: operator_reference_hash.as_deref(),
            backup_references: &request.backup_references,
            role_mode,
            runtime_role: None,
        },
    )
    .await
    .map_err(platform_error)?;
    if let Err(_commit_error) = tx.commit().await {
        let recorded = match migration.client().await {
            Ok(readback) => platform::activation_recorded(&**readback, &layout(), activation_id)
                .await
                .ok(),
            Err(_) => None,
        };
        if recorded != Some(true) {
            return Err(ActivationError::OutcomeUnknown { activation_id });
        }
    }
    audit_request
        .respond(json!({
            "event": "messaging.package.activation.finished",
            "activationId": activation.activation_id,
            "packageDigest": activation.package_digest,
            "predecessorPackageDigest": activation.predecessor_package_digest,
            "planKind": activation.plan_kind.as_str(),
            "roleMode": activation.role_mode.as_str(),
            "operatorReferenceHash": activation.operator_reference_hash,
            "schemaVersionsApplied": schema_versions_applied,
            "applied": true,
            "outcome": "applied",
        }))
        .await
        .map_err(|_| ActivationError::AppliedUnaudited {
            activation_id,
            package_digest: package_digest.to_owned(),
        })?;
    Ok(ActivationApplied {
        activation,
        schema_versions_applied,
        recorded: true,
    })
}

pub async fn check_runtime(
    store: &PostgresStore,
    database_id: &str,
    package_digest: &str,
) -> Result<Activation, ActivationError> {
    store.ready().await?;
    let client = store.client().await?;
    let active = platform::check_active_package(&**client, &layout(), database_id, package_digest)
        .await
        .map_err(|error| match error {
            platform::ActivePackageError::NotActivated => ActivationError::NotActivated,
            platform::ActivePackageError::DatabaseIdMismatch => ActivationError::DatabaseIdMismatch,
            platform::ActivePackageError::PackageNotActive { .. } => {
                ActivationError::PackageNotActive
            }
            platform::ActivePackageError::Activation(error) => {
                ActivationError::Store(platform_error(error))
            }
        })?;
    let role = platform::observe_role(&**client, &layout(), None, &[])
        .await
        .map_err(platform_error)?
        .ok_or(ActivationError::GrantsStale)?;
    if active.role_mode == RoleMode::Split && role.mode != RoleMode::Split {
        return Err(ActivationError::RoleModeWeakened);
    }
    if role.mode == RoleMode::Split && (!role.grants_current || !role.readable) {
        return Err(ActivationError::GrantsStale);
    }
    Ok(active)
}

async fn respond_refused(
    audit_request: &mut AuditRequest,
    activation_id: Uuid,
    package_digest: &str,
    refusals: &[ActivationRefusal],
) -> Result<(), ActivationError> {
    audit_request
        .respond(json!({
            "event": "messaging.package.activation.finished",
            "activationId": activation_id,
            "packageDigest": package_digest,
            "outcome": "refused",
            "refusals": refusals.iter().map(|refusal| refusal.code).collect::<Vec<_>>(),
        }))
        .await
        .map_err(|error| ActivationError::Audit(error.to_string()))
}

fn valid_operator_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::{platform, schema_history_refusal};

    fn schema(applied: &[i64]) -> platform::SchemaState {
        platform::SchemaState {
            applied: applied.to_vec(),
            pending: Vec::new(),
        }
    }

    #[test]
    fn schema_history_accepts_every_known_prefix() {
        for applied in [&[][..], &[1][..], &[1, 2][..], &[1, 2, 3][..]] {
            assert!(schema_history_refusal(&schema(applied)).is_none());
        }
    }

    #[test]
    fn schema_history_distinguishes_newer_and_invalid_versions() {
        let newer = schema_history_refusal(&schema(&[1, 2, 99])).expect("a newer version");
        assert_eq!(newer.code, "messagingctl.activation.schema-newer");
        assert!(newer.message.contains("version 99"));

        let invalid = schema_history_refusal(&schema(&[2])).expect("an invalid history");
        assert_eq!(invalid.code, "messagingctl.activation.schema-invalid");
        assert!(invalid.message.contains("version 2"));
    }
}

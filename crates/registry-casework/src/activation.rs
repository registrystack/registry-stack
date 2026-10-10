// SPDX-License-Identifier: Apache-2.0
//! Package activation: the append-only ledger that records which verified
//! Casework package a database runs, and the one transaction that applies a
//! package to it.
//!
//! `caseworkctl plan` reads what an activation would do in a read-only
//! transaction. `caseworkctl apply` runs, in one transaction under the
//! migration lock, the ledger checks, the pending schema migrations, the
//! pinned-work check, source binding generation registration, task template
//! activation, the ledger row, and, when the runtime connects as its own
//! role, the grants that keep that role from writing the ledger. Startup only
//! reads the ledger and refuses a database whose active package is not the
//! configured one.

use std::collections::{BTreeMap, BTreeSet};

use registry_casework_core::{CaseworkProject, SourceAdapter, TaskTemplate};
use registry_platform_activation::{
    self as platform_activation, KnownTrigger, Layout, NewActivation, RoleObservation,
};
use serde::Serialize;
use serde_json::{json, Value};
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::audit::AuditOutcome;
use crate::pinned_work::{compare_pinned_work, PinnedWorkVerdict, StrandedWork};
use crate::store::{
    migrate_in, pending_migration_refusals, pinned_work_inventory_in,
    register_source_generation_in, MIGRATIONS, MIGRATION_LOCK_KEY, SUPPORTED_SCHEMA_VERSION,
};
use crate::{PostgresStore, StoreError};

/// The schema identifier every activation audit entry carries.
pub const ACTIVATION_AUDIT_SCHEMA: &str = "casework-activation-audit/v1";

/// What a single-role deployment can and cannot catch, stated wherever the
/// role mode is reported.
pub use registry_platform_activation::{
    Activation, DatabaseIdCheck, PlanKind, RoleMode, SINGLE_ROLE_STATEMENT,
};

/// The triggers the Casework migrations create, as table, trigger, and the
/// function in the Casework schema it executes. Any other trigger on a
/// Casework table is stray authority in a split-role deployment.
const MIGRATION_TRIGGERS: [KnownTrigger; 2] = [
    KnownTrigger {
        relation: "casework_meta",
        trigger: "casework_task_directory_changed",
        function: "casework_task_directory_changed",
    },
    KnownTrigger {
        relation: "casework_items",
        trigger: "casework_task_item_changed",
        function: "casework_task_item_changed",
    },
];

fn activation_layout() -> Layout {
    Layout::new(
        "casework",
        "casework_activations",
        "casework_schema_migrations",
        &MIGRATION_TRIGGERS,
        false,
    )
    .expect("the Casework activation layout uses static PostgreSQL identifiers")
}

fn platform_error(error: platform_activation::Error) -> StoreError {
    match error {
        platform_activation::Error::Database(error) => error.into(),
        platform_activation::Error::UnsupportedPostgres => StoreError::UnsupportedPostgres,
        platform_activation::Error::InvalidLayout | platform_activation::Error::Corrupt => {
            StoreError::Corrupt
        }
    }
}

/// The longest `--operator-reference` accepted, in bytes.
pub const MAX_OPERATOR_REFERENCE_BYTES: usize = 256;
/// The most `--backup` references one activation records.
pub const MAX_BACKUP_REFERENCES: usize = 16;
/// The longest `--backup` reference accepted, in bytes.
pub const MAX_BACKUP_REFERENCE_BYTES: usize = 512;

/// The largest serialized task template the ledger stores.
const MAX_TASK_TEMPLATE_BYTES: usize = 65536;

/// The oldest schema version whose retained work, source generations, and
/// task templates a plan can read before migrating. A plan against an older
/// schema reports its effects as not evaluated; apply evaluates them after
/// migrating.
const EFFECTS_SCHEMA_VERSION: i64 = 18;

/// The audit profile an operator's activation is recorded under.
const OPERATOR_PROFILE: &str = "system:operator";

/// The audit event of one package activation.
const ACTIVATION_EVENT: &str = "casework.package-activated";

/// The keyed-hash class of an operator reference, scoped by activation id.
const OPERATOR_REFERENCE_HASH_CLASS: &str = "casework-operator-reference-v1";

const REFUSAL_PREFIX: &str = "casework.activation";

const PLAN_THEN_APPLY: &str =
    "run `caseworkctl plan --runtime-config FILE` then `caseworkctl apply --runtime-config FILE`";

/// The verified package and runtime identity an activation is planned or
/// applied for.
pub struct ActivationCandidate<'a> {
    /// The configured `identity.databaseId`.
    pub database_id: &'a str,
    /// The verified package digest.
    pub package_digest: &'a str,
    /// The configured `package.acknowledgeStrandedWork`.
    pub acknowledged_stranded_work: Option<&'a str>,
    pub project: &'a CaseworkProject,
    /// The source adapters built from the package and the runtime bindings.
    pub adapters: &'a [&'a dyn SourceAdapter],
}

/// Operator-supplied references an activation records.
#[derive(Clone, Debug, Default)]
pub struct ApplyRequest {
    /// Stored and audited only as a keyed hash scoped by the activation id.
    pub operator_reference: Option<String>,
    pub backup_references: Vec<String>,
}

/// Validate one `--operator-reference` value.
pub fn validate_operator_reference(value: &str) -> Result<(), String> {
    validate_reference("--operator-reference", value, MAX_OPERATOR_REFERENCE_BYTES)
}

/// Validate one `--backup` value.
pub fn validate_backup_reference(value: &str) -> Result<(), String> {
    validate_reference("--backup", value, MAX_BACKUP_REFERENCE_BYTES)
}

fn validate_reference(flag: &str, value: &str, max: usize) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{flag} must not be empty"));
    }
    if value.len() > max {
        return Err(format!("{flag} must be at most {max} bytes"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{flag} must not contain control characters"));
    }
    Ok(())
}

impl ApplyRequest {
    fn validate(&self) -> Result<(), StoreError> {
        if let Some(reference) = &self.operator_reference {
            validate_operator_reference(reference).map_err(|_| StoreError::Invalid)?;
        }
        if self.backup_references.len() > MAX_BACKUP_REFERENCES {
            return Err(StoreError::Invalid);
        }
        for reference in &self.backup_references {
            validate_backup_reference(reference).map_err(|_| StoreError::Invalid)?;
        }
        Ok(())
    }
}

/// The pinned-work verdict an activation reaches.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PinnedWorkEffect {
    /// `clear`, `acknowledged`, or `refused`.
    pub verdict: &'static str,
    pub stranded: Vec<StrandedWork>,
}

/// What an activation does to one source's binding generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum GenerationChange {
    /// No state is recorded for this source; apply records the generation.
    Registered,
    /// The generation is already the recorded one.
    Unchanged,
    /// State is recorded under another generation; apply rebinds it.
    Changed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceGenerationEffect {
    pub source_id: String,
    pub change: GenerationChange,
}

/// What an activation does to one task template version.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TemplateChange {
    /// The version is stored for the first time and becomes active.
    Added,
    /// A stored inactive version becomes active again.
    Activated,
    /// The version stays active.
    Retained,
    /// An active version the package no longer declares is deactivated and
    /// its live grants are invalidated.
    Deactivated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskTemplateEffect {
    pub template_id: String,
    pub template_version: String,
    pub change: TemplateChange,
}

/// The Casework-specific effects of an activation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationEffects {
    pub pinned_work: PinnedWorkEffect,
    pub source_generations: Vec<SourceGenerationEffect>,
    pub task_templates: Vec<TaskTemplateEffect>,
}

impl ActivationEffects {
    fn changes_nothing(&self) -> bool {
        self.source_generations
            .iter()
            .all(|source| source.change == GenerationChange::Unchanged)
            && self
                .task_templates
                .iter()
                .all(|template| template.change == TemplateChange::Retained)
    }
}

/// One reason an activation is refused, with the location the operator
/// corrects and the next command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationRefusal {
    pub code: String,
    pub path: String,
    pub message: String,
}

impl ActivationRefusal {
    fn new(code: &str, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: format!("{REFUSAL_PREFIX}.{code}"),
            path: path.into(),
            message: message.into(),
        }
    }

    /// Split-role apply refuses a runtime role that owns a Casework object,
    /// can create one in the schema, or can attach a trigger to a Casework
    /// table, and refuses any trigger on a Casework table that no Casework
    /// migration creates: a trigger fires as the migration role inside
    /// apply's own transaction. `statements` are the SQL statements that
    /// take that authority away.
    fn role_mode_weakened(statements: &[String]) -> Self {
        Self::new(
            "role-mode-weakened",
            "runtime.yaml:/database/runtimeUrlRef",
            format!(
                "the runtime role can write the activation ledger through code that runs as \
                 the migration role; {}",
                stray_authority_fix(statements)
            ),
        )
    }

    fn database_id_mismatch() -> Self {
        Self::new(
            "database-id-mismatch",
            "runtime.yaml:/identity/databaseId",
            database_id_mismatch_message(),
        )
    }
}

/// The refusal sentence for a configured `identity.databaseId` that differs
/// from the one the database's activation ledger records. It names neither
/// value.
#[must_use]
pub fn database_id_mismatch_message() -> String {
    "the package deployment binding differs from the runtime configuration at \
     identity.databaseId; point database.runtimeUrlRef and database.migrationUrlRef at the \
     database this configuration belongs to, or correct identity.databaseId"
        .to_owned()
}

/// What `caseworkctl plan` reports. It is read in a read-only transaction.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationPlan {
    pub active: Option<Activation>,
    pub candidate_package_digest: String,
    pub database_id_check: DatabaseIdCheck,
    pub plan_kind: PlanKind,
    /// The newest applied schema version, or none on an empty database.
    pub schema_version: Option<i64>,
    pub supported_schema_version: i64,
    pub pending_schema_versions: Vec<i64>,
    /// Absent when the schema is too old to read before migrating, or when
    /// the runtime role lacks SELECT on a Casework table until apply
    /// reissues its grants.
    pub effects: Option<ActivationEffects>,
    pub refusals: Vec<ActivationRefusal>,
    /// The role mode the planning connection's authority gives it, absent
    /// when it cannot see the ledger yet. `caseworkctl plan` connects with
    /// the runtime credential, so this is the runtime role's mode.
    pub runtime_role_mode: Option<RoleMode>,
    /// Whether apply would record an activation.
    pub changes_pending: bool,
}

/// What `caseworkctl apply` recorded.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationApplied {
    pub activation: Activation,
    pub schema_versions_applied: Vec<i64>,
    pub effects: ActivationEffects,
}

/// What `caseworkctl status` reports.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationStatus {
    pub active: Option<Activation>,
    /// Every ledger row, oldest first.
    pub history: Vec<Activation>,
    pub schema_version: Option<i64>,
    pub supported_schema_version: i64,
    /// The role mode this connection has, absent before the first apply.
    pub role_mode: Option<RoleMode>,
}

/// A refused or failed activation.
#[derive(Debug, thiserror::Error)]
pub enum ActivationError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("{}", describe_refusals(.0))]
    Refused(Vec<ActivationRefusal>),
    /// The activation committed, but the audit destination did not accept
    /// its response entry.
    #[error(
        "package {package_digest} is active as activation {activation_id}, but the audit destination did not accept the activation's response entry; restore the audit destination, then confirm the activation with `caseworkctl status --runtime-config FILE`"
    )]
    AppliedUnaudited {
        activation_id: Uuid,
        package_digest: String,
    },
}

fn describe_refusals(refusals: &[ActivationRefusal]) -> String {
    refusals
        .iter()
        .map(|refusal| refusal.message.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

/// The read-only state an activation starts from.
struct Analysis {
    active: Option<Activation>,
    database_id_check: DatabaseIdCheck,
    schema_version: Option<i64>,
    pending_schema_versions: Vec<i64>,
    effects: Option<ActivationEffects>,
    refusals: Vec<ActivationRefusal>,
}

impl PostgresStore {
    /// Read what applying `candidate` would do, in a read-only transaction.
    /// It writes nothing and works against an empty database. It reads the
    /// ledger and the effects from one snapshot, so an apply that commits
    /// while it runs cannot change them between reads.
    pub async fn plan_activation(
        &self,
        candidate: &ActivationCandidate<'_>,
    ) -> Result<ActivationPlan, StoreError> {
        let mut client = self.client().await?;
        let transaction = client
            .build_transaction()
            .read_only(true)
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await?;
        if let Some(schema) = unreadable_ledger(&transaction).await? {
            return Err(StoreError::LedgerUnreadable { schema });
        }
        let observation = observe_role(&transaction, None).await?;
        // A runtime role that lost SELECT on a Casework table, as reassigning
        // the table to the migration role takes it, cannot read the effects;
        // apply, which reissues the grants, evaluates them.
        let readable = observation.is_none_or(|observation| observation.readable);
        let mut analysis = analyze(&transaction, candidate, observation, readable).await?;
        // Before the first apply the migration role is unknown, so the check
        // starts once the ledger names it as its owner.
        if observation.is_some() {
            let stray = stray_authority(&transaction, None).await?;
            if !stray.is_empty() {
                analysis
                    .refusals
                    .push(ActivationRefusal::role_mode_weakened(&stray));
            }
        }
        transaction.commit().await?;
        Ok(ActivationPlan {
            runtime_role_mode: observation.map(|observation| observation.mode),
            plan_kind: plan_kind(analysis.active.as_ref()),
            active: analysis.active,
            candidate_package_digest: candidate.package_digest.to_owned(),
            database_id_check: analysis.database_id_check,
            schema_version: analysis.schema_version,
            supported_schema_version: SUPPORTED_SCHEMA_VERSION,
            pending_schema_versions: analysis.pending_schema_versions,
            effects: analysis.effects,
            changes_pending: analysis.refusals.is_empty(),
            refusals: analysis.refusals,
        })
    }

    /// Apply `candidate` in one transaction under the migration lock and
    /// record it as the active package. Call it on a store connected with
    /// the migration credential and holding the operator audit destination.
    /// `runtime_user` is the PostgreSQL role the runtime credential connects
    /// as. When it is a different role from this connection's, apply grants
    /// it the service's privileges without write access to the ledgers, and
    /// records the activation split-role only if, after those grants, the
    /// role still cannot write the activation ledger.
    ///
    /// The audit `request` entry is accepted before the transaction opens,
    /// and the `response` entry follows the commit. Any refusal rolls the
    /// whole transaction back and is answered `refused`. A response entry
    /// the destination refuses after the commit is reported as
    /// [`ActivationError::AppliedUnaudited`], never as a failed activation.
    pub async fn apply_activation(
        &self,
        runtime_user: &str,
        candidate: &ActivationCandidate<'_>,
        request: &ApplyRequest,
    ) -> Result<ActivationApplied, ActivationError> {
        request.validate()?;
        let identifiers = self.audit_identifiers()?;
        let mut audit = self
            .begin_audit_with_schema(
                ACTIVATION_AUDIT_SCHEMA,
                json!({
                    "event": ACTIVATION_EVENT,
                    "profileId": OPERATOR_PROFILE,
                    "packageDigest": candidate.package_digest,
                }),
            )
            .await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await.map_err(StoreError::from)?;
        let applied = apply_in(
            &transaction,
            &mut audit,
            &identifiers,
            runtime_user,
            candidate,
            request,
        )
        .await;
        match applied {
            Ok(applied) => {
                if let Err(error) = audit.commit(transaction).await {
                    // The commit may have taken effect before the response
                    // entry was refused; the ledger says which.
                    return Err(
                        if self
                            .activation_recorded(applied.activation.activation_id)
                            .await?
                        {
                            ActivationError::AppliedUnaudited {
                                activation_id: applied.activation.activation_id,
                                package_digest: applied.activation.package_digest,
                            }
                        } else {
                            error.into()
                        },
                    );
                }
                if applied.effects.pinned_work.verdict == "acknowledged" {
                    tracing::warn!(
                        stranded = %crate::describe_stranded_work(&applied.effects.pinned_work.stranded),
                        "activated an acknowledged Casework policy package that strands pinned work"
                    );
                }
                Ok(applied)
            }
            Err(error) => {
                drop(transaction);
                let outcome = match &error {
                    ActivationError::Refused(_) => AuditOutcome::Refused,
                    ActivationError::Store(_) | ActivationError::AppliedUnaudited { .. } => {
                        AuditOutcome::Failed
                    }
                };
                audit.conclude_without_change(outcome).await?;
                Err(error)
            }
        }
    }

    /// The ledger, schema version, and this connection's role mode, read in
    /// a read-only transaction.
    pub async fn activation_status(&self) -> Result<ActivationStatus, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.build_transaction().read_only(true).start().await?;
        let schema_version = schema_version(&transaction).await?;
        let history = activation_history(&transaction).await?;
        let role_mode = observe_role(&transaction, None)
            .await?
            .map(|observation| observation.mode);
        transaction.commit().await?;
        Ok(ActivationStatus {
            active: history.last().cloned(),
            history,
            schema_version,
            supported_schema_version: SUPPORTED_SCHEMA_VERSION,
            role_mode,
        })
    }

    /// The active package's ledger row, if any package was applied.
    pub async fn active_activation(&self) -> Result<Option<Activation>, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.build_transaction().read_only(true).start().await?;
        let active = latest_activation(&transaction).await?;
        transaction.commit().await?;
        Ok(active)
    }

    /// The role mode this connection's authority gives it: `split` when it
    /// cannot write the activation ledger by privilege, ownership, or
    /// attribute. Absent before the first apply.
    pub async fn effective_role_mode(&self) -> Result<Option<RoleMode>, StoreError> {
        Ok(self.effective_role().await?.map(|(mode, _)| mode))
    }

    /// [`Self::effective_role_mode`] and whether this connection's role holds
    /// every grant a split-role apply issues it.
    pub(crate) async fn effective_role(&self) -> Result<Option<(RoleMode, bool)>, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.build_transaction().read_only(true).start().await?;
        let role = observe_role(&transaction, None)
            .await?
            .map(|observation| (observation.mode, observation.grants_current));
        transaction.commit().await?;
        Ok(role)
    }

    /// What to do about a split-role activation whose runtime role can now
    /// write the activation ledger: take away the ownership, privilege, or
    /// trigger that gives it that authority, or else rerun apply, which
    /// reissues the grants or records the single-role mode.
    pub(crate) async fn role_mode_weakened_fix(&self) -> Result<String, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.build_transaction().read_only(true).start().await?;
        let stray = stray_authority(&transaction, None).await?;
        transaction.commit().await?;
        Ok(if stray.is_empty() {
            "run `caseworkctl plan --runtime-config FILE` then `caseworkctl apply \
             --runtime-config FILE` to reissue the runtime role's grants or record the \
             single-role mode"
                .to_owned()
        } else {
            stray_authority_fix(&stray)
        })
    }

    /// Whether the ledger holds the activation `activation_id`, read on a
    /// connection outside any transaction.
    async fn activation_recorded(&self, activation_id: Uuid) -> Result<bool, StoreError> {
        let client = self.client().await?;
        platform_activation::activation_recorded(&**client, &activation_layout(), activation_id)
            .await
            .map_err(platform_error)
    }

    /// The PostgreSQL role this store connects as.
    pub async fn current_user(&self) -> Result<String, StoreError> {
        let client = self.client().await?;
        Ok(client
            .query_one("SELECT current_user::text", &[])
            .await?
            .get(0))
    }

    /// Whether `generation` is the recorded binding generation of
    /// `source_id`.
    pub async fn source_generation_registered(
        &self,
        source_id: &str,
        generation: &str,
    ) -> Result<bool, StoreError> {
        let client = self.client().await?;
        Ok(client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM casework_source_reconciliation_progress WHERE source_id=$1 AND binding_generation=$2)",
                &[&source_id, &generation],
            )
            .await?
            .get(0))
    }
}

async fn apply_in(
    transaction: &Transaction<'_>,
    audit: &mut crate::audit::AuditOperation,
    identifiers: &registry_platform_audit::AuditKeyHasher,
    runtime_user: &str,
    candidate: &ActivationCandidate<'_>,
    request: &ApplyRequest,
) -> Result<ActivationApplied, ActivationError> {
    transaction
        .query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_KEY])
        .await
        .map_err(StoreError::from)?;
    // Lock order. A runtime transaction that reads or changes the Directory
    // takes the casework_meta singleton first, and source reconciliation
    // takes its progress rows before it reads or rebinds subjects. Apply
    // takes both, in that order, before any migration DDL, so it never holds
    // a DDL lock while it waits for a runtime transaction that would in turn
    // wait for that DDL.
    lock_runtime_order(transaction).await?;
    let current_user: String = transaction
        .query_one("SELECT current_user::text", &[])
        .await
        .map_err(StoreError::from)?
        .get(0);
    let split = current_user != runtime_user;
    if split {
        let mut stray = stray_authority(transaction, Some(runtime_user)).await?;
        stray.extend(default_trigger_grant(transaction, runtime_user).await?);
        if !stray.is_empty() {
            return Err(ActivationError::Refused(vec![
                ActivationRefusal::role_mode_weakened(&stray),
            ]));
        }
    }
    let observation = if split {
        observe_role(transaction, Some(runtime_user)).await?
    } else {
        Some(RoleObservation {
            mode: RoleMode::Single,
            grants_current: true,
            readable: true,
        })
    };
    // Every refusal known from the ledger and the schema is raised here,
    // before any statement that changes anything.
    let before = analyze(transaction, candidate, observation, true).await?;
    let early: Vec<_> = before
        .refusals
        .iter()
        .filter(|refusal| before.effects.is_none() || is_ledger_refusal(refusal))
        .cloned()
        .collect();
    if !early.is_empty() {
        return Err(ActivationError::Refused(early));
    }
    if !before.refusals.is_empty() {
        return Err(ActivationError::Refused(before.refusals));
    }
    let schema_versions_applied = match migrate_in(transaction).await {
        Ok(versions) => versions,
        Err(error) if migration_refusal_code(&error).is_some() => {
            return Err(ActivationError::Refused(vec![ActivationRefusal::new(
                migration_refusal_code(&error).expect("matched a migration refusal"),
                "database",
                error.to_string(),
            )]));
        }
        Err(error) => return Err(error.into()),
    };
    let (effects, refusals) = evaluate_effects(transaction, candidate).await?;
    if !refusals.is_empty() {
        return Err(ActivationError::Refused(refusals));
    }
    for adapter in candidate.adapters {
        register_source_generation_in(
            transaction,
            adapter.source_id(),
            adapter.binding_generation(),
        )
        .await?;
    }
    crate::task_grants::activate_task_templates_in(
        transaction,
        audit,
        &candidate.project.task_templates,
    )
    .await?;
    let activation_id = Uuid::new_v4();
    let operator_reference_hash = request
        .operator_reference
        .as_deref()
        .map(|reference| {
            identifiers
                .audit_reference_hash(
                    OPERATOR_REFERENCE_HASH_CLASS,
                    &activation_id.to_string(),
                    reference,
                )
                .map_err(|_| StoreError::Invalid)
        })
        .transpose()?;
    // The role mode is what the runtime role can do once the grants are
    // issued, never only whether the two credentials name different roles.
    let role_mode = if split {
        grant_runtime_role(transaction, runtime_user).await?;
        observe_role(transaction, Some(runtime_user))
            .await?
            .map_or(RoleMode::Single, |observation| observation.mode)
    } else {
        RoleMode::Single
    };
    let activation = platform_activation::append_activation(
        transaction,
        &activation_layout(),
        &NewActivation {
            activation_id,
            package_digest: candidate.package_digest,
            database_id: candidate.database_id,
            operator_reference_hash: operator_reference_hash.as_deref(),
            backup_references: &request.backup_references,
            role_mode,
            runtime_role: None,
        },
    )
    .await
    .map_err(platform_error)?;
    audit.record(
        activation_id,
        json!({
            "event": ACTIVATION_EVENT,
            "profileId": OPERATOR_PROFILE,
            "activationId": activation.activation_id,
            "packageDigest": activation.package_digest,
            "predecessorPackageDigest": activation.predecessor_package_digest,
            "planKind": activation.plan_kind.as_str(),
            "roleMode": activation.role_mode.as_str(),
            "operatorReferenceHash": activation.operator_reference_hash,
            "schemaVersionsApplied": schema_versions_applied,
            "outcome": "applied",
        }),
    )?;
    Ok(ActivationApplied {
        activation,
        schema_versions_applied,
        effects,
    })
}

fn is_ledger_refusal(refusal: &ActivationRefusal) -> bool {
    ["database-id-mismatch", "already-active", "schema-newer"]
        .iter()
        .any(|code| refusal.code == format!("{REFUSAL_PREFIX}.{code}"))
}

fn plan_kind(active: Option<&Activation>) -> PlanKind {
    if active.is_some() {
        PlanKind::Successor
    } else {
        PlanKind::Initial
    }
}

/// The refusal code for a schema migration this release declines to run,
/// or none for a failure that is not the operator's to correct.
fn migration_refusal_code(error: &StoreError) -> Option<&'static str> {
    match error {
        StoreError::SchemaNewer { .. } => Some("schema-newer"),
        StoreError::HostedWorkWouldBeDropped { .. } => Some("hosted-work-would-be-dropped"),
        StoreError::UnpublishedAuditWouldBeDropped { .. } => {
            Some("unpublished-audit-would-be-dropped")
        }
        _ => None,
    }
}

/// Read, without writing, every refusal and effect applying `candidate`
/// would meet. `role` is the runtime role's observed authority; an active
/// package is already active only when the ledger row records that role's
/// mode and, split-role, the role holds every grant apply issues. Effects
/// are evaluated only when `readable`, and without them the active package
/// is never already active.
async fn analyze(
    transaction: &Transaction<'_>,
    candidate: &ActivationCandidate<'_>,
    role: Option<RoleObservation>,
    readable: bool,
) -> Result<Analysis, StoreError> {
    let applied = applied_versions(transaction).await?;
    let schema_version = applied.last().copied();
    let mut refusals = Vec::new();
    if let Some(found) = schema_version.filter(|found| *found > SUPPORTED_SCHEMA_VERSION) {
        refusals.push(ActivationRefusal::new(
            "schema-newer",
            "database",
            StoreError::SchemaNewer {
                found,
                supported: SUPPORTED_SCHEMA_VERSION,
            }
            .to_string(),
        ));
        return Ok(Analysis {
            active: latest_activation(transaction).await?,
            database_id_check: DatabaseIdCheck::NotRecorded,
            schema_version,
            pending_schema_versions: Vec::new(),
            effects: None,
            refusals,
        });
    }
    let applied: BTreeSet<i64> = applied.into_iter().collect();
    let pending_schema_versions: Vec<i64> = MIGRATIONS
        .iter()
        .map(|(version, _)| *version)
        .filter(|version| !applied.contains(version))
        .collect();
    let active = latest_activation(transaction).await?;
    let database_id_check =
        platform_activation::database_id_check(active.as_ref(), candidate.database_id);
    if database_id_check == DatabaseIdCheck::Differs {
        refusals.push(ActivationRefusal::database_id_mismatch());
    }
    for refusal in pending_migration_refusals(transaction, &pending_schema_versions).await? {
        refusals.push(ActivationRefusal::new(
            migration_refusal_code(&refusal).expect("a destructive-migration refusal"),
            "database",
            refusal.to_string(),
        ));
    }
    let effects = match schema_version {
        None => Some(empty_database_effects(candidate, &mut refusals)),
        Some(version) if version >= EFFECTS_SCHEMA_VERSION && readable => {
            let (effects, effect_refusals) = evaluate_effects(transaction, candidate).await?;
            refusals.extend(effect_refusals);
            Some(effects)
        }
        Some(_) => None,
    };
    if let (Some(active), Some(effects)) = (&active, &effects) {
        if active.package_digest == candidate.package_digest
            && pending_schema_versions.is_empty()
            && effects.changes_nothing()
            && database_id_check == DatabaseIdCheck::Matches
            && role.is_none_or(|role| {
                role.mode == active.role_mode
                    && (role.mode == RoleMode::Single || role.grants_current)
            })
        {
            refusals.push(ActivationRefusal::new(
                "already-active",
                "runtime.yaml:/package",
                format!(
                    "package {} is already the active package in this database; nothing needs applying",
                    active.package_digest
                ),
            ));
        }
    }
    Ok(Analysis {
        active,
        database_id_check,
        schema_version,
        pending_schema_versions,
        effects,
        refusals,
    })
}

/// The effects of the first activation of an empty database: nothing is
/// pinned, every source generation is recorded, and every template is added.
fn empty_database_effects(
    candidate: &ActivationCandidate<'_>,
    refusals: &mut Vec<ActivationRefusal>,
) -> ActivationEffects {
    let mut task_templates = Vec::new();
    for template in &candidate.project.task_templates {
        match template_document(template) {
            Ok(_) => task_templates.push(TaskTemplateEffect {
                template_id: template.id.clone(),
                template_version: template.version.clone(),
                change: TemplateChange::Added,
            }),
            Err(refusal) => refusals.push(refusal),
        }
    }
    ActivationEffects {
        pinned_work: PinnedWorkEffect {
            verdict: "clear",
            stranded: Vec::new(),
        },
        source_generations: candidate
            .adapters
            .iter()
            .map(|adapter| SourceGenerationEffect {
                source_id: adapter.source_id().to_owned(),
                change: GenerationChange::Registered,
            })
            .collect(),
        task_templates,
    }
}

/// Read the pinned-work verdict, source generation changes, and task
/// template changes against a schema at least [`EFFECTS_SCHEMA_VERSION`].
async fn evaluate_effects(
    transaction: &Transaction<'_>,
    candidate: &ActivationCandidate<'_>,
) -> Result<(ActivationEffects, Vec<ActivationRefusal>), StoreError> {
    let mut refusals = Vec::new();
    let inventory = pinned_work_inventory_in(transaction).await?;
    let stranded = compare_pinned_work(candidate.project, candidate.adapters, &inventory);
    let verdict = match crate::pinned_work_verdict(
        &stranded,
        candidate.package_digest,
        candidate.acknowledged_stranded_work,
    ) {
        PinnedWorkVerdict::Clear => "clear",
        PinnedWorkVerdict::Acknowledged => "acknowledged",
        PinnedWorkVerdict::Refused => {
            refusals.push(ActivationRefusal::new(
                "stranded-work",
                "runtime.yaml:/package/acknowledgeStrandedWork",
                crate::stranded_work_refusal(&stranded, candidate.package_digest),
            ));
            "refused"
        }
    };
    let mut source_generations = Vec::with_capacity(candidate.adapters.len());
    for adapter in candidate.adapters {
        let source_id = adapter.source_id();
        let generation = adapter.binding_generation();
        let row = transaction
            .query_one(
                "SELECT
                   EXISTS(SELECT 1 FROM casework_attempts a JOIN casework_items i ON i.item_id=a.item_id JOIN casework_subjects s ON s.source_id=i.source_id AND s.subject_kind=i.subject_kind AND s.subject_id=i.subject_id WHERE s.source_id=$1 AND s.binding_generation<>$2 AND a.state IN ('pending','uncertain')),
                   EXISTS(SELECT 1 FROM casework_source_reconciliation_progress WHERE source_id=$1 AND binding_generation=$2),
                   EXISTS(SELECT 1 FROM casework_source_reconciliation_progress WHERE source_id=$1 AND binding_generation<>$2)
                   OR EXISTS(SELECT 1 FROM casework_subjects WHERE source_id=$1 AND binding_generation<>$2 AND erased_at IS NULL)",
                &[&source_id, &generation],
            )
            .await?;
        let (pending, recorded, other): (bool, bool, bool) = (row.get(0), row.get(1), row.get(2));
        if pending {
            refusals.push(ActivationRefusal::new(
                "attempt-pending",
                format!("runtime.yaml:/sources/{source_id}"),
                format!(
                    "source {source_id} has a source attempt still pending or uncertain under its previous binding generation; settle it with `caseworkctl attempt settle` (after `caseworkctl attempt mark-uncertain` for an expired lease), then {PLAN_THEN_APPLY}"
                ),
            ));
        }
        let change = if other {
            GenerationChange::Changed
        } else if recorded {
            GenerationChange::Unchanged
        } else {
            GenerationChange::Registered
        };
        source_generations.push(SourceGenerationEffect {
            source_id: source_id.to_owned(),
            change,
        });
    }
    let mut task_templates = Vec::new();
    let mut configured = BTreeSet::new();
    let stored: BTreeMap<(String, String), (Value, bool)> = transaction
        .query(
            "SELECT template_id,template_version,document,active FROM casework_task_templates",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| ((row.get(0), row.get(1)), (row.get(2), row.get(3))))
        .collect();
    for template in &candidate.project.task_templates {
        configured.insert((template.id.clone(), template.version.clone()));
        let document = match template_document(template) {
            Ok(document) => document,
            Err(refusal) => {
                refusals.push(refusal);
                continue;
            }
        };
        let change = match stored.get(&(template.id.clone(), template.version.clone())) {
            None => TemplateChange::Added,
            Some((stored, _)) if *stored != document => {
                refusals.push(ActivationRefusal::new(
                    "template-changed",
                    "casework.yaml:/taskTemplates",
                    format!(
                        "task template {} version {} is already stored with a different definition, and a stored version never changes; give the changed template a new version, package the project again, then {PLAN_THEN_APPLY}",
                        template.id, template.version
                    ),
                ));
                continue;
            }
            Some((_, true)) => TemplateChange::Retained,
            Some((_, false)) => TemplateChange::Activated,
        };
        task_templates.push(TaskTemplateEffect {
            template_id: template.id.clone(),
            template_version: template.version.clone(),
            change,
        });
    }
    for ((template_id, template_version), (_, active)) in &stored {
        if *active && !configured.contains(&(template_id.clone(), template_version.clone())) {
            task_templates.push(TaskTemplateEffect {
                template_id: template_id.clone(),
                template_version: template_version.clone(),
                change: TemplateChange::Deactivated,
            });
        }
    }
    Ok((
        ActivationEffects {
            pinned_work: PinnedWorkEffect { verdict, stranded },
            source_generations,
            task_templates,
        },
        refusals,
    ))
}

fn template_document(template: &TaskTemplate) -> Result<Value, ActivationRefusal> {
    let too_large = || {
        ActivationRefusal::new(
            "template-too-large",
            "casework.yaml:/taskTemplates",
            format!(
                "task template {} version {} is larger than {MAX_TASK_TEMPLATE_BYTES} bytes once serialized; shorten it, package the project again, then {PLAN_THEN_APPLY}",
                template.id, template.version
            ),
        )
    };
    let document = serde_json::to_value(template).map_err(|_| too_large())?;
    let bytes = serde_json::to_vec(&document).map_err(|_| too_large())?;
    if bytes.len() > MAX_TASK_TEMPLATE_BYTES {
        return Err(too_large());
    }
    Ok(document)
}

async fn applied_versions(transaction: &Transaction<'_>) -> Result<Vec<i64>, StoreError> {
    let versions: Vec<i64> = MIGRATIONS.iter().map(|(version, _)| *version).collect();
    platform_activation::schema_state(transaction, &activation_layout(), &versions)
        .await
        .map(|state| state.applied)
        .map_err(platform_error)
}

async fn schema_version(transaction: &Transaction<'_>) -> Result<Option<i64>, StoreError> {
    Ok(applied_versions(transaction).await?.last().copied())
}

async fn relation_exists(transaction: &Transaction<'_>, name: &str) -> Result<bool, StoreError> {
    platform_activation::relation_exists(transaction, name)
        .await
        .map_err(platform_error)
}

async fn latest_activation(
    transaction: &Transaction<'_>,
) -> Result<Option<Activation>, StoreError> {
    platform_activation::active_activation(transaction, &activation_layout())
        .await
        .map_err(platform_error)
}

async fn activation_history(transaction: &Transaction<'_>) -> Result<Vec<Activation>, StoreError> {
    platform_activation::activation_history(transaction, &activation_layout())
        .await
        .map_err(platform_error)
}

/// Take the row locks runtime transactions take first, in their order: the
/// casework_meta singleton, then every source reconciliation progress row.
/// A database with neither relation has no runtime to wait for.
async fn lock_runtime_order(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    if relation_exists(transaction, "casework_meta").await? {
        transaction
            .query(
                "SELECT 1 FROM casework_meta WHERE singleton=true FOR UPDATE",
                &[],
            )
            .await?;
    }
    if relation_exists(transaction, "casework_source_reconciliation_progress").await? {
        transaction
            .query(
                "SELECT 1 FROM casework_source_reconciliation_progress ORDER BY source_id,binding_generation FOR UPDATE",
                &[],
            )
            .await?;
    }
    Ok(())
}

/// The schema holding the activation ledger this connection's search path
/// reaches first, when this connection's role cannot read that ledger: it
/// lacks USAGE on the schema, which hides the ledger so the database would
/// read as empty, or SELECT on `casework_activations` or
/// `casework_schema_migrations`, as a rotated runtime role does before apply
/// grants it. `pg_class` names the ledger whatever the role may use.
async fn unreadable_ledger(transaction: &Transaction<'_>) -> Result<Option<String>, StoreError> {
    platform_activation::unreadable_ledger(transaction, &activation_layout())
        .await
        .map_err(platform_error)
}

/// The authority of `role`, or of this connection's role when none is
/// given, over the activation ledger. The role is single-role when it can
/// write the ledger in any way: a superuser or row-security bypass attribute,
/// a delete or truncate privilege on either ledger, an insert or update
/// privilege on either ledger or on any of its columns, membership in
/// the ledger's or the schema's owner, or, when `role` is named, membership
/// in this connection's role. It is single-role too when it can reach the
/// ledger through code that runs as the migration role: it owns, or is a
/// member of the owner of, a Casework relation or function, holds TRIGGER on
/// a Casework table or view, or holds CREATE on the schema, or when a
/// trigger no Casework migration creates is attached to a Casework table.
/// Absent when the role cannot see the ledger.
async fn observe_role(
    transaction: &Transaction<'_>,
    role: Option<&str>,
) -> Result<Option<RoleObservation>, StoreError> {
    platform_activation::observe_role(transaction, &activation_layout(), role, &[])
        .await
        .map_err(platform_error)
}

/// The SQL statements that take away `role`'s authority to reach the
/// activation ledger through code that runs as the migration role, or this
/// connection's role's when none is given: reassign every Casework relation
/// or function a role it belongs to owns, revoke every CREATE grant on the
/// schema and every TRIGGER grant on a Casework table or view that reaches
/// it, `PUBLIC`'s included, and drop every trigger on a Casework table that
/// no Casework migration creates. `role` is measured against this
/// connection's role, the migration role; without one it is measured
/// against the ledger's owner. Empty when there is none of these, and for a
/// superuser or a member of the migration role or the schema owner, whose
/// authority no reassignment, revoke, or drop takes away.
async fn stray_authority(
    transaction: &Transaction<'_>,
    role: Option<&str>,
) -> Result<Vec<String>, StoreError> {
    platform_activation::stray_authority(transaction, &activation_layout(), role)
        .await
        .map_err(platform_error)
}

/// The `ALTER DEFAULT PRIVILEGES` statement that takes away a default
/// privilege of this connection's role, the migration role, granting
/// `role` TRIGGER on the tables it creates in the Casework schema, directly,
/// through `PUBLIC`, or through a role `role` belongs to. Apply refuses it
/// before any migration: a refusal after the migrations would name tables
/// its rollback removes, and apply never revokes TRIGGER itself.
async fn default_trigger_grant(
    transaction: &Transaction<'_>,
    role: &str,
) -> Result<Option<String>, StoreError> {
    platform_activation::default_trigger_grant(transaction, role)
        .await
        .map(|grant| grant.map(|grant| grant.statement()))
        .map_err(platform_error)
}

/// The next action for stray authority `statements` from
/// [`stray_authority`]. Reassigning an object to the migration role takes
/// the runtime role's grants on it too, so apply must reissue them; a revoke
/// or a drop takes nothing apply issued.
fn stray_authority_fix(statements: &[String]) -> String {
    let reassigns = statements
        .iter()
        .any(|statement| statement.starts_with("REASSIGN OWNED BY "));
    let statements = statements
        .iter()
        .map(|statement| format!("`{statement}`"))
        .collect::<Vec<_>>()
        .join(" and ");
    if reassigns {
        format!(
            "run {statements} as the migration role, then `caseworkctl apply --runtime-config \
             FILE` to reissue the runtime role's grants"
        )
    } else {
        format!(
            "run {statements} as the migration role, then rerun the command that refused, or \
             `caseworkctl plan --runtime-config FILE` to confirm"
        )
    }
}

/// Give `runtime_user` what the service needs in the Casework schema, and
/// take away its write access to both ledgers. A TRIGGER privilege it holds
/// was already refused by [`stray_authority`]. Every statement is
/// idempotent, and every split-role apply reissues them.
async fn grant_runtime_role(
    transaction: &Transaction<'_>,
    runtime_user: &str,
) -> Result<(), StoreError> {
    platform_activation::grant_runtime_role(transaction, &activation_layout(), runtime_user, &[])
        .await
        .map_err(platform_error)
}

#[cfg(test)]
mod tests {
    use super::{DatabaseIdCheck, MIGRATIONS, MIGRATION_TRIGGERS};

    /// CFG-NAME-2: the comparison a plan report states is a kebab-case value.
    #[test]
    fn cfg_name_2_the_database_id_check_is_written_in_kebab_case() {
        for (check, written) in [
            (DatabaseIdCheck::NotRecorded, "\"not-recorded\""),
            (DatabaseIdCheck::Matches, "\"matches\""),
            (DatabaseIdCheck::Differs, "\"differs\""),
        ] {
            assert_eq!(serde_json::to_string(&check).unwrap(), written);
        }
    }

    /// Every `CREATE TRIGGER` in the migrations, as table, trigger, and
    /// function.
    fn created_triggers() -> Vec<(String, String, String)> {
        let mut found = Vec::new();
        for (_, sql) in MIGRATIONS {
            let words: Vec<String> = sql
                .split(|c: char| c.is_whitespace() || c == '(' || c == ';')
                .filter(|word| !word.is_empty())
                .map(str::to_owned)
                .collect();
            for (at, word) in words.iter().enumerate() {
                // CREATE TRIGGER, CREATE OR REPLACE TRIGGER, and CREATE
                // CONSTRAINT TRIGGER.
                if !word.eq_ignore_ascii_case("TRIGGER")
                    || at == 0
                    || !["CREATE", "REPLACE", "CONSTRAINT"]
                        .iter()
                        .any(|before| words[at - 1].eq_ignore_ascii_case(before))
                {
                    continue;
                }
                let rest = &words[at + 1..];
                let table = rest
                    .iter()
                    .position(|word| word.eq_ignore_ascii_case("ON"))
                    .map(|on| rest[on + 1].clone())
                    .expect("a trigger names its table");
                let function = rest
                    .iter()
                    .position(|word| word.eq_ignore_ascii_case("FUNCTION"))
                    .map(|function| rest[function + 1].clone())
                    .expect("a trigger names its function");
                found.push((table, rest[0].clone(), function));
            }
        }
        found.sort();
        found
    }

    #[test]
    fn the_known_triggers_are_exactly_the_ones_the_migrations_create() {
        let mut known: Vec<_> = MIGRATION_TRIGGERS
            .iter()
            .map(|known| {
                (
                    known.relation.to_owned(),
                    known.trigger.to_owned(),
                    known.function.to_owned(),
                )
            })
            .collect();
        known.sort();
        assert_eq!(created_triggers(), known);
    }
}

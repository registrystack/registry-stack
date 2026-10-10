//! The activation ledger and the one transaction that accepts a package.
//!
//! A database serves the verified Scheduling package its ledger names: the
//! `scheduling_activations` row with the greatest `apply_order`. Only
//! `schedulingctl apply` writes that ledger, with the migration credential,
//! and it migrates the schema, adopts the deployment identity, publishes the
//! policy, and records the row in one transaction under the migration lock.
//! Startup, `schedulingctl plan`, and `schedulingctl status` read it and write
//! nothing.

use std::future::Future;

use registry_platform_activation::{self as platform_activation, Layout, NewActivation};
use registry_scheduling_core::SchedulingPolicy;
use tokio_postgres::GenericClient;
use uuid::Uuid;

use super::{
    check_policy_publication, current_schema_in, lock_publication, publish_policy,
    refuse_combined_conflicts, PolicyPublication, PostgresStore, StoreError, ACTIVATIONS_MIGRATION,
    ACTIVATIONS_MIGRATION_VERSION, ATTEMPT_KEY_REFERENCE_MIGRATION,
    ATTEMPT_KEY_REFERENCE_MIGRATION_VERSION, AUDIT_WRITER_MIGRATION,
    AUDIT_WRITER_MIGRATION_VERSION, CLAIM_OWNER_MIGRATION, CLAIM_OWNER_MIGRATION_VERSION,
    DUPLICATE_LOOKUP_INDEX_MIGRATION, DUPLICATE_LOOKUP_INDEX_MIGRATION_VERSION,
    EXTERNAL_REFERENCES_MIGRATION, EXTERNAL_REFERENCES_MIGRATION_VERSION, FACTS_REVISION_MIGRATION,
    HOOK_DELIVERY_MIGRATION_VERSION, MIGRATION_LOCK_KEY, POLICY_DOCUMENT_MIGRATION,
    POLICY_DOCUMENT_MIGRATION_VERSION, SCHEDULING_MIGRATION, SCHEMA_VERSIONS,
    WINDOW_RECORDS_MIGRATION, WINDOW_RECORDS_MIGRATION_VERSION, WINDOW_REVISION_HEADS_MIGRATION,
    WINDOW_REVISION_HEADS_MIGRATION_VERSION,
};

/// Said wherever the effective role mode is `single`.
pub use registry_platform_activation::{Activation, RoleMode, SINGLE_ROLE_STATEMENT};

fn activation_layout() -> Layout {
    Layout::new(
        "scheduling",
        "scheduling_activations",
        "scheduling_schema_migrations",
        &[],
        true,
    )
    .expect("the Scheduling activation layout uses static PostgreSQL identifiers")
    .with_sequence_select()
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

/// The schema versions a database holds, and the ones this release would
/// still apply.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SchemaState {
    pub applied: Vec<i64>,
    pub pending: Vec<i64>,
}

impl SchemaState {
    /// Refuse a version this release does not know: a newer one belongs to
    /// a later release, and an unknown older one is a damaged ledger.
    pub fn check(&self) -> Result<(), StoreError> {
        let newest = SCHEMA_VERSIONS[SCHEMA_VERSIONS.len() - 1];
        for version in &self.applied {
            if !SCHEMA_VERSIONS.contains(version) {
                return Err(if *version > newest {
                    StoreError::SchemaNewer { version: *version }
                } else {
                    StoreError::Corrupt
                });
            }
        }
        Ok(())
    }

    /// The greatest applied version, or zero on an empty database.
    #[must_use]
    pub fn current(&self) -> i64 {
        self.applied.iter().copied().max().unwrap_or(0)
    }
}

/// The deployment identity and policy the database serves now.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeployedPolicy {
    pub scheduling_id: String,
    pub policy_revision: i64,
    pub policy_digest: String,
}

/// The activation a records swap answers to: the database identity and the
/// package the operator's configuration names.
#[derive(Clone, Copy, Debug)]
pub struct ActivePackage<'a> {
    pub database_id: &'a str,
    pub package_digest: &'a str,
}

/// Everything one apply records.
#[derive(Clone, Debug)]
pub struct ActivationRequest<'a> {
    pub activation_id: Uuid,
    pub package_digest: &'a str,
    pub database_id: &'a str,
    pub policy: &'a SchedulingPolicy,
    pub operator_reference_hash: Option<&'a str>,
    pub backup_references: &'a [String],
    /// `split` when the runtime and migration credentials are different
    /// users, so apply grants the runtime role the service's privileges and
    /// withholds the ledger's. The mode recorded is the one the runtime role
    /// holds after those grants.
    pub role_mode: RoleMode,
    /// The PostgreSQL user the runtime credential connects as.
    pub runtime_role: &'a str,
}

/// What one committed apply did.
#[derive(Clone, Debug)]
pub struct ActivationOutcome {
    pub activation: Activation,
    pub schema_versions_applied: Vec<i64>,
    pub publication: PolicyPublication,
    /// Whether this apply claimed an unadopted database for the policy's
    /// scheduling id.
    pub scheduling_id_adopted: bool,
}

/// What an apply of the candidate would do, read without writing.
#[derive(Debug)]
pub struct ActivationPlan {
    pub active: Option<Activation>,
    pub schema: SchemaState,
    pub deployed: Option<DeployedPolicy>,
    /// The policy publication apply would make. Absent while schema versions
    /// the policy check reads are still pending: apply runs the check inside
    /// its transaction once they are applied.
    pub publication: Option<PolicyPublication>,
    /// Whether retained hook bindings were verified against the candidate.
    /// Absent when the database retains no hook state to verify.
    pub retained_hook_bindings_verified: Option<bool>,
    /// Every refusal apply would raise that is known without writing.
    pub refusals: Vec<StoreError>,
    /// The PostgreSQL user the planning credential connects as.
    pub runtime_role: String,
    /// The role mode that user holds over the ledger now, or none before
    /// the first apply created it.
    pub effective_role_mode: Option<RoleMode>,
    /// Whether an apply of the candidate would record an activation: false
    /// whenever the plan names a refusal.
    pub changes_pending: bool,
}

impl PostgresStore {
    /// The active package, or none on a database no apply has accepted.
    pub async fn active_activation(&self) -> Result<Option<Activation>, StoreError> {
        let client = self.client().await?;
        active_activation_in(&**client).await
    }

    /// Refuse unless the ledger names this deployment and package.
    pub async fn check_active_package(
        &self,
        expected: &ActivePackage<'_>,
    ) -> Result<Activation, StoreError> {
        let client = self.client().await?;
        check_active_package_in(&**client, expected).await
    }

    /// Every accepted package, oldest first.
    pub async fn activation_history(&self) -> Result<Vec<Activation>, StoreError> {
        let client = self.client().await?;
        platform_activation::activation_history(&**client, &activation_layout())
            .await
            .map_err(platform_error)
    }

    /// The PostgreSQL user this store's credential connects as.
    pub async fn current_user(&self) -> Result<String, StoreError> {
        let client = self.client().await?;
        Ok(client
            .query_one("SELECT current_user::text", &[])
            .await?
            .get(0))
    }

    /// The role mode this store's credential holds over the activation
    /// ledger, or none before the first apply created it.
    pub async fn effective_role_mode(&self) -> Result<Option<RoleMode>, StoreError> {
        let client = self.client().await?;
        let user: String = client
            .query_one("SELECT current_user::text", &[])
            .await?
            .get(0);
        role_mode_in(&**client, &user, None).await
    }

    /// The refusal naming how this store's credential, a role other than the
    /// migration role, can still write the ledger indirectly, or none when it
    /// cannot.
    pub async fn split_weakness(&self) -> Result<Option<StoreError>, StoreError> {
        let client = self.client().await?;
        let user: String = client
            .query_one("SELECT current_user::text", &[])
            .await?
            .get(0);
        split_weakness_in(&**client, &user).await
    }

    /// The refusal naming a split runtime credential that no longer holds
    /// every grant apply issues it, or none when it does.
    pub async fn missing_runtime_grants(&self) -> Result<Option<StoreError>, StoreError> {
        let client = self.client().await?;
        let user: String = client
            .query_one("SELECT current_user::text", &[])
            .await?
            .get(0);
        Ok(
            (!grants_current_in(&**client, &user, Some(RoleMode::Split)).await?)
                .then_some(StoreError::RuntimeGrantsMissing(user)),
        )
    }

    /// Accept one package in one transaction under the migration lock:
    /// refuse a foreign database, or the package already active with nothing
    /// left to change, before any statement changes anything, then migrate,
    /// adopt the scheduling id, publish the policy, in split mode grant the
    /// runtime role the service's privileges without the ledger's, and
    /// record the ledger row with the role mode those grants leave it.
    ///
    /// `verify_retained` proves retained hook events stay deliverable under
    /// the candidate. It runs on its own connection against the committed
    /// state, before this transaction takes the publication locks, because
    /// the verification reads the meta row under a share lock.
    pub async fn activate<F, Fut>(
        &self,
        request: &ActivationRequest<'_>,
        verify_retained: F,
    ) -> Result<ActivationOutcome, StoreError>
    where
        F: FnOnce(DeployedPolicy) -> Fut,
        Fut: Future<Output = Result<(), StoreError>>,
    {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        transaction
            .execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_KEY])
            .await?;

        let active = active_activation_in(&*transaction).await?;
        let schema = schema_state_in(&*transaction).await?;
        let migration_role: String = transaction
            .query_one("SELECT current_user::text", &[])
            .await?
            .get(0);
        if let Some(active) = &active {
            if active.database_id != request.database_id {
                return Err(StoreError::DatabaseIdMismatch);
            }
            // A weakened split is named before any statement, since an
            // object the runtime role owns can also refuse the migration
            // role's own reads; the check after the grants covers the first
            // apply, which creates the ledger it reads.
            if request.role_mode == RoleMode::Split {
                if let Some(weakened) =
                    split_weakness_in(&*transaction, request.runtime_role).await?
                {
                    return Err(weakened);
                }
            }
            let mode_now =
                role_mode_in(&*transaction, request.runtime_role, Some(&migration_role)).await?;
            let grants_current =
                grants_current_in(&*transaction, request.runtime_role, mode_now).await?;
            if already_active(
                active,
                request.package_digest,
                request.runtime_role,
                mode_now,
                grants_current,
                &schema,
            ) {
                return Err(StoreError::PackageAlreadyActive {
                    digest: active.package_digest.clone(),
                });
            }
        }
        if request.role_mode == RoleMode::Split {
            if let Some(weakened) =
                default_trigger_grant_in(&*transaction, request.runtime_role).await?
            {
                return Err(weakened);
            }
        }
        schema.check()?;
        let deployed = deployed_policy_in(&*transaction).await?;
        if let Some(deployed) = &deployed {
            refuse_foreign_scheduling_id(deployed, request.policy)?;
            if retains_hook_state(deployed, &schema) {
                verify_retained(deployed.clone()).await?;
            }
        }

        // Lock order: the migration advisory lock, then every supply anchor
        // and the meta row, then the schema migrations. A capacity
        // transaction takes one anchor and then the meta row, so the
        // publication locks come before any migration DDL lock and a
        // migration never holds a table while it waits on an anchor. The
        // retained-binding check above runs before them on its own
        // connection, because it reads the meta row under a share lock. A
        // database without the supply and meta tables has no anchor to wait
        // on, so its publication locks are taken once migrations create them.
        let publication_locked = publication_tables_exist(&*transaction).await?;
        if publication_locked {
            lock_publication(&transaction).await?;
        }
        let schema_versions_applied = apply_migrations_in(&transaction).await?;
        if !publication_locked {
            lock_publication(&transaction).await?;
        }
        let scheduling_id_adopted = transaction
            .execute(
                "UPDATE scheduling_meta SET scheduling_id=$1, updated_at=now() \
                 WHERE singleton AND scheduling_id=''",
                &[&&*request.policy.project.id],
            )
            .await?
            == 1;
        let stored_id: String = transaction
            .query_one(
                "SELECT scheduling_id FROM scheduling_meta WHERE singleton",
                &[],
            )
            .await?
            .get(0);
        if stored_id != *request.policy.project.id {
            return Err(StoreError::DeploymentIdentity);
        }
        let publication =
            check_policy_publication(&transaction, self.observed_now(), request.policy).await?;
        publish_policy(
            &transaction,
            &publication,
            request.policy,
            &policy_pool_ids(request.policy),
        )
        .await?;

        if request.role_mode == RoleMode::Split {
            grant_runtime_role(&transaction, request.runtime_role).await?;
            if let Some(weakened) = split_weakness_in(&*transaction, request.runtime_role).await? {
                return Err(weakened);
            }
        }
        // The mode recorded is the authority the runtime role holds once the
        // grants are issued, which a membership or a superuser attribute can
        // make single even when the two credentials are different users.
        let role_mode = role_mode_in(&*transaction, request.runtime_role, Some(&migration_role))
            .await?
            .ok_or(StoreError::Corrupt)?;
        let activation = platform_activation::append_activation(
            &*transaction,
            &activation_layout(),
            &NewActivation {
                activation_id: request.activation_id,
                package_digest: request.package_digest,
                database_id: request.database_id,
                operator_reference_hash: request.operator_reference_hash,
                backup_references: request.backup_references,
                role_mode,
                runtime_role: Some(request.runtime_role),
            },
        )
        .await
        .map_err(platform_error)?;
        // The activation takes every supply anchor, so its commit is read
        // back like a records swap when its acknowledgment is lost.
        self.commit_publication(transaction).await?;
        Ok(ActivationOutcome {
            activation,
            schema_versions_applied,
            publication,
            scheduling_id_adopted,
        })
    }

    /// What `activate` would do with the candidate, read in one read-only
    /// snapshot. Every refusal known without writing is collected rather
    /// than returned, so one plan names them all; only a database that
    /// cannot be read is an error.
    pub async fn plan_activation<F, Fut>(
        &self,
        database_id: &str,
        package_digest: &str,
        policy: &SchedulingPolicy,
        verify_retained: F,
    ) -> Result<ActivationPlan, StoreError>
    where
        F: FnOnce(DeployedPolicy) -> Fut,
        Fut: Future<Output = Result<(), StoreError>>,
    {
        let mut client = self.client().await?;
        let transaction = client
            .build_transaction()
            .read_only(true)
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await?;
        if let Some(schema) = unreadable_ledger_in(&*transaction).await? {
            return Err(StoreError::LedgerUnreadable { schema });
        }
        let mut refusals = Vec::new();

        let active = active_activation_in(&*transaction).await?;
        let schema = schema_state_in(&*transaction).await?;
        let runtime_role: String = transaction
            .query_one("SELECT current_user::text", &[])
            .await?
            .get(0);
        let effective_role_mode = role_mode_in(&*transaction, &runtime_role, None).await?;
        if let Some(weakened) = split_weakness_in(&*transaction, &runtime_role).await? {
            refusals.push(weakened);
        }
        let mut changes_pending = true;
        if let Some(active) = &active {
            if active.database_id != database_id {
                refusals.push(StoreError::DatabaseIdMismatch);
            }
            let grants_current =
                grants_current_in(&*transaction, &runtime_role, effective_role_mode).await?;
            if already_active(
                active,
                package_digest,
                &runtime_role,
                effective_role_mode,
                grants_current,
                &schema,
            ) {
                changes_pending = false;
                refusals.push(StoreError::PackageAlreadyActive {
                    digest: active.package_digest.clone(),
                });
            }
        }
        if schema.pending.contains(&AUDIT_WRITER_MIGRATION_VERSION) {
            match refuse_to_drop_unpublished_audit(&*transaction, true).await {
                Ok(()) => {}
                Err(refusal @ StoreError::UnpublishedAuditWouldBeDropped { .. }) => {
                    refusals.push(refusal);
                }
                Err(error) => return Err(error),
            }
        }
        if let Err(refusal) = schema.check() {
            refusals.push(refusal);
            return Ok(ActivationPlan {
                active,
                schema,
                deployed: None,
                publication: None,
                retained_hook_bindings_verified: None,
                refusals,
                runtime_role,
                effective_role_mode,
                changes_pending: false,
            });
        }
        let deployed = deployed_policy_in(&*transaction).await?;
        let mut retained_hook_bindings_verified = None;
        if let Some(deployed) = &deployed {
            if let Err(refusal) = refuse_foreign_scheduling_id(deployed, policy) {
                refusals.push(refusal);
            }
            if retains_hook_state(deployed, &schema) {
                let verified = verify_retained(deployed.clone()).await;
                retained_hook_bindings_verified = Some(verified.is_ok());
                if let Err(refusal) = verified {
                    refusals.push(refusal);
                }
            }
        }
        let policy_tables_current = schema
            .pending
            .iter()
            .all(|version| *version == ACTIVATIONS_MIGRATION_VERSION);
        let publication = if deployed.is_none() {
            // An empty database holds no windows or commitments to answer
            // for; apply publishes the candidate over the seeded revision.
            match refuse_combined_conflicts(policy, &[]) {
                Ok(()) => Some(PolicyPublication {
                    stored_revision: 1,
                    stored_digest: String::new(),
                    policy_digest: policy.policy_digest(),
                    advances: true,
                }),
                Err(refusal) => {
                    refusals.push(refusal);
                    None
                }
            }
        } else if policy_tables_current {
            match check_policy_publication(&transaction, self.observed_now(), policy).await {
                Ok(publication) => Some(publication),
                Err(refusal) if refusal.is_activation_refusal() => {
                    refusals.push(refusal);
                    None
                }
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        transaction.rollback().await?;
        // An apply records an activation only when it would meet no refusal.
        let changes_pending = changes_pending && refusals.is_empty();
        Ok(ActivationPlan {
            active,
            schema,
            deployed,
            publication,
            retained_hook_bindings_verified,
            refusals,
            runtime_role,
            effective_role_mode,
            changes_pending,
        })
    }
}

/// Whether an apply of the candidate would change nothing: it is the active
/// package, this release has no schema version left to apply, and the
/// runtime credential is the role the ledger recorded, holding the role mode
/// the ledger recorded. The active package is accepted again otherwise,
/// because apply is the only command that migrates, and the only one that
/// grants a rotated runtime role, moves a deployment to split mode, or
/// reissues grants someone widened.
fn already_active(
    active: &Activation,
    package_digest: &str,
    runtime_role: &str,
    role_mode: Option<RoleMode>,
    grants_current: bool,
    schema: &SchemaState,
) -> bool {
    active.package_digest == package_digest
        && schema.pending.is_empty()
        && active.runtime_role.as_deref() == Some(runtime_role)
        && role_mode == Some(active.role_mode)
        && grants_current
}

/// Whether `role` still holds every grant apply issues a split runtime role:
/// USAGE on the schema, SELECT on every `scheduling_*` table, INSERT,
/// UPDATE, and DELETE on every one but the ledger and the schema history,
/// use of every `scheduling_*` sequence, and EXECUTE on every `scheduling_*`
/// function, and the same on the platform hook delivery objects Scheduling
/// installs in its schema. Another application's objects in the same schema
/// are neither granted nor required. Moving an object's ownership
/// back to the migration role drops the grants the runtime role held on it,
/// and a reapply is what restores them. True in single role mode, where
/// apply issues no grants.
async fn grants_current_in(
    client: &impl GenericClient,
    role: &str,
    role_mode: Option<RoleMode>,
) -> Result<bool, StoreError> {
    if role_mode != Some(RoleMode::Split) {
        return Ok(true);
    }
    let schema = current_schema_in(client).await?;
    let delivery = registry_platform_hooks::delivery_schema::object_names(&schema);
    let current_user: String = client
        .query_one("SELECT current_user::text", &[])
        .await?
        .get(0);
    platform_activation::observe_role(
        client,
        &activation_layout(),
        (current_user != role).then_some(role),
        &delivery,
    )
    .await
    .map_err(platform_error)?
    .map(|observation| observation.grants_current)
    .ok_or(StoreError::Corrupt)
}

/// The role mode `role` holds over the activation ledger, or none before
/// the first apply created it. It is `single` when the role can insert,
/// update, delete, or truncate ledger or schema history rows, by a table or
/// a column privilege, is or holds
/// the ledger's owner, the schema's owner, or `migration_role`, is a
/// superuser or bypasses row security, or can write the ledger indirectly
/// as [`split_weakness_in`] describes; `split` otherwise.
async fn role_mode_in(
    client: &impl GenericClient,
    role: &str,
    migration_role: Option<&str>,
) -> Result<Option<RoleMode>, StoreError> {
    let layout = activation_layout();
    if !platform_activation::relation_exists(client, layout.ledger_relation())
        .await
        .map_err(platform_error)?
    {
        return Ok(None);
    }
    let schema = current_schema_in(client).await?;
    let delivery = registry_platform_hooks::delivery_schema::object_names(&schema);
    platform_activation::observe_role(client, &layout, migration_role.map(|_| role), &delivery)
        .await
        .map_err(platform_error)
        .map(|observation| observation.map(|observation| observation.mode))
}

/// How `role`, a role other than the ledger's owner, can still write the
/// ledger although apply revoked its writes: it owns, or holds a role that
/// owns, the Scheduling schema or a `scheduling_*` relation or function in
/// it, it holds TRIGGER on a `scheduling_*` relation, or it holds CREATE on
/// the schema. Each lets it attach code that runs as the migration role
/// inside a later apply, such as a deferred constraint trigger on a table
/// apply writes. A trigger already attached to a `scheduling_*` table
/// weakens the split the same way, since no Scheduling migration creates
/// one and revoking the power that attached it leaves it in place. None
/// when the ledger does not exist yet, when `role` is or holds the ledger's
/// owner or is a superuser (single role mode), or when nothing holds.
async fn split_weakness_in(
    client: &impl GenericClient,
    role: &str,
) -> Result<Option<StoreError>, StoreError> {
    let Some(weakness) =
        platform_activation::first_authority_weakness(client, &activation_layout(), role)
            .await
            .map_err(platform_error)?
    else {
        return Ok(None);
    };
    let runtime = weakness.runtime_role;
    let schema = weakness.schema;
    let migration = weakness.migration_role;
    // Moving ownership takes the runtime role's grants on the object with
    // it, so only that fix needs an apply to reissue them.
    const THEN_APPLY: &str =
        "then run `schedulingctl apply --runtime-config FILE` to reissue the runtime role's grants";
    let (cause, fix, then) = match weakness.cause {
        platform_activation::AuthorityCause::OwnedObject { owner } => (
            format!("{owner} owns an object in the Scheduling schema {schema}"),
            format!("REASSIGN OWNED BY {owner} TO {migration}"),
            THEN_APPLY,
        ),
        platform_activation::AuthorityCause::TriggerPrivilege { relation, grantee } => (
            format!("it holds TRIGGER on {relation}"),
            format!("REVOKE TRIGGER ON {relation} FROM {grantee}"),
            THEN_RERUN,
        ),
        platform_activation::AuthorityCause::SchemaCreate { grantee } => (
            format!("it holds CREATE on the Scheduling schema {schema}"),
            format!("REVOKE CREATE ON SCHEMA {schema} FROM {grantee}"),
            THEN_RERUN,
        ),
        platform_activation::AuthorityCause::AttachedTriggers(attached) => {
            let mut listed = Vec::with_capacity(attached.len());
            let mut drops = Vec::with_capacity(attached.len());
            for trigger in attached {
                listed.push(format!("{} on {}", trigger.name, trigger.relation));
                drops.push(format!(
                    "DROP TRIGGER {} ON {}",
                    trigger.name, trigger.relation
                ));
            }
            return Ok(Some(StoreError::SplitRoleWeakened(format!(
                "the Scheduling tables carry triggers no Scheduling migration creates ({}), which run as the migration role {migration} inside an apply, so the runtime role {runtime} is not separated from it; run `{}` as a database administrator, {THEN_RERUN}",
                listed.join(", "),
                drops.join("; ")
            ))));
        }
    };
    Ok(Some(StoreError::SplitRoleWeakened(format!(
        "the runtime role {runtime} is not separated from the migration role {migration}: {cause}, so it can write the activation ledger indirectly; run `{fix}` as a database administrator, {then}"
    ))))
}

/// What follows a fix that only takes a privilege or a trigger away.
const THEN_RERUN: &str = "then rerun the command that refused, or run `schedulingctl plan --runtime-config FILE` to confirm";

/// The refusal naming a default privilege of the migration role that
/// grants `role` TRIGGER on the tables a migration creates, directly,
/// through PUBLIC, or through a role it holds, or none when no such
/// default exists. Apply checks it before any migration: the grants it
/// issues never take TRIGGER away, and a table a refused first apply
/// created does not survive to have it revoked.
async fn default_trigger_grant_in(
    client: &impl GenericClient,
    role: &str,
) -> Result<Option<StoreError>, StoreError> {
    let Some(grant) = platform_activation::default_trigger_grant(client, role)
        .await
        .map_err(platform_error)?
    else {
        return Ok(None);
    };
    let runtime = grant.runtime_role;
    let migration = grant.migration_role;
    let scope = grant.scope;
    let grantee = grant.grantee;
    Ok(Some(StoreError::SplitRoleWeakened(format!(
        "the runtime role {runtime} is not separated from the migration role {migration}: a default privilege grants {grantee} TRIGGER on every table {migration} creates, so a migration would hand it a table it can attach a trigger to; run `ALTER DEFAULT PRIVILEGES FOR ROLE {migration}{scope} REVOKE TRIGGER ON TABLES FROM {grantee}` as a database administrator, {THEN_RERUN}"
    ))))
}

/// Whether the tables the publication locks read exist yet.
async fn publication_tables_exist(client: &impl GenericClient) -> Result<bool, StoreError> {
    Ok(client
        .query_one(
            "SELECT to_regclass('scheduling_supply') IS NOT NULL \
                 AND to_regclass('scheduling_meta') IS NOT NULL",
            &[],
        )
        .await?
        .get(0))
}

/// Refuse a database another deployment adopted. An empty id is a database
/// no deployment has adopted yet.
fn refuse_foreign_scheduling_id(
    deployed: &DeployedPolicy,
    policy: &SchedulingPolicy,
) -> Result<(), StoreError> {
    if deployed.scheduling_id.is_empty() || deployed.scheduling_id == *policy.project.id {
        Ok(())
    } else {
        Err(StoreError::DeploymentIdentity)
    }
}

/// Whether the database may retain hook events a candidate must still
/// deliver: a policy was published and the delivery tables exist.
fn retains_hook_state(deployed: &DeployedPolicy, schema: &SchemaState) -> bool {
    !deployed.policy_digest.is_empty() && schema.applied.contains(&HOOK_DELIVERY_MIGRATION_VERSION)
}

/// The pool anchors the policy's exact-time offerings name, sorted and
/// without repeats.
#[must_use]
pub fn policy_pool_ids(policy: &SchedulingPolicy) -> Vec<String> {
    let mut ids: Vec<String> = policy
        .offerings
        .iter()
        .filter_map(|offering| offering.exact_time.as_ref().map(|exact| exact.pool.clone()))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// The schema holding the activation ledger this connection's search path
/// reaches first, when this connection's role cannot read that ledger: it
/// lacks USAGE on the schema, which hides the ledger so the database would
/// read as empty, or SELECT on `scheduling_activations` or
/// `scheduling_schema_migrations`, as a rotated runtime role does before
/// apply grants it. `pg_class` names the ledger whatever the role may use.
async fn unreadable_ledger_in(client: &impl GenericClient) -> Result<Option<String>, StoreError> {
    platform_activation::unreadable_ledger(client, &activation_layout())
        .await
        .map_err(platform_error)
}

/// Refuse unless the ledger's latest row names `expected`: a database never
/// activated, another database identity, or another active package.
pub(super) async fn check_active_package_in(
    client: &impl GenericClient,
    expected: &ActivePackage<'_>,
) -> Result<Activation, StoreError> {
    platform_activation::check_active_package(
        client,
        &activation_layout(),
        expected.database_id,
        expected.package_digest,
    )
    .await
    .map_err(|error| match error {
        platform_activation::ActivePackageError::NotActivated => StoreError::NotActivated,
        platform_activation::ActivePackageError::DatabaseIdMismatch => {
            StoreError::DatabaseIdMismatch
        }
        platform_activation::ActivePackageError::PackageNotActive { active, candidate } => {
            StoreError::PackageNotActive { active, candidate }
        }
        platform_activation::ActivePackageError::Activation(error) => platform_error(error),
    })
}

async fn active_activation_in(
    client: &impl GenericClient,
) -> Result<Option<Activation>, StoreError> {
    platform_activation::active_activation(client, &activation_layout())
        .await
        .map_err(platform_error)
}

async fn deployed_policy_in(
    client: &impl GenericClient,
) -> Result<Option<DeployedPolicy>, StoreError> {
    let exists: bool = client
        .query_one("SELECT to_regclass('scheduling_meta') IS NOT NULL", &[])
        .await?
        .get(0);
    if !exists {
        return Ok(None);
    }
    let row = client
        .query_one(
            "SELECT scheduling_id, policy_revision, policy_digest FROM scheduling_meta WHERE singleton",
            &[],
        )
        .await?;
    Ok(Some(DeployedPolicy {
        scheduling_id: row.get(0),
        policy_revision: row.get(1),
        policy_digest: row.get(2),
    }))
}

/// Refuse schema version 8 while the audit outbox it drops still holds a
/// record its publisher had not reached. Migration calls it holding the
/// table exclusively; a plan (`plan` true) reads it without a lock and
/// passes over an outbox the planning role cannot read, which apply counts
/// again.
async fn refuse_to_drop_unpublished_audit(
    client: &impl GenericClient,
    plan: bool,
) -> Result<(), StoreError> {
    let readable: bool = client
        .query_one(
            "SELECT to_regclass('scheduling_audit_outbox') IS NOT NULL \
             AND (NOT $1 OR has_table_privilege(to_regclass('scheduling_audit_outbox'),'SELECT'))",
            &[&plan],
        )
        .await?
        .get(0);
    if !readable {
        return Ok(());
    }
    let rows: i64 = client
        .query_one(
            "SELECT count(*) FROM scheduling_audit_outbox WHERE published_at IS NULL",
            &[],
        )
        .await?
        .get(0);
    if rows == 0 {
        Ok(())
    } else {
        Err(StoreError::UnpublishedAuditWouldBeDropped {
            version: AUDIT_WRITER_MIGRATION_VERSION,
            rows,
        })
    }
}

/// The schema versions this database holds and the ones still pending. A
/// database no migration has touched holds none.
pub(super) async fn schema_state_in(
    client: &impl GenericClient,
) -> Result<SchemaState, StoreError> {
    let state = platform_activation::schema_state(client, &activation_layout(), &SCHEMA_VERSIONS)
        .await
        .map_err(platform_error)?;
    Ok(SchemaState {
        applied: state.applied,
        pending: state.pending,
    })
}

/// Apply every pending schema version inside the caller's transaction, in
/// ledger order, and return the versions applied. The caller holds the
/// migration lock; nothing here commits.
pub(super) async fn apply_migrations_in(
    transaction: &deadpool_postgres::Transaction<'_>,
) -> Result<Vec<i64>, StoreError> {
    transaction
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS scheduling_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL);",
        )
        .await?;
    let state = schema_state_in(&**transaction).await?;
    state.check()?;
    for version in &state.pending {
        match *version {
            1 => transaction.batch_execute(SCHEDULING_MIGRATION).await?,
            2 => transaction.batch_execute(FACTS_REVISION_MIGRATION).await?,
            HOOK_DELIVERY_MIGRATION_VERSION => {
                let schema = current_schema_in(&**transaction).await?;
                registry_platform_hooks::delivery_schema::install(&**transaction, &schema).await?;
            }
            POLICY_DOCUMENT_MIGRATION_VERSION => {
                transaction.batch_execute(POLICY_DOCUMENT_MIGRATION).await?;
            }
            WINDOW_RECORDS_MIGRATION_VERSION => {
                transaction.batch_execute(WINDOW_RECORDS_MIGRATION).await?;
            }
            WINDOW_REVISION_HEADS_MIGRATION_VERSION => {
                transaction
                    .batch_execute(WINDOW_REVISION_HEADS_MIGRATION)
                    .await?;
            }
            DUPLICATE_LOOKUP_INDEX_MIGRATION_VERSION => {
                transaction
                    .batch_execute(DUPLICATE_LOOKUP_INDEX_MIGRATION)
                    .await?;
            }
            AUDIT_WRITER_MIGRATION_VERSION => {
                // Hold the table exclusively for the rest of this transaction
                // so no concurrent writer can insert an unpublished row
                // between the count below and the drop the migration
                // performs.
                transaction
                    .batch_execute("LOCK TABLE scheduling_audit_outbox IN ACCESS EXCLUSIVE MODE")
                    .await?;
                refuse_to_drop_unpublished_audit(&**transaction, false).await?;
                transaction.batch_execute(AUDIT_WRITER_MIGRATION).await?;
            }
            ACTIVATIONS_MIGRATION_VERSION => {
                transaction.batch_execute(ACTIVATIONS_MIGRATION).await?;
            }
            EXTERNAL_REFERENCES_MIGRATION_VERSION => {
                transaction
                    .batch_execute(EXTERNAL_REFERENCES_MIGRATION)
                    .await?;
            }
            ATTEMPT_KEY_REFERENCE_MIGRATION_VERSION => {
                transaction
                    .batch_execute(ATTEMPT_KEY_REFERENCE_MIGRATION)
                    .await?;
            }
            CLAIM_OWNER_MIGRATION_VERSION => {
                transaction.batch_execute(CLAIM_OWNER_MIGRATION).await?;
            }
            _ => return Err(StoreError::Corrupt),
        }
        transaction
            .execute(
                "INSERT INTO scheduling_schema_migrations(version,applied_at) VALUES($1,now()) ON CONFLICT(version) DO NOTHING",
                &[version],
            )
            .await?;
    }
    Ok(state.pending)
}

/// Give the runtime role what the service needs and nothing that writes a
/// ledger. Only `scheduling_*` tables, views, sequences, and functions and
/// the platform hook delivery objects Scheduling installs are granted, so an
/// object another application keeps in a shared schema such as `public`
/// stays out of the runtime's reach. The statements are
/// idempotent, so every split-mode apply reissues them and a table a later
/// migration adds is covered.
async fn grant_runtime_role(
    transaction: &deadpool_postgres::Transaction<'_>,
    runtime_role: &str,
) -> Result<(), StoreError> {
    let schema = current_schema_in(&**transaction).await?;
    let delivery = registry_platform_hooks::delivery_schema::object_names(&schema);
    platform_activation::grant_runtime_role(
        &**transaction,
        &activation_layout(),
        runtime_role,
        &delivery,
    )
    .await
    .map_err(platform_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_newer_schema_version_names_the_release_that_applied_it() {
        let newer = SCHEMA_VERSIONS[SCHEMA_VERSIONS.len() - 1] + 1;
        let state = SchemaState {
            applied: SCHEMA_VERSIONS.iter().copied().chain([newer]).collect(),
            pending: Vec::new(),
        };
        assert!(matches!(
            state.check(),
            Err(StoreError::SchemaNewer { version }) if version == newer
        ));
        let damaged = SchemaState {
            applied: vec![0],
            pending: Vec::new(),
        };
        assert!(matches!(damaged.check(), Err(StoreError::Corrupt)));
    }

    #[test]
    fn a_pending_schema_names_plan_then_apply() {
        let message = StoreError::SchemaPending {
            pending: vec![8, 9],
        }
        .to_string();
        assert!(message.contains("pending versions 8, 9"), "{message}");
        assert!(
            message.contains(
                "`schedulingctl plan --runtime-config FILE` then `schedulingctl apply --runtime-config FILE`"
            ),
            "{message}"
        );
    }
}

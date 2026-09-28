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

use chrono::{DateTime, Utc};
use registry_scheduling_core::SchedulingPolicy;
use tokio_postgres::GenericClient;
use uuid::Uuid;

use super::{
    check_policy_publication, current_schema_in, lock_publication, publish_policy,
    refuse_combined_conflicts, PolicyPublication, PostgresStore, StoreError, ACTIVATIONS_MIGRATION,
    ACTIVATIONS_MIGRATION_VERSION, AUDIT_WRITER_MIGRATION, AUDIT_WRITER_MIGRATION_VERSION,
    DUPLICATE_LOOKUP_INDEX_MIGRATION, DUPLICATE_LOOKUP_INDEX_MIGRATION_VERSION,
    FACTS_REVISION_MIGRATION, HOOK_DELIVERY_MIGRATION_VERSION, MIGRATION_LOCK_KEY,
    POLICY_DOCUMENT_MIGRATION, POLICY_DOCUMENT_MIGRATION_VERSION, SCHEDULING_MIGRATION,
    SCHEMA_VERSIONS, WINDOW_RECORDS_MIGRATION, WINDOW_RECORDS_MIGRATION_VERSION,
    WINDOW_REVISION_HEADS_MIGRATION, WINDOW_REVISION_HEADS_MIGRATION_VERSION,
};

/// Said wherever the effective role mode is `single`.
pub const SINGLE_ROLE_STATEMENT: &str =
    "single-role mode: the ledger check catches a wrong package, but not someone holding this credential";

const ACTIVATION_COLUMNS: &str = "activation_id, apply_order, package_digest, \
     predecessor_package_digest, database_id, plan_kind, applied_at, \
     operator_reference_hash, backup_references, role_mode, runtime_role";

/// Whether the runtime credential can write the activation ledger. The ledger
/// records the mode the runtime role actually holds once an apply's grants
/// are issued, read from its privileges and memberships rather than from
/// whether its user name differs from the migration credential's.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoleMode {
    /// One credential migrates and serves, so it can also rewrite the ledger.
    Single,
    /// The runtime credential reads the ledger and cannot write it.
    Split,
}

impl RoleMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Split => "split",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "single" => Ok(Self::Single),
            "split" => Ok(Self::Split),
            _ => Err(StoreError::Corrupt),
        }
    }
}

/// One accepted package, as the ledger recorded it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Activation {
    pub activation_id: Uuid,
    pub apply_order: i64,
    pub package_digest: String,
    pub predecessor_package_digest: Option<String>,
    pub database_id: String,
    pub plan_kind: String,
    pub applied_at: DateTime<Utc>,
    pub operator_reference_hash: Option<String>,
    pub backup_references: Vec<String>,
    pub role_mode: RoleMode,
    /// The PostgreSQL user the runtime credential connected as.
    pub runtime_role: String,
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

    /// Every accepted package, oldest first.
    pub async fn activation_history(&self) -> Result<Vec<Activation>, StoreError> {
        let client = self.client().await?;
        if !ledger_exists(&**client).await? {
            return Ok(Vec::new());
        }
        let rows = client
            .query(
                &format!(
                    "SELECT {ACTIVATION_COLUMNS} FROM scheduling_activations ORDER BY apply_order"
                ),
                &[],
            )
            .await?;
        rows.iter().map(activation_from_row).collect()
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
                &[&request.policy.scheduling.id],
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
        if stored_id != request.policy.scheduling.id {
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
        let predecessor = active.as_ref().map(|active| active.package_digest.as_str());
        let plan_kind = if predecessor.is_some() {
            "successor"
        } else {
            "initial"
        };
        let row = transaction
            .query_one(
                &format!(
                    "INSERT INTO scheduling_activations({ACTIVATION_COLUMNS}) \
                     SELECT $1, COALESCE(max(apply_order), 0) + 1, $2, $3, $4, $5, now(), $6, $7, $8, $9 \
                     FROM scheduling_activations RETURNING {ACTIVATION_COLUMNS}"
                ),
                &[
                    &request.activation_id,
                    &request.package_digest,
                    &predecessor,
                    &request.database_id,
                    &plan_kind,
                    &request.operator_reference_hash,
                    &request.backup_references,
                    &role_mode.as_str(),
                    &request.runtime_role,
                ],
            )
            .await?;
        let activation = activation_from_row(&row)?;
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
        && active.runtime_role == runtime_role
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
    Ok(client
        .query_one(
            "SELECT has_schema_privilege(r.oid, n.oid, 'USAGE') \
                 AND NOT EXISTS (SELECT 1 FROM pg_class AS t \
                     WHERE t.relnamespace = n.oid AND t.relkind IN ('r', 'p', 'v', 'm', 'f') \
                       AND (t.relname LIKE 'scheduling\\_%' \
                           OR format('%I.%I', n.nspname, t.relname) = ANY($2::text[])) \
                       AND NOT (has_table_privilege(r.oid, t.oid, 'SELECT') \
                           AND (t.relname IN ('scheduling_activations', 'scheduling_schema_migrations') \
                               OR (has_table_privilege(r.oid, t.oid, 'INSERT') \
                                   AND has_table_privilege(r.oid, t.oid, 'UPDATE') \
                                   AND has_table_privilege(r.oid, t.oid, 'DELETE'))))) \
                 AND NOT EXISTS (SELECT 1 FROM pg_class AS q \
                     WHERE q.relnamespace = n.oid AND q.relkind = 'S' \
                       AND (q.relname LIKE 'scheduling\\_%' \
                           OR format('%I.%I', n.nspname, q.relname) = ANY($2::text[])) \
                       AND NOT (has_sequence_privilege(r.oid, q.oid, 'USAGE') \
                           AND has_sequence_privilege(r.oid, q.oid, 'SELECT'))) \
                 AND NOT EXISTS (SELECT 1 FROM pg_proc AS p \
                     WHERE p.pronamespace = n.oid AND p.prokind = 'f' \
                       AND p.proname LIKE 'scheduling\\_%' \
                       AND NOT has_function_privilege(r.oid, p.oid, 'EXECUTE')) \
             FROM pg_roles AS r \
             CROSS JOIN pg_class AS c \
             JOIN pg_namespace AS n ON n.oid = c.relnamespace \
             WHERE r.rolname = $1::text AND c.oid = to_regclass('scheduling_activations')",
            &[&role, &delivery],
        )
        .await?
        .get(0))
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
    if !ledger_exists(client).await? {
        return Ok(None);
    }
    let writes: bool = client
        .query_opt(
            "SELECT has_table_privilege(r.oid, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE') \
                 OR has_any_column_privilege(r.oid, c.oid, 'INSERT, UPDATE') \
                 OR COALESCE(has_table_privilege(r.oid, \
                        to_regclass('scheduling_schema_migrations'), \
                        'INSERT, UPDATE, DELETE, TRUNCATE'), false) \
                 OR COALESCE(has_any_column_privilege(r.oid, \
                        to_regclass('scheduling_schema_migrations'), \
                        'INSERT, UPDATE'), false) \
                 OR pg_has_role(r.oid, c.relowner, 'MEMBER') \
                 OR pg_has_role(r.oid, n.nspowner, 'MEMBER') \
                 OR COALESCE(pg_has_role(r.oid, m.oid, 'MEMBER'), false) \
                 OR r.rolsuper OR r.rolbypassrls \
             FROM pg_roles AS r \
             CROSS JOIN pg_class AS c \
             JOIN pg_namespace AS n ON n.oid = c.relnamespace \
             LEFT JOIN pg_roles AS m ON m.rolname = $2::text \
             WHERE r.rolname = $1::text AND c.oid = to_regclass('scheduling_activations')",
            &[&role, &migration_role],
        )
        .await?
        .ok_or(StoreError::Corrupt)?
        .get(0);
    Ok(Some(
        if writes || split_weakness_in(client, role).await?.is_some() {
            RoleMode::Single
        } else {
            RoleMode::Split
        },
    ))
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
    // The grantee a privilege is revoked from is the one `role` holds it
    // through: `role` itself, PUBLIC, or a role it is a member of.
    let Some(row) = client
        .query_opt(
            "SELECT quote_ident(r.rolname), quote_ident(n.nspname), \
                 quote_ident(pg_get_userbyid(c.relowner)), \
                 (SELECT quote_ident(pg_get_userbyid(owner)) FROM ( \
                     SELECT n.nspowner AS owner \
                     UNION ALL SELECT o.relowner FROM pg_class AS o \
                         WHERE o.relnamespace = n.oid AND o.relname LIKE 'scheduling\\_%' \
                     UNION ALL SELECT p.proowner FROM pg_proc AS p \
                         WHERE p.pronamespace = n.oid AND p.proname LIKE 'scheduling\\_%' \
                 ) AS owners \
                 WHERE pg_has_role(r.oid, owner, 'MEMBER') \
                 ORDER BY owner = r.oid DESC, pg_get_userbyid(owner) LIMIT 1), \
                 triggers.relation, triggers.grantee, \
                 has_schema_privilege(r.oid, n.oid, 'CREATE'), \
                 (SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' \
                         ELSE quote_ident(pg_get_userbyid(a.grantee)) END \
                     FROM aclexplode(n.nspacl) AS a \
                     WHERE a.privilege_type = 'CREATE' \
                       AND (a.grantee = 0 OR pg_has_role(r.oid, a.grantee, 'MEMBER')) \
                     ORDER BY a.grantee = r.oid DESC, a.grantee = 0 DESC LIMIT 1) \
             FROM pg_roles AS r \
             CROSS JOIN pg_class AS c \
             JOIN pg_namespace AS n ON n.oid = c.relnamespace \
             LEFT JOIN LATERAL ( \
                 SELECT format('%I.%I', n.nspname, t.relname) AS relation, \
                     (SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' \
                             ELSE quote_ident(pg_get_userbyid(a.grantee)) END \
                         FROM aclexplode(t.relacl) AS a \
                         WHERE a.privilege_type = 'TRIGGER' \
                           AND (a.grantee = 0 OR pg_has_role(r.oid, a.grantee, 'MEMBER')) \
                         ORDER BY a.grantee = r.oid DESC, a.grantee = 0 DESC LIMIT 1) AS grantee \
                 FROM pg_class AS t \
                 WHERE t.relnamespace = n.oid AND t.relname LIKE 'scheduling\\_%' \
                   AND t.relkind IN ('r', 'p', 'v', 'm', 'f') \
                   AND has_table_privilege(r.oid, t.oid, 'TRIGGER') \
                 ORDER BY t.relname LIMIT 1 \
             ) AS triggers ON true \
             WHERE r.rolname = $1::text AND c.oid = to_regclass('scheduling_activations') \
               AND NOT pg_has_role(r.oid, c.relowner, 'MEMBER') \
               AND NOT r.rolsuper",
            &[&role],
        )
        .await?
    else {
        return Ok(None);
    };
    let (runtime, schema, migration): (String, String, String) =
        (row.try_get(0)?, row.try_get(1)?, row.try_get(2)?);
    let owner: Option<String> = row.try_get(3)?;
    let triggers_on: Option<String> = row.try_get(4)?;
    let trigger_grantee: Option<String> = row.try_get(5)?;
    let creates: bool = row.try_get(6)?;
    let create_grantee: Option<String> = row.try_get(7)?;
    // Moving ownership takes the runtime role's grants on the object with
    // it, so only that fix needs an apply to reissue them.
    const THEN_APPLY: &str =
        "then run `schedulingctl apply --runtime-config FILE` to reissue the runtime role's grants";
    let (cause, fix, then) = match (owner, triggers_on) {
        (Some(owner), _) => (
            format!("{owner} owns an object in the Scheduling schema {schema}"),
            format!("REASSIGN OWNED BY {owner} TO {migration}"),
            THEN_APPLY,
        ),
        (None, Some(table)) => (
            format!("it holds TRIGGER on {table}"),
            format!(
                "REVOKE TRIGGER ON {table} FROM {}",
                trigger_grantee.as_deref().unwrap_or(&runtime)
            ),
            THEN_RERUN,
        ),
        (None, None) if creates => (
            format!("it holds CREATE on the Scheduling schema {schema}"),
            format!(
                "REVOKE CREATE ON SCHEMA {schema} FROM {}",
                create_grantee.as_deref().unwrap_or(&runtime)
            ),
            THEN_RERUN,
        ),
        (None, None) => {
            let attached = client
                .query(
                    "SELECT quote_ident(g.tgname), format('%I.%I', n.nspname, t.relname) \
                     FROM pg_trigger AS g \
                     JOIN pg_class AS t ON t.oid = g.tgrelid \
                     JOIN pg_namespace AS n ON n.oid = t.relnamespace \
                     WHERE NOT g.tgisinternal AND t.relname LIKE 'scheduling\\_%' \
                       AND n.oid = (SELECT relnamespace FROM pg_class \
                                    WHERE oid = to_regclass('scheduling_activations')) \
                     ORDER BY 2, 1",
                    &[],
                )
                .await?;
            if attached.is_empty() {
                return Ok(None);
            }
            let mut listed = Vec::with_capacity(attached.len());
            let mut drops = Vec::with_capacity(attached.len());
            for trigger in &attached {
                let (name, table): (String, String) = (trigger.try_get(0)?, trigger.try_get(1)?);
                listed.push(format!("{name} on {table}"));
                drops.push(format!("DROP TRIGGER {name} ON {table}"));
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
    let Some(row) = client
        .query_opt(
            "SELECT quote_ident(r.rolname), quote_ident(current_user::text), \
                 CASE WHEN d.defaclnamespace = 0 THEN '' \
                      ELSE ' IN SCHEMA ' || quote_ident(n.nspname) END, \
                 CASE WHEN a.grantee = 0 THEN 'PUBLIC' \
                      ELSE quote_ident(pg_get_userbyid(a.grantee)) END \
             FROM pg_roles AS r \
             CROSS JOIN pg_default_acl AS d \
             CROSS JOIN LATERAL aclexplode(d.defaclacl) AS a \
             LEFT JOIN pg_namespace AS n ON n.oid = d.defaclnamespace \
             WHERE r.rolname = $1::text \
               AND d.defaclrole = (SELECT oid FROM pg_roles WHERE rolname = current_user) \
               AND d.defaclobjtype = 'r' \
               AND (d.defaclnamespace = 0 OR n.nspname = current_schema()) \
               AND a.privilege_type = 'TRIGGER' \
               AND (a.grantee = 0 OR pg_has_role(r.oid, a.grantee, 'MEMBER')) \
             ORDER BY a.grantee = r.oid DESC, a.grantee = 0 DESC, d.defaclnamespace DESC \
             LIMIT 1",
            &[&role],
        )
        .await?
    else {
        return Ok(None);
    };
    let (runtime, migration, scope, grantee): (String, String, String, String) = (
        row.try_get(0)?,
        row.try_get(1)?,
        row.try_get(2)?,
        row.try_get(3)?,
    );
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
    if deployed.scheduling_id.is_empty() || deployed.scheduling_id == policy.scheduling.id {
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

async fn ledger_exists(client: &impl GenericClient) -> Result<bool, StoreError> {
    Ok(client
        .query_one(
            "SELECT to_regclass('scheduling_activations') IS NOT NULL",
            &[],
        )
        .await?
        .get(0))
}

/// The schema holding the activation ledger this connection's search path
/// reaches first, when this connection's role cannot read that ledger: it
/// lacks USAGE on the schema, which hides the ledger so the database would
/// read as empty, or SELECT on `scheduling_activations` or
/// `scheduling_schema_migrations`, as a rotated runtime role does before
/// apply grants it. `pg_class` names the ledger whatever the role may use.
async fn unreadable_ledger_in(client: &impl GenericClient) -> Result<Option<String>, StoreError> {
    let row = client
        .query_opt(
            "SELECT n.nspname::text,
               has_schema_privilege(n.oid, 'USAGE')
               AND has_table_privilege(a.oid, 'SELECT')
               AND (m.oid IS NULL OR has_table_privilege(m.oid, 'SELECT'))
             FROM unnest(string_to_array(current_setting('search_path'), ','))
               WITH ORDINALITY AS p(entry, position)
             JOIN pg_namespace n ON n.nspname = CASE btrim(btrim(p.entry), '\"')
               WHEN '$user' THEN current_user::text ELSE btrim(btrim(p.entry), '\"') END
             JOIN pg_class a ON a.relnamespace = n.oid AND a.relname = 'scheduling_activations'
             LEFT JOIN pg_class m
               ON m.relnamespace = n.oid AND m.relname = 'scheduling_schema_migrations'
             ORDER BY p.position
             LIMIT 1",
            &[],
        )
        .await?;
    Ok(row
        .filter(|row| !row.get::<_, bool>(1))
        .map(|row| row.get(0)))
}

/// Refuse unless the ledger's latest row names `expected`: a database never
/// activated, another database identity, or another active package.
pub(super) async fn check_active_package_in(
    client: &impl GenericClient,
    expected: &ActivePackage<'_>,
) -> Result<(), StoreError> {
    let active = active_activation_in(client)
        .await?
        .ok_or(StoreError::NotActivated)?;
    if active.database_id != expected.database_id {
        return Err(StoreError::DatabaseIdMismatch);
    }
    if active.package_digest != expected.package_digest {
        return Err(StoreError::PackageNotActive {
            active: active.package_digest,
            candidate: expected.package_digest.to_owned(),
        });
    }
    Ok(())
}

async fn active_activation_in(
    client: &impl GenericClient,
) -> Result<Option<Activation>, StoreError> {
    if !ledger_exists(client).await? {
        return Ok(None);
    }
    client
        .query_opt(
            &format!(
                "SELECT {ACTIVATION_COLUMNS} FROM scheduling_activations \
                 ORDER BY apply_order DESC LIMIT 1"
            ),
            &[],
        )
        .await?
        .as_ref()
        .map(activation_from_row)
        .transpose()
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

fn activation_from_row(row: &tokio_postgres::Row) -> Result<Activation, StoreError> {
    Ok(Activation {
        activation_id: row.try_get(0)?,
        apply_order: row.try_get(1)?,
        package_digest: row.try_get(2)?,
        predecessor_package_digest: row.try_get(3)?,
        database_id: row.try_get(4)?,
        plan_kind: row.try_get(5)?,
        applied_at: row.try_get(6)?,
        operator_reference_hash: row.try_get(7)?,
        backup_references: row.try_get(8)?,
        role_mode: RoleMode::parse(row.try_get::<_, &str>(9)?)?,
        runtime_role: row.try_get(10)?,
    })
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
    let exists: bool = client
        .query_one(
            "SELECT to_regclass('scheduling_schema_migrations') IS NOT NULL",
            &[],
        )
        .await?
        .get(0);
    let applied: Vec<i64> = if exists {
        client
            .query(
                "SELECT version FROM scheduling_schema_migrations ORDER BY version",
                &[],
            )
            .await?
            .iter()
            .map(|row| row.try_get(0))
            .collect::<Result<_, _>>()?
    } else {
        Vec::new()
    };
    let pending = SCHEMA_VERSIONS
        .iter()
        .copied()
        .filter(|version| !applied.contains(version))
        .collect();
    Ok(SchemaState { applied, pending })
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
    let role: String = transaction
        .query_one("SELECT quote_ident($1)", &[&runtime_role])
        .await?
        .get(0);
    let delivery = registry_platform_hooks::delivery_schema::object_names(&schema);
    let mut statements = vec![format!("GRANT USAGE ON SCHEMA {schema} TO {role}")];
    for row in transaction
        .query(
            "SELECT format('%I.%I', n.nspname, c.relname), c.relkind::text \
             FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace \
             WHERE n.nspname = current_schema() \
               AND (c.relname LIKE 'scheduling\\_%' \
                   OR format('%I.%I', n.nspname, c.relname) = ANY($1::text[])) \
               AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') \
             ORDER BY c.relname",
            &[&delivery],
        )
        .await?
    {
        let (name, kind): (String, String) = (row.try_get(0)?, row.try_get(1)?);
        statements.push(if kind == "S" {
            format!("GRANT USAGE, SELECT ON SEQUENCE {name} TO {role}")
        } else {
            format!("GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {name} TO {role}")
        });
    }
    for row in transaction
        .query(
            "SELECT format('%I.%I(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)) \
             FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace \
             WHERE n.nspname = current_schema() AND p.proname LIKE 'scheduling\\_%' \
               AND p.prokind = 'f' \
             ORDER BY 1",
            &[],
        )
        .await?
    {
        let name: String = row.try_get(0)?;
        statements.push(format!("GRANT EXECUTE ON FUNCTION {name} TO {role}"));
    }
    statements.push(format!(
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON \
         {schema}.scheduling_activations, {schema}.scheduling_schema_migrations FROM {role}"
    ));
    statements.push(format!(
        "REVOKE ALL ON {schema}.scheduling_activations FROM PUBLIC"
    ));
    transaction.batch_execute(&statements.join(";")).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_newer_schema_version_names_the_release_that_applied_it() {
        let state = SchemaState {
            applied: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            pending: Vec::new(),
        };
        assert!(matches!(
            state.check(),
            Err(StoreError::SchemaNewer { version: 10 })
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

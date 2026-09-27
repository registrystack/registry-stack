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
     operator_reference_hash, backup_references, role_mode";

/// Whether the runtime credential can write the activation ledger.
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

/// Everything one apply records.
#[derive(Clone, Debug)]
pub struct ActivationRequest<'a> {
    pub activation_id: Uuid,
    pub package_digest: &'a str,
    pub database_id: &'a str,
    pub policy: &'a SchedulingPolicy,
    pub operator_reference_hash: Option<&'a str>,
    pub backup_references: &'a [String],
    pub role_mode: RoleMode,
    /// The PostgreSQL user the runtime credential connects as. Split mode
    /// grants it the service's privileges and withholds the ledger's.
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

    /// `split` when this store's credential cannot insert, update, or delete
    /// activation ledger rows, `single` when it can, and none before the
    /// first apply created the ledger.
    pub async fn effective_role_mode(&self) -> Result<Option<RoleMode>, StoreError> {
        let client = self.client().await?;
        if !ledger_exists(&**client).await? {
            return Ok(None);
        }
        let writes: bool = client
            .query_one(
                "SELECT has_table_privilege('scheduling_activations', 'INSERT, UPDATE, DELETE')",
                &[],
            )
            .await?
            .get(0);
        Ok(Some(if writes {
            RoleMode::Single
        } else {
            RoleMode::Split
        }))
    }

    /// Accept one package in one transaction under the migration lock:
    /// refuse a foreign database, or the package already active on a schema
    /// with nothing pending, before any statement changes anything, then migrate, adopt the scheduling id,
    /// publish the policy, record the ledger row, and in split mode grant the
    /// runtime role the service's privileges without the ledger's.
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
        if let Some(active) = &active {
            refuse_ledger_mismatch(active, request.database_id, request.package_digest, &schema)?;
        }
        schema.check()?;
        let deployed = deployed_policy_in(&*transaction).await?;
        if let Some(deployed) = &deployed {
            refuse_foreign_scheduling_id(deployed, request.policy)?;
            if retains_hook_state(deployed, &schema) {
                verify_retained(deployed.clone()).await?;
            }
        }

        let schema_versions_applied = apply_migrations_in(&transaction).await?;
        lock_publication(&transaction).await?;
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
                     SELECT $1, COALESCE(max(apply_order), 0) + 1, $2, $3, $4, $5, now(), $6, $7, $8 \
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
                    &request.role_mode.as_str(),
                ],
            )
            .await?;
        let activation = activation_from_row(&row)?;
        if request.role_mode == RoleMode::Split {
            grant_runtime_role(&transaction, request.runtime_role).await?;
        }
        transaction.commit().await?;
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
        let mut refusals = Vec::new();

        let active = active_activation_in(&*transaction).await?;
        let schema = schema_state_in(&*transaction).await?;
        if let Some(active) = &active {
            if active.database_id != database_id {
                refusals.push(StoreError::DatabaseIdMismatch);
            }
            if active.package_digest == package_digest && schema.pending.is_empty() {
                refusals.push(StoreError::PackageAlreadyActive {
                    digest: active.package_digest.clone(),
                });
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
        Ok(ActivationPlan {
            active,
            schema,
            deployed,
            publication,
            retained_hook_bindings_verified,
            refusals,
        })
    }
}

/// Refuse a ledger that belongs to another database, or a candidate that is
/// already the active package. The active package is accepted again only
/// when this release still has schema versions to apply, because apply is
/// the only command that migrates and startup refuses a pending schema.
fn refuse_ledger_mismatch(
    active: &Activation,
    database_id: &str,
    package_digest: &str,
    schema: &SchemaState,
) -> Result<(), StoreError> {
    if active.database_id != database_id {
        return Err(StoreError::DatabaseIdMismatch);
    }
    if active.package_digest == package_digest && schema.pending.is_empty() {
        return Err(StoreError::PackageAlreadyActive {
            digest: active.package_digest.clone(),
        });
    }
    Ok(())
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
    })
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
                let rows: i64 = transaction
                    .query_one(
                        "SELECT count(*) FROM scheduling_audit_outbox WHERE published_at IS NULL",
                        &[],
                    )
                    .await?
                    .get(0);
                if rows != 0 {
                    return Err(StoreError::UnpublishedAuditWouldBeDropped {
                        version: AUDIT_WRITER_MIGRATION_VERSION,
                        rows,
                    });
                }
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
/// ledger. The statements are idempotent, so every split-mode apply reissues
/// them and a table a later migration adds is covered.
async fn grant_runtime_role(
    transaction: &deadpool_postgres::Transaction<'_>,
    runtime_role: &str,
) -> Result<(), StoreError> {
    let schema = current_schema_in(&**transaction).await?;
    let role: String = transaction
        .query_one("SELECT quote_ident($1)", &[&runtime_role])
        .await?
        .get(0);
    transaction
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA {schema} TO {role};\
             GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO {role};\
             GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {role};\
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {schema} TO {role};\
             REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON \
             {schema}.scheduling_activations, {schema}.scheduling_schema_migrations FROM {role};\
             REVOKE ALL ON {schema}.scheduling_activations FROM PUBLIC;"
        ))
        .await?;
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

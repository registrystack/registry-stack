// SPDX-License-Identifier: Apache-2.0

//! The instance claim: which physical database a Registry serves from.
//!
//! A logical restore (`pg_dump` and `pg_restore`, or a copy into another
//! database or cluster) carries every row into a database with another
//! physical identity. Were the copy to serve beside the original, the two
//! would be divergent writers of one Registry: each would accept writes and
//! commit revisions from the same history, each would admit imports under the
//! import authorities the backup carried open, and each would deliver the
//! same outbox work.
//!
//! The claim is one row naming the physical identity the Registry serves
//! from: the cluster's system identifier and the database oid. The first
//! apply into a fresh database, one with no committed revision and no commit
//! head, records the database it runs in. An apply into a database that
//! already holds committed history, a Registry installed before the claim
//! existed or a copy restored from a backup taken before it, records no
//! claim, so that database refuses to serve until an operator adopts it. The
//! serving runtime compares the claim with the database it is connected to at
//! startup and on every readiness probe, and refuses by name when they differ.
//! An operator makes a copy the Registry's database with an explicit adoption,
//! which moves the claim, raises its epoch, supersedes every open import
//! authority, and, once that commits, appends one audit entry naming the claim
//! it replaced.
//!
//! The system identifier comes from `pg_control_system()`, which PostgreSQL
//! grants to every role by default but a managed service may withhold. When
//! the role reading it holds no `EXECUTE` privilege on it, the identifier is
//! absent, a claim is recorded without it, and a claim or a connection
//! without it compares the database oid alone. The oid still tells another
//! database in the same cluster apart, but a copy restored into a fresh
//! cluster can reach the same oid, so the oid alone is the weaker check.
//!
//! The runtime role reads the claim and cannot change it. Operator tooling is
//! not refused on a copy, so a copy can be inspected, verified, and adopted.
//!
//! A physical copy (a base backup, point-in-time recovery, a storage snapshot,
//! or a promoted replica) keeps the system identifier and the database oid,
//! so the claim cannot tell it from its original. Fencing the original before
//! a physical copy serves remains the operator's work. Adopting a database the
//! claim already names claims it again, which supersedes every import
//! authority the restore reopened.

use serde::Serialize;
use tokio_postgres::GenericClient;

use crate::postgres::SqlIdentifier;

/// The product-owned claim table and the table privileges the runtime role
/// holds on it. Catalog closure consumes this list.
pub(crate) const INSTANCE_CLAIM_TABLES: &[(&str, &[&str])] =
    &[("registry_instance_claim", &["SELECT"])];

const DATABASE_OID: &str = "SELECT oid
                              FROM pg_catalog.pg_database
                             WHERE datname = pg_catalog.current_database()";

/// Whether the connected role may call `pg_control_system()`. A function
/// privilege is checked when a statement starts, before any branch of it
/// runs, so the identifier is read by a second statement only when this one
/// answers true.
const SYSTEM_IDENTIFIER_READABLE: &str = "SELECT COALESCE(
         pg_catalog.has_function_privilege(
             pg_catalog.to_regprocedure('pg_catalog.pg_control_system()'),
             'EXECUTE'),
         false)";

const SYSTEM_IDENTIFIER: &str = "SELECT system_identifier FROM pg_catalog.pg_control_system()";

/// The physical identity of one PostgreSQL database.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceIdentity {
    /// The cluster's system identifier, in decimal, or `None` when the role
    /// that read it may not call `pg_control_system()`. It is a 64-bit value,
    /// so it is written as a string to survive readers that hold numbers as
    /// doubles.
    pub system_identifier: Option<String>,
    pub database_oid: u32,
}

impl InstanceIdentity {
    /// Whether a recorded claim names this database: the oids agree, and so
    /// do the system identifiers when both sides carry one.
    fn named_by(&self, claim: &InstanceIdentity) -> bool {
        self.database_oid == claim.database_oid
            && match (&self.system_identifier, &claim.system_identifier) {
                (Some(live), Some(claimed)) => live == claimed,
                _ => true,
            }
    }
}

/// Whether the claim names the database a connection reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClaimCheck {
    Current,
    Mismatch,
    Unavailable,
}

/// KERNEL INTERNAL SCHEMA MIGRATION (instance claim): creates
/// `registry_internal.registry_instance_claim` and records the database the
/// installing transaction runs in, only when no claim is present and the
/// database is fresh: no committed revision and no commit head. A restored
/// copy therefore keeps the claim of its original, and a database that
/// already holds committed history gains no claim until an operator adopts
/// it. The revision and commit head tables must already exist. Additive and
/// idempotent.
pub(crate) async fn install(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), tokio_postgres::Error> {
    migration
        .batch_execute(&format!(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_instance_claim (
                 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
                 system_identifier bigint,
                 database_oid oid NOT NULL,
                 epoch bigint NOT NULL DEFAULT 1 CHECK (epoch >= 1),
                 claimed_at timestamptz NOT NULL DEFAULT transaction_timestamp()
             );
             REVOKE ALL ON registry_internal.registry_instance_claim FROM PUBLIC;
             {runtime_revoke}
             GRANT SELECT ON registry_internal.registry_instance_claim TO \"{role}\";",
            role = runtime_role.as_str(),
            runtime_revoke = crate::postgres::RuntimeRevoke::detect(migration, runtime_role)
                .await?
                .revoke_all_on("registry_internal.registry_instance_claim"),
        ))
        .await?;
    let live = live_identity(migration).await?;
    migration
        .execute(
            "INSERT INTO registry_internal.registry_instance_claim
                 (singleton, system_identifier, database_oid)
             SELECT true, $1::text::bigint, $2
              WHERE NOT EXISTS (SELECT 1 FROM registry_internal.registry_revisions)
                AND NOT EXISTS (SELECT 1 FROM registry_internal.registry_commit_head)
             ON CONFLICT (singleton) DO NOTHING",
            &[&live.system_identifier, &live.database_oid],
        )
        .await?;
    Ok(())
}

/// Compare the claim with the database the connection reached. A missing
/// claim row is a mismatch: no claim names this database.
pub(crate) async fn check(client: &impl GenericClient) -> ClaimCheck {
    let Ok(live) = live_identity(client).await else {
        return ClaimCheck::Unavailable;
    };
    let row = match client
        .query_opt(
            "SELECT system_identifier, database_oid
               FROM registry_internal.registry_instance_claim
              WHERE singleton",
            &[],
        )
        .await
    {
        Ok(row) => row,
        Err(_) => return ClaimCheck::Unavailable,
    };
    let Some(row) = row else {
        return ClaimCheck::Mismatch;
    };
    match identity_from(&row) {
        Ok(claim) if live.named_by(&claim) => ClaimCheck::Current,
        Ok(_) => ClaimCheck::Mismatch,
        Err(_) => ClaimCheck::Unavailable,
    }
}

async fn live_identity(
    client: &impl GenericClient,
) -> Result<InstanceIdentity, tokio_postgres::Error> {
    let database_oid = client.query_one(DATABASE_OID, &[]).await?.try_get(0)?;
    let readable: bool = client
        .query_one(SYSTEM_IDENTIFIER_READABLE, &[])
        .await?
        .try_get(0)?;
    let system_identifier = if readable {
        Some(
            client
                .query_one(SYSTEM_IDENTIFIER, &[])
                .await?
                .try_get::<_, i64>(0)?
                .to_string(),
        )
    } else {
        None
    };
    Ok(InstanceIdentity {
        system_identifier,
        database_oid,
    })
}

/// The identity a claim row records, from its first two columns.
fn identity_from(row: &tokio_postgres::Row) -> Result<InstanceIdentity, tokio_postgres::Error> {
    Ok(InstanceIdentity {
        system_identifier: row
            .try_get::<_, Option<i64>>(0)?
            .map(|value| value.to_string()),
        database_oid: row.try_get(1)?,
    })
}

#[cfg(feature = "tooling")]
pub use operator::{
    InstanceClaim, InstanceClaimAdoption, InstanceClaimError, InstanceClaimService,
    InstanceClaimStatus,
};

#[cfg(feature = "tooling")]
mod operator {
    use std::path::Path;
    use std::time::Duration;

    use chrono::{DateTime, Utc};
    use registry_platform_audit::AuditEntry;
    use serde::Serialize;
    use serde_json::{json, Value};
    use tokio_postgres::{GenericClient, Transaction};
    use uuid::Uuid;

    use super::{identity_from, live_identity, InstanceIdentity};
    use crate::audit::RegistryAudit;
    use crate::postgres::{
        verify_catalog_identity_for_catalog, verify_migration_role, ConnectionConfig,
        ExpectedManagedCatalog, ExpectedRegistryIdentity, RegistryLockKey, SqlIdentifier,
    };

    const AUDIT_SCHEMA: &str = "breg-instance-claim-audit/v1";
    const AUDIT_OPERATION_ID: &str = "breg.instance_claim.adopt";

    /// Value-free refusal of an instance claim operation.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
    pub enum InstanceClaimError {
        #[error("the instance claim is unavailable")]
        Unavailable,
    }

    /// The recorded claim.
    #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct InstanceClaim {
        #[serde(flatten)]
        pub identity: InstanceIdentity,
        pub epoch: i64,
        pub claimed_at: DateTime<Utc>,
    }

    /// The recorded claim beside the database the connection reached.
    #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct InstanceClaimStatus {
        pub live: InstanceIdentity,
        pub claim: Option<InstanceClaim>,
        pub matches: bool,
    }

    /// The claim an adoption replaced, the one it recorded, and the import
    /// authorities it superseded because the copy carried them open.
    #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct InstanceClaimAdoption {
        pub previous: Option<InstanceClaim>,
        pub current: InstanceClaim,
        pub superseded_import_authorities: Vec<uuid::Uuid>,
    }

    /// Package-bound operator boundary used by `bregctl instance-claim`.
    ///
    /// The same runtime configuration, package, database identity, catalog,
    /// roles, and Registry lock close before a claim is read or moved, and an
    /// adoption appends to the operator companion of the configured audit
    /// destination.
    pub struct InstanceClaimService {
        expected: ExpectedRegistryIdentity,
        expected_catalog: ExpectedManagedCatalog,
        lock_key: RegistryLockKey,
        migration_connection: ConnectionConfig,
        runtime_connection: ConnectionConfig,
        migration_role: SqlIdentifier,
        runtime_role: SqlIdentifier,
        lock_timeout: Duration,
        statement_timeout: Duration,
        audit: RegistryAudit,
    }

    impl InstanceClaimService {
        pub async fn from_runtime_config(path: &Path) -> Result<Self, InstanceClaimError> {
            if !path.is_absolute() {
                return Err(InstanceClaimError::Unavailable);
            }
            let config = crate::runtime_config::load_runtime_config(path)
                .map_err(|_| InstanceClaimError::Unavailable)?;
            let audit = RegistryAudit::open_companion(&config)
                .await
                .map_err(|_| InstanceClaimError::Unavailable)?;
            let runtime_connection = config
                .runtime_database_connection_config()
                .map_err(|_| InstanceClaimError::Unavailable)?;
            let pool = runtime_connection
                .build_pool()
                .map_err(|_| InstanceClaimError::Unavailable)?;
            let mut client = pool
                .get()
                .await
                .map_err(|_| InstanceClaimError::Unavailable)?;
            let startup = crate::startup::prepare_startup(
                config.package().root(),
                &config.package_load_context(),
                config.identity().database_id(),
                &mut client,
                config.database().roles().migration(),
                config.database().roles().runtime(),
            )
            .await
            .map_err(|_| InstanceClaimError::Unavailable)?;
            Ok(Self {
                expected: startup.expected_identity().clone(),
                expected_catalog: startup.expected_catalog().clone(),
                lock_key: startup.lock_key(),
                migration_connection: config
                    .migration_database_connection_config()
                    .map_err(|_| InstanceClaimError::Unavailable)?,
                runtime_connection,
                migration_role: config.database().roles().migration().clone(),
                runtime_role: config.database().roles().runtime().clone(),
                lock_timeout: config.operational_timeouts().migration_lock,
                statement_timeout: config.operational_timeouts().migration_statement,
                audit,
            })
        }

        #[cfg(feature = "postgres-test")]
        #[doc(hidden)]
        #[allow(clippy::too_many_arguments)]
        #[must_use]
        pub fn new_for_test(
            expected: ExpectedRegistryIdentity,
            expected_catalog: ExpectedManagedCatalog,
            lock_key: RegistryLockKey,
            migration_connection: ConnectionConfig,
            runtime_connection: ConnectionConfig,
            migration_role: SqlIdentifier,
            runtime_role: SqlIdentifier,
            audit: RegistryAudit,
        ) -> Self {
            Self {
                expected,
                expected_catalog,
                lock_key,
                migration_connection,
                runtime_connection,
                migration_role,
                runtime_role,
                lock_timeout: Duration::from_secs(5),
                statement_timeout: Duration::from_secs(10),
                audit,
            }
        }

        /// Read the claim and the identity of the database the runtime role
        /// reaches, in a read-only transaction that first closes the catalog
        /// identity.
        pub async fn status(&self) -> Result<InstanceClaimStatus, InstanceClaimError> {
            let pool = self
                .runtime_connection
                .build_pool()
                .map_err(|_| InstanceClaimError::Unavailable)?;
            let mut client = pool
                .get()
                .await
                .map_err(|_| InstanceClaimError::Unavailable)?;
            let pg_client: &mut tokio_postgres::Client = &mut client;
            let transaction = pg_client
                .build_transaction()
                .read_only(true)
                .start()
                .await
                .map_err(|_| InstanceClaimError::Unavailable)?;
            self.set_local_timeouts(&transaction).await?;
            verify_catalog_identity_for_catalog(
                &transaction,
                &self.expected,
                &self.expected_catalog,
                &self.migration_role,
                &self.runtime_role,
            )
            .await
            .map_err(|_| InstanceClaimError::Unavailable)?;
            let status = read_status(&transaction, false).await?;
            transaction
                .commit()
                .await
                .map_err(|_| InstanceClaimError::Unavailable)?;
            Ok(status)
        }

        /// Make the connected database the one the claim names.
        ///
        /// A request entry is accepted before any database work, so an audit
        /// outage moves nothing. Under the Registry lock, the claim then names
        /// this database and its epoch rises by one, and every open import
        /// authority is superseded, in one transaction. Once it commits, each
        /// supersession's transition record and the response naming the claim
        /// replaced and the authorities superseded are appended. An adoption
        /// that ends without a response, as after a commit error, writes the
        /// unfinished outcome.
        ///
        /// A claim that already names this database is claimed again the same
        /// way. That is the step after a physical restore, which keeps the
        /// system identifier and the oid and so reopens every authority
        /// closed after the backup point.
        pub async fn adopt(&self) -> Result<InstanceClaimAdoption, InstanceClaimError> {
            if !crate::audit::profile_is_keyed(self.audit.profile()) {
                return Err(InstanceClaimError::Unavailable);
            }
            let correlation = Uuid::new_v4().to_string();
            let request = json!({
                "phase": "attempt",
                "operationId": AUDIT_OPERATION_ID,
                "packageRevision": self.expected.package_revision,
            });
            let mut attempt = self
                .audit
                .begin(
                    AuditEntry::request(AUDIT_SCHEMA, correlation, request.clone()),
                    outcome_record(&request, "unfinished"),
                )
                .await
                .map_err(|_| InstanceClaimError::Unavailable)?;
            let pool = self
                .migration_connection
                .build_pool()
                .map_err(|_| InstanceClaimError::Unavailable)?;
            let mut client = match pool.get().await {
                Ok(client) => client,
                Err(_) => {
                    respond_refused(&mut attempt, &request, "failed").await;
                    return Err(InstanceClaimError::Unavailable);
                }
            };
            let mut pending = Vec::new();
            let adopted = match self.adopt_in_transaction(&mut client, &mut pending).await {
                Ok(adopted) => adopted,
                Err(error) => {
                    respond_refused(&mut attempt, &request, "failed").await;
                    return Err(error);
                }
            };
            // A commit error leaves the attempt unanswered, so it records the
            // unfinished outcome when dropped.
            let (adoption, record) = adopted.commit().await?;
            crate::import_authority::append_transitions(&self.audit, pending)
                .await
                .map_err(|_| InstanceClaimError::Unavailable)?;
            attempt
                .respond(record)
                .await
                .map_err(|_| InstanceClaimError::Unavailable)?;
            Ok(adoption)
        }

        async fn adopt_in_transaction<'c>(
            &self,
            client: &'c mut tokio_postgres::Client,
            pending: &mut Vec<Value>,
        ) -> Result<Adopted<'c>, InstanceClaimError> {
            verify_migration_role(client, &self.migration_role)
                .await
                .map_err(|_| InstanceClaimError::Unavailable)?;
            let transaction = client
                .transaction()
                .await
                .map_err(|_| InstanceClaimError::Unavailable)?;
            self.set_local_timeouts(&transaction).await?;
            transaction
                .execute(
                    "SELECT pg_catalog.pg_advisory_xact_lock($1)",
                    &[&self.lock_key.get()],
                )
                .await
                .map_err(|_| InstanceClaimError::Unavailable)?;
            verify_catalog_identity_for_catalog(
                &transaction,
                &self.expected,
                &self.expected_catalog,
                &self.migration_role,
                &self.runtime_role,
            )
            .await
            .map_err(|_| InstanceClaimError::Unavailable)?;
            let (adoption, record) =
                adopt_in(&transaction, pending, &self.expected.package_revision).await?;
            Ok(Adopted {
                transaction,
                adoption,
                record,
            })
        }

        async fn set_local_timeouts(
            &self,
            transaction: &Transaction<'_>,
        ) -> Result<(), InstanceClaimError> {
            transaction
                .query_one(
                    "SELECT set_config('lock_timeout', $1, true),
                            set_config('statement_timeout', $2, true)",
                    &[
                        &format!("{}ms", self.lock_timeout.as_millis()),
                        &format!("{}ms", self.statement_timeout.as_millis()),
                    ],
                )
                .await
                .map(|_| ())
                .map_err(|_| InstanceClaimError::Unavailable)
        }
    }

    /// An adoption written and not yet committed.
    struct Adopted<'c> {
        transaction: Transaction<'c>,
        adoption: InstanceClaimAdoption,
        record: Value,
    }

    impl Adopted<'_> {
        async fn commit(self) -> Result<(InstanceClaimAdoption, Value), InstanceClaimError> {
            self.transaction
                .commit()
                .await
                .map_err(|_| InstanceClaimError::Unavailable)?;
            Ok((self.adoption, self.record))
        }
    }

    /// The response of an adoption that committed nothing: the request's
    /// fields with `outcome`.
    fn outcome_record(request: &Value, outcome: &str) -> Value {
        let mut record = request.clone();
        if let Some(fields) = record.as_object_mut() {
            fields.insert("phase".to_owned(), json!("terminal"));
            fields.insert("outcome".to_owned(), json!(outcome));
        }
        record
    }

    async fn respond_refused(
        attempt: &mut registry_platform_audit::AuditRequest,
        request: &Value,
        outcome: &str,
    ) {
        if attempt
            .respond(outcome_record(request, outcome))
            .await
            .is_err()
        {
            tracing::error!("the instance claim adoption's response audit entry was not recorded");
        }
    }

    pub(crate) async fn read_status(
        client: &impl GenericClient,
        lock: bool,
    ) -> Result<InstanceClaimStatus, InstanceClaimError> {
        let live = live_identity(client)
            .await
            .map_err(|_| InstanceClaimError::Unavailable)?;
        let row = client
            .query_opt(
                if lock {
                    "SELECT system_identifier, database_oid, epoch, claimed_at
                       FROM registry_internal.registry_instance_claim
                      WHERE singleton
                      FOR UPDATE"
                } else {
                    "SELECT system_identifier, database_oid, epoch, claimed_at
                       FROM registry_internal.registry_instance_claim
                      WHERE singleton"
                },
                &[],
            )
            .await
            .map_err(|_| InstanceClaimError::Unavailable)?;
        let claim = row.map(|row| claim_from(&row)).transpose()?;
        let matches = claim
            .as_ref()
            .is_some_and(|claim| live.named_by(&claim.identity));
        Ok(InstanceClaimStatus {
            live,
            claim,
            matches,
        })
    }

    /// Move the claim to the connected database inside the caller's
    /// transaction, which already holds the Registry lock, and supersede
    /// every open import authority, collecting each transition record into
    /// `pending`. Returns the response record to append once the transaction
    /// commits.
    pub(crate) async fn adopt_in(
        transaction: &Transaction<'_>,
        pending: &mut Vec<Value>,
        package_revision: &str,
    ) -> Result<(InstanceClaimAdoption, Value), InstanceClaimError> {
        let status = read_status(transaction, true).await?;
        // A claim that already names this database is a re-claim after a
        // physical restore, which keeps the system identifier and the oid.
        let event = if status.matches {
            "reclaimed"
        } else {
            "adopted"
        };
        let row = transaction
            .query_one(
                "INSERT INTO registry_internal.registry_instance_claim
                     (singleton, system_identifier, database_oid, epoch, claimed_at)
                 VALUES (true, $1::text::bigint, $2, 1, transaction_timestamp())
                 ON CONFLICT (singleton) DO UPDATE
                    SET system_identifier = EXCLUDED.system_identifier,
                        database_oid = EXCLUDED.database_oid,
                        epoch = registry_instance_claim.epoch + 1,
                        claimed_at = EXCLUDED.claimed_at
                 RETURNING system_identifier, database_oid, epoch, claimed_at",
                &[&status.live.system_identifier, &status.live.database_oid],
            )
            .await
            .map_err(|_| InstanceClaimError::Unavailable)?;
        let current = claim_from(&row)?;
        let superseded_import_authorities =
            crate::import_authority::supersede_every_open(transaction, pending, package_revision)
                .await
                .map_err(|_| InstanceClaimError::Unavailable)?;
        let record = json!({
            "phase": "terminal",
            "outcome": "committed",
            "event": event,
            "operationId": AUDIT_OPERATION_ID,
            "packageRevision": package_revision,
            "previous": status.claim.as_ref().map(audit_claim),
            "current": audit_claim(&current),
            "supersededImportAuthorities": superseded_import_authorities
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        });
        Ok((
            InstanceClaimAdoption {
                previous: status.claim,
                current,
                superseded_import_authorities,
            },
            record,
        ))
    }

    fn audit_claim(claim: &InstanceClaim) -> Value {
        json!({
            "systemIdentifier": claim.identity.system_identifier,
            "databaseOid": claim.identity.database_oid,
            "epoch": claim.epoch,
        })
    }

    fn claim_from(row: &tokio_postgres::Row) -> Result<InstanceClaim, InstanceClaimError> {
        let unavailable = |_| InstanceClaimError::Unavailable;
        Ok(InstanceClaim {
            identity: identity_from(row).map_err(unavailable)?,
            epoch: row.try_get(2).map_err(unavailable)?,
            claimed_at: row.try_get(3).map_err(unavailable)?,
        })
    }
}

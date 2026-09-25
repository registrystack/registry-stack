// SPDX-License-Identifier: Apache-2.0

//! The instance claim: which physical database a Registry serves from.
//!
//! A logical restore (`pg_dump` and `pg_restore`, or a copy into another
//! database or cluster) carries every row, including the audit head, into a
//! database with another physical identity. Were the copy to serve beside the
//! original, both would extend the same audit chain from the same head and the
//! journal would split in two histories that each verify on their own.
//!
//! The claim is one row naming the physical identity the Registry serves
//! from: the cluster's system identifier and the database oid. The first
//! apply into a database with an empty audit journal records the database it
//! runs in. An apply into a database whose journal already holds records, a
//! Registry installed before the claim existed or a copy restored from a
//! backup taken before it, records no claim, so that database refuses to
//! serve until an operator adopts it. The serving runtime compares the claim
//! with the database it is connected to at startup and on every readiness
//! probe, and refuses by name when they differ. An operator makes a copy the
//! Registry's database with an explicit adoption, which verifies the audit
//! chain first, moves the claim, raises its epoch, and appends one audit
//! record naming the claim it replaced.
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
//! a physical copy serves remains the operator's work.

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
/// audit journal is empty. A restored copy therefore keeps the claim of its
/// original, and a database that already holds audit records gains no claim
/// until an operator adopts it. Additive and idempotent.
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
             REVOKE ALL ON registry_internal.registry_instance_claim FROM \"{role}\";
             GRANT SELECT ON registry_internal.registry_instance_claim TO \"{role}\";",
            role = runtime_role.as_str(),
        ))
        .await?;
    let live = live_identity(migration).await?;
    migration
        .execute(
            "INSERT INTO registry_internal.registry_instance_claim
                 (singleton, system_identifier, database_oid)
             SELECT true, $1::text::bigint, $2
              WHERE NOT EXISTS (SELECT 1 FROM registry_internal.registry_audit)
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

    use chrono::{DateTime, Utc};
    use serde::Serialize;
    use serde_json::json;
    use tokio_postgres::GenericClient;

    use super::{identity_from, live_identity, InstanceIdentity};
    use crate::audit_tooling::{AuditOperatorService, AuditToolingError};

    const AUDIT_SCHEMA: &str = "breg-instance-claim-audit/v1";
    const AUDIT_OPERATION_ID: &str = "breg.instance_claim.adopt";

    /// Value-free refusal of an instance claim operation.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
    pub enum InstanceClaimError {
        #[error("the instance claim already names this database")]
        AlreadyCurrent,
        #[error("the audit journal does not verify, so the claim was not moved")]
        AuditChain(AuditToolingError),
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
    /// It carries the audit operator boundary, so the same runtime
    /// configuration, package, database identity, catalog, roles, Registry
    /// lock, and audit key close before a claim is read or moved.
    pub struct InstanceClaimService {
        audit: AuditOperatorService,
    }

    impl InstanceClaimService {
        pub async fn from_runtime_config(path: &Path) -> Result<Self, InstanceClaimError> {
            AuditOperatorService::from_runtime_config(path)
                .await
                .map(Self::new)
                .map_err(|_| InstanceClaimError::Unavailable)
        }

        #[must_use]
        pub fn new(audit: AuditOperatorService) -> Self {
            Self { audit }
        }

        /// Read the claim and the identity of the database the runtime role
        /// reaches.
        pub async fn status(&self) -> Result<InstanceClaimStatus, InstanceClaimError> {
            self.audit.read_instance_claim().await
        }

        /// Make the connected database the one the claim names.
        ///
        /// Under the Registry lock and with the audit head locked, the audit
        /// chain must verify before the claim moves. The claim then names
        /// this database and its epoch rises by one, every open import
        /// authority is superseded with its own transition record, and one
        /// audit record names the claim it replaced and the authorities it
        /// superseded, all in one transaction.
        pub async fn adopt(&self) -> Result<InstanceClaimAdoption, InstanceClaimError> {
            self.audit.adopt_instance_claim().await
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
    /// transaction, which already holds the Registry lock, the audit head,
    /// and a verified chain, and supersede every open import authority.
    /// Returns the audit record to append.
    pub(crate) async fn adopt_in(
        transaction: &tokio_postgres::Transaction<'_>,
        profile: &registry_platform_audit::AuditProfile,
        package_revision: &str,
    ) -> Result<(InstanceClaimAdoption, serde_json::Value), InstanceClaimError> {
        let status = read_status(transaction, true).await?;
        if status.matches {
            return Err(InstanceClaimError::AlreadyCurrent);
        }
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
            crate::import_authority::supersede_every_open(transaction, profile, package_revision)
                .await
                .map_err(|_| InstanceClaimError::Unavailable)?;
        let record = json!({
            "schema": AUDIT_SCHEMA,
            "phase": "terminal",
            "outcome": "committed",
            "event": "adopted",
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

    fn audit_claim(claim: &InstanceClaim) -> serde_json::Value {
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

#[cfg(feature = "tooling")]
pub(crate) use operator::{adopt_in, read_status};

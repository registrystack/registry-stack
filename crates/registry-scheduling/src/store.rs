// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL store: schema, the capacity transactions, and the worker
//! queries.
//!
//! Every commitment lands through one transaction shape:
//!
//! 1. `SELECT ... FOR UPDATE` on the supply row that anchors the decision:
//!    the resource pool for an exact-time offering, the published window for
//!    an arrival window.
//! 2. A ledger snapshot whose hold expiry is evaluated *in the query*: a
//!    claim consumes capacity when it is an active booking, or an active
//!    hold whose `hold_expires_at` is still ahead of the observed now. A
//!    delayed cleanup worker therefore cannot keep an expired hold alive.
//! 3. The revision and policy-revision guards, with `policy.changed`
//!    winning.
//! 4. The pure evaluators from `registry-scheduling-core`, in memory, inside
//!    the lock but never doing I/O. The task grant's expiry is re-checked
//!    here too, against the same now, so a grant that lapses before the
//!    commit never books.
//! 5. The claim, the idempotency attempt, the history event, and the outbox
//!    rows, written in that same transaction.
//! 6. Commit.
//!
//! Workers claim due work with `FOR UPDATE SKIP LOCKED` and a limit, the
//! idiom the stack already uses for due clocks and retention sweeps.

use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use registry_platform_calendar::CalendarInterval;
use registry_platform_config::SecretResolver;
use registry_scheduling_core::{
    evaluate_exact_time_admission, evaluate_hold_state, evaluate_window_admission,
    AdmissionRefusal, ExactTimeContext, LedgerClaim, LedgerKind, LedgerSnapshot, PoolMember,
    SchedulingFacts,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tokio_postgres::{Config as PgConfig, Row};
use uuid::Uuid;

use crate::config::{describe_secret_failure, DatabaseConfig};

const SCHEDULING_MIGRATION: &str = include_str!("../migrations/0001_scheduling.sql");

/// Every schema version in ledger order.
const MIGRATIONS: [(i64, &str); 1] = [(1, SCHEDULING_MIGRATION)];

/// Serializes operator-run migrations on one session lock. A second migrator
/// waits here instead of racing the ledger primary key. The key spells the
/// ASCII bytes of "sched".
const MIGRATION_LOCK_KEY: i64 = 0x7363_6865_6475_6c65;

/// The advisory-lock namespace the hold ceiling serializes one caller in. The
/// second half of the key is the caller's pseudonym, which is already keyed to
/// this deployment, so two deployments sharing a database do not serialize each
/// other. The lock is a transaction lock: PostgreSQL releases it when the
/// capacity transaction ends, committed or rolled back. The namespace spells
/// the ASCII bytes of "SCHD".
const HOLD_CEILING_LOCK_NAMESPACE: i32 = 0x5343_4844;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("the Scheduling database configuration is invalid")]
    Configuration,
    #[error("the Scheduling database secret could not be resolved: {0}")]
    SecretConfiguration(String),
    #[error("the Scheduling database is not in the state this runtime expects")]
    Corrupt,
    /// The environment records would retire resources that live appointments
    /// or holds still occupy. The swap is refused whole, so the operator
    /// either keeps the resource or closes what stands on it first.
    #[error("the environment records retire {0}, which live appointments or holds still occupy")]
    FactsInUse(String),
    // Both carry the driver's own account of what went wrong. Neither the
    // pool nor the driver repeats the connection string in its message, so
    // naming the cause costs no credential.
    #[error("the Scheduling query failed: {0}")]
    Query(#[from] tokio_postgres::Error),
    #[error("the Scheduling database connection could not be established: {0}")]
    Pool(#[from] deadpool_postgres::PoolError),
}

#[derive(Clone)]
pub struct PostgresStore {
    pool: Pool,
}

impl std::fmt::Debug for PostgresStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresStore")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptState {
    Completed,
    Refused,
}

impl AttemptState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Refused => "refused",
        }
    }
}

/// One appointment or hold claim row. This is also the replay receipt body:
/// a stored attempt carries these fields, so a replayed response is the
/// original response, not a re-derivation from live state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimRow {
    pub claim_id: Uuid,
    pub kind: LedgerKind,
    pub state: ClaimState,
    pub offering: String,
    pub supply_id: String,
    pub channel: Option<String>,
    pub displayed_start: DateTime<Utc>,
    pub displayed_end: DateTime<Utc>,
    pub occupied_start: DateTime<Utc>,
    pub occupied_end: DateTime<Utc>,
    pub units: i32,
    pub duplicate_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_expires_at: Option<DateTime<Utc>>,
    pub revision: i64,
    pub policy_revision: i64,
    pub actor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimState {
    Active,
    Released,
    Cancelled,
    Consumed,
    Expired,
}

impl ClaimState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
        }
    }
}

/// The caller-side facts every commitment carries. `now` is observed once
/// per request and used for every decision inside it, including the grant
/// re-check, so a transaction never mixes two observations of time.
pub struct Commitment<'c> {
    pub now: DateTime<Utc>,
    pub policy_revision: i64,
    /// The pseudonymized actor reference history and audit carry.
    pub actor: &'c str,
    pub actor_issuer: &'c str,
    pub actor_subject: &'c str,
    pub idempotency_key: &'c str,
    /// The idempotent hash of the request payload.
    pub request_hash: &'c str,
    pub attempt_expires_at: DateTime<Utc>,
    /// The task grant's `exp`, re-checked inside the capacity transaction.
    pub grant_exp_unix: Option<u64>,
    /// The audit identity of the commitment, written in the same
    /// transaction as the state change.
    pub audit_event: Uuid,
    pub audit_record: Value,
}

/// The policy-resolved supply an admission runs against.
pub enum SupplyContext<'p> {
    ExactTime {
        exact: &'p registry_scheduling_core::ExactTimeOffering,
        members: &'p [PoolMember],
        open: &'p [CalendarInterval],
        closures: &'p [CalendarInterval],
    },
    Window {
        window: &'p registry_scheduling_core::PublishedWindow,
        lead_time_minutes: u32,
        horizon_days: u32,
        channels: &'p [registry_scheduling_core::Channel],
    },
}

/// What one committed operation produced.
#[derive(Clone, Debug)]
pub enum CommitOutcome {
    Booking(ClaimRow),
    Hold(ClaimRow),
    Cancelled(ClaimRow),
    Released,
    /// A stored attempt answered instead: replay its receipt exactly.
    Replay {
        status_code: u16,
        receipt: Value,
    },
}

/// What resolving a stored attempt decided.
enum ReplayOutcome {
    Replay {
        status_code: u16,
        receipt: Value,
    },
    /// The key is being misused, or its receipt has been erased past
    /// retention. Either way this request does not proceed to a commitment.
    Refused(CommitError),
}

#[derive(Debug, Error)]
pub enum CommitError {
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A statement inside the capacity transaction itself failed.
    #[error("the Scheduling query failed")]
    Query(#[from] tokio_postgres::Error),
    #[error("the admission was refused")]
    Refused(#[from] AdmissionRefusal),
    #[error("the idempotency key was reused with a different request")]
    KeyReused,
    #[error("the stored response for this idempotency key has expired")]
    KeyExpired,
    #[error("the caller holds more active holds than the hold policy allows")]
    HoldCeiling,
    #[error("the task grant lapsed before the commitment")]
    Unauthorized,
    #[error("the observed revision does not match the current revision")]
    RevisionMismatch,
    #[error("the cancellation cutoff has passed")]
    CutoffPassed,
}

/// One due or delivered outbox intent.
#[derive(Clone, Debug)]
pub struct OutboxRow {
    pub outbox_id: Uuid,
    pub purpose: String,
    pub claim_id: Uuid,
    pub appointment_revision: i64,
    pub due_at: DateTime<Utc>,
    pub attempts: i32,
    pub payload: Value,
}

/// One delivery intent no sweep will carry any further, as an operator reads
/// it. The delivery state is what separates the two ways that happens: `local`
/// is a deployment that declares no destination, and `failed` is a destination
/// that refused every attempt the ceiling allowed.
#[derive(Clone, Debug)]
pub struct UndeliveredIntent {
    pub outbox_id: Uuid,
    pub purpose: String,
    pub claim_id: Uuid,
    pub appointment_revision: i64,
    pub due_at: DateTime<Utc>,
    pub delivery_state: String,
    pub attempts: i32,
    pub payload: Value,
}

impl PostgresStore {
    pub fn connect_runtime(
        config: &DatabaseConfig,
        secrets: &SecretResolver,
    ) -> Result<Self, StoreError> {
        Self::connect_reference(
            config,
            secrets,
            "database.runtimeUrlRef",
            &config.runtime_url_ref,
        )
    }

    pub fn connect_migration(
        config: &DatabaseConfig,
        secrets: &SecretResolver,
    ) -> Result<Self, StoreError> {
        Self::connect_reference(
            config,
            secrets,
            "database.migrationUrlRef",
            &config.migration_url_ref,
        )
    }

    fn connect_reference(
        config: &DatabaseConfig,
        secrets: &SecretResolver,
        field: &'static str,
        reference: &str,
    ) -> Result<Self, StoreError> {
        let protected = secrets.resolve(reference).map_err(|error| {
            StoreError::SecretConfiguration(describe_secret_failure(field, reference, &error))
        })?;
        let url = std::str::from_utf8(protected.expose_secret())
            .map_err(|_| StoreError::Configuration)?;
        let mut postgres = PgConfig::from_str(url).map_err(|_| StoreError::Configuration)?;
        if postgres.get_user().is_none() || postgres.get_dbname().is_none() {
            return Err(StoreError::Configuration);
        }
        let manager_config = ManagerConfig {
            recycling_method: RecyclingMethod::Verified,
        };
        #[cfg(feature = "postgres-test")]
        let manager = if config.test_only_plaintext {
            postgres.ssl_mode(tokio_postgres::config::SslMode::Disable);
            Manager::from_config(postgres, tokio_postgres::NoTls, manager_config)
        } else {
            postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
            let connector = tls_connector(config, secrets)?;
            Manager::from_config(postgres, connector, manager_config)
        };
        #[cfg(not(feature = "postgres-test"))]
        let manager = {
            if config.test_only_plaintext {
                return Err(StoreError::Configuration);
            }
            postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
            let connector = tls_connector(config, secrets)?;
            Manager::from_config(postgres, connector, manager_config)
        };
        let pool = Pool::builder(manager)
            .max_size(32)
            .wait_timeout(Some(Duration::from_secs(5)))
            .create_timeout(Some(Duration::from_secs(5)))
            .recycle_timeout(Some(Duration::from_secs(5)))
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|_| StoreError::Configuration)?;
        Ok(Self { pool })
    }

    async fn client(&self) -> Result<deadpool_postgres::Client, StoreError> {
        self.pool.get().await.map_err(StoreError::Pool)
    }

    pub async fn migrate(&self) -> Result<(), StoreError> {
        let mut client = self.client().await?;
        client
            .query_one("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK_KEY])
            .await?;
        let applied = Self::apply_migrations(&mut client).await;
        let released = client
            .query_one("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK_KEY])
            .await;
        applied?;
        if released?.get::<_, bool>(0) {
            Ok(())
        } else {
            Err(StoreError::Corrupt)
        }
    }

    async fn apply_migrations(client: &mut deadpool_postgres::Client) -> Result<(), StoreError> {
        let transaction = client.transaction().await?;
        transaction
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS scheduling_schema_migrations (\
                 version bigint PRIMARY KEY CHECK (version > 0),\
                 applied_at timestamptz NOT NULL);",
            )
            .await?;
        transaction.commit().await?;

        for (version, migration) in MIGRATIONS {
            let transaction = client.transaction().await?;
            let applied: bool = transaction
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM scheduling_schema_migrations WHERE version=$1)",
                    &[&version],
                )
                .await?
                .get(0);
            if !applied {
                transaction.batch_execute(migration).await?;
                transaction
                    .execute(
                        "INSERT INTO scheduling_schema_migrations(version,applied_at) VALUES($1,now()) ON CONFLICT(version) DO NOTHING",
                        &[&version],
                    )
                    .await?;
            }
            transaction.commit().await?;
        }
        Ok(())
    }

    pub async fn ready(&self) -> Result<(), StoreError> {
        let client = self.client().await?;
        let applied = client
            .query(
                "SELECT version FROM scheduling_schema_migrations ORDER BY version",
                &[],
            )
            .await?;
        let schema_is_current = applied.len() == MIGRATIONS.len()
            && applied
                .iter()
                .zip(MIGRATIONS.iter())
                .all(|(row, (expected, _))| {
                    row.try_get::<_, i64>(0)
                        .is_ok_and(|version| version == *expected)
                });
        if schema_is_current {
            Ok(())
        } else {
            Err(StoreError::Corrupt)
        }
    }

    /// Adopt this database for one deployment identity. A fresh database
    /// carries the empty id the migration seeds; the first adopt claims it
    /// for the policy's scheduling id, an adopt under the same id again is a
    /// no-op, and an adopt under a different id is refused: two deployments
    /// never share one database silently.
    pub async fn adopt(&self, scheduling_id: &str) -> Result<(), StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_one(
                "SELECT scheduling_id FROM scheduling_meta WHERE singleton FOR UPDATE",
                &[],
            )
            .await?;
        let stored: String = row.get(0);
        if stored.is_empty() {
            transaction
                .execute(
                    "UPDATE scheduling_meta SET scheduling_id=$1, updated_at=now() WHERE singleton",
                    &[&scheduling_id],
                )
                .await?;
        } else if stored != scheduling_id {
            return Err(StoreError::Corrupt);
        }
        transaction.commit().await?;
        Ok(())
    }

    /// The deployment identity and current policy revision.
    pub async fn scheduling_meta(&self) -> Result<(String, i64, String), StoreError> {
        let client = self.client().await?;
        let row = client
            .query_one(
                "SELECT scheduling_id, policy_revision, policy_digest FROM scheduling_meta WHERE singleton",
                &[],
            )
            .await?;
        Ok((
            row.get::<_, String>(0),
            row.get::<_, i64>(1),
            row.get::<_, String>(2),
        ))
    }

    /// Publish a policy: bump the revision when the digest changed, and make
    /// sure every supply anchor the policy needs exists. Re-applying the
    /// same policy is a no-op that still verifies the anchors.
    pub async fn apply_policy(
        &self,
        scheduling_id: &str,
        policy_digest: &str,
        pool_ids: &[String],
        window_ids: &[String],
    ) -> Result<i64, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_one(
                "SELECT scheduling_id, policy_revision, policy_digest FROM scheduling_meta WHERE singleton FOR UPDATE",
                &[],
            )
            .await?;
        if row.get::<_, String>(0) != scheduling_id {
            return Err(StoreError::Corrupt);
        }
        let revision;
        if row.get::<_, String>(2) != policy_digest {
            revision = row.get::<_, i64>(1) + 1;
            transaction
                .execute(
                    "INSERT INTO scheduling_policy_revisions(policy_revision, policy_digest) \
                     VALUES($1,$2)",
                    &[&revision, &policy_digest],
                )
                .await?;
            transaction
                .execute(
                    "UPDATE scheduling_meta SET policy_revision=$1, policy_digest=$2, \
                     updated_at=now() WHERE singleton",
                    &[&revision, &policy_digest],
                )
                .await?;
        } else {
            revision = row.get(1);
        }
        for (id, kind) in pool_ids
            .iter()
            .map(|id| (id, "pool"))
            .chain(window_ids.iter().map(|id| (id, "window")))
        {
            transaction
                .execute(
                    "INSERT INTO scheduling_supply(supply_id, kind) VALUES($1,$2) \
                     ON CONFLICT(supply_id) DO NOTHING",
                    &[id, &kind],
                )
                .await?;
        }
        transaction.commit().await?;
        Ok(revision)
    }

    /// The environment records an admission runs against.
    pub async fn facts(&self) -> Result<SchedulingFacts, StoreError> {
        let client = self.client().await?;
        let locations = client
            .query(
                "SELECT location_id, timezone FROM scheduling_locations",
                &[],
            )
            .await?;
        let members = client
            .query(
                "SELECT resource_id, pool_id, capabilities, available \
                 FROM scheduling_pool_members ORDER BY pool_id, resource_id",
                &[],
            )
            .await?;
        let pools = client
            .query("SELECT pool_id FROM scheduling_pools ORDER BY pool_id", &[])
            .await?;
        let exceptions = client
            .query(
                "SELECT exception_id, location, kind, date::text, start_time, end_time, \
                 reopens, authority FROM scheduling_exceptions",
                &[],
            )
            .await?;
        Ok(SchedulingFacts {
            locations: locations
                .iter()
                .map(|row| registry_scheduling_core::LocationRecord {
                    id: row.get(0),
                    timezone: row.get(1),
                })
                .collect(),
            pools: pools
                .iter()
                .map(|pool| registry_scheduling_core::ResourcePool {
                    id: pool.get(0),
                    members: members
                        .iter()
                        .filter(|member| member.get::<_, String>(1) == pool.get::<_, String>(0))
                        .map(|member| registry_scheduling_core::PoolMember {
                            resource_id: member.get(0),
                            capabilities: member.get(2),
                            available: member.get(3),
                        })
                        .collect(),
                })
                .collect(),
            exceptions: exceptions
                .iter()
                .map(|row| registry_scheduling_core::CalendarExceptionRecord {
                    id: row.get(0),
                    location: row.get(1),
                    kind: match row.get::<_, String>(2).as_str() {
                        "closure" => registry_scheduling_core::ExceptionRecordKind::Closure,
                        _ => registry_scheduling_core::ExceptionRecordKind::Opening,
                    },
                    date: row.get(3),
                    start_time: row.get(4),
                    end_time: row.get(5),
                    reopens: row.get(6),
                    authority: row.get(7),
                })
                .collect(),
        })
    }

    /// Replace the environment records wholesale. This is the operator
    /// tooling path (`schedulingctl records apply`): one attributable write
    /// that swaps locations, pools, members, and exceptions atomically.
    pub async fn replace_facts(
        &self,
        facts: &SchedulingFacts,
        audit_event: Uuid,
        audit_record: Value,
    ) -> Result<(), StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        replace_facts_in_transaction(&transaction, facts, audit_event, audit_record).await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Mint a listing cursor.
    pub async fn insert_cursor(
        &self,
        cursor_id: Uuid,
        context: &str,
        position: Value,
        expires_at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let client = self.client().await?;
        client
            .execute(
                "INSERT INTO scheduling_cursors(cursor_id, context, position, expires_at) \
                 VALUES($1,$2,$3,$4)",
                &[&cursor_id, &context, &position, &expires_at],
            )
            .await?;
        Ok(())
    }

    /// Resolve one listing cursor by id.
    pub async fn cursor(&self, cursor_id: Uuid) -> Result<Option<Value>, StoreError> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT context, position, expires_at FROM scheduling_cursors WHERE cursor_id=$1",
                &[&cursor_id],
            )
            .await?;
        Ok(row.map(|row| {
            json!({
                "context": row.get::<_, String>(0),
                "position": row.get::<_, Value>(1),
                "expiresAt": row.get::<_, DateTime<Utc>>(2),
            })
        }))
    }

    /// One appointment or hold claim by id.
    pub async fn claim(&self, claim_id: Uuid) -> Result<Option<ClaimRow>, StoreError> {
        let client = self.client().await?;
        let row = client.query_opt(SELECT_CLAIM, &[&claim_id]).await?;
        row.map(map_claim_row).transpose()
    }

    /// The history of one claim, newest first, bounded by the listing limit.
    /// A page resumes strictly before the (occurred_at, event_id) pair its
    /// last row carries, so two events sharing an instant still page
    /// deterministically.
    pub async fn claim_history(
        &self,
        claim_id: Uuid,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> Result<Vec<Value>, StoreError> {
        let (before_at, before_id) = match before {
            Some((at, id)) => (Some(at), Some(id)),
            None => (None, None),
        };
        let client = self.client().await?;
        let rows = client
            .query(
                "SELECT event_id, revision, kind, occurred_at, actor, detail \
                 FROM scheduling_history WHERE claim_id=$1 \
                   AND ($3::timestamptz IS NULL OR (occurred_at, event_id) < ($3::timestamptz, $4::uuid)) \
                 ORDER BY occurred_at DESC, event_id DESC LIMIT $2",
                &[&claim_id, &limit, &before_at, &before_id],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|row| {
                json!({
                    "eventId": row.get::<_, Uuid>(0),
                    "revision": row.get::<_, i64>(1),
                    "kind": row.get::<_, String>(2),
                    "occurredAt": row.get::<_, DateTime<Utc>>(3),
                    "actor": row.get::<_, String>(4),
                    "detail": row.get::<_, Value>(5),
                })
            })
            .collect())
    }

    /// List pool members page-wise, resuming after `after_id`.
    pub async fn list_resources(
        &self,
        after_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<(String, String, Vec<String>, bool)>, StoreError> {
        let client = self.client().await?;
        let rows = client
            .query(
                "SELECT resource_id, pool_id, capabilities, available \
                 FROM scheduling_pool_members \
                 WHERE ($1::text IS NULL OR resource_id > $1) \
                 ORDER BY resource_id LIMIT $2",
                &[&after_id, &limit],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
            .collect())
    }

    /// List locations page-wise, resuming after `after_id`.
    pub async fn list_locations(
        &self,
        after_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<(String, String)>, StoreError> {
        let client = self.client().await?;
        let rows = client
            .query(
                "SELECT location_id, timezone FROM scheduling_locations \
                 WHERE ($1::text IS NULL OR location_id > $1) \
                 ORDER BY location_id LIMIT $2",
                &[&after_id, &limit],
            )
            .await?;
        Ok(rows.iter().map(|row| (row.get(0), row.get(1))).collect())
    }

    /// A read-only member snapshot for availability and explain. No lock:
    /// nothing here commits, so committed rows are read as they stand.
    pub async fn member_snapshot(
        &self,
        members: &[String],
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<LedgerSnapshot, StoreError> {
        let client = self.client().await?;
        let rows = client
            .query(CONSUMING_CLAUSES, &[&members, &from, &to, &now])
            .await?;
        Ok(snapshot_from_rows(rows))
    }

    /// A read-only window snapshot for availability and explain.
    pub async fn window_snapshot(
        &self,
        window_id: &str,
        now: DateTime<Utc>,
    ) -> Result<LedgerSnapshot, StoreError> {
        let client = self.client().await?;
        let rows = client
            .query(
                "SELECT claim_id, supply_id, kind, channel, occupied_start, occupied_end, \
                 units, duplicate_key, hold_expires_at \
                 FROM scheduling_claims \
                 WHERE state='active' \
                   AND (kind='booking' OR (kind='hold' AND hold_expires_at > $2)) \
                   AND supply_id = $1 \
                 ORDER BY occupied_start",
                &[&window_id, &now],
            )
            .await?;
        Ok(snapshot_from_rows(rows))
    }

    /// Mint a hold through the full capacity transaction.
    pub async fn create_hold(
        &self,
        offering: &registry_scheduling_core::OfferingPolicy,
        supply: &SupplyContext<'_>,
        request: &registry_scheduling_core::AdmissionRequest,
        ttl_minutes: u32,
        max_per_caller: u32,
        mut commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        match replay_stored_attempt(&transaction, &commitment, "hold:create").await? {
            Some(ReplayOutcome::Replay {
                status_code,
                receipt,
            }) => {
                transaction.commit().await?;
                return Ok(CommitOutcome::Replay {
                    status_code,
                    receipt,
                });
            }
            Some(ReplayOutcome::Refused(error)) => return Err(error),
            None => {}
        }
        check_grant_current(&commitment)?;
        commitment.policy_revision = current_policy_revision(&transaction).await?;
        let snapshot = lock_and_snapshot(&transaction, supply, commitment.now).await?;
        // The caller lock is taken after the supply lock, never before: every
        // hold transaction acquires the two in that one order, so no pair of
        // them can hold what the other is waiting for.
        if transaction
            .lock_caller_and_count_active_holds(commitment.actor, commitment.now)
            .await?
            >= i64::from(max_per_caller)
        {
            return Err(CommitError::HoldCeiling);
        }
        let admission = evaluate(offering, supply, request, &snapshot, &commitment, None)?;
        let expires_at = commitment
            .now
            .checked_add_signed(TimeDelta::minutes(i64::from(ttl_minutes)))
            .ok_or(AdmissionRefusal::ScheduleUnpublished)?;
        let hold_id = Uuid::new_v4();
        let claim = transaction
            .insert_claim(&NewClaim {
                claim_id: hold_id,
                kind: LedgerKind::Hold,
                state: ClaimState::Active,
                offering: &admission.offering,
                supply_id: admission
                    .resource
                    .as_deref()
                    .unwrap_or(window_supply_id(supply)),
                channel: request.channel.as_deref(),
                displayed_start: admission.start,
                displayed_end: admission.end,
                occupied_start: admission.occupied_start,
                occupied_end: admission.occupied_end,
                units: i32::try_from(admission.units).unwrap_or(i32::MAX),
                duplicate_key: request.duplicate_key.as_deref(),
                hold_expires_at: Some(expires_at),
                revision: 1,
                policy_revision: commitment.policy_revision,
                actor: commitment.actor,
                reason: None,
            })
            .await?;
        transaction
            .insert_history(
                hold_id,
                1,
                "held",
                commitment.now,
                commitment.actor,
                json!({"expiresAt": expires_at, "offering": admission.offering}),
            )
            .await?;
        transaction
            .insert_audit(commitment.audit_event, &commitment.audit_record)
            .await?;
        transaction
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                "hold:create",
                AttemptState::Completed,
                201,
                json!({"kind": "hold", "claim": claim}),
            )
            .await?;
        transaction.commit().await?;
        Ok(CommitOutcome::Hold(claim))
    }

    /// Create an appointment directly, through the full capacity
    /// transaction.
    pub async fn create_appointment(
        &self,
        offering: &registry_scheduling_core::OfferingPolicy,
        supply: &SupplyContext<'_>,
        request: &registry_scheduling_core::AdmissionRequest,
        mut commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        match replay_stored_attempt(&transaction, &commitment, "appointment:create").await? {
            Some(ReplayOutcome::Replay {
                status_code,
                receipt,
            }) => {
                transaction.commit().await?;
                return Ok(CommitOutcome::Replay {
                    status_code,
                    receipt,
                });
            }
            Some(ReplayOutcome::Refused(error)) => return Err(error),
            None => {}
        }
        check_grant_current(&commitment)?;
        commitment.policy_revision = current_policy_revision(&transaction).await?;
        let snapshot = lock_and_snapshot(&transaction, supply, commitment.now).await?;
        let admission = evaluate(offering, supply, request, &snapshot, &commitment, None)?;
        let appointment_id = Uuid::new_v4();
        let claim = transaction
            .insert_claim(&NewClaim {
                claim_id: appointment_id,
                kind: LedgerKind::Booking,
                state: ClaimState::Active,
                offering: &admission.offering,
                supply_id: admission
                    .resource
                    .as_deref()
                    .unwrap_or(window_supply_id(supply)),
                channel: request.channel.as_deref(),
                displayed_start: admission.start,
                displayed_end: admission.end,
                occupied_start: admission.occupied_start,
                occupied_end: admission.occupied_end,
                units: i32::try_from(admission.units).unwrap_or(i32::MAX),
                duplicate_key: request.duplicate_key.as_deref(),
                hold_expires_at: None,
                revision: 1,
                policy_revision: commitment.policy_revision,
                actor: commitment.actor,
                reason: None,
            })
            .await?;
        transaction
            .insert_history(
                appointment_id,
                1,
                "confirmed",
                commitment.now,
                commitment.actor,
                json!({"offering": admission.offering, "start": admission.start}),
            )
            .await?;
        transaction
            .insert_outbox(
                "confirmation",
                appointment_id,
                1,
                commitment.now,
                confirmation_payload(&claim, commitment.policy_revision),
            )
            .await?;
        mint_reminders(&transaction, &claim, offering, commitment.now).await?;
        transaction
            .insert_audit(commitment.audit_event, &commitment.audit_record)
            .await?;
        transaction
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                "appointment:create",
                AttemptState::Completed,
                201,
                json!({"kind": "booking", "claim": claim}),
            )
            .await?;
        transaction.commit().await?;
        Ok(CommitOutcome::Booking(claim))
    }

    /// Confirm a held allocation: the hold converts to an appointment in one
    /// transaction. The hold's own allocation is the reservation; the
    /// confirm re-checks expiry, policy identity, and the grant, then
    /// consumes the hold and writes the booking beside it.
    pub async fn confirm_hold(
        &self,
        hold_id: Uuid,
        offering: &registry_scheduling_core::OfferingPolicy,
        supply: &SupplyContext<'_>,
        mut commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let scope = format!("hold:{hold_id}:confirm");
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        match replay_stored_attempt(&transaction, &commitment, &scope).await? {
            Some(ReplayOutcome::Replay {
                status_code,
                receipt,
            }) => {
                transaction.commit().await?;
                return Ok(CommitOutcome::Replay {
                    status_code,
                    receipt,
                });
            }
            Some(ReplayOutcome::Refused(error)) => return Err(error),
            None => {}
        }
        check_grant_current(&commitment)?;
        commitment.policy_revision = current_policy_revision(&transaction).await?;
        // The snapshot is read under the lock for serialization order, but
        // admission is not re-evaluated: the hold's own reservation transfers
        // to the booking in this same transaction, so capacity does not
        // change. What must hold is identity (the policy revision the hold
        // was admitted under is still current), checked below.
        let _snapshot = lock_and_snapshot(&transaction, supply, commitment.now).await?;
        let hold = transaction
            .claim_in_transaction(hold_id)
            .await?
            .ok_or(AdmissionRefusal::HoldReleased)?;
        if hold.kind != LedgerKind::Hold || hold.state != ClaimState::Active {
            return Err(AdmissionRefusal::HoldReleased.into());
        }
        // The expiry check stays here so a hold whose TTL lapsed inside this
        // very transaction is refused by the same clock the snapshot used.
        evaluate_hold_state(&hold_ledger_claim(&hold), commitment.now)?;
        if hold.policy_revision != commitment.policy_revision {
            return Err(AdmissionRefusal::PolicyChanged.into());
        }
        if hold.actor != commitment.actor {
            // Confirming another caller's hold is never a state error: it is
            // an authorization refusal the audit journal records.
            return Err(CommitError::Unauthorized);
        }
        let appointment_id = Uuid::new_v4();
        let claim = transaction
            .insert_claim(&NewClaim {
                claim_id: appointment_id,
                kind: LedgerKind::Booking,
                state: ClaimState::Active,
                offering: &hold.offering,
                supply_id: &hold.supply_id,
                channel: hold.channel.as_deref(),
                displayed_start: hold.displayed_start,
                displayed_end: hold.displayed_end,
                occupied_start: hold.occupied_start,
                occupied_end: hold.occupied_end,
                units: hold.units,
                duplicate_key: hold.duplicate_key.as_deref(),
                hold_expires_at: None,
                revision: 1,
                policy_revision: commitment.policy_revision,
                actor: commitment.actor,
                reason: None,
            })
            .await?;
        transaction
            .close_claim(hold_id, ClaimState::Consumed, None, hold.revision + 1)
            .await?;
        transaction
            .insert_history(
                appointment_id,
                1,
                "confirmed",
                commitment.now,
                commitment.actor,
                json!({"confirmedFrom": hold_id, "start": claim.displayed_start}),
            )
            .await?;
        transaction
            .insert_history(
                hold_id,
                hold.revision + 1,
                "consumed",
                commitment.now,
                commitment.actor,
                json!({"appointment": appointment_id}),
            )
            .await?;
        transaction
            .insert_outbox(
                "confirmation",
                appointment_id,
                1,
                commitment.now,
                confirmation_payload(&claim, commitment.policy_revision),
            )
            .await?;
        mint_reminders(&transaction, &claim, offering, commitment.now).await?;
        transaction
            .insert_audit(commitment.audit_event, &commitment.audit_record)
            .await?;
        transaction
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                &scope,
                AttemptState::Completed,
                201,
                json!({"kind": "booking", "claim": claim}),
            )
            .await?;
        transaction.commit().await?;
        Ok(CommitOutcome::Booking(claim))
    }

    /// Release a hold early.
    pub async fn release_hold(
        &self,
        hold_id: Uuid,
        commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let scope = format!("hold:{hold_id}:release");
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        match replay_stored_attempt(&transaction, &commitment, &scope).await? {
            Some(ReplayOutcome::Replay {
                status_code,
                receipt,
            }) => {
                transaction.commit().await?;
                return Ok(CommitOutcome::Replay {
                    status_code,
                    receipt,
                });
            }
            Some(ReplayOutcome::Refused(error)) => return Err(error),
            None => {}
        }
        check_grant_current(&commitment)?;
        let hold = transaction
            .claim_in_transaction(hold_id)
            .await?
            .ok_or(AdmissionRefusal::HoldReleased)?;
        if hold.kind != LedgerKind::Hold || hold.state != ClaimState::Active {
            return Err(AdmissionRefusal::HoldReleased.into());
        }
        if hold.actor != commitment.actor {
            return Err(CommitError::Unauthorized);
        }
        transaction
            .close_claim(hold_id, ClaimState::Released, None, hold.revision + 1)
            .await?;
        transaction
            .insert_history(
                hold_id,
                hold.revision + 1,
                "released",
                commitment.now,
                commitment.actor,
                json!({}),
            )
            .await?;
        transaction.suppress_pending_reminders(hold_id).await?;
        transaction
            .insert_audit(commitment.audit_event, &commitment.audit_record)
            .await?;
        transaction
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                &scope,
                AttemptState::Completed,
                204,
                Value::Null,
            )
            .await?;
        transaction.commit().await?;
        Ok(CommitOutcome::Released)
    }

    /// Reschedule an appointment to a new time, keeping its identity.
    pub async fn reschedule_appointment(
        &self,
        appointment_id: Uuid,
        offering: &registry_scheduling_core::OfferingPolicy,
        supply: &SupplyContext<'_>,
        request: &registry_scheduling_core::AdmissionRequest,
        observed_revision: u64,
        mut commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let scope = format!("appointment:{appointment_id}:reschedule");
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        match replay_stored_attempt(&transaction, &commitment, &scope).await? {
            Some(ReplayOutcome::Replay {
                status_code,
                receipt,
            }) => {
                transaction.commit().await?;
                return Ok(CommitOutcome::Replay {
                    status_code,
                    receipt,
                });
            }
            Some(ReplayOutcome::Refused(error)) => return Err(error),
            None => {}
        }
        check_grant_current(&commitment)?;
        commitment.policy_revision = current_policy_revision(&transaction).await?;
        let snapshot = lock_and_snapshot(&transaction, supply, commitment.now).await?;
        let appointment = transaction
            .claim_in_transaction(appointment_id)
            .await?
            .ok_or(AdmissionRefusal::HoldReleased)?;
        if appointment.kind != LedgerKind::Booking || appointment.state != ClaimState::Active {
            return Err(AdmissionRefusal::HoldReleased.into());
        }
        // The policy guard wins over the revision guard: a caller whose
        // observed revision is also stale learns the policy moved first.
        if request.policy_revision != u64::try_from(commitment.policy_revision).unwrap_or(u64::MAX)
        {
            return Err(AdmissionRefusal::PolicyChanged.into());
        }
        if u64::try_from(appointment.revision) != Ok(observed_revision) {
            return Err(CommitError::RevisionMismatch);
        }
        if appointment.actor != commitment.actor {
            return Err(CommitError::Unauthorized);
        }
        // The appointment's own allocation is the exclusion: a reschedule
        // never competes with the booking it moves. It is read from the row
        // this transaction locked, never from the request.
        let own_claim_id = appointment.claim_id.to_string();
        let admission = evaluate(
            offering,
            supply,
            request,
            &snapshot,
            &commitment,
            Some(&own_claim_id),
        )?;
        let next_revision = appointment.revision + 1;
        transaction
            .move_claim(&ClaimMove {
                claim_id: appointment_id,
                supply_id: admission
                    .resource
                    .as_deref()
                    .unwrap_or(&appointment.supply_id),
                displayed_start: admission.start,
                displayed_end: admission.end,
                occupied_start: admission.occupied_start,
                occupied_end: admission.occupied_end,
                policy_revision: commitment.policy_revision,
                next_revision,
            })
            .await?;
        transaction
            .insert_history(appointment_id, next_revision, "rescheduled", commitment.now,
                commitment.actor,
                json!({
                    "from": {"start": appointment.displayed_start, "end": appointment.displayed_end},
                    "to": {"start": admission.start, "end": admission.end},
                }))
            .await?;
        // A stale unsent reminder describes an appointment that no longer
        // exists in this form; it is suppressed, never sent (INT-02).
        transaction
            .suppress_pending_reminders(appointment_id)
            .await?;
        let moved = ClaimRow {
            displayed_start: admission.start,
            displayed_end: admission.end,
            occupied_start: admission.occupied_start,
            occupied_end: admission.occupied_end,
            supply_id: admission.resource.unwrap_or(appointment.supply_id.clone()),
            revision: next_revision,
            policy_revision: commitment.policy_revision,
            ..appointment.clone()
        };
        mint_reminders(&transaction, &moved, offering, commitment.now).await?;
        transaction
            .insert_outbox(
                "change",
                appointment_id,
                next_revision,
                commitment.now,
                confirmation_payload(&moved, commitment.policy_revision),
            )
            .await?;
        transaction
            .insert_audit(commitment.audit_event, &commitment.audit_record)
            .await?;
        transaction
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                &scope,
                AttemptState::Completed,
                200,
                json!({"kind": "booking", "claim": moved}),
            )
            .await?;
        transaction.commit().await?;
        Ok(CommitOutcome::Booking(moved))
    }

    /// Cancel an appointment. Cancellation is a release of capacity: it is
    /// guarded by the observed revision and the cutoff, never by the policy
    /// revision, so an appointment is always cancellable under the policy
    /// that currently governs its offering.
    pub async fn cancel_appointment(
        &self,
        appointment_id: Uuid,
        observed_revision: u64,
        cancellation_cutoff_minutes: Option<u32>,
        reason: Option<&str>,
        commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let scope = format!("appointment:{appointment_id}:cancel");
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        match replay_stored_attempt(&transaction, &commitment, &scope).await? {
            Some(ReplayOutcome::Replay {
                status_code,
                receipt,
            }) => {
                transaction.commit().await?;
                return Ok(CommitOutcome::Replay {
                    status_code,
                    receipt,
                });
            }
            Some(ReplayOutcome::Refused(error)) => return Err(error),
            None => {}
        }
        check_grant_current(&commitment)?;
        let appointment = transaction
            .claim_in_transaction(appointment_id)
            .await?
            .ok_or(AdmissionRefusal::HoldReleased)?;
        if appointment.kind != LedgerKind::Booking || appointment.state != ClaimState::Active {
            return Err(AdmissionRefusal::HoldReleased.into());
        }
        if u64::try_from(appointment.revision) != Ok(observed_revision) {
            return Err(CommitError::RevisionMismatch);
        }
        if appointment.actor != commitment.actor {
            return Err(CommitError::Unauthorized);
        }
        if let Some(cutoff) = cancellation_cutoff_minutes {
            let earliest_cancel_end = appointment
                .displayed_start
                .checked_sub_signed(TimeDelta::minutes(i64::from(cutoff)))
                .ok_or(CommitError::CutoffPassed)?;
            if commitment.now >= earliest_cancel_end {
                return Err(CommitError::CutoffPassed);
            }
        }
        let next_revision = appointment.revision + 1;
        transaction
            .close_claim(appointment_id, ClaimState::Cancelled, reason, next_revision)
            .await?;
        transaction
            .insert_history(
                appointment_id,
                next_revision,
                "cancelled",
                commitment.now,
                commitment.actor,
                json!({"reason": reason}),
            )
            .await?;
        transaction
            .suppress_pending_reminders(appointment_id)
            .await?;
        transaction
            .insert_outbox(
                "cancellation",
                appointment_id,
                next_revision,
                commitment.now,
                json!({
                    "appointmentId": appointment_id,
                    "revision": next_revision,
                    "reason": reason,
                }),
            )
            .await?;
        let cancelled = ClaimRow {
            state: ClaimState::Cancelled,
            revision: next_revision,
            reason: reason.map(str::to_owned),
            closed_at: Some(commitment.now),
            ..appointment
        };
        transaction
            .insert_audit(commitment.audit_event, &commitment.audit_record)
            .await?;
        transaction
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                &scope,
                AttemptState::Completed,
                200,
                json!({"kind": "booking", "claim": cancelled.clone()}),
            )
            .await?;
        transaction.commit().await?;
        Ok(CommitOutcome::Cancelled(cancelled))
    }

    /// Expire holds whose TTL has passed. Each expiry is a state change with
    /// its own history event, so the ledger never depends on the sweeper
    /// having run for capacity to be free: the snapshot query already
    /// discounts expired holds.
    pub async fn expire_due_holds(
        &self,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<u64, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let rows = transaction
            .query(
                "UPDATE scheduling_claims SET state='expired', closed_at=now(), changed_at=now() \
                 WHERE claim_id IN (\
                     SELECT claim_id FROM scheduling_claims \
                     WHERE kind='hold' AND state='active' AND hold_expires_at <= $1 \
                     ORDER BY hold_expires_at LIMIT $2 FOR UPDATE SKIP LOCKED)\
                     RETURNING claim_id, revision",
                &[&now, &limit],
            )
            .await?;
        for row in &rows {
            let claim_id: Uuid = row.get(0);
            transaction
                .execute(
                    "INSERT INTO scheduling_history(event_id, claim_id, revision, kind, \
                     occurred_at, actor, detail) \
                     VALUES($1,$2,$3,'expired',$4,'system','{}')",
                    &[&Uuid::new_v4(), &claim_id, &row.get::<_, i64>(1), &now],
                )
                .await?;
        }
        transaction.commit().await?;
        Ok(rows.len() as u64)
    }

    /// Claim due outbox intents for dispatch, marking their attempt. An
    /// intent is due when its own time has come and the back-off a failed
    /// attempt wrote has passed: without the second half a failing intent
    /// would be re-claimed on every tick and burn its attempts ceiling in
    /// seconds.
    pub async fn claim_due_intents(
        &self,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let rows = transaction
            .query(
                "UPDATE scheduling_outbox SET attempts = attempts + 1, next_attempt_at = $3 \
                 WHERE outbox_id IN (\
                     SELECT outbox_id FROM scheduling_outbox \
                     WHERE delivery_state='pending' AND due_at <= $1 \
                     AND next_attempt_at <= $1 \
                     ORDER BY due_at LIMIT $2 FOR UPDATE SKIP LOCKED) \
                 RETURNING outbox_id, purpose, claim_id, appointment_revision, due_at, attempts, payload",
                &[&now, &limit, &now],
            )
            .await?;
        transaction.commit().await?;
        Ok(rows
            .iter()
            .map(|row| OutboxRow {
                outbox_id: row.get(0),
                purpose: row.get(1),
                claim_id: row.get(2),
                appointment_revision: row.get(3),
                due_at: row.get(4),
                attempts: row.get(5),
                payload: row.get(6),
            })
            .collect())
    }

    /// The intents nothing will deliver without an operator, oldest first.
    ///
    /// A deployment that declares no reminders destination holds every intent
    /// locally, and a destination that refused every attempt leaves the intent
    /// failed. Both are recorded and then waited on by nobody, so without a
    /// read path an operator cannot tell either has happened. Delivered
    /// intents are not listed, and neither are pending ones: the sweep is
    /// still carrying those.
    pub async fn undelivered_intents(
        &self,
        limit: i64,
    ) -> Result<Vec<UndeliveredIntent>, StoreError> {
        let client = self.client().await?;
        let rows = client
            .query(
                "SELECT outbox_id, purpose, claim_id, appointment_revision, due_at, \
                 delivery_state, attempts, payload FROM scheduling_outbox \
                 WHERE delivery_state IN ('local','failed') \
                 ORDER BY due_at, outbox_id LIMIT $1",
                &[&limit],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|row| UndeliveredIntent {
                outbox_id: row.get(0),
                purpose: row.get(1),
                claim_id: row.get(2),
                appointment_revision: row.get(3),
                due_at: row.get(4),
                delivery_state: row.get(5),
                attempts: row.get(6),
                payload: row.get(7),
            })
            .collect())
    }

    /// Mark one intent delivered.
    pub async fn mark_intent_delivered(&self, outbox_id: Uuid) -> Result<(), StoreError> {
        let client = self.client().await?;
        client
            .execute(
                "UPDATE scheduling_outbox SET delivery_state='delivered', delivered_at=now() \
                 WHERE outbox_id=$1",
                &[&outbox_id],
            )
            .await?;
        Ok(())
    }

    /// Schedule one intent's retry, or fail it once its attempts reach the
    /// ceiling.
    pub async fn retry_intent(
        &self,
        outbox_id: Uuid,
        next_attempt_at: DateTime<Utc>,
        attempts_ceiling: i32,
    ) -> Result<(), StoreError> {
        let client = self.client().await?;
        client
            .execute(
                "UPDATE scheduling_outbox \
                 SET delivery_state = CASE WHEN attempts >= $3 THEN 'failed' ELSE 'pending' END, \
                     next_attempt_at = CASE WHEN attempts >= $3 THEN now() ELSE $2 END \
                 WHERE outbox_id=$1",
                &[&outbox_id, &next_attempt_at, &attempts_ceiling],
            )
            .await?;
        Ok(())
    }

    /// Hold one intent locally: the deployment has no destination
    /// configured, so the intent stays recorded instead of pretending a
    /// delivery happened. Nothing is delivered, so no delivery instant is
    /// stamped either.
    pub async fn hold_intent_local(&self, outbox_id: Uuid) -> Result<(), StoreError> {
        let client = self.client().await?;
        client
            .execute(
                "UPDATE scheduling_outbox SET delivery_state='local' WHERE outbox_id=$1",
                &[&outbox_id],
            )
            .await?;
        Ok(())
    }

    /// Erase cursors whose fifteen minutes have passed.
    pub async fn erase_expired_cursors(&self, now: DateTime<Utc>) -> Result<u64, StoreError> {
        let client = self.client().await?;
        Ok(client
            .execute(
                "DELETE FROM scheduling_cursors WHERE expires_at <= $1",
                &[&now],
            )
            .await?)
    }

    /// Record a refused attempt outside the capacity transaction: the store
    /// refused the admission and rolled back, so the service writes the
    /// receipt a replay of the same key must answer with. A concurrent writer
    /// of the same key already stored one; the conflict is not an error,
    /// because either receipt answers the same replay.
    pub async fn record_refused_attempt(
        &self,
        commitment: &Commitment<'_>,
        scope: &str,
        status_code: u16,
        receipt: Value,
    ) -> Result<(), StoreError> {
        let client = self.client().await?;
        client
            .execute(
                "INSERT INTO scheduling_attempts(attempt_id, actor_issuer, actor_subject, scope, \
                 idempotency_key, request_hash, state, status_code, receipt, expires_at) \
                 VALUES($1,$2,$3,$4,$5,$6,'refused',$7,$8,$9) ON CONFLICT DO NOTHING",
                &[
                    &Uuid::new_v4(),
                    &commitment.actor_issuer,
                    &commitment.actor_subject,
                    &scope,
                    &commitment.idempotency_key,
                    &commitment.request_hash,
                    &i32::from(status_code),
                    &receipt,
                    &commitment.attempt_expires_at,
                ],
            )
            .await?;
        Ok(())
    }

    /// Record an authorization refusal in the audit journal. The capacity
    /// transactions write their audit rows in-transaction; a grant that lapsed
    /// or an actor that did not own the claim changes nothing, so its audit
    /// row is written beside the refusal instead.
    pub async fn record_refusal_audit(
        &self,
        audit_event: Uuid,
        audit_record: Value,
    ) -> Result<(), StoreError> {
        let client = self.client().await?;
        client
            .execute(
                "INSERT INTO scheduling_audit_outbox(event_id, audit_record) VALUES($1,$2)",
                &[&audit_event, &audit_record],
            )
            .await?;
        Ok(())
    }

    /// Erase idempotency receipts past their retention period. The answer is
    /// dropped, the row is kept and stamped erased: a key that answered once
    /// stays spent, so a retry after the period is refused as expired rather
    /// than executed again as a fresh request.
    ///
    /// This is the only retention the sweep enforces beside listing cursors.
    /// Appointments, history, the delivery outbox and the audit journal are
    /// not swept.
    pub async fn erase_expired_attempts(&self, now: DateTime<Utc>) -> Result<u64, StoreError> {
        let client = self.client().await?;
        Ok(client
            .execute(
                "UPDATE scheduling_attempts SET erased_at=$1, receipt=NULL \
                 WHERE expires_at <= $1 AND erased_at IS NULL",
                &[&now],
            )
            .await?)
    }

    /// The pending audit journal, oldest first.
    ///
    /// The order is the one the rows were written in, not the one their
    /// identifiers sort in: the publisher appends what this returns to a hash
    /// chain, so the order it reads in is the order the chain attests to.
    pub async fn pending_audit(&self, limit: i64) -> Result<Vec<(Uuid, Value)>, StoreError> {
        let client = self.client().await?;
        Ok(client
            .query(
                "SELECT event_id, audit_record FROM scheduling_audit_outbox \
                 WHERE published_at IS NULL ORDER BY recorded_seq LIMIT $1",
                &[&limit],
            )
            .await?
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect())
    }

    pub async fn mark_audit_published(&self, event_id: Uuid) -> Result<(), StoreError> {
        let client = self.client().await?;
        client
            .execute(
                "UPDATE scheduling_audit_outbox SET published_at=now() \
                 WHERE event_id=$1 AND published_at IS NULL",
                &[&event_id],
            )
            .await?;
        Ok(())
    }
}

const SELECT_CLAIM: &str = "SELECT claim_id, kind, state, offering, supply_id, channel, \
     displayed_start, displayed_end, occupied_start, occupied_end, units, duplicate_key, \
     hold_expires_at, revision, policy_revision, actor, reason, created_at, closed_at \
     FROM scheduling_claims WHERE claim_id=$1";

/// The consuming-claim filter, with hold expiry evaluated in the query. This
/// is the sentence the whole capacity contract turns on: an expired hold
/// stops consuming capacity at its expiry, whether or not any worker has
/// touched it.
const CONSUMING_CLAUSES: &str = "SELECT claim_id, supply_id, kind, channel, occupied_start, \
     occupied_end, units, duplicate_key, hold_expires_at \
     FROM scheduling_claims \
     WHERE state='active' \
       AND (kind='booking' OR (kind='hold' AND hold_expires_at > $4)) \
       AND supply_id = ANY($1) \
       AND occupied_start < $3::timestamptz AND $2::timestamptz < occupied_end \
     ORDER BY occupied_start";

fn map_claim_row(row: Row) -> Result<ClaimRow, StoreError> {
    Ok(ClaimRow {
        claim_id: row.get(0),
        kind: match row.get::<_, String>(1).as_str() {
            "booking" => LedgerKind::Booking,
            _ => LedgerKind::Hold,
        },
        state: match row.get::<_, String>(2).as_str() {
            "active" => ClaimState::Active,
            "released" => ClaimState::Released,
            "cancelled" => ClaimState::Cancelled,
            "consumed" => ClaimState::Consumed,
            _ => ClaimState::Expired,
        },
        offering: row.get(3),
        supply_id: row.get(4),
        channel: row.get(5),
        displayed_start: row.get(6),
        displayed_end: row.get(7),
        occupied_start: row.get(8),
        occupied_end: row.get(9),
        units: row.get(10),
        duplicate_key: row.get(11),
        hold_expires_at: row.get(12),
        revision: row.get(13),
        policy_revision: row.get(14),
        actor: row.get(15),
        reason: row.get(16),
        created_at: row.get(17),
        closed_at: row.get(18),
    })
}

fn snapshot_from_rows(rows: Vec<Row>) -> LedgerSnapshot {
    LedgerSnapshot {
        claims: rows
            .iter()
            .map(|row| LedgerClaim {
                id: row.get::<_, Uuid>(0).to_string(),
                supply_id: row.get(1),
                kind: match row.get::<_, String>(2).as_str() {
                    "booking" => LedgerKind::Booking,
                    _ => LedgerKind::Hold,
                },
                channel: row.get(3),
                start: row.get(4),
                end: row.get(5),
                units: u32::try_from(row.get::<_, i32>(6)).unwrap_or(u32::MAX),
                duplicate_key: row.get(7),
                expires_at: row.get(8),
            })
            .collect(),
    }
}

/// The window id a window admission's claim occupies.
fn window_supply_id<'a>(supply: &'a SupplyContext<'a>) -> &'a str {
    match supply {
        SupplyContext::Window { window, .. } => &window.id,
        SupplyContext::ExactTime { .. } => "",
    }
}

/// Steps 1 and 2: lock the anchor row, then read the ledger snapshot with
/// expiry evaluated in the query.
async fn lock_and_snapshot(
    transaction: &deadpool_postgres::Transaction<'_>,
    supply: &SupplyContext<'_>,
    now: DateTime<Utc>,
) -> Result<LedgerSnapshot, StoreError> {
    match supply {
        SupplyContext::ExactTime {
            exact,
            members,
            open,
            ..
        } => {
            // The anchor is the pool, not the members: two offerings on one
            // pool sell the same members and must serialize against each
            // other, and `apply_policy` anchors pool ids only.
            transaction
                .lock_supply(std::slice::from_ref(&exact.pool))
                .await?;
            // Claims occupy a member, so the snapshot reads member ids even
            // though the lock is the pool's.
            let member_ids: Vec<String> = members
                .iter()
                .map(|member| member.resource_id.clone())
                .collect();
            let earliest = open
                .iter()
                .map(|interval| interval.start)
                .min()
                .unwrap_or(now);
            let latest = open
                .iter()
                .map(|interval| interval.end)
                .max()
                .unwrap_or(now);
            let rows = transaction
                .query(CONSUMING_CLAUSES, &[&member_ids, &earliest, &latest, &now])
                .await?;
            Ok(snapshot_from_rows(rows))
        }
        SupplyContext::Window { window, .. } => {
            transaction
                .lock_supply(std::slice::from_ref(&window.id))
                .await?;
            let rows = transaction
                .query(
                    "SELECT claim_id, supply_id, kind, channel, occupied_start, occupied_end, \
                     units, duplicate_key, hold_expires_at \
                     FROM scheduling_claims \
                     WHERE state='active' \
                       AND (kind='booking' OR (kind='hold' AND hold_expires_at > $2)) \
                       AND supply_id = $1 \
                     ORDER BY occupied_start",
                    &[&window.id, &now],
                )
                .await?;
            Ok(snapshot_from_rows(rows))
        }
    }
}

/// The task-grant re-check, inside the transaction: the grant's own expiry
/// is the one fact that can change between the service's authorization
/// decision and the commit, so it is checked against the commitment's now.
fn check_grant_current(commitment: &Commitment<'_>) -> Result<(), CommitError> {
    match commitment.grant_exp_unix {
        Some(exp) if commitment.now.timestamp() < i64::try_from(exp).unwrap_or(i64::MAX) => Ok(()),
        Some(_) => Err(CommitError::Unauthorized),
        // A mutating commitment without a grant never reaches the store: the
        // service refuses it before the transaction opens.
        None => Ok(()),
    }
}

/// The in-memory evaluator call, step 4.
///
/// `exclude` is the one standing claim this commitment replaces, supplied
/// only by the reschedule transaction from the appointment row it locks. A
/// create path passes `None`: the wire request cannot carry an exclusion, so
/// no caller can name another party's allocation out of the check.
fn evaluate(
    offering: &registry_scheduling_core::OfferingPolicy,
    supply: &SupplyContext<'_>,
    request: &registry_scheduling_core::AdmissionRequest,
    snapshot: &LedgerSnapshot,
    commitment: &Commitment<'_>,
    exclude: Option<&str>,
) -> Result<registry_scheduling_core::Admission, AdmissionRefusal> {
    match supply {
        SupplyContext::ExactTime {
            exact,
            members,
            open,
            closures,
        } => evaluate_exact_time_admission(
            &ExactTimeContext {
                offering,
                exact,
                members,
                open,
                closures,
                snapshot,
                policy_revision: u64::try_from(commitment.policy_revision).unwrap_or(u64::MAX),
                now: commitment.now,
            },
            request,
            exclude,
        ),
        SupplyContext::Window {
            window,
            lead_time_minutes,
            horizon_days,
            channels,
        } => evaluate_window_admission(
            &registry_scheduling_core::WindowContext {
                offering,
                window,
                lead_time_minutes: *lead_time_minutes,
                horizon_days: *horizon_days,
                snapshot,
                policy_revision: u64::try_from(commitment.policy_revision).unwrap_or(u64::MAX),
                channels,
                now: commitment.now,
            },
            request,
            exclude,
        ),
    }
}

fn hold_ledger_claim(hold: &ClaimRow) -> LedgerClaim {
    LedgerClaim {
        id: hold.claim_id.to_string(),
        supply_id: hold.supply_id.clone(),
        kind: hold.kind,
        channel: hold.channel.clone(),
        start: hold.occupied_start,
        end: hold.occupied_end,
        units: u32::try_from(hold.units).unwrap_or(u32::MAX),
        duplicate_key: hold.duplicate_key.clone(),
        expires_at: hold.hold_expires_at,
    }
}

/// The policy revision the deployment is published under, read inside the
/// commitment's own transaction. A commitment is admitted against the stored
/// revision, never against one cached when the process started: operator
/// tooling and a rolling deploy both move it under a running process, and a
/// claim written under the cached number would name a policy that no longer
/// stands.
///
/// The share lock holds it still for the life of the transaction, so a
/// policy published concurrently waits behind the commitments already in
/// flight instead of moving under them.
async fn current_policy_revision(
    transaction: &deadpool_postgres::Transaction<'_>,
) -> Result<i64, StoreError> {
    let row = transaction
        .query_one(
            "SELECT policy_revision FROM scheduling_meta WHERE singleton FOR SHARE",
            &[],
        )
        .await?;
    Ok(row.get(0))
}

/// Replay a stored attempt: the same key with a different payload is
/// refused as reused, an erased receipt as expired, and a retained one is
/// answered exactly as it was.
async fn replay_stored_attempt(
    transaction: &deadpool_postgres::Transaction<'_>,
    commitment: &Commitment<'_>,
    scope: &str,
) -> Result<Option<ReplayOutcome>, StoreError> {
    let row = transaction
        .query_opt(
            "SELECT request_hash, state, status_code, receipt, expires_at, erased_at \
             FROM scheduling_attempts \
             WHERE actor_issuer=$1 AND actor_subject=$2 AND scope=$3 AND idempotency_key=$4",
            &[
                &commitment.actor_issuer,
                &commitment.actor_subject,
                &scope,
                &commitment.idempotency_key,
            ],
        )
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored_hash: String = row.get(0);
    let expires_at: DateTime<Utc> = row.get(4);
    let erased_at: Option<DateTime<Utc>> = row.get(5);
    let receipt: Option<Value> = row.get(3);
    // A different payload under a stored key is a reuse whether or not the
    // answer is still held: the caller is told the key is not theirs to
    // re-aim before being told the answer is gone.
    if stored_hash != commitment.request_hash {
        return Ok(Some(ReplayOutcome::Refused(CommitError::KeyReused)));
    }
    let Some(receipt) = receipt.filter(|_| erased_at.is_none() && expires_at > commitment.now)
    else {
        return Ok(Some(ReplayOutcome::Refused(CommitError::KeyExpired)));
    };
    Ok(Some(ReplayOutcome::Replay {
        status_code: u16::try_from(row.get::<_, i32>(2)).unwrap_or(500),
        receipt,
    }))
}

/// Mint reminder intents for a freshly committed appointment: one outbox
/// row per authored offset whose due time is still ahead. An offset already
/// past mints nothing, because a reminder about the past is noise, not a
/// notice.
async fn mint_reminders(
    transaction: &deadpool_postgres::Transaction<'_>,
    claim: &ClaimRow,
    offering: &registry_scheduling_core::OfferingPolicy,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    for reminder in &offering.reminders {
        let minutes = reminder.minutes_before;
        let Some(due_at) = claim
            .displayed_start
            .checked_sub_signed(TimeDelta::minutes(i64::from(minutes)))
        else {
            continue;
        };
        if due_at <= now {
            continue;
        }
        transaction
            .execute(
                "INSERT INTO scheduling_outbox(outbox_id, purpose, claim_id, \
                 appointment_revision, due_at, delivery_state, next_attempt_at, payload) \
                 VALUES($1,'reminder',$2,$3,$4,'pending',$4,$5)",
                &[
                    &Uuid::new_v4(),
                    &claim.claim_id,
                    &claim.revision,
                    &due_at,
                    &json!({
                        "appointmentId": claim.claim_id,
                        "revision": claim.revision,
                        "offering": offering.id,
                        "start": claim.displayed_start,
                        "minutesBefore": minutes,
                    }),
                ],
            )
            .await?;
    }
    Ok(())
}

fn confirmation_payload(claim: &ClaimRow, policy_revision: i64) -> Value {
    json!({
        "appointmentId": claim.claim_id,
        "revision": claim.revision,
        "offering": claim.offering,
        "start": claim.displayed_start,
        "end": claim.displayed_end,
        "policyRevision": policy_revision,
    })
}

pub(crate) async fn replace_facts_in_transaction(
    transaction: &deadpool_postgres::Transaction<'_>,
    facts: &SchedulingFacts,
    audit_event: Uuid,
    audit_record: Value,
) -> Result<(), StoreError> {
    // Take every supply anchor before reading a claim. A capacity
    // transaction holds its own anchor from its snapshot until it commits,
    // so holding all of them means no commitment is mid-evaluation against
    // members this swap is about to delete, and a claim written a moment
    // later is seen by the guard below rather than stranded behind it. A
    // capacity transaction takes exactly one anchor and this one takes them
    // in the anchor's own order, so the two cannot cycle.
    transaction
        .execute(
            "SELECT supply_id FROM scheduling_supply ORDER BY supply_id FOR UPDATE",
            &[],
        )
        .await?;
    let occupied = occupied_resources_retired_by(transaction, facts).await?;
    if !occupied.is_empty() {
        return Err(StoreError::FactsInUse(occupied.join(", ")));
    }
    transaction
        .execute("DELETE FROM scheduling_pool_members", &[])
        .await?;
    transaction
        .execute("DELETE FROM scheduling_pools", &[])
        .await?;
    transaction
        .execute("DELETE FROM scheduling_locations", &[])
        .await?;
    transaction
        .execute("DELETE FROM scheduling_exceptions", &[])
        .await?;
    for location in &facts.locations {
        transaction
            .execute(
                "INSERT INTO scheduling_locations(location_id, timezone) VALUES($1,$2)",
                &[&location.id, &location.timezone],
            )
            .await?;
    }
    for pool in &facts.pools {
        transaction
            .execute(
                "INSERT INTO scheduling_pools(pool_id) VALUES($1)",
                &[&pool.id],
            )
            .await?;
        for member in &pool.members {
            transaction
                .execute(
                    "INSERT INTO scheduling_pool_members(resource_id, pool_id, capabilities, \
                     available) VALUES($1,$2,$3,$4)",
                    &[
                        &member.resource_id,
                        &pool.id,
                        &member.capabilities,
                        &member.available,
                    ],
                )
                .await?;
        }
    }
    for exception in &facts.exceptions {
        let kind = match exception.kind {
            registry_scheduling_core::ExceptionRecordKind::Closure => "closure",
            registry_scheduling_core::ExceptionRecordKind::Opening => "opening",
        };
        transaction
            .execute(
                "INSERT INTO scheduling_exceptions(exception_id, location, kind, date, \
                 start_time, end_time, reopens, authority) \
                 VALUES($1,$2,$3,$4::text::date,$5,$6,$7,$8)",
                &[
                    &exception.id,
                    &exception.location,
                    &kind,
                    &exception.date,
                    &exception.start_time,
                    &exception.end_time,
                    &exception.reopens,
                    &exception.authority,
                ],
            )
            .await?;
    }
    transaction
        .execute(
            "INSERT INTO scheduling_audit_outbox(event_id, audit_record) VALUES($1,$2)",
            &[&audit_event, &audit_record],
        )
        .await?;
    Ok(())
}

/// The resources live claims occupy that the incoming records do not carry.
///
/// An exact-time claim names its member in `supply_id`, so a swap that drops
/// a member out from under a live booking would leave that booking pointing
/// at a resource the deployment no longer has: invisible to every pool
/// snapshot, counted against nothing, and still promised to its caller. A
/// window claim names the window instead, which records never carry, so the
/// window anchors are excluded rather than reported as missing members.
async fn occupied_resources_retired_by(
    transaction: &deadpool_postgres::Transaction<'_>,
    facts: &SchedulingFacts,
) -> Result<Vec<String>, StoreError> {
    let incoming: Vec<String> = facts
        .pools
        .iter()
        .flat_map(|pool| pool.members.iter())
        .map(|member| member.resource_id.clone())
        .collect();
    let rows = transaction
        .query(
            "SELECT DISTINCT supply_id FROM scheduling_claims \
             WHERE state='active' \
               AND (kind='booking' OR (kind='hold' AND hold_expires_at > now())) \
               AND supply_id <> ALL($1::text[]) \
               AND supply_id NOT IN \
                   (SELECT supply_id FROM scheduling_supply WHERE kind='window') \
             ORDER BY supply_id",
            &[&incoming],
        )
        .await?;
    Ok(rows.iter().map(|row| row.get(0)).collect())
}

/// A claim about to be written.
struct NewClaim<'c> {
    claim_id: Uuid,
    kind: LedgerKind,
    state: ClaimState,
    offering: &'c str,
    supply_id: &'c str,
    channel: Option<&'c str>,
    displayed_start: DateTime<Utc>,
    displayed_end: DateTime<Utc>,
    occupied_start: DateTime<Utc>,
    occupied_end: DateTime<Utc>,
    units: i32,
    duplicate_key: Option<&'c str>,
    hold_expires_at: Option<DateTime<Utc>>,
    revision: i64,
    policy_revision: i64,
    actor: &'c str,
    reason: Option<&'c str>,
}

/// A claim about to move to a new time or resource.
struct ClaimMove<'c> {
    claim_id: Uuid,
    supply_id: &'c str,
    displayed_start: DateTime<Utc>,
    displayed_end: DateTime<Utc>,
    occupied_start: DateTime<Utc>,
    occupied_end: DateTime<Utc>,
    policy_revision: i64,
    next_revision: i64,
}

/// The private statement-set the capacity transactions run. Holding these on
/// a trait keeps every multi-step method on `Transaction` without exposing
/// the transaction handle itself.
#[async_trait::async_trait]
trait CapacityStatements {
    async fn lock_supply(&self, supply_ids: &[String]) -> Result<(), StoreError>;
    async fn insert_claim(&self, claim: &NewClaim<'_>) -> Result<ClaimRow, StoreError>;
    async fn close_claim(
        &self,
        claim_id: Uuid,
        state: ClaimState,
        reason: Option<&str>,
        next_revision: i64,
    ) -> Result<(), StoreError>;
    async fn move_claim(&self, movement: &ClaimMove<'_>) -> Result<(), StoreError>;
    async fn insert_history(
        &self,
        claim_id: Uuid,
        revision: i64,
        kind: &str,
        occurred_at: DateTime<Utc>,
        actor: &str,
        detail: Value,
    ) -> Result<(), StoreError>;
    async fn insert_outbox(
        &self,
        purpose: &str,
        claim_id: Uuid,
        appointment_revision: i64,
        due_at: DateTime<Utc>,
        payload: Value,
    ) -> Result<(), StoreError>;
    async fn suppress_pending_reminders(&self, claim_id: Uuid) -> Result<(), StoreError>;
    /// Write the receipt this commitment answers a replay with. The key is
    /// claimed here, at the end of the transaction, so a writer who finds it
    /// already taken is refused rather than failed.
    async fn insert_attempt(
        &self,
        attempt_id: Uuid,
        commitment: &Commitment<'_>,
        scope: &str,
        state: AttemptState,
        status_code: u16,
        receipt: Value,
    ) -> Result<(), CommitError>;
    async fn insert_audit(&self, event_id: Uuid, record: &Value) -> Result<(), StoreError>;
    async fn claim_in_transaction(&self, claim_id: Uuid) -> Result<Option<ClaimRow>, StoreError>;
    /// Take the caller's hold-ceiling lock, then count the holds it has open.
    ///
    /// The lock is the reason the count means anything. A commitment locks the
    /// supply anchor it is about to draw from, but the ceiling bounds the
    /// caller across every pool, and two holds on two pools lock two different
    /// rows. Without a lock scoped to the caller, two concurrent holds each
    /// read the same under-ceiling count and both write, so a caller admitted
    /// two holds can end up holding three. The count and the lock are one
    /// method so neither can be taken without the other.
    async fn lock_caller_and_count_active_holds(
        &self,
        actor: &str,
        now: DateTime<Utc>,
    ) -> Result<i64, StoreError>;
}

#[async_trait::async_trait]
impl CapacityStatements for deadpool_postgres::Transaction<'_> {
    async fn lock_supply(&self, supply_ids: &[String]) -> Result<(), StoreError> {
        let rows = self
            .query(
                "SELECT supply_id FROM scheduling_supply WHERE supply_id = ANY($1) FOR UPDATE",
                &[&supply_ids],
            )
            .await?;
        if rows.len() != supply_ids.len() {
            return Err(StoreError::Corrupt);
        }
        Ok(())
    }

    async fn insert_claim(&self, claim: &NewClaim<'_>) -> Result<ClaimRow, StoreError> {
        let kind = match claim.kind {
            LedgerKind::Booking => "booking",
            LedgerKind::Hold => "hold",
        };
        let row = self
            .query_one(
                "INSERT INTO scheduling_claims(claim_id, kind, state, offering, supply_id, \
                 channel, displayed_start, displayed_end, occupied_start, occupied_end, units, \
                 duplicate_key, hold_expires_at, revision, policy_revision, actor, reason) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) \
                 RETURNING created_at",
                &[
                    &claim.claim_id,
                    &kind,
                    &claim.state.as_str(),
                    &claim.offering,
                    &claim.supply_id,
                    &claim.channel,
                    &claim.displayed_start,
                    &claim.displayed_end,
                    &claim.occupied_start,
                    &claim.occupied_end,
                    &claim.units,
                    &claim.duplicate_key,
                    &claim.hold_expires_at,
                    &claim.revision,
                    &claim.policy_revision,
                    &claim.actor,
                    &claim.reason,
                ],
            )
            .await?;
        Ok(ClaimRow {
            claim_id: claim.claim_id,
            kind: claim.kind,
            state: claim.state,
            offering: claim.offering.to_owned(),
            supply_id: claim.supply_id.to_owned(),
            channel: claim.channel.map(str::to_owned),
            displayed_start: claim.displayed_start,
            displayed_end: claim.displayed_end,
            occupied_start: claim.occupied_start,
            occupied_end: claim.occupied_end,
            units: claim.units,
            duplicate_key: claim.duplicate_key.map(str::to_owned),
            hold_expires_at: claim.hold_expires_at,
            revision: claim.revision,
            policy_revision: claim.policy_revision,
            actor: claim.actor.to_owned(),
            reason: claim.reason.map(str::to_owned),
            created_at: row.get(0),
            closed_at: None,
        })
    }

    async fn close_claim(
        &self,
        claim_id: Uuid,
        state: ClaimState,
        reason: Option<&str>,
        next_revision: i64,
    ) -> Result<(), StoreError> {
        self.execute(
            "UPDATE scheduling_claims SET state=$2, reason=$3, revision=$4, \
             closed_at=now(), changed_at=now() WHERE claim_id=$1",
            &[&claim_id, &state.as_str(), &reason, &next_revision],
        )
        .await?;
        Ok(())
    }

    async fn move_claim(&self, movement: &ClaimMove<'_>) -> Result<(), StoreError> {
        self.execute(
            "UPDATE scheduling_claims SET supply_id=$2, displayed_start=$3, displayed_end=$4, \
             occupied_start=$5, occupied_end=$6, policy_revision=$7, revision=$8, \
             changed_at=now() WHERE claim_id=$1",
            &[
                &movement.claim_id,
                &movement.supply_id,
                &movement.displayed_start,
                &movement.displayed_end,
                &movement.occupied_start,
                &movement.occupied_end,
                &movement.policy_revision,
                &movement.next_revision,
            ],
        )
        .await?;
        Ok(())
    }

    async fn insert_history(
        &self,
        claim_id: Uuid,
        revision: i64,
        kind: &str,
        occurred_at: DateTime<Utc>,
        actor: &str,
        detail: Value,
    ) -> Result<(), StoreError> {
        self.execute(
            "INSERT INTO scheduling_history(event_id, claim_id, revision, kind, occurred_at, \
             actor, detail) VALUES($1,$2,$3,$4,$5,$6,$7)",
            &[
                &Uuid::new_v4(),
                &claim_id,
                &revision,
                &kind,
                &occurred_at,
                &actor,
                &detail,
            ],
        )
        .await?;
        Ok(())
    }

    async fn insert_outbox(
        &self,
        purpose: &str,
        claim_id: Uuid,
        appointment_revision: i64,
        due_at: DateTime<Utc>,
        payload: Value,
    ) -> Result<(), StoreError> {
        self.execute(
            "INSERT INTO scheduling_outbox(outbox_id, purpose, claim_id, appointment_revision, \
             due_at, delivery_state, next_attempt_at, payload) \
             VALUES($1,$2,$3,$4,$5,'pending',$5,$6)",
            &[
                &Uuid::new_v4(),
                &purpose,
                &claim_id,
                &appointment_revision,
                &due_at,
                &payload,
            ],
        )
        .await?;
        Ok(())
    }

    async fn suppress_pending_reminders(&self, claim_id: Uuid) -> Result<(), StoreError> {
        self.execute(
            "DELETE FROM scheduling_outbox \
             WHERE claim_id=$1 AND purpose='reminder' AND delivery_state='pending'",
            &[&claim_id],
        )
        .await?;
        Ok(())
    }

    async fn insert_attempt(
        &self,
        attempt_id: Uuid,
        commitment: &Commitment<'_>,
        scope: &str,
        state: AttemptState,
        status_code: u16,
        receipt: Value,
    ) -> Result<(), CommitError> {
        let written = self
            .execute(
                "INSERT INTO scheduling_attempts(attempt_id, actor_issuer, actor_subject, scope, \
                 idempotency_key, request_hash, state, status_code, receipt, expires_at) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING",
                &[
                    &attempt_id,
                    &commitment.actor_issuer,
                    &commitment.actor_subject,
                    &scope,
                    &commitment.idempotency_key,
                    &commitment.request_hash,
                    &state.as_str(),
                    &i32::from(status_code),
                    &receipt,
                    &commitment.attempt_expires_at,
                ],
            )
            .await?;
        if written == 0 {
            // The replay read at the head of this transaction saw no stored
            // attempt because the writer that owns the key had not committed
            // yet. The key is not this caller's to answer under, and the
            // whole transaction rolls back behind the refusal, so nothing was
            // decided.
            return Err(CommitError::KeyReused);
        }
        Ok(())
    }

    async fn insert_audit(&self, event_id: Uuid, record: &Value) -> Result<(), StoreError> {
        self.execute(
            "INSERT INTO scheduling_audit_outbox(event_id, audit_record) VALUES($1,$2)",
            &[&event_id, &record],
        )
        .await?;
        Ok(())
    }

    async fn claim_in_transaction(&self, claim_id: Uuid) -> Result<Option<ClaimRow>, StoreError> {
        let row = self.query_opt(SELECT_CLAIM, &[&claim_id]).await?;
        row.map(map_claim_row).transpose()
    }

    async fn lock_caller_and_count_active_holds(
        &self,
        actor: &str,
        now: DateTime<Utc>,
    ) -> Result<i64, StoreError> {
        self.execute(
            "SELECT pg_advisory_xact_lock($1, hashtext($2))",
            &[&HOLD_CEILING_LOCK_NAMESPACE, &actor],
        )
        .await?;
        let row = self
            .query_one(
                "SELECT count(*) FROM scheduling_claims \
                 WHERE actor=$1 AND kind='hold' AND state='active' AND hold_expires_at > $2",
                &[&actor, &now],
            )
            .await?;
        Ok(row.get(0))
    }
}

fn tls_connector(
    config: &DatabaseConfig,
    secrets: &SecretResolver,
) -> Result<tokio_postgres_rustls::MakeRustlsConnect, StoreError> {
    let provider = rustls::crypto::ring::default_provider();
    if provider.install_default().is_err()
        && rustls::crypto::CryptoProvider::get_default().is_none()
    {
        return Err(StoreError::Configuration);
    }
    if let Some(reference) = &config.trusted_root_certificate_ref {
        let certificate = secrets.resolve(reference).map_err(|error| {
            StoreError::SecretConfiguration(describe_secret_failure(
                "database.trustedRootCertificateRef",
                reference,
                &error,
            ))
        })?;
        let mut roots = rustls::RootCertStore::empty();
        use rustls::pki_types::pem::PemObject as _;
        let mut count = 0usize;
        for certificate in
            rustls::pki_types::CertificateDer::pem_slice_iter(certificate.expose_secret())
        {
            roots
                .add(certificate.map_err(|_| StoreError::Configuration)?)
                .map_err(|_| StoreError::Configuration)?;
            count += 1;
        }
        if count == 0 {
            return Err(StoreError::Configuration);
        }
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(tokio_postgres_rustls::MakeRustlsConnect::new(client))
    } else {
        tokio_postgres_rustls::MakeRustlsConnect::with_native_certs()
            .map(|value| value.0)
            .map_err(|_| StoreError::Configuration)
    }
}

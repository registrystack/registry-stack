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
//! 3. The revision guards, with `policy.changed` winning: the revision of
//!    the policy this process actually evaluated must still be the stored
//!    one, and the facts the request resolved must not have been replaced
//!    by a records swap. Both are checked under the anchor, after every
//!    lock wait, so a commitment never carries a stale evaluation forward.
//! 4. The pure evaluators from `registry-scheduling-core`, in memory, inside
//!    the lock but never doing I/O. The task grant's expiry is re-checked
//!    here too, against a fresh observation of the clock taken after the
//!    waits, so a grant that lapses before the commit never books. A new
//!    hold's expiry starts at that same observation, so lock waits do not
//!    shorten its time to live.
//! 5. The claim, the idempotency attempt, the history event, and the outbox
//!    rows, written in that same transaction. The lifecycle writes carry
//!    the observed revision and the active state in their own predicates,
//!    so a second writer that accepted the same observed state changes
//!    nothing.
//! 6. Commit.
//!
//! Workers claim due work with `FOR UPDATE SKIP LOCKED`, a limit, and a
//! dispatch lease: a claimed intent is not claimable again until its lease
//! passes, and an outcome write only lands for the attempt that owns it.

use std::collections::HashMap;
use std::str::FromStr;
#[cfg(feature = "postgres-test")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
#[cfg(feature = "postgres-test")]
use tokio::sync::Notify;

use chrono::{DateTime, TimeDelta, Utc};
use deadpool_postgres::{
    GenericClient as DeadpoolGenericClient, Manager, ManagerConfig, Pool, RecyclingMethod, Runtime,
};
use registry_platform_calendar::CalendarInterval;
use registry_platform_config::SecretResolver;
use registry_platform_dispatch::postgres::{cancel_unattempted, JobKey, JobTable};
use registry_scheduling_core::{
    assess_window_record_impact, evaluate_exact_time_admission, evaluate_exact_time_bundle,
    evaluate_exact_time_physical_bundle, evaluate_hold_state, evaluate_window_admission,
    location_closure_intervals, location_open_intervals, maximum_concurrent_units,
    AdditionalAllocationRequest, AdmissionRefusal, AllocationDocument, AllocationError,
    AllocationInterval, AllocationLimits, AllocationRequirementDocument, BundleAdmission,
    BundleAllocation, BundleEvaluationError, ExactTimeBundleContext, ExactTimeBundleLineContext,
    ExactTimeContext, ExternalReference, LedgerClaim, LedgerKind, LedgerSnapshot, PartyCounts,
    PartyReference, PolicyCheckReason, PoolMember, PublishedWindow, SchedulingDiagnostic,
    SchedulingFacts, SchedulingPolicy, StandingAllocation, APPOINTMENT_CANCELLED_TRIGGER,
    APPOINTMENT_CONFIRMED_TRIGGER, APPOINTMENT_RESCHEDULED_TRIGGER,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tokio_postgres::{Config as PgConfig, Row};
use uuid::Uuid;

use crate::config::{describe_secret_failure, DatabaseConfig};
use crate::hooks::{ActivatedHooks, HookCaptureError};

mod activation;
mod attempt_key;
mod attendance;
mod operational;
mod resource_availability;
mod source_busy;
pub use activation::{
    activation_layout, policy_pool_ids, Activation, ActivationOutcome, ActivationPlan,
    ActivationRequest, ActivePackage, DeployedPolicy, RoleMode, SchemaState, SINGLE_ROLE_STATEMENT,
};
use activation::{apply_migrations_in, check_active_package_in, schema_state_in};
pub use attempt_key::attempt_key_reference;
pub use operational::{OperationalAppointmentRow, OperationalScopeCoverage};
pub use resource_availability::{ResourceSupplyImpact, ResourceSupplyImpacts};
pub use source_busy::{resource_interval_is_available, BusyStoreError};

const SCHEDULING_MIGRATION: &str = include_str!("../migrations/0200_scheduling.sql");
const OPERATIONAL_READS_MIGRATION: &str = include_str!("../migrations/0201_operational_reads.sql");
const RESOURCE_AVAILABILITY_MIGRATION: &str =
    include_str!("../migrations/0202_resource_availability.sql");
const BOOKING_PARTY_MIGRATION: &str = include_str!("../migrations/0203_booking_party.sql");
const SOURCE_MANAGER_MIGRATION: &str = include_str!("../migrations/0204_source_manager.sql");
const ATOMIC_ALLOCATIONS_MIGRATION: &str =
    include_str!("../migrations/0205_atomic_allocations.sql");
const SOURCE_BUSY_MIGRATION: &str = include_str!("../migrations/0206_source_busy.sql");
const WINDOW_RESOURCES_MIGRATION: &str = include_str!("../migrations/0207_window_resources.sql");
const ATTENDANCE_MIGRATION: &str = include_str!("../migrations/0208_attendance.sql");
const SOURCE_BUSY_OUTCOME_MIGRATION: &str =
    include_str!("../migrations/0209_source_busy_outcome.sql");
/// Every schema version, in the order it is applied. The baseline is
/// version [`BASELINE_SCHEMA_VERSION`], above every version an earlier
/// release applied; each later migration takes the next number.
const SCHEMA_VERSIONS: [i64; 10] = [200, 201, 202, 203, 204, 205, 206, 207, 208, 209];
/// The baseline schema version. A ledger holding any version below it was
/// left by an earlier pre-1.0 release, which this release refuses by name:
/// version 100 is the v0.42.0 and v0.43.0 baseline, whose outbox and hook
/// delivery tables are not the shared dispatch shape this release reads.
const BASELINE_SCHEMA_VERSION: i64 = 200;
/// The most undelivered intents one operator query returns. This matches the
/// product's 200-item maximum for public listings, so an operator read does
/// not create a second, unbounded listing policy.
pub const MAXIMUM_UNDELIVERED_INTENTS_LIMIT: i64 = 200;
const _: () = assert!(
    versions_start_at_baseline_and_increase(&SCHEMA_VERSIONS),
    "Scheduling migrations must start at BASELINE_SCHEMA_VERSION and strictly increase"
);

const fn versions_start_at_baseline_and_increase(versions: &[i64]) -> bool {
    if versions.is_empty() || versions[0] != BASELINE_SCHEMA_VERSION {
        return false;
    }
    let mut index = 1;
    while index < versions.len() {
        if versions[index] <= versions[index - 1] {
            return false;
        }
        index += 1;
    }
    true
}

/// Refuse, by name, a ledger a pre-1.0 release left: any version below the
/// 1.0 baseline. It is taken before any pending or newer check.
fn refuse_pre_1_0_schema(applied: &[i64]) -> Result<(), StoreError> {
    if applied
        .iter()
        .any(|version| *version < BASELINE_SCHEMA_VERSION)
    {
        return Err(StoreError::Pre1_0Schema {
            versions: applied.to_vec(),
        });
    }
    Ok(())
}

/// Serializes schema migration and package activation on one transaction
/// lock. A second `schedulingctl apply` waits here until the first commits or
/// rolls back, so two applies never race the ledger. The key spells the ASCII
/// bytes of "sched".
const MIGRATION_LOCK_KEY: i64 = 0x7363_6865_6475_6c65;

/// The advisory-lock namespace the hold ceiling serializes one caller in. The
/// second half of the key hashes the deployment's schema with the caller's
/// verified issuer and subject, so two deployments sharing a database do not
/// serialize each other. The lock is a transaction lock: PostgreSQL releases
/// it when the capacity transaction ends, committed or rolled back. The
/// namespace spells the ASCII bytes of "SCHD".
const HOLD_CEILING_LOCK_NAMESPACE: i32 = 0x5343_4844;

/// The deployment's clock: the instant the HTTP edge stamps on each request,
/// the store's authorization re-checks and hold expiry inside a capacity
/// transaction, and the runtime workers' passes all read it. Production
/// observes the system clock; the database suite pins one, so a test's
/// slots and windows sit at a fixed time of day and an expiry boundary is
/// crossed deterministically inside a transaction. The clock sits behind a
/// shared lock so every handle cloned from one store reads the same time.
pub type Clock = std::sync::Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;
type SharedClock = std::sync::Arc<std::sync::RwLock<Clock>>;

fn system_clock() -> SharedClock {
    std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(Utc::now)))
}

/// Mark one runtime transaction as understanding the atomic allocation
/// ledger. The migration-owned triggers refuse writers that omit this local
/// marker, and PostgreSQL clears it at commit or rollback.
async fn mark_allocation_writer(
    transaction: &deadpool_postgres::Transaction<'_>,
) -> Result<(), StoreError> {
    transaction
        .batch_execute("SET LOCAL registry_scheduling.allocation_writer = 'v2'")
        .await?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("PostgreSQL 17 or newer is required; upgrade the database server before activating or serving a package")]
    UnsupportedPostgres,
    #[error("the Scheduling database configuration is invalid")]
    Configuration,
    #[error("the undelivered-intents limit must be between 1 and 200")]
    InvalidUndeliveredIntentsLimit,
    #[error("the Scheduling database secret could not be resolved: {0}")]
    SecretConfiguration(String),
    #[error("the Scheduling database is not in the state this runtime expects")]
    Corrupt,
    #[error("the bounded Scheduling capacity snapshot is too large to evaluate")]
    CapacitySnapshotTooLarge,
    #[error(
        "the Scheduling database uses a pre-1.0 schema (versions {}); this release supports fresh installs only. Create a fresh database and apply the package",
        schema_versions(versions)
    )]
    Pre1_0Schema { versions: Vec<i64> },
    #[error("the Scheduling database belongs to another deployment")]
    DeploymentIdentity,
    /// A commit whose acknowledgment never arrived and whose outcome could
    /// not be read back: it may have taken effect.
    #[error(
        "a Scheduling commit was not acknowledged and its outcome could not be read back; it may have taken effect"
    )]
    Unacknowledged,
    /// The schema is behind this release. Only `schedulingctl apply`
    /// migrates it.
    #[error(
        "the Scheduling database schema is behind this release (pending versions {}); run `schedulingctl plan --runtime-config FILE` then `schedulingctl apply --runtime-config FILE`",
        schema_versions(pending)
    )]
    SchemaPending { pending: Vec<i64> },
    #[error(
        "the Scheduling database holds schema version {version}, newer than this release knows; run the Scheduling release that applied it"
    )]
    SchemaNewer { version: i64 },
    /// The runtime role cannot read the activation ledger its search path
    /// reaches: it lacks USAGE on the schema, which would otherwise read as
    /// an empty database, or SELECT on a ledger table, as a rotated runtime
    /// role does before apply grants it.
    #[error(
        "the Scheduling runtime role cannot read the activation ledger in schema {schema}; run `schedulingctl apply --runtime-config FILE` to grant the runtime role its privileges, then rerun `schedulingctl plan --runtime-config FILE`"
    )]
    LedgerUnreadable { schema: String },
    #[error(
        "no Scheduling package has been applied to this database; run `schedulingctl plan --runtime-config FILE` then `schedulingctl apply --runtime-config FILE`"
    )]
    NotActivated,
    /// The ledger recorded another database identity. Only the key is
    /// named: the two values are operator identifiers, not a diagnosis.
    #[error(
        "the database identity recorded by the activation ledger differs from the runtime configuration at identity.databaseId; point database.runtimeUrlRef and database.migrationUrlRef at the database this deployment owns, or correct identity.databaseId"
    )]
    DatabaseIdMismatch,
    #[error(
        "package {digest} is already the active package on this database; nothing needs applying"
    )]
    PackageAlreadyActive { digest: String },
    #[error(
        "the verified package {candidate} is not the active package {active} on this database; run `schedulingctl plan --runtime-config FILE` then `schedulingctl apply --runtime-config FILE`"
    )]
    PackageNotActive { active: String, candidate: String },
    /// The ledger recorded split role mode, and the runtime credential can
    /// now write the ledger: a grant was added after the apply, or the role
    /// gained the migration role's authority.
    #[error(
        "the activation ledger records split role mode, but the runtime credential can now write the ledger; run `schedulingctl apply --runtime-config FILE` to reissue the runtime role's grants and record the role mode it holds"
    )]
    RoleModeDrift,
    /// The runtime role differs from the migration role but can still write
    /// the ledger indirectly, through an object it owns, a TRIGGER or schema
    /// CREATE privilege, or a trigger already attached to a Scheduling
    /// table, which the grants apply issues cannot take away. The text names
    /// the statement that separates the roles.
    #[error("{0}")]
    SplitRoleWeakened(String),
    /// A split runtime role no longer holds every grant apply issued it,
    /// which moving an object's ownership back to the migration role takes
    /// away. The field names the runtime role.
    #[error(
        "the runtime role {0} no longer holds every grant `schedulingctl apply` issues it; run `schedulingctl apply --runtime-config FILE` to reissue them"
    )]
    RuntimeGrantsMissing(String),
    /// A retained hook event could not be proven deliverable under the
    /// destination binding it was captured for.
    #[error(
        "the candidate policy cannot deliver every retained hook event under the destination binding it was captured for, or the retained deliveries could not be read; keep those destinations declared and unchanged until their deliveries drain"
    )]
    RetainedHookBindings,
    /// The hook half of the terminal dispatch retention pass failed. The
    /// cause is value-free: a refused bound or the server's SQLSTATE.
    #[error("the Scheduling dispatch retention pass could not complete: {0}")]
    DispatchRetention(#[source] registry_platform_hooks::delivery::RetentionError),
    /// A delivery-intent dispatch pass could not complete: the claim, the
    /// liveness read, or the outcome write was refused. The cause is
    /// value-free; the dispatch core reports it as an operational event.
    #[error("the Scheduling delivery intent dispatch pass could not complete")]
    IntentDispatch,
    /// The environment records would retire or reduce supply that live
    /// appointments or holds still occupy. The swap is refused whole, so the
    /// operator either keeps the supply or closes what stands on it first.
    #[error(
        "the environment records retire, move, or reduce {0}, which live appointments or holds still occupy"
    )]
    FactsInUse(String),
    #[error(
        "window {window} changed without advancing its revision beyond {current}; proposed revision is {proposed}"
    )]
    WindowRevision {
        window: String,
        current: u64,
        proposed: u64,
    },
    #[error("the proposed policy would strand standing commitments: {0}")]
    PolicyInUse(String),
    /// A commitment asked to serialize against supply no publication
    /// anchored. Naming the reference is what makes this an operator's
    /// deployment gap in the diagnostics rather than an unexplained
    /// inconsistency; the caller is told only that the deployment is
    /// unavailable.
    #[error("the Scheduling deployment anchors no supply for {0}")]
    UnanchoredSupply(String),
    /// A resource pool and a published window claim the same supply
    /// identifier. The two publish paths would write one anchor row between
    /// them, so the identifier is refused by name at whichever of them
    /// arrives second.
    #[error("the supply identifier {0}")]
    SupplyIdentifierCollision(String),
    /// A policy and the window records it governs contradict each other.
    /// The authoring tool refuses the same combination against the files on
    /// an operator's disk; this is that refusal taken at the write, where
    /// both sides are the deployed ones.
    #[error("the policy and the window records it governs disagree: {0}")]
    CombinedInvariant(String),
    // Both carry the driver's own account of what went wrong. Neither the
    // pool nor the driver repeats the connection string in its message, so
    // naming the cause costs no credential.
    #[error("the Scheduling query failed: {0}")]
    Query(#[from] tokio_postgres::Error),
    #[error("the Scheduling database connection could not be established: {0}")]
    Pool(#[from] deadpool_postgres::PoolError),
}

fn schema_versions(versions: &[i64]) -> String {
    versions
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

impl StoreError {
    /// Whether this is a refusal the operator answers by changing an input
    /// or running another command, as opposed to a database that is
    /// unreachable or failed.
    #[must_use]
    pub fn is_activation_refusal(&self) -> bool {
        matches!(
            self,
            Self::Pre1_0Schema { .. }
                | Self::SchemaPending { .. }
                | Self::SchemaNewer { .. }
                | Self::NotActivated
                | Self::DatabaseIdMismatch
                | Self::PackageAlreadyActive { .. }
                | Self::PackageNotActive { .. }
                | Self::RoleModeDrift
                | Self::SplitRoleWeakened(_)
                | Self::RuntimeGrantsMissing(_)
                | Self::LedgerUnreadable { .. }
                | Self::RetainedHookBindings
                | Self::DeploymentIdentity
                | Self::PolicyInUse(_)
                | Self::CombinedInvariant(_)
                | Self::SupplyIdentifierCollision(_)
        )
    }
}

#[derive(Clone)]
pub struct PostgresStore {
    pool: Pool,
    clock: SharedClock,
    busy_source_bindings: Arc<std::collections::BTreeMap<String, Vec<String>>>,
    /// Test switches that report the next capacity commit that took effect
    /// as unacknowledged, and the next read-back of one as unreadable.
    #[cfg(feature = "postgres-test")]
    lose_acknowledgment: Arc<AtomicBool>,
    #[cfg(feature = "postgres-test")]
    fail_read_back: Arc<AtomicBool>,
    #[cfg(feature = "postgres-test")]
    pause_operational_page: Arc<AtomicBool>,
    #[cfg(feature = "postgres-test")]
    operational_page_paused: Arc<Notify>,
    #[cfg(feature = "postgres-test")]
    resume_operational_page: Arc<Notify>,
}

impl PostgresStore {
    /// Bind each resource to the configured source ids whose fresh coverage
    /// every new allocation must satisfy. Profiles remain the authority
    /// source; this derived index contains no credentials or caller data.
    #[must_use]
    pub fn with_busy_source_profiles(
        mut self,
        profiles: &std::collections::BTreeMap<String, crate::source_busy::BusyImportProfileConfig>,
    ) -> Self {
        let mut bindings = std::collections::BTreeMap::<String, Vec<String>>::new();
        for profile in profiles.values() {
            for resource in &profile.resources {
                bindings
                    .entry(resource.clone())
                    .or_default()
                    .push(profile.source_id.clone());
            }
        }
        for sources in bindings.values_mut() {
            sources.sort();
            sources.dedup();
        }
        self.busy_source_bindings = Arc::new(bindings);
        self
    }

    /// One observation of the store's clock: a request's own `now` at the
    /// edge, and the time an authorization re-check inside a transaction is
    /// decided under. Production observes the system clock.
    pub(crate) fn observed_now(&self) -> DateTime<Utc> {
        let clock = self
            .clock
            .read()
            .expect("the store clock is never held across a panic");
        clock()
    }

    /// The task-grant re-check at decision time: one fresh observation of
    /// the store's clock, taken after every wait and immediately before the
    /// final writes, so a grant that lapsed while this transaction waited
    /// for a lock never commits. The rest of the transaction keeps the
    /// request's own single `now`, with two exceptions, both decided at that
    /// post-lock observation: this authorization-currency re-check, and a
    /// new hold's expiry. `create_hold` takes the observation itself, checks
    /// the grant against it, and starts the hold's TTL at the same instant.
    fn recheck_grant(&self, commitment: &Commitment<'_>) -> Result<(), CommitError> {
        check_grant_current_at(commitment, self.observed_now())
    }

    /// Pin the store's clock, which the HTTP edge, the authorization
    /// re-checks, and the worker passes read. Test-only: production always
    /// observes the system clock. Every handle cloned from this store reads
    /// the pinned time.
    #[cfg(feature = "postgres-test")]
    pub fn pin_clock(&self, clock: Clock) {
        *self
            .clock
            .write()
            .expect("the store clock is never held across a panic") = clock;
    }

    /// Report the next capacity commit as unacknowledged after it took
    /// effect, as a connection lost during `COMMIT` does. Test-only, and
    /// shared by every handle cloned from this store.
    #[cfg(feature = "postgres-test")]
    pub fn lose_next_commit_acknowledgment(&self) {
        self.lose_acknowledgment.store(true, Ordering::SeqCst);
    }

    /// Make the next read-back of an unacknowledged commit unreadable, as a
    /// database that cannot be reached again does. Test-only.
    #[cfg(feature = "postgres-test")]
    pub fn fail_next_read_back(&self) {
        self.fail_read_back.store(true, Ordering::SeqCst);
    }

    /// Pause the next operational page after its parent rows are read and
    /// before its allocation rows are read. Test-only: this makes a
    /// concurrent lifecycle write deterministic when proving snapshot
    /// coherence.
    #[cfg(feature = "postgres-test")]
    pub fn pause_next_operational_page_between_queries(&self) {
        self.pause_operational_page.store(true, Ordering::SeqCst);
    }

    /// Wait until the armed operational page reaches its between-query
    /// pause. Test-only.
    #[cfg(feature = "postgres-test")]
    pub async fn wait_for_operational_page_pause(&self) {
        self.operational_page_paused.notified().await;
    }

    /// Let a paused operational page finish. Test-only.
    #[cfg(feature = "postgres-test")]
    pub fn release_operational_page_pause(&self) {
        self.resume_operational_page.notify_one();
    }

    async fn pause_operational_page_if_requested(&self) {
        #[cfg(feature = "postgres-test")]
        if self.pause_operational_page.swap(false, Ordering::SeqCst) {
            self.operational_page_paused.notify_one();
            self.resume_operational_page.notified().await;
        }
    }

    /// Whether the test switch reports this commit as unacknowledged. Always
    /// false outside tests.
    fn acknowledgment_lost(&self) -> bool {
        #[cfg(feature = "postgres-test")]
        {
            self.lose_acknowledgment.swap(false, Ordering::SeqCst)
        }
        #[cfg(not(feature = "postgres-test"))]
        {
            false
        }
    }

    /// Whether the test switch makes this read-back unreadable. Always false
    /// outside tests.
    fn read_back_fails(&self) -> bool {
        #[cfg(feature = "postgres-test")]
        {
            self.fail_read_back.swap(false, Ordering::SeqCst)
        }
        #[cfg(not(feature = "postgres-test"))]
        {
            false
        }
    }

    /// Commit a capacity transaction whose decision is already written.
    ///
    /// A `COMMIT` whose acknowledgment never arrives may still have taken
    /// effect, as when the connection is lost after it reached the database.
    /// Its transaction's status is then read back on another connection,
    /// outside any transaction: the read writes nothing and takes no
    /// capacity lock. A commit that took effect is answered as committed,
    /// one that rolled back as the query failure it was, and one whose
    /// status cannot be read as [`CommitError::Unacknowledged`].
    ///
    /// A commitment's task grant is re-checked after the transaction id is
    /// read, so no database round trip separates that re-check from the
    /// `COMMIT` it guards.
    async fn commit_capacity(
        &self,
        transaction: deadpool_postgres::Transaction<'_>,
        grant: Option<&Commitment<'_>>,
    ) -> Result<(), CommitError> {
        let transaction_id: String = transaction
            .query_one("SELECT pg_current_xact_id()::text", &[])
            .await?
            .get(0);
        if let Some(commitment) = grant {
            self.recheck_grant(commitment)?;
        }
        let failure = match transaction.commit().await {
            Ok(()) if !self.acknowledgment_lost() => return Ok(()),
            Ok(()) => None,
            Err(error) => Some(error),
        };
        match self.read_back(&transaction_id).await {
            ReadBack::Committed => {
                tracing::warn!(
                    "a Scheduling capacity commit was not acknowledged but took effect; it is answered as committed"
                );
                Ok(())
            }
            ReadBack::RolledBack => {
                Err(failure.map_or(CommitError::Unacknowledged, CommitError::Query))
            }
            ReadBack::Unknown => {
                tracing::error!(
                    "a Scheduling capacity commit was not acknowledged and its outcome could not be read back"
                );
                Err(CommitError::Unacknowledged)
            }
        }
    }

    /// Read whether the transaction `transaction_id` committed, on a pooled
    /// connection outside any transaction.
    async fn read_back(&self, transaction_id: &str) -> ReadBack {
        if self.read_back_fails() {
            return ReadBack::Unknown;
        }
        let Ok(client) = self.client().await else {
            return ReadBack::Unknown;
        };
        let status = client
            .query_one("SELECT pg_xact_status($1::text::xid8)", &[&transaction_id])
            .await
            .map(|row| row.get::<_, Option<String>>(0));
        match status.as_ref().map(|status| status.as_deref()) {
            Ok(Some("committed")) => ReadBack::Committed,
            Ok(Some("aborted")) => ReadBack::RolledBack,
            // Still in progress, too old to report, or unreadable.
            _ => ReadBack::Unknown,
        }
    }
}

/// What reading back an unacknowledged capacity commit found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadBack {
    Committed,
    RolledBack,
    Unknown,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allocations: Vec<AllocationDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party: Option<PartyCounts>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub party_references: Vec<PartyReference>,
    /// A source-bound manager selected from the fixed signed task subject.
    /// Absence means the verified owner pair remains the manager.
    #[serde(skip)]
    pub source_manager: Option<SourceBoundManager>,
    pub duplicate_key: Option<String>,
    #[serde(default)]
    pub external_references: Vec<ExternalReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_expires_at: Option<DateTime<Utc>>,
    pub revision: i64,
    pub policy_revision: i64,
    /// The pseudonym of the caller that booked, which history and audit
    /// carry. It decides nothing: ownership is `owner`.
    pub actor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<DateTime<Utc>>,
    /// The verified caller that owns the claim, read from its row. It is
    /// never serialized, so a receipt, a payload, or a hook projection built
    /// from a claim cannot carry it, and a claim read back from a receipt has
    /// none. `None` also covers an owner erased after its retention window,
    /// or a claim written before owners were stored; no caller owns either.
    #[serde(skip)]
    pub owner: Option<ClaimOwner>,
}

/// The verified token issuer and subject that own a claim. Every ownership
/// decision compares these, never the pseudonym, so rotating the audit hash
/// key leaves each hold and appointment with the caller that booked it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimOwner {
    pub issuer: String,
    pub subject: String,
}

/// A stable source-local manager identity. Only an exact current task grant
/// from the same source can exercise it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceBoundManager {
    pub source_issuer: String,
    pub subject: String,
}

impl ClaimRow {
    /// Whether the verified `issuer` and `subject` own this claim. A claim
    /// with no stored owner is owned by nobody.
    #[must_use]
    pub fn is_owned_by(&self, issuer: &str, subject: &str) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|owner| owner.issuer == issuer && owner.subject == subject)
    }

    /// Whether a commitment carries the authority that manages this claim.
    /// Source-bound claims never fall back to their creating actor.
    fn is_managed_by(&self, commitment: &Commitment<'_>) -> bool {
        match &self.source_manager {
            Some(expected) => commitment.source_manager.as_ref() == Some(expected),
            None => self.is_owned_by(commitment.actor_issuer, commitment.actor_subject),
        }
    }

    /// Whether this claim holds its offering's terms still. This is the Rust
    /// twin of the sentence `apply_policy` selects on: publication refuses to
    /// change the service, location, mode or supply of an offering under a
    /// claim that answers true here, so for such a claim the current policy
    /// and the revision the claim names give the same terms. Under every
    /// other claim, a closed one or a hold already past its expiry, the
    /// offering is free to move and only the revision the claim names still
    /// describes what was committed.
    #[must_use]
    pub fn pins_its_offering(&self, now: DateTime<Utc>) -> bool {
        self.state == ClaimState::Active
            && match self.kind {
                LedgerKind::Booking | LedgerKind::Window => true,
                LedgerKind::Hold => self.hold_expires_at.is_some_and(|expiry| expiry > now),
            }
    }
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
/// per request and used for every decision the caller reads inside it, so
/// a transaction never mixes two observations of the time it answers with.
/// Authorization currency and transfer of a hold are the two deliberate
/// exceptions. The grant's expiry is re-checked against a fresh observation
/// taken inside the transaction, after every wait and immediately before the
/// final write. A hold's expiry is re-checked after its supply anchor is
/// locked, so capacity another transaction reclaimed after expiry cannot also
/// be transferred into an appointment by an older confirmation request.
pub struct Commitment<'c> {
    pub now: DateTime<Utc>,
    /// The revision of the policy this process evaluated, not the stored
    /// current one: the capacity transaction verifies the two still agree
    /// before it commits, so a claim never carries a revision that names
    /// rules it was not evaluated under.
    pub policy_revision: i64,
    /// The records revision the request resolved its supply under. A
    /// wholesale records replacement increments it; a transaction whose
    /// resolved facts are older than the stored revision is refused.
    pub facts_revision: i64,
    /// The pseudonymized actor reference history and audit carry.
    pub actor: &'c str,
    /// The verified token issuer and subject: the owner of every claim this
    /// commitment writes or acts on, and the raw caller of its idempotency
    /// attempt while that attempt's receipt is retained.
    pub actor_issuer: &'c str,
    pub actor_subject: &'c str,
    /// The exact fresh source authority presented for this operation, or none
    /// when the verified actor manages the claim directly.
    pub source_manager: Option<SourceBoundManager>,
    pub idempotency_key: &'c str,
    /// The idempotent hash of the request payload.
    pub request_hash: &'c str,
    pub attempt_expires_at: DateTime<Utc>,
    /// The task grant's `exp`, re-checked inside the capacity transaction.
    pub grant_exp_unix: Option<u64>,
    pub hooks: Option<&'c ActivatedHooks>,
}

impl Commitment<'_> {
    /// The digest this commitment's idempotency attempt is stored and found
    /// under for `scope`.
    fn key_reference(&self, scope: &str) -> String {
        attempt_key_reference(
            self.actor_issuer,
            self.actor_subject,
            scope,
            self.idempotency_key,
        )
    }
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
        open: &'p [CalendarInterval],
        closures: &'p [CalendarInterval],
    },
}

/// One policy-resolved exact-time requirement in a logical reservation.
/// Every line is built from one facts revision and passed to one transaction.
pub struct BundleSupplyLine<'p> {
    pub requirement_id: String,
    pub offering: &'p registry_scheduling_core::OfferingPolicy,
    pub exact: &'p registry_scheduling_core::ExactTimeOffering,
    pub members: &'p [PoolMember],
    pub open: &'p [CalendarInterval],
    pub closures: &'p [CalendarInterval],
    pub resource: Option<&'p str>,
    pub stored_resource: bool,
    pub units: u32,
}

const MAXIMUM_CAPACITY_SNAPSHOT_ROWS: usize = 4_096;

struct NewClaimAllocation<'p> {
    requirement: &'p str,
    offering: &'p str,
    operational_service: &'p str,
    operational_location: &'p str,
    anchor_id: &'p str,
    resource_id: &'p str,
    occupied_start: DateTime<Utc>,
    occupied_end: DateTime<Utc>,
    units: u32,
}

/// What one committed operation produced.
#[derive(Clone, Debug)]
pub enum CommitOutcome {
    Booking(ClaimRow),
    Attendance(crate::attendance::AttendanceObservation),
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
    #[error("the Scheduling hook event could not be captured")]
    Hooks(#[from] HookCaptureError),
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
    #[error("the attendance observation time is in the future")]
    ObservationInFuture,
    #[error("the cancellation cutoff has passed")]
    CutoffPassed,
    /// The environment records were replaced after this request resolved
    /// its supply. Nothing was decided; the caller retries against the
    /// current records.
    #[error("the environment records were replaced while the request was in flight")]
    FactsStale,
    /// The capacity transaction's `COMMIT` was not acknowledged and reading
    /// its status back failed, so whether it took effect is unknown. A retry
    /// under the same idempotency key replays its receipt if it did.
    #[error("the capacity commit was not acknowledged and its outcome is unknown")]
    Unacknowledged,
}

/// One due or delivered outbox intent.
#[derive(Clone, Debug)]
pub struct OutboxRow {
    pub outbox_id: Uuid,
    pub purpose: String,
    pub claim_id: Uuid,
    pub appointment_revision: i64,
    pub due_at: DateTime<Utc>,
    pub payload: Value,
}

/// One delivery intent the dispatcher will carry no further, as an operator reads
/// it. The delivery state is what separates the two ways that happens: `local`
/// is a deployment that declares no destination, and `failed` is a destination
/// that refused the intent outright or failed every attempt the policy
/// allowed.
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
        Ok(Self {
            pool,
            clock: system_clock(),
            busy_source_bindings: Arc::default(),
            #[cfg(feature = "postgres-test")]
            lose_acknowledgment: Arc::default(),
            #[cfg(feature = "postgres-test")]
            fail_read_back: Arc::default(),
            #[cfg(feature = "postgres-test")]
            pause_operational_page: Arc::default(),
            #[cfg(feature = "postgres-test")]
            operational_page_paused: Arc::default(),
            #[cfg(feature = "postgres-test")]
            resume_operational_page: Arc::default(),
        })
    }

    async fn client(&self) -> Result<deadpool_postgres::Client, StoreError> {
        self.pool.get().await.map_err(StoreError::Pool)
    }

    pub(crate) async fn hook_delivery_client(
        &self,
    ) -> Result<deadpool_postgres::Client, StoreError> {
        self.client().await
    }

    /// The schema this store's connections work in.
    pub async fn schema_name(&self) -> Result<String, StoreError> {
        let client = self.client().await?;
        current_schema_in(&**client).await
    }

    /// Apply every pending schema migration in one transaction, serialized on
    /// the migration lock. `schedulingctl apply` runs the same migrations
    /// inside its activation transaction; this entry point serves the
    /// database suites that provision a schema without activating a package.
    pub async fn migrate(&self) -> Result<Vec<i64>, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
        transaction
            .execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_KEY])
            .await?;
        let applied = apply_migrations_in(&transaction).await?;
        operational::rematerialize_operational_scopes_in(&*transaction).await?;
        transaction.commit().await?;
        Ok(applied)
    }

    /// The schema versions this database holds and the ones this release
    /// would still apply.
    pub async fn schema_state(&self) -> Result<SchemaState, StoreError> {
        let client = self.client().await?;
        schema_state_in(&**client).await
    }

    /// Refuse a database whose schema is not exactly this release's.
    pub async fn ready(&self) -> Result<(), StoreError> {
        let client = self.client().await?;
        if let Some(schema) = activation::unreadable_ledger_in(&**client).await? {
            return Err(StoreError::LedgerUnreadable { schema });
        }
        let state = schema_state_in(&**client).await?;
        state.check()?;
        if state.pending.is_empty() {
            Ok(())
        } else {
            Err(StoreError::SchemaPending {
                pending: state.pending,
            })
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
        mark_allocation_writer(&transaction).await?;
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

    /// Publish a policy after proving it does not strand standing commitments
    /// or move their offering to different supply. Re-applying the same digest
    /// remains a no-op for the revision.
    ///
    /// Lock order, load-bearing: policy publication takes every existing
    /// supply anchor in order before `scheduling_meta`, the same order as the
    /// records swap. Capacity transactions take one anchor and then the meta
    /// row, so an older runtime cannot add a commitment between this method's
    /// impact assessment and publication.
    pub async fn apply_policy(
        &self,
        scheduling_id: &str,
        policy_digest: &str,
        pool_ids: &[String],
        policy: &SchedulingPolicy,
    ) -> Result<i64, StoreError> {
        if policy.policy_digest() != policy_digest {
            return Err(StoreError::Corrupt);
        }
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
        lock_publication(&transaction).await?;
        let stored_id: String = transaction
            .query_one(
                "SELECT scheduling_id FROM scheduling_meta WHERE singleton",
                &[],
            )
            .await?
            .get(0);
        if stored_id != scheduling_id {
            return Err(StoreError::Corrupt);
        }
        let publication =
            check_policy_publication(&transaction, self.observed_now(), policy).await?;
        let revision = publish_policy(&transaction, &publication, policy, pool_ids).await?;
        transaction.commit().await?;
        Ok(revision)
    }

    /// The environment records an admission runs against, with the records
    /// revision they were read under. The whole read shares one repeatable
    /// snapshot, so no records replacement can land between the members and
    /// the exceptions and hand a caller a torn combination; the revision
    /// travels with the facts into the capacity transaction, which refuses
    /// to commit against records a replacement has since superseded.
    pub async fn facts(&self) -> Result<(SchedulingFacts, i64), StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
        transaction
            .batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .await?;
        let revision: i64 = transaction
            .query_one(
                "SELECT facts_revision FROM scheduling_meta WHERE singleton",
                &[],
            )
            .await?
            .get(0);
        let locations = transaction
            .query(
                "SELECT location_id, timezone FROM scheduling_locations",
                &[],
            )
            .await?;
        let members = transaction
            .query(
                "SELECT resource_id, pool_id, capabilities, available, capacity_units, availability \
                 FROM scheduling_pool_members ORDER BY pool_id, resource_id",
                &[],
            )
            .await?;
        let pools = transaction
            .query("SELECT pool_id FROM scheduling_pools ORDER BY pool_id", &[])
            .await?;
        let windows = transaction
            .query(
                "SELECT window_record FROM scheduling_windows ORDER BY window_id",
                &[],
            )
            .await?;
        let exceptions = transaction
            .query(
                "SELECT exception_id, location, kind, date::text, start_time, end_time, \
                 reopens, authority FROM scheduling_exceptions",
                &[],
            )
            .await?;
        let windows = windows
            .iter()
            .map(|row| {
                serde_json::from_value::<registry_scheduling_core::PublishedWindow>(row.get(0))
                    .map_err(|_| StoreError::Corrupt)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let facts = SchedulingFacts {
            locations: locations
                .iter()
                .map(|row| registry_scheduling_core::LocationRecord {
                    id: row.get(0),
                    timezone: row.get(1),
                })
                .collect(),
            pools: pools
                .iter()
                .map(|pool| {
                    Ok(registry_scheduling_core::ResourcePool {
                        id: pool.get(0),
                        members: members
                            .iter()
                            .filter(|member| member.get::<_, String>(1) == pool.get::<_, String>(0))
                            .map(|member| {
                                Ok(registry_scheduling_core::PoolMember {
                                    resource_id: member.get(0),
                                    capabilities: member.get(2),
                                    available: member.get(3),
                                    capacity_units: u32::try_from(member.get::<_, i32>(4))
                                        .map_err(|_| StoreError::Corrupt)?,
                                    availability: member
                                        .get::<_, Option<Value>>(5)
                                        .map(serde_json::from_value)
                                        .transpose()
                                        .map_err(|_| StoreError::Corrupt)?,
                                })
                            })
                            .collect::<Result<Vec<_>, StoreError>>()?,
                    })
                })
                .collect::<Result<Vec<_>, StoreError>>()?,
            windows,
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
        };
        Ok((facts, revision))
    }

    /// Replace the environment records wholesale. This is the operator
    /// tooling path (`schedulingctl records apply`): one attributable write
    /// that swaps locations, pools, members, windows, and exceptions atomically.
    pub async fn replace_facts(
        &self,
        scheduling_id: &str,
        facts: &SchedulingFacts,
    ) -> Result<(), StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
        replace_facts_in_transaction(
            &transaction,
            scheduling_id,
            facts,
            None,
            &self.busy_source_bindings,
        )
        .await?;
        // The swap takes every supply anchor, so its commit is read back
        // like a capacity commit when its acknowledgment is lost.
        self.commit_publication(transaction).await
    }

    /// Replace the environment records only while `expected` is the active
    /// package on this database. The ledger is read once the swap holds the
    /// supply anchors and the meta row, which an apply takes before it
    /// records its row, so an apply cannot activate another package between
    /// the check and the swap.
    pub async fn replace_active_facts(
        &self,
        scheduling_id: &str,
        facts: &SchedulingFacts,
        expected: &ActivePackage<'_>,
    ) -> Result<(), StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
        replace_facts_in_transaction(
            &transaction,
            scheduling_id,
            facts,
            Some(expected),
            &self.busy_source_bindings,
        )
        .await?;
        self.commit_publication(transaction).await
    }

    /// Commit a transaction that holds every supply anchor and no task
    /// grant, reading its status back like a capacity commit when the
    /// acknowledgment is lost.
    async fn commit_publication(
        &self,
        transaction: deadpool_postgres::Transaction<'_>,
    ) -> Result<(), StoreError> {
        match self.commit_capacity(transaction, None).await {
            Ok(()) => Ok(()),
            Err(CommitError::Store(error)) => Err(error),
            Err(CommitError::Query(error)) => Err(error.into()),
            Err(CommitError::Unacknowledged) => Err(StoreError::Unacknowledged),
            Err(other) => unreachable!(
                "a capacity commit only fails as a query or unacknowledged, not {other}"
            ),
        }
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
        let Some(row) = row else {
            return Ok(None);
        };
        let mut claims = vec![map_claim_row(row)?];
        load_claim_allocations(&client, &mut claims).await?;
        Ok(claims.pop())
    }

    /// Appointments owned by the verified `issuer` and `subject` that carry
    /// exactly the requested opaque reference, ordered by identifier for
    /// stable cursor paging.
    pub async fn list_appointments_by_external_reference(
        &self,
        issuer: &str,
        subject: &str,
        reference: &ExternalReference,
        after_id: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<ClaimRow>, StoreError> {
        let client = self.client().await?;
        let reference = serde_json::to_value([reference]).map_err(|_| StoreError::Corrupt)?;
        let rows = client
            .query(
                "SELECT claim_id, kind, state, offering, supply_id, channel, \
                 displayed_start, displayed_end, occupied_start, occupied_end, units, duplicate_key, \
                 external_references, hold_expires_at, revision, policy_revision, actor, reason, \
                 created_at, closed_at, owner_issuer, owner_subject, recipient_count, attendee_count, \
                 party_references, manager_source_issuer, manager_subject FROM scheduling_claims \
                 WHERE kind='booking' AND owner_issuer=$1 AND owner_subject=$2 \
                   AND manager_source_issuer IS NULL \
                   AND external_references @> $3::jsonb \
                   AND ($4::uuid IS NULL OR claim_id > $4) \
                 ORDER BY claim_id LIMIT $5",
                &[&issuer, &subject, &reference, &after_id, &limit],
            )
            .await?;
        let mut claims = rows
            .into_iter()
            .map(map_claim_row)
            .collect::<Result<Vec<_>, _>>()?;
        load_claim_allocations(&client, &mut claims).await?;
        Ok(claims)
    }

    /// The offering as the policy revision `policy_revision` published it.
    ///
    /// Every claim names the revision it was committed under, and every
    /// published revision retains its document. Publication may retire an
    /// offering once no claim on it is live, so the close that retired it has
    /// a receipt the current policy can no longer describe: the terms that
    /// governed the claim are read from the revision that governed it.
    pub async fn retained_offering(
        &self,
        policy_revision: i64,
        offering: &str,
    ) -> Result<Option<registry_scheduling_core::OfferingPolicy>, StoreError> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT policy_document FROM scheduling_policy_revisions \
                 WHERE policy_revision=$1",
                &[&policy_revision],
            )
            .await?;
        let Some(document) = row.and_then(|row| row.get::<_, Option<Value>>(0)) else {
            return Ok(None);
        };
        Ok(retained_policy(document)?.offering(offering).cloned())
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
    ) -> Result<Vec<(String, String, Vec<String>, bool, u32)>, StoreError> {
        let client = self.client().await?;
        let rows = client
            .query(
                "SELECT resource_id, pool_id, capabilities, available, capacity_units \
                 FROM scheduling_pool_members \
                 WHERE ($1::text IS NULL OR resource_id > $1) \
                 ORDER BY resource_id LIMIT $2",
                &[&after_id, &limit],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok((
                    row.get(0),
                    row.get(1),
                    row.get(2),
                    row.get(3),
                    u32::try_from(row.get::<_, i32>(4)).map_err(|_| StoreError::Corrupt)?,
                ))
            })
            .collect::<Result<Vec<_>, StoreError>>()
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
        let mut snapshot = snapshot_from_rows(rows);
        source_busy::append_busy_search_blocks(
            &client,
            &self.busy_source_bindings,
            members,
            from,
            to,
            now,
            &mut snapshot,
        )
        .await
        .map_err(source_busy::as_store_error)?;
        Ok(snapshot)
    }

    /// A bounded read-only snapshot for atomic capacity preview. Unlike a
    /// commitment it acquires no allocation locks and therefore promises
    /// advice at the observed instant, not a reservation.
    pub async fn bundle_preview_snapshot(
        &self,
        members: &[String],
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<LedgerSnapshot, StoreError> {
        let client = self.client().await?;
        let limit =
            i64::try_from(MAXIMUM_CAPACITY_SNAPSHOT_ROWS + 1).map_err(|_| StoreError::Corrupt)?;
        let rows = client
            .query(
                "SELECT c.claim_id, a.offering, a.resource_id, c.kind, c.channel, \
             a.occupied_start, a.occupied_end, a.units, c.duplicate_key, c.hold_expires_at \
             FROM scheduling_claim_allocations AS a \
             JOIN scheduling_claims AS c ON c.claim_id=a.claim_id \
             WHERE c.state='active' \
               AND (c.kind IN ('booking','window') OR (c.kind='hold' AND c.hold_expires_at > $4)) \
               AND a.resource_id=ANY($1) \
               AND a.occupied_start < $3 AND $2 < a.occupied_end \
             ORDER BY a.occupied_start, a.claim_id, a.resource_id LIMIT $5",
                &[&members, &from, &to, &now, &limit],
            )
            .await?;
        if rows.len() > MAXIMUM_CAPACITY_SNAPSHOT_ROWS {
            return Err(StoreError::CapacitySnapshotTooLarge);
        }
        let mut snapshot = snapshot_from_rows(rows);
        source_busy::append_busy_search_blocks(
            &client,
            &self.busy_source_bindings,
            members,
            from,
            to,
            now,
            &mut snapshot,
        )
        .await
        .map_err(source_busy::as_store_error)?;
        Ok(snapshot)
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
                "SELECT claim_id, offering, supply_id, kind, channel, occupied_start, occupied_end, \
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
    pub async fn create_bundle_hold(
        &self,
        lines: &[BundleSupplyLine<'_>],
        request: &registry_scheduling_core::AdmissionRequest,
        ttl_minutes: u32,
        max_per_caller: u32,
        commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let primary = lines.first().ok_or(StoreError::Corrupt)?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
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
        let mut snapshot = lock_bundle_and_snapshot(
            &transaction,
            lines,
            request,
            commitment.now,
            &[],
            &self.busy_source_bindings,
        )
        .await?;
        include_bundle_active_duplicates(
            &transaction,
            &mut snapshot,
            lines,
            request.duplicate_key.as_deref(),
            commitment.now,
        )
        .await?;
        if transaction
            .lock_caller_and_count_active_holds(
                commitment.actor_issuer,
                commitment.actor_subject,
                commitment.now,
            )
            .await?
            >= i64::from(max_per_caller)
        {
            return Err(CommitError::HoldCeiling);
        }
        guard_revisions(&transaction, &commitment).await?;
        let admission = evaluate_bundle(lines, request, &snapshot, &commitment, None, false)?;
        let primary_allocation = admission
            .allocations
            .iter()
            .find(|allocation| allocation.requirement_id == "primary")
            .ok_or(StoreError::Corrupt)?;
        let decided_at = self.observed_now();
        check_grant_current_at(&commitment, decided_at)?;
        let expires_at = decided_at
            .checked_add_signed(TimeDelta::minutes(i64::from(ttl_minutes)))
            .ok_or(AdmissionRefusal::ScheduleUnpublished)?;
        let hold_id = Uuid::new_v4();
        let mut claim = transaction
            .insert_claim(&NewClaim {
                claim_id: hold_id,
                kind: LedgerKind::Hold,
                state: ClaimState::Active,
                offering: &admission.offering,
                operational_service: &primary.offering.service,
                operational_location: &primary.offering.location,
                operational_mode: primary.offering.mode,
                supply_id: &primary_allocation.resource,
                channel: request.channel.as_deref(),
                displayed_start: admission.start,
                displayed_end: admission.end,
                occupied_start: primary_allocation.occupied_start,
                occupied_end: primary_allocation.occupied_end,
                units: i32::try_from(primary_allocation.units).map_err(|_| StoreError::Corrupt)?,
                party: request.party,
                party_references: &request.party_references,
                source_manager: commitment.source_manager.as_ref(),
                duplicate_key: request.duplicate_key.as_deref(),
                external_references: &request.external_references,
                hold_expires_at: Some(expires_at),
                revision: 1,
                policy_revision: commitment.policy_revision,
                actor: commitment.actor,
                owner_issuer: commitment.actor_issuer,
                owner_subject: commitment.actor_subject,
                reason: None,
            })
            .await?;
        let stored = stored_bundle_allocations(&admission, lines)?;
        transaction
            .insert_claim_allocations(hold_id, &stored)
            .await?;
        claim.allocations = allocation_documents(&admission)?;
        transaction
            .insert_history(
                hold_id,
                1,
                "held",
                commitment.now,
                commitment.actor,
                json!({"expiresAt": expires_at, "offering": admission.offering, "allocations": claim.allocations}),
            )
            .await?;
        transaction
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                "hold:create",
                AttemptState::Completed,
                201,
                claim_receipt("hold", &claim, true, commitment.policy_revision),
            )
            .await?;
        self.commit_capacity(transaction, Some(&commitment)).await?;
        Ok(CommitOutcome::Hold(claim))
    }

    /// Create an exact-time appointment and every physical allocation in one
    /// capacity transaction.
    pub async fn create_bundle_appointment(
        &self,
        lines: &[BundleSupplyLine<'_>],
        request: &registry_scheduling_core::AdmissionRequest,
        commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let primary = lines.first().ok_or(StoreError::Corrupt)?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
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
        let mut snapshot = lock_bundle_and_snapshot(
            &transaction,
            lines,
            request,
            commitment.now,
            &[],
            &self.busy_source_bindings,
        )
        .await?;
        include_bundle_active_duplicates(
            &transaction,
            &mut snapshot,
            lines,
            request.duplicate_key.as_deref(),
            commitment.now,
        )
        .await?;
        guard_revisions(&transaction, &commitment).await?;
        let admission = evaluate_bundle(lines, request, &snapshot, &commitment, None, false)?;
        self.recheck_grant(&commitment)?;
        let primary_allocation = admission
            .allocations
            .iter()
            .find(|allocation| allocation.requirement_id == "primary")
            .ok_or(StoreError::Corrupt)?;
        let appointment_id = Uuid::new_v4();
        let mut claim = transaction
            .insert_claim(&NewClaim {
                claim_id: appointment_id,
                kind: LedgerKind::Booking,
                state: ClaimState::Active,
                offering: &admission.offering,
                operational_service: &primary.offering.service,
                operational_location: &primary.offering.location,
                operational_mode: primary.offering.mode,
                supply_id: &primary_allocation.resource,
                channel: request.channel.as_deref(),
                displayed_start: admission.start,
                displayed_end: admission.end,
                occupied_start: primary_allocation.occupied_start,
                occupied_end: primary_allocation.occupied_end,
                units: i32::try_from(primary_allocation.units).map_err(|_| StoreError::Corrupt)?,
                party: request.party,
                party_references: &request.party_references,
                source_manager: commitment.source_manager.as_ref(),
                duplicate_key: request.duplicate_key.as_deref(),
                external_references: &request.external_references,
                hold_expires_at: None,
                revision: 1,
                policy_revision: commitment.policy_revision,
                actor: commitment.actor,
                owner_issuer: commitment.actor_issuer,
                owner_subject: commitment.actor_subject,
                reason: None,
            })
            .await?;
        let stored = stored_bundle_allocations(&admission, lines)?;
        transaction
            .insert_claim_allocations(appointment_id, &stored)
            .await?;
        claim.allocations = allocation_documents(&admission)?;
        transaction
            .insert_history(
                appointment_id,
                1,
                "confirmed",
                commitment.now,
                commitment.actor,
                json!({"offering": admission.offering, "start": admission.start, "allocations": claim.allocations}),
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
        mint_reminders(&transaction, &claim, primary.offering, commitment.now).await?;
        if let Some(hooks) = commitment.hooks {
            hooks
                .capture(&transaction, APPOINTMENT_CONFIRMED_TRIGGER, &claim)
                .await?;
        }
        transaction
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                "appointment:create",
                AttemptState::Completed,
                201,
                claim_receipt("booking", &claim, true, commitment.policy_revision),
            )
            .await?;
        self.commit_capacity(transaction, Some(&commitment)).await?;
        Ok(CommitOutcome::Booking(claim))
    }

    /// Mint a hold through the full capacity transaction.
    pub async fn create_hold(
        &self,
        offering: &registry_scheduling_core::OfferingPolicy,
        supply: &SupplyContext<'_>,
        request: &registry_scheduling_core::AdmissionRequest,
        ttl_minutes: u32,
        max_per_caller: u32,
        commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
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
        let mut snapshot = lock_and_snapshot(&transaction, supply, commitment.now).await?;
        include_active_duplicate(
            &transaction,
            &mut snapshot,
            offering,
            request.duplicate_key.as_deref(),
            commitment.now,
        )
        .await?;
        // The caller lock is taken after the supply lock, never before: every
        // hold transaction acquires the two in that one order, so no pair of
        // them can hold what the other is waiting for.
        if transaction
            .lock_caller_and_count_active_holds(
                commitment.actor_issuer,
                commitment.actor_subject,
                commitment.now,
            )
            .await?
            >= i64::from(max_per_caller)
        {
            return Err(CommitError::HoldCeiling);
        }
        guard_revisions(&transaction, &commitment).await?;
        let admission = evaluate(offering, supply, request, &snapshot, &commitment, None)?;
        // One observation of the store's clock, after the supply and caller
        // locks and immediately before the hold is written: the grant must
        // still stand at the instant this transaction decides, and the hold's
        // time to live starts at that same instant, so a create that waited
        // on either lock still hands its caller the whole authored TTL.
        let decided_at = self.observed_now();
        check_grant_current_at(&commitment, decided_at)?;
        let expires_at = decided_at
            .checked_add_signed(TimeDelta::minutes(i64::from(ttl_minutes)))
            .ok_or(AdmissionRefusal::ScheduleUnpublished)?;
        let hold_id = Uuid::new_v4();
        let claim = transaction
            .insert_claim(&NewClaim {
                claim_id: hold_id,
                kind: LedgerKind::Hold,
                state: ClaimState::Active,
                offering: &admission.offering,
                operational_service: &offering.service,
                operational_location: &offering.location,
                operational_mode: offering.mode,
                supply_id: admission
                    .resource
                    .as_deref()
                    .unwrap_or(window_supply_id(supply)),
                channel: request.channel.as_deref(),
                displayed_start: admission.start,
                displayed_end: admission.end,
                occupied_start: admission.occupied_start,
                occupied_end: admission.occupied_end,
                units: i32::try_from(admission.units).map_err(|_| StoreError::Corrupt)?,
                party: request.party,
                party_references: &request.party_references,
                source_manager: commitment.source_manager.as_ref(),
                duplicate_key: request.duplicate_key.as_deref(),
                external_references: &request.external_references,
                hold_expires_at: Some(expires_at),
                revision: 1,
                policy_revision: commitment.policy_revision,
                actor: commitment.actor,
                owner_issuer: commitment.actor_issuer,
                owner_subject: commitment.actor_subject,
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
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                "hold:create",
                AttemptState::Completed,
                201,
                claim_receipt(
                    "hold",
                    &claim,
                    matches!(supply, SupplyContext::ExactTime { .. }),
                    commitment.policy_revision,
                ),
            )
            .await?;
        self.commit_capacity(transaction, Some(&commitment)).await?;
        Ok(CommitOutcome::Hold(claim))
    }

    /// Create an appointment directly, through the full capacity
    /// transaction.
    pub async fn create_appointment(
        &self,
        offering: &registry_scheduling_core::OfferingPolicy,
        supply: &SupplyContext<'_>,
        request: &registry_scheduling_core::AdmissionRequest,
        commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
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
        let mut snapshot = lock_and_snapshot(&transaction, supply, commitment.now).await?;
        include_active_duplicate(
            &transaction,
            &mut snapshot,
            offering,
            request.duplicate_key.as_deref(),
            commitment.now,
        )
        .await?;
        guard_revisions(&transaction, &commitment).await?;
        let admission = evaluate(offering, supply, request, &snapshot, &commitment, None)?;
        self.recheck_grant(&commitment)?;
        let appointment_id = Uuid::new_v4();
        let claim = transaction
            .insert_claim(&NewClaim {
                claim_id: appointment_id,
                kind: LedgerKind::Booking,
                state: ClaimState::Active,
                offering: &admission.offering,
                operational_service: &offering.service,
                operational_location: &offering.location,
                operational_mode: offering.mode,
                supply_id: admission
                    .resource
                    .as_deref()
                    .unwrap_or(window_supply_id(supply)),
                channel: request.channel.as_deref(),
                displayed_start: admission.start,
                displayed_end: admission.end,
                occupied_start: admission.occupied_start,
                occupied_end: admission.occupied_end,
                units: i32::try_from(admission.units).map_err(|_| StoreError::Corrupt)?,
                party: request.party,
                party_references: &request.party_references,
                source_manager: commitment.source_manager.as_ref(),
                duplicate_key: request.duplicate_key.as_deref(),
                external_references: &request.external_references,
                hold_expires_at: None,
                revision: 1,
                policy_revision: commitment.policy_revision,
                actor: commitment.actor,
                owner_issuer: commitment.actor_issuer,
                owner_subject: commitment.actor_subject,
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
        if let Some(hooks) = commitment.hooks {
            hooks
                .capture(&transaction, APPOINTMENT_CONFIRMED_TRIGGER, &claim)
                .await?;
        }
        transaction
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                "appointment:create",
                AttemptState::Completed,
                201,
                claim_receipt(
                    "booking",
                    &claim,
                    matches!(supply, SupplyContext::ExactTime { .. }),
                    commitment.policy_revision,
                ),
            )
            .await?;
        self.commit_capacity(transaction, Some(&commitment)).await?;
        Ok(CommitOutcome::Booking(claim))
    }

    /// Confirm a held allocation: the hold converts to an appointment in one
    /// transaction, preserving every exact resource assignment.
    pub async fn confirm_bundle_hold(
        &self,
        hold_id: Uuid,
        lines: &[BundleSupplyLine<'_>],
        request: &registry_scheduling_core::AdmissionRequest,
        commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let scope = format!("hold:{hold_id}:confirm");
        let primary = lines.first().ok_or(StoreError::Corrupt)?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
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
        let mut snapshot = lock_bundle_and_snapshot(
            &transaction,
            lines,
            request,
            commitment.now,
            &[],
            &self.busy_source_bindings,
        )
        .await?;
        include_bundle_active_duplicates(
            &transaction,
            &mut snapshot,
            lines,
            request.duplicate_key.as_deref(),
            commitment.now,
        )
        .await?;
        let hold = transaction
            .claim_in_transaction(hold_id)
            .await?
            .ok_or(AdmissionRefusal::HoldReleased)?;
        if hold.kind != LedgerKind::Hold || hold.state != ClaimState::Active {
            return Err(AdmissionRefusal::HoldReleased.into());
        }
        guard_revisions(&transaction, &commitment).await?;
        evaluate_hold_state(&hold_ledger_claim(&hold), self.observed_now())?;
        if hold.policy_revision != commitment.policy_revision {
            return Err(AdmissionRefusal::PolicyChanged.into());
        }
        if !hold.is_managed_by(&commitment) {
            return Err(CommitError::Unauthorized);
        }
        let admission = confirm_stored_bundle(lines, request, &snapshot, &commitment, &hold)?;
        let documents = allocation_documents(&admission)?;
        if documents != hold.allocations {
            return Err(StoreError::Corrupt.into());
        }
        self.recheck_grant(&commitment)?;
        let primary_allocation = admission
            .allocations
            .iter()
            .find(|allocation| allocation.requirement_id == "primary")
            .ok_or(StoreError::Corrupt)?;
        let appointment_id = Uuid::new_v4();
        let mut claim = transaction
            .insert_claim(&NewClaim {
                claim_id: appointment_id,
                kind: LedgerKind::Booking,
                state: ClaimState::Active,
                offering: &hold.offering,
                operational_service: &primary.offering.service,
                operational_location: &primary.offering.location,
                operational_mode: primary.offering.mode,
                supply_id: &primary_allocation.resource,
                channel: hold.channel.as_deref(),
                displayed_start: hold.displayed_start,
                displayed_end: hold.displayed_end,
                occupied_start: primary_allocation.occupied_start,
                occupied_end: primary_allocation.occupied_end,
                units: i32::try_from(primary_allocation.units).map_err(|_| StoreError::Corrupt)?,
                party: hold.party,
                party_references: &hold.party_references,
                source_manager: hold.source_manager.as_ref(),
                duplicate_key: hold.duplicate_key.as_deref(),
                external_references: &hold.external_references,
                hold_expires_at: None,
                revision: 1,
                policy_revision: commitment.policy_revision,
                actor: commitment.actor,
                owner_issuer: commitment.actor_issuer,
                owner_subject: commitment.actor_subject,
                reason: None,
            })
            .await?;
        let stored = stored_bundle_allocations(&admission, lines)?;
        transaction
            .insert_claim_allocations(appointment_id, &stored)
            .await?;
        claim.allocations = documents;
        if !transaction
            .close_claim(hold_id, ClaimState::Consumed, None, hold.revision)
            .await?
        {
            return Err(AdmissionRefusal::HoldReleased.into());
        }
        transaction
            .insert_history(
                appointment_id,
                1,
                "confirmed",
                commitment.now,
                commitment.actor,
                json!({"confirmedFrom": hold_id, "start": claim.displayed_start, "allocations": claim.allocations}),
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
        mint_reminders(&transaction, &claim, primary.offering, commitment.now).await?;
        if let Some(hooks) = commitment.hooks {
            hooks
                .capture(&transaction, APPOINTMENT_CONFIRMED_TRIGGER, &claim)
                .await?;
        }
        transaction
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                &scope,
                AttemptState::Completed,
                201,
                claim_receipt("booking", &claim, true, commitment.policy_revision),
            )
            .await?;
        self.commit_capacity(transaction, Some(&commitment)).await?;
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
        commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let scope = format!("hold:{hold_id}:confirm");
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
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
        // The snapshot is read under the lock for serialization order, but
        // admission is not re-evaluated: the hold's own reservation transfers
        // to the booking in this same transaction, so capacity does not
        // change. What must hold is identity (the policy revision the hold
        // was admitted under is still current), checked with the other
        // revision guards below, under the anchor.
        let _snapshot = lock_and_snapshot(&transaction, supply, commitment.now).await?;
        let hold = transaction
            .claim_in_transaction(hold_id)
            .await?
            .ok_or(AdmissionRefusal::HoldReleased)?;
        if hold.kind != LedgerKind::Hold || hold.state != ClaimState::Active {
            return Err(AdmissionRefusal::HoldReleased.into());
        }
        guard_revisions(&transaction, &commitment).await?;
        // A confirmation request may have entered while the hold was live but
        // reached this anchor after its capacity was reclaimed. Re-read the
        // clock only after taking the anchor: accepting the older request time
        // here could transfer capacity that a later transaction already
        // booked. Other caller-visible decisions keep the request's single
        // clock observation.
        evaluate_hold_state(&hold_ledger_claim(&hold), self.observed_now())?;
        if hold.policy_revision != commitment.policy_revision {
            return Err(AdmissionRefusal::PolicyChanged.into());
        }
        if !hold.is_managed_by(&commitment) {
            // Confirming another caller's hold is never a state error: it is
            // an authorization refusal the audit entries record.
            return Err(CommitError::Unauthorized);
        }
        // A hold reserves capacity, but a subsequently recorded absence must
        // not turn into a confirmed promise. The facts revision was checked
        // under the anchor above; keep the hold intact for release or expiry.
        if let SupplyContext::ExactTime {
            exact,
            members,
            open,
            closures,
        } = supply
        {
            let member = members
                .iter()
                .find(|member| member.resource_id == hold.supply_id)
                .ok_or(AdmissionRefusal::ResourceUnavailable)?;
            if !member.serves(&offering.requires_capabilities) {
                return Err(AdmissionRefusal::CapabilityUnmatched.into());
            }
            if !member.available_during(hold.occupied_start, hold.occupied_end) {
                return Err(AdmissionRefusal::ResourceUnavailable.into());
            }
            let (start, end) = match exact.opening_coverage {
                registry_scheduling_core::OpeningCoverage::ServiceInterval => {
                    (hold.displayed_start, hold.displayed_end)
                }
                registry_scheduling_core::OpeningCoverage::OccupiedInterval => {
                    (hold.occupied_start, hold.occupied_end)
                }
            };
            if !registry_scheduling_core::covers_span(open, start, end) {
                return Err(if closures
                    .iter()
                    .any(|closed| start < closed.end && closed.start < end)
                {
                    AdmissionRefusal::LocationClosed
                } else {
                    AdmissionRefusal::ScheduleUnpublished
                }
                .into());
            }
        }
        self.recheck_grant(&commitment)?;
        let appointment_id = Uuid::new_v4();
        let claim = transaction
            .insert_claim(&NewClaim {
                claim_id: appointment_id,
                kind: LedgerKind::Booking,
                state: ClaimState::Active,
                offering: &hold.offering,
                operational_service: &offering.service,
                operational_location: &offering.location,
                operational_mode: offering.mode,
                supply_id: &hold.supply_id,
                channel: hold.channel.as_deref(),
                displayed_start: hold.displayed_start,
                displayed_end: hold.displayed_end,
                occupied_start: hold.occupied_start,
                occupied_end: hold.occupied_end,
                units: hold.units,
                party: hold.party,
                party_references: &hold.party_references,
                source_manager: hold.source_manager.as_ref(),
                duplicate_key: hold.duplicate_key.as_deref(),
                external_references: &hold.external_references,
                hold_expires_at: None,
                revision: 1,
                policy_revision: commitment.policy_revision,
                actor: commitment.actor,
                owner_issuer: commitment.actor_issuer,
                owner_subject: commitment.actor_subject,
                reason: None,
            })
            .await?;
        if !transaction
            .close_claim(hold_id, ClaimState::Consumed, None, hold.revision)
            .await?
        {
            // The hold changed state between the read and this write; the
            // whole transaction, booking included, rolls back behind the
            // refusal.
            return Err(AdmissionRefusal::HoldReleased.into());
        }
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
        if let Some(hooks) = commitment.hooks {
            hooks
                .capture(&transaction, APPOINTMENT_CONFIRMED_TRIGGER, &claim)
                .await?;
        }
        transaction
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                &scope,
                AttemptState::Completed,
                201,
                claim_receipt(
                    "booking",
                    &claim,
                    matches!(supply, SupplyContext::ExactTime { .. }),
                    commitment.policy_revision,
                ),
            )
            .await?;
        self.commit_capacity(transaction, Some(&commitment)).await?;
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
        mark_allocation_writer(&transaction).await?;
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
        if !hold.is_managed_by(&commitment) {
            return Err(CommitError::Unauthorized);
        }
        self.recheck_grant(&commitment)?;
        if !transaction
            .close_claim(hold_id, ClaimState::Released, None, hold.revision)
            .await?
        {
            return Err(AdmissionRefusal::HoldReleased.into());
        }
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
        self.commit_capacity(transaction, Some(&commitment)).await?;
        Ok(CommitOutcome::Released)
    }

    /// Reschedule every exact allocation to a new interval while preserving
    /// the logical appointment identity. A refusal rolls back both the parent
    /// movement and the child replacement.
    pub async fn reschedule_bundle_appointment(
        &self,
        appointment_id: Uuid,
        lines: &[BundleSupplyLine<'_>],
        request: &registry_scheduling_core::AdmissionRequest,
        observed_revision: u64,
        commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let scope = format!("appointment:{appointment_id}:reschedule");
        let primary = lines.first().ok_or(StoreError::Corrupt)?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
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
        let old_anchors = transaction
            .query(
                "SELECT DISTINCT anchor_id FROM scheduling_claim_allocations \
                 WHERE claim_id=$1 AND anchor_id IS NOT NULL ORDER BY anchor_id",
                &[&appointment_id],
            )
            .await?
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>();
        let mut snapshot = lock_bundle_and_snapshot(
            &transaction,
            lines,
            request,
            commitment.now,
            &old_anchors,
            &self.busy_source_bindings,
        )
        .await?;
        include_bundle_active_duplicates(
            &transaction,
            &mut snapshot,
            lines,
            request.duplicate_key.as_deref(),
            commitment.now,
        )
        .await?;
        let appointment = transaction
            .claim_in_transaction(appointment_id)
            .await?
            .ok_or(AdmissionRefusal::HoldReleased)?;
        if appointment.kind != LedgerKind::Booking || appointment.state != ClaimState::Active {
            return Err(AdmissionRefusal::HoldReleased.into());
        }
        guard_revisions(&transaction, &commitment).await?;
        if request.policy_revision != u64::try_from(commitment.policy_revision).unwrap_or(u64::MAX)
        {
            return Err(AdmissionRefusal::PolicyChanged.into());
        }
        if !appointment.is_managed_by(&commitment) {
            return Err(CommitError::Unauthorized);
        }
        if u64::try_from(appointment.revision) != Ok(observed_revision) {
            return Err(CommitError::RevisionMismatch);
        }
        let own_claim_id = appointment.claim_id.to_string();
        let admission = evaluate_bundle(
            lines,
            request,
            &snapshot,
            &commitment,
            Some(&own_claim_id),
            false,
        )?;
        self.recheck_grant(&commitment)?;
        let primary_allocation = admission
            .allocations
            .iter()
            .find(|allocation| allocation.requirement_id == "primary")
            .ok_or(StoreError::Corrupt)?;
        let next_revision = appointment.revision + 1;
        let next_units =
            i32::try_from(primary_allocation.units).map_err(|_| StoreError::Corrupt)?;
        if !transaction
            .move_claim(
                &ClaimMove {
                    claim_id: appointment_id,
                    supply_id: &primary_allocation.resource,
                    displayed_start: admission.start,
                    displayed_end: admission.end,
                    occupied_start: primary_allocation.occupied_start,
                    occupied_end: primary_allocation.occupied_end,
                    channel: request.channel.as_deref(),
                    units: next_units,
                    party: request.party,
                    policy_revision: commitment.policy_revision,
                    next_revision,
                },
                appointment.revision,
            )
            .await?
        {
            return Err(CommitError::RevisionMismatch);
        }
        let stored = stored_bundle_allocations(&admission, lines)?;
        transaction
            .replace_claim_allocations(appointment_id, &stored)
            .await?;
        let documents = allocation_documents(&admission)?;
        transaction
            .insert_history(
                appointment_id,
                next_revision,
                "rescheduled",
                commitment.now,
                commitment.actor,
                json!({
                    "from": {"start": appointment.displayed_start, "end": appointment.displayed_end, "allocations": appointment.allocations},
                    "to": {"start": admission.start, "end": admission.end, "allocations": documents},
                }),
            )
            .await?;
        transaction.cancel_unsent_reminders(appointment_id).await?;
        let moved = ClaimRow {
            displayed_start: admission.start,
            displayed_end: admission.end,
            occupied_start: primary_allocation.occupied_start,
            occupied_end: primary_allocation.occupied_end,
            supply_id: primary_allocation.resource.clone(),
            channel: request.channel.clone(),
            units: next_units,
            allocations: documents,
            party: request.party,
            revision: next_revision,
            policy_revision: commitment.policy_revision,
            ..appointment.clone()
        };
        mint_reminders(&transaction, &moved, primary.offering, commitment.now).await?;
        transaction
            .insert_outbox(
                "change",
                appointment_id,
                next_revision,
                commitment.now,
                confirmation_payload(&moved, commitment.policy_revision),
            )
            .await?;
        if let Some(hooks) = commitment.hooks {
            hooks
                .capture(&transaction, APPOINTMENT_RESCHEDULED_TRIGGER, &moved)
                .await?;
        }
        transaction
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                &scope,
                AttemptState::Completed,
                200,
                claim_receipt("booking", &moved, true, commitment.policy_revision),
            )
            .await?;
        self.commit_capacity(transaction, Some(&commitment)).await?;
        Ok(CommitOutcome::Booking(moved))
    }

    /// Reschedule an appointment to a new time, keeping its identity.
    pub async fn reschedule_appointment(
        &self,
        appointment_id: Uuid,
        offering: &registry_scheduling_core::OfferingPolicy,
        supply: &SupplyContext<'_>,
        request: &registry_scheduling_core::AdmissionRequest,
        observed_revision: u64,
        commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let scope = format!("appointment:{appointment_id}:reschedule");
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
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
        // A move between two windows of one offering releases units in the
        // window the appointment leaves and takes them in the one it enters.
        // Both window anchors are held, in supply-id order (`lock_supply`
        // sorts them), before the snapshot and before any claim row, so two
        // moves in opposite directions serialize instead of deadlocking.
        let left_window = match supply {
            SupplyContext::Window { window, .. } => transaction
                .query_opt(
                    "SELECT supply_id FROM scheduling_claims WHERE claim_id=$1 AND kind='booking'",
                    &[&appointment_id],
                )
                .await
                .map_err(StoreError::from)?
                .map(|row| row.get::<_, String>(0))
                .filter(|current| *current != window.id),
            SupplyContext::ExactTime { .. } => None,
        };
        if let (Some(left), SupplyContext::Window { window, .. }) = (&left_window, supply) {
            let mut anchors = vec![left.clone(), window.id.clone()];
            anchors.sort();
            transaction.lock_supply(&anchors).await?;
        }
        let mut snapshot = lock_and_snapshot(&transaction, supply, commitment.now).await?;
        include_active_duplicate(
            &transaction,
            &mut snapshot,
            offering,
            request.duplicate_key.as_deref(),
            commitment.now,
        )
        .await?;
        let appointment = transaction
            .claim_in_transaction(appointment_id)
            .await?
            .ok_or(AdmissionRefusal::HoldReleased)?;
        if appointment.kind != LedgerKind::Booking || appointment.state != ClaimState::Active {
            return Err(AdmissionRefusal::HoldReleased.into());
        }
        guard_revisions(&transaction, &commitment).await?;
        // The policy guard wins over the revision guard: a caller whose
        // observed revision is also stale learns the policy moved first.
        if request.policy_revision != u64::try_from(commitment.policy_revision).unwrap_or(u64::MAX)
        {
            return Err(AdmissionRefusal::PolicyChanged.into());
        }
        if !appointment.is_managed_by(&commitment) {
            return Err(CommitError::Unauthorized);
        }
        if u64::try_from(appointment.revision) != Ok(observed_revision) {
            return Err(CommitError::RevisionMismatch);
        }
        // The window the appointment occupies now must be one this
        // transaction holds: a concurrent move between the read above and
        // the locks is answered as the revision race it is.
        let entered = window_supply_id(supply);
        if !entered.is_empty()
            && appointment.supply_id != entered
            && Some(&appointment.supply_id) != left_window.as_ref()
        {
            return Err(CommitError::RevisionMismatch);
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
        self.recheck_grant(&commitment)?;
        let next_revision = appointment.revision + 1;
        let next_units = i32::try_from(admission.units).map_err(|_| StoreError::Corrupt)?;
        // A window admission names no resource: the claim occupies the
        // window it was admitted to, which a reschedule may change.
        let next_supply = admission.resource.clone().unwrap_or_else(|| {
            if entered.is_empty() {
                appointment.supply_id.clone()
            } else {
                entered.to_owned()
            }
        });
        if !transaction
            .move_claim(
                &ClaimMove {
                    claim_id: appointment_id,
                    supply_id: &next_supply,
                    displayed_start: admission.start,
                    displayed_end: admission.end,
                    occupied_start: admission.occupied_start,
                    occupied_end: admission.occupied_end,
                    channel: request.channel.as_deref(),
                    units: next_units,
                    party: request.party,
                    policy_revision: commitment.policy_revision,
                    next_revision,
                },
                appointment.revision,
            )
            .await?
        {
            // A concurrent lifecycle writer moved the appointment first;
            // this transaction's whole decision rolls back behind the
            // refusal.
            return Err(CommitError::RevisionMismatch);
        }
        transaction
            .insert_history(appointment_id, next_revision, "rescheduled", commitment.now,
                commitment.actor,
                json!({
                    "from": {"start": appointment.displayed_start, "end": appointment.displayed_end},
                    "to": {"start": admission.start, "end": admission.end},
                }))
            .await?;
        // A stale unsent reminder describes an appointment that no longer
        // exists in this form; it is cancelled here, and one a dispatcher
        // already holds is set aside at its send, never sent (INT-02).
        transaction.cancel_unsent_reminders(appointment_id).await?;
        let moved = ClaimRow {
            displayed_start: admission.start,
            displayed_end: admission.end,
            occupied_start: admission.occupied_start,
            occupied_end: admission.occupied_end,
            supply_id: next_supply,
            channel: request.channel.clone(),
            units: next_units,
            party: request.party,
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
        if let Some(hooks) = commitment.hooks {
            hooks
                .capture(&transaction, APPOINTMENT_RESCHEDULED_TRIGGER, &moved)
                .await?;
        }
        transaction
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                &scope,
                AttemptState::Completed,
                200,
                claim_receipt(
                    "booking",
                    &moved,
                    matches!(supply, SupplyContext::ExactTime { .. }),
                    commitment.policy_revision,
                ),
            )
            .await?;
        self.commit_capacity(transaction, Some(&commitment)).await?;
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
        resource_is_member: bool,
        reason: Option<&str>,
        commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let scope = format!("appointment:{appointment_id}:cancel");
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
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
        if !appointment.is_managed_by(&commitment) {
            return Err(CommitError::Unauthorized);
        }
        if u64::try_from(appointment.revision) != Ok(observed_revision) {
            return Err(CommitError::RevisionMismatch);
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
        self.recheck_grant(&commitment)?;
        let next_revision = appointment.revision + 1;
        if !transaction
            .close_claim(
                appointment_id,
                ClaimState::Cancelled,
                reason,
                appointment.revision,
            )
            .await?
        {
            // A concurrent lifecycle writer closed or moved the appointment
            // first; nothing this transaction decided stands.
            return Err(CommitError::RevisionMismatch);
        }
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
        transaction.cancel_unsent_reminders(appointment_id).await?;
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
        if let Some(hooks) = commitment.hooks {
            hooks
                .capture(&transaction, APPOINTMENT_CANCELLED_TRIGGER, &cancelled)
                .await?;
        }
        transaction
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                &scope,
                AttemptState::Completed,
                200,
                claim_receipt(
                    "booking",
                    &cancelled,
                    resource_is_member,
                    commitment.policy_revision,
                ),
            )
            .await?;
        self.commit_capacity(transaction, Some(&commitment)).await?;
        Ok(CommitOutcome::Cancelled(cancelled))
    }

    /// Read a retained successful command receipt for the exact owning caller.
    /// Absence, request mismatch and expiry all remain unresolved. This read
    /// never opens a capacity transaction or creates an idempotency attempt.
    pub async fn appointment_receipt(
        &self,
        issuer: &str,
        subject: &str,
        scope: &str,
        key: &str,
        request_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Value>, StoreError> {
        let client = self.client().await?;
        let reference = attempt_key_reference(issuer, subject, scope, key);
        let row = client
            .query_opt(
                "SELECT a.receipt FROM scheduling_attempts a \
                 JOIN scheduling_claims c ON c.claim_id=(a.receipt->'claim'->>'claimId')::uuid \
                 WHERE a.key_reference=$1 AND a.request_hash=$2 \
                 AND a.state='completed' AND a.status_code IN (200,201) \
                 AND a.erased_at IS NULL AND a.expires_at>$3 \
                 AND c.owner_issuer=$4 AND c.owner_subject=$5",
                &[&reference, &request_hash, &now, &issuer, &subject],
            )
            .await?;
        Ok(row.and_then(|row| row.get(0)))
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
        mark_allocation_writer(&transaction).await?;
        let rows = transaction
            .query(
                "UPDATE scheduling_claims SET state='expired', revision=revision + 1, \
                 closed_at=now(), changed_at=now() \
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

    /// A pooled connection for the delivery-intent dispatcher.
    pub(crate) async fn intent_dispatch_client(
        &self,
    ) -> Result<deadpool_postgres::Client, StoreError> {
        self.client().await
    }

    /// The intents nothing will deliver without an operator, oldest first.
    ///
    /// A deployment that declares no reminders destination sets every intent
    /// aside locally, and a destination that refused an intent, or failed
    /// every attempt the policy allowed, leaves it failed. Both are recorded
    /// and then waited on by nobody, so without a read path an operator
    /// cannot tell either has happened. Delivered intents are not listed,
    /// and neither are pending or leased ones: the dispatcher is still
    /// carrying those. A reminder cancelled, or set aside, because its
    /// appointment was cancelled or moved is not listed either: nobody is
    /// meant to deliver it.
    pub async fn undelivered_intents(
        &self,
        limit: i64,
    ) -> Result<Vec<UndeliveredIntent>, StoreError> {
        let limit = validated_undelivered_intents_limit(limit)?;
        let client = self.client().await?;
        let rows = client
            .query(
                "SELECT outbox_id, purpose, claim_id, appointment_revision, due_at, \
                 CASE WHEN last_failure_class = 'destination_unconfigured' \
                      THEN 'local' ELSE 'failed' END, \
                 attempt::integer, payload FROM scheduling_outbox \
                 WHERE state IN ('dead-lettered','expired') \
                   AND last_failure_class IS DISTINCT FROM 'superseded' \
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
    ) -> Result<Option<(u16, Value)>, CommitError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
        let written = transaction
            .execute(
                "INSERT INTO scheduling_attempts(attempt_id, key_reference, actor_issuer, \
                 actor_subject, scope, idempotency_key, request_hash, state, status_code, receipt, \
                 expires_at) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,'refused',$8,$9,$10) ON CONFLICT DO NOTHING",
                &[
                    &Uuid::new_v4(),
                    &commitment.key_reference(scope),
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
        if written == 1 {
            transaction.commit().await?;
            return Ok(None);
        }
        match replay_stored_attempt(&transaction, commitment, scope).await? {
            Some(ReplayOutcome::Replay {
                status_code,
                receipt,
            }) => {
                transaction.commit().await?;
                Ok(Some((status_code, receipt)))
            }
            Some(ReplayOutcome::Refused(error)) => Err(error),
            None => Err(StoreError::Corrupt.into()),
        }
    }

    /// Clear raw ownership once a claim's end or earlier closure is beyond
    /// the configured window. Expired holds use their actual expiry even if
    /// the expiry worker recorded closure later. Consuming a hold closes it;
    /// the appointment created from it retains its own independent owner.
    ///
    /// The digest binds the fixed domain, the claim UUID bytes, and the two
    /// UTF-8 owner values prefixed by their big-endian u64 byte lengths. It
    /// is scoped to one claim and never used for authorization. PostgreSQL
    /// computes it and clears the raw pair in one atomic row update, whose
    /// predicate is rechecked after a concurrent reschedule or closure.
    pub async fn erase_expired_claim_owners(
        &self,
        now: DateTime<Utc>,
        retention_days: u32,
    ) -> Result<u64, StoreError> {
        if !(1..=crate::config::MAX_CLAIM_OWNER_RETENTION_DAYS).contains(&retention_days) {
            return Err(StoreError::Configuration);
        }
        let cutoff = now
            .checked_sub_signed(TimeDelta::days(i64::from(retention_days)))
            .ok_or(StoreError::Configuration)?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
        let erased = transaction.execute(
            "UPDATE scheduling_claims SET owner_reference='sha256:' || encode(sha256(\
             convert_to('scheduling-claim-owner-v1','UTF8') || uuid_send(claim_id) || \
             int8send(octet_length(convert_to(owner_issuer,'UTF8'))::bigint) || convert_to(owner_issuer,'UTF8') || \
             int8send(octet_length(convert_to(owner_subject,'UTF8'))::bigint) || convert_to(owner_subject,'UTF8')), 'hex'), \
             owner_issuer=NULL, owner_subject=NULL, owner_erased_at=$1, \
             party_references='[]'::jsonb, manager_source_issuer=NULL, manager_subject=NULL \
             WHERE owner_issuer IS NOT NULL AND \
             CASE WHEN kind='booking' THEN LEAST(displayed_end, closed_at) \
                  ELSE LEAST(hold_expires_at, closed_at) END <= $2",
            &[&now, &cutoff],
        ).await?;
        transaction.commit().await?;
        Ok(erased)
    }

    /// Prune at most 256 settled outbox intents of any purpose
    /// (confirmation, change, cancellation, reminder) and 256 terminal hook
    /// deliveries per tick, using the configured receipt metadata horizon.
    /// An intent is settled once delivered, cancelled before any attempt,
    /// or set aside as superseded: nobody is meant to act on any of them.
    /// Pending, leased and every other set-aside intent remain retained;
    /// hooks also preserve replay until payload expiry has completed.
    pub async fn erase_terminal_dispatch(
        &self,
        now: DateTime<Utc>,
        receipt_retention_days: u32,
    ) -> Result<u64, StoreError> {
        if !(1..=crate::config::MAX_RECEIPT_RETENTION_DAYS).contains(&receipt_retention_days) {
            return Err(StoreError::Configuration);
        }
        let cutoff = now
            .checked_sub_signed(TimeDelta::days(i64::from(receipt_retention_days)))
            .ok_or(StoreError::Configuration)?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_allocation_writer(&transaction).await?;
        let schema = current_schema_in(&*transaction).await?;
        let reminders = transaction
            .execute(
                "DELETE FROM scheduling_outbox WHERE outbox_id IN (
                SELECT outbox_id FROM scheduling_outbox
                WHERE (state='delivered' AND delivered_at <= $1)
                   OR (state='cancelled' AND updated_at <= $1)
                   OR (state='dead-lettered' AND last_failure_class='superseded'
                       AND dead_lettered_at <= $1)
                ORDER BY COALESCE(delivered_at, dead_lettered_at, updated_at), outbox_id
                LIMIT 256 FOR UPDATE SKIP LOCKED
             )",
                &[&cutoff],
            )
            .await?;
        let hooks = registry_platform_hooks::delivery::prune_terminal_deliveries(
            &transaction,
            &schema,
            cutoff.into(),
        )
        .await
        .map_err(StoreError::DispatchRetention)?;
        transaction.commit().await?;
        Ok(reminders + hooks)
    }

    /// Erase idempotency receipts past their retention period. The answer and
    /// the raw issuer, subject, and key are dropped together; the row is kept
    /// under its key reference and stamped erased. A key that answered once
    /// stays spent for its caller, so a retry after the period is refused as
    /// expired rather than executed again as a fresh request, and the row is
    /// never deleted.
    ///
    /// Claim ownership has its own retention pass. Claim, history and outbox
    /// rows remain; audit entries live under the audit destination's retention.
    pub async fn erase_expired_attempts(&self, now: DateTime<Utc>) -> Result<u64, StoreError> {
        let client = self.client().await?;
        Ok(client
            .execute(
                "UPDATE scheduling_attempts SET erased_at=$1, receipt=NULL, \
                 actor_issuer=NULL, actor_subject=NULL, idempotency_key=NULL \
                 WHERE expires_at <= $1 AND erased_at IS NULL",
                &[&now],
            )
            .await?)
    }
}

const SELECT_CLAIM: &str = "SELECT claim_id, kind, state, offering, supply_id, channel, \
     displayed_start, displayed_end, occupied_start, occupied_end, units, duplicate_key, \
     external_references, hold_expires_at, revision, policy_revision, actor, reason, created_at, closed_at, \
     owner_issuer, owner_subject, recipient_count, attendee_count, party_references, \
     manager_source_issuer, manager_subject \
     FROM scheduling_claims WHERE claim_id=$1";

/// The consuming-claim filter, with hold expiry evaluated in the query. This
/// is the sentence the whole capacity contract turns on: an expired hold
/// stops consuming capacity at its expiry, whether or not any worker has
/// touched it.
const CONSUMING_CLAUSES: &str =
    "SELECT c.claim_id, a.offering, a.resource_id, c.kind, c.channel, a.occupied_start, \
     a.occupied_end, a.units, c.duplicate_key, c.hold_expires_at \
     FROM scheduling_claim_allocations AS a \
     JOIN scheduling_claims AS c ON c.claim_id=a.claim_id \
     WHERE c.state='active' \
       AND (c.kind IN ('booking','window') OR (c.kind='hold' AND c.hold_expires_at > $4)) \
       AND a.resource_id = ANY($1) \
       AND a.occupied_start < $3::timestamptz AND $2::timestamptz < a.occupied_end \
     ORDER BY a.occupied_start, a.claim_id, a.resource_id";

fn map_claim_row(row: Row) -> Result<ClaimRow, StoreError> {
    Ok(ClaimRow {
        claim_id: row.get(0),
        kind: match row.get::<_, String>(1).as_str() {
            "booking" => LedgerKind::Booking,
            "hold" => LedgerKind::Hold,
            "window" => LedgerKind::Window,
            _ => return Err(StoreError::Corrupt),
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
        allocations: Vec::new(),
        duplicate_key: row.get(11),
        external_references: serde_json::from_value(row.get(12))
            .map_err(|_| StoreError::Corrupt)?,
        hold_expires_at: row.get(13),
        revision: row.get(14),
        policy_revision: row.get(15),
        actor: row.get(16),
        reason: row.get(17),
        created_at: row.get(18),
        closed_at: row.get(19),
        owner: match (row.get(20), row.get(21)) {
            (Some(issuer), Some(subject)) => Some(ClaimOwner { issuer, subject }),
            _ => None,
        },
        party: match (row.get::<_, Option<i32>>(22), row.get::<_, Option<i32>>(23)) {
            (Some(recipients), Some(attendees)) => Some(PartyCounts {
                recipients: u32::try_from(recipients).map_err(|_| StoreError::Corrupt)?,
                attendees: u32::try_from(attendees).map_err(|_| StoreError::Corrupt)?,
            }),
            (None, None) => None,
            _ => return Err(StoreError::Corrupt),
        },
        party_references: serde_json::from_value(row.get(24)).map_err(|_| StoreError::Corrupt)?,
        source_manager: match (row.get(25), row.get(26)) {
            (Some(source_issuer), Some(subject)) => Some(SourceBoundManager {
                source_issuer,
                subject,
            }),
            (None, None) => None,
            _ => return Err(StoreError::Corrupt),
        },
    })
}

/// Attach only allocation rows whose immutable operational labels were
/// recovered. Version-zero rows still count for capacity by resource id, but
/// cannot safely be disclosed as authorized operational detail.
async fn load_claim_allocations(
    client: &impl DeadpoolGenericClient,
    claims: &mut [ClaimRow],
) -> Result<(), StoreError> {
    if claims.is_empty() {
        return Ok(());
    }
    let claim_ids: Vec<Uuid> = claims.iter().map(|claim| claim.claim_id).collect();
    let rows = client
        .query(
            "SELECT claim_id, requirement_kind, requirement_index, offering, resource_id, \
             units, occupied_start, occupied_end \
             FROM scheduling_claim_allocations \
             WHERE claim_id = ANY($1) AND allocation_scope_version=1 \
               AND operational_mode='exact-time' \
             ORDER BY claim_id, CASE requirement_kind WHEN 'primary' THEN -1 ELSE requirement_index END, \
                      part_index",
            &[&claim_ids],
        )
        .await?;
    for row in rows {
        let claim_id: Uuid = row.get(0);
        let claim = claims
            .iter_mut()
            .find(|claim| claim.claim_id == claim_id)
            .ok_or(StoreError::Corrupt)?;
        let requirement = match row.get::<_, String>(1).as_str() {
            "primary" => AllocationRequirementDocument::Primary,
            "additional" => AllocationRequirementDocument::Additional {
                index: u8::try_from(row.get::<_, i16>(2)).map_err(|_| StoreError::Corrupt)?,
            },
            _ => return Err(StoreError::Corrupt),
        };
        claim.allocations.push(AllocationDocument {
            requirement,
            offering: row.get(3),
            resource: row.get(4),
            units: u32::try_from(row.get::<_, i32>(5)).map_err(|_| StoreError::Corrupt)?,
            occupied_start: row.get(6),
            occupied_end: row.get(7),
        });
    }
    Ok(())
}

fn snapshot_from_rows(rows: Vec<Row>) -> LedgerSnapshot {
    LedgerSnapshot {
        claims: rows
            .iter()
            .map(|row| LedgerClaim {
                id: row.get::<_, Uuid>(0).to_string(),
                offering: row.get(1),
                supply_id: row.get(2),
                kind: match row.get::<_, String>(3).as_str() {
                    "booking" => LedgerKind::Booking,
                    "hold" => LedgerKind::Hold,
                    "window" => LedgerKind::Window,
                    _ => unreachable!("database claim-kind constraint rejected this value"),
                },
                channel: row.get(4),
                start: row.get(5),
                end: row.get(6),
                units: u32::try_from(row.get::<_, i32>(7)).unwrap_or(u32::MAX),
                duplicate_key: row.get(8),
                expires_at: row.get(9),
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
            let buffer = TimeDelta::minutes(
                i64::from(exact.buffer_before_minutes) + i64::from(exact.buffer_after_minutes),
            );
            let duration = TimeDelta::minutes(i64::from(exact.duration_minutes));
            let earliest = earliest
                .checked_sub_signed(buffer)
                .ok_or(StoreError::Corrupt)?;
            let latest = latest
                .checked_add_signed(duration + buffer)
                .ok_or(StoreError::Corrupt)?;
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
                    "SELECT claim_id, offering, supply_id, kind, channel, occupied_start, occupied_end, \
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

async fn lock_bundle_and_snapshot(
    transaction: &deadpool_postgres::Transaction<'_>,
    lines: &[BundleSupplyLine<'_>],
    request: &registry_scheduling_core::AdmissionRequest,
    now: DateTime<Utc>,
    extra_anchors: &[String],
    busy_source_bindings: &std::collections::BTreeMap<String, Vec<String>>,
) -> Result<LedgerSnapshot, CommitError> {
    let Some(primary) = lines.first() else {
        return Err(StoreError::Corrupt.into());
    };
    let duration_minutes = primary
        .exact
        .selected_duration_minutes(request.duration_minutes)
        .ok_or(AdmissionRefusal::DurationOutOfPolicy)?;
    let mut anchors: Vec<String> = lines.iter().map(|line| line.exact.pool.clone()).collect();
    anchors.extend(extra_anchors.iter().cloned());
    anchors.sort();
    anchors.dedup();
    transaction.lock_supply(&anchors).await?;

    let mut resources: Vec<String> = lines
        .iter()
        .flat_map(|line| line.members.iter().map(|member| member.resource_id.clone()))
        .collect();
    resources.sort();
    resources.dedup();
    let maximum_before = lines
        .iter()
        .map(|line| line.exact.buffer_before_minutes)
        .max()
        .unwrap_or(0);
    let maximum_after = lines
        .iter()
        .map(|line| line.exact.buffer_after_minutes)
        .max()
        .unwrap_or(0);
    let from = request
        .start
        .checked_sub_signed(TimeDelta::minutes(i64::from(maximum_before)))
        .ok_or(AdmissionRefusal::ScheduleUnpublished)?;
    let to = request
        .start
        .checked_add_signed(TimeDelta::minutes(
            i64::from(duration_minutes) + i64::from(maximum_after),
        ))
        .ok_or(AdmissionRefusal::ScheduleUnpublished)?;
    let limit =
        i64::try_from(MAXIMUM_CAPACITY_SNAPSHOT_ROWS + 1).map_err(|_| StoreError::Corrupt)?;
    let rows = transaction
        .query(
            "SELECT c.claim_id, a.offering, a.resource_id, c.kind, c.channel, \
             a.occupied_start, a.occupied_end, a.units, c.duplicate_key, c.hold_expires_at \
             FROM scheduling_claim_allocations AS a \
             JOIN scheduling_claims AS c ON c.claim_id=a.claim_id \
             WHERE c.state='active' \
               AND (c.kind IN ('booking','window') OR (c.kind='hold' AND c.hold_expires_at > $4)) \
               AND a.resource_id = ANY($1) \
               AND a.occupied_start < $3 AND $2 < a.occupied_end \
             ORDER BY a.occupied_start, a.claim_id, a.resource_id LIMIT $5",
            &[&resources, &from, &to, &now, &limit],
        )
        .await?;
    if rows.len() > MAXIMUM_CAPACITY_SNAPSHOT_ROWS {
        return Err(StoreError::CapacitySnapshotTooLarge.into());
    }
    let mut snapshot = snapshot_from_rows(rows);
    source_busy::append_busy_allocation_blocks(
        transaction,
        busy_source_bindings,
        lines,
        request,
        now,
        &mut snapshot,
    )
    .await
    .map_err(source_busy::as_store_error)?;
    Ok(snapshot)
}

fn evaluate_bundle(
    lines: &[BundleSupplyLine<'_>],
    request: &registry_scheduling_core::AdmissionRequest,
    snapshot: &LedgerSnapshot,
    commitment: &Commitment<'_>,
    exclude: Option<&str>,
    confirming_hold: bool,
) -> Result<BundleAdmission, CommitError> {
    let contexts: Vec<_> = lines
        .iter()
        .map(|line| ExactTimeBundleLineContext {
            requirement_id: line.requirement_id.clone(),
            offering: line.offering,
            exact: line.exact,
            members: line.members,
            open: line.open,
            closures: line.closures,
            resource: line.resource,
            stored_resource: line.stored_resource,
            units: line.units,
        })
        .collect();
    match evaluate_exact_time_bundle(
        &ExactTimeBundleContext {
            lines: &contexts,
            snapshot,
            policy_revision: u64::try_from(commitment.policy_revision).unwrap_or(u64::MAX),
            now: commitment.now,
            exclude_reservation: exclude,
            confirming_hold,
            limits: AllocationLimits {
                maximum_requirements: registry_scheduling_core::MAXIMUM_ALLOCATION_REQUIREMENTS,
                maximum_units_per_requirement: registry_scheduling_core::MAXIMUM_RESOURCE_UNITS,
                maximum_candidate_resources: 4_096,
                maximum_standing_allocations: MAXIMUM_CAPACITY_SNAPSHOT_ROWS,
            },
        },
        request,
    ) {
        Ok(admission) => Ok(admission),
        Err(BundleEvaluationError::Admission(refusal)) => Err(refusal.into()),
        Err(BundleEvaluationError::Allocation(AllocationError::CapacityExhausted { .. })) => {
            Err(AdmissionRefusal::CapacityExhausted.into())
        }
        Err(BundleEvaluationError::Allocation(AllocationError::SnapshotTooLarge { .. })) => {
            Err(StoreError::CapacitySnapshotTooLarge.into())
        }
        Err(BundleEvaluationError::Shape) => Err(StoreError::Corrupt.into()),
        Err(error) => {
            tracing::info!(error = %error, "an atomic allocation request was invalid");
            Err(AdmissionRefusal::AtomicBundleRequired.into())
        }
    }
}

fn confirm_stored_bundle(
    lines: &[BundleSupplyLine<'_>],
    request: &registry_scheduling_core::AdmissionRequest,
    snapshot: &LedgerSnapshot,
    commitment: &Commitment<'_>,
    hold: &ClaimRow,
) -> Result<BundleAdmission, CommitError> {
    let evaluated = evaluate_bundle(
        lines,
        request,
        snapshot,
        commitment,
        Some(&hold.claim_id.to_string()),
        true,
    )?;
    if evaluated.start != hold.displayed_start || evaluated.end != hold.displayed_end {
        return Err(StoreError::Corrupt.into());
    }

    let standing_allocations = snapshot
        .consuming(commitment.now)
        .map(|claim| StandingAllocation {
            reservation_id: claim.id.clone(),
            resource_id: claim.supply_id.clone(),
            interval: AllocationInterval {
                start: claim.start,
                end: claim.end,
            },
            units: claim.units,
        })
        .collect::<Vec<_>>();
    let mut totals = HashMap::<String, u32>::new();
    let mut resources = HashMap::<(String, String), ()>::new();
    let mut allocations = Vec::with_capacity(hold.allocations.len());
    for allocation in &hold.allocations {
        let requirement_id = match allocation.requirement {
            AllocationRequirementDocument::Primary => "primary".to_owned(),
            AllocationRequirementDocument::Additional { index } => {
                format!("additional:{index}")
            }
        };
        let line = lines
            .iter()
            .find(|line| line.requirement_id == requirement_id)
            .ok_or(StoreError::Corrupt)?;
        let expected = evaluated
            .allocations
            .iter()
            .find(|part| part.requirement_id == requirement_id)
            .ok_or(StoreError::Corrupt)?;
        if allocation.offering != line.offering.id
            || allocation.offering != expected.offering
            || allocation.occupied_start != expected.occupied_start
            || allocation.occupied_end != expected.occupied_end
            || resources
                .insert((requirement_id.clone(), allocation.resource.clone()), ())
                .is_some()
        {
            return Err(StoreError::Corrupt.into());
        }
        let member = line
            .members
            .iter()
            .find(|member| member.resource_id == allocation.resource)
            .ok_or(AdmissionRefusal::CapacityExhausted)?;
        if !member.serves(&line.offering.requires_capabilities)
            || member.capacity_units == 0
            || !member.available_during(allocation.occupied_start, allocation.occupied_end)
        {
            return Err(AdmissionRefusal::CapacityExhausted.into());
        }
        let interval = AllocationInterval {
            start: allocation.occupied_start,
            end: allocation.occupied_end,
        };
        let other_units = maximum_concurrent_units(
            &allocation.resource,
            &interval,
            &standing_allocations,
            Some(&hold.claim_id.to_string()),
        )
        .map_err(|_| StoreError::Corrupt)?;
        if other_units
            .checked_add(allocation.units)
            .is_none_or(|units| units > member.capacity_units)
        {
            return Err(AdmissionRefusal::CapacityExhausted.into());
        }
        let total = totals.entry(requirement_id.clone()).or_default();
        *total = total
            .checked_add(allocation.units)
            .ok_or(StoreError::Corrupt)?;
        allocations.push(BundleAllocation {
            requirement_id,
            offering: allocation.offering.clone(),
            resource: allocation.resource.clone(),
            units: allocation.units,
            occupied_start: allocation.occupied_start,
            occupied_end: allocation.occupied_end,
        });
    }
    if lines
        .iter()
        .any(|line| totals.get(&line.requirement_id).copied() != Some(line.units))
        || totals.len() != lines.len()
    {
        return Err(StoreError::Corrupt.into());
    }
    Ok(BundleAdmission {
        offering: evaluated.offering,
        start: evaluated.start,
        end: evaluated.end,
        allocations,
    })
}

fn stored_bundle_allocations<'a>(
    admission: &'a BundleAdmission,
    lines: &'a [BundleSupplyLine<'a>],
) -> Result<Vec<NewClaimAllocation<'a>>, StoreError> {
    admission
        .allocations
        .iter()
        .map(|allocation| {
            let line = lines
                .iter()
                .find(|line| line.requirement_id == allocation.requirement_id)
                .ok_or(StoreError::Corrupt)?;
            Ok(NewClaimAllocation {
                requirement: &allocation.requirement_id,
                offering: &allocation.offering,
                operational_service: &line.offering.service,
                operational_location: &line.offering.location,
                anchor_id: &line.exact.pool,
                resource_id: &allocation.resource,
                occupied_start: allocation.occupied_start,
                occupied_end: allocation.occupied_end,
                units: allocation.units,
            })
        })
        .collect()
}

fn allocation_documents(
    admission: &BundleAdmission,
) -> Result<Vec<AllocationDocument>, StoreError> {
    admission
        .allocations
        .iter()
        .map(|allocation| {
            let requirement = if allocation.requirement_id == "primary" {
                AllocationRequirementDocument::Primary
            } else {
                let index = allocation
                    .requirement_id
                    .strip_prefix("additional:")
                    .and_then(|index| index.parse::<u8>().ok())
                    .ok_or(StoreError::Corrupt)?;
                AllocationRequirementDocument::Additional { index }
            };
            Ok(AllocationDocument {
                requirement,
                offering: allocation.offering.clone(),
                resource: allocation.resource.clone(),
                units: allocation.units,
                occupied_start: allocation.occupied_start,
                occupied_end: allocation.occupied_end,
            })
        })
        .collect()
}

/// Add the offering-wide duplicate fact that a time-bounded capacity snapshot
/// may omit. The existing supply lock serializes this read with every writer
/// for the offering's frozen supply. The bounded lookup covers both the
/// logical claim's primary offering and its indexed allocation rows, so a
/// secondary bundle line remains a duplicate fact when it is later requested
/// as either a primary or secondary line.
///
/// A booking counts while its own time has not passed. The guard is there so
/// one party holds one live booking per offering, and a booking that has
/// already happened is not one: there is no completion transition, and
/// cancellation closes at the cutoff, so an elapsed booking counted here would
/// refuse that party the offering permanently.
async fn include_active_duplicate(
    transaction: &deadpool_postgres::Transaction<'_>,
    snapshot: &mut LedgerSnapshot,
    offering: &registry_scheduling_core::OfferingPolicy,
    duplicate_key: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    if offering.duplicate_active_key.is_none() {
        return Ok(());
    }
    let Some(duplicate_key) = duplicate_key else {
        return Ok(());
    };
    include_active_duplicates_for_offerings(
        transaction,
        snapshot,
        std::slice::from_ref(&offering.id),
        duplicate_key,
        now,
    )
    .await
}

/// Add the offering-wide duplicate facts for every keyed line in one bundle.
///
/// A bundle stores one logical claim whose top-level offering is the primary
/// line. Additional line offerings live on allocation rows, so the global
/// lookup must consider both places. Duplicate-only snapshot rows use an
/// internal resource name outside the published candidate set: they inform
/// the pure duplicate check without counting physical capacity a second time.
async fn include_bundle_active_duplicates(
    transaction: &deadpool_postgres::Transaction<'_>,
    snapshot: &mut LedgerSnapshot,
    lines: &[BundleSupplyLine<'_>],
    duplicate_key: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let Some(duplicate_key) = duplicate_key else {
        return Ok(());
    };
    let mut offerings = lines
        .iter()
        .filter(|line| line.offering.duplicate_active_key.is_some())
        .map(|line| line.offering.id.clone())
        .collect::<Vec<_>>();
    offerings.sort();
    offerings.dedup();
    if offerings.is_empty() {
        return Ok(());
    }
    include_active_duplicates_for_offerings(transaction, snapshot, &offerings, duplicate_key, now)
        .await
}

async fn include_active_duplicates_for_offerings(
    transaction: &deadpool_postgres::Transaction<'_>,
    snapshot: &mut LedgerSnapshot,
    offerings: &[String],
    duplicate_key: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let limit =
        i64::try_from(MAXIMUM_CAPACITY_SNAPSHOT_ROWS + 1).map_err(|_| StoreError::Corrupt)?;
    let rows = transaction
        .query(
            "SELECT DISTINCT ON (claim_id,offering) \
               claim_id,offering,occupied_start,occupied_end,duplicate_key,hold_expires_at \
             FROM ( \
               SELECT c.claim_id,c.offering,c.occupied_start,c.occupied_end, \
                      c.duplicate_key,c.hold_expires_at \
               FROM scheduling_claims AS c \
               WHERE c.state='active' AND c.kind='booking' \
                 AND c.offering=ANY($1) AND c.duplicate_key=$2 AND c.occupied_end > $3 \
               UNION ALL \
               SELECT c.claim_id,a.offering,a.occupied_start,a.occupied_end, \
                      c.duplicate_key,c.hold_expires_at \
               FROM scheduling_claims AS c \
               JOIN scheduling_claim_allocations AS a ON a.claim_id=c.claim_id \
               WHERE c.state='active' AND c.kind='booking' \
                 AND a.offering=ANY($1) AND c.duplicate_key=$2 AND a.occupied_end > $3 \
             ) AS matched \
             ORDER BY claim_id,offering,occupied_end DESC LIMIT $4",
            &[&offerings, &duplicate_key, &now, &limit],
        )
        .await?;
    for row in rows {
        let id = row.get::<_, Uuid>(0).to_string();
        let offering: String = row.get(1);
        if snapshot
            .claims
            .iter()
            .any(|existing| existing.id == id && existing.offering == offering)
        {
            continue;
        }
        if snapshot.claims.len() >= MAXIMUM_CAPACITY_SNAPSHOT_ROWS {
            return Err(StoreError::CapacitySnapshotTooLarge);
        }
        snapshot.claims.push(LedgerClaim {
            id,
            supply_id: format!("duplicate-only:{offering}"),
            offering,
            kind: LedgerKind::Booking,
            channel: None,
            start: row.get(2),
            end: row.get(3),
            units: 1,
            duplicate_key: row.get(4),
            expires_at: row.get(5),
        });
    }
    Ok(())
}

/// The task-grant re-check at the door of the transaction: a request whose
/// grant already lapsed fails before any lock is taken.
fn check_grant_current(commitment: &Commitment<'_>) -> Result<(), CommitError> {
    check_grant_current_at(commitment, commitment.now)
}

/// The same expiry rule against an explicitly supplied observation of now,
/// which is how the store re-checks it at decision time.
fn check_grant_current_at(
    commitment: &Commitment<'_>,
    now: DateTime<Utc>,
) -> Result<(), CommitError> {
    match commitment.grant_exp_unix {
        Some(exp) if now.timestamp() < i64::try_from(exp).unwrap_or(i64::MAX) => Ok(()),
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
            open,
            closures,
        } => evaluate_window_admission(
            &registry_scheduling_core::WindowContext {
                offering,
                window,
                open,
                closures,
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
        offering: hold.offering.clone(),
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

/// The revision guard and its transaction-wide share lock.
///
/// A commitment may only land under the policy revision this process
/// actually evaluated and the records revision the request actually
/// resolved. The stored revisions are the deployment's current truth: a
/// policy published by another process, or a records swap another operator
/// wrote, makes the caller's whole evaluation stale, and the commitment is
/// refused rather than stamped with a revision whose rules it never saw.
/// The share lock holds both revisions still for the life of the transaction,
/// so they cannot move again between the guard and the commit. Exact and
/// arrival commitments take it after their supply anchor, matching records
/// publication's supply-then-meta order.
async fn guard_revisions(
    transaction: &deadpool_postgres::Transaction<'_>,
    commitment: &Commitment<'_>,
) -> Result<(), CommitError> {
    let row = transaction
        .query_one(
            "SELECT policy_revision, facts_revision FROM scheduling_meta WHERE singleton FOR SHARE",
            &[],
        )
        .await?;
    let current_policy: i64 = row.get(0);
    let current_facts: i64 = row.get(1);
    if current_policy != commitment.policy_revision {
        return Err(AdmissionRefusal::PolicyChanged.into());
    }
    if current_facts != commitment.facts_revision {
        return Err(CommitError::FactsStale);
    }
    Ok(())
}

/// The current schema of a connection, refused unless it is a plain
/// lower-case identifier that statements may name without quoting.
async fn current_schema_in(
    client: &impl tokio_postgres::GenericClient,
) -> Result<String, StoreError> {
    let schema: Option<String> = client
        .query_one("SELECT current_schema()", &[])
        .await?
        .get(0);
    let schema = schema.ok_or(StoreError::Corrupt)?;
    let valid = !schema.is_empty()
        && schema.len() <= 63
        && schema
            .bytes()
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_lowercase())
        && schema
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if valid {
        Ok(schema)
    } else {
        Err(StoreError::Corrupt)
    }
}

/// Take the policy publication locks in the store's documented order: every
/// existing supply anchor, in identifier order, and then the meta row.
/// Capacity transactions take one anchor and then the meta row, so no
/// commitment can land between a publication's impact assessment and its
/// write.
async fn lock_publication(
    transaction: &deadpool_postgres::Transaction<'_>,
) -> Result<(), StoreError> {
    transaction
        .execute(
            "SELECT supply_id FROM scheduling_supply ORDER BY supply_id FOR UPDATE",
            &[],
        )
        .await?;
    transaction
        .execute(
            "SELECT 1 FROM scheduling_meta WHERE singleton FOR UPDATE",
            &[],
        )
        .await?;
    Ok(())
}

/// What publishing a policy would do, decided against the deployed state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPublication {
    /// The policy revision and digest the database serves now. An empty
    /// digest is a database no policy has been published to.
    pub stored_revision: i64,
    pub stored_digest: String,
    /// The candidate's digest.
    pub policy_digest: String,
    /// Whether publishing advances the policy revision: the digest changed.
    pub advances: bool,
}

impl PolicyPublication {
    /// The revision the candidate is served under once published.
    #[must_use]
    pub fn revision(&self) -> i64 {
        if self.advances {
            self.stored_revision + 1
        } else {
            self.stored_revision
        }
    }
}

/// Prove a candidate policy may be published: it contradicts none of the
/// deployed window records, and every offering with standing commitments
/// keeps its service, location, mode, and supply. The check reads and never
/// writes, so a read-only transaction may run it; a publishing transaction
/// runs it after [`lock_publication`], so nothing it read can move before the
/// write.
async fn check_policy_publication(
    transaction: &deadpool_postgres::Transaction<'_>,
    now: DateTime<Utc>,
    policy: &SchedulingPolicy,
) -> Result<PolicyPublication, StoreError> {
    let policy_digest = policy.policy_digest();
    let row = transaction
        .query_one(
            "SELECT policy_revision, policy_digest FROM scheduling_meta WHERE singleton",
            &[],
        )
        .await?;
    // The candidate policy answers for the window records this deployment
    // already holds.
    refuse_combined_conflicts(policy, &deployed_windows(transaction).await?)?;
    let stored_revision = row.get::<_, i64>(0);
    let stored_digest = row.get::<_, String>(1);
    if stored_digest != policy_digest && !stored_digest.is_empty() {
        let current_document: Option<Value> = transaction
            .query_opt(
                "SELECT policy_document FROM scheduling_policy_revisions \
                 WHERE policy_revision=$1 AND policy_digest=$2",
                &[&stored_revision, &stored_digest],
            )
            .await?
            .and_then(|stored| stored.get(0));
        let Some(current_document) = current_document else {
            return Err(StoreError::PolicyInUse(
                "the current policy document is unavailable; restore its verified backup before publishing a change"
                    .to_owned(),
            ));
        };
        // The historical document and digest are preserved as they were
        // published; only the lifecycle terms governed by the current policy
        // shape are compared.
        let current = retained_policy(current_document)?;
        let active_offerings = transaction
            .query(
                "SELECT offering FROM ( \
                   SELECT c.offering FROM scheduling_claims AS c \
                   WHERE c.state='active' \
                     AND (c.kind IN ('booking','window') OR (c.kind='hold' AND c.hold_expires_at > $1)) \
                   UNION \
                   SELECT a.offering FROM scheduling_claim_allocations AS a \
                   JOIN scheduling_claims AS c ON c.claim_id=a.claim_id \
                   WHERE c.state='active' \
                     AND (c.kind IN ('booking','window') OR (c.kind='hold' AND c.hold_expires_at > $1)) \
                 ) active_offerings ORDER BY offering",
                &[&now],
            )
            .await?;
        for active in active_offerings {
            let offering_id: String = active.get(0);
            let Some(current_offering) = current.offering(&offering_id) else {
                return Err(StoreError::PolicyInUse(format!(
                    "offering {offering_id} has active commitments but is absent from the retained current policy"
                )));
            };
            let retained = policy.offering(&offering_id).is_some_and(|proposed| {
                let same_supply = match (
                    &current_offering.exact_time,
                    &proposed.exact_time,
                    &current_offering.arrival,
                    &proposed.arrival,
                ) {
                    (Some(current), Some(next), None, None) => current.pool == next.pool,
                    (None, None, Some(current), Some(next)) => current.window == next.window,
                    _ => false,
                };
                proposed.service == current_offering.service
                    && proposed.location == current_offering.location
                    && proposed.mode == current_offering.mode
                    && same_supply
            });
            if !retained {
                return Err(StoreError::PolicyInUse(format!(
                    "offering {offering_id} has active commitments and must retain its service, location, mode, and supply"
                )));
            }
        }
    }
    Ok(PolicyPublication {
        advances: stored_digest != policy_digest,
        stored_revision,
        stored_digest,
        policy_digest,
    })
}

/// Publish a checked policy: a changed digest takes the next revision, the
/// same digest retains its revision, and every pool the policy's offerings
/// name is anchored. The caller holds the publication locks.
async fn publish_policy(
    transaction: &deadpool_postgres::Transaction<'_>,
    publication: &PolicyPublication,
    policy: &SchedulingPolicy,
    pool_ids: &[String],
) -> Result<i64, StoreError> {
    let policy_document = serde_json::to_value(policy).map_err(|_| StoreError::Corrupt)?;
    let revision = publication.revision();
    if publication.advances {
        transaction
            .execute(
                "INSERT INTO scheduling_policy_revisions(\
                 policy_revision, policy_digest, policy_document) VALUES($1,$2,$3)",
                &[&revision, &publication.policy_digest, &policy_document],
            )
            .await?;
        transaction
            .execute(
                "UPDATE scheduling_meta SET policy_revision=$1, policy_digest=$2, \
                 updated_at=now() WHERE singleton",
                &[&revision, &publication.policy_digest],
            )
            .await?;
    }
    for id in pool_ids {
        anchor_supply(transaction, id, "pool").await?;
    }
    Ok(revision)
}

/// Read a retained policy document without reinterpreting its stored members.
fn retained_policy(document: Value) -> Result<SchedulingPolicy, StoreError> {
    serde_json::from_value(document).map_err(|_| StoreError::Corrupt)
}

/// The combined policy-by-records contradictions a database write refuses.
///
/// `SchedulingPolicy::check_window_records` stays the single implementation
/// of the rules; this narrows its findings to the ones that are a genuine
/// disagreement between the two sides. Two of its reasons name an absence
/// instead:
///
/// - `UnknownWindow` is a policy that references a window the deployment has
///   not published yet. That is the ordinary bootstrap order, and the runtime
///   already refuses each admission on such an offering loudly, so a write
///   must not be held hostage to it.
/// - `UnknownOffering` is a deployed window whose offering this publication
///   retires. Refusing it would make an arrival offering impossible to
///   withdraw, since the window records could only be removed afterwards.
///   A window resource requirement's offering is no exception: the
///   reservation the window holds through it is an active commitment, so the
///   publication is refused as `PolicyInUse` instead, and a records apply
///   that reserves through an unknown offering is refused when it reserves.
///
/// Everything that remains is a statement one side makes that the other
/// contradicts, and no ordering of the two writes makes it safe. In
/// particular `SharedSupplyUnpartitioned`, where a pool staffs a window and
/// also backs an exact-time offering: the two modes lock different anchors,
/// so their capacity transactions never serialize and the ledger cannot see
/// that it sold the same people twice.
fn combined_conflicts(
    policy: &SchedulingPolicy,
    windows: &[PublishedWindow],
) -> Vec<SchedulingDiagnostic> {
    policy
        .check_window_records(windows)
        .into_iter()
        .filter(|finding| {
            !matches!(
                finding.reason,
                PolicyCheckReason::UnknownWindow | PolicyCheckReason::UnknownOffering
            )
        })
        .collect()
}

/// Anchor one supply identifier under the kind that claims it.
///
/// The pool anchors and the window anchors are written by two independent
/// publish paths into one table keyed by the identifier, and the two
/// namespaces are authored separately. Both paths write it through here, so
/// an identifier the other kind already holds is refused by name at the
/// second of them rather than aborting the transaction on the primary key or
/// silently leaving the other kind's row standing. A row of the same kind is
/// left exactly as it is: republishing a policy re-anchors its pools, and
/// that is a no-op, not a conflict.
async fn anchor_supply(
    transaction: &deadpool_postgres::Transaction<'_>,
    supply_id: &str,
    kind: &str,
) -> Result<(), StoreError> {
    let anchored: String = transaction
        .query_one(
            "INSERT INTO scheduling_supply(supply_id, kind) VALUES($1,$2) \
             ON CONFLICT(supply_id) DO UPDATE SET kind=scheduling_supply.kind \
             RETURNING kind",
            &[&supply_id, &kind],
        )
        .await?
        .get(0);
    if anchored != kind {
        return Err(StoreError::SupplyIdentifierCollision(format!(
            "{supply_id} already anchors {anchored} supply and cannot also anchor a {kind}"
        )));
    }
    Ok(())
}

/// The window records the deployment currently holds, in identifier order.
async fn deployed_windows(
    transaction: &deadpool_postgres::Transaction<'_>,
) -> Result<Vec<PublishedWindow>, StoreError> {
    transaction
        .query(
            "SELECT window_record FROM scheduling_windows ORDER BY window_id",
            &[],
        )
        .await?
        .iter()
        .map(|row| {
            serde_json::from_value::<PublishedWindow>(row.get(0)).map_err(|_| StoreError::Corrupt)
        })
        .collect()
}

/// The refusal carrying every contradiction, or `Ok(())` when there is none.
fn refuse_combined_conflicts(
    policy: &SchedulingPolicy,
    windows: &[PublishedWindow],
) -> Result<(), StoreError> {
    let conflicts = combined_conflicts(policy, windows);
    if conflicts.is_empty() {
        return Ok(());
    }
    Err(StoreError::CombinedInvariant(
        conflicts
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    ))
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
             FROM scheduling_attempts WHERE key_reference=$1",
            &[&commitment.key_reference(scope)],
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
    let claim_id = if let Some(claim) = receipt.get("claim") {
        Some(
            claim
                .get("claimId")
                .and_then(Value::as_str)
                .and_then(|id| Uuid::parse_str(id).ok())
                .ok_or(StoreError::Corrupt)?,
        )
    } else if receipt.is_null() {
        // Hold release answers 204 without a body. Its internal scope binds
        // the claim, including when refusal recording reconciles a replay.
        scope
            .strip_prefix("hold:")
            .and_then(|id| id.strip_suffix(":release"))
            .map(|id| Uuid::parse_str(id).map_err(|_| StoreError::Corrupt))
            .transpose()?
    } else {
        None
    };
    if let Some(claim_id) = claim_id {
        let owned = transaction
            .claim_in_transaction(claim_id)
            .await?
            .is_some_and(|claim| {
                claim.is_owned_by(commitment.actor_issuer, commitment.actor_subject)
            });
        if !owned {
            return Ok(Some(ReplayOutcome::Refused(CommitError::Unauthorized)));
        }
    }
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
        let minutes = reminder.offset_minutes;
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
                "INSERT INTO scheduling_outbox(outbox_id, purpose, generation, state, \
                 attempt, next_attempt_at, claim_id, appointment_revision, due_at, payload) \
                 VALUES($1,'reminder',1,'pending',0,$4,$2,$3,$4,$5)",
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

/// The durable success receipt retains every value the public projection
/// cannot recover from a claim alone. In particular, whether `supply_id` was
/// a pool member must survive a later policy mode change or removal.
fn claim_receipt(
    kind: &str,
    claim: &ClaimRow,
    resource_is_member: bool,
    policy_revision: i64,
) -> Value {
    json!({
        "kind": kind,
        "claim": claim,
        "resource": resource_is_member.then(|| claim.supply_id.clone()),
        "manager": claim.source_manager.as_ref().map(|_| "schedulingManager"),
        "policyRevision": policy_revision,
    })
}

pub(crate) async fn replace_facts_in_transaction(
    transaction: &deadpool_postgres::Transaction<'_>,
    scheduling_id: &str,
    facts: &SchedulingFacts,
    expected: Option<&ActivePackage<'_>>,
    busy_source_bindings: &std::collections::BTreeMap<String, Vec<String>>,
) -> Result<(), StoreError> {
    if facts
        .pools
        .iter()
        .flat_map(|pool| &pool.members)
        .any(|member| {
            member
                .availability
                .as_ref()
                .is_some_and(|availability| !availability.is_valid())
        })
    {
        return Err(StoreError::CombinedInvariant(
            "resource availability requires at most 256 positive intervals per list, each spanning at most 3650 days".to_owned(),
        ));
    }
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
    let meta = transaction
        .query_one(
            "SELECT scheduling_id, policy_revision, policy_digest FROM scheduling_meta \
             WHERE singleton FOR UPDATE",
            &[],
        )
        .await?;
    if let Some(expected) = expected {
        check_active_package_in(&**transaction, expected).await?;
    }
    if meta.get::<_, String>(0) != scheduling_id {
        return Err(StoreError::DeploymentIdentity);
    }
    // The incoming records answer to the policy deployed now, the same pair
    // the authoring tool checks together offline. An empty digest is a
    // deployment whose records are being seeded before any policy exists,
    // and there is nothing yet for them to contradict.
    let policy_digest: String = meta.get(2);
    let policy_revision: i64 = meta.get(1);
    let deployed_policy = if policy_digest.is_empty() {
        None
    } else {
        let document: Option<Value> = transaction
            .query_opt(
                "SELECT policy_document FROM scheduling_policy_revisions \
                 WHERE policy_revision=$1 AND policy_digest=$2",
                &[&policy_revision, &policy_digest],
            )
            .await?
            .and_then(|stored| stored.get(0));
        let Some(document) = document else {
            return Err(StoreError::CombinedInvariant(
                "the deployed policy document is unavailable; restore its verified backup before replacing the records"
                    .to_owned(),
            ));
        };
        let policy = retained_policy(document)?;
        refuse_combined_conflicts(&policy, &facts.windows)?;
        Some(policy)
    };
    let occupied = occupied_resources_changed_by(transaction, facts).await?;
    if !occupied.is_empty() {
        return Err(StoreError::FactsInUse(occupied.join(", ")));
    }
    let current_windows = deployed_windows(transaction).await?;
    let revision_heads = transaction
        .query(
            "SELECT window_id, window_record FROM scheduling_window_revision_heads ORDER BY window_id",
            &[],
        )
        .await?
        .iter()
        .map(|row| {
            let window_id: String = row.get(0);
            let window = serde_json::from_value::<registry_scheduling_core::PublishedWindow>(
                row.get(1),
            )
            .map_err(|_| StoreError::Corrupt)?;
            if window.id != window_id {
                return Err(StoreError::Corrupt);
            }
            Ok(window)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for proposed in &facts.windows {
        let Some(current) = revision_heads
            .iter()
            .find(|current| current.id == proposed.id)
        else {
            continue;
        };
        if proposed != current && proposed.revision <= current.revision {
            return Err(StoreError::WindowRevision {
                window: proposed.id.clone(),
                current: current.revision,
                proposed: proposed.revision,
            });
        }
    }
    let now = Utc::now();
    let rows = transaction
        .query(
            "SELECT c.claim_id, c.offering, c.supply_id, c.kind, c.channel, \
             c.occupied_start, c.occupied_end, c.units, c.duplicate_key, c.hold_expires_at \
             FROM scheduling_claims AS c \
             JOIN scheduling_supply AS s ON s.supply_id=c.supply_id \
             WHERE s.kind='window' AND c.state='active' \
               AND (c.kind='booking' OR (c.kind='hold' AND c.hold_expires_at > $1)) \
             ORDER BY c.occupied_start",
            &[&now],
        )
        .await?;
    let reductions = assess_window_record_impact(
        &current_windows,
        &facts.windows,
        &snapshot_from_rows(rows),
        now,
    );
    if !reductions.is_empty() {
        let details = reductions
            .iter()
            .map(|reduction| {
                format!(
                    "{}:{} has {} committed units but proposes {}",
                    reduction.window,
                    reduction
                        .channel
                        .map_or("total", |channel| channel.as_str()),
                    reduction.committed_units,
                    reduction.proposed_units
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(StoreError::FactsInUse(details));
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
    transaction
        .execute("DELETE FROM scheduling_windows", &[])
        .await?;
    transaction
        .execute("DELETE FROM scheduling_supply WHERE kind='window'", &[])
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
            let availability = member
                .availability
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| StoreError::Corrupt)?;
            transaction
                .execute(
                    "INSERT INTO scheduling_pool_members(resource_id, pool_id, capabilities, \
                     available, capacity_units, availability) VALUES($1,$2,$3,$4,$5,$6)",
                    &[
                        &member.resource_id,
                        &pool.id,
                        &member.capabilities,
                        &member.available,
                        &i32::try_from(member.capacity_units).map_err(|_| StoreError::Corrupt)?,
                        &availability,
                    ],
                )
                .await?;
        }
    }
    for window in &facts.windows {
        let record = serde_json::to_value(window).map_err(|_| StoreError::Corrupt)?;
        transaction
            .execute(
                "INSERT INTO scheduling_windows(window_id, window_record) VALUES($1,$2)",
                &[&window.id, &record],
            )
            .await?;
        anchor_supply(transaction, &window.id, "window").await?;
        transaction
            .execute(
                "INSERT INTO scheduling_window_revision_heads(window_id, window_record, updated_at) \
                 VALUES($1,$2,now()) \
                 ON CONFLICT(window_id) DO UPDATE SET window_record=EXCLUDED.window_record, \
                 updated_at=EXCLUDED.updated_at",
                &[&window.id, &record],
            )
            .await?;
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
    replace_window_resource_claims(
        transaction,
        facts,
        &revision_heads,
        deployed_policy.as_ref(),
        policy_revision,
        now,
        busy_source_bindings,
    )
    .await?;
    // The records revision moves last, inside the same transaction that
    // holds every supply anchor: a capacity transaction that acquires its
    // anchor after this commit reads the new revision and refuses to
    // evaluate against the resolved-before facts it carried in.
    transaction
        .execute(
            "UPDATE scheduling_meta SET facts_revision = facts_revision + 1, \
             updated_at=now() WHERE singleton",
            &[],
        )
        .await?;
    Ok(())
}

struct ResolvedParentRequirement<'a> {
    offering: &'a registry_scheduling_core::OfferingPolicy,
    exact: &'a registry_scheduling_core::ExactTimeOffering,
    members: &'a [PoolMember],
    open: Vec<CalendarInterval>,
    closures: Vec<CalendarInterval>,
    resource: Option<&'a str>,
    units: u32,
}

/// One physical requirement a parent claim reserves for a whole published
/// window.
struct ParentRequirement<'a> {
    requirement: &'a str,
    offering: &'a str,
    resource: Option<&'a str>,
    units: u32,
}

/// A parent claim and the span and requirements it reserves once on behalf
/// of every booking it serves. `subject` names it in refusals.
struct ParentReservation<'a> {
    claim_id: Uuid,
    subject: String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    requirements: &'a [ParentRequirement<'a>],
}

/// Reserve a parent's physical requirements through the claim-allocation
/// ledger, under the same supply locks and evaluator as an exact-time bundle,
/// replacing whatever the parent held before.
async fn replace_parent_allocations(
    transaction: &deadpool_postgres::Transaction<'_>,
    parent: &ParentReservation<'_>,
    facts: &SchedulingFacts,
    policy: &SchedulingPolicy,
    policy_revision: i64,
    now: DateTime<Utc>,
    busy_source_bindings: &std::collections::BTreeMap<String, Vec<String>>,
) -> Result<(), StoreError> {
    let subject = &parent.subject;
    let duration_seconds = parent.end.signed_duration_since(parent.start).num_seconds();
    if duration_seconds <= 0 || duration_seconds % 60 != 0 {
        return Err(StoreError::CombinedInvariant(format!(
            "{subject} must span whole positive minutes"
        )));
    }
    let duration_minutes = u32::try_from(duration_seconds / 60).map_err(|_| StoreError::Corrupt)?;
    let mut resolved = Vec::with_capacity(parent.requirements.len());
    for requirement in parent.requirements {
        let offering = policy.offering(requirement.offering).ok_or_else(|| {
            StoreError::CombinedInvariant(format!(
                "{subject} requirement {} names unknown offering {}",
                requirement.requirement, requirement.offering
            ))
        })?;
        let exact = offering.exact_time.as_ref().ok_or_else(|| {
            StoreError::CombinedInvariant(format!(
                "{subject} requirement {} is not exact-time",
                requirement.requirement
            ))
        })?;
        let pool = facts.pool(&exact.pool).ok_or_else(|| {
            StoreError::CombinedInvariant(format!(
                "{subject} requirement {} names unavailable pool {}",
                requirement.requirement, exact.pool
            ))
        })?;
        let location = facts.location(&offering.location).ok_or_else(|| {
            StoreError::CombinedInvariant(format!(
                "{subject} requirement {} names unavailable location {}",
                requirement.requirement, offering.location
            ))
        })?;
        let exceptions = facts
            .exceptions
            .iter()
            .filter(|exception| exception.location == offering.location)
            .map(|exception| exception.borrowed())
            .collect::<Vec<_>>();
        let open =
            location_open_intervals(policy, &offering.location, &location.timezone, &exceptions)
                .map_err(|error| StoreError::CombinedInvariant(error.to_string()))?;
        let closures = location_closure_intervals(facts, &offering.location, &location.timezone)
            .map_err(|error| StoreError::CombinedInvariant(error.to_string()))?;
        resolved.push(ResolvedParentRequirement {
            offering,
            exact,
            members: &pool.members,
            open,
            closures,
            resource: requirement.resource,
            units: requirement.units,
        });
    }
    let lines = resolved
        .iter()
        .enumerate()
        .map(|(index, line)| BundleSupplyLine {
            requirement_id: if index == 0 {
                "primary".to_owned()
            } else {
                format!("additional:{}", index - 1)
            },
            offering: line.offering,
            exact: line.exact,
            members: line.members,
            open: &line.open,
            closures: &line.closures,
            resource: line.resource,
            stored_resource: true,
            units: line.units,
        })
        .collect::<Vec<_>>();
    let primary = resolved.first().ok_or(StoreError::Corrupt)?;
    let request = registry_scheduling_core::AdmissionRequest {
        offering: primary.offering.id.clone(),
        start: parent.start,
        duration_minutes: Some(duration_minutes),
        resource: primary.resource.map(str::to_owned),
        resource_units: primary.units,
        additional_allocations: resolved
            .iter()
            .skip(1)
            .map(|line| AdditionalAllocationRequest {
                offering: line.offering.id.clone(),
                resource: line.resource.map(str::to_owned),
                units: line.units,
            })
            .collect(),
        party: None,
        manager: None,
        channel: None,
        duplicate_key: None,
        policy_revision: u64::try_from(policy_revision).map_err(|_| StoreError::Corrupt)?,
        window_revision: None,
        capabilities: Vec::new(),
        prerequisites: Vec::new(),
        external_references: Vec::new(),
        party_references: Vec::new(),
    };
    let mut snapshot = lock_bundle_and_snapshot(
        transaction,
        &lines,
        &request,
        now,
        &[],
        busy_source_bindings,
    )
    .await
    .map_err(|error| {
        StoreError::FactsInUse(format!("{subject} physical allocation refused: {error}"))
    })?;
    // The parent may already own allocations while its safe source
    // revision is being replaced. Exclude only that stable parent claim.
    let parent_id = parent.claim_id.to_string();
    snapshot.claims.retain(|claim| claim.id != parent_id);
    let contexts = lines
        .iter()
        .map(|line| ExactTimeBundleLineContext {
            requirement_id: line.requirement_id.clone(),
            offering: line.offering,
            exact: line.exact,
            members: line.members,
            open: line.open,
            closures: line.closures,
            resource: line.resource,
            stored_resource: line.stored_resource,
            units: line.units,
        })
        .collect::<Vec<_>>();
    let physical = evaluate_exact_time_physical_bundle(
        &ExactTimeBundleContext {
            lines: &contexts,
            snapshot: &snapshot,
            policy_revision: u64::try_from(policy_revision).map_err(|_| StoreError::Corrupt)?,
            now,
            exclude_reservation: Some(&parent_id),
            confirming_hold: false,
            limits: AllocationLimits {
                maximum_requirements: registry_scheduling_core::MAXIMUM_ALLOCATION_REQUIREMENTS,
                maximum_units_per_requirement: registry_scheduling_core::MAXIMUM_RESOURCE_UNITS,
                maximum_candidate_resources: 4_096,
                maximum_standing_allocations: MAXIMUM_CAPACITY_SNAPSHOT_ROWS,
            },
        },
        parent.start,
        duration_minutes,
    );
    let admission = match physical {
        Ok(admission) => admission,
        Err(BundleEvaluationError::Allocation(AllocationError::SnapshotTooLarge { .. })) => {
            return Err(StoreError::CapacitySnapshotTooLarge)
        }
        Err(error) => {
            return Err(StoreError::FactsInUse(format!(
                "{subject} physical allocation refused: {error}"
            )))
        }
    };
    let stored = stored_bundle_allocations(&admission, &lines)?;
    transaction
        .replace_claim_allocations(parent.claim_id, &stored)
        .await
}

/// Reserve each published window's physical `resources` once, through one
/// parent claim per window that every booking in the window shares. Bookings
/// carry only units; the parent carries the room, facilitator, or equipment,
/// so its allocations conflict with exact bookings and other parents under
/// the same supply locks. A parent is recomputed only when its window record
/// changed, so an unchanged window keeps what it holds across policy
/// publications and records applies alike, as an exact booking keeps its
/// allocations, and every parent that moves or goes away releases its
/// allocations before any other parent reserves.
#[allow(clippy::too_many_arguments)]
async fn replace_window_resource_claims(
    transaction: &deadpool_postgres::Transaction<'_>,
    facts: &SchedulingFacts,
    prior_records: &[PublishedWindow],
    policy: Option<&SchedulingPolicy>,
    policy_revision: i64,
    now: DateTime<Utc>,
    busy_source_bindings: &std::collections::BTreeMap<String, Vec<String>>,
) -> Result<(), StoreError> {
    let existing = transaction
        .query(
            "SELECT supply_id, claim_id FROM scheduling_claims \
             WHERE kind='window' ORDER BY supply_id",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, Uuid>(1)))
        .collect::<std::collections::BTreeMap<_, _>>();
    for (window_id, claim_id) in &existing {
        let reserves = facts
            .windows
            .iter()
            .any(|window| &window.id == window_id && !window.resources.is_empty());
        if reserves {
            continue;
        }
        transaction
            .replace_claim_allocations(*claim_id, &[])
            .await?;
        transaction
            .execute(
                "DELETE FROM scheduling_claims WHERE claim_id=$1 AND kind='window'",
                &[claim_id],
            )
            .await?;
    }
    let mut changed = Vec::new();
    for window in facts
        .windows
        .iter()
        .filter(|window| !window.resources.is_empty())
    {
        let policy = policy.ok_or_else(|| {
            StoreError::CombinedInvariant("window resources require a deployed policy".to_owned())
        })?;
        let offering = policy.offering(&window.offering).ok_or_else(|| {
            StoreError::CombinedInvariant(format!(
                "window {} reserves resources for unknown offering {}",
                window.id, window.offering
            ))
        })?;
        let prior = existing.get(&window.id);
        let unchanged = prior.is_some() && prior_records.iter().any(|record| record == window);
        let claim_id = prior.copied().unwrap_or_else(Uuid::new_v4);
        let revision = i64::try_from(window.revision).map_err(|_| StoreError::Corrupt)?;
        let written = transaction
            .execute(
                "INSERT INTO scheduling_claims( \
                    claim_id, kind, state, offering, operational_scope_version, \
                    operational_service, operational_location, operational_mode, supply_id, \
                    displayed_start, displayed_end, occupied_start, occupied_end, units, revision, \
                    policy_revision, actor, external_references, party_references) \
                 VALUES($1,'window','active',$2,1,$3,$4,'arrival-window',$5,$6,$7,$6,$7,1,$8,$9,'records','[]','[]') \
                 ON CONFLICT(claim_id) DO UPDATE SET offering=EXCLUDED.offering, \
                    operational_service=EXCLUDED.operational_service, \
                    operational_location=EXCLUDED.operational_location, \
                    displayed_start=EXCLUDED.displayed_start, displayed_end=EXCLUDED.displayed_end, \
                    occupied_start=EXCLUDED.occupied_start, occupied_end=EXCLUDED.occupied_end, \
                    revision=EXCLUDED.revision, policy_revision=EXCLUDED.policy_revision, \
                    changed_at=now() \
                 WHERE scheduling_claims.kind='window' \
                   AND scheduling_claims.supply_id=EXCLUDED.supply_id",
                &[
                    &claim_id,
                    &window.offering,
                    &offering.service,
                    &offering.location,
                    &window.id,
                    &window.start,
                    &window.end,
                    &revision,
                    &policy_revision,
                ],
            )
            .await?;
        if written != 1 {
            return Err(StoreError::Corrupt);
        }
        if !unchanged {
            transaction.replace_claim_allocations(claim_id, &[]).await?;
            changed.push((claim_id, window));
        }
    }
    let Some(policy) = policy else {
        return Ok(());
    };
    for (claim_id, window) in changed {
        let requirements = window
            .resources
            .iter()
            .map(|requirement| ParentRequirement {
                requirement: &requirement.requirement,
                offering: &requirement.offering,
                resource: requirement.resource.as_deref(),
                units: requirement.units,
            })
            .collect::<Vec<_>>();
        replace_parent_allocations(
            transaction,
            &ParentReservation {
                claim_id,
                subject: format!("window {}", window.id),
                start: window.start,
                end: window.end,
                requirements: &requirements,
            },
            facts,
            policy,
            policy_revision,
            now,
            busy_source_bindings,
        )
        .await?;
    }
    Ok(())
}

/// The currently known resources live allocations occupy that the incoming
/// records move between pools. Physical loss is representable: removing a
/// member leaves its child allocation intact, reports a current shortage, and
/// blocks new use until stock returns. Moving a present member would instead
/// change which independently locked pool sells it, so remains refused.
async fn occupied_resources_changed_by(
    transaction: &deadpool_postgres::Transaction<'_>,
    facts: &SchedulingFacts,
) -> Result<Vec<String>, StoreError> {
    let incoming: HashMap<&str, &str> = facts
        .pools
        .iter()
        .flat_map(|pool| {
            pool.members
                .iter()
                .map(move |member| (member.resource_id.as_str(), pool.id.as_str()))
        })
        .collect();
    let rows = transaction
        .query(
            "SELECT DISTINCT a.resource_id, m.pool_id FROM scheduling_claim_allocations AS a \
             JOIN scheduling_claims AS c ON c.claim_id = a.claim_id \
             JOIN scheduling_pool_members AS m ON m.resource_id = a.resource_id \
             WHERE c.state='active' \
               AND (c.kind IN ('booking','window') OR (c.kind='hold' AND c.hold_expires_at > now())) \
             ORDER BY a.resource_id",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let resource: String = row.get(0);
            let current_pool: String = row.get(1);
            match incoming.get(resource.as_str()) {
                Some(incoming_pool) if *incoming_pool == current_pool => None,
                Some(incoming_pool) => {
                    Some(format!("{resource} from {current_pool} to {incoming_pool}"))
                }
                None => None,
            }
        })
        .collect())
}

/// A claim about to be written.
struct NewClaim<'c> {
    claim_id: Uuid,
    kind: LedgerKind,
    state: ClaimState,
    offering: &'c str,
    operational_service: &'c str,
    operational_location: &'c str,
    operational_mode: registry_scheduling_core::SchedulingMode,
    supply_id: &'c str,
    channel: Option<&'c str>,
    displayed_start: DateTime<Utc>,
    displayed_end: DateTime<Utc>,
    occupied_start: DateTime<Utc>,
    occupied_end: DateTime<Utc>,
    units: i32,
    party: Option<PartyCounts>,
    party_references: &'c [PartyReference],
    source_manager: Option<&'c SourceBoundManager>,
    duplicate_key: Option<&'c str>,
    external_references: &'c [ExternalReference],
    hold_expires_at: Option<DateTime<Utc>>,
    revision: i64,
    policy_revision: i64,
    actor: &'c str,
    owner_issuer: &'c str,
    owner_subject: &'c str,
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
    channel: Option<&'c str>,
    units: i32,
    party: Option<PartyCounts>,
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
    async fn insert_claim_allocations(
        &self,
        claim_id: Uuid,
        allocations: &[NewClaimAllocation<'_>],
    ) -> Result<(), StoreError>;
    async fn replace_claim_allocations(
        &self,
        claim_id: Uuid,
        allocations: &[NewClaimAllocation<'_>],
    ) -> Result<(), StoreError>;
    async fn close_claim(
        &self,
        claim_id: Uuid,
        state: ClaimState,
        reason: Option<&str>,
        observed_revision: i64,
    ) -> Result<bool, StoreError>;
    /// Move an active booking to a new time or resource under the revision
    /// the mover observed. `false` means a concurrent writer changed the
    /// claim first and this transaction's whole decision is superseded.
    async fn move_claim(
        &self,
        movement: &ClaimMove<'_>,
        observed_revision: i64,
    ) -> Result<bool, StoreError>;
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
    /// Cancel the appointment's reminders no attempt has started on, so the
    /// dispatcher never claims them (INT-02).
    async fn cancel_unsent_reminders(&self, claim_id: Uuid) -> Result<(), StoreError>;
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
        issuer: &str,
        subject: &str,
        now: DateTime<Utc>,
    ) -> Result<i64, StoreError>;
}

#[async_trait::async_trait]
impl CapacityStatements for deadpool_postgres::Transaction<'_> {
    async fn lock_supply(&self, supply_ids: &[String]) -> Result<(), StoreError> {
        let rows = self
            .query(
                "SELECT supply_id FROM scheduling_supply WHERE supply_id = ANY($1) \
                 ORDER BY supply_id FOR UPDATE",
                &[&supply_ids],
            )
            .await?;
        if rows.len() != supply_ids.len() {
            let anchored: Vec<String> = rows.iter().map(|row| row.get(0)).collect();
            let missing: Vec<&str> = supply_ids
                .iter()
                .map(String::as_str)
                .filter(|wanted| !anchored.iter().any(|found| found == wanted))
                .collect();
            return Err(StoreError::UnanchoredSupply(missing.join(", ")));
        }
        Ok(())
    }

    async fn insert_claim(&self, claim: &NewClaim<'_>) -> Result<ClaimRow, StoreError> {
        let kind = match claim.kind {
            LedgerKind::Booking => "booking",
            LedgerKind::Hold => "hold",
            LedgerKind::Window => "window",
        };
        let recipient_count = claim
            .party
            .map(|party| i32::try_from(party.recipients))
            .transpose()
            .map_err(|_| StoreError::Corrupt)?;
        let attendee_count = claim
            .party
            .map(|party| i32::try_from(party.attendees))
            .transpose()
            .map_err(|_| StoreError::Corrupt)?;
        let row = self
            .query_one(
                "INSERT INTO scheduling_claims(claim_id, kind, state, offering, operational_scope_version, \
                 operational_service, operational_location, operational_mode, supply_id, \
                 channel, displayed_start, displayed_end, occupied_start, occupied_end, units, \
                 duplicate_key, external_references, hold_expires_at, revision, policy_revision, actor, reason, \
                 owner_issuer, owner_subject, recipient_count, attendee_count, party_references, \
                 manager_source_issuer, manager_subject) \
                 VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28) \
                 RETURNING created_at",
                &[
                    &claim.claim_id,
                    &kind,
                    &claim.state.as_str(),
                    &claim.offering,
                    &claim.operational_service,
                    &claim.operational_location,
                    &match claim.operational_mode {
                        registry_scheduling_core::SchedulingMode::ExactTime => "exact-time",
                        registry_scheduling_core::SchedulingMode::ArrivalWindow => "arrival-window",
                    },
                    &claim.supply_id,
                    &claim.channel,
                    &claim.displayed_start,
                    &claim.displayed_end,
                    &claim.occupied_start,
                    &claim.occupied_end,
                    &claim.units,
                    &claim.duplicate_key,
                    &serde_json::to_value(claim.external_references).map_err(|_| StoreError::Corrupt)?,
                    &claim.hold_expires_at,
                    &claim.revision,
                    &claim.policy_revision,
                    &claim.actor,
                    &claim.reason,
                    &claim.owner_issuer,
                    &claim.owner_subject,
                    &recipient_count,
                    &attendee_count,
                    &serde_json::to_value(claim.party_references)
                        .map_err(|_| StoreError::Corrupt)?,
                    &claim.source_manager.map(|manager| manager.source_issuer.as_str()),
                    &claim.source_manager.map(|manager| manager.subject.as_str()),
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
            allocations: Vec::new(),
            party: claim.party,
            party_references: claim.party_references.to_vec(),
            source_manager: claim.source_manager.cloned(),
            duplicate_key: claim.duplicate_key.map(str::to_owned),
            external_references: claim.external_references.to_vec(),
            hold_expires_at: claim.hold_expires_at,
            revision: claim.revision,
            policy_revision: claim.policy_revision,
            actor: claim.actor.to_owned(),
            reason: claim.reason.map(str::to_owned),
            created_at: row.get(0),
            closed_at: None,
            owner: Some(ClaimOwner {
                issuer: claim.owner_issuer.to_owned(),
                subject: claim.owner_subject.to_owned(),
            }),
        })
    }

    async fn insert_claim_allocations(
        &self,
        claim_id: Uuid,
        allocations: &[NewClaimAllocation<'_>],
    ) -> Result<(), StoreError> {
        let mut ordered = Vec::with_capacity(allocations.len());
        for allocation in allocations {
            let (kind, index) = if allocation.requirement == "primary" {
                ("primary", 0_i16)
            } else {
                let index = allocation
                    .requirement
                    .strip_prefix("additional:")
                    .and_then(|index| index.parse::<i16>().ok())
                    .ok_or(StoreError::Corrupt)?;
                ("additional", index)
            };
            ordered.push((kind, index, allocation));
        }
        ordered.sort_by(|left, right| {
            let left_requirement = (left.0 != "primary", left.1);
            let right_requirement = (right.0 != "primary", right.1);
            left_requirement
                .cmp(&right_requirement)
                .then_with(|| left.2.resource_id.cmp(right.2.resource_id))
        });
        let mut previous_requirement = None;
        let mut part_index = 0_i16;
        for (kind, index, allocation) in ordered {
            let requirement = (kind, index);
            if previous_requirement == Some(requirement) {
                part_index = part_index.checked_add(1).ok_or(StoreError::Corrupt)?;
            } else {
                previous_requirement = Some(requirement);
                part_index = 0;
            }
            self.execute(
                "INSERT INTO scheduling_claim_allocations( \
                 claim_id, requirement_kind, requirement_index, part_index, \
                 allocation_scope_version, offering, operational_service, operational_location, \
                 operational_mode, anchor_id, resource_id, occupied_start, occupied_end, units) \
                 VALUES($1,$2,$3,$4,1,$5,$6,$7,'exact-time',$8,$9,$10,$11,$12)",
                &[
                    &claim_id,
                    &kind,
                    &index,
                    &part_index,
                    &allocation.offering,
                    &allocation.operational_service,
                    &allocation.operational_location,
                    &allocation.anchor_id,
                    &allocation.resource_id,
                    &allocation.occupied_start,
                    &allocation.occupied_end,
                    &i32::try_from(allocation.units).map_err(|_| StoreError::Corrupt)?,
                ],
            )
            .await?;
        }
        Ok(())
    }

    async fn replace_claim_allocations(
        &self,
        claim_id: Uuid,
        allocations: &[NewClaimAllocation<'_>],
    ) -> Result<(), StoreError> {
        self.execute(
            "DELETE FROM scheduling_claim_allocations WHERE claim_id=$1",
            &[&claim_id],
        )
        .await?;
        self.insert_claim_allocations(claim_id, allocations).await
    }

    /// Close the claim under the revision its caller observed. The
    /// predicate, not an earlier read, decides: a concurrent lifecycle
    /// writer that already moved the claim makes this affect zero rows, and
    /// the caller rolls its whole transaction back behind the conflict.
    async fn close_claim(
        &self,
        claim_id: Uuid,
        state: ClaimState,
        reason: Option<&str>,
        observed_revision: i64,
    ) -> Result<bool, StoreError> {
        let closed = self
            .execute(
                "UPDATE scheduling_claims SET state=$2, reason=$3, \
                 revision=$4 + 1, closed_at=now(), changed_at=now() \
                 WHERE claim_id=$1 AND state='active' AND revision=$4",
                &[&claim_id, &state.as_str(), &reason, &observed_revision],
            )
            .await?;
        Ok(closed == 1)
    }

    async fn move_claim(
        &self,
        movement: &ClaimMove<'_>,
        observed_revision: i64,
    ) -> Result<bool, StoreError> {
        let recipient_count = movement
            .party
            .map(|party| i32::try_from(party.recipients))
            .transpose()
            .map_err(|_| StoreError::Corrupt)?;
        let attendee_count = movement
            .party
            .map(|party| i32::try_from(party.attendees))
            .transpose()
            .map_err(|_| StoreError::Corrupt)?;
        let moved = self
            .execute(
                "UPDATE scheduling_claims SET supply_id=$2, displayed_start=$3, displayed_end=$4, \
                 occupied_start=$5, occupied_end=$6, channel=$7, units=$8, recipient_count=$9, \
                 attendee_count=$10, policy_revision=$11, revision=$12, changed_at=now() \
                 WHERE claim_id=$1 AND state='active' AND revision=$13",
                &[
                    &movement.claim_id,
                    &movement.supply_id,
                    &movement.displayed_start,
                    &movement.displayed_end,
                    &movement.occupied_start,
                    &movement.occupied_end,
                    &movement.channel,
                    &movement.units,
                    &recipient_count,
                    &attendee_count,
                    &movement.policy_revision,
                    &movement.next_revision,
                    &observed_revision,
                ],
            )
            .await?;
        Ok(moved == 1)
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
            "INSERT INTO scheduling_outbox(outbox_id, purpose, generation, state, attempt, \
             next_attempt_at, claim_id, appointment_revision, due_at, payload) \
             VALUES($1,$2,1,'pending',0,$5,$3,$4,$5,$6)",
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

    async fn cancel_unsent_reminders(&self, claim_id: Uuid) -> Result<(), StoreError> {
        // A reminder already attempted, or leased by a dispatcher right now,
        // is left alone: the dispatch core never cancels a job that may
        // have reached its destination, and the send-time liveness read
        // sets it aside instead.
        let schema = current_schema_in(&**self).await?;
        let table = JobTable::new(&schema, "scheduling_outbox", "outbox_id", "purpose")
            .map_err(|_| StoreError::Configuration)?;
        let rows = self
            .query(
                "SELECT outbox_id FROM scheduling_outbox \
                 WHERE claim_id=$1 AND purpose='reminder' AND state='pending' AND attempt=0",
                &[&claim_id],
            )
            .await?;
        for row in rows {
            let key =
                JobKey::new(row.get::<_, Uuid>(0), "reminder").map_err(|_| StoreError::Corrupt)?;
            cancel_unattempted(self, &table, &key)
                .await
                .map_err(|_| StoreError::IntentDispatch)?;
        }
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
                "INSERT INTO scheduling_attempts(attempt_id, key_reference, actor_issuer, \
                 actor_subject, scope, idempotency_key, request_hash, state, status_code, receipt, \
                 expires_at) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING",
                &[
                    &attempt_id,
                    &commitment.key_reference(scope),
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
            // yet. Roll back this transaction's tentative effects; the
            // service then reconciles against the winning receipt.
            return Err(CommitError::KeyReused);
        }
        Ok(())
    }

    async fn claim_in_transaction(&self, claim_id: Uuid) -> Result<Option<ClaimRow>, StoreError> {
        // Serialize the ownership decision with owner erasure and lifecycle
        // writes, so a stale owner read cannot commit after the sweep.
        let row = self
            .query_opt(&format!("{SELECT_CLAIM} FOR UPDATE"), &[&claim_id])
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut claims = vec![map_claim_row(row)?];
        load_claim_allocations(self, &mut claims).await?;
        Ok(claims.pop())
    }

    async fn lock_caller_and_count_active_holds(
        &self,
        issuer: &str,
        subject: &str,
        now: DateTime<Utc>,
    ) -> Result<i64, StoreError> {
        self.execute(
            "SELECT pg_advisory_xact_lock($1, \
             hashtext(jsonb_build_array(current_schema(), $2::text, $3::text)::text))",
            &[&HOLD_CEILING_LOCK_NAMESPACE, &issuer, &subject],
        )
        .await?;
        let row = self
            .query_one(
                "SELECT count(*) FROM scheduling_claims \
                 WHERE owner_issuer=$1 AND owner_subject=$2 \
                   AND kind='hold' AND state='active' AND hold_expires_at > $3",
                &[&issuer, &subject, &now],
            )
            .await?;
        Ok(row.get(0))
    }
}

fn validated_undelivered_intents_limit(limit: i64) -> Result<i64, StoreError> {
    if (1..=MAXIMUM_UNDELIVERED_INTENTS_LIMIT).contains(&limit) {
        Ok(limit)
    } else {
        Err(StoreError::InvalidUndeliveredIntentsLimit)
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

#[cfg(test)]
mod query_bound_tests {
    use super::*;

    #[test]
    fn undelivered_intents_limit_is_positive_and_bounded() {
        assert_eq!(validated_undelivered_intents_limit(1).unwrap(), 1);
        assert_eq!(
            validated_undelivered_intents_limit(MAXIMUM_UNDELIVERED_INTENTS_LIMIT).unwrap(),
            MAXIMUM_UNDELIVERED_INTENTS_LIMIT
        );
        for limit in [0, -1, MAXIMUM_UNDELIVERED_INTENTS_LIMIT + 1, i64::MAX] {
            assert!(matches!(
                validated_undelivered_intents_limit(limit),
                Err(StoreError::InvalidUndeliveredIntentsLimit)
            ));
        }
    }
}

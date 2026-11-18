// SPDX-License-Identifier: Apache-2.0

//! Durable, fenced work for managed external-projection refresh plans.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use tokio_postgres::GenericClient;
use uuid::Uuid;

use super::{GuardedTransaction, RuntimeRevoke, SqlIdentifier};

const MAX_KEY_BYTES: usize = 1024;

/// Seconds a failed target waits before its next attempt, indexed by the
/// attempts already made. A target whose attempts run past the schedule is
/// settled as exhausted.
pub(crate) const RETRY_DELAYS: [u64; 3] = [15, 30, 60];

/// The wait before the next attempt of a target that has made `attempts`
/// attempts, or `None` once the retry schedule is exhausted.
pub(crate) fn retry_delay(attempts: i16) -> Option<Duration> {
    let index = usize::try_from(attempts).ok()?.checked_sub(1)?;
    RETRY_DELAYS.get(index).copied().map(Duration::from_secs)
}

/// Claims stop counting attempts here. A claim lost to a crash still counts,
/// so a target reclaimed past the retry schedule reaches this ceiling and is
/// settled as exhausted before any source I/O.
pub(crate) const ATTEMPTS_CEILING: i16 = RETRY_DELAYS.len() as i16 + 2;

#[cfg(test)]
pub(crate) const TABLES: &[&str] = &[
    "registry_internal.registry_external_refresh_plans",
    "registry_internal.registry_external_refresh_work",
];

pub(crate) const TABLE_PRIVILEGES: &[(&str, &[&str])] = &[
    (
        "registry_internal.registry_external_refresh_plans",
        &["INSERT", "SELECT", "UPDATE"],
    ),
    (
        "registry_internal.registry_external_refresh_work",
        &["DELETE", "INSERT", "SELECT", "UPDATE"],
    ),
];

pub(crate) const WORK_SEQUENCE: &str =
    "registry_internal.registry_external_refresh_work_work_id_seq";

#[cfg(test)]
pub(crate) const BACKUP_EXCLUDED_TABLES: &[&str] = TABLES;

pub(crate) const INDEXES: &[&str] = &[
    "registry_internal.registry_external_refresh_work_due_idx",
    "registry_internal.registry_external_refresh_plan_capture_idx",
];

/// Entries are (identity, result type, returns set, security definer, runtime execute).
pub(crate) const MANAGED_FUNCTIONS: &[(&str, &str, bool, bool, bool)] = &[
    (
        "registry_internal.capture_external_refresh_records(p_records jsonb)",
        "bigint",
        false,
        true,
        true,
    ),
    (
        "registry_internal.purge_external_refresh_state(p_limit integer)",
        "record",
        true,
        true,
        true,
    ),
];

const RUNTIME_FUNCTIONS: &[&str] = &[
    "registry_internal.capture_external_refresh_records(jsonb)",
    "registry_internal.purge_external_refresh_state(integer)",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum QueueError {
    #[error("external refresh plans require separate migration and runtime database roles")]
    RoleSeparationRequired,
    #[error("external refresh queue input is invalid")]
    Invalid,
    #[error("external refresh plan authority changed")]
    AuthorityChanged,
    #[error("external refresh queue lease is stale")]
    StaleLease,
    #[error("external refresh queue is unavailable")]
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlanRegistration {
    pub(crate) plan_id: String,
    pub(crate) package_digest: String,
    pub(crate) activation_id: Uuid,
    pub(crate) authority_digest: String,
    pub(crate) root_entity_id: String,
    pub(crate) watched_fields: BTreeSet<String>,
    /// Primary epoch first, followed by the optional label epoch. Preserving
    /// this order gives every lease guard the same plan -> primary -> label
    /// lock order.
    pub(crate) projection_epochs: Vec<Uuid>,
    pub(crate) interval_seconds: i64,
    pub(crate) page_size: i32,
    pub(crate) max_pending: i32,
}

impl PlanRegistration {
    fn valid(&self) -> bool {
        valid_key(&self.plan_id)
            && valid_key(&self.package_digest)
            && valid_key(&self.authority_digest)
            && valid_key(&self.root_entity_id)
            && !self.watched_fields.is_empty()
            && self.watched_fields.iter().all(|field| valid_key(field))
            && !self.projection_epochs.is_empty()
            && self.projection_epochs.iter().collect::<BTreeSet<_>>().len()
                == self.projection_epochs.len()
            && (1..=31_536_000).contains(&self.interval_seconds)
            && (1..=100).contains(&self.page_size)
            && (1..=10_000).contains(&self.max_pending)
    }
}

/// A lease token contains no subject or selector value and is safe to log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PlanLease {
    pub(crate) plan_generation: i64,
    pub(crate) lease_generation: i64,
    pub(crate) token: Uuid,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum WorkTarget {
    LocalRecord {
        record_id: Uuid,
    },
    ParentLabels {
        record_id: Uuid,
        after: Option<String>,
    },
    SourceChange {
        projection_epoch: Uuid,
        selector_scheme: String,
        selector: String,
    },
}

impl fmt::Debug for WorkTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("WorkTarget")
            .field(&self.to_string())
            .finish()
    }
}

impl fmt::Display for WorkTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalRecord { .. } => formatter.write_str("local-record"),
            Self::ParentLabels { .. } => formatter.write_str("parent-labels"),
            Self::SourceChange { .. } => formatter.write_str("source-change"),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ClaimedTarget {
    pub(crate) work_id: i64,
    pub(crate) enqueue_generation: i64,
    pub(crate) attempts: i16,
    pub(crate) expires_at: i64,
    pub(crate) target: WorkTarget,
}

impl fmt::Debug for ClaimedTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedTarget")
            .field("work_id", &self.work_id)
            .field("enqueue_generation", &self.enqueue_generation)
            .field("attempts", &self.attempts)
            .field("expires_at", &self.expires_at)
            .field("target", &self.target.to_string())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StepKind {
    Targets,
    Sweep,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StepState {
    pub(crate) checkpoint: SweepCheckpoint,
    pub(crate) sweep_due: bool,
    pub(crate) has_ready_targets: bool,
    pub(crate) next: StepKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceChangeAdmission {
    Accepted,
    AtCapacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Settlement {
    Published,
    AuthorizedAbsence,
    EmptyCollection,
    FreshReuse,
    NoEligibleWitness,
    Denied,
    RetentionRefused,
    Expired,
    AttemptsExhausted,
    AuthorityChanged,
}

impl Settlement {
    fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::AuthorizedAbsence => "authorized-absence",
            Self::EmptyCollection => "empty-collection",
            Self::FreshReuse => "fresh-reuse",
            Self::NoEligibleWitness => "no-eligible-witness",
            Self::Denied => "denied",
            Self::RetentionRefused => "retention-refused",
            Self::Expired => "expired",
            Self::AttemptsExhausted => "attempts-exhausted",
            Self::AuthorityChanged => "authority-changed",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SweepCheckpoint {
    pub(crate) phase: String,
    pub(crate) baseline_sequence: i64,
    pub(crate) continuation: Option<String>,
    pub(crate) completed: bool,
    pub(crate) acquisition_failures: i64,
}

impl fmt::Debug for SweepCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SweepCheckpoint")
            .field("phase", &self.phase)
            .field("baseline_sequence", &self.baseline_sequence)
            .field("continuation_present", &self.continuation.is_some())
            .field("completed", &self.completed)
            .field("acquisition_failures", &self.acquisition_failures)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PurgedQueueState {
    pub(crate) work: u64,
    pub(crate) plans: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlanStatus {
    pub(crate) active: bool,
    pub(crate) due: bool,
    pub(crate) leased: bool,
    pub(crate) pending: u64,
    pub(crate) ready: u64,
    pub(crate) oldest_ready_age_seconds: Option<u64>,
    pub(crate) last_attempt_at: Option<i64>,
    pub(crate) last_completed_at: Option<i64>,
    pub(crate) last_attempt_outcome: Option<String>,
}

pub(crate) async fn install(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), QueueError> {
    let migration_role: String = migration
        .query_one("SELECT current_user", &[])
        .await
        .map_err(|_| QueueError::Unavailable)?
        .get(0);
    if migration_role == runtime_role.as_str() {
        return Err(QueueError::RoleSeparationRequired);
    }
    migration
        .batch_execute(INSTALL_SQL)
        .await
        .map_err(|_| QueueError::Unavailable)?;
    let revoke = RuntimeRevoke::detect(migration, runtime_role)
        .await
        .map_err(|_| QueueError::Unavailable)?
        .with_public();
    for (table, privileges) in TABLE_PRIVILEGES {
        migration
            .batch_execute(&format!(
                "REVOKE ALL ON TABLE {table} FROM {revoke}; GRANT {} ON TABLE {table} TO {};",
                privileges.join(", "),
                runtime_role.quoted()
            ))
            .await
            .map_err(|_| QueueError::Unavailable)?;
    }
    migration
        .batch_execute(&format!(
            "REVOKE ALL ON SEQUENCE {WORK_SEQUENCE} FROM {revoke}; GRANT SELECT, USAGE ON SEQUENCE {WORK_SEQUENCE} TO {};",
            runtime_role.quoted()
        ))
        .await
        .map_err(|_| QueueError::Unavailable)?;
    for function in RUNTIME_FUNCTIONS {
        migration
            .batch_execute(&format!(
                "REVOKE ALL ON FUNCTION {function} FROM {revoke}; GRANT EXECUTE ON FUNCTION {function} TO {};",
                runtime_role.quoted()
            ))
            .await
            .map_err(|_| QueueError::Unavailable)?;
    }
    Ok(())
}

/// Reconcile the complete startup inventory. A changed authority key bumps
/// the generation, invalidates every old lease and queued selector, and makes
/// the current plan due immediately. Removing a plan retires its managed work.
pub(crate) async fn register_plans(
    transaction: &GuardedTransaction<'_>,
    registrations: &[PlanRegistration],
) -> Result<(), QueueError> {
    if registrations.iter().any(|plan| !plan.valid())
        || registrations
            .iter()
            .map(|plan| &plan.plan_id)
            .collect::<BTreeSet<_>>()
            .len()
            != registrations.len()
    {
        return Err(QueueError::Invalid);
    }
    let client = transaction.transaction();
    // Registration can retire and insert multiple plans. Take the table lock
    // before touching plan rows so concurrent queue work cannot invert locks.
    client
        .batch_execute(
            "LOCK TABLE registry_internal.registry_external_refresh_plans IN EXCLUSIVE MODE",
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    let active_ids = registrations
        .iter()
        .map(|plan| plan.plan_id.as_str())
        .collect::<Vec<_>>();
    client
        .execute(
            "UPDATE registry_internal.registry_external_refresh_plans
             SET active=false,plan_generation=plan_generation+1,lease_token=NULL,lease_expires_at=NULL,
                 reconciliation_due=false,updated_at=clock_timestamp()
             WHERE active AND NOT (plan_id=ANY($1::text[]))",
            &[&active_ids],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    for plan in registrations {
        let watched = plan
            .watched_fields
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let epochs = plan.projection_epochs.to_vec();
        client
            .execute(
                REGISTER_PLAN_SQL,
                &[
                    &plan.plan_id,
                    &plan.package_digest,
                    &plan.activation_id,
                    &plan.authority_digest,
                    &plan.root_entity_id,
                    &watched,
                    &epochs,
                    &plan.interval_seconds,
                    &plan.page_size,
                    &plan.max_pending,
                ],
            )
            .await
            .map_err(|_| QueueError::Unavailable)?;
        let active = client
            .query(
                "SELECT scope.epoch
                 FROM unnest($1::uuid[]) requested(epoch)
                 JOIN registry_internal.registry_external_projection_scopes scope
                   ON scope.epoch=requested.epoch AND scope.active
                 ORDER BY array_position($1::uuid[],scope.epoch)",
                &[&epochs],
            )
            .await
            .map_err(|_| QueueError::Unavailable)?;
        let active = active
            .iter()
            .map(|row| row.get::<_, Uuid>(0))
            .collect::<BTreeSet<_>>();
        if active.len() != epochs.len() {
            return Err(QueueError::AuthorityChanged);
        }
    }
    Ok(())
}

const REGISTER_PLAN_SQL: &str = r#"
INSERT INTO registry_internal.registry_external_refresh_plans AS current
    (plan_id,package_digest,activation_id,authority_digest,root_entity_id,watched_fields,
     projection_epochs,interval_seconds,page_size,max_pending,next_due_at,reconciliation_due)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp(),true)
ON CONFLICT (plan_id) DO UPDATE SET
    package_digest=EXCLUDED.package_digest,activation_id=EXCLUDED.activation_id,
    authority_digest=EXCLUDED.authority_digest,root_entity_id=EXCLUDED.root_entity_id,
    watched_fields=EXCLUDED.watched_fields,projection_epochs=EXCLUDED.projection_epochs,
    interval_seconds=EXCLUDED.interval_seconds,page_size=EXCLUDED.page_size,
    max_pending=EXCLUDED.max_pending,active=true,
    (plan_generation,next_due_at,reconciliation_due,reconciliation_generation,
     lease_token,lease_expires_at,sweep_phase,sweep_baseline,sweep_continuation,
     sweep_started_at,sweep_reconciliation_generation,sweep_acquisition_failures,
     next_turn,last_attempt_at,last_attempt_outcome,last_completed_at) = (
        SELECT current.plan_generation+CASE WHEN reset THEN 1 ELSE 0 END,
            CASE WHEN reset OR empty THEN clock_timestamp()
                 WHEN current.sweep_phase='complete' AND NOT current.reconciliation_due
                      AND current.interval_seconds<>EXCLUDED.interval_seconds
                      AND current.sweep_started_at IS NOT NULL
                 THEN greatest(
                     current.sweep_started_at+make_interval(secs => EXCLUDED.interval_seconds::double precision),
                     CASE WHEN current.sweep_acquisition_failures>0
                          THEN current.last_completed_at+interval '60 seconds' END)
                 ELSE current.next_due_at END,
            current.reconciliation_due OR reset,
            current.reconciliation_generation+CASE WHEN reset THEN 1 ELSE 0 END,
            CASE WHEN reset OR empty THEN NULL ELSE current.lease_token END,
            CASE WHEN reset OR empty THEN NULL ELSE current.lease_expires_at END,
            CASE WHEN reset OR empty THEN 'roots' ELSE current.sweep_phase END,
            CASE WHEN reset OR empty THEN 0 ELSE current.sweep_baseline END,
            CASE WHEN reset OR empty THEN NULL ELSE current.sweep_continuation END,
            CASE WHEN reset OR empty THEN NULL ELSE current.sweep_started_at END,
            CASE WHEN reset THEN 0 ELSE current.sweep_reconciliation_generation END,
            CASE WHEN reset OR empty THEN 0 ELSE current.sweep_acquisition_failures END,
            CASE WHEN reset THEN 'targets' ELSE current.next_turn END,
            CASE WHEN reset THEN NULL ELSE current.last_attempt_at END,
            CASE WHEN reset THEN NULL ELSE current.last_attempt_outcome END,
            CASE WHEN reset THEN NULL ELSE current.last_completed_at END
        FROM (SELECT NOT current.active OR
            (current.package_digest,current.activation_id,current.authority_digest,
             current.projection_epochs,current.root_entity_id,current.watched_fields)
            IS DISTINCT FROM
            (EXCLUDED.package_digest,EXCLUDED.activation_id,EXCLUDED.authority_digest,
             EXCLUDED.projection_epochs,EXCLUDED.root_entity_id,EXCLUDED.watched_fields) AS reset,
            -- A primary epoch with no snapshot rows lost its cache, for
            -- example in a restore that left the tables out. The sweep
            -- restarts now instead of waiting for the stored due time.
            NOT EXISTS (
                SELECT 1 FROM registry_internal.registry_external_projection_scopes scope
                JOIN registry_internal.registry_external_projection_snapshots snapshot
                  ON snapshot.projection_id=scope.projection_id AND snapshot.epoch=scope.epoch
                WHERE scope.epoch=EXCLUDED.projection_epochs[1]) AS empty) AS authority
    ),
    updated_at=clock_timestamp()
"#;

/// Only local identity and changed field names cross into the refresh queue.
#[derive(serde::Serialize)]
pub(crate) struct LocalRecordCapture {
    pub(crate) entity_id: String,
    pub(crate) record_id: Uuid,
    pub(crate) changed_fields: BTreeSet<String>,
}

/// Stage local work inside the Record mutation transaction. Passing an empty
/// field set means a create and therefore matches every active plan for the
/// Record type. At capacity the plan is marked due instead of losing the
/// reconciliation obligation.
pub(crate) async fn capture_local_records(
    client: &impl GenericClient,
    captures: &[LocalRecordCapture],
) -> Result<u64, QueueError> {
    if captures.is_empty() {
        return Ok(0);
    }
    if captures.iter().any(|capture| {
        !valid_key(&capture.entity_id)
            || capture.changed_fields.iter().any(|field| !valid_key(field))
    }) {
        return Err(QueueError::Invalid);
    }
    let records = serde_json::to_value(captures).map_err(|_| QueueError::Invalid)?;
    let row = client
        .query_one(
            "SELECT registry_internal.capture_external_refresh_records($1)",
            &[&records],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    let count: Option<i64> = row.get(0);
    u64::try_from(count.ok_or(QueueError::Unavailable)?).map_err(|_| QueueError::Unavailable)
}

#[cfg(all(test, feature = "postgres-test"))]
pub(crate) async fn capture_local_record(
    client: &impl GenericClient,
    entity_id: &str,
    record_id: Uuid,
    changed_fields: &BTreeSet<String>,
) -> Result<u64, QueueError> {
    capture_local_records(
        client,
        &[LocalRecordCapture {
            entity_id: entity_id.to_owned(),
            record_id,
            changed_fields: changed_fields.clone(),
        }],
    )
    .await
}

/// Admit a source change after HTTP authentication and source-binding checks.
/// The change upserts the plan's one work row for its target, so a repeated
/// change refreshes that row instead of queueing another. The selector is
/// retained only in pending work.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn enqueue_source_change(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    authority_digest: &str,
    target_digest: &str,
    projection_epoch: Uuid,
    selector_scheme: &str,
    selector: &str,
    expires_at: i64,
) -> Result<SourceChangeAdmission, QueueError> {
    if [
        plan_id,
        authority_digest,
        target_digest,
        selector_scheme,
        selector,
    ]
    .iter()
    .any(|value| !valid_key(value))
        || expires_at <= 0
    {
        return Err(QueueError::Invalid);
    }
    // Wait for the plan lock before opening the admission query's snapshot,
    // so the capacity count sees work a concurrent admission committed.
    let client = transaction.transaction();
    let row = client
        .query_opt(
            "SELECT 1 FROM registry_internal.registry_external_refresh_plans
             WHERE plan_id=$1 FOR UPDATE",
            &[&plan_id],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    if row.is_none() {
        return Err(QueueError::AuthorityChanged);
    }
    let row = client
        .query_one(
            ENQUEUE_SOURCE_CHANGE_SQL,
            &[
                &plan_id,
                &authority_digest,
                &target_digest,
                &projection_epoch,
                &selector_scheme,
                &selector,
                &expires_at,
            ],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    match row.get::<_, &str>(0) {
        "accepted" => Ok(SourceChangeAdmission::Accepted),
        "capacity" => Ok(SourceChangeAdmission::AtCapacity),
        "authority-changed" => Err(QueueError::AuthorityChanged),
        _ => Err(QueueError::Unavailable),
    }
}

pub(crate) async fn claim_plan(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    authority_digest: &str,
    lease: Duration,
) -> Result<Option<PlanLease>, QueueError> {
    if !valid_key(plan_id) || !valid_key(authority_digest) || lease.is_zero() {
        return Err(QueueError::Invalid);
    }
    let lease_seconds = i64::try_from(lease.as_secs()).map_err(|_| QueueError::Invalid)?;
    if lease_seconds > 3600 {
        return Err(QueueError::Invalid);
    }
    let token = Uuid::new_v4();
    let row = transaction
        .transaction()
        .query_opt(
            "UPDATE registry_internal.registry_external_refresh_plans
             SET lease_generation=lease_generation+1,lease_token=$3,
                 lease_expires_at=clock_timestamp()+make_interval(secs => $4::bigint::double precision),updated_at=clock_timestamp()
             WHERE plan_id=$1 AND authority_digest=$2 AND active
               AND (lease_expires_at IS NULL OR lease_expires_at<=clock_timestamp())
               AND (next_due_at<=clock_timestamp() OR EXISTS (
                    SELECT 1 FROM registry_internal.registry_external_refresh_work work
                    WHERE work.plan_id=$1 AND work.plan_generation=registry_external_refresh_plans.plan_generation
                      AND work.ready_at<=clock_timestamp() AND work.expires_at>clock_timestamp()))
             RETURNING plan_generation,lease_generation",
            &[&plan_id, &authority_digest, &token, &lease_seconds],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    Ok(row.map(|row| PlanLease {
        plan_generation: row.get(0),
        lease_generation: row.get(1),
        token,
    }))
}

/// Postpone a plan whose configured projection is no longer bound, so the
/// worker reports it once per plan interval rather than on every tick. Its
/// queued work waits with it. A plan another worker holds is left alone.
pub(crate) async fn defer_plan(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    authority_digest: &str,
) -> Result<bool, QueueError> {
    if !valid_key(plan_id) || !valid_key(authority_digest) {
        return Err(QueueError::Invalid);
    }
    let row = transaction
        .transaction()
        .query_one(
            "WITH deferred AS (
                 UPDATE registry_internal.registry_external_refresh_plans
                 SET next_due_at=clock_timestamp()+make_interval(secs => interval_seconds::double precision),
                     last_attempt_at=clock_timestamp(),last_attempt_outcome='invalid-binding',
                     updated_at=clock_timestamp()
                 WHERE plan_id=$1 AND authority_digest=$2 AND active
                   AND (lease_expires_at IS NULL OR lease_expires_at<=clock_timestamp())
                 RETURNING plan_id,plan_generation,next_due_at
             ), postponed AS (
                 UPDATE registry_internal.registry_external_refresh_work work
                 SET ready_at=greatest(work.ready_at,deferred.next_due_at)
                 FROM deferred
                 WHERE work.plan_id=deferred.plan_id AND work.plan_generation=deferred.plan_generation
                 RETURNING 1
             )
             SELECT count(*) FROM deferred",
            &[&plan_id, &authority_digest],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    Ok(row.get::<_, i64>(0) == 1)
}

/// Recheck the plan fence in the transaction that precedes acquisition or
/// publishes one per-key result. An optional target fence prevents a stale
/// owner from publishing and then settling over a newer enqueue generation.
pub(crate) async fn guard_plan_lease(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    authority_digest: &str,
    projection_epoch: Option<Uuid>,
    lease: PlanLease,
    target: Option<(i64, i64)>,
) -> Result<(), QueueError> {
    let row = transaction
        .transaction()
        .query_opt(
            "SELECT projection_epochs
             FROM registry_internal.registry_external_refresh_plans
             WHERE plan_id=$1 AND authority_digest=$2 AND plan_generation=$3
               AND lease_generation=$4 AND lease_token=$5 AND active
               AND lease_expires_at>clock_timestamp()
             FOR SHARE",
            &[
                &plan_id,
                &authority_digest,
                &lease.plan_generation,
                &lease.lease_generation,
                &lease.token,
            ],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?
        .ok_or(QueueError::StaleLease)?;
    if let Some(epoch) = projection_epoch {
        if !row.get::<_, Vec<Uuid>>(0).contains(&epoch) {
            return Err(QueueError::AuthorityChanged);
        }
        let active = transaction
            .transaction()
            .query_opt(
                "SELECT 1 FROM registry_internal.registry_external_projection_scopes
                 WHERE epoch=$1 AND active",
                &[&epoch],
            )
            .await
            .map_err(|_| QueueError::Unavailable)?;
        if active.is_none() {
            return Err(QueueError::AuthorityChanged);
        }
    }
    if let Some((work_id, enqueue_generation)) = target {
        let current = transaction
            .transaction()
            .query_opt(
                "SELECT 1 FROM registry_internal.registry_external_refresh_work
                 WHERE plan_id=$1 AND plan_generation=$2 AND work_id=$3 AND enqueue_generation=$4
                   AND expires_at>clock_timestamp()
                 FOR UPDATE",
                &[
                    &plan_id,
                    &lease.plan_generation,
                    &work_id,
                    &enqueue_generation,
                ],
            )
            .await
            .map_err(|_| QueueError::Unavailable)?;
        if current.is_none() {
            return Err(QueueError::StaleLease);
        }
    }
    Ok(())
}

pub(crate) async fn has_ready_work(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    authority_digest: &str,
) -> Result<bool, QueueError> {
    let row = transaction
        .transaction()
        .query_one(
            "SELECT EXISTS (
                SELECT 1 FROM registry_internal.registry_external_refresh_plans plan
                WHERE plan.plan_id=$1 AND plan.authority_digest=$2 AND plan.active
                  AND (plan.lease_expires_at IS NULL OR plan.lease_expires_at<=clock_timestamp())
                  AND (plan.next_due_at<=clock_timestamp() OR EXISTS (
                    SELECT 1 FROM registry_internal.registry_external_refresh_work work
                    WHERE work.plan_id=plan.plan_id AND work.plan_generation=plan.plan_generation
                      AND work.ready_at<=clock_timestamp() AND work.expires_at>clock_timestamp())))",
            &[&plan_id, &authority_digest],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    Ok(row.get(0))
}

pub(crate) async fn load_step_state(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    authority_digest: &str,
    lease: PlanLease,
) -> Result<StepState, QueueError> {
    let row = transaction
        .transaction()
        .query_opt(
            "SELECT sweep_phase,sweep_baseline,sweep_continuation,sweep_acquisition_failures,
                    next_due_at<=clock_timestamp() AS sweep_due,
                    EXISTS (SELECT 1 FROM registry_internal.registry_external_refresh_work work
                        WHERE work.plan_id=plan.plan_id AND work.plan_generation=plan.plan_generation
                          AND work.ready_at<=clock_timestamp() AND work.expires_at>clock_timestamp()) AS has_targets,
                    next_turn
             FROM registry_internal.registry_external_refresh_plans plan
             WHERE plan_id=$1 AND authority_digest=$2 AND plan_generation=$3
               AND lease_generation=$4 AND lease_token=$5 AND active
               AND lease_expires_at>clock_timestamp()",
            &[
                &plan_id,
                &authority_digest,
                &lease.plan_generation,
                &lease.lease_generation,
                &lease.token,
            ],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?
        .ok_or(QueueError::StaleLease)?;
    let sweep_due: bool = row.get(4);
    let has_ready_targets: bool = row.get(5);
    let preferred: String = row.get(6);
    let next = match (sweep_due, has_ready_targets, preferred.as_str()) {
        (true, true, "sweep") | (true, false, _) => StepKind::Sweep,
        (true, true, "targets") | (false, true, _) => StepKind::Targets,
        _ => StepKind::Sweep,
    };
    Ok(StepState {
        checkpoint: SweepCheckpoint {
            phase: row.get(0),
            baseline_sequence: row.get(1),
            continuation: row.get(2),
            completed: false,
            acquisition_failures: row.get(3),
        },
        sweep_due,
        has_ready_targets,
        next,
    })
}

/// Atomically start a due traversal or return its existing durable baseline
/// and sealed continuation. Call this in a short transaction before the first
/// page performs source I/O; `finish_step` advances it after publication.
pub(crate) async fn prepare_sweep(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    authority_digest: &str,
    lease: PlanLease,
    proposed_baseline: i64,
) -> Result<SweepCheckpoint, QueueError> {
    if proposed_baseline < 1 {
        return Err(QueueError::Invalid);
    }
    let row = transaction
        .transaction()
        .query_opt(
            "UPDATE registry_internal.registry_external_refresh_plans
             SET sweep_phase=CASE WHEN sweep_phase='complete' THEN 'roots' ELSE sweep_phase END,
                 sweep_baseline=CASE WHEN sweep_phase='complete' OR sweep_baseline=0
                                     THEN $6 ELSE sweep_baseline END,
                 sweep_continuation=CASE WHEN sweep_phase='complete' THEN NULL ELSE sweep_continuation END,
                 sweep_acquisition_failures=CASE WHEN sweep_phase='complete' THEN 0 ELSE sweep_acquisition_failures END,
                 sweep_started_at=CASE WHEN sweep_phase='complete'
                                           OR (sweep_phase='roots' AND sweep_baseline=0)
                                       THEN clock_timestamp() ELSE sweep_started_at END,
                 sweep_reconciliation_generation=CASE WHEN sweep_phase='complete'
                      OR (sweep_phase='roots' AND sweep_baseline=0)
                      THEN reconciliation_generation ELSE sweep_reconciliation_generation END,
                 updated_at=clock_timestamp()
             WHERE plan_id=$1 AND authority_digest=$2 AND plan_generation=$3
               AND lease_generation=$4 AND lease_token=$5 AND active
               AND lease_expires_at>clock_timestamp()
               AND next_due_at<=clock_timestamp()
             RETURNING sweep_phase,sweep_baseline,sweep_continuation,sweep_acquisition_failures",
            &[
                &plan_id,
                &authority_digest,
                &lease.plan_generation,
                &lease.lease_generation,
                &lease.token,
                &proposed_baseline,
            ],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?
        .ok_or(QueueError::StaleLease)?;
    Ok(SweepCheckpoint {
        phase: row.get(0),
        baseline_sequence: row.get(1),
        continuation: row.get(2),
        completed: false,
        acquisition_failures: row.get(3),
    })
}

pub(crate) async fn claim_targets(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    lease: PlanLease,
) -> Result<Vec<ClaimedTarget>, QueueError> {
    let rows = transaction
        .transaction()
        .query(
            CLAIM_TARGETS_SQL,
            &[
                &plan_id,
                &lease.plan_generation,
                &lease.lease_generation,
                &lease.token,
                &ATTEMPTS_CEILING,
            ],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    rows.into_iter()
        .map(|row| {
            let kind: String = row.get(4);
            let target = match kind.as_str() {
                "local" => WorkTarget::LocalRecord {
                    record_id: row
                        .get::<_, Option<Uuid>>(5)
                        .ok_or(QueueError::Unavailable)?,
                },
                "labels" => WorkTarget::ParentLabels {
                    record_id: row
                        .get::<_, Option<Uuid>>(5)
                        .ok_or(QueueError::Unavailable)?,
                    after: row.get(9),
                },
                "source" => WorkTarget::SourceChange {
                    projection_epoch: row
                        .get::<_, Option<Uuid>>(6)
                        .ok_or(QueueError::Unavailable)?,
                    selector_scheme: row
                        .get::<_, Option<String>>(7)
                        .ok_or(QueueError::Unavailable)?,
                    selector: row
                        .get::<_, Option<String>>(8)
                        .ok_or(QueueError::Unavailable)?,
                },
                _ => return Err(QueueError::Unavailable),
            };
            Ok(ClaimedTarget {
                work_id: row.get(0),
                enqueue_generation: row.get(1),
                attempts: row.get(2),
                expires_at: row.get(10),
                target,
            })
        })
        .collect()
}

const CLAIM_TARGETS_SQL: &str = r#"
WITH plan AS MATERIALIZED (
    SELECT plan_id,plan_generation,lease_generation,lease_token,page_size
    FROM registry_internal.registry_external_refresh_plans
    WHERE plan_id=$1 AND plan_generation=$2 AND lease_generation=$3 AND lease_token=$4
      AND active AND lease_expires_at>clock_timestamp()
), ready AS MATERIALIZED (
    SELECT work.work_id FROM registry_internal.registry_external_refresh_work AS work
    JOIN plan USING (plan_id,plan_generation)
    WHERE work.ready_at<=clock_timestamp() AND work.expires_at>clock_timestamp()
    ORDER BY work.ready_at,work.work_id LIMIT (SELECT page_size FROM plan)
    FOR UPDATE OF work SKIP LOCKED
), claimed AS (
    UPDATE registry_internal.registry_external_refresh_work AS work
    SET attempts=least(attempts+1,$5::smallint)
    FROM ready WHERE work.work_id=ready.work_id
    RETURNING work.*
)
SELECT work_id,enqueue_generation,attempts,plan_generation,kind,record_id,
       projection_epoch,selector_scheme,selector,continuation,
       floor(extract(epoch FROM expires_at))::bigint
FROM claimed ORDER BY ready_at,work_id
"#;

/// Enqueue runtime-derived follow-on work, currently the bounded continuation
/// of a related-label pass. Source changes use `enqueue_source_change`, which
/// is fenced by plan authority and projection epoch instead of a lease and
/// reports a full queue to its caller.
pub(crate) async fn enqueue_internal_target(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    authority_digest: &str,
    lease: PlanLease,
    target: &WorkTarget,
    expires_at: i64,
) -> Result<(), QueueError> {
    if expires_at <= 0 {
        return Err(QueueError::Invalid);
    }
    let (kind, record_id, continuation, target_digest) = match target {
        WorkTarget::ParentLabels { record_id, after } => {
            if after.as_deref().is_some_and(|value| !valid_cursor(value)) {
                return Err(QueueError::Invalid);
            }
            (
                "labels",
                Some(*record_id),
                after.clone(),
                format!("labels:{record_id}"),
            )
        }
        WorkTarget::LocalRecord { record_id } => (
            "local",
            Some(*record_id),
            None,
            format!("local:{record_id}"),
        ),
        WorkTarget::SourceChange { .. } => return Err(QueueError::Invalid),
    };
    let changed = transaction
        .transaction()
        .execute(
            "INSERT INTO registry_internal.registry_external_refresh_work
                (plan_id,plan_generation,kind,record_id,continuation,target_digest,expires_at)
             SELECT plan_id,plan_generation,$6,$7,$8,$9,to_timestamp($10::bigint)
             FROM registry_internal.registry_external_refresh_plans
             WHERE plan_id=$1 AND authority_digest=$2 AND plan_generation=$3
               AND lease_generation=$4 AND lease_token=$5 AND active
               AND lease_expires_at>clock_timestamp()
               AND ((SELECT count(*) FROM registry_internal.registry_external_refresh_work work
                     WHERE work.plan_id=registry_external_refresh_plans.plan_id
                       AND work.plan_generation=registry_external_refresh_plans.plan_generation)<max_pending
                    OR EXISTS (SELECT 1 FROM registry_internal.registry_external_refresh_work work
                               WHERE work.plan_id=$1 AND work.target_digest=$9))
             ON CONFLICT (plan_id,target_digest) DO UPDATE SET
                plan_generation=EXCLUDED.plan_generation,
                enqueue_generation=registry_external_refresh_work.enqueue_generation+1,
                attempts=0,ready_at=clock_timestamp(),expires_at=EXCLUDED.expires_at,
                continuation=EXCLUDED.continuation",
            &[
                &plan_id,
                &authority_digest,
                &lease.plan_generation,
                &lease.lease_generation,
                &lease.token,
                &kind,
                &record_id,
                &continuation,
                &target_digest,
                &expires_at,
            ],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    if changed == 0 {
        let fallback = transaction
            .transaction()
            .execute(
                "UPDATE registry_internal.registry_external_refresh_plans
                 SET reconciliation_due=true,reconciliation_generation=reconciliation_generation+1,
                     next_due_at=least(next_due_at,clock_timestamp()+interval '60 seconds'),
                     updated_at=clock_timestamp()
                 WHERE plan_id=$1 AND authority_digest=$2 AND plan_generation=$3
                   AND lease_generation=$4 AND lease_token=$5 AND active
                   AND lease_expires_at>clock_timestamp()",
                &[
                    &plan_id,
                    &authority_digest,
                    &lease.plan_generation,
                    &lease.lease_generation,
                    &lease.token,
                ],
            )
            .await
            .map_err(|_| QueueError::Unavailable)?;
        if fallback == 0 {
            return Err(QueueError::StaleLease);
        }
    }
    Ok(())
}

/// Queue a per-key failure discovered by a sweep page as a target that has
/// made one attempt and waits the first retry delay. Collisions preserve the
/// higher attempt count and the earlier ready/expiry bounds, so another
/// observation cannot renew retention or restart an exhausted retry budget.
///
/// Returns `false` when the plan's queue is full. The sweep itself is the
/// reconciliation for the key, so a refusal leaves the plan schedule alone and
/// the key waits for the next sweep.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn enqueue_sweep_retry(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    authority_digest: &str,
    lease: PlanLease,
    target_digest: &str,
    projection_epoch: Uuid,
    selector_scheme: &str,
    selector: &str,
    expires_at: i64,
) -> Result<bool, QueueError> {
    if !valid_key(target_digest)
        || !valid_key(selector_scheme)
        || !valid_key(selector)
        || expires_at <= 0
    {
        return Err(QueueError::Invalid);
    }
    let first_delay = i64::try_from(RETRY_DELAYS[0]).map_err(|_| QueueError::Invalid)?;
    guard_plan_lease(
        transaction,
        plan_id,
        authority_digest,
        Some(projection_epoch),
        lease,
        None,
    )
    .await?;
    let changed = transaction
        .transaction()
        .execute(
            "INSERT INTO registry_internal.registry_external_refresh_work
                (plan_id,plan_generation,kind,projection_epoch,selector_scheme,selector,
                 target_digest,attempts,ready_at,expires_at)
             SELECT plan_id,plan_generation,'source',$6,$7,$8,$9,1,
                    clock_timestamp()+make_interval(secs => $10::bigint::double precision),
                    to_timestamp($11::bigint)
             FROM registry_internal.registry_external_refresh_plans plan
             WHERE plan_id=$1 AND authority_digest=$2 AND plan_generation=$3
               AND lease_generation=$4 AND lease_token=$5 AND active
               AND lease_expires_at>clock_timestamp()
               AND ((SELECT count(*) FROM registry_internal.registry_external_refresh_work work
                     WHERE work.plan_id=plan.plan_id AND work.plan_generation=plan.plan_generation)<plan.max_pending
                    OR EXISTS (SELECT 1 FROM registry_internal.registry_external_refresh_work work
                               WHERE work.plan_id=$1 AND work.target_digest=$9))
             ON CONFLICT (plan_id,target_digest) DO UPDATE SET
                plan_generation=EXCLUDED.plan_generation,
                enqueue_generation=registry_external_refresh_work.enqueue_generation+1,
                attempts=CASE WHEN registry_external_refresh_work.attempts=0 THEN 0
                              ELSE greatest(registry_external_refresh_work.attempts,EXCLUDED.attempts) END,
                ready_at=least(registry_external_refresh_work.ready_at,EXCLUDED.ready_at),
                expires_at=least(registry_external_refresh_work.expires_at,EXCLUDED.expires_at)",
            &[
                &plan_id,
                &authority_digest,
                &lease.plan_generation,
                &lease.lease_generation,
                &lease.token,
                &projection_epoch,
                &selector_scheme,
                &selector,
                &target_digest,
                &first_delay,
                &expires_at,
            ],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    Ok(changed > 0)
}

pub(crate) async fn settle_target(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    lease: PlanLease,
    target: &ClaimedTarget,
    outcome: Settlement,
) -> Result<(), QueueError> {
    let row = transaction
        .transaction()
        .query_one(
            SETTLE_TARGET_SQL,
            &[
                &plan_id,
                &lease.plan_generation,
                &lease.lease_generation,
                &lease.token,
                &target.work_id,
                &target.enqueue_generation,
                &outcome.as_str(),
            ],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    if row.get::<_, i64>(0) == 0 {
        return Err(QueueError::StaleLease);
    }
    Ok(())
}

const SETTLE_TARGET_SQL: &str = r#"
WITH valid AS (
    SELECT 1 FROM registry_internal.registry_external_refresh_plans
    WHERE plan_id=$1 AND plan_generation=$2 AND lease_generation=$3 AND lease_token=$4
      AND active AND lease_expires_at>clock_timestamp()
), settled AS (
    DELETE FROM registry_internal.registry_external_refresh_work AS work
    USING valid
    WHERE work.work_id=$5 AND work.plan_id=$1 AND work.plan_generation=$2
      AND work.enqueue_generation=$6
    RETURNING work.work_id
), due AS (
    -- A target given up on makes the plan due for reconciliation, but no
    -- sooner than the floor after the current sweep started, so one bad key
    -- cannot keep restarting sweeps.
    UPDATE registry_internal.registry_external_refresh_plans plan
    SET reconciliation_due=true,
        reconciliation_generation=reconciliation_generation+1,
        next_due_at=least(next_due_at,greatest(
            clock_timestamp()+interval '60 seconds',
            coalesce(sweep_started_at,clock_timestamp())
                +make_interval(secs => least(interval_seconds,900)::double precision))),
        updated_at=clock_timestamp()
    FROM settled
    WHERE plan.plan_id=$1 AND $7 IN ('expired','attempts-exhausted','authority-changed')
    RETURNING plan.plan_id
)
SELECT count(*) FROM settled
"#;

/// Retry only this claimed target after the delay its attempts select, or
/// settle it as exhausted once the schedule runs out. A concurrent enqueue
/// increments the row's generation, so this stale owner changes zero rows and
/// cannot postpone or clear the newer work.
pub(crate) async fn retry_target(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    lease: PlanLease,
    target: &ClaimedTarget,
) -> Result<(), QueueError> {
    let Some(delay) = retry_delay(target.attempts) else {
        return settle_target(
            transaction,
            plan_id,
            lease,
            target,
            Settlement::AttemptsExhausted,
        )
        .await;
    };
    let delay = i64::try_from(delay.as_secs()).map_err(|_| QueueError::Invalid)?;
    let changed = transaction
        .transaction()
        .execute(
            "UPDATE registry_internal.registry_external_refresh_work AS work
             SET ready_at=clock_timestamp()+make_interval(secs => $7::bigint::double precision)
             WHERE work.work_id=$5 AND work.plan_id=$1 AND work.plan_generation=$2
               AND work.enqueue_generation=$6 AND EXISTS (
                 SELECT 1 FROM registry_internal.registry_external_refresh_plans plan
                 WHERE plan.plan_id=$1 AND plan.plan_generation=$2 AND plan.lease_generation=$3
                   AND plan.lease_token=$4 AND plan.active AND plan.lease_expires_at>clock_timestamp())",
            &[
                &plan_id,
                &lease.plan_generation,
                &lease.lease_generation,
                &lease.token,
                &target.work_id,
                &target.enqueue_generation,
                &delay,
            ],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    if changed == 0 {
        return Err(QueueError::StaleLease);
    }
    Ok(())
}

/// Persist one bounded step and release its lease. Alternating the next turn
/// prevents either sustained source changes or a long sweep from starving the
/// other.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn finish_step(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    authority_digest: &str,
    lease: PlanLease,
    performed: StepKind,
    checkpoint: &SweepCheckpoint,
    outcome: &str,
) -> Result<(), QueueError> {
    if !matches!(checkpoint.phase.as_str(), "roots" | "labels" | "complete")
        || checkpoint.baseline_sequence < 0
        || checkpoint.acquisition_failures < 0
        || checkpoint
            .continuation
            .as_deref()
            .is_some_and(|value| !valid_cursor(value))
        || !matches!(
            outcome,
            "targets" | "sweep-page" | "sweep-complete" | "sweep-with-failures" | "idle"
        )
    {
        return Err(QueueError::Invalid);
    }
    let next_turn = match performed {
        StepKind::Targets => "sweep",
        StepKind::Sweep => "targets",
    };
    let changed = transaction
        .transaction()
        .execute(
            "UPDATE registry_internal.registry_external_refresh_plans
             SET sweep_phase=$6,sweep_baseline=$7,sweep_continuation=$8,
                 sweep_acquisition_failures=$9::bigint,
                 last_completed_at=CASE WHEN $10 THEN clock_timestamp() ELSE last_completed_at END,
                 next_due_at=CASE WHEN $10 THEN
                     CASE WHEN reconciliation_generation>sweep_reconciliation_generation
                         THEN greatest(
                             clock_timestamp()+interval '60 seconds',
                             coalesce(sweep_started_at,clock_timestamp())
                                 +make_interval(secs => least(interval_seconds,900)::double precision))
                         ELSE greatest(
                             clock_timestamp()+CASE WHEN $9::bigint>0 THEN interval '60 seconds' ELSE interval '0 seconds' END,
                             coalesce(sweep_started_at,clock_timestamp())
                                 +make_interval(secs => interval_seconds::double precision))
                     END
                     ELSE next_due_at END,
                 reconciliation_due=CASE WHEN $10 THEN
                     reconciliation_generation>sweep_reconciliation_generation
                     ELSE reconciliation_due END,
                 next_turn=$11,last_attempt_at=clock_timestamp(),last_attempt_outcome=$12,
                 lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp()
             WHERE plan_id=$1 AND authority_digest=$2 AND plan_generation=$3
               AND lease_generation=$4 AND lease_token=$5 AND active
               AND lease_expires_at>clock_timestamp()",
            &[
                &plan_id,
                &authority_digest,
                &lease.plan_generation,
                &lease.lease_generation,
                &lease.token,
                &checkpoint.phase,
                &checkpoint.baseline_sequence,
                &checkpoint.continuation,
                &checkpoint.acquisition_failures,
                &checkpoint.completed,
                &next_turn,
                &outcome,
            ],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    if changed == 0 {
        return Err(QueueError::StaleLease);
    }
    Ok(())
}

pub(crate) async fn purge_expired(
    transaction: &GuardedTransaction<'_>,
    limit: u32,
) -> Result<PurgedQueueState, QueueError> {
    if !(1..=1000).contains(&limit) {
        return Err(QueueError::Invalid);
    }
    let limit = i32::try_from(limit).map_err(|_| QueueError::Invalid)?;
    let rows = transaction
        .transaction()
        .query(
            "SELECT * FROM registry_internal.purge_external_refresh_state($1)",
            &[&limit],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    let mut purged = PurgedQueueState { work: 0, plans: 0 };
    for row in rows {
        let kind: String = row.get(0);
        let count = u64::try_from(row.get::<_, i64>(1)).map_err(|_| QueueError::Unavailable)?;
        match kind.as_str() {
            "work" => purged.work += count,
            "plan" => purged.plans += count,
            _ => return Err(QueueError::Unavailable),
        }
    }
    Ok(purged)
}

/// Value-free operator status. Counts and fixed categories intentionally omit
/// Record IDs, source selectors, cursors and authority bytes.
pub(crate) async fn plan_status(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    authority_digest: &str,
) -> Result<Option<PlanStatus>, QueueError> {
    let row = transaction
        .transaction()
        .query_opt(
            "SELECT plan.active,
                    plan.next_due_at<=clock_timestamp(),
                    COALESCE(plan.lease_expires_at>clock_timestamp(),false),
                    count(work.work_id),
                    count(work.work_id) FILTER (WHERE work.ready_at<=clock_timestamp()
                        AND work.expires_at>clock_timestamp()),
                    floor(extract(epoch FROM clock_timestamp()-min(work.ready_at)
                        FILTER (WHERE work.ready_at<=clock_timestamp() AND work.expires_at>clock_timestamp())))::bigint,
                    floor(extract(epoch FROM plan.last_attempt_at))::bigint,
                    floor(extract(epoch FROM plan.last_completed_at))::bigint,
                    plan.last_attempt_outcome
             FROM registry_internal.registry_external_refresh_plans plan
             LEFT JOIN registry_internal.registry_external_refresh_work work
               ON work.plan_id=plan.plan_id AND work.plan_generation=plan.plan_generation
             WHERE plan.plan_id=$1 AND plan.authority_digest=$2
             GROUP BY plan.plan_id",
            &[&plan_id, &authority_digest],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    row.map(|row| {
        let nonnegative = |column| -> Result<u64, QueueError> {
            u64::try_from(row.get::<_, i64>(column)).map_err(|_| QueueError::Unavailable)
        };
        let age = row
            .get::<_, Option<i64>>(5)
            .map(|age| u64::try_from(age.max(0)).map_err(|_| QueueError::Unavailable))
            .transpose()?;
        Ok(PlanStatus {
            active: row.get(0),
            due: row.get(1),
            leased: row.get(2),
            pending: nonnegative(3)?,
            ready: nonnegative(4)?,
            oldest_ready_age_seconds: age,
            last_attempt_at: row.get(6),
            last_completed_at: row.get(7),
            last_attempt_outcome: row.get(8),
        })
    })
    .transpose()
}

fn valid_key(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_KEY_BYTES && !value.chars().any(char::is_control)
}

fn valid_cursor(value: &str) -> bool {
    !value.is_empty() && value.len() <= 16 * 1024 && !value.chars().any(char::is_control)
}

pub(crate) const INSTALL_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS registry_internal.registry_external_refresh_plans (
    plan_id text PRIMARY KEY CHECK (octet_length(plan_id) BETWEEN 1 AND 1024),
    package_digest text NOT NULL CHECK (octet_length(package_digest) BETWEEN 1 AND 1024),
    activation_id uuid NOT NULL,
    authority_digest text NOT NULL CHECK (octet_length(authority_digest) BETWEEN 1 AND 1024),
    root_entity_id text NOT NULL CHECK (octet_length(root_entity_id) BETWEEN 1 AND 1024),
    watched_fields text[] NOT NULL CHECK (cardinality(watched_fields)>0),
    projection_epochs uuid[] NOT NULL CHECK (cardinality(projection_epochs)>0),
    interval_seconds bigint NOT NULL CHECK (interval_seconds BETWEEN 1 AND 31536000),
    page_size integer NOT NULL CHECK (page_size BETWEEN 1 AND 100),
    max_pending integer NOT NULL CHECK (max_pending BETWEEN 1 AND 10000),
    active boolean NOT NULL DEFAULT true,
    plan_generation bigint NOT NULL DEFAULT 1 CHECK (plan_generation>0),
    lease_generation bigint NOT NULL DEFAULT 0 CHECK (lease_generation>=0),
    lease_token uuid,
    lease_expires_at timestamptz,
    next_due_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    reconciliation_due boolean NOT NULL DEFAULT true,
    reconciliation_generation bigint NOT NULL DEFAULT 1 CHECK (reconciliation_generation>0),
    sweep_phase text NOT NULL DEFAULT 'roots' CHECK (sweep_phase IN ('roots','labels','complete')),
    sweep_baseline bigint NOT NULL DEFAULT 0 CHECK (sweep_baseline>=0),
    sweep_continuation text CHECK (sweep_continuation IS NULL OR octet_length(sweep_continuation) BETWEEN 1 AND 16384),
    sweep_acquisition_failures bigint NOT NULL DEFAULT 0 CHECK (sweep_acquisition_failures>=0),
    sweep_started_at timestamptz,
    sweep_reconciliation_generation bigint NOT NULL DEFAULT 0 CHECK (sweep_reconciliation_generation>=0),
    next_turn text NOT NULL DEFAULT 'targets' CHECK (next_turn IN ('targets','sweep')),
    last_attempt_at timestamptz,
    last_attempt_outcome text CHECK (last_attempt_outcome IS NULL OR last_attempt_outcome IN
        ('targets','sweep-page','sweep-complete','sweep-with-failures','idle','invalid-binding')),
    last_completed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT registry_external_refresh_plan_lease_pair CHECK ((lease_token IS NULL)=(lease_expires_at IS NULL))
);
CREATE TABLE IF NOT EXISTS registry_internal.registry_external_refresh_work (
    work_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    plan_id text NOT NULL REFERENCES registry_internal.registry_external_refresh_plans(plan_id) ON DELETE CASCADE,
    plan_generation bigint NOT NULL CHECK (plan_generation>0),
    kind text NOT NULL CHECK (kind IN ('local','labels','source')),
    record_id uuid,
    projection_epoch uuid,
    selector_scheme text CHECK (selector_scheme IS NULL OR octet_length(selector_scheme) BETWEEN 1 AND 1024),
    selector text CHECK (selector IS NULL OR octet_length(selector) BETWEEN 1 AND 1024),
    continuation text CHECK (continuation IS NULL OR octet_length(continuation) BETWEEN 1 AND 16384),
    target_digest text NOT NULL CHECK (octet_length(target_digest) BETWEEN 1 AND 1024),
    enqueue_generation bigint NOT NULL DEFAULT 1 CHECK (enqueue_generation>0),
    attempts smallint NOT NULL DEFAULT 0 CHECK (attempts>=0),
    ready_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT registry_external_refresh_work_shape CHECK (
        (kind='local' AND record_id IS NOT NULL AND projection_epoch IS NULL AND selector_scheme IS NULL AND selector IS NULL AND continuation IS NULL)
        OR (kind='labels' AND record_id IS NOT NULL AND projection_epoch IS NULL AND selector_scheme IS NULL AND selector IS NULL)
        OR (kind='source' AND record_id IS NULL AND projection_epoch IS NOT NULL AND selector_scheme IS NOT NULL AND selector IS NOT NULL AND continuation IS NULL)),
    UNIQUE (plan_id,target_digest)
);
CREATE INDEX IF NOT EXISTS registry_external_refresh_work_due_idx
    ON registry_internal.registry_external_refresh_work(plan_id,ready_at,work_id);
CREATE INDEX IF NOT EXISTS registry_external_refresh_plan_capture_idx
    ON registry_internal.registry_external_refresh_plans(root_entity_id,active,plan_id);

CREATE OR REPLACE FUNCTION registry_internal.capture_external_refresh_records(
    p_records jsonb
) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, registry_internal AS $body$
DECLARE captured bigint;
BEGIN
    IF jsonb_typeof(p_records) IS DISTINCT FROM 'array' THEN RETURN NULL; END IF;
    IF EXISTS (
        SELECT 1 FROM jsonb_to_recordset(p_records) AS input(entity_id text,record_id uuid,changed_fields text[])
        WHERE input.entity_id IS NULL OR octet_length(input.entity_id) NOT BETWEEN 1 AND 1024
            OR input.record_id IS NULL OR input.changed_fields IS NULL
            OR EXISTS (SELECT 1 FROM unnest(input.changed_fields) field
                       WHERE field IS NULL OR octet_length(field) NOT BETWEEN 1 AND 1024)
    ) THEN RETURN NULL; END IF;

    -- One statement queues every matching Record for every active plan.
    -- Admitted writers read plan rows without a lock, so concurrent writers
    -- on any plans do not wait on each other; capacity is counted once per
    -- plan, which lets concurrent writers overshoot max_pending by their own
    -- batch at most. A target already queued takes no new capacity.
    WITH matched AS MATERIALIZED (
        SELECT DISTINCT inventory.plan_id,inventory.plan_generation,inventory.max_pending,
               ttl.seconds,input.record_id,'local:'||input.record_id::text AS target
        FROM registry_internal.registry_external_refresh_plans inventory
        CROSS JOIN LATERAL (
            SELECT min(scope.cache_ttl_seconds)::double precision AS seconds
            FROM unnest(inventory.projection_epochs) requested(epoch)
            JOIN registry_internal.registry_external_projection_scopes scope
              ON scope.epoch=requested.epoch AND scope.active
            HAVING count(DISTINCT scope.epoch)=cardinality(inventory.projection_epochs)
        ) ttl
        JOIN jsonb_to_recordset(p_records) AS input(entity_id text,record_id uuid,changed_fields text[])
          ON input.entity_id=inventory.root_entity_id
         AND (cardinality(input.changed_fields)=0 OR inventory.watched_fields && input.changed_fields)
        WHERE inventory.active
    ), ranked AS MATERIALIZED (
        SELECT matched.*,
               EXISTS (SELECT 1 FROM registry_internal.registry_external_refresh_work work
                       WHERE work.plan_id=matched.plan_id AND work.target_digest=matched.target) AS present,
               (SELECT count(*) FROM registry_internal.registry_external_refresh_work work
                WHERE work.plan_id=matched.plan_id
                  AND work.plan_generation=matched.plan_generation) AS pending
        FROM matched
    ), admitted AS MATERIALIZED (
        SELECT ranked.*,
               present OR row_number() OVER (PARTITION BY plan_id,present ORDER BY record_id)
                   <=max_pending-pending AS admit
        FROM ranked
    ), queued AS (
        INSERT INTO registry_internal.registry_external_refresh_work
            (plan_id,plan_generation,kind,record_id,target_digest,expires_at)
        SELECT plan_id,plan_generation,'local',record_id,target,
               clock_timestamp()+make_interval(secs => seconds)
        FROM admitted WHERE admit
        ON CONFLICT (plan_id,target_digest) DO UPDATE SET
            plan_generation=EXCLUDED.plan_generation,
            enqueue_generation=registry_external_refresh_work.enqueue_generation+1,
            attempts=0,ready_at=clock_timestamp(),expires_at=EXCLUDED.expires_at
        RETURNING 1
    ), refused AS (
        -- A Record the full queue refused is reconciled by the next sweep.
        -- Refused writers lock their plan rows in plan order, so two of them
        -- never deadlock, and hold each bump until they commit: a sweep that
        -- starts later re-reads the plan row after this Record is visible,
        -- and a sweep already running sees the higher generation and runs
        -- again. Every refused writer bumps, even on a plan already flagged.
        -- The lock is NO KEY UPDATE: it still holds off a sweep start, while
        -- an admitted writer's foreign-key check on the same plan row does
        -- not wait on it.
        UPDATE registry_internal.registry_external_refresh_plans plan
        SET reconciliation_due=true,reconciliation_generation=reconciliation_generation+1,
            next_due_at=least(next_due_at,clock_timestamp()),updated_at=clock_timestamp()
        WHERE plan.plan_id IN (
            SELECT locked.plan_id FROM registry_internal.registry_external_refresh_plans locked
            WHERE locked.plan_id IN (SELECT plan_id FROM admitted WHERE NOT admit)
            ORDER BY locked.plan_id FOR NO KEY UPDATE)
        RETURNING 1
    )
    SELECT count(*) INTO captured FROM queued;
    RETURN captured;
END $body$;

CREATE OR REPLACE FUNCTION registry_internal.purge_external_refresh_state(p_limit integer)
RETURNS TABLE (purged_kind text,purged_count bigint) LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, registry_internal AS $body$
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='external refresh purge limit is invalid';
    END IF;
    RETURN QUERY WITH plans AS MATERIALIZED (
        SELECT plan_id,plan_generation,active,projection_epochs
        FROM registry_internal.registry_external_refresh_plans
        ORDER BY plan_id FOR UPDATE
    ), expired AS MATERIALIZED (
        SELECT work.work_id,work.plan_id,
               work.expires_at<=clock_timestamp()
                   AND plan.active AND work.plan_generation=plan.plan_generation
                   AND NOT EXISTS (
                       SELECT 1 FROM unnest(plan.projection_epochs) requested(epoch)
                       WHERE NOT EXISTS (
                           SELECT 1 FROM registry_internal.registry_external_projection_scopes scope
                           WHERE scope.epoch=requested.epoch AND scope.active)) AS reconcile
        FROM plans plan
        JOIN registry_internal.registry_external_refresh_work work USING (plan_id)
        WHERE work.expires_at<=clock_timestamp()
           OR NOT plan.active
           OR work.plan_generation<>plan.plan_generation
           OR EXISTS (
               SELECT 1 FROM unnest(plan.projection_epochs) requested(epoch)
               WHERE NOT EXISTS (
                   SELECT 1 FROM registry_internal.registry_external_projection_scopes scope
                   WHERE scope.epoch=requested.epoch AND scope.active))
        ORDER BY work.expires_at,work.work_id LIMIT p_limit
        FOR UPDATE OF work SKIP LOCKED
    ), removed AS (
        DELETE FROM registry_internal.registry_external_refresh_work work USING expired
        WHERE work.work_id=expired.work_id RETURNING expired.plan_id,expired.reconcile
    ), due AS (
        UPDATE registry_internal.registry_external_refresh_plans plan
        SET reconciliation_due=true,
            reconciliation_generation=reconciliation_generation+1,
            next_due_at=least(next_due_at,greatest(
                clock_timestamp()+interval '60 seconds',
                coalesce(sweep_started_at,clock_timestamp())
                    +make_interval(secs => least(interval_seconds,900)::double precision))),
            updated_at=clock_timestamp()
        WHERE plan.plan_id IN (SELECT plan_id FROM removed WHERE reconcile)
        RETURNING plan.plan_id
    ) SELECT 'work',count(*) FROM removed;
    RETURN QUERY WITH retired AS (
        SELECT plan.plan_id FROM registry_internal.registry_external_refresh_plans plan
        WHERE NOT plan.active
          AND plan.updated_at<=clock_timestamp()-interval '24 hours'
          AND NOT EXISTS (SELECT 1 FROM registry_internal.registry_external_refresh_work work
                          WHERE work.plan_id=plan.plan_id)
        ORDER BY plan.plan_id LIMIT p_limit FOR UPDATE SKIP LOCKED
    ), removed AS (
        DELETE FROM registry_internal.registry_external_refresh_plans plan USING retired
        WHERE plan.plan_id=retired.plan_id RETURNING 1
    ) SELECT 'plan',count(*) FROM removed;
END $body$;
"#;

/// One statement admits a source change: it checks the plan's authority and
/// epoch, counts the plan's current work rows against `max_pending`, and
/// upserts the target's work row. A change to an already queued target takes
/// no new capacity; a refused change asks for a sweep instead.
const ENQUEUE_SOURCE_CHANGE_SQL: &str = r#"
WITH plan AS MATERIALIZED (
    SELECT * FROM registry_internal.registry_external_refresh_plans
    WHERE plan_id=$1
), status AS MATERIALIZED (
    SELECT CASE
        WHEN NOT EXISTS (SELECT 1 FROM plan WHERE active AND authority_digest=$2 AND $4=ANY(projection_epochs))
            OR NOT EXISTS (SELECT 1 FROM registry_internal.registry_external_projection_scopes
                           WHERE epoch=$4 AND active)
            THEN 'authority-changed'
        WHEN (SELECT count(*) FROM registry_internal.registry_external_refresh_work work
              JOIN plan USING (plan_id) WHERE work.plan_generation=plan.plan_generation)>=(SELECT max_pending FROM plan)
             AND NOT EXISTS (SELECT 1 FROM registry_internal.registry_external_refresh_work
                             WHERE plan_id=$1 AND target_digest=$3)
            THEN 'capacity'
        ELSE 'accepted' END AS value
), work AS (
    INSERT INTO registry_internal.registry_external_refresh_work
        (plan_id,plan_generation,kind,projection_epoch,selector_scheme,selector,target_digest,expires_at)
    SELECT plan_id,plan_generation,'source',$4,$5,$6,$3,to_timestamp($7::bigint)
    FROM plan CROSS JOIN status WHERE status.value='accepted'
    ON CONFLICT (plan_id,target_digest) DO UPDATE SET
        plan_generation=EXCLUDED.plan_generation,
        enqueue_generation=registry_external_refresh_work.enqueue_generation+1,
        attempts=0,ready_at=clock_timestamp(),expires_at=least(registry_external_refresh_work.expires_at,EXCLUDED.expires_at)
    RETURNING 1
), fallback AS (
    UPDATE registry_internal.registry_external_refresh_plans current
    SET reconciliation_due=true,reconciliation_generation=reconciliation_generation+1,
        next_due_at=least(next_due_at,clock_timestamp()+interval '60 seconds'),
        updated_at=clock_timestamp()
    FROM status
    WHERE current.plan_id=$1 AND status.value='capacity'
    RETURNING 1
)
SELECT CASE WHEN value='accepted' AND NOT EXISTS (SELECT 1 FROM work)
            THEN 'unavailable' ELSE value END
FROM status
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_queue_state_is_backup_excluded_and_keeps_no_receipts() {
        assert_eq!(BACKUP_EXCLUDED_TABLES.len(), 2);
        assert!(BACKUP_EXCLUDED_TABLES
            .iter()
            .all(|table| INSTALL_SQL.contains(table)));
        assert!(!INSTALL_SQL.contains("receipt"));
        assert!(!INDEXES.iter().any(|index| index.contains("receipt")));
    }

    #[test]
    fn plan_registration_rejects_unbounded_and_incomplete_capture_inventory() {
        let mut plan = PlanRegistration {
            plan_id: "plan".to_owned(),
            package_digest: "sha256:package".to_owned(),
            activation_id: Uuid::new_v4(),
            authority_digest: "sha256:authority".to_owned(),
            root_entity_id: "licence".to_owned(),
            watched_fields: BTreeSet::from(["holder".to_owned()]),
            projection_epochs: vec![Uuid::new_v4()],
            interval_seconds: 900,
            page_size: 50,
            max_pending: 10_000,
        };
        assert!(plan.valid());
        plan.watched_fields.clear();
        assert!(!plan.valid());
        plan.watched_fields.insert("holder".to_owned());
        plan.max_pending = 10_001;
        assert!(!plan.valid());
    }

    #[test]
    fn queue_sql_keeps_generation_fences_and_newer_enqueue_protection() {
        assert!(SETTLE_TARGET_SQL.contains("work.enqueue_generation=$6"));
        assert!(SETTLE_TARGET_SQL.contains("plan_generation=$2"));
        assert!(CLAIM_TARGETS_SQL.contains("FOR UPDATE OF work SKIP LOCKED"));
    }

    #[test]
    fn purge_locks_plans_before_bounded_stale_work() {
        let purge = INSTALL_SQL
            .split("CREATE OR REPLACE FUNCTION registry_internal.purge_external_refresh_state")
            .nth(1)
            .unwrap();
        assert!(
            purge.find("ORDER BY plan_id FOR UPDATE").unwrap()
                < purge.find("FOR UPDATE OF work SKIP LOCKED").unwrap()
        );
        assert!(purge.contains("work.plan_generation<>plan.plan_generation"));
        assert!(purge.contains("WHERE reconcile"));
        assert!(purge.contains("plan.updated_at<=clock_timestamp()-interval '24 hours'"));
    }

    #[test]
    fn capture_flags_refused_plans_in_plan_order() {
        let capture = INSTALL_SQL
            .split("CREATE OR REPLACE FUNCTION registry_internal.capture_external_refresh_records")
            .nth(1)
            .unwrap()
            .split("CREATE OR REPLACE FUNCTION")
            .next()
            .unwrap();
        let refused = capture.split("refused AS (").nth(1).unwrap();
        assert!(
            refused.contains("ORDER BY locked.plan_id FOR NO KEY UPDATE"),
            "writers refused on several plans lock them in one order: {refused}"
        );
        assert!(!refused.contains("SKIP LOCKED"), "{refused}");
    }

    #[test]
    fn a_plan_deferred_for_an_invalid_binding_is_a_recorded_outcome() {
        assert!(INSTALL_SQL.contains("'invalid-binding'"));
    }
}

#[cfg(all(test, feature = "postgres-test"))]
mod postgres_tests {
    use super::*;
    use crate::postgres::external_projection::postgres_tests::Activated;

    const EXPIRES_AT: i64 = 4_102_444_800;

    async fn transaction<'a>(
        runtime: &'a mut deadpool_postgres::Client,
        registry: &crate::model::CompiledRegistry,
        expected: &super::super::ExpectedRegistryIdentity,
    ) -> super::super::GuardedTransaction<'a> {
        super::super::begin_registry_transaction(
            runtime,
            super::super::RegistryLockKey::derive(registry.registry_id()).unwrap(),
            Duration::from_secs(2),
            expected,
        )
        .await
        .unwrap()
    }

    fn registration(
        fixture: &Activated,
        plan_id: &str,
        authority_digest: &str,
        projection_epochs: Vec<Uuid>,
    ) -> PlanRegistration {
        PlanRegistration {
            plan_id: plan_id.to_owned(),
            package_digest: fixture.expected.package_digest.clone(),
            activation_id: fixture.expected.activation_uuid().unwrap(),
            authority_digest: authority_digest.to_owned(),
            root_entity_id: "local-record".to_owned(),
            watched_fields: BTreeSet::from(["subject-key".to_owned()]),
            projection_epochs,
            interval_seconds: 900,
            page_size: 50,
            max_pending: 100,
        }
    }

    /// Admit one source change in its own committed transaction.
    async fn admit(
        fixture: &Activated,
        registry: &crate::model::CompiledRegistry,
        projection_epoch: Uuid,
        selector: &str,
    ) -> Result<SourceChangeAdmission, QueueError> {
        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, registry, &fixture.expected).await;
        let admitted = enqueue_source_change(
            &tx,
            "plan",
            "authority",
            &format!("target-{selector}"),
            projection_epoch,
            "urn:test:keys",
            selector,
            EXPIRES_AT,
        )
        .await;
        tx.commit().await.unwrap();
        admitted
    }

    /// Admit the same source change from two transactions, the second
    /// blocked on the plan row lock the first holds. The first sets the
    /// work row's attempts before it commits.
    async fn race_source_change_after_plan_lock(
        fixture: &Activated,
        registry: &crate::model::CompiledRegistry,
        projection_epoch: Uuid,
        selector: &str,
        first_attempts: i16,
    ) -> (bool, Result<SourceChangeAdmission, QueueError>) {
        let (plan_id, authority_digest) = ("plan", "authority");
        let target_digest = format!("target-{selector}");
        let mut first_runtime = fixture.pool.get().await.unwrap();
        let mut second_runtime = fixture.pool.get().await.unwrap();
        let first_tx = transaction(&mut first_runtime, registry, &fixture.expected).await;
        let second_tx = transaction(&mut second_runtime, registry, &fixture.expected).await;
        first_tx
            .transaction()
            .query_one(
                "SELECT 1 FROM registry_internal.registry_external_refresh_plans
                 WHERE plan_id=$1 FOR UPDATE",
                &[&plan_id],
            )
            .await
            .unwrap();
        let second_pid: i32 = second_tx
            .transaction()
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let first_pid: i32 = first_tx
            .transaction()
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let second_admission = enqueue_source_change(
            &second_tx,
            plan_id,
            authority_digest,
            &target_digest,
            projection_epoch,
            "urn:test:keys",
            selector,
            EXPIRES_AT,
        );
        let commit_first = async {
            let waited = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let waiting: bool = fixture
                        .database
                        .admin
                        .query_one(
                            "SELECT $2=ANY(pg_blocking_pids($1))",
                            &[&second_pid, &first_pid],
                        )
                        .await
                        .unwrap()
                        .get(0);
                    if waiting {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .is_ok();
            let admitted = enqueue_source_change(
                &first_tx,
                plan_id,
                authority_digest,
                &target_digest,
                projection_epoch,
                "urn:test:keys",
                selector,
                EXPIRES_AT,
            )
            .await;
            first_tx
                .transaction()
                .execute(
                    "UPDATE registry_internal.registry_external_refresh_work
                     SET attempts=$3 WHERE plan_id=$1 AND target_digest=$2",
                    &[&plan_id, &target_digest, &first_attempts],
                )
                .await
                .unwrap();
            let committed = first_tx.commit().await;
            (waited, admitted, committed)
        };
        let (second_admission, (waited, first_admission, first_commit)) =
            tokio::join!(second_admission, commit_first);
        assert_eq!(first_admission.unwrap(), SourceChangeAdmission::Accepted);
        first_commit.unwrap();
        second_tx.commit().await.unwrap();
        drop(first_runtime);
        drop(second_runtime);
        (waited, second_admission)
    }

    #[tokio::test]
    async fn local_capture_skips_when_any_required_epoch_is_inactive() {
        let registry = super::super::external_view_query::tests::registry();
        let fixture = Activated::new(&registry).await;
        let primary = fixture
            .bind(&registry, "projection", "binding", "grant", 60)
            .await
            .unwrap();
        let secondary_epoch = Uuid::new_v4();
        fixture
            .migration
            .execute(
                "INSERT INTO registry_internal.registry_external_projection_scopes
                    (projection_id,epoch,binding_digest,grant_digest,cache_ttl_seconds)
                 VALUES ('secondary',$1,'secondary-binding','secondary-grant',60)",
                &[&secondary_epoch],
            )
            .await
            .unwrap();
        let registration = registration(
            &fixture,
            "plan",
            "authority",
            vec![primary.epoch, secondary_epoch],
        );
        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        register_plans(&tx, &[registration]).await.unwrap();
        tx.commit().await.unwrap();

        fixture
            .migration
            .execute(
                "UPDATE registry_internal.registry_external_projection_scopes
                 SET active=false WHERE epoch=$1 OR epoch=$2",
                &[&primary.epoch, &secondary_epoch],
            )
            .await
            .unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        assert_eq!(
            capture_local_record(
                tx.transaction(),
                "local-record",
                Uuid::new_v4(),
                &BTreeSet::from(["subject-key".to_owned()]),
            )
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            tx.transaction()
                .query_one("SELECT 1", &[])
                .await
                .unwrap()
                .get::<_, i32>(0),
            1,
            "capture must not abort the authoritative write transaction"
        );
        tx.rollback().await.unwrap();

        fixture
            .migration
            .execute(
                "UPDATE registry_internal.registry_external_projection_scopes
                 SET active=true WHERE epoch=$1",
                &[&primary.epoch],
            )
            .await
            .unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        assert_eq!(
            capture_local_record(
                tx.transaction(),
                "local-record",
                Uuid::new_v4(),
                &BTreeSet::from(["subject-key".to_owned()]),
            )
            .await
            .unwrap(),
            0,
            "an inactive required label epoch must suppress the parent capture"
        );
        tx.commit().await.unwrap();
        drop(runtime);
        let queued: i64 = fixture
            .migration
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_external_refresh_work",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(queued, 0);
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn source_change_admission_updates_the_work_row_committed_while_it_waited() {
        let registry = super::super::external_view_query::tests::registry();
        let fixture = Activated::new(&registry).await;
        let scope = fixture
            .bind(&registry, "projection", "binding", "grant", 60)
            .await
            .unwrap();
        let registration = registration(&fixture, "plan", "authority", vec![scope.epoch]);
        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        register_plans(&tx, &[registration]).await.unwrap();
        tx.commit().await.unwrap();
        drop(runtime);

        let (waited, admitted) =
            race_source_change_after_plan_lock(&fixture, &registry, scope.epoch, "subject", 3)
                .await;
        assert!(
            waited,
            "the second admission must wait on the plan row lock"
        );
        assert_eq!(admitted.unwrap(), SourceChangeAdmission::Accepted);
        let rows = fixture
            .migration
            .query(
                "SELECT enqueue_generation,attempts
                 FROM registry_internal.registry_external_refresh_work
                 WHERE plan_id='plan' AND target_digest='target-subject'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "both admissions share one work row");
        assert_eq!(rows[0].get::<_, i64>(0), 2);
        assert_eq!(
            rows[0].get::<_, i16>(1),
            0,
            "a newer source change restarts the retry budget"
        );
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn source_change_capacity_counts_pending_work_rows() {
        let registry = super::super::external_view_query::tests::registry();
        let fixture = Activated::new(&registry).await;
        let scope = fixture
            .bind(&registry, "projection", "binding", "grant", 60)
            .await
            .unwrap();
        let mut registration = registration(&fixture, "plan", "authority", vec![scope.epoch]);
        registration.max_pending = 2;
        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        register_plans(&tx, &[registration]).await.unwrap();
        tx.transaction()
            .execute(
                "UPDATE registry_internal.registry_external_refresh_plans
                 SET reconciliation_due=false,next_due_at=clock_timestamp()+interval '1 hour'",
                &[],
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        drop(runtime);

        for selector in ["first", "first", "second"] {
            assert_eq!(
                admit(&fixture, &registry, scope.epoch, selector).await,
                Ok(SourceChangeAdmission::Accepted),
                "{selector}"
            );
        }
        assert_eq!(
            admit(&fixture, &registry, scope.epoch, "third").await,
            Ok(SourceChangeAdmission::AtCapacity)
        );
        assert_eq!(
            admit(&fixture, &registry, scope.epoch, "first").await,
            Ok(SourceChangeAdmission::Accepted),
            "a change to a queued target takes no new capacity"
        );
        let state = fixture
            .migration
            .query_one(
                "SELECT (SELECT count(*) FROM registry_internal.registry_external_refresh_work
                         WHERE plan_id='plan'),
                        reconciliation_due,next_due_at<=clock_timestamp()+interval '60 seconds'
                 FROM registry_internal.registry_external_refresh_plans WHERE plan_id='plan'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(state.get::<_, i64>(0), 2);
        assert!(state.get::<_, bool>(1), "a refused change asks for a sweep");
        assert!(state.get::<_, bool>(2), "the sweep is due within a minute");
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn durable_queue_fences_newer_enqueues_and_authority_changes() {
        let registry = super::super::external_view_query::tests::registry();
        let fixture = Activated::new(&registry).await;
        let scope = fixture
            .bind(&registry, "projection", "binding", "grant", 60)
            .await
            .unwrap();
        let authority = "sha256:plan-authority";
        let registration = PlanRegistration {
            plan_id: "plan".to_owned(),
            package_digest: fixture.expected.package_digest.clone(),
            activation_id: Uuid::parse_str(&fixture.expected.activation_id).unwrap(),
            authority_digest: authority.to_owned(),
            root_entity_id: "local-record".to_owned(),
            watched_fields: BTreeSet::from(["subject-key".to_owned()]),
            projection_epochs: vec![scope.epoch],
            interval_seconds: 900,
            page_size: 50,
            max_pending: 10_000,
        };
        let record_id = Uuid::new_v4();
        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        register_plans(&tx, std::slice::from_ref(&registration))
            .await
            .unwrap();
        assert_eq!(
            capture_local_record(
                tx.transaction(),
                "local-record",
                record_id,
                &BTreeSet::from(["subject-key".to_owned()])
            )
            .await
            .unwrap(),
            1
        );
        let lease = claim_plan(&tx, "plan", authority, Duration::from_secs(120))
            .await
            .unwrap()
            .unwrap();
        let state = load_step_state(&tx, "plan", authority, lease)
            .await
            .unwrap();
        assert!(state.sweep_due);
        assert!(state.has_ready_targets);
        let claimed = claim_targets(&tx, "plan", lease).await.unwrap();
        assert_eq!(claimed.len(), 1);
        guard_plan_lease(
            &tx,
            "plan",
            authority,
            Some(scope.epoch),
            lease,
            Some((claimed[0].work_id, claimed[0].enqueue_generation)),
        )
        .await
        .unwrap();
        // A second commit for the same root wins over the leased generation.
        capture_local_record(
            tx.transaction(),
            "local-record",
            record_id,
            &BTreeSet::from(["subject-key".to_owned()]),
        )
        .await
        .unwrap();
        assert_eq!(
            settle_target(&tx, "plan", lease, &claimed[0], Settlement::Published)
                .await
                .unwrap_err(),
            QueueError::StaleLease
        );
        finish_step(
            &tx,
            "plan",
            authority,
            lease,
            StepKind::Targets,
            &state.checkpoint,
            "targets",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        drop(runtime);

        let pending: i64 = fixture
            .migration
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_external_refresh_work WHERE plan_id='plan'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(pending, 1);

        fixture
            .migration
            .execute(
                "UPDATE registry_internal.registry_external_refresh_work
                 SET attempts=4 WHERE plan_id='plan'",
                &[],
            )
            .await
            .unwrap();
        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        let lease = claim_plan(&tx, "plan", authority, Duration::from_secs(120))
            .await
            .unwrap()
            .unwrap();
        let state = load_step_state(&tx, "plan", authority, lease)
            .await
            .unwrap();
        let claimed = claim_targets(&tx, "plan", lease).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].attempts, 5);
        retry_target(&tx, "plan", lease, &claimed[0]).await.unwrap();
        finish_step(
            &tx,
            "plan",
            authority,
            lease,
            StepKind::Targets,
            &state.checkpoint,
            "targets",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        drop(runtime);

        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        assert_eq!(
            capture_local_record(
                tx.transaction(),
                "local-record",
                Uuid::new_v4(),
                &BTreeSet::from(["subject-key".to_owned()]),
            )
            .await
            .unwrap(),
            1
        );
        let mut changed = registration;
        changed.authority_digest = "sha256:rotated-authority".to_owned();
        register_plans(&tx, &[changed]).await.unwrap();
        tx.commit().await.unwrap();
        drop(runtime);
        let pending: i64 = fixture
            .migration
            .query_one(
                "SELECT count(*)
                 FROM registry_internal.registry_external_refresh_work work
                 JOIN registry_internal.registry_external_refresh_plans plan USING (plan_id)
                 WHERE work.plan_id='plan' AND work.plan_generation=plan.plan_generation",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(pending, 0);
        let retained: i64 = fixture
            .migration
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_external_refresh_work
                 WHERE plan_id='plan'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(retained, 1);
        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        let purged = purge_expired(&tx, 1000).await.unwrap();
        assert_eq!(purged.work, 1);
        assert_eq!(purged.plans, 0);
        tx.commit().await.unwrap();
        drop(runtime);
        let retained: i64 = fixture
            .migration
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_external_refresh_work
                 WHERE plan_id='plan'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(retained, 0);
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn schedule_edits_recalculate_due_time_and_authority_changes_restart_at_roots() {
        let registry = super::super::external_view_query::tests::registry();
        let fixture = Activated::new(&registry).await;
        let scope = fixture
            .bind(&registry, "projection", "binding", "grant", 60)
            .await
            .unwrap();
        let mut plan = PlanRegistration {
            plan_id: "plan".to_owned(),
            package_digest: fixture.expected.package_digest.clone(),
            activation_id: fixture.expected.activation_uuid().unwrap(),
            authority_digest: "original-authority".to_owned(),
            root_entity_id: "local-record".to_owned(),
            watched_fields: BTreeSet::from(["subject-key".to_owned()]),
            projection_epochs: vec![scope.epoch],
            interval_seconds: 900,
            page_size: 50,
            max_pending: 100,
        };
        // A cached epoch keeps its schedule across registration.
        fixture.cache(&scope).await;
        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        register_plans(&tx, std::slice::from_ref(&plan))
            .await
            .unwrap();
        tx.transaction()
            .execute(
                "UPDATE registry_internal.registry_external_refresh_plans SET
                sweep_phase='complete',sweep_started_at=clock_timestamp()-interval '5 minutes',
                last_completed_at=clock_timestamp()-interval '4 minutes',
                next_due_at=clock_timestamp()+interval '10 minutes',reconciliation_due=false",
                &[],
            )
            .await
            .unwrap();
        plan.interval_seconds = 120;
        register_plans(&tx, std::slice::from_ref(&plan))
            .await
            .unwrap();
        let state = tx.transaction().query_one(
            "SELECT plan_generation,projection_epochs,next_due_at<=clock_timestamp(),sweep_phase
             FROM registry_internal.registry_external_refresh_plans WHERE plan_id='plan'",
            &[],
        ).await.unwrap();
        assert_eq!(state.get::<_, i64>(0), 1);
        assert_eq!(state.get::<_, Vec<Uuid>>(1), vec![scope.epoch]);
        assert!(
            state.get::<_, bool>(2),
            "shorter interval takes effect immediately"
        );
        assert_eq!(state.get::<_, &str>(3), "complete");

        let lease = claim_plan(
            &tx,
            "plan",
            &plan.authority_digest,
            Duration::from_secs(120),
        )
        .await
        .unwrap()
        .unwrap();
        tx.transaction()
            .execute(
                "UPDATE registry_internal.registry_external_refresh_plans SET
                sweep_phase='labels',sweep_baseline=0,sweep_reconciliation_generation=1,
                reconciliation_generation=2",
                &[],
            )
            .await
            .unwrap();
        let labels = prepare_sweep(&tx, "plan", &plan.authority_digest, lease, 42)
            .await
            .unwrap();
        assert_eq!(labels.phase, "labels");
        assert_eq!(labels.baseline_sequence, 42);
        let state = tx
            .transaction()
            .query_one(
                "SELECT sweep_started_at<clock_timestamp()-interval '4 minutes',
                    reconciliation_generation>sweep_reconciliation_generation
             FROM registry_internal.registry_external_refresh_plans WHERE plan_id='plan'",
                &[],
            )
            .await
            .unwrap();
        assert!(
            state.get::<_, bool>(0),
            "labels preserve the start of the root traversal"
        );
        assert!(
            state.get::<_, bool>(1),
            "labels preserve reconciliation requested during the root traversal"
        );

        // A saved label phase must never carry across a new authority. Its
        // root phase was run under the old policy and proves nothing now.
        tx.transaction()
            .execute(
                "UPDATE registry_internal.registry_external_refresh_plans SET
                sweep_phase='labels',sweep_baseline=42,sweep_continuation='sealed-fixture-position',
                sweep_acquisition_failures=1",
                &[],
            )
            .await
            .unwrap();
        plan.authority_digest = "changed-authority".to_owned();
        register_plans(&tx, std::slice::from_ref(&plan))
            .await
            .unwrap();
        let state = tx
            .transaction()
            .query_one(
                "SELECT plan_generation,sweep_phase,sweep_baseline,sweep_continuation IS NULL,
                    sweep_acquisition_failures,last_completed_at IS NULL
             FROM registry_internal.registry_external_refresh_plans WHERE plan_id='plan'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(state.get::<_, i64>(0), 2);
        assert_eq!(state.get::<_, &str>(1), "roots");
        assert_eq!(state.get::<_, i64>(2), 0);
        assert!(state.get::<_, bool>(3));
        assert_eq!(state.get::<_, i64>(4), 0);
        assert!(state.get::<_, bool>(5));
        tx.commit().await.unwrap();
        drop(runtime);
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn a_bad_key_that_exhausts_its_retries_does_not_make_the_plan_due_within_a_minute() {
        let registry = super::super::external_view_query::tests::registry();
        let fixture = Activated::new(&registry).await;
        let scope = fixture
            .bind(&registry, "projection", "binding", "grant", 60)
            .await
            .unwrap();
        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        register_plans(
            &tx,
            &[registration(
                &fixture,
                "plan",
                "authority",
                vec![scope.epoch],
            )],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // A sweep meets one key it cannot acquire and queues it for retry.
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        let lease = claim_plan(&tx, "plan", "authority", Duration::from_secs(120))
            .await
            .unwrap()
            .unwrap();
        prepare_sweep(&tx, "plan", "authority", lease, 1)
            .await
            .unwrap();
        assert_eq!(
            enqueue_sweep_retry(
                &tx,
                "plan",
                "authority",
                lease,
                "target-bad",
                scope.epoch,
                "urn:test:keys",
                "bad",
                EXPIRES_AT,
            )
            .await,
            Ok(true)
        );
        finish_step(
            &tx,
            "plan",
            "authority",
            lease,
            StepKind::Sweep,
            &SweepCheckpoint {
                phase: "complete".to_owned(),
                baseline_sequence: 1,
                continuation: None,
                completed: true,
                acquisition_failures: 1,
            },
            "sweep-with-failures",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        drop(runtime);

        // Its last retry is ready and fails again.
        fixture
            .migration
            .execute(
                "UPDATE registry_internal.registry_external_refresh_work
                 SET ready_at=clock_timestamp()-interval '1 second',attempts=3",
                &[],
            )
            .await
            .unwrap();
        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        let lease = claim_plan(&tx, "plan", "authority", Duration::from_secs(120))
            .await
            .unwrap()
            .unwrap();
        let state = load_step_state(&tx, "plan", "authority", lease)
            .await
            .unwrap();
        assert_eq!(state.next, StepKind::Targets);
        let claimed = claim_targets(&tx, "plan", lease).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].attempts, 4);
        retry_target(&tx, "plan", lease, &claimed[0]).await.unwrap();
        finish_step(
            &tx,
            "plan",
            "authority",
            lease,
            StepKind::Targets,
            &state.checkpoint,
            "targets",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        drop(runtime);

        let state = fixture
            .migration
            .query_one(
                "SELECT next_due_at>clock_timestamp()+interval '60 seconds',
                        next_due_at>=sweep_started_at+interval '900 seconds',
                        reconciliation_due,
                        (SELECT count(*) FROM registry_internal.registry_external_refresh_work)
                 FROM registry_internal.registry_external_refresh_plans WHERE plan_id='plan'",
                &[],
            )
            .await
            .unwrap();
        assert!(
            state.get::<_, bool>(0),
            "giving up on one key must not start another sweep within a minute"
        );
        assert!(
            state.get::<_, bool>(1),
            "the next sweep starts no sooner than the sweep floor"
        );
        assert!(
            state.get::<_, bool>(2),
            "giving up still asks the next sweep to reconcile"
        );
        assert_eq!(state.get::<_, i64>(3), 0, "the exhausted key is settled");
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn a_sweep_retry_refused_at_capacity_does_not_reschedule_the_sweep() {
        let registry = super::super::external_view_query::tests::registry();
        let fixture = Activated::new(&registry).await;
        let scope = fixture
            .bind(&registry, "projection", "binding", "grant", 60)
            .await
            .unwrap();
        let mut plan = registration(&fixture, "plan", "authority", vec![scope.epoch]);
        plan.max_pending = 1;
        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        register_plans(&tx, &[plan]).await.unwrap();
        assert_eq!(
            capture_local_record(
                tx.transaction(),
                "local-record",
                Uuid::new_v4(),
                &BTreeSet::from(["subject-key".to_owned()]),
            )
            .await
            .unwrap(),
            1
        );
        tx.commit().await.unwrap();

        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        let lease = claim_plan(&tx, "plan", "authority", Duration::from_secs(120))
            .await
            .unwrap()
            .unwrap();
        prepare_sweep(&tx, "plan", "authority", lease, 1)
            .await
            .unwrap();
        const STATE: &str = "SELECT reconciliation_generation,next_due_at::text,
                (SELECT count(*) FROM registry_internal.registry_external_refresh_work)
             FROM registry_internal.registry_external_refresh_plans WHERE plan_id='plan'";
        let before = tx.transaction().query_one(STATE, &[]).await.unwrap();
        assert_eq!(
            enqueue_sweep_retry(
                &tx,
                "plan",
                "authority",
                lease,
                "target-refused",
                scope.epoch,
                "urn:test:keys",
                "refused",
                EXPIRES_AT,
            )
            .await,
            Ok(false)
        );
        let after = tx.transaction().query_one(STATE, &[]).await.unwrap();
        assert_eq!(
            after.get::<_, i64>(0),
            before.get::<_, i64>(0),
            "the running sweep already reconciles; a refused retry asks for nothing more"
        );
        assert_eq!(after.get::<_, &str>(1), before.get::<_, &str>(1));
        assert_eq!(after.get::<_, i64>(2), 1, "the full queue takes no retry");
        tx.rollback().await.unwrap();
        drop(runtime);
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn concurrent_record_writers_capture_without_waiting_on_plan_rows() {
        let registry = super::super::external_view_query::tests::registry();
        let fixture = Activated::new(&registry).await;
        let scope = fixture
            .bind(&registry, "projection", "binding", "grant", 60)
            .await
            .unwrap();
        let fields = BTreeSet::from(["subject-key".to_owned()]);
        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        register_plans(
            &tx,
            &[
                registration(&fixture, "plan-a", "authority", vec![scope.epoch]),
                registration(&fixture, "plan-b", "authority", vec![scope.epoch]),
            ],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        drop(runtime);

        let mut first_runtime = fixture.pool.get().await.unwrap();
        let mut second_runtime = fixture.pool.get().await.unwrap();
        let first = transaction(&mut first_runtime, &registry, &fixture.expected).await;
        assert_eq!(
            capture_local_record(first.transaction(), "local-record", Uuid::new_v4(), &fields)
                .await
                .unwrap(),
            2
        );
        let second = transaction(&mut second_runtime, &registry, &fixture.expected).await;
        second
            .transaction()
            .batch_execute("SET LOCAL lock_timeout='200ms'")
            .await
            .unwrap();
        assert_eq!(
            capture_local_record(
                second.transaction(),
                "local-record",
                Uuid::new_v4(),
                &fields
            )
            .await,
            Ok(2),
            "a second writer must not wait on plan rows the first writer touched"
        );
        second.commit().await.unwrap();
        first.commit().await.unwrap();
        drop(first_runtime);
        drop(second_runtime);
        let queued: i64 = fixture
            .migration
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_external_refresh_work",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(queued, 4);
        fixture.cleanup().await;
    }

    /// A writer refused at capacity keeps the plan row it flagged until it
    /// commits. A sweep cannot start between the first refused writer's
    /// commit and the second's, so the sweep that reconciles both reads the
    /// second writer's Record or sees its reconciliation generation bump.
    #[tokio::test]
    async fn a_writer_refused_at_capacity_holds_its_plan_flag_until_it_commits() {
        let registry = super::super::external_view_query::tests::registry();
        let fixture = Activated::new(&registry).await;
        let scope = fixture
            .bind(&registry, "projection", "binding", "grant", 60)
            .await
            .unwrap();
        let fields = BTreeSet::from(["subject-key".to_owned()]);
        let mut plan = registration(&fixture, "plan", "authority", vec![scope.epoch]);
        plan.max_pending = 1;
        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        register_plans(&tx, &[plan]).await.unwrap();
        assert_eq!(
            capture_local_record(tx.transaction(), "local-record", Uuid::new_v4(), &fields)
                .await
                .unwrap(),
            1
        );
        tx.transaction()
            .execute(
                "UPDATE registry_internal.registry_external_refresh_plans
                 SET reconciliation_due=false,next_due_at=clock_timestamp()",
                &[],
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        const GENERATION: &str = "SELECT reconciliation_generation
             FROM registry_internal.registry_external_refresh_plans WHERE plan_id='plan'";
        let before: i64 = fixture
            .migration
            .query_one(GENERATION, &[])
            .await
            .unwrap()
            .get(0);
        // The fixture pool holds two runtime connections; the worker reuses
        // the first writer's connection after that writer commits.
        drop(runtime);

        let mut first_runtime = fixture.pool.get().await.unwrap();
        let mut second_runtime = fixture.pool.get().await.unwrap();
        let first = transaction(&mut first_runtime, &registry, &fixture.expected).await;
        assert_eq!(
            capture_local_record(first.transaction(), "local-record", Uuid::new_v4(), &fields)
                .await
                .unwrap(),
            0,
            "the full queue refuses the first writer"
        );
        let second = transaction(&mut second_runtime, &registry, &fixture.expected).await;
        let second_pid: i32 = second
            .transaction()
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let second_record = Uuid::new_v4();
        let second_capture =
            capture_local_record(second.transaction(), "local-record", second_record, &fields);
        let commit_first = async {
            let waited = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let waiting: bool = fixture
                        .database
                        .admin
                        .query_one("SELECT cardinality(pg_blocking_pids($1))>0", &[&second_pid])
                        .await
                        .unwrap()
                        .get(0);
                    if waiting {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .is_ok();
            first.commit().await.unwrap();
            waited
        };
        let (second_captured, waited) = tokio::join!(second_capture, commit_first);
        assert!(waited, "the second refused writer waits for the first");
        assert_eq!(
            second_captured,
            Ok(0),
            "the full queue refuses the second writer"
        );

        // The worker cannot start a sweep until the second writer commits.
        let worker = transaction(&mut first_runtime, &registry, &fixture.expected).await;
        worker
            .transaction()
            .batch_execute("SET LOCAL lock_timeout='200ms'")
            .await
            .unwrap();
        assert!(
            matches!(
                claim_plan(&worker, "plan", "authority", Duration::from_secs(120)).await,
                Err(QueueError::Unavailable)
            ),
            "a sweep start waits on the second writer's flag"
        );
        worker.rollback().await.unwrap();
        second.commit().await.unwrap();
        drop(first_runtime);
        drop(second_runtime);
        let after: i64 = fixture
            .migration
            .query_one(GENERATION, &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            after,
            before + 2,
            "each refused writer bumps the generation"
        );
        fixture.cleanup().await;
    }

    /// A refused writer's plan lock does not stop an admitted writer on the
    /// same plan from queueing its Record: the admitted writer's reference to
    /// the plan row does not wait on the flag, while a sweep start still does.
    #[tokio::test]
    async fn an_admitted_writer_does_not_wait_on_a_refused_writer_of_its_plan() {
        let registry = super::super::external_view_query::tests::registry();
        let fixture = Activated::new(&registry).await;
        let scope = fixture
            .bind(&registry, "projection", "binding", "grant", 60)
            .await
            .unwrap();
        let fields = BTreeSet::from(["subject-key".to_owned()]);
        let mut plan = registration(&fixture, "plan", "authority", vec![scope.epoch]);
        plan.max_pending = 1;
        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        register_plans(&tx, &[plan]).await.unwrap();
        tx.commit().await.unwrap();
        drop(runtime);

        let mut first_runtime = fixture.pool.get().await.unwrap();
        let mut second_runtime = fixture.pool.get().await.unwrap();
        // The first writer fills the plan's one slot and is refused for its
        // second Record, so it holds the plan flag until it commits.
        let first = transaction(&mut first_runtime, &registry, &fixture.expected).await;
        let capture = |record_id| LocalRecordCapture {
            entity_id: "local-record".to_owned(),
            record_id,
            changed_fields: fields.clone(),
        };
        assert_eq!(
            capture_local_records(
                first.transaction(),
                &[capture(Uuid::new_v4()), capture(Uuid::new_v4())]
            )
            .await,
            Ok(1)
        );
        // The second writer still sees the slot free and is admitted.
        let second = transaction(&mut second_runtime, &registry, &fixture.expected).await;
        second
            .transaction()
            .batch_execute("SET LOCAL lock_timeout='200ms'")
            .await
            .unwrap();
        assert_eq!(
            capture_local_record(
                second.transaction(),
                "local-record",
                Uuid::new_v4(),
                &fields
            )
            .await,
            Ok(1),
            "an admitted writer does not wait on the refused writer's plan lock"
        );
        second.commit().await.unwrap();

        let worker = transaction(&mut second_runtime, &registry, &fixture.expected).await;
        worker
            .transaction()
            .batch_execute("SET LOCAL lock_timeout='200ms'")
            .await
            .unwrap();
        assert!(
            matches!(
                claim_plan(&worker, "plan", "authority", Duration::from_secs(120)).await,
                Err(QueueError::Unavailable)
            ),
            "a sweep start waits on the refused writer's flag"
        );
        worker.rollback().await.unwrap();
        first.commit().await.unwrap();
        drop(first_runtime);
        drop(second_runtime);
        let queued: i64 = fixture
            .migration
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_external_refresh_work",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(queued, 2, "both admitted Records are queued");
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn registration_of_a_plan_whose_epoch_has_no_snapshots_makes_it_due_now() {
        let registry = super::super::external_view_query::tests::registry();
        let fixture = Activated::new(&registry).await;
        let scope = fixture
            .bind(&registry, "projection", "binding", "grant", 60)
            .await
            .unwrap();
        let plan = registration(&fixture, "plan", "authority", vec![scope.epoch]);
        const PARK: &str = "UPDATE registry_internal.registry_external_refresh_plans SET
            next_due_at=clock_timestamp()+interval '1 hour',sweep_phase='labels',sweep_baseline=42,
            sweep_continuation='sealed-fixture-position',sweep_acquisition_failures=1,
            sweep_started_at=clock_timestamp()-interval '5 minutes',lease_token=gen_random_uuid(),
            lease_expires_at=clock_timestamp()+interval '1 hour',reconciliation_due=false";
        const STATE: &str = "SELECT next_due_at<=clock_timestamp(),sweep_phase,sweep_baseline,
                sweep_continuation IS NULL,sweep_acquisition_failures,lease_token IS NULL,
                plan_generation
             FROM registry_internal.registry_external_refresh_plans WHERE plan_id='plan'";
        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        register_plans(&tx, std::slice::from_ref(&plan))
            .await
            .unwrap();
        tx.commit().await.unwrap();

        fixture.migration.execute(PARK, &[]).await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        register_plans(&tx, std::slice::from_ref(&plan))
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let state = fixture.migration.query_one(STATE, &[]).await.unwrap();
        assert!(state.get::<_, bool>(0), "an empty epoch is due now");
        assert_eq!(state.get::<_, &str>(1), "roots");
        assert_eq!(state.get::<_, i64>(2), 0);
        assert!(state.get::<_, bool>(3));
        assert_eq!(state.get::<_, i64>(4), 0);
        assert!(
            state.get::<_, bool>(5),
            "the sweep restarts under a new lease"
        );
        assert_eq!(state.get::<_, i64>(6), 1, "the authority is unchanged");

        // Once the epoch holds a snapshot, registration keeps the schedule.
        fixture.cache(&scope).await;
        fixture.migration.execute(PARK, &[]).await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        register_plans(&tx, std::slice::from_ref(&plan))
            .await
            .unwrap();
        tx.commit().await.unwrap();
        drop(runtime);
        let state = fixture.migration.query_one(STATE, &[]).await.unwrap();
        assert!(!state.get::<_, bool>(0));
        assert_eq!(state.get::<_, &str>(1), "labels");
        assert_eq!(state.get::<_, i64>(2), 42);
        assert!(!state.get::<_, bool>(3));
        assert_eq!(state.get::<_, i64>(4), 1);
        assert!(!state.get::<_, bool>(5));
        assert_eq!(state.get::<_, i64>(6), 1);
        fixture.cleanup().await;
    }

    #[tokio::test]
    async fn install_keeps_no_lease_on_work_rows() {
        let registry = super::super::external_view_query::tests::registry();
        let fixture = Activated::new(&registry).await;
        let scope = fixture
            .bind(&registry, "projection", "binding", "grant", 60)
            .await
            .unwrap();
        let catalog = fixture
            .migration
            .query_one(
                "SELECT
                    (SELECT count(*) FROM information_schema.columns
                     WHERE table_schema='registry_internal'
                       AND table_name='registry_external_refresh_work'
                       AND column_name LIKE 'lease%'),
                    EXISTS (SELECT 1 FROM pg_constraint
                            WHERE conname='registry_external_refresh_work_lease_pair'),
                    (SELECT indpred IS NULL FROM pg_index
                     WHERE indexrelid='registry_internal.registry_external_refresh_work_due_idx'::regclass)",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(catalog.get::<_, i64>(0), 0, "work rows carry no lease");
        assert!(!catalog.get::<_, bool>(1));
        assert!(
            catalog.get::<_, bool>(2),
            "the due index covers every work row"
        );

        let mut runtime = fixture.pool.get().await.unwrap();
        let tx = transaction(&mut runtime, &registry, &fixture.expected).await;
        register_plans(
            &tx,
            &[registration(
                &fixture,
                "plan",
                "authority",
                vec![scope.epoch],
            )],
        )
        .await
        .unwrap();
        capture_local_record(
            tx.transaction(),
            "local-record",
            Uuid::new_v4(),
            &BTreeSet::from(["subject-key".to_owned()]),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        drop(runtime);
        fixture
            .migration
            .execute(
                "UPDATE registry_internal.registry_external_refresh_work SET attempts=6",
                &[],
            )
            .await
            .unwrap();
        assert!(fixture
            .migration
            .execute(
                "UPDATE registry_internal.registry_external_refresh_work SET attempts=-1",
                &[],
            )
            .await
            .is_err());
        fixture.cleanup().await;
    }
}

// SPDX-License-Identifier: Apache-2.0

//! Durable, fenced work for managed external-projection refresh plans.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use tokio_postgres::GenericClient;
use uuid::Uuid;

use super::{GuardedTransaction, RuntimeRevoke, SqlIdentifier};

const DEFAULT_RECEIPT_RETENTION_SECONDS: i64 = 24 * 60 * 60;
const MAX_KEY_BYTES: usize = 1024;

#[cfg(test)]
pub(crate) const TABLES: &[&str] = &[
    "registry_internal.registry_external_refresh_plans",
    "registry_internal.registry_external_refresh_work",
    "registry_internal.registry_external_refresh_receipts",
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
    (
        "registry_internal.registry_external_refresh_receipts",
        &["DELETE", "INSERT", "SELECT", "UPDATE"],
    ),
];

pub(crate) const WORK_SEQUENCE: &str =
    "registry_internal.registry_external_refresh_work_work_id_seq";

#[cfg(test)]
pub(crate) const BACKUP_EXCLUDED_TABLES: &[&str] = TABLES;

pub(crate) const INDEXES: &[&str] = &[
    "registry_internal.registry_external_refresh_work_due_idx",
    "registry_internal.registry_external_refresh_receipts_expiry_idx",
    "registry_internal.registry_external_refresh_plan_capture_idx",
];

/// Entries are (identity, result type, returns set, security definer, runtime execute).
pub(crate) const MANAGED_FUNCTIONS: &[(&str, &str, bool, bool, bool)] = &[
    (
        "registry_internal.capture_external_refresh_record(p_entity text, p_record uuid, p_changed text[])",
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
    "registry_internal.capture_external_refresh_record(text,uuid,text[])",
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
    #[error("external refresh queue is at capacity")]
    AtCapacity,
    #[error("external refresh hint conflicts with an accepted receipt")]
    Conflict,
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
    SourceHint {
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
            Self::SourceHint { .. } => formatter.write_str("source-hint"),
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
pub(crate) enum HintAdmission {
    Accepted,
    Duplicate,
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
    pub(crate) receipts: u64,
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
        let epochs = plan.projection_epochs.iter().copied().collect::<Vec<_>>();
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
    plan_generation=current.plan_generation + CASE WHEN
        current.package_digest<>EXCLUDED.package_digest
        OR current.activation_id<>EXCLUDED.activation_id
        OR current.authority_digest<>EXCLUDED.authority_digest
        OR current.projection_epochs<>EXCLUDED.projection_epochs
        OR current.root_entity_id<>EXCLUDED.root_entity_id
        OR current.watched_fields<>EXCLUDED.watched_fields THEN 1 ELSE 0 END,
    next_due_at=CASE WHEN NOT current.active
        OR current.package_digest<>EXCLUDED.package_digest
        OR current.activation_id<>EXCLUDED.activation_id
        OR current.authority_digest<>EXCLUDED.authority_digest
        OR current.projection_epochs<>EXCLUDED.projection_epochs
        OR current.root_entity_id<>EXCLUDED.root_entity_id
        OR current.watched_fields<>EXCLUDED.watched_fields
        THEN clock_timestamp() ELSE current.next_due_at END,
    reconciliation_due=current.reconciliation_due OR NOT current.active
        OR current.package_digest<>EXCLUDED.package_digest
        OR current.activation_id<>EXCLUDED.activation_id
        OR current.authority_digest<>EXCLUDED.authority_digest
        OR current.projection_epochs<>EXCLUDED.projection_epochs
        OR current.root_entity_id<>EXCLUDED.root_entity_id
        OR current.watched_fields<>EXCLUDED.watched_fields,
    reconciliation_generation=current.reconciliation_generation + CASE WHEN
        NOT current.active
        OR current.package_digest<>EXCLUDED.package_digest
        OR current.activation_id<>EXCLUDED.activation_id
        OR current.authority_digest<>EXCLUDED.authority_digest
        OR current.projection_epochs<>EXCLUDED.projection_epochs
        OR current.root_entity_id<>EXCLUDED.root_entity_id
        OR current.watched_fields<>EXCLUDED.watched_fields THEN 1 ELSE 0 END,
    lease_token=CASE WHEN current.package_digest<>EXCLUDED.package_digest
        OR current.activation_id<>EXCLUDED.activation_id
        OR current.authority_digest<>EXCLUDED.authority_digest
        OR current.projection_epochs<>EXCLUDED.projection_epochs
        OR current.root_entity_id<>EXCLUDED.root_entity_id
        OR current.watched_fields<>EXCLUDED.watched_fields
        THEN NULL ELSE current.lease_token END,
    lease_expires_at=CASE WHEN current.package_digest<>EXCLUDED.package_digest
        OR current.activation_id<>EXCLUDED.activation_id
        OR current.authority_digest<>EXCLUDED.authority_digest
        OR current.projection_epochs<>EXCLUDED.projection_epochs
        OR current.root_entity_id<>EXCLUDED.root_entity_id
        OR current.watched_fields<>EXCLUDED.watched_fields
        THEN NULL ELSE current.lease_expires_at END,
    updated_at=clock_timestamp()
"#;

/// Stage local work inside the Record mutation transaction. Passing an empty
/// field set means a create and therefore matches every active plan for the
/// Record type. At capacity the plan is marked due instead of losing the
/// reconciliation obligation.
pub(crate) async fn capture_local_record(
    client: &impl GenericClient,
    entity_id: &str,
    record_id: Uuid,
    changed_fields: &BTreeSet<String>,
) -> Result<u64, QueueError> {
    if !valid_key(entity_id) || changed_fields.iter().any(|field| !valid_key(field)) {
        return Err(QueueError::Invalid);
    }
    let changed = changed_fields
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let row = client
        .query_one(
            "SELECT registry_internal.capture_external_refresh_record($1,$2,$3)",
            &[&entity_id, &record_id, &changed],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    u64::try_from(row.get::<_, i64>(0)).map_err(|_| QueueError::Unavailable)
}

/// Admit a source hint after HTTP authentication and source-binding checks.
/// The selector is retained only in pending work; the replay receipt keeps a
/// keyed digest and fixed outcome, never the selector itself.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn enqueue_hint(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    authority_digest: &str,
    notifier_digest: &str,
    hint_id_digest: &str,
    payload_digest: &str,
    target_digest: &str,
    projection_epoch: Uuid,
    selector_scheme: &str,
    selector: &str,
    expires_at: i64,
) -> Result<HintAdmission, QueueError> {
    if [
        plan_id,
        authority_digest,
        notifier_digest,
        hint_id_digest,
        payload_digest,
        target_digest,
        selector_scheme,
        selector,
    ]
    .iter()
    .any(|value| !valid_key(value))
        || notifier_digest.len() + hint_id_digest.len() + 1 > MAX_KEY_BYTES
        || expires_at <= 0
    {
        return Err(QueueError::Invalid);
    }
    let row = transaction
        .transaction()
        .query_one(
            ENQUEUE_HINT_SQL,
            &[
                &plan_id,
                &authority_digest,
                &notifier_digest,
                &hint_id_digest,
                &payload_digest,
                &target_digest,
                &projection_epoch,
                &selector_scheme,
                &selector,
                &expires_at,
                &DEFAULT_RECEIPT_RETENTION_SECONDS,
            ],
        )
        .await
        .map_err(|_| QueueError::Unavailable)?;
    match row.get::<_, &str>(0) {
        "accepted" => Ok(HintAdmission::Accepted),
        "duplicate" => Ok(HintAdmission::Duplicate),
        "conflict" => Err(QueueError::Conflict),
        "capacity" => Err(QueueError::AtCapacity),
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

/// Coalesce a manual sweep request with any due or active run. The active
/// lease is not replaced, so a request cannot steal an in-flight step.
pub(crate) async fn request_sweep(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    authority_digest: &str,
) -> Result<bool, QueueError> {
    if !valid_key(plan_id) || !valid_key(authority_digest) {
        return Err(QueueError::Invalid);
    }
    transaction
        .transaction()
        .execute(
            "UPDATE registry_internal.registry_external_refresh_plans
             SET reconciliation_due=true,
                 reconciliation_generation=reconciliation_generation+CASE
                     WHEN sweep_phase='complete' AND next_due_at>clock_timestamp() THEN 1 ELSE 0 END,
                 next_due_at=least(next_due_at,clock_timestamp()),updated_at=clock_timestamp()
             WHERE plan_id=$1 AND authority_digest=$2 AND active",
            &[&plan_id, &authority_digest],
        )
        .await
        .map(|changed| changed == 1)
        .map_err(|_| QueueError::Unavailable)
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
                   AND lease_generation=$5 AND lease_token=$6
                   AND lease_expires_at>clock_timestamp() AND expires_at>clock_timestamp()
                 FOR UPDATE",
                &[
                    &plan_id,
                    &lease.plan_generation,
                    &work_id,
                    &enqueue_generation,
                    &lease.lease_generation,
                    &lease.token,
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
                      AND work.ready_at<=clock_timestamp() AND work.expires_at>clock_timestamp()
                      AND (work.lease_token IS NULL OR work.lease_expires_at<=clock_timestamp()))))",
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
                          AND work.ready_at<=clock_timestamp() AND work.expires_at>clock_timestamp()
                          AND (work.lease_token IS NULL OR work.lease_expires_at<=clock_timestamp())) AS has_targets,
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
                 sweep_started_at=CASE WHEN sweep_phase='complete' OR sweep_baseline=0
                                       THEN clock_timestamp() ELSE sweep_started_at END,
                 sweep_reconciliation_generation=CASE WHEN sweep_phase='complete' OR sweep_baseline=0
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
                "source" => WorkTarget::SourceHint {
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
      AND (work.lease_token IS NULL OR work.lease_expires_at<=clock_timestamp())
    ORDER BY work.ready_at,work.work_id LIMIT (SELECT page_size FROM plan)
    FOR UPDATE OF work SKIP LOCKED
), claimed AS (
    UPDATE registry_internal.registry_external_refresh_work AS work
    SET lease_generation=$3,lease_token=$4,
        lease_expires_at=(SELECT p.lease_expires_at FROM registry_internal.registry_external_refresh_plans p WHERE p.plan_id=$1),
        attempts=least(attempts+1,5)
    FROM ready WHERE work.work_id=ready.work_id
    RETURNING work.*
)
SELECT work_id,enqueue_generation,attempts,plan_generation,kind,record_id,
       projection_epoch,selector_scheme,selector,continuation,
       floor(extract(epoch FROM expires_at))::bigint
FROM claimed ORDER BY ready_at,work_id
"#;

/// Enqueue runtime-derived follow-on work, currently the bounded continuation
/// of a related-label pass. Source hints use `enqueue_hint` because they also
/// owe replay/conflict receipts.
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
        WorkTarget::SourceHint { .. } => return Err(QueueError::Invalid),
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
                continuation=EXCLUDED.continuation,
                lease_generation=NULL,lease_token=NULL,lease_expires_at=NULL",
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

/// Queue a per-key failure discovered by a sweep page. Collisions preserve
/// the higher attempt count and the earlier ready/expiry bounds, so another
/// observation cannot renew retention or restart an exhausted retry budget.
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
    attempts: i16,
    ready_at: i64,
    expires_at: i64,
) -> Result<(), QueueError> {
    if !valid_key(target_digest)
        || !valid_key(selector_scheme)
        || !valid_key(selector)
        || !(1..=3).contains(&attempts)
        || ready_at <= 0
        || expires_at <= ready_at
    {
        return Err(QueueError::Invalid);
    }
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
             SELECT plan_id,plan_generation,'source',$6,$7,$8,$9,$10,
                    to_timestamp($11::bigint),to_timestamp($12::bigint)
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
                expires_at=least(registry_external_refresh_work.expires_at,EXCLUDED.expires_at),
                lease_generation=NULL,lease_token=NULL,lease_expires_at=NULL",
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
                &attempts,
                &ready_at,
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
      AND work.lease_generation=$3 AND work.lease_token=$4
      AND work.enqueue_generation=$6
    RETURNING work.work_id
), due AS (
    UPDATE registry_internal.registry_external_refresh_plans plan
    SET reconciliation_due=true,
        reconciliation_generation=reconciliation_generation+1,
        next_due_at=least(next_due_at,clock_timestamp()+interval '60 seconds'),
        updated_at=clock_timestamp()
    FROM settled
    WHERE plan.plan_id=$1 AND $7 IN ('expired','attempts-exhausted','authority-changed')
    RETURNING plan.plan_id
), receipt AS (
INSERT INTO registry_internal.registry_external_refresh_receipts
    (plan_id,receipt_digest,payload_digest,outcome,expires_at)
SELECT $1,'work:'||$5::text,'generation:'||$6::text,$7,
       clock_timestamp()+interval '24 hours' FROM settled
WHERE (SELECT count(*) FROM registry_internal.registry_external_refresh_receipts
       WHERE plan_id=$1)<100000
   OR EXISTS (SELECT 1 FROM registry_internal.registry_external_refresh_receipts
              WHERE plan_id=$1 AND receipt_digest='work:'||$5::text)
ON CONFLICT (plan_id,receipt_digest) DO UPDATE SET outcome=EXCLUDED.outcome,expires_at=EXCLUDED.expires_at
RETURNING 1
)
SELECT count(*) FROM settled
"#;

/// Retry only this claimed target. A concurrent enqueue increments the row's
/// generation and clears the lease; this stale owner therefore changes zero
/// rows and cannot postpone or clear the newer work.
pub(crate) async fn retry_target(
    transaction: &GuardedTransaction<'_>,
    plan_id: &str,
    lease: PlanLease,
    target: &ClaimedTarget,
    delay: Duration,
) -> Result<(), QueueError> {
    if target.attempts >= 4 {
        return settle_target(
            transaction,
            plan_id,
            lease,
            target,
            Settlement::AttemptsExhausted,
        )
        .await;
    }
    let delay = i64::try_from(delay.as_secs()).map_err(|_| QueueError::Invalid)?;
    let changed = transaction
        .transaction()
        .execute(
            "UPDATE registry_internal.registry_external_refresh_work AS work
             SET ready_at=clock_timestamp()+make_interval(secs => $7::bigint::double precision),
                 lease_token=NULL,lease_expires_at=NULL
             WHERE work.work_id=$5 AND work.plan_id=$1 AND work.plan_generation=$2
               AND work.lease_generation=$3 AND work.lease_token=$4
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
/// prevents either sustained hints or a long sweep from starving the other.
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
    transaction
        .transaction()
        .execute(
            "UPDATE registry_internal.registry_external_refresh_work work
             SET lease_generation=NULL,lease_token=NULL,lease_expires_at=NULL
             WHERE work.plan_id=$1 AND work.plan_generation=$3
               AND work.lease_generation=$4 AND work.lease_token=$5
               AND EXISTS (SELECT 1 FROM registry_internal.registry_external_refresh_plans plan
                   WHERE plan.plan_id=$1 AND plan.authority_digest=$2
                     AND plan.plan_generation=$3 AND plan.lease_generation=$4
                     AND plan.lease_token=$5 AND plan.active
                     AND plan.lease_expires_at>clock_timestamp())",
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
    let changed = transaction
        .transaction()
        .execute(
            "UPDATE registry_internal.registry_external_refresh_plans
             SET sweep_phase=$6,sweep_baseline=$7,sweep_continuation=$8,
                 sweep_acquisition_failures=$9::bigint,
                 last_completed_at=CASE WHEN $10 THEN clock_timestamp() ELSE last_completed_at END,
                 next_due_at=CASE WHEN $10 THEN
                     CASE WHEN $9::bigint>0 OR reconciliation_generation>sweep_reconciliation_generation
                         THEN clock_timestamp()+interval '60 seconds'
                         ELSE greatest(
                             clock_timestamp(),
                             coalesce(sweep_started_at,clock_timestamp())
                                 +make_interval(secs => interval_seconds::double precision))
                     END
                     ELSE next_due_at END,
                 reconciliation_due=CASE WHEN $10 THEN
                     $9::bigint>0 OR reconciliation_generation>sweep_reconciliation_generation
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
    let mut purged = PurgedQueueState {
        work: 0,
        receipts: 0,
        plans: 0,
    };
    for row in rows {
        let kind: String = row.get(0);
        let count = u64::try_from(row.get::<_, i64>(1)).map_err(|_| QueueError::Unavailable)?;
        match kind.as_str() {
            "work" => purged.work += count,
            "receipt" => purged.receipts += count,
            "plan" => purged.plans += count,
            _ => return Err(QueueError::Unavailable),
        }
    }
    Ok(purged)
}

/// Value-free operator status. Counts and fixed categories intentionally omit
/// Record IDs, source selectors, cursors, receipt digests and authority bytes.
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
                        AND work.expires_at>clock_timestamp()
                        AND (work.lease_token IS NULL OR work.lease_expires_at<=clock_timestamp())),
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
        ('targets','sweep-page','sweep-complete','sweep-with-failures','idle')),
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
    attempts smallint NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    ready_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    lease_generation bigint,
    lease_token uuid,
    lease_expires_at timestamptz,
    CONSTRAINT registry_external_refresh_work_shape CHECK (
        (kind='local' AND record_id IS NOT NULL AND projection_epoch IS NULL AND selector_scheme IS NULL AND selector IS NULL AND continuation IS NULL)
        OR (kind='labels' AND record_id IS NOT NULL AND projection_epoch IS NULL AND selector_scheme IS NULL AND selector IS NULL)
        OR (kind='source' AND record_id IS NULL AND projection_epoch IS NOT NULL AND selector_scheme IS NOT NULL AND selector IS NOT NULL AND continuation IS NULL)),
    CONSTRAINT registry_external_refresh_work_lease_pair CHECK ((lease_token IS NULL)=(lease_expires_at IS NULL)),
    UNIQUE (plan_id,target_digest)
);
CREATE TABLE IF NOT EXISTS registry_internal.registry_external_refresh_receipts (
    plan_id text NOT NULL REFERENCES registry_internal.registry_external_refresh_plans(plan_id) ON DELETE CASCADE,
    receipt_digest text NOT NULL CHECK (octet_length(receipt_digest) BETWEEN 1 AND 1024),
    payload_digest text NOT NULL CHECK (octet_length(payload_digest) BETWEEN 1 AND 1024),
    outcome text NOT NULL CHECK (outcome IN ('accepted','published','authorized-absence','empty-collection',
        'fresh-reuse','no-eligible-witness','denied','retention-refused','expired','attempts-exhausted','authority-changed')),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (plan_id,receipt_digest)
);
CREATE INDEX IF NOT EXISTS registry_external_refresh_work_due_idx
    ON registry_internal.registry_external_refresh_work(plan_id,ready_at,work_id)
    WHERE lease_token IS NULL;
CREATE INDEX IF NOT EXISTS registry_external_refresh_receipts_expiry_idx
    ON registry_internal.registry_external_refresh_receipts(expires_at,plan_id,receipt_digest);
CREATE INDEX IF NOT EXISTS registry_external_refresh_plan_capture_idx
    ON registry_internal.registry_external_refresh_plans(root_entity_id,active,plan_id);

CREATE OR REPLACE FUNCTION registry_internal.capture_external_refresh_record(
    p_entity text,p_record uuid,p_changed text[]
) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, registry_internal AS $body$
DECLARE plan registry_internal.registry_external_refresh_plans; captured bigint := 0;
    pending bigint; target text;
BEGIN
    IF p_entity IS NULL OR octet_length(p_entity) NOT BETWEEN 1 AND 1024
        OR p_record IS NULL OR p_changed IS NULL
        OR EXISTS (SELECT 1 FROM unnest(p_changed) field WHERE field IS NULL OR octet_length(field) NOT BETWEEN 1 AND 1024)
        THEN RETURN NULL; END IF;
    FOR plan IN SELECT * FROM registry_internal.registry_external_refresh_plans
        WHERE active AND root_entity_id=p_entity
          AND (cardinality(p_changed)=0 OR watched_fields && p_changed)
        ORDER BY plan_id FOR UPDATE
    LOOP
        target := 'local:'||p_record::text;
        SELECT count(*) INTO pending FROM registry_internal.registry_external_refresh_work
            WHERE plan_id=plan.plan_id AND plan_generation=plan.plan_generation;
        IF pending>=plan.max_pending AND NOT EXISTS (
            SELECT 1 FROM registry_internal.registry_external_refresh_work
            WHERE plan_id=plan.plan_id AND target_digest=target) THEN
            UPDATE registry_internal.registry_external_refresh_plans
                SET reconciliation_due=true,reconciliation_generation=reconciliation_generation+1,
                    next_due_at=least(next_due_at,clock_timestamp()),updated_at=clock_timestamp()
                WHERE plan_id=plan.plan_id;
            CONTINUE;
        END IF;
        INSERT INTO registry_internal.registry_external_refresh_work
            (plan_id,plan_generation,kind,record_id,target_digest,expires_at)
        VALUES (plan.plan_id,plan.plan_generation,'local',p_record,target,
                clock_timestamp()+make_interval(secs => (
                    SELECT min(scope.cache_ttl_seconds)::double precision
                    FROM unnest(plan.projection_epochs) AS requested(epoch)
                    JOIN registry_internal.registry_external_projection_scopes scope
                      ON scope.epoch=requested.epoch AND scope.active)))
        ON CONFLICT (plan_id,target_digest) DO UPDATE SET
            plan_generation=EXCLUDED.plan_generation,
            enqueue_generation=registry_external_refresh_work.enqueue_generation+1,
            attempts=0,ready_at=clock_timestamp(),expires_at=EXCLUDED.expires_at,
            lease_generation=NULL,lease_token=NULL,lease_expires_at=NULL;
        captured := captured+1;
    END LOOP;
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
            next_due_at=least(next_due_at,clock_timestamp()+interval '60 seconds'),
            updated_at=clock_timestamp()
        WHERE plan.plan_id IN (SELECT plan_id FROM removed WHERE reconcile)
        RETURNING plan.plan_id
    ) SELECT 'work',count(*) FROM removed;
    RETURN QUERY WITH expired AS (
        SELECT plan_id,receipt_digest FROM registry_internal.registry_external_refresh_receipts
        WHERE expires_at<=clock_timestamp() ORDER BY expires_at,plan_id,receipt_digest
        LIMIT p_limit FOR UPDATE SKIP LOCKED
    ), removed AS (
        DELETE FROM registry_internal.registry_external_refresh_receipts receipt USING expired
        WHERE receipt.plan_id=expired.plan_id AND receipt.receipt_digest=expired.receipt_digest RETURNING 1
    ) SELECT 'receipt',count(*) FROM removed;
    RETURN QUERY WITH retired AS (
        SELECT plan.plan_id FROM registry_internal.registry_external_refresh_plans plan
        WHERE NOT plan.active
          AND plan.updated_at<=clock_timestamp()-interval '24 hours'
          AND NOT EXISTS (SELECT 1 FROM registry_internal.registry_external_refresh_work work
                          WHERE work.plan_id=plan.plan_id)
          AND NOT EXISTS (SELECT 1 FROM registry_internal.registry_external_refresh_receipts receipt
                          WHERE receipt.plan_id=plan.plan_id)
        ORDER BY plan.plan_id LIMIT p_limit FOR UPDATE SKIP LOCKED
    ), removed AS (
        DELETE FROM registry_internal.registry_external_refresh_plans plan USING retired
        WHERE plan.plan_id=retired.plan_id RETURNING 1
    ) SELECT 'plan',count(*) FROM removed;
END $body$;
"#;

const ENQUEUE_HINT_SQL: &str = r#"
WITH plan AS MATERIALIZED (
    SELECT * FROM registry_internal.registry_external_refresh_plans
    WHERE plan_id=$1 FOR UPDATE
), existing AS MATERIALIZED (
    SELECT payload_digest FROM registry_internal.registry_external_refresh_receipts
    WHERE plan_id=$1 AND receipt_digest=$3||':'||$4 AND expires_at>clock_timestamp()
), status AS MATERIALIZED (
    SELECT CASE
        WHEN NOT EXISTS (SELECT 1 FROM plan WHERE active AND authority_digest=$2 AND $7=ANY(projection_epochs))
            OR NOT EXISTS (SELECT 1 FROM registry_internal.registry_external_projection_scopes
                           WHERE epoch=$7 AND active)
            THEN 'authority-changed'
        WHEN EXISTS (SELECT 1 FROM existing WHERE payload_digest<>$5) THEN 'conflict'
        WHEN EXISTS (SELECT 1 FROM existing WHERE payload_digest=$5) THEN 'duplicate'
        WHEN (SELECT count(*) FROM registry_internal.registry_external_refresh_receipts receipt
              JOIN plan USING (plan_id))>=100000 THEN 'capacity'
        WHEN (SELECT count(*) FROM registry_internal.registry_external_refresh_work work
              JOIN plan USING (plan_id) WHERE work.plan_generation=plan.plan_generation)>=(SELECT max_pending FROM plan)
             AND NOT EXISTS (SELECT 1 FROM registry_internal.registry_external_refresh_work
                             WHERE plan_id=$1 AND target_digest=$6)
            THEN 'capacity'
        ELSE 'accepted' END AS value
), receipt AS (
    INSERT INTO registry_internal.registry_external_refresh_receipts
        (plan_id,receipt_digest,payload_digest,outcome,expires_at)
    SELECT $1,$3||':'||$4,$5,'accepted',
           clock_timestamp()+make_interval(secs => $11::bigint::double precision)
    WHERE (SELECT value FROM status)='accepted'
    ON CONFLICT (plan_id,receipt_digest) DO UPDATE SET
        payload_digest=EXCLUDED.payload_digest,outcome=EXCLUDED.outcome,expires_at=EXCLUDED.expires_at
    WHERE registry_external_refresh_receipts.expires_at<=clock_timestamp()
    RETURNING 1
), work AS (
    INSERT INTO registry_internal.registry_external_refresh_work
        (plan_id,plan_generation,kind,projection_epoch,selector_scheme,selector,target_digest,expires_at)
    SELECT plan_id,plan_generation,'source',$7,$8,$9,
           $6,
           to_timestamp($10::bigint) FROM plan
    WHERE (SELECT value FROM status)='accepted'
    ON CONFLICT (plan_id,target_digest) DO UPDATE SET
        plan_generation=EXCLUDED.plan_generation,
        enqueue_generation=registry_external_refresh_work.enqueue_generation+1,
        attempts=0,ready_at=clock_timestamp(),expires_at=least(registry_external_refresh_work.expires_at,EXCLUDED.expires_at),
        lease_generation=NULL,lease_token=NULL,lease_expires_at=NULL
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
SELECT value FROM status
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_queue_state_is_backup_excluded_and_value_free_receipts_are_separate() {
        assert_eq!(BACKUP_EXCLUDED_TABLES.len(), 3);
        assert!(BACKUP_EXCLUDED_TABLES
            .iter()
            .all(|table| INSTALL_SQL.contains(table)));
        assert!(INSTALL_SQL.contains("payload_digest text NOT NULL"));
        let receipts = INSTALL_SQL
            .split(
                "CREATE TABLE IF NOT EXISTS registry_internal.registry_external_refresh_receipts",
            )
            .nth(1)
            .unwrap()
            .split("CREATE INDEX")
            .next()
            .unwrap();
        assert!(!receipts.contains("selector"));
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
        assert!(REGISTER_PLAN_SQL.contains("authority_digest<>EXCLUDED.authority_digest"));
        assert!(REGISTER_PLAN_SQL.contains("THEN NULL ELSE current.lease_token"));
    }

    #[test]
    fn queue_sql_bounds_receipts_and_clamps_crash_reclaims() {
        assert!(ENQUEUE_HINT_SQL.contains(">=100000 THEN 'capacity'"));
        assert!(SETTLE_TARGET_SQL.contains(")<100000"));
        assert!(CLAIM_TARGETS_SQL.contains("attempts=least(attempts+1,5)"));
        assert!(INSTALL_SQL.contains("attempts BETWEEN 0 AND 5"));
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
}

#[cfg(all(test, feature = "postgres-test"))]
mod postgres_tests {
    use super::*;
    use crate::postgres::external_projection::postgres_tests::Activated;

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
                 SET attempts=4,lease_generation=NULL,lease_token=NULL,lease_expires_at=NULL
                 WHERE plan_id='plan'",
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
        retry_target(&tx, "plan", lease, &claimed[0], Duration::from_secs(15))
            .await
            .unwrap();
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
        assert_eq!(purged.receipts, 0);
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
}

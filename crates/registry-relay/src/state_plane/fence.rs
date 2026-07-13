// SPDX-License-Identifier: Apache-2.0
//! Dedicated-connection serving fence and durable dispatch permits.
//!
//! This capability is compiled private infrastructure. It is not serving
//! authority by itself. The consultation runtime must run every credential or
//! data call inside [`PostgresServingFence::authorize_and_dispatch`] and must
//! never retain the raw PostgreSQL client.

use std::{future::Future, time::Duration};

use registry_platform_audit::AuditChainHasher;
use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot, watch, Mutex},
    task::{AbortHandle, JoinHandle},
    time::Instant,
};
use tokio_postgres::{Client, Error as PostgresError, Row};
use ulid::Ulid;

use crate::consultation::commitments::{
    CanonicalDispatchRequestEffect, KeyedDispatchRequestCommitment,
};

use super::migration::{
    validate_runtime_capability_v1, AuditChainKeyEpochId, RuntimeCapabilityError,
    MIGRATION_ADVISORY_LOCK_KEY_V1, RUNTIME_SESSION_LIMITS_SQL,
};

const FENCE_ACQUIRE_SQL: &str = "SELECT * FROM relay_state_api.serving_fence_acquire_v1($1, $2)";
const FENCE_FINALIZE_SQL: &str =
    "SELECT * FROM relay_state_api.serving_fence_finalize_v1($1, $2, $3)";
const FENCE_STATUS_SQL: &str = "SELECT * FROM relay_state_api.serving_fence_status_v1($1, $2, $3)";
const FENCE_RELEASE_SQL: &str =
    "SELECT * FROM relay_state_api.serving_fence_release_v1($1, $2, $3)";
const PERMIT_AUTHORIZE_SQL: &str = r#"
WITH permit_check AS MATERIALIZED (
    SELECT * FROM relay_state_api.dispatch_permit_authorize_v1(
        $1, $2, $3, $4, $5, $6, $7, $8
    )
)
SELECT permit_check.*,
       permit_check.deadline_unix_ms
           - floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
           - 1 AS remaining_ms
FROM permit_check
"#;
const PERMIT_COMPLETE_SQL: &str =
    "SELECT * FROM relay_state_api.dispatch_permit_complete_v1($1, $2, $3, $4, $5, $6, $7)";
const FENCE_OPEN_AFTER_RECOVERY_SQL: &str =
    "SELECT * FROM relay_state_api.serving_fence_open_after_recovery_v1($1, $2, $3)";

const DATABASE_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const HARD_SOURCE_DEADLINE: Duration = Duration::from_secs(60);
const CANCELLATION_GRACE: Duration = Duration::from_secs(1);
const LOCAL_TAKEOVER_WAIT: Duration = HARD_SOURCE_DEADLINE.saturating_add(CANCELLATION_GRACE);
const MAX_POST_LOCAL_BARRIER_WAIT: Duration = Duration::from_secs(15);
const MAX_BARRIER_POLL: Duration = Duration::from_millis(250);

/// Deployment-specific fixed advisory-lock key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServingFenceLockKey(i64);

impl ServingFenceLockKey {
    pub(crate) fn new(value: i64) -> Result<Self, ServingFenceError> {
        if value == 0 || value == MIGRATION_ADVISORY_LOCK_KEY_V1 {
            return Err(ServingFenceError::InvalidLockKey);
        }
        Ok(Self(value))
    }

    pub(super) fn as_i64(self) -> i64 {
        self.0
    }
}

impl std::fmt::Debug for ServingFenceLockKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ServingFenceLockKey(<deployment-bound>)")
    }
}

/// Canonical Relay operation identifier stored by the permit state plane.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DispatchOperationId(String);

impl DispatchOperationId {
    pub(crate) fn parse(value: &str) -> Result<Self, ServingFenceError> {
        let parsed = Ulid::from_string(value).map_err(|_| ServingFenceError::InvalidOperationId)?;
        if parsed.to_string() != value {
            return Err(ServingFenceError::InvalidOperationId);
        }
        Ok(Self(value.to_owned()))
    }

    #[cfg(test)]
    pub(crate) fn from_ulid(value: Ulid) -> Self {
        Self(value.to_string())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for DispatchOperationId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DispatchOperationId(<redacted>)")
    }
}

/// Exact millisecond budget used by PostgreSQL to derive the permit deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DispatchPermitBudget(u16);

impl DispatchPermitBudget {
    pub(crate) fn new(duration: Duration) -> Result<Self, ServingFenceError> {
        let milliseconds = duration.as_millis();
        if milliseconds == 0
            || milliseconds > HARD_SOURCE_DEADLINE.as_millis()
            || Duration::from_millis(milliseconds as u64) != duration
        {
            return Err(ServingFenceError::InvalidPermitBudget);
        }
        Ok(Self(milliseconds as u16))
    }

    pub(crate) fn as_milliseconds(self) -> i32 {
        i32::from(self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DispatchPermitKind {
    Credential,
    Data,
}

impl DispatchPermitKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::Data => "data",
        }
    }
}

/// Exact closed permit manifest installed atomically with one attempt.
pub(crate) struct ConsultationPermitSet {
    permits: Vec<(DispatchPermitKind, u8)>,
}

impl ConsultationPermitSet {
    pub(crate) fn from_counts(
        credential_count: u8,
        data_count: u8,
    ) -> Result<Self, ServingFenceError> {
        if credential_count > 1 || data_count > 16 {
            return Err(ServingFenceError::InvalidPermitManifest);
        }
        let mut permits = Vec::with_capacity(usize::from(credential_count + data_count));
        if credential_count == 1 {
            permits.push((DispatchPermitKind::Credential, 0));
        }
        permits.extend((0..data_count).map(|ordinal| (DispatchPermitKind::Data, ordinal)));
        Ok(Self { permits })
    }

    pub(super) fn postgres_arrays(&self) -> (Vec<String>, Vec<i16>) {
        self.permits
            .iter()
            .map(|(kind, ordinal)| (kind.as_str().to_owned(), i16::from(*ordinal)))
            .unzip()
    }

    pub(super) fn permits(&self) -> &[(DispatchPermitKind, u8)] {
        &self.permits
    }
}

/// One-shot authority minted only while the dedicated fence is ready.
#[must_use = "the fence authority must be consumed by atomic attempt persistence"]
pub(crate) struct FencedConsultationAttemptAuthority {
    pub(super) lock_key: ServingFenceLockKey,
    pub(super) holder_id: String,
    pub(super) fence_generation: i64,
    pub(super) budget: DispatchPermitBudget,
    pub(super) permit_set: ConsultationPermitSet,
    pub(super) lifecycle_seal: ConsultationLifecycleSeal,
}

impl FencedConsultationAttemptAuthority {
    pub(super) fn arm_lifecycle_seal(&mut self) {
        self.lifecycle_seal.arm_for_attempt_cas();
    }

    pub(super) fn disarm_after_non_mutating_attempt_cas(&mut self) {
        self.lifecycle_seal.disarm_after_non_mutating_attempt_cas();
    }
}

/// Durable child permit identity. Possession is not outbound-call authority.
pub(crate) struct ConsultationDispatchPermit {
    pub(super) operation_id: DispatchOperationId,
    pub(super) kind: DispatchPermitKind,
    pub(super) ordinal: u8,
    pub(super) fence_generation: i64,
    pub(super) holder_id: String,
    pub(super) budget: DispatchPermitBudget,
    pub(super) deadline_unix_ms: i64,
    pub(super) local_not_after: Instant,
    pub(super) state: DispatchPermitState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DispatchPermitState {
    Ready,
    Dispatching,
    Completed,
    Uncertain,
}

impl ConsultationDispatchPermit {
    pub(crate) fn operation_id(&self) -> &DispatchOperationId {
        &self.operation_id
    }

    pub(crate) fn fence_generation(&self) -> i64 {
        self.fence_generation
    }

    pub(crate) fn deadline_unix_ms(&self) -> i64 {
        self.deadline_unix_ms
    }

    #[cfg(test)]
    pub(crate) fn is_uncertain(&self) -> bool {
        self.state == DispatchPermitState::Uncertain
    }
}

impl std::fmt::Debug for ConsultationDispatchPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsultationDispatchPermit")
            .field("operation_id", &"<redacted>")
            .field("kind", &self.kind)
            .field("ordinal", &self.ordinal)
            .field("fence_generation", &self.fence_generation)
            .field("holder_id", &"<redacted>")
            .field("budget", &self.budget)
            .field("deadline_unix_ms", &self.deadline_unix_ms)
            .field("state", &self.state)
            .finish()
    }
}

/// Exact non-cloneable dispatch session returned by the atomic attempt CAS.
#[must_use = "the consultation must reach an acknowledged terminal completion"]
pub(crate) struct AuditedConsultationDispatch {
    pub(super) operation_id: DispatchOperationId,
    pub(super) attempt_envelope_id: String,
    pub(super) attempt_record_hash: [u8; 32],
    pub(super) lock_key: ServingFenceLockKey,
    pub(super) fence_generation: i64,
    pub(super) holder_id: String,
    pub(super) deadline_unix_ms: i64,
    pub(super) local_not_after: Instant,
    pub(super) permits: Vec<ConsultationDispatchPermit>,
    pub(super) request_effect_hasher: AuditChainHasher,
    pub(super) lifecycle_seal: ConsultationLifecycleSeal,
}

impl AuditedConsultationDispatch {
    /// Consume one complete canonical request effect into an opaque keyed
    /// commitment. The deployment key remains inside the audited dispatch and
    /// the clear request effect is zeroized when this call returns.
    pub(crate) fn commit_request_effect(
        &self,
        effect: CanonicalDispatchRequestEffect,
    ) -> Result<KeyedDispatchRequestCommitment, ServingFenceError> {
        let digest = self
            .request_effect_hasher
            .relay_request_effect_commitment(effect.as_bytes())
            .map_err(|_| ServingFenceError::RequestCommitmentUnavailable)?;
        Ok(KeyedDispatchRequestCommitment::from_digest(digest))
    }
    /// Return the optional credential permit before any data exchange starts.
    ///
    /// A cached credential legitimately leaves this permit unused. Once a data
    /// permit has entered any non-ready state, however, credential acquisition
    /// can no longer be inserted retroactively into the recorded operation
    /// path.
    pub(crate) fn credential_permit_mut(
        &mut self,
    ) -> Result<Option<&mut ConsultationDispatchPermit>, ServingFenceError> {
        if self.permits.iter().any(|permit| {
            permit.kind == DispatchPermitKind::Data && permit.state != DispatchPermitState::Ready
        }) {
            return Err(ServingFenceError::PermitOrderViolation);
        }
        Ok(self
            .permits
            .iter_mut()
            .find(|permit| permit.kind == DispatchPermitKind::Credential))
    }

    /// Return only the next monotonically consumable data permit.
    ///
    /// The permit ordinal is the actual call position, not a caller-selected
    /// plan-step index. An uncertain credential exchange blocks data access,
    /// and a gap in the local data prefix is treated as protocol drift.
    pub(crate) fn next_data_permit_mut(
        &mut self,
    ) -> Result<Option<&mut ConsultationDispatchPermit>, ServingFenceError> {
        if self.permits.iter().any(|permit| {
            permit.kind == DispatchPermitKind::Credential
                && matches!(
                    permit.state,
                    DispatchPermitState::Dispatching | DispatchPermitState::Uncertain
                )
        }) {
            return Err(ServingFenceError::PermitUncertain);
        }
        let Some(index) = self.permits.iter().position(|permit| {
            permit.kind == DispatchPermitKind::Data
                && permit.state != DispatchPermitState::Completed
        }) else {
            return Ok(None);
        };
        if self.permits[index + 1..].iter().any(|permit| {
            permit.kind == DispatchPermitKind::Data
                && permit.state == DispatchPermitState::Completed
        }) {
            return Err(ServingFenceError::PermitOrderViolation);
        }
        Ok(Some(&mut self.permits[index]))
    }

    pub(crate) fn deadline_unix_ms(&self) -> i64 {
        self.deadline_unix_ms
    }

    /// Return the non-shortenable process-monotonic deadline paired with the
    /// PostgreSQL deadline by the atomic attempt CAS. Local SnapshotExact work
    /// consumes this same bound even though it has no outbound child permit.
    pub(crate) fn local_not_after(&self) -> Instant {
        self.local_not_after
    }

    pub(super) fn postgres_permit_arrays(&self) -> (Vec<String>, Vec<i16>) {
        self.permits
            .iter()
            .map(|permit| (permit.kind.as_str().to_owned(), i16::from(permit.ordinal)))
            .unzip()
    }

    pub(super) fn disarm_after_terminal_completion(&mut self) {
        self.lifecycle_seal.disarm_after_terminal_completion();
    }

    #[cfg(test)]
    pub(crate) fn lifecycle_is_armed(&self) -> bool {
        self.lifecycle_seal.is_armed()
    }
}

/// Opaque canonical takeover batch. It cannot be cloned, serialized, or
/// constructed by production callers.
#[must_use = "every persisted orphan must be recovered before admission opens"]
pub(crate) struct TakeoverCompletionRecoveryAuthority {
    pub(super) lock_key: ServingFenceLockKey,
    pub(super) holder_id: String,
    pub(super) fence_generation: i64,
    pub(super) operation_ids: Vec<DispatchOperationId>,
    pub(super) next_index: usize,
}

impl TakeoverCompletionRecoveryAuthority {
    pub(crate) fn remaining(&self) -> usize {
        self.operation_ids.len().saturating_sub(self.next_index)
    }

    pub(super) fn current_operation(&self) -> Option<&DispatchOperationId> {
        self.operation_ids.get(self.next_index)
    }

    pub(super) fn mark_current_recovered(&mut self) {
        self.next_index += 1;
    }

    fn is_complete(&self) -> bool {
        self.next_index == self.operation_ids.len()
    }

    #[cfg(test)]
    pub(crate) fn duplicate_for_test(&self) -> Self {
        Self {
            lock_key: self.lock_key,
            holder_id: self.holder_id.clone(),
            fence_generation: self.fence_generation,
            operation_ids: self.operation_ids.clone(),
            next_index: self.next_index,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServingFenceReadiness {
    Ready,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ServingFenceError {
    #[error("Relay serving-fence lock key is invalid")]
    InvalidLockKey,
    #[error("Relay dispatch operation identifier is invalid")]
    InvalidOperationId,
    #[error("Relay dispatch permit budget is invalid")]
    InvalidPermitBudget,
    #[error("Relay consultation permit manifest is invalid")]
    InvalidPermitManifest,
    #[error("Relay serving fence is held by another instance")]
    Contended,
    #[error("Relay serving-fence runtime identity is not bound")]
    WrongRuntimeIdentity,
    #[error("Relay serving-fence capability has drifted")]
    CapabilityDrift,
    #[error("Relay serving-fence admission is closed")]
    AdmissionClosed,
    #[error("Relay serving-fence ownership is unavailable")]
    OwnershipLost,
    #[error("Relay dispatch permit conflicts with a durable operation")]
    PermitConflict,
    #[error("Relay dispatch request commitment does not match the consultation key epoch")]
    RequestCommitmentMismatch,
    #[error("Relay keyed dispatch request commitment is unavailable")]
    RequestCommitmentUnavailable,
    #[error("Relay dispatch permit completion could not be acknowledged")]
    PermitCompletionConflict,
    #[error("Relay dispatch permit is unknown")]
    PermitUnknown,
    #[error("Relay dispatch permit has expired")]
    PermitExpired,
    #[error("Relay dispatch permit has completed")]
    PermitCompleted,
    #[error("Relay dispatch permit was already dispatched")]
    PermitAlreadyDispatched,
    #[error("Relay dispatch permits were consumed out of order")]
    PermitOrderViolation,
    #[error("Relay dispatch permit was abandoned during takeover")]
    PermitAbandoned,
    #[error("Relay dispatch permit outcome is uncertain")]
    PermitUncertain,
    #[error("Relay dispatch permit belongs to a stale fence generation")]
    StaleGeneration,
    #[error("Relay serving-fence takeover did not reach its database barrier")]
    TakeoverTimedOut,
    #[error("Relay serving-fence recovery is incomplete")]
    RecoveryIncomplete,
    #[error("Relay serving-fence database protocol has drifted")]
    ProtocolDrift,
    #[error("Relay serving fence is unavailable")]
    Unavailable,
}

/// Execute-only fence capability backed by one dedicated PostgreSQL session.
pub(crate) struct PostgresServingFence {
    lock_key: ServingFenceLockKey,
    generation: i64,
    holder_id: String,
    commands: mpsc::UnboundedSender<FenceCommand>,
    admission: watch::Sender<bool>,
    actor_abort: AbortHandle,
    actor: Mutex<Option<JoinHandle<()>>>,
    takeover_recovery: Option<TakeoverCompletionRecoveryAuthority>,
}

type ConnectionDriver = JoinHandle<Result<(), PostgresError>>;

struct ConnectionDriverGuard(Option<ConnectionDriver>);

impl ConnectionDriverGuard {
    fn new(driver: ConnectionDriver) -> Self {
        Self(Some(driver))
    }

    fn handle_mut(&mut self) -> &mut ConnectionDriver {
        self.0.as_mut().expect("connection driver is present")
    }

    fn take(&mut self) -> ConnectionDriver {
        self.0.take().expect("connection driver is moved once")
    }
}

impl Drop for ConnectionDriverGuard {
    fn drop(&mut self) {
        if let Some(driver) = self.0.take() {
            driver.abort();
        }
    }
}

struct SessionUncertaintyGuard {
    admission: watch::Sender<bool>,
    actor_abort: AbortHandle,
    confirmed: bool,
}

/// Fence-linked ownership of one nonterminal durable consultation.
///
/// The seal is deliberately neither `Clone` nor `Debug`. It is harmless while
/// carried by a freshly minted attempt authority and is armed immediately
/// before an attempt CAS can commit without its acknowledgement being
/// observed. A proven `head_changed` result returns it to the harmless
/// pre-intent state before retry. Once a durable intent is observed, the seal
/// moves into the resulting dispatch. Losing that sole dispatch before an
/// acknowledged terminal completion closes admission and drops the dedicated
/// fence session so the successor must run takeover recovery.
pub(super) struct ConsultationLifecycleSeal {
    admission: watch::Sender<bool>,
    actor_abort: AbortHandle,
    armed: bool,
}

impl ConsultationLifecycleSeal {
    fn unarmed(admission: &watch::Sender<bool>, actor_abort: &AbortHandle) -> Self {
        Self {
            admission: admission.clone(),
            actor_abort: actor_abort.clone(),
            armed: false,
        }
    }

    fn arm_for_attempt_cas(&mut self) {
        self.armed = true;
    }

    fn disarm_after_non_mutating_attempt_cas(&mut self) {
        self.armed = false;
    }

    fn disarm_after_terminal_completion(&mut self) {
        self.armed = false;
    }

    #[cfg(test)]
    fn is_armed(&self) -> bool {
        self.armed
    }
}

impl Drop for ConsultationLifecycleSeal {
    fn drop(&mut self) {
        if self.armed {
            self.admission.send_replace(false);
            self.actor_abort.abort();
        }
    }
}

impl SessionUncertaintyGuard {
    fn new(admission: &watch::Sender<bool>, actor_abort: &AbortHandle) -> Self {
        Self {
            admission: admission.clone(),
            actor_abort: actor_abort.clone(),
            confirmed: false,
        }
    }

    fn confirm(&mut self) {
        self.confirmed = true;
    }
}

impl Drop for SessionUncertaintyGuard {
    fn drop(&mut self) {
        if !self.confirmed {
            self.admission.send_replace(false);
            self.actor_abort.abort();
        }
    }
}

struct PermitDispatchGuard<'a> {
    state: &'a mut DispatchPermitState,
    finished: bool,
}

impl<'a> PermitDispatchGuard<'a> {
    fn new(state: &'a mut DispatchPermitState) -> Self {
        *state = DispatchPermitState::Dispatching;
        Self {
            state,
            finished: false,
        }
    }

    fn finish(mut self) {
        *self.state = DispatchPermitState::Completed;
        self.finished = true;
    }
}

impl Drop for PermitDispatchGuard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            *self.state = DispatchPermitState::Uncertain;
        }
    }
}

#[derive(Debug)]
struct AuthorizationWindow {
    remaining_ms: i64,
}

enum FenceCommand {
    Readiness {
        reply: oneshot::Sender<Result<(), ServingFenceError>>,
    },
    AuthorizePermit {
        operation_id: String,
        kind: &'static str,
        ordinal: i16,
        request_commitment: String,
        expected_deadline_unix_ms: i64,
        reply: oneshot::Sender<Result<AuthorizationWindow, ServingFenceError>>,
    },
    CompletePermit {
        operation_id: String,
        kind: &'static str,
        ordinal: i16,
        request_commitment: String,
        expected_deadline_unix_ms: i64,
        reply: oneshot::Sender<Result<(), ServingFenceError>>,
    },
    OpenAfterRecovery {
        reply: oneshot::Sender<Result<(), ServingFenceError>>,
    },
    Release {
        reply: oneshot::Sender<Result<(), ServingFenceError>>,
    },
}

impl PostgresServingFence {
    pub(crate) async fn acquire(
        client: Client,
        connection_driver: ConnectionDriver,
        chain_key_epoch_id: &AuditChainKeyEpochId,
        lock_key: ServingFenceLockKey,
    ) -> Result<Self, ServingFenceError> {
        let mut driver_guard = ConnectionDriverGuard::new(connection_driver);
        initialization_timeout(client.batch_execute("ROLLBACK"))
            .await?
            .map_err(|_| ServingFenceError::Unavailable)?;
        initialization_timeout(client.batch_execute(RUNTIME_SESSION_LIMITS_SQL))
            .await?
            .map_err(|_| ServingFenceError::Unavailable)?;
        initialization_timeout(validate_runtime_capability_v1(&client, chain_key_epoch_id))
            .await?
            .map_err(map_runtime_capability_error)?;

        let holder_id = Ulid::new().to_string();
        let acquired = initialization_timeout(
            client.query_one(FENCE_ACQUIRE_SQL, &[&lock_key.as_i64(), &holder_id]),
        )
        .await?
        .map_err(|_| ServingFenceError::Unavailable)?;
        match try_str(&acquired, "outcome")? {
            "contended" => return Err(ServingFenceError::Contended),
            "acquired" => {}
            _ => return Err(ServingFenceError::ProtocolDrift),
        }
        let generation = try_i64(&acquired, "fence_generation")?;
        if generation <= 0
            || try_str(&acquired, "holder_id")? != holder_id
            || try_i64(&acquired, "lock_key")? != lock_key.as_i64()
        {
            return Err(ServingFenceError::ProtocolDrift);
        }
        let takeover_required = try_bool(&acquired, "takeover_required")?;
        let database_admission_open = try_bool(&acquired, "admission_open")?;
        if takeover_required == database_admission_open {
            return Err(ServingFenceError::ProtocolDrift);
        }
        let recovery_operation_ids = if takeover_required {
            // Start no earlier than the observed successful acquisition. This
            // deliberately waits for the complete source deadline plus grace
            // from PostgreSQL's actual lock acquisition rather than risking a
            // shortened barrier.
            tokio::time::sleep_until(Instant::now() + LOCAL_TAKEOVER_WAIT).await;
            finish_takeover(&client, lock_key, &holder_id, generation).await?
        } else {
            Vec::new()
        };

        let (commands, command_receiver) = mpsc::unbounded_channel();
        let (admission, _) = watch::channel(!takeover_required);
        let actor_admission = admission.clone();
        let driver = driver_guard.take();
        let actor_holder_id = holder_id.clone();
        let actor = tokio::spawn(run_fence_actor(
            client,
            driver,
            command_receiver,
            actor_admission,
            lock_key,
            actor_holder_id,
            generation,
        ));
        let actor_abort = actor.abort_handle();
        let takeover_recovery = takeover_required.then_some(TakeoverCompletionRecoveryAuthority {
            lock_key,
            holder_id: holder_id.clone(),
            fence_generation: generation,
            operation_ids: recovery_operation_ids,
            next_index: 0,
        });
        Ok(Self {
            lock_key,
            generation,
            holder_id,
            commands,
            admission,
            actor_abort,
            actor: Mutex::new(Some(actor)),
            takeover_recovery,
        })
    }

    pub(crate) fn generation(&self) -> i64 {
        self.generation
    }

    pub(crate) fn take_takeover_recovery_authority(
        &mut self,
    ) -> Option<TakeoverCompletionRecoveryAuthority> {
        self.takeover_recovery.take()
    }

    pub(crate) async fn open_after_takeover_recovery(
        &self,
        authority: TakeoverCompletionRecoveryAuthority,
    ) -> Result<(), ServingFenceError> {
        if !authority.is_complete()
            || authority.lock_key != self.lock_key
            || authority.fence_generation != self.generation
            || authority.holder_id != self.holder_id
        {
            return Err(ServingFenceError::RecoveryIncomplete);
        }
        let mut uncertainty = SessionUncertaintyGuard::new(&self.admission, &self.actor_abort);
        let (reply, response) = oneshot::channel();
        self.commands
            .send(FenceCommand::OpenAfterRecovery { reply })
            .map_err(|_| ServingFenceError::Unavailable)?;
        response
            .await
            .map_err(|_| ServingFenceError::Unavailable)??;
        uncertainty.confirm();
        Ok(())
    }

    pub(crate) async fn authorize_consultation_attempt(
        &self,
        budget: DispatchPermitBudget,
        permit_set: ConsultationPermitSet,
    ) -> Result<FencedConsultationAttemptAuthority, ServingFenceError> {
        if self.readiness().await != ServingFenceReadiness::Ready {
            return Err(ServingFenceError::AdmissionClosed);
        }
        Ok(FencedConsultationAttemptAuthority {
            lock_key: self.lock_key,
            holder_id: self.holder_id.clone(),
            fence_generation: self.generation,
            budget,
            permit_set,
            lifecycle_seal: ConsultationLifecycleSeal::unarmed(&self.admission, &self.actor_abort),
        })
    }

    pub(crate) async fn readiness(&self) -> ServingFenceReadiness {
        if !*self.admission.borrow() {
            return ServingFenceReadiness::Unavailable;
        }
        let mut uncertainty = SessionUncertaintyGuard::new(&self.admission, &self.actor_abort);
        let (reply, response) = oneshot::channel();
        if self
            .commands
            .send(FenceCommand::Readiness { reply })
            .is_err()
        {
            return ServingFenceReadiness::Unavailable;
        }
        match response.await {
            Ok(Ok(())) => {
                uncertainty.confirm();
                ServingFenceReadiness::Ready
            }
            _ => ServingFenceReadiness::Unavailable,
        }
    }

    /// Run one outbound call under fresh database authorization. The closure is
    /// lazy and is never invoked if ownership, permit state, or time is invalid.
    /// It receives the exact conservative absolute deadline used by the fence,
    /// so the transport cannot widen the window by rebuilding it from a later
    /// remaining-duration observation. No reusable authorization value can
    /// escape this method.
    pub(crate) async fn authorize_and_dispatch<T, F, Fut>(
        &self,
        permit: &mut ConsultationDispatchPermit,
        request_commitment: KeyedDispatchRequestCommitment,
        dispatch: F,
    ) -> Result<T, ServingFenceError>
    where
        F: FnOnce(Instant) -> Fut,
        Fut: Future<Output = T>,
    {
        self.require_open()?;
        if permit.fence_generation != self.generation || permit.holder_id != self.holder_id {
            return Err(ServingFenceError::StaleGeneration);
        }
        match permit.state {
            DispatchPermitState::Ready => {}
            DispatchPermitState::Completed => {
                return Err(ServingFenceError::PermitAlreadyDispatched)
            }
            DispatchPermitState::Dispatching | DispatchPermitState::Uncertain => {
                return Err(ServingFenceError::PermitUncertain)
            }
        }
        permit.state = DispatchPermitState::Uncertain;
        let mut uncertainty = SessionUncertaintyGuard::new(&self.admission, &self.actor_abort);
        let authorize_started = Instant::now();
        let (reply, response) = oneshot::channel();
        self.commands
            .send(FenceCommand::AuthorizePermit {
                operation_id: permit.operation_id.as_str().to_owned(),
                kind: permit.kind.as_str(),
                ordinal: i16::from(permit.ordinal),
                request_commitment: request_commitment.as_str().to_owned(),
                expected_deadline_unix_ms: permit.deadline_unix_ms,
                reply,
            })
            .map_err(|_| ServingFenceError::Unavailable)?;
        let authorized = match response.await.map_err(|_| ServingFenceError::Unavailable)? {
            Ok(authorized) => authorized,
            Err(error) => {
                let Some(state) = permit_state_after_known_rejection(error) else {
                    return Err(error);
                };
                permit.state = state;
                uncertainty.confirm();
                return Err(error);
            }
        };
        let response_observed = Instant::now();
        let Some(local_deadline) = conservative_dispatch_deadline(
            permit.local_not_after,
            authorize_started,
            response_observed,
            authorized.remaining_ms,
            permit.budget,
        ) else {
            // PostgreSQL has already committed the one-shot marker. Even when
            // response transit exhausts the local window, this permit can
            // never become reusable. Recovery must conservatively record an
            // outcome-unknown completion.
            permit.state = DispatchPermitState::Uncertain;
            uncertainty.confirm();
            return Err(ServingFenceError::PermitExpired);
        };
        if !*self.admission.borrow() {
            return Err(ServingFenceError::Unavailable);
        }

        // The database authorization outcome is now fully known. Cancellation
        // after this point can make only this permit uncertain; connection
        // driver loss is independently propagated by the actor watch signal.
        uncertainty.confirm();
        let operation_id = permit.operation_id.as_str().to_owned();
        let kind = permit.kind.as_str();
        let ordinal = i16::from(permit.ordinal);
        let expected_deadline_unix_ms = permit.deadline_unix_ms;
        let dispatch_guard = PermitDispatchGuard::new(&mut permit.state);
        let result =
            run_guarded_dispatch(local_deadline, self.admission.subscribe(), dispatch).await;
        match result {
            Ok(output) => {
                let (reply, response) = oneshot::channel();
                self.commands
                    .send(FenceCommand::CompletePermit {
                        operation_id,
                        kind,
                        ordinal,
                        request_commitment: request_commitment.as_str().to_owned(),
                        expected_deadline_unix_ms,
                        reply,
                    })
                    .map_err(|_| ServingFenceError::Unavailable)?;
                response
                    .await
                    .map_err(|_| ServingFenceError::Unavailable)??;
                dispatch_guard.finish();
                Ok(output)
            }
            Err(error) => Err(error),
        }
    }

    /// Exercise the database permit-order boundary without the safe local
    /// cursor. Production has no equivalent capability.
    #[cfg(test)]
    pub(crate) async fn authorize_permit_position_for_test(
        &self,
        operation_id: &DispatchOperationId,
        kind: DispatchPermitKind,
        ordinal: u8,
        request_commitment: KeyedDispatchRequestCommitment,
        expected_deadline_unix_ms: i64,
    ) -> Result<(), ServingFenceError> {
        self.require_open()?;
        let mut uncertainty = SessionUncertaintyGuard::new(&self.admission, &self.actor_abort);
        let (reply, response) = oneshot::channel();
        self.commands
            .send(FenceCommand::AuthorizePermit {
                operation_id: operation_id.as_str().to_owned(),
                kind: kind.as_str(),
                ordinal: i16::from(ordinal),
                request_commitment: request_commitment.as_str().to_owned(),
                expected_deadline_unix_ms,
                reply,
            })
            .map_err(|_| ServingFenceError::Unavailable)?;
        let result = response
            .await
            .map_err(|_| ServingFenceError::Unavailable)?
            .map(|_| ());
        uncertainty.confirm();
        result
    }

    /// Close admission, release the database fence, and join its actor.
    ///
    /// The shared receiver permits explicit shutdown through an `Arc`; a
    /// repeated call remains unavailable because the actor is joined once.
    /// Dropping without a successful release retains the fail-closed abort.
    pub(crate) async fn release(&self) -> Result<(), ServingFenceError> {
        self.admission.send_replace(false);
        let mut uncertainty = SessionUncertaintyGuard::new(&self.admission, &self.actor_abort);
        let (reply, response) = oneshot::channel();
        self.commands
            .send(FenceCommand::Release { reply })
            .map_err(|_| ServingFenceError::Unavailable)?;
        let result = response.await.map_err(|_| ServingFenceError::Unavailable)?;
        let actor = self
            .actor
            .lock()
            .await
            .take()
            .ok_or(ServingFenceError::Unavailable)?;
        actor.await.map_err(|_| ServingFenceError::Unavailable)?;
        match result {
            Ok(()) => {
                uncertainty.confirm();
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn require_open(&self) -> Result<(), ServingFenceError> {
        if *self.admission.borrow() {
            Ok(())
        } else {
            Err(ServingFenceError::AdmissionClosed)
        }
    }
}

const fn permit_state_after_known_rejection(
    error: ServingFenceError,
) -> Option<DispatchPermitState> {
    match error {
        ServingFenceError::PermitExpired
        | ServingFenceError::PermitOrderViolation
        | ServingFenceError::RequestCommitmentMismatch => Some(DispatchPermitState::Ready),
        ServingFenceError::PermitCompleted
        | ServingFenceError::PermitAlreadyDispatched
        | ServingFenceError::PermitConflict => Some(DispatchPermitState::Completed),
        _ => None,
    }
}

impl Drop for PostgresServingFence {
    fn drop(&mut self) {
        self.admission.send_replace(false);
        if let Some(actor) = self.actor.get_mut().take() {
            actor.abort();
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_fence_actor(
    client: Client,
    connection_driver: ConnectionDriver,
    mut commands: mpsc::UnboundedReceiver<FenceCommand>,
    admission: watch::Sender<bool>,
    lock_key: ServingFenceLockKey,
    holder_id: String,
    generation: i64,
) {
    let mut driver = ConnectionDriverGuard::new(connection_driver);
    loop {
        let command = tokio::select! {
            biased;
            _ = driver.handle_mut() => break,
            command = commands.recv() => match command {
                Some(command) => command,
                None => break,
            },
        };
        let close = handle_fence_command(
            &client, &admission, lock_key, &holder_id, generation, command,
        )
        .await;
        if close {
            break;
        }
    }
    admission.send_replace(false);
    drop(client);
}

async fn handle_fence_command(
    client: &Client,
    admission: &watch::Sender<bool>,
    lock_key: ServingFenceLockKey,
    holder_id: &str,
    generation: i64,
    command: FenceCommand,
) -> bool {
    match command {
        FenceCommand::Readiness { reply } => {
            let result = actor_readiness(client, lock_key, holder_id, generation).await;
            let fatal = result.is_err();
            if fatal {
                admission.send_replace(false);
            }
            fatal || reply.send(result).is_err()
        }
        FenceCommand::AuthorizePermit {
            operation_id,
            kind,
            ordinal,
            request_commitment,
            expected_deadline_unix_ms,
            reply,
        } => {
            let result = actor_authorize_permit(
                client,
                lock_key,
                holder_id,
                generation,
                &operation_id,
                kind,
                ordinal,
                &request_commitment,
                expected_deadline_unix_ms,
            )
            .await;
            let fatal = !matches!(
                result,
                Ok(_)
                    | Err(ServingFenceError::PermitExpired
                        | ServingFenceError::PermitCompleted
                        | ServingFenceError::PermitAlreadyDispatched
                        | ServingFenceError::PermitOrderViolation
                        | ServingFenceError::PermitConflict
                        | ServingFenceError::RequestCommitmentMismatch)
            );
            if fatal {
                admission.send_replace(false);
            }
            fatal || reply.send(result).is_err()
        }
        FenceCommand::CompletePermit {
            operation_id,
            kind,
            ordinal,
            request_commitment,
            expected_deadline_unix_ms,
            reply,
        } => {
            let result = actor_complete_permit(
                client,
                lock_key,
                holder_id,
                generation,
                &operation_id,
                kind,
                ordinal,
                &request_commitment,
                expected_deadline_unix_ms,
            )
            .await;
            let fatal = !matches!(
                result,
                Ok(())
                    | Err(ServingFenceError::PermitCompleted
                        | ServingFenceError::PermitCompletionConflict)
            );
            if fatal {
                admission.send_replace(false);
            }
            fatal || reply.send(result).is_err()
        }
        FenceCommand::OpenAfterRecovery { reply } => {
            let result = actor_open_after_recovery(client, lock_key, holder_id, generation).await;
            if result.is_ok() {
                admission.send_replace(true);
            }
            let fatal = result.is_err();
            if fatal {
                admission.send_replace(false);
            }
            fatal || reply.send(result).is_err()
        }
        FenceCommand::Release { reply } => {
            admission.send_replace(false);
            let result = actor_release(client, lock_key, holder_id, generation).await;
            let _ = reply.send(result);
            true
        }
    }
}

async fn actor_readiness(
    client: &Client,
    lock_key: ServingFenceLockKey,
    holder_id: &str,
    generation: i64,
) -> Result<(), ServingFenceError> {
    let row = database_timeout(client.query_one(
        FENCE_STATUS_SQL,
        &[&lock_key.as_i64(), &holder_id, &generation],
    ))
    .await?;
    match try_str(&row, "outcome")? {
        "ready" => Ok(()),
        "ownership_lost" => Err(ServingFenceError::OwnershipLost),
        _ => Err(ServingFenceError::ProtocolDrift),
    }
}

#[allow(clippy::too_many_arguments)]
async fn actor_authorize_permit(
    client: &Client,
    lock_key: ServingFenceLockKey,
    holder_id: &str,
    generation: i64,
    operation_id: &str,
    kind: &str,
    ordinal: i16,
    request_commitment: &str,
    expected_deadline_unix_ms: i64,
) -> Result<AuthorizationWindow, ServingFenceError> {
    let row = database_timeout(client.query_one(
        PERMIT_AUTHORIZE_SQL,
        &[
            &lock_key.as_i64(),
            &holder_id,
            &generation,
            &operation_id,
            &kind,
            &ordinal,
            &request_commitment,
            &expected_deadline_unix_ms,
        ],
    ))
    .await?;
    match try_str(&row, "outcome")? {
        "authorized" => {}
        "expired" => return Err(ServingFenceError::PermitExpired),
        "unknown" => return Err(ServingFenceError::PermitUnknown),
        "completed" => return Err(ServingFenceError::PermitCompleted),
        "already_dispatched" => return Err(ServingFenceError::PermitAlreadyDispatched),
        "permit_order_violation" => return Err(ServingFenceError::PermitOrderViolation),
        "operation_conflict" => return Err(ServingFenceError::PermitConflict),
        "request_commitment_mismatch" => return Err(ServingFenceError::RequestCommitmentMismatch),
        "permit_mismatch" => return Err(ServingFenceError::ProtocolDrift),
        "abandoned" => return Err(ServingFenceError::PermitAbandoned),
        "stale_generation" => return Err(ServingFenceError::StaleGeneration),
        "admission_closed" => return Err(ServingFenceError::AdmissionClosed),
        "ownership_lost" => return Err(ServingFenceError::OwnershipLost),
        _ => return Err(ServingFenceError::ProtocolDrift),
    }
    if try_i64(&row, "deadline_unix_ms")? != expected_deadline_unix_ms {
        return Err(ServingFenceError::ProtocolDrift);
    }
    Ok(AuthorizationWindow {
        remaining_ms: try_i64(&row, "remaining_ms")?,
    })
}

#[allow(clippy::too_many_arguments)]
async fn actor_complete_permit(
    client: &Client,
    lock_key: ServingFenceLockKey,
    holder_id: &str,
    generation: i64,
    operation_id: &str,
    kind: &str,
    ordinal: i16,
    request_commitment: &str,
    expected_deadline_unix_ms: i64,
) -> Result<(), ServingFenceError> {
    let row = database_timeout(client.query_one(
        PERMIT_COMPLETE_SQL,
        &[
            &lock_key.as_i64(),
            &holder_id,
            &generation,
            &operation_id,
            &kind,
            &ordinal,
            &request_commitment,
        ],
    ))
    .await?;
    match try_str(&row, "outcome")? {
        "completed" | "already_completed" => {}
        "completion_conflict" => return Err(ServingFenceError::PermitCompletionConflict),
        "unknown" => return Err(ServingFenceError::PermitUnknown),
        "abandoned" => return Err(ServingFenceError::PermitAbandoned),
        "stale_generation" => return Err(ServingFenceError::StaleGeneration),
        "admission_closed" => return Err(ServingFenceError::AdmissionClosed),
        "ownership_lost" => return Err(ServingFenceError::OwnershipLost),
        _ => return Err(ServingFenceError::ProtocolDrift),
    }
    if try_i64(&row, "deadline_unix_ms")? != expected_deadline_unix_ms {
        return Err(ServingFenceError::ProtocolDrift);
    }
    Ok(())
}

async fn actor_open_after_recovery(
    client: &Client,
    lock_key: ServingFenceLockKey,
    holder_id: &str,
    generation: i64,
) -> Result<(), ServingFenceError> {
    let row = database_timeout(client.query_one(
        FENCE_OPEN_AFTER_RECOVERY_SQL,
        &[&lock_key.as_i64(), &holder_id, &generation],
    ))
    .await?;
    match try_str(&row, "outcome")? {
        "opened" => Ok(()),
        "recovery_incomplete" => Err(ServingFenceError::RecoveryIncomplete),
        "ownership_lost" => Err(ServingFenceError::OwnershipLost),
        _ => Err(ServingFenceError::ProtocolDrift),
    }
}

async fn actor_release(
    client: &Client,
    lock_key: ServingFenceLockKey,
    holder_id: &str,
    generation: i64,
) -> Result<(), ServingFenceError> {
    let row = database_timeout(client.query_one(
        FENCE_RELEASE_SQL,
        &[&lock_key.as_i64(), &holder_id, &generation],
    ))
    .await?;
    match try_str(&row, "outcome")? {
        "released" => Ok(()),
        "ownership_lost" => Err(ServingFenceError::OwnershipLost),
        _ => Err(ServingFenceError::ProtocolDrift),
    }
}

async fn finish_takeover(
    client: &Client,
    lock_key: ServingFenceLockKey,
    holder_id: &str,
    generation: i64,
) -> Result<Vec<DispatchOperationId>, ServingFenceError> {
    let deadline = Instant::now() + MAX_POST_LOCAL_BARRIER_WAIT;
    loop {
        let row = database_timeout(client.query_one(
            FENCE_FINALIZE_SQL,
            &[&lock_key.as_i64(), &holder_id, &generation],
        ))
        .await?;
        match try_str(&row, "outcome")? {
            "recovery_ready" => {
                let operation_ids = row
                    .try_get::<_, Vec<String>>("recovery_operation_ids")
                    .map_err(|_| ServingFenceError::ProtocolDrift)?;
                let parsed = operation_ids
                    .iter()
                    .map(|operation_id| DispatchOperationId::parse(operation_id))
                    .collect::<Result<Vec<_>, _>>()?;
                if parsed
                    .windows(2)
                    .any(|pair| pair[0].as_str().as_bytes() >= pair[1].as_str().as_bytes())
                {
                    return Err(ServingFenceError::ProtocolDrift);
                }
                return Ok(parsed);
            }
            "barrier_pending" => {
                let remaining_ms = try_i64(&row, "remaining_ms")?;
                if remaining_ms <= 0 || Instant::now() >= deadline {
                    return Err(ServingFenceError::TakeoverTimedOut);
                }
                let sleep = Duration::from_millis(remaining_ms as u64).min(MAX_BARRIER_POLL);
                tokio::time::sleep(sleep).await;
            }
            "ownership_lost" => return Err(ServingFenceError::OwnershipLost),
            _ => return Err(ServingFenceError::ProtocolDrift),
        }
    }
}

fn conservative_dispatch_deadline(
    local_not_after: Instant,
    authorize_started: Instant,
    response_observed: Instant,
    postgres_remaining_ms: i64,
    budget: DispatchPermitBudget,
) -> Option<Instant> {
    if postgres_remaining_ms <= 0 {
        return None;
    }
    let budget = Duration::from_millis(budget.as_milliseconds() as u64);
    let postgres_remaining = Duration::from_millis(postgres_remaining_ms as u64)
        .min(budget)
        .min(HARD_SOURCE_DEADLINE);
    let from_postgres_remaining = authorize_started.checked_add(postgres_remaining)?;
    let deadline = local_not_after.min(from_postgres_remaining);
    (deadline > response_observed).then_some(deadline)
}

async fn run_guarded_dispatch<T, F, Fut>(
    deadline: Instant,
    mut admission: watch::Receiver<bool>,
    dispatch: F,
) -> Result<T, ServingFenceError>
where
    F: FnOnce(Instant) -> Fut,
    Fut: Future<Output = T>,
{
    if Instant::now() >= deadline {
        return Err(ServingFenceError::PermitExpired);
    }
    if !*admission.borrow() {
        return Err(ServingFenceError::Unavailable);
    }
    let outbound = dispatch(deadline);
    tokio::pin!(outbound);
    let sealed = async {
        loop {
            if admission.changed().await.is_err() || !*admission.borrow() {
                return;
            }
        }
    };
    tokio::pin!(sealed);
    tokio::select! {
        biased;
        _ = &mut sealed => Err(ServingFenceError::Unavailable),
        _ = tokio::time::sleep_until(deadline) => Err(ServingFenceError::PermitExpired),
        output = &mut outbound => Ok(output),
    }
}

async fn initialization_timeout<T, F>(future: F) -> Result<T, ServingFenceError>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(DATABASE_OPERATION_TIMEOUT, future)
        .await
        .map_err(|_| ServingFenceError::Unavailable)
}

async fn database_timeout<F>(future: F) -> Result<Row, ServingFenceError>
where
    F: Future<Output = Result<Row, PostgresError>>,
{
    tokio::time::timeout(DATABASE_OPERATION_TIMEOUT, future)
        .await
        .map_err(|_| ServingFenceError::Unavailable)?
        .map_err(|_| ServingFenceError::Unavailable)
}

fn map_runtime_capability_error(error: RuntimeCapabilityError) -> ServingFenceError {
    match error {
        RuntimeCapabilityError::WrongRuntimeIdentity => ServingFenceError::WrongRuntimeIdentity,
        RuntimeCapabilityError::Drift => ServingFenceError::CapabilityDrift,
        RuntimeCapabilityError::Unavailable => ServingFenceError::Unavailable,
    }
}

fn try_bool(row: &Row, column: &str) -> Result<bool, ServingFenceError> {
    row.try_get(column)
        .map_err(|_| ServingFenceError::ProtocolDrift)
}

fn try_i64(row: &Row, column: &str) -> Result<i64, ServingFenceError> {
    row.try_get(column)
        .map_err(|_| ServingFenceError::ProtocolDrift)
}

fn try_str<'a>(row: &'a Row, column: &str) -> Result<&'a str, ServingFenceError> {
    row.try_get(column)
        .map_err(|_| ServingFenceError::ProtocolDrift)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use registry_platform_audit::AuditHashSecret;

    use crate::consultation::commitments::ConsultationCommitmentError;

    use super::*;

    fn test_dispatch(
        credential_count: u8,
        data_count: u8,
    ) -> (AuditedConsultationDispatch, tokio::task::JoinHandle<()>) {
        let (admission, _) = watch::channel(true);
        let actor = tokio::spawn(std::future::pending::<()>());
        let operation_id = DispatchOperationId::from_ulid(Ulid::new());
        let budget = DispatchPermitBudget::new(Duration::from_secs(1)).expect("valid budget");
        let permit_set = ConsultationPermitSet::from_counts(credential_count, data_count)
            .expect("valid permit set");
        let deadline_unix_ms = 1_000;
        let local_not_after = Instant::now() + Duration::from_secs(1);
        let permits = permit_set
            .permits()
            .iter()
            .map(|(kind, ordinal)| ConsultationDispatchPermit {
                operation_id: operation_id.clone(),
                kind: *kind,
                ordinal: *ordinal,
                fence_generation: 1,
                holder_id: Ulid::new().to_string(),
                budget,
                deadline_unix_ms,
                local_not_after,
                state: DispatchPermitState::Ready,
            })
            .collect();
        (
            AuditedConsultationDispatch {
                operation_id,
                attempt_envelope_id: Ulid::new().to_string(),
                attempt_record_hash: [7; 32],
                lock_key: ServingFenceLockKey::new(1).expect("valid lock key"),
                fence_generation: 1,
                holder_id: Ulid::new().to_string(),
                deadline_unix_ms,
                local_not_after,
                permits,
                request_effect_hasher: AuditChainHasher::keyed(
                    AuditHashSecret::new(vec![0x42; 32]).expect("strong test key"),
                ),
                lifecycle_seal: ConsultationLifecycleSeal::unarmed(
                    &admission,
                    &actor.abort_handle(),
                ),
            },
            actor,
        )
    }

    #[tokio::test]
    async fn shared_fence_can_release_and_join_its_actor() {
        let (commands, mut command_receiver) = mpsc::unbounded_channel();
        let (admission, _) = watch::channel(true);
        let actor = tokio::spawn(async move {
            let command = command_receiver.recv().await.expect("release command");
            let FenceCommand::Release { reply } = command else {
                panic!("shared fence sends only the expected release command");
            };
            reply.send(Ok(())).expect("release receiver remains live");
        });
        let actor_abort = actor.abort_handle();
        let fence = Arc::new(PostgresServingFence {
            lock_key: ServingFenceLockKey::new(1).expect("test key is valid"),
            generation: 1,
            holder_id: Ulid::new().to_string(),
            commands,
            admission,
            actor_abort,
            actor: Mutex::new(Some(actor)),
            takeover_recovery: None,
        });

        Arc::clone(&fence)
            .release()
            .await
            .expect("shared fence releases cleanly");

        assert!(!*fence.admission.borrow());
        assert!(fence.actor.lock().await.is_none());
    }

    #[tokio::test]
    async fn dropping_an_unreleased_shared_fence_aborts_its_actor() {
        let (commands, _command_receiver) = mpsc::unbounded_channel();
        let (admission, mut admission_receiver) = watch::channel(true);
        let actor = tokio::spawn(std::future::pending::<()>());
        let actor_abort = actor.abort_handle();
        let fence = PostgresServingFence {
            lock_key: ServingFenceLockKey::new(1).expect("test key is valid"),
            generation: 1,
            holder_id: Ulid::new().to_string(),
            commands,
            admission,
            actor_abort: actor_abort.clone(),
            actor: Mutex::new(Some(actor)),
            takeover_recovery: None,
        };

        drop(fence);
        admission_receiver
            .changed()
            .await
            .expect("drop publishes closed admission");
        tokio::task::yield_now().await;

        assert!(!*admission_receiver.borrow());
        assert!(actor_abort.is_finished());
    }

    #[test]
    fn lock_key_cannot_alias_migration_or_unconfigured_zero() {
        assert_eq!(
            ServingFenceLockKey::new(0),
            Err(ServingFenceError::InvalidLockKey)
        );
        assert_eq!(
            ServingFenceLockKey::new(MIGRATION_ADVISORY_LOCK_KEY_V1),
            Err(ServingFenceError::InvalidLockKey)
        );
        assert!(ServingFenceLockKey::new(-9_223_372_036_854_000_001).is_ok());
    }

    #[test]
    fn permit_budget_is_exactly_millisecond_bounded() {
        assert_eq!(
            DispatchPermitBudget::new(Duration::ZERO),
            Err(ServingFenceError::InvalidPermitBudget)
        );
        assert_eq!(
            DispatchPermitBudget::new(Duration::from_micros(1_500)),
            Err(ServingFenceError::InvalidPermitBudget)
        );
        assert_eq!(
            DispatchPermitBudget::new(HARD_SOURCE_DEADLINE + Duration::from_millis(1)),
            Err(ServingFenceError::InvalidPermitBudget)
        );
        assert_eq!(
            DispatchPermitBudget::new(HARD_SOURCE_DEADLINE)
                .expect("hard deadline is allowed")
                .as_milliseconds(),
            60_000
        );
    }

    #[test]
    fn nonmutating_permit_rejections_keep_current_permit_ready() {
        assert_eq!(
            permit_state_after_known_rejection(ServingFenceError::RequestCommitmentMismatch),
            Some(DispatchPermitState::Ready)
        );
        assert_eq!(
            permit_state_after_known_rejection(ServingFenceError::PermitConflict),
            Some(DispatchPermitState::Completed),
            "a durable operation conflict remains fail-closed"
        );
        assert_eq!(
            permit_state_after_known_rejection(ServingFenceError::PermitOrderViolation),
            Some(DispatchPermitState::Ready),
            "the SQL order rejection proves this local permit was not consumed"
        );
        assert_eq!(
            permit_state_after_known_rejection(ServingFenceError::Unavailable),
            None,
            "uncertain failures cannot reset a permit"
        );
    }

    #[tokio::test]
    async fn audited_dispatch_commits_complete_effect_canonically_and_allows_repeats() {
        let (dispatch, actor) = test_dispatch(0, 2);
        let first = CanonicalDispatchRequestEffect::try_from_complete_value(serde_json::json!({
            "destination_id": "registry-source",
            "method": "POST",
            "target": "/records?active=true",
            "headers": [{
                "name": "content-type",
                "value_base64url": "YXBwbGljYXRpb24vanNvbg",
            }],
            "body_base64url": "eyJzdWJqZWN0IjoiUGVyc29uLTQyIn0",
        }))
        .expect("complete effect");
        let repeated = CanonicalDispatchRequestEffect::try_from_complete_value(serde_json::json!({
            "body_base64url": "eyJzdWJqZWN0IjoiUGVyc29uLTQyIn0",
            "headers": [{
                "value_base64url": "YXBwbGljYXRpb24vanNvbg",
                "name": "content-type",
            }],
            "target": "/records?active=true",
            "method": "POST",
            "destination_id": "registry-source",
        }))
        .expect("same complete effect in different key order");
        let first = dispatch
            .commit_request_effect(first)
            .expect("keyed request commitment");
        let repeated = dispatch
            .commit_request_effect(repeated)
            .expect("repeated keyed request commitment");
        assert_eq!(first.as_str(), repeated.as_str());
        assert!(first.as_str().starts_with("hmac-sha256:"));
        assert_eq!(first.as_str().len(), 76);
        assert!(!format!("{first:?}").contains("Person-42"));
        actor.abort();
    }

    #[test]
    fn dispatch_effect_rejects_incomplete_or_credential_bearing_shapes() {
        for value in [
            serde_json::json!({
                "destination_id": "registry-source",
                "method": "GET",
                "target": "/records",
                "headers": [],
            }),
            serde_json::json!({
                "destination_id": "registry-source",
                "method": "GET",
                "target": "/records",
                "headers": [],
                "body_base64url": null,
                "authorization": "Bearer secret",
            }),
        ] {
            assert_eq!(
                CanonicalDispatchRequestEffect::try_from_complete_value(value).err(),
                Some(ConsultationCommitmentError::AuthorizationMismatch)
            );
        }
    }

    #[test]
    fn dynamic_data_permit_budget_is_bounded_at_sixteen_ordinals() {
        let maximum = ConsultationPermitSet::from_counts(1, 16).expect("maximum manifest");
        let data_ordinals = maximum
            .permits()
            .iter()
            .filter_map(|(kind, ordinal)| (*kind == DispatchPermitKind::Data).then_some(*ordinal))
            .collect::<Vec<_>>();
        assert_eq!(data_ordinals, (0..16).collect::<Vec<_>>());
        assert!(matches!(
            ConsultationPermitSet::from_counts(0, 17),
            Err(ServingFenceError::InvalidPermitManifest)
        ));
    }

    #[tokio::test]
    async fn dispatch_exposes_only_the_next_data_ordinal() {
        let (mut dispatch, actor) = test_dispatch(1, 3);
        assert!(dispatch
            .credential_permit_mut()
            .expect("credential lookup")
            .is_some());

        let first = dispatch
            .next_data_permit_mut()
            .expect("first lookup")
            .expect("first permit");
        assert_eq!(first.ordinal, 0);
        first.state = DispatchPermitState::Completed;
        assert_eq!(
            dispatch.credential_permit_mut().unwrap_err(),
            ServingFenceError::PermitOrderViolation
        );

        let second = dispatch
            .next_data_permit_mut()
            .expect("second lookup")
            .expect("second permit");
        assert_eq!(second.ordinal, 1);
        second.state = DispatchPermitState::Completed;
        let third = dispatch
            .next_data_permit_mut()
            .expect("third lookup")
            .expect("third permit");
        assert_eq!(third.ordinal, 2);
        third.state = DispatchPermitState::Completed;
        assert!(dispatch
            .next_data_permit_mut()
            .expect("exhausted lookup")
            .is_none());
        actor.abort();
    }

    #[tokio::test]
    async fn dispatch_rejects_uncertain_credentials_and_data_gaps() {
        let (mut dispatch, actor) = test_dispatch(1, 2);
        dispatch.permits[0].state = DispatchPermitState::Uncertain;
        assert_eq!(
            dispatch.next_data_permit_mut().unwrap_err(),
            ServingFenceError::PermitUncertain
        );
        dispatch.permits[0].state = DispatchPermitState::Ready;
        dispatch.permits[2].state = DispatchPermitState::Completed;
        assert_eq!(
            dispatch.next_data_permit_mut().unwrap_err(),
            ServingFenceError::PermitOrderViolation
        );
        actor.abort();

        let (mut cache_hit_dispatch, actor) = test_dispatch(1, 1);
        assert_eq!(
            cache_hit_dispatch
                .next_data_permit_mut()
                .expect("cache-hit data lookup")
                .expect("data permit")
                .ordinal,
            0
        );
        actor.abort();
    }

    #[test]
    fn local_takeover_wait_equals_protocol_deadline_plus_grace() {
        assert_eq!(
            LOCAL_TAKEOVER_WAIT,
            HARD_SOURCE_DEADLINE + CANCELLATION_GRACE
        );
    }

    #[tokio::test]
    async fn consultation_lifecycle_seal_fails_closed_only_while_armed() {
        let (admission, _) = watch::channel(true);
        let unarmed_actor = tokio::spawn(std::future::pending::<()>());
        let unarmed = ConsultationLifecycleSeal::unarmed(&admission, &unarmed_actor.abort_handle());
        drop(unarmed);
        tokio::task::yield_now().await;
        assert!(*admission.borrow());
        assert!(!unarmed_actor.is_finished());
        unarmed_actor.abort();

        let armed_actor = tokio::spawn(std::future::pending::<()>());
        let mut armed = ConsultationLifecycleSeal::unarmed(&admission, &armed_actor.abort_handle());
        armed.arm_for_attempt_cas();
        drop(armed);
        tokio::task::yield_now().await;
        assert!(!*admission.borrow());
        assert!(armed_actor
            .await
            .expect_err("armed seal aborts actor")
            .is_cancelled());

        admission.send_replace(true);
        let completed_actor = tokio::spawn(std::future::pending::<()>());
        let mut completed =
            ConsultationLifecycleSeal::unarmed(&admission, &completed_actor.abort_handle());
        completed.arm_for_attempt_cas();
        completed.disarm_after_terminal_completion();
        drop(completed);
        tokio::task::yield_now().await;
        assert!(*admission.borrow());
        assert!(!completed_actor.is_finished());
        completed_actor.abort();
    }

    #[tokio::test]
    async fn exhausted_head_changed_attempt_retries_leave_fence_ready() {
        let (admission, _) = watch::channel(true);
        let actor = tokio::spawn(std::future::pending::<()>());
        let mut authority = FencedConsultationAttemptAuthority {
            lock_key: ServingFenceLockKey::new(1).expect("test key is valid"),
            holder_id: Ulid::new().to_string(),
            fence_generation: 1,
            budget: DispatchPermitBudget::new(Duration::from_millis(1))
                .expect("test budget is valid"),
            permit_set: ConsultationPermitSet::from_counts(0, 0)
                .expect("empty permit set is valid"),
            lifecycle_seal: ConsultationLifecycleSeal::unarmed(&admission, &actor.abort_handle()),
        };
        for _ in 0..8 {
            authority.arm_lifecycle_seal();
            authority.disarm_after_non_mutating_attempt_cas();
        }
        drop(authority);
        tokio::task::yield_now().await;
        assert!(*admission.borrow());
        assert!(!actor.is_finished());
        actor.abort();
    }

    #[test]
    fn conservative_deadline_never_widens_budget_or_expired_pg_window() {
        let budget = DispatchPermitBudget::new(Duration::from_secs(10)).expect("valid budget");
        let permit_created = Instant::now();
        let local_not_after = permit_created + Duration::from_secs(10);
        let authorize_started = permit_created + Duration::from_secs(9);
        let response_observed = permit_created + Duration::from_secs(9);
        let deadline = conservative_dispatch_deadline(
            local_not_after,
            authorize_started,
            response_observed,
            100_000,
            budget,
        )
        .expect("creation-anchored budget has one second remaining");
        assert_eq!(deadline, local_not_after);
        assert_eq!(deadline, permit_created + Duration::from_secs(10));
        assert!(conservative_dispatch_deadline(
            local_not_after,
            authorize_started,
            response_observed,
            0,
            budget,
        )
        .is_none());
    }

    #[test]
    fn authorization_transit_only_consumes_the_postgres_window() {
        let budget = DispatchPermitBudget::new(Duration::from_secs(10)).expect("valid budget");
        let permit_created = Instant::now();
        let local_not_after = permit_created + Duration::from_secs(10);
        let authorize_started = permit_created + Duration::from_secs(2);
        let response_observed = permit_created + Duration::from_secs(4);
        let deadline = conservative_dispatch_deadline(
            local_not_after,
            authorize_started,
            response_observed,
            5_000,
            budget,
        )
        .expect("one second remains after response transit");
        assert_eq!(deadline, permit_created + Duration::from_secs(7));
        assert!(deadline < response_observed + Duration::from_secs(5));

        let fully_consumed_response = permit_created + Duration::from_secs(8);
        assert!(conservative_dispatch_deadline(
            local_not_after,
            authorize_started,
            fully_consumed_response,
            5_000,
            budget,
        )
        .is_none());
    }

    #[tokio::test]
    async fn expired_deadline_never_invokes_lazy_dispatch() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let (_, admission) = watch::channel(true);
        let invocations = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&invocations);
        let result = run_guarded_dispatch(Instant::now(), admission, move |_deadline| async move {
            observed.fetch_add(1, Ordering::SeqCst);
        })
        .await;
        assert_eq!(result, Err(ServingFenceError::PermitExpired));
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn guarded_dispatch_passes_the_exact_deadline_without_widening() {
        let (_admission_tx, admission) = watch::channel(true);
        let exact_deadline = Instant::now() + Duration::from_secs(1);

        // Model callback transit after the deadline was selected. Rebuilding a
        // deadline from a remaining duration here could move it later; the
        // callback must instead receive the original instant bit-for-bit.
        tokio::time::sleep(Duration::from_millis(5)).await;
        let observed_deadline =
            run_guarded_dispatch(exact_deadline, admission, |received_deadline| async move {
                received_deadline
            })
            .await
            .expect("dispatch completes before its exact deadline");

        assert_eq!(observed_deadline, exact_deadline);
    }

    #[test]
    fn operation_ids_require_canonical_ulid_text() {
        let canonical = Ulid::new().to_string();
        assert!(DispatchOperationId::parse(&canonical).is_ok());
        assert_eq!(
            DispatchOperationId::parse(&canonical.to_ascii_lowercase()),
            Err(ServingFenceError::InvalidOperationId)
        );
        assert_eq!(
            DispatchOperationId::parse("not-an-operation-id"),
            Err(ServingFenceError::InvalidOperationId)
        );
    }
}

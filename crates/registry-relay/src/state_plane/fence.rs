// SPDX-License-Identifier: Apache-2.0
//! Dedicated-connection serving fence and durable dispatch permits.
//!
//! This capability is compiled private infrastructure. It is not serving
//! authority by itself. The consultation runtime must run every credential or
//! data call inside [`PostgresServingFence::authorize_and_dispatch`] and must
//! never retain the raw PostgreSQL client.

use std::{future::Future, time::Duration};

use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::{AbortHandle, JoinHandle},
    time::Instant,
};
use tokio_postgres::{Client, Error as PostgresError, Row};
use ulid::Ulid;

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
const PERMIT_CREATE_SQL: &str =
    "SELECT * FROM relay_state_api.dispatch_permit_create_v1($1, $2, $3, $4, $5)";
const PERMIT_AUTHORIZE_SQL: &str = r#"
WITH permit_check AS MATERIALIZED (
    SELECT * FROM relay_state_api.dispatch_permit_authorize_v1($1, $2, $3, $4)
)
SELECT permit_check.*,
       permit_check.deadline_unix_ms
           - floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
           - 1 AS remaining_ms
FROM permit_check
"#;
const PERMIT_COMPLETE_SQL: &str =
    "SELECT * FROM relay_state_api.dispatch_permit_complete_v1($1, $2, $3, $4)";

const DATABASE_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const HARD_SOURCE_DEADLINE: Duration = Duration::from_secs(10);
const CANCELLATION_GRACE: Duration = Duration::from_secs(1);
const LOCAL_TAKEOVER_WAIT: Duration = Duration::from_secs(11);
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

/// Durable permit identity. Possession is not outbound-call authority.
pub(crate) struct DispatchPermit {
    operation_id: DispatchOperationId,
    fence_generation: i64,
    holder_id: String,
    budget: DispatchPermitBudget,
    deadline_unix_ms: i64,
    local_not_after: Instant,
    state: DispatchPermitState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchPermitState {
    Active,
    Dispatching,
    Completed,
    Uncertain,
}

impl DispatchPermit {
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

impl std::fmt::Debug for DispatchPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DispatchPermit")
            .field("operation_id", &"<redacted>")
            .field("fence_generation", &self.fence_generation)
            .field("holder_id", &"<redacted>")
            .field("budget", &self.budget)
            .field("deadline_unix_ms", &self.deadline_unix_ms)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServingFenceReadiness {
    Ready,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PermitCompletionOutcome {
    Completed,
    AlreadyCompleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ServingFenceError {
    #[error("Relay serving-fence lock key is invalid")]
    InvalidLockKey,
    #[error("Relay dispatch operation identifier is invalid")]
    InvalidOperationId,
    #[error("Relay dispatch permit budget is invalid")]
    InvalidPermitBudget,
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
    #[error("Relay dispatch permit is an identical replay")]
    PermitReplay,
    #[error("Relay dispatch permit conflicts with a durable operation")]
    PermitConflict,
    #[error("Relay dispatch permit is unknown")]
    PermitUnknown,
    #[error("Relay dispatch permit has expired")]
    PermitExpired,
    #[error("Relay dispatch permit has completed")]
    PermitCompleted,
    #[error("Relay dispatch permit was abandoned during takeover")]
    PermitAbandoned,
    #[error("Relay dispatch permit outcome is uncertain")]
    PermitUncertain,
    #[error("Relay dispatch permit belongs to a stale fence generation")]
    StaleGeneration,
    #[error("Relay serving-fence takeover did not reach its database barrier")]
    TakeoverTimedOut,
    #[error("Relay serving-fence database protocol has drifted")]
    ProtocolDrift,
    #[error("Relay serving fence is unavailable")]
    Unavailable,
}

/// Execute-only fence capability backed by one dedicated PostgreSQL session.
pub(crate) struct PostgresServingFence {
    generation: i64,
    holder_id: String,
    commands: mpsc::UnboundedSender<FenceCommand>,
    admission: watch::Sender<bool>,
    actor_abort: AbortHandle,
    actor: Option<JoinHandle<()>>,
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
        *self.state = DispatchPermitState::Active;
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
struct CreatedPermit {
    fence_generation: i64,
    holder_id: String,
    deadline_unix_ms: i64,
}

#[derive(Debug)]
struct AuthorizationWindow {
    remaining_ms: i64,
}

enum FenceCommand {
    Readiness {
        reply: oneshot::Sender<Result<(), ServingFenceError>>,
    },
    CreatePermit {
        operation_id: String,
        budget_ms: i32,
        reply: oneshot::Sender<Result<CreatedPermit, ServingFenceError>>,
    },
    AuthorizePermit {
        operation_id: String,
        expected_deadline_unix_ms: i64,
        reply: oneshot::Sender<Result<AuthorizationWindow, ServingFenceError>>,
    },
    CompletePermit {
        operation_id: String,
        reply: oneshot::Sender<Result<PermitCompletionOutcome, ServingFenceError>>,
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
        if takeover_required {
            // Start no earlier than the observed successful acquisition. This
            // deliberately waits longer than eleven seconds from PostgreSQL's
            // actual lock acquisition rather than risking a shortened barrier.
            tokio::time::sleep_until(Instant::now() + LOCAL_TAKEOVER_WAIT).await;
            finish_takeover(&client, lock_key, &holder_id, generation).await?;
        }

        let (commands, command_receiver) = mpsc::unbounded_channel();
        let (admission, _) = watch::channel(true);
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
        Ok(Self {
            generation,
            holder_id,
            commands,
            admission,
            actor_abort,
            actor: Some(actor),
        })
    }

    pub(crate) fn generation(&self) -> i64 {
        self.generation
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

    pub(crate) async fn create_permit(
        &self,
        operation_id: DispatchOperationId,
        budget: DispatchPermitBudget,
    ) -> Result<DispatchPermit, ServingFenceError> {
        self.require_open()?;
        let create_started = Instant::now();
        let mut uncertainty = SessionUncertaintyGuard::new(&self.admission, &self.actor_abort);
        let (reply, response) = oneshot::channel();
        self.commands
            .send(FenceCommand::CreatePermit {
                operation_id: operation_id.as_str().to_owned(),
                budget_ms: budget.as_milliseconds(),
                reply,
            })
            .map_err(|_| ServingFenceError::Unavailable)?;
        let created = match response.await.map_err(|_| ServingFenceError::Unavailable)? {
            Ok(created) => created,
            Err(ServingFenceError::PermitReplay) => {
                uncertainty.confirm();
                return Err(ServingFenceError::PermitReplay);
            }
            Err(ServingFenceError::PermitConflict) => {
                uncertainty.confirm();
                return Err(ServingFenceError::PermitConflict);
            }
            Err(error) => return Err(error),
        };
        let permit = DispatchPermit {
            operation_id,
            fence_generation: created.fence_generation,
            holder_id: created.holder_id,
            budget,
            deadline_unix_ms: created.deadline_unix_ms,
            local_not_after: create_started
                + Duration::from_millis(budget.as_milliseconds() as u64),
            state: DispatchPermitState::Active,
        };
        uncertainty.confirm();
        Ok(permit)
    }

    /// Run one outbound call under fresh database authorization. The closure is
    /// lazy and is never invoked if ownership, permit state, or time is invalid.
    /// No reusable authorization value can escape this method.
    pub(crate) async fn authorize_and_dispatch<T, F, Fut>(
        &self,
        permit: &mut DispatchPermit,
        dispatch: F,
    ) -> Result<T, ServingFenceError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        self.require_open()?;
        if permit.fence_generation != self.generation || permit.holder_id != self.holder_id {
            return Err(ServingFenceError::StaleGeneration);
        }
        match permit.state {
            DispatchPermitState::Active => {}
            DispatchPermitState::Completed => return Err(ServingFenceError::PermitCompleted),
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
                expected_deadline_unix_ms: permit.deadline_unix_ms,
                reply,
            })
            .map_err(|_| ServingFenceError::Unavailable)?;
        let authorized = match response.await.map_err(|_| ServingFenceError::Unavailable)? {
            Ok(authorized) => authorized,
            Err(ServingFenceError::PermitExpired) => {
                permit.state = DispatchPermitState::Active;
                uncertainty.confirm();
                return Err(ServingFenceError::PermitExpired);
            }
            Err(ServingFenceError::PermitCompleted) => {
                permit.state = DispatchPermitState::Completed;
                uncertainty.confirm();
                return Err(ServingFenceError::PermitCompleted);
            }
            Err(error) => return Err(error),
        };
        let response_observed = Instant::now();
        let Some(local_deadline) = conservative_dispatch_deadline(
            permit.local_not_after,
            authorize_started,
            response_observed,
            authorized.remaining_ms,
            permit.budget,
        ) else {
            permit.state = DispatchPermitState::Active;
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
        let dispatch_guard = PermitDispatchGuard::new(&mut permit.state);
        let result =
            run_guarded_dispatch(local_deadline, self.admission.subscribe(), dispatch).await;
        match result {
            Ok(output) => {
                dispatch_guard.finish();
                Ok(output)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn complete_permit(
        &self,
        permit: &mut DispatchPermit,
    ) -> Result<PermitCompletionOutcome, ServingFenceError> {
        self.require_open()?;
        if permit.fence_generation != self.generation || permit.holder_id != self.holder_id {
            return Err(ServingFenceError::StaleGeneration);
        }
        match permit.state {
            DispatchPermitState::Completed => return Ok(PermitCompletionOutcome::AlreadyCompleted),
            DispatchPermitState::Active => {}
            DispatchPermitState::Dispatching | DispatchPermitState::Uncertain => {
                return Err(ServingFenceError::PermitUncertain)
            }
        }
        permit.state = DispatchPermitState::Uncertain;
        let mut uncertainty = SessionUncertaintyGuard::new(&self.admission, &self.actor_abort);
        let (reply, response) = oneshot::channel();
        self.commands
            .send(FenceCommand::CompletePermit {
                operation_id: permit.operation_id.as_str().to_owned(),
                reply,
            })
            .map_err(|_| ServingFenceError::Unavailable)?;
        match response.await.map_err(|_| ServingFenceError::Unavailable)? {
            Ok(outcome) => {
                permit.state = DispatchPermitState::Completed;
                uncertainty.confirm();
                Ok(outcome)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn release(mut self) -> Result<(), ServingFenceError> {
        self.admission.send_replace(false);
        let mut uncertainty = SessionUncertaintyGuard::new(&self.admission, &self.actor_abort);
        let (reply, response) = oneshot::channel();
        self.commands
            .send(FenceCommand::Release { reply })
            .map_err(|_| ServingFenceError::Unavailable)?;
        let result = response.await.map_err(|_| ServingFenceError::Unavailable)?;
        let actor = self.actor.take().ok_or(ServingFenceError::Unavailable)?;
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

impl Drop for PostgresServingFence {
    fn drop(&mut self) {
        self.admission.send_replace(false);
        if let Some(actor) = self.actor.take() {
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
        FenceCommand::CreatePermit {
            operation_id,
            budget_ms,
            reply,
        } => {
            let result = actor_create_permit(
                client,
                lock_key,
                holder_id,
                generation,
                &operation_id,
                budget_ms,
            )
            .await;
            let fatal = !matches!(
                result,
                Ok(_) | Err(ServingFenceError::PermitReplay | ServingFenceError::PermitConflict)
            );
            if fatal {
                admission.send_replace(false);
            }
            fatal || reply.send(result).is_err()
        }
        FenceCommand::AuthorizePermit {
            operation_id,
            expected_deadline_unix_ms,
            reply,
        } => {
            let result = actor_authorize_permit(
                client,
                lock_key,
                holder_id,
                generation,
                &operation_id,
                expected_deadline_unix_ms,
            )
            .await;
            let fatal = !matches!(
                result,
                Ok(_) | Err(ServingFenceError::PermitExpired | ServingFenceError::PermitCompleted)
            );
            if fatal {
                admission.send_replace(false);
            }
            fatal || reply.send(result).is_err()
        }
        FenceCommand::CompletePermit {
            operation_id,
            reply,
        } => {
            let result =
                actor_complete_permit(client, lock_key, holder_id, generation, &operation_id).await;
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

async fn actor_create_permit(
    client: &Client,
    lock_key: ServingFenceLockKey,
    holder_id: &str,
    generation: i64,
    operation_id: &str,
    budget_ms: i32,
) -> Result<CreatedPermit, ServingFenceError> {
    let row = database_timeout(client.query_one(
        PERMIT_CREATE_SQL,
        &[
            &lock_key.as_i64(),
            &holder_id,
            &generation,
            &operation_id,
            &budget_ms,
        ],
    ))
    .await?;
    match try_str(&row, "outcome")? {
        "inserted" => {}
        "identical_replay" => return Err(ServingFenceError::PermitReplay),
        "conflicting_replay" => return Err(ServingFenceError::PermitConflict),
        "admission_closed" => return Err(ServingFenceError::AdmissionClosed),
        "ownership_lost" => return Err(ServingFenceError::OwnershipLost),
        _ => return Err(ServingFenceError::ProtocolDrift),
    }
    let stored_operation_id = try_str(&row, "operation_id")?;
    let stored_generation = try_i64(&row, "fence_generation")?;
    let stored_holder_id = try_str(&row, "holder_id")?;
    let stored_budget_ms = try_i32(&row, "budget_ms")?;
    if stored_operation_id != operation_id
        || stored_generation != generation
        || stored_holder_id != holder_id
        || stored_budget_ms != budget_ms
    {
        return Err(ServingFenceError::ProtocolDrift);
    }
    Ok(CreatedPermit {
        fence_generation: stored_generation,
        holder_id: stored_holder_id.to_owned(),
        deadline_unix_ms: try_i64(&row, "deadline_unix_ms")?,
    })
}

async fn actor_authorize_permit(
    client: &Client,
    lock_key: ServingFenceLockKey,
    holder_id: &str,
    generation: i64,
    operation_id: &str,
    expected_deadline_unix_ms: i64,
) -> Result<AuthorizationWindow, ServingFenceError> {
    let row = database_timeout(client.query_one(
        PERMIT_AUTHORIZE_SQL,
        &[&lock_key.as_i64(), &holder_id, &generation, &operation_id],
    ))
    .await?;
    match try_str(&row, "outcome")? {
        "authorized" => {}
        "expired" => return Err(ServingFenceError::PermitExpired),
        "unknown" => return Err(ServingFenceError::PermitUnknown),
        "completed" => return Err(ServingFenceError::PermitCompleted),
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

async fn actor_complete_permit(
    client: &Client,
    lock_key: ServingFenceLockKey,
    holder_id: &str,
    generation: i64,
    operation_id: &str,
) -> Result<PermitCompletionOutcome, ServingFenceError> {
    let row = database_timeout(client.query_one(
        PERMIT_COMPLETE_SQL,
        &[&lock_key.as_i64(), &holder_id, &generation, &operation_id],
    ))
    .await?;
    match try_str(&row, "outcome")? {
        "completed" => Ok(PermitCompletionOutcome::Completed),
        "already_completed" => Ok(PermitCompletionOutcome::AlreadyCompleted),
        "unknown" => Err(ServingFenceError::PermitUnknown),
        "abandoned" => Err(ServingFenceError::PermitAbandoned),
        "stale_generation" => Err(ServingFenceError::StaleGeneration),
        "admission_closed" => Err(ServingFenceError::AdmissionClosed),
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
) -> Result<(), ServingFenceError> {
    let deadline = Instant::now() + MAX_POST_LOCAL_BARRIER_WAIT;
    loop {
        let row = database_timeout(client.query_one(
            FENCE_FINALIZE_SQL,
            &[&lock_key.as_i64(), &holder_id, &generation],
        ))
        .await?;
        match try_str(&row, "outcome")? {
            "opened" => return Ok(()),
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
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    if Instant::now() >= deadline {
        return Err(ServingFenceError::PermitExpired);
    }
    if !*admission.borrow() {
        return Err(ServingFenceError::Unavailable);
    }
    let outbound = dispatch();
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

fn try_i32(row: &Row, column: &str) -> Result<i32, ServingFenceError> {
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
    use super::*;

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
            10_000
        );
    }

    #[test]
    fn local_takeover_wait_equals_protocol_deadline_plus_grace() {
        assert_eq!(
            LOCAL_TAKEOVER_WAIT,
            HARD_SOURCE_DEADLINE + CANCELLATION_GRACE
        );
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
        let result = run_guarded_dispatch(Instant::now(), admission, move || async move {
            observed.fetch_add(1, Ordering::SeqCst);
        })
        .await;
        assert_eq!(result, Err(ServingFenceError::PermitExpired));
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
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

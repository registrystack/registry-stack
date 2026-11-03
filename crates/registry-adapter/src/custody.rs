// SPDX-License-Identifier: Apache-2.0

//! The served write's custody: the concrete [`WriteExecutionContext`]
//! behind the engine's `WriteCustody` seam
//! (`products/adapter/CONCEPT.md` section 9). The journal transaction,
//! the idempotency store, and every terminal resolution stay
//! facade-side; the engine names this module never, and
//! the facade installs the concrete arc on each served write's exchange
//! and consults it for the terminal response.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use deadpool_postgres::GenericClient;
use registry_adapter_core::ErrorClass;
use tokio::sync::Mutex;

use crate::engine::exchange::{WriteClaim, WriteCustody};
use crate::engine::route::RouteFailure;
use crate::idempotent::{
    AsyncEffectAttempt, Claim, ClaimRequest, Execution, IdempotencyError, PostgresIdempotencyStore,
    RecoveryLease, ResumeClaimContext, StoredResponse, TerminalOutcome, VerifiedCallerIdentity,
};

/// Artifact-defined metadata needed to precommit asynchronous recovery before
/// the source mutation is sent.
pub struct AsyncWriteContext {
    pub response_request_id: String,
    pub artifact_digest: [u8; 32],
    pub binding_id: String,
    pub profile_operation: String,
    pub record_type: String,
    pub recovery_id: Option<String>,
    pub effect_deadline: SystemTime,
}

/// Active-artifact and finite-deadline authority for a compiled linear write.
pub struct ResumeWriteContext {
    pub artifact_digest: [u8; 32],
    pub effect_deadline: SystemTime,
    pub step_count: u32,
}

/// The facade-visible result of running the idempotency processor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteResolution {
    Pending,
    Replay {
        outcome: TerminalOutcome,
        response: StoredResponse,
    },
    Accepted {
        response: StoredResponse,
    },
    Uncertain,
    Conflict,
    Mismatch,
    ResponseExpired,
    UnsupportedIncomplete,
    ResumePending,
    Released,
    Finished,
}

enum WriteState {
    Ready,
    Executing {
        execution: Option<Execution>,
        key: String,
        effect_marked: bool,
        /// Camel repository membership is eager or completion-time. The
        /// execution above is the host's independent durable reservation.
        eager: bool,
        /// Exactly one block-scoped or exchange-scoped completion may apply.
        completion_recorded: bool,
    },
    Replay {
        outcome: TerminalOutcome,
        response: StoredResponse,
    },
    Accepted {
        response: StoredResponse,
    },
    Uncertain {
        key: String,
    },
    Conflict,
    Mismatch,
    ResponseExpired,
    UnsupportedIncomplete {
        execution: Option<Execution>,
    },
    ResumePending,
    Released,
    Finished,
}

/// A process-private idempotency capability shared across exchange clones.
/// Its Debug implementation deliberately reports no caller, operation, key,
/// request digest, response, or database detail.
pub struct WriteExecutionContext {
    store: PostgresIdempotencyStore,
    caller: VerifiedCallerIdentity,
    deployment: String,
    concrete_operation: String,
    request_digest: [u8; 32],
    async_write: Option<AsyncWriteContext>,
    resume_write: Option<ResumeWriteContext>,
    async_effect_committed: AtomicBool,
    state: Mutex<WriteState>,
}

impl fmt::Debug for WriteExecutionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WriteExecutionContext")
            .finish_non_exhaustive()
    }
}

impl WriteExecutionContext {
    /// Construct the served write's concrete custody over its store and
    /// verified caller. The facade keeps this concrete arc beside itself
    /// for the terminal resolution, and installs a clone on the served
    /// write's exchange behind the engine's seam.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: PostgresIdempotencyStore,
        caller: VerifiedCallerIdentity,
        deployment: String,
        concrete_operation: String,
        request_digest: [u8; 32],
    ) -> Arc<Self> {
        Self::new_with_async(
            store,
            caller,
            deployment,
            concrete_operation,
            request_digest,
            None,
            None,
        )
    }

    /// Construct asynchronous write custody with the pre-send recovery
    /// metadata the loaded facade already proved closed.
    #[allow(clippy::too_many_arguments)]
    pub fn new_async(
        store: PostgresIdempotencyStore,
        caller: VerifiedCallerIdentity,
        deployment: String,
        concrete_operation: String,
        request_digest: [u8; 32],
        async_write: AsyncWriteContext,
    ) -> Arc<Self> {
        Self::new_with_async(
            store,
            caller,
            deployment,
            concrete_operation,
            request_digest,
            Some(async_write),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_resume(
        store: PostgresIdempotencyStore,
        caller: VerifiedCallerIdentity,
        deployment: String,
        concrete_operation: String,
        request_digest: [u8; 32],
        resume_write: ResumeWriteContext,
    ) -> Arc<Self> {
        Self::new_with_async(
            store,
            caller,
            deployment,
            concrete_operation,
            request_digest,
            None,
            Some(resume_write),
        )
    }

    fn new_with_async(
        store: PostgresIdempotencyStore,
        caller: VerifiedCallerIdentity,
        deployment: String,
        concrete_operation: String,
        request_digest: [u8; 32],
        async_write: Option<AsyncWriteContext>,
        resume_write: Option<ResumeWriteContext>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            caller,
            deployment,
            concrete_operation,
            request_digest,
            async_write,
            resume_write,
            async_effect_committed: AtomicBool::new(false),
            state: Mutex::new(WriteState::Ready),
        })
    }

    /// The terminal resolution of the served write, read by the facade
    /// when the route answers.
    pub async fn resolution(&self) -> WriteResolution {
        match &*self.state.lock().await {
            WriteState::Ready | WriteState::Executing { .. } => WriteResolution::Pending,
            WriteState::Replay { outcome, response } => WriteResolution::Replay {
                outcome: *outcome,
                response: response.clone(),
            },
            WriteState::Accepted { response } => WriteResolution::Accepted {
                response: response.clone(),
            },
            WriteState::Uncertain { .. } => WriteResolution::Uncertain,
            WriteState::Conflict => WriteResolution::Conflict,
            WriteState::Mismatch => WriteResolution::Mismatch,
            WriteState::ResponseExpired => WriteResolution::ResponseExpired,
            WriteState::UnsupportedIncomplete { .. } => WriteResolution::UnsupportedIncomplete,
            WriteState::ResumePending => WriteResolution::ResumePending,
            WriteState::Released => WriteResolution::Released,
            WriteState::Finished => WriteResolution::Finished,
        }
    }

    /// Keep a completed source effect resumable when the facade cannot
    /// validate its terminal result. The bad source body is never stored;
    /// ending this cleanly returned attempt's lease allows an immediate
    /// same-request retry after the source is repaired.
    pub async fn retain_resume_after_host_validation_failure(
        &self,
    ) -> Result<(), IdempotencyError> {
        if self.resume_write.is_none() || self.async_write.is_some() {
            return Err(IdempotencyError::StateConflict);
        }
        let mut state = self.state.lock().await;
        let WriteState::Executing {
            execution,
            effect_marked: true,
            completion_recorded: true,
            ..
        } = &mut *state
        else {
            return Err(IdempotencyError::StateConflict);
        };
        let execution = execution.as_ref().ok_or(IdempotencyError::StateConflict)?;
        self.store
            .release_resume_lease(execution, SystemTime::now())
            .await?;
        *state = WriteState::ResumePending;
        Ok(())
    }

    /// Persist the terminal response on the facade's journal transaction so
    /// terminal audit and response custody have one commit boundary.
    pub async fn finish_with_client(
        &self,
        client: &impl GenericClient,
        outcome: TerminalOutcome,
        response: StoredResponse,
    ) -> Result<(), IdempotencyError> {
        let mut state = self.state.lock().await;
        let execution = match &mut *state {
            WriteState::Executing { execution, .. }
            | WriteState::UnsupportedIncomplete { execution } => execution,
            _ => return Err(IdempotencyError::StateConflict),
        };
        let execution = execution.take().ok_or(IdempotencyError::StateConflict)?;
        self.store
            .finish_with_client(client, execution, outcome, response, SystemTime::now())
            .await?;
        *state = WriteState::Finished;
        Ok(())
    }

    /// Commit the declared source acceptance on the facade's journal
    /// transaction. The fresh acceptance instant also anchors link expiry.
    pub async fn accept_with_client(
        &self,
        client: &impl GenericClient,
        source_id: &str,
        response: StoredResponse,
        accepted_at: SystemTime,
    ) -> Result<(), IdempotencyError> {
        let mut state = self.state.lock().await;
        let WriteState::Executing { execution, .. } = &mut *state else {
            return Err(IdempotencyError::StateConflict);
        };
        let execution = execution.take().ok_or(IdempotencyError::StateConflict)?;
        self.store
            .accept_with_client(client, execution, source_id, response, accepted_at)
            .await?;
        *state = WriteState::Finished;
        Ok(())
    }

    /// Whether a source effect whose outcome is unknown has the durable,
    /// host-generated correlation required for a safe source-native check.
    pub async fn has_recoverable_uncertainty(&self) -> bool {
        let correlated = self
            .async_write
            .as_ref()
            .is_some_and(|write| write.recovery_id.is_some());
        if !correlated {
            return false;
        }
        match &*self.state.lock().await {
            WriteState::Uncertain { .. } => true,
            WriteState::Executing { .. } => self.async_effect_committed.load(Ordering::Acquire),
            _ => false,
        }
    }

    /// Whether a declared asynchronous effect was durably marked before its
    /// source outcome became unknown. With or without a recovery route, such
    /// a key stays spent and can never authorize a repeated mutation.
    pub async fn has_uncertain_effect(&self) -> bool {
        if self.async_write.is_none() || !self.async_effect_committed.load(Ordering::Acquire) {
            return false;
        }
        matches!(
            &*self.state.lock().await,
            WriteState::Executing { .. } | WriteState::UnsupportedIncomplete { .. }
        )
    }

    /// Acquire the store's one finite uncertainty-recovery lease for this
    /// exact caller, deployment, operation, key, request, and artifact.
    pub async fn acquire_uncertain_recovery(
        &self,
        now: SystemTime,
        requested_deadline: SystemTime,
    ) -> Result<RecoveryLease, IdempotencyError> {
        let key = match &*self.state.lock().await {
            WriteState::Executing { key, .. } | WriteState::Uncertain { key } => key.clone(),
            _ => return Err(IdempotencyError::StateConflict),
        };
        let artifact_digest = self
            .async_write
            .as_ref()
            .and_then(|write| write.recovery_id.as_ref().map(|_| write.artifact_digest))
            .ok_or(IdempotencyError::StateConflict)?;
        self.store
            .acquire_uncertain_recovery(
                ClaimRequest {
                    caller: &self.caller,
                    deployment: &self.deployment,
                    concrete_operation: &self.concrete_operation,
                    key: &key,
                    request_digest: self.request_digest,
                },
                artifact_digest,
                now,
                requested_deadline,
            )
            .await
    }
}

fn idempotency_failure(error: IdempotencyError) -> RouteFailure {
    tracing::error!(%error, "the idempotency store refused a write transition");
    RouteFailure::of(ErrorClass::Facade)
}

/// The concrete capability: the same transitions the exchange's seam
/// exposes, over the idempotency store's own state machine.
impl WriteCustody for WriteExecutionContext {
    fn claim<'a>(
        &'a self,
        key: &'a str,
        eager: bool,
    ) -> Pin<Box<dyn Future<Output = Result<WriteClaim, RouteFailure>> + Send + 'a>> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            if !matches!(*state, WriteState::Ready) {
                return Err(RouteFailure::of(ErrorClass::Facade));
            }
            let request = ClaimRequest {
                caller: &self.caller,
                deployment: &self.deployment,
                concrete_operation: &self.concrete_operation,
                key,
                request_digest: self.request_digest,
            };
            let claimed = match &self.resume_write {
                Some(resume) => {
                    self.store
                        .claim_resume(
                            request,
                            ResumeClaimContext {
                                artifact_digest: resume.artifact_digest,
                                effect_deadline: resume.effect_deadline,
                                step_count: resume.step_count,
                            },
                            SystemTime::now(),
                        )
                        .await
                }
                None => self.store.claim(request, SystemTime::now()).await,
            }
            .map_err(idempotency_failure)?;
            match claimed {
                Claim::Execute(execution) => {
                    *state = WriteState::Executing {
                        execution: Some(execution),
                        key: key.to_owned(),
                        effect_marked: false,
                        eager,
                        completion_recorded: false,
                    };
                    Ok(WriteClaim::Execute)
                }
                Claim::Resume {
                    execution,
                    next_step,
                    bindings,
                } => {
                    *state = WriteState::Executing {
                        execution: Some(execution),
                        key: key.to_owned(),
                        effect_marked: false,
                        eager,
                        completion_recorded: false,
                    };
                    Ok(WriteClaim::Resume(
                        crate::engine::exchange::ResumeExecution::new(next_step, bindings),
                    ))
                }
                Claim::Replay { outcome, response } => {
                    *state = WriteState::Replay { outcome, response };
                    Ok(WriteClaim::Stop)
                }
                Claim::Accepted { response } => {
                    *state = WriteState::Accepted { response };
                    Ok(WriteClaim::Stop)
                }
                Claim::InFlight => {
                    *state = WriteState::Conflict;
                    Ok(WriteClaim::Stop)
                }
                Claim::EffectUnknown
                    if self
                        .async_write
                        .as_ref()
                        .is_some_and(|write| write.recovery_id.is_some()) =>
                {
                    *state = WriteState::Uncertain {
                        key: key.to_owned(),
                    };
                    Ok(WriteClaim::Stop)
                }
                Claim::EffectUnknown => {
                    *state = WriteState::Conflict;
                    Ok(WriteClaim::Stop)
                }
                Claim::Mismatch => {
                    *state = WriteState::Mismatch;
                    Ok(WriteClaim::Stop)
                }
                Claim::ResponseExpired { .. } | Claim::AcceptedExpired => {
                    *state = WriteState::ResponseExpired;
                    Ok(WriteClaim::Stop)
                }
            }
        })
    }

    fn before_effect<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<(), RouteFailure>> + Send + 'a>> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let WriteState::Executing {
                execution,
                key,
                effect_marked,
                ..
            } = &mut *state
            else {
                return Err(RouteFailure::of(ErrorClass::Facade));
            };
            if *effect_marked {
                return Ok(());
            }
            let Some(execution) = execution.as_mut() else {
                return Err(RouteFailure::of(ErrorClass::Facade));
            };
            let now = SystemTime::now();
            match &self.async_write {
                Some(async_write) => {
                    self.store
                        .mark_async_effect_attempted(
                            execution,
                            ClaimRequest {
                                caller: &self.caller,
                                deployment: &self.deployment,
                                concrete_operation: &self.concrete_operation,
                                key,
                                request_digest: self.request_digest,
                            },
                            AsyncEffectAttempt {
                                response_request_id: &async_write.response_request_id,
                                artifact_digest: async_write.artifact_digest,
                                binding_id: &async_write.binding_id,
                                profile_operation: &async_write.profile_operation,
                                concrete_operation: &self.concrete_operation,
                                record_type: &async_write.record_type,
                                recovery_id: async_write.recovery_id.as_deref(),
                                effect_deadline: async_write.effect_deadline,
                            },
                            now,
                        )
                        .await
                        .map_err(idempotency_failure)?;
                    self.async_effect_committed.store(true, Ordering::Release);
                }
                None => self
                    .store
                    .mark_effect_attempted(execution, now)
                    .await
                    .map_err(idempotency_failure)?,
            }
            *effect_marked = true;
            Ok(())
        })
    }

    fn before_resume_step<'a>(
        &'a self,
        ordinal: u32,
    ) -> Pin<Box<dyn Future<Output = Result<(), RouteFailure>> + Send + 'a>> {
        Box::pin(async move {
            if self.resume_write.is_none() || self.async_write.is_some() {
                return Err(RouteFailure::of(ErrorClass::Facade));
            }
            let mut state = self.state.lock().await;
            let WriteState::Executing {
                execution,
                effect_marked,
                ..
            } = &mut *state
            else {
                return Err(RouteFailure::of(ErrorClass::Facade));
            };
            if *effect_marked {
                return Ok(());
            }
            let execution = execution
                .as_mut()
                .ok_or_else(|| RouteFailure::of(ErrorClass::Facade))?;
            self.store
                .mark_resume_step_attempted(execution, ordinal, SystemTime::now())
                .await
                .map_err(idempotency_failure)?;
            *effect_marked = true;
            Ok(())
        })
    }

    fn checkpoint_resume_step<'a>(
        &'a self,
        ordinal: u32,
        bindings: Vec<crate::engine::ResumeValue>,
    ) -> Pin<Box<dyn Future<Output = Result<(), RouteFailure>> + Send + 'a>> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let WriteState::Executing {
                execution,
                effect_marked,
                ..
            } = &mut *state
            else {
                return Err(RouteFailure::of(ErrorClass::Facade));
            };
            if !*effect_marked {
                return Err(RouteFailure::of(ErrorClass::Facade));
            }
            let execution = execution
                .as_mut()
                .ok_or_else(|| RouteFailure::of(ErrorClass::Facade))?;
            self.store
                .checkpoint_resume_step(execution, ordinal, &bindings, SystemTime::now())
                .await
                .map_err(idempotency_failure)?;
            *effect_marked = false;
            Ok(())
        })
    }

    fn source_recovery_id(&self) -> Option<String> {
        if !self.async_effect_committed.load(Ordering::Acquire) {
            return None;
        }
        self.async_write
            .as_ref()
            .and_then(|write| write.recovery_id.clone())
    }

    fn mark_unsupported_incomplete<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<bool, RouteFailure>> + Send + 'a>> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let WriteState::Executing {
                execution,
                effect_marked,
                ..
            } = &mut *state
            else {
                return Err(RouteFailure::of(ErrorClass::Facade));
            };
            if !*effect_marked {
                let Some(execution) = execution.as_mut() else {
                    return Err(RouteFailure::of(ErrorClass::Facade));
                };
                self.store
                    .mark_effect_attempted(execution, SystemTime::now())
                    .await
                    .map_err(idempotency_failure)?;
                *effect_marked = true;
            }
            *state = WriteState::UnsupportedIncomplete {
                execution: execution.take(),
            };
            Ok(true)
        })
    }

    fn complete<'a>(
        &'a self,
        succeeded: bool,
        remove_on_failure: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(), RouteFailure>> + Send + 'a>> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            if matches!(*state, WriteState::UnsupportedIncomplete { .. }) {
                return Ok(());
            }
            let WriteState::Executing {
                execution,
                effect_marked,
                eager,
                completion_recorded,
                ..
            } = &mut *state
            else {
                return Err(RouteFailure::of(ErrorClass::Facade));
            };
            if *completion_recorded {
                return Err(RouteFailure::of(ErrorClass::Facade));
            }
            *completion_recorded = true;
            if self.resume_write.is_some() && !succeeded {
                let execution = execution
                    .as_ref()
                    .ok_or_else(|| RouteFailure::of(ErrorClass::Facade))?;
                self.store
                    .release_resume_lease(execution, SystemTime::now())
                    .await
                    .map_err(idempotency_failure)?;
                *state = WriteState::ResumePending;
                return Ok(());
            }
            // A successful EIP member stays reserved. So does any attempted
            // source effect, and an eager failure when removeOnFailure is
            // false. A non-eager failure never became an EIP member, so its
            // safe host reservation is releasable regardless of that option.
            if succeeded || *effect_marked || (*eager && !remove_on_failure) {
                return Ok(());
            }
            let Some(execution) = execution.take() else {
                return Err(RouteFailure::of(ErrorClass::Facade));
            };
            self.store
                .release_before_effect(execution)
                .await
                .map_err(idempotency_failure)?;
            *state = WriteState::Released;
            Ok(())
        })
    }
}

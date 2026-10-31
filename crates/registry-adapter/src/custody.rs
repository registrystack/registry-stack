// SPDX-License-Identifier: Apache-2.0

//! The served write's custody: the concrete [`WriteExecutionContext`]
//! behind the engine's `WriteCustody` seam
//! (`products/adapter/CONCEPT.md` section 9, and the E3 ruling in
//! `products/adapter/scratch/core/engine-boundary-plan.md`). The
//! journal transaction, the idempotency store, and every terminal
//! resolution stay facade-side; the engine names this module never, and
//! the facade installs the concrete arc on each served write's exchange
//! and consults it for the terminal response.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;

use deadpool_postgres::GenericClient;
use registry_adapter_core::ErrorClass;
use tokio::sync::Mutex;

use crate::engine::exchange::{WriteClaim, WriteCustody};
use crate::engine::route::RouteFailure;
use crate::idempotent::{
    Claim, ClaimRequest, Execution, IdempotencyError, PostgresIdempotencyStore, StoredResponse,
    TerminalOutcome, VerifiedCallerIdentity,
};

/// The facade-visible result of running the idempotency processor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteResolution {
    Pending,
    Replay {
        outcome: TerminalOutcome,
        response: StoredResponse,
    },
    Conflict,
    Mismatch,
    ResponseExpired,
    UnsupportedIncomplete,
    Released,
    Finished,
}

enum WriteState {
    Ready,
    Executing {
        execution: Option<Execution>,
        effect_marked: bool,
    },
    Replay {
        outcome: TerminalOutcome,
        response: StoredResponse,
    },
    Conflict,
    Mismatch,
    ResponseExpired,
    UnsupportedIncomplete {
        execution: Option<Execution>,
    },
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
        Arc::new(Self {
            store,
            caller,
            deployment,
            concrete_operation,
            request_digest,
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
            WriteState::Conflict => WriteResolution::Conflict,
            WriteState::Mismatch => WriteResolution::Mismatch,
            WriteState::ResponseExpired => WriteResolution::ResponseExpired,
            WriteState::UnsupportedIncomplete { .. } => WriteResolution::UnsupportedIncomplete,
            WriteState::Released => WriteResolution::Released,
            WriteState::Finished => WriteResolution::Finished,
        }
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
    ) -> Pin<Box<dyn Future<Output = Result<WriteClaim, RouteFailure>> + Send + 'a>> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            if !matches!(*state, WriteState::Ready) {
                return Err(RouteFailure::of(ErrorClass::Facade));
            }
            let claimed = self
                .store
                .claim(
                    ClaimRequest {
                        caller: &self.caller,
                        deployment: &self.deployment,
                        concrete_operation: &self.concrete_operation,
                        key,
                        request_digest: self.request_digest,
                    },
                    SystemTime::now(),
                )
                .await
                .map_err(idempotency_failure)?;
            match claimed {
                Claim::Execute(execution) => {
                    *state = WriteState::Executing {
                        execution: Some(execution),
                        effect_marked: false,
                    };
                    Ok(WriteClaim::Execute)
                }
                Claim::Replay { outcome, response } => {
                    *state = WriteState::Replay { outcome, response };
                    Ok(WriteClaim::Stop)
                }
                Claim::InFlight | Claim::EffectUnknown => {
                    *state = WriteState::Conflict;
                    Ok(WriteClaim::Stop)
                }
                Claim::Mismatch => {
                    *state = WriteState::Mismatch;
                    Ok(WriteClaim::Stop)
                }
                Claim::ResponseExpired { .. } => {
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
                effect_marked,
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
            self.store
                .mark_effect_attempted(execution, SystemTime::now())
                .await
                .map_err(idempotency_failure)?;
            *effect_marked = true;
            Ok(())
        })
    }

    fn mark_unsupported_incomplete<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<bool, RouteFailure>> + Send + 'a>> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let WriteState::Executing {
                execution,
                effect_marked,
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

    fn release_before_effect<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<(), RouteFailure>> + Send + 'a>> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let WriteState::Executing {
                execution,
                effect_marked,
            } = &mut *state
            else {
                return Err(RouteFailure::of(ErrorClass::Facade));
            };
            if *effect_marked {
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

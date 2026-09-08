// SPDX-License-Identifier: Apache-2.0
//! Bounded bridge between synchronous governed handlers and asynchronous Evidence.

use crate::{
    action_evidence_client::{EvidenceActionClient, VerifiedAcquisition},
    action_handler::{ActionHandlerError, ActionHandlerOutcome},
    model::CompiledAction,
    mutation::MutationError,
};
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
use tokio::sync::Semaphore;

pub const MAXIMUM_EVIDENCE_EVALUATIONS: usize = 8;
pub const MAXIMUM_RETAINED_EVIDENCE_BYTES: usize = 1024 * 1024;

pub struct FrozenEvidenceEvaluation {
    pub outcome: Result<ActionHandlerOutcome, MutationError>,
    pub acquisitions: Vec<VerifiedAcquisition>,
}

pub struct ActionEvidenceEvaluator {
    client: Arc<EvidenceActionClient>,
    capacity: Arc<Semaphore>,
}

struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl ActionEvidenceEvaluator {
    pub fn new(client: Arc<EvidenceActionClient>) -> Self {
        Self {
            client,
            capacity: Arc::new(Semaphore::new(MAXIMUM_EVIDENCE_EVALUATIONS)),
        }
    }

    pub async fn evaluate(
        &self,
        action: CompiledAction,
        inputs: Map<String, Value>,
        deadline: Instant,
    ) -> FrozenEvidenceEvaluation {
        let unavailable = || FrozenEvidenceEvaluation {
            outcome: Err(MutationError::Unavailable),
            acquisitions: Vec::new(),
        };
        let Ok(Ok(permit)) =
            tokio::time::timeout_at(deadline.into(), self.capacity.clone().acquire_owned()).await
        else {
            return unavailable();
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel_on_drop = CancelOnDrop(cancelled.clone());
        let client = self.client.clone();
        let runtime = tokio::runtime::Handle::current();
        let worker = tokio::task::spawn_blocking(move || {
            // The permit belongs to the worker, not the request future. Timeout
            // cannot admit replacement workers while this one is still exiting.
            let _permit = permit;
            let acquisitions = Arc::new(Mutex::new(Vec::<VerifiedAcquisition>::new()));
            let acquired = acquisitions.clone();
            let helper_cancelled = cancelled.clone();
            let capabilities = action.evidence.clone();
            let resolver = move |alias: &str,
                                 subjects: Value|
                  -> Result<Value, ActionHandlerError> {
                let capability = capabilities
                    .iter()
                    .find(|capability| capability.id == alias)
                    .ok_or(ActionHandlerError::Evidence)?;
                let subjects: BTreeMap<String, BTreeMap<String, Value>> =
                    serde_json::from_value(subjects).map_err(|_| ActionHandlerError::Evidence)?;
                let acquisition = runtime
                    .block_on(client.resolve(
                        capability,
                        &subjects,
                        deadline,
                        helper_cancelled.clone(),
                    ))
                    .map_err(|_| ActionHandlerError::Evidence)?;
                if helper_cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return Err(ActionHandlerError::Deadline);
                }
                let output = serde_json::to_value(acquisition.outputs())
                    .map_err(|_| ActionHandlerError::Evidence)?;
                let mut entries = acquired.lock().map_err(|_| ActionHandlerError::Evidence)?;
                let bytes = entries
                    .iter()
                    .try_fold(0usize, |sum, entry| {
                        entry.retained_bytes().map(|size| sum.saturating_add(size))
                    })
                    .map_err(|_| ActionHandlerError::Evidence)?;
                if bytes
                    .checked_add(
                        acquisition
                            .retained_bytes()
                            .map_err(|_| ActionHandlerError::Evidence)?,
                    )
                    .is_none_or(|total| total > MAXIMUM_RETAINED_EVIDENCE_BYTES)
                {
                    return Err(ActionHandlerError::Evidence);
                }
                entries.push(acquisition);
                Ok(output)
            };
            let outcome = crate::action_handler::evaluate_with_engine(
                &action,
                &inputs,
                deadline,
                Some(Arc::new(resolver)),
                Some(cancelled.clone()),
            )
            .map_err(|diagnostic| {
                if diagnostic.kind == ActionHandlerError::Deadline {
                    MutationError::Unavailable
                } else if diagnostic.kind == ActionHandlerError::Evidence {
                    MutationError::ActionEvidenceFailure {
                        capability: diagnostic.evidence_capability,
                    }
                } else {
                    MutationError::ActionHandlerFailure(diagnostic.kind)
                }
            });
            let acquisitions = match acquisitions.lock() {
                Ok(mut entries) => std::mem::take(&mut *entries),
                Err(_) => {
                    return FrozenEvidenceEvaluation {
                        outcome: Err(MutationError::Unavailable),
                        acquisitions: Vec::new(),
                    }
                }
            };
            FrozenEvidenceEvaluation {
                outcome,
                acquisitions,
            }
        });
        match tokio::time::timeout_at(deadline.into(), worker).await {
            Ok(Ok(result)) => result,
            _ => unavailable(),
        }
    }
}

impl From<crate::action_evidence_client::EvidenceAcquisitionFailure> for MutationError {
    fn from(error: crate::action_evidence_client::EvidenceAcquisitionFailure) -> Self {
        match error {
            crate::action_evidence_client::EvidenceAcquisitionFailure::Cancelled => {
                Self::Unavailable
            }
            _ => Self::ActionEvidenceFailure { capability: None },
        }
    }
}

#[cfg(test)]
#[path = "../tests/support/action_evidence_runtime.rs"]
mod tests;

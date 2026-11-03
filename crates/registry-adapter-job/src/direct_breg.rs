// SPDX-License-Identifier: Apache-2.0

//! The off-by-default direct BReg destination. It maps one projected
//! item to either one immediate Action or one Proposal start and submit,
//! derives stable command keys from job and item identity, and
//! deterministically re-prepares on every retry. Prepared request bytes
//! are never returned to the job store and never persisted.

use std::fmt::Write as _;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use registry_adapter_connectors::breg::{problems, BregConnector};
use registry_adapter_connectors::operation::{
    CommandKey, ConnectorFault, Operation, OutcomeCategory, SendOutcome,
};
use registry_adapter_core::JobIdentity;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::destination::{DeliverableItem, HandOffOutcome, JobDestination};

const REVISED_ITEM: &str = "adapter.job.revised-item";
const MAPPING_REFUSED: &str = "adapter.job.breg-mapping-refused";
const DESTINATION_AUTHORITY: &str = "adapter.job.breg-authority-unavailable";
const DESTINATION_BINDING: &str = "adapter.job.breg-binding-changed";
const DESTINATION_UNAVAILABLE: &str = "adapter.job.breg-unavailable";
const DESTINATION_UNCERTAIN: &str = "adapter.job.breg-outcome-uncertain";
const DESTINATION_PENDING: &str = "adapter.job.breg-outcome-pending";
const DESTINATION_INVALID: &str = "adapter.job.breg-outcome-invalid";

/// The one BReg operation a projected item maps to. The Proposal form
/// is still one destination hand-off: start and submit use distinct,
/// stable keys derived from the same item identity.
#[derive(Clone, Debug)]
pub enum DirectBregOperation {
    /// Invoke one immediate Action.
    ImmediateAction {
        /// The Action input produced by the reviewed mapping.
        input: Value,
    },
    /// Start and submit one Proposal.
    Proposal {
        /// The Proposal Action input produced by the reviewed mapping.
        start_input: Value,
        /// The submission body for the draft the start returns.
        submit_body: Value,
    },
}

/// A value-free, item-scoped mapping refusal. Mapping diagnostics stay
/// at the authoring/check boundary rather than repeating source values
/// at runtime.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectBregMappingRefused;

/// The pure mapping seam. It receives only the declared projection,
/// never the raw source row.
pub trait DirectBregMapper: Send + Sync {
    /// Produce one direct operation or refuse this item without I/O.
    fn map(&self, item: &DeliverableItem) -> Result<DirectBregOperation, DirectBregMappingRefused>;
}

impl<F> DirectBregMapper for F
where
    F: Fn(&DeliverableItem) -> Result<DirectBregOperation, DirectBregMappingRefused> + Send + Sync,
{
    fn map(&self, item: &DeliverableItem) -> Result<DirectBregOperation, DirectBregMappingRefused> {
        self(item)
    }
}

/// An operational direct destination over one metadata-bound BReg
/// connector and one reviewed item mapper.
pub struct DirectBregDestination<M> {
    connector: Arc<BregConnector>,
    mapper: M,
}

impl<M> DirectBregDestination<M> {
    /// Bind the destination to one connector and mapper for the process
    /// lifetime.
    #[must_use]
    pub fn new(connector: Arc<BregConnector>, mapper: M) -> Self {
        Self { connector, mapper }
    }
}

impl<M: DirectBregMapper> DirectBregDestination<M> {
    fn deliver_item(&self, job: &JobIdentity, item: &DeliverableItem) -> HandOffOutcome {
        if item.admitted_before {
            return HandOffOutcome::Held {
                code: REVISED_ITEM.to_string(),
                run_id: item.prior_run_id.clone(),
            };
        }
        let operation = match self.mapper.map(item) {
            Ok(operation) => operation,
            Err(DirectBregMappingRefused) => {
                return HandOffOutcome::Refused {
                    code: MAPPING_REFUSED.to_string(),
                };
            }
        };
        match operation {
            DirectBregOperation::ImmediateAction { input } => {
                let action = self.connector.action_invoke();
                let prepared = match action.prepare(&input, command_key(job, item, "invoke")) {
                    Ok(prepared) => prepared,
                    Err(fault) => return fault_outcome(fault),
                };
                match action.send(&prepared) {
                    Ok(outcome) => terminal_outcome(outcome),
                    Err(fault) => fault_outcome(fault),
                }
            }
            DirectBregOperation::Proposal {
                start_input,
                submit_body,
            } => self.deliver_proposal(job, item, &start_input, submit_body),
        }
    }

    fn deliver_proposal(
        &self,
        job: &JobIdentity,
        item: &DeliverableItem,
        start_input: &Value,
        submit_body: Value,
    ) -> HandOffOutcome {
        let start = self.connector.proposal_start();
        let prepared = match start.prepare(start_input, command_key(job, item, "start")) {
            Ok(prepared) => prepared,
            Err(fault) => return fault_outcome(fault),
        };
        let started = match start.send(&prepared) {
            Ok(outcome) => outcome,
            Err(fault) => return fault_outcome(fault),
        };
        let proposal = match accepted_correlation(started) {
            Ok(proposal) => proposal,
            Err(outcome) => return outcome,
        };
        let summary = match self.connector.reads().proposal_summary(&proposal) {
            Ok(summary) => summary,
            Err(fault) => return fault_outcome(fault),
        };
        let submit = self.connector.proposal_submit();
        let input = serde_json::json!({
            "proposal": proposal,
            "submissionVersion": summary.submission_version,
            "body": submit_body,
        });
        let prepared = match submit.prepare(&input, command_key(job, item, "submit")) {
            Ok(prepared) => prepared,
            Err(fault) => return fault_outcome(fault),
        };
        match submit.send(&prepared) {
            Ok(outcome) => terminal_outcome(outcome),
            Err(fault) => fault_outcome(fault),
        }
    }
}

impl<M: DirectBregMapper> JobDestination for DirectBregDestination<M> {
    fn deliver<'a>(
        &'a self,
        job: &'a JobIdentity,
        item: &'a DeliverableItem,
    ) -> Pin<Box<dyn Future<Output = HandOffOutcome> + Send + 'a>> {
        Box::pin(async move { self.deliver_item(job, item) })
    }
}

fn accepted_correlation(outcome: SendOutcome) -> Result<String, HandOffOutcome> {
    match outcome.category {
        OutcomeCategory::Accepted | OutcomeCategory::Completed => {
            outcome.correlation.ok_or_else(|| HandOffOutcome::StopPass {
                code: DESTINATION_INVALID.to_string(),
            })
        }
        OutcomeCategory::Refused => Err(refused_outcome(outcome)),
        OutcomeCategory::Uncertain => Err(HandOffOutcome::StopPass {
            code: DESTINATION_UNCERTAIN.to_string(),
        }),
        OutcomeCategory::Pending => Err(HandOffOutcome::StopPass {
            code: DESTINATION_PENDING.to_string(),
        }),
    }
}

fn terminal_outcome(outcome: SendOutcome) -> HandOffOutcome {
    match outcome.category {
        OutcomeCategory::Accepted | OutcomeCategory::Completed => HandOffOutcome::Acknowledged {
            run_id: outcome.correlation,
        },
        OutcomeCategory::Refused => refused_outcome(outcome),
        OutcomeCategory::Uncertain => HandOffOutcome::StopPass {
            code: DESTINATION_UNCERTAIN.to_string(),
        },
        OutcomeCategory::Pending => HandOffOutcome::StopPass {
            code: DESTINATION_PENDING.to_string(),
        },
    }
}

fn refused_outcome(outcome: SendOutcome) -> HandOffOutcome {
    match outcome.native_problem.as_deref() {
        Some(problems::IDEMPOTENCY_KEY_REUSED | problems::IDEMPOTENCY_EXPIRED) => {
            HandOffOutcome::Held {
                code: outcome
                    .native_problem
                    .expect("the matched problem code is present"),
                run_id: outcome.correlation,
            }
        }
        Some(code) => HandOffOutcome::Refused {
            code: code.to_string(),
        },
        None => HandOffOutcome::Refused {
            code: MAPPING_REFUSED.to_string(),
        },
    }
}

fn fault_outcome(fault: ConnectorFault) -> HandOffOutcome {
    let code = match fault {
        ConnectorFault::InvalidInput => MAPPING_REFUSED,
        ConnectorFault::AuthorityAbsent | ConnectorFault::NotEnabled => DESTINATION_AUTHORITY,
        ConnectorFault::BindingChanged | ConnectorFault::NotPrepared => DESTINATION_BINDING,
        ConnectorFault::Native { .. } => DESTINATION_UNAVAILABLE,
        _ => DESTINATION_UNAVAILABLE,
    };
    if code == MAPPING_REFUSED {
        HandOffOutcome::Refused {
            code: code.to_string(),
        }
    } else {
        HandOffOutcome::StopPass {
            code: code.to_string(),
        }
    }
}

fn command_key(job: &JobIdentity, item: &DeliverableItem, step: &str) -> CommandKey {
    let mut digest = Sha256::new();
    let sequence = item.sequence.to_string();
    for component in [
        job.id.as_str().as_bytes(),
        item.key.as_bytes(),
        sequence.as_bytes(),
        item.digest.as_bytes(),
    ] {
        digest.update((component.len() as u64).to_be_bytes());
        digest.update(component);
    }
    let mut key = String::with_capacity(64 + step.len() + 13);
    key.push_str("adapter-job:");
    for byte in digest.finalize() {
        write!(&mut key, "{byte:02x}").expect("writing to a string cannot fail");
    }
    key.push(':');
    key.push_str(step);
    CommandKey::new(key).expect("the derived command key is bounded and non-empty")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_keys_are_stable_bounded_and_step_specific() {
        let job = JobIdentity {
            id: "case-daily".parse().expect("a local id"),
            version: "1".to_string(),
        };
        let item = DeliverableItem {
            key: "submissions/a".to_string(),
            sequence: 1,
            digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            prior_run_id: None,
            admitted_before: false,
            first_seen: std::time::SystemTime::UNIX_EPOCH,
            event_time: std::time::SystemTime::UNIX_EPOCH,
            delivery_attempt: 1,
            projected: serde_json::json!({}),
        };
        let start = command_key(&job, &item, "start");
        assert_eq!(start, command_key(&job, &item, "start"));
        assert_ne!(start, command_key(&job, &item, "submit"));
        assert!(start.as_str().len() <= 256);
        assert!(!start.as_str().contains(&item.key));
    }

    /// The job store keeps no version beside a pending item, so a redeploy
    /// under a new job version must retry that item under the same command
    /// key: BReg then replays a committed receipt instead of executing again.
    #[test]
    fn command_keys_survive_a_job_version_change() {
        let mut job = JobIdentity {
            id: "case-daily".parse().expect("a local id"),
            version: "1".to_string(),
        };
        let item = DeliverableItem {
            key: "submissions/a".to_string(),
            sequence: 1,
            digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            prior_run_id: None,
            admitted_before: false,
            first_seen: std::time::SystemTime::UNIX_EPOCH,
            event_time: std::time::SystemTime::UNIX_EPOCH,
            delivery_attempt: 1,
            projected: serde_json::json!({}),
        };
        let first = command_key(&job, &item, "invoke");
        job.version = "2".to_string();
        assert_eq!(first, command_key(&job, &item, "invoke"));
    }

    #[test]
    fn spent_or_mismatched_idempotency_keys_hold_the_item() {
        for code in [
            problems::IDEMPOTENCY_KEY_REUSED,
            problems::IDEMPOTENCY_EXPIRED,
        ] {
            assert_eq!(
                refused_outcome(SendOutcome {
                    category: OutcomeCategory::Refused,
                    native_problem: Some(code.to_string()),
                    correlation: Some("proposal-a".to_string()),
                    note: None,
                }),
                HandOffOutcome::Held {
                    code: code.to_string(),
                    run_id: Some("proposal-a".to_string()),
                }
            );
        }
    }
}

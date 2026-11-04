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

use crate::destination::{
    breg_item_code, DeliverableItem, DeliveryFamily, DeliveryIdentity, HandOffOutcome,
    JobDestination,
};

const REVISED_ITEM: &str = "adapter.job.revised-item";
const MAPPING_REFUSED: &str = "adapter.job.breg-mapping-refused";
const DESTINATION_AUTHORITY: &str = "adapter.job.breg-authority-unavailable";
const DESTINATION_BINDING: &str = "adapter.job.breg-binding-changed";
const DESTINATION_UNAVAILABLE: &str = "adapter.job.breg-unavailable";
const DESTINATION_UNCERTAIN: &str = "adapter.job.breg-outcome-uncertain";
const DESTINATION_PENDING: &str = "adapter.job.breg-outcome-pending";
const DESTINATION_INVALID: &str = "adapter.job.breg-outcome-invalid";
const RECEIVER_IDENTITY_DOMAIN: &[u8] = b"registry-adapter/direct-breg-receiver/v1";
const BODY_IDENTITY_DOMAIN: &[u8] = b"registry-adapter/direct-breg-operation/v1";

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

/// Public, credential-free configuration covered by the durable receiver
/// identity. Idempotency receipts are scoped to the authenticated caller, so
/// the caller and its issuer are part of the receiver; credential references
/// and material, resolved TLS bytes and timeouts are deliberately excluded.
/// The digest only establishes exact equality on retry.
pub struct DirectBregReceiverDigestContext<'a> {
    /// The runtime binding id.
    pub binding: &'a str,
    /// The BReg deployment origin.
    pub base_url: &'a str,
    /// The token endpoint the caller authenticates against.
    pub token_endpoint: &'a str,
    /// The authenticated caller's client id.
    pub client_id: &'a str,
    /// The private trust profile for the BReg origin, when one is set.
    pub data_tls_trust_profile: Option<&'a str>,
    /// The access profile every call selects under.
    pub access_profile: &'a str,
    /// The authored Action identifier.
    pub action: &'a str,
    /// The authored mode, `immediate` or `proposal`.
    pub mode: &'a str,
}

/// Derive the durable 32-byte BReg receiver identity.
#[must_use]
pub fn receiver_identity(context: &DirectBregReceiverDigestContext<'_>) -> [u8; 32] {
    let mut digest = Sha256::new();
    component(&mut digest, RECEIVER_IDENTITY_DOMAIN);
    for value in [
        context.binding,
        context.base_url,
        context.token_endpoint,
        context.client_id,
    ] {
        component(&mut digest, value.as_bytes());
    }
    match context.data_tls_trust_profile {
        Some(profile) => {
            digest.update([1]);
            component(&mut digest, profile.as_bytes());
        }
        None => digest.update([0]),
    }
    for value in [context.access_profile, context.action, context.mode] {
        component(&mut digest, value.as_bytes());
    }
    digest.finalize().into()
}

/// The durable identity of one mapped operation: what the destination would
/// send for the item, before any key or token enters. `serde_json` orders
/// object members, so equal operations digest equally.
fn operation_identity(operation: &DirectBregOperation) -> [u8; 32] {
    let mut digest = Sha256::new();
    component(&mut digest, BODY_IDENTITY_DOMAIN);
    let (tag, members): (u8, Vec<&Value>) = match operation {
        DirectBregOperation::ImmediateAction { input } => (0, vec![input]),
        DirectBregOperation::Proposal {
            start_input,
            submit_body,
        } => (1, vec![start_input, submit_body]),
    };
    digest.update([tag]);
    for member in members {
        let bytes = serde_json::to_vec(member).expect("a JSON value always serializes");
        component(&mut digest, &bytes);
    }
    digest.finalize().into()
}

fn component(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

/// An operational direct destination over one metadata-bound BReg
/// connector and one reviewed item mapper.
pub struct DirectBregDestination<M> {
    connector: Arc<BregConnector>,
    mapper: M,
    receiver: [u8; 32],
}

impl<M> DirectBregDestination<M> {
    /// Bind the destination to one connector, mapper and durable receiver
    /// identity ([`receiver_identity`]) for the process lifetime.
    #[must_use]
    pub fn new(connector: Arc<BregConnector>, mapper: M, receiver: [u8; 32]) -> Self {
        Self {
            connector,
            mapper,
            receiver,
        }
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
    /// An item handed off before is held, never sent, so only a delivery that
    /// reaches BReg freezes an identity. A mapping refusal has no operation
    /// to identify; the pass treats it as a body that cannot be confirmed.
    fn delivery_identity(
        &self,
        _job: &JobIdentity,
        item: &DeliverableItem,
    ) -> Option<DeliveryIdentity> {
        if item.admitted_before {
            return None;
        }
        Some(DeliveryIdentity {
            family: DeliveryFamily::Breg,
            receiver: self.receiver,
            canonical_body: self
                .mapper
                .map(item)
                .map(|operation| operation_identity(&operation))
                .map_err(|DirectBregMappingRefused| ()),
        })
    }

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
                code: breg_item_code(
                    &outcome
                        .native_problem
                        .expect("the matched problem code is present"),
                ),
                run_id: outcome.correlation,
            }
        }
        Some(code) => HandOffOutcome::Refused {
            code: breg_item_code(code),
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

    fn receiver_context() -> DirectBregReceiverDigestContext<'static> {
        DirectBregReceiverDigestContext {
            binding: "breg-prod",
            base_url: "https://breg.example/institution-a",
            token_endpoint: "https://auth.example/token",
            client_id: "adapter-job",
            data_tls_trust_profile: None,
            access_profile: "writer",
            action: "register-household",
            mode: "proposal",
        }
    }

    #[test]
    fn the_receiver_identity_covers_every_public_selector() {
        let base = receiver_identity(&receiver_context());
        assert_eq!(base, receiver_identity(&receiver_context()));
        let changed = [
            DirectBregReceiverDigestContext {
                binding: "breg-staging",
                ..receiver_context()
            },
            DirectBregReceiverDigestContext {
                base_url: "https://breg.example/institution-b",
                ..receiver_context()
            },
            DirectBregReceiverDigestContext {
                token_endpoint: "https://auth.example/other",
                ..receiver_context()
            },
            DirectBregReceiverDigestContext {
                client_id: "another-job",
                ..receiver_context()
            },
            DirectBregReceiverDigestContext {
                data_tls_trust_profile: Some("private-ca"),
                ..receiver_context()
            },
            DirectBregReceiverDigestContext {
                access_profile: "reader",
                ..receiver_context()
            },
            DirectBregReceiverDigestContext {
                action: "update-household",
                ..receiver_context()
            },
            DirectBregReceiverDigestContext {
                mode: "immediate",
                ..receiver_context()
            },
        ];
        for context in &changed {
            assert_ne!(base, receiver_identity(context), "{:?}", context.binding);
        }
        // A selector moved across a field boundary is a different receiver.
        let shifted = DirectBregReceiverDigestContext {
            binding: "breg-pro",
            base_url: "dhttps://breg.example/institution-a",
            ..receiver_context()
        };
        assert_ne!(base, receiver_identity(&shifted));
    }

    #[test]
    fn the_operation_identity_follows_the_mapped_operation_only() {
        let action = |input: Value| DirectBregOperation::ImmediateAction { input };
        let proposal = |start_input: Value, submit_body: Value| DirectBregOperation::Proposal {
            start_input,
            submit_body,
        };
        let base = operation_identity(&action(serde_json::json!({"a": 1, "b": 2})));
        assert_eq!(
            base,
            operation_identity(&action(serde_json::json!({"b": 2, "a": 1}))),
            "member order is not part of the operation"
        );
        assert_ne!(
            base,
            operation_identity(&action(serde_json::json!({"a": 1, "b": 3})))
        );
        let started = proposal(serde_json::json!({"a": 1}), serde_json::json!({"b": 2}));
        assert_ne!(base, operation_identity(&started));
        assert_ne!(
            operation_identity(&started),
            operation_identity(&proposal(
                serde_json::json!({"b": 2}),
                serde_json::json!({"a": 1})
            )),
            "start input and submit body are distinct members"
        );
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
                    code: breg_item_code(code),
                    run_id: Some("proposal-a".to_string()),
                }
            );
        }
    }

    #[test]
    fn a_native_refusal_keeps_its_word_behind_the_breg_prefix() {
        assert_eq!(
            refused_outcome(SendOutcome {
                category: OutcomeCategory::Refused,
                native_problem: Some("input.invalid".to_string()),
                correlation: None,
                note: None,
            }),
            HandOffOutcome::Refused {
                code: "adapter.job.breg.input.invalid".to_string()
            }
        );
    }
}

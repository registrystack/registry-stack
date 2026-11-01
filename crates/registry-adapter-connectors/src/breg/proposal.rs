// SPDX-License-Identifier: Apache-2.0
//! The BReg Proposal Action family: start (`breg.proposal.start`) and
//! submit (`breg.proposal.submit`), as two operations with separate
//! keys, plus the status read both observe through.
//!
//! Start prepares exactly like the immediate Action (see
//! [`super::action`]) and sends one `start_proposal` exchange; its
//! outcome is Accepted with the started draft's id as the correlation.
//!
//! Submit's prepared form holds the proposal identity, the submission
//! version the runner observed, the exact transition body, and the key.
//! The client grants no public way to persist an executable Proposal
//! transition without a fresh authorized read (a document parsed outside
//! the client carries no source binding, and parsed
//! `BRegPreparedProposal` bytes are not executable until
//! `recover_proposal` re-arms them), so every `send` and every `recover`
//! re-arms against a fresh `get_proposal` read, exactly the client's
//! documented restart flow. The one mutating exchange is still
//! `execute_proposal`, and it always carries the same key. A read that
//! shows the transition already holds answers the observed completion
//! and never sends again. The receipt-horizon refusals the product
//! answers (`idempotency.key-reused` 409, `idempotency.expired` 410)
//! surface as [`OutcomeCategory::Refused`] with those problem words; no
//! path falls back to another mode or key.
//!
//! Closed input shapes: `breg.proposal.start/v1` is
//! `{"input": { ...action inputs... }}`; `breg.proposal.submit/v1` is
//! `{"proposal": "<uuid>", "submissionVersion": <n>, "body": {...}}`,
//! where the version is the one the runner observed on the draft.

use std::sync::{Arc, LazyLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use registry_breg_client::{BRegActionMode, BRegIdempotencyKey, BRegProposal, BRegProposalState};

use crate::operation::{
    BodyKind, CommandKey, ConnectorFault, CredentialRequirements, IdempotencyRule, InputSchema,
    MutationBehavior, NativeState, Observable, Operation, OperationDescriptor, OutcomeCategory,
    PreparedAttempt, Product, RecoveryRule, SendOutcome,
};

use super::{action, classify, completed, fault, refused_state};

/// Starting a Proposal holds the target conditions' declared
/// preconditions; an unguarded action carries none.
pub static START: LazyLock<OperationDescriptor> = LazyLock::new(|| OperationDescriptor {
    name: "breg.proposal.start",
    product: Product::Breg,
    input_schema: InputSchema::ConnectorDefined {
        shape: "breg.proposal.start/v1".to_owned(),
    },
    body_kind: BodyKind::Json,
    mutation: MutationBehavior::Preconditioned,
    credentials: CredentialRequirements {
        credential_kinds: vec!["private-key-jwt".to_owned()],
        requires_task_grant: false,
        requires_operator_authority: false,
    },
    idempotency: IdempotencyRule::CallerKeyed {
        receipt_retention_days: Some(7),
    },
    recovery: RecoveryRule::ExactSameKey,
    completion: "the destination holds the started draft",
    observable: true,
});

/// Submitting freezes the exact submission the prepared body carries.
pub static SUBMIT: LazyLock<OperationDescriptor> = LazyLock::new(|| OperationDescriptor {
    name: "breg.proposal.submit",
    product: Product::Breg,
    input_schema: InputSchema::ConnectorDefined {
        shape: "breg.proposal.submit/v1".to_owned(),
    },
    body_kind: BodyKind::Json,
    mutation: MutationBehavior::Preconditioned,
    credentials: CredentialRequirements {
        credential_kinds: vec!["private-key-jwt".to_owned()],
        requires_task_grant: false,
        requires_operator_authority: false,
    },
    idempotency: IdempotencyRule::CallerKeyed {
        receipt_retention_days: Some(7),
    },
    recovery: RecoveryRule::ExactSameKey,
    completion:
        "the destination accepted the submit transition and answered with the submitted receipt",
    observable: true,
});

const START_OPERATION: &str = "breg.proposal.start";
const SUBMIT_OPERATION: &str = "breg.proposal.submit";

/// The exact, persistable start attempt.
pub struct PreparedStart {
    envelope: Vec<u8>,
    key: CommandKey,
}

impl PreparedStart {
    /// Restore the stored bytes of one start attempt.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorFault> {
        let envelope = action::unseal_invocation(bytes, START_OPERATION)?;
        Ok(Self {
            envelope: bytes.to_vec(),
            key: CommandKey::new(envelope.key).map_err(|_| ConnectorFault::NotPrepared)?,
        })
    }
}

impl std::fmt::Debug for PreparedStart {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedStart(<redacted>)")
    }
}

impl std::fmt::Debug for PreparedSubmit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedSubmit(<redacted>)")
    }
}

impl PreparedAttempt for PreparedStart {
    fn as_bytes(&self) -> &[u8] {
        &self.envelope
    }

    fn operation(&self) -> &'static str {
        START_OPERATION
    }

    fn key(&self) -> &CommandKey {
        &self.key
    }
}

#[derive(Serialize, Deserialize)]
struct SubmitEnvelope {
    version: u8,
    operation: String,
    key: String,
    proposal: String,
    submission_version: u32,
    body: Value,
}

/// The exact, persistable submit attempt.
pub struct PreparedSubmit {
    envelope: Vec<u8>,
    key: CommandKey,
}

impl PreparedSubmit {
    /// Restore the stored bytes of one submit attempt.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorFault> {
        let envelope: SubmitEnvelope =
            serde_json::from_slice(bytes).map_err(|_| ConnectorFault::NotPrepared)?;
        if envelope.version != 1 || envelope.operation != SUBMIT_OPERATION {
            return Err(ConnectorFault::NotPrepared);
        }
        Ok(Self {
            envelope: bytes.to_vec(),
            key: CommandKey::new(envelope.key).map_err(|_| ConnectorFault::NotPrepared)?,
        })
    }
}

impl PreparedAttempt for PreparedSubmit {
    fn as_bytes(&self) -> &[u8] {
        &self.envelope
    }

    fn operation(&self) -> &'static str {
        SUBMIT_OPERATION
    }

    fn key(&self) -> &CommandKey {
        &self.key
    }
}

fn proposal_state_word(state: BRegProposalState) -> &'static str {
    match state {
        BRegProposalState::Draft => "draft",
        BRegProposalState::Submitted => "submitted",
        BRegProposalState::Applied => "applied",
        BRegProposalState::Cancelled => "cancelled",
        BRegProposalState::Rejected => "rejected",
    }
}

/// The native lifecycle state one Proposal carries: its state word,
/// turn, submission version, and, when present, the decision and
/// application progress.
pub(crate) fn proposal_state(proposal: &BRegProposal) -> NativeState {
    fn word(value: impl Serialize) -> Option<String> {
        serde_json::to_value(value)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
    }
    let mut details = Vec::new();
    if let Some(turn) = proposal.turn() {
        if let Some(word) = word(turn) {
            details.push(("turn".to_owned(), word));
        }
    }
    details.push((
        "submissionVersion".to_owned(),
        proposal.submission_version().to_string(),
    ));
    if let Some(decision) = proposal.decision() {
        if let Some(word) = word(decision.status) {
            details.push(("decision".to_owned(), word));
        }
    }
    if let Some(application) = proposal.application_status() {
        if let Some(word) = word(application.state) {
            details.push(("application".to_owned(), word));
        }
    }
    NativeState {
        state: proposal_state_word(proposal.state()).to_owned(),
        details,
    }
}

/// The Proposal start operation over one connected connector.
pub struct ProposalStart {
    pub(crate) connector: Arc<super::BregConnector>,
}

impl Observable for ProposalStart {
    fn observe(&self, correlation: &str) -> Result<NativeState, ConnectorFault> {
        observe_proposal(&self.connector, correlation)
    }
}

/// Start a Proposal through the configured action.
impl Operation for ProposalStart {
    type Prepared = PreparedStart;

    fn describe(&self) -> &OperationDescriptor {
        &START
    }

    fn prepare(&self, input: &Value, key: CommandKey) -> Result<PreparedStart, ConnectorFault> {
        if self.connector.action_mode() != BRegActionMode::Proposal {
            return Err(ConnectorFault::NotEnabled);
        }
        // Touch the bindings so a deployment without the Proposal grants
        // answers at prepare.
        self.connector.proposal_get_binding()?;
        self.connector.proposal_collection()?;
        let invocation = action::prepare_invocation(&self.connector, input, &key)?;
        let envelope = action::seal_invocation(
            START_OPERATION,
            &key,
            self.connector.action_binding().action_identifier(),
            self.connector.action_binding().definition_revision(),
            &invocation,
        )?;
        Ok(PreparedStart { envelope, key })
    }

    fn send(&self, prepared: &PreparedStart) -> Result<SendOutcome, ConnectorFault> {
        self.recover(prepared)
    }

    fn recover(&self, prepared: &PreparedStart) -> Result<SendOutcome, ConnectorFault> {
        let envelope = action::unseal_invocation(&prepared.envelope, START_OPERATION)?;
        let request = action::invocation_request(&self.connector, &envelope)?;
        let key =
            BRegIdempotencyKey::parse(&envelope.key).map_err(|_| ConnectorFault::NotPrepared)?;
        let answer = self.connector.block(self.connector.client().start_proposal(
            self.connector.action_binding(),
            &request,
            &key,
        ));
        match answer {
            Ok(proposal) => Ok(SendOutcome {
                category: OutcomeCategory::Accepted,
                native_problem: None,
                correlation: Some(proposal.value.id().to_owned()),
                note: Some("observe the draft through the Proposal family's status read"),
            }),
            Err(error) => classify(&error),
        }
    }
}

/// The Proposal submit operation over one connected connector.
pub struct ProposalSubmit {
    pub(crate) connector: Arc<super::BregConnector>,
}

impl Observable for ProposalSubmit {
    fn observe(&self, correlation: &str) -> Result<NativeState, ConnectorFault> {
        observe_proposal(&self.connector, correlation)
    }
}

impl ProposalSubmit {
    fn unseal(&self, prepared: &PreparedSubmit) -> Result<SubmitEnvelope, ConnectorFault> {
        let envelope: SubmitEnvelope =
            serde_json::from_slice(&prepared.envelope).map_err(|_| ConnectorFault::NotPrepared)?;
        if envelope.version != 1 || envelope.operation != SUBMIT_OPERATION {
            return Err(ConnectorFault::NotPrepared);
        }
        Ok(envelope)
    }

    /// The read-then-decide core of `send` and `recover`: a fresh
    /// authorized read re-arms the exact transition or proves it already
    /// holds; only the re-armed attempt is ever executed, under the same
    /// key.
    fn execute(&self, prepared: &PreparedSubmit) -> Result<SendOutcome, ConnectorFault> {
        let envelope = self.unseal(prepared)?;
        let key =
            BRegIdempotencyKey::parse(&envelope.key).map_err(|_| ConnectorFault::NotPrepared)?;
        let read = self.connector.block(
            self.connector
                .client()
                .get_proposal(self.connector.proposal_get_binding()?, &envelope.proposal),
        );
        // A failed pre-read means the transition was never sent; report
        // the fault so the runner repeats this operation's rule.
        let current = match read {
            Ok(read) => read.value,
            Err(error) => return Err(fault(&error)),
        };
        if current.id() != envelope.proposal
            || current.submission_version() != envelope.submission_version
        {
            // The draft the attempt was prepared from is gone: revised,
            // replaced, or concealed. Re-prepare from a fresh observation.
            return Ok(refused_state(proposal_state_word(current.state())));
        }
        if matches!(
            current.state(),
            BRegProposalState::Submitted | BRegProposalState::Applied
        ) {
            return Ok(SendOutcome {
                category: OutcomeCategory::Completed,
                native_problem: None,
                correlation: Some(current.id().to_owned()),
                note: Some("the fresh read already holds the submitted state"),
            });
        }
        if current.state() != BRegProposalState::Draft {
            return Ok(refused_state(proposal_state_word(current.state())));
        }
        let armed = self
            .connector
            .client()
            .prepare_proposal(&current, "submit", envelope.body.clone(), &key)
            .map_err(|error| fault(&error))?;
        // Re-arm a restored attempt through the client's own recovery
        // check before executing it.
        let armed = self
            .connector
            .client()
            .recover_proposal(&current, &armed)
            .map_err(|error| fault(&error))?;
        let answer = self
            .connector
            .block(self.connector.client().execute_proposal(&armed));
        match answer {
            Ok(submitted) => Ok(completed(submitted.value.id().to_owned())),
            Err(error) => classify(&error),
        }
    }
}

/// Observe one Proposal through the family's status read.
pub(crate) fn observe_proposal(
    connector: &super::BregConnector,
    correlation: &str,
) -> Result<NativeState, ConnectorFault> {
    let answer = connector.block(
        connector
            .client()
            .get_proposal(connector.proposal_get_binding()?, correlation),
    );
    match answer {
        Ok(read) => Ok(proposal_state(&read.value)),
        Err(error) => Err(fault(&error)),
    }
}

impl Operation for ProposalSubmit {
    type Prepared = PreparedSubmit;

    fn describe(&self) -> &OperationDescriptor {
        &SUBMIT
    }

    fn prepare(&self, input: &Value, key: CommandKey) -> Result<PreparedSubmit, ConnectorFault> {
        if self.connector.action_mode() != BRegActionMode::Proposal {
            return Err(ConnectorFault::NotEnabled);
        }
        self.connector.proposal_get_binding()?;
        let proposal = input
            .get("proposal")
            .and_then(Value::as_str)
            .ok_or(ConnectorFault::InvalidInput)?;
        Uuid::parse_str(proposal).map_err(|_| ConnectorFault::InvalidInput)?;
        let submission_version = input
            .get("submissionVersion")
            .and_then(Value::as_u64)
            .filter(|version| (1..=u32::MAX as u64).contains(version))
            .ok_or(ConnectorFault::InvalidInput)? as u32;
        let body = input
            .get("body")
            .cloned()
            .ok_or(ConnectorFault::InvalidInput)?;
        if !body.is_object() {
            return Err(ConnectorFault::InvalidInput);
        }
        let envelope = SubmitEnvelope {
            version: 1,
            operation: SUBMIT_OPERATION.to_owned(),
            key: key.as_str().to_owned(),
            proposal: proposal.to_owned(),
            submission_version,
            body,
        };
        Ok(PreparedSubmit {
            envelope: serde_json::to_vec(&envelope).map_err(|_| ConnectorFault::InvalidInput)?,
            key,
        })
    }

    fn send(&self, prepared: &PreparedSubmit) -> Result<SendOutcome, ConnectorFault> {
        self.execute(prepared)
    }

    fn recover(&self, prepared: &PreparedSubmit) -> Result<SendOutcome, ConnectorFault> {
        self.execute(prepared)
    }
}

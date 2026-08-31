// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use registry_platform_canonical_json::canonicalize_json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::contract::Operation;
use crate::model::CompiledChangeRequestStage;

pub const MAX_REQUEST_TARGETS: usize = 16;
pub const MAX_REQUEST_FIELD_MUTATIONS: usize = 128;
pub const MAX_REQUEST_SNAPSHOT_BYTES: usize = 2_097_152;

const MAX_STAGES: usize = 32;
const MAX_APPROVALS_PER_STAGE: u16 = 32;
const MAX_IDENTIFIER_BYTES: usize = 512;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RequestWorkflow {
    request: RequestKey,
    owner: TrustedActorRef,
    state: RequestState,
    current_version: ProposalVersion,
    workflow_revision: StateRevision,
    proposals: BTreeMap<ProposalVersion, ProposalSnapshot>,
    decisions: Vec<ReviewDecision>,
    application: Option<ApplicationReceipt>,
}

impl RequestWorkflow {
    pub fn new_draft(
        request: RequestKey,
        owner: TrustedActorRef,
        workflow_revision: StateRevision,
    ) -> Self {
        Self {
            request,
            owner,
            state: RequestState::Draft,
            current_version: ProposalVersion::first(),
            workflow_revision,
            proposals: BTreeMap::new(),
            decisions: Vec::new(),
            application: None,
        }
    }

    pub fn state(&self) -> RequestState {
        self.state
    }

    pub fn request(&self) -> &RequestKey {
        &self.request
    }

    pub fn owner(&self) -> &TrustedActorRef {
        &self.owner
    }

    pub fn current_version(&self) -> ProposalVersion {
        self.current_version
    }

    pub fn workflow_revision(&self) -> StateRevision {
        self.workflow_revision
    }

    pub fn proposal(&self, version: ProposalVersion) -> Option<&ProposalSnapshot> {
        self.proposals.get(&version)
    }

    pub fn current_proposal(&self) -> Option<&ProposalSnapshot> {
        self.proposal(self.current_version)
    }

    pub fn decisions(&self) -> &[ReviewDecision] {
        &self.decisions
    }

    pub fn application(&self) -> Option<&ApplicationReceipt> {
        self.application.as_ref()
    }

    pub fn validate_restored(self) -> Result<Self, WorkflowError> {
        self.validate_restored_invariants()?;
        Ok(self)
    }

    #[cfg(feature = "runtime")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn restore(
        request: RequestKey,
        owner: TrustedActorRef,
        state: RequestState,
        current_version: ProposalVersion,
        workflow_revision: StateRevision,
        proposals: BTreeMap<ProposalVersion, ProposalSnapshot>,
        decisions: Vec<ReviewDecision>,
        application: Option<ApplicationReceipt>,
    ) -> Result<Self, WorkflowError> {
        Self {
            request,
            owner,
            state,
            current_version,
            workflow_revision,
            proposals,
            decisions,
            application,
        }
        .validate_restored()
    }

    pub fn submit(
        mut self,
        context: TrustedTransitionContext,
        proposal: PreparedProposal,
    ) -> Result<WorkflowTransition, WorkflowError> {
        if self.state != RequestState::Draft {
            return Err(WorkflowError::InvalidTransition);
        }
        if self.proposals.contains_key(&self.current_version) {
            return Err(WorkflowError::InvalidTransition);
        }
        let version = self.current_version;
        let proposal = proposal.freeze(&self.request, version, context)?;
        let effect_digest = proposal.effect_digest.clone();
        self.proposals.insert(version, proposal);
        self.state = RequestState::Submitted;
        self.workflow_revision = self.workflow_revision.next()?;
        Ok(WorkflowTransition {
            workflow: self,
            effect: TransitionEffect::Submitted {
                version,
                effect_digest,
            },
        })
    }

    pub fn decide(
        mut self,
        context: TrustedTransitionContext,
        stage_id: impl Into<String>,
        version: ProposalVersion,
        displayed_digest: &ProposalDigest,
        decision: ReviewDecisionKind,
    ) -> Result<WorkflowTransition, WorkflowError> {
        if self.state != RequestState::Submitted {
            return Err(WorkflowError::InvalidTransition);
        }
        if version != self.current_version {
            return Err(WorkflowError::StaleProposalVersion);
        }
        let stage_id = ValidatedToken::new(stage_id, TokenKind::Stage)?;
        let (proposal_digest, submitted_by, pending_stage, is_last_stage) = {
            let proposal = self
                .proposals
                .get(&version)
                .ok_or(WorkflowError::ProposalUnavailable)?;
            proposal.verify_digest(&self.request)?;
            if !proposal.effect_digest.matches(displayed_digest) {
                return Err(WorkflowError::DigestMismatch);
            }
            let pending_stage = self
                .pending_stage(proposal)
                .ok_or(WorkflowError::InvalidTransition)?
                .clone();
            let is_last_stage = proposal
                .stages
                .last()
                .is_some_and(|stage| stage.id == pending_stage.id);
            (
                proposal.effect_digest.clone(),
                proposal.submitted_by.clone(),
                pending_stage,
                is_last_stage,
            )
        };
        if pending_stage.id != stage_id.0 {
            return Err(WorkflowError::StageOutOfOrder);
        }
        if pending_stage.exclude_submitter && context.actor == submitted_by {
            return Err(WorkflowError::SubmitterExcluded);
        }
        if self.decisions.iter().any(|existing| {
            existing.version == version
                && existing.stage_id == stage_id.0
                && existing.actor == context.actor
        }) {
            return Err(WorkflowError::DuplicateDecision);
        }

        let review = ReviewDecision {
            version,
            stage_id: stage_id.0,
            kind: decision,
            actor: context.actor,
            decided_at: context.now,
            effect_digest: proposal_digest,
        };
        self.decisions.push(review.clone());

        match decision {
            ReviewDecisionKind::Approve => {
                let approvals = self
                    .decisions
                    .iter()
                    .filter(|decision| {
                        decision.version == version
                            && decision.stage_id == review.stage_id
                            && decision.kind == ReviewDecisionKind::Approve
                    })
                    .map(|decision| &decision.actor)
                    .collect::<BTreeSet<_>>()
                    .len();
                if approvals >= usize::from(pending_stage.approvals) && is_last_stage {
                    self.state = RequestState::Approved;
                }
            }
            ReviewDecisionKind::Reject => {
                self.state = RequestState::Rejected;
            }
            ReviewDecisionKind::RequestRevision => {
                self.state = RequestState::NeedsChanges;
            }
        }
        self.workflow_revision = self.workflow_revision.next()?;
        Ok(WorkflowTransition {
            workflow: self,
            effect: TransitionEffect::DecisionRecorded(review),
        })
    }

    pub fn revise(
        mut self,
        _context: TrustedTransitionContext,
    ) -> Result<WorkflowTransition, WorkflowError> {
        if !matches!(
            self.state,
            RequestState::NeedsChanges | RequestState::Rejected
        ) {
            return Err(WorkflowError::InvalidTransition);
        }
        self.state = RequestState::Draft;
        let version = self.current_version.next()?;
        self.current_version = version;
        self.workflow_revision = self.workflow_revision.next()?;
        Ok(WorkflowTransition {
            workflow: self,
            effect: TransitionEffect::DraftVersionStarted {
                version,
                reason: DraftStartReason::Revision,
            },
        })
    }

    pub fn rebase(
        mut self,
        _context: TrustedTransitionContext,
    ) -> Result<WorkflowTransition, WorkflowError> {
        if !matches!(
            self.state,
            RequestState::Submitted
                | RequestState::Approved
                | RequestState::NeedsChanges
                | RequestState::Rejected
        ) {
            return Err(WorkflowError::InvalidTransition);
        }
        self.state = RequestState::Draft;
        let version = self.current_version.next()?;
        self.current_version = version;
        self.workflow_revision = self.workflow_revision.next()?;
        Ok(WorkflowTransition {
            workflow: self,
            effect: TransitionEffect::DraftVersionStarted {
                version,
                reason: DraftStartReason::Rebase,
            },
        })
    }

    pub fn cancel(
        mut self,
        _context: TrustedTransitionContext,
    ) -> Result<WorkflowTransition, WorkflowError> {
        if matches!(self.state, RequestState::Applied | RequestState::Canceled) {
            return Err(WorkflowError::InvalidTransition);
        }
        self.state = RequestState::Canceled;
        self.workflow_revision = self.workflow_revision.next()?;
        Ok(WorkflowTransition {
            workflow: self,
            effect: TransitionEffect::Canceled,
        })
    }

    pub fn apply(
        mut self,
        context: TrustedTransitionContext,
        version: ProposalVersion,
        displayed_digest: &ProposalDigest,
        contract_fingerprint: &ContractFingerprint,
        observed_targets: Vec<ObservedTarget>,
        application: PreparedApplication,
    ) -> Result<WorkflowTransition, WorkflowError> {
        if self.state != RequestState::Approved {
            return Err(WorkflowError::InvalidTransition);
        }
        if version != self.current_version {
            return Err(WorkflowError::StaleProposalVersion);
        }
        if self.application.is_some() {
            return Err(WorkflowError::AlreadyApplied);
        }
        let proposal = self
            .proposals
            .get(&version)
            .ok_or(WorkflowError::ProposalUnavailable)?;
        proposal.verify_digest(&self.request)?;
        if !proposal.effect_digest.matches(displayed_digest) {
            return Err(WorkflowError::DigestMismatch);
        }
        if &proposal.contract_fingerprint != contract_fingerprint {
            return Err(WorkflowError::ContractFingerprintMismatch);
        }
        proposal.verify_observed_targets(&observed_targets)?;
        proposal.verify_application_links(&application.result_links)?;

        let receipt = ApplicationReceipt {
            application_id: application.application_id,
            version,
            effect_digest: proposal.effect_digest.clone(),
            applied_by: context.actor,
            applied_at: context.now,
            result_links: application.result_links,
        };
        self.state = RequestState::Applied;
        self.workflow_revision = self.workflow_revision.next()?;
        self.application = Some(receipt.clone());
        Ok(WorkflowTransition {
            workflow: self,
            effect: TransitionEffect::Applied(receipt),
        })
    }

    fn pending_stage<'a>(
        &self,
        proposal: &'a ProposalSnapshot,
    ) -> Option<&'a CompiledChangeRequestStage> {
        proposal
            .stages
            .iter()
            .find(|stage| !self.stage_is_satisfied(proposal, &stage.id))
    }

    fn stage_is_satisfied(&self, proposal: &ProposalSnapshot, stage_id: &str) -> bool {
        let Some(stage) = proposal.stages.iter().find(|stage| stage.id == stage_id) else {
            return false;
        };
        let approvals = self
            .decisions
            .iter()
            .filter(|decision| {
                decision.version == proposal.version
                    && decision.stage_id == stage_id
                    && decision.kind == ReviewDecisionKind::Approve
            })
            .map(|decision| &decision.actor)
            .collect::<BTreeSet<_>>()
            .len();
        approvals >= usize::from(stage.approvals)
    }

    fn validate_restored_invariants(&self) -> Result<(), WorkflowError> {
        self.request.validate()?;
        self.owner.validate()?;
        self.current_version.validate()?;
        self.workflow_revision.validate()?;

        for (version, proposal) in &self.proposals {
            version.validate()?;
            if *version != proposal.version {
                return Err(WorkflowError::InvalidRestoredState);
            }
            if *version > self.current_version {
                return Err(WorkflowError::InvalidRestoredState);
            }
            proposal.validate_restored(&self.request)?;
        }

        self.validate_restored_decisions()?;
        self.validate_restored_application()?;
        self.validate_restored_state()
    }

    fn validate_restored_decisions(&self) -> Result<(), WorkflowError> {
        let mut seen = BTreeSet::new();
        let mut terminal_by_version: BTreeMap<ProposalVersion, ReviewDecisionKind> =
            BTreeMap::new();
        for decision in &self.decisions {
            decision.validate()?;
            if !seen.insert((
                decision.version,
                decision.stage_id.as_str(),
                decision.actor.as_str(),
            )) {
                return Err(WorkflowError::DuplicateDecision);
            }
            let proposal = self
                .proposals
                .get(&decision.version)
                .ok_or(WorkflowError::InvalidRestoredState)?;
            if !proposal.effect_digest.matches(&decision.effect_digest) {
                return Err(WorkflowError::DigestMismatch);
            }
            let Some(stage_index) = proposal
                .stages
                .iter()
                .position(|stage| stage.id == decision.stage_id)
            else {
                return Err(WorkflowError::InvalidRestoredState);
            };
            for prior_stage in &proposal.stages[..stage_index] {
                if !self.stage_is_satisfied(proposal, &prior_stage.id) {
                    return Err(WorkflowError::StageOutOfOrder);
                }
            }
            if matches!(
                decision.kind,
                ReviewDecisionKind::Reject | ReviewDecisionKind::RequestRevision
            ) && terminal_by_version
                .insert(decision.version, decision.kind)
                .is_some()
            {
                return Err(WorkflowError::InvalidRestoredState);
            }
        }
        for (version, terminal) in terminal_by_version {
            let proposal = self
                .proposals
                .get(&version)
                .ok_or(WorkflowError::InvalidRestoredState)?;
            let terminal_stage = self
                .decisions
                .iter()
                .find(|decision| decision.version == version && decision.kind == terminal)
                .ok_or(WorkflowError::InvalidRestoredState)?
                .stage_id
                .as_str();
            let terminal_index = proposal
                .stages
                .iter()
                .position(|stage| stage.id == terminal_stage)
                .ok_or(WorkflowError::InvalidRestoredState)?;
            if self.decisions.iter().any(|decision| {
                decision.version == version
                    && proposal
                        .stages
                        .iter()
                        .position(|stage| stage.id == decision.stage_id)
                        .is_some_and(|index| index > terminal_index)
            }) {
                return Err(WorkflowError::InvalidRestoredState);
            }
        }
        Ok(())
    }

    fn validate_restored_application(&self) -> Result<(), WorkflowError> {
        let Some(application) = &self.application else {
            return Ok(());
        };
        application.validate()?;
        if application.version != self.current_version {
            return Err(WorkflowError::InvalidRestoredState);
        }
        let proposal = self
            .proposals
            .get(&application.version)
            .ok_or(WorkflowError::InvalidRestoredState)?;
        if !proposal.effect_digest.matches(&application.effect_digest) {
            return Err(WorkflowError::DigestMismatch);
        }
        proposal.verify_application_links(&application.result_links)
    }

    fn validate_restored_state(&self) -> Result<(), WorkflowError> {
        let current_proposal = self.proposals.get(&self.current_version);
        let current_terminal = self.decisions.iter().find(|decision| {
            decision.version == self.current_version
                && matches!(
                    decision.kind,
                    ReviewDecisionKind::Reject | ReviewDecisionKind::RequestRevision
                )
        });
        let current_satisfied =
            current_proposal.is_some_and(|proposal| self.all_stages_satisfied(proposal));
        match self.state {
            RequestState::Draft => {
                if current_proposal.is_some()
                    || self.application.is_some()
                    || self
                        .decisions
                        .iter()
                        .any(|decision| decision.version == self.current_version)
                {
                    return Err(WorkflowError::InvalidRestoredState);
                }
            }
            RequestState::Submitted => {
                if current_proposal.is_none()
                    || current_terminal.is_some()
                    || current_satisfied
                    || self.application.is_some()
                {
                    return Err(WorkflowError::InvalidRestoredState);
                }
            }
            RequestState::Approved => {
                if current_proposal.is_none()
                    || current_terminal.is_some()
                    || !current_satisfied
                    || self.application.is_some()
                {
                    return Err(WorkflowError::InvalidRestoredState);
                }
            }
            RequestState::NeedsChanges => {
                if current_proposal.is_none()
                    || !current_terminal.is_some_and(|decision| {
                        decision.kind == ReviewDecisionKind::RequestRevision
                    })
                    || self.application.is_some()
                {
                    return Err(WorkflowError::InvalidRestoredState);
                }
            }
            RequestState::Rejected => {
                if current_proposal.is_none()
                    || !current_terminal
                        .is_some_and(|decision| decision.kind == ReviewDecisionKind::Reject)
                    || self.application.is_some()
                {
                    return Err(WorkflowError::InvalidRestoredState);
                }
            }
            RequestState::Canceled => {
                if self.application.is_some() {
                    return Err(WorkflowError::InvalidRestoredState);
                }
                if current_proposal.is_none()
                    && (self
                        .decisions
                        .iter()
                        .any(|decision| decision.version == self.current_version))
                {
                    return Err(WorkflowError::InvalidRestoredState);
                }
            }
            RequestState::Applied => {
                let Some(proposal) = current_proposal else {
                    return Err(WorkflowError::InvalidRestoredState);
                };
                if current_terminal.is_some()
                    || !self.all_stages_satisfied(proposal)
                    || self.application.is_none()
                {
                    return Err(WorkflowError::InvalidRestoredState);
                }
            }
        }
        Ok(())
    }

    fn all_stages_satisfied(&self, proposal: &ProposalSnapshot) -> bool {
        proposal
            .stages
            .iter()
            .all(|stage| self.stage_is_satisfied(proposal, &stage.id))
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PreparedProposal {
    request_record_revision: RecordRevision,
    contract_fingerprint: ContractFingerprint,
    originating_package: PackageFingerprint,
    stages: Vec<CompiledChangeRequestStage>,
    effects: Vec<PreparedEffect>,
    combined_snapshot_bytes: usize,
}

impl PreparedProposal {
    pub fn new(
        request_record_revision: RecordRevision,
        contract_fingerprint: ContractFingerprint,
        originating_package: PackageFingerprint,
        stages: Vec<CompiledChangeRequestStage>,
        effects: Vec<PreparedEffect>,
        combined_snapshot_bytes: usize,
    ) -> Result<Self, WorkflowError> {
        validate_stages(&stages)?;
        validate_effects(&effects, combined_snapshot_bytes)?;
        Ok(Self {
            request_record_revision,
            contract_fingerprint,
            originating_package,
            stages,
            effects,
            combined_snapshot_bytes,
        })
    }

    pub fn request_record_revision(&self) -> RecordRevision {
        self.request_record_revision
    }

    pub fn contract_fingerprint(&self) -> &ContractFingerprint {
        &self.contract_fingerprint
    }

    pub fn originating_package(&self) -> &PackageFingerprint {
        &self.originating_package
    }

    pub fn stages(&self) -> &[CompiledChangeRequestStage] {
        &self.stages
    }

    pub fn effects(&self) -> &[PreparedEffect] {
        &self.effects
    }

    pub fn combined_snapshot_bytes(&self) -> usize {
        self.combined_snapshot_bytes
    }

    fn freeze(
        self,
        request: &RequestKey,
        version: ProposalVersion,
        context: TrustedTransitionContext,
    ) -> Result<ProposalSnapshot, WorkflowError> {
        let effect_digest = proposal_digest(
            request,
            version,
            self.request_record_revision,
            &self.contract_fingerprint,
            &self.originating_package,
            &self.stages,
            &self.effects,
        )?;
        Ok(ProposalSnapshot {
            version,
            request_record_revision: self.request_record_revision,
            contract_fingerprint: self.contract_fingerprint,
            originating_package: self.originating_package,
            stages: self.stages,
            effects: self.effects,
            combined_snapshot_bytes: self.combined_snapshot_bytes,
            effect_digest,
            submitted_by: context.actor,
            submitted_at: context.now,
        })
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProposalSnapshot {
    version: ProposalVersion,
    request_record_revision: RecordRevision,
    contract_fingerprint: ContractFingerprint,
    originating_package: PackageFingerprint,
    stages: Vec<CompiledChangeRequestStage>,
    effects: Vec<PreparedEffect>,
    combined_snapshot_bytes: usize,
    effect_digest: ProposalDigest,
    submitted_by: TrustedActorRef,
    submitted_at: TrustedTimestamp,
}

impl ProposalSnapshot {
    pub fn version(&self) -> ProposalVersion {
        self.version
    }

    pub fn request_record_revision(&self) -> RecordRevision {
        self.request_record_revision
    }

    pub fn effect_digest(&self) -> &ProposalDigest {
        &self.effect_digest
    }

    pub fn stages(&self) -> &[CompiledChangeRequestStage] {
        &self.stages
    }

    pub fn effects(&self) -> &[PreparedEffect] {
        &self.effects
    }

    pub fn contract_fingerprint(&self) -> &ContractFingerprint {
        &self.contract_fingerprint
    }

    pub fn originating_package(&self) -> &PackageFingerprint {
        &self.originating_package
    }

    pub fn combined_snapshot_bytes(&self) -> usize {
        self.combined_snapshot_bytes
    }

    pub fn submitted_by(&self) -> &TrustedActorRef {
        &self.submitted_by
    }

    pub fn submitted_at(&self) -> &TrustedTimestamp {
        &self.submitted_at
    }

    pub fn verify_digest(&self, request: &RequestKey) -> Result<(), WorkflowError> {
        let actual = proposal_digest(
            request,
            self.version,
            self.request_record_revision,
            &self.contract_fingerprint,
            &self.originating_package,
            &self.stages,
            &self.effects,
        )?;
        if actual.matches(&self.effect_digest) {
            Ok(())
        } else {
            Err(WorkflowError::DigestMismatch)
        }
    }

    fn validate_restored(&self, request: &RequestKey) -> Result<(), WorkflowError> {
        self.version.validate()?;
        self.request_record_revision.validate()?;
        self.contract_fingerprint.validate()?;
        self.originating_package.validate()?;
        validate_stages(&self.stages)?;
        validate_effects(&self.effects, self.combined_snapshot_bytes)?;
        self.effect_digest.validate()?;
        self.submitted_by.validate()?;
        self.submitted_at.validate()?;
        self.verify_digest(request)
    }

    fn expected_targets(&self) -> BTreeMap<TargetIdentity, ExpectedTargetState> {
        let mut targets = BTreeMap::new();
        for effect in &self.effects {
            let (identity, expected) = effect.target.expected_state();
            targets.insert(identity, expected);
        }
        targets
    }

    fn verify_observed_targets(&self, observed: &[ObservedTarget]) -> Result<(), WorkflowError> {
        let expected = self.expected_targets();
        if observed.len() != expected.len() {
            return Err(WorkflowError::TargetBindingMismatch);
        }
        let mut seen = BTreeSet::new();
        for target in observed {
            let identity = target.identity();
            if !seen.insert(identity.clone()) {
                return Err(WorkflowError::TargetBindingMismatch);
            }
            let Some(expected_state) = expected.get(&identity) else {
                return Err(WorkflowError::TargetBindingMismatch);
            };
            match (expected_state, target) {
                (
                    ExpectedTargetState::Existing { base_revision },
                    ObservedTarget::Existing {
                        current_revision, ..
                    },
                ) if base_revision == current_revision => {}
                (ExpectedTargetState::Existing { .. }, ObservedTarget::Existing { .. }) => {
                    return Err(WorkflowError::StaleTargetRevision);
                }
                (ExpectedTargetState::ReservedCreate, ObservedTarget::ReservedCreate { .. }) => {}
                _ => return Err(WorkflowError::TargetBindingMismatch),
            }
        }
        Ok(())
    }

    fn verify_application_links(
        &self,
        result_links: &[ApplicationResultLink],
    ) -> Result<(), WorkflowError> {
        let expected = self
            .expected_targets()
            .keys()
            .map(TargetIdentity::record_key)
            .collect::<BTreeSet<_>>();
        let actual = result_links
            .iter()
            .map(|link| (link.entity_id.clone(), link.record_id.clone()))
            .collect::<BTreeSet<_>>();
        if expected != actual || result_links.len() != actual.len() {
            return Err(WorkflowError::ApplicationReceiptMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PreparedEffect {
    id: EffectId,
    operation: Operation,
    target: PreparedTarget,
    field_changes: Vec<PreparedFieldChange>,
}

impl PreparedEffect {
    pub fn new(
        id: EffectId,
        operation: Operation,
        target: PreparedTarget,
        field_changes: Vec<PreparedFieldChange>,
    ) -> Result<Self, WorkflowError> {
        if !matches!(operation, Operation::Create | Operation::Patch) {
            return Err(WorkflowError::UnsupportedOperation);
        }
        match (&target, operation) {
            (PreparedTarget::ReservedCreate { .. }, Operation::Create)
            | (PreparedTarget::Existing { .. }, Operation::Patch) => {}
            _ => return Err(WorkflowError::TargetOperationMismatch),
        }
        if field_changes.is_empty() {
            return Err(WorkflowError::EmptyEffect);
        }
        let mut fields = BTreeSet::new();
        for change in &field_changes {
            if !fields.insert(change.field.clone()) {
                return Err(WorkflowError::OverlappingFieldWrite);
            }
            if operation == Operation::Create && change.before != FieldValue::Missing {
                return Err(WorkflowError::TargetOperationMismatch);
            }
        }
        Ok(Self {
            id,
            operation,
            target,
            field_changes,
        })
    }

    pub fn id(&self) -> &EffectId {
        &self.id
    }

    pub fn operation(&self) -> Operation {
        self.operation
    }

    pub fn target(&self) -> &PreparedTarget {
        &self.target
    }

    pub fn field_changes(&self) -> &[PreparedFieldChange] {
        &self.field_changes
    }

    fn validate_restored(&self) -> Result<(), WorkflowError> {
        self.id.validate()?;
        if !matches!(self.operation, Operation::Create | Operation::Patch) {
            return Err(WorkflowError::UnsupportedOperation);
        }
        self.target.validate()?;
        match (&self.target, self.operation) {
            (PreparedTarget::ReservedCreate { .. }, Operation::Create)
            | (PreparedTarget::Existing { .. }, Operation::Patch) => {}
            _ => return Err(WorkflowError::TargetOperationMismatch),
        }
        if self.field_changes.is_empty() {
            return Err(WorkflowError::EmptyEffect);
        }
        let mut fields = BTreeSet::new();
        for change in &self.field_changes {
            change.validate()?;
            if !fields.insert(change.field.clone()) {
                return Err(WorkflowError::OverlappingFieldWrite);
            }
            if self.operation == Operation::Create && change.before != FieldValue::Missing {
                return Err(WorkflowError::TargetOperationMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum PreparedTarget {
    Existing {
        entity_id: EntityId,
        record_id: RecordId,
        base_revision: RecordRevision,
    },
    ReservedCreate {
        entity_id: EntityId,
        reserved_record_id: RecordId,
    },
}

impl PreparedTarget {
    pub fn existing(
        entity_id: EntityId,
        record_id: RecordId,
        base_revision: RecordRevision,
    ) -> Self {
        Self::Existing {
            entity_id,
            record_id,
            base_revision,
        }
    }

    pub fn reserved_create(entity_id: EntityId, reserved_record_id: RecordId) -> Self {
        Self::ReservedCreate {
            entity_id,
            reserved_record_id,
        }
    }

    pub fn entity_id(&self) -> &EntityId {
        match self {
            Self::Existing { entity_id, .. } | Self::ReservedCreate { entity_id, .. } => entity_id,
        }
    }

    pub fn existing_record_id(&self) -> Option<&RecordId> {
        match self {
            Self::Existing { record_id, .. } => Some(record_id),
            Self::ReservedCreate { .. } => None,
        }
    }

    pub fn reserved_record_id(&self) -> Option<&RecordId> {
        match self {
            Self::ReservedCreate {
                reserved_record_id, ..
            } => Some(reserved_record_id),
            Self::Existing { .. } => None,
        }
    }

    pub fn base_revision(&self) -> Option<RecordRevision> {
        match self {
            Self::Existing { base_revision, .. } => Some(*base_revision),
            Self::ReservedCreate { .. } => None,
        }
    }

    fn identity(&self) -> TargetIdentity {
        match self {
            Self::Existing {
                entity_id,
                record_id,
                ..
            } => TargetIdentity::Existing {
                entity_id: entity_id.clone(),
                record_id: record_id.clone(),
            },
            Self::ReservedCreate {
                entity_id,
                reserved_record_id,
            } => TargetIdentity::ReservedCreate {
                entity_id: entity_id.clone(),
                reserved_record_id: reserved_record_id.clone(),
            },
        }
    }

    fn expected_state(&self) -> (TargetIdentity, ExpectedTargetState) {
        match self {
            Self::Existing {
                entity_id,
                record_id,
                base_revision,
            } => (
                TargetIdentity::Existing {
                    entity_id: entity_id.clone(),
                    record_id: record_id.clone(),
                },
                ExpectedTargetState::Existing {
                    base_revision: *base_revision,
                },
            ),
            Self::ReservedCreate {
                entity_id,
                reserved_record_id,
            } => (
                TargetIdentity::ReservedCreate {
                    entity_id: entity_id.clone(),
                    reserved_record_id: reserved_record_id.clone(),
                },
                ExpectedTargetState::ReservedCreate,
            ),
        }
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        match self {
            Self::Existing {
                entity_id,
                record_id,
                base_revision,
            } => {
                entity_id.validate()?;
                record_id.validate()?;
                base_revision.validate()
            }
            Self::ReservedCreate {
                entity_id,
                reserved_record_id,
            } => {
                entity_id.validate()?;
                reserved_record_id.validate()
            }
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PreparedFieldChange {
    field: FieldId,
    before: FieldValue,
    after: FieldValue,
}

impl PreparedFieldChange {
    pub fn set(field: FieldId, before: FieldValue, after: Value) -> Result<Self, WorkflowError> {
        if after == Value::Null {
            return Err(WorkflowError::NullSetValue);
        }
        Ok(Self {
            field,
            before,
            after: FieldValue::Present { value: after },
        })
    }

    pub fn clear(field: FieldId, before: FieldValue) -> Self {
        Self {
            field,
            before,
            after: FieldValue::Missing,
        }
    }

    pub fn field(&self) -> &FieldId {
        &self.field
    }

    pub fn before(&self) -> &FieldValue {
        &self.before
    }

    pub fn after(&self) -> &FieldValue {
        &self.after
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        self.field.validate()?;
        self.before.validate(false)?;
        self.after.validate(true)
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum FieldValue {
    Missing,
    Present { value: Value },
}

impl FieldValue {
    pub fn present(value: Value) -> Self {
        Self::Present { value }
    }

    fn validate(&self, reject_null: bool) -> Result<(), WorkflowError> {
        match self {
            Self::Missing => Ok(()),
            Self::Present { value } if reject_null && value == &Value::Null => {
                Err(WorkflowError::NullSetValue)
            }
            Self::Present { value } => canonicalize_json(value)
                .map(|_| ())
                .map_err(|_| WorkflowError::Canonicalization),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TrustedTransitionContext {
    actor: TrustedActorRef,
    now: TrustedTimestamp,
}

impl TrustedTransitionContext {
    pub fn from_verified_context(actor: TrustedActorRef, now: TrustedTimestamp) -> Self {
        Self { actor, now }
    }

    pub fn actor(&self) -> &TrustedActorRef {
        &self.actor
    }

    pub fn now(&self) -> &TrustedTimestamp {
        &self.now
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum ObservedTarget {
    Existing {
        entity_id: EntityId,
        record_id: RecordId,
        current_revision: RecordRevision,
    },
    ReservedCreate {
        entity_id: EntityId,
        reserved_record_id: RecordId,
    },
}

impl ObservedTarget {
    pub fn existing(
        entity_id: EntityId,
        record_id: RecordId,
        current_revision: RecordRevision,
    ) -> Self {
        Self::Existing {
            entity_id,
            record_id,
            current_revision,
        }
    }

    pub fn reserved_create(entity_id: EntityId, reserved_record_id: RecordId) -> Self {
        Self::ReservedCreate {
            entity_id,
            reserved_record_id,
        }
    }

    fn identity(&self) -> TargetIdentity {
        match self {
            Self::Existing {
                entity_id,
                record_id,
                ..
            } => TargetIdentity::Existing {
                entity_id: entity_id.clone(),
                record_id: record_id.clone(),
            },
            Self::ReservedCreate {
                entity_id,
                reserved_record_id,
            } => TargetIdentity::ReservedCreate {
                entity_id: entity_id.clone(),
                reserved_record_id: reserved_record_id.clone(),
            },
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PreparedApplication {
    application_id: ApplicationId,
    result_links: Vec<ApplicationResultLink>,
}

impl PreparedApplication {
    pub fn new(
        application_id: ApplicationId,
        result_links: Vec<ApplicationResultLink>,
    ) -> Result<Self, WorkflowError> {
        if result_links.is_empty() {
            return Err(WorkflowError::ApplicationReceiptMismatch);
        }
        let mut unique = BTreeSet::new();
        for link in &result_links {
            if !unique.insert((link.entity_id.clone(), link.record_id.clone())) {
                return Err(WorkflowError::ApplicationReceiptMismatch);
            }
        }
        Ok(Self {
            application_id,
            result_links,
        })
    }

    pub fn application_id(&self) -> &ApplicationId {
        &self.application_id
    }

    pub fn result_links(&self) -> &[ApplicationResultLink] {
        &self.result_links
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApplicationReceipt {
    application_id: ApplicationId,
    version: ProposalVersion,
    effect_digest: ProposalDigest,
    applied_by: TrustedActorRef,
    applied_at: TrustedTimestamp,
    result_links: Vec<ApplicationResultLink>,
}

impl ApplicationReceipt {
    #[cfg(feature = "runtime")]
    pub(crate) fn restore(
        application_id: ApplicationId,
        version: ProposalVersion,
        effect_digest: ProposalDigest,
        applied_by: TrustedActorRef,
        applied_at: TrustedTimestamp,
        result_links: Vec<ApplicationResultLink>,
    ) -> Result<Self, WorkflowError> {
        let receipt = Self {
            application_id,
            version,
            effect_digest,
            applied_by,
            applied_at,
            result_links,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn application_id(&self) -> &ApplicationId {
        &self.application_id
    }

    pub fn version(&self) -> ProposalVersion {
        self.version
    }

    pub fn effect_digest(&self) -> &ProposalDigest {
        &self.effect_digest
    }

    pub fn result_links(&self) -> &[ApplicationResultLink] {
        &self.result_links
    }

    pub fn applied_by(&self) -> &TrustedActorRef {
        &self.applied_by
    }

    pub fn applied_at(&self) -> &TrustedTimestamp {
        &self.applied_at
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        self.application_id.validate()?;
        self.version.validate()?;
        self.effect_digest.validate()?;
        self.applied_by.validate()?;
        self.applied_at.validate()?;
        if self.result_links.is_empty() {
            return Err(WorkflowError::ApplicationReceiptMismatch);
        }
        let mut unique = BTreeSet::new();
        for link in &self.result_links {
            link.validate()?;
            if !unique.insert((link.entity_id.clone(), link.record_id.clone())) {
                return Err(WorkflowError::ApplicationReceiptMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApplicationResultLink {
    entity_id: EntityId,
    record_id: RecordId,
    record_revision: RecordRevision,
}

impl ApplicationResultLink {
    pub fn new(entity_id: EntityId, record_id: RecordId, record_revision: RecordRevision) -> Self {
        Self {
            entity_id,
            record_id,
            record_revision,
        }
    }

    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    pub fn record_id(&self) -> &RecordId {
        &self.record_id
    }

    pub fn record_revision(&self) -> RecordRevision {
        self.record_revision
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        self.entity_id.validate()?;
        self.record_id.validate()?;
        self.record_revision.validate()
    }
}

#[derive(Clone, PartialEq)]
pub struct WorkflowTransition {
    workflow: RequestWorkflow,
    effect: TransitionEffect,
}

impl WorkflowTransition {
    pub fn into_workflow(self) -> RequestWorkflow {
        self.workflow
    }

    pub fn workflow(&self) -> &RequestWorkflow {
        &self.workflow
    }

    pub fn effect(&self) -> &TransitionEffect {
        &self.effect
    }
}

#[derive(Clone, PartialEq)]
pub enum TransitionEffect {
    Submitted {
        version: ProposalVersion,
        effect_digest: ProposalDigest,
    },
    DecisionRecorded(ReviewDecision),
    DraftVersionStarted {
        version: ProposalVersion,
        reason: DraftStartReason,
    },
    Canceled,
    Applied(ApplicationReceipt),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DraftStartReason {
    Revision,
    Rebase,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewDecision {
    version: ProposalVersion,
    stage_id: String,
    kind: ReviewDecisionKind,
    actor: TrustedActorRef,
    decided_at: TrustedTimestamp,
    effect_digest: ProposalDigest,
}

impl ReviewDecision {
    #[cfg(feature = "runtime")]
    pub(crate) fn restore(
        version: ProposalVersion,
        stage_id: String,
        kind: ReviewDecisionKind,
        actor: TrustedActorRef,
        decided_at: TrustedTimestamp,
        effect_digest: ProposalDigest,
    ) -> Result<Self, WorkflowError> {
        let decision = Self {
            version,
            stage_id,
            kind,
            actor,
            decided_at,
            effect_digest,
        };
        decision.validate()?;
        Ok(decision)
    }

    pub fn version(&self) -> ProposalVersion {
        self.version
    }

    pub fn stage_id(&self) -> &str {
        &self.stage_id
    }

    pub fn kind(&self) -> ReviewDecisionKind {
        self.kind
    }

    pub fn actor(&self) -> &TrustedActorRef {
        &self.actor
    }

    pub fn decided_at(&self) -> &TrustedTimestamp {
        &self.decided_at
    }

    pub fn effect_digest(&self) -> &ProposalDigest {
        &self.effect_digest
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        self.version.validate()?;
        ValidatedToken::new(self.stage_id.clone(), TokenKind::Stage)?;
        self.actor.validate()?;
        self.decided_at.validate()?;
        self.effect_digest.validate()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecisionKind {
    Approve,
    Reject,
    RequestRevision,
}

#[cfg(feature = "runtime")]
impl ReviewDecisionKind {
    pub(crate) fn from_storage(value: &str) -> Result<Self, WorkflowError> {
        match value {
            "approve" => Ok(Self::Approve),
            "reject" => Ok(Self::Reject),
            "request_revision" => Ok(Self::RequestRevision),
            _ => Err(WorkflowError::InvalidRestoredState),
        }
    }

    pub(crate) fn as_storage(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::RequestRevision => "request_revision",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestState {
    Draft,
    Submitted,
    Approved,
    NeedsChanges,
    Rejected,
    Canceled,
    Applied,
}

#[cfg(feature = "runtime")]
impl RequestState {
    pub(crate) fn from_storage(value: &str) -> Result<Self, WorkflowError> {
        match value {
            "draft" => Ok(Self::Draft),
            "submitted" => Ok(Self::Submitted),
            "approved" => Ok(Self::Approved),
            "needs_changes" => Ok(Self::NeedsChanges),
            "rejected" => Ok(Self::Rejected),
            "canceled" => Ok(Self::Canceled),
            "applied" => Ok(Self::Applied),
            _ => Err(WorkflowError::InvalidRestoredState),
        }
    }

    pub(crate) fn as_storage(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Submitted => "submitted",
            Self::Approved => "approved",
            Self::NeedsChanges => "needs_changes",
            Self::Rejected => "rejected",
            Self::Canceled => "canceled",
            Self::Applied => "applied",
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RequestKey {
    entity_id: EntityId,
    record_id: RecordId,
}

impl RequestKey {
    pub fn new(entity_id: EntityId, record_id: RecordId) -> Self {
        Self {
            entity_id,
            record_id,
        }
    }

    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    pub fn record_id(&self) -> &RecordId {
        &self.record_id
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        self.entity_id.validate()?;
        self.record_id.validate()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProposalVersion(u32);

impl ProposalVersion {
    pub fn new(value: u32) -> Result<Self, WorkflowError> {
        if value == 0 {
            return Err(WorkflowError::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    pub fn first() -> Self {
        Self(1)
    }

    pub fn get(self) -> u32 {
        self.0
    }

    fn next(self) -> Result<Self, WorkflowError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(WorkflowError::VersionOverflow)
    }

    fn validate(self) -> Result<(), WorkflowError> {
        if self.0 == 0 {
            return Err(WorkflowError::InvalidIdentifier);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StateRevision(u64);

impl StateRevision {
    pub fn new(value: u64) -> Result<Self, WorkflowError> {
        if value == 0 {
            return Err(WorkflowError::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, WorkflowError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(WorkflowError::StateRevisionOverflow)
    }

    fn validate(self) -> Result<(), WorkflowError> {
        if self.0 == 0 {
            return Err(WorkflowError::InvalidIdentifier);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecordRevision(i64);

impl RecordRevision {
    pub fn new(value: i64) -> Result<Self, WorkflowError> {
        if value <= 0 {
            return Err(WorkflowError::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    pub fn get(self) -> i64 {
        self.0
    }

    fn validate(self) -> Result<(), WorkflowError> {
        if self.0 <= 0 {
            return Err(WorkflowError::InvalidIdentifier);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntityId(String);

impl EntityId {
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowError> {
        Ok(Self(ValidatedToken::new(value, TokenKind::Entity)?.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        ValidatedToken::new(self.0.clone(), TokenKind::Entity).map(|_| ())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FieldId(String);

impl FieldId {
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowError> {
        Ok(Self(ValidatedToken::new(value, TokenKind::Field)?.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        ValidatedToken::new(self.0.clone(), TokenKind::Field).map(|_| ())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EffectId(String);

impl EffectId {
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowError> {
        Ok(Self(ValidatedToken::new(value, TokenKind::Effect)?.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        ValidatedToken::new(self.0.clone(), TokenKind::Effect).map(|_| ())
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecordId(String);

impl RecordId {
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowError> {
        Ok(Self(ValidatedToken::new(value, TokenKind::Record)?.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        ValidatedToken::new(self.0.clone(), TokenKind::Record).map(|_| ())
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TrustedActorRef(String);

impl TrustedActorRef {
    pub fn from_verified_context(value: impl Into<String>) -> Result<Self, WorkflowError> {
        Ok(Self(ValidatedToken::new(value, TokenKind::Actor)?.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        ValidatedToken::new(self.0.clone(), TokenKind::Actor).map(|_| ())
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TrustedTimestamp(String);

impl TrustedTimestamp {
    pub fn from_server_clock(value: impl Into<String>) -> Result<Self, WorkflowError> {
        Ok(Self(ValidatedToken::new(value, TokenKind::Timestamp)?.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        ValidatedToken::new(self.0.clone(), TokenKind::Timestamp).map(|_| ())
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContractFingerprint(String);

impl ContractFingerprint {
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowError> {
        Ok(Self(ValidatedToken::new(value, TokenKind::Digest)?.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        ValidatedToken::new(self.0.clone(), TokenKind::Digest).map(|_| ())
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PackageFingerprint(String);

impl PackageFingerprint {
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowError> {
        Ok(Self(ValidatedToken::new(value, TokenKind::Digest)?.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        ValidatedToken::new(self.0.clone(), TokenKind::Digest).map(|_| ())
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProposalDigest(String);

impl ProposalDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowError> {
        Ok(Self(ValidatedToken::new(value, TokenKind::Digest)?.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn matches(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        ValidatedToken::new(self.0.clone(), TokenKind::Digest).map(|_| ())
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApplicationId(String);

impl ApplicationId {
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowError> {
        Ok(Self(ValidatedToken::new(value, TokenKind::Application)?.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        ValidatedToken::new(self.0.clone(), TokenKind::Application).map(|_| ())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ValidatedToken(String);

impl ValidatedToken {
    fn new(value: impl Into<String>, kind: TokenKind) -> Result<Self, WorkflowError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_IDENTIFIER_BYTES
            || value.chars().any(|character| character.is_control())
        {
            return Err(match kind {
                TokenKind::Digest => WorkflowError::InvalidDigest,
                _ => WorkflowError::InvalidIdentifier,
            });
        }
        if kind == TokenKind::Digest && !value.starts_with("sha256:") {
            return Err(WorkflowError::InvalidDigest);
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind {
    Actor,
    Application,
    Digest,
    Effect,
    Entity,
    Field,
    Record,
    Stage,
    Timestamp,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
enum TargetIdentity {
    Existing {
        entity_id: EntityId,
        record_id: RecordId,
    },
    ReservedCreate {
        entity_id: EntityId,
        reserved_record_id: RecordId,
    },
}

impl TargetIdentity {
    fn record_key(&self) -> (EntityId, RecordId) {
        match self {
            Self::Existing {
                entity_id,
                record_id,
            } => (entity_id.clone(), record_id.clone()),
            Self::ReservedCreate {
                entity_id,
                reserved_record_id,
            } => (entity_id.clone(), reserved_record_id.clone()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedTargetState {
    Existing { base_revision: RecordRevision },
    ReservedCreate,
}

struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl fmt::Debug for RequestWorkflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestWorkflow")
            .field("request", &self.request)
            .field("owner", &Redacted)
            .field("state", &self.state)
            .field("current_version", &self.current_version)
            .field("workflow_revision", &self.workflow_revision)
            .field("proposal_count", &self.proposals.len())
            .field("decision_count", &self.decisions.len())
            .field("has_application", &self.application.is_some())
            .finish()
    }
}

impl fmt::Debug for PreparedProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedProposal")
            .field("request_record_revision", &Redacted)
            .field("contract_fingerprint", &Redacted)
            .field("originating_package", &Redacted)
            .field("stage_count", &self.stages.len())
            .field("effect_count", &self.effects.len())
            .field("combined_snapshot_bytes", &self.combined_snapshot_bytes)
            .finish()
    }
}

impl fmt::Debug for ProposalSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProposalSnapshot")
            .field("version", &self.version)
            .field("request_record_revision", &Redacted)
            .field("contract_fingerprint", &Redacted)
            .field("originating_package", &Redacted)
            .field("stage_count", &self.stages.len())
            .field("effect_count", &self.effects.len())
            .field("combined_snapshot_bytes", &self.combined_snapshot_bytes)
            .field("effect_digest", &Redacted)
            .field("submitted_by", &Redacted)
            .field("submitted_at", &Redacted)
            .finish()
    }
}

impl fmt::Debug for PreparedEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedEffect")
            .field("id", &self.id)
            .field("operation", &self.operation)
            .field("target", &self.target)
            .field("field_count", &self.field_changes.len())
            .finish()
    }
}

impl fmt::Debug for PreparedTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Existing { entity_id, .. } => formatter
                .debug_struct("Existing")
                .field("entity_id", entity_id)
                .field("record_id", &Redacted)
                .field("base_revision", &Redacted)
                .finish(),
            Self::ReservedCreate { entity_id, .. } => formatter
                .debug_struct("ReservedCreate")
                .field("entity_id", entity_id)
                .field("reserved_record_id", &Redacted)
                .finish(),
        }
    }
}

impl fmt::Debug for PreparedFieldChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedFieldChange")
            .field("field", &self.field)
            .field("before", &self.before)
            .field("after", &self.after)
            .finish()
    }
}

impl fmt::Debug for FieldValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("Missing"),
            Self::Present { .. } => formatter
                .debug_struct("Present")
                .field("value", &Redacted)
                .finish(),
        }
    }
}

impl fmt::Debug for TrustedTransitionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedTransitionContext")
            .field("actor", &Redacted)
            .field("now", &Redacted)
            .finish()
    }
}

impl fmt::Debug for ObservedTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Existing { entity_id, .. } => formatter
                .debug_struct("Existing")
                .field("entity_id", entity_id)
                .field("record_id", &Redacted)
                .field("current_revision", &Redacted)
                .finish(),
            Self::ReservedCreate { entity_id, .. } => formatter
                .debug_struct("ReservedCreate")
                .field("entity_id", entity_id)
                .field("reserved_record_id", &Redacted)
                .finish(),
        }
    }
}

impl fmt::Debug for PreparedApplication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedApplication")
            .field("application_id", &Redacted)
            .field("result_count", &self.result_links.len())
            .finish()
    }
}

impl fmt::Debug for ApplicationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationReceipt")
            .field("application_id", &Redacted)
            .field("version", &self.version)
            .field("effect_digest", &Redacted)
            .field("applied_by", &Redacted)
            .field("applied_at", &Redacted)
            .field("result_count", &self.result_links.len())
            .finish()
    }
}

impl fmt::Debug for ApplicationResultLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationResultLink")
            .field("entity_id", &self.entity_id)
            .field("record_id", &Redacted)
            .field("record_revision", &Redacted)
            .finish()
    }
}

impl fmt::Debug for WorkflowTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowTransition")
            .field("workflow", &self.workflow)
            .field("effect", &self.effect)
            .finish()
    }
}

impl fmt::Debug for TransitionEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submitted { version, .. } => formatter
                .debug_struct("Submitted")
                .field("version", version)
                .field("effect_digest", &Redacted)
                .finish(),
            Self::DecisionRecorded(decision) => formatter
                .debug_tuple("DecisionRecorded")
                .field(decision)
                .finish(),
            Self::DraftVersionStarted { version, reason } => formatter
                .debug_struct("DraftVersionStarted")
                .field("version", version)
                .field("reason", reason)
                .finish(),
            Self::Canceled => formatter.write_str("Canceled"),
            Self::Applied(receipt) => formatter.debug_tuple("Applied").field(receipt).finish(),
        }
    }
}

impl fmt::Debug for ReviewDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReviewDecision")
            .field("version", &self.version)
            .field("stage_id", &self.stage_id)
            .field("kind", &self.kind)
            .field("actor", &Redacted)
            .field("decided_at", &Redacted)
            .field("effect_digest", &Redacted)
            .finish()
    }
}

impl fmt::Debug for RequestKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestKey")
            .field("entity_id", &self.entity_id)
            .field("record_id", &Redacted)
            .finish()
    }
}

impl fmt::Debug for RecordId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecordId(<redacted>)")
    }
}

impl fmt::Debug for TrustedActorRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustedActorRef(<redacted>)")
    }
}

impl fmt::Debug for TrustedTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustedTimestamp(<redacted>)")
    }
}

impl fmt::Debug for ContractFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContractFingerprint(<redacted>)")
    }
}

impl fmt::Debug for PackageFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PackageFingerprint(<redacted>)")
    }
}

impl fmt::Debug for ProposalDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProposalDigest(<redacted>)")
    }
}

impl fmt::Debug for ApplicationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApplicationId(<redacted>)")
    }
}

#[derive(thiserror::Error, Clone, Debug, Eq, PartialEq)]
pub enum WorkflowError {
    #[error("request workflow transition is not valid from the current state")]
    InvalidTransition,
    #[error("proposal version is stale")]
    StaleProposalVersion,
    #[error("proposal digest does not match the frozen version")]
    DigestMismatch,
    #[error("proposal is unavailable")]
    ProposalUnavailable,
    #[error("review stage is not the next pending stage")]
    StageOutOfOrder,
    #[error("submitter cannot approve this stage")]
    SubmitterExcluded,
    #[error("actor already decided this stage for this proposal")]
    DuplicateDecision,
    #[error("proposal version overflow")]
    VersionOverflow,
    #[error("request workflow revision overflow")]
    StateRevisionOverflow,
    #[error("identifier is invalid")]
    InvalidIdentifier,
    #[error("digest is invalid")]
    InvalidDigest,
    #[error("proposal has no review stages")]
    NoReviewStages,
    #[error("review stage approval count is invalid")]
    InvalidApprovalCount,
    #[error("proposal has too many review stages")]
    TooManyStages,
    #[error("proposal has no effects")]
    EmptyProposal,
    #[error("effect has no field changes")]
    EmptyEffect,
    #[error("effect operation is unsupported")]
    UnsupportedOperation,
    #[error("effect operation does not match its target binding")]
    TargetOperationMismatch,
    #[error("proposal writes the same target field more than once")]
    OverlappingFieldWrite,
    #[error("proposal exceeds the target bound")]
    TooManyTargets,
    #[error("proposal exceeds the field mutation bound")]
    TooManyFieldMutations,
    #[error("proposal exceeds the snapshot byte bound")]
    SnapshotTooLarge,
    #[error("proposal canonicalization failed")]
    Canonicalization,
    #[error("set values cannot be JSON null")]
    NullSetValue,
    #[error("target binding does not match the frozen proposal")]
    TargetBindingMismatch,
    #[error("target revision differs from the frozen proposal base revision")]
    StaleTargetRevision,
    #[error("contract fingerprint differs from the frozen proposal")]
    ContractFingerprintMismatch,
    #[error("application receipt does not match the frozen proposal targets")]
    ApplicationReceiptMismatch,
    #[error("request has already been applied")]
    AlreadyApplied,
    #[error("restored request workflow state is inconsistent")]
    InvalidRestoredState,
}

fn validate_stages(stages: &[CompiledChangeRequestStage]) -> Result<(), WorkflowError> {
    if stages.is_empty() {
        return Err(WorkflowError::NoReviewStages);
    }
    if stages.len() > MAX_STAGES {
        return Err(WorkflowError::TooManyStages);
    }
    let mut ids = BTreeSet::new();
    for stage in stages {
        ValidatedToken::new(stage.id.clone(), TokenKind::Stage)?;
        if !ids.insert(stage.id.as_str()) {
            return Err(WorkflowError::InvalidIdentifier);
        }
        if stage.approvals == 0 || stage.approvals > MAX_APPROVALS_PER_STAGE {
            return Err(WorkflowError::InvalidApprovalCount);
        }
    }
    Ok(())
}

fn validate_effects(
    effects: &[PreparedEffect],
    combined_snapshot_bytes: usize,
) -> Result<(), WorkflowError> {
    if effects.is_empty() {
        return Err(WorkflowError::EmptyProposal);
    }
    let mut targets = BTreeSet::new();
    let mut target_states = BTreeMap::new();
    let mut field_writes = BTreeSet::new();
    for effect in effects {
        effect.validate_restored()?;
        let target = effect.target.identity();
        let (_, expected_state) = effect.target.expected_state();
        if let Some(existing) = target_states.insert(target.clone(), expected_state) {
            if existing != expected_state {
                return Err(WorkflowError::TargetBindingMismatch);
            }
        }
        targets.insert(target.clone());
        for change in &effect.field_changes {
            if !field_writes.insert((target.clone(), change.field.clone())) {
                return Err(WorkflowError::OverlappingFieldWrite);
            }
        }
    }
    if targets.len() > MAX_REQUEST_TARGETS {
        return Err(WorkflowError::TooManyTargets);
    }
    if field_writes.len() > MAX_REQUEST_FIELD_MUTATIONS {
        return Err(WorkflowError::TooManyFieldMutations);
    }
    let canonical_effects = canonicalize_json(
        &serde_json::to_value(effects).map_err(|_| WorkflowError::Canonicalization)?,
    )
    .map_err(|_| WorkflowError::Canonicalization)?;
    if combined_snapshot_bytes > MAX_REQUEST_SNAPSHOT_BYTES
        || canonical_effects.len() > combined_snapshot_bytes
    {
        return Err(WorkflowError::SnapshotTooLarge);
    }
    Ok(())
}

fn proposal_digest(
    request: &RequestKey,
    version: ProposalVersion,
    request_record_revision: RecordRevision,
    contract_fingerprint: &ContractFingerprint,
    originating_package: &PackageFingerprint,
    stages: &[CompiledChangeRequestStage],
    effects: &[PreparedEffect],
) -> Result<ProposalDigest, WorkflowError> {
    let value = json!({
        "schema": "registry-server.change-request.proposal.v1",
        "request": request,
        "version": version,
        "requestRecordRevision": request_record_revision,
        "contractFingerprint": contract_fingerprint,
        "originatingPackage": originating_package,
        "stages": stages,
        "effects": effects,
    });
    let canonical = canonicalize_json(&value).map_err(|_| WorkflowError::Canonicalization)?;
    ProposalDigest::new(format!("sha256:{}", hex_lower(&Sha256::digest(canonical))))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> RecordId {
        RecordId::new(value).expect("record id")
    }

    fn entity(value: &str) -> EntityId {
        EntityId::new(value).expect("entity id")
    }

    fn field(value: &str) -> FieldId {
        FieldId::new(value).expect("field id")
    }

    fn effect_id(value: &str) -> EffectId {
        EffectId::new(value).expect("effect id")
    }

    fn actor(value: &str) -> TrustedActorRef {
        TrustedActorRef::from_verified_context(value).expect("actor")
    }

    fn at(second: u8) -> TrustedTimestamp {
        TrustedTimestamp::from_server_clock(format!("2026-08-31T00:00:{second:02}Z"))
            .expect("timestamp")
    }

    fn context(actor_ref: &str, second: u8) -> TrustedTransitionContext {
        TrustedTransitionContext::from_verified_context(actor(actor_ref), at(second))
    }

    fn revision(value: i64) -> RecordRevision {
        RecordRevision::new(value).expect("record revision")
    }

    fn state_revision(value: u64) -> StateRevision {
        StateRevision::new(value).expect("state revision")
    }

    fn stages() -> Vec<CompiledChangeRequestStage> {
        vec![
            CompiledChangeRequestStage {
                id: "review".to_owned(),
                approvals: 2,
                exclude_submitter: true,
            },
            CompiledChangeRequestStage {
                id: "quality".to_owned(),
                approvals: 1,
                exclude_submitter: false,
            },
        ]
    }

    fn one_stage() -> Vec<CompiledChangeRequestStage> {
        vec![CompiledChangeRequestStage {
            id: "review".to_owned(),
            approvals: 1,
            exclude_submitter: true,
        }]
    }

    fn workflow() -> RequestWorkflow {
        RequestWorkflow::new_draft(
            RequestKey::new(entity("placement-correction-request"), id("request-1")),
            actor("submitter"),
            state_revision(1),
        )
    }

    fn patch_effect(after: &str, base_revision: i64) -> PreparedEffect {
        PreparedEffect::new(
            effect_id("patch-placement"),
            Operation::Patch,
            PreparedTarget::existing(
                entity("asset-placement"),
                id("placement-1"),
                revision(base_revision),
            ),
            vec![PreparedFieldChange::set(
                field("site"),
                FieldValue::present(json!("site-a")),
                json!(after),
            )
            .expect("field set")],
        )
        .expect("effect")
    }

    fn create_effect(effect: &str, target: &str, record: &str) -> PreparedEffect {
        PreparedEffect::new(
            effect_id(effect),
            Operation::Create,
            PreparedTarget::reserved_create(entity(target), id(record)),
            vec![PreparedFieldChange::set(
                field("display-name"),
                FieldValue::Missing,
                json!("Ada"),
            )
            .expect("field set")],
        )
        .expect("create effect")
    }

    fn proposal(
        effects: Vec<PreparedEffect>,
        stages: Vec<CompiledChangeRequestStage>,
    ) -> PreparedProposal {
        let canonical_len =
            canonicalize_json(&serde_json::to_value(&effects).expect("effects serialize"))
                .expect("effects canonicalize")
                .len();
        PreparedProposal::new(
            revision(7),
            ContractFingerprint::new("sha256:contract").expect("contract fingerprint"),
            PackageFingerprint::new("sha256:package").expect("package fingerprint"),
            stages,
            effects,
            canonical_len,
        )
        .expect("proposal")
    }

    fn submitted_one_stage() -> RequestWorkflow {
        workflow()
            .submit(
                context("submitter", 1),
                proposal(vec![patch_effect("site-b", 3)], one_stage()),
            )
            .expect("submit")
            .into_workflow()
    }

    fn approve_current(workflow: RequestWorkflow, actor_ref: &str, second: u8) -> RequestWorkflow {
        let digest = workflow
            .current_proposal()
            .expect("proposal")
            .effect_digest()
            .clone();
        let version = workflow.current_version();
        workflow
            .decide(
                context(actor_ref, second),
                "review",
                version,
                &digest,
                ReviewDecisionKind::Approve,
            )
            .expect("approve")
            .into_workflow()
    }

    #[test]
    fn submission_freezes_digest_and_rejects_digest_tampering() {
        let submitted = submitted_one_stage();
        let digest = submitted
            .current_proposal()
            .expect("proposal")
            .effect_digest()
            .clone();
        assert_eq!(submitted.state(), RequestState::Submitted);

        let tampered = proposal(vec![patch_effect("site-c", 3)], one_stage())
            .freeze(
                &RequestKey::new(entity("placement-correction-request"), id("request-1")),
                submitted.current_version(),
                context("submitter", 2),
            )
            .expect("tampered proposal")
            .effect_digest()
            .clone();
        assert_ne!(digest, tampered);

        let refused = submitted.decide(
            context("reviewer-a", 3),
            "review",
            ProposalVersion::first(),
            &tampered,
            ReviewDecisionKind::Approve,
        );
        assert_eq!(
            refused.expect_err("digest mismatch"),
            WorkflowError::DigestMismatch
        );
    }

    #[test]
    fn sequential_stages_require_distinct_actors_and_exclude_submitter() {
        let submitted = workflow()
            .submit(
                context("submitter", 1),
                proposal(vec![patch_effect("site-b", 3)], stages()),
            )
            .expect("submit")
            .into_workflow();
        let digest = submitted
            .current_proposal()
            .expect("proposal")
            .effect_digest()
            .clone();

        let self_approval = submitted.clone().decide(
            context("submitter", 2),
            "review",
            ProposalVersion::first(),
            &digest,
            ReviewDecisionKind::Approve,
        );
        assert_eq!(
            self_approval.expect_err("self approval refused"),
            WorkflowError::SubmitterExcluded
        );

        let stage_skip = submitted.clone().decide(
            context("reviewer-a", 3),
            "quality",
            ProposalVersion::first(),
            &digest,
            ReviewDecisionKind::Approve,
        );
        assert_eq!(
            stage_skip.expect_err("stage order refused"),
            WorkflowError::StageOutOfOrder
        );

        let after_first = submitted
            .decide(
                context("reviewer-a", 4),
                "review",
                ProposalVersion::first(),
                &digest,
                ReviewDecisionKind::Approve,
            )
            .expect("first approval")
            .into_workflow();
        assert_eq!(after_first.state(), RequestState::Submitted);

        let duplicate = after_first.clone().decide(
            context("reviewer-a", 5),
            "review",
            ProposalVersion::first(),
            &digest,
            ReviewDecisionKind::Approve,
        );
        assert_eq!(
            duplicate.expect_err("duplicate refused"),
            WorkflowError::DuplicateDecision
        );

        let after_second = after_first
            .decide(
                context("reviewer-b", 6),
                "review",
                ProposalVersion::first(),
                &digest,
                ReviewDecisionKind::Approve,
            )
            .expect("second approval")
            .into_workflow();
        assert_eq!(after_second.state(), RequestState::Submitted);

        let approved = after_second
            .decide(
                context("submitter", 7),
                "quality",
                ProposalVersion::first(),
                &digest,
                ReviewDecisionKind::Approve,
            )
            .expect("quality approval")
            .into_workflow();
        assert_eq!(approved.state(), RequestState::Approved);
    }

    #[test]
    fn revision_starts_a_new_version_and_old_decisions_cannot_apply() {
        let submitted = submitted_one_stage();
        let digest = submitted
            .current_proposal()
            .expect("proposal")
            .effect_digest()
            .clone();
        let needs_changes = submitted
            .decide(
                context("reviewer-a", 2),
                "review",
                ProposalVersion::first(),
                &digest,
                ReviewDecisionKind::RequestRevision,
            )
            .expect("request revision")
            .into_workflow();
        assert_eq!(needs_changes.state(), RequestState::NeedsChanges);

        let draft = needs_changes
            .revise(context("submitter", 3))
            .expect("revise")
            .into_workflow();
        assert_eq!(draft.state(), RequestState::Draft);
        assert_eq!(draft.current_version().get(), 2);

        let resubmitted = draft
            .submit(
                context("submitter", 4),
                proposal(vec![patch_effect("site-c", 4)], one_stage()),
            )
            .expect("resubmit")
            .into_workflow();
        let stale = resubmitted.decide(
            context("reviewer-b", 5),
            "review",
            ProposalVersion::first(),
            &digest,
            ReviewDecisionKind::Approve,
        );
        assert_eq!(
            stale.expect_err("old version refused"),
            WorkflowError::StaleProposalVersion
        );
    }

    #[test]
    fn apply_requires_approved_digest_contract_and_current_target_revisions() {
        let approved = approve_current(submitted_one_stage(), "reviewer-a", 2);
        assert_eq!(approved.state(), RequestState::Approved);
        let proposal = approved.current_proposal().expect("proposal");
        let digest = proposal.effect_digest().clone();
        let contract = proposal.contract_fingerprint().clone();

        let stale = approved.clone().apply(
            context("applier", 3),
            ProposalVersion::first(),
            &digest,
            &contract,
            vec![ObservedTarget::existing(
                entity("asset-placement"),
                id("placement-1"),
                revision(4),
            )],
            PreparedApplication::new(
                ApplicationId::new("application-1").expect("application id"),
                vec![ApplicationResultLink::new(
                    entity("asset-placement"),
                    id("placement-1"),
                    revision(5),
                )],
            )
            .expect("application"),
        );
        assert_eq!(
            stale.expect_err("stale target refused"),
            WorkflowError::StaleTargetRevision
        );

        let wrong_contract = approved.clone().apply(
            context("applier", 4),
            ProposalVersion::first(),
            &digest,
            &ContractFingerprint::new("sha256:changed").expect("contract fingerprint"),
            vec![ObservedTarget::existing(
                entity("asset-placement"),
                id("placement-1"),
                revision(3),
            )],
            PreparedApplication::new(
                ApplicationId::new("application-1").expect("application id"),
                vec![ApplicationResultLink::new(
                    entity("asset-placement"),
                    id("placement-1"),
                    revision(5),
                )],
            )
            .expect("application"),
        );
        assert_eq!(
            wrong_contract.expect_err("contract mismatch refused"),
            WorkflowError::ContractFingerprintMismatch
        );

        let mut tampered = approved.clone();
        tampered
            .proposals
            .get_mut(&ProposalVersion::first())
            .expect("proposal")
            .effects[0]
            .field_changes[0]
            .after = FieldValue::present(json!("site-tampered"));
        let tampered_apply = tampered.apply(
            context("applier", 5),
            ProposalVersion::first(),
            &digest,
            &contract,
            vec![ObservedTarget::existing(
                entity("asset-placement"),
                id("placement-1"),
                revision(3),
            )],
            PreparedApplication::new(
                ApplicationId::new("application-1").expect("application id"),
                vec![ApplicationResultLink::new(
                    entity("asset-placement"),
                    id("placement-1"),
                    revision(5),
                )],
            )
            .expect("application"),
        );
        assert_eq!(
            tampered_apply.expect_err("tampered effects refused"),
            WorkflowError::DigestMismatch
        );

        let applied = approved
            .apply(
                context("applier", 6),
                ProposalVersion::first(),
                &digest,
                &contract,
                vec![ObservedTarget::existing(
                    entity("asset-placement"),
                    id("placement-1"),
                    revision(3),
                )],
                PreparedApplication::new(
                    ApplicationId::new("application-1").expect("application id"),
                    vec![ApplicationResultLink::new(
                        entity("asset-placement"),
                        id("placement-1"),
                        revision(5),
                    )],
                )
                .expect("application"),
            )
            .expect("apply")
            .into_workflow();
        assert_eq!(applied.state(), RequestState::Applied);
        assert!(applied.application().is_some());
        assert_eq!(
            applied
                .cancel(context("applier", 7))
                .expect_err("applied cannot cancel"),
            WorkflowError::InvalidTransition
        );
    }

    #[test]
    fn bounds_and_overlapping_field_writes_are_refused_before_submission() {
        let duplicate_field = PreparedEffect::new(
            effect_id("patch-placement"),
            Operation::Patch,
            PreparedTarget::existing(entity("asset-placement"), id("placement-1"), revision(3)),
            vec![
                PreparedFieldChange::set(
                    field("site"),
                    FieldValue::present(json!("a")),
                    json!("b"),
                )
                .expect("field set"),
                PreparedFieldChange::clear(field("site"), FieldValue::present(json!("a"))),
            ],
        );
        assert_eq!(
            duplicate_field.expect_err("duplicate field refused"),
            WorkflowError::OverlappingFieldWrite
        );

        let too_many_targets = (0..=MAX_REQUEST_TARGETS)
            .map(|index| {
                create_effect(
                    &format!("person-{index}"),
                    "person",
                    &format!("person-{index}"),
                )
            })
            .collect::<Vec<_>>();
        let refused = PreparedProposal::new(
            revision(7),
            ContractFingerprint::new("sha256:contract").expect("contract fingerprint"),
            PackageFingerprint::new("sha256:package").expect("package fingerprint"),
            one_stage(),
            too_many_targets,
            MAX_REQUEST_SNAPSHOT_BYTES,
        );
        assert_eq!(
            refused.expect_err("target bound refused"),
            WorkflowError::TooManyTargets
        );

        let null_set = PreparedFieldChange::set(field("site"), FieldValue::Missing, Value::Null);
        assert_eq!(
            null_set.expect_err("null set refused"),
            WorkflowError::NullSetValue
        );
    }

    #[test]
    fn disjoint_writes_to_one_target_must_share_one_base_revision() {
        let first = PreparedEffect::new(
            effect_id("patch-site"),
            Operation::Patch,
            PreparedTarget::existing(entity("asset-placement"), id("placement-1"), revision(3)),
            vec![PreparedFieldChange::set(
                field("site"),
                FieldValue::present(json!("a")),
                json!("b"),
            )
            .expect("field set")],
        )
        .expect("first effect");
        let second = PreparedEffect::new(
            effect_id("patch-label"),
            Operation::Patch,
            PreparedTarget::existing(entity("asset-placement"), id("placement-1"), revision(4)),
            vec![PreparedFieldChange::set(
                field("label"),
                FieldValue::present(json!("old")),
                json!("new"),
            )
            .expect("field set")],
        )
        .expect("second effect");

        let refused = PreparedProposal::new(
            revision(7),
            ContractFingerprint::new("sha256:contract").expect("contract fingerprint"),
            PackageFingerprint::new("sha256:package").expect("package fingerprint"),
            one_stage(),
            vec![first, second],
            MAX_REQUEST_SNAPSHOT_BYTES,
        );
        assert_eq!(
            refused.expect_err("base mismatch refused"),
            WorkflowError::TargetBindingMismatch
        );
    }

    #[test]
    fn debug_output_redacts_values_principals_and_record_ids() {
        let submitted = submitted_one_stage();
        let debug = format!("{submitted:?}");

        assert!(!debug.contains("submitter"));
        assert!(!debug.contains("request-1"));
        assert!(!debug.contains("placement-1"));
        assert!(!debug.contains("site-a"));
        assert!(!debug.contains("site-b"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn restored_workflow_revalidates_versions_state_and_digests() {
        let submitted = submitted_one_stage();
        let encoded = serde_json::to_value(&submitted).expect("workflow serializes");
        let restored = serde_json::from_value::<RequestWorkflow>(encoded.clone())
            .expect("workflow deserializes")
            .validate_restored()
            .expect("valid workflow restores");
        assert_eq!(restored.state(), RequestState::Submitted);

        let mut zero_version = encoded.clone();
        zero_version["currentVersion"] = json!(0);
        let refused = serde_json::from_value::<RequestWorkflow>(zero_version)
            .expect("serde accepts raw zero version")
            .validate_restored();
        assert_eq!(
            refused.expect_err("zero version refused"),
            WorkflowError::InvalidIdentifier
        );

        let mut bad_digest = encoded.clone();
        let proposal = bad_digest["proposals"]
            .as_object_mut()
            .expect("proposal map")
            .values_mut()
            .next()
            .expect("proposal");
        proposal["effectDigest"] = json!("sha256:bad");
        let refused = serde_json::from_value::<RequestWorkflow>(bad_digest)
            .expect("serde accepts raw digest")
            .validate_restored();
        assert_eq!(
            refused.expect_err("digest revalidation refused"),
            WorkflowError::DigestMismatch
        );

        let mut unsupported_operation = encoded;
        let proposal = unsupported_operation["proposals"]
            .as_object_mut()
            .expect("proposal map")
            .values_mut()
            .next()
            .expect("proposal");
        proposal["effects"][0]["operation"] = json!("list");
        let refused = serde_json::from_value::<RequestWorkflow>(unsupported_operation)
            .expect("serde accepts raw unsupported operation")
            .validate_restored();
        assert_eq!(
            refused.expect_err("unsupported restored operation refused"),
            WorkflowError::UnsupportedOperation
        );
    }

    #[test]
    fn restored_terminal_state_must_match_application_and_review_facts() {
        let approved = approve_current(submitted_one_stage(), "reviewer-a", 2);
        let mut encoded = serde_json::to_value(&approved).expect("workflow serializes");
        encoded["state"] = json!("applied");
        let refused = serde_json::from_value::<RequestWorkflow>(encoded)
            .expect("serde accepts inconsistent applied state")
            .validate_restored();
        assert_eq!(
            refused.expect_err("missing application refused"),
            WorkflowError::InvalidRestoredState
        );

        let proposal = approved.current_proposal().expect("proposal");
        let digest = proposal.effect_digest().clone();
        let contract = proposal.contract_fingerprint().clone();
        let applied = approved
            .apply(
                context("applier", 3),
                ProposalVersion::new(1).expect("version"),
                &digest,
                &contract,
                vec![ObservedTarget::existing(
                    entity("asset-placement"),
                    id("placement-1"),
                    revision(3),
                )],
                PreparedApplication::new(
                    ApplicationId::new("application-1").expect("application id"),
                    vec![ApplicationResultLink::new(
                        entity("asset-placement"),
                        id("placement-1"),
                        revision(5),
                    )],
                )
                .expect("application"),
            )
            .expect("apply")
            .into_workflow();
        let restored = serde_json::from_value::<RequestWorkflow>(
            serde_json::to_value(&applied).expect("workflow serializes"),
        )
        .expect("workflow deserializes")
        .validate_restored()
        .expect("applied workflow restores");
        assert_eq!(restored.state(), RequestState::Applied);
        assert_eq!(
            restored.application().expect("application").result_links()[0]
                .record_revision()
                .get(),
            5
        );
    }

    #[test]
    fn restored_draft_after_revision_may_omit_historical_proposals() {
        let submitted = submitted_one_stage();
        let digest = submitted
            .current_proposal()
            .expect("proposal")
            .effect_digest()
            .clone();
        let draft = submitted
            .decide(
                context("reviewer-a", 2),
                "review",
                ProposalVersion::first(),
                &digest,
                ReviewDecisionKind::RequestRevision,
            )
            .expect("request revision")
            .into_workflow()
            .revise(context("submitter", 3))
            .expect("revise")
            .into_workflow();
        let mut encoded = serde_json::to_value(&draft).expect("workflow serializes");
        encoded["proposals"] = json!({});
        encoded["decisions"] = json!([]);

        let restored = serde_json::from_value::<RequestWorkflow>(encoded)
            .expect("workflow deserializes")
            .validate_restored()
            .expect("current draft restores without historical snapshots");
        assert_eq!(restored.state(), RequestState::Draft);
        assert_eq!(restored.current_version().get(), 2);
    }
}

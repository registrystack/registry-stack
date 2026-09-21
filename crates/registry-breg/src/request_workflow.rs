// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use registry_platform_canonical_json::canonicalize_json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::contract::Operation;
/// Maximum Unicode characters in a source-supplied application reason.
pub const MAX_APPLICATION_REASON_CHARS: usize = 4096;

pub fn valid_application_reason(reason: &str) -> bool {
    !reason.contains('\0') && reason.chars().count() <= MAX_APPLICATION_REASON_CHARS
}

pub const MAX_REQUEST_TARGETS: usize = 16;
pub const MAX_REQUEST_FIELD_MUTATIONS: usize = 128;
/// Internal proposal and target snapshots retain unchanged encrypted members
/// as tagged base64 envelopes. Keep the authored/plaintext admission ceiling
/// at 2 MiB, but give the stored packet the same deterministic expansion
/// headroom as revision snapshots.
pub const MAX_REQUEST_SNAPSHOT_BYTES: usize = crate::history_schema::MAX_HISTORY_SNAPSHOT_BYTES;

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
        application: Option<ApplicationReceipt>,
    ) -> Result<Self, WorkflowError> {
        Self {
            request,
            owner,
            state,
            current_version,
            workflow_revision,
            proposals,
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
        let review_requirement = proposal.review_requirement().clone();
        self.proposals.insert(version, proposal);
        self.state = RequestState::Submitted;
        self.workflow_revision = self.workflow_revision.next()?;
        Ok(WorkflowTransition {
            workflow: self,
            effect: TransitionEffect::Submitted {
                version,
                effect_digest,
                review_requirement,
            },
        })
    }

    pub fn revise(
        mut self,
        _context: TrustedTransitionContext,
    ) -> Result<WorkflowTransition, WorkflowError> {
        if self.state != RequestState::Submitted {
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
        if self.state != RequestState::Submitted {
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
        context: TrustedTransitionContext,
    ) -> Result<WorkflowTransition, WorkflowError> {
        if context.actor != self.owner {
            return Err(WorkflowError::NotOwner);
        }
        if matches!(self.state, RequestState::Applied | RequestState::Cancelled) {
            return Err(WorkflowError::InvalidTransition);
        }
        self.state = RequestState::Cancelled;
        self.workflow_revision = self.workflow_revision.next()?;
        Ok(WorkflowTransition {
            workflow: self,
            effect: TransitionEffect::Cancelled,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply(
        mut self,
        context: TrustedTransitionContext,
        version: ProposalVersion,
        displayed_digest: &ProposalDigest,
        contract_fingerprint: &ContractFingerprint,
        review_evidence: Option<&crate::review_integration::AcceptedReviewEvidence>,
        observed_targets: Vec<ObservedTarget>,
        application: PreparedApplication,
        reason: Option<String>,
    ) -> Result<WorkflowTransition, WorkflowError> {
        if reason
            .as_deref()
            .is_some_and(|reason| !valid_application_reason(reason))
        {
            return Err(WorkflowError::InvalidApplicationReason);
        }
        if self.state != RequestState::Submitted {
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
        match proposal.review_requirement() {
            crate::model::CompiledChangeRequestReview::None(_) if review_evidence.is_none() => {}
            crate::model::CompiledChangeRequestReview::Required(requirement)
                if review_evidence.is_some_and(|evidence| {
                    evidence.matches_proposal(
                        &requirement.authority,
                        &requirement.policy_id,
                        self.request.record_id().as_str(),
                        version.get(),
                        proposal.effect_digest().as_str(),
                    )
                }) => {}
            _ => return Err(WorkflowError::ReviewEvidenceMismatch),
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
            reason_present: reason.is_some(),
            reason,
        };
        self.state = RequestState::Applied;
        self.workflow_revision = self.workflow_revision.next()?;
        self.application = Some(receipt.clone());
        Ok(WorkflowTransition {
            workflow: self,
            effect: TransitionEffect::Applied(receipt),
        })
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

        self.validate_restored_application()?;
        self.validate_restored_state()
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
        match self.state {
            RequestState::Draft => {
                if current_proposal.is_some() || self.application.is_some() {
                    return Err(WorkflowError::InvalidRestoredState);
                }
            }
            RequestState::Submitted => {
                if current_proposal.is_none() || self.application.is_some() {
                    return Err(WorkflowError::InvalidRestoredState);
                }
            }
            RequestState::Cancelled | RequestState::Superseded => {
                if self.application.is_some() {
                    return Err(WorkflowError::InvalidRestoredState);
                }
            }
            RequestState::Applied => {
                if current_proposal.is_none() || self.application.is_none() {
                    return Err(WorkflowError::InvalidRestoredState);
                }
            }
        }
        Ok(())
    }
}

/// Exact review binding copied into the immutable proposal snapshot.
pub type FrozenReviewRequirement = crate::model::CompiledChangeRequestReview;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrozenPlannerKind {
    Declarative,
    Rhai,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FrozenPlanningBinding {
    kind: FrozenPlannerKind,
    abi_identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    script_digest: Option<ProposalDigest>,
}

impl FrozenPlanningBinding {
    pub fn new(
        kind: FrozenPlannerKind,
        abi_identifier: impl Into<String>,
        script_digest: Option<ProposalDigest>,
    ) -> Result<Self, WorkflowError> {
        let binding = Self {
            kind,
            abi_identifier: abi_identifier.into(),
            script_digest,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn kind(&self) -> FrozenPlannerKind {
        self.kind
    }

    pub fn abi_identifier(&self) -> &str {
        &self.abi_identifier
    }

    pub fn script_digest(&self) -> Option<&ProposalDigest> {
        self.script_digest.as_ref()
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        if self.abi_identifier != "registry.change-request-plan/v1"
            || matches!(self.kind, FrozenPlannerKind::Rhai) != self.script_digest.is_some()
        {
            return Err(WorkflowError::InvalidPlanningBinding);
        }
        if let Some(digest) = &self.script_digest {
            digest.validate()?;
        }
        Ok(())
    }
}

/// Immutable value-free attachment binding retained in a proposal digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttachmentManifestEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_policy: Option<String>,
    pub sha256: String,
    pub content_type: String,
    pub byte_size: u64,
}

fn validate_attachment_manifest(
    manifest: &BTreeMap<String, AttachmentManifestEntry>,
) -> Result<(), WorkflowError> {
    if manifest.len() > crate::contract::MAX_ATTACHMENT_SLOTS {
        return Err(WorkflowError::InvalidRestoredState);
    }
    for (slot, entry) in manifest {
        if slot.is_empty()
            || slot.len() > 128
            || slot.chars().any(char::is_control)
            || entry.sha256.len() != 64
            || !entry
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || entry.content_type.is_empty()
            || entry.content_type.len() > 255
            || entry.content_type.chars().any(char::is_control)
            || entry.byte_size > u64::from(crate::contract::MAX_ATTACHMENT_BYTES)
            || entry.verification_policy.as_ref().is_some_and(|policy| {
                policy.is_empty()
                    || policy == "disabled"
                    || policy.len() > 1024
                    || policy.chars().any(char::is_control)
            })
        {
            return Err(WorkflowError::InvalidRestoredState);
        }
    }
    Ok(())
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FrozenApplicationPreconditions {
    pub contract: crate::model::CompiledChangeRequestPreconditions,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub request_values: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<FrozenGuardTargetSnapshot>,
}

impl FrozenApplicationPreconditions {
    pub fn validate(&self) -> Result<(), WorkflowError> {
        if self.contract.is_empty()
            || self.targets.len() != self.contract.targets.len()
            || self.targets.len() > MAX_REQUEST_TARGETS
        {
            return Err(WorkflowError::InvalidRestoredState);
        }
        let expected_ids = self
            .contract
            .targets
            .iter()
            .map(|target| target.id.as_str())
            .collect::<BTreeSet<_>>();
        let actual_ids = self
            .targets
            .iter()
            .map(|target| target.id.as_str())
            .collect::<BTreeSet<_>>();
        if expected_ids != actual_ids || actual_ids.len() != self.targets.len() {
            return Err(WorkflowError::InvalidRestoredState);
        }
        let mut expected_request_fields = BTreeSet::new();
        for predicate in &self.contract.request {
            expected_request_fields.insert(predicate.field.as_str());
            if let crate::model::CompiledChangeRequestPredicateExpected::RequestField { field } =
                &predicate.expected
            {
                expected_request_fields.insert(field);
            }
        }
        for target in &self.contract.targets {
            expected_request_fields.insert(target.from_field.as_str());
            for predicate in &target.requires {
                if let crate::model::CompiledChangeRequestPredicateExpected::RequestField {
                    field,
                } = &predicate.expected
                {
                    expected_request_fields.insert(field);
                }
            }
        }
        for evidence in &self.contract.evidence {
            for selector in evidence
                .subjects
                .values()
                .flat_map(|subject| subject.selectors.values())
            {
                if let crate::model::CompiledChangeRequestSelector::RequestField { field } =
                    selector
                {
                    expected_request_fields.insert(field);
                }
            }
            for requirement in &evidence.requires {
                if let crate::model::CompiledChangeRequestEvidenceExpected::RequestField { field } =
                    &requirement.expected
                {
                    expected_request_fields.insert(field);
                }
            }
        }
        if expected_request_fields
            != self
                .request_values
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
        {
            return Err(WorkflowError::InvalidRestoredState);
        }
        for target in &self.targets {
            target.validate()?;
            let compiled = self
                .contract
                .targets
                .iter()
                .find(|candidate| candidate.id == target.id)
                .ok_or(WorkflowError::InvalidRestoredState)?;
            if compiled.entity_id != target.entity_id {
                return Err(WorkflowError::InvalidRestoredState);
            }
            let expected_fields = compiled
                .requires
                .iter()
                .map(|predicate| predicate.field.as_str())
                .chain(
                    self.contract
                        .evidence
                        .iter()
                        .flat_map(|evidence| evidence.subjects.values())
                        .flat_map(|subject| subject.selectors.values())
                        .filter_map(|selector| match selector {
                            crate::model::CompiledChangeRequestSelector::TargetField {
                                target: selector_target,
                                field,
                            } if selector_target == &target.id => Some(field.as_str()),
                            _ => None,
                        }),
                )
                .collect::<BTreeSet<_>>();
            if expected_fields
                != target
                    .values
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>()
            {
                return Err(WorkflowError::InvalidRestoredState);
            }
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FrozenGuardTargetSnapshot {
    pub id: String,
    pub entity_id: String,
    pub record_id: RecordId,
    pub expected_revision: i64,
    pub values: BTreeMap<String, serde_json::Value>,
}

impl FrozenGuardTargetSnapshot {
    fn validate(&self) -> Result<(), WorkflowError> {
        if self.id.is_empty()
            || self.entity_id.is_empty()
            || self.expected_revision <= 0
            || self.values.is_empty()
        {
            return Err(WorkflowError::InvalidRestoredState);
        }
        self.record_id.validate()?;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PreparedProposal {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    attachments: BTreeMap<String, AttachmentManifestEntry>,
    request_record_revision: RecordRevision,
    contract_fingerprint: ContractFingerprint,
    originating_package: PackageFingerprint,
    effects: Vec<PreparedEffect>,
    combined_snapshot_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    planning_binding: Option<FrozenPlanningBinding>,
    review_requirement: FrozenReviewRequirement,
    #[serde(default)]
    on_approved: crate::model::CompiledChangeRequestOnApproved,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application_preconditions: Option<FrozenApplicationPreconditions>,
}

impl PreparedProposal {
    pub fn new_with_binding(
        request_record_revision: RecordRevision,
        contract_fingerprint: ContractFingerprint,
        originating_package: PackageFingerprint,
        review_requirement: FrozenReviewRequirement,
        planning_binding: FrozenPlanningBinding,
        effects: Vec<PreparedEffect>,
        combined_snapshot_bytes: usize,
    ) -> Result<Self, WorkflowError> {
        planning_binding.validate()?;
        validate_effects(&effects, combined_snapshot_bytes)?;
        Ok(Self {
            request_record_revision,
            contract_fingerprint,
            originating_package,
            effects,
            combined_snapshot_bytes,
            planning_binding: Some(planning_binding),
            review_requirement,
            on_approved: crate::model::CompiledChangeRequestOnApproved::default(),
            attachments: BTreeMap::new(),
            application_preconditions: None,
        })
    }

    pub fn with_application_preconditions(
        mut self,
        preconditions: FrozenApplicationPreconditions,
    ) -> Result<Self, WorkflowError> {
        preconditions.validate()?;
        let canonical = canonicalize_json(
            &serde_json::to_value(&preconditions).map_err(|_| WorkflowError::Canonicalization)?,
        )
        .map_err(|_| WorkflowError::Canonicalization)?;
        self.combined_snapshot_bytes = self
            .combined_snapshot_bytes
            .checked_add(canonical.len())
            .filter(|bytes| *bytes <= MAX_REQUEST_SNAPSHOT_BYTES)
            .ok_or(WorkflowError::SnapshotTooLarge)?;
        self.application_preconditions = Some(preconditions);
        Ok(self)
    }

    pub fn with_on_approved(
        mut self,
        on_approved: crate::model::CompiledChangeRequestOnApproved,
    ) -> Result<Self, WorkflowError> {
        crate::review_integration::validate_application_binding(
            on_approved.mode,
            on_approved.executor.as_deref(),
        )
        .map_err(|_| WorkflowError::InvalidRestoredState)?;
        self.on_approved = on_approved;
        Ok(self)
    }

    /// Binds exact evidence bytes and media interpretation to this proposal.
    pub fn with_attachments(
        mut self,
        attachments: BTreeMap<String, AttachmentManifestEntry>,
    ) -> Result<Self, WorkflowError> {
        validate_attachment_manifest(&attachments)?;
        self.attachments = attachments;
        Ok(self)
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

    pub fn effects(&self) -> &[PreparedEffect] {
        &self.effects
    }

    pub fn combined_snapshot_bytes(&self) -> usize {
        self.combined_snapshot_bytes
    }

    pub fn planning_binding(&self) -> Option<&FrozenPlanningBinding> {
        self.planning_binding.as_ref()
    }

    pub fn review_requirement(&self) -> &FrozenReviewRequirement {
        &self.review_requirement
    }

    pub fn on_approved(&self) -> &crate::model::CompiledChangeRequestOnApproved {
        &self.on_approved
    }

    pub fn application_preconditions(&self) -> Option<&FrozenApplicationPreconditions> {
        self.application_preconditions.as_ref()
    }

    fn freeze(
        self,
        request: &RequestKey,
        version: ProposalVersion,
        context: TrustedTransitionContext,
    ) -> Result<ProposalSnapshot, WorkflowError> {
        validate_attachment_manifest(&self.attachments)?;
        let effect_digest = proposal_digest(ProposalDigestInput {
            request,
            version,
            request_record_revision: self.request_record_revision,
            contract_fingerprint: &self.contract_fingerprint,
            originating_package: &self.originating_package,
            effects: &self.effects,
            planning_binding: self.planning_binding.as_ref(),
            review_requirement: &self.review_requirement,
            on_approved: &self.on_approved,
            attachments: &self.attachments,
            application_preconditions: self.application_preconditions.as_ref(),
        })?;
        Ok(ProposalSnapshot {
            version,
            request_record_revision: self.request_record_revision,
            contract_fingerprint: self.contract_fingerprint,
            originating_package: self.originating_package,
            effects: self.effects,
            combined_snapshot_bytes: self.combined_snapshot_bytes,
            planning_binding: self.planning_binding,
            review_requirement: self.review_requirement,
            on_approved: self.on_approved,
            application_preconditions: self.application_preconditions,
            effect_digest,
            attachments: self.attachments,
            submitted_by: context.actor,
            submitted_at: context.now,
        })
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProposalSnapshot {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    attachments: BTreeMap<String, AttachmentManifestEntry>,
    version: ProposalVersion,
    request_record_revision: RecordRevision,
    contract_fingerprint: ContractFingerprint,
    originating_package: PackageFingerprint,
    effects: Vec<PreparedEffect>,
    combined_snapshot_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    planning_binding: Option<FrozenPlanningBinding>,
    review_requirement: FrozenReviewRequirement,
    #[serde(default)]
    on_approved: crate::model::CompiledChangeRequestOnApproved,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application_preconditions: Option<FrozenApplicationPreconditions>,
    effect_digest: ProposalDigest,
    submitted_by: TrustedActorRef,
    submitted_at: TrustedTimestamp,
}

impl ProposalSnapshot {
    pub fn attachments(&self) -> &BTreeMap<String, AttachmentManifestEntry> {
        &self.attachments
    }

    pub fn version(&self) -> ProposalVersion {
        self.version
    }

    pub fn request_record_revision(&self) -> RecordRevision {
        self.request_record_revision
    }

    pub fn effect_digest(&self) -> &ProposalDigest {
        &self.effect_digest
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

    pub fn planning_binding(&self) -> Option<&FrozenPlanningBinding> {
        self.planning_binding.as_ref()
    }

    pub fn review_requirement(&self) -> &FrozenReviewRequirement {
        &self.review_requirement
    }

    pub fn on_approved(&self) -> &crate::model::CompiledChangeRequestOnApproved {
        &self.on_approved
    }

    pub fn application_preconditions(&self) -> Option<&FrozenApplicationPreconditions> {
        self.application_preconditions.as_ref()
    }

    pub fn submitted_by(&self) -> &TrustedActorRef {
        &self.submitted_by
    }

    pub fn submitted_at(&self) -> &TrustedTimestamp {
        &self.submitted_at
    }

    pub fn verify_digest(&self, request: &RequestKey) -> Result<(), WorkflowError> {
        let actual = proposal_digest(ProposalDigestInput {
            request,
            version: self.version,
            request_record_revision: self.request_record_revision,
            contract_fingerprint: &self.contract_fingerprint,
            originating_package: &self.originating_package,
            effects: &self.effects,
            planning_binding: self.planning_binding.as_ref(),
            review_requirement: &self.review_requirement,
            on_approved: &self.on_approved,
            attachments: &self.attachments,
            application_preconditions: self.application_preconditions.as_ref(),
        })?;
        if actual.matches(&self.effect_digest) {
            Ok(())
        } else {
            Err(WorkflowError::DigestMismatch)
        }
    }

    fn validate_restored(&self, request: &RequestKey) -> Result<(), WorkflowError> {
        self.version.validate()?;
        validate_attachment_manifest(&self.attachments)?;
        self.request_record_revision.validate()?;
        self.contract_fingerprint.validate()?;
        self.originating_package.validate()?;
        self.planning_binding
            .as_ref()
            .ok_or(WorkflowError::InvalidRestoredState)?
            .validate()?;
        if let Some(preconditions) = &self.application_preconditions {
            if self.planning_binding.is_none() {
                return Err(WorkflowError::InvalidRestoredState);
            }
            preconditions.validate()?;
        }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default)]
    reason_present: bool,
}

impl ApplicationReceipt {
    #[cfg(feature = "runtime")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn restore(
        application_id: ApplicationId,
        version: ProposalVersion,
        effect_digest: ProposalDigest,
        applied_by: TrustedActorRef,
        applied_at: TrustedTimestamp,
        result_links: Vec<ApplicationResultLink>,
        reason: Option<String>,
        reason_present: bool,
    ) -> Result<Self, WorkflowError> {
        let receipt = Self {
            application_id,
            version,
            effect_digest,
            applied_by,
            applied_at,
            result_links,
            reason,
            reason_present,
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

    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    pub fn reason_present(&self) -> bool {
        self.reason_present
    }

    fn validate(&self) -> Result<(), WorkflowError> {
        if self
            .reason
            .as_deref()
            .is_some_and(|reason| !valid_application_reason(reason))
            || (self.reason.is_some() && !self.reason_present)
        {
            return Err(WorkflowError::InvalidApplicationReason);
        }
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
        review_requirement: FrozenReviewRequirement,
    },
    DraftVersionStarted {
        version: ProposalVersion,
        reason: DraftStartReason,
    },
    Cancelled,
    Applied(ApplicationReceipt),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DraftStartReason {
    Revision,
    Rebase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestState {
    Draft,
    Submitted,
    Cancelled,
    Applied,
    Superseded,
}

#[cfg(feature = "runtime")]
impl RequestState {
    pub(crate) fn from_storage(value: &str) -> Result<Self, WorkflowError> {
        match value {
            "draft" => Ok(Self::Draft),
            "submitted" => Ok(Self::Submitted),
            "cancelled" => Ok(Self::Cancelled),
            "applied" => Ok(Self::Applied),
            "superseded" => Ok(Self::Superseded),
            "approved" | "needs_changes" | "rejected" | "canceled" => {
                Err(WorkflowError::OccupiedLegacyApprovalState)
            }
            _ => Err(WorkflowError::InvalidRestoredState),
        }
    }

    pub(crate) fn as_storage(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Submitted => "submitted",
            Self::Cancelled => "cancelled",
            Self::Applied => "applied",
            Self::Superseded => "superseded",
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
            Self::DraftVersionStarted { version, reason } => formatter
                .debug_struct("DraftVersionStarted")
                .field("version", version)
                .field("reason", reason)
                .finish(),
            Self::Cancelled => formatter.write_str("Cancelled"),
            Self::Applied(receipt) => formatter.debug_tuple("Applied").field(receipt).finish(),
        }
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
    #[error("application reason is invalid or exceeds its bounds")]
    InvalidApplicationReason,
    #[error("proposal version is stale")]
    StaleProposalVersion,
    #[error("proposal digest does not match the frozen version")]
    DigestMismatch,
    #[error("proposal is unavailable")]
    ProposalUnavailable,
    #[error("only the request owner can take this transition")]
    NotOwner,
    #[error("proposal version overflow")]
    VersionOverflow,
    #[error("request workflow revision overflow")]
    StateRevisionOverflow,
    #[error("identifier is invalid")]
    InvalidIdentifier,
    #[error("digest is invalid")]
    InvalidDigest,
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
    #[error("proposal planning binding is invalid")]
    InvalidPlanningBinding,
    #[error("set values cannot be JSON null")]
    NullSetValue,
    #[error("target binding does not match the frozen proposal")]
    TargetBindingMismatch,
    #[error("target revision differs from the frozen proposal base revision")]
    StaleTargetRevision,
    #[error("contract fingerprint differs from the frozen proposal")]
    ContractFingerprintMismatch,
    #[error("accepted review evidence does not match the frozen proposal")]
    ReviewEvidenceMismatch,
    #[error("application receipt does not match the frozen proposal targets")]
    ApplicationReceiptMismatch,
    #[error("request has already been applied")]
    AlreadyApplied,
    #[error("restored request workflow state is inconsistent")]
    InvalidRestoredState,
    #[error("request occupies an obsolete local approval state and requires explicit migration")]
    OccupiedLegacyApprovalState,
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

struct ProposalDigestInput<'a> {
    attachments: &'a BTreeMap<String, AttachmentManifestEntry>,
    request: &'a RequestKey,
    version: ProposalVersion,
    request_record_revision: RecordRevision,
    contract_fingerprint: &'a ContractFingerprint,
    originating_package: &'a PackageFingerprint,
    effects: &'a [PreparedEffect],
    planning_binding: Option<&'a FrozenPlanningBinding>,
    review_requirement: &'a FrozenReviewRequirement,
    on_approved: &'a crate::model::CompiledChangeRequestOnApproved,
    application_preconditions: Option<&'a FrozenApplicationPreconditions>,
}

fn proposal_digest(input: ProposalDigestInput<'_>) -> Result<ProposalDigest, WorkflowError> {
    let ProposalDigestInput {
        attachments,
        request,
        version,
        request_record_revision,
        contract_fingerprint,
        originating_package,
        effects,
        planning_binding,
        review_requirement,
        on_approved,
        application_preconditions,
    } = input;
    let planning_binding = planning_binding.ok_or(WorkflowError::InvalidPlanningBinding)?;
    let mut value = match application_preconditions {
        None => json!({
            "schema": "breg.change-request.proposal.v5",
            "request": request,
            "version": version,
            "requestRecordRevision": request_record_revision,
            "contractFingerprint": contract_fingerprint,
            "originatingPackage": originating_package,
            "review": review_requirement,
            "onApproved": on_approved,
            "planningBinding": planning_binding,
            "effects": effects,
        }),
        Some(application_preconditions) => json!({
            "schema": "breg.change-request.proposal.v5",
            "request": request,
            "version": version,
            "requestRecordRevision": request_record_revision,
            "contractFingerprint": contract_fingerprint,
            "originatingPackage": originating_package,
            "review": review_requirement,
            "onApproved": on_approved,
            "planningBinding": planning_binding,
            "effects": effects,
            "applicationPreconditions": application_preconditions,
        }),
    };
    if !attachments.is_empty() {
        value["attachments"] =
            serde_json::to_value(attachments).map_err(|_| WorkflowError::Canonicalization)?;
    }
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
mod source_owned_review_tests {
    use super::*;
    use crate::model::{
        CompiledChangeRequestNoReview, CompiledChangeRequestNoReviewMode,
        CompiledChangeRequestReviewRequirement,
    };
    use crate::review_integration::{
        AcceptedReviewBinding, AcceptedReviewEvidence, ReviewPolicyBinding, ReviewResultEnvelope,
        ReviewSubjectBinding, TerminalReviewStatus,
    };
    use uuid::Uuid;

    fn entity(value: &str) -> EntityId {
        EntityId::new(value).expect("entity id")
    }

    fn record(value: &str) -> RecordId {
        RecordId::new(value).expect("record id")
    }

    fn revision(value: i64) -> RecordRevision {
        RecordRevision::new(value).expect("record revision")
    }

    fn context(actor: &str, timestamp: &str) -> TrustedTransitionContext {
        TrustedTransitionContext::from_verified_context(
            TrustedActorRef::from_verified_context(actor).expect("actor"),
            TrustedTimestamp::from_server_clock(timestamp).expect("timestamp"),
        )
    }

    fn workflow() -> RequestWorkflow {
        RequestWorkflow::new_draft(
            RequestKey::new(entity("placement-correction-request"), record("request-1")),
            TrustedActorRef::from_verified_context("submitter").expect("owner"),
            StateRevision::new(1).expect("state revision"),
        )
    }

    fn proposal(review: FrozenReviewRequirement) -> PreparedProposal {
        let effect = PreparedEffect::new(
            EffectId::new("patch-placement").expect("effect id"),
            Operation::Patch,
            PreparedTarget::existing(
                entity("asset-placement"),
                record("placement-1"),
                revision(3),
            ),
            vec![PreparedFieldChange::set(
                FieldId::new("site").expect("field id"),
                FieldValue::present(json!("site-a")),
                json!("site-b"),
            )
            .expect("field change")],
        )
        .expect("effect");
        let snapshot_bytes = canonicalize_json(
            &serde_json::to_value(std::slice::from_ref(&effect)).expect("effect serializes"),
        )
        .expect("effect canonicalizes")
        .len();
        PreparedProposal::new_with_binding(
            revision(7),
            ContractFingerprint::new("sha256:contract").expect("contract fingerprint"),
            PackageFingerprint::new("sha256:package").expect("package fingerprint"),
            review,
            FrozenPlanningBinding::new(
                FrozenPlannerKind::Declarative,
                "registry.change-request-plan/v1",
                None,
            )
            .expect("planning binding"),
            vec![effect],
            snapshot_bytes,
        )
        .expect("proposal")
    }

    fn no_review() -> FrozenReviewRequirement {
        FrozenReviewRequirement::None(CompiledChangeRequestNoReview {
            mode: CompiledChangeRequestNoReviewMode::None,
        })
    }

    fn required_review() -> FrozenReviewRequirement {
        FrozenReviewRequirement::Required(CompiledChangeRequestReviewRequirement {
            authority: "casework-main".to_owned(),
            policy_id: "request-review".to_owned(),
        })
    }

    fn application() -> PreparedApplication {
        PreparedApplication::new(
            ApplicationId::new("application-1").expect("application id"),
            vec![ApplicationResultLink::new(
                entity("asset-placement"),
                record("placement-1"),
                revision(4),
            )],
        )
        .expect("application")
    }

    fn observed_targets() -> Vec<ObservedTarget> {
        vec![ObservedTarget::existing(
            entity("asset-placement"),
            record("placement-1"),
            revision(3),
        )]
    }

    fn accepted_evidence(proposal: &ProposalSnapshot) -> AcceptedReviewEvidence {
        let subject = ReviewSubjectBinding {
            source: "breg".to_owned(),
            subject_type: "change_request".to_owned(),
            id: "request-1".to_owned(),
            version: proposal.version().get().to_string(),
            digest: proposal.effect_digest().as_str().to_owned(),
        };
        let policy = ReviewPolicyBinding {
            id: "request-review".to_owned(),
            version: "7".to_owned(),
            digest: format!("sha256:{}", "b".repeat(64)),
        };
        let accepted = AcceptedReviewBinding {
            authority: "casework-main".to_owned(),
            request_id: Uuid::from_u128(1),
            subject: subject.clone(),
            policy: policy.clone(),
            submission_digest: format!("sha256:{}", "c".repeat(64)),
        };
        let result = ReviewResultEnvelope {
            result_id: Uuid::from_u128(2),
            request_id: accepted.request_id,
            subject,
            policy,
            submission_digest: accepted.submission_digest.clone(),
            status: TerminalReviewStatus::Approved,
            completed_at: "2026-09-19T00:01:00Z".to_owned(),
            available_until: "2026-09-20T00:01:00Z".to_owned(),
        };
        AcceptedReviewEvidence::from_approved("casework-main", &accepted, &result)
            .expect("accepted evidence")
    }

    #[test]
    fn explicit_no_review_applies_directly_and_refuses_unsolicited_evidence() {
        let submitted = workflow()
            .submit(
                context("submitter", "2026-09-19T00:00:00Z"),
                proposal(no_review()),
            )
            .expect("submit")
            .into_workflow();
        let frozen = submitted.current_proposal().expect("frozen proposal");
        let digest = frozen.effect_digest().clone();
        let contract = frozen.contract_fingerprint().clone();

        let evidence = accepted_evidence(frozen);
        let refused = submitted.clone().apply(
            context("applier", "2026-09-19T00:02:00Z"),
            ProposalVersion::first(),
            &digest,
            &contract,
            Some(&evidence),
            observed_targets(),
            application(),
            None,
        );
        assert_eq!(
            refused.expect_err("unsolicited review evidence must be refused"),
            WorkflowError::ReviewEvidenceMismatch
        );

        let applied = submitted
            .apply(
                context("applier", "2026-09-19T00:02:00Z"),
                ProposalVersion::first(),
                &digest,
                &contract,
                None,
                observed_targets(),
                application(),
                None,
            )
            .expect("direct application")
            .into_workflow();
        assert_eq!(applied.state(), RequestState::Applied);
    }

    #[test]
    fn required_review_applies_only_with_exact_approved_result_binding() {
        let submitted = workflow()
            .submit(
                context("submitter", "2026-09-19T00:00:00Z"),
                proposal(required_review()),
            )
            .expect("submit")
            .into_workflow();
        let frozen = submitted.current_proposal().expect("frozen proposal");
        let digest = frozen.effect_digest().clone();
        let contract = frozen.contract_fingerprint().clone();

        let refused = submitted.clone().apply(
            context("applier", "2026-09-19T00:02:00Z"),
            ProposalVersion::first(),
            &digest,
            &contract,
            None,
            observed_targets(),
            application(),
            None,
        );
        assert_eq!(
            refused.expect_err("missing review evidence must be refused"),
            WorkflowError::ReviewEvidenceMismatch
        );

        let evidence = accepted_evidence(frozen);
        let applied = submitted
            .apply(
                context("applier", "2026-09-19T00:02:00Z"),
                ProposalVersion::first(),
                &digest,
                &contract,
                Some(&evidence),
                observed_targets(),
                application(),
                Some("casework approval received".to_owned()),
            )
            .expect("review-backed application")
            .into_workflow();
        assert_eq!(applied.state(), RequestState::Applied);
    }

    #[test]
    fn proposal_digest_binds_exact_review_authority_and_policy() {
        let first = workflow()
            .submit(
                context("submitter", "2026-09-19T00:00:00Z"),
                proposal(required_review()),
            )
            .expect("submit")
            .into_workflow();
        let second = workflow()
            .submit(
                context("submitter", "2026-09-19T00:00:00Z"),
                proposal(FrozenReviewRequirement::Required(
                    CompiledChangeRequestReviewRequirement {
                        authority: "casework-secondary".to_owned(),
                        policy_id: "request-review-v2".to_owned(),
                    },
                )),
            )
            .expect("submit")
            .into_workflow();
        assert_ne!(
            first.current_proposal().expect("proposal").effect_digest(),
            second.current_proposal().expect("proposal").effect_digest()
        );
    }

    #[test]
    fn proposal_v3_digest_binds_frozen_application_contract_and_values() {
        let preconditions = FrozenApplicationPreconditions {
            contract: crate::model::CompiledChangeRequestPreconditions {
                request: vec![crate::model::CompiledChangeRequestPredicate {
                    field: "valid-through".to_owned(),
                    expected: crate::model::CompiledChangeRequestPredicateExpected::CurrentDate {
                        relation: crate::model::CompiledCurrentDateRelation::OnOrAfter,
                    },
                }],
                targets: Vec::new(),
                evidence: Vec::new(),
            },
            request_values: BTreeMap::from([("valid-through".to_owned(), json!("2026-09-12"))]),
            targets: Vec::new(),
        };
        let submitted = workflow()
            .submit(
                context("submitter", "2026-09-19T00:00:00Z"),
                proposal(required_review())
                    .with_application_preconditions(preconditions)
                    .expect("preconditions freeze"),
            )
            .expect("submit")
            .into_workflow();
        let snapshot = submitted.current_proposal().expect("proposal");
        snapshot
            .verify_digest(submitted.request())
            .expect("digest verifies");
        let mut tampered = snapshot.clone();
        tampered
            .application_preconditions
            .as_mut()
            .expect("preconditions")
            .request_values
            .insert("valid-through".to_owned(), json!("2099-01-01"));
        assert_eq!(
            tampered.verify_digest(submitted.request()),
            Err(WorkflowError::DigestMismatch)
        );
    }

    #[test]
    fn proposal_digest_binds_attachment_hash_type_size_and_slot() {
        let manifest = BTreeMap::from([(
            "evidence".to_owned(),
            AttachmentManifestEntry {
                verification_policy: None,
                sha256: "a".repeat(64),
                content_type: "application/pdf".to_owned(),
                byte_size: 10,
            },
        )]);
        let prepared = proposal(required_review());
        let frozen = workflow()
            .submit(
                context("submitter", "2026-09-19T00:00:00Z"),
                prepared
                    .clone()
                    .with_attachments(manifest.clone())
                    .expect("attachments freeze"),
            )
            .expect("submit")
            .into_workflow();
        let snapshot = frozen.current_proposal().expect("proposal");
        snapshot
            .verify_digest(frozen.request())
            .expect("digest verifies");
        assert_eq!(snapshot.attachments(), &manifest);
        let original = snapshot.effect_digest().clone();
        for mutation in 0..5 {
            let mut changed = manifest.clone();
            match mutation {
                0 => changed.get_mut("evidence").expect("slot").sha256 = "b".repeat(64),
                1 => {
                    changed.get_mut("evidence").expect("slot").content_type =
                        "image/png".to_owned();
                }
                2 => changed.get_mut("evidence").expect("slot").byte_size = 11,
                3 => {
                    changed
                        .get_mut("evidence")
                        .expect("slot")
                        .verification_policy = Some("policy-a".to_owned());
                }
                _ => {
                    let entry = changed.remove("evidence").expect("slot");
                    changed.insert("other".to_owned(), entry);
                }
            }
            let result = workflow()
                .submit(
                    context("submitter", "2026-09-19T00:00:00Z"),
                    prepared
                        .clone()
                        .with_attachments(changed)
                        .expect("attachments freeze"),
                )
                .expect("submit")
                .into_workflow();
            assert_ne!(
                result.current_proposal().expect("proposal").effect_digest(),
                &original
            );
        }
        let mut tampered = snapshot.clone();
        tampered
            .attachments
            .get_mut("evidence")
            .expect("slot")
            .sha256 = "c".repeat(64);
        assert_eq!(
            tampered.verify_digest(frozen.request()),
            Err(WorkflowError::DigestMismatch)
        );
    }

    #[cfg(feature = "runtime")]
    #[test]
    fn occupied_local_approval_states_require_explicit_migration() {
        for state in ["approved", "needs_changes", "rejected", "canceled"] {
            assert_eq!(
                RequestState::from_storage(state),
                Err(WorkflowError::OccupiedLegacyApprovalState)
            );
        }
    }
}

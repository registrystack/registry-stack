//! Fail-closed native Evidence audit through the platform audit writer.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions, TryLockError},
    io::{BufRead, BufReader, Error as IoError, ErrorKind, Read},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_audit::{
    AuditDestination, AuditEntry, AuditError, AuditKeyHasher, AuditPhase as EntryPhase,
    AuditProfile, AuditUnavailable, AuditWriter, AuthorizationAuditEvent, AuthorizationOutcome,
};
use registry_platform_crypto::canonicalize_json;
use registry_platform_oidc::ActorKind;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::config::{AssuranceProfile, MAXIMUM_HOLDER_BOUND_BATCH_SIZE};
use crate::model::EVIDENCE_REQUEST_BATCH_MAX_ITEMS;

/// Envelope schema of an authorized-material event.
pub const AUDIT_SCHEMA: &str = "registry.evidence.audit/v2";
/// Envelope schema of a request-batch event.
pub const REQUEST_BATCH_AUDIT_SCHEMA: &str = "registry.evidence.audit.request-batch/v2";
/// Envelope schema of an authenticated authorization refusal.
pub const AUTHORIZATION_REFUSAL_AUDIT_SCHEMA: &str =
    "registry.evidence.audit.authorization-refusal/v2";
const AUTHORIZATION_REFUSAL_ERROR_CATEGORY: &str = "not-authorized";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditPhase {
    AccessAttempt,
    DisclosureRelease,
    Denial,
    TransientFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditDecision {
    Authorized,
    Released,
    NoMatch,
    Ambiguous,
    Unresolved,
    FactMissing,
    DependencyFailure,
    EvaluationFailure,
    SigningFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizationRefusalAuditDecision {
    NotAuthorized,
}

/// Minimal native audit event for an authenticated authorization refusal.
///
/// This is deliberately a distinct closed shape from [`EvidenceAuditEvent`]:
/// authorization has not resolved an authority, requirement, subjects, source,
/// or response protection that could be recorded safely.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceAuthorizationRefusalAuditEvent {
    pub assurance_profile: AssuranceProfile,
    pub event_id: String,
    pub occurred_at: String,
    pub operation: String,
    pub phase: AuditPhase,
    pub bundle_revision: String,
    pub requester_pseudonym: String,
    pub actor_kind: ActorKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_pseudonym: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_pseudonym: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_pseudonym: Option<String>,
    pub decision: AuthorizationRefusalAuditDecision,
    pub safe_error_category: String,
    pub reason: String,
    pub duration_milliseconds: u64,
}

impl EvidenceAuthorizationRefusalAuditEvent {
    pub fn new(
        assurance_profile: AssuranceProfile,
        operation: String,
        bundle_revision: String,
        requester_pseudonym: String,
        duration_milliseconds: u64,
    ) -> Self {
        Self {
            assurance_profile,
            event_id: format!("urn:ulid:{}", ulid::Ulid::new()),
            occurred_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            operation,
            phase: AuditPhase::Denial,
            bundle_revision,
            requester_pseudonym,
            actor_kind: ActorKind::Service,
            client_pseudonym: None,
            grant_pseudonym: None,
            actor_pseudonym: None,
            decision: AuthorizationRefusalAuditDecision::NotAuthorized,
            safe_error_category: AUTHORIZATION_REFUSAL_ERROR_CATEGORY.to_owned(),
            reason: "authorization.profile".to_owned(),
            duration_milliseconds,
        }
    }

    pub fn validate_phase_fields(&self) -> Result<(), EvidenceAuditError> {
        if self.phase != AuditPhase::Denial
            || self.decision != AuthorizationRefusalAuditDecision::NotAuthorized
            || !valid_uri(&self.event_id)
            || chrono::DateTime::parse_from_rfc3339(&self.occurred_at).is_err()
            || !(16..=128).contains(&self.operation.len())
            || !valid_revision(&self.bundle_revision)
            || !valid_pseudonym(&self.requester_pseudonym)
            || self
                .client_pseudonym
                .as_ref()
                .is_some_and(|value| !valid_pseudonym(value))
            || self
                .grant_pseudonym
                .as_ref()
                .is_some_and(|value| !valid_pseudonym(value))
            || self
                .actor_pseudonym
                .as_ref()
                .is_some_and(|value| !valid_pseudonym(value))
            || self.safe_error_category != AUTHORIZATION_REFUSAL_ERROR_CATEGORY
            || !valid_purpose(&self.reason, 128)
            || self.duration_milliseconds > 86_400_000
        {
            return Err(EvidenceAuditError::InvalidEvent);
        }
        if let Some(client) = &self.client_pseudonym {
            AuthorizationAuditEvent::denied_without_purpose(
                self.actor_kind.as_str(),
                self.requester_pseudonym.clone(),
                client.clone(),
                self.grant_pseudonym.clone(),
                None,
                self.operation.clone(),
                self.reason.clone(),
            )
            .map_err(|_| EvidenceAuditError::InvalidEvent)?;
        }
        Ok(())
    }
}

/// Closed non-secret response-protection mode resolved with authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseProtection {
    Signed,
    Unsigned,
    SdJwtVc,
}

impl ResponseProtection {
    /// Report whether release under this mode is cryptographically protected
    /// and therefore records the signing key identifier.
    pub fn is_signed(self) -> bool {
        matches!(self, Self::Signed | Self::SdJwtVc)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityKind {
    Statutory,
    Organizational,
    Consent,
    Delegated,
    ExplicitRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditAuthority {
    pub kind: AuthorityKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_pseudonym: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver_pseudonym: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditSubject {
    pub role: String,
    pub selector_profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_bundle_pseudonym: Option<String>,
}

/// The closed phase vocabulary of one multi-subject request-batch operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceRequestBatchAuditPhase {
    AccessAttempt,
    DisclosureRelease,
    TerminalFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceRequestBatchAuditDecision {
    Authorized,
    Released,
    Aborted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceRequestBatchAuditOutcomeKind {
    Evidence,
    EvidenceNotAvailable,
}

/// One group of items whose selectors a single physical source call carries
/// under one identical authority decision.
///
/// Sequential execution emits one index and one group per call. A source that
/// accepts a native batch can group equal pseudonymous subject sets without
/// repeating them, while the ordered index partition preserves accountability
/// for every logical item without recording any selector or source value.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceRequestBatchAuditItemGroup {
    pub item_indices: Vec<u8>,
    pub authority: AuditAuthority,
    pub subjects: Vec<AuditSubject>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceRequestBatchAuditOutcome {
    pub item_index: u8,
    pub outcome: EvidenceRequestBatchAuditOutcomeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
}

/// Batch-native audit event. It deliberately does not reuse
/// [`EvidenceAuditEvent`]: the singular shape associates one subject set with
/// one access, while this shape has an explicit item-to-subject grouping and
/// exactly one terminal event for the outer operation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceRequestBatchAuditEvent {
    pub assurance_profile: AssuranceProfile,
    pub event_id: String,
    pub occurred_at: String,
    pub operation: String,
    pub phase: EvidenceRequestBatchAuditPhase,
    pub requirement: String,
    pub bundle_revision: String,
    pub purpose: String,
    pub requester_pseudonym: String,
    pub actor_kind: ActorKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_pseudonym: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_pseudonym: Option<String>,
    pub response_protection: ResponseProtection,
    pub decision: EvidenceRequestBatchAuditDecision,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_indices: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_groups: Option<Vec<EvidenceRequestBatchAuditItemGroup>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disclosed_concepts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcomes: Option<Vec<EvidenceRequestBatchAuditOutcome>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_error_category: Option<String>,
    pub duration_milliseconds: u64,
}

impl EvidenceRequestBatchAuditEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        assurance_profile: AssuranceProfile,
        operation: String,
        phase: EvidenceRequestBatchAuditPhase,
        requirement: String,
        bundle_revision: String,
        purpose: String,
        requester_pseudonym: String,
        decision: EvidenceRequestBatchAuditDecision,
        duration_milliseconds: u64,
    ) -> Self {
        Self {
            assurance_profile,
            event_id: format!("urn:ulid:{}", ulid::Ulid::new()),
            occurred_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            operation,
            phase,
            requirement,
            bundle_revision,
            purpose,
            requester_pseudonym,
            actor_kind: ActorKind::Service,
            client_pseudonym: None,
            actor_pseudonym: None,
            response_protection: ResponseProtection::Signed,
            decision,
            reason: "authorization.allowed".to_owned(),
            source_id: None,
            adapter_id: None,
            item_indices: None,
            item_groups: None,
            disclosed_concepts: None,
            signing_key_id: None,
            outcomes: None,
            safe_error_category: None,
            duration_milliseconds,
        }
    }

    pub fn validate_phase_fields(&self) -> Result<(), EvidenceAuditError> {
        let common_valid = valid_uri(&self.event_id)
            && chrono::DateTime::parse_from_rfc3339(&self.occurred_at).is_ok()
            && (16..=128).contains(&self.operation.len())
            && valid_uri(&self.requirement)
            && valid_revision(&self.bundle_revision)
            && valid_purpose(&self.purpose, 128)
            && valid_pseudonym(&self.requester_pseudonym)
            && self
                .client_pseudonym
                .as_ref()
                .is_none_or(|value| valid_pseudonym(value))
            && self
                .actor_pseudonym
                .as_ref()
                .is_none_or(|value| valid_pseudonym(value))
            && self.response_protection == ResponseProtection::Signed
            && valid_purpose(&self.reason, 128)
            && self.duration_milliseconds <= 86_400_000;
        if !common_valid {
            return Err(EvidenceAuditError::InvalidEvent);
        }

        let valid_access = || {
            let Some(item_indices) = self.item_indices.as_ref() else {
                return false;
            };
            let Some(item_groups) = self.item_groups.as_ref() else {
                return false;
            };
            valid_batch_item_indices(item_indices)
                && valid_batch_item_groups(item_groups, item_indices)
                && self
                    .source_id
                    .as_ref()
                    .is_some_and(|value| valid_local_name(value, 128))
                && self
                    .adapter_id
                    .as_ref()
                    .is_some_and(|value| valid_local_name(value, 128))
                && self.disclosed_concepts.is_none()
                && self.signing_key_id.is_none()
                && self.outcomes.is_none()
                && self.safe_error_category.is_none()
        };
        let valid_release = || {
            self.source_id.is_none()
                && self.adapter_id.is_none()
                && self.item_indices.is_none()
                && self.item_groups.as_ref().is_some_and(|groups| {
                    self.outcomes.as_ref().is_some_and(|outcomes| {
                        let expected = (0..outcomes.len())
                            .map(|index| u8::try_from(index).unwrap_or(u8::MAX))
                            .collect::<Vec<_>>();
                        valid_batch_item_groups(groups, &expected)
                    })
                })
                && self.safe_error_category.is_none()
                && self.disclosed_concepts.as_ref().is_some_and(|concepts| {
                    concepts.len() <= 16
                        && concepts.iter().all(|concept| valid_uri(concept))
                        && concepts.iter().collect::<BTreeSet<_>>().len() == concepts.len()
                })
                && self.outcomes.as_ref().is_some_and(|outcomes| {
                    let signed_any = outcomes.iter().any(|outcome| {
                        outcome.outcome == EvidenceRequestBatchAuditOutcomeKind::Evidence
                    });
                    valid_batch_outcomes(outcomes)
                        && self.signing_key_id.is_some() == signed_any
                        && self.signing_key_id.as_ref().is_none_or(|value| {
                            !value.is_empty()
                                && value.len() <= 256
                                && !value.chars().any(char::is_control)
                        })
                })
        };
        let valid_abort = || {
            self.source_id.is_none()
                && self.adapter_id.is_none()
                && self.item_indices.is_none()
                && self.item_groups.is_none()
                && self.disclosed_concepts.is_none()
                && self.signing_key_id.is_none()
                && self.outcomes.is_none()
                && self
                    .safe_error_category
                    .as_ref()
                    .is_some_and(|value| valid_local_name(value, 128))
        };

        let phase_valid = match (self.phase, self.decision) {
            (
                EvidenceRequestBatchAuditPhase::AccessAttempt,
                EvidenceRequestBatchAuditDecision::Authorized,
            ) => valid_access(),
            (
                EvidenceRequestBatchAuditPhase::DisclosureRelease,
                EvidenceRequestBatchAuditDecision::Released,
            ) => valid_release(),
            (
                EvidenceRequestBatchAuditPhase::TerminalFailure,
                EvidenceRequestBatchAuditDecision::Aborted,
            ) => valid_abort(),
            _ => false,
        };
        phase_valid
            .then_some(())
            .ok_or(EvidenceAuditError::InvalidEvent)
    }
}

fn valid_batch_item_indices(indices: &[u8]) -> bool {
    !indices.is_empty()
        && indices.len() <= EVIDENCE_REQUEST_BATCH_MAX_ITEMS
        && indices
            .iter()
            .all(|index| usize::from(*index) < EVIDENCE_REQUEST_BATCH_MAX_ITEMS)
        && indices.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_batch_item_groups(
    groups: &[EvidenceRequestBatchAuditItemGroup],
    item_indices: &[u8],
) -> bool {
    if groups.is_empty() || groups.len() > item_indices.len() {
        return false;
    }
    let mut grouped_indices = Vec::with_capacity(item_indices.len());
    let mut previous_first = None;
    for (group_index, group) in groups.iter().enumerate() {
        if !valid_batch_item_indices(&group.item_indices)
            || previous_first.is_some_and(|previous| previous >= group.item_indices[0])
            || groups[..group_index].iter().any(|previous| {
                previous.authority == group.authority && previous.subjects == group.subjects
            })
            || group
                .authority
                .grant_pseudonym
                .as_ref()
                .is_some_and(|value| !valid_pseudonym(value))
            || group
                .authority
                .approver_pseudonym
                .as_ref()
                .is_some_and(|value| !valid_pseudonym(value))
            || group.subjects.is_empty()
            || group.subjects.len() > 8
            || group.subjects.iter().any(|subject| {
                !valid_local_name(&subject.role, 64)
                    || !valid_local_name(&subject.selector_profile, 128)
                    || subject
                        .selector_bundle_pseudonym
                        .as_ref()
                        .is_some_and(|value| !valid_pseudonym(value))
            })
        {
            return false;
        }
        previous_first = group.item_indices.first().copied();
        grouped_indices.extend_from_slice(&group.item_indices);
    }
    grouped_indices.sort_unstable();
    grouped_indices.windows(2).all(|pair| pair[0] != pair[1]) && grouped_indices == item_indices
}

fn valid_batch_outcomes(outcomes: &[EvidenceRequestBatchAuditOutcome]) -> bool {
    (1..=EVIDENCE_REQUEST_BATCH_MAX_ITEMS).contains(&outcomes.len())
        && outcomes.iter().enumerate().all(|(index, outcome)| {
            usize::from(outcome.item_index) == index
                && match outcome.outcome {
                    EvidenceRequestBatchAuditOutcomeKind::Evidence => {
                        outcome.evidence_id.as_ref().is_some_and(|id| valid_uri(id))
                    }
                    EvidenceRequestBatchAuditOutcomeKind::EvidenceNotAvailable => {
                        outcome.evidence_id.is_none()
                    }
                }
        })
        && outcomes
            .iter()
            .filter_map(|outcome| outcome.evidence_id.as_ref())
            .collect::<BTreeSet<_>>()
            .len()
            == outcomes
                .iter()
                .filter(|outcome| outcome.evidence_id.is_some())
                .count()
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceAuditEvent {
    pub assurance_profile: AssuranceProfile,
    pub event_id: String,
    pub occurred_at: String,
    pub operation: String,
    pub phase: AuditPhase,
    pub requirement: String,
    pub bundle_revision: String,
    pub purpose: String,
    pub requester_pseudonym: String,
    pub actor_kind: ActorKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_pseudonym: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_pseudonym: Option<String>,
    pub authority: AuditAuthority,
    pub subjects: Vec<AuditSubject>,
    pub response_protection: ResponseProtection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter_id: Option<String>,
    /// Every source executed by a multi-stage acquisition, in execution order,
    /// recorded only on the disclosure release that closed it. Absent for the
    /// frozen one and two stage kinds, whose release shape stays byte-identical:
    /// there the scalar names the last executed stage, and an earlier stage is
    /// read from its own access-attempt event, as it always has been.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ids: Option<Vec<String>>,
    /// The adapter of each executed stage, positionally aligned with
    /// [`Self::source_ids`]. Two stages may name one adapter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter_ids: Option<Vec<String>>,
    pub decision: AuditDecision,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disclosed_concepts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
    /// Every assertion one release carried, in release order, recorded only
    /// where a single release covered more than one. A release of exactly one
    /// assertion leaves this unset and names that assertion in
    /// [`Self::evidence_id`], so the shape every existing release already had
    /// stays byte-identical.
    ///
    /// A batch is named here rather than in one event per member because the
    /// release gate writes one terminal event per operation: N events would
    /// either be N operations, losing the fact that one request released them,
    /// or N terminal events for one operation, which no reader could tell apart
    /// from a duplicated release.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_error_category: Option<String>,
    pub duration_milliseconds: u64,
}

impl EvidenceAuditEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        assurance_profile: AssuranceProfile,
        operation: String,
        phase: AuditPhase,
        requirement: String,
        bundle_revision: String,
        purpose: String,
        requester_pseudonym: String,
        authority: AuditAuthority,
        subjects: Vec<AuditSubject>,
        response_protection: ResponseProtection,
        decision: AuditDecision,
        duration_milliseconds: u64,
    ) -> Self {
        Self {
            assurance_profile,
            event_id: format!("urn:ulid:{}", ulid::Ulid::new()),
            occurred_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            operation,
            phase,
            requirement,
            bundle_revision,
            purpose,
            requester_pseudonym,
            actor_kind: ActorKind::Service,
            client_pseudonym: None,
            actor_pseudonym: None,
            authority,
            subjects,
            response_protection,
            source_id: None,
            adapter_id: None,
            source_ids: None,
            adapter_ids: None,
            decision,
            reason: "authorization.allowed".to_owned(),
            disclosed_concepts: None,
            evidence_id: None,
            evidence_ids: None,
            signing_key_id: None,
            safe_error_category: None,
            duration_milliseconds,
        }
    }

    pub fn validate_phase_fields(&self) -> Result<(), EvidenceAuditError> {
        let any_release_field = self.disclosed_concepts.is_some()
            || self.evidence_id.is_some()
            || self.evidence_ids.is_some();
        // A release names what it released exactly once: the scalar for the one
        // assertion, or the array for the set a batch carried. Both together
        // would let a reader count one release twice, and neither would leave a
        // release that names nothing.
        let names_the_released_set = self.evidence_id.is_some() ^ self.evidence_ids.is_some();
        let all_release_fields = self.disclosed_concepts.is_some() && names_the_released_set;
        if (self.phase == AuditPhase::DisclosureRelease && !all_release_fields)
            || (self.phase != AuditPhase::DisclosureRelease && any_release_field)
        {
            return Err(EvidenceAuditError::InvalidEvent);
        }
        // A signing key identity exists exactly for cryptographically
        // protected disclosure release.
        let signing_key_required =
            self.phase == AuditPhase::DisclosureRelease && self.response_protection.is_signed();
        if self.signing_key_id.is_some() != signing_key_required {
            return Err(EvidenceAuditError::InvalidEvent);
        }
        let phase_decision_is_native = matches!(
            (self.phase, self.decision),
            (AuditPhase::AccessAttempt, AuditDecision::Authorized)
                | (AuditPhase::DisclosureRelease, AuditDecision::Released)
                | (
                    AuditPhase::Denial,
                    AuditDecision::NoMatch
                        | AuditDecision::Ambiguous
                        | AuditDecision::Unresolved
                        | AuditDecision::FactMissing
                )
                | (
                    AuditPhase::TransientFailure,
                    AuditDecision::DependencyFailure
                        | AuditDecision::EvaluationFailure
                        | AuditDecision::SigningFailure
                )
        );
        // Stage arrays exist exactly for a disclosure release that closed a
        // multi-stage acquisition: one search and two to four members. They
        // are ordered, positionally aligned, and end at the stage the scalars
        // already name, so a reader of the scalars alone is never misled.
        let stage_arrays_are_valid = match (self.source_ids.as_ref(), self.adapter_ids.as_ref()) {
            (None, None) => true,
            (Some(source_ids), Some(adapter_ids)) => {
                self.phase == AuditPhase::DisclosureRelease
                    && (3..=5).contains(&source_ids.len())
                    && adapter_ids.len() == source_ids.len()
                    && source_ids.iter().all(|value| valid_local_name(value, 128))
                    && adapter_ids.iter().all(|value| valid_local_name(value, 128))
                    && source_ids.iter().collect::<BTreeSet<_>>().len() == source_ids.len()
                    && self.source_id.as_deref() == source_ids.last().map(String::as_str)
                    && self.adapter_id.as_deref() == adapter_ids.last().map(String::as_str)
            }
            _ => false,
        };
        // A released set exists exactly for a release that carried more than one
        // assertion, and stays within the ceiling the bundle's holder-bound
        // batch size is bounded by, so an audit reader never faces an unbounded
        // list.
        let evidence_ids_are_valid = self.evidence_ids.as_ref().is_none_or(|evidence_ids| {
            self.phase == AuditPhase::DisclosureRelease
                && (2..=usize::from(MAXIMUM_HOLDER_BOUND_BATCH_SIZE)).contains(&evidence_ids.len())
                && evidence_ids.iter().all(|value| valid_uri(value))
                && evidence_ids.iter().collect::<BTreeSet<_>>().len() == evidence_ids.len()
        });
        let concepts_are_valid = self.disclosed_concepts.as_ref().is_none_or(|concepts| {
            concepts.len() <= 16
                && concepts.iter().all(|concept| valid_uri(concept))
                && concepts.iter().collect::<BTreeSet<_>>().len() == concepts.len()
        });
        if !phase_decision_is_native
            || !valid_uri(&self.event_id)
            || chrono::DateTime::parse_from_rfc3339(&self.occurred_at).is_err()
            || !valid_uri(&self.requirement)
            || !valid_revision(&self.bundle_revision)
            || !valid_purpose(&self.purpose, 128)
            || !valid_pseudonym(&self.requester_pseudonym)
            || self
                .client_pseudonym
                .as_ref()
                .is_some_and(|value| !valid_pseudonym(value))
            || self
                .actor_pseudonym
                .as_ref()
                .is_some_and(|value| !valid_pseudonym(value))
            || self
                .authority
                .grant_pseudonym
                .as_ref()
                .is_some_and(|value| !valid_pseudonym(value))
            || self
                .authority
                .approver_pseudonym
                .as_ref()
                .is_some_and(|value| !valid_pseudonym(value))
            || self.subjects.is_empty()
            || self.subjects.len() > 8
            || !(16..=128).contains(&self.operation.len())
            || self.subjects.iter().any(|subject| {
                !valid_local_name(&subject.role, 64)
                    || !valid_local_name(&subject.selector_profile, 128)
                    || subject
                        .selector_bundle_pseudonym
                        .as_ref()
                        .is_some_and(|value| !valid_pseudonym(value))
            })
            || self
                .source_id
                .as_ref()
                .is_some_and(|value| !valid_local_name(value, 128))
            || self
                .adapter_id
                .as_ref()
                .is_some_and(|value| !valid_local_name(value, 128))
            || !stage_arrays_are_valid
            || !concepts_are_valid
            || !evidence_ids_are_valid
            || self
                .evidence_id
                .as_ref()
                .is_some_and(|value| !valid_uri(value))
            || self.signing_key_id.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
            })
            || self
                .safe_error_category
                .as_ref()
                .is_some_and(|value| !valid_local_name(value, 128))
            || self.duration_milliseconds > 86_400_000
            || !valid_purpose(&self.reason, 128)
        {
            return Err(EvidenceAuditError::InvalidEvent);
        }
        if let Some(client) = &self.client_pseudonym {
            AuthorizationAuditEvent::new(
                self.actor_kind.as_str(),
                self.requester_pseudonym.clone(),
                client.clone(),
                self.authority.grant_pseudonym.clone(),
                self.authority.approver_pseudonym.clone(),
                self.purpose.clone(),
                self.operation.clone(),
                AuthorizationOutcome::Allowed,
                self.reason.clone(),
            )
            .map_err(|_| EvidenceAuditError::InvalidEvent)?;
        }
        Ok(())
    }
}

fn valid_uri(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && url::Url::parse(value).is_ok()
}

fn valid_revision(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn valid_purpose(value: &str, maximum: usize) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= maximum
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

fn valid_local_name(value: &str, maximum: usize) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= maximum
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_pseudonym(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("hmac-sha256:v") else {
        return false;
    };
    let Some((version, digest)) = rest.split_once(':') else {
        return false;
    };
    !version.is_empty()
        && !version.starts_with('0')
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Debug, Error)]
pub enum EvidenceAuditError {
    #[error("audit configuration is invalid")]
    Configuration,
    #[error("audit event is invalid")]
    InvalidEvent,
    #[error("audit initialization or read failed")]
    Audit(#[from] AuditError),
    /// The writer did not accept an entry. Every caller refuses the request
    /// that needed it with the existing service-unavailable problem.
    #[error("audit destination did not accept the entry")]
    Unavailable(#[from] AuditUnavailable),
    /// The stopped local audit files read and hold no operation, as before a
    /// local service has answered its first request. Reported apart from a
    /// read failure because it is a complete answer.
    #[error("stopped local audit retains no operation")]
    NoOperation,
}

/// Evidence's audit boundary: the closed native record families, their keyed
/// pseudonyms, and the one platform writer every entry goes through.
///
/// Every entry's correlation is the record's server-minted `operation`, so an
/// access attempt and the terminal event it led to share one correlation.
pub struct EvidenceAuditLog {
    writer: AuditWriter,
    key_hasher: AuditKeyHasher,
    key_version: u32,
}

impl std::fmt::Debug for EvidenceAuditLog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceAuditLog")
            .field("writer", &self.writer)
            .field("key_version", &self.key_version)
            .finish_non_exhaustive()
    }
}

impl EvidenceAuditLog {
    /// Derive the identifier key, then open the configured destination. The
    /// key is derived first, so an unusable secret never creates an audit
    /// file.
    pub async fn initialize(
        destination: AuditDestination,
        master_secret: Vec<u8>,
        key_version: u32,
    ) -> Result<Self, EvidenceAuditError> {
        let key_hasher = identifier_key_hasher(master_secret, key_version)?;
        let writer = AuditWriter::open(destination).await?;
        Ok(Self {
            writer,
            key_hasher,
            key_version,
        })
    }

    /// Wrap a writer that is already open, such as one built with
    /// [`AuditWriter::from_line_sink`] to observe or refuse writes.
    pub fn with_writer(
        writer: AuditWriter,
        master_secret: Vec<u8>,
        key_version: u32,
    ) -> Result<Self, EvidenceAuditError> {
        let key_hasher = identifier_key_hasher(master_secret, key_version)?;
        Ok(Self {
            writer,
            key_hasher,
            key_version,
        })
    }

    pub fn pseudonym(
        &self,
        class: &str,
        scope: &str,
        protected_input: &[u8],
    ) -> Result<String, EvidenceAuditError> {
        if protected_input.is_empty() {
            return Err(EvidenceAuditError::InvalidEvent);
        }
        let transient = URL_SAFE_NO_PAD.encode(protected_input);
        let digest = self
            .key_hasher
            .audit_reference_hash(class, scope, &transient)
            .map_err(|_| EvidenceAuditError::InvalidEvent)?;
        let digest = digest
            .strip_prefix("hmac-sha256:")
            .ok_or(EvidenceAuditError::InvalidEvent)?;
        Ok(format!("hmac-sha256:v{}:{digest}", self.key_version))
    }

    /// Append an authorized-material event. An access attempt is a `request`
    /// entry; every terminal phase is a `response` entry.
    pub async fn append(&self, event: EvidenceAuditEvent) -> Result<(), EvidenceAuditError> {
        event.validate_phase_fields()?;
        let phase = if event.phase == AuditPhase::AccessAttempt {
            EntryPhase::Request
        } else {
            EntryPhase::Response
        };
        self.write(AUDIT_SCHEMA, phase, &event.operation, &event)
            .await
    }

    /// Append an authorization refusal. It is decided before any protected
    /// I/O, so it is one `response` entry with no `request` entry before it.
    pub async fn append_authorization_refusal(
        &self,
        event: EvidenceAuthorizationRefusalAuditEvent,
    ) -> Result<(), EvidenceAuditError> {
        event.validate_phase_fields()?;
        self.write(
            AUTHORIZATION_REFUSAL_AUDIT_SCHEMA,
            EntryPhase::Response,
            &event.operation,
            &event,
        )
        .await
    }

    /// Append a request-batch event. A physical source access is a `request`
    /// entry; the terminal release or failure is a `response` entry.
    pub async fn append_request_batch(
        &self,
        event: EvidenceRequestBatchAuditEvent,
    ) -> Result<(), EvidenceAuditError> {
        event.validate_phase_fields()?;
        let phase = if event.phase == EvidenceRequestBatchAuditPhase::AccessAttempt {
            EntryPhase::Request
        } else {
            EntryPhase::Response
        };
        self.write(REQUEST_BATCH_AUDIT_SCHEMA, phase, &event.operation, &event)
            .await
    }

    async fn write<T: Serialize>(
        &self,
        schema: &str,
        phase: EntryPhase,
        correlation: &str,
        event: &T,
    ) -> Result<(), EvidenceAuditError> {
        let record = serde_json::to_value(event).map_err(AuditError::Json)?;
        self.writer
            .append(AuditEntry::new(schema, phase, correlation, record))
            .await?;
        Ok(())
    }

    pub async fn ready(&self) -> bool {
        self.writer.ready().await
    }

    /// Durable writes performed so far, for proving that concurrent appends
    /// share them rather than each paying an `fsync`.
    #[cfg(test)]
    pub(crate) fn durable_writes(&self) -> usize {
        usize::try_from(self.writer.durable_writes()).unwrap_or(usize::MAX)
    }
}

/// The identifier hasher behind every pseudonym. Derivation is the platform
/// profile's, so pseudonyms stay byte-identical for one secret and key
/// version.
fn identifier_key_hasher(
    master_secret: Vec<u8>,
    key_version: u32,
) -> Result<AuditKeyHasher, EvidenceAuditError> {
    if key_version == 0 {
        return Err(EvidenceAuditError::Configuration);
    }
    let profile = AuditProfile::production_from_secret_bytes(Zeroizing::new(master_secret))?;
    Ok(profile.key_hasher())
}

pub const LOCAL_AUDIT_OPERATION_VIEW_SCHEMA_V1: &str = "registry.evidence.local-audit-operation/v1";

/// Minimized verified view of one native audit operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalAuditOperationView {
    schema: &'static str,
    operation: String,
    events: Vec<LocalAuditOperationEvent>,
    #[serde(skip)]
    assurance_profile: AssuranceProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
enum LocalAuditOperationEvent {
    Authorized(LocalAuthorizedOperationEvent),
    AuthorizationRefusal(LocalAuthorizationRefusalOperationEvent),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalAuthorizedOperationEvent {
    occurred_at: String,
    phase: AuditPhase,
    decision: AuditDecision,
    requirement: String,
    purpose: String,
    requester_pseudonym: String,
    response_protection: ResponseProtection,
    #[serde(skip_serializing_if = "Option::is_none")]
    disclosed_concepts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_id: Option<String>,
    /// Carried through so a local reader sees the same released set the durable
    /// record names, and never a batch release that appears to have released
    /// nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalAuthorizationRefusalOperationEvent {
    occurred_at: String,
    phase: AuditPhase,
    decision: AuthorizationRefusalAuditDecision,
    requester_pseudonym: String,
    safe_error_category: String,
}

/// One stored line as the platform writer lays it out.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredAuditEntry {
    schema: String,
    event_id: String,
    time: String,
    phase: EntryPhase,
    correlation: String,
    record: serde_json::Value,
}

/// Largest stored line the local reader accepts, matching the writer's entry
/// bound.
const MAXIMUM_LOCAL_AUDIT_LINE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy)]
struct LocalAuditInspectionBounds {
    maximum_segments: usize,
    maximum_records: usize,
    maximum_output_bytes: usize,
}

impl LocalAuditInspectionBounds {
    const DEFAULT: Self = Self {
        maximum_segments: 1024,
        maximum_records: 10_000,
        maximum_output_bytes: 256 * 1024,
    };
}

struct PendingLocalOperation {
    event: EvidenceAuditEvent,
    view: LocalAuditOperationEvent,
}

#[derive(Default)]
struct LocalAuditCollector {
    bounds: Option<LocalAuditInspectionBounds>,
    records: usize,
    /// Each open operation's access entries, one per source stage, in order.
    pending: BTreeMap<String, Vec<PendingLocalOperation>>,
    completed: BTreeSet<String>,
    last_operation: Option<String>,
    last_completed: Option<LocalAuditOperationView>,
    /// Whether the entries read come from the oldest retained file, where a
    /// terminal entry may follow an access entry retention deleted.
    oldest_file: bool,
}

impl LocalAuditCollector {
    fn new(bounds: LocalAuditInspectionBounds) -> Self {
        Self {
            bounds: Some(bounds),
            ..Self::default()
        }
    }

    fn collect(&mut self, entry: StoredAuditEntry) -> Result<(), AuditError> {
        let bounds = self.bounds.ok_or_else(invalid_audit_data)?;
        self.records = self.records.checked_add(1).ok_or_else(file_size_error)?;
        if self.records > bounds.maximum_records {
            return Err(file_size_error());
        }
        if entry.event_id.is_empty() || entry.time.is_empty() {
            return Err(invalid_audit_data());
        }
        match entry.schema.as_str() {
            AUDIT_SCHEMA => {
                let event: EvidenceAuditEvent =
                    serde_json::from_value(entry.record).map_err(|_| invalid_audit_data())?;
                let expected_phase = if event.phase == AuditPhase::AccessAttempt {
                    EntryPhase::Request
                } else {
                    EntryPhase::Response
                };
                if entry.phase != expected_phase || entry.correlation != event.operation {
                    return Err(invalid_audit_data());
                }
                self.collect_authorized(event)
            }
            AUTHORIZATION_REFUSAL_AUDIT_SCHEMA => {
                let event: EvidenceAuthorizationRefusalAuditEvent =
                    serde_json::from_value(entry.record).map_err(|_| invalid_audit_data())?;
                if entry.phase != EntryPhase::Response || entry.correlation != event.operation {
                    return Err(invalid_audit_data());
                }
                self.collect_authorization_refusal(event)
            }
            _ => Err(invalid_audit_data()),
        }
    }

    fn collect_authorized(&mut self, event: EvidenceAuditEvent) -> Result<(), AuditError> {
        event
            .validate_phase_fields()
            .map_err(|_| invalid_audit_data())?;
        let operation = event.operation.clone();
        let previous_operation = self.last_operation.replace(operation.clone());
        let view = LocalAuditOperationEvent::from(&event);

        if event.phase == AuditPhase::AccessAttempt {
            if self.completed.contains(&operation) {
                return Err(invalid_audit_data());
            }
            let stages = self.pending.entry(operation).or_default();
            // A multi-stage acquisition writes one access entry per source
            // call; each later stage shares the operation's context.
            if let Some(previous) = stages.last() {
                if !occurred_in_order(&previous.event, &event)
                    || !same_operation_context(&previous.event, &event)
                {
                    return Err(invalid_audit_data());
                }
            }
            stages.push(PendingLocalOperation { event, view });
            return Ok(());
        }

        let Some(stages) = self.pending.remove(&operation) else {
            // Retention deletes whole sealed files, so the oldest retained
            // file may open with terminal entries whose access entries were
            // deleted. Such an operation is no longer inspectable and is not
            // the last operation; anywhere later, a terminal entry without
            // its access entry is corrupt.
            if !self.oldest_file || !self.completed.insert(operation) {
                return Err(invalid_audit_data());
            }
            self.last_operation = previous_operation;
            return Ok(());
        };
        // The terminal entry names the source of the last stage that ran.
        let last = stages.last().ok_or_else(invalid_audit_data)?;
        if !coherent_operation_pair(&last.event, &event)
            || !self.completed.insert(operation.clone())
        {
            return Err(invalid_audit_data());
        }
        let assurance_profile = last.event.assurance_profile;
        let mut events: Vec<_> = stages.into_iter().map(|stage| stage.view).collect();
        events.push(view);
        self.last_completed = Some(LocalAuditOperationView {
            schema: LOCAL_AUDIT_OPERATION_VIEW_SCHEMA_V1,
            operation,
            events,
            assurance_profile,
        });
        Ok(())
    }

    fn collect_authorization_refusal(
        &mut self,
        event: EvidenceAuthorizationRefusalAuditEvent,
    ) -> Result<(), AuditError> {
        event
            .validate_phase_fields()
            .map_err(|_| invalid_audit_data())?;
        let operation = event.operation.clone();
        self.last_operation = Some(operation.clone());
        if self.pending.contains_key(&operation) || !self.completed.insert(operation.clone()) {
            return Err(invalid_audit_data());
        }
        self.last_completed = Some(LocalAuditOperationView {
            schema: LOCAL_AUDIT_OPERATION_VIEW_SCHEMA_V1,
            operation,
            events: vec![LocalAuditOperationEvent::from(&event)],
            assurance_profile: event.assurance_profile,
        });
        Ok(())
    }

    fn finish(mut self) -> Result<LocalAuditOperationView, EvidenceAuditError> {
        let bounds = self.bounds.take().ok_or(EvidenceAuditError::InvalidEvent)?;
        let last = self
            .last_operation
            .take()
            .ok_or(EvidenceAuditError::NoOperation)?;
        let view = if let Some(stages) = self.pending.remove(&last) {
            let assurance_profile = stages
                .first()
                .ok_or(EvidenceAuditError::InvalidEvent)?
                .event
                .assurance_profile;
            LocalAuditOperationView {
                schema: LOCAL_AUDIT_OPERATION_VIEW_SCHEMA_V1,
                operation: last,
                events: stages.into_iter().map(|stage| stage.view).collect(),
                assurance_profile,
            }
        } else {
            self.last_completed
                .take()
                .filter(|completed| completed.operation == last)
                .ok_or(EvidenceAuditError::InvalidEvent)?
        };
        let starts_with_complete_native_event =
            view.events.first().is_some_and(|event| match event {
                LocalAuditOperationEvent::Authorized(event) => {
                    event.phase == AuditPhase::AccessAttempt
                        && event.decision == AuditDecision::Authorized
                }
                LocalAuditOperationEvent::AuthorizationRefusal(event) => {
                    event.phase == AuditPhase::Denial
                        && event.decision == AuthorizationRefusalAuditDecision::NotAuthorized
                }
            });
        if !starts_with_complete_native_event || view.assurance_profile != AssuranceProfile::Local {
            return Err(EvidenceAuditError::InvalidEvent);
        }
        let serialized = serde_json::to_value(&view).map_err(AuditError::Json)?;
        if canonicalize_json(&serialized)
            .map_err(|_| invalid_audit_data())?
            .len()
            > bounds.maximum_output_bytes
        {
            return Err(EvidenceAuditError::Configuration);
        }
        Ok(view)
    }
}

impl From<&EvidenceAuditEvent> for LocalAuditOperationEvent {
    fn from(event: &EvidenceAuditEvent) -> Self {
        Self::Authorized(LocalAuthorizedOperationEvent {
            occurred_at: event.occurred_at.clone(),
            phase: event.phase,
            decision: event.decision,
            requirement: event.requirement.clone(),
            purpose: event.purpose.clone(),
            requester_pseudonym: event.requester_pseudonym.clone(),
            response_protection: event.response_protection,
            disclosed_concepts: event.disclosed_concepts.clone(),
            evidence_id: event.evidence_id.clone(),
            evidence_ids: event.evidence_ids.clone(),
        })
    }
}

impl From<&EvidenceAuthorizationRefusalAuditEvent> for LocalAuditOperationEvent {
    fn from(event: &EvidenceAuthorizationRefusalAuditEvent) -> Self {
        Self::AuthorizationRefusal(LocalAuthorizationRefusalOperationEvent {
            occurred_at: event.occurred_at.clone(),
            phase: event.phase,
            decision: event.decision,
            requester_pseudonym: event.requester_pseudonym.clone(),
            safe_error_category: event.safe_error_category.clone(),
        })
    }
}

fn coherent_operation_pair(access: &EvidenceAuditEvent, terminal: &EvidenceAuditEvent) -> bool {
    occurred_in_order(access, terminal)
        && same_operation_context(access, terminal)
        && access.source_id == terminal.source_id
        && access.adapter_id == terminal.adapter_id
}

fn occurred_in_order(earlier: &EvidenceAuditEvent, later: &EvidenceAuditEvent) -> bool {
    chrono::DateTime::parse_from_rfc3339(&earlier.occurred_at)
        .ok()
        .zip(chrono::DateTime::parse_from_rfc3339(&later.occurred_at).ok())
        .is_some_and(|(earlier, later)| earlier <= later)
}

/// Everything two entries of one operation share, whichever source stage
/// each names.
fn same_operation_context(access: &EvidenceAuditEvent, terminal: &EvidenceAuditEvent) -> bool {
    access.operation == terminal.operation
        && access.assurance_profile == terminal.assurance_profile
        && access.requirement == terminal.requirement
        && access.bundle_revision == terminal.bundle_revision
        && access.purpose == terminal.purpose
        && access.requester_pseudonym == terminal.requester_pseudonym
        && access.actor_kind == terminal.actor_kind
        && access.client_pseudonym == terminal.client_pseudonym
        && access.actor_pseudonym == terminal.actor_pseudonym
        && access.reason == terminal.reason
        && access.authority == terminal.authority
        && access.subjects == terminal.subjects
        && access.response_protection == terminal.response_protection
}

/// Read the stopped local audit file and its retained sealed files in order,
/// and derive the last operation from the entries read.
///
/// The reader takes the writer's lock for the whole read, so it refuses while
/// an Evidence process still writes the file.
pub fn last_local_audit_operation(
    path: &Path,
) -> Result<LocalAuditOperationView, EvidenceAuditError> {
    last_local_audit_operation_with_bounds(path, LocalAuditInspectionBounds::DEFAULT)
}

fn last_local_audit_operation_with_bounds(
    path: &Path,
    bounds: LocalAuditInspectionBounds,
) -> Result<LocalAuditOperationView, EvidenceAuditError> {
    if bounds.maximum_segments == 0
        || bounds.maximum_records == 0
        || bounds.maximum_output_bytes == 0
    {
        return Err(EvidenceAuditError::Configuration);
    }
    if !path.is_absolute() {
        return Err(EvidenceAuditError::Configuration);
    }

    let _writer_lock = lock_stopped_audit_file(path)?;
    let files = local_audit_files(path, bounds.maximum_segments)?;
    let mut collector = LocalAuditCollector::new(bounds);
    for (index, file) in files.iter().enumerate() {
        collector.oldest_file = index == 0;
        read_local_audit_file(file, &mut collector)?;
    }
    collector.finish()
}

/// Take the writer's lock, refusing while a writer holds it. The lock is
/// released when the returned file is dropped.
fn lock_stopped_audit_file(path: &Path) -> Result<File, AuditError> {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock_path = PathBuf::from(lock_path);
    let lock = open_local_audit_file(&lock_path)?;
    match lock.try_lock() {
        Ok(()) => Ok(lock),
        Err(TryLockError::WouldBlock) => Err(AuditError::SinkLocked {
            path: lock_path.display().to_string(),
        }),
        Err(TryLockError::Error(error)) => Err(AuditError::Io(error)),
    }
}

/// The retained sealed files in sequence order, then the active file.
fn local_audit_files(path: &Path, maximum_files: usize) -> Result<Vec<PathBuf>, AuditError> {
    let parent = path.parent().ok_or_else(invalid_audit_data)?;
    let active = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(invalid_audit_data)?;
    let mut sealed = Vec::new();
    for entry in std::fs::read_dir(parent).map_err(AuditError::Io)? {
        let candidate = entry.map_err(AuditError::Io)?.path();
        let sequence = candidate
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(active))
            .and_then(|suffix| suffix.strip_prefix('.'))
            .filter(|digits| digits.len() == 8 && digits.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|digits| digits.parse::<u64>().ok());
        if let Some(sequence) = sequence {
            sealed.push((sequence, candidate));
            if sealed.len() >= maximum_files {
                return Err(file_size_error());
            }
        }
    }
    sealed.sort_unstable_by_key(|(sequence, _)| *sequence);
    let mut files: Vec<PathBuf> = sealed.into_iter().map(|(_, file)| file).collect();
    files.push(path.to_path_buf());
    Ok(files)
}

fn read_local_audit_file(
    path: &Path,
    collector: &mut LocalAuditCollector,
) -> Result<(), AuditError> {
    let file = open_local_audit_file(path)?;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = (&mut reader)
            .take(MAXIMUM_LOCAL_AUDIT_LINE_BYTES + 1)
            .read_until(b'\n', &mut line)
            .map_err(AuditError::Io)?;
        if read == 0 {
            return Ok(());
        }
        // A line without its newline is either longer than any entry the
        // writer produces or a torn final write; neither is a whole entry.
        if line.pop() != Some(b'\n') {
            return Err(invalid_audit_data());
        }
        let entry: StoredAuditEntry =
            serde_json::from_slice(&line).map_err(|_| invalid_audit_data())?;
        collector.collect(entry)?;
    }
}

/// Open an audit file for reading without following a symbolic link, and
/// require a regular file.
fn open_local_audit_file(path: &Path) -> Result<File, AuditError> {
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits() as i32)
        .open(path)
        .map_err(AuditError::Io)?;
    if !file.metadata().map_err(AuditError::Io)?.is_file() {
        return Err(invalid_audit_data());
    }
    Ok(file)
}

fn invalid_audit_data() -> AuditError {
    AuditError::Io(IoError::new(
        ErrorKind::InvalidData,
        "audit record is invalid",
    ))
}

fn file_size_error() -> AuditError {
    AuditError::Io(IoError::other("audit file size bound exceeded"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Seek, SeekFrom, Write},
        sync::Arc,
    };

    use registry_platform_audit::FileDestination;

    fn request_batch_item_group(
        indices: Vec<u8>,
        pseudonym_digit: char,
    ) -> EvidenceRequestBatchAuditItemGroup {
        EvidenceRequestBatchAuditItemGroup {
            item_indices: indices,
            authority: AuditAuthority {
                kind: AuthorityKind::Statutory,
                grant_pseudonym: None,
                approver_pseudonym: None,
            },
            subjects: vec![AuditSubject {
                role: "subject".to_owned(),
                selector_profile: "profile-v1".to_owned(),
                selector_bundle_pseudonym: Some(format!(
                    "hmac-sha256:v1:{}",
                    pseudonym_digit.to_string().repeat(64)
                )),
            }],
        }
    }

    fn request_batch_event(
        phase: EvidenceRequestBatchAuditPhase,
        decision: EvidenceRequestBatchAuditDecision,
    ) -> EvidenceRequestBatchAuditEvent {
        EvidenceRequestBatchAuditEvent::new(
            AssuranceProfile::EvidenceGrade,
            "operation-request-batch-audit".to_owned(),
            phase,
            "urn:example:requirement:v1".to_owned(),
            format!("sha256:{}", "0".repeat(64)),
            "casework".to_owned(),
            "hmac-sha256:v1:1111111111111111111111111111111111111111111111111111111111111111"
                .to_owned(),
            decision,
            5,
        )
    }

    #[test]
    fn request_batch_audit_groups_partition_items_and_terminal_shapes_are_closed() {
        let mut access = request_batch_event(
            EvidenceRequestBatchAuditPhase::AccessAttempt,
            EvidenceRequestBatchAuditDecision::Authorized,
        );
        access.source_id = Some("source-a".to_owned());
        access.adapter_id = Some("adapter-a".to_owned());
        access.item_indices = Some(vec![0, 1, 2]);
        // Equal items may be grouped even when their positions are not
        // adjacent. Groups remain ordered by their first item index.
        access.item_groups = Some(vec![
            request_batch_item_group(vec![0, 2], '2'),
            request_batch_item_group(vec![1], '3'),
        ]);
        access
            .validate_phase_fields()
            .expect("non-adjacent equal item grouping is a complete partition");

        let mut split_equivalent_groups = access.clone();
        split_equivalent_groups.item_groups = Some(vec![
            request_batch_item_group(vec![0], '2'),
            request_batch_item_group(vec![1], '3'),
            request_batch_item_group(vec![2], '2'),
        ]);
        assert!(matches!(
            split_equivalent_groups.validate_phase_fields(),
            Err(EvidenceAuditError::InvalidEvent)
        ));

        let mut release = request_batch_event(
            EvidenceRequestBatchAuditPhase::DisclosureRelease,
            EvidenceRequestBatchAuditDecision::Released,
        );
        release.item_groups = access.item_groups.clone();
        release.disclosed_concepts = Some(Vec::new());
        release.outcomes = Some(vec![
            EvidenceRequestBatchAuditOutcome {
                item_index: 0,
                outcome: EvidenceRequestBatchAuditOutcomeKind::EvidenceNotAvailable,
                evidence_id: None,
            },
            EvidenceRequestBatchAuditOutcome {
                item_index: 1,
                outcome: EvidenceRequestBatchAuditOutcomeKind::EvidenceNotAvailable,
                evidence_id: None,
            },
            EvidenceRequestBatchAuditOutcome {
                item_index: 2,
                outcome: EvidenceRequestBatchAuditOutcomeKind::EvidenceNotAvailable,
                evidence_id: None,
            },
        ]);
        release
            .validate_phase_fields()
            .expect("all-unavailable release correctly names no signing key");
        release.signing_key_id = Some("signing-key-that-was-not-used".to_owned());
        assert!(matches!(
            release.validate_phase_fields(),
            Err(EvidenceAuditError::InvalidEvent)
        ));

        let mut aborted = request_batch_event(
            EvidenceRequestBatchAuditPhase::TerminalFailure,
            EvidenceRequestBatchAuditDecision::Aborted,
        );
        aborted.safe_error_category = Some("source-status".to_owned());
        aborted
            .validate_phase_fields()
            .expect("value-free terminal failure is valid");
        aborted.item_groups = access.item_groups;
        assert!(matches!(
            aborted.validate_phase_fields(),
            Err(EvidenceAuditError::InvalidEvent)
        ));
    }

    #[test]
    fn request_batch_audit_contract_schema_accepts_every_phase_and_rejects_mixed_shapes() {
        let schema: serde_json::Value = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/contracts/request-batch-audit-event.schema.yaml"
        ))
        .expect("request-batch audit event schema parses");
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .expect("request-batch audit event schema compiles as Draft 2020-12");

        let mut access = request_batch_event(
            EvidenceRequestBatchAuditPhase::AccessAttempt,
            EvidenceRequestBatchAuditDecision::Authorized,
        );
        access.source_id = Some("source-a".to_owned());
        access.adapter_id = Some("adapter-a".to_owned());
        access.item_indices = Some(vec![0, 1]);
        access.item_groups = Some(vec![
            request_batch_item_group(vec![0], '2'),
            request_batch_item_group(vec![1], '3'),
        ]);

        let mut mixed_release = request_batch_event(
            EvidenceRequestBatchAuditPhase::DisclosureRelease,
            EvidenceRequestBatchAuditDecision::Released,
        );
        mixed_release.item_groups = access.item_groups.clone();
        mixed_release.disclosed_concepts = Some(vec!["urn:example:concept:eligible".to_owned()]);
        mixed_release.signing_key_id = Some("signing-key-a".to_owned());
        mixed_release.outcomes = Some(vec![
            EvidenceRequestBatchAuditOutcome {
                item_index: 0,
                outcome: EvidenceRequestBatchAuditOutcomeKind::Evidence,
                evidence_id: Some("urn:example:evidence:batch-item-0".to_owned()),
            },
            EvidenceRequestBatchAuditOutcome {
                item_index: 1,
                outcome: EvidenceRequestBatchAuditOutcomeKind::EvidenceNotAvailable,
                evidence_id: None,
            },
        ]);

        let mut all_unavailable_release = mixed_release.clone();
        all_unavailable_release.disclosed_concepts = Some(Vec::new());
        all_unavailable_release.signing_key_id = None;
        all_unavailable_release.outcomes = Some(vec![
            EvidenceRequestBatchAuditOutcome {
                item_index: 0,
                outcome: EvidenceRequestBatchAuditOutcomeKind::EvidenceNotAvailable,
                evidence_id: None,
            },
            EvidenceRequestBatchAuditOutcome {
                item_index: 1,
                outcome: EvidenceRequestBatchAuditOutcomeKind::EvidenceNotAvailable,
                evidence_id: None,
            },
        ]);

        let mut abort = request_batch_event(
            EvidenceRequestBatchAuditPhase::TerminalFailure,
            EvidenceRequestBatchAuditDecision::Aborted,
        );
        abort.safe_error_category = Some("source-status".to_owned());

        for (name, event) in [
            ("access", &access),
            ("mixed-release", &mixed_release),
            ("all-unavailable-release", &all_unavailable_release),
            ("abort", &abort),
        ] {
            event
                .validate_phase_fields()
                .unwrap_or_else(|error| panic!("native rules reject {name}: {error}"));
            let value = serde_json::to_value(event).expect("request-batch event serializes");
            assert!(validator.is_valid(&value), "schema rejects {name}");
        }

        let mut release_fields_on_access = access.clone();
        release_fields_on_access.disclosed_concepts = Some(Vec::new());
        release_fields_on_access.outcomes = all_unavailable_release.outcomes.clone();

        let mut source_fields_on_release = mixed_release.clone();
        source_fields_on_release.source_id = Some("source-a".to_owned());
        source_fields_on_release.adapter_id = Some("adapter-a".to_owned());

        let mut item_fields_on_abort = abort.clone();
        item_fields_on_abort.item_groups = access.item_groups.clone();

        let mut signing_key_on_all_unavailable = all_unavailable_release.clone();
        signing_key_on_all_unavailable.signing_key_id = Some("unused-signing-key".to_owned());

        for (name, event) in [
            ("release-fields-on-access", release_fields_on_access),
            ("source-fields-on-release", source_fields_on_release),
            ("item-fields-on-abort", item_fields_on_abort),
            (
                "signing-key-on-all-unavailable",
                signing_key_on_all_unavailable,
            ),
        ] {
            assert!(
                matches!(
                    event.validate_phase_fields(),
                    Err(EvidenceAuditError::InvalidEvent)
                ),
                "native rules accept mixed request-batch event {name}"
            );
            let value = serde_json::to_value(event).expect("request-batch event serializes");
            assert!(
                !validator.is_valid(&value),
                "schema accepts mixed event {name}"
            );
        }

        let mut request_derived_canary =
            serde_json::to_value(access).expect("request-batch access serializes");
        request_derived_canary
            .as_object_mut()
            .expect("request-batch access is an object")
            .insert(
                "requestNonce".to_owned(),
                serde_json::json!("request-derived-canary"),
            );
        assert!(
            !validator.is_valid(&request_derived_canary),
            "schema accepts a request-derived field"
        );
        assert!(
            serde_json::from_value::<EvidenceRequestBatchAuditEvent>(request_derived_canary)
                .is_err(),
            "native event type accepts a request-derived field"
        );
    }

    fn event(log: &EvidenceAuditLog) -> EvidenceAuditEvent {
        EvidenceAuditEvent::new(
            AssuranceProfile::EvidenceGrade,
            "01K1EXAMPLE0000000000000000".to_string(),
            AuditPhase::AccessAttempt,
            "urn:example:requirement:v1".to_string(),
            format!("sha256:{}", "0".repeat(64)),
            "casework".to_string(),
            log.pseudonym("requester-v1", "urn:example:trust", b"principal-canary")
                .expect("pseudonym builds"),
            AuditAuthority {
                kind: AuthorityKind::Statutory,
                grant_pseudonym: None,
                approver_pseudonym: None,
            },
            vec![AuditSubject {
                role: "subject".to_string(),
                selector_profile: "person-v1".to_string(),
                selector_bundle_pseudonym: Some(
                    log.pseudonym("subject-v1", "casework", b"selector-canary")
                        .expect("pseudonym builds"),
                ),
            }],
            ResponseProtection::Signed,
            AuditDecision::Authorized,
            5,
        )
    }

    /// Frozen shape of a release that closed a multi-stage acquisition: three
    /// executed stages in execution order, two of which share one adapter, and
    /// scalars naming the last stage.
    fn fixture_multi_stage_release() -> EvidenceAuditEvent {
        let mut release = EvidenceAuditEvent::new(
            AssuranceProfile::EvidenceGrade,
            "fixture-operation-00000003".to_owned(),
            AuditPhase::DisclosureRelease,
            "urn:example:fixture:requirement:property:v1".to_owned(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "fixture-procedure".to_owned(),
            "hmac-sha256:v1:1111111111111111111111111111111111111111111111111111111111111111"
                .to_owned(),
            AuditAuthority {
                kind: AuthorityKind::Statutory,
                grant_pseudonym: None,
                approver_pseudonym: None,
            },
            vec![AuditSubject {
                role: "subject".to_owned(),
                selector_profile: "opaque-record-v1".to_owned(),
                selector_bundle_pseudonym: Some(
                    "hmac-sha256:v1:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_owned(),
                ),
            }],
            ResponseProtection::Signed,
            AuditDecision::Released,
            21,
        );
        release.event_id = "urn:example:fixture:audit:release-003".to_owned();
        release.occurred_at = "2026-08-02T00:00:04Z".to_owned();
        release.source_id = Some("source-c".to_owned());
        release.adapter_id = Some("adapter-b".to_owned());
        release.source_ids = Some(vec![
            "source-a".to_owned(),
            "source-b".to_owned(),
            "source-c".to_owned(),
        ]);
        release.adapter_ids = Some(vec![
            "adapter-a".to_owned(),
            "adapter-b".to_owned(),
            "adapter-b".to_owned(),
        ]);
        release.disclosed_concepts = Some(vec!["urn:example:fixture:concept:boolean-a".to_owned()]);
        release.evidence_id = Some("urn:example:fixture:evidence:002".to_owned());
        release.signing_key_id = Some("_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo".to_owned());
        release
    }

    #[test]
    fn frozen_audit_fixture_matches_native_event_shape_and_phase_rules() {
        let fixture: serde_json::Value = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/fixtures/conformance/audit-events.yaml"
        ))
        .expect("frozen audit fixture parses");
        assert_eq!(
            fixture["fixture"],
            serde_json::json!("registry.evidence.audit-events/v2")
        );
        assert_eq!(fixture["synthetic_only"], serde_json::json!(true));

        let access = EvidenceAuditEvent {
            assurance_profile: AssuranceProfile::EvidenceGrade,
            event_id: "urn:example:fixture:audit:access-001".to_owned(),
            occurred_at: "2026-08-02T00:00:00Z".to_owned(),
            operation: "fixture-operation-00000001".to_owned(),
            phase: AuditPhase::AccessAttempt,
            requirement: "urn:example:fixture:requirement:property:v1".to_owned(),
            bundle_revision:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
            purpose: "fixture-procedure".to_owned(),
            requester_pseudonym:
                "hmac-sha256:v1:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_owned(),
            actor_kind: ActorKind::Service,
            client_pseudonym: None,
            actor_pseudonym: None,
            authority: AuditAuthority {
                kind: AuthorityKind::Statutory,
                grant_pseudonym: None,
                approver_pseudonym: None,
            },
            subjects: vec![AuditSubject {
                role: "subject".to_owned(),
                selector_profile: "opaque-record-v1".to_owned(),
                selector_bundle_pseudonym: Some(
                    "hmac-sha256:v1:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_owned(),
                ),
            }],
            response_protection: ResponseProtection::Signed,
            source_id: Some("source-a".to_owned()),
            adapter_id: Some("adapter-a".to_owned()),
            source_ids: None,
            adapter_ids: None,
            decision: AuditDecision::Authorized,
            reason: "authorization.allowed".to_owned(),
            disclosed_concepts: None,
            evidence_id: None,
            evidence_ids: None,
            signing_key_id: None,
            safe_error_category: None,
            duration_milliseconds: 2,
        };
        access
            .validate_phase_fields()
            .expect("fixture access event satisfies native phase rules");
        assert_eq!(
            serde_json::to_value(&access).expect("access event serializes"),
            fixture["access_attempt"]
        );

        let mut release = access.clone();
        release.event_id = "urn:example:fixture:audit:release-001".to_owned();
        release.occurred_at = "2026-08-02T00:00:01Z".to_owned();
        release.phase = AuditPhase::DisclosureRelease;
        release.decision = AuditDecision::Released;
        release.disclosed_concepts = Some(vec!["urn:example:fixture:concept:boolean-a".to_owned()]);
        release.evidence_id = Some("urn:example:fixture:evidence:001".to_owned());
        release.signing_key_id = Some("_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo".to_owned());
        release.duration_milliseconds = 12;
        release
            .validate_phase_fields()
            .expect("fixture release event satisfies native phase rules");
        assert_eq!(
            serde_json::to_value(&release).expect("release event serializes"),
            fixture["disclosure_release"]
        );

        let mut unsigned_release = release.clone();
        unsigned_release.event_id = "urn:example:fixture:audit:release-002".to_owned();
        unsigned_release.occurred_at = "2026-08-02T00:00:02Z".to_owned();
        unsigned_release.response_protection = ResponseProtection::Unsigned;
        unsigned_release.signing_key_id = None;
        unsigned_release
            .validate_phase_fields()
            .expect("fixture unsigned release event satisfies native phase rules");
        assert_eq!(
            serde_json::to_value(&unsigned_release).expect("unsigned release event serializes"),
            fixture["unsigned_disclosure_release"]
        );
        unsigned_release.signing_key_id =
            Some("_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo".to_owned());
        assert!(matches!(
            unsigned_release.validate_phase_fields(),
            Err(EvidenceAuditError::InvalidEvent)
        ));

        let fetch_set_release = fixture_multi_stage_release();
        fetch_set_release
            .validate_phase_fields()
            .expect("fixture multi-stage release event satisfies native phase rules");
        assert_eq!(
            serde_json::to_value(&fetch_set_release).expect("multi-stage release event serializes"),
            fixture["disclosure_release_fetch_set"]
        );

        // The stage arrays are additive: a single-stage acquisition emits no
        // key for them at all, so every frozen shape stays byte-identical.
        for (name, event) in [("access", &access), ("release", &release)] {
            let serialized = serde_json::to_value(event).expect("event serializes");
            let object = serialized.as_object().expect("event is an object");
            assert!(
                !object.contains_key("sourceIds") && !object.contains_key("adapterIds"),
                "single-stage {name} event emits a stage array key"
            );
        }

        let refusal = EvidenceAuthorizationRefusalAuditEvent {
            assurance_profile: AssuranceProfile::EvidenceGrade,
            event_id: "urn:example:fixture:audit:authorization-refusal-001".to_owned(),
            occurred_at: "2026-08-02T00:00:03Z".to_owned(),
            operation: "fixture-operation-00000002".to_owned(),
            phase: AuditPhase::Denial,
            bundle_revision:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            requester_pseudonym:
                "hmac-sha256:v1:3333333333333333333333333333333333333333333333333333333333333333"
                    .to_owned(),
            actor_kind: ActorKind::Service,
            client_pseudonym: None,
            grant_pseudonym: None,
            actor_pseudonym: Some(
                "hmac-sha256:v1:4444444444444444444444444444444444444444444444444444444444444444"
                    .to_owned(),
            ),
            decision: AuthorizationRefusalAuditDecision::NotAuthorized,
            safe_error_category: "not-authorized".to_owned(),
            reason: "authorization.profile".to_owned(),
            duration_milliseconds: 3,
        };
        refusal
            .validate_phase_fields()
            .expect("fixture authorization refusal satisfies native phase rules");
        assert_eq!(
            serde_json::to_value(&refusal).expect("authorization refusal serializes"),
            fixture["authorization_refusal"]
        );

        let mut signed_release_without_key = release.clone();
        signed_release_without_key.signing_key_id = None;
        assert!(matches!(
            signed_release_without_key.validate_phase_fields(),
            Err(EvidenceAuditError::InvalidEvent)
        ));

        let mut release_fields_on_access = access;
        release_fields_on_access.disclosed_concepts = release.disclosed_concepts.clone();
        release_fields_on_access.evidence_id = release.evidence_id.clone();
        release_fields_on_access.signing_key_id = release.signing_key_id.clone();
        assert!(matches!(
            release_fields_on_access.validate_phase_fields(),
            Err(EvidenceAuditError::InvalidEvent)
        ));
        release.evidence_id = None;
        assert!(matches!(
            release.validate_phase_fields(),
            Err(EvidenceAuditError::InvalidEvent)
        ));

        assert_eq!(
            fixture["order"],
            serde_json::json!({
                "authorization_refusal_durable_before": ["not-authorized-response"],
                "access_attempt_durable_before": ["credential-resolution", "source-access"],
                "disclosure_release_durable_after": ["signing"],
                "disclosure_release_durable_before": ["response-release"]
            })
        );
        assert_eq!(
            fixture["negative"],
            serde_json::json!([
                "raw-principal",
                "raw-actor-or-grant",
                "raw-selector-value",
                "separate-field-hash",
                "plain-sha256-subject-hash",
                "base64url-reencoded-audit-hmac",
                "globally-stable-subject-pseudonym",
                "source-or-supported-value",
                "credential-token-or-private-key",
                "candidate-count-score-hint-or-comparison",
                "release-fields-on-access-event",
                "missing-release-fields-on-release-event",
                "signing-key-on-unsigned-release-event",
                "missing-signing-key-on-signed-release-event",
                "request-derived-field-on-authorization-refusal",
                "unmatched-authority-on-authorization-refusal",
                "response-protection-on-authorization-refusal",
                "missing-authorization-refusal-category",
                "authorization-refusal-under-authorized-envelope-schema",
                "authorized-event-under-refusal-envelope-schema",
                "request-nonce-in-any-event",
                "stage-arrays-on-non-release-event",
                "mismatched-stage-arrays-on-release-event"
            ])
        );
    }

    #[test]
    fn audit_contract_schema_accepts_each_native_shape_and_rejects_mixed_shapes() {
        let schema: serde_json::Value = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/contracts/audit-event.schema.yaml"
        ))
        .expect("audit event schema parses");
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .expect("audit event schema compiles as Draft 2020-12");
        let fixture: serde_json::Value = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/fixtures/conformance/audit-events.yaml"
        ))
        .expect("frozen audit fixture parses");

        for name in [
            "access_attempt",
            "disclosure_release",
            "unsigned_disclosure_release",
            "disclosure_release_fetch_set",
            "authorization_refusal",
        ] {
            assert!(
                validator.is_valid(&fixture[name]),
                "schema rejects positive fixture {name}"
            );
        }

        let mut unresolved = fixture["access_attempt"].clone();
        unresolved["phase"] = serde_json::json!("denial");
        unresolved["decision"] = serde_json::json!("unresolved");
        unresolved["safeErrorCategory"] = serde_json::json!("unresolved");
        assert!(
            validator.is_valid(&unresolved),
            "schema rejects the neutral declared-unresolved denial"
        );

        // The schema id is the envelope's, never a record field.
        let mut refusal_with_record_schema = fixture["authorization_refusal"].clone();
        refusal_with_record_schema["schema"] =
            serde_json::json!(AUTHORIZATION_REFUSAL_AUDIT_SCHEMA);

        let mut authorized_with_record_schema = fixture["access_attempt"].clone();
        authorized_with_record_schema["schema"] = serde_json::json!(AUDIT_SCHEMA);

        let mut polluted_refusal = fixture["authorization_refusal"].clone();
        let polluted = polluted_refusal
            .as_object_mut()
            .expect("refusal fixture is an object");
        polluted.insert(
            "requirement".to_owned(),
            serde_json::json!("urn:example:requirement:probe:v1"),
        );
        polluted.insert("purpose".to_owned(), serde_json::json!("probe"));
        polluted.insert(
            "authority".to_owned(),
            serde_json::json!({"kind": "statutory"}),
        );
        polluted.insert(
            "subjects".to_owned(),
            serde_json::json!([{"role": "subject", "selectorProfile": "person-v1"}]),
        );
        polluted.insert("responseProtection".to_owned(), serde_json::json!("signed"));
        polluted.insert(
            "requestNonce".to_owned(),
            serde_json::json!("request-derived-canary"),
        );

        let mut stage_arrays_on_access = fixture["access_attempt"].clone();
        let access_object = stage_arrays_on_access
            .as_object_mut()
            .expect("access fixture is an object");
        access_object.insert(
            "sourceIds".to_owned(),
            fixture["disclosure_release_fetch_set"]["sourceIds"].clone(),
        );
        access_object.insert(
            "adapterIds".to_owned(),
            fixture["disclosure_release_fetch_set"]["adapterIds"].clone(),
        );

        let mut release_without_adapter_ids = fixture["disclosure_release_fetch_set"].clone();
        release_without_adapter_ids
            .as_object_mut()
            .expect("multi-stage release fixture is an object")
            .remove("adapterIds");

        let mut release_without_source_ids = fixture["disclosure_release_fetch_set"].clone();
        release_without_source_ids
            .as_object_mut()
            .expect("multi-stage release fixture is an object")
            .remove("sourceIds");

        let mut release_without_scalar_source = fixture["disclosure_release_fetch_set"].clone();
        release_without_scalar_source
            .as_object_mut()
            .expect("multi-stage release fixture is an object")
            .remove("sourceId");

        let mut release_with_one_stage_array = fixture["disclosure_release_fetch_set"].clone();
        release_with_one_stage_array["sourceIds"] = serde_json::json!(["source-a"]);

        let mut release_with_repeated_source = fixture["disclosure_release_fetch_set"].clone();
        release_with_repeated_source["sourceIds"] =
            serde_json::json!(["source-a", "source-a", "source-c"]);

        // The arrays are positionally aligned, so one more adapter than source
        // describes no acquisition. An external reader validating against the
        // published schema alone must reject it, exactly as this runtime does.
        let mut release_with_unequal_arrays = fixture["disclosure_release_fetch_set"].clone();
        release_with_unequal_arrays["adapterIds"] =
            serde_json::json!(["adapter-a", "adapter-b", "adapter-c", "adapter-d"]);

        let mut refusal_with_stage_arrays = fixture["authorization_refusal"].clone();
        refusal_with_stage_arrays
            .as_object_mut()
            .expect("refusal fixture is an object")
            .insert(
                "sourceIds".to_owned(),
                fixture["disclosure_release_fetch_set"]["sourceIds"].clone(),
            );

        for (name, candidate) in [
            ("refusal-with-record-schema", refusal_with_record_schema),
            (
                "authorized-with-record-schema",
                authorized_with_record_schema,
            ),
            ("polluted-refusal", polluted_refusal),
            ("stage-arrays-on-access", stage_arrays_on_access),
            ("release-without-adapter-ids", release_without_adapter_ids),
            ("release-without-source-ids", release_without_source_ids),
            (
                "release-without-scalar-source",
                release_without_scalar_source,
            ),
            ("release-with-one-stage-array", release_with_one_stage_array),
            ("release-with-repeated-source", release_with_repeated_source),
            ("release-with-unequal-arrays", release_with_unequal_arrays),
            ("refusal-with-stage-arrays", refusal_with_stage_arrays),
        ] {
            assert!(
                !validator.is_valid(&candidate),
                "schema accepts mixed audit shape {name}"
            );
        }
    }

    #[test]
    fn multi_stage_release_names_every_executed_stage_in_execution_order() {
        let release = fixture_multi_stage_release();
        release
            .validate_phase_fields()
            .expect("a multi-stage release names every executed stage");

        // Two members may legitimately read one register through one adapter,
        // so only the source identities are required to be distinct.
        let mut shared_adapter = release.clone();
        shared_adapter.adapter_ids = Some(vec!["adapter-a".to_owned(); 3]);
        shared_adapter.adapter_id = Some("adapter-a".to_owned());
        shared_adapter
            .validate_phase_fields()
            .expect("members may share one adapter");

        let mut widest = release.clone();
        widest.source_ids = Some(vec![
            "source-a".to_owned(),
            "source-b".to_owned(),
            "source-c".to_owned(),
            "source-d".to_owned(),
            "source-e".to_owned(),
        ]);
        widest.adapter_ids = Some(vec!["adapter-a".to_owned(); 5]);
        widest.adapter_id = Some("adapter-a".to_owned());
        widest.source_id = Some("source-e".to_owned());
        widest
            .validate_phase_fields()
            .expect("a search and four members is the widest acquisition");

        let mut arrays_on_access = release.clone();
        arrays_on_access.phase = AuditPhase::AccessAttempt;
        arrays_on_access.decision = AuditDecision::Authorized;
        arrays_on_access.disclosed_concepts = None;
        arrays_on_access.evidence_id = None;
        arrays_on_access.signing_key_id = None;

        let mut source_ids_alone = release.clone();
        source_ids_alone.adapter_ids = None;

        let mut adapter_ids_alone = release.clone();
        adapter_ids_alone.source_ids = None;

        let mut unequal_lengths = release.clone();
        unequal_lengths.adapter_ids = Some(vec!["adapter-a".to_owned(), "adapter-b".to_owned()]);

        let mut too_narrow = release.clone();
        too_narrow.source_ids = Some(vec!["source-a".to_owned(), "source-c".to_owned()]);
        too_narrow.adapter_ids = Some(vec!["adapter-a".to_owned(), "adapter-b".to_owned()]);

        let mut too_wide = release.clone();
        too_wide.source_ids = Some(vec![
            "source-a".to_owned(),
            "source-b".to_owned(),
            "source-d".to_owned(),
            "source-e".to_owned(),
            "source-f".to_owned(),
            "source-c".to_owned(),
        ]);
        too_wide.adapter_ids = Some(vec!["adapter-b".to_owned(); 6]);

        let mut stale_scalar_source = release.clone();
        stale_scalar_source.source_id = Some("source-a".to_owned());

        let mut stale_scalar_adapter = release.clone();
        stale_scalar_adapter.adapter_id = Some("adapter-a".to_owned());

        let mut missing_scalars = release.clone();
        missing_scalars.source_id = None;
        missing_scalars.adapter_id = None;

        let mut repeated_source = release.clone();
        repeated_source.source_ids = Some(vec![
            "source-a".to_owned(),
            "source-a".to_owned(),
            "source-c".to_owned(),
        ]);

        let mut unnamed_stage = release.clone();
        unnamed_stage.source_ids = Some(vec![
            "source-a".to_owned(),
            "Source-B".to_owned(),
            "source-c".to_owned(),
        ]);

        for (name, candidate) in [
            ("arrays-on-access", arrays_on_access),
            ("source-ids-alone", source_ids_alone),
            ("adapter-ids-alone", adapter_ids_alone),
            ("unequal-lengths", unequal_lengths),
            ("too-narrow", too_narrow),
            ("too-wide", too_wide),
            ("stale-scalar-source", stale_scalar_source),
            ("stale-scalar-adapter", stale_scalar_adapter),
            ("missing-scalars", missing_scalars),
            ("repeated-source", repeated_source),
            ("unnamed-stage", unnamed_stage),
        ] {
            assert!(
                matches!(
                    candidate.validate_phase_fields(),
                    Err(EvidenceAuditError::InvalidEvent)
                ),
                "native phase rules accept invalid stage arrays {name}"
            );
        }
    }

    /// A release that carried more than one assertion, named as one terminal
    /// event over the complete released set.
    fn fixture_batch_release() -> EvidenceAuditEvent {
        let mut release = fixture_multi_stage_release();
        release.event_id = "urn:example:fixture:audit:release-004".to_owned();
        release.occurred_at = "2026-08-02T00:00:05Z".to_owned();
        release.evidence_id = None;
        release.evidence_ids = Some(vec![
            "urn:example:fixture:evidence:003".to_owned(),
            "urn:example:fixture:evidence:004".to_owned(),
        ]);
        release
    }

    #[test]
    fn a_release_names_the_set_it_released_exactly_once() {
        fixture_batch_release()
            .validate_phase_fields()
            .expect("a batch release names the complete released set");

        let mut widest = fixture_batch_release();
        widest.evidence_ids = Some(
            (0..usize::from(MAXIMUM_HOLDER_BOUND_BATCH_SIZE))
                .map(|index| format!("urn:example:fixture:evidence:batch-{index}"))
                .collect(),
        );
        widest
            .validate_phase_fields()
            .expect("the batch ceiling is a releasable size");

        // Both names present would let a reader count one release twice, and
        // neither leaves the terminal event without the set it released.
        let mut both_names = fixture_batch_release();
        both_names.evidence_id = Some("urn:example:fixture:evidence:003".to_owned());

        let mut neither_name = fixture_batch_release();
        neither_name.evidence_ids = None;

        // The set names a batch, so one member is the scalar's shape, not this
        // one, and a repeated identifier describes no release at all.
        let mut single_member = fixture_batch_release();
        single_member.evidence_ids = Some(vec!["urn:example:fixture:evidence:003".to_owned()]);

        let mut repeated_member = fixture_batch_release();
        repeated_member.evidence_ids = Some(vec![
            "urn:example:fixture:evidence:003".to_owned(),
            "urn:example:fixture:evidence:003".to_owned(),
        ]);

        let mut past_the_ceiling = fixture_batch_release();
        past_the_ceiling.evidence_ids = Some(
            (0..=usize::from(MAXIMUM_HOLDER_BOUND_BATCH_SIZE))
                .map(|index| format!("urn:example:fixture:evidence:batch-{index}"))
                .collect(),
        );

        let mut unnamed_member = fixture_batch_release();
        unnamed_member.evidence_ids = Some(vec![
            "urn:example:fixture:evidence:003".to_owned(),
            "not an identifier".to_owned(),
        ]);

        let mut set_on_access = fixture_batch_release();
        set_on_access.phase = AuditPhase::AccessAttempt;
        set_on_access.decision = AuditDecision::Authorized;
        set_on_access.disclosed_concepts = None;
        set_on_access.signing_key_id = None;
        set_on_access.source_ids = None;
        set_on_access.adapter_ids = None;

        for (name, candidate) in [
            ("both-names", both_names),
            ("neither-name", neither_name),
            ("single-member", single_member),
            ("repeated-member", repeated_member),
            ("past-the-ceiling", past_the_ceiling),
            ("unnamed-member", unnamed_member),
            ("set-on-access", set_on_access),
        ] {
            assert!(
                matches!(
                    candidate.validate_phase_fields(),
                    Err(EvidenceAuditError::InvalidEvent)
                ),
                "native phase rules accept invalid released set {name}"
            );
        }

        // A release of one assertion stays byte-identical: the batch key is
        // additive, so no existing frozen shape moves.
        let one_assertion = fixture_multi_stage_release();
        let serialized = serde_json::to_value(&one_assertion).expect("release serializes");
        assert!(
            !serialized
                .as_object()
                .expect("release is an object")
                .contains_key("evidenceIds"),
            "a release of one assertion emits the batch key"
        );
    }

    #[test]
    fn audit_contract_schema_agrees_on_the_released_set() {
        let schema: serde_json::Value = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/contracts/audit-event.schema.yaml"
        ))
        .expect("audit event schema parses");
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .expect("audit event schema compiles as Draft 2020-12");

        let batch =
            serde_json::to_value(fixture_batch_release()).expect("batch release serializes");
        assert!(
            validator.is_valid(&batch),
            "schema rejects a release naming the complete released set"
        );

        let mut both_names = batch.clone();
        both_names["evidenceId"] = serde_json::json!("urn:example:fixture:evidence:003");

        let mut neither_name = batch.clone();
        neither_name
            .as_object_mut()
            .expect("batch release is an object")
            .remove("evidenceIds");

        let mut single_member = batch.clone();
        single_member["evidenceIds"] = serde_json::json!(["urn:example:fixture:evidence:003"]);

        let mut repeated_member = batch.clone();
        repeated_member["evidenceIds"] = serde_json::json!([
            "urn:example:fixture:evidence:003",
            "urn:example:fixture:evidence:003"
        ]);

        let mut set_on_access = batch.clone();
        let access_object = set_on_access
            .as_object_mut()
            .expect("batch release is an object");
        access_object.insert("phase".to_owned(), serde_json::json!("access-attempt"));
        access_object.insert("decision".to_owned(), serde_json::json!("authorized"));
        access_object.remove("disclosedConcepts");
        access_object.remove("signingKeyId");
        access_object.remove("sourceIds");
        access_object.remove("adapterIds");

        let mut set_on_refusal = batch;
        let refusal_object = set_on_refusal
            .as_object_mut()
            .expect("batch release is an object");
        refusal_object.insert("phase".to_owned(), serde_json::json!("denial"));
        refusal_object.insert("decision".to_owned(), serde_json::json!("not-authorized"));
        refusal_object.insert(
            "safeErrorCategory".to_owned(),
            serde_json::json!("not-authorized"),
        );

        for (name, candidate) in [
            ("both-names", both_names),
            ("neither-name", neither_name),
            ("single-member", single_member),
            ("repeated-member", repeated_member),
            ("set-on-access", set_on_access),
            ("set-on-refusal", set_on_refusal),
        ] {
            assert!(
                !validator.is_valid(&candidate),
                "schema accepts invalid released set {name}"
            );
        }
    }

    const MASTER: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn file_destination(path: &Path) -> AuditDestination {
        AuditDestination::File(FileDestination::new(path).expect("audit path is absolute"))
    }

    async fn file_log(path: &Path) -> EvidenceAuditLog {
        EvidenceAuditLog::initialize(file_destination(path), MASTER.to_vec(), 1)
            .await
            .expect("audit initializes")
    }

    /// Lines a stream writer emitted, shared with the test that reads them.
    #[derive(Clone, Default)]
    struct CapturedLines(Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for CapturedLines {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("capture lock")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl CapturedLines {
        fn entries(&self) -> Vec<serde_json::Value> {
            let bytes = self.0.lock().expect("capture lock").clone();
            String::from_utf8(bytes)
                .expect("entries are UTF-8")
                .lines()
                .map(|line| serde_json::from_str(line).expect("entry is JSON"))
                .collect()
        }
    }

    fn captured_log() -> (EvidenceAuditLog, CapturedLines) {
        let captured = CapturedLines::default();
        let writer = AuditWriter::from_line_sink(Box::new(captured.clone()));
        let log =
            EvidenceAuditLog::with_writer(writer, MASTER.to_vec(), 1).expect("audit key derives");
        (log, captured)
    }

    struct RefusingSink;

    impl Write for RefusingSink {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("destination refused the write"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Write entries exactly as given, bypassing the native record checks, so
    /// the local reader's own checks are what a test exercises.
    async fn append_raw_entries(path: &Path, entries: Vec<AuditEntry>) {
        let writer = AuditWriter::open(file_destination(path))
            .await
            .expect("raw writer opens");
        for entry in entries {
            writer.append(entry).await.expect("raw entry appends");
        }
    }

    /// Seal the active file under the next sequence, as rotation does, so a
    /// test can build history across files without writing a whole rotation's
    /// worth of entries.
    fn seal_active_file(path: &Path, sequence: u64) {
        let mut sealed = path.as_os_str().to_os_string();
        sealed.push(format!(".{sequence:08}"));
        std::fs::rename(path, PathBuf::from(sealed)).expect("active file is sealed");
    }

    #[tokio::test]
    async fn audit_is_durable_keyed_and_redacted() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = file_log(&path).await;
        assert!(log.ready().await, "an opened destination is ready");
        log.append(event(&log)).await.expect("event appends");
        assert!(log.ready().await);

        let contents = std::fs::read_to_string(&path).expect("audit reads");
        assert!(!contents.contains("principal-canary"));
        assert!(!contents.contains("selector-canary"));
        assert!(contents.contains("hmac-sha256:v1:"));
        assert!(!contents.contains("hmac-sha256:v1:hmac-sha256:"));
        assert!(contents.ends_with('\n'));

        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .and_then(|mut file| file.write_all(b"{}\n"))
            .expect("tamper audit file");
        assert!(!log.ready().await, "readiness detects an external write");
    }

    #[test]
    fn pseudonyms_are_byte_identical_for_one_secret_and_key_version() {
        let (log, _) = captured_log();
        assert_eq!(
            log.pseudonym("requester-v1", "urn:example:trust", b"principal-canary")
                .expect("pseudonym builds"),
            "hmac-sha256:v1:4e879be5e2b07e5d7cdd40680e24f165c40712e3d375306d4c7d6ae50c66b68c",
        );
    }

    /// Entries are not chained, so nothing at startup can compare a master
    /// against earlier entries. What keeps two key epochs apart in one log is
    /// the pseudonym itself: the version is stamped into its prefix, and a
    /// different master yields a different digest for the same input.
    #[test]
    fn pseudonyms_keep_key_epochs_distinguishable() {
        let pseudonym = |master: &[u8], version: u32| {
            let writer = AuditWriter::from_line_sink(Box::new(CapturedLines::default()));
            EvidenceAuditLog::with_writer(writer, master.to_vec(), version)
                .expect("audit key derives")
                .pseudonym("requester-v1", "urn:example:trust", b"principal-canary")
                .expect("pseudonym builds")
        };
        let original = pseudonym(MASTER, 1);
        let next_version = pseudonym(MASTER, 2);
        let replaced_master = pseudonym(b"fedcba9876543210fedcba9876543210", 2);

        assert!(original.starts_with("hmac-sha256:v1:"));
        assert!(next_version.starts_with("hmac-sha256:v2:"));
        assert_ne!(original, next_version);
        assert_ne!(
            next_version, replaced_master,
            "a different master yields a different pseudonym for the same input"
        );
    }

    #[tokio::test]
    async fn entries_carry_the_envelope_schema_phase_and_correlation() {
        let (log, captured) = captured_log();
        let access = local_access(&log, "local-operation-0000000000000001");
        let release = local_release(&access);
        let refusal = local_authorization_refusal(&log, "local-refusal-000000000000000002");
        let mut batch_access = request_batch_event(
            EvidenceRequestBatchAuditPhase::AccessAttempt,
            EvidenceRequestBatchAuditDecision::Authorized,
        );
        batch_access.source_id = Some("source-a".to_owned());
        batch_access.adapter_id = Some("adapter-a".to_owned());
        batch_access.item_indices = Some(vec![0]);
        batch_access.item_groups = Some(vec![request_batch_item_group(vec![0], '2')]);
        let mut batch_abort = request_batch_event(
            EvidenceRequestBatchAuditPhase::TerminalFailure,
            EvidenceRequestBatchAuditDecision::Aborted,
        );
        batch_abort.safe_error_category = Some("source-status".to_owned());

        let expected = [
            (
                AUDIT_SCHEMA,
                "request",
                access.operation.clone(),
                serde_json::to_value(&access).expect("access serializes"),
            ),
            (
                AUDIT_SCHEMA,
                "response",
                release.operation.clone(),
                serde_json::to_value(&release).expect("release serializes"),
            ),
            (
                AUTHORIZATION_REFUSAL_AUDIT_SCHEMA,
                "response",
                refusal.operation.clone(),
                serde_json::to_value(&refusal).expect("refusal serializes"),
            ),
            (
                REQUEST_BATCH_AUDIT_SCHEMA,
                "request",
                batch_access.operation.clone(),
                serde_json::to_value(&batch_access).expect("batch access serializes"),
            ),
            (
                REQUEST_BATCH_AUDIT_SCHEMA,
                "response",
                batch_abort.operation.clone(),
                serde_json::to_value(&batch_abort).expect("batch abort serializes"),
            ),
        ];

        log.append(access).await.expect("access appends");
        log.append(release).await.expect("release appends");
        log.append_authorization_refusal(refusal)
            .await
            .expect("refusal appends");
        log.append_request_batch(batch_access)
            .await
            .expect("batch access appends");
        log.append_request_batch(batch_abort)
            .await
            .expect("batch abort appends");

        let entries = captured.entries();
        assert_eq!(entries.len(), expected.len());
        for (entry, (schema, phase, correlation, record)) in entries.iter().zip(expected) {
            assert_eq!(
                entry
                    .as_object()
                    .expect("entry is an object")
                    .keys()
                    .collect::<Vec<_>>(),
                [
                    "correlation",
                    "eventId",
                    "phase",
                    "record",
                    "schema",
                    "time"
                ]
            );
            assert_eq!(entry["schema"], serde_json::json!(schema));
            assert_eq!(entry["phase"], serde_json::json!(phase));
            assert_eq!(entry["correlation"], serde_json::json!(correlation));
            assert_eq!(entry["record"], record, "the record is the native event");
            assert!(
                entry["record"].get("schema").is_none(),
                "the schema id is the envelope's, never a record field"
            );
        }
    }

    #[tokio::test]
    async fn a_refused_write_stops_every_later_append() {
        let writer = AuditWriter::from_line_sink(Box::new(RefusingSink));
        let log =
            EvidenceAuditLog::with_writer(writer, MASTER.to_vec(), 1).expect("audit key derives");
        assert!(matches!(
            log.append(event(&log)).await,
            Err(EvidenceAuditError::Unavailable(_))
        ));
        assert!(!log.ready().await, "a refused write stops the writer");
        assert!(matches!(
            log.append_authorization_refusal(local_authorization_refusal(
                &log,
                "local-refusal-000000000000000001"
            ))
            .await,
            Err(EvidenceAuditError::Unavailable(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_appends_record_each_entry_exactly_once() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = Arc::new(file_log(&path).await);

        const CONCURRENCY: usize = 16;
        let mut handles = Vec::with_capacity(CONCURRENCY);
        for index in 0..CONCURRENCY {
            let log = Arc::clone(&log);
            handles.push(tokio::spawn(async move {
                let mut event = event(log.as_ref());
                event.operation = format!("concurrent-operation-{index:04}");
                log.append(event).await
            }));
        }
        for handle in handles {
            handle
                .await
                .expect("append task joins")
                .expect("a concurrent append is accepted");
        }
        assert!(log.ready().await);

        let mut correlations: Vec<String> = std::fs::read_to_string(&path)
            .expect("audit reads")
            .lines()
            .map(|line| {
                let entry: StoredAuditEntry = serde_json::from_str(line).expect("entry parses");
                assert_eq!(entry.schema, AUDIT_SCHEMA);
                assert_eq!(entry.phase, EntryPhase::Request);
                entry.correlation
            })
            .collect();
        correlations.sort_unstable();
        let expected: Vec<String> = (0..CONCURRENCY)
            .map(|index| format!("concurrent-operation-{index:04}"))
            .collect();
        assert_eq!(
            correlations, expected,
            "every concurrent append is durably recorded exactly once"
        );
    }

    #[tokio::test]
    async fn restart_appends_to_the_same_destination() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = file_log(&path).await;
            log.append(event(&log)).await.expect("event appends");
        }

        let restarted = file_log(&path).await;
        assert!(restarted.ready().await);
        restarted
            .append(event(&restarted))
            .await
            .expect("restarted writer accepts an append");
        assert_eq!(
            std::fs::read_to_string(&path)
                .expect("audit reads")
                .lines()
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn same_length_external_mutation_fails_readiness_and_future_appends() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = file_log(&path).await;
        log.append(event(&log)).await.expect("event appends");

        std::thread::sleep(std::time::Duration::from_millis(2));
        let mut external = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("audit file opens for mutation");
        external
            .seek(SeekFrom::Start(0))
            .and_then(|_| external.write_all(b"["))
            .and_then(|_| external.sync_all())
            .expect("same-length mutation persists");

        assert!(!log.ready().await);
        assert!(log.append(event(&log)).await.is_err());
    }

    #[tokio::test]
    async fn invalid_release_shape_fails_closed_before_any_write() {
        let (log, captured) = captured_log();
        let mut invalid = event(&log);
        invalid.phase = AuditPhase::DisclosureRelease;
        assert!(matches!(
            log.append(invalid).await,
            Err(EvidenceAuditError::InvalidEvent)
        ));
        assert!(
            captured.entries().is_empty(),
            "an invalid event is never written"
        );
    }

    #[tokio::test]
    async fn second_writer_is_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let first = file_log(&path).await;
        let second =
            EvidenceAuditLog::initialize(file_destination(&path), MASTER.to_vec(), 1).await;
        assert!(matches!(
            second,
            Err(EvidenceAuditError::Audit(AuditError::SinkLocked { .. }))
        ));
        drop(first);
    }

    #[tokio::test]
    async fn an_unusable_key_version_opens_no_destination() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        assert!(matches!(
            EvidenceAuditLog::initialize(file_destination(&path), MASTER.to_vec(), 0).await,
            Err(EvidenceAuditError::Configuration)
        ));
        assert!(
            !path.exists(),
            "key derivation runs before the file is created"
        );
    }

    #[tokio::test]
    async fn pathname_replacement_never_redirects_the_pinned_audit_writer() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let displaced = directory.path().join("displaced.jsonl");
        let log = file_log(&path).await;

        std::fs::rename(&path, &displaced).expect("initialized file is displaced");
        std::fs::write(&path, b"replacement-canary\n").expect("replacement is created");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("replacement mode is owner-only");

        assert!(!log.ready().await);
        assert_eq!(
            std::fs::read_to_string(&path).expect("replacement reads"),
            "replacement-canary\n"
        );
    }

    fn local_access(log: &EvidenceAuditLog, operation: &str) -> EvidenceAuditEvent {
        let mut event = EvidenceAuditEvent::new(
            AssuranceProfile::Local,
            operation.to_owned(),
            AuditPhase::AccessAttempt,
            "urn:example:requirement:age-bracket:v1".to_owned(),
            format!("sha256:{}", "a".repeat(64)),
            "benefit:eligibility".to_owned(),
            log.pseudonym(
                "requester-v1",
                "urn:example:trust",
                b"raw-requester-token-canary",
            )
            .expect("requester pseudonym builds"),
            AuditAuthority {
                kind: AuthorityKind::Delegated,
                grant_pseudonym: Some(
                    log.pseudonym("grant-v1", "urn:example:trust", b"raw-grant-token-canary")
                        .expect("grant pseudonym builds"),
                ),
                approver_pseudonym: Some(
                    log.pseudonym(
                        "approver-v1",
                        "urn:example:trust",
                        b"raw-approver-token-canary",
                    )
                    .expect("approver pseudonym builds"),
                ),
            },
            vec![AuditSubject {
                role: "subject".to_owned(),
                selector_profile: "person-v1".to_owned(),
                selector_bundle_pseudonym: Some(
                    log.pseudonym(
                        "subject-v1",
                        "benefit:eligibility",
                        b"person-id-raw-selector-canary",
                    )
                    .expect("subject pseudonym builds"),
                ),
            }],
            ResponseProtection::Signed,
            AuditDecision::Authorized,
            4,
        );
        event.actor_pseudonym = Some(
            log.pseudonym("actor-v1", "urn:example:trust", b"raw-actor-token-canary")
                .expect("actor pseudonym builds"),
        );
        event.source_id = Some("source-private-canary".to_owned());
        event.adapter_id = Some("adapter-private-canary".to_owned());
        event
    }

    fn local_release(access: &EvidenceAuditEvent) -> EvidenceAuditEvent {
        let mut release = access.clone();
        release.event_id = format!("urn:ulid:{}", ulid::Ulid::new());
        release.occurred_at = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::milliseconds(1))
            .expect("timestamp advances")
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        release.phase = AuditPhase::DisclosureRelease;
        release.decision = AuditDecision::Released;
        release.disclosed_concepts = Some(vec!["urn:example:concept:age-bracket".to_owned()]);
        release.evidence_id = Some(format!("urn:example:evidence:{}", ulid::Ulid::new()));
        release.signing_key_id = Some("local-signing-key-1".to_owned());
        release.duration_milliseconds = 19;
        release
    }

    fn local_authorization_refusal(
        log: &EvidenceAuditLog,
        operation: &str,
    ) -> EvidenceAuthorizationRefusalAuditEvent {
        let mut event = EvidenceAuthorizationRefusalAuditEvent::new(
            AssuranceProfile::Local,
            operation.to_owned(),
            format!("sha256:{}", "a".repeat(64)),
            log.pseudonym(
                "requester-v1",
                "urn:example:trust",
                b"raw-refused-requester-token-canary",
            )
            .expect("requester pseudonym builds"),
            3,
        );
        event.actor_pseudonym = Some(
            log.pseudonym(
                "actor-v1",
                "urn:example:trust",
                b"raw-refused-actor-token-canary",
            )
            .expect("actor pseudonym builds"),
        );
        event
    }

    async fn append_local_operation(log: &EvidenceAuditLog, operation: &str) {
        let access = local_access(log, operation);
        let release = local_release(&access);
        log.append(access).await.expect("access event appends");
        log.append(release).await.expect("release event appends");
    }

    #[tokio::test]
    async fn local_inspection_skips_a_terminal_whose_access_retention_removed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = file_log(&path).await;
        append_local_operation(&log, "local-operation-0000000000000001").await;
        append_local_operation(&log, "local-operation-0000000000000002").await;
        drop(log);
        let written = std::fs::read_to_string(&path).expect("audit file reads");
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 4);

        // Retention deleted the older file holding the first access entry.
        std::fs::write(&path, format!("{}\n{}\n{}\n", lines[1], lines[2], lines[3]))
            .expect("oldest retained file");
        let value = serde_json::to_value(
            last_local_audit_operation(&path).expect("a cut stream still reads"),
        )
        .expect("view serializes");
        assert_eq!(
            value["operation"],
            serde_json::json!("local-operation-0000000000000002")
        );

        // Only the oldest retained file can begin inside an operation.
        let sealed = path.with_file_name("audit.jsonl.00000001");
        std::fs::write(&sealed, format!("{}\n{}\n", lines[2], lines[3])).expect("sealed file");
        std::fs::set_permissions(&sealed, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("mode");
        std::fs::write(&path, format!("{}\n", lines[1])).expect("active file");
        assert!(last_local_audit_operation(&path).is_err());
    }

    #[tokio::test]
    async fn authorization_refusal_is_a_distinct_minimal_native_event() {
        let (log, captured) = captured_log();
        let operation = "local-refusal-000000000000000001";
        let event = local_authorization_refusal(&log, operation);
        event
            .validate_phase_fields()
            .expect("native refusal validates");

        let value = serde_json::to_value(&event).expect("refusal serializes");
        assert_eq!(
            value
                .as_object()
                .expect("refusal is an object")
                .keys()
                .collect::<Vec<_>>(),
            [
                "actorKind",
                "actorPseudonym",
                "assuranceProfile",
                "bundleRevision",
                "decision",
                "durationMilliseconds",
                "eventId",
                "occurredAt",
                "operation",
                "phase",
                "reason",
                "requesterPseudonym",
                "safeErrorCategory",
            ]
        );
        assert_eq!(value["phase"], serde_json::json!("denial"));
        assert_eq!(value["decision"], serde_json::json!("not-authorized"));
        assert_eq!(
            value["safeErrorCategory"],
            serde_json::json!("not-authorized")
        );
        let rendered = serde_json::to_string(&value).expect("refusal renders");
        for forbidden in [
            "requirement",
            "purpose",
            "authority",
            "subjects",
            "responseProtection",
            "sourceId",
            "adapterId",
            "nonce",
            "requestNonce",
            "raw-refused-requester-token-canary",
            "raw-refused-actor-token-canary",
        ] {
            assert!(!rendered.contains(forbidden), "event disclosed {forbidden}");
        }

        log.append_authorization_refusal(event)
            .await
            .expect("refusal appends");
        let entries = captured.entries();
        assert_eq!(entries.len(), 1, "a refusal is one entry");
        assert_eq!(
            entries[0]["schema"],
            serde_json::json!(AUTHORIZATION_REFUSAL_AUDIT_SCHEMA)
        );
        assert_eq!(entries[0]["phase"], serde_json::json!("response"));
        assert_eq!(entries[0]["correlation"], serde_json::json!(operation));
    }

    #[tokio::test]
    async fn local_inspection_reports_stopped_audit_that_retains_no_operation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = file_log(&path).await;
        drop(log);

        assert!(matches!(
            last_local_audit_operation(&path),
            Err(EvidenceAuditError::NoOperation)
        ));
    }

    #[tokio::test]
    async fn local_inspection_returns_a_standalone_refusal_as_the_last_operation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = file_log(&path).await;
        append_local_operation(&log, "local-operation-0000000000000001").await;
        let refusal_operation = "local-refusal-000000000000000002";
        log.append_authorization_refusal(local_authorization_refusal(&log, refusal_operation))
            .await
            .expect("refusal appends");
        drop(log);

        let value = serde_json::to_value(
            last_local_audit_operation(&path).expect("stopped local audit reads"),
        )
        .expect("view serializes");
        assert_eq!(value["operation"], serde_json::json!(refusal_operation));
        let events = value["events"].as_array().expect("events are an array");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0]
                .as_object()
                .expect("refusal is an object")
                .keys()
                .collect::<Vec<_>>(),
            [
                "decision",
                "occurredAt",
                "phase",
                "requesterPseudonym",
                "safeErrorCategory",
            ]
        );
        assert_eq!(events[0]["phase"], serde_json::json!("denial"));
        assert_eq!(events[0]["decision"], serde_json::json!("not-authorized"));
        assert_eq!(
            events[0]["safeErrorCategory"],
            serde_json::json!("not-authorized")
        );
        let rendered = serde_json::to_string(&value).expect("view renders");
        for forbidden in [
            "assuranceProfile",
            "actorPseudonym",
            "bundleRevision",
            "durationMilliseconds",
            "requirement",
            "purpose",
            "authority",
            "subjects",
            "responseProtection",
            "sourceId",
            "adapterId",
        ] {
            assert!(!rendered.contains(forbidden), "view disclosed {forbidden}");
        }
    }

    #[tokio::test]
    async fn authorization_refusal_rejects_non_native_fields_and_values() {
        let (log, captured) = captured_log();

        for mutate in [
            |event: &mut EvidenceAuthorizationRefusalAuditEvent| {
                event.phase = AuditPhase::AccessAttempt;
            },
            |event: &mut EvidenceAuthorizationRefusalAuditEvent| {
                event.safe_error_category = "grant-mismatch".to_owned();
            },
        ] {
            let mut invalid =
                local_authorization_refusal(&log, "local-refusal-invalid-000000000001");
            mutate(&mut invalid);
            assert!(matches!(
                invalid.validate_phase_fields(),
                Err(EvidenceAuditError::InvalidEvent)
            ));
            assert!(matches!(
                log.append_authorization_refusal(invalid).await,
                Err(EvidenceAuditError::InvalidEvent)
            ));
        }
        assert!(captured.entries().is_empty());
    }

    #[tokio::test]
    async fn local_inspection_rejects_malformed_and_misfiled_entries() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (log, _) = captured_log();
        let refusal = local_authorization_refusal(&log, "local-refusal-malformed-00000000001");
        let refusal_record = serde_json::to_value(&refusal).expect("refusal serializes");
        let access = local_access(&log, "local-refusal-malformed-00000000003");
        let access_record = serde_json::to_value(&access).expect("access serializes");
        let mut legacy_denial =
            serde_json::to_value(local_access(&log, "local-refusal-malformed-00000000002"))
                .expect("legacy event serializes");
        let legacy_object = legacy_denial
            .as_object_mut()
            .expect("legacy event is an object");
        legacy_object.insert("phase".to_owned(), serde_json::json!("denial"));
        legacy_object.insert("decision".to_owned(), serde_json::json!("not-authorized"));
        legacy_object.insert(
            "safeErrorCategory".to_owned(),
            serde_json::json!("not-authorized"),
        );

        let with_field = |record: &serde_json::Value, key: &str, value: serde_json::Value| {
            let mut record = record.clone();
            record
                .as_object_mut()
                .expect("record is an object")
                .insert(key.to_owned(), value);
            record
        };
        let mut refusal_without_category = refusal_record.clone();
        refusal_without_category
            .as_object_mut()
            .expect("refusal is an object")
            .remove("safeErrorCategory");
        let mut invalid_access = access.clone();
        invalid_access.decision = AuditDecision::Released;

        let refusal_operation = refusal.operation.clone();
        let access_operation = access.operation.clone();
        let malformed = [
            (
                "refusal-under-authorized-envelope-schema",
                AuditEntry::response(AUDIT_SCHEMA, &refusal_operation, refusal_record.clone()),
            ),
            (
                "authorized-under-refusal-envelope-schema",
                AuditEntry::request(
                    AUTHORIZATION_REFUSAL_AUDIT_SCHEMA,
                    &access_operation,
                    access_record.clone(),
                ),
            ),
            (
                "access-under-response-phase",
                AuditEntry::response(AUDIT_SCHEMA, &access_operation, access_record.clone()),
            ),
            (
                "refusal-under-request-phase",
                AuditEntry::request(
                    AUTHORIZATION_REFUSAL_AUDIT_SCHEMA,
                    &refusal_operation,
                    refusal_record.clone(),
                ),
            ),
            (
                "access-under-another-correlation",
                AuditEntry::request(AUDIT_SCHEMA, "another-operation", access_record.clone()),
            ),
            (
                "record-schema-field",
                AuditEntry::response(
                    AUTHORIZATION_REFUSAL_AUDIT_SCHEMA,
                    &refusal_operation,
                    with_field(
                        &refusal_record,
                        "schema",
                        serde_json::json!(AUTHORIZATION_REFUSAL_AUDIT_SCHEMA),
                    ),
                ),
            ),
            (
                "requirement",
                AuditEntry::response(
                    AUTHORIZATION_REFUSAL_AUDIT_SCHEMA,
                    &refusal_operation,
                    with_field(
                        &refusal_record,
                        "requirement",
                        serde_json::json!("urn:example:requirement:probe:v1"),
                    ),
                ),
            ),
            (
                "response-protection",
                AuditEntry::response(
                    AUTHORIZATION_REFUSAL_AUDIT_SCHEMA,
                    &refusal_operation,
                    with_field(
                        &refusal_record,
                        "responseProtection",
                        serde_json::json!("signed"),
                    ),
                ),
            ),
            (
                "missing-category",
                AuditEntry::response(
                    AUTHORIZATION_REFUSAL_AUDIT_SCHEMA,
                    &refusal_operation,
                    refusal_without_category,
                ),
            ),
            (
                "wrong-decision",
                AuditEntry::response(
                    AUTHORIZATION_REFUSAL_AUDIT_SCHEMA,
                    &refusal_operation,
                    with_field(&refusal_record, "decision", serde_json::json!("no-match")),
                ),
            ),
            (
                "legacy-full-shape",
                AuditEntry::response(
                    AUTHORIZATION_REFUSAL_AUDIT_SCHEMA,
                    "local-refusal-malformed-00000000002",
                    legacy_denial,
                ),
            ),
            (
                "invalid-native-event",
                AuditEntry::request(
                    AUDIT_SCHEMA,
                    &access_operation,
                    serde_json::to_value(invalid_access).expect("invalid event serializes"),
                ),
            ),
            (
                "request-batch-family",
                AuditEntry::request(
                    REQUEST_BATCH_AUDIT_SCHEMA,
                    "operation-request-batch-audit",
                    serde_json::to_value(request_batch_event(
                        EvidenceRequestBatchAuditPhase::TerminalFailure,
                        EvidenceRequestBatchAuditDecision::Aborted,
                    ))
                    .expect("batch event serializes"),
                ),
            ),
            (
                "unknown-schema",
                AuditEntry::request(
                    "registry.evidence.audit/v1",
                    &access_operation,
                    access_record.clone(),
                ),
            ),
        ];

        for (name, entry) in malformed {
            let path = directory.path().join(format!("{name}.jsonl"));
            append_raw_entries(&path, vec![entry]).await;
            assert!(
                last_local_audit_operation(&path).is_err(),
                "misfiled entry {name} must fail closed"
            );
        }
    }

    #[tokio::test]
    async fn local_inspection_never_pairs_an_access_event_with_a_refusal() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("access-then-refusal.jsonl");
        let log = file_log(&path).await;
        let operation = "local-refusal-mixed-operation-0000001";
        log.append(local_access(&log, operation))
            .await
            .expect("access appends");
        log.append_authorization_refusal(local_authorization_refusal(&log, operation))
            .await
            .expect("refusal appends");
        drop(log);

        assert!(
            last_local_audit_operation(&path).is_err(),
            "a refusal is standalone and cannot close an authorized access event"
        );

        let path = directory.path().join("refusal-then-access.jsonl");
        let log = file_log(&path).await;
        log.append_authorization_refusal(local_authorization_refusal(&log, operation))
            .await
            .expect("refusal appends");
        log.append(local_access(&log, operation))
            .await
            .expect("access appends");
        drop(log);
        assert!(
            last_local_audit_operation(&path).is_err(),
            "an authorized operation cannot reuse a completed refusal operation id"
        );

        let path = directory.path().join("duplicate-refusal.jsonl");
        let log = file_log(&path).await;
        log.append_authorization_refusal(local_authorization_refusal(&log, operation))
            .await
            .expect("first refusal appends");
        log.append_authorization_refusal(local_authorization_refusal(&log, operation))
            .await
            .expect("second refusal appends");
        drop(log);
        assert!(
            last_local_audit_operation(&path).is_err(),
            "a completed refusal operation id cannot be reused"
        );
    }

    #[tokio::test]
    async fn local_inspection_uses_physical_last_record_across_heterogeneous_operations() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("authorized-terminal-last.jsonl");
        let log = file_log(&path).await;
        let authorized_operation = "local-interleaved-authorized-000000001";
        let access = local_access(&log, authorized_operation);
        let release = local_release(&access);
        log.append(access).await.expect("access appends");
        log.append_authorization_refusal(local_authorization_refusal(
            &log,
            "local-interleaved-refusal-0000000001",
        ))
        .await
        .expect("interleaved refusal appends");
        log.append(release).await.expect("release appends");
        drop(log);

        let value = serde_json::to_value(
            last_local_audit_operation(&path).expect("heterogeneous stopped audit reads"),
        )
        .expect("view serializes");
        assert_eq!(
            value["operation"],
            serde_json::json!(authorized_operation),
            "the physically last authorized terminal wins over an earlier refusal"
        );
        assert_eq!(value["events"].as_array().map(Vec::len), Some(2));

        let path = directory.path().join("refusal-last.jsonl");
        let log = file_log(&path).await;
        append_local_operation(&log, "local-heterogeneous-authorized-000001").await;
        let refusal_operation = "local-heterogeneous-refusal-000000001";
        log.append_authorization_refusal(local_authorization_refusal(&log, refusal_operation))
            .await
            .expect("last refusal appends");
        drop(log);

        let value = serde_json::to_value(
            last_local_audit_operation(&path).expect("heterogeneous stopped audit reads"),
        )
        .expect("view serializes");
        assert_eq!(
            value["operation"],
            serde_json::json!(refusal_operation),
            "the physically last refusal wins over an earlier authorized terminal"
        );
        assert_eq!(value["events"].as_array().map(Vec::len), Some(1));
    }

    #[tokio::test]
    async fn local_inspection_returns_one_closed_two_phase_view() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = file_log(&path).await;
        let operation = "local-operation-0000000000000001";
        append_local_operation(&log, operation).await;
        drop(log);

        let view = last_local_audit_operation(&path).expect("stopped local audit reads");
        let value = serde_json::to_value(view).expect("view serializes");
        assert_eq!(
            value
                .as_object()
                .expect("view is an object")
                .keys()
                .collect::<Vec<_>>(),
            ["events", "operation", "schema"]
        );
        assert_eq!(
            value["schema"],
            serde_json::json!(LOCAL_AUDIT_OPERATION_VIEW_SCHEMA_V1)
        );
        assert_eq!(value["operation"], serde_json::json!(operation));
        let events = value["events"].as_array().expect("events are an array");
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0]
                .as_object()
                .expect("access is an object")
                .keys()
                .collect::<Vec<_>>(),
            [
                "decision",
                "occurredAt",
                "phase",
                "purpose",
                "requesterPseudonym",
                "requirement",
                "responseProtection",
            ]
        );
        assert_eq!(events[0]["phase"], serde_json::json!("access-attempt"));
        assert_eq!(events[0]["decision"], serde_json::json!("authorized"));
        assert_eq!(
            events[1]
                .as_object()
                .expect("release is an object")
                .keys()
                .collect::<Vec<_>>(),
            [
                "decision",
                "disclosedConcepts",
                "evidenceId",
                "occurredAt",
                "phase",
                "purpose",
                "requesterPseudonym",
                "requirement",
                "responseProtection",
            ]
        );
        assert_eq!(events[1]["phase"], serde_json::json!("disclosure-release"));
        assert_eq!(events[1]["decision"], serde_json::json!("released"));

        let rendered = serde_json::to_string(&value).expect("view renders");
        for forbidden in [
            "assuranceProfile",
            "actorPseudonym",
            "grantPseudonym",
            "subjects",
            "selectorProfile",
            "selectorBundlePseudonym",
            "sourceId",
            "adapterId",
            "durationMilliseconds",
            "signingKeyId",
            "bundleRevision",
            "raw-requester-token-canary",
            "raw-grant-token-canary",
            "raw-approver-token-canary",
            "raw-actor-token-canary",
            "person-id-raw-selector-canary",
            "source-private-canary",
            "adapter-private-canary",
        ] {
            assert!(!rendered.contains(forbidden), "view disclosed {forbidden}");
        }
    }

    #[tokio::test]
    async fn local_inspection_returns_every_source_stage_of_a_multi_stage_operation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let operation = "local-multi-stage-operation-00000001";
        let stages = |log: &EvidenceAuditLog| {
            let search = local_access(log, operation);
            let mut fetch = search.clone();
            fetch.event_id = format!("urn:ulid:{}", ulid::Ulid::new());
            fetch.occurred_at =
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            fetch.source_id = Some("fetch-source-private-canary".to_owned());
            fetch.adapter_id = Some("fetch-adapter-private-canary".to_owned());
            (search, fetch)
        };

        let path = directory.path().join("closed.jsonl");
        let log = file_log(&path).await;
        let (search, fetch) = stages(&log);
        let release = local_release(&fetch);
        for event in [search, fetch, release] {
            log.append(event).await.expect("stage appends");
        }
        drop(log);
        let value = serde_json::to_value(
            last_local_audit_operation(&path).expect("multi-stage operation reads"),
        )
        .expect("view serializes");
        assert_eq!(value["operation"], serde_json::json!(operation));
        let phases: Vec<_> = value["events"]
            .as_array()
            .expect("events are an array")
            .iter()
            .map(|event| event["phase"].clone())
            .collect();
        assert_eq!(
            phases,
            [
                serde_json::json!("access-attempt"),
                serde_json::json!("access-attempt"),
                serde_json::json!("disclosure-release"),
            ]
        );

        let path = directory.path().join("pending.jsonl");
        let log = file_log(&path).await;
        let (search, fetch) = stages(&log);
        log.append(search).await.expect("search appends");
        log.append(fetch).await.expect("fetch appends");
        drop(log);
        let value = serde_json::to_value(
            last_local_audit_operation(&path).expect("pending multi-stage operation reads"),
        )
        .expect("view serializes");
        assert_eq!(value["events"].as_array().map(Vec::len), Some(2));

        let path = directory.path().join("foreign-stage.jsonl");
        let log = file_log(&path).await;
        let (search, mut fetch) = stages(&log);
        fetch.purpose = "other:purpose".to_owned();
        log.append(search).await.expect("search appends");
        log.append(fetch).await.expect("foreign stage appends");
        drop(log);
        assert!(
            last_local_audit_operation(&path).is_err(),
            "a later stage must share the operation's context"
        );

        let path = directory.path().join("terminal-names-earlier-stage.jsonl");
        let log = file_log(&path).await;
        let (search, fetch) = stages(&log);
        let mut release = local_release(&fetch);
        release.source_id.clone_from(&search.source_id);
        release.adapter_id.clone_from(&search.adapter_id);
        for event in [search, fetch, release] {
            log.append(event).await.expect("stage appends");
        }
        drop(log);
        assert!(
            last_local_audit_operation(&path).is_err(),
            "the terminal entry names the last stage that ran"
        );
    }

    #[tokio::test]
    async fn local_inspection_selects_the_last_native_operation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = file_log(&path).await;
        append_local_operation(&log, "local-operation-0000000000000001").await;
        append_local_operation(&log, "local-operation-0000000000000002").await;
        drop(log);

        let value = serde_json::to_value(
            last_local_audit_operation(&path).expect("stopped local audit reads"),
        )
        .expect("view serializes");
        assert_eq!(
            value["operation"],
            serde_json::json!("local-operation-0000000000000002")
        );
        assert_eq!(value["events"].as_array().map(Vec::len), Some(2));
    }

    #[tokio::test]
    async fn local_inspection_reads_sealed_files_in_sequence_then_the_active_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        for index in 0..3u64 {
            let log = file_log(&path).await;
            append_local_operation(&log, &format!("local-operation-{index:016}")).await;
            drop(log);
            seal_active_file(&path, index + 1);
        }
        let log = file_log(&path).await;
        let operation = "local-operation-0000000000000003";
        let access = local_access(&log, operation);
        let release = local_release(&access);
        log.append(access).await.expect("access appends");
        drop(log);
        // The access attempt is sealed and its release lands in the active
        // file, so the view only closes if the files are read in order.
        seal_active_file(&path, 4);
        let log = file_log(&path).await;
        log.append(release).await.expect("release appends");
        drop(log);

        let value = serde_json::to_value(
            last_local_audit_operation(&path).expect("sealed and active files read"),
        )
        .expect("view serializes");
        assert_eq!(value["operation"], serde_json::json!(operation));
        assert_eq!(value["events"].as_array().map(Vec::len), Some(2));
    }

    #[tokio::test]
    async fn local_inspection_rejects_tampering_and_a_live_writer() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("live.jsonl");
        let live = file_log(&path).await;
        append_local_operation(&live, "local-operation-0000000000000001").await;
        assert!(
            matches!(
                last_local_audit_operation(&path),
                Err(EvidenceAuditError::Audit(AuditError::SinkLocked { .. }))
            ),
            "a live writer fails rather than yielding a partial view"
        );
        drop(live);
        last_local_audit_operation(&path).expect("the stopped file reads");

        rewrite_line(&path, 0, |line| line.replacen('{', "[", 1));
        assert!(
            last_local_audit_operation(&path).is_err(),
            "a line that is not an entry yields no view"
        );
    }

    #[tokio::test]
    async fn local_inspection_rejects_a_torn_final_line_and_a_missing_active_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = file_log(&path).await;
        append_local_operation(&log, "local-operation-0000000000000001").await;
        drop(log);
        let length = std::fs::metadata(&path).expect("audit metadata").len();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_len(length - 8))
            .expect("final line is torn");
        assert!(
            last_local_audit_operation(&path).is_err(),
            "a torn final line yields no view"
        );

        let active_path = directory.path().join("missing-active.jsonl");
        let active = file_log(&active_path).await;
        append_local_operation(&active, "local-operation-0000000000000001").await;
        drop(active);
        std::fs::remove_file(&active_path).expect("active file is removed");
        assert!(
            last_local_audit_operation(&active_path).is_err(),
            "an absent active file yields no view"
        );
    }

    #[tokio::test]
    async fn local_inspection_refuses_a_symbolic_link() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target.jsonl");
        let log = file_log(&target).await;
        append_local_operation(&log, "local-operation-0000000000000001").await;
        drop(log);
        let link = directory.path().join("audit.jsonl");
        std::os::unix::fs::symlink(&target, &link).expect("active link is created");
        std::fs::copy(
            directory.path().join("target.jsonl.lock"),
            directory.path().join("audit.jsonl.lock"),
        )
        .expect("lock is copied");
        assert!(
            last_local_audit_operation(&link).is_err(),
            "the reader never follows a symbolic link"
        );
    }

    #[tokio::test]
    async fn local_inspection_fails_instead_of_truncating_at_any_bound() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = file_log(&path).await;
        for index in 0..2 {
            append_local_operation(&log, &format!("local-operation-{index:016}")).await;
        }
        drop(log);
        seal_active_file(&path, 1);
        let log = file_log(&path).await;
        for index in 2..4 {
            append_local_operation(&log, &format!("local-operation-{index:016}")).await;
        }
        drop(log);
        last_local_audit_operation(&path).expect("the default bounds hold");

        let defaults = LocalAuditInspectionBounds::DEFAULT;
        for bounds in [
            LocalAuditInspectionBounds {
                maximum_segments: 1,
                ..defaults
            },
            LocalAuditInspectionBounds {
                maximum_records: 1,
                ..defaults
            },
            LocalAuditInspectionBounds {
                maximum_output_bytes: 1,
                ..defaults
            },
        ] {
            assert!(
                last_local_audit_operation_with_bounds(&path, bounds).is_err(),
                "a bound failure yields no truncated view"
            );
        }
    }

    fn rewrite_line(path: &Path, index: usize, rewrite: impl Fn(&str) -> String) {
        let contents = std::fs::read_to_string(path).expect("audit file reads");
        let mut lines: Vec<String> = contents.lines().map(str::to_owned).collect();
        lines[index] = rewrite(&lines[index]);
        let mut rewritten = lines.join("\n");
        rewritten.push('\n');
        std::fs::write(path, rewritten).expect("audit file rewrites");
    }

    /// Readiness reports on the destination, not on how busy the writer is.
    /// The fingerprint it compares is the one the writer advances on every
    /// append, so a probe that read it outside the writer's lock would see the
    /// service's own traffic as external mutation and flap under load.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn readiness_holds_while_appends_are_in_flight() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = Arc::new(file_log(&path).await);

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut writers = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let log = Arc::clone(&log);
            let stop = Arc::clone(&stop);
            writers.spawn(async move {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    log.append(event(&log)).await.expect("event appends");
                }
            });
        }

        // Probe often enough to land inside a durable write rather than only in
        // the gaps between them, which is the window the race lives in.
        let mut probes = 0usize;
        let mut unready = 0usize;
        for _ in 0..200 {
            if log.ready().await {
                probes += 1;
            } else {
                unready += 1;
            }
            tokio::task::yield_now().await;
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        while let Some(result) = writers.join_next().await {
            result.expect("writer task joins");
        }

        assert_eq!(
            unready, 0,
            "readiness stayed true through {probes} probes but reported unready {unready} times while the service was writing its own audit records"
        );
    }

    /// The point of group commit: appends that arrive while a durable write is
    /// in flight join the next one instead of each paying their own `fsync`.
    #[tokio::test]
    async fn concurrent_appends_share_durable_writes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = Arc::new(file_log(&path).await);

        const APPENDS: usize = 64;
        let mut appends = tokio::task::JoinSet::new();
        for _ in 0..APPENDS {
            let log = Arc::clone(&log);
            appends.spawn(async move { log.append(event(&log)).await.expect("event appends") });
        }
        while let Some(result) = appends.join_next().await {
            result.expect("append task joins");
        }

        let writes = log.durable_writes();
        assert!(
            writes < APPENDS,
            "concurrent appends must share durable writes, saw {writes} for {APPENDS} records"
        );
        assert_eq!(
            std::fs::read_to_string(&path)
                .expect("audit reads")
                .lines()
                .count(),
            APPENDS,
            "batching must not drop or duplicate a record"
        );
    }

    /// A durable write that fails leaves the writer unable to say what reached
    /// the disk, so it must refuse everything afterwards.
    #[tokio::test]
    async fn a_failed_durable_write_stops_the_writer() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = file_log(&path).await;
        log.append(event(&log)).await.expect("event appends");
        assert!(log.ready().await);

        // Truncating through a second handle leaves the writer's pinned handle
        // valid but the file no longer the one it fingerprinted.
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("external truncation opens");

        assert!(
            log.append(event(&log)).await.is_err(),
            "an externally modified file fails the write"
        );
        assert!(
            log.append(event(&log)).await.is_err(),
            "the writer stays stopped"
        );
        assert!(
            !log.ready().await,
            "a stopped writer never reports itself ready again"
        );
    }

    /// Callers wait for a batch they did not write, so a batch that fails has
    /// to hand every one of them the failure. Waiting on a durable write that
    /// will never arrive would hang the request that asked for the audit
    /// record, which is a worse outcome than refusing it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_stopped_writer_fails_concurrent_waiters_instead_of_hanging_them() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = Arc::new(file_log(&path).await);
        log.append(event(&log)).await.expect("event appends");
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("external truncation opens");
        assert!(
            log.append(event(&log)).await.is_err(),
            "an externally modified file fails the write"
        );

        let mut waiters = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let log = Arc::clone(&log);
            waiters.spawn(async move { log.append(event(&log)).await });
        }
        let outcomes = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut outcomes = Vec::new();
            while let Some(result) = waiters.join_next().await {
                outcomes.push(result.expect("append task joins"));
            }
            outcomes
        })
        .await
        .expect("a stopped writer answers every waiter rather than hanging one");

        assert_eq!(outcomes.len(), 32);
        assert!(
            outcomes.iter().all(Result::is_err),
            "every waiter is told the writer stopped"
        );
    }
}

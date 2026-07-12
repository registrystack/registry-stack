// SPDX-License-Identifier: Apache-2.0
//! Sealed public response for one decoder-validated consultation.
//!
//! Serialization happens before durable completion. Until the state plane
//! returns a publication grant, the complete candidate response remains in a
//! zeroizing owner and cannot be converted into an HTTP body.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};

use registry_platform_httputil::destination::json::ProjectedJsonScalar;
use serde::de::Error as _;
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::source_backend::{PublishedSnapshotHandle, SnapshotExactRecord};
use crate::source_plan::runtime_profile::{
    CompiledOutputShape, CompiledRuntimeProfile, CompiledSourceObservedAtContract,
    CompiledSourceRevisionContract,
};
use crate::state_plane::ConsultationPublicationGrant;

use super::{AcquisitionClass, ConsultationId, ConsultationOutcome, NotaryEvaluationId};

/// Frozen v1 public response-body ceiling.
pub(crate) const MAX_CONSULTATION_RESPONSE_BYTES: usize = 64 * 1_024;

/// Value-free failure while preparing a candidate public response.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum ConsultationResponseError {
    #[error("consultation response time is invalid")]
    InvalidTime,
    #[error("consultation response could not be serialized")]
    Serialization,
    #[error("consultation response exceeds the v1 bound")]
    ResponseTooLarge,
}

/// Candidate response bytes that remain non-publishable until durable normal
/// completion returns the exact paired grant.
#[must_use = "candidate consultation output requires a durable publication grant"]
pub(crate) struct PublishableConsultationResponse {
    bytes: Zeroizing<Vec<u8>>,
    terminal: BatchTerminalPayload,
}

/// Closed, evaluation-id-free terminal result retained for an authenticated
/// Notary batch child. It is constructed before either the first response or
/// a replay response is serialized, so both paths use the same renderer.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BatchTerminalPayload {
    schema: BatchTerminalSchema,
    consultation_id: String,
    outcome: BatchTerminalOutcome,
    data: Option<BTreeMap<String, BatchTerminalScalar>>,
    profile: BatchTerminalProfile,
    provenance: BatchTerminalProvenance,
}

#[derive(Serialize, Deserialize)]
enum BatchTerminalSchema {
    #[serde(rename = "registry.relay.batch-terminal/v1")]
    V1,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum BatchTerminalOutcome {
    Match,
    NoMatch,
    Ambiguous,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchTerminalProfile {
    id: String,
    version: String,
    contract_hash: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchTerminalProvenance {
    relay_acquired_at: String,
    source_observed_at: Option<String>,
    source_revision: Option<String>,
    acquisition_class: String,
    integration_pack: BatchTerminalIntegrationPack,
    policy_id: String,
    policy_hash: String,
    consent: BatchTerminalConsent,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_generation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_published_at: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchTerminalIntegrationPack {
    id: String,
    version: String,
    hash: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchTerminalConsent {
    outcome: String,
    verifier_id: Option<String>,
    verifier_revision: Option<String>,
    checked_at: Option<String>,
    expires_at: Option<String>,
    revocation_status: String,
}

enum BatchTerminalScalar {
    Null,
    String(Zeroizing<String>),
    Boolean(bool),
    Integer(i64),
}

impl Serialize for BatchTerminalScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Null => serializer.serialize_none(),
            Self::String(value) => serializer.serialize_str(value),
            Self::Boolean(value) => serializer.serialize_bool(*value),
            Self::Integer(value) => serializer.serialize_i64(*value),
        }
    }
}

impl<'de> Deserialize<'de> for BatchTerminalScalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::Null => Ok(Self::Null),
            serde_json::Value::String(value) => Ok(Self::String(Zeroizing::new(value))),
            serde_json::Value::Bool(value) => Ok(Self::Boolean(value)),
            serde_json::Value::Number(value) => value
                .as_i64()
                .map(Self::Integer)
                .ok_or_else(|| D::Error::custom("batch terminal scalar is not a signed integer")),
            _ => Err(D::Error::custom("batch terminal value is not a scalar")),
        }
    }
}

impl fmt::Debug for BatchTerminalPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BatchTerminalPayload([REDACTED])")
    }
}

/// Closed typed fact map produced only by a capability decoder.
pub(super) struct ValidatedFactMap {
    fields: Box<[(Box<str>, ProjectedJsonScalar)]>,
}

impl ValidatedFactMap {
    pub(super) fn try_new(
        profile: &CompiledRuntimeProfile,
        mut fields: Vec<(Box<str>, ProjectedJsonScalar)>,
    ) -> Result<Self, ConsultationResponseError> {
        fields.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        if fields
            .windows(2)
            .any(|pair| pair[0].0.as_ref() == pair[1].0.as_ref())
            || fields.len() != profile.output().len()
        {
            return Err(ConsultationResponseError::Serialization);
        }
        for (name, value) in &fields {
            let output = profile
                .output_field(name)
                .ok_or(ConsultationResponseError::Serialization)?;
            let valid = match (output.shape(), value) {
                (
                    CompiledOutputShape::String { max_bytes, .. },
                    ProjectedJsonScalar::String(value),
                ) => value.as_str().len() <= usize::try_from(max_bytes).unwrap_or(usize::MAX),
                (CompiledOutputShape::Boolean { .. }, ProjectedJsonScalar::Boolean(_))
                | (CompiledOutputShape::Presence, ProjectedJsonScalar::Boolean(_)) => true,
                (
                    CompiledOutputShape::Integer {
                        minimum, maximum, ..
                    },
                    ProjectedJsonScalar::Integer(value),
                ) => (minimum..=maximum).contains(value),
                (CompiledOutputShape::Date { .. }, ProjectedJsonScalar::String(value)) => {
                    valid_full_date(value)
                }
                (
                    CompiledOutputShape::String { nullable: true, .. }
                    | CompiledOutputShape::Boolean { nullable: true }
                    | CompiledOutputShape::Integer { nullable: true, .. }
                    | CompiledOutputShape::Date { nullable: true },
                    ProjectedJsonScalar::Null,
                ) => true,
                _ => false,
            };
            if !valid {
                return Err(ConsultationResponseError::Serialization);
            }
        }
        Ok(Self {
            fields: fields.into_boxed_slice(),
        })
    }

    pub(super) fn fields(&self) -> impl ExactSizeIterator<Item = (&str, &ProjectedJsonScalar)> {
        self.fields
            .iter()
            .map(|(name, value)| (name.as_ref(), value))
    }
}

impl PublishableConsultationResponse {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_validated_live_result(
        consultation_id: ConsultationId,
        notary_evaluation_id: Option<NotaryEvaluationId>,
        profile: &CompiledRuntimeProfile,
        outcome: ConsultationOutcome,
        facts: Option<&ValidatedFactMap>,
        relay_acquired_at_unix_ms: i64,
    ) -> Result<Self, ConsultationResponseError> {
        Self::serialize_validated_live_result(
            consultation_id,
            notary_evaluation_id,
            profile,
            outcome,
            facts.map(ProjectedRecord::Facts),
            relay_acquired_at_unix_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_validated_snapshot_result(
        consultation_id: ConsultationId,
        notary_evaluation_id: Option<NotaryEvaluationId>,
        profile: &CompiledRuntimeProfile,
        outcome: ConsultationOutcome,
        record: Option<&SnapshotExactRecord>,
        relay_acquired_at_unix_ms: i64,
        source_observed_at_unix_ms: Option<i64>,
        source_revision: Option<&str>,
        snapshot: &PublishedSnapshotHandle,
    ) -> Result<Self, ConsultationResponseError> {
        if profile.footprint().acquisition_class() != AcquisitionClass::MaterializedSnapshot {
            return Err(ConsultationResponseError::Serialization);
        }
        let output_fields = profile
            .output()
            .map(|field| {
                (
                    field.name(),
                    matches!(field.shape(), CompiledOutputShape::Presence),
                )
            })
            .collect();
        Self::serialize_validated_result(
            consultation_id,
            notary_evaluation_id,
            profile,
            outcome,
            record.map(|record| ProjectedRecord::Snapshot {
                fields: record.fields(),
                output_fields,
            }),
            relay_acquired_at_unix_ms,
            SnapshotResponseProvenance {
                source_observed_at_unix_ms,
                source_revision,
                generation_id: snapshot.generation(),
                published_at_unix_ms: snapshot.published_at_unix_ms(),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn serialize_validated_live_result(
        consultation_id: ConsultationId,
        notary_evaluation_id: Option<NotaryEvaluationId>,
        profile: &CompiledRuntimeProfile,
        outcome: ConsultationOutcome,
        data: Option<ProjectedRecord<'_>>,
        relay_acquired_at_unix_ms: i64,
    ) -> Result<Self, ConsultationResponseError> {
        Self::serialize_validated_result(
            consultation_id,
            notary_evaluation_id,
            profile,
            outcome,
            data,
            relay_acquired_at_unix_ms,
            LiveResponseProvenance,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn serialize_validated_result<'a>(
        consultation_id: ConsultationId,
        notary_evaluation_id: Option<NotaryEvaluationId>,
        profile: &'a CompiledRuntimeProfile,
        outcome: ConsultationOutcome,
        data: Option<ProjectedRecord<'a>>,
        relay_acquired_at_unix_ms: i64,
        provenance: impl SealedResponseProvenance<'a>,
    ) -> Result<Self, ConsultationResponseError> {
        let relay_acquired_at = rfc3339_milliseconds(relay_acquired_at_unix_ms)?;
        let source_observed_at = provenance.source_observed_at()?;
        let snapshot_generation_id = provenance.snapshot_generation_id();
        let snapshot_published_at = provenance.snapshot_published_at()?;
        let profile_identity = profile.profile();
        let integration_pack = profile.integration_pack();
        let policy = profile.authorization().policy();
        let data = match (outcome, data) {
            (ConsultationOutcome::Match, Some(record)) => Some(record),
            (ConsultationOutcome::NoMatch | ConsultationOutcome::Ambiguous, None) => None,
            _ => return Err(ConsultationResponseError::Serialization),
        };
        let terminal = BatchTerminalPayload {
            schema: BatchTerminalSchema::V1,
            consultation_id: consultation_id.to_canonical_string(),
            outcome: BatchTerminalOutcome::from_consultation(outcome),
            data: data
                .map(ProjectedRecord::into_terminal_fields)
                .transpose()?,
            profile: BatchTerminalProfile {
                id: profile_identity.id().as_str().to_owned(),
                version: profile_identity.version().to_string(),
                contract_hash: profile_identity.contract_hash().as_str().to_owned(),
            },
            provenance: BatchTerminalProvenance {
                relay_acquired_at,
                source_observed_at,
                source_revision: provenance.source_revision().map(str::to_owned),
                acquisition_class: acquisition_class_str(profile.footprint().acquisition_class())
                    .to_owned(),
                integration_pack: BatchTerminalIntegrationPack {
                    id: integration_pack.id().as_str().to_owned(),
                    version: integration_pack.version().to_string(),
                    hash: integration_pack.hash().as_str().to_owned(),
                },
                policy_id: policy.id().as_str().to_owned(),
                policy_hash: policy.hash().as_str().to_owned(),
                consent: BatchTerminalConsent {
                    outcome: "not_required".to_owned(),
                    verifier_id: None,
                    verifier_revision: None,
                    checked_at: None,
                    expires_at: None,
                    revocation_status: "not_applicable".to_owned(),
                },
                snapshot_generation_id,
                snapshot_published_at,
            },
        };
        let configured_limit =
            usize::try_from(profile.effective_limits().max_public_response_bytes())
                .map_err(|_| ConsultationResponseError::ResponseTooLarge)?;
        let limit = configured_limit.min(MAX_CONSULTATION_RESPONSE_BYTES);
        let bytes = terminal.render(notary_evaluation_id, limit)?;
        Ok(Self { bytes, terminal })
    }

    pub(super) fn batch_terminal_json(
        &self,
    ) -> Result<Zeroizing<String>, ConsultationResponseError> {
        serde_json::to_string(&self.terminal)
            .map(Zeroizing::new)
            .map_err(|_| ConsultationResponseError::Serialization)
    }

    pub(super) fn replay_http_body(
        persisted: Zeroizing<String>,
        expected_consultation_id: &str,
        profile: &CompiledRuntimeProfile,
        notary_evaluation_id: Option<NotaryEvaluationId>,
    ) -> Result<Vec<u8>, ConsultationResponseError> {
        let terminal = BatchTerminalPayload::from_persisted(persisted.as_str())?;
        if terminal.consultation_id != expected_consultation_id {
            return Err(ConsultationResponseError::Serialization);
        }
        let mut bytes = terminal.render_replay(profile, notary_evaluation_id)?;
        Ok(std::mem::take(bytes.as_mut()))
    }

    #[cfg(test)]
    pub(crate) fn batch_no_match_for_state_test(
        consultation_id: ConsultationId,
        notary_evaluation_id: NotaryEvaluationId,
        profile: &CompiledRuntimeProfile,
        relay_acquired_at_unix_ms: i64,
    ) -> Result<Self, ConsultationResponseError> {
        Self::from_validated_live_result(
            consultation_id,
            Some(notary_evaluation_id),
            profile,
            ConsultationOutcome::NoMatch,
            None,
            relay_acquired_at_unix_ms,
        )
    }

    #[cfg(test)]
    pub(crate) fn batch_terminal_json_for_state_test(
        &self,
    ) -> Result<Zeroizing<String>, ConsultationResponseError> {
        self.batch_terminal_json()
    }

    #[cfg(test)]
    pub(crate) fn replay_http_body_for_state_test(
        persisted: Zeroizing<String>,
        expected_consultation_id: &str,
        profile: &CompiledRuntimeProfile,
        notary_evaluation_id: NotaryEvaluationId,
    ) -> Result<Vec<u8>, ConsultationResponseError> {
        Self::replay_http_body(
            persisted,
            expected_consultation_id,
            profile,
            Some(notary_evaluation_id),
        )
    }

    /// Declassify the already validated public bytes only while consuming the
    /// durable publication authority returned for the same completed attempt.
    pub(super) fn into_http_body(mut self, _grant: ConsultationPublicationGrant) -> Vec<u8> {
        std::mem::take(self.bytes.as_mut())
    }

    #[cfg(test)]
    fn bytes_for_test(&self) -> &[u8] {
        &self.bytes
    }
}

impl BatchTerminalOutcome {
    const fn from_consultation(outcome: ConsultationOutcome) -> Self {
        match outcome {
            ConsultationOutcome::Match => Self::Match,
            ConsultationOutcome::NoMatch => Self::NoMatch,
            ConsultationOutcome::Ambiguous => Self::Ambiguous,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::NoMatch => "no_match",
            Self::Ambiguous => "ambiguous",
        }
    }
}

impl BatchTerminalPayload {
    pub(super) fn from_persisted(value: &str) -> Result<Self, ConsultationResponseError> {
        let terminal: Self =
            serde_json::from_str(value).map_err(|_| ConsultationResponseError::Serialization)?;
        let canonical_id = ulid::Ulid::from_string(&terminal.consultation_id)
            .ok()
            .filter(|id| id.to_string() == terminal.consultation_id)
            .ok_or(ConsultationResponseError::Serialization)?;
        let _ = canonical_id;
        match (terminal.outcome, terminal.data.as_ref()) {
            (BatchTerminalOutcome::Match, Some(data)) if !data.is_empty() => {}
            (BatchTerminalOutcome::NoMatch | BatchTerminalOutcome::Ambiguous, None) => {}
            _ => return Err(ConsultationResponseError::Serialization),
        }
        Ok(terminal)
    }

    pub(super) fn render_replay(
        &self,
        profile: &CompiledRuntimeProfile,
        notary_evaluation_id: Option<NotaryEvaluationId>,
    ) -> Result<Zeroizing<Vec<u8>>, ConsultationResponseError> {
        self.validate_profile(profile)?;
        let limit = usize::try_from(profile.effective_limits().max_public_response_bytes())
            .map_err(|_| ConsultationResponseError::ResponseTooLarge)?
            .min(MAX_CONSULTATION_RESPONSE_BYTES);
        self.render(notary_evaluation_id, limit)
    }

    fn validate_profile(
        &self,
        profile: &CompiledRuntimeProfile,
    ) -> Result<(), ConsultationResponseError> {
        if self.profile.id != profile.profile().id().as_str()
            || self.profile.version != profile.profile().version().to_string()
            || self.profile.contract_hash != profile.profile().contract_hash().as_str()
            || self.provenance.acquisition_class
                != acquisition_class_str(profile.footprint().acquisition_class())
            || self.provenance.integration_pack.id != profile.integration_pack().id().as_str()
            || self.provenance.integration_pack.version
                != profile.integration_pack().version().to_string()
            || self.provenance.integration_pack.hash != profile.integration_pack().hash().as_str()
            || self.provenance.policy_id != profile.authorization().policy().id().as_str()
            || self.provenance.policy_hash != profile.authorization().policy().hash().as_str()
            || self.provenance.consent.outcome != "not_required"
            || self.provenance.consent.revocation_status != "not_applicable"
            || self.provenance.consent.verifier_id.is_some()
            || self.provenance.consent.verifier_revision.is_some()
            || self.provenance.consent.checked_at.is_some()
            || self.provenance.consent.expires_at.is_some()
            || !valid_rfc3339_milliseconds(&self.provenance.relay_acquired_at)
        {
            return Err(ConsultationResponseError::Serialization);
        }
        let provenance = profile.acquisition_provenance();
        let source_observed_valid = match provenance.source_observed_at() {
            CompiledSourceObservedAtContract::Absent => {
                self.provenance.source_observed_at.is_none()
            }
            CompiledSourceObservedAtContract::AcquiredRfc3339 { .. } => self
                .provenance
                .source_observed_at
                .as_deref()
                .is_some_and(valid_rfc3339_milliseconds),
        };
        let source_revision_valid = match provenance.source_revision() {
            CompiledSourceRevisionContract::Absent => self.provenance.source_revision.is_none(),
            CompiledSourceRevisionContract::AcquiredString { max_bytes, .. } => self
                .provenance
                .source_revision
                .as_deref()
                .is_some_and(|value| !value.is_empty() && value.len() <= usize::from(*max_bytes)),
        };
        let snapshot_generation_valid = if provenance.snapshot_generation_required() {
            self.provenance
                .snapshot_generation_id
                .as_deref()
                .and_then(|value| ulid::Ulid::from_string(value).ok())
                .is_some_and(|id| {
                    id.to_string()
                        == self
                            .provenance
                            .snapshot_generation_id
                            .as_deref()
                            .unwrap_or_default()
                })
        } else {
            self.provenance.snapshot_generation_id.is_none()
        };
        let snapshot_published_valid = if provenance.snapshot_published_at_required() {
            self.provenance
                .snapshot_published_at
                .as_deref()
                .is_some_and(valid_rfc3339_milliseconds)
        } else {
            self.provenance.snapshot_published_at.is_none()
        };
        if !source_observed_valid
            || !source_revision_valid
            || !snapshot_generation_valid
            || !snapshot_published_valid
        {
            return Err(ConsultationResponseError::Serialization);
        }
        if let Some(data) = &self.data {
            if data.len() != profile.output().len() {
                return Err(ConsultationResponseError::Serialization);
            }
            for (name, value) in data {
                let field = profile
                    .output_field(name)
                    .ok_or(ConsultationResponseError::Serialization)?;
                let valid = match (field.shape(), value) {
                    (
                        CompiledOutputShape::String { max_bytes, .. },
                        BatchTerminalScalar::String(value),
                    ) => value.len() <= usize::try_from(max_bytes).unwrap_or(usize::MAX),
                    (CompiledOutputShape::Date { .. }, BatchTerminalScalar::String(value)) => {
                        valid_full_date(value)
                    }
                    (
                        CompiledOutputShape::Boolean { .. } | CompiledOutputShape::Presence,
                        BatchTerminalScalar::Boolean(_),
                    ) => true,
                    (
                        CompiledOutputShape::Integer {
                            minimum, maximum, ..
                        },
                        BatchTerminalScalar::Integer(value),
                    ) => (minimum..=maximum).contains(value),
                    (
                        CompiledOutputShape::String { nullable: true, .. }
                        | CompiledOutputShape::Boolean { nullable: true }
                        | CompiledOutputShape::Integer { nullable: true, .. }
                        | CompiledOutputShape::Date { nullable: true },
                        BatchTerminalScalar::Null,
                    ) => true,
                    _ => false,
                };
                if !valid {
                    return Err(ConsultationResponseError::Serialization);
                }
            }
        }
        Ok(())
    }

    pub(super) fn render(
        &self,
        notary_evaluation_id: Option<NotaryEvaluationId>,
        limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>, ConsultationResponseError> {
        if limit == 0 || limit > MAX_CONSULTATION_RESPONSE_BYTES {
            return Err(ConsultationResponseError::ResponseTooLarge);
        }
        let notary_evaluation_id =
            notary_evaluation_id.map(NotaryEvaluationId::to_canonical_string);
        let envelope = ConsultationResult {
            schema: "registry.relay.consultation-result.v1",
            consultation_id: &self.consultation_id,
            notary_evaluation_id: notary_evaluation_id.as_deref(),
            profile: ResponseProfile {
                id: &self.profile.id,
                version: &self.profile.version,
                contract_hash: &self.profile.contract_hash,
            },
            outcome: self.outcome.as_str(),
            data: self.data.as_ref(),
            provenance: ResponseProvenance {
                relay_acquired_at: &self.provenance.relay_acquired_at,
                source_observed_at: self.provenance.source_observed_at.as_deref(),
                source_revision: self.provenance.source_revision.as_deref(),
                acquisition_class: &self.provenance.acquisition_class,
                integration_pack: ResponseIntegrationPack {
                    id: &self.provenance.integration_pack.id,
                    version: &self.provenance.integration_pack.version,
                    hash: &self.provenance.integration_pack.hash,
                },
                policy_id: &self.provenance.policy_id,
                policy_hash: &self.provenance.policy_hash,
                consent: ResponseConsent {
                    outcome: &self.provenance.consent.outcome,
                    verifier_id: self.provenance.consent.verifier_id.as_deref(),
                    verifier_revision: self.provenance.consent.verifier_revision.as_deref(),
                    checked_at: self.provenance.consent.checked_at.as_deref(),
                    expires_at: self.provenance.consent.expires_at.as_deref(),
                    revocation_status: &self.provenance.consent.revocation_status,
                },
                snapshot_generation_id: self.provenance.snapshot_generation_id.as_deref(),
                snapshot_published_at: self.provenance.snapshot_published_at.as_deref(),
            },
        };
        let mut bytes = Zeroizing::new(Vec::with_capacity(limit));
        let mut writer = BoundedResponseWriter::new(&mut bytes, limit);
        if serde_json::to_writer(&mut writer, &envelope).is_err() {
            return Err(if writer.exceeded {
                ConsultationResponseError::ResponseTooLarge
            } else {
                ConsultationResponseError::Serialization
            });
        }
        Ok(bytes)
    }
}

impl fmt::Debug for PublishableConsultationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishableConsultationResponse")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize)]
struct ConsultationResult<'a> {
    schema: &'static str,
    consultation_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    notary_evaluation_id: Option<&'a str>,
    profile: ResponseProfile<'a>,
    outcome: &'static str,
    data: Option<&'a BTreeMap<String, BatchTerminalScalar>>,
    provenance: ResponseProvenance<'a>,
}

#[derive(Serialize)]
struct ResponseProfile<'a> {
    id: &'a str,
    version: &'a str,
    contract_hash: &'a str,
}

#[derive(Serialize)]
struct ResponseProvenance<'a> {
    relay_acquired_at: &'a str,
    source_observed_at: Option<&'a str>,
    source_revision: Option<&'a str>,
    acquisition_class: &'a str,
    integration_pack: ResponseIntegrationPack<'a>,
    policy_id: &'a str,
    policy_hash: &'a str,
    consent: ResponseConsent<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_generation_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_published_at: Option<&'a str>,
}

#[derive(Serialize)]
struct ResponseIntegrationPack<'a> {
    id: &'a str,
    version: &'a str,
    hash: &'a str,
}

#[derive(Serialize)]
struct ResponseConsent<'a> {
    outcome: &'a str,
    verifier_id: Option<&'a str>,
    verifier_revision: Option<&'a str>,
    checked_at: Option<&'a str>,
    expires_at: Option<&'a str>,
    revocation_status: &'a str,
}

enum ProjectedRecord<'a> {
    Facts(&'a ValidatedFactMap),
    Snapshot {
        fields: &'a serde_json::Map<String, serde_json::Value>,
        output_fields: Vec<(&'a str, bool)>,
    },
    #[cfg(test)]
    Test(&'a [(&'a str, TestProjectedScalar<'a>)]),
}

impl ProjectedRecord<'_> {
    fn into_terminal_fields(
        self,
    ) -> Result<BTreeMap<String, BatchTerminalScalar>, ConsultationResponseError> {
        let mut output = BTreeMap::new();
        match self {
            Self::Facts(facts) => {
                for (name, value) in facts.fields() {
                    let value = match value {
                        ProjectedJsonScalar::Null => BatchTerminalScalar::Null,
                        ProjectedJsonScalar::String(value) => {
                            BatchTerminalScalar::String(Zeroizing::new(value.as_str().to_owned()))
                        }
                        ProjectedJsonScalar::Boolean(value) => BatchTerminalScalar::Boolean(*value),
                        ProjectedJsonScalar::Integer(value) => BatchTerminalScalar::Integer(*value),
                        ProjectedJsonScalar::Number(_) => {
                            return Err(ConsultationResponseError::Serialization);
                        }
                    };
                    output.insert(name.to_owned(), value);
                }
            }
            Self::Snapshot {
                fields,
                output_fields,
            } => {
                for (name, presence) in output_fields {
                    let value = if presence {
                        BatchTerminalScalar::Boolean(true)
                    } else {
                        terminal_scalar_from_json(
                            fields
                                .get(name)
                                .ok_or(ConsultationResponseError::Serialization)?,
                        )?
                    };
                    output.insert(name.to_owned(), value);
                }
            }
            #[cfg(test)]
            Self::Test(fields) => {
                for (name, value) in fields {
                    let value = match value {
                        TestProjectedScalar::Null => BatchTerminalScalar::Null,
                        TestProjectedScalar::String(value) => {
                            BatchTerminalScalar::String(Zeroizing::new((*value).to_owned()))
                        }
                        TestProjectedScalar::Boolean(value) => BatchTerminalScalar::Boolean(*value),
                        TestProjectedScalar::Integer(value) => BatchTerminalScalar::Integer(*value),
                        TestProjectedScalar::Number(_) => {
                            return Err(ConsultationResponseError::Serialization);
                        }
                    };
                    output.insert((*name).to_owned(), value);
                }
            }
        }
        Ok(output)
    }
}

fn terminal_scalar_from_json(
    value: &serde_json::Value,
) -> Result<BatchTerminalScalar, ConsultationResponseError> {
    match value {
        serde_json::Value::Null => Ok(BatchTerminalScalar::Null),
        serde_json::Value::String(value) => {
            Ok(BatchTerminalScalar::String(Zeroizing::new(value.clone())))
        }
        serde_json::Value::Bool(value) => Ok(BatchTerminalScalar::Boolean(*value)),
        serde_json::Value::Number(value) => value
            .as_i64()
            .map(BatchTerminalScalar::Integer)
            .ok_or(ConsultationResponseError::Serialization),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            Err(ConsultationResponseError::Serialization)
        }
    }
}

impl Serialize for ProjectedRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Facts(facts) => {
                let mut map = serializer.serialize_map(Some(facts.fields.len()))?;
                for (name, value) in facts.fields() {
                    map.serialize_entry(name, &ProjectedScalar(value))?;
                }
                map.end()
            }
            Self::Snapshot {
                fields,
                output_fields,
            } => {
                let mut map = serializer.serialize_map(Some(output_fields.len()))?;
                for (name, presence) in output_fields {
                    if *presence {
                        map.serialize_entry(*name, &true)?;
                    } else {
                        let value = fields.get(*name).ok_or_else(|| {
                            serde::ser::Error::custom("snapshot output field is unavailable")
                        })?;
                        map.serialize_entry(*name, value)?;
                    }
                }
                map.end()
            }
            #[cfg(test)]
            Self::Test(fields) => {
                let mut map = serializer.serialize_map(Some(fields.len()))?;
                for (name, value) in *fields {
                    map.serialize_entry(name, value)?;
                }
                map.end()
            }
        }
    }
}

trait SealedResponseProvenance<'a> {
    fn source_observed_at(&self) -> Result<Option<String>, ConsultationResponseError>;
    fn source_revision(&self) -> Option<&'a str>;
    fn snapshot_generation_id(&self) -> Option<String>;
    fn snapshot_published_at(&self) -> Result<Option<String>, ConsultationResponseError>;
}

struct LiveResponseProvenance;

impl<'a> SealedResponseProvenance<'a> for LiveResponseProvenance {
    fn source_observed_at(&self) -> Result<Option<String>, ConsultationResponseError> {
        Ok(None)
    }

    fn source_revision(&self) -> Option<&'a str> {
        None
    }

    fn snapshot_generation_id(&self) -> Option<String> {
        None
    }

    fn snapshot_published_at(&self) -> Result<Option<String>, ConsultationResponseError> {
        Ok(None)
    }
}

struct SnapshotResponseProvenance<'a> {
    source_observed_at_unix_ms: Option<i64>,
    source_revision: Option<&'a str>,
    generation_id: crate::consultation::SnapshotGenerationId,
    published_at_unix_ms: i64,
}

impl<'a> SealedResponseProvenance<'a> for SnapshotResponseProvenance<'a> {
    fn source_observed_at(&self) -> Result<Option<String>, ConsultationResponseError> {
        self.source_observed_at_unix_ms
            .map(rfc3339_milliseconds)
            .transpose()
    }

    fn source_revision(&self) -> Option<&'a str> {
        self.source_revision
    }

    fn snapshot_generation_id(&self) -> Option<String> {
        Some(self.generation_id.to_canonical_string())
    }

    fn snapshot_published_at(&self) -> Result<Option<String>, ConsultationResponseError> {
        rfc3339_milliseconds(self.published_at_unix_ms).map(Some)
    }
}

#[cfg(test)]
enum TestProjectedScalar<'a> {
    Null,
    String(&'a str),
    Boolean(bool),
    Integer(i64),
    Number(f64),
}

#[cfg(test)]
impl Serialize for TestProjectedScalar<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Null => serializer.serialize_none(),
            Self::String(value) => serializer.serialize_str(value),
            Self::Boolean(value) => serializer.serialize_bool(*value),
            Self::Integer(value) => serializer.serialize_i64(*value),
            Self::Number(value) => serializer.serialize_f64(*value),
        }
    }
}

struct ProjectedScalar<'a>(&'a ProjectedJsonScalar);

impl Serialize for ProjectedScalar<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            ProjectedJsonScalar::Null => serializer.serialize_none(),
            ProjectedJsonScalar::String(value) => serializer.serialize_str(value),
            ProjectedJsonScalar::Boolean(value) => serializer.serialize_bool(*value),
            ProjectedJsonScalar::Integer(value) => serializer.serialize_i64(*value),
            ProjectedJsonScalar::Number(value) => serializer.serialize_f64(*value),
        }
    }
}

struct BoundedResponseWriter<'a> {
    bytes: &'a mut Zeroizing<Vec<u8>>,
    limit: usize,
    exceeded: bool,
}

impl<'a> BoundedResponseWriter<'a> {
    fn new(bytes: &'a mut Zeroizing<Vec<u8>>, limit: usize) -> Self {
        Self {
            bytes,
            limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedResponseWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let within_limit = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .is_some_and(|length| length <= self.limit);
        if !within_limit {
            self.exceeded = true;
            return Err(io::Error::other("consultation response limit exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn rfc3339_milliseconds(unix_ms: i64) -> Result<String, ConsultationResponseError> {
    let unix_nanos = i128::from(unix_ms)
        .checked_mul(1_000_000)
        .ok_or(ConsultationResponseError::InvalidTime)?;
    OffsetDateTime::from_unix_timestamp_nanos(unix_nanos)
        .map_err(|_| ConsultationResponseError::InvalidTime)?
        .format(&Rfc3339)
        .map_err(|_| ConsultationResponseError::InvalidTime)
}

fn valid_full_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| value[range].parse::<u16>().ok();
    let (Some(year), Some(month), Some(day)) = (number(0..4), number(5..7), number(8..10)) else {
        return false;
    };
    let Ok(month) = time::Month::try_from(u8::try_from(month).unwrap_or(0)) else {
        return false;
    };
    time::Date::from_calendar_date(i32::from(year), month, u8::try_from(day).unwrap_or(0)).is_ok()
}

fn valid_rfc3339_milliseconds(value: &str) -> bool {
    value.len() == 24
        && value.as_bytes().get(19) == Some(&b'.')
        && value.as_bytes().get(23) == Some(&b'Z')
        && value.as_bytes()[20..23].iter().all(u8::is_ascii_digit)
        && OffsetDateTime::parse(value, &Rfc3339).is_ok()
}

const fn outcome_str(outcome: ConsultationOutcome) -> &'static str {
    match outcome {
        ConsultationOutcome::Match => "match",
        ConsultationOutcome::NoMatch => "no_match",
        ConsultationOutcome::Ambiguous => "ambiguous",
    }
}

const fn acquisition_class_str(class: AcquisitionClass) -> &'static str {
    match class {
        AcquisitionClass::SourceProjectedExact => "source_projected_exact",
        AcquisitionClass::BoundedFullRecord => "bounded_full_record",
        AcquisitionClass::MaterializedSnapshot => "materialized_snapshot",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::{json, Value};

    use crate::source_plan::dhis2_runtime_vector_plan_fixture;

    #[test]
    fn response_timestamp_is_utc_rfc3339_and_millisecond_exact() {
        assert_eq!(
            rfc3339_milliseconds(1_752_148_800_123).unwrap(),
            "2025-07-10T12:00:00.123Z"
        );
        assert_eq!(
            rfc3339_milliseconds(-1),
            Ok("1969-12-31T23:59:59.999Z".into())
        );
    }

    #[test]
    fn frozen_public_vocabulary_is_complete() {
        assert_eq!(outcome_str(ConsultationOutcome::Match), "match");
        assert_eq!(outcome_str(ConsultationOutcome::NoMatch), "no_match");
        assert_eq!(outcome_str(ConsultationOutcome::Ambiguous), "ambiguous");
        assert_eq!(
            acquisition_class_str(AcquisitionClass::SourceProjectedExact),
            "source_projected_exact"
        );
        assert_eq!(
            acquisition_class_str(AcquisitionClass::BoundedFullRecord),
            "bounded_full_record"
        );
        assert_eq!(
            acquisition_class_str(AcquisitionClass::MaterializedSnapshot),
            "materialized_snapshot"
        );
    }

    #[test]
    fn final_fact_validation_enforces_compiled_string_and_integer_bounds() {
        let string_plan = dhis2_runtime_vector_plan_fixture();
        assert!(ValidatedFactMap::try_new(
            string_plan.runtime_profile(),
            vec![(
                "status".into(),
                ProjectedJsonScalar::String(Zeroizing::new("x".repeat(32))),
            )],
        )
        .is_ok());
        assert!(ValidatedFactMap::try_new(
            string_plan.runtime_profile(),
            vec![(
                "status".into(),
                ProjectedJsonScalar::String(Zeroizing::new("x".repeat(33))),
            )],
        )
        .is_err());

        let mut integer_plan = dhis2_runtime_vector_plan_fixture();
        integer_plan
            .runtime_profile_mut_for_test()
            .replace_output_shape_for_test(
                "status",
                CompiledOutputShape::Integer {
                    nullable: false,
                    minimum: -2,
                    maximum: 2,
                },
            )
            .expect("test output shape");
        assert!(ValidatedFactMap::try_new(
            integer_plan.runtime_profile(),
            vec![("status".into(), ProjectedJsonScalar::Integer(2))],
        )
        .is_ok());
        assert!(ValidatedFactMap::try_new(
            integer_plan.runtime_profile(),
            vec![("status".into(), ProjectedJsonScalar::Integer(3))],
        )
        .is_err());
    }

    #[test]
    fn snapshot_projection_derives_presence_without_a_physical_field() {
        let fields = serde_json::Map::from_iter([(
            "registration_status".to_owned(),
            Value::String("active".to_owned()),
        )]);
        let projected = ProjectedRecord::Snapshot {
            fields: &fields,
            output_fields: vec![("exists", true), ("registration_status", false)],
        };
        assert_eq!(
            serde_json::to_value(projected).expect("snapshot projection"),
            json!({"exists": true, "registration_status": "active"})
        );
    }

    #[test]
    fn exact_response_shape_covers_all_outcomes_consent_and_optional_notary_id() {
        let plan = dhis2_runtime_vector_plan_fixture();
        let profile = plan.runtime_profile();
        let notary = NotaryEvaluationId::try_parse("01JYZZZZZZZZZZZZZZZZZZZZZZ").unwrap();
        let match_fields = [("status", TestProjectedScalar::String("ACTIVE"))];
        let cases = [
            (
                ConsultationOutcome::Match,
                Some(ProjectedRecord::Test(&match_fields[..])),
                Some(notary),
                json!({"status": "ACTIVE"}),
            ),
            (ConsultationOutcome::NoMatch, None, None, Value::Null),
            (ConsultationOutcome::Ambiguous, None, None, Value::Null),
        ];

        for (outcome, data, evaluation_id, expected_data) in cases {
            let candidate = PublishableConsultationResponse::serialize_validated_live_result(
                ConsultationId::generate(),
                evaluation_id,
                profile,
                outcome,
                data,
                1_752_148_800_123,
            )
            .expect("frozen response serializes");
            let value: Value = serde_json::from_slice(candidate.bytes_for_test()).unwrap();
            assert_eq!(
                value.as_object().unwrap().keys().collect::<Vec<_>>(),
                [
                    "consultation_id",
                    "data",
                    "notary_evaluation_id",
                    "outcome",
                    "profile",
                    "provenance",
                    "schema",
                ]
                .into_iter()
                .filter(|key| evaluation_id.is_some() || *key != "notary_evaluation_id")
                .collect::<Vec<_>>()
            );
            assert_eq!(value["schema"], "registry.relay.consultation-result.v1");
            assert_eq!(value["outcome"], outcome_str(outcome));
            assert_eq!(value["data"], expected_data);
            assert_eq!(value["profile"]["id"], profile.profile().id().as_str());
            assert_eq!(
                value["profile"]["contract_hash"],
                profile.profile().contract_hash().as_str()
            );
            assert_eq!(
                value["provenance"]["relay_acquired_at"],
                "2025-07-10T12:00:00.123Z"
            );
            assert_eq!(value["provenance"]["source_observed_at"], Value::Null);
            assert_eq!(value["provenance"]["source_revision"], Value::Null);
            assert_eq!(
                value["provenance"]["consent"],
                json!({
                    "outcome": "not_required",
                    "verifier_id": null,
                    "verifier_revision": null,
                    "checked_at": null,
                    "expires_at": null,
                    "revocation_status": "not_applicable"
                })
            );
            assert_eq!(
                value.get("notary_evaluation_id").and_then(Value::as_str),
                evaluation_id.map(|id| id.to_canonical_string()).as_deref()
            );
        }
    }

    #[test]
    fn bounded_writer_never_grows_or_retains_bytes_beyond_its_limit() {
        let mut bytes = Zeroizing::new(Vec::with_capacity(4));
        let mut writer = BoundedResponseWriter::new(&mut bytes, 4);
        assert_eq!(writer.write(b"1234").unwrap(), 4);
        assert!(writer.write(b"5").is_err());
        assert!(writer.exceeded);
        assert_eq!(bytes.as_slice(), b"1234");
        assert_eq!(bytes.capacity(), 4);
    }

    #[test]
    fn test_projection_serializer_covers_every_platform_scalar_kind() {
        let fields = [
            ("null", TestProjectedScalar::Null),
            ("string", TestProjectedScalar::String("value")),
            ("boolean", TestProjectedScalar::Boolean(true)),
            ("integer", TestProjectedScalar::Integer(7)),
            ("number", TestProjectedScalar::Number(1.5)),
        ];
        assert_eq!(
            serde_json::to_value(ProjectedRecord::Test(&fields)).unwrap(),
            json!({
                "null": null,
                "string": "value",
                "boolean": true,
                "integer": 7,
                "number": 1.5
            })
        );
    }
}

//! Runtime-free wire contract between review producers and Registry Casework.
//!
//! This crate deliberately contains no policy evaluator, persistence, HTTP
//! client, source adapter, credential, or business-operation implementation.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const MAXIMUM_CANONICAL_CREATE_BYTES: usize = 96 * 1024;
pub const MAXIMUM_IDENTIFIER_BYTES: usize = 128;
pub const MAXIMUM_REFERENCE_BYTES: usize = 256;
pub const MAXIMUM_CONTEXT_BYTES: usize = 64 * 1024;
pub const MAXIMUM_RESULT_BYTES: usize = 16 * 1024;
pub const MAXIMUM_JSON_DEPTH: usize = 32;
pub const MAXIMUM_JSON_NODES: usize = 4096;
pub const REVIEW_REQUESTS_PATH: &str = "/v1/review-requests";
pub const REVIEW_RESULTS_FEED_PATH: &str = "/v1/review-results";
pub const REVIEW_COMPLETIONS_PATH: &str = "/v1/review-completions";

#[must_use]
pub fn review_request_path(request_id: Uuid) -> String {
    format!("{REVIEW_REQUESTS_PATH}/{request_id}")
}

#[must_use]
pub fn review_result_path(request_id: Uuid) -> String {
    format!("{}/{request_id}/result", REVIEW_REQUESTS_PATH)
}

#[must_use]
pub fn review_cancel_path(request_id: Uuid) -> String {
    format!("{}/{request_id}/cancel", REVIEW_REQUESTS_PATH)
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentDigest(String);

impl ContentDigest {
    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        let suffix = value.strip_prefix("sha256:").ok_or(ProtocolError::Digest)?;
        if suffix.len() != 64
            || suffix
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(ProtocolError::Digest);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn for_bytes(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut value = String::with_capacity(71);
        value.push_str("sha256:");
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Self(value)
    }
}

impl fmt::Debug for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ContentDigest")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for ContentDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ContentDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

pub type SubmissionDigest = ContentDigest;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectBinding {
    pub source: String,
    #[serde(rename = "type")]
    pub subject_type: String,
    pub id: String,
    pub version: String,
    pub digest: ContentDigest,
}

impl SubjectBinding {
    pub fn check(&self) -> Result<(), ProtocolError> {
        for value in [&self.source, &self.subject_type, &self.id, &self.version] {
            check_bounded_text(value, MAXIMUM_IDENTIFIER_BYTES)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyBinding {
    pub id: String,
    pub version: String,
    pub digest: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HumanIdentity {
    pub issuer: String,
    pub subject: String,
}

impl HumanIdentity {
    pub fn check(&self) -> Result<(), ProtocolError> {
        check_bounded_text(&self.issuer, MAXIMUM_REFERENCE_BYTES)?;
        check_bounded_text(&self.subject, MAXIMUM_REFERENCE_BYTES)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceContextBinding {
    pub reference: String,
}

impl SourceContextBinding {
    pub fn check(&self) -> Result<(), ProtocolError> {
        check_bounded_text(&self.reference, MAXIMUM_REFERENCE_BYTES)
    }
}

impl PolicyBinding {
    pub fn check(&self) -> Result<(), ProtocolError> {
        check_bounded_text(&self.id, MAXIMUM_IDENTIFIER_BYTES)?;
        check_bounded_text(&self.version, MAXIMUM_IDENTIFIER_BYTES)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "strategy",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ReviewContext {
    Submitted { snapshot: Value },
    Source { binding: SourceContextBinding },
}

impl ReviewContext {
    pub fn check(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Submitted { snapshot } => {
                if canonical_bytes(snapshot)?.len() > MAXIMUM_CONTEXT_BYTES {
                    return Err(ProtocolError::ContextTooLarge);
                }
            }
            Self::Source { binding } => binding.check()?,
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewCreateRequest {
    pub kind: String,
    pub subject: SubjectBinding,
    pub requester_reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator: Option<HumanIdentity>,
    pub context: ReviewContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_constraints: Option<Value>,
}

impl ReviewCreateRequest {
    pub fn check(&self) -> Result<(), ProtocolError> {
        check_bounded_text(&self.kind, MAXIMUM_IDENTIFIER_BYTES)?;
        check_bounded_text(&self.requester_reference, MAXIMUM_REFERENCE_BYTES)?;
        if let Some(initiator) = &self.initiator {
            initiator.check()?;
        }
        self.subject.check()?;
        self.context.check()?;
        if let Some(constraints) = &self.result_constraints {
            if canonical_bytes(constraints)?.len() > MAXIMUM_RESULT_BYTES {
                return Err(ProtocolError::ResultTooLarge);
            }
        }
        if canonical_bytes(self)?.len() > MAXIMUM_CANONICAL_CREATE_BYTES {
            return Err(ProtocolError::CreateTooLarge);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmissionIdentity<'a> {
    pub producer: &'a str,
    pub source_namespace: &'a str,
    pub request: &'a ReviewCreateRequest,
}

pub fn submission_digest(
    producer: &str,
    source_namespace: &str,
    request: &ReviewCreateRequest,
) -> Result<SubmissionDigest, ProtocolError> {
    request.check()?;
    check_bounded_text(producer, MAXIMUM_IDENTIFIER_BYTES)?;
    check_bounded_text(source_namespace, MAXIMUM_IDENTIFIER_BYTES)?;
    let bytes = canonical_bytes(&SubmissionIdentity {
        producer,
        source_namespace,
        request,
    })?;
    Ok(ContentDigest::for_bytes(&bytes))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewRequestAccepted {
    pub request_id: Uuid,
    pub subject: SubjectBinding,
    pub policy: PolicyBinding,
    pub submission_digest: SubmissionDigest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewRequestLifecycle {
    Reviewing,
    Approved,
    Rejected,
    ChangesRequested,
    Answered,
    Cancelled,
    Superseded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewRequestView {
    pub request_id: Uuid,
    pub subject: SubjectBinding,
    pub policy: PolicyBinding,
    pub submission_digest: SubmissionDigest,
    pub requester_reference: String,
    pub lifecycle: ReviewRequestLifecycle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_stage: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewResultStatus {
    Approved,
    Rejected,
    ChangesRequested,
    Answered,
    Cancelled,
    Superseded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewResult {
    pub result_id: Uuid,
    pub request_id: Uuid,
    pub subject: SubjectBinding,
    pub policy: PolicyBinding,
    pub submission_digest: SubmissionDigest,
    pub status: ReviewResultStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    pub completed_at: DateTime<Utc>,
    pub available_until: DateTime<Utc>,
}

impl ReviewResult {
    pub fn check(&self) -> Result<(), ProtocolError> {
        self.subject.check()?;
        self.policy.check()?;
        if self.available_until <= self.completed_at {
            return Err(ProtocolError::Availability);
        }
        if let Some(outcome) = &self.outcome {
            check_bounded_text(outcome, MAXIMUM_IDENTIFIER_BYTES)?;
        }
        if let Some(result) = &self.result {
            if canonical_bytes(result)?.len() > MAXIMUM_RESULT_BYTES {
                return Err(ProtocolError::ResultTooLarge);
            }
        }
        match self.status {
            ReviewResultStatus::Approved
            | ReviewResultStatus::Cancelled
            | ReviewResultStatus::Superseded
                if self.outcome.is_some() || self.result.is_some() =>
            {
                Err(ProtocolError::TerminalPayload)
            }
            ReviewResultStatus::Rejected
            | ReviewResultStatus::ChangesRequested
            | ReviewResultStatus::Answered
                if self.outcome.is_none() =>
            {
                Err(ProtocolError::TerminalPayload)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewResultFeedEntry {
    pub event_id: Uuid,
    pub request_id: Uuid,
    pub result_id: Uuid,
    pub completed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewResultFeedPage {
    pub items: Vec<ReviewResultFeedEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewResultLookup {
    Available,
    Pending,
    ConcealedOrUnknown,
    Expired,
}

impl ReviewResultLookup {
    pub fn from_status(status: u16) -> Result<Self, ProtocolError> {
        match status {
            200 => Ok(Self::Available),
            202 => Ok(Self::Pending),
            404 => Ok(Self::ConcealedOrUnknown),
            410 => Ok(Self::Expired),
            _ => Err(ProtocolError::UnexpectedResultStatus),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewCancelRequest {
    pub subject: SubjectBinding,
    pub reason: String,
}

impl ReviewCancelRequest {
    pub fn check(&self) -> Result<(), ProtocolError> {
        self.subject.check()?;
        check_bounded_text(&self.reason, MAXIMUM_REFERENCE_BYTES)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "outcome",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ReviewCancelResponse {
    Cancelled { result: ReviewResult },
    AlreadyTerminal { result: ReviewResult },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewCompletion {
    #[serde(rename = "type")]
    pub event_type: ReviewCompletionType,
    pub event_id: Uuid,
    pub request_id: Uuid,
    pub result_id: Uuid,
    pub completed_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReviewCompletionType {
    #[serde(rename = "review.completed")]
    ReviewCompleted,
}

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let value = serde_json::to_value(value).map_err(|_| ProtocolError::Canonical)?;
    check_json_complexity(&value)?;
    registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| ProtocolError::Canonical)
}

fn check_json_complexity(value: &Value) -> Result<(), ProtocolError> {
    let mut pending = vec![(value, 1usize)];
    let mut nodes = 0usize;
    while let Some((value, depth)) = pending.pop() {
        nodes = nodes.checked_add(1).ok_or(ProtocolError::JsonComplexity)?;
        if depth > MAXIMUM_JSON_DEPTH || nodes > MAXIMUM_JSON_NODES {
            return Err(ProtocolError::JsonComplexity);
        }
        match value {
            Value::Array(items) => pending.extend(items.iter().map(|item| (item, depth + 1))),
            Value::Object(fields) => {
                pending.extend(fields.values().map(|item| (item, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn check_bounded_text(value: &str, maximum: usize) -> Result<(), ProtocolError> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        Err(ProtocolError::Text)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProtocolError {
    #[error("digest must be a lowercase sha256 digest")]
    Digest,
    #[error("a required text value is empty, unbounded, or contains controls")]
    Text,
    #[error("the review context exceeds the protocol bound")]
    ContextTooLarge,
    #[error("the create request exceeds the protocol bound")]
    CreateTooLarge,
    #[error("the result or result constraints exceed the protocol bound")]
    ResultTooLarge,
    #[error("the value cannot be canonically encoded")]
    Canonical,
    #[error("the JSON value exceeds the protocol complexity bound")]
    JsonComplexity,
    #[error("the terminal status does not permit the supplied outcome or result")]
    TerminalPayload,
    #[error("result availability must end after completion")]
    Availability,
    #[error("the result endpoint returned a status outside the review lookup contract")]
    UnexpectedResultStatus,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn request() -> ReviewCreateRequest {
        ReviewCreateRequest {
            kind: "registry-correction".to_owned(),
            subject: SubjectBinding {
                source: "registry".to_owned(),
                subject_type: "change-request".to_owned(),
                id: "proposal-7".to_owned(),
                version: "3".to_owned(),
                digest: ContentDigest::for_bytes(b"proposal"),
            },
            requester_reference: "source-request-7".to_owned(),
            initiator: Some(HumanIdentity {
                issuer: "https://issuer.example".to_owned(),
                subject: "person-2".to_owned(),
            }),
            context: ReviewContext::Source {
                binding: SourceContextBinding {
                    reference: "proposal-7".to_owned(),
                },
            },
            result_constraints: None,
        }
    }

    #[test]
    fn submission_digest_binds_producer_namespace_and_entire_request() {
        let request = request();
        let digest = submission_digest("producer-a", "registry", &request).unwrap();
        assert_eq!(
            digest,
            submission_digest("producer-a", "registry", &request).unwrap()
        );
        assert_ne!(
            digest,
            submission_digest("producer-b", "registry", &request).unwrap()
        );
        let mut changed = request;
        changed.requester_reference = "other-reference".to_owned();
        assert_ne!(
            digest,
            submission_digest("producer-a", "registry", &changed).unwrap()
        );
    }

    #[test]
    fn approved_result_cannot_carry_a_custom_outcome_or_payload() {
        let completed_at = Utc.with_ymd_and_hms(2026, 9, 19, 0, 0, 0).unwrap();
        let result = ReviewResult {
            result_id: Uuid::nil(),
            request_id: Uuid::nil(),
            subject: request().subject,
            policy: PolicyBinding {
                id: "registry-correction".to_owned(),
                version: "1".to_owned(),
                digest: ContentDigest::for_bytes(b"policy"),
            },
            submission_digest: ContentDigest::for_bytes(b"submission"),
            status: ReviewResultStatus::Approved,
            outcome: Some("approved".to_owned()),
            result: Some(json!({"approved": true})),
            completed_at,
            available_until: completed_at + chrono::Duration::days(30),
        };
        assert_eq!(result.check(), Err(ProtocolError::TerminalPayload));
    }

    #[test]
    fn corrective_results_require_a_configured_outcome() {
        let completed_at = Utc.with_ymd_and_hms(2026, 9, 19, 0, 0, 0).unwrap();
        let result = ReviewResult {
            result_id: Uuid::nil(),
            request_id: Uuid::nil(),
            subject: request().subject,
            policy: PolicyBinding {
                id: "registry-correction".to_owned(),
                version: "1".to_owned(),
                digest: ContentDigest::for_bytes(b"policy"),
            },
            submission_digest: ContentDigest::for_bytes(b"submission"),
            status: ReviewResultStatus::ChangesRequested,
            outcome: None,
            result: None,
            completed_at,
            available_until: completed_at + chrono::Duration::days(30),
        };
        assert_eq!(result.check(), Err(ProtocolError::TerminalPayload));
    }

    #[test]
    fn completion_envelope_contains_no_result_or_destination() {
        let completed_at = Utc.with_ymd_and_hms(2026, 9, 19, 0, 0, 0).unwrap();
        let completion = ReviewCompletion {
            event_type: ReviewCompletionType::ReviewCompleted,
            event_id: Uuid::nil(),
            request_id: Uuid::nil(),
            result_id: Uuid::nil(),
            completed_at,
        };
        assert_eq!(
            serde_json::to_value(completion).unwrap(),
            json!({
                "type": "review.completed",
                "eventId": Uuid::nil(),
                "requestId": Uuid::nil(),
                "resultId": Uuid::nil(),
                "completedAt": completed_at,
            })
        );
    }

    #[test]
    fn result_lookup_statuses_are_closed() {
        assert_eq!(
            ReviewResultLookup::from_status(202),
            Ok(ReviewResultLookup::Pending)
        );
        assert_eq!(
            ReviewResultLookup::from_status(500),
            Err(ProtocolError::UnexpectedResultStatus)
        );
    }

    #[test]
    fn constructed_json_values_are_depth_and_node_bounded() {
        let mut too_deep = Value::Null;
        for _ in 0..MAXIMUM_JSON_DEPTH {
            too_deep = json!([too_deep]);
        }
        assert_eq!(
            canonical_bytes(&too_deep),
            Err(ProtocolError::JsonComplexity)
        );

        let too_many_nodes = Value::Array(vec![Value::Null; MAXIMUM_JSON_NODES]);
        assert_eq!(
            canonical_bytes(&too_many_nodes),
            Err(ProtocolError::JsonComplexity)
        );
    }
}

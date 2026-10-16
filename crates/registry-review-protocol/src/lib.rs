//! Runtime-free wire contract between review producers and review providers.
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
/// Upper bound for the reason a decision gives the subject's owner, matching
/// the bound Casework keeps on the private reason a reviewer records.
pub const MAXIMUM_PUBLIC_REASON_BYTES: usize = 2_000;
pub const MAXIMUM_JSON_DEPTH: usize = 32;
pub const MAXIMUM_JSON_NODES: usize = 4096;
pub const MAXIMUM_PORTABLE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
pub const REVIEW_REQUESTS_PATH: &str = "/v1/review-requests";
pub const REVIEW_RESULTS_FEED_PATH: &str = "/v1/review-results";
pub const REVIEW_COMPLETIONS_PATH: &str = "/v1/review-completions";
pub const REVIEW_PROFILE_HEADER: &str = "registry-review-profile";
pub const REVIEW_VALIDATION_PATH_HEADER: &str = "registry-review-validation-path";
pub const REVIEW_VALIDATION_REASON_HEADER: &str = "registry-review-validation-reason";

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

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ContentDigest {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ContentDigest".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71})
    }
}

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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyBinding {
    pub id: String,
    pub version: String,
    pub digest: ContentDigest,
}

/// Select the trusted provider's current policy, or require one exact binding.
/// The selector stays in the submission identity; acceptance records the concrete binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", schemars(extend("dependentRequired" = {"version": ["digest"], "digest": ["version"]})))]
pub struct PolicySelection {
    pub id: String,
    #[serde(
        default,
        deserialize_with = "deserialize_present_pin",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub version: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_pin",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "ContentDigest"))]
    pub digest: Option<ContentDigest>,
}

fn deserialize_present_pin<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl PolicySelection {
    pub fn current(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: None,
            digest: None,
        }
    }

    pub fn check(&self) -> Result<(), ProtocolError> {
        check_bounded_text(&self.id, MAXIMUM_IDENTIFIER_BYTES)?;
        match (&self.version, &self.digest) {
            (None, None) => Ok(()),
            (Some(version), Some(_)) => check_bounded_text(version, MAXIMUM_IDENTIFIER_BYTES),
            _ => Err(ProtocolError::PolicySelection),
        }
    }

    /// An omitted pin delegates version selection, never policy identity or authority.
    pub fn matches(&self, binding: &PolicyBinding) -> bool {
        self.check().is_ok()
            && binding.check().is_ok()
            && self.id == binding.id
            && match (&self.version, &self.digest) {
                (None, None) => true,
                (Some(version), Some(digest)) => {
                    version == &binding.version && digest == &binding.digest
                }
                _ => false,
            }
    }
}

impl From<PolicyBinding> for PolicySelection {
    fn from(binding: PolicyBinding) -> Self {
        Self {
            id: binding.id,
            version: Some(binding.version),
            digest: Some(binding.digest),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    tag = "mode",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ReviewContext {
    Submitted {
        #[cfg_attr(feature="schema",schemars(with="serde_json::Map<String,Value>",extend("x-maximum-canonical-bytes"=MAXIMUM_CONTEXT_BYTES,"x-maximum-json-depth"=MAXIMUM_JSON_DEPTH,"x-maximum-json-nodes"=MAXIMUM_JSON_NODES)))]
        snapshot: Value,
    },
    CurrentSource {
        binding: SourceContextBinding,
    },
}

impl ReviewContext {
    pub fn check(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Submitted { snapshot } => {
                if !snapshot.is_object() {
                    return Err(ProtocolError::ContextShape);
                }
                if canonical_bytes(snapshot)?.len() > MAXIMUM_CONTEXT_BYTES {
                    return Err(ProtocolError::ContextTooLarge);
                }
            }
            Self::CurrentSource { binding } => binding.check()?,
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewCreateRequest {
    pub policy: PolicySelection,
    pub subject: SubjectBinding,
    pub requester_reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator: Option<HumanIdentity>,
    pub context: ReviewContext,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature="schema",schemars(with="serde_json::Map<String,Value>",extend("x-maximum-canonical-bytes"=MAXIMUM_RESULT_BYTES)))]
    pub result_constraints: Option<Value>,
}

/// Preserve an explicitly present JSON `null` so semantic validation can
/// reject it as a non-object instead of treating it like an omitted field.
fn deserialize_present_value<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

impl ReviewCreateRequest {
    pub fn check(&self) -> Result<(), ProtocolError> {
        self.policy.check()?;
        check_bounded_text(&self.requester_reference, MAXIMUM_REFERENCE_BYTES)?;
        if let Some(initiator) = &self.initiator {
            initiator.check()?;
        }
        self.subject.check()?;
        self.context.check()?;
        if let Some(constraints) = &self.result_constraints {
            if !constraints.is_object() {
                return Err(ProtocolError::ResultShape);
            }
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewRequestAccepted {
    pub request_id: Uuid,
    pub subject: SubjectBinding,
    pub policy: PolicyBinding,
    pub submission_digest: SubmissionDigest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewResultStatus {
    Approved,
    Rejected,
    ChangesRequested,
    Answered,
    Cancelled,
    Superseded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
    /// Text the decision gives for release to the subject's owner. It is
    /// distinct from the reviewer's private reason, which never leaves
    /// Casework.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature="schema",schemars(length(min=1,max=MAXIMUM_PUBLIC_REASON_BYTES),extend("x-maximum-utf8-bytes"=MAXIMUM_PUBLIC_REASON_BYTES)))]
    pub public_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature="schema",schemars(with="serde_json::Map<String,Value>",extend("x-maximum-canonical-bytes"=MAXIMUM_RESULT_BYTES)))]
    pub result: Option<Value>,
    pub completed_at: DateTime<Utc>,
    pub available_until: DateTime<Utc>,
}

impl ReviewResult {
    pub fn check(&self) -> Result<(), ProtocolError> {
        // A nil result identifier cannot anchor the unique stored result a
        // later reconciliation or duplicate feed entry correlates against.
        if self.result_id.is_nil() {
            return Err(ProtocolError::Identifier);
        }
        self.subject.check()?;
        self.policy.check()?;
        if self.available_until <= self.completed_at {
            return Err(ProtocolError::Availability);
        }
        if let Some(outcome) = &self.outcome {
            check_bounded_text(outcome, MAXIMUM_IDENTIFIER_BYTES)?;
        }
        if let Some(public_reason) = &self.public_reason {
            check_public_reason(public_reason)?;
        }
        if let Some(result) = &self.result {
            if !result.is_object() {
                return Err(ProtocolError::ResultShape);
            }
            if canonical_bytes(result)?.len() > MAXIMUM_RESULT_BYTES {
                return Err(ProtocolError::ResultTooLarge);
            }
        }
        // Every decided status names the policy outcome that settled it; a
        // closed request was never decided, so it carries no decision text.
        match self.status {
            ReviewResultStatus::Cancelled | ReviewResultStatus::Superseded
                if self.outcome.is_some()
                    || self.public_reason.is_some()
                    || self.result.is_some() =>
            {
                Err(ProtocolError::TerminalPayload)
            }
            ReviewResultStatus::Approved if self.result.is_some() => {
                Err(ProtocolError::TerminalPayload)
            }
            ReviewResultStatus::Approved
            | ReviewResultStatus::Rejected
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewResultFeedEntry {
    pub event_id: Uuid,
    pub request_id: Uuid,
    pub result_id: Uuid,
    pub completed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewResultFeedPage {
    pub items: Vec<ReviewResultFeedEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Uuid>,
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    tag = "outcome",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ReviewCancelResponse {
    Cancelled { result: ReviewResult },
    AlreadyTerminal { result: ReviewResult },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
            Value::Number(number) => {
                let portable = if let Some(value) = number.as_i64() {
                    value.unsigned_abs() <= MAXIMUM_PORTABLE_JSON_INTEGER
                } else if let Some(value) = number.as_u64() {
                    value <= MAXIMUM_PORTABLE_JSON_INTEGER
                } else {
                    // `serde_json::Number` preserves whether a value was built as
                    // an integer or a floating-point number. The interop limit is
                    // for integer representations that JavaScript cannot carry
                    // exactly; finite scientific values remain valid JSON numbers.
                    number.as_f64().is_some()
                };
                if !portable {
                    return Err(ProtocolError::JsonIntegerRange);
                }
            }
            Value::Null | Value::Bool(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

/// Checks the text a decision gives for release to the subject's owner.
pub fn check_public_reason(value: &str) -> Result<(), ProtocolError> {
    check_bounded_text(value, MAXIMUM_PUBLIC_REASON_BYTES).map_err(|_| ProtocolError::PublicReason)
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
    #[error("a policy pin requires both version and digest")]
    PolicySelection,
    #[error("digest must be a lowercase sha256 digest")]
    Digest,
    #[error("a required text value is empty, unbounded, or contains controls")]
    Text,
    #[error("the review context exceeds the protocol bound")]
    ContextTooLarge,
    #[error("the submitted review context must be an object")]
    ContextShape,
    #[error("the create request exceeds the protocol bound")]
    CreateTooLarge,
    #[error("the result or result constraints exceed the protocol bound")]
    ResultTooLarge,
    #[error("the review result payload must be an object")]
    ResultShape,
    #[error("the value cannot be canonically encoded")]
    Canonical,
    #[error("the JSON value exceeds the protocol complexity bound")]
    JsonComplexity,
    #[error("a JSON integer is outside the portable exact-integer range")]
    JsonIntegerRange,
    #[error("the terminal status does not permit the supplied outcome or result")]
    TerminalPayload,
    #[error(
        "publicReason must be non-blank text of at most 2000 UTF-8 bytes without control characters"
    )]
    PublicReason,
    #[error("result availability must end after completion")]
    Availability,
    #[error("a correlation identifier cannot be the nil UUID")]
    Identifier,
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
            policy: PolicyBinding {
                id: "registry-correction".to_owned(),
                version: "1".to_owned(),
                digest: ContentDigest::for_bytes(b"policy"),
            }
            .into(),
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
            context: ReviewContext::CurrentSource {
                binding: SourceContextBinding {
                    reference: "proposal-7".to_owned(),
                },
            },
            result_constraints: None,
        }
    }

    #[test]
    fn policy_selection_freezes_the_original_selector_in_submission_identity() {
        let strict = request();
        let binding = PolicyBinding {
            id: strict.policy.id.clone(),
            version: "1".into(),
            digest: ContentDigest::for_bytes(b"policy"),
        };
        let mut current = strict.clone();
        current.policy = PolicySelection::current(&binding.id);
        assert_eq!(
            serde_json::to_value(&current.policy).unwrap(),
            json!({"id": binding.id})
        );
        assert!(current.check().is_ok());
        assert!(current.policy.matches(&binding));
        assert_ne!(
            submission_digest("producer", "registry", &current).unwrap(),
            submission_digest("producer", "registry", &strict).unwrap()
        );
        let mut changed = binding.clone();
        changed.version = "2".into();
        changed.digest = ContentDigest::for_bytes(b"next policy");
        assert!(current.policy.matches(&changed));
        assert!(!strict.policy.matches(&changed));
        changed.id = "another-policy".into();
        assert!(!current.policy.matches(&changed));
        for partial in [
            json!({"id": "review", "version": "1"}),
            json!({"id": "review", "digest": binding.digest}),
        ] {
            let partial: PolicySelection = serde_json::from_value(partial).unwrap();
            assert_eq!(partial.check(), Err(ProtocolError::PolicySelection));
            assert!(!partial.matches(&binding));
        }
        for invalid in [
            json!({"id":"review","version":null}),
            json!({"id":"review","digest":null}),
            json!({"id":"review","pin":{}}),
        ] {
            assert!(serde_json::from_value::<PolicySelection>(invalid).is_err());
        }
    }

    #[test]
    fn expected_policy_is_required_and_changes_submission_identity() {
        let original = request();
        let value = serde_json::to_value(&original).unwrap();
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("policy");
        assert!(serde_json::from_value::<ReviewCreateRequest>(missing.clone()).is_err());
        missing["kind"] = json!(original.policy.id);
        assert!(serde_json::from_value::<ReviewCreateRequest>(missing).is_err());
        let mut unknown = value.clone();
        unknown["kind"] = json!(original.policy.id);
        assert!(serde_json::from_value::<ReviewCreateRequest>(unknown).is_err());
        let mut unknown_policy_field = value.clone();
        unknown_policy_field["policy"]["other"] = json!(true);
        assert!(serde_json::from_value::<ReviewCreateRequest>(unknown_policy_field).is_err());

        let digest = submission_digest("producer-a", "registry", &original).unwrap();
        for (field, changed) in [
            ("id", json!("other-policy")),
            ("version", json!("2")),
            ("digest", json!(ContentDigest::for_bytes(b"changed-policy"))),
        ] {
            let mut changed_value = value.clone();
            changed_value["policy"][field] = changed;
            let changed: ReviewCreateRequest = serde_json::from_value(changed_value).unwrap();
            assert_ne!(
                submission_digest("producer-a", "registry", &changed).unwrap(),
                digest,
                "submission digest must bind policy {field}"
            );
        }
    }

    #[test]
    fn create_request_validates_the_complete_policy_binding() {
        for field in ["id", "version"] {
            for invalid in [String::new(), "x".repeat(MAXIMUM_IDENTIFIER_BYTES + 1)] {
                let mut value = serde_json::to_value(request()).unwrap();
                value["policy"][field] = json!(invalid);
                let request: ReviewCreateRequest = serde_json::from_value(value).unwrap();
                assert!(request.check().is_err(), "invalid policy {field}");
            }
        }
        let mut value = serde_json::to_value(request()).unwrap();
        value["policy"]["digest"] = json!("not-a-digest");
        assert!(serde_json::from_value::<ReviewCreateRequest>(value).is_err());
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
    fn result_constraints_must_be_objects() {
        for constraints in [json!("scalar"), json!(["array"])] {
            let mut request = request();
            request.result_constraints = Some(constraints);
            assert_eq!(request.check(), Err(ProtocolError::ResultShape));
        }
        let mut request = request();
        request.result_constraints = Some(json!({"type": "object"}));
        assert!(request.check().is_ok());
    }

    #[test]
    fn digest_bearing_json_requires_portable_exact_integers() {
        let mut request = request();
        request.context = ReviewContext::Submitted {
            snapshot: json!({"maximum": MAXIMUM_PORTABLE_JSON_INTEGER}),
        };
        assert!(request.check().is_ok());

        request.context = ReviewContext::Submitted {
            snapshot: json!({"tooLarge": MAXIMUM_PORTABLE_JSON_INTEGER + 1}),
        };
        assert_eq!(request.check(), Err(ProtocolError::JsonIntegerRange));

        request.context = ReviewContext::Submitted {
            snapshot: json!({"tooSmall": -(MAXIMUM_PORTABLE_JSON_INTEGER as i64) - 1}),
        };
        assert_eq!(request.check(), Err(ProtocolError::JsonIntegerRange));

        request.context = ReviewContext::Submitted {
            snapshot: json!({"scientific": 1e100_f64}),
        };
        assert!(request.check().is_ok());
    }

    #[test]
    fn create_request_preserves_explicit_null_result_constraints() {
        let mut value = serde_json::to_value(request()).expect("serialize review create request");
        value["resultConstraints"] = Value::Null;
        let explicit_null: ReviewCreateRequest =
            serde_json::from_value(value).expect("deserialize explicit null result constraints");
        assert_eq!(explicit_null.result_constraints, Some(Value::Null));

        let omitted: ReviewCreateRequest = serde_json::from_value(json!({
            "policy": {
                "id": "registry-correction",
                "version": "1",
                "digest": ContentDigest::for_bytes(b"policy").to_string()
            },
            "subject": {
                "source": "registry",
                "type": "change-request",
                "id": "proposal-7",
                "version": "3",
                "digest": ContentDigest::for_bytes(b"proposal").to_string()
            },
            "requesterReference": "source-request-7",
            "context": {
                "mode": "current-source",
                "binding": {"reference": "proposal-7"}
            }
        }))
        .expect("deserialize omitted result constraints");
        assert_eq!(omitted.result_constraints, None);
    }

    fn decided_result(status: ReviewResultStatus, outcome: Option<&str>) -> ReviewResult {
        let completed_at = Utc.with_ymd_and_hms(2026, 9, 19, 0, 0, 0).unwrap();
        ReviewResult {
            result_id: Uuid::from_u128(0x1),
            request_id: Uuid::nil(),
            subject: request().subject,
            policy: PolicyBinding {
                id: "registry-correction".to_owned(),
                version: "1".to_owned(),
                digest: ContentDigest::for_bytes(b"policy"),
            },
            submission_digest: ContentDigest::for_bytes(b"submission"),
            status,
            outcome: outcome.map(str::to_owned),
            public_reason: None,
            result: None,
            completed_at,
            available_until: completed_at + chrono::Duration::days(30),
        }
    }

    #[test]
    fn approved_result_names_its_outcome_but_carries_no_payload() {
        let mut result = decided_result(ReviewResultStatus::Approved, Some("approved"));
        assert!(result.check().is_ok());
        result.result = Some(json!({"approved": true}));
        assert_eq!(result.check(), Err(ProtocolError::TerminalPayload));
    }

    #[test]
    fn every_decided_result_requires_an_outcome() {
        for status in [
            ReviewResultStatus::Approved,
            ReviewResultStatus::Rejected,
            ReviewResultStatus::ChangesRequested,
            ReviewResultStatus::Answered,
        ] {
            assert_eq!(
                decided_result(status, None).check(),
                Err(ProtocolError::TerminalPayload),
                "{status:?}"
            );
            assert!(decided_result(status, Some("outcome")).check().is_ok());
        }
    }

    #[test]
    fn closed_results_carry_no_outcome_or_public_reason() {
        for status in [
            ReviewResultStatus::Cancelled,
            ReviewResultStatus::Superseded,
        ] {
            assert!(decided_result(status, None).check().is_ok());
            assert_eq!(
                decided_result(status, Some("approved")).check(),
                Err(ProtocolError::TerminalPayload)
            );
            let mut result = decided_result(status, None);
            result.public_reason = Some("Closed by the producer.".to_owned());
            assert_eq!(result.check(), Err(ProtocolError::TerminalPayload));
        }
    }

    #[test]
    fn decided_results_carry_a_bounded_public_reason() {
        let mut result = decided_result(ReviewResultStatus::Rejected, Some("rejected"));
        result.public_reason = Some("The submitted address could not be verified.".to_owned());
        assert!(result.check().is_ok());
        assert_eq!(
            serde_json::to_value(&result).unwrap()["publicReason"],
            json!("The submitted address could not be verified.")
        );
        result.public_reason = Some("x".repeat(MAXIMUM_PUBLIC_REASON_BYTES));
        assert!(result.check().is_ok());
        for refused in [
            "x".repeat(MAXIMUM_PUBLIC_REASON_BYTES + 1),
            "   ".to_owned(),
            "line\u{0}break".to_owned(),
        ] {
            result.public_reason = Some(refused);
            assert_eq!(result.check(), Err(ProtocolError::PublicReason));
        }
        assert!(ProtocolError::PublicReason
            .to_string()
            .contains(&MAXIMUM_PUBLIC_REASON_BYTES.to_string()));
        result.public_reason = None;
        assert!(serde_json::to_value(&result)
            .unwrap()
            .get("publicReason")
            .is_none());
    }

    #[test]
    fn corrective_results_require_a_configured_outcome() {
        let completed_at = Utc.with_ymd_and_hms(2026, 9, 19, 0, 0, 0).unwrap();
        let result = ReviewResult {
            result_id: Uuid::from_u128(0x1),
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
            public_reason: None,
            result: None,
            completed_at,
            available_until: completed_at + chrono::Duration::days(30),
        };
        assert_eq!(result.check(), Err(ProtocolError::TerminalPayload));
    }

    #[test]
    fn a_nil_result_identifier_cannot_anchor_stored_results() {
        let completed_at = Utc.with_ymd_and_hms(2026, 9, 19, 0, 0, 0).unwrap();
        let mut result = ReviewResult {
            result_id: Uuid::from_u128(0x1),
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
            public_reason: None,
            result: None,
            completed_at,
            available_until: completed_at + chrono::Duration::days(30),
        };
        assert!(result.check().is_ok());
        result.result_id = Uuid::nil();
        assert_eq!(result.check(), Err(ProtocolError::Identifier));
    }

    #[test]
    fn corrective_result_payloads_must_be_objects() {
        let completed_at = Utc.with_ymd_and_hms(2026, 9, 19, 0, 0, 0).unwrap();
        for payload in [json!("scalar"), json!(["array"])] {
            let result = ReviewResult {
                result_id: Uuid::from_u128(0x1),
                request_id: Uuid::nil(),
                subject: request().subject,
                policy: PolicyBinding {
                    id: "registry-correction".to_owned(),
                    version: "1".to_owned(),
                    digest: ContentDigest::for_bytes(b"policy"),
                },
                submission_digest: ContentDigest::for_bytes(b"submission"),
                status: ReviewResultStatus::ChangesRequested,
                outcome: Some("needs-correction".to_owned()),
                public_reason: None,
                result: Some(payload),
                completed_at,
                available_until: completed_at + chrono::Duration::days(30),
            };
            assert_eq!(result.check(), Err(ProtocolError::ResultShape));
        }
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
    fn multi_word_protocol_values_are_kebab_case() {
        assert_eq!(
            serde_json::to_value(ReviewRequestLifecycle::ChangesRequested).unwrap(),
            json!("changes-requested")
        );
        assert_eq!(
            serde_json::to_value(ReviewResultStatus::ChangesRequested).unwrap(),
            json!("changes-requested")
        );
        assert!(
            serde_json::from_value::<ReviewRequestLifecycle>(json!("changes_requested")).is_err()
        );
        assert!(serde_json::from_value::<ReviewResultStatus>(json!("changes_requested")).is_err());

        let result = ReviewResult {
            result_id: Uuid::from_u128(1),
            request_id: Uuid::nil(),
            subject: request().subject,
            policy: PolicyBinding {
                id: "registry-correction".to_owned(),
                version: "1".to_owned(),
                digest: ContentDigest::for_bytes(b"policy"),
            },
            submission_digest: submission_digest("producer", "registry", &request()).unwrap(),
            status: ReviewResultStatus::Cancelled,
            outcome: None,
            public_reason: None,
            result: None,
            completed_at: Utc.with_ymd_and_hms(2026, 9, 19, 0, 0, 0).unwrap(),
            available_until: Utc.with_ymd_and_hms(2026, 9, 20, 0, 0, 0).unwrap(),
        };
        let already_terminal = serde_json::to_value(ReviewCancelResponse::AlreadyTerminal {
            result: result.clone(),
        })
        .unwrap();
        assert_eq!(already_terminal["outcome"], json!("already-terminal"));
        let mut previous_spelling = already_terminal;
        previous_spelling["outcome"] = json!("already_terminal");
        assert!(serde_json::from_value::<ReviewCancelResponse>(previous_spelling).is_err());
        assert_eq!(
            serde_json::to_value(ReviewCancelResponse::Cancelled { result }).unwrap()["outcome"],
            json!("cancelled")
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

    #[test]
    fn submitted_context_is_an_object() {
        for snapshot in [Value::Null, json!([]), json!("scalar")] {
            assert_eq!(
                ReviewContext::Submitted { snapshot }.check(),
                Err(ProtocolError::ContextShape)
            );
        }
        assert!(ReviewContext::Submitted {
            snapshot: json!({"field": "value"})
        }
        .check()
        .is_ok());
    }

    #[cfg(feature = "schema")]
    #[test]
    fn schemas_follow_the_wire_shape() {
        let digest = serde_json::to_value(schemars::schema_for!(ContentDigest)).unwrap();
        assert_eq!(digest["type"], "string");
        assert_eq!(digest["pattern"], "^sha256:[0-9a-f]{64}$");

        let create = serde_json::to_value(schemars::schema_for!(ReviewCreateRequest)).unwrap();
        assert_eq!(create["additionalProperties"], false);
        let required = create["required"].as_array().unwrap();
        for field in ["policy", "subject", "requesterReference", "context"] {
            assert!(required.contains(&json!(field)), "{field} is not required");
        }
        assert!(!required.contains(&json!("initiator")));
        assert!(!required.contains(&json!("resultConstraints")));

        let result = serde_json::to_value(schemars::schema_for!(ReviewResult)).unwrap();
        let status = &result["$defs"]["ReviewResultStatus"];
        assert_eq!(
            status["enum"],
            json!([
                "approved",
                "rejected",
                "changes-requested",
                "answered",
                "cancelled",
                "superseded"
            ])
        );

        let cancel = serde_json::to_value(schemars::schema_for!(ReviewCancelResponse)).unwrap();
        let outcomes: Vec<_> = cancel["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .map(|branch| branch["properties"]["outcome"]["const"].clone())
            .collect();
        assert_eq!(outcomes, [json!("cancelled"), json!("already-terminal")]);
    }
}

#[cfg(test)]
mod policy_binding_tests {
    use super::*;
    #[test]
    fn expected_policy_is_required_and_old_kind_or_strategy_wire_is_refused() {
        let value = serde_json::json!({"policy":{"id":"review","version":"1","digest":ContentDigest::for_bytes(b"policy")},"subject":{"source":"source","type":"subject","id":"1","version":"1","digest":ContentDigest::for_bytes(b"subject")},"requesterReference":"request","context":{"mode":"submitted","snapshot":{}}});
        let request: ReviewCreateRequest = serde_json::from_value(value.clone()).unwrap();
        request.check().unwrap();
        let mut retired = value.clone();
        retired.as_object_mut().unwrap().remove("policy");
        retired["kind"] = serde_json::json!("review");
        assert!(serde_json::from_value::<ReviewCreateRequest>(retired).is_err());
        let mut retired = value;
        retired["context"] = serde_json::json!({"strategy":"submitted","snapshot":{}});
        assert!(serde_json::from_value::<ReviewCreateRequest>(retired).is_err());
        let original = submission_digest("producer", "source", &request).unwrap();
        let mut changed = request;
        changed.policy.version = Some("2".into());
        assert_ne!(
            original,
            submission_digest("producer", "source", &changed).unwrap()
        );
    }
}

use std::fmt;

use chrono::{DateTime, Utc};
use jsonschema::{Draft, JSONSchema};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{IssuerPrincipal, OccurrenceState, Page};

pub const MAXIMUM_HOSTED_KINDS: usize = 64;
pub const MAXIMUM_HOSTED_OUTCOMES: usize = 16;
pub const MAXIMUM_HOSTED_SCHEMA_BYTES: usize = 64 * 1024;
pub const MAXIMUM_HOSTED_DISPLAY_BYTES: usize = 16 * 1024;
pub const MAXIMUM_HOSTED_DISPLAY_DEPTH: usize = 16;
pub const MAXIMUM_HOSTED_REFERENCE_BYTES: usize = 128;
pub const MAXIMUM_HOSTED_NOTE_BYTES: usize = 2_000;
pub const MAXIMUM_HOSTED_REASON_BYTES: usize = 2_000;
pub const MAXIMUM_HOSTED_RETENTION_DAYS: u32 = 3_650;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedKindPolicy {
    pub id: String,
    pub version: String,
    pub queue: String,
    pub deciding_profiles: Vec<String>,
    pub retention: HostedRetentionPolicy,
    pub display_schema: Value,
    pub outcomes: Vec<HostedOutcomePolicy>,
}

impl HostedKindPolicy {
    pub fn check(&self) -> Result<(), HostedPolicyError> {
        if !valid_identifier(&self.id)
            || !valid_version(&self.version)
            || !valid_identifier(&self.queue)
            || self.deciding_profiles.is_empty()
            || self.deciding_profiles.len() > 16
            || !all_unique(self.deciding_profiles.iter().map(String::as_str))
            || self
                .deciding_profiles
                .iter()
                .any(|profile| !valid_identifier(profile))
        {
            return Err(HostedPolicyError::Identity);
        }
        self.retention.check()?;
        check_display_schema(&self.display_schema)?;
        if self.outcomes.is_empty()
            || self.outcomes.len() > MAXIMUM_HOSTED_OUTCOMES
            || !all_unique(self.outcomes.iter().map(|outcome| outcome.id.as_str()))
            || self.outcomes.iter().any(|outcome| !outcome.is_valid())
        {
            return Err(HostedPolicyError::Outcomes);
        }
        Ok(())
    }

    pub fn validate_display(&self, display: &Value) -> Result<(), HostedValidationError> {
        validate_display(&self.display_schema, display)
    }

    #[must_use]
    pub fn outcome(&self, id: &str) -> Option<&HostedOutcomePolicy> {
        self.outcomes.iter().find(|outcome| outcome.id == id)
    }

    pub fn policy_digest(&self) -> Result<HostedPolicyDigest, HostedPolicyError> {
        self.check()?;
        digest_policy(self)
    }

    pub fn snapshot(&self) -> Result<HostedKindPolicySnapshot, HostedPolicyError> {
        let digest = self.policy_digest()?;
        Ok(HostedKindPolicySnapshot {
            identity: HostedPolicyIdentity {
                kind_id: self.id.clone(),
                version: self.version.clone(),
                digest,
            },
            queue: self.queue.clone(),
            deciding_profiles: self.deciding_profiles.clone(),
            retention: self.retention.clone(),
            display_schema: self.display_schema.clone(),
            outcomes: self.outcomes.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedRetentionPolicy {
    pub terminal_days: u32,
    pub accountability_days: u32,
}

impl HostedRetentionPolicy {
    fn check(&self) -> Result<(), HostedPolicyError> {
        if self.terminal_days == 0
            || self.accountability_days < self.terminal_days
            || self.accountability_days > MAXIMUM_HOSTED_RETENTION_DAYS
        {
            return Err(HostedPolicyError::Retention);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedOutcomePolicy {
    pub id: String,
    pub label: String,
    pub reason_required: bool,
}

impl HostedOutcomePolicy {
    fn is_valid(&self) -> bool {
        valid_identifier(&self.id)
            && !self.label.trim().is_empty()
            && self.label.len() <= 120
            && self.label.chars().all(|character| !character.is_control())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedPolicyIdentity {
    pub kind_id: String,
    pub version: String,
    pub digest: HostedPolicyDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedKindPolicySnapshot {
    pub identity: HostedPolicyIdentity,
    pub queue: String,
    pub deciding_profiles: Vec<String>,
    pub retention: HostedRetentionPolicy,
    pub display_schema: Value,
    pub outcomes: Vec<HostedOutcomePolicy>,
}

impl HostedKindPolicySnapshot {
    pub fn verify(&self) -> Result<(), HostedPolicyError> {
        let policy = HostedKindPolicy {
            id: self.identity.kind_id.clone(),
            version: self.identity.version.clone(),
            queue: self.queue.clone(),
            deciding_profiles: self.deciding_profiles.clone(),
            retention: self.retention.clone(),
            display_schema: self.display_schema.clone(),
            outcomes: self.outcomes.clone(),
        };
        if policy.policy_digest()? != self.identity.digest {
            return Err(HostedPolicyError::DigestMismatch);
        }
        Ok(())
    }

    pub fn validate_display(&self, display: &Value) -> Result<(), HostedValidationError> {
        validate_display(&self.display_schema, display)
    }

    #[must_use]
    pub fn outcome(&self, id: &str) -> Option<&HostedOutcomePolicy> {
        self.outcomes.iter().find(|outcome| outcome.id == id)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HostedPolicyDigest(String);

impl HostedPolicyDigest {
    pub fn parse(value: &str) -> Result<Self, HostedPolicyError> {
        if value.len() == 71
            && value.starts_with("sha256:")
            && value[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value.to_owned()))
        } else {
            Err(HostedPolicyError::Digest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HostedPolicyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("HostedPolicyDigest")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for HostedPolicyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for HostedPolicyDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HostedPolicyDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpaqueActorRef(String);

impl OpaqueActorRef {
    pub fn parse(value: &str) -> Result<Self, InvalidActorRef> {
        let suffix = value.strip_prefix("actor_").ok_or(InvalidActorRef)?;
        if suffix.is_empty()
            || value.len() > 128
            || suffix
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'))
        {
            return Err(InvalidActorRef);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OpaqueActorRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OpaqueActorRef")
            .field(&self.0)
            .finish()
    }
}

impl Serialize for OpaqueActorRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for OpaqueActorRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidActorRef;

impl fmt::Display for InvalidActorRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("actor reference must be an opaque actor_ identifier")
    }
}

impl std::error::Error for InvalidActorRef {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedWorkItemContext {
    pub requester_reference: String,
    pub kind: String,
    pub version: String,
    pub display: Value,
    pub kind_policy_digest: HostedPolicyDigest,
    pub outcomes: Vec<HostedOutcomePolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedCreateRequest {
    pub kind: String,
    pub requester_reference: String,
    pub display: Value,
}

impl HostedCreateRequest {
    pub fn check(&self, policy: &HostedKindPolicy) -> Result<(), HostedValidationError> {
        if self.kind != policy.id {
            return Err(HostedValidationError::new(
                "$.kind",
                HostedValidationReason::KindNotAllowed,
            ));
        }
        if !bounded_text(&self.requester_reference, MAXIMUM_HOSTED_REFERENCE_BYTES) {
            return Err(HostedValidationError::new(
                "$.requesterReference",
                HostedValidationReason::ReferenceInvalid,
            ));
        }
        policy.validate_display(&self.display)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HostedRequestError> {
        let value = serde_json::to_value(self).map_err(|_| HostedRequestError::Canonical)?;
        registry_platform_canonical_json::canonicalize_json(&value)
            .map_err(|_| HostedRequestError::Canonical)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedNoteRequest {
    pub note: String,
}

impl HostedNoteRequest {
    pub fn check(&self) -> Result<(), HostedValidationError> {
        bounded_text(&self.note, MAXIMUM_HOSTED_NOTE_BYTES)
            .then_some(())
            .ok_or_else(|| {
                HostedValidationError::new("$.note", HostedValidationReason::TextInvalid)
            })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedCancelRequest {
    pub reason: String,
}

impl HostedCancelRequest {
    pub fn check(&self) -> Result<(), HostedValidationError> {
        bounded_text(&self.reason, MAXIMUM_HOSTED_REASON_BYTES)
            .then_some(())
            .ok_or_else(|| {
                HostedValidationError::new("$.reason", HostedValidationReason::TextInvalid)
            })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedDecisionRequest {
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl HostedDecisionRequest {
    pub fn check(&self, policy: &HostedKindPolicySnapshot) -> Result<(), HostedValidationError> {
        let outcome = policy.outcome(&self.outcome).ok_or_else(|| {
            HostedValidationError::new("$.outcome", HostedValidationReason::OutcomeNotDeclared)
        })?;
        if self
            .reason
            .as_deref()
            .is_some_and(|reason| !bounded_text(reason, MAXIMUM_HOSTED_REASON_BYTES))
        {
            return Err(HostedValidationError::new(
                "$.reason",
                HostedValidationReason::TextInvalid,
            ));
        }
        if outcome.reason_required
            && self
                .reason
                .as_deref()
                .is_none_or(|reason| reason.trim().is_empty())
        {
            return Err(HostedValidationError::new(
                "$.reason",
                HostedValidationReason::ReasonRequired,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequesterHostedItem {
    pub item_id: Uuid,
    pub requester_reference: String,
    pub kind: String,
    pub version: String,
    pub display: Value,
    pub state: OccurrenceState,
    pub revision: i64,
    pub kind_policy_digest: HostedPolicyDigest,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum HostedTerminalState {
    Completed {
        outcome: String,
        actor_ref: OpaqueActorRef,
    },
    Cancelled {
        cancellation_reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostedTerminalResult {
    pub item_id: Uuid,
    pub event_id: Uuid,
    pub requester_reference: String,
    #[serde(flatten)]
    pub terminal: HostedTerminalState,
    pub kind_policy_digest: HostedPolicyDigest,
    pub terminal_at: DateTime<Utc>,
}

impl<'de> Deserialize<'de> for HostedTerminalResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value.get("state").and_then(Value::as_str) {
            Some("completed") => {
                let wire: CompletedTerminalWire =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                Ok(Self {
                    item_id: wire.item_id,
                    event_id: wire.event_id,
                    requester_reference: wire.requester_reference,
                    terminal: HostedTerminalState::Completed {
                        outcome: wire.outcome,
                        actor_ref: wire.actor_ref,
                    },
                    kind_policy_digest: wire.kind_policy_digest,
                    terminal_at: wire.terminal_at,
                })
            }
            Some("cancelled") => {
                let wire: CancelledTerminalWire =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                Ok(Self {
                    item_id: wire.item_id,
                    event_id: wire.event_id,
                    requester_reference: wire.requester_reference,
                    terminal: HostedTerminalState::Cancelled {
                        cancellation_reason: wire.cancellation_reason,
                    },
                    kind_policy_digest: wire.kind_policy_digest,
                    terminal_at: wire.terminal_at,
                })
            }
            _ => Err(serde::de::Error::custom(
                "hosted terminal state must be completed or cancelled",
            )),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompletedTerminalWire {
    item_id: Uuid,
    event_id: Uuid,
    requester_reference: String,
    #[serde(rename = "state")]
    _state: CompletedTerminalTag,
    outcome: String,
    actor_ref: OpaqueActorRef,
    kind_policy_digest: HostedPolicyDigest,
    terminal_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CancelledTerminalWire {
    item_id: Uuid,
    event_id: Uuid,
    requester_reference: String,
    #[serde(rename = "state")]
    _state: CancelledTerminalTag,
    cancellation_reason: String,
    kind_policy_digest: HostedPolicyDigest,
    terminal_at: DateTime<Utc>,
}

#[derive(Deserialize)]
enum CompletedTerminalTag {
    #[serde(rename = "completed")]
    Completed,
}

#[derive(Deserialize)]
enum CancelledTerminalTag {
    #[serde(rename = "cancelled")]
    Cancelled,
}

pub type HostedTerminalPage = Page<HostedTerminalResult>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedNote {
    pub note_id: Uuid,
    pub item_id: Uuid,
    pub note: String,
    pub item_revision: i64,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedAccountabilityRecord {
    pub item_id: Uuid,
    pub event_id: Uuid,
    pub actor_ref: OpaqueActorRef,
    pub actor: IssuerPrincipal,
    pub profile_id: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub recorded_at: DateTime<Utc>,
    pub retained_until: DateTime<Utc>,
}

/// The explicit starter used by authoring tools. A runtime never installs it
/// when `hostedKinds` is absent.
#[must_use]
pub fn standalone_decision_starter_kind() -> HostedKindPolicy {
    HostedKindPolicy {
        id: "decision".to_owned(),
        version: "1".to_owned(),
        queue: "decisions".to_owned(),
        deciding_profiles: vec!["staff".to_owned()],
        retention: HostedRetentionPolicy {
            terminal_days: 90,
            accountability_days: 365,
        },
        display_schema: json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["summary", "reference"],
            "properties": {
                "summary": {"type": "string", "maxLength": 160},
                "reference": {"type": "string", "maxLength": 120}
            }
        }),
        outcomes: vec![
            HostedOutcomePolicy {
                id: "confirmed".to_owned(),
                label: "Confirm".to_owned(),
                reason_required: false,
            },
            HostedOutcomePolicy {
                id: "rejected".to_owned(),
                label: "Return for correction".to_owned(),
                reason_required: true,
            },
        ],
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum HostedPolicyError {
    #[error("the hosted kind identity or deciding profiles are invalid")]
    Identity,
    #[error("the hosted kind retention is invalid")]
    Retention,
    #[error("the hosted display schema is invalid or unbounded")]
    DisplaySchema,
    #[error("the hosted outcomes are invalid")]
    Outcomes,
    #[error("the hosted policy could not be canonicalized")]
    Canonical,
    #[error("the hosted policy digest is invalid")]
    Digest,
    #[error("the hosted policy snapshot digest does not match its contents")]
    DigestMismatch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostedValidationReason {
    KindNotAllowed,
    ReferenceInvalid,
    ObjectRequired,
    MaximumBytesExceeded,
    MaximumDepthExceeded,
    SchemaMismatch,
    OutcomeNotDeclared,
    ReasonRequired,
    TextInvalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostedValidationError {
    pub path: String,
    pub reason: HostedValidationReason,
}

impl HostedValidationError {
    pub fn new(path: impl Into<String>, reason: HostedValidationReason) -> Self {
        let path = path.into();
        Self {
            path: if path.len() <= 256 && path.bytes().all(valid_path_byte) {
                path
            } else {
                "$.display".to_owned()
            },
            reason,
        }
    }
}

impl fmt::Display for HostedValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "hosted request validation failed at {}",
            self.path
        )
    }
}

impl std::error::Error for HostedValidationError {}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HostedRequestError {
    #[error("the hosted request could not be canonicalized")]
    Canonical,
}

fn check_display_schema(schema: &Value) -> Result<(), HostedPolicyError> {
    let root = schema.as_object().ok_or(HostedPolicyError::DisplaySchema)?;
    if root.get("type") != Some(&Value::String("object".to_owned()))
        || root.get("additionalProperties") != Some(&Value::Bool(false))
        || !bounded_json(schema, MAXIMUM_HOSTED_DISPLAY_DEPTH)
        || !schema_refs_are_local(schema)
        || !object_schemas_are_closed(schema)
        || !registry_platform_canonical_json::canonicalize_json(schema)
            .is_ok_and(|bytes| bytes.len() <= MAXIMUM_HOSTED_SCHEMA_BYTES)
        || JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(schema)
            .is_err()
    {
        return Err(HostedPolicyError::DisplaySchema);
    }
    Ok(())
}

fn validate_display(schema: &Value, display: &Value) -> Result<(), HostedValidationError> {
    if !display.is_object() {
        return Err(HostedValidationError::new(
            "$.display",
            HostedValidationReason::ObjectRequired,
        ));
    }
    if !bounded_json(display, MAXIMUM_HOSTED_DISPLAY_DEPTH) {
        return Err(HostedValidationError::new(
            "$.display",
            HostedValidationReason::MaximumDepthExceeded,
        ));
    }
    if !registry_platform_canonical_json::canonicalize_json(display)
        .is_ok_and(|bytes| bytes.len() <= MAXIMUM_HOSTED_DISPLAY_BYTES)
    {
        return Err(HostedValidationError::new(
            "$.display",
            HostedValidationReason::MaximumBytesExceeded,
        ));
    }
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .map_err(|_| {
            HostedValidationError::new("$.display", HostedValidationReason::SchemaMismatch)
        })?;
    if let Err(errors) = compiled.validate(display) {
        let path = errors
            .into_iter()
            .next()
            .map(|error| {
                let path = error.instance_path.to_string();
                if path.is_empty() {
                    "$.display".to_owned()
                } else {
                    format!("$.display{path}")
                }
            })
            .unwrap_or_else(|| "$.display".to_owned());
        return Err(HostedValidationError::new(
            path,
            HostedValidationReason::SchemaMismatch,
        ));
    }
    Ok(())
}

fn digest_policy(policy: &HostedKindPolicy) -> Result<HostedPolicyDigest, HostedPolicyError> {
    let value = json!({
        "schema": "registry-casework-hosted-kind-policy/v1",
        "policy": policy,
    });
    let canonical = registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| HostedPolicyError::Canonical)?;
    let bytes = Sha256::digest(canonical);
    let mut digest = String::with_capacity(71);
    digest.push_str("sha256:");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut digest, "{byte:02x}").expect("writing to a String cannot fail");
    }
    HostedPolicyDigest::parse(&digest)
}

fn bounded_json(value: &Value, maximum_depth: usize) -> bool {
    let mut pending = vec![(value, 1_usize)];
    while let Some((value, depth)) = pending.pop() {
        if depth > maximum_depth {
            return false;
        }
        match value {
            Value::Array(values) => {
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                pending.extend(values.values().map(|value| (value, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    true
}

fn schema_refs_are_local(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().all(|(key, value)| {
            if key == "$ref" {
                value
                    .as_str()
                    .is_some_and(|reference| reference == "#" || reference.starts_with("#/"))
            } else {
                schema_refs_are_local(value)
            }
        }),
        Value::Array(values) => values.iter().all(schema_refs_are_local),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => true,
    }
}

fn object_schemas_are_closed(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            let declares_object = object.get("type").is_some_and(|value| match value {
                Value::String(value) => value == "object",
                Value::Array(values) => values.iter().any(|value| value == "object"),
                _ => false,
            });
            let uses_object_keywords = [
                "properties",
                "patternProperties",
                "required",
                "minProperties",
                "maxProperties",
                "dependentRequired",
                "dependentSchemas",
                "propertyNames",
            ]
            .iter()
            .any(|keyword| object.contains_key(*keyword));
            let closed = if declares_object || uses_object_keywords {
                object.get("additionalProperties") == Some(&Value::Bool(false))
            } else {
                true
            };
            closed
                && object
                    .iter()
                    .all(|(keyword, value)| match keyword.as_str() {
                        "properties" | "patternProperties" | "dependentSchemas" | "$defs"
                        | "definitions" => value
                            .as_object()
                            .is_none_or(|schemas| schemas.values().all(object_schemas_are_closed)),
                        "allOf" | "anyOf" | "oneOf" | "prefixItems" => value
                            .as_array()
                            .is_none_or(|schemas| schemas.iter().all(object_schemas_are_closed)),
                        "additionalProperties"
                        | "unevaluatedProperties"
                        | "propertyNames"
                        | "contains"
                        | "items"
                        | "additionalItems"
                        | "unevaluatedItems"
                        | "not"
                        | "if"
                        | "then"
                        | "else"
                        | "contentSchema" => object_schemas_are_closed(value),
                        _ => true,
                    })
        }
        Value::Array(values) => values.iter().all(object_schemas_are_closed),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => true,
    }
}

fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn bounded_text(value: &str, maximum_bytes: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= maximum_bytes
        && value.chars().all(|character| !character.is_control())
}

fn valid_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'$' | b'.' | b'/' | b'_' | b'-' | b'~')
}

fn all_unique<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut values: Vec<_> = values.collect();
    values.sort_unstable();
    values.windows(2).all(|pair| pair[0] != pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starter_kind_is_explicit_valid_and_bounded() {
        let policy = standalone_decision_starter_kind();
        assert_eq!(policy.check(), Ok(()));
        assert_eq!(policy.id, "decision");
        assert_eq!(policy.outcomes.len(), 2);
        assert_eq!(
            policy.validate_display(&json!({
                "summary": "Review the prepared batch",
                "reference": "batch-0042"
            })),
            Ok(())
        );
    }

    #[test]
    fn display_validation_reports_only_a_bounded_path_and_reason() {
        let policy = standalone_decision_starter_kind();
        let error = policy
            .validate_display(&json!({
                "summary": "x".repeat(161),
                "reference": "batch-0042"
            }))
            .expect_err("oversized summary");
        assert_eq!(error.path, "$.display/summary");
        assert_eq!(error.reason, HostedValidationReason::SchemaMismatch);
        assert!(!error.to_string().contains(&"x".repeat(16)));

        let error = policy
            .validate_display(&Value::String("secret".to_owned()))
            .expect_err("object required");
        assert_eq!(error.path, "$.display");
        assert_eq!(error.reason, HostedValidationReason::ObjectRequired);

        let mut policy = standalone_decision_starter_kind();
        policy.display_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["résumé"],
            "properties": {"résumé": {"type": "string", "minLength": 1}}
        });
        let error = policy
            .validate_display(&json!({"résumé": ""}))
            .expect_err("non-ASCII field path is not copied into a response header");
        assert_eq!(error.path, "$.display");
    }

    #[test]
    fn display_policy_refuses_remote_refs_and_open_nested_objects() {
        let mut policy = standalone_decision_starter_kind();
        policy.display_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"value": {"$ref": "https://example.test/value.json"}}
        });
        assert_eq!(policy.check(), Err(HostedPolicyError::DisplaySchema));

        policy.display_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "details": {
                    "properties": {"allowed": {"type": "string"}}
                }
            }
        });
        assert_eq!(policy.check(), Err(HostedPolicyError::DisplaySchema));

        policy.display_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"value": {"type": "object"}}
        });
        assert_eq!(policy.check(), Err(HostedPolicyError::DisplaySchema));
    }

    #[test]
    fn display_policy_allows_schema_keyword_names_as_display_fields() {
        let mut policy = standalone_decision_starter_kind();
        policy.display_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "required": {"type": "boolean"},
                "properties": {"type": "string", "maxLength": 20}
            }
        });
        assert_eq!(policy.check(), Ok(()));
        assert_eq!(
            policy.validate_display(&json!({"required": true, "properties": "ordinary field"})),
            Ok(())
        );
    }

    #[test]
    fn display_payload_has_aggregate_byte_and_depth_bounds() {
        let mut policy = standalone_decision_starter_kind();
        policy.display_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"value": {"type": "string"}},
            "required": ["value"]
        });
        let error = policy
            .validate_display(&json!({"value": "x".repeat(MAXIMUM_HOSTED_DISPLAY_BYTES)}))
            .expect_err("aggregate bytes bounded");
        assert_eq!(error.reason, HostedValidationReason::MaximumBytesExceeded);

        let mut nested = Value::Null;
        for _ in 0..MAXIMUM_HOSTED_DISPLAY_DEPTH {
            nested = json!({"value": nested});
        }
        let error = policy
            .validate_display(&nested)
            .expect_err("aggregate depth bounded");
        assert_eq!(error.reason, HostedValidationReason::MaximumDepthExceeded);
    }

    #[test]
    fn outcome_and_retention_policy_are_bounded() {
        let mut policy = standalone_decision_starter_kind();
        policy.outcomes.push(policy.outcomes[0].clone());
        assert_eq!(policy.check(), Err(HostedPolicyError::Outcomes));

        let mut policy = standalone_decision_starter_kind();
        policy.retention.accountability_days = policy.retention.terminal_days - 1;
        assert_eq!(policy.check(), Err(HostedPolicyError::Retention));
    }

    #[test]
    fn decisions_use_the_pinned_outcome_vocabulary_and_reason_rule() {
        let snapshot = standalone_decision_starter_kind().snapshot().unwrap();
        let missing_reason = HostedDecisionRequest {
            outcome: "rejected".to_owned(),
            reason: None,
        }
        .check(&snapshot)
        .expect_err("rejection requires a reason");
        assert_eq!(missing_reason.path, "$.reason");
        assert_eq!(
            missing_reason.reason,
            HostedValidationReason::ReasonRequired
        );

        let unknown = HostedDecisionRequest {
            outcome: "later-policy-outcome".to_owned(),
            reason: None,
        }
        .check(&snapshot)
        .expect_err("outcome is pinned");
        assert_eq!(unknown.path, "$.outcome");
        assert_eq!(unknown.reason, HostedValidationReason::OutcomeNotDeclared);
    }

    #[test]
    fn snapshot_identity_detects_policy_mutation() {
        let policy = standalone_decision_starter_kind();
        let snapshot = policy.snapshot().unwrap();
        assert_eq!(snapshot.verify(), Ok(()));

        let mut changed_policy = policy;
        changed_policy.outcomes[0].label = "Confirm batch".to_owned();
        assert_ne!(
            snapshot.identity.digest,
            changed_policy.policy_digest().unwrap()
        );

        let mut tampered_snapshot = snapshot;
        tampered_snapshot.outcomes[0].label = "Changed after creation".to_owned();
        assert_eq!(
            tampered_snapshot.verify(),
            Err(HostedPolicyError::DigestMismatch)
        );
    }

    #[test]
    fn terminal_wire_state_cannot_mix_completion_and_cancellation() {
        let digest = standalone_decision_starter_kind().policy_digest().unwrap();
        let terminal = HostedTerminalResult {
            item_id: Uuid::nil(),
            event_id: Uuid::from_u128(1),
            requester_reference: "batch-0042".to_owned(),
            terminal: HostedTerminalState::Completed {
                outcome: "confirmed".to_owned(),
                actor_ref: OpaqueActorRef::parse("actor_01K4W92K7C8V6M2A").unwrap(),
            },
            kind_policy_digest: digest,
            terminal_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        };
        let value = serde_json::to_value(&terminal).unwrap();
        assert_eq!(value["state"], "completed");
        assert_eq!(value["outcome"], "confirmed");
        assert!(value.get("cancellationReason").is_none());
        assert_eq!(
            serde_json::from_value::<HostedTerminalResult>(value.clone()).unwrap(),
            terminal
        );

        let mut invalid = value;
        invalid["cancellationReason"] = json!("mixed terminal result");
        assert!(serde_json::from_value::<HostedTerminalResult>(invalid).is_err());

        let cancelled = HostedTerminalResult {
            item_id: Uuid::nil(),
            event_id: Uuid::from_u128(2),
            requester_reference: "batch-0043".to_owned(),
            terminal: HostedTerminalState::Cancelled {
                cancellation_reason: "superseded batch".to_owned(),
            },
            kind_policy_digest: standalone_decision_starter_kind().policy_digest().unwrap(),
            terminal_at: DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
        };
        assert_eq!(
            serde_json::from_value::<HostedTerminalResult>(
                serde_json::to_value(&cancelled).unwrap()
            )
            .unwrap(),
            cancelled
        );
    }
}

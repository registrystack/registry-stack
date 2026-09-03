// SPDX-License-Identifier: Apache-2.0

//! Bounded correction/change context stored with one committed change.

use std::fmt;

use registry_platform_canonical_json::canonicalize_json;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const MAX_REASON_CODE_BYTES: usize = 64;
const MAX_REASON_TEXT_BYTES: usize = 4 * 1024;
const MAX_SOURCE_REFERENCE_BYTES: usize = 256;
const MAX_SOURCE_REFERENCES: usize = 16;
const MAX_CANONICAL_CONTEXT_BYTES: usize = 16 * 1024;
const MAX_TRUSTED_REFERENCE_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeIntent {
    Unspecified,
    Change,
    Correction,
}

impl ChangeIntent {
    fn from_json(value: Option<&Value>) -> Result<Self, ChangeContextError> {
        match value {
            None => Ok(Self::Unspecified),
            Some(Value::String(kind)) if kind == "change" => Ok(Self::Change),
            Some(Value::String(kind)) if kind == "correction" => Ok(Self::Correction),
            Some(_) => Err(ChangeContextError::Invalid),
        }
    }

    fn as_str(self) -> Option<&'static str> {
        match self {
            Self::Unspecified => None,
            Self::Change => Some("change"),
            Self::Correction => Some("correction"),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ChangeContext {
    intent: ChangeIntent,
    reason_code: Option<String>,
    reason_text: Option<String>,
    source_references: Vec<String>,
    canonical: Vec<u8>,
    digest: [u8; 32],
}

impl ChangeContext {
    pub fn parse_json(value: &Value) -> Result<Self, ChangeContextError> {
        let object = value.as_object().ok_or(ChangeContextError::Invalid)?;
        for key in object.keys() {
            if !matches!(
                key.as_str(),
                "kind" | "reasonCode" | "reasonText" | "sourceReferences"
            ) {
                return Err(ChangeContextError::Invalid);
            }
        }

        let intent = ChangeIntent::from_json(object.get("kind"))?;
        let reason_code = optional_bounded_string(
            object.get("reasonCode"),
            MAX_REASON_CODE_BYTES,
            FieldRequirement::NonEmptyWhenPresent,
        )?;
        if intent == ChangeIntent::Correction && reason_code.is_none() {
            return Err(ChangeContextError::Invalid);
        }
        let reason_text = optional_bounded_string(
            object.get("reasonText"),
            MAX_REASON_TEXT_BYTES,
            FieldRequirement::NonEmptyWhenPresent,
        )?;
        let source_references = parse_source_references(object.get("sourceReferences"))?;

        let canonical_value = canonical_context_value(
            intent,
            reason_code.as_deref(),
            reason_text.as_deref(),
            &source_references,
        );
        let canonical =
            canonicalize_json(&canonical_value).map_err(|_| ChangeContextError::Invalid)?;
        if canonical.is_empty() || canonical.len() > MAX_CANONICAL_CONTEXT_BYTES {
            return Err(ChangeContextError::Invalid);
        }
        let digest = Sha256::digest(&canonical).into();
        Ok(Self {
            intent,
            reason_code,
            reason_text,
            source_references,
            canonical,
            digest,
        })
    }

    #[must_use]
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    #[must_use]
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

impl fmt::Debug for ChangeContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChangeContext")
            .field("intent", &self.intent)
            .field("has_reason_code", &self.reason_code.is_some())
            .field("has_reason_text", &self.reason_text.is_some())
            .field("source_reference_count", &self.source_references.len())
            .field("canonical_bytes", &"<redacted>")
            .field("digest", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum CommitOrigin<'a> {
    Mutation {
        actor_reference: &'a str,
        request_reference: &'a str,
    },
    Migration {
        system_origin: &'a str,
        migration_reference: Option<&'a str>,
    },
    Baseline {
        system_origin: &'a str,
        baseline_reference: Option<&'a str>,
    },
}

impl fmt::Debug for CommitOrigin<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mutation { .. } => formatter
                .debug_struct("CommitOrigin::Mutation")
                .field("actor_reference", &"<redacted>")
                .field("request_reference", &"<redacted>")
                .finish(),
            Self::Migration {
                migration_reference,
                ..
            } => formatter
                .debug_struct("CommitOrigin::Migration")
                .field("system_origin", &"<redacted>")
                .field("has_migration_reference", &migration_reference.is_some())
                .finish(),
            Self::Baseline {
                baseline_reference, ..
            } => formatter
                .debug_struct("CommitOrigin::Baseline")
                .field("system_origin", &"<redacted>")
                .field("has_baseline_reference", &baseline_reference.is_some())
                .finish(),
        }
    }
}

impl<'a> CommitOrigin<'a> {
    pub(crate) fn validate(self) -> Result<ValidatedCommitOrigin<'a>, ChangeContextError> {
        match self {
            Self::Mutation {
                actor_reference,
                request_reference,
            } => {
                validate_reference(actor_reference)?;
                validate_reference(request_reference)?;
                Ok(ValidatedCommitOrigin {
                    kind: "mutation",
                    actor_reference: Some(actor_reference),
                    request_reference: Some(request_reference),
                    system_origin: None,
                    migration_reference: None,
                    baseline_reference: None,
                    establishes_baseline: false,
                })
            }
            Self::Migration {
                system_origin,
                migration_reference,
            } => {
                validate_reference(system_origin)?;
                if let Some(reference) = migration_reference {
                    validate_reference(reference)?;
                }
                Ok(ValidatedCommitOrigin {
                    kind: "migration",
                    actor_reference: None,
                    request_reference: None,
                    system_origin: Some(system_origin),
                    migration_reference,
                    baseline_reference: None,
                    establishes_baseline: false,
                })
            }
            Self::Baseline {
                system_origin,
                baseline_reference,
            } => {
                validate_reference(system_origin)?;
                if let Some(reference) = baseline_reference {
                    validate_reference(reference)?;
                }
                Ok(ValidatedCommitOrigin {
                    kind: "baseline",
                    actor_reference: None,
                    request_reference: None,
                    system_origin: Some(system_origin),
                    migration_reference: None,
                    baseline_reference,
                    establishes_baseline: true,
                })
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ValidatedCommitOrigin<'a> {
    pub(crate) kind: &'static str,
    pub(crate) actor_reference: Option<&'a str>,
    pub(crate) request_reference: Option<&'a str>,
    pub(crate) system_origin: Option<&'a str>,
    pub(crate) migration_reference: Option<&'a str>,
    pub(crate) baseline_reference: Option<&'a str>,
    pub(crate) establishes_baseline: bool,
}

impl fmt::Debug for ValidatedCommitOrigin<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedCommitOrigin")
            .field("kind", &self.kind)
            .field("has_actor_reference", &self.actor_reference.is_some())
            .field("has_request_reference", &self.request_reference.is_some())
            .field("has_system_origin", &self.system_origin.is_some())
            .field(
                "has_migration_reference",
                &self.migration_reference.is_some(),
            )
            .field("has_baseline_reference", &self.baseline_reference.is_some())
            .field("establishes_baseline", &self.establishes_baseline)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ChangeContextError {
    #[error("change context is invalid")]
    Invalid,
}

#[derive(Clone, Copy)]
enum FieldRequirement {
    NonEmptyWhenPresent,
}

fn optional_bounded_string(
    value: Option<&Value>,
    max_bytes: usize,
    requirement: FieldRequirement,
) -> Result<Option<String>, ChangeContextError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Value::String(value) = value else {
        return Err(ChangeContextError::Invalid);
    };
    if matches!(requirement, FieldRequirement::NonEmptyWhenPresent) && value.is_empty() {
        return Err(ChangeContextError::Invalid);
    }
    if value.len() > max_bytes {
        return Err(ChangeContextError::Invalid);
    }
    Ok(Some(value.clone()))
}

fn parse_source_references(value: Option<&Value>) -> Result<Vec<String>, ChangeContextError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Value::Array(values) = value else {
        return Err(ChangeContextError::Invalid);
    };
    if values.len() > MAX_SOURCE_REFERENCES {
        return Err(ChangeContextError::Invalid);
    }
    values
        .iter()
        .map(|value| {
            let Value::String(reference) = value else {
                return Err(ChangeContextError::Invalid);
            };
            if reference.is_empty() || reference.len() > MAX_SOURCE_REFERENCE_BYTES {
                return Err(ChangeContextError::Invalid);
            }
            Ok(reference.clone())
        })
        .collect()
}

fn canonical_context_value(
    intent: ChangeIntent,
    reason_code: Option<&str>,
    reason_text: Option<&str>,
    source_references: &[String],
) -> Value {
    let mut object = Map::new();
    if let Some(kind) = intent.as_str() {
        object.insert("kind".to_owned(), Value::String(kind.to_owned()));
    }
    if let Some(reason_code) = reason_code {
        object.insert(
            "reasonCode".to_owned(),
            Value::String(reason_code.to_owned()),
        );
    }
    if let Some(reason_text) = reason_text {
        object.insert(
            "reasonText".to_owned(),
            Value::String(reason_text.to_owned()),
        );
    }
    if !source_references.is_empty() {
        object.insert(
            "sourceReferences".to_owned(),
            Value::Array(
                source_references
                    .iter()
                    .map(|reference| Value::String(reference.clone()))
                    .collect(),
            ),
        );
    }
    Value::Object(object)
}

fn validate_reference(reference: &str) -> Result<(), ChangeContextError> {
    if reference.is_empty() || reference.len() > MAX_TRUSTED_REFERENCE_BYTES {
        return Err(ChangeContextError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn correction_requires_bounded_reason_and_rejects_unknown_members() {
        assert!(ChangeContext::parse_json(&json!({
            "kind": "correction",
            "reasonCode": "effective_date_corrected"
        }))
        .is_ok());
        assert!(ChangeContext::parse_json(&json!({ "kind": "correction" })).is_err());
        assert!(ChangeContext::parse_json(&json!({
            "kind": "change",
            "reasonCode": "x".repeat(MAX_REASON_CODE_BYTES + 1)
        }))
        .is_err());
        assert!(ChangeContext::parse_json(&json!({
            "kind": "change",
            "extra": true
        }))
        .is_err());
    }

    #[test]
    fn context_canonicalization_is_stable_and_digest_bound() {
        let first = ChangeContext::parse_json(&json!({
            "sourceReferences": ["case-document:review-204"],
            "reasonText": "Reviewed source gives June 15 as the move date.",
            "reasonCode": "effective_date_corrected",
            "kind": "correction"
        }))
        .unwrap();
        let second = ChangeContext::parse_json(&json!({
            "kind": "correction",
            "reasonCode": "effective_date_corrected",
            "reasonText": "Reviewed source gives June 15 as the move date.",
            "sourceReferences": ["case-document:review-204"]
        }))
        .unwrap();

        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.intent, ChangeIntent::Correction);
        assert_eq!(
            first.reason_code.as_deref(),
            Some("effective_date_corrected")
        );
        assert_eq!(
            first.source_references,
            &["case-document:review-204".to_owned()]
        );
    }

    #[test]
    fn system_origins_do_not_require_fabricated_user_identity() {
        let migration = CommitOrigin::Migration {
            system_origin: "breg-migration",
            migration_reference: Some("plan:step-1"),
        }
        .validate()
        .unwrap();
        assert_eq!(migration.kind, "migration");
        assert_eq!(migration.actor_reference, None);
        assert_eq!(migration.request_reference, None);

        let baseline = CommitOrigin::Baseline {
            system_origin: "breg-empty-baseline",
            baseline_reference: None,
        }
        .validate()
        .unwrap();
        assert!(baseline.establishes_baseline);
        assert_eq!(baseline.kind, "baseline");
    }

    #[test]
    fn debug_output_redacts_raw_context_and_trusted_references() {
        let context = ChangeContext::parse_json(&json!({
            "kind": "correction",
            "reasonCode": "reason-code-canary",
            "reasonText": "reason-text-canary",
            "sourceReferences": ["source-reference-canary"]
        }))
        .unwrap();
        let rendered = format!("{context:?}");
        for forbidden in [
            "reason-code-canary",
            "reason-text-canary",
            "source-reference-canary",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "debug output exposed raw context value {forbidden}: {rendered}"
            );
        }

        let origin = CommitOrigin::Mutation {
            actor_reference: "actor-reference-canary",
            request_reference: "request-reference-canary",
        };
        let rendered = format!("{origin:?}");
        assert!(!rendered.contains("actor-reference-canary"));
        assert!(!rendered.contains("request-reference-canary"));

        let validated = origin.validate().unwrap();
        let rendered = format!("{validated:?}");
        assert!(!rendered.contains("actor-reference-canary"));
        assert!(!rendered.contains("request-reference-canary"));
    }
}

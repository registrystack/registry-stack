//! Public operations contract assets shared by Registry runtimes.
//!
//! Relay and Notary own route wiring, authorization, and local posture
//! collection. This crate owns the shared public contract and the emit-only
//! sensitivity-tier filter used before posture leaves a runtime.

use std::sync::OnceLock;

use serde_json::Value;

pub const POSTURE_SCHEMA_V1: &str = include_str!("../schemas/registry.ops.posture.v1.schema.json");

pub const RELAY_POSTURE_EXAMPLE_V1: &str =
    include_str!("../examples/registry-relay.posture.valid.json");

pub const NOTARY_POSTURE_EXAMPLE_V1: &str =
    include_str!("../examples/registry-notary.posture.valid.json");

pub const DEFAULT_POSTURE_ALLOWLIST_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/default-allowlist.json");

pub const REDACTION_INPUT_SENSITIVE_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/redaction-input-sensitive.json");

pub const DEFAULT_REDACTED_POSTURE_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/default-redacted.posture.valid.json");

pub const RESTRICTED_POSTURE_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/restricted-posture.valid.json");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostureTier {
    Default,
    Restricted,
}

impl PostureTier {
    fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Restricted => "restricted",
        }
    }
}

#[derive(Clone, Debug)]
pub enum PostureFilterError {
    InvalidAllowlist,
    MissingAllowedPointers,
    InvalidAllowedPointer,
    FilteredToEmptyDocument,
}

impl std::fmt::Display for PostureFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAllowlist => write!(f, "invalid posture allowlist"),
            Self::MissingAllowedPointers => write!(f, "posture allowlist is missing pointers"),
            Self::InvalidAllowedPointer => {
                write!(f, "posture allowlist contains a non-string pointer")
            }
            Self::FilteredToEmptyDocument => {
                write!(f, "posture filter removed the entire document")
            }
        }
    }
}

impl std::error::Error for PostureFilterError {}

pub fn filter_posture_for_tier(
    mut posture: Value,
    tier: PostureTier,
) -> Result<Value, PostureFilterError> {
    posture["tier"] = Value::String(tier.as_str().to_string());
    match tier {
        PostureTier::Default => filter_default_posture(posture),
        PostureTier::Restricted => Ok(posture),
    }
}

fn filter_default_posture(posture: Value) -> Result<Value, PostureFilterError> {
    let allowed = default_allowed_patterns()?;
    let mut path = Vec::new();
    filter_value(&posture, &mut path, allowed).ok_or(PostureFilterError::FilteredToEmptyDocument)
}

static DEFAULT_ALLOWED_PATTERNS: OnceLock<Result<Vec<PointerPattern>, PostureFilterError>> =
    OnceLock::new();

fn default_allowed_patterns() -> Result<&'static [PointerPattern], PostureFilterError> {
    DEFAULT_ALLOWED_PATTERNS
        .get_or_init(load_default_allowed_patterns)
        .as_deref()
        .map_err(Clone::clone)
}

fn load_default_allowed_patterns() -> Result<Vec<PointerPattern>, PostureFilterError> {
    let allowlist: Value = serde_json::from_str(DEFAULT_POSTURE_ALLOWLIST_FIXTURE_V1)
        .map_err(|_| PostureFilterError::InvalidAllowlist)?;
    allowlist["allowed_json_pointers"]
        .as_array()
        .ok_or(PostureFilterError::MissingAllowedPointers)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(PointerPattern::parse)
                .ok_or(PostureFilterError::InvalidAllowedPointer)
        })
        .collect::<Result<Vec<_>, _>>()
}

fn filter_value<'a>(
    value: &'a Value,
    path: &mut Vec<&'a str>,
    allowed: &[PointerPattern],
) -> Option<Value> {
    if allowed.iter().any(|pattern| pattern.matches(path)) {
        return Some(value.clone());
    }

    match value {
        Value::Object(map) => {
            let filtered = map
                .iter()
                .filter_map(|(key, child)| {
                    path.push(key.as_str());
                    let filtered = filter_value(child, path, allowed);
                    path.pop();
                    filtered.map(|child| (key.clone(), child))
                })
                .collect::<serde_json::Map<_, _>>();
            (!filtered.is_empty()
                || allowed
                    .iter()
                    .any(|pattern| pattern.has_descendant_of(path)))
            .then_some(Value::Object(filtered))
        }
        Value::Array(items) => {
            let filtered = items
                .iter()
                .filter_map(|child| {
                    path.push("*");
                    let filtered = filter_value(child, path, allowed);
                    path.pop();
                    filtered
                })
                .collect::<Vec<_>>();
            (!filtered.is_empty()
                || allowed
                    .iter()
                    .any(|pattern| pattern.has_descendant_of(path)))
            .then_some(Value::Array(filtered))
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => None,
    }
}

#[derive(Clone, Debug)]
struct PointerPattern {
    segments: Vec<String>,
}

impl PointerPattern {
    fn parse(pointer: &str) -> Self {
        Self {
            segments: pointer_segments(pointer),
        }
    }

    fn matches(&self, path: &[&str]) -> bool {
        self.segments.len() == path.len()
            && self
                .segments
                .iter()
                .zip(path)
                .all(|(pattern, segment)| pattern == "*" || pattern == segment)
    }

    fn has_descendant_of(&self, path: &[&str]) -> bool {
        self.segments.len() > path.len()
            && self
                .segments
                .iter()
                .zip(path)
                .all(|(pattern, segment)| pattern == "*" || pattern == segment)
    }
}

fn pointer_segments(pointer: &str) -> Vec<String> {
    pointer
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(unescape_pointer_segment)
        .collect()
}

fn unescape_pointer_segment(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

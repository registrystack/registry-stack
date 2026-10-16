//! The checks authored Evidence documents must pass.
//!
//! Each check reports through [`Finding`] rather than an error type, and the
//! sentences it produces are the ones adopters have been reading: the
//! extraction of these rules into a library changed where they live, not what
//! they say. `tests/finding_messages.rs` holds every sentence to its exact
//! text.
//!
//! The checks stop at the first departure they find, so a returned vector
//! holds at most one finding today. The vector is the shape of the answer, not
//! a promise that it is short: a caller that renders findings next to fields
//! should already be written to show all of them.

use crate::finding::{FieldPath, Finding};
use serde_json::Value;

fn one(field: FieldPath, code: &'static str, message: impl Into<String>) -> Vec<Finding> {
    vec![Finding::new(field, code, message)]
}

/// Check that one authored Output schema closes its object form.
///
/// The declared Output schema is the contract the output gate holds a
/// derivation's structured value to, and the compiler closes the fact schema it
/// builds the same way. An object Output schema that permits properties it
/// never declared would let a derivation return keys no reviewer saw, so an
/// object schema must name the properties it permits and refuse the rest
/// outright. A schema that does not declare an object type permits no object
/// property set and is not checked here.
///
/// Findings apply to the schema document itself, so the caller renders them
/// beside `schemas/<name>.yaml` rather than beside the definition that named it.
#[must_use]
pub fn validate_output_schema_document(document: &Value) -> Vec<Finding> {
    let declares_object = match document.get("type") {
        Some(Value::String(value)) => value == "object",
        Some(Value::Array(values)) => values.iter().any(|value| value == "object"),
        _ => false,
    };
    if !declares_object {
        return Vec::new();
    }
    if document.get("additionalProperties") != Some(&Value::Bool(false)) {
        return one(
            FieldPath::root().key("additionalProperties"),
            "evidence.output-schema.open-object",
            "an object Output schema must set additionalProperties: false",
        );
    }
    if document
        .get("properties")
        .and_then(Value::as_object)
        .is_none()
    {
        return one(
            FieldPath::root().key("properties"),
            "evidence.output-schema.declared-properties",
            "an object Output schema must declare the properties it permits",
        );
    }
    Vec::new()
}

/// Check that a projected claim name is usable and does not take a name the
/// response format has already given a meaning.
#[must_use]
pub fn validate_sd_jwt_claim_name(value: &str) -> Vec<Finding> {
    const RESERVED: [&str; 24] = [
        "iss",
        "sub",
        "aud",
        "iat",
        "nbf",
        "exp",
        "vct",
        "id",
        "jti",
        "_sd",
        "_sd_alg",
        "cnf",
        "status",
        "issuedBy",
        "providedBy",
        "supportsRequirement",
        "purpose",
        "audience",
        "assuranceProfile",
        "observedAt",
        "configurationRevision",
        "requestNonce",
        "subjects",
        "structuredValues",
    ];
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !matches!(bytes.first(), Some(b'A'..=b'Z' | b'a'..=b'z'))
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        || RESERVED.contains(&value)
    {
        return one(
            FieldPath::root().key("sdJwtVc").key("claim"),
            "sd-jwt-vc-claim-name",
            "sdJwtVc.claim must be a bounded JSON claim name",
        );
    }
    Vec::new()
}

/// Whether a value is a lowercase local identifier: the one spelling the
/// authoring form accepts wherever an author names something.
#[must_use]
pub fn valid_local_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= 64
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// Whether a value may name a projected fact.
#[must_use]
pub fn valid_field_name(value: &str) -> bool {
    valid_local_identifier(value)
}

/// The collections one fact path visits, as the pointers that name them.
///
/// A fact path walks into arrays by writing `*` for the element, so
/// `/records/*/date_of_birth` visits the collection at `/records`, and each `*`
/// contributes the pointer that stands before it: a path with two of them names
/// the outer collection and the inner one, in that order. Those pointers are
/// what an author bounds under `source.collectionBounds`, and reading a path for
/// them is a rule of the authoring form rather than a step of any one caller's
/// algorithm, which is why it is written here once. A path visiting no
/// collection names none.
#[must_use]
pub fn collection_pointers(path: &str) -> Vec<String> {
    let mut walked = Vec::new();
    let mut collections = Vec::new();
    for segment in path.split('/').skip(1) {
        if segment == "*" {
            collections.push(format!("/{}", walked.join("/")));
        }
        walked.push(segment);
    }
    collections
}

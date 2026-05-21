// SPDX-License-Identifier: Apache-2.0
//! `VerifyResult` v1 credentialSubject builder.
//!
//! Legacy predicate-only attestation without exposing the underlying row.
//! The public `/verify` route has been removed; the schema remains published
//! for old verifier fixtures and compatibility tests.

use serde_json::{json, Value};

/// Inputs gathered by legacy verify-result issuance paths.
#[derive(Debug, Clone)]
pub struct VerifyResultInput {
    pub subject_uri: String,
    pub dataset: String,
    pub entity: String,
    pub subject_id: String,
    pub predicate: String,
    pub value: Value,
    pub as_of_rfc3339: String,
}

/// Build the `credentialSubject` JSON for a `VerifyResult` VC.
///
/// The `id` is the canonical entity URL; the JWT `sub` claim carries
/// the same value, so consumers that look only at JWT claims still see
/// the subject.
#[must_use]
pub fn verify_result_subject(input: &VerifyResultInput) -> Value {
    json!({
        "id": &input.subject_uri,
        "dataset": &input.dataset,
        "entity": &input.entity,
        "subjectId": &input.subject_id,
        "predicate": &input.predicate,
        "value": &input.value,
        "asOf": &input.as_of_rfc3339,
    })
}

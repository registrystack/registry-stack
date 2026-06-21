// SPDX-License-Identifier: Apache-2.0
//! Shared authorization_details enforcement for Notary transaction scopes.

use registry_notary_core::{
    AccessMode, ClaimRef, EvidenceAuthorizationDetails, EvidenceAuthorizationSubject, EvidenceError,
};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopedAuthorizationError {
    DetailType,
    Action,
    Location,
    Claim,
    Disclosure,
    Format,
    Purpose,
    AccessMode,
    Subject,
}

pub(crate) struct ScopedAuthorizationSubject {
    pub(crate) binding_claim: String,
    pub(crate) id_type: String,
}

pub(crate) struct ScopedAuthorizationRequest<'a> {
    pub(crate) service_id: &'a str,
    pub(crate) action: &'a str,
    pub(crate) claims: &'a [ClaimRef],
    pub(crate) disclosure: &'a str,
    pub(crate) format: &'a str,
    pub(crate) purpose: &'a str,
    pub(crate) access_mode: AccessMode,
    pub(crate) subject: Option<ScopedAuthorizationSubject>,
}

pub(crate) fn extract_notary_transaction_authorization_details(
    raw: &Value,
) -> Result<Option<EvidenceAuthorizationDetails>, EvidenceError> {
    let details = raw.as_array().ok_or(EvidenceError::MissingCredential)?;
    let mut matched = None;
    for detail in details {
        let Some(object) = detail.as_object() else {
            continue;
        };
        let type_matches = object.get("type").and_then(Value::as_str)
            == Some(registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE);
        let schema_matches = object.get("schema_version").and_then(Value::as_str)
            == Some(registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION);
        if !type_matches && !schema_matches {
            continue;
        }
        if !type_matches || !schema_matches || matched.is_some() {
            return Err(EvidenceError::MissingCredential);
        }
        matched = Some(
            serde_json::from_value::<EvidenceAuthorizationDetails>(detail.clone())
                .map_err(|_| EvidenceError::MissingCredential)?,
        );
    }
    Ok(matched)
}

pub(crate) fn validate_scoped_authorization_details(
    details: &EvidenceAuthorizationDetails,
    expected: &ScopedAuthorizationRequest<'_>,
) -> Result<(), ScopedAuthorizationError> {
    if details.detail_type != registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE
        || details.schema_version
            != registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
    {
        return Err(ScopedAuthorizationError::DetailType);
    }
    if !exact_single(&details.actions, expected.action) {
        return Err(ScopedAuthorizationError::Action);
    }
    if !exact_single(&details.locations, expected.service_id) {
        return Err(ScopedAuthorizationError::Location);
    }
    if details.claims != expected.claims {
        return Err(ScopedAuthorizationError::Claim);
    }
    if details.disclosure.as_deref() != Some(expected.disclosure) {
        return Err(ScopedAuthorizationError::Disclosure);
    }
    if details.format.as_deref() != Some(expected.format) {
        return Err(ScopedAuthorizationError::Format);
    }
    if details.purpose.as_deref() != Some(expected.purpose) {
        return Err(ScopedAuthorizationError::Purpose);
    }
    if details.access_mode != Some(expected.access_mode) {
        return Err(ScopedAuthorizationError::AccessMode);
    }
    if !subject_matches(details.subject.as_ref(), expected.subject.as_ref()) {
        return Err(ScopedAuthorizationError::Subject);
    }
    Ok(())
}

fn exact_single(values: &[String], expected: &str) -> bool {
    values.len() == 1 && values[0] == expected
}

fn subject_matches(
    actual: Option<&EvidenceAuthorizationSubject>,
    expected: Option<&ScopedAuthorizationSubject>,
) -> bool {
    match (actual, expected) {
        (Some(actual), Some(expected)) => {
            actual.binding_claim == expected.binding_claim && actual.id_type == expected.id_type
        }
        (None, None) => true,
        _ => false,
    }
}

// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) fn supports_object_field_redaction(
    claim_value_type: &str,
    redaction_fields: &BTreeSet<String>,
) -> bool {
    claim_value_type == "object"
        && !redaction_fields.is_empty()
        && redaction_fields
            .iter()
            .all(|field| is_top_level_redaction_field(field))
}

pub(super) fn is_top_level_redaction_field(field: &str) -> bool {
    !field.is_empty()
        && field != "value"
        && !field.contains('.')
        && !field.contains('[')
        && !field.contains(']')
}

pub(super) fn redact_object_fields(
    value: &Value,
    redaction_fields: &BTreeSet<String>,
) -> Result<Option<Value>, EvidenceError> {
    let Some(mut object) = value.as_object().cloned() else {
        return Ok(None);
    };
    for field in redaction_fields {
        if object.remove(field).is_none() {
            return Err(EvidenceError::DisclosureNotAllowed);
        }
    }
    Ok(Some(Value::Object(object)))
}

pub(super) fn view_claim(
    self_attestation_rate_keys: &SelfAttestationRateLimitKeys,
    result: &ClaimResultInternal,
    claim: &ClaimDefinition,
    disclosure: DisclosureProfile,
    format: &str,
) -> Result<ClaimResultView, EvidenceError> {
    let mut effective_disclosure = disclosure;
    let field_redaction =
        supports_object_field_redaction(claim.value.value_type.as_str(), &result.redaction_fields);
    let forced_redaction = !result.redaction_fields.is_empty()
        && effective_disclosure == DisclosureProfile::Value
        && !field_redaction;
    if forced_redaction {
        effective_disclosure = DisclosureProfile::Redacted;
    }
    let allowed = claim
        .disclosure
        .allowed
        .iter()
        .any(|candidate| candidate == effective_disclosure.as_str());
    if !allowed {
        if forced_redaction {
            return Err(EvidenceError::DisclosureNotAllowed);
        }
        effective_disclosure = match DisclosureDowngrade::parse(&claim.disclosure.downgrade)
            .ok_or(EvidenceError::InvalidRequest)?
        {
            DisclosureDowngrade::Default => DisclosureProfile::parse(&claim.disclosure.default)
                .ok_or(EvidenceError::InvalidRequest)?,
            DisclosureDowngrade::Redacted => DisclosureProfile::Redacted,
            DisclosureDowngrade::Deny => return Err(EvidenceError::DisclosureNotAllowed),
        };
        if !claim
            .disclosure
            .allowed
            .iter()
            .any(|candidate| candidate == effective_disclosure.as_str())
        {
            return Err(EvidenceError::DisclosureNotAllowed);
        }
    }
    if effective_disclosure == DisclosureProfile::Predicate && !result.redaction_fields.is_empty() {
        return Err(EvidenceError::DisclosureNotAllowed);
    }
    let value = match effective_disclosure {
        DisclosureProfile::Value if field_redaction => {
            redact_object_fields(&result.value, &result.redaction_fields)?
        }
        DisclosureProfile::Value => Some(result.value.clone()),
        DisclosureProfile::Predicate => result.value.as_bool().map(Value::Bool),
        DisclosureProfile::Redacted => None,
    };
    let satisfied = match effective_disclosure {
        DisclosureProfile::Value | DisclosureProfile::Predicate => result.value.as_bool(),
        DisclosureProfile::Redacted => None,
    };
    Ok(ClaimResultView {
        evaluation_id: result.evaluation_id.clone(),
        claim_id: result.claim_id.clone(),
        claim_version: result.claim_version.clone(),
        subject_type: result.subject_type.clone(),
        requester_ref: result
            .requester
            .as_ref()
            .map(|requester| entity_ref_view(self_attestation_rate_keys, "requester", requester))
            .transpose()?,
        target_ref: target_ref_view(self_attestation_rate_keys, &result.target)?,
        value,
        satisfied,
        disclosure: effective_disclosure.as_str().to_string(),
        redacted_fields: if field_redaction {
            result.redaction_fields.iter().cloned().collect()
        } else if effective_disclosure == DisclosureProfile::Redacted {
            if result.redaction_fields.is_empty() {
                vec![result.claim_id.clone()]
            } else {
                result.redaction_fields.iter().cloned().collect()
            }
        } else {
            Vec::new()
        },
        format: format.to_string(),
        issued_at: format_time(result.issued_at),
        expires_at: result.expires_at.map(format_time),
        provenance: result.provenance.clone(),
    })
}

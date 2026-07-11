// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) fn render_results(
    evidence: &EvidenceConfig,
    results: &[ClaimResultView],
    format: &str,
) -> Result<Value, EvidenceError> {
    match format {
        FORMAT_CLAIM_RESULT_JSON => Ok(json!({ "results": results })),
        FORMAT_CCCEV_JSONLD => Ok(render_cccev(evidence, results)),
        FORMAT_SD_JWT_VC => Err(EvidenceError::FormatUnsupported),
        _ => Err(EvidenceError::FormatUnsupported),
    }
}

pub(super) fn render_cccev(config: &EvidenceConfig, results: &[ClaimResultView]) -> Value {
    let evidence_nodes = results
        .iter()
        .map(|result| render_cccev_evidence_node(config, result))
        .collect::<Vec<_>>();
    json!({
        "@context": {
            "cccev": "http://data.europa.eu/m8g/",
            "dcterms": "http://purl.org/dc/terms/",
            "foaf": "http://xmlns.com/foaf/0.1/",
            "time": "http://www.w3.org/2006/time#",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
            "cccev:isProvidedBy": { "@type": "@id" },
            "cccev:supportsRequirement": { "@type": "@id" },
            "cccev:supportsValue": { "@type": "@id" },
            "cccev:providesValueFor": { "@type": "@id" },
            "cccev:validityPeriod": { "@type": "@id" },
            "time:hasBeginning": { "@type": "xsd:dateTime" },
            "time:hasEnd": { "@type": "xsd:dateTime" }
        },
        "@graph": evidence_nodes
    })
}

pub(super) fn render_cccev_evidence_node(
    config: &EvidenceConfig,
    result: &ClaimResultView,
) -> Value {
    let evidence_id = format!(
        "urn:registry-notary:evidence-render:{}:{}",
        result.evaluation_id, result.claim_id
    );
    let value_id = format!("{evidence_id}#value");
    let period_id = format!("{evidence_id}#validity");

    // Look up the requirement IRI from the claim's oots config when present.
    // Fall back to a urn: reference so the output is always valid JSON-LD.
    let requirement_iri = config
        .claims
        .iter()
        .find(|claim| claim.id == result.claim_id && claim.version == result.claim_version)
        .and_then(|c| c.oots.as_ref())
        .and_then(|o| o.requirement.as_deref())
        .map(|iri| json!({ "@id": iri }))
        .unwrap_or_else(|| json!({ "@id": format!("urn:claim:{}", result.claim_id) }));

    // Build the issuing authority as an Agent node using the service_id from
    // the provenance `generated_by` block (which replaced `computed_by`).
    let provided_by = json!({
        "@type": "foaf:Agent",
        "dcterms:identifier": result.provenance.generated_by.service_id,
    });

    // Build the validity period from issued_at / expires_at.
    let mut validity_period = json!({
        "@id": period_id,
        "@type": "time:ProperInterval",
        "time:hasBeginning": { "@value": result.issued_at, "@type": "xsd:dateTime" },
    });
    if let Some(expires_at) = result.expires_at.as_deref() {
        validity_period["time:hasEnd"] = json!({ "@value": expires_at, "@type": "xsd:dateTime" });
    }

    // Build the SupportedValue node with the claim's value.
    let concept_iri = format!("urn:claim-concept:{}", result.claim_id);
    let supports_value = json!({
        "@id": value_id,
        "@type": "cccev:SupportedValue",
        "cccev:providesValueFor": {
            "@id": concept_iri,
            "@type": "cccev:InformationConcept",
            "dcterms:identifier": result.claim_id,
        },
        "cccev:value": result.value,
    });

    let mut evidence_node = json!({
        "@id": evidence_id,
        "@type": "cccev:Evidence",
        "dcterms:identifier": result.evaluation_id,
        "cccev:isProvidedBy": provided_by,
        "cccev:supportsRequirement": requirement_iri,
        "cccev:supportsValue": supports_value,
        "cccev:validityPeriod": validity_period,
    });
    if let Some(satisfied) = result.satisfied {
        evidence_node["cccev:isConformantTo"] = json!(satisfied);
    }
    evidence_node
}

pub fn credential_profile_for<'a>(
    config: &'a EvidenceConfig,
    evaluation: &registry_notary_core::StoredEvaluation,
    requested_profile: Option<&'a str>,
) -> Result<(&'a str, &'a CredentialProfileConfig), EvidenceError> {
    let claim_refs = evaluation.selected_claim_refs();
    let claim_versions = requested_claim_versions(&claim_refs)?;
    if let Some(profile_id) = requested_profile {
        let profile = config
            .credential_profiles
            .get(profile_id)
            .ok_or(EvidenceError::CredentialIssuerNotConfigured)?;
        // The caller-supplied profile must also be on the allow-list of at
        // least one claim in the evaluation. Without this check a client
        // could mint a credential against a profile the claim never opted
        // in to, bypassing per-claim policy.
        let allowed = claim_refs
            .iter()
            .filter_map(|claim_ref| {
                find_claim_for_selection(config, claim_ref, &claim_versions).ok()
            })
            .any(|claim| {
                claim
                    .credential_profiles
                    .iter()
                    .any(|allowed| allowed == profile_id)
            });
        if !allowed {
            return Err(EvidenceError::CredentialIssuerNotConfigured);
        }
        return Ok((profile_id, profile));
    }
    for claim_ref in &claim_refs {
        let claim = find_claim_for_selection(config, claim_ref, &claim_versions)?;
        for profile_id in &claim.credential_profiles {
            if let Some(profile) = config.credential_profiles.get(profile_id) {
                return Ok((profile_id, profile));
            }
        }
    }
    Err(EvidenceError::CredentialIssuerNotConfigured)
}

pub fn format_time(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .expect("OffsetDateTime within supported RFC3339 range")
}

pub(super) fn target_ref_view(
    self_attestation_rate_keys: &SelfAttestationRateLimitKeys,
    target: &EvidenceEntity,
) -> Result<TargetRefView, EvidenceError> {
    let entity_ref = entity_ref_view(self_attestation_rate_keys, "target", target)?;
    Ok(TargetRefView {
        entity_type: entity_ref.entity_type,
        handle: entity_ref.handle,
        identifier_schemes: entity_ref.identifier_schemes,
        profile: entity_ref.profile,
    })
}

pub(super) fn entity_ref_view(
    self_attestation_rate_keys: &SelfAttestationRateLimitKeys,
    role: &str,
    entity: &EvidenceEntity,
) -> Result<EvidenceEntityRef, EvidenceError> {
    let stable_input = serde_json::json!({
        "role": role,
        "type": entity.entity_type,
        "id": entity.id,
        "identifiers": entity.identifiers,
        "attributes": entity.attributes,
    })
    .to_string();
    let hash = self_attestation_rate_keys
        .subject_ref(role, &stable_input)
        .map_err(|error| error.evidence_error())?;
    let mut identifier_schemes: Vec<String> = entity
        .identifiers
        .iter()
        .map(|identifier| identifier.scheme.clone())
        .collect();
    identifier_schemes.sort();
    identifier_schemes.dedup();
    Ok(EvidenceEntityRef {
        entity_type: entity.entity_type.clone(),
        handle: format!("rnref:v1:{}", hash.as_str()),
        identifier_schemes,
        profile: None,
    })
}

pub(super) fn batch_claim_result(
    evidence: &EvidenceConfig,
    result: &ClaimResultView,
) -> Result<BatchClaimResultView, EvidenceError> {
    let claim = find_claim(evidence, &result.claim_id)?;
    Ok(BatchClaimResultView {
        result_id: Ulid::new().to_string(),
        claim_id: result.claim_id.clone(),
        claim_version: result.claim_version.clone(),
        value_type: batch_value_type(claim, result),
        value: result.value.clone(),
        satisfied: result.satisfied,
        disclosure: result.disclosure.clone(),
        provenance: result.provenance.clone(),
    })
}

pub(super) fn batch_value_type(claim: &ClaimDefinition, result: &ClaimResultView) -> String {
    if !claim.value.value_type.is_empty() {
        return claim.value.value_type.clone();
    }
    match result.value.as_ref() {
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
        Some(Value::Null) | None => "unknown",
    }
    .to_string()
}

pub(super) fn batch_item_error(error: &EvidenceError) -> BatchItemError {
    BatchItemError {
        code: error.code().to_string(),
        title: evidence_title(error).to_string(),
        retryable: matches!(error, EvidenceError::SourceUnavailable),
        audit_code: Some(error.audit_code().to_string()),
    }
}

pub(super) fn stored_disclosure(results: &[ClaimResultView]) -> String {
    let Some(first) = results.first() else {
        return "redacted".to_string();
    };
    if results
        .iter()
        .all(|result| result.disclosure == first.disclosure)
    {
        first.disclosure.clone()
    } else {
        "mixed".to_string()
    }
}

pub(super) fn hash_json<T: serde::Serialize>(value: &T) -> Result<String, EvidenceError> {
    let bytes = serde_json::to_vec(value).map_err(|_| EvidenceError::InvalidRequest)?;
    Ok(sha256_hex(&bytes))
}

pub(crate) fn batch_request_hash(request: &BatchEvaluateRequest) -> Result<String, EvidenceError> {
    hash_json(request)
}

pub(crate) fn batch_idempotency_key(principal_id: &str, key: &str) -> String {
    format!(
        "{}:/v1/batch-evaluations:{}",
        principal_id,
        sha256_hex(key.as_bytes())
    )
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex_encode(&Sha256::digest(bytes))
}

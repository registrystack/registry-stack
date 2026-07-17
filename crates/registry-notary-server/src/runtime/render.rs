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

/// Fail closed unless every credential fact currently resolves to one
/// registry-backed claim. OID4VCI uses this before issuer or nonce access so a
/// config assembled without the shared loader cannot recover a signing path.
pub(crate) fn require_registry_backed_credential_claims(
    evidence: &EvidenceConfig,
    claim_ids: &[String],
) -> Result<(), EvidenceError> {
    if claim_ids.is_empty() || claim_ids.len() > MAX_CLAIM_DEPENDENCY_NODES_V1 {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    let mut seen = BTreeSet::new();
    for claim_id in claim_ids {
        if !seen.insert(claim_id.as_str()) {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
    }
    let selected = claim_ids
        .iter()
        .map(|claim_id| ClaimRef::from(claim_id.as_str()))
        .collect::<Vec<_>>();
    let versions = requested_claim_versions(&selected)?;
    let levels = build_claim_levels(evidence, &selected, &versions)
        .map_err(|_| EvidenceError::EvaluationBindingMismatch)?;
    for claim_id in levels.iter().flatten() {
        if evidence
            .claims
            .iter()
            .filter(|candidate| candidate.id.as_str() == claim_id.as_str())
            .count()
            != 1
        {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
        let claim = find_claim_for_selection(evidence, claim_id.as_str(), &versions)
            .map_err(|_| EvidenceError::EvaluationBindingMismatch)?;
        let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
            return Err(EvidenceError::EvaluationBindingMismatch);
        };
        if consultations.len() != 1 || claim.purpose.as_deref().is_none() {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
    }
    Ok(())
}

/// Commit one compiler pin to the exact Relay execution and claim provenance
/// observed during evaluation. This is an unkeyed integrity cross-binding for
/// detecting partial stored-record mutation. It is not an authenticity anchor
/// against an operator able to rewrite every committed field and the digest.
pub(crate) fn issuance_execution_binding(
    claim: &StoredIssuanceClaimProvenance,
    consultation: &StoredIssuanceConsultationProvenance,
    evaluation_id: &str,
    issued_at: &str,
    provenance: &ClaimProvenance,
) -> Result<String, EvidenceError> {
    sha256_canonical_json(&json!({
        "schema": "registry.notary.issuance-execution-binding/v1",
        "claim": {
            "id": claim.claim_id,
            "version": claim.claim_version,
            "relay_profile_id": claim.relay_profile_id,
            "relay_contract_hash": claim.relay_contract_hash,
            "canonical_purpose": claim.canonical_purpose,
        },
        "execution": {
            "consultation_id": consultation.consultation_id,
            "acquired_at": consultation.acquired_at,
        },
        "result": {
            "evaluation_id": evaluation_id,
            "issued_at": issued_at,
            "provenance": provenance,
        },
    }))
}

fn expected_issuance_claim_provenance(
    evidence: &EvidenceConfig,
    evaluation: &registry_notary_core::StoredEvaluation,
    evaluation_id: &str,
    claim_id: &str,
    claim_version: &str,
    relay_consultation_count: usize,
) -> ClaimProvenance {
    let mut provenance = ClaimProvenance::new(
        evidence.service_id.clone(),
        evaluation_id.to_string(),
        claim_id.to_string(),
        claim_version.to_string(),
        ProvenanceUsed {
            relay_consultation_count,
        },
    );
    let policy = evaluation_policy_from_subject_access(evaluation.subject_access.as_ref());
    provenance.generated_by.policy_id = policy.policy_id;
    provenance.generated_by.policy_version = policy.policy_version;
    provenance.generated_by.policy_hash = policy.policy_hash;
    provenance
}

/// Verify the restricted Relay execution record before credential signing.
///
/// Public result provenance intentionally exposes only a consultation count.
/// This verifier joins it to the private dependency-closure compiler pins and rejects
/// legacy, incomplete, duplicated, extra, or tampered state before a signer,
/// holder-proof replay store, credential id, or status store is touched.
pub(crate) fn require_issuable_evaluation_provenance(
    evidence: &EvidenceConfig,
    evaluation_id: &str,
    evaluation: &registry_notary_core::StoredEvaluation,
) -> Result<(), EvidenceError> {
    let selected = evaluation.selected_claim_refs();
    if selected.is_empty()
        || selected.len() > MAX_CLAIM_DEPENDENCY_NODES_V1
        || evaluation.claim_ids.len() != selected.len()
        || evaluation.results.len() != selected.len()
    {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    let stored = evaluation
        .issuance_provenance
        .as_ref()
        .ok_or(EvidenceError::EvaluationBindingMismatch)?;
    if stored.claims.is_empty()
        || stored.claims.len() > MAX_CLAIM_DEPENDENCY_NODES_V1
        || stored.consultations.is_empty()
        || stored.consultations.len() > MAX_CLAIM_DEPENDENCY_NODES_V1
    {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }

    let versions = requested_claim_versions(&selected)?;
    let levels = build_claim_levels(evidence, &selected, &versions)
        .map_err(|_| EvidenceError::EvaluationBindingMismatch)?;
    let expected_claim_ids = levels.iter().flatten().collect::<BTreeSet<_>>();
    if expected_claim_ids.len() != stored.claims.len() {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }

    let mut selected_ids = BTreeSet::new();
    let mut result_ids = BTreeSet::new();
    let mut private_claims = BTreeMap::new();
    let mut private_consultations = BTreeMap::new();
    for result in &evaluation.results {
        if !result_ids.insert(result.claim_id.as_str()) {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
    }
    for provenance in &stored.claims {
        if private_claims
            .insert(provenance.claim_id.as_str(), provenance)
            .is_some()
        {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
    }
    for consultation in &stored.consultations {
        let consultation_id = Ulid::from_string(&consultation.consultation_id)
            .map_err(|_| EvidenceError::EvaluationBindingMismatch)?;
        let acquired_at = OffsetDateTime::parse(&consultation.acquired_at, &Rfc3339)
            .map_err(|_| EvidenceError::EvaluationBindingMismatch)?;
        if consultation_id.to_string() != consultation.consultation_id
            || format_time(acquired_at) != consultation.acquired_at
            || private_consultations
                .insert(
                    consultation.consultation_id.as_str(),
                    (consultation, acquired_at),
                )
                .is_some()
        {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
    }

    let mut referenced_consultations = BTreeSet::new();
    for claim_id in &expected_claim_ids {
        if evidence
            .claims
            .iter()
            .filter(|candidate| candidate.id.as_str() == claim_id.as_str())
            .count()
            != 1
        {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
        let claim = find_claim_for_selection(evidence, claim_id.as_str(), &versions)
            .map_err(|_| EvidenceError::EvaluationBindingMismatch)?;
        let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
            return Err(EvidenceError::EvaluationBindingMismatch);
        };
        let (_, consultation) = consultations
            .first_key_value()
            .filter(|_| consultations.len() == 1)
            .ok_or(EvidenceError::EvaluationBindingMismatch)?;
        if claim.purpose.as_deref() != Some(evaluation.purpose.as_str()) {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
        let private = private_claims
            .get(claim_id.as_str())
            .ok_or(EvidenceError::EvaluationBindingMismatch)?;
        let (private_consultation, _) = private_consultations
            .get(private.consultation_id.as_str())
            .ok_or(EvidenceError::EvaluationBindingMismatch)?;
        if private.claim_version != claim.version
            || private.relay_profile_id != consultation.profile.id
            || private.relay_contract_hash != consultation.profile.contract_hash
            || private.canonical_purpose != evaluation.purpose
        {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
        let claim_levels =
            build_claim_levels(evidence, &[ClaimRef::from(claim_id.as_str())], &versions)
                .map_err(|_| EvidenceError::EvaluationBindingMismatch)?;
        let claim_consultations = claim_levels
            .iter()
            .flatten()
            .map(|dependency_id| {
                private_claims
                    .get(dependency_id.as_str())
                    .map(|dependency| dependency.consultation_id.as_str())
                    .ok_or(EvidenceError::EvaluationBindingMismatch)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let expected_provenance = expected_issuance_claim_provenance(
            evidence,
            evaluation,
            evaluation_id,
            claim_id,
            &claim.version,
            claim_consultations.len(),
        );
        let expected_binding = issuance_execution_binding(
            private,
            private_consultation,
            evaluation_id,
            &private_consultation.acquired_at,
            &expected_provenance,
        )?;
        if private.execution_binding != expected_binding {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
        referenced_consultations.insert(private.consultation_id.as_str());
    }
    if referenced_consultations.len() != private_consultations.len() {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }

    for (position, claim_ref) in selected.iter().enumerate() {
        if evaluation.claim_ids[position] != claim_ref.id
            || !selected_ids.insert(claim_ref.id.as_str())
        {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
        let selected_claim = find_claim_for_selection(evidence, claim_ref, &versions)
            .map_err(|_| EvidenceError::EvaluationBindingMismatch)?;
        let root_private = private_claims
            .get(claim_ref.id.as_str())
            .ok_or(EvidenceError::EvaluationBindingMismatch)?;
        let (_, root_acquired_at) = private_consultations
            .get(root_private.consultation_id.as_str())
            .ok_or(EvidenceError::EvaluationBindingMismatch)?;
        let (root_consultation, _) = private_consultations
            .get(root_private.consultation_id.as_str())
            .ok_or(EvidenceError::EvaluationBindingMismatch)?;
        let root_levels = build_claim_levels(evidence, std::slice::from_ref(claim_ref), &versions)
            .map_err(|_| EvidenceError::EvaluationBindingMismatch)?;
        let root_consultations = root_levels
            .iter()
            .flatten()
            .map(|claim_id| {
                private_claims
                    .get(claim_id.as_str())
                    .map(|private| private.consultation_id.as_str())
                    .ok_or(EvidenceError::EvaluationBindingMismatch)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;

        let result = evaluation
            .results
            .iter()
            .find(|result| result.claim_id == claim_ref.id)
            .ok_or(EvidenceError::EvaluationBindingMismatch)?;
        let generated = &result.provenance.generated_by;
        let result_issued_at = OffsetDateTime::parse(&result.issued_at, &Rfc3339)
            .map_err(|_| EvidenceError::EvaluationBindingMismatch)?;
        let result_binding = issuance_execution_binding(
            root_private,
            root_consultation,
            evaluation_id,
            &result.issued_at,
            &result.provenance,
        )?;
        if result.evaluation_id != evaluation_id
            || result.claim_version != selected_claim.version
            || result_issued_at != *root_acquired_at
            || result.provenance.schema_version
                != registry_notary_core::CLAIM_PROVENANCE_SCHEMA_VERSION
            || generated.entry_type
                != registry_notary_core::PROVENANCE_GENERATED_BY_CLAIM_EVALUATION
            || generated.service_id != evidence.service_id
            || generated.evaluation_id != evaluation_id
            || generated.claim_id != claim_ref.id
            || generated.claim_version != selected_claim.version
            || result.provenance.used.relay_consultation_count != root_consultations.len()
            || result_binding != root_private.execution_binding
        {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
    }

    Ok(())
}

pub fn format_time(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .expect("OffsetDateTime within supported RFC3339 range")
}

pub(super) fn target_ref_view(
    subject_access_rate_keys: &SubjectAccessRateLimitKeys,
    target: &EvidenceEntity,
) -> Result<TargetRefView, EvidenceError> {
    let entity_ref = entity_ref_view(subject_access_rate_keys, "target", target)?;
    Ok(TargetRefView {
        entity_type: entity_ref.entity_type,
        handle: entity_ref.handle,
        identifier_schemes: entity_ref.identifier_schemes,
        profile: entity_ref.profile,
    })
}

pub(super) fn entity_ref_view(
    subject_access_rate_keys: &SubjectAccessRateLimitKeys,
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
    let hash = subject_access_rate_keys
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
        retryable: false,
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

pub(crate) fn batch_request_binding_hash(
    evidence: &EvidenceConfig,
    request: &BatchEvaluateRequest,
    principal: &EvidencePrincipal,
    effective_item_purposes: &[String],
    claim_versions: &ClaimVersionSelections,
) -> Result<String, EvidenceError> {
    let checked_scopes = principal
        .scopes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    hash_json(&json!({
        "schema": "registry.notary.batch-idempotency-binding/v1",
        "evidence_config": evidence,
        "request": request,
        "authentication": {
            "auth_profile_id": principal.auth_profile_id.as_str(),
            "principal_id": principal.principal_id.as_str(),
            "checked_scopes": checked_scopes,
        },
        "effective_item_purposes": effective_item_purposes,
        "claim_versions": claim_versions,
    }))
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

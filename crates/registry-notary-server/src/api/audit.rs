// SPDX-License-Identifier: Apache-2.0
//! Audit context assembly and shared evidence problem responses.

use super::*;

pub(super) fn attach_evidence_audit(
    response: &mut Response,
    decision: &str,
    verification_id: Option<String>,
    claim_ids: &[String],
    row_count: Option<u64>,
) {
    attach_evidence_audit_with_purposes(
        response,
        decision,
        verification_id,
        claim_ids,
        row_count,
        None,
    );
}

pub(super) fn attach_evidence_audit_with_purposes(
    response: &mut Response,
    decision: &str,
    verification_id: Option<String>,
    claim_ids: &[String],
    row_count: Option<u64>,
    purposes: Option<Vec<String>>,
) {
    response.extensions_mut().insert(EvidenceAuditContext {
        verification_id,
        verification_decision: Some(decision.to_string()),
        claim_hash: (!claim_ids.is_empty()).then(|| evidence_claim_hash(claim_ids)),
        purposes,
        row_count,
        source_read_count: row_count,
        forwarded: None,
        access_mode: None,
        denial_code: None,
        token_claim_name: None,
        credential_profile: None,
        protocol: None,
        credential_configuration_id: None,
        holder_binding_mode: None,
        rate_limit_bucket: None,
        policy_hash: None,
        target_type: None,
        target_ref_hash: None,
        requester_type: None,
        requester_ref_hash: None,
        matching_policy_id: None,
        matching_method: None,
        matching_outcome: None,
        matching_error_code: None,
        batch_items: None,
        ..EvidenceAuditContext::default()
    });
}

pub(super) fn attach_zero_source_no_forward_audit(response: &mut Response) {
    if let Some(audit) = response.extensions_mut().get_mut::<EvidenceAuditContext>() {
        audit.source_read_count = Some(0);
        audit.forwarded = Some(false);
    }
}

pub(super) fn attach_relay_consultation_audit(response: &mut Response, ids: Vec<String>) {
    if ids.is_empty() {
        return;
    }
    if let Some(audit) = response.extensions_mut().get_mut::<EvidenceAuditContext>() {
        audit.source_read_count = u64::try_from(ids.len()).ok();
        audit.relay_consultation_ids = ids;
    }
}

pub(super) fn attach_runtime_evaluation_audit(
    response: &mut Response,
    runtime_audit: EvaluationAuditSnapshot,
) {
    let relay_forwarded_count = runtime_audit.relay_forwarded_count();
    let (evaluation_id, relay_consultation_ids) = runtime_audit.into_parts();
    if let Some(audit) = response.extensions_mut().get_mut::<EvidenceAuditContext>() {
        if evaluation_id.is_some() {
            audit.verification_id = evaluation_id;
        }
        if relay_forwarded_count > 0 {
            audit.forwarded = Some(true);
        }
    }
    attach_relay_consultation_audit(response, relay_consultation_ids);
}

pub(super) fn attach_source_sidecar_config_hashes(
    response: &mut Response,
    config_hashes: Vec<String>,
) {
    if config_hashes.is_empty() {
        return;
    }
    if let Some(audit) = response.extensions_mut().get_mut::<EvidenceAuditContext>() {
        audit.source_sidecar_config_hashes = Some(config_hashes);
    }
}

pub(super) fn attach_redacted_fields_audit(response: &mut Response, results: &[ClaimResultView]) {
    let redacted_fields: BTreeSet<String> = results
        .iter()
        .flat_map(|result| result.redacted_fields.iter().cloned())
        .collect();
    if redacted_fields.is_empty() {
        return;
    }
    if let Some(audit) = response.extensions_mut().get_mut::<EvidenceAuditContext>() {
        audit.redacted_fields = Some(redacted_fields.into_iter().collect());
    }
}

pub(super) fn attach_evaluate_request_audit(
    response: &mut Response,
    keys: &SelfAttestationRateLimitKeys,
    request: &EvaluateRequest,
    result: Option<&ClaimResultView>,
    matching_error_code: Option<&str>,
    denied_matching_policy: Option<&MatchingPolicyAuditIdentity>,
) -> Result<(), EvidenceError> {
    let Some(audit) = response.extensions_mut().get_mut::<EvidenceAuditContext>() else {
        return Ok(());
    };
    if audit.purposes.is_none() {
        audit.purposes = request
            .purpose
            .as_ref()
            .map(|purpose| vec![purpose.clone()]);
    }
    audit.target_type = result
        .map(|result| result.target_ref.entity_type.as_str())
        .or_else(|| {
            request
                .target
                .as_ref()
                .map(|target| target.entity_type.as_str())
        })
        .filter(|entity_type| !entity_type.is_empty())
        .map(str::to_string);
    audit.target_ref_hash = match result {
        Some(result) => Some(hash_audit_handle(
            keys,
            "target",
            result.target_ref.entity_type.as_str(),
            request.purpose.as_deref(),
            &result.target_ref.handle,
        )?),
        None => match request.target.as_ref() {
            Some(target) => {
                hash_audit_matching_attempt(keys, "target", request.purpose.as_deref(), target)?
            }
            None => None,
        },
    };
    if let Some(requester_ref) = result.and_then(|result| result.requester_ref.as_ref()) {
        audit.requester_type = Some(requester_ref.entity_type.clone());
        audit.requester_ref_hash = Some(hash_audit_handle(
            keys,
            "requester",
            requester_ref.entity_type.as_str(),
            request.purpose.as_deref(),
            &requester_ref.handle,
        )?);
    } else if let Some(requester) = request.requester.as_ref() {
        audit.requester_type = Some(requester.entity_type.clone());
        audit.requester_ref_hash =
            hash_audit_matching_attempt(keys, "requester", request.purpose.as_deref(), requester)?;
    }
    if let Some(matching) = result.and_then(|result| result.matching.as_ref()) {
        audit.matching_policy_id = Some(matching.policy_id.clone());
        audit.matching_policy_hash = matching
            .policy_hash
            .as_ref()
            .map(|hash| Hashed::<PolicyIdentifier>::from_hash(hash.clone()));
        audit.matching_evaluated_rule_ids =
            (!matching.evaluated_rule_ids.is_empty()).then(|| matching.evaluated_rule_ids.clone());
        audit.ecosystem_binding_id = matching.ecosystem_binding_id.clone();
        audit.ecosystem_binding_version = matching.ecosystem_binding_version.clone();
        audit.pack_id = matching.pack_id.clone();
        audit.pack_version = matching.pack_version.clone();
        audit.matching_method = Some(matching.method.clone());
        audit.matching_outcome = Some("matched".to_string());
    } else if let Some(error_code) = matching_error_code.filter(|code| is_matching_audit_code(code))
    {
        if let Some(policy) = denied_matching_policy {
            audit.matching_policy_id = Some(policy.policy_id.clone());
            audit.matching_policy_hash = Some(Hashed::<PolicyIdentifier>::from_hash(
                policy.policy_hash.clone(),
            ));
            audit.matching_evaluated_rule_ids =
                (!policy.evaluated_rule_ids.is_empty()).then(|| policy.evaluated_rule_ids.clone());
            audit.ecosystem_binding_id = policy.ecosystem_binding_id.clone();
            audit.ecosystem_binding_version = policy.ecosystem_binding_version.clone();
            audit.pack_id = policy.pack_id.clone();
            audit.pack_version = policy.pack_version.clone();
        }
        audit.matching_outcome = Some("error".to_string());
        audit.matching_error_code = Some(error_code.to_string());
    }
    if audit.redacted_fields.is_none() {
        audit.redacted_fields = result.and_then(|result| {
            (!result.redacted_fields.is_empty()).then(|| result.redacted_fields.clone())
        });
    }
    Ok(())
}

pub(super) fn attach_batch_evaluate_response_audit(
    response: &mut Response,
    keys: &SelfAttestationRateLimitKeys,
    evidence: &EvidenceConfig,
    request: &BatchEvaluateRequest,
    result: &registry_notary_core::BatchEvaluateResponse,
    audit_purposes: Option<&[String]>,
) -> Result<(), EvidenceError> {
    let Some(audit) = response.extensions_mut().get_mut::<EvidenceAuditContext>() else {
        return Ok(());
    };
    let mut batch_items = Vec::with_capacity(result.items.len());
    for item in &result.items {
        let purpose_scope = audit_purposes
            .and_then(|purposes| purposes.get(item.input_index))
            .map(String::as_str);
        let matching_error_code = item
            .errors
            .first()
            .and_then(|error| error.audit_code.as_deref().or(Some(error.code.as_str())))
            .filter(|code| is_matching_audit_code(code))
            .map(str::to_string);
        let matching = item.matching.as_ref();
        let denied_matching_policy = matching_error_code.as_deref().and_then(|code| {
            denied_batch_item_matching_policy_audit_identity(
                evidence,
                request,
                item.input_index,
                code,
            )
        });
        batch_items.push(EvidenceBatchItemAuditEvent {
            input_index: item.input_index,
            target_type: Some(item.target_ref.entity_type.clone())
                .filter(|entity_type| !entity_type.is_empty()),
            target_ref_hash: if item.errors.is_empty() {
                Some(hash_audit_handle(
                    keys,
                    "target",
                    item.target_ref.entity_type.as_str(),
                    purpose_scope,
                    &item.target_ref.handle,
                )?)
            } else {
                None
            },
            requester_type: item
                .requester_ref
                .as_ref()
                .map(|requester| requester.entity_type.clone()),
            requester_ref_hash: item
                .requester_ref
                .as_ref()
                .filter(|_| item.errors.is_empty())
                .map(|requester| {
                    hash_audit_handle(
                        keys,
                        "requester",
                        requester.entity_type.as_str(),
                        purpose_scope,
                        &requester.handle,
                    )
                })
                .transpose()?,
            matching_policy_id: matching
                .map(|matching| matching.policy_id.clone())
                .or_else(|| {
                    denied_matching_policy
                        .as_ref()
                        .map(|policy| policy.policy_id.clone())
                }),
            matching_policy_hash: matching
                .and_then(|matching| matching.policy_hash.as_ref())
                .map(|hash| Hashed::<PolicyIdentifier>::from_hash(hash.clone()))
                .or_else(|| {
                    denied_matching_policy.as_ref().map(|policy| {
                        Hashed::<PolicyIdentifier>::from_hash(policy.policy_hash.clone())
                    })
                }),
            matching_evaluated_rule_ids: matching
                .map(|matching| matching.evaluated_rule_ids.clone())
                .filter(|rule_ids| !rule_ids.is_empty())
                .or_else(|| {
                    denied_matching_policy
                        .as_ref()
                        .map(|policy| policy.evaluated_rule_ids.clone())
                        .filter(|rule_ids| !rule_ids.is_empty())
                }),
            ecosystem_binding_id: matching
                .and_then(|matching| matching.ecosystem_binding_id.clone())
                .or_else(|| {
                    denied_matching_policy
                        .as_ref()
                        .and_then(|policy| policy.ecosystem_binding_id.clone())
                }),
            ecosystem_binding_version: matching
                .and_then(|matching| matching.ecosystem_binding_version.clone())
                .or_else(|| {
                    denied_matching_policy
                        .as_ref()
                        .and_then(|policy| policy.ecosystem_binding_version.clone())
                }),
            pack_id: matching
                .and_then(|matching| matching.pack_id.clone())
                .or_else(|| {
                    denied_matching_policy
                        .as_ref()
                        .and_then(|policy| policy.pack_id.clone())
                }),
            pack_version: matching
                .and_then(|matching| matching.pack_version.clone())
                .or_else(|| {
                    denied_matching_policy
                        .as_ref()
                        .and_then(|policy| policy.pack_version.clone())
                }),
            matching_method: matching.map(|matching| matching.method.clone()),
            matching_outcome: if item.errors.is_empty() {
                Some("matched".to_string())
            } else if matching_error_code.is_some() {
                Some("error".to_string())
            } else {
                None
            },
            matching_error_code,
        });
    }
    audit.batch_items = Some(batch_items);
    Ok(())
}

pub(super) fn denied_batch_item_matching_policy_audit_identity(
    evidence: &EvidenceConfig,
    request: &BatchEvaluateRequest,
    input_index: usize,
    matching_error_code: &str,
) -> Option<MatchingPolicyAuditIdentity> {
    let item = request.items.get(input_index)?;
    let evaluate_request = EvaluateRequest {
        requester: item.requester.clone(),
        target: Some(item.target.clone()),
        relationship: item.relationship.clone(),
        on_behalf_of: item.on_behalf_of.clone(),
        variables: Default::default(),
        claims: request.claims.clone(),
        disclosure: request.disclosure.clone(),
        format: request.format.clone(),
        purpose: item.purpose.clone().or_else(|| request.purpose.clone()),
    };
    denied_matching_policy_audit_identity(evidence, &evaluate_request, Some(matching_error_code))
}

pub(super) fn matching_policy_audit_identity_from_error(
    evidence: &EvidenceConfig,
    error: &EvidenceError,
) -> Option<MatchingPolicyAuditIdentity> {
    let EvidenceError::PolicyDenied {
        policy_id: Some(policy_id),
        policy_hash: Some(policy_hash),
        evaluated_rule_ids,
        ..
    } = error
    else {
        return None;
    };
    let ecosystem_binding = ecosystem_binding_for_policy(evidence, policy_id, policy_hash);
    Some(MatchingPolicyAuditIdentity {
        policy_id: policy_id.clone(),
        policy_hash: policy_hash.clone(),
        ecosystem_binding_id: ecosystem_binding.clone(),
        ecosystem_binding_version: ecosystem_binding
            .as_deref()
            .and_then(ecosystem_binding_version_from_id),
        pack_id: ecosystem_binding.clone(),
        pack_version: ecosystem_binding
            .as_deref()
            .and_then(ecosystem_binding_version_from_id),
        evaluated_rule_ids: evaluated_rule_ids.clone(),
    })
}

pub(super) fn ecosystem_binding_for_policy(
    evidence: &EvidenceConfig,
    policy_id: &str,
    policy_hash: &str,
) -> Option<String> {
    evidence
        .ecosystem_bindings
        .iter()
        .find(|(_, binding)| binding.policy_id == policy_id && binding.policy_hash == policy_hash)
        .map(|(id, _)| id.clone())
}

pub(super) fn ecosystem_binding_version_from_id(id: &str) -> Option<String> {
    let (_, version) = id.rsplit_once('/')?;
    let version = version.trim();
    (!version.is_empty()).then(|| version.to_string())
}

pub(super) fn merge_matching_policy_audit_identity(
    primary: Option<MatchingPolicyAuditIdentity>,
    fallback: Option<MatchingPolicyAuditIdentity>,
) -> Option<MatchingPolicyAuditIdentity> {
    match (primary, fallback) {
        (Some(mut primary), Some(fallback)) => {
            if primary.ecosystem_binding_id.is_none() {
                primary.ecosystem_binding_id = fallback.ecosystem_binding_id;
            }
            if primary.ecosystem_binding_version.is_none() {
                primary.ecosystem_binding_version = fallback.ecosystem_binding_version;
            }
            if primary.pack_id.is_none() {
                primary.pack_id = fallback.pack_id;
            }
            if primary.pack_version.is_none() {
                primary.pack_version = fallback.pack_version;
            }
            if primary.evaluated_rule_ids.is_empty() {
                primary.evaluated_rule_ids = fallback.evaluated_rule_ids;
            }
            Some(primary)
        }
        (Some(primary), None) => Some(primary),
        (None, fallback) => fallback,
    }
}

pub(super) fn hash_audit_handle(
    keys: &SelfAttestationRateLimitKeys,
    role: &str,
    entity_type: &str,
    purpose_scope: Option<&str>,
    handle: &str,
) -> Result<Hashed<EvidenceEntityReference>, EvidenceError> {
    let input = canonical_audit_handle_input(role, entity_type, purpose_scope, handle)?;
    keys.audit_pseudonym_ref("matched-reference-v1", &input)
        .map(|hash| Hashed::from_hash(hash.as_str().to_string()))
        .map_err(|error| error.evidence_error())
}

pub(super) fn hash_audit_matching_attempt(
    _keys: &SelfAttestationRateLimitKeys,
    role: &str,
    purpose_scope: Option<&str>,
    entity: &EvidenceEntity,
) -> Result<Option<Hashed<EvidenceEntityReference>>, EvidenceError> {
    let _ = canonical_audit_identifier_input(role, purpose_scope, entity)?;
    Ok(None)
}

pub(super) fn canonical_audit_handle_input(
    role: &str,
    entity_type: &str,
    purpose_scope: Option<&str>,
    handle: &str,
) -> Result<String, EvidenceError> {
    serde_json::to_string(&json!({
        "class": "matched-reference-v1",
        "version": 1,
        "role": role,
        "entity_type": entity_type,
        "purpose_scope": purpose_scope.unwrap_or(""),
        "handle": handle,
    }))
    .map_err(|_| EvidenceError::InvalidRequest)
}

pub(super) fn canonical_audit_identifier_input(
    role: &str,
    purpose_scope: Option<&str>,
    entity: &EvidenceEntity,
) -> Result<Option<String>, EvidenceError> {
    let mut identifiers = entity
        .identifiers
        .iter()
        .filter(|identifier| !identifier.value.trim().is_empty())
        .map(|identifier| {
            let mut canonical = BTreeMap::new();
            canonical.insert("country", identifier.country.as_deref().unwrap_or(""));
            canonical.insert("issuer", identifier.issuer.as_deref().unwrap_or(""));
            canonical.insert("scheme", identifier.scheme.as_str());
            canonical.insert("value", identifier.value.as_str());
            canonical
        })
        .collect::<Vec<_>>();
    identifiers.sort_by(|left, right| {
        (
            left["scheme"],
            left["issuer"],
            left["country"],
            left["value"],
        )
            .cmp(&(
                right["scheme"],
                right["issuer"],
                right["country"],
                right["value"],
            ))
    });
    identifiers.dedup();
    if identifiers.is_empty() && entity.id.as_deref().is_none_or(str::is_empty) {
        return Ok(None);
    }
    serde_json::to_string(&json!({
        "class": "matching-attempt-v1",
        "version": 1,
        "role": role,
        "entity_type": entity.entity_type,
        "purpose_scope": purpose_scope.unwrap_or(""),
        "id": entity.id.as_deref().unwrap_or(""),
        "identifiers": identifiers,
    }))
    .map(Some)
    .map_err(|_| EvidenceError::InvalidRequest)
}

pub(super) fn is_matching_audit_code(code: &str) -> bool {
    code.starts_with("target.")
        || code.starts_with("requester.")
        || code.starts_with("relationship.")
        || code.starts_with("pdp.")
        || matches!(code, "purpose.not_allowed" | "evidence.not_available")
}

pub(super) fn denied_matching_policy_audit_identity(
    evidence: &EvidenceConfig,
    request: &EvaluateRequest,
    matching_error_code: Option<&str>,
) -> Option<MatchingPolicyAuditIdentity> {
    matching_error_code.filter(|code| is_matching_policy_provenance_code(code))?;
    let context = request.request_context()?;
    request.claims.iter().find_map(|claim_ref| {
        let claim = match claim_ref.version.as_deref() {
            Some(version) => find_claim_version(evidence, claim_ref.id.as_str(), version).ok()?,
            None => find_claim(evidence, claim_ref.id.as_str()).ok()?,
        };
        if let Some(binding) = claim_rule_source_id(claim)
            .and_then(|source| claim.source_bindings.get(source))
            .filter(|binding| source_binding_matches_request(binding, &context))
        {
            return Some(matching_policy_audit_identity(evidence, binding));
        }
        claim
            .source_bindings
            .values()
            .find(|binding| source_binding_matches_request(binding, &context))
            .or_else(|| {
                (claim.source_bindings.len() == 1).then(|| {
                    claim
                        .source_bindings
                        .values()
                        .next()
                        .expect("single source binding exists")
                })
            })
            .map(|binding| matching_policy_audit_identity(evidence, binding))
    })
}

pub(super) fn claim_rule_source_id(claim: &registry_notary_core::ClaimDefinition) -> Option<&str> {
    match &claim.rule {
        registry_notary_core::RuleConfig::Extract { source, .. }
        | registry_notary_core::RuleConfig::Exists { source } => Some(source.as_str()),
        registry_notary_core::RuleConfig::Cel { .. }
        | registry_notary_core::RuleConfig::Plugin { .. } => None,
    }
}

pub(super) fn source_binding_matches_request(
    binding: &registry_notary_core::SourceBindingConfig,
    context: &registry_notary_core::EvidenceRequestContext,
) -> bool {
    if binding.query_fields.is_empty() {
        return source_lookup_input_matches_request(binding.lookup.input.as_str(), context);
    }
    binding
        .query_fields
        .iter()
        .all(|field| source_lookup_input_matches_request(field.input.as_str(), context))
}

pub(super) fn source_lookup_input_matches_request(
    input: &str,
    context: &registry_notary_core::EvidenceRequestContext,
) -> bool {
    context.lookup_value(input).is_some() || parse_source_lookup_input(input).is_some()
}

pub(super) fn parse_source_lookup_input(input: &str) -> Option<(&str, &str)> {
    let remainder = input
        .strip_prefix("sources.")
        .or_else(|| input.strip_prefix("source."))?;
    let (binding_id, field_path) = remainder.split_once('.')?;
    if binding_id.is_empty() || field_path.is_empty() {
        return None;
    }
    Some((binding_id, field_path))
}

pub(super) fn is_matching_policy_provenance_code(code: &str) -> bool {
    if code.starts_with("pdp.") {
        return true;
    }
    matches!(
        code,
        "target.matching_policy_rejected"
            | "requester.matching_policy_rejected"
            | "relationship.policy_rejected"
    )
}

// Before a stored evaluation is found, keep caller-controlled evaluation ids out of audit data.
pub(super) fn credential_denial_response_without_evaluation(error: EvidenceError) -> Response {
    let denial_code = denial_code_from_error(&error);
    let mut response = evidence_error_response(error);
    attach_evidence_audit(&mut response, "credential_denied", None, &[], None);
    attach_zero_source_no_forward_audit(&mut response);
    if let Some(audit) = response.extensions_mut().get_mut::<EvidenceAuditContext>() {
        audit.denial_code = denial_code;
    }
    response
}

pub(super) fn credential_denial_response_for_evaluation(
    state: &RegistryNotaryApiState,
    error: EvidenceError,
    evaluation_id: &str,
    evaluation: &registry_notary_core::StoredEvaluation,
    principal: &EvidencePrincipal,
    profile: Option<(&str, &CredentialProfileConfig)>,
) -> Response {
    let denial_code = denial_code_from_error(&error);
    let mut response = evidence_error_response(error);
    if evaluation.self_attestation.is_some() || principal.is_self_attestation() {
        if let Err(error) = attach_self_attestation_credential_denial_audit(
            &mut response,
            &state.self_attestation_rate_keys,
            evaluation_id,
            evaluation,
            profile,
        ) {
            return evidence_error_response(error);
        }
        override_attestation_audit_access_mode(&mut response, evaluation.access_mode());
    } else {
        attach_evidence_audit_with_purposes(
            &mut response,
            "credential_denied",
            Some(evaluation_id.to_string()),
            &evaluation.claim_ids,
            None,
            Some(vec![evaluation.purpose.clone()]),
        );
        if let Some((profile_id, profile)) = profile {
            if let Some(audit) = response.extensions_mut().get_mut::<EvidenceAuditContext>() {
                audit.credential_profile = ConfigMetadata::new(profile_id).ok();
                audit.holder_binding_mode =
                    ConfigMetadata::new(profile.holder_binding.mode.as_str()).ok();
            }
        }
    }
    attach_zero_source_no_forward_audit(&mut response);
    if let Some(audit) = response.extensions_mut().get_mut::<EvidenceAuditContext>() {
        audit.denial_code = denial_code;
    }
    response
}

pub(super) struct SelfAttestationCredentialAuditDetails<'a> {
    pub(super) profile_id: &'a str,
    pub(super) holder_binding_mode: &'a str,
    pub(super) policy_hash: Option<Hashed<PolicyIdentifier>>,
    pub(super) purposes: Option<Vec<String>>,
    pub(super) protocol: Option<&'a str>,
    pub(super) credential_configuration_id: Option<&'a str>,
}

pub(super) fn attach_self_attestation_credential_denial_audit(
    response: &mut Response,
    keys: &SelfAttestationRateLimitKeys,
    evaluation_id: &str,
    evaluation: &registry_notary_core::StoredEvaluation,
    profile: Option<(&str, &CredentialProfileConfig)>,
) -> Result<(), EvidenceError> {
    let first_result = evaluation.results.first();
    let target_type = first_result
        .map(|result| result.target_ref.entity_type.clone())
        .filter(|entity_type| !entity_type.is_empty());
    let target_ref_hash = first_result
        .map(|result| {
            hash_audit_handle(
                keys,
                "target",
                result.target_ref.entity_type.as_str(),
                None,
                &result.target_ref.handle,
            )
        })
        .transpose()?;
    let requester_type = first_result
        .and_then(|result| result.requester_ref.as_ref())
        .map(|requester| requester.entity_type.clone());
    let requester_ref_hash = first_result
        .and_then(|result| result.requester_ref.as_ref())
        .map(|requester| {
            hash_audit_handle(
                keys,
                "requester",
                requester.entity_type.as_str(),
                None,
                &requester.handle,
            )
        })
        .transpose()?;
    let profile_id = profile.map(|(profile_id, _)| profile_id);
    let holder_binding_mode = profile.map(|(_, profile)| profile.holder_binding.mode.as_str());
    let matching = first_result.and_then(|result| result.matching.as_ref());
    response.extensions_mut().insert(EvidenceAuditContext {
        verification_id: Some(evaluation_id.to_string()),
        verification_decision: Some("credential_denied".to_string()),
        claim_hash: (!evaluation.claim_ids.is_empty())
            .then(|| evidence_claim_hash(&evaluation.claim_ids)),
        purposes: Some(vec![evaluation.purpose.clone()]),
        row_count: None,
        access_mode: Some(AccessMode::SelfAttestation),
        denial_code: None,
        token_claim_name: None,
        credential_profile: profile_id.and_then(|value| ConfigMetadata::new(value).ok()),
        protocol: None,
        credential_configuration_id: None,
        holder_binding_mode: holder_binding_mode.and_then(|value| ConfigMetadata::new(value).ok()),
        rate_limit_bucket: None,
        policy_hash: evaluation
            .self_attestation
            .as_ref()
            .and_then(|metadata| metadata.policy_hash.clone()),
        target_type,
        target_ref_hash,
        requester_type,
        requester_ref_hash,
        matching_policy_id: matching.map(|matching| matching.policy_id.clone()),
        ecosystem_binding_id: matching.and_then(|matching| matching.ecosystem_binding_id.clone()),
        ecosystem_binding_version: matching
            .and_then(|matching| matching.ecosystem_binding_version.clone()),
        pack_id: matching.and_then(|matching| matching.pack_id.clone()),
        pack_version: matching.and_then(|matching| matching.pack_version.clone()),
        matching_method: matching.map(|matching| matching.method.clone()),
        matching_outcome: matching.map(|_| "matched".to_string()),
        matching_error_code: None,
        batch_items: None,
        ..EvidenceAuditContext::default()
    });
    Ok(())
}

pub(super) fn attach_self_attestation_credential_audit(
    response: &mut Response,
    keys: &SelfAttestationRateLimitKeys,
    evaluation_id: &str,
    claim_ids: &[String],
    results: &[ClaimResultView],
    row_count: u64,
    details: SelfAttestationCredentialAuditDetails<'_>,
) -> Result<(), EvidenceError> {
    let first_result = results.first();
    let target_type = first_result
        .map(|result| result.target_ref.entity_type.clone())
        .filter(|entity_type| !entity_type.is_empty());
    let target_ref_hash = first_result
        .map(|result| {
            hash_audit_handle(
                keys,
                "target",
                result.target_ref.entity_type.as_str(),
                None,
                &result.target_ref.handle,
            )
        })
        .transpose()?;
    let requester_type = first_result
        .and_then(|result| result.requester_ref.as_ref())
        .map(|requester| requester.entity_type.clone());
    let requester_ref_hash = first_result
        .and_then(|result| result.requester_ref.as_ref())
        .map(|requester| {
            hash_audit_handle(
                keys,
                "requester",
                requester.entity_type.as_str(),
                None,
                &requester.handle,
            )
        })
        .transpose()?;
    let matching = first_result.and_then(|result| result.matching.as_ref());
    response.extensions_mut().insert(EvidenceAuditContext {
        verification_id: Some(evaluation_id.to_string()),
        verification_decision: Some("credential_issued".to_string()),
        claim_hash: (!claim_ids.is_empty()).then(|| evidence_claim_hash(claim_ids)),
        purposes: details.purposes,
        row_count: Some(row_count),
        access_mode: Some(AccessMode::SelfAttestation),
        denial_code: None,
        token_claim_name: None,
        credential_profile: ConfigMetadata::new(details.profile_id).ok(),
        protocol: details
            .protocol
            .and_then(|value| ConfigMetadata::new(value).ok()),
        credential_configuration_id: details
            .credential_configuration_id
            .and_then(|value| ConfigMetadata::new(value).ok()),
        holder_binding_mode: ConfigMetadata::new(details.holder_binding_mode).ok(),
        rate_limit_bucket: None,
        policy_hash: details.policy_hash,
        target_type,
        target_ref_hash,
        requester_type,
        requester_ref_hash,
        matching_policy_id: matching.map(|matching| matching.policy_id.clone()),
        ecosystem_binding_id: matching.and_then(|matching| matching.ecosystem_binding_id.clone()),
        ecosystem_binding_version: matching
            .and_then(|matching| matching.ecosystem_binding_version.clone()),
        pack_id: matching.and_then(|matching| matching.pack_id.clone()),
        pack_version: matching.and_then(|matching| matching.pack_version.clone()),
        matching_method: matching.map(|matching| matching.method.clone()),
        matching_outcome: matching.map(|_| "matched".to_string()),
        matching_error_code: None,
        batch_items: None,
        ..EvidenceAuditContext::default()
    });
    Ok(())
}

pub(super) fn attach_self_attestation_success_audit(
    response: &mut Response,
    decision: &str,
    verification_id: Option<String>,
    claim_ids: &[String],
    row_count: Option<u64>,
    purposes: Option<Vec<String>>,
    policy_hash: Option<Hashed<PolicyIdentifier>>,
) {
    response.extensions_mut().insert(EvidenceAuditContext {
        verification_id,
        verification_decision: Some(decision.to_string()),
        claim_hash: (!claim_ids.is_empty()).then(|| evidence_claim_hash(claim_ids)),
        purposes,
        row_count,
        access_mode: Some(AccessMode::SelfAttestation),
        denial_code: None,
        token_claim_name: None,
        credential_profile: None,
        protocol: None,
        credential_configuration_id: None,
        holder_binding_mode: None,
        rate_limit_bucket: None,
        policy_hash,
        target_type: None,
        target_ref_hash: None,
        requester_type: None,
        requester_ref_hash: None,
        matching_policy_id: None,
        matching_method: None,
        matching_outcome: None,
        matching_error_code: None,
        batch_items: None,
        ..EvidenceAuditContext::default()
    });
}

pub(super) fn override_attestation_audit_access_mode(
    response: &mut Response,
    access_mode: AccessMode,
) {
    if let Some(audit) = response.extensions_mut().get_mut::<EvidenceAuditContext>() {
        audit.access_mode = Some(access_mode);
    }
}

pub(super) fn attach_self_attestation_audit(
    response: &mut Response,
    decision: &str,
    claim_ids: &[String],
    denial_code: Option<SelfAttestationDenialCode>,
    token_claim_name: Option<&str>,
) {
    response.extensions_mut().insert(EvidenceAuditContext {
        verification_id: None,
        verification_decision: Some(decision.to_string()),
        claim_hash: (!claim_ids.is_empty()).then(|| evidence_claim_hash(claim_ids)),
        purposes: None,
        row_count: None,
        access_mode: Some(AccessMode::SelfAttestation),
        denial_code,
        token_claim_name: token_claim_name.and_then(|name| ConfigMetadata::new(name).ok()),
        credential_profile: None,
        protocol: None,
        credential_configuration_id: None,
        holder_binding_mode: None,
        rate_limit_bucket: None,
        policy_hash: None,
        target_type: None,
        target_ref_hash: None,
        requester_type: None,
        requester_ref_hash: None,
        matching_policy_id: None,
        matching_method: None,
        matching_outcome: None,
        matching_error_code: None,
        batch_items: None,
        ..EvidenceAuditContext::default()
    });
}

pub(super) fn attach_oid4vci_self_attestation_denial_audit(
    response: &mut Response,
    decision: &str,
    claim_ids: &[String],
    credential_configuration_id: &str,
    denial_code: Option<SelfAttestationDenialCode>,
    token_claim_name: Option<&str>,
) {
    response.extensions_mut().insert(EvidenceAuditContext {
        verification_id: None,
        verification_decision: Some(decision.to_string()),
        claim_hash: (!claim_ids.is_empty()).then(|| evidence_claim_hash(claim_ids)),
        purposes: None,
        row_count: None,
        access_mode: Some(AccessMode::SelfAttestation),
        denial_code,
        token_claim_name: token_claim_name.and_then(|name| ConfigMetadata::new(name).ok()),
        credential_profile: None,
        protocol: ConfigMetadata::new("openid4vci").ok(),
        credential_configuration_id: ConfigMetadata::new(credential_configuration_id).ok(),
        holder_binding_mode: None,
        rate_limit_bucket: None,
        policy_hash: None,
        target_type: None,
        target_ref_hash: None,
        requester_type: None,
        requester_ref_hash: None,
        matching_policy_id: None,
        matching_method: None,
        matching_outcome: None,
        matching_error_code: None,
        batch_items: None,
        ..EvidenceAuditContext::default()
    });
}

pub(super) fn attach_self_attestation_rate_limit_audit(
    response: &mut Response,
    decision: &str,
    claim_ids: &[String],
    bucket: Option<SelfAttestationRateLimitBucket>,
) {
    response.extensions_mut().insert(EvidenceAuditContext {
        verification_id: None,
        verification_decision: Some(decision.to_string()),
        claim_hash: (!claim_ids.is_empty()).then(|| evidence_claim_hash(claim_ids)),
        purposes: None,
        row_count: None,
        access_mode: Some(AccessMode::SelfAttestation),
        denial_code: Some(SelfAttestationDenialCode::RateLimited),
        token_claim_name: None,
        credential_profile: None,
        protocol: None,
        credential_configuration_id: None,
        holder_binding_mode: None,
        rate_limit_bucket: bucket.and_then(|bucket| RateLimitBucket::new(bucket.as_str()).ok()),
        policy_hash: None,
        target_type: None,
        target_ref_hash: None,
        requester_type: None,
        requester_ref_hash: None,
        matching_policy_id: None,
        matching_method: None,
        matching_outcome: None,
        matching_error_code: None,
        batch_items: None,
        ..EvidenceAuditContext::default()
    });
}

pub(crate) fn evidence_error_response(error: EvidenceError) -> Response {
    let request_id = crate::standalone::current_request_correlation_id();
    evidence_error_response_with_request_id(error, request_id.as_ref())
}

pub(crate) fn evidence_error_response_with_request_id(
    error: EvidenceError,
    request_id: Option<&BoundedCorrelationId>,
) -> Response {
    let code = error.code().to_string();
    let audit_code = error.audit_code().to_string();
    let status = evidence_status(&error);
    let mut body = json!({
        "type": format!("{}/{}", crate::PROBLEM_TYPE_BASE_URL, code.replace('.', "/")),
        "title": evidence_title(&error),
        "status": status.as_u16(),
        "detail": evidence_detail(&error),
        "code": code,
    });
    if let Some(request_id) = request_id {
        body["request_id"] = json!(request_id.as_str());
    }
    let mut response = (status, Json(body)).into_response();
    response
        .extensions_mut()
        .insert(EvidenceErrorCodeContext(audit_code));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    if let EvidenceError::MachineQuotaExceeded {
        retry_after_seconds,
    } = &error
    {
        if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    if let Some(request_id) = request_id {
        if let Ok(value) = HeaderValue::from_str(request_id.as_str()) {
            response.headers_mut().insert("x-request-id", value);
        }
    }
    response
}

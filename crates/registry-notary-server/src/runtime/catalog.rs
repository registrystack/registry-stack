// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(crate) fn claim_ids(claims: &[ClaimRef]) -> Vec<String> {
    claims.iter().map(|claim| claim.id.clone()).collect()
}

pub(crate) fn requested_claim_versions(
    claims: &[ClaimRef],
) -> Result<ClaimVersionSelections, EvidenceError> {
    let mut versions = BTreeMap::new();
    for claim in claims {
        if claim.id.trim().is_empty()
            || claim
                .version
                .as_deref()
                .is_some_and(|version| version.trim().is_empty())
        {
            return Err(EvidenceError::InvalidRequest);
        }
        match versions.get(&claim.id) {
            Some(existing) => {
                if existing != &claim.version {
                    return Err(EvidenceError::InvalidRequest);
                }
            }
            None => {
                versions.insert(claim.id.clone(), claim.version.clone());
            }
        }
    }
    Ok(versions)
}

pub(crate) fn validate_batch_subject_limit(
    config: &EvidenceConfig,
    request: &BatchEvaluateRequest,
) -> Result<(), EvidenceError> {
    if request.claims.is_empty() || request.items.is_empty() {
        return Err(EvidenceError::InvalidRequest);
    }
    let claim_versions = requested_claim_versions(&request.claims)?;
    let max_subjects = max_batch_subjects(config, &request.claims, &claim_versions)?;
    if request.items.len() > max_subjects {
        return Err(EvidenceError::BatchTooLarge);
    }
    Ok(())
}

pub(super) fn find_claim_for_selection<'a>(
    config: &'a EvidenceConfig,
    claim_id: &str,
    versions: &ClaimVersionSelections,
) -> Result<&'a ClaimDefinition, EvidenceError> {
    match versions.get(claim_id).and_then(Option::as_deref) {
        Some(version) => find_claim_version(config, claim_id, version),
        None => find_claim(config, claim_id),
    }
}

/// Topological levels of the DAG closure over `requested`. Each level is the
/// set of claims whose dependencies all appear in earlier levels. Claims at
/// the same level are independent and safe to evaluate concurrently.
///
/// Cycle and unknown-dep validation already happened at config load; we still
/// guard with bounded iterations so a malformed config cannot infinite-loop.
pub(crate) fn build_claim_levels(
    evidence: &EvidenceConfig,
    requested: &[ClaimRef],
    claim_versions: &ClaimVersionSelections,
) -> Result<Vec<Vec<String>>, EvidenceError> {
    // Closure: starting from `requested`, accumulate every transitive dep.
    let mut closure: BTreeSet<String> = BTreeSet::new();
    let mut frontier: Vec<String> = claim_ids(requested);
    let mut edge_count = 0usize;
    while let Some(claim_id) = frontier.pop() {
        if !closure.insert(claim_id.clone()) {
            continue;
        }
        if closure.len() > MAX_CLAIM_DEPENDENCY_NODES_V1 {
            return Err(EvidenceError::RuleEvaluationFailed);
        }
        let claim = find_claim_for_selection(evidence, &claim_id, claim_versions)?;
        edge_count = edge_count
            .checked_add(claim.depends_on.len())
            .ok_or(EvidenceError::RuleEvaluationFailed)?;
        if edge_count > MAX_CLAIM_DEPENDENCY_EDGES_V1 {
            return Err(EvidenceError::RuleEvaluationFailed);
        }
        for dep in &claim.depends_on {
            if !closure.contains(dep) {
                frontier.push(dep.clone());
            }
        }
    }
    // Kahn-style level construction: a claim is ready when all its deps are
    // already in earlier levels.
    let mut placed: BTreeSet<String> = BTreeSet::new();
    let mut levels: Vec<Vec<String>> = Vec::new();
    let total = closure.len();
    while placed.len() < total {
        let mut next_level: Vec<String> = Vec::new();
        for claim_id in &closure {
            if placed.contains(claim_id) {
                continue;
            }
            let claim = find_claim_for_selection(evidence, claim_id, claim_versions)?;
            if claim.depends_on.iter().all(|dep| placed.contains(dep)) {
                next_level.push(claim_id.clone());
            }
        }
        if next_level.is_empty() {
            // Should never happen: cycle detection runs at config load.
            return Err(EvidenceError::RuleEvaluationFailed);
        }
        for claim_id in &next_level {
            placed.insert(claim_id.clone());
        }
        levels.push(next_level);
    }
    Ok(levels)
}

pub fn find_claim<'a>(
    config: &'a EvidenceConfig,
    claim_id: &str,
) -> Result<&'a ClaimDefinition, EvidenceError> {
    config
        .claims
        .iter()
        .find(|claim| claim.id == claim_id)
        .ok_or(EvidenceError::ClaimNotFound)
}

pub fn find_claim_version<'a>(
    config: &'a EvidenceConfig,
    claim_id: &str,
    version: &str,
) -> Result<&'a ClaimDefinition, EvidenceError> {
    let mut has_claim_id = false;
    for claim in &config.claims {
        if claim.id == claim_id {
            has_claim_id = true;
            if claim.version == version {
                return Ok(claim);
            }
        }
    }
    if has_claim_id {
        Err(EvidenceError::ClaimVersionNotFound)
    } else {
        Err(EvidenceError::ClaimNotFound)
    }
}

pub fn claim_summary(claim: &ClaimDefinition) -> Value {
    // Only publish the oots block when oots is explicitly enabled. When disabled,
    // the sub-fields (requirement, LoA, etc.) are intentionally not advertised,
    // so emitting them as null would be misleading.
    let oots = claim
        .oots
        .as_ref()
        .filter(|o| o.enabled)
        .map(|o| serde_json::to_value(o).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    let mut summary = json!({
        "id": claim.id,
        "title": claim.title,
        "version": claim.version,
        "subject_type": claim.subject_type,
        "operations": {
            "evaluate": claim.operations.evaluate.enabled,
            "batch_evaluate": claim.operations.batch_evaluate.enabled,
        },
        "formats": claim.formats,
        "disclosure": {
            "default": claim.disclosure.default,
            "allowed": claim.disclosure.allowed,
            "downgrade": claim.disclosure.downgrade,
        },
        "cccev": claim.cccev,
        "oots": oots,
    });
    if let Some(semantics) = claim_semantics_metadata(claim) {
        summary["semantics"] = semantics;
    }
    let target_inputs = claim_target_inputs(claim);
    if !target_inputs.is_empty() {
        summary["target_inputs"] = json!(target_inputs);
    }
    if let Some(cccev) = &claim.cccev {
        if let Some(evidence_type) = &cccev.evidence_type {
            summary["evidence_type"] = json!(evidence_type);
        }
        if let Some(evidence_type_iri) = &cccev.evidence_type_iri {
            summary["evidence_type_iri"] = json!(evidence_type_iri);
        }
    }
    summary
}

pub(crate) fn claim_semantics_metadata(claim: &ClaimDefinition) -> Option<Value> {
    let semantics = claim
        .semantics
        .as_ref()
        .and_then(|semantics| serde_json::to_value(semantics).ok())
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();

    (!semantics.is_empty()).then_some(Value::Object(semantics))
}

pub(super) fn claim_target_inputs(claim: &ClaimDefinition) -> Vec<Value> {
    let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
        return Vec::new();
    };
    consultations
        .values()
        .filter_map(|consultation| {
            let mut inputs = consultation
                .inputs
                .values()
                .filter_map(|input| public_target_input(input.request_context_path()))
                .collect::<Vec<_>>();
            inputs.sort_by_key(ToString::to_string);
            inputs.dedup();
            (!inputs.is_empty()).then(|| {
                json!({
                    "target_type": claim.subject_type,
                    "method": "relay_consultation",
                    "confidence": "contract_pinned",
                    "groups": [{ "inputs": inputs }],
                })
            })
        })
        .collect()
}

pub(super) fn public_target_input(path: &str) -> Option<Value> {
    let (kind, name, label) = if path == "target.id" {
        ("id", "id", "ID".to_string())
    } else {
        let (kind, name) = path
            .strip_prefix("target.identifiers.")
            .map(|name| ("identifier", name))
            .or_else(|| {
                path.strip_prefix("target.attributes.")
                    .map(|name| ("attribute", name))
            })?;
        if name.is_empty() || name.contains('*') {
            return None;
        }
        (kind, name, input_label(name))
    };
    Some(json!({
        "path": path,
        "kind": kind,
        "name": name,
        "label": label,
    }))
}

pub(super) fn input_label(name: &str) -> String {
    let mut label = String::new();
    for (index, part) in name.split('_').filter(|part| !part.is_empty()).enumerate() {
        if !label.is_empty() {
            label.push(' ');
        }
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            if index == 0 {
                label.extend(first.to_uppercase());
            } else {
                label.push(first);
            }
            label.push_str(chars.as_str());
        }
    }
    if label.is_empty() {
        name.to_string()
    } else {
        label
    }
}

pub fn formats(config: &EvidenceConfig) -> Vec<EvidenceFormat> {
    let mut seen = BTreeMap::new();
    seen.insert(FORMAT_CLAIM_RESULT_JSON.to_string(), true);
    seen.insert(FORMAT_CCCEV_JSONLD.to_string(), true);
    seen.insert(
        FORMAT_SD_JWT_VC.to_string(),
        !config.credential_profiles.is_empty(),
    );
    for claim in &config.claims {
        for format in &claim.formats {
            seen.entry(format.clone()).or_insert(true);
        }
    }
    seen.into_iter()
        .map(|(id, enabled)| EvidenceFormat {
            kind: format_kind(&id).to_string(),
            status: if enabled { "enabled" } else { "disabled" }.to_string(),
            id,
        })
        .collect()
}

pub(super) fn format_kind(format: &str) -> &'static str {
    match format {
        FORMAT_CLAIM_RESULT_JSON => "claim_result",
        FORMAT_SD_JWT_VC => "credential",
        _ => "renderer",
    }
}

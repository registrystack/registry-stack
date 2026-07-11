use super::*;

pub(in super::super) fn registry_data_api_url(
    base_url: &str,
    binding: &SourceBindingConfig,
) -> Result<reqwest::Url, EvidenceError> {
    let base = reqwest::Url::parse(base_url).map_err(|_| EvidenceError::SourceUnavailable)?;
    httputil_url::append_path_segments(
        &base,
        &[
            "v1",
            "datasets",
            binding.dataset.as_str(),
            "entities",
            binding.entity.as_str(),
            "records",
        ],
    )
    .map_err(|_| EvidenceError::SourceUnavailable)
}

pub(in super::super) fn value_query_string(value: &Value) -> Result<String, EvidenceError> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err(EvidenceError::InvalidRequest),
    }
}

pub(in super::super) fn registry_data_api_query_pair(
    query_value: &SourceQueryValue,
) -> Result<(String, String), EvidenceError> {
    let name = match query_value.op.as_str() {
        "eq" => query_value.field.clone(),
        "in" => format!("{}.in", query_value.field),
        "ge" | "gte" => format!("{}.gte", query_value.field),
        "le" | "lte" => format!("{}.lte", query_value.field),
        "between" => format!("{}.between", query_value.field),
        _ => return Err(EvidenceError::InvalidRequest),
    };
    let value = match query_value.op.as_str() {
        "in" | "between" => value_query_csv(&query_value.value)?,
        _ => value_query_string(&query_value.value)?,
    };
    Ok((name, value))
}

pub(in super::super) fn value_query_csv(value: &Value) -> Result<String, EvidenceError> {
    let values = match value {
        Value::Array(values) => values,
        _ => return value_query_string(value),
    };
    if values.is_empty() {
        return Err(EvidenceError::InvalidRequest);
    }
    let parts = values
        .iter()
        .map(value_query_string)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(parts.join(","))
}

pub(in super::super) fn lookup_value(
    binding: &SourceBindingConfig,
    subject: &SubjectRequest,
) -> Result<Value, EvidenceError> {
    if binding.lookup.op != "eq" {
        return Err(EvidenceError::InvalidRequest);
    }
    match binding.lookup.input.as_str() {
        "target.id" if subject.id_type.is_none() => Ok(Value::String(subject.id.clone())),
        input
            if input.starts_with("target.identifiers.")
                && subject.id_type.as_deref() == input.strip_prefix("target.identifiers.") =>
        {
            Ok(Value::String(subject.id.clone()))
        }
        _ => Err(EvidenceError::InvalidRequest),
    }
}

pub(in super::super) fn lookup_value_for_context(
    binding: &SourceBindingConfig,
    context: &EvidenceRequestContext,
) -> Result<Value, EvidenceError> {
    if binding.lookup.op != "eq" {
        return Err(EvidenceError::InvalidRequest);
    }
    match context.lookup_value(binding.lookup.input.as_str()) {
        Some(value) => Ok(value),
        None => Err(registry_notary_core::missing_context_error(
            binding.lookup.input.as_str(),
        )),
    }
}

pub(in super::super) fn canonical_subject_bindings(
    bindings: &[(SourceBindingConfig, EvidenceRequestContext)],
) -> Option<Vec<(SourceBindingConfig, SubjectRequest)>> {
    let mut subject_bindings = Vec::with_capacity(bindings.len());
    for (binding, context) in bindings {
        if context.requester.is_some()
            || context.relationship.is_some()
            || context.on_behalf_of.is_some()
        {
            return None;
        }
        let subject = context.target_subject()?;
        match binding.lookup.input.as_str() {
            "target.id" if subject.id_type.is_none() => {}
            input
                if input.starts_with("target.identifiers.")
                    && subject.id_type.as_deref() == input.strip_prefix("target.identifiers.") => {}
            _ => return None,
        }
        subject_bindings.push((binding.clone(), subject));
    }
    Some(subject_bindings)
}

pub(in super::super) fn collect_claim_required_scopes(
    evidence: &EvidenceConfig,
    claim_id: &str,
    scopes: &mut Vec<String>,
) -> Result<(), EvidenceError> {
    let claim = crate::find_claim(evidence, claim_id)?;
    collect_claim_required_scopes_for_claim(evidence, claim, scopes)
}

pub(in super::super) fn collect_claim_required_scopes_for_claim(
    evidence: &EvidenceConfig,
    claim: &registry_notary_core::ClaimDefinition,
    scopes: &mut Vec<String>,
) -> Result<(), EvidenceError> {
    for binding in claim.source_bindings.values() {
        if let Some(scope) = binding.required_scope.as_deref() {
            scopes.push(scope.to_string());
        } else {
            scopes.push(format!("{}:evidence_verification", binding.dataset));
        }
    }
    for dep in &claim.depends_on {
        collect_claim_required_scopes(evidence, dep, scopes)?;
    }
    Ok(())
}

pub(in super::super) fn projected_source_fields_with_lookup(
    binding: &SourceBindingConfig,
    lookup_field: &str,
) -> Vec<String> {
    let mut fields = vec![lookup_field.to_string()];
    for field in binding.fields.values() {
        fields.push(field.field.clone());
    }
    if let Some(source_observed_at_field) = binding.matching.source_observed_at_field.as_ref() {
        fields.push(source_observed_at_field.clone());
    }
    fields.sort();
    fields.dedup();
    fields
}

pub(in super::super) fn projected_source_fields_with_query_values(
    binding: &SourceBindingConfig,
    query_values: &[SourceQueryValue],
) -> Vec<String> {
    let mut fields = query_values
        .iter()
        .map(|value| value.field.clone())
        .collect::<Vec<_>>();
    for field in binding.fields.values() {
        fields.push(field.field.clone());
    }
    if let Some(source_observed_at_field) = binding.matching.source_observed_at_field.as_ref() {
        fields.push(source_observed_at_field.clone());
    }
    fields.sort();
    fields.dedup();
    fields
}

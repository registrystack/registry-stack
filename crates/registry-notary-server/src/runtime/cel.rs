// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) async fn evaluate_cel_expression(
    ctx: &CelEvaluationContext<'_>,
) -> Result<Value, EvidenceError> {
    #[cfg(feature = "registry-notary-cel")]
    let config = ctx.config;
    #[cfg(not(feature = "registry-notary-cel"))]
    let config = &RegistryNotaryCelConfig::default();
    validate_cel_policy(ctx.expression, ctx.bindings, ctx.claim, config)?;
    #[cfg(feature = "registry-notary-cel")]
    {
        evaluate_with_cel(ctx).await
    }
    #[cfg(not(feature = "registry-notary-cel"))]
    {
        let _ = ctx;
        Err(EvidenceError::OperationUnsupported)
    }
}

#[cfg(feature = "registry-notary-cel")]
pub(crate) fn validate_cel_claims_for_startup(
    evidence: &EvidenceConfig,
    config: &RegistryNotaryCelConfig,
) -> Result<(), EvidenceError> {
    let mut runtime = MappingRuntime::new(RuntimeOptions::default());
    runtime.limits = cel_security_limits(config);
    for claim in &evidence.claims {
        let RuleConfig::Cel {
            expression,
            bindings,
        } = &claim.rule
        else {
            continue;
        };
        validate_cel_policy(expression, bindings, claim, config)?;
        validate_cel_expression_roots(expression)?;
        if !config.allow_regex && cel_expression_uses_regex(expression) {
            return Err(EvidenceError::InvalidRequest);
        }
        let input = StandaloneExpressionInput::new(
            cel_preflight_root_bindings(evidence, claim, bindings)
                .into_iter()
                .collect(),
        );
        let preview = runtime.preview_cel_expression_with_input(expression, input);
        if preview
            .issues
            .iter()
            .any(|issue| issue.severity == ErrorSeverity::Error)
        {
            return Err(EvidenceError::InvalidRequest);
        }
        if let Some(value) = preview.value.as_ref() {
            validate_claim_value_type(value, &claim.value.value_type)?;
        }
    }
    Ok(())
}

pub(super) fn validate_cel_policy(
    expression: &str,
    bindings: &CelBindingsConfig,
    claim: &ClaimDefinition,
    _config: &RegistryNotaryCelConfig,
) -> Result<(), EvidenceError> {
    if expression.trim().is_empty() {
        return Err(EvidenceError::InvalidRequest);
    }
    #[cfg(feature = "registry-notary-cel")]
    {
        cel_security_limits(_config)
            .check_expr(expression)
            .map_err(|_| EvidenceError::InvalidRequest)?;
        if bindings.claims.len() > MAX_CEL_CLAIM_BINDINGS
            || bindings.vars.len() > MAX_CEL_VAR_BINDINGS
        {
            return Err(EvidenceError::InvalidRequest);
        }
        for (alias, binding) in &bindings.claims {
            if !is_cel_identifier(alias) || !claim.depends_on.contains(&binding.claim) {
                return Err(EvidenceError::InvalidRequest);
            }
        }
        for alias in bindings.vars.keys() {
            if !is_cel_identifier(alias) {
                return Err(EvidenceError::InvalidRequest);
            }
        }
    }
    #[cfg(not(feature = "registry-notary-cel"))]
    {
        let _ = (expression, bindings, claim);
    }
    Ok(())
}

pub(super) fn validate_claim_value_type(
    value: &Value,
    value_type: &str,
) -> Result<(), EvidenceError> {
    let valid = match value_type.trim() {
        "" | "unknown" => true,
        "boolean" | "bool" => value.is_boolean(),
        "number" | "float" | "double" => value.is_number(),
        "integer" | "int" => value.as_i64().is_some() || value.as_u64().is_some(),
        "string" | "date" | "datetime" | "date-time" | "uri" => value.is_string(),
        "array" | "list" => value.is_array(),
        "object" => value.is_object(),
        "null" => value.is_null(),
        _ => return Err(EvidenceError::InvalidRequest),
    };
    if valid {
        Ok(())
    } else {
        Err(EvidenceError::RuleEvaluationFailed)
    }
}

#[cfg(feature = "registry-notary-cel")]
pub(super) async fn evaluate_with_cel(
    ctx: &CelEvaluationContext<'_>,
) -> Result<Value, EvidenceError> {
    let root_bindings = cel_root_bindings(ctx)?;
    let value = if let Some(worker) = ctx.worker {
        worker
            .evaluate(
                ctx.expression,
                Value::Object(root_bindings.into_iter().collect()),
            )
            .await
            .map_err(cel_worker_error)?
    } else {
        #[cfg(test)]
        {
            evaluate_cel_in_process_for_unit_tests(ctx.expression, root_bindings)?
        }
        #[cfg(not(test))]
        {
            return Err(EvidenceError::OperationUnsupported);
        }
    };
    validate_cel_result_limits(&value, ctx.config)?;
    Ok(value)
}

#[cfg(feature = "registry-notary-cel")]
#[cfg(test)]
pub(super) fn evaluate_cel_in_process_for_unit_tests(
    expression: &str,
    root_bindings: BTreeMap<String, Value>,
) -> Result<Value, EvidenceError> {
    MappingRuntime::new(RuntimeOptions::default())
        .evaluate_cel_expression_with_input(
            expression,
            StandaloneExpressionInput::new(root_bindings.into_iter().collect()),
        )
        .map_err(|error| match error {
            crosswalk_core::StandaloneEvalError::Compile(_)
            | crosswalk_core::StandaloneEvalError::InvalidBindingName { .. } => {
                EvidenceError::InvalidRequest
            }
            crosswalk_core::StandaloneEvalError::Evaluate { .. } => {
                EvidenceError::RuleEvaluationFailed
            }
        })
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn cel_preflight_root_bindings(
    evidence: &EvidenceConfig,
    claim: &ClaimDefinition,
    bindings: &CelBindingsConfig,
) -> BTreeMap<String, Value> {
    let mut sources = Map::new();
    for (alias, binding) in &claim.source_bindings {
        let mut source = Map::new();
        for (field_alias, field) in &binding.fields {
            source.insert(
                field_alias.clone(),
                cel_dummy_value_for_type(field.field_type.as_deref().unwrap_or("string")),
            );
        }
        sources.insert(alias.clone(), Value::Object(source));
    }

    let mut claims = Map::new();
    for (alias, binding) in &bindings.claims {
        let value_type = evidence
            .claims
            .iter()
            .find(|candidate| candidate.id == binding.claim)
            .map(|candidate| candidate.value.value_type.as_str())
            .unwrap_or("boolean");
        let value = cel_dummy_value_for_type(value_type);
        claims.insert(
            alias.clone(),
            json!({
                "value": value,
                "satisfied": value.as_bool().unwrap_or(true),
                "claim_id": binding.claim,
                "version": "preflight",
            }),
        );
    }

    BTreeMap::from([
        ("source".to_string(), Value::Object(sources)),
        ("claims".to_string(), Value::Object(claims)),
        (
            "ctx".to_string(),
            json!({
                "purpose": "preflight",
                "subject": { "id": "preflight-subject" },
                "target": {
                    "type": "Person",
                    "id": "preflight-subject"
                },
                "today": "2026-06-16",
            }),
        ),
        (
            "vars".to_string(),
            Value::Object(bindings.vars.clone().into_iter().collect()),
        ),
        ("meta".to_string(), cel_meta(evidence, claim)),
    ])
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn cel_dummy_value_for_type(value_type: &str) -> Value {
    match value_type {
        "boolean" | "bool" => Value::Bool(true),
        "number" | "float" | "double" => json!(1.0),
        "integer" | "int" => json!(1),
        "date" => json!("2000-01-01"),
        "datetime" | "date-time" => json!("2000-01-01T00:00:00Z"),
        "array" | "list" => json!([]),
        "object" => json!({}),
        "null" => Value::Null,
        _ => json!("preflight"),
    }
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn validate_cel_expression_roots(expression: &str) -> Result<(), EvidenceError> {
    for root in cel_root_references(expression) {
        if !matches!(
            root.as_str(),
            "source" | "claims" | "ctx" | "vars" | "meta" | "date" | "person"
        ) {
            return Err(EvidenceError::InvalidRequest);
        }
    }
    Ok(())
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn cel_root_references(expression: &str) -> BTreeSet<String> {
    let bytes = expression.as_bytes();
    let mut roots = BTreeSet::new();
    let mut index = 0;
    let mut quote: Option<u8> = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(active_quote) = quote {
            if byte == b'\\' {
                index = index.saturating_add(2);
                continue;
            }
            if byte == active_quote {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
            index += 1;
            continue;
        }
        if !is_cel_identifier_start_byte(byte) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && is_cel_identifier_continue_byte(bytes[index]) {
            index += 1;
        }
        let mut lookahead = index;
        while lookahead < bytes.len() && bytes[lookahead].is_ascii_whitespace() {
            lookahead += 1;
        }
        let previous = start
            .checked_sub(1)
            .and_then(|previous| bytes.get(previous))
            .copied();
        let is_member = previous == Some(b'.');
        let is_root = matches!(bytes.get(lookahead), Some(b'.' | b'[')) && !is_member;
        if is_root {
            roots.insert(expression[start..index].to_string());
        }
    }
    roots
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn is_cel_identifier_start_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn is_cel_identifier_continue_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn cel_root_bindings(
    ctx: &CelEvaluationContext<'_>,
) -> Result<BTreeMap<String, Value>, EvidenceError> {
    let mut claim_values = Map::new();
    for (alias, binding) in &ctx.bindings.claims {
        let result = ctx
            .claims
            .get(&binding.claim)
            .ok_or(EvidenceError::RuleEvaluationFailed)?;
        let value = cel_project_claim_value(ctx, &binding.claim, result)?;
        let satisfied = value.as_ref().and_then(Value::as_bool);
        claim_values.insert(
            alias.clone(),
            json!({
                "value": value,
                "satisfied": satisfied,
                "claim_id": result.claim_id,
                "version": result.claim_version,
            }),
        );
    }
    let subject = ctx
        .subject
        .map(|subject| json!({ "id": subject.id }))
        .unwrap_or(Value::Null);
    let target =
        serde_json::to_value(ctx.target).map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    let root_bindings = BTreeMap::from([
        (
            "source".to_string(),
            Value::Object(ctx.sources.clone().into_iter().collect()),
        ),
        ("claims".to_string(), Value::Object(claim_values)),
        (
            "ctx".to_string(),
            json!({
                "purpose": ctx.purpose,
                "subject": subject,
                "target": target,
                "today": ctx.today,
            }),
        ),
        (
            "vars".to_string(),
            Value::Object(ctx.bindings.vars.clone().into_iter().collect()),
        ),
        ("meta".to_string(), cel_meta(ctx.evidence, ctx.claim)),
    ]);
    validate_cel_binding_limits(
        &Value::Object(root_bindings.clone().into_iter().collect()),
        ctx.config,
    )?;
    Ok(root_bindings)
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn cel_project_claim_value(
    ctx: &CelEvaluationContext<'_>,
    claim_id: &str,
    result: &ClaimResultInternal,
) -> Result<Option<Value>, EvidenceError> {
    if result.redaction_fields.is_empty() {
        return Ok(Some(result.value.clone()));
    }
    let claim = find_claim_version(ctx.evidence, claim_id, &result.claim_version)?;
    if supports_object_field_redaction(claim.value.value_type.as_str(), &result.redaction_fields) {
        return redact_object_fields(&result.value, &result.redaction_fields);
    }
    Ok(None)
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn cel_worker_error(error: CelWorkerError) -> EvidenceError {
    match error {
        CelWorkerError::Compile | CelWorkerError::Protocol => EvidenceError::InvalidRequest,
        CelWorkerError::Evaluate | CelWorkerError::Harness(_) => {
            EvidenceError::RuleEvaluationFailed
        }
    }
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn validate_cel_binding_limits(
    value: &Value,
    config: &RegistryNotaryCelConfig,
) -> Result<(), EvidenceError> {
    if serialized_json_len(value)? > config.max_binding_json_bytes {
        return Err(EvidenceError::RuleEvaluationFailed);
    }
    let mut stack = vec![(value, 0_usize)];
    while let Some((value, depth)) = stack.pop() {
        if depth > config.max_object_depth {
            return Err(EvidenceError::RuleEvaluationFailed);
        }
        match value {
            Value::String(value) if value.len() > config.max_string_bytes => {
                return Err(EvidenceError::RuleEvaluationFailed);
            }
            Value::Array(values) => {
                if values.len() > config.max_list_items {
                    return Err(EvidenceError::RuleEvaluationFailed);
                }
                for value in values {
                    stack.push((value, depth + 1));
                }
            }
            Value::Object(values) => {
                if values.len() > config.max_object_keys {
                    return Err(EvidenceError::RuleEvaluationFailed);
                }
                for value in values.values() {
                    stack.push((value, depth + 1));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn validate_cel_result_limits(
    value: &Value,
    config: &RegistryNotaryCelConfig,
) -> Result<(), EvidenceError> {
    validate_cel_binding_limits(value, config)?;
    if serialized_json_len(value)? > config.max_result_json_bytes {
        return Err(EvidenceError::RuleEvaluationFailed);
    }
    Ok(())
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn serialized_json_len(value: &Value) -> Result<usize, EvidenceError> {
    struct CountingWriter {
        count: usize,
    }

    impl std::io::Write for CountingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.count = self
                .count
                .checked_add(buf.len())
                .ok_or_else(|| std::io::Error::other("serialized JSON length overflow"))?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut writer = CountingWriter { count: 0 };
    serde_json::to_writer(&mut writer, value).map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    Ok(writer.count)
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn cel_security_limits(config: &RegistryNotaryCelConfig) -> SecurityLimits {
    SecurityLimits {
        max_expression_bytes: config.max_expression_bytes,
        max_output_json_bytes: config.max_result_json_bytes,
        max_list_len: config.max_list_items,
        max_string_bytes: config.max_string_bytes,
        ..SecurityLimits::default()
    }
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn is_cel_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn cel_meta(evidence: &EvidenceConfig, claim: &ClaimDefinition) -> Value {
    let mut sources = Map::new();
    for (alias, binding) in &claim.source_bindings {
        let connector = match binding.connector {
            registry_notary_core::config::SourceConnectorKind::RegistryDataApi => {
                "registry_data_api"
            }
            registry_notary_core::config::SourceConnectorKind::Dci => "dci",
            registry_notary_core::config::SourceConnectorKind::SourceAdapterSidecar => {
                "source_adapter_sidecar"
            }
        };
        sources.insert(
            alias.clone(),
            json!({
                "dataset": binding.dataset,
                "entity": binding.entity,
                "connector": connector,
            }),
        );
    }
    json!({
        "service_id": evidence.service_id,
        "api_version": evidence.api_version,
        "claim": {
            "id": claim.id,
            "version": claim.version,
            "subject_type": claim.subject_type,
        },
        "sources": sources,
    })
}

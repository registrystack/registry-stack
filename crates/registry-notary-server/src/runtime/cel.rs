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
        if claim.evidence_mode.is_registry_backed() {
            validate_registry_cel_expression(expression, claim)?;
        } else {
            validate_cel_expression_roots(expression)?;
        }
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
            validate_claim_value_config(value, &claim.value)?;
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
        "integer" | "int" => {
            const MAX_SAFE_INTEGER: i64 = (1_i64 << 53) - 1;
            value
                .as_i64()
                .is_some_and(|value| (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value))
                || value
                    .as_u64()
                    .is_some_and(|value| value <= MAX_SAFE_INTEGER as u64)
        }
        "date" => value.as_str().is_some_and(is_rfc3339_full_date),
        "string" | "datetime" | "date-time" | "uri" => value.is_string(),
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

pub(super) fn validate_claim_value_config(
    value: &Value,
    config: &registry_notary_core::ClaimValueConfig,
) -> Result<(), EvidenceError> {
    if value.is_null() {
        return config
            .nullable
            .then_some(())
            .ok_or(EvidenceError::RuleEvaluationFailed);
    }
    validate_claim_value_type(value, &config.value_type)?;
    if config.max_bytes.is_some_and(|max_bytes| {
        value
            .as_str()
            .is_none_or(|string| string.len() > max_bytes as usize)
    }) {
        return Err(EvidenceError::RuleEvaluationFailed);
    }
    Ok(())
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
    if let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode {
        let mut roots = BTreeMap::new();
        if let Some((name, consultation)) = consultations.first_key_value() {
            let mut output_view = consultation
                .outputs
                .iter()
                .filter(|(_, output)| output.is_scalar())
                .map(|(name, output)| (name.clone(), registry_output_dummy_value(output)))
                .collect::<Map<_, _>>();
            output_view.insert("matched".to_string(), Value::Bool(true));
            output_view.insert("outcome".to_string(), Value::String("match".to_string()));
            roots.insert(name.clone(), Value::Object(output_view));
        }
        for (name, variable) in &evidence.variables {
            let value = match variable.value_type {
                registry_notary_core::RequestVariableType::Date => json!("2026-01-01"),
            };
            roots.insert(name.clone(), value);
        }
        return roots;
    }
    let sources = Map::new();

    let mut claims = Map::new();
    for (alias, binding) in &bindings.claims {
        let value = evidence
            .claims
            .iter()
            .find(|candidate| candidate.id == binding.claim)
            .map(|candidate| cel_dummy_value_for_config(&candidate.value))
            .unwrap_or(Value::Bool(true));
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
fn registry_output_dummy_value(output: &registry_notary_core::RelayOutputContract) -> Value {
    match output {
        registry_notary_core::RelayOutputContract::Boolean { .. } => Value::Bool(true),
        registry_notary_core::RelayOutputContract::Integer { minimum, .. } => json!(minimum),
        registry_notary_core::RelayOutputContract::String { max_bytes, .. } => {
            bounded_string_preview(Some(*max_bytes))
        }
        registry_notary_core::RelayOutputContract::Date { .. } => json!("2000-01-01"),
        registry_notary_core::RelayOutputContract::Object { fields, .. } => Value::Object(
            fields
                .iter()
                .filter(|(_, field)| field.required)
                .map(|(name, field)| {
                    (
                        name.clone(),
                        registry_output_dummy_value(field.schema.as_ref()),
                    )
                })
                .collect(),
        ),
        registry_notary_core::RelayOutputContract::Array { .. } => Value::Array(Vec::new()),
    }
}

#[cfg(feature = "registry-notary-cel")]
fn cel_dummy_value_for_config(config: &registry_notary_core::ClaimValueConfig) -> Value {
    match config.value_type.as_str() {
        "boolean" | "bool" => Value::Bool(true),
        "number" | "float" | "double" => json!(1.0),
        "integer" | "int" => json!(1),
        "date" => json!("2000-01-01"),
        "datetime" | "date-time" | "string" | "uri" | "" | "unknown" => {
            bounded_string_preview(config.max_bytes)
        }
        "array" | "list" => json!([]),
        "object" => json!({}),
        "null" => Value::Null,
        _ => bounded_string_preview(config.max_bytes),
    }
}

#[cfg(feature = "registry-notary-cel")]
fn bounded_string_preview(max_bytes: Option<u32>) -> Value {
    Value::String(if max_bytes == Some(0) {
        String::new()
    } else {
        "x".to_string()
    })
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
fn validate_registry_cel_expression(
    expression: &str,
    claim: &ClaimDefinition,
) -> Result<(), EvidenceError> {
    if contains_unquoted_bracket(expression) {
        return Err(EvidenceError::InvalidRequest);
    }
    let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
        return Err(EvidenceError::InvalidRequest);
    };
    let (consultation_name, consultation) = consultations
        .first_key_value()
        .filter(|_| consultations.len() == 1)
        .ok_or(EvidenceError::InvalidRequest)?;
    for root in cel_root_references(expression) {
        if root != *consultation_name && root != "date" {
            return Err(EvidenceError::InvalidRequest);
        }
    }
    let referenced_members = cel_first_level_member_references(expression, consultation_name);
    if referenced_members.iter().any(|member| {
        consultation
            .outputs
            .get(member)
            .is_none_or(|output| !output.is_scalar())
            && !matches!(member.as_str(), "matched" | "outcome")
    }) {
        return Err(EvidenceError::InvalidRequest);
    }
    let compact = expression
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(char::from)
        .collect::<String>();
    for (name, output) in &consultation.outputs {
        if !output.nullable() {
            continue;
        }
        let path = format!("{consultation_name}.{name}");
        if !referenced_members.contains(name) {
            continue;
        }
        let left_guard = format!("{path}!=null");
        let right_guard = format!("null!={path}");
        let guard_index = compact
            .find(&left_guard)
            .or_else(|| compact.find(&right_guard))
            .ok_or(EvidenceError::InvalidRequest)?;
        let question_index = compact.find('?').ok_or(EvidenceError::InvalidRequest)?;
        if guard_index > question_index || compact[..guard_index].contains(&path) {
            return Err(EvidenceError::InvalidRequest);
        }
    }
    Ok(())
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn cel_first_level_member_references(expression: &str, root: &str) -> BTreeSet<String> {
    let tokens = cel_tokens(expression);
    let mut members = BTreeSet::new();

    for (index, token) in tokens.iter().enumerate() {
        let CelToken::Identifier { text } = token else {
            continue;
        };
        if *text != root || matches!(previous_token(&tokens, index), Some(CelToken::Dot)) {
            continue;
        }
        if let Some([CelToken::Dot, CelToken::Identifier { text: member }]) =
            next_tokens::<2>(&tokens, index)
        {
            members.insert((*member).to_string());
        }
    }
    members
}

pub(super) fn registry_cel_required_variables<'a>(
    expression: &str,
    declared: impl IntoIterator<Item = &'a str>,
) -> BTreeSet<String> {
    let identifiers = cel_bare_identifiers(expression);
    declared
        .into_iter()
        .filter(|name| identifiers.contains(*name))
        .map(str::to_string)
        .collect()
}

fn cel_bare_identifiers(expression: &str) -> BTreeSet<String> {
    let tokens = cel_tokens(expression);
    tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| match token {
            CelToken::Identifier { text }
                if !matches!(previous_token(&tokens, index), Some(CelToken::Dot)) =>
            {
                Some((*text).to_string())
            }
            _ => None,
        })
        .collect()
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn contains_unquoted_bracket(expression: &str) -> bool {
    cel_tokens(expression)
        .iter()
        .any(|token| matches!(token, CelToken::Bracket))
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn cel_root_references(expression: &str) -> BTreeSet<String> {
    let tokens = cel_tokens(expression);
    tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| match token {
            CelToken::Identifier { text } => {
                let is_root = matches!(
                    next_token(&tokens, index),
                    Some(CelToken::Dot | CelToken::Bracket)
                ) && !matches!(previous_token(&tokens, index), Some(CelToken::Dot));
                is_root.then(|| (*text).to_string())
            }
            CelToken::Dot | CelToken::Bracket | CelToken::Other => None,
        })
        .collect()
}

#[derive(Clone, Copy)]
enum CelToken<'a> {
    Identifier { text: &'a str },
    Dot,
    Bracket,
    Other,
}

fn cel_tokens(expression: &str) -> Vec<CelToken<'_>> {
    let bytes = expression.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes.get(index..index + 2) == Some(b"//") {
            index = skip_line_comment(bytes, index + 2);
            continue;
        }
        if let Some(end) = cel_string_literal_end(bytes, index) {
            tokens.push(CelToken::Other);
            index = end;
            continue;
        }
        if bytes[index] == b'`' {
            tokens.push(CelToken::Other);
            index = escaped_identifier_end(bytes, index);
            continue;
        }
        if bytes[index] == b'.' {
            tokens.push(CelToken::Dot);
            index += 1;
            continue;
        }
        if matches!(bytes[index], b'[' | b']') {
            tokens.push(CelToken::Bracket);
            index += 1;
            continue;
        }
        if is_cel_identifier_start_byte(bytes[index]) {
            let start = index;
            index = identifier_end(bytes, start);
            tokens.push(CelToken::Identifier {
                text: &expression[start..index],
            });
            continue;
        }
        if !bytes[index].is_ascii_whitespace() {
            tokens.push(CelToken::Other);
        }
        index += 1;
    }
    tokens
}

fn previous_token<'a>(tokens: &'a [CelToken<'a>], index: usize) -> Option<CelToken<'a>> {
    index
        .checked_sub(1)
        .and_then(|previous| tokens.get(previous))
        .copied()
}

#[cfg(feature = "registry-notary-cel")]
fn next_token<'a>(tokens: &'a [CelToken<'a>], index: usize) -> Option<CelToken<'a>> {
    tokens.get(index + 1).copied()
}

#[cfg(feature = "registry-notary-cel")]
fn next_tokens<'a, const N: usize>(
    tokens: &'a [CelToken<'a>],
    index: usize,
) -> Option<[CelToken<'a>; N]> {
    tokens.get(index + 1..index + 1 + N)?.try_into().ok()
}

fn cel_string_literal_end(bytes: &[u8], index: usize) -> Option<usize> {
    let (quote_index, raw) = if matches!(bytes.get(index), Some(b'\'' | b'"')) {
        (index, false)
    } else if matches!(bytes.get(index), Some(b'r' | b'R'))
        && matches!(bytes.get(index + 1), Some(b'\'' | b'"'))
    {
        (index + 1, true)
    } else if matches!(bytes.get(index), Some(b'b' | b'B'))
        && matches!(bytes.get(index + 1), Some(b'\'' | b'"'))
    {
        (index + 1, false)
    } else if matches!(bytes.get(index), Some(b'b' | b'B'))
        && matches!(bytes.get(index + 1), Some(b'r' | b'R'))
        && matches!(bytes.get(index + 2), Some(b'\'' | b'"'))
    {
        (index + 2, true)
    } else {
        return None;
    };
    let quote = bytes[quote_index];
    let triple = bytes.get(quote_index..quote_index + 3) == Some(&[quote, quote, quote]);
    Some(if triple {
        skip_triple_quoted_literal(bytes, quote_index + 3, quote, raw)
    } else {
        skip_quoted_literal(bytes, quote_index + 1, quote, raw)
    })
}

fn skip_quoted_literal(bytes: &[u8], mut index: usize, quote: u8, raw: bool) -> usize {
    while index < bytes.len() {
        if !raw && bytes[index] == b'\\' {
            index = index.saturating_add(2);
            continue;
        }
        if bytes[index] == quote {
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

fn skip_triple_quoted_literal(bytes: &[u8], mut index: usize, quote: u8, raw: bool) -> usize {
    while index < bytes.len() {
        if !raw && bytes[index] == b'\\' {
            index = index.saturating_add(2);
            continue;
        }
        if bytes.get(index..index + 3) == Some(&[quote, quote, quote]) {
            return index + 3;
        }
        index += 1;
    }
    bytes.len()
}

fn escaped_identifier_end(bytes: &[u8], mut index: usize) -> usize {
    index += 1;
    while index < bytes.len() {
        if bytes[index] == b'`' {
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

fn skip_line_comment(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index] != b'\n' {
        index += 1;
    }
    index
}

fn identifier_end(bytes: &[u8], mut index: usize) -> usize {
    index += 1;
    while index < bytes.len() && is_cel_identifier_continue_byte(bytes[index]) {
        index += 1;
    }
    index
}

pub(super) fn is_cel_identifier_start_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

pub(super) fn is_cel_identifier_continue_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn cel_root_bindings(
    ctx: &CelEvaluationContext<'_>,
) -> Result<BTreeMap<String, Value>, EvidenceError> {
    if ctx.claim.evidence_mode.is_registry_backed() {
        let mut root_bindings =
            registry_cel_scalar_consultation_outputs(ctx.claim, ctx.consultation_outputs)?;
        for (name, declaration) in &ctx.evidence.variables {
            let Some(value) = ctx.variables.get(name) else {
                continue;
            };
            match declaration.value_type {
                registry_notary_core::RequestVariableType::Date => {
                    root_bindings.insert(name.clone(), Value::String(value.to_string()));
                }
            }
        }
        let root_bindings = root_bindings.into_iter().collect::<BTreeMap<_, _>>();
        validate_cel_binding_limits(
            &Value::Object(root_bindings.clone().into_iter().collect()),
            ctx.config,
        )?;
        return Ok(root_bindings);
    }
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
            Value::Object(ctx.consultation_outputs.clone().into_iter().collect()),
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
pub(super) fn registry_cel_scalar_consultation_outputs(
    claim: &ClaimDefinition,
    consultation_outputs: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Value>, EvidenceError> {
    let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
        return Err(EvidenceError::InvalidRequest);
    };
    consultations
        .iter()
        .map(|(consultation_name, consultation)| {
            let source = consultation_outputs
                .get(consultation_name)
                .and_then(Value::as_object)
                .ok_or(EvidenceError::RuleEvaluationFailed)?;
            let mut projected = Map::new();
            for fixed in ["matched", "outcome"] {
                if let Some(value) = source.get(fixed) {
                    projected.insert(fixed.to_string(), value.clone());
                }
            }
            for (name, _) in consultation
                .outputs
                .iter()
                .filter(|(_, output)| output.is_scalar())
            {
                if let Some(value) = source.get(name) {
                    projected.insert(name.clone(), value.clone());
                }
            }
            Ok((consultation_name.clone(), Value::Object(projected)))
        })
        .collect()
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
        CelWorkerError::Unavailable
        | CelWorkerError::Compile
        | CelWorkerError::Protocol
        | CelWorkerError::Evaluate
        | CelWorkerError::Harness(_) => EvidenceError::RuleEvaluationFailed,
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
    if let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode {
        for (alias, consultation) in consultations {
            sources.insert(alias.clone(), json!({ "profile": consultation.profile.id }));
        }
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

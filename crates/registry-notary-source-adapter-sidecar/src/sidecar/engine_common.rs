use super::*;

pub(super) fn value_to_query_string(value: &Value) -> Result<String, SourceExecutionError> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(_) | Value::Bool(_) => Ok(value.to_string()),
        _ => Err(SourceExecutionError::HttpJsonBadRequest),
    }
}

pub(super) fn request_fields(request: &Value) -> Result<Vec<String>, SourceExecutionError> {
    request
        .get("fields")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?
        .iter()
        .map(|field| {
            field
                .as_str()
                .map(str::to_string)
                .ok_or(SourceExecutionError::HttpJsonBadRequest)
        })
        .collect()
}

pub(super) fn request_query_values(
    request: &Value,
) -> Result<BTreeMap<String, String>, SourceExecutionError> {
    request
        .get("query_values")
        .and_then(Value::as_object)
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| {
                    value
                        .as_str()
                        .map(|value| (key.clone(), value.to_string()))
                        .ok_or(SourceExecutionError::HttpJsonBadRequest)
                })
                .collect()
        })
        .unwrap_or_else(|| Ok(BTreeMap::new()))
}

pub(super) fn http_json_batch_timeout(limits: &LimitConfig, item_count: usize) -> Duration {
    let computed_ms = limits
        .worker_timeout_ms
        .saturating_mul(item_count.max(1) as u64);
    let timeout_ms = limits
        .batch_timeout_ms
        .map_or(computed_ms, |configured| configured.min(computed_ms));
    Duration::from_millis(timeout_ms.max(1))
}

pub(super) fn shared_credential_error(error: &Value) -> bool {
    matches!(
        error.get("code").and_then(Value::as_str),
        Some(
            "target_auth" | "target_rate_limit" | "source.target_auth" | "source.target_rate_limit"
        )
    )
}

pub(super) fn public_credential(source: &SourceConfig, credential: &Value) -> Value {
    let Some(credential) = credential.as_object() else {
        return Value::Object(Map::new());
    };
    let mut public = Map::new();
    for field in &source.credential_public_fields {
        if let Some(value) = credential.get(field) {
            public.insert(field.clone(), value.clone());
        }
    }
    Value::Object(public)
}

pub(super) fn http_json_bindings(
    request: &Value,
    public_credential: &Value,
    body: Option<Value>,
) -> StandaloneExpressionInput {
    let mut root_bindings = BTreeMap::new();
    for key in [
        "lookup",
        "fields",
        "limit",
        "purpose",
        "correlation_id",
        "dataset",
        "entity",
        "source_id",
        "items",
        "query_signature",
    ] {
        root_bindings.insert(
            key.to_string(),
            request.get(key).cloned().unwrap_or(Value::Null),
        );
    }
    root_bindings.insert("credential_public".to_string(), public_credential.clone());
    root_bindings.insert("body".to_string(), body.unwrap_or(Value::Null));
    StandaloneExpressionInput::new(root_bindings)
}

pub(super) fn http_flow_initial_bindings(flow: &HttpFlowSourceConfig) -> BTreeMap<String, Value> {
    let mut bindings = BTreeMap::new();
    for step in &flow.steps {
        if let Some(response) = &step.response {
            for name in response.bind.keys() {
                bindings.insert(name.clone(), Value::Null);
            }
        }
    }
    bindings
}

pub(super) fn http_flow_bindings(
    request: &Value,
    public_credential: &Value,
    flow_bindings: &BTreeMap<String, Value>,
    body: Option<Value>,
    response_meta: Option<(reqwest::StatusCode, Value)>,
) -> StandaloneExpressionInput {
    let mut bindings = http_json_bindings(request, public_credential, body);
    for (name, value) in flow_bindings {
        bindings.root_bindings.insert(name.clone(), value.clone());
    }
    if let Some((status, headers)) = response_meta {
        bindings
            .root_bindings
            .insert("status".to_string(), json!(status.as_u16()));
        bindings
            .root_bindings
            .insert("headers".to_string(), headers);
    } else {
        bindings
            .root_bindings
            .insert("status".to_string(), Value::Null);
        bindings
            .root_bindings
            .insert("headers".to_string(), Value::Null);
    }
    bindings
}

pub(super) fn http_flow_headers_value(headers: &reqwest::header::HeaderMap) -> Value {
    let mut object = Map::new();
    for (name, value) in headers {
        if let Ok(value) = value.to_str() {
            object.insert(name.as_str().to_ascii_lowercase(), json!(value));
        }
    }
    Value::Object(object)
}

pub(super) fn http_json_batch_item_bindings(
    request: &Value,
    public_credential: &Value,
    item: &Value,
    body: Option<Value>,
) -> StandaloneExpressionInput {
    let mut bindings = http_json_bindings(request, public_credential, body);
    bindings
        .root_bindings
        .insert("item".to_string(), item.clone());
    bindings
}

pub(super) fn http_json_batch_record_bindings(
    request: &Value,
    public_credential: &Value,
    record: &Value,
) -> StandaloneExpressionInput {
    let mut bindings = http_json_bindings(request, public_credential, None);
    bindings
        .root_bindings
        .insert("record".to_string(), record.clone());
    bindings
}

pub(super) fn eval_http_json_string(
    expr: &HttpJsonCelExpression,
    bindings: StandaloneExpressionInput,
) -> Result<String, SourceExecutionError> {
    match eval_http_json_value(expr, bindings)? {
        Value::String(value) => Ok(value),
        Value::Number(number) => Ok(number.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err(SourceExecutionError::HttpJson),
    }
}

pub(super) fn eval_http_json_value(
    expr: &HttpJsonCelExpression,
    bindings: StandaloneExpressionInput,
) -> Result<Value, SourceExecutionError> {
    let runtime = MappingRuntime::new(RuntimeOptions::default());
    runtime
        .evaluate_cel_expression_with_input(&expr.cel, bindings)
        .map_err(|_| SourceExecutionError::HttpJson)
}

pub(super) fn eval_http_flow_bool(
    expr: &HttpJsonCelExpression,
    bindings: StandaloneExpressionInput,
) -> Result<bool, SourceExecutionError> {
    match eval_http_json_value(expr, bindings)? {
        Value::Bool(value) => Ok(value),
        _ => Err(SourceExecutionError::HttpJson),
    }
}

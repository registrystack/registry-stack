use super::*;

pub(super) async fn execute_http_json(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: Value,
) -> Result<SourceExecution, SourceExecutionError> {
    if request.get("mode").and_then(Value::as_str) == Some("batch_match") {
        let item_count = request
            .get("items")
            .and_then(Value::as_array)
            .map_or(1, |items| items.len().max(1));
        let value = tokio::time::timeout(
            http_json_batch_timeout(&state.config.limits, item_count),
            execute_http_json_batch(state, source_id, source, &request),
        )
        .await
        .map_err(|_| SourceExecutionError::HttpJsonTimeout)??;
        return Ok(SourceExecution {
            value,
            worker_id: "http_json".to_string(),
        });
    }
    let data = execute_http_json_lookup(state, source_id, source, &request).await?;
    if data.get("error").is_some() {
        return Ok(SourceExecution {
            value: data,
            worker_id: "http_json".to_string(),
        });
    }
    Ok(SourceExecution {
        value: json!({ "data": data }),
        worker_id: "http_json".to_string(),
    })
}

pub(super) async fn execute_http_json_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    match source.batch.mode {
        SourceBatchMode::SequentialLookup => {
            execute_http_json_sequential_batch(state, source_id, source, request).await
        }
        SourceBatchMode::ParallelLookup => {
            execute_http_json_parallel_batch(state, source_id, source, request).await
        }
        SourceBatchMode::NativeBatch => {
            execute_http_json_native_batch(state, source_id, source, request).await
        }
        SourceBatchMode::WorkflowBatch => Err(SourceExecutionError::HttpJsonBadRequest),
    }
}

pub(super) async fn execute_http_json_sequential_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    if query_signature.len() != 1 {
        return Err(SourceExecutionError::HttpJsonBadRequest);
    }
    let lookup_field = query_signature
        .first()
        .and_then(|term| term.get("field"))
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    let mut responses = Vec::with_capacity(items.len());
    for item in items {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?;
        let lookup_request = http_json_item_lookup_request(source_id, request, lookup_field, item)?;
        let data = execute_http_json_lookup(state, source_id, source, &lookup_request).await?;
        if let Some(error) = data.get("error") {
            if shared_credential_error(error) {
                return Ok(json!({ "error": error }));
            }
            responses.push(json!({ "id": id, "error": error }));
        } else {
            responses.push(json!({ "id": id, "data": data }));
        }
    }
    Ok(json!({ "items": responses }))
}

pub(super) async fn execute_http_json_parallel_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    if query_signature.len() != 1 {
        return Err(SourceExecutionError::HttpJsonBadRequest);
    }
    let lookup_field = query_signature
        .first()
        .and_then(|term| term.get("field"))
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    let max_parallel = source
        .batch
        .max_parallel
        .unwrap_or(1)
        .min(items.len().max(1));
    let semaphore = Arc::new(Semaphore::new(max_parallel));
    let state = Arc::new(state.clone());
    let source = Arc::new(source.clone());
    let source_id = source_id.to_string();
    let mut tasks = JoinSet::new();
    let mut requested_ids = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?
            .to_string();
        requested_ids.push(id.clone());
        let lookup_request =
            http_json_item_lookup_request(&source_id, request, lookup_field, item)?;
        let permit = semaphore.clone();
        let task_state = Arc::clone(&state);
        let task_source = Arc::clone(&source);
        let task_source_id = source_id.clone();
        tasks.spawn(async move {
            let _permit = permit
                .acquire_owned()
                .await
                .map_err(|_| SourceExecutionError::HttpJson)?;
            let data = execute_http_json_lookup(
                &task_state,
                &task_source_id,
                task_source.as_ref(),
                &lookup_request,
            )
            .await?;
            Ok::<_, SourceExecutionError>((idx, id, data))
        });
    }

    let mut responses = vec![Value::Null; items.len()];
    while let Some(joined) = tasks.join_next().await {
        let (idx, id, data) = joined.map_err(|_| SourceExecutionError::HttpJson)??;
        if let Some(error) = data.get("error") {
            if shared_credential_error(error) {
                tasks.abort_all();
                return Ok(json!({ "error": error }));
            }
            responses[idx] = json!({ "id": id, "error": error });
        } else {
            responses[idx] = json!({ "id": id, "data": data });
        }
    }

    for (idx, response) in responses.iter_mut().enumerate() {
        if response.is_null() {
            *response = json!({
                "id": requested_ids[idx],
                "error": { "code": "source.unavailable" }
            });
        }
    }
    Ok(json!({ "items": responses }))
}

pub(super) fn http_json_item_lookup_request(
    source_id: &str,
    batch_request: &Value,
    lookup_field: &str,
    item: &Value,
) -> Result<Value, SourceExecutionError> {
    let lookup_value = item
        .get("values")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
        .cloned()
        .ok_or(SourceExecutionError::HttpJson)?;
    Ok(json!({
        "source_id": source_id,
        "dataset": batch_request.get("dataset").cloned().unwrap_or(Value::Null),
        "entity": batch_request.get("entity").cloned().unwrap_or(Value::Null),
        "lookup": {
            "field": lookup_field,
            "value": lookup_value,
        },
        "fields": batch_request.get("fields").cloned().unwrap_or_else(|| json!([])),
        "limit": 2,
        "purpose": batch_request.get("purpose").cloned().unwrap_or(Value::Null),
        "correlation_id": batch_request.get("correlation_id").cloned().unwrap_or(Value::Null),
    }))
}

pub(super) async fn execute_http_json_native_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let http_json = source
        .http_json
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let batch = http_json
        .batch
        .as_ref()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let credential = state
        .credentials
        .get(source_id)
        .cloned()
        .unwrap_or(Value::Null);
    let public_credential = public_credential(source, &credential);
    let bindings = http_json_bindings(request, &public_credential, None);
    let base_url = eval_http_json_string(&http_json.base_url, bindings.clone())?;
    let prepared =
        prepare_http_json_request(state, source_id, source, &base_url, &batch.path).await?;
    let mut builder = match batch.method {
        HttpJsonMethod::Get => prepared.client.get(prepared.url),
        HttpJsonMethod::Post => prepared
            .client
            .post(prepared.url)
            .json(&http_json_batch_request_body(request)),
    };
    for (name, expr) in &batch.query {
        let value = eval_http_json_string(expr, bindings.clone())?;
        builder = builder.query(&[(name.as_str(), value)]);
    }
    for (name, expr) in &batch.headers {
        let value = eval_http_json_string(expr, bindings.clone())?;
        builder = builder.header(name.as_str(), value);
    }
    builder = apply_http_json_auth(
        state,
        source_id,
        source,
        builder,
        http_json.auth.as_ref(),
        &credential,
    )
    .await?;
    if let Some(error) = acquire_http_json_rate_or_error(state, source_id).await {
        return Ok(error);
    }

    let response = builder.send().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(json!({ "error": { "code": "source.target_auth" } }));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after_seconds = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(state.config.limits.retry_after_seconds);
        remember_source_backoff_seconds(state, source_id, retry_after_seconds).await;
        return Ok(json!({
            "error": {
                "code": "source.target_rate_limit",
                "retry_after_seconds": retry_after_seconds
            }
        }));
    }
    if !status.is_success() {
        return Ok(json!({ "error": { "code": "source.unavailable" } }));
    }
    let body = read_limited_json_response(response, state.config.limits.max_output_bytes).await?;
    fan_out_http_json_native_batch(batch, request, &public_credential, body)
}

pub(super) fn fan_out_http_json_native_batch(
    batch: &HttpJsonBatchConfig,
    request: &Value,
    public_credential: &Value,
    body: Value,
) -> Result<Value, SourceExecutionError> {
    let records = eval_http_json_value(
        &batch.response.records,
        http_json_bindings(request, public_credential, Some(body)),
    )?;
    let records = records.as_array().ok_or(SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;

    let mut request_keys = BTreeSet::new();
    for item in items {
        item.get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?;
        let key = eval_http_json_string(
            &batch.response.item_key,
            http_json_batch_item_bindings(request, public_credential, item, None),
        )?;
        request_keys.insert(key);
    }

    let mut grouped = BTreeMap::<String, Vec<Value>>::new();
    for record in records {
        let key = eval_http_json_string(
            &batch.response.record_key,
            http_json_batch_record_bindings(request, public_credential, record),
        )?;
        if request_keys.contains(&key) {
            grouped.entry(key).or_default().push(record.clone());
        }
    }

    let mut response_items = Vec::with_capacity(items.len());
    for item in items {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?;
        let key = eval_http_json_string(
            &batch.response.item_key,
            http_json_batch_item_bindings(request, public_credential, item, None),
        )?;
        response_items.push(json!({
            "id": id,
            "data": grouped.get(&key).cloned().unwrap_or_default()
        }));
    }
    Ok(json!({ "items": response_items }))
}

pub(super) async fn execute_http_json_lookup(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let http_json = source
        .http_json
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let credential = state
        .credentials
        .get(source_id)
        .cloned()
        .unwrap_or(Value::Null);
    let public_credential = public_credential(source, &credential);
    let cache_key = http_json_cache_key(state, source_id, request)?;
    if let Some(cache_key) = cache_key.as_deref() {
        if let Some(value) = http_json_cache_get(state, source_id, cache_key).await {
            return Ok(value);
        }
        record_metric_with_items(state, source_id, "source_cache_miss", Duration::ZERO, 1).await;
    }
    let bindings = http_json_bindings(request, &public_credential, None);
    let base_url = eval_http_json_string(&http_json.base_url, bindings.clone())?;
    let prepared =
        prepare_http_json_request(state, source_id, source, &base_url, &http_json.path).await?;
    let mut builder = match http_json.method {
        HttpJsonMethod::Get => prepared.client.get(prepared.url),
        HttpJsonMethod::Post => prepared
            .client
            .post(prepared.url)
            .json(&http_json_request_body(request)),
    };
    for (name, expr) in &http_json.query {
        let value = eval_http_json_string(expr, bindings.clone())?;
        builder = builder.query(&[(name.as_str(), value)]);
    }
    for (name, expr) in &http_json.headers {
        let value = eval_http_json_string(expr, bindings.clone())?;
        builder = builder.header(name.as_str(), value);
    }
    builder = apply_http_json_auth(
        state,
        source_id,
        source,
        builder,
        http_json.auth.as_ref(),
        &credential,
    )
    .await?;
    if let Some(error) = acquire_http_json_rate_or_error(state, source_id).await {
        return Ok(error);
    }
    let response = builder.send().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(json!({ "error": { "code": "source.target_auth" } }));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after_seconds = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(state.config.limits.retry_after_seconds);
        remember_source_backoff_seconds(state, source_id, retry_after_seconds).await;
        return Ok(json!({
            "error": {
                "code": "source.target_rate_limit",
                "retry_after_seconds": retry_after_seconds
            }
        }));
    }
    if !status.is_success() {
        return Ok(json!({ "error": { "code": "source.unavailable" } }));
    }
    let body = read_limited_json_response(response, state.config.limits.max_output_bytes).await?;
    let records = eval_http_json_value(
        &http_json.response.records,
        http_json_bindings(request, &public_credential, Some(body)),
    )?;
    if !records.is_array() {
        return Err(SourceExecutionError::HttpJson);
    }
    if let Some(cache_key) = cache_key.as_deref() {
        http_json_cache_put(state, source_id, source, cache_key, &records).await;
    }
    Ok(records)
}

pub(super) fn http_json_request_body(request: &Value) -> Value {
    json!({
        "source_id": request.get("source_id").cloned().unwrap_or(Value::Null),
        "dataset": request.get("dataset").cloned().unwrap_or(Value::Null),
        "entity": request.get("entity").cloned().unwrap_or(Value::Null),
        "lookup": request.get("lookup").cloned().unwrap_or(Value::Null),
        "fields": request.get("fields").cloned().unwrap_or_else(|| json!([])),
        "limit": request.get("limit").cloned().unwrap_or(Value::Null),
        "purpose": request.get("purpose").cloned().unwrap_or(Value::Null),
        "correlation_id": request.get("correlation_id").cloned().unwrap_or(Value::Null),
    })
}

pub(super) fn http_json_batch_request_body(request: &Value) -> Value {
    json!({
        "source_id": request.get("source_id").cloned().unwrap_or(Value::Null),
        "dataset": request.get("dataset").cloned().unwrap_or(Value::Null),
        "entity": request.get("entity").cloned().unwrap_or(Value::Null),
        "query_signature": request.get("query_signature").cloned().unwrap_or_else(|| json!([])),
        "items": request.get("items").cloned().unwrap_or_else(|| json!([])),
        "fields": request.get("fields").cloned().unwrap_or_else(|| json!([])),
        "purpose": request.get("purpose").cloned().unwrap_or(Value::Null),
        "correlation_id": request.get("correlation_id").cloned().unwrap_or(Value::Null),
    })
}

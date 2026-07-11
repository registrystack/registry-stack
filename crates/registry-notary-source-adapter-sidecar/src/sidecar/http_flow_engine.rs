use super::*;

pub(super) async fn execute_http_flow(
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
            execute_http_flow_batch(state, source_id, source, &request),
        )
        .await
        .map_err(|_| SourceExecutionError::HttpJsonTimeout)??;
        return Ok(SourceExecution {
            value,
            worker_id: "http_flow".to_string(),
        });
    }
    let data = execute_http_flow_lookup_with_timeout(state, source_id, source, &request).await?;
    if data.get("error").is_some() {
        return Ok(SourceExecution {
            value: data,
            worker_id: "http_flow".to_string(),
        });
    }
    Ok(SourceExecution {
        value: json!({ "data": data }),
        worker_id: "http_flow".to_string(),
    })
}

pub(super) async fn execute_http_flow_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    match source.batch.mode {
        SourceBatchMode::SequentialLookup => {
            execute_http_flow_sequential_batch(state, source_id, source, request).await
        }
        SourceBatchMode::ParallelLookup => {
            execute_http_flow_parallel_batch(state, source_id, source, request).await
        }
        SourceBatchMode::WorkflowBatch | SourceBatchMode::NativeBatch => {
            Err(SourceExecutionError::HttpJsonBadRequest)
        }
    }
}

pub(super) async fn execute_http_flow_sequential_batch(
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
        let data = execute_http_flow_lookup_with_timeout(state, source_id, source, &lookup_request)
            .await?;
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

pub(super) async fn execute_http_flow_parallel_batch(
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
    let source = source.clone();
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
        let task_source = source.clone();
        let task_source_id = source_id.clone();
        tasks.spawn(async move {
            let _permit = permit
                .acquire_owned()
                .await
                .map_err(|_| SourceExecutionError::HttpJson)?;
            let data = execute_http_flow_lookup_with_timeout(
                &task_state,
                &task_source_id,
                &task_source,
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

pub(super) async fn execute_http_flow_lookup_with_timeout(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let timeout = http_flow_timeout(state, source)?;
    match tokio::time::timeout(
        timeout,
        execute_http_flow_lookup(state, source_id, source, request),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            record_http_flow_metric(state, source_id, None, "flow_timeout", 1).await;
            Err(SourceExecutionError::HttpJsonTimeout)
        }
    }
}

pub(super) fn http_flow_timeout(
    state: &AppState,
    source: &SourceConfig,
) -> Result<Duration, SourceExecutionError> {
    let flow = source
        .http_flow
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    Ok(Duration::from_millis(
        flow.timeout_ms
            .unwrap_or(state.config.limits.worker_timeout_ms)
            .max(1),
    ))
}

pub(super) async fn execute_http_flow_lookup(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let flow = source
        .http_flow
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
    }

    let mut bindings = http_flow_initial_bindings(flow);
    for step in &flow.steps {
        if let Some(when) = &step.when {
            if !eval_http_flow_bool(
                when,
                http_flow_bindings(request, &public_credential, &bindings, None, None),
            )? {
                record_http_flow_metric(state, source_id, Some(&step.id), "step_skipped", 1).await;
                continue;
            }
        }

        let prepared = prepare_http_json_request(
            state,
            source_id,
            source,
            &step.request.base_url,
            &step.request.path,
        )
        .await?;
        let mut builder = match step.request.method {
            HttpJsonMethod::Get => prepared.client.get(prepared.url),
            HttpJsonMethod::Post => return Err(SourceExecutionError::HttpJsonBadRequest),
        };
        let request_bindings =
            http_flow_bindings(request, &public_credential, &bindings, None, None);
        for (name, expr) in &step.request.query {
            let value = eval_http_json_string(expr, request_bindings.clone())?;
            builder = builder.query(&[(name.as_str(), value)]);
        }
        for (name, expr) in &step.request.headers {
            let value = eval_http_json_string(expr, request_bindings.clone())?;
            builder = builder.header(name.as_str(), value);
        }
        builder = apply_http_json_auth(
            state,
            source_id,
            source,
            builder,
            step.request.auth.as_ref(),
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
        match http_flow_status_action(state, step, status, response.headers())? {
            HttpFlowStepOutcome::Bind => {
                let response_headers = http_flow_headers_value(response.headers());
                let body =
                    read_limited_json_response(response, state.config.limits.max_output_bytes)
                        .await?;
                let scope = http_flow_bindings(
                    request,
                    &public_credential,
                    &bindings,
                    Some(body),
                    Some((status, response_headers)),
                );
                let mut step_bindings = BTreeMap::new();
                if let Some(response) = &step.response {
                    for (name, expr) in &response.bind {
                        let value = eval_http_json_value(expr, scope.clone())?;
                        step_bindings.insert(name.clone(), value);
                    }
                }
                bindings.extend(step_bindings);
                record_http_flow_metric(state, source_id, Some(&step.id), "step_success", 1).await;
            }
            HttpFlowStepOutcome::Continue => {
                record_http_flow_metric(state, source_id, Some(&step.id), "step_skipped", 1).await;
            }
            HttpFlowStepOutcome::NotFound => {
                record_http_flow_metric(state, source_id, Some(&step.id), "flow_not_found", 1)
                    .await;
                if let Some(cache_key) = cache_key.as_deref() {
                    http_json_cache_put(state, source_id, source, cache_key, &json!([])).await;
                }
                return Ok(json!([]));
            }
            HttpFlowStepOutcome::Error(error) => {
                record_http_flow_metric(
                    state,
                    source_id,
                    Some(&step.id),
                    http_flow_error_metric_outcome(&error),
                    1,
                )
                .await;
                remember_source_backoff(state, source_id, &error).await;
                return Ok(error);
            }
        }
    }

    let records = eval_http_json_value(
        &flow.output.records,
        http_flow_bindings(request, &public_credential, &bindings, None, None),
    )?;
    if !records.is_array() {
        record_http_flow_metric(state, source_id, None, "flow_invalid_output", 1).await;
        return Err(SourceExecutionError::HttpJson);
    }
    if let Some(cache_key) = cache_key.as_deref() {
        http_json_cache_put(state, source_id, source, cache_key, &records).await;
    }
    Ok(records)
}

pub(super) fn http_flow_error_metric_outcome(error: &Value) -> &'static str {
    match error
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_str)
    {
        Some("source.target_auth") => "step_target_auth",
        Some("source.target_rate_limit") => "step_target_rate_limit",
        Some("source.timeout") => "step_source_timeout",
        Some("source.unavailable") => "step_source_unavailable",
        _ => "step_source_error",
    }
}

pub(super) enum HttpFlowStepOutcome {
    Bind,
    Continue,
    NotFound,
    Error(Value),
}

pub(super) fn http_flow_status_action(
    state: &AppState,
    step: &HttpFlowStepConfig,
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Result<HttpFlowStepOutcome, SourceExecutionError> {
    let action = step.on_status.get(&status.as_u16().to_string()).copied();
    match action {
        Some(HttpFlowStatusAction::Continue) => return Ok(HttpFlowStepOutcome::Continue),
        Some(HttpFlowStatusAction::SourceUnavailable) => {
            return Ok(HttpFlowStepOutcome::Error(
                json!({ "error": { "code": "source.unavailable" } }),
            ));
        }
        Some(HttpFlowStatusAction::TargetAuth) => {
            return Ok(HttpFlowStepOutcome::Error(
                json!({ "error": { "code": "source.target_auth" } }),
            ));
        }
        Some(HttpFlowStatusAction::TargetRateLimit) => {
            return Ok(HttpFlowStepOutcome::Error(json!({
                "error": {
                    "code": "source.target_rate_limit",
                    "retry_after_seconds": http_flow_retry_after_seconds(state, headers)
                }
            })));
        }
        Some(HttpFlowStatusAction::Timeout) => {
            return Ok(HttpFlowStepOutcome::Error(
                json!({ "error": { "code": "source.timeout" } }),
            ));
        }
        None => {}
    }

    if status.is_success() {
        return Ok(HttpFlowStepOutcome::Bind);
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(HttpFlowStepOutcome::NotFound);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(HttpFlowStepOutcome::Error(
            json!({ "error": { "code": "source.target_auth" } }),
        ));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Ok(HttpFlowStepOutcome::Error(json!({
            "error": {
                "code": "source.target_rate_limit",
                "retry_after_seconds": http_flow_retry_after_seconds(state, headers)
            }
        })));
    }
    if status == reqwest::StatusCode::REQUEST_TIMEOUT {
        return Ok(HttpFlowStepOutcome::Error(
            json!({ "error": { "code": "source.timeout" } }),
        ));
    }
    Ok(HttpFlowStepOutcome::Error(
        json!({ "error": { "code": "source.unavailable" } }),
    ))
}

pub(super) fn http_flow_retry_after_seconds(
    state: &AppState,
    headers: &reqwest::header::HeaderMap,
) -> u64 {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(state.config.limits.retry_after_seconds)
}

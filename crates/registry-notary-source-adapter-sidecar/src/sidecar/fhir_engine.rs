use super::*;

pub(super) async fn execute_fhir(
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
            execute_fhir_batch_match(state, source_id, source, &request),
        )
        .await
        .map_err(|_| SourceExecutionError::HttpJsonTimeout)??;
        return Ok(SourceExecution {
            value,
            worker_id: "fhir".to_string(),
        });
    }

    let lookup = request
        .get("lookup")
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let lookup_field = lookup
        .get("field")
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let lookup_value = lookup
        .get("value")
        .cloned()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let fields = request_fields(&request)?;
    let limit = request
        .get("limit")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(2);
    let purpose = request.get("purpose").and_then(Value::as_str).unwrap_or("");
    let query_values = request_query_values(&request)?;
    let data = execute_fhir_lookup(
        state,
        source_id,
        source,
        lookup_field,
        lookup_value,
        &query_values,
        &fields,
        limit,
        purpose,
    )
    .await?;
    Ok(SourceExecution {
        value: json!({ "data": data }),
        worker_id: "fhir".to_string(),
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn execute_fhir_lookup(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    lookup_field: &str,
    lookup_value: Value,
    query_values: &BTreeMap<String, String>,
    fields: &[String],
    limit: usize,
    purpose: &str,
) -> Result<Vec<Value>, SourceExecutionError> {
    let fhir = source.fhir.as_ref().ok_or(SourceExecutionError::HttpJson)?;
    let mut nodes = BTreeMap::<String, Vec<Value>>::new();
    let anchor = search_fhir_node(
        state,
        source_id,
        source,
        fhir,
        &fhir.anchor,
        lookup_field,
        &lookup_value,
        query_values,
        &nodes,
        purpose,
    )
    .await?;
    match anchor.len() {
        0 => return Ok(Vec::new()),
        1 => {
            nodes.insert(fhir.anchor.id.clone(), anchor);
        }
        _ => {
            nodes.insert(fhir.anchor.id.clone(), anchor);
            return Ok(project_fhir_records(fhir, &nodes, fields, limit));
        }
    }

    for relation in &fhir.relations {
        let node = FhirNodeConfig {
            id: relation.id.clone(),
            resource_type: relation.resource_type.clone(),
            cardinality: relation.cardinality.clone(),
            search: relation.search.clone(),
        };
        let resources = search_fhir_node(
            state,
            source_id,
            source,
            fhir,
            &node,
            lookup_field,
            &lookup_value,
            query_values,
            &nodes,
            purpose,
        )
        .await?;
        if resources.is_empty() {
            if matches!(relation.cardinality.as_str(), "zero_or_one" | "any") {
                nodes.insert(relation.id.clone(), resources);
                continue;
            }
            return Ok(Vec::new());
        }
        if matches!(relation.cardinality.as_str(), "one" | "zero_or_one") && resources.len() > 1 {
            nodes.insert(relation.id.clone(), resources);
            return Ok(project_fhir_records(fhir, &nodes, fields, limit));
        }
        nodes.insert(relation.id.clone(), resources);
    }

    Ok(project_fhir_records(fhir, &nodes, fields, limit))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn search_fhir_node(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    fhir: &FhirSourceConfig,
    node: &FhirNodeConfig,
    lookup_field: &str,
    lookup_value: &Value,
    query_values: &BTreeMap<String, String>,
    nodes: &BTreeMap<String, Vec<Value>>,
    purpose: &str,
) -> Result<Vec<Value>, SourceExecutionError> {
    let prepared = prepare_http_json_request(
        state,
        source_id,
        source,
        &fhir.base_url,
        &node.resource_type,
    )
    .await?;
    let mut url = prepared.url;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("_count", &(fhir.max_search_results + 1).to_string());
        for search in &node.search {
            let value = fhir_search_value(search, lookup_field, lookup_value, query_values, nodes)?;
            query.append_pair(&search.param, &value);
        }
    }
    let mut request = prepared
        .client
        .get(url)
        .header("accept", fhir.accept.as_str());
    if fhir.forward_data_purpose {
        request = request.header("data-purpose", purpose);
    }
    request = apply_fhir_auth(state, fhir, request)?;
    if !fhir.prefer_handling.is_empty() {
        request = request.header("prefer", format!("handling={}", fhir.prefer_handling));
    }
    if acquire_http_json_rate_or_error(state, source_id)
        .await
        .is_some()
    {
        return Err(SourceExecutionError::HttpJsonTimeout);
    }
    let response = request.send().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(SourceExecutionError::HttpJson);
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after_seconds = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(state.config.limits.retry_after_seconds);
        remember_source_backoff_seconds(state, source_id, retry_after_seconds).await;
        return Err(SourceExecutionError::HttpJsonTimeout);
    }
    if !status.is_success() {
        return Err(SourceExecutionError::HttpJson);
    }
    let max_bytes = fhir
        .max_source_bundle_bytes
        .min(state.config.limits.max_output_bytes);
    let body = read_limited_json_response(response, max_bytes).await?;
    fhir_bundle_match_resources(&body, &node.resource_type, fhir.max_search_results + 1)
}

pub(super) fn fhir_search_value(
    search: &FhirSearchParamConfig,
    lookup_field: &str,
    lookup_value: &Value,
    query_values: &BTreeMap<String, String>,
    nodes: &BTreeMap<String, Vec<Value>>,
) -> Result<String, SourceExecutionError> {
    let raw = if let Some(value) = &search.value {
        value.clone()
    } else if search.value_from_lookup.unwrap_or(false) {
        let _ = lookup_field;
        value_to_query_string(lookup_value)?
    } else if let Some(field) = &search.value_from_query {
        query_values
            .get(field)
            .cloned()
            .ok_or(SourceExecutionError::HttpJsonBadRequest)?
    } else if let Some(value_from_node) = &search.value_from_node {
        fhir_value_from_node(value_from_node, nodes)?
    } else {
        return Err(SourceExecutionError::HttpJsonBadRequest);
    };
    match search.search_type.as_str() {
        "token" => Ok(search
            .system
            .as_ref()
            .map(|system| format!("{system}|{raw}"))
            .unwrap_or(raw)),
        "reference" | "string" | "date" | "code" => Ok(raw),
        _ => Err(SourceExecutionError::HttpJsonBadRequest),
    }
}

pub(super) fn fhir_value_from_node(
    value_from_node: &str,
    nodes: &BTreeMap<String, Vec<Value>>,
) -> Result<String, SourceExecutionError> {
    let (node_id, selector) = value_from_node
        .split_once('.')
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let resource = nodes
        .get(node_id)
        .and_then(|resources| resources.first())
        .ok_or(SourceExecutionError::HttpJson)?;
    match selector {
        "id" => resource
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or(SourceExecutionError::HttpJson),
        "reference" => {
            let resource_type = resource
                .get("resourceType")
                .and_then(Value::as_str)
                .ok_or(SourceExecutionError::HttpJson)?;
            let id = resource
                .get("id")
                .and_then(Value::as_str)
                .ok_or(SourceExecutionError::HttpJson)?;
            Ok(format!("{resource_type}/{id}"))
        }
        pointer if pointer.starts_with('/') => resource
            .pointer(pointer)
            .ok_or(SourceExecutionError::HttpJson)
            .and_then(value_to_query_string),
        _ => Err(SourceExecutionError::HttpJsonBadRequest),
    }
}

pub(super) fn fhir_bundle_match_resources(
    body: &Value,
    resource_type: &str,
    limit: usize,
) -> Result<Vec<Value>, SourceExecutionError> {
    if body.get("resourceType").and_then(Value::as_str) != Some("Bundle")
        || body.get("type").and_then(Value::as_str) != Some("searchset")
    {
        return Err(SourceExecutionError::HttpJson);
    }
    let entries = body
        .get("entry")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut resources = Vec::new();
    for entry in entries {
        if entry.pointer("/search/mode").and_then(Value::as_str) != Some("match") {
            continue;
        }
        let Some(resource) = entry.get("resource") else {
            continue;
        };
        if resource.get("resourceType").and_then(Value::as_str) != Some(resource_type) {
            return Err(SourceExecutionError::HttpJson);
        }
        resources.push(resource.clone());
        if resources.len() >= limit {
            break;
        }
    }
    Ok(resources)
}

pub(super) fn project_fhir_records(
    fhir: &FhirSourceConfig,
    nodes: &BTreeMap<String, Vec<Value>>,
    fields: &[String],
    limit: usize,
) -> Vec<Value> {
    let row_count = nodes
        .values()
        .map(Vec::len)
        .max()
        .unwrap_or_default()
        .min(limit);
    (0..row_count)
        .map(|index| project_fhir_record(fhir, nodes, fields, index))
        .collect()
}

pub(super) fn project_fhir_record(
    fhir: &FhirSourceConfig,
    nodes: &BTreeMap<String, Vec<Value>>,
    fields: &[String],
    index: usize,
) -> Value {
    let mut record = Map::new();
    for field in fields {
        let Some(projection) = fhir.project.get(field) else {
            continue;
        };
        let Some(resource) = nodes
            .get(&projection.node)
            .and_then(|resources| resources.get(index).or_else(|| resources.first()))
        else {
            continue;
        };
        if let Some(value) = resource.pointer(&projection.pointer) {
            record.insert(field.clone(), value.clone());
        } else if let Some(value) = &projection.default_value {
            record.insert(field.clone(), value.clone());
        }
    }
    Value::Object(record)
}

pub(super) async fn execute_fhir_batch_match(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    match source.batch.mode {
        SourceBatchMode::SequentialLookup => {
            execute_fhir_sequential_batch_match(state, source_id, source, request).await
        }
        SourceBatchMode::ParallelLookup => {
            execute_fhir_parallel_batch_match(state, source_id, source, request).await
        }
        SourceBatchMode::WorkflowBatch | SourceBatchMode::NativeBatch => {
            Err(SourceExecutionError::HttpJsonBadRequest)
        }
    }
}

pub(super) async fn execute_fhir_sequential_batch_match(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .cloned()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let query_signature: Vec<BatchQueryTerm> =
        serde_json::from_value(query_signature).map_err(|_| SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .cloned()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let items: Vec<BatchMatchItem> =
        serde_json::from_value(items).map_err(|_| SourceExecutionError::HttpJson)?;
    let fields = request_fields(request)?;
    let purpose = request.get("purpose").and_then(Value::as_str).unwrap_or("");
    let mut output = Vec::with_capacity(items.len());
    for item in &items {
        let query = fhir_batch_item_query(source, &query_signature, item);
        let Ok((lookup_field, lookup_value, query_values)) = query else {
            output.push(json!({
                "id": item.id,
                "error": { "code": "source_unavailable" }
            }));
            continue;
        };
        let result = execute_fhir_lookup(
            state,
            source_id,
            source,
            &lookup_field,
            Value::String(lookup_value),
            &query_values,
            &fields,
            2,
            purpose,
        )
        .await;
        match result {
            Ok(data) => output.push(json!({ "id": item.id, "data": data })),
            Err(_) => output.push(json!({
                "id": item.id,
                "error": { "code": "source_unavailable" }
            })),
        }
    }
    Ok(json!({ "items": output }))
}

pub(super) async fn execute_fhir_parallel_batch_match(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .cloned()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let query_signature: Vec<BatchQueryTerm> =
        serde_json::from_value(query_signature).map_err(|_| SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .cloned()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let items: Vec<BatchMatchItem> =
        serde_json::from_value(items).map_err(|_| SourceExecutionError::HttpJson)?;
    let fields = Arc::new(request_fields(request)?);
    let purpose = Arc::new(
        request
            .get("purpose")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    );
    let max_parallel = source
        .batch
        .max_parallel
        .unwrap_or(1)
        .min(items.len().max(1));
    let semaphore = Arc::new(Semaphore::new(max_parallel));
    let state = Arc::new(state.clone());
    let source = Arc::new(source.clone());
    let source_id = source_id.to_string();
    let query_signature = Arc::new(query_signature);
    let mut tasks = JoinSet::new();
    let requested_ids = items.iter().map(|item| item.id.clone()).collect::<Vec<_>>();
    for (idx, item) in items.into_iter().enumerate() {
        let permit = semaphore.clone();
        let task_state = Arc::clone(&state);
        let task_source = Arc::clone(&source);
        let task_source_id = source_id.clone();
        let task_query_signature = Arc::clone(&query_signature);
        let task_fields = Arc::clone(&fields);
        let task_purpose = Arc::clone(&purpose);
        tasks.spawn(async move {
            let _permit = permit
                .acquire_owned()
                .await
                .map_err(|_| SourceExecutionError::HttpJson)?;
            let id = item.id.clone();
            let response = match fhir_batch_item_query(
                task_source.as_ref(),
                task_query_signature.as_ref(),
                &item,
            ) {
                Ok((lookup_field, lookup_value, query_values)) => {
                    match execute_fhir_lookup(
                        &task_state,
                        &task_source_id,
                        task_source.as_ref(),
                        &lookup_field,
                        Value::String(lookup_value),
                        &query_values,
                        task_fields.as_ref(),
                        2,
                        task_purpose.as_ref(),
                    )
                    .await
                    {
                        Ok(data) => json!({ "id": id, "data": data }),
                        Err(_) => json!({
                            "id": id,
                            "error": { "code": "source_unavailable" }
                        }),
                    }
                }
                Err(_) => json!({
                    "id": id,
                    "error": { "code": "source_unavailable" }
                }),
            };
            Ok::<_, SourceExecutionError>((idx, response))
        });
    }

    let mut output = vec![Value::Null; requested_ids.len()];
    while let Some(joined) = tasks.join_next().await {
        let (idx, response) = joined.map_err(|_| SourceExecutionError::HttpJson)??;
        output[idx] = response;
    }
    for (idx, response) in output.iter_mut().enumerate() {
        if response.is_null() {
            *response = json!({
                "id": requested_ids[idx],
                "error": { "code": "source_unavailable" }
            });
        }
    }
    Ok(json!({ "items": output }))
}

pub(super) fn fhir_batch_item_query(
    source: &SourceConfig,
    query_signature: &[BatchQueryTerm],
    item: &BatchMatchItem,
) -> Result<(String, String, BTreeMap<String, String>), SourceExecutionError> {
    let mut query_values = BTreeMap::new();
    for (term, value) in query_signature.iter().zip(item.values.iter()) {
        query_values.insert(term.field.clone(), value_to_query_string(value)?);
    }
    primary_lookup_value(source, &query_values).ok_or(SourceExecutionError::HttpJsonBadRequest)
}

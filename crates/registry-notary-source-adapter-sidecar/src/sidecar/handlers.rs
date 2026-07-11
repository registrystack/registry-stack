use super::*;

pub(super) async fn healthz(State(_state): State<Arc<AppState>>) -> Response {
    (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response()
}

pub(super) async fn ready(State(state): State<Arc<AppState>>) -> Response {
    let mut body = json!({ "status": "ready" });
    if let Some(assurance) = &state.config.assurance {
        body["config_hash"] = json!(assurance.config_hash);
        body["expression_hashes_verified"] = json!(assurance.expression_hashes_verified);
        body["runtime_verified"] = json!(assurance.runtime_verified);
        body["smoke_verified"] = json!(assurance.smoke_verified);
    }
    (StatusCode::OK, Json(body)).into_response()
}

pub(super) async fn assurance(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return *response;
    }
    match &state.config.assurance {
        Some(assurance) => (StatusCode::OK, Json(assurance)).into_response(),
        None => problem(
            StatusCode::NOT_FOUND,
            "governed sidecar assurance is not configured",
        ),
    }
}

pub(super) async fn lookup(
    State(state): State<Arc<AppState>>,
    Path((dataset, entity)): Path<(String, String)>,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let started_at = Instant::now();
    if let Err(response) = authorize(&state, &headers) {
        return *response;
    }
    let Some(purpose) = headers
        .get("data-purpose")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        return problem(StatusCode::BAD_REQUEST, "missing Data-Purpose");
    };

    let Some((source_id, source)) = state
        .config
        .sources
        .iter()
        .find(|(_, source)| source.dataset == dataset && source.entity == entity)
    else {
        return problem(StatusCode::NOT_FOUND, "source route not found");
    };

    let query = match validate_query(&state, source, raw_query.as_deref(), query) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let correlation_id = headers
        .get("x-correlation-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    let request = json!({
        "source_id": source_id,
        "dataset": dataset,
        "entity": entity,
        "lookup": {
            "field": query.lookup_field,
            "value": query.lookup_value,
        },
        "query_values": query.query_values,
        "fields": query.fields,
        "limit": query.limit,
        "purpose": purpose,
        "correlation_id": correlation_id.clone(),
        "configuration": state.credentials.get(source_id).cloned().unwrap_or(Value::Null),
    });

    let _source_permit = match acquire_source_permit(&state, source_id, "source_saturated", 1).await
    {
        Ok(permit) => permit,
        Err(response) => return *response,
    };
    let source_execution = match execute_source_json(&state, source_id, source, request).await {
        Ok(execution) => execution,
        Err(SourceExecutionError::HttpJson) => {
            record_metric_with_items(&state, source_id, "source_error", started_at.elapsed(), 1)
                .await;
            let worker_id = source.engine.worker_id();
            warn!(
                correlation_id = correlation_id.as_deref().unwrap_or(""),
                source_id = source_id.as_str(),
                outcome = "source_error",
                worker_id,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "sidecar lookup failed"
            );
            return problem(StatusCode::BAD_GATEWAY, "source adapter execution failed");
        }
        Err(SourceExecutionError::HttpJsonTimeout) => {
            record_metric_with_items(&state, source_id, "source_timeout", started_at.elapsed(), 1)
                .await;
            let worker_id = source.engine.worker_id();
            warn!(
                correlation_id = correlation_id.as_deref().unwrap_or(""),
                source_id = source_id.as_str(),
                outcome = "source_timeout",
                worker_id,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "sidecar lookup timed out"
            );
            return problem_with_code(
                StatusCode::GATEWAY_TIMEOUT,
                "source timeout",
                "source.timeout",
            );
        }
        Err(SourceExecutionError::HttpJsonBadRequest) => {
            record_metric_with_items(&state, source_id, "source_error", started_at.elapsed(), 1)
                .await;
            return problem(StatusCode::BAD_REQUEST, "invalid source adapter request");
        }
    };

    let response = normalize_worker_response(source_execution.value, &query.fields, query.limit);
    let outcome = if response.status().is_success() {
        "success"
    } else {
        "source_error"
    };
    record_metric_with_items(&state, source_id, outcome, started_at.elapsed(), 1).await;
    info!(
        correlation_id = correlation_id.as_deref().unwrap_or(""),
        source_id = source_id.as_str(),
        outcome,
        worker_id = source_execution.worker_id,
        status = response.status().as_u16(),
        duration_ms = started_at.elapsed().as_millis() as u64,
        "sidecar lookup completed"
    );
    response
}

pub(super) async fn batch_match(
    State(state): State<Arc<AppState>>,
    Path((dataset, entity)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    let started_at = Instant::now();
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    if let Err(response) = authorize(&state, &headers) {
        return *response;
    }
    let Some(purpose) = headers
        .get("data-purpose")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        return problem(StatusCode::BAD_REQUEST, "missing Data-Purpose");
    };

    let Some((source_id, source)) = state
        .config
        .sources
        .iter()
        .find(|(_, source)| source.dataset == dataset && source.entity == entity)
    else {
        return problem(StatusCode::NOT_FOUND, "source route not found");
    };

    let body = match parse_batch_match_body(&state, body).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    if let Err(response) = validate_batch_match_request(&state, &body) {
        return *response;
    }

    let correlation_id = headers
        .get("x-correlation-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let request = json!({
        "mode": "batch_match",
        "source_id": source_id,
        "dataset": dataset,
        "entity": entity,
        "query_signature": body.query_signature,
        "items": body.items,
        "batch": source.batch.clone(),
        "fields": body.fields,
        "purpose": purpose,
        "correlation_id": correlation_id.clone(),
        "configuration": state.credentials.get(source_id).cloned().unwrap_or(Value::Null),
    });

    let batch_item_count = body.items.len();
    let _source_permit = match acquire_source_permit(
        &state,
        source_id,
        "batch_source_saturated",
        batch_item_count,
    )
    .await
    {
        Ok(permit) => permit,
        Err(response) => return *response,
    };
    let source_execution = match execute_source_json(&state, source_id, source, request).await {
        Ok(execution) => execution,
        Err(SourceExecutionError::HttpJson) => {
            record_metric_with_items(
                &state,
                source_id,
                "batch_source_error",
                started_at.elapsed(),
                batch_item_count,
            )
            .await;
            let worker_id = source.engine.worker_id();
            warn!(
                correlation_id = correlation_id.as_deref().unwrap_or(""),
                source_id = source_id.as_str(),
                outcome = "batch_source_error",
                worker_id,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "sidecar batch match failed"
            );
            return problem(StatusCode::BAD_GATEWAY, "source adapter execution failed");
        }
        Err(SourceExecutionError::HttpJsonTimeout) => {
            record_metric_with_items(
                &state,
                source_id,
                "batch_source_timeout",
                started_at.elapsed(),
                batch_item_count,
            )
            .await;
            let worker_id = source.engine.worker_id();
            warn!(
                correlation_id = correlation_id.as_deref().unwrap_or(""),
                source_id = source_id.as_str(),
                outcome = "batch_source_timeout",
                worker_id,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "sidecar batch match timed out"
            );
            return problem_with_code(
                StatusCode::GATEWAY_TIMEOUT,
                "source timeout",
                "source.timeout",
            );
        }
        Err(SourceExecutionError::HttpJsonBadRequest) => {
            record_metric_with_items(
                &state,
                source_id,
                "batch_source_error",
                started_at.elapsed(),
                batch_item_count,
            )
            .await;
            return problem(StatusCode::BAD_REQUEST, "invalid source adapter request");
        }
    };

    let response = normalize_batch_worker_response(
        source_execution.value,
        &body.fields,
        &body
            .items
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>(),
    );
    let outcome = if response.status().is_success() {
        "batch_success"
    } else {
        "batch_source_error"
    };
    record_metric_with_items(
        &state,
        source_id,
        outcome,
        started_at.elapsed(),
        batch_item_count,
    )
    .await;
    info!(
        correlation_id = correlation_id.as_deref().unwrap_or(""),
        source_id = source_id.as_str(),
        outcome,
        worker_id = source_execution.worker_id,
        status = response.status().as_u16(),
        duration_ms = started_at.elapsed().as_millis() as u64,
        "sidecar batch match completed"
    );
    response
}

pub(super) async fn enforce_uri_limit(request: Request<Body>, next: Next) -> Response {
    if request
        .uri()
        .path_and_query()
        .map_or(0, |value| value.as_str().len())
        > MAX_URI_BYTES
    {
        return problem(
            StatusCode::URI_TOO_LONG,
            "request URI exceeds configured byte limit",
        );
    }
    next.run(request).await
}

pub(super) async fn parse_batch_match_body(
    state: &AppState,
    body: Body,
) -> Result<BatchMatchRequest, Box<Response>> {
    let limit = state.config.limits.max_request_bytes;
    let bytes = to_bytes(body, limit).await.map_err(|_| {
        Box::new(problem(
            StatusCode::BAD_REQUEST,
            "request body exceeds configured byte limit",
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        Box::new(problem(
            StatusCode::BAD_REQUEST,
            "invalid batch match request",
        ))
    })
}

pub(super) fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    let Some(raw) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(Box::new(unauthorized()));
    };
    let token = parse_bearer_token(raw).map_err(|_| Box::new(unauthorized()))?;
    if state
        .auth_tokens
        .iter()
        .any(|configured| verify_api_key(token, &configured.fingerprint).unwrap_or(false))
    {
        Ok(())
    } else {
        Err(Box::new(problem(
            StatusCode::FORBIDDEN,
            "sidecar token rejected",
        )))
    }
}

pub(super) fn unauthorized() -> Response {
    let mut response = problem(
        StatusCode::UNAUTHORIZED,
        "missing or malformed sidecar token",
    );
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

struct LookupQuery {
    lookup_field: String,
    lookup_value: String,
    query_values: BTreeMap<String, String>,
    fields: Vec<String>,
    limit: usize,
}

fn validate_query(
    state: &AppState,
    source: &SourceConfig,
    raw_query: Option<&str>,
    query: HashMap<String, String>,
) -> Result<LookupQuery, Box<Response>> {
    if raw_query
        .map(|raw| raw.len() > state.config.limits.max_request_bytes)
        .unwrap_or(false)
    {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "query string too large",
        )));
    }

    for (key, value) in &query {
        if key.len() > state.config.limits.max_query_parameter_bytes
            || value.len() > state.config.limits.max_query_parameter_bytes
        {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "query parameter exceeds configured byte limit",
            )));
        }
    }

    let limit = query
        .get("limit")
        .map(|raw| raw.parse::<usize>())
        .transpose()
        .map_err(|_| Box::new(problem(StatusCode::BAD_REQUEST, "invalid limit")))?
        .unwrap_or(2);
    if limit > 2 {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "limit must be at most 2",
        )));
    }

    let fields = query
        .get("fields")
        .map(|raw| {
            raw.split(',')
                .filter(|field| !field.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if fields.is_empty() {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "fields projection is required",
        )));
    }

    let lookup_pairs = query
        .into_iter()
        .filter(|(key, _)| key != "fields" && key != "limit")
        .collect::<Vec<_>>();
    if lookup_pairs.is_empty() {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "at least one lookup predicate is required",
        )));
    }
    if source.engine != SourceEngine::Fhir && lookup_pairs.len() != 1 {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "exactly one lookup predicate is required",
        )));
    }
    let query_values = lookup_pairs.into_iter().collect::<BTreeMap<_, _>>();
    let (lookup_field, lookup_value, query_values) =
        primary_lookup_value(source, &query_values).expect("at least one lookup pair");
    if lookup_value.is_empty() {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "lookup predicate value is required",
        )));
    }

    Ok(LookupQuery {
        lookup_field,
        lookup_value,
        query_values,
        fields,
        limit,
    })
}

pub(super) fn primary_lookup_value(
    source: &SourceConfig,
    query_values: &BTreeMap<String, String>,
) -> Option<(String, String, BTreeMap<String, String>)> {
    if source.engine == SourceEngine::Fhir {
        if let Some(smoke) = &source.smoke_lookup {
            if let Some(value) = query_values.get(&smoke.field) {
                return Some((smoke.field.clone(), value.clone(), query_values.clone()));
            }
        }
    }
    query_values
        .iter()
        .next()
        .map(|(field, value)| (field.clone(), value.clone(), query_values.clone()))
}

pub(super) fn validate_batch_match_request(
    state: &AppState,
    body: &BatchMatchRequest,
) -> Result<(), Box<Response>> {
    if body.fields.is_empty() {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "fields projection is required",
        )));
    }
    for field in &body.fields {
        if field.is_empty() {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "fields projection entries are required",
            )));
        }
        if field.len() > state.config.limits.max_query_parameter_bytes {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "fields projection entry exceeds configured byte limit",
            )));
        }
    }
    if body.query_signature.is_empty() {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "query_signature is required",
        )));
    }
    if body.items.is_empty() {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "items are required",
        )));
    }
    if body.items.len() > state.config.limits.max_batch_items {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "batch item count exceeds configured limit",
        )));
    }
    for term in &body.query_signature {
        if term.field.is_empty() {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "query_signature field is required",
            )));
        }
        if term.field.len() > state.config.limits.max_query_parameter_bytes {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "query_signature field exceeds configured byte limit",
            )));
        }
        if term.op != "eq" {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "unsupported query operation",
            )));
        }
    }
    let mut request_ids = BTreeSet::new();
    for item in &body.items {
        if item.id.is_empty() {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "batch item id is required",
            )));
        }
        if !request_ids.insert(item.id.as_str()) {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "batch item id duplicated",
            )));
        }
        if item.values.len() != body.query_signature.len() {
            return Err(Box::new(problem(
                StatusCode::BAD_REQUEST,
                "batch item values must match query_signature length",
            )));
        }
        for value in &item.values {
            if value_query_size(value) > state.config.limits.max_query_parameter_bytes {
                return Err(Box::new(problem(
                    StatusCode::BAD_REQUEST,
                    "batch item value exceeds configured byte limit",
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn value_query_size(value: &Value) -> usize {
    match value {
        Value::String(value) => value.len(),
        other => other.to_string().len(),
    }
}

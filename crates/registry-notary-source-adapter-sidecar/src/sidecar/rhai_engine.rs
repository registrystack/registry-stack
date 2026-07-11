use super::*;

/// The async host backing a `script_rhai` run's `source.*` capabilities. It owns
/// everything the call needs by value (clones / `Arc`s), so it is `Send + Sync`
/// and outlives the bridged blocking execution. Every effect — target
/// resolution, allow-listing, SSRF policy, auth, rate limiting, bounded JSON
/// body handling — is reused from the `http_json` machinery; the script never
/// sees any of it.
struct RhaiHttpHost {
    state: AppState,
    source: SourceConfig,
    source_id: String,
    /// The resolved per-source credential object (secret fields are read by
    /// `apply_http_json_auth`). `Value::Null` when the source has no credential.
    credential: Value,
}

enum RhaiSourceRequest {
    Get,
    PostJson(Value),
}

#[async_trait::async_trait]
impl ScriptSourceHost for RhaiHttpHost {
    async fn source_get(
        &self,
        target: &str,
        path: &str,
        query: Value,
    ) -> Result<SourceResponse, SourceScriptError> {
        self.source_request(target, path, query, RhaiSourceRequest::Get)
            .await
    }

    async fn source_post_json(
        &self,
        target: &str,
        path: &str,
        query: Value,
        body: Value,
    ) -> Result<SourceResponse, SourceScriptError> {
        self.source_request(target, path, query, RhaiSourceRequest::PostJson(body))
            .await
    }
}

impl RhaiHttpHost {
    async fn source_request(
        &self,
        target: &str,
        path: &str,
        query: Value,
        request: RhaiSourceRequest,
    ) -> Result<SourceResponse, SourceScriptError> {
        let rhai = self
            .source
            .rhai
            .as_ref()
            .ok_or(SourceScriptError::HostDenied {
                reason: "missing rhai config".into(),
            })?;
        let target_config = rhai
            .targets
            .get(target)
            .ok_or(SourceScriptError::HostDenied {
                reason: "unknown target".into(),
            })?;

        // Reuse the http_json request preparation: it parses the base URL,
        // enforces `allowed_base_urls`, joins the (already canonicalized) path,
        // checks same-origin, and applies the SSRF/localhost client policy.
        let prepared = prepare_http_json_request(
            &self.state,
            &self.source_id,
            &self.source,
            &target_config.base_url,
            path,
        )
        .await
        .map_err(map_source_execution_error)?;

        let mut builder = match request {
            RhaiSourceRequest::Get => prepared.client.get(prepared.url),
            RhaiSourceRequest::PostJson(body) => {
                ensure_rhai_post_json_body_size(&body, self.state.config.limits.max_request_bytes)?;
                prepared.client.post(prepared.url).json(&body)
            }
        };
        if let Value::Object(params) = &query {
            for (name, value) in params {
                // Match the http_json contract: reject a query-parameter name
                // carrying control characters or whitespace rather than relying
                // solely on the client's URL encoder. A name can derive from
                // untrusted upstream data, so the call fails closed.
                if !is_valid_http_param_name(name) {
                    return Err(SourceScriptError::HostDenied {
                        reason: "invalid query parameter name".into(),
                    });
                }
                if let Some(rendered) = rhai_query_param_value(value) {
                    builder = builder.query(&[(name.as_str(), rendered)]);
                }
            }
        }
        // Static, operator-configured request headers (validated at startup as
        // non-restricted). Applied before auth so they can never shadow it.
        for (name, value) in &target_config.headers {
            builder = builder.header(name, value);
        }
        builder = apply_http_json_auth(
            &self.state,
            &self.source_id,
            &self.source,
            builder,
            target_config.auth.as_ref(),
            &self.credential,
        )
        .await
        .map_err(map_source_execution_error)?;

        // Honour the same rate-limit/backoff gate as http_json. A limiter
        // rejection is reported to the script as a 429 so `problem_code()`
        // surfaces `source.target_rate_limit`.
        if acquire_http_json_rate_or_error(&self.state, &self.source_id)
            .await
            .is_some()
        {
            return Err(SourceScriptError::HttpStatus { status: 429 });
        }

        let response = builder.send().await.map_err(|error| {
            if error.is_timeout() {
                SourceScriptError::Deadline
            } else {
                SourceScriptError::HttpTransport
            }
        })?;
        let status = response.status();
        let status_code = status.as_u16();

        // Per-target visibility gate: a 2xx, or a status this target explicitly
        // allows, is returned to the script; any other non-2xx terminates the
        // run as an upstream-status error (the engine's union `visible_statuses`
        // is only the ceiling — the host decides per target).
        if status.is_success() || target_config.visible_statuses.contains(&status_code) {
            let body = if status.is_success() {
                read_limited_json_or_empty_response(
                    response,
                    self.state.config.limits.max_output_bytes,
                )
                .await
                .map_err(map_source_execution_error)?
            } else {
                read_limited_optional_json_response(
                    response,
                    self.state.config.limits.max_output_bytes,
                )
                .await
                .map_err(map_source_execution_error)?
            };
            Ok(SourceResponse {
                status: status_code,
                body,
            })
        } else {
            Err(SourceScriptError::HttpStatus {
                status: status_code,
            })
        }
    }
}

pub(super) fn ensure_rhai_post_json_body_size(
    body: &Value,
    max_bytes: usize,
) -> Result<(), SourceScriptError> {
    let bytes = serde_json::to_vec(body).map_err(|_| SourceScriptError::HostDenied {
        reason: "request body is not serializable".into(),
    })?;
    if bytes.len() > max_bytes {
        return Err(SourceScriptError::HostDenied {
            reason: "request body exceeds configured byte limit".into(),
        });
    }
    Ok(())
}

/// Map the http_json outbound machinery's coarse error into the script host's
/// taxonomy. A transport timeout becomes a deadline; everything else collapses
/// to a transport failure (both ultimately surface as `source.unavailable`
/// except the timeout, which surfaces as `source.timeout`).
pub(super) fn map_source_execution_error(error: SourceExecutionError) -> SourceScriptError {
    match error {
        SourceExecutionError::HttpJsonTimeout => SourceScriptError::Deadline,
        SourceExecutionError::HttpJson | SourceExecutionError::HttpJsonBadRequest => {
            SourceScriptError::HttpTransport
        }
    }
}

/// Stringify a scalar query-parameter value the way http_json does; non-scalar
/// values (objects, arrays, null) are dropped, matching query-string semantics.
pub(super) fn rhai_query_param_value(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

pub(super) async fn execute_rhai(
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
            execute_rhai_batch(state, source_id, source, &request),
        )
        .await
        .map_err(|_| SourceExecutionError::HttpJsonTimeout)??;
        return Ok(SourceExecution {
            value,
            worker_id: "script_rhai".to_string(),
        });
    }

    execute_rhai_lookup(state, source_id, source, request).await
}

pub(super) async fn execute_rhai_lookup(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: Value,
) -> Result<SourceExecution, SourceExecutionError> {
    // Presence is also enforced at validation/compile time; guard here so a
    // misconfigured source fails closed rather than reaching the host.
    let _rhai = source.rhai.as_ref().ok_or(SourceExecutionError::HttpJson)?;
    let lookup = request
        .get("lookup")
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let lookup_field = lookup
        .get("field")
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let lookup_value = lookup
        .get("value")
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let fields = request_fields(&request)?;
    let limit = request.get("limit").and_then(Value::as_u64).unwrap_or(2);
    let purpose = request
        .get("purpose")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let dataset = request
        .get("dataset")
        .and_then(Value::as_str)
        .unwrap_or(&source.dataset)
        .to_string();
    let entity = request
        .get("entity")
        .and_then(Value::as_str)
        .unwrap_or(&source.entity)
        .to_string();

    let credential = state
        .credentials
        .get(source_id)
        .cloned()
        .unwrap_or(Value::Null);
    // The script only ever sees the whitelisted public credential fields, never
    // a raw secret (mirrors the http_json `public_credential` projection).
    let credential_public = public_credential(source, &credential);

    let ctx = ScriptCtx::new(
        source_id,
        dataset,
        entity,
        Lookup {
            field: lookup_field.to_string(),
            value: lookup_value.to_string(),
        },
        purpose,
    )
    .fields(fields)
    .limit(limit)
    .credential_public(credential_public);

    let engine = state
        .rhai_engines
        .get(source_id)
        .cloned()
        .ok_or(SourceExecutionError::HttpJson)?;

    let host = RhaiHttpHost {
        state: state.clone(),
        source: source.clone(),
        source_id: source_id.to_string(),
        credential,
    };

    match engine.execute(Arc::new(host), ctx).await {
        Ok(records) => Ok(SourceExecution {
            value: json!({ "data": records }),
            worker_id: "script_rhai".to_string(),
        }),
        // Mirror http_json: a classified script error is returned as the
        // sidecar's `{ "error": { "code": ... } }` envelope (never the script
        // source, a response body, or a secret), and the public problem code is
        // the engine's stable mapping.
        Err(error) => Ok(SourceExecution {
            value: json!({ "error": { "code": error.problem_code() } }),
            worker_id: "script_rhai".to_string(),
        }),
    }
}

pub(super) async fn execute_rhai_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    match source.batch.mode {
        SourceBatchMode::SequentialLookup => {
            execute_rhai_sequential_batch(state, source_id, source, request).await
        }
        SourceBatchMode::ParallelLookup => {
            execute_rhai_parallel_batch(state, source_id, source, request).await
        }
        SourceBatchMode::WorkflowBatch | SourceBatchMode::NativeBatch => {
            Err(SourceExecutionError::HttpJsonBadRequest)
        }
    }
}

pub(super) async fn execute_rhai_sequential_batch(
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
        let execution = execute_rhai_lookup(state, source_id, source, lookup_request).await?;
        if let Some(error) = execution.value.get("error") {
            if shared_credential_error(error) {
                return Ok(json!({ "error": error }));
            }
            responses.push(json!({ "id": id, "error": error }));
        } else if let Some(data) = execution.value.get("data") {
            responses.push(json!({ "id": id, "data": data }));
        } else {
            return Err(SourceExecutionError::HttpJson);
        }
    }
    Ok(json!({ "items": responses }))
}

pub(super) async fn execute_rhai_parallel_batch(
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
            let execution = execute_rhai_lookup(
                &task_state,
                &task_source_id,
                task_source.as_ref(),
                lookup_request,
            )
            .await?;
            Ok::<_, SourceExecutionError>((idx, id, execution.value))
        });
    }

    let mut responses = vec![Value::Null; items.len()];
    while let Some(joined) = tasks.join_next().await {
        let (idx, id, value) = joined.map_err(|_| SourceExecutionError::HttpJson)??;
        if let Some(error) = value.get("error") {
            if shared_credential_error(error) {
                tasks.abort_all();
                return Ok(json!({ "error": error }));
            }
            responses[idx] = json!({ "id": id, "error": error });
        } else if let Some(data) = value.get("data") {
            responses[idx] = json!({ "id": id, "data": data });
        } else {
            tasks.abort_all();
            return Err(SourceExecutionError::HttpJson);
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

/// Compile every `script_rhai` source's engine once, keyed by `source_id`.
///
/// The compile uses the union of all targets' `visible_statuses` so the engine
/// surfaces any status some target allows; per-target gating then happens in the
/// host. A compile failure is a configuration error that fails startup. The
/// engine carries no script source in its error `Display`, so the message is
/// safe to surface.
pub(super) fn compile_rhai_engines(
    config: &SidecarConfig,
) -> Result<BTreeMap<String, Arc<ScriptEngine>>, SidecarError> {
    let mut engines = BTreeMap::new();
    for (source_id, source) in &config.sources {
        if source.engine != SourceEngine::ScriptRhai {
            continue;
        }
        let rhai = source.rhai.as_ref().ok_or_else(|| {
            SidecarError::Config(format!(
                "source {source_id} engine script_rhai requires a rhai config"
            ))
        })?;
        let policy = rhai.limits.to_policy(rhai_union_visible_statuses(rhai));
        let engine =
            ScriptEngine::compile(&rhai.script, &rhai.entrypoint, &policy).map_err(|error| {
                SidecarError::Config(format!(
                    "source {source_id} rhai script failed to compile: {error}"
                ))
            })?;
        engines.insert(source_id.clone(), Arc::new(engine));
    }
    Ok(engines)
}

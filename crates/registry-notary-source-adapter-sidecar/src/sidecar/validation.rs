use super::*;

pub(super) fn validate_config(config: &SidecarConfig) -> Result<(), SidecarError> {
    if config.auth.bearer_tokens.is_empty() {
        return Err(SidecarError::Config(
            "at least one sidecar bearer token is required".to_string(),
        ));
    }
    for token in &config.auth.bearer_tokens {
        match (&token.token, &token.hash_env) {
            (None, Some(hash_env)) if !hash_env.trim().is_empty() => {}
            (Some(_), _) => {
                return Err(SidecarError::Config(format!(
                    "bearer token {} must use hash_env; plaintext token is not supported",
                    token.id
                )));
            }
            (None, None) => {
                return Err(SidecarError::Config(format!(
                    "bearer token {} must set hash_env",
                    token.id
                )));
            }
            (None, Some(_)) => {
                return Err(SidecarError::Config(format!(
                    "bearer token {} hash_env must be non-empty",
                    token.id
                )));
            }
        }
    }
    if config.sources.is_empty() {
        return Err(SidecarError::Config(
            "at least one source binding is required".to_string(),
        ));
    }
    if config.server.request_timeout_ms == 0 {
        return Err(SidecarError::Config(
            "server.request_timeout_ms must be greater than zero".to_string(),
        ));
    }
    if config.server.request_body_timeout_ms == 0 {
        return Err(SidecarError::Config(
            "server.request_body_timeout_ms must be greater than zero".to_string(),
        ));
    }
    if config.server.http1_header_read_timeout_ms == 0 {
        return Err(SidecarError::Config(
            "server.http1_header_read_timeout_ms must be greater than zero".to_string(),
        ));
    }
    if config.server.max_connections == 0 {
        return Err(SidecarError::Config(
            "server.max_connections must be greater than zero".to_string(),
        ));
    }
    if config.limits.max_workers == 0 {
        return Err(SidecarError::Config(
            "limits.max_workers must be greater than zero".to_string(),
        ));
    }
    if config.limits.worker_timeout_ms == 0 {
        return Err(SidecarError::Config(
            "limits.worker_timeout_ms must be greater than zero".to_string(),
        ));
    }
    match config.limits.max_worker_memory_mb {
        Some(0) => {
            return Err(SidecarError::Config(
                "limits.max_worker_memory_mb must be greater than zero".to_string(),
            ));
        }
        Some(_) => {}
        None => {}
    }
    if config.limits.max_output_bytes == 0
        || config.limits.max_request_bytes == 0
        || config.limits.max_query_parameter_bytes == 0
        || config.limits.max_batch_items == 0
    {
        return Err(SidecarError::Config(
            "byte limits must be greater than zero".to_string(),
        ));
    }
    if config.limits.batch_timeout_ms == Some(0) {
        return Err(SidecarError::Config(
            "limits.batch_timeout_ms must be greater than zero".to_string(),
        ));
    }
    for (source_id, source) in &config.sources {
        if source.limits.max_in_flight == Some(0) {
            return Err(SidecarError::Config(format!(
                "source {source_id} limits.max_in_flight must be greater than zero"
            )));
        }
        if source.limits.requests_per_second == Some(0) {
            return Err(SidecarError::Config(format!(
                "source {source_id} limits.requests_per_second must be greater than zero"
            )));
        }
        if source.limits.burst == Some(0) {
            return Err(SidecarError::Config(format!(
                "source {source_id} limits.burst must be greater than zero"
            )));
        }
        if source.limits.burst.is_some() && source.limits.requests_per_second.is_none() {
            return Err(SidecarError::Config(format!(
                "source {source_id} limits.burst requires limits.requests_per_second"
            )));
        }
        if source.batch.max_parallel == Some(0) {
            return Err(SidecarError::Config(format!(
                "source {source_id} batch.max_parallel must be greater than zero"
            )));
        }
        if let Some(cache) = &source.cache {
            if cache.exact_match_ttl_ms == Some(0) || cache.not_found_ttl_ms == Some(0) {
                return Err(SidecarError::Config(format!(
                    "source {source_id} cache TTLs must be greater than zero"
                )));
            }
            if cache.max_entries == Some(0) {
                return Err(SidecarError::Config(format!(
                    "source {source_id} cache.max_entries must be greater than zero"
                )));
            }
            if cache.exact_match_ttl_ms.is_none() && cache.not_found_ttl_ms.is_none() {
                return Err(SidecarError::Config(format!(
                    "source {source_id} cache must configure at least one TTL"
                )));
            }
        }
        validate_source_execution(source_id, source)?;
        if source
            .allowed_base_urls
            .iter()
            .any(|url| url.trim().is_empty())
        {
            return Err(SidecarError::Config(format!(
                "source {source_id} allowed_base_urls must not contain empty values"
            )));
        }
        let Some(smoke) = &source.smoke_lookup else {
            return Err(SidecarError::Config(format!(
                "source {source_id} smoke_lookup is required for readiness"
            )));
        };
        if !smoke.fields.iter().any(|field| field == &smoke.field) {
            return Err(SidecarError::Config(format!(
                "source {source_id} smoke_lookup.fields must include lookup field {}",
                smoke.field
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_source_execution(
    source_id: &str,
    source: &SourceConfig,
) -> Result<(), SidecarError> {
    match source.engine {
        SourceEngine::HttpJson => validate_http_json_source(source_id, source),
        SourceEngine::HttpFlow => validate_http_flow_source(source_id, source),
        SourceEngine::Fhir => validate_fhir_source(source_id, source),
        SourceEngine::ScriptRhai => validate_rhai_source(source_id, source),
    }
}

pub(super) fn validate_http_json_source(
    source_id: &str,
    source: &SourceConfig,
) -> Result<(), SidecarError> {
    if source.http_flow.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_flow config is not valid when engine is http_json"
        )));
    }
    if source.fhir.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir config is not valid when engine is http_json"
        )));
    }
    if source.credential_env.trim().is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} credential_env is required for http_json sources"
        )));
    }
    let http_json = source.http_json.as_ref().ok_or_else(|| {
        SidecarError::Config(format!(
            "source {source_id} http_json config is required when engine is http_json"
        ))
    })?;
    if http_json.base_url.cel.trim().is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_json.base_url.cel must be non-empty"
        )));
    }
    validate_http_json_path(source_id, "http_json.path", &http_json.path)?;
    if source.batch.mode == SourceBatchMode::NativeBatch && http_json.batch.is_none() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_json.batch is required when batch.mode is native_batch"
        )));
    }
    if source.batch.mode == SourceBatchMode::WorkflowBatch {
        return Err(SidecarError::Config(format!(
            "source {source_id} batch.mode workflow_batch was retired with the worker engine"
        )));
    }
    if source.batch.mode != SourceBatchMode::ParallelLookup && source.batch.max_parallel.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} batch.max_parallel requires batch.mode parallel_lookup"
        )));
    }
    if http_json.response.records.cel.trim().is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_json.response.records.cel must be non-empty"
        )));
    }
    if source.allowed_base_urls.is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} allowed_base_urls is required for http_json"
        )));
    }
    for (name, expr) in &http_json.query {
        validate_http_header_or_query_name(source_id, "query", name)?;
        validate_http_json_cel(source_id, &format!("http_json.query.{name}"), expr)?;
    }
    for (name, expr) in &http_json.headers {
        validate_http_header_or_query_name(source_id, "headers", name)?;
        validate_http_json_cel(source_id, &format!("http_json.headers.{name}"), expr)?;
    }
    validate_http_json_cel(source_id, "http_json.base_url", &http_json.base_url)?;
    validate_http_json_cel(
        source_id,
        "http_json.response.records",
        &http_json.response.records,
    )?;
    if let Some(batch) = &http_json.batch {
        validate_http_json_path(source_id, "http_json.batch.path", &batch.path)?;
        for (name, expr) in &batch.query {
            validate_http_header_or_query_name(source_id, "query", name)?;
            validate_http_json_cel(source_id, &format!("http_json.batch.query.{name}"), expr)?;
        }
        for (name, expr) in &batch.headers {
            validate_http_header_or_query_name(source_id, "headers", name)?;
            validate_http_json_cel(source_id, &format!("http_json.batch.headers.{name}"), expr)?;
        }
        validate_http_json_cel(
            source_id,
            "http_json.batch.response.records",
            &batch.response.records,
        )?;
        validate_http_json_cel(
            source_id,
            "http_json.batch.response.record_key",
            &batch.response.record_key,
        )?;
        validate_http_json_cel(
            source_id,
            "http_json.batch.response.item_key",
            &batch.response.item_key,
        )?;
    }
    if let Some(auth) = &http_json.auth {
        validate_http_json_auth_config(source_id, source, "http_json.auth", auth)?;
    }
    Ok(())
}

pub(super) fn validate_http_flow_source(
    source_id: &str,
    source: &SourceConfig,
) -> Result<(), SidecarError> {
    if source.http_json.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_json config is not valid when engine is http_flow"
        )));
    }
    if source.fhir.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir config is not valid when engine is http_flow"
        )));
    }
    if source.credential_env.trim().is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} credential_env is required for http_flow sources"
        )));
    }
    if matches!(
        source.batch.mode,
        SourceBatchMode::WorkflowBatch | SourceBatchMode::NativeBatch
    ) {
        return Err(SidecarError::Config(format!(
            "source {source_id} batch.mode is not supported for http_flow sources"
        )));
    }
    if source.batch.mode != SourceBatchMode::ParallelLookup && source.batch.max_parallel.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} batch.max_parallel requires batch.mode parallel_lookup"
        )));
    }
    if source.allowed_base_urls.is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} allowed_base_urls is required for http_flow"
        )));
    }
    let flow = source.http_flow.as_ref().ok_or_else(|| {
        SidecarError::Config(format!(
            "source {source_id} http_flow config is required when engine is http_flow"
        ))
    })?;
    if flow.steps.len() < 2 {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_flow.steps must contain at least two steps"
        )));
    }
    if flow.steps.len() > 5 {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_flow.steps must not contain more than five steps"
        )));
    }
    if let Some(max_steps) = flow.max_steps {
        if max_steps == 0 || max_steps > 5 {
            return Err(SidecarError::Config(format!(
                "source {source_id} http_flow.max_steps must be between one and five"
            )));
        }
        if flow.steps.len() > max_steps {
            return Err(SidecarError::Config(format!(
                "source {source_id} http_flow.steps exceeds http_flow.max_steps"
            )));
        }
    }
    if flow.timeout_ms == Some(0) {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_flow.timeout_ms must be greater than zero"
        )));
    }
    validate_http_json_cel(source_id, "http_flow.output.records", &flow.output.records)?;

    let mut step_ids = BTreeSet::new();
    let mut bindings = BTreeSet::new();
    for step in &flow.steps {
        validate_http_flow_identifier(source_id, "http_flow step id", &step.id)?;
        if !step_ids.insert(step.id.clone()) {
            return Err(SidecarError::Config(format!(
                "source {source_id} http_flow step {} is duplicated",
                step.id
            )));
        }
        if let Some(when) = &step.when {
            validate_http_json_cel(
                source_id,
                &format!("http_flow.steps.{}.when", step.id),
                when,
            )?;
        }
        if step.request.method != HttpJsonMethod::Get {
            return Err(SidecarError::Config(format!(
                "source {source_id} http_flow step {} only supports GET in v1",
                step.id
            )));
        }
        validate_http_flow_base_url(source_id, source, &step.id, &step.request.base_url)?;
        validate_http_json_path(
            source_id,
            &format!("http_flow.steps.{}.request.path", step.id),
            &step.request.path,
        )?;
        for (name, expr) in &step.request.query {
            validate_http_header_or_query_name(source_id, "query", name)?;
            validate_http_json_cel(
                source_id,
                &format!("http_flow.steps.{}.request.query.{name}", step.id),
                expr,
            )?;
        }
        for (name, expr) in &step.request.headers {
            validate_http_header_or_query_name(source_id, "headers", name)?;
            validate_http_json_cel(
                source_id,
                &format!("http_flow.steps.{}.request.headers.{name}", step.id),
                expr,
            )?;
        }
        if let Some(response) = &step.response {
            for (name, expr) in &response.bind {
                validate_http_flow_identifier(source_id, "http_flow binding", name)?;
                if http_flow_reserved_binding(name) {
                    return Err(SidecarError::Config(format!(
                        "source {source_id} http_flow binding {name} is reserved"
                    )));
                }
                if !bindings.insert(name.clone()) {
                    return Err(SidecarError::Config(format!(
                        "source {source_id} http_flow binding {name} is duplicated"
                    )));
                }
                validate_http_json_cel(
                    source_id,
                    &format!("http_flow.steps.{}.response.bind.{name}", step.id),
                    expr,
                )?;
            }
        }
        for status in step.on_status.keys() {
            let status_code = status.parse::<u16>().map_err(|_| {
                SidecarError::Config(format!(
                    "source {source_id} http_flow step {} on_status keys must be HTTP status codes",
                    step.id
                ))
            })?;
            if !(100..=599).contains(&status_code) {
                return Err(SidecarError::Config(format!(
                    "source {source_id} http_flow step {} on_status keys must be HTTP status codes",
                    step.id
                )));
            }
        }
        if let Some(auth) = &step.request.auth {
            validate_http_json_auth_config(
                source_id,
                source,
                &format!("http_flow.steps.{}.request.auth", step.id),
                auth,
            )?;
        }
    }
    Ok(())
}

pub(super) fn validate_fhir_source(
    source_id: &str,
    source: &SourceConfig,
) -> Result<(), SidecarError> {
    if source.http_json.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_json config is not valid when engine is fhir"
        )));
    }
    if source.http_flow.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_flow config is not valid when engine is fhir"
        )));
    }
    if source.cache.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} cache is not supported for fhir sources"
        )));
    }
    if matches!(
        source.batch.mode,
        SourceBatchMode::WorkflowBatch | SourceBatchMode::NativeBatch
    ) {
        return Err(SidecarError::Config(format!(
            "source {source_id} batch.mode is not supported for fhir sources"
        )));
    }
    if source.batch.mode != SourceBatchMode::ParallelLookup && source.batch.max_parallel.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} batch.max_parallel requires batch.mode parallel_lookup"
        )));
    }
    if source.allowed_base_urls.is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} allowed_base_urls is required for fhir"
        )));
    }
    let fhir = source.fhir.as_ref().ok_or_else(|| {
        SidecarError::Config(format!(
            "source {source_id} fhir config is required when engine is fhir"
        ))
    })?;
    if fhir.version != "R4" {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir.version must be R4"
        )));
    }
    if fhir.search_method != "get" {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir.search_method must be get"
        )));
    }
    if fhir.max_search_results == 0 {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir.max_search_results must be greater than zero"
        )));
    }
    if fhir
        .bearer_token_env
        .as_deref()
        .is_some_and(|env| env.trim().is_empty())
    {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir.bearer_token_env must not be empty"
        )));
    }
    let base_url = reqwest::Url::parse(&fhir.base_url).map_err(|_| {
        SidecarError::Config(format!(
            "source {source_id} fhir.base_url must be an absolute URL"
        ))
    })?;
    validate_fhir_base_url_policy(source_id, source, &base_url)?;
    ensure_allowed_base_url(source_id, source, &base_url)?;
    validate_fhir_node(source_id, "anchor", &fhir.anchor)?;
    let mut node_ids = BTreeSet::from([fhir.anchor.id.as_str()]);
    for relation in &fhir.relations {
        validate_fhir_node(
            source_id,
            &format!("relation {}", relation.id),
            &FhirNodeConfig {
                id: relation.id.clone(),
                resource_type: relation.resource_type.clone(),
                cardinality: relation.cardinality.clone(),
                search: relation.search.clone(),
            },
        )?;
        if !node_ids.insert(relation.id.as_str()) {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir node id {} is duplicated",
                relation.id
            )));
        }
    }
    for (field, projection) in &fhir.project {
        if field.trim().is_empty() {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir.project field must not be empty"
            )));
        }
        if !node_ids.contains(projection.node.as_str()) {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir.project.{field}.node is not defined"
            )));
        }
        if !projection.pointer.starts_with('/') {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir.project.{field}.pointer must be a JSON Pointer"
            )));
        }
        if let Some(value) = &projection.default_value {
            if value.is_object() || value.is_array() {
                return Err(SidecarError::Config(format!(
                    "source {source_id} fhir.project.{field}.default must be scalar"
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_rhai_source(
    source_id: &str,
    source: &SourceConfig,
) -> Result<(), SidecarError> {
    if source.http_json.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_json config is not valid when engine is script_rhai"
        )));
    }
    if source.http_flow.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_flow config is not valid when engine is script_rhai"
        )));
    }
    if source.fhir.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir config is not valid when engine is script_rhai"
        )));
    }
    if matches!(
        source.batch.mode,
        SourceBatchMode::WorkflowBatch | SourceBatchMode::NativeBatch
    ) {
        return Err(SidecarError::Config(format!(
            "source {source_id} batch.mode is not supported for script_rhai sources"
        )));
    }
    if source.batch.mode != SourceBatchMode::ParallelLookup && source.batch.max_parallel.is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} batch.max_parallel requires batch.mode parallel_lookup"
        )));
    }
    if source.allowed_base_urls.is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} allowed_base_urls is required for script_rhai"
        )));
    }
    let rhai = source.rhai.as_ref().ok_or_else(|| {
        SidecarError::Config(format!(
            "source {source_id} engine script_rhai requires a rhai config"
        ))
    })?;
    if rhai.targets.is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} rhai.targets must not be empty"
        )));
    }
    let mut requires_credential = false;
    for (target_id, target) in &rhai.targets {
        let base = reqwest::Url::parse(&target.base_url).map_err(|_| {
            SidecarError::Config(format!(
                "source {source_id} rhai.targets.{target_id}.base_url must be a URL"
            ))
        })?;
        ensure_allowed_base_url(source_id, source, &base).map_err(|_| {
            SidecarError::Config(format!(
                "source {source_id} rhai.targets.{target_id}.base_url is not in allowed_base_urls"
            ))
        })?;
        for status in &target.visible_statuses {
            if !(100..=599).contains(status) {
                return Err(SidecarError::Config(format!(
                    "source {source_id} rhai.targets.{target_id}.visible_statuses contains an invalid HTTP status {status}"
                )));
            }
        }
        for (name, value) in &target.headers {
            validate_http_request_header_name(
                source_id,
                &format!("rhai.targets.{target_id}.headers.{name}"),
                name,
            )?;
            if !is_valid_http_header_value(value) {
                return Err(SidecarError::Config(format!(
                    "source {source_id} rhai.targets.{target_id}.headers.{name} has an invalid value"
                )));
            }
        }
        if let Some(auth) = &target.auth {
            requires_credential = true;
            validate_http_json_auth_config(
                source_id,
                source,
                &format!("rhai.targets.{target_id}.auth"),
                auth,
            )?;
        }
    }
    // A credential env is only required when at least one target authenticates;
    // an unauthenticated script_rhai source may omit it entirely.
    if requires_credential && source.credential_env.trim().is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} credential_env is required when a rhai target configures auth"
        )));
    }
    // The script must compile under the same union policy used at runtime. This
    // validates the entrypoint's existence and the policy bounds up front. The
    // rhai error's Display is non-sensitive (no script source) and is surfaced.
    let policy = rhai.limits.to_policy(rhai_union_visible_statuses(rhai));
    ScriptEngine::compile(&rhai.script, &rhai.entrypoint, &policy).map_err(|error| {
        SidecarError::Config(format!(
            "source {source_id} rhai script failed to compile: {error}"
        ))
    })?;
    Ok(())
}

pub(super) fn validate_fhir_node(
    source_id: &str,
    label: &str,
    node: &FhirNodeConfig,
) -> Result<(), SidecarError> {
    if node.id.trim().is_empty() || node.resource_type.trim().is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir {label} id and resource_type are required"
        )));
    }
    if !is_fhir_resource_type(&node.resource_type) {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir {label} resource_type is invalid"
        )));
    }
    if !matches!(
        node.cardinality.as_str(),
        "one" | "zero_or_one" | "one_or_more" | "any"
    ) {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir {label} cardinality is unsupported"
        )));
    }
    if node.search.is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir {label} search must not be empty"
        )));
    }
    for search in &node.search {
        if search.param.trim().is_empty() {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir {label} search param is required"
            )));
        }
        if !matches!(
            search.search_type.as_str(),
            "token" | "reference" | "string" | "date" | "code"
        ) {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir {label} search type {} is unsupported",
                search.search_type
            )));
        }
        let value_sources = [
            search.value.is_some(),
            search.value_from_lookup.unwrap_or(false),
            search.value_from_query.is_some(),
            search.value_from_node.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if value_sources != 1 {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir {label} search {} must declare exactly one value source",
                search.param
            )));
        }
    }
    Ok(())
}

pub(super) fn is_fhir_resource_type(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|first| first.is_ascii_uppercase())
        && chars.all(|ch| ch.is_ascii_alphanumeric())
}

pub(super) fn validate_fhir_base_url_policy(
    source_id: &str,
    source: &SourceConfig,
    base_url: &reqwest::Url,
) -> Result<(), SidecarError> {
    let Some(host) = base_url.host_str() else {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir.base_url must include a host"
        )));
    };
    if host.eq_ignore_ascii_case("metadata.google.internal") {
        return Err(SidecarError::Config(format!(
            "source {source_id} fhir.base_url must not target metadata services"
        )));
    }
    match base_url.scheme() {
        "https" => {}
        "http" => {
            let ip = host.parse::<IpAddr>().ok().map(canonical_ip);
            if ip.is_some_and(is_cloud_metadata_ip) {
                return Err(SidecarError::Config(format!(
                    "source {source_id} fhir.base_url must not target metadata services"
                )));
            }
            let loopback = ip.is_some_and(|ip| ip.is_loopback()) || is_localhost_host(host);
            if loopback {
                if !(source.allow_insecure_localhost || source.allow_insecure_private_network) {
                    return Err(SidecarError::Config(format!(
                        "source {source_id} fhir.base_url requires allow_insecure_localhost for loopback http"
                    )));
                }
            } else if !source.allow_insecure_private_network {
                return Err(SidecarError::Config(format!(
                    "source {source_id} fhir.base_url must use https or explicitly allowed private-network http"
                )));
            } else {
                // Runtime request preparation resolves the hostname and applies
                // the private-network and metadata-service IP policy before any
                // outbound request is sent.
            }
        }
        _ => {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir.base_url must use https or explicitly allowed private-network http"
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_http_flow_base_url(
    source_id: &str,
    source: &SourceConfig,
    step_id: &str,
    base_url: &str,
) -> Result<(), SidecarError> {
    let base = reqwest::Url::parse(base_url).map_err(|_| {
        SidecarError::Config(format!(
            "source {source_id} http_flow step {step_id} request.base_url must be a URL"
        ))
    })?;
    ensure_allowed_base_url(source_id, source, &base)
}

pub(super) fn validate_http_flow_identifier(
    source_id: &str,
    label: &str,
    value: &str,
) -> Result<(), SidecarError> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(SidecarError::Config(format!(
            "source {source_id} {label} contains an invalid identifier"
        )))
    }
}

pub(super) fn http_flow_reserved_binding(value: &str) -> bool {
    matches!(
        value,
        "source_id"
            | "dataset"
            | "entity"
            | "lookup"
            | "fields"
            | "limit"
            | "purpose"
            | "correlation_id"
            | "credential_public"
            | "body"
            | "status"
            | "headers"
            | "items"
            | "query_signature"
            | "item"
            | "record"
    )
}

pub(super) fn validate_http_json_path(
    source_id: &str,
    label: &str,
    path: &str,
) -> Result<(), SidecarError> {
    if path.trim().is_empty()
        || !path.starts_with('/')
        || path.starts_with("//")
        || path
            .trim_start_matches('/')
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label} must be an absolute path under the configured base_url"
        )));
    }
    Ok(())
}

pub(super) fn validate_http_json_secret_ref(
    source_id: &str,
    label: &str,
    secret_ref: Option<&HttpJsonSecretRef>,
) -> Result<(), SidecarError> {
    let secret_ref = secret_ref.ok_or_else(|| {
        SidecarError::Config(format!(
            "source {source_id} {label} must name one top-level credential field"
        ))
    })?;
    if secret_ref.secret.trim().is_empty() || secret_ref.secret.contains('.') {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label} must name one top-level credential field"
        )));
    }
    Ok(())
}

/// Validate a shared `HttpJsonAuthConfig` for any engine (`http_json`,
/// `http_flow`, or a `script_rhai` target). `label_prefix` is the config path up
/// to and including `.auth`. Every kind names its secret via a top-level
/// credential field; `api_key_*` additionally require a valid, non-restricted
/// header name or query-parameter name. The secret value itself is resolved
/// from the credential env at request time and never appears in config.
pub(super) fn validate_http_json_auth_config(
    source_id: &str,
    source: &SourceConfig,
    label_prefix: &str,
    auth: &HttpJsonAuthConfig,
) -> Result<(), SidecarError> {
    match auth.kind {
        HttpJsonAuthKind::Bearer => {
            validate_http_json_secret_ref(
                source_id,
                &format!("{label_prefix}.token.secret"),
                auth.token.as_ref(),
            )?;
        }
        HttpJsonAuthKind::Basic => {
            validate_http_json_secret_ref(
                source_id,
                &format!("{label_prefix}.username.secret"),
                auth.username.as_ref(),
            )?;
            validate_http_json_secret_ref(
                source_id,
                &format!("{label_prefix}.password.secret"),
                auth.password.as_ref(),
            )?;
        }
        HttpJsonAuthKind::ApiKeyHeader => {
            validate_http_json_secret_ref(
                source_id,
                &format!("{label_prefix}.token.secret"),
                auth.token.as_ref(),
            )?;
            let Some(header) = auth.header.as_deref() else {
                return Err(SidecarError::Config(format!(
                    "source {source_id} {label_prefix}.header is required when type is api_key_header"
                )));
            };
            validate_http_request_header_name(
                source_id,
                &format!("{label_prefix}.header"),
                header,
            )?;
        }
        HttpJsonAuthKind::ApiKeyQuery => {
            validate_http_json_secret_ref(
                source_id,
                &format!("{label_prefix}.token.secret"),
                auth.token.as_ref(),
            )?;
            let Some(param) = auth.query_param.as_deref() else {
                return Err(SidecarError::Config(format!(
                    "source {source_id} {label_prefix}.query_param is required when type is api_key_query"
                )));
            };
            if !is_valid_http_param_name(param) {
                return Err(SidecarError::Config(format!(
                    "source {source_id} {label_prefix}.query_param is not a valid query parameter name"
                )));
            }
        }
        HttpJsonAuthKind::OAuth2ClientCredentials => {
            let token_url = auth.token_url.as_deref().ok_or_else(|| {
                SidecarError::Config(format!(
                    "source {source_id} {label_prefix}.token_url is required when type is oauth2_client_credentials"
                ))
            })?;
            validate_http_json_auth_token_url(
                source_id,
                source,
                &format!("{label_prefix}.token_url"),
                token_url,
            )?;
            validate_http_json_secret_ref(
                source_id,
                &format!("{label_prefix}.client_id.secret"),
                auth.client_id.as_ref(),
            )?;
            validate_http_json_secret_ref(
                source_id,
                &format!("{label_prefix}.client_secret.secret"),
                auth.client_secret.as_ref(),
            )?;
            if let Some(request_format) = &auth.request_format {
                if !matches!(request_format.as_str(), "form" | "json") {
                    return Err(SidecarError::Config(format!(
                        "source {source_id} {label_prefix}.request_format must be form or json"
                    )));
                }
            }
            if auth
                .scope
                .as_ref()
                .is_some_and(|scope| scope.trim().is_empty())
            {
                return Err(SidecarError::Config(format!(
                    "source {source_id} {label_prefix}.scope must not be empty when set"
                )));
            }
            if auth
                .audience
                .as_ref()
                .is_some_and(|audience| audience.trim().is_empty())
            {
                return Err(SidecarError::Config(format!(
                    "source {source_id} {label_prefix}.audience must not be empty when set"
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_http_json_auth_token_url(
    source_id: &str,
    source: &SourceConfig,
    label: &str,
    token_url: &str,
) -> Result<(), SidecarError> {
    let url = reqwest::Url::parse(token_url)
        .map_err(|_| SidecarError::Config(format!("source {source_id} {label} must be a URL")))?;
    if url.fragment().is_some() {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label} must not include a fragment"
        )));
    }
    if !matches!(url.scheme(), "http" | "https") {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label} must use http or https"
        )));
    }
    ensure_allowed_base_url(source_id, source, &url).map_err(|_| {
        SidecarError::Config(format!(
            "source {source_id} {label} is not in allowed_base_urls"
        ))
    })
}

/// HTTP request headers a target/source must not set directly: authentication
/// (use `auth`), cookies, host/length framing, hop-by-hop headers, and
/// forwarding headers. Comparison is case-insensitive; the `proxy-` prefix is
/// blanket-denied.
pub(super) fn is_restricted_request_header(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    if lower.starts_with("proxy-") {
        return true;
    }
    matches!(
        lower.as_str(),
        "authorization"
            | "cookie"
            | "host"
            | "content-length"
            | "connection"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "keep-alive"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
    )
}

/// Validate an operator-configured static request-header name: it must be a
/// legal header name and must not be one of the restricted headers.
pub(super) fn validate_http_request_header_name(
    source_id: &str,
    label: &str,
    name: &str,
) -> Result<(), SidecarError> {
    if !is_valid_http_header_name(name) {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label} is not a valid HTTP header name"
        )));
    }
    if is_restricted_request_header(name) {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label} sets a restricted header (auth, cookie, host, hop-by-hop, and forwarding headers are not allowed)"
        )));
    }
    Ok(())
}

/// A static request-header value is valid if it carries no CR/LF/NUL or other
/// ASCII control bytes (tab is permitted), preventing header injection. The
/// value is operator config, not a secret.
pub(super) fn is_valid_http_header_value(value: &str) -> bool {
    !value
        .bytes()
        .any(|byte| byte.is_ascii_control() && byte != b'\t')
}

pub(super) fn validate_http_json_cel(
    source_id: &str,
    label: &str,
    expr: &HttpJsonCelExpression,
) -> Result<(), SidecarError> {
    if expr.cel.trim().is_empty() {
        return Err(SidecarError::Config(format!(
            "source {source_id} {label}.cel must be non-empty"
        )));
    }
    Ok(())
}

/// Whether `name` is a valid HTTP header / query-parameter name: non-empty and
/// free of ASCII control characters and whitespace. Shared by the config-time
/// validator and the runtime `script_rhai` query-name guard so both engines
/// enforce the same invariant rather than relying solely on the client's URL
/// encoder.
pub(super) fn is_valid_http_param_name(name: &str) -> bool {
    !name.trim().is_empty()
        && !name
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
}

/// Whether `name` is a valid HTTP header name (an RFC 7230 token). This is
/// stricter than `is_valid_http_param_name`: `reqwest` rejects a non-token
/// header name when it builds the request, so checking it here turns what would
/// otherwise be a smoke-time or first-request failure into a config error that
/// blocks readiness. Query-parameter names keep the looser predicate because the
/// client percent-encodes them.
pub(super) fn is_valid_http_header_name(name: &str) -> bool {
    reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_ok()
}

pub(super) fn validate_http_header_or_query_name(
    source_id: &str,
    section: &str,
    name: &str,
) -> Result<(), SidecarError> {
    // Header names must be valid HTTP tokens; query-parameter names use the
    // looser control/whitespace check (the client percent-encodes them).
    let valid = if section == "headers" {
        is_valid_http_header_name(name)
    } else {
        is_valid_http_param_name(name)
    };
    if !valid {
        return Err(SidecarError::Config(format!(
            "source {source_id} http_json.{section} contains an invalid name"
        )));
    }
    Ok(())
}

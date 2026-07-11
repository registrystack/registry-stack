use super::*;

pub(super) struct SidecarAuditPipeline {
    pub(super) sink: JsonlFileSink,
    pub(super) chain: OnceCell<ChainState>,
    pub(super) profile: AuditProfile,
}

impl SidecarAuditPipeline {
    pub(super) fn from_config(config: &SidecarAuditConfig) -> Result<Option<Self>, SidecarError> {
        match config.sink.as_str() {
            "none" => Ok(None),
            "file" | "jsonl" => {
                let path = config.path.as_deref().ok_or_else(|| {
                    SidecarError::Config(
                        "audit.path is required when audit.sink is file or jsonl".to_string(),
                    )
                })?;
                let hash_secret_env = config.hash_secret_env.as_deref().ok_or_else(|| {
                    SidecarError::Config(
                        "audit.hash_secret_env is required when audit.sink is file or jsonl"
                            .to_string(),
                    )
                })?;
                let profile = AuditProfile::production_from_env(hash_secret_env)?;
                let sink =
                    JsonlFileSink::with_rotation(path, config.max_size_bytes(), config.max_files());
                Ok(Some(Self {
                    sink,
                    chain: OnceCell::new(),
                    profile,
                }))
            }
            sink => Err(SidecarError::Config(format!(
                "audit.sink {sink} is unsupported"
            ))),
        }
    }

    pub(super) async fn emit(
        &self,
        record: Value,
    ) -> Result<(), registry_platform_audit::AuditError> {
        let chain = self
            .chain
            .get_or_try_init(|| async { self.profile.bootstrap_or_start_empty(&self.sink).await })
            .await?;
        chain.append(&self.sink, record).await?;
        Ok(())
    }

    pub(super) async fn probe_startup_writable(
        &self,
        assurance: &SidecarAssurance,
    ) -> Result<(), registry_platform_audit::AuditError> {
        self.emit(json!({
            "event_type": "registry-notary-source-adapter-sidecar.startup_audit_probe",
            "phase": "startup",
            "outcome": "writable",
            "product": assurance.product.as_str(),
            "instance_id": assurance.instance_id.as_str(),
            "environment": assurance.environment.as_str(),
            "stream_id": assurance.stream_id.as_str(),
            "bundle_id": assurance.bundle_id.as_str(),
            "sequence": assurance.sequence,
            "config_hash": assurance.config_hash.as_str(),
            "timestamp": Utc::now().to_rfc3339(),
        }))
        .await
    }

    pub(super) fn hash(&self, value: &str) -> String {
        self.profile.key_hasher().hash(value)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct MetricKey {
    source_id: String,
    outcome: String,
    engine: Option<String>,
    step_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct MetricValue {
    count: u64,
    duration_ms_total: u64,
    items_total: u64,
}

pub(super) async fn metrics(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if state.config.server.metrics_require_auth {
        if let Err(response) = authorize(&state, &headers) {
            return *response;
        }
    }
    let mut body = String::new();
    body.push_str("# TYPE registry_notary_source_adapter_sidecar_source_permits gauge\n");
    for (source_id, source) in &state.config.sources {
        let max_permits = source
            .limits
            .max_in_flight
            .unwrap_or(state.config.limits.max_workers);
        let available = state
            .source_limiters
            .get(source_id)
            .map(|limiter| limiter.available_permits())
            .unwrap_or(0);
        let in_flight = max_permits.saturating_sub(available);
        for (label, value) in [
            ("max", max_permits),
            ("available", available),
            ("in_flight", in_flight),
        ] {
            body.push_str(&format!(
                "registry_notary_source_adapter_sidecar_source_permits{{source_id=\"{}\",state=\"{}\"}} {}\n",
                escape_metric_label(source_id),
                label,
                value
            ));
        }
    }
    let client_counts = {
        let clients = state.http_json_clients.lock().await;
        let mut counts = BTreeMap::<String, usize>::new();
        for key in clients.keys() {
            if let Some((source_id, _)) = key.split_once('|') {
                *counts.entry(source_id.to_string()).or_default() += 1;
            }
        }
        counts
    };
    if !client_counts.is_empty() {
        body.push_str("# TYPE registry_notary_source_adapter_sidecar_http_json_clients gauge\n");
        for (source_id, count) in client_counts {
            body.push_str(&format!(
                "registry_notary_source_adapter_sidecar_http_json_clients{{source_id=\"{}\"}} {}\n",
                escape_metric_label(&source_id),
                count
            ));
        }
    }
    let metrics = state.metrics.lock().await;
    if !metrics.is_empty() {
        body.push_str("# TYPE registry_notary_source_adapter_sidecar_lookup_total counter\n");
        body.push_str(
            "# TYPE registry_notary_source_adapter_sidecar_lookup_duration_ms_total counter\n",
        );
        body.push_str("# TYPE registry_notary_source_adapter_sidecar_lookup_items_total counter\n");
    }
    for (key, value) in metrics.iter() {
        let labels = metric_labels(key);
        body.push_str(&format!(
            "registry_notary_source_adapter_sidecar_lookup_total{{{labels}}} {}\n",
            value.count
        ));
        body.push_str(&format!(
            "registry_notary_source_adapter_sidecar_lookup_duration_ms_total{{{labels}}} {}\n",
            value.duration_ms_total
        ));
        body.push_str(&format!(
            "registry_notary_source_adapter_sidecar_lookup_items_total{{{labels}}} {}\n",
            value.items_total
        ));
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

pub(super) fn metric_labels(key: &MetricKey) -> String {
    let mut labels = vec![
        format!("source_id=\"{}\"", escape_metric_label(&key.source_id)),
        format!("outcome=\"{}\"", escape_metric_label(&key.outcome)),
    ];
    if let Some(engine) = &key.engine {
        labels.push(format!("engine=\"{}\"", escape_metric_label(engine)));
    }
    if let Some(step_id) = &key.step_id {
        labels.push(format!("step_id=\"{}\"", escape_metric_label(step_id)));
    }
    labels.join(",")
}

pub(super) async fn sidecar_audit_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_string();
    let purpose = request
        .headers()
        .get("data-purpose")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let correlation_id = request
        .headers()
        .get("x-correlation-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    if !is_sidecar_data_route(&path) {
        return next.run(request).await;
    }
    let Some(audit) = state.audit.as_ref() else {
        return next.run(request).await;
    };
    let attempted = sidecar_audit_record(
        audit,
        "attempt",
        &method,
        &path,
        None,
        purpose.clone(),
        correlation_id.clone(),
    );
    if let Err(error) = audit.emit(attempted).await {
        return sidecar_audit_write_failed(error, &method, &path);
    }

    let response = next.run(request).await;
    let status = response.status().as_u16();
    let event = sidecar_audit_record(
        audit,
        "outcome",
        &method,
        &path,
        Some(status),
        purpose,
        correlation_id,
    );
    match audit.emit(event).await {
        Ok(()) => response,
        Err(error) => sidecar_audit_write_failed(error, &method, &path),
    }
}

pub(super) fn sidecar_audit_write_failed(
    error: registry_platform_audit::AuditError,
    method: &str,
    path: &str,
) -> Response {
    warn!(
        error = %error,
        method = method,
        path = path,
        "sidecar audit write failed"
    );
    problem_with_code(
        StatusCode::INTERNAL_SERVER_ERROR,
        "sidecar audit write failed",
        "audit.write_failed",
    )
}

pub(super) fn is_sidecar_data_route(path: &str) -> bool {
    path.starts_with("/v1/datasets/") && path.contains("/records")
}

pub(super) fn sidecar_audit_record(
    audit: &SidecarAuditPipeline,
    phase: &str,
    method: &str,
    path: &str,
    status: Option<u16>,
    purpose: Option<String>,
    correlation_id: Option<String>,
) -> Value {
    let (dataset, entity) = sidecar_dataset_entity(path);
    json!({
        "event_type": "registry-notary-source-adapter-sidecar.data_route",
        "phase": phase,
        "method": method,
        "path": path,
        "status": status,
        "decision": match status {
            Some(status) if status < 400 => "permitted",
            Some(_) => "denied",
            None => "attempted",
        },
        "dataset": dataset,
        "entity": entity,
        "purpose_hash": purpose.as_deref().map(|value| audit.hash(value)),
        "correlation_id_hash": correlation_id.as_deref().map(|value| audit.hash(value)),
    })
}

pub(super) fn sidecar_dataset_entity(path: &str) -> (Option<String>, Option<String>) {
    let mut segments = path.split('/').filter(|segment| !segment.is_empty());
    match (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        (Some("v1"), Some("datasets"), Some(dataset), Some("entities"), Some(entity)) => {
            (Some(dataset.to_string()), Some(entity.to_string()))
        }
        _ => (None, None),
    }
}

pub(super) async fn record_metric_with_items(
    state: &AppState,
    source_id: &str,
    outcome: &str,
    duration: Duration,
    items: usize,
) {
    record_metric_with_labels(state, source_id, outcome, duration, items, None, None).await;
}

pub(super) async fn record_metric_with_labels(
    state: &AppState,
    source_id: &str,
    outcome: &str,
    duration: Duration,
    items: usize,
    engine: Option<&str>,
    step_id: Option<&str>,
) {
    let key = MetricKey {
        source_id: source_id.to_string(),
        outcome: outcome.to_string(),
        engine: engine.map(ToOwned::to_owned),
        step_id: step_id.map(ToOwned::to_owned),
    };
    let mut metrics = state.metrics.lock().await;
    let value = metrics.entry(key).or_default();
    value.count = value.count.saturating_add(1);
    value.duration_ms_total = value
        .duration_ms_total
        .saturating_add(duration.as_millis() as u64);
    value.items_total = value.items_total.saturating_add(items as u64);
}

pub(super) async fn record_http_flow_metric(
    state: &AppState,
    source_id: &str,
    step_id: Option<&str>,
    outcome: &str,
    items: usize,
) {
    record_metric_with_labels(
        state,
        source_id,
        outcome,
        Duration::ZERO,
        items,
        Some("http_flow"),
        step_id,
    )
    .await;
}

pub(super) async fn acquire_http_json_rate_or_error(
    state: &AppState,
    source_id: &str,
) -> Option<Value> {
    let runtime = state.source_runtime.get(source_id)?;
    if let Some(retry_after) = source_backoff_retry_after(runtime).await {
        record_metric_with_items(state, source_id, "source_backoff", Duration::ZERO, 1).await;
        return Some(json!({
            "error": {
                "code": "source.target_rate_limit",
                "retry_after_seconds": retry_after
            }
        }));
    }
    let Some(rate_limiter) = &runtime.rate_limiter else {
        return None;
    };
    let mut bucket = rate_limiter.lock().await;
    if let Err(wait) = bucket.try_take(Instant::now()) {
        let retry_after = duration_retry_after_seconds(wait);
        drop(bucket);
        record_metric_with_items(state, source_id, "source_rate_limited", Duration::ZERO, 1).await;
        return Some(json!({
            "error": {
                "code": "source.target_rate_limit",
                "retry_after_seconds": retry_after
            }
        }));
    }
    None
}

pub(super) async fn source_backoff_retry_after(runtime: &SourceRuntimeState) -> Option<u64> {
    let now = Instant::now();
    let mut backoff = runtime.backoff_until.lock().await;
    let until = backoff.as_ref().copied()?;
    if until <= now {
        *backoff = None;
        None
    } else {
        Some(duration_retry_after_seconds(until.duration_since(now)))
    }
}

pub(super) fn duration_retry_after_seconds(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
        .max(1)
}

pub(super) async fn remember_source_backoff(state: &AppState, source_id: &str, response: &Value) {
    let Some(error) = response.get("error").and_then(Value::as_object) else {
        return;
    };
    if !matches!(
        error.get("code").and_then(Value::as_str),
        Some("target_rate_limit" | "source.target_rate_limit")
    ) {
        return;
    }
    let seconds = error
        .get("retry_after_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(state.config.limits.retry_after_seconds)
        .max(1);
    if let Some(runtime) = state.source_runtime.get(source_id) {
        *runtime.backoff_until.lock().await = Some(Instant::now() + Duration::from_secs(seconds));
    }
}

pub(super) async fn remember_source_backoff_seconds(
    state: &AppState,
    source_id: &str,
    seconds: u64,
) {
    if let Some(runtime) = state.source_runtime.get(source_id) {
        *runtime.backoff_until.lock().await =
            Some(Instant::now() + Duration::from_secs(seconds.max(1)));
    }
}

pub(super) async fn acquire_source_permit(
    state: &Arc<AppState>,
    source_id: &str,
    saturated_outcome: &'static str,
    items: usize,
) -> Result<OwnedSemaphorePermit, Box<Response>> {
    let Some(limiter) = state.source_limiters.get(source_id) else {
        return Err(Box::new(problem(
            StatusCode::BAD_GATEWAY,
            "source limiter unavailable",
        )));
    };
    match limiter.clone().try_acquire_owned() {
        Ok(permit) => Ok(permit),
        Err(_) => {
            record_metric_with_items(state, source_id, saturated_outcome, Duration::ZERO, items)
                .await;
            let mut response = problem_with_code(
                StatusCode::SERVICE_UNAVAILABLE,
                "source concurrency limit reached",
                "source.saturated",
            );
            if let Ok(value) =
                HeaderValue::from_str(&state.config.limits.retry_after_seconds.to_string())
            {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            Err(Box::new(response))
        }
    }
}

pub(super) fn escape_metric_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

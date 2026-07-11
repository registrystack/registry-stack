use super::*;

pub async fn sidecar_router(config: SidecarConfig) -> Result<Router, SidecarError> {
    validate_config(&config)?;
    let auth_tokens = resolve_auth_tokens(&config)?;
    let fhir_bearer_tokens = resolve_fhir_bearer_tokens(&config)?;
    let audit = SidecarAuditPipeline::from_config(&config.audit)?;
    if config.assurance.is_some() && audit.is_none() {
        return Err(SidecarError::Config(
            "governed sidecar runtime requires durable audit configuration".to_string(),
        ));
    }
    if let (Some(assurance), Some(audit)) = (config.assurance.as_ref(), audit.as_ref()) {
        audit.probe_startup_writable(assurance).await?;
    }
    let request_timeout = Duration::from_millis(config.server.request_timeout_ms);
    let request_body_timeout = Duration::from_millis(config.server.request_body_timeout_ms);

    let credentials = load_credentials(&config)?;
    let source_limiters = config
        .sources
        .iter()
        .map(|(source_id, source)| {
            let max_in_flight = source
                .limits
                .max_in_flight
                .unwrap_or(config.limits.max_workers);
            (source_id.clone(), Arc::new(Semaphore::new(max_in_flight)))
        })
        .collect();
    let source_runtime = config
        .sources
        .iter()
        .map(|(source_id, source)| {
            SourceRuntimeState::new(source).map(|runtime| (source_id.clone(), Arc::new(runtime)))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let rhai_engines = compile_rhai_engines(&config)?;
    let state = Arc::new(AppState {
        config: Arc::new(config),
        auth_tokens: Arc::new(auth_tokens),
        fhir_bearer_tokens: Arc::new(fhir_bearer_tokens),
        credentials: Arc::new(credentials),
        source_limiters: Arc::new(source_limiters),
        source_runtime: Arc::new(source_runtime),
        http_json_clients: Arc::new(Mutex::new(BTreeMap::new())),
        oauth2_tokens: Arc::new(Mutex::new(BTreeMap::new())),
        oauth2_token_locks: Arc::new(Mutex::new(BTreeMap::new())),
        rhai_engines: Arc::new(rhai_engines),
        metrics: Arc::new(Mutex::new(BTreeMap::new())),
        audit: audit.map(Arc::new),
    });
    run_smoke_lookups(&state).await?;
    accept_governed_config(&state.config)?;

    Ok(Router::new()
        .route("/healthz", get(healthz))
        .route("/ready", get(ready))
        .route("/v1/assurance", get(assurance))
        .route("/metrics", get(metrics))
        .route(
            "/v1/datasets/{dataset}/entities/{entity}/records",
            get(lookup),
        )
        .route(
            "/v1/datasets/{dataset}/entities/{entity}/records:batchMatch",
            post(batch_match),
        )
        .with_state(Arc::clone(&state))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            sidecar_audit_middleware,
        ))
        .layer(middleware::from_fn(enforce_uri_limit))
        .layer(RequestBodyTimeoutLayer::new(request_body_timeout))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        )))
}

pub async fn run(config: SidecarConfig) -> Result<(), Box<dyn std::error::Error>> {
    let bind = config.server.bind;
    let max_connections = config.server.max_connections;
    let request_timeout_ms = config.server.request_timeout_ms;
    let request_body_timeout_ms = config.server.request_body_timeout_ms;
    let http1_header_read_timeout =
        Duration::from_millis(config.server.http1_header_read_timeout_ms);
    let http2_keep_alive_interval = http1_header_read_timeout;
    let app = sidecar_router(config).await?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let local_addr = listener.local_addr()?;
    let connection_permits = Arc::new(Semaphore::new(max_connections));
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let mut tasks = JoinSet::new();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    tracing::info!(
        %local_addr,
        max_connections,
        request_timeout_ms,
        request_body_timeout_ms,
        http1_header_read_timeout_ms = %http1_header_read_timeout.as_millis(),
        "registry notary source adapter sidecar listening"
    );

    loop {
        while let Some(joined) = tasks.try_join_next() {
            if let Err(error) = joined {
                warn!(error = %error, bind = %local_addr, "sidecar HTTP connection task failed");
            }
        }

        let permit = tokio::select! {
            biased;
            _ = &mut shutdown => {
                tracing::info!(
                    "registry notary source adapter sidecar shutdown signal received"
                );
                break;
            }
            permit = Arc::clone(&connection_permits).acquire_owned() => {
                match permit {
                    Ok(permit) => permit,
                    Err(_) => break,
                }
            }
        };
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                tracing::info!(
                    "registry notary source adapter sidecar shutdown signal received"
                );
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, remote_addr)) => {
                        let app = app.clone();
                        let close_rx = shutdown_rx.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            serve_sidecar_connection(
                                stream,
                                remote_addr,
                                app,
                                http1_header_read_timeout,
                                http2_keep_alive_interval,
                                close_rx,
                            )
                            .await;
                        });
                    }
                    Err(error) => {
                        warn!(error = %error, bind = %local_addr, "failed to accept sidecar connection");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                }
            }
        }
    }

    drop(shutdown_tx);
    while let Some(joined) = tasks.join_next().await {
        if let Err(error) = joined {
            warn!(error = %error, bind = %local_addr, "sidecar HTTP connection task failed during shutdown");
        }
    }
    Ok(())
}

pub(super) async fn serve_sidecar_connection(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    app: Router,
    http1_header_read_timeout: Duration,
    http2_keep_alive_interval: Duration,
    mut close_rx: watch::Receiver<()>,
) {
    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
        let app = app.clone();
        async move {
            let request = request.map(Body::new);
            match app.oneshot(request).await {
                Ok(response) => Ok::<_, Infallible>(response),
                Err(err) => match err {},
            }
        }
    });

    let mut builder = HyperBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(http1_header_read_timeout)
        .keep_alive(false);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(http2_keep_alive_interval)
        .keep_alive_timeout(http2_keep_alive_interval);

    let io = TokioIo::new(stream);
    let conn = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(conn);
    let mut shutdown_initiated = false;

    loop {
        tokio::select! {
            result = &mut conn => {
                if let Err(error) = result {
                    tracing::debug!(%remote_addr, %error, "sidecar HTTP connection ended with error");
                }
                break;
            }
            _ = close_rx.changed(), if !shutdown_initiated => {
                conn.as_mut().graceful_shutdown();
                shutdown_initiated = true;
            }
        }
    }
}

pub(super) async fn run_smoke_lookups(state: &Arc<AppState>) -> Result<(), SidecarError> {
    for (source_id, source) in &state.config.sources {
        let Some(smoke) = &source.smoke_lookup else {
            continue;
        };
        let deadline =
            Instant::now() + Duration::from_millis(state.config.limits.liveness_window_ms.max(1));
        let retry_after = Duration::from_secs(state.config.limits.retry_after_seconds.max(1));
        let mut last_reason = "smoke lookup was not attempted".to_string();
        let mut attempted = false;

        loop {
            if attempted && Instant::now() >= deadline {
                return Err(SidecarError::SmokeLookup {
                    source_id: source_id.clone(),
                    reason: last_reason,
                });
            }
            attempted = true;

            let mut request = json!({
                "source_id": source_id,
                "dataset": source.dataset,
                "entity": source.entity,
                "lookup": {
                    "field": smoke.field,
                    "value": smoke.value,
                },
                "query_values": {},
                "fields": smoke.fields,
                "limit": 1,
                "purpose": smoke.purpose,
                "correlation_id": "startup-smoke",
                "configuration": state.credentials.get(source_id).cloned().unwrap_or(Value::Null),
            });
            if let Some(query_values) = request
                .get_mut("query_values")
                .and_then(Value::as_object_mut)
            {
                query_values.insert(smoke.field.clone(), Value::String(smoke.value.clone()));
                for (key, value) in &smoke.query_values {
                    query_values.insert(key.clone(), Value::String(value.clone()));
                }
            }
            match execute_source_json(state, source_id, source, request).await {
                Ok(execution) => {
                    let response = execution.value;
                    if let Some(records) = response.get("data").and_then(Value::as_array) {
                        if records.iter().any(|record| {
                            record
                                .get(&smoke.field)
                                .and_then(Value::as_str)
                                .is_some_and(|value| value == smoke.value)
                        }) {
                            break;
                        }
                        last_reason = format!(
                            "worker response did not contain expected smoke record for {}",
                            smoke.field
                        );
                    } else if let Some(code) =
                        response.pointer("/error/code").and_then(Value::as_str)
                    {
                        last_reason = response
                            .pointer("/error/message")
                            .and_then(Value::as_str)
                            .map(|message| format!("worker returned error {code}: {message}"))
                            .unwrap_or_else(|| format!("worker returned error {code}"));
                    } else {
                        last_reason = "worker response did not contain data array".to_string();
                    }
                }
                Err(error) => {
                    last_reason = smoke_execution_error_reason(&error);
                }
            }

            if Instant::now() >= deadline {
                return Err(SidecarError::SmokeLookup {
                    source_id: source_id.clone(),
                    reason: last_reason,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            tokio::time::sleep(retry_after.min(remaining)).await;
        }
    }
    Ok(())
}

pub(super) fn smoke_execution_error_reason(error: &SourceExecutionError) -> String {
    match error {
        SourceExecutionError::HttpJson
        | SourceExecutionError::HttpJsonBadRequest
        | SourceExecutionError::HttpJsonTimeout => "source adapter execution failed".to_string(),
    }
}

pub(super) async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub(super) fn problem(status: StatusCode, title: &'static str) -> Response {
    problem_body(status, title, None)
}

pub(super) fn problem_with_code(
    status: StatusCode,
    title: &'static str,
    code: &'static str,
) -> Response {
    problem_body(status, title, Some(code))
}

pub(super) fn problem_body(
    status: StatusCode,
    title: &'static str,
    code: Option<&'static str>,
) -> Response {
    let mut body = json!({
        "type": "about:blank",
        "title": title,
        "status": status.as_u16(),
    });
    if let Some(code) = code {
        body["code"] = json!(code);
    }
    (status, Json(body)).into_response()
}

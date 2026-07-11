use super::*;

#[derive(Clone)]
pub(super) struct ExpectedSidecarRuntime {
    pub(super) expected: ExpectedSidecarConfig,
    pub(super) ttl: Duration,
    pub(super) cache: Arc<StdMutex<Option<CachedSidecarAssurance>>>,
}

#[derive(Clone, Debug)]
pub(super) struct CachedSidecarAssurance {
    pub(super) checked_at: Instant,
    pub(super) assurance: ObservedSidecarAssurance,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct ObservedSidecarAssurance {
    product: String,
    instance_id: String,
    environment: String,
    stream_id: String,
    config_hash: String,
    #[serde(default)]
    expression_hashes_verified: bool,
    #[serde(default)]
    runtime_verified: bool,
    #[serde(default)]
    smoke_verified: bool,
}

pub(super) async fn ensure_source_adapter_sidecar_assurance(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
) -> Result<(), EvidenceError> {
    let Some(runtime) = &connection.expected_sidecar else {
        return Ok(());
    };
    let now = Instant::now();
    {
        let cache = runtime
            .cache
            .lock()
            .map_err(|_| EvidenceError::SourceUnavailable)?;
        if let Some(cached) = cache.as_ref() {
            if now.duration_since(cached.checked_at) <= runtime.ttl {
                validate_source_adapter_sidecar_assurance(&runtime.expected, &cached.assurance)?;
                return Ok(());
            }
        }
    }

    let url = source_adapter_sidecar_assurance_url(&connection.base_url)?;
    let body = send_request_with_retry(
        sources,
        connection,
        "source_adapter_sidecar_assurance",
        &url,
        reqwest::Method::GET,
        sources.request_timeout,
        |request, token| {
            add_correlation_header(
                request
                    .bearer_auth(token)
                    .header("accept", "application/json"),
            )
        },
    )
    .await?;
    let assurance: ObservedSidecarAssurance =
        serde_json::from_value(body).map_err(|_| EvidenceError::SourceUnavailable)?;
    validate_source_adapter_sidecar_assurance(&runtime.expected, &assurance)?;
    let mut cache = runtime
        .cache
        .lock()
        .map_err(|_| EvidenceError::SourceUnavailable)?;
    *cache = Some(CachedSidecarAssurance {
        checked_at: Instant::now(),
        assurance,
    });
    Ok(())
}

pub(super) fn cached_source_adapter_sidecar_config_hash(
    connection: &ResolvedEvidenceSourceConnection,
) -> Option<String> {
    let runtime = connection.expected_sidecar.as_ref()?;
    let cache = runtime.cache.lock().ok()?;
    let cached = cache.as_ref()?;
    validate_source_adapter_sidecar_assurance(&runtime.expected, &cached.assurance).ok()?;
    Some(cached.assurance.config_hash.clone())
}

/// Minimized public summary of a validated source-adapter sidecar runtime, for claim
/// provenance. Only returns `Some` when a cached assurance exists and validates
/// against the pinned expected config; `pinned` is therefore always `true` here
/// (the entry could not validate against a non-pinned config). The full
/// assurance document stays in restricted audit.
pub(super) fn cached_source_adapter_sidecar_runtime_summary(
    connection: &ResolvedEvidenceSourceConnection,
) -> Option<SourceRuntimeSummary> {
    let runtime = connection.expected_sidecar.as_ref()?;
    let cache = runtime.cache.lock().ok()?;
    let cached = cache.as_ref()?;
    validate_source_adapter_sidecar_assurance(&runtime.expected, &cached.assurance).ok()?;
    Some(SourceRuntimeSummary {
        kind: SOURCE_RUNTIME_KIND_SOURCE_ADAPTER_SIDECAR.to_string(),
        config_hash: cached.assurance.config_hash.clone(),
        assurance: SourceRuntimeAssurance {
            pinned: true,
            expression_hashes_verified: cached.assurance.expression_hashes_verified,
            runtime_verified: cached.assurance.runtime_verified,
            smoke_verified: cached.assurance.smoke_verified,
        },
    })
}

pub(super) fn validate_source_adapter_sidecar_assurance(
    expected: &ExpectedSidecarConfig,
    observed: &ObservedSidecarAssurance,
) -> Result<(), EvidenceError> {
    if observed.product != expected.product
        || observed.instance_id != expected.instance_id
        || observed.environment != expected.environment
        || observed.stream_id != expected.stream_id
        || observed.config_hash != expected.config_hash
    {
        return Err(EvidenceError::SourceUnavailable);
    }
    if expected.require_expression_hashes_verified && !observed.expression_hashes_verified {
        return Err(EvidenceError::SourceUnavailable);
    }
    if expected.require_runtime_verified && !observed.runtime_verified {
        return Err(EvidenceError::SourceUnavailable);
    }
    if expected.require_smoke_verified && !observed.smoke_verified {
        return Err(EvidenceError::SourceUnavailable);
    }
    Ok(())
}

pub(super) fn source_adapter_sidecar_assurance_url(
    base_url: &str,
) -> Result<reqwest::Url, EvidenceError> {
    let mut base = reqwest::Url::parse(base_url).map_err(|_| EvidenceError::SourceUnavailable)?;
    if !base.path().ends_with('/') {
        base.path_segments_mut()
            .map_err(|_| EvidenceError::SourceUnavailable)?
            .push("");
    }
    base.join("v1/assurance")
        .map_err(|_| EvidenceError::SourceUnavailable)
}

use super::*;

pub(in super::super) async fn send_request_with_retry(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    connector: &'static str,
    url: &reqwest::Url,
    method: reqwest::Method,
    request_timeout: Duration,
    build_request: impl Fn(reqwest::RequestBuilder, String) -> reqwest::RequestBuilder,
) -> Result<Value, EvidenceError> {
    let permit = connection
        .semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| EvidenceError::SourceUnavailable)?;
    let available = connection.semaphore.available_permits();
    let in_flight = connection.max_in_flight.saturating_sub(available);
    sources
        .metrics
        .set_source_in_flight(connector, in_flight as u64);
    tracing::info!(
        target: "registry_notary_server::outbound",
        connection_id = %connection.id,
        connector = connector,
        in_flight = in_flight,
        max_in_flight = connection.max_in_flight,
        "outbound permit acquired",
    );
    let start = Instant::now();
    let mut attempt: u32 = 0;
    let max_attempts = if connection.retry_on_5xx { 2 } else { 1 };
    let mut refreshed_after_401 = false;
    let mut force_refresh_next = false;
    let result = loop {
        attempt += 1;
        let force_refresh = force_refresh_next;
        force_refresh_next = false;
        let token = match connection
            .auth
            .bearer_token(&connection.fetch_url_policy, force_refresh)
            .await
        {
            Ok(token) => token,
            Err(error) => break Err(error),
        };
        let validated_url = match connection
            .fetch_url_policy
            .validate_for_immediate_fetch_with_timeout(url, SOURCE_REQUEST_TIMEOUT)
            .await
        {
            Ok(validated_url) => validated_url,
            Err(error) => {
                tracing::warn!(
                    target: "registry_notary_server::outbound",
                    connection_id = %connection.id,
                    connector = connector,
                    scheme = url.scheme(),
                    host = url.host_str().unwrap_or("<missing>"),
                    error = %error,
                    "source URL rejected by fetch policy",
                );
                break Err(EvidenceError::SourceUnavailable);
            }
        };
        tracing::debug!(
            target: "registry_notary_server::outbound",
            connection_id = %connection.id,
            connector = connector,
            scheme = url.scheme(),
            host = url.host_str().unwrap_or("<missing>"),
            resolved_ips = ?validated_url.resolved_ips(),
            "source URL validated for pinned immediate fetch",
        );
        let request = match pinned_request_builder(&validated_url, method.clone(), request_timeout)
        {
            Ok(request) => request,
            Err(error) => {
                tracing::error!(
                    target: "registry_notary_server::outbound",
                    connection_id = %connection.id,
                    connector = connector,
                    scheme = url.scheme(),
                    host = url.host_str().unwrap_or("<missing>"),
                    error = %error,
                    "source request could not use pinned fetch target",
                );
                break Err(EvidenceError::SourceUnavailable);
            }
        };
        let outcome = build_request(request, token).send().await;
        let retryable = match &outcome {
            Err(_) => true,
            Ok(response) => response.status().is_server_error(),
        };
        if let Ok(response) = &outcome {
            if response.status() == StatusCode::UNAUTHORIZED
                && connection.auth.can_refresh()
                && !refreshed_after_401
            {
                refreshed_after_401 = true;
                force_refresh_next = true;
                sources.metrics.record_source_retry(connector);
                tracing::info!(
                    target: "registry_notary_server::outbound",
                    connection_id = %connection.id,
                    connector = connector,
                    attempt = attempt,
                    "oauth_refresh_after_401",
                );
                continue;
            }
        }
        if attempt < max_attempts && retryable {
            sources.metrics.record_source_retry(connector);
            tracing::info!(
                target: "registry_notary_server::outbound",
                connection_id = %connection.id,
                connector = connector,
                attempt = attempt,
                "retry_attempted",
            );
            tokio::time::sleep(retry_backoff()).await;
            continue;
        }
        match outcome {
            Err(_) => break Err(EvidenceError::SourceUnavailable),
            Ok(response) => {
                if !response.status().is_success() {
                    break Err(EvidenceError::SourceUnavailable);
                }
                break read_source_json(response).await;
            }
        }
    };
    let latency_ms = start.elapsed().as_millis() as u64;
    let status = match &result {
        Ok(_) => "success",
        Err(_) => "error",
    };
    sources
        .metrics
        .record_source_request(connector, status, latency_ms);
    tracing::debug!(
        target: "registry_notary_server::outbound",
        connection_id = %connection.id,
        connector = connector,
        latency_ms = latency_ms,
        attempts = attempt,
        outcome = status,
        "outbound completed",
    );
    drop(permit);
    let available_after = connection.semaphore.available_permits();
    let in_flight_after = connection.max_in_flight.saturating_sub(available_after);
    sources
        .metrics
        .set_source_in_flight(connector, in_flight_after as u64);
    tracing::info!(
        target: "registry_notary_server::outbound",
        connection_id = %connection.id,
        connector = connector,
        in_flight = in_flight_after,
        max_in_flight = connection.max_in_flight,
        "outbound permit released",
    );
    result
}

/// Backoff duration for the single permitted retry. Uniform jitter in
/// [50ms, 150ms) to spread retries across concurrent failures.
pub(in super::super) fn retry_backoff() -> Duration {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    // Hash to a value in [0, 100ms) then offset by 50ms.
    let jitter_ms = (nanos as u64) % 100;
    Duration::from_millis(50 + jitter_ms)
}

pub(in super::super) async fn read_source_json(
    response: reqwest::Response,
) -> Result<Value, EvidenceError> {
    let body = read_bounded(response, MAX_SOURCE_JSON_BYTES as u64)
        .await
        .map_err(|_| EvidenceError::SourceUnavailable)?;
    serde_json::from_slice(&body).map_err(|_| EvidenceError::SourceUnavailable)
}

pub(in super::super) fn source_url(
    base_url: &str,
    path: &str,
) -> Result<reqwest::Url, EvidenceError> {
    if reqwest::Url::parse(path).is_ok() {
        return Err(EvidenceError::SourceUnavailable);
    }
    let base = reqwest::Url::parse(base_url).map_err(|_| EvidenceError::SourceUnavailable)?;
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(base);
    }
    let segments = trimmed.split('/').collect::<Vec<_>>();
    httputil_url::append_path_segments(&base, &segments)
        .map_err(|_| EvidenceError::SourceUnavailable)
}

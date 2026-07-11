use super::*;
use crate::request_context::current_request_correlation_id;

mod egress;

pub(super) use egress::*;

/// Outermost response middleware: injects `request_id` into any
/// `application/problem+json` body and sets the `x-request-id` response header.
///
/// Mints a server-owned ULID before running the inner stack so that
/// early-boundary rejections (414, 413) receive a correlation identifier even
/// when the inner auth/audit layer has not yet run. For responses produced
/// by inner handlers that already carry `x-request-id`, the existing header
/// value is used and the body field is inserted only when absent (idempotent
/// when the inner response already has both).
pub(super) async fn attach_request_id_to_problem_response(
    request: Request,
    next: Next,
) -> Response {
    // Mint a server-owned ULID for this request.  Early-boundary middlewares
    // (reject_oversized_request_uri, rewrite_payload_too_large_problem) run
    // inside this layer; they do not have access to auth_audit_middleware's
    // task-local, so this is the only opportunity to assign them an id.
    let minted = Ulid::new().to_string();

    let response = next.run(request).await;

    let is_problem = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/problem+json"));
    if !is_problem {
        return response;
    }

    // Prefer a request_id already set by an inner layer (auth_audit_middleware
    // sets x-request-id on authenticated-path responses); fall back to the
    // minted value for early-boundary responses.
    let request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or(minted);

    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 64 * 1024).await else {
        // Body too large or read error; the body is consumed and cannot be
        // restored, so return an empty body with corrected framing.
        parts.headers.remove(header::CONTENT_LENGTH);
        return Response::from_parts(parts, Body::empty());
    };
    let Ok(Value::Object(mut problem)) = serde_json::from_slice::<Value>(&bytes) else {
        // Non-object or non-JSON body; pass through unchanged.
        return Response::from_parts(parts, Body::from(bytes));
    };
    // Insert only when absent so existing per-handler injection is idempotent.
    problem
        .entry("request_id")
        .or_insert_with(|| Value::String(request_id.clone()));
    let Ok(body) = serde_json::to_vec(&Value::Object(problem)) else {
        // Serialization failed (should not happen); pass through original bytes.
        return Response::from_parts(parts, Body::from(bytes));
    };
    parts.headers.remove(header::CONTENT_LENGTH);
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        parts.headers.insert("x-request-id", value);
    }
    Response::from_parts(parts, Body::from(body))
}

pub(super) async fn reject_oversized_request_uri(request: Request, next: Next) -> Response {
    let uri_len = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().len())
        .unwrap_or_else(|| request.uri().path().len());
    if uri_len <= MAX_REQUEST_URI_BYTES {
        return next.run(request).await;
    }
    request_uri_too_long_problem()
}

pub(super) fn request_uri_too_long_problem() -> Response {
    let status = StatusCode::URI_TOO_LONG;
    let mut response = (
        status,
        Json(json!({
            "type": format!("{}/request/uri-too-long", crate::PROBLEM_TYPE_BASE_URL),
            "title": "URI too long",
            "status": status.as_u16(),
            "detail": "request URI exceeds the configured 8 KiB limit",
            "code": "request.uri_too_long",
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
}

pub(super) async fn rewrite_payload_too_large_problem(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    if response.status() != StatusCode::PAYLOAD_TOO_LARGE {
        return response;
    }
    let is_problem_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/problem+json"));
    if is_problem_json {
        return response;
    }
    registry_platform_httpsec::body_limit_problem_response(Request::new(Body::empty())).await
}

pub(crate) fn audit_error_response(error: AuditError) -> Response {
    tracing::error!(target: "registry_notary_server::audit", error = %error, "audit event write failed");
    let status = StatusCode::INTERNAL_SERVER_ERROR;
    let mut response = (
        status,
        Json(json!({
            "type": format!("{}/audit/write_failed", crate::PROBLEM_TYPE_BASE_URL),
            "title": "Audit write failed",
            "status": status.as_u16(),
            "detail": "audit event could not be written",
            "code": "audit.write_failed",
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/problem+json".parse().unwrap(),
    );
    response
        .extensions_mut()
        .insert(EvidenceErrorCodeContext("audit.write_failed".to_string()));
    response
}

pub(super) fn add_correlation_header(builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Some(correlation_id) = current_request_correlation_id() {
        builder.header("x-request-id", correlation_id.as_str())
    } else {
        builder
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct PinnedClientCacheKey {
    host: String,
    resolved_addrs: Vec<SocketAddr>,
    timeout: Duration,
}

pub(super) static PINNED_CLIENTS: OnceLock<
    StdMutex<HashMap<PinnedClientCacheKey, reqwest::Client>>,
> = OnceLock::new();

pub(super) fn pinned_request_builder(
    validated_url: &ValidatedFetchUrl,
    method: reqwest::Method,
    timeout: Duration,
) -> Result<reqwest::RequestBuilder, FetchUrlError> {
    let host = validated_url
        .url()
        .host_str()
        .ok_or(FetchUrlError::MissingHost)?
        .to_string();
    let key = PinnedClientCacheKey {
        host: host.clone(),
        resolved_addrs: validated_url.resolved_addrs().to_vec(),
        timeout,
    };
    let clients = PINNED_CLIENTS.get_or_init(|| StdMutex::new(HashMap::new()));
    if let Some(client) = clients
        .lock()
        .expect("pinned client cache lock is not poisoned")
        .get(&key)
        .cloned()
    {
        return Ok(client
            .request(method, validated_url.url().clone())
            .timeout(timeout));
    }
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent("registry-notary/0.2")
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve_to_addrs(&host, validated_url.resolved_addrs())
        .build()
        .map_err(FetchUrlError::ClientBuild)?;
    let client = clients
        .lock()
        .expect("pinned client cache lock is not poisoned")
        .entry(key)
        .or_insert(client)
        .clone();
    Ok(client
        .request(method, validated_url.url().clone())
        .timeout(timeout))
}

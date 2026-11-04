// SPDX-License-Identifier: Apache-2.0

//! Request correlation for the fixed GovStack facade.

use axum::body::Body;
use axum::http::header::CONTENT_LENGTH;
use axum::http::{HeaderMap, Request};
use axum::middleware::Next;
use axum::response::Response;
use registry_platform_httpsec::{TraceContext, TraceId};
use serde_json::Value;

use crate::engine::exchange::Exchange;

/// One server-minted request identity and its effective W3C trace.
///
/// The request identity remains the journal and exchange identity. A valid
/// caller trace can influence only public correlation and trusted propagation.
#[derive(Clone, Debug)]
pub(crate) struct RequestCorrelation {
    request_id: String,
    trace: TraceContext,
}

impl RequestCorrelation {
    #[must_use]
    pub(crate) fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            request_id: new_request_id(),
            trace: TraceContext::from_headers(headers),
        }
    }

    #[must_use]
    pub(crate) fn server_created() -> Self {
        Self {
            request_id: new_request_id(),
            trace: TraceContext::server_created(),
        }
    }

    #[must_use]
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub(crate) fn trace_id(&self) -> &TraceId {
        &self.trace.trace_id
    }

    pub(crate) fn install(&self, exchange: &mut Exchange) -> Result<(), &'static str> {
        let mut headers = HeaderMap::new();
        self.trace.apply(&mut headers);
        let traceparent = headers
            .remove("traceparent")
            .ok_or("the shared trace context produced no traceparent")?;
        exchange
            .install_system_traceparent(traceparent)
            .map_err(|_| "the exchange already carries system trace context")
    }

    pub(crate) fn finish(&self, mut response: Response) -> Response {
        // Write handlers finish fresh Problems before terminal custody. That
        // consumes the marker, so the boundary can regenerate per-attempt
        // tracing without retagging the exact body of a stored replay.
        if let Some(mut problem) = response.extensions_mut().remove::<ConsultationProblem>() {
            if let Some(object) = problem.0.as_object_mut() {
                object.insert(
                    "traceId".to_owned(),
                    Value::String(self.trace_id().as_str().to_owned()),
                );
            }
            *response.body_mut() = Body::from(problem.0.to_string());
            response.headers_mut().remove(CONTENT_LENGTH);
        }
        self.trace.apply(response.headers_mut());
        response
    }
}

#[derive(Clone)]
struct ConsultationProblem(Value);

#[derive(Clone)]
struct ProblemIdentity(String);

pub(crate) fn mark_problem(response: &mut Response, body: Value) {
    if let Some(problem_type) = body.get("type").and_then(Value::as_str) {
        response
            .extensions_mut()
            .insert(ProblemIdentity(problem_type.to_owned()));
    }
    response.extensions_mut().insert(ConsultationProblem(body));
}

/// Restore only the trusted audit identity of an exact fixed-target replay.
/// The custodied body remains byte-for-byte immutable and therefore does not
/// receive the mutable marker used to finish a fresh Problem's trace.
pub(crate) fn mark_stored_problem_identity(
    response: &mut Response,
    status: u16,
    content_type: Option<&[u8]>,
    body: &[u8],
) -> Result<(), ()> {
    if content_type != Some(b"application/problem+json") {
        return Err(());
    }
    let problem: Value = serde_json::from_slice(body).map_err(|_| ())?;
    if problem.get("status").and_then(Value::as_u64) != Some(u64::from(status))
        || !problem.get("title").is_some_and(Value::is_string)
        || !problem.get("traceId").is_some_and(|value| {
            value.as_str().is_some_and(|trace| {
                trace.len() == 32
                    && trace
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        })
    {
        return Err(());
    }
    let problem_type = problem
        .get("type")
        .and_then(Value::as_str)
        .filter(|value| canonical_problem_type(value))
        .ok_or(())?;
    response
        .extensions_mut()
        .insert(ProblemIdentity(problem_type.to_owned()));
    Ok(())
}

fn canonical_problem_type(value: &str) -> bool {
    let Some(code) = value.strip_prefix("https://govstack.global/problems/digital-registries/")
    else {
        return false;
    };
    !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && code.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && code
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

/// Read trusted metadata from an already-rendered GovStack Problem without
/// parsing response bytes or inspecting source-owned values.
pub(crate) fn problem_type(response: &Response) -> Option<&str> {
    response
        .extensions()
        .get::<ProblemIdentity>()
        .map(|identity| identity.0.as_str())
}

/// Install explicit request context and finish only the fixed GovStack
/// facade's response with its effective trace.
pub(crate) async fn boundary(mut request: Request<Body>, next: Next) -> Response {
    let correlation = RequestCorrelation::from_headers(request.headers());
    request.extensions_mut().insert(correlation.clone());
    correlation.finish(next.run(request).await)
}

fn new_request_id() -> String {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).expect("the operating system supplies randomness");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::{HeaderValue, StatusCode};
    use serde_json::json;

    #[test]
    fn caller_trace_never_becomes_the_request_identity() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            HeaderValue::from_static("00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"),
        );
        let first = RequestCorrelation::from_headers(&headers);
        let second = RequestCorrelation::from_headers(&headers);

        assert_eq!(
            first.trace_id().as_str(),
            "0123456789abcdef0123456789abcdef"
        );
        assert_ne!(first.request_id(), first.trace_id().as_str());
        assert_ne!(first.request_id(), second.request_id());
    }

    #[tokio::test]
    async fn boundary_uses_effective_trace_for_headers_and_problem_body() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            HeaderValue::from_static("00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"),
        );
        headers.insert(
            "tracestate",
            HeaderValue::from_static("vendor=opaque-caller-state"),
        );
        let correlation = RequestCorrelation::from_headers(&headers);
        let body = json!({"status": 503, "traceId": "server-request-id"});
        let mut response = Response::new(Body::from(body.to_string()));
        *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
        mark_problem(&mut response, body);

        let response = correlation.finish(response);

        assert_eq!(
            response.headers().get("traceparent"),
            Some(&HeaderValue::from_static(
                "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
            ))
        );
        assert_eq!(response.headers().get("tracestate"), None);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body.get("traceId"),
            Some(&Value::String(
                "0123456789abcdef0123456789abcdef".to_owned()
            ))
        );
    }

    #[tokio::test]
    async fn stored_problem_identity_is_audit_only_and_keeps_exact_body() {
        let body = br#"{"type":"https://govstack.global/problems/digital-registries/invalid-content","title":"invalid content","status":422,"traceId":"11111111111111111111111111111111"}"#;
        let mut response = Response::new(Body::from(body.as_slice()));
        *response.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
        mark_stored_problem_identity(&mut response, 422, Some(b"application/problem+json"), body)
            .expect("the custodied host Problem has a canonical audit identity");

        assert_eq!(
            problem_type(&response),
            Some("https://govstack.global/problems/digital-registries/invalid-content")
        );
        let response = RequestCorrelation::server_created().finish(response);
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            body.as_slice()
        );
    }

    #[test]
    fn stored_problem_identity_rejects_mismatched_or_noncanonical_custody() {
        for body in [
            br#"{"type":"https://govstack.global/problems/digital-registries/invalid-content","title":"invalid content","status":400,"traceId":"11111111111111111111111111111111"}"#.as_slice(),
            br#"{"type":"https://source.invalid/problem","title":"invalid content","status":422,"traceId":"11111111111111111111111111111111"}"#.as_slice(),
        ] {
            let mut response = Response::new(Body::empty());
            assert!(mark_stored_problem_identity(
                &mut response,
                422,
                Some(b"application/problem+json"),
                body,
            )
            .is_err());
            assert_eq!(problem_type(&response), None);
        }
    }
}

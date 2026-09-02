// SPDX-License-Identifier: Apache-2.0

//! Request correlation at the Registry Server HTTP boundary.

use std::time::Instant;

use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use registry_platform_httpsec::{Problem, ProblemBody, TraceContext, TraceId};
use serde_json::Value;
use uuid::Uuid;

/// Server-owned request identifier and the effective W3C trace context.
///
/// `request_id` is always freshly minted by Registry Server. The trace may
/// retain one valid inbound `traceparent`, as defined by the shared platform
/// parser, but caller-supplied `tracestate` is never reflected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestCorrelation {
    request_id: Uuid,
    trace: TraceContext,
}

impl RequestCorrelation {
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            request_id: Uuid::new_v4(),
            trace: TraceContext::from_headers(headers),
        }
    }

    #[must_use]
    pub fn server_created() -> Self {
        Self {
            request_id: Uuid::new_v4(),
            trace: TraceContext::server_created(),
        }
    }

    #[must_use]
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    #[must_use]
    pub fn trace_id(&self) -> &TraceId {
        &self.trace.trace_id
    }

    fn apply_trace(&self, headers: &mut HeaderMap) {
        self.trace.apply(headers);
    }
}

/// Closed public problem metadata used by the correlation boundary.
///
/// Carrying this in response extensions lets the outer timeout/observation
/// layer render the shared [`ProblemBody`] with the exact effective trace ID
/// without parsing or trusting response bytes.
#[derive(Clone)]
pub(crate) struct PublicProblem {
    type_uri: String,
    title: &'static str,
    status: StatusCode,
    detail: &'static str,
    code: &'static str,
    field_path: Option<String>,
}

/// Build one value-free public problem. The boundary replaces this provisional
/// body with [`ProblemBody`] carrying the request's effective trace ID.
pub(crate) fn problem_response(
    status: StatusCode,
    type_uri: impl Into<String>,
    title: &'static str,
    detail: &'static str,
    code: &'static str,
) -> Response {
    let type_uri = type_uri.into();
    let problem = PublicProblem {
        type_uri: type_uri.clone(),
        title,
        status,
        detail,
        code,
        field_path: None,
    };
    let mut response = Problem::new(&type_uri, title, status)
        .detail(detail)
        .with_extra("code", Value::String(code.to_owned()))
        .into_response();
    response.extensions_mut().insert(problem);
    response
}

/// Build one public problem with a safe action field path.
///
/// The field path is produced only from fixed envelope members or compiled
/// public names that were already admitted for this action surface.
pub(crate) fn problem_response_with_field_path(
    status: StatusCode,
    type_uri: impl Into<String>,
    title: &'static str,
    detail: &'static str,
    code: &'static str,
    field_path: impl Into<String>,
) -> Response {
    let type_uri = type_uri.into();
    let field_path = field_path.into();
    let problem = PublicProblem {
        type_uri: type_uri.clone(),
        title,
        status,
        detail,
        code,
        field_path: Some(field_path.clone()),
    };
    let mut response = Problem::new(&type_uri, title, status)
        .detail(detail)
        .with_extra("code", Value::String(code.to_owned()))
        .with_extra("fieldPath", Value::String(field_path))
        .into_response();
    response.extensions_mut().insert(problem);
    response
}

/// Observe a router that is not already owned by an outer correlation layer.
/// Nested use is deliberately idempotent so the production timeout wrapper
/// and focused test routers share one request ID and emit one log record.
pub(crate) async fn observe(mut request: Request<Body>, next: Next) -> Response {
    if request.extensions().get::<RequestCorrelation>().is_some() {
        return next.run(request).await;
    }
    let correlation = RequestCorrelation::from_headers(request.headers());
    request.extensions_mut().insert(correlation.clone());
    let method = method_name(request.method());
    let started = Instant::now();
    let response = next.run(request).await;
    finish_response(response, &correlation, method, started)
}

/// Establish correlation for an outer boundary such as the request timeout.
pub(crate) fn begin_request(request: &mut Request<Body>) -> (RequestCorrelation, bool) {
    if let Some(correlation) = request.extensions().get::<RequestCorrelation>() {
        return (correlation.clone(), false);
    }
    let correlation = RequestCorrelation::from_headers(request.headers());
    request.extensions_mut().insert(correlation.clone());
    (correlation, true)
}

/// Render correlated problem details, attach the effective trace, and emit one
/// closed operational request record when this layer owns the boundary.
pub(crate) fn finish_response(
    response: Response,
    correlation: &RequestCorrelation,
    method: &'static str,
    started: Instant,
) -> Response {
    let elapsed = started.elapsed();
    let problem = response.extensions().get::<PublicProblem>().cloned();
    let mut response = if let Some(problem) = &problem {
        let (mut parts, _) = response.into_parts();
        let body = ProblemBody {
            type_uri: problem.type_uri.clone(),
            title: problem.title,
            status: problem.status.as_u16(),
            detail: problem.detail,
            code: problem.code,
            trace_id: correlation.trace_id().clone(),
        };
        let body = match &problem.field_path {
            Some(field_path) => {
                let mut value =
                    serde_json::to_value(&body).expect("ProblemBody serialization is infallible");
                value
                    .as_object_mut()
                    .expect("ProblemBody serializes as an object")
                    .insert("fieldPath".to_owned(), Value::String(field_path.clone()));
                serde_json::to_vec(&value).expect("ProblemBody serialization is infallible")
            }
            None => serde_json::to_vec(&body).expect("ProblemBody serialization is infallible"),
        };
        parts.headers.remove(CONTENT_LENGTH);
        parts.headers.insert(
            CONTENT_TYPE,
            "application/problem+json"
                .parse()
                .expect("problem content type is valid"),
        );
        Response::from_parts(parts, Body::from(body))
    } else {
        response
    };
    if problem.is_some() {
        response.headers_mut().insert(
            CACHE_CONTROL,
            "no-store".parse().expect("cache policy is valid"),
        );
    }
    correlation.apply_trace(response.headers_mut());

    let status = status_class(response.status());
    let problem_code = problem.as_ref().map_or("none", |problem| problem.code);
    tracing::info!(
        target: "registry_server::request",
        method,
        request_id = %correlation.request_id(),
        trace_id = correlation.trace_id().as_str(),
        duration_ms = duration_milliseconds(elapsed),
        status,
        problem_code,
        "Registry Server request served"
    );
    response
}

pub(crate) fn method_name(method: &axum::http::Method) -> &'static str {
    match *method {
        axum::http::Method::GET => "GET",
        axum::http::Method::POST => "POST",
        axum::http::Method::PATCH => "PATCH",
        axum::http::Method::DELETE => "DELETE",
        axum::http::Method::HEAD => "HEAD",
        axum::http::Method::OPTIONS => "OPTIONS",
        _ => "OTHER",
    }
}

pub(crate) fn status_class(status: StatusCode) -> &'static str {
    if status.is_server_error() {
        "server_error"
    } else if status.is_client_error() {
        "client_error"
    } else {
        "success"
    }
}

fn duration_milliseconds(elapsed: std::time::Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

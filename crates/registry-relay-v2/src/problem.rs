// SPDX-License-Identifier: Apache-2.0
//! Value-free RFC 9457 problems for Relay V2.
//!
//! The public `code` is a Registry Stack identifier rather than an internal
//! error.  Callers must never attach rejected selector values, SQL, source
//! paths, token material, or principal identifiers to a problem.

use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use serde::Serialize;
use ulid::Ulid;

const PROBLEM_BASE: &str = "https://id.registrystack.org/problems/registry-relay/";

/// Closed public failure classes for the V2 HTTP boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProblemCode {
    ConsultationInvalidRequest,
    AggregateDataInvalidRequest,
    FieldsInvalid,
    UnknownFilter,
    InvalidFilter,
    CursorInvalid,
    AccessProfileInvalid,
    MissingCredential,
    InvalidCredential,
    ConsultationDenied,
    AggregateDataDenied,
    ResourceNotFound,
    ConsultationUnresolved,
    UnsupportedFormat,
    BodyTooLarge,
    ConsultationResponseTooLarge,
    AggregateDataTooLarge,
    UriTooLong,
    UnsupportedMediaType,
    RateLimited,
    AggregateDataRateLimited,
    Internal,
    SourceUnavailable,
    AuditUnavailable,
    ServiceNotReady,
    Timeout,
}

impl ProblemCode {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ConsultationInvalidRequest => "consultation.invalid_request",
            Self::AggregateDataInvalidRequest => "aggregate-data.invalid_request",
            Self::FieldsInvalid => "request.fields_invalid",
            Self::UnknownFilter => "filter.unknown_field",
            Self::InvalidFilter => "filter.invalid_value",
            Self::CursorInvalid => "query.cursor_invalid",
            Self::AccessProfileInvalid => "request.access_profile_invalid",
            Self::MissingCredential => "auth.missing_credential",
            Self::InvalidCredential => "auth.invalid_credential",
            Self::ConsultationDenied => "consultation.denied",
            Self::AggregateDataDenied => "aggregate-data.denied",
            Self::ResourceNotFound => "resource.not_found",
            Self::ConsultationUnresolved => "consultation.unresolved",
            Self::UnsupportedFormat => "format.unsupported",
            Self::BodyTooLarge => "internal.payload_too_large",
            Self::ConsultationResponseTooLarge => "consultation.response_too_large",
            Self::AggregateDataTooLarge => "aggregate-data.too_large",
            Self::UriTooLong => "internal.uri_too_long",
            Self::UnsupportedMediaType => "request.media_type_unsupported",
            Self::RateLimited => "consultation.rate_limited",
            Self::AggregateDataRateLimited => "aggregate-data.rate_limited",
            Self::SourceUnavailable => "source.unavailable",
            Self::AuditUnavailable => "audit.unavailable",
            Self::Internal => "internal.unhandled",
            Self::ServiceNotReady => "service.not_ready",
            Self::Timeout => "internal.timeout",
        }
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::ConsultationInvalidRequest => "Consultation request is invalid",
            Self::AggregateDataInvalidRequest => "Aggregate data request is invalid",
            Self::FieldsInvalid => "Field selection is invalid",
            Self::UnknownFilter => "Filter is not declared",
            Self::InvalidFilter => "Filter value is invalid",
            Self::CursorInvalid => "Cursor is invalid",
            Self::AccessProfileInvalid => "Access profile selection is invalid",
            Self::MissingCredential => "Bearer access token is required",
            Self::InvalidCredential => "Bearer access token is invalid",
            Self::ConsultationDenied => "Consultation is not permitted",
            Self::AggregateDataDenied => "Aggregate data access is not permitted",
            Self::ResourceNotFound => "Requested resource was not found",
            Self::ConsultationUnresolved => "Requested record was not resolved",
            Self::UnsupportedFormat => "Requested format is not supported",
            Self::BodyTooLarge => "Request body is too large",
            Self::ConsultationResponseTooLarge => "Consultation response is too large",
            Self::AggregateDataTooLarge => "Aggregate data request is too broad",
            Self::UriTooLong => "Request URI is too long",
            Self::UnsupportedMediaType => "Request media type is not supported",
            Self::RateLimited => "Consultation quota is exhausted",
            Self::AggregateDataRateLimited => "Aggregate data quota is exhausted",
            Self::Internal => "Request could not be served",
            Self::SourceUnavailable => "Authoritative source is unavailable",
            Self::AuditUnavailable => "Required audit is unavailable",
            Self::ServiceNotReady => "Service is not ready",
            Self::Timeout => "Request timed out",
        }
    }

    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::ConsultationInvalidRequest
            | Self::AggregateDataInvalidRequest
            | Self::FieldsInvalid
            | Self::UnknownFilter
            | Self::InvalidFilter
            | Self::CursorInvalid
            | Self::AccessProfileInvalid => 400,
            Self::MissingCredential | Self::InvalidCredential => 401,
            Self::ConsultationDenied | Self::AggregateDataDenied => 403,
            Self::ResourceNotFound | Self::ConsultationUnresolved => 404,
            Self::UnsupportedFormat => 406,
            Self::BodyTooLarge
            | Self::ConsultationResponseTooLarge
            | Self::AggregateDataTooLarge => 413,
            Self::UriTooLong => 414,
            Self::UnsupportedMediaType => 415,
            Self::RateLimited | Self::AggregateDataRateLimited => 429,
            Self::SourceUnavailable | Self::AuditUnavailable => 503,
            Self::ServiceNotReady => 503,
            Self::Timeout => 504,
            Self::Internal => 500,
        }
    }

    #[must_use]
    pub fn type_uri(self) -> String {
        format!("{PROBLEM_BASE}{}", self.code().replace('.', "/"))
    }

    #[must_use]
    pub fn body(self, trace_id: TraceId) -> ProblemBody {
        ProblemBody {
            type_uri: self.type_uri(),
            title: self.title(),
            status: self.status(),
            detail: self.detail(),
            code: self.code(),
            trace_id,
        }
    }

    /// Serialize the one fixed public failure body and attach the effective
    /// W3C trace context. No rejected value is accepted by this API.
    #[must_use]
    pub fn response(self, trace: &TraceContext) -> Response<Body> {
        let bytes = serde_json::to_vec(&self.body(trace.trace_id.clone()))
            .unwrap_or_else(|_| b"{}".to_vec());
        let mut response = Response::new(Body::from(bytes));
        *response.status_mut() =
            StatusCode::from_u16(self.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let headers = response.headers_mut();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if matches!(self, Self::MissingCredential | Self::InvalidCredential) {
            headers.insert(
                WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"registry-relay\""),
            );
        }
        if matches!(self, Self::RateLimited | Self::AggregateDataRateLimited) {
            headers.insert("retry-after", HeaderValue::from_static("60"));
        }
        trace.apply(headers);
        response
    }

    const fn detail(self) -> &'static str {
        match self {
            Self::ConsultationInvalidRequest => "the consultation request is invalid",
            Self::AggregateDataInvalidRequest => "the aggregate data request is invalid",
            Self::FieldsInvalid => "field selection is invalid",
            Self::UnknownFilter => "filter is not declared for this operation",
            Self::InvalidFilter => "filter value is invalid",
            Self::CursorInvalid => "cursor is invalid for this query",
            Self::AccessProfileInvalid => "access profile selection is invalid",
            Self::MissingCredential => "a bearer access token is required",
            Self::InvalidCredential => "bearer access token validation failed",
            Self::ConsultationDenied => "the consultation is not permitted",
            Self::AggregateDataDenied => "aggregate data access is not permitted",
            Self::ResourceNotFound => "the requested resource was not found",
            Self::ConsultationUnresolved => "the requested record was not resolved",
            Self::UnsupportedFormat => "the requested format is not supported",
            Self::BodyTooLarge => "request body exceeds the configured limit",
            Self::ConsultationResponseTooLarge => {
                "the consultation response exceeds the configured limit"
            }
            Self::AggregateDataTooLarge => {
                "the aggregate data request exceeds its observation limit"
            }
            Self::UriTooLong => "request URI exceeds the configured limit",
            Self::UnsupportedMediaType => "request body must use application/json",
            Self::RateLimited => "the consultation quota is exhausted",
            Self::AggregateDataRateLimited => "the aggregate data quota is exhausted",
            Self::Internal => "the request could not be served",
            Self::SourceUnavailable => "the authoritative source is unavailable",
            Self::AuditUnavailable => "required audit is unavailable",
            Self::ServiceNotReady => "the service is not ready",
            Self::Timeout => "request exceeded the configured timeout",
        }
    }
}

/// A validated W3C Trace Context trace identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct TraceId(String);

impl TraceId {
    /// Parse the 32 lower-case hexadecimal trace-id representation.
    pub fn parse(value: &str) -> Result<Self, TraceIdError> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(TraceIdError);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Effective request trace. An invalid `traceparent` is replaced with a
/// server-created context. Caller-supplied `tracestate` never enters it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: TraceId,
    parent_id: String,
    trace_flags: String,
}

impl TraceContext {
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Self {
        headers
            .get("traceparent")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_traceparent)
            .unwrap_or_else(Self::server_created)
    }

    #[must_use]
    pub fn server_created() -> Self {
        let value = u128::from(Ulid::new());
        let trace_id = TraceId(format!("{value:032x}"));
        let parent = u64::try_from(value & u128::from(u64::MAX)).unwrap_or(1);
        Self {
            trace_id,
            parent_id: format!("{:016x}", parent.max(1)),
            trace_flags: "01".into(),
        }
    }

    pub fn apply(&self, headers: &mut HeaderMap) {
        // Relay's value-free response boundary never reflects caller-controlled
        // vendor state, even when the incoming value is syntactically valid.
        headers.remove("tracestate");
        let traceparent = format!(
            "00-{}-{}-{}",
            self.trace_id.as_str(),
            self.parent_id,
            self.trace_flags
        );
        if let Ok(value) = HeaderValue::from_str(&traceparent) {
            headers.insert(HeaderName::from_static("traceparent"), value);
        }
    }
}

fn parse_traceparent(value: &str) -> Option<TraceContext> {
    if !value.is_ascii() || value.len() != 55 {
        return None;
    }
    let parts = value.split('-').collect::<Vec<_>>();
    if parts.len() != 4 || parts[0] != "00" {
        return None;
    }
    let trace = parts[1];
    let parent = parts[2];
    let flags = parts[3];
    if !lower_hex(trace, 32)
        || trace.bytes().all(|byte| byte == b'0')
        || !lower_hex(parent, 16)
        || parent.bytes().all(|byte| byte == b'0')
        || !lower_hex(flags, 2)
    {
        return None;
    }
    Some(TraceContext {
        trace_id: TraceId(trace.to_owned()),
        parent_id: parent.to_owned(),
        trace_flags: flags.to_owned(),
    })
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("trace identifier is invalid")]
pub struct TraceIdError;

/// The fixed safe HTTP problem representation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProblemBody {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: &'static str,
    pub status: u16,
    pub detail: &'static str,
    pub code: &'static str,
    pub trace_id: TraceId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unresolved_lookup_causes_have_one_public_body() {
        let trace = TraceId::parse("0123456789abcdef0123456789abcdef").expect("trace parses");
        let body = ProblemCode::ConsultationUnresolved.body(trace);
        assert_eq!(body.status, 404);
        assert_eq!(body.code, "consultation.unresolved");
        assert_eq!(
            body.type_uri,
            "https://id.registrystack.org/problems/registry-relay/consultation/unresolved"
        );
    }

    #[test]
    fn aggregate_data_failures_have_their_own_bounded_problem_family() {
        assert_eq!(
            ProblemCode::AggregateDataInvalidRequest.code(),
            "aggregate-data.invalid_request"
        );
        assert_eq!(ProblemCode::AggregateDataDenied.status(), 403);
        assert_eq!(ProblemCode::AggregateDataTooLarge.status(), 413);
        assert_eq!(ProblemCode::AggregateDataRateLimited.status(), 429);
    }

    #[test]
    fn consultation_response_bound_has_a_stable_public_problem() {
        let body = ProblemCode::ConsultationResponseTooLarge
            .body(TraceId::parse("0123456789abcdef0123456789abcdef").expect("trace parses"));
        assert_eq!(body.status, 413);
        assert_eq!(body.code, "consultation.response_too_large");
        assert_eq!(
            body.detail,
            "the consultation response exceeds the configured limit"
        );
    }

    #[test]
    fn trace_identifier_has_one_canonical_wire_shape() {
        assert!(TraceId::parse("0123456789abcdef0123456789abcdef").is_ok());
        assert!(TraceId::parse("not-a-trace").is_err());
    }

    #[test]
    fn version_zero_traceparent_rejects_non_lowercase_hex() {
        for value in [
            "00-0123456789abcdeF0123456789abcdef-0123456789abcdef-01",
            "00-0123456789abcdef0123456789abcdef-0123456789abcdeF-01",
            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-0A",
        ] {
            assert!(
                parse_traceparent(value).is_none(),
                "accepted non-lowercase traceparent {value}"
            );
        }
    }

    #[test]
    fn invalid_traceparent_is_replaced_with_server_context() {
        let supplied_trace_id = "0123456789abcdef0123456789abcdeF";
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            HeaderValue::from_str(&format!("00-{supplied_trace_id}-0123456789abcdef-00"))
                .expect("test traceparent is an HTTP header value"),
        );
        headers.insert(
            "tracestate",
            HeaderValue::from_static("vendor=caller-controlled-canary"),
        );

        let trace = TraceContext::from_headers(&headers);

        assert_ne!(
            trace.trace_id.as_str(),
            supplied_trace_id.to_ascii_lowercase()
        );
        assert_eq!(trace.trace_flags, "01");
        let mut response_headers = HeaderMap::new();
        trace.apply(&mut response_headers);
        assert_ne!(
            response_headers
                .get("traceparent")
                .expect("server context is applied")
                .to_str()
                .expect("traceparent is ASCII"),
            format!(
                "00-{}-0123456789abcdef-00",
                supplied_trace_id.to_ascii_lowercase()
            )
        );
    }

    #[test]
    fn caller_tracestate_is_never_echoed_in_ordinary_or_problem_headers() {
        const CANARY: &str = "7tenant@vendor-system=caller-controlled-canary";
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            "traceparent",
            HeaderValue::from_static("00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"),
        );
        request_headers.insert("tracestate", HeaderValue::from_static(CANARY));
        let trace = TraceContext::from_headers(&request_headers);

        let mut ordinary_headers = HeaderMap::new();
        ordinary_headers.insert("tracestate", HeaderValue::from_static(CANARY));
        trace.apply(&mut ordinary_headers);
        assert!(!ordinary_headers.contains_key("tracestate"));

        let response = ProblemCode::Internal.response(&trace);
        assert!(!response.headers().contains_key("tracestate"));
        assert!(response.headers().values().all(|value| {
            !value
                .to_str()
                .expect("response headers are ASCII")
                .contains("caller-controlled-canary")
        }));
    }
}

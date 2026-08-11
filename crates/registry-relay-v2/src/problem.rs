// SPDX-License-Identifier: Apache-2.0
//! Value-free RFC 9457 problems for Relay V2.
//!
//! The public `code` is a Registry Stack identifier rather than an internal
//! error.  Callers must never attach rejected selector values, SQL, source
//! paths, token material, or principal identifiers to a problem.

use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, Response, StatusCode};
pub use registry_platform_httpsec::{ProblemBody, TraceContext, TraceId};

const PROBLEM_BASE: &str = "https://id.registrystack.org/problems/registry-relay/";

macro_rules! define_problem_codes {
    ($(
        $variant:ident => {
            code: $code:literal,
            title: $title:literal,
            status: $status:literal,
            detail: $detail:literal
        }
    ),+ $(,)?) => {
        /// Closed public failure classes for the V2 HTTP boundary.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum ProblemCode {
            $($variant),+
        }

        impl ProblemCode {
            /// Complete inventory used to generate the public identifier catalog.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            #[must_use]
            pub const fn code(self) -> &'static str {
                match self {
                    $(Self::$variant => $code),+
                }
            }

            #[must_use]
            pub const fn title(self) -> &'static str {
                match self {
                    $(Self::$variant => $title),+
                }
            }

            #[must_use]
            pub const fn status(self) -> u16 {
                match self {
                    $(Self::$variant => $status),+
                }
            }

            #[must_use]
            pub const fn detail(self) -> &'static str {
                match self {
                    $(Self::$variant => $detail),+
                }
            }
        }
    };
}

define_problem_codes! {
    ConsultationInvalidRequest => { code: "consultation.invalid_request", title: "Consultation request is invalid", status: 400, detail: "the consultation request is invalid" },
    AggregateDataInvalidRequest => { code: "aggregate-data.invalid_request", title: "Aggregate data request is invalid", status: 400, detail: "the aggregate data request is invalid" },
    FieldsInvalid => { code: "request.fields_invalid", title: "Field selection is invalid", status: 400, detail: "field selection is invalid" },
    UnknownFilter => { code: "filter.unknown_field", title: "Filter is not declared", status: 400, detail: "filter is not declared for this operation" },
    InvalidFilter => { code: "filter.invalid_value", title: "Filter value is invalid", status: 400, detail: "filter value is invalid" },
    CursorInvalid => { code: "query.cursor_invalid", title: "Cursor is invalid", status: 400, detail: "cursor is invalid for this query" },
    AccessProfileInvalid => { code: "request.access_profile_invalid", title: "Access profile selection is invalid", status: 400, detail: "access profile selection is invalid" },
    MissingCredential => { code: "auth.missing_credential", title: "Bearer access token is required", status: 401, detail: "a bearer access token is required" },
    InvalidCredential => { code: "auth.invalid_credential", title: "Bearer access token is invalid", status: 401, detail: "bearer access token validation failed" },
    ConsultationDenied => { code: "consultation.denied", title: "Consultation is not permitted", status: 403, detail: "the consultation is not permitted" },
    AggregateDataDenied => { code: "aggregate-data.denied", title: "Aggregate data access is not permitted", status: 403, detail: "aggregate data access is not permitted" },
    ResourceNotFound => { code: "resource.not_found", title: "Requested resource was not found", status: 404, detail: "the requested resource was not found" },
    ConsultationUnresolved => { code: "consultation.unresolved", title: "Requested record was not resolved", status: 404, detail: "the requested record was not resolved" },
    UnsupportedFormat => { code: "format.unsupported", title: "Requested format is not supported", status: 406, detail: "the requested format is not supported" },
    BodyTooLarge => { code: "internal.payload_too_large", title: "Request body is too large", status: 413, detail: "request body exceeds the configured limit" },
    ConsultationResponseTooLarge => { code: "consultation.response_too_large", title: "Consultation response is too large", status: 413, detail: "the consultation response exceeds the configured limit" },
    AggregateDataTooLarge => { code: "aggregate-data.too_large", title: "Aggregate data request is too broad", status: 413, detail: "the aggregate data request exceeds its observation limit" },
    UriTooLong => { code: "internal.uri_too_long", title: "Request URI is too long", status: 414, detail: "request URI exceeds the configured limit" },
    UnsupportedMediaType => { code: "request.media_type_unsupported", title: "Request media type is not supported", status: 415, detail: "request body must use application/json" },
    RateLimited => { code: "consultation.rate_limited", title: "Consultation quota is exhausted", status: 429, detail: "the consultation quota is exhausted" },
    AggregateDataRateLimited => { code: "aggregate-data.rate_limited", title: "Aggregate data quota is exhausted", status: 429, detail: "the aggregate data quota is exhausted" },
    Internal => { code: "internal.unhandled", title: "Request could not be served", status: 500, detail: "the request could not be served" },
    SourceUnavailable => { code: "source.unavailable", title: "Authoritative source is unavailable", status: 503, detail: "the authoritative source is unavailable" },
    AuditUnavailable => { code: "audit.unavailable", title: "Required audit is unavailable", status: 503, detail: "required audit is unavailable" },
    ServiceNotReady => { code: "service.not_ready", title: "Service is not ready", status: 503, detail: "the service is not ready" },
    Timeout => { code: "internal.timeout", title: "Request timed out", status: 504, detail: "request exceeded the configured timeout" },
}

impl ProblemCode {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn public_problem_inventory_has_unique_codes_and_type_uris() {
        let mut codes = BTreeSet::new();
        let mut type_uris = BTreeSet::new();
        for problem in ProblemCode::ALL {
            assert!(codes.insert(problem.code()));
            assert!(type_uris.insert(problem.type_uri()));
        }
    }

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
    fn version_zero_traceparent_rejects_non_lowercase_hex() {
        for value in [
            "00-0123456789abcdeF0123456789abcdef-0123456789abcdef-01",
            "00-0123456789abcdef0123456789abcdef-0123456789abcdeF-01",
            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-0A",
        ] {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                "traceparent",
                HeaderValue::from_str(value).expect("fixture is a valid HTTP header value"),
            );
            let trace = TraceContext::from_headers(&headers);
            assert_ne!(
                trace.trace_id.as_str(),
                "0123456789abcdef0123456789abcdef",
                "accepted non-lowercase traceparent {value}"
            );
        }
    }

    #[test]
    fn invalid_traceparent_is_replaced_with_server_context() {
        let supplied_trace_id = "0123456789abcdef0123456789abcdeF";
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "traceparent",
            HeaderValue::from_str(&format!("00-{supplied_trace_id}-0123456789abcdef-00"))
                .expect("fixture is a valid HTTP header value"),
        );

        let trace = TraceContext::from_headers(&headers);

        assert_ne!(
            trace.trace_id.as_str(),
            supplied_trace_id.to_ascii_lowercase()
        );
    }

    #[test]
    fn caller_tracestate_is_never_echoed_in_ordinary_or_problem_headers() {
        const CANARY: &str = "7tenant@vendor-system=caller-controlled-canary";
        let mut request_headers = axum::http::HeaderMap::new();
        request_headers.insert(
            "traceparent",
            HeaderValue::from_static("00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"),
        );
        request_headers.insert("tracestate", HeaderValue::from_static(CANARY));
        let trace = TraceContext::from_headers(&request_headers);

        let mut ordinary_headers = axum::http::HeaderMap::new();
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

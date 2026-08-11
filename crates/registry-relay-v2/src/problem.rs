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
pub use registry_relay_http_contract::ProblemCode;
use registry_relay_http_contract::PROBLEM_MEDIA_TYPE;

/// Relay-runtime response construction for the shared public problem catalog.
pub trait ProblemCodeResponseExt {
    #[must_use]
    fn body(self, trace_id: TraceId) -> ProblemBody;

    /// Serialize the one fixed public failure body and attach the effective
    /// W3C trace context. No rejected value is accepted by this API.
    #[must_use]
    fn response(self, trace: &TraceContext) -> Response<Body>;
}

impl ProblemCodeResponseExt for ProblemCode {
    fn body(self, trace_id: TraceId) -> ProblemBody {
        ProblemBody {
            type_uri: self.type_uri().to_owned(),
            title: self.title(),
            status: self.status(),
            detail: self.detail(),
            code: self.code(),
            trace_id,
        }
    }

    fn response(self, trace: &TraceContext) -> Response<Body> {
        let bytes = serde_json::to_vec(&self.body(trace.trace_id.clone()))
            .unwrap_or_else(|_| b"{}".to_vec());
        let mut response = Response::new(Body::from(bytes));
        *response.status_mut() =
            StatusCode::from_u16(self.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let headers = response.headers_mut();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(PROBLEM_MEDIA_TYPE));
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

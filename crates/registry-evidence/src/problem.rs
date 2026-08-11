//! Closed public problem details for the Evidence HTTP boundary.

use http::StatusCode;
use registry_platform_httpsec::{ProblemBody, TraceId};

const PROBLEM_BASE: &str = "https://id.registrystack.org/problems/registry-evidence/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProblemCode {
    MalformedRequest,
    InvalidSelector,
    AuthenticationFailed,
    NotAuthorized,
    ResponseFormatNotAcceptable,
    EvidenceNotAvailable,
    RateLimited,
    DependencyUnavailable,
    ServiceUnavailable,
    ResourceNotFound,
}

impl ProblemCode {
    /// Complete inventory used to generate the public identifier catalog.
    pub const ALL: &'static [Self] = &[
        Self::MalformedRequest,
        Self::InvalidSelector,
        Self::AuthenticationFailed,
        Self::NotAuthorized,
        Self::ResponseFormatNotAcceptable,
        Self::EvidenceNotAvailable,
        Self::RateLimited,
        Self::DependencyUnavailable,
        Self::ServiceUnavailable,
        Self::ResourceNotFound,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            Self::MalformedRequest => "evidence.invalid_request",
            Self::InvalidSelector => "request.selector_invalid",
            Self::AuthenticationFailed => "auth.invalid_credential",
            Self::NotAuthorized => "evidence.denied",
            Self::ResponseFormatNotAcceptable => "format.unsupported",
            Self::EvidenceNotAvailable => "evidence.unavailable",
            Self::RateLimited => "evidence.rate_limited",
            Self::DependencyUnavailable => "source.unavailable",
            Self::ServiceUnavailable => "service.unavailable",
            Self::ResourceNotFound => "resource.not_found",
        }
    }

    pub const fn status(self) -> StatusCode {
        match self {
            Self::MalformedRequest | Self::InvalidSelector => StatusCode::BAD_REQUEST,
            Self::AuthenticationFailed => StatusCode::UNAUTHORIZED,
            Self::NotAuthorized => StatusCode::FORBIDDEN,
            Self::ResponseFormatNotAcceptable => StatusCode::NOT_ACCEPTABLE,
            Self::EvidenceNotAvailable => StatusCode::UNPROCESSABLE_ENTITY,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::DependencyUnavailable | Self::ServiceUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::ResourceNotFound => StatusCode::NOT_FOUND,
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::MalformedRequest => "Evidence request is invalid",
            Self::InvalidSelector => "Selector is invalid",
            Self::AuthenticationFailed => "Bearer access token is invalid",
            Self::NotAuthorized => "Evidence request is not permitted",
            Self::ResponseFormatNotAcceptable => "Requested format is not supported",
            Self::EvidenceNotAvailable => "Evidence could not be produced",
            Self::RateLimited => "Evidence request rate is exhausted",
            Self::DependencyUnavailable => "Authoritative source is unavailable",
            Self::ServiceUnavailable => "Service is unavailable",
            Self::ResourceNotFound => "Requested resource was not found",
        }
    }

    pub const fn detail(self) -> &'static str {
        match self {
            Self::MalformedRequest => "the Evidence request is invalid",
            Self::InvalidSelector => "selector does not match an available request profile",
            Self::AuthenticationFailed => "bearer access token validation failed",
            Self::NotAuthorized => "the Evidence request is not permitted",
            Self::ResponseFormatNotAcceptable => "the requested format is not supported",
            Self::EvidenceNotAvailable => "evidence could not be produced for this request",
            Self::RateLimited => "the Evidence request rate is exhausted",
            Self::DependencyUnavailable => "the authoritative source is unavailable",
            Self::ServiceUnavailable => "the request could not be served",
            Self::ResourceNotFound => "the requested resource was not found",
        }
    }

    pub fn type_uri(self) -> String {
        format!("{PROBLEM_BASE}{}", self.code().replace('.', "/"))
    }

    pub fn body(self, trace_id: TraceId) -> ProblemBody {
        ProblemBody {
            type_uri: self.type_uri(),
            title: self.title(),
            status: self.status().as_u16(),
            detail: self.detail(),
            code: self.code(),
            trace_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unresolved_internal_classes_share_one_exact_public_shape() {
        let trace = TraceId::parse("0123456789abcdef0123456789abcdef").expect("trace parses");
        let no_match = ProblemCode::EvidenceNotAvailable.body(trace.clone());
        let ambiguous = ProblemCode::EvidenceNotAvailable.body(trace);
        assert_eq!(no_match, ambiguous);
        assert_eq!(
            serde_json::to_value(no_match).expect("problem serializes"),
            serde_json::json!({
                "type": "https://id.registrystack.org/problems/registry-evidence/evidence/unavailable",
                "title": "Evidence could not be produced",
                "status": 422,
                "detail": "evidence could not be produced for this request",
                "code": "evidence.unavailable",
                "traceId": "0123456789abcdef0123456789abcdef"
            })
        );
    }

    #[test]
    fn every_code_has_the_contract_status_and_title() {
        let cases = [
            (
                ProblemCode::MalformedRequest,
                400,
                "Evidence request is invalid",
            ),
            (ProblemCode::InvalidSelector, 400, "Selector is invalid"),
            (
                ProblemCode::AuthenticationFailed,
                401,
                "Bearer access token is invalid",
            ),
            (
                ProblemCode::NotAuthorized,
                403,
                "Evidence request is not permitted",
            ),
            (
                ProblemCode::ResponseFormatNotAcceptable,
                406,
                "Requested format is not supported",
            ),
            (
                ProblemCode::EvidenceNotAvailable,
                422,
                "Evidence could not be produced",
            ),
            (
                ProblemCode::RateLimited,
                429,
                "Evidence request rate is exhausted",
            ),
            (
                ProblemCode::DependencyUnavailable,
                503,
                "Authoritative source is unavailable",
            ),
            (
                ProblemCode::ServiceUnavailable,
                503,
                "Service is unavailable",
            ),
            (
                ProblemCode::ResourceNotFound,
                404,
                "Requested resource was not found",
            ),
        ];
        for (code, status, title) in cases {
            assert_eq!(code.status().as_u16(), status);
            assert_eq!(code.title(), title);
        }
    }
}

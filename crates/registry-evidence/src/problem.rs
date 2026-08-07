//! Closed public problem details for the Evidence HTTP boundary.

use http::StatusCode;

use crate::model::ProblemBody;

const PROBLEM_BASE: &str = "https://registrystack.org/problems/evidence/";

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
}

impl ProblemCode {
    pub const fn code(self) -> &'static str {
        match self {
            Self::MalformedRequest => "malformed_request",
            Self::InvalidSelector => "invalid_selector",
            Self::AuthenticationFailed => "authentication_failed",
            Self::NotAuthorized => "not_authorized",
            Self::ResponseFormatNotAcceptable => "response_format_not_acceptable",
            Self::EvidenceNotAvailable => "evidence_not_available",
            Self::RateLimited => "rate_limited",
            Self::DependencyUnavailable => "dependency_unavailable",
            Self::ServiceUnavailable => "service_unavailable",
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
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::MalformedRequest | Self::InvalidSelector => "Request is not valid",
            Self::AuthenticationFailed => "Authentication failed",
            Self::NotAuthorized => "Request is not authorized",
            Self::ResponseFormatNotAcceptable => "Requested response format is not acceptable",
            Self::EvidenceNotAvailable => "Evidence could not be produced",
            Self::RateLimited => "Request rate exceeded",
            Self::DependencyUnavailable | Self::ServiceUnavailable => {
                "Service temporarily unavailable"
            }
        }
    }

    pub fn body(self, operation: &str) -> ProblemBody {
        ProblemBody {
            type_uri: format!("{PROBLEM_BASE}{}", self.code()),
            title: self.title().to_string(),
            status: self.status().as_u16(),
            code: self.code().to_string(),
            operation: operation.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unresolved_internal_classes_share_one_exact_public_shape() {
        let no_match = ProblemCode::EvidenceNotAvailable.body("operation-0000000000000001");
        let ambiguous = ProblemCode::EvidenceNotAvailable.body("operation-0000000000000001");
        assert_eq!(no_match, ambiguous);
        assert_eq!(
            serde_json::to_value(no_match).expect("problem serializes"),
            serde_json::json!({
                "type": "https://registrystack.org/problems/evidence/evidence_not_available",
                "title": "Evidence could not be produced",
                "status": 422,
                "code": "evidence_not_available",
                "operation": "operation-0000000000000001"
            })
        );
    }

    #[test]
    fn every_code_has_the_contract_status_and_title() {
        let cases = [
            (ProblemCode::MalformedRequest, 400, "Request is not valid"),
            (ProblemCode::InvalidSelector, 400, "Request is not valid"),
            (
                ProblemCode::AuthenticationFailed,
                401,
                "Authentication failed",
            ),
            (ProblemCode::NotAuthorized, 403, "Request is not authorized"),
            (
                ProblemCode::ResponseFormatNotAcceptable,
                406,
                "Requested response format is not acceptable",
            ),
            (
                ProblemCode::EvidenceNotAvailable,
                422,
                "Evidence could not be produced",
            ),
            (ProblemCode::RateLimited, 429, "Request rate exceeded"),
            (
                ProblemCode::DependencyUnavailable,
                503,
                "Service temporarily unavailable",
            ),
            (
                ProblemCode::ServiceUnavailable,
                503,
                "Service temporarily unavailable",
            ),
        ];
        for (code, status, title) in cases {
            assert_eq!(code.status().as_u16(), status);
            assert_eq!(code.title(), title);
        }
    }
}

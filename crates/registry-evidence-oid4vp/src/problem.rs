// SPDX-License-Identifier: Apache-2.0

//! The closed problem vocabulary of the verifier service.
//!
//! The vocabulary is closed on purpose: a caller can enumerate every problem
//! this service can answer, and a problem outside this list is a defect. The
//! service builds every problem document from a [`ProblemCode`], so no problem
//! type is spelled anywhere else. A title and a description name the problem
//! and never a value.

/// The prefix of every problem type URI this service answers with.
pub const PROBLEM_TYPE_BASE: &str =
    "https://id.registrystack.org/problems/registry-evidence-oid4vp/";

/// Every problem the verifier service can answer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProblemCode {
    AuditUnavailable,
    BodyTooLarge,
    Capacity,
    InternalError,
    InvalidRequest,
    IssuerUnavailable,
    MethodNotAllowed,
    NotFound,
    NotYetPresented,
    RateLimited,
    RequestNotFound,
    RequestTimeout,
    SessionNotFound,
    Unauthorized,
    UnknownPolicy,
    UnsupportedMediaType,
    WalletError,
}

impl ProblemCode {
    /// The complete closed vocabulary, in code-string order.
    pub const ALL: &'static [Self] = &[
        Self::AuditUnavailable,
        Self::BodyTooLarge,
        Self::Capacity,
        Self::InternalError,
        Self::InvalidRequest,
        Self::IssuerUnavailable,
        Self::MethodNotAllowed,
        Self::NotFound,
        Self::NotYetPresented,
        Self::RateLimited,
        Self::RequestNotFound,
        Self::RequestTimeout,
        Self::SessionNotFound,
        Self::Unauthorized,
        Self::UnknownPolicy,
        Self::UnsupportedMediaType,
        Self::WalletError,
    ];

    /// The last segment of the problem type URI.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuditUnavailable => "audit-unavailable",
            Self::BodyTooLarge => "body-too-large",
            Self::Capacity => "capacity",
            Self::InternalError => "internal-error",
            Self::InvalidRequest => "invalid-request",
            Self::IssuerUnavailable => "issuer-unavailable",
            Self::MethodNotAllowed => "method-not-allowed",
            Self::NotFound => "not-found",
            Self::NotYetPresented => "not-yet-presented",
            Self::RateLimited => "rate-limited",
            Self::RequestNotFound => "request-not-found",
            Self::RequestTimeout => "request-timeout",
            Self::SessionNotFound => "session-not-found",
            Self::Unauthorized => "unauthorized",
            Self::UnknownPolicy => "unknown-policy",
            Self::UnsupportedMediaType => "unsupported-media-type",
            Self::WalletError => "wallet-error",
        }
    }

    /// The code for `code`, or `None` for anything outside the vocabulary.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|problem| problem.code() == code)
    }

    /// The full problem type URI.
    #[must_use]
    pub fn type_uri(self) -> String {
        format!("{PROBLEM_TYPE_BASE}{}", self.code())
    }

    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::AuditUnavailable | Self::Capacity | Self::IssuerUnavailable => 503,
            Self::BodyTooLarge => 413,
            Self::InternalError => 500,
            Self::InvalidRequest => 400,
            Self::MethodNotAllowed => 405,
            Self::NotFound | Self::RequestNotFound | Self::SessionNotFound => 404,
            Self::NotYetPresented => 409,
            Self::RateLimited => 429,
            Self::RequestTimeout => 408,
            Self::Unauthorized => 401,
            Self::UnknownPolicy | Self::WalletError => 422,
            Self::UnsupportedMediaType => 415,
        }
    }

    /// The fixed title. It names the problem and never a value.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::AuditUnavailable | Self::Capacity | Self::IssuerUnavailable => {
                "Service Unavailable"
            }
            Self::BodyTooLarge => "Payload Too Large",
            Self::InternalError => "Internal Server Error",
            Self::InvalidRequest => "Invalid Request",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::NotFound | Self::RequestNotFound | Self::SessionNotFound => "Not Found",
            Self::NotYetPresented => "Not Yet Presented",
            Self::RateLimited => "Too Many Requests",
            Self::RequestTimeout => "Request Timeout",
            Self::Unauthorized => "Unauthorized",
            Self::UnknownPolicy => "Unknown Policy",
            Self::UnsupportedMediaType => "Unsupported Media Type",
            Self::WalletError => "Wallet Error",
        }
    }

    /// The fixed description of the problem. It is value-free like the title.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::AuditUnavailable => {
                "The audit destination did not accept the operation. Try again after the service recovers."
            }
            Self::BodyTooLarge => "The request body exceeds the accepted size.",
            Self::Capacity => {
                "The service is at capacity or holds as many sessions as it allows. Retry after the interval given."
            }
            Self::InternalError => "The request could not be completed.",
            Self::InvalidRequest => "The request body is malformed or does not have the required members.",
            Self::IssuerUnavailable => {
                "The token issuer is unavailable. Retry after the interval given."
            }
            Self::MethodNotAllowed => "The route exists but not for this method.",
            Self::NotFound => "The requested route does not exist.",
            Self::NotYetPresented => "The wallet has not presented yet.",
            Self::RateLimited => "Too many requests. Retry after the interval given.",
            Self::RequestNotFound => {
                "The request object is unknown, expired, or no longer pending."
            }
            Self::RequestTimeout => "The request took longer than the service waits.",
            Self::SessionNotFound => {
                "The session is unknown, expired, already read, or created by another principal."
            }
            Self::Unauthorized => "A valid bearer token is required.",
            Self::UnknownPolicy => "No presentation policy has the identifier given.",
            Self::UnsupportedMediaType => "The request body is not application/json.",
            Self::WalletError => {
                "The wallet reported an error instead of presenting. The closed category names it."
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;

    #[test]
    fn the_vocabulary_is_closed_sorted_and_unique() {
        assert_eq!(ProblemCode::ALL.len(), 17);
        let codes: Vec<&str> = ProblemCode::ALL.iter().map(|p| p.code()).collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            codes, sorted,
            "ALL is in code-string order, without repeats"
        );
        for problem in ProblemCode::ALL {
            assert_eq!(ProblemCode::from_code(problem.code()), Some(*problem));
            assert!(problem.type_uri().starts_with(PROBLEM_TYPE_BASE));
            assert!(problem.type_uri().ends_with(problem.code()));
            assert!(StatusCode::from_u16(problem.http_status()).is_ok());
            assert!(!problem.title().is_empty());
            assert!(!problem.detail().is_empty());
        }
        assert_eq!(ProblemCode::from_code("unlisted"), None);
    }
}

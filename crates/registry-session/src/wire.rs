// SPDX-License-Identifier: Apache-2.0

//! Names the service and its generated gateway configuration share.
//!
//! The service's answers and the gateway fragments it generates must agree on
//! these values, so both read them from here.

/// The response header that only the session service's own answers carry: the
/// check's denials, the gateway's local reply when the check fails, and the
/// public routes' problem answers. A page reads it to tell the session's own
/// `session.expired` or `session.unavailable` from a product's answer with the
/// same status or code. The gateway removes it from every upstream answer
/// except the service's own public routes.
pub const ANSWER_MARKER_HEADER: &str = "registry-session-answer";

/// The value of [`ANSWER_MARKER_HEADER`].
pub const ANSWER_MARKER_VALUE: &str = "1";

/// The request header a page sets on its calls to a module.
pub const CLIENT_HEADER: &str = "registry-client";

/// The request header that names the site a request came from.
pub const ORIGIN_HEADER: &str = "origin";

/// The request header the browser fills in with the relation between the
/// requesting site and the target.
pub const FETCH_SITE_HEADER: &str = "sec-fetch-site";

/// The request headers the gateway forwards to the check: the session cookie
/// and the three the check's cross-site rules read. The check reads no other
/// request header than the method and the path.
pub const CHECK_REQUEST_HEADERS: [&str; 4] =
    ["cookie", ORIGIN_HEADER, FETCH_SITE_HEADER, CLIENT_HEADER];

/// The prefix of every session problem's `type` URI.
const PROBLEM_TYPE_PREFIX: &str =
    "https://id.registrystack.org/problems/registry-platform/session/";

/// Every problem the service answers: its code suffix and the one `type` URI
/// that goes with it. A client treats a 401 or 503 as the session's own answer
/// only when the marker header and this URI both arrive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProblemKind {
    Refused,
    Expired,
    Unavailable,
    ReturnRefused,
    RateLimited,
    Busy,
    NotFound,
    MethodNotAllowed,
    Internal,
}

impl ProblemKind {
    /// Every kind, for tests that cover each one.
    pub const ALL: [Self; 9] = [
        Self::Refused,
        Self::Expired,
        Self::Unavailable,
        Self::ReturnRefused,
        Self::RateLimited,
        Self::Busy,
        Self::NotFound,
        Self::MethodNotAllowed,
        Self::Internal,
    ];

    /// The suffix of the code and of the `type` URI.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::Expired => "expired",
            Self::Unavailable => "unavailable",
            Self::ReturnRefused => "return-refused",
            Self::RateLimited => "rate-limited",
            Self::Busy => "busy",
            Self::NotFound => "not-found",
            Self::MethodNotAllowed => "method-not-allowed",
            Self::Internal => "internal",
        }
    }

    /// The problem's `code` member.
    #[must_use]
    pub fn code(self) -> String {
        format!("session.{}", self.suffix())
    }

    /// The problem's `type` URI.
    #[must_use]
    pub fn type_uri(self) -> String {
        format!("{PROBLEM_TYPE_PREFIX}{}", self.suffix())
    }

    /// The problem's `title` member.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Refused => "Forbidden",
            Self::Expired => "Session expired",
            Self::Unavailable => "Session service unavailable",
            Self::ReturnRefused => "Return path not accepted",
            Self::RateLimited => "Too many requests",
            Self::Busy => "Busy",
            Self::NotFound => "Not found",
            Self::MethodNotAllowed => "Method not allowed",
            Self::Internal => "Something went wrong",
        }
    }
}

/// A no-store problem answer for `kind` with the answer marker. Nothing from
/// the request is echoed.
#[must_use]
pub fn problem(kind: ProblemKind, status: axum::http::StatusCode) -> axum::response::Response {
    use axum::http::{header, HeaderName, HeaderValue};
    let mut response =
        registry_platform_httpsec::Problem::new(&kind.type_uri(), kind.title(), status)
            .with_extra("code", serde_json::Value::from(kind.code()))
            .into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        HeaderName::from_static(ANSWER_MARKER_HEADER),
        HeaderValue::from_static(ANSWER_MARKER_VALUE),
    );
    response
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;

    #[tokio::test]
    async fn every_problem_carries_its_own_type_uri_its_code_and_the_marker() {
        let mut seen = std::collections::HashSet::new();
        for kind in ProblemKind::ALL {
            let response = problem(kind, StatusCode::BAD_REQUEST);
            assert_eq!(
                response
                    .headers()
                    .get(ANSWER_MARKER_HEADER)
                    .map(|v| v.to_str().ok()),
                Some(Some(ANSWER_MARKER_VALUE))
            );
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .expect("body");
            let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
            assert_eq!(body["type"], kind.type_uri());
            assert_eq!(body["code"], kind.code());
            assert!(kind.type_uri().starts_with(PROBLEM_TYPE_PREFIX));
            assert!(seen.insert(kind.type_uri()), "one URI per code");
        }
    }
}

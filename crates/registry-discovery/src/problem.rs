// SPDX-License-Identifier: Apache-2.0
//! Fixed value-free RFC 9457 Discovery problems.

use crate::query::QueryError;
use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, Response, StatusCode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProblemCode {
    InvalidRequest,
    NotFound,
    ResultBoundExceeded,
    Unavailable,
}

impl ProblemCode {
    pub const ALL: [Self; 4] = [
        Self::InvalidRequest,
        Self::NotFound,
        Self::ResultBoundExceeded,
        Self::Unavailable,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid-request",
            Self::NotFound => "not-found",
            Self::ResultBoundExceeded => "result-bound-exceeded",
            Self::Unavailable => "unavailable",
        }
    }

    #[must_use]
    pub const fn type_uri(self) -> &'static str {
        match self {
            Self::InvalidRequest => {
                "https://id.registrystack.org/problems/registry-discovery/invalid-request"
            }
            Self::NotFound => "https://id.registrystack.org/problems/registry-discovery/not-found",
            Self::ResultBoundExceeded => {
                "https://id.registrystack.org/problems/registry-discovery/result-bound-exceeded"
            }
            Self::Unavailable => {
                "https://id.registrystack.org/problems/registry-discovery/unavailable"
            }
        }
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::InvalidRequest => "Invalid request",
            Self::NotFound => "Not found",
            Self::ResultBoundExceeded => "Result bound exceeded",
            Self::Unavailable => "Unavailable",
        }
    }

    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::InvalidRequest => "The Discovery request is invalid.",
            Self::NotFound => "The requested Discovery resource was not found.",
            Self::ResultBoundExceeded => {
                "The complete Discovery result exceeds its configured bound."
            }
            Self::Unavailable => "Registry Discovery is temporarily unavailable.",
        }
    }

    #[must_use]
    pub fn response(self) -> Response<Body> {
        let mut response = Response::new(Body::from(self.body()));
        *response.status_mut() = self.status();
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }

    const fn body(self) -> &'static [u8] {
        match self {
            Self::InvalidRequest => br#"{"type":"https://id.registrystack.org/problems/registry-discovery/invalid-request","title":"Invalid request","status":400}"#.as_slice(),
            Self::NotFound => br#"{"type":"https://id.registrystack.org/problems/registry-discovery/not-found","title":"Not found","status":404}"#.as_slice(),
            Self::ResultBoundExceeded => br#"{"type":"https://id.registrystack.org/problems/registry-discovery/result-bound-exceeded","title":"Result bound exceeded","status":422}"#.as_slice(),
            Self::Unavailable => br#"{"type":"https://id.registrystack.org/problems/registry-discovery/unavailable","title":"Unavailable","status":503}"#.as_slice(),
        }
    }

    pub const fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::ResultBoundExceeded => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl From<QueryError> for ProblemCode {
    fn from(value: QueryError) -> Self {
        match value {
            QueryError::InvalidRequest => Self::InvalidRequest,
            QueryError::ResultBoundExceeded => Self::ResultBoundExceeded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problems_are_static_and_value_free() {
        for problem in ProblemCode::ALL {
            let expected = format!(
                r#"{{"type":"{}","title":"{}","status":{}}}"#,
                problem.type_uri(),
                problem.title(),
                problem.status().as_u16()
            );
            assert_eq!(problem.body(), expected.as_bytes());
            let response = problem.response();
            assert_eq!(response.headers()[CONTENT_TYPE], "application/problem+json");
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
            assert_eq!(response.status(), problem.status());
            assert!(problem
                .type_uri()
                .starts_with("https://id.registrystack.org/problems/registry-discovery/"));
            assert!(crate::openapi::PROBLEM_CONTRACTS.contains(&(
                problem.type_uri(),
                problem.title(),
                problem.status().as_u16(),
            )));
        }
    }
}

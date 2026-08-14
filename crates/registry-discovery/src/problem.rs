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
    #[must_use]
    pub fn response(self) -> Response<Body> {
        let bytes = match self {
            Self::InvalidRequest => br#"{"type":"https://registrystack.org/problems/discovery/invalid-request","title":"Invalid request","status":400}"#.as_slice(),
            Self::NotFound => br#"{"type":"https://registrystack.org/problems/discovery/not-found","title":"Not found","status":404}"#.as_slice(),
            Self::ResultBoundExceeded => br#"{"type":"https://registrystack.org/problems/discovery/result-bound-exceeded","title":"Result bound exceeded","status":422}"#.as_slice(),
            Self::Unavailable => br#"{"type":"https://registrystack.org/problems/discovery/unavailable","title":"Unavailable","status":503}"#.as_slice(),
        };
        let mut response = Response::new(Body::from(bytes));
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

    const fn status(self) -> StatusCode {
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
        for problem in [
            ProblemCode::InvalidRequest,
            ProblemCode::NotFound,
            ProblemCode::ResultBoundExceeded,
            ProblemCode::Unavailable,
        ] {
            let response = problem.response();
            assert_eq!(response.headers()[CONTENT_TYPE], "application/problem+json");
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        }
    }
}

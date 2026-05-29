// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use registry_notary_core::EvidenceError;
use serde_json::json;
use ulid::Ulid;

use crate::api::{evidence_detail, evidence_status, evidence_title};

#[derive(Debug)]
pub(super) struct FederationProblem {
    pub(super) status: StatusCode,
    problem_type: String,
    title: String,
    detail: String,
    pub(super) code: String,
}

impl FederationProblem {
    pub(super) fn new(status: StatusCode, suffix: &str, title: &str, code: &str) -> Self {
        Self {
            status,
            problem_type: format!("urn:registry-notary:problem:federation:{suffix}"),
            title: title.to_string(),
            detail: title.to_ascii_lowercase(),
            code: code.to_string(),
        }
    }

    pub(super) fn invalid_request(detail: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            problem_type: "urn:registry-notary:problem:federation:invalid-request".to_string(),
            title: "Invalid federation request".to_string(),
            detail: detail.to_string(),
            code: "federation.invalid_request".to_string(),
        }
    }

    pub(super) fn invalid_request_owned() -> Self {
        Self::invalid_request("required federation claim is missing")
    }

    pub(super) fn invalid_token() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid-token",
            "Invalid federation token",
            "federation.invalid_token",
        )
    }

    pub(super) fn forbidden(detail: &str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            problem_type: "urn:registry-notary:problem:federation:forbidden".to_string(),
            title: "Federation request forbidden".to_string(),
            detail: detail.to_string(),
            code: "federation.forbidden".to_string(),
        }
    }

    pub(super) fn server_disabled() -> Self {
        Self::new(
            StatusCode::NOT_IMPLEMENTED,
            "disabled",
            "Federation is disabled",
            "federation.disabled",
        )
    }

    pub(super) fn server_error(detail: &str) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            problem_type: "urn:registry-notary:problem:federation:server-error".to_string(),
            title: "Federation server error".to_string(),
            detail: detail.to_string(),
            code: "federation.server_error".to_string(),
        }
    }

    pub(super) fn from_evidence_error(error: EvidenceError) -> Self {
        let status = evidence_status(&error);
        Self {
            status,
            problem_type: format!("urn:registry-notary:problem:federation:{}", error.code()),
            title: evidence_title(&error).to_string(),
            detail: evidence_detail(&error).to_string(),
            code: error.audit_code().to_string(),
        }
    }
}

pub(super) fn federation_problem_response(problem: FederationProblem) -> Response {
    let body = json!({
        "type": problem.problem_type,
        "title": problem.title,
        "status": problem.status.as_u16(),
        "detail": problem.detail,
        "code": problem.code,
        "instance": format!("urn:ulid:{}", Ulid::new()),
    });
    let mut response = (problem.status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
}

pub(super) async fn apply_denial_latency(started: Instant, minimum_denial_latency_ms: u64) {
    let floor = Duration::from_millis(minimum_denial_latency_ms);
    let elapsed = started.elapsed();
    if elapsed < floor {
        tokio::time::sleep(floor - elapsed).await;
    }
}

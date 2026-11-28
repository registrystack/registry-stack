// SPDX-License-Identifier: Apache-2.0

//! A key source that does not answer. The caller is answered
//! `service.unavailable` with `Retry-After`, never a 401, and the operator's
//! counter records `key-source-unavailable`. The database is named by
//! `DOCUMENTS_TEST_DATABASE_URL`.

mod support;

use axum::body::Body;
use axum::http::Request;
use registry_documents::runtime::{prepare_with_verifier, Prepared};
use registry_platform_authcommon::FailedCheck;
use support::{
    Api, Deployment, FakeVerifier, APPROVE, CITIZEN, DATABASE_STORAGE, DISABLED_VERIFIER,
};
use tower::ServiceExt as _;

/// The count `documents_request_refusals_total` holds for `check`.
async fn counted(prepared: &Prepared, check: FailedCheck) -> u64 {
    let response = prepared
        .metrics_app()
        .expect("a metrics listener is configured")
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let text = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let prefix = format!(
        "documents_request_refusals_total{{check=\"{}\"}} ",
        check.as_str()
    );
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("no series for {}\n{text}", check.as_str()))
        .parse()
        .unwrap()
}

#[tokio::test]
async fn an_unreachable_key_source_answers_unavailable_and_counts_the_check() {
    let mut deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    deployment.configure(&format!("metricsListener:\n  bind: 127.0.0.1:{port}\n"));
    // Nothing listens on the discard port, so every key fetch fails.
    deployment.fetch_keys_from("http://127.0.0.1:9/jwks");
    deployment.migrate().await;
    let prepared = prepare_with_verifier(
        &deployment.runtime,
        FakeVerifier::new("refusal-key-source", APPROVE),
        support::TEST_POSTURE,
    )
    .await
    .expect("the runtime prepares without reaching the key source");
    let api = Api::new(&prepared);
    let before = counted(&prepared, FailedCheck::KeySourceUnavailable).await;
    let answer = api.get(CITIZEN, "/v1/documents").await;
    assert_eq!(
        answer.status,
        503,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(answer.headers["retry-after"], "5");
    assert_eq!(answer.headers["content-type"], "application/problem+json");
    assert_eq!(answer.json()["code"], "service.unavailable");
    assert!(answer.headers.get("www-authenticate").is_none());
    assert_eq!(
        counted(&prepared, FailedCheck::KeySourceUnavailable).await,
        before + 1
    );
    drop(deployment);
}

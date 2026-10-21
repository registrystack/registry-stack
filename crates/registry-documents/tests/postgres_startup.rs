// SPDX-License-Identifier: Apache-2.0

//! Database-backed startup tests: a runtime prepared against a real
//! PostgreSQL server answers its health route through the Rust client and
//! refuses every other route with a typed problem, a runtime whose database
//! cannot be reached refuses to start before it binds, and so does one whose
//! database does not carry this release's schema.

mod support;

use std::time::Duration;

use registry_documents::runtime::{prepare, RuntimeError};
use registry_documents_client::{DocumentsClient, DocumentsClientConfig, ProblemCode};
use support::{database_url, Deployment, DATABASE_STORAGE, DISABLED_VERIFIER};
use url::Url;

#[tokio::test]
async fn a_prepared_runtime_answers_health_and_refuses_every_other_route() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let prepared = prepare(&deployment.runtime)
        .await
        .expect("the runtime prepares");
    let address = prepared.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(prepared.serve_until(async {
        stopped.await.ok();
    }));

    let base = Url::parse(&format!("http://{address}/")).unwrap();
    let client = DocumentsClient::new(
        DocumentsClientConfig::new(base.clone()).with_request_timeout(Duration::from_secs(5)),
    )
    .unwrap();
    client.health().await.expect("the health route answers");

    for (method, path) in [
        (reqwest::Method::GET, "documents"),
        (reqwest::Method::POST, "documents"),
        (
            reqwest::Method::PUT,
            "uploads/00000000-0000-4000-8000-000000000000/content",
        ),
    ] {
        let response = reqwest::Client::new()
            .request(method, base.join(path).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()["content-type"],
            "application/problem+json"
        );
        let problem: serde_json::Value = response.json().await.unwrap();
        assert_eq!(
            problem["type"],
            registry_documents_client::type_uri(ProblemCode::RequestNotFound.code())
        );
    }

    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_runtime_whose_database_refuses_the_credential_does_not_start() {
    let mut refused = Url::parse(&database_url()).unwrap();
    refused.set_password(Some("not-the-test-password")).unwrap();
    let deployment =
        Deployment::with_url(DATABASE_STORAGE, DISABLED_VERIFIER, Some(refused.as_str())).await;
    let error = prepare(&deployment.runtime)
        .await
        .expect_err("startup is refused");
    let RuntimeError::Database { stage, .. } = error else {
        panic!("a database refusal, not {error}");
    };
    assert_eq!(stage, "runtime database connection");
}

#[tokio::test]
async fn a_runtime_over_a_database_without_the_schema_does_not_start() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    let error = prepare(&deployment.runtime)
        .await
        .expect_err("startup is refused");
    let RuntimeError::Database { stage, .. } = error else {
        panic!("a database refusal, not {error}");
    };
    assert_eq!(stage, "runtime database schema check");
}

#[tokio::test]
async fn applying_the_schema_twice_applies_nothing_twice() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    deployment.migrate().await;
    let rows = deployment
        .admin
        .query(
            &format!(
                "SELECT version FROM {}.documents_schema_migrations",
                deployment.schema
            ),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, i64>(0), 100);
}

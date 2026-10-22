// SPDX-License-Identifier: Apache-2.0

//! Database-backed startup tests: a runtime prepared against a real
//! PostgreSQL server answers its health route through the Rust client,
//! refuses a document route without a verified bearer token and an unknown
//! route with typed problems, and serves a document route to a caller whose
//! token verifies; a runtime whose database
//! cannot be reached refuses to start before it binds, and so does one whose
//! database does not carry this release's schema.

mod support;

use std::time::Duration;

use registry_documents::activation::ActivationError;
use registry_documents::runtime::{prepare, RuntimeError};
use registry_documents_client::{DocumentsClient, DocumentsClientConfig, ProblemCode};
use support::{
    database_url, pdf, reservation_body, sha256, token, Deployment, APP, CITIZEN, DATABASE_STORAGE,
    DISABLED_VERIFIER,
};
use url::Url;

#[tokio::test]
async fn a_prepared_runtime_serves_documents_only_to_a_verified_caller() {
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

    let problem = |response: reqwest::Response| async move {
        assert_eq!(
            response.headers()["content-type"],
            "application/problem+json"
        );
        let problem: serde_json::Value = response.json().await.unwrap();
        problem["type"].as_str().unwrap().to_owned()
    };
    let http = reqwest::Client::new();
    let versioned = base.join("v1/").unwrap();
    for (method, path) in [
        (reqwest::Method::GET, "documents"),
        (reqwest::Method::POST, "documents"),
        (reqwest::Method::GET, "document-grants"),
        (reqwest::Method::GET, "document-policies"),
        (
            reqwest::Method::PUT,
            "uploads/00000000-0000-4000-8000-000000000000/content",
        ),
    ] {
        let response = http
            .request(method.clone(), versioned.join(path).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{path}"
        );
        assert_eq!(response.headers()["www-authenticate"], "Bearer");
        assert_eq!(
            problem(response).await,
            registry_documents_client::type_uri(ProblemCode::AuthenticationRefused.code())
        );
        // A token from no issuer this deployment trusts is the same refusal.
        let response = http
            .request(method, versioned.join(path).unwrap())
            .bearer_auth("not.a.token")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
    let response = http
        .get(versioned.join("no-such-route").unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert_eq!(
        problem(response).await,
        registry_documents_client::type_uri(ProblemCode::RequestNotFound.code())
    );

    // A verified caller reaches the document routes over the socket.
    let content = pdf(1024, 3);
    let reserved = http
        .post(versioned.join("documents").unwrap())
        .bearer_auth(token(APP))
        .header("idempotency-key", "startup-reservation")
        .json(&reservation_body(
            "citizen-delivery",
            CITIZEN.subject,
            &sha256(&content),
            1024,
            "application/pdf",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(reserved.status(), reqwest::StatusCode::CREATED);
    let policies = http
        .get(versioned.join("document-policies").unwrap())
        .bearer_auth(token(CITIZEN))
        .send()
        .await
        .unwrap();
    assert_eq!(policies.status(), reqwest::StatusCode::OK);

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
    assert!(
        matches!(
            error,
            RuntimeError::Activation(ActivationError::NotActivated)
        ),
        "an unactivated database refusal, not {error}"
    );
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

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
use registry_documents::runtime::{prepare_with_posture, RuntimeError};
use registry_documents_client::{DocumentsClient, DocumentsClientConfig, ProblemCode};
use support::{
    database_url, pdf, reservation_body, sha256, token, Deployment, APP, CITIZEN, DATABASE_STORAGE,
    DISABLED_VERIFIER, PARTNER_SERVICE, READER, STAFF,
};
use url::Url;

struct StartupLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for StartupLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn a_prepared_runtime_serves_documents_only_to_a_verified_caller() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    use tracing::Instrument as _;

    let startup_log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let capture = startup_log.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(move || StartupLog(capture.clone()))
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let prepared = prepare_with_posture(&deployment.runtime, support::TEST_POSTURE)
        .instrument(tracing::info_span!("documents_startup_under_test"))
        .await
        .expect("the runtime prepares");
    let log = String::from_utf8(startup_log.lock().unwrap().clone()).unwrap();
    let fields: Vec<_> = log
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|entry| entry["span"]["name"] == "documents_startup_under_test")
        .map(|entry| entry["fields"].clone())
        .collect();
    assert!(fields
        .iter()
        .any(|entry| entry["message"] == "posture declared"
            && entry["posture"] == "development"
            && entry["posture_source"] == "flag"
            && entry["development_settings"] == 1));
    assert!(fields.iter().any(|entry| entry["error_code"]
        == "documents.posture.content-verification-disabled"
        && entry["pointer"] == "/contentVerification"));
    let address = prepared.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(prepared.serve_until(async {
        stopped.await.ok();
    }));

    let base = Url::parse(&format!("http://{address}/")).unwrap();
    let client = DocumentsClient::new(
        DocumentsClientConfig::new_without_peer_policy(base.clone())
            .with_attempt_timeout(Duration::from_secs(5)),
    )
    .unwrap();
    assert!(matches!(
        client.health().await,
        Err(registry_documents_client::DocumentsClientError::Protocol {
            status: 200,
            failure: registry_documents_client::DocumentsProtocolFailure::HeaderBounds,
            ..
        })
    ));
    let ready = reqwest::get(base.join("ready").unwrap()).await.unwrap();
    assert_eq!(ready.status(), reqwest::StatusCode::OK);
    assert_eq!(ready.headers()["registry-posture"], "development");
    assert_eq!(
        ready.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({
            "status": "ready",
            "posture": "development",
            "developmentSettings": [{
                "code": "documents.posture.content-verification-disabled",
                "pointer": "/contentVerification",
            }],
        })
    );

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

    let lines = deployment.audit_entries();
    assert!(!lines.is_empty());
    assert!(lines.iter().all(|line| line["posture"] == "development"));

    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

/// The runtime file says `allowedClients: from-package` and lists no client.
/// Each requester client of the package reaches its profile, and a client the
/// package does not name is refused.
#[tokio::test]
async fn a_runtime_that_admits_the_package_clients_serves_a_call_from_each() {
    let mut deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.admit_package_clients();
    let text = std::fs::read_to_string(&deployment.runtime).unwrap();
    assert!(text.contains("allowedClients: from-package"), "{text}");
    deployment.migrate().await;
    let prepared = prepare_with_posture(&deployment.runtime, support::TEST_POSTURE)
        .await
        .expect("the runtime prepares");
    let address = prepared.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(prepared.serve_until(async {
        stopped.await.ok();
    }));
    let http = reqwest::Client::new();
    let policies = format!("http://{address}/v1/document-policies");
    for principal in [APP, CITIZEN, READER, STAFF] {
        let response = http
            .get(&policies)
            .bearer_auth(token(principal))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK, "{principal:?}");
    }
    let response = http
        .get(&policies)
        .bearer_auth(token(PARTNER_SERVICE))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_runtime_whose_database_refuses_the_credential_does_not_start() {
    let mut refused = Url::parse(&database_url()).unwrap();
    refused.set_password(Some("not-the-test-password")).unwrap();
    let deployment =
        Deployment::with_url(DATABASE_STORAGE, DISABLED_VERIFIER, Some(refused.as_str())).await;
    let error = prepare_with_posture(&deployment.runtime, support::TEST_POSTURE)
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
    let error = prepare_with_posture(&deployment.runtime, support::TEST_POSTURE)
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
                "SELECT version FROM {}.documents_schema_migrations ORDER BY version",
                deployment.schema
            ),
            &[],
        )
        .await
        .unwrap();
    let versions: Vec<i64> = rows.iter().map(|row| row.get(0)).collect();
    assert_eq!(versions, [100, 101]);
}

const HTTP_VERIFIER: &str = "contentVerification:\n  type: http\n  url: http://127.0.0.1:9/verify\n  authorizationRef: secret:file/verifier-token\n  policyId: documents-default\n";

#[tokio::test]
async fn production_starts_with_a_loopback_http_issuer() {
    let mut deployment = Deployment::new(DATABASE_STORAGE, HTTP_VERIFIER).await;
    deployment.secret("verifier-token", "synthetic-verifier-token");
    let document = std::fs::read_to_string(&deployment.runtime).unwrap();
    let loopback = document.replace(
        "issuer: https://identity.example.test/realms/registry",
        "issuer: http://127.0.0.1:8080/realms/registry",
    );
    assert_ne!(document, loopback);
    std::fs::write(&deployment.runtime, loopback).unwrap();
    let posture = registry_platform_config::declared_from(Some("production"), None).unwrap();
    let config =
        registry_documents::config::RuntimeConfig::load_with_posture(&deployment.runtime, posture)
            .unwrap();
    registry_documents::runtime::apply_activation(&config, &Default::default())
        .await
        .unwrap();
    let prepared = prepare_with_posture(&deployment.runtime, posture)
        .await
        .unwrap();
    assert!(prepared.local_addr().unwrap().ip().is_loopback());
}

#[tokio::test]
async fn loopback_plaintext_database_transport_refuses_a_private_network_host_at_connect() {
    let deployment = Deployment::with_url(
        DATABASE_STORAGE,
        DISABLED_VERIFIER,
        Some("postgresql://synthetic@10.0.0.5/documents"),
    )
    .await;
    let document = std::fs::read_to_string(&deployment.runtime)
        .unwrap()
        .replace("testOnlyPlaintext: true", "transport: loopback-plaintext");
    std::fs::write(&deployment.runtime, document).unwrap();
    let error = prepare_with_posture(&deployment.runtime, support::TEST_POSTURE)
        .await
        .unwrap_err();
    let RuntimeError::Database {
        source: registry_documents::store::StoreError::Transport(error),
        ..
    } = error
    else {
        panic!("expected a database transport refusal, got {error:?}");
    };
    assert_eq!(error.code(), "platform.database.transport-host-mismatch");
}

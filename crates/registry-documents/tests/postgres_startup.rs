// SPDX-License-Identifier: Apache-2.0

//! Database-backed startup tests: a runtime prepared against a real
//! PostgreSQL server answers its health route through the Rust client and
//! refuses every other route with a typed problem, and a runtime whose
//! database cannot be reached refuses to start before it binds.
//!
//! The database is named by `DOCUMENTS_TEST_DATABASE_URL`. A test binary
//! that passes because its database URL is absent is not database
//! verification, so the variable is required: without it every test in this
//! file fails on the spot.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

use registry_documents::runtime::{prepare, RuntimeError};
use registry_documents_client::{DocumentsClient, DocumentsClientConfig, ProblemCode};
use url::Url;

fn database_url() -> String {
    std::env::var("DOCUMENTS_TEST_DATABASE_URL")
        .expect("DOCUMENTS_TEST_DATABASE_URL names a disposable PostgreSQL test server")
}

/// Write a development runtime configuration whose secrets are files under
/// `directory`; both database credentials hold `url`.
fn runtime_config(directory: &Path, url: &str) -> std::path::PathBuf {
    let secrets = directory.join("secrets");
    std::fs::create_dir(&secrets).unwrap();
    for (name, value) in [
        ("runtime-database-url", url),
        ("migration-database-url", url),
        ("documents-audit-key", "startup-test-audit-key-not-a-secret"),
    ] {
        let path = secrets.join(name);
        std::fs::write(&path, value).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let document = format!(
        "\
apiVersion: id.registrystack.org/formats/documents/runtime/v1alpha1
kind: DocumentsRuntimeConfig
identity:
  databaseId: registry-documents-startup-test
package:
  root: {package}
listener:
  bind: 127.0.0.1:0
  tlsTermination: development-loopback
  networkExposure: private-address
secretProviders:
  file:
    root: {secrets}
database:
  runtimeUrlRef: secret:file/runtime-database-url
  migrationUrlRef: secret:file/migration-database-url
  testOnlyPlaintext: true
authentication:
  oidc:
    issuer: https://identity.example.test/realms/registry
    audience: urn:example:documents
    allowedClients: [startup-test]
audit:
  destination: file
  path: {audit}
  hashKeyRef: secret:file/documents-audit-key
storage:
  type: database
  maximumDocumentBytes: 1048576
contentVerification:
  type: disabled
cleanup:
  erasure: active
",
        package = directory.join("package").display(),
        secrets = secrets.display(),
        audit = directory.join("audit.ndjson").display(),
    );
    let path = directory.join("runtime.yaml");
    std::fs::write(&path, document).unwrap();
    path
}

#[tokio::test]
async fn a_prepared_runtime_answers_health_and_refuses_every_other_route() {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let path = runtime_config(directory.path(), &database_url());
    let prepared = prepare(&path).await.expect("the runtime prepares");
    let address = prepared.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(prepared.serve_until(async {
        let _ = stopped.await;
    }));

    let base = Url::parse(&format!("http://{address}/")).unwrap();
    let client = DocumentsClient::new(
        DocumentsClientConfig::new(base.clone()).with_request_timeout(Duration::from_secs(5)),
    )
    .unwrap();
    client.health().await.expect("the health route answers");

    let response = reqwest::get(base.join("documents").unwrap()).await.unwrap();
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

    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_runtime_whose_database_refuses_the_credential_does_not_start() {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let mut refused = Url::parse(&database_url()).unwrap();
    refused.set_password(Some("not-the-test-password")).unwrap();
    let path = runtime_config(directory.path(), refused.as_str());
    let error = prepare(&path).await.expect_err("startup is refused");
    let RuntimeError::Database { stage, .. } = error else {
        panic!("a database refusal, not {error}");
    };
    assert_eq!(stage, "runtime database connection");
}

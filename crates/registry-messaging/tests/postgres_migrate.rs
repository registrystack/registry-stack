// SPDX-License-Identifier: Apache-2.0

//! Database-backed store tests: migrations applied concurrently and
//! repeatedly, version 3 discarding the idempotency records scoped to the
//! caller's pseudonym, readiness against the applied schema, a served
//! runtime answering `/ready` from a real PostgreSQL deployment, and the
//! `messaging` binary keeping its operational logs off a `stdout` audit
//! destination. The package ledger has its own suite, `postgres_package`.
//!
//! Every test runs in its own schema inside the database named by
//! `MESSAGING_TEST_DATABASE_URL`. A test binary that passes because its
//! database URL is absent is not database verification, so the variable is
//! required: without it every test in this file fails on the spot.

mod support;

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use axum::http::StatusCode;
use registry_messaging::activation::ApplyRequest;
use registry_messaging::config::{DatabaseConfig, RuntimeConfig};
use registry_messaging::package::{package_inputs, write_package_inputs};
use registry_messaging::runtime::{apply_activation, serve_from_path};
use registry_messaging::store::{PostgresStore, StoreError};
use registry_messaging_client::{MessagingClient, MessagingClientConfig};
use registry_messaging_core::CallerIdentity;
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::json;
use support::{email_submission, sender_token, Harness, ISSUER, SENDER_PRINCIPAL};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use uuid::Uuid;

/// One isolated schema and the secret reference that reaches it.
struct Isolated {
    schema: String,
    reference: String,
    admin: tokio_postgres::Client,
}

async fn isolated_schema() -> Isolated {
    let base = std::env::var("MESSAGING_TEST_DATABASE_URL")
        .expect("MESSAGING_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let schema = format!("messaging_{}", Uuid::new_v4().simple());
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");

    // The schema exists before any store resolves into it: table creation
    // follows search_path, and the scoped URL points every store connection
    // at this schema.
    let (admin, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("connect the messaging test database");
    tokio::spawn(async move { connection.await.expect("the messaging admin connection") });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("an isolated messaging schema");

    let secret_name = format!("MESSAGING_SCHEMA_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&secret_name, &scoped);
    Isolated {
        schema,
        reference: format!("secret:env/{secret_name}"),
        admin,
    }
}

fn database(reference: &str) -> DatabaseConfig {
    DatabaseConfig {
        runtime_url_ref: reference.to_owned(),
        migration_url_ref: reference.to_owned(),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    }
}

fn secrets() -> SecretResolver {
    SecretResolver::new([SecretProvider::Environment], "/private/tmp")
        .expect("the messaging test secret resolver")
}

async fn applied_versions(isolated: &Isolated) -> Vec<i64> {
    isolated
        .admin
        .query(
            &format!(
                "SELECT version FROM {}.messaging_schema_migrations ORDER BY version",
                isolated.schema
            ),
            &[],
        )
        .await
        .expect("the applied migrations")
        .iter()
        .map(|row| row.get(0))
        .collect()
}

#[tokio::test]
async fn concurrent_migrators_apply_each_version_once_and_both_succeed() {
    let isolated = isolated_schema().await;
    let config = database(&isolated.reference);
    let secrets = secrets();
    let first = PostgresStore::connect_migration(&config, &secrets).expect("a migration store");
    let second = PostgresStore::connect_migration(&config, &secrets).expect("a migration store");
    let third = PostgresStore::connect_migration(&config, &secrets).expect("a migration store");
    let (a, b, c) = tokio::join!(first.migrate(), second.migrate(), third.migrate());
    a.expect("the first concurrent migration");
    b.expect("the second concurrent migration");
    c.expect("the third concurrent migration");
    assert_eq!(applied_versions(&isolated).await, [1, 2, 3]);

    first
        .migrate()
        .await
        .expect("a repeated migration applies nothing");
    assert_eq!(applied_versions(&isolated).await, [1, 2, 3]);

    let runtime = PostgresStore::connect_runtime(&config, &secrets).expect("a runtime store");
    runtime.ready().await.expect("a migrated store is ready");
}

#[tokio::test]
async fn a_store_nobody_migrated_is_not_ready() {
    let isolated = isolated_schema().await;
    let runtime = PostgresStore::connect_runtime(&database(&isolated.reference), &secrets())
        .expect("a runtime store");
    assert!(runtime.ready().await.is_err());
}

#[tokio::test]
async fn a_store_carrying_an_unknown_version_is_not_ready() {
    let isolated = isolated_schema().await;
    let config = database(&isolated.reference);
    let store = PostgresStore::connect_migration(&config, &secrets()).expect("a migration store");
    store.migrate().await.expect("the migrations");
    isolated
        .admin
        .batch_execute(&format!(
            "INSERT INTO {}.messaging_schema_migrations(version, applied_at) VALUES (99, now())",
            isolated.schema
        ))
        .await
        .expect("a version from a newer runtime");
    assert!(matches!(
        store.ready().await,
        Err(StoreError::SchemaVersion)
    ));
}

/// Version 3 scopes every spent key to the caller's issuer and subject. It
/// discards the records written under the caller's pseudonym, so their keys
/// can be used again, and the runtime keys every later record by its caller.
#[tokio::test]
async fn version_3_discards_pseudonym_scoped_records_and_the_runtime_scopes_keys_to_the_caller() {
    let harness = Harness::start().await;
    let sender = sender_token();
    let (status, earlier) = harness
        .submit(&sender, "earlier", &email_submission())
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{earlier}");
    let pseudonym = harness
        .audit
        .principal_pseudonym(&CallerIdentity {
            issuer: ISSUER.to_owned(),
            subject: SENDER_PRINCIPAL.to_owned(),
        })
        .expect("the caller's pseudonym");

    // Rebuild the table as version 2 left it, holding the record a runtime
    // wrote under the caller's pseudonym and a tombstone whose message
    // retention deleted.
    let first_tail = include_str!("../migrations/0001_messaging.sql");
    let first_tail = &first_tail[first_tail
        .find("CREATE TABLE messaging_idempotency")
        .expect("version 1 creates the idempotency table")..];
    harness
        .isolated
        .admin
        .batch_execute(&format!(
            "CREATE TABLE version_3_scratch AS SELECT * FROM messaging_idempotency; \
             DROP TABLE messaging_idempotency; \
             DELETE FROM messaging_schema_migrations WHERE version = 3; \
             {first_tail}"
        ))
        .await
        .expect("the version 2 idempotency table");
    for statement in [
        "INSERT INTO messaging_idempotency \
             (principal, operation, idempotency_key, request_hash, message_id, \
              status_code, receipt, created_at, expires_at, erased_at) \
         SELECT $1::text, operation, idempotency_key, request_hash, message_id, \
                status_code, receipt, created_at, expires_at, erased_at \
           FROM version_3_scratch",
        "INSERT INTO messaging_idempotency \
             (principal, operation, idempotency_key, created_at, expires_at, erased_at) \
         VALUES ($1::text, 'submit-message', 'tombstone', now() - interval '40 days', \
                 now() - interval '10 days', now() - interval '10 days')",
    ] {
        harness.execute(statement, &[&pseudonym]).await;
    }
    harness.execute("DROP TABLE version_3_scratch", &[]).await;

    let applied = apply_activation(&harness.config, &ApplyRequest::default())
        .await
        .expect("messagingctl apply");
    assert_eq!(applied.schema_versions_applied, [3]);
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_idempotency")
            .await,
        0
    );
    assert_eq!(
        harness
            .count(
                "SELECT count(*) FROM information_schema.columns \
                  WHERE table_schema = current_schema() \
                    AND table_name = 'messaging_idempotency' AND column_name = 'principal'"
            )
            .await,
        0
    );

    // Each discarded key records a new message, under the caller's issuer
    // and subject, and is spent again.
    for key in ["earlier", "tombstone"] {
        let (status, receipt) = harness.submit(&sender, key, &email_submission()).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{key}: {receipt}");
        assert_ne!(receipt["id"], earlier["id"]);
        let replay = harness.submit(&sender, key, &email_submission()).await;
        assert_eq!(replay, (StatusCode::ACCEPTED, receipt));
    }
    let mut different = email_submission();
    different["correlationId"] = json!("case-43");
    let (status, problem) = harness.submit(&sender, "earlier", &different).await;
    assert_eq!(status, StatusCode::CONFLICT, "{problem}");
    assert_eq!(problem["code"], "idempotency.key-reused");
    let caller_keys: i64 = harness
        .isolated
        .admin
        .query_one(
            "SELECT count(*) FROM messaging_idempotency \
              WHERE submitter_issuer = $1 AND submitter_subject = $2",
            &[&ISSUER, &SENDER_PRINCIPAL],
        )
        .await
        .expect("the caller's keys")
        .get(0);
    assert_eq!(caller_keys, 2);
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        3
    );
}

/// A free loopback port, released for the runtime to bind.
fn free_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    listener.local_addr().expect("the bound address")
}

async fn get(address: SocketAddr, path: &str) -> Option<u16> {
    let mut stream = tokio::net::TcpStream::connect(address).await.ok()?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await.ok()?;
    response.strip_prefix("HTTP/1.1 ")?.get(..3)?.parse().ok()
}

/// A public P-256 key (RFC 7517, appendix A.1). Nothing in this test signs
/// a token; the key only has to be a well-formed verification key.
fn static_jwks() -> String {
    json!({"keys": [{
        "kty": "EC",
        "crv": "P-256",
        "kid": "test-1",
        "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
    }]})
    .to_string()
}

/// The audit block that writes the journal to a file under `root`.
fn file_audit(root: &Path) -> serde_json::Value {
    json!({"path": root.join("audit").join("messaging.jsonl")})
}

fn write_runtime(
    root: &Path,
    database_reference: &str,
    public: SocketAddr,
    metrics: SocketAddr,
    audit: serde_json::Value,
) {
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let package = root.join("package");
    std::fs::write(
        project.join("messaging.yaml"),
        serde_norway::to_string(&json!({
            "apiVersion": registry_messaging_core::MESSAGING_PACKAGE_API_VERSION,
            "kind": registry_messaging_core::MESSAGING_PACKAGE_KIND,
            "accessProfiles": [{
                "id": "operations",
                "principalClaim": "sub",
                "requiredScopes": ["messaging:operate"],
                "requesterClients": ["operations-console"],
                "role": "operator",
                "requestsPerMinute": 60,
                "burst": 10
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let inputs = package_inputs(&project).expect("the authored package inputs");
    write_package_inputs(&package, &inputs, None).expect("the installed package");

    let jwks_name = format!("MESSAGING_JWKS_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    let audit_name = format!("MESSAGING_AUDIT_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&jwks_name, static_jwks());
    std::env::set_var(&audit_name, "an-audit-master-secret-of-32-bytes!");
    let mut audit = audit;
    audit["hashKeyRef"] = json!(format!("secret:env/{audit_name}"));
    let runtime = json!({
        "apiVersion": registry_messaging_core::MESSAGING_RUNTIME_API_VERSION,
        "kind": registry_messaging_core::MESSAGING_RUNTIME_KIND,
        "identity": {"databaseId": "messaging-test"},
        "package": {"root": package},
        "listener": {"bind": public.to_string(), "tlsTermination": "development-loopback"},
        "metricsListener": {"bind": metrics.to_string()},
        "secretProviders": {"environment": {}},
        "database": {
            "runtimeUrlRef": database_reference,
            "migrationUrlRef": database_reference,
            "testOnlyPlaintext": true
        },
        "authentication": {"oidc": {
            "issuer": "https://identity.example.test",
            "audience": "urn:example:messaging",
            "jwksSource": {"kind": "static", "documentRef": format!("secret:env/{jwks_name}")},
            "allowedClients": ["operations-console"]
        }},
        "audit": audit
    });
    std::fs::write(
        root.join("runtime.yaml"),
        serde_norway::to_string(&runtime).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn a_served_runtime_is_ready_and_keeps_metrics_on_the_private_listener() {
    let isolated = isolated_schema().await;
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .expect("a runtime directory");
    let public = free_port();
    let metrics = free_port();
    write_runtime(
        root.path(),
        &isolated.reference,
        public,
        metrics,
        file_audit(root.path()),
    );
    let runtime_config = root.path().join("runtime.yaml");

    let config = RuntimeConfig::load(&runtime_config).expect("the runtime configuration");
    apply_activation(&config, &ApplyRequest::default())
        .await
        .expect("messagingctl apply");
    let served = tokio::spawn(serve_from_path(
        runtime_config.clone(),
        registry_messaging::dispatch::Transports::new(),
    ));

    let mut ready = None;
    for _ in 0..100 {
        ready = get(public, "/ready").await;
        if ready.is_some() || served.is_finished() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        !served.is_finished(),
        "the runtime stopped: {:?}",
        served.await
    );
    assert_eq!(ready, Some(200));
    assert_eq!(get(public, "/health").await, Some(200));
    assert_eq!(get(public, "/metrics").await, Some(404));
    assert_eq!(get(public, "/v1/messages/m-1").await, Some(401));
    assert_eq!(get(metrics, "/metrics").await, Some(200));
    assert_eq!(get(metrics, "/ready").await, Some(404));

    // The published client reads the served runtime as the contract promises.
    let client = MessagingClient::new(MessagingClientConfig::new(
        url::Url::parse(&format!("http://{public}/")).expect("the runtime URL"),
    ))
    .expect("a messaging client");
    client.health().await.expect("the client reads liveness");
    client.ready().await.expect("the client reads readiness");
    served.abort();

    let journal = std::fs::read_to_string(root.path().join("audit").join("messaging.jsonl"))
        .expect("the audit journal");
    assert_eq!(journal.lines().count(), 1);
    assert!(journal.contains("messaging.runtime.started"));
    assert!(!journal.contains("postgres://"));
    assert!(!journal.contains("an-audit-master-secret"));
}

/// A `stdout` audit destination carries audit entries alone: the binary's
/// operational log goes to stderr, so a strict JSON Lines collector reading
/// stdout never meets a log record.
#[tokio::test]
async fn a_stdout_audit_destination_never_carries_operational_logs() {
    let isolated = isolated_schema().await;
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .expect("a runtime directory");
    let public = free_port();
    let metrics = free_port();
    write_runtime(
        root.path(),
        &isolated.reference,
        public,
        metrics,
        json!({"destination": "stdout"}),
    );
    let runtime_config = root.path().join("runtime.yaml");
    let config = RuntimeConfig::load(&runtime_config).expect("the runtime configuration");
    apply_activation(&config, &ApplyRequest::default())
        .await
        .expect("messagingctl apply");

    // The secrets the configuration names are this process's environment,
    // which the binary inherits.
    let mut served = Command::new(env!("CARGO_BIN_EXE_messaging"))
        .arg("--runtime-config")
        .arg(&runtime_config)
        .arg("serve")
        .env("MESSAGING_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("messaging serve starts");
    let mut ready = None;
    // A freshly linked binary can take seconds to start on its first run.
    for _ in 0..400 {
        ready = get(public, "/ready").await;
        if ready.is_some() || served.try_wait().expect("the child state").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    served.kill().expect("stop messaging serve");
    let output = served.wait_with_output().expect("the served output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        ready,
        Some(200),
        "the runtime did not become ready: {stderr}"
    );
    assert!(
        stderr.contains("serving Registry Messaging"),
        "the operational log reaches stderr: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.contains("messaging.runtime.started"),
        "the audit entry reaches stdout: {stdout}"
    );
    for line in stdout.lines() {
        let entry: serde_json::Value = serde_json::from_str(line).expect("a JSON Lines entry");
        assert!(
            !line.contains("serving Registry Messaging") && entry.get("level").is_none(),
            "stdout carried a log record: {line}"
        );
    }
}

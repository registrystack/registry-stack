// SPDX-License-Identifier: Apache-2.0

//! Database-backed store tests: migrations applied concurrently and
//! repeatedly, readiness against the applied schema, and a served runtime
//! answering `/ready` from a real PostgreSQL deployment. The package ledger
//! has its own suite, `postgres_package`.
//!
//! Every test runs in its own schema inside the database named by
//! `MESSAGING_TEST_DATABASE_URL`. A test binary that passes because its
//! database URL is absent is not database verification, so the variable is
//! required: without it every test in this file fails on the spot.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use registry_messaging::config::{DatabaseConfig, RuntimeConfig};
use registry_messaging::runtime::{apply_package, migrate_from_path, serve_from_path};
use registry_messaging::store::{PostgresStore, StoreError};
use registry_messaging_client::{MessagingClient, MessagingClientConfig};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::json;
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
    assert_eq!(applied_versions(&isolated).await, [1]);

    first
        .migrate()
        .await
        .expect("a repeated migration applies nothing");
    assert_eq!(applied_versions(&isolated).await, [1]);

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

fn write_runtime(root: &Path, database_reference: &str, public: SocketAddr, metrics: SocketAddr) {
    let package = root.join("package");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::write(
        package.join("messaging.yaml"),
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

    let jwks_name = format!("MESSAGING_JWKS_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    let audit_name = format!("MESSAGING_AUDIT_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&jwks_name, static_jwks());
    std::env::set_var(&audit_name, "an-audit-master-secret-of-32-bytes!");
    let runtime = json!({
        "apiVersion": registry_messaging_core::MESSAGING_RUNTIME_API_VERSION,
        "kind": registry_messaging_core::MESSAGING_RUNTIME_KIND,
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
        "audit": {
            "path": root.join("audit").join("messaging.jsonl"),
            "hashKeyRef": format!("secret:env/{audit_name}")
        }
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
    let root = tempfile::tempdir().expect("a runtime directory");
    let public = free_port();
    let metrics = free_port();
    write_runtime(root.path(), &isolated.reference, public, metrics);
    let runtime_config = root.path().join("runtime.yaml");

    migrate_from_path(&runtime_config)
        .await
        .expect("messaging migrate");
    let config = RuntimeConfig::load(&runtime_config).expect("the runtime configuration");
    apply_package(&config, true)
        .await
        .expect("messagingctl apply --apply");
    let served = tokio::spawn(serve_from_path(runtime_config.clone()));

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

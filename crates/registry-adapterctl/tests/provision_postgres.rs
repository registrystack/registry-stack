// SPDX-License-Identifier: Apache-2.0

//! `adapterctl provision` against a real server, then `adapter serve` on what
//! it created: the facade migrates as the migration role, grants the runtime
//! role what its deployment uses, and listens with split roles and no hand
//! SQL.
//!
//! `PROVISION_TEST_DATABASE_URL` names a disposable PostgreSQL 17 superuser
//! URL with `sslmode=verify-full`, and `PROVISION_TEST_DATABASE_CA` the PEM
//! file its certificate chains to. The administrator sessions of this suite
//! use verified TLS, so the server must offer it. Without the variables the
//! test fails on the spot: a skipped database test is not database
//! verification.
#![cfg(feature = "postgres-test")]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use registry_platform_provision::test_support::{connect_verified, provision_test_env};
use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use uuid::Uuid;

const CURSOR_KEY: &str = "synthetic-cursor-key-0123456789!";

fn repository(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

/// Run the built binary with `--format json` and return its exit code and
/// report.
fn ctl(arguments: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_adapterctl"))
        .args(["--format", "json"])
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    (output.status.code().unwrap(), report)
}

/// Read one HTTP status code from `GET path`, or none when nothing answers.
async fn http_status(address: &str, path: &str) -> Option<u16> {
    let mut stream = tokio::net::TcpStream::connect(address).await.ok()?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .ok()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.ok()?;
    let text = String::from_utf8_lossy(&response);
    text.split_whitespace().nth(1)?.parse().ok()
}

/// `provision` as the operate page runs it, from the administrator URL of a
/// non-superuser that holds only `CREATEROLE` and `CREATEDB`, over a runtime
/// file whose two URLs name the roles and the database. `adapter serve` then
/// migrates over the migration credential, grants the runtime role its
/// privileges, and answers a request over the runtime credential.
#[tokio::test]
async fn provision_then_serve_with_split_roles() {
    let (base_url, ca) = provision_test_env();
    let admin = connect_verified(&base_url, &ca, None).await;
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let secrets = directory.path().join("secrets");
    std::fs::create_dir(&secrets).unwrap();
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
    let secret = |name: &str, value: &str| {
        let path = secrets.join(name);
        std::fs::write(&path, value).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    secret("cursor-key", CURSOR_KEY);
    secret("upstream-user", "upstream-user");
    secret("upstream-password", "upstream-password");
    // The runtime verifies tokens against a static key set, so it starts
    // without reaching the issuer.
    secret(
        "jwks.json",
        r#"{"keys":[{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}]}"#,
    );
    secret("postgres-ca.pem", &String::from_utf8_lossy(&ca));

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let bind = format!("127.0.0.1:{port}");
    let runtime_file = directory.path().join("runtime.yaml");
    std::fs::write(
        &runtime_file,
        format!(
            "\
apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: adapter-provision-test
endpoints:
  - endpoint: tracker
    baseUrl: https://192.168.1.10
    credential:
      type: basic
      usernameRef: secret:file/upstream-user
      passwordRef: secret:file/upstream-password
secretProviders:
  file:
    root: {secrets}
listener:
  bind: {bind}
database:
  runtimeUrlRef: secret:file/runtime-database-url
  migrationUrlRef: secret:file/migration-database-url
  caBundleRef: secret:file/postgres-ca.pem
oidc:
  issuer: https://identity.example.test
  audience: urn:example:adapter
  jwksSource:
    type: static
    documentRef: secret:file/jwks.json
allowedClients:
  - provision-test-client
allowedPrivateCidrs:
  - 192.168.0.0/16
audit:
  retentionDays: 90
idempotency:
  responseRetentionSeconds: 86400
cursorKeyRef: secret:file/cursor-key
",
            secrets = secrets.display(),
        ),
    )
    .unwrap();
    let runtime = runtime_file.display().to_string();

    let suffix = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let (owner, migration, runtime_role, database) = (
        format!("adapter_owner_{suffix}"),
        format!("adapter_mig_{suffix}"),
        format!("adapter_rt_{suffix}"),
        format!("adapter_db_{suffix}"),
    );
    let password = |purpose: &str| format!("{purpose}-{}", Uuid::new_v4().simple());
    let (owner_password, migration_password, runtime_password) = (
        password("owner"),
        password("migration"),
        password("runtime"),
    );
    admin
        .batch_execute(&format!(
            "CREATE ROLE {owner} LOGIN PASSWORD '{owner_password}' NOSUPERUSER CREATEROLE CREATEDB"
        ))
        .await
        .unwrap();

    let base = registry_platform_provision::admin_config(&base_url, Some(&ca))
        .expect("PROVISION_TEST_DATABASE_URL is a valid administrator URL");
    let (host, db_port) = (base.host(), base.port());
    let url = |role: &str, password: &str, database: &str| {
        format!("postgresql://{role}:{password}@{host}:{db_port}/{database}")
    };
    secret(
        "migration-database-url",
        &url(&migration, &migration_password, &database),
    );
    secret(
        "runtime-database-url",
        &url(&runtime_role, &runtime_password, &database),
    );
    let admin_file = directory.path().join("admin-url");
    std::fs::write(&admin_file, url(&owner, &owner_password, "postgres")).unwrap();
    std::fs::set_permissions(&admin_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    let (code, provisioned) = ctl(&[
        "provision",
        "--runtime-config",
        &runtime,
        "--admin-url-file",
        admin_file.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{provisioned:#}");
    assert_eq!(provisioned["status"], "complete");
    assert_eq!(provisioned["executed"], true);
    assert_eq!(provisioned["roleMode"], "split");
    assert_eq!(provisioned["database"], database.as_str());
    for secret in [&owner_password, &migration_password, &runtime_password] {
        assert!(
            !provisioned.to_string().contains(secret.as_str()),
            "the report holds no password"
        );
    }

    let (code, again) = ctl(&[
        "provision",
        "--runtime-config",
        &runtime,
        "--admin-url-file",
        admin_file.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "a second run converges: {again:#}");

    let server = tokio::spawn({
        let project = repository("products/adapter/examples/dhis2-tracker");
        let profile = repository("products/adapter/profiles/breg-records/profile.yaml");
        let pack = repository("products/adapter/packs/dhis2-tracker/pack.yaml");
        let runtime = runtime_file.clone();
        async move {
            registry_adapter::serve::run(&project, Some(&profile), Some(&pack), &runtime).await
        }
    });
    // An unauthenticated request reaches the facade and is refused by its
    // authenticator, so a 401 shows the runtime role serving.
    let route = "/.well-known/registry-adapter/effective-contract";
    let mut status = None;
    for _ in 0..300 {
        if server.is_finished() {
            break;
        }
        status = http_status(&bind, route).await;
        if status.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if server.is_finished() {
        let outcome = server.await.expect("the server task does not panic");
        panic!("the facade stopped instead of serving: {outcome:?}");
    }
    assert_eq!(status, Some(401), "the facade never answered");
    server.abort();

    // The runtime role holds what the deployment uses and nothing on the
    // migration ledger of the idempotency store.
    let runtime_session =
        connect_verified(&url(&runtime_role, &runtime_password, &database), &ca, None).await;
    let granted = runtime_session
        .query_one(
            "SELECT has_table_privilege(current_user, 'adapter_journal_events', 'INSERT'), \
                    has_table_privilege(current_user, 'adapter_idempotency_schema_migrations', 'SELECT')",
            &[],
        )
        .await
        .unwrap();
    assert!(granted.get::<_, bool>(0), "the journal is writable");
    assert!(
        !granted.get::<_, bool>(1),
        "the idempotency migration ledger is not readable"
    );
    drop(runtime_session);

    for statement in [
        format!("DROP DATABASE {database} WITH (FORCE)"),
        format!("DROP ROLE {runtime_role}"),
        format!("DROP ROLE {migration}"),
        format!("DROP ROLE {owner}"),
    ] {
        admin.batch_execute(&statement).await.unwrap();
    }
}

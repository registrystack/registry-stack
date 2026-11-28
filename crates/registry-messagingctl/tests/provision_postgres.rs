// SPDX-License-Identifier: Apache-2.0

//! `messagingctl provision` against a real server, then `apply` and the
//! runtime on what it created.
//!
//! `PROVISION_TEST_DATABASE_URL` names a disposable PostgreSQL 17 superuser
//! URL with `sslmode=verify-full`, and `PROVISION_TEST_DATABASE_CA` the PEM
//! file its certificate chains to. The administrator sessions of this suite
//! use verified TLS, so the server must offer it. Without the variables the
//! test fails on the spot: a skipped database test is not database
//! verification.
#![cfg(feature = "postgres-test")]

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use registry_platform_provision::test_support::{connect_verified, provision_test_env};
use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use uuid::Uuid;

/// One deployment directory and the superuser session that creates the
/// roles `provision` is run from.
struct Deployment {
    directory: tempfile::TempDir,
    admin: tokio_postgres::Client,
}

impl Deployment {
    async fn new() -> Self {
        let (url, ca_pem) = provision_test_env();
        let admin = connect_verified(&url, &ca_pem, None).await;
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let secrets = directory.path().join("secrets");
        std::fs::create_dir(&secrets).unwrap();
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
        let deployment = Self { directory, admin };
        deployment.secret("audit-key", "0123456789abcdef0123456789abcdef");
        // The runtime verifies tokens against a static key set, so it starts
        // without reaching the issuer.
        deployment.secret(
            "jwks.json",
            r#"{"keys":[{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}]}"#,
        );
        deployment
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn runtime(&self) -> String {
        self.path("runtime.yaml").display().to_string()
    }

    /// Write or replace the secret file `name` with `value`.
    fn secret(&self, name: &str, value: &str) {
        let path = self.path("secrets").join(name);
        std::fs::write(&path, value).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// Write the runtime document over `package`, listening on `bind`, with
    /// the database connections verified against the CA secret.
    fn write_runtime(&self, package: &std::path::Path, bind: &str) {
        let document = format!(
            "\
apiVersion: id.registrystack.org/formats/messaging/runtime/v1alpha1
kind: MessagingRuntimeConfig
identity:
  databaseId: registry-messaging-ctl-test
package:
  root: {package}
listener:
  bind: {bind}
  tlsTermination: development-loopback
secretProviders:
  file:
    root: {secrets}
database:
  runtimeUrlRef: secret:file/runtime-database-url
  migrationUrlRef: secret:file/migration-database-url
  caBundleRef: secret:file/postgres-ca.pem
authentication:
  oidc:
    issuer: https://identity.example.test
    audience: urn:example:messaging
    allowedClients: [case-system, operations-console]
    jwksSource:
      type: static
      documentRef: secret:file/jwks.json
audit:
  destination: file
  path: {audit}
  hashKeyRef: secret:file/audit-key
",
            package = package.display(),
            secrets = self.path("secrets").display(),
            audit = self.path("audit.ndjson").display(),
        );
        std::fs::write(self.path("runtime.yaml"), document).unwrap();
    }
}

/// Run the built binary with `--format json` and return its exit code and
/// report.
fn ctl(arguments: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_messagingctl"))
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

/// `provision` as the operate page runs it: from the administrator URL of a
/// non-superuser that holds only `CREATEROLE` and `CREATEDB`, over a runtime
/// file whose two URLs name the roles and the database. `apply` then
/// activates the package over the migration credential, and the runtime
/// starts over the runtime credential and answers its readiness route.
#[tokio::test]
async fn provision_then_apply_then_serve_with_split_roles() {
    let deployment = Deployment::new().await;
    let project = deployment.path("project").display().to_string();
    let (code, report) = ctl(&["init", &project]);
    assert_eq!(code, 0, "{report:#}");
    let package = deployment.path("package");
    let (code, report) = ctl(&["package", &project, "--output", package.to_str().unwrap()]);
    assert_eq!(code, 0, "{report:#}");

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let bind = format!("127.0.0.1:{port}");
    deployment.write_runtime(&package, &bind);
    let runtime = deployment.runtime();

    let (base_url, ca) = provision_test_env();
    deployment.secret("postgres-ca.pem", &String::from_utf8_lossy(&ca));

    let suffix = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let (owner, migration, runtime_role, database) = (
        format!("messaging_owner_{suffix}"),
        format!("messaging_mig_{suffix}"),
        format!("messaging_rt_{suffix}"),
        format!("messaging_db_{suffix}"),
    );
    let password = |purpose: &str| format!("{purpose}-{}", Uuid::new_v4().simple());
    let (owner_password, migration_password, runtime_password) = (
        password("owner"),
        password("migration"),
        password("runtime"),
    );
    deployment
        .admin
        .batch_execute(&format!(
            "CREATE ROLE {owner} LOGIN PASSWORD '{owner_password}' NOSUPERUSER CREATEROLE CREATEDB"
        ))
        .await
        .unwrap();

    let base = registry_platform_provision::admin_config(&base_url, Some(&ca))
        .expect("PROVISION_TEST_DATABASE_URL is a valid administrator URL");
    let (host, port) = (base.host(), base.port());
    let url = |role: &str, password: &str, database: &str| {
        format!("postgresql://{role}:{password}@{host}:{port}/{database}")
    };
    deployment.secret(
        "migration-database-url",
        &url(&migration, &migration_password, &database),
    );
    deployment.secret(
        "runtime-database-url",
        &url(&runtime_role, &runtime_password, &database),
    );
    let admin_file = deployment.path("admin-url");
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
    for statement in again["statements"].as_array().unwrap() {
        assert_ne!(statement["outcome"], "created", "{statement}");
    }

    let (code, applied) = ctl(&["apply", "--runtime-config", &runtime]);
    assert_eq!(code, 0, "{applied:#}");

    let server = tokio::spawn({
        let runtime = runtime.clone();
        async move {
            registry_messaging::runtime::serve_from_path(
                &runtime,
                registry_messaging::dispatch::Transports::new(),
            )
            .await
        }
    });
    let mut ready = None;
    for _ in 0..300 {
        if server.is_finished() {
            break;
        }
        ready = http_status(&bind, "/ready").await;
        if ready == Some(200) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if server.is_finished() {
        let outcome = server.await.expect("the server task does not panic");
        panic!("the service stopped instead of serving: {outcome:?}");
    }
    assert_eq!(ready, Some(200), "the service never reported ready");
    server.abort();

    for statement in [
        format!("DROP DATABASE {database} WITH (FORCE)"),
        format!("DROP ROLE {runtime_role}"),
        format!("DROP ROLE {migration}"),
        format!("DROP ROLE {owner}"),
    ] {
        deployment.admin.batch_execute(&statement).await.unwrap();
    }
}

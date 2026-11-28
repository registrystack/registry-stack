// SPDX-License-Identifier: Apache-2.0

//! `documentsctl provision` against a real server, then `apply` and the
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
use std::path::{Path, PathBuf};
use std::process::Command;

use registry_platform_provision::test_support::{connect_verified, provision_test_env};
use serde_json::Value;
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
        for (name, value) in [
            (
                "documents-audit-key",
                "documentsctl-test-audit-key-not-a-secret",
            ),
            (
                "hook-key",
                "documentsctl-test-hook-key-not-a-secret-0123456789",
            ),
        ] {
            let path = secrets.join(name);
            std::fs::write(&path, value).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self { directory, admin }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn runtime(&self) -> String {
        self.path("runtime.yaml").display().to_string()
    }

    /// Write the runtime document over `package`, pinned to `digest`.
    fn write_runtime(&self, package: &Path, digest: &str) {
        let document = format!(
            "\
apiVersion: id.registrystack.org/formats/documents/runtime/v1alpha1
kind: DocumentsRuntimeConfig
identity:
  databaseId: registry-documents-ctl-test
package:
  root: {package}
  expectedDigest: {digest}
listener:
  bind: 127.0.0.1:0
  tlsTermination: loopback-plaintext
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
    scopeClaim: scope
    allowedClients: [civil-registry-app, citizen-portal, case-portal, partner-portal]
audit:
  destination: file
  path: {audit}
  hashKeyRef: secret:file/documents-audit-key
storage:
  type: database
contentVerification:
  type: http
  url: http://127.0.0.1:9/verify
  authorizationRef: secret:file/hook-key
  policyId: documents-test
cleanup:
  erasure: active
destinations:
  hooks:
    owning-system-events:
      url: http://127.0.0.1:9/document-events
      hmacSha256KeyRef: secret:file/hook-key
",
            package = package.display(),
            secrets = self.path("secrets").display(),
            audit = self.path("audit.ndjson").display(),
        );
        std::fs::write(self.path("runtime.yaml"), document).unwrap();
    }

    /// `init`, then `package`, then a runtime document pinned to the
    /// package digest the report names.
    fn deploy(&self) -> String {
        let project = self.path("project").display().to_string();
        let (code, report) = ctl(&["init", &project]);
        assert_eq!(code, 0, "{report:#}");
        let package = self.path("package");
        let (code, report) = ctl(&["package", &project, "--output", package.to_str().unwrap()]);
        assert_eq!(code, 0, "{report:#}");
        let digest = report["packageDigest"].as_str().unwrap().to_owned();
        self.write_runtime(&package, &digest);
        digest
    }

    /// Replace the secret file `name` with `value`.
    fn secret(&self, name: &str, value: &str) {
        let path = self.path("secrets").join(name);
        std::fs::write(&path, value).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// Run the built binary with `--format json` and return its exit code and
/// report.
fn ctl(arguments: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_documentsctl"))
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

/// The public half of a P-256 key, as a key set the runtime trusts.
const PUBLIC_KEY_SET: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":"documentsctl-test-1","x":"gEHpg5PeV9TxLeisE9SSOQLb8FibjLxUHbQANAxmS4A","y":"wPnAyYS42uEWe2vyT4ys7yOAPoQwYU5FkogAZYroLbk"}]}"#;

/// `provision` as the operate page runs it: from the administrator URL of a
/// non-superuser that holds only `CREATEROLE` and `CREATEDB`, over a runtime
/// file whose two URLs name the roles and the database. `apply` then
/// activates the package over the migration credential, and the runtime
/// starts over the runtime credential and answers its health route.
#[tokio::test]
async fn provision_then_apply_then_serve_with_split_roles() {
    let deployment = Deployment::new().await;
    deployment.deploy();
    let runtime = deployment.runtime();
    let (base_url, ca) = provision_test_env();
    let ca_path = deployment.path("secrets").join("postgres-ca.pem");
    std::fs::write(&ca_path, &ca).unwrap();
    std::fs::set_permissions(&ca_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let document = std::fs::read_to_string(&runtime).unwrap();
    // The runtime verifies tokens against a static key set, so it starts
    // without reaching the issuer.
    const ALLOWED_CLIENTS: &str =
        "    allowedClients: [civil-registry-app, citizen-portal, case-portal, partner-portal]\n";
    assert!(document.contains("  testOnlyPlaintext: true\n"));
    assert!(document.contains(ALLOWED_CLIENTS));
    std::fs::write(
        &runtime,
        document
            .replace(
                "  testOnlyPlaintext: true\n",
                "  caBundleRef: secret:file/postgres-ca.pem\n",
            )
            .replace(
                ALLOWED_CLIENTS,
                &format!(
                    "{ALLOWED_CLIENTS}    jwksSource:\n      type: static\n      documentRef: secret:file/jwks.json\n"
                ),
            ),
    )
    .unwrap();
    deployment.secret("jwks.json", PUBLIC_KEY_SET);

    let suffix = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let (owner, migration, runtime_role, database) = (
        format!("documents_owner_{suffix}"),
        format!("documents_mig_{suffix}"),
        format!("documents_rt_{suffix}"),
        format!("documents_db_{suffix}"),
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
        assert_ne!(
            statement["outcome"], "created",
            "a second run creates nothing: {statement}"
        );
    }

    let (code, applied) = ctl(&["apply", "--runtime-config", &runtime]);
    assert_eq!(code, 0, "{applied:#}");
    assert_eq!(applied["activation"]["roleMode"], "split");

    let prepared = registry_documents::runtime::prepare(&runtime)
        .await
        .expect("the runtime prepares over the runtime role");
    let address = prepared.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(prepared.serve_until(async {
        stopped.await.ok();
    }));
    let response = tokio::task::spawn_blocking(move || {
        use std::io::{Read as _, Write as _};
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    })
    .await
    .unwrap();
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the health route answers: {response}"
    );
    stop.send(()).unwrap();
    server.await.unwrap().expect("the server stops cleanly");

    for statement in [
        format!("DROP DATABASE {database} WITH (FORCE)"),
        format!("DROP ROLE {runtime_role}"),
        format!("DROP ROLE {migration}"),
        format!("DROP ROLE {owner}"),
    ] {
        deployment.admin.batch_execute(&statement).await.unwrap();
    }
}

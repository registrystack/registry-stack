// SPDX-License-Identifier: Apache-2.0

//! The operator verbs of the built `documentsctl` binary against
//! PostgreSQL: a starter project written by `init`, packaged by `package`,
//! and activated by `apply` over the migration credential, then read by
//! `status` and the dead-letter verbs.
//!
//! The database is named by `DOCUMENTS_TEST_DATABASE_URL`, and each test
//! works in its own schema. Without the variable every test fails on the
//! spot: a skipped database test is not database verification.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use uuid::Uuid;

/// One deployment directory over a fresh schema.
struct Deployment {
    directory: tempfile::TempDir,
    admin: tokio_postgres::Client,
    schema: String,
}

impl Deployment {
    async fn new() -> Self {
        let base = std::env::var("DOCUMENTS_TEST_DATABASE_URL")
            .expect("DOCUMENTS_TEST_DATABASE_URL names a disposable PostgreSQL test server");
        let schema = format!("documentsctl_{}", Uuid::new_v4().simple());
        let (admin, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
            .await
            .expect("connect the documents test database");
        tokio::spawn(async move { connection.await.expect("the admin connection") });
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base.contains('?') { '&' } else { '?' };
        let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let secrets = directory.path().join("secrets");
        std::fs::create_dir(&secrets).unwrap();
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, value) in [
            ("runtime-database-url", scoped.as_str()),
            ("migration-database-url", scoped.as_str()),
            (
                "documents-audit-key",
                "documentsctl-test-audit-key-not-a-secret",
            ),
        ] {
            let path = secrets.join(name);
            std::fs::write(&path, value).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self {
            directory,
            admin,
            schema,
        }
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
    scopeClaim: scope
    allowedClients: [civil-registry-app, citizen-portal, case-portal, partner-portal]
audit:
  destination: file
  path: {audit}
  hashKeyRef: secret:file/documents-audit-key
storage:
  type: database
contentVerification:
  type: disabled
cleanup:
  erasure: active
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

    async fn relations(&self) -> i64 {
        self.admin
            .query_one(
                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = $1",
                &[&self.schema],
            )
            .await
            .unwrap()
            .get(0)
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

#[tokio::test]
async fn init_package_plan_apply_and_status_activate_a_starter_deployment() {
    let deployment = Deployment::new().await;
    let digest = deployment.deploy();
    let runtime = deployment.runtime();

    let (code, status) = ctl(&["status", "--runtime-config", &runtime]);
    assert_eq!(code, 0, "{status:#}");
    assert_eq!(status["active"], Value::Null);

    let (code, plan) = ctl(&["plan", "--runtime-config", &runtime]);
    assert_eq!(code, 0, "{plan:#}");
    assert_eq!(plan["command"], "plan");
    assert_eq!(plan["packageDigest"], digest);
    assert_eq!(plan["change"], "activate");
    assert_eq!(deployment.relations().await, 0, "plan writes nothing");

    let (code, applied) = ctl(&[
        "apply",
        "--runtime-config",
        &runtime,
        "--operator-reference",
        "CHANGE-4471",
        "--backup",
        "snapshot-before-documents",
    ]);
    assert_eq!(code, 0, "{applied:#}");
    assert_eq!(applied["status"], "complete");
    assert_eq!(applied["change"], "activate");
    assert_eq!(applied["applied"], true);
    assert_eq!(applied["restartRequired"], true);
    assert_eq!(applied["activation"]["packageDigest"], digest);
    assert_eq!(
        applied["activation"]["backupReferences"],
        serde_json::json!(["snapshot-before-documents"])
    );
    assert!(
        !applied.to_string().contains("CHANGE-4471"),
        "the operator reference is reported only as its keyed hash"
    );
    assert!(applied["activation"]["operatorReferenceHash"].is_string());

    let (code, again) = ctl(&["apply", "--runtime-config", &runtime]);
    assert_eq!(code, 0, "{again:#}");
    assert_eq!(again["change"], "none");
    assert_eq!(again["applied"], false);

    let (code, status) = ctl(&["status", "--runtime-config", &runtime]);
    assert_eq!(code, 0, "{status:#}");
    assert_eq!(status["active"]["packageDigest"], digest);
    assert_eq!(status["history"].as_array().unwrap().len(), 1);

    let (code, listed) = ctl(&["verification", "list", "--runtime-config", &runtime]);
    assert_eq!(code, 0, "{listed:#}");
    assert_eq!(listed["command"], "verification list");
    assert_eq!(listed["deadLetters"], serde_json::json!([]));

    let (code, refused) = ctl(&[
        "verification",
        "replay",
        "--runtime-config",
        &runtime,
        "--version-id",
        &Uuid::new_v4().to_string(),
        "--expected-generation",
        "1",
    ]);
    assert_eq!(code, 1, "{refused:#}");
    assert_eq!(refused["status"], "domain-refusal");
    assert_eq!(
        refused["diagnostics"][0]["code"],
        "documents.verification.not-found"
    );

    let (code, erasure) = ctl(&["erasure", "status", "--runtime-config", &runtime]);
    assert_eq!(code, 0, "{erasure:#}");
    assert_eq!(erasure["command"], "erasure status");
    assert_eq!(erasure["status"], "complete");
    assert_eq!(erasure["erasure"], "active");
    assert_eq!(erasure["awaitingGrace"], 0);
    assert_eq!(erasure["due"], 0);
    assert_eq!(erasure["deadLettered"], 0);
    let output = Command::new(env!("CARGO_BIN_EXE_documentsctl"))
        .args(["erasure", "status", "--runtime-config", &runtime])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "erasure: active\nawaiting grace: 0\ndue: 0\ndead-lettered: 0\n"
    );

    let (code, listed) = ctl(&["erasure", "list", "--runtime-config", &runtime]);
    assert_eq!(code, 0, "{listed:#}");
    assert_eq!(listed["command"], "erasure list");
    assert_eq!(listed["deadLetters"], serde_json::json!([]));

    let (code, refused) = ctl(&[
        "erasure",
        "replay",
        "--runtime-config",
        &runtime,
        "--version-id",
        &Uuid::new_v4().to_string(),
        "--expected-generation",
        "1",
    ]);
    assert_eq!(code, 1, "{refused:#}");
    assert_eq!(refused["command"], "erasure replay");
    assert_eq!(
        refused["diagnostics"][0]["code"],
        "documents.erasure.not-found"
    );
    assert_eq!(refused["diagnostics"][0]["path"], "erasure");
}

#[tokio::test]
async fn the_dead_letter_verbs_refuse_a_database_that_is_not_activated() {
    let deployment = Deployment::new().await;
    deployment.deploy();
    let runtime = deployment.runtime();
    for arguments in [
        vec!["verification", "list", "--runtime-config", &runtime],
        vec![
            "verification",
            "replay",
            "--runtime-config",
            &runtime,
            "--version-id",
            "00000000-0000-4000-8000-000000000001",
            "--expected-generation",
            "1",
        ],
        vec!["erasure", "status", "--runtime-config", &runtime],
        vec!["erasure", "list", "--runtime-config", &runtime],
        vec![
            "erasure",
            "replay",
            "--runtime-config",
            &runtime,
            "--version-id",
            "00000000-0000-4000-8000-000000000001",
            "--expected-generation",
            "1",
        ],
    ] {
        let (code, report) = ctl(&arguments);
        assert_eq!(code, 1, "{arguments:?}: {report:#}");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "documentsctl.activation.not-activated"
        );
        assert!(report["diagnostics"][0]["suggestedAction"]
            .as_str()
            .unwrap()
            .contains("documentsctl plan"));
    }
    assert_eq!(deployment.relations().await, 0, "a refusal writes nothing");
}

#[tokio::test]
async fn apply_refuses_a_package_that_is_not_the_pinned_one() {
    let deployment = Deployment::new().await;
    deployment.deploy();
    let wrong = format!("sha256:{}", "0".repeat(64));
    deployment.write_runtime(&deployment.path("package"), &wrong);
    let (code, report) = ctl(&["apply", "--runtime-config", &deployment.runtime()]);
    assert_eq!(code, 1, "{report:#}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "documents.package.digest-mismatch"
    );
    assert_eq!(report["diagnostics"][0]["path"], "/package/expectedDigest");
    assert_eq!(deployment.relations().await, 0, "nothing was applied");
}

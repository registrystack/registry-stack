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
            (
                "hook-key",
                "documentsctl-test-hook-key-not-a-secret-0123456789",
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

/// A database provisioned as the Document Store operate page provisions
/// one: split migration and runtime login roles, `PUBLIC` stripped of every
/// privilege on the database and on the `public` schema, and the schema
/// handed to the migration role. The runtime role holds only `CONNECT`, so
/// before the first apply it has no usage on any schema and its
/// `current_schema()` is null. Roles are cluster-wide, so each is named
/// after the suite's own database, which makes a leftover from a failed run
/// attributable, and [`ProvisionedDatabase::drop`] removes them with the
/// database.
struct ProvisionedDatabase {
    name: String,
    migration_role: String,
    runtime_role: String,
}

impl ProvisionedDatabase {
    const PASSWORD: &'static str = "documents-test";

    async fn new(admin: &tokio_postgres::Client) -> Self {
        let suite = base_config()
            .get_dbname()
            .expect("DOCUMENTS_TEST_DATABASE_URL names a database")
            .to_owned();
        // The longest name, `<suite>_migration_<suffix>`, stays within
        // PostgreSQL's 63-byte identifier limit.
        let suite = &suite[..suite.len().min(44)];
        let suffix = &Uuid::new_v4().simple().to_string()[..8];
        let provisioned = Self {
            name: format!("{suite}_database_{suffix}"),
            migration_role: format!("{suite}_migration_{suffix}"),
            runtime_role: format!("{suite}_runtime_{suffix}"),
        };
        let Self {
            name,
            migration_role,
            runtime_role,
        } = &provisioned;
        let password = Self::PASSWORD;
        for role in [migration_role, runtime_role] {
            admin
                .batch_execute(&format!(
                    "CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB \
                     NOCREATEROLE NOINHERIT NOBYPASSRLS"
                ))
                .await
                .unwrap();
        }
        admin
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        let (database, connection) =
            tokio_postgres::connect(&provisioned.url("postgres", None), tokio_postgres::NoTls)
                .await
                .expect("connect the provisioned database");
        let connection = tokio::spawn(connection);
        database
            .batch_execute(&format!(
                "REVOKE ALL ON DATABASE {name} FROM PUBLIC;
                 GRANT CONNECT ON DATABASE {name} TO {migration_role}, {runtime_role};
                 ALTER SCHEMA public OWNER TO {migration_role};
                 REVOKE ALL ON SCHEMA public FROM PUBLIC;"
            ))
            .await
            .unwrap();
        drop(database);
        connection.await.unwrap().unwrap();
        provisioned
    }

    /// A connection string reaching this database as `user`, with the
    /// suite's own password when `password` is `None`.
    fn url(&self, user: &str, password: Option<&str>) -> String {
        let base = base_config();
        let tokio_postgres::config::Host::Tcp(host) = &base.get_hosts()[0] else {
            panic!("the test server is reached over TCP");
        };
        let port = base.get_ports().first().copied().unwrap_or(5432);
        let password = match password {
            Some(password) => password.to_owned(),
            None => String::from_utf8(base.get_password().unwrap_or_default().to_vec()).unwrap(),
        }
        .replace('\\', "\\\\")
        .replace('\'', "\\'");
        format!(
            "host={host} port={port} user={user} password='{password}' dbname={}",
            self.name
        )
    }

    async fn drop(self, admin: &tokio_postgres::Client) {
        // DROP DATABASE runs outside a transaction, so alone.
        for statement in [
            format!("DROP DATABASE {} WITH (FORCE)", self.name),
            format!("DROP ROLE {}", self.runtime_role),
            format!("DROP ROLE {}", self.migration_role),
        ] {
            admin.batch_execute(&statement).await.unwrap();
        }
    }
}

/// The suite's own connection settings.
fn base_config() -> tokio_postgres::Config {
    std::env::var("DOCUMENTS_TEST_DATABASE_URL")
        .expect("DOCUMENTS_TEST_DATABASE_URL names a disposable PostgreSQL test server")
        .parse()
        .expect("DOCUMENTS_TEST_DATABASE_URL is a PostgreSQL connection string")
}

/// The operate page's journey on a database provisioned as it says: `plan`
/// over the runtime credential, which holds nothing but `CONNECT` before
/// the first apply, reports the initial activation; `apply` over the
/// migration credential splits the roles; and `plan` then reports nothing
/// to change.
#[tokio::test]
async fn plan_reports_the_initial_activation_on_a_database_provisioned_as_the_operate_page_says() {
    let deployment = Deployment::new().await;
    let digest = deployment.deploy();
    let runtime = deployment.runtime();
    let provisioned = ProvisionedDatabase::new(&deployment.admin).await;
    deployment.secret(
        "runtime-database-url",
        &provisioned.url(
            &provisioned.runtime_role,
            Some(ProvisionedDatabase::PASSWORD),
        ),
    );
    deployment.secret(
        "migration-database-url",
        &provisioned.url(
            &provisioned.migration_role,
            Some(ProvisionedDatabase::PASSWORD),
        ),
    );

    let (code, plan) = ctl(&["plan", "--runtime-config", &runtime]);
    assert_eq!(code, 0, "{plan:#}");
    assert_eq!(plan["packageDigest"], digest);
    assert_eq!(plan["change"], "activate");
    assert_eq!(plan["planKind"], "initial");
    assert_eq!(plan["activeDigest"], Value::Null);
    assert_eq!(plan["pendingSchemaVersions"], serde_json::json!([100]));
    assert_eq!(plan["runtimeRoleMode"], Value::Null);
    assert_eq!(plan["refusals"], serde_json::json!([]));
    let output = Command::new(env!("CARGO_BIN_EXE_documentsctl"))
        .args(["plan", "--runtime-config", &runtime])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("package digest: {digest}\nchange: activate\n")
    );

    let (code, status) = ctl(&["status", "--runtime-config", &runtime]);
    assert_eq!(code, 0, "{status:#}");
    assert_eq!(status["active"], Value::Null);

    let (code, applied) = ctl(&["apply", "--runtime-config", &runtime]);
    assert_eq!(code, 0, "{applied:#}");
    assert_eq!(applied["activation"]["roleMode"], "split");

    let (code, plan) = ctl(&["plan", "--runtime-config", &runtime]);
    assert_eq!(code, 0, "{plan:#}");
    assert_eq!(plan["change"], "none");
    assert_eq!(plan["runtimeRoleMode"], "split");
    assert_eq!(plan["grantsCurrent"], true);

    // After apply, a runtime role that lost its schema usage resolves no
    // schema again. That is a misconfiguration, refused by name rather
    // than read as a database nobody applied a package to.
    let (database, connection) =
        tokio_postgres::connect(&provisioned.url("postgres", None), tokio_postgres::NoTls)
            .await
            .expect("connect the provisioned database");
    let connection = tokio::spawn(connection);
    database
        .batch_execute(&format!(
            "REVOKE USAGE ON SCHEMA public FROM {}",
            provisioned.runtime_role
        ))
        .await
        .unwrap();
    drop(database);
    connection.await.unwrap().unwrap();
    let (code, plan) = ctl(&["plan", "--runtime-config", &runtime]);
    assert_eq!(code, 1, "{plan:#}");
    assert_eq!(
        plan["diagnostics"][0]["code"],
        "documentsctl.activation.ledger-unreadable"
    );

    provisioned.drop(&deployment.admin).await;
}

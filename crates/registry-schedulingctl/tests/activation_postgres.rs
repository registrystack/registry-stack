// SPDX-License-Identifier: Apache-2.0

//! Package activation against a real PostgreSQL, each test on its own
//! disposable schema.
//!
//! `schedulingctl apply` is the only writer of the activation ledger: it
//! migrates, adopts, publishes, and records one row in one transaction under
//! the migration lock, and it audits every attempt. `plan` and `status` read
//! with the runtime credential and write nothing. Startup serves only the
//! package the ledger names, on the database the ledger names, and in split
//! role mode the runtime credential cannot write the ledger while the
//! service still starts and serves.

use registry_platform_config::{SecretProvider, SecretResolver};
use registry_scheduling::config::RuntimeConfig;
use registry_scheduling::store::PostgresStore;
use registry_schedulingctl::activation;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

/// The advisory lock every apply takes for its transaction.
const MIGRATION_LOCK_KEY: i64 = 0x7363_6865_6475_6c65;

const POLICY: &str = r#"apiVersion: registry.registrystack.org/scheduling-policy-package/v1alpha1
kind: SchedulingPolicyPackage
scheduling:
  id: registry-updates
  version: 1
services:
  - id: registry-update
    label: Registry record update
offerings:
  - id: registry-update-30
    service: registry-update
    label: 30-minute counter update
    mode: exact-time
    location: bangkok-counter
    because: A 30-minute registry update at an interchangeable counter station.
    exactTime:
      durationMinutes: 30
      bufferBeforeMinutes: 5
      bufferAfterMinutes: 5
      leadTimeMinutes: 120
      horizonDays: 60
      pool: update-stations
      startIncrementMinutes: 30
      maxRecipients: 1
    cancellationCutoffMinutes: 240
    requiresCapabilities: []
    prerequisites: []
holidaySets:
  - id: office-holidays
    revision: 1
    because: Public holidays observed by the registry offices.
    dates: []
openings:
  - id: bangkok-counter-hours
    location: bangkok-counter
    holidaySet: office-holidays
    weekdays: [mon, tue, wed, thu, fri]
    startTime: "09:00"
    endTime: "12:30"
    effectiveFrom: "2026-10-01"
    effectiveUntil: "2026-12-31"
    because: Counter opening hours reviewed by the office manager.
holdPolicy:
  ttlMinutes: 5
  maxPerCaller: 3
  because: Holds are short because counter capacity is scarce.
"#;

/// A successor of [`POLICY`]: the same deployment with a changed label, so
/// its package and policy digests differ.
fn successor_policy() -> String {
    POLICY.replacen(
        "label: 30-minute counter update",
        "label: 30-minute counter visit",
        1,
    )
}

/// A static key set, so the runtime starts without reaching an issuer.
const JWKS: &str = r#"{"keys":[{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}]}"#;

fn base_url() -> String {
    std::env::var("SCHEDULING_TEST_DATABASE_URL")
        .expect("SCHEDULING_TEST_DATABASE_URL names a disposable PostgreSQL test server")
}

fn scoped_url(base: &str, schema: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}options=-csearch_path%3D{schema}")
}

/// `base` with its user information replaced, for a role the test created.
fn with_login(base: &str, user: &str, password: &str) -> String {
    let (scheme, rest) = base.split_once("://").expect("a URL with a scheme");
    let host = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    format!("{scheme}://{user}:{password}@{host}")
}

async fn connect(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("the test server accepts the connection");
    tokio::spawn(async move {
        // The connection ends when the test drops the client.
        let _ = connection.await;
    });
    client
}

/// A sealed package directory holding `policy`.
fn package(root: &Path, name: &str, policy: &str) -> PathBuf {
    let project = root.join(name);
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("scheduling.yaml"), policy).unwrap();
    registry_platform_config::package::write_sum_file(
        &project,
        None,
        &registry_scheduling::config::package_limits(),
        registry_scheduling::config::PACKAGE_COMMAND,
    )
    .expect("the package is sealed");
    project
}

/// One disposable deployment: a schema, the secret names its runtime
/// configurations resolve, and a directory for its packages and audit.
struct Deployment {
    admin: tokio_postgres::Client,
    schema: String,
    root: tempfile::TempDir,
    runtime_secret: String,
    migration_secret: String,
    audit_secret: String,
    jwks_secret: String,
    roles: Vec<String>,
}

impl Deployment {
    /// A deployment whose runtime and migration credentials are the test
    /// server's own role: single role mode.
    async fn single(prefix: &str) -> Self {
        let base = base_url();
        let admin = connect(&base).await;
        let schema = format!("{prefix}_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .expect("a disposable schema is created");
        let deployment = Self::named(admin, schema, Vec::new());
        std::env::set_var(
            &deployment.runtime_secret,
            scoped_url(&base, &deployment.schema),
        );
        std::env::set_var(
            &deployment.migration_secret,
            scoped_url(&base, &deployment.schema),
        );
        deployment
    }

    /// A deployment with a migration role that owns the schema and a runtime
    /// role that holds nothing until apply grants it: split role mode.
    async fn split(prefix: &str) -> Self {
        let base = base_url();
        let admin = connect(&base).await;
        let suffix = Uuid::new_v4().simple().to_string();
        let schema = format!("{prefix}_{suffix}");
        let migration_role = format!("scheduling_migration_{suffix}");
        let runtime_role = format!("scheduling_runtime_{suffix}");
        let password = Uuid::new_v4().simple().to_string();
        admin
            .batch_execute(&format!(
                "CREATE ROLE {migration_role} LOGIN PASSWORD '{password}';\
                 CREATE ROLE {runtime_role} LOGIN PASSWORD '{password}';\
                 CREATE SCHEMA {schema} AUTHORIZATION {migration_role};"
            ))
            .await
            .expect("the two deployment roles and their schema are created");
        let deployment = Self::named(
            admin,
            schema,
            vec![runtime_role.clone(), migration_role.clone()],
        );
        std::env::set_var(
            &deployment.runtime_secret,
            scoped_url(
                &with_login(&base, &runtime_role, &password),
                &deployment.schema,
            ),
        );
        std::env::set_var(
            &deployment.migration_secret,
            scoped_url(
                &with_login(&base, &migration_role, &password),
                &deployment.schema,
            ),
        );
        deployment
    }

    fn named(admin: tokio_postgres::Client, schema: String, roles: Vec<String>) -> Self {
        let tag = Uuid::new_v4().simple().to_string().to_ascii_uppercase();
        let deployment = Self {
            admin,
            schema,
            root: tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap(),
            runtime_secret: format!("SCHEDULING_ACTIVATION_RUNTIME_{tag}"),
            migration_secret: format!("SCHEDULING_ACTIVATION_MIGRATION_{tag}"),
            audit_secret: format!("SCHEDULING_ACTIVATION_AUDIT_{tag}"),
            jwks_secret: format!("SCHEDULING_ACTIVATION_JWKS_{tag}"),
            roles,
        };
        std::env::set_var(&deployment.audit_secret, "0123456789abcdef0123456789abcdef");
        std::env::set_var(&deployment.jwks_secret, JWKS);
        deployment
    }

    fn package(&self, name: &str, policy: &str) -> PathBuf {
        package(self.root.path(), name, policy)
    }

    fn audit_path(&self) -> PathBuf {
        self.root.path().join("audit.ndjson")
    }

    /// Write one runtime configuration for this deployment and return its
    /// path.
    fn config(&self, name: &str, package: &Path, options: ConfigOptions<'_>) -> PathBuf {
        let expected = options
            .expected_digest
            .map(|digest| format!("  expectedDigest: {digest}\n"))
            .unwrap_or_default();
        let text = format!(
            "apiVersion: registry.registrystack.org/scheduling-runtime/v1alpha1\n\
             kind: SchedulingRuntimeConfig\n\
             package:\n  root: {package}\n{expected}\
             identity:\n  databaseId: {database_id}\n\
             listener:\n  bind: {bind}\n  tlsTermination: development-loopback\n\
             secretProviders:\n  environment: {{}}\n\
             authentication:\n  oidc:\n    issuer: https://identity.example.test\n\
             \x20   audience: urn:example:scheduling\n\
             \x20   jwksSource:\n      kind: static\n      documentRef: secret:env/{jwks}\n\
             database:\n  runtimeUrlRef: secret:env/{runtime}\n\
             \x20 migrationUrlRef: secret:env/{migration}\n\
             \x20 testOnlyPlaintext: true\n\
             audit:\n  path: {audit}\n  hashKeyRef: secret:env/{audit_key}\n\
             retention:\n  attemptReceiptDays: 2\n",
            package = package.display(),
            database_id = options.database_id,
            bind = options.bind,
            jwks = self.jwks_secret,
            runtime = self.runtime_secret,
            migration = self.migration_secret,
            audit = self.audit_path().display(),
            audit_key = self.audit_secret,
        );
        let path = self.root.path().join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    /// The migration store, for fixtures that must reach the schema directly.
    fn migration_store(&self, config: &Path) -> PostgresStore {
        let config = RuntimeConfig::load(config).expect("the runtime configuration loads");
        let resolver = SecretResolver::new([SecretProvider::Environment], "")
            .expect("the environment secret provider configures");
        PostgresStore::connect_migration(&config.database, &resolver).unwrap()
    }

    async fn scalar_i64(&self, sql: &str) -> i64 {
        self.admin
            .query_one(&sql.replace("{schema}", &self.schema), &[])
            .await
            .expect("the admin query runs")
            .get(0)
    }

    async fn ledger_rows(&self) -> i64 {
        self.scalar_i64("SELECT count(*) FROM {schema}.scheduling_activations")
            .await
    }

    async fn tables(&self) -> i64 {
        self.admin
            .query_one(
                "SELECT count(*) FROM pg_tables WHERE schemaname=$1",
                &[&self.schema],
            )
            .await
            .expect("the catalog is readable")
            .get(0)
    }

    /// Every activation audit entry, in write order.
    fn activation_audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.root.path().join("audit.schedulingctl.ndjson"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("an audit entry is JSON"))
            .filter(|entry| entry["schema"] == "scheduling-activation-audit/v1")
            .collect()
    }

    async fn drop(self) {
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .expect("the disposable schema is dropped");
        for role in &self.roles {
            self.admin
                .batch_execute(&format!("DROP OWNED BY {role}; DROP ROLE {role}"))
                .await
                .expect("the disposable role is dropped");
        }
    }
}

struct ConfigOptions<'a> {
    database_id: &'a str,
    bind: &'a str,
    expected_digest: Option<&'a str>,
}

impl Default for ConfigOptions<'_> {
    fn default() -> Self {
        Self {
            database_id: "scheduling-activation-test",
            bind: "127.0.0.1:8105",
            expected_digest: None,
        }
    }
}

/// Run one operator command on a plain thread: each builds its own
/// single-threaded runtime, which cannot nest inside this test's runtime.
fn ctl<F>(command: F) -> anyhow::Result<Value>
where
    F: FnOnce() -> anyhow::Result<Value> + Send + 'static,
{
    std::thread::spawn(command)
        .join()
        .expect("the command does not panic")
}

fn apply(config: &Path) -> anyhow::Result<Value> {
    let config = config.to_path_buf();
    ctl(move || activation::apply(&config, None, &[]))
}

fn plan(config: &Path) -> Value {
    let config = config.to_path_buf();
    ctl(move || activation::plan(&config)).expect("plan reports")
}

fn status(config: &Path) -> Value {
    let config = config.to_path_buf();
    ctl(move || activation::status(&config)).expect("status reports")
}

fn refusal(result: anyhow::Result<Value>) -> String {
    format!("{:#}", result.expect_err("the command refuses"))
}

#[tokio::test]
async fn plan_on_an_empty_database_reports_the_initial_activation_and_writes_nothing() {
    let deployment = Deployment::single("activation_plan_empty").await;
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());

    let report = plan(&config);
    assert_eq!(report["command"], "plan");
    assert!(report["activePackage"].is_null(), "{report}");
    assert_eq!(report["databaseIdCheck"], "initial");
    assert_eq!(report["schemaVersion"], 0);
    assert_eq!(
        report["pendingSchemaVersions"],
        serde_json::json!([1, 2, 3, 4, 5, 6, 7, 8, 9])
    );
    assert_eq!(report["policy"]["revisionAdvances"], true);
    assert_eq!(report["policy"]["revision"], 2);
    assert_eq!(report["retainedHookBindings"], "none-retained");
    assert_eq!(report["changesPending"], true);
    assert_eq!(report["refusals"], serde_json::json!([]));
    assert_eq!(deployment.tables().await, 0, "plan created a table");
    assert!(
        deployment.activation_audit().is_empty(),
        "plan wrote an audit entry"
    );
    deployment.drop().await;
}

#[tokio::test]
async fn apply_records_one_row_per_activation_and_a_previous_package_is_a_new_row() {
    let deployment = Deployment::single("activation_history").await;
    let first = deployment.package("first", POLICY);
    let second = deployment.package("second", &successor_policy());
    let first_config = deployment.config("first.yaml", &first, ConfigOptions::default());
    let second_config = deployment.config("second.yaml", &second, ConfigOptions::default());

    let initial = ctl({
        let config = first_config.clone();
        move || {
            activation::apply(
                &config,
                Some("CHG-4242"),
                &["snapshot-2026-09-27".to_owned()],
            )
        }
    })
    .expect("the first package activates");
    assert_eq!(initial["command"], "apply");
    assert_eq!(initial["applyOrder"], 1);
    assert!(initial["predecessorPackageDigest"].is_null());
    assert_eq!(initial["roleMode"], "single");
    assert!(initial["roleModeStatement"]
        .as_str()
        .unwrap()
        .starts_with("single-role mode"));
    assert_eq!(
        initial["schemaVersionsApplied"],
        serde_json::json!([1, 2, 3, 4, 5, 6, 7, 8, 9])
    );
    assert_eq!(initial["effects"]["schedulingIdAdopted"], true);
    assert_eq!(initial["effects"]["policyRevision"], 2);
    assert_eq!(initial["effects"]["policyRevisionAdvanced"], true);

    // The operator reference is kept only as a keyed hash, in the ledger and
    // in the audit stream; the backup reference is kept as given.
    let row = deployment
        .admin
        .query_one(
            &format!(
                "SELECT operator_reference_hash, backup_references, plan_kind \
                 FROM {}.scheduling_activations",
                deployment.schema
            ),
            &[],
        )
        .await
        .unwrap();
    let hash: String = row.get(0);
    assert!(!hash.contains("CHG-4242"));
    assert!(!hash.is_empty());
    assert_eq!(row.get::<_, Vec<String>>(1), ["snapshot-2026-09-27"]);
    assert_eq!(row.get::<_, String>(2), "initial");
    let audit_text =
        std::fs::read_to_string(deployment.root.path().join("audit.schedulingctl.ndjson")).unwrap();
    assert!(
        !audit_text.contains("CHG-4242"),
        "the raw reference was audited"
    );
    let audit = deployment.activation_audit();
    assert_eq!(audit.len(), 2, "{audit:?}");
    assert_eq!(audit[0]["phase"], "request");
    assert_eq!(audit[1]["phase"], "response");
    assert_eq!(audit[0]["correlation"], initial["activationId"]);
    assert_eq!(audit[1]["correlation"], initial["activationId"]);
    assert_eq!(audit[0]["record"]["operatorReferenceHash"], hash.as_str());
    assert_eq!(audit[1]["record"]["outcome"], "allowed");

    // The startup the runtime performs is not an activation: no row is
    // written until the successor is applied.
    let successor = apply(&second_config).expect("the successor activates");
    assert_eq!(successor["applyOrder"], 2);
    assert_eq!(
        successor["predecessorPackageDigest"],
        initial["packageDigest"]
    );
    assert_eq!(successor["schemaVersionsApplied"], serde_json::json!([]));
    assert_eq!(successor["effects"]["policyRevision"], 3);

    // Going back is an activation like any other.
    let back = apply(&first_config).expect("the previous package activates again");
    assert_eq!(back["applyOrder"], 3);
    assert_eq!(back["packageDigest"], initial["packageDigest"]);
    assert_eq!(back["predecessorPackageDigest"], successor["packageDigest"]);
    assert_eq!(deployment.ledger_rows().await, 3);

    let report = status(&first_config);
    assert_eq!(
        report["activePackage"]["packageDigest"],
        initial["packageDigest"]
    );
    let history = report["history"].as_array().unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0]["planKind"], "initial");
    assert_eq!(history[2]["planKind"], "successor");
    assert_eq!(report["schemaVersion"], 9);
    assert_eq!(report["roleMode"], "single");
    assert!(report["roleModeStatement"].is_string());
    deployment.drop().await;
}

#[tokio::test]
async fn apply_refuses_the_active_package_and_a_foreign_database_without_writing() {
    let deployment = Deployment::single("activation_refusals").await;
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());
    let applied = apply(&config).expect("the package activates");
    let digest = applied["packageDigest"].as_str().unwrap().to_owned();

    let error = refusal(apply(&config));
    assert!(
        error.contains(&format!(
            "package {digest} is already the active package on this database; nothing needs applying"
        )),
        "{error}"
    );
    assert_eq!(deployment.ledger_rows().await, 1);
    let audit = deployment.activation_audit();
    assert_eq!(audit.len(), 4, "{audit:?}");
    assert_eq!(audit[3]["record"]["outcome"], "refused");
    assert_eq!(
        audit[3]["record"]["reason"],
        "schedulingctl.activation.package-already-active"
    );

    // Planning the active package changes nothing and is not a refusal.
    let report = plan(&config);
    assert_eq!(report["changesPending"], false);
    assert_eq!(report["databaseIdCheck"], "match");
    assert_eq!(
        report["refusals"][0]["code"],
        "schedulingctl.activation.package-already-active"
    );

    // A configuration naming another database is refused before any
    // statement changes this one, by plan and by apply.
    let successor = deployment.package("successor", &successor_policy());
    let foreign = deployment.config(
        "foreign.yaml",
        &successor,
        ConfigOptions {
            database_id: "another-database",
            ..ConfigOptions::default()
        },
    );
    let report = plan(&foreign);
    assert_eq!(report["databaseIdCheck"], "mismatch");
    assert_eq!(
        report["refusals"][0]["code"],
        "schedulingctl.activation.database-id-mismatch"
    );
    let meta_before = deployment
        .scalar_i64("SELECT policy_revision FROM {schema}.scheduling_meta")
        .await;
    let error = refusal(apply(&foreign));
    assert!(error.contains("identity.databaseId"), "{error}");
    assert!(!error.contains("another-database"), "{error}");
    assert_eq!(deployment.ledger_rows().await, 1);
    assert_eq!(
        deployment
            .scalar_i64("SELECT policy_revision FROM {schema}.scheduling_meta")
            .await,
        meta_before,
        "the refused apply published its policy"
    );
    let audit = deployment.activation_audit();
    assert_eq!(audit.len(), 6, "{audit:?}");
    assert_eq!(
        audit[5]["record"]["reason"],
        "schedulingctl.activation.database-id-mismatch"
    );
    deployment.drop().await;
}

#[tokio::test]
async fn apply_refuses_to_activate_without_its_audit_destination() {
    let deployment = Deployment::single("activation_audit").await;
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());
    std::fs::create_dir(deployment.root.path().join("audit.schedulingctl.ndjson")).unwrap();

    let error = refusal(apply(&config));
    assert!(
        error.starts_with("opening the schedulingctl audit destination"),
        "{error}"
    );
    assert_eq!(deployment.tables().await, 0, "an unaudited apply wrote");
    deployment.drop().await;
}

#[tokio::test]
async fn apply_waits_for_the_migration_lock_another_apply_holds() {
    // Split roles name the waiting apply: sibling tests take the same lock
    // on the same server under other roles.
    let deployment = Deployment::split("activation_lock").await;
    let migration_role = deployment.roles[1].clone();
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());

    let holder = connect(&base_url()).await;
    holder.batch_execute("BEGIN").await.unwrap();
    holder
        .execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_KEY])
        .await
        .unwrap();
    let waiting = std::thread::spawn({
        let config = config.clone();
        move || activation::apply(&config, None, &[])
    });

    let mut blocked = false;
    for _ in 0..200 {
        let waiters: i64 = deployment
            .admin
            .query_one(
                "SELECT count(*) FROM pg_locks JOIN pg_stat_activity USING (pid) \
                 WHERE locktype='advisory' AND NOT granted AND usename=$1",
                &[&migration_role],
            )
            .await
            .unwrap()
            .get(0);
        if waiters > 0 {
            blocked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(blocked, "the apply never waited on the migration lock");
    assert!(
        !waiting.is_finished(),
        "the apply finished under a held lock"
    );
    assert_eq!(deployment.tables().await, 0, "the waiting apply wrote");

    holder.batch_execute("COMMIT").await.unwrap();
    let report = waiting
        .join()
        .expect("the apply does not panic")
        .expect("the apply proceeds once the lock is released");
    assert_eq!(report["applyOrder"], 1);
    deployment.drop().await;
}

#[tokio::test]
async fn startup_refuses_a_database_the_ledger_does_not_name_for_this_package() {
    let deployment = Deployment::single("activation_startup").await;
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());

    // No ledger row: the schema is current but nothing was activated.
    deployment
        .migration_store(&config)
        .migrate()
        .await
        .expect("the schema migrates");
    let error = registry_scheduling::runtime::serve_from_path(&config)
        .await
        .expect_err("startup refuses a database with no active package")
        .to_string();
    assert!(
        error.contains("no Scheduling package has been applied to this database; run `schedulingctl plan --runtime-config FILE` then `schedulingctl apply --runtime-config FILE`"),
        "{error}"
    );
    assert_eq!(deployment.ledger_rows().await, 0, "startup activated");

    let applied = apply(&config).expect("the package activates");

    // Another package on disk than the one the ledger names.
    let successor = deployment.package("successor", &successor_policy());
    let other = deployment.config("other.yaml", &successor, ConfigOptions::default());
    let error = registry_scheduling::runtime::serve_from_path(&other)
        .await
        .expect_err("startup refuses a package the ledger does not name")
        .to_string();
    assert!(
        error.contains(&format!(
            "is not the active package {} on this database; run `schedulingctl plan --runtime-config FILE` then `schedulingctl apply --runtime-config FILE`",
            applied["packageDigest"].as_str().unwrap()
        )),
        "{error}"
    );

    // The ledger belongs to another database.
    let foreign = deployment.config(
        "foreign.yaml",
        &package,
        ConfigOptions {
            database_id: "another-database",
            ..ConfigOptions::default()
        },
    );
    let error = registry_scheduling::runtime::serve_from_path(&foreign)
        .await
        .expect_err("startup refuses a foreign ledger")
        .to_string();
    assert!(error.contains("identity.databaseId"), "{error}");

    // A pin naming another package than the one at package.root.
    let pinned = deployment.config(
        "pinned.yaml",
        &package,
        ConfigOptions {
            expected_digest: Some(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            ..ConfigOptions::default()
        },
    );
    let error = registry_scheduling::runtime::serve_from_path(&pinned)
        .await
        .expect_err("startup refuses a package its pin does not name")
        .to_string();
    assert!(error.contains("package.expectedDigest"), "{error}");

    assert_eq!(
        deployment.ledger_rows().await,
        1,
        "startup wrote the ledger"
    );
    deployment.drop().await;
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

#[tokio::test]
async fn split_roles_deny_the_runtime_a_ledger_write_and_the_service_still_serves() {
    let deployment = Deployment::split("activation_split").await;
    let package = deployment.package("package", POLICY);
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let bind = format!("127.0.0.1:{port}");
    let config = deployment.config(
        "runtime.yaml",
        &package,
        ConfigOptions {
            bind: &bind,
            ..ConfigOptions::default()
        },
    );

    let applied = apply(&config).expect("the package activates with the migration credential");
    assert_eq!(applied["roleMode"], "split");
    assert!(applied["roleModeStatement"].is_null());
    let report = status(&config);
    assert_eq!(report["roleMode"], "split");
    assert!(report["roleModeStatement"].is_null());
    assert_eq!(report["history"].as_array().map(Vec::len), Some(1));

    // The runtime credential reads the ledger and cannot change it.
    let runtime = connect(&std::env::var(&deployment.runtime_secret).unwrap()).await;
    runtime
        .query("SELECT activation_id FROM scheduling_activations", &[])
        .await
        .expect("the runtime reads the ledger");
    for statement in [
        "INSERT INTO scheduling_activations(activation_id, apply_order, package_digest, \
         database_id, plan_kind, applied_at, role_mode) VALUES(gen_random_uuid(), 2, \
         'sha256:0000000000000000000000000000000000000000000000000000000000000000', \
         'scheduling-activation-test', 'initial', now(), 'split')",
        "UPDATE scheduling_activations SET database_id='elsewhere'",
        "DELETE FROM scheduling_activations",
        "DELETE FROM scheduling_schema_migrations",
    ] {
        let error = runtime
            .batch_execute(statement)
            .await
            .expect_err("the runtime role cannot write the ledger");
        assert_eq!(
            error.code(),
            Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE),
            "{statement}"
        );
    }
    assert_eq!(deployment.ledger_rows().await, 1);

    // The service starts under the runtime credential and serves.
    let server = tokio::spawn({
        let config = config.clone();
        async move { registry_scheduling::runtime::serve_from_path(&config).await }
    });
    let mut ready = None;
    for _ in 0..300 {
        if server.is_finished() {
            break;
        }
        ready = http_status(&bind, "/readyz").await;
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
    assert_eq!(
        deployment.ledger_rows().await,
        1,
        "startup wrote the ledger"
    );
    deployment.drop().await;
}

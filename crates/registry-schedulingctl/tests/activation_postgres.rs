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
use registry_scheduling::store::{attempt_key_reference, PostgresStore};
use registry_schedulingctl::activation;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

/// The advisory lock every apply takes for its transaction.
const MIGRATION_LOCK_KEY: i64 = 0x7363_6865_6475_6c65;

const POLICY: &str = r#"apiVersion: id.registrystack.org/formats/scheduling/project/v1alpha1
kind: SchedulingProject
project:
  id: registry-updates
  version: "1"
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
      maximumRecipients: 1
    cancellationCutoffMinutes: 240
holidaySets:
  - id: office-holidays
    revision: 1
    because: Public holidays observed by the registry offices.
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
channels: [public, assisted]
holdPolicy:
  ttlMinutes: 5
  maximumPerCaller: 3
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

/// A fixed, non-secret audit HMAC key for the disposable deployments.
const AUDIT_HMAC: &str = "0123456789abcdef0123456789abcdef";

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
        std::env::set_var(&deployment.audit_secret, AUDIT_HMAC);
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
            "apiVersion: id.registrystack.org/formats/scheduling/runtime/v1alpha1\n\
             kind: SchedulingRuntimeConfig\n\
             package:\n  root: {package}\n{expected}\
             identity:\n  databaseId: {database_id}\n\
             listener:\n  bind: {bind}\n  tlsTermination: development-loopback\n\
             secretProviders:\n  environment: {{}}\n\
             authentication:\n  oidc:\n    issuer: https://identity.example.test\n\
             \x20   audience: urn:example:scheduling\n\
             \x20   allowedClients: [scheduling-test-client]\n\
             \x20   jwksSource:\n      kind: static\n      documentRef: secret:env/{jwks}\n\
             database:\n  runtimeUrlRef: secret:env/{runtime}\n\
             \x20 migrationUrlRef: secret:env/{migration}\n\
             \x20 testOnlyPlaintext: true\n\
             audit:\n  path: {audit}\n  hashKeyRef: secret:env/{audit_key}\n\
             retention:\n  attemptReceiptRetentionDays: 2\n",
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
        serde_json::json!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
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

/// A policy hook whose destination cannot sign is refused by apply before
/// it writes anything, so plan reports the same refusal and no pending
/// change. Plan resolves the key reference only to learn whether it names a
/// key of a usable size; the report carries neither the key nor its source.
#[tokio::test]
async fn plan_reports_a_hook_destination_apply_cannot_sign_for() {
    let deployment = Deployment::single("activation_plan_hook_key").await;
    let policy = format!(
        "{POLICY}hooks:\n  - id: confirmed-observer\n    phase: after\n    trigger: appointment.confirmed\n    projection: [appointmentId, revision, state]\n    handler: {{type: url, destinationId: appointment-events}}\n"
    );
    let package = deployment.package("package", &policy);
    let key_secret = format!("{}_HOOK_KEY", deployment.audit_secret);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(&format!(
        "destinations:\n  hooks:\n    appointment-events:\n      url: http://127.0.0.1:9/events\n      hmacSha256KeyRef: secret:env/{key_secret}\n"
    ));
    std::fs::write(&config, text).unwrap();

    for key in [None, Some("too-short")] {
        match key {
            Some(value) => std::env::set_var(&key_secret, value),
            None => std::env::remove_var(&key_secret),
        }
        let report = plan(&config);
        assert_eq!(report["changesPending"], false, "{report}");
        let refusals = report["refusals"].as_array().expect("refusals");
        assert_eq!(refusals.len(), 1, "{report}");
        assert_eq!(
            refusals[0]["code"],
            "schedulingctl.activation.hook-destinations"
        );
        let message = refusals[0]["message"].as_str().unwrap();
        assert!(message.contains("signing secret"), "{message}");
        assert!(!report.to_string().contains("too-short"), "{report}");
        let refused = apply(&config).expect_err("apply refuses the same destination");
        assert!(
            format!("{refused:#}").contains("signing secret"),
            "{refused:#}"
        );
        assert_eq!(deployment.tables().await, 0, "apply created a table");
    }

    std::env::set_var(&key_secret, "k".repeat(32));
    let report = plan(&config);
    assert_eq!(report["changesPending"], true, "{report}");
    assert_eq!(report["refusals"], serde_json::json!([]));
    std::env::remove_var(&key_secret);
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
        serde_json::json!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
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

    // Going back is an activation like any other. The same operator
    // reference on it hashes differently: the hash is keyed to the
    // activation, so two rows cannot be linked by it.
    let rehashed = ctl({
        let config = first_config.clone();
        move || activation::apply(&config, Some("CHG-4242"), &[])
    })
    .expect("the previous package activates again");
    let second_hash: String = deployment
        .admin
        .query_one(
            &format!(
                "SELECT operator_reference_hash FROM {}.scheduling_activations \
                 WHERE apply_order = 3",
                deployment.schema
            ),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_ne!(second_hash, hash, "one reference linked two activations");
    assert!(!second_hash.contains("CHG-4242"));

    let back = apply(&second_config).expect("the successor activates again");
    assert_eq!(rehashed["applyOrder"], 3);
    assert_eq!(rehashed["packageDigest"], initial["packageDigest"]);
    assert_eq!(
        rehashed["predecessorPackageDigest"],
        successor["packageDigest"]
    );
    assert_eq!(back["applyOrder"], 4);
    assert_eq!(back["packageDigest"], successor["packageDigest"]);
    assert_eq!(deployment.ledger_rows().await, 4);

    let report = status(&second_config);
    assert_eq!(
        report["activePackage"]["packageDigest"],
        successor["packageDigest"]
    );
    let history = report["history"].as_array().unwrap();
    assert_eq!(history.len(), 4);
    assert_eq!(history[0]["planKind"], "initial");
    assert_eq!(history[2]["planKind"], "successor");
    assert_eq!(history[0]["roleMode"], "single");
    assert!(history[0]["runtimeRole"].is_string(), "{report}");
    assert_eq!(report["schemaVersion"], 12);
    assert_eq!(report["roleMode"], "single");
    assert!(report["roleModeStatement"].is_string());
    deployment.drop().await;
}

#[tokio::test]
async fn external_reference_migration_preserves_existing_claims_with_an_empty_set() {
    let deployment = Deployment::single("activation_external_references").await;
    let first = deployment.package("first", POLICY);
    let second = deployment.package("second", &successor_policy());
    let first_config = deployment.config("first.yaml", &first, ConfigOptions::default());
    let second_config = deployment.config("second.yaml", &second, ConfigOptions::default());
    apply(&first_config).expect("the initial package activates");

    deployment
        .admin
        .batch_execute(&format!(
            "INSERT INTO {schema}.scheduling_claims
                (claim_id, kind, state, offering, supply_id, displayed_start,
                 displayed_end, occupied_start, occupied_end, units, revision,
                 policy_revision, actor)
             VALUES ('00000000-0000-4000-8000-000000001764', 'booking', 'active',
                     'registry-update-30', 'update-stations', now(), now() + interval '30 minutes',
                     now(), now() + interval '30 minutes', 1, 1, 1, 'legacy-actor');
             ALTER TABLE {schema}.scheduling_claims DROP COLUMN external_references;
             DELETE FROM {schema}.scheduling_schema_migrations WHERE version=10;",
            schema = deployment.schema
        ))
        .await
        .expect("simulate a populated schema immediately before migration 10");

    let report = apply(&second_config).expect("the successor applies migration 10");
    assert_eq!(report["schemaVersionsApplied"], serde_json::json!([10]));
    let row = deployment
        .admin
        .query_one(
            &format!(
                "SELECT offering, actor, external_references
                   FROM {}.scheduling_claims
                  WHERE claim_id='00000000-0000-4000-8000-000000001764'",
                deployment.schema
            ),
            &[],
        )
        .await
        .expect("the pre-migration claim remains");
    assert_eq!(row.get::<_, String>(0), "registry-update-30");
    assert_eq!(row.get::<_, String>(1), "legacy-actor");
    assert_eq!(row.get::<_, Value>(2), serde_json::json!([]));

    deployment.drop().await;
}

/// Migration 11 re-keys every stored attempt under the digest the runtime
/// computes, so a key spent before the upgrade stays spent after it, and
/// clears the raw caller and key from a receipt the sweep had already erased.
#[tokio::test]
async fn attempt_key_reference_migration_rekeys_spent_keys_and_clears_erased_callers() {
    let deployment = Deployment::single("activation_attempt_key_reference").await;
    let first = deployment.package("first", POLICY);
    let second = deployment.package("second", &successor_policy());
    let first_config = deployment.config("first.yaml", &first, ConfigOptions::default());
    let second_config = deployment.config("second.yaml", &second, ConfigOptions::default());
    apply(&first_config).expect("the initial package activates");

    deployment
        .admin
        .batch_execute(&format!(
            "ALTER TABLE {schema}.scheduling_attempts
                 DROP CONSTRAINT scheduling_attempts_raw_caller_check,
                 DROP COLUMN key_reference,
                 ALTER COLUMN actor_issuer SET NOT NULL,
                 ALTER COLUMN actor_subject SET NOT NULL,
                 ALTER COLUMN idempotency_key SET NOT NULL,
                 ADD UNIQUE (actor_issuer, actor_subject, scope, idempotency_key);
             DELETE FROM {schema}.scheduling_schema_migrations WHERE version=11;
             INSERT INTO {schema}.scheduling_attempts
                 (attempt_id, actor_issuer, actor_subject, scope, idempotency_key,
                  request_hash, state, status_code, receipt, expires_at, erased_at)
             VALUES
                 ('00000000-0000-4000-8000-000000001101', 'https://issuer.test',
                  'subject-é', 'appointment:create', 'legacy-live', 'sha256:live',
                  'completed', 201, '{{}}'::jsonb, now() + interval '1 day', NULL),
                 ('00000000-0000-4000-8000-000000001102', 'https://issuer.test',
                  'subject-é', 'hold:create', 'legacy-erased', 'sha256:erased',
                  'refused', 409, NULL, now() - interval '1 day', now());",
            schema = deployment.schema
        ))
        .await
        .expect("simulate stored attempts immediately before migration 11");

    let report = apply(&second_config).expect("the successor applies migration 11");
    assert_eq!(report["schemaVersionsApplied"], serde_json::json!([11]));
    let rows = deployment
        .admin
        .query(
            &format!(
                "SELECT attempt_id::text, key_reference, actor_issuer, actor_subject,
                        idempotency_key, scope, request_hash
                   FROM {}.scheduling_attempts ORDER BY attempt_id",
                deployment.schema
            ),
            &[],
        )
        .await
        .expect("the stored attempts remain");
    assert_eq!(rows.len(), 2);

    let live = &rows[0];
    assert_eq!(
        live.get::<_, String>(1),
        attempt_key_reference(
            "https://issuer.test",
            "subject-é",
            "appointment:create",
            "legacy-live"
        ),
        "the migration's digest is the runtime's"
    );
    assert_eq!(
        live.get::<_, Option<String>>(2).as_deref(),
        Some("https://issuer.test")
    );
    assert_eq!(
        live.get::<_, Option<String>>(3).as_deref(),
        Some("subject-é")
    );
    assert_eq!(
        live.get::<_, Option<String>>(4).as_deref(),
        Some("legacy-live")
    );

    let erased = &rows[1];
    assert_eq!(
        erased.get::<_, String>(1),
        attempt_key_reference(
            "https://issuer.test",
            "subject-é",
            "hold:create",
            "legacy-erased"
        ),
        "an erased key stays spent under its digest"
    );
    assert_eq!(erased.get::<_, Option<String>>(2), None);
    assert_eq!(erased.get::<_, Option<String>>(3), None);
    assert_eq!(erased.get::<_, Option<String>>(4), None);
    assert_eq!(erased.get::<_, String>(5), "hold:create");
    assert_eq!(erased.get::<_, String>(6), "sha256:erased");

    // The raw caller and key are cleared together, and only from an erased
    // receipt.
    for statement in [
        "UPDATE {schema}.scheduling_attempts SET actor_issuer=NULL \
         WHERE attempt_id='00000000-0000-4000-8000-000000001101'",
        "UPDATE {schema}.scheduling_attempts \
         SET actor_issuer=NULL, actor_subject=NULL, idempotency_key=NULL \
         WHERE attempt_id='00000000-0000-4000-8000-000000001101'",
        "UPDATE {schema}.scheduling_attempts SET idempotency_key='legacy-erased' \
         WHERE attempt_id='00000000-0000-4000-8000-000000001102'",
    ] {
        let error = deployment
            .admin
            .batch_execute(&statement.replace("{schema}", &deployment.schema))
            .await
            .expect_err("a partial or premature clearing is refused");
        let constraint = error
            .as_db_error()
            .and_then(|error| error.constraint())
            .map(str::to_owned);
        assert_eq!(
            constraint.as_deref(),
            Some("scheduling_attempts_raw_caller_check"),
            "{statement}"
        );
    }

    deployment.drop().await;
}

/// Migration 12 adds the verified owner beside the pseudonym. A claim
/// written before it recorded only the pseudonym, so it keeps its capacity,
/// its pseudonym, and its state with no owner, and the constraint holds every
/// owner as a whole non-empty pair.
#[tokio::test]
async fn claim_owner_migration_keeps_existing_claims_and_refuses_a_partial_owner() {
    let deployment = Deployment::single("activation_claim_owner").await;
    let first = deployment.package("first", POLICY);
    let second = deployment.package("second", &successor_policy());
    let first_config = deployment.config("first.yaml", &first, ConfigOptions::default());
    let second_config = deployment.config("second.yaml", &second, ConfigOptions::default());
    apply(&first_config).expect("the initial package activates");

    deployment
        .admin
        .batch_execute(&format!(
            "ALTER TABLE {schema}.scheduling_claims
                 DROP CONSTRAINT scheduling_claims_owner_check,
                 DROP COLUMN owner_issuer,
                 DROP COLUMN owner_subject;
             DELETE FROM {schema}.scheduling_schema_migrations WHERE version=12;
             INSERT INTO {schema}.scheduling_claims
                (claim_id, kind, state, offering, supply_id, displayed_start,
                 displayed_end, occupied_start, occupied_end, units, revision,
                 policy_revision, actor)
             VALUES ('00000000-0000-4000-8000-000000001930', 'booking', 'active',
                     'registry-update-30', 'update-stations', now(), now() + interval '30 minutes',
                     now(), now() + interval '30 minutes', 1, 1, 1, 'legacy-actor');",
            schema = deployment.schema
        ))
        .await
        .expect("simulate a populated schema immediately before migration 12");

    let report = apply(&second_config).expect("the successor applies migration 12");
    assert_eq!(report["schemaVersionsApplied"], serde_json::json!([12]));
    let row = deployment
        .admin
        .query_one(
            &format!(
                "SELECT state, actor, owner_issuer, owner_subject
                   FROM {}.scheduling_claims
                  WHERE claim_id='00000000-0000-4000-8000-000000001930'",
                deployment.schema
            ),
            &[],
        )
        .await
        .expect("the pre-migration claim remains");
    assert_eq!(row.get::<_, String>(0), "active");
    assert_eq!(row.get::<_, String>(1), "legacy-actor");
    assert_eq!(row.get::<_, Option<String>>(2), None);
    assert_eq!(row.get::<_, Option<String>>(3), None);

    for statement in [
        "UPDATE {schema}.scheduling_claims SET owner_issuer='https://issuer.test' \
         WHERE claim_id='00000000-0000-4000-8000-000000001930'",
        "UPDATE {schema}.scheduling_claims SET owner_subject='subject-1' \
         WHERE claim_id='00000000-0000-4000-8000-000000001930'",
        "UPDATE {schema}.scheduling_claims SET owner_issuer='', owner_subject='subject-1' \
         WHERE claim_id='00000000-0000-4000-8000-000000001930'",
        "UPDATE {schema}.scheduling_claims SET owner_issuer='https://issuer.test', owner_subject='' \
         WHERE claim_id='00000000-0000-4000-8000-000000001930'",
    ] {
        let error = deployment
            .admin
            .batch_execute(&statement.replace("{schema}", &deployment.schema))
            .await
            .expect_err("a partial or empty owner is refused");
        let constraint = error
            .as_db_error()
            .and_then(|error| error.constraint())
            .map(str::to_owned);
        assert_eq!(
            constraint.as_deref(),
            Some("scheduling_claims_owner_check"),
            "{statement}"
        );
    }
    deployment
        .admin
        .batch_execute(&format!(
            "UPDATE {}.scheduling_claims
                SET owner_issuer='https://issuer.test', owner_subject='subject-1'
              WHERE claim_id='00000000-0000-4000-8000-000000001930'",
            deployment.schema
        ))
        .await
        .expect("a whole owner is accepted");

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
    // A plan apply would refuse records no activation.
    assert_eq!(report["changesPending"], false, "{report}");
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

/// A pending migration that would drop unpublished audit is named by
/// `plan`, read without a lock, and `apply` refuses the same.
#[tokio::test]
async fn plan_reports_the_unpublished_audit_apply_refuses() {
    let deployment = Deployment::single("activation_plan_outbox").await;
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());
    apply(&config).expect("the package activates");
    // The schema head of the release that published audit from an outbox,
    // holding one record its publisher has not reached.
    deployment
        .admin
        .batch_execute(&format!(
            "CREATE TABLE {schema}.scheduling_audit_outbox (event_id uuid PRIMARY KEY, \
                 audit_record jsonb NOT NULL, published_at timestamptz); \
             INSERT INTO {schema}.scheduling_audit_outbox(event_id, audit_record) \
                 VALUES('00000000-0000-4000-8000-0000000000c1', '{{}}'); \
             DELETE FROM {schema}.scheduling_schema_migrations WHERE version=8;",
            schema = deployment.schema
        ))
        .await
        .expect("simulate the schema before migration 8");
    let successor = deployment.package("successor", &successor_policy());
    let config = deployment.config("successor.yaml", &successor, ConfigOptions::default());

    let report = plan(&config);
    let codes: Vec<&str> = report["refusals"]
        .as_array()
        .expect("refusals")
        .iter()
        .map(|refusal| refusal["code"].as_str().expect("code"))
        .collect();
    assert_eq!(
        codes,
        ["schedulingctl.activation.unpublished-audit"],
        "{report}"
    );
    assert_eq!(report["changesPending"], false, "{report}");
    assert!(
        report["refusals"][0]["message"]
            .as_str()
            .expect("message")
            .contains("holds 1 audit record(s) that schema migration 8 would drop"),
        "{report}"
    );

    let error = refusal(apply(&config));
    assert!(
        error.contains("holds 1 audit record(s) that schema migration 8 would drop"),
        "{error}"
    );
    assert_eq!(deployment.ledger_rows().await, 1);
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
        .expect_err("startup refuses a package its pin does not name");
    let report = error
        .configuration_report()
        .unwrap_or_else(|| panic!("startup refusal carries a report: {error}"));
    let findings: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect();
    assert_eq!(
        findings,
        [(
            "scheduling.package.digest-mismatch",
            "/package/expectedDigest"
        )]
    );

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
        LEDGER_INSERT,
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

#[tokio::test]
async fn split_apply_grants_the_runtime_role_only_scheduling_objects() {
    // A schema Scheduling shares with another application, such as public,
    // holds objects the migration role owns that are not Scheduling's.
    let deployment = Deployment::split("activation_foreign").await;
    let (runtime_role, migration_role) = (deployment.roles[0].clone(), deployment.roles[1].clone());
    let schema = deployment.schema.clone();
    deployment
        .admin
        .batch_execute(&format!(
            "CREATE TABLE {schema}.other_app_records (id bigint GENERATED ALWAYS AS IDENTITY, body text);\
             CREATE SEQUENCE {schema}.other_app_counter;\
             CREATE FUNCTION {schema}.other_app_touch() RETURNS integer LANGUAGE sql AS 'SELECT 1';\
             REVOKE EXECUTE ON FUNCTION {schema}.other_app_touch() FROM PUBLIC;\
             ALTER TABLE {schema}.other_app_records OWNER TO {migration_role};\
             ALTER SEQUENCE {schema}.other_app_counter OWNER TO {migration_role};\
             ALTER FUNCTION {schema}.other_app_touch() OWNER TO {migration_role};"
        ))
        .await
        .expect("another application's objects are created");
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());

    let applied = apply(&config).expect("the package activates with the migration credential");
    assert_eq!(applied["roleMode"], "split");
    let row = deployment
        .admin
        .query_one(
            &format!(
                "SELECT has_table_privilege($1, '{schema}.other_app_records', 'SELECT, INSERT, UPDATE, DELETE'), \
                        has_sequence_privilege($1, '{schema}.other_app_counter', 'USAGE, SELECT'), \
                        has_sequence_privilege($1, pg_get_serial_sequence('{schema}.other_app_records', 'id'), 'USAGE, SELECT'), \
                        has_function_privilege($1, '{schema}.other_app_touch()', 'EXECUTE'), \
                        has_table_privilege($1, '{schema}.scheduling_claims', 'SELECT, INSERT, UPDATE, DELETE')"
            ),
            &[&runtime_role],
        )
        .await
        .expect("the runtime role's privileges are readable");
    let privileges: [bool; 5] = [row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)];
    assert_eq!(
        privileges,
        [false, false, false, false, true],
        "the runtime role holds [foreign table, foreign sequence, foreign identity, foreign function, scheduling_claims]"
    );

    // The foreign objects it was never granted do not count as lost grants.
    let digest = applied["packageDigest"].as_str().unwrap().to_owned();
    let error = refusal(apply(&config));
    assert!(
        error.contains(&format!(
            "package {digest} is already the active package on this database; nothing needs applying"
        )),
        "{error}"
    );
    deployment
        .admin
        .batch_execute(&format!(
            "DROP TABLE {schema}.other_app_records; DROP SEQUENCE {schema}.other_app_counter; \
             DROP FUNCTION {schema}.other_app_touch()"
        ))
        .await
        .expect("the foreign objects are dropped");
    deployment.drop().await;
}

#[tokio::test]
async fn plan_before_the_first_split_apply_reports_the_initial_activation() {
    // The runtime role holds nothing until the first apply grants it, so it
    // cannot even see the schema: plan must read that as an empty database.
    let deployment = Deployment::split("activation_plan_split").await;
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());

    let report = plan(&config);
    assert!(report["activePackage"].is_null(), "{report}");
    assert_eq!(report["databaseIdCheck"], "initial");
    assert_eq!(report["retainedHookBindings"], "none-retained");
    assert_eq!(report["changesPending"], true);
    assert_eq!(report["refusals"], serde_json::json!([]));
    assert_eq!(deployment.tables().await, 0, "plan created a table");
    deployment.drop().await;
}

/// Whether `statement`, run by `client`, is refused for want of privilege.
async fn denied(client: &tokio_postgres::Client, statement: &str) -> bool {
    client
        .batch_execute(statement)
        .await
        .err()
        .and_then(|error| error.code().cloned())
        == Some(tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE)
}

const LEDGER_INSERT: &str = "INSERT INTO scheduling_activations(activation_id, apply_order, \
     package_digest, database_id, plan_kind, applied_at, role_mode, runtime_role) \
     VALUES(gen_random_uuid(), 99, \
     'sha256:0000000000000000000000000000000000000000000000000000000000000000', \
     'scheduling-activation-test', 'initial', now(), 'split', 'intruder')";

#[tokio::test]
async fn a_runtime_role_that_can_write_the_ledger_is_refused_at_startup_until_apply_reissues_its_grants(
) {
    let deployment = Deployment::split("activation_drift").await;
    let runtime_role = deployment.roles[0].clone();
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());
    let applied = apply(&config).expect("the package activates");
    assert_eq!(applied["roleMode"], "split");

    // Someone grants the runtime role a ledger write after the apply.
    deployment
        .admin
        .batch_execute(&format!(
            "GRANT INSERT ON {}.scheduling_activations TO {runtime_role}",
            deployment.schema
        ))
        .await
        .unwrap();
    let error = registry_scheduling::runtime::serve_from_path(&config)
        .await
        .expect_err("startup refuses a split ledger the runtime role can write")
        .to_string();
    assert!(
        error.contains("records split role mode")
            && error.contains("run `schedulingctl apply --runtime-config FILE`"),
        "{error}"
    );

    // The active package applies again, because its recorded role mode no
    // longer holds; plan says so without calling it a refusal.
    let report = plan(&config);
    assert_eq!(report["changesPending"], true, "{report}");
    assert_eq!(report["effectiveRoleMode"], "single");
    assert_eq!(report["refusals"], serde_json::json!([]));
    let reapplied = apply(&config).expect("apply reissues the runtime role's grants");
    assert_eq!(reapplied["applyOrder"], 2);
    assert_eq!(reapplied["roleMode"], "split");
    let runtime = connect(&std::env::var(&deployment.runtime_secret).unwrap()).await;
    assert!(denied(&runtime, LEDGER_INSERT).await, "the grant survived");
    assert_eq!(plan(&config)["changesPending"], false);
    assert_eq!(deployment.ledger_rows().await, 2);

    // A write on the schema history counts the same as one on the ledger.
    deployment
        .admin
        .batch_execute(&format!(
            "GRANT UPDATE ON {}.scheduling_schema_migrations TO {runtime_role}",
            deployment.schema
        ))
        .await
        .unwrap();
    let error = startup_refusal(&config).await;
    assert!(error.contains("records split role mode"), "{error}");
    let reapplied = apply(&config).expect("apply reissues the runtime role's grants");
    assert_eq!(reapplied["roleMode"], "split");
    assert_eq!(deployment.ledger_rows().await, 3);

    // A column-level write on either ledger counts the same as a table-level
    // one, and apply's revoke takes it back with the table's.
    let mut rows = 3;
    for grant in [
        "GRANT UPDATE (package_digest) ON {schema}.scheduling_activations TO {role}",
        "GRANT INSERT (version) ON {schema}.scheduling_schema_migrations TO {role}",
    ] {
        deployment
            .admin
            .batch_execute(
                &grant
                    .replace("{schema}", &deployment.schema)
                    .replace("{role}", &runtime_role),
            )
            .await
            .unwrap();
        let error = startup_refusal(&config).await;
        assert!(
            error.contains("records split role mode"),
            "{grant}: {error}"
        );
        let reapplied = apply(&config).expect("apply reissues the runtime role's grants");
        assert_eq!(reapplied["roleMode"], "split", "{grant}");
        rows += 1;
        assert_eq!(deployment.ledger_rows().await, rows);
    }
    deployment.drop().await;
}

/// The refusal startup reports, bounded so a startup that serves instead
/// fails the test rather than holding it open.
async fn startup_refusal(config: &Path) -> String {
    tokio::time::timeout(
        Duration::from_secs(20),
        registry_scheduling::runtime::serve_from_path(config),
    )
    .await
    .expect("startup refuses instead of serving")
    .expect_err("startup refuses")
    .to_string()
}

/// What follows a fix that takes grants away with the object it moves.
const THEN_APPLY: &str =
    "then run `schedulingctl apply --runtime-config FILE` to reissue the runtime role's grants";

/// What follows a fix that leaves the runtime role's grants in place.
const THEN_RERUN: &str =
    "then rerun the command that refused, or run `schedulingctl plan --runtime-config FILE` to confirm";

/// The fix a weakened split names, then what to run next.
fn names_fix(error: &str, fix: &str, then: &str) -> bool {
    error.contains(&format!("run `{fix}` as a database administrator, {then}"))
}

/// Whether `role` holds `privilege` on the Scheduling table `table`.
async fn holds(deployment: &Deployment, role: &str, table: &str, privilege: &str) -> bool {
    deployment
        .admin
        .query_one(
            "SELECT has_table_privilege($1::text, format('%I.%I', $2::text, $3::text), $4::text)",
            &[&role, &deployment.schema, &table, &privilege],
        )
        .await
        .expect("the catalog is readable")
        .get(0)
}

#[tokio::test]
async fn a_runtime_role_owning_a_scheduling_table_is_refused_in_split_mode_naming_reassign_owned() {
    let deployment = Deployment::split("activation_owner").await;
    let (runtime_role, migration_role) = (deployment.roles[0].clone(), deployment.roles[1].clone());
    let fix = format!("REASSIGN OWNED BY {runtime_role} TO {migration_role}");
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());
    assert_eq!(
        apply(&config).expect("the package activates")["roleMode"],
        "split"
    );

    // The runtime role comes to own a table apply writes and attaches a
    // deferred trigger that would run as the migration role at commit.
    let schema = deployment.schema.clone();
    deployment
        .admin
        .batch_execute(&format!(
            "ALTER TABLE {schema}.scheduling_supply OWNER TO {runtime_role}"
        ))
        .await
        .unwrap();
    connect(&std::env::var(&deployment.runtime_secret).unwrap())
        .await
        .batch_execute(&format!(
            "CREATE CONSTRAINT TRIGGER planted AFTER UPDATE ON {schema}.scheduling_supply \
             DEFERRABLE INITIALLY DEFERRED FOR EACH ROW \
             EXECUTE FUNCTION suppress_redundant_updates_trigger()"
        ))
        .await
        .expect("the owning runtime role attaches a trigger");
    let error = startup_refusal(&config).await;
    assert!(names_fix(&error, &fix, THEN_APPLY), "{error}");

    let report = plan(&config);
    assert_eq!(report["effectiveRoleMode"], "single", "{report}");
    assert_eq!(
        report["refusals"][0]["code"], "schedulingctl.activation.split-role-weakened",
        "{report}"
    );
    let error = refusal(apply(&config));
    assert!(names_fix(&error, &fix, THEN_APPLY), "{error}");
    assert_eq!(
        deployment.ledger_rows().await,
        1,
        "a weakened split was recorded"
    );

    // Reassigning the table leaves the trigger the runtime role attached,
    // and apply still refuses, naming it.
    deployment
        .admin
        .batch_execute(&format!(
            "REASSIGN OWNED BY {runtime_role} TO {migration_role}"
        ))
        .await
        .unwrap();
    let drop_trigger = format!("DROP TRIGGER planted ON {schema}.scheduling_supply");
    let error = refusal(apply(&config));
    assert!(names_fix(&error, &drop_trigger, THEN_RERUN), "{error}");
    assert_eq!(deployment.ledger_rows().await, 1);
    deployment.admin.batch_execute(&drop_trigger).await.unwrap();

    // Membership in a role that owns a Scheduling table counts the same,
    // one that grants no inherited privilege but still permits SET ROLE too.
    let owner = format!("{runtime_role}_owner");
    deployment
        .admin
        .batch_execute(&format!(
            "CREATE ROLE {owner}; GRANT {owner} TO {runtime_role} WITH INHERIT FALSE, SET TRUE;\
             ALTER TABLE {schema}.scheduling_meta OWNER TO {owner}"
        ))
        .await
        .unwrap();
    let error = refusal(apply(&config));
    assert!(
        names_fix(
            &error,
            &format!("REASSIGN OWNED BY {owner} TO {migration_role}"),
            THEN_APPLY
        ),
        "{error}"
    );
    assert_eq!(deployment.ledger_rows().await, 1);

    deployment
        .admin
        .batch_execute(&format!(
            "REASSIGN OWNED BY {owner} TO {migration_role}; DROP ROLE {owner}"
        ))
        .await
        .unwrap();
    // Moving ownership back took the runtime role's grants on the table
    // with it, so startup refuses and the active package is not yet served
    // as applied: apply reissues the grants as one more row.
    assert!(!holds(&deployment, &runtime_role, "scheduling_supply", "SELECT").await);
    let error = startup_refusal(&config).await;
    assert!(
        error.contains(&format!(
            "the runtime role {runtime_role} no longer holds every grant `schedulingctl apply` issues it; run `schedulingctl apply --runtime-config FILE` to reissue them"
        )),
        "{error}"
    );
    let report = plan(&config);
    assert_eq!(report["effectiveRoleMode"], "split", "{report}");
    assert_eq!(report["changesPending"], true, "{report}");
    assert_eq!(
        apply(&config).expect("apply reissues the grants")["roleMode"],
        "split"
    );
    assert_eq!(deployment.ledger_rows().await, 2);
    assert!(holds(&deployment, &runtime_role, "scheduling_supply", "UPDATE").await);
    assert_eq!(plan(&config)["changesPending"], false);
    deployment.drop().await;
}

#[tokio::test]
async fn a_runtime_role_with_create_on_the_schema_is_refused_in_split_mode_naming_revoke_create() {
    let deployment = Deployment::split("activation_create").await;
    let runtime_role = deployment.roles[0].clone();
    let fix = format!(
        "REVOKE CREATE ON SCHEMA {} FROM {runtime_role}",
        deployment.schema
    );
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());
    let grant = format!(
        "GRANT CREATE ON SCHEMA {} TO {runtime_role}",
        deployment.schema
    );
    deployment.admin.batch_execute(&grant).await.unwrap();

    let error = refusal(apply(&config));
    assert!(names_fix(&error, &fix, THEN_RERUN), "{error}");
    assert_eq!(
        deployment.tables().await,
        0,
        "the refused apply wrote tables"
    );

    deployment
        .admin
        .batch_execute(&format!(
            "REVOKE CREATE ON SCHEMA {} FROM {runtime_role}",
            deployment.schema
        ))
        .await
        .unwrap();
    assert_eq!(
        apply(&config).expect("the package activates")["roleMode"],
        "split"
    );

    deployment.admin.batch_execute(&grant).await.unwrap();
    let error = startup_refusal(&config).await;
    assert!(names_fix(&error, &fix, THEN_RERUN), "{error}");
    assert_eq!(
        deployment.ledger_rows().await,
        1,
        "startup wrote the ledger"
    );

    // Held through PUBLIC, the privilege is revoked from PUBLIC.
    let schema = &deployment.schema;
    deployment
        .admin
        .batch_execute(&format!(
            "REVOKE CREATE ON SCHEMA {schema} FROM {runtime_role};\
             GRANT CREATE ON SCHEMA {schema} TO PUBLIC"
        ))
        .await
        .unwrap();
    let error = refusal(apply(&config));
    assert!(
        names_fix(
            &error,
            &format!("REVOKE CREATE ON SCHEMA {schema} FROM PUBLIC"),
            THEN_RERUN
        ),
        "{error}"
    );
    assert_eq!(deployment.ledger_rows().await, 1);
    deployment.drop().await;
}

#[tokio::test]
async fn a_runtime_role_holding_trigger_on_a_scheduling_table_is_refused_in_split_mode_naming_revoke_trigger(
) {
    let deployment = Deployment::split("activation_trigger").await;
    let (runtime_role, migration_role) = (deployment.roles[0].clone(), deployment.roles[1].clone());
    let schema = deployment.schema.clone();
    let fix = format!("REVOKE TRIGGER ON {schema}.scheduling_supply FROM {runtime_role}");
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());

    // A default privilege would hand the runtime role TRIGGER on every table
    // the first apply creates. Apply does not take it away: it refuses before
    // any migration, naming the default privilege to revoke, since the tables
    // a later refusal would name do not survive its rollback.
    deployment
        .admin
        .batch_execute(&format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {migration_role} IN SCHEMA {schema} \
             GRANT TRIGGER ON TABLES TO {runtime_role}"
        ))
        .await
        .unwrap();
    let default_fix = format!(
        "ALTER DEFAULT PRIVILEGES FOR ROLE {migration_role} IN SCHEMA {schema} \
         REVOKE TRIGGER ON TABLES FROM {runtime_role}"
    );
    let error = refusal(apply(&config));
    assert!(names_fix(&error, &default_fix, THEN_RERUN), "{error}");
    assert_eq!(
        deployment.tables().await,
        0,
        "a refused apply created tables"
    );
    deployment.admin.batch_execute(&default_fix).await.unwrap();
    assert_eq!(
        apply(&config).expect("the package activates")["roleMode"],
        "split"
    );
    assert!(!holds(&deployment, &runtime_role, "scheduling_supply", "TRIGGER").await);

    // TRIGGER granted afterwards lets the runtime role attach a deferred
    // trigger that runs as the migration role at the next apply's commit.
    deployment
        .admin
        .batch_execute(&format!(
            "GRANT TRIGGER ON {schema}.scheduling_supply TO {runtime_role}"
        ))
        .await
        .unwrap();
    let error = startup_refusal(&config).await;
    assert!(names_fix(&error, &fix, THEN_RERUN), "{error}");
    let report = plan(&config);
    assert_eq!(report["effectiveRoleMode"], "single", "{report}");
    assert_eq!(
        report["refusals"][0]["code"], "schedulingctl.activation.split-role-weakened",
        "{report}"
    );
    let error = refusal(apply(&config));
    assert!(names_fix(&error, &fix, THEN_RERUN), "{error}");
    assert_eq!(
        deployment.ledger_rows().await,
        1,
        "a weakened split was recorded"
    );

    deployment.admin.batch_execute(&fix).await.unwrap();
    let report = plan(&config);
    assert_eq!(report["effectiveRoleMode"], "split", "{report}");
    assert_eq!(report["changesPending"], false, "{report}");

    // Held through PUBLIC, the privilege is revoked from PUBLIC.
    deployment
        .admin
        .batch_execute(&format!(
            "GRANT TRIGGER ON {schema}.scheduling_supply TO PUBLIC"
        ))
        .await
        .unwrap();
    let error = refusal(apply(&config));
    assert!(
        names_fix(
            &error,
            &format!("REVOKE TRIGGER ON {schema}.scheduling_supply FROM PUBLIC"),
            THEN_RERUN
        ),
        "{error}"
    );
    assert_eq!(deployment.ledger_rows().await, 1);
    deployment.drop().await;
}

/// Membership in the migration role is its authority, whether it is
/// inherited or only permits `SET ROLE` to it.
#[tokio::test]
async fn a_runtime_role_holding_the_migration_role_is_recorded_as_single() {
    for options in ["", " WITH INHERIT FALSE, SET TRUE"] {
        let deployment = Deployment::split("activation_member").await;
        let (runtime_role, migration_role) =
            (deployment.roles[0].clone(), deployment.roles[1].clone());
        deployment
            .admin
            .batch_execute(&format!(
                "GRANT {migration_role} TO {runtime_role}{options}"
            ))
            .await
            .unwrap();
        let package = deployment.package("package", POLICY);
        let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());

        let applied = apply(&config).expect("the package activates");
        assert_eq!(applied["roleMode"], "single", "{options}: {applied}");
        assert!(applied["roleModeStatement"].is_string());
        let report = status(&config);
        assert_eq!(report["history"][0]["roleMode"], "single", "{options}");
        assert_eq!(report["roleMode"], "single", "{options}");
        deployment.drop().await;
    }
}

#[tokio::test]
async fn rotating_the_runtime_role_reapplies_the_active_package() {
    let mut deployment = Deployment::split("activation_rotate").await;
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());
    apply(&config).expect("the package activates");

    let rotated = format!("scheduling_rotated_{}", Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    deployment
        .admin
        .batch_execute(&format!(
            "CREATE ROLE {rotated} LOGIN PASSWORD '{password}'"
        ))
        .await
        .unwrap();
    deployment.roles.insert(0, rotated.clone());
    std::env::set_var(
        &deployment.runtime_secret,
        scoped_url(
            &with_login(&base_url(), &rotated, &password),
            &deployment.schema,
        ),
    );

    let reapplied = apply(&config).expect("the active package applies for the rotated role");
    assert_eq!(reapplied["applyOrder"], 2);
    assert_eq!(reapplied["roleMode"], "split");
    let report = status(&config);
    assert_eq!(report["history"][1]["runtimeRole"], rotated.as_str());
    let runtime = connect(&std::env::var(&deployment.runtime_secret).unwrap()).await;
    assert!(denied(&runtime, LEDGER_INSERT).await);
    assert_eq!(plan(&config)["changesPending"], false);
    deployment.drop().await;
}

#[tokio::test]
async fn plan_as_a_rotated_runtime_role_that_cannot_read_the_ledger_names_apply() {
    let mut deployment = Deployment::split("activation_plan_rotated").await;
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());
    apply(&config).expect("the package activates");

    let rotated = format!("scheduling_rotated_{}", Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    deployment
        .admin
        .batch_execute(&format!(
            "CREATE ROLE {rotated} LOGIN PASSWORD '{password}'"
        ))
        .await
        .unwrap();
    deployment.roles.insert(0, rotated.clone());
    std::env::set_var(
        &deployment.runtime_secret,
        scoped_url(
            &with_login(&base_url(), &rotated, &password),
            &deployment.schema,
        ),
    );
    let planned = |config: &Path| {
        let config = config.to_path_buf();
        ctl(move || activation::plan(&config))
    };
    let expected = format!(
        "the Scheduling runtime role cannot read the activation ledger in schema {}; run `schedulingctl apply --runtime-config FILE` to grant the runtime role its privileges, then rerun `schedulingctl plan --runtime-config FILE`",
        deployment.schema
    );

    // Without USAGE on the schema the ledger is invisible, which must not
    // read as an empty database.
    let error = planned(&config).expect_err("a role that cannot see the ledger is refused");
    assert!(
        error
            .chain()
            .any(|cause| cause.downcast_ref::<activation::Refusal>().is_some()),
        "{error:#}"
    );
    assert!(format!("{error:#}").ends_with(&expected), "{error:#}");

    // With USAGE but without SELECT on the ledger tables.
    deployment
        .admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA {} TO {rotated}",
            deployment.schema
        ))
        .await
        .unwrap();
    let error = planned(&config).expect_err("a role that cannot read the ledger is refused");
    assert!(format!("{error:#}").ends_with(&expected), "{error:#}");

    apply(&config).expect("the active package applies for the rotated role");
    assert_eq!(plan(&config)["changesPending"], false);
    deployment.drop().await;
}

/// An audit sink that accepts its first `lines` lines and refuses every
/// later write.
struct LimitedSink {
    lines: usize,
}

impl std::io::Write for LimitedSink {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.lines == 0 {
            return Err(std::io::Error::other("the test sink refuses this append"));
        }
        self.lines -= buffer
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
            .min(self.lines);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn apply_audited_by(config: &Path, lines: usize) -> anyhow::Result<Value> {
    let config = config.to_path_buf();
    ctl(move || {
        activation::apply_with_audit_sink(&config, None, &[], Box::new(LimitedSink { lines }))
    })
}

#[tokio::test]
async fn apply_writes_nothing_when_its_request_audit_entry_is_refused() {
    let deployment = Deployment::single("activation_audit_request").await;
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());

    let error = apply_audited_by(&config, 0).expect_err("the unaudited apply refuses");
    assert!(
        format!("{error:#}")
            .starts_with("writing the activation.apply request audit entry; nothing was applied"),
        "{error:#}"
    );
    assert!(error
        .chain()
        .any(|cause| cause.is::<registry_platform_audit::AuditUnavailable>()));
    assert_eq!(deployment.tables().await, 0, "an unaudited apply wrote");
    deployment.drop().await;
}

#[tokio::test]
async fn an_apply_whose_response_audit_entry_is_refused_reports_it_applied_unaudited() {
    let deployment = Deployment::single("activation_audit_response").await;
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());

    let error = apply_audited_by(&config, 1).expect_err("the unaudited response is reported");
    let unaudited = error
        .downcast_ref::<activation::AppliedUnaudited>()
        .expect("the failure says the package was applied unaudited");
    let message = unaudited.to_string();
    assert!(message.contains("was applied as activation"), "{message}");
    assert!(
        message.contains("`schedulingctl status --runtime-config FILE`"),
        "{message}"
    );
    assert_eq!(deployment.ledger_rows().await, 1, "the activation stands");
    deployment.drop().await;
}

#[tokio::test]
async fn apply_takes_the_publication_locks_before_it_migrates() {
    // Split roles name the waiting apply among sibling tests on the server.
    let deployment = Deployment::split("activation_lock_order").await;
    let migration_role = deployment.roles[1].clone();
    let package = deployment.package("package", POLICY);
    let config = deployment.config("runtime.yaml", &package, ConfigOptions::default());
    apply(&config).expect("the package activates");
    assert!(
        deployment
            .scalar_i64("SELECT count(*) FROM {schema}.scheduling_supply")
            .await
            > 0,
        "the policy anchors no supply to wait on"
    );

    // A database from before the ledger: its last schema version pending.
    deployment
        .admin
        .batch_execute(&format!(
            "DROP TABLE {schema}.scheduling_activations;\
             DELETE FROM {schema}.scheduling_schema_migrations WHERE version IN (9, 10);",
            schema = deployment.schema
        ))
        .await
        .unwrap();

    // A capacity transaction holds a supply anchor.
    let holder = connect(&base_url()).await;
    holder.batch_execute("BEGIN").await.unwrap();
    holder
        .batch_execute(&format!(
            "SELECT supply_id FROM {}.scheduling_supply FOR UPDATE",
            deployment.schema
        ))
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
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE usename=$1 AND wait_event_type='Lock' \
                 AND wait_event IN ('transactionid', 'tuple')",
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
    assert!(blocked, "the apply never waited on the supply anchor");
    // A row-lock wait holds a tuple lock in AccessExclusive mode, so only
    // relation locks show a migration's DDL.
    let exclusive: i64 = deployment
        .admin
        .query_one(
            "SELECT count(*) FROM pg_locks JOIN pg_stat_activity USING (pid) \
             WHERE usename=$1 AND granted AND locktype='relation' \
             AND mode='AccessExclusiveLock'",
            &[&migration_role],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        exclusive, 0,
        "the apply held migration locks while it waited on supply"
    );

    holder.batch_execute("COMMIT").await.unwrap();
    let report = waiting
        .join()
        .expect("the apply does not panic")
        .expect("the apply proceeds once the anchor is released");
    assert_eq!(report["schemaVersionsApplied"], serde_json::json!([9, 10]));
    deployment.drop().await;
}

// SPDX-License-Identifier: Apache-2.0

//! Database-backed activation tests: `messagingctl plan` previews and
//! `messagingctl apply` records a package, the runtime serves only the
//! package the shared ledger names active, `package.expectedDigest` pins it,
//! and a template version renders the same bytes across an upgrade.
//!
//! Every test runs in its own schema inside the database named by
//! `MESSAGING_TEST_DATABASE_URL`. A test binary that passes because its
//! database URL is absent is not database verification, so the variable is
//! required: without it every test in this file fails on the spot.

use std::cell::Cell;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use registry_messaging::activation::{ActivationChange, ActivationError, ApplyRequest};
use registry_messaging::config::{RuntimeConfig, RuntimeConfigError};
use registry_messaging::package::{load_package, package_inputs, write_package_inputs};
use registry_messaging::runtime::{
    activation_plan, apply_activation, apply_package, migrate_from_path, serve_from_path,
    PackageChange, RuntimeError,
};
use registry_messaging::store::PostgresStore;
use registry_messaging_core::{Package, TemplatePreviewRequest};
use registry_platform_audit::AuditDestination;
use serde_json::{json, Value};
use uuid::Uuid;

/// The activation lock key, the ASCII bytes of "messagin".
const LEDGER_LOCK_KEY: i64 = 0x6d65_7373_6167_696e;

/// One isolated schema and the secret reference that reaches it.
struct Isolated {
    schema: String,
    reference: String,
    migration_reference: String,
    admin: tokio_postgres::Client,
}

async fn isolated_schema() -> Isolated {
    let base = std::env::var("MESSAGING_TEST_DATABASE_URL")
        .expect("MESSAGING_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let schema = format!("messaging_{}", Uuid::new_v4().simple());
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
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
        migration_reference: format!("secret:env/{secret_name}"),
        admin,
    }
}

async fn isolated_split_schema() -> (Isolated, String, String) {
    let base = std::env::var("MESSAGING_TEST_DATABASE_URL")
        .expect("MESSAGING_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let suffix = Uuid::new_v4().simple().to_string();
    let schema = format!("messaging_{suffix}");
    let migration_role = format!("msg_migration_{suffix}");
    let runtime_role = format!("msg_runtime_{suffix}");
    let (admin, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("connect the messaging test database");
    tokio::spawn(async move { connection.await.expect("the messaging admin connection") });
    admin
        .batch_execute(&format!(
            "CREATE ROLE {migration_role} LOGIN PASSWORD 'messaging-test'; \
         CREATE ROLE {runtime_role} LOGIN PASSWORD 'messaging-test'; \
         CREATE SCHEMA {schema} AUTHORIZATION {migration_role}"
        ))
        .await
        .expect("split Messaging roles and schema");
    let scoped = |role: &str| {
        let mut url = url::Url::parse(&base).expect("the test database URL");
        url.set_username(role).expect("a role in the URL");
        url.set_password(Some("messaging-test"))
            .expect("a password in the URL");
        url.query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        url.to_string()
    };
    let runtime_name = format!("MESSAGING_RUNTIME_{}", suffix.to_ascii_uppercase());
    let migration_name = format!("MESSAGING_MIGRATION_{}", suffix.to_ascii_uppercase());
    std::env::set_var(&runtime_name, scoped(&runtime_role));
    std::env::set_var(&migration_name, scoped(&migration_role));
    (
        Isolated {
            schema,
            reference: format!("secret:env/{runtime_name}"),
            migration_reference: format!("secret:env/{migration_name}"),
            admin,
        },
        migration_role,
        runtime_role,
    )
}

impl Isolated {
    /// Every digest the ledger recorded, oldest first.
    async fn ledger(&self) -> Vec<String> {
        self.admin
            .query(
                &format!(
                    "SELECT package_digest FROM {}.messaging_activations ORDER BY apply_order",
                    self.schema
                ),
                &[],
            )
            .await
            .expect("the package ledger")
            .iter()
            .map(|row| row.get(0))
            .collect()
    }
}

fn free_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    listener.local_addr().expect("the bound address")
}

/// A public P-256 key (RFC 7517, appendix A.1); nothing here signs a token.
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

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A deployment over a copy of the published starter package.
struct Deployment {
    root: tempfile::TempDir,
    reference: String,
    migration_reference: String,
    package_generation: Cell<u32>,
}

impl Deployment {
    fn new(isolated: &Isolated) -> Self {
        let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap())
            .expect("a runtime directory");
        let starter =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/messaging/examples/starter");
        let project = root.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::copy(
            starter.join("messaging.yaml"),
            project.join("messaging.yaml"),
        )
        .unwrap();
        copy_tree(&starter.join("templates"), &project.join("templates"));
        copy_tree(&starter.join("providers"), &project.join("providers"));
        let deployment = Self {
            root,
            reference: isolated.reference.clone(),
            migration_reference: isolated.migration_reference.clone(),
            package_generation: Cell::new(0),
        };
        deployment.install_project();
        deployment.write_runtime(None);
        deployment
    }

    fn project(&self) -> PathBuf {
        self.root.path().join("project")
    }

    fn package(&self) -> PathBuf {
        self.root
            .path()
            .join(format!("package-{}", self.package_generation.get()))
    }

    fn install_project(&self) {
        let inputs = package_inputs(&self.project()).expect("the package inputs");
        let generation = self.package_generation.get() + 1;
        let output = self.root.path().join(format!("package-{generation}"));
        write_package_inputs(&output, &inputs, None).expect("the installed package");
        self.package_generation.set(generation);
    }

    fn runtime_path(&self) -> PathBuf {
        self.root.path().join("runtime.yaml")
    }

    fn write_runtime(&self, expected_digest: Option<&str>) {
        let jwks_name = format!("MESSAGING_JWKS_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
        let audit_name =
            format!("MESSAGING_AUDIT_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
        std::env::set_var(&jwks_name, static_jwks());
        std::env::set_var(&audit_name, "an-audit-master-secret-of-32-bytes!");
        let mut package = json!({"root": self.package()});
        if let Some(digest) = expected_digest {
            package["expectedDigest"] = json!(digest);
        }
        let runtime = json!({
            "apiVersion": registry_messaging_core::MESSAGING_RUNTIME_API_VERSION,
            "kind": registry_messaging_core::MESSAGING_RUNTIME_KIND,
        "identity": {"databaseId": "messaging-test"},
            "package": package,
            "listener": {"bind": free_port().to_string(), "tlsTermination": "development-loopback"},
            "secretProviders": {"environment": {}},
            "database": {
                "runtimeUrlRef": self.reference,
                "migrationUrlRef": self.migration_reference,
                "testOnlyPlaintext": true
            },
            "authentication": {"oidc": {
                "issuer": "https://identity.example.test",
                "audience": "urn:example:messaging",
                "jwksSource": {"type": "static", "documentRef": format!("secret:env/{jwks_name}")},
                "allowedClients": ["case-system", "operations-console"]
            }},
            "audit": {
                "path": self.root.path().join("audit").join("messaging.jsonl"),
                "hashKeyRef": format!("secret:env/{audit_name}")
            }
        });
        std::fs::write(
            self.runtime_path(),
            serde_norway::to_string(&runtime).unwrap(),
        )
        .unwrap();
    }

    fn config(&self) -> RuntimeConfig {
        RuntimeConfig::load(self.runtime_path()).expect("the runtime configuration")
    }

    fn loaded(&self) -> Package {
        load_package(&self.package())
            .expect("the deployment package")
            .package
    }

    /// Ship version 2 of the email template beside version 1, the way an
    /// adopter upgrades a template without touching the version in use.
    fn add_reminder_version_two(&self) {
        let project = self.project();
        let manifest = std::fs::read_to_string(project.join("messaging.yaml")).unwrap();
        let upgraded = manifest.replace(
            "  - id: appointment-reminder\n    version: \"1\"\n",
            "  - id: appointment-reminder\n    version: \"1\"\n  - id: appointment-reminder\n    version: \"2\"\n",
        );
        assert_ne!(
            manifest, upgraded,
            "the starter lists appointment-reminder 1"
        );
        std::fs::write(project.join("messaging.yaml"), upgraded).unwrap();
        let one = project.join("templates/appointment-reminder/1");
        let two = project.join("templates/appointment-reminder/2");
        copy_tree(&one, &two);
        for locale in ["en", "fr"] {
            let text = two.join(locale).join("text.j2");
            let source = std::fs::read_to_string(&text).unwrap();
            std::fs::write(&text, format!("[v2] {source}")).unwrap();
        }
        self.install_project();
        self.write_runtime(None);
    }

    async fn serve_error(&self) -> RuntimeError {
        tokio::time::timeout(
            Duration::from_secs(30),
            serve_from_path(
                self.runtime_path(),
                registry_messaging::dispatch::Transports::new(),
            ),
        )
        .await
        .expect("a refused start returns instead of serving")
        .expect_err("the runtime refuses to serve")
    }
}

fn render(package: &Package, version: &str, locale: &str) -> Value {
    let preview = package
        .preview(
            "appointment-reminder",
            version,
            &TemplatePreviewRequest {
                locale: locale.to_owned(),
                data: json!({"name": "Ada", "day": "2026-10-01", "office": "Central"}),
            },
        )
        .expect("the template renders");
    let mut value = serde_json::to_value(&preview).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("packageDigest")
        .expect("a preview names its package digest");
    value
}

async fn migrated(isolated: &Isolated) -> Deployment {
    let deployment = Deployment::new(isolated);
    migrate_from_path(deployment.runtime_path())
        .await
        .expect("the test schema migrations");
    deployment
}

#[tokio::test]
async fn startup_opens_the_audit_writer_before_serving() {
    let isolated = isolated_schema().await;
    let deployment = migrated(&isolated).await;
    let config = deployment.config();
    apply_package(&config, true).await.expect("apply");

    let app = registry_messaging::runtime::assemble(
        &config,
        registry_messaging::dispatch::Transports::new(),
    )
    .await
    .expect("assemble after opening the audit writer");
    let records: Vec<Value> = std::fs::read_to_string(
        config
            .audit
            .path
            .as_ref()
            .expect("an audit file destination"),
    )
    .expect("the startup journal")
    .lines()
    .map(|line| serde_json::from_str(line).unwrap())
    .collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["phase"], "response");
    assert_eq!(records[0]["record"]["event"], "messaging.runtime.started");
    drop(app);
}

#[tokio::test]
async fn plan_is_read_only_and_apply_records_once_and_is_idempotent() {
    let isolated = isolated_schema().await;
    let deployment = migrated(&isolated).await;
    let digest = deployment.loaded().digest().to_owned();

    let preview = activation_plan(&deployment.config())
        .await
        .expect("activation plan");
    assert_eq!(preview.package_digest, digest);
    assert_eq!(preview.active_digest, None);
    assert_eq!(preview.change, ActivationChange::Activate);
    assert!(isolated.ledger().await.is_empty());
    let operator_audit = match deployment
        .config()
        .audit
        .destination()
        .unwrap()
        .for_process("messagingctl")
        .unwrap()
    {
        AuditDestination::File(file) => file.path().to_owned(),
        _ => panic!("the test configures a file audit destination"),
    };
    assert!(
        !operator_audit.exists(),
        "a preview does not open or write the operator audit destination"
    );

    let applied = apply_package(&deployment.config(), true)
        .await
        .expect("apply");
    assert_eq!(applied.change, PackageChange::Activate);
    assert!(applied.applied);
    assert_eq!(isolated.ledger().await, std::slice::from_ref(&digest));
    let entries: Vec<Value> = std::fs::read_to_string(&operator_audit)
        .expect("the operator audit destination")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["phase"], "request");
    assert_eq!(
        entries[0]["record"]["event"],
        "messaging.package.activation.requested"
    );
    assert_eq!(entries[1]["phase"], "response");
    assert_eq!(
        entries[1]["record"]["event"],
        "messaging.package.activation.finished"
    );
    assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
    assert_eq!(entries[1]["record"]["applied"], true);

    let again = apply_package(&deployment.config(), true)
        .await
        .expect("a repeated apply");
    assert_eq!(again.active_digest.as_deref(), Some(digest.as_str()));
    assert_eq!(again.change, PackageChange::None);
    assert!(!again.applied);
    assert_eq!(isolated.ledger().await, [digest]);
    assert_eq!(
        std::fs::read_to_string(operator_audit)
            .unwrap()
            .lines()
            .count(),
        2,
        "an idempotent no-op writes no activation pair"
    );
}

#[tokio::test]
async fn apply_refuses_a_newer_schema_before_activation_and_audits_the_refusal() {
    let isolated = isolated_schema().await;
    let deployment = migrated(&isolated).await;
    isolated
        .admin
        .execute(
            &format!(
                "INSERT INTO {}.messaging_schema_migrations(version,applied_at) VALUES(99,now())",
                isolated.schema
            ),
            &[],
        )
        .await
        .expect("a schema version from a future release");

    let preview = activation_plan(&deployment.config())
        .await
        .expect("the future schema has an actionable plan refusal");
    assert_eq!(preview.refusals.len(), 1);
    assert_eq!(
        preview.refusals[0].code,
        "messagingctl.activation.schema-newer"
    );
    assert!(preview.refusals[0].message.contains("version 99"));

    let config = deployment.config();
    let refused = apply_activation(&config, &ApplyRequest::default())
        .await
        .expect_err("apply refuses a future schema");
    match refused {
        RuntimeError::Activation(ActivationError::Refused(refusals)) => {
            assert_eq!(refusals.len(), 1);
            assert_eq!(refusals[0].code, "messagingctl.activation.schema-newer");
        }
        other => panic!("expected a schema refusal, got {other}"),
    }
    assert!(isolated.ledger().await.is_empty());

    let versions: Vec<i64> = isolated
        .admin
        .query(
            &format!(
                "SELECT version FROM {}.messaging_schema_migrations ORDER BY version",
                isolated.schema
            ),
            &[],
        )
        .await
        .expect("the unchanged schema history")
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(versions, [1, 2, 99]);

    let operator_audit = match config
        .audit
        .destination()
        .unwrap()
        .for_process("messagingctl")
        .unwrap()
    {
        AuditDestination::File(file) => file.path().to_owned(),
        _ => panic!("the test configures a file audit destination"),
    };
    let entries: Vec<Value> = std::fs::read_to_string(operator_audit)
        .expect("the operator audit destination")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["phase"], "request");
    assert_eq!(entries[1]["phase"], "response");
    assert_eq!(entries[1]["record"]["outcome"], "refused");
    assert_eq!(
        entries[1]["record"]["refusals"],
        json!(["messagingctl.activation.schema-newer"])
    );
}

#[tokio::test]
async fn package_plan_ignores_a_refused_audit_destination_and_apply_refuses_before_effect() {
    let isolated = isolated_schema().await;
    let deployment = migrated(&isolated).await;
    let blocked_parent = deployment.root.path().join("audit-parent-is-a-file");
    std::fs::write(&blocked_parent, b"not a directory").unwrap();
    let mut config = deployment.config();
    config.audit.path = Some(blocked_parent.join("audit.jsonl"));

    let preview = activation_plan(&config)
        .await
        .expect("a preview does not open the audit destination");
    assert_eq!(preview.change, ActivationChange::Activate);
    assert!(isolated.ledger().await.is_empty());

    let refused = apply_package(&config, true)
        .await
        .expect_err("an applied activation requires the audit destination");
    assert!(
        matches!(refused, RuntimeError::AuditJournal(_)),
        "{refused}"
    );
    assert!(isolated.ledger().await.is_empty());
}

#[tokio::test]
async fn concurrent_applies_record_the_package_once() {
    let isolated = isolated_schema().await;
    let deployment = migrated(&isolated).await;
    let config = deployment.config();
    let (first, second) = tokio::join!(apply_package(&config, true), apply_package(&config, true));
    let results = [first, second];
    let recorded = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .filter(|apply| apply.applied)
        .count();
    assert_eq!(recorded, 1);
    for error in results.iter().filter_map(|result| result.as_ref().err()) {
        assert!(matches!(error, RuntimeError::AuditJournal(_)), "{error}");
    }
    assert_eq!(isolated.ledger().await.len(), 1);
}

#[tokio::test]
async fn apply_reports_the_active_digest_it_read_under_the_ledger_lock() {
    let isolated = isolated_schema().await;
    let deployment = migrated(&isolated).await;
    let config = deployment.config();
    let concurrent = format!("sha256:{}", "c".repeat(64));
    // Another activation holds the ledger lock and records a package the
    // apply has not seen when it first reads the ledger.
    isolated
        .admin
        .batch_execute(&format!(
            "BEGIN; SELECT pg_advisory_xact_lock({LEDGER_LOCK_KEY}); \
             INSERT INTO {}.messaging_activations \
               (activation_id,apply_order,package_digest,database_id,plan_kind,applied_at,role_mode) \
             VALUES (gen_random_uuid(),1,'{concurrent}','messaging-test','initial',now(),'single')",
            isolated.schema
        ))
        .await
        .unwrap();
    let apply = tokio::spawn({
        let config = config.clone();
        async move { apply_activation(&config, &ApplyRequest::default()).await }
    });
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let waiting: i64 = isolated
                .admin
                .query_one(
                    "SELECT count(*) FROM pg_locks \
                      WHERE locktype = 'advisory' AND NOT granted \
                        AND pg_backend_pid() = ANY (pg_blocking_pids(pid))",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            if waiting > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the apply waits for the ledger lock this connection holds");
    isolated.admin.batch_execute("COMMIT").await.unwrap();

    let applied = apply.await.unwrap().expect("apply");
    assert!(applied.recorded);
    assert_eq!(
        applied.activation.predecessor_package_digest.as_deref(),
        Some(concurrent.as_str())
    );
    let operator_audit = match config
        .audit
        .destination()
        .unwrap()
        .for_process("messagingctl")
        .unwrap()
    {
        AuditDestination::File(file) => file.path().to_owned(),
        _ => panic!("the test configures a file audit destination"),
    };
    let finished: Vec<Value> = std::fs::read_to_string(operator_audit)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|entry| entry["phase"] == "response")
        .collect();
    assert_eq!(finished.len(), 1);
    assert_eq!(
        finished[0]["record"]["predecessorPackageDigest"],
        concurrent.as_str()
    );
}

#[tokio::test]
async fn the_runtime_refuses_a_package_the_ledger_does_not_name_active() {
    let isolated = isolated_schema().await;
    let deployment = migrated(&isolated).await;
    let unapplied = deployment.serve_error().await;
    assert!(matches!(
        unapplied,
        RuntimeError::Activation(ActivationError::NotActivated)
    ));

    apply_package(&deployment.config(), true)
        .await
        .expect("apply");
    let applied = deployment.loaded().digest().to_owned();
    deployment.add_reminder_version_two();
    let edited = deployment.loaded().digest().to_owned();
    assert_ne!(applied, edited);
    let mismatch = deployment.serve_error().await;
    assert!(matches!(
        mismatch,
        RuntimeError::Activation(ActivationError::PackageNotActive)
    ));
    assert!(
        !deployment
            .config()
            .audit
            .path
            .as_ref()
            .expect("an audit file destination")
            .exists(),
        "a refused start writes no runtime audit record"
    );
}

#[tokio::test]
async fn a_pinned_digest_must_match_the_package_before_any_ledger_write() {
    let isolated = isolated_schema().await;
    let deployment = migrated(&isolated).await;
    let digest = deployment.loaded().digest().to_owned();

    deployment.write_runtime(Some(&format!("sha256:{}", "0".repeat(64))));
    match RuntimeConfig::load(deployment.runtime_path()) {
        Err(error @ RuntimeConfigError::Package(_)) => {
            assert_eq!(error.pointer(), "/package/expectedDigest");
            assert_eq!(error.code(), "messaging.package.digest-mismatch");
            // The refusal names the digest of the package found, never the
            // pinned value as written.
            let rendered = error.to_string();
            assert!(
                !rendered.contains(&format!("sha256:{}", "0".repeat(64))),
                "{rendered}"
            );
            assert!(rendered.contains(&digest), "{rendered}");
        }
        other => panic!("expected a digest mismatch, got {other:?}"),
    }
    assert!(isolated.ledger().await.is_empty());
    assert!(matches!(
        deployment.serve_error().await,
        RuntimeError::Config(RuntimeConfigError::Package(_))
    ));

    deployment.write_runtime(Some(&digest));
    let applied = apply_package(&deployment.config(), true)
        .await
        .expect("apply under a matching pin");
    assert!(applied.applied);
    assert_eq!(isolated.ledger().await, [digest]);
}

/// A template version is immutable content: once a package ships it, an
/// upgrade that adds a later version must not change what the earlier one
/// renders, while the ledger keeps both packages in order. Dispatch extends
/// this by asserting that a message accepted under version 1 still carries
/// these bytes.
#[tokio::test]
async fn a_template_version_renders_the_same_bytes_across_a_package_upgrade() {
    let isolated = isolated_schema().await;
    let deployment = migrated(&isolated).await;
    apply_package(&deployment.config(), true)
        .await
        .expect("apply the first package");
    let first = deployment.loaded();
    let before = [render(&first, "1", "en"), render(&first, "1", "fr")];

    deployment.add_reminder_version_two();
    let upgrade = apply_package(&deployment.config(), false)
        .await
        .expect("preview the upgrade");
    assert_eq!(upgrade.change, PackageChange::Activate);
    assert_eq!(upgrade.active_digest.as_deref(), Some(first.digest()));
    apply_package(&deployment.config(), true)
        .await
        .expect("apply the upgrade");
    let second = deployment.loaded();
    assert_eq!(
        isolated.ledger().await,
        [first.digest().to_owned(), second.digest().to_owned()]
    );

    let after = [render(&second, "1", "en"), render(&second, "1", "fr")];
    assert_eq!(
        serde_json::to_vec(&before).unwrap(),
        serde_json::to_vec(&after).unwrap()
    );
    let upgraded = render(&second, "2", "en");
    assert!(upgraded["parts"]["text"]
        .as_str()
        .unwrap()
        .starts_with("[v2] Hello Ada"));
    assert_eq!(upgraded["parts"]["subject"], before[0]["parts"]["subject"]);
}

#[tokio::test]
async fn split_role_activation_binds_identity_and_withholds_both_ledgers() {
    let (isolated, _migration_role, runtime_role) = isolated_split_schema().await;
    let deployment = Deployment::new(&isolated);
    let config = deployment.config();
    let applied = apply_activation(
        &config,
        &ApplyRequest {
            operator_reference: Some("change-42".to_owned()),
            backup_references: vec!["snapshot-2026-09-29".to_owned()],
        },
    )
    .await
    .expect("one transactional split-role activation");
    assert_eq!(applied.schema_versions_applied, [1, 2]);
    assert!(applied.recorded);
    assert_eq!(applied.activation.database_id, "messaging-test");
    assert_eq!(applied.activation.role_mode.as_str(), "split");
    assert!(applied
        .activation
        .operator_reference_hash
        .as_deref()
        .is_some_and(|value| value.starts_with("hmac-sha256:")));
    assert_eq!(
        applied.activation.backup_references,
        ["snapshot-2026-09-29"]
    );

    let privilege = isolated.admin.query_one(
        &format!(
            "SELECT has_table_privilege('{runtime_role}', '{schema}.messaging_activations', 'SELECT'), \
                    has_table_privilege('{runtime_role}', '{schema}.messaging_activations', 'INSERT'), \
                    has_table_privilege('{runtime_role}', '{schema}.messaging_schema_migrations', 'INSERT'), \
                    has_table_privilege('{runtime_role}', '{schema}.messaging_messages', 'INSERT')",
            schema = isolated.schema,
        ),
        &[],
    ).await.expect("runtime grants");
    assert_eq!(
        (
            privilege.get(0),
            privilege.get(1),
            privilege.get(2),
            privilege.get(3)
        ),
        (true, false, false, true)
    );

    let secrets = config.secret_resolver().expect("secrets");
    let runtime =
        PostgresStore::connect_runtime(&config.database, &secrets).expect("runtime store");
    registry_messaging::activation::check_runtime(
        &runtime,
        config.database_id(),
        deployment.loaded().digest(),
    )
    .await
    .expect("the activated runtime boundary");
    let wrong_identity = registry_messaging::activation::check_runtime(
        &runtime,
        "another-deployment",
        deployment.loaded().digest(),
    )
    .await
    .expect_err("the database identity is exact");
    assert!(matches!(
        wrong_identity,
        ActivationError::DatabaseIdMismatch
    ));

    isolated
        .admin
        .batch_execute(&format!(
            "GRANT INSERT ON {schema}.messaging_activations TO {runtime_role}",
            schema = isolated.schema,
        ))
        .await
        .expect("temporarily widen the runtime role");
    let widened = registry_messaging::activation::check_runtime(
        &runtime,
        config.database_id(),
        deployment.loaded().digest(),
    )
    .await
    .expect_err("a widened runtime role is refused");
    assert!(matches!(widened, ActivationError::RoleModeWeakened));

    isolated
        .admin
        .batch_execute(&format!(
            "REVOKE INSERT ON {schema}.messaging_activations FROM {runtime_role}; \
             REVOKE INSERT ON {schema}.messaging_messages FROM {runtime_role}",
            schema = isolated.schema,
        ))
        .await
        .expect("make runtime grants stale");
    let stale = registry_messaging::activation::check_runtime(
        &runtime,
        config.database_id(),
        deployment.loaded().digest(),
    )
    .await
    .expect_err("incomplete runtime grants are refused");
    assert!(matches!(stale, ActivationError::GrantsStale));

    isolated
        .admin
        .batch_execute(&format!(
            "REVOKE SELECT ON {schema}.messaging_activations FROM {runtime_role}",
            schema = isolated.schema,
        ))
        .await
        .expect("make the activation ledger unreadable");
    let unreadable = registry_messaging::activation::status(&runtime)
        .await
        .expect_err("status refuses an unreadable ledger");
    match unreadable {
        ActivationError::Refused(refusals) => assert_eq!(
            refusals[0].code,
            "messagingctl.activation.ledger-unreadable"
        ),
        other => panic!("expected a ledger refusal, got {other}"),
    }
}

/// Every entry the operator process wrote to its audit destination.
fn operator_audit_entries(config: &RuntimeConfig) -> Vec<Value> {
    let path = match config
        .audit
        .destination()
        .unwrap()
        .for_process("messagingctl")
        .unwrap()
    {
        AuditDestination::File(file) => file.path().to_owned(),
        _ => panic!("the test configures a file audit destination"),
    };
    std::fs::read_to_string(path)
        .expect("the operator audit destination")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn reapplying_the_active_package_over_stale_grants_records_the_repair() {
    let (isolated, _migration_role, runtime_role) = isolated_split_schema().await;
    let deployment = Deployment::new(&isolated);
    let config = deployment.config();
    let first = apply_activation(&config, &ApplyRequest::default())
        .await
        .expect("the initial split-role activation");
    assert!(first.recorded);

    isolated
        .admin
        .batch_execute(&format!(
            "REVOKE INSERT ON {schema}.messaging_messages FROM {runtime_role}",
            schema = isolated.schema,
        ))
        .await
        .expect("make runtime grants stale");
    let preview = activation_plan(&config)
        .await
        .expect("a plan over stale grants");
    assert_eq!(preview.change, ActivationChange::Activate);
    assert_eq!(preview.grants_current, Some(false));

    let repaired = apply_activation(&config, &ApplyRequest::default())
        .await
        .expect("a reapply restores the runtime grants");
    assert!(
        repaired.recorded,
        "restoring stale grants is a change the ledger records"
    );
    assert_ne!(
        repaired.activation.activation_id,
        first.activation.activation_id
    );
    assert_eq!(
        repaired.activation.predecessor_package_digest.as_deref(),
        Some(deployment.loaded().digest())
    );
    let digest = deployment.loaded().digest().to_owned();
    assert_eq!(isolated.ledger().await, [digest.clone(), digest.clone()]);

    let entries = operator_audit_entries(&config);
    assert_eq!(entries.len(), 4);
    assert_eq!(
        entries[2]["record"]["event"],
        "messaging.package.activation.requested"
    );
    assert_eq!(
        entries[3]["record"]["event"],
        "messaging.package.activation.finished"
    );
    assert_eq!(entries[3]["record"]["outcome"], "applied");
    assert_eq!(entries[3]["record"]["applied"], true);
    assert_eq!(
        entries[3]["record"]["activationId"],
        entries[2]["record"]["activationId"]
    );

    let secrets = config.secret_resolver().expect("secrets");
    let runtime =
        PostgresStore::connect_runtime(&config.database, &secrets).expect("runtime store");
    registry_messaging::activation::check_runtime(&runtime, config.database_id(), &digest)
        .await
        .expect("the repaired runtime boundary");
    let settled = activation_plan(&config).await.expect("a settled plan");
    assert_eq!(settled.change, ActivationChange::None);
}

#[tokio::test]
async fn an_unchanged_apply_answers_its_own_request_and_names_the_active_activation() {
    let isolated = isolated_schema().await;
    let deployment = migrated(&isolated).await;
    let config = deployment.config();
    let first = apply_activation(&config, &ApplyRequest::default())
        .await
        .expect("the initial activation");
    assert!(first.recorded);

    let again = apply_activation(&config, &ApplyRequest::default())
        .await
        .expect("a repeated activation");
    assert!(!again.recorded);
    assert_eq!(
        again.activation.activation_id,
        first.activation.activation_id
    );

    let entries = operator_audit_entries(&config);
    assert_eq!(entries.len(), 4);
    let (requested, finished) = (&entries[2], &entries[3]);
    assert_eq!(
        requested["record"]["event"],
        "messaging.package.activation.requested"
    );
    assert_eq!(finished["record"]["outcome"], "unchanged");
    assert_eq!(requested["correlation"], finished["correlation"]);
    assert_eq!(
        finished["record"]["activationId"], requested["record"]["activationId"],
        "the response answers the activation id its request announced"
    );
    assert_ne!(
        finished["record"]["activationId"],
        json!(first.activation.activation_id)
    );
    assert_eq!(
        finished["record"]["activeActivationId"],
        json!(first.activation.activation_id)
    );
}

#[tokio::test]
async fn a_post_migration_role_refusal_rolls_back_the_whole_activation_and_is_audited() {
    let (isolated, _migration_role, runtime_role) = isolated_split_schema().await;
    isolated
        .admin
        .batch_execute(&format!("ALTER ROLE {runtime_role} SUPERUSER"))
        .await
        .expect("make the runtime role too powerful");
    let deployment = Deployment::new(&isolated);
    let config = deployment.config();

    let refused = apply_activation(&config, &ApplyRequest::default())
        .await
        .expect_err("activation refuses a runtime superuser after checking its effective grants");
    match refused {
        RuntimeError::Activation(ActivationError::Refused(refusals)) => assert_eq!(
            refusals[0].code,
            "messagingctl.activation.role-mode-weakened"
        ),
        other => panic!("expected a role-boundary refusal, got {other}"),
    }

    let row = isolated
        .admin
        .query_one(
            &format!(
                "SELECT to_regclass('{schema}.messaging_schema_migrations')::text, \
                        to_regclass('{schema}.messaging_activations')::text",
                schema = isolated.schema,
            ),
            &[],
        )
        .await
        .expect("inspect the rolled-back schema");
    assert_eq!(row.get::<_, Option<String>>(0), None);
    assert_eq!(row.get::<_, Option<String>>(1), None);

    let operator_audit = match config
        .audit
        .destination()
        .unwrap()
        .for_process("messagingctl")
        .unwrap()
    {
        AuditDestination::File(file) => file.path().to_owned(),
        _ => panic!("the test configures a file audit destination"),
    };
    let entries: Vec<Value> = std::fs::read_to_string(operator_audit)
        .expect("the operator audit destination")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["phase"], "request");
    assert_eq!(entries[1]["phase"], "response");
    assert_eq!(entries[1]["record"]["outcome"], "refused");
}

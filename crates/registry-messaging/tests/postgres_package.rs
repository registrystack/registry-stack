// SPDX-License-Identifier: Apache-2.0

//! Database-backed package ledger tests: `messagingctl apply` previews and
//! records a package, the runtime serves only the package the ledger names
//! active, `package.expectedDigest` pins it, and a template version renders
//! the same bytes across a package upgrade that adds a new version.
//!
//! Every test runs in its own schema inside the database named by
//! `MESSAGING_TEST_DATABASE_URL`. A test binary that passes because its
//! database URL is absent is not database verification, so the variable is
//! required: without it every test in this file fails on the spot.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use registry_messaging::config::{RuntimeConfig, RuntimeConfigError};
use registry_messaging::package::load_package;
use registry_messaging::runtime::{
    apply_package, migrate_from_path, serve_from_path, PackageChange, RuntimeError,
};
use registry_messaging_core::{Package, TemplatePreviewRequest};
use serde_json::{json, Value};
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

impl Isolated {
    /// Every digest the ledger recorded, oldest first.
    async fn ledger(&self) -> Vec<String> {
        self.admin
            .query(
                &format!(
                    "SELECT package_digest FROM {}.messaging_package_ledger ORDER BY sequence",
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
}

impl Deployment {
    fn new(isolated: &Isolated) -> Self {
        let root = tempfile::tempdir().expect("a runtime directory");
        let starter =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/messaging/examples/starter");
        let package = root.path().join("package");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::copy(
            starter.join("messaging.yaml"),
            package.join("messaging.yaml"),
        )
        .unwrap();
        copy_tree(&starter.join("templates"), &package.join("templates"));
        copy_tree(&starter.join("providers"), &package.join("providers"));
        let deployment = Self {
            root,
            reference: isolated.reference.clone(),
        };
        deployment.write_runtime(None);
        deployment
    }

    fn package(&self) -> PathBuf {
        self.root.path().join("package")
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
            "package": package,
            "listener": {"bind": free_port().to_string(), "tlsTermination": "development-loopback"},
            "secretProviders": {"environment": {}},
            "database": {
                "runtimeUrlRef": self.reference,
                "migrationUrlRef": self.reference,
                "testOnlyPlaintext": true
            },
            "authentication": {"oidc": {
                "issuer": "https://identity.example.test",
                "audience": "urn:example:messaging",
                "jwksSource": {"kind": "static", "documentRef": format!("secret:env/{jwks_name}")},
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
        let package = self.package();
        let manifest = std::fs::read_to_string(package.join("messaging.yaml")).unwrap();
        let upgraded = manifest.replace(
            "  - id: appointment-reminder\n    version: \"1\"\n",
            "  - id: appointment-reminder\n    version: \"1\"\n  - id: appointment-reminder\n    version: \"2\"\n",
        );
        assert_ne!(
            manifest, upgraded,
            "the starter lists appointment-reminder 1"
        );
        std::fs::write(package.join("messaging.yaml"), upgraded).unwrap();
        let one = package.join("templates/appointment-reminder/1");
        let two = package.join("templates/appointment-reminder/2");
        copy_tree(&one, &two);
        for locale in ["en", "fr"] {
            let text = two.join(locale).join("text.j2");
            let source = std::fs::read_to_string(&text).unwrap();
            std::fs::write(&text, format!("[v2] {source}")).unwrap();
        }
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
        .expect("messaging migrate");
    deployment
}

#[tokio::test]
async fn startup_publishes_every_pending_outbox_batch_before_its_start_record() {
    let isolated = isolated_schema().await;
    let deployment = migrated(&isolated).await;
    let config = deployment.config();
    apply_package(&config, true).await.expect("apply");

    // More than one publication batch must precede the restart marker.
    for sequence in 0..125 {
        let event_id = Uuid::new_v4();
        let record = json!({
            "event": "messaging.test.committed-before-restart",
            "eventId": event_id.to_string(),
            "sequence": sequence
        });
        isolated.admin.execute(
            &format!("INSERT INTO {}.messaging_audit_outbox (event_id, audit_record) VALUES ($1, $2)", isolated.schema),
            &[&event_id, &record],
        ).await.expect("a committed pre-restart audit event");
    }

    let app = registry_messaging::runtime::assemble(
        &config,
        registry_messaging::dispatch::Transports::new(),
    )
    .await
    .expect("assemble after recovering the pending outbox");
    let records: Vec<Value> = std::fs::read_to_string(&config.audit.path)
        .expect("the startup journal")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 126);
    for (sequence, record) in records.iter().take(125).enumerate() {
        assert_eq!(record["record"]["sequence"], sequence);
    }
    assert_eq!(records[125]["record"]["event"], "messaging.runtime.started");
    let pending: i64 = isolated
        .admin
        .query_one(
            &format!(
                "SELECT count(*) FROM {}.messaging_audit_outbox WHERE published_at IS NULL",
                isolated.schema
            ),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(pending, 0);
    drop(app);
}

#[tokio::test]
async fn apply_previews_by_default_records_once_and_is_idempotent() {
    let isolated = isolated_schema().await;
    let deployment = migrated(&isolated).await;
    let digest = deployment.loaded().digest().to_owned();

    let preview = apply_package(&deployment.config(), false)
        .await
        .expect("apply preview");
    assert_eq!(preview.package_digest, digest);
    assert_eq!(preview.active_digest, None);
    assert_eq!(preview.change, PackageChange::Activate);
    assert!(!preview.applied);
    assert!(isolated.ledger().await.is_empty());

    let applied = apply_package(&deployment.config(), true)
        .await
        .expect("apply");
    assert_eq!(applied.change, PackageChange::Activate);
    assert!(applied.applied);
    assert_eq!(isolated.ledger().await, std::slice::from_ref(&digest));

    let again = apply_package(&deployment.config(), true)
        .await
        .expect("a repeated apply");
    assert_eq!(again.active_digest.as_deref(), Some(digest.as_str()));
    assert_eq!(again.change, PackageChange::None);
    assert!(!again.applied);
    assert_eq!(isolated.ledger().await, [digest]);
}

#[tokio::test]
async fn concurrent_applies_record_the_package_once() {
    let isolated = isolated_schema().await;
    let deployment = migrated(&isolated).await;
    let config = deployment.config();
    let (first, second) = tokio::join!(apply_package(&config, true), apply_package(&config, true));
    let recorded = [first.expect("apply"), second.expect("apply")]
        .iter()
        .filter(|apply| apply.applied)
        .count();
    assert_eq!(recorded, 1);
    assert_eq!(isolated.ledger().await.len(), 1);
}

#[tokio::test]
async fn the_runtime_refuses_a_package_the_ledger_does_not_name_active() {
    let isolated = isolated_schema().await;
    let deployment = migrated(&isolated).await;
    assert!(
        matches!(
            deployment.serve_error().await,
            RuntimeError::PackageNotApplied { .. }
        ),
        "an unapplied package is refused"
    );

    apply_package(&deployment.config(), true)
        .await
        .expect("apply");
    let applied = deployment.loaded().digest().to_owned();
    deployment.add_reminder_version_two();
    let edited = deployment.loaded().digest().to_owned();
    assert_ne!(applied, edited);
    match deployment.serve_error().await {
        RuntimeError::PackageLedgerMismatch { active, package } => {
            assert_eq!(active, applied);
            assert_eq!(package, edited);
        }
        other => panic!("expected a ledger mismatch, got {other}"),
    }
    assert!(
        !deployment.root.path().join("audit").exists(),
        "a refused start writes no audit record"
    );
}

#[tokio::test]
async fn a_pinned_digest_must_match_the_package_before_any_ledger_write() {
    let isolated = isolated_schema().await;
    let deployment = migrated(&isolated).await;
    let digest = deployment.loaded().digest().to_owned();

    deployment.write_runtime(Some(&format!("sha256:{}", "0".repeat(64))));
    match RuntimeConfig::load(deployment.runtime_path()) {
        Err(RuntimeConfigError::PackageDigestMismatch { expected, actual }) => {
            assert_eq!(expected, format!("sha256:{}", "0".repeat(64)));
            assert_eq!(actual, digest);
        }
        other => panic!("expected a digest mismatch, got {other:?}"),
    }
    assert!(isolated.ledger().await.is_empty());
    assert!(matches!(
        deployment.serve_error().await,
        RuntimeError::Config(RuntimeConfigError::PackageDigestMismatch { .. })
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

// SPDX-License-Identifier: Apache-2.0

//! Database-backed store tests: migrations applied concurrently and
//! repeatedly, caller-scoped idempotency keys, readiness against the applied
//! schema, a served
//! runtime answering `/ready` from a real PostgreSQL deployment, and the
//! `messaging` binary keeping its operational logs off a `stdout` audit
//! destination. The package ledger has its own suite, `postgres_package`.
//!
//! Every test runs in its own schema inside the database named by
//! `MESSAGING_TEST_DATABASE_URL`. A test binary that passes because its
//! database URL is absent is not database verification, so the variable is
//! required: without it every test in this file fails on the spot.

mod support;

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use axum::http::StatusCode;
use registry_messaging::activation::ApplyRequest;
use registry_messaging::config::{DatabaseConfig, RuntimeConfig};
use registry_messaging::package::{package_inputs, write_package_inputs};
use registry_messaging::runtime::{apply_activation, serve_from_path};
use registry_messaging::store::{PostgresStore, StoreError};
use registry_messaging_client::{MessagingClient, MessagingClientConfig};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_testing::verify_postgres_schema_equivalence;
use serde_json::json;
use support::{
    email_submission, sender_token, sender_token_for, Harness, ISSUER, SENDER_PRINCIPAL,
};
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

async fn install_catalog_probe(isolated: &Isolated) {
    isolated
        .admin
        .batch_execute(&format!(
            r#"
            CREATE TABLE {schema}.catalog_probe (
                id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                state text NOT NULL DEFAULT 'pending',
                source text NOT NULL DEFAULT 'domain.literal',
                changed_at timestamptz,
                CONSTRAINT catalog_probe_state CHECK (state IN ('pending', 'done'))
            );
            CREATE INDEX catalog_probe_pending_idx
                ON {schema}.catalog_probe (id) WHERE state = 'pending';
            CREATE FUNCTION {schema}.catalog_probe_touch() RETURNS trigger
                LANGUAGE plpgsql AS $function$
                BEGIN
                    NEW.changed_at := transaction_timestamp();
                    RETURN NEW;
                END
                $function$;
            CREATE TRIGGER catalog_probe_touch
                BEFORE UPDATE ON {schema}.catalog_probe
                FOR EACH ROW EXECUTE FUNCTION {schema}.catalog_probe_touch();
            CREATE FUNCTION {schema}.catalog_probe_increment(value integer) RETURNS integer
                LANGUAGE sql IMMUTABLE STRICT
                AS $function$ SELECT value + 1 $function$;
            CREATE VIEW {schema}.catalog_probe_pending AS
                SELECT id, source FROM {schema}.catalog_probe WHERE state = 'pending';
            ALTER TABLE {schema}.catalog_probe ENABLE ROW LEVEL SECURITY;
            ALTER TABLE {schema}.catalog_probe FORCE ROW LEVEL SECURITY;
            CREATE POLICY catalog_probe_pending_policy ON {schema}.catalog_probe
                USING (state = 'pending') WITH CHECK (state = 'pending');
            "#,
            schema = isolated.schema,
        ))
        .await
        .expect("install the catalog comparison probe");
}

async fn equivalent_catalog_probes() -> (Isolated, Isolated) {
    let left = isolated_schema().await;
    let right = isolated_schema().await;
    install_catalog_probe(&left).await;
    install_catalog_probe(&right).await;
    verify_postgres_schema_equivalence(&left.admin, &left.schema, &right.admin, &right.schema)
        .await
        .expect("independently installed equivalent schemas have one catalog");
    (left, right)
}

async fn assert_catalog_difference(mutation: &str, expected: &str) {
    let (left, right) = equivalent_catalog_probes().await;
    right
        .admin
        .batch_execute(&mutation.replace("{schema}", &right.schema))
        .await
        .expect("mutate one comparison schema");
    let report =
        verify_postgres_schema_equivalence(&left.admin, &left.schema, &right.admin, &right.schema)
            .await
            .expect_err("the catalog mutation is visible");
    assert!(report.contains(expected), "{report}");
}

#[tokio::test]
async fn postgres_catalog_comparison_detects_migration_shape_and_security_drift() {
    for (mutation, expected) in [
        (
            "ALTER TABLE {schema}.catalog_probe DROP CONSTRAINT catalog_probe_state",
            "catalog_probe_state",
        ),
        ("DROP INDEX {schema}.catalog_probe_pending_idx", "catalog_probe_pending_idx"),
        (
            "DROP TRIGGER catalog_probe_touch ON {schema}.catalog_probe",
            "catalog_probe_touch",
        ),
        (
            "DROP FUNCTION {schema}.catalog_probe_increment(integer)",
            "catalog_probe_increment",
        ),
        (
            "CREATE OR REPLACE VIEW {schema}.catalog_probe_pending AS SELECT id, source FROM {schema}.catalog_probe WHERE state = 'done'",
            "catalog_probe_pending",
        ),
        (
            "ALTER SEQUENCE {schema}.catalog_probe_id_seq INCREMENT BY 2",
            "catalog_probe_id_seq",
        ),
        (
            "ALTER TABLE {schema}.catalog_probe NO FORCE ROW LEVEL SECURITY",
            "forceRowSecurity",
        ),
        (
            "DROP POLICY catalog_probe_pending_policy ON {schema}.catalog_probe",
            "catalog_probe_pending_policy",
        ),
        (
            "GRANT USAGE ON SCHEMA {schema} TO PUBLIC",
            "namespace",
        ),
    ] {
        assert_catalog_difference(mutation, expected).await;
    }

    let (left, right) = equivalent_catalog_probes().await;
    left.admin
        .batch_execute(&format!(
            "ALTER TABLE {}.catalog_probe ALTER COLUMN source SET DEFAULT '{}'",
            left.schema, left.schema
        ))
        .await
        .expect("put the left schema name in a domain literal");
    right
        .admin
        .batch_execute(&format!(
            "ALTER TABLE {}.catalog_probe ALTER COLUMN source SET DEFAULT '{}'",
            right.schema, right.schema
        ))
        .await
        .expect("put the right schema name in a domain literal");
    let report =
        verify_postgres_schema_equivalence(&left.admin, &left.schema, &right.admin, &right.schema)
            .await
            .expect_err("schema qualifier normalization never rewrites domain literals");
    assert!(report.contains("default"), "{report}");
    assert!(report.contains(&left.schema), "{report}");
    assert!(report.contains(&right.schema), "{report}");
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
    assert_eq!(applied_versions(&isolated).await, [100, 101]);

    first
        .migrate()
        .await
        .expect("a repeated migration applies nothing");
    assert_eq!(applied_versions(&isolated).await, [100, 101]);

    let runtime = PostgresStore::connect_runtime(&config, &secrets).expect("a runtime store");
    runtime.ready().await.expect("a migrated store is ready");
}

#[tokio::test]
async fn a_pre_1_0_schema_is_refused_by_migrate_and_readiness() {
    let isolated = isolated_schema().await;
    let config = database(&isolated.reference);
    let store = PostgresStore::connect_migration(&config, &secrets()).expect("a migration store");
    isolated
        .admin
        .batch_execute(&format!(
            "CREATE TABLE {schema}.messaging_schema_migrations (
                     version bigint PRIMARY KEY CHECK (version > 0),
                     applied_at timestamptz NOT NULL
                 );
                 INSERT INTO {schema}.messaging_schema_migrations(version, applied_at)
                     VALUES (1, now());",
            schema = isolated.schema,
        ))
        .await
        .expect("seed the ledger a pre-1.0 release left");

    let refusal = store
        .migrate()
        .await
        .expect_err("a pre-1.0 schema is never upgraded in place");
    assert!(matches!(
        &refusal,
        StoreError::Pre1_0Schema { versions } if versions == &vec![1]
    ));
    assert!(refusal.to_string().contains("fresh database"), "{refusal}");
    assert!(matches!(
        store.ready().await,
        Err(StoreError::Pre1_0Schema { versions }) if versions == vec![1]
    ));
    assert_eq!(applied_versions(&isolated).await, [1]);
}

/// The baseline v0.42.0 and v0.43.0 shipped and recorded as version 100,
/// byte for byte. Its dispatch job shape accepted a `leased` row without a
/// lease expiry; version 101 replaces that shape.
const RELEASED_BASELINE: &str = include_str!("../migrations/0100_messaging.sql");

/// A queued message as v0.43.0 accepted it: the message row, its payload,
/// and its pending dispatch job.
const QUEUED_MESSAGE: &str = "
    INSERT INTO messaging_messages (
        message_id, submitter_issuer, submitter_subject, access_profile,
        sender_profile, channel, provider, sender, recipient_kind,
        content_source, package_digest, maximum_attempts,
        initial_retry_delay_ms, maximum_retry_delay_ms, on_uncertain,
        provider_idempotent_submit, accepted_at, expires_at
    ) VALUES (
        '00000000-0000-0000-0000-000000000101', 'https://issuer.example',
        'sender', 'senders', 'email', 'email', 'relay', 'from@example.org',
        'email', 'direct',
        'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        3, 1000, 1000, 'hold', false, now(), now() + interval '1 day'
    );
    INSERT INTO messaging_message_payloads (message_id, recipient, text_body)
        VALUES ('00000000-0000-0000-0000-000000000101', 'to@example.org', 'body');
    INSERT INTO messaging_dispatch_jobs (
        message_id, part, generation, state, attempt, next_attempt_at
    ) VALUES (
        '00000000-0000-0000-0000-000000000101', 'message', 1, 'pending', 0, now()
    );";

/// Lease the queued job without a lease expiry, a row the dispatcher never
/// writes and the corrected shape refuses.
const LEASE_WITHOUT_EXPIRY: &str = "
    UPDATE messaging_dispatch_jobs
       SET state = 'leased', attempt = 1, next_attempt_at = NULL,
           attempt_started_at = now(), lease_token = gen_random_uuid(),
           lease_expires_at = NULL
     WHERE message_id = '00000000-0000-0000-0000-000000000101'";

#[tokio::test]
async fn a_version_100_database_migrates_forward_keeps_its_queue_and_refuses_a_lease_without_expiry(
) {
    let isolated = isolated_schema().await;
    let config = database(&isolated.reference);
    let store = PostgresStore::connect_migration(&config, &secrets()).expect("a migration store");
    isolated
        .admin
        .batch_execute(&format!(
            "SET search_path TO {schema};
             CREATE TABLE messaging_schema_migrations (
                 version bigint PRIMARY KEY CHECK (version > 0),
                 applied_at timestamptz NOT NULL
             );
             {RELEASED_BASELINE}
             INSERT INTO messaging_schema_migrations(version, applied_at) VALUES (100, now());
             {QUEUED_MESSAGE}",
            schema = isolated.schema,
        ))
        .await
        .expect("a database v0.43.0 installed, with one queued message");
    isolated
        .admin
        .batch_execute(&format!("BEGIN; {LEASE_WITHOUT_EXPIRY}; ROLLBACK;"))
        .await
        .expect("the released shape accepts a lease without an expiry");
    assert!(
        matches!(store.ready().await, Err(StoreError::SchemaVersion)),
        "a version 100 database is not ready before apply migrates it"
    );

    store.migrate().await.expect("version 100 migrates forward");
    assert_eq!(applied_versions(&isolated).await, [100, 101]);
    let queued = isolated
        .admin
        .query_one(
            "SELECT state, attempt, generation FROM messaging_dispatch_jobs \
             WHERE message_id = '00000000-0000-0000-0000-000000000101'",
            &[],
        )
        .await
        .expect("the queued job survives the migration");
    assert_eq!(queued.get::<_, String>(0), "pending");
    assert_eq!(queued.get::<_, i16>(1), 0);
    assert_eq!(queued.get::<_, i64>(2), 1);

    let refused = isolated
        .admin
        .batch_execute(LEASE_WITHOUT_EXPIRY)
        .await
        .expect_err("the migrated shape refuses a lease without an expiry");
    let refused = refused.as_db_error().expect("a database refusal");
    assert_eq!(
        refused.code(),
        &tokio_postgres::error::SqlState::CHECK_VIOLATION
    );
    assert_eq!(refused.constraint(), Some("messaging_dispatch_jobs_shape"));

    PostgresStore::connect_runtime(&config, &secrets())
        .expect("a runtime store")
        .ready()
        .await
        .expect("the migrated store is ready");
}

/// The activation path `messagingctl apply` takes migrates a version 100
/// database forward inside its own transaction, the path an operator upgrading
/// from v0.43.0 runs, rather than the store's standalone migrator.
#[tokio::test]
async fn apply_migrates_a_version_100_database_forward_and_keeps_its_queue() {
    let isolated = isolated_schema().await;
    isolated
        .admin
        .batch_execute(&format!(
            "SET search_path TO {schema};
             CREATE TABLE messaging_schema_migrations (
                 version bigint PRIMARY KEY CHECK (version > 0),
                 applied_at timestamptz NOT NULL
             );
             {RELEASED_BASELINE}
             INSERT INTO messaging_schema_migrations(version, applied_at) VALUES (100, now());
             {QUEUED_MESSAGE}
             RESET search_path;",
            schema = isolated.schema,
        ))
        .await
        .expect("a database v0.43.0 installed, with one queued message");
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .expect("a runtime directory");
    write_runtime(
        root.path(),
        &isolated.reference,
        free_port(),
        free_port(),
        file_audit(root.path()),
    );
    let config =
        RuntimeConfig::load(root.path().join("runtime.yaml")).expect("the runtime configuration");

    let applied = apply_activation(&config, &ApplyRequest::default())
        .await
        .expect("messagingctl apply migrates version 100 forward");
    assert_eq!(applied.schema_versions_applied, [101]);
    assert!(applied.recorded);
    assert_eq!(applied_versions(&isolated).await, [100, 101]);
    let queued = isolated
        .admin
        .query_one(
            &format!(
                "SELECT state, attempt, generation FROM {}.messaging_dispatch_jobs \
                 WHERE message_id = '00000000-0000-0000-0000-000000000101'",
                isolated.schema
            ),
            &[],
        )
        .await
        .expect("the queued job survives the migration");
    assert_eq!(queued.get::<_, String>(0), "pending");
    assert_eq!(queued.get::<_, i16>(1), 0);
    assert_eq!(queued.get::<_, i64>(2), 1);
    let refused = isolated
        .admin
        .batch_execute(&format!(
            "SET search_path TO {}; {LEASE_WITHOUT_EXPIRY}",
            isolated.schema
        ))
        .await
        .expect_err("the migrated shape refuses a lease without an expiry");
    let refused = refused.as_db_error().expect("a database refusal");
    assert_eq!(
        refused.code(),
        &tokio_postgres::error::SqlState::CHECK_VIOLATION
    );
    assert_eq!(refused.constraint(), Some("messaging_dispatch_jobs_shape"));

    let again = apply_activation(&config, &ApplyRequest::default())
        .await
        .expect("a repeated apply");
    assert!(again.schema_versions_applied.is_empty());
    assert!(!again.recorded);
    PostgresStore::connect_runtime(&config.database, &secrets())
        .expect("a runtime store")
        .ready()
        .await
        .expect("the migrated store is ready");
}

/// The migrated dispatch job table is exactly the shape the dispatch core
/// declares: every core column, constraint and index exists with the same
/// definition. Messaging adds its own foreign key and part constraint and
/// its own indexes beside them, never a different definition of a core
/// one.
#[tokio::test]
async fn the_migrated_job_table_is_exactly_the_dispatch_core_shape() {
    let isolated = isolated_schema().await;
    PostgresStore::connect_migration(&database(&isolated.reference), &secrets())
        .expect("a migration store")
        .migrate()
        .await
        .expect("the migrations");
    let core = format!("{}_core", isolated.schema);
    let table = registry_platform_dispatch::postgres::JobTable::new(
        &core,
        registry_messaging::dispatch::JOB_TABLE,
        "message_id",
        "part",
    )
    .expect("the core job table");
    isolated
        .admin
        .batch_execute(&format!(
            "CREATE SCHEMA {core}; {}",
            table.create_statements().join("\n")
        ))
        .await
        .expect("a fresh core job table");

    let migrated = job_table_catalog(&isolated.admin, &isolated.schema).await;
    let declared = job_table_catalog(&isolated.admin, &core).await;
    assert_eq!(migrated.columns, declared.columns, "the job table columns");
    for (name, definition) in &declared.constraints {
        assert_eq!(
            migrated.constraints.get(name),
            Some(definition),
            "constraint {name}"
        );
    }
    for (name, definition) in &declared.indexes {
        assert_eq!(migrated.indexes.get(name), Some(definition), "index {name}");
    }
}

struct JobTableCatalog {
    columns: Vec<(String, String, String, Option<String>)>,
    constraints: std::collections::BTreeMap<String, String>,
    indexes: std::collections::BTreeMap<String, String>,
}

async fn job_table_catalog(admin: &tokio_postgres::Client, schema: &str) -> JobTableCatalog {
    let table = registry_messaging::dispatch::JOB_TABLE;
    let columns = admin
        .query(
            "SELECT column_name::text, data_type::text, is_nullable::text, column_default::text \
             FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 \
             ORDER BY ordinal_position",
            &[&schema, &table],
        )
        .await
        .expect("the job table columns")
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect();
    let relation = format!("{schema}.{table}");
    let constraints = admin
        .query(
            "SELECT conname::text, pg_get_constraintdef(oid) FROM pg_constraint \
             WHERE conrelid = $1::text::regclass",
            &[&relation],
        )
        .await
        .expect("the job table constraints")
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    let indexes = admin
        .query(
            "SELECT indexname::text, replace(indexdef, $1 || '.', '') FROM pg_indexes \
             WHERE schemaname = $1 AND tablename = $2",
            &[&schema, &table],
        )
        .await
        .expect("the job table indexes")
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    JobTableCatalog {
        columns,
        constraints,
        indexes,
    }
}

#[tokio::test]
async fn a_fresh_schema_uses_only_the_shared_package_activation_ledger() {
    let isolated = isolated_schema().await;
    let store = PostgresStore::connect_migration(&database(&isolated.reference), &secrets())
        .expect("a migration store");
    store.migrate().await.expect("the fresh schema migrations");

    let ledgers = isolated
        .admin
        .query_one(
            &format!(
                "SELECT to_regclass('{schema}.legacy_messaging_package_ledger') IS NULL, \
                        to_regclass('{schema}.messaging_activations') IS NOT NULL",
                schema = isolated.schema,
            ),
            &[],
        )
        .await
        .expect("the fresh schema's package activation relations");
    assert!(
        ledgers.get::<_, bool>(0),
        "the unused legacy ledger is absent"
    );
    assert!(
        ledgers.get::<_, bool>(1),
        "the shared activation ledger exists"
    );
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
            "INSERT INTO {}.messaging_schema_migrations(version, applied_at) VALUES (199, now())",
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

/// The audit block that writes the journal to a file under `root`.
fn file_audit(root: &Path) -> serde_json::Value {
    json!({"path": root.join("audit").join("messaging.jsonl")})
}

fn write_runtime(
    root: &Path,
    database_reference: &str,
    public: SocketAddr,
    metrics: SocketAddr,
    audit: serde_json::Value,
) {
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let package = root.join("package");
    std::fs::write(
        project.join("messaging.yaml"),
        serde_norway::to_string(&json!({
            "apiVersion": registry_messaging_core::MESSAGING_PROJECT_API_VERSION,
            "kind": registry_messaging_core::MESSAGING_PROJECT_KIND,
            "project": {"id": "operations", "version": "1"},
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
    let inputs = package_inputs(&project).expect("the authored package inputs");
    write_package_inputs(&package, &inputs, None).expect("the installed package");

    let jwks_name = format!("MESSAGING_JWKS_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    let audit_name = format!("MESSAGING_AUDIT_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&jwks_name, static_jwks());
    std::env::set_var(&audit_name, "an-audit-master-secret-of-32-bytes!");
    let mut audit = audit;
    audit["hashKeyRef"] = json!(format!("secret:env/{audit_name}"));
    let runtime = json!({
        "apiVersion": registry_messaging_core::MESSAGING_RUNTIME_API_VERSION,
        "kind": registry_messaging_core::MESSAGING_RUNTIME_KIND,
        "identity": {"databaseId": "messaging-test"},
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
            "jwksSource": {"type": "static", "documentRef": format!("secret:env/{jwks_name}")},
            "allowedClients": ["operations-console"]
        }},
        "audit": audit
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
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .expect("a runtime directory");
    let public = free_port();
    let metrics = free_port();
    write_runtime(
        root.path(),
        &isolated.reference,
        public,
        metrics,
        file_audit(root.path()),
    );
    let runtime_config = root.path().join("runtime.yaml");

    let config = RuntimeConfig::load(&runtime_config).expect("the runtime configuration");
    apply_activation(&config, &ApplyRequest::default())
        .await
        .expect("messagingctl apply");
    let served = tokio::spawn(serve_from_path(
        runtime_config.clone(),
        registry_messaging::dispatch::Transports::new(),
    ));

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

/// A `stdout` audit destination carries audit entries alone: the binary's
/// operational log goes to stderr, so a strict JSON Lines collector reading
/// stdout never meets a log record.
#[tokio::test]
async fn a_stdout_audit_destination_never_carries_operational_logs() {
    let isolated = isolated_schema().await;
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .expect("a runtime directory");
    let public = free_port();
    let metrics = free_port();
    write_runtime(
        root.path(),
        &isolated.reference,
        public,
        metrics,
        json!({"destination": "stdout"}),
    );
    let runtime_config = root.path().join("runtime.yaml");
    let config = RuntimeConfig::load(&runtime_config).expect("the runtime configuration");
    apply_activation(&config, &ApplyRequest::default())
        .await
        .expect("messagingctl apply");

    // The secrets the configuration names are this process's environment,
    // which the binary inherits.
    let mut served = Command::new(env!("CARGO_BIN_EXE_messaging"))
        .arg("--runtime-config")
        .arg(&runtime_config)
        .arg("serve")
        .env("MESSAGING_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("messaging serve starts");
    let mut ready = None;
    // A freshly linked binary can take seconds to start on its first run.
    for _ in 0..400 {
        ready = get(public, "/ready").await;
        if ready.is_some() || served.try_wait().expect("the child state").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    served.kill().expect("stop messaging serve");
    let output = served.wait_with_output().expect("the served output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        ready,
        Some(200),
        "the runtime did not become ready: {stderr}"
    );
    assert!(
        stderr.contains("serving Registry Messaging"),
        "the operational log reaches stderr: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.contains("messaging.runtime.started"),
        "the audit entry reaches stdout: {stdout}"
    );
    for line in stdout.lines() {
        let entry: serde_json::Value = serde_json::from_str(line).expect("a JSON Lines entry");
        assert!(
            !line.contains("serving Registry Messaging") && entry.get("level").is_none(),
            "stdout carried a log record: {line}"
        );
    }
}

/// A spent key is bound to the verified caller, independent of another caller's key.
#[tokio::test]
async fn the_runtime_scopes_spent_keys_to_the_verified_caller() {
    let harness = Harness::start().await;
    let sender = sender_token();
    let submission = email_submission();
    let accepted = harness.submit(&sender, "same-key", &submission).await;
    assert_eq!(accepted.0, StatusCode::ACCEPTED, "{}", accepted.1);
    assert_eq!(
        harness.submit(&sender, "same-key", &submission).await,
        accepted
    );
    let other = harness
        .submit(&sender_token_for("another-sender"), "same-key", &submission)
        .await;
    assert_eq!(other.0, StatusCode::ACCEPTED, "{}", other.1);
    assert_ne!(accepted.1["id"], other.1["id"]);
    let mut changed = submission;
    changed["correlationId"] = json!("different-body");
    let refused = harness.submit(&sender, "same-key", &changed).await;
    assert_eq!(refused.0, StatusCode::CONFLICT);
    assert_eq!(refused.1["code"], "idempotency.key-reused");
    let row = harness.isolated.admin.query_one(
        "SELECT submitter_issuer, submitter_subject FROM messaging_idempotency WHERE message_id = $1::text::uuid",
        &[&accepted.1["id"].as_str().unwrap()]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), ISSUER);
    assert_eq!(row.get::<_, String>(1), SENDER_PRINCIPAL);
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        2
    );
}

#[tokio::test]
async fn the_dispatch_job_shape_refuses_a_lease_without_an_expiry() {
    let isolated = isolated_schema().await;
    let store = PostgresStore::connect_migration(&database(&isolated.reference), &secrets())
        .expect("a migration store");
    store.migrate().await.expect("the fresh schema migrations");
    // A copy with the job table's checks and without its foreign key, so one
    // row exercises the shape check alone.
    isolated
        .admin
        .batch_execute(&format!(
            "CREATE TABLE {schema}.shape_probe
                 (LIKE {schema}.messaging_dispatch_jobs
                  INCLUDING DEFAULTS INCLUDING CONSTRAINTS);",
            schema = isolated.schema,
        ))
        .await
        .expect("copy the dispatch job checks");
    let leased = |expiry: &str| {
        format!(
            "INSERT INTO {schema}.shape_probe
                 (message_id, part, generation, state, attempt,
                  attempt_started_at, lease_expires_at, lease_token)
             VALUES (gen_random_uuid(), 'message', 1, 'leased', 1,
                     transaction_timestamp(), {expiry}, gen_random_uuid())",
            schema = isolated.schema,
        )
    };
    let error = isolated
        .admin
        .batch_execute(&leased("NULL"))
        .await
        .expect_err("a leased job without a lease expiry is refused");
    let database = error.as_db_error().expect("a database refusal");
    assert_eq!(
        database.code(),
        &tokio_postgres::error::SqlState::CHECK_VIOLATION
    );
    assert_eq!(database.constraint(), Some("messaging_dispatch_jobs_shape"));
    isolated
        .admin
        .batch_execute(&leased("transaction_timestamp() + interval '1 minute'"))
        .await
        .expect("the same lease with an expiry is admitted");
}

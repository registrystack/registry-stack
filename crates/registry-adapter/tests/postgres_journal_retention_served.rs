// SPDX-License-Identifier: Apache-2.0

//! Journal retention through the real Adapter binary: a served deployment,
//! read-only or write, deletes journal events older than
//! `audit.retentionDays` and keeps the ones inside the window, and a
//! runtime role that cannot run those deletes is refused at startup.
//! Absence of `ADAPTER_TEST_DATABASE_URL` is a failure, never a skip.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use registry_adapter::journal::MAX_RETENTION_BATCH;
use registry_platform_testing::{access_token_test_key, jwks_from_private_jwk};
use served_harness::upstream::UpstreamDouble;
use served_harness::{Served, AUDIENCE, ISSUER, PASSWORD, USERNAME};

/// Exactly 32 bytes, the cursor key length.
const CURSOR_KEY: &str = "synthetic-cursor-key-0123456789!";
const RUNTIME_PASSWORD: &str = "synthetic-runtime-password";

/// More expired rows than one retention batch removes, so the sweep has to
/// drain a backlog. The harness deployment keeps 90 days.
fn seed_expired_and_in_window_rows() -> String {
    let expired = MAX_RETENTION_BATCH + 1;
    format!(
        "INSERT INTO adapter_journal_events \
             (event_kind, exchange_id, operation, caller_ref, route_id, occurred_at) \
         SELECT 'exchangeCreated', 'expired-' || g, 'records-get', 'synthetic-caller', \
                'seeded', now() - interval '91 days' - g * interval '1 millisecond' \
         FROM generate_series(1, {expired}) AS g; \
         INSERT INTO adapter_journal_events \
             (event_kind, exchange_id, operation, caller_ref, route_id, occurred_at) \
         VALUES ('exchangeCreated', 'in-window', 'records-get', 'synthetic-caller', \
                 'seeded', now() - interval '89 days');"
    )
}

async fn connect(database: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(database, tokio_postgres::NoTls)
        .await
        .expect("connect the journal schema");
    tokio::spawn(connection);
    client
}

async fn execute(database: &str, sql: &str) {
    connect(database)
        .await
        .batch_execute(sql)
        .await
        .expect("run the statement");
}

async fn seeded_exchange_ids(database: &str) -> Vec<String> {
    connect(database)
        .await
        .query(
            "SELECT exchange_id FROM adapter_journal_events \
             WHERE route_id = 'seeded' ORDER BY exchange_id",
            &[],
        )
        .await
        .expect("read the journal")
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect()
}

/// Migrate a fresh schema through one deployment, then stop it, so no
/// running sweeper sees the rows a test seeds afterwards.
async fn migrated_schema(upstream: &UpstreamDouble, project: &Path, runtime_id: &str) -> String {
    let migrating =
        Served::start_for_deployment(&upstream.url(""), project, runtime_id, None).await;
    let database = migrating.database.clone();
    drop(migrating);
    database
}

async fn seed(database: &str) {
    execute(database, &seed_expired_and_in_window_rows()).await;
    assert_eq!(
        seeded_exchange_ids(database).await.len(),
        usize::try_from(MAX_RETENTION_BATCH).expect("the batch fits usize") + 2
    );
}

/// Wait until only the in-window seeded row remains.
async fn await_retention(database: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let remaining = seeded_exchange_ids(database).await;
        if remaining == ["in-window"] {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "expired journal events outlived audit.retentionDays: {} seeded rows remain",
            remaining.len()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Seed a stopped deployment's schema, then start a second over it: its
/// first retention tick runs at startup and must drain the backlog.
async fn assert_served_retention(project: &Path, first_id: &str, second_id: &str) {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(&upstream, project, first_id).await;
    seed(&database).await;
    let serving =
        Served::start_for_deployment(&upstream.url(""), project, second_id, Some(&database)).await;
    await_retention(&serving.database).await;
}

#[tokio::test]
async fn a_read_only_deployment_deletes_journal_events_past_audit_retention() {
    assert_served_retention(
        &Served::govstack_project(),
        "govstack-retention-east",
        "govstack-retention-west",
    )
    .await;
}

#[tokio::test]
async fn a_write_deployment_deletes_journal_events_past_audit_retention() {
    assert_served_retention(
        &Served::example_project(),
        "tracker-retention-east",
        "tracker-retention-west",
    )
    .await;
}

/// One `adapter` process whose runtime and migration roles differ.
struct SplitRoles {
    child: Child,
    port: u16,
    _directory: tempfile::TempDir,
}

impl Drop for SplitRoles {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl SplitRoles {
    /// Serve the read-only GovStack project, migrating as the test
    /// database's own role and serving as `runtime_url`'s role.
    fn spawn(upstream_url: &str, migration_url: &str, runtime_url: &str) -> Self {
        let key = access_token_test_key(jsonwebtoken::Algorithm::ES256);
        let jwks = jwks_from_private_jwk(&key).to_string();
        let port = TcpListener::bind("127.0.0.1:0")
            .expect("bind a free loopback port")
            .local_addr()
            .expect("local address")
            .port();
        let directory = tempfile::tempdir().expect("a scratch directory");
        let runtime = directory.path().join("runtime.yaml");
        std::fs::write(
            &runtime,
            format!(
                r#"apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: govstack-split-roles
endpoints:
  - endpoint: tracker
    baseUrl: {upstream_url}
    credential:
      type: basic
      usernameRef: secret:env/TEST_UPSTREAM_USERNAME
      passwordRef: secret:env/TEST_UPSTREAM_PASSWORD
listener:
  bind: 127.0.0.1:{port}
database:
  runtimeUrlRef: secret:env/TEST_DB_RUNTIME_URL
  migrationUrlRef: secret:env/TEST_DB_MIGRATION_URL
  testOnlyPlaintext: true
oidc:
  issuer: {ISSUER}
  audience: {AUDIENCE}
  allowInsecureHttp: true
  jwksSource:
    type: static
    documentRef: secret:env/TEST_JWKS
allowedClients:
  - synthetic-client
allowedPrivateCidrs:
  - 192.168.0.0/16
audit:
  retentionDays: 90
idempotency:
  responseRetentionSeconds: 86400
cursorKeyRef: secret:env/TEST_CURSOR_KEY
"#
            ),
        )
        .expect("write the runtime config");
        let project = Served::govstack_project();
        let mut command = Command::new(env!("CARGO_BIN_EXE_adapter"));
        command
            .args(["serve", "--runtime-config"])
            .arg(&runtime)
            .arg("--project")
            .arg(&project);
        if !project.join("pack.yaml").exists() {
            command.arg("--pack").arg(Served::example_pack());
        }
        if !project.join("profile.yaml").exists() {
            command.arg("--profile").arg(Served::govstack_profile());
        }
        let child = command
            .env("TEST_UPSTREAM_USERNAME", USERNAME)
            .env("TEST_UPSTREAM_PASSWORD", PASSWORD)
            .env("TEST_DB_MIGRATION_URL", migration_url)
            .env("TEST_DB_RUNTIME_URL", runtime_url)
            .env("TEST_JWKS", &jwks)
            .env("TEST_CURSOR_KEY", CURSOR_KEY)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the adapter binary starts");
        Self {
            child,
            port,
            _directory: directory,
        }
    }

    /// The stderr of an adapter that refuses to start; panics when it
    /// listens, or never exits.
    fn refusal(mut self) -> String {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().expect("poll the adapter") {
                assert!(!status.success(), "the adapter exited successfully");
                let mut stderr = String::new();
                if let Some(mut pipe) = self.child.stderr.take() {
                    pipe.read_to_string(&mut stderr).expect("read stderr");
                }
                return stderr;
            }
            assert!(
                TcpStream::connect(("127.0.0.1", self.port)).is_err(),
                "the adapter started serving"
            );
            assert!(Instant::now() < deadline, "the adapter never exited");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn wait_until_listening(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().expect("poll the adapter") {
                let mut stderr = String::new();
                if let Some(mut pipe) = self.child.stderr.take() {
                    pipe.read_to_string(&mut stderr).expect("read stderr");
                }
                panic!("the adapter exited early ({status}): {stderr}");
            }
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
            }
            assert!(Instant::now() < deadline, "the adapter never listened");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// `database` with its user and password replaced by `role`'s.
fn as_role(database: &str, role: &str) -> String {
    let (scheme, rest) = database
        .split_once("://")
        .expect("the test database URL has a scheme");
    let (_, host) = rest
        .split_once('@')
        .expect("the test database URL names its user");
    format!("{scheme}://{role}:{RUNTIME_PASSWORD}@{host}")
}

#[tokio::test]
async fn a_runtime_role_without_delete_is_refused_and_insert_select_delete_serves() {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(&upstream, &Served::govstack_project(), "govstack-grants").await;
    let schema: String = connect(&database)
        .await
        .query_one("SELECT current_schema()", &[])
        .await
        .expect("read the migrated schema")
        .get(0);
    let role = format!("{schema}_runtime");
    execute(
        &database,
        &format!(
            "CREATE ROLE {role} LOGIN PASSWORD '{RUNTIME_PASSWORD}'; \
             GRANT USAGE ON SCHEMA {schema} TO {role}; \
             GRANT SELECT ON adapter_schema_migrations TO {role}; \
             GRANT INSERT, SELECT ON adapter_journal_events TO {role};"
        ),
    )
    .await;
    seed(&database).await;
    let runtime_url = as_role(&database, &role);

    let stderr = SplitRoles::spawn(&upstream.url(""), &database, &runtime_url).refusal();
    assert!(
        stderr.contains("the runtime role lacks DELETE on adapter_journal_events"),
        "{stderr}"
    );
    assert_eq!(
        seeded_exchange_ids(&database).await.len(),
        usize::try_from(MAX_RETENTION_BATCH).expect("the batch fits usize") + 2,
        "a refused deployment deletes nothing"
    );

    execute(
        &database,
        &format!("GRANT DELETE ON adapter_journal_events TO {role};"),
    )
    .await;
    let mut serving = SplitRoles::spawn(&upstream.url(""), &database, &runtime_url);
    serving.wait_until_listening();
    await_retention(&database).await;
    drop(serving);
    execute(
        &database,
        &format!("DROP OWNED BY {role}; DROP ROLE {role};"),
    )
    .await;
}

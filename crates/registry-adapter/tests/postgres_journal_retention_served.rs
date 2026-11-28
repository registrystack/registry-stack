// SPDX-License-Identifier: Apache-2.0

//! Journal retention through the real Adapter binary: a served deployment,
//! read-only or write, deletes journal events older than
//! `audit.retentionDays` and keeps the ones inside the window. The same
//! suite covers the runtime role's grants: a split role starts with none and
//! ends with exactly the privileges its deployment requires, a single role
//! issues no grant, a runtime URL that does not connect stops startup before
//! any grant, and a grant the migration role cannot make stops it with the cause.
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
        Self::spawn_project(
            upstream_url,
            migration_url,
            runtime_url,
            &Served::govstack_project(),
            None,
            "tracker",
        )
    }

    /// Serve `project` under `profile`, its one source endpoint `endpoint`
    /// pointed at `upstream_url`, with split migration and runtime roles.
    fn spawn_project(
        upstream_url: &str,
        migration_url: &str,
        runtime_url: &str,
        project: &Path,
        profile: Option<&Path>,
        endpoint: &str,
    ) -> Self {
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
  - endpoint: {endpoint}
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
        let mut command = Command::new(env!("CARGO_BIN_EXE_adapter"));
        command
            .args(["serve", "--runtime-config"])
            .arg(&runtime)
            .arg("--project")
            .arg(project);
        if !project.join("pack.yaml").exists() {
            command.arg("--pack").arg(Served::example_pack());
        }
        if let Some(profile) = profile.filter(|_| !project.join("profile.yaml").exists()) {
            command.arg("--profile").arg(profile);
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

/// A login role the test creates in the shared database, dropped with its
/// owned objects when the test ends.
async fn create_login_role(database: &str, role: &str) {
    execute(
        database,
        &format!("CREATE ROLE {role} LOGIN PASSWORD '{RUNTIME_PASSWORD}';"),
    )
    .await;
}

async fn drop_role(database: &str, role: &str) {
    execute(
        database,
        &format!("DROP OWNED BY {role}; DROP ROLE {role};"),
    )
    .await;
}

async fn current_schema(database: &str) -> String {
    connect(database)
        .await
        .query_one("SELECT current_schema()", &[])
        .await
        .expect("read the migrated schema")
        .get(0)
}

#[tokio::test]
async fn a_split_runtime_role_with_no_grants_is_granted_what_it_needs_and_runs_retention() {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(&upstream, &Served::govstack_project(), "govstack-grants").await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    create_login_role(&database, &role).await;
    seed(&database).await;
    let runtime_url = as_role(&database, &role);

    let mut serving = SplitRoles::spawn(&upstream.url(""), &database, &runtime_url);
    serving.wait_until_listening();
    await_retention(&database).await;
    drop(serving);
    drop_role(&database, &role).await;
}

/// The privileges `role` holds on every table of `schema`, by table, for the
/// seven table privileges PostgreSQL defines. Tables with none are omitted.
async fn table_privileges(
    database: &str,
    schema: &str,
    role: &str,
) -> std::collections::BTreeMap<String, Vec<String>> {
    let rows = connect(database)
        .await
        .query(
            "SELECT c.relname, p.privilege \
             FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', \
                                     'REFERENCES', 'TRIGGER']) AS p(privilege) \
             WHERE n.nspname = $1 AND c.relkind IN ('r', 'p') \
               AND has_table_privilege($2, c.oid, p.privilege) \
             ORDER BY c.relname, p.privilege",
            &[&schema, &role],
        )
        .await
        .expect("read the role's table privileges");
    let mut held = std::collections::BTreeMap::<String, Vec<String>>::new();
    for row in rows {
        held.entry(row.get(0)).or_default().push(row.get(1));
    }
    held
}

/// Every role that holds a privilege on a table or sequence of `schema` or on
/// the schema itself without owning it, by name, with `PUBLIC` for the
/// pseudo-role. A grantee that may pass the privilege on reads
/// `<name> WITH GRANT OPTION`. Unlike `has_table_privilege`, this reads the
/// ACLs, so a grant to `PUBLIC` is not mistaken for a grant to one role.
async fn acl_grantees(database: &str, schema: &str) -> std::collections::BTreeSet<String> {
    connect(database)
        .await
        .query(
            "SELECT (CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END) \
                    || (CASE WHEN a.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END) \
             FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             CROSS JOIN LATERAL aclexplode(c.relacl) a \
             WHERE n.nspname = $1 AND c.relkind IN ('r', 'p', 'S') AND a.grantee <> c.relowner \
             UNION \
             SELECT (CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END) \
                    || (CASE WHEN a.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END) \
             FROM pg_namespace n \
             CROSS JOIN LATERAL aclexplode(n.nspacl) a \
             WHERE n.nspname = $1 AND a.grantee <> n.nspowner",
            &[&schema],
        )
        .await
        .expect("read the ACL grantees")
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect()
}

fn expected(grants: &[(&str, &[&str])]) -> std::collections::BTreeMap<String, Vec<String>> {
    grants
        .iter()
        .map(|(table, privileges)| {
            let mut privileges: Vec<String> = privileges.iter().map(|p| (*p).to_owned()).collect();
            privileges.sort();
            ((*table).to_owned(), privileges)
        })
        .collect()
}

/// Serve `project` with a split runtime role that starts with no grants, and
/// assert the role ends with exactly `grants` and `USAGE` (not `CREATE`) on
/// the schema.
async fn assert_serve_grants_exactly(
    project: &Path,
    profile: Option<&Path>,
    endpoint: &str,
    deployment: &str,
    grants: &[(&str, &[&str])],
) {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(&upstream, &Served::govstack_project(), deployment).await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    create_login_role(&database, &role).await;
    assert!(
        table_privileges(&database, &schema, &role).await.is_empty(),
        "the role starts with no table privilege"
    );
    let runtime_url = as_role(&database, &role);
    let mut serving = SplitRoles::spawn_project(
        &upstream.url(""),
        &database,
        &runtime_url,
        project,
        profile,
        endpoint,
    );
    serving.wait_until_listening();
    assert_eq!(
        table_privileges(&database, &schema, &role).await,
        expected(grants),
        "the runtime role holds exactly the privileges the deployment requires"
    );
    let schema_privileges = connect(&database)
        .await
        .query_one(
            "SELECT has_schema_privilege($1, $2, 'USAGE'), has_schema_privilege($1, $2, 'CREATE')",
            &[&role, &schema],
        )
        .await
        .expect("read the schema privileges");
    assert_eq!(
        acl_grantees(&database, &schema).await,
        std::collections::BTreeSet::from([role.clone()]),
        "the runtime role is the only grantee, and PUBLIC gained nothing"
    );
    assert!(schema_privileges.get::<_, bool>(0), "USAGE on the schema");
    assert!(
        !schema_privileges.get::<_, bool>(1),
        "no CREATE on the schema"
    );
    drop(serving);
    drop_role(&database, &role).await;
}

const EVERY_DEPLOYMENT: [(&str, &[&str]); 2] = [
    ("adapter_journal_events", &["INSERT", "SELECT", "DELETE"]),
    ("adapter_schema_migrations", &["SELECT"]),
];
const WRITE: [(&str, &[&str]); 2] = [
    (
        "adapter_idempotency_entries",
        &["SELECT", "INSERT", "UPDATE", "DELETE"],
    ),
    (
        "adapter_idempotency_resumes",
        &["SELECT", "INSERT", "UPDATE", "DELETE"],
    ),
];
const RECOVERY: [(&str, &[&str]); 2] = [
    (
        "adapter_idempotency_async_artifacts",
        &["SELECT", "INSERT", "UPDATE"],
    ),
    ("adapter_idempotency_resume_bindings", &["SELECT", "INSERT"]),
];

#[tokio::test]
async fn serve_grants_exactly_the_required_privileges() {
    // A read-only deployment: the journal and the migration ledger only.
    assert_serve_grants_exactly(
        &Served::govstack_project(),
        None,
        "tracker",
        "grants-read",
        &EVERY_DEPLOYMENT,
    )
    .await;

    // A synchronous write adds idempotent claims and response custody, and
    // no artifact fence.
    let write: Vec<_> = EVERY_DEPLOYMENT.iter().chain(&WRITE).copied().collect();
    assert_serve_grants_exactly(
        &Served::example_project(),
        Some(&Served::example_profile()),
        "tracker",
        "grants-write",
        &write,
    )
    .await;

    // A resumable write adds the artifact fence and the resume bindings.
    let resumable: Vec<_> = EVERY_DEPLOYMENT
        .iter()
        .chain(&WRITE)
        .chain(&RECOVERY)
        .copied()
        .collect();
    let recovery_project = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/adapter/examples/facade-recovery");
    assert_serve_grants_exactly(
        &recovery_project,
        Some(&Served::example_profile()),
        "reference",
        "grants-resume",
        &resumable,
    )
    .await;
}

#[tokio::test]
async fn a_runtime_url_that_cannot_connect_fails_startup_before_any_grant() {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(&upstream, &Served::govstack_project(), "grants-ghost").await;
    let schema = current_schema(&database).await;
    // The runtime URL names a role that does not exist.
    let runtime_url = as_role(&database, &format!("{schema}_absent"));

    let stderr = SplitRoles::spawn(&upstream.url(""), &database, &runtime_url).refusal();
    assert!(stderr.contains("database runtime"), "{stderr}");
    assert!(!stderr.contains(RUNTIME_PASSWORD), "{stderr}");
    assert_eq!(
        acl_grantees(&database, &schema).await,
        std::collections::BTreeSet::new(),
        "no grant is made before the runtime credential works: {stderr}"
    );
}

#[tokio::test]
async fn a_runtime_url_naming_public_is_refused_and_grants_nothing() {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(&upstream, &Served::govstack_project(), "grants-public").await;
    let schema = current_schema(&database).await;
    let runtime_url = as_role(&database, "public");

    let stderr = SplitRoles::spawn(&upstream.url(""), &database, &runtime_url).refusal();
    assert!(!stderr.contains(RUNTIME_PASSWORD), "{stderr}");
    assert_eq!(
        acl_grantees(&database, &schema).await,
        std::collections::BTreeSet::new(),
        "no grant reached PUBLIC or any other role: {stderr}"
    );
}

#[tokio::test]
async fn a_runtime_role_with_members_is_granted_nothing_and_refused() {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(&upstream, &Served::govstack_project(), "grants-members").await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    let member = format!("{schema}_member");
    create_login_role(&database, &role).await;
    create_login_role(&database, &member).await;
    execute(&database, &format!("GRANT {role} TO {member};")).await;
    let runtime_url = as_role(&database, &role);

    let stderr = SplitRoles::spawn(&upstream.url(""), &database, &runtime_url).refusal();
    assert!(stderr.contains("the runtime role lacks"), "{stderr}");
    assert_eq!(
        acl_grantees(&database, &schema).await,
        std::collections::BTreeSet::new(),
        "an automatic grant is never made to a role others inherit from: {stderr}"
    );
    drop_role(&database, &member).await;
    drop_role(&database, &role).await;
}

/// The role that created the runtime role administers it, as in a database
/// built by `adapterctl provision`, so its membership does not stop the grant.
#[tokio::test]
async fn a_runtime_role_whose_only_member_administers_it_is_granted_its_privileges() {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(&upstream, &Served::govstack_project(), "grants-admin").await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    let administrator = format!("{schema}_admin");
    create_login_role(&database, &role).await;
    create_login_role(&database, &administrator).await;
    execute(
        &database,
        &format!("GRANT {role} TO {administrator} WITH ADMIN OPTION;"),
    )
    .await;
    let runtime_url = as_role(&database, &role);

    let mut serving = SplitRoles::spawn(&upstream.url(""), &database, &runtime_url);
    serving.wait_until_listening();
    assert_eq!(
        acl_grantees(&database, &schema).await,
        std::collections::BTreeSet::from([role.clone()]),
        "the runtime role received the grants"
    );
    drop(serving);
    drop_role(&database, &administrator).await;
    drop_role(&database, &role).await;
}

/// Create the runtime role the way `adapterctl provision` does: a
/// `LOGIN CREATEROLE` administrator creates it with `createrole_self_grant`
/// set to `set,inherit`. PostgreSQL then records two membership rows for the
/// administrator in the runtime role, one that carries ADMIN OPTION and one
/// that carries SET and INHERIT.
async fn create_provisioned_runtime_role(database: &str, runtime: &str, administrator: &str) {
    execute(
        database,
        &format!("CREATE ROLE {administrator} LOGIN CREATEROLE PASSWORD '{RUNTIME_PASSWORD}';"),
    )
    .await;
    execute(
        &as_role(database, administrator),
        &format!(
            "SET createrole_self_grant = 'set,inherit'; \
             CREATE ROLE {runtime} LOGIN PASSWORD '{RUNTIME_PASSWORD}';"
        ),
    )
    .await;
    let rows = connect(database)
        .await
        .query(
            "SELECT m.admin_option FROM pg_auth_members m \
             JOIN pg_roles r ON r.oid = m.roleid \
             JOIN pg_roles a ON a.oid = m.member \
             WHERE r.rolname = $1 AND a.rolname = $2 ORDER BY m.admin_option",
            &[&runtime, &administrator],
        )
        .await
        .expect("read the administrator's memberships");
    assert_eq!(
        rows.iter()
            .map(|row| row.get::<_, bool>(0))
            .collect::<Vec<_>>(),
        [false, true],
        "the administrator holds one ADMIN row and one plain row in the runtime role"
    );
}

/// The layout `adapterctl provision` builds, with the CREATEROLE administrator
/// as the runtime role's only member, still receives its grants. Pinned on
/// the two-row layout: a per-row test of ADMIN OPTION would count the
/// administrator's plain row and refuse every provisioned database.
#[tokio::test]
async fn a_provisioned_runtime_role_is_granted_its_privileges() {
    let upstream = UpstreamDouble::start();
    let database =
        migrated_schema(&upstream, &Served::govstack_project(), "grants-provisioned").await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    let administrator = format!("{schema}_admin");
    create_provisioned_runtime_role(&database, &role, &administrator).await;
    let runtime_url = as_role(&database, &role);

    let mut serving = SplitRoles::spawn(&upstream.url(""), &database, &runtime_url);
    serving.wait_until_listening();
    assert_eq!(
        acl_grantees(&database, &schema).await,
        std::collections::BTreeSet::from([role.clone()]),
        "the runtime role received the grants"
    );
    drop(serving);
    drop_role(&database, &role).await;
    drop_role(&database, &administrator).await;
}

/// The provisioned layout plus one member that does not administer the role:
/// that member would inherit the grants, so none is made.
#[tokio::test]
async fn a_provisioned_runtime_role_with_a_plain_member_is_granted_nothing_and_refused() {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(&upstream, &Served::govstack_project(), "grants-mixed").await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    let administrator = format!("{schema}_admin");
    let member = format!("{schema}_member");
    create_provisioned_runtime_role(&database, &role, &administrator).await;
    create_login_role(&database, &member).await;
    execute(&database, &format!("GRANT {role} TO {member};")).await;
    let runtime_url = as_role(&database, &role);

    let stderr = SplitRoles::spawn(&upstream.url(""), &database, &runtime_url).refusal();
    assert!(stderr.contains("the runtime role lacks"), "{stderr}");
    assert_eq!(
        acl_grantees(&database, &schema).await,
        std::collections::BTreeSet::new(),
        "a plain member blocks the grant even beside an administrator: {stderr}"
    );
    drop_role(&database, &member).await;
    drop_role(&database, &role).await;
    drop_role(&database, &administrator).await;
}

/// A member that holds ADMIN OPTION but has members of its own reaches the
/// runtime role through them, so it does not make the grant safe.
#[tokio::test]
async fn an_administrator_with_members_of_its_own_blocks_the_grant() {
    let upstream = UpstreamDouble::start();
    let database =
        migrated_schema(&upstream, &Served::govstack_project(), "grants-admin-chain").await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    let administrator = format!("{schema}_admin");
    let behind = format!("{schema}_behind");
    create_login_role(&database, &role).await;
    create_login_role(&database, &administrator).await;
    create_login_role(&database, &behind).await;
    execute(
        &database,
        &format!(
            "GRANT {role} TO {administrator} WITH ADMIN OPTION; \
             GRANT {administrator} TO {behind};"
        ),
    )
    .await;
    let runtime_url = as_role(&database, &role);

    let stderr = SplitRoles::spawn(&upstream.url(""), &database, &runtime_url).refusal();
    assert!(stderr.contains("the runtime role lacks"), "{stderr}");
    assert_eq!(
        acl_grantees(&database, &schema).await,
        std::collections::BTreeSet::new(),
        "an administrator that others inherit from blocks the grant: {stderr}"
    );
    drop_role(&database, &behind).await;
    drop_role(&database, &administrator).await;
    drop_role(&database, &role).await;
}

#[tokio::test]
async fn a_migration_role_that_does_not_own_the_tables_fails_startup_and_grants_nothing() {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(&upstream, &Served::govstack_project(), "grants-nonowner").await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    let migrator = format!("{schema}_migrator");
    create_login_role(&database, &role).await;
    create_login_role(&database, &migrator).await;
    // The migrator can use and read the schema but owns nothing and holds no
    // grant option, so PostgreSQL turns each of its GRANTs into a warning.
    execute(
        &database,
        &format!(
            "GRANT USAGE, CREATE ON SCHEMA {schema} TO {migrator}; \
             GRANT ALL ON ALL TABLES IN SCHEMA {schema} TO {migrator};"
        ),
    )
    .await;
    let migration_url = as_role(&database, &migrator);
    let runtime_url = as_role(&database, &role);

    let stderr = SplitRoles::spawn(&upstream.url(""), &migration_url, &runtime_url).refusal();
    assert!(
        stderr.contains("INSERT, SELECT, DELETE on adapter_journal_events"),
        "{stderr}"
    );
    assert!(
        stderr.contains("the migration role does not own"),
        "{stderr}"
    );
    assert!(!stderr.contains(RUNTIME_PASSWORD), "{stderr}");
    assert!(
        !acl_grantees(&database, &schema).await.contains(&role),
        "a failed grant leaves nothing behind: {stderr}"
    );
    drop_role(&database, &migrator).await;
    drop_role(&database, &role).await;
}

/// The migration role owns the journal tables but not the idempotency ones, so
/// the grants on the first succeed and the check on the second fails: nothing
/// stays granted.
#[tokio::test]
async fn a_migration_role_that_owns_only_some_tables_grants_nothing() {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(&upstream, &Served::govstack_project(), "grants-partial").await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    let migrator = format!("{schema}_migrator");
    create_login_role(&database, &role).await;
    create_login_role(&database, &migrator).await;
    execute(
        &database,
        &format!(
            "GRANT USAGE, CREATE ON SCHEMA {schema} TO {migrator}; \
             GRANT ALL ON ALL TABLES IN SCHEMA {schema} TO {migrator}; \
             ALTER TABLE {schema}.adapter_journal_events OWNER TO {migrator}; \
             ALTER TABLE {schema}.adapter_schema_migrations OWNER TO {migrator};"
        ),
    )
    .await;
    let migration_url = as_role(&database, &migrator);
    let runtime_url = as_role(&database, &role);

    let stderr = SplitRoles::spawn_project(
        &upstream.url(""),
        &migration_url,
        &runtime_url,
        &Served::example_project(),
        Some(&Served::example_profile()),
        "tracker",
    )
    .refusal();
    assert!(
        stderr.contains("on adapter_idempotency_entries"),
        "{stderr}"
    );
    assert!(
        !acl_grantees(&database, &schema).await.contains(&role),
        "the grants on the tables the migration role owns were rolled back: {stderr}"
    );
    drop_role(&database, &migrator).await;
    drop_role(&database, &role).await;
}

/// A start that finds every privilege in place writes no catalog row.
#[tokio::test]
async fn a_restart_with_every_grant_in_place_writes_no_grant() {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(&upstream, &Served::govstack_project(), "grants-restart").await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    create_login_role(&database, &role).await;
    let runtime_url = as_role(&database, &role);
    let catalog_versions = || async {
        connect(&database)
            .await
            .query(
                "SELECT c.relname::text, c.xmin::text FROM pg_class c \
                 JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE n.nspname = $1 AND c.relkind IN ('r', 'p') \
                 UNION ALL SELECT n.nspname::text, n.xmin::text FROM pg_namespace n \
                 WHERE n.nspname = $1 \
                 ORDER BY 1",
                &[&schema],
            )
            .await
            .expect("read the catalog row versions")
            .iter()
            .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
            .collect::<Vec<_>>()
    };

    let mut first = SplitRoles::spawn(&upstream.url(""), &database, &runtime_url);
    first.wait_until_listening();
    drop(first);
    let granted = catalog_versions().await;
    let mut second = SplitRoles::spawn(&upstream.url(""), &database, &runtime_url);
    second.wait_until_listening();
    drop(second);
    assert_eq!(
        catalog_versions().await,
        granted,
        "a restart rewrote a table or schema ACL"
    );
    drop_role(&database, &role).await;
}

/// The advisory-lock key the grant step takes, so two replicas starting
/// together do not rewrite the same catalog rows at once.
const GRANT_LOCK_KEY: i64 = 0x6164_6170_5f67_6e74;

#[tokio::test]
async fn the_grant_step_waits_for_the_grant_lock() {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(&upstream, &Served::govstack_project(), "grants-lock").await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    create_login_role(&database, &role).await;
    let runtime_url = as_role(&database, &role);
    let holder = connect(&database).await;
    holder
        .query_one("SELECT pg_advisory_lock($1)", &[&GRANT_LOCK_KEY])
        .await
        .expect("take the grant lock");

    let mut serving = SplitRoles::spawn(&upstream.url(""), &database, &runtime_url);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        serving
            .child
            .try_wait()
            .expect("poll the adapter")
            .is_none(),
        "the adapter exited while the grant lock was held"
    );
    assert!(
        TcpStream::connect(("127.0.0.1", serving.port)).is_err(),
        "the adapter served while the grant lock was held"
    );
    assert_eq!(
        acl_grantees(&database, &schema).await,
        std::collections::BTreeSet::new(),
        "the adapter granted before it held the grant lock"
    );
    holder
        .query_one("SELECT pg_advisory_unlock($1)", &[&GRANT_LOCK_KEY])
        .await
        .expect("release the grant lock");
    serving.wait_until_listening();
    drop(serving);
    drop_role(&database, &role).await;
}

#[tokio::test]
async fn single_role_serve_issues_no_grant() {
    let upstream = UpstreamDouble::start();
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the test clock is after the Unix epoch")
        .as_nanos();
    let schema = format!("adapter_single_{suffix}");
    let role = format!("{schema}_solo");
    let log = format!("{schema}_log");
    // An event trigger records the session role of every GRANT in the
    // database, so the test can observe a grant a single role issues to itself.
    execute(
        &base,
        &format!(
            "CREATE SCHEMA {schema}; CREATE SCHEMA {log}; \
             CREATE TABLE {log}.grants (session_role text NOT NULL); \
             CREATE FUNCTION {log}.record() RETURNS event_trigger \
               LANGUAGE plpgsql SECURITY DEFINER AS $$ \
               BEGIN INSERT INTO {log}.grants VALUES (session_user); END $$; \
             CREATE EVENT TRIGGER {log}_trigger ON ddl_command_end \
               WHEN TAG IN ('GRANT') EXECUTE FUNCTION {log}.record(); \
             CREATE ROLE {role} LOGIN PASSWORD '{RUNTIME_PASSWORD}'; \
             GRANT USAGE, CREATE ON SCHEMA {schema} TO {role};"
        ),
    )
    .await;
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let single_url = as_role(&scoped, &role);
    let grants_by_role = || async {
        connect(&base)
            .await
            .query(
                &format!("SELECT count(*) FROM {log}.grants WHERE session_role = $1"),
                &[&role],
            )
            .await
            .expect("read the grant log")[0]
            .get::<_, i64>(0)
    };

    let mut serving = SplitRoles::spawn(&upstream.url(""), &single_url, &single_url);
    serving.wait_until_listening();
    assert_eq!(grants_by_role().await, 0, "a single role issues no grant");
    // Positive control: the trigger does see a grant the same role issues.
    execute(
        &single_url,
        "GRANT SELECT ON adapter_schema_migrations TO PUBLIC;",
    )
    .await;
    assert_eq!(grants_by_role().await, 1, "the grant log records a grant");
    drop(serving);
    execute(
        &base,
        &format!(
            "DROP EVENT TRIGGER {log}_trigger; DROP OWNED BY {role}; DROP ROLE {role}; \
             DROP SCHEMA {schema} CASCADE; DROP SCHEMA {log} CASCADE;"
        ),
    )
    .await;
}

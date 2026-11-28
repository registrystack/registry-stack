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
             (event_kind, exchange_id, operation, caller_ref, route_id, occurred_at, posture) \
         SELECT 'exchangeCreated', 'expired-' || g, 'records-get', 'synthetic-caller', \
                'seeded', now() - interval '91 days' - g * interval '1 millisecond', 'production' \
         FROM generate_series(1, {expired}) AS g; \
         INSERT INTO adapter_journal_events \
             (event_kind, exchange_id, operation, caller_ref, route_id, occurred_at, posture) \
         VALUES ('exchangeCreated', 'in-window', 'records-get', 'synthetic-caller', \
                 'seeded', now() - interval '89 days', 'production');"
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
    key: registry_platform_crypto::PrivateJwk,
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
        Self::spawn_launch(
            upstream_url,
            migration_url,
            runtime_url,
            Some((project, profile, endpoint)),
            None,
            "production",
        )
    }

    /// Serve `payments` (with the provider packs it pins) over split roles,
    /// beside the GovStack project when `facade` is given, alone when not.
    fn spawn_payments(
        migration_url: &str,
        runtime_url: &str,
        facade: Option<(&str, &Path)>,
        payments: &Path,
        packs: &[&Path],
    ) -> Self {
        Self::spawn_launch(
            facade.map_or("", |(upstream_url, _)| upstream_url),
            migration_url,
            runtime_url,
            facade.map(|(_, project)| (project, None, "tracker")),
            Some((payments, packs)),
            "development",
        )
    }

    fn spawn_launch(
        upstream_url: &str,
        migration_url: &str,
        runtime_url: &str,
        facade: Option<(&Path, Option<&Path>, &str)>,
        payments: Option<(&Path, &[&Path])>,
        posture: &str,
    ) -> Self {
        let endpoints = match facade {
            Some((_, _, endpoint)) => format!(
                r#"endpoints:
  - endpoint: {endpoint}
    baseUrl: {upstream_url}
    credential:
      type: basic
      usernameRef: secret:env/TEST_UPSTREAM_USERNAME
      passwordRef: secret:env/TEST_UPSTREAM_PASSWORD
"#
            ),
            None => "endpoints: []\n".to_owned(),
        };
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
{endpoints}listener:
  bind: 127.0.0.1:{port}
database:
  runtimeUrlRef: secret:env/TEST_DB_RUNTIME_URL
  migrationUrlRef: secret:env/TEST_DB_MIGRATION_URL
  transport: loopback-plaintext
oidc:
  issuer: {ISSUER}
  audience: {AUDIENCE}
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
        command.args(["serve", "--runtime-config"]).arg(&runtime);
        command.env_remove("REGISTRY_STACK_POSTURE");
        if let Some((project, profile, _)) = facade {
            command.arg("--project").arg(project);
            if !project.join("pack.yaml").exists() {
                command.arg("--pack").arg(Served::example_pack());
            }
            if let Some(profile) = profile.filter(|_| !project.join("profile.yaml").exists()) {
                command.arg("--profile").arg(profile);
            }
        }
        if let Some((payments, packs)) = payments {
            command
                .args(["--posture", posture, "--payments-config"])
                .arg(payments);
            for pack in packs {
                command.arg("--payment-provider-pack").arg(pack);
            }
        }
        let child = command
            .env("TEST_UPSTREAM_USERNAME", USERNAME)
            .env("TEST_UPSTREAM_PASSWORD", PASSWORD)
            .env("TEST_DB_MIGRATION_URL", migration_url)
            .env("TEST_DB_RUNTIME_URL", runtime_url)
            .env("TEST_JWKS", &jwks)
            .env("TEST_CURSOR_KEY", CURSOR_KEY)
            .env("TEST_PAYMENT_TOKEN", "synthetic-payment-token")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the adapter binary starts");
        Self {
            child,
            port,
            _directory: directory,
            key,
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
/// built by the shared provisioning plan, so its membership does not stop the grant.
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

/// Create the runtime role the way the shared provisioning plan does: a
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

/// The layout the shared provisioning plan builds, with the CREATEROLE administrator
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
    // Other tests run GRANTs while it exists, and its own cleanup can drop the
    // log table under one of them, so the function ignores that one case.
    execute(
        &base,
        &format!(
            "CREATE SCHEMA {schema}; CREATE SCHEMA {log}; \
             CREATE TABLE {log}.grants (session_role text NOT NULL); \
             CREATE FUNCTION {log}.record() RETURNS event_trigger \
               LANGUAGE plpgsql SECURITY DEFINER AS $$ \
               BEGIN INSERT INTO {log}.grants VALUES (session_user); \
               EXCEPTION WHEN undefined_table THEN NULL; END $$; \
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

// Payment tables. The payment host's startup check requires the privileges
// below on the collection tables and, when `payments.yaml` declares a
// disbursement connection, on the G2P tables. These lists are retyped here on
// purpose: a change to the check must change them too.
const COLLECTIONS: [(&str, &[&str]); 3] = [
    ("adapter_payment_attempts", &["SELECT", "INSERT", "UPDATE"]),
    ("adapter_payment_commands", &["SELECT", "INSERT"]),
    ("adapter_payment_events", &["SELECT", "INSERT"]),
];
const DISBURSEMENTS: [(&str, &[&str]); 3] = [
    ("adapter_g2p_attempts", &["SELECT", "INSERT", "UPDATE"]),
    ("adapter_g2p_commands", &["SELECT", "INSERT"]),
    ("adapter_g2p_events", &["SELECT", "INSERT"]),
];
const COLLECTIONS_SEQUENCE: &str = "adapter_payment_events_sequence_seq";
const DISBURSEMENTS_SEQUENCE: &str = "adapter_g2p_events_sequence_seq";

const G2P_SCRIPT: &str = r#"
fn submit_request(intent, settings, acceptance) {
    #{pathParameters: #{}, query: #{}, headers: #{}, body: #{correlation: intent.correlationId}}
}
fn submit_response(intent, settings, acceptance, response) {
    #{correlationId: intent.correlationId, references: #{transfer: response.body.id}}
}
fn status_request(intent, settings, acceptance) {
    #{pathParameters: #{}, query: #{id: acceptance.references.transfer}, headers: #{}, body: ()}
}
fn status_response(intent, settings, acceptance, response) {
    #{
        correlationId: response.body.correlation,
        providerReference: response.body.id,
        state: "provider-confirmed",
        money: #{minorUnits: response.body.minorUnits, currency: response.body.currency, scale: 2},
        parties: [
            #{role: "funding", key: "ACCOUNT_ID", value: response.body.debit},
            #{role: "recipient", key: "MSISDN", value: response.body.credit}
        ]
    }
}
"#;

/// A `payments.yaml` with one simulator collection connection, and one bearer
/// disbursement connection when `disbursements`, with the provider pack the
/// second pins. Returns the configuration path and the packs to pass.
fn payments_fixture(
    directory: &Path,
    disbursements: bool,
) -> (std::path::PathBuf, Vec<std::path::PathBuf>) {
    std::fs::create_dir_all(directory.join("scripts")).expect("create the pack scripts directory");
    std::fs::write(directory.join("scripts/g2p.rhai"), G2P_SCRIPT).expect("write the script");
    let pack = format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/payment-provider-pack/v1alpha1
kind: AdapterPaymentProviderPack
id: g2p-pay
version: '1'
connector: adapter-payment-http/v1
capabilities: [disbursement]
mapping:
  disbursement:
    auth: bearer
    submit:
      path: /disbursements
      request: {{file: scripts/g2p.rhai, entrypoint: submit_request}}
      response: {{file: scripts/g2p.rhai, entrypoint: submit_response}}
    status:
      path: /disbursements/status
      request: {{file: scripts/g2p.rhai, entrypoint: status_request}}
      response: {{file: scripts/g2p.rhai, entrypoint: status_response}}
  scripts:
    - path: scripts/g2p.rhai
      digest: {}
"#,
        registry_platform_config::sha256_uri(G2P_SCRIPT.as_bytes())
    );
    let pack_path = directory.join("pack.yaml");
    std::fs::write(&pack_path, &pack).expect("write the provider pack");
    let mut yaml = r#"apiVersion: id.registrystack.org/formats/adapter/payments/v1alpha1
kind: AdapterPayments
connections:
  - id: licence-fees
    institutionId: institution-a
    serviceId: licence-issuance
    allowedClients: [synthetic-client]
    requiredScope: payments:collect
    binding:
      simulation: true
      currency: USD
      currencyScale: 2
      providerCredentialRef: secret:env/TEST_PAYMENT_TOKEN
      providerCredentialIdentity: registry
      replayWindowSeconds: 3600
      provider:
        type: simulator
        connection:
          baseUrl: http://127.0.0.1:8099/
          tenant: pilot
          biller: ministry
          billerName: Ministry
          callbackUrl: https://programme.example.test/callback
          payerFiBic: SIMBANK
      registry:
        baseUrl: http://127.0.0.1:8080/
        recordType: service-fee-bill
        recordRoute: service-fee-bills
        readProfile: payment-adapter-reporter
        bindProfile: payment-adapter-binder
        receiptProfile: payment-adapter-reporter
        bindAction: bind-payment-attempt
        receiptAction: record-payment-receipt
        credentialRef: secret:env/TEST_PAYMENT_TOKEN
        credentialIdentity: payment-adapter
"#
    .to_owned();
    if disbursements {
        yaml.push_str(&format!(
            r#"disbursements:
  - id: cash-transfers
    allowedClients: [synthetic-client]
    requiredScope: payments:disburse
    binding:
      institutionId: ministry-social-protection
      serviceId: cash-transfer
      programmeId: cash-programme
      fundingAccountId: programme-account
      currency: KES
      currencyScale: 2
      providerPack:
        id: g2p-pay
        version: '1'
        digest: {}
      fundingPartyKey: ACCOUNT_ID
      recipientPartyKey: MSISDN
      provider:
        type: http
        revision: bearer-v1
        submitBaseUrl: https://disbursements.example.test/
        statusBaseUrl: https://disbursements.example.test/
        auth:
          type: bearer
          credentialIdentity: provider
          credentialRef: secret:env/TEST_PAYMENT_TOKEN
        settings: {{}}
      registry:
        baseUrl: https://breg.example.test/
        credentialIdentity: g2p-payment-adapter
        credentialRef: secret:env/TEST_PAYMENT_TOKEN
        recordRoute: disbursement-instructions
        recordType: disbursement-instruction
        readProfile: g2p-adapter-read
        bindAction: bind-payout-attempt
        bindProfile: g2p-adapter-bind
        reportAction: record-provider-confirmation
        reportProfile: g2p-adapter-report
"#,
            registry_platform_config::sha256_uri(pack.as_bytes())
        ));
    }
    let payments_path = directory.join("payments.yaml");
    std::fs::write(&payments_path, yaml).expect("write the payments configuration");
    (
        payments_path,
        if disbursements {
            vec![pack_path]
        } else {
            Vec::new()
        },
    )
}

/// Whether `role` holds USAGE on the sequence `name` of `schema`.
async fn sequence_usage(database: &str, schema: &str, name: &str, role: &str) -> bool {
    connect(database)
        .await
        .query_one(
            "SELECT has_sequence_privilege($1, to_regclass($2), 'USAGE')",
            &[&role, &format!("{schema}.{name}")],
        )
        .await
        .expect("read the sequence privilege")
        .get(0)
}

/// The tables `role` holds a privilege on, restricted to the payment host's
/// (`adapter_payment_*` and `adapter_g2p_*`).
async fn payment_table_privileges(
    database: &str,
    schema: &str,
    role: &str,
) -> std::collections::BTreeMap<String, Vec<String>> {
    table_privileges(database, schema, role)
        .await
        .into_iter()
        .filter(|(table, _)| {
            table.starts_with("adapter_payment_") || table.starts_with("adapter_g2p_")
        })
        .collect()
}

/// How a payment grant test serves: beside a GovStack project, or alone.
#[derive(Clone, Copy)]
enum PaymentHost {
    BesideFacade,
    Alone,
}

/// Serve payments over a split runtime role that starts with no grants, and
/// assert it ends holding exactly the privileges the payment host requires:
/// the collection tables, and the G2P tables when `disbursements`, plus USAGE
/// on the schema and the events sequences, and nothing else anywhere.
async fn assert_payments_grants_exactly(host: PaymentHost, disbursements: bool, deployment: &str) {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(&upstream, &Served::govstack_project(), deployment).await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    create_login_role(&database, &role).await;
    let directory = tempfile::tempdir().expect("a scratch directory");
    let (payments, packs) = payments_fixture(directory.path(), disbursements);
    let packs: Vec<&Path> = packs.iter().map(std::path::PathBuf::as_path).collect();
    let runtime_url = as_role(&database, &role);
    let upstream_url = upstream.url("");
    let govstack = Served::govstack_project();
    let facade = match host {
        PaymentHost::BesideFacade => Some((upstream_url.as_str(), govstack.as_path())),
        PaymentHost::Alone => None,
    };
    let mut serving =
        SplitRoles::spawn_payments(&database, &runtime_url, facade, &payments, &packs);
    serving.wait_until_listening();
    if matches!(host, PaymentHost::BesideFacade) {
        let (status, ready) = served_get(serving.port, "/ready", None).await;
        assert_eq!(status, 200, "{ready}");
        assert_eq!(
            ready["developmentSettings"],
            serde_json::json!([{
                "code": "adapter.posture.payment-simulator",
                "pointer": "/connections/0/binding/provider",
                "file": "payments.yaml"
            }])
        );
    }

    let mut required: Vec<(&str, &[&str])> = COLLECTIONS.to_vec();
    if disbursements {
        required.extend(DISBURSEMENTS);
    }
    // Beside a project the facade's own tables are granted too. The facade
    // grant tests cover those, so this reads the payment tables only.
    assert_eq!(
        payment_table_privileges(&database, &schema, &role).await,
        expected(&required),
        "the runtime role holds exactly the payment privileges the host requires"
    );
    assert!(sequence_usage(&database, &schema, COLLECTIONS_SEQUENCE, &role).await);
    assert_eq!(
        sequence_usage(&database, &schema, DISBURSEMENTS_SEQUENCE, &role).await,
        disbursements,
        "the G2P sequence is granted when a disbursement connection is declared, not before"
    );
    let schema_privileges = connect(&database)
        .await
        .query_one(
            "SELECT has_schema_privilege($1, $2, 'USAGE'), has_schema_privilege($1, $2, 'CREATE')",
            &[&role, &schema],
        )
        .await
        .expect("read the schema privileges");
    assert!(schema_privileges.get::<_, bool>(0), "USAGE on the schema");
    assert!(
        !schema_privileges.get::<_, bool>(1),
        "no CREATE on the schema"
    );
    assert_eq!(
        acl_grantees(&database, &schema).await,
        std::collections::BTreeSet::from([role.clone()]),
        "the runtime role is the only grantee, and PUBLIC gained nothing"
    );
    drop(serving);
    drop_role(&database, &role).await;
}

#[tokio::test]
async fn serve_grants_the_collection_tables_beside_a_project() {
    assert_payments_grants_exactly(PaymentHost::BesideFacade, false, "grants-pay-facade").await;
}

#[tokio::test]
async fn serve_grants_the_g2p_tables_when_disbursements_are_declared_beside_a_project() {
    assert_payments_grants_exactly(PaymentHost::BesideFacade, true, "grants-g2p-facade").await;
}

#[tokio::test]
async fn the_payments_only_host_grants_the_collection_tables_and_schema_usage() {
    assert_payments_grants_exactly(PaymentHost::Alone, false, "grants-pay-alone").await;
}

#[tokio::test]
async fn the_payments_only_host_grants_the_g2p_tables_when_disbursements_are_declared() {
    assert_payments_grants_exactly(PaymentHost::Alone, true, "grants-g2p-alone").await;
}

/// One role on both sessions owns the payment tables and issues no grant.
#[tokio::test]
async fn a_single_role_payments_host_issues_no_grant() {
    let upstream = UpstreamDouble::start();
    let database =
        migrated_schema(&upstream, &Served::govstack_project(), "grants-pay-single").await;
    let schema = current_schema(&database).await;
    let directory = tempfile::tempdir().expect("a scratch directory");
    let (payments, packs) = payments_fixture(directory.path(), true);
    let packs: Vec<&Path> = packs.iter().map(std::path::PathBuf::as_path).collect();
    let mut serving = SplitRoles::spawn_payments(&database, &database, None, &payments, &packs);
    serving.wait_until_listening();
    assert_eq!(
        acl_grantees(&database, &schema).await,
        std::collections::BTreeSet::new(),
        "no role other than the owner holds anything"
    );
    drop(serving);
}

/// A runtime role with a plain member inherits what it is granted, so the
/// payment tables are granted nothing and startup refuses as it does without
/// the grant step.
#[tokio::test]
async fn a_payments_runtime_role_with_members_is_granted_nothing_and_refused() {
    let upstream = UpstreamDouble::start();
    let database =
        migrated_schema(&upstream, &Served::govstack_project(), "grants-pay-members").await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    let member = format!("{schema}_member");
    create_login_role(&database, &role).await;
    create_login_role(&database, &member).await;
    execute(&database, &format!("GRANT {role} TO {member};")).await;
    let directory = tempfile::tempdir().expect("a scratch directory");
    let (payments, packs) = payments_fixture(directory.path(), true);
    let packs: Vec<&Path> = packs.iter().map(std::path::PathBuf::as_path).collect();
    let runtime_url = as_role(&database, &role);

    let stderr =
        SplitRoles::spawn_payments(&database, &runtime_url, None, &payments, &packs).refusal();
    assert!(
        stderr.contains("payment runtime role lacks required table or sequence privileges"),
        "{stderr}"
    );
    assert_eq!(
        acl_grantees(&database, &schema).await,
        std::collections::BTreeSet::new(),
        "an automatic grant is never made to a role others inherit from: {stderr}"
    );
    drop_role(&database, &member).await;
    drop_role(&database, &role).await;
}

/// A migration role that owns the facade tables but not a payment table
/// cannot make that grant: the whole transaction rolls back and the refusal
/// names the privilege and the table.
#[tokio::test]
async fn a_migration_role_that_does_not_own_a_payment_table_fails_startup_and_grants_nothing() {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(
        &upstream,
        &Served::govstack_project(),
        "grants-pay-nonowner",
    )
    .await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    let migrator = format!("{schema}_migrator");
    create_login_role(&database, &role).await;
    create_login_role(&database, &migrator).await;
    let directory = tempfile::tempdir().expect("a scratch directory");
    let (payments, packs) = payments_fixture(directory.path(), false);
    let packs: Vec<&Path> = packs.iter().map(std::path::PathBuf::as_path).collect();
    let migration_url = as_role(&database, &migrator);
    let runtime_url = as_role(&database, &role);
    // Create the payment tables as the test database's own role first, so the
    // migrator owns none of them. The payments-only host then migrates as the
    // migrator, which finds them in place.
    let mut alone = SplitRoles::spawn_payments(&database, &database, None, &payments, &packs);
    alone.wait_until_listening();
    drop(alone);
    execute(
        &database,
        &format!(
            "GRANT USAGE, CREATE ON SCHEMA {schema} TO {migrator}; \
             GRANT ALL ON ALL TABLES IN SCHEMA {schema} TO {migrator}; \
             GRANT ALL ON ALL SEQUENCES IN SCHEMA {schema} TO {migrator};"
        ),
    )
    .await;

    let stderr =
        SplitRoles::spawn_payments(&migration_url, &runtime_url, None, &payments, &packs).refusal();
    assert!(
        stderr.contains("SELECT, INSERT, UPDATE on adapter_payment_attempts"),
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

/// A payments configuration the host refuses (a credential reference that
/// resolves to nothing) settles before any database work, so nothing is
/// granted, beside a project or alone.
async fn assert_refused_payments_grant_nothing(host: PaymentHost, deployment: &str) {
    let upstream = UpstreamDouble::start();
    let database = migrated_schema(&upstream, &Served::govstack_project(), deployment).await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    create_login_role(&database, &role).await;
    let directory = tempfile::tempdir().expect("a scratch directory");
    let (payments, packs) = payments_fixture(directory.path(), true);
    let refused = std::fs::read_to_string(&payments)
        .expect("read the payments configuration")
        .replace(
            "secret:env/TEST_PAYMENT_TOKEN",
            "secret:env/TEST_PAYMENT_ABSENT",
        );
    std::fs::write(&payments, refused).expect("write the refused configuration");
    let packs: Vec<&Path> = packs.iter().map(std::path::PathBuf::as_path).collect();
    let runtime_url = as_role(&database, &role);
    let upstream_url = upstream.url("");
    let govstack = Served::govstack_project();
    let facade = match host {
        PaymentHost::BesideFacade => Some((upstream_url.as_str(), govstack.as_path())),
        PaymentHost::Alone => None,
    };

    let stderr =
        SplitRoles::spawn_payments(&database, &runtime_url, facade, &payments, &packs).refusal();
    assert!(
        stderr.contains("a payment credential could not be resolved"),
        "{stderr}"
    );
    assert_eq!(
        acl_grantees(&database, &schema).await,
        std::collections::BTreeSet::new(),
        "a refused payments configuration grants nothing: {stderr}"
    );
    drop_role(&database, &role).await;
}

#[tokio::test]
async fn a_refused_payments_configuration_grants_nothing_beside_a_project() {
    assert_refused_payments_grant_nothing(PaymentHost::BesideFacade, "grants-refused-facade").await;
}

#[tokio::test]
async fn a_refused_payments_configuration_grants_nothing_when_served_alone() {
    assert_refused_payments_grant_nothing(PaymentHost::Alone, "grants-refused-alone").await;
}

/// The payment grants share the facade tables' transaction: the migration role
/// owns the facade tables but not the payment tables, so the facade grants,
/// which would succeed alone, roll back with the payment ones.
#[tokio::test]
async fn payment_grants_commit_with_the_facade_grants_or_not_at_all() {
    let upstream = UpstreamDouble::start();
    let database =
        migrated_schema(&upstream, &Served::govstack_project(), "grants-pay-atomic").await;
    let schema = current_schema(&database).await;
    let role = format!("{schema}_runtime");
    let migrator = format!("{schema}_migrator");
    create_login_role(&database, &role).await;
    create_login_role(&database, &migrator).await;
    let directory = tempfile::tempdir().expect("a scratch directory");
    let (payments, packs) = payments_fixture(directory.path(), false);
    let packs: Vec<&Path> = packs.iter().map(std::path::PathBuf::as_path).collect();
    // Create the payment tables as the test database's own role, then hand
    // every other table to the migrator.
    let mut creator = SplitRoles::spawn_payments(&database, &database, None, &payments, &packs);
    creator.wait_until_listening();
    drop(creator);
    execute(
        &database,
        &format!(
            "GRANT USAGE, CREATE ON SCHEMA {schema} TO {migrator}; \
             GRANT ALL ON ALL TABLES IN SCHEMA {schema} TO {migrator}; \
             GRANT ALL ON ALL SEQUENCES IN SCHEMA {schema} TO {migrator}; \
             DO $$ DECLARE t text; BEGIN \
               FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = '{schema}' \
                 AND tablename NOT LIKE 'adapter\\_payment\\_%' AND tablename NOT LIKE 'adapter\\_g2p\\_%' \
               LOOP EXECUTE format('ALTER TABLE {schema}.%I OWNER TO {migrator}', t); END LOOP; \
             END $$;"
        ),
    )
    .await;
    let migration_url = as_role(&database, &migrator);
    let runtime_url = as_role(&database, &role);
    let upstream_url = upstream.url("");
    let govstack = Served::govstack_project();

    let stderr = SplitRoles::spawn_payments(
        &migration_url,
        &runtime_url,
        Some((upstream_url.as_str(), govstack.as_path())),
        &payments,
        &packs,
    )
    .refusal();
    assert!(stderr.contains("on adapter_payment_attempts"), "{stderr}");
    assert!(
        !acl_grantees(&database, &schema).await.contains(&role),
        "the facade grants rolled back with the payment ones: {stderr}"
    );
    drop_role(&database, &migrator).await;
    drop_role(&database, &role).await;
}

#[tokio::test]
async fn served_journal_rows_include_the_declared_posture() {
    let upstream = UpstreamDouble::start();
    let url = upstream.url("");
    for (served, expected) in [
        (Served::start(&url).await, "production"),
        (Served::start_development(&url).await, "development"),
    ] {
        let token = served.token("");
        let (status, _, _) = served.request("GET", "/v1/records/person", Some(&token), &[], b"");
        assert_ne!(status, 500);
        let rows = connect(&served.database)
            .await
            .query("SELECT posture FROM adapter_journal_events", &[])
            .await
            .expect("read the posture of each journal event");
        assert!(
            !rows.is_empty(),
            "the exchange writes journal rows: HTTP {status}"
        );
        assert!(rows.iter().all(|row| row.get::<_, &str>(0) == expected));
    }
}

async fn served_get(port: u16, path: &str, bearer: Option<&str>) -> (u16, serde_json::Value) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    if let Some(token) = bearer {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    request.push_str("\r\n");
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        stream.read_to_string(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (
        head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        serde_json::from_str(body).unwrap(),
    )
}

async fn served_disbursement_status_with_marked_peer(posture: registry_platform_config::Posture) {
    use registry_adapter::payments::{
        config::{PaymentsConfig, API_VERSION, KIND},
        g2p_model::{DisbursementInstruction, G2pAttempt, PreparedG2pRegistryAction},
        g2p_store::G2pStore,
        model::digest,
        provider_mapping::{
            PaymentEndpointRole, PaymentHttpMethod, PreparedProviderRequest, ProviderAcceptance,
        },
    };
    use registry_platform_config::{
        DeclaredPosture, Posture, PostureSource, RuntimeConfigLoader, RuntimeEnvelope,
    };
    use serde_json::json;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use uuid::Uuid;

    let upstream = UpstreamDouble::start();
    let database = migrated_schema(
        &upstream,
        &Served::govstack_project(),
        "marked-payment-peer",
    )
    .await;
    let directory = tempfile::tempdir().unwrap();
    let (payments, packs) = payments_fixture(directory.path(), true);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/", listener.local_addr().unwrap());
    let yaml = std::fs::read_to_string(&payments).unwrap();
    let collections = yaml.find("connections:").unwrap();
    let disbursements = yaml.find("disbursements:").unwrap();
    let yaml = format!(
        "{}connections: []\n{}",
        &yaml[..collections],
        &yaml[disbursements..]
    )
    .replace("https://disbursements.example.test/", &base);
    std::fs::write(&payments, &yaml).unwrap();
    let loaded = RuntimeConfigLoader::new(
        RuntimeEnvelope {
            api_version: API_VERSION,
            kind: KIND,
        },
        DeclaredPosture {
            posture,
            source: PostureSource::Flag,
        },
    )
    .parse_str::<PaymentsConfig>(&yaml, |_| None)
    .unwrap();
    let connection = loaded.config.disbursements.into_iter().next().unwrap();
    let binding = connection.binding;
    let record_id = Uuid::new_v4();
    let instruction = DisbursementInstruction {
        record_id,
        instruction_id: Uuid::new_v4(),
        instruction_version: 1,
        instruction_digest: "a".repeat(64),
        institution_id: binding.institution_id.clone(),
        service_id: binding.service_id.clone(),
        programme_id: binding.programme_id.clone(),
        cycle_id: "cycle-1".to_owned(),
        beneficiary_id: "beneficiary-1".to_owned(),
        beneficiary_destination: "254700000002".to_owned(),
        funding_account_id: binding.funding_account_id.clone(),
        amount_minor: 100_000,
        currency: binding.currency.clone(),
        currency_scale: binding.currency_scale,
    };
    let intent = binding.provider_intent(&instruction).unwrap();
    let prepared = PreparedProviderRequest {
        provider_pack: binding.provider_pack.clone(),
        role: PaymentEndpointRole::DisbursementSubmit,
        method: PaymentHttpMethod::Post,
        path: "/disbursements".to_owned(),
        query: Default::default(),
        headers: Default::default(),
        body: Some(
            registry_platform_canonical_json::canonicalize_json(&json!({
                "correlation": intent.correlation_id
            }))
            .unwrap(),
        ),
    };
    const CLIENT: &str = "synthetic-client";
    const SUBJECT: &str = "payment-workflow";
    let principal = digest(&[ISSUER, CLIENT, SUBJECT]).unwrap();
    let attempt = G2pAttempt::new(
        Uuid::new_v4(),
        connection.id,
        principal.clone(),
        instruction,
        binding,
        prepared,
        PreparedG2pRegistryAction {
            action: "bind-payout-attempt".to_owned(),
            key: "binding-key".to_owned(),
            inputs: Default::default(),
            evidence: "prepared".to_owned(),
        },
    )
    .unwrap();

    let packs: Vec<_> = packs.iter().map(std::path::PathBuf::as_path).collect();
    let mut serving = SplitRoles::spawn_launch(
        "",
        &database,
        &database,
        None,
        Some((&payments, &packs)),
        posture.as_str(),
    );
    serving.wait_until_listening();
    let manager = deadpool_postgres::Manager::new(database.parse().unwrap(), tokio_postgres::NoTls);
    let pool = deadpool_postgres::Pool::builder(manager).build().unwrap();
    let store = G2pStore::new(pool, "govstack-split-roles".to_owned(), posture);
    let saved = store
        .reserve(&attempt, "command-key", "request-digest")
        .await
        .unwrap();
    let id = saved.id;
    let reservation = connect(&database)
        .await
        .query_one(
            "SELECT posture FROM adapter_g2p_events WHERE attempt_id = $1 AND kind = 'g2p.attempt-reserved'",
            &[&id],
        )
        .await
        .expect("read the reservation audit posture");
    assert_eq!(reservation.get::<_, &str>(0), posture.as_str());
    let connection = &saved.connection;
    store
        .record_bound(connection, &principal, id)
        .await
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    store
        .begin_dispatch(connection, &principal, id, i64::try_from(now).unwrap())
        .await
        .unwrap();
    store
        .record_acceptance(
            connection,
            &principal,
            id,
            ProviderAcceptance {
                correlation_id: intent.correlation_id.clone(),
                references: [("transfer".to_owned(), "provider-reference".to_owned())].into(),
            },
        )
        .await
        .unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let stub_calls = calls.clone();
    let response = json!({
        "correlation": intent.correlation_id,
        "id": "provider-reference",
        "minorUnits": "100000", "currency": "KES",
        "debit": "programme-account", "credit": "254700000002",
        "private": "opaque-provider-response"
    });
    let peer = axum::Router::new().route(
        "/disbursements/status",
        axum::routing::get(move || {
            stub_calls.fetch_add(1, Ordering::Relaxed);
            let response = response.clone();
            async move { ([("Registry-Posture", "development")], axum::Json(response)) }
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, peer).await.unwrap() });
    let token = registry_platform_testing::sign_compact_jwt_with_key(
        &serving.key,
        "at+jwt",
        "canary-resource-key",
        json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": SUBJECT, "client_id": CLIENT,
            "scope": "payments:disburse", "iat": now, "exp": now + 300,
            "jti": Uuid::new_v4().to_string()
        }),
    );
    let (status, body) = served_get(
        serving.port,
        &format!("/v1/payments/{connection}/disbursements/{id}"),
        Some(&token),
    )
    .await;
    server.abort();
    assert_eq!(calls.load(Ordering::Relaxed), 1, "{status}: {body}");
    match posture {
        Posture::Production => {
            assert_eq!(status, 503, "{body}");
            assert_eq!(body["title"], "adapter.payment.unavailable", "{body}");
            assert!(
                !body.to_string().contains("opaque-provider-response"),
                "{body}"
            );
        }
        Posture::Development => {
            assert_eq!(status, 200, "{body}");
        }
    }
    let audits = connect(&database)
        .await
        .query(
            "SELECT posture FROM adapter_payment_events WHERE attempt_id = $1 AND kind LIKE 'read-disbursement.%'",
            &[&id],
        )
        .await
        .unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].get::<_, &str>(0), posture.as_str());
}

#[tokio::test]
async fn served_production_refuses_a_development_payment_peer_opaquely() {
    served_disbursement_status_with_marked_peer(registry_platform_config::Posture::Production)
        .await;
}

#[tokio::test]
async fn served_development_accepts_a_development_payment_peer() {
    served_disbursement_status_with_marked_peer(registry_platform_config::Posture::Development)
        .await;
}

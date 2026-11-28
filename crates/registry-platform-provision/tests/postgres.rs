// SPDX-License-Identifier: Apache-2.0
//! Runs the provisioning executor against real PostgreSQL servers.
//!
//! The suite reads three variables and fails, never skips, when one is
//! missing:
//!
//! - `PROVISION_TEST_DATABASE_URL`: a disposable PostgreSQL 17 superuser with
//!   PostGIS available, over TLS.
//! - `PROVISION_TEST_DATABASE_CA`: the CA PEM file that signs its certificate.
//! - `PROVISION_TEST_OLD_DATABASE_URL`: a disposable superuser on a server
//!   older than the floor, signed by the same CA.
//!
//! Each test creates its own administrator role, so a test that provisions as
//! a non-superuser holds only the attributes the test names.

use registry_platform_provision::{
    admin_config, execute, plan, render_script, verify_logins, AdminConfig, AdminConfigError, Mode,
    Needs, Outcome, ProductDatabase, ProvisionError, ProvisionTarget, RoleCredential, SchemaLayout,
    Scope, Spatial, StatementOutcome,
};
use rustls::pki_types::{pem::PemObject as _, CertificateDer};
use tokio_postgres::{config::SslMode, Client, Config};
use tokio_postgres_rustls::MakeRustlsConnect;
use url::Url;

/// One test at a time: concurrent `CREATE DATABASE` calls contend for
/// `template1`.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const NON_SUPERUSER_ADMIN: &str = "CREATEROLE CREATEDB";
const SUPERUSER_ADMIN: &str = "SUPERUSER";

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("the postgres-test feature needs {name}"))
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0_u8; bytes];
    getrandom::fill(&mut buffer).expect("random bytes");
    buffer.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn quote(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn tls(ca: &[u8]) -> MakeRustlsConnect {
    let provider = rustls::crypto::ring::default_provider();
    if provider.install_default().is_err() {
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "no TLS provider"
        );
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(ca) {
        roots.add(certificate.expect("CA PEM")).expect("CA root");
    }
    MakeRustlsConnect::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// A plain session for the test's own setup and catalog reads.
struct Raw {
    client: Client,
    task: tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
}

impl Drop for Raw {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Raw {
    async fn connect(base: &Url, ca: &[u8], user: &str, password: &str, database: &str) -> Self {
        let mut config = Config::new();
        config
            .host(base.host_str().expect("host"))
            .port(base.port().unwrap_or(5432))
            .user(user)
            .password(password)
            .dbname(database)
            .ssl_mode(SslMode::Require);
        let (client, connection) = config.connect(tls(ca)).await.expect("test session");
        Self {
            client,
            task: tokio::spawn(connection),
        }
    }

    async fn exec(&self, sql: &str) {
        self.client.batch_execute(sql).await.unwrap();
    }

    async fn text(&self, sql: &str) -> String {
        self.client
            .query_one(sql, &[])
            .await
            .unwrap()
            .get::<_, Option<String>>(0)
            .unwrap_or_default()
    }

    async fn flag(&self, sql: &str) -> bool {
        self.client.query_one(sql, &[]).await.unwrap().get(0)
    }
}

struct Server {
    url: Url,
    ca: Vec<u8>,
    superuser: Raw,
}

impl Server {
    async fn start(url_variable: &str) -> Self {
        let url = Url::parse(&required(url_variable)).expect("test URL");
        let ca = std::fs::read(required("PROVISION_TEST_DATABASE_CA")).expect("CA file");
        let superuser = Raw::connect(
            &url,
            &ca,
            url.username(),
            url.password().expect("password"),
            "postgres",
        )
        .await;
        Self { url, ca, superuser }
    }

    async fn session(&self, user: &str, password: &str, database: &str) -> Raw {
        Raw::connect(&self.url, &self.ca, user, password, database).await
    }
}

/// Names and passwords for one test, and the administrator it provisions as.
struct Fixture {
    server: Server,
    suffix: String,
    admin_password: String,
    migration_password: String,
    runtime_password: String,
}

impl Fixture {
    async fn new(administrator_attributes: &str) -> Self {
        Self::on(
            Server::start("PROVISION_TEST_DATABASE_URL").await,
            administrator_attributes,
        )
        .await
    }

    async fn on(server: Server, administrator_attributes: &str) -> Self {
        let fixture = Self {
            server,
            suffix: random_hex(5),
            admin_password: random_hex(16),
            migration_password: random_hex(16),
            runtime_password: random_hex(16),
        };
        fixture
            .server
            .superuser
            .exec(&format!(
                "CREATE ROLE {} LOGIN {administrator_attributes} PASSWORD '{}'",
                quote(&fixture.admin_name()),
                fixture.admin_password
            ))
            .await;
        fixture
    }

    fn database(&self) -> String {
        format!("s2_db_{}", self.suffix)
    }
    fn migration_name(&self) -> String {
        format!("s2_mig_{}", self.suffix)
    }
    fn runtime_name(&self) -> String {
        format!("s2_run_{}", self.suffix)
    }
    fn admin_name(&self) -> String {
        format!("s2_adm_{}", self.suffix)
    }
    fn bbox_name(&self) -> String {
        format!("s2_bbox_{}", self.suffix)
    }

    fn admin_url(&self) -> String {
        let mut url = self.server.url.clone();
        url.set_username(&self.admin_name()).unwrap();
        url.set_password(Some(&self.admin_password)).unwrap();
        url.set_path("/postgres");
        url.into()
    }

    fn admin(&self) -> AdminConfig {
        admin_config(&self.admin_url(), Some(&self.server.ca)).unwrap()
    }

    fn target(&self) -> ProvisionTarget {
        ProvisionTarget {
            database: self.database(),
            migration: RoleCredential::new(self.migration_name(), &self.migration_password),
            runtime: RoleCredential::new(self.runtime_name(), &self.runtime_password),
        }
    }

    fn single_role_target(&self) -> ProvisionTarget {
        ProvisionTarget {
            database: self.database(),
            migration: RoleCredential::new(self.migration_name(), &self.migration_password),
            runtime: RoleCredential::new(self.migration_name(), &self.migration_password),
        }
    }

    fn owned_product() -> ProductDatabase {
        ProductDatabase {
            product: "owned",
            layout: SchemaLayout::Owned(vec!["s2_one".to_owned(), "s2_two".to_owned()]),
            btree_gist: true,
            spatial: None,
        }
    }

    fn public_product() -> ProductDatabase {
        ProductDatabase {
            product: "public",
            layout: SchemaLayout::PublicForMigration,
            btree_gist: false,
            spatial: None,
        }
    }

    fn created_by_apply_product() -> ProductDatabase {
        ProductDatabase {
            product: "created-by-apply",
            layout: SchemaLayout::CreatedByApply,
            btree_gist: false,
            spatial: None,
        }
    }

    fn spatial_product(&self, minimum_postgis: (u32, u32)) -> ProductDatabase {
        ProductDatabase {
            product: "spatial",
            layout: SchemaLayout::Owned(vec!["s2_one".to_owned()]),
            btree_gist: true,
            spatial: Some(Spatial {
                schema: "registry_spatial_ext".to_owned(),
                bbox_role: self.bbox_name(),
                minimum_postgis,
            }),
        }
    }

    fn layouts() -> [ProductDatabase; 3] {
        [
            Self::owned_product(),
            Self::public_product(),
            Self::created_by_apply_product(),
        ]
    }

    async fn provision(&self, product: &ProductDatabase) -> Result<Outcome, ProvisionError> {
        let plan = plan(product, &self.target()).unwrap();
        execute(&self.admin(), &plan, Mode::Converge).await
    }

    /// The catalog this fixture's objects leave behind, with this fixture's
    /// names replaced by placeholders, so two fixtures compare by shape.
    async fn snapshot(&self) -> String {
        let su = &self.server.superuser;
        let names = vec![self.migration_name(), self.runtime_name(), self.bbox_name()];
        let roles = su
            .client
            .query_one(
                "SELECT string_agg(concat_ws('|', rolname, rolsuper, rolinherit, rolcreaterole, \
                        rolcreatedb, rolcanlogin, rolreplication, rolbypassrls, rolconnlimit, \
                        coalesce(rolvaliduntil::text, '')), E'\\n' ORDER BY rolname) \
                   FROM pg_catalog.pg_roles WHERE rolname = ANY($1)",
                &[&names],
            )
            .await
            .unwrap()
            .get::<_, Option<String>>(0)
            .unwrap_or_default();
        let members = su
            .client
            .query_one(
                "SELECT string_agg(concat_ws('|', r.rolname, m.rolname, a.admin_option, \
                        a.inherit_option, a.set_option), E'\\n' ORDER BY r.rolname, m.rolname) \
                   FROM pg_catalog.pg_auth_members a \
                   JOIN pg_catalog.pg_roles r ON r.oid = a.roleid \
                   JOIN pg_catalog.pg_roles m ON m.oid = a.member \
                  WHERE r.rolname = ANY($1) OR m.rolname = ANY($1)",
                &[&names],
            )
            .await
            .unwrap()
            .get::<_, Option<String>>(0)
            .unwrap_or_default();
        let database = su
            .client
            .query_opt(
                "SELECT concat_ws('|', datname, pg_catalog.pg_get_userbyid(datdba), \
                        datallowconn, coalesce(datacl::text, '')) \
                   FROM pg_catalog.pg_database WHERE datname = $1",
                &[&self.database()],
            )
            .await
            .unwrap()
            .map(|row| row.get::<_, String>(0))
            .unwrap_or_else(|| "<no database>".to_owned());
        let inside = if database == "<no database>" {
            String::new()
        } else {
            let session = self
                .server
                .session(
                    self.server.url.username(),
                    self.server.url.password().unwrap(),
                    &self.database(),
                )
                .await;
            let schemas = session
                .text(
                    "SELECT string_agg(concat_ws('|', nspname, \
                            pg_catalog.pg_get_userbyid(nspowner), coalesce(nspacl::text, '')), \
                            E'\\n' ORDER BY nspname) \
                       FROM pg_catalog.pg_namespace \
                      WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'",
                )
                .await;
            let extensions = session
                .text(
                    "SELECT string_agg(extname, ',' ORDER BY extname) \
                       FROM pg_catalog.pg_extension",
                )
                .await;
            format!("{schemas}\n{extensions}")
        };
        let snapshot = format!("{roles}\n--\n{members}\n--\n{database}\n--\n{inside}");
        snapshot
            .replace(&self.database(), "<db>")
            .replace(&self.migration_name(), "<migration>")
            .replace(&self.runtime_name(), "<runtime>")
            .replace(&self.bbox_name(), "<bbox>")
            .replace(&self.admin_name(), "<admin>")
    }

    async fn role_exists(&self, role: &str) -> bool {
        self.server
            .superuser
            .flag(&format!(
                "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{role}')"
            ))
            .await
    }

    async fn database_exists(&self) -> bool {
        self.server
            .superuser
            .flag(&format!(
                "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = '{}')",
                self.database()
            ))
            .await
    }

    async fn cleanup(self) {
        let su = &self.server.superuser;
        su.exec(&format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            quote(&self.database())
        ))
        .await;
        for role in [
            self.migration_name(),
            self.runtime_name(),
            self.bbox_name(),
            self.admin_name(),
        ] {
            su.exec(&format!("DROP ROLE IF EXISTS {}", quote(&role)))
                .await;
        }
    }
}

async fn count_records(session: &Raw) -> String {
    session.text("SELECT count(*)::text FROM records").await
}

async fn lock() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL.lock().await
}

fn outcome_of(outcome: &Outcome, step: &str) -> StatementOutcome {
    outcome
        .statements
        .iter()
        .find(|(name, _)| *name == step)
        .unwrap_or_else(|| panic!("no outcome for {step}"))
        .1
}

fn created(outcome: &Outcome) -> Vec<&'static str> {
    outcome
        .statements
        .iter()
        .filter(|(_, result)| *result == StatementOutcome::Created)
        .map(|(step, _)| *step)
        .collect()
}

// ---- A.13 test 4 ----------------------------------------------------------

#[tokio::test]
async fn provision_twice_leaves_the_same_catalog() {
    let _serial = lock().await;
    for product in Fixture::layouts() {
        let fixture = Fixture::new(NON_SUPERUSER_ADMIN).await;
        let first = fixture.provision(&product).await.unwrap();
        assert_eq!(
            outcome_of(&first, "role.migration"),
            StatementOutcome::Created
        );
        assert_eq!(
            outcome_of(&first, "role.runtime"),
            StatementOutcome::Created
        );
        assert_eq!(
            outcome_of(&first, "database.create"),
            StatementOutcome::Created
        );
        assert_eq!(
            outcome_of(&first, "database.grant-connect"),
            StatementOutcome::Applied
        );
        let after_first = fixture.snapshot().await;
        assert!(after_first.contains("<migration>"), "{after_first}");

        let second = fixture.provision(&product).await.unwrap();
        assert_eq!(created(&second), Vec::<&str>::new(), "{product:?}");
        assert_eq!(
            outcome_of(&second, "role.migration"),
            StatementOutcome::Present
        );
        assert_eq!(
            outcome_of(&second, "role.runtime"),
            StatementOutcome::Present
        );
        assert_eq!(
            outcome_of(&second, "database.create"),
            StatementOutcome::Present
        );
        assert_eq!(
            outcome_of(&second, "database.revoke-public"),
            StatementOutcome::Applied
        );
        assert_eq!(
            first
                .statements
                .iter()
                .map(|(step, _)| *step)
                .collect::<Vec<_>>(),
            second
                .statements
                .iter()
                .map(|(step, _)| *step)
                .collect::<Vec<_>>()
        );
        assert_eq!(after_first, fixture.snapshot().await, "{product:?}");
        verify_logins(&fixture.admin(), &fixture.target())
            .await
            .unwrap();
        fixture.cleanup().await;
    }
}

#[tokio::test]
async fn schema_work_converges_by_object() {
    let _serial = lock().await;
    let fixture = Fixture::new(NON_SUPERUSER_ADMIN).await;
    let product = Fixture::owned_product();
    let first = fixture.provision(&product).await.unwrap();
    assert_eq!(
        outcome_of(&first, "extension.btree-gist"),
        StatementOutcome::Created
    );
    let schemas: Vec<_> = first
        .statements
        .iter()
        .filter(|(step, _)| *step == "schema.owned")
        .map(|(_, result)| *result)
        .collect();
    assert_eq!(schemas, vec![StatementOutcome::Created; 2]);
    let second = fixture.provision(&product).await.unwrap();
    assert_eq!(
        outcome_of(&second, "extension.btree-gist"),
        StatementOutcome::Present
    );
    let schemas: Vec<_> = second
        .statements
        .iter()
        .filter(|(step, _)| *step == "schema.owned")
        .map(|(_, result)| *result)
        .collect();
    assert_eq!(schemas, vec![StatementOutcome::Present; 2]);
    fixture.cleanup().await;
}

// ---- A.13 test 5 ----------------------------------------------------------

#[tokio::test]
async fn non_superuser_administrator_provisions() {
    let _serial = lock().await;
    let fixture = Fixture::new(NON_SUPERUSER_ADMIN).await;
    let su = &fixture.server.superuser;
    let attributes = su
        .text(&format!(
            "SELECT concat_ws('|', rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, \
                    rolreplication) \
               FROM pg_catalog.pg_roles WHERE rolname = '{}'",
            fixture.admin_name()
        ))
        .await;
    assert_eq!(attributes, "f|t|t|f|f");

    let outcome = fixture.provision(&Fixture::owned_product()).await.unwrap();
    assert!(!outcome.single_role);
    assert_eq!(
        outcome_of(&outcome, "schema.owned"),
        StatementOutcome::Created
    );
    verify_logins(&fixture.admin(), &fixture.target())
        .await
        .unwrap();
    fixture.cleanup().await;
}

// ---- A.11: split roles, forced row-level security ---------------------------

#[tokio::test]
async fn split_roles_hold_only_what_the_plan_grants() {
    let _serial = lock().await;
    for product in Fixture::layouts() {
        let fixture = Fixture::new(NON_SUPERUSER_ADMIN).await;
        fixture.provision(&product).await.unwrap();
        let su = &fixture.server.superuser;
        let (m, r, db) = (
            fixture.migration_name(),
            fixture.runtime_name(),
            fixture.database(),
        );
        for role in [&m, &r] {
            let attributes = su
                .text(&format!(
                    "SELECT concat_ws('|', rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, \
                            rolinherit, rolbypassrls, rolreplication) \
                       FROM pg_catalog.pg_roles WHERE rolname = '{role}'"
                ))
                .await;
            assert_eq!(attributes, "t|f|f|f|f|f|f", "{role}");
        }
        assert!(
            su.flag(&format!(
                "SELECT has_database_privilege('{r}', '{db}', 'CONNECT')"
            ))
            .await
        );
        assert!(
            su.flag(&format!(
                "SELECT has_database_privilege('{m}', '{db}', 'CONNECT')"
            ))
            .await
        );
        assert!(
            !su.flag(&format!(
                "SELECT has_database_privilege('{r}', '{db}', 'CREATE')"
            ))
            .await
        );
        assert!(
            !su.flag(&format!(
                "SELECT has_database_privilege('{r}', '{db}', 'TEMPORARY')"
            ))
            .await,
            "PUBLIC temporary access is revoked"
        );
        let acl = su
            .text(&format!(
                "SELECT datacl::text FROM pg_catalog.pg_database WHERE datname = '{db}'"
            ))
            .await;
        assert!(
            !acl.split(',')
                .any(|entry| entry.trim_start_matches('{').starts_with('=')),
            "no PUBLIC entry remains: {acl}"
        );
        let wants_create = matches!(product.layout, SchemaLayout::CreatedByApply);
        assert_eq!(
            su.flag(&format!(
                "SELECT has_database_privilege('{m}', '{db}', 'CREATE')"
            ))
            .await,
            wants_create,
            "{product:?}"
        );
        match &product.layout {
            SchemaLayout::Owned(schemas) => {
                let session = fixture
                    .server
                    .session(
                        fixture.server.url.username(),
                        fixture.server.url.password().unwrap(),
                        &db,
                    )
                    .await;
                for schema in schemas {
                    let owner = session
                        .text(&format!(
                            "SELECT pg_catalog.pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace \
                              WHERE nspname = '{schema}'"
                        ))
                        .await;
                    assert_eq!(owner, m);
                    assert!(
                        !session
                            .flag(&format!(
                                "SELECT has_schema_privilege('{r}', '{schema}', 'USAGE')"
                            ))
                            .await,
                        "the runtime role gets nothing on {schema}"
                    );
                }
            }
            SchemaLayout::PublicForMigration => {
                let session = fixture
                    .server
                    .session(
                        fixture.server.url.username(),
                        fixture.server.url.password().unwrap(),
                        &db,
                    )
                    .await;
                assert!(
                    session
                        .flag(&format!(
                            "SELECT has_schema_privilege('{m}', 'public', 'CREATE')"
                        ))
                        .await
                );
                assert!(
                    !session
                        .flag(&format!(
                            "SELECT has_schema_privilege('{r}', 'public', 'CREATE')"
                        ))
                        .await
                );
            }
            SchemaLayout::CreatedByApply => {}
        }
        fixture.cleanup().await;
    }
}

#[tokio::test]
async fn provisioned_roles_are_bound_by_forced_row_level_security() {
    let _serial = lock().await;
    let fixture = Fixture::new(NON_SUPERUSER_ADMIN).await;
    fixture.provision(&Fixture::public_product()).await.unwrap();
    let migration = fixture
        .server
        .session(
            &fixture.migration_name(),
            &fixture.migration_password,
            &fixture.database(),
        )
        .await;
    let runtime = fixture
        .server
        .session(
            &fixture.runtime_name(),
            &fixture.runtime_password,
            &fixture.database(),
        )
        .await;
    migration
        .exec("CREATE TABLE records (id int PRIMARY KEY, visible bool NOT NULL)")
        .await;
    migration
        .exec("INSERT INTO records VALUES (1, true), (2, false)")
        .await;
    migration
        .exec(&format!(
            "GRANT SELECT ON records TO {}",
            quote(&fixture.runtime_name())
        ))
        .await;
    migration
        .exec("ALTER TABLE records ENABLE ROW LEVEL SECURITY")
        .await;
    migration
        .exec("CREATE POLICY only_visible ON records FOR SELECT USING (visible)")
        .await;
    // The owner is exempt from a policy that is not forced.
    assert_eq!(count_records(&migration).await, "2");
    assert_eq!(count_records(&runtime).await, "1");
    migration
        .exec("ALTER TABLE records FORCE ROW LEVEL SECURITY")
        .await;
    // Neither role bypasses row-level security, so forcing it binds the owner too.
    assert_eq!(count_records(&migration).await, "1");
    assert_eq!(count_records(&runtime).await, "1");
    let denied = runtime
        .client
        .batch_execute("CREATE TABLE elsewhere (id int)")
        .await
        .unwrap_err();
    assert_eq!(denied.code().map(|code| code.code()), Some("42501"));
    drop((migration, runtime));
    fixture.cleanup().await;
}

#[tokio::test]
async fn single_role_mode_creates_one_role() {
    let _serial = lock().await;
    let fixture = Fixture::new(NON_SUPERUSER_ADMIN).await;
    let target = fixture.single_role_target();
    let plan = plan(&Fixture::public_product(), &target).unwrap();
    assert!(plan.single_role());
    let outcome = execute(&fixture.admin(), &plan, Mode::Converge)
        .await
        .unwrap();
    assert!(outcome.single_role);
    assert!(outcome
        .statements
        .iter()
        .all(|(step, _)| *step != "role.runtime"));
    assert!(fixture.role_exists(&fixture.migration_name()).await);
    assert!(!fixture.role_exists(&fixture.runtime_name()).await);
    verify_logins(&fixture.admin(), &target).await.unwrap();
    fixture.cleanup().await;
}

// ---- A.13 test 6 ----------------------------------------------------------

#[tokio::test]
async fn administrator_without_createdb_is_told_the_statement() {
    let _serial = lock().await;
    let fixture = Fixture::new("CREATEROLE").await;
    let error = fixture
        .provision(&Fixture::owned_product())
        .await
        .unwrap_err();
    assert_eq!(error.code(), "platform.provision.statement-needs-privilege");
    assert_eq!(error.step(), Some("database.create"));
    match &error {
        ProvisionError::StatementNeedsPrivilege {
            needs,
            scope,
            database,
            ..
        } => {
            assert_eq!(*needs, Needs::CreateDb);
            assert_eq!(*scope, Scope::Server);
            assert_eq!(database, &fixture.database());
        }
        other => panic!("unexpected error {other:?}"),
    }
    assert_eq!(
        error.to_string(),
        "the administrator role cannot run CREATE DATABASE in the server; it needs CREATEDB"
    );
    assert!(!fixture.database_exists().await);
    fixture.cleanup().await;
}

#[tokio::test]
async fn administrator_without_createrole_is_told_the_first_statement() {
    let _serial = lock().await;
    let fixture = Fixture::new("").await;
    let error = fixture
        .provision(&Fixture::owned_product())
        .await
        .unwrap_err();
    assert_eq!(error.code(), "platform.provision.statement-needs-privilege");
    assert_eq!(error.step(), Some("role.migration"));
    assert_eq!(
        error.to_string(),
        "the administrator role cannot run CREATE ROLE in the server; it needs CREATEROLE"
    );
    assert!(!fixture.role_exists(&fixture.migration_name()).await);
    fixture.cleanup().await;
}

// ---- A.13 test 7 ----------------------------------------------------------

#[tokio::test]
async fn postgis_without_superuser_names_the_extension_statement() {
    let _serial = lock().await;
    let fixture = Fixture::new(NON_SUPERUSER_ADMIN).await;
    let product = fixture.spatial_product((3, 5));
    let error = fixture.provision(&product).await.unwrap_err();
    assert_eq!(error.code(), "platform.provision.statement-needs-privilege");
    assert_eq!(error.step(), Some("extension.postgis"));
    match &error {
        ProvisionError::StatementNeedsPrivilege {
            needs,
            scope,
            database,
            ..
        } => {
            assert_eq!(*needs, Needs::Superuser);
            assert_eq!(*scope, Scope::Database);
            assert_eq!(database, &fixture.database());
        }
        other => panic!("unexpected error {other:?}"),
    }
    assert_eq!(
        error.to_string(),
        format!(
            "the administrator role cannot run CREATE EXTENSION postgis in database \"{}\"; \
             it needs a superuser",
            fixture.database()
        )
    );

    // A superuser runs the one statement the error names, from the plan.
    let plan = plan(&product, &fixture.target()).unwrap();
    let statement = plan
        .statements()
        .iter()
        .find(|statement| statement.step == "extension.postgis")
        .unwrap();
    let session = fixture
        .server
        .session(
            fixture.server.url.username(),
            fixture.server.url.password().unwrap(),
            &fixture.database(),
        )
        .await;
    session.exec(&statement.printable).await;
    drop(session);

    let outcome = execute(&fixture.admin(), &plan, Mode::Converge)
        .await
        .unwrap();
    assert_eq!(
        outcome_of(&outcome, "extension.postgis"),
        StatementOutcome::Present
    );
    assert_eq!(
        outcome_of(&outcome, "schema.owned"),
        StatementOutcome::Present
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn postgis_is_created_when_the_administrator_is_a_superuser() {
    let _serial = lock().await;
    let fixture = Fixture::new(SUPERUSER_ADMIN).await;
    let product = fixture.spatial_product((3, 5));
    let first = fixture.provision(&product).await.unwrap();
    assert_eq!(
        outcome_of(&first, "extension.postgis"),
        StatementOutcome::Created
    );
    assert_eq!(
        outcome_of(&first, "role.spatial-bbox"),
        StatementOutcome::Created
    );
    let second = fixture.provision(&product).await.unwrap();
    assert_eq!(
        outcome_of(&second, "extension.postgis"),
        StatementOutcome::Present
    );
    assert_eq!(
        outcome_of(&second, "role.spatial-bbox"),
        StatementOutcome::Present
    );

    // An installed PostGIS below the product's minimum is named, not skipped.
    let too_new = fixture.spatial_product((99, 0));
    let error = fixture.provision(&too_new).await.unwrap_err();
    assert_eq!(error.code(), "platform.provision.extension-too-old");
    assert_eq!(error.step(), Some("extension.postgis"));
    fixture.cleanup().await;
}

// ---- A.13 test 8 ----------------------------------------------------------

#[tokio::test]
async fn existing_role_with_other_attributes_is_refused() {
    let _serial = lock().await;
    let differing = [
        ("LOGIN CREATEDB", "role.migration", true),
        ("LOGIN CREATEROLE", "role.migration", true),
        ("LOGIN REPLICATION", "role.migration", true),
        ("LOGIN BYPASSRLS", "role.migration", true),
        ("LOGIN INHERIT", "role.migration", true),
        ("NOLOGIN", "role.migration", true),
        ("LOGIN CREATEDB", "role.runtime", false),
    ];
    for (attributes, step, migration) in differing {
        let fixture = Fixture::new(NON_SUPERUSER_ADMIN).await;
        let role = if migration {
            fixture.migration_name()
        } else {
            fixture.runtime_name()
        };
        let before = "SELECT concat_ws('|', rolcanlogin, rolcreatedb, rolcreaterole, rolinherit, \
                      rolbypassrls, rolreplication) FROM pg_catalog.pg_roles WHERE rolname = ";
        fixture
            .server
            .superuser
            .exec(&format!("CREATE ROLE {} {attributes}", quote(&role)))
            .await;
        let stored = fixture
            .server
            .superuser
            .text(&format!("{before}'{role}'"))
            .await;
        let error = fixture
            .provision(&Fixture::public_product())
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            "platform.provision.role-attributes-differ",
            "{attributes}"
        );
        assert_eq!(error.step(), Some(step));
        assert!(error.to_string().contains(&role));
        assert_eq!(
            fixture
                .server
                .superuser
                .text(&format!("{before}'{role}'"))
                .await,
            stored,
            "the existing role is never altered"
        );
        assert!(
            !fixture.database_exists().await,
            "nothing runs after a refusal"
        );
        fixture
            .server
            .superuser
            .exec(&format!(
                "DROP ROLE IF EXISTS {}",
                quote(&fixture.migration_name())
            ))
            .await;
        fixture.cleanup().await;
    }
}

#[tokio::test]
async fn existing_database_owned_by_another_role_is_refused() {
    let _serial = lock().await;
    let fixture = Fixture::new(NON_SUPERUSER_ADMIN).await;
    fixture
        .server
        .superuser
        .exec(&format!("CREATE DATABASE {}", quote(&fixture.database())))
        .await;
    let acl_before = fixture
        .server
        .superuser
        .text(&format!(
            "SELECT coalesce(datacl::text, '') FROM pg_catalog.pg_database WHERE datname = '{}'",
            fixture.database()
        ))
        .await;
    let error = fixture
        .provision(&Fixture::public_product())
        .await
        .unwrap_err();
    assert_eq!(error.code(), "platform.provision.database-owner-differs");
    assert_eq!(error.step(), Some("database.create"));
    assert_eq!(
        acl_before,
        fixture
            .server
            .superuser
            .text(&format!(
                "SELECT coalesce(datacl::text, '') FROM pg_catalog.pg_database \
                  WHERE datname = '{}'",
                fixture.database()
            ))
            .await
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn existing_schema_owned_by_another_role_is_refused() {
    let _serial = lock().await;
    let fixture = Fixture::new(SUPERUSER_ADMIN).await;
    fixture
        .server
        .superuser
        .exec(&format!("CREATE DATABASE {}", quote(&fixture.database())))
        .await;
    let session = fixture
        .server
        .session(
            fixture.server.url.username(),
            fixture.server.url.password().unwrap(),
            &fixture.database(),
        )
        .await;
    session.exec("CREATE SCHEMA s2_one").await;
    drop(session);
    let error = fixture
        .provision(&Fixture::owned_product())
        .await
        .unwrap_err();
    assert_eq!(error.code(), "platform.provision.schema-owner-differs");
    assert_eq!(error.step(), Some("schema.owned"));
    fixture.cleanup().await;
}

#[tokio::test]
async fn a_changed_password_fails_the_login_check_for_that_role() {
    let _serial = lock().await;
    let fixture = Fixture::new(NON_SUPERUSER_ADMIN).await;
    fixture.provision(&Fixture::public_product()).await.unwrap();
    verify_logins(&fixture.admin(), &fixture.target())
        .await
        .unwrap();
    fixture
        .server
        .superuser
        .exec(&format!(
            "ALTER ROLE {} PASSWORD '{}'",
            quote(&fixture.runtime_name()),
            random_hex(16)
        ))
        .await;
    // The existing role keeps its stored password, so converging reports it
    // present and only the login check notices the mismatch.
    let again = fixture.provision(&Fixture::public_product()).await.unwrap();
    assert_eq!(
        outcome_of(&again, "role.runtime"),
        StatementOutcome::Present
    );
    let error = verify_logins(&fixture.admin(), &fixture.target())
        .await
        .unwrap_err();
    assert_eq!(error.code(), "platform.provision.role-login-failed");
    assert!(error.to_string().contains(&fixture.runtime_name()));
    assert!(!error.to_string().contains(&fixture.migration_name()));
    fixture.cleanup().await;
}

// ---- A.13 test 9 ----------------------------------------------------------

fn unquote(identifier: &str) -> String {
    identifier
        .trim()
        .trim_start_matches('"')
        .trim_end_matches('"')
        .replace("\"\"", "\"")
}

/// Runs a printed script the way `psql` does: a `\connect` opens a new
/// session that has none of the earlier `SET`s, and `\password` sets the
/// password the administrator would have typed.
async fn run_script(fixture: &Fixture, script: &str) {
    let server = &fixture.server;
    let mut session = server
        .session(&fixture.admin_name(), &fixture.admin_password, "postgres")
        .await;
    let mut pending = String::new();
    for line in script.lines() {
        if pending.is_empty() && line.starts_with("--") {
            continue;
        }
        if let Some(database) = line.strip_prefix("\\connect ") {
            session = server
                .session(
                    &fixture.admin_name(),
                    &fixture.admin_password,
                    &unquote(database),
                )
                .await;
            continue;
        }
        if let Some(role) = line.strip_prefix("\\password ") {
            let role = unquote(role);
            let password = if role == fixture.migration_name() {
                &fixture.migration_password
            } else {
                &fixture.runtime_password
            };
            session
                .exec(&format!(
                    "ALTER ROLE {} PASSWORD '{password}'",
                    quote(&role)
                ))
                .await;
            continue;
        }
        pending.push_str(line);
        pending.push('\n');
        if line.ends_with(';') {
            session.exec(&pending).await;
            pending.clear();
        }
    }
    assert!(pending.is_empty(), "the script ends inside a statement");
}

#[tokio::test]
async fn printed_script_gives_the_same_catalog() {
    let _serial = lock().await;
    for product in Fixture::layouts() {
        let executed = Fixture::new(NON_SUPERUSER_ADMIN).await;
        executed.provision(&product).await.unwrap();

        let scripted = Fixture::new(NON_SUPERUSER_ADMIN).await;
        let script = render_script(&plan(&product, &scripted.target()).unwrap());
        run_script(&scripted, &script).await;
        verify_logins(&scripted.admin(), &scripted.target())
            .await
            .unwrap();

        assert_eq!(
            executed.snapshot().await,
            scripted.snapshot().await,
            "{product:?}"
        );
        executed.cleanup().await;
        scripted.cleanup().await;
    }
}

// ---- Floor ------------------------------------------------------------------

#[tokio::test]
async fn server_below_the_floor_is_refused_before_any_statement() {
    let _serial = lock().await;
    let old = Server::start("PROVISION_TEST_OLD_DATABASE_URL").await;
    let version: i32 = old
        .superuser
        .text("SELECT current_setting('server_version_num')")
        .await
        .parse()
        .unwrap();
    assert!(version < 170_000, "the old server must be below the floor");
    let fixture = Fixture::on(old, SUPERUSER_ADMIN).await;
    let error = fixture
        .provision(&Fixture::owned_product())
        .await
        .unwrap_err();
    assert_eq!(error.code(), "platform.provision.unsupported-postgres");
    assert_eq!(error.step(), None);
    assert!(
        error
            .to_string()
            .starts_with("PostgreSQL 17 or newer is required"),
        "{error}"
    );
    assert!(!fixture.role_exists(&fixture.migration_name()).await);
    assert!(!fixture.database_exists().await);

    // Fresh mode is for a server the caller just made, and does not check.
    let plan = plan(&Fixture::public_product(), &fixture.target()).unwrap();
    execute(&fixture.admin(), &plan, Mode::Fresh).await.unwrap();
    assert!(fixture.database_exists().await);
    fixture.cleanup().await;
}

// ---- A.13 test 11 -----------------------------------------------------------

/// Every rendering of a value the caller could print or log.
fn renderings(error: &(dyn std::error::Error + 'static)) -> Vec<String> {
    let mut texts = vec![
        format!("{error}"),
        format!("{error:?}"),
        format!("{error:#?}"),
    ];
    let mut source = error.source();
    while let Some(cause) = source {
        texts.push(format!("{cause}"));
        texts.push(format!("{cause:?}"));
        source = cause.source();
    }
    texts
}

fn assert_clean(texts: &[String], secrets: &[String]) {
    for text in texts {
        for secret in secrets {
            assert!(!secret.is_empty());
            assert!(!text.contains(secret.as_str()), "a secret reached: {text}");
        }
        assert!(
            !text.contains("SCRAM-SHA-256$"),
            "a verifier reached: {text}"
        );
        assert!(!text.contains("postgresql://"), "a URL reached: {text}");
        assert!(!text.contains("PASSWORD"), "statement text reached: {text}");
    }
}

#[tokio::test]
async fn error_text_never_contains_a_password_a_verifier_or_a_url() {
    let _serial = lock().await;
    let mut texts: Vec<String> = Vec::new();

    // A CREATE ROLE statement that carries a verifier and is refused.
    let without_createrole = Fixture::new("").await;
    let mut secrets = vec![
        without_createrole.admin_password.clone(),
        without_createrole.migration_password.clone(),
        without_createrole.runtime_password.clone(),
        without_createrole.admin_url(),
    ];
    let error = without_createrole
        .provision(&Fixture::owned_product())
        .await
        .unwrap_err();
    texts.extend(renderings(&error));
    without_createrole.cleanup().await;

    // A statement that fails on the server with a verifier in its text, and
    // the verifiers the server stores.
    let fixture = Fixture::new(NON_SUPERUSER_ADMIN).await;
    secrets.extend([
        fixture.admin_password.clone(),
        fixture.migration_password.clone(),
        fixture.runtime_password.clone(),
        fixture.admin_url(),
    ]);
    let success = fixture.provision(&Fixture::public_product()).await.unwrap();
    texts.push(format!("{success:?}"));
    for role in [fixture.migration_name(), fixture.runtime_name()] {
        secrets.push(
            fixture
                .server
                .superuser
                .text(&format!(
                    "SELECT rolpassword FROM pg_catalog.pg_authid WHERE rolname = '{role}'"
                ))
                .await,
        );
    }
    let plan = plan(&Fixture::public_product(), &fixture.target()).unwrap();
    texts.push(format!("{plan:?}"));
    texts.push(format!("{:?}", fixture.target()));
    texts.push(format!("{:?}", fixture.admin()));
    texts.push(render_script(&plan));
    let error = execute(&fixture.admin(), &plan, Mode::Fresh)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "platform.provision.statement-failed");
    assert_eq!(error.step(), Some("role.migration"));
    texts.extend(renderings(&error));

    // A refused existing role.
    let other = Fixture::new(NON_SUPERUSER_ADMIN).await;
    secrets.extend([
        other.migration_password.clone(),
        other.runtime_password.clone(),
    ]);
    other
        .server
        .superuser
        .exec(&format!(
            "CREATE ROLE {} LOGIN CREATEDB",
            quote(&other.migration_name())
        ))
        .await;
    let error = other
        .provision(&Fixture::public_product())
        .await
        .unwrap_err();
    texts.extend(renderings(&error));
    other.cleanup().await;

    // A wrong administrator password.
    let wrong = random_hex(16);
    secrets.push(wrong.clone());
    let mut url = Url::parse(&fixture.admin_url()).unwrap();
    url.set_password(Some(&wrong)).unwrap();
    secrets.push(url.to_string());
    let admin = admin_config(url.as_str(), Some(&fixture.server.ca)).unwrap();
    let error = execute(&admin, &plan, Mode::Converge).await.unwrap_err();
    assert_eq!(error.code(), "platform.provision.admin-connect-failed");
    assert!(matches!(
        &error,
        ProvisionError::AdminConnectFailed { sqlstate: Some(state) } if state == "28P01"
    ));
    texts.extend(renderings(&error));

    // A changed password.
    fixture
        .server
        .superuser
        .exec(&format!(
            "ALTER ROLE {} PASSWORD '{}'",
            quote(&fixture.migration_name()),
            random_hex(16)
        ))
        .await;
    let error = verify_logins(&fixture.admin(), &fixture.target())
        .await
        .unwrap_err();
    texts.extend(renderings(&error));

    // A URL the executor refuses to read.
    let error: AdminConfigError = admin_config(
        &format!("{}&sslmode=disable", fixture.admin_url()),
        Some(&fixture.server.ca),
    )
    .unwrap_err();
    texts.extend(renderings(&error));

    assert_clean(&texts, &secrets);
    fixture.cleanup().await;
}

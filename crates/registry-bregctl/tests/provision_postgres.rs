// SPDX-License-Identifier: Apache-2.0

//! `bregctl provision` against a real server, then `test`, `package`,
//! `apply` and the runtime on what it created.
//!
//! `PROVISION_TEST_DATABASE_URL` names a disposable PostgreSQL 17 superuser
//! URL with `sslmode=verify-full`, and `PROVISION_TEST_DATABASE_CA` the PEM
//! file its certificate chains to. A spatial package needs a server with
//! PostGIS (`products/breg/scripts/local-postgres-tls.sh` starts one). The
//! administrator sessions of this suite use verified TLS, so the server must
//! offer it. Without the variables the tests fail on the spot: a skipped
//! database test is not database verification.
#![cfg(feature = "postgres-test")]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
use registry_platform_provision::test_support::{connect_verified, provision_test_env};
use registry_platform_testing::{TestActorKind, TestAuthorizationServer, TestClient};
use serde_json::{json, Value};
use uuid::Uuid;

const AUDIENCE: &str = "urn:example:applications";

fn private_file(path: &Path, contents: &[u8]) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Run the built binary with `--format json` and return its exit code and
/// report.
fn ctl(arguments: &[&std::ffi::OsStr]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(["--format", "json"])
        .args(arguments)
        .output()
        .unwrap();
    let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code().unwrap(), report)
}

fn ctl_ok(arguments: &[&std::ffi::OsStr]) -> Value {
    let (code, report) = ctl(arguments);
    assert_eq!(code, 0, "{report:#}");
    report
}

/// A project with one record type. A spatial project adds a polygon field,
/// which makes the generated schema need PostGIS.
fn project(root: &Path, spatial: bool) {
    let mut fields = vec![json!({
        "id": "owner", "type": "string", "required": true,
        "maximumLength": 80, "classification": "internal"
    })];
    let mut readable = vec!["owner"];
    if spatial {
        fields.push(json!({
            "id": "boundary", "type": "crs84-polygon", "precision": 9, "maximumPositions": 100,
            "bbox": {"west": "100.450000000", "south": "13.600000000",
                     "east": "100.700000000", "north": "13.900000000"},
            "required": true, "classification": "internal"
        }));
        readable.push("boundary");
    }
    let registry = json!({
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {
            "id": "provision-proof",
            "canonicalBaseIri": "https://synthetic.example.test/provision-proof",
            "version": "1",
            "defaultLanguage": "en"
        },
        "package": {"sourceRevision": "provision-proof"},
        "datasets": {"notes": {}},
        "recordTypes": {"note": {
            "primaryDataset": "notes", "route": "notes", "mutationMode": "mutable",
            "classification": "internal", "fields": fields
        }},
        "accessProfiles": {"writer": {
            "default": true,
            "principalClaim": "sub",
            "requiredScopes": ["applications:read"],
            "actorKind": "service",
            "requesterClients": ["application-reader"],
            "permissions": {"records": [{
                "recordType": "note",
                "operations": ["list"],
                "readableFields": readable,
                "rowBoundaries": "unrestricted"
            }]}
        }}
    });
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("registry.yaml"),
        serde_norway::to_string(&registry).unwrap(),
    )
    .unwrap();
    let journeys = json!({
        "apiVersion": "id.registrystack.org/formats/breg/journeys/v1",
        "kind": "BRegJourneys",
        "journeys": [{"id": "provision-proof", "steps": [{
            "id": "list", "recordType": "note", "accessProfile": "writer",
            "claims": {"principal": "fixture-reader", "scopes": ["applications:read"],
                       "actorKind": "service", "requesterClient": "application-reader",
                       "directClaims": {}},
            "request": {"type": "list"},
            "expect": {"outcome": "success", "status": 200, "count": 0}
        }]}]
    });
    std::fs::write(
        root.join("tests/journeys.yaml"),
        serde_norway::to_string(&journeys).unwrap(),
    )
    .unwrap();
}

/// One deployment directory, the issuer its tokens come from, and the
/// superuser session that creates the roles `provision` is run from.
struct Deployment {
    directory: tempfile::TempDir,
    admin: tokio_postgres::Client,
    base_url: String,
    ca: Vec<u8>,
    issuer: TestAuthorizationServer,
    suffix: String,
    owner: String,
    owner_password: String,
    migration: String,
    runtime_role: String,
    passwords: [String; 2],
    /// Databases to drop at the end, and roles to drop after them.
    databases: Vec<String>,
}

impl Deployment {
    async fn new() -> Self {
        let (base_url, ca) = provision_test_env();
        let admin = connect_verified(&base_url, &ca, None).await;
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let secrets = directory.path().join("secrets");
        std::fs::create_dir(&secrets).unwrap();
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(directory.path().join("audit")).unwrap();
        private_file(&secrets.join("postgres-ca.pem"), &ca);
        private_file(
            &secrets.join("audit-key"),
            b"synthetic-audit-key-of-at-least-32-bytes",
        );
        private_file(
            &secrets.join("cursor-key"),
            b"synthetic-cursor-key-of-at-least-32-bytes",
        );
        let issuer = TestAuthorizationServer::builder()
            .with_signing_key(generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap())
            .client(
                TestClient::new("application-reader")
                    .with_resource(AUDIENCE)
                    .with_actor_kind(TestActorKind::Service),
            )
            .start()
            .await;
        let jwks = reqwest::get(issuer.jwks_uri())
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        private_file(&secrets.join("jwks"), &jwks);
        let token = issuer.issue_access_token(
            "application-reader",
            "fixture-reader",
            AUDIENCE,
            "applications:read",
            chrono::Utc::now().timestamp() + 3600,
        );
        private_file(&secrets.join("fixture-token"), token.as_bytes());
        let credentials = json!({
            "apiVersion": "id.registrystack.org/formats/breg/schema-test-credentials/v1",
            "kind": "BRegSchemaTestCredentials",
            "bindings": [{"journeyId": "provision-proof", "stepId": "list",
                          "credential": {"type": "bearer", "tokenRef": "secret:file/fixture-token"}}]
        });
        std::fs::write(
            directory.path().join("credentials.yaml"),
            serde_norway::to_string(&credentials).unwrap(),
        )
        .unwrap();

        let suffix = Uuid::new_v4().simple().to_string()[..8].to_owned();
        let password = |purpose: &str| format!("{purpose}-{}", Uuid::new_v4().simple());
        let deployment = Self {
            owner: format!("breg_owner_{suffix}"),
            owner_password: password("owner"),
            migration: format!("breg_mig_{suffix}"),
            runtime_role: format!("breg_rt_{suffix}"),
            passwords: [password("migration"), password("runtime")],
            suffix,
            directory,
            admin,
            base_url,
            ca,
            issuer,
            databases: Vec::new(),
        };
        deployment
            .admin
            .batch_execute(&format!(
                "CREATE ROLE {} LOGIN PASSWORD '{}' NOSUPERUSER CREATEROLE CREATEDB",
                deployment.owner, deployment.owner_password
            ))
            .await
            .unwrap();
        deployment
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    /// A URL for `role` against this server and `database`.
    fn url(&self, role: &str, password: &str, database: &str) -> String {
        let base = registry_platform_provision::admin_config(&self.base_url, Some(&self.ca))
            .expect("PROVISION_TEST_DATABASE_URL is a valid administrator URL");
        format!(
            "postgresql://{role}:{password}@{}:{}/{database}",
            base.host(),
            base.port()
        )
    }

    /// Writes the runtime file `name` for `database` over `package`. The two
    /// database URLs are the only place the roles, the database and the
    /// passwords are written.
    fn write_runtime(&self, name: &str, database: &str, package: &Path, bind: &str) -> String {
        private_file(
            &self.path("secrets").join(format!("{name}-migration-url")),
            self.url(&self.migration, &self.passwords[0], database)
                .as_bytes(),
        );
        private_file(
            &self.path("secrets").join(format!("{name}-runtime-url")),
            self.url(&self.runtime_role, &self.passwords[1], database)
                .as_bytes(),
        );
        let runtime = json!({
            "apiVersion": "id.registrystack.org/formats/breg/runtime/v1alpha1",
            "kind": "BRegRuntimeConfig",
            "listener": {"bind": bind},
            "identity": {"environment": "test", "instanceId": "provision-proof",
                         "databaseId": "provision-proof",
                         "databaseInitializationEnvironment": "test"},
            "secretProviders": {"file": {"root": self.path("secrets")}},
            "database": {
                "runtimeUrlRef": format!("secret:file/{name}-runtime-url"),
                "migrationUrlRef": format!("secret:file/{name}-migration-url"),
                "caBundleRef": "secret:file/postgres-ca.pem",
                "pool": {"maximumConnections": 4},
                "roles": {"migration": self.migration, "runtime": self.runtime_role}
            },
            "package": {"root": package},
            "authentication": {
                "oidc": {
                    "issuer": self.issuer.issuer(), "audience": AUDIENCE,
                    "allowedAlgorithm": "ES256", "accessTokenType": "at+jwt",
                    "scopeClaim": "scope", "scopeSeparator": " ",
                    "allowedClients": ["application-reader"],
                    "maximumTokenLifetimeSeconds": 3600, "leewayMilliseconds": 0,
                    "jwksSource": {"type": "static", "documentRef": "secret:file/jwks"}
                },
                "authorityClaims": {"principal": "sub"}
            },
            "audit": {"hashKeyRef": "secret:file/audit-key", "path": self.path("audit/breg.jsonl")},
            "cursor": {"secretRef": "secret:file/cursor-key"}
        });
        let file = self.path(&format!("{name}.yaml"));
        std::fs::write(&file, serde_norway::to_string(&runtime).unwrap()).unwrap();
        file.display().to_string()
    }

    fn admin_url_file(&self) -> String {
        let file = self.path("admin-url");
        private_file(
            &file,
            self.url(&self.owner, &self.owner_password, "postgres")
                .as_bytes(),
        );
        file.display().to_string()
    }

    /// `provision` as the operate page runs it, from the non-superuser owner.
    fn provision(&self, runtime: &str, package: Option<&Path>) -> (i32, Value) {
        let admin_file = self.admin_url_file();
        let fixed = [
            "provision",
            "--runtime-config",
            runtime,
            "--admin-url-file",
            &admin_file,
        ];
        let mut arguments: Vec<&std::ffi::OsStr> = fixed.iter().map(std::ffi::OsStr::new).collect();
        if let Some(package) = package {
            arguments.push("--package".as_ref());
            arguments.push(package.as_os_str());
        }
        let (code, report) = ctl(&arguments);
        for password in self.passwords.iter().chain([&self.owner_password]) {
            assert!(
                !report.to_string().contains(password.as_str()),
                "the report holds no password"
            );
        }
        (code, report)
    }

    /// The PostGIS objects a spatial `test` needs in an already provisioned
    /// rehearsal database: the operate page's statements, run by the
    /// superuser, because `provision` cannot plan them before a package
    /// exists to ask.
    async fn add_postgis(&self, database: &str) {
        let bbox = format!("{}__spatial_bbox", self.runtime_role);
        let (migration, runtime) = (&self.migration, &self.runtime_role);
        let setup = connect_verified(&self.base_url, &self.ca, Some(database)).await;
        setup
            .batch_execute(&format!(
                "CREATE SCHEMA registry_spatial_ext;\n\
                 REVOKE ALL ON SCHEMA registry_spatial_ext FROM PUBLIC;\n\
                 CREATE EXTENSION postgis WITH SCHEMA registry_spatial_ext;\n\
                 DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{bbox}') THEN \
                   CREATE ROLE {bbox} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS; \
                 END IF; END $$;\n\
                 GRANT {bbox} TO {migration} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;\n\
                 GRANT USAGE ON SCHEMA registry_spatial_ext TO {migration}, {runtime}, {bbox};"
            ))
            .await
            .unwrap();
    }

    /// `test` then `package` over a rehearsal database, returning the
    /// package directory.
    fn build_package(&self, rehearsal_runtime: &str) -> PathBuf {
        let project = self.path("project");
        let receipt = self.path("receipt.json");
        let build = self.path("build");
        ctl_ok(&[
            "test".as_ref(),
            project.as_os_str(),
            "--runtime-config".as_ref(),
            rehearsal_runtime.as_ref(),
            "--credentials".as_ref(),
            self.path("credentials.yaml").as_os_str(),
            "--output".as_ref(),
            receipt.as_os_str(),
        ]);
        ctl_ok(&[
            "package".as_ref(),
            project.as_os_str(),
            "--test-receipt".as_ref(),
            receipt.as_os_str(),
            "--output".as_ref(),
            build.as_os_str(),
        ]);
        build.join("package")
    }

    async fn finish(self) {
        // Dropping a database waits for its sessions to end, which the
        // administrator session's statement timeout would cut short.
        let mut statements: Vec<String> = vec!["SET statement_timeout = 0".to_owned()];
        statements.extend(
            self.databases
                .iter()
                .map(|database| format!("DROP DATABASE IF EXISTS {database} WITH (FORCE)")),
        );
        statements.push(format!(
            "DROP ROLE IF EXISTS {}__spatial_bbox",
            self.runtime_role
        ));
        for role in [&self.runtime_role, &self.migration, &self.owner] {
            statements.push(format!("DROP ROLE IF EXISTS {role}"));
        }
        for statement in statements {
            self.admin.batch_execute(&statement).await.unwrap();
        }
    }
}

fn free_address() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

/// `provision` over the rehearsal and the serving database, `test` and
/// `package` over the first, `apply` over the second, and the runtime
/// started over the runtime credential answers its readiness route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provision_then_apply_then_serve_with_split_roles() {
    let mut deployment = Deployment::new().await;
    project(&deployment.path("project"), false);
    let (rehearsal, live) = (
        format!("breg_rehearsal_{}", deployment.suffix),
        format!("breg_live_{}", deployment.suffix),
    );
    deployment.databases = vec![rehearsal.clone(), live.clone()];
    let empty_package = deployment.path("empty-package");
    std::fs::create_dir(&empty_package).unwrap();

    let rehearsal_runtime =
        deployment.write_runtime("rehearsal", &rehearsal, &empty_package, "127.0.0.1:0");
    let (code, provisioned) = deployment.provision(&rehearsal_runtime, None);
    assert_eq!(code, 0, "{provisioned:#}");
    assert_eq!(provisioned["status"], "complete");
    assert_eq!(provisioned["executed"], true);
    assert_eq!(provisioned["roleMode"], "split");
    assert_eq!(provisioned["database"], rehearsal.as_str());
    let package = deployment.build_package(&rehearsal_runtime);

    let address = free_address();
    let live_runtime = deployment.write_runtime("live", &live, &package, &address);
    let (code, provisioned) = deployment.provision(&live_runtime, None);
    assert_eq!(code, 0, "{provisioned:#}");
    assert_eq!(provisioned["roleMode"], "split");
    assert_eq!(provisioned["database"], live.as_str());
    let (code, again) = deployment.provision(&live_runtime, None);
    assert_eq!(code, 0, "a second run converges: {again:#}");
    for statement in again["statements"].as_array().unwrap() {
        assert_ne!(
            statement["outcome"], "created",
            "a second run creates nothing: {statement}"
        );
    }

    let applied = ctl_ok(&[
        "apply".as_ref(),
        "--runtime-config".as_ref(),
        live_runtime.as_ref(),
        "--package".as_ref(),
        package.as_os_str(),
        "--initial".as_ref(),
    ]);
    assert_eq!(applied["activation"], "initial", "{applied:#}");

    let config = registry_breg::runtime_config::load_runtime_config(Path::new(&live_runtime))
        .expect("the live runtime file loads");
    let prepared = registry_breg::startup::prepare_loaded(config)
        .await
        .expect("the runtime prepares over the runtime role");
    assert_eq!(
        format!("{:?}", prepared.role_mode()).to_lowercase(),
        "split",
        "the runtime serves on separate roles"
    );
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(registry_breg::startup::serve_until_shutdown(
        prepared,
        async move {
            stopped.await.ok();
            Ok(())
        },
    ));
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut ready = false;
    for _ in 0..100 {
        if let Ok(response) = http.get(format!("http://{address}/ready")).send().await {
            if response.status().is_success() {
                ready = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(ready, "the readiness route answers");
    stop.send(()).unwrap();
    server.await.unwrap().expect("the server stops cleanly");
    deployment.finish().await;
}

/// A package with a polygon field needs PostGIS, and `CREATE EXTENSION
/// postgis` needs a superuser, so a non-superuser owner is told which
/// statement needs more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spatial_package_as_a_non_superuser_owner_names_the_postgis_statement() {
    let mut deployment = Deployment::new().await;
    project(&deployment.path("project"), true);
    let (rehearsal, live) = (
        format!("breg_rehearsal_{}", deployment.suffix),
        format!("breg_live_{}", deployment.suffix),
    );
    deployment.databases = vec![rehearsal.clone(), live.clone()];
    let empty_package = deployment.path("empty-package");
    std::fs::create_dir(&empty_package).unwrap();

    // The owner provisions the rehearsal database, then the superuser adds
    // the PostGIS objects `test` needs.
    let rehearsal_runtime =
        deployment.write_runtime("rehearsal", &rehearsal, &empty_package, "127.0.0.1:0");
    let (code, provisioned) = deployment.provision(&rehearsal_runtime, None);
    assert_eq!(code, 0, "{provisioned:#}");
    deployment.add_postgis(&rehearsal).await;
    let package = deployment.build_package(&rehearsal_runtime);

    let live_runtime = deployment.write_runtime("live", &live, &package, "127.0.0.1:0");
    let (code, refused) = deployment.provision(&live_runtime, Some(&package));
    assert_eq!(code, 1, "{refused:#}");
    assert_eq!(refused["status"], "domain-refusal", "{refused:#}");
    let diagnostic = &refused["diagnostics"][0];
    assert_eq!(
        diagnostic["code"], "platform.provision.statement-needs-privilege",
        "{refused:#}"
    );
    assert_eq!(diagnostic["path"], "extension.postgis", "{refused:#}");
    deployment.finish().await;
}

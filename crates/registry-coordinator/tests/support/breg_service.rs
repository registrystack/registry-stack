// SPDX-License-Identifier: Apache-2.0
//! A separately built BReg service, activated through public operator commands.
//! Only fixture-owned databases and roles are provisioned or removed here.

use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::{Duration, Instant},
};

use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig, StaticToken};
use registry_platform_testing::TestAuthorizationServer;
use serde_json::{json, Value};

fn binary(variable: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(variable).unwrap_or_else(|| {
        panic!("{variable} is required; run products/coordinator/scripts/test-breg-action.py")
    }));
    assert!(
        path.is_file(),
        "{variable} must name an existing executable"
    );
    path
}

fn operator(binary: &Path, args: &[&std::ffi::OsStr], log: &Path) {
    let output = Command::new(binary)
        .args(["--format", "json"])
        .args(args)
        .output()
        .expect("independent BReg operator starts");
    let mut bytes = output.stdout;
    bytes.extend_from_slice(&output.stderr);
    crate::support::private_file(log, &bytes);
    assert!(
        output.status.success(),
        "BReg operator failed; inspect {}",
        log.display()
    );
}

fn document(path: &Path, value: Value) {
    crate::support::private_file(path, serde_norway::to_string(&value).unwrap().as_bytes());
}

pub struct Breg {
    pub root: PathBuf,
    pub base_url: String,
    admin_url: String,
    databases: [String; 2],
    roles: [String; 2],
    child: Option<Child>,
}

impl Breg {
    pub async fn start(issuer: &TestAuthorizationServer) -> Self {
        let ctl = binary("COORDINATOR_BREGCTL_BIN");
        let runtime_binary = binary("COORDINATOR_BREG_BIN");
        let admin_url = std::env::var("COORDINATOR_TEST_DATABASE_URL")
            .expect("owned disposable local PostgreSQL URL is required");
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        // Keep private logs on failure. Successful fixtures remove this tree.
        let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap())
            .unwrap()
            .keep();
        let mut service = Self {
            root,
            base_url: String::new(),
            admin_url,
            databases: [
                format!("coord_breg_test_{suffix}"),
                format!("coord_breg_live_{suffix}"),
            ],
            roles: [
                format!("coord_breg_migrate_{suffix}"),
                format!("coord_breg_runtime_{suffix}"),
            ],
            child: None,
        };
        let password = uuid::Uuid::new_v4().simple().to_string();
        let (admin, connection) =
            tokio_postgres::connect(&service.admin_url, tokio_postgres::NoTls)
                .await
                .unwrap();
        let root_connection = tokio::spawn(connection);
        for role in &service.roles {
            admin.batch_execute(&format!(
                "CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{password}'"
            )).await.expect("fixture administrator creates owned role");
        }
        for (index, database) in service.databases.iter().enumerate() {
            admin
                .batch_execute(&format!("CREATE DATABASE {database}"))
                .await
                .unwrap();
            let mut url = url::Url::parse(&service.admin_url).unwrap();
            url.set_path(&format!("/{database}"));
            let (owner, connection) = tokio_postgres::connect(url.as_str(), tokio_postgres::NoTls)
                .await
                .unwrap();
            let database_connection = tokio::spawn(connection);
            owner.batch_execute(&format!(
                "REVOKE ALL ON DATABASE {database} FROM PUBLIC; GRANT CONNECT, TEMPORARY ON DATABASE {database} TO {}; GRANT CONNECT ON DATABASE {database} TO {}",
                service.roles[0], service.roles[1]
            )).await.unwrap();
            // This is deployment provisioning, not BReg runtime behavior.
            // It follows BReg postgres::roles::provision_managed_schemas.
            for schema in [
                "registry_internal",
                "registry_data",
                "registry_source",
                "registry_derived",
                "registry_context",
            ] {
                owner.batch_execute(&format!("CREATE SCHEMA {schema} AUTHORIZATION {}; REVOKE ALL ON SCHEMA {schema} FROM PUBLIC", service.roles[0])).await.unwrap();
            }
            database_connection.abort();
            for (role_index, role) in service.roles.iter().enumerate() {
                url.set_username(role).unwrap();
                url.set_password(Some(&password)).unwrap();
                crate::support::private_file(
                    &service.root.join(format!("database-{index}-{role_index}")),
                    url.as_str().as_bytes(),
                );
            }
        }
        root_connection.abort();
        let project = service.root.join("project");
        std::fs::create_dir_all(project.join("tests")).unwrap();
        document(
            &project.join("registry.yaml"),
            json!({
                "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
                "registry":{"id":"coordinator-action-proof", "canonicalBaseIri":"https://synthetic.example.invalid/action-proof", "version":"1", "defaultLanguage":"en"},
                "package":{"sourceRevision":"coordinator-native-action-proof"},
                "entities":[{"id":"item", "primaryDataset":"synthetic-items", "route":"items", "mutationMode":"mutable", "classification":"internal",
                    "fields":[{"id":"owner", "type":"string", "required":true, "maxLength":80, "classification":"internal"},
                        {"id":"label", "type":"string", "required":true, "minLength":1, "maxLength":80, "classification":"internal"}]}],
                "actions":[{"id":"update-item", "inputs":[
                    {"id":"target", "apiName":"targetId", "type":"reference", "target":"item", "required":true, "classification":"internal"},
                    {"id":"label", "type":"string", "required":true, "minLength":1, "maxLength":80, "classification":"internal"}],
                    "effects":[{"id":"item", "target":{"fromField":"target"}, "operation":"patch", "set":{"label":{"fromField":"label"}}}]}],
                "accessProfiles":[
                    {"id":"writer", "default":true, "principalClaim":"sub", "requiredScopes":["applications:read"], "actorKind":"service", "requesterClients":["application-reader"],
                        "permissions":[{"entity":"item", "operations":["create","get","list"], "readableFields":["owner","label"], "writableFields":["owner","label"],
                            "rowBoundaries":[{"field":"owner", "claim":"sub", "operator":"equals"}]},
                            {"action":"update-item", "operations":["invoke"], "targets":[{"entity":"item", "rowBoundaries":[{"field":"owner", "claim":"sub", "operator":"equals"}]}], "results":["item"]}]},
                    {"id":"reader", "principalClaim":"sub", "requiredScopes":["applications:read"], "actorKind":"service", "requesterClients":["application-reader"],
                        "permissions":[{"entity":"item", "operations":["get"], "readableFields":["owner","label"], "rowBoundaries":[{"field":"owner", "claim":"sub", "operator":"equals"}]}]}
                ]
            }),
        );
        document(
            &project.join("tests/journeys.yaml"),
            json!({
                "apiVersion":"id.registrystack.org/formats/breg/journeys/v1", "kind":"BRegJourneys",
                "journeys":[{"id":"fixture-empty", "steps":[{"id":"list", "entity":"item", "accessProfile":"writer",
                    "claims":{"principal":"poc-reader", "scopes":["applications:read"], "actorKind":"service", "requesterClient":"application-reader", "directClaims":{"sub":"poc-reader"}},
                    "request":{"type":"list"}, "expect":{"outcome":"success", "status":200, "count":0}}]}]
            }),
        );
        let token = issuer.issue_access_token(
            "application-reader",
            "poc-reader",
            "urn:example:applications",
            "applications:read",
            chrono::Utc::now().timestamp() + 300,
        );
        crate::support::private_file(&service.root.join("fixture-token"), token.as_bytes());
        document(
            &service.root.join("credentials.yaml"),
            json!({
                "apiVersion":"id.registrystack.org/formats/breg/schema-test-credentials/v1", "kind":"BRegSchemaTestCredentials",
                "bindings":[{"journeyId":"fixture-empty", "stepId":"list", "credential":{"type":"bearer", "tokenRef":"secret:file/fixture-token"}}]
            }),
        );
        let jwks = reqwest::get(issuer.jwks_uri())
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        crate::support::private_file(&service.root.join("jwks"), &jwks);
        crate::support::private_file(
            &service.root.join("audit-key"),
            b"synthetic-audit-key-of-at-least-32-bytes",
        );
        crate::support::private_file(
            &service.root.join("cursor-key"),
            b"synthetic-cursor-key-of-at-least-32-bytes",
        );
        std::fs::create_dir(service.root.join("empty-package")).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let runtime = |database: usize, package: &Path| {
            json!({
                "apiVersion":"registry.registrystack.org/breg-runtime/v1alpha1", "kind":"BRegRuntimeConfig",
            "listener":{"bind":address.to_string()},
                "identity":{"environment":"test", "instanceId":"coordinator-action-proof", "databaseId":"coordinator-action-proof", "databaseInitializationEnvironment":"test"},
                "secretProviders":{"file":{"root":service.root}},
                "database":{"runtimeUrlRef":format!("secret:file/database-{database}-1"), "migrationUrlRef":format!("secret:file/database-{database}-0"), "testOnlyPlaintext":true,
                    "pool":{"maxSize":4}, "roles":{"migration":service.roles[0], "runtime":service.roles[1]}},
                "package":{"root":package},
                "authentication":{"oidc":{"issuer":issuer.issuer(), "audience":"urn:example:applications", "allowedAlgorithm":"ES256", "accessTokenType":"at+jwt", "scopeClaim":"scope", "scopeSeparator":" ", "allowedClients":["application-reader"],
                    "maxTokenLifetimeSeconds":3600, "leewayMilliseconds":0, "jwksSource":{"kind":"static", "documentRef":"secret:file/jwks"}}, "authorityClaims":{"principal":"sub"}},
                "audit":{"hashKeyRef":"secret:file/audit-key", "path":service.root.join("audit/breg.jsonl")},
                "cursor":{"secretRef":"secret:file/cursor-key"}
            })
        };
        let rehearsal = service.root.join("rehearsal.yaml");
        document(&rehearsal, runtime(0, &service.root.join("empty-package")));
        let receipt = service.root.join("receipt.json");
        operator(
            &ctl,
            &[
                "test".as_ref(),
                project.as_os_str(),
                "--runtime-config".as_ref(),
                rehearsal.as_os_str(),
                "--credentials".as_ref(),
                service.root.join("credentials.yaml").as_os_str(),
                "--output".as_ref(),
                receipt.as_os_str(),
            ],
            &service.root.join("test.log"),
        );
        let build = service.root.join("build");
        operator(
            &ctl,
            &[
                "package".as_ref(),
                project.as_os_str(),
                "--test-receipt".as_ref(),
                receipt.as_os_str(),
                "--output".as_ref(),
                build.as_os_str(),
            ],
            &service.root.join("package.log"),
        );
        let live = service.root.join("live.yaml");
        let package = build.join("package");
        document(&live, runtime(1, &package));
        drop(listener);
        operator(
            &ctl,
            &[
                "apply".as_ref(),
                "--runtime-config".as_ref(),
                live.as_os_str(),
                "--package".as_ref(),
                package.as_os_str(),
                "--initial".as_ref(),
            ],
            &service.root.join("apply.log"),
        );
        let log_path = service.root.join("service.log");
        crate::support::private_file(&log_path, b"");
        let log = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        service.child = Some(
            Command::new(runtime_binary)
                .arg("--runtime-config")
                .arg(live)
                .stdout(Stdio::from(log.try_clone().unwrap()))
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap(),
        );
        service.base_url = format!("http://{address}");
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(
                service
                    .child
                    .as_mut()
                    .unwrap()
                    .try_wait()
                    .unwrap()
                    .is_none(),
                "BReg exited; inspect {}",
                log_path.display()
            );
            if http
                .get(format!("{}/ready", service.base_url))
                .timeout(Duration::from_secs(2))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "BReg not ready; inspect {}",
                log_path.display()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        service
    }

    pub fn client(&self, issuer: &TestAuthorizationServer) -> BaseRegistryClient {
        let token = issuer.issue_access_token(
            "application-reader",
            "poc-reader",
            "urn:example:applications",
            "applications:read",
            chrono::Utc::now().timestamp() + 300,
        );
        BaseRegistryClient::new(
            BaseRegistryClientConfig::new(self.base_url.parse().unwrap())
                .with_token_provider(std::sync::Arc::new(StaticToken::new(token).unwrap()))
                .with_max_mutation_retries(0),
        )
        .unwrap()
    }

    pub fn finish(self) {
        let root = self.root.clone();
        drop(self);
        std::fs::remove_dir_all(root).unwrap();
    }
}

impl Drop for Breg {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let admin_url = self.admin_url.clone();
        let databases = self.databases.clone();
        let roles = self.roles.clone();
        // Cleanup also runs on assertion failure, on a separate runtime because
        // Drop can run inside Tokio. FORCE targets only generated fixture DBs.
        let result = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let (admin, connection) =
                        tokio_postgres::connect(&admin_url, tokio_postgres::NoTls).await?;
                    let task = tokio::spawn(connection);
                    for database in databases {
                        admin
                            .batch_execute(&format!(
                                "DROP DATABASE IF EXISTS {database} WITH (FORCE)"
                            ))
                            .await?;
                    }
                    for role in roles {
                        admin
                            .batch_execute(&format!("DROP ROLE IF EXISTS {role}"))
                            .await?;
                    }
                    task.abort();
                    Ok::<(), tokio_postgres::Error>(())
                })
        })
        .join();
        if !matches!(result, Ok(Ok(()))) {
            eprintln!("fixture-owned BReg database cleanup failed");
        }
    }
}

pub struct LostResponse {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    pub base_url: String,
}

impl LostResponse {
    pub fn start(origin: &str) -> Self {
        Self::start_for(
            origin,
            "/v1/actions/update-item?accessProfile=writer",
            false,
        )
    }

    pub fn observe_action(origin: &str) -> Self {
        Self::start_for(origin, "/v1/actions/update-item?accessProfile=writer", true)
    }

    pub fn start_notice(origin: &str) -> Self {
        Self::start_for(origin, "/v1/messages", false)
    }

    fn start_for(origin: &str, mutation_path: &str, observe_only: bool) -> Self {
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/coordinator/scripts/test-breg-action.py");
        let mut command = Command::new("python3");
        command
            .arg(script)
            .arg("--proxy-origin")
            .arg(origin)
            .arg("--mutation-path")
            .arg(mutation_path);
        if observe_only {
            command.arg("--observe-only");
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut base_url = String::new();
        output.read_line(&mut base_url).unwrap();
        assert!(
            base_url.starts_with("http://127.0.0.1:"),
            "lost-response proxy starts"
        );
        Self {
            child,
            input,
            output,
            base_url: base_url.trim().into(),
        }
    }

    pub fn observations(&mut self) -> Value {
        writeln!(self.input, "observations").unwrap();
        self.input.flush().unwrap();
        let mut result = String::new();
        self.output.read_line(&mut result).unwrap();
        serde_json::from_str(&result).unwrap()
    }
}

impl Drop for LostResponse {
    fn drop(&mut self) {
        let _ = writeln!(self.input, "close");
        let _ = self.input.flush();
        let _ = self.child.wait();
    }
}

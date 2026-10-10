// SPDX-License-Identifier: Apache-2.0
//! The ordinary package/apply/service path against real PostgreSQL and OIDC.
#![cfg(feature = "postgres-test")]
use chrono::Utc;
use registry_coordinator::{
    adapters::HttpAdapters,
    deployment,
    http::{self, HttpState},
    project,
    runtime::RuntimeConfig,
};
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
use registry_platform_testing::{TestAuthorizationServer, TestClient};
use serde_json::{json, Value};
use std::{fs, sync::Arc};
use uuid::Uuid;
fn private(path: &std::path::Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
// Execute the actual binary, with one process-owned ctl audit companion.
fn local_cli(path: &std::path::Path, command: &str, success: bool) -> Value {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["--format", "json", "--runtime-config"])
        .arg(path)
        .arg(command)
        .output()
        .unwrap();
    assert_eq!(
        output.status.success(),
        success,
        "{command}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["kind"], "CoordinatorCtlReport");
    assert_eq!(report["ok"], success);
    assert!(report["diagnostics"].is_array());
    report
}
async fn serve_fixture(state: HttpState) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, http::router(state)).await.unwrap();
    });
    (origin, task)
}
async fn assert_status_audit(
    http: &reqwest::Client,
    origin: &str,
    credential: &str,
    run: &str,
    audit_path: &std::path::Path,
    expected_status: u16,
    expected_outcome: &str,
) {
    let before = fs::read_to_string(audit_path).unwrap().lines().count();
    let response = http
        .get(format!("{origin}/v1/runs/{run}"))
        .bearer_auth(credential)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), expected_status);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: Value = response.json().await.unwrap();
    if expected_status == 200 {
        assert_eq!(body["runId"], run);
        assert_eq!(body["workflowId"], "delayed-follow-up");
    } else {
        assert_eq!(body["code"], "coordinator.command.run-absent");
        assert!(body.get("runId").is_none());
    }
    let entries = fs::read_to_string(audit_path)
        .unwrap()
        .lines()
        .skip(before)
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 2, "one status request has one audit pair");
    assert_eq!(entries[0]["phase"], "request");
    assert_eq!(entries[1]["phase"], "response");
    assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
    for entry in &entries {
        assert_eq!(entry["record"]["action"], "status");
    }
    assert_eq!(entries[1]["record"]["outcome"], expected_outcome);
}
async fn assert_authenticated_run_validation(
    http: &reqwest::Client,
    origin: &str,
    database: &str,
    namespace: &str,
    operator: &str,
    producer: &str,
) {
    let routes = [
        ("GET", ""),
        ("GET", "/inspect"),
        ("POST", "/retry-same"),
        ("POST", "/cancel"),
        ("POST", "/reconcile"),
    ];
    let absent = Uuid::new_v4().to_string();
    let long_id = "x".repeat(46);
    let (mut locker, connection) = tokio_postgres::connect(database, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let lock = locker.transaction().await.unwrap();
    lock.batch_execute(&format!(
        "LOCK TABLE {namespace}.runs IN ACCESS EXCLUSIVE MODE"
    ))
    .await
    .unwrap();
    // Authentication, action refusal and malformed identifiers must answer
    // while any attempted run lookup would be blocked by this table lock.
    let checks = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for (method, suffix) in routes {
            for id in ["not-a-uuid", &long_id, "%FF", &absent] {
                for credential in [None, Some("not.a.valid-token")] {
                    let mut request = http
                        .request(
                            method.parse().unwrap(),
                            format!("{origin}/v1/runs/{id}{suffix}"),
                        )
                        .header("content-type", "application/json")
                        .body("{");
                    if let Some(credential) = credential {
                        request = request.bearer_auth(credential);
                    }
                    let response = request.send().await.unwrap();
                    assert_eq!(
                        response.status(),
                        401,
                        "{method} {suffix} refuses credentials first"
                    );
                    assert_eq!(response.headers()["www-authenticate"], "Bearer");
                    assert_eq!(response.headers()["cache-control"], "no-store");
                    assert_eq!(
                        response.json::<Value>().await.unwrap()["code"],
                        "coordinator.access.unauthenticated"
                    );
                }
            }
            for id in ["not-a-uuid", &long_id, "%FF"] {
                let response = http
                    .request(
                        method.parse().unwrap(),
                        format!("{origin}/v1/runs/{id}{suffix}"),
                    )
                    .bearer_auth(operator)
                    .header("content-type", "application/json")
                    .body("{")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), 400);
                assert!(response.headers().get("www-authenticate").is_none());
                let problem = response.json::<Value>().await.unwrap();
                assert_eq!(problem["code"], "coordinator.request.invalid");
                assert!(!problem.to_string().contains(id));
            }
            if !suffix.is_empty() {
                let response = http
                    .request(
                        method.parse().unwrap(),
                        format!("{origin}/v1/runs/not-a-uuid{suffix}"),
                    )
                    .bearer_auth(producer)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), 403);
                assert!(response.headers().get("www-authenticate").is_none());
                assert_eq!(
                    response.json::<Value>().await.unwrap()["code"],
                    "coordinator.access.denied"
                );
            }
        }
        for query in [
            "limit=not-an-integer",
            "limit=0",
            "limit=101",
            "unknown=1",
            "limit=1&limit=2",
        ] {
            for (credential, expected, code) in [
                (None, 401, "coordinator.access.unauthenticated"),
                (
                    Some("not.a.valid-token"),
                    401,
                    "coordinator.access.unauthenticated",
                ),
                (Some(operator), 400, "coordinator.request.invalid"),
            ] {
                let mut request = http.get(format!("{origin}/v1/runs?{query}"));
                if let Some(credential) = credential {
                    request = request.bearer_auth(credential);
                }
                let response = request.send().await.unwrap();
                assert_eq!(response.status(), expected);
                assert_eq!(
                    response
                        .headers()
                        .get("www-authenticate")
                        .map(|value| value.to_str().unwrap()),
                    if expected == 401 {
                        Some("Bearer")
                    } else {
                        None
                    }
                );
                assert_eq!(response.json::<Value>().await.unwrap()["code"], code);
            }
        }
    })
    .await;
    lock.rollback().await.unwrap();
    assert!(
        checks.is_ok(),
        "authentication or malformed input attempted a run database read"
    );
    // The accepted UUID syntaxes still reach the authorized absence lookup.
    for id in [
        absent.clone(),
        absent.replace('-', ""),
        format!("{{{absent}}}"),
        format!("urn:uuid:{absent}"),
    ] {
        for (method, suffix) in routes {
            let response = http
                .request(
                    method.parse().unwrap(),
                    format!("{origin}/v1/runs/{id}{suffix}"),
                )
                .bearer_auth(operator)
                .header("content-type", "application/json")
                .body("{")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 404);
            assert!(response.headers().get("www-authenticate").is_none());
        }
    }
    // Transport body bounds remain before product parsing or authorization.
    let oversized = http
        .post(format!("{origin}/v1/runs/{absent}/cancel"))
        .body("x".repeat(65_537))
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), 413);
}
async fn fixture_job_state(
    admin: &tokio_postgres::Client,
    namespace: &str,
    run: Uuid,
    state: &str,
    uncertain: bool,
) {
    admin.execute(&format!("UPDATE {namespace}.jobs SET state=$2,uncertain=$3,attempt=GREATEST(attempt,1),next_attempt_at=CASE WHEN $2='pending' THEN clock_timestamp() ELSE NULL END,attempt_started_at=NULL,lease_expires_at=NULL,lease_token=NULL,delivered_at=CASE WHEN $2='delivered' THEN clock_timestamp() ELSE NULL END,dead_lettered_at=CASE WHEN $2='dead-lettered' THEN clock_timestamp() ELSE NULL END,expired_at=CASE WHEN $2='expired' THEN clock_timestamp() ELSE NULL END,failure_code=NULL WHERE run_id=$1"), &[&run,&state,&uncertain]).await.unwrap();
}
struct ServiceProcess(std::process::Child);
impl std::ops::Deref for ServiceProcess {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for ServiceProcess {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ServiceProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn spawn_service(path: &std::path::Path, recovery_only: bool) -> ServiceProcess {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_coordinator"));
    command.arg("--runtime-config").arg(path);
    if recovery_only {
        command.arg("--recovery-only");
    }
    ServiceProcess(
        command
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    )
}
async fn await_service_exit(child: &mut ServiceProcess) -> std::process::ExitStatus {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("bounded service fixture did not exit");
    })
}
async fn stop_service(child: &mut ServiceProcess) {
    assert!(std::process::Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .unwrap()
        .success());
    assert!(await_service_exit(child).await.success());
}
async fn assert_bounded_readiness(
    http: &reqwest::Client,
    origin: &str,
    database: &str,
    namespace: &str,
) {
    assert_eq!(
        http.get(format!("{origin}/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let (mut locker, connection) = tokio_postgres::connect(database, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let lock = locker.transaction().await.unwrap();
    lock.query_one(
        &format!("SELECT id FROM {namespace}.admission_lock WHERE id FOR UPDATE"),
        &[],
    )
    .await
    .unwrap();
    // Probes may read fresh control/custody state, but must neither rescan live
    // snapshots under the admission lock nor calculate doctor's run counts.
    lock.batch_execute(&format!(
        "LOCK TABLE {namespace}.runs IN ACCESS EXCLUSIVE MODE"
    ))
    .await
    .unwrap();
    let probes = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut pending = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let http = http.clone();
            let url = format!("{origin}/ready");
            pending.spawn(async move { http.get(url).send().await.unwrap().status() });
        }
        while let Some(result) = pending.join_next().await {
            assert_eq!(result.unwrap(), 200);
        }
    })
    .await;
    lock.rollback().await.unwrap();
    assert!(
        probes.is_ok(),
        "repeated readiness probes waited for live-work locks"
    );
    // A successful cached binding inspection never caches mutable recovery or
    // key-custody decisions. Each change must be visible on the next probe.
    for column in ["restore_hold", "admissions_hold"] {
        locker
            .batch_execute(&format!(
                "UPDATE {namespace}.control SET {column}=true WHERE id"
            ))
            .await
            .unwrap();
        assert_eq!(
            http.get(format!("{origin}/ready"))
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
        locker
            .batch_execute(&format!(
                "UPDATE {namespace}.control SET {column}=false WHERE id"
            ))
            .await
            .unwrap();
        assert_eq!(
            http.get(format!("{origin}/ready"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }
    let marker: String = locker
        .query_one(
            &format!("SELECT admission_key_commitment FROM {namespace}.control WHERE id"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    locker
        .execute(
            &format!("UPDATE {namespace}.control SET admission_key_commitment=$1 WHERE id"),
            &[&"wrong-key"],
        )
        .await
        .unwrap();
    assert_eq!(
        http.get(format!("{origin}/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    locker
        .execute(
            &format!("UPDATE {namespace}.control SET admission_key_commitment=$1 WHERE id"),
            &[&marker],
        )
        .await
        .unwrap();
    assert_eq!(
        http.get(format!("{origin}/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}
async fn assert_other_revision_refused(
    admin: &tokio_postgres::Client,
    namespace: &str,
    migration: &registry_coordinator::store::Store,
    runtime: &RuntimeConfig,
    package: &deployment::LoadedPackage,
    store: &registry_coordinator::store::Store,
) {
    let rows_sql = format!(
        "SELECT jsonb_build_object(
            'runs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY run_id) FROM {namespace}.runs r),
            'jobs',(SELECT jsonb_agg(to_jsonb(j) ORDER BY run_id,step) FROM {namespace}.jobs j),
            'ledger',(SELECT jsonb_agg(version ORDER BY version) FROM {namespace}.coordinator_migrations))"
    );
    let before: Value = admin.query_one(&rows_sql, &[]).await.unwrap().get(0);
    assert!(!before["runs"].as_array().unwrap().is_empty());
    assert!(!before["jobs"].as_array().unwrap().is_empty());
    assert_eq!(before["ledger"], json!([4]));
    // A store is created at one revision. Neither serving nor explicit apply
    // changes a database that records another one, in control or in the ledger.
    for (damage, repair, code) in [
        (
            format!(
                "ALTER TABLE {namespace}.control DROP CONSTRAINT control_schema_version_check;
                UPDATE {namespace}.control SET schema_version=3 WHERE id"
            ),
            format!(
                "UPDATE {namespace}.control SET schema_version=4 WHERE id;
                ALTER TABLE {namespace}.control ADD CONSTRAINT control_schema_version_check CHECK(schema_version=4)"
            ),
            "coordinator.command.schema-version",
        ),
        (
            format!("INSERT INTO {namespace}.coordinator_migrations VALUES(3)"),
            format!("DELETE FROM {namespace}.coordinator_migrations WHERE version=3"),
            "coordinator.deployment.refused",
        ),
    ] {
        admin.batch_execute(&damage).await.unwrap();
        let damaged: Value = admin.query_one(&rows_sql, &[]).await.unwrap().get(0);
        assert!(deployment::check(store, runtime, &package.digest)
            .await
            .is_err());
        for _ in 0..2 {
            let error = deployment::apply(migration, runtime, package)
                .await
                .unwrap_err();
            assert_eq!(error.code, code);
            assert!([Some(error.message.as_str()), error.suggested_action.as_deref()]
                .into_iter()
                .flatten()
                .any(|text| text.contains("apply to a new database")));
            let after: Value = admin.query_one(&rows_sql, &[]).await.unwrap().get(0);
            assert_eq!(after, damaged, "a refused apply changes nothing");
        }
        admin.batch_execute(&repair).await.unwrap();
        deployment::check(store, runtime, &package.digest)
            .await
            .unwrap();
    }
    let after: Value = admin.query_one(&rows_sql, &[]).await.unwrap().get(0);
    assert_eq!(after, before);
}
// Listener polling is cheap, but readiness performs the complete database and
// audit checks. Its deadline is the overall budget, not a 200ms health-probe
// assumption. Retain only fixed transport categories and numeric statuses.
async fn probe_service_readiness(
    http: &reqwest::Client,
    origin: &str,
    budget: std::time::Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + budget;
    let mut stage = "listener";
    let mut last_status = None;
    let mut last_failure = "none";
    let result = tokio::time::timeout_at(deadline, async {
        loop {
            let mut request = http.get(format!(
                "{origin}/{}",
                if stage == "listener" {
                    "health"
                } else {
                    "ready"
                }
            ));
            if stage == "listener" {
                request = request.timeout(std::time::Duration::from_millis(200));
            }
            match request.send().await {
                Ok(response) => {
                    last_status = Some(response.status().as_u16());
                    last_failure = "none";
                    if response.status() == 200 {
                        if stage == "readiness" {
                            return;
                        }
                        stage = "readiness";
                        last_status = None;
                        continue;
                    }
                }
                Err(error) => {
                    last_failure = if error.is_timeout() {
                        "timeout"
                    } else if error.is_connect() {
                        "connect"
                    } else {
                        "transport"
                    };
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    result.map_err(|_| format!("stage={stage}, last_status={last_status:?}, last_transport_failure={last_failure}, overall_budget_elapsed=true"))
}

#[tokio::test]
async fn readiness_probe_uses_overall_budget_for_database_evaluation() {
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };
    let service = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&service)
        .await;
    Mock::given(method("GET"))
        .and(path("/ready"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_millis(300)))
        .expect(1)
        .mount(&service)
        .await;
    probe_service_readiness(
        &reqwest::Client::new(),
        &service.uri(),
        std::time::Duration::from_secs(2),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn readiness_probe_never_accepts_health_or_unready_as_ready() {
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };
    let service = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&service)
        .await;
    Mock::given(method("GET"))
        .and(path("/ready"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&service)
        .await;
    let error = probe_service_readiness(
        &reqwest::Client::new(),
        &service.uri(),
        std::time::Duration::from_millis(300),
    )
    .await
    .unwrap_err();
    assert!(error.contains("stage=readiness"));
    assert!(error.contains("last_status=Some(503)"));
    assert!(error.contains("overall_budget_elapsed=true"));
}

#[tokio::test]
async fn split_activation_and_real_router_enforce_owned_progress_and_operator_recovery() {
    let database = std::env::var("COORDINATOR_TEST_DATABASE_URL")
        .expect("COORDINATOR_TEST_DATABASE_URL names a disposable PostgreSQL 17+ database");
    let (admin, connection) = tokio_postgres::connect(&database, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let project_path = root_path.join("project");
    project::init(&project_path).unwrap();
    let package_path = root_path.join("package");
    let digest = deployment::package(&project_path, &package_path).unwrap();
    let suffix = Uuid::new_v4().simple().to_string();
    let role = format!("coord_{suffix}");
    let namespace = format!("coordinator_{suffix}");
    let password = Uuid::new_v4().simple().to_string();
    admin.batch_execute(&format!("CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS")).await.unwrap();
    let mut runtime_url =
        url::Url::parse(&database).expect("test DB URL is a local PostgreSQL URL");
    runtime_url.set_username(&role).unwrap();
    runtime_url.set_password(Some(&password)).unwrap();
    private(
        &root_path.join("runtime-url"),
        runtime_url.as_str().as_bytes(),
    );
    private(&root_path.join("migration-url"), database.as_bytes());
    // Binary key custody accepts every byte value, including NUL.
    for (name, byte) in [("state-key", 71), ("admission-key", 72), ("audit-key", 73)] {
        let mut key = [byte; 32];
        key[7] = 0;
        private(&root_path.join(name), &key);
    }
    let issuer = TestAuthorizationServer::builder()
        .with_signing_key(generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap())
        .client(TestClient::new("producer"))
        .client(TestClient::new("operator"))
        .start()
        .await;
    private(
        &root_path.join("reader-jwk"),
        registry_platform_testing::fixtures::ED25519_PRIVATE_JWK.as_bytes(),
    );
    private(
        &root_path.join("notices-jwk"),
        registry_platform_testing::fixtures::ED25519_PRIVATE_JWK.as_bytes(),
    );
    let path = root_path.join("runtime.yaml");
    let template = include_str!("../../../products/coordinator/examples/pilot-runtime.yaml");
    let mut doc: Value = yaml_value(
        template,
        registry_coordinator::runtime::API_VERSION,
        registry_coordinator::runtime::KIND,
    )
    .unwrap();
    doc["namespace"] = json!(namespace);
    doc["secretProviders"]["file"]["root"] = json!(&root_path);
    doc["database"]["runtimeUrlRef"] = json!("secret:file/runtime-url");
    doc["database"]["migrationUrlRef"] = json!("secret:file/migration-url");
    doc["database"]
        .as_object_mut()
        .unwrap()
        .remove("trustedRootCertificateRef");
    let d = &mut doc["deployment"];
    d["databaseId"] = json!("router-pilot-test");
    d["runtimeRole"] = json!(role);
    d["package"] = json!({"root":package_path,"expectedDigest":digest});
    d["listener"] = json!({"bind":"127.0.0.1:0","tlsTermination":"development-loopback"});
    d["auditFile"] = json!(root_path.join("audit.jsonl"));
    d["stateKeys"] = json!({"1":{"keyRef":"secret:file/state-key"}});
    d["admissionKeyRef"] = json!("secret:file/admission-key");
    d["auditKeyRef"] = json!("secret:file/audit-key");
    d["authentication"] = json!({"issuer":issuer.issuer(),"audience":"urn:coordinator:test","scopeClaim":"scope","jwksSource":{"type":"uri","uri":issuer.jwks_uri()},"allowedClients":["producer","operator"],"policies":[{"clientId":"producer","requiredScopes":["coordinator:start"],"flows":["delayed-follow-up"],"actions":["start","status"]},{"clientId":"operator","requiredScopes":["coordinator:operate"],"flows":["delayed-follow-up"],"actions":["status","inspect","retry-same","cancel","reconcile","doctor","restore-hold","release-restore-hold","release-admission-hold","complete-execution-recovery","retain"],"operator":true}]});
    fs::write(&path, serde_norway::to_string(&doc).unwrap()).unwrap();
    let runtime = Arc::new(RuntimeConfig::load(&path).unwrap());
    let package =
        Arc::new(deployment::load_package(deployment::config(&runtime).unwrap()).unwrap());
    let migration = deployment::open_ctl(&runtime, true).await.unwrap();
    deployment::apply(&migration, &runtime, &package)
        .await
        .unwrap();
    let apply_audit = fs::read_to_string(migration.audit_writer().path().unwrap()).unwrap();
    let apply_entries = apply_audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(apply_entries.len(), 2);
    assert_eq!(apply_entries[0]["record"]["action"], "activation.apply");
    assert_eq!(apply_entries[0]["phase"], "request");
    assert_eq!(apply_entries[1]["phase"], "response");
    assert_eq!(
        apply_entries[0]["correlation"],
        apply_entries[1]["correlation"]
    );
    for entry in apply_entries {
        assert_eq!(entry["schema"], "registry-coordinator/audit/v1");
    }
    drop(migration);
    let store = deployment::open(&runtime, false).await.unwrap();
    deployment::check(&store, &runtime, &package.digest)
        .await
        .unwrap();
    let mut wrong_identity = (*runtime).clone();
    wrong_identity.deployment.as_mut().unwrap().database_id = "wrong-database".into();
    assert!(deployment::check(&store, &wrong_identity, &package.digest)
        .await
        .is_err());
    // Status validates with runtime credentials only; even an absent migration
    // credential must not affect it. Plan remains a non-validating observation.
    let status_path = root_path.join("status-runtime.yaml");
    let mut status_doc = doc.clone();
    status_doc["database"]["migrationUrlRef"] = json!("secret:file/absent-migration-url");
    fs::write(&status_path, serde_norway::to_string(&status_doc).unwrap()).unwrap();
    let active_before: Value = admin
        .query_one(
            &format!("SELECT to_jsonb(c) FROM {namespace}.control c"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let activation_count: i64 = admin
        .query_one(
            &format!("SELECT count(*) FROM {namespace}.coordinator_activations"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        local_cli(&status_path, "plan", true)["packageDigest"],
        digest
    );
    status_doc["deployment"]["databaseId"] = json!("wrong-database");
    fs::write(&status_path, serde_norway::to_string(&status_doc).unwrap()).unwrap();
    assert_eq!(
        local_cli(&status_path, "plan", true)["databaseId"],
        "wrong-database"
    );
    assert_eq!(
        local_cli(&status_path, "deployment-status", false)["diagnostics"][0]["code"],
        "coordinator.deployment.refused"
    );
    status_doc["deployment"]["databaseId"] = json!("router-pilot-test");
    fs::write(&status_path, serde_norway::to_string(&status_doc).unwrap()).unwrap();
    let checked = local_cli(&status_path, "deployment-status", true);
    assert_eq!(checked["status"], "checked");
    assert_eq!(checked["databaseId"], "router-pilot-test");
    assert_eq!(checked["packageDigest"], digest);
    assert_eq!(checked["schemaVersion"], 4);
    assert_eq!(checked["runtimeRole"], role);
    assert_eq!(checked["active"]["roleMode"], "split");
    status_doc["deployment"]["runtimeRole"] = json!("wrong_runtime_role");
    fs::write(&status_path, serde_norway::to_string(&status_doc).unwrap()).unwrap();
    assert_eq!(
        local_cli(&status_path, "plan", true)["runtimeRole"],
        "wrong_runtime_role"
    );
    let wrong_role = local_cli(&status_path, "deployment-status", false);
    assert_eq!(
        wrong_role["diagnostics"][0]["code"],
        "coordinator.deployment.refused"
    );
    assert!(wrong_role["diagnostics"][0]["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("runtimeRole"));
    status_doc["deployment"]["runtimeRole"] = json!(role);
    fs::write(&status_path, serde_norway::to_string(&status_doc).unwrap()).unwrap();
    local_cli(&status_path, "deployment-status", true);
    // The trusted migration owner simulates inconsistent activation metadata.
    // Status must validate this name separately from the configured role.
    admin.batch_execute(&format!("UPDATE {namespace}.coordinator_activations SET runtime_role='wrong_activation_role' WHERE apply_order=(SELECT max(apply_order) FROM {namespace}.coordinator_activations)")).await.unwrap();
    assert_eq!(
        local_cli(&status_path, "plan", true)["active"]["runtimeRole"],
        "wrong_activation_role"
    );
    assert_eq!(
        local_cli(&status_path, "deployment-status", false)["diagnostics"][0]["code"],
        "coordinator.deployment.refused"
    );
    admin.batch_execute(&format!("UPDATE {namespace}.coordinator_activations SET runtime_role='{role}' WHERE apply_order=(SELECT max(apply_order) FROM {namespace}.coordinator_activations)")).await.unwrap();
    local_cli(&status_path, "deployment-status", true);
    let other_project = root_path.join("other-project");
    project::init(&other_project).unwrap();
    let functions = other_project.join("functions.rhai");
    fs::write(
        &functions,
        format!(
            "{}\n// A different checked package.\n",
            fs::read_to_string(&functions).unwrap()
        ),
    )
    .unwrap();
    let other_package = root_path.join("other-package");
    let other_digest = deployment::package(&other_project, &other_package).unwrap();
    assert_ne!(other_digest, digest);
    status_doc["deployment"]["package"] =
        json!({"root":other_package,"expectedDigest":other_digest});
    fs::write(&status_path, serde_norway::to_string(&status_doc).unwrap()).unwrap();
    assert_eq!(
        local_cli(&status_path, "plan", true)["packageDigest"],
        other_digest
    );
    assert_eq!(
        local_cli(&status_path, "deployment-status", false)["diagnostics"][0]["code"],
        "coordinator.deployment.refused"
    );
    status_doc["deployment"]["package"] = doc["deployment"]["package"].clone();
    fs::write(&status_path, serde_norway::to_string(&status_doc).unwrap()).unwrap();
    // A ledger holding another revision, stale effective table grants, and forbidden
    // control write authority all refuse status while plan still reports observation.
    for (damage, repair) in [
        (
            format!("INSERT INTO {namespace}.coordinator_migrations VALUES(5)"),
            format!("DELETE FROM {namespace}.coordinator_migrations WHERE version=5"),
        ),
        (
            format!("REVOKE SELECT ON {namespace}.jobs FROM {role}"),
            format!("GRANT SELECT ON {namespace}.jobs TO {role}"),
        ),
        (
            format!("GRANT UPDATE(database_id) ON {namespace}.control TO {role}"),
            format!("REVOKE UPDATE(database_id) ON {namespace}.control FROM {role}"),
        ),
    ] {
        admin.batch_execute(&damage).await.unwrap();
        local_cli(&status_path, "plan", true);
        assert_eq!(
            local_cli(&status_path, "deployment-status", false)["diagnostics"][0]["code"],
            "coordinator.deployment.refused"
        );
        admin.batch_execute(&repair).await.unwrap();
        local_cli(&status_path, "deployment-status", true);
    }
    assert_eq!(
        admin
            .query_one(
                &format!("SELECT to_jsonb(c) FROM {namespace}.control c"),
                &[]
            )
            .await
            .unwrap()
            .get::<_, Value>(0),
        active_before
    );
    assert_eq!(
        admin
            .query_one(
                &format!("SELECT count(*) FROM {namespace}.coordinator_activations"),
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        activation_count
    );
    let runtime_connection = tokio_postgres::connect(runtime_url.as_str(), tokio_postgres::NoTls)
        .await
        .unwrap();
    let runtime_client = runtime_connection.0;
    tokio::spawn(async move {
        let _ = runtime_connection.1.await;
    });
    assert!(runtime_client
        .batch_execute(&format!("DELETE FROM {namespace}.coordinator_activations"))
        .await
        .is_err());
    assert!(runtime_client
        .batch_execute(&format!("CREATE TABLE {namespace}.forbidden(id int)"))
        .await
        .is_err());
    assert!(runtime_client
        .batch_execute(&format!(
            "UPDATE {namespace}.control SET active_package_digest='forged' WHERE id"
        ))
        .await
        .is_err());
    assert!(runtime_client
        .batch_execute(&format!(
            "UPDATE {namespace}.control SET admission_key_commitment='forged' WHERE id"
        ))
        .await
        .is_err());
    let d = deployment::config(&runtime).unwrap();
    let authenticator = Arc::new(
        d.authentication
            .authenticator(&runtime.secret_providers, true)
            .await
            .unwrap(),
    );
    let adapters = Arc::new(HttpAdapters::new(&runtime).unwrap());
    let recovery_authenticator = authenticator.clone();
    let recovery_adapters = adapters.clone();
    let recovery_store = store.clone();
    let recovery_runtime = runtime.clone();
    let recovery_package = package.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            http::router(HttpState {
                recovery_only: false,
                store,
                runtime,
                package,
                authenticator,
                adapters,
            }),
        )
        .await
        .unwrap();
    });
    let http = reqwest::Client::new();
    let token = |client, subject, scope| {
        issuer.issue_access_token(
            client,
            subject,
            "urn:coordinator:test",
            scope,
            Utc::now().timestamp() + 300,
        )
    };
    let a = token("producer", "owner-a", "coordinator:start");
    let b = token("producer", "owner-b", "coordinator:start");
    let op = token("operator", "operator-1", "coordinator:operate");
    assert_authenticated_run_validation(&http, &origin, &database, &namespace, &op, &a).await;
    let input = json!({"applicationId":"00000000-0000-4000-8000-000000000001","sendAfter":(Utc::now()+chrono::Duration::minutes(20)).to_rfc3339()});
    assert_bounded_readiness(&http, &origin, &database, &namespace).await;
    let long_key = "x".repeat(257);
    for key in [None, Some(""), Some(long_key.as_str())] {
        for (credential, expected, code) in [
            (None, 401, "coordinator.access.unauthenticated"),
            (Some(&op), 403, "coordinator.access.denied"),
            (Some(&a), 400, "coordinator.command.start-key-invalid"),
        ] {
            let mut request = http
                .post(format!("{origin}/v1/runs"))
                .json(&json!({"flow":"delayed-follow-up","input":input}));
            if let Some(key) = key {
                request = request.header("Idempotency-Key", key);
            }
            if let Some(credential) = credential {
                request = request.bearer_auth(credential);
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), expected);
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.json::<Value>().await.unwrap()["code"], code);
        }
    }
    let refused_counts = admin
        .query_one(
            &format!("SELECT (SELECT count(*) FROM {namespace}.runs), (SELECT count(*) FROM {namespace}.jobs)"),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        (
            refused_counts.get::<_, i64>(0),
            refused_counts.get::<_, i64>(1)
        ),
        (0, 0),
        "malformed start keys create no admission or dispatch job"
    );
    // A different config is initially compatible with an empty deployment.
    // Another old-config instance may admit work after this startup check.
    let mut drift = (*recovery_runtime).clone();
    drift.connections.get_mut("applications").unwrap().base_url =
        "http://127.0.0.1:48888".parse().unwrap();
    deployment::check_serving(&recovery_store, &drift, &recovery_package.digest)
        .await
        .unwrap();
    for (key, invalid) in [
        ("schema-invalid", json!({})),
        (
            "size-invalid",
            json!({"applicationId":"00000000-0000-4000-8000-000000000001","sendAfter":"x".repeat(16_385)}),
        ),
    ] {
        let refused = http
            .post(format!("{origin}/v1/runs"))
            .bearer_auth(&a)
            .header("Idempotency-Key", key)
            .json(&json!({"flow":"delayed-follow-up","input":invalid}))
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), 400, "invalid admission {key}");
        let admitted: i64 = admin
            .query_one(&format!("SELECT count(*) FROM {namespace}.runs"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(admitted, 0, "invalid input creates no admission");
    }
    let unauthorized = http
        .post(format!("{origin}/v1/runs"))
        .json(&json!({"flow":"delayed-follow-up","input":input}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);
    // Start media validation follows authentication and start-action policy,
    // even when the unsupported body is malformed. Refusals create no work.
    for content_type in [None, Some("text/plain"), Some("application/xml")] {
        for body in [
            json!({"flow":"delayed-follow-up","input":input}).to_string(),
            "{".to_string(),
        ] {
            for (credential, expected, code) in [
                (None, 401, "coordinator.access.unauthenticated"),
                (Some(&op), 403, "coordinator.access.denied"),
                (Some(&a), 415, "coordinator.request.content-type-invalid"),
            ] {
                let mut request = http
                    .post(format!("{origin}/v1/runs"))
                    .header("Idempotency-Key", "media-type-refusal")
                    .body(body.clone());
                if let Some(content_type) = content_type {
                    request = request.header("content-type", content_type);
                }
                if let Some(token) = credential {
                    request = request.bearer_auth(token);
                }
                let response = request.send().await.unwrap();
                let status = response.status();
                assert_eq!(response.headers()["cache-control"], "no-store");
                let problem: Value = response.json().await.unwrap();
                let admitted: i64 = admin
                    .query_one(&format!("SELECT count(*) FROM {namespace}.runs"), &[])
                    .await
                    .unwrap()
                    .get(0);
                let jobs: i64 = admin
                    .query_one(&format!("SELECT count(*) FROM {namespace}.jobs"), &[])
                    .await
                    .unwrap()
                    .get(0);
                assert_eq!(
                    (admitted, jobs),
                    (0, 0),
                    "media-type refusal {content_type:?} returned {status}"
                );
                assert_eq!(status, expected, "start media type {content_type:?}");
                assert_eq!(problem["code"], code);
            }
        }
    }
    let wrong_flow = http
        .post(format!("{origin}/v1/runs"))
        .bearer_auth(&a)
        .header("Idempotency-Key", "flow-refusal")
        .json(&json!({"flow":"other-flow","input":input}))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_flow.status(), 403);
    assert_eq!(
        wrong_flow.json::<Value>().await.unwrap()["code"],
        "coordinator.access.denied"
    );
    // Exercise the actual post-commit audit failure, rather than constructing a
    // problem code: intent is accepted, admission commits, then response audit
    // refuses its accepted outcome. Recovery must keep the original start key.
    {
        use registry_coordinator::{
            protected_state::StateKeys,
            store::{Store, StoreSecurity},
        };
        use registry_platform_audit::{AuditProfile, AuditWriter};
        use std::{collections::BTreeMap, sync::Mutex};
        struct RefuseAcceptedResponse(Arc<Mutex<Vec<Value>>>, &'static str);
        impl std::io::Write for RefuseAcceptedResponse {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let entry: Value = serde_json::from_slice(bytes)?;
                self.0.lock().unwrap().push(entry.clone());
                if entry["phase"] == "response"
                    && entry["record"]["action"] == self.1
                    && entry["record"]["outcome"] == "accepted"
                {
                    return Err(std::io::Error::other("injected response audit outage"));
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let state_key: [u8; 32] = fs::read(root_path.join("state-key"))
            .unwrap()
            .try_into()
            .unwrap();
        let admission_key: [u8; 32] = fs::read(root_path.join("admission-key"))
            .unwrap()
            .try_into()
            .unwrap();
        let failing = Arc::new(
            Store::open(
                runtime_url.as_str(),
                &namespace,
                StoreSecurity {
                    database_id: "router-pilot-test".into(),
                    keys: StateKeys::new(1, BTreeMap::from([(1, state_key)]), admission_key)
                        .unwrap(),
                    audit: AuditWriter::from_line_sink(Box::new(RefuseAcceptedResponse(
                        attempts.clone(),
                        "admit",
                    ))),
                    audit_profile: AuditProfile::production_from_secret_bytes(
                        zeroize::Zeroizing::new(fs::read(root_path.join("audit-key")).unwrap()),
                    )
                    .unwrap(),
                },
                None,
            )
            .await
            .unwrap()
            .with_package_digest(recovery_package.digest.clone()),
        );
        let (failing_origin, failing_task) = serve_fixture(HttpState {
            recovery_only: false,
            store: failing,
            runtime: recovery_runtime.clone(),
            package: recovery_package.clone(),
            authenticator: recovery_authenticator.clone(),
            adapters: recovery_adapters.clone(),
        })
        .await;
        let bearer = token("producer", "audit-owner", "coordinator:start");
        let boundary_key = "k".repeat(256);
        let response = http
            .post(format!("{failing_origin}/v1/runs"))
            .bearer_auth(&bearer)
            .header("Idempotency-Key", &boundary_key)
            .json(&json!({"flow":"delayed-follow-up","input":input}))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .unwrap();
        let status = response.status();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let problem: Value = response.json().await.unwrap();
        assert_eq!(
            problem["code"],
            "coordinator.command.audit-response-unavailable"
        );
        assert_eq!(
            problem["message"],
            "the operation may have completed; recover its original identity before trying again"
        );
        assert!(problem["suggestedAction"].is_null());
        {
            let entries = attempts.lock().unwrap();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0]["phase"], "request");
            assert_eq!(entries[1]["phase"], "response");
            assert_eq!(entries[1]["record"]["outcome"], "accepted");
            assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
        }
        let persisted = admin
            .query_one(&format!("SELECT run_id, state FROM {namespace}.runs"), &[])
            .await
            .unwrap();
        let persisted_id: Uuid = persisted.get(0);
        assert_eq!(persisted.get::<_, String>(1), "running");
        let replay = http
            .post(format!("{origin}/v1/runs"))
            .bearer_auth(&bearer)
            .header("Idempotency-Key", &boundary_key)
            .json(&json!({"flow":"delayed-follow-up","input":input}))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .unwrap();
        assert_eq!(replay.status(), 200);
        assert_eq!(
            replay.json::<Value>().await.unwrap()["runId"],
            persisted_id.to_string()
        );
        let count: i64 = admin
            .query_one(&format!("SELECT count(*) FROM {namespace}.runs"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            count, 1,
            "same-key recovery must not create another admission"
        );
        let status_attempts = Arc::new(Mutex::new(Vec::new()));
        let failing_status = Arc::new(
            Store::open(
                runtime_url.as_str(),
                &namespace,
                StoreSecurity {
                    database_id: "router-pilot-test".into(),
                    keys: StateKeys::new(1, BTreeMap::from([(1, state_key)]), admission_key)
                        .unwrap(),
                    audit: AuditWriter::from_line_sink(Box::new(RefuseAcceptedResponse(
                        status_attempts.clone(),
                        "status",
                    ))),
                    audit_profile: AuditProfile::production_from_secret_bytes(
                        zeroize::Zeroizing::new(fs::read(root_path.join("audit-key")).unwrap()),
                    )
                    .unwrap(),
                },
                None,
            )
            .await
            .unwrap()
            .with_package_digest(recovery_package.digest.clone()),
        );
        let (status_origin, status_task) = serve_fixture(HttpState {
            recovery_only: false,
            store: failing_status,
            runtime: recovery_runtime.clone(),
            package: recovery_package.clone(),
            authenticator: recovery_authenticator.clone(),
            adapters: recovery_adapters.clone(),
        })
        .await;
        let response = http
            .get(format!("{status_origin}/v1/runs/{persisted_id}"))
            .bearer_auth(&bearer)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 503);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let problem: Value = response.json().await.unwrap();
        assert_eq!(
            problem["code"],
            "coordinator.command.audit-response-unavailable"
        );
        assert!(problem.get("runId").is_none());
        {
            let entries = status_attempts.lock().unwrap();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0]["phase"], "request");
            assert_eq!(entries[1]["phase"], "response");
            assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
            assert_eq!(entries[1]["record"]["action"], "status");
            assert_eq!(entries[1]["record"]["outcome"], "accepted");
        }
        status_task.abort();
        let _ = status_task.await;
        let cancelled = http
            .post(format!("{origin}/v1/runs/{persisted_id}/cancel"))
            .bearer_auth(&op)
            .json(&json!({"reason":"settle-audit-test"}))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .unwrap();
        assert_eq!(cancelled.status(), 200);
        // Fixture-owner cleanup isolates this completed regression from the
        // later retention/history assertions. Production recovery above kept
        // the admission identity; no runtime API removes it.
        assert_eq!(
            admin
                .execute(
                    &format!("DELETE FROM {namespace}.jobs WHERE run_id=$1"),
                    &[&persisted_id]
                )
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            admin
                .execute(
                    &format!("DELETE FROM {namespace}.runs WHERE run_id=$1"),
                    &[&persisted_id]
                )
                .await
                .unwrap(),
            1
        );
        failing_task.abort();
        let _ = failing_task.await;
        assert_eq!(
            status, 503,
            "post-success audit failure is unavailability, not a state conflict"
        );
    }
    let started = http
        .post(format!("{origin}/v1/runs"))
        .bearer_auth(&a)
        .header("Idempotency-Key", "stable-key")
        .json(&json!({"flow":"delayed-follow-up","input":input}))
        .send()
        .await
        .unwrap();
    let status = started.status();
    let body: Value = started.json().await.unwrap();
    assert_eq!(status, 200, "{body}");
    let id = body["runId"].as_str().unwrap();
    let audit_path = root_path.join("audit.jsonl");
    for (credential, run, expected, outcome) in [
        (&a, id.to_string(), 200, "accepted"),
        (&op, id.to_string(), 200, "accepted"),
        (&b, id.to_string(), 404, "unknown"),
        (&a, Uuid::new_v4().to_string(), 404, "unknown"),
    ] {
        assert_status_audit(
            &http,
            &origin,
            credential,
            &run,
            &audit_path,
            expected,
            outcome,
        )
        .await;
    }
    let mut denied_flow_runtime = (*recovery_runtime).clone();
    denied_flow_runtime
        .deployment
        .as_mut()
        .unwrap()
        .authentication
        .policies[0]
        .flows = vec!["other-flow".into()];
    let denied_flow_authenticator = Arc::new(
        denied_flow_runtime
            .deployment
            .as_ref()
            .unwrap()
            .authentication
            .authenticator(&denied_flow_runtime.secret_providers, true)
            .await
            .unwrap(),
    );
    let (denied_origin, denied_task) = serve_fixture(HttpState {
        recovery_only: false,
        store: recovery_store.clone(),
        runtime: recovery_runtime.clone(),
        package: recovery_package.clone(),
        authenticator: denied_flow_authenticator,
        adapters: recovery_adapters.clone(),
    })
    .await;
    assert_status_audit(&http, &denied_origin, &a, id, &audit_path, 404, "accepted").await;
    denied_task.abort();
    let _ = denied_task.await;
    // Authorization precedes semantic reason/retention validation. Each invalid
    // bounded request leaves the admitted run untouched and creates no hold.
    for reason in [
        "".to_string(),
        "x".repeat(257),
        "line\nfeed".into(),
        "nul\0byte".into(),
    ] {
        for route in [format!("/v1/runs/{id}/cancel"), "/v1/restore-hold".into()] {
            for (credential, expected) in [(None, 401), (Some(&a), 403), (Some(&op), 400)] {
                let mut request = http
                    .post(format!("{origin}{route}"))
                    .json(&json!({"reason":reason}));
                if let Some(token) = credential {
                    request = request.bearer_auth(token);
                }
                let response = request.send().await.unwrap();
                assert_eq!(response.status(), expected, "reason request {route}");
                if expected == 400 {
                    assert_eq!(response.headers()["cache-control"], "no-store");
                    assert_eq!(
                        response.json::<Value>().await.unwrap()["code"],
                        "coordinator.command.reason-invalid"
                    );
                }
            }
        }
    }
    for body in [
        json!({"before":Utc::now().to_rfc3339(),"limit":0}),
        json!({"before":Utc::now().to_rfc3339(),"limit":101}),
        json!({"before":(Utc::now()+chrono::Duration::hours(1)).to_rfc3339(),"limit":1}),
    ] {
        for (credential, expected) in [(None, 401), (Some(&a), 403), (Some(&op), 400)] {
            let mut request = http.post(format!("{origin}/v1/retention")).json(&body);
            if let Some(token) = credential {
                request = request.bearer_auth(token);
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), expected, "retention request");
            if expected == 400 {
                assert_eq!(
                    response.json::<Value>().await.unwrap()["code"],
                    "coordinator.command.retention-invalid"
                );
            }
        }
    }
    let unchanged = http
        .get(format!("{origin}/v1/runs/{id}"))
        .bearer_auth(&a)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(unchanged["state"], "running");
    assert!(!admin
        .query_one(
            &format!("SELECT restore_hold FROM {namespace}.control WHERE id"),
            &[]
        )
        .await
        .unwrap()
        .get::<_, bool>(0));
    for malformed in [
        "{",
        "[]",
        "{\"reason\":[]} ",
        "{\"reason\":\"one\",\"reason\":\"two\"}",
        "{\"reason\":\"x\",\"unknown\":true}",
    ] {
        for route in [
            format!("/v1/runs/{id}/cancel"),
            format!("/v1/runs/{id}/retry-same"),
            format!("/v1/runs/{id}/reconcile"),
            "/v1/restore-hold".into(),
            "/v1/release-restore-hold".into(),
            "/v1/release-admission-hold".into(),
            "/v1/complete-execution-recovery".into(),
            "/v1/retention".into(),
        ] {
            for (credential, expected) in [(None, 401), (Some(&a), 403), (Some(&op), 400)] {
                let mut request = http
                    .post(format!("{origin}{route}"))
                    .header("content-type", "application/json")
                    .body(malformed);
                if let Some(token) = credential {
                    request = request.bearer_auth(token);
                }
                let response = request.send().await.unwrap();
                assert_eq!(response.status(), expected, "malformed recovery {route}");
                let problem: Value = response.json().await.unwrap();
                assert!(!problem.to_string().contains("unknown"));
            }
        }
    }
    for content_type in [None, Some("text/plain"), Some("application/xml")] {
        for route in [format!("/v1/runs/{id}/cancel"), "/v1/retention".into()] {
            for (credential, expected) in [(None, 401), (Some(&a), 403), (Some(&op), 415)] {
                let mut request = http.post(format!("{origin}{route}")).body("{}");
                if let Some(content_type) = content_type {
                    request = request.header("content-type", content_type);
                }
                if let Some(token) = credential {
                    request = request.bearer_auth(token);
                }
                assert_eq!(request.send().await.unwrap().status(), expected);
            }
        }
    }
    for media in [
        "application/json; charset=utf-8",
        "application/problem+json",
    ] {
        let response = http
            .post(format!("{origin}/v1/runs/{id}/cancel"))
            .bearer_auth(&op)
            .header("content-type", media)
            .body("{\"reason\":\"\"}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        assert_eq!(
            response.json::<Value>().await.unwrap()["code"],
            "coordinator.command.reason-invalid"
        );
    }
    // Observe this exact namespace's binding check waiting on the same guard
    // as admission/apply, rather than merely assuming a sleep proves locking.
    let (mut locker, locker_connection) = tokio_postgres::connect(&database, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = locker_connection.await;
    });
    let lock = locker.transaction().await.unwrap();
    let lock_query = format!("SELECT id FROM {namespace}.admission_lock WHERE id FOR UPDATE");
    lock.query_one(&lock_query, &[]).await.unwrap();
    let checking = tokio::spawn({
        let store = recovery_store.clone();
        let runtime = drift.clone();
        let digest = recovery_package.digest.clone();
        async move { deployment::check_serving(&store, &runtime, &digest).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let waiting:bool=admin.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE query=$1 AND wait_event_type='Lock')",&[&lock_query]).await.unwrap().get(0);
            if waiting {break;}
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }).await.unwrap();
    assert!(!checking.is_finished());
    lock.rollback().await.unwrap();
    assert_eq!(
        checking.await.unwrap().unwrap_err().code,
        "coordinator.command.live-binding-conflict"
    );
    // Simulate the listener opened after the compatible empty startup above.
    // HTTP admission must rescan inside its insertion transaction, not rely on
    // that stale startup result or a separate pre-insert observation.
    let (drift_origin, drift_task) = serve_fixture(HttpState {
        recovery_only: false,
        store: recovery_store.clone(),
        runtime: Arc::new(drift.clone()),
        package: recovery_package.clone(),
        authenticator: recovery_authenticator.clone(),
        adapters: recovery_adapters.clone(),
    })
    .await;
    let before_rows: i64 = admin
        .query_one(&format!("SELECT count(*) FROM {namespace}.runs"), &[])
        .await
        .unwrap()
        .get(0);
    let refused = http
        .post(format!("{drift_origin}/v1/runs"))
        .bearer_auth(&a)
        .header("Idempotency-Key", "drift-new-work")
        .json(&json!({"flow":"delayed-follow-up","input":input}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 409);
    assert_eq!(
        refused.json::<Value>().await.unwrap()["code"],
        "coordinator.command.live-binding-conflict"
    );
    assert_eq!(
        admin
            .query_one(&format!("SELECT count(*) FROM {namespace}.runs"), &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        before_rows
    );
    assert_eq!(
        http.get(format!("{drift_origin}/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    drift_task.abort();
    let _ = drift_task.await;
    // A settled refusal is still recoverable through the original identity.
    // Apply must retain that run's bindings even while its job is dead-lettered.
    let run_id = Uuid::parse_str(id).unwrap();
    admin.execute(&format!("UPDATE {namespace}.jobs SET state='dead-lettered',attempt=1,next_attempt_at=NULL,dead_lettered_at=clock_timestamp() WHERE run_id=$1"), &[&run_id]).await.unwrap();
    admin.execute(&format!("UPDATE {namespace}.runs SET state='failed',completed_at=clock_timestamp() WHERE run_id=$1"), &[&run_id]).await.unwrap();
    let binding = recovery_runtime
        .binding_digest_for(&recovery_package.definition.workflow)
        .unwrap();
    assert!(
        recovery_store
            .inspect(run_id, &binding)
            .await
            .unwrap()
            .recovery
            .retry_allowed
    );
    let mut changed_binding = (*recovery_runtime).clone();
    changed_binding
        .connections
        .get_mut("applications")
        .unwrap()
        .base_url = "http://127.0.0.1:48888".parse().unwrap();
    // Real service processes refuse each supported binding drift before opening
    // their listener. None acquires product authority or dispatches a job.
    let service_path = root_path.join("service-runtime.yaml");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let service_origin = format!("http://127.0.0.1:{port}");
    let mut service_doc = doc.clone();
    service_doc["deployment"]["auditFile"] = json!(root_path.join("service-audit.jsonl"));
    service_doc["deployment"]["listener"]["bind"] = json!(format!("127.0.0.1:{port}"));
    let original_apps = service_doc["connections"]["applications"].clone();
    for (member, value) in [
        ("baseUrl", json!("http://127.0.0.1:48888")),
        ("authorization.clientId", json!("other-reader")),
        ("authorization.scopes", json!(["other:read"])),
        (
            "authorization.taskAuthority",
            json!({"baseUrl":"http://127.0.0.1:48889","issuer":"urn:synthetic:casework","subject":"other-agent","exchangeAudience":"urn:synthetic:exchange","bootstrapResource":"urn:synthetic:casework"}),
        ),
    ] {
        service_doc["connections"]["applications"] = original_apps.clone();
        if let Some(field) = member.strip_prefix("authorization.") {
            service_doc["connections"]["applications"]["authorization"][field] = value;
        } else {
            service_doc["connections"]["applications"][member] = value;
        }
        fs::write(
            &service_path,
            serde_norway::to_string(&service_doc).unwrap(),
        )
        .unwrap();
        let mut child = spawn_service(&service_path, false);
        assert!(!await_service_exit(&mut child).await.success());
        let mut stderr = String::new();
        std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut stderr).unwrap();
        assert!(
            stderr.contains("coordinator.command.live-binding-conflict"),
            "bounded startup refusal: {stderr}"
        );
        assert!(stderr.contains("--recovery-only"));
        assert_eq!(
            local_cli(&service_path, "deployment-status", false)["diagnostics"][0]["code"],
            "coordinator.command.live-binding-conflict"
        );
    }
    service_doc["connections"]["applications"] = original_apps.clone();
    service_doc["connections"]["applications"]["baseUrl"] = json!("http://127.0.0.1:48888");
    fs::write(
        &service_path,
        serde_norway::to_string(&service_doc).unwrap(),
    )
    .unwrap();
    let mut recovery_child = spawn_service(&service_path, true);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            assert!(
                recovery_child.try_wait().unwrap().is_none(),
                "recovery-only should remain available"
            );
            if http
                .get(format!("{service_origin}/health"))
                .timeout(std::time::Duration::from_millis(200))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        http.get(format!("{service_origin}/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    let recovery_start = http
        .post(format!("{service_origin}/v1/runs"))
        .bearer_auth(&a)
        .header("Idempotency-Key", "recovery-new-work")
        .json(&json!({"flow":"delayed-follow-up","input":input}))
        .send()
        .await
        .unwrap();
    assert_eq!(recovery_start.status(), 409);
    assert_eq!(
        recovery_start.json::<Value>().await.unwrap()["code"],
        "coordinator.command.recovery-only"
    );
    let protected = http
        .get(format!("{service_origin}/v1/runs/{id}/inspect"))
        .bearer_auth(&op)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(protected["recovery"]["retryAllowed"], false);
    assert_eq!(protected["recovery"]["reason"], "binding-changed");
    let retry = http
        .post(format!("{service_origin}/v1/runs/{id}/retry-same"))
        .bearer_auth(&op)
        .json(&json!({"reason":"original-binding-required"}))
        .send()
        .await
        .unwrap();
    assert_eq!(retry.status(), 409);
    stop_service(&mut recovery_child).await;
    assert_eq!(
        admin
            .query_one(&format!("SELECT count(*) FROM {namespace}.runs"), &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        before_rows
    );
    assert_eq!(
        admin
            .query_one(
                &format!("SELECT attempt FROM {namespace}.jobs WHERE run_id=$1"),
                &[&run_id]
            )
            .await
            .unwrap()
            .get::<_, i16>(0),
        1
    );
    let migration = deployment::open_ctl(&recovery_runtime, true).await.unwrap();
    assert_eq!(
        deployment::apply(&migration, &changed_binding, &recovery_package)
            .await
            .unwrap_err()
            .code,
        "coordinator.command.live-binding-conflict"
    );
    // Model the two cancellation states that still require recovery. These
    // flags do not create product effects, and apply must preserve their binding.
    for uncertain in [true, false] {
        admin
            .execute(
                &format!("UPDATE {namespace}.jobs SET uncertain=$2 WHERE run_id=$1"),
                &[&run_id, &uncertain],
            )
            .await
            .unwrap();
        admin.execute(&format!("UPDATE {namespace}.runs SET cancel_requested=true,state='attention',restore_review_required=$2 WHERE run_id=$1"), &[&run_id, &!uncertain]).await.unwrap();
        assert_eq!(
            deployment::apply(&migration, &changed_binding, &recovery_package)
                .await
                .unwrap_err()
                .code,
            "coordinator.command.live-binding-conflict"
        );
    }
    admin
        .execute(
            &format!("UPDATE {namespace}.jobs SET uncertain=false WHERE run_id=$1"),
            &[&run_id],
        )
        .await
        .unwrap();
    admin.execute(&format!("UPDATE {namespace}.runs SET cancel_requested=false,state='failed',restore_review_required=false WHERE run_id=$1"), &[&run_id]).await.unwrap();
    assert_other_revision_refused(
        &admin,
        &namespace,
        &migration,
        &recovery_runtime,
        &recovery_package,
        &recovery_store,
    )
    .await;
    recovery_store.retry_same(run_id, &binding).await.unwrap();
    assert_eq!(
        recovery_store.status(run_id).await.unwrap().state,
        "running"
    );
    let replay = http
        .post(format!("{origin}/v1/runs"))
        .bearer_auth(&a)
        .header("Idempotency-Key", "stable-key")
        .json(&json!({"flow":"delayed-follow-up","input":input}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(body["runId"], replay["runId"]);
    let historical_project = root_path.join("historical-project");
    fs::create_dir(&historical_project).unwrap();
    fs::write(
        historical_project.join("workflow.yaml"),
        fs::read_to_string(project_path.join("workflow.yaml"))
            .unwrap()
            .replace("id: delayed-follow-up", "id: historical-follow-up"),
    )
    .unwrap();
    fs::copy(
        project_path.join("functions.rhai"),
        historical_project.join("functions.rhai"),
    )
    .unwrap();
    let historical =
        registry_coordinator::definition::Definition::load(&historical_project).unwrap();
    let owner = registry_coordinator::store::Actor {
        issuer: issuer.issuer().to_string(),
        subject: "owner-a".into(),
        client_id: "producer".into(),
        operator: false,
    };
    recovery_store
        .admit_owned(
            &historical,
            input.clone(),
            &owner,
            "historical-owned",
            &binding,
        )
        .await
        .unwrap();
    for bearer in [&a, &op] {
        let listed: Value = http
            .get(format!("{origin}/v1/runs?limit=1"))
            .bearer_auth(bearer)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(listed["runs"].as_array().unwrap().len(), 1);
        assert_eq!(
            listed["runs"][0]["runId"], id,
            "flow policy filters newer historical work before LIMIT"
        );
    }
    let hidden = http
        .get(format!("{origin}/v1/runs/{id}"))
        .bearer_auth(&b)
        .send()
        .await
        .unwrap();
    assert_eq!(hidden.status(), 404);
    let absent = http
        .get(format!("{origin}/v1/runs/{}", Uuid::new_v4()))
        .bearer_auth(&b)
        .send()
        .await
        .unwrap();
    assert_eq!(absent.status(), 404);
    assert_eq!(
        hidden.json::<Value>().await.unwrap(),
        absent.json::<Value>().await.unwrap()
    );
    let list = http
        .get(format!("{origin}/v1/runs"))
        .bearer_auth(&b)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert!(list["runs"].as_array().unwrap().is_empty());
    let denied = http
        .get(format!("{origin}/v1/runs/{id}/inspect"))
        .bearer_auth(&a)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    let inspect = http
        .get(format!("{origin}/v1/runs/{id}/inspect"))
        .bearer_auth(&op)
        .send()
        .await
        .unwrap();
    assert_eq!(inspect.status(), 200);
    assert!(!inspect.text().await.unwrap().contains("recordId"));
    let duplicate = http
        .post(format!("{origin}/v1/runs"))
        .bearer_auth(&a)
        .header("Idempotency-Key", "duplicate")
        .header("content-type", "application/json")
        .body("{\"flow\":\"delayed-follow-up\",\"flow\":\"other\",\"input\":{}}")
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), 400);
    let terminal = http
        .post(format!("{origin}/v1/runs"))
        .bearer_auth(&a)
        .header("Idempotency-Key", "terminal-key")
        .json(&json!({"flow":"delayed-follow-up","input":input}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let terminal_id = terminal["runId"].as_str().unwrap();
    // Cancellation leaves a nonuncertain dead-lettered job settled; its retained
    // tombstone must never be decoded as a live definition during apply.
    let terminal_uuid = Uuid::parse_str(terminal_id).unwrap();
    admin.execute(&format!("UPDATE {namespace}.jobs SET state='dead-lettered',attempt=1,next_attempt_at=NULL,dead_lettered_at=clock_timestamp() WHERE run_id=$1"), &[&terminal_uuid]).await.unwrap();
    admin.execute(&format!("UPDATE {namespace}.runs SET state='failed',completed_at=clock_timestamp() WHERE run_id=$1"), &[&terminal_uuid]).await.unwrap();
    let cancelled = http
        .post(format!("{origin}/v1/runs/{terminal_id}/cancel"))
        .bearer_auth(&op)
        .json(&json!({"reason":"retention-test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(cancelled.status(), 200);
    let erased = http
        .post(format!("{origin}/v1/retention"))
        .bearer_auth(&op)
        .json(&json!({"before":Utc::now().to_rfc3339(),"limit":100}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert!(erased["erased"].as_u64().unwrap() >= 1);
    let tombstone = http
        .get(format!("{origin}/v1/runs/{terminal_id}/inspect"))
        .bearer_auth(&op)
        .send()
        .await
        .unwrap();
    assert_eq!(tombstone.status(), 200);
    let tombstone: Value = tombstone.json().await.unwrap();
    assert_eq!(tombstone["recovery"]["retryAllowed"], false);
    assert_eq!(tombstone["recovery"]["reason"], "payload-erased");
    assert!(tombstone["run"]["output"].is_null());
    deployment::apply(&migration, &recovery_runtime, &recovery_package)
        .await
        .unwrap();
    let operator = registry_coordinator::store::Actor {
        issuer: issuer.issuer().to_string(),
        subject: "operator-1".into(),
        client_id: "operator".into(),
        operator: true,
    };
    recovery_store
        .cancel_owned(run_id, &operator, "settle-original-run")
        .await
        .unwrap();
    // Settle the legitimately retained historical run before changing its
    // shared bindings; its policy must not be spoofed into the current flow.
    let historical_rows = recovery_store
        .list_owned(100, &operator, &["historical-follow-up".into()])
        .await
        .unwrap();
    for row in historical_rows {
        recovery_store
            .cancel_owned(row.run_id, &operator, "settle-historical-run")
            .await
            .unwrap();
    }
    // Settled history keeps its own binding identity after the active runtime
    // legitimately retires a connection. Use a real immutable historical
    // definition/version and owned admission, then actual cancellation.
    let retired_project = root_path.join("retired-project");
    fs::create_dir(&retired_project).unwrap();
    let mut retired_workflow: Value = yaml_value(
        &fs::read_to_string(project_path.join("workflow.yaml")).unwrap(),
        registry_coordinator::authoring::API_VERSION,
        registry_coordinator::authoring::KIND,
    )
    .unwrap();
    retired_workflow["project"]["version"] = json!("retired-v1");
    fs::write(
        retired_project.join("workflow.yaml"),
        serde_norway::to_string(&retired_workflow)
            .unwrap()
            .replace("applications", "retired-applications"),
    )
    .unwrap();
    fs::copy(
        project_path.join("functions.rhai"),
        retired_project.join("functions.rhai"),
    )
    .unwrap();
    let retired_definition =
        registry_coordinator::definition::Definition::load(&retired_project).unwrap();
    let mut original_retired_runtime = (*recovery_runtime).clone();
    original_retired_runtime.connections.insert(
        "retired-applications".into(),
        original_retired_runtime.connections["applications"].clone(),
    );
    let retired_binding = original_retired_runtime
        .binding_digest_for(&retired_definition.workflow)
        .unwrap();
    let retired_run = recovery_store
        .admit_runtime_owned(
            &retired_definition,
            input.clone(),
            &operator,
            "retired-history",
            &retired_binding,
            &original_retired_runtime,
        )
        .await
        .unwrap();
    recovery_store
        .cancel_owned(retired_run, &operator, "retire-settled-work")
        .await
        .unwrap();
    assert!(recovery_runtime
        .binding_digest_for(&retired_definition.workflow)
        .is_err());
    deployment::apply(&migration, &recovery_runtime, &recovery_package)
        .await
        .unwrap();
    let retired_inspection = http
        .get(format!("{origin}/v1/runs/{retired_run}/inspect"))
        .bearer_auth(&op)
        .send()
        .await
        .unwrap();
    assert_eq!(retired_inspection.status(), 200);
    let retired_inspection: Value = retired_inspection.json().await.unwrap();
    assert_eq!(retired_inspection["run"]["bindingDigest"], retired_binding);
    assert_eq!(retired_inspection["recovery"]["retryAllowed"], false);
    // Test the settled-state classification independently of convenient labels.
    // These transitions are fixture-only, preserve encrypted history, and never
    // call an adapter or fabricate receipt proof.
    for (run_state, job_state) in [
        ("finished", "delivered"),
        ("failed", "delivered"),
        ("expired", "expired"),
        ("cancelled", "dead-lettered"),
        ("cancelled-after-effect", "delivered"),
    ] {
        admin.execute(&format!("UPDATE {namespace}.runs SET state=$2,cancel_requested=$3,restore_review_required=false WHERE run_id=$1"), &[&retired_run,&run_state,&run_state.starts_with("cancelled")]).await.unwrap();
        fixture_job_state(&admin, &namespace, retired_run, job_state, false).await;
        let inspection = http
            .get(format!("{origin}/v1/runs/{retired_run}/inspect"))
            .bearer_auth(&op)
            .send()
            .await
            .unwrap();
        assert_eq!(inspection.status(), 200, "settled {run_state}/{job_state}");
        let inspection: Value = inspection.json().await.unwrap();
        assert_eq!(inspection["recovery"]["retryAllowed"], false);
        deployment::check_serving(&recovery_store, &recovery_runtime, &recovery_package.digest)
            .await
            .unwrap();
    }
    for (run_state, job_state, uncertain, review) in [
        ("cancelled", "unknown", true, false),
        ("failed", "dead-lettered", false, false),
        ("failed", "delivered", true, false),
        ("finished", "pending", false, false),
        ("cancelled", "expired", false, true),
    ] {
        admin.execute(&format!("UPDATE {namespace}.runs SET state=$2,cancel_requested=$3,restore_review_required=$4 WHERE run_id=$1"), &[&retired_run,&run_state,&run_state.starts_with("cancelled"),&review]).await.unwrap();
        fixture_job_state(&admin, &namespace, retired_run, job_state, uncertain).await;
        let inspection = http
            .get(format!("{origin}/v1/runs/{retired_run}/inspect"))
            .bearer_auth(&op)
            .send()
            .await
            .unwrap();
        assert_eq!(
            inspection.status(),
            409,
            "protected {run_state}/{job_state}"
        );
        assert_eq!(
            deployment::check_serving(&recovery_store, &recovery_runtime, &recovery_package.digest)
                .await
                .unwrap_err()
                .code,
            "coordinator.command.live-binding-conflict"
        );
    }
    admin.execute(&format!("UPDATE {namespace}.runs SET state='cancelled',cancel_requested=true,restore_review_required=false WHERE run_id=$1"), &[&retired_run]).await.unwrap();
    fixture_job_state(&admin, &namespace, retired_run, "expired", false).await;
    // With every old run settled, the normal service can start with the retired
    // connection absent, and the real authenticated inspector remains usable.
    service_doc["connections"]["applications"] = original_apps;
    fs::write(
        &service_path,
        serde_norway::to_string(&service_doc).unwrap(),
    )
    .unwrap();
    let mut normal_child = spawn_service(&service_path, false);
    probe_service_readiness(&http, &service_origin, std::time::Duration::from_secs(10))
        .await
        .unwrap_or_else(|diagnostic| {
            panic!(
                "normal service was not ready: {diagnostic}; child_exit={:?}",
                normal_child.try_wait().unwrap()
            );
        });
    assert!(normal_child.try_wait().unwrap().is_none());
    let inspection = http
        .get(format!("{service_origin}/v1/runs/{retired_run}/inspect"))
        .bearer_auth(&op)
        .send()
        .await
        .unwrap();
    assert_eq!(inspection.status(), 200);
    assert_eq!(
        inspection.json::<Value>().await.unwrap()["recovery"]["retryAllowed"],
        false
    );
    stop_service(&mut normal_child).await;
    deployment::apply(&migration, &changed_binding, &recovery_package)
        .await
        .unwrap();
    deployment::apply(&migration, &recovery_runtime, &recovery_package)
        .await
        .unwrap();
    let held = http
        .post(format!("{origin}/v1/restore-hold"))
        .bearer_auth(&op)
        .json(&json!({"reason":"restore-test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(held.status(), 200);
    assert_eq!(
        http.get(format!("{origin}/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    let blocked = http
        .post(format!("{origin}/v1/runs"))
        .bearer_auth(&a)
        .header("Idempotency-Key", "another")
        .json(&json!({"flow":"delayed-follow-up","input":input}))
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), 409);
    let doctor = http
        .get(format!("{origin}/v1/doctor"))
        .bearer_auth(&op)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(doctor["state"]["admissionsHold"], true);
    let no_attestation=http.post(format!("{origin}/v1/release-admission-hold")).bearer_auth(&op).json(&json!({"recoveryReference":"restore-test","admissionHistoryComplete":false,"priorDeploymentFenced":true})).send().await.unwrap();
    assert_eq!(no_attestation.status(), 409);
    let missing_execution=http.post(format!("{origin}/v1/complete-execution-recovery")).bearer_auth(&op).json(&json!({"recoveryReference":"restore-test","executionHistoryComplete":false,"priorDeploymentFenced":true})).send().await.unwrap();
    assert_eq!(missing_execution.status(), 409);
    task.abort();
    let _ = task.await;
    // Terminal tombstones still pin workflow id/version to their original
    // artifact. Apply must refuse reuse before appending an activation.
    let erased: bool=admin.query_one(&format!("SELECT snapshot IS NULL AND payload_erased_at IS NOT NULL FROM {namespace}.runs WHERE run_id=$1"),&[&terminal_uuid]).await.unwrap().get(0);
    assert!(erased);
    let count_before: i64 = admin
        .query_one(
            &format!("SELECT count(*) FROM {namespace}.coordinator_activations"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let source = project_path.join("functions.rhai");
    fs::write(
        &source,
        format!(
            "{}\n// Different immutable definition under the same version.\n",
            fs::read_to_string(&source).unwrap()
        ),
    )
    .unwrap();
    let changed_package_path = root_path.join("changed-version-package");
    let changed_digest = deployment::package(&project_path, &changed_package_path).unwrap();
    let mut changed_definition_runtime = (*recovery_runtime).clone();
    changed_definition_runtime
        .deployment
        .as_mut()
        .unwrap()
        .package
        .root = changed_package_path;
    changed_definition_runtime
        .deployment
        .as_mut()
        .unwrap()
        .package
        .expected_digest = Some(changed_digest);
    let changed_definition_package =
        deployment::load_package(deployment::config(&changed_definition_runtime).unwrap()).unwrap();
    assert_eq!(
        deployment::apply(
            &migration,
            &changed_definition_runtime,
            &changed_definition_package
        )
        .await
        .unwrap_err()
        .code,
        "coordinator.command.workflow-version-conflict"
    );
    let count_after: i64 = admin
        .query_one(
            &format!("SELECT count(*) FROM {namespace}.coordinator_activations"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        count_before, count_after,
        "refused activation appends no ledger entry"
    );
    let active: Option<String> = admin
        .query_one(
            &format!("SELECT active_package_digest FROM {namespace}.control WHERE id"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(active.as_deref(), Some(recovery_package.digest.as_str()));
    let workflow_path = project_path.join("workflow.yaml");
    let mut workflow: Value = yaml_value(
        &fs::read_to_string(&workflow_path).unwrap(),
        registry_coordinator::authoring::API_VERSION,
        registry_coordinator::authoring::KIND,
    )
    .unwrap();
    workflow["project"]["version"] = json!("v2");
    fs::write(&workflow_path, serde_norway::to_string(&workflow).unwrap()).unwrap();
    let next_package_path = root_path.join("next-version-package");
    let next_digest = deployment::package(&project_path, &next_package_path).unwrap();
    changed_definition_runtime
        .deployment
        .as_mut()
        .unwrap()
        .package
        .root = next_package_path;
    changed_definition_runtime
        .deployment
        .as_mut()
        .unwrap()
        .package
        .expected_digest = Some(next_digest);
    let next_package =
        deployment::load_package(deployment::config(&changed_definition_runtime).unwrap()).unwrap();
    deployment::apply(&migration, &changed_definition_runtime, &next_package)
        .await
        .unwrap();
    // The existing fixture service owns its durable audit writer. Reuse that
    // custody while pinning the replacement service view to the new package.
    let next_store = recovery_store
        .as_ref()
        .clone()
        .with_package_digest(next_package.digest.clone());
    next_store
        .complete_execution_recovery(&operator, "complete-fenced-history", true, true)
        .await
        .unwrap();
    next_store
        .release_restore_hold(&operator, "complete-fenced-history")
        .await
        .unwrap();
    next_store
        .release_admission_hold(&operator, "complete-fenced-history", true, true)
        .await
        .unwrap();
    next_store
        .admit_owned(
            &next_package.definition,
            input.clone(),
            &operator,
            "next-version-admission",
            &changed_definition_runtime
                .binding_digest_for(&next_package.definition.workflow)
                .unwrap(),
        )
        .await
        .unwrap();
    drop(runtime_client);
    issuer.stop().await;
    admin
        .batch_execute(&format!(
            "DROP SCHEMA {namespace} CASCADE; DROP ROLE {role}"
        ))
        .await
        .unwrap();
}

fn yaml_value(
    text: &str,
    api_version: &str,
    kind: &str,
) -> std::result::Result<Value, registry_platform_yaml::Report> {
    use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
    let versions = [ApiVersion::current(api_version)];
    let format = FormatSpec {
        kind,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &versions,
            retired_api_versions: &[],
        },
        removed_keys: &[],
    };
    Reader::new("fixture.yaml")
        .read(text.as_bytes(), &Expect::one(&format))
        .map(|document| document.to_json_value())
}

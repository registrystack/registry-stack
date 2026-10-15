// SPDX-License-Identifier: Apache-2.0
//! The ordinary package/apply/service path against real PostgreSQL and OIDC.
#![cfg(feature = "postgres-test")]
#[path = "support/failed_fixture.rs"]
mod failed_fixture;
use chrono::Utc;
use registry_coordinator::{
    adapters::HttpAdapters,
    deployment,
    http::{self, HttpState},
    project,
    runtime::RuntimeConfig,
};
use registry_platform_config::PackageConfig;
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
    local_cli_args(path, &[command], success)
}
fn local_cli_args(path: &std::path::Path, args: &[&str], success: bool) -> Value {
    let command = args[0];
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["--format", "json", "--runtime-config"])
        .arg(path)
        .args(args)
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
    if expected_status != 200 {
        assert_eq!(
            response.headers()["content-type"],
            "application/problem+json"
        );
    }
    let body: Value = response.json().await.unwrap();
    if expected_status == 200 {
        assert_eq!(body["runId"], run);
        assert_eq!(body["workflow"], "delayed-follow-up");
    } else {
        assert_eq!(body["code"], "run.not-visible");
        assert_eq!(
            body["type"],
            "https://id.registrystack.org/problems/registry-coordinator/run/not-visible"
        );
        assert_eq!(body["status"], 404);
        assert!(body["traceId"].as_str().is_some_and(|id| id.len() == 32));
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
async fn assert_run_flow_refused(
    http: &reqwest::Client,
    origin: &str,
    credential: &str,
    run: &str,
    audit_path: &std::path::Path,
) {
    for (method, suffix) in [
        (reqwest::Method::GET, ""),
        (reqwest::Method::GET, "/inspect"),
        (reqwest::Method::POST, "/retry-same"),
        (reqwest::Method::POST, "/cancel"),
        (reqwest::Method::POST, "/reconcile"),
    ] {
        let before = fs::read_to_string(audit_path).unwrap().lines().count();
        let mut request = http
            .request(method.clone(), format!("{origin}/v1/runs/{run}{suffix}"))
            .bearer_auth(credential);
        if method == reqwest::Method::POST {
            request = request.json(&json!({"reason":"denied-flow-regression"}));
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 404, "{method} {suffix}");
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response.headers()["content-type"],
            "application/problem+json"
        );
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["code"], "run.not-visible");
        assert_eq!(body["status"], 404);
        assert!(body.get("runId").is_none());
        let rendered = body.to_string();
        assert!(!rendered.contains(run));
        assert!(!rendered.contains("delayed-follow-up"));

        let entries = fs::read_to_string(audit_path)
            .unwrap()
            .lines()
            .skip(before)
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 2, "{method} {suffix} has one audit pair");
        assert_eq!(entries[0]["phase"], "request");
        assert_eq!(entries[1]["phase"], "response");
        assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
        for entry in &entries {
            assert_eq!(entry["record"]["action"], "status");
        }
        assert_eq!(entries[1]["record"]["outcome"], "unknown");
    }
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
                        "authentication.refused"
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
                assert_eq!(problem["code"], "request.invalid");
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
                    "operation.not-authorized"
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
            let invalid = if matches!(query, "limit=0" | "limit=101") {
                "request.limit-out-of-range"
            } else {
                "request.invalid"
            };
            for (credential, expected, code) in [
                (None, 401, "authentication.refused"),
                (Some("not.a.valid-token"), 401, "authentication.refused"),
                (Some(operator), 400, invalid),
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
        .body("x".repeat(131_073))
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), 413);
    assert_eq!(
        oversized.headers()["content-type"],
        "application/problem+json"
    );
    assert_eq!(
        oversized.json::<Value>().await.unwrap()["code"],
        "request.body-too-large"
    );
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
async fn assert_reapply_preserves_schema_and_work(
    admin: &tokio_postgres::Client,
    namespace: &str,
    migration: &registry_coordinator::store::Store,
    runtime: &RuntimeConfig,
    workflows: &deployment::Workflows,
    store: &registry_coordinator::store::Store,
) {
    let rows_sql = format!(
        "SELECT jsonb_build_object(
            'runs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY run_id) FROM {namespace}.runs r),
            'jobs',(SELECT jsonb_agg(to_jsonb(j) ORDER BY run_id,step) FROM {namespace}.jobs j),
            'ledger',(SELECT jsonb_agg(version ORDER BY version) FROM {namespace}.coordinator_migrations),
            'schemaVersion',(SELECT schema_version FROM {namespace}.control WHERE id))"
    );
    // Grants rewrite ACLs on every apply; relations, columns and constraints
    // are created once and never replaced.
    let catalog_sql = "SELECT jsonb_agg(entry ORDER BY entry) FROM (
            SELECT format('relation %s %s %s', c.relname, c.oid, c.relfilenode) AS entry
              FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1
            UNION ALL
            SELECT format('column %s.%s %s %s', t.relname, a.attname, a.attnum, a.atttypid)
              FROM pg_attribute a JOIN pg_class t ON t.oid=a.attrelid
              JOIN pg_namespace n ON n.oid=t.relnamespace
              WHERE n.nspname=$1 AND a.attnum>0 AND NOT a.attisdropped
            UNION ALL
            SELECT format('constraint %s.%s %s %s %s', t.relname, k.conname, k.oid, k.xmin, pg_get_constraintdef(k.oid))
              FROM pg_constraint k JOIN pg_class t ON t.oid=k.conrelid
              JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=$1) entries";
    let before: Value = admin.query_one(&rows_sql, &[]).await.unwrap().get(0);
    let catalog: Value = admin
        .query_one(catalog_sql, &[&namespace])
        .await
        .unwrap()
        .get(0);
    assert!(!before["runs"].as_array().unwrap().is_empty());
    assert!(!before["jobs"].as_array().unwrap().is_empty());
    assert_eq!(before["ledger"], json!([4]));
    assert_eq!(before["schemaVersion"], 4);
    for _ in 0..2 {
        deployment::apply(migration, runtime, workflows, &[])
            .await
            .unwrap();
        deployment::check(store, runtime, workflows.digest())
            .await
            .unwrap();
        let after: Value = admin.query_one(&rows_sql, &[]).await.unwrap().get(0);
        assert_eq!(after, before, "apply must preserve protected work");
        let after: Value = admin
            .query_one(catalog_sql, &[&namespace])
            .await
            .unwrap()
            .get(0);
        assert_eq!(after, catalog, "apply must not change the created schema");
    }
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
    project::init(&project_path, Some("delayed-follow-up")).unwrap();
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
    let template = include_str!("../../../products/coordinator/examples/single-flow-runtime.yaml");
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
    d["databaseId"] = json!("router-test");
    d["runtimeRole"] = json!(role);
    d["packages"] = json!([{"root":package_path,"expectedDigest":digest}]);
    d["listener"] = json!({"bind":"127.0.0.1:0","tlsTermination":"development-loopback"});
    d["auditFile"] = json!(root_path.join("audit.jsonl"));
    d["stateKeys"] = json!({"1":{"keyRef":"secret:file/state-key"}});
    d["admissionKeyRef"] = json!("secret:file/admission-key");
    d["auditKeyRef"] = json!("secret:file/audit-key");
    d["authentication"] = json!({"issuer":issuer.issuer(),"audience":"urn:coordinator:test","scopeClaim":"scope","jwksSource":{"type":"uri","uri":issuer.jwks_uri()},"policies":{"producer":{"requiredScopes":["coordinator:start"],"workflows":["delayed-follow-up"],"actions":["start","status"]},"operator":{"requiredScopes":["coordinator:operate"],"workflows":["delayed-follow-up"],"actions":["status","inspect","retry-same","cancel","reconcile","doctor","restore-hold","release-restore-hold","release-admission-hold","complete-execution-recovery","retain"],"operator":true}}});
    fs::write(&path, serde_norway::to_string(&doc).unwrap()).unwrap();
    let runtime = Arc::new(RuntimeConfig::load(&path).unwrap());
    let workflows =
        Arc::new(deployment::load_workflows(deployment::config(&runtime).unwrap()).unwrap());
    let package = workflows.get("delayed-follow-up").unwrap().clone();
    let workflow_revision = package.definition.digest.clone();
    let workflows_digest = workflows.digest().to_owned();
    assert_ne!(
        workflows_digest, digest,
        "the set digest names the workflows, not one package"
    );
    let migration = deployment::open_ctl(&runtime, true).await.unwrap();
    let applied = deployment::apply(&migration, &runtime, &workflows, &[])
        .await
        .unwrap();
    assert_eq!(applied.workflows_digest, workflows_digest);
    assert_eq!(applied.activation.package_digest, workflows_digest);
    assert_eq!(
        changes(&applied),
        pairs(&[("delayed-follow-up", "install")])
    );
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
    deployment::check(&store, &runtime, &workflows_digest)
        .await
        .unwrap();
    let mut wrong_identity = (*runtime).clone();
    wrong_identity.deployment.as_mut().unwrap().database_id = "wrong-database".into();
    assert!(
        deployment::check(&store, &wrong_identity, &workflows_digest)
            .await
            .is_err()
    );
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
    let planned = local_cli(&status_path, "plan", true);
    assert_eq!(planned["workflowsDigest"], workflows_digest);
    assert_eq!(planned["workflows"][0]["change"], "unchanged");
    assert_eq!(planned["workflows"][0]["packageDigest"], digest);
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
    status_doc["deployment"]["databaseId"] = json!("router-test");
    fs::write(&status_path, serde_norway::to_string(&status_doc).unwrap()).unwrap();
    let checked = local_cli(&status_path, "deployment-status", true);
    assert_eq!(checked["status"], "checked");
    assert_eq!(checked["databaseId"], "router-test");
    assert_eq!(checked["workflowsDigest"], workflows_digest);
    assert_eq!(checked["workflows"], json!({"delayed-follow-up": digest}));
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
    // Key custody that differs from what apply registered is refused by name,
    // with its fix, and never with a key or its commitment.
    let mut next_key = [74; 32];
    next_key[7] = 0;
    private(&root_path.join("state-key-2"), &next_key);
    let registered: (String, Value) = admin
        .query_one(
            &format!(
                "SELECT admission_key_commitment,state_key_commitments FROM {namespace}.control"
            ),
            &[],
        )
        .await
        .map(|row| (row.get(0), row.get(1)))
        .unwrap();
    for (active, keys, fix) in [
        (
            2,
            json!({"1":{"keyRef":"secret:file/state-key"},"2":{"keyRef":"secret:file/state-key-2"}}),
            "coordinatorctl apply",
        ),
        (
            1,
            json!({"1":{"keyRef":"secret:file/state-key-2"}}),
            "deployment.stateKeys",
        ),
    ] {
        status_doc["deployment"]["activeStateKey"] = json!(active);
        status_doc["deployment"]["stateKeys"] = keys;
        fs::write(&status_path, serde_norway::to_string(&status_doc).unwrap()).unwrap();
        let refused = local_cli(&status_path, "deployment-status", false);
        let diagnostic = &refused["diagnostics"][0];
        assert_eq!(diagnostic["code"], "coordinator.command.state-key-custody");
        assert!(
            diagnostic["suggestedAction"]
                .as_str()
                .unwrap()
                .contains(fix),
            "{diagnostic}"
        );
        let printed = refused.to_string();
        assert!(!printed.contains(&registered.0));
        for commitment in registered.1.as_object().unwrap().values() {
            assert!(!printed.contains(commitment.as_str().unwrap()));
        }
    }
    status_doc["deployment"]["activeStateKey"] = json!(1);
    status_doc["deployment"]["stateKeys"] = json!({"1":{"keyRef":"secret:file/state-key"}});
    fs::write(&status_path, serde_norway::to_string(&status_doc).unwrap()).unwrap();
    local_cli(&status_path, "deployment-status", true);
    let other_project = root_path.join("other-project");
    project::init(&other_project, Some("delayed-follow-up")).unwrap();
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
    status_doc["deployment"]["packages"] =
        json!([{"root":other_package,"expectedDigest":other_digest}]);
    fs::write(&status_path, serde_norway::to_string(&status_doc).unwrap()).unwrap();
    let planned = local_cli(&status_path, "plan", true);
    assert_eq!(planned["workflows"][0]["change"], "replace");
    assert_eq!(planned["workflows"][0]["packageDigest"], other_digest);
    assert_eq!(planned["workflows"][0]["activePackageDigest"], digest);
    assert_eq!(
        local_cli(&status_path, "deployment-status", false)["diagnostics"][0]["code"],
        "coordinator.deployment.refused"
    );
    status_doc["deployment"]["packages"] = doc["deployment"]["packages"].clone();
    fs::write(&status_path, serde_norway::to_string(&status_doc).unwrap()).unwrap();
    // A prior protected-state schema is refused by the Store gate before
    // deployment inspection can use that layout. Plan can still report its
    // read-only observation through the migration role.
    admin
        .batch_execute(&format!(
            "ALTER TABLE {namespace}.control DROP CONSTRAINT control_schema_version_check;
             UPDATE {namespace}.control SET schema_version=1"
        ))
        .await
        .unwrap();
    local_cli(&status_path, "plan", true);
    assert_eq!(
        local_cli(&status_path, "deployment-status", false)["diagnostics"][0]["code"],
        "coordinator.command.store-unavailable"
    );
    admin
        .batch_execute(&format!(
            "UPDATE {namespace}.control SET schema_version=4;
             ALTER TABLE {namespace}.control ADD CONSTRAINT control_schema_version_check CHECK(schema_version=4)"
        ))
        .await
        .unwrap();
    local_cli(&status_path, "deployment-status", true);
    // A newer ledger, stale effective table grants, and forbidden control
    // write authority all refuse status while plan still reports observation.
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
            "UPDATE {namespace}.control SET active_flows_digest='forged' WHERE id"
        ))
        .await
        .is_err());
    assert!(runtime_client
        .batch_execute(&format!(
            "UPDATE {namespace}.control SET active_flows='{{}}' WHERE id"
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
    let recovery_flows = workflows.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            http::router(HttpState {
                recovery_only: false,
                store,
                runtime,
                workflows,
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
    let contract: Value = http
        .get(format!("{origin}/v1/workflows/delayed-follow-up"))
        .bearer_auth(&a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(contract["workflow"], "delayed-follow-up");
    assert_eq!(contract["workflowRevision"], workflow_revision);
    assert_eq!(
        contract["input"],
        recovery_package.definition.workflow.input
    );
    assert_eq!(
        contract["outcomes"],
        serde_json::to_value(&recovery_package.definition.workflow.outcomes).unwrap()
    );
    for (workflow, credential, expected) in
        [("delayed-follow-up", &op, 403), ("not-permitted", &a, 403)]
    {
        let response = http
            .get(format!("{origin}/v1/workflows/{workflow}"))
            .bearer_auth(credential)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(
            response.json::<Value>().await.unwrap()["code"],
            "operation.not-authorized"
        );
    }

    let authorization_a = format!("Bearer {a}");
    let authorization_b = format!("Bearer {b}");
    let authorization_op = format!("Bearer {op}");
    for values in [
        [&authorization_a, &authorization_a],
        [&authorization_a, &authorization_b],
        [&authorization_b, &authorization_a],
        [&authorization_a, &authorization_op],
    ] {
        for (method, path) in [
            ("GET", "/v1/workflows/delayed-follow-up"),
            ("GET", "/v1/runs"),
            ("POST", "/v1/runs"),
            ("GET", "/v1/runs/00000000-0000-4000-8000-000000000001"),
            (
                "POST",
                "/v1/runs/00000000-0000-4000-8000-000000000001/retry-same",
            ),
            ("POST", "/v1/review-requests"),
            (
                "GET",
                "/v1/review-requests/00000000-0000-4000-8000-000000000001",
            ),
            (
                "POST",
                "/v1/review-requests/00000000-0000-4000-8000-000000000001/cancel",
            ),
        ] {
            let response = http
                .request(method.parse().unwrap(), format!("{origin}{path}"))
                .header("Authorization", values[0])
                .header("Authorization", values[1])
                .json(&json!({}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 401, "{method} {path}");
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.headers()["www-authenticate"], "Bearer");
            assert_eq!(
                response.json::<Value>().await.unwrap()["code"],
                "authentication.refused"
            );
        }
    }
    assert_authenticated_run_validation(&http, &origin, &database, &namespace, &op, &a).await;
    let input = json!({"applicationId":"00000000-0000-4000-8000-000000000001","sendAfter":(Utc::now()+chrono::Duration::minutes(20)).to_rfc3339()});
    assert_bounded_readiness(&http, &origin, &database, &namespace).await;
    let long_key = "x".repeat(257);
    for keys in [
        vec![],
        vec![""],
        vec![long_key.as_str()],
        vec!["same-key", "same-key"],
        vec!["first-key", "second-key"],
        vec!["second-key", "first-key"],
    ] {
        for (credential, expected, code) in [
            (None, 401, "authentication.refused"),
            (Some(&op), 403, "operation.not-authorized"),
            (Some(&a), 400, "idempotency.key-invalid"),
        ] {
            let mut request = http
                .post(format!("{origin}/v1/runs"))
                .json(&json!({"workflow":"delayed-follow-up","workflowRevision":workflow_revision,"input":input}));
            for key in &keys {
                request = request.header("Idempotency-Key", *key);
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
        "malformed idempotency keys create no admission or dispatch job"
    );
    // A different config is initially compatible with an empty deployment.
    // Another old-config instance may admit work after this startup check.
    let mut drift = (*recovery_runtime).clone();
    let registry_coordinator::runtime::ConnectionConfig::Breg(bound_config) =
        drift.connections.get_mut("applications").unwrap()
    else {
        panic!("BReg binding")
    };
    bound_config.base_url = "http://127.0.0.1:48888".parse().unwrap();
    deployment::check_serving(&recovery_store, &drift, recovery_flows.digest())
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
            .json(&json!({"workflow":"delayed-follow-up","workflowRevision":workflow_revision,"input":invalid}))
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
        .json(&json!({"workflow":"delayed-follow-up","workflowRevision":workflow_revision,"input":input}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);
    // Start media validation follows authentication and start-action policy,
    // even when the unsupported body is malformed. Refusals create no work.
    for content_type in [None, Some("text/plain"), Some("application/xml")] {
        for body in [
            json!({"workflow":"delayed-follow-up","workflowRevision":workflow_revision,"input":input}).to_string(),
            "{".to_string(),
        ] {
            for (credential, expected, code) in [
                (None, 401, "authentication.refused"),
                (Some(&op), 403, "operation.not-authorized"),
                (Some(&a), 415, "request.unsupported-media-type"),
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
        .json(&json!({"workflow":"other-flow","workflowRevision":workflow_revision,"input":input}))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_flow.status(), 403);
    assert_eq!(
        wrong_flow.json::<Value>().await.unwrap()["code"],
        "operation.not-authorized"
    );
    // Exercise the actual post-commit audit failure, rather than constructing a
    // problem code: intent is accepted, admission commits, then response audit
    // refuses its accepted outcome. Recovery must keep the original idempotency key.
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
                    database_id: "router-test".into(),
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
            .with_workflows_digest(recovery_flows.digest().to_owned()),
        );
        let (failing_origin, failing_task) = serve_fixture(HttpState {
            recovery_only: false,
            store: failing,
            runtime: recovery_runtime.clone(),
            workflows: recovery_flows.clone(),
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
            .json(&json!({"workflow":"delayed-follow-up","workflowRevision":workflow_revision,"input":input}))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .unwrap();
        let status = response.status();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let problem: Value = response.json().await.unwrap();
        assert_eq!(problem["code"], "audit.response-unavailable");
        assert_eq!(
            problem["detail"],
            "The operation may have completed, but its audited result could not be released. Inspect the run before repeating the operation."
        );
        assert!(problem.get("suggestedAction").is_none());
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
            .json(&json!({"workflow":"delayed-follow-up","workflowRevision":workflow_revision,"input":input}))
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
                    database_id: "router-test".into(),
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
            .with_workflows_digest(recovery_flows.digest().to_owned()),
        );
        let (status_origin, status_task) = serve_fixture(HttpState {
            recovery_only: false,
            store: failing_status,
            runtime: recovery_runtime.clone(),
            workflows: recovery_flows.clone(),
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
        assert_eq!(problem["code"], "audit.response-unavailable");
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
        let cancel_status = cancelled.status();
        let cancelled: Value = cancelled.json().await.unwrap();
        assert_eq!(cancel_status, 200, "{cancelled}");
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
        .json(&json!({"workflow":"delayed-follow-up","workflowRevision":workflow_revision,"input":input}))
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
    let policies = &mut denied_flow_runtime
        .deployment
        .as_mut()
        .unwrap()
        .authentication
        .policies;
    let run_actions = policies["operator"]
        .actions
        .iter()
        .copied()
        .filter(|action| !action.is_deployment_wide())
        .collect();
    policies.get_mut("producer").unwrap().actions = run_actions;
    for policy in policies.values_mut() {
        policy.workflows = vec!["other-flow".into()];
    }
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
        workflows: recovery_flows.clone(),
        authenticator: denied_flow_authenticator,
        adapters: recovery_adapters.clone(),
    })
    .await;
    admin
        .execute(
            &format!("UPDATE {namespace}.runs SET terminal_output=$2 WHERE run_id=$1"),
            &[
                &Uuid::parse_str(id).unwrap(),
                &json!({"invalid":"protected-state"}),
            ],
        )
        .await
        .unwrap();
    for credential in [&a, &op] {
        assert_run_flow_refused(&http, &denied_origin, credential, id, &audit_path).await;
    }
    admin
        .execute(
            &format!("UPDATE {namespace}.runs SET terminal_output=NULL WHERE run_id=$1"),
            &[&Uuid::parse_str(id).unwrap()],
        )
        .await
        .unwrap();
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
                        "request.reason-invalid"
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
                    "request.retention-invalid"
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
            "request.reason-invalid"
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
        let digest = recovery_flows.digest().to_owned();
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
        "live-binding-conflict"
    );
    // Simulate the listener opened after the compatible empty startup above.
    // HTTP admission must rescan inside its insertion transaction, not rely on
    // that stale startup result or a separate pre-insert observation.
    let (drift_origin, drift_task) = serve_fixture(HttpState {
        recovery_only: false,
        store: recovery_store.clone(),
        runtime: Arc::new(drift.clone()),
        workflows: recovery_flows.clone(),
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
        .json(&json!({"workflow":"delayed-follow-up","workflowRevision":workflow_revision,"input":input}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 409);
    assert_eq!(
        refused.json::<Value>().await.unwrap()["code"],
        "binding.live-conflict"
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
    let registry_coordinator::runtime::ConnectionConfig::Breg(bound_config) =
        changed_binding.connections.get_mut("applications").unwrap()
    else {
        panic!("BReg binding")
    };
    bound_config.base_url = "http://127.0.0.1:48888".parse().unwrap();
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
            stderr.contains("live-binding-conflict"),
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
        .json(&json!({"workflow":"delayed-follow-up","workflowRevision":workflow_revision,"input":input}))
        .send()
        .await
        .unwrap();
    assert_eq!(recovery_start.status(), 409);
    assert_eq!(
        recovery_start.json::<Value>().await.unwrap()["code"],
        "admission.recovery-only"
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
        deployment::apply(&migration, &changed_binding, &recovery_flows, &[])
            .await
            .unwrap_err()
            .code,
        "live-binding-conflict"
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
            deployment::apply(&migration, &changed_binding, &recovery_flows, &[])
                .await
                .unwrap_err()
                .code,
            "live-binding-conflict"
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
    assert_reapply_preserves_schema_and_work(
        &admin,
        &namespace,
        &migration,
        &recovery_runtime,
        &recovery_flows,
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
        .json(&json!({"workflow":"delayed-follow-up","workflowRevision":workflow_revision,"input":input}))
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
    // Each answer carries its own request's trace; every other member of a
    // hidden run's problem is the same as an absent run's.
    let without_trace = |mut problem: Value| {
        let trace = problem.as_object_mut().unwrap().remove("traceId").unwrap();
        assert_eq!(trace.as_str().unwrap().len(), 32);
        problem
    };
    let hidden = without_trace(hidden.json::<Value>().await.unwrap());
    assert_eq!(hidden["code"], "run.not-visible");
    assert_eq!(hidden, without_trace(absent.json::<Value>().await.unwrap()));
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
        .json(&json!({"workflow":"delayed-follow-up","workflowRevision":workflow_revision,"input":input}))
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
    // The cancellation's completion time comes from the database clock, so
    // the cutoff does too.
    let cutoff = database_clock::retention_cutoff(&admin).await;
    let erased = http
        .post(format!("{origin}/v1/retention"))
        .bearer_auth(&op)
        .json(&json!({"before":cutoff.to_rfc3339(),"limit":100}))
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
    deployment::apply(&migration, &recovery_runtime, &recovery_flows, &[])
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
            &retired_definition.digest,
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
    deployment::apply(&migration, &recovery_runtime, &recovery_flows, &[])
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
        deployment::check_serving(&recovery_store, &recovery_runtime, recovery_flows.digest())
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
            deployment::check_serving(&recovery_store, &recovery_runtime, recovery_flows.digest())
                .await
                .unwrap_err()
                .code,
            "live-binding-conflict"
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
    deployment::apply(&migration, &changed_binding, &recovery_flows, &[])
        .await
        .unwrap();
    deployment::apply(&migration, &recovery_runtime, &recovery_flows, &[])
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
        .json(&json!({"workflow":"delayed-follow-up","workflowRevision":workflow_revision,"input":input}))
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
    // Terminal tombstones retain the original computed revision. An authored
    // version label cannot block activation of a different reviewed revision.
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
        .packages = vec![PackageConfig {
        root: changed_package_path,
        expected_digest: Some(changed_digest),
    }];
    let changed_definition_flows =
        deployment::load_workflows(deployment::config(&changed_definition_runtime).unwrap())
            .unwrap();
    let planned = deployment::plan(
        &recovery_store,
        &changed_definition_runtime,
        &changed_definition_flows,
        &[],
    )
    .await
    .unwrap();
    assert_eq!(planned["workflows"][0]["change"], "replace");
    deployment::apply(
        &migration,
        &changed_definition_runtime,
        &changed_definition_flows,
        &[],
    )
    .await
    .unwrap();
    let count_after: i64 = admin
        .query_one(
            &format!("SELECT count(*) FROM {namespace}.coordinator_activations"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        count_before + 1,
        count_after,
        "a changed revision appends one activation without reinterpreting history"
    );
    let active: Option<String> = admin
        .query_one(
            &format!("SELECT active_flows_digest FROM {namespace}.control WHERE id"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(active.as_deref(), Some(changed_definition_flows.digest()));
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
        .packages = vec![PackageConfig {
        root: next_package_path,
        expected_digest: Some(next_digest),
    }];
    let next_flows =
        deployment::load_workflows(deployment::config(&changed_definition_runtime).unwrap())
            .unwrap();
    let next_package = next_flows.get("delayed-follow-up").unwrap().clone();
    let planned = deployment::plan(
        &recovery_store,
        &changed_definition_runtime,
        &next_flows,
        &[],
    )
    .await
    .unwrap();
    assert_eq!(planned["workflows"][0]["change"], "replace", "{planned}");
    deployment::apply(&migration, &changed_definition_runtime, &next_flows, &[])
        .await
        .unwrap();
    // The existing fixture service owns its durable audit writer. Reuse that
    // custody while pinning the replacement service view to the new package.
    let next_store = recovery_store
        .as_ref()
        .clone()
        .with_workflows_digest(next_flows.digest().to_owned());
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
    let next_binding = changed_definition_runtime
        .binding_digest_for(&next_package.definition.workflow)
        .unwrap();
    let recovered_tombstone = next_store
        .admit_runtime_owned(
            &next_package.definition,
            input.clone(),
            &owner,
            "terminal-key",
            &next_binding,
            &changed_definition_runtime,
            &workflow_revision,
        )
        .await
        .unwrap();
    assert_eq!(recovered_tombstone, terminal_uuid);
    let reinterpreted = next_store
        .admit_runtime_owned(
            &next_package.definition,
            input.clone(),
            &owner,
            "terminal-key",
            &next_binding,
            &changed_definition_runtime,
            &next_package.definition.digest,
        )
        .await
        .unwrap_err();
    assert_eq!(reinterpreted.code, "start-conflict");
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

const OPERATOR_ACTIONS: [&str; 11] = [
    "status",
    "inspect",
    "retry-same",
    "cancel",
    "reconcile",
    "doctor",
    "restore-hold",
    "release-restore-hold",
    "release-admission-hold",
    "complete-execution-recovery",
    "retain",
];
const DEPLOYMENT_ACTIONS: [&str; 6] = [
    "doctor",
    "restore-hold",
    "release-restore-hold",
    "release-admission-hold",
    "complete-execution-recovery",
    "retain",
];
const DELAYED: &str = "delayed-follow-up";
const GOVERNED: &str = "governed-action-follow-up";
const ROTATED_STATE_KEY: [u8; 32] = [84; 32];

/// One disposable namespace, role, key set and issuer for a deployment that
/// serves the delayed and governed follow-up example workflows side by side.
struct TwoFlowFixture {
    admin: tokio_postgres::Client,
    database: String,
    _root: failed_fixture::FixtureDirectory,
    root_path: std::path::PathBuf,
    role: String,
    namespace: String,
    issuer: TestAuthorizationServer,
    doc: Value,
    delayed_project: std::path::PathBuf,
}

impl TwoFlowFixture {
    async fn start() -> Self {
        let database = std::env::var("COORDINATOR_TEST_DATABASE_URL")
            .expect("COORDINATOR_TEST_DATABASE_URL names a disposable PostgreSQL 17+ database");
        let (admin, connection) = tokio_postgres::connect(&database, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let root = failed_fixture::FixtureDirectory::new(tempfile::tempdir().unwrap());
        let root_path = root.path().canonicalize().unwrap();
        let suffix = Uuid::new_v4().simple().to_string();
        let role = format!("coord_{suffix}");
        let namespace = format!("coordinator_{suffix}");
        let password = Uuid::new_v4().simple().to_string();
        admin.batch_execute(&format!("CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS")).await.unwrap();
        let mut runtime_url = url::Url::parse(&database).unwrap();
        runtime_url.set_username(&role).unwrap();
        runtime_url.set_password(Some(&password)).unwrap();
        private(
            &root_path.join("runtime-url"),
            runtime_url.as_str().as_bytes(),
        );
        private(&root_path.join("migration-url"), database.as_bytes());
        for (name, byte) in [("state-key", 81), ("admission-key", 82), ("audit-key", 83)] {
            private(&root_path.join(name), &[byte; 32]);
        }
        for name in ["reader-jwk", "notices-jwk"] {
            private(
                &root_path.join(name),
                registry_platform_testing::fixtures::ED25519_PRIVATE_JWK.as_bytes(),
            );
        }
        let clients = [
            "producer-a",
            "producer-b",
            "producer-wide",
            "operator-a",
            "operator",
            "deployment-operator",
        ];
        let mut builder = TestAuthorizationServer::builder()
            .with_signing_key(generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap());
        for client in clients {
            builder = builder.client(TestClient::new(client));
        }
        let issuer = builder.start().await;
        let mut doc: Value = yaml_value(
            include_str!("../../../products/coordinator/examples/two-flow-runtime.yaml"),
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
        d["databaseId"] = json!("two-flow-test");
        d["runtimeRole"] = json!(role);
        d["listener"] = json!({"bind":"127.0.0.1:0","tlsTermination":"development-loopback"});
        d["auditFile"] = json!(root_path.join("audit.jsonl"));
        d["stateKeys"] = json!({"1":{"keyRef":"secret:file/state-key"}});
        d["admissionKeyRef"] = json!("secret:file/admission-key");
        d["auditKeyRef"] = json!("secret:file/audit-key");
        let producer = |workflows: Value| json!({"requiredScopes":["coordinator:start"],"workflows":workflows,"actions":["start","status"]});
        let operator = |workflows: Value| json!({"requiredScopes":["coordinator:operate"],"workflows":workflows,"actions":OPERATOR_ACTIONS,"operator":true});
        d["authentication"] = json!({
            "issuer": issuer.issuer(),
            "audience": "urn:coordinator:test",
            "scopeClaim": "scope",
            "jwksSource": {"type": "uri", "uri": issuer.jwks_uri()},
            "policies": {
                "producer-a": producer(json!([DELAYED])),
                "producer-b": producer(json!([GOVERNED])),
                "producer-wide": producer(json!([DELAYED, GOVERNED, "retired-flow"])),
                "operator-a": operator(json!([DELAYED])),
                "operator": operator(json!([DELAYED, GOVERNED])),
                "deployment-operator": {"requiredScopes":["coordinator:operate"],"actions":DEPLOYMENT_ACTIONS,"operator":true},
            },
        });
        let delayed_project = root_path.join("delayed-project");
        project::init(&delayed_project, Some("delayed-follow-up")).unwrap();
        Self {
            admin,
            database,
            _root: root,
            root_path,
            role,
            namespace,
            issuer,
            doc,
            delayed_project,
        }
    }

    /// Package a project and return its pin.
    fn pin(&self, project: &std::path::Path, name: &str) -> Value {
        let root = self.root_path.join(name);
        let digest = deployment::package(project, &root).unwrap();
        json!({"root": root, "expectedDigest": digest})
    }

    fn governed_project() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/coordinator/examples")
            .join(GOVERNED)
    }

    /// Write one runtime document listing `packages` and load it with its workflows.
    fn runtime(
        &self,
        name: &str,
        packages: Value,
    ) -> (
        std::path::PathBuf,
        Arc<RuntimeConfig>,
        Arc<deployment::Workflows>,
    ) {
        let mut doc = self.doc.clone();
        doc["deployment"]["packages"] = packages;
        let path = self.root_path.join(name);
        fs::write(&path, serde_norway::to_string(&doc).unwrap()).unwrap();
        let runtime = Arc::new(RuntimeConfig::load(&path).unwrap());
        let workflows =
            Arc::new(deployment::load_workflows(deployment::config(&runtime).unwrap()).unwrap());
        (path, runtime, workflows)
    }

    fn token(&self, client: &str, subject: &str, scope: &str) -> String {
        self.issuer.issue_access_token(
            client,
            subject,
            "urn:coordinator:test",
            scope,
            Utc::now().timestamp() + 300,
        )
    }

    async fn active_flows(&self) -> Value {
        self.admin
            .query_one(
                &format!("SELECT active_flows FROM {}.control", self.namespace),
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }

    async fn activations(&self) -> i64 {
        self.admin
            .query_one(
                &format!(
                    "SELECT count(*) FROM {}.coordinator_activations",
                    self.namespace
                ),
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }

    async fn run_rows(&self, flow: &str) -> Value {
        self.admin
            .query_one(
                &format!("SELECT jsonb_build_object('runs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.run_id) FROM {0}.runs r WHERE r.workflow_id=$1),'jobs',(SELECT jsonb_agg(to_jsonb(j) ORDER BY j.run_id,j.step) FROM {0}.jobs j JOIN {0}.runs r ON r.run_id=j.run_id WHERE r.workflow_id=$1))", self.namespace),
                &[&flow],
            )
            .await
            .unwrap()
            .get(0)
    }

    /// Edit the runtime document to add state key version 2 and make it the
    /// active version, the way an operator rotates the payload state key.
    fn rotate_state_keys(&mut self) {
        private(&self.root_path.join("state-key-2"), &ROTATED_STATE_KEY);
        self.doc["deployment"]["stateKeys"]["2"] = json!({"keyRef":"secret:file/state-key-2"});
        self.doc["deployment"]["activeStateKey"] = json!(2);
    }

    /// Every value a custody refusal must never print: the commitments the
    /// control row registers, and each key's bytes as raw text, hex and base64.
    async fn custody_secrets(&self) -> Vec<String> {
        use base64::Engine as _;
        let row = self
            .admin
            .query_one(
                &format!(
                    "SELECT admission_key_commitment,state_key_commitments FROM {}.control",
                    self.namespace
                ),
                &[],
            )
            .await
            .unwrap();
        let mut secrets = vec![row.get::<_, String>(0)];
        secrets.extend(
            row.get::<_, Value>(1)
                .as_object()
                .unwrap()
                .values()
                .map(|commitment| commitment.as_str().unwrap().to_owned()),
        );
        for key in [[81; 32], [82; 32], ROTATED_STATE_KEY] {
            secrets.push(String::from_utf8_lossy(&key).into_owned());
            secrets.push(hex::encode(key));
            secrets.push(base64::engine::general_purpose::STANDARD_NO_PAD.encode(key));
        }
        secrets
    }

    async fn stop(self) {
        self.issuer.stop().await;
        self.admin
            .batch_execute(&format!(
                "DROP SCHEMA IF EXISTS {} CASCADE; DROP ROLE {}",
                self.namespace, self.role
            ))
            .await
            .unwrap();
    }
}

fn changes(applied: &deployment::Applied) -> Vec<(String, String)> {
    applied
        .workflows
        .iter()
        .map(|change| (change.workflow.clone(), change.change.as_str().to_owned()))
        .collect()
}

fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|(flow, change)| ((*flow).to_owned(), (*change).to_owned()))
        .collect()
}

async fn start_run(
    http: &reqwest::Client,
    origin: &str,
    credential: &str,
    key: &str,
    flow: &str,
    input: Value,
) -> (u16, Value) {
    let contract: Value = http
        .get(format!("{origin}/v1/workflows/{flow}"))
        .bearer_auth(credential)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let revision = contract["workflowRevision"]
        .as_str()
        .unwrap_or("sha256:0000000000000000000000000000000000000000000000000000000000000000");
    let response = http
        .post(format!("{origin}/v1/runs"))
        .bearer_auth(credential)
        .header("Idempotency-Key", key)
        .json(&json!({"workflow": flow, "workflowRevision":revision, "input": input}))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap())
}

async fn list_flows(http: &reqwest::Client, origin: &str, credential: &str) -> Vec<String> {
    let listed: Value = http
        .get(format!("{origin}/v1/runs?limit=10"))
        .bearer_auth(credential)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut workflows: Vec<String> = listed["runs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|run| run["workflow"].as_str().unwrap().to_owned())
        .collect();
    workflows.sort();
    workflows
}

/// Build the same activated state shared by HTTP and its durable worker.
async fn runtime_http_state(
    runtime: &Arc<RuntimeConfig>,
    workflows: &Arc<deployment::Workflows>,
) -> HttpState {
    let authenticator = Arc::new(
        deployment::config(runtime)
            .unwrap()
            .authentication
            .authenticator(&runtime.secret_providers, true)
            .await
            .unwrap(),
    );
    HttpState {
        recovery_only: false,
        store: deployment::open(runtime, false).await.unwrap(),
        runtime: runtime.clone(),
        workflows: workflows.clone(),
        authenticator,
        adapters: Arc::new(HttpAdapters::new(runtime).unwrap()),
    }
}

/// Serve one runtime file's router in process, as its service would.
async fn serve_runtime(
    runtime: &Arc<RuntimeConfig>,
    workflows: &Arc<deployment::Workflows>,
) -> (String, tokio::task::JoinHandle<()>) {
    serve_fixture(runtime_http_state(runtime, workflows).await).await
}

#[tokio::test]
async fn plan_refuses_missing_and_wrong_product_bindings_before_reporting_installability() {
    let f = TwoFlowFixture::start().await;
    let delayed = f.pin(&f.delayed_project, "plan-binding-delayed");
    let (_, runtime, workflows) = f.runtime("plan-binding.yaml", json!([delayed]));
    let migration = deployment::open_ctl(&runtime, true).await.unwrap();
    deployment::apply(&migration, &runtime, &workflows, &[])
        .await
        .unwrap();
    deployment::plan(&migration, &runtime, &workflows, &[])
        .await
        .expect("a plan with its declared binding remains usable");

    let mut wrong_product = runtime.as_ref().clone();
    wrong_product.connections.insert(
        "notices".into(),
        runtime.connections["applications"].clone(),
    );
    let wrong = deployment::plan(&migration, &wrong_product, &workflows, &[])
        .await
        .expect_err("plan must validate the product bound to each logical connection");
    assert_eq!(wrong.code, "workflow-binding");
    assert_eq!(wrong.field.as_deref(), Some("/connections/notices"));

    let mut missing = runtime.as_ref().clone();
    missing.connections.remove("notices");
    let missing = deployment::plan(&migration, &missing, &workflows, &[])
        .await
        .expect_err("plan must validate that every logical connection is configured");
    assert_eq!(missing.code, "workflow-binding");
    assert_eq!(missing.field.as_deref(), Some("/connections/notices"));

    drop(migration);
    f.stop().await;
}

#[tokio::test]
async fn two_flows_upgrade_roll_back_and_remove_without_touching_each_other() {
    let f = TwoFlowFixture::start().await;
    let delayed_v1 = f.pin(&f.delayed_project, "delayed-v1");
    let governed_v1 = f.pin(&TwoFlowFixture::governed_project(), "governed-v1");
    let workflow_path = f.delayed_project.join("workflow.yaml");
    let mut workflow: Value = yaml_value(
        &fs::read_to_string(&workflow_path).unwrap(),
        registry_coordinator::authoring::API_VERSION,
        registry_coordinator::authoring::KIND,
    )
    .unwrap();
    workflow["project"]["version"] = json!("2");
    let deadline = workflow["workflow"]["deadlineSeconds"].as_u64().unwrap();
    workflow["workflow"]["deadlineSeconds"] = json!(deadline + 1);
    fs::write(&workflow_path, serde_norway::to_string(&workflow).unwrap()).unwrap();
    let delayed_v2 = f.pin(&f.delayed_project, "delayed-v2");
    let digest = |pin: &Value| pin["expectedDigest"].as_str().unwrap().to_owned();

    // Install both workflows in one activation.
    let (both_path, runtime, workflows) = f.runtime("both.yaml", json!([delayed_v1, governed_v1]));
    let migration = deployment::open_ctl(&runtime, true).await.unwrap();
    let applied = deployment::apply(&migration, &runtime, &workflows, &[])
        .await
        .unwrap();
    assert_eq!(
        changes(&applied),
        pairs(&[(DELAYED, "install"), (GOVERNED, "install")])
    );
    assert_eq!(applied.workflows_digest, workflows.digest());
    assert_eq!(applied.activation.package_digest, workflows.digest());
    let installed = json!({DELAYED: digest(&delayed_v1), GOVERNED: digest(&governed_v1)});
    assert_eq!(f.active_flows().await, installed);
    let planned = local_cli(&both_path, "plan", true);
    assert_eq!(planned["workflowsDigest"], workflows.digest());
    for (index, flow, pin) in [(0, DELAYED, &delayed_v1), (1, GOVERNED, &governed_v1)] {
        assert_eq!(planned["workflows"][index]["workflow"], flow);
        assert_eq!(planned["workflows"][index]["change"], "unchanged");
        assert_eq!(planned["workflows"][index]["packageDigest"], digest(pin));
        assert_eq!(
            planned["workflows"][index]["activePackageDigest"],
            digest(pin)
        );
    }
    let checked = local_cli(&both_path, "deployment-status", true);
    assert_eq!(checked["workflowsDigest"], workflows.digest());
    assert_eq!(checked["workflows"], installed);

    // One service and one HTTP surface serve both workflows.
    let store = deployment::open(&runtime, false).await.unwrap();
    deployment::check(&store, &runtime, workflows.digest())
        .await
        .unwrap();
    let d = deployment::config(&runtime).unwrap();
    let authenticator = Arc::new(
        d.authentication
            .authenticator(&runtime.secret_providers, true)
            .await
            .unwrap(),
    );
    let adapters = Arc::new(HttpAdapters::new(&runtime).unwrap());
    let (origin, server) = serve_fixture(HttpState {
        recovery_only: false,
        store: store.clone(),
        runtime: runtime.clone(),
        workflows: workflows.clone(),
        authenticator: authenticator.clone(),
        adapters: adapters.clone(),
    })
    .await;
    let http = reqwest::Client::new();
    let producer_a = f.token("producer-a", "owner-a", "coordinator:start");
    let producer_b = f.token("producer-b", "owner-b", "coordinator:start");
    let producer_wide = f.token("producer-wide", "owner-wide", "coordinator:start");
    let operator_a = f.token("operator-a", "operator-a", "coordinator:operate");
    let operator = f.token("operator", "operator", "coordinator:operate");
    let delayed_input = json!({"applicationId":"00000000-0000-4000-8000-000000000001","sendAfter":(Utc::now()+chrono::Duration::minutes(20)).to_rfc3339()});
    let governed_input = json!({"applicationId":"00000000-0000-4000-8000-000000000002"});
    let (status, body) = start_run(
        &http,
        &origin,
        &producer_a,
        "a-1",
        DELAYED,
        delayed_input.clone(),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["workflow"], DELAYED);
    let delayed_run = body["runId"].as_str().unwrap().to_owned();
    let delayed_revision = body["workflowRevision"].as_str().unwrap().to_owned();
    let (status, body) = start_run(
        &http,
        &origin,
        &producer_b,
        "b-1",
        GOVERNED,
        governed_input.clone(),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["workflow"], GOVERNED);
    let governed_run = body["runId"].as_str().unwrap().to_owned();

    // A caller allowed only flow A is refused on flow B, and a flow the caller
    // may name but the deployment does not serve is absent. Neither admits.
    let (status, body) = start_run(
        &http,
        &origin,
        &producer_a,
        "a-on-b",
        GOVERNED,
        governed_input.clone(),
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("operation.not-authorized"))
    );
    let (status, body) = start_run(
        &http,
        &origin,
        &producer_wide,
        "retired",
        "retired-flow",
        governed_input.clone(),
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str(), body["detail"].as_str()),
        (
            404,
            Some("workflow.not-served"),
            Some("This deployment does not serve the named workflow.")
        )
    );
    assert!(body.get("suggestedAction").is_none());
    let admitted: i64 = f
        .admin
        .query_one(&format!("SELECT count(*) FROM {}.runs", f.namespace), &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(admitted, 2, "refused starts admit nothing");

    // Read and list routes cross workflows only as far as the caller's policy.
    assert_eq!(
        list_flows(&http, &origin, &operator).await,
        [DELAYED, GOVERNED]
    );
    assert_eq!(list_flows(&http, &origin, &operator_a).await, [DELAYED]);
    assert_eq!(list_flows(&http, &origin, &producer_b).await, [GOVERNED]);

    // Paging preserves the caller and flow policy, and both the exact state
    // filter and the attention grouping are applied before the page limit.
    let delayed_run_id = Uuid::parse_str(&delayed_run).unwrap();
    let governed_run_id = Uuid::parse_str(&governed_run).unwrap();
    f.admin
        .execute(
            &format!(
                "UPDATE {}.runs SET restore_review_required=true WHERE run_id IN ($1,$2)",
                f.namespace
            ),
            &[&delayed_run_id, &governed_run_id],
        )
        .await
        .unwrap();
    for (credential, expected_run) in [
        (&producer_a, delayed_run.as_str()),
        (&producer_b, governed_run.as_str()),
    ] {
        let response = http
            .get(format!("{origin}/v1/runs?limit=10&attention=true"))
            .bearer_auth(credential)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let page: Value = response.json().await.unwrap();
        assert_eq!(page["runs"].as_array().unwrap().len(), 1);
        assert_eq!(page["runs"][0]["runId"], expected_run);
        assert_eq!(page["runs"][0]["state"], "attention");
    }
    let first_page: Value = http
        .get(format!("{origin}/v1/runs?limit=1"))
        .bearer_auth(&operator)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cursor = first_page["nextCursor"].as_str().unwrap();
    for request in [
        http.get(format!("{origin}/v1/runs?limit=1&cursor={cursor}"))
            .bearer_auth(&producer_b),
        http.get(format!("{origin}/v1/runs?limit=1&cursor={cursor}"))
            .bearer_auth(&operator_a),
        http.get(format!(
            "{origin}/v1/runs?limit=1&cursor={cursor}&state=attention"
        ))
        .bearer_auth(&operator),
        http.get(format!(
            "{origin}/v1/runs?limit=1&cursor={cursor}&attention=true"
        ))
        .bearer_auth(&operator),
    ] {
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 400);
        assert_eq!(
            response.json::<Value>().await.unwrap()["code"],
            "request.invalid"
        );
    }
    let attention_page: Value = http
        .get(format!("{origin}/v1/runs?limit=10&state=attention"))
        .bearer_auth(&operator)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(attention_page["runs"].as_array().unwrap().len(), 2);
    f.admin
        .execute(
            &format!(
                "UPDATE {}.runs SET restore_review_required=false WHERE run_id IN ($1,$2)",
                f.namespace
            ),
            &[&delayed_run_id, &governed_run_id],
        )
        .await
        .unwrap();
    for (credential, run, expected) in [
        (&operator, &governed_run, 200),
        (&operator_a, &delayed_run, 200),
        (&operator_a, &governed_run, 404),
        (&producer_b, &governed_run, 200),
    ] {
        let response = http
            .get(format!("{origin}/v1/runs/{run}"))
            .bearer_auth(credential)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }

    // A deployment-wide action is an operator's, whichever workflows its policy
    // lists for run actions. A policy without the action is refused, and the
    // refusal changes nothing.
    for (credential, expected) in [(&operator_a, 200), (&operator, 200), (&producer_a, 403)] {
        let response = http
            .get(format!("{origin}/v1/doctor"))
            .bearer_auth(credential)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let control_before: Value = f
        .admin
        .query_one(
            &format!("SELECT to_jsonb(c) FROM {}.control c", f.namespace),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    for (path, body) in [
        ("restore-hold", json!({"reason":"flow-a-only"})),
        ("release-restore-hold", json!({"reason":"flow-a-only"})),
        (
            "release-admission-hold",
            json!({"recoveryReference":"flow-a-only","admissionHistoryComplete":true,"priorDeploymentFenced":true}),
        ),
        (
            "complete-execution-recovery",
            json!({"recoveryReference":"flow-a-only","executionHistoryComplete":true,"priorDeploymentFenced":true}),
        ),
        (
            "retention",
            json!({"before":Utc::now().to_rfc3339(),"limit":10}),
        ),
    ] {
        let response = http
            .post(format!("{origin}/v1/{path}"))
            .bearer_auth(&producer_a)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "{path}");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["code"], "operation.not-authorized", "{path}");
    }
    let control_after: Value = f
        .admin
        .query_one(
            &format!("SELECT to_jsonb(c) FROM {}.control c", f.namespace),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(control_after, control_before);

    // Upgrading flow A leaves flow B's active package and runs untouched, and
    // the run in flight on A keeps the definition it was admitted with.
    let governed_before = f.run_rows(GOVERNED).await;
    let delayed_before = f.run_rows(DELAYED).await;
    let (upgrade_path, upgraded_runtime, upgraded) =
        f.runtime("upgrade.yaml", json!([delayed_v2, governed_v1]));
    let planned = local_cli(&upgrade_path, "plan", true);
    assert_eq!(planned["workflows"][0]["change"], "replace");
    assert_eq!(
        planned["workflows"][0]["packageDigest"],
        digest(&delayed_v2)
    );
    assert_eq!(
        planned["workflows"][0]["activePackageDigest"],
        digest(&delayed_v1)
    );
    assert_eq!(planned["workflows"][1]["change"], "unchanged");
    let applied = deployment::apply(&migration, &upgraded_runtime, &upgraded, &[])
        .await
        .unwrap();
    assert_eq!(
        changes(&applied),
        pairs(&[(DELAYED, "replace"), (GOVERNED, "unchanged")])
    );
    assert_eq!(
        f.active_flows().await,
        json!({DELAYED: digest(&delayed_v2), GOVERNED: digest(&governed_v1)})
    );
    assert_eq!(f.run_rows(GOVERNED).await, governed_before);
    assert_eq!(f.run_rows(DELAYED).await, delayed_before);
    // Every apply fences services started under the previous set.
    assert!(deployment::check(&store, &runtime, workflows.digest())
        .await
        .is_err());
    let (status, _) = start_run(
        &http,
        &origin,
        &producer_b,
        "b-stale",
        GOVERNED,
        governed_input.clone(),
    )
    .await;
    assert_ne!(status, 200, "a fenced service admits nothing");
    server.abort();
    // The fixture service owns its durable audit writer. Reuse that custody
    // while pinning the restarted service view to the upgraded set.
    let upgraded_store = Arc::new(
        store
            .as_ref()
            .clone()
            .with_workflows_digest(upgraded.digest().to_owned()),
    );
    deployment::check(&upgraded_store, &upgraded_runtime, upgraded.digest())
        .await
        .unwrap();
    for run in [&delayed_run, &governed_run] {
        let status = upgraded_store.status(run.parse().unwrap()).await.unwrap();
        assert_eq!(status.state, "running");
    }
    let (origin, server) = serve_fixture(HttpState {
        recovery_only: false,
        store: upgraded_store.clone(),
        runtime: upgraded_runtime.clone(),
        workflows: upgraded.clone(),
        authenticator: authenticator.clone(),
        adapters: adapters.clone(),
    })
    .await;
    let active_revision = &upgraded.get(DELAYED).unwrap().definition.digest;
    assert_ne!(&delayed_revision, active_revision);
    let before = f.run_rows(DELAYED).await;
    let stale = http
        .post(format!("{origin}/v1/runs"))
        .bearer_auth(&producer_a)
        .header("Idempotency-Key", "stale-new-key")
        .json(
            &json!({"workflow":DELAYED,"workflowRevision":delayed_revision,"input":delayed_input}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), 409);
    assert_eq!(
        stale.json::<Value>().await.unwrap()["code"],
        "workflow.revision-mismatch"
    );
    assert_eq!(f.run_rows(DELAYED).await, before);
    let recovered = http
        .post(format!("{origin}/v1/runs"))
        .bearer_auth(&producer_a)
        .header("Idempotency-Key", "a-1")
        .json(
            &json!({"workflow":DELAYED,"workflowRevision":delayed_revision,"input":delayed_input}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(recovered.status(), 200);
    let recovered: Value = recovered.json().await.unwrap();
    assert_eq!(recovered["runId"], delayed_run);
    assert_eq!(recovered["workflowRevision"], delayed_revision);
    let reinterpreted = http
        .post(format!("{origin}/v1/runs"))
        .bearer_auth(&producer_a)
        .header("Idempotency-Key", "a-1")
        .json(&json!({"workflow":DELAYED,"workflowRevision":active_revision,"input":delayed_input}))
        .send()
        .await
        .unwrap();
    assert_eq!(reinterpreted.status(), 409);
    assert_eq!(
        reinterpreted.json::<Value>().await.unwrap()["code"],
        "idempotency.key-reused"
    );
    let (status, body) = start_run(
        &http,
        &origin,
        &producer_a,
        "a-2",
        DELAYED,
        delayed_input.clone(),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["workflowRevision"],
        upgraded.get(DELAYED).unwrap().definition.digest
    );
    server.abort();

    // Rolling flow A back leaves flow B where it was.
    let governed_before = f.run_rows(GOVERNED).await;
    let applied = deployment::apply(&migration, &runtime, &workflows, &[])
        .await
        .unwrap();
    assert_eq!(
        changes(&applied),
        pairs(&[(DELAYED, "replace"), (GOVERNED, "unchanged")])
    );
    assert_eq!(f.active_flows().await, installed);
    assert_eq!(applied.activation.package_digest, workflows.digest());
    assert_eq!(
        applied.activation.predecessor_package_digest.as_deref(),
        Some(upgraded.digest())
    );
    assert_eq!(f.run_rows(GOVERNED).await, governed_before);
    assert_eq!(f.activations().await, 3);

    // Removing flow B is explicit and refused while B has live runs.
    let (only_path, only_delayed_runtime, only_delayed) =
        f.runtime("only-delayed.yaml", json!([delayed_v1]));
    for (remove, code) in [
        (vec![], "deployment.workflow-unlisted"),
        (vec![GOVERNED.to_owned()], "deployment.workflow-live-runs"),
        (vec![DELAYED.to_owned()], "deployment.refused"),
        (vec!["retired-flow".to_owned()], "deployment.refused"),
    ] {
        let error = deployment::apply(&migration, &only_delayed_runtime, &only_delayed, &remove)
            .await
            .unwrap_err();
        assert_eq!(error.code, code, "{remove:?}");
    }
    let refused = local_cli(&only_path, "plan", false);
    assert_eq!(
        refused["diagnostics"][0]["code"],
        "coordinator.deployment.workflow-unlisted"
    );
    assert!(refused["diagnostics"][0]["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("--remove-workflow"));
    assert_eq!(f.activations().await, 3);
    assert_eq!(f.active_flows().await, installed);
    assert_eq!(f.run_rows(GOVERNED).await, governed_before);

    // Once B's runs are terminal, the explicit removal leaves A in place and
    // B's settled runs readable.
    let governed_id: Uuid = governed_run.parse().unwrap();
    f.admin.execute(&format!("UPDATE {}.runs SET state='cancelled',cancel_requested=true,restore_review_required=false WHERE run_id=$1", f.namespace), &[&governed_id]).await.unwrap();
    fixture_job_state(&f.admin, &f.namespace, governed_id, "dead-lettered", false).await;
    let planned = local_cli_args(&only_path, &["plan", "--remove-workflow", GOVERNED], true);
    assert_eq!(planned["workflows"][1]["workflow"], GOVERNED);
    assert_eq!(planned["workflows"][1]["change"], "remove");
    let applied = deployment::apply(
        &migration,
        &only_delayed_runtime,
        &only_delayed,
        &[GOVERNED.to_owned()],
    )
    .await
    .unwrap();
    assert_eq!(
        changes(&applied),
        pairs(&[(DELAYED, "unchanged"), (GOVERNED, "remove")])
    );
    assert_eq!(
        f.active_flows().await,
        json!({DELAYED: digest(&delayed_v1)})
    );
    let remaining = store
        .as_ref()
        .clone()
        .with_workflows_digest(only_delayed.digest().to_owned());
    deployment::check(&remaining, &only_delayed_runtime, only_delayed.digest())
        .await
        .unwrap();
    assert_eq!(
        remaining.status(governed_id).await.unwrap().state,
        "cancelled"
    );
    drop(migration);
    f.stop().await;
}

/// A deployment operator lists no flow: every deployment-wide action reaches
/// each flow the deployment serves, including a flow added after the policy
/// was written, while no run of any flow is within its reach.
#[tokio::test]
async fn deployment_operators_act_on_every_flow_without_a_flow_list() {
    let f = TwoFlowFixture::start().await;
    let delayed = f.pin(&f.delayed_project, "delayed");
    let governed = f.pin(&TwoFlowFixture::governed_project(), "governed");
    let (_, runtime, workflows) = f.runtime("delayed.yaml", json!([delayed.clone()]));
    let migration = deployment::open_ctl(&runtime, true).await.unwrap();
    deployment::apply(&migration, &runtime, &workflows, &[])
        .await
        .unwrap();
    let store = deployment::open(&runtime, false).await.unwrap();
    let d = deployment::config(&runtime).unwrap();
    let authenticator = Arc::new(
        d.authentication
            .authenticator(&runtime.secret_providers, true)
            .await
            .unwrap(),
    );
    let adapters = Arc::new(HttpAdapters::new(&runtime).unwrap());
    let http = reqwest::Client::new();
    let deployment_operator = f.token(
        "deployment-operator",
        "deployment-operator",
        "coordinator:operate",
    );
    let producer_a = f.token("producer-a", "owner-a", "coordinator:start");
    let doctor = |origin: &str| {
        http.get(format!("{origin}/v1/doctor"))
            .bearer_auth(&deployment_operator)
            .send()
    };

    let (origin, server) = serve_fixture(HttpState {
        recovery_only: false,
        store: store.clone(),
        runtime: runtime.clone(),
        workflows: workflows.clone(),
        authenticator: authenticator.clone(),
        adapters: adapters.clone(),
    })
    .await;
    let response = doctor(&origin).await.unwrap();
    assert_eq!(response.status(), 200);
    let (status, body) = start_run(
        &http,
        &origin,
        &producer_a,
        "a-1",
        DELAYED,
        json!({"applicationId":"00000000-0000-4000-8000-000000000001","sendAfter":(Utc::now()+chrono::Duration::minutes(20)).to_rfc3339()}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let delayed_run = body["runId"].as_str().unwrap().to_owned();
    server.abort();

    // Add the governed flow. No policy changes, and the deployment operator
    // still takes every deployment-wide action against both workflows.
    let (_, both_runtime, both) = f.runtime("both.yaml", json!([delayed, governed]));
    deployment::apply(&migration, &both_runtime, &both, &[])
        .await
        .unwrap();
    drop(migration);
    let both_store = Arc::new(
        store
            .as_ref()
            .clone()
            .with_workflows_digest(both.digest().to_owned()),
    );
    let (origin, server) = serve_fixture(HttpState {
        recovery_only: false,
        store: both_store.clone(),
        runtime: both_runtime.clone(),
        workflows: both.clone(),
        authenticator: authenticator.clone(),
        adapters: adapters.clone(),
    })
    .await;
    let response = doctor(&origin).await.unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["activationReady"], true, "{body}");
    // The hold, the attestation and both releases complete in order, with the
    // delayed run still waiting.
    for (path, body, answer) in [
        (
            "restore-hold",
            json!({"reason":"deployment-wide"}),
            json!({"restoreHold":true}),
        ),
        (
            "complete-execution-recovery",
            json!({"recoveryReference":"deployment-wide","executionHistoryComplete":true,"priorDeploymentFenced":true}),
            json!({"executionRecoveryReviewed":true}),
        ),
        (
            "release-restore-hold",
            json!({"reason":"deployment-wide"}),
            json!({"restoreHold":false}),
        ),
        (
            "release-admission-hold",
            json!({"recoveryReference":"deployment-wide","admissionHistoryComplete":true,"priorDeploymentFenced":true}),
            json!({"admissionsHold":false}),
        ),
        (
            "retention",
            json!({"before":Utc::now().to_rfc3339(),"limit":10}),
            json!({"erased":0}),
        ),
    ] {
        let response = http
            .post(format!("{origin}/v1/{path}"))
            .bearer_auth(&deployment_operator)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{path}");
        assert_eq!(response.json::<Value>().await.unwrap(), answer, "{path}");
    }

    // Run actions stay scoped by workflows, and this policy lists none: no run of
    // either flow is readable or listable through it, and it starts nothing.
    for request in [
        http.get(format!("{origin}/v1/runs/{delayed_run}")),
        http.get(format!("{origin}/v1/runs?limit=10")),
    ] {
        let response = request
            .bearer_auth(&deployment_operator)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
    }
    let (status, body) = start_run(
        &http,
        &origin,
        &deployment_operator,
        "operator-start",
        GOVERNED,
        json!({"applicationId":"00000000-0000-4000-8000-000000000002"}),
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("operation.not-authorized"))
    );
    server.abort();
    f.stop().await;
}

/// Forward the service's standard error line by line, so a test can wait for
/// one event without blocking the runtime that serves the fixture issuer.
fn stderr_lines(child: &mut ServiceProcess) -> tokio::sync::mpsc::UnboundedReceiver<String> {
    let stderr = child.stderr.take().unwrap();
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in std::io::BufRead::lines(std::io::BufReader::new(stderr)) {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    receiver
}

/// Wait up to 20 seconds for a line containing `needle`, keeping every line read.
async fn await_line(
    lines: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    seen: &mut Vec<String>,
    needle: &str,
) {
    let found = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while let Some(line) = lines.recv().await {
            let found = line.contains(needle);
            seen.push(line);
            if found {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(found, Ok(true), "no line containing {needle}: {seen:#?}");
}

/// A worker poll that fails is retried only after the deployment is confirmed
/// again. A database the runtime role cannot reach holds the worker without
/// stopping the service; a moved activation found the same way stops it.
#[tokio::test]
async fn the_service_waits_out_an_unreachable_database_and_stops_on_a_moved_activation() {
    let mut f = TwoFlowFixture::start().await;
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let origin = format!("http://127.0.0.1:{port}");
    f.doc["deployment"]["listener"]["bind"] = json!(format!("127.0.0.1:{port}"));
    let delayed = f.pin(&f.delayed_project, "delayed");
    let governed = f.pin(&TwoFlowFixture::governed_project(), "governed");
    // The service process keeps its own durable audit file.
    let audit = f.doc["deployment"]["auditFile"].clone();
    f.doc["deployment"]["auditFile"] = json!(f.root_path.join("service-audit.jsonl"));
    let (service_path, _, _) = f.runtime("service.yaml", json!([delayed.clone()]));
    f.doc["deployment"]["auditFile"] = audit;
    let (_, runtime, workflows) = f.runtime("delayed.yaml", json!([delayed.clone()]));
    let migration = deployment::open_ctl(&runtime, true).await.unwrap();
    deployment::apply(&migration, &runtime, &workflows, &[])
        .await
        .unwrap();
    let store = deployment::open(&runtime, false).await.unwrap();
    let http = reqwest::Client::new();
    let mut child = spawn_service(&service_path, false);
    let mut lines = stderr_lines(&mut child);
    let mut seen = Vec::new();
    probe_service_readiness(&http, &origin, std::time::Duration::from_secs(10))
        .await
        .unwrap_or_else(|diagnostic| {
            while let Ok(line) = lines.try_recv() {
                seen.push(line);
            }
            panic!(
                "service was not ready: {diagnostic}; child_exit={:?}; {seen:#?}",
                child.try_wait().unwrap()
            )
        });

    // Refuse the runtime role new sessions and end the ones it holds.
    f.admin
        .batch_execute(&format!(
            "ALTER ROLE {0} NOLOGIN; SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='{0}'",
            f.role
        ))
        .await
        .unwrap();
    let unreachable = deployment::check(&store, &runtime, workflows.digest())
        .await
        .unwrap_err();
    assert_eq!(unreachable.code, "store-unavailable");
    assert_eq!(
        unreachable.suggested_action.as_deref(),
        Some("restore database connectivity")
    );
    await_line(&mut lines, &mut seen, "worker-unavailable").await;
    await_line(&mut lines, &mut seen, "store-unavailable").await;
    assert!(
        child.try_wait().unwrap().is_none(),
        "an unreachable database must not stop the service: {seen:#?}"
    );
    assert_eq!(
        http.get(format!("{origin}/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    let (status, body) = start_run(
        &http,
        &origin,
        &f.token("producer-a", "owner-a", "coordinator:start"),
        "outage-1",
        DELAYED,
        json!({"applicationId":"00000000-0000-4000-8000-000000000001","sendAfter":(Utc::now()+chrono::Duration::minutes(20)).to_rfc3339()}),
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (503, Some("service.unavailable"))
    );
    assert!(body.get("suggestedAction").is_none());

    f.admin
        .batch_execute(&format!("ALTER ROLE {} LOGIN", f.role))
        .await
        .unwrap();
    await_line(&mut lines, &mut seen, "worker loop resumed").await;
    assert!(child.try_wait().unwrap().is_none());
    probe_service_readiness(&http, &origin, std::time::Duration::from_secs(10))
        .await
        .unwrap_or_else(|diagnostic| panic!("service did not recover: {diagnostic}"));

    // Applying another set of packages moves the activation under the service.
    let resumed = seen.len();
    let (_, both_runtime, both) = f.runtime("both.yaml", json!([delayed, governed]));
    deployment::apply(&migration, &both_runtime, &both, &[])
        .await
        .unwrap();
    assert!(!await_service_exit(&mut child).await.success());
    while let Some(line) = lines.recv().await {
        seen.push(line);
    }
    let after = &seen[resumed..];
    let refused_poll = after
        .iter()
        .position(|line| line.contains("worker-unavailable"));
    let stopped = after
        .iter()
        .position(|line| line.starts_with("deployment.refused"));
    assert!(
        matches!((refused_poll, stopped), (Some(poll), Some(stop)) if poll < stop),
        "the worker transaction refuses the moved activation, then the confirmation stops the service: {seen:#?}"
    );
    assert!(
        !after
            .iter()
            .any(|line| line.contains("worker loop resumed")),
        "no poll succeeds under a moved activation: {seen:#?}"
    );
    drop((store, migration));
    f.stop().await;
}

/// Once apply registers a rotated key set, a router still serving the old
/// runtime file refuses by name: a start answers 409 `state-key-custody` and
/// admits nothing, and readiness answers not ready. Neither answer names a
/// key or a key commitment. The runtime file apply registered serves again.
#[tokio::test]
async fn a_rotated_key_set_refuses_starts_and_readiness_on_the_old_runtime_file() {
    let mut f = TwoFlowFixture::start().await;
    let delayed = f.pin(&f.delayed_project, "delayed");
    let (_, runtime, workflows) = f.runtime("delayed.yaml", json!([delayed.clone()]));
    let migration = deployment::open_ctl(&runtime, true).await.unwrap();
    deployment::apply(&migration, &runtime, &workflows, &[])
        .await
        .unwrap();
    let (origin, server) = serve_runtime(&runtime, &workflows).await;
    let http = reqwest::Client::new();
    probe_service_readiness(&http, &origin, std::time::Duration::from_secs(10))
        .await
        .unwrap_or_else(|diagnostic| panic!("router was not ready: {diagnostic}"));

    f.rotate_state_keys();
    // The first apply still holds its audit file's single-writer lock.
    f.doc["deployment"]["auditFile"] = json!(f.root_path.join("rotated-audit.jsonl"));
    let (_, rotated, rotated_flows) = f.runtime("rotated.yaml", json!([delayed]));
    let rotation = deployment::open_ctl(&rotated, true).await.unwrap();
    deployment::apply(&rotation, &rotated, &rotated_flows, &[])
        .await
        .unwrap();
    let secrets = f.custody_secrets().await;

    let producer = f.token("producer-a", "owner-a", "coordinator:start");
    let input = json!({"applicationId":"00000000-0000-4000-8000-000000000001","sendAfter":(Utc::now()+chrono::Duration::minutes(20)).to_rfc3339()});
    let (status, refused) = start_run(
        &http,
        &origin,
        &producer,
        "custody-1",
        DELAYED,
        input.clone(),
    )
    .await;
    assert_eq!(
        (status, refused["code"].as_str()),
        (409, Some("deployment.refused")),
        "{refused}"
    );
    // The caller is not the deployment's operator: the problem carries no
    // configuration key and no operator fix.
    assert!(
        refused.get("suggestedAction").is_none()
            && !refused.to_string().contains("deployment.stateKeys"),
        "{refused}"
    );
    assert_eq!(f.run_rows(DELAYED).await, json!({"runs":null,"jobs":null}));
    let response = http.get(format!("{origin}/ready")).send().await.unwrap();
    assert_eq!(response.status(), 503);
    let readiness = response.text().await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&readiness).unwrap(),
        json!({"ready":false})
    );
    for printed in [refused.to_string(), readiness] {
        assert!(
            !secrets
                .iter()
                .any(|secret| printed.contains(secret.as_str())),
            "a custody refusal printed a key or a key commitment"
        );
    }

    // A router on the runtime file apply registered admits the same start.
    let (rotated_origin, rotated_server) = serve_runtime(&rotated, &rotated_flows).await;
    probe_service_readiness(&http, &rotated_origin, std::time::Duration::from_secs(10))
        .await
        .unwrap_or_else(|diagnostic| panic!("rotated router was not ready: {diagnostic}"));
    let (status, body) = start_run(
        &http,
        &rotated_origin,
        &producer,
        "custody-1",
        DELAYED,
        input,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        f.run_rows(DELAYED).await["runs"].as_array().map(Vec::len),
        Some(1)
    );
    server.abort();
    rotated_server.abort();
    drop((migration, rotation));
    f.stop().await;
}

/// A service still running on the old runtime file when apply registers a
/// rotated key set dispatches nothing more. Its next worker poll is refused
/// inside the worker transaction, the confirmation that follows names
/// `state-key-custody`, and the service stops with a failure status for its
/// supervisor to restart it with the runtime file apply registered. Work that
/// came due stays pending with no attempt, and nothing the service prints
/// names a key or a key commitment.
#[tokio::test]
async fn a_rotated_key_set_stops_a_service_on_the_old_runtime_file_before_it_dispatches() {
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };
    let mut f = TwoFlowFixture::start().await;
    // A read attempt would first exchange a token here.
    let token = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&token)
        .await;
    f.doc["connections"]["applications"]["authorization"]["tokenEndpoint"] =
        json!(format!("{}/token", token.uri()));
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let origin = format!("http://127.0.0.1:{port}");
    f.doc["deployment"]["listener"]["bind"] = json!(format!("127.0.0.1:{port}"));
    let delayed = f.pin(&f.delayed_project, "delayed");
    let audit = f.doc["deployment"]["auditFile"].clone();
    f.doc["deployment"]["auditFile"] = json!(f.root_path.join("service-audit.jsonl"));
    let (service_path, _, _) = f.runtime("service.yaml", json!([delayed.clone()]));
    f.doc["deployment"]["auditFile"] = audit;
    let (_, runtime, workflows) = f.runtime("delayed.yaml", json!([delayed.clone()]));
    let migration = deployment::open_ctl(&runtime, true).await.unwrap();
    deployment::apply(&migration, &runtime, &workflows, &[])
        .await
        .unwrap();
    // The service polls once as it starts and then every five seconds, so no
    // poll is in flight while the rotation is applied and the admitted work
    // comes due: the next poll finds both.
    let mut child = ServiceProcess(
        std::process::Command::new(env!("CARGO_BIN_EXE_coordinator"))
            .arg("--runtime-config")
            .arg(&service_path)
            .args(["--poll-ms", "5000"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut lines = stderr_lines(&mut child);
    let mut seen = Vec::new();
    let http = reqwest::Client::new();
    probe_service_readiness(&http, &origin, std::time::Duration::from_secs(10))
        .await
        .unwrap_or_else(|diagnostic| panic!("service was not ready: {diagnostic}"));
    let (status, body) = start_run(
        &http,
        &origin,
        &f.token("producer-a", "owner-a", "coordinator:start"),
        "custody-1",
        DELAYED,
        json!({"applicationId":"00000000-0000-4000-8000-000000000001","sendAfter":(Utc::now()+chrono::Duration::minutes(20)).to_rfc3339()}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let run = Uuid::parse_str(body["runId"].as_str().unwrap()).unwrap();

    f.rotate_state_keys();
    // The first apply still holds its audit file's single-writer lock.
    f.doc["deployment"]["auditFile"] = json!(f.root_path.join("rotated-audit.jsonl"));
    let (_, rotated, rotated_flows) = f.runtime("rotated.yaml", json!([delayed]));
    let rotation = deployment::open_ctl(&rotated, true).await.unwrap();
    deployment::apply(&rotation, &rotated, &rotated_flows, &[])
        .await
        .unwrap();
    f.admin
        .execute(
            &format!(
                "UPDATE {}.jobs SET next_attempt_at=clock_timestamp() WHERE run_id=$1",
                f.namespace
            ),
            &[&run],
        )
        .await
        .unwrap();
    await_line(&mut lines, &mut seen, "state-key-custody").await;
    assert!(!await_service_exit(&mut child).await.success());
    while let Some(line) = lines.recv().await {
        seen.push(line);
    }
    let refused_poll = seen
        .iter()
        .position(|line| line.contains("worker-unavailable"));
    let stopped = seen
        .iter()
        .position(|line| line.starts_with("state-key-custody"));
    assert!(
        matches!((refused_poll, stopped), (Some(poll), Some(stop)) if poll < stop),
        "the worker transaction refuses the changed custody, then the confirmation stops the service: {seen:#?}"
    );
    assert!(
        !seen.iter().any(|line| line.contains("worker loop resumed")),
        "no poll succeeds under changed key custody: {seen:#?}"
    );
    assert!(
        token.received_requests().await.unwrap().is_empty(),
        "no step was executed"
    );
    let jobs: Vec<(String, i16, bool)> = f
        .admin
        .query(
            &format!(
                "SELECT state, attempt, lease_token IS NULL FROM {}.jobs WHERE run_id=$1",
                f.namespace
            ),
            &[&run],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    assert_eq!(jobs, [("pending".to_owned(), 0, true)]);
    let secrets = f.custody_secrets().await;
    assert!(
        !seen
            .iter()
            .any(|line| secrets.iter().any(|secret| line.contains(secret.as_str()))),
        "the service printed a key or a key commitment"
    );
    drop((migration, rotation));
    f.stop().await;
}

/// SIGTERM stops the service the way an orchestrator stops it: the worker
/// finishes the attempt it holds, leases nothing more, and the process exits 0
/// with no lease left behind.
#[tokio::test]
async fn a_terminated_service_finishes_the_attempt_in_flight_and_leases_nothing_more() {
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };
    let mut f = TwoFlowFixture::start().await;
    // The token exchange of each read attempt answers slowly, so the stop
    // arrives while one attempt is in flight.
    let token = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(503).set_delay(std::time::Duration::from_millis(1_500)))
        .mount(&token)
        .await;
    f.doc["connections"]["applications"]["authorization"]["tokenEndpoint"] =
        json!(format!("{}/token", token.uri()));
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let origin = format!("http://127.0.0.1:{port}");
    f.doc["deployment"]["listener"]["bind"] = json!(format!("127.0.0.1:{port}"));
    let delayed = f.pin(&f.delayed_project, "delayed");
    let audit = f.doc["deployment"]["auditFile"].clone();
    f.doc["deployment"]["auditFile"] = json!(f.root_path.join("service-audit.jsonl"));
    let (service_path, _, _) = f.runtime("service.yaml", json!([delayed.clone()]));
    f.doc["deployment"]["auditFile"] = audit;
    let (_, runtime, workflows) = f.runtime("delayed.yaml", json!([delayed]));
    let migration = deployment::open_ctl(&runtime, true).await.unwrap();
    deployment::apply(&migration, &runtime, &workflows, &[])
        .await
        .unwrap();
    let http = reqwest::Client::new();
    let mut child = spawn_service(&service_path, false);
    let mut lines = stderr_lines(&mut child);
    let mut seen = Vec::new();
    probe_service_readiness(&http, &origin, std::time::Duration::from_secs(10))
        .await
        .unwrap_or_else(|diagnostic| panic!("service was not ready: {diagnostic}"));
    let producer = f.token("producer-a", "owner-a", "coordinator:start");
    for (key, application) in [
        ("terminate-1", "00000000-0000-4000-8000-000000000001"),
        ("terminate-2", "00000000-0000-4000-8000-000000000002"),
    ] {
        let (status, body) = start_run(
            &http,
            &origin,
            &producer,
            key,
            DELAYED,
            json!({"applicationId": application, "sendAfter": (Utc::now() - chrono::Duration::minutes(1)).to_rfc3339()}),
        )
        .await;
        assert_eq!(status, 200, "{body}");
    }
    let requested = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            if !token.received_requests().await.unwrap().is_empty() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(requested.is_ok(), "no read attempt started");

    assert!(std::process::Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .unwrap()
        .success());
    let status = await_service_exit(&mut child).await;
    while let Some(line) = lines.recv().await {
        seen.push(line);
    }
    assert!(status.success(), "{status:?}: {seen:#?}");
    assert!(
        seen.iter().any(|line| line.contains("\"stopped\"")),
        "the service reports a clean stop: {seen:#?}"
    );
    assert_eq!(
        token.received_requests().await.unwrap().len(),
        1,
        "no attempt starts after the stop"
    );
    let rows = f
        .admin
        .query(
            &format!(
                "SELECT state, attempt, lease_token IS NULL FROM {}.jobs WHERE step='read-application' ORDER BY attempt DESC",
                f.namespace
            ),
            &[],
        )
        .await
        .unwrap();
    let jobs: Vec<(String, i16, bool)> = rows
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    assert!(
        matches!(jobs.first(), Some((state, 1, true)) if state != "leased"),
        "the attempt in flight finished and released its lease: {jobs:?}"
    );
    assert!(
        jobs.iter().skip(1).all(|(_, attempt, _)| *attempt == 0),
        "no further attempt was leased: {jobs:?}"
    );
    drop(migration);
    f.stop().await;
}

/// Scrape the metrics socket, holding it to the exposition media type and to
/// no caching, and return the body.
async fn scrape_metrics(http: &reqwest::Client, origin: &str) -> String {
    let response = http.get(format!("{origin}/metrics")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let header = |name: reqwest::header::HeaderName| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    assert_eq!(
        header(reqwest::header::CONTENT_TYPE).as_deref(),
        Some("text/plain; version=0.0.4")
    );
    assert_eq!(
        header(reqwest::header::CACHE_CONTROL).as_deref(),
        Some("no-store")
    );
    response.text().await.unwrap()
}

/// The value of one exact series in a scrape, or `None` when it has no sample.
fn sample(body: &str, series: &str) -> Option<u64> {
    body.lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' ')?.parse().ok())
}

/// The operator reads the closed series on the metrics socket only. Refusals
/// and admissions move them, and a store the service cannot read leaves the
/// dispatch gauge without samples rather than reporting an empty queue.
#[tokio::test]
async fn the_metrics_listener_counts_closed_series_and_leaves_the_gauge_stale_in_an_outage() {
    let mut f = TwoFlowFixture::start().await;
    let sockets: Vec<std::net::TcpListener> = (0..2)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let [port, metrics_port] = [0, 1].map(|i| sockets[i].local_addr().unwrap().port());
    drop(sockets);
    let origin = format!("http://127.0.0.1:{port}");
    let metrics_origin = format!("http://127.0.0.1:{metrics_port}");
    f.doc["deployment"]["listener"]["bind"] = json!(format!("127.0.0.1:{port}"));
    f.doc["deployment"]["metricsListener"] = json!({"bind": format!("127.0.0.1:{metrics_port}")});
    let delayed = f.pin(&f.delayed_project, "delayed");
    let audit = f.doc["deployment"]["auditFile"].clone();
    f.doc["deployment"]["auditFile"] = json!(f.root_path.join("service-audit.jsonl"));
    let (service_path, _, _) = f.runtime("service.yaml", json!([delayed.clone()]));
    f.doc["deployment"]["auditFile"] = audit;
    let (_, runtime, workflows) = f.runtime("delayed.yaml", json!([delayed]));
    let migration = deployment::open_ctl(&runtime, true).await.unwrap();
    deployment::apply(&migration, &runtime, &workflows, &[])
        .await
        .unwrap();
    let http = reqwest::Client::new();
    let mut child = spawn_service(&service_path, false);
    let mut lines = stderr_lines(&mut child);
    let mut seen = Vec::new();
    await_line(&mut lines, &mut seen, "serving Registry Coordinator").await;
    assert!(
        seen.last().unwrap().contains("\"metrics_listener\":true"),
        "{seen:#?}"
    );
    probe_service_readiness(&http, &origin, std::time::Duration::from_secs(10))
        .await
        .unwrap_or_else(|diagnostic| panic!("service was not ready: {diagnostic}"));

    let body = scrape_metrics(&http, &metrics_origin).await;
    assert_eq!(sample(&body, "coordinator_runs_admitted_total"), Some(0));
    for state in ["pending", "leased", "unknown"] {
        assert_eq!(
            sample(
                &body,
                &format!("coordinator_dispatch_jobs{{state=\"{state}\"}}")
            ),
            Some(0),
            "{body}"
        );
    }
    // The public listener serves no metrics route.
    assert_eq!(
        http.get(format!("{origin}/metrics"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // A malformed bearer and a verified token no policy admits are both
    // refused before a caller is resolved, each under its own reason.
    let malformed = http
        .get(format!("{origin}/v1/runs?limit=10"))
        .bearer_auth("not-a-token")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), 401);
    let unadmitted = http
        .get(format!("{origin}/v1/runs?limit=10"))
        .bearer_auth(f.token("producer-a", "owner-a", "coordinator:other"))
        .send()
        .await
        .unwrap();
    assert_eq!(unadmitted.status(), 403);
    let application = "00000000-0000-4000-8000-0000000000aa";
    let (status, run) = start_run(
        &http,
        &origin,
        &f.token("producer-a", "owner-a", "coordinator:start"),
        "metrics-1",
        DELAYED,
        json!({"applicationId": application, "sendAfter": (Utc::now() + chrono::Duration::minutes(20)).to_rfc3339()}),
    )
    .await;
    assert_eq!(status, 200, "{run}");
    let run_id = run["runId"].as_str().unwrap().to_owned();
    let body = scrape_metrics(&http, &metrics_origin).await;
    for (series, expected) in [
        (
            "coordinator_authentication_refusals_total{reason=\"refused\"}",
            1,
        ),
        (
            "coordinator_authentication_refusals_total{reason=\"policy\"}",
            1,
        ),
        (
            "coordinator_authentication_refusals_total{reason=\"unavailable\"}",
            0,
        ),
        ("coordinator_runs_admitted_total", 1),
        ("coordinator_dispatch_jobs{state=\"pending\"}", 1),
    ] {
        assert_eq!(sample(&body, series), Some(expected), "{series}: {body}");
    }
    for caller_text in [
        DELAYED,
        run_id.as_str(),
        application,
        "owner-a",
        "producer-a",
    ] {
        assert!(
            !body.contains(caller_text),
            "{caller_text} labelled: {body}"
        );
    }

    // Refuse the runtime role new sessions and end the ones it holds.
    f.admin
        .batch_execute(&format!(
            "ALTER ROLE {0} NOLOGIN; SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='{0}'",
            f.role
        ))
        .await
        .unwrap();
    let body = scrape_metrics(&http, &metrics_origin).await;
    assert!(
        !body.contains("coordinator_dispatch_jobs{"),
        "an unreadable queue has no samples, never zero: {body}"
    );
    assert!(body.contains("# TYPE coordinator_dispatch_jobs gauge"));
    assert_eq!(sample(&body, "coordinator_runs_admitted_total"), Some(1));
    await_line(
        &mut lines,
        &mut seen,
        "the dispatch queue could not be sampled",
    )
    .await;
    assert!(
        seen.last().unwrap().contains("store-unavailable"),
        "{seen:#?}"
    );

    f.admin
        .batch_execute(&format!("ALTER ROLE {} LOGIN", f.role))
        .await
        .unwrap();
    let sampled = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let body = scrape_metrics(&http, &metrics_origin).await;
            if sample(&body, "coordinator_dispatch_jobs{state=\"pending\"}") == Some(1) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(sampled.is_ok(), "the gauge did not return with the store");

    stop_service(&mut child).await;
    while let Some(line) = lines.recv().await {
        seen.push(line);
    }
    for caller_text in ["not-a-token", application, run_id.as_str()] {
        assert!(
            !seen.iter().any(|line| line.contains(caller_text)),
            "{caller_text} logged: {seen:#?}"
        );
    }
    drop(migration);
    f.stop().await;
}

#[path = "support/postgres_tool.rs"]
mod postgres_tool;

#[path = "support/database_clock.rs"]
mod database_clock;

/// This also tests PostgreSQL's backup tooling, so it is run explicitly with a
/// client matching the disposable server, using scripts/test-restore.sh.
#[tokio::test]
#[ignore = "requires matching pg_dump and psql; run products/coordinator/scripts/test-restore.sh"]
async fn restoring_a_two_flow_backup_keeps_every_flow_and_its_runs() {
    use registry_coordinator::store::Actor;
    let dump_tool = std::env::var("COORDINATOR_PG_DUMP").unwrap_or_else(|_| "pg_dump".into());
    let psql_tool = std::env::var("COORDINATOR_PSQL").unwrap_or_else(|_| "psql".into());
    let f = TwoFlowFixture::start().await;
    let delayed = f.pin(&f.delayed_project, "delayed");
    let governed = f.pin(&TwoFlowFixture::governed_project(), "governed");
    let (_, runtime, workflows) = f.runtime("both.yaml", json!([delayed, governed]));
    let migration = deployment::open_ctl(&runtime, true).await.unwrap();
    deployment::apply(&migration, &runtime, &workflows, &[])
        .await
        .unwrap();
    drop(migration);
    let store = deployment::open(&runtime, false).await.unwrap();
    let owner = Actor {
        issuer: f.issuer.issuer().to_owned(),
        subject: "owner".into(),
        client_id: "producer-wide".into(),
        operator: false,
    };
    let mut runs = Vec::new();
    for (flow, input) in [
        (
            DELAYED,
            json!({"applicationId":"00000000-0000-4000-8000-000000000001","sendAfter":(Utc::now()+chrono::Duration::minutes(20)).to_rfc3339()}),
        ),
        (
            GOVERNED,
            json!({"applicationId":"00000000-0000-4000-8000-000000000002"}),
        ),
    ] {
        let package = workflows.get(flow).unwrap();
        let binding = runtime
            .binding_digest_for(&package.definition.workflow)
            .unwrap();
        runs.push(
            store
                .admit_owned(&package.definition, input, &owner, flow, &binding)
                .await
                .unwrap(),
        );
    }
    let active_before = f.active_flows().await;
    let delayed_before = f.run_rows(DELAYED).await;
    let governed_before = f.run_rows(GOVERNED).await;
    let backup = f.root_path.join("two-flow.sql");
    let dump = postgres_tool::command(&dump_tool, &f.database)
        .args([
            "--no-password",
            "--no-owner",
            "--no-acl",
            "--schema",
            &f.namespace,
            "--file",
        ])
        .arg(&backup)
        .output()
        .expect("start matching pg_dump");
    assert!(dump.status.success(), "isolated namespace backup failed");
    drop(store);
    f.admin
        .batch_execute(&format!("DROP SCHEMA {} CASCADE", f.namespace))
        .await
        .unwrap();
    let restore = postgres_tool::command(&psql_tool, &f.database)
        .args([
            "--no-password",
            "--no-psqlrc",
            "--set",
            "ON_ERROR_STOP=1",
            "--file",
        ])
        .arg(&backup)
        .output()
        .expect("start matching psql");
    assert!(
        restore.status.success(),
        "isolated namespace restore failed"
    );
    assert_eq!(f.active_flows().await, active_before);
    assert_eq!(f.run_rows(DELAYED).await, delayed_before);
    assert_eq!(f.run_rows(GOVERNED).await, governed_before);
    // The dump carries no grants; applying the same retained packages again
    // restores them without changing either flow.
    let migration = deployment::open_ctl(&runtime, true).await.unwrap();
    let applied = deployment::apply(&migration, &runtime, &workflows, &[])
        .await
        .unwrap();
    assert_eq!(
        changes(&applied),
        pairs(&[(DELAYED, "unchanged"), (GOVERNED, "unchanged")])
    );
    drop(migration);
    let restored = deployment::open(&runtime, false).await.unwrap();
    deployment::check(&restored, &runtime, workflows.digest())
        .await
        .unwrap();
    for (run, flow) in runs.iter().zip([DELAYED, GOVERNED]) {
        let status = restored.status_owned(*run, &owner).await.unwrap();
        assert_eq!(status.workflow, flow);
        assert_eq!(status.state, "running");
    }
    f.stop().await;
}

#[tokio::test]
#[ignore = "requires built Node/Python bindings, TypeScript compiler, and Pyright"]
async fn generated_typed_clients_start_get_and_cancel_real_runs() {
    generated_typed_client_journeys(&[
        "delayed-follow-up",
        "external-job",
        "standalone-review",
        "proposal-follow-up",
    ])
    .await;
}

#[tokio::test]
#[ignore = "requires built Node/Python bindings, TypeScript compiler, and Pyright"]
async fn generated_external_job_clients_read_a_successful_terminal_outcome() {
    generated_typed_client_journeys(&["external-job"]).await;
}

async fn generated_typed_client_journeys(projects: &[&str]) {
    use registry_coordinator::sdk::{generate, Language};
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let examples = repository.join("products/coordinator/examples");
    for &workflow in projects {
        let mut f = TwoFlowFixture::start().await;
        let project = if workflow == DELAYED {
            f.delayed_project.clone()
        } else {
            examples.join(workflow)
        };
        let jobs = if workflow == "external-job" {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/jobs/status"))
                .and(query_param("id", "sdk-synthetic-job"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "jobId":"sdk-synthetic-job", "state":"succeeded"
                })))
                .expect(4)
                .mount(&server)
                .await;
            Some(server)
        } else {
            None
        };
        if workflow == "external-job" {
            let external =
                RuntimeConfig::load(&examples.join("external-job/runtime.yaml")).unwrap();
            f.doc["connections"]["jobs"] =
                serde_json::to_value(&external.connections["jobs"]).unwrap();
            f.doc["connections"]["jobs"]["baseUrl"] = json!(jobs.as_ref().unwrap().uri());
        }
        if workflow == "proposal-follow-up" {
            f.doc["connections"]["facilities"] = f.doc["connections"]["applications"].clone();
        }
        if workflow == "standalone-review" {
            let authorization = f.doc["connections"]["applications"]["authorization"].clone();
            f.doc["connections"]["review"] = json!({
                "type":"casework-review-producer", "baseUrl":"http://127.0.0.1:9011",
                "profile":"coordinator-producer", "producer":"coordinator", "authorization":authorization
            });
        }
        f.doc["deployment"]["authentication"]["policies"]["operator"]["workflows"] =
            json!([workflow]);
        f.doc["deployment"]["authentication"]["policies"]["operator"]["actions"]
            .as_array_mut()
            .unwrap()
            .push(json!("start"));
        let pin = f.pin(&project, "sdk-package");
        let (_, runtime, workflows) = f.runtime("sdk-runtime.yaml", json!([pin]));
        let migration = deployment::open_ctl(&runtime, true).await.unwrap();
        deployment::apply(&migration, &runtime, &workflows, &[])
            .await
            .unwrap();
        drop(migration);
        let definition = &workflows.get(workflow).unwrap().definition;
        let input = match workflow {
            "delayed-follow-up" => {
                json!({"applicationId":"00000000-0000-4000-8000-000000000001","sendAfter":(Utc::now()+chrono::Duration::minutes(20)).to_rfc3339()})
            }
            "external-job" => json!({"jobId":"sdk-synthetic-job"}),
            "standalone-review" | "proposal-follow-up" => serde_json::from_slice(
                &fs::read(examples.join(workflow).join("input.json")).unwrap(),
            )
            .unwrap(),
            _ => unreachable!(),
        };
        let directory = f.root_path.join("sdk");
        fs::create_dir(&directory).unwrap();
        fs::write(
            directory.join("workflow.ts"),
            generate(definition, Language::Typescript).unwrap(),
        )
        .unwrap();
        fs::write(
            directory.join("workflow.py"),
            generate(definition, Language::Python).unwrap(),
        )
        .unwrap();
        fs::write(directory.join("typed-input.ts"), format!(
        "import type {{ Input, Outcome }} from './workflow';\nconst input: Input = {};\nexport const output = (value: Outcome) => value.output;\nvoid input;\n", input
    )).unwrap();
        if workflow == "external-job" {
            let types = directory.join("typed-input.ts");
            let mut source = fs::read_to_string(&types).unwrap();
            source.push_str(r#"
export function jobId(value: Outcome): string {
  if (value.outcome === 'job-result' && value.output?.state === 'complete') return value.output.result.jobId;
  throw new Error('Expected completed external job');
}
"#);
            fs::write(types, source).unwrap();
        }
        let modules = directory.join("node_modules/@registrystack");
        fs::create_dir_all(&modules).unwrap();
        std::os::unix::fs::symlink(
            repository.join("crates/registry-stack-client-node"),
            modules.join("client"),
        )
        .unwrap();
        let tsc = std::env::var("COORDINATOR_SDK_TSC")
            .expect("COORDINATOR_SDK_TSC names the installed TypeScript compiler");
        let compiled = std::process::Command::new(tsc)
            .args([
                "--strict",
                "--skipLibCheck",
                "false",
                "--types",
                "node",
                "--typeRoots",
            ])
            .arg(repository.join("crates/registry-coordinator-client-node/node_modules/@types"))
            .args([
                "--moduleResolution",
                "node16",
                "--module",
                "node16",
                "--target",
                "es2022",
                "--outDir",
            ])
            .arg(directory.join("js"))
            .arg(directory.join("workflow.ts"))
            .arg(directory.join("typed-input.ts"))
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stdout)
        );
        fs::write(directory.join("node.cjs"), r#"
const assert = require('node:assert/strict');
const { WorkflowClient, workflow, workflowRevision } = require('./js/workflow.js');
const { CoordinatorClient } = require(process.env.COORDINATOR_SDK_NODE_CLIENT);
(async () => {
  const generic = new CoordinatorClient({baseUrl:process.env.COORDINATOR_SDK_ORIGIN,maxMutationRetries:0});
  const client = new WorkflowClient(generic);
  const token = process.env.COORDINATOR_SDK_TOKEN;
  const contract = (await generic.workflow(token, workflow)).value;
  assert.equal(contract.workflowRevision, workflowRevision);
  if (process.env.COORDINATOR_SDK_PHASE === 'terminal') {
    const { jobId } = require('./js/typed-input.js');
    const started = await client.start(token, 'generated-typescript-terminal', JSON.parse(process.env.COORDINATOR_SDK_INPUT));
    for (let attempt = 0; attempt < 500; ++attempt) {
      const read = await client.get(token, started.status.runId);
      if (read.status.state === 'finished') {
        assert.deepEqual(read.result, {outcome:'job-result',output:{state:'complete',result:{jobId:'sdk-synthetic-job'}}});
        assert.equal(jobId(read.result), 'sdk-synthetic-job');
        return;
      }
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    throw new Error('External job did not finish');
  }
  const started = await client.start(token, 'generated-typescript', JSON.parse(process.env.COORDINATOR_SDK_INPUT));
  const read = await client.get(token, started.status.runId);
  assert.equal(read.status.runId, started.status.runId);
  assert.equal(read.status.workflowRevision, started.status.workflowRevision);
  await assert.rejects(client.cancel(token, {...read, status:{...read.status, workflowRevision:'sha256:'+'1'.repeat(64)}}, 'wrong-revision'), /Workflow contract mismatch/);
  assert.equal((await generic.status(token, started.status.runId)).value.cancelRequested, false);
  const cancelled = await client.cancel(token, read, 'generated-client-regression');
  assert.equal(cancelled.status.cancelRequested, true);
  assert.equal(cancelled.status.state, 'cancelled');
})().catch(() => { console.error('generated TypeScript journey failed'); process.exitCode=1; });
"#).unwrap();
        fs::write(
            directory.join("python.py"),
            r#"
import ctypes, glob, json, os, time
runtime = os.environ.get('REGISTRY_CARGO_RUNTIME_LIBRARY_PATH')
if runtime:
    ctypes.CDLL(glob.glob(runtime + '/libaws_lc_fips*_crypto.dylib')[0], mode=ctypes.RTLD_GLOBAL)
from registry_coordinator_client import CoordinatorClient
from workflow import WorkflowClient, WORKFLOW, WORKFLOW_REVISION
generic = CoordinatorClient(os.environ['COORDINATOR_SDK_ORIGIN'], max_mutation_retries=0)
client = WorkflowClient(generic)
token = os.environ['COORDINATOR_SDK_TOKEN']
contract = generic.workflow(token, WORKFLOW)['value']
assert contract['workflowRevision'] == WORKFLOW_REVISION
if os.environ.get('COORDINATOR_SDK_PHASE') == 'terminal':
    from typed_input import job_id
    started = client.start(token, 'generated-python-terminal', json.loads(os.environ['COORDINATOR_SDK_INPUT']))
    for attempt in range(500):
        read = client.get(token, started['status']['runId'])
        if read['status']['state'] == 'finished':
            assert read['result'] == {'outcome':'job-result','output':{'state':'complete','result':{'jobId':'sdk-synthetic-job'}}}
            assert job_id(read['result']) == 'sdk-synthetic-job'
            break
        time.sleep(0.02)
    else:
        raise AssertionError('External job did not finish')
    raise SystemExit(0)
started = client.start(token, 'generated-python', json.loads(os.environ['COORDINATOR_SDK_INPUT']))
read = client.get(token, started['status']['runId'])
assert read['status']['runId'] == started['status']['runId']
assert read['status']['workflowRevision'] == started['status']['workflowRevision']
wrong = {**read, 'status':{**read['status'], 'workflowRevision':'sha256:'+'1'*64}}
try:
    client.cancel(token, wrong, 'wrong-revision')
except ValueError as error:
    assert str(error) == 'Workflow contract mismatch'
else:
    raise AssertionError('wrong revision reached cancellation')
assert generic.status(token, started['status']['runId'])['value']['cancelRequested'] is False
cancelled = client.cancel(token, read, 'generated-client-regression')
assert cancelled['status']['cancelRequested'] is True
assert cancelled['status']['state'] == 'cancelled'
"#,
        )
        .unwrap();
        let python_types = directory.join("python-types/registry_client/coordinator");
        fs::create_dir_all(&python_types).unwrap();
        fs::write(
            directory.join("python-types/registry_client/__init__.pyi"),
            "",
        )
        .unwrap();
        std::os::unix::fs::symlink(
            repository.join("crates/registry-coordinator-client-py/python/registry_coordinator_client/__init__.pyi"),
            python_types.join("__init__.pyi"),
        ).unwrap();
        fs::write(directory.join("typed_input.py"), format!(
            "from workflow import Input, Outcome\nrequest: Input = {}\ndef output(value: Outcome) -> object:\n    return value['output']\n", input
        )).unwrap();
        if workflow == "external-job" {
            let types = directory.join("typed_input.py");
            let mut source = fs::read_to_string(&types).unwrap();
            source.push_str(
                r#"
def job_id(value: Outcome) -> str:
    if value['outcome'] == 'job-result':
        output = value['output']
        if output is not None and output['state'] == 'complete':
            return output['result']['jobId']
    raise ValueError('Expected completed external job')
"#,
            );
            fs::write(types, source).unwrap();
        }
        fs::write(
            directory.join("pyrightconfig.json"),
            serde_json::to_vec(&json!({
                "typeCheckingMode":"standard", "pythonVersion":"3.11",
                "extraPaths":[directory.join("python-types")],
                "include":["workflow.py","typed_input.py"]
            }))
            .unwrap(),
        )
        .unwrap();
        let checked = std::process::Command::new("pyright")
            .arg("--project")
            .arg(directory.join("pyrightconfig.json"))
            .output()
            .unwrap();
        assert!(
            checked.status.success(),
            "{workflow}: {}",
            String::from_utf8_lossy(&checked.stdout)
        );
        // The exact operator policy explicitly permits start and cancellation of these fixture runs.
        let credential = f.token("operator", "sdk-owner", "coordinator:operate");
        let state = runtime_http_state(&runtime, &workflows).await;
        let (origin, server) = serve_fixture(state.clone()).await;
        let python_root = std::env::var("COORDINATOR_SDK_PYTHON_ROOT")
            .expect("COORDINATOR_SDK_PYTHON_ROOT names the built Python module import root");
        let phases: &[&str] = if workflow == "external-job" {
            &["cancel", "terminal"]
        } else {
            &["cancel"]
        };
        for &phase in phases {
            let worker = if phase == "terminal" {
                assert!(
                    jobs.as_ref()
                        .unwrap()
                        .received_requests()
                        .await
                        .unwrap()
                        .is_empty(),
                    "cancelled admissions dispatched no product reads"
                );
                let worker = registry_coordinator::worker::Worker::new(
                    state.store.clone(),
                    state.adapters.clone(),
                );
                let (stop, mut stopped) = tokio::sync::oneshot::channel();
                let task = tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = &mut stopped => break,
                            tick = worker.tick() => { tick.expect("external-job durable worker tick"); }
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                });
                Some((stop, task))
            } else {
                None
            };
            for (binary, script) in [("node", "node.cjs"), ("python3", "python.py")] {
                let phase = phase.to_owned();
                let origin = origin.clone();
                let credential = credential.clone();
                let input = input.to_string();
                let directory = directory.clone();
                let python_root = python_root.clone();
                let repository = repository.to_owned();
                let output = tokio::task::spawn_blocking(move || {
                    std::process::Command::new(binary)
                        .arg(directory.join(script))
                        .env("COORDINATOR_SDK_PHASE", phase)
                        .env("COORDINATOR_SDK_ORIGIN", origin)
                        .env("COORDINATOR_SDK_TOKEN", credential)
                        .env("COORDINATOR_SDK_INPUT", input)
                        .env(
                            "COORDINATOR_SDK_NODE_CLIENT",
                            repository.join("crates/registry-coordinator-client-node/client.js"),
                        )
                        .env("PYTHONPATH", python_root)
                        .output()
                        .unwrap()
                })
                .await
                .unwrap();
                assert!(
                    output.status.success(),
                    "{workflow} {binary}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if let Some((stop, task)) = worker {
                stop.send(())
                    .expect("worker remains alive until the clients finish");
                task.await.expect("external-job worker completed cleanly");
            }
        }
        if let Some(jobs) = jobs {
            jobs.verify().await;
        }
        server.abort();
        let _ = server.await;
        drop(state);
        f.stop().await;
    }
}

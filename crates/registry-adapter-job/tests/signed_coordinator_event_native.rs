// SPDX-License-Identifier: Apache-2.0
#![cfg(all(
    feature = "postgres-test",
    feature = "signed-coordinator-event",
    feature = "native-test-support"
))]

//! The signed event destination through the actual job pass and store,
//! against native Coordinator and PostgreSQL. The runner supplies the
//! separately built Coordinator binaries and disposable database.

#[path = "support/casework_native_service.rs"]
mod casework_native_service;
#[path = "support/job_fixture.rs"]
mod job_fixture;
#[path = "support/kobo_native_source.rs"]
mod kobo_native_source;
#[cfg(feature = "job-postgres")]
#[path = "support/postgres_native_source.rs"]
mod postgres_native_source;

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use registry_adapter_connectors::coordinator_event::{
    CoordinatorEventConnector, CoordinatorEventReceiver,
};
use registry_adapter_core::JobIdentity;
use registry_adapter_engine::job::{compile_job, compile_job_with};
use registry_adapter_job::destination::{DeliverableItem, HandOffOutcome, JobDestination};
use registry_adapter_job::pass::{run_pass, PassOptions, StopReason};
#[cfg(feature = "job-postgres")]
use registry_adapter_job::postgres_source::activate_postgres_sources;
use registry_adapter_job::signed_coordinator_event::{
    SignedCoordinatorEventDestination, SignedCoordinatorEventReceiver,
};
use registry_adapter_job::store::{self, ItemStatus};
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
use registry_platform_httputil::destination::{DestinationProfile, EventDestinationPolicy};
use registry_platform_testing::{fixtures, TestActorKind, TestAuthorizationServer, TestClient};
use serde_json::{json, Value};
use tokio_postgres::{Config as PgConfig, NoTls};

const KEY: &[u8] = &[0x5a; 32];
const WORKFLOW: &str = "register-household";
const PRIMARY_TRIGGER: &str = "submission-received";
const REVISED_TRIGGER: &str = "submission-revised";
const TARGET: &str = "/v1/events/register-household/submission-received";
const SOURCE: &str = "urn:registry-adapter:job:kobotoolbox-submissions-workflow-example";
const EVENT_TYPE: &str = "org.openspp.registry.household-submitted.v1";
const DATA_SCHEMA: &str = "urn:registry-adapter:schema:household-submitted:v1";
const REVISED_EVENT_TYPE: &str = "org.openspp.registry.household-revised.v1";
const REVISED_DATA_SCHEMA: &str = "urn:registry-adapter:schema:household-revised:v1";

async fn issuer() -> TestAuthorizationServer {
    let (_, public) = fixtures::ed25519_pair();
    let mut builder = TestAuthorizationServer::builder()
        .with_signing_key(
            generate_private_jwk(GeneratedKeyAlgorithm::Es256)
                .expect("generate the synthetic issuer key"),
        )
        .client(
            TestClient::new("operator")
                .with_public_jwk(public.clone())
                .with_resource("urn:adapter:coordinator-native")
                .with_actor_kind(TestActorKind::Service)
                .with_service_subject("adapter-job-native"),
        )
        .client(
            TestClient::new("application-reader")
                .with_public_jwk(public.clone())
                .with_resource("urn:example:applications")
                .with_actor_kind(TestActorKind::Service)
                .with_service_subject("adapter-job-native"),
        );
    for client in casework_native_service::clients(public) {
        builder = builder.client(client);
    }
    builder.start().await
}

fn binary(variable: &str) -> PathBuf {
    let path =
        PathBuf::from(std::env::var_os(variable).unwrap_or_else(|| {
            panic!("{variable} is required by the Adapter native event runner")
        }));
    assert!(path.is_file(), "{variable} must name an executable");
    path
}

fn private_file(path: &Path, contents: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents).expect("write a private fixture file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("set private fixture permissions");
}

fn configure_maintained_job(job: &Path) {
    let authored = std::fs::read_to_string(job).expect("read the native job");
    let expected = r#"  workflow: case-ingestion
  trigger: submitted
  source: urn:registry-adapter:job:case-daily
  eventType: org.example.case-submitted.v1
  dataSchema: urn:example:schema:case-submitted:v1
projection:
  fields:
    - id
    - answers.age"#;
    assert!(
        authored.contains(expected),
        "the shared native job retains its reviewed destination block"
    );
    let maintained = format!(
        "  workflow: {WORKFLOW}\n  trigger: {PRIMARY_TRIGGER}\n  source: {SOURCE}\n  eventType: {EVENT_TYPE}\n  dataSchema: {DATA_SCHEMA}\n  revisedReceiver:\n    trigger: {REVISED_TRIGGER}\n    eventType: {REVISED_EVENT_TYPE}\n    dataSchema: {REVISED_DATA_SCHEMA}\nprojection:\n  fields:\n    - _id\n    - respondent_name\n    - household.household_size"
    );
    std::fs::write(job, authored.replace(expected, &maintained))
        .expect("write the maintained native job");
}

fn operator(binary: &Path, args: &[&std::ffi::OsStr], log: &Path) -> Value {
    let output = Command::new(binary)
        .args(["--format", "json"])
        .args(args)
        .output()
        .expect("the Coordinator operator starts");
    let report = output.stdout.clone();
    let error_report = output.stderr.clone();
    let mut diagnostic = output.stdout;
    diagnostic.extend_from_slice(&output.stderr);
    private_file(log, &diagnostic);
    let parsed = serde_json::from_slice::<Value>(&report).ok();
    let parsed_error = serde_json::from_slice::<Value>(&error_report).ok();
    if !output.status.success() {
        let mut diagnostics = Vec::new();
        if let Some(report) = parsed.as_ref() {
            problem_diagnostics(report, &mut diagnostics);
        }
        if let Some(report) = parsed_error.as_ref() {
            problem_diagnostics(report, &mut diagnostics);
        }
        let rendered_error = String::from_utf8_lossy(&error_report);
        let rendered_report = String::from_utf8_lossy(&report);
        for field in [
            "database.testOnlyPlaintext",
            "database",
            "connections",
            "eventSources",
            "secretProviders",
            "deployment.authentication",
            "deployment.runtimeRole",
            "deployment.packages",
            "deployment.listener",
            "jwksSource",
            "responseSchema",
        ] {
            if rendered_error.contains(field) || rendered_report.contains(field) {
                diagnostics.push(field.to_string());
            }
        }
        diagnostics.sort();
        diagnostics.dedup();
        panic!(
            "Coordinator operator failed under value-free diagnostics {diagnostics:?}; inspect private {}",
            log.display()
        );
    }
    parsed.expect("the Coordinator operator returns JSON")
}

fn problem_diagnostics(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::Object(members) => {
            for (name, value) in members {
                if matches!(name.as_str(), "code" | "id" | "path") {
                    if let Some(value) = value.as_str().filter(|value| {
                        !value.is_empty()
                            && value.len() <= 128
                            && value.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                            })
                    }) {
                        output.push(value.to_string());
                    }
                }
                problem_diagnostics(value, output);
            }
        }
        Value::Array(items) => {
            for item in items {
                problem_diagnostics(item, output);
            }
        }
        _ => {}
    }
}

struct CoordinatorProcess(Child);

impl Drop for CoordinatorProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct FixtureRoot(PathBuf);

impl FixtureRoot {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for FixtureRoot {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            if let Err(error) = std::fs::remove_dir_all(&self.0) {
                eprintln!("fixture-owned Coordinator root cleanup failed: {error}");
            }
        }
    }
}

struct OwnedCoordinator {
    database: String,
    namespace: String,
    role: String,
}

impl Drop for OwnedCoordinator {
    fn drop(&mut self) {
        let database = self.database.clone();
        let namespace = self.namespace.clone();
        let role = self.role.clone();
        let result = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a cleanup runtime")
                .block_on(async move {
                    let (admin, connection) = tokio_postgres::connect(&database, NoTls).await?;
                    let task = tokio::spawn(connection);
                    admin
                        .batch_execute(&format!(
                            "DROP SCHEMA IF EXISTS {namespace} CASCADE; DROP ROLE IF EXISTS {role}"
                        ))
                        .await?;
                    task.abort();
                    Ok::<(), tokio_postgres::Error>(())
                })
        })
        .join();
        if !matches!(result, Ok(Ok(()))) {
            eprintln!("fixture-owned Coordinator cleanup failed");
        }
    }
}

struct NativeCoordinator {
    origin: String,
    _process: CoordinatorProcess,
    _owned: OwnedCoordinator,
    _root: FixtureRoot,
}

impl NativeCoordinator {
    async fn start(
        issuer: &TestAuthorizationServer,
        breg_origin: &str,
        breg_contract: Value,
        casework: &casework_native_service::Casework,
        address: std::net::SocketAddr,
    ) -> Self {
        let ctl = binary("ADAPTER_COORDINATORCTL_BIN");
        let runtime_binary = binary("ADAPTER_COORDINATOR_BIN");
        let root = FixtureRoot(
            tempfile::tempdir_in(std::env::temp_dir().canonicalize().expect("temp root"))
                .expect("a private Coordinator fixture root")
                .keep(),
        );
        let project = root.path().join("project");
        std::fs::create_dir(&project).expect("the project directory");
        std::fs::create_dir(project.join("generated")).expect("the generated contract directory");
        private_file(
            &project.join("generated/households.contract.json"),
            &serde_json::to_vec(&breg_contract).expect("the live BReg contract renders"),
        );
        let maintained = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/examples/kobotoolbox-job/workflow");
        let functions = std::fs::read_to_string(maintained.join("functions.rhai"))
            .expect("read the maintained workflow functions");
        let policy_digest = casework.binding["digest"]
            .as_str()
            .expect("the Casework policy binding carries a digest");
        private_file(
            &project.join("functions.rhai"),
            functions
                .replace(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    policy_digest,
                )
                .as_bytes(),
        );
        private_file(
            &project.join("workflow.yaml"),
            &std::fs::read(maintained.join("workflow.yaml"))
                .expect("read the maintained workflow project"),
        );
        let package = root.path().join("package");
        let packaged = operator(
            &ctl,
            &[
                "package".as_ref(),
                "--project".as_ref(),
                project.as_os_str(),
                "--output".as_ref(),
                package.as_os_str(),
            ],
            &root.path().join("package.log"),
        );
        let package_digest = packaged["packageDigest"]
            .as_str()
            .expect("the package report digest");

        let database = std::env::var("ADAPTER_TEST_DATABASE_URL")
            .expect("the native runner supplies disposable PostgreSQL");
        let (admin, connection) = tokio_postgres::connect(&database, NoTls)
            .await
            .expect("connect the Coordinator database");
        let admin_task = tokio::spawn(connection);
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let role = format!("coord_adapter_{}", &suffix[..16]);
        let namespace = format!("coordinator_{}", &suffix[..24]);
        let password = uuid::Uuid::new_v4().simple().to_string();
        admin
            .batch_execute(&format!(
                "CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS"
            ))
            .await
            .expect("create the fixture Coordinator role");
        admin_task.abort();
        let mut runtime_url = url::Url::parse(&database).expect("parse the database URL");
        runtime_url
            .set_username(&role)
            .expect("set the fixture database role");
        runtime_url
            .set_password(Some(&password))
            .expect("set the fixture database password");
        for (name, contents) in [
            ("runtime-database", runtime_url.as_str().as_bytes()),
            ("migration-database", database.as_bytes()),
            ("state-key", &[0x47; 32]),
            ("admission-key", &[0x48; 32]),
            ("audit-key", &[0x49; 32]),
            ("event-key", KEY),
            ("client-key", fixtures::ED25519_PRIVATE_JWK.as_bytes()),
            (
                "review-completion-token",
                casework.completion_token().as_bytes(),
            ),
        ] {
            private_file(&root.path().join(name), contents);
        }
        let origin = format!("http://{address}");
        let runtime = json!({
            "apiVersion": "id.registrystack.org/formats/coordinator/runtime/v1alpha1",
            "kind": "CoordinatorRuntimeConfig",
            "secretProviders": {"file": {"root": root.path()}},
            "database": {"runtimeUrlRef": "secret:file/runtime-database",
                "migrationUrlRef": "secret:file/migration-database"},
            "namespace": namespace,
            "connections": {
                "households": {
                    "type": "breg", "baseUrl": breg_origin, "profile": "writer",
                    "authorization": {
                        "tokenEndpoint": issuer.token_endpoint(), "clientId": "application-reader",
                        "signingKeyRef": "secret:file/client-key", "resource": "urn:example:applications",
                        "scopes": ["applications:read"]
                    }
                },
                "review": {
                    "type": "casework-review-producer",
                    "baseUrl": casework.origin,
                    "profile": "coordinator-producer",
                    "producer": "coordinator",
                    "authorization": {
                        "tokenEndpoint": issuer.token_endpoint(),
                        "clientId": casework_native_service::PRODUCER_CLIENT,
                        "signingKeyRef": "secret:file/client-key",
                        "resource": casework_native_service::AUDIENCE,
                        "scopes": ["casework:review"]
                    },
                    "completion": {
                        "recipientBinding": casework_native_service::RECIPIENT_BINDING,
                        "bearerTokenRef": "secret:file/review-completion-token"
                    },
                    "resultCheckSeconds": 900
                }
            },
            "eventSources": {"adapter": {"source": SOURCE, "signingKeyRef": "secret:file/event-key"}},
            "deployment": {
                "databaseId": format!("adapter-native-{suffix}"), "runtimeRole": role,
                "packages": [{"root": package, "expectedDigest": package_digest}],
                "listener": {"bind": address.to_string(), "tlsTermination": "development-loopback"},
                "authentication": {"issuer": issuer.issuer(), "audience": "urn:adapter:coordinator-native",
                    "scopeClaim": "scope", "jwksSource": {"type": "uri", "uri": issuer.jwks_uri()},
                    "policies": {"operator": {"requiredScopes": ["coordinator:operate"],
                        "workflows": [WORKFLOW], "actions": ["status", "inspect"], "operator": true}}},
                "auditFile": root.path().join("audit.jsonl"), "auditKeyRef": "secret:file/audit-key",
                "activeStateKey": 1, "stateKeys": {"1": {"keyRef": "secret:file/state-key"}},
                "admissionKeyRef": "secret:file/admission-key"
            }
        });
        let runtime_path = root.path().join("runtime.yaml");
        private_file(
            &runtime_path,
            serde_norway::to_string(&runtime)
                .expect("the runtime renders")
                .as_bytes(),
        );
        operator(
            &ctl,
            &[
                "--runtime-config".as_ref(),
                runtime_path.as_os_str(),
                "apply".as_ref(),
            ],
            &root.path().join("apply.log"),
        );
        let log_path = root.path().join("service.log");
        private_file(&log_path, b"");
        let log = OpenOptions::new()
            .append(true)
            .open(&log_path)
            .expect("open the Coordinator log");
        let mut process = CoordinatorProcess(
            Command::new(runtime_binary)
                .arg("--runtime-config")
                .arg(&runtime_path)
                .stdout(Stdio::from(log.try_clone().expect("clone the log")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("start native Coordinator"),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(
                process.0.try_wait().expect("poll Coordinator").is_none(),
                "native Coordinator exited; inspect {}",
                log_path.display()
            );
            if reqwest::get(format!("{origin}/ready"))
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "native Coordinator was not ready"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Self {
            origin,
            _process: process,
            _owned: OwnedCoordinator {
                database,
                namespace,
                role,
            },
            _root: root,
        }
    }
}

#[derive(Clone)]
struct LoseFirstRunHeader {
    destination: String,
    first_run: Arc<Mutex<Option<String>>>,
}

async fn forward(
    State(proxy): State<LoseFirstRunHeader>,
    mut headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    headers.remove("host");
    let response = reqwest::Client::new()
        .post(format!("{}{}", proxy.destination, TARGET))
        .headers(headers)
        .body(body)
        .send()
        .await
        .expect("forward to native Coordinator");
    let status = response.status();
    let run = response
        .headers()
        .get("x-coordinator-run-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if status.as_u16() != 204 {
        let problem = response
            .text()
            .await
            .unwrap_or_else(|error| format!("unreadable Problem body: {error}"));
        panic!("native Coordinator answered {status}: {problem}");
    }
    let mut first = proxy.first_run.lock().expect("the proxy Run lock");
    if first.is_none() {
        *first = run;
        return StatusCode::NO_CONTENT.into_response();
    }
    assert_eq!(*first, run, "native Coordinator recovered the same Run");
    let mut answer = StatusCode::NO_CONTENT.into_response();
    answer.headers_mut().insert(
        "x-coordinator-run-id",
        HeaderValue::from_str(run.as_deref().expect("Coordinator returned a Run"))
            .expect("a Run header"),
    );
    answer
}

async fn wait_for_proposal(issuer: &TestAuthorizationServer, coordinator_origin: &str, run: &str) {
    let token = issuer.issue_access_token(
        "operator",
        "adapter-job-native",
        "urn:adapter:coordinator-native",
        "coordinator:operate",
        chrono::Utc::now().timestamp() + 3600,
    );
    // BReg applies a review-free Proposal from its own queue, so the
    // Coordinator's first read right after Submit usually finds it still
    // submitted and schedules the next read at the connection's result
    // check. The operator's Check now brings that read forward to the
    // 30 second read floor, as an operator watching the Run would.
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut checked = false;
    let final_status = loop {
        if !checked {
            let response = reqwest::Client::new()
                .post(format!("{coordinator_origin}/v1/runs/{run}/check"))
                .bearer_auth(&token)
                .json(&json!({"step": "await-proposal"}))
                .send()
                .await
                .expect("ask the native Coordinator to check now");
            if response.status().is_success() {
                let answer: Value = response
                    .json()
                    .await
                    .expect("native Check now answer is JSON");
                checked = answer["observations"]
                    .as_u64()
                    .is_some_and(|reads| reads > 0);
            }
        }
        let response = reqwest::Client::new()
            .get(format!("{coordinator_origin}/v1/runs/{run}"))
            .bearer_auth(&token)
            .send()
            .await
            .expect("read native Coordinator status");
        assert!(
            response.status().is_success(),
            "native status is authorized"
        );
        let status: Value = response
            .json()
            .await
            .expect("native Coordinator status is JSON");
        let state = status["state"].as_str().unwrap_or_default();
        if state == "finished" {
            break status;
        }
        assert!(
            !matches!(state, "failed" | "attention"),
            "native Coordinator left the Proposal path at step {} in state {state} \
             (failure code {}); a product refusal is logged in the kept BReg fixture's service.log",
            status["step"],
            status["failureCode"]
        );
        assert!(
            Instant::now() < deadline,
            "native Coordinator did not finish the Proposal path in time: {status}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(final_status["outcome"], "proposal-applied");
    let inspection: Value = reqwest::Client::new()
        .get(format!("{coordinator_origin}/v1/runs/{run}/inspect"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("inspect the native Coordinator Run")
        .error_for_status()
        .expect("native Run inspection is authorized")
        .json()
        .await
        .expect("native Run inspection is JSON");
    assert!(inspection["effects"].as_array().is_some_and(|effects| {
        effects.iter().any(|effect| {
            effect["step"] == "submit-first"
                && effect["operation"]["id"] == "breg.submit-proposal/v1"
                && effect["state"] == "accepted"
        })
    }));
    // A settled Run ends its waits, so the finished outcome, not a kept
    // wait, is the evidence of which completion the Run followed.
    assert_eq!(
        inspection["waits"],
        json!([]),
        "a finished native Run keeps no wait"
    );
}

fn operator_token(issuer: &TestAuthorizationServer) -> String {
    issuer.issue_access_token(
        "operator",
        "adapter-job-native",
        "urn:adapter:coordinator-native",
        "coordinator:operate",
        chrono::Utc::now().timestamp() + 3600,
    )
}

async fn wait_for_outcome(
    issuer: &TestAuthorizationServer,
    coordinator_origin: &str,
    run: &str,
    outcome: &str,
) {
    let token = operator_token(issuer);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status: Value = reqwest::Client::new()
            .get(format!("{coordinator_origin}/v1/runs/{run}"))
            .bearer_auth(&token)
            .send()
            .await
            .expect("read the native Coordinator status")
            .error_for_status()
            .expect("the native Coordinator status is authorized")
            .json()
            .await
            .expect("the native Coordinator status is JSON");
        if status["state"] == "finished" {
            assert_eq!(status["outcome"], outcome);
            return;
        }
        assert!(
            !matches!(status["state"].as_str(), Some("failed" | "attention")),
            "the native Run stopped before {outcome}: {status}"
        );
        assert!(
            Instant::now() < deadline,
            "the native Run did not finish as {outcome}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn assert_revised_run_used_resolved_lookup(
    issuer: &TestAuthorizationServer,
    coordinator_origin: &str,
    run: &str,
) {
    let inspection: Value = reqwest::Client::new()
        .get(format!("{coordinator_origin}/v1/runs/{run}/inspect"))
        .bearer_auth(operator_token(issuer))
        .send()
        .await
        .expect("inspect the revised native Coordinator Run")
        .error_for_status()
        .expect("the revised native Run inspection is authorized")
        .json()
        .await
        .expect("the revised native Run inspection is JSON");
    // Inspection lists only calls with a dispatch risk, so the read-only
    // lookup is never an effect; the resolved review, which the workflow
    // reaches only when the lookup resolved, is the evidence.
    assert!(
        inspection["effects"].as_array().is_some_and(|effects| {
            effects.iter().any(|effect| {
                effect["step"] == "review-resolved"
                    && effect["operation"]["id"] == "casework.submit-review-request/v1"
                    && effect["state"] == "accepted"
            })
        }),
        "the revised Run reached the resolved review: {}",
        inspection["effects"]
    );
    // A settled Run ends its waits, so the finished outcome, not a kept
    // wait, is the evidence of which completion the Run followed.
    assert_eq!(
        inspection["waits"],
        json!([]),
        "a finished native Run keeps no wait"
    );
}

async fn assert_revised_run_used_unresolved_review(
    issuer: &TestAuthorizationServer,
    coordinator_origin: &str,
    run: &str,
) {
    let inspection: Value = reqwest::Client::new()
        .get(format!("{coordinator_origin}/v1/runs/{run}/inspect"))
        .bearer_auth(operator_token(issuer))
        .send()
        .await
        .expect("inspect the unresolved revised native Coordinator Run")
        .error_for_status()
        .expect("the unresolved revised native Run inspection is authorized")
        .json()
        .await
        .expect("the unresolved revised native Run inspection is JSON");
    assert!(inspection["effects"].as_array().is_some_and(|effects| {
        effects.iter().any(|effect| {
            effect["step"] == "review-unresolved"
                && effect["operation"]["id"] == "casework.submit-review-request/v1"
                && effect["state"] == "accepted"
        })
    }));
    // A settled Run ends its waits, so the finished outcome, not a kept
    // wait, is the evidence of which completion the Run followed.
    assert_eq!(
        inspection["waits"],
        json!([]),
        "a finished native Run keeps no wait"
    );
}

fn maintained_destination(base_url: &str, policy_name: &str) -> SignedCoordinatorEventDestination {
    let policy = Arc::new(
        EventDestinationPolicy::new(
            policy_name,
            base_url,
            DestinationProfile::LoopbackDevelopmentHttp,
            &[],
        )
        .expect("the maintained event policy freezes"),
    );
    let connector = Arc::new(
        CoordinatorEventConnector::new(policy, SOURCE, KEY.to_vec(), Duration::from_secs(3))
            .expect("the maintained event connector freezes"),
    );
    SignedCoordinatorEventDestination::new(
        connector,
        SignedCoordinatorEventReceiver::new(
            CoordinatorEventReceiver::new(WORKFLOW, PRIMARY_TRIGGER, EVENT_TYPE, DATA_SCHEMA)
                .expect("the maintained primary receiver freezes"),
            [0x11; 32],
        ),
        Some(SignedCoordinatorEventReceiver::new(
            CoordinatorEventReceiver::new(
                WORKFLOW,
                REVISED_TRIGGER,
                REVISED_EVENT_TYPE,
                REVISED_DATA_SCHEMA,
            )
            .expect("the maintained revised receiver freezes"),
            [0x12; 32],
        )),
    )
}

async fn assert_attention_list(
    issuer: &TestAuthorizationServer,
    coordinator_origin: &str,
    run: &str,
) {
    let token = operator_token(issuer);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let page: Value = reqwest::Client::new()
            .get(format!("{coordinator_origin}/v1/runs?attention=true"))
            .bearer_auth(&token)
            .send()
            .await
            .expect("list native Coordinator attention Runs")
            .error_for_status()
            .expect("the native attention list is authorized")
            .json()
            .await
            .expect("the native attention list is JSON");
        if page["runs"].as_array().is_some_and(|runs| {
            runs.iter().any(|listed| {
                listed["runId"] == run
                    && matches!(listed["state"].as_str(), Some("attention" | "failed"))
            })
        }) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the stopped native Run did not appear under attention=true"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn isolated_store() -> Pool {
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL names disposable PostgreSQL");
    let schema = format!("adapter_job_event_{}", uuid::Uuid::new_v4().simple());
    let (admin, connection) = tokio_postgres::connect(&base, NoTls)
        .await
        .expect("connect the Adapter store database");
    tokio::spawn(connection);
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create an isolated Adapter schema");
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let mut scoped = PgConfig::from_str(&url).expect("parse the Adapter store URL");
    scoped.ssl_mode(tokio_postgres::config::SslMode::Disable);
    let pool = Pool::builder(Manager::from_config(
        scoped,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Verified,
        },
    ))
    .max_size(2)
    .build()
    .expect("build the Adapter store pool");
    let client = pool.get().await.expect("an Adapter store client");
    store::migrate(&client)
        .await
        .expect("migrate the Adapter store");
    drop(client);
    pool
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs under the Adapter native Coordinator runner"]
async fn a_lost_native_event_answer_recovers_the_same_coordinator_run() {
    let issuer = issuer().await;
    let breg = registry_adapter_connectors::test_support::Breg::start(&issuer).await;
    let breg_contract = breg.action_contract();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve the Coordinator address");
    let coordinator_address = listener.local_addr().expect("the Coordinator address");
    drop(listener);
    let casework =
        casework_native_service::Casework::start(&issuer, &format!("http://{coordinator_address}"))
            .await;
    let coordinator = NativeCoordinator::start(
        &issuer,
        &breg.origin(),
        breg_contract,
        &casework,
        coordinator_address,
    )
    .await;
    let proxy = LoseFirstRunHeader {
        destination: coordinator.origin.clone(),
        first_run: Arc::new(Mutex::new(None)),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the lost-answer proxy");
    let address = listener.local_addr().expect("the proxy address");
    let app = Router::new()
        .route(TARGET, post(forward))
        .with_state(proxy.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve the proxy") });
    let policy = Arc::new(
        EventDestinationPolicy::new(
            "adapter-native-coordinator",
            &format!("http://127.0.0.1:{}/", address.port()),
            DestinationProfile::LoopbackDevelopmentHttp,
            &[],
        )
        .expect("the native event policy freezes"),
    );
    let connector = Arc::new(
        CoordinatorEventConnector::new(policy, SOURCE, KEY.to_vec(), Duration::from_secs(3))
            .expect("the native event connector freezes"),
    );
    let fixture = job_fixture::JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(
            200,
            // The projection's dotted path walks nested objects, so the
            // group arrives as an object, as the Kobo pack shapes it.
            json!({"data": [{"id": "a", "_id": "a", "respondent_name": "Amina", "household": {"household_size": "4"}}], "nextCursor": "p2"}),
        )],
        job_fixture::Edits::Ordered,
    )
    .await;
    configure_maintained_job(&fixture.job);
    let program = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect("the native job compiles");
    let receiver =
        CoordinatorEventReceiver::new(WORKFLOW, PRIMARY_TRIGGER, EVENT_TYPE, DATA_SCHEMA)
            .expect("the native primary receiver freezes");
    let destination = SignedCoordinatorEventDestination::new(
        connector,
        SignedCoordinatorEventReceiver::new(receiver, [0x11; 32]),
        Some(SignedCoordinatorEventReceiver::new(
            CoordinatorEventReceiver::new(
                WORKFLOW,
                REVISED_TRIGGER,
                REVISED_EVENT_TYPE,
                REVISED_DATA_SCHEMA,
            )
            .expect("the revised receiver freezes"),
            [0x12; 32],
        )),
    );
    let pool = isolated_store().await;
    let first = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(
        first.stopped,
        Some(StopReason::DestinationStop {
            code: "coordinator.event.outcome-uncertain".to_string()
        })
    );
    let second = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(second.stopped, None);
    assert_eq!(second.items_redelivered, 1);
    let client = pool.get().await.expect("an Adapter store client");
    let item = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("read the native item")
        .expect("the native item exists");
    assert_eq!(item.status, ItemStatus::Acknowledged);
    assert_eq!(
        item.run_id,
        proxy.first_run.lock().expect("the proxy Run lock").clone()
    );
    let run = item.run_id.expect("the job store kept the Coordinator Run");
    wait_for_proposal(&issuer, &coordinator.origin, &run).await;
    drop(client);
    drop(destination);
    drop(coordinator);
    drop(casework);
    breg.finish();
    issuer.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs under the Adapter native Coordinator runner"]
async fn maintained_kobo_pack_reaches_proposal_repeat_and_resolved_revision_review() {
    let issuer = issuer().await;
    let breg = registry_adapter_connectors::test_support::Breg::start(&issuer).await;
    let breg_contract = breg.action_contract();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve the Coordinator address");
    let coordinator_address = listener.local_addr().expect("the Coordinator address");
    drop(listener);
    let casework =
        casework_native_service::Casework::start(&issuer, &format!("http://{coordinator_address}"))
            .await;
    let coordinator = NativeCoordinator::start(
        &issuer,
        &breg.origin(),
        breg_contract,
        &casework,
        coordinator_address,
    )
    .await;
    let source = kobo_native_source::MaintainedKoboSource::start().await;
    let program = compile_job_with(
        &source.pack,
        &source.job,
        &source.runtime,
        &source.profile,
        &source.project,
    )
    .expect("the maintained Kobo pack and Coordinator job compile together");
    assert_eq!(
        program.job.job.id.as_str(),
        "kobotoolbox-submissions-workflow-example"
    );
    assert_eq!(program.source_route.id.as_str(), "kobo-submissions");

    let proxy = LoseFirstRunHeader {
        destination: coordinator.origin.clone(),
        first_run: Arc::new(Mutex::new(None)),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the maintained lost-answer proxy");
    let address = listener.local_addr().expect("the proxy address");
    let app = Router::new()
        .route(TARGET, post(forward))
        .with_state(proxy.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve the proxy") });
    let lost_answer_destination = maintained_destination(
        &format!("http://127.0.0.1:{}/", address.port()),
        "adapter-maintained-kobo-lost-answer",
    );
    let pool = isolated_store().await;

    let first = run_pass(
        &pool,
        &program,
        &lost_answer_destination,
        PassOptions::default(),
    )
    .await;
    assert_eq!(
        first.stopped,
        Some(StopReason::DestinationStop {
            code: "coordinator.event.outcome-uncertain".to_string()
        })
    );
    assert_eq!(first.items_read, 1);
    assert_eq!(first.items_new, 1);

    let recovered = run_pass(
        &pool,
        &program,
        &lost_answer_destination,
        PassOptions::default(),
    )
    .await;
    assert_eq!(recovered.stopped, None);
    assert_eq!(recovered.items_read, 1);
    assert_eq!(recovered.items_redelivered, 1);
    assert_eq!(recovered.items_acknowledged, 1);
    let client = pool.get().await.expect("an Adapter store client");
    let admitted = store::inspect_item(&client, "kobotoolbox-submissions-workflow-example", "4103")
        .await
        .expect("read the maintained Kobo item")
        .expect("the maintained Kobo item exists");
    assert_eq!(admitted.status, ItemStatus::Acknowledged);
    assert_eq!(admitted.sequence, 1);
    assert_eq!(
        admitted.run_id,
        proxy.first_run.lock().expect("the proxy Run lock").clone()
    );
    let first_run = admitted
        .run_id
        .expect("the maintained Kobo hand-off kept its Coordinator Run");
    drop(client);
    wait_for_proposal(&issuer, &coordinator.origin, &first_run).await;
    drop(lost_answer_destination);

    let destination = maintained_destination(
        &format!("{}/", coordinator.origin),
        "adapter-maintained-kobo-revision",
    );
    let tail = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(tail.stopped, None);
    assert_eq!(tail.items_read, 0);

    let unchanged = run_pass(
        &pool,
        &program,
        &destination,
        PassOptions {
            rescan: true,
            ..PassOptions::default()
        },
    )
    .await;
    assert_eq!(unchanged.stopped, None);
    assert_eq!(unchanged.items_read, 1);
    assert_eq!(unchanged.items_skipped, 1);
    // An ongoing scan's rescan ends at its first empty page, so the next
    // pass reads the tail and closes the traversal; only then does a
    // requested rescan start again from the first page.
    let caught_up = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(caught_up.stopped, None);
    assert_eq!(caught_up.items_read, 0);

    source.revise();
    let revised = run_pass(
        &pool,
        &program,
        &destination,
        PassOptions {
            rescan: true,
            ..PassOptions::default()
        },
    )
    .await;
    assert_eq!(revised.stopped, None);
    assert_eq!(revised.items_read, 1);
    assert_eq!(revised.items_changed, 1);
    assert_eq!(revised.items_acknowledged, 1);
    let client = pool.get().await.expect("an Adapter store client");
    let reviewed = store::inspect_item(&client, "kobotoolbox-submissions-workflow-example", "4103")
        .await
        .expect("read the revised maintained Kobo item")
        .expect("the revised maintained Kobo item exists");
    assert_eq!(reviewed.status, ItemStatus::Acknowledged);
    assert_eq!(reviewed.sequence, 2);
    assert_eq!(reviewed.prior_run_id.as_deref(), Some(first_run.as_str()));
    let revised_run = reviewed
        .run_id
        .expect("the revised maintained Kobo hand-off kept its Coordinator Run");
    drop(client);
    casework.approve("4103").await;
    wait_for_outcome(
        &issuer,
        &coordinator.origin,
        &revised_run,
        "revised-reviewed",
    )
    .await;
    assert_revised_run_used_resolved_lookup(&issuer, &coordinator.origin, &revised_run).await;

    let requests = source.requests();
    assert_eq!(requests.len(), 6);
    assert!(requests.iter().all(|request| request.authenticated));
    for request in &requests {
        let parsed = url::Url::parse(&format!("http://fixture{}", request.target))
            .expect("the recorded Kobo target parses");
        assert_eq!(parsed.path(), kobo_native_source::DATA_PATH);
        let query = parsed
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            query.get("format").map(|value| value.as_ref()),
            Some("json")
        );
        assert_eq!(query.get("limit").map(|value| value.as_ref()), Some("100"));
        assert_eq!(
            query.get("sort").map(|value| value.as_ref()),
            Some(r#"{"_id":1}"#)
        );
    }
    for index in [0, 1, 3, 5] {
        let parsed = url::Url::parse(&format!("http://fixture{}", requests[index].target))
            .expect("the first-page Kobo target parses");
        assert!(parsed.query_pairs().all(|(name, _)| name != "query"));
    }
    for index in [2, 4] {
        let tail_target = url::Url::parse(&format!("http://fixture{}", requests[index].target))
            .expect("the Kobo tail target parses");
        let tail_query = tail_target
            .query_pairs()
            .find_map(|(name, value)| (name == "query").then_some(value.into_owned()))
            .expect("the ordered tail read carries its keyset query");
        assert_eq!(
            serde_json::from_str::<Value>(&tail_query).expect("the Kobo keyset query is JSON"),
            json!({"_id": {"$gt": 4103}})
        );
    }

    drop(destination);
    drop(coordinator);
    drop(casework);
    breg.finish();
    issuer.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs under the Adapter native Coordinator runner"]
#[cfg(feature = "job-postgres")]
async fn postgres_source_reaches_native_coordinator_and_reviews_a_revised_row() {
    let issuer = issuer().await;
    let breg = registry_adapter_connectors::test_support::Breg::start(&issuer).await;
    let breg_contract = breg.action_contract();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve the Coordinator address");
    let coordinator_address = listener.local_addr().expect("the Coordinator address");
    drop(listener);
    let casework =
        casework_native_service::Casework::start(&issuer, &format!("http://{coordinator_address}"))
            .await;
    let coordinator = NativeCoordinator::start(
        &issuer,
        &breg.origin(),
        breg_contract,
        &casework,
        coordinator_address,
    )
    .await;
    let policy = Arc::new(
        EventDestinationPolicy::new(
            "adapter-native-coordinator-postgres",
            &coordinator.origin,
            DestinationProfile::LoopbackDevelopmentHttp,
            &[],
        )
        .expect("the native PostgreSQL event policy freezes"),
    );
    let connector = Arc::new(
        CoordinatorEventConnector::new(policy, SOURCE, KEY.to_vec(), Duration::from_secs(3))
            .expect("the native PostgreSQL event connector freezes"),
    );
    let fixture = job_fixture::JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, json!({"data": []}))],
        job_fixture::Edits::Ordered,
    )
    .await;
    configure_maintained_job(&fixture.job);
    let source = postgres_native_source::PostgresNativeSource::install_household(
        &fixture.pack,
        &fixture.job,
        &fixture.runtime,
    )
    .await;
    let mut program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the SQL job compiles");
    activate_postgres_sources(&mut program, &source.resolver())
        .expect("the production PostgreSQL source host activates");
    let receiver =
        CoordinatorEventReceiver::new(WORKFLOW, PRIMARY_TRIGGER, EVENT_TYPE, DATA_SCHEMA)
            .expect("the native primary receiver freezes");
    let destination = SignedCoordinatorEventDestination::new(
        connector,
        SignedCoordinatorEventReceiver::new(receiver, [0x11; 32]),
        Some(SignedCoordinatorEventReceiver::new(
            CoordinatorEventReceiver::new(
                WORKFLOW,
                REVISED_TRIGGER,
                REVISED_EVENT_TYPE,
                REVISED_DATA_SCHEMA,
            )
            .expect("the native revised receiver freezes"),
            [0x12; 32],
        )),
    );
    let pool = isolated_store().await;

    let first = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(first.stopped, None);
    assert_eq!(first.items_read, 1);
    assert_eq!(first.items_new, 1);
    assert_eq!(first.items_acknowledged, 1);
    let item_key = postgres_native_source::only_item_key(&pool).await;
    let client = pool.get().await.expect("an Adapter store client");
    let admitted = store::inspect_item(&client, "case-daily", &item_key)
        .await
        .expect("read the SQL-backed Coordinator item")
        .expect("the SQL-backed Coordinator item exists");
    assert_eq!(admitted.status, ItemStatus::Acknowledged);
    assert_eq!(admitted.sequence, 1);
    let run = admitted.run_id.expect("native Coordinator returned a Run");
    drop(client);
    wait_for_proposal(&issuer, &coordinator.origin, &run).await;

    let repeated = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(repeated.stopped, None);
    assert_eq!(repeated.items_skipped, 1);

    source.revise_label().await;
    let revised = run_pass(
        &pool,
        &program,
        &destination,
        PassOptions {
            rescan: true,
            ..PassOptions::default()
        },
    )
    .await;
    assert_eq!(revised.stopped, None);
    assert_eq!(revised.items_changed, 1);
    assert_eq!(revised.items_acknowledged, 1);
    let client = pool.get().await.expect("an Adapter store client");
    let reviewed = store::inspect_item(&client, "case-daily", &item_key)
        .await
        .expect("read the revised Coordinator item")
        .expect("the revised Coordinator item exists");
    assert_eq!(reviewed.status, ItemStatus::Acknowledged);
    assert_eq!(reviewed.sequence, 2);
    assert_eq!(reviewed.prior_run_id.as_deref(), Some(run.as_str()));
    let revised_run = reviewed.run_id.expect("the revised Coordinator Run");
    drop(client);
    casework.approve(&item_key).await;
    wait_for_outcome(
        &issuer,
        &coordinator.origin,
        &revised_run,
        "revised-reviewed",
    )
    .await;

    let job = JobIdentity {
        id: "case-daily".parse().expect("the native job identifier"),
        version: "1".to_string(),
    };
    let now = SystemTime::now();
    let revised_without_prior = DeliverableItem {
        key: "submissions/missing-no-prior".to_string(),
        sequence: 2,
        digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            .to_string(),
        prior_run_id: None,
        admitted_before: true,
        first_seen: now,
        event_time: now,
        delivery_attempt: 1,
        projected: json!({
            "_id": "missing-source-submission",
            "respondent_name": "Unresolved revision without prior Run metadata",
            "household.household_size": 5
        }),
    };
    let no_prior_run = match destination.deliver(&job, &revised_without_prior).await {
        HandOffOutcome::Acknowledged { run_id: Some(run) } => run,
        other => panic!("the revised event without priorRunId is admitted: {other:?}"),
    };
    casework.approve(&revised_without_prior.key).await;
    wait_for_outcome(
        &issuer,
        &coordinator.origin,
        &no_prior_run,
        "revised-reviewed",
    )
    .await;
    assert_revised_run_used_unresolved_review(&issuer, &coordinator.origin, &no_prior_run).await;

    let invalid = DeliverableItem {
        key: "submissions/invalid".to_string(),
        sequence: 1,
        digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333"
            .to_string(),
        prior_run_id: None,
        admitted_before: false,
        first_seen: now,
        event_time: now,
        delivery_attempt: 1,
        projected: json!({
            "_id": "invalid",
            "respondent_name": "Invalid household size",
            "household.household_size": "not-an-integer"
        }),
    };
    let stopped_run = match destination.deliver(&job, &invalid).await {
        HandOffOutcome::Acknowledged { run_id: Some(run) } => run,
        other => panic!("the invalid event is admitted before its Run stops: {other:?}"),
    };
    assert_attention_list(&issuer, &coordinator.origin, &stopped_run).await;

    postgres_native_source::assert_no_payload_columns(&pool).await;
    drop(destination);
    drop(coordinator);
    drop(casework);
    breg.finish();
    issuer.stop().await;
}

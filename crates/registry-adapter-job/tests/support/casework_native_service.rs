// SPDX-License-Identifier: Apache-2.0

//! Native Casework fixture for the maintained Adapter to Coordinator workflow.
//! It packages one submitted-context review policy, applies it to an isolated
//! PostgreSQL schema, and drives one real staff decision through HTTP.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use registry_platform_testing::{TestActorKind, TestAuthorizationServer, TestClient};
use serde_json::{json, Value};

pub const AUDIENCE: &str = "urn:adapter:casework-native";
pub const PRODUCER_CLIENT: &str = "review-producer";
pub const PRODUCER_SUBJECT: &str = "coordinator-native";
pub const STAFF_CLIENT: &str = "staff";
pub const STAFF_SUBJECT: &str = "adapter-caseworker";
pub const ADMIN_CLIENT: &str = "administrator";
pub const ADMIN_SUBJECT: &str = "adapter-casework-admin";
pub const POLICY: &str = "household-ingestion-review";
pub const RECIPIENT_BINDING: &str = "adapter-ingestion-review-v1";

pub fn clients(public: registry_platform_crypto::PublicJwk) -> [TestClient; 3] {
    [
        TestClient::new(PRODUCER_CLIENT)
            .with_public_jwk(public)
            .with_resource(AUDIENCE)
            .with_actor_kind(TestActorKind::Service)
            .with_service_subject(PRODUCER_SUBJECT),
        TestClient::new(STAFF_CLIENT)
            .with_resource(AUDIENCE)
            .with_actor_kind(TestActorKind::Human),
        TestClient::new(ADMIN_CLIENT)
            .with_resource(AUDIENCE)
            .with_actor_kind(TestActorKind::Human),
    ]
}

fn binary(variable: &str) -> PathBuf {
    let path =
        PathBuf::from(std::env::var_os(variable).unwrap_or_else(|| {
            panic!("{variable} is required by the Adapter native event runner")
        }));
    assert!(path.is_file(), "{variable} must name an executable");
    path
}

fn private_file(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create a private Casework fixture directory");
    }
    std::fs::write(path, bytes).expect("write a private Casework fixture file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("set private Casework fixture permissions");
}

fn document(path: &Path, value: &Value) {
    private_file(
        path,
        &serde_json::to_vec_pretty(value).expect("render the Casework fixture document"),
    );
}

fn operator(binary: &Path, args: &[&std::ffi::OsStr], log: &Path) -> Value {
    let output = Command::new(binary)
        .args(["--format", "json"])
        .args(args)
        .output()
        .expect("the native Casework operator starts");
    let report = output.stdout.clone();
    let mut raw = output.stdout;
    raw.extend_from_slice(&output.stderr);
    private_file(log, &raw);
    assert!(
        output.status.success(),
        "native Casework operator failed; inspect {}",
        log.display()
    );
    serde_json::from_slice(&report).expect("the Casework operator report is JSON")
}

struct Process(Child);

impl Drop for Process {
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
                eprintln!("fixture-owned Casework root cleanup failed: {error}");
            }
        }
    }
}

struct OwnedSchema {
    database: String,
    schema: String,
}

impl Drop for OwnedSchema {
    fn drop(&mut self) {
        let database = self.database.clone();
        let schema = self.schema.clone();
        let result = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a Casework cleanup runtime")
                .block_on(async move {
                    let (admin, connection) =
                        tokio_postgres::connect(&database, tokio_postgres::NoTls).await?;
                    let task = tokio::spawn(connection);
                    admin
                        .batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
                        .await?;
                    task.abort();
                    Ok::<(), tokio_postgres::Error>(())
                })
        })
        .join();
        if !matches!(result, Ok(Ok(()))) {
            eprintln!("fixture-owned Casework schema cleanup failed");
        }
    }
}

pub struct Casework {
    pub origin: String,
    pub binding: Value,
    completion_token: String,
    staff_token: String,
    _process: Process,
    _owned: OwnedSchema,
    _root: FixtureRoot,
}

impl Casework {
    pub async fn start(issuer: &TestAuthorizationServer, coordinator_origin: &str) -> Self {
        let ctl = binary("ADAPTER_CASEWORKCTL_BIN");
        let runtime_binary = binary("ADAPTER_CASEWORK_BIN");
        let root = FixtureRoot(
            tempfile::tempdir_in(std::env::temp_dir().canonicalize().expect("temp root"))
                .expect("a private Casework fixture root")
                .keep(),
        );
        let project = root.path().join("project");
        std::fs::create_dir(&project).expect("the Casework project directory");
        document(
            &project.join("casework.yaml"),
            &json!({
                "apiVersion": "id.registrystack.org/formats/casework/project/v1alpha1",
                "kind": "CaseworkProject",
                "project": {"id": "adapter-ingestion-review", "version": "1"},
                "accessProfiles": {
                    "staff": {"principalClaim": "sub", "requiredScopes": ["casework:staff"], "actsAs":"staff"},
                    "supervisor": {"principalClaim": "sub", "requiredScopes": ["casework:supervisor"], "actsAs":"supervisor"},
                    "administrator": {"principalClaim": "sub", "requiredScopes": ["casework:admin"], "actsAs":"administrator"},
                    "coordinator-producer": {"principalClaim": "sub", "requiredScopes": ["casework:review"], "actsAs":"requester"}
                },
                "queues": {"applications": {"label": "Household ingestion reviews"}},
                "teams": {"reviewers": {"label": "Household reviewers", "serves": ["applications"], "memberProfiles": ["staff"], "supervisorProfiles": ["supervisor"]}},
                "reviewPolicies": {(POLICY): {
                    "version": "1",
                    "purpose": "approval",
                    "context": {"mode": "submitted"},
                    "stages": [{"id": "review", "queue": "applications", "decidingProfiles": ["staff"], "requiredApprovals": 1, "excludeInitiator": false}],
                    "outcomes": {
                        "approved": {"label": "Approve revision", "settlement": "approved", "reasonRequired": false, "publicReason": "none"},
                        "rejected": {"label": "Reject revision", "settlement": "rejected", "reasonRequired": false, "publicReason": "optional"}
                    },
                    "retention": {"terminalRetentionDays": 30, "accountabilityRetentionDays": 90},
                    "displaySchema": {
                        "type": "object", "additionalProperties": false,
                        "required": ["resolution", "sourceSubmissionId", "respondentName", "householdSize"],
                        "properties": {
                            "resolution": {"type": "string", "enum": ["resolved", "unresolved", "proposal-returned"]},
                            "sourceSubmissionId": {"type": "string", "minLength": 1, "maxLength": 128},
                            "respondentName": {"type": "string", "minLength": 1, "maxLength": 256},
                            "householdSize": {"type": "integer", "minimum": 1},
                            "priorRunId": {"type": "string", "format": "uuid"},
                            "recordId": {"type": "string", "format": "uuid"}
                        }
                    }
                }},
                "trustedProducers": {"coordinator": {
                    "profile": "coordinator-producer",
                    "issuer": issuer.issuer(),
                    "subject": PRODUCER_SUBJECT,
                    "sourceNamespaces": ["adapter-ingestion"],
                    "reviewPolicies": [POLICY],
                    "retention": {"receiptRetentionDays": 7},
                    "completion": {"destinationId": "coordinator", "recipientBinding": RECIPIENT_BINDING}
                }}
            }),
        );
        let checked = operator(
            &ctl,
            &["check".as_ref(), project.as_os_str()],
            &root.path().join("check.log"),
        );
        let binding = checked["policyBindings"]
            .as_array()
            .and_then(|items| items.iter().find(|item| item["id"] == POLICY))
            .cloned()
            .expect("the checked Casework policy binding");
        let package = root.path().join("package");
        operator(
            &ctl,
            &[
                "package".as_ref(),
                project.as_os_str(),
                "--output".as_ref(),
                package.as_os_str(),
            ],
            &root.path().join("package.log"),
        );

        let database = std::env::var("ADAPTER_TEST_DATABASE_URL")
            .expect("the native runner supplies disposable PostgreSQL");
        let schema = format!("adapter_casework_{}", uuid::Uuid::new_v4().simple());
        let (admin, connection) = tokio_postgres::connect(&database, tokio_postgres::NoTls)
            .await
            .expect("connect the Casework database");
        let admin_task = tokio::spawn(connection);
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .expect("create an isolated Casework schema");
        admin_task.abort();
        let separator = if database.contains('?') { '&' } else { '?' };
        let scoped_database = format!("{database}{separator}options=-csearch_path%3D{schema}");
        let jwks = reqwest::get(issuer.jwks_uri())
            .await
            .expect("read the synthetic issuer JWKS")
            .bytes()
            .await
            .expect("read the synthetic issuer JWKS body");
        let completion_token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        for (name, bytes) in [
            ("database", scoped_database.as_bytes()),
            ("jwks", jwks.as_ref()),
            (
                "audit-key",
                b"synthetic-casework-audit-key-0123456789".as_slice(),
            ),
            ("completion-token", completion_token.as_bytes()),
        ] {
            private_file(&root.path().join(name), bytes);
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve a Casework address");
        let address = listener.local_addr().expect("the Casework address");
        drop(listener);
        let origin = format!("http://{address}");
        let runtime = root.path().join("runtime.yaml");
        document(
            &runtime,
            &json!({
                "apiVersion": "id.registrystack.org/formats/casework/runtime/v1alpha1",
                "kind": "CaseworkRuntimeConfig",
                "identity": {"databaseId": format!("adapter-ingestion-review-{schema}")},
                "package": {"root": package},
                "listener": {"bind": address.to_string(), "tlsTermination": "development-loopback", "networkExposure": "private-address"},
                "secretProviders": {"file": {"root": root.path()}},
                "database": {"runtimeUrlRef": "secret:file/database", "migrationUrlRef": "secret:file/database", "testOnlyPlaintext": true},
                "authentication": {"oidc": {
                    "issuer": issuer.issuer(), "audience": AUDIENCE,
                    "allowedClients": [PRODUCER_CLIENT, STAFF_CLIENT, ADMIN_CLIENT],
                    "scopeClaim": "scope", "jwksSource": {"type": "static", "documentRef": "secret:file/jwks"},
                    "humanIdentity": {"claim": "registry_actor_kind", "value": "human"}
                }},
                "audit": {"path": root.path().join("audit.ndjson"), "hashKeyRef": "secret:file/audit-key"},
                "contextProviders": {},
                "reviewCompletionDestinations": {"coordinator": {
                    "url": format!("{coordinator_origin}/v1/review-completions"),
                    "bearerTokenRef": "secret:file/completion-token",
                    "attemptTimeoutMilliseconds": 5000,
                    "maximumAttempts": 10,
                    "retryDelaySeconds": 1
                }}
            }),
        );
        operator(
            &ctl,
            &[
                "apply".as_ref(),
                "--runtime-config".as_ref(),
                runtime.as_os_str(),
            ],
            &root.path().join("apply.log"),
        );
        let log_path = root.path().join("service.log");
        private_file(&log_path, b"");
        let log = OpenOptions::new()
            .append(true)
            .open(&log_path)
            .expect("open the Casework service log");
        let mut process = Process(
            Command::new(runtime_binary)
                .arg("--runtime-config")
                .arg(&runtime)
                .arg("serve")
                .stdout(Stdio::from(
                    log.try_clone().expect("clone the Casework log"),
                ))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("start native Casework"),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(
                process.0.try_wait().expect("poll Casework").is_none(),
                "native Casework exited; inspect {}",
                log_path.display()
            );
            if reqwest::get(format!("{origin}/ready"))
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                break;
            }
            assert!(Instant::now() < deadline, "native Casework was not ready");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let admin_token = issuer.issue_access_token_with_claims(
            ADMIN_CLIENT,
            ADMIN_SUBJECT,
            AUDIENCE,
            "casework:admin",
            chrono::Utc::now().timestamp() + 3600,
            BTreeMap::from([("casework_principal".to_owned(), json!(ADMIN_SUBJECT))]),
        );
        let staff_token = issuer.issue_access_token_with_claims(
            STAFF_CLIENT,
            STAFF_SUBJECT,
            AUDIENCE,
            "casework:staff",
            chrono::Utc::now().timestamp() + 3600,
            BTreeMap::from([("casework_principal".to_owned(), json!(STAFF_SUBJECT))]),
        );
        let http = reqwest::Client::new();
        let directory: Value = http
            .get(format!("{origin}/v1/directory"))
            .bearer_auth(&admin_token)
            .header("Registry-Casework-Profile", "administrator")
            .send()
            .await
            .expect("read the native Casework directory")
            .error_for_status()
            .expect("the native Casework directory is authorized")
            .json()
            .await
            .expect("the native Casework directory is JSON");
        http.post(format!("{origin}/v1/directory/bootstrap"))
            .bearer_auth(&admin_token)
            .header("Registry-Casework-Profile", "administrator")
            .header("If-Match", format!("\"{}\"", directory["revision"]))
            .header("Idempotency-Key", "adapter-native-casework-bootstrap")
            .json(&json!({
                "teamId": "reviewers", "queueId": "applications", "supervisors": [],
                "staff": [{"issuer": issuer.issuer(), "subject": STAFF_SUBJECT}]
            }))
            .send()
            .await
            .expect("bootstrap the native Casework directory")
            .error_for_status()
            .expect("the native Casework directory bootstrap succeeds");

        Self {
            origin,
            binding,
            completion_token,
            staff_token,
            _process: process,
            _owned: OwnedSchema { database, schema },
            _root: root,
        }
    }

    pub fn completion_token(&self) -> &str {
        &self.completion_token
    }

    pub async fn approve(&self, requester_reference: &str) -> String {
        let http = reqwest::Client::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        let task = loop {
            let page: Value = http
                .get(format!(
                    "{}/v1/review-tasks?queue=applications&limit=100",
                    self.origin
                ))
                .bearer_auth(&self.staff_token)
                .header("Registry-Casework-Profile", "staff")
                .send()
                .await
                .expect("list native Casework tasks")
                .error_for_status()
                .expect("the staff task page is authorized")
                .json()
                .await
                .expect("the staff task page is JSON");
            if let Some(task) = page["items"].as_array().and_then(|items| {
                items.iter().find(|task| {
                    task["requesterReference"] == requester_reference && task["state"] == "open"
                })
            }) {
                break task.clone();
            }
            assert!(
                Instant::now() < deadline,
                "the revised event did not open a native Casework task"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let task_id = task["taskId"]
            .as_str()
            .expect("the Casework task identifier")
            .to_owned();
        let task_url = format!("{}/v1/review-tasks/{task_id}", self.origin);
        http.post(format!("{task_url}/claim"))
            .bearer_auth(&self.staff_token)
            .header("Registry-Casework-Profile", "staff")
            .header("If-Match", format!("\"{}\"", task["revision"]))
            .header("Idempotency-Key", format!("adapter-native-claim-{task_id}"))
            .send()
            .await
            .expect("claim the native Casework task")
            .error_for_status()
            .expect("the native Casework claim succeeds");
        let current: Value = http
            .get(&task_url)
            .bearer_auth(&self.staff_token)
            .header("Registry-Casework-Profile", "staff")
            .send()
            .await
            .expect("read the claimed native Casework task")
            .error_for_status()
            .expect("the claimed native Casework task is authorized")
            .json()
            .await
            .expect("the claimed native Casework task is JSON");
        let response = http
            .post(format!("{task_url}/decisions"))
            .bearer_auth(&self.staff_token)
            .header("Registry-Casework-Profile", "staff")
            .header("If-Match", format!("\"{}\"", current["revision"]))
            .header(
                "Idempotency-Key",
                format!("adapter-native-decide-{task_id}"),
            )
            .json(&json!({"decision": {"type": "approve", "outcome": "approved"}}))
            .send()
            .await
            .expect("decide the native Casework task");
        assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
        task_id
    }
}

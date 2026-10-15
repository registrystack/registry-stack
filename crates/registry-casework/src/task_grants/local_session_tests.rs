//! Installed Casework dev session, submitted review and stock issuer task exchange.
//! Build casework/caseworkctl and provide Docker before opting in. The separate
//! native exchange test exercises the Evidence, BReg and Scheduling resources.
use axum::http::StatusCode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use registry_casework_core::{CASEWORK_PROFILE_HEADER, REVIEW_PROFILE_HEADER};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
const AUDIENCE: &str = "urn:breg:task-test";
const AUTHORITY: &str = "https://casework.local.example";

struct LocalSession {
    project: PathBuf,
    binary: PathBuf,
    ports: [u16; 4],
}
impl LocalSession {
    async fn ctl(&self, args: Vec<String>) -> std::process::Output {
        let binary = self.binary.clone();
        tokio::task::spawn_blocking(move || {
            Command::new(binary)
                .args(["--format", "json"])
                .args(args)
                .env("REGISTRY_THUNDERID_TOOLING_DIAGNOSTICS", "1")
                .output()
                .unwrap()
        })
        .await
        .unwrap()
    }
    async fn success(&self, args: Vec<String>) -> Value {
        let result = self.ctl(args).await;
        if !result.status.success() {
            eprintln!("{}", super::dev_session_logs::diagnostics(&self.root()));
        }
        assert!(
            result.status.success(),
            "CLI refusal: stdout={} stderr={}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["ok"], true);
        report["data"].clone()
    }
    async fn start(&self) -> Value {
        self.success(vec![
            "dev".into(),
            self.project.display().to_string(),
            "--casework-port".into(),
            self.ports[0].to_string(),
            "--issuer-port".into(),
            self.ports[1].to_string(),
            "--database-port".into(),
            self.ports[2].to_string(),
            "--casework-bin".into(),
            self.binary.with_file_name("casework").display().to_string(),
        ])
        .await
    }
    async fn stop(&self) {
        self.success(vec![
            "dev".into(),
            "stop".into(),
            self.project.display().to_string(),
        ])
        .await;
    }
    async fn token(&self, id: &str) -> String {
        let report = self
            .success(vec![
                "dev".into(),
                "token".into(),
                id.into(),
                self.project.display().to_string(),
            ])
            .await;
        read_header(Path::new(report["headerFile"].as_str().unwrap()))
    }
    fn root(&self) -> PathBuf {
        self.project.join(".casework/dev")
    }
    fn issuer(&self) -> String {
        format!("http://127.0.0.1:{}", self.ports[1])
    }
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.ports[0])
    }
}
impl Drop for LocalSession {
    fn drop(&mut self) {
        let output = Command::new(&self.binary)
            .args(["--format", "json", "dev", "stop"])
            .arg(&self.project)
            .arg("--remove")
            .env("REGISTRY_THUNDERID_TOOLING_DIAGNOSTICS", "1")
            .output()
            .unwrap();
        if !output.status.success() {
            eprintln!("{}", super::dev_session_logs::diagnostics(&self.root()));
            eprintln!(
                "owned dev cleanup: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if !std::thread::panicking() {
            assert!(output.status.success(), "owned dev cleanup failed");
        }
    }
}
fn read_header(path: &Path) -> String {
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .strip_prefix("Authorization: Bearer ")
        .unwrap()
        .to_owned()
}
fn payload(token: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}
fn private(path: &Path, value: &[u8]) {
    fs::write(path, value).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
async fn http(
    method: &str,
    url: &str,
    token: &str,
    profile: (&str, &str),
    revision: Option<i64>,
    body: Option<Value>,
    idempotency_key: Option<&str>,
) -> (StatusCode, Value) {
    let (profile_header, profile) = profile;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let mut request = client
        .request(method.parse().unwrap(), url)
        .bearer_auth(token)
        .header(profile_header, profile);
    if method == "POST" {
        let key = idempotency_key
            .map(str::to_owned)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        request = request.header("idempotency-key", key);
    }
    if let Some(revision) = revision {
        request = request.header("if-match", format!("\"{revision}\""));
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    (status, response.json().await.unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker and built casework/caseworkctl binaries"]
async fn submitted_review_dev_approves_exchanges_and_revokes_on_stock_issuer() {
    let workspace = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let held = (0..4)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    let ports = held
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    drop(held);
    let binary = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("caseworkctl");
    assert!(
        binary.is_file() && binary.with_file_name("casework").is_file(),
        "build casework and caseworkctl first"
    );
    let session = LocalSession {
        project: workspace.path().join("casework"),
        binary,
        ports,
    };
    fs::create_dir(&session.project).unwrap();
    let agent = session
        .success(vec!["dev".into(), "identity".into(), "task-agent".into()])
        .await;
    let requester = session
        .success(vec!["dev".into(), "identity".into(), "requester".into()])
        .await;
    let policy = json!({
        "apiVersion":"id.registrystack.org/formats/casework/project/v1alpha1",
        "kind":"CaseworkProject", "project":{"id":"local-review","version":"1"},
        "accessProfiles":{
            "staff":{"principalClaim":"sub","requiredScopes":["casework:staff"],"role":"staff"},
            "supervisor":{"principalClaim":"sub","requiredScopes":["casework:supervisor"],"role":"supervisor"},
            "administrator":{"principalClaim":"sub","requiredScopes":["casework:admin"],"role":"administrator"},
            "requester":{"principalClaim":"sub","requiredScopes":["casework:reviews:request"],"role":"requester"}
        },
        "queues":{"review":{"label":"Review"}},
        "teams":{"team":{"label":"Review team","serves":["review"],"memberProfiles":["staff"],"supervisorProfiles":["supervisor"]}},
        "reviewPolicies":[{"id":"external-review","version":"1","purpose":"approval","context":{"mode":"submitted"},
            "stages":[{"id":"review","queue":"review","decidingProfiles":["staff"],"requiredApprovals":1}],
            "retention":{"terminalRetentionDays":30,"accountabilityRetentionDays":90},
            "displaySchema":{"type":"object","additionalProperties":false,"required":["tenant"],"properties":{"tenant":{"type":"string","maxLength":128}}},"outcomes":{"approved":{"label":"Approve","settlement":"approved","reasonRequired":false,"publicReason":"optional"}}}],
        "trustedProducers":{"requester":{"profile":"requester","issuer":session.issuer(),"subject":requester["subject"],"sourceNamespaces":["standalone"],"reviewPolicies":["external-review"],"retention":{"receiptRetentionDays":7}}},
        "taskTemplates":[{"id":"draft","version":"1","label":"Prepare correction","eligibleTeams":["team"],"eligibleProfiles":["staff"],"source":"standalone","reviewPolicies":["external-review"],"agent":{"issuer":session.issuer(),"subject":agent["subject"]},"client":"task-agent","resource":AUDIENCE,"scopes":["records:get"],"purpose":"review","bounds":{"type":"breg","permissions":[{"collection":"correction-requests","operations":["create","get","patch","submit-request"]}]},"subjects":{"tenant_claim":"tenant"},"lifetimeSeconds":900}]
    });
    fs::write(
        session.project.join("casework.yaml"),
        serde_norway::to_string(&policy).unwrap(),
    )
    .unwrap();
    let clients = json!({
        "apiVersion":"id.registrystack.org/formats/casework/dev-clients/v1alpha1", "kind":"CaseworkDevClients",
        "clients":[
            {"id":"staff","accessProfile":"staff","scopes":["casework:staff"],"claims":{"registry_actor_kind":"human"}},
            {"id":"supervisor","accessProfile":"supervisor","scopes":["casework:supervisor"],"claims":{"registry_actor_kind":"human"}},
            {"id":"administrator","accessProfile":"administrator","scopes":["casework:admin"],"claims":{"registry_actor_kind":"human"}},
            {"id":"requester","accessProfile":"requester","scopes":["casework:reviews:request"]}
        ],
        "directory":[{"team":"team","queue":"review","staff":["staff"],"supervisors":["supervisor"]}],
        "integrations":{"resource":AUDIENCE,
            "serviceClients":[{"id":"task-agent","scopes":["casework:grants:assert"],"taskExchange":true},
                              {"id":"status-client","scopes":["casework:grants:status"]}],
            "taskAuthority":{"issuer":AUTHORITY,"jwksPort":session.ports[3],"statusClients":{"status-client":AUDIENCE}}}
    });
    fs::write(
        session.project.join("dev-clients.yaml"),
        serde_norway::to_string(&clients).unwrap(),
    )
    .unwrap();
    let authored =
        registry_casework_core::CaseworkProject::load(session.project.join("casework.yaml"))
            .unwrap();
    let binding = authored.compile_policy("external-review").unwrap().identity;
    session.start().await;
    let requester_token = session.token("requester").await;
    let request = json!({
        "policy": binding,
        "subject": {
            "source": "standalone",
            "type": "request",
            "id": "local-request",
            "version": "1",
            "digest": registry_casework_core::ContentDigest::for_bytes(b"local-request")
        },
        "requesterReference": "local-request",
        "context": {"mode": "submitted", "snapshot": {"tenant": "tenant-a"}}
    });
    let create_key = uuid::Uuid::new_v4().to_string();
    let (status, refused) = http(
        "POST",
        &format!("{}/v1/review-requests", session.url()),
        &requester_token,
        (CASEWORK_PROFILE_HEADER, "requester"),
        None,
        Some(request.clone()),
        Some(&create_key),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["code"], "request.invalid");
    let (status, accepted) = http(
        "POST",
        &format!("{}/v1/review-requests", session.url()),
        &requester_token,
        (REVIEW_PROFILE_HEADER, "requester"),
        None,
        Some(request),
        Some(&create_key),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{accepted}");
    let human = session.token("staff").await;
    let (status, page) = http(
        "GET",
        &format!("{}/v1/review-tasks?queue=review&limit=25", session.url()),
        &human,
        (CASEWORK_PROFILE_HEADER, "staff"),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let item = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["state"] == "open")
        .expect("submitted review created an open task");
    let id = item["taskId"].as_str().unwrap();
    let (status, claimed) = http(
        "POST",
        &format!("{}/v1/review-tasks/{id}/claim", session.url()),
        &human,
        (CASEWORK_PROFILE_HEADER, "staff"),
        Some(item["revision"].as_i64().unwrap()),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{claimed}");
    let revision = claimed["revision"].as_i64().unwrap();
    let (status, preview) = http(
        "GET",
        &format!("{}/v1/review-tasks/{id}/task-templates", session.url()),
        &human,
        (CASEWORK_PROFILE_HEADER, "staff"),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(
        preview["templates"][0]["subjects"]["tenant_claim"],
        "tenant-a"
    );
    let (status, grant) = http(
        "POST",
        &format!("{}/v1/review-tasks/{id}/task-grants", session.url()),
        &human,
        (CASEWORK_PROFILE_HEADER, "staff"),
        Some(revision),
        Some(json!({"templateId":"draft","templateVersion":"1"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    let grant_id = grant["id"].as_str().unwrap();
    let bootstrap = session.token("task-agent").await;
    assert!(payload(&bootstrap).get("registry_grant_id").is_none());
    let connection = workspace.path().join("connection.yaml");
    private(&connection, serde_norway::to_string(&json!({
        "apiVersion":registry_thunderid_tooling::task_connection::API_VERSION,
        "kind":registry_thunderid_tooling::task_connection::KIND,
        "caseworkUrl":session.url(),"tokenEndpoint":format!("{}/oauth2/token",session.issuer()),
        "clientAssertionAudience":session.issuer(),"bootstrapResource":AUDIENCE,
        "secretProviders":{"file":{"root":session.root().join("credentials/task-agent")}},
        "clients":{"task-agent":{"assertionKeyRef":"secret:file/assertion-key.jwk","resource":AUDIENCE,"scopes":["records:get"]}}
    })).unwrap().as_bytes());
    let args = vec![
        "dev".into(),
        "grant".into(),
        "task-agent".into(),
        "--grant".into(),
        grant_id.into(),
        "--connection".into(),
        connection.display().to_string(),
        session.project.display().to_string(),
    ];
    let issued = session.success(args.clone()).await;
    let claims = payload(&read_header(Path::new(
        issued["headerFile"].as_str().unwrap(),
    )));
    assert_eq!(claims["registry_grant_exp"], grant["expiresAt"]);
    assert_eq!(claims["identity"], json!({"tenant_claim":"tenant-a"}));
    assert_eq!(claims["registry_grant_source_issuer"], AUTHORITY);
    session.stop().await;
    session.start().await;
    let repeated = session.success(args.clone()).await;
    assert_eq!(
        payload(&read_header(Path::new(
            repeated["headerFile"].as_str().unwrap()
        )))["registry_grant_exp"],
        claims["registry_grant_exp"]
    );
    let human = session.token("staff").await;
    let (status, revoked) = http(
        "POST",
        &format!(
            "{}/v1/review-tasks/{id}/task-grants/{grant_id}/revoke",
            session.url()
        ),
        &human,
        (CASEWORK_PROFILE_HEADER, "staff"),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoked}");
    assert!(!session.ctl(args).await.status.success());
}

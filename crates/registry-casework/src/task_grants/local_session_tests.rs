//! Installed Casework dev session, stock issuer and actual source-backed BREG HTTP/PostgreSQL.
//! Build casework/caseworkctl and set disposable BREG_TEST_DATABASE_URL before opting in.
use super::native_resource as resource;
use axum::http::{Method, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use registry_platform_httputil::{PrivateKeyJwt, PrivateKeyJwtConfig};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
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
                .output()
                .unwrap()
        })
        .await
        .unwrap()
    }
    async fn success(&self, args: Vec<String>) -> Value {
        let result = self.ctl(args).await;
        assert!(
            result.status.success(),
            "CLI refusal: stdout={} stderr={}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        serde_json::from_slice(&result.stdout).unwrap()
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
            .output()
            .unwrap();
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
        .trim()
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
    human: bool,
    revision: Option<i64>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let mut request = client
        .request(method.parse().unwrap(), url)
        .bearer_auth(token);
    if human {
        request = request
            .header("registry-casework-profile", "staff")
            .header("registry-source-profile", "reviewer");
    }
    if let Some(revision) = revision {
        request = request
            .header("if-match", format!("\"{revision}\""))
            .header("idempotency-key", uuid::Uuid::new_v4().to_string());
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    (status, response.json().await.unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker, built casework/caseworkctl and disposable BREG_TEST_DATABASE_URL"]
async fn source_backed_dev_approves_exchanges_and_revokes_on_stock_issuer() {
    let workspace = tempfile::tempdir().unwrap();
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
    fs::create_dir(session.project.join("sources")).unwrap();
    let source_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let source_url = format!("http://{}", source_listener.local_addr().unwrap());
    let mut project: Value =
        serde_json::from_str(&resource::PROJECT.replace("\"placement\"", "\"record\"")).unwrap();
    project["accessProfiles"][0]["actorKind"] = json!("service");
    project["accessProfiles"][0]["requesterClients"] = json!(["seed-client"]);
    project["accessProfiles"][0]["requiredScopes"] = json!(["records:get"]);
    project["accessProfiles"][1]["taskGrant"]["sourceIssuer"] = json!(AUTHORITY);
    project["accessProfiles"][1]["permissions"][0]["operations"] =
        json!(["create", "get", "patch", "submit_request"]);
    project["accessProfiles"][1]["permissions"][0]
        .as_object_mut()
        .unwrap()
        .remove("revisionAccess");
    let mut source_creator = project["accessProfiles"][1].clone();
    source_creator["id"] = json!("source-creator");
    source_creator["default"] = json!(false);
    source_creator["actorKind"] = json!("service");
    source_creator["requesterClients"] = json!(["seed-client"]);
    source_creator.as_object_mut().unwrap().remove("taskGrant");
    project["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(source_creator);
    project["accessProfiles"][2]["permissions"][0]["readableRequestFields"] =
        json!(["reason", "review_state"]);
    project["accessProfiles"][2]["actorKind"] = json!("human");
    project["accessProfiles"][2]["requesterClients"] = json!(["staff"]);
    project["accessProfiles"][2]["requiredScopes"] = json!(["records:get"]);
    let mut reader = project["accessProfiles"][2].clone();
    reader["id"] = json!("reader");
    reader["actorKind"] = json!("service");
    reader["requesterClients"] = json!(["source-reader"]);
    reader["permissions"][0]["operations"] = json!(["get", "list"]);
    reader["permissions"][0]
        .as_object_mut()
        .unwrap()
        .remove("reviewStages");
    project["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(reader);
    let registry = Arc::new(
        registry_breg::compile_project(
            &registry_breg::parse_project_json(&serde_json::to_vec(&project).unwrap()).unwrap(),
            &[],
            registry_breg::CompileProfile::Authoring,
        )
        .unwrap(),
    );
    let entity = &registry.entities()["correction-request"];
    let contract = entity.change_request.as_ref().unwrap();
    let schema: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/schemas/correction-request.schema.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let description = json!({"apiVersion":"registry.registrystack.org/casework-source-description/v1alpha1","kind":"BRegCaseworkSourceDescription","origin":"bregctl explain change-requests","authority":"none","sourceId":"source","sourceRevision":registry.revision(),"request":{"requestEntity":"correction-request","requestRoute":"correction-requests","reviewMode":"staged","stages":[{"id":"review","approvals":1,"excludeSubmitter":true,"excludePreviousReviewers":false}],"application":{"mode":"manual"},"contractFingerprint":contract.contract_fingerprint,"fields":entity.stored_fields.iter().map(|field|json!({"field":field.logical.id,"apiName":field.logical.api_name,"schema":schema["properties"][&field.logical.api_name]})).collect::<Vec<_>>()}});
    fs::write(
        session.project.join("sources/source.json"),
        serde_json::to_vec(&description).unwrap(),
    )
    .unwrap();
    let identity = session
        .success(vec!["dev".into(), "identity".into(), "task-agent".into()])
        .await;
    let policy = json!({"apiVersion":"registry.registrystack.org/casework/v1alpha1","kind":"CaseworkProject","casework":{"id":"source-local","version":"1"},"accessProfiles":[{"id":"supervisor","principalClaim":"sub","requiredScopes":["casework:supervisor"],"role":"supervisor"},{"id":"staff","principalClaim":"sub","requiredScopes":["casework:staff"],"role":"staff"},{"id":"administrator","principalClaim":"sub","requiredScopes":["casework:admin"],"role":"administrator"}],"queues":[{"id":"review","label":"Review"}],"sources":[{"id":"source","adapter":"breg","description":"sources/source.json","requests":[{"entity":"correction-request","queue":"review","projection":["tenant"]}]}],"taskTemplates":[{"id":"draft","version":"1","label":"Prepare correction","eligibleTeams":["team"],"eligibleProfiles":["staff"],"source":"source","itemKinds":["correction-request"],"itemStates":["claimed"],"agent":{"issuer":session.issuer(),"subject":identity["subject"]},"client":"task-agent","resource":AUDIENCE,"scopes":["records:get"],"purpose":"review","bounds":{"type":"breg","permissions":[{"collection":"correction-requests","operations":["create","get","patch","submit_request"]}]},"subjects":{"tenant_claim":"tenant"},"lifetimeSeconds":900}]});
    fs::write(
        session.project.join("casework.yaml"),
        serde_norway::to_string(&policy).unwrap(),
    )
    .unwrap();
    let webhook = workspace.path().join("webhook");
    private(&webhook, b"synthetic-source-webhook-key-32-bytes");
    let clients = json!({"version":1,"clients":[{"id":"supervisor","accessProfile":"supervisor","scopes":["casework:supervisor"],"claims":{"registry_actor_kind":"human"}},{"id":"administrator","accessProfile":"administrator","scopes":["casework:admin"],"claims":{"registry_actor_kind":"human"}},{"id":"staff","accessProfile":"staff","scopes":["casework:staff","records:get"],"claims":{"registry_actor_kind":"human","tenant_claim":"tenant-a","registry_purpose":"review"}}],"directory":[{"team":"team","queue":"review","staff":["staff"],"supervisors":["supervisor"]}],"integrations":{"resource":AUDIENCE,"sources":{"source":{"baseUrl":source_url,"readerProfile":"reader","tokenEndpoint":format!("{}/oauth2/token",session.issuer()),"clientAssertionAudience":session.issuer(),"resource":AUDIENCE,"scopes":["records:get"],"clientIdRef":"secret:file/service-source-reader-id","clientAssertionKeyRef":"secret:file/service-source-reader-key","webhookSecretRef":"secret:file/source-webhook","eventSource":"urn:registrystack:registry:task-authority-http:instance:task-instance"}},"secretFiles":{"source-webhook":webhook},"serviceClients":[{"id":"source-reader","scopes":["records:get"],"claims":{"tenant_claim":"tenant-a","registry_purpose":"review"}},{"id":"seed-client","scopes":["records:get"],"claims":{"tenant_claim":"tenant-a","registry_purpose":"review"}},{"id":"task-agent","scopes":["casework:grants:assert"],"taskExchange":true},{"id":"status-client","scopes":["casework:grants:status"]}],"taskAuthority":{"id":"casework","issuer":AUTHORITY,"jwksPort":session.ports[3],"statusClients":{"status-client":AUDIENCE}}}});
    fs::write(
        session.project.join("dev-clients.yaml"),
        serde_norway::to_string(&clients).unwrap(),
    )
    .unwrap();
    session.start().await;
    let jwks: Value =
        serde_json::from_slice(&fs::read(session.root().join("secrets/issuer-jwks")).unwrap())
            .unwrap();
    let status_key = registry_platform_crypto::PrivateJwk::parse(
        &fs::read_to_string(
            session
                .root()
                .join("credentials/status-client/assertion-key.jwk"),
        )
        .unwrap(),
    )
    .unwrap();
    let provider = PrivateKeyJwt::new(
        PrivateKeyJwtConfig::new(
            format!("{}/oauth2/token", session.issuer())
                .parse()
                .unwrap(),
            "status-client",
            status_key,
        )
        .with_audience(session.issuer())
        .with_resource(AUDIENCE)
        .with_scopes(["casework:grants:status"]),
    )
    .unwrap();
    let checker = Arc::new(
        registry_breg::task_grant::TaskGrantStatusClient::new(
            "casework".into(),
            AUTHORITY.into(),
            AUDIENCE.into(),
            session.url().parse().unwrap(),
            Arc::new(provider),
            None,
        )
        .unwrap(),
    );
    let db = resource::TestDatabase::create(9).await;
    let installed = resource::install(&db, &registry).await;
    let app = resource::app_with_clients(
        &db,
        registry,
        installed,
        &session.issuer(),
        jwks.clone(),
        checker,
        vec![
            "task-agent".into(),
            "seed-client".into(),
            "source-reader".into(),
            "staff".into(),
            "status-client".into(),
        ],
    );
    let served = app.clone();
    let server = tokio::spawn(async move { axum::serve(source_listener, served).await.unwrap() });
    let seed = session.token("seed-client").await;
    assert_eq!(payload(&seed)["tenant_claim"], "tenant-a");
    assert_eq!(payload(&seed)["registry_actor_kind"], "service");
    assert_eq!(payload(&seed)["aud"], AUDIENCE);
    let old = resource::create(
        &app,
        "/v1/records/sites?accessProfile=steward",
        &seed,
        "local-old",
        json!({"tenant":"tenant-a","name":"Old"}),
    )
    .await;
    let next = resource::create(
        &app,
        "/v1/records/sites?accessProfile=steward",
        &seed,
        "local-next",
        json!({"tenant":"tenant-a","name":"Next"}),
    )
    .await;
    let placement = resource::create(
        &app,
        "/v1/records/placements?accessProfile=steward",
        &seed,
        "local-placement",
        json!({"tenant":"tenant-a","site":resource::id(&old)}),
    )
    .await;
    let request_data = json!({"tenant":"tenant-a","record":resource::id(&placement),"proposedSite":resource::id(&next),"reason":"Synthetic correction"});
    let draft = resource::create(
        &app,
        "/v1/records/correction-requests?accessProfile=source-creator",
        &seed,
        "local-source",
        request_data.clone(),
    )
    .await;
    let current = resource::get(&app, &resource::id(&draft), "source-creator", &seed).await;
    let action = current.body["data"]["request"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["operation"] == "submit_request")
        .unwrap();
    let submitted = resource::send(
        &app,
        Method::POST,
        action["href"].as_str().unwrap(),
        &seed,
        Some("local-submit"),
        Some(action["ifMatch"].as_str().unwrap()),
        json!({}),
    )
    .await;
    assert_eq!(submitted.status, StatusCode::OK);
    use registry_casework_core::SourceAdapter;
    let runtime = crate::RuntimeConfig::load(session.root().join("operator.yaml")).unwrap();
    let secrets = crate::secret_resolver(&runtime).unwrap();
    let authored =
        registry_casework_core::CaseworkProject::load(session.project.join("casework.yaml"))
            .unwrap();
    let adapter = runtime.sources["source"]
        .build_adapter(&authored.sources[0], &session.project, &secrets)
        .unwrap();
    let discovered = adapter
        .discover_active(None, 25)
        .await
        .expect("actual source reader can discover active requests");
    assert_eq!(discovered.subjects.len(), 1);
    adapter
        .read_authoritative(&discovered.subjects[0])
        .await
        .expect("actual source reader can observe its request");
    session.stop().await;
    session.start().await; // Immediate source reconciliation uses the retained issuer and real submitted source.
    let human = session.token("staff").await;
    let mut items = Value::Null;
    for _ in 0..100 {
        let (status, body) = http(
            "GET",
            &format!(
                "{}/v1/work-items?view=my_teams&queue=review&limit=25",
                session.url()
            ),
            &human,
            true,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        if body["items"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        {
            items = body;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        items["items"].is_array(),
        "source item should reconcile into Casework"
    );
    let item = &items["items"][0];
    let id = item["itemId"]
        .as_str()
        .or_else(|| item["id"].as_str())
        .unwrap();
    let (status, claimed) = http(
        "POST",
        &format!("{}/v1/work-items/{id}/claim", session.url()),
        &human,
        true,
        Some(item["revision"].as_i64().unwrap()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let revision = claimed["item"]["revision"].as_i64().unwrap();
    let (status, preview) = http(
        "GET",
        &format!("{}/v1/work-items/{id}/task-templates", session.url()),
        &human,
        true,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        preview["templates"][0]["subjects"]["tenant_claim"],
        "tenant-a"
    );
    let (status, grant) = http(
        "POST",
        &format!("{}/v1/work-items/{id}/task-grants", session.url()),
        &human,
        true,
        Some(revision),
        Some(json!({"templateId":"draft","templateVersion":"1"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let grant_id = grant["id"].as_str().unwrap();
    let bootstrap = session.token("task-agent").await;
    assert!(payload(&bootstrap).get("registry_grant_id").is_none());
    for client in ["task-agent", "status-client"] {
        let token = session.token(client).await;
        let denied = resource::send(
            &app,
            Method::GET,
            &format!(
                "/v1/records/correction-requests/{}?accessProfile=reviewer",
                resource::id(&draft)
            ),
            &token,
            None,
            None,
            Value::Null,
        )
        .await;
        assert_eq!(denied.status, StatusCode::NOT_FOUND);
    }
    let connection = workspace.path().join("connection.yaml");
    private(&connection,serde_norway::to_string(&json!({"version":1,"caseworkUrl":session.url(),"tokenEndpoint":format!("{}/oauth2/token",session.issuer()),"clientAssertionAudience":session.issuer(),"bootstrapResource":AUDIENCE,"clients":{"task-agent":{"assertionKeyFile":session.root().join("credentials/task-agent/assertion-key.jwk"),"resource":AUDIENCE,"scopes":["records:get"]}}})).unwrap().as_bytes());
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
    let header = PathBuf::from(issued["headerFile"].as_str().unwrap());
    let token = read_header(&header);
    let claims = payload(&token);
    assert_eq!(claims["registry_grant_exp"], grant["expiresAt"]);
    assert_eq!(claims["identity"], json!({"tenant_claim":"tenant-a"}));
    assert_eq!(claims["registry_grant_source_issuer"], AUTHORITY);
    let task_draft = resource::create(
        &app,
        "/v1/records/correction-requests?accessProfile=submitter",
        &token,
        "local-task-draft",
        request_data.clone(),
    )
    .await;
    assert_eq!(task_draft.status, StatusCode::CREATED);
    session.stop().await;
    session.start().await;
    assert_eq!(
        serde_json::from_slice::<Value>(
            &fs::read(session.root().join("secrets/issuer-jwks")).unwrap()
        )
        .unwrap(),
        jwks
    );
    let repeated = session.success(args.clone()).await;
    assert_eq!(
        payload(&read_header(Path::new(
            repeated["headerFile"].as_str().unwrap()
        )))["registry_grant_exp"],
        claims["registry_grant_exp"]
    );
    let human = session.token("staff").await;
    let (status, _) = http(
        "POST",
        &format!(
            "{}/v1/work-items/{id}/task-grants/{grant_id}/revoke",
            session.url()
        ),
        &human,
        true,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let before = resource::counts(&db).await;
    let refused = resource::send(
        &app,
        Method::POST,
        "/v1/records/correction-requests?accessProfile=submitter",
        &token,
        Some("local-revoked"),
        None,
        json!({"data":request_data}),
    )
    .await;
    assert_eq!(refused.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(resource::counts(&db).await, before);
    assert!(!session.ctl(args).await.status.success());
    server.abort();
    db.cleanup().await;
}

// SPDX-License-Identifier: Apache-2.0
//! Built BReg, gateway and review-page processes composed over public HTTP.
//! The test issuer supplies bounded task grants; BReg owns Proposal ownership,
//! target authorization, current disclosure and every lifecycle transition.

#[path = "../../registry-coordinator/tests/support/breg_service.rs"]
mod breg_service;
#[path = "support/citizen_project.rs"]
mod citizen_project;
#[path = "support/gateway.rs"]
mod gateway;
#[path = "support/mock_registry.rs"]
mod mock_registry;
#[path = "../../registry-breg-review/tests/support/mod.rs"]
mod review_support;

mod support {
    pub fn private_file(path: &std::path::Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

use axum::{
    body::Bytes,
    extract::{Path as RoutePath, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::Engine as _;
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm, PrivateJwk};
use registry_platform_testing::{
    sign_compact_jwt_with_key, ExchangeProfile, TestActorKind, TestAuthorizationServer, TestClient,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const AUDIENCE: &str = "urn:example:applications";
const A: &str = "synthetic-citizen-a";
const B: &str = "synthetic-citizen-b";
const SCOPE: &str = "address-correction:self";

#[derive(Clone)]
struct Grants {
    endpoint: String,
    key: PrivateJwk,
    issuer: String,
    bindings: Arc<Mutex<BTreeMap<String, Value>>>,
    // Reissue an immutable task grant for the same principal and bounds.
    grant_ids: Arc<Mutex<BTreeMap<String, (String, Value)>>>,
    // An explicit source-owned task inventory, independent of MCP arguments.
    proposals: Arc<Mutex<BTreeMap<String, Vec<String>>>>,
    delegated: Arc<Mutex<BTreeMap<String, String>>>,
}

async fn exchange(
    State(grants): State<Grants>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let mut request = reqwest::Client::new().post(&grants.endpoint).body(body);
    if let Some(value) = headers.get("content-type") {
        request = request.header("content-type", value);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    let mut response: Value = response.json().await.unwrap();
    if status.is_success() {
        let token = response["access_token"].as_str().unwrap();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap();
        let mut claims: Value = serde_json::from_slice(&payload).unwrap();
        if claims.get("act").is_some() {
            let principal = claims["sub"].as_str().unwrap().to_owned();
            let mut permissions = vec![
                json!({"collection":"person-addresses","operations":["get","list"]}),
                json!({"collection":"action:correct-address","operations":["start"]}),
            ];
            for id in grants
                .proposals
                .lock()
                .unwrap()
                .get(&principal)
                .into_iter()
                .flatten()
            {
                permissions.push(json!({"collection":format!("proposal:{id}"),"operations":["get","list","edit"]}));
            }
            let grant_key = format!("{principal}:{permissions:?}");
            let (grant_id, grant_exp) = grants
                .grant_ids
                .lock()
                .unwrap()
                .entry(grant_key)
                .or_insert_with(|| (uuid::Uuid::new_v4().to_string(), claims["exp"].clone()))
                .clone();
            claims["registry_grant_id"] = json!(grant_id);
            claims["registry_grant_source_issuer"] = json!("https://tasks.example.test");
            claims["registry_grant_client"] = claims["azp"].clone();
            claims["registry_grant_resource"] = claims["aud"].clone();
            claims["registry_grant_exp"] = grant_exp;
            claims["registry_purpose"] = json!("address-correction");
            claims["registry_actor_kind"] = json!("agent");
            claims["registry_approver"] = json!("h:synthetic-task-owner");
            claims["registry_grant_bounds"] = json!({"type":"breg","permissions":permissions});
            claims["identity"] = json!({"citizen":principal});
            grants.bindings.lock().unwrap().insert(
                grant_id.clone(),
                json!({
                "grantId":grant_id,"sourceIssuer":claims["registry_grant_source_issuer"],
                "principal":claims["sub"],"client":claims["azp"],"resource":claims["aud"],
                "purpose":claims["registry_purpose"],"bounds":claims["registry_grant_bounds"],
                "subjects":claims["identity"],"expiresAt":claims["registry_grant_exp"]}),
            );
            let token = sign_compact_jwt_with_key(
                &grants.key,
                "at+jwt",
                grants.key.kid.as_deref().unwrap(),
                claims,
            );
            grants
                .delegated
                .lock()
                .unwrap()
                .insert(principal, token.clone());
            response["access_token"] = json!(token);
        }
    }
    (status, Json(response))
}

async fn status(
    State(grants): State<Grants>,
    RoutePath(id): RoutePath<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let jwk = serde_json::from_value(serde_json::to_value(grants.key.public()).unwrap()).unwrap();
    let key = jsonwebtoken::DecodingKey::from_jwk(&jwk).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[&grants.issuer]);
    validation.set_audience(&["urn:tasks:native"]);
    let Ok(verified) = jsonwebtoken::decode::<Value>(token, &key, &validation) else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"active":false})));
    };
    if verified.claims["azp"] != "grant-status-reader"
        || verified.claims["scope"] != "casework:grants:status"
    {
        return (StatusCode::UNAUTHORIZED, Json(json!({"active":false})));
    }
    let binding = grants.bindings.lock().unwrap().get(&id).cloned();
    (
        StatusCode::OK,
        Json(json!({"active":binding.is_some(),"grant":binding})),
    )
}

struct Process(Child);
impl Process {
    async fn start(binary: &Path, config: &Path, origin: &str) -> Self {
        let log_path = config.with_extension("log");
        support::private_file(&log_path, b"");
        let log = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        let mut command = Command::new(binary);
        command.arg("--runtime-config").arg(config);
        command.arg("serve");
        let mut process = Self(
            command
                .stdout(Stdio::from(log.try_clone().unwrap()))
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        let http = reqwest::Client::new();
        loop {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "native service exited; inspect {}",
                log_path.display()
            );
            if http
                .get(format!("{origin}/health"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                return process;
            }
            assert!(
                Instant::now() < deadline,
                "native service not ready; inspect {}",
                log_path.display()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn address() -> std::net::SocketAddr {
    tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}
fn correction() -> Value {
    json!({"startAttemptId":"53e14a1a-6e19-4b2e-af6e-b9c39a9a3250",
        "newAddressLine":"2 Quay","newLocality":"Port Selene","newPostalCode":"PS-200"})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built matching breg, bregctl and breg-review plus owned PostgreSQL"]
async fn native_citizen_gateway_and_review_share_engine_owned_authority() {
    use gateway::{call, connect, structured};
    use review_support::{browser, cookie_pair, page, sign_in_to};
    let gateway_address = address().await;
    let review_address = address().await;
    let gateway_origin = format!("http://{gateway_address}");
    let resource = format!("{gateway_origin}/mcp");
    let review_origin = format!("http://{review_address}");
    let signing_key = generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap();
    let gateway_key = generate_private_jwk(GeneratedKeyAlgorithm::Es384).unwrap();
    let issuer = TestAuthorizationServer::builder()
        .with_signing_key(signing_key.clone())
        .client(
            TestClient::new("application-reader")
                .with_resource(AUDIENCE)
                .with_actor_kind(TestActorKind::Service),
        )
        .client(
            TestClient::new("citizen-gateway")
                .with_public_jwk(gateway_key.public())
                .with_resource(AUDIENCE)
                .with_resource(&resource)
                .with_actor_kind(TestActorKind::Agent)
                .with_service_subject(gateway::ACTOR),
        )
        .client(TestClient::new("chat-host").with_resource(&resource))
        .client(
            TestClient::new("grant-status-reader")
                .with_public_jwk(gateway_key.public())
                .with_resource("urn:tasks:native")
                .with_actor_kind(TestActorKind::Service),
        )
        .client(
            TestClient::new("citizen-review-page")
                .with_public_jwk(registry_platform_testing::fixtures::ed25519_pair().1)
                .with_resource(AUDIENCE)
                .with_redirect_uri(format!("{review_origin}/signin/callback")),
        )
        .exchange_profile(ExchangeProfile::Conformant)
        .start()
        .await;
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap()
        .keep();
    let grants = Grants {
        endpoint: issuer.token_endpoint(),
        key: signing_key,
        issuer: issuer.issuer(),
        bindings: Arc::default(),
        grant_ids: Arc::default(),
        proposals: Arc::default(),
        delegated: Arc::default(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grant_origin = format!("http://{}", listener.local_addr().unwrap());
    let token_endpoint = format!("{grant_origin}/token");
    let app = Router::new()
        .route("/token", post(exchange))
        .route("/v1/task-grants/{id}/status", get(status))
        .with_state(grants.clone());
    let exchange_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let task_status = json!([{"sourceIssuer":"https://tasks.example.test","baseUrl":grant_origin,
        "tokenEndpoint":issuer.token_endpoint(),"clientAssertionAudience":issuer.issuer(),
        "clientId":"grant-status-reader","privateKeyRef":"secret:file/status-key","caseworkResource":"urn:tasks:native"}]);
    let service = breg_service::Breg::start_citizen(
        &issuer,
        citizen_project::project(),
        task_status,
        gateway::private_jwk_json(&gateway_key).as_bytes(),
    )
    .await;
    let secrets = gateway::write_secrets(root.as_path(), &gateway_key);
    support::private_file(
        &secrets.join("review-key"),
        registry_platform_testing::fixtures::ED25519_PRIVATE_JWK.as_bytes(),
    );
    let config = root.as_path().join("gateway.yaml");
    let doc = gateway::document(&gateway::Document {
        listen: &gateway_address.to_string(),
        resource: &resource,
        issuer: &issuer.issuer(),
        jwks: &issuer.jwks_uri(),
        registry: &service.base_url,
        token_endpoint: &token_endpoint,
        review: &format!("{review_origin}/"),
        secrets: &secrets,
        audit: &root.as_path().join("gateway-audit/events.jsonl"),
        limits: gateway::Limits::default(),
    })
    .replace(gateway::AUDIENCE, AUDIENCE)
    .replace("algorithms: [EdDSA]", "algorithms: [ES256]");
    std::fs::write(&config, doc).unwrap();
    let gateway_process = Process::start(
        Path::new(env!("CARGO_BIN_EXE_breg-mcp")),
        &config,
        &gateway_origin,
    )
    .await;
    let review_config = root.as_path().join("review.yaml");
    std::fs::write(&review_config,format!("apiVersion: id.registrystack.org/formats/breg/review-runtime/v1alpha1\nkind: BRegReviewRuntimeConfig\nlistener:\n  bind: {review_address}\n  tlsTermination: development-loopback\npublicOrigin: {review_origin}\nsecretProviders:\n  file:\n    root: {}\nsignIn:\n  issuer: {}\n  clientId: citizen-review-page\n  clientKeyRef: secret:file/review-key\n  scopes: [{SCOPE}]\nregistry:\n  baseUrl: {}\n  resource: {AUDIENCE}\n  action: correct-address\n  targetInput: address\n  accessProfile: citizen-review\naudit:\n  hashKeyRef: secret:file/audit-key\n  path: {}\n",secrets.display(),issuer.issuer(),service.base_url,root.as_path().join("review-audit/events.jsonl").display())).unwrap();
    let review_binary = std::env::var_os("BREG_REVIEW_NATIVE_BIN")
        .expect("BREG_REVIEW_NATIVE_BIN names matching built breg-review");
    let review_process =
        Process::start(Path::new(&review_binary), &review_config, &review_origin).await;
    let http = reqwest::Client::new();
    let service_token = issuer.issue_access_token(
        "application-reader",
        "coordinator-reader",
        AUDIENCE,
        "applications:read",
        gateway::now() + 300,
    );
    let mut targets = BTreeMap::new();
    for (citizen, line) in [(A, "1 Harbour Road"), (B, "4 Mill Street")] {
        let response=http.post(format!("{}/v1/records/person-addresses?accessProfile=writer",service.base_url)).bearer_auth(&service_token).header("idempotency-key",format!("seed-{citizen}")).json(&json!({"data":{"owner":citizen,"addressLine":line,"locality":"Solmara","postalCode":"PS-100"}})).send().await.unwrap();
        assert_eq!(response.status(), 201);
        let value: Value = response.json().await.unwrap();
        targets.insert(
            citizen,
            value["data"]["recordIdentifier"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let token = |citizen| {
        issuer.issue_access_token("chat-host", citizen, &resource, SCOPE, gateway::now() + 300)
    };
    let a = connect(&resource, &token(A)).await;
    let b = connect(&resource, &token(B)).await;
    for (client, own, foreign) in [
        (&a, "1 Harbour Road", "4 Mill Street"),
        (&b, "4 Mill Street", "1 Harbour Road"),
    ] {
        let details = call(client, "get_my_details", json!({})).await;
        assert_eq!(details.is_error, Some(false));
        let text = structured(&details).to_string();
        assert!(text.contains(own));
        assert!(!text.contains(foreign));
    }
    let mut smuggled = correction();
    smuggled["address"] = json!(targets[A]);
    assert_eq!(
        gateway::error_code(&call(&b, "start_application", smuggled).await),
        "invalid-arguments"
    );
    let own_b = call(&b, "start_application", correction()).await;
    assert_eq!(own_b.is_error, Some(false), "{own_b:?}");
    let b_proposal = structured(&own_b)["application"]["applicationId"]
        .as_str()
        .unwrap()
        .to_owned();
    let first = call(&a, "start_application", correction()).await;
    assert_eq!(first.is_error, Some(false), "{first:?}");
    let proposal = structured(&first)["application"]["applicationId"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut changed_same_attempt = correction();
    changed_same_attempt["newLocality"] = json!("Old Town");
    assert_eq!(
        gateway::error_code(&call(&a, "start_application", changed_same_attempt).await),
        "idempotency-conflict"
    );
    grants
        .proposals
        .lock()
        .unwrap()
        .insert(A.into(), vec![proposal.clone()]);
    // Deliberately give B the same instance task bound: BReg still requires
    // its independently stored caller ownership and target boundary.
    grants
        .proposals
        .lock()
        .unwrap()
        .insert(B.into(), vec![b_proposal.clone(), proposal.clone()]);
    let own = call(
        &a,
        "get_application_status",
        json!({"applicationId":proposal}),
    )
    .await;
    assert_eq!(own.is_error, Some(false), "{own:?}");
    let review = call(&a, "prepare_review", json!({"applicationId":proposal})).await;
    assert_eq!(review.is_error, Some(false), "{review:?}");
    let review_url = structured(&review)["reviewUrl"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(review_url, format!("{review_origin}/proposals/{proposal}"));
    let tools = a.list_all_tools().await.unwrap();
    assert!(!tools.iter().any(|tool| matches!(
        tool.name.as_ref(),
        "submit_application" | "apply_application"
    )));
    assert_eq!(
        call(
            &b,
            "get_application_status",
            json!({"applicationId":proposal})
        )
        .await
        .is_error,
        Some(true)
    );
    let delegated = grants.delegated.lock().unwrap()[A].clone();
    for operation in ["submit", "apply"] {
        let refused = http
            .post(format!(
                "{}/v1/proposals/{proposal}/{operation}?accessProfile=citizen-agent",
                service.base_url
            ))
            .bearer_auth(&delegated)
            .header("idempotency-key", format!("agent-{operation}"))
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            refused.status(),
            404,
            "gateway delegation has no {operation} authority"
        );
    }
    let human = browser();
    let signed = sign_in_to(&human, &review_origin, A, &proposal).await;
    let cookie = cookie_pair(&signed.set_cookie("breg-review-session").unwrap());
    let view = page(
        human
            .get(&review_url)
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(view.status, StatusCode::OK, "{}", view.body);
    assert!(view.body.contains("1 Harbour Road"));
    assert!(view.body.contains("2 Quay"));
    let submitted = page(
        human
            .post(format!("{review_origin}/proposals/{proposal}/submit"))
            .header("cookie", &cookie)
            .form(&[
                ("csrf", view.input("csrf").unwrap()),
                ("view", view.input("view").unwrap()),
            ])
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(submitted.status, StatusCode::OK, "{}", submitted.body);
    assert!(submitted.body.contains("data-outcome=\"submitted\""));
    let human_token = issuer.issue_access_token(
        "citizen-review-page",
        A,
        AUDIENCE,
        SCOPE,
        gateway::now() + 300,
    );
    let persisted: Value = http
        .get(format!(
            "{}/v1/proposals/{proposal}?accessProfile=citizen-review",
            service.base_url
        ))
        .bearer_auth(&human_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(persisted["state"], "submitted");
    assert_eq!(persisted["input"]["address"], targets[A]);
    let cancelled = http
        .post(format!(
            "{}/v1/proposals/{proposal}/cancel?accessProfile=citizen-review",
            service.base_url
        ))
        .bearer_auth(&human_token)
        .header(
            "if-match",
            persisted["links"]["cancel"]["ifMatch"].as_str().unwrap(),
        )
        .header("idempotency-key", "cancel-first-citizen-application")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(cancelled.status(), StatusCode::OK);
    let terminal: Value = http
        .get(format!(
            "{}/v1/proposals/{proposal}?accessProfile=citizen-review",
            service.base_url
        ))
        .bearer_auth(&human_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(terminal["state"], "cancelled");
    let changed_grant_retry = call(&a, "start_application", correction()).await;
    assert_eq!(
        gateway::error_code(&changed_grant_retry),
        "idempotency-conflict"
    );
    let before_replay: Value = http
        .get(format!(
            "{}/v1/proposals?accessProfile=citizen-review",
            service.base_url
        ))
        .bearer_auth(&human_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(before_replay["items"].as_array().unwrap().len(), 1);
    // The original Start task grant remains valid for replay. The later
    // instance grant is separate and does not change that grant's binding.
    grants.proposals.lock().unwrap().insert(A.into(), vec![]);
    let retried = call(&a, "start_application", correction()).await;
    assert_eq!(retried.is_error, Some(false), "{retried:?}");
    assert_eq!(
        structured(&retried)["application"]["applicationId"],
        proposal
    );
    // A Start-only grant can identify the committed Proposal but cannot read
    // its newer terminal state. The human read above owns that assertion.
    assert_eq!(structured(&retried)["application"]["status"], "draft");
    let b_signin = sign_in_to(&human, &review_origin, B, &proposal).await;
    let b_cookie = cookie_pair(&b_signin.set_cookie("breg-review-session").unwrap());
    let hidden = page(
        human
            .get(format!("{review_origin}/proposals/{proposal}"))
            .header("cookie", &b_cookie)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert!(!hidden.body.contains("1 Harbour Road"));
    assert!(!hidden.body.contains("2 Quay"));
    assert!(!hidden.body.contains("<form"));
    let own_b_page = page(
        human
            .get(format!("{review_origin}/proposals/{b_proposal}"))
            .header("cookie", &b_cookie)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(own_b_page.status, StatusCode::OK);
    assert!(own_b_page.body.contains("4 Mill Street"));
    assert!(!own_b_page.body.contains("1 Harbour Road"));
    assert!(own_b_page.input("view").is_some());
    // A second real draft is visible, then loses current target access.
    // A new Start task has no instance grants for its not-yet-created Proposal.
    grants.proposals.lock().unwrap().insert(A.into(), vec![]);
    let mut second_input = correction();
    second_input["startAttemptId"] = json!("a6878495-b52f-420f-9dc5-220c944de359");
    let second = call(&a, "start_application", second_input).await;
    assert_eq!(second.is_error, Some(false), "{second:?}");
    let second = structured(&second)["application"]["applicationId"]
        .as_str()
        .unwrap()
        .to_owned();
    grants
        .proposals
        .lock()
        .unwrap()
        .get_mut(A)
        .unwrap()
        .push(second.clone());
    let before = page(
        human
            .get(format!("{review_origin}/proposals/{second}"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert!(before.input("view").is_some(), "{}", before.body);
    let target_url = format!(
        "{}/v1/records/person-addresses/{}?accessProfile=writer",
        service.base_url, targets[A]
    );
    let target = http
        .get(&target_url)
        .bearer_auth(&service_token)
        .send()
        .await
        .unwrap();
    let etag = target.headers()["etag"].clone();
    let revoked = http
        .patch(&target_url)
        .bearer_auth(&service_token)
        .header("if-match", etag)
        .header("idempotency-key", "withdraw-current-citizen-access")
        .header("content-type", "application/json-patch+json")
        .json(&json!([{"op":"replace","path":"/data/owner","value":B}]))
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 200);
    // B now has current target access, so only stored Proposal ownership can
    // conceal A's submitted Proposal. The task inventory alone cannot own it.
    let human_b = issuer.issue_access_token(
        "citizen-review-page",
        B,
        AUDIENCE,
        SCOPE,
        gateway::now() + 300,
    );
    assert_eq!(
        http.get(format!(
            "{}/v1/records/person-addresses/{}?accessProfile=citizen-review",
            service.base_url, targets[A]
        ))
        .bearer_auth(&human_b)
        .send()
        .await
        .unwrap()
        .status(),
        200
    );
    assert_eq!(
        http.get(format!(
            "{}/v1/proposals/{proposal}?accessProfile=citizen-review",
            service.base_url
        ))
        .bearer_auth(&human_b)
        .send()
        .await
        .unwrap()
        .status(),
        404,
        "stored caller ownership survives current target reassignment"
    );
    let hidden_now = page(
        human
            .get(format!("{review_origin}/proposals/{second}"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(hidden_now.status, StatusCode::NOT_FOUND);
    assert!(hidden_now.input("view").is_none());
    assert!(!hidden_now.body.contains("1 Harbour Road"));
    assert_eq!(
        call(&a, "prepare_review", json!({"applicationId":second}))
            .await
            .is_error,
        Some(true)
    );
    let refused = page(
        human
            .post(format!("{review_origin}/proposals/{second}/submit"))
            .header("cookie", &cookie)
            .form(&[
                ("csrf", before.input("csrf").unwrap()),
                ("view", before.input("view").unwrap()),
            ])
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert!(!refused.body.contains("data-outcome=\"submitted\""));
    assert!(!refused.body.contains("1 Harbour Road"));
    assert_eq!(
        http.get(format!(
            "{}/v1/proposals/{second}?accessProfile=citizen-review",
            service.base_url
        ))
        .bearer_auth(&human_token)
        .send()
        .await
        .unwrap()
        .status(),
        404
    );
    let final_target: Value = http
        .get(&target_url)
        .bearer_auth(&service_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let current = http
        .get(&target_url)
        .bearer_auth(&service_token)
        .send()
        .await
        .unwrap();
    let etag = current.headers()["etag"].clone();
    let restored = http
        .patch(&target_url)
        .bearer_auth(&service_token)
        .header("if-match", etag)
        .header("idempotency-key", "restore-fixture-citizen-access")
        .header("content-type", "application/json-patch+json")
        .json(&json!([{"op":"replace","path":"/data/owner","value":A}]))
        .send()
        .await
        .unwrap();
    assert_eq!(restored.status(), 200);
    let unchanged_proposal: Value = http
        .get(format!(
            "{}/v1/proposals/{second}?accessProfile=citizen-review",
            service.base_url
        ))
        .bearer_auth(&human_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        unchanged_proposal["state"], "draft",
        "refused review Submit did not freeze the draft"
    );
    assert_eq!(
        final_target["data"]["domainData"]["addressLine"], "1 Harbour Road",
        "neither gateway nor submitted manual work applied a patch"
    );
    a.cancel().await.unwrap();
    b.cancel().await.unwrap();
    drop(review_process);
    drop(gateway_process);
    exchange_task.abort();
    service.finish();
    issuer.stop().await;
    std::fs::remove_dir_all(root).unwrap();
}

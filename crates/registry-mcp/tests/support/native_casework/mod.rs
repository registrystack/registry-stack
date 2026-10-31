// SPDX-License-Identifier: Apache-2.0

mod breg;
mod casework;
mod database;
mod process;

use breg::Breg;
use casework::Casework;
use database::NativeDatabases;
use registry_mcp::{config::RuntimeConfig, runtime};
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm, PrivateJwk};
use registry_platform_httputil::client::BearerToken;
use registry_platform_testing::{
    ExchangeProfile, TestActorKind, TestAuthorizationServer, TestClient,
};
use rmcp::{
    model::{CallToolRequestParams, CallToolResult, ErrorCode},
    service::RunningService,
    transport::{
        streamable_http_client::StreamableHttpClientTransportConfig, StreamableHttpClientTransport,
    },
    RoleClient, ServiceExt as _,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub const LIST_TOOL: &str = "list_my_review_tasks";
pub const CONTEXT_TOOL: &str = "get_review_task_context";
pub const BREG_AUDIENCE: &str = "urn:casework:facility-breg";
pub const CASEWORK_AUDIENCE: &str = "urn:casework:facility-review";
const CHAT_CLIENT: &str = "synthetic-chat-host";
const GATEWAY_CLIENT: &str = "registry-mcp";
const HUMAN_CLIENT: &str = "casework-human";
const PRODUCER_CLIENT: &str = "facility-registry";
const SOURCE_CLIENT: &str = "casework-source-reader";
const STATUS_CLIENT: &str = "casework-service";
const SOURCE_ACTOR_SUBJECT: &str = "00000000-0000-4000-8000-0000000000c7";
const ALICE: &str = "synthetic-staff-alice";
const BOB: &str = "synthetic-staff-bob";
const SUPERVISOR: &str = "synthetic-staff-supervisor";
const GATEWAY_SCOPE: &str = "casework:read";

pub struct NativeCaseworkStack {
    pub authorization: TestAuthorizationServer,
    resource: String,
    alice_gateway_token: String,
    bob_gateway_token: String,
    alice_task: Uuid,
    bob_task: Uuid,
    concealed_task: Uuid,
    admin_token: BearerToken,
    alice_setup_token: BearerToken,
    supervisor_token: BearerToken,
    gateway: tokio::task::JoinHandle<()>,
    casework: Option<Casework>,
    breg: Option<Breg>,
    databases: Option<NativeDatabases>,
    directory: process::FixtureDirectory,
}

impl NativeCaseworkStack {
    pub async fn start() -> Self {
        let fixtures = process::required_absolute_path("REGISTRY_STACK_FIXTURES_ROOT");
        assert!(fixtures
            .join("products/breg/examples/facility/registry.yaml")
            .is_file());
        assert!(fixtures
            .join("products/casework/examples/canonical-review/casework.yaml")
            .is_file());
        let directory = process::FixtureDirectory::new(
            tempfile::Builder::new()
                .prefix("registry-mcp-native-casework-")
                .tempdir()
                .expect("native Casework scratch directory"),
        );
        let secrets = directory.path().join("secrets");
        std::fs::create_dir(&secrets).expect("native Casework secret directory");
        let gateway_key = generate_private_jwk(GeneratedKeyAlgorithm::Es256)
            .expect("generate gateway exchange key");
        let source_key = generate_private_jwk(GeneratedKeyAlgorithm::Es256)
            .expect("generate Casework source exchange key");
        let status_key = generate_private_jwk(GeneratedKeyAlgorithm::Es256)
            .expect("generate Casework status client key");
        write_key(&secrets.join("source-key"), &source_key);
        write_key(&secrets.join("status-key"), &status_key);
        let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("gateway listener");
        let resource = format!(
            "http://{}/mcp",
            gateway_listener.local_addr().expect("gateway address")
        );
        let propagated = ["registry_principal", "registry_purpose", "jurisdiction"];
        let exchange_client = |id: &str,
                               key: &PrivateJwk,
                               subject_resource: &str,
                               resource: &str,
                               actor: &str,
                               kind| {
            propagated.iter().fold(
                TestClient::new(id)
                    .with_public_jwk(key.public())
                    .with_exchange_subject_resource(subject_resource)
                    .with_resource(subject_resource)
                    .with_resource(resource)
                    .with_service_subject(actor)
                    .with_actor_kind(kind),
                |client, claim| client.with_exchange_subject_claim(*claim),
            )
        };
        let authorization = TestAuthorizationServer::builder()
            .with_signing_key(
                generate_private_jwk(GeneratedKeyAlgorithm::Es256)
                    .expect("generate synthetic issuer key"),
            )
            .exchange_profile(ExchangeProfile::IssuerQualifiedActor)
            .client(TestClient::new(CHAT_CLIENT).with_resource(&resource))
            .client(
                TestClient::new(HUMAN_CLIENT)
                    .with_resource(CASEWORK_AUDIENCE)
                    .with_resource(BREG_AUDIENCE),
            )
            .client(
                TestClient::new(PRODUCER_CLIENT)
                    .with_resource(CASEWORK_AUDIENCE)
                    .with_actor_kind(TestActorKind::Service),
            )
            .client(exchange_client(
                GATEWAY_CLIENT,
                &gateway_key,
                &resource,
                CASEWORK_AUDIENCE,
                GATEWAY_CLIENT,
                TestActorKind::Service,
            ))
            .client(
                exchange_client(
                    SOURCE_CLIENT,
                    &source_key,
                    CASEWORK_AUDIENCE,
                    BREG_AUDIENCE,
                    SOURCE_ACTOR_SUBJECT,
                    TestActorKind::Agent,
                )
                .with_exchange_scope_grant(
                    "casework:staff:delegated-read",
                    "registry:proposal:review",
                ),
            )
            .client(
                TestClient::new(STATUS_CLIENT)
                    .with_public_jwk(status_key.public())
                    .with_resource(BREG_AUDIENCE)
                    .with_actor_kind(TestActorKind::Service)
                    .with_service_subject(STATUS_CLIENT)
                    .with_client_credentials_claim("registry_principal", json!(STATUS_CLIENT))
                    .with_client_credentials_claim("registry_purpose", json!("facility-review")),
            )
            .client(TestClient::new("fixture-reader").with_resource(BREG_AUDIENCE))
            .client(TestClient::new("fixture-operator").with_resource(BREG_AUDIENCE))
            .client(TestClient::new("fixture-registrar").with_resource(BREG_AUDIENCE))
            .client(TestClient::new("fixture-author").with_resource(BREG_AUDIENCE))
            .start()
            .await;
        let databases = NativeDatabases::create(&secrets).await;
        let producer_token_raw = authorization.issue_access_token(
            PRODUCER_CLIENT,
            "facility-registry-review-producer",
            CASEWORK_AUDIENCE,
            "casework:request",
            now() + 300,
        );
        let casework_address = process::free_address();
        let future_casework =
            url::Url::parse(&format!("http://{casework_address}/")).expect("future Casework URL");
        let breg = Breg::start(
            &directory.path().join("breg"),
            &fixtures,
            &databases,
            &authorization,
            &future_casework,
            &producer_token_raw,
        )
        .await;
        let casework = Casework::start(
            &directory.path().join("casework"),
            &fixtures,
            &databases,
            &authorization,
            &breg.base_url,
            &breg.package,
            casework_address,
            &secrets.join("status-key"),
            &secrets.join("source-key"),
        )
        .await;
        let admin_token = bearer(
            &authorization,
            HUMAN_CLIENT,
            "synthetic-admin",
            CASEWORK_AUDIENCE,
            "casework:admin",
            "zone-a",
        );
        let alice_human = staff_bearer(&authorization, ALICE, "zone-a");
        let alice_zone_b_human = staff_bearer(&authorization, ALICE, "zone-b");
        let supervisor_human =
            human_source_bearer(&authorization, SUPERVISOR, "casework:supervisor", "zone-a");
        casework
            .bootstrap_staff(&authorization, &admin_token, ALICE, BOB, SUPERVISOR)
            .await;
        let proposal_a = breg.create_proposal(&authorization, 1, "zone-a").await;
        let proposal_b = breg.create_proposal(&authorization, 2, "zone-a").await;
        let proposal_concealed = breg.create_proposal(&authorization, 3, "zone-b").await;
        let alice_task = casework.task_for_proposal(&alice_human, &proposal_a).await;
        let bob_task = casework.task_for_proposal(&alice_human, &proposal_b).await;
        let concealed_task = casework
            .task_for_proposal(&alice_zone_b_human, &proposal_concealed)
            .await;
        casework
            .claim(&alice_human, alice_task, "native-staff-claim-a")
            .await;
        casework
            .claim(&alice_human, bob_task, "native-staff-claim-transfer")
            .await;
        casework
            .claim(
                &alice_zone_b_human,
                concealed_task,
                "native-staff-claim-concealed",
            )
            .await;
        process::private_file(
            &secrets.join("audit-key"),
            b"synthetic-gateway-audit-key-0123456789abcdef",
        );
        write_key(&secrets.join("gateway-client-key"), &gateway_key);
        let gateway_path = directory.path().join("gateway-runtime.yaml");
        write_gateway_runtime(
            &gateway_path,
            &resource,
            &authorization,
            &casework.base_url,
            directory.path(),
        );
        let config =
            RuntimeConfig::load(&gateway_path).expect("native staff gateway configuration");
        let router = runtime::build(&config)
            .await
            .expect("native staff gateway router");
        let gateway = tokio::spawn(async move {
            axum::serve(gateway_listener, router)
                .await
                .expect("native staff gateway serves")
        });
        let gateway_claims = |subject: &str| {
            BTreeMap::from([
                ("registry_principal".to_owned(), json!(subject)),
                ("registry_purpose".to_owned(), json!("facility-review")),
                ("jurisdiction".to_owned(), json!("zone-a")),
            ])
        };
        let gateway_scopes = "casework:read casework:staff casework:staff:delegated-read";
        let alice_gateway_token = authorization.issue_access_token_with_claims(
            CHAT_CLIENT,
            ALICE,
            &resource,
            gateway_scopes,
            now() + 300,
            gateway_claims(ALICE),
        );
        let bob_gateway_token = authorization.issue_access_token_with_claims(
            CHAT_CLIENT,
            BOB,
            &resource,
            gateway_scopes,
            now() + 300,
            gateway_claims(BOB),
        );
        Self {
            authorization,
            resource,
            alice_gateway_token,
            bob_gateway_token,
            alice_task,
            bob_task,
            concealed_task,
            admin_token,
            alice_setup_token: alice_human,
            supervisor_token: supervisor_human,
            gateway,
            casework: Some(casework),
            breg: Some(breg),
            databases: Some(databases),
            directory,
        }
    }

    pub async fn client_for_alice(&self) -> RunningService<RoleClient, ()> {
        self.client(&self.alice_gateway_token).await
    }
    pub async fn client_for_bob(&self) -> RunningService<RoleClient, ()> {
        self.client(&self.bob_gateway_token).await
    }
    async fn client(&self, token: &str) -> RunningService<RoleClient, ()> {
        let transport = StreamableHttpClientTransport::from_config(
            StreamableHttpClientTransportConfig::with_uri(self.resource.clone())
                .auth_header(token.to_owned()),
        );
        ().serve(transport)
            .await
            .expect("native MCP client connects")
    }
    pub async fn call(
        &self,
        client: &RunningService<RoleClient, ()>,
        tool: &str,
        arguments: Value,
    ) -> CallToolResult {
        client
            .call_tool(
                CallToolRequestParams::new(tool.to_owned()).with_arguments(
                    arguments
                        .as_object()
                        .cloned()
                        .expect("tool arguments object"),
                ),
            )
            .await
            .expect("native MCP call completes")
    }
    pub async fn assert_unknown_tool(
        &self,
        client: &RunningService<RoleClient, ()>,
        tool: &str,
        arguments: Value,
    ) {
        let error = client
            .call_tool(
                CallToolRequestParams::new(tool.to_owned()).with_arguments(
                    arguments
                        .as_object()
                        .cloned()
                        .expect("tool arguments object"),
                ),
            )
            .await
            .expect_err("an unconfigured mutation is refused by MCP");
        match error {
            rmcp::ServiceError::McpError(error) => {
                assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
                assert_eq!(error.message, "unknown tool");
                assert!(error.data.is_none());
            }
            other => panic!("unexpected MCP refusal: {other:?}"),
        }
    }
    pub async fn list(&self, client: &RunningService<RoleClient, ()>) -> CallToolResult {
        self.call(client, LIST_TOOL, json!({})).await
    }
    pub async fn context(
        &self,
        client: &RunningService<RoleClient, ()>,
        task: Uuid,
    ) -> CallToolResult {
        self.call(client, CONTEXT_TOOL, json!({"taskId":task}))
            .await
    }
    pub fn task_ids(&self, value: &Value) -> BTreeSet<Uuid> {
        value
            .pointer("/caseworkData/value/items")
            .and_then(Value::as_array)
            .expect("delegated task page")
            .iter()
            .map(|task| serde_json::from_value(task["taskId"].clone()).expect("task UUID"))
            .collect()
    }
    pub const fn alice_zone_a_task(&self) -> Uuid {
        self.alice_task
    }
    pub const fn bob_zone_a_task(&self) -> Uuid {
        self.bob_task
    }
    pub const fn alice_zone_b_task(&self) -> Uuid {
        self.concealed_task
    }
    pub fn exchange_count(&self) -> usize {
        self.authorization.exchange_observations().len()
    }
    pub async fn revoke_alice_membership(&self) {
        self.casework
            .as_ref()
            .expect("Casework running")
            .remove_alice(&self.authorization, &self.admin_token, ALICE, BOB)
            .await;
    }
    pub async fn transfer_zone_a_to_bob(&self) {
        let transferred = self
            .casework
            .as_ref()
            .expect("Casework running")
            .transfer(
                &self.authorization,
                &self.supervisor_token,
                &self.alice_setup_token,
                self.bob_task,
                BOB,
            )
            .await;
        assert_eq!(transferred.task_id, self.bob_task);
    }
    pub fn assert_exchange_chain(&self) {
        let observations = self.authorization.exchange_observations();
        let issuer = self.authorization.issuer();
        assert!(observations.iter().any(|row| {
            row.client_id == GATEWAY_CLIENT
                && row.resource == CASEWORK_AUDIENCE
                && row
                    .scopes
                    .iter()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>()
                    == BTreeSet::from(["casework:staff", "casework:staff:delegated-read"])
                && row.subject == ALICE
                && row.subject_issuer == issuer
                && row.subject_resource.as_deref() == Some(self.resource.as_str())
                && row.actor_subject.as_deref() == Some(GATEWAY_CLIENT)
                && row.actor_issuer.as_deref() == Some(issuer.as_str())
                && row.propagated_claims
                    == BTreeMap::from([
                        ("jurisdiction".to_owned(), json!("zone-a")),
                        ("registry_principal".to_owned(), json!(ALICE)),
                        ("registry_purpose".to_owned(), json!("facility-review")),
                    ])
        }));
        assert!(observations.iter().any(|row| {
            row.client_id == SOURCE_CLIENT
                && row.resource == BREG_AUDIENCE
                && row
                    .scopes
                    .iter()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>()
                    == BTreeSet::from(["registry:proposal:review"])
                && row.subject == ALICE
                && row.subject_issuer == issuer
                && row.subject_resource.as_deref() == Some(CASEWORK_AUDIENCE)
                && row.actor_subject.as_deref() == Some(SOURCE_ACTOR_SUBJECT)
                && row.actor_issuer.as_deref() == Some(issuer.as_str())
                && row.propagated_claims
                    == BTreeMap::from([
                        ("jurisdiction".to_owned(), json!("zone-a")),
                        ("registry_principal".to_owned(), json!(ALICE)),
                        ("registry_purpose".to_owned(), json!("facility-review")),
                    ])
        }));
    }
    pub fn assert_minimized_audit(&self) {
        let gateway = std::fs::read_to_string(self.directory.path().join("gateway-audit.jsonl"))
            .expect("gateway audit");
        let casework =
            std::fs::read_to_string(&self.casework.as_ref().expect("Casework running").audit_path)
                .expect("Casework audit");
        let entries = gateway
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("gateway audit JSON"))
            .collect::<Vec<_>>();
        let casework_entries = casework
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("Casework audit JSON"))
            .collect::<Vec<_>>();
        for raw in [
            ALICE,
            BOB,
            SUPERVISOR,
            CHAT_CLIENT,
            GATEWAY_CLIENT,
            SOURCE_ACTOR_SUBJECT,
            "facility-registry-review-producer",
        ] {
            assert!(
                !entries
                    .iter()
                    .any(|entry| entry["record"].to_string().contains(raw)),
                "gateway audit contains raw identity"
            );
            assert!(
                !casework_entries
                    .iter()
                    .any(|entry| entry["record"].to_string().contains(raw)),
                "Casework audit contains raw identity"
            );
        }
        assert!(entries.iter().any(|entry| entry
            .pointer("/record/principalPseudonym")
            .and_then(Value::as_str)
            .is_some()));
        assert!(entries
            .iter()
            .any(|entry| entry.pointer("/record/outcome") == Some(&json!("ok"))));
        assert!(casework_entries.iter().any(|entry| {
            let record = &entry["record"];
            record["event"] == json!("casework.delegated-review-task-context-read")
                && record["roleMode"] == json!("delegated-staff-read")
                && record["readerPolicyId"] == json!(casework::READER_POLICY)
                && record["principalPseudonym"].as_str().is_some()
                && record["gatewayPseudonym"].as_str().is_some()
                && record["clientPseudonym"].as_str().is_some()
        }));
    }
    pub async fn finish(mut self) {
        self.gateway.abort();
        drop(self.casework.take());
        drop(self.breg.take());
        if let Some(databases) = self.databases.take() {
            databases.finish().await;
        }
    }
}

pub fn structured(result: &CallToolResult) -> Value {
    result
        .structured_content
        .clone()
        .expect("structured MCP content")
}
pub fn error_code(result: &CallToolResult) -> &str {
    assert_eq!(result.is_error, Some(true), "{result:?}");
    result
        .structured_content
        .as_ref()
        .and_then(|value| value.pointer("/error/code"))
        .and_then(Value::as_str)
        .expect("MCP error code")
}

fn bearer(
    server: &TestAuthorizationServer,
    client: &str,
    subject: &str,
    resource: &str,
    scope: &str,
    jurisdiction: &str,
) -> BearerToken {
    BearerToken::new(server.issue_access_token_with_claims(
        client,
        subject,
        resource,
        scope,
        now() + 300,
        BTreeMap::from([
            ("registry_principal".to_owned(), json!(subject)),
            ("registry_purpose".to_owned(), json!("facility-review")),
            ("jurisdiction".to_owned(), json!(jurisdiction)),
        ]),
    ))
    .expect("synthetic bearer token")
}
fn staff_bearer(
    server: &TestAuthorizationServer,
    subject: &str,
    jurisdiction: &str,
) -> BearerToken {
    human_source_bearer(server, subject, "casework:staff", jurisdiction)
}
/// Existing human Casework setup forwards one credential to its paired source.
/// The delegated path under test does not: both exchanges above require one
/// exact scalar upstream resource and issue one exact downstream audience.
fn human_source_bearer(
    server: &TestAuthorizationServer,
    subject: &str,
    casework_scope: &str,
    jurisdiction: &str,
) -> BearerToken {
    BearerToken::new(server.issue_access_token_for_audiences_with_claims(
        HUMAN_CLIENT,
        subject,
        vec![CASEWORK_AUDIENCE.to_owned(), BREG_AUDIENCE.to_owned()],
        &format!("{casework_scope} registry:proposal:review"),
        now() + 300,
        BTreeMap::from([
            ("registry_principal".to_owned(), json!(subject)),
            ("registry_purpose".to_owned(), json!("facility-review")),
            ("jurisdiction".to_owned(), json!(jurisdiction)),
        ]),
    ))
    .expect("synthetic setup-only human bearer token")
}
fn write_key(path: &Path, key: &PrivateJwk) {
    process::private_file(
        path,
        serde_json::to_string(&json!({
            "kty":key.kty,
            "kid":key.kid,
            "alg":key.alg,
            "crv":key.crv,
            "x":key.x,
            "y":key.y,
            "d":key.d,
        }))
        .expect("private JWK JSON")
        .as_bytes(),
    );
}
fn write_gateway_runtime(
    path: &Path,
    resource: &str,
    issuer: &TestAuthorizationServer,
    casework_origin: &url::Url,
    scratch: &Path,
) {
    process::json_document(
        path,
        &json!({
            "apiVersion":"id.registrystack.org/formats/platform/mcp-runtime/v1alpha1","kind":"PlatformMcpRuntimeConfig","name":"Native Casework proof","logLevel":"info",
            "listener":{"bind":"127.0.0.1:1","tlsTermination":"development-loopback"},"secretProviders":{"file":{"root":scratch.join("secrets")}},
            "resourceServer":{"resource":resource,"issuer":issuer.issuer(),"allowInsecureHttp":true,"jwksSource":{"type":"uri","uri":issuer.jwks_uri()},"algorithms":["ES256"],"allowedClients":[CHAT_CLIENT],"requiredScopes":[GATEWAY_SCOPE],"maximumTokenLifetimeSeconds":3600},
            "audit":{"hashKeyRef":"secret:file/audit-key","destination":"file","path":scratch.join("gateway-audit.jsonl")},
            "rateLimits":{"perPrincipal":{"requestsPerMinute":1000,"burst":1000},"perClient":{"requestsPerMinute":1000,"burst":1000}},
            "bindings":[{"name":"native-casework","tools":[LIST_TOOL,CONTEXT_TOOL],"provider":{
            "type":"casework","authority":"delegated-staff-read","baseUrl":casework_origin.as_str(),"readerPolicy":casework::READER_POLICY,"sourceProfile":casework::SOURCE_PROFILE,"pageSize":20,
                "authorization":{"exchange":{"tokenEndpoint":issuer.token_endpoint(),"clientId":GATEWAY_CLIENT,"privateKeyRef":"secret:file/gateway-client-key"},"audience":CASEWORK_AUDIENCE,"scopes":["casework:staff","casework:staff:delegated-read"]}
            }}]
        }),
    );
}
pub fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs(),
    )
    .expect("time fits")
}

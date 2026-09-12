// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "postgres-test")]
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
    Router,
};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    authenticated_router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
};
use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema, ExpectedRegistryIdentity,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_breg::task_grant::{TaskGrantBinding, TaskGrantError, TaskGrantStatusChecker};
use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use registry_platform_audit::AuditProfile;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tower::ServiceExt;
use uuid::Uuid;
use zeroize::Zeroizing;
const PACKAGE: &str = "task-authority-http";
const AUDIENCE: &str = "urn:breg:task-test";
const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SOURCE: &str = "https://casework.example";
const PROJECT: &str = r#"{
  "apiVersion":"registry.registrystack.org/v1alpha1",
  "kind":"RegistryProject",
  "registry":{"id":"task-authority-http","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
  "entities":[
    {
      "id":"asset-site",
      "primaryDataset":"test-dataset",
      "route":"sites",
      "mutationMode":"create_only",
      "classification":"internal",
      "fields":[
        {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
        {"id":"name","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}
      ]
    },
    {
      "id":"asset-placement",
      "primaryDataset":"test-dataset",
      "route":"placements",
      "mutationMode":"mutable",
      "classification":"internal",
      "changeControl":{"requiredFor":["patch"]},
      "fields":[
        {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
        {"id":"site","type":"reference","target":"asset-site","required":true,"classification":"internal"}
      ]
    },
    {
      "id":"correction-request",
      "primaryDataset":"test-dataset",
      "route":"correction-requests",
      "mutationMode":"mutable",
      "classification":"internal",
      "fields":[
        {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
        {"id":"placement","type":"reference","target":"asset-placement","required":true,"classification":"internal"},
        {"id":"proposed-site","type":"reference","target":"asset-site","required":true,"classification":"internal"},
        {"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"internal"}
      ],
      "changeRequest":{
        "effects":[{"target":{"fromField":"placement"},"operation":"patch","set":{"site":{"fromField":"proposed-site"}}}],
        "review":{"stages":[{"id":"review","approvals":1,"excludeSubmitter":true}]}
      }
    }
  ],
  "accessProfiles":[
    {
      "id":"steward",
      "default":true,
      "principalClaim":"sub",
      "permissions":[
        {
          "entity":"asset-site",
          "operations":["create","get","list"],
          "readableFields":["tenant","name"],
          "writableFields":["tenant","name"],
          "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
        },
        {
          "entity":"asset-placement",
          "operations":["create","get","list","revisions"],
          "revisionAccess":true,
          "readableFields":["tenant","site"],
          "writableFields":["tenant","site"],
          "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
          "requestPresence":[{"requestType":"correction-request","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
        }
      ]
    },
    {
      "id":"submitter",
      "default":true,
      "principalClaim":"sub",
      "permissions":[
        {
          "entity":"correction-request",
          "operations":["create","get","list","revisions","patch","submit_request","revise_request","cancel_request"],
          "revisionAccess":true,
          "readableFields":["tenant","placement","proposed-site","reason"],
          "writableFields":["tenant","placement","proposed-site","reason"],
          "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
        }
      ],
      "actorKind":"agent",
      "requesterClients":["task-agent"],
      "requiredPurposes":["review"],
      "taskGrant":{"authority":"casework","sourceIssuer":"https://casework.example"}
    },
    {
      "id":"reviewer",
      "principalClaim":"sub",
      "requiredPurposes":["review"],
      "permissions":[
        {
          "entity":"correction-request",
          "operations":["get","list","approve_request","reject_request","request_revision"],
          "readableFields":["tenant","placement","proposed-site","reason"],
          "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
          "reviewStages":[{"stage":"review","targets":[{"entity":"asset-placement","readableFields":["site"],"rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]}]
        }
      ]
    },
    {
      "id":"applier",
      "principalClaim":"sub",
      "requiredPurposes":["apply"],
      "permissions":[
        {
          "entity":"correction-request",
          "operations":["get","apply_request"],
          "readableFields":["tenant","placement","proposed-site","reason"],
          "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
          "applyTargets":[{"entity":"asset-placement","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
        }
      ]
    }
  ]
}"#;

#[derive(Default)]
struct Status {
    bindings: Mutex<BTreeMap<String, TaskGrantBinding>>,
    revoked: Mutex<std::collections::BTreeSet<String>>,
    unavailable: Mutex<std::collections::BTreeSet<String>>,
    calls: AtomicUsize,
    revoke_after_check: Mutex<Option<String>>,
}
impl TaskGrantStatusChecker for Status {
    fn check<'a>(
        &'a self,
        binding: &'a TaskGrantBinding,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TaskGrantError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                self.bindings.lock().unwrap().get(binding.grant_id()),
                Some(binding),
                "every later human check uses the entire original immutable binding"
            );
            if self
                .unavailable
                .lock()
                .unwrap()
                .contains(binding.grant_id())
            {
                return Err(TaskGrantError::Unavailable);
            }
            if self.revoked.lock().unwrap().contains(binding.grant_id()) {
                Err(TaskGrantError::Refused)
            } else {
                if self.revoke_after_check.lock().unwrap().as_deref() == Some(binding.grant_id()) {
                    self.revoked
                        .lock()
                        .unwrap()
                        .insert(binding.grant_id().to_owned());
                }
                Ok(())
            }
        })
    }
}
impl Status {
    fn revoke(&self, id: &str) {
        self.revoked.lock().unwrap().insert(id.to_owned());
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}
struct Ready;
impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
async fn install(db: &TestDatabase, registry: &CompiledRegistry) -> ExpectedRegistryIdentity {
    let (migration, task) = db.connect_migration().await;
    install_compiled_schema(&migration, registry, &db.runtime_role)
        .await
        .unwrap();
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &db.runtime_role,
        registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE,
            environment: "local",
            instance_id: "task-instance",
            database_id: "task-database",
            package_revision: REVISION,
            package_sequence: 1,
        },
    )
    .await
    .unwrap();
    drop(migration);
    task.abort();
    identity
}
fn app(
    db: &TestDatabase,
    registry: Arc<CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    idp: &MockIdp,
    status: Arc<Status>,
) -> Router {
    let pool = db.runtime_config.build_pool().unwrap();
    let lock = RegistryLockKey::derive(PACKAGE).unwrap();
    let audit = AuditProfile::production_from_secret_bytes(vec![0x9a; 32].into()).unwrap();
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x49; 32]), Duration::from_secs(300)).unwrap(),
    );
    let reads = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    ));
    let writes = Arc::new(
        PostgresRecordMutationService::new(
            pool,
            registry.clone(),
            identity.clone(),
            lock,
            Duration::from_secs(2),
            audit,
        )
        .with_task_status(status),
    );
    let keys = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        idp.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![AUDIENCE.into()]);
    verifier.allowed_clients = vec!["task-agent".into(), "human-client".into()];
    let auth = RegistryAuthenticator::new(
        &registry,
        verifier,
        keys,
        AuthorityClaimConfig::new("sub", Some("registry_purpose".into())),
    )
    .unwrap();
    authenticated_router(
        Arc::new(
            HttpService::new(
                registry,
                ReadRuntimeIdentity {
                    package_revision: identity.package_revision,
                    schema_fingerprint: identity.schema_fingerprint,
                },
                reads,
                Arc::new(Ready),
                cursors,
            )
            .with_postgres_mutations(writes),
        ),
        Arc::new(auth),
    )
}
fn human(idp: &MockIdp, subject: &str, purpose: &str) -> String {
    idp.mint_token(
        json!({"aud":AUDIENCE,"client_id":"human-client","sub":subject,"tenant_claim":"tenant-a","registry_purpose":purpose}),
    )
}
fn agent(idp: &MockIdp, status: &Status) -> (String, String) {
    let id = Uuid::new_v4().to_string();
    let expires = chrono::Utc::now().timestamp() + 900;
    let project: Value = serde_json::from_str(PROJECT).unwrap();
    let permissions = project["accessProfiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == "submitter")
        .unwrap()["permissions"]
        .as_array()
        .unwrap();
    let bounds = json!({"type":"breg","permissions":permissions.iter().map(|p|json!({"collection":"correction-requests","operations":p["operations"]})).collect::<Vec<_>>()});
    let subjects = json!({"tenant_claim":"tenant-a"});
    let binding:TaskGrantBinding=serde_json::from_value(json!({"grantId":id,"authority":"casework","sourceIssuer":SOURCE,"principal":"agent-subject","client":"task-agent","resource":AUDIENCE,"purpose":"review","bounds":bounds,"subjects":subjects,"expiresAt":expires})).unwrap();
    status.bindings.lock().unwrap().insert(id.clone(), binding);
    let token=idp.mint_token(json!({"aud":AUDIENCE,"sub":"agent-subject","client_id":"task-agent","registry_actor_kind":"agent","registry_grant_id":id,"registry_grant_authority":"casework","registry_grant_source_issuer":SOURCE,"registry_grant_client":"task-agent","registry_grant_resource":AUDIENCE,"registry_purpose":"review","registry_grant_exp":expires,"registry_grant_bounds":bounds,"identity":subjects}));
    (id, token)
}
struct Response {
    status: StatusCode,
    body: Value,
    etag: String,
}
async fn send(
    app: &Router,
    method: Method,
    uri: &str,
    token: &str,
    key: Option<&str>,
    etag: Option<&str>,
    body: Value,
) -> Response {
    let mut req = Request::builder()
        .method(method.clone())
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    if let Some(key) = key {
        req = req.header("idempotency-key", key);
    }
    if let Some(etag) = etag {
        req = req.header("if-match", etag);
    }
    if method == Method::PATCH {
        req = req.header("content-type", "application/json-patch+json");
    } else {
        req = req.header("content-type", "application/json");
    }
    let raw = if method == Method::GET {
        Vec::new()
    } else {
        serde_json::to_vec(&body).unwrap()
    };
    let response = app
        .clone()
        .oneshot(req.body(Body::from(raw)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let etag = response
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
        .unwrap();
    Response { status, etag, body }
}
async fn create(app: &Router, route: &str, token: &str, key: &str, data: Value) -> Response {
    let r = send(
        app,
        Method::POST,
        route,
        token,
        Some(key),
        None,
        json!({"data":data}),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    r
}
fn id(response: &Response) -> String {
    response.body["data"]["recordIdentifier"]
        .as_str()
        .unwrap()
        .into()
}
async fn get(app: &Router, id: &str, profile: &str, token: &str) -> Response {
    let r = send(
        app,
        Method::GET,
        &format!("/v1/records/correction-requests/{id}?accessProfile={profile}"),
        token,
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    r
}
fn action(r: &Response, operation: &str) -> Value {
    r.body["data"]["request"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["operation"] == operation)
        .unwrap()
        .clone()
}
async fn perform(app: &Router, action: &Value, token: &str, key: &str) -> Response {
    let mut body = if action.get("proposalVersion").is_some() {
        json!({"proposalVersion":action["proposalVersion"],"effectDigest":action["effectDigest"]})
    } else {
        json!({})
    };
    if action["operation"] == "reject_request" {
        body["reason"] = json!("The task was revoked.");
    }
    send(
        app,
        Method::POST,
        action["href"].as_str().unwrap(),
        token,
        Some(key),
        action["ifMatch"].as_str(),
        body,
    )
    .await
}
async fn counts(db: &TestDatabase) -> Vec<i64> {
    let mut counts = Vec::new();
    for table in [
        "registry_revisions",
        "registry_idempotency",
        "registry_request_proposals",
        "registry_request_decisions",
        "registry_request_applications",
        "registry_request_results",
        "registry_request_task_authority",
    ] {
        counts.push(
            db.admin
                .query_one(
                    &format!("SELECT count(*) FROM registry_internal.{table}"),
                    &[],
                )
                .await
                .unwrap()
                .get(0),
        );
    }
    counts
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn task_http_to_postgres_preserves_original_authority_and_completed_receipts() {
    let db = TestDatabase::create(8).await;
    let registry = Arc::new(
        compile_project(
            &parse_project_json(PROJECT.as_bytes()).unwrap(),
            &[],
            CompileProfile::Authoring,
        )
        .unwrap(),
    );
    let identity = install(&db, &registry).await;
    let idp = MockIdp::start().await;
    let status = Arc::new(Status::default());
    let app = app(&db, registry.clone(), identity, &idp, status.clone());
    let steward = human(&idp, "steward", "maintain");
    let reviewer = human(&idp, "reviewer", "review");
    let applier = human(&idp, "applier", "apply");
    let old = create(
        &app,
        "/v1/records/sites?accessProfile=steward",
        &steward,
        "old-site",
        json!({"tenant":"tenant-a","name":"old"}),
    )
    .await;
    let new = create(
        &app,
        "/v1/records/sites?accessProfile=steward",
        &steward,
        "new-site",
        json!({"tenant":"tenant-a","name":"new"}),
    )
    .await;
    let target = create(
        &app,
        "/v1/records/placements?accessProfile=steward",
        &steward,
        "placement",
        json!({"tenant":"tenant-a","site":id(&old)}),
    )
    .await;
    for phase in [
        "draft",
        "unavailable",
        "retry",
        "submitted",
        "approved",
        "applied",
    ] {
        let (grant, token) = agent(&idp, &status);
        let create_key = format!("{phase}-create");
        let before_calls = status.calls();
        let draft=create(&app,"/v1/records/correction-requests?accessProfile=submitter",&token,&create_key,json!({"tenant":"tenant-a","placement":id(&target),"proposedSite":id(&new),"reason":"synthetic correction"})).await;
        assert_eq!(
            status.calls(),
            before_calls + 1,
            "HTTP grant must reach the SQL coordinator"
        );
        let record = id(&draft);
        let read = get(&app, &record, "submitter", &token).await;
        let submit = action(&read, "submit_request");
        let (other_grant, other_token) = agent(&idp, &status);
        let same_read = get(&app, &record, "submitter", &other_token).await;
        assert_eq!(
            read.etag, same_read.etag,
            "grant IDs do not alter read ETags"
        );
        let conflict=send(&app,Method::POST,"/v1/records/correction-requests?accessProfile=submitter",&other_token,Some(&create_key),None,json!({"data":{"tenant":"tenant-a","placement":id(&target),"proposedSite":id(&new),"reason":"synthetic correction"}})).await;
        assert_eq!(
            conflict.status,
            StatusCode::CONFLICT,
            "different immutable grant cannot reuse key"
        );
        status.revoke(&other_grant);
        if phase == "draft" {
            status.revoke(&grant);
            let before = counts(&db).await;
            let patch = send(
                &app,
                Method::PATCH,
                &format!("/v1/records/correction-requests/{record}?accessProfile=submitter"),
                &token,
                Some("revoked-patch"),
                Some(&read.etag),
                json!([{"op":"replace","path":"/data/reason","value":"must not commit"}]),
            )
            .await;
            assert_eq!(
                patch.status,
                StatusCode::PRECONDITION_FAILED,
                "{}",
                patch.body
            );
            assert_eq!(
                perform(&app, &submit, &token, "revoked-submit")
                    .await
                    .status,
                StatusCode::PRECONDITION_FAILED
            );
            assert_eq!(counts(&db).await, before);
            let call_count = status.calls();
            let recovered=create(&app,"/v1/records/correction-requests?accessProfile=submitter",&token,&create_key,json!({"tenant":"tenant-a","placement":id(&target),"proposedSite":id(&new),"reason":"synthetic correction"})).await;
            assert_eq!(recovered.body, draft.body);
            assert_eq!(status.calls(), call_count);
            assert_eq!(counts(&db).await, before);
            continue;
        }
        if phase == "unavailable" {
            status.unavailable.lock().unwrap().insert(grant.clone());
            let before = counts(&db).await;
            assert_eq!(
                perform(&app, &submit, &token, "unavailable-submit")
                    .await
                    .status,
                StatusCode::SERVICE_UNAVAILABLE
            );
            assert_eq!(counts(&db).await, before);
            continue;
        }
        if phase == "retry" {
            let table = &registry.entities()["correction-request"].physical_table;
            let role = db.runtime_role.as_str();
            db.admin.batch_execute(&format!(r#"
              CREATE SEQUENCE registry_internal.task_retry_sequence;
              GRANT USAGE, SELECT ON SEQUENCE registry_internal.task_retry_sequence TO "{role}";
              CREATE FUNCTION registry_internal.task_retry_once() RETURNS trigger LANGUAGE plpgsql AS $$
              BEGIN
                IF nextval('registry_internal.task_retry_sequence')=1 THEN
                  RAISE EXCEPTION 'synthetic serialization abort' USING ERRCODE='40001';
                END IF;
                RETURN NEW;
              END $$;
              CREATE TRIGGER task_retry_once BEFORE UPDATE ON registry_data."{table}"
                FOR EACH ROW EXECUTE FUNCTION registry_internal.task_retry_once();
            "#)).await.unwrap();
            *status.revoke_after_check.lock().unwrap() = Some(grant.clone());
            let before = counts(&db).await;
            let calls = status.calls();
            let refused = perform(&app, &submit, &token, "serialization-retry").await;
            assert_eq!(
                refused.status,
                StatusCode::PRECONDITION_FAILED,
                "{}",
                refused.body
            );
            assert_eq!(
                status.calls(),
                calls + 2,
                "an aborted SQL transaction must acquire fresh status on retry"
            );
            assert_eq!(
                counts(&db).await,
                before,
                "the aborted first attempt leaves no mutation or proposal state"
            );
            db.admin
                .batch_execute(&format!(
                    "DROP TRIGGER task_retry_once ON registry_data.\"{table}\";"
                ))
                .await
                .unwrap();
            continue;
        }
        let submit_key = format!("{phase}-submit");
        let submitted = perform(&app, &submit, &token, &submit_key).await;
        assert_eq!(submitted.status, StatusCode::OK, "{}", submitted.body);
        let stored:Value=db.admin.query_one("SELECT binding FROM registry_internal.registry_request_task_authority WHERE request_id=$1",&[&Uuid::parse_str(&record).unwrap()]).await.unwrap().get(0);
        assert_eq!(stored["grantId"], grant);
        assert_eq!(stored["principal"], "agent-subject");
        let review = action(
            &get(&app, &record, "reviewer", &reviewer).await,
            "approve_request",
        );
        if phase == "submitted" {
            status.revoke(&grant);
            let before = counts(&db).await;
            assert_eq!(
                perform(&app, &review, &reviewer, "revoked-approve")
                    .await
                    .status,
                StatusCode::PRECONDITION_FAILED
            );
            assert_eq!(counts(&db).await, before);
            let call_count = status.calls();
            assert_eq!(
                perform(&app, &submit, &token, &submit_key).await.status,
                StatusCode::OK
            );
            assert_eq!(
                status.calls(),
                call_count,
                "completed receipt does not reacquire mutation authority"
            );
            let reject = action(
                &get(&app, &record, "reviewer", &reviewer).await,
                "reject_request",
            );
            assert_eq!(
                perform(&app, &reject, &reviewer, "human-reject")
                    .await
                    .status,
                StatusCode::OK
            );
            assert_eq!(
                status.calls(),
                call_count,
                "reviewer rejection does not depend on revoked task"
            );
            continue;
        }
        let review_key = format!("{phase}-approve");
        assert_eq!(
            perform(&app, &review, &reviewer, &review_key).await.status,
            StatusCode::OK
        );
        let apply = action(
            &get(&app, &record, "applier", &applier).await,
            "apply_request",
        );
        if phase == "approved" {
            status.revoke(&grant);
            let before = counts(&db).await;
            assert_eq!(
                perform(&app, &apply, &applier, "revoked-apply")
                    .await
                    .status,
                StatusCode::PRECONDITION_FAILED
            );
            assert_eq!(counts(&db).await, before);
            continue;
        }
        let receipt = perform(&app, &apply, &applier, "apply").await;
        assert_eq!(receipt.status, StatusCode::OK, "{}", receipt.body);
        status.revoke(&grant);
        let before = counts(&db).await;
        let call_count = status.calls();
        let replay = perform(&app, &apply, &applier, "apply").await;
        assert_eq!(replay.status, StatusCode::OK);
        assert_eq!(replay.body, receipt.body);
        assert_eq!(counts(&db).await, before);
        assert_eq!(status.calls(), call_count);
        let recovered = perform(&app, &apply, &applier, "apply-new-recovery-key").await;
        assert_eq!(recovered.status, StatusCode::OK);
        assert_eq!(recovered.body, receipt.body);
        assert_eq!(status.calls(), call_count);
        let mut receipt_only = before.clone();
        receipt_only[1] += 1;
        assert_eq!(
            counts(&db).await,
            receipt_only,
            "new recovery key may retain its receipt but cannot apply again"
        );
        let before = receipt_only;
        let changed = send(
            &app,
            Method::POST,
            apply["href"].as_str().unwrap(),
            &applier,
            Some("apply"),
            apply["ifMatch"].as_str(),
            json!({"proposalVersion":2,"effectDigest":apply["effectDigest"]}),
        )
        .await;
        assert_eq!(changed.status, StatusCode::CONFLICT);
        assert_eq!(counts(&db).await, before);
        let hidden=idp.mint_token(json!({"aud":AUDIENCE,"client_id":"human-client","sub":"applier","tenant_claim":"tenant-b","registry_purpose":"apply"}));
        let refusal = perform(&app, &apply, &hidden, "apply").await;
        assert!(
            !refusal.status.is_success(),
            "a completed receipt still requires current disclosure"
        );
        assert_eq!(counts(&db).await, before);
        assert_eq!(status.calls(), call_count);
    }
    db.cleanup().await;
}

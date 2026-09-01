// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_platform_audit::AuditProfile;
use registry_server::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::cursor::CursorCodec;
use registry_server::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use serde_json::{json, Value};
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "request-query-registry";
const PACKAGE_REVISION: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TENANT: &str = "tenant-a";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_request_queues_filter_count_and_page_on_server_owned_state() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(compiled_registry());
    let identity = install_registry(&database, &registry).await;
    let app = request_query_router(&database, registry, identity);

    let steward = claims("steward-principal", None);
    let submitter = claims("submitter-principal", None);
    let reviewer = claims("reviewer-principal", Some("review"));

    let first_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "queue-create-first-site",
        json!({"tenant": TENANT, "name": "first"}),
    )
    .await;
    let second_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "queue-create-second-site",
        json!({"tenant": TENANT, "name": "second"}),
    )
    .await;
    let third_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "queue-create-third-site",
        json!({"tenant": TENANT, "name": "third"}),
    )
    .await;
    let first_placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=steward",
        steward.clone(),
        "queue-create-first-placement",
        json!({"tenant": TENANT, "site": first_site.id}),
    )
    .await;
    let second_placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=steward",
        steward.clone(),
        "queue-create-second-placement",
        json!({"tenant": TENANT, "site": first_site.id}),
    )
    .await;
    let draft_request = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=submitter",
        submitter.clone(),
        "queue-create-draft-request",
        json!({
            "tenant": TENANT,
            "placement": first_placement.id,
            "proposedSite": second_site.id,
            "reason": "draft request must not enter submitted queue"
        }),
    )
    .await;
    let first_submitted = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=submitter",
        submitter.clone(),
        "queue-create-first-submitted-request",
        json!({
            "tenant": TENANT,
            "placement": first_placement.id,
            "proposedSite": third_site.id,
            "reason": "first submitted request"
        }),
    )
    .await;
    let second_submitted = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=submitter",
        submitter.clone(),
        "queue-create-second-submitted-request",
        json!({
            "tenant": TENANT,
            "placement": second_placement.id,
            "proposedSite": third_site.id,
            "reason": "second submitted request"
        }),
    )
    .await;

    let first_submitted_body = submit_request(
        &app,
        &first_submitted.id,
        submitter.clone(),
        "queue-submit-first-request",
    )
    .await;
    let first_digest = first_submitted_body["request"]["effectDigest"]
        .as_str()
        .expect("submitted request has a digest")
        .to_owned();
    let second_submitted_body = submit_request(
        &app,
        &second_submitted.id,
        submitter.clone(),
        "queue-submit-second-request",
    )
    .await;
    let second_digest = second_submitted_body["request"]["effectDigest"]
        .as_str()
        .expect("submitted request has a digest")
        .to_owned();
    assert_ne!(first_digest, second_digest);

    let submitted_page = response_parts(
        send(
            &app,
            Method::GET,
            "/v1/records/correction-requests?accessProfile=reviewer&$select=reason&$filter=serverState%20eq%20'submitted'&$orderby=proposalVersion&$top=1&$count=true",
            Some(reviewer.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(
        submitted_page.status,
        StatusCode::OK,
        "{}",
        submitted_page.body
    );
    assert_eq!(submitted_page.cache_control.as_deref(), Some("no-store"));
    assert_eq!(submitted_page.body["count"], 2);
    let submitted_items = submitted_page.body["items"]
        .as_array()
        .expect("submitted queue returns items");
    assert_eq!(submitted_items.len(), 1);
    assert_eq!(submitted_items[0]["request"]["serverState"], "submitted");
    assert_ne!(submitted_items[0]["id"], draft_request.id);
    assert!(submitted_items[0]["data"].get("serverState").is_none());
    assert!(submitted_page.body["pageInfo"]["nextCursor"].is_string());

    let cursor = submitted_page.body["pageInfo"]["nextCursor"]
        .as_str()
        .expect("first submitted page carries cursor")
        .to_owned();
    let continuation = response_parts(
        send(
            &app,
            Method::GET,
            &format!("/v1/records/correction-requests?accessProfile=reviewer&$skiptoken={cursor}"),
            Some(reviewer.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(continuation.status, StatusCode::OK, "{}", continuation.body);
    assert_eq!(continuation.body["count"], 1);
    let continuation_items = continuation.body["items"]
        .as_array()
        .expect("cursor returns items");
    assert_eq!(continuation_items.len(), 1);
    assert_eq!(continuation_items[0]["request"]["serverState"], "submitted");
    assert_ne!(continuation_items[0]["id"], submitted_items[0]["id"]);
    assert!(continuation.body["pageInfo"]["nextCursor"].is_null());

    let cursor_wrong_profile = response_parts(
        send(
            &app,
            Method::GET,
            &format!("/v1/records/correction-requests?accessProfile=submitter&$skiptoken={cursor}"),
            Some(submitter.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(cursor_wrong_profile.status, StatusCode::BAD_REQUEST);
    assert_eq!(cursor_wrong_profile.body["code"], "query.cursor_invalid");
    let wrong_profile_text = cursor_wrong_profile.body.to_string();
    assert!(!wrong_profile_text.contains("submitted"));
    assert!(!wrong_profile_text.contains(TENANT));

    let draft_count = response_parts(
        send(
            &app,
            Method::GET,
            "/v1/records/correction-requests?accessProfile=submitter&$select=reason&$filter=effectDigest%20eq%20null&$count=true",
            Some(submitter),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(draft_count.status, StatusCode::OK, "{}", draft_count.body);
    assert_eq!(draft_count.body["count"], 1);
    assert_eq!(draft_count.body["items"][0]["id"], draft_request.id);
    assert_eq!(
        draft_count.body["items"][0]["request"]["serverState"],
        "draft"
    );
    assert!(draft_count.body["items"][0]["data"]
        .get("effectDigest")
        .is_none());

    let selected_server_state = response_parts(
        send(
            &app,
            Method::GET,
            "/v1/records/correction-requests?accessProfile=reviewer&$select=serverState",
            Some(reviewer.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(selected_server_state.status, StatusCode::BAD_REQUEST);
    assert_eq!(selected_server_state.body["code"], "query.invalid");

    let target_state_filter = response_parts(
        send(
            &app,
            Method::GET,
            "/v1/records/placements?accessProfile=steward&$filter=serverState%20eq%20'submitted'&$count=true",
            Some(steward),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(target_state_filter.status, StatusCode::BAD_REQUEST);
    assert_eq!(target_state_filter.body["code"], "query.invalid");
    assert!(!target_state_filter.body.to_string().contains("pending"));

    database.cleanup().await;
}

fn request_query_router(
    database: &TestDatabase,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: registry_server::postgres::ExpectedRegistryIdentity,
) -> axum::Router {
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let audit = AuditProfile::production_from_secret_bytes(vec![0x4d; 32].into())
        .expect("test audit profile is keyed");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x51; 32]), Duration::from_secs(300))
            .expect("cursor codec builds"),
    );
    let reads = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    ));
    let mutations = Arc::new(PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit,
    ));
    router(Arc::new(
        HttpService::new(
            registry,
            ReadRuntimeIdentity {
                package_revision: identity.package_revision,
                schema_fingerprint: identity.schema_fingerprint,
            },
            reads,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_postgres_mutations(mutations),
    ))
}

#[derive(Clone)]
struct CreatedRecord {
    id: String,
}

async fn create_record(
    app: &axum::Router,
    uri: &str,
    claims: VerifiedRequestClaims,
    key: &str,
    data: Value,
) -> CreatedRecord {
    let response = response_parts(
        send(
            app,
            Method::POST,
            uri,
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", key),
            ],
            serde_json::to_vec(&json!({ "data": data })).expect("create body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.body);
    let id = response.body["id"]
        .as_str()
        .expect("created response includes id")
        .to_owned();
    assert!(Uuid::parse_str(&id).is_ok_and(|uuid| uuid.to_string() == id));
    CreatedRecord { id }
}

async fn submit_request(
    app: &axum::Router,
    request_id: &str,
    claims: VerifiedRequestClaims,
    key: &str,
) -> Value {
    let before = response_parts(
        send(
            app,
            Method::GET,
            &format!("/v1/records/correction-requests/{request_id}?accessProfile=submitter"),
            Some(claims.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(before.status, StatusCode::OK, "{}", before.body);
    let action = before.body["request"]["actions"]
        .as_array()
        .expect("request read exposes action links")
        .iter()
        .find(|action| action["operation"] == "submit_request")
        .expect("submit action exists")
        .clone();
    let href = action["href"].as_str().expect("submit action has href");
    let if_match = action["ifMatch"]
        .as_str()
        .expect("submit action has precondition");
    let response = response_parts(
        send(
            app,
            Method::POST,
            href,
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", key),
                ("if-match", if_match),
            ],
            serde_json::to_vec(&json!({})).expect("submit body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    response.body
}

async fn install_registry(
    database: &TestDatabase,
    registry: &Arc<registry_server::CompiledRegistry>,
) -> registry_server::postgres::ExpectedRegistryIdentity {
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, registry, &database.runtime_role)
        .await
        .expect("request query schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: "request-query-instance",
            database_id: "request-query-database",
            package_revision: PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("active request-query identity initializes");
    drop(migration);
    migration_task.abort();
    identity
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    headers: &[(<&str as ToOwned>::Owned, <&str as ToOwned>::Owned)],
    body: Vec<u8>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .expect("request builds");
    for (name, value) in headers {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("test header name"),
            HeaderValue::from_str(value).expect("test header value"),
        );
    }
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router returns response")
}

struct ResponseParts {
    status: StatusCode,
    body: Value,
    cache_control: Option<String>,
}

async fn response_parts(response: axum::response::Response) -> ResponseParts {
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body is bounded")
        .to_vec();
    ResponseParts {
        status,
        body: serde_json::from_slice(&bytes).expect("response body is JSON"),
        cache_control: headers
            .get("cache-control")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    }
}

fn claims(principal: &str, purpose: Option<&str>) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        BTreeSet::new(),
        purpose.map(str::to_owned),
        BTreeMap::from([(
            "tenant_claim".to_owned(),
            VerifiedClaimValue::direct_string(TENANT).expect("tenant claim is a direct string"),
        )]),
    )
    .expect("claims verify")
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn compiled_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"request-query-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[
            {
              "id":"asset-site","primaryDataset":"test-dataset","route":"sites","mutationMode":"create_only","classification":"internal",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"name","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}
              ]
            },
            {
              "id":"asset-placement","primaryDataset":"test-dataset","route":"placements","mutationMode":"mutable","classification":"internal",
              "changeControl":{"requiredFor":["patch"]},
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"site","type":"reference","target":"asset-site","required":true,"classification":"internal"}
              ]
            },
            {
              "id":"correction-request","primaryDataset":"test-dataset","route":"correction-requests","mutationMode":"mutable","classification":"internal",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"placement","type":"reference","target":"asset-placement","required":true,"classification":"internal"},
                {"id":"proposed-site","type":"reference","target":"asset-site","required":true,"classification":"internal"},
                {"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"internal"}
              ],
              "changeRequest":{
                "effects":[{
                  "target":{"fromField":"placement"},
                  "operation":"patch",
                  "set":{"site":{"fromField":"proposed-site"}}
                }],
                "review":{"stages":[{"id":"review","approvals":1,"excludeSubmitter":true}]}
              }
            }
          ],
          "accessProfiles":[
            {
              "id":"steward","default":true,"principalClaim":"registry_principal",
              "grants":[{
                "entity":"asset-site",
                "operations":["create","get","list"],
                "readableFields":["tenant","name"],
                "writableFields":["tenant","name"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
              },{
                "entity":"asset-placement",
                "operations":["create","get","list"],
                "readableFields":["tenant","site"],
                "writableFields":["tenant","site"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "allowCount":true,
                "requestPresence":[{"requestType":"correction-request","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
              }]
            },
            {
              "id":"submitter","default":true,"principalClaim":"registry_principal",
              "grants":[{
                "entity":"correction-request",
                "operations":["create","get","list","patch","submit_request","revise_request","cancel_request"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "writableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "allowCount":true
              }]
            },
            {
              "id":"reviewer","principalClaim":"registry_principal","requiredPurposes":["review"],
              "grants":[{
                "entity":"correction-request",
                "operations":["get","list","approve_request","reject_request","request_revision"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "allowCount":true,
                "reviewStages":[{"stage":"review","targets":[{
                  "entity":"asset-placement",
                  "readableFields":["site"],
                  "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
                }]}]
              }]
            },
            {
              "id":"applier","principalClaim":"registry_principal","requiredPurposes":["apply"],
              "grants":[{
                "entity":"correction-request",
                "operations":["get","apply_request"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "applyTargets":[{
                  "entity":"asset-placement",
                  "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
                }]
              }]
            }
          ]
        }"#,
    )
    .expect("request query fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("request query fixture compiles")
}

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
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema, ExpectedManagedCatalog,
    PostgresRecordMutationService, PostgresRecordReadService, PostgresSnapshotReadService,
    RegistryLockKey, RegistryStateTestIdentity,
};
use registry_breg::request_retention::{
    RequestDetailErasureScope, RequestRetentionOperatorService,
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "request-read-retention";
const PACKAGE_REVISION: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TENANT: &str = "tenant-a";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn erased_terminal_request_get_keeps_metadata_and_scopes_result_links_to_target_get() {
    let database = TestDatabase::create(6).await;
    let registry = Arc::new(compiled_registry());
    let identity = install_registry(&database, &registry).await;
    let app = request_router(&database, registry.clone(), identity.clone());
    let operator = claims("operator", "operator-principal");
    let request_only = claims("request-only", "request-principal");

    let old_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=operator",
        operator.clone(),
        "read-retention-old-site",
        json!({"tenant": TENANT, "name": "old"}),
    )
    .await;
    let new_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=operator",
        operator.clone(),
        "read-retention-new-site",
        json!({"tenant": TENANT, "name": "new"}),
    )
    .await;
    let placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=operator",
        operator.clone(),
        "read-retention-placement",
        json!({"tenant": TENANT, "site": old_site.id}),
    )
    .await;
    let request = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=operator",
        operator.clone(),
        "read-retention-request",
        json!({
            "tenant": TENANT,
            "placement": placement.id,
            "proposedSite": new_site.id,
            "reason": "erase this request detail"
        }),
    )
    .await;
    let submitted = run_action(
        &app,
        &request.id,
        "submit_request",
        "read-retention-submit",
        operator.clone(),
        |_| json!({}),
    )
    .await;
    let effect_digest = submitted["request"]["effectDigest"]
        .as_str()
        .expect("submission has effect digest")
        .to_owned();
    run_action(
        &app,
        &request.id,
        "approve_request",
        "read-retention-approve",
        operator.clone(),
        |_| json!({"proposalVersion": 1, "effectDigest": effect_digest}),
    )
    .await;
    let before_apply = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=operator",
            request.id
        ),
        operator.clone(),
    )
    .await;
    let apply_action = action(&before_apply.body, "apply_request");
    let apply_body = json!({"proposalVersion": 1, "effectDigest": effect_digest});
    let applied = send_action(
        &app,
        &apply_action,
        "read-retention-apply",
        operator.clone(),
        apply_body.clone(),
    )
    .await;
    assert_eq!(
        applied.status,
        StatusCode::OK,
        "apply_request failed with {}",
        applied.body
    );

    let visible = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=operator",
            request.id
        ),
        operator,
    )
    .await;
    assert_eq!(visible.body["data"]["request"]["bregState"], "applied");
    assert_eq!(
        visible.body["data"]["request"]["history"]["proposals"][0]["resultLinkCount"],
        1
    );
    assert_eq!(
        visible.body["data"]["request"]["history"]["proposals"][0]["resultLinks"][0]
            ["targetEntityId"],
        "placement"
    );
    assert_eq!(
        visible.body["data"]["request"]["history"]["proposals"][0]["resultLinks"][0]
            ["targetRecordId"],
        placement.id
    );

    let hidden = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=request-only",
            request.id
        ),
        request_only,
    )
    .await;
    assert_eq!(
        hidden.body["data"]["request"]["history"]["proposals"][0]["resultLinkCount"],
        0
    );
    assert_eq!(
        hidden.body["data"]["request"]["history"]["proposals"][0]["resultLinks"]
            .as_array()
            .expect("result links are an array")
            .len(),
        0,
        "request GET authority alone does not reveal application target identifiers"
    );

    let public_detail = get_record_anonymous(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=public-request",
            request.id
        ),
    )
    .await;
    assert_eq!(
        public_detail.body["data"]["request"]["bregState"],
        "applied"
    );
    assert_eq!(public_detail.body["data"]["request"]["proposalVersion"], 1);
    assert_effect_digests_withheld(&public_detail.body["data"]);

    let public_list = get_record_anonymous(
        &app,
        "/v1/records/correction-requests?accessProfile=public-request",
    )
    .await;
    let public_item = public_list.body["items"]
        .as_array()
        .expect("public list returns items")
        .iter()
        .find(|item| item["recordIdentifier"] == request.id)
        .expect("public list includes created request");
    assert_eq!(public_item["request"]["bregState"], "applied");
    assert_eq!(public_item["request"]["proposalVersion"], 1);
    assert_effect_digests_withheld(public_item);

    let retention = RequestRetentionOperatorService::new_for_test(
        registry.as_ref().clone(),
        identity,
        ExpectedManagedCatalog::compiled(&registry),
        RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives"),
        database.migration_config.clone(),
        database.migration_role.clone(),
        database.runtime_role.clone(),
        AuditProfile::production_from_secret_bytes(vec![0x8b; 32].into())
            .expect("test audit profile is keyed"),
    );
    retention
        .erase(RequestDetailErasureScope {
            request_entity_id: "correction-request",
            request_id: Uuid::parse_str(&request.id).expect("request id parses"),
            proposal_version: 1,
        })
        .await
        .expect("terminal request detail erases through the verified operator boundary");

    let erased = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=operator",
            request.id
        ),
        claims("operator", "operator-principal"),
    )
    .await;
    assert_eq!(erased.body["data"]["request"]["bregState"], "applied");
    assert_eq!(erased.body["data"]["request"]["detailErased"], true);
    assert_eq!(erased.body["data"]["domainData"], json!({}));
    assert_eq!(
        erased.body["data"]["revisionIdentifier"],
        (request.revision + 4).to_string()
    );
    assert_eq!(
        erased.body["data"]["request"]["history"]["proposals"][0]["detailErased"],
        true
    );
    assert_eq!(
        erased.body["data"]["request"]["history"]["proposals"][0]["resultLinkCount"],
        1
    );
    assert_eq!(
        erased.body["data"]["request"]["history"]["proposals"][0]["resultLinks"][0]
            ["targetRecordId"],
        placement.id
    );
    assert!(
        !erased
            .body
            .to_string()
            .contains("erase this request detail"),
        "erased intake and snapshot payloads are not reconstructed in the response"
    );

    let erased_hidden = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=request-only",
            request.id
        ),
        claims("request-only", "request-principal"),
    )
    .await;
    assert_eq!(erased_hidden.body["data"]["request"]["detailErased"], true);
    assert_eq!(
        erased_hidden.body["data"]["request"]["history"]["proposals"][0]["resultLinkCount"],
        0
    );
    assert_eq!(
        erased_hidden.body["data"]["request"]["history"]["proposals"][0]["resultLinks"]
            .as_array()
            .expect("result links are an array")
            .len(),
        0
    );

    let erased_public = get_record_anonymous(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=public-request",
            request.id
        ),
    )
    .await;
    assert_eq!(erased_public.body["data"]["request"]["detailErased"], true);
    assert_eq!(erased_public.body["data"]["domainData"], json!({}));
    assert_effect_digests_withheld(&erased_public.body["data"]);

    let same_key_replay = send_action(
        &app,
        &apply_action,
        "read-retention-apply",
        claims("operator", "operator-principal"),
        apply_body.clone(),
    )
    .await;
    assert_eq!(same_key_replay.status, StatusCode::CONFLICT);
    assert_eq!(same_key_replay.body["code"], "idempotency.conflict");

    let new_key_replay = send_action(
        &app,
        &apply_action,
        "read-retention-apply-erased",
        claims("operator", "operator-principal"),
        apply_body.clone(),
    )
    .await;
    assert_eq!(new_key_replay.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(new_key_replay.body["code"], "precondition.failed");

    let empty_history = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=operator&requestHistoryAfterProposalVersion=1",
            request.id
        ),
        claims("operator", "operator-principal"),
    )
    .await;
    assert_eq!(
        empty_history.body["data"]["request"]["history"],
        Value::Null,
        "continuing after the only proposal returns no retained-history page"
    );
    assert_not_found(
        &app,
        "/v1/records/correction-requests/00000000-0000-4000-8000-000000000099?accessProfile=operator",
        claims("operator", "operator-principal"),
    )
    .await;
    assert_not_found(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=operator",
            request.id
        ),
        claims_with_tenant("operator", "other-tenant-principal", "tenant-b"),
    )
    .await;
    assert_bad_query(
        &app,
        &format!(
            "/v1/records/placements/{}?accessProfile=operator&requestHistoryAfterProposalVersion=1",
            placement.id
        ),
        claims("operator", "operator-principal"),
    )
    .await;
    assert_bad_query(
        &app,
        "/v1/records/correction-requests?accessProfile=operator&requestHistoryAfterProposalVersion=1",
        claims("operator", "operator-principal"),
    )
    .await;

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_reads_exclude_soft_erased_request_revisions() {
    let database = TestDatabase::create(6).await;
    let registry = Arc::new(compiled_registry());
    let identity = install_registry(&database, &registry).await;
    let app = request_router(&database, registry.clone(), identity.clone());
    let operator = claims("operator", "operator-principal");
    let reader = claims("snapshot-reader", "snapshot-principal");

    let old_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=operator",
        operator.clone(),
        "snapshot-erasure-old-site",
        json!({"tenant": TENANT, "name": "old"}),
    )
    .await;
    let new_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=operator",
        operator.clone(),
        "snapshot-erasure-new-site",
        json!({"tenant": TENANT, "name": "new"}),
    )
    .await;
    let placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=operator",
        operator.clone(),
        "snapshot-erasure-placement",
        json!({"tenant": TENANT, "site": old_site.id}),
    )
    .await;
    let request = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=operator",
        operator.clone(),
        "snapshot-erasure-request",
        json!({
            "tenant": TENANT,
            "placement": placement.id,
            "proposedSite": new_site.id,
            "reason": "erase this request detail"
        }),
    )
    .await;
    let submitted = run_action(
        &app,
        &request.id,
        "submit_request",
        "snapshot-erasure-submit",
        operator.clone(),
        |_| json!({}),
    )
    .await;
    let effect_digest = submitted["request"]["effectDigest"]
        .as_str()
        .expect("submission has effect digest")
        .to_owned();
    run_action(
        &app,
        &request.id,
        "approve_request",
        "snapshot-erasure-approve",
        operator.clone(),
        |_| json!({"proposalVersion": 1, "effectDigest": effect_digest}),
    )
    .await;
    let before_apply = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=operator",
            request.id
        ),
        operator.clone(),
    )
    .await;
    let apply_action = action(&before_apply.body, "apply_request");
    let applied = send_action(
        &app,
        &apply_action,
        "snapshot-erasure-apply",
        operator,
        json!({"proposalVersion": 1, "effectDigest": effect_digest}),
    )
    .await;
    assert_eq!(
        applied.status,
        StatusCode::OK,
        "apply_request failed with {}",
        applied.body
    );

    let snapshot_count =
        "/v1/records/correction-requests:snapshot?accessProfile=snapshot-reader&$select=reason&$count=true";
    let snapshot_page =
        "/v1/records/correction-requests:snapshot?accessProfile=snapshot-reader&$select=reason";
    let before = response_parts(
        send(
            &app,
            Method::GET,
            snapshot_count,
            Some(reader.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(
        before.status,
        StatusCode::OK,
        "snapshot count before erasure failed with {}",
        before.body
    );
    assert_eq!(before.body["count"], 1);
    let before_items = before.body["items"]
        .as_array()
        .expect("snapshot items are an array");
    assert_eq!(before_items.len(), 1);
    assert_eq!(before_items[0]["recordIdentifier"], request.id);

    let retention = RequestRetentionOperatorService::new_for_test(
        registry.as_ref().clone(),
        identity,
        ExpectedManagedCatalog::compiled(&registry),
        RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives"),
        database.migration_config.clone(),
        database.migration_role.clone(),
        database.runtime_role.clone(),
        AuditProfile::production_from_secret_bytes(vec![0x8b; 32].into())
            .expect("test audit profile is keyed"),
    );
    retention
        .erase(RequestDetailErasureScope {
            request_entity_id: "correction-request",
            request_id: Uuid::parse_str(&request.id).expect("request id parses"),
            proposal_version: 1,
        })
        .await
        .expect("terminal request detail erases through the verified operator boundary");

    let after = response_parts(
        send(
            &app,
            Method::GET,
            snapshot_count,
            Some(reader.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(
        after.status,
        StatusCode::OK,
        "snapshot count after erasure failed with {}",
        after.body
    );
    assert_eq!(
        after.body["count"], 0,
        "soft-erased request revisions must not be counted by snapshot reads"
    );
    assert_eq!(
        after.body["items"]
            .as_array()
            .expect("snapshot items are an array")
            .len(),
        0,
        "soft-erased request revisions must not be paged by snapshot reads"
    );

    let after_page = response_parts(
        send(
            &app,
            Method::GET,
            snapshot_page,
            Some(reader),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(
        after_page.status,
        StatusCode::OK,
        "snapshot page after erasure failed with {}",
        after_page.body
    );
    assert!(
        !after_page
            .body
            .to_string()
            .contains("erase this request detail"),
        "soft-erased snapshot payloads are not served by snapshot reads"
    );

    database.cleanup().await;
}

async fn install_registry(
    database: &TestDatabase,
    registry: &Arc<registry_breg::CompiledRegistry>,
) -> registry_breg::postgres::ExpectedRegistryIdentity {
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, registry, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: "request-read-retention-instance",
            database_id: "request-read-retention-database",
            package_revision: PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("active package identity initializes");
    drop(migration);
    migration_task.abort();
    identity
}

fn request_router(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
) -> axum::Router {
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let audit = AuditProfile::production_from_secret_bytes(vec![0x8b; 32].into())
        .expect("test audit profile is keyed");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x37; 32]), Duration::from_secs(300))
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
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
    ));
    let snapshots = Arc::new(PostgresSnapshotReadService::new(
        pool,
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit,
        cursors.clone(),
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
        .with_postgres_mutations(mutations)
        .with_snapshots(snapshots),
    ))
}

#[derive(Clone)]
struct CreatedRecord {
    id: String,
    revision: u64,
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
    assert_eq!(
        response.status,
        StatusCode::CREATED,
        "create {uri} failed with {}",
        response.body
    );
    CreatedRecord {
        id: response.body["data"]["recordIdentifier"]
            .as_str()
            .expect("created response has id")
            .to_owned(),
        revision: response.body["data"]["revisionIdentifier"]
            .as_str()
            .and_then(|revision| revision.parse().ok())
            .expect("created response has revision"),
    }
}

async fn get_record(app: &axum::Router, uri: &str, claims: VerifiedRequestClaims) -> ResponseParts {
    let response =
        response_parts(send(app, Method::GET, uri, Some(claims), &[], Vec::new()).await).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "GET {uri} failed with {}",
        response.body
    );
    response
}

async fn get_record_anonymous(app: &axum::Router, uri: &str) -> ResponseParts {
    let response = response_parts(send(app, Method::GET, uri, None, &[], Vec::new()).await).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "anonymous GET {uri} failed with {}",
        response.body
    );
    response
}

fn assert_effect_digests_withheld(record: &Value) {
    assert!(record["request"].get("effectDigest").is_none());
    assert!(record["request"]["application"]
        .get("effectDigest")
        .is_none());
    let proposal = &record["request"]["history"]["proposals"][0];
    assert!(proposal.get("effectDigest").is_none());
    assert_eq!(proposal["resultLinkCount"], 0);
    assert_eq!(
        proposal["resultLinks"]
            .as_array()
            .expect("public result links are an array")
            .len(),
        0
    );
}

async fn assert_not_found(app: &axum::Router, uri: &str, claims: VerifiedRequestClaims) {
    let response =
        response_parts(send(app, Method::GET, uri, Some(claims), &[], Vec::new()).await).await;
    assert_eq!(
        response.status,
        StatusCode::NOT_FOUND,
        "GET {uri} should be concealed, got {}",
        response.body
    );
    assert_eq!(response.body["code"], "resource.not_found");
}

async fn assert_bad_query(app: &axum::Router, uri: &str, claims: VerifiedRequestClaims) {
    let response =
        response_parts(send(app, Method::GET, uri, Some(claims), &[], Vec::new()).await).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "GET {uri} should reject the query, got {}",
        response.body
    );
    assert_eq!(response.body["code"], "query.invalid");
}

async fn send_action(
    app: &axum::Router,
    action: &RequestAction,
    key: &str,
    claims: VerifiedRequestClaims,
    body: Value,
) -> ResponseParts {
    response_parts(
        send(
            app,
            Method::POST,
            &action.href,
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", key),
                ("if-match", &action.if_match),
            ],
            serde_json::to_vec(&body).expect("action body serializes"),
        )
        .await,
    )
    .await
}

async fn run_action(
    app: &axum::Router,
    request_id: &str,
    operation: &str,
    key: &str,
    claims: VerifiedRequestClaims,
    body: impl FnOnce(&RequestAction) -> Value,
) -> Value {
    let before = get_record(
        app,
        &format!("/v1/records/correction-requests/{request_id}?accessProfile=operator"),
        claims.clone(),
    )
    .await;
    let action = action(&before.body, operation);
    let response = send_action(app, &action, key, claims, body(&action)).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "action {operation} failed with {}",
        response.body
    );
    response.body
}

struct RequestAction {
    href: String,
    if_match: String,
}

fn action(body: &Value, operation: &str) -> RequestAction {
    let actions = body["data"]["request"]["actions"]
        .as_array()
        .expect("request read exposes actions");
    let action = actions
        .iter()
        .find(|action| action["operation"] == operation)
        .unwrap_or_else(|| panic!("missing {operation} in {actions:?}"));
    RequestAction {
        href: action["href"].as_str().expect("action has href").to_owned(),
        if_match: action["ifMatch"]
            .as_str()
            .expect("action has precondition")
            .to_owned(),
    }
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    headers: &[(&str, &str)],
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
}

async fn response_parts(response: axum::response::Response) -> ResponseParts {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body is bounded")
        .to_vec();
    ResponseParts {
        status,
        body: serde_json::from_slice(&bytes).expect("response body is JSON"),
    }
}

fn claims(_profile: &str, principal: &str) -> VerifiedRequestClaims {
    claims_with_tenant(_profile, principal, TENANT)
}

fn claims_with_tenant(_profile: &str, principal: &str, tenant: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        BTreeSet::new(),
        None,
        BTreeMap::from([(
            "tenant_claim".to_owned(),
            VerifiedClaimValue::direct_string(tenant).expect("tenant claim"),
        )]),
    )
    .expect("claims are verified")
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"request-read-retention","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[
            {
              "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"create_only","classification":"internal",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"name","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}
              ]
            },
            {
              "id":"placement","primaryDataset":"test-dataset","route":"placements","mutationMode":"mutable","classification":"internal",
              "changeControl":{"requiredFor":["patch"]},
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"site","type":"reference","target":"site","required":true,"classification":"internal"}
              ]
            },
            {
              "id":"correction-request","primaryDataset":"test-dataset","route":"correction-requests","mutationMode":"mutable","classification":"public",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"public"},
                {"id":"placement","type":"reference","target":"placement","required":true,"classification":"public"},
                {"id":"proposed-site","type":"reference","target":"site","required":true,"classification":"public"},
                {"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"public"}
              ],
              "changeRequest":{
                "retention":{"mode":"operator_erase"},
                "effects":[{
                  "target":{"fromField":"placement"},
                  "operation":"patch",
                  "set":{"site":{"fromField":"proposed-site"}}
                }],
                "review":{"stages":[{"id":"review","approvals":1}]}
              }
            }
          ],
          "accessProfiles":[
            {
              "id":"operator","default":true,"principalClaim":"registry_principal",
              "grants":[{
                "entity":"site",
                "operations":["create","get","list"],
                "readableFields":["tenant","name"],
                "writableFields":["tenant","name"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
              },{
                "entity":"placement",
                "operations":["create","get","list"],
                "readableFields":["tenant","site"],
                "writableFields":["tenant","site"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
              },{
                "entity":"correction-request",
                "operations":["create","get","list","patch","submit_request","approve_request","apply_request"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "writableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "reviewStages":[{"stage":"review","targets":[{
                  "entity":"placement",
                  "readableFields":["site"],
                  "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
                }]}],
                "applyTargets":[{"entity":"placement","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
              }]
            },
            {
              "id":"request-only","principalClaim":"registry_principal",
              "grants":[{
                "entity":"correction-request",
                "operations":["get"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
              }]
            },
            {
              "id":"public-request","anonymous":true,
              "grants":[{
                "entity":"correction-request",
                "operations":["get","list"],
                "readableFields":["tenant","placement","proposed-site","reason"]
              }]
            },
            {
              "id":"snapshot-reader","principalClaim":"registry_principal",
              "grants":[{
                "entity":"correction-request",
                "operations":["snapshot"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "allowCount":true
              }]
            }
          ]
        }"#,
    )
    .expect("request read retention fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("request read retention fixture compiles")
}

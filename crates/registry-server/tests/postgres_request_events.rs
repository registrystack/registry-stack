// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use postgres_harness::TestDatabase;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::parse_json_strict;
use registry_server::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::contract::{EventConditionSource, EventSource, EventTrigger};
use registry_server::cursor::CursorCodec;
use registry_server::event_destination::ActivatedEventDestinationRegistry;
use registry_server::mutation::install_mutation_schema;
use registry_server::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema, ExpectedRegistryIdentity,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_server::request_events::{insert_request_lifecycle_events, RequestLifecycleEvent};
use registry_server::runtime_config::parse_runtime_config;
use registry_server::webhook::{WebhookDeliveryService, WebhookWorkOutcome};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex, Notify};
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const REQUEST_ENTITY: &str = "placement-correction-request";
const TARGET_ENTITY: &str = "asset-placement";
const PACKAGE_ID: &str = "request-event-registry";
const INSTANCE_ID: &str = "request-event-instance";
const DATABASE_ID: &str = "request-event-database";
const PACKAGE_REVISION: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SCHEMA_FINGERPRINT: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DESTINATION_ID: &str = "review-operations";
const DELIVERY_PATH: &str = "/request-events";
const HMAC_KEY: &[u8] = b"request-event-webhook-signing-key-0123456789abcdef";
const KEY_REF: &str = "request-event-signing-key";
const CA_REF: &str = "request-event-ca";
const TENANT: &str = "tenant-a";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_request_lifecycle_events_are_transactional_and_stably_deduplicated() {
    load_postgres_env();
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    install_mutation_schema(&migration, &database.runtime_role)
        .await
        .expect("mutation and outbox schema installs");

    let request_id = Uuid::new_v4();
    let events = configured_events();
    let mut values = Map::new();
    values.insert("reason".to_owned(), json!("correct the recorded site"));

    let rolled_back = migration.transaction().await.expect("transaction starts");
    insert_request_lifecycle_events(
        &rolled_back,
        &events,
        &[],
        None,
        lifecycle_event(
            request_id,
            2,
            1,
            2,
            "draft",
            "submitted",
            "submit",
            None,
            &values,
        ),
    )
    .await
    .expect("request lifecycle event inserts inside transaction");
    rolled_back
        .rollback()
        .await
        .expect("transaction rolls back");
    assert_eq!(
        outbox_count(&migration).await,
        0,
        "lifecycle events are not visible when the transition rolls back"
    );

    let filtered = migration.transaction().await.expect("transaction starts");
    insert_request_lifecycle_events(
        &filtered,
        &events,
        &[],
        None,
        lifecycle_event(
            request_id,
            2,
            1,
            2,
            "draft",
            "submitted",
            "submit",
            None,
            &values,
        ),
    )
    .await
    .expect("nonmatching lifecycle condition skips notification");
    filtered.commit().await.expect("transaction commits");
    assert_eq!(
        outbox_count(&migration).await,
        0,
        "closed lifecycle conditions filter notifications without creating state"
    );

    let committed = migration.transaction().await.expect("transaction starts");
    for _ in 0..2 {
        insert_request_lifecycle_events(
            &committed,
            &events,
            &[],
            None,
            lifecycle_event(
                request_id,
                3,
                1,
                3,
                "submitted",
                "approved",
                "approve",
                Some("review"),
                &values,
            ),
        )
        .await
        .expect("duplicate lifecycle capture is idempotent");
    }
    committed.commit().await.expect("transaction commits");

    let rows = migration
        .query(
            "SELECT event_id, event_type, trigger, entity_id, record_revision,
                    convert_from(payload, 'UTF8')
             FROM registry_internal.registry_outbox
             ORDER BY outbox_id",
            &[],
        )
        .await
        .expect("outbox rows read");
    assert_eq!(rows.len(), 1, "request/version/stage identity deduplicates");
    assert_eq!(rows[0].get::<_, String>(1), "approval-ready");
    assert_eq!(rows[0].get::<_, String>(2), "request_lifecycle");
    assert_eq!(rows[0].get::<_, String>(3), REQUEST_ENTITY);
    assert_eq!(rows[0].get::<_, i64>(4), 3);

    let payload_text = rows[0].get::<_, String>(5);
    let payload = parse_json_strict(payload_text.as_bytes()).expect("payload is strict JSON");
    assert_eq!(payload["trigger"], "request_lifecycle");
    assert_eq!(payload["recordId"], request_id.to_string());
    assert_eq!(payload["revision"], 3);
    assert_eq!(payload["request"]["proposalVersion"], 1);
    assert_eq!(payload["request"]["workflowRevision"], 3);
    assert_eq!(payload["request"]["transition"], "approve");
    assert_eq!(payload["request"]["fromState"], "submitted");
    assert_eq!(payload["request"]["toState"], "approved");
    assert_eq!(payload["request"]["stage"], "review");
    assert_eq!(payload["request"]["effectDigest"], Value::Null);
    assert!(payload["request"]["deduplicationKey"]
        .as_str()
        .is_some_and(|value| value.starts_with("sha256:")));
    assert_eq!(
        payload["values"],
        json!({"reason":"correct the recorded site"})
    );
    assert_eq!(
        migration
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_outbox
                 WHERE entity_id = $1",
                &[&TARGET_ENTITY],
            )
            .await
            .expect("target outbox count reads")
            .get::<_, i64>(0),
        0,
        "request lifecycle capture does not create canonical target events before application"
    );

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn real_postgres_request_lifecycle_webhook_retries_and_operator_replay_keep_payload_dedup_key(
) {
    load_postgres_env();
    let receiver = HttpsReceiver::start().await;
    let database = TestDatabase::create(8).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let compiled = compiled_lifecycle_registry();
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled lifecycle event schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("active registry identity initializes");

    let fixture = DestinationFixture::new(&receiver);
    let destinations = Arc::new(fixture.activate(&compiled));
    let delivery = compiled
        .event_deliveries()
        .deliveries
        .iter()
        .find(|delivery| delivery.event_id == "request-approved")
        .expect("compiled lifecycle delivery exists")
        .clone();
    let mut values = Map::new();
    values.insert("reason".to_owned(), json!("external review completed"));
    let request_id = Uuid::new_v4();
    let transaction = migration.transaction().await.expect("transaction starts");
    insert_request_lifecycle_events(
        &transaction,
        &compiled.entities()[REQUEST_ENTITY].events,
        &compiled.event_deliveries().deliveries,
        Some(&destinations),
        lifecycle_event(
            request_id,
            3,
            1,
            3,
            "submitted",
            "approved",
            "approve",
            Some("review"),
            &values,
        ),
    )
    .await
    .expect("lifecycle event and webhook delivery insert together");
    transaction.commit().await.expect("event commits");
    migration_task.abort();

    let captured = capture_event(&database).await;
    assert_eq!(captured.compiled_delivery_id, delivery.id);
    let payload = parse_json_strict(&captured.payload).expect("payload is strict JSON");
    let dedup_key = payload["request"]["deduplicationKey"]
        .as_str()
        .expect("payload carries consumer deduplication key")
        .to_owned();
    assert_eq!(payload["trigger"], "request_lifecycle");
    assert_eq!(payload["request"]["transition"], "approve");

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let service = WebhookDeliveryService::new(
        pool,
        Arc::clone(&destinations),
        identity,
        RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives"),
        Duration::from_secs(2),
        AuditProfile::production_from_secret_bytes(vec![0x7c; 32].into())
            .expect("test audit profile is keyed"),
    );

    receiver.enqueue(ResponsePlan::Status(500)).await;
    receiver.enqueue(ResponsePlan::Status(500)).await;
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::RetryScheduled)
    );
    receiver.wait_for_count(1).await;
    tokio::time::sleep(Duration::from_millis(1_020)).await;
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::DeadLettered)
    );
    receiver.wait_for_count(2).await;

    let first = receiver.request(0).await;
    let second = receiver.request(1).await;
    assert_lifecycle_delivery_request(&first, &captured, 1);
    assert_lifecycle_delivery_request(&second, &captured, 1);
    assert_eq!(
        first.body, second.body,
        "delivery retry preserves payload bytes"
    );
    assert_eq!(
        first.headers.get("idempotency-key"),
        second.headers.get("idempotency-key"),
        "delivery retry for the same generation keeps the delivery key"
    );
    assert_eq!(
        parse_json_strict(&first.body).expect("first body parses")["request"]["deduplicationKey"],
        dedup_key
    );

    let next_generation = service
        .replay(captured.event_id, &captured.compiled_delivery_id, 1)
        .await
        .expect("operator replay is available for retained dead letters");
    assert_eq!(next_generation, 2);
    receiver.enqueue(ResponsePlan::Status(204)).await;
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered)
    );
    receiver.wait_for_count(3).await;
    let replay = receiver.request(2).await;
    assert_lifecycle_delivery_request(&replay, &captured, 2);
    assert_eq!(
        replay.body, first.body,
        "operator replay preserves payload bytes"
    );
    assert_ne!(
        replay.headers.get("idempotency-key"),
        first.headers.get("idempotency-key"),
        "operator replay uses a new delivery key even though the consumer dedup key is stable"
    );
    assert_eq!(
        parse_json_strict(&replay.body).expect("replay body parses")["request"]["deduplicationKey"],
        dedup_key
    );

    receiver.stop().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_webhook_service_event_material_does_not_grant_request_action_authority() {
    load_postgres_env();
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(compiled_lifecycle_registry());
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("compiled lifecycle authority schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("active registry identity initializes");
    migration_task.abort();

    let app = event_authority_router(&database, Arc::clone(&registry), identity);
    let steward = api_claims("steward-principal", None);
    let site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "authority-site",
        json!({"tenant": TENANT, "name": "Warehouse A"}),
    )
    .await;
    let placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=steward",
        steward.clone(),
        "authority-placement",
        json!({"tenant": TENANT, "site": site.id}),
    )
    .await;
    let proposed_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward,
        "authority-proposed-site",
        json!({"tenant": TENANT, "name": "Warehouse B"}),
    )
    .await;
    let request = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=submitter",
        api_claims("submitter-principal", None),
        "authority-request",
        json!({
            "tenant": TENANT,
            "placement": placement.id,
            "proposedSite": proposed_site.id,
            "reason": "external receiver wants this transition"
        }),
    )
    .await;
    let service_claims = api_claims("webhook-service-principal", Some("webhook"));
    let service_view = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=service",
            request.id
        ),
        service_claims.clone(),
    )
    .await;
    assert_eq!(service_view.status, StatusCode::OK);
    assert!(
        service_view.body["request"]["actions"]
            .as_array()
            .is_none_or(|actions| actions.is_empty()),
        "service read profile must not receive request action links"
    );

    let response = response_parts(
        send(
            &app,
            Method::POST,
            &format!(
                "/v1/records/correction-requests/{}/actions/stages/review/approve?accessProfile=service",
                request.id
            ),
            Some(service_claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "event-callback-authority-attempt"),
                ("if-match", &request.etag),
                ("ce-id", "00000000-0000-4000-8000-000000000001"),
                ("ce-type", "request-approved"),
                ("x-registry-signature", "sha256=fakesignature"),
                ("x-registry-event-generation", "7"),
            ],
            serde_json::to_vec(&json!({
                "proposalVersion": 1,
                "stage": "review",
                "effectDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "callbackGranted": true,
                "deduplicationKey": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            }))
            .expect("event-like callback body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::NOT_FOUND,
        "webhook service event material must not select an unauthorized request action: {}",
        response.body
    );
    assert_eq!(response.body["code"], "resource.not_found");

    let submitter_view = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=submitter",
            request.id
        ),
        api_claims("submitter-principal", None),
    )
    .await;
    assert_eq!(submitter_view.body["request"]["serverState"], "draft");
    assert_eq!(
        outbox_count(&database.admin).await,
        0,
        "refused callback-shaped action does not author lifecycle outbox state"
    );

    database.cleanup().await;
}

fn configured_events() -> BTreeMap<String, EventSource> {
    let event = EventSource {
        id: "approval-ready".to_owned(),
        trigger: EventTrigger::RequestLifecycle,
        projection: BTreeSet::from(["reason".to_owned()]),
        when: Some(EventConditionSource::RequestLifecycle {
            transitions: BTreeSet::from(["approve".to_owned()]),
            to_states: BTreeSet::from(["approved".to_owned()]),
            stages: BTreeSet::from(["review".to_owned()]),
        }),
        webhook: None,
    };
    BTreeMap::from([(event.id.clone(), event)])
}

fn compiled_lifecycle_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"request-event-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"asset-site","primaryDataset":"test-dataset","route":"sites","mutationMode":"create_only","classification":"internal",
            "fields":[
              {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
              {"id":"name","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}
            ]
          },{
            "id":"asset-placement","primaryDataset":"test-dataset","route":"placements","mutationMode":"mutable","classification":"internal",
            "changeControl":{"requiredFor":["patch"]},
            "fields":[
              {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
              {"id":"site","type":"reference","target":"asset-site","required":true,"classification":"internal"}
            ]
          },{
            "id":"placement-correction-request","primaryDataset":"test-dataset","route":"correction-requests","mutationMode":"mutable","classification":"internal",
            "fields":[
              {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
              {"id":"placement","type":"reference","target":"asset-placement","required":true,"classification":"internal"},
              {"id":"proposed-site","type":"reference","target":"asset-site","required":true,"classification":"internal"},
              {"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"internal"}
            ],
            "events":[{
              "id":"request-approved",
              "trigger":"request_lifecycle",
              "projection":["reason"],
              "when":{
                "kind":"request_lifecycle",
                "transitions":["approve"],
                "toStates":["approved"],
                "stages":["review"]
              },
              "webhook":{"destinationId":"review-operations"}
            }],
            "changeRequest":{
              "effects":[{
                "target":{"fromField":"placement"},
                "operation":"patch",
                "set":{"site":{"fromField":"proposed-site"}}
              }],
              "review":{"stages":[{"id":"review","approvals":1,"excludeSubmitter":true}]}
            }
          }],
          "accessProfiles":[{
            "id":"steward","principalClaim":"registry_principal","grants":[{
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
              "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
            }]
          },{
            "id":"submitter","default":true,"principalClaim":"registry_principal","grants":[{
              "entity":"placement-correction-request",
              "operations":["create","get","list","patch","submit_request","revise_request","cancel_request"],
              "readableFields":["tenant","placement","proposed-site","reason"],
              "writableFields":["tenant","placement","proposed-site","reason"],
              "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
            }]
          },{
            "id":"reviewer","principalClaim":"registry_principal","requiredPurposes":["review"],"grants":[{
              "entity":"placement-correction-request",
              "operations":["get","list","approve_request","reject_request","request_revision"],
              "readableFields":["tenant","placement","proposed-site","reason"],
              "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
              "reviewStages":[{
                "stage":"review",
                "targets":[{"entity":"asset-placement","readableFields":["site"],"rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
              }]
            }]
          },{
            "id":"service","principalClaim":"registry_principal","requiredPurposes":["webhook"],"grants":[{
              "entity":"placement-correction-request",
              "operations":["get","list"],
              "readableFields":["tenant","placement","proposed-site","reason"],
              "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
            }]
          },{
            "id":"applier","principalClaim":"registry_principal","requiredPurposes":["apply"],"grants":[{
              "entity":"placement-correction-request",
              "operations":["get","apply_request"],
              "readableFields":["tenant","placement","proposed-site","reason"],
              "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
              "applyTargets":[{"entity":"asset-placement","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
            }]
          }]
        }"#,
    )
    .expect("lifecycle event fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("lifecycle event fixture compiles")
}

struct CapturedEvent {
    event_id: Uuid,
    compiled_delivery_id: String,
    payload: Vec<u8>,
    data_schema: String,
}

async fn capture_event(database: &TestDatabase) -> CapturedEvent {
    let row = database
        .admin
        .query_one(
            "SELECT outbox.event_id, delivery.compiled_delivery_id,
                    outbox.payload, delivery.data_schema
             FROM registry_internal.registry_outbox AS outbox
             JOIN registry_internal.registry_webhook_deliveries AS delivery
               ON delivery.event_id = outbox.event_id
             ORDER BY outbox.outbox_id DESC
             LIMIT 1",
            &[],
        )
        .await
        .expect("captured lifecycle event reads");
    CapturedEvent {
        event_id: row.get(0),
        compiled_delivery_id: row.get(1),
        payload: row.get(2),
        data_schema: row.get(3),
    }
}

fn assert_lifecycle_delivery_request(
    request: &ReceivedRequest,
    event: &CapturedEvent,
    generation: i64,
) {
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, DELIVERY_PATH);
    assert_eq!(request.body, event.payload);
    assert_eq!(header(request, "ce-id"), event.event_id.to_string());
    assert_eq!(header(request, "ce-specversion"), "1.0");
    assert_eq!(
        header(request, "ce-source"),
        "urn:registrystack:registry:request-event-registry:instance:request-event-instance"
    );
    assert_eq!(header(request, "ce-type"), "request-approved");
    assert_eq!(header(request, "ce-dataschema"), event.data_schema);
    assert_eq!(
        header(request, "x-registry-event-generation"),
        generation.to_string()
    );
    assert_eq!(header(request, "content-type"), "application/json");
    assert!(request.headers.contains_key("x-registry-signature"));
    assert!(request.headers.contains_key("idempotency-key"));
}

fn header<'a>(request: &'a ReceivedRequest, name: &str) -> &'a str {
    request
        .headers
        .get(name)
        .map(String::as_str)
        .expect("closed webhook header exists")
}

#[allow(clippy::too_many_arguments)] // Keep lifecycle identity, state, and captured values explicit.
fn lifecycle_event<'a>(
    request_id: Uuid,
    request_record_revision: i64,
    proposal_version: u32,
    workflow_revision: u64,
    from_state: &'a str,
    to_state: &'a str,
    transition: &'a str,
    stage_id: Option<&'a str>,
    request_values: &'a Map<String, Value>,
) -> RequestLifecycleEvent<'a> {
    RequestLifecycleEvent {
        request_entity_id: REQUEST_ENTITY,
        request_id,
        request_record_reference: "request-reference",
        request_record_revision,
        proposal_version,
        workflow_revision,
        from_state,
        to_state,
        transition,
        stage_id,
        effect_digest: None,
        package_revision: PACKAGE_REVISION,
        schema_fingerprint: SCHEMA_FINGERPRINT,
        request_values,
        payload_retention: Duration::from_secs(7 * 24 * 60 * 60),
    }
}

fn event_authority_router(
    database: &TestDatabase,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
) -> axum::Router {
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let audit = AuditProfile::production_from_secret_bytes(vec![0x9a; 32].into())
        .expect("test audit profile is keyed");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x49; 32]), Duration::from_secs(300))
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
    etag: String,
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
        "create {uri} failed with body {}",
        response.body
    );
    let id = response.body["id"]
        .as_str()
        .expect("created response includes id")
        .to_owned();
    assert!(Uuid::parse_str(&id).is_ok_and(|uuid| uuid.to_string() == id));
    assert_eq!(response.body["revision"], 1);
    assert!(response.etag.starts_with("\"rs-"));
    CreatedRecord {
        id,
        etag: response.etag,
    }
}

async fn get_record(app: &axum::Router, uri: &str, claims: VerifiedRequestClaims) -> ResponseParts {
    let response =
        response_parts(send(app, Method::GET, uri, Some(claims), &[], Vec::new()).await).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "get {uri} failed with body {}",
        response.body
    );
    response
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
    etag: String,
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
        etag: headers
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
    }
}

fn api_claims(principal: &str, purpose: Option<&str>) -> VerifiedRequestClaims {
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
    .expect("test claims are verified")
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

struct DestinationFixture {
    root: PathBuf,
    secret_root: PathBuf,
    package_root: PathBuf,
    trust_anchor: PathBuf,
    receiver_port: u16,
}

impl DestinationFixture {
    fn new(receiver: &HttpsReceiver) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("temporary parent canonicalizes")
            .join(format!(
                "registry-server-request-events-{suffix}-{}",
                std::process::id()
            ));
        let secret_root = root.join("secrets");
        let package_root = root.join("package");
        fs::create_dir_all(&secret_root).expect("secret root creates");
        fs::create_dir(&package_root).expect("package root creates");
        let trust_anchor = root.join("trust-anchor.json");
        fs::write(&trust_anchor, "{}").expect("trust anchor placeholder writes");
        write_secret(&secret_root.join(KEY_REF), HMAC_KEY);
        write_secret(
            &secret_root.join(CA_REF),
            receiver.certificate_pem.as_bytes(),
        );
        Self {
            root,
            secret_root,
            package_root,
            trust_anchor,
            receiver_port: receiver.address.port(),
        }
    }

    fn activate(
        &self,
        compiled: &registry_server::CompiledRegistry,
    ) -> ActivatedEventDestinationRegistry {
        let raw = format!(
            r#"apiVersion: registry.registrystack.org/server-runtime/v1alpha1
kind: RegistryServerRuntimeConfig
listener:
  bind: 127.0.0.1:8080
  trustedProxy: direct
identity:
  environment: local
  instanceId: {INSTANCE_ID}
  databaseId: {DATABASE_ID}
  databaseInitializationEnvironment: local
secretProviders:
  file:
    root: {}
database:
  runtimeUrlRef: secret:file/database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 8
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: registry_migration
    runtime: registry_runtime
package:
  root: {}
  trustAnchorPath: {}
  compilerSourceRevision: source-revision-1
  activeRevision: {PACKAGE_REVISION}
  activeSequence: 1
authentication:
  oidc:
    issuer: https://issuer.example
    audience: urn:registry-server:request-events
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [registry-client]
    deniedKids: [denied-kid]
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 900
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
audit:
  hashKeyRef: secret:file/audit-key
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
eventDestinations:
  {DESTINATION_ID}:
    origin: https://localhost:{}/
    path: {DELIVERY_PATH}
    networkProfile: pinnedLoopbackHttpsTest
    dnsFamily: ipv4Only
    allowedPrivateCidrs: []
    hmacSha256KeyRef: secret:file/{KEY_REF}
    classificationCeiling: internal
    tls:
      caBundleRef: secret:file/{CA_REF}
    deliveryCeilings:
      attemptTimeoutMilliseconds: 100
      maximumAttempts: 2
operationalTimeouts:
  httpRequestMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
  recordLockMilliseconds: 5000
  migrationLockMilliseconds: 30000
  migrationStatementMilliseconds: 60000
"#,
            self.secret_root.display(),
            self.package_root.display(),
            self.trust_anchor.display(),
            self.receiver_port,
        );
        parse_runtime_config(&raw)
            .expect("strict pinned-loopback HTTPS config parses")
            .activate_event_destinations(compiled)
            .expect("exact lifecycle destination activates")
    }
}

impl Drop for DestinationFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write_secret(path: &std::path::Path, value: &[u8]) {
    fs::write(path, value).expect("test secret writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("test secret permissions set");
    }
}

#[derive(Clone)]
enum ResponsePlan {
    Status(u16),
}

#[derive(Clone)]
struct ReceivedRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct HttpsReceiver {
    address: std::net::SocketAddr,
    certificate_pem: String,
    plans: Arc<Mutex<VecDeque<ResponsePlan>>>,
    requests: Arc<Mutex<Vec<ReceivedRequest>>>,
    notify: Arc<Notify>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl HttpsReceiver {
    async fn start() -> Self {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".to_owned()])
                .expect("loopback TLS certificate generates");
        let certificate_der = cert.der().clone();
        let certificate_pem = pem("CERTIFICATE", certificate_der.as_ref());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key)
            .expect("loopback TLS server configuration builds");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback TLS receiver binds");
        let address = listener
            .local_addr()
            .expect("receiver address is available");
        let plans = Arc::new(Mutex::new(VecDeque::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let task_plans = Arc::clone(&plans);
        let task_requests = Arc::clone(&requests);
        let task_notify = Arc::clone(&notify);
        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = &mut shutdown_rx => return,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, _)) = accepted else {
                    return;
                };
                let acceptor = acceptor.clone();
                let plans = Arc::clone(&task_plans);
                let requests = Arc::clone(&task_requests);
                let notify = Arc::clone(&task_notify);
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let Ok(request) = read_request(&mut stream).await else {
                        return;
                    };
                    requests.lock().await.push(request);
                    notify.notify_waiters();
                    let ResponsePlan::Status(status) = plans
                        .lock()
                        .await
                        .pop_front()
                        .unwrap_or(ResponsePlan::Status(204));
                    let reason = if status == 204 {
                        "No Content"
                    } else {
                        "Server Error"
                    };
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            address,
            certificate_pem,
            plans,
            requests,
            notify,
            shutdown: Some(shutdown_tx),
            task,
        }
    }

    async fn enqueue(&self, plan: ResponsePlan) {
        self.plans.lock().await.push_back(plan);
    }

    async fn request(&self, index: usize) -> ReceivedRequest {
        self.requests
            .lock()
            .await
            .get(index)
            .cloned()
            .expect("requested receiver observation exists")
    }

    async fn wait_for_count(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.requests.lock().await.len() < expected {
                self.notify.notified().await;
            }
        })
        .await
        .expect("receiver observes the expected request count");
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }
}

async fn read_request<S>(stream: &mut S) -> Result<ReceivedRequest, ()>
where
    S: AsyncReadExt + Unpin,
{
    let mut bytes = Vec::with_capacity(2_048);
    let header_end = loop {
        let mut chunk = [0_u8; 1_024];
        let read = stream.read(&mut chunk).await.map_err(|_| ())?;
        if read == 0 || bytes.len() + read > 2_097_152 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end]).map_err(|_| ())?;
    let mut lines = header_text.split("\r\n");
    let mut request_line = lines.next().ok_or(())?.split_whitespace();
    let method = request_line.next().ok_or(())?.to_owned();
    let target = request_line.next().ok_or(())?.to_owned();
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(())?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let content_length = headers
        .get("content-length")
        .ok_or(())?
        .parse::<usize>()
        .map_err(|_| ())?;
    while bytes.len() - header_end < content_length {
        let mut chunk = [0_u8; 1_024];
        let read = stream.read(&mut chunk).await.map_err(|_| ())?;
        if read == 0 || bytes.len() + read > 2_097_152 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(ReceivedRequest {
        method,
        target,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is UTF-8"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

async fn outbox_count(client: &tokio_postgres::Client) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_outbox",
            &[],
        )
        .await
        .expect("outbox count reads")
        .get(0)
}

fn load_postgres_env() {
    if env::var_os("REGISTRY_SERVER_TEST_DATABASE_URL").is_some() {
        return;
    }
    let Ok(contents) = std::fs::read_to_string("/private/tmp/registry-cr-plain-gqgr39oa/test.env")
    else {
        return;
    };
    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "REGISTRY_SERVER_TEST_DATABASE_URL" {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('\'')
            .and_then(|value| value.strip_suffix('\''))
            .or_else(|| {
                value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
            })
            .unwrap_or(value);
        env::set_var("REGISTRY_SERVER_TEST_DATABASE_URL", value);
        return;
    }
}

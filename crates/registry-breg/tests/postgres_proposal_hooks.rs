// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "postgres-test")]
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/proposal_hooks_model.rs"]
mod model;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use registry_breg::{
    api::VerifiedRequestClaims,
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_json, ModuleAssetSource},
    event_destination::ActivatedEventDestinationRegistry,
    hook_handler::HookHandlerRegistry,
    postgres::{PostgresRecordMutationService, RegistryLockKey},
    webhook::{WebhookDeliveryService, WebhookWorkOutcome},
};
use registry_breg_client::{
    BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
    BRegProblemCode, BRegProposal, BRegRecordFormat, BaseRegistryClient,
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

const NONE: &[u8] = b"fn handle(ctx) { #{answer: \"none\"} }";
const CANDIDATE: &[u8]=b"fn handle(ctx) { #{answer: \"proposal\", document: #{action: \"correct-name\", input: #{}, outcome: #{}}} }";
fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).unwrap()
}
fn claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "sub",
        "raw-actor-canary",
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::new(),
    )
    .unwrap()
}
fn compile(source: Value, scripts: &[(&str, &[u8])]) -> registry_breg::CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let assets = scripts
        .iter()
        .map(|(id, bytes)| ModuleAssetSource {
            module: None,
            path: format!("hooks/{id}.rhai"),
            bytes: bytes.to_vec(),
        })
        .collect::<Vec<_>>();
    compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring).unwrap()
}
fn runtime(
    registry: &registry_breg::CompiledRegistry,
    port: Option<u16>,
) -> (tempfile::TempDir, Arc<ActivatedEventDestinationRegistry>) {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key_path = root.path().join("observer-key");
    std::fs::write(&key_path, [7u8; 32]).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut config = include_str!("../../../products/breg/examples/minimal/runtime.yaml")
        .replace("/var/lib/breg/secrets", root.path().to_str().unwrap())
        .replace("environment: example", "environment: local")
        .replace(
            "databaseInitializationEnvironment: example",
            "databaseInitializationEnvironment: local",
        );
    if let Some(port) = port {
        config.push_str(&format!("\neventDestinations:\n  observer:\n    origin: http://127.0.0.1:{port}/\n    path: /events\n    networkProfile: loopback-development-http\n    dnsFamily: dual-stack-strict\n    allowedPrivateCidrs: []\n    hmacSha256KeyRef: secret:file/observer-key\n    classificationCeiling: internal\n    deliveryCeilings:\n      attemptTimeoutMilliseconds: 1000\n      maximumAttempts: 2\n"));
    }
    let destinations = registry_breg::runtime_config::parse_runtime_config(&config)
        .unwrap()
        .activate_event_destinations(registry)
        .unwrap();
    (root, Arc::new(destinations))
}
fn audit() -> registry_breg::audit::RegistryAudit {
    registry_breg::audit::test_support::capturing(
        AuditProfile::production_from_secret_bytes(vec![0x61; 32].into()).unwrap(),
    )
    .0
}
fn service(
    fixture: &client_http::ClientFixture,
    destinations: Arc<ActivatedEventDestinationRegistry>,
) -> WebhookDeliveryService {
    WebhookDeliveryService::new(
        fixture.pool.clone(),
        destinations,
        Arc::new(HookHandlerRegistry::new(
            &fixture.registry,
            &fixture.identity.activation_id,
        )),
        fixture.registry.clone(),
        fixture.identity.clone(),
        "client-capability-test",
        RegistryLockKey::derive(fixture.registry.registry_id()).unwrap(),
        Duration::from_secs(2),
        audit(),
    )
}
async fn with_destinations(
    fixture: &client_http::ClientFixture,
    destinations: Arc<ActivatedEventDestinationRegistry>,
) -> client_http::ClientHttp {
    let mutations = PostgresRecordMutationService::new_with_event_destinations(
        fixture.pool.clone(),
        fixture.registry.clone(),
        fixture.identity.clone(),
        "client-capability-test",
        RegistryLockKey::derive(fixture.registry.registry_id()).unwrap(),
        Duration::from_secs(2),
        audit(),
        Some(destinations),
    );
    fixture.client_with_mutations(claims(), mutations).await
}
async fn start(client: &BaseRegistryClient) -> BRegProposal {
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create")
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(json!({"name":"before-canary"}).as_object().unwrap().clone())
                .unwrap(),
            &key("record"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        json!({"target":record.value.data.record_identifier,"value":"input-context-canary"})
            .as_object()
            .unwrap()
            .clone(),
        None,
    )
    .unwrap();
    let first = client
        .start_proposal(&action, &input, &key("start"))
        .await
        .unwrap()
        .value;
    let replay = client
        .start_proposal(&action, &input, &key("start"))
        .await
        .unwrap()
        .value;
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(replay).unwrap()
    );
    first
}
async fn lifecycle(
    client: &BaseRegistryClient,
    proposal: &BRegProposal,
    operation: &str,
) -> BRegProposal {
    let attempt = client
        .prepare_proposal(proposal, operation, json!({}), &key(operation))
        .unwrap();
    let result = client.execute_proposal(&attempt).await.unwrap().value;
    assert_eq!(
        serde_json::to_value(&result).unwrap(),
        serde_json::to_value(client.execute_proposal(&attempt).await.unwrap().value).unwrap()
    );
    result
}
async fn count(fixture: &client_http::ClientFixture, table: &str) -> i64 {
    fixture
        .database
        .admin
        .query_one(
            &format!("SELECT count(*) FROM registry_internal.{table}"),
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_observers_capture_filter_fanout_replay_and_private_values_atomically() {
    let registry = compile(
        model::source(json!([
            model::local_hook("all", json!([])),
            model::local_hook("submitted", json!(["submitted"]))
        ])),
        &[("all", NONE), ("submitted", NONE)],
    );
    let (_root, destinations) = runtime(&registry, None);
    let fixture = client_http::ClientFixture::start(registry, claims()).await;
    let client = &fixture.http.client;
    let draft = start(client).await;
    assert_eq!(count(&fixture, "registry_outbox").await, 1);
    assert_eq!(count(&fixture, "registry_webhook_deliveries").await, 1);
    let uploaded = client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"attachment-bytes-canary",
            &key("attachment"),
        )
        .await
        .unwrap()
        .value;
    let submitted = lifecycle(client, &uploaded, "submit").await;
    lifecycle(client, &submitted, "cancel").await;
    // Upload is an authorized draft Edit and emits the same value-free event.
    assert_eq!(count(&fixture, "registry_outbox").await, 4);
    assert_eq!(count(&fixture, "registry_webhook_deliveries").await, 5);
    let rows=fixture.database.admin.query("SELECT event_type,payload,record_revision FROM registry_internal.registry_outbox ORDER BY outbox_id",&[]).await.unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>(),
        [
            "proposal.started",
            "proposal.edited",
            "proposal.submitted",
            "proposal.cancelled"
        ]
    );
    for row in &rows {
        let bytes = row.get::<_, Vec<u8>>(1);
        let text = std::str::from_utf8(&bytes).unwrap();
        for canary in [
            "before-canary",
            "input-context-canary",
            "attachment-bytes-canary",
            "raw-actor-canary",
        ] {
            assert!(!text.contains(canary), "event retained {canary}");
        }
        let envelope = registry_platform_hooks::HookEnvelope::from_canonical_bytes(
            &bytes,
            &registry_platform_hooks::EnvelopeLimits::default(),
        )
        .unwrap();
        assert_eq!(envelope.subject.record_revision, row.get::<_, i64>(2));
        assert_eq!(envelope.data.as_object().unwrap().len(), 11);
    }
    let service = service(&fixture, destinations);
    for _ in 0..5 {
        assert_eq!(
            service.deliver_once().await,
            Ok(WebhookWorkOutcome::Delivered)
        );
    }
    assert_eq!(service.deliver_once().await, Ok(WebhookWorkOutcome::Idle));
    assert_eq!(
        fixture
            .database
            .admin
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_outbox WHERE payload IS NOT NULL",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(count(&fixture, "registry_proposal_applications").await, 0);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unbound_native_destination_rolls_back_the_proposal_and_outbox() {
    let mut hook = model::url_hook();
    hook["transitions"] = json!(["started"]);
    let fixture =
        client_http::ClientFixture::start(compile(model::source(json!([hook])), &[]), claims())
            .await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create")
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(json!({"name":"before"}).as_object().unwrap().clone()).unwrap(),
            &key("record"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        json!({"target":record.value.data.record_identifier,"value":"after"})
            .as_object()
            .unwrap()
            .clone(),
        None,
    )
    .unwrap();
    assert_eq!(
        client
            .start_proposal(&action, &input, &key("start"))
            .await
            .unwrap_err()
            .problem_code(),
        Some(BRegProblemCode::ServiceUnavailable)
    );
    for table in [
        "registry_proposal_state",
        "registry_outbox",
        "registry_webhook_deliveries",
        "registry_webhook_delivery_state",
    ] {
        assert_eq!(count(&fixture, table).await, 0, "{table}");
    }
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_url_delivery_keeps_exact_bytes_tightened_budgets_and_expired_lease_recovery() {
    use axum::{
        body::Bytes,
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
    };
    type Received = Arc<tokio::sync::Mutex<Vec<(HeaderMap, Vec<u8>)>>>;
    async fn receive(
        State(received): State<Received>,
        headers: HeaderMap,
        body: Bytes,
    ) -> StatusCode {
        received.lock().await.push((headers, body.to_vec()));
        StatusCode::NO_CONTENT
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received: Received = Arc::default();
    let app = axum::Router::new()
        .route("/events", post(receive))
        .with_state(received.clone());
    let receiver = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let registry = compile(model::source(json!([model::url_hook()])), &[]);
    let (_root, destinations) = runtime(&registry, Some(port));
    let fixture = client_http::ClientFixture::start(registry, claims()).await;
    let http = with_destinations(&fixture, destinations.clone()).await;
    let draft = start(&http.client).await;
    lifecycle(&http.client, &draft, "submit").await;
    let captured=fixture.database.admin.query_one("SELECT o.payload,d.attempt_timeout_ms,d.deployed_attempt_timeout_ms,d.maximum_attempts,d.deployed_maximum_attempts FROM registry_internal.registry_webhook_deliveries d JOIN registry_internal.registry_outbox o USING(event_id)",&[]).await.unwrap();
    let bytes = captured.get::<_, Vec<u8>>(0);
    assert_eq!(captured.get::<_, i64>(1), 5000);
    assert_eq!(captured.get::<_, i64>(2), 1000);
    assert_eq!(captured.get::<_, i16>(3), 5);
    assert_eq!(captured.get::<_, i16>(4), 2);
    fixture.database.admin.execute("UPDATE registry_internal.registry_webhook_delivery_state SET state='leased',attempt=1,next_attempt_at=NULL,attempt_started_at=transaction_timestamp()-interval '10 seconds',lease_expires_at=transaction_timestamp()-interval '5 seconds',lease_token=gen_random_uuid()",&[]).await.unwrap();
    let service = service(&fixture, destinations);
    // Expired lease recovery is durable before retrying the exact event.
    assert_eq!(service.deliver_once().await, Ok(WebhookWorkOutcome::Idle));
    fixture.database.admin.execute("UPDATE registry_internal.registry_webhook_delivery_state SET next_attempt_at=transaction_timestamp()-interval '1 second' WHERE state='pending'",&[]).await.unwrap();
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered)
    );
    let requests = received.lock().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1, bytes);
    assert_eq!(requests[0].0["ce-type"], "proposal.submitted");
    assert_eq!(
        requests[0].0["ce-dataschema"],
        registry_breg::proposal_hooks::PROPOSAL_EVENT_SCHEMA
    );
    assert_eq!(requests[0].0["x-registry-delivery-attempt"], "2");
    assert!(requests[0].0["x-registry-signature"]
        .to_str()
        .unwrap()
        .starts_with("v1="));
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&[7u8; 32]).unwrap();
    mac.update(b"breg-webhook-signature-v1");
    for value in [
        "ce-specversion",
        "ce-id",
        "ce-source",
        "ce-type",
        "ce-time",
        "ce-dataschema",
        "x-registry-event-generation",
        "x-registry-delivery-attempt",
        "x-registry-delivery-time",
    ]
    .into_iter()
    .map(|name| requests[0].0[name].as_bytes())
    .chain([
        b"POST".as_slice(),
        b"/events".as_slice(),
        b"application/json".as_slice(),
        requests[0].0["idempotency-key"].as_bytes(),
        requests[0].1.as_slice(),
    ]) {
        mac.update(&(value.len() as u64).to_be_bytes());
        mac.update(value);
    }
    assert_eq!(
        requests[0].0["x-registry-signature"].to_str().unwrap(),
        format!("v1={}", URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    );
    drop(requests);
    drop(http);
    receiver.abort();
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_observers_refuse_callback_candidates_before_action_grant_lookup() {
    let registry = compile(
        model::source(json!([model::local_hook("candidate", json!(["started"]))])),
        &[("candidate", CANDIDATE)],
    );
    let (_root, destinations) = runtime(&registry, None);
    let fixture = client_http::ClientFixture::start(registry, claims()).await;
    start(&fixture.http.client).await;
    let service = service(&fixture, destinations);
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::DeadLettered)
    );
    let code: String = fixture
        .database
        .admin
        .query_one(
            "SELECT proposal_code FROM registry_internal.registry_webhook_delivery_state",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(code, "hook.proposal.observer_only");
    assert_eq!(count(&fixture, "registry_proposal_state").await, 1);
    assert_eq!(count(&fixture, "registry_proposal_applications").await, 0);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_observer_candidates_have_no_application_authority_even_under_a_forged_owner() {
    let mut source = model::source(json!([model::local_hook("candidate", json!(["started"]))]));
    source["recordTypes"][0]["hooks"] = json!([{"id":"record-candidate","phase":"after","trigger":"created","projection":["name"],"principal":"clerk","handler":{"type":"rhai","script":"hooks/candidate.rhai","abi":"registry.hook-handler/v1"}}]);
    let registry = compile(source, &[("candidate", CANDIDATE)]);
    let (_root, destinations) = runtime(&registry, None);
    let fixture = client_http::ClientFixture::start(registry, claims()).await;
    let draft = start(&fixture.http.client).await;
    let native_id = "events.proposals.correct-name.candidate.webhook";
    let forged_id = "events.target.record-candidate.webhook";
    // The migrated outbox contract remains native even if an adversarial row
    // substitutes a compiled Record owner with a proposing principal.
    fixture.database.admin.execute("INSERT INTO registry_internal.registry_webhook_deliveries SELECT (jsonb_populate_record(NULL::registry_internal.registry_webhook_deliveries,to_jsonb(d)||jsonb_build_object('compiled_delivery_id',$2::text))).* FROM registry_internal.registry_webhook_deliveries d WHERE compiled_delivery_id=$1",&[&native_id,&forged_id]).await.unwrap();
    fixture.database.admin.execute("INSERT INTO registry_internal.registry_webhook_delivery_state SELECT (jsonb_populate_record(NULL::registry_internal.registry_webhook_delivery_state,to_jsonb(s)||jsonb_build_object('compiled_delivery_id',$2::text))).* FROM registry_internal.registry_webhook_delivery_state s WHERE compiled_delivery_id=$1",&[&native_id,&forged_id]).await.unwrap();
    fixture.database.admin.execute("DELETE FROM registry_internal.registry_webhook_delivery_state WHERE compiled_delivery_id=$1",&[&native_id]).await.unwrap();
    fixture.database.admin.execute("DELETE FROM registry_internal.registry_webhook_deliveries WHERE compiled_delivery_id=$1",&[&native_id]).await.unwrap();
    let service = service(&fixture, destinations);
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered)
    );
    let ordinary=fixture.database.admin.query_one("SELECT s.proposal_disposition,s.proposal_code FROM registry_internal.registry_webhook_delivery_state s JOIN registry_internal.registry_outbox o USING(event_id) WHERE o.event_type='record-candidate'",&[]).await.unwrap();
    assert_eq!(ordinary.get::<_, String>(0), "refused");
    assert_eq!(
        ordinary.get::<_, String>(1),
        "hook.proposal.action_without_handler"
    );
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::DeadLettered)
    );
    let row=fixture.database.admin.query_one("SELECT s.proposal_code FROM registry_internal.registry_webhook_delivery_state s JOIN registry_internal.registry_outbox o USING(event_id) WHERE o.event_type='proposal.started'",&[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "hook.proposal.observer_only");
    assert_eq!(count(&fixture, "registry_proposal_state").await, 1);
    assert_eq!(count(&fixture, "registry_proposal_applications").await, 0);
    assert_eq!(
        fixture
            .http
            .client
            .read_proposal(&draft)
            .await
            .unwrap()
            .value
            .state(),
        registry_breg_client::BRegProposalState::Draft
    );
    fixture.finish().await;
}

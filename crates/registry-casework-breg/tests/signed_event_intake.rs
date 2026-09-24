// SPDX-License-Identifier: Apache-2.0
#![recursion_limit = "256"]

mod support;

use std::sync::Arc;

use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig, StaticToken};
use registry_casework_breg::{BregAdapter, BregRequestConfig, BregSourceConfig};
use registry_casework_core::{
    EventRequest, RoutingSourceMetadata, SourceAdapter, SourceAdapterError,
};
use registry_platform_crypto::delivery_signature::{sign_v1, SignatureFields};
use registry_platform_hooks::{Causation, EnvelopeLimits, EventSubject, HookEnvelope};
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use wiremock::{
    matchers::{header, method, path, query_param, query_param_is_missing},
    Mock, MockServer, ResponseTemplate,
};

const KEY: &[u8] = b"casework-webhook-signing-key-0123456789abcdef";
const RECORD_ID: &str = "00000000-0000-4000-8000-000000000001";
const EVENT_SOURCE_A: &str = "urn:registrystack:registry:test:instance:source-a";
const EVENT_SOURCE_B: &str = "urn:registrystack:registry:test:instance:source-b";
const EVENT_TYPE: &str = "casework-lifecycle-v1";
const VALUES_CANARY: &str = "VALUES-MUST-DIE-WITH-INTAKE";
const REASON_CANARY: &str = "REASON-MUST-DIE-WITH-INTAKE";
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const REGISTRY_REVISION: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const EVENT_ID: &str = "00000000-0000-4000-8000-000000000099";
const EVENT_TIME: &str = "2026-09-10T01:00:00Z";
const DATA_SCHEMA: &str =
    "urn:registrystack:registry:test:event:casework-lifecycle-v1:schema:sha256:aaa";
const RECORD_REFERENCE: &str =
    "hmac-sha256:00000000000000000000000000000000000000000000000000000000000000aa";

fn adapter(source_id: &str, event_source: &str, event_type: &str) -> BregAdapter {
    adapter_at(source_id, event_source, event_type, "http://127.0.0.1:9")
}

fn adapter_at(
    source_id: &str,
    event_source: &str,
    event_type: &str,
    base_url: &str,
) -> BregAdapter {
    BregAdapter::new(
        BregSourceConfig {
            source_id: source_id.to_owned(),
            requests: vec![BregRequestConfig {
                entity: "correction".to_owned(),
                route: "corrections".to_owned(),
                routing_metadata: RoutingSourceMetadata {
                    stages: vec![],
                    fields: vec![],
                },
                context_projection: Vec::new(),
                display_reference: None,
            }],
            expected_registry_revision: REGISTRY_REVISION.to_owned(),
            binding_generation: "generation-1".to_owned(),
            reader_profile: "reader".to_owned(),
            event_source: event_source.to_owned(),
            event_type: event_type.to_owned(),
        },
        BaseRegistryClient::new(
            BaseRegistryClientConfig::new(base_url.parse().unwrap())
                .with_token_provider(Arc::new(StaticToken::new("reader-token").unwrap())),
        )
        .unwrap(),
        KEY.to_vec(),
    )
    .unwrap()
}

fn record(record_id: &str, entity: &str) -> Value {
    json!({
        "data": {
            "recordIdentifier": record_id,
            "revisionIdentifier": "2",
            "domainData": {},
            "request": {
                "bregState": "submitted",
                "proposalVersion": 1,
                "effectDigest": REGISTRY_REVISION,
                "proposal": {
                    "review": {
                        "authority": "casework-main",
                        "policyId": "registry-correction"
                    }
                },
                "editable": false,
                "actions": []
            }
        },
        "meta": {
            "registryIdentifier": "test",
            "datasetIdentifier": "primary",
            "entityTypeIdentifier": entity
        }
    })
}

fn response(value: Value, entity: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(value)
        .insert_header("traceparent", TRACEPARENT)
        .insert_header("etag", "\"breg-record-2\"")
        .insert_header("cache-control", "no-store")
        .insert_header(
            "link",
            format!(
                "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/{entity}>; rel=\"describedby\""
            ),
        )
}

fn collection_response(value: Value, entity: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(value)
        .insert_header("traceparent", TRACEPARENT)
        .insert_header("cache-control", "no-store")
        .insert_header(
            "link",
            format!(
                "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/{entity}>; rel=\"describedby\""
            ),
        )
}

async fn mount_metadata(server: &MockServer, revision: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/registry"))
        .and(header("authorization", "Bearer reader-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(support::lifecycle_metadata(revision))
                .insert_header("traceparent", TRACEPARENT),
        )
        .expect(1)
        .mount(server)
        .await;
}

/// The product projection a Base Registry Engine delivery carries as the
/// envelope's `data`.
fn data(deduplication_key: &str) -> Value {
    json!({
        "trigger": "request_lifecycle",
        "entity": "correction",
        "recordId": RECORD_ID,
        "revision": 42,
        "values": {"private": VALUES_CANARY},
        "request": {
            "deduplicationKey": deduplication_key,
            "reason": REASON_CANARY
        }
    })
}

/// The canonical envelope bytes the delivery body is.
fn envelope_body(event_source: &str, event_type: &str, data: Value) -> Vec<u8> {
    envelope(event_source, event_type, data)
        .to_canonical_bytes(&EnvelopeLimits::default())
        .unwrap()
}

/// The canonical envelope a delivery body is.
fn envelope(event_source: &str, event_type: &str, data: Value) -> HookEnvelope {
    HookEnvelope {
        id: EVENT_ID.to_owned(),
        event_type: event_type.to_owned(),
        source: event_source.to_owned(),
        time: OffsetDateTime::parse(EVENT_TIME, &Rfc3339).unwrap(),
        subject: EventSubject {
            record_reference: RECORD_REFERENCE.to_owned(),
            record_revision: 42,
        },
        dataschema: DATA_SCHEMA.to_owned(),
        data,
        causation: Causation::root(EVENT_ID),
    }
}

fn signed_request(
    source_id: &str,
    event_source: &str,
    event_type: &str,
    delivery_time: &str,
    data: Value,
) -> EventRequest {
    signed_bytes(
        source_id,
        event_source,
        event_type,
        delivery_time,
        envelope_body(event_source, event_type, data),
    )
}

fn signed_bytes(
    source_id: &str,
    event_source: &str,
    event_type: &str,
    delivery_time: &str,
    body: Vec<u8>,
) -> EventRequest {
    let request_target = format!("/events/sources/{source_id}");
    let fields = SignatureFields {
        id: EVENT_ID,
        source: event_source,
        event_type,
        time: EVENT_TIME,
        data_schema: DATA_SCHEMA,
        generation: "1",
        attempt: "1",
        delivery_time,
        method: "POST",
        request_target: &request_target,
        content_type: "application/json",
        idempotency_key: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        body: &body,
    };
    let signature = sign_v1(KEY, fields).unwrap();
    EventRequest {
        headers: vec![
            ("ce-id".into(), fields.id.into()),
            ("ce-specversion".into(), "1.0".into()),
            ("ce-source".into(), event_source.into()),
            ("ce-type".into(), event_type.into()),
            ("ce-time".into(), fields.time.into()),
            ("ce-dataschema".into(), fields.data_schema.into()),
            ("x-registry-event-generation".into(), "1".into()),
            ("x-registry-delivery-attempt".into(), "1".into()),
            ("x-registry-delivery-time".into(), delivery_time.into()),
            ("content-type".into(), "application/json".into()),
            ("idempotency-key".into(), fields.idempotency_key.into()),
            ("x-registry-signature".into(), signature),
        ],
        body,
    }
}

fn now() -> String {
    OffsetDateTime::now_utc().format(&Rfc3339).unwrap()
}

#[tokio::test]
async fn signed_transition_returns_only_source_qualified_invalidation_metadata() {
    let first = adapter("source_a", EVENT_SOURCE_A, EVENT_TYPE)
        .verify_transition(signed_request(
            "source_a",
            EVENT_SOURCE_A,
            EVENT_TYPE,
            &now(),
            data("deduplication-1"),
        ))
        .await
        .unwrap();
    let second = adapter("source_b", EVENT_SOURCE_B, EVENT_TYPE)
        .verify_transition(signed_request(
            "source_b",
            EVENT_SOURCE_B,
            EVENT_TYPE,
            &now(),
            data("deduplication-1"),
        ))
        .await
        .unwrap();

    assert_eq!(first.subject.source_id, "source_a");
    assert_eq!(second.subject.source_id, "source_b");
    assert_eq!(first.subject.kind, "correction");
    assert_eq!(first.subject.id, RECORD_ID);
    assert_eq!(first.ordered_revision, 42);
    assert_eq!(
        first.deduplication_key,
        ["deduplication", "-", "1"].concat()
    );
    assert_ne!(first.subject, second.subject);
    let retained = serde_json::to_string(&first).unwrap();
    assert!(!retained.contains(VALUES_CANARY));
    assert!(!retained.contains(REASON_CANARY));
}

#[tokio::test]
async fn signed_but_wrong_source_or_event_type_is_refused() {
    let receiver = adapter("source_a", EVENT_SOURCE_A, EVENT_TYPE);
    for request in [
        signed_request(
            "source_a",
            EVENT_SOURCE_B,
            EVENT_TYPE,
            &now(),
            data("deduplication-1"),
        ),
        signed_request(
            "source_a",
            EVENT_SOURCE_A,
            "another-lifecycle-v1",
            &now(),
            data("deduplication-1"),
        ),
    ] {
        assert_eq!(
            receiver.verify_transition(request).await,
            Err(SourceAdapterError::Invalid)
        );
    }
}

#[tokio::test]
async fn route_target_and_route_segment_are_closed_before_intake() {
    assert!(matches!(
        BregAdapter::new(
            BregSourceConfig {
                source_id: "source/a".into(),
                requests: vec![BregRequestConfig {
                    entity: "correction".into(),
                    route: "corrections".into(),
                    routing_metadata: RoutingSourceMetadata {
                        stages: vec![],
                        fields: vec![],
                    },
                    context_projection: Vec::new(),
                    display_reference: None,
                }],
                expected_registry_revision: REGISTRY_REVISION.into(),
                binding_generation: "generation-1".into(),
                reader_profile: "reader".into(),
                event_source: EVENT_SOURCE_A.into(),
                event_type: EVENT_TYPE.into(),
            },
            BaseRegistryClient::new(BaseRegistryClientConfig::new(
                "http://127.0.0.1:9".parse().unwrap(),
            ))
            .unwrap(),
            KEY.to_vec(),
        ),
        Err(SourceAdapterError::Invalid)
    ));

    let request = signed_request(
        "another_source",
        EVENT_SOURCE_A,
        EVENT_TYPE,
        &now(),
        data("deduplication-1"),
    );
    assert_eq!(
        adapter("source_a", EVENT_SOURCE_A, EVENT_TYPE)
            .verify_transition(request)
            .await,
        Err(SourceAdapterError::Invalid)
    );
}

#[tokio::test]
async fn case_insensitive_duplicate_signed_header_is_refused() {
    let mut request = signed_request(
        "source_a",
        EVENT_SOURCE_A,
        EVENT_TYPE,
        &now(),
        data("deduplication-1"),
    );
    request.headers.push(("CE-ID".into(), "duplicate".into()));
    assert_eq!(
        adapter("source_a", EVENT_SOURCE_A, EVENT_TYPE)
            .verify_transition(request)
            .await,
        Err(SourceAdapterError::Invalid)
    );
}

#[tokio::test]
async fn stale_delivery_and_body_tampering_are_refused() {
    let stale = (OffsetDateTime::now_utc() - Duration::minutes(10))
        .format(&Rfc3339)
        .unwrap();
    let receiver = adapter("source_a", EVENT_SOURCE_A, EVENT_TYPE);
    assert_eq!(
        receiver
            .verify_transition(signed_request(
                "source_a",
                EVENT_SOURCE_A,
                EVENT_TYPE,
                &stale,
                data("deduplication-1"),
            ))
            .await,
        Err(SourceAdapterError::Invalid)
    );

    let mut tampered = signed_request(
        "source_a",
        EVENT_SOURCE_A,
        EVENT_TYPE,
        &now(),
        data("deduplication-1"),
    );
    tampered.body = envelope_body(EVENT_SOURCE_A, EVENT_TYPE, data("attacker-substitution"));
    assert_eq!(
        receiver.verify_transition(tampered).await,
        Err(SourceAdapterError::Invalid)
    );
}

#[tokio::test]
async fn a_pre_envelope_delivery_body_is_refused() {
    let projection = serde_json::to_vec(&data("deduplication-1")).unwrap();
    let request = signed_bytes("source_a", EVENT_SOURCE_A, EVENT_TYPE, &now(), projection);
    assert_eq!(
        adapter("source_a", EVENT_SOURCE_A, EVENT_TYPE)
            .verify_transition(request)
            .await,
        Err(SourceAdapterError::Invalid),
        "the projection alone is no longer a delivery body"
    );
}

#[tokio::test]
async fn an_envelope_that_disagrees_with_its_signed_identity_is_refused() {
    let receiver = adapter("source_a", EVENT_SOURCE_A, EVENT_TYPE);
    let foreign = envelope_body(EVENT_SOURCE_B, EVENT_TYPE, data("deduplication-1"));
    assert_eq!(
        receiver
            .verify_transition(signed_bytes(
                "source_a",
                EVENT_SOURCE_A,
                EVENT_TYPE,
                &now(),
                foreign,
            ))
            .await,
        Err(SourceAdapterError::Invalid),
        "an envelope source that differs from the signed header is refused"
    );
    let wrong_type = envelope_body(
        EVENT_SOURCE_A,
        "another-lifecycle-v1",
        data("deduplication-1"),
    );
    assert_eq!(
        receiver
            .verify_transition(signed_bytes(
                "source_a",
                EVENT_SOURCE_A,
                EVENT_TYPE,
                &now(),
                wrong_type,
            ))
            .await,
        Err(SourceAdapterError::Invalid),
        "an envelope type that differs from the signed header is refused"
    );
    let wrong_id = {
        let mut envelope = envelope(EVENT_SOURCE_A, EVENT_TYPE, data("deduplication-1"));
        let id = "00000000-0000-4000-8000-000000000098";
        envelope.id = id.to_owned();
        envelope.causation = Causation::root(id);
        envelope
            .to_canonical_bytes(&EnvelopeLimits::default())
            .unwrap()
    };
    assert_eq!(
        receiver
            .verify_transition(signed_bytes(
                "source_a",
                EVENT_SOURCE_A,
                EVENT_TYPE,
                &now(),
                wrong_id,
            ))
            .await,
        Err(SourceAdapterError::Invalid),
        "an envelope id that differs from the signed header is refused"
    );
    let wrong_dataschema = {
        let mut envelope = envelope(EVENT_SOURCE_A, EVENT_TYPE, data("deduplication-1"));
        envelope.dataschema = format!("{DATA_SCHEMA}-disagreed");
        envelope
            .to_canonical_bytes(&EnvelopeLimits::default())
            .unwrap()
    };
    assert_eq!(
        receiver
            .verify_transition(signed_bytes(
                "source_a",
                EVENT_SOURCE_A,
                EVENT_TYPE,
                &now(),
                wrong_dataschema,
            ))
            .await,
        Err(SourceAdapterError::Invalid),
        "an envelope dataschema that differs from the signed header is refused"
    );
    let wrong_time = {
        let mut envelope = envelope(EVENT_SOURCE_A, EVENT_TYPE, data("deduplication-1"));
        envelope.time = OffsetDateTime::parse("2026-09-10T01:00:01Z", &Rfc3339).unwrap();
        envelope
            .to_canonical_bytes(&EnvelopeLimits::default())
            .unwrap()
    };
    assert_eq!(
        receiver
            .verify_transition(signed_bytes(
                "source_a",
                EVENT_SOURCE_A,
                EVENT_TYPE,
                &now(),
                wrong_time,
            ))
            .await,
        Err(SourceAdapterError::Invalid),
        "an envelope time that differs from the signed header is refused"
    );
}

#[tokio::test]
async fn a_non_canonical_envelope_is_refused() {
    let mut envelope: Value = serde_json::from_slice(&envelope_body(
        EVENT_SOURCE_A,
        EVENT_TYPE,
        data("deduplication-1"),
    ))
    .unwrap();
    envelope
        .as_object_mut()
        .unwrap()
        .insert("padding".to_owned(), Value::Null);
    let request = signed_bytes(
        "source_a",
        EVENT_SOURCE_A,
        EVENT_TYPE,
        &now(),
        serde_json::to_vec(&envelope).unwrap(),
    );
    assert_eq!(
        adapter("source_a", EVENT_SOURCE_A, EVENT_TYPE)
            .verify_transition(request)
            .await,
        Err(SourceAdapterError::Invalid),
        "an envelope with a member the contract does not declare is refused"
    );
}

#[tokio::test]
async fn authoritative_read_rejects_a_record_from_another_entity() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/corrections/{RECORD_ID}")))
        .and(header("authorization", "Bearer reader-token"))
        .respond_with(response(
            record(RECORD_ID, "another-entity"),
            "another-entity",
        ))
        .expect(1)
        .mount(&server)
        .await;

    let receiver = adapter_at("source_a", EVENT_SOURCE_A, EVENT_TYPE, &server.uri());
    let subject = registry_casework_core::SubjectRef {
        source_id: "source_a".into(),
        kind: "correction".into(),
        id: RECORD_ID.into(),
    };
    assert_eq!(
        receiver.read_authoritative(&subject).await,
        Err(SourceAdapterError::BindingMoved)
    );
}

#[tokio::test]
async fn discovery_rejects_a_non_uuid_record_identifier() {
    let server = MockServer::start().await;
    mount_metadata(&server, REGISTRY_REVISION).await;
    let invalid = "not-a-uuid";
    let item = record(invalid, "correction")["data"].clone();
    Mock::given(method("GET"))
        .and(path("/v1/records/corrections"))
        .and(header("authorization", "Bearer reader-token"))
        .respond_with(collection_response(
            json!({
                "items": [item],
                "pageInfo": {"nextCursor": null},
                "meta": {
                    "registryIdentifier": "test",
                    "datasetIdentifier": "primary",
                    "entityTypeIdentifier": "correction"
                }
            }),
            "correction",
        ))
        .expect(1)
        .mount(&server)
        .await;

    let receiver = adapter_at("source_a", EVENT_SOURCE_A, EVENT_TYPE, &server.uri());
    // The maintained BReg client rejects the identifier before the adapter's
    // defense-in-depth SubjectRef validation, so its protocol failure maps to
    // source unavailability. Either way, no malformed subject is returned.
    assert_eq!(
        receiver.discover_active(None, 50).await,
        Err(SourceAdapterError::Unavailable)
    );
}

const SECOND_RECORD_ID: &str = "00000000-0000-4000-8000-000000000002";

fn request_config(entity: &str, route: &str) -> BregRequestConfig {
    BregRequestConfig {
        entity: entity.to_owned(),
        route: route.to_owned(),
        routing_metadata: RoutingSourceMetadata {
            stages: vec![],
            fields: vec![],
        },
        context_projection: Vec::new(),
        display_reference: None,
    }
}

/// One source whose registry carries two request entities.
fn two_entity_adapter(base_url: &str) -> BregAdapter {
    BregAdapter::new(
        BregSourceConfig {
            source_id: "source_a".to_owned(),
            requests: vec![
                request_config("correction", "corrections"),
                request_config("renewal", "renewals"),
            ],
            expected_registry_revision: REGISTRY_REVISION.to_owned(),
            binding_generation: "generation-1".to_owned(),
            reader_profile: "reader".to_owned(),
            event_source: EVENT_SOURCE_A.to_owned(),
            event_type: EVENT_TYPE.to_owned(),
        },
        BaseRegistryClient::new(
            BaseRegistryClientConfig::new(base_url.parse().unwrap())
                .with_token_provider(Arc::new(StaticToken::new("reader-token").unwrap())),
        )
        .unwrap(),
        KEY.to_vec(),
    )
    .unwrap()
}

async fn mount_metadata_times(server: &MockServer, times: u64) {
    Mock::given(method("GET"))
        .and(path("/v1/registry"))
        .and(header("authorization", "Bearer reader-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(support::lifecycle_metadata(REGISTRY_REVISION))
                .insert_header("traceparent", TRACEPARENT),
        )
        .expect(times)
        .mount(server)
        .await;
}

fn listing(record_ids: &[&str], entity: &str, next: Option<&str>) -> ResponseTemplate {
    collection_response(
        json!({
            "items": record_ids
                .iter()
                .map(|id| record(id, entity)["data"].clone())
                .collect::<Vec<_>>(),
            "pageInfo": {"nextCursor": next},
            "meta": {
                "registryIdentifier": "test",
                "datasetIdentifier": "primary",
                "entityTypeIdentifier": entity
            }
        }),
        entity,
    )
}

async fn mount_listing(
    server: &MockServer,
    route: &str,
    skiptoken: Option<&str>,
    response: ResponseTemplate,
) {
    let mock = Mock::given(method("GET"))
        .and(path(format!("/v1/records/{route}")))
        .and(header("authorization", "Bearer reader-token"));
    match skiptoken {
        Some(token) => mock.and(query_param("$skiptoken", token)),
        None => mock.and(query_param_is_missing("$skiptoken")),
    }
    .respond_with(response)
    .expect(1)
    .mount(server)
    .await;
}

#[tokio::test]
async fn a_signed_transition_names_whichever_configured_request_entity_it_carries() {
    let receiver = two_entity_adapter("http://127.0.0.1:9");
    let mut renewal = data("deduplication-1");
    renewal["entity"] = json!("renewal");
    let hint = receiver
        .verify_transition(signed_request(
            "source_a",
            EVENT_SOURCE_A,
            EVENT_TYPE,
            &now(),
            renewal,
        ))
        .await
        .unwrap();
    assert_eq!(hint.subject.kind, "renewal");

    let mut unconfigured = data("deduplication-1");
    unconfigured["entity"] = json!("licence");
    assert_eq!(
        receiver
            .verify_transition(signed_request(
                "source_a",
                EVENT_SOURCE_A,
                EVENT_TYPE,
                &now(),
                unconfigured,
            ))
            .await,
        Err(SourceAdapterError::Invalid)
    );
}

#[tokio::test]
async fn an_authoritative_read_uses_the_route_of_the_subject_request_entity() {
    let server = MockServer::start().await;
    mount_metadata(&server, REGISTRY_REVISION).await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/renewals/{RECORD_ID}")))
        .and(header("authorization", "Bearer reader-token"))
        .respond_with(response(record(RECORD_ID, "renewal"), "renewal"))
        .expect(1)
        .mount(&server)
        .await;
    let subject = registry_casework_core::SubjectRef {
        source_id: "source_a".into(),
        kind: "renewal".into(),
        id: RECORD_ID.into(),
    };
    let observation = two_entity_adapter(&server.uri())
        .read_authoritative(&subject)
        .await
        .unwrap();
    assert_eq!(observation.subject.kind, "renewal");

    let unconfigured = registry_casework_core::SubjectRef {
        kind: "licence".into(),
        ..subject
    };
    assert_eq!(
        two_entity_adapter(&server.uri())
            .read_authoritative(&unconfigured)
            .await,
        Err(SourceAdapterError::Invalid)
    );
}

#[tokio::test]
async fn discovery_pages_through_every_request_entity_in_order() {
    let server = MockServer::start().await;
    mount_metadata_times(&server, 2).await;
    mount_listing(
        &server,
        "corrections",
        None,
        listing(&[RECORD_ID], "correction", Some("next-token")),
    )
    .await;
    mount_listing(
        &server,
        "corrections",
        Some("next-token"),
        listing(&[], "correction", None),
    )
    .await;
    mount_listing(
        &server,
        "renewals",
        None,
        listing(&[SECOND_RECORD_ID], "renewal", None),
    )
    .await;
    let adapter = two_entity_adapter(&server.uri());

    let first = adapter.discover_active(None, 50).await.unwrap();
    assert_eq!(first.subjects.len(), 1);
    assert_eq!(first.subjects[0].kind, "correction");
    assert_eq!(first.subjects[0].id, RECORD_ID);
    let cursor = first.next_cursor.expect("the correction listing continues");

    // The correction listing's last page is empty, so the same call moves on
    // to the renewal listing instead of returning an empty page.
    let second = adapter.discover_active(Some(&cursor), 50).await.unwrap();
    assert_eq!(second.subjects.len(), 1);
    assert_eq!(second.subjects[0].kind, "renewal");
    assert_eq!(second.subjects[0].id, SECOND_RECORD_ID);
    assert!(second.next_cursor.is_none());
}

#[tokio::test]
async fn discovery_moves_to_the_next_request_entity_when_a_listing_ends() {
    let server = MockServer::start().await;
    mount_metadata_times(&server, 2).await;
    mount_listing(
        &server,
        "corrections",
        None,
        listing(&[RECORD_ID], "correction", None),
    )
    .await;
    mount_listing(
        &server,
        "renewals",
        None,
        listing(&[SECOND_RECORD_ID], "renewal", None),
    )
    .await;
    let adapter = two_entity_adapter(&server.uri());

    let first = adapter.discover_active(None, 50).await.unwrap();
    assert_eq!(first.subjects[0].kind, "correction");
    let cursor = first
        .next_cursor
        .expect("the renewal listing is still to read");
    let second = adapter.discover_active(Some(&cursor), 50).await.unwrap();
    assert_eq!(second.subjects[0].kind, "renewal");
    assert!(second.next_cursor.is_none());
}

#[tokio::test]
async fn a_discovery_cursor_naming_an_unconfigured_request_entity_is_refused() {
    let server = MockServer::start().await;
    mount_metadata_times(&server, 1).await;
    let cursor = registry_casework_core::DiscoveryCursor(
        json!({"entity": "licence", "continuation": null}).to_string(),
    );
    assert_eq!(
        two_entity_adapter(&server.uri())
            .discover_active(Some(&cursor), 50)
            .await,
        Err(SourceAdapterError::Invalid)
    );
}

#[test]
fn routing_metadata_is_scoped_to_one_request_entity() {
    let adapter = two_entity_adapter("http://127.0.0.1:9");
    assert!(adapter.routing_metadata("correction").is_some());
    assert!(adapter.routing_metadata("renewal").is_some());
    assert!(adapter.routing_metadata("licence").is_none());
}

#[test]
fn an_adapter_with_no_or_duplicate_request_entities_is_refused() {
    let base = || {
        BaseRegistryClient::new(
            BaseRegistryClientConfig::new("http://127.0.0.1:9".parse().unwrap())
                .with_token_provider(Arc::new(StaticToken::new("reader-token").unwrap())),
        )
        .unwrap()
    };
    let config = |requests| BregSourceConfig {
        source_id: "source_a".to_owned(),
        requests,
        expected_registry_revision: REGISTRY_REVISION.to_owned(),
        binding_generation: "generation-1".to_owned(),
        reader_profile: "reader".to_owned(),
        event_source: EVENT_SOURCE_A.to_owned(),
        event_type: EVENT_TYPE.to_owned(),
    };
    assert!(BregAdapter::new(config(Vec::new()), base(), KEY.to_vec()).is_err());
    assert!(BregAdapter::new(
        config(vec![
            request_config("correction", "corrections"),
            request_config("correction", "renewals"),
        ]),
        base(),
        KEY.to_vec(),
    )
    .is_err());
    assert!(BregAdapter::new(
        config(vec![
            request_config("correction", "corrections"),
            request_config("renewal", "corrections"),
        ]),
        base(),
        KEY.to_vec(),
    )
    .is_err());
}

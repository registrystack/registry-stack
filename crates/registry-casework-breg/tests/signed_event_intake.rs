// SPDX-License-Identifier: Apache-2.0
#![recursion_limit = "256"]

mod support;

use std::sync::Arc;

use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig, StaticToken};
use registry_casework_breg::{BregAdapter, BregReviewStage, BregSourceConfig};
use registry_casework_core::{
    EventRequest, RoutingSourceMetadata, SourceAdapter, SourceAdapterError,
};
use registry_platform_crypto::breg_webhook::{sign_v1, SignatureFields};
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use wiremock::{
    matchers::{header, method, path},
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
            entity: "correction".to_owned(),
            route: "corrections".to_owned(),
            stages: vec![BregReviewStage {
                id: "review".to_owned(),
                approvals: 1,
                exclude_submitter: false,
                exclude_previous_reviewers: false,
            }],
            routing_metadata: RoutingSourceMetadata {
                stages: vec!["review".into()],
                fields: vec![],
            },
            display_reference: None,
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
                "editable": false,
                "actions": [],
                "decisions": []
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

fn body(deduplication_key: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "trigger": "request_lifecycle",
        "entity": "correction",
        "recordId": RECORD_ID,
        "revision": 42,
        "values": {"private": VALUES_CANARY},
        "request": {
            "deduplicationKey": deduplication_key,
            "reason": REASON_CANARY
        }
    }))
    .unwrap()
}

fn signed_request(
    source_id: &str,
    event_source: &str,
    event_type: &str,
    delivery_time: &str,
    body: Vec<u8>,
) -> EventRequest {
    let request_target = format!("/events/sources/{source_id}");
    let fields = SignatureFields {
        id: "00000000-0000-4000-8000-000000000099",
        source: event_source,
        event_type,
        time: "2026-09-10T01:00:00Z",
        data_schema:
            "urn:registrystack:registry:test:event:casework-lifecycle-v1:schema:sha256:aaa",
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
            body("deduplication-1"),
        ))
        .await
        .unwrap();
    let second = adapter("source_b", EVENT_SOURCE_B, EVENT_TYPE)
        .verify_transition(signed_request(
            "source_b",
            EVENT_SOURCE_B,
            EVENT_TYPE,
            &now(),
            body("deduplication-1"),
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
            body("deduplication-1"),
        ),
        signed_request(
            "source_a",
            EVENT_SOURCE_A,
            "another-lifecycle-v1",
            &now(),
            body("deduplication-1"),
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
                entity: "correction".into(),
                route: "corrections".into(),
                stages: vec![BregReviewStage {
                    id: "review".into(),
                    approvals: 1,
                    exclude_submitter: false,
                    exclude_previous_reviewers: false,
                }],
                routing_metadata: RoutingSourceMetadata {
                    stages: vec!["review".into()],
                    fields: vec![],
                },
                display_reference: None,
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
        body("deduplication-1"),
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
        body("deduplication-1"),
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
                body("deduplication-1"),
            ))
            .await,
        Err(SourceAdapterError::Invalid)
    );

    let mut tampered = signed_request(
        "source_a",
        EVENT_SOURCE_A,
        EVENT_TYPE,
        &now(),
        body("deduplication-1"),
    );
    tampered.body = body("attacker-substitution");
    assert_eq!(
        receiver.verify_transition(tampered).await,
        Err(SourceAdapterError::Invalid)
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

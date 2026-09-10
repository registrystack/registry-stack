// SPDX-License-Identifier: Apache-2.0
use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig, StaticToken};
use registry_casework_breg::{BregAdapter, BregSourceConfig};
use registry_casework_core::*;
use serde_json::{json, Value};
use std::sync::Arc;
use wiremock::{
    matchers::{header, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};
const ID: &str = "00000000-0000-4000-8000-000000000001";
const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
fn adapter(base: &str) -> BregAdapter {
    BregAdapter::new(
        BregSourceConfig {
            source_id: "source".into(),
            entity: "correction".into(),
            route: "correction".into(),
            stage: "review".into(),
            binding_generation: "generation-1".into(),
            expected_registry_revision: DIGEST.into(),
            reader_profile: "reader".into(),
            event_source: "urn:registrystack:registry:test:instance:test".into(),
            event_type: "casework-lifecycle-v1".into(),
        },
        BaseRegistryClient::new(
            BaseRegistryClientConfig::new(base.parse().unwrap())
                .with_token_provider(Arc::new(StaticToken::new("reader-token").unwrap())),
        )
        .unwrap(),
        vec![42; 32],
    )
    .unwrap()
}
fn subject() -> SubjectRef {
    SubjectRef {
        source_id: "source".into(),
        kind: "correction".into(),
        id: ID.into(),
    }
}
fn record(state: &str, reason: Option<&str>) -> Value {
    let mut decision = json!({"stageId":"review","kind":"request_revision","decidedAt":"2026-09-10T01:00:00Z","reasonPresent":reason.is_some()});
    if let Some(reason) = reason {
        decision["reason"] = json!(reason);
    }
    json!({"data":{"recordIdentifier":ID,"revisionIdentifier":"2","domainData":{"hidden":"SOURCE-CONTENT-CANARY"},"request":{"bregState":state,"proposalVersion":1,"effectDigest":DIGEST,"editable":false,"actions":[],"decisions":[decision]}},"meta":{"registryIdentifier":"test","datasetIdentifier":"primary","entityTypeIdentifier":"correction"}})
}
fn response(value: Value) -> ResponseTemplate {
    response_with_etag(value, "\"breg-record-2\"")
}
fn response_with_etag(value: Value, etag: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(value).insert_header("traceparent",TRACE).insert_header("etag",etag)
 .insert_header("cache-control","no-store").insert_header("link","<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/correction>; rel=\"describedby\"")
}
async fn mount_metadata(server: &MockServer, token: &str, profile: &str) {
    mount_metadata_revision(server, token, profile, DIGEST).await;
}
async fn mount_metadata_revision(server: &MockServer, token: &str, profile: &str, revision: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/registry"))
        .and(header("authorization", format!("Bearer {token}")))
        .and(query_param("accessProfile", profile))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("traceparent", TRACE)
            .set_body_json(json!({"id":"test","version":"1.0.0","revision":revision,"metadataVersion":"1","entities":[],"operations":[]})))
        .expect(1)
        .mount(server).await;
}
#[tokio::test]
async fn authoritative_read_retains_representation_etag_at_unchanged_record_revision() {
    let mut observations = Vec::new();
    for (verification, etag) in [
        ("pending", "\"breg-record-pending\""),
        ("approved", "\"breg-record-approved\""),
    ] {
        let server = MockServer::start().await;
        mount_metadata(&server, "reader-token", "reader").await;
        let mut representation = record("submitted", None);
        representation["data"]["domainData"]["attachmentVerification"] = json!(verification);
        Mock::given(method("GET"))
            .and(path(format!("/v1/records/correction/{ID}")))
            .and(header("authorization", "Bearer reader-token"))
            .respond_with(response_with_etag(representation, etag))
            .expect(1)
            .mount(&server)
            .await;
        let observation = adapter(&server.uri())
            .read_authoritative(&subject())
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(&observation).unwrap()["representationEtag"],
            etag
        );
        observations.push(observation);
    }
    assert_eq!(
        observations[0].ordered_revision,
        observations[1].ordered_revision
    );
    assert_eq!(observations[0].binding, observations[1].binding);
}
#[tokio::test]
async fn live_registry_change_refuses_projection_under_the_imported_stage_policy() {
    let server = MockServer::start().await;
    let changed = "sha256:1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    mount_metadata_revision(&server, "alice-token", "reviewer", changed).await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/correction/{ID}")))
        .and(header("authorization", "Bearer alice-token"))
        .respond_with(response(record("submitted", None)))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        adapter(&server.uri())
            .read_for_caller(
                &subject(),
                "reviewer",
                EphemeralCredential::new("alice-token")
            )
            .await
            .unwrap_err(),
        SourceAdapterError::BindingMoved
    );
}
#[tokio::test]
async fn caller_disclosure_never_reuses_reader_content_or_another_persons_reason() {
    let server = MockServer::start().await;
    for (token, reason) in [
        ("alice-token", Some("Please correct the activity")),
        ("bob-token", None),
    ] {
        mount_metadata(&server, token, "reviewer").await;
        let mut caller_record = record("needs_changes", reason);
        if token == "bob-token" {
            caller_record["data"]["domainData"] = json!({});
        }
        Mock::given(method("GET"))
            .and(path(format!("/v1/records/correction/{ID}")))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(response(caller_record))
            .expect(1)
            .mount(&server)
            .await;
    }
    let source = adapter(&server.uri());
    let first = source
        .read_for_caller(
            &subject(),
            "reviewer",
            EphemeralCredential::new("alice-token"),
        )
        .await
        .unwrap();
    let second = source
        .read_for_caller(
            &subject(),
            "reviewer",
            EphemeralCredential::new("bob-token"),
        )
        .await
        .unwrap();
    assert_eq!(
        first.disclosed.get("reasons"),
        Some(&json!(["Please correct the activity"]))
    );
    assert!(second.disclosed.is_empty());
    assert_eq!(
        first.disclosed.get("readableFields"),
        Some(&json!(["hidden"]))
    );
    assert!(!serde_json::to_string(&first)
        .unwrap()
        .contains("SOURCE-CONTENT-CANARY"));
}
#[tokio::test]
async fn source_outage_is_not_a_concealed_or_empty_result() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        adapter(&server.uri())
            .read_for_caller(
                &subject(),
                "reviewer",
                EphemeralCredential::new("alice-token")
            )
            .await
            .unwrap_err(),
        SourceAdapterError::Unavailable
    );
}
#[tokio::test]
async fn draft_does_not_open_review_and_approved_opens_separate_application() {
    for (remote, kind, state) in [
        ("draft", OccurrenceKind::Review, OccurrenceState::Superseded),
        (
            "approved",
            OccurrenceKind::Application,
            OccurrenceState::Open,
        ),
        (
            "applied",
            OccurrenceKind::Review,
            OccurrenceState::Completed,
        ),
    ] {
        let server = MockServer::start().await;
        mount_metadata(&server, "reader-token", "reader").await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/records/correction/{ID}")))
            .and(header("authorization", "Bearer reader-token"))
            .respond_with(response(record(remote, None)))
            .expect(1)
            .mount(&server)
            .await;
        let observed = adapter(&server.uri())
            .read_authoritative(&subject())
            .await
            .unwrap();
        assert_eq!(observed.occurrence_kind, kind);
        assert_eq!(observed.state, state);
    }
}
#[tokio::test]
async fn stale_source_generation_is_refused_before_any_read_or_write() {
    let server = MockServer::start().await;
    let source = adapter(&server.uri());
    let actor = ActorContext {
        principal: IssuerPrincipal {
            issuer: "https://idp.example".into(),
            subject: "alice".into(),
        },
        profile_id: "staff".into(),
        role: CaseworkRole::Staff,
    };
    let result = source
        .prepare_action(PrepareActionRequest {
            subject: &subject(),
            displayed_binding: &SourceBinding {
                source_revision: "1".into(),
                version: "1".into(),
                integrity: Some(DIGEST.into()),
                generation: "old-source".into(),
            },
            operation: OperationName::parse("approve").expect("approve operation"),
            reason: None,
            actor: &actor,
            source_profile_id: "reviewer",
            idempotency_key: "attempt-1",
            credential: EphemeralCredential::new("alice-token"),
        })
        .await;
    assert_eq!(result.unwrap_err(), SourceAdapterError::BindingMoved);
    assert!(server.received_requests().await.unwrap().is_empty());
}

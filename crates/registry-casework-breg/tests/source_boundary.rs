// SPDX-License-Identifier: Apache-2.0
use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig, StaticToken};
use registry_casework_breg::{BregAdapter, BregReviewStage, BregSourceConfig};
use registry_casework_core::*;
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc};
use wiremock::{
    matchers::{header, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};
const ID: &str = "00000000-0000-4000-8000-000000000001";
const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
fn adapter(base: &str) -> BregAdapter {
    adapter_with_stages(
        base,
        vec![BregReviewStage {
            id: "review".into(),
            approvals: 1,
            exclude_submitter: false,
            exclude_previous_reviewers: false,
        }],
    )
}
fn adapter_with_routing(base: &str) -> BregAdapter {
    let stages = vec![BregReviewStage {
        id: "review".into(),
        approvals: 1,
        exclude_submitter: false,
        exclude_previous_reviewers: false,
    }];
    BregAdapter::new(
        BregSourceConfig {
            source_id: "source".into(),
            entity: "correction".into(),
            route: "correction".into(),
            stages,
            routing_metadata: RoutingSourceMetadata {
                stages: vec!["review".into()],
                fields: vec![RoutingFieldDescriptor {
                    field: "region".into(),
                    api_name: "serviceRegion".into(),
                    schema: json!({"type":"string","enum":["north","south"]}),
                }],
            },
            display_reference: None,
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
fn adapter_with_stages(base: &str, stages: Vec<BregReviewStage>) -> BregAdapter {
    adapter_with_stages_and_reference(base, stages, None)
}
fn adapter_with_reference(base: &str) -> BregAdapter {
    adapter_with_stages_and_reference(
        base,
        vec![BregReviewStage {
            id: "review".into(),
            approvals: 1,
            exclude_submitter: false,
            exclude_previous_reviewers: false,
        }],
        Some(RoutingFieldDescriptor {
            field: "case-number".into(),
            api_name: "caseNumber".into(),
            schema: json!({"type":"string"}),
        }),
    )
}
fn adapter_with_stages_and_reference(
    base: &str,
    stages: Vec<BregReviewStage>,
    display_reference: Option<RoutingFieldDescriptor>,
) -> BregAdapter {
    let routing_metadata = RoutingSourceMetadata {
        stages: stages.iter().map(|stage| stage.id.clone()).collect(),
        fields: vec![],
    };
    BregAdapter::new(
        BregSourceConfig {
            source_id: "source".into(),
            entity: "correction".into(),
            route: "correction".into(),
            stages,
            routing_metadata,
            display_reference,
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
fn review_record(
    state: &str,
    revision: i64,
    proposal_version: u64,
    review: Option<Value>,
    review_timing: Value,
    decisions: Vec<Value>,
) -> Value {
    let mut value = record(state, None);
    value["data"]["revisionIdentifier"] = json!(revision.to_string());
    value["data"]["request"]["proposalVersion"] = json!(proposal_version);
    value["data"]["request"]["decisions"] = Value::Array(decisions);
    if let Some(review) = review {
        value["data"]["request"]["review"] = review;
    }
    value["data"]["request"]["reviewTiming"] = review_timing;
    value
}
fn stages() -> (Vec<BregReviewStage>, Value) {
    (
        vec![
            BregReviewStage {
                id: "technical".into(),
                approvals: 2,
                exclude_submitter: true,
                exclude_previous_reviewers: false,
            },
            BregReviewStage {
                id: "authorization".into(),
                approvals: 1,
                exclude_submitter: true,
                exclude_previous_reviewers: true,
            },
        ],
        json!([
            {"id":"technical","approvals":2,"excludeSubmitter":true},
            {"id":"authorization","approvals":1,"excludeSubmitter":true,
                "excludePreviousReviewers":true}
        ]),
    )
}
fn pending_review(stage: &str) -> Value {
    json!({
        "stages":[{"id":stage,"approvals":1,"excludeSubmitter":false}],
        "submittedAt":"2026-09-10T02:00:00Z",
        "pendingStage":stage,
        "stageEnteredAt":"2026-09-10T02:30:00Z"
    })
}
fn timing(paused_milliseconds: u64, pause_started_at: Option<&str>) -> Value {
    json!({
        "firstSubmittedAt":"2026-09-10T02:00:00Z",
        "pausedMilliseconds":paused_milliseconds,
        "pauseStartedAt":pause_started_at,
        "completedAt":null
    })
}
async fn authoritative(
    server: &MockServer,
    stages: Vec<BregReviewStage>,
    value: Value,
) -> AuthoritativeObservation {
    mount_metadata(server, "reader-token", "reader").await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/correction/{ID}")))
        .and(header("authorization", "Bearer reader-token"))
        .respond_with(response(value))
        .expect(1)
        .mount(server)
        .await;
    adapter_with_stages(&server.uri(), stages)
        .read_authoritative(&subject())
        .await
        .unwrap()
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

fn diagnostic_field(id: &str, api_name: &str) -> Value {
    json!({
        "id": id,
        "apiName": api_name,
        "label": id,
        "schema": {"type": "string"},
        "required": false,
        "nullable": true,
        "readOnly": false,
        "removable": false
    })
}

fn diagnostic_operation(kind: &str, path: &str, fields: &[(&str, &str)]) -> Value {
    json!({
        "id": format!("records.correction.{kind}"),
        "method": "GET",
        "path": path,
        "operation": kind,
        "sourceEntity": "correction",
        "responseEntity": "correction",
        "accessProfile": "reader",
        "requiredCapabilities": [],
        "entityLabel": "Corrections",
        "identifier": {"apiName": "id", "location": "envelope"},
        "titleFields": [],
        "fields": fields
            .iter()
            .map(|(id, api_name)| diagnostic_field(id, api_name))
            .collect::<Vec<_>>(),
        "readableFields": fields.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        "readableRequestFields": ["reason", "review_state"],
        "createWritableFields": [],
        "patchWritableFields": [],
        "selectors": [],
        "query": null,
        "request": {"fieldNames": "api", "queryParameters": ["$select"]}
    })
}

fn diagnostic_metadata(kinds: &[&str], fields: &[(&str, &str)]) -> Value {
    json!({
        "id": "test",
        "version": "1.0.0",
        "revision": DIGEST,
        "metadataVersion": "1",
        "entities": [{
            "id": "correction",
            "datasetIdentifier": "primary",
            "route": "correction",
            "operations": kinds
                .iter()
                .map(|kind| json!({"operation": kind, "accessProfile": "reader"}))
                .collect::<Vec<_>>(),
            "readableFields": fields.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            "schema": "/v1/schemas/correction"
        }],
        "operations": kinds
            .iter()
            .map(|kind| diagnostic_operation(
                kind,
                if *kind == "get" {
                    "/v1/records/correction/{record_id}"
                } else {
                    "/v1/records/correction"
                },
                fields,
            ))
            .collect::<Vec<_>>()
    })
}

async fn mount_reader_diagnostic(
    server: &MockServer,
    metadata: Value,
    ready_status: u16,
    expect_list: bool,
) {
    let ready = if ready_status == 200 {
        ResponseTemplate::new(200)
            .set_body_json(json!({"status": "ready"}))
            .insert_header("traceparent", TRACE)
    } else {
        ResponseTemplate::new(ready_status)
    };
    Mock::given(method("GET"))
        .and(path("/ready"))
        .respond_with(ready)
        .expect(1)
        .mount(server)
        .await;
    if ready_status != 200 {
        return;
    }
    Mock::given(method("GET"))
        .and(path("/v1/registry"))
        .and(header("authorization", "Bearer reader-token"))
        .and(query_param("accessProfile", "reader"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("traceparent", TRACE)
                .set_body_json(metadata),
        )
        .expect(1)
        .mount(server)
        .await;
    if expect_list {
        Mock::given(method("GET"))
            .and(path("/v1/records/correction"))
            .and(header("authorization", "Bearer reader-token"))
            .and(query_param("accessProfile", "reader"))
            .and(query_param("$top", "1"))
            .and(query_param(
                "$filter",
                "bregState eq 'submitted' or bregState eq 'approved' or bregState eq 'needs_changes'",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("traceparent", TRACE)
                    .insert_header("cache-control", "no-store")
                    .insert_header(
                        "link",
                        "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/correction>; rel=\"describedby\"",
                    )
                    .set_body_json(json!({
                        "items": [],
                        "pageInfo": {"nextCursor": null},
                        "meta": {
                            "registryIdentifier": "test",
                            "datasetIdentifier": "primary",
                            "entityTypeIdentifier": "correction"
                        }
                    })),
            )
            .expect(1)
            .mount(server)
            .await;
    }
}

#[tokio::test]
async fn reader_diagnostic_proves_exact_get_list_projection_on_an_empty_registry() {
    let server = MockServer::start().await;
    mount_reader_diagnostic(
        &server,
        diagnostic_metadata(&["get", "list"], &[("record", "record")]),
        200,
        true,
    )
    .await;

    adapter(&server.uri())
        .verify_reader_readiness()
        .await
        .unwrap();
}

#[tokio::test]
async fn reader_diagnostic_refuses_missing_get_or_routing_projection_grants() {
    let server = MockServer::start().await;
    mount_reader_diagnostic(
        &server,
        diagnostic_metadata(&["list"], &[("record", "record")]),
        200,
        false,
    )
    .await;
    assert_eq!(
        adapter(&server.uri()).verify_reader_readiness().await,
        Err(SourceAdapterError::Denied)
    );

    let server = MockServer::start().await;
    mount_reader_diagnostic(
        &server,
        diagnostic_metadata(&["get", "list"], &[("record", "record")]),
        200,
        false,
    )
    .await;
    assert_eq!(
        adapter_with_routing(&server.uri())
            .verify_reader_readiness()
            .await,
        Err(SourceAdapterError::Denied)
    );
}

#[tokio::test]
async fn reader_diagnostic_refuses_a_reader_whose_grant_conceals_review_state() {
    for concealed in [json!(["reason"]), Value::Null] {
        let server = MockServer::start().await;
        let mut metadata = diagnostic_metadata(&["get", "list"], &[("record", "record")]);
        for operation in metadata["operations"].as_array_mut().unwrap() {
            if concealed.is_null() {
                operation
                    .as_object_mut()
                    .unwrap()
                    .remove("readableRequestFields");
            } else {
                operation["readableRequestFields"] = concealed.clone();
            }
        }
        mount_reader_diagnostic(&server, metadata, 200, false).await;

        assert_eq!(
            adapter(&server.uri()).verify_reader_readiness().await,
            Err(SourceAdapterError::Denied)
        );
    }
}

#[tokio::test]
async fn reader_diagnostic_refuses_a_registry_revision_that_moved() {
    let server = MockServer::start().await;
    let mut metadata = diagnostic_metadata(&["get", "list"], &[("record", "record")]);
    metadata["revision"] =
        json!("sha256:1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    mount_reader_diagnostic(&server, metadata, 200, false).await;

    assert_eq!(
        adapter(&server.uri()).verify_reader_readiness().await,
        Err(SourceAdapterError::BindingMoved)
    );
}

#[tokio::test]
async fn reader_diagnostic_refuses_an_unready_source_before_using_reader_credentials() {
    let server = MockServer::start().await;
    mount_reader_diagnostic(&server, json!({}), 503, false).await;

    assert_eq!(
        adapter(&server.uri()).verify_reader_readiness().await,
        Err(SourceAdapterError::Unavailable)
    );
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
        representation["data"]["request"]["review"] = pending_review("review");
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
    let first = serde_json::to_value(&observations[0]).unwrap();
    assert_eq!(first["submittedAt"], "2026-09-10T02:00:00Z");
    assert_eq!(first["stageEnteredAt"], "2026-09-10T02:30:00Z");
    assert_eq!(observations[0].review_timing, None);
}

#[tokio::test]
async fn authoritative_read_maps_only_imported_routing_fields_and_redacts_values() {
    let server = MockServer::start().await;
    mount_metadata(&server, "reader-token", "reader").await;
    let mut representation = record("submitted", None);
    representation["data"]["request"]["review"] = pending_review("review");
    representation["data"]["domainData"]["serviceRegion"] = json!("north");
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/correction/{ID}")))
        .and(header("authorization", "Bearer reader-token"))
        .respond_with(response(representation))
        .expect(1)
        .mount(&server)
        .await;

    let adapter = adapter_with_routing(&server.uri());
    assert_eq!(
        adapter.routing_metadata().unwrap().fields[0].api_name,
        "serviceRegion"
    );
    let observation = adapter.read_authoritative(&subject()).await.unwrap();
    let routing = observation.routing_context.as_ref().unwrap();
    assert_eq!(routing.activity, RoutingActivity::Review);
    assert_eq!(routing.stage.as_deref(), Some("review"));
    assert_eq!(
        routing.fields,
        BTreeMap::from([("region".into(), json!("north"))])
    );

    let debug = format!("{routing:?}");
    assert!(!debug.contains("north"));
    assert!(!debug.contains("region"));
    let serialized = serde_json::to_value(&observation).unwrap();
    assert!(serialized.get("routingContext").is_none());
    assert!(!serialized.to_string().contains("SOURCE-CONTENT-CANARY"));
}

#[tokio::test]
async fn display_reference_is_retained_only_when_explicitly_configured() {
    let server = MockServer::start().await;
    mount_metadata(&server, "reader-token", "reader").await;
    let mut representation = record("submitted", None);
    representation["data"]["request"]["review"] = pending_review("review");
    representation["data"]["domainData"]["caseNumber"] = json!("CASE-2026-0042");
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/correction/{ID}")))
        .and(header("authorization", "Bearer reader-token"))
        .respond_with(response(representation))
        .expect(1)
        .mount(&server)
        .await;

    let observation = adapter_with_reference(&server.uri())
        .read_authoritative(&subject())
        .await
        .unwrap();
    assert_eq!(
        observation.display_reference.as_deref(),
        Some("CASE-2026-0042")
    );
}

#[tokio::test]
async fn a_missing_optional_reference_does_not_wedge_source_synchronization() {
    let server = MockServer::start().await;
    mount_metadata(&server, "reader-token", "reader").await;
    let mut representation = record("submitted", None);
    representation["data"]["request"]["review"] = pending_review("review");
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/correction/{ID}")))
        .and(header("authorization", "Bearer reader-token"))
        .respond_with(response(representation))
        .expect(1)
        .mount(&server)
        .await;

    let observation = adapter_with_reference(&server.uri())
        .read_authoritative(&subject())
        .await
        .expect("the request remains observable");
    assert_eq!(observation.display_reference, None);
}

#[tokio::test]
async fn current_caller_disclosure_controls_the_display_reference() {
    for (token, disclosed, expected) in [
        ("alice-token", true, Some("CASE-2026-0042")),
        ("bob-token", false, None),
    ] {
        let server = MockServer::start().await;
        mount_metadata(&server, token, "reviewer").await;
        let mut caller_record = record("needs_changes", None);
        if disclosed {
            caller_record["data"]["domainData"]["caseNumber"] = json!("CASE-2026-0042");
        }
        Mock::given(method("GET"))
            .and(path(format!("/v1/records/correction/{ID}")))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(response(caller_record))
            .expect(1)
            .mount(&server)
            .await;

        let view = adapter_with_reference(&server.uri())
            .read_for_caller(&subject(), "reviewer", EphemeralCredential::new(token))
            .await
            .unwrap();
        assert_eq!(view.display_reference.as_deref(), expected);
    }
}

#[tokio::test]
async fn source_pending_stage_keeps_partial_approvals_together_and_opens_the_next_stage() {
    let (configured, frozen) = stages();
    let submitted_at = "2026-09-10T02:00:00Z";
    let first = authoritative(
        &MockServer::start().await,
        configured.clone(),
        review_record(
            "submitted",
            2,
            1,
            Some(json!({"stages":frozen.clone(),"submittedAt":submitted_at,
                "pendingStage":"technical","stageEnteredAt":submitted_at})),
            timing(0, None),
            vec![],
        ),
    )
    .await;
    let one_approval = authoritative(
        &MockServer::start().await,
        configured.clone(),
        review_record(
            "submitted",
            3,
            1,
            Some(json!({"stages":frozen.clone(),"submittedAt":submitted_at,
                "pendingStage":"technical","stageEnteredAt":submitted_at})),
            timing(0, None),
            vec![json!({"stageId":"technical","kind":"approve",
                "decidedAt":"2026-09-10T03:00:00Z","reasonPresent":false})],
        ),
    )
    .await;
    let next_stage = authoritative(
        &MockServer::start().await,
        configured,
        review_record(
            "submitted",
            4,
            1,
            Some(json!({"stages":frozen,"submittedAt":submitted_at,
                "pendingStage":"authorization","stageEnteredAt":"2026-09-10T04:00:00Z"})),
            timing(0, None),
            vec![
                json!({"stageId":"technical","kind":"approve",
                    "decidedAt":"2026-09-10T03:00:00Z","reasonPresent":false}),
                json!({"stageId":"technical","kind":"approve",
                    "decidedAt":"2026-09-10T04:00:00Z","reasonPresent":false}),
            ],
        ),
    )
    .await;

    assert_eq!(first.stage.as_deref(), Some("technical"));
    assert_eq!(first.occurrence_key, one_approval.occurrence_key);
    assert_eq!(next_stage.stage.as_deref(), Some("authorization"));
    assert_ne!(first.occurrence_key, next_stage.occurrence_key);
    assert_eq!(
        next_stage
            .stage_entered_at
            .expect("source stage entry")
            .to_rfc3339(),
        "2026-09-10T04:00:00+00:00"
    );
}

#[tokio::test]
async fn correction_and_resubmission_preserve_request_timing_and_change_occurrence_once() {
    let (configured, frozen) = stages();
    let initial = authoritative(
        &MockServer::start().await,
        configured.clone(),
        review_record(
            "submitted",
            2,
            1,
            Some(
                json!({"stages":frozen.clone(),"submittedAt":"2026-09-10T02:00:00Z",
                "pendingStage":"technical","stageEnteredAt":"2026-09-10T02:00:00Z"}),
            ),
            timing(0, None),
            vec![],
        ),
    )
    .await;
    let correction = authoritative(
        &MockServer::start().await,
        configured.clone(),
        review_record(
            "needs_changes",
            3,
            1,
            Some(
                json!({"stages":frozen.clone(),"submittedAt":"2026-09-10T02:00:00Z",
                "pendingStage":null,"stageEnteredAt":null}),
            ),
            timing(0, Some("2026-09-10T06:00:00Z")),
            vec![json!({"stageId":"technical","kind":"request_revision",
                "decidedAt":"2026-09-10T06:00:00Z","reasonPresent":true,
                "reason":"Correct the request"})],
        ),
    )
    .await;
    let draft = authoritative(
        &MockServer::start().await,
        configured.clone(),
        review_record(
            "draft",
            4,
            2,
            None,
            timing(0, Some("2026-09-10T06:00:00Z")),
            vec![],
        ),
    )
    .await;
    let resubmitted = authoritative(
        &MockServer::start().await,
        configured,
        review_record(
            "submitted",
            5,
            2,
            Some(json!({"stages":frozen,"submittedAt":"2026-09-11T06:00:00Z",
                "pendingStage":"technical","stageEnteredAt":"2026-09-11T06:00:00Z"})),
            timing(86_400_000, None),
            vec![],
        ),
    )
    .await;

    assert_eq!(correction.stage.as_deref(), Some("technical"));
    assert_eq!(initial.occurrence_key, correction.occurrence_key);
    assert_eq!(correction.stage_entered_at, None);
    assert_eq!(draft.stage, None);
    assert_eq!(draft.state, OccurrenceState::Superseded);
    assert_ne!(draft.occurrence_key, initial.occurrence_key);
    assert_ne!(resubmitted.occurrence_key, initial.occurrence_key);
    let retained = resubmitted.review_timing.expect("source request timing");
    assert_eq!(
        retained.first_submitted_at.to_rfc3339(),
        "2026-09-10T02:00:00+00:00"
    );
    assert_eq!(retained.paused_milliseconds, 86_400_000);
    assert_eq!(
        resubmitted
            .submitted_at
            .expect("current proposal submission")
            .to_rfc3339(),
        "2026-09-11T06:00:00+00:00"
    );
}

#[tokio::test]
async fn frozen_policy_survives_current_policy_evolution_but_missing_stage_metadata_does_not() {
    let (configured, mut frozen) = stages();
    frozen[1]["excludePreviousReviewers"] = json!(false);
    let server = MockServer::start().await;
    mount_metadata(&server, "reader-token", "reader").await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/correction/{ID}")))
        .and(header("authorization", "Bearer reader-token"))
        .respond_with(response(review_record(
            "submitted",
            2,
            1,
            Some(json!({"stages":frozen,"submittedAt":"2026-09-10T02:00:00Z",
                "pendingStage":"technical","stageEnteredAt":"2026-09-10T02:00:00Z"})),
            timing(0, None),
            vec![],
        )))
        .expect(1)
        .mount(&server)
        .await;
    let frozen_observation = adapter_with_stages(&server.uri(), configured.clone())
        .read_authoritative(&subject())
        .await
        .unwrap();
    assert_eq!(frozen_observation.stage.as_deref(), Some("technical"));

    let server = MockServer::start().await;
    mount_metadata(&server, "reader-token", "reader").await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/correction/{ID}")))
        .and(header("authorization", "Bearer reader-token"))
        .respond_with(response(record("submitted", None)))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        adapter_with_stages(&server.uri(), configured)
            .read_authoritative(&subject())
            .await
            .unwrap_err(),
        SourceAdapterError::Invalid
    );
}
#[tokio::test]
async fn occurrence_key_uses_the_source_review_stage_and_refuses_a_concealed_one() {
    let configured = vec![BregReviewStage {
        id: "review".into(),
        approvals: 1,
        exclude_submitter: false,
        exclude_previous_reviewers: false,
    }];
    let frozen = json!([
        {"id":"review","approvals":1,"excludeSubmitter":false},
        {"id":"second-review","approvals":1,"excludeSubmitter":false}
    ]);
    let server = MockServer::start().await;
    let granted = authoritative(
        &server,
        configured.clone(),
        review_record(
            "submitted",
            2,
            1,
            Some(json!({"stages":frozen,"submittedAt":"2026-09-10T02:00:00Z",
                "pendingStage":"second-review","stageEnteredAt":"2026-09-10T03:00:00Z"})),
            timing(0, None),
            vec![],
        ),
    )
    .await;
    assert_eq!(granted.stage.as_deref(), Some("second-review"));

    // The same subject read by a reader whose grant conceals review_state has
    // no source stage. One configured stage is not a substitute for it, so the
    // read is refused rather than keyed under a stage the granted read would
    // not agree with.
    let server = MockServer::start().await;
    mount_metadata(&server, "reader-token", "reader").await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/correction/{ID}")))
        .and(header("authorization", "Bearer reader-token"))
        .respond_with(response(review_record(
            "submitted",
            2,
            1,
            None,
            timing(0, None),
            vec![],
        )))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        adapter_with_stages(&server.uri(), configured)
            .read_authoritative(&subject())
            .await
            .unwrap_err(),
        SourceAdapterError::Invalid
    );
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

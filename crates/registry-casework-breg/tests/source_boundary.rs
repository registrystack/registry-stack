// SPDX-License-Identifier: Apache-2.0
use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig, StaticToken};
use registry_casework_breg::{BregAdapter, BregSourceConfig};
use registry_casework_core::*;
use serde_json::{json, Value};
use std::io::Write;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::fmt::MakeWriter;
use wiremock::{
    matchers::{header, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};
const ID: &str = "00000000-0000-4000-8000-000000000001";
const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
fn adapter(base: &str) -> BregAdapter {
    adapter_with_reference_config(base, None)
}
fn adapter_with_context_projection(base: &str) -> BregAdapter {
    let mut config = BregSourceConfig {
        source_id: "source".into(),
        entity: "correction".into(),
        route: "correction".into(),
        routing_metadata: RoutingSourceMetadata::default(),
        context_projection: vec![
            RoutingFieldDescriptor {
                field: "summary".into(),
                api_name: "summary".into(),
                schema: json!({"type":"string","maxLength":32}),
            },
            RoutingFieldDescriptor {
                field: "attachment-metadata".into(),
                api_name: "attachmentMetadata".into(),
                schema: json!({
                    "type":"object",
                    "additionalProperties":false,
                    "required":["name"],
                    "properties":{"name":{"type":"string","maxLength":32}}
                }),
            },
        ],
        display_reference: None,
        binding_generation: "generation-1".into(),
        expected_registry_revision: DIGEST.into(),
        reader_profile: "reader".into(),
        event_source: "urn:registrystack:registry:test:instance:test".into(),
        event_type: "casework-lifecycle-v1".into(),
    };
    config.routing_metadata.stages.clear();
    BregAdapter::new(
        config,
        BaseRegistryClient::new(
            BaseRegistryClientConfig::new(base.parse().unwrap())
                .with_token_provider(Arc::new(StaticToken::new("reader-token").unwrap())),
        )
        .unwrap(),
        vec![42; 32],
    )
    .unwrap()
}
fn adapter_with_routing(base: &str) -> BregAdapter {
    BregAdapter::new(
        BregSourceConfig {
            source_id: "source".into(),
            entity: "correction".into(),
            route: "correction".into(),
            routing_metadata: RoutingSourceMetadata {
                stages: vec![],
                fields: vec![RoutingFieldDescriptor {
                    field: "region".into(),
                    api_name: "serviceRegion".into(),
                    schema: json!({"type":"string","enum":["north","south"]}),
                }],
            },
            context_projection: Vec::new(),
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
fn adapter_with_reference(base: &str) -> BregAdapter {
    adapter_with_reference_config(
        base,
        Some(RoutingFieldDescriptor {
            field: "case-number".into(),
            api_name: "caseNumber".into(),
            schema: json!({"type":"string"}),
        }),
    )
}
fn adapter_with_reference_config(
    base: &str,
    display_reference: Option<RoutingFieldDescriptor>,
) -> BregAdapter {
    let routing_metadata = RoutingSourceMetadata {
        stages: vec![],
        fields: vec![],
    };
    BregAdapter::new(
        BregSourceConfig {
            source_id: "source".into(),
            entity: "correction".into(),
            route: "correction".into(),
            routing_metadata,
            context_projection: Vec::new(),
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
    let _ = reason;
    json!({"data":{"recordIdentifier":ID,"revisionIdentifier":"2","domainData":{"hidden":"SOURCE-CONTENT-CANARY"},"request":{"bregState":state,"proposalVersion":1,"effectDigest":DIGEST,"proposal":{"review":{"authority":"casework-main","policyId":"registry-correction"}},"editable":false,"actions":[]}},"meta":{"registryIdentifier":"test","datasetIdentifier":"primary","entityTypeIdentifier":"correction"}})
}
fn review_status(application_state: &str) -> Value {
    json!({
        "submission": {
            "state":"accepted", "authority":"casework-main",
            "requestId":"00000000-0000-4000-8000-000000000002",
            "submissionDigest":DIGEST,
            "policy":{"id":"registry-correction","version":"1","digest":DIGEST}
        },
        "result":{"state":"pending"},
        "delivery":{"state":"polling"},
        "application":{"mode":"manual","state":application_state},
        "recovery":{"state":"none"}
    })
}
async fn authoritative(server: &MockServer, value: Value) -> AuthoritativeObservation {
    mount_metadata(server, "reader-token", "reader").await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/correction/{ID}")))
        .and(header("authorization", "Bearer reader-token"))
        .respond_with(response(value))
        .expect(1)
        .mount(server)
        .await;
    adapter(&server.uri())
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
                "bregState eq 'submitted'",
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
async fn reader_diagnostic_names_the_route_and_reason_for_malformed_registry_metadata() {
    let server = MockServer::start().await;
    let mut metadata = diagnostic_metadata(&["get", "list"], &[("record", "record")]);
    metadata["entities"] = json!("not-an-array");
    let logs = captured_logs(async {
        mount_reader_diagnostic(&server, metadata, 200, false).await;
        assert_eq!(
            adapter(&server.uri()).verify_reader_readiness().await,
            Err(SourceAdapterError::Unavailable)
        );
    })
    .await;

    let entry: Value = serde_json::from_str(logs.lines().next().expect("one log entry"))
        .expect("structured tracing entry");
    assert_eq!(entry["level"], "WARN");
    assert_eq!(entry["fields"]["route"], "GET /v1/registry");
    assert_eq!(entry["fields"]["metadata_error_kind"], "Shape");
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
        representation["data"]["request"]["review"] = review_status("awaitingReview");
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
    assert!(first.get("submittedAt").is_none());
    assert!(first.get("stageEnteredAt").is_none());
    assert_eq!(observations[0].review_timing, None);
}

#[tokio::test]
async fn authoritative_read_maps_only_imported_routing_fields_and_redacts_values() {
    let server = MockServer::start().await;
    mount_metadata(&server, "reader-token", "reader").await;
    let mut representation = record("submitted", None);
    representation["data"]["request"]["review"] = review_status("awaitingReview");
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
    assert_eq!(routing.activity, RoutingActivity::Apply);
    assert_eq!(routing.stage, None);
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
    representation["data"]["request"]["review"] = review_status("awaitingReview");
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
    representation["data"]["request"]["review"] = review_status("awaitingReview");
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
        let mut caller_record = record("submitted", None);
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
async fn external_review_projection_controls_only_source_application_state() {
    let mut occurrence_key = None;
    for (application_state, expected) in [
        ("awaitingReview", OccurrenceState::WaitingApplication),
        ("blocked", OccurrenceState::WaitingApplication),
        ("expired", OccurrenceState::WaitingApplication),
        ("ready", OccurrenceState::Open),
        ("queued", OccurrenceState::Synchronizing),
        ("applying", OccurrenceState::Synchronizing),
        ("applied", OccurrenceState::Completed),
    ] {
        let server = MockServer::start().await;
        let mut value = record("submitted", None);
        value["data"]["request"]["review"] = review_status(application_state);
        let observed = authoritative(&server, value).await;
        assert_eq!(observed.occurrence_kind, OccurrenceKind::Application);
        assert_eq!(observed.stage, None);
        assert_eq!(observed.submitted_at, None);
        assert_eq!(observed.review_timing, None);
        assert_eq!(observed.state, expected);
        if let Some(key) = &occurrence_key {
            assert_eq!(&observed.occurrence_key, key);
        } else {
            occurrence_key = Some(observed.occurrence_key);
        }
    }
}
#[tokio::test]
async fn live_registry_change_refuses_projection_under_the_imported_source_contract() {
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
async fn caller_context_projection_is_value_bounded_and_never_widens() {
    let server = MockServer::start().await;
    for token in ["alice-token", "bob-token"] {
        mount_metadata(&server, token, "reviewer").await;
        let mut caller_record = record("submitted", None);
        caller_record["data"]["domainData"] = json!({
            "summary":"Caller-visible correction",
            "reason":"SOURCE-CONTENT-CANARY",
            "verifiedEvidence":{"raw":"PRIVATE-EVIDENCE-CANARY"}
        });
        if token == "alice-token" {
            caller_record["data"]["domainData"]["attachmentMetadata"] =
                json!({"name":"evidence.pdf"});
        }
        if token == "bob-token" {
            caller_record["data"]["domainData"]
                .as_object_mut()
                .unwrap()
                .remove("attachmentMetadata");
        }
        Mock::given(method("GET"))
            .and(path(format!("/v1/records/correction/{ID}")))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(response(caller_record))
            .expect(1)
            .mount(&server)
            .await;
    }
    let source = adapter_with_context_projection(&server.uri());
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
        first.disclosed.get("summary"),
        Some(&json!("Caller-visible correction"))
    );
    assert_eq!(
        first.disclosed.get("attachmentMetadata"),
        Some(&json!({"name":"evidence.pdf"}))
    );
    assert!(!second.disclosed.contains_key("attachmentMetadata"));
    let serialized = serde_json::to_string(&first).unwrap();
    assert!(!serialized.contains("SOURCE-CONTENT-CANARY"));
    assert!(!serialized.contains("PRIVATE-EVIDENCE-CANARY"));
    assert!(!first.disclosed.contains_key("reason"));
    assert!(!first.disclosed.contains_key("verifiedEvidence"));
}

#[tokio::test]
async fn caller_context_projection_refuses_a_value_outside_the_imported_schema() {
    let server = MockServer::start().await;
    mount_metadata(&server, "alice-token", "reviewer").await;
    let mut caller_record = record("submitted", None);
    caller_record["data"]["domainData"] = json!({"summary":"x".repeat(33)});
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/correction/{ID}")))
        .and(header("authorization", "Bearer alice-token"))
        .respond_with(response(caller_record))
        .expect(1)
        .mount(&server)
        .await;

    assert_eq!(
        adapter_with_context_projection(&server.uri())
            .read_for_caller(
                &subject(),
                "reviewer",
                EphemeralCredential::new("alice-token")
            )
            .await
            .unwrap_err(),
        SourceAdapterError::Invalid
    );
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
#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

struct CapturedLogWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log capture").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for CapturedLogs {
    type Writer = CapturedLogWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        CapturedLogWriter(Arc::clone(&self.0))
    }
}

/// Run `work` under a JSON tracing subscriber and return what it logged.
async fn captured_logs(work: impl std::future::Future<Output = ()>) -> String {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_ansi(false)
        .with_writer(logs.clone())
        .finish();
    work.with_subscriber(subscriber).await;
    let raw = logs.0.lock().expect("log capture").clone();
    String::from_utf8(raw).unwrap()
}

/// Assert the source reader entries, in order, as a level and an optional
/// cause the logged error must contain.
fn assert_reader_log(raw: &str, expected: &[(&str, Option<&str>)]) {
    let entries = raw
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("structured tracing entry"))
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), expected.len(), "{raw}");
    for (entry, (level, cause)) in entries.iter().zip(expected) {
        assert_eq!(entry["level"], *level, "{raw}");
        assert_eq!(entry["fields"]["source_id"], "source");
        match cause {
            Some(cause) => assert!(
                entry["fields"]["error"]
                    .as_str()
                    .is_some_and(|error| error.contains(cause)),
                "{raw}"
            ),
            None => assert!(entry["fields"].get("error").is_none(), "{raw}"),
        }
    }
}

#[tokio::test]
async fn source_reader_failure_causes_are_logged_once_per_change_and_on_recovery() {
    let server = MockServer::start().await;
    let adapter = adapter(&server.uri());
    let logs = captured_logs(async {
        let refused = Mock::given(method("GET"))
            .and(path(format!("/v1/records/correction/{ID}")))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header("traceparent", TRACE)
                    .insert_header("cache-control", "no-store")
                    .set_body_raw(
                        serde_json::to_vec(&json!({"type":"https://id.registrystack.org/problems/registry-breg/authentication/refused","title":"Unauthorized","status":401,"detail":"The bearer credential is missing or refused.","code":"authentication.refused","traceId":"4bf92f3577b34da6a3ce929d0e0e4736"})).unwrap(),
                        "application/problem+json",
                    ),
            )
            .expect(3)
            .mount_as_scoped(&server)
            .await;
        for _ in 0..3 {
            assert_eq!(
                adapter.read_authoritative(&subject()).await.unwrap_err(),
                SourceAdapterError::Concealed
            );
        }
        drop(refused);

        let outage = Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .expect(2)
            .mount_as_scoped(&server)
            .await;
        assert_eq!(
            adapter.discover_active(None, 100).await.unwrap_err(),
            SourceAdapterError::Unavailable
        );
        assert_eq!(
            adapter
                .read_for_caller(
                    &subject(),
                    "reviewer",
                    EphemeralCredential::new("alice-token")
                )
                .await
                .unwrap_err(),
            SourceAdapterError::Unavailable
        );
        drop(outage);

        let missing = Mock::given(method("GET"))
            .and(path(format!("/v1/records/correction/{ID}")))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount_as_scoped(&server)
            .await;
        assert_eq!(
            adapter.read_authoritative(&subject()).await.unwrap_err(),
            SourceAdapterError::Concealed
        );
        drop(missing);

        mount_metadata(&server, "reader-token", "reader").await;
        let mut representation = record("submitted", None);
        representation["data"]["request"]["review"] = review_status("awaitingReview");
        Mock::given(method("GET"))
            .and(path(format!("/v1/records/correction/{ID}")))
            .and(header("authorization", "Bearer reader-token"))
            .respond_with(response(representation))
            .expect(1)
            .mount(&server)
            .await;
        adapter.read_authoritative(&subject()).await.unwrap();
    })
    .await;

    for secret in ["reader-token", "alice-token", "SOURCE-CONTENT-CANARY"] {
        assert!(!logs.contains(secret), "logs must not carry {secret}");
    }
    assert_reader_log(
        &logs,
        &[
            ("WARN", Some("status 401, code authentication.refused")),
            ("WARN", Some("status 503")),
            ("INFO", None),
        ],
    );
}

#[tokio::test]
async fn source_reader_404_is_quiet_only_for_a_record_read() {
    let server = MockServer::start().await;
    let adapter = adapter(&server.uri());
    let logs = captured_logs(async {
        let contract_missing = Mock::given(method("GET"))
            .and(path("/v1/registry"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount_as_scoped(&server)
            .await;
        assert_eq!(
            adapter.discover_active(None, 100).await.unwrap_err(),
            SourceAdapterError::Concealed
        );
        drop(contract_missing);

        mount_metadata(&server, "reader-token", "reader").await;
        let route_missing = Mock::given(method("GET"))
            .and(path("/v1/records/correction"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount_as_scoped(&server)
            .await;
        assert_eq!(
            adapter.discover_active(None, 100).await.unwrap_err(),
            SourceAdapterError::Concealed
        );
        drop(route_missing);
    })
    .await;

    assert_reader_log(
        &logs,
        &[
            ("WARN", Some("status 404")),
            ("INFO", None),
            ("WARN", Some("status 404")),
        ],
    );
}

#[tokio::test]
async fn caller_reads_neither_report_nor_clear_a_source_reader_failure() {
    let server = MockServer::start().await;
    let adapter = adapter(&server.uri());
    let logs = captured_logs(async {
        let caller_refused = Mock::given(method("GET"))
            .and(header("authorization", "Bearer alice-token"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount_as_scoped(&server)
            .await;
        assert_eq!(
            adapter
                .read_for_caller(
                    &subject(),
                    "reviewer",
                    EphemeralCredential::new("alice-token")
                )
                .await
                .unwrap_err(),
            SourceAdapterError::Concealed
        );
        drop(caller_refused);

        let reader_outage = Mock::given(method("GET"))
            .and(header("authorization", "Bearer reader-token"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount_as_scoped(&server)
            .await;
        assert_eq!(
            adapter.read_authoritative(&subject()).await.unwrap_err(),
            SourceAdapterError::Unavailable
        );
        drop(reader_outage);

        mount_metadata(&server, "alice-token", "reviewer").await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/records/correction/{ID}")))
            .and(header("authorization", "Bearer alice-token"))
            .respond_with(response(record("submitted", None)))
            .expect(1)
            .mount(&server)
            .await;
        adapter
            .read_for_caller(
                &subject(),
                "reviewer",
                EphemeralCredential::new("alice-token"),
            )
            .await
            .unwrap();
    })
    .await;

    assert_reader_log(&logs, &[("WARN", Some("status 503"))]);
}

#[tokio::test]
async fn source_lifecycle_is_projected_as_application_work_only() {
    for (remote, kind, state) in [
        (
            "draft",
            OccurrenceKind::Application,
            OccurrenceState::Superseded,
        ),
        (
            "submitted",
            OccurrenceKind::Application,
            OccurrenceState::WaitingApplication,
        ),
        (
            "applied",
            OccurrenceKind::Application,
            OccurrenceState::Completed,
        ),
        (
            "cancelled",
            OccurrenceKind::Application,
            OccurrenceState::Cancelled,
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

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/correction/{ID}")))
        .and(header("authorization", "Bearer reader-token"))
        .respond_with(response(record("superseded", None)))
        .expect(1)
        .mount(&server)
        .await;
    let logs = captured_logs(async {
        assert_eq!(
            adapter(&server.uri())
                .read_authoritative(&subject())
                .await
                .unwrap_err(),
            SourceAdapterError::Unavailable,
            "a source state BReg never writes is refused"
        );
    })
    .await;
    assert_reader_log(&logs, &[("WARN", Some("did not match the expected shape"))]);
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
            operation: OperationName::parse("cancel").expect("cancel operation"),
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

// SPDX-License-Identifier: Apache-2.0

//! Occurrence projection: descriptor parsing, the pure view, creation-revision
//! evidence and the explicit read helper. The projection cases are
//! deterministic and clock-free: every timestamp is supplied as input.

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use jsonschema::{Draft, JSONSchema};
use registry_breg_client::{
    occurrence_view, occurrence_view_from_json, BRegActionInvocationRequest, BRegCreationRevision,
    BRegIdempotencyKey, BRegMetadata, BRegOccurrenceDescriptor, BRegOccurrenceError,
    BRegOccurrenceEvidence, BRegProposalApplication, BaseRegistryClient, BaseRegistryClientConfig,
    BaseRegistryClientError, RegistryRecord, OCCURRENCE_DESCRIPTOR_VERSION,
    OCCURRENCE_VIEW_CONTRACT,
};
use registry_platform_httputil::client::{BearerToken, TokenError, TokenProvider};
use serde_json::{json, Map, Value};
use tokio::net::TcpListener;
use url::Url;

const REGISTRY_REVISION: &str =
    "sha256:00000000000000000000000000000000000000000000000000000000000000aa";
const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const INCORPORATION_ID: &str = "6f1e0c62-0000-4000-8000-000000000001";
const COMPANY_ID: &str = "6f1e0c62-0000-4000-8000-00000000c001";
const APPLICATION_ID: &str = "a1000000-0000-4000-8000-000000000001";
const DECISION_ID: &str = "7a2d0000-0000-4000-8000-000000000010";
const CORRECTION_ID: &str = "7a2d0000-0000-4000-8000-000000000011";
const PERMIT_ID: &str = "7a2d0000-0000-4000-8000-000000000a01";
const TRANSFER_ID: &str = "8b3e0000-0000-4000-8000-000000000020";
const OTHER_TRANSFER_ID: &str = "8b3e0000-0000-4000-8000-000000000021";
const RECORD_LINK: &str = "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </tenant/base/v1/schemas/incorporation>; rel=\"describedby\"";
const CREATED_AT: &str = "2026-10-26T08:15:30.123456Z";

fn field_ref(id: &str, api_name: &str, value_type: &str, target: Option<&str>) -> Value {
    let mut value = json!({"id": id, "apiName": api_name, "type": value_type});
    if let Some(target) = target {
        value["target"] = json!(target);
    }
    value
}

fn incorporation_descriptor() -> Value {
    json!({
        "descriptorVersion": 1,
        "label": "Incorporation",
        "subjects": [{"role": "company", "label": "Company", "kind": "native",
            "field": field_ref("company", "company", "reference", Some("company"))}],
        "summary": field_ref("summary", "summary", "text", None),
        "occurredAt": {"type": "point", "at": field_ref("occurred-on", "occurredOn", "date", None)},
        "effective": {"type": "point", "at": field_ref("effective-at", "effectiveAt", "timestamp", None)},
        "sources": [{"role": "application", "label": "Application", "kind": "external",
            "namespace": "urn:example:synthetic:applications",
            "field": field_ref("application-reference", "applicationReference", "string", None)}],
        "correction": {"relation": "corrects",
            "field": field_ref("corrects", "corrects", "reference", Some("incorporation"))},
        "sourceEventId": {
            "field": field_ref("application-reference", "applicationReference", "string", None),
            "namespace": "urn:example:synthetic:applications",
            "duplicates": "reject",
            "constraint": "one-per-application"},
        "recordedTime": {"source": "creation-revision"}
    })
}

/// The caller-filtered form for a caller who cannot read the grounds or the
/// summary: undeclared and withheld members are both omitted.
fn suspension_descriptor() -> Value {
    json!({
        "descriptorVersion": 1,
        "label": "Suspension decided",
        "subjects": [{"role": "permit", "label": "Permit", "kind": "native",
            "field": field_ref("permit", "permit", "reference", Some("permit"))}],
        "occurredAt": {"type": "point", "at": field_ref("decided-on", "decidedOn", "date", None)},
        "effective": {"type": "interval", "meaning": "span",
            "start": field_ref("effective-from", "effectiveFrom", "date", None),
            "end": field_ref("effective-until", "effectiveUntil", "date", None)},
        "sources": [],
        "correction": {"relation": "corrects",
            "field": field_ref("corrects", "corrects", "reference", Some("suspension-decision"))},
        "recordedTime": {"source": "creation-revision"}
    })
}

fn transfer_descriptor() -> Value {
    json!({
        "descriptorVersion": 1,
        "label": "Ownership transferred",
        "subjects": [
            {"role": "asset", "label": "Asset", "kind": "native",
                "field": field_ref("asset", "asset", "reference", Some("asset"))},
            {"role": "previous-ownership", "label": "Previous ownership", "kind": "native",
                "field": field_ref("previous-ownership", "previousOwnership", "reference", Some("ownership-record"))},
            {"role": "new-ownership", "label": "New ownership", "kind": "native",
                "field": field_ref("new-ownership", "newOwnership", "reference", Some("ownership-record"))}
        ],
        "occurredAt": {"type": "interval", "meaning": "within",
            "start": field_ref("agreed-not-before", "agreedNotBefore", "date", None),
            "end": field_ref("agreed-before", "agreedBefore", "date", None)},
        "effective": {"type": "point", "at": field_ref("effective-at", "effectiveAt", "timestamp", None)},
        "sources": [{"role": "deed", "label": "Deed", "kind": "external",
            "namespace": "urn:example:synthetic:deeds",
            "field": field_ref("deed-reference", "deedReference", "string", None)}],
        "sourceEventId": {
            "field": field_ref("deed-reference", "deedReference", "string", None),
            "namespace": "urn:example:synthetic:deeds",
            "duplicates": "reject",
            "constraint": "one-per-deed"},
        "recordedTime": {"source": "creation-revision"}
    })
}

fn incorporation_record() -> Value {
    json!({"recordIdentifier": INCORPORATION_ID, "revisionIdentifier": "1",
        "domainData": {"company": COMPANY_ID, "applicationReference": "APP-2026-0042",
            "effectiveAt": "2026-11-02T09:00:00Z", "occurredOn": null,
            "summary": "Synthetic incorporation of a test company.", "corrects": null}})
}

fn decision_record() -> Value {
    json!({"recordIdentifier": DECISION_ID, "revisionIdentifier": "1",
        "domainData": {"permit": PERMIT_ID, "decidedOn": "2026-10-26",
            "effectiveFrom": "2026-12-01", "effectiveUntil": null, "corrects": null}})
}

fn correction_record() -> Value {
    json!({"recordIdentifier": CORRECTION_ID, "revisionIdentifier": "1",
        "domainData": {"permit": PERMIT_ID, "decidedOn": "2026-10-27",
            "effectiveFrom": "2026-12-15", "effectiveUntil": "2027-01-15", "corrects": DECISION_ID}})
}

fn transfer_record() -> Value {
    json!({"recordIdentifier": TRANSFER_ID, "revisionIdentifier": "1",
        "domainData": {"asset": "8b3e0000-0000-4000-8000-000000000b01",
            "previousOwnership": "8b3e0000-0000-4000-8000-000000000b11",
            "newOwnership": "8b3e0000-0000-4000-8000-000000000b12",
            "agreedNotBefore": "2026-09-01", "agreedBefore": null,
            "effectiveAt": "2026-10-20T00:00:00+02:00", "deedReference": "DEED-0007"}})
}

fn creation_revision_json() -> Value {
    json!({"recordId": INCORPORATION_ID, "revision": "1", "createdAt": CREATED_AT})
}

fn incorporation_receipt() -> Value {
    json!({"action": "incorporate-company", "applicationId": APPLICATION_ID,
        "results": {
            "record-incorporation": {"recordType": "incorporation", "recordId": INCORPORATION_ID, "revision": 1},
            "update-company": {"recordType": "company", "recordId": COMPANY_ID, "revision": 2}}})
}

fn arguments(record_type: &str, descriptor: Value, record: Value) -> Map<String, Value> {
    let Value::Object(map) = json!({
        "registryRevision": REGISTRY_REVISION,
        "recordType": record_type,
        "descriptor": descriptor,
        "record": record
    }) else {
        unreachable!("object literal");
    };
    map
}

fn project(arguments: &Map<String, Value>) -> Result<Value, BRegOccurrenceError> {
    let bytes = serde_json::to_vec(arguments).expect("arguments serialize");
    occurrence_view_from_json(&bytes).map(|view| serde_json::to_value(view).expect("view"))
}

fn expect_view(arguments: &Map<String, Value>) -> Value {
    project(arguments).expect("the view projects")
}

fn available(value_type: &str, value: &str) -> Value {
    json!({"status": "available", "type": value_type, "value": value})
}

fn reference(value: &str, target: &str) -> Value {
    json!({"status": "available", "type": "reference", "value": value, "target": target})
}

fn unavailable() -> Value {
    json!({"status": "unavailable"})
}

fn declared_unknown() -> Value {
    json!({"status": "declaredUnknown"})
}

fn incorporation_arguments() -> Map<String, Value> {
    let mut arguments = arguments(
        "incorporation",
        incorporation_descriptor(),
        incorporation_record(),
    );
    arguments.insert("creationRevision".into(), creation_revision_json());
    arguments.insert(
        "actionReceipts".into(),
        json!([{"effect": "record-incorporation", "receipt": incorporation_receipt()}]),
    );
    arguments
}

fn decision_arguments() -> Map<String, Value> {
    arguments(
        "suspension-decision",
        suspension_descriptor(),
        decision_record(),
    )
}

fn correction_arguments() -> Map<String, Value> {
    arguments(
        "suspension-decision",
        suspension_descriptor(),
        correction_record(),
    )
}

fn transfer_arguments() -> Map<String, Value> {
    arguments(
        "ownership-transfer",
        transfer_descriptor(),
        transfer_record(),
    )
}

fn expected_incorporation() -> Value {
    json!({
        "contract": "id.registrystack.org/formats/breg/occurrence-view/v1alpha1",
        "descriptorVersion": 1,
        "registryRevision": REGISTRY_REVISION,
        "source": {"recordType": "incorporation", "recordId": INCORPORATION_ID, "revision": "1"},
        "label": "Incorporation",
        "subjects": [{"role": "company", "label": "Company", "kind": "native",
            "value": reference(COMPANY_ID, "company")}],
        "summary": available("text", "Synthetic incorporation of a test company."),
        "occurredAt": {"type": "point", "at": declared_unknown()},
        "effective": {"type": "point", "at": available("instant", "2026-11-02T09:00:00Z")},
        "recordedAt": available("instant", CREATED_AT),
        "recordedAtSource": "creation-revision",
        "sources": [{"role": "application", "label": "Application", "kind": "external",
            "namespace": "urn:example:synthetic:applications",
            "value": available("text", "APP-2026-0042")}],
        "correction": {"relation": "corrects", "reference": declared_unknown()},
        "sourceEventId": {
            "namespace": available("text", "urn:example:synthetic:applications"),
            "value": available("text", "APP-2026-0042"),
            "duplicates": "reject"},
        "provenance": [{"kind": "action-receipt", "action": "incorporate-company",
            "applicationId": APPLICATION_ID, "effect": "record-incorporation"}],
        "ignoredEvidence": []
    })
}

fn expected_decision() -> Value {
    json!({
        "contract": "id.registrystack.org/formats/breg/occurrence-view/v1alpha1",
        "descriptorVersion": 1,
        "registryRevision": REGISTRY_REVISION,
        "source": {"recordType": "suspension-decision", "recordId": DECISION_ID, "revision": "1"},
        "label": "Suspension decided",
        "subjects": [{"role": "permit", "label": "Permit", "kind": "native",
            "value": reference(PERMIT_ID, "permit")}],
        "summary": unavailable(),
        "occurredAt": {"type": "point", "at": available("date", "2026-10-26")},
        "effective": {"type": "interval", "meaning": "span",
            "start": available("date", "2026-12-01"), "end": declared_unknown()},
        "recordedAt": unavailable(),
        "recordedAtSource": "creation-revision",
        "sources": [],
        "correction": {"relation": "corrects", "reference": declared_unknown()},
        "sourceEventId": unavailable(),
        "provenance": [],
        "ignoredEvidence": []
    })
}

fn expected_correction() -> Value {
    let mut view = expected_decision();
    view["source"]["recordId"] = json!(CORRECTION_ID);
    view["occurredAt"] = json!({"type": "point", "at": available("date", "2026-10-27")});
    view["effective"] = json!({"type": "interval", "meaning": "span",
        "start": available("date", "2026-12-15"), "end": available("date", "2027-01-15")});
    view["correction"] = json!({"relation": "corrects",
        "reference": reference(DECISION_ID, "suspension-decision")});
    view
}

fn expected_transfer() -> Value {
    json!({
        "contract": "id.registrystack.org/formats/breg/occurrence-view/v1alpha1",
        "descriptorVersion": 1,
        "registryRevision": REGISTRY_REVISION,
        "source": {"recordType": "ownership-transfer", "recordId": TRANSFER_ID, "revision": "1"},
        "label": "Ownership transferred",
        "subjects": [
            {"role": "asset", "label": "Asset", "kind": "native",
                "value": reference("8b3e0000-0000-4000-8000-000000000b01", "asset")},
            {"role": "previous-ownership", "label": "Previous ownership", "kind": "native",
                "value": reference("8b3e0000-0000-4000-8000-000000000b11", "ownership-record")},
            {"role": "new-ownership", "label": "New ownership", "kind": "native",
                "value": reference("8b3e0000-0000-4000-8000-000000000b12", "ownership-record")}
        ],
        "summary": unavailable(),
        "occurredAt": {"type": "interval", "meaning": "within",
            "start": available("date", "2026-09-01"), "end": declared_unknown()},
        "effective": {"type": "point", "at": available("instant", "2026-10-20T00:00:00+02:00")},
        "recordedAt": unavailable(),
        "recordedAtSource": "creation-revision",
        "sources": [{"role": "deed", "label": "Deed", "kind": "external",
            "namespace": "urn:example:synthetic:deeds",
            "value": available("text", "DEED-0007")}],
        "correction": unavailable(),
        "sourceEventId": {
            "namespace": available("text", "urn:example:synthetic:deeds"),
            "value": available("text", "DEED-0007"),
            "duplicates": "reject"},
        "provenance": [],
        "ignoredEvidence": []
    })
}

// ---- Projections and the generated fixtures ----

fn fixture_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/occurrence-view")
}

fn read_fixture(name: &str) -> Value {
    let path = fixture_directory().join(name);
    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn write_fixture(name: &str, value: &Value) {
    let mut text = serde_json::to_string_pretty(value).expect("fixture serializes");
    text.push('\n');
    let path = fixture_directory().join(name);
    std::fs::write(&path, text).unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
}

#[test]
fn incorporation_with_unknown_occurrence_date_and_receipt_provenance() {
    assert_eq!(
        expect_view(&incorporation_arguments()),
        expected_incorporation()
    );
}

#[test]
fn restricted_suspension_decision_with_future_effect_and_its_correction() {
    assert_eq!(expect_view(&decision_arguments()), expected_decision());
    assert_eq!(expect_view(&correction_arguments()), expected_correction());
}

#[test]
fn ownership_transfer_keeps_three_subjects_and_a_within_window_as_bounds() {
    assert_eq!(expect_view(&transfer_arguments()), expected_transfer());
}

/// The checked-in fixtures are producer output. Regenerate them with
/// `OCCURRENCE_VIEW_REGENERATE=1`; otherwise the files must equal what the
/// projection produces now, and the inputs must equal the ones the cases use.
#[test]
fn generated_fixtures_equal_the_projection_output() {
    let cases = [
        ("incorporation", incorporation_arguments()),
        ("suspension-decision", decision_arguments()),
        ("suspension-correction", correction_arguments()),
        ("ownership-transfer", transfer_arguments()),
    ];
    let regenerate = std::env::var_os("OCCURRENCE_VIEW_REGENERATE").is_some();
    for (name, input) in cases {
        let view = expect_view(&input);
        let input = Value::Object(input);
        if regenerate {
            write_fixture(&format!("{name}.input.json"), &input);
            write_fixture(&format!("{name}.json"), &view);
        } else {
            assert_eq!(
                read_fixture(&format!("{name}.input.json")),
                input,
                "{name} input"
            );
            assert_eq!(read_fixture(&format!("{name}.json")), view, "{name} view");
        }
    }
}

// ---- The published view schema ----

fn view_schema() -> JSONSchema {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/contracts/occurrence-view/OccurrenceView.schema.json");
    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let schema: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
    assert_eq!(
        schema["properties"]["contract"]["const"],
        json!(OCCURRENCE_VIEW_CONTRACT),
        "the schema pins the contract identifier the client emits"
    );
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .unwrap_or_else(|error| panic!("the view schema compiles: {error}"))
}

fn assert_valid(schema: &JSONSchema, label: &str, view: &Value) {
    if let Err(errors) = schema.validate(view) {
        let report: Vec<String> = errors
            .map(|error| format!("{}: {error}", error.instance_path))
            .collect();
        panic!("{label} violates the view schema:\n{}", report.join("\n"));
    }
}

#[test]
fn the_committed_fixtures_validate_against_the_view_schema() {
    let schema = view_schema();
    for name in [
        "incorporation",
        "suspension-decision",
        "suspension-correction",
        "ownership-transfer",
    ] {
        assert_valid(&schema, name, &read_fixture(&format!("{name}.json")));
    }
}

#[test]
fn every_status_and_degraded_member_validates_against_the_view_schema() {
    let schema = view_schema();

    let mut descriptor = incorporation_descriptor();
    descriptor["effective"] = json!({"type": "recurrence", "rule": "weekly"});
    descriptor["correction"]["relation"] = json!("supersedes");
    descriptor["sourceEventId"]["duplicates"] = json!("merge");
    descriptor["subjects"][0]["kind"] = json!("delegated");
    descriptor["occurredAt"] = json!({"type": "interval", "meaning": "around",
        "start": field_ref("occurred-on", "occurredOn", "date", None)});
    let mut arguments = arguments("incorporation", descriptor, incorporation_record());
    arguments["descriptor"]["summary"]["type"] = json!("duration");
    arguments["record"]["domainData"]["summary"] = json!("P1D");
    arguments.insert("creationRevision".into(), creation_revision_json());
    arguments.insert(
        "actionReceipts".into(),
        json!([{"effect": "record-incorporation", "receipt": incorporation_receipt()},
            {"effect": "absent-effect", "receipt": incorporation_receipt()}]),
    );
    arguments.insert(
        "proposalApplications".into(),
        json!([{"applicationId": "b2000000-0000-4000-8000-000000000002", "submissionVersion": 3,
            "effectDigest": "sha256:00000000000000000000000000000000000000000000000000000000000000bb",
            "appliedBy": "reviewer-ref-1", "appliedAt": "2026-10-26T09:00:00Z",
            "resultLinks": [{"recordType": "incorporation", "recordId": INCORPORATION_ID, "revision": 2}]}]),
    );
    let view = expect_view(&arguments);
    assert_eq!(view["subjects"][0]["value"]["status"], json!("unsupported"));
    assert_eq!(view["summary"]["status"], json!("unsupported"));
    assert_valid(&schema, "degraded view", &view);

    let mut bare = transfer_arguments();
    bare.insert(
        "proposalApplications".into(),
        json!([{"applicationId": "b2000000-0000-4000-8000-000000000002", "submissionVersion": 3,
            "effectDigest": "sha256:00000000000000000000000000000000000000000000000000000000000000bb",
            "appliedBy": "reviewer-ref-1", "appliedAt": "2026-10-26T09:00:00Z",
            "resultLinks": [{"recordType": "ownership-transfer", "recordId": TRANSFER_ID, "revision": 1}]}]),
    );
    let view = expect_view(&bare);
    assert_eq!(view["provenance"][0]["kind"], json!("proposal-application"));
    assert_valid(&schema, "proposal provenance view", &view);
}

#[test]
fn the_view_schema_refuses_shapes_the_projection_never_emits() {
    let schema = view_schema();
    let valid = read_fixture("incorporation.json");
    let mutations: [(&str, DescriptorMutation); 7] = [
        ("an unknown member", |view| view["extra"] = json!(true)),
        ("a wrong contract", |view| view["contract"] = json!("other")),
        ("a missing recordedAtSource", |view| {
            view.as_object_mut()
                .expect("view")
                .remove("recordedAtSource");
        }),
        ("an unknown status word", |view| {
            view["summary"] = json!({"status": "redacted"});
        }),
        ("an available value without a value", |view| {
            view["summary"] = json!({"status": "available", "type": "text"});
        }),
        ("an unsupported value without a detail", |view| {
            view["summary"] = json!({"status": "unsupported"});
        }),
        ("an unknown ignored-evidence reason", |view| {
            view["ignoredEvidence"] = json!([{"kind": "action-receipt",
                "applicationId": APPLICATION_ID, "reason": "stale"}]);
        }),
    ];
    for (label, mutate) in mutations {
        let mut view = valid.clone();
        mutate(&mut view);
        assert!(!schema.is_valid(&view), "the schema accepted {label}");
    }
}

// ---- Dates stay dates, unknowns stay unknown (deterministic, clock-free) ----

#[test]
fn dates_stay_dates_and_unknowns_stay_unknown() {
    let view = expect_view(&incorporation_arguments());
    // The creation time is a transaction timestamp; the effective instant and
    // the occurrence date are separate facts and never take its value.
    assert_eq!(view["recordedAt"]["value"], json!(CREATED_AT));
    assert_ne!(
        view["effective"]["at"]["value"],
        view["recordedAt"]["value"]
    );
    assert_eq!(view["occurredAt"]["at"], declared_unknown());

    let transfer = expect_view(&transfer_arguments());
    assert_eq!(transfer["occurredAt"]["start"]["type"], json!("date"));
    assert_eq!(
        transfer["occurredAt"]["start"]["value"],
        json!("2026-09-01")
    );
    assert_eq!(transfer["occurredAt"]["meaning"], json!("within"));
    assert!(transfer["occurredAt"].get("at").is_none());
    assert_eq!(
        transfer["effective"]["at"]["value"],
        json!("2026-10-20T00:00:00+02:00"),
        "the offset is kept and the instant is not normalized"
    );

    let decision = expect_view(&decision_arguments());
    assert_eq!(decision["occurredAt"]["at"]["value"], json!("2026-10-26"));
    assert_eq!(decision["effective"]["start"]["value"], json!("2026-12-01"));
    assert!(decision.get("status").is_none());
    assert!(decision.get("completed").is_none());
}

// ---- Value rules ----

fn with_domain_data(
    mut arguments: Map<String, Value>,
    name: &str,
    value: Option<Value>,
) -> Map<String, Value> {
    let data = arguments["record"]["domainData"]
        .as_object_mut()
        .expect("domain data");
    match value {
        Some(value) => data.insert(name.to_owned(), value),
        None => data.remove(name),
    };
    arguments
}

#[test]
fn an_absent_key_is_unavailable_and_a_null_is_declared_unknown() {
    let absent = with_domain_data(incorporation_arguments(), "occurredOn", None);
    assert_eq!(expect_view(&absent)["occurredAt"]["at"], unavailable());
    let null = with_domain_data(incorporation_arguments(), "occurredOn", Some(Value::Null));
    assert_eq!(expect_view(&null)["occurredAt"]["at"], declared_unknown());
}

#[test]
fn instants_are_emitted_with_uppercase_separator_and_zone_letters() {
    let mut arguments = with_domain_data(
        incorporation_arguments(),
        "effectiveAt",
        Some(json!("2026-11-02t09:00:00.5z")),
    );
    arguments.insert(
        "creationRevision".into(),
        json!({"recordId": INCORPORATION_ID, "revision": "1",
            "createdAt": "2026-10-26t08:15:30z"}),
    );
    let view = expect_view(&arguments);
    assert_eq!(
        view["effective"]["at"]["value"],
        json!("2026-11-02T09:00:00.5Z")
    );
    assert_eq!(view["recordedAt"]["value"], json!("2026-10-26T08:15:30Z"));

    let offset = with_domain_data(
        incorporation_arguments(),
        "effectiveAt",
        Some(json!("2026-10-20t00:00:00+02:00")),
    );
    assert_eq!(
        expect_view(&offset)["effective"]["at"]["value"],
        json!("2026-10-20T00:00:00+02:00"),
        "only letter case changes; the authored offset is kept"
    );
}

#[test]
fn values_that_contradict_the_declared_type_are_incompatible_metadata() {
    for (name, value) in [
        ("occurredOn", json!(20260901)),
        ("occurredOn", json!("2026-13-01")),
        ("occurredOn", json!("2026-10-26T00:00:00Z")),
        ("occurredOn", json!("26-10-2026")),
        ("effectiveAt", json!("2026-11-02")),
        ("effectiveAt", json!(true)),
        ("company", json!("not-a-uuid")),
        ("company", json!(["6f1e0c62-0000-4000-8000-00000000c001"])),
        ("applicationReference", json!(7)),
    ] {
        let arguments = with_domain_data(incorporation_arguments(), name, Some(value.clone()));
        let error = project(&arguments).expect_err(&format!("{name}={value} is refused"));
        assert!(
            matches!(error, BRegOccurrenceError::IncompatibleMetadata { .. }),
            "{name}={value}: {error}"
        );
        assert_eq!(error.code(), "incompatible-metadata");
        let text = error.to_string();
        assert!(
            !text.contains("not-a-uuid"),
            "the record value is not echoed: {text}"
        );
    }
}

#[test]
fn a_numeric_date_is_incompatible_metadata_on_the_transfer_window() {
    let arguments = with_domain_data(
        transfer_arguments(),
        "agreedNotBefore",
        Some(json!(20260901)),
    );
    assert!(matches!(
        project(&arguments),
        Err(BRegOccurrenceError::IncompatibleMetadata { .. })
    ));
}

#[test]
fn an_unknown_field_type_makes_only_that_member_unsupported() {
    let mut descriptor = transfer_descriptor();
    descriptor["effective"]["at"]["type"] = json!("duration");
    let mut arguments = arguments("ownership-transfer", descriptor, transfer_record());
    arguments["record"]["domainData"]["effectiveAt"] = json!("P1D");
    let view = expect_view(&arguments);
    assert_eq!(
        view["effective"]["at"],
        json!({"status": "unsupported", "detail": "value type duration"})
    );
    assert_eq!(view["subjects"].as_array().expect("subjects").len(), 3);
    assert_eq!(view["occurredAt"]["start"]["value"], json!("2026-09-01"));
}

#[test]
fn unknown_time_types_relations_and_meanings_degrade_to_unsupported_members() {
    let mut descriptor = incorporation_descriptor();
    descriptor["effective"] = json!({"type": "recurrence", "rule": "weekly"});
    descriptor["correction"]["relation"] = json!("amends");
    descriptor["sourceEventId"]["duplicates"] = json!("merge");
    let view = expect_view(&arguments(
        "incorporation",
        descriptor,
        incorporation_record(),
    ));
    assert_eq!(
        view["effective"],
        json!({"status": "unsupported", "detail": "time type recurrence"})
    );
    assert_eq!(
        view["correction"],
        json!({"status": "unsupported", "detail": "correction relation amends"})
    );
    assert_eq!(
        view["sourceEventId"],
        json!({"status": "unsupported", "detail": "duplicates policy merge"})
    );
    assert_eq!(view["label"], json!("Incorporation"));

    let mut descriptor = transfer_descriptor();
    descriptor["occurredAt"]["meaning"] = json!("around");
    let view = expect_view(&arguments(
        "ownership-transfer",
        descriptor,
        transfer_record(),
    ));
    assert_eq!(
        view["occurredAt"],
        json!({"status": "unsupported", "detail": "interval meaning around"})
    );
}

#[test]
fn a_supersedes_correction_is_projected_like_a_corrects_correction() {
    let mut descriptor = suspension_descriptor();
    descriptor["correction"]["relation"] = json!("supersedes");
    let view = expect_view(&arguments(
        "suspension-decision",
        descriptor.clone(),
        correction_record(),
    ));
    assert_eq!(
        view["correction"],
        json!({"relation": "supersedes", "reference": reference(DECISION_ID, "suspension-decision")})
    );
    let parsed = BRegOccurrenceDescriptor::from_value(&descriptor).expect("descriptor parses");
    assert_eq!(parsed.to_value(), descriptor);
}

#[test]
fn an_unknown_role_kind_makes_only_that_role_unsupported() {
    let mut descriptor = transfer_descriptor();
    descriptor["subjects"][1]["kind"] = json!("delegated");
    let view = expect_view(&arguments(
        "ownership-transfer",
        descriptor.clone(),
        transfer_record(),
    ));
    let subjects = view["subjects"].as_array().expect("subjects");
    assert_eq!(subjects.len(), 3);
    assert_eq!(
        subjects[1],
        json!({"role": "previous-ownership", "label": "Previous ownership",
            "value": {"status": "unsupported", "detail": "role kind delegated"}})
    );
    assert_eq!(subjects[0]["kind"], json!("native"));
    assert_eq!(subjects[2]["value"]["status"], json!("available"));
    assert_eq!(view["sources"][0]["value"]["value"], json!("DEED-0007"));
    let parsed = BRegOccurrenceDescriptor::from_value(&descriptor).expect("descriptor parses");
    assert_eq!(parsed.to_value(), descriptor);
}

#[test]
fn an_open_interval_end_that_is_not_mapped_is_unavailable() {
    let mut descriptor = suspension_descriptor();
    descriptor["effective"]
        .as_object_mut()
        .expect("interval")
        .remove("end");
    let view = expect_view(&arguments(
        "suspension-decision",
        descriptor,
        decision_record(),
    ));
    assert_eq!(view["effective"]["end"], unavailable());
    assert_eq!(view["effective"]["start"]["value"], json!("2026-12-01"));
}

#[test]
fn a_source_event_namespace_can_come_from_a_record_field() {
    let mut descriptor = incorporation_descriptor();
    descriptor["sourceEventId"] = json!({
        "field": field_ref("application-reference", "applicationReference", "string", None),
        "namespaceField": field_ref("applicant-system", "applicantSystem", "string", None),
        "duplicates": "allow"});
    let arguments = with_domain_data(
        arguments("incorporation", descriptor, incorporation_record()),
        "applicantSystem",
        Some(json!("urn:example:synthetic:intake")),
    );
    let view = expect_view(&arguments);
    assert_eq!(
        view["sourceEventId"],
        json!({"namespace": available("text", "urn:example:synthetic:intake"),
            "value": available("text", "APP-2026-0042"), "duplicates": "allow"})
    );
}

// ---- Evidence ----

#[test]
fn recorded_time_comes_only_from_the_creation_revision_of_this_record() {
    let mut arguments = incorporation_arguments();
    arguments.insert(
        "creationRevision".into(),
        json!({"recordId": OTHER_TRANSFER_ID, "revision": "1", "createdAt": CREATED_AT}),
    );
    let error = project(&arguments).expect_err("another record's creation revision is refused");
    assert!(matches!(
        error,
        BRegOccurrenceError::WrongRecordEvidence { .. }
    ));
    assert_eq!(error.code(), "wrong-record-evidence");

    let mut transfer = transfer_arguments();
    transfer.insert(
        "creationRevision".into(),
        json!({"recordId": OTHER_TRANSFER_ID, "revision": "1", "createdAt": CREATED_AT}),
    );
    assert!(matches!(
        project(&transfer),
        Err(BRegOccurrenceError::WrongRecordEvidence { .. })
    ));
}

#[test]
fn a_creation_revision_that_is_not_revision_one_is_refused() {
    let mut arguments = incorporation_arguments();
    arguments.insert(
        "creationRevision".into(),
        json!({"recordId": INCORPORATION_ID, "revision": "2", "createdAt": CREATED_AT}),
    );
    let error = project(&arguments).expect_err("only revision 1 states the recorded time");
    assert!(matches!(
        error,
        BRegOccurrenceError::RevisionMismatch { ref expected, ref found }
            if expected == "1" && found == "2"
    ));
    assert_eq!(error.code(), "revision-mismatch");
}

#[test]
fn a_creation_revision_with_an_invalid_timestamp_is_refused() {
    let mut arguments = incorporation_arguments();
    arguments.insert(
        "creationRevision".into(),
        json!({"recordId": INCORPORATION_ID, "revision": "1", "createdAt": "2026-10-26"}),
    );
    assert!(project(&arguments).is_err());
}

#[test]
fn a_receipt_for_another_revision_is_listed_as_ignored_evidence() {
    let mut arguments = transfer_arguments();
    arguments["record"]["revisionIdentifier"] = json!("2");
    arguments.insert(
        "actionReceipts".into(),
        json!([{"effect": "record-transfer", "receipt": {
            "action": "transfer-ownership", "applicationId": APPLICATION_ID,
            "results": {"record-transfer": {
                "recordType": "ownership-transfer", "recordId": TRANSFER_ID, "revision": 1}}}}]),
    );
    let view = expect_view(&arguments);
    assert_eq!(view["provenance"], json!([]));
    assert_eq!(
        view["ignoredEvidence"],
        json!([{"kind": "action-receipt", "applicationId": APPLICATION_ID,
            "reason": "revision-mismatch"}])
    );
    assert_eq!(view["source"]["revision"], json!("2"));
}

#[test]
fn evidence_with_no_result_for_this_record_is_listed_as_ignored_evidence() {
    let mut arguments = transfer_arguments();
    arguments.insert(
        "actionReceipts".into(),
        json!([
            {"effect": "update-company", "receipt": incorporation_receipt()},
            {"effect": "absent-effect", "receipt": incorporation_receipt()}
        ]),
    );
    arguments.insert(
        "proposalApplications".into(),
        json!([{"applicationId": "b2000000-0000-4000-8000-000000000002", "submissionVersion": 1,
            "effectDigest": "sha256:00000000000000000000000000000000000000000000000000000000000000bb",
            "resultLinks": [{"recordType": "ownership-transfer", "recordId": OTHER_TRANSFER_ID, "revision": 1}]}]),
    );
    let view = expect_view(&arguments);
    assert_eq!(view["provenance"], json!([]));
    assert_eq!(
        view["ignoredEvidence"],
        json!([
            {"kind": "action-receipt", "applicationId": APPLICATION_ID, "reason": "no-matching-result"},
            {"kind": "action-receipt", "applicationId": APPLICATION_ID, "reason": "no-matching-result"},
            {"kind": "proposal-application", "applicationId": "b2000000-0000-4000-8000-000000000002",
                "reason": "no-matching-result"}
        ])
    );
}

#[test]
fn a_matching_proposal_application_contributes_only_what_it_carries() {
    let application = |extra: Value| {
        let mut value = json!({
            "applicationId": "b2000000-0000-4000-8000-000000000002", "submissionVersion": 3,
            "effectDigest": "sha256:00000000000000000000000000000000000000000000000000000000000000bb",
            "resultLinks": [{"recordType": "ownership-transfer", "recordId": TRANSFER_ID, "revision": 1}]});
        value
            .as_object_mut()
            .expect("object")
            .extend(extra.as_object().expect("extra").clone());
        value
    };
    let mut full = transfer_arguments();
    full.insert(
        "proposalApplications".into(),
        json!([application(
            json!({"appliedBy": "reviewer-ref-1", "appliedAt": "2026-10-26T09:00:00Z"})
        )]),
    );
    assert_eq!(
        expect_view(&full)["provenance"],
        json!([{"kind": "proposal-application",
            "applicationId": "b2000000-0000-4000-8000-000000000002", "submissionVersion": 3,
            "appliedAt": "2026-10-26T09:00:00Z", "appliedBy": "reviewer-ref-1"}])
    );
    let mut bare = transfer_arguments();
    bare.insert(
        "proposalApplications".into(),
        json!([application(json!({}))]),
    );
    assert_eq!(
        expect_view(&bare)["provenance"],
        json!([{"kind": "proposal-application",
            "applicationId": "b2000000-0000-4000-8000-000000000002", "submissionVersion": 3}])
    );
}

#[test]
fn an_applied_at_instant_is_emitted_like_every_other_instant() {
    let mut arguments = transfer_arguments();
    arguments.insert(
        "proposalApplications".into(),
        json!([{"applicationId": "b2000000-0000-4000-8000-000000000002", "submissionVersion": 3,
            "effectDigest": "sha256:00000000000000000000000000000000000000000000000000000000000000bb",
            "appliedBy": "reviewer-ref-1", "appliedAt": "2026-10-26t09:00:00.5z",
            "resultLinks": [{"recordType": "ownership-transfer", "recordId": TRANSFER_ID, "revision": 1}]}]),
    );
    assert_eq!(
        expect_view(&arguments)["provenance"][0]["appliedAt"],
        json!("2026-10-26T09:00:00.5Z")
    );

    arguments["proposalApplications"][0]["appliedAt"] = json!("yesterday");
    assert!(matches!(
        project(&arguments),
        Err(BRegOccurrenceError::WrongRecordEvidence { .. })
    ));
}

#[test]
fn repeated_evidence_contributes_one_provenance_entry_in_first_seen_order() {
    let receipt = |effect: &str| json!({"effect": effect, "receipt": incorporation_receipt()});
    let mut arguments = incorporation_arguments();
    arguments.insert(
        "actionReceipts".into(),
        json!([
            receipt("record-incorporation"),
            receipt("update-company"),
            receipt("record-incorporation")
        ]),
    );
    let application = json!({"applicationId": "b2000000-0000-4000-8000-000000000002",
        "submissionVersion": 1,
        "effectDigest": "sha256:00000000000000000000000000000000000000000000000000000000000000bb",
        "resultLinks": [{"recordType": "incorporation", "recordId": INCORPORATION_ID, "revision": 1}]});
    arguments.insert(
        "proposalApplications".into(),
        json!([application.clone(), application]),
    );
    let view = expect_view(&arguments);
    assert_eq!(
        view["provenance"],
        json!([
            {"kind": "action-receipt", "action": "incorporate-company",
                "applicationId": APPLICATION_ID, "effect": "record-incorporation"},
            {"kind": "proposal-application",
                "applicationId": "b2000000-0000-4000-8000-000000000002", "submissionVersion": 1}
        ])
    );
    // The update-company receipt result names another record type.
    assert_eq!(
        view["ignoredEvidence"],
        json!([{"kind": "action-receipt", "applicationId": APPLICATION_ID,
            "reason": "no-matching-result"}])
    );
}

// ---- Descriptor errors ----

#[test]
fn descriptor_version_other_than_one_is_unsupported() {
    let mut descriptor = transfer_descriptor();
    descriptor["descriptorVersion"] = json!(2);
    let error = project(&arguments(
        "ownership-transfer",
        descriptor,
        transfer_record(),
    ))
    .expect_err("version 2 is refused");
    assert!(matches!(
        error,
        BRegOccurrenceError::UnsupportedVersion { found: 2 }
    ));
    assert_eq!(error.code(), "unsupported-version");
    assert_eq!(OCCURRENCE_DESCRIPTOR_VERSION, 1);
}

#[test]
fn a_descriptor_version_that_is_not_a_positive_integer_is_malformed() {
    for version in [json!("1"), json!(1.0), json!(-1), json!(null), json!(true)] {
        let mut descriptor = transfer_descriptor();
        descriptor["descriptorVersion"] = version.clone();
        let error = BRegOccurrenceDescriptor::from_value(&descriptor)
            .expect_err(&format!("{version} is not a descriptor version"));
        assert!(
            matches!(error, BRegOccurrenceError::MalformedDescriptor { ref path } if path == "descriptorVersion"),
            "{version}: {error}"
        );
    }
}

#[test]
fn a_descriptor_missing_a_required_member_is_malformed() {
    for (member, path) in [
        ("subjects", "subjects"),
        ("sources", "sources"),
        ("label", "label"),
        ("recordedTime", "recordedTime"),
        ("descriptorVersion", "descriptorVersion"),
    ] {
        let mut descriptor = transfer_descriptor();
        descriptor
            .as_object_mut()
            .expect("descriptor")
            .remove(member);
        let error = BRegOccurrenceDescriptor::from_value(&descriptor)
            .expect_err(&format!("missing {member}"));
        assert!(
            matches!(error, BRegOccurrenceError::MalformedDescriptor { path: ref found } if found == path),
            "{member}: {error}"
        );
        assert_eq!(error.code(), "malformed-descriptor");
    }
}

type DescriptorMutation = fn(&mut Value);

#[test]
fn malformed_nested_members_name_their_path() {
    let cases: [(&str, DescriptorMutation); 8] = [
        ("subjects[0].kind", |d| {
            d["subjects"][0]
                .as_object_mut()
                .expect("role")
                .remove("kind");
        }),
        ("subjects[0].field.apiName", |d| {
            d["subjects"][0]["field"]
                .as_object_mut()
                .expect("field")
                .remove("apiName");
        }),
        ("sources[0].namespace", |d| {
            d["sources"][0]
                .as_object_mut()
                .expect("source")
                .remove("namespace");
        }),
        ("recordedTime.source", |d| {
            d["recordedTime"]["source"] = json!("clock")
        }),
        ("sourceEventId", |d| {
            d["sourceEventId"]["namespaceField"] =
                field_ref("applicant-system", "applicantSystem", "string", None);
        }),
        ("occurredAt.type", |d| {
            d["occurredAt"]
                .as_object_mut()
                .expect("time")
                .remove("type");
        }),
        ("effective.type", |d| {
            let time = d["effective"].as_object_mut().expect("time");
            time.remove("type");
            time.insert("kind".into(), json!("point"));
        }),
        ("occurredAt.at", |d| {
            d["occurredAt"].as_object_mut().expect("time").remove("at");
        }),
    ];
    for (path, mutate) in cases {
        let mut descriptor = incorporation_descriptor();
        mutate(&mut descriptor);
        let error = BRegOccurrenceDescriptor::from_value(&descriptor)
            .expect_err(&format!("{path} is malformed"));
        assert!(
            matches!(error, BRegOccurrenceError::MalformedDescriptor { path: ref found } if found == path),
            "{path}: {error}"
        );
    }
    assert!(matches!(
        BRegOccurrenceDescriptor::from_value(&json!([])),
        Err(BRegOccurrenceError::MalformedDescriptor { .. })
    ));
}

#[test]
fn unknown_descriptor_members_are_ignored() {
    let mut descriptor = incorporation_descriptor();
    descriptor["futureMember"] = json!({"anything": true});
    descriptor["subjects"][0]["futureMember"] = json!(1);
    assert_eq!(
        expect_view(&arguments(
            "incorporation",
            descriptor,
            incorporation_record()
        ))["label"],
        json!("Incorporation")
    );
}

#[test]
fn descriptors_round_trip_through_their_canonical_form() {
    for descriptor in [
        incorporation_descriptor(),
        suspension_descriptor(),
        transfer_descriptor(),
    ] {
        let parsed = BRegOccurrenceDescriptor::from_value(&descriptor).expect("parses");
        assert_eq!(
            parsed.to_value(),
            descriptor,
            "canonical form omits what is absent"
        );
        let reparsed = BRegOccurrenceDescriptor::from_value(&parsed.to_value()).expect("reparses");
        assert_eq!(parsed, reparsed);
    }
}

#[test]
fn argument_documents_are_strict() {
    let bytes = |value: &Value| serde_json::to_vec(value).expect("serializes");
    for invalid in [
        b"not json".to_vec(),
        bytes(&json!([])),
        bytes(&json!({"registryRevision": REGISTRY_REVISION})),
        {
            let mut arguments = incorporation_arguments();
            arguments.insert("extra".into(), json!(true));
            bytes(&Value::Object(arguments))
        },
        {
            let mut arguments = incorporation_arguments();
            arguments["record"]["domainData"] = json!([]);
            bytes(&Value::Object(arguments))
        },
        br#"{"recordType":"a","recordType":"b"}"#.to_vec(),
    ] {
        let error = occurrence_view_from_json(&invalid).expect_err("invalid input is refused");
        assert!(
            matches!(error, BRegOccurrenceError::InvalidInput { .. }),
            "{error}"
        );
        assert_eq!(error.code(), "invalid-input");
    }
}

#[test]
fn invalid_input_errors_carry_no_supplied_value() {
    let secret = "SECRET-EVIDENCE-VALUE";
    let mut wrong_type = incorporation_arguments();
    wrong_type["actionReceipts"][0]["receipt"]["results"]["record-incorporation"]["revision"] =
        json!(secret);
    let mut unknown_member = incorporation_arguments();
    unknown_member.insert(secret.into(), json!(true));
    let mut unknown_nested = incorporation_arguments();
    unknown_nested["actionReceipts"][0]["receipt"][secret] = json!(secret);
    let mut wrong_domain_data = incorporation_arguments();
    wrong_domain_data["record"]["domainData"] = json!(secret);
    let mut wrong_record_member = incorporation_arguments();
    wrong_record_member["record"]
        .as_object_mut()
        .expect("record")
        .remove("revisionIdentifier");
    wrong_record_member["record"]["recordIdentifier"] = json!(secret);
    for arguments in [
        wrong_type,
        unknown_member,
        unknown_nested,
        wrong_domain_data,
    ] {
        let error = project(&arguments).expect_err("invalid input is refused");
        assert!(
            matches!(error, BRegOccurrenceError::InvalidInput { .. }),
            "{error}"
        );
        let message = error.to_string();
        assert!(!message.contains(secret), "{message}");
        assert!(!message.contains("SECRET"), "{message}");
    }
    let error = project(&wrong_record_member).expect_err("a missing member is refused");
    assert!(!error.to_string().contains(secret), "{error}");
}

#[test]
fn a_record_id_that_is_not_a_uuid_is_wrong_record_evidence() {
    let mut arguments = incorporation_arguments();
    arguments["record"]["recordIdentifier"] = json!("not-a-uuid");
    assert!(matches!(
        project(&arguments),
        Err(BRegOccurrenceError::WrongRecordEvidence { .. })
    ));
}

#[test]
fn error_codes_and_display_are_stable() {
    let cases = [
        (BRegOccurrenceError::NotAnOccurrence, "not-an-occurrence"),
        (
            BRegOccurrenceError::UnsupportedVersion { found: 9 },
            "unsupported-version",
        ),
        (
            BRegOccurrenceError::MalformedDescriptor {
                path: "label".into(),
            },
            "malformed-descriptor",
        ),
        (
            BRegOccurrenceError::WrongRecordEvidence { reason: "x".into() },
            "wrong-record-evidence",
        ),
        (
            BRegOccurrenceError::RevisionMismatch {
                expected: "1".into(),
                found: "2".into(),
            },
            "revision-mismatch",
        ),
        (
            BRegOccurrenceError::IncompatibleMetadata { reason: "x".into() },
            "incompatible-metadata",
        ),
        (
            BRegOccurrenceError::InvalidInput { reason: "x".into() },
            "invalid-input",
        ),
    ];
    for (error, code) in cases {
        assert_eq!(error.code(), code);
        assert!(!error.to_string().is_empty());
        assert!(!error.to_string().contains('\u{2014}'));
        let _: &dyn std::error::Error = &error;
    }
}

// ---- Typed entry point, metadata accessor, creation-revision document ----

fn registry_record(value: &Value) -> RegistryRecord {
    RegistryRecord {
        record_identifier: value["recordIdentifier"].as_str().expect("id").to_owned(),
        revision_identifier: value["revisionIdentifier"]
            .as_str()
            .expect("revision")
            .to_owned(),
        domain_data: value["domainData"]
            .as_object()
            .expect("domain data")
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        extensions: BTreeMap::new(),
    }
}

#[test]
fn the_typed_view_equals_the_json_view_for_the_same_evidence() {
    let descriptor =
        BRegOccurrenceDescriptor::from_value(&incorporation_descriptor()).expect("descriptor");
    let creation = BRegCreationRevision::from_document(
        INCORPORATION_ID,
        &creation_revision_envelope(INCORPORATION_ID, "1", Value::Null, "create"),
    )
    .expect("creation revision");
    let view = occurrence_view(
        REGISTRY_REVISION,
        "incorporation",
        &descriptor,
        &registry_record(&incorporation_record()),
        &BRegOccurrenceEvidence {
            creation_revision: Some(&creation),
            ..Default::default()
        },
    )
    .expect("typed view");
    let mut expected = expected_incorporation();
    expected["provenance"] = json!([]);
    assert_eq!(serde_json::to_value(&view).expect("view"), expected);
}

#[test]
fn typed_proposal_applications_are_projected_like_their_json_form() {
    let descriptor =
        BRegOccurrenceDescriptor::from_value(&transfer_descriptor()).expect("descriptor");
    let application: BRegProposalApplication = serde_json::from_value(json!({
        "applicationId": "b2000000-0000-4000-8000-000000000002", "submissionVersion": 3,
        "effectDigest": "sha256:00000000000000000000000000000000000000000000000000000000000000bb",
        "appliedAt": "2026-10-26T09:00:00Z",
        "resultLinks": [{"recordType": "ownership-transfer", "recordId": TRANSFER_ID, "revision": 1}]
    }))
    .expect("application");
    let applications = [&application];
    let view = occurrence_view(
        REGISTRY_REVISION,
        "ownership-transfer",
        &descriptor,
        &registry_record(&transfer_record()),
        &BRegOccurrenceEvidence {
            proposal_applications: &applications,
            ..Default::default()
        },
    )
    .expect("typed view");
    let view = serde_json::to_value(&view).expect("view");
    assert_eq!(
        view["provenance"],
        json!([{"kind": "proposal-application",
            "applicationId": "b2000000-0000-4000-8000-000000000002", "submissionVersion": 3,
            "appliedAt": "2026-10-26T09:00:00Z"}])
    );
}

fn creation_revision_envelope(
    record_id: &str,
    revision: &str,
    predecessor: Value,
    mutation_kind: &str,
) -> Value {
    json!({
        "data": {
            "recordIdentifier": record_id,
            "revisionIdentifier": revision,
            "domainData": {"company": COMPANY_ID},
            "predecessorRevision": predecessor,
            "lifecycle": "active",
            "packageRevision": REGISTRY_REVISION,
            "operationIdentifier": "records.incorporation.create",
            "mutationKind": mutation_kind,
            "createdAt": CREATED_AT,
            "actorReference": "actor-ref-1",
            "requestReference": "request-ref-1"
        },
        "meta": {"registryIdentifier": "registry", "datasetIdentifier": "dataset",
            "entityTypeIdentifier": "incorporation"}
    })
}

#[test]
fn from_document_accepts_only_the_creating_revision_of_the_record() {
    let creation = BRegCreationRevision::from_document(
        INCORPORATION_ID,
        &creation_revision_envelope(INCORPORATION_ID, "1", Value::Null, "create"),
    )
    .expect("revision 1 create");
    assert_eq!(
        serde_json::to_value(&creation).expect("serializes"),
        creation_revision_json()
    );

    let wrong_record = BRegCreationRevision::from_document(
        OTHER_TRANSFER_ID,
        &creation_revision_envelope(INCORPORATION_ID, "1", Value::Null, "create"),
    );
    assert!(matches!(
        wrong_record,
        Err(BRegOccurrenceError::WrongRecordEvidence { .. })
    ));
    for (document, label) in [
        (
            creation_revision_envelope(INCORPORATION_ID, "1", json!(0), "create"),
            "predecessor",
        ),
        (
            creation_revision_envelope(INCORPORATION_ID, "1", Value::Null, "update"),
            "mutation kind",
        ),
        (json!({"meta": {}}), "missing data"),
        (json!([]), "not an object"),
    ] {
        assert!(
            matches!(
                BRegCreationRevision::from_document(INCORPORATION_ID, &document),
                Err(BRegOccurrenceError::WrongRecordEvidence { .. })
            ),
            "{label}"
        );
    }
    let later = BRegCreationRevision::from_document(
        INCORPORATION_ID,
        &creation_revision_envelope(INCORPORATION_ID, "2", json!(1), "update"),
    );
    assert!(matches!(
        later,
        Err(BRegOccurrenceError::RevisionMismatch { ref expected, ref found })
            if expected == "1" && found == "2"
    ));
    let mut bad_time = creation_revision_envelope(INCORPORATION_ID, "1", Value::Null, "create");
    bad_time["data"]["createdAt"] = json!("yesterday");
    assert!(matches!(
        BRegCreationRevision::from_document(INCORPORATION_ID, &bad_time),
        Err(BRegOccurrenceError::WrongRecordEvidence { .. })
    ));
}

fn metadata_with(entities: Value) -> BRegMetadata {
    let document = json!({
        "id": "fixture-registry", "version": "1", "revision": REGISTRY_REVISION,
        "metadataVersion": "2", "recordTypes": entities, "operations": []
    });
    BRegMetadata::from_slice(&serde_json::to_vec(&document).expect("serializes"))
        .expect("metadata parses")
}

fn entity(id: &str, route: &str, occurrence: Option<Value>) -> Value {
    let mut value = json!({
        "id": id, "datasetIdentifier": "register", "route": route, "operations": [],
        "readableFields": [], "schema": format!("/v1/schemas/{id}")
    });
    if let Some(occurrence) = occurrence {
        value["occurrence"] = occurrence;
    }
    value
}

#[test]
fn metadata_exposes_the_descriptor_lazily_and_tolerates_a_bad_one() {
    let metadata = metadata_with(json!([
        entity(
            "incorporation",
            "incorporations",
            Some(incorporation_descriptor())
        ),
        entity("review-note", "review-notes", None),
        entity("broken", "brokens", Some(json!({"descriptorVersion": 1}))),
        entity(
            "future",
            "futures",
            Some({
                let mut descriptor = incorporation_descriptor();
                descriptor["descriptorVersion"] = json!(2);
                descriptor
            })
        ),
        entity("scalar", "scalars", Some(json!("occurrence")))
    ]));
    let descriptor = metadata
        .occurrence("incorporation")
        .expect("declared occurrence");
    assert_eq!(descriptor.to_value(), incorporation_descriptor());
    assert_eq!(
        descriptor,
        BRegOccurrenceDescriptor::from_value(&incorporation_descriptor()).expect("parses")
    );
    assert!(matches!(
        metadata.occurrence("review-note"),
        Err(BRegOccurrenceError::NotAnOccurrence)
    ));
    assert!(matches!(
        metadata.occurrence("not-visible"),
        Err(BRegOccurrenceError::NotAnOccurrence)
    ));
    assert!(matches!(
        metadata.occurrence("broken"),
        Err(BRegOccurrenceError::MalformedDescriptor { .. })
    ));
    assert!(matches!(
        metadata.occurrence("future"),
        Err(BRegOccurrenceError::UnsupportedVersion { .. })
    ));
    assert!(matches!(
        metadata.occurrence("scalar"),
        Err(BRegOccurrenceError::MalformedDescriptor { ref path }) if path == "occurrence"
    ));
}

// ---- Explicit read helper over an HTTP mock ----

#[derive(Clone)]
struct MockResponse {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl MockResponse {
    fn json(status: StatusCode, body: Value) -> Self {
        Self {
            status,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("traceparent".into(), TRACEPARENT.into()),
            ],
            body: serde_json::to_vec(&body).expect("fixture serializes"),
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.retain(|(existing, _)| existing != name);
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    fn problem(status: StatusCode, body: Value) -> Self {
        let mut response = Self::json(status, body);
        response.headers.retain(|(name, _)| name != "content-type");
        response
            .headers
            .push(("content-type".into(), "application/problem+json".into()));
        response
            .headers
            .push(("cache-control".into(), "no-store".into()));
        response
    }
}

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: String,
    uri: String,
}

#[derive(Clone)]
struct MockState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    responses: Arc<Mutex<VecDeque<MockResponse>>>,
}

async fn handler(State(state): State<MockState>, request: Request<Body>) -> Response<Body> {
    let captured = CapturedRequest {
        method: request.method().to_string(),
        uri: request.uri().to_string(),
    };
    to_bytes(request.into_body(), 1024 * 1024)
        .await
        .expect("bounded request body");
    state
        .requests
        .lock()
        .expect("request capture lock")
        .push(captured);
    let spec = state
        .responses
        .lock()
        .expect("response queue lock")
        .pop_front()
        .unwrap_or_else(|| {
            MockResponse::json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"unexpectedRequest": true}),
            )
        });
    let mut response = Response::new(Body::from(spec.body));
    *response.status_mut() = spec.status;
    for (name, value) in spec.headers {
        response.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("fixture header name"),
            HeaderValue::from_str(&value).expect("fixture header value"),
        );
    }
    response
}

#[derive(Debug)]
struct CountingToken(AtomicUsize);

#[async_trait]
impl TokenProvider for CountingToken {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        BearerToken::new("occurrence-test-token")
    }
}

struct TestClient {
    client: BaseRegistryClient,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

async fn test_client(responses: Vec<MockResponse>) -> TestClient {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        requests: requests.clone(),
        responses: Arc::new(Mutex::new(VecDeque::from(responses))),
    };
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock registry");
    let address = listener.local_addr().expect("mock address");
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(handler)).with_state(state),
        )
        .await
        .expect("serve mock registry");
    });
    let config = BaseRegistryClientConfig::new(
        Url::parse(&format!("http://{address}/tenant/base")).expect("base URL"),
    )
    .with_token_provider(Arc::new(CountingToken(AtomicUsize::new(0))))
    .with_maximum_mutation_retries(0);
    TestClient {
        client: BaseRegistryClient::new(config).expect("client"),
        requests,
    }
}

fn revision_response(document: Value) -> MockResponse {
    MockResponse::json(StatusCode::OK, document).with_header("link", RECORD_LINK)
}

fn problem_body(status: u16, title: &str, code: &str, detail: &str) -> Value {
    json!({
        "type": format!("https://id.registrystack.org/problems/registry-breg/{}", code.replace('.', "/")),
        "title": title, "status": status, "detail": detail, "code": code, "traceId": TRACE_ID
    })
}

#[tokio::test]
async fn the_creation_revision_helper_reads_exactly_revision_one() {
    let fixture = test_client(vec![revision_response(creation_revision_envelope(
        INCORPORATION_ID,
        "1",
        Value::Null,
        "create",
    ))])
    .await;
    let creation = fixture
        .client
        .occurrence_creation_revision("incorporations", INCORPORATION_ID, Some("history-reader"))
        .await
        .expect("read succeeds")
        .expect("a creation revision");
    assert_eq!(
        serde_json::to_value(&creation).expect("serializes"),
        creation_revision_json()
    );
    let requests = fixture.requests.lock().expect("requests").clone();
    assert_eq!(requests.len(), 1, "one exchange and no retry");
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].uri,
        format!("/tenant/base/v1/records/incorporations/{INCORPORATION_ID}/revisions/1?accessProfile=history-reader")
    );
}

#[tokio::test]
async fn a_concealed_or_absent_history_is_none_and_never_a_substitute_time() {
    let not_found = problem_body(
        404,
        "Not Found",
        "resource.not_found",
        "The requested resource was not found.",
    );
    let forbidden = problem_body(
        403,
        "Forbidden",
        "access.denied",
        "The caller may not read this history.",
    );
    for (status, body) in [
        (StatusCode::NOT_FOUND, not_found),
        (StatusCode::FORBIDDEN, forbidden),
    ] {
        let fixture = test_client(vec![MockResponse::problem(status, body)]).await;
        let result = fixture
            .client
            .occurrence_creation_revision("incorporations", INCORPORATION_ID, None)
            .await
            .expect("concealment is not an error");
        assert!(result.is_none(), "{status}");
        assert_eq!(fixture.requests.lock().expect("requests").len(), 1);
    }
}

#[tokio::test]
async fn other_failures_and_invalid_documents_stay_visible() {
    let unauthorized = problem_body(
        401,
        "Unauthorized",
        "authentication.refused",
        "The bearer credential is missing or refused.",
    );
    let fixture = test_client(vec![MockResponse::problem(
        StatusCode::UNAUTHORIZED,
        unauthorized,
    )])
    .await;
    assert!(fixture
        .client
        .occurrence_creation_revision("incorporations", INCORPORATION_ID, None)
        .await
        .is_err());

    let unavailable = problem_body(
        503,
        "Service Unavailable",
        "source.unavailable",
        "The Registry data service is unavailable.",
    );
    let fixture = test_client(vec![MockResponse::problem(
        StatusCode::SERVICE_UNAVAILABLE,
        unavailable,
    )])
    .await;
    assert!(fixture
        .client
        .occurrence_creation_revision("incorporations", INCORPORATION_ID, None)
        .await
        .is_err());

    // Revision 1 that is not a create, or whose predecessor is set, is not a
    // creation revision; the helper reports the protocol failure.
    for document in [
        creation_revision_envelope(INCORPORATION_ID, "1", Value::Null, "update"),
        creation_revision_envelope(INCORPORATION_ID, "1", json!(3), "create"),
    ] {
        let fixture = test_client(vec![revision_response(document)]).await;
        let error = fixture
            .client
            .occurrence_creation_revision("incorporations", INCORPORATION_ID, None)
            .await
            .expect_err("a non-create revision 1 is refused");
        assert!(
            matches!(error, BaseRegistryClientError::Protocol { .. }),
            "{error}"
        );
    }

    let fixture = test_client(vec![]).await;
    for (route, id) in [
        ("../incorporations", INCORPORATION_ID),
        ("incorporations", "arbitrary"),
    ] {
        assert!(fixture
            .client
            .occurrence_creation_revision(route, id, None)
            .await
            .is_err());
    }
    assert!(
        fixture.requests.lock().expect("requests").is_empty(),
        "invalid selectors fail before I/O"
    );
}

fn action_metadata() -> Value {
    json!({
        "id": "fixture-registry", "version": "1", "revision": REGISTRY_REVISION,
        "metadataVersion": "2", "recordTypes": [], "operations": [],
        "actions": [{
            "id": "incorporate-company", "apiName": "incorporateCompany",
            "revision": "sha256:00000000000000000000000000000000000000000000000000000000000000bb",
            "display": {}, "execution": {"mode": "immediate"},
            "route": "/v1/actions/incorporate-company", "conditionRoute": null,
            "inputMode": "fixed", "maximumInputStringBytes": null,
            "inputs": [{"id": "reference", "apiName": "reference", "required": true,
                "nullable": false, "classification": "internal",
                "schema": {"type": "string", "minLength": 1, "maxLength": 40},
                "fieldType": {"type": "string", "minimumLength": 1, "maximumLength": 40}}],
            "referenceInputs": [], "requiredConditionKeys": [],
            "resultEffects": [
                {"effect": "record-incorporation", "recordType": "incorporation", "operation": "create"},
                {"effect": "update-company", "recordType": "company", "operation": "patch"}],
            "access": {"selectedProfile": "preparer"},
            "routes": {
                "invoke": {"method": "POST", "path": "/v1/actions/incorporate-company",
                    "operationId": "actions.incorporate-company.invoke", "requiresIdempotencyKey": true,
                    "inputSchema": "action-incorporate-company-invoke-input",
                    "responseSchema": "action-incorporate-company-invoke-response"},
                "targetConditions": null},
            "bounds": {"maximumTargets": 4, "maximumFieldMutations": 8, "maximumSnapshotBytes": 1024}
        }]
    })
}

#[tokio::test]
async fn a_typed_action_receipt_projects_like_its_json_form() {
    let fixture = test_client(vec![
        MockResponse::json(StatusCode::OK, action_metadata()),
        MockResponse::json(StatusCode::OK, incorporation_receipt())
            .with_header("cache-control", "no-store")
            .with_header("vary", "authorization, accept"),
    ])
    .await;
    let metadata = fixture
        .client
        .registry_contract(Some("preparer"))
        .await
        .expect("metadata")
        .value;
    let action = metadata
        .select_action("incorporate-company", "preparer")
        .expect("the immediate action");
    let request = BRegActionInvocationRequest::new(
        &action,
        Map::from_iter([("reference".to_owned(), json!("APP-2026-0042"))]),
        None,
    )
    .expect("valid inputs");
    let receipt = fixture
        .client
        .invoke_action(
            &action,
            &request,
            &BRegIdempotencyKey::parse("incorporate-1").expect("key"),
        )
        .await
        .expect("the receipt")
        .value;

    let descriptor =
        BRegOccurrenceDescriptor::from_value(&incorporation_descriptor()).expect("descriptor");
    let creation: BRegCreationRevision =
        serde_json::from_value(creation_revision_json()).expect("creation revision");
    let receipts = [(&receipt, "record-incorporation")];
    let view = occurrence_view(
        REGISTRY_REVISION,
        "incorporation",
        &descriptor,
        &registry_record(&incorporation_record()),
        &BRegOccurrenceEvidence {
            creation_revision: Some(&creation),
            action_receipts: &receipts,
            proposal_applications: &[],
        },
    )
    .expect("typed view");
    assert_eq!(
        serde_json::to_value(&view).expect("view"),
        expect_view(&incorporation_arguments())
    );

    let mismatched = [(&receipt, "update-company")];
    let view = occurrence_view(
        REGISTRY_REVISION,
        "incorporation",
        &descriptor,
        &registry_record(&incorporation_record()),
        &BRegOccurrenceEvidence {
            action_receipts: &mismatched,
            ..Default::default()
        },
    )
    .expect("typed view");
    let view = serde_json::to_value(&view).expect("view");
    assert_eq!(view["provenance"], json!([]));
    assert_eq!(
        view["ignoredEvidence"][0]["reason"],
        json!("no-matching-result")
    );
    assert_eq!(
        OCCURRENCE_VIEW_CONTRACT,
        expected_incorporation()["contract"]
            .as_str()
            .expect("contract")
    );
}

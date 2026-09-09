//! Attachment slots are promoted only from an exact caller-filtered contract,
//! and an upload that the slot cannot accept is refused before any request.

use serde_json::{json, Value};

#[path = "../src/strict_json.rs"]
mod strict_json;

#[allow(dead_code)]
#[path = "../../registry-record/src/lib.rs"]
mod registry_record;
pub use registry_record::*;

#[allow(dead_code)]
#[path = "../src/lifecycle.rs"]
mod breg_lifecycle;
pub use breg_lifecycle::*;

#[allow(dead_code)]
#[path = "../src/attachment.rs"]
mod breg_attachment;
pub use breg_attachment::*;

#[allow(dead_code)]
#[path = "../src/metadata.rs"]
mod breg_metadata;

use breg_metadata::{BRegMetadata, BRegMetadataSelectionErrorKind};

const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SLOT: &str = "supporting-file";
const PATH: &str = "/v1/records/companies/{record_id}/attachments/supporting-file";

fn field(id: &str, api_name: &str) -> Value {
    json!({
        "id": id,
        "apiName": api_name,
        "label": "Response-controlled presentation",
        "schema": {"type": "string"},
        "required": true,
        "nullable": false,
        "readOnly": false,
        "removable": false
    })
}

fn operation(
    id: &str,
    method: &str,
    path: &str,
    kind: &str,
    request: Value,
    writable_fields: (Value, Value),
) -> Value {
    let (create_writable, patch_writable) = writable_fields;
    json!({
        "id": id,
        "method": method,
        "path": path,
        "operation": kind,
        "sourceEntity": "company",
        "responseEntity": "company",
        "accessProfile": "company-writer",
        "requiredCapabilities": [],
        "entityLabel": "Companies",
        "identifier": {"apiName": "id", "location": "envelope"},
        "titleFields": ["legal-name"],
        "fields": [field("legal-name", "legalName")],
        "readableFields": ["legal-name"],
        "createWritableFields": create_writable,
        "patchWritableFields": patch_writable,
        "selectors": [],
        "query": null,
        "request": request
    })
}

fn base_fixture() -> Value {
    let create_request = json!({
        "fieldNames": "api",
        "queryParameters": [],
        "body": "data_envelope",
        "contentType": "application/json",
        "idempotencyKeyRequired": true,
        "mutationSemantics": "direct",
        "schema": {"type": "object", "properties": {"data": {"type": "object"}}}
    });
    let patch_request = json!({
        "fieldNames": "api",
        "queryParameters": [],
        "body": "json_patch",
        "contentType": "application/json-patch+json",
        "patchPathPrefix": "/data/",
        "patchOperations": ["add", "replace", "remove", "test"],
        "removeSemantics": "set_null",
        "ifMatchRequired": true,
        "idempotencyKeyRequired": true,
        "mutationSemantics": "direct",
        "schema": {"type": "array", "items": {"oneOf": [{"type": "object"}]}}
    });
    let get_request = json!({"fieldNames": "api", "queryParameters": ["$select"]});
    json!({
        "id": "business-registry",
        "version": "1.2.3",
        "revision": REVISION,
        "metadataVersion": "1",
        "entities": [{
            "id": "company",
            "datasetIdentifier": "legal-entities",
            "route": "companies",
            "operations": [
                {"operation": "create", "accessProfile": "company-writer"},
                {"operation": "patch", "accessProfile": "company-writer"},
                {"operation": "get", "accessProfile": "company-writer"}
            ],
            "readableFields": ["legal-name"],
            "schema": "/v1/schemas/company"
        }],
        "operations": [
            operation("records.company.create", "POST", "/v1/records/companies", "create",
                create_request, (json!(["legal-name"]), json!([]))),
            operation("records.company.patch", "PATCH", "/v1/records/companies/{record_id}",
                "patch", patch_request, (json!([]), json!(["legal-name"]))),
            operation("records.company.get", "GET", "/v1/records/companies/{record_id}", "get",
                get_request, (json!([]), json!([])))
        ]
    })
}

/// The exact `x-registry-attachment` capability the engine serves for a slot
/// the caller may read, upload and remove.
fn descriptor() -> Value {
    json!({
        "requiredForSubmit": true,
        "maximumBytes": 1024,
        "contentTypes": ["application/pdf", "image/png"],
        "verification": {
            "statusField": "verificationStatus",
            "allowedStatuses": ["notRequired", "approved"],
            "pendingOrRejectedBlocks": ["download", "submit"]
        },
        "download": {"method": "GET", "path": PATH, "accessProfile": "company-writer",
            "authorizationOperation": "get", "queryParameters": ["proposalVersion"],
            "body": "none", "ifMatchRequired": false, "idempotencyKeyRequired": false,
            "proposalVersionRequired": true},
        "upload": {"method": "PATCH", "path": PATH, "accessProfile": "company-writer",
            "authorizationOperation": "patch", "queryParameters": [], "body": "binary",
            "ifMatchRequired": true, "idempotencyKeyRequired": true, "requiredState": "draft"},
        "remove": {"method": "DELETE", "path": PATH, "accessProfile": "company-writer",
            "authorizationOperation": "patch", "queryParameters": [], "body": "none",
            "ifMatchRequired": true, "idempotencyKeyRequired": true, "requiredState": "draft"}
    })
}

fn slot_field(descriptor: &Value) -> Value {
    json!({
        "id": SLOT,
        "apiName": SLOT,
        "label": "Supporting file",
        "schema": {
            "anyOf": [{"type": "null"}, {"type": "object"}],
            "readOnly": true,
            "x-registry-fieldKind": "attachment",
            "x-registry-attachment": descriptor
        },
        "required": false,
        "nullable": true,
        "readOnly": true,
        "removable": false
    })
}

/// Carry one slot descriptor on every caller-visible operation, exactly as the
/// engine repeats the merged capability across each surface.
fn fixture_with(descriptor: Value) -> Value {
    let mut value = base_fixture();
    for operation in value["operations"].as_array_mut().unwrap() {
        operation["fields"]
            .as_array_mut()
            .unwrap()
            .push(slot_field(&descriptor));
        operation["readableFields"]
            .as_array_mut()
            .unwrap()
            .push(json!(SLOT));
    }
    value
}

fn parse(value: &Value) -> BRegMetadata {
    BRegMetadata::from_slice(&serde_json::to_vec(value).unwrap())
        .expect("metadata conforms")
        .bind_source("https://registry.example/v1/".to_owned())
}

fn selected() -> BRegAttachmentSlot {
    parse(&fixture_with(descriptor()))
        .select_attachments("company", "company-writer")
        .expect("the served slot contract is complete")
        .remove(0)
}

#[test]
fn exact_slot_capability_promotes_every_advertised_route() {
    let slots = parse(&fixture_with(descriptor()))
        .select_attachments("company", "company-writer")
        .expect("the served slot contract is complete");
    assert_eq!(slots.len(), 1);
    let slot = &slots[0];
    assert_eq!(slot.slot_identifier(), SLOT);
    assert_eq!(slot.registry_identifier(), "business-registry");
    assert_eq!(slot.dataset_identifier(), "legal-entities");
    assert_eq!(slot.registry_revision(), REVISION);
    assert_eq!(slot.entity_identifier(), "company");
    assert_eq!(slot.access_profile(), "company-writer");
    assert!(slot.required_for_submit());
    assert_eq!(slot.maximum_bytes(), 1024);
    assert_eq!(slot.content_types(), ["application/pdf", "image/png"]);
    assert!(slot.accepts_content_type("image/png"));
    assert!(!slot.accepts_content_type("application/zip"));
    assert!(slot.can_download() && slot.can_upload() && slot.can_remove());
    assert!(
        !format!("{slot:?}").contains(SLOT),
        "a redacted Debug must not echo response-controlled identifiers"
    );
}

#[test]
fn a_read_only_caller_promotes_a_download_without_write_routes() {
    let mut descriptor = descriptor();
    let object = descriptor.as_object_mut().unwrap();
    object.remove("upload");
    object.remove("remove");
    let slot = parse(&fixture_with(descriptor))
        .select_attachments("company", "company-writer")
        .expect("a download-only slot is a complete contract")
        .remove(0);
    assert!(slot.can_download());
    assert!(!slot.can_upload() && !slot.can_remove());
    assert_eq!(
        BRegAttachmentUpload::new(&slot, "application/pdf", vec![1]).unwrap_err(),
        BRegAttachmentError::UploadNotAdvertised
    );
}

#[test]
fn selection_refuses_an_unbound_source_a_missing_entity_and_a_foreign_profile() {
    let metadata =
        BRegMetadata::from_slice(&serde_json::to_vec(&fixture_with(descriptor())).unwrap())
            .expect("metadata conforms");
    assert_eq!(
        metadata
            .select_attachments("company", "company-writer")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::UnboundSource
    );
    let metadata = parse(&fixture_with(descriptor()));
    assert_eq!(
        metadata
            .select_attachments("supplier", "company-writer")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::NotFound
    );
    assert_eq!(
        metadata
            .select_attachments("company", "company-reader")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::ProfileMismatch
    );
    assert_eq!(
        parse(&base_fixture())
            .select_attachments("company", "company-writer")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::NotFound,
        "an entity without slots has no attachment contract to promote"
    );
}

#[test]
fn selection_refuses_every_deviation_from_the_served_slot_contract() {
    for (label, mutate) in [
        (
            "a route that is not this slot's route",
            &(|value: &mut Value| {
                value["upload"]["path"] =
                    json!("/v1/records/companies/{record_id}/attachments/other")
            }) as &dyn Fn(&mut Value),
        ),
        (
            "an upload without a matching removal route",
            &|value: &mut Value| {
                value.as_object_mut().unwrap().remove("remove");
            },
        ),
        (
            "a download that does not require a proposal version",
            &|value: &mut Value| {
                value["download"]
                    .as_object_mut()
                    .unwrap()
                    .remove("proposalVersionRequired");
            },
        ),
        (
            "an upload that does not require If-Match",
            &|value: &mut Value| value["upload"]["ifMatchRequired"] = json!(false),
        ),
        (
            "an upload that does not require an idempotency key",
            &|value: &mut Value| value["upload"]["idempotencyKeyRequired"] = json!(false),
        ),
        (
            "an upload that is not bound to the selected profile",
            &|value: &mut Value| value["upload"]["accessProfile"] = json!("company-reader"),
        ),
        ("an upload outside the draft state", &|value: &mut Value| {
            value["upload"]["requiredState"] = json!("submitted")
        }),
        ("a relaxed verification policy", &|value: &mut Value| {
            value["verification"]["allowedStatuses"] =
                json!(["notRequired", "approved", "pending"]);
        }),
        (
            "a capacity beyond the engine bound",
            &|value: &mut Value| value["maximumBytes"] = json!(16 * 1024 * 1024 + 1),
        ),
        ("a slot that accepts nothing", &|value: &mut Value| {
            value["contentTypes"] = json!([])
        }),
        (
            "a content type that is not a concrete media type",
            &|value: &mut Value| value["contentTypes"] = json!(["application/*"]),
        ),
        ("a duplicated content type", &|value: &mut Value| {
            value["contentTypes"] = json!(["application/pdf", "application/pdf"])
        }),
        ("an unknown capability member", &|value: &mut Value| {
            value["retentionDays"] = json!(30)
        }),
    ] {
        let mut value = descriptor();
        mutate(&mut value);
        assert_eq!(
            parse(&fixture_with(value))
                .select_attachments("company", "company-writer")
                .unwrap_err()
                .kind(),
            BRegMetadataSelectionErrorKind::ContractMismatch,
            "{label} must not promote"
        );
    }
}

#[test]
fn selection_refuses_capabilities_that_disagree_across_surfaces() {
    let mut value = fixture_with(descriptor());
    value["operations"][2]["fields"][1]["schema"]["x-registry-attachment"]["maximumBytes"] =
        json!(2048);
    assert_eq!(
        parse(&value)
            .select_attachments("company", "company-writer")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::ContractMismatch
    );
}

#[test]
fn an_upload_is_refused_before_any_request_when_the_slot_cannot_accept_it() {
    let slot = selected();
    for (label, content_type, bytes, expected) in [
        (
            "an empty body",
            "application/pdf",
            Vec::new(),
            BRegAttachmentError::EmptyUpload,
        ),
        (
            "a body beyond the slot capacity",
            "application/pdf",
            vec![0u8; 1025],
            BRegAttachmentError::UploadTooLarge,
        ),
        (
            "a content type outside the slot policy",
            "application/zip",
            vec![1],
            BRegAttachmentError::ContentTypeNotAccepted,
        ),
        (
            "a parameterised content type",
            "application/pdf; charset=utf-8",
            vec![1],
            BRegAttachmentError::InvalidContentType,
        ),
        (
            "a wildcard content type",
            "application/*",
            vec![1],
            BRegAttachmentError::InvalidContentType,
        ),
        (
            "an uppercase content type the engine compares byte for byte",
            "Application/PDF",
            vec![1],
            BRegAttachmentError::InvalidContentType,
        ),
    ] {
        let refusal = BRegAttachmentUpload::new(&slot, content_type, bytes)
            .expect_err("the client refuses locally");
        assert_eq!(refusal, expected, "{label} must be refused");
        assert!(!refusal.reason().is_empty());
    }
    let accepted = BRegAttachmentUpload::new(&slot, "application/pdf", vec![0u8; 1024])
        .expect("a body at the slot capacity is accepted");
    assert_eq!(accepted.content_type(), "application/pdf");
    assert_eq!(accepted.byte_size(), 1024);
    assert!(!format!("{accepted:?}").contains("bytes"));
}

fn record(domain_data: Value) -> RegistryRecord {
    RegistryRecord {
        record_identifier: "00000000-0000-4000-8000-000000000001".to_owned(),
        revision_identifier: "1".to_owned(),
        domain_data: serde_json::from_value(domain_data).expect("object"),
        extensions: Default::default(),
    }
}

fn live_value() -> Value {
    json!({
        "slotId": SLOT,
        "proposalVersion": 2,
        "filled": true,
        "sha256": DIGEST,
        "byteSize": 12,
        "erased": false,
        "contentType": "application/pdf",
        "uploadedAt": "2026-01-02T03:04:05.000000Z",
        "uploadedBy": "urn:registry:actor:reviewer",
        "verificationStatus": "approved"
    })
}

#[test]
fn a_records_slot_state_is_read_from_the_engine_owned_projection() {
    let slot = selected();
    assert_eq!(
        slot.value_in(&record(json!({"legalName": "Acme"})))
            .unwrap(),
        BRegAttachmentSlotValue::NotSelected
    );
    assert_eq!(
        slot.value_in(&record(json!({SLOT: Value::Null}))).unwrap(),
        BRegAttachmentSlotValue::Empty
    );
    let value = slot.value_in(&record(json!({SLOT: live_value()}))).unwrap();
    let state = value.filled().expect("a filled slot");
    assert_eq!(state.slot_identifier(), SLOT);
    assert_eq!(state.proposal_version(), 2);
    assert!(!state.erased());
    assert_eq!(state.byte_size(), 12);
    assert_eq!(state.sha256(), DIGEST);
    assert_eq!(state.content_type(), Some("application/pdf"));
    assert_eq!(state.uploaded_at(), Some("2026-01-02T03:04:05.000000Z"));
    assert_eq!(state.uploaded_by(), Some("urn:registry:actor:reviewer"));
    assert_eq!(
        state.verification_status(),
        Some(BRegAttachmentVerificationStatus::Approved)
    );
    assert!(state.verification_status().unwrap().released());
}

#[test]
fn an_erased_slot_value_keeps_only_the_retained_members() {
    let slot = selected();
    let erased = json!({
        "slotId": SLOT, "proposalVersion": 1, "filled": true,
        "sha256": DIGEST, "byteSize": 12, "erased": true
    });
    let value = slot.value_in(&record(json!({SLOT: erased}))).unwrap();
    let state = value.filled().expect("an erased slot is still filled");
    assert!(state.erased());
    assert_eq!(state.content_type(), None);
    assert_eq!(state.uploaded_at(), None);
    assert_eq!(state.uploaded_by(), None);
    assert_eq!(state.verification_status(), None);
}

#[test]
fn a_retained_value_may_predate_a_narrower_upload_policy() {
    let slot = selected();
    let mut value = live_value();
    value["contentType"] = json!("application/vnd.oasis.opendocument.text");
    let value = slot.value_in(&record(json!({SLOT: value}))).unwrap();
    assert_eq!(
        value.filled().unwrap().content_type(),
        Some("application/vnd.oasis.opendocument.text"),
        "a stored content type is reported even when the slot no longer accepts it"
    );
}

#[test]
fn a_slot_value_outside_the_served_schema_is_refused() {
    let slot = selected();
    for (label, mutate) in [
        (
            "another slot's value",
            &(|value: &mut Value| value["slotId"] = json!("other")) as &dyn Fn(&mut Value),
        ),
        ("an unfilled marker", &|value: &mut Value| {
            value["filled"] = json!(false)
        }),
        ("a zero proposal version", &|value: &mut Value| {
            value["proposalVersion"] = json!(0)
        }),
        ("an uppercase digest", &|value: &mut Value| {
            value["sha256"] = json!(DIGEST.to_uppercase())
        }),
        ("a truncated digest", &|value: &mut Value| {
            value["sha256"] = json!(&DIGEST[..63])
        }),
        ("a zero byte size", &|value: &mut Value| {
            value["byteSize"] = json!(0)
        }),
        (
            "a byte size beyond the engine bound",
            &|value: &mut Value| value["byteSize"] = json!(16 * 1024 * 1024 + 1),
        ),
        (
            "an unregistered verification status",
            &|value: &mut Value| value["verificationStatus"] = json!("verified"),
        ),
        (
            "a live value missing its content type",
            &|value: &mut Value| {
                value.as_object_mut().unwrap().remove("contentType");
            },
        ),
        (
            "an erased value keeping live members",
            &|value: &mut Value| value["erased"] = json!(true),
        ),
        ("an unknown member", &|value: &mut Value| {
            value["retainedUntil"] = json!("2030-01-01")
        }),
        (
            "a control character in an actor reference",
            &|value: &mut Value| value["uploadedBy"] = json!("urn:registry:actor:\u{7}"),
        ),
    ] {
        let mut value = live_value();
        mutate(&mut value);
        assert_eq!(
            slot.value_in(&record(json!({SLOT: value}))).unwrap_err(),
            BRegAttachmentError::InvalidSlotValue,
            "{label} must be refused"
        );
    }
}

#[test]
fn a_pending_or_rejected_verification_does_not_release_content() {
    for (status, released) in [
        (BRegAttachmentVerificationStatus::NotRequired, true),
        (BRegAttachmentVerificationStatus::Pending, false),
        (BRegAttachmentVerificationStatus::Approved, true),
        (BRegAttachmentVerificationStatus::Rejected, false),
    ] {
        assert_eq!(status.released(), released, "{}", status.as_str());
    }
    assert_eq!(
        BRegAttachmentVerificationStatus::NotRequired.as_str(),
        "notRequired"
    );
}

/// A list surface repeats the slot in its selectable fields, where the slot
/// identifier is the verbatim API property name.
fn list_operation(descriptor: &Value, api_name: &str) -> Value {
    let mut value = operation(
        "records.company.list",
        "GET",
        "/v1/records/companies",
        "list",
        json!({"fieldNames": "api", "queryParameters": ["$select", "$top"]}),
        (json!([]), json!([])),
    );
    value["fields"]
        .as_array_mut()
        .unwrap()
        .push(slot_field(descriptor));
    value["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!(SLOT));
    value["query"] = json!({
        "kind": "list",
        "selectableFields": [
            {"id": "legal-name", "apiName": "legalName"},
            {"id": SLOT, "apiName": api_name}
        ],
        "filterableFields": [],
        "sortableFields": [],
        "allowCount": false,
        "defaultPageSize": 100,
        "maxPageSize": 100,
        "maxFilterClauses": 32,
        "maxInValues": 100,
        "pagination": {
            "parameter": "$skiptoken",
            "responsePath": "pageInfo.nextCursor",
            "exclusive": true
        },
        "temporal": null
    });
    value
}

fn fixture_with_list(api_name: &str) -> Value {
    let descriptor = descriptor();
    let mut value = fixture_with(descriptor.clone());
    value["operations"]
        .as_array_mut()
        .unwrap()
        .push(list_operation(&descriptor, api_name));
    value["entities"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .push(json!({"operation": "list", "accessProfile": "company-writer"}));
    value
}

#[test]
fn a_listed_slot_keeps_its_verbatim_api_property_name() {
    let slots = parse(&fixture_with_list(SLOT))
        .select_attachments("company", "company-writer")
        .expect("a list surface repeats the same slot capability");
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].slot_identifier(), SLOT);
}

#[test]
fn a_listed_field_that_is_not_a_slot_keeps_strict_api_naming() {
    let mut value = fixture_with_list(SLOT);
    value["operations"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()["query"]["selectableFields"][0]["apiName"] = json!("legal-name");
    assert!(
        BRegMetadata::from_slice(&serde_json::to_vec(&value).unwrap()).is_err(),
        "an ordinary field must not borrow the verbatim slot naming"
    );
}

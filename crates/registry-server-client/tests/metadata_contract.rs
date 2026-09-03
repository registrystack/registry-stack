use serde_json::{json, Value};
use uuid::Uuid;

#[path = "../src/strict_json.rs"]
mod strict_json;

#[allow(dead_code)]
#[path = "../../registry-record/src/lib.rs"]
mod registry_record;
pub use registry_record::*;

#[allow(dead_code)]
#[path = "../src/lifecycle.rs"]
mod server_lifecycle;
pub use server_lifecycle::*;

#[allow(dead_code)]
#[path = "../src/metadata.rs"]
mod server_metadata;

use server_metadata::{
    RegistryServerChangeRequestApplicationMode, RegistryServerChangeRequestDisposition,
    RegistryServerChangeRequestPlannerKind, RegistryServerChangeRequestReviewMode,
    RegistryServerDirectWrite, RegistryServerMetadata, RegistryServerMetadataErrorKind,
    RegistryServerMetadataSelectionErrorKind, RegistryServerOperationKind,
};

const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn field(id: &str, api_name: &str) -> Value {
    json!({
        "id": id,
        "apiName": api_name,
        "label": "Response-controlled presentation",
        "schema": {
            "type": "string",
            "x-future-schema-key": {"kept": true}
        },
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
    required_capabilities: Value,
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
        "requiredCapabilities": required_capabilities,
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

fn fixture() -> Value {
    let create_request = json!({
        "fieldNames": "api",
        "queryParameters": [],
        "body": "data_envelope",
        "contentType": "application/json",
        "idempotencyKeyRequired": true,
        "mutationSemantics": "direct",
        "schema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["data"],
            "properties": {"data": {"type": "object"}},
            "x-open-extension": "retained"
        }
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
            operation(
                "records.company.create", "POST", "/v1/records/companies", "create",
                json!([]), create_request, (json!(["legal-name"]), json!([]))
            ),
            operation(
                "records.company.patch", "PATCH", "/v1/records/companies/{record_id}", "patch",
                json!([]), patch_request, (json!([]), json!(["legal-name"]))
            ),
            operation(
                "records.company.get", "GET", "/v1/records/companies/{record_id}", "get",
                json!([]), get_request, (json!([]), json!([]))
            )
        ],
        "actions": [{"id": "future-action", "openShape": {"retained": true}}]
    })
}

fn lifecycle_schema(kind: &str) -> Value {
    match kind {
        "approve_request" => json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "required": ["proposalVersion", "effectDigest"],
            "properties": {
                "proposalVersion": {
                    "type": "integer", "format": "int64", "minimum": 1,
                    "maximum": 4294967295_u64
                },
                "effectDigest": {
                    "type": "string",
                    "pattern": "^sha256:[0-9a-f]{64}$",
                    "description": "Digest of the immutable proposal effects displayed to the actor."
                }
            }
        }),
        _ => json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }),
    }
}

fn lifecycle_fixture() -> Value {
    let mut value = fixture();
    let mut lifecycle_operations = Vec::new();
    let mut summaries = Vec::new();
    for (id, path, kind) in [
        (
            "records.company.request.submit",
            "/v1/records/companies/{record_id}/actions/submit",
            "submit_request",
        ),
        (
            "records.company.request.stages.legal-review.approve",
            "/v1/records/companies/{record_id}/actions/stages/legal-review/approve",
            "approve_request",
        ),
    ] {
        lifecycle_operations.push(operation(
            id,
            "POST",
            path,
            kind,
            json!(["change_request_lifecycle"]),
            json!({
                "fieldNames": "api",
                "queryParameters": [],
                "body": "change_request_action",
                "contentType": "application/json",
                "ifMatchRequired": true,
                "idempotencyKeyRequired": true,
                "mutationSemantics": "change_request_lifecycle",
                "schema": lifecycle_schema(kind)
            }),
            (json!([]), json!([])),
        ));
        summaries.push(json!({"operation": kind, "accessProfile": "company-writer"}));
    }
    value["operations"]
        .as_array_mut()
        .unwrap()
        .extend(lifecycle_operations);
    value["entities"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .extend(summaries);
    value
}

fn parse(value: &Value) -> RegistryServerMetadata {
    RegistryServerMetadata::from_slice(&serde_json::to_vec(value).unwrap())
        .unwrap()
        .bind_source("https://registry.example/v1/".to_owned())
}

#[test]
fn runtime_v1_promotes_only_exact_direct_create_and_patch_contracts() {
    let metadata = parse(&fixture());
    assert_eq!(metadata.registry_identifier(), "business-registry");
    assert_eq!(metadata.registry_version(), "1.2.3");
    assert_eq!(metadata.registry_revision(), REVISION);
    assert_eq!(metadata.operations().len(), 3);
    assert!(metadata.actions().is_some());
    assert_eq!(
        metadata.operations()[0].fields()[0].schema()["x-future-schema-key"]["kept"],
        true
    );

    let RegistryServerDirectWrite::Create(create) = metadata
        .select_direct_write("records.company.create", "company-writer")
        .unwrap()
    else {
        panic!("Create binding expected")
    };
    assert_eq!(create.registry_identifier(), "business-registry");
    assert_eq!(create.dataset_identifier(), "legal-entities");
    assert_eq!(create.registry_revision(), REVISION);
    assert_eq!(create.operation_identifier(), "records.company.create");
    assert_eq!(create.access_profile(), "company-writer");
    assert_eq!(create.entity_identifier(), "company");
    assert_eq!(create.path(), "/v1/records/companies");
    assert_eq!(
        create.writable_api_names(),
        &std::collections::BTreeSet::from(["legalName".to_owned()])
    );
    assert_eq!(
        create.required_api_names(),
        &std::collections::BTreeSet::from(["legalName".to_owned()])
    );
    assert!(create.matches_source("https://registry.example/v1/"));
    assert_eq!(create.request_schema()["x-open-extension"], "retained");

    let RegistryServerDirectWrite::Patch(patch) = metadata
        .select_direct_write("records.company.patch", "company-writer")
        .unwrap()
    else {
        panic!("PATCH binding expected")
    };
    assert_eq!(patch.registry_identifier(), "business-registry");
    assert_eq!(patch.dataset_identifier(), "legal-entities");
    assert_eq!(patch.registry_revision(), REVISION);
    assert_eq!(patch.operation_identifier(), "records.company.patch");
    assert_eq!(patch.access_profile(), "company-writer");
    assert_eq!(patch.entity_identifier(), "company");
    assert_eq!(
        patch.writable_api_names(),
        &std::collections::BTreeSet::from(["legalName".to_owned()])
    );
    assert_eq!(
        patch.readable_api_names(),
        &std::collections::BTreeSet::from(["legalName".to_owned()])
    );
    assert!(patch.removable_api_names().is_empty());
    assert!(patch.matches_source("https://registry.example/v1/"));
    assert_eq!(
        patch.path_for_record(Uuid::parse_str("00000000-0000-4000-8000-000000000042").unwrap()),
        "/v1/records/companies/00000000-0000-4000-8000-000000000042"
    );

    let error = metadata
        .select_direct_write("records.company.get", "company-writer")
        .unwrap_err();
    assert_eq!(
        error.kind(),
        RegistryServerMetadataSelectionErrorKind::UnsupportedOperation
    );
}

#[test]
fn change_request_capability_is_strict_typed_and_never_creates_authority() {
    let capability = json!({
        "planner": {
            "kind": "rhai",
            "abi": "registry.change-request-plan/v1",
            "limits": {
                "maximumTargets": 16,
                "maximumFieldMutations": 128,
                "maximumSnapshotBytes": 2_097_152,
                "maximumSourceBytes": 65_536,
                "maximumOperations": 100_000,
                "maximumCallDepth": 32,
                "maximumExpressionDepth": 64,
                "maximumStringBytes": 16_384,
                "maximumArrayItems": 256,
                "maximumMapEntries": 256,
                "maximumModules": 0
            },
            "possibleWriteCount": 1,
            "possibleWriteOperations": ["patch"]
        },
        "reviewMode": "none",
        "application": {
            "mode": "planner",
            "allowedDispositions": ["apply", "queue"],
            "queueReasons": [{"code": "manual-check", "label": "Manual check"}]
        }
    });
    let mut value = fixture();
    value["entities"][0]["changeRequest"] = capability.clone();
    let metadata = parse(&value);
    let change_request = metadata
        .change_request_capability("company")
        .expect("visible request capability is typed");
    assert_eq!(
        change_request.planner().kind(),
        RegistryServerChangeRequestPlannerKind::Rhai
    );
    assert_eq!(
        change_request.planner().abi(),
        Some("registry.change-request-plan/v1")
    );
    let limits = change_request
        .planner()
        .limits()
        .expect("Rhai limits exist");
    assert_eq!(limits.maximum_targets(), 16);
    assert_eq!(limits.maximum_field_mutations(), 128);
    assert_eq!(limits.maximum_snapshot_bytes(), 2_097_152);
    assert_eq!(limits.maximum_source_bytes(), 65_536);
    assert_eq!(limits.maximum_operations(), 100_000);
    assert_eq!(limits.maximum_call_depth(), 32);
    assert_eq!(limits.maximum_expression_depth(), 64);
    assert_eq!(limits.maximum_string_bytes(), 16_384);
    assert_eq!(limits.maximum_array_items(), 256);
    assert_eq!(limits.maximum_map_entries(), 256);
    assert_eq!(limits.maximum_modules(), 0);
    assert_eq!(change_request.planner().possible_write_count(), Some(1));
    assert!(matches!(
        change_request.planner().possible_write_operations(),
        [RegistryServerOperationKind::Patch]
    ));
    assert_eq!(
        change_request.review_mode(),
        RegistryServerChangeRequestReviewMode::None
    );
    assert_eq!(
        change_request.application().mode(),
        RegistryServerChangeRequestApplicationMode::Planner
    );
    assert_eq!(
        change_request.application().allowed_dispositions(),
        [
            RegistryServerChangeRequestDisposition::Apply,
            RegistryServerChangeRequestDisposition::Queue
        ]
    );
    assert_eq!(
        change_request.application().queue_reasons()[0].code(),
        "manual-check"
    );
    assert_eq!(
        change_request.application().queue_reasons()[0].label(),
        "Manual check"
    );
    assert!(!format!("{change_request:?}").contains("Manual check"));
    assert!(matches!(
        metadata
            .select_direct_write("records.company.patch", "company-writer")
            .expect("descriptive capability does not alter direct-write authority"),
        RegistryServerDirectWrite::Patch(_)
    ));

    for malformed in [
        {
            let mut malformed = capability.clone();
            malformed["planner"]["source"] = json!("scripts/private.rhai");
            malformed
        },
        {
            let mut malformed = capability.clone();
            malformed["planner"]["limits"]["maximumModules"] = json!(1);
            malformed
        },
        {
            let mut malformed = capability;
            malformed["planner"]["possibleWriteOperations"] = json!(["patch", "patch"]);
            malformed
        },
    ] {
        let mut value = fixture();
        value["entities"][0]["changeRequest"] = malformed;
        assert!(RegistryServerMetadata::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}

#[test]
fn duplicate_json_members_are_refused_at_every_depth() {
    let duplicate_root = format!(
        r#"{{"id":"business-registry","id":"attacker","version":"1","revision":"{REVISION}","metadataVersion":"1","entities":[],"operations":[]}}"#
    );
    let error = RegistryServerMetadata::from_slice(duplicate_root.as_bytes()).unwrap_err();
    assert_eq!(
        error.kind(),
        RegistryServerMetadataErrorKind::DuplicateMember
    );

    let nested = format!(
        r#"{{"id":"business-registry","version":"1","revision":"{REVISION}","metadataVersion":"1","entities":[],"operations":[],"extension":{{"key":1,"key":2}}}}"#
    );
    let error = RegistryServerMetadata::from_slice(nested.as_bytes()).unwrap_err();
    assert_eq!(
        error.kind(),
        RegistryServerMetadataErrorKind::DuplicateMember
    );
}

#[test]
fn legacy_entity_summary_cannot_grant_operation_authority() {
    let legacy = json!({
        "registryId": "business-registry",
        "version": "1",
        "entities": [{
            "id": "company",
            "route": "companies",
            "schemaPath": "/v1/schemas/company",
            "entries": [{
                "routeId": "records.company.create",
                "operation": "create",
                "accessProfile": "company-writer",
                "responseEntityId": "company",
                "readableFields": ["legal-name"]
            }]
        }]
    });
    let error = RegistryServerMetadata::from_slice(&serde_json::to_vec(&legacy).unwrap())
        .expect_err("generated legacy metadata is not runtime authority");
    assert_eq!(error.kind(), RegistryServerMetadataErrorKind::Shape);

    let mut incomplete = fixture();
    incomplete["operations"] = json!([]);
    let error = RegistryServerMetadata::from_slice(&serde_json::to_vec(&incomplete).unwrap())
        .expect_err("entity summaries cannot stand in for operations");
    assert_eq!(
        error.kind(),
        RegistryServerMetadataErrorKind::DanglingReference
    );
}

#[test]
fn unknown_capability_and_kind_remain_discoverable_but_inert() {
    let mut capability = fixture();
    capability["operations"][0]["requiredCapabilities"] = json!(["future_write_protocol"]);
    let metadata = parse(&capability);
    assert_eq!(
        metadata
            .select_direct_write("records.company.create", "company-writer")
            .unwrap_err()
            .kind(),
        RegistryServerMetadataSelectionErrorKind::RequiredCapability
    );

    let mut unknown = fixture();
    unknown["operations"][0]["operation"] = json!("future_mutation");
    unknown["entities"][0]["operations"][0]["operation"] = json!("future_mutation");
    let metadata = parse(&unknown);
    assert!(matches!(
        metadata.operations()[0].kind(),
        RegistryServerOperationKind::Unknown(value) if value == "future_mutation"
    ));
    assert_eq!(
        metadata
            .select_direct_write("records.company.create", "company-writer")
            .unwrap_err()
            .kind(),
        RegistryServerMetadataSelectionErrorKind::UnsupportedOperation
    );
}

#[test]
fn execution_selection_requires_exact_source_and_profile_binding() {
    let inert =
        RegistryServerMetadata::from_slice(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
    assert_eq!(
        inert
            .select_direct_write("records.company.create", "company-writer")
            .unwrap_err()
            .kind(),
        RegistryServerMetadataSelectionErrorKind::UnboundSource
    );

    let metadata = inert.bind_source("https://registry.example/v1/".to_owned());
    assert_eq!(
        metadata
            .select_direct_write("records.company.create", "other-profile")
            .unwrap_err()
            .kind(),
        RegistryServerMetadataSelectionErrorKind::ProfileMismatch
    );
}

#[test]
fn lifecycle_authority_requires_exact_profile_capability_schema_and_routes() {
    let metadata = parse(&lifecycle_fixture());
    let authority = metadata
        .select_lifecycle("company", "company-writer")
        .expect("exact lifecycle authority");
    assert_eq!(authority.registry_revision(), REVISION);
    assert!(format!("{authority:?}").contains("operation_count: 2"));

    assert_eq!(
        metadata
            .select_lifecycle("company", "other-profile")
            .unwrap_err()
            .kind(),
        RegistryServerMetadataSelectionErrorKind::ProfileMismatch
    );

    let mut malformed = lifecycle_fixture();
    malformed["operations"][3]["request"]["schema"]["additionalProperties"] = json!(true);
    let metadata = parse(&malformed);
    assert_eq!(
        metadata
            .select_lifecycle("company", "company-writer")
            .unwrap_err()
            .kind(),
        RegistryServerMetadataSelectionErrorKind::ContractMismatch
    );
}

#[test]
fn malformed_bindings_and_cross_field_references_fail_closed() {
    let mut duplicate_actions = fixture();
    duplicate_actions["actions"] = json!([
        {"id": "future-action"},
        {"id": "future-action", "unknownProtocol": true}
    ]);
    assert_eq!(
        RegistryServerMetadata::from_slice(&serde_json::to_vec(&duplicate_actions).unwrap())
            .unwrap_err()
            .kind(),
        RegistryServerMetadataErrorKind::DuplicateIdentifier
    );

    let mut unknown_root = fixture();
    unknown_root["futureAuthority"] = json!({"operation": "create"});
    assert_eq!(
        RegistryServerMetadata::from_slice(&serde_json::to_vec(&unknown_root).unwrap())
            .unwrap_err()
            .kind(),
        RegistryServerMetadataErrorKind::Shape
    );

    let mut mismatch = fixture();
    mismatch["operations"][0]["path"] = json!("/v1/records/other");
    let metadata = parse(&mismatch);
    assert_eq!(
        metadata
            .select_direct_write("records.company.create", "company-writer")
            .unwrap_err()
            .kind(),
        RegistryServerMetadataSelectionErrorKind::ContractMismatch
    );

    let mut dangling = fixture();
    dangling["operations"][0]["responseEntity"] = json!("hidden-company");
    assert_eq!(
        RegistryServerMetadata::from_slice(&serde_json::to_vec(&dangling).unwrap())
            .unwrap_err()
            .kind(),
        RegistryServerMetadataErrorKind::DanglingReference
    );

    let mut duplicate = fixture();
    duplicate["operations"][1]["id"] = duplicate["operations"][0]["id"].clone();
    assert_eq!(
        RegistryServerMetadata::from_slice(&serde_json::to_vec(&duplicate).unwrap())
            .unwrap_err()
            .kind(),
        RegistryServerMetadataErrorKind::DuplicateIdentifier
    );
}

#[test]
fn metadata_version_revision_and_resource_bounds_are_exact() {
    for invalid in ["0", "2", "1.0"] {
        let mut value = fixture();
        value["metadataVersion"] = json!(invalid);
        assert_eq!(
            RegistryServerMetadata::from_slice(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .kind(),
            RegistryServerMetadataErrorKind::Version
        );
    }
    for invalid in [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "sha256:aaaaaaaa",
    ] {
        let mut value = fixture();
        value["revision"] = json!(invalid);
        assert_eq!(
            RegistryServerMetadata::from_slice(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .kind(),
            RegistryServerMetadataErrorKind::Revision
        );
    }

    let mut deep = fixture();
    let mut nested = json!(null);
    for _ in 0..40 {
        nested = json!([nested]);
    }
    deep["extension"] = nested;
    assert_eq!(
        RegistryServerMetadata::from_slice(&serde_json::to_vec(&deep).unwrap())
            .unwrap_err()
            .kind(),
        RegistryServerMetadataErrorKind::Bound
    );
}

#[test]
fn debug_and_errors_do_not_render_response_controlled_values() {
    let canary = "citizen-national-identifier-canary";
    let malformed = format!("{{\"{canary}\":");
    let error = RegistryServerMetadata::from_slice(malformed.as_bytes()).unwrap_err();
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(canary));

    let mut value = fixture();
    value["id"] = json!(canary);
    let metadata = parse(&value);
    let rendered = format!("{metadata:?}");
    assert!(!rendered.contains(canary));

    let selection = metadata
        .select_direct_write(canary, "company-writer")
        .unwrap_err();
    let rendered = format!("{selection:?} {selection}");
    assert!(!rendered.contains(canary));
}

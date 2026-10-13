use serde_json::{json, Value};
use uuid::Uuid;
use crate::*;

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
        "sourceRecordType": "company",
        "responseRecordType": "company",
        "accessProfile": "company-writer",
        "requiredCapabilities": required_capabilities,
        "recordTypeLabel": "Companies",
        "identifier": {"apiName": "id", "location": "envelope"},
        "titleFields": ["legal-name"],
        "fields": [field("legal-name", "legalName")],
        "readableFields": ["legal-name"],
        "readableRequestFields": [],
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
        "recordTypes": [{
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





fn parse(value: &Value) -> BRegMetadata {
    BRegMetadata::from_slice(&serde_json::to_vec(value).unwrap())
        .unwrap()
        .bind_source("https://registry.example/v1/".to_owned())
}

fn statistical_dataset() -> Value {
    json!({
        "id": "company-counts",
        "unit": "company",
        "periodKind": "flow",
        "granularity": "month",
        "firstPeriod": "2025-01",
        "dimensions": [{
            "field": "category",
            "vocabulary": "company-category",
            "codes": ["Registered", "other", "_U", "_T"]
        }],
        "definitionDigest": REVISION,
        "operations": ["read-live", "list-releases", "read-latest-release", "read-release-version", "read-released-series"]
    })
}

#[test]
fn runtime_v1_accepts_statistical_datasets_without_adding_entity_authority() {
    let mut mixed = fixture();
    mixed["statisticalDatasets"] = json!([statistical_dataset()]);
    let metadata = parse(&mixed);
    assert_eq!(
        metadata.statistical_datasets(),
        Some(&mixed["statisticalDatasets"])
    );
    assert_eq!(metadata.operations().len(), 3);
    assert!(metadata
        .select_direct_write("records.company.create", "company-writer")
        .is_ok());

    let mut release_only = mixed;
    release_only["recordTypes"] = json!([]);
    release_only["operations"] = json!([]);
    release_only["statisticalDatasets"][0]["operations"] = json!([
        "list-releases",
        "read-latest-release",
        "read-release-version",
        "read-released-series"
    ]);
    release_only.as_object_mut().unwrap().remove("actions");
    let metadata = parse(&release_only);
    assert!(metadata.operations().is_empty());
    assert_eq!(
        metadata.statistical_datasets(),
        Some(&release_only["statisticalDatasets"])
    );
    assert_eq!(
        metadata
            .select_direct_write("records.company.create", "company-writer")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::NotFound
    );

    let mut empty = fixture();
    empty["statisticalDatasets"] = json!([]);
    assert_eq!(parse(&empty).statistical_datasets(), Some(&json!([])));
}

#[test]
fn statistical_dataset_metadata_validates_known_domains_and_periods() {
    type MetadataMutation = fn(&mut Value);
    let cases: &[(&str, BRegMetadataErrorKind, MetadataMutation)] = &[
        (
            "non-array datasets",
            BRegMetadataErrorKind::Shape,
            |value| {
                value["statisticalDatasets"] = json!({});
            },
        ),
        ("null datasets", BRegMetadataErrorKind::Shape, |value| {
            value["statisticalDatasets"] = Value::Null;
        }),
        (
            "offline profile projection",
            BRegMetadataErrorKind::Shape,
            |value| {
                value["statisticalDatasets"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("operations");
                value["statisticalDatasets"][0]["accessProfiles"] =
                    json!({"reader": ["read-live"]});
            },
        ),
        ("missing member", BRegMetadataErrorKind::Shape, |value| {
            value["statisticalDatasets"][0]
                .as_object_mut()
                .unwrap()
                .remove("unit");
        }),
        (
            "duplicate dataset",
            BRegMetadataErrorKind::DuplicateIdentifier,
            |value| {
                value["statisticalDatasets"]
                    .as_array_mut()
                    .unwrap()
                    .push(statistical_dataset());
            },
        ),
        (
            "wrong period granularity",
            BRegMetadataErrorKind::Shape,
            |value| {
                value["statisticalDatasets"][0]["firstPeriod"] = json!("2025");
            },
        ),
        ("invalid month", BRegMetadataErrorKind::Shape, |value| {
            value["statisticalDatasets"][0]["firstPeriod"] = json!("2025-13");
        }),
        (
            "exclusive end outside calendar",
            BRegMetadataErrorKind::Shape,
            |value| {
                value["statisticalDatasets"][0]["firstPeriod"] = json!("9999-12");
            },
        ),
        ("invalid digest", BRegMetadataErrorKind::Revision, |value| {
            value["statisticalDatasets"][0]["definitionDigest"] = json!("sha256:bad");
        }),
        ("null dimensions", BRegMetadataErrorKind::Shape, |value| {
            value["statisticalDatasets"][0]["dimensions"] = Value::Null;
        }),
        (
            "duplicate dimension",
            BRegMetadataErrorKind::DuplicateIdentifier,
            |value| {
                let dimension = value["statisticalDatasets"][0]["dimensions"][0].clone();
                value["statisticalDatasets"][0]["dimensions"]
                    .as_array_mut()
                    .unwrap()
                    .push(dimension);
            },
        ),
        (
            "duplicate code",
            BRegMetadataErrorKind::DuplicateIdentifier,
            |value| {
                value["statisticalDatasets"][0]["dimensions"][0]["codes"] = json!(["_T", "_T"]);
            },
        ),
        (
            "missing total code",
            BRegMetadataErrorKind::Shape,
            |value| {
                value["statisticalDatasets"][0]["dimensions"][0]["codes"] = json!(["other"]);
            },
        ),
        ("empty operations", BRegMetadataErrorKind::Shape, |value| {
            value["statisticalDatasets"][0]["operations"] = json!([]);
        }),
        (
            "duplicate operation",
            BRegMetadataErrorKind::DuplicateIdentifier,
            |value| {
                value["statisticalDatasets"][0]["operations"] = json!(["read-live", "read-live"]);
            },
        ),
    ];
    for (name, kind, change) in cases {
        let mut value = fixture();
        value["statisticalDatasets"] = json!([statistical_dataset()]);
        change(&mut value);
        assert_eq!(
            BRegMetadata::from_slice(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .kind(),
            *kind,
            "{name}"
        );
    }

    for (granularity, period) in [
        ("day", "2024-02-29"),
        ("month", "9999-11"),
        ("quarter", "9999-Q3"),
        ("year", "9998"),
    ] {
        let mut value = fixture();
        let mut dataset = statistical_dataset();
        dataset["granularity"] = json!(granularity);
        dataset["firstPeriod"] = json!(period);
        dataset["dimensions"] = json!([]);
        dataset["operations"] = json!(["read-live"]);
        value["statisticalDatasets"] = json!([dataset]);
        parse(&value);
    }
}

#[test]
fn unsupported_statistical_vocabulary_omits_only_the_affected_dataset() {
    type DatasetMutation = fn(&mut Value);
    let cases: &[(&str, DatasetMutation)] = &[
        ("period kind", |dataset| {
            dataset["periodKind"] = json!("future-period-kind");
        }),
        ("granularity", |dataset| {
            dataset["granularity"] = json!("week");
        }),
        ("reserved dimension code", |dataset| {
            dataset["dimensions"][0]["codes"] = json!(["_X", "_T"]);
        }),
        ("operation", |dataset| {
            dataset["operations"] = json!(["future-statistical-operation"]);
        }),
    ];

    for (name, change) in cases {
        let supported = statistical_dataset();
        let mut unsupported = statistical_dataset();
        unsupported["id"] = json!("future-dataset");
        change(&mut unsupported);
        let mut value = fixture();
        value["statisticalDatasets"] = json!([unsupported, supported.clone()]);
        let metadata = parse(&value);
        assert_eq!(
            metadata.statistical_datasets(),
            Some(&json!([supported])),
            "{name}"
        );
        assert!(metadata
            .select_direct_write("records.company.create", "company-writer")
            .is_ok());
    }
}

#[test]
fn statistical_dataset_metadata_retains_duplicate_member_and_resource_bounds() {
    let mut value = fixture();
    value["statisticalDatasets"] = json!([statistical_dataset()]);
    let bytes = serde_json::to_string(&value).unwrap().replace(
        "\"firstPeriod\":\"2025-01\"",
        "\"firstPeriod\":\"2025-01\",\"firstPeriod\":\"2025-01\"",
    );
    assert_eq!(
        BRegMetadata::from_slice(bytes.as_bytes())
            .unwrap_err()
            .kind(),
        BRegMetadataErrorKind::DuplicateMember
    );

    value["statisticalDatasets"][0]["dimensions"][0]["codes"] = json!(["x".repeat(65_537), "_T"]);
    assert_eq!(
        BRegMetadata::from_slice(&serde_json::to_vec(&value).unwrap())
            .unwrap_err()
            .kind(),
        BRegMetadataErrorKind::Bound
    );
}

#[test]
fn runtime_v1_promotes_only_exact_direct_create_and_patch_contracts() {
    let metadata = parse(&fixture());
    assert_eq!(metadata.registry_identifier(), "business-registry");
    assert_eq!(metadata.registry_version(), "1.2.3");
    assert_eq!(metadata.registry_revision(), REVISION);
    assert_eq!(metadata.operations().len(), 3);
    assert!(metadata.action_metadata().is_some());
    assert!(metadata.statistical_datasets().is_none());
    assert_eq!(
        metadata.operations()[0].fields()[0].schema()["x-future-schema-key"]["kept"],
        true
    );

    let BRegDirectWrite::Create(create) = metadata
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
    assert_eq!(create.record_type_identifier(), "company");
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

    let BRegDirectWrite::Patch(patch) = metadata
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
    assert_eq!(patch.record_type_identifier(), "company");
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
        BRegMetadataSelectionErrorKind::UnsupportedOperation
    );
}

/// A company carrying `capability`, with every field the capability names
/// readable on the entity and on each of its operations, as a conforming
/// runtime publishes it.



#[test]
fn duplicate_json_members_are_refused_at_every_depth() {
    let duplicate_root = format!(
        r#"{{"id":"business-registry","id":"attacker","version":"1","revision":"{REVISION}","metadataVersion":"1","recordTypes":[],"operations":[]}}"#
    );
    let error = BRegMetadata::from_slice(duplicate_root.as_bytes()).unwrap_err();
    assert_eq!(error.kind(), BRegMetadataErrorKind::DuplicateMember);

    let nested = format!(
        r#"{{"id":"business-registry","version":"1","revision":"{REVISION}","metadataVersion":"1","recordTypes":[],"operations":[],"extension":{{"key":1,"key":2}}}}"#
    );
    let error = BRegMetadata::from_slice(nested.as_bytes()).unwrap_err();
    assert_eq!(error.kind(), BRegMetadataErrorKind::DuplicateMember);
}

#[test]
fn legacy_entity_summary_cannot_grant_operation_authority() {
    let legacy = json!({
        "registryId": "business-registry",
        "version": "1",
        "recordTypes": [{
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
    let error = BRegMetadata::from_slice(&serde_json::to_vec(&legacy).unwrap())
        .expect_err("generated legacy metadata is not runtime authority");
    assert_eq!(error.kind(), BRegMetadataErrorKind::Shape);

    let mut incomplete = fixture();
    incomplete["operations"] = json!([]);
    let error = BRegMetadata::from_slice(&serde_json::to_vec(&incomplete).unwrap())
        .expect_err("entity summaries cannot stand in for operations");
    assert_eq!(error.kind(), BRegMetadataErrorKind::DanglingReference);
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
        BRegMetadataSelectionErrorKind::RequiredCapability
    );
    assert!(metadata
        .select_direct_write("records.company.patch", "company-writer")
        .is_ok());

    let mut unknown = fixture();
    unknown["operations"][0]["operation"] = json!("future_mutation");
    unknown["recordTypes"][0]["operations"][0]["operation"] = json!("future_mutation");
    let metadata = parse(&unknown);
    assert!(matches!(
        metadata.operations()[0].kind(),
        BRegOperationKind::Unknown(value) if value == "future_mutation"
    ));
    assert_eq!(
        metadata
            .select_direct_write("records.company.create", "company-writer")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::UnsupportedOperation
    );
}

#[test]
fn execution_selection_requires_exact_source_and_profile_binding() {
    let inert = BRegMetadata::from_slice(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
    assert_eq!(
        inert
            .select_direct_write("records.company.create", "company-writer")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::UnboundSource
    );

    let metadata = inert.bind_source("https://registry.example/v1/".to_owned());
    assert_eq!(
        metadata
            .select_direct_write("records.company.create", "other-profile")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::ProfileMismatch
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
        BRegMetadata::from_slice(&serde_json::to_vec(&duplicate_actions).unwrap())
            .unwrap_err()
            .kind(),
        BRegMetadataErrorKind::DuplicateIdentifier
    );

    let mut mismatch = fixture();
    mismatch["operations"][0]["path"] = json!("/v1/records/other");
    let metadata = parse(&mismatch);
    assert_eq!(
        metadata
            .select_direct_write("records.company.create", "company-writer")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::ContractMismatch
    );

    let mut dangling = fixture();
    dangling["operations"][0]["responseRecordType"] = json!("hidden-company");
    assert_eq!(
        BRegMetadata::from_slice(&serde_json::to_vec(&dangling).unwrap())
            .unwrap_err()
            .kind(),
        BRegMetadataErrorKind::DanglingReference
    );

    let mut duplicate = fixture();
    duplicate["operations"][1]["id"] = duplicate["operations"][0]["id"].clone();
    assert_eq!(
        BRegMetadata::from_slice(&serde_json::to_vec(&duplicate).unwrap())
            .unwrap_err()
            .kind(),
        BRegMetadataErrorKind::DuplicateIdentifier
    );
}

#[test]
fn unknown_members_are_ignored_without_changing_known_selection_contracts() {
    let mut value = fixture();
    value["futureDescription"] = json!({"label": "Future registry description"});
    value["recordTypes"][0]["futureDescription"] = json!("Future entity description");
    value["recordTypes"][0]["operations"][2]["futureDescription"] = json!(true);
    value["operations"][2]["futureDescription"] = json!({"group": "search"});
    value["operations"][2]["identifier"]["futureDescription"] = json!(true);
    value["operations"][2]["fields"][0]["futureDescription"] = json!("hint");
    value["operations"][2]["request"]["futureExecutionMember"] = json!({"ignored": true});
    value["operations"][0]["futureExecutionMember"] = json!({"ignored": true});
    value["operations"][0]["request"]["futureExecutionMember"] = json!(true);
    value["statisticalDatasets"] = json!([statistical_dataset()]);
    value["statisticalDatasets"][0]["futureDescription"] = json!("hint");
    value["statisticalDatasets"][0]["dimensions"][0]["futureDescription"] = json!("hint");

    let metadata = parse(&value);
    let selected_read = metadata
        .operation("records.company.get")
        .expect("the known read operation remains available");
    assert_eq!(selected_read.kind(), &BRegOperationKind::Get);
    assert!(metadata
        .select_direct_write("records.company.create", "company-writer")
        .is_ok());
}

#[test]
fn known_members_keep_their_types_when_unknown_members_are_tolerated() {
    for mut malformed in [
        {
            let mut value = fixture();
            value["metadataVersion"] = json!(1);
            value
        },
        {
            let mut value = fixture();
            value["recordTypes"][0]["readableFields"] = json!({});
            value
        },
        {
            let mut value = fixture();
            value["operations"][0]["request"]["queryParameters"] = json!({});
            value
        },
    ] {
        malformed["unknown"] = json!(true);
        assert_eq!(
            BRegMetadata::from_slice(&serde_json::to_vec(&malformed).unwrap())
                .unwrap_err()
                .kind(),
            BRegMetadataErrorKind::Shape
        );
    }

    let mut oversized_unknown = fixture();
    oversized_unknown["futureDescription"] = json!("x".repeat(65_537));
    assert_eq!(
        BRegMetadata::from_slice(&serde_json::to_vec(&oversized_unknown).unwrap())
            .unwrap_err()
            .kind(),
        BRegMetadataErrorKind::Bound
    );
}

#[test]
fn metadata_version_revision_and_resource_bounds_are_exact() {
    for invalid in ["0", "2", "1.0"] {
        let mut value = fixture();
        value["metadataVersion"] = json!(invalid);
        assert_eq!(
            BRegMetadata::from_slice(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .kind(),
            BRegMetadataErrorKind::Version
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
            BRegMetadata::from_slice(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .kind(),
            BRegMetadataErrorKind::Revision
        );
    }

    let mut deep = fixture();
    let mut nested = json!(null);
    for _ in 0..40 {
        nested = json!([nested]);
    }
    deep["extension"] = nested;
    assert_eq!(
        BRegMetadata::from_slice(&serde_json::to_vec(&deep).unwrap())
            .unwrap_err()
            .kind(),
        BRegMetadataErrorKind::Bound
    );
}

#[test]
fn debug_and_errors_do_not_render_response_controlled_values() {
    let canary = "citizen-national-identifier-canary";
    let malformed = format!("{{\"{canary}\":");
    let error = BRegMetadata::from_slice(malformed.as_bytes()).unwrap_err();
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(canary));

    let mut value = fixture();
    value["id"] = json!(canary);
    let mut dataset = statistical_dataset();
    dataset["id"] = json!(canary);
    dataset["dimensions"][0]["codes"][0] = json!(canary);
    value["statisticalDatasets"] = json!([dataset]);
    let metadata = parse(&value);
    let rendered = format!("{metadata:?}");
    assert!(!rendered.contains(canary));

    let selection = metadata
        .select_direct_write(canary, "company-writer")
        .unwrap_err();
    let rendered = format!("{selection:?} {selection}");
    assert!(!rendered.contains(canary));
}

#[test]
fn list_query_and_presentation_descriptors_are_retained_without_authority() {
    let mut value = fixture();
    value["operations"][2]["query"] = json!({
        "kind": "odata",
        "selectableFields": [{"id": "legal-name", "apiName": "legalName"}],
        "filterableFields": [
            {"id": "__request_breg_state", "apiName": "bregState", "operators": ["equals", "in"]},
            {"id": "__request_review_outcome", "apiName": "reviewOutcome", "operators": ["equals", "in"]}
        ],
        "sortableFields": [{"id": "legal-name", "apiName": "legalName", "directions": ["asc", "desc"]}],
        "allowCount": true, "defaultPageSize": 25, "maximumPageSize": 100,
        "maximumFilterClauses": 5, "maximumInValues": 10,
        "pagination": {"parameter": "$skiptoken", "responsePath": "pageInfo.nextCursor", "exclusive": true},
        "temporal": {"mode": "current"}
    });
    let metadata = parse(&value);
    let operation = metadata.operation("records.company.get").unwrap();
    assert_eq!(
        operation.fields()[0].label(),
        "Response-controlled presentation"
    );
    let query = operation.query().unwrap();
    assert_eq!(query.filterable_fields[0].api_name, "bregState");
    assert_eq!(query.filterable_fields[0].operators, ["equals", "in"]);
    assert_eq!(query.filterable_fields[1].api_name, "reviewOutcome");
    assert_eq!(query.maximum_page_size, 100);
    assert!(metadata
        .select_direct_write("records.company.get", "company-writer")
        .is_err());

    let mut beyond_exact = value.clone();
    beyond_exact["operations"][2]["query"]["maximumPageSize"] = json!(9_007_199_254_740_992u64);
    assert!(
        BRegMetadata::from_slice(&serde_json::to_vec(&beyond_exact).unwrap()).is_err(),
        "a limit the JavaScript number boundary cannot carry exactly must be refused"
    );
}

#[test]
fn unsupported_selector_is_omitted_and_unsupported_temporal_mode_stays_visible() {
    let mut value = fixture();
    value["operations"][2]["selectors"] = json!([
        {
            "id": "by-name", "label": "By name", "valueOrigin": "request",
            "fields": [{"id": "legal-name", "apiName": "legalName", "label": "Legal name",
                "schema": {"type": "string"}, "required": true}],
            "requestFields": ["legalName"]
        },
        {
            "id": "future-selector", "label": "Future selector", "valueOrigin": "future-origin",
            "fields": [{"id": "legal-name", "apiName": "legalName", "label": "Legal name",
                "schema": {"type": "string"}, "required": true}],
            "requestFields": []
        }
    ]);
    value["operations"][2]["query"] = json!({
        "kind": "odata",
        "selectableFields": [{"id": "legal-name", "apiName": "legalName"}],
        "filterableFields": [], "sortableFields": [], "allowCount": false,
        "defaultPageSize": 25, "maximumPageSize": 100,
        "maximumFilterClauses": 5, "maximumInValues": 10,
        "pagination": {"parameter": "$skiptoken", "responsePath": "pageInfo.nextCursor", "exclusive": true},
        "temporal": {"mode": "future-temporal-mode", "futureParameter": "at"}
    });

    let metadata = parse(&value);
    let get = metadata.operation("records.company.get").unwrap();
    assert_eq!(get.selectors().len(), 1);
    assert_eq!(get.selectors()[0].identifier(), "by-name");
    // Null already means the collection is not temporal, so a mode this
    // client does not understand must reach the caller as served.
    let query = get.query().unwrap();
    assert_eq!(
        query.temporal,
        Some(json!({"mode": "future-temporal-mode", "futureParameter": "at"}))
    );
    assert_eq!(query.selectable_fields[0].api_name, "legalName");
    assert_eq!(query.maximum_page_size, 100);
    assert!(metadata
        .select_direct_write("records.company.create", "company-writer")
        .is_ok());

    let mut malformed_selector = value.clone();
    malformed_selector["operations"][2]["selectors"][0]["requestFields"] = json!([]);
    assert_eq!(
        BRegMetadata::from_slice(&serde_json::to_vec(&malformed_selector).unwrap())
            .unwrap_err()
            .kind(),
        BRegMetadataErrorKind::Shape
    );

    let mut malformed_temporal = value;
    malformed_temporal["operations"][2]["query"]["temporal"] = json!({"mode": "as-of"});
    assert_eq!(
        BRegMetadata::from_slice(&serde_json::to_vec(&malformed_temporal).unwrap())
            .unwrap_err()
            .kind(),
        BRegMetadataErrorKind::Shape
    );
}

#[test]
fn unsupported_spatial_vocabulary_omits_only_the_spatial_capability() {
    let mut value = fixture();
    value["operations"][2]["query"] = json!({
        "kind": "list",
        "selectableFields": [{"id": "legal-name", "apiName": "legalName"}],
        "filterableFields": [], "sortableFields": [], "allowCount": false,
        "defaultPageSize": 25, "maximumPageSize": 100,
        "maximumFilterClauses": 5, "maximumInValues": 10,
        "pagination": {"parameter": "$skiptoken", "responsePath": "pageInfo.nextCursor", "exclusive": true},
        "temporal": null,
        "spatialQueries": {"bbox": {"geometryProperty": "legalName",
            "maximumLongitudeSpanDegrees": 0.5, "maximumLatitudeSpanDegrees": 0.25,
            "coordinateReferenceSystem": "CRS84", "semantics": "inclusive_2d_non_crossing"}}
    });

    for (member, unsupported_value) in [
        ("coordinateReferenceSystem", "FUTURE_CRS"),
        ("semantics", "future_bbox_semantics"),
    ] {
        let mut unsupported = value.clone();
        unsupported["operations"][2]["query"]["spatialQueries"]["bbox"][member] =
            json!(unsupported_value);
        let metadata = parse(&unsupported);
        let query = metadata
            .operation("records.company.get")
            .unwrap()
            .query()
            .unwrap();
        assert_eq!(query.maximum_page_size, 100);
        assert!(query.spatial_queries.is_none());
        assert!(metadata
            .select_direct_write("records.company.create", "company-writer")
            .is_ok());
    }

    let mut malformed_bounds = value.clone();
    malformed_bounds["operations"][2]["query"]["spatialQueries"]["bbox"]
        ["maximumLongitudeSpanDegrees"] = json!(0);
    assert_eq!(
        BRegMetadata::from_slice(&serde_json::to_vec(&malformed_bounds).unwrap())
            .unwrap_err()
            .kind(),
        BRegMetadataErrorKind::Shape
    );

    let mut malformed_crs = value;
    malformed_crs["operations"][2]["query"]["spatialQueries"]["bbox"]
        ["coordinateReferenceSystem"] = json!(true);
    assert_eq!(
        BRegMetadata::from_slice(&serde_json::to_vec(&malformed_crs).unwrap())
            .unwrap_err()
            .kind(),
        BRegMetadataErrorKind::Shape
    );
}

#[test]
fn attachment_schema_capabilities_are_preserved_without_granting_json_writes() {
    let mut source = fixture();
    let descriptor = json!({
        "requiredForSubmit": true, "maximumBytes": 1024, "contentTypes": ["application/pdf"],
        "classification": "restricted",
        "verification": {"statusField": "verificationStatus", "allowedStatuses": ["notRequired", "approved"],
            "pendingOrRejectedBlocks": ["download", "submit"]},
        "remove": {"method": "DELETE", "path": "/v1/records/companies/{record_id}/attachments/supporting-file",
            "accessProfile": "company-writer", "authorizationOperation": "patch", "queryParameters": [],
            "body": "none", "ifMatchRequired": true, "idempotencyKeyRequired": true, "requiredState": "draft"},
        "upload": {"method": "PATCH", "path": "/v1/records/companies/{record_id}/attachments/supporting-file",
            "accessProfile": "company-writer", "authorizationOperation": "patch", "queryParameters": [],
            "body": "binary", "ifMatchRequired": true, "idempotencyKeyRequired": true, "requiredState": "draft"},
        "download": {"method": "GET", "path": "/v1/records/companies/{record_id}/attachments/supporting-file",
            "accessProfile": "company-writer", "authorizationOperation": "get", "queryParameters": ["proposalVersion"],
            "body": "none", "ifMatchRequired": false, "idempotencyKeyRequired": false, "proposalVersionRequired": true}
    });
    let mut slot = field("supporting-file", "supporting-file");
    slot["required"] = json!(false);
    slot["nullable"] = json!(true);
    slot["readOnly"] = json!(true);
    slot["schema"] = json!({"anyOf": [{"type": "object"}, {"type": "null"}], "readOnly": true,
        "x-registry-fieldKind": "attachment", "x-registry-attachment": descriptor});
    for operation in source["operations"].as_array_mut().unwrap() {
        operation["fields"]
            .as_array_mut()
            .unwrap()
            .push(slot.clone());
        operation["readableFields"]
            .as_array_mut()
            .unwrap()
            .push(json!("supporting-file"));
    }
    let metadata = parse(&source);
    let slot = &metadata.operations()[1].fields()[1];
    assert!(slot.read_only());
    assert!(!slot.required());
    assert!(!slot.removable());
    assert_eq!(slot.schema()["x-registry-attachment"], descriptor);
    let BRegDirectWrite::Patch(patch) = metadata
        .select_direct_write("records.company.patch", "company-writer")
        .unwrap()
    else {
        panic!("patch binding")
    };
    assert!(!patch.writable_api_names().contains("supporting-file"));
    let BRegDirectWrite::Create(create) = metadata
        .select_direct_write("records.company.create", "company-writer")
        .unwrap()
    else {
        panic!("create binding")
    };
    assert!(!create.writable_api_names().contains("supporting-file"));
    source["operations"][1]["patchWritableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("supporting-file"));
    assert_eq!(
        BRegMetadata::from_slice(&serde_json::to_vec(&source).unwrap())
            .unwrap_err()
            .kind(),
        BRegMetadataErrorKind::Shape
    );
}

#[test]
fn complete_descriptive_metadata_is_retained_and_spatial_is_optional() {
    let mut value = fixture();
    {
        let get = &mut value["operations"][2];
        get["readPath"] = json!({"id": "related-companies", "label": "Related companies"});
        get["selectors"] = json!([{
            "id": "by-name", "label": "By name", "valueOrigin": "request",
            "fields": [{"id": "legal-name", "apiName": "legalName", "label": "Legal name",
                "schema": {"type": "string", "maxLength": 120}, "required": true}],
            "requestFields": ["legalName"]
        }]);
        get["fields"][0]["storageValidation"] =
            json!({"kind": "postgresql-are", "pattern": "^[A-Z]+$"});
        get["fields"][0]["codeLabels"] = json!({"active": "Active"});
        get["fields"][0]["reference"] = json!({
            "manualEntry": true,
            "targetRecordType": "company",
            "operations": [{"operationId": "records.company.get", "accessProfile": "company-writer",
                "labelFields": ["legal-name"]}]
        });
        get["query"] = json!({
        "kind": "list",
        "selectableFields": [{"id": "legal-name", "apiName": "legalName"}],
        "filterableFields": [], "sortableFields": [], "allowCount": false,
        "defaultPageSize": 25, "maximumPageSize": 100, "maximumFilterClauses": 8,
        "maximumInValues": 16,
        "pagination": {"parameter": "$skiptoken", "responsePath": "pageInfo.nextCursor", "exclusive": true},
        "temporal": null,
        "spatialQueries": {"bbox": {"geometryProperty": "legalName",
            "maximumLongitudeSpanDegrees": 0.5, "maximumLatitudeSpanDegrees": 0.25,
            "coordinateReferenceSystem": "CRS84", "semantics": "inclusive_2d_non_crossing"}}
        });
    }
    let metadata = parse(&value);
    let operation = metadata.operation("records.company.get").unwrap();
    assert_eq!(
        operation.read_path().unwrap().identifier(),
        "related-companies"
    );
    assert_eq!(operation.selectors()[0].request_fields(), ["legalName"]);
    let field = &operation.fields()[0];
    assert_eq!(field.code_labels()["active"], "Active");
    assert_eq!(field.storage_validation().unwrap().kind(), "postgresql-are");
    assert!(field.reference().unwrap().manual_entry());
    assert_eq!(
        field.reference().unwrap().operations()[0].operation_identifier(),
        "records.company.get"
    );
    let bbox = operation
        .query()
        .unwrap()
        .spatial_queries
        .as_ref()
        .unwrap()
        .bbox
        .as_ref()
        .unwrap();
    assert_eq!(bbox.geometry_property, "legalName");
    assert_eq!(bbox.coordinate_reference_system, "CRS84");

    value["operations"][2]["query"]
        .as_object_mut()
        .unwrap()
        .remove("spatialQueries");
    assert!(parse(&value)
        .operation("records.company.get")
        .unwrap()
        .query()
        .unwrap()
        .spatial_queries
        .is_none());
}

#[test]
fn exact_tombstone_batch_and_immediate_action_contracts_promote() {
    let mut value = fixture();
    let tombstone = operation(
        "records.company.tombstone",
        "DELETE",
        "/v1/records/companies/{record_id}",
        "tombstone",
        json!([]),
        json!({"fieldNames": "api", "queryParameters": [], "body": "none",
            "ifMatchRequired": true, "idempotencyKeyRequired": true,
            "mutationSemantics": "direct"}),
        (json!([]), json!([])),
    );
    let batch_schema = json!({
        "type": "object", "additionalProperties": false, "required": ["items"],
        "properties": {"items": {"type": "array", "minItems": 1, "maxItems": 20,
            "items": {"oneOf": [{"type": "object", "properties": {
                "operation": {"const": "create"}, "data": {"type": "object"}}}]}}}
    });
    let batch = operation(
        "records.company.batch",
        "POST",
        "/v1/records/companies:batch",
        "batch",
        json!([]),
        json!({"fieldNames": "api", "queryParameters": [], "body": "batch",
            "contentType": "application/json", "idempotencyKeyRequired": true,
            "mutationSemantics": "direct", "maximumItems": 20, "maximumBodyBytes": 4096,
            "allowCreate": true, "allowPatch": false, "schema": batch_schema}),
        (json!(["legal-name"]), json!([])),
    );
    value["operations"]
        .as_array_mut()
        .unwrap()
        .extend([tombstone, batch]);
    value["recordTypes"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .extend([
            json!({"operation": "tombstone", "accessProfile": "company-writer"}),
            json!({"operation": "batch", "accessProfile": "company-writer"}),
        ]);
    value["actions"] = json!([{
        "id": "register-company", "route": "/v1/actions/register-company",
        "conditionRoute": null, "contractFingerprint": REVISION,
        "apiName": "registerCompany", "revision": REVISION, "display": {}, "execution": {"mode":"immediate"},
        "inputMode": "fixed", "maximumInputStringBytes": null,
        "inputs": [{"id": "legal-name", "apiName": "legalName", "fieldType": {
            "type": "string", "minimumLength": 0, "maximumLength": 100},
            "required": true, "nullable": false, "classification": "internal"}],
        "referenceInputs": [], "requiredConditionKeys": [],
        "resultEffects": [{"effect": "company", "recordType": "company", "operation": "create"}],
        "access": {"selectedProfile": "company-writer"},
        "routes": {"invoke": {"method": "POST", "path": "/v1/actions/register-company",
            "operationId": "actions.register-company.invoke", "requiresIdempotencyKey": true,
            "inputSchema": "action-register-company-invoke-input", "responseSchema": "action-register-company-invoke-response"},
            "targetConditions": null},
        "bounds": {"maximumTargets": 4, "maximumFieldMutations": 8, "maximumSnapshotBytes": 1024}
    }]);
    let metadata = parse(&value);
    let tombstone = metadata
        .select_tombstone("company", "company-writer")
        .unwrap();
    assert_eq!(
        tombstone.path_for_record(Uuid::nil()),
        "/v1/records/companies/00000000-0000-0000-0000-000000000000"
    );
    assert!(tombstone.request_schema().is_none());
    let batch = metadata.select_batch("company", "company-writer").unwrap();
    assert_eq!(batch.path(), "/v1/records/companies:batch");
    assert_eq!(batch.maximum_items(), 20);
    assert!(batch.allows_create());
    assert!(!batch.allows_patch());

    let mut unsupported_tombstone = value.clone();
    unsupported_tombstone["operations"][3]["requiredCapabilities"] =
        json!(["future_tombstone_protocol"]);
    assert_eq!(
        parse(&unsupported_tombstone)
            .select_tombstone("company", "company-writer")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::RequiredCapability
    );
    let mut unsupported_batch = value.clone();
    unsupported_batch["operations"][4]["requiredCapabilities"] = json!(["future_batch_protocol"]);
    let metadata = parse(&unsupported_batch);
    assert_eq!(
        metadata
            .select_batch("company", "company-writer")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::RequiredCapability
    );
    assert!(metadata
        .select_direct_write("records.company.create", "company-writer")
        .is_ok());

    let action = metadata
        .select_action("register-company", "company-writer")
        .unwrap();
    assert_eq!(action.invoke_path(), "/v1/actions/register-company");
    assert!(!action.is_handler());
    assert!(!action.inputs()[0].nullable());

    let mut unsupported_input_mode = value.clone();
    unsupported_input_mode["actions"][0]["inputMode"] = json!("future-input-mode");
    let metadata = parse(&unsupported_input_mode);
    assert_eq!(metadata.actions().len(), 1);
    assert_eq!(
        metadata.actions()[0].input_mode(),
        Some("future-input-mode")
    );
    assert_eq!(
        metadata
            .select_action("register-company", "company-writer")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::ContractMismatch
    );
    assert!(metadata
        .select_direct_write("records.company.create", "company-writer")
        .is_ok());

    let mut malformed_input_mode = value.clone();
    malformed_input_mode["actions"][0]["inputMode"] = json!(true);
    assert_eq!(
        BRegMetadata::from_slice(&serde_json::to_vec(&malformed_input_mode).unwrap())
            .unwrap_err()
            .kind(),
        BRegMetadataErrorKind::Shape
    );

    let mut unsupported_action = value.clone();
    unsupported_action["actions"][0]["requiredCapabilities"] = json!(["future_action_protocol"]);
    let metadata = parse(&unsupported_action);
    assert_eq!(metadata.actions().len(), 1);
    assert_eq!(
        metadata
            .select_action("register-company", "company-writer")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::RequiredCapability
    );
    assert!(metadata
        .select_direct_write("records.company.create", "company-writer")
        .is_ok());

    let mut malformed_capabilities = value.clone();
    malformed_capabilities["actions"][0]["requiredCapabilities"] = json!(true);
    assert_eq!(
        BRegMetadata::from_slice(&serde_json::to_vec(&malformed_capabilities).unwrap())
            .unwrap_err()
            .kind(),
        BRegMetadataErrorKind::Shape
    );
    malformed_capabilities["actions"][0]["requiredCapabilities"] =
        json!(["future_action_protocol", "future_action_protocol"]);
    assert_eq!(
        BRegMetadata::from_slice(&serde_json::to_vec(&malformed_capabilities).unwrap())
            .unwrap_err()
            .kind(),
        BRegMetadataErrorKind::DuplicateIdentifier
    );

    let mut unsupported_bounds = value.clone();
    unsupported_bounds["actions"][0]["bounds"]["maximumTargets"] = json!(17);
    assert_eq!(
        parse(&unsupported_bounds)
            .select_action("register-company", "company-writer")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::ContractMismatch
    );

    let mut structured = value.clone();
    structured["actions"][0]["inputs"][0]["fieldType"] = json!({
        "type": "structured", "maximumBytes": 64,
        "schema": {"type": "object", "additionalProperties": false,
            "properties": {"value": {"type": "string"}}}
    });
    parse(&structured)
        .select_action("register-company", "company-writer")
        .expect("a bounded closed Draft 2020-12 structured schema promotes");

    let oversized_properties = (0..3_000)
        .map(|index| (format!("field{index}"), json!({"type": "string"})))
        .collect::<serde_json::Map<_, _>>();
    let malformed_structured_schemas = [
        json!({"type": "object", "properties": {}}),
        json!({"type": "array", "items": {"$ref": "https://example.test/schema"}}),
        json!({
            "type": "object", "additionalProperties": false,
            "properties": oversized_properties
        }),
        json!({"type": "array", "items": {"type": "not-a-json-schema-type"}}),
    ];
    for schema in malformed_structured_schemas {
        let mut malformed = value.clone();
        malformed["actions"][0]["inputs"][0]["fieldType"] =
            json!({"type": "structured", "maximumBytes": 64, "schema": schema});
        assert_eq!(
            parse(&malformed)
                .select_action("register-company", "company-writer")
                .unwrap_err()
                .kind(),
            BRegMetadataSelectionErrorKind::ContractMismatch
        );
    }

    let mut optional_condition = value.clone();
    optional_condition["actions"][0]["conditionRoute"] =
        json!("/v1/actions/register-company/target-conditions");
    optional_condition["actions"][0]["routes"]["targetConditions"] = json!({
        "method": "POST", "path": "/v1/actions/register-company/target-conditions",
        "operationId": "actions.register-company.target-conditions",
        "requiresIdempotencyKey": false,
        "inputSchema": "action-register-company-target-conditions-input",
        "responseSchema": "action-register-company-target-conditions-response"
    });
    optional_condition["actions"][0]["inputs"][0]["fieldType"] =
        json!({"type": "reference", "target": "company", "onDelete": "restrict"});
    optional_condition["actions"][0]["inputs"][0]["required"] = json!(false);
    optional_condition["actions"][0]["referenceInputs"] = json!([{
        "input": "legal-name", "apiName": "legalName", "targetRecordType": "company"
    }]);
    optional_condition["actions"][0]["requiredConditionKeys"] = json!(["legalName"]);
    assert_eq!(
        parse(&optional_condition)
            .select_action("register-company", "company-writer")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::ContractMismatch
    );

    value["actions"][0]["inputs"][0]
        .as_object_mut()
        .unwrap()
        .remove("nullable");
    assert_eq!(
        parse(&value)
            .select_action("register-company", "company-writer")
            .unwrap_err()
            .kind(),
        BRegMetadataSelectionErrorKind::ContractMismatch
    );
}



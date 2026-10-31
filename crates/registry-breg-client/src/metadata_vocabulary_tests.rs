use super::*;
use serde_json::{json, Value};

const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn metadata(vocabulary: &str) -> Value {
    json!({
        "id": "fixture-registry",
        "version": "1",
        "revision": REVISION,
        "metadataVersion": "2",
        "recordTypes": [],
        "operations": [],
        "statisticalDatasets": [{
            "id": "item-counts",
            "unit": "item",
            "periodKind": "flow",
            "granularity": "month",
            "firstPeriod": "2025-01",
            "dimensions": [{
                "field": "status",
                "vocabulary": vocabulary,
                "codes": ["active", "_T"]
            }],
            "definitionDigest": REVISION,
            "operations": ["read-live"]
        }],
        "actions": [{
            "id": "update-status",
            "apiName": "updateStatus",
            "revision": REVISION,
            "display": {"label": "Update status"},
            "execution": {"mode": "immediate"},
            "route": "/v1/actions/update-status",
            "inputMode": "handler",
            "maximumInputStringBytes": 16384,
            "inputs": [{
                "id": "status",
                "apiName": "status",
                "schema": {"type": "string", "enum": ["active"]},
                "fieldType": {
                    "type": "vocabulary-code",
                    "vocabulary": vocabulary,
                    "values": ["active"]
                },
                "required": true,
                "nullable": false,
                "classification": "internal"
            }],
            "referenceInputs": [],
            "requiredConditionKeys": [],
            "resultEffects": [],
            "access": {"selectedProfile": "writer"},
            "routes": {
                "invoke": {
                    "method": "POST",
                    "path": "/v1/actions/update-status",
                    "operationId": "actions.update-status.invoke",
                    "requiresIdempotencyKey": true,
                    "inputSchema": "action-update-status-invoke-input",
                    "responseSchema": "action-update-status-invoke-response"
                }
            },
            "bounds": {
                "maximumTargets": 1,
                "maximumFieldMutations": 1,
                "maximumSnapshotBytes": 1024
            }
        }]
    })
}

fn parse(value: &Value) -> Result<BRegMetadata, BRegMetadataError> {
    BRegMetadata::from_slice(&serde_json::to_vec(value).unwrap())
        .map(|metadata| metadata.bind_source("https://registry.example/v1/".to_owned()))
}

#[test]
fn dimension_vocabulary_accepts_every_bounded_engine_string() {
    for vocabulary in [
        "https://example.org/vocabularies/licence-statuses",
        "สถานะใบอนุญาต/許可状態",
        "",
        "line one\nline two\0",
    ] {
        let value = metadata(vocabulary);
        let parsed = parse(&value).unwrap();
        assert_eq!(
            parsed.statistical_datasets().unwrap()[0]["dimensions"][0]["vocabulary"],
            vocabulary
        );
    }
}

#[test]
fn action_field_type_vocabulary_accepts_every_bounded_engine_string() {
    for vocabulary in [
        "https://example.org/vocabularies/licence-statuses",
        "สถานะใบอนุญาต/許可状態",
        "",
        "line one\nline two\0",
    ] {
        let mut value = metadata("status");
        value["actions"][0]["inputs"][0]["fieldType"]["vocabulary"] = json!(vocabulary);
        let parsed = parse(&value).unwrap();
        assert_eq!(
            parsed.actions()[0].inputs()[0].field_type()["vocabulary"],
            vocabulary
        );
        parsed.select_action("update-status", "writer").unwrap();
    }
}

#[test]
fn action_vocabulary_codes_follow_engine_code_grammar() {
    for codes in [
        json!(["A-report", "B-report", "C-report"]),
        json!(["123", "two words", "สถานะ/許可"]),
        json!(["x".repeat(128), "é".repeat(64)]),
    ] {
        let mut value = metadata("status");
        value["actions"][0]["inputs"][0]["fieldType"]["values"] = codes.clone();
        value["actions"][0]["inputs"][0]["schema"]["enum"] = codes.clone();
        let parsed = parse(&value).unwrap();
        let action = parsed.select_action("update-status", "writer").unwrap();
        assert_eq!(action.inputs()[0].field_type()["values"], codes);
        for code in codes.as_array().unwrap() {
            crate::BRegActionInvocationRequest::new(
                &action,
                Map::from_iter([("status".to_owned(), code.clone())]),
                None,
            )
            .unwrap();
        }
    }
}

#[test]
fn invalid_action_vocabulary_codes_never_promote_to_authority() {
    for codes in [
        json!([]),
        json!([""]),
        json!(["A-report", "A-report"]),
        json!(["line one\nline two"]),
        json!(["nul\0"]),
        json!(["x".repeat(129)]),
        json!(["é".repeat(65)]),
        json!([17]),
        json!("A-report"),
    ] {
        let mut value = metadata("status");
        value["actions"][0]["inputs"][0]["fieldType"]["values"] = codes;
        let parsed = parse(&value).unwrap();
        assert_eq!(parsed.actions().len(), 1);
        assert_eq!(
            parsed
                .select_action("update-status", "writer")
                .unwrap_err()
                .kind(),
            BRegMetadataSelectionErrorKind::ContractMismatch
        );
    }
}

#[test]
fn vocabulary_strings_retain_the_metadata_string_bound() {
    let maximum = "v".repeat(64 * 1024);
    let parsed = parse(&metadata(&maximum)).unwrap();
    assert_eq!(
        parsed.statistical_datasets().unwrap()[0]["dimensions"][0]["vocabulary"],
        maximum
    );
    assert_eq!(
        parsed.actions()[0].inputs()[0].field_type()["vocabulary"],
        maximum
    );

    let over_limit = metadata(&"v".repeat(64 * 1024 + 1));
    assert_eq!(
        parse(&over_limit).unwrap_err().kind(),
        BRegMetadataErrorKind::Bound
    );

    let mut over_limit = metadata("status");
    over_limit["actions"][0]["inputs"][0]["fieldType"]["vocabulary"] =
        json!("v".repeat(64 * 1024 + 1));
    assert_eq!(
        parse(&over_limit).unwrap_err().kind(),
        BRegMetadataErrorKind::Bound
    );
}

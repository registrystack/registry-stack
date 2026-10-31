// SPDX-License-Identifier: Apache-2.0

//! The maintained `dhis2-tracker` pack's attribute mapping and synchronous
//! import-summary decisions, executed through the runtime's real Rhai ABI.

use std::path::{Path, PathBuf};

use registry_adapter::engine::scripts::ScriptSet;
use registry_adapter_core::AdapterPack;
use serde_json::{json, Value};

fn empty_code_maps() -> registry_adapter::engine::scripts::CodeMaps {
    std::sync::Arc::new(std::collections::BTreeMap::new())
}

fn pack_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/adapter/packs/dhis2-tracker/pack.yaml")
}

#[allow(
    clippy::disallowed_methods,
    reason = "the test reads a committed example, pack or fixture to build its input; it reads no operator configuration"
)]
fn scripts() -> ScriptSet {
    let text = std::fs::read_to_string(pack_path()).expect("the pack is readable");
    let mut document: Value = serde_norway::from_str(&text).expect("the pack is YAML");
    let members = document.as_object_mut().expect("the pack is a mapping");
    members.remove("apiVersion");
    members.remove("kind");
    let pack: AdapterPack = serde_json::from_value(document).expect("the pack parses");
    let path = pack_path();
    let directory = path.parent().expect("a pack directory");
    let mut set = ScriptSet::default();
    for (path, entrypoint) in [
        ("scripts/to-record.rhai", "to_record"),
        ("scripts/shape-records.rhai", "shape_records"),
        ("scripts/to-bundle.rhai", "to_bundle"),
        ("scripts/import-summary.rhai", "is_complete_import"),
        ("scripts/import-summary.rhai", "is_partial_import"),
        ("scripts/import-summary.rhai", "partial_import_data"),
    ] {
        set.add(&pack, directory, path, entrypoint)
            .unwrap_or_else(|error| panic!("{path}:{entrypoint} compiles: {error}"));
    }
    set
}

fn attribute_map() -> Value {
    json!({
        "given_name": "rmeJVy1Rl5V",
        "clinic_code": "XQwFPP7o2yd"
    })
}

fn entity() -> Value {
    json!({
        "trackedEntity": "EeBJ3Sn9uLg",
        "trackedEntityType": "cQWYtUfH6Vx",
        "orgUnit": "slSrf7H9lMf",
        "createdAt": "2017-01-20T10:44:02.770",
        "updatedAt": "2017-05-26T11:46:22.372",
        "attributes": [
            {"attribute": "rmeJVy1Rl5V", "value": "Ada"},
            {"attribute": "XQwFPP7o2yd", "value": "clinic-7"},
            {"attribute": "gVHsLdJYICk", "value": "UNMAPPED-SENSITIVE-CANARY"}
        ]
    })
}

fn exchange(body: Value, map: Value) -> Value {
    json!({
        "body": body,
        "headers": {},
        "properties": {"dhis2AttributeMap": map}
    })
}

fn update_exchange(body: Value, map: Value, record_id: &str) -> Value {
    json!({
        "body": body,
        "headers": {"recordid": record_id},
        "properties": {"dhis2AttributeMap": map}
    })
}

fn create_exchange(body: Value, map: Value, record_id: &str) -> Value {
    json!({
        "body": body,
        "headers": {
            "idempotency-key": "create-person-1",
            "recordid": record_id,
            "recordtype": "person"
        },
        "properties": {"dhis2AttributeMap": map}
    })
}

#[test]
fn one_project_owned_map_controls_both_read_directions_and_the_write_bundle() {
    let set = scripts();
    let map = attribute_map();

    let record = set
        .call(
            &empty_code_maps(),
            "scripts/to-record.rhai",
            "to_record",
            &exchange(entity(), map.clone()),
        )
        .expect("to_record runs");
    assert_eq!(record["domainData"]["given_name"], "Ada");
    assert_eq!(record["domainData"]["clinic_code"], "clinic-7");
    assert!(!record.to_string().contains("UNMAPPED-SENSITIVE-CANARY"));

    let page = set
        .call(
            &empty_code_maps(),
            "scripts/shape-records.rhai",
            "shape_records",
            &exchange(json!({"trackedEntities": [entity()]}), map.clone()),
        )
        .expect("shape_records runs");
    assert_eq!(page[0]["domainData"], record["domainData"]);

    let submitted = json!({
        "tracked_entity_type": "cQWYtUfH6Vx",
        "org_unit": "slSrf7H9lMf",
        "given_name": "Ada",
        "clinic_code": "clinic-7",
        "unmapped_sensitive": "REQUEST-SENSITIVE-CANARY"
    });
    let bundle = set
        .call(
            &empty_code_maps(),
            "scripts/to-bundle.rhai",
            "to_bundle",
            &create_exchange(submitted, map, "EeBJ3Sn9uLg"),
        )
        .expect("to_bundle runs");
    assert_eq!(
        bundle["trackedEntities"][0]["attributes"],
        json!([
            {"attribute": "XQwFPP7o2yd", "value": "clinic-7"},
            {"attribute": "rmeJVy1Rl5V", "value": "Ada"}
        ])
    );
    assert!(!bundle.to_string().contains("REQUEST-SENSITIVE-CANARY"));
}

#[test]
fn the_empty_default_preserves_the_existing_base_record_and_writes_no_attributes() {
    let set = scripts();
    let record = set
        .call(
            &empty_code_maps(),
            "scripts/to-record.rhai",
            "to_record",
            &exchange(entity(), json!({})),
        )
        .expect("to_record runs");
    assert_eq!(
        record["domainData"],
        json!({
            "tracked_entity_type": "cQWYtUfH6Vx",
            "org_unit": "slSrf7H9lMf",
            "created_at": "2017-01-20T10:44:02.770",
            "updated_at": "2017-05-26T11:46:22.372"
        })
    );

    let submitted = json!({
        "tracked_entity_type": "cQWYtUfH6Vx",
        "org_unit": "slSrf7H9lMf"
    });
    let bundle = set
        .call(
            &empty_code_maps(),
            "scripts/to-bundle.rhai",
            "to_bundle",
            &create_exchange(submitted, json!({}), "EeBJ3Sn9uLg"),
        )
        .expect("to_bundle runs");
    assert_eq!(bundle["trackedEntities"][0]["attributes"], json!([]));
}

#[test]
fn an_update_binds_the_source_uid_to_the_validated_record_id_header() {
    let set = scripts();
    let submitted = json!({
        "tracked_entity_type": "cQWYtUfH6Vx",
        "org_unit": "slSrf7H9lMf"
    });
    let bundle = set
        .call(
            &empty_code_maps(),
            "scripts/to-bundle.rhai",
            "to_bundle",
            &update_exchange(submitted, json!({}), "path-owned-id"),
        )
        .expect("the facade-validated update runs");
    assert_eq!(
        bundle["trackedEntities"][0]["trackedEntity"],
        "path-owned-id"
    );
}

#[test]
fn a_malformed_source_attribute_row_is_refused_instead_of_partially_disclosed() {
    let set = scripts();
    let mut malformed = entity();
    malformed["attributes"][0]
        .as_object_mut()
        .expect("an attribute row")
        .remove("attribute");
    let failure = set.call(
        &empty_code_maps(),
        "scripts/to-record.rhai",
        "to_record",
        &exchange(malformed, attribute_map()),
    );
    assert!(
        failure.is_err(),
        "the malformed source row must fail closed"
    );
}

#[test]
fn synchronous_import_summaries_distinguish_complete_partial_and_unfinished() {
    let set = scripts();
    let complete = exchange(
        json!({
            "status": "OK",
            "stats": {"created": 1, "updated": 0, "deleted": 0, "ignored": 0, "total": 1}
        }),
        json!({}),
    );
    let partial = exchange(
        json!({
            "status": "ERROR",
            "validationReport": {
                "errorReports": [
                    {
                        "trackerType": "TRACKED_ENTITY-SENSITIVE-CANARY",
                        "uid": "UID-SENSITIVE-CANARY",
                        "errorCode": "E1005"
                    },
                    {
                        "trackerType": "TRACKED_ENTITY-SENSITIVE-CANARY",
                        "uid": "UID-SENSITIVE-CANARY",
                        "errorCode": "E1089"
                    },
                    {
                        "trackerType": "EVENT-SENSITIVE-CANARY",
                        "uid": "UID-SENSITIVE-CANARY",
                        "errorCode": "E1090"
                    }
                ]
            },
            "stats": {"created": 1, "updated": 2, "deleted": 0, "ignored": 1, "total": 4}
        }),
        json!({}),
    );
    let missing_error_reports = exchange(
        json!({
            "status": "WARNING",
            "validationReport": {},
            "stats": {"created": 1, "updated": 0, "deleted": 0, "ignored": 1, "total": 2}
        }),
        json!({}),
    );
    let malformed_error_reports = exchange(
        json!({
            "status": "WARNING",
            "validationReport": {"errorReports": {}},
            "stats": {"created": 1, "updated": 0, "deleted": 0, "ignored": 1, "total": 2}
        }),
        json!({}),
    );
    let delete_summary = exchange(
        json!({
            "status": "WARNING",
            "validationReport": {"errorReports": []},
            "stats": {"created": 1, "updated": 0, "deleted": 1, "ignored": 1, "total": 3}
        }),
        json!({}),
    );
    let unfinished = exchange(json!({"status": "PENDING"}), json!({}));

    for (entrypoint, exchange, expected) in [
        ("is_complete_import", &complete, true),
        ("is_partial_import", &complete, false),
        ("is_complete_import", &partial, false),
        ("is_partial_import", &partial, true),
        ("is_partial_import", &missing_error_reports, false),
        ("is_partial_import", &malformed_error_reports, false),
        ("is_partial_import", &delete_summary, false),
        ("is_complete_import", &unfinished, false),
        ("is_partial_import", &unfinished, false),
    ] {
        let result = set
            .call(
                &empty_code_maps(),
                "scripts/import-summary.rhai",
                entrypoint,
                exchange,
            )
            .unwrap_or_else(|error| panic!("{entrypoint} runs: {error}"));
        assert_eq!(result, json!(expected), "{entrypoint}");
    }

    let data = set
        .call(
            &empty_code_maps(),
            "scripts/import-summary.rhai",
            "partial_import_data",
            &partial,
        )
        .expect("partial_import_data runs");
    assert_eq!(
        data,
        json!({
            "imported": 1,
            "updated": 2,
            "ignored": 1,
            "rejected": 2
        }),
        "two errors for one tracker object count once, while the same UID under another tracker type is a distinct object"
    );
    assert!(
        !data.to_string().contains("SENSITIVE-CANARY"),
        "normalization returns counts only"
    );

    let absent = set
        .call(
            &empty_code_maps(),
            "scripts/import-summary.rhai",
            "partial_import_data",
            &missing_error_reports,
        )
        .expect("missing errorReports is a closed non-match, not a script error");
    assert_eq!(absent, Value::Null);
}

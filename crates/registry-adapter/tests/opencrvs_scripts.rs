// SPDX-License-Identifier: Apache-2.0

//! The `opencrvs-events` pack's shaping scripts, run through the engine's
//! script set over the declaration map a project supplies as a `map` route
//! template parameter. The fixtures are hand-derived and synthetic: nothing
//! here ran against a real OpenCRVS.

use std::path::{Path, PathBuf};

use registry_adapter::scripts::ScriptSet;
use registry_adapter_core::AdapterPack;
use serde_json::{json, Value};

fn pack_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/adapter/packs/opencrvs-events/pack.yaml")
}

#[allow(clippy::disallowed_methods)]
fn scripts() -> ScriptSet {
    let text = std::fs::read_to_string(pack_path()).expect("the pack is readable");
    let mut document: Value = serde_norway::from_str(&text).expect("the pack is YAML");
    let members = document.as_object_mut().expect("the pack is a mapping");
    members.remove("apiVersion");
    members.remove("kind");
    let pack: AdapterPack = serde_json::from_value(document).expect("the pack parses");
    let directory = pack_path()
        .parent()
        .expect("a pack directory")
        .to_path_buf();
    let mut set = ScriptSet::default();
    set.add(&pack, &directory, "scripts/to-record.rhai", "to_record")
        .expect("to-record compiles under its pinned digest");
    set.add(
        &pack,
        &directory,
        "scripts/shape-records.rhai",
        "shape_records",
    )
    .expect("shape-records compiles under its pinned digest");
    set
}

fn event() -> Value {
    json!({
        "id": "00000000-0000-4000-8000-000000000001",
        "trackingId": "EVT-SYNTHETIC-001",
        "type": "birth",
        "status": "REGISTERED",
        "dateOfEvent": "2015-04-01",
        "declaration": {
            "mother.personReference": "PERSON-SYNTHETIC-A",
            "father.personReference": "PERSON-SYNTHETIC-B",
            "unrelated.field": "SOURCE-UNRELATED-CANARY"
        }
    })
}

fn exchange(map: Value) -> Value {
    json!({
        "body": { "total": 1, "results": [event()] },
        "headers": {},
        "properties": { "opencrvsDeclarationMap": map }
    })
}

fn expected_data(with_references: bool) -> Value {
    let mut data = json!({
        "event_id": "00000000-0000-4000-8000-000000000001",
        "tracking_id": "EVT-SYNTHETIC-001",
        "status": "REGISTERED",
        "event_type": "birth",
        "date_of_event": "2015-04-01"
    });
    if with_references {
        data["mother_reference"] = json!("PERSON-SYNTHETIC-A");
        data["father_reference"] = json!("PERSON-SYNTHETIC-B");
    }
    data
}

#[test]
fn only_the_mapped_declaration_keys_reach_the_record_under_the_mapped_field() {
    let set = scripts();
    let map = json!({
        "mother_reference": "mother.personReference",
        "father_reference": "father.personReference"
    });

    let record = set
        .call(
            "scripts/to-record.rhai",
            "to_record",
            &exchange(map.clone()),
        )
        .expect("to_record runs");
    assert_eq!(record["recordIdentifier"], "EVT-SYNTHETIC-001");
    assert_eq!(record["domainData"], expected_data(true));

    let page = set
        .call(
            "scripts/shape-records.rhai",
            "shape_records",
            &exchange(map),
        )
        .expect("shape_records runs");
    assert_eq!(page[0]["domainData"], expected_data(true));
    assert!(
        !page.to_string().contains("SOURCE-UNRELATED-CANARY"),
        "an unmapped declaration leaf never leaves the source"
    );
}

#[test]
fn an_empty_map_exposes_no_declaration_leaf() {
    let set = scripts();
    let record = set
        .call("scripts/to-record.rhai", "to_record", &exchange(json!({})))
        .expect("to_record runs");
    assert_eq!(record["domainData"], expected_data(false));
    let page = set
        .call(
            "scripts/shape-records.rhai",
            "shape_records",
            &exchange(json!({})),
        )
        .expect("shape_records runs");
    assert_eq!(page[0]["domainData"], expected_data(false));
}

#[test]
fn a_mapped_key_the_event_does_not_carry_is_left_out() {
    let set = scripts();
    let record = set
        .call(
            "scripts/to-record.rhai",
            "to_record",
            &exchange(json!({ "informant_reference": "informant.personReference" })),
        )
        .expect("to_record runs");
    assert_eq!(record["domainData"], expected_data(false));
}

// SPDX-License-Identifier: Apache-2.0
//! Documented synthetic OpenCRVS exact acquisition, without deployment policy.
use registry_adapter::engine::scripts::ScriptSet;
use registry_adapter_core::AdapterPack;
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

#[allow(
    clippy::disallowed_methods,
    reason = "the test reads a committed synthetic pack and no operator configuration"
)]
fn scripts() -> ScriptSet {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/adapter/packs/opencrvs-events");
    let mut value: Value =
        serde_norway::from_slice(&std::fs::read(directory.join("pack.yaml")).unwrap()).unwrap();
    value.as_object_mut().unwrap().remove("apiVersion");
    value.as_object_mut().unwrap().remove("kind");
    let pack: AdapterPack = serde_json::from_value(value).unwrap();
    assert!(pack
        .route_templates
        .get("read-registered-event")
        .unwrap()
        .read_support
        .is_some());
    let mut scripts = ScriptSet::default();
    for entrypoint in ["source_query", "is_missing", "is_unique", "source_page"] {
        scripts
            .add(&pack, &directory, "scripts/source-read.rhai", entrypoint)
            .unwrap();
    }
    scripts
}

fn call(entrypoint: &str, body: Value) -> Value {
    scripts().call(&Arc::new(BTreeMap::new()), "scripts/source-read.rhai", entrypoint,
        &json!({"body":body,"headers":{},"properties":{"opencrvsEventType":"birth","opencrvsRecordId":"EVENT-001"}})).unwrap()
}

fn response() -> Value {
    json!({"total":1,"results":[{"id":"native-001","trackingId":"EVENT-001","type":"birth","status":"REGISTERED","declaration":{"private":"PRIVATE-CANARY"}}]})
}

#[test]
fn synthetic_native_lookup_uses_a_complete_exact_key_and_detects_ambiguity() {
    let request = call("source_query", json!({"recordId":"EVENT-001"}));
    assert_eq!(request["limit"], 2);
    assert_eq!(request["offset"], 0);
    assert_eq!(
        request["query"]["clauses"][0]["trackingId"],
        json!({"type":"exact","term":"EVENT-001"})
    );
    assert_eq!(call("is_unique", response()), true);
    assert_eq!(call("is_missing", json!({"total":0,"results":[]})), true);
    for invalid in [
        json!({"total":2,"results":response()["results"]}),
        json!({"total":0,"results":response()["results"]}),
        json!({"total":1,"results":[]}),
    ] {
        assert_eq!(call("is_unique", invalid), false);
    }
    for (field, value) in [
        ("trackingId", "OTHER"),
        ("type", "death"),
        ("status", "DRAFT"),
    ] {
        let mut invalid = response();
        invalid["results"][0][field] = json!(value);
        assert_eq!(call("is_unique", invalid), false);
    }
}

#[test]
fn synthetic_native_item_preserves_source_data_for_a_separate_project_projection() {
    let body = response();
    let page = call("source_page", body.clone());
    assert_eq!(page["items"][0]["key"], "EVENT-001");
    assert_eq!(page["items"][0]["value"], body["results"][0]);
    assert!(page["items"][0]["value"]["declaration"]["private"].is_string());
    assert!(
        page.get("data").is_none(),
        "a source pack creates no public view"
    );
}

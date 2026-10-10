// SPDX-License-Identifier: Apache-2.0
use registry_coordinator::definition::Definition;
use serde_json::{json, Value};
use std::path::Path;

fn snapshot() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/delayed-follow-up");
    serde_json::from_str(&Definition::load(&path).unwrap().snapshot().unwrap()).unwrap()
}

fn canonical(value: &Value) -> String {
    String::from_utf8(registry_platform_canonical_json::canonicalize_json(value).unwrap()).unwrap()
}

#[test]
fn old_snapshots_keep_their_exact_bytes_and_only_original_operation_semantics() {
    let mut legacy = snapshot();
    legacy["adapterAbi"] = json!("coordinator/product-operations/v3");
    legacy
        .as_object_mut()
        .unwrap()
        .remove("operationIdentities");
    let bytes = canonical(&legacy);
    let restored = Definition::from_snapshot(&bytes).unwrap();
    assert_eq!(restored.snapshot().unwrap(), bytes);
    assert_eq!(
        restored.explain().unwrap()["adapterAbi"],
        "coordinator/product-operations/v3"
    );
    assert_eq!(
        restored.digest,
        registry_platform_config::sha256_uri(bytes.as_bytes())
    );

    legacy["workflow"]["steps"]["notify"]["call"]["operation"] = json!("invoke-breg-action");
    legacy["workflow"]["steps"]["notify"]["call"]["connection"] = json!("applications");
    assert!(Definition::from_snapshot(&canonical(&legacy)).is_err());
}

#[test]
fn snapshots_refuse_missing_changed_extra_or_reordered_operation_contracts() {
    let original = snapshot();
    assert_eq!(original["operationIdentities"].as_array().unwrap().len(), 2);
    for field in [
        "version",
        "product",
        "effect",
        "keyRequirement",
        "recovery",
        "readReceipt",
        "requiresPreparation",
    ] {
        let mut changed = original.clone();
        changed["operationIdentities"][0][field] = match field {
            "version" => json!(2),
            "product" => json!("messaging"),
            "effect" => json!("mutation"),
            "keyRequirement" => json!("required"),
            "recovery" => json!("same-command"),
            _ => json!(true),
        };
        assert!(
            Definition::from_snapshot(&canonical(&changed)).is_err(),
            "{field}"
        );
    }
    let mut changed = original.clone();
    changed
        .as_object_mut()
        .unwrap()
        .remove("operationIdentities");
    assert!(Definition::from_snapshot(&canonical(&changed)).is_err());
    let mut changed = original.clone();
    let extra = changed["operationIdentities"][0].clone();
    changed["operationIdentities"]
        .as_array_mut()
        .unwrap()
        .push(extra);
    assert!(Definition::from_snapshot(&canonical(&changed)).is_err());
    let mut changed = original;
    changed["operationIdentities"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert!(Definition::from_snapshot(&canonical(&changed)).is_err());
}

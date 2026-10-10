// SPDX-License-Identifier: Apache-2.0
//! Schema finishing shared by Coordinator's authored formats.
use serde_json::{json, Value};

pub(crate) fn finish(schema: &mut Value, api_version: &str, kind: &str, id: &str) {
    refuse_null(schema);
    schema["$id"] = json!(id);
    schema["properties"]["apiVersion"] = json!({"type":"string", "const":api_version});
    schema["properties"]["kind"] = json!({"type":"string", "const":kind});
    let required = schema["required"]
        .as_array_mut()
        .expect("authored root has required members");
    required.extend([json!("apiVersion"), json!("kind")]);
}

fn refuse_null(value: &mut Value) {
    match value {
        Value::Object(object) => {
            if object.contains_key("x-registry-foreign") {
                return;
            }
            if object.get("default") == Some(&Value::Null) {
                object.remove("default");
            }
            if let Some(Value::Array(types)) = object.get_mut("type") {
                types.retain(|kind| kind != "null");
                if let [kind] = types.as_slice() {
                    let kind = kind.clone();
                    object.insert("type".into(), kind);
                }
            }
            if let Some(Value::Array(branches)) = object.get_mut("anyOf") {
                branches.retain(|branch| branch.get("type") != Some(&json!("null")));
                if let [branch] = branches.as_slice() {
                    let branch = branch.clone();
                    object.remove("anyOf");
                    if let Value::Object(branch) = branch {
                        object.extend(branch);
                    }
                }
            }
            object.values_mut().for_each(refuse_null);
        }
        Value::Array(items) => items.iter_mut().for_each(refuse_null),
        _ => {}
    }
}

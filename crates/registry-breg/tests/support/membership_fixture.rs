// SPDX-License-Identifier: Apache-2.0

use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use serde_json::{json, Value};

pub fn source(root: &str) -> Value {
    let mut value: Value = serde_json::from_str(include_str!(
        "../../../../products/breg/fixtures/organization-membership-access/registry.yaml"
    ))
    .unwrap();
    let facility = value["recordTypes"]
        .as_object_mut()
        .unwrap()
        .remove("facility")
        .unwrap();
    value["recordTypes"][root] = facility;
    value["recordTypes"][root]["route"] = json!(if root == "facility" {
        "facilities".to_owned()
    } else {
        format!("{root}s")
    });
    value["accessProfiles"]["member"]["permissions"]["records"][0]["recordType"] = json!(root);
    value["accessProfiles"]["steward"]["permissions"]["records"][2]["recordType"] = json!(root);
    value
}

pub fn compile(value: &Value) -> Result<CompiledRegistry, registry_breg::CompileFailure> {
    compile_project(
        &parse_project_json(&serde_json::to_vec(value).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
}

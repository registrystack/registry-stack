// SPDX-License-Identifier: Apache-2.0

use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use serde_json::{json, Value};

pub fn source(root: &str) -> Value {
    let mut value: Value = serde_json::from_str(include_str!(
        "../../../../products/breg/fixtures/organization-membership-access/registry.yaml"
    ))
    .unwrap();
    value["recordTypes"][2]["id"] = json!(root);
    value["recordTypes"][2]["route"] = json!(if root == "facility" {
        "facilities".to_owned()
    } else {
        format!("{root}s")
    });
    value["accessProfiles"][0]["permissions"]["records"][0]["recordType"] = json!(root);
    value["accessProfiles"][1]["permissions"]["records"][2]["recordType"] = json!(root);
    value
}

pub fn compile(value: &Value) -> Result<CompiledRegistry, registry_breg::CompileFailure> {
    compile_project(
        &parse_project_json(&serde_json::to_vec(value).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
}

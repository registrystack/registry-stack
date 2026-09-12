// SPDX-License-Identifier: Apache-2.0

use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use serde_json::{json, Value};

pub fn source(root: &str) -> Value {
    let authored = registry_breg::parse_project_yaml(
        include_str!(
            "../../../../products/breg/fixtures/organization-membership-access/registry.yaml"
        )
        .as_bytes(),
    )
    .unwrap();
    let mut value = serde_json::to_value(authored).unwrap();
    value["entities"][2]["id"] = json!(root);
    value["entities"][2]["route"] = json!(if root == "facility" {
        "facilities".to_owned()
    } else {
        format!("{root}s")
    });
    value["accessProfiles"][0]["permissions"][0]["entity"] = json!(root);
    value["accessProfiles"][1]["permissions"][2]["entity"] = json!(root);
    value
}

pub fn compile(value: &Value) -> Result<CompiledRegistry, registry_breg::CompileFailure> {
    compile_project(
        &parse_project_json(&serde_json::to_vec(value).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
}

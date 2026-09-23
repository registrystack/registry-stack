// SPDX-License-Identifier: Apache-2.0

use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use serde_json::Value;

pub const PROJECT: &str = include_str!("../fixtures/consent-access.yaml");

pub fn source() -> Value {
    let authored = registry_breg::parse_project_yaml(PROJECT.as_bytes()).unwrap();
    serde_json::to_value(authored).unwrap()
}

pub fn compile(value: &Value) -> Result<CompiledRegistry, registry_breg::CompileFailure> {
    compile_project(
        &parse_project_json(&serde_json::to_vec(value).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
}

/// Compile a variant that must fail, and return every diagnostic code.
#[allow(dead_code)]
pub fn refusal_codes(value: &Value) -> Vec<String> {
    compile(value)
        .expect_err("the variant must be refused")
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect()
}

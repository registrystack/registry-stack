// SPDX-License-Identifier: Apache-2.0
//! An action input may carry the same native pattern a Record field can.

use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_yaml, ModuleAssetSource};
use registry_breg::diagnostics::CompileFailure;
use registry_breg::CompiledRegistry;

const POSTAL_INPUT: &str =
    "{id: postal-code, apiName: postalCode, typeRef: postal-code, required: true, classification: internal}";
const PATTERN: &str = "^[0-9]{5}$";

/// The facility example with `replacement` in place of the postal-code input of
/// both of its Actions; the Record field of the same name is left as authored.
fn compile_with_postal_input(replacement: &str) -> Result<CompiledRegistry, CompileFailure> {
    let yaml = include_str!("../../../products/breg/examples/facility/registry.yaml");
    let (records, actions) = yaml.split_once("\nactions:\n").unwrap();
    assert_eq!(actions.matches(POSTAL_INPUT).count(), 2);
    let yaml = format!(
        "{records}\nactions:\n{}",
        actions.replace(POSTAL_INPUT, replacement)
    );
    compile_project_with_assets(
        &parse_project_yaml(yaml.as_bytes()).unwrap(),
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/correct-address.rhai".into(),
            bytes: include_bytes!(
                "../../../products/breg/examples/facility/plans/correct-address.rhai"
            )
            .to_vec(),
        }],
        CompileProfile::Authoring,
    )
}

fn codes(failure: &CompileFailure) -> Vec<&str> {
    failure
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect()
}

#[test]
fn a_pattern_beside_a_type_reference_is_kept_on_the_compiled_input() {
    let registry = compile_with_postal_input(&format!(
        "{{id: postal-code, apiName: postalCode, typeRef: postal-code, pattern: '{PATTERN}', required: true, classification: internal}}"
    ))
    .unwrap();
    for action in ["register-facility", "correct-address"] {
        let action = registry
            .actions()
            .actions
            .iter()
            .find(|candidate| candidate.id == action)
            .unwrap();
        let input = action
            .inputs
            .iter()
            .find(|input| input.id == "postal-code")
            .unwrap();
        assert_eq!(input.pattern.as_deref(), Some(PATTERN), "{}", action.id);
        let other = action
            .inputs
            .iter()
            .find(|input| input.id == "city")
            .unwrap();
        assert_eq!(other.pattern, None);
    }
}

#[test]
fn an_inline_string_input_may_declare_a_pattern() {
    let registry = compile_with_postal_input(&format!(
        "{{id: postal-code, apiName: postalCode, type: string, minimumLength: 1, maximumLength: 24, pattern: '{PATTERN}', required: true, classification: internal}}"
    ))
    .unwrap();
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|candidate| candidate.id == "register-facility")
        .unwrap();
    assert_eq!(
        action
            .inputs
            .iter()
            .find(|input| input.id == "postal-code")
            .unwrap()
            .pattern
            .as_deref(),
        Some(PATTERN)
    );
}

#[test]
fn the_native_expression_does_not_become_a_portable_schema_pattern() {
    let registry = compile_with_postal_input(&format!(
        "{{id: postal-code, apiName: postalCode, typeRef: postal-code, pattern: '{PATTERN}', required: true, classification: internal}}"
    ))
    .unwrap();
    for artifact in registry.artifacts().entries().values().filter(|artifact| {
        artifact.path.ends_with(".json")
            && (artifact.path.contains("schema") || artifact.path.contains("openapi"))
    }) {
        let value: serde_json::Value = serde_json::from_slice(&artifact.bytes).unwrap();
        assert!(
            !value.to_string().contains("[0-9]{5}"),
            "{} must not carry the native expression",
            artifact.path
        );
    }
}

#[test]
fn a_pattern_on_a_non_string_input_is_refused() {
    let failure = compile_with_postal_input(&format!(
        "{{id: postal-code, apiName: postalCode, type: boolean, pattern: '{PATTERN}', required: true, classification: internal}}"
    ))
    .unwrap_err();
    assert!(
        codes(&failure).contains(&"breg.action.input-pattern-type-unsupported"),
        "{:?}",
        codes(&failure)
    );
}

#[test]
fn an_oversized_pattern_is_refused_without_echoing_it() {
    let oversized = "x".repeat(4097);
    let failure = compile_with_postal_input(&format!(
        "{{id: postal-code, apiName: postalCode, typeRef: postal-code, pattern: '{oversized}', required: true, classification: internal}}"
    ))
    .unwrap_err();
    assert!(
        codes(&failure).contains(&"breg.action.input-pattern-bounds-invalid"),
        "{:?}",
        codes(&failure)
    );
    assert!(!format!("{failure:?}").contains(&oversized));
}

#[test]
fn syntax_is_left_to_postgresql_as_it_is_for_a_record_pattern() {
    assert!(compile_with_postal_input(
        "{id: postal-code, apiName: postalCode, typeRef: postal-code, pattern: '[', required: true, classification: internal}"
    )
    .is_ok());
}

#[test]
fn a_reusable_value_type_cannot_carry_a_pattern() {
    let yaml = include_str!("../../../products/breg/examples/facility/registry.yaml");
    let declared = "postal-code: {type: string, minimumLength: 1, maximumLength: 24}";
    assert_eq!(yaml.matches(declared).count(), 1);
    let yaml = yaml.replace(
        declared,
        &format!("postal-code: {{type: string, minimumLength: 1, maximumLength: 24, pattern: '{PATTERN}'}}"),
    );
    let refused = match parse_project_yaml(yaml.as_bytes()) {
        Err(_) => true,
        Ok(source) => compile_project_with_assets(
            &source,
            &[],
            &[ModuleAssetSource {
                module: None,
                path: "plans/correct-address.rhai".into(),
                bytes: include_bytes!(
                    "../../../products/breg/examples/facility/plans/correct-address.rhai"
                )
                .to_vec(),
            }],
            CompileProfile::Authoring,
        )
        .is_err(),
    };
    assert!(refused, "a shared type must not carry a native pattern");
}

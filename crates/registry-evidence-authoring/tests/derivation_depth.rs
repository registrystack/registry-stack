// SPDX-License-Identifier: Apache-2.0

use registry_evidence_authoring::{derivation::validate_function, project::FunctionInterface};

// Under pinned Rhai, 20 nested map values exceed a maximum expression depth of 32
// but fit within 64; 40 exceed 64.
const ABOVE_DEFAULT_DEPTH_NESTING: usize = 20;
const BEYOND_ABI_DEPTH_NESTING: usize = 40;

fn nested_map(depth: usize) -> String {
    (0..depth).fold("0".to_owned(), |value, _| format!("#{{ value: {value} }}"))
}

fn function_expression(depth: usize) -> String {
    format!(
        "fn derive(facts, parameters, request) {{ {} }}",
        nested_map(depth)
    )
}

fn top_level_expression(depth: usize) -> String {
    format!(
        "let parsed_only = {}; fn derive(facts, parameters, request) {{ #{{}} }}",
        nested_map(depth)
    )
}

fn assert_compiles(source: &str) {
    let findings = validate_function(source, FunctionInterface::AssertionDerive);
    assert!(
        findings.is_empty(),
        "a Function within the documented expression-depth ceiling was refused: {findings:?}"
    );
}

fn assert_depth_refused(source: &str) {
    let findings = validate_function(source, FunctionInterface::AssertionDerive);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, "function-compile");
}

#[test]
fn authoring_parser_uses_the_runtime_function_expression_depth_ceiling() {
    assert_compiles(&function_expression(ABOVE_DEFAULT_DEPTH_NESTING));
    assert_depth_refused(&function_expression(BEYOND_ABI_DEPTH_NESTING));
}

#[test]
fn authoring_parser_sets_the_same_ceiling_for_top_level_expressions() {
    // Runtime policy separately refuses executable top-level statements. This
    // case isolates the parser's first expression-depth setting so it cannot
    // silently return to Rhai's build-profile-dependent default.
    assert_compiles(&top_level_expression(ABOVE_DEFAULT_DEPTH_NESTING));
    assert_depth_refused(&top_level_expression(BEYOND_ABI_DEPTH_NESTING));
}

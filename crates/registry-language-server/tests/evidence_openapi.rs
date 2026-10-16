// SPDX-License-Identifier: Apache-2.0
#[path = "support/normalized.rs"]
mod normalized;
use normalized::*;

// OpenAPI is an import input, never an alternate Evidence project grammar.
#[test]
fn normalized_project_needs_no_openapi_description() {
    let p = Project::new(SOURCE);
    assert!(p.index().diagnostics().is_empty());
}
#[test]
fn unreferenced_openapi_does_not_change_project_symbols_or_diagnostics() {
    let p = Project::new(SOURCE);
    let before = p.index();
    p.write("source.openapi.yaml", "not: [valid yaml\n");
    let after = p.index();
    assert_eq!(before.symbols(), after.symbols());
    assert_eq!(before.diagnostics(), after.diagnostics());
}
#[test]
fn operation_source_is_rejected_by_the_one_shared_model() {
    let p = Project::new(&SOURCE.replace(
        "    acquisition: {type: single, source: person}",
        "    source: {operation: readPerson}",
    ));
    assert!(!p.index().diagnostics().is_empty());
}

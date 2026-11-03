// SPDX-License-Identifier: Apache-2.0
#[path = "support/normalized.rs"]
mod normalized;
use normalized::*;

#[test]
fn asking_for_completion_does_not_change_diagnostics() {
    let p = Project::new(&SOURCE.replace("source: person}", "source: missing}"));
    let index = p.index();
    let before = index.diagnostics().to_vec();
    for line in 0..35 {
        let _ = index.completions_at(
            &p.path(PROJECT),
            tower_lsp_server::ls_types::Position::new(line, 0),
        );
    }
    assert_eq!(index.diagnostics(), before);
}
#[test]
fn unresolved_function_completion_still_offers_the_correct_interface() {
    let source = SOURCE.replace(
        "derive: {function: derive-status}",
        "derive: {function: missing}",
    );
    let p = Project::new(&source);
    assert_eq!(
        labels(
            &p.index(),
            &p.path(PROJECT),
            after(&source, "derive: {function: ")
        ),
        vec!["derive-status"]
    );
}
#[test]
fn controls_in_recoverable_names_are_not_offered() {
    let source = SOURCE.replace("  person:\n", "  \"bad\\u0001name\":\n");
    let p = Project::new(&source);
    assert!(labels(
        &p.index(),
        &p.path(PROJECT),
        after(&source, "acquisition: {source: ")
    )
    .iter()
    .all(|x| !x.chars().any(char::is_control)));
}
#[test]
fn output_completion_never_offers_private_facts() {
    let p = Project::new(SOURCE);
    p.write(
        DERIVE,
        r#"fn derive(facts, selectors, context) { let local_fact = facts["canary"]; [#{output: "active", value: facts.active}] }"#,
    );
    let index = p.index();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    assert_eq!(
        labels(&index, &p.path(DERIVE), p.at(DERIVE, "active\"")),
        vec!["active"]
    );
}

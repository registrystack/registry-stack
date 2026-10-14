// SPDX-License-Identifier: Apache-2.0
#[path = "support/normalized.rs"]
mod normalized;
use normalized::*;

#[test]
fn sources_complete_with_the_declared_names() {
    let p = Project::new(SOURCE);
    assert_eq!(
        labels(
            &p.index(),
            &p.path(PROJECT),
            after(SOURCE, "acquisition: {type: single, source: ")
        ),
        vec!["person"]
    );
}
#[test]
fn functions_complete_only_the_matching_interface() {
    let p = Project::new(SOURCE);
    let index = p.index();
    assert_eq!(
        labels(
            &index,
            &p.path(PROJECT),
            after(SOURCE, "derive: {function: ")
        ),
        vec!["derive-status"]
    );
    assert_eq!(
        labels(
            &index,
            &p.path(PROJECT),
            after(SOURCE, "extract: {function: ")
        ),
        vec!["extract-person"]
    );
}
#[test]
fn output_completion_is_definition_scoped() {
    let p = Project::new(SOURCE);
    assert_eq!(
        labels(&p.index(), &p.path(DERIVE), p.at(DERIVE, "active\"")),
        vec!["active"]
    );
}
#[test]
fn selectors_complete_and_declarations_offer_no_references() {
    let p = Project::new(SOURCE);
    let index = p.index();
    assert_eq!(
        labels(
            &index,
            &p.path(PROJECT),
            after(SOURCE, "subjects: [{role: person, selectors: [")
        ),
        vec!["person-by-id"]
    );
    assert!(labels(&index, &p.path(PROJECT), p.at(PROJECT, "person-by-id:")).is_empty());
}
#[test]
fn candidate_replaces_the_entire_written_value() {
    let p = Project::new(SOURCE);
    let at = after(SOURCE, "derive: {function: ");
    let candidates = p.index().completions_at(&p.path(PROJECT), at);
    assert_eq!(candidates[0].range.start, at);
    assert_eq!(
        candidates[0].range.end.character - at.character,
        "derive-status".len() as u32
    );
}

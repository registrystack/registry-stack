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
            after(SOURCE, "acquisition: {source: ")
        ),
        vec!["person"]
    );
}
#[test]
fn functions_complete_only_the_matching_interface() {
    let source = SOURCE.replace(
        "functions:\n",
        "functions:\n  - {id: retired-extract, interface: source-extract/v1, source: functions/retired.rhai}\n",
    );
    let p = Project::new(&source);
    p.write(
        "functions/retired.rhai",
        "fn extract(response, selectors, context) { response }\n",
    );
    let index = p.index();
    assert_eq!(
        labels(
            &index,
            &p.path(PROJECT),
            after(&source, "derive: {function: ")
        ),
        vec!["derive-status"]
    );
}
#[test]
fn retired_acquisition_channels_offer_no_sources_or_functions() {
    let source = SOURCE
        .replace(
            "functions:\n",
            "functions:\n  - {id: retired-extract, interface: source-extract/v1, source: functions/retired.rhai}\n",
        )
        .replace(
            "    connection: population\n",
            "    connection: population\n    extract: {function: retired-extract}\n    prepare: {function: retired-extract}\n    selectors: [{role: person, profiles: [person-by-id]}]\n    request: {pathBindings: {id: {selector: {role: person, profile: person-by-id, field: person-id}}}}\n",
        )
        .replace(
            "acquisition: {source: person}",
            "acquisition: {source: person, search: person, fetch: person}",
        );
    let p = Project::new(&source);
    p.write(
        "functions/retired.rhai",
        "fn extract(response, selectors, context) { response }\n",
    );
    let index = p.index();
    for prefix in [
        "extract: {function: ",
        "prepare: {function: ",
        "profiles: [",
        "request: {pathBindings: {id: {selector: {role: person, profile: ",
        "search: ",
        "fetch: ",
    ] {
        let position = after(&source, prefix);
        assert!(
            labels(&index, &p.path(PROJECT), position).is_empty(),
            "retired channel {prefix} must not offer declarations"
        );
        assert!(index.definitions_at(&p.path(PROJECT), position).is_empty());
    }
    assert!(
        !index.diagnostics().is_empty(),
        "the shared reader refuses retired members"
    );
    let source = source.replace("fetch: person", "fetch: [{source: person}]");
    p.write(PROJECT, &source);
    let index = p.index();
    let position = after(&source, "fetch: [{source: ");
    assert!(labels(&index, &p.path(PROJECT), position).is_empty());
    assert!(index.definitions_at(&p.path(PROJECT), position).is_empty());
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

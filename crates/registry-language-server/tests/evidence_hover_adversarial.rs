// SPDX-License-Identifier: Apache-2.0
#[path = "support/normalized.rs"]
mod normalized;
use normalized::*;

#[test]
fn reference_hover_names_the_normalized_symbol_and_relative_file() {
    let p = Project::new(SOURCE);
    let hover = p
        .index()
        .hover_at(
            &p.path(PROJECT),
            after(SOURCE, "acquisition: {type: single, source: "),
        )
        .unwrap();
    assert!(hover.markdown.contains("source"));
    assert!(hover.markdown.contains("evidence.yaml"));
    assert!(
        !hover
            .markdown
            .contains(&p.root.to_string_lossy().to_string())
    );
}
#[test]
fn scoped_output_hover_names_its_definition() {
    let p = Project::new(SOURCE);
    let hover = p
        .index()
        .hover_at(&p.path(DERIVE), p.at(DERIVE, "active\""))
        .unwrap();
    assert!(hover.markdown.contains("active-status"));
}
#[test]
fn hostile_symbol_markup_is_escaped_in_hover() {
    let source = SOURCE
        .replace("source: person}", "source: 'a`b'}")
        .replace("  person:\n", "  'a`b':\n");
    let p = Project::new(&source);
    let index = p.index();
    let hover = index
        .hover_at(&p.path(PROJECT), after(&source, "source: '"))
        .unwrap();
    assert!(!hover.markdown.contains("a`b"));
}
#[test]
fn secrets_and_runtime_state_have_no_hover() {
    let p = Project::new(SOURCE);
    for name in ["secrets/key.yaml", ".evidence/dev/bundle.yaml"] {
        p.write(name, SOURCE);
        let index = p.index();
        assert!(
            index
                .hover_at(&p.path(name), at(SOURCE, "active-status:"))
                .is_none()
        );
    }
}

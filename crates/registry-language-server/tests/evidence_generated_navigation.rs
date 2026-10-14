// SPDX-License-Identifier: Apache-2.0
#[path = "support/normalized.rs"]
mod normalized;
use normalized::*;
#[test]
fn typescript_and_python_outputs_navigate_to_the_same_normalized_model() {
    let p = Project::new(SOURCE);
    let project = registry_evidence_authoring::project::read_project(PROJECT, SOURCE.as_bytes())
        .unwrap()
        .value;
    for (file, source) in [
        (
            "types/evidence.ts",
            registry_evidence_authoring::project::typescript(&project),
        ),
        (
            "types/evidence.py",
            registry_evidence_authoring::project::python(&project),
        ),
    ] {
        p.write(file, &source);
        let index = p.index();
        assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
        let output_offset = source.find("\"active\"").unwrap();
        let output = after(&source, &source[..output_offset + 1]);
        assert_eq!(
            index.definitions_at(&p.path(file), output)[0].range.start,
            at(SOURCE, "active: {concept:")
        );
        let definition = source.rfind("\"active-status\"").unwrap();
        let before = &source[..definition + 1];
        let position = tower_lsp_server::ls_types::Position::new(
            before.bytes().filter(|&b| b == b'\n').count() as u32,
            before.rsplit('\n').next().unwrap().encode_utf16().count() as u32,
        );
        assert_eq!(
            index.definitions_at(&p.path(file), position)[0].range.start,
            at(SOURCE, "active-status:")
        );
    }
}
#[test]
fn ordinary_code_files_are_not_indexed_as_generated_types() {
    let p = Project::new(SOURCE);
    p.write("ordinary.py", "active = 'private'\n");
    assert!(
        !p.index()
            .document_paths()
            .any(|x| x == p.path("ordinary.py"))
    );
}

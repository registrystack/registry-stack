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
    let scripts = project
        .functions
        .iter()
        .map(|function| (function.source.clone(), p.read(&function.source)))
        .collect();
    let compiled = registry_evidence_authoring::compile::compile(&project, &scripts).unwrap();
    for (file, source) in [
        (
            "types/evidence.ts",
            registry_evidence_authoring::project::typescript(&project, &compiled),
        ),
        (
            "types/evidence.py",
            registry_evidence_authoring::project::python(&project, &compiled),
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
        for (id, expected) in [
            ("person", "person:"),
            ("extract-person", "extract-person, interface:"),
        ] {
            let key = format!("\"{id}\":");
            let offset = if id == "person" {
                source.find(&key)
            } else {
                source.rfind(&key)
            }
            .unwrap();
            let position = after(&source, &source[..offset + 1]);
            assert_eq!(
                index
                    .definitions_at(&p.path(file), position)
                    .first()
                    .unwrap_or_else(|| panic!("missing generated {id} reference in {file}"))
                    .range
                    .start,
                at(SOURCE, expected)
            );
        }
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
    assert!(!p
        .index()
        .document_paths()
        .any(|x| x == p.path("ordinary.py")));
}

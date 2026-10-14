// SPDX-License-Identifier: Apache-2.0
#[path = "support/normalized.rs"]
mod normalized;
use normalized::*;

use registry_language_server::{EvidenceKind, SymbolKind};
#[test]
fn normalized_project_is_accepted_by_the_shared_reader_and_editor() {
    registry_evidence_authoring::project::read_project(PROJECT, SOURCE.as_bytes()).unwrap();
    let p = Project::new(SOURCE);
    assert!(
        p.index().diagnostics().is_empty(),
        "{:?}",
        p.index().diagnostics()
    );
}
#[test]
fn named_sources_navigate_in_both_directions() {
    let p = Project::new(SOURCE);
    let index = p.index();
    let at = p.at(PROJECT, "person:\n");
    let reference = after(SOURCE, "acquisition: {type: single, source: ");
    assert_eq!(
        index.definitions_at(&p.path(PROJECT), reference)[0]
            .range
            .start,
        at
    );
    assert!(
        index
            .references_at(&p.path(PROJECT), at, false)
            .iter()
            .any(|x| x.range.start == reference)
    );
}
#[test]
fn named_functions_and_their_assets_navigate() {
    let p = Project::new(SOURCE);
    let index = p.index();
    let function = after(SOURCE, "derive: {function: ");
    let declaration = after(SOURCE, "- {id: derive-status");
    assert_eq!(
        index.definitions_at(&p.path(PROJECT), function)[0]
            .range
            .start,
        at(SOURCE, "derive-status, interface")
    );
    let asset = p.at(PROJECT, DERIVE);
    assert_eq!(
        index.definitions_at(&p.path(PROJECT), asset)[0].path,
        p.path(DERIVE)
    );
    let _ = declaration;
}
#[test]
fn selector_profiles_resolve_subjects_sources_and_bindings() {
    let p = Project::new(SOURCE);
    let index = p.index();
    let declared = p.at(PROJECT, "person-by-id:");
    assert_eq!(
        index.references_at(&p.path(PROJECT), declared, false).len(),
        3
    );
}
#[test]
fn release_output_references_resolve_to_definition_owned_outputs() {
    let p = Project::new(SOURCE);
    let index = p.index();
    let release = p.at(DERIVE, "active\"");
    let declared = at(SOURCE, "active: {concept:");
    assert_eq!(
        index.definitions_at(&p.path(DERIVE), release)[0]
            .range
            .start,
        declared
    );
    assert!(
        index
            .references_at(&p.path(PROJECT), declared, false)
            .iter()
            .any(|x| x.path == p.path(DERIVE))
    );
}
#[test]
fn authority_grants_use_normalized_definitions_and_selectors() {
    let p = Project::new(SOURCE);
    let file = "targets/local/authority.yaml";
    p.write(file, AUTHORITY);
    let index = p.index();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    assert_eq!(
        index.definitions_at(&p.path(file), p.at(file, "active-status"))[0]
            .range
            .start,
        p.at(PROJECT, "active-status:")
    );
    assert_eq!(
        index.definitions_at(&p.path(file), p.at(file, "person-by-id"))[0]
            .range
            .start,
        p.at(PROJECT, "person-by-id:")
    );
}
#[test]
fn output_schema_and_fixture_assets_navigate() {
    let source=SOURCE.replace("type: boolean}\n    validitySeconds", "type: boolean, schema: schemas/output.json}\n    fixtures: fixtures/cases.yaml\n    validitySeconds");
    let p = Project::new(&source);
    p.write("fixtures/cases.yaml", "cases: []\n");
    p.write("schemas/output.json", "{}\n");
    let index = p.index();
    assert_eq!(
        index.definitions_at(&p.path(PROJECT), p.at(PROJECT, "schemas/output.json"))[0].path,
        p.path("schemas/output.json")
    );
    assert_eq!(
        index.definitions_at(&p.path(PROJECT), p.at(PROJECT, "fixtures/cases.yaml"))[0].path,
        p.path("fixtures/cases.yaml")
    );
}
#[test]
fn assertion_definitions_and_outputs_are_distinct_symbol_kinds() {
    let p = Project::new(SOURCE);
    let index = p.index();
    assert!(
        index
            .symbols()
            .iter()
            .any(|x| x.kind == SymbolKind::Evidence(EvidenceKind::AssertionDefinition))
    );
    assert!(
        index
            .symbols()
            .iter()
            .any(|x| x.kind == SymbolKind::Evidence(EvidenceKind::Output)
                && x.container_name.as_deref() == Some("active-status"))
    );
}
#[test]
fn canonical_standalone_project_uses_the_same_editor_model() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/examples/standalone");
    let index = registry_language_server::ProjectIndex::load_evidence(&root).unwrap();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    assert!(
        index
            .workspace_symbols("adult-status")
            .iter()
            .any(|x| x.kind == SymbolKind::Evidence(EvidenceKind::AssertionDefinition))
    );
}
#[test]
fn missing_function_schema_and_fixture_files_report_at_their_paths() {
    let source=SOURCE.replace("type: boolean}\n    validitySeconds", "type: boolean, schema: schemas/missing.yaml}\n    fixtures: fixtures/missing.yaml\n    validitySeconds");
    let p = Project::new(&source);
    std::fs::remove_file(p.path(DERIVE)).unwrap();
    let index = p.index();
    for name in [DERIVE, "schemas/missing.yaml", "fixtures/missing.yaml"] {
        assert!(
            index
                .diagnostics()
                .iter()
                .any(|x| x.path == p.path(PROJECT) && x.range.start == at(&source, name)),
            "missing {name}: {:?}",
            index.diagnostics()
        );
    }
}
#[test]
fn symlink_and_hard_link_function_assets_never_navigate() {
    let p = Project::new(SOURCE);
    std::fs::remove_file(p.path(DERIVE)).unwrap();
    p.write("private/function.rhai", "fn derive(a,b,c) {}\n");
    std::fs::hard_link(p.path("private/function.rhai"), p.path(DERIVE)).unwrap();
    assert!(
        p.index()
            .definitions_at(&p.path(PROJECT), at(SOURCE, DERIVE))
            .is_empty()
    );
    #[cfg(unix)]
    {
        std::fs::remove_file(p.path(DERIVE)).unwrap();
        std::os::unix::fs::symlink(p.path("private/function.rhai"), p.path(DERIVE)).unwrap();
        assert!(
            p.index()
                .definitions_at(&p.path(PROJECT), at(SOURCE, DERIVE))
                .is_empty()
        );
    }
}

#[test]
fn a_shared_named_derivation_resolves_each_calling_definition_output() {
    let project = registry_evidence_authoring::project::read_project(PROJECT, SOURCE.as_bytes())
        .unwrap()
        .value;
    let mut value = serde_json::to_value(project).unwrap();
    let mut other = value["assertionDefinitions"]["active-status"].clone();
    other["semantics"]["requirement"] = serde_json::json!("urn:example:requirement:other");
    value["assertionDefinitions"]["other-status"] = other;
    value["apiVersion"] =
        serde_json::json!(registry_evidence_authoring::project::PROJECT_API_VERSION);
    value["kind"] = serde_json::json!(registry_evidence_authoring::project::PROJECT_KIND);
    let source = serde_norway::to_string(&value).unwrap();
    let p = Project::new(&source);
    let index = p.index();
    let release = p.at(DERIVE, "active\"");
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    assert_eq!(index.definitions_at(&p.path(DERIVE), release).len(), 2);
    assert_eq!(labels(&index, &p.path(DERIVE), release), vec!["active"]);
}

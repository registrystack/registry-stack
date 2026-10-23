// SPDX-License-Identifier: Apache-2.0
//! Native BReg authoring navigation against the maintained compiler fixtures.
mod support;

use registry_language_server::{ProductKind, ProjectIndex};
use serde_json::json;
use std::{fs, path::PathBuf};
use support::{
    file,
    lsp::{uri, LspSession},
    EvidenceProject as Project,
};

fn fixture(name: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/examples")
            .join(name),
    )
    .unwrap()
}

fn facility() -> Project {
    let mut source = fixture("facility/registry.yaml");
    for (before, after) in [
        (
            "source: plans/correct-address.rhai",
            "source: <|source|>plans/correct-address.rhai",
        ),
        (
            "function: correct-address-plan",
            "function: <|function|>correct-address-plan",
        ),
        (
            "typeRef: address-line",
            "typeRef: <|value-type|>address-line",
        ),
        (
            "facility: {fromEffect: facility}",
            "facility: {fromEffect: <|effect|>facility}",
        ),
        (
            "facility-code: {fromInput: facility-code}",
            "<|set-field|>facility-code: {fromInput: <|input|>facility-code}",
        ),
        (
            "field: status, equals: active",
            "field: <|guard-field|>status, equals: active",
        ),
        (
            "field: address-line}",
            "field: <|context-field|>address-line}",
        ),
        ("authority: casework", "authority: <|authority|>casework"),
        (
            "fields: [address-line, city, postal-code]",
            "fields: [<|write-field|>address-line, city, postal-code]",
        ),
        (
            "results: [facility, assignment]",
            "results: [<|result|>facility, assignment]",
        ),
        (
            "readableInputs: [facility, address-line, city, postal-code]",
            "readableInputs: [<|read-input|>facility, address-line, city, postal-code]",
        ),
        (
            "readableAttachments: [supporting-document]",
            "readableAttachments: [<|attachment|>supporting-document]",
        ),
        (
            "readableContextFields: [facilityId,",
            "readableContextFields: [<|context|>facilityId,",
        ),
    ] {
        assert!(
            source.contains(before),
            "canonical fixture changed: {before}"
        );
        source = source.replacen(before, after, 1);
    }
    Project::new(&[
        file("registry.yaml", &source),
        file(
            "plans/correct-address.rhai",
            &fixture("facility/plans/correct-address.rhai"),
        ),
    ])
}

#[test]
fn minimal_and_facility_have_coherent_native_symbols_and_no_missing_edges() {
    for project in [
        Project::new(&[file("registry.yaml", &fixture("minimal/registry.yaml"))]),
        facility(),
    ] {
        let index = ProjectIndex::load_product(project.root(), ProductKind::Breg).unwrap();
        assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
        assert!(index.symbols().iter().any(|symbol| symbol.name == "name"));
        assert!(index.symbols().iter().any(|symbol| symbol.name == "id"));
    }
}

#[test]
fn facility_plans_proposal_grants_and_guards_navigate_and_complete_in_scope() {
    let project = facility();
    let index = ProjectIndex::load_product(project.root(), ProductKind::Breg).unwrap();
    let path = project.path("registry.yaml");
    for (cursor, expected) in [
        ("function", "correct-address-plan"),
        ("value-type", "address-line"),
        ("effect", "facility"),
        ("set-field", "facility-code"),
        ("input", "facility-code"),
        ("guard-field", "status"),
        ("context-field", "address-line"),
        ("write-field", "address-line"),
        ("authority", "casework"),
        ("result", "facility"),
        ("read-input", "facility"),
        ("attachment", "supporting-document"),
        ("context", "facilityId"),
    ] {
        let position = project.cursor("registry.yaml", cursor);
        let definitions = index.definitions_at(&path, position);
        assert_eq!(definitions.len(), 1, "{cursor}: {definitions:?}");
        assert_eq!(definitions[0].path, path);
        assert!(index.hover_at(&path, position).is_some(), "{cursor}");
        let candidates = index.completions_at(&path, position);
        assert!(
            candidates.iter().any(|item| item.label == expected),
            "{cursor}: {candidates:?}"
        );
        if ["set-field", "guard-field", "context-field", "write-field"].contains(&cursor) {
            assert!(
                !candidates.iter().any(|item| item.label == "email"),
                "other record field leaked into {cursor}"
            );
        }
        if cursor == "read-input" {
            assert!(
                !candidates.iter().any(|item| item.label == "operator"),
                "other Action input leaked"
            );
        }
    }
    assert_eq!(
        index.definitions_at(&path, project.cursor("registry.yaml", "source"))[0].path,
        project.path("plans/correct-address.rhai")
    );
}

#[test]
fn generated_identifier_scopes_navigate_and_complete_within_the_record_type() {
    let project = Project::new(&[file(
        "registry.yaml",
        "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject: {id: generated-identifiers}\nrecordTypes:\n  - id: application\n    fields:\n      - {id: <|field|>jurisdiction, type: string}\n      - id: number\n        type: string\n        generate: {type: sequence, minimumDigits: 4, scope: [<|scope|>jurisdiction]}\n  - id: unrelated\n    fields: [{id: other-scope, type: string}]\n",
    )]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Breg).unwrap();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    let path = project.path("registry.yaml");
    let position = project.cursor("registry.yaml", "scope");
    let definitions = index.definitions_at(&path, position);
    assert_eq!(definitions.len(), 1, "{definitions:?}");
    assert_eq!(
        definitions[0].range.start,
        project.cursor("registry.yaml", "field")
    );
    assert!(index.hover_at(&path, position).is_some());
    let candidates = index.completions_at(&path, position);
    assert!(candidates.iter().any(|item| item.label == "jurisdiction"));
    assert!(!candidates.iter().any(|item| item.label == "other-scope"));
}

#[test]
fn module_extension_generated_identifier_scopes_use_the_extended_record_type() {
    let project = Project::new(&[
        file(
            "registry.yaml",
            "apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject: {id: generated-identifiers}\nmodules: [{id: core}, {id: identifiers}]\n",
        ),
        file(
            "modules/core/module.yaml",
            "kind: BRegModule\nid: core\nrecordTypes:\n  - id: application\n    fields: [{id: <|field|>jurisdiction, type: string}]\n  - id: unrelated\n    fields: [{id: other-scope, type: string}]\n",
        ),
        file(
            "modules/identifiers/module.yaml",
            "kind: BRegModule\nid: identifiers\ndependencies: [core]\nextendRecordTypes:\n  - recordType: application\n    fields:\n      - id: number\n        type: string\n        generate: {type: sequence, minimumDigits: 4, scope: [<|scope|>jurisdiction]}\n      - id: broken-number\n        type: string\n        generate: {type: sequence, minimumDigits: 4, scope: [<|missing|>missing-scope]}\n",
        ),
    ]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Breg).unwrap();
    let extension = project.path("modules/identifiers/module.yaml");
    let position = project.cursor("modules/identifiers/module.yaml", "scope");
    let definitions = index.definitions_at(&extension, position);
    assert_eq!(definitions.len(), 1, "{definitions:?}");
    assert_eq!(
        definitions[0].range.start,
        project.cursor("modules/core/module.yaml", "field")
    );
    assert!(index.hover_at(&extension, position).is_some());
    let candidates = index.completions_at(&extension, position);
    assert!(candidates.iter().any(|item| item.label == "jurisdiction"));
    assert!(!candidates.iter().any(|item| item.label == "other-scope"));
    assert!(index.diagnostics().iter().any(|diagnostic| {
        diagnostic.path == extension
            && diagnostic.range.start
                == project.cursor("modules/identifiers/module.yaml", "missing")
            && diagnostic.message.contains("missing-scope")
    }));
}

#[tokio::test]
async fn canonical_function_reference_changes_are_visible_through_lsp() {
    let project = facility();
    let path = project.path("registry.yaml");
    let source = fs::read_to_string(&path).unwrap();
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    session.open(&path, &source, 1).await;
    let params = json!({"textDocument":{"uri":uri(&path)},"position":project.cursor("registry.yaml", "function")});
    assert_eq!(
        session
            .request("textDocument/definition", params.clone())
            .await
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        session.request("textDocument/completion", params).await["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["label"] == "correct-address-plan")
    );
    let edited = source.replace("function: correct-address-plan", "function: missing-plan");
    session.notify("textDocument/didChange", json!({"textDocument":{"uri":uri(&path),"version":2},"contentChanges":[{"text":edited}]})).await;
    assert!(session
        .published_diagnostics(&path)
        .unwrap()
        .iter()
        .any(|item| item["message"].as_str().unwrap().contains("missing-plan")));
    session.notify("textDocument/didChange", json!({"textDocument":{"uri":uri(&path),"version":3},"contentChanges":[{"text":source}]})).await;
    assert!(session.published_diagnostics(&path).unwrap().is_empty());
}

#[test]
fn retired_entities_handlers_and_change_request_paths_have_no_editor_fallback() {
    let project = Project::new(&[file("registry.yaml", "kind: BRegProject\nentities: [{id: retired, fields: [{id: old-field}], changeRequest: {planner: {script: old.rhai}}}]\nactions: [{id: old-action, effects: [{id: old-effect}], handler: {script: <|script|>old.rhai}}]\naccessProfiles: [{id: staff, permissions: {entities: [{entity: <|entity|>retired}]}}]\n"), file("old.rhai", "// retired\n")]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Breg).unwrap();
    assert!(!index
        .symbols()
        .iter()
        .any(|symbol| ["retired", "old-field", "old-effect"].contains(&symbol.name.as_str())));
    for cursor in ["script", "entity"] {
        let position = project.cursor("registry.yaml", cursor);
        assert!(index
            .definitions_at(&project.path("registry.yaml"), position)
            .is_empty());
        assert!(index
            .completions_at(&project.path("registry.yaml"), position)
            .is_empty());
    }
}

#[test]
fn module_value_types_extensions_functions_and_empty_input_plans_resolve() {
    let project = Project::new(&[
        file("registry.yaml", "kind: BRegProject\nmodules: [{id: core}, {id: extra}]\naccessProfiles: [{id: staff, permissions: {actions: [{action: create, results: [<|result|>created]}]}}]\n"),
        file("modules/core/module.yaml", "kind: BRegModule\nid: core\nvalueTypes: {bounded-name: {type: string, maximumLength: 64}}\nrecordTypes: [{id: person, fields: [{id: name, typeRef: bounded-name}]}]\nfunctions: [{id: make-person, source: <|asset|>plans/create.rhai}]\nactions: [{id: create, execution: {mode: immediate}, plan: {type: function, function: make-person, inputs: [], writes: [{id: <|effect|>created, target: {recordType: person}, fields: [name]}]}}]\n"),
        file("modules/extra/module.yaml", "kind: BRegModule\nid: extra\ndependencies: [core]\nextendRecordTypes: [{recordType: <|record|>person, fields: [{id: alias, typeRef: <|type|>bounded-name}]}]\nactions: [{id: update, execution: {mode: immediate}, inputs: [{id: person, type: reference, target: person}], plan: {type: function, function: <|function|>make-person, inputs: [person], writes: [{id: changed, target: {fromInput: person}, fields: [<|field|>alias]}]}}]\n"),
        file("modules/core/plans/create.rhai", "fn plan(ctx) { #{} }\n"),
    ]);
    let index = ProjectIndex::load_product(project.root(), ProductKind::Breg).unwrap();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    for cursor in ["record", "type", "function", "field"] {
        let path = project.path("modules/extra/module.yaml");
        assert_eq!(
            index
                .definitions_at(&path, project.cursor("modules/extra/module.yaml", cursor))
                .len(),
            1,
            "{cursor}"
        );
    }
    assert_eq!(
        index.definitions_at(
            &project.path("registry.yaml"),
            project.cursor("registry.yaml", "result")
        )[0]
        .range
        .start,
        project.cursor("modules/core/module.yaml", "effect")
    );
    assert_eq!(
        index.definitions_at(
            &project.path("modules/core/module.yaml"),
            project.cursor("modules/core/module.yaml", "asset")
        )[0]
        .path,
        project.path("modules/core/plans/create.rhai")
    );
}

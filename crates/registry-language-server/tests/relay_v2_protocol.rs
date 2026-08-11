// SPDX-License-Identifier: Apache-2.0
//! Relay V2 authoring behavior as an editor observes it over LSP.

mod support;

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde_json::{json, Value};
use support::lsp::{uri, LspSession};
use tower_lsp_server::ls_types::Position;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/relay-v2/acceptance/business-registry")
        .canonicalize()
        .expect("the Relay V2 acceptance project exists")
}

fn position_of(document: &str, needle: &str) -> Position {
    let offset = document
        .find(needle)
        .expect("the document contains the cursor text");
    let before = &document[..offset];
    let line = before.lines().count().saturating_sub(1) as u32;
    let column = before
        .rsplit_once('\n')
        .map_or(before, |(_, current)| current)
        .encode_utf16()
        .count() as u32;
    Position::new(line, column)
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("project directory creates");
    for entry in fs::read_dir(source).expect("project directory reads") {
        let entry = entry.expect("project entry reads");
        let target = destination.join(entry.file_name());
        if entry
            .file_type()
            .expect("project entry has a type")
            .is_dir()
        {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("project file copies");
        }
    }
}

#[tokio::test]
async fn relay_v2_navigation_and_unsaved_compiler_diagnostics_reach_the_editor() {
    let root = project_root();
    let registry = root.join("registry.yaml");
    let document = fs::read_to_string(&registry).expect("registry.yaml reads");
    let source = position_of(&document, "companies\n      view:");
    let mut session = LspSession::start();
    session.initialize(&root).await;
    session.open(&registry, &document, 1).await;

    assert_eq!(
        session.published_diagnostics(&registry),
        Some(Vec::<Value>::new()),
        "the accepted project is compiler-clean"
    );

    let definitions = session
        .request(
            "textDocument/definition",
            json!({
                "textDocument": {"uri": uri(&registry)},
                "position": {"line": source.line, "character": source.character},
            }),
        )
        .await;
    let definitions = definitions.as_array().expect("definition answers an array");
    assert_eq!(definitions.len(), 1, "{definitions:?}");
    assert_eq!(definitions[0]["uri"], uri(&registry));

    let hover = session
        .request(
            "textDocument/hover",
            json!({
                "textDocument": {"uri": uri(&registry)},
                "position": {"line": source.line, "character": source.character},
            }),
        )
        .await;
    assert!(
        hover["contents"]["value"]
            .as_str()
            .is_some_and(|value| value.contains("Relay V2 source") && value.contains("`companies`")),
        "{hover:?}"
    );

    let unsaved = document.replacen("source: companies", "source: missing", 1);
    session
        .notify(
            "textDocument/didChange",
            json!({
                "textDocument": {"uri": uri(&registry), "version": 2},
                "contentChanges": [{"text": unsaved}],
            }),
        )
        .await;

    let diagnostics = session
        .published_diagnostics(&registry)
        .expect("the server publishes the unsaved compiler result");
    let diagnostic = diagnostics
        .iter()
        .find(|diagnostic| diagnostic["code"] == "relay-v2/resource.source_unknown")
        .unwrap_or_else(|| panic!("the compiler refusal is published: {diagnostics:?}"));
    assert_eq!(diagnostic["source"], json!("relay-v2"));
    assert_eq!(diagnostic["severity"], json!(1));
}

#[tokio::test]
async fn an_unsaved_reference_loads_a_governed_file_outside_the_prior_closure() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let project = temporary.path().join("project");
    copy_tree(&project_root(), &project);
    let governed = fs::read_to_string(project.join("codelists/legal-forms.yaml"))
        .expect("the existing governed file reads");
    fs::create_dir(project.join("policies")).expect("the governed file directory creates");
    let unsaved_governed = project.join("policies/alternate-legal-forms.yaml");
    assert!(!unsaved_governed.exists());
    let root = project.canonicalize().expect("project root canonicalizes");
    let registry = root.join("registry.yaml");
    let document = fs::read_to_string(&registry).expect("registry.yaml reads");
    let unsaved = document.replacen(
        "codelist: codelists/legal-forms.yaml",
        "codelist: policies/alternate-legal-forms.yaml",
        1,
    );
    let mut session = LspSession::start();
    session.initialize(&root).await;

    session.open(&unsaved_governed, &governed, 1).await;
    session.open(&registry, &unsaved, 1).await;

    assert_eq!(
        session.published_diagnostics(&registry),
        Some(Vec::<Value>::new()),
        "the newly referenced governed file joins the unsaved project closure"
    );
}

#[tokio::test]
async fn a_new_unsaved_runtime_document_contributes_compiler_diagnostics() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let project = temporary.path().join("project");
    copy_tree(&project_root(), &project);
    let invalid = fs::read_to_string(project.join("runtime.yaml"))
        .expect("the runtime fixture reads")
        .replacen(
            "apiVersion: relay.registrystack.org/v2alpha1",
            "apiVersion: relay.registrystack.org/unsupported",
            1,
        );
    fs::remove_file(project.join("runtime.yaml")).expect("the runtime starts absent");
    let root = project.canonicalize().expect("project root canonicalizes");
    let runtime = root.join("runtime.yaml");
    let mut session = LspSession::start();
    session.initialize(&root).await;

    session.open(&runtime, &invalid, 1).await;

    let diagnostics = session
        .published_diagnostics(&runtime)
        .expect("the unsaved runtime receives diagnostics");
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic["code"] == "relay-v2/runtime.yaml_invalid"),
        "the compiler reads the unsaved runtime: {diagnostics:?}"
    );
    assert!(!runtime.exists(), "the test never saves the runtime buffer");
}

// SPDX-License-Identifier: Apache-2.0
//! The shared editor navigates local Coordinator contracts without reading runtime authority.
mod support;

use registry_language_server::{ProductKind, ProjectIndex};
use serde_json::json;
use std::{fs, path::PathBuf};
use support::{
    file,
    lsp::{uri, LspSession},
    EvidenceProject as Project,
};

const WORKFLOW: &str = r#"
apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project: {id: editor-workflow, version: v1}
types:
  <|type|>request: {type: object}
contracts:
  <|contract|>registry: {type: breg, source: <|contract-file|>generated/registry.json}
functions:
  <|function|>make-request:
    runtime: rhai
    source: <|function-file|>functions.rhai
    entrypoint: make_request
    inputs: {request: {typeRef: <|function-type-use|>request}}
    output: {operationInput: <|operation-type-use|>read-record}
operations:
  <|operation|>read-record:
    uses: breg.invoke-action/v1
    connection: external-registry
    action: {contract: <|contract-use|>registry, id: remotely-owned-action}
workflow:
  input: {typeRef: <|type-use|>request}
  deadlineSeconds: 300
  eventTriggers:
    <|trigger|>record-saved:
      source: external-events
      eventType: externally-owned-record-event
      dataSchema: urn:example:remote-event:v1
      event: {typeRef: <|event-type-use|>request}
      input:
        type: function
        function: <|event-function-use|>make-request
        inputs: {request: {type: input}}
  review:
    outcomes:
      <|review-use|>handled: {status: approved, outcome: handled}
  start: <|start-use|>read
  steps:
    <|step|>read:
      type: call
      operation: <|operation-use|>read-record
      input:
        type: function
        function: <|function-use|>make-request
        inputs: {request: {type: input}}
      next: <|next-use|>complete
    <|finish|>complete:
      type: finish
      outcome: <|outcome-use|>handled
      output:
        type: fields
        fields:
          record: {type: step, step: <|step-use|>read}
          literal:
            type: literal
            value: {type: function, function: not-a-local-function, step: not-a-local-step, typeRef: not-a-local-type}
  outcomes:
    <|outcome|>handled: {operationOutput: <|output-operation-use|>read-record}
"#;

fn project() -> Project {
    Project::new(&[
        file("workflow.yaml", WORKFLOW),
        file("functions.rhai", "fn make_request(args) { args.request }"),
        file(
            "generated/registry.json",
            r#"{"private-contract-detail":"not-an-editor-symbol"}"#,
        ),
        file(
            "runtime.yaml",
            "connections: {external-registry: {privateKeyRef: secret:operator/key}}\n",
        ),
    ])
}

#[test]
fn coordinator_native_review_and_event_edges_resolve_without_claiming_external_names() {
    let project = project();
    let index = ProjectIndex::load_product(project.root(), ProductKind::Coordinator).unwrap();
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    let path = project.path("workflow.yaml");
    for (reference, definition, expected) in [
        ("type-use", "type", "request"),
        ("function-type-use", "type", "request"),
        ("event-type-use", "type", "request"),
        ("operation-type-use", "operation", "read-record"),
        ("operation-use", "operation", "read-record"),
        ("output-operation-use", "operation", "read-record"),
        ("contract-use", "contract", "registry"),
        ("function-use", "function", "make-request"),
        ("event-function-use", "function", "make-request"),
        ("start-use", "step", "read"),
        ("next-use", "finish", "complete"),
        ("step-use", "step", "read"),
        ("outcome-use", "outcome", "handled"),
        ("review-use", "outcome", "handled"),
    ] {
        let position = project.cursor("workflow.yaml", reference);
        let definitions = index.definitions_at(&path, position);
        assert_eq!(definitions.len(), 1, "{reference}");
        assert_eq!(definitions[0].path, path);
        assert_eq!(
            definitions[0].range.start,
            project.cursor("workflow.yaml", definition),
            "{reference}"
        );
        assert!(index.hover_at(&path, position).is_some(), "{reference}");
        assert!(
            index
                .completions_at(&path, position)
                .iter()
                .any(|candidate| candidate.label == expected),
            "{reference}"
        );
        assert!(
            index
                .references_at(&path, project.cursor("workflow.yaml", definition), false)
                .iter()
                .any(|location| location.range.start == position),
            "{reference}"
        );
    }
    for (reference, asset) in [
        ("function-file", "functions.rhai"),
        ("contract-file", "generated/registry.json"),
    ] {
        assert_eq!(
            index.definitions_at(&path, project.cursor("workflow.yaml", reference))[0].path,
            project.path(asset)
        );
    }
    for name in [
        "editor-workflow",
        "request",
        "make-request",
        "registry",
        "read-record",
        "read",
        "complete",
        "handled",
        "record-saved",
    ] {
        assert!(
            index.symbols().iter().any(|symbol| symbol.name == name),
            "{name}"
        );
    }
    assert!(!index
        .symbols()
        .iter()
        .any(|symbol| symbol.name == "not-an-editor-symbol"));
    assert!(index
        .document_symbols(&project.path("runtime.yaml"))
        .is_empty());
}

#[test]
fn every_maintained_coordinator_workflow_has_no_invented_missing_local_references() {
    let examples =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../products/coordinator/examples");
    let mut count = 0;
    for entry in fs::read_dir(examples).unwrap() {
        let root = entry.unwrap().path();
        if !root.join("workflow.yaml").is_file() {
            continue;
        }
        let index = ProjectIndex::load_product(&root, ProductKind::Coordinator).unwrap();
        assert!(
            index.diagnostics().is_empty(),
            "{}: {:?}",
            root.display(),
            index.diagnostics()
        );
        assert!(!index
            .document_symbols(&root.join("workflow.yaml").canonicalize().unwrap())
            .is_empty());
        count += 1;
    }
    assert_eq!(
        count, 11,
        "cover every maintained native and Review workflow"
    );
}

#[tokio::test]
async fn coordinator_discovery_unsaved_diagnostics_and_watched_assets_use_the_real_protocol() {
    let project = project();
    let path = project.path("workflow.yaml");
    let source = fs::read_to_string(&path).unwrap();
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    session.open(&path, &source, 1).await;
    assert!(session.published_diagnostics(&path).unwrap().is_empty());
    let symbols = session
        .request("workspace/symbol", json!({"query":"editor-workflow"}))
        .await;
    assert!(symbols
        .as_array()
        .unwrap()
        .iter()
        .any(|symbol| symbol["name"] == "editor-workflow"));
    let params = json!({"textDocument":{"uri":uri(&path)},"position":project.cursor("workflow.yaml", "event-function-use")});
    assert_eq!(
        session
            .request("textDocument/definition", params)
            .await
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let changed = source
        .replace("function: make-request", "function: unknown-function")
        .replace("operation: read-record", "operation: unknown-operation")
        .replace("start: read", "start: unknown-step")
        .replace("typeRef: request", "typeRef: unknown-type")
        .replace("outcome: handled", "outcome: unknown-outcome")
        .replace("contract: registry", "contract: unknown-contract");
    session.notify("textDocument/didChange", json!({"textDocument":{"uri":uri(&path),"version":2},"contentChanges":[{"text":changed}]})).await;
    let diagnostics = session.published_diagnostics(&path).unwrap();
    for name in [
        "unknown-function",
        "unknown-operation",
        "unknown-step",
        "unknown-type",
        "unknown-outcome",
        "unknown-contract",
    ] {
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic["source"] == "coordinator"
                    && diagnostic["message"].as_str().unwrap().contains(name)),
            "{name}: {diagnostics:?}"
        );
    }
    session.notify("textDocument/didChange", json!({"textDocument":{"uri":uri(&path),"version":3},"contentChanges":[{"text":source}]})).await;
    assert!(session.published_diagnostics(&path).unwrap().is_empty());
    let asset = project.path("functions.rhai");
    fs::remove_file(&asset).unwrap();
    session
        .notify(
            "workspace/didChangeWatchedFiles",
            json!({"changes":[{"uri":uri(&asset),"type":3}]}),
        )
        .await;
    assert!(session
        .published_diagnostics(&path)
        .unwrap()
        .iter()
        .any(|diagnostic| diagnostic["message"]
            .as_str()
            .unwrap()
            .contains("functions.rhai")));
    fs::write(&asset, "fn make_request(args) { args.request }").unwrap();
    session
        .notify(
            "workspace/didChangeWatchedFiles",
            json!({"changes":[{"uri":uri(&asset),"type":1}]}),
        )
        .await;
    assert!(session.published_diagnostics(&path).unwrap().is_empty());
}

#[tokio::test]
async fn coordinator_roots_do_not_adopt_foreign_or_future_documents() {
    for document in [
        "kind: UnrelatedWorkflow\nworkflow: {start: unknown}\n",
        "apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1-retired\n",
    ] {
        let project = Project::new(&[file("workflow.yaml", document)]);
        let path = project.path("workflow.yaml");
        let mut session = LspSession::start();
        session.initialize(project.root()).await;
        session.open(&path, document, 1).await;
        assert_eq!(session.published_diagnostics(&path), None);
        assert!(session
            .request("workspace/symbol", json!({"query":""}))
            .await
            .as_array()
            .unwrap()
            .is_empty());
    }
}

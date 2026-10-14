// SPDX-License-Identifier: Apache-2.0
#[allow(dead_code)]
#[path = "support/lsp.rs"]
mod lsp;
#[path = "support/normalized.rs"]
mod normalized;
use lsp::{uri, LspSession};
use normalized::*;
use serde_json::json;

#[tokio::test]
async fn handshake_and_normalized_project_diagnostics_are_clean() {
    let p = Project::new(SOURCE);
    let mut session = LspSession::start();
    let capabilities = session.initialize(&p.root).await;
    assert_eq!(capabilities["capabilities"]["definitionProvider"], true);
    session.open(&p.path(PROJECT), SOURCE, 1).await;
    assert_eq!(
        session.published_diagnostics(&p.path(PROJECT)),
        Some(vec![])
    );
}
#[tokio::test]
async fn definition_references_completion_and_hover_use_named_sources() {
    let p = Project::new(SOURCE);
    let mut session = LspSession::start();
    session.initialize(&p.root).await;
    session.open(&p.path(PROJECT), SOURCE, 1).await;
    let position = after(SOURCE, "acquisition: {type: single, source: ");
    let params = json!({"textDocument":{"uri":uri(&p.path(PROJECT))},"position":position});
    let definition = session
        .request("textDocument/definition", params.clone())
        .await;
    assert_eq!(
        definition[0]["range"]["start"],
        json!(at(SOURCE, "person:\n"))
    );
    let hover = session.request("textDocument/hover", params.clone()).await;
    assert!(hover["contents"]["value"]
        .as_str()
        .unwrap()
        .contains("source"));
    let completion = session
        .request("textDocument/completion", params.clone())
        .await;
    assert_eq!(completion["items"][0]["label"], "person");
    let refs=session.request("textDocument/references",json!({"textDocument":{"uri":uri(&p.path(PROJECT))},"position":at(SOURCE,"person:\n"),"context":{"includeDeclaration":false}})).await;
    assert_eq!(refs.as_array().unwrap().len(), 1);
}
#[tokio::test]
async fn a_shared_parser_refusal_reaches_the_protocol() {
    let source = SOURCE.replace("source: person}", "source: missing}");
    let p = Project::new(&source);
    let mut session = LspSession::start();
    session.initialize(&p.root).await;
    session.open(&p.path(PROJECT), &source, 1).await;
    let diagnostics = session.published_diagnostics(&p.path(PROJECT)).unwrap();
    assert!(diagnostics
        .iter()
        .any(|d| d["code"] == "evidence.project.acquisition-source"));
    assert!(diagnostics.iter().all(|d| d["source"] == "evidence"));
}

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
async fn every_completion_trigger_uses_the_same_interface_filtered_list() {
    let p = Project::new(SOURCE);
    let mut session = LspSession::start();
    session.initialize(&p.root).await;
    session.open(&p.path(PROJECT), SOURCE, 1).await;
    let mut responses = Vec::new();
    for trigger in [1, 2, 3] {
        responses.push(session.request("textDocument/completion",json!({"textDocument":{"uri":uri(&p.path(PROJECT))},"position":after(SOURCE,"derive: {function: "),"context":{"triggerKind":trigger,"triggerCharacter":"-"}})).await);
    }
    assert_eq!(responses[0], responses[1]);
    assert_eq!(responses[1], responses[2]);
    assert_eq!(responses[0]["items"].as_array().unwrap().len(), 1);
    assert_eq!(responses[0]["items"][0]["label"], "derive-status");
}
#[tokio::test]
async fn positions_outside_the_project_have_no_cards_or_completions() {
    let p = Project::new(SOURCE);
    p.write("notes.yaml", SOURCE);
    let mut session = LspSession::start();
    session.initialize(&p.root).await;
    for path in [
        p.path("notes.yaml"),
        p.path("secrets/key.yaml"),
        p.path(".evidence/dev/bundle.yaml"),
    ] {
        let params =
            json!({"textDocument":{"uri":uri(&path)},"position":{"line":26,"character":41}});
        assert!(session
            .request("textDocument/hover", params.clone())
            .await
            .is_null());
        let c = session.request("textDocument/completion", params).await;
        assert!(c.is_null() || c["items"].as_array().is_none_or(Vec::is_empty));
    }
}
#[tokio::test]
async fn a_line_beyond_the_buffer_has_no_hover() {
    let p = Project::new(SOURCE);
    let mut session = LspSession::start();
    session.initialize(&p.root).await;
    session.open(&p.path(PROJECT), SOURCE, 1).await;
    assert!(session.request("textDocument/hover",json!({"textDocument":{"uri":uri(&p.path(PROJECT))},"position":{"line":9999,"character":0}})).await.is_null());
}

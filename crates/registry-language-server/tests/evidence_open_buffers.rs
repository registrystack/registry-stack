// SPDX-License-Identifier: Apache-2.0
#[allow(dead_code)]
#[path = "support/lsp.rs"]
mod lsp;
#[path = "support/normalized.rs"]
mod normalized;
use lsp::{uri, LspSession};
use normalized::*;
use serde_json::json;

async fn change(session: &mut LspSession, p: &Project, source: &str, version: i32) {
    session.notify("textDocument/didChange",json!({"textDocument":{"uri":uri(&p.path(PROJECT)),"version":version},"contentChanges":[{"text":source}]})).await;
}
#[tokio::test]
async fn unsaved_project_changes_refresh_navigation_and_shared_diagnostics() {
    let p = Project::new(SOURCE);
    let mut session = LspSession::start();
    session.initialize(&p.root).await;
    session.open(&p.path(PROJECT), SOURCE, 1).await;
    let edited = SOURCE.replace("source: person}", "source: missing}");
    change(&mut session, &p, &edited, 2).await;
    assert!(!session
        .published_diagnostics(&p.path(PROJECT))
        .unwrap()
        .is_empty());
    assert!(session.request("textDocument/definition",json!({"textDocument":{"uri":uri(&p.path(PROJECT))},"position":after(&edited,"acquisition: {type: single, source: ")})).await.as_array().is_none_or(Vec::is_empty));
    change(&mut session, &p, SOURCE, 3).await;
    assert_eq!(
        session.published_diagnostics(&p.path(PROJECT)),
        Some(vec![])
    );
}
#[tokio::test]
async fn creating_a_missing_function_asset_refreshes_the_index() {
    let p = Project::new(SOURCE);
    std::fs::remove_file(p.path(DERIVE)).unwrap();
    let mut session = LspSession::start();
    session.initialize(&p.root).await;
    session.open(&p.path(PROJECT), SOURCE, 1).await;
    p.write(
        DERIVE,
        "fn derive(facts,selectors,context) { [#{output: \"active\", value:true}] }\n",
    );
    session
        .notify(
            "workspace/didChangeWatchedFiles",
            json!({"changes":[{"uri":uri(&p.path(DERIVE)),"type":1}]}),
        )
        .await;
    let definition = session
        .request(
            "textDocument/definition",
            json!({"textDocument":{"uri":uri(&p.path(PROJECT))},"position":at(SOURCE,DERIVE)}),
        )
        .await;
    assert_eq!(definition[0]["uri"], uri(&p.path(DERIVE)));
}
#[tokio::test]
async fn an_unsaved_named_function_refreshes_its_interface_diagnostics() {
    let p = Project::new(SOURCE);
    let mut session = LspSession::start();
    session.initialize(&p.root).await;
    session
        .open(&p.path(DERIVE), "fn extract(a,b) {}\n", 1)
        .await;
    assert!(!session
        .published_diagnostics(&p.path(DERIVE))
        .unwrap()
        .is_empty());
}

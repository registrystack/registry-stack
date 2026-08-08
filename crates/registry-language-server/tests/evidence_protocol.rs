// SPDX-License-Identifier: Apache-2.0
//! The Evidence edges as an editor sees them, over the protocol.
//!
//! The tests in `evidence_index.rs` ask the index directly, one edge at a time. These ask the
//! server the way a client does, so that what the index knows is also what reaches an author: the
//! handshake, an opened document, a jump from one file to another, an error published where the
//! editor will draw it, and that error taken back when the file leaves the project under the tab
//! the author still has open.

mod support;

use std::fs;

use serde_json::{json, Value};
use support::{
    adult_status_project,
    lsp::{uri, LspSession},
    replacing, without, EvidenceProject, ACCESS_POLICY_PATH, QUESTION, QUESTION_PATH, SOURCE_PATH,
};

/// The text a client sends for one project file, which is what the file says on disk.
fn text_of(project: &EvidenceProject, relative: &str) -> String {
    fs::read_to_string(project.path(relative)).expect("the project file is readable")
}

#[tokio::test]
async fn the_handshake_offers_the_navigation_an_evidence_author_uses() {
    let project = EvidenceProject::new(&adult_status_project());
    let mut session = LspSession::start();

    let result = session.initialize(project.root()).await;

    let capabilities = &result["capabilities"];
    assert_eq!(capabilities["definitionProvider"], json!(true));
    assert_eq!(capabilities["referencesProvider"], json!(true));
    assert_eq!(capabilities["workspaceSymbolProvider"], json!(true));
    assert_eq!(capabilities["positionEncoding"], json!("utf-16"));
    assert_eq!(
        result["serverInfo"]["name"],
        json!("Registry Stack Language Server")
    );
}

#[tokio::test]
async fn an_opened_question_is_indexed_and_reported_clean() {
    let project = EvidenceProject::new(&adult_status_project());
    let mut session = LspSession::start();
    session.initialize(project.root()).await;

    session
        .open(
            &project.path(QUESTION_PATH),
            &text_of(&project, QUESTION_PATH),
            1,
        )
        .await;

    assert_eq!(
        session.published_diagnostics(&project.path(QUESTION_PATH)),
        Some(Vec::<Value>::new()),
        "the worked project holds nothing to report"
    );
}

/// `LspSession::call` races a `tokio::select!` against the server's notification burst: the
/// answer and the publish the handler triggered can both be ready on the same poll, and which one
/// the loop sees first is decided by `select!`'s internal ordering, not by which happened first.
/// Opening a document is exactly the kind of call that triggers a publish, so this repeats the
/// open many times over fresh sessions and insists the harness drained the opened document's own
/// notification every time, not just on the runs where `select!` happened to favor the socket.
#[tokio::test]
async fn opening_a_document_reliably_drains_its_publish_notification() {
    let project = EvidenceProject::new(&adult_status_project());

    for attempt in 0..50 {
        let mut session = LspSession::start();
        session.initialize(project.root()).await;
        session
            .open(
                &project.path(QUESTION_PATH),
                &text_of(&project, QUESTION_PATH),
                1,
            )
            .await;

        assert!(
            session
                .published_diagnostics(&project.path(QUESTION_PATH))
                .is_some(),
            "attempt {attempt}: the server published for the opened document, but the harness \
             did not drain it before the call returned"
        );
    }
}

#[tokio::test]
async fn definition_on_the_source_a_question_reads_opens_that_source_document() {
    let project = EvidenceProject::new(&adult_status_project());
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let question = project.path(QUESTION_PATH);
    session
        .open(&question, &text_of(&project, QUESTION_PATH), 1)
        .await;

    let cursor = project.cursor(QUESTION_PATH, "source-ref");
    let locations = session
        .request(
            "textDocument/definition",
            json!({
                "textDocument": {"uri": uri(&question)},
                "position": {"line": cursor.line, "character": cursor.character},
            }),
        )
        .await;

    let locations = locations.as_array().expect("definition answers an array");
    assert_eq!(locations.len(), 1, "{locations:?}");
    assert_eq!(locations[0]["uri"], uri(&project.path(SOURCE_PATH)));
}

#[tokio::test]
async fn a_source_that_is_not_there_reaches_the_author_as_an_evidence_error() {
    let question = QUESTION.replace("<|source-ref|>people", "<|source-ref|>ledger");
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        QUESTION_PATH,
        &question,
    ));
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let path = project.path(QUESTION_PATH);

    session
        .open(&path, &text_of(&project, QUESTION_PATH), 1)
        .await;

    let published = session
        .published_diagnostics(&path)
        .expect("the server published for the opened document");
    assert_eq!(published.len(), 1, "{published:?}");
    let diagnostic = &published[0];
    assert_eq!(diagnostic["source"], json!("evidence"));
    assert_eq!(diagnostic["code"], json!("evidence/unknown-source"));
    // Severity 1 is ERROR, which is the only severity this server publishes.
    assert_eq!(diagnostic["severity"], json!(1));
    assert_eq!(
        diagnostic["message"],
        json!("Unknown source reference 'ledger'")
    );
    let cursor = project.cursor(QUESTION_PATH, "source-ref");
    assert_eq!(diagnostic["range"]["start"]["line"], json!(cursor.line));
    assert_eq!(
        diagnostic["range"]["start"]["character"],
        json!(cursor.character)
    );
}

/// A question deleted under a tab the author still has open has its errors taken back.
///
/// An editor draws whatever the last publication for a document said, so a document that leaves
/// the project has to be published clean and not merely dropped from the index. The client keeps
/// the tab open across the deletion, which is what it does for every deleted file, and the watched
/// change is the only thing that tells the server the file is gone. What the compiler reads at that
/// point is a project without the question and without a word to say about it.
#[tokio::test]
async fn a_question_deleted_under_an_open_tab_has_its_errors_taken_back() {
    let question = QUESTION.replace("<|source-ref|>people", "<|source-ref|>ledger");
    let project = EvidenceProject::new(&without(
        &replacing(&adult_status_project(), QUESTION_PATH, &question),
        ACCESS_POLICY_PATH,
    ));
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let path = project.path(QUESTION_PATH);
    session
        .open(&path, &text_of(&project, QUESTION_PATH), 1)
        .await;
    assert_eq!(
        session
            .published_diagnostics(&path)
            .map(|published| published.len()),
        Some(1),
        "the open question names a source the project does not hold"
    );

    fs::remove_file(&path).expect("the project file is removable");
    session
        .notify(
            "workspace/didChangeWatchedFiles",
            // Change type 3 is Deleted.
            json!({"changes": [{"uri": uri(&path), "type": 3}]}),
        )
        .await;

    assert_eq!(
        session.published_diagnostics(&path),
        Some(Vec::<Value>::new()),
        "the tab is still open, and the project the compiler reads no longer holds the file"
    );
}

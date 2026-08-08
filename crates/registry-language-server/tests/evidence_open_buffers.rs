// SPDX-License-Identifier: Apache-2.0
//! What the server answers from while a client holds a tab open across a change on disk.
//!
//! The protocol settles the first question: between `didOpen` and `didClose` the client owns a
//! document's content, so the server answers for that document from the buffer and never from the
//! file under it. The project settles the second: the tree `evidence check` builds is the one its
//! directories hold, so a buffer over a path those directories no longer hold contributes nothing
//! to it. A branch switch asks both questions at once, which is why they are tested together and
//! over the real server rather than against the document store directly.

mod support;

use std::{fs, path::Path};

use serde_json::json;
use support::{
    adult_status_project,
    lsp::{uri, LspSession},
    operation_question_project, replacing, without_cursors, EvidenceProject, ACCESS_POLICY_PATH,
    OPENAPI_PATH, OPERATION_OPENAPI, QUESTION, QUESTION_PATH,
};

/// The text a client sends for one project file, which is what the file says on disk.
fn text_of(project: &EvidenceProject, relative: &str) -> String {
    fs::read_to_string(project.path(relative)).expect("the project file is readable")
}

/// One keystroke: the whole document as the client now holds it, under the version it now carries.
///
/// The server advertises full synchronization, so a change notification carries the text and no
/// range.
async fn change(session: &mut LspSession, path: &Path, text: &str, version: i32) {
    session
        .notify(
            "textDocument/didChange",
            json!({
                "textDocument": {"uri": uri(path), "version": version},
                "contentChanges": [{"text": text}],
            }),
        )
        .await;
}

/// One watched-file change, as a client watching the workspace reports it. Change type 1 is
/// Created and type 3 is Deleted.
async fn watched(session: &mut LspSession, path: &Path, kind: i32) {
    session
        .notify(
            "workspace/didChangeWatchedFiles",
            json!({"changes": [{"uri": uri(path), "type": kind}]}),
        )
        .await;
}

/// One save, as a client that was told to include the text reports it.
async fn saved(session: &mut LspSession, path: &Path, text: &str) {
    session
        .notify(
            "textDocument/didSave",
            json!({"textDocument": {"uri": uri(path)}, "text": text}),
        )
        .await;
}

/// The rules the server last published against one document, in the order it published them.
fn published_codes(session: &LspSession, path: &Path) -> Vec<String> {
    session
        .published_diagnostics(path)
        .unwrap_or_else(|| panic!("the server published for {}", path.display()))
        .iter()
        .map(|diagnostic| {
            diagnostic["code"]
                .as_str()
                .unwrap_or("<published without a code>")
                .to_owned()
        })
        .collect()
}

/// The unsaved revision of a document survives the file under it leaving and coming back.
///
/// This is a branch switch over an edited tab, which is the everyday way a project file leaves and
/// returns while the client still holds the buffer. The client never sent `didClose`, so it still
/// owns the document, and the revision the author is looking at is the one the server has to answer
/// from throughout. Reading the file back over the buffer discards work the author can still see on
/// screen and reports the project from a revision nobody holds.
#[tokio::test]
async fn a_file_that_comes_back_does_not_take_the_tab_still_open_over_it_from_disk() {
    let project = EvidenceProject::new(&adult_status_project());
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let question = project.path(QUESTION_PATH);
    let on_disk = text_of(&project, QUESTION_PATH);
    session.open(&question, &on_disk, 1).await;
    assert_eq!(
        published_codes(&session, &question),
        Vec::<String>::new(),
        "the worked project holds nothing to report"
    );

    let unsaved =
        without_cursors(&QUESTION.replace("<|source-ref|>people", "<|source-ref|>ledger"));
    change(&mut session, &question, &unsaved, 2).await;
    assert_eq!(
        published_codes(&session, &question),
        vec!["evidence/unknown-source"],
        "the unsaved revision names a source the project does not hold"
    );

    fs::remove_file(&question).expect("the project file is removable");
    watched(&mut session, &question, 3).await;
    assert_eq!(
        published_codes(&session, &question),
        Vec::<String>::new(),
        "the project no longer holds the file, so the buffer says nothing about the project"
    );

    fs::write(&question, &on_disk).expect("the project file is writable");
    watched(&mut session, &question, 1).await;

    assert_eq!(
        published_codes(&session, &question),
        vec!["evidence/unknown-source"],
        "the tab was never closed, so the unsaved revision is still what the server answers from"
    );
}

/// A file that returns without the client saying so stops being reported as missing.
///
/// A client is free to report the deletion and not the return: a watcher that misses one event, a
/// checkout the client only half observes. The compiler reads the directory, so from the moment the
/// file is back the project it builds holds the question, and an editor still calling that question
/// unknown is drawing an error over a project `evidence check` accepts. The author is given no
/// keystroke to answer it with, because the document it is reported against is already correct.
#[tokio::test]
async fn a_question_that_comes_back_unannounced_stops_being_reported_as_unknown() {
    let project = EvidenceProject::new(&adult_status_project());
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let question = project.path(QUESTION_PATH);
    let policy = project.path(ACCESS_POLICY_PATH);
    let question_text = text_of(&project, QUESTION_PATH);
    let policy_text = text_of(&project, ACCESS_POLICY_PATH);
    session.open(&question, &question_text, 1).await;
    session.open(&policy, &policy_text, 1).await;
    assert_eq!(
        published_codes(&session, &policy),
        Vec::<String>::new(),
        "the policy admits a question the project holds"
    );

    fs::remove_file(&question).expect("the project file is removable");
    watched(&mut session, &question, 3).await;
    assert_eq!(
        published_codes(&session, &policy),
        vec!["evidence/unknown-question"],
        "the compiler refuses this project too: the policy admits a question it does not hold"
    );

    fs::write(&question, &question_text).expect("the project file is writable");
    change(
        &mut session,
        &policy,
        &format!("{policy_text}# a keystroke somewhere else in the project\n"),
        2,
    )
    .await;

    assert_eq!(
        published_codes(&session, &policy),
        Vec::<String>::new(),
        "the question is back in the directory the compiler reads, so nothing is unknown"
    );
}

/// Saving the OpenAPI description answers the questions that read it.
///
/// The description is the one project file the build reads from disk rather than from the text a
/// root holds, and no question document changes when an author adds the operation to it. So the
/// author has no keystroke anywhere that would answer the report, and until the save is heard the
/// editor is calling an operation the description publishes unpublished, over a project
/// `evidence check` accepts. The client here declares no dynamic file watching, which is what a
/// real client that has none looks like: the save is the only thing the server is told.
#[tokio::test]
async fn a_saved_description_answers_the_question_that_names_its_operation() {
    let described = without_cursors(OPERATION_OPENAPI);
    let unpublished = described.replace("      operationId: readPerson\n", "");
    assert_ne!(
        described, unpublished,
        "the fixture description publishes the operation this removes"
    );
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        OPENAPI_PATH,
        &unpublished,
    ));
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let question = project.path(QUESTION_PATH);
    let description = project.path(OPENAPI_PATH);
    session
        .open(&question, &text_of(&project, QUESTION_PATH), 1)
        .await;
    session.open(&description, &unpublished, 1).await;
    assert_eq!(
        published_codes(&session, &question),
        vec!["evidence/unknown-operation"],
        "the description on disk publishes no operation the question could name"
    );

    fs::write(&description, &described).expect("the project file is writable");
    saved(&mut session, &description, &described).await;

    assert_eq!(
        published_codes(&session, &question),
        Vec::<String>::new(),
        "the description now publishes the operation, so the question names one that is there"
    );
}

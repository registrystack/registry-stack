// SPDX-License-Identifier: Apache-2.0
//! Completion and hover as a real client sends them: sloppy, out of range, and occasionally hostile.
//!
//! `evidence_completion.rs` asks `ProjectIndex` directly, one property at a time, and
//! `evidence_protocol.rs` already covers the two methods' happy path over the protocol: an opened
//! question, a resolved source, an unknown source turned into a diagnostic. This file asks the same
//! two methods the way an editor reaches them when the author is not cooperating: a URI the server
//! has never indexed, a position past the end of a document, a syntax error the parser tolerates, a
//! scheme that names nothing on this filesystem, a completion context the client forgot to send, a
//! buffer that disagrees with disk, and a request that lands in the middle of an edit. None of it
//! should ever panic, hang, or answer from a document the loader refused.

mod support;

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        mpsc::{self, Receiver, RecvTimeoutError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use serde_json::{json, Value};
use support::{
    adult_status_project,
    lsp::{uri, LspSession},
    replacing, without_cursors, EvidenceProject, QUESTION, QUESTION_PATH, SOURCE,
};
use tempfile::TempDir;
use tower_lsp_server::ls_types::Uri;

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

/// A `textDocument/completion` or `textDocument/hover` position, built from plain numbers so a test
/// can hand it values no real editor would compute, such as `u32::MAX`.
fn position(line: u32, character: u32) -> Value {
    json!({"line": line, "character": character})
}

/// The labels a completion response offers, in the order the server sent them.
fn labels_of(response: &Value) -> Vec<String> {
    response["items"]
        .as_array()
        .expect("completion answers a list of items")
        .iter()
        .map(|item| {
            item["label"]
                .as_str()
                .expect("a completion item carries a string label")
                .to_owned()
        })
        .collect()
}

// --- 1. A URI the server has never seen, and one outside every workspace root. ---

/// A path inside the project that was never written to disk and never opened answers empty rather
/// than erroring.
///
/// `root_for` is a directory-prefix test, not a filesystem read, so a hostile or merely confused
/// client asking about a path under the workspace root that does not exist yet still gets a clean,
/// typed answer: an empty completion list and no hover, never a crash from a lookup the loader never
/// indexed.
#[tokio::test]
async fn a_path_the_project_never_held_answers_empty_completion_and_no_hover() {
    let project = EvidenceProject::new(&adult_status_project());
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let ghost = project.path("questions/ghost.yaml");

    let completion = session
        .request(
            "textDocument/completion",
            json!({
                "textDocument": {"uri": uri(&ghost)},
                "position": position(0, 0),
            }),
        )
        .await;
    assert_eq!(completion, json!({"isIncomplete": true, "items": []}));

    let hover = session
        .request(
            "textDocument/hover",
            json!({
                "textDocument": {"uri": uri(&ghost)},
                "position": position(0, 0),
            }),
        )
        .await;
    assert_eq!(hover, Value::Null);
}

/// A real file that exists on disk but sits entirely outside every workspace root answers empty
/// too, and not because the file is missing.
///
/// This is the companion to the previous test: there the path did not exist, here it does, just
/// nowhere the client told the server to look. Both land on the same `root_for` prefix check, and
/// the server does not read a byte of a file it was never asked to index, no matter how well formed
/// that file is.
#[tokio::test]
async fn a_real_file_outside_every_workspace_root_answers_empty_completion_and_no_hover() {
    let project = EvidenceProject::new(&adult_status_project());
    let mut session = LspSession::start();
    session.initialize(project.root()).await;

    let elsewhere = TempDir::new().expect("a second temporary directory");
    let stray = elsewhere.path().join("stray.yaml");
    fs::write(&stray, "id: stray\nquestion: not part of this project\n")
        .expect("the stray file is writable");
    let stray = stray.canonicalize().expect("the stray file canonicalizes");

    let completion = session
        .request(
            "textDocument/completion",
            json!({
                "textDocument": {"uri": uri(&stray)},
                "position": position(0, 0),
            }),
        )
        .await;
    assert_eq!(completion, json!({"isIncomplete": true, "items": []}));

    let hover = session
        .request(
            "textDocument/hover",
            json!({
                "textDocument": {"uri": uri(&stray)},
                "position": position(0, 0),
            }),
        )
        .await;
    assert_eq!(hover, Value::Null);
}

// --- 2. Positions past the end of the document. ---

/// A line number past the last line of an open document answers empty rather than panicking.
///
/// Every match against a position in the index is an `Ord` comparison over plain `u32` fields
/// (`range_contains`, `position_cmp`), so there is no arithmetic here that could overflow or index
/// out of bounds; this proves that reasoning holds over the wire and not only in the unit tests that
/// call the index directly.
#[tokio::test]
async fn a_line_number_past_the_end_of_the_document_answers_empty_completion_and_no_hover() {
    let project = EvidenceProject::new(&adult_status_project());
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let question = project.path(QUESTION_PATH);
    session
        .open(&question, &text_of(&project, QUESTION_PATH), 1)
        .await;

    let completion = session
        .request(
            "textDocument/completion",
            json!({
                "textDocument": {"uri": uri(&question)},
                "position": position(999_999, 0),
            }),
        )
        .await;
    assert_eq!(completion, json!({"isIncomplete": true, "items": []}));

    let hover = session
        .request(
            "textDocument/hover",
            json!({
                "textDocument": {"uri": uri(&question)},
                "position": position(999_999, 0),
            }),
        )
        .await;
    assert_eq!(hover, Value::Null);
}

/// A character offset past the end of a real line answers empty too, on the same reasoning as a
/// line number past the end of the document.
#[tokio::test]
async fn a_character_offset_past_the_end_of_a_line_answers_empty_completion_and_no_hover() {
    let project = EvidenceProject::new(&adult_status_project());
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let question = project.path(QUESTION_PATH);
    session
        .open(&question, &text_of(&project, QUESTION_PATH), 1)
        .await;
    let cursor = project.cursor(QUESTION_PATH, "source-ref");

    let completion = session
        .request(
            "textDocument/completion",
            json!({
                "textDocument": {"uri": uri(&question)},
                "position": position(cursor.line, 999_999),
            }),
        )
        .await;
    assert_eq!(completion, json!({"isIncomplete": true, "items": []}));

    let hover = session
        .request(
            "textDocument/hover",
            json!({
                "textDocument": {"uri": uri(&question)},
                "position": position(cursor.line, 999_999),
            }),
        )
        .await;
    assert_eq!(hover, Value::Null);
}

/// The most extreme position a client can send in either field, `u32::MAX`, answers empty on the
/// same code path as an ordinary out-of-range position. Nothing about this handler does arithmetic
/// on the position that a maximal value would overflow.
#[tokio::test]
async fn the_maximum_u32_position_answers_empty_completion_and_no_hover() {
    let project = EvidenceProject::new(&adult_status_project());
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let question = project.path(QUESTION_PATH);
    session
        .open(&question, &text_of(&project, QUESTION_PATH), 1)
        .await;

    let completion = session
        .request(
            "textDocument/completion",
            json!({
                "textDocument": {"uri": uri(&question)},
                "position": position(u32::MAX, u32::MAX),
            }),
        )
        .await;
    assert_eq!(completion, json!({"isIncomplete": true, "items": []}));

    let hover = session
        .request(
            "textDocument/hover",
            json!({
                "textDocument": {"uri": uri(&question)},
                "position": position(u32::MAX, u32::MAX),
            }),
        )
        .await;
    assert_eq!(hover, Value::Null);
}

// --- 3. A document with a YAML syntax error. ---

/// Completion and hover still work on the well-formed part of a document that has a syntax error
/// later on.
///
/// Tree-sitter recovers a partial tree around the break, and `yaml.rs` already proves at the unit
/// level that values before a trailing syntax error stay readable. This is the same property over
/// the protocol: the `source.ref` cursor sits well before the unterminated flow sequence appended
/// at the end, so a client hovering or completing there should see the same answer it would see over
/// the clean document.
#[tokio::test]
async fn completion_and_hover_still_read_the_text_before_a_later_syntax_error() {
    let malformed = format!("{QUESTION}unterminated: [\n");
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        QUESTION_PATH,
        &malformed,
    ));
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let question = project.path(QUESTION_PATH);
    session
        .open(&question, &text_of(&project, QUESTION_PATH), 1)
        .await;
    let cursor = project.cursor(QUESTION_PATH, "source-ref");

    let completion = session
        .request(
            "textDocument/completion",
            json!({
                "textDocument": {"uri": uri(&question)},
                "position": {"line": cursor.line, "character": cursor.character},
            }),
        )
        .await;
    assert_eq!(labels_of(&completion), vec!["people".to_owned()]);

    let hover = session
        .request(
            "textDocument/hover",
            json!({
                "textDocument": {"uri": uri(&question)},
                "position": {"line": cursor.line, "character": cursor.character},
            }),
        )
        .await;
    let rendered = hover["contents"]["value"]
        .as_str()
        .expect("a hover carries markdown despite the syntax error later in the document");
    assert!(rendered.contains("**source**"), "{rendered}");
    assert!(rendered.contains("`people`"), "{rendered}");
}

// --- 4. `untitled:` and other non-`file:` schemes. ---

/// Completion and hover both decline a document that names nothing on this filesystem, over the
/// protocol and not only in `only_file_uris_name_a_document_on_this_filesystem`'s unit test.
///
/// `document_path` early-returns `None` for anything whose scheme is not `file`, before the handler
/// ever touches the workspace, so the result is `null` rather than the empty list a real but
/// unindexed `file:` path answers with.
#[tokio::test]
async fn non_file_schemes_are_declined_for_completion_and_hover() {
    let project = EvidenceProject::new(&adult_status_project());
    let mut session = LspSession::start();
    session.initialize(project.root()).await;

    for foreign in [
        "untitled:Untitled-1",
        "zipfile:///archive.zip::/registry-stack.yaml",
        "https://example.test/registry-stack.yaml",
    ] {
        session
            .notify(
                "textDocument/didOpen",
                json!({
                    "textDocument": {
                        "uri": foreign,
                        "languageId": "yaml",
                        "version": 1,
                        "text": "id: scratch\n",
                    },
                }),
            )
            .await;

        let completion = session
            .request(
                "textDocument/completion",
                json!({
                    "textDocument": {"uri": foreign},
                    "position": position(0, 0),
                }),
            )
            .await;
        assert_eq!(completion, Value::Null, "{foreign}");

        let hover = session
            .request(
                "textDocument/hover",
                json!({
                    "textDocument": {"uri": foreign},
                    "position": position(0, 0),
                }),
            )
            .await;
        assert_eq!(hover, Value::Null, "{foreign}");
    }
}

// --- 5. Completion context: Invoked, TriggerCharacter, and absent entirely. ---

/// A completion list is the same whether the client names a context or leaves the key out of the
/// request altogether.
///
/// `evidence_protocol.rs`'s `a_list_is_the_same_however_the_client_asked_for_it` already proves
/// `Invoked` and `TriggerCharacter` answer identically. `CompletionParams::context` is `Option` with
/// no `#[serde(default)]` attribute needed, which only matters because plenty of clients simply do
/// not populate optional fields they have nothing to say about; the missing key has to deserialize
/// to `None` and answer the same list as the two contexts that are actually sent.
#[tokio::test]
async fn a_completion_list_is_the_same_whether_the_client_sends_a_context_or_omits_it() {
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        "sources/ledger.yaml",
        SOURCE,
    ));
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let question = project.path(QUESTION_PATH);
    session
        .open(&question, &text_of(&project, QUESTION_PATH), 1)
        .await;
    let cursor = project.cursor(QUESTION_PATH, "source-ref");

    let mut base_params = serde_json::Map::new();
    base_params.insert("textDocument".to_owned(), json!({"uri": uri(&question)}));
    base_params.insert(
        "position".to_owned(),
        json!({"line": cursor.line, "character": cursor.character}),
    );

    let without_context = base_params.clone();
    assert!(
        !without_context.contains_key("context"),
        "the params carry no context key at all, not a context of null"
    );
    let omitted = session
        .request("textDocument/completion", Value::Object(without_context))
        .await;

    let mut invoked = base_params.clone();
    invoked.insert("context".to_owned(), json!({"triggerKind": 1}));
    let invoked = session
        .request("textDocument/completion", Value::Object(invoked))
        .await;

    base_params.insert(
        "context".to_owned(),
        json!({"triggerKind": 2, "triggerCharacter": ":"}),
    );
    let triggered = session
        .request("textDocument/completion", Value::Object(base_params))
        .await;

    assert_eq!(
        labels_of(&omitted),
        vec!["ledger".to_owned(), "people".to_owned()]
    );
    assert_eq!(omitted, invoked, "an absent context changed the answer");
    assert_eq!(omitted, triggered, "an absent context changed the answer");
}

// --- 6. Unsaved buffers and closed documents. ---

/// Hover and completion answer the open, unsaved buffer while it is open, and revert to disk once
/// the client closes the tab.
///
/// This is `evidence_open_buffers.rs`'s ownership rule read through completion and hover instead of
/// diagnostics: between `didOpen` and `didClose` the client's revision is what the server answers
/// from, whatever the file on disk says underneath it, and `RootState::close` reloads from disk the
/// moment the tab closes. `people` and `ledger` are both real sources in this project and both six
/// characters long, so the swap keeps the cursor's line and character stable across every state.
#[tokio::test]
async fn hover_and_completion_answer_the_open_buffer_then_revert_to_disk_on_close() {
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        "sources/ledger.yaml",
        SOURCE,
    ));
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let question = project.path(QUESTION_PATH);
    let on_disk = text_of(&project, QUESTION_PATH);
    assert!(on_disk.contains("ref: people"), "{on_disk}");
    let unsaved =
        without_cursors(&QUESTION.replace("<|source-ref|>people", "<|source-ref|>ledger"));
    let cursor = project.cursor(QUESTION_PATH, "source-ref");

    session.open(&question, &unsaved, 1).await;

    let hover = session
        .request(
            "textDocument/hover",
            json!({
                "textDocument": {"uri": uri(&question)},
                "position": {"line": cursor.line, "character": cursor.character},
            }),
        )
        .await;
    let rendered = hover["contents"]["value"]
        .as_str()
        .expect("a hover carries markdown for the unsaved buffer");
    assert!(rendered.contains("`ledger`"), "{rendered}");
    assert!(!rendered.contains("`people`"), "{rendered}");

    let completion = session
        .request(
            "textDocument/completion",
            json!({
                "textDocument": {"uri": uri(&question)},
                "position": {"line": cursor.line, "character": cursor.character},
            }),
        )
        .await;
    assert_eq!(
        labels_of(&completion),
        vec!["ledger".to_owned(), "people".to_owned()]
    );

    session
        .notify(
            "textDocument/didClose",
            json!({"textDocument": {"uri": uri(&question)}}),
        )
        .await;

    let hover_after_close = session
        .request(
            "textDocument/hover",
            json!({
                "textDocument": {"uri": uri(&question)},
                "position": {"line": cursor.line, "character": cursor.character},
            }),
        )
        .await;
    let rendered = hover_after_close["contents"]["value"]
        .as_str()
        .expect("a hover carries markdown once the document reverts to disk");
    assert!(rendered.contains("`people`"), "{rendered}");
    assert!(!rendered.contains("`ledger`"), "{rendered}");

    let completion_after_close = session
        .request(
            "textDocument/completion",
            json!({
                "textDocument": {"uri": uri(&question)},
                "position": {"line": cursor.line, "character": cursor.character},
            }),
        )
        .await;
    assert_eq!(
        labels_of(&completion_after_close),
        vec!["ledger".to_owned(), "people".to_owned()],
        "both sources still exist as files, closing the tab only changes which revision answers"
    );
}

// --- 7. A change immediately followed by a request: no stale or torn index. ---

/// A hover request sent immediately after a `didChange` never answers from the revision the change
/// just replaced.
///
/// `completions_at` for a reference slot lists every symbol of the right kind the project holds,
/// independent of what is currently typed there (`query_can_offer` matches on kind and scope, never
/// on the current name), so the completion candidate set for this field cannot tell a fresh index
/// from a stale one; hover can, because its markdown names the specific reference under the cursor.
/// `LspSession::notify` awaits the handler's own completion, and `update_document` rebuilds the
/// index synchronously before that await resolves, so this toggles the buffer several times and
/// asserts hover reflects the latest text on every single round trip, catching a torn read that
/// only shows up occasionally rather than one that never showed up in a single pass. A completion
/// request is sent in the same interleaving, immediately after each change, to prove the rebuild
/// itself never crashes or hangs under rapid edits, even though its answer does not vary here.
#[tokio::test]
async fn a_request_immediately_after_a_change_never_serves_the_edit_it_replaced() {
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        "sources/ledger.yaml",
        SOURCE,
    ));
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let question = project.path(QUESTION_PATH);
    session
        .open(&question, &text_of(&project, QUESTION_PATH), 1)
        .await;
    let cursor = project.cursor(QUESTION_PATH, "source-ref");

    for (revision, reference, other) in [
        (2, "ledger", "people"),
        (3, "people", "ledger"),
        (4, "ledger", "people"),
        (5, "people", "ledger"),
    ] {
        let edited = without_cursors(&QUESTION.replace(
            "<|source-ref|>people",
            &format!("<|source-ref|>{reference}"),
        ));
        change(&mut session, &question, &edited, revision).await;

        let hover = session
            .request(
                "textDocument/hover",
                json!({
                    "textDocument": {"uri": uri(&question)},
                    "position": {"line": cursor.line, "character": cursor.character},
                }),
            )
            .await;
        let rendered = hover["contents"]["value"]
            .as_str()
            .unwrap_or_else(|| panic!("revision {revision}: hover carries markdown"));
        assert!(
            rendered.contains(&format!("`{reference}`")),
            "revision {revision}: expected `{reference}`, got {rendered}"
        );
        assert!(
            !rendered.contains(&format!("`{other}`")),
            "revision {revision}: stale `{other}` survived the change, got {rendered}"
        );

        let completion = session
            .request(
                "textDocument/completion",
                json!({
                    "textDocument": {"uri": uri(&question)},
                    "position": {"line": cursor.line, "character": cursor.character},
                }),
            )
            .await;
        assert_eq!(
            labels_of(&completion),
            vec!["ledger".to_owned(), "people".to_owned()],
            "revision {revision}: completion did not survive the interleaved change"
        );
    }
}

// --- 8 and 9: the handshake, `completionItem/resolve`, and stdout hygiene, over a real subprocess. ---
//
// The two properties below need to inspect a JSON-RPC error response and the exact bytes the server
// writes to its own stdout, and `LspSession::request` panics on any error response while
// `LspSession::call` is private, so neither is reachable through the in-process harness. These
// duplicate the small amount of raw framing `tests/protocol.rs` already hand-rolls, because that
// module's helpers are private to their own binary and there is no third crate for both to share.

/// How long a test waits for one more message before concluding the server has stopped producing
/// them.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);

fn send(stdin: &mut ChildStdin, message: Value) {
    let body = serde_json::to_vec(&message).unwrap();
    write!(stdin, "Content-Length: {}\r\n\r\n", body.len()).unwrap();
    stdin.write_all(&body).unwrap();
    stdin.flush().unwrap();
}

/// Reads one framed LSP message from a reader, or `None` once it closes.
fn read_one_message<R: BufRead>(reader: &mut R) -> Option<Value> {
    let mut content_length = None;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap() == 0 {
            return None;
        }
        if header == "\r\n" {
            break;
        }
        if let Some(length) = header.strip_prefix("Content-Length:") {
            content_length = Some(length.trim().parse::<usize>().unwrap());
        }
    }
    let mut body = vec![0; content_length.expect("response has Content-Length")];
    reader.read_exact(&mut body).unwrap();
    Some(serde_json::from_slice(&body).unwrap())
}

/// Reads framed LSP messages off a reader on a background thread and forwards each one to the
/// returned channel, so a caller waiting for a message that never arrives times out on
/// `Receiver::recv_timeout` instead of blocking on the pipe. The join handle lets a caller wait for
/// the thread to observe end-of-stream, which matters for the stdout-hygiene test below: it has to
/// know every byte the process ever wrote has been accounted for before it inspects them.
fn spawn_message_reader<R: Read + Send + 'static>(reader: R) -> (Receiver<Value>, JoinHandle<()>) {
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        while let Some(message) = read_one_message(&mut reader) {
            if sender.send(message).is_err() {
                break; // the test dropped its receiver
            }
        }
    });
    (receiver, handle)
}

fn receive(messages: &Receiver<Value>) -> Value {
    match messages.recv_timeout(MESSAGE_TIMEOUT) {
        Ok(message) => message,
        Err(RecvTimeoutError::Timeout) => {
            panic!("language server sent nothing for {MESSAGE_TIMEOUT:?}")
        }
        Err(RecvTimeoutError::Disconnected) => panic!("language server closed stdout"),
    }
}

fn receive_response(messages: &Receiver<Value>, id: i64) -> Value {
    let mut others = Vec::new();
    loop {
        let message = receive(messages);
        if message.get("id").and_then(Value::as_i64) == Some(id) {
            return message;
        }
        others.push(message);
        assert!(
            others.len() < 50,
            "language server did not return response {id}; received instead: {others:?}"
        );
    }
}

fn file_uri(path: &Path) -> String {
    Uri::from_file_path(path)
        .expect("a project path is absolute")
        .to_string()
}

fn spawn_server(root: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_registry-language-server"))
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the language server binary starts")
}

fn shut_down(stdin: &mut ChildStdin, stdout: &Receiver<Value>, mut child: Child, id: i64) {
    send(
        stdin,
        json!({"jsonrpc": "2.0", "id": id, "method": "shutdown", "params": null}),
    );
    receive_response(stdout, id);
    send(
        stdin,
        json!({"jsonrpc": "2.0", "method": "exit", "params": null}),
    );
    assert!(child
        .wait()
        .expect("the server process is waitable")
        .success());
}

/// The handshake declares exactly what completion and hover implement, and a client that asks the
/// unimplemented `completionItem/resolve` gets a clean method-not-found error rather than a hang.
///
/// `resolve_provider: Some(false)` in `initialize`'s capabilities is only a true statement if there
/// is really no `completion_resolve` override on `Backend`: `tower-lsp-server`'s default
/// implementation for an unoverridden handler returns `Error::method_not_found()`, so the two facts
/// (the advertised capability and the actual dispatch) are checked together here, over the same
/// session, rather than trusted to agree.
#[test]
fn the_handshake_advertises_exactly_what_completion_and_hover_implement() {
    let project = EvidenceProject::new(&adult_status_project());
    let mut child = spawn_server(project.root());
    let mut stdin = child.stdin.take().unwrap();
    let (stdout, _reader) = spawn_message_reader(child.stdout.take().unwrap());

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "capabilities": {},
                "workspaceFolders": [{"uri": file_uri(project.root()), "name": "project"}],
            }
        }),
    );
    let initialize = receive_response(&stdout, 1);
    let capabilities = &initialize["result"]["capabilities"];
    assert_eq!(
        capabilities["completionProvider"]["triggerCharacters"],
        json!([":", ".", "/"])
    );
    assert_eq!(
        capabilities["completionProvider"]["resolveProvider"],
        json!(false)
    );
    assert_eq!(capabilities["hoverProvider"], json!(true));

    send(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "completionItem/resolve",
            "params": {"label": "people"}
        }),
    );
    let resolve = receive_response(&stdout, 2);
    assert!(
        resolve.get("result").is_none(),
        "completionItem/resolve answered a result despite advertising no resolve support: {resolve}"
    );
    assert_eq!(
        resolve["error"]["code"],
        json!(-32601),
        "expected a method-not-found error: {resolve}"
    );

    shut_down(&mut stdin, &stdout, child, 3);
}

/// A reader that copies every byte it reads into a shared buffer, so the bytes the test asserts on
/// are exactly the ones the reading side of the protocol actually consumed, in order, with nothing
/// skipped.
struct CapturingReader<R> {
    inner: R,
    raw: Arc<Mutex<Vec<u8>>>,
}

impl<R: Read> Read for CapturingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.raw.lock().unwrap().extend_from_slice(&buf[..read]);
        Ok(read)
    }
}

/// Parses a raw byte stream as a strict sequence of `Content-Length` framed JSON-RPC messages,
/// panicking with the byte offset of the first thing that is not one: a stray log line, a header
/// with no terminating blank line, a declared length that runs past the end of the stream, or a body
/// that is not valid JSON. This is deliberately stricter than [`read_one_message`]: that helper
/// (like `tests/protocol.rs`'s) only looks for a `Content-Length:` line and silently ignores any
/// other header-shaped line, which would quietly absorb exactly the kind of stray output this test
/// exists to catch. Returns the number of messages found, so a caller can also assert the exchange
/// was not vacuously empty.
fn assert_only_framed_json_rpc(raw: &[u8]) -> usize {
    let mut cursor = 0;
    let mut messages = 0;
    while cursor < raw.len() {
        let remaining = &raw[cursor..];
        let header_end = remaining
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap_or_else(|| {
                panic!(
                    "byte {cursor} starts a header block with no terminating blank line; next \
                     bytes: {:?}",
                    String::from_utf8_lossy(&remaining[..remaining.len().min(200)])
                )
            });
        let header = std::str::from_utf8(&remaining[..header_end])
            .unwrap_or_else(|error| panic!("byte {cursor}: header is not valid UTF-8: {error}"));
        let content_length = header
            .split("\r\n")
            .find_map(|line| line.strip_prefix("Content-Length:"))
            .unwrap_or_else(|| {
                panic!("byte {cursor}: header carries no Content-Length: {header:?}")
            })
            .trim()
            .parse::<usize>()
            .unwrap_or_else(|error| {
                panic!("byte {cursor}: malformed Content-Length in {header:?}: {error}")
            });
        cursor += header_end + 4;
        let body = raw.get(cursor..cursor + content_length).unwrap_or_else(|| {
            panic!(
                "byte {cursor}: Content-Length {content_length} runs past the {} bytes captured",
                raw.len()
            )
        });
        serde_json::from_slice::<Value>(body)
            .unwrap_or_else(|error| panic!("byte {cursor}: frame body is not valid JSON: {error}"));
        cursor += content_length;
        messages += 1;
    }
    messages
}

/// Nothing but framed JSON-RPC ever reaches the server's stdout, even while a client sends a battery
/// of hostile and sloppy completion and hover requests: extreme positions, a document that was never
/// opened, a document that was never even named by a `didOpen`, negative numbers where the protocol
/// promises a `u32`, and a method the server does not implement at all.
///
/// A stray `println!`, a panic message written to the wrong stream, or a partially written frame
/// would corrupt every message after it for a real client reading this same pipe, which is a defect
/// no single request/response assertion can see: the response to the very request that provoked the
/// corruption can still look correct while the byte stream around it is already broken. This
/// captures every byte the process wrote to stdout for the whole session and re-parses it from
/// scratch with [`assert_only_framed_json_rpc`], independent of and stricter than the header-skipping
/// reader used to drive the conversation.
#[test]
fn nothing_but_framed_json_rpc_reaches_stdout_under_hostile_requests() {
    let project = EvidenceProject::new(&adult_status_project());
    let mut child = spawn_server(project.root());
    let mut stdin = child.stdin.take().unwrap();
    let raw = Arc::new(Mutex::new(Vec::new()));
    let tee = CapturingReader {
        inner: child.stdout.take().unwrap(),
        raw: raw.clone(),
    };
    let (stdout, reader) = spawn_message_reader(tee);

    let question = project.path(QUESTION_PATH);
    let question_uri = file_uri(&question);

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "capabilities": {},
                "workspaceFolders": [{"uri": file_uri(project.root()), "name": "project"}],
            }
        }),
    );
    receive_response(&stdout, 1);
    send(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": question_uri,
                    "languageId": "yaml",
                    "version": 1,
                    "text": text_of(&project, QUESTION_PATH),
                }
            }
        }),
    );

    // The maximum position, on a document the client did open.
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {"uri": question_uri},
                "position": {"line": u32::MAX, "character": u32::MAX},
            }
        }),
    );
    receive_response(&stdout, 2);

    // A hover for a document that was never named by any `didOpen`, `didChange`, or project file.
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": "untitled:Untitled-1"},
                "position": {"line": 0, "character": 0},
            }
        }),
    );
    receive_response(&stdout, 3);

    // A position whose line is negative, which is not representable in the `u32` the protocol
    // promises: this has to fail parameter deserialization rather than silently wrapping or
    // truncating into some other position.
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {"uri": question_uri},
                "position": {"line": -1, "character": 0},
            }
        }),
    );
    let malformed = receive_response(&stdout, 4);
    assert!(
        malformed.get("result").is_none(),
        "a negative line answered a result instead of an error: {malformed}"
    );
    assert!(malformed.get("error").is_some(), "{malformed}");

    // A method the server never registers at all.
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "textDocument/frobnicate",
            "params": {}
        }),
    );
    let unknown_method = receive_response(&stdout, 5);
    assert_eq!(
        unknown_method["error"]["code"],
        json!(-32601),
        "{unknown_method}"
    );

    // The session still answers an ordinary request correctly after all of the above: none of the
    // hostile input left the server, or the harness's read of it, in a broken state.
    let cursor = project.cursor(QUESTION_PATH, "source-ref");
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": question_uri},
                "position": {"line": cursor.line, "character": cursor.character},
            }
        }),
    );
    let recovered = receive_response(&stdout, 6);
    assert!(
        recovered["result"]["contents"]["value"]
            .as_str()
            .is_some_and(|markdown| markdown.contains("`people`")),
        "{recovered}"
    );

    shut_down(&mut stdin, &stdout, child, 7);
    reader
        .join()
        .expect("the stdout reader thread does not panic");

    let raw = raw.lock().unwrap();
    let messages = assert_only_framed_json_rpc(&raw);
    assert!(
        messages >= 7,
        "expected at least the 7 responses this test correlated by id, found {messages} frames"
    );
}

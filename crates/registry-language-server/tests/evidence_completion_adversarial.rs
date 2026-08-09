// SPDX-License-Identifier: Apache-2.0
//! What the list of names offered at a field promises, driven against the promise rather than
//! against the code that makes it.
//!
//! `evidence_completion.rs` asserts that the list is the kind of name the field takes. These tests
//! ask the harder question the invariant asks of every surface of this server: the editor is never
//! stricter than the compiler, and a list is the one place where the editor can be *looser* than
//! the compiler and still mislead. A name offered at a field is a name the author is told they may
//! write there. Offering one `evidence check` refuses hands the author a keystroke that breaks the
//! project, and hands it to them in the moment they were asking what is allowed.
//!
//! So the tests below come in two halves. The first half drives the properties completion claims
//! for itself: that asking for a list never reports anything, that the trigger a client fired on
//! does not change the answer, that a name a root does not hold never reaches its list, that a
//! departed name departs, and that accepting a candidate leaves the document the author meant. The
//! second half is the other direction, and each test there fails: a field is offered a name the
//! authoring form or the compiler refuses at that field.

mod support;

use std::{fs, path::Path};

use registry_evidence_authoring::{
    model::Question, testing::ProjectFile, validate::validate_answer_schema_path,
};
use registry_language_server::{CompletionCandidate, ProjectIndex};
use serde_json::{json, Value};
use support::{
    adult_status_project, file,
    lsp::{uri, LspSession},
    operation_question_project, replacing, without_cursors, EvidenceProject, DERIVATION,
    OPENAPI_PATH, OPERATION_OPENAPI, OPERATION_QUESTION, QUESTION, QUESTION_PATH, SCHEMA, SOURCE,
    SOURCE_PATH,
};
use tower_lsp_server::ls_types::{Position, Range};

/// The labels one position offers, in the order they are offered.
fn labels_at(
    index: &ProjectIndex,
    project: &EvidenceProject,
    relative: &str,
    cursor: &str,
) -> Vec<String> {
    candidates_at(index, project, relative, cursor)
        .into_iter()
        .map(|candidate| candidate.label)
        .collect()
}

fn candidates_at(
    index: &ProjectIndex,
    project: &EvidenceProject,
    relative: &str,
    cursor: &str,
) -> Vec<CompletionCandidate> {
    index.completions_at(&project.path(relative), project.cursor(relative, cursor))
}

/// The one candidate carrying a label, so a test names the entry it is about instead of counting
/// into a list whose length is what the test is checking elsewhere.
fn candidate_named(
    index: &ProjectIndex,
    project: &EvidenceProject,
    relative: &str,
    cursor: &str,
    label: &str,
) -> CompletionCandidate {
    let candidates = candidates_at(index, project, relative, cursor);
    candidates
        .iter()
        .find(|candidate| candidate.label == label)
        .unwrap_or_else(|| panic!("the field offers '{label}': {candidates:?}"))
        .clone()
}

/// The rule codes a project reports, in the order it reports them.
fn reported_codes(index: &ProjectIndex) -> Vec<&str> {
    index
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_deref().unwrap_or("<no code>"))
        .collect()
}

/// The text of a document with one candidate accepted into it, as a client applies the edit.
///
/// The range is in the protocol's own units, which are UTF-16 code units into a line, so this
/// converts the way a conforming client converts. A test that applied a candidate by byte offsets
/// would be testing its own arithmetic against the server's rather than the server against the
/// protocol.
///
/// What lands in the document is the candidate's text rather than its label, which is what a client
/// applies: the label is what the menu draws, and the two are the same name spelled for two places.
fn accepted(text: &str, candidate: &CompletionCandidate) -> String {
    let mut edited = text.to_owned();
    edited.replace_range(
        byte_offset(text, candidate.range.start)..byte_offset(text, candidate.range.end),
        &candidate.new_text,
    );
    edited
}

/// Where a protocol position falls in the bytes of a document.
fn byte_offset(text: &str, position: Position) -> usize {
    let line_start = text
        .split_inclusive('\n')
        .take(position.line as usize)
        .map(str::len)
        .sum::<usize>();
    assert!(
        line_start <= text.len(),
        "{position:?} names a line past the end of the document"
    );
    let line = text[line_start..].lines().next().unwrap_or("");
    let mut units = 0;
    for (index, character) in line.char_indices() {
        if units >= position.character {
            return line_start + index;
        }
        units += character.len_utf16() as u32;
    }
    assert!(
        units >= position.character,
        "{position:?} names a column past the end of its line"
    );
    line_start + line.len()
}

/// The text a client sends for one project file, which is what the file says on disk.
fn text_of(project: &EvidenceProject, relative: &str) -> String {
    fs::read_to_string(project.path(relative)).expect("the project file is readable")
}

/// A second source document beside the one the shared project holds, so a list of the sources a
/// question may read cannot pass by echoing the name already written.
fn project_with_two_sources() -> Vec<ProjectFile> {
    replacing(&adult_status_project(), "sources/ledger.yaml", SOURCE)
}

/// The compact-form description with a second leaf in its response, so a list of fact paths is
/// longer than the one path the question already projects.
fn description_with_two_leaves() -> String {
    let described = OPERATION_OPENAPI.replace(
        "                type: object\n                properties:\n",
        "                type: object\n                properties:\n                  \
         record_count: {type: integer}\n",
    );
    assert_ne!(
        described, OPERATION_OPENAPI,
        "the description declares the response object this adds a second leaf to"
    );
    described
}

/// The labels one completion answer carries, read out of the protocol response rather than out of
/// the index, so a test over the server asserts what a client really receives.
fn protocol_labels(answer: &Value) -> Vec<String> {
    answer["items"]
        .as_array()
        .expect("completion answers a list of items")
        .iter()
        .map(|item| {
            item["label"]
                .as_str()
                .expect("every item carries a label")
                .to_owned()
        })
        .collect()
}

async fn complete(
    session: &mut LspSession,
    path: &Path,
    position: Position,
    context: Value,
) -> Value {
    session
        .request(
            "textDocument/completion",
            json!({
                "textDocument": {"uri": uri(path)},
                "position": {"line": position.line, "character": position.character},
                "context": context,
            }),
        )
        .await
}

/// One keystroke: the whole document as the client now holds it. The server advertises full
/// synchronization, so a change notification carries the text and no range.
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

/// One watched-file change, as a client watching the workspace reports it. Change type 3 is
/// Deleted.
async fn watched(session: &mut LspSession, path: &Path, kind: i32) {
    session
        .notify(
            "workspace/didChangeWatchedFiles",
            json!({"changes": [{"uri": uri(path), "type": kind}]}),
        )
        .await;
}

// ---------------------------------------------------------------------------------------------
// Properties that hold.
// ---------------------------------------------------------------------------------------------

/// Asking what may stand somewhere is not an assertion that something is wrong there.
///
/// The list of selectable leaves is recorded during the same walk that reports an unselectable fact
/// path, and it is recorded first, on every path the author wrote, before the rung below decides
/// whether any of them is a leaf. So the two could plausibly be entangled: a recorded choice that
/// suppressed a report, or a report that truncated the recording. This writes a question with one
/// good fact path and one bad one and insists on both halves at once. Exactly one path is reported,
/// which is the one that is wrong, and both paths are offered the same complete list, which is the
/// moment the list is worth most.
#[test]
fn recording_a_list_neither_adds_a_report_nor_takes_one_away() {
    const ONE_FACT: &str = concat!(
        "    - name: date_of_birth\n",
        "      path: <|fact-path|>/records/*/date_of_birth\n",
        "      combine: collect\n",
    );
    const TWO_FACTS: &str = concat!(
        "    - name: date_of_birth\n",
        "      path: <|fact-path|>/records/*/date_of_birth\n",
        "      combine: collect\n",
        "    - name: record_count\n",
        "      path: <|second-path|>/record_countt\n",
        "      combine: exactly-one\n",
    );
    let two_facts = OPERATION_QUESTION.replace(ONE_FACT, TWO_FACTS);
    assert_ne!(
        two_facts, OPERATION_QUESTION,
        "the compact question writes the single fact this replaces with two"
    );
    let project = EvidenceProject::new(&replacing(
        &replacing(
            &operation_question_project(),
            OPENAPI_PATH,
            &description_with_two_leaves(),
        ),
        QUESTION_PATH,
        &two_facts,
    ));
    let index = project.index();

    assert_eq!(
        reported_codes(&index),
        vec!["evidence/unselectable-fact-path"],
        "one fact path is not a leaf and one is, so exactly one of them is reported"
    );
    let offered = vec![
        "/record_count".to_owned(),
        "/records/*/date_of_birth".to_owned(),
    ];
    assert_eq!(
        labels_at(&index, &project, QUESTION_PATH, "fact-path"),
        offered,
        "the path that is a leaf is offered every leaf"
    );
    assert_eq!(
        labels_at(&index, &project, QUESTION_PATH, "second-path"),
        offered,
        "the path that is not a leaf is offered every leaf, at the field being reported"
    );
}

/// The same claim swept rather than argued: over two whole projects, every position of every
/// document the index holds, plus the description it reads from disk, is asked for a list, and the
/// project reports exactly what it reported before anything was asked. A list is drawn from a
/// fourth vector nothing in `build_diagnostics` reads, and this is what that separation is for.
#[test]
fn no_position_of_any_document_turns_a_list_into_a_report() {
    for files in [project_with_two_sources(), operation_question_project()] {
        let project = EvidenceProject::new(&files);
        let index = project.index();
        let before = index.diagnostics().to_vec();
        let mut paths = index
            .document_paths()
            .map(Path::to_path_buf)
            .collect::<Vec<_>>();
        paths.push(project.path(OPENAPI_PATH));

        let mut offered = 0;
        for path in &paths {
            let text = fs::read_to_string(path).unwrap_or_default();
            for (line, contents) in text.lines().enumerate() {
                for character in 0..=contents.encode_utf16().count() {
                    let position = Position::new(line as u32, character as u32);
                    offered += usize::from(!index.completions_at(path, position).is_empty());
                }
            }
        }

        assert!(offered > 0, "the sweep asked somewhere a list is offered");
        assert_eq!(
            index.diagnostics(),
            before,
            "asking for a list changed what the project reports"
        );
    }
}

/// Which trigger kind a client sends is decided by client settings this server has no say in, and
/// `evidence_protocol.rs` already holds the two ordinary kinds over a field that resolves a
/// reference. This covers the other branch of `completions_at`, the one that answers from a
/// recorded set of choices rather than from a reference, and adds the kind a client sends when it
/// is re-asking an incomplete list. Every list this server returns is incomplete, so that third
/// kind is the one an author's second keystroke actually produces.
#[tokio::test]
async fn the_trigger_kind_does_not_change_a_list_over_a_fact_path() {
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        OPENAPI_PATH,
        &description_with_two_leaves(),
    ));
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let question = project.path(QUESTION_PATH);
    session
        .open(&question, &text_of(&project, QUESTION_PATH), 1)
        .await;
    let cursor = project.cursor(QUESTION_PATH, "fact-path");

    let mut answers = Vec::new();
    // Trigger kind 1 is Invoked, 2 is TriggerCharacter and 3 is TriggerForIncompleteCompletions.
    for context in [
        json!({"triggerKind": 1}),
        json!({"triggerKind": 2, "triggerCharacter": "/"}),
        json!({"triggerKind": 2, "triggerCharacter": ":"}),
        json!({"triggerKind": 2, "triggerCharacter": "."}),
        json!({"triggerKind": 3}),
        Value::Null,
    ] {
        answers.push(complete(&mut session, &question, cursor, context).await);
    }

    assert_eq!(
        protocol_labels(&answers[0]),
        vec![
            "/record_count".to_owned(),
            "/records/*/date_of_birth".to_owned()
        ]
    );
    for (position, answer) in answers.iter().enumerate().skip(1) {
        assert_eq!(
            answer, &answers[0],
            "context {position} changed the answer the author sees"
        );
    }
}

/// A root answers from the project it is, and from no other. Two folders open beside each other in
/// one window is the ordinary shape of a working day, and a name offered from the wrong one is a
/// name the compiler reading this project has never heard of.
#[tokio::test]
async fn a_name_only_another_root_holds_is_not_offered_in_this_one() {
    let first = EvidenceProject::new(&project_with_two_sources());
    let second = EvidenceProject::new(&adult_status_project());
    let mut session = LspSession::start();
    session
        .request(
            "initialize",
            json!({
                "processId": null,
                "capabilities": {},
                "workspaceFolders": [
                    {"uri": uri(first.root()), "name": "first"},
                    {"uri": uri(second.root()), "name": "second"},
                ],
            }),
        )
        .await;
    session.notify("initialized", json!({})).await;

    let answer = complete(
        &mut session,
        &second.path(QUESTION_PATH),
        second.cursor(QUESTION_PATH, "source-ref"),
        json!({"triggerKind": 1}),
    )
    .await;

    assert_eq!(
        protocol_labels(&answer),
        vec!["people".to_owned()],
        "the second root holds one source, and the first root's second source reached its list"
    );
    let answer = complete(
        &mut session,
        &first.path(QUESTION_PATH),
        first.cursor(QUESTION_PATH, "source-ref"),
        json!({"triggerKind": 1}),
    )
    .await;
    assert_eq!(
        protocol_labels(&answer),
        vec!["ledger".to_owned(), "people".to_owned()],
        "and the first root still answers from everything it holds"
    );
}

/// A document no root holds is a document this server knows nothing about, and a list is one of the
/// two ways it could answer about one anyway.
#[tokio::test]
async fn a_document_outside_every_root_is_offered_nothing() {
    let project = EvidenceProject::new(&project_with_two_sources());
    let outside = tempfile::TempDir::new().expect("a directory beside the project");
    let stray = outside.path().join("adult-status.yaml");
    fs::write(&stray, without_cursors(QUESTION)).expect("the stray file is writable");
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    session.open(&stray, &without_cursors(QUESTION), 1).await;

    let answer = complete(
        &mut session,
        &stray,
        project.cursor(QUESTION_PATH, "source-ref"),
        json!({"triggerKind": 1}),
    )
    .await;

    assert_eq!(protocol_labels(&answer), Vec::<String>::new());
}

/// The containment gate is a filesystem rule, and a symbolic link is the case it exists for. A
/// source the gate refuses is a source the project does not hold, and a name the project does not
/// hold must not be offered as one a question may read.
#[test]
fn a_source_the_containment_gate_refuses_is_not_offered() {
    let outside = tempfile::TempDir::new().expect("a directory beside the project");
    let target = outside.path().join("ledger.yaml");
    fs::write(&target, without_cursors(SOURCE)).expect("the outside file is writable");
    let project = EvidenceProject::new(&adult_status_project());
    std::os::unix::fs::symlink(&target, project.path("sources/ledger.yaml"))
        .expect("the link is creatable");
    let index = project.index();

    assert_eq!(
        labels_at(&index, &project, QUESTION_PATH, "source-ref"),
        vec!["people".to_owned()],
        "a source reached only through a link out of the project was offered as one to read"
    );
}

/// A name the author just deleted is a name the compiler no longer resolves, and the list is
/// rebuilt from the buffer rather than from the revision the file was opened at.
#[tokio::test]
async fn a_concept_removed_by_a_keystroke_stops_being_offered() {
    let project = EvidenceProject::new(&adult_status_project());
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let question = project.path(QUESTION_PATH);
    session
        .open(&question, &text_of(&project, QUESTION_PATH), 1)
        .await;
    let cursor = project.cursor(QUESTION_PATH, "allow");
    assert_eq!(
        protocol_labels(
            &complete(&mut session, &question, cursor, json!({"triggerKind": 1})).await
        ),
        vec!["is_adult".to_owned()]
    );

    let renamed = without_cursors(&QUESTION.replace("<|concept|>is_adult", "<|concept|>is_of_age"));
    change(&mut session, &question, &renamed, 2).await;

    assert_eq!(
        protocol_labels(
            &complete(&mut session, &question, cursor, json!({"triggerKind": 1})).await
        ),
        vec!["is_of_age".to_owned()],
        "the concept the author renamed away from is still on the menu"
    );
}

/// A file the client reports gone is gone from the project the compiler reads, whether or not a tab
/// is still open over it. Both halves matter here: the deletion has to reach the list, and the tab
/// held aside over the departed file must not put the name back.
#[tokio::test]
async fn a_deleted_source_stops_being_offered_with_and_without_a_tab_over_it() {
    for keep_open in [false, true] {
        let project = EvidenceProject::new(&project_with_two_sources());
        let mut session = LspSession::start();
        session.initialize(project.root()).await;
        let question = project.path(QUESTION_PATH);
        let ledger = project.path("sources/ledger.yaml");
        session
            .open(&question, &text_of(&project, QUESTION_PATH), 1)
            .await;
        if keep_open {
            session
                .open(&ledger, &text_of(&project, "sources/ledger.yaml"), 1)
                .await;
        }
        let cursor = project.cursor(QUESTION_PATH, "source-ref");
        assert_eq!(
            protocol_labels(
                &complete(&mut session, &question, cursor, json!({"triggerKind": 1})).await
            ),
            vec!["ledger".to_owned(), "people".to_owned()],
            "the project holds both sources before the deletion"
        );

        fs::remove_file(&ledger).expect("the project file is removable");
        watched(&mut session, &ledger, 3).await;

        assert_eq!(
            protocol_labels(
                &complete(&mut session, &question, cursor, json!({"triggerKind": 1})).await
            ),
            vec!["people".to_owned()],
            "a source the project no longer holds is still offered (tab open: {keep_open})"
        );
    }
}

/// Accepting a candidate replaces the value the author wrote and nothing beside it, in a document
/// whose columns are not its bytes.
///
/// The protocol counts UTF-16 code units into a line, and a name being typed is exactly where a
/// paste of the wrong keyboard layout ends up. Three placements are checked at once because they
/// fail differently: characters inside the value move the end of the range, characters before it on
/// the same line move the start, and a quoted value puts a delimiter one column outside a range
/// that must not reach it. An off-by-one in any of the three eats a quote or a comma, and the
/// author's next keystroke is against a document that no longer parses.
#[test]
fn accepting_a_candidate_beside_multibyte_text_leaves_the_document_the_author_meant() {
    let unquoted = QUESTION.replace("<|source-ref|>people", "<|source-ref|>\u{1d51e}ledger");
    let quoted = QUESTION.replace("<|source-ref|>people", "'<|source-ref|>\u{1d51e}ledger'");
    let policy = "version: 1\nid: adult-checks\nquestions: [a-\u{1d51e}dult-status, \
                  <|policy-question|>adult-statu]\n";

    for (relative, cursor, written, label, expected) in [
        (
            QUESTION_PATH,
            "source-ref",
            unquoted.as_str(),
            "people",
            "  ref: people\n",
        ),
        (
            QUESTION_PATH,
            "source-ref",
            quoted.as_str(),
            "people",
            "  ref: 'people'\n",
        ),
        (
            "access/policies/adult-checks.yaml",
            "policy-question",
            policy,
            "adult-status",
            "questions: [a-\u{1d51e}dult-status, adult-status]\n",
        ),
    ] {
        let project =
            EvidenceProject::new(&replacing(&project_with_two_sources(), relative, written));
        let index = project.index();
        let text = text_of(&project, relative);

        let candidate = candidate_named(&index, &project, relative, cursor, label);
        let edited = accepted(&text, &candidate);

        assert!(
            edited.contains(expected),
            "accepting '{label}' over {written:?} left {edited:?}"
        );
        assert_eq!(
            edited.len(),
            text.len() + candidate.new_text.len() - replaced_bytes(&text, candidate.range),
            "the edit replaced more or less of the document than the value the author wrote"
        );
    }
}

/// How many bytes of a document a range covers, for the length check above.
fn replaced_bytes(text: &str, range: Range) -> usize {
    byte_offset(text, range.end) - byte_offset(text, range.start)
}

/// The same, at the other branch of `completions_at`: a fact path is answered from a recorded set
/// of choices rather than from a reference, and it carries its own range.
#[test]
fn accepting_a_leaf_over_a_multibyte_fact_path_leaves_the_document_the_author_meant() {
    let project = EvidenceProject::new(&replacing(
        &replacing(
            &operation_question_project(),
            OPENAPI_PATH,
            &description_with_two_leaves(),
        ),
        QUESTION_PATH,
        &OPERATION_QUESTION.replace(
            "path: <|fact-path|>/records/*/date_of_birth",
            "path: <|fact-path|>/records/*/\u{1d51e}ate",
        ),
    ));
    let index = project.index();
    let text = text_of(&project, QUESTION_PATH);

    let candidate = candidate_named(
        &index,
        &project,
        QUESTION_PATH,
        "fact-path",
        "/records/*/date_of_birth",
    );

    assert!(
        accepted(&text, &candidate).contains("      path: /records/*/date_of_birth\n"),
        "accepting a leaf left {:?}",
        accepted(&text, &candidate)
    );
}

/// Accepting a name that carries YAML's own punctuation leaves the field holding that name.
///
/// What a candidate is called is unrestricted: an `operationId` is whatever the description's author
/// wrote, and nothing in the form checks its characters. The range an offer replaces is the value
/// the author wrote and not the quotes around it, so a name put there is read back by the scalar it
/// lands in and has to be spelled for it. Each document below is read back with the deserializer the
/// compiler reads a question with, which is both the proof that it still parses and the proof that
/// the field holds the name that was offered.
#[test]
fn accepting_a_name_carrying_yaml_punctuation_leaves_the_field_holding_that_name() {
    for (published, written, label, expected) in [
        (
            "'<|operation-id|>read: person'",
            "operation: <|operation|>readPerson",
            "read: person",
            "  operation: \"read: person\"\n",
        ),
        (
            "'<|operation-id|>say \"hi\"'",
            "operation: \"<|operation|>readPerson\"",
            "say \"hi\"",
            "  operation: \"say \\\"hi\\\"\"\n",
        ),
        (
            "\"<|operation-id|>it's\"",
            "operation: '<|operation|>readPerson'",
            "it's",
            "  operation: 'it''s'\n",
        ),
    ] {
        let project = EvidenceProject::new(&replacing(
            &replacing(
                &operation_question_project(),
                OPENAPI_PATH,
                &OPERATION_OPENAPI.replace("<|operation-id|>readPerson", published),
            ),
            QUESTION_PATH,
            &OPERATION_QUESTION.replace("operation: <|operation|>readPerson", written),
        ));
        let index = project.index();
        let text = text_of(&project, QUESTION_PATH);

        let candidate = candidate_named(&index, &project, QUESTION_PATH, "operation", label);
        let edited = accepted(&text, &candidate);

        assert!(
            edited.contains(expected),
            "accepting '{label}' over {written:?} left {edited:?}"
        );
        let question = serde_norway::from_str::<Question>(&edited)
            .unwrap_or_else(|error| panic!("accepting '{label}' left {edited:?}: {error}"));
        assert_eq!(question.source.operation.as_deref(), Some(label));
    }
}

/// The same, where the value the author is writing is a mapping key.
///
/// A bound is written as the key of `source.collectionBounds`, so the text put there is followed by
/// the `:` that ends the key. A name carrying its own `: ` would end the key early, which is a
/// document that does not parse rather than one holding the wrong name.
#[test]
fn accepting_a_collection_bound_that_carries_a_separator_leaves_a_document_that_parses() {
    let collection = "/rec: ords";
    let project = EvidenceProject::new(&replacing(
        &replacing(
            &operation_question_project(),
            OPENAPI_PATH,
            &OPERATION_OPENAPI.replace(
                "                  records:",
                "                  \"rec: ords\":",
            ),
        ),
        QUESTION_PATH,
        &OPERATION_QUESTION.replace(
            "path: <|fact-path|>/records/*/date_of_birth",
            "path: '<|fact-path|>/rec: ords/*/date_of_birth'",
        ),
    ));
    let index = project.index();
    let text = text_of(&project, QUESTION_PATH);

    let candidate = candidate_named(
        &index,
        &project,
        QUESTION_PATH,
        "collection-bound",
        collection,
    );
    let edited = accepted(&text, &candidate);

    assert!(
        edited.contains("    \"/rec: ords\": 16\n"),
        "accepting '{collection}' left {edited:?}"
    );
    let question = serde_norway::from_str::<Question>(&edited)
        .unwrap_or_else(|error| panic!("accepting '{collection}' left {edited:?}: {error}"));
    assert!(
        question.source.collection_bounds.contains_key(collection),
        "the bound the author accepted is the one the field holds: {:?}",
        question.source.collection_bounds
    );
}

/// A value written as a block scalar is offered nothing, which is the other side of the same rule.
///
/// A block scalar's text is not its value, so `scalar_from_node` indexes none, and there is no
/// fourth style for a candidate to be spelled for. That leaves the list empty at such a field. The
/// invariant is one-sided, so a name the author is not offered costs them a keystroke, while a name
/// spelled for a style this could not read would cost them a document that no longer parses.
#[test]
fn a_name_written_as_a_block_scalar_is_offered_nothing() {
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        QUESTION_PATH,
        &QUESTION.replace(
            "  ref: <|source-ref|>people",
            "  ref: |-\n    <|source-ref|>people",
        ),
    ));
    let index = project.index();

    assert_eq!(
        labels_at(&index, &project, QUESTION_PATH, "source-ref"),
        Vec::<String>::new()
    );
}

/// A document the loader could not read still lends its name to the documents that spell it, and
/// that is deliberate rather than an oversight of this surface.
///
/// `define_by_its_place` gives a question past its byte ceiling the name its path already makes,
/// because leaving it undefined would report an access policy that admits it, and that policy has
/// nothing wrong with it. The list follows the same definitions navigation does, so the name is
/// offered too. It is worth pinning: the project is one `evidence check` refuses whatever the
/// author picks here, so offering the name misleads nobody, and the alternative is a second error
/// drawn on a correct document.
#[test]
fn a_question_past_its_ceiling_still_lends_its_name_to_the_policy_that_admits_it() {
    let oversized = format!(
        "{}\n# {}\n",
        without_cursors(QUESTION),
        "p".repeat(64 * 1024)
    );
    let policy = "version: 1\nid: adult-checks\nquestions: [<|policy-question|>adult-status]\n";
    let project = EvidenceProject::new(&replacing(
        &replacing(&adult_status_project(), QUESTION_PATH, &oversized),
        "access/policies/adult-checks.yaml",
        policy,
    ));
    let index = project.index();

    assert!(
        reported_codes(&index)
            .iter()
            .any(|code| code.starts_with("evidence/")),
        "the oversized question is reported on itself: {:?}",
        reported_codes(&index)
    );
    assert_eq!(
        labels_at(
            &index,
            &project,
            "access/policies/adult-checks.yaml",
            "policy-question"
        ),
        vec!["adult-status".to_owned()],
        "the policy is offered the question it admits, whose file the loader could not read"
    );
}

// ---------------------------------------------------------------------------------------------
// Fields narrower than their kind: a name the compiler refuses is found, and never offered.
// ---------------------------------------------------------------------------------------------

/// An operation published under a method other than `get` is found, and never offered.
///
/// `evidence/openapi.rs` publishes an identifier under all eight HTTP methods on purpose, and the
/// reason it gives is sound for the direction it is about: the compiler resolves an identifier
/// across all eight and only then refuses one whose method is not `get`, so an editor looking only
/// at `get` would call a published name unpublished. Resolution and offering are not the same
/// question, though, and this surface must not ask them of one set. `unique_operation`
/// (`crates/registry-evidencectl/src/authoring.rs:1569-1571`) refuses a resolved operation whose
/// method is not `get` with "the local tutorial source supports only one resolved GET operationId",
/// so `notePerson` below is a name that refuses the project the moment an author takes it, and a
/// name the list therefore never puts in front of them.
///
/// Nothing else would speak if it did. The operation is written down to a shape every other rung
/// accepts, so the first assertion below takes the name by hand and finds the editor silent over
/// the result: an offer would be the only thing the author ever read about that field, and the next
/// thing they heard would be `evidence check`.
#[test]
fn an_operation_published_under_another_method_is_never_offered_to_a_question() {
    // The same subject parameter and the same response as the operation the question already
    // names, so the three rungs after resolution have nothing to say about a question that takes
    // this one. Only the method differs, and the method is what the compiler refuses.
    const NOTE_PERSON: &str = concat!(
        "  /people/{person_id}/notes:\n",
        "    post:\n",
        "      operationId: notePerson\n",
        "      parameters:\n",
        "        - name: person_id\n",
        "          in: path\n",
        "          required: true\n",
        "          schema: {type: string}\n",
        "      responses:\n",
        "        '200':\n",
        "          description: The records held for one person\n",
        "          content:\n",
        "            application/json:\n",
        "              schema:\n",
        "                type: object\n",
        "                properties:\n",
        "                  records:\n",
        "                    type: array\n",
        "                    items:\n",
        "                      type: object\n",
        "                      properties:\n",
        "                        date_of_birth: {type: string, format: date}\n",
    );
    let described = format!("{OPERATION_OPENAPI}{NOTE_PERSON}");
    let taken = EvidenceProject::new(&replacing(
        &replacing(&operation_question_project(), OPENAPI_PATH, &described),
        QUESTION_PATH,
        &OPERATION_QUESTION.replace("<|operation|>readPerson", "<|operation|>notePerson"),
    ));
    assert_eq!(
        reported_codes(&taken.index()),
        Vec::<&str>::new(),
        "a question that took the offered name is reported clean, while unique_operation refuses \
         the project for the method it was published under"
    );

    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        OPENAPI_PATH,
        &described,
    ));
    let index = project.index();
    assert_eq!(
        reported_codes(&index),
        Vec::<&str>::new(),
        "the project the author is looking at is reported clean, so the list is all they have"
    );
    assert_eq!(
        labels_at(&index, &project, QUESTION_PATH, "operation"),
        vec!["readPerson".to_owned()],
        "source.operation offers only the identifiers published under get, because unique_operation \
         refuses a question that names any other"
    );
}

/// A derivation file another question already claims is found, and never offered.
///
/// `registry-evidencectl` requires each question to name its own: `derivation_paths.insert`
/// (`crates/registry-evidencectl/src/authoring.rs:475-477`) refuses a project where two questions
/// point at one file, with "each question must name its own derivation file". `evidence/index.rs`
/// says as much in its own module documentation and draws no error of its own, which is right: two
/// questions sharing a file is a project-wide fact, and neither question is the one that is wrong.
/// Not drawing an error over a mistake already made is a different act from offering the author the
/// keystroke that makes it, though, and this list is the only place
/// `derivations/residence-region.rhai` would ever be put in front of the author of
/// `questions/adult-status.yaml`.
///
/// The quiet is what would make it a trap rather than a bad menu. The first assertion below writes
/// the project by hand and finds nothing reported over it, so an offer would put the author
/// somewhere the editor never speaks again.
#[test]
fn a_derivation_file_another_question_claims_is_never_offered() {
    let second = QUESTION
        .replace("<|id|>adult-status", "residence-region")
        .replace("<|concept|>is_adult", "in_region")
        .replace("<|allow|>is_adult", "in_region")
        .replace(
            "<|derivation|>derivations/adult-status.rhai",
            "derivations/residence-region.rhai",
        )
        .replace("<|source-ref|>", "")
        .replace("<|subject-profile|>", "")
        .replace(
            "<|fixtures|>fixtures/adult-status.yaml",
            "fixtures/residence-region.yaml",
        );
    let mut files = adult_status_project();
    files.push(file("questions/residence-region.yaml", &second));
    files.push(file("derivations/residence-region.rhai", DERIVATION));
    files.push(file("fixtures/residence-region.yaml", support::FIXTURE));

    let taken = EvidenceProject::new(&replacing(
        &files,
        QUESTION_PATH,
        &QUESTION.replace(
            "<|derivation|>derivations/adult-status.rhai",
            "<|derivation|>derivations/residence-region.rhai",
        ),
    ));
    assert_eq!(
        reported_codes(&taken.index()),
        Vec::<&str>::new(),
        "a question naming another question's derivation is reported clean here, while the compiler \
         refuses the project for two questions naming one file"
    );

    let project = EvidenceProject::new(&files);
    let index = project.index();

    assert!(
        index
            .symbols()
            .iter()
            .any(|symbol| symbol.name == "derivations/residence-region.rhai"),
        "the second question names a derivation file of its own, or this asserts nothing"
    );
    assert_eq!(
        labels_at(&index, &project, QUESTION_PATH, "derivation"),
        vec!["derivations/adult-status.rhai".to_owned()],
        "a question is offered its own derivation file and no file another question claims, because \
         the compiler refuses a project where two questions name one file"
    );
}

/// A source's own artifact is found at an answer schema, and never offered there.
///
/// The two pointers share one kind. `refer_to_file` records a question's `answers[].schema` as a
/// schema file, and `refer_to_source_artifact` records a source's `responseSchema` as one too, both
/// under a global key, which is correct for navigation: they may point at the same file, and
/// `Find references` on it should collect both. The two fields do not take the same set of paths,
/// though. A source artifact may live under `adapters/` with any extension, which
/// `evidence/index.rs` documents and depends on; an answer schema must be exactly
/// `schemas/<name>.yaml`, which `validate_answer_schema_path` enforces and which this test asks it
/// to confirm rather than restating. So the kind holds paths this field refuses, and the offer is
/// the part of the kind the form's own rule accepts.
///
/// This one would be a bad menu rather than a trap, and the assertion that says so comes first. The
/// form runs inside this server, so an author who writes the refused path is told on the next
/// keystroke, at the field, in the compiler's own sentence. What an offer would cost is a keystroke
/// and some trust in the list.
#[test]
fn a_source_artifact_is_never_offered_at_an_answer_schema() {
    let artifact = "adapters/people-response.yaml";
    assert!(
        !validate_answer_schema_path(artifact).is_empty(),
        "the form refuses this path at an answer schema, or this test asserts nothing"
    );
    assert!(
        validate_answer_schema_path("schemas/adult-status.yaml").is_empty(),
        "and accepts the one the question really names"
    );

    const BOOLEAN_ANSWER: &str = concat!(
        "  - concept: <|concept|>is_adult\n",
        "    id: urn:example:concepts:is-adult\n",
        "    type: boolean\n",
    );
    const STRUCTURED_ANSWER: &str = concat!(
        "  - concept: <|concept|>is_adult\n",
        "    id: urn:example:concepts:is-adult\n",
        "    type: reviewed-structured-value\n",
        "    schema: <|answer-schema|>schemas/adult-status.yaml\n",
        "    maximumSerializedBytes: 4096\n",
    );
    let structured = QUESTION.replace(BOOLEAN_ANSWER, STRUCTURED_ANSWER);
    assert_ne!(
        structured, QUESTION,
        "the shared question writes the boolean answer this replaces with a structured one"
    );
    let mut files = replacing(
        &replacing(&adult_status_project(), QUESTION_PATH, &structured),
        SOURCE_PATH,
        &SOURCE.replace(
            "<|response-schema|>schemas/people-response.schema.yaml",
            "<|response-schema|>adapters/people-response.yaml",
        ),
    );
    files.push(file("schemas/adult-status.yaml", SCHEMA));
    files.push(file(artifact, SCHEMA));

    let taken = EvidenceProject::new(&replacing(
        &files,
        QUESTION_PATH,
        &structured.replace(
            "<|answer-schema|>schemas/adult-status.yaml",
            &format!("<|answer-schema|>{artifact}"),
        ),
    ));
    assert_eq!(
        reported_codes(&taken.index()),
        vec!["evidence/answer-schema-path"],
        "a question that writes the refused path is told so at the field, which is what would keep \
         an offer a bad menu rather than a silent trap"
    );

    let project = EvidenceProject::new(&files);
    let index = project.index();

    assert!(
        !labels_at(&index, &project, QUESTION_PATH, "answer-schema").is_empty(),
        "the answer schema field offers the project's schema files"
    );
    assert!(
        !labels_at(&index, &project, QUESTION_PATH, "answer-schema").contains(&artifact.to_owned()),
        "a source artifact under adapters/ is not offered at an answer schema, because \
         validate_answer_schema_path refuses it there: {:?}",
        labels_at(&index, &project, QUESTION_PATH, "answer-schema")
    );
}

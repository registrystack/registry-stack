// SPDX-License-Identifier: Apache-2.0
//! The authoring library's findings, placed in the document that holds them.
//!
//! The editor does not decide what a question must look like. It deserializes the document with the
//! same reader the compiler uses, runs `registry_evidence_authoring::validate::validate_question`,
//! and puts each finding where the field it names is written. Every test below asserts the same
//! sentence twice: once from the library, called directly, and once from the diagnostic the server
//! would publish, so a diagnostic can never drift away from the refusal behind it.

mod support;

use registry_evidence_authoring::{model::Question, validate::validate_question};
use registry_language_server::IndexedDiagnostic;
use support::{
    adult_status_project, replacing, EvidenceProject, ACCESS_POLICY_PATH, QUESTION, QUESTION_PATH,
};
use tower_lsp_server::ls_types::DiagnosticSeverity;

/// What the authoring library says about one question document, as `(code, message)` pairs.
fn authoring_findings(text: &str) -> Vec<(&'static str, String)> {
    let question = serde_norway::from_str::<Question>(text).expect("the question deserializes");
    validate_question(&question)
        .into_iter()
        .map(|finding| (finding.code, finding.message))
        .collect()
}

/// The project built from one question text, and the diagnostics reported for that question.
fn question_project(text: &str) -> (EvidenceProject, Vec<IndexedDiagnostic>) {
    let project = EvidenceProject::new(&replacing(&adult_status_project(), QUESTION_PATH, text));
    let path = project.path(QUESTION_PATH);
    let reported = project
        .index()
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.path == path)
        .cloned()
        .collect();
    (project, reported)
}

/// The text a project file holds once its cursor markers are stripped, which is what a reader of
/// that file, and the deserializer, actually see.
fn without_cursors(text: &str) -> String {
    let mut stripped = text.to_owned();
    while let Some(start) = stripped.find("<|") {
        let end = stripped[start..]
            .find("|>")
            .expect("a cursor marker closes with |>");
        stripped.replace_range(start..start + end + "|>".len(), "");
    }
    stripped
}

#[test]
fn a_finding_is_reported_at_the_field_it_names() {
    let text = QUESTION.replace("<|concept|>is_adult", "<|concept|>IsAdult");

    let (project, reported) = question_project(&text);

    assert_eq!(
        authoring_findings(&without_cursors(&text)),
        vec![(
            "answer-concept-identifier",
            "answer concept must be a lowercase local identifier".to_owned()
        )],
        "the authoring library refuses this question"
    );
    assert_eq!(reported.len(), 1, "{reported:?}");
    assert_eq!(
        reported[0].code.as_deref(),
        Some("evidence/answer-concept-identifier")
    );
    assert_eq!(
        reported[0].message,
        "answer concept must be a lowercase local identifier"
    );
    assert_eq!(
        reported[0].range.start,
        project.cursor(QUESTION_PATH, "concept"),
        "the diagnostic underlines the concept the finding named"
    );
}

/// A finding often names a field the author left out, which is the whole point of the finding. The
/// bridge walks as far as the document goes and stops on the deepest field it does hold, so the
/// diagnostic lands on the answer that is missing its schema rather than at the top of the file.
#[test]
fn a_finding_naming_a_field_the_document_omits_lands_on_the_field_above_it() {
    let text = QUESTION
        .replace(
            "  - concept: <|concept|>is_adult\n",
            "  - <|answer|>concept: is_adult\n",
        )
        .replace(
            "    type: boolean\n",
            "    type: reviewed-structured-value\n    maximumSerializedBytes: 4096\n",
        );

    let (project, reported) = question_project(&text);

    assert_eq!(
        authoring_findings(&without_cursors(&text)),
        vec![(
            "structured-answer-schema",
            "a reviewed structured answer requires schema".to_owned()
        )],
        "the authoring library refuses this question"
    );
    assert_eq!(reported.len(), 1, "{reported:?}");
    assert_eq!(
        reported[0].code.as_deref(),
        Some("evidence/structured-answer-schema")
    );
    assert_eq!(
        reported[0].range.start,
        project.cursor(QUESTION_PATH, "answer"),
        "the diagnostic underlines the answer the schema is missing from"
    );
}

/// A document the deserializer cannot read is one problem, reported once, and the question is still
/// the question its file names: the access policy that admits it keeps navigating and stays quiet.
#[test]
fn a_question_the_deserializer_cannot_read_is_reported_once_and_still_names_itself() {
    let text = QUESTION.replace("    type: boolean\n", "    type: mystery\n");

    let project = EvidenceProject::new(&replacing(&adult_status_project(), QUESTION_PATH, &text));
    let index = project.index();

    assert!(
        serde_norway::from_str::<Question>(&without_cursors(&text)).is_err(),
        "the authoring library's own reader refuses this question"
    );
    let reported = index.diagnostics();
    let question = reported
        .iter()
        .filter(|diagnostic| diagnostic.path == project.path(QUESTION_PATH))
        .collect::<Vec<_>>();
    assert_eq!(question.len(), 1, "{reported:?}");
    assert_eq!(question[0].code.as_deref(), Some("evidence/question-shape"));
    assert!(
        question[0]
            .message
            .starts_with("This is not the shape of a question:"),
        "{}",
        question[0].message
    );
    assert!(
        reported
            .iter()
            .all(|diagnostic| diagnostic.path != project.path(ACCESS_POLICY_PATH)),
        "the policy still finds the question it admits: {reported:?}"
    );
}

/// The policy the whole channel is held to: every Evidence diagnostic is an error, and every one
/// names the rule behind it so a client can silence one rule instead of the server. Nothing
/// advisory, nothing informational, nothing an author is invited to disagree with.
#[test]
fn every_evidence_diagnostic_is_an_error_that_names_its_rule() {
    let broken = [
        // A name with nothing behind it.
        QUESTION.replace("<|source-ref|>people", "ledger"),
        // A shape the reader refuses.
        QUESTION.replace("    type: boolean\n", "    type: mystery\n"),
        // A field the authoring library refuses.
        QUESTION.replace("<|concept|>is_adult", "IsAdult"),
        // An identifier that disagrees with the file it is written in.
        QUESTION.replace("id: <|id|>adult-status", "id: adult-status-v2"),
        // A document that stops parsing.
        format!("{QUESTION}unterminated: [\n"),
    ];

    let mut seen = 0;
    for text in &broken {
        let (_project, reported) = question_project(text);
        assert!(!reported.is_empty(), "{text}");
        for diagnostic in &reported {
            assert_eq!(
                diagnostic.severity,
                DiagnosticSeverity::ERROR,
                "{diagnostic:?}"
            );
            let code = diagnostic
                .code
                .as_deref()
                .unwrap_or_else(|| panic!("{diagnostic:?} names its rule"));
            assert!(code.starts_with("evidence/"), "{code}");
            seen += 1;
        }
    }
    assert!(seen >= broken.len(), "each broken document reported");
}

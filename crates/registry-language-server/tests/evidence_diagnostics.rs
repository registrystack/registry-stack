// SPDX-License-Identifier: Apache-2.0
//! The authoring library's findings, placed in the document that holds them.
//!
//! The editor does not decide what a question must look like. It deserializes the document with the
//! same reader the compiler uses, runs `registry_evidence_authoring::validate::validate_question`,
//! and puts each finding where the field it names is written.
//!
//! A test of a finding asserts the same sentence twice: once from the library, called directly, and
//! once from the diagnostic the server would publish, so a diagnostic can never drift away from the
//! refusal behind it. A document the reader cannot deserialize is paired the same way, against that
//! reader.
//!
//! The diagnostics the index draws from one document's name for another are not paired here. The
//! `evidence/unknown-*` codes and the two file-name codes are refused by `registry-evidencectl`,
//! which depends on this crate: a dependency the other way is a cycle, and that crate builds a
//! binary rather than a library, so there is nothing here to call. `tests/evidence_index.rs` holds
//! each of those diagnostics to its own exact sentence and names the refusal it stands for in prose.
//! Nothing executes that half of the pair, in either crate, so those rules are held to each other by
//! review and the pairing belongs in `registry-evidencectl`'s own suite.

mod support;

use registry_evidence_authoring::{
    model::{AccessPolicy, Question},
    validate::{validate_access_policy, validate_question},
};
use registry_language_server::IndexedDiagnostic;
use support::{
    adult_status_project, replacing, EvidenceProject, ACCESS_POLICY, ACCESS_POLICY_PATH, OPENAPI,
    OPENAPI_PATH, QUESTION, QUESTION_PATH,
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
fn an_invalid_marker_stops_dependent_diagnostics() {
    let files = replacing(
        &replacing(
            &adult_status_project(),
            "evidence-project.yaml",
            "version: 2\nproject: evidence-authoring\n",
        ),
        QUESTION_PATH,
        &QUESTION.replace("<|source-ref|>people", "missing"),
    );
    let project = EvidenceProject::new(&files);
    let reported = project.index().diagnostics().to_vec();

    assert_eq!(reported.len(), 1, "{reported:?}");
    assert_eq!(reported[0].path, project.path("evidence-project.yaml"));
    assert_eq!(
        reported[0].code.as_deref(),
        Some("evidence/project-marker-version")
    );
    assert_eq!(
        reported[0].message,
        "evidence-project.yaml version must be 1"
    );
}

#[test]
fn an_invalid_openapi_prerequisite_stops_dependent_diagnostics() {
    let files = replacing(
        &replacing(
            &adult_status_project(),
            OPENAPI_PATH,
            &OPENAPI.replace("openapi: 3.1.0", "openapi: '2.0.0'"),
        ),
        QUESTION_PATH,
        &QUESTION.replace("<|source-ref|>people", "missing"),
    );
    let project = EvidenceProject::new(&files);
    let reported = project.index().diagnostics().to_vec();

    assert_eq!(reported.len(), 1, "{reported:?}");
    assert_eq!(reported[0].path, project.path(OPENAPI_PATH));
    assert_eq!(
        reported[0].code.as_deref(),
        Some("evidence/openapi-prerequisite")
    );
    assert!(
        reported[0]
            .message
            .contains("only OpenAPI 3.0.x and 3.1.x are supported"),
        "{}",
        reported[0].message
    );
}

#[test]
fn an_invalid_access_policy_stops_filename_and_question_resolution() {
    let policy = ACCESS_POLICY
        .replace("version: 1", "version: 2")
        .replace("adult-checks", "wrong-name")
        .replace("adult-status", "missing");
    let parsed = serde_norway::from_str::<AccessPolicy>(&without_cursors(&policy))
        .expect("the policy has the closed shape");
    assert_eq!(
        validate_access_policy(&parsed)[0].code,
        "access-policy-version"
    );

    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        ACCESS_POLICY_PATH,
        &policy,
    ));
    let reported = project.index().diagnostics().to_vec();

    assert_eq!(reported.len(), 1, "{reported:?}");
    assert_eq!(reported[0].path, project.path(ACCESS_POLICY_PATH));
    assert_eq!(
        reported[0].code.as_deref(),
        Some("evidence/access-policy-version")
    );
    assert_eq!(reported[0].message, "access policy version must be 1");
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

#[test]
fn a_referenced_subject_source_marker_is_reported_by_the_shared_check() {
    let text = QUESTION.replace(
        "  profile: <|subject-profile|>person-reference-v1\n",
        "  profile: <|subject-profile|>person-reference-v1\n  source: <|source-marker|>true\n",
    );

    let (project, reported) = question_project(&text);

    assert_eq!(
        authoring_findings(&without_cursors(&text)),
        vec![(
            "subject-source-context",
            "subject.source is available only to an inline OpenAPI operation".to_owned()
        )],
        "the authoring library refuses this question"
    );
    assert_eq!(reported.len(), 1, "{reported:?}");
    assert_eq!(
        reported[0].code.as_deref(),
        Some("evidence/subject-source-context")
    );
    assert_eq!(
        reported[0].message,
        "subject.source is available only to an inline OpenAPI operation"
    );
    assert_eq!(
        reported[0].range.start,
        project.cursor(QUESTION_PATH, "source-marker"),
        "the diagnostic underlines the source marker the finding named"
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

/// One doubled concept is one mistake. The authoring library owns the sentence that names it and
/// says it once, at the answer that repeats; the index sees the same concept defined twice and stays
/// quiet, because a duplicate reported there would be a second and a third error on one line.
#[test]
fn a_doubled_concept_is_reported_once_by_the_check_that_owns_it() {
    let text = QUESTION.replace(
        "  - concept: <|concept|>is_adult\n    id: urn:example:concepts:is-adult\n    type: boolean\n",
        "  - concept: is_adult\n    id: urn:example:concepts:is-adult\n    type: boolean\n  \
         - concept: <|concept|>is_adult\n    id: urn:example:concepts:is-adult\n    type: boolean\n",
    );

    let (project, reported) = question_project(&text);

    assert_eq!(
        authoring_findings(&without_cursors(&text)),
        vec![(
            "answer-concept-unique",
            "answer concepts must be unique".to_owned()
        )],
        "the authoring library refuses this question"
    );
    assert_eq!(
        reported
            .iter()
            .map(|diagnostic| (diagnostic.code.as_deref(), diagnostic.message.as_str()))
            .collect::<Vec<_>>(),
        vec![(
            Some("evidence/answer-concept-unique"),
            "answer concepts must be unique"
        )],
        "{reported:?}"
    );
    assert_eq!(
        reported[0].range.start,
        project.cursor(QUESTION_PATH, "concept"),
        "the diagnostic underlines the concept that repeats"
    );
}

/// A finding quotes the name the author wrote, and the instruction it gives comes after that name.
/// The sentence reaches the editor whole, so the author reads the part they have to act on rather
/// than the part they already have in front of them.
#[test]
fn a_finding_that_quotes_a_long_name_reaches_the_editor_whole() {
    let fact = "date_of_birth_of_the_person_this_question_is_asked_about_in_full";
    let text = QUESTION.replace(
        "source:\n  ref: <|source-ref|>people\n",
        &format!(
            "source:\n  operation: listPeople\n  facts:\n    - name: {fact}\n      \
             path: /records/*/date_of_birth\n      combine: <|combine|>exactly-one\n"
        ),
    );
    let sentence = format!(
        "source fact `{fact}` visits a collection and must explicitly use `combine: collect`"
    );
    assert!(sentence.chars().count() > 120, "{sentence}");

    let (project, reported) = question_project(&text);

    assert_eq!(
        authoring_findings(&without_cursors(&text)),
        vec![("fact-combination", sentence.clone())],
        "the authoring library refuses this question"
    );
    // Which edges a compact-form question draws is `evidence_index.rs`'s subject. What is asserted
    // here is the sentence the finding carries, whole.
    let paired = reported
        .iter()
        .filter(|diagnostic| diagnostic.code.as_deref() == Some("evidence/fact-combination"))
        .collect::<Vec<_>>();
    assert_eq!(paired.len(), 1, "{reported:?}");
    assert_eq!(paired[0].message, sentence);
    assert_eq!(
        paired[0].range.start,
        project.cursor(QUESTION_PATH, "combine"),
        "the diagnostic underlines the combination the finding named"
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

/// A question the deserializer cannot read says nothing about the names it spells.
///
/// The compiler reaches a question's cross-file checks through `compile_question_plan`, which runs
/// on a question the form has already accepted, so a source that is not there is not a second
/// sentence: it is a name inside a document whose shape is what the author has to fix first.
/// Answering one mistake with two sentences puts the author's attention on a field that may well be
/// correct once the shape is.
#[test]
fn a_question_the_deserializer_cannot_read_says_nothing_about_the_names_it_spells() {
    let text = QUESTION
        .replace("    type: boolean\n", "    type: mystery\n")
        .replace("<|source-ref|>people", "ledger");

    let (_project, reported) = question_project(&text);

    assert_eq!(
        reported
            .iter()
            .map(|diagnostic| diagnostic.code.as_deref().unwrap_or("<no code>"))
            .collect::<Vec<_>>(),
        vec!["evidence/question-shape"],
        "{reported:?}"
    );
}

/// The document that admits such a question still finds it.
///
/// What a question file declares is the name its path gives it, and that is not gated on anything
/// written inside it. Silencing the names a malformed question spells must not silence the name it
/// is: an access policy admitting a question whose document is right there has nothing wrong with
/// it, and telling it the question is missing would be the diagnostic this whole surface refuses to
/// draw.
#[test]
fn an_access_policy_admitting_a_question_the_deserializer_cannot_read_is_told_nothing() {
    let text = QUESTION
        .replace("    type: boolean\n", "    type: mystery\n")
        .replace("<|source-ref|>people", "ledger");
    let project = EvidenceProject::new(&replacing(&adult_status_project(), QUESTION_PATH, &text));

    let index = project.index();
    let reported = index.diagnostics();

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
///
/// Each document names the rules it is expected to break, so a mistake that starts reporting a
/// different rule, or one rule twice, fails here rather than passing a count.
#[test]
fn every_evidence_diagnostic_is_an_error_that_names_its_rule() {
    let broken = [
        // A name with nothing behind it.
        (
            QUESTION.replace("<|source-ref|>people", "ledger"),
            vec!["evidence/unknown-source"],
        ),
        // A shape the reader refuses.
        (
            QUESTION.replace("    type: boolean\n", "    type: mystery\n"),
            vec!["evidence/question-shape"],
        ),
        // A field the authoring library refuses.
        (
            QUESTION.replace("<|concept|>is_adult", "IsAdult"),
            vec!["evidence/answer-concept-identifier"],
        ),
        // An identifier that disagrees with the file it is written in.
        (
            QUESTION.replace("id: <|id|>adult-status", "id: adult-status-v2"),
            vec!["evidence/question-file-name"],
        ),
        // A document that stops parsing.
        (
            format!("{QUESTION}unterminated: [\n"),
            vec!["evidence/syntax"],
        ),
    ];

    for (text, expected) in &broken {
        let (_project, reported) = question_project(text);
        for diagnostic in &reported {
            assert_eq!(
                diagnostic.severity,
                DiagnosticSeverity::ERROR,
                "{diagnostic:?}"
            );
        }
        assert_eq!(
            reported
                .iter()
                .map(|diagnostic| diagnostic
                    .code
                    .as_deref()
                    .unwrap_or_else(|| panic!("{diagnostic:?} names its rule")))
                .collect::<Vec<_>>(),
            *expected,
            "{text}"
        );
    }
}

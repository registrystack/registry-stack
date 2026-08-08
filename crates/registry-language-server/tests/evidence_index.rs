// SPDX-License-Identifier: Apache-2.0
//! One test per edge an Evidence authoring project draws between two documents.
//!
//! Each edge is checked three ways, because an editor that gets any one of them wrong is worse than
//! one that offers nothing: the reference goes to the definition, the definition lists the
//! reference, and a name with nothing behind it is reported.
//!
//! Every reported edge is also paired with the sentence `registry-evidencectl` refuses the same
//! project with, cited beside the test. The editor is allowed to be earlier than the compiler and is
//! not allowed to be stricter, so a rule with no refusal behind it does not ship as a diagnostic.

mod support;

use registry_evidence_authoring::testing::ProjectFile;
use registry_language_server::{EvidenceKind, SymbolKind};
use support::{
    adult_status_project, file, replacing, without, EvidenceProject, ACCESS_POLICY,
    ACCESS_POLICY_PATH, DERIVATION_PATH, FIXTURE_PATH, QUESTION, QUESTION_PATH, SCHEMA,
    SELECTOR_PATH, SOURCE, SOURCE_PATH,
};

/// The worked project the compiler accepts is a project the editor reports nothing about. This is
/// the guard the rest of the file leans on: every test below breaks exactly one thing, so a
/// diagnostic that appears there is the one the test broke.
#[test]
fn the_worked_project_reports_nothing() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();

    assert!(
        index.diagnostics().is_empty(),
        "the referenced form the compiler accepts reports nothing: {:?}",
        index.diagnostics()
    );
}

/// Edge 1: a question document defines the question its `id` names, and the name has to be the file
/// stem. Paired with `crates/registry-evidencectl/src/authoring.rs`, which refuses a question whose
/// `id` does not match its file name.
#[test]
fn a_question_defines_the_identifier_it_writes() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();
    let identifier = project.cursor(QUESTION_PATH, "id");

    let symbol = index
        .document_symbols(&project.path(QUESTION_PATH))
        .into_iter()
        .find(|symbol| symbol.kind == SymbolKind::Evidence(EvidenceKind::Question))
        .expect("the question document defines a question");
    assert_eq!(symbol.name, "adult-status");
    assert_eq!(symbol.location.range.start, identifier);

    // The access policy names the question, so the definition knows one use of itself.
    let uses = index.references_at(&project.path(QUESTION_PATH), identifier, false);
    assert_eq!(
        uses.iter()
            .map(|use_| use_.path.clone())
            .collect::<Vec<_>>(),
        vec![project.path(ACCESS_POLICY_PATH)]
    );
}

#[test]
fn a_question_identifier_that_is_not_the_file_name_is_reported() {
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        QUESTION_PATH,
        &QUESTION.replace("id: <|id|>adult-status", "id: <|id|>adult_status"),
    ));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(diagnostic.range.start, project.cursor(QUESTION_PATH, "id"));
    assert_eq!(
        diagnostic.message,
        "Question 'adult_status' does not match its file name; \
         rename the identifier or the file so both read 'adult-status'"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/question-file-name")
    );
}

/// Edge 2: `derivation:` names the Rhai file that computes the answer. Paired with
/// `crates/registry-evidencectl/src/authoring.rs`, which reads the derivation at
/// `derivations/<name>.rhai` and fails the build when it is not there.
#[test]
fn a_question_refers_to_its_derivation_file() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();
    let reference = project.cursor(QUESTION_PATH, "derivation");

    assert_eq!(
        definition_paths(&index, &project, QUESTION_PATH, "derivation"),
        vec![project.path(DERIVATION_PATH)]
    );
    assert_eq!(
        index
            .references_at(&project.path(QUESTION_PATH), reference, false)
            .into_iter()
            .map(|location| location.path)
            .collect::<Vec<_>>(),
        vec![project.path(QUESTION_PATH)]
    );
}

#[test]
fn a_derivation_file_that_is_not_there_is_reported() {
    let project = EvidenceProject::new(&without(&adult_status_project(), DERIVATION_PATH));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(
        diagnostic.range.start,
        project.cursor(QUESTION_PATH, "derivation")
    );
    assert_eq!(
        diagnostic.message,
        "Unknown derivation file reference 'derivations/adult-status.rhai'"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/unknown-derivation-file")
    );
}

/// Edge 3: `source.ref` names a source document by its file stem. Paired with
/// `crates/registry-evidencectl/src/authoring.rs`: "question source ref `x` has no sources/x.yaml".
#[test]
fn a_question_refers_to_the_source_it_reads() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();

    assert_eq!(
        definition_paths(&index, &project, QUESTION_PATH, "source-ref"),
        vec![project.path(SOURCE_PATH)]
    );

    // From the source, the question that reads it is one of its uses.
    let source = project.path(SOURCE_PATH);
    let definition = index
        .document_symbols(&source)
        .into_iter()
        .find(|symbol| symbol.kind == SymbolKind::Evidence(EvidenceKind::Source))
        .expect("the source document defines a source")
        .location
        .range
        .start;
    assert!(index
        .references_at(&source, definition, false)
        .into_iter()
        .any(|location| location.path == project.path(QUESTION_PATH)));
}

#[test]
fn a_source_that_is_not_there_is_reported() {
    let project = EvidenceProject::new(&without(&adult_status_project(), SOURCE_PATH));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(
        diagnostic.range.start,
        project.cursor(QUESTION_PATH, "source-ref")
    );
    assert_eq!(diagnostic.message, "Unknown source reference 'people'");
    assert_eq!(diagnostic.code.as_deref(), Some("evidence/unknown-source"));
}

/// Edge 4: a structured answer's `schema` names a file under `schemas/`. Paired with
/// `crates/registry-evidencectl/src/authoring.rs`, which resolves the answer schema by file stem
/// against the schemas it read.
#[test]
fn an_answer_refers_to_the_schema_it_is_checked_against() {
    let project = EvidenceProject::new(&structured_answer_project());
    let index = project.index();

    assert_eq!(
        definition_paths(&index, &project, QUESTION_PATH, "answer-schema"),
        vec![project.path("schemas/person-record.yaml")]
    );
    assert_eq!(
        index
            .references_at(
                &project.path(QUESTION_PATH),
                project.cursor(QUESTION_PATH, "answer-schema"),
                false
            )
            .into_iter()
            .map(|location| location.path)
            .collect::<Vec<_>>(),
        vec![project.path(QUESTION_PATH)]
    );
}

#[test]
fn an_answer_schema_that_is_not_there_is_reported() {
    let project = EvidenceProject::new(&without(
        &structured_answer_project(),
        "schemas/person-record.yaml",
    ));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(
        diagnostic.range.start,
        project.cursor(QUESTION_PATH, "answer-schema")
    );
    assert_eq!(
        diagnostic.message,
        "Unknown schema file reference 'schemas/person-record.yaml'"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/unknown-schema-file")
    );
}

/// Edge 5: `governance.fixtures` names a file under `fixtures/`. Paired with
/// `crates/registry-evidencectl/src/authoring.rs`, which requires the fixture path to be
/// `fixtures/<name>.yaml` and reads it.
#[test]
fn a_question_refers_to_the_fixtures_that_exercise_it() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();

    assert_eq!(
        definition_paths(&index, &project, QUESTION_PATH, "fixtures"),
        vec![project.path(FIXTURE_PATH)]
    );
    assert_eq!(
        index
            .references_at(
                &project.path(QUESTION_PATH),
                project.cursor(QUESTION_PATH, "fixtures"),
                false
            )
            .into_iter()
            .map(|location| location.path)
            .collect::<Vec<_>>(),
        vec![project.path(QUESTION_PATH)]
    );
}

#[test]
fn a_fixture_file_that_is_not_there_is_reported() {
    let project = EvidenceProject::new(&without(&adult_status_project(), FIXTURE_PATH));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(
        diagnostic.range.start,
        project.cursor(QUESTION_PATH, "fixtures")
    );
    assert_eq!(
        diagnostic.message,
        "Unknown fixture file reference 'fixtures/adult-status.yaml'"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/unknown-fixture-file")
    );
}

/// Edge 6: a subject's `profile` names a selector profile by its file stem. Paired with
/// `crates/registry-evidencectl/src/authoring.rs`: "referenced source question uses missing
/// selectors/<profile>.yaml".
#[test]
fn a_subject_refers_to_the_selector_profile_that_picks_it() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();

    assert_eq!(
        definition_paths(&index, &project, QUESTION_PATH, "subject-profile"),
        vec![project.path(SELECTOR_PATH)]
    );

    // The question and the source both name the profile, so its definition knows two uses.
    let selector = project.path(SELECTOR_PATH);
    let definition = index
        .document_symbols(&selector)
        .into_iter()
        .find(|symbol| symbol.kind == SymbolKind::Evidence(EvidenceKind::SelectorProfile))
        .expect("the selector document defines a profile")
        .location
        .range
        .start;
    assert_eq!(
        index
            .references_at(&selector, definition, false)
            .into_iter()
            .map(|location| location.path)
            .collect::<Vec<_>>(),
        vec![project.path(QUESTION_PATH), project.path(SOURCE_PATH)]
    );
}

#[test]
fn a_selector_profile_that_is_not_there_is_reported() {
    let project = EvidenceProject::new(&without(&adult_status_project(), SELECTOR_PATH));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(
        diagnostic.range.start,
        project.cursor(QUESTION_PATH, "subject-profile")
    );
    assert_eq!(
        diagnostic.message,
        "Unknown selector profile reference 'person-reference-v1'"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/unknown-selector-profile")
    );
}

/// Edge 7: an answer defines the concept it answers, scoped to its own question, and
/// `disclosure.allow` names those concepts. Paired with `registry_evidence_authoring::validate`'s
/// `disclosure-allow` finding, which refuses an allowed name that no answer produces.
#[test]
fn an_answer_defines_the_concept_disclosure_allows() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();
    let concept = project.cursor(QUESTION_PATH, "concept");

    assert_eq!(
        index
            .definitions_at(
                &project.path(QUESTION_PATH),
                project.cursor(QUESTION_PATH, "allow")
            )
            .into_iter()
            .map(|location| location.range.start)
            .collect::<Vec<_>>(),
        vec![concept]
    );
    assert_eq!(
        index
            .references_at(&project.path(QUESTION_PATH), concept, false)
            .into_iter()
            .map(|location| location.range.start)
            .collect::<Vec<_>>(),
        vec![project.cursor(QUESTION_PATH, "allow")]
    );
}

/// A disclosed name no answer produces is one mistake, and the authoring library already has a
/// sentence for it. The index resolves `disclosure.allow` so navigation works, and stays quiet when
/// the name resolves to nothing so the author reads one error rather than two.
#[test]
fn a_disclosed_concept_no_answer_produces_is_reported_once_by_the_authoring_library() {
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        QUESTION_PATH,
        &QUESTION.replace("allow: [<|allow|>is_adult]", "allow: [<|allow|>is_minor]"),
    ));
    let index = project.index();

    let reported = index.diagnostics();
    assert_eq!(reported.len(), 1, "{reported:?}");
    assert_eq!(
        reported[0].code.as_deref(),
        Some("evidence/disclosure-allow")
    );
    assert_eq!(
        reported[0].message,
        "disclosure.allow must contain exactly the declared answer concepts"
    );
    assert_eq!(reported[0].path, project.path(QUESTION_PATH));
}

/// Two questions may answer the same concept, so a concept name belongs to the question that
/// answers it. Neither question's disclosure may reach the other's answer.
#[test]
fn one_question_s_concept_does_not_answer_another_question_s_disclosure() {
    const MINOR_PATH: &str = "questions/minor-status.yaml";
    let mut files = adult_status_project();
    files.push(file(
        MINOR_PATH,
        &QUESTION
            .replace("id: <|id|>adult-status", "id: minor-status")
            .replace("<|concept|>is_adult", "is_minor")
            .replace(
                "derivation: <|derivation|>derivations/adult-status.rhai",
                "derivation: derivations/minor-status.rhai",
            ),
    ));
    files.push(file("derivations/minor-status.rhai", support::DERIVATION));
    let project = EvidenceProject::new(&files);
    let index = project.index();

    assert_eq!(
        index.definitions_at(
            &project.path(MINOR_PATH),
            project.cursor(MINOR_PATH, "allow")
        ),
        vec![],
        "the concept the other question answers is not this question's to disclose"
    );
    assert_eq!(
        index
            .definitions_at(
                &project.path(QUESTION_PATH),
                project.cursor(QUESTION_PATH, "allow")
            )
            .into_iter()
            .map(|location| (location.path, location.range.start))
            .collect::<Vec<_>>(),
        vec![(
            project.path(QUESTION_PATH),
            project.cursor(QUESTION_PATH, "concept")
        )],
        "each question's disclosure reaches its own answer"
    );

    let reported = index.diagnostics();
    assert_eq!(reported.len(), 1, "{reported:?}");
    assert_eq!(
        reported[0].code.as_deref(),
        Some("evidence/disclosure-allow")
    );
    assert_eq!(reported[0].path, project.path(MINOR_PATH));
}

/// Edge 8: an access policy names the questions it admits. Paired with
/// `crates/registry-evidencectl/src/authoring.rs`: "access policy names a question that does not
/// exist in this project".
#[test]
fn an_access_policy_refers_to_the_questions_it_admits() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();

    assert_eq!(
        definition_paths(&index, &project, ACCESS_POLICY_PATH, "policy-question"),
        vec![project.path(QUESTION_PATH)]
    );
    assert_eq!(
        index
            .references_at(
                &project.path(ACCESS_POLICY_PATH),
                project.cursor(ACCESS_POLICY_PATH, "policy-question"),
                false
            )
            .into_iter()
            .map(|location| location.path)
            .collect::<Vec<_>>(),
        vec![project.path(ACCESS_POLICY_PATH)]
    );
}

#[test]
fn an_admitted_question_that_is_not_there_is_reported() {
    let project = EvidenceProject::new(&without(&adult_status_project(), QUESTION_PATH));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, ACCESS_POLICY_PATH);
    assert_eq!(
        diagnostic.range.start,
        project.cursor(ACCESS_POLICY_PATH, "policy-question")
    );
    assert_eq!(
        diagnostic.message,
        "Unknown question reference 'adult-status'"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/unknown-question")
    );
}

/// An access policy is named by its file too. Paired with
/// `crates/registry-evidencectl/src/authoring.rs`, which refuses a policy whose `id` is not its file
/// stem.
#[test]
fn an_access_policy_identifier_that_is_not_the_file_name_is_reported() {
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        ACCESS_POLICY_PATH,
        &ACCESS_POLICY.replace(
            "id: <|policy-id|>adult-checks",
            "id: <|policy-id|>adult-check",
        ),
    ));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, ACCESS_POLICY_PATH);
    assert_eq!(
        diagnostic.range.start,
        project.cursor(ACCESS_POLICY_PATH, "policy-id")
    );
    assert_eq!(
        diagnostic.message,
        "Access policy 'adult-check' does not match its file name; \
         rename the identifier or the file so both read 'adult-checks'"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/access-policy-file-name")
    );
}

/// Edge 9: a source's selector inputs offer alternatives, each naming a selector profile. Paired
/// with `crates/registry-evidencectl/src/authoring.rs`, which resolves the alternative a question
/// selects against `selectors/<profile>.yaml`.
#[test]
fn a_source_selector_input_refers_to_the_profiles_it_offers() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();

    assert_eq!(
        definition_paths(&index, &project, SOURCE_PATH, "alternative-profile"),
        vec![project.path(SELECTOR_PATH)]
    );
}

#[test]
fn a_source_selector_input_offering_a_profile_that_is_not_there_is_reported() {
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        SOURCE_PATH,
        &SOURCE.replace(
            "profile: <|alternative-profile|>person-reference-v1",
            "profile: <|alternative-profile|>person-reference-v2",
        ),
    ));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, SOURCE_PATH);
    assert_eq!(
        diagnostic.range.start,
        project.cursor(SOURCE_PATH, "alternative-profile")
    );
    assert_eq!(
        diagnostic.message,
        "Unknown selector profile reference 'person-reference-v2'"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/unknown-selector-profile")
    );
}

/// Edge 10: a source names the schemas its parameters, response, and facts are checked against.
/// Paired with `crates/registry-evidencectl/src/authoring.rs`, which reads each of the source's own
/// artifact pointers and fails the build when one is missing.
#[test]
fn a_source_refers_to_the_schemas_it_is_checked_against() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();

    for (cursor, schema) in [
        ("parameters-schema", "schemas/people-parameters.schema.yaml"),
        ("response-schema", "schemas/people-response.schema.yaml"),
        ("fact-schema", "schemas/people-facts.schema.yaml"),
    ] {
        assert_eq!(
            definition_paths(&index, &project, SOURCE_PATH, cursor),
            vec![project.path(schema)],
            "{cursor}"
        );
        assert_eq!(
            index
                .references_at(
                    &project.path(SOURCE_PATH),
                    project.cursor(SOURCE_PATH, cursor),
                    false
                )
                .into_iter()
                .map(|location| location.path)
                .collect::<Vec<_>>(),
            vec![project.path(SOURCE_PATH)],
            "{cursor}"
        );
    }
}

#[test]
fn a_source_schema_that_is_not_there_is_reported() {
    let project = EvidenceProject::new(&without(
        &adult_status_project(),
        "schemas/people-facts.schema.yaml",
    ));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, SOURCE_PATH);
    assert_eq!(
        diagnostic.range.start,
        project.cursor(SOURCE_PATH, "fact-schema")
    );
    assert_eq!(
        diagnostic.message,
        "Unknown schema file reference 'schemas/people-facts.schema.yaml'"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/unknown-schema-file")
    );
}

/// A file reference is resolved by where it points, not by what happens to be readable there. A
/// path outside the authoring form's layout resolves to nothing even when a file sits at it.
#[test]
fn a_file_reference_outside_the_project_layout_is_reported() {
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        QUESTION_PATH,
        &QUESTION.replace(
            "derivation: <|derivation|>derivations/adult-status.rhai",
            "derivation: <|derivation|>../derivations/adult-status.rhai",
        ),
    ));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/unknown-derivation-file")
    );
    assert_eq!(
        diagnostic.message,
        "Unknown derivation file reference '../derivations/adult-status.rhai'"
    );
}

/// A question that stops parsing still defines what it has written, so the rest of the project
/// keeps resolving against it while the author types.
#[test]
fn a_question_that_stops_parsing_still_answers_the_access_policy() {
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        QUESTION_PATH,
        &QUESTION.replace("purpose: fixture-eligibility", "purpose: [unclosed"),
    ));
    let index = project.index();

    assert!(
        index
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.path == project.path(QUESTION_PATH)),
        "the access policy still resolves the question: {:?}",
        index.diagnostics()
    );
}

/// The same project with a structured answer, which is the only answer kind that names a schema.
fn structured_answer_project() -> Vec<ProjectFile> {
    let files = replacing(
        &adult_status_project(),
        QUESTION_PATH,
        &QUESTION
            .replace(
                "    type: boolean\n",
                "    type: reviewed-structured-value\n    \
                 schema: <|answer-schema|>schemas/person-record.yaml\n    \
                 maximumSerializedBytes: 4096\n",
            )
            .replace("<|derivation|>", ""),
    );
    replacing(&files, "schemas/person-record.yaml", SCHEMA)
}

/// The only diagnostic one document reports, with the whole project's diagnostics in the failure
/// message when there is more than one.
fn only_diagnostic_in<'index>(
    index: &'index registry_language_server::ProjectIndex,
    project: &EvidenceProject,
    relative: &str,
) -> &'index registry_language_server::IndexedDiagnostic {
    let path = project.path(relative);
    let reported = index
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.path == path)
        .collect::<Vec<_>>();
    assert_eq!(
        reported.len(),
        1,
        "{relative} reports one problem: {:?}",
        index.diagnostics()
    );
    reported[0]
}

/// Where the reference under a named cursor is defined.
fn definition_paths(
    index: &registry_language_server::ProjectIndex,
    project: &EvidenceProject,
    relative: &str,
    cursor: &str,
) -> Vec<std::path::PathBuf> {
    index
        .definitions_at(&project.path(relative), project.cursor(relative, cursor))
        .into_iter()
        .map(|location| location.path)
        .collect()
}

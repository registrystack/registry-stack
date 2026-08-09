// SPDX-License-Identifier: Apache-2.0
//! The edges a question draws into the project's own OpenAPI description.
//!
//! A question written in the compact form names an operation of `source.openapi.yaml` instead of a
//! source document, and everything else it writes is read against that operation: the subject is
//! selected by one of the operation's path parameters, each fact projects a leaf of its response,
//! and each collection bound names a collection some fact visits. `tests/evidence_index.rs` covers
//! the edges a project draws between two authored documents; these four are the ones drawn into the
//! description instead.
//!
//! Every diagnostic here is paired with the exact sentence `registry-evidencectl` refuses the same
//! project with, cited beside the test. The editor is allowed to be earlier than the compiler and
//! is not allowed to be stricter, so each test that reports something is followed by the cases the
//! compiler accepts, or cannot judge, where the editor stays quiet.
//!
//! The pairing is cited rather than compiled. `registry-evidencectl` depends on this crate, so a
//! test here cannot call the compile checks it holds without a dependency cycle, and each rule is
//! quoted by file and line instead.

mod support;

use registry_evidence_authoring::{
    layout::MAX_OPENAPI_BYTES, marker::PROJECT_MARKER_FILE, testing::ProjectFile,
};
use registry_language_server::{EvidenceKind, IndexedDiagnostic, ProjectIndex, SymbolKind};
use support::{
    adult_status_project, operation_question_project, replacing, without, EvidenceProject,
    OPENAPI_PATH, OPERATION_OPENAPI, OPERATION_QUESTION, QUESTION_PATH,
};

/// The worked compact-form project the compiler accepts is a project the editor reports nothing
/// about. Every test below breaks exactly one thing, so a diagnostic that appears there is the one
/// the test broke.
#[test]
fn the_worked_compact_form_project_reports_nothing() {
    let project = EvidenceProject::new(&operation_question_project());
    let index = project.index();

    assert!(
        index.diagnostics().is_empty(),
        "the compact form the compiler accepts reports nothing: {:?}",
        index.diagnostics()
    );
}

/// Edge 1: `source.operation` names an operationId the description publishes. Paired with
/// `unique_operation` in `crates/registry-evidencectl/src/authoring.rs:1532-1573`, which scans all
/// eight HTTP methods of every path item for the exact `operationId` and refuses the project with
/// "source.operation must resolve to exactly one OpenAPI operationId" when the matches are not
/// exactly one.
#[test]
fn a_question_refers_to_the_operation_it_answers() {
    let project = EvidenceProject::new(&operation_question_project());
    let index = project.index();

    assert_eq!(
        index
            .definitions_at(
                &project.path(QUESTION_PATH),
                project.cursor(QUESTION_PATH, "operation")
            )
            .into_iter()
            .map(|location| (location.path, location.range.start))
            .collect::<Vec<_>>(),
        vec![(
            project.path(OPENAPI_PATH),
            project.cursor(OPENAPI_PATH, "operation-id")
        )]
    );
    assert_eq!(
        index
            .references_at(
                &project.path(OPENAPI_PATH),
                project.cursor(OPENAPI_PATH, "operation-id"),
                false
            )
            .into_iter()
            .map(|location| (location.path, location.range.start))
            .collect::<Vec<_>>(),
        vec![(
            project.path(QUESTION_PATH),
            project.cursor(QUESTION_PATH, "operation")
        )]
    );
}

#[test]
fn an_operation_the_description_does_not_publish_is_reported() {
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        QUESTION_PATH,
        &OPERATION_QUESTION.replace(
            "operation: <|operation|>readPerson",
            "operation: <|operation|>listPeople",
        ),
    ));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(
        diagnostic.range.start,
        project.cursor(QUESTION_PATH, "operation")
    );
    assert_eq!(
        diagnostic.message,
        "Unknown operation reference 'listPeople'"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/unknown-operation")
    );
}

/// The other half of `unique_operation`'s rule: two operations carrying one `operationId` are as
/// many matches as none, and the compiler refuses both with the same sentence.
#[test]
fn an_operation_identifier_two_operations_publish_is_reported() {
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        OPENAPI_PATH,
        &format!(
            "{OPERATION_OPENAPI}  /people/{{person_id}}/history:\n    get:\n      \
             operationId: readPerson\n      responses:\n        '200':\n          \
             description: The same identifier again\n          content:\n            \
             application/json:\n              schema: {{type: object}}\n"
        ),
    ));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(
        diagnostic.range.start,
        project.cursor(QUESTION_PATH, "operation")
    );
    assert_eq!(
        diagnostic.message,
        "Ambiguous operation reference 'readPerson': found 2 definitions"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/ambiguous-operation")
    );
}

/// The same description with no question naming the repeated identifier, which is a project the
/// compiler builds and the editor must say nothing about.
///
/// `Description::published` (`crates/registry-language-server/src/evidence/openapi.rs:139`) yields a
/// repeated `operationId` once per operation on purpose, and every published operation is defined
/// as a symbol whether or not a question names it, so both definitions really are in the index.
/// `unique_operation` (`crates/registry-evidencectl/src/authoring.rs:1565-1567`) refuses an
/// ambiguous identifier only where a question spells it, so nothing refuses this description. The
/// exemption in `SymbolKind::reports_duplicates` is what keeps the editor quiet over it, and this
/// test fails if that exemption is removed.
#[test]
fn an_identifier_two_operations_publish_and_no_question_names_is_reported_nowhere() {
    let described = OPERATION_OPENAPI.replace(
        "paths:\n",
        concat!(
            "paths:\n",
            "  /people:\n",
            "    get:\n",
            "      operationId: listPeople\n",
            "      responses:\n",
            "        '200':\n",
            "          description: Every person\n",
            "  /people/all:\n",
            "    get:\n",
            "      operationId: listPeople\n",
            "      responses:\n",
            "        '200':\n",
            "          description: Every person, again\n",
        ),
    );
    assert_ne!(
        described, OPERATION_OPENAPI,
        "the fixture must publish one identifier twice"
    );
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        OPENAPI_PATH,
        &described,
    ));
    let index = project.index();

    assert_eq!(
        index
            .symbols()
            .iter()
            .filter(|symbol| {
                symbol.kind == SymbolKind::Evidence(EvidenceKind::Operation)
                    && symbol.name == "listPeople"
            })
            .count(),
        2,
        "the description defines the repeated identifier twice, which is what makes it a duplicate"
    );
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
}

/// An operationId on a method the compiler will not compile still resolves here.
///
/// `unique_operation` matches the identifier across all eight methods and only then refuses a
/// method that is not `get`, with "the local tutorial source supports only one resolved GET
/// operationId". The name the author wrote does name that operation, so reporting it as one the
/// description does not publish would be a sentence about the wrong mistake, and one the compiler
/// never prints.
#[test]
fn an_operation_published_under_another_method_still_resolves() {
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        OPENAPI_PATH,
        &OPERATION_OPENAPI.replace("    get:\n", "    post:\n"),
    ));
    let index = project.index();

    assert_eq!(
        index
            .definitions_at(
                &project.path(QUESTION_PATH),
                project.cursor(QUESTION_PATH, "operation")
            )
            .into_iter()
            .map(|location| location.path)
            .collect::<Vec<_>>(),
        vec![project.path(OPENAPI_PATH)]
    );
    assert!(
        index
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.code.as_deref() != Some("evidence/unknown-operation")),
        "{:?}",
        index.diagnostics()
    );
}

/// Edge 2: `subject.selector` names one of the operation's required string path parameters. Paired
/// with `exact_path_selectors` in `crates/registry-evidencectl/src/authoring.rs:1575-1646`, which
/// gathers the path item's and the operation's `parameters`, keeps the ones that are `in: path`,
/// `required: true` and `schema.type: string`, and refuses the project with "question selectors must
/// equal the operation's required string path parameters" when the question's selectors are not
/// exactly that set.
#[test]
fn a_subject_selector_the_operation_has_no_path_parameter_for_is_reported() {
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        QUESTION_PATH,
        &OPERATION_QUESTION.replace(
            "selector: <|selector|>person_id",
            "selector: <|selector|>person_ref",
        ),
    ));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(
        diagnostic.range.start,
        project.cursor(QUESTION_PATH, "selector")
    );
    assert_eq!(
        diagnostic.message,
        "Subject selector 'person_ref' is not a required string path parameter of operation 'readPerson'"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/subject-selector")
    );
}

/// An operation whose parameters this editor cannot read the way the compiler reads them is one it
/// says nothing about.
///
/// `exact_path_selectors` refuses each of these documents before it compares anything, so the
/// project does not build; the editor knows only that it cannot tell which names are selectors, and
/// a guess would report a selector the compiler may well accept.
#[test]
fn a_selector_of_an_operation_whose_parameters_cannot_be_read_is_left_alone() {
    for unreadable in [
        "          in: query\n",
        "          required: false\n",
        "          schema: {type: integer}\n",
    ] {
        let description = match unreadable {
            "          in: query\n" => {
                OPERATION_OPENAPI.replace("          in: path\n", unreadable)
            }
            "          required: false\n" => {
                OPERATION_OPENAPI.replace("          required: true\n", unreadable)
            }
            _ => OPERATION_OPENAPI.replace("          schema: {type: string}\n", unreadable),
        };
        assert_ne!(description, OPERATION_OPENAPI, "{unreadable:?}");
        let project = EvidenceProject::new(&replacing(
            &operation_question_project(),
            OPENAPI_PATH,
            &description,
        ));

        let index = project.index();

        assert!(
            index.diagnostics().is_empty(),
            "{unreadable:?}: {:?}",
            index.diagnostics()
        );
    }
}

/// Edge 3: each `source.facts[].path` selects a leaf the operation's response offers. Paired with
/// `compile_facts` in `crates/registry-evidencectl/src/authoring.rs:1648-1679`, which asks
/// `registry_evidence_authoring::openapi::selectable_leaves` for the same set at :1661 and refuses
/// the project with "source fact `<name>` path `<path>` is not a selectable scalar leaf in the 200
/// application/json response".
#[test]
fn a_fact_path_the_response_does_not_offer_is_reported() {
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        QUESTION_PATH,
        &OPERATION_QUESTION.replace(
            "path: <|fact-path|>/records/*/date_of_birth",
            "path: <|fact-path|>/records/*/name",
        ),
    ));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(
        diagnostic.range.start,
        project.cursor(QUESTION_PATH, "fact-path")
    );
    assert_eq!(
        diagnostic.message,
        "Fact path '/records/*/name' is not a selectable leaf of the 200 application/json response of operation 'readPerson'"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/unselectable-fact-path")
    );
}

/// The same rule where the member really is there. `/records/*` is a member the response has and is
/// not a scalar, which is the case `compile_facts` refuses at :1666-1674 itself; a member that is
/// not there at all is refused one check earlier, by `validate_selected_schema_path` at
/// `crates/registry-evidencectl/src/authoring.rs:1659`, with a sentence of its own. Both are
/// projects the build will not compile, and the field the author has to change is the same one.
#[test]
fn a_fact_path_at_something_that_is_not_a_scalar_leaf_is_reported() {
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        QUESTION_PATH,
        &OPERATION_QUESTION.replace(
            "path: <|fact-path|>/records/*/date_of_birth",
            "path: <|fact-path|>/records/*",
        ),
    ));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(
        diagnostic.message,
        "Fact path '/records/*' is not a selectable leaf of the 200 application/json response of operation 'readPerson'"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/unselectable-fact-path")
    );
}

/// A response the flattening cannot read offers no leaves, and an editor that reported every fact
/// path against an empty set would underline a project whose only problem is elsewhere.
#[test]
fn a_fact_path_of_an_operation_with_no_readable_response_is_left_alone() {
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        OPENAPI_PATH,
        &OPERATION_OPENAPI.replace("        '200':\n", "        '404':\n"),
    ));
    let index = project.index();

    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
}

/// Edge 4: every key of `source.collectionBounds` names a collection some fact path visits, and
/// every collection they visit is bounded. Paired with `compile_facts` in
/// `crates/registry-evidencectl/src/authoring.rs:1681-1705`, which settles the two sets against each
/// other and refuses the project with "source.collectionBounds must exactly name every selected
/// collection (missing: ...; unused: ...)".
#[test]
fn a_collection_bound_names_the_fact_path_that_visits_it() {
    let project = EvidenceProject::new(&operation_question_project());
    let index = project.index();

    assert_eq!(
        index
            .definitions_at(
                &project.path(QUESTION_PATH),
                project.cursor(QUESTION_PATH, "collection-bound")
            )
            .into_iter()
            .map(|location| (location.path, location.range.start))
            .collect::<Vec<_>>(),
        vec![(
            project.path(QUESTION_PATH),
            project.cursor(QUESTION_PATH, "fact-path")
        )]
    );
}

#[test]
fn a_collection_bound_no_fact_visits_is_reported() {
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        QUESTION_PATH,
        &OPERATION_QUESTION.replace(
            "    <|collection-bound|>/records: 16\n",
            "    /records: 16\n    <|collection-bound|>/nope: 16\n",
        ),
    ));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(
        diagnostic.range.start,
        project.cursor(QUESTION_PATH, "collection-bound")
    );
    assert_eq!(
        diagnostic.message,
        "Unknown collection reference '/nope' in question 'adult-status'"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/unknown-collection")
    );
}

#[test]
fn a_collection_no_bound_names_is_reported() {
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        QUESTION_PATH,
        &OPERATION_QUESTION.replace(
            "  collectionBounds:\n    <|collection-bound|>/records: 16\n",
            "  collectionBounds: {}\n",
        ),
    ));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(
        diagnostic.range.start,
        project.cursor(QUESTION_PATH, "fact-path")
    );
    assert_eq!(
        diagnostic.message,
        "This path visits the collection '/records', which source.collectionBounds does not bound"
    );
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/undeclared-collection")
    );
}

/// Two facts reading different members of one array visit one collection, which one bound bounds.
/// A collection defined once per fact would report the author's single correct bound as an ambiguous
/// reference, over a project the compiler builds.
#[test]
fn two_facts_visiting_one_collection_declare_it_once() {
    let described = OPERATION_OPENAPI.replace(
        "                        date_of_birth: {type: string, format: date}\n",
        "                        date_of_birth: {type: string, format: date}\n                        given_name: {type: string, maxLength: 64}\n",
    );
    assert_ne!(
        described, OPERATION_OPENAPI,
        "the fixture must describe a second member"
    );
    let files = replacing(&operation_question_project(), OPENAPI_PATH, &described);
    let project = EvidenceProject::new(&replacing(
        &files,
        QUESTION_PATH,
        &OPERATION_QUESTION.replace(
            "      combine: collect\n",
            "      combine: collect\n    - name: given_name\n      path: /records/*/given_name\n      combine: collect\n",
        ),
    ));
    let index = project.index();

    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    assert_eq!(
        index
            .definitions_at(
                &project.path(QUESTION_PATH),
                project.cursor(QUESTION_PATH, "collection-bound")
            )
            .len(),
        1,
        "one collection is defined once however many facts visit it"
    );
}

/// One mistake, one sentence. An operation that does not resolve leaves the selector, the fact path
/// and the collection bound with nothing to be read against, and the compiler stops at
/// `unique_operation` without judging any of them
/// (`crates/registry-evidencectl/src/authoring.rs:990`).
#[test]
fn an_unresolved_operation_reports_nothing_about_the_fields_that_read_it() {
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        QUESTION_PATH,
        &OPERATION_QUESTION
            .replace(
                "operation: <|operation|>readPerson",
                "operation: <|operation|>listPeople",
            )
            .replace(
                "selector: <|selector|>person_id",
                "selector: <|selector|>person_ref",
            )
            .replace(
                "path: <|fact-path|>/records/*/date_of_birth",
                "path: <|fact-path|>/nowhere/*/name",
            )
            .replace(
                "    <|collection-bound|>/records: 16\n",
                "    <|collection-bound|>/nope: 16\n",
            ),
    ));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/unknown-operation")
    );
}

/// The same discipline one rung earlier. A question the authoring form refuses is one
/// `compile_question_plan` never reads, because it takes its inline source out with
/// `.expect("inline source was validated")`
/// (`crates/registry-evidencectl/src/authoring.rs:989`), so the field the form names is the only
/// thing the author is told about.
#[test]
fn a_question_the_form_refuses_reports_only_its_own_problem() {
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        QUESTION_PATH,
        &OPERATION_QUESTION
            .replace(
                "operation: <|operation|>readPerson",
                "operation: <|operation|>''",
            )
            .replace(
                "selector: <|selector|>person_id",
                "selector: <|selector|>person_ref",
            ),
    ));
    let index = project.index();

    let diagnostic = only_diagnostic_in(&index, &project, QUESTION_PATH);
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("evidence/operation-identifier")
    );
}

/// A question that reads a named source names nothing in the description, and the compact-form
/// edges are not drawn over it at all.
#[test]
fn a_question_written_in_the_referenced_form_draws_no_operation_edge() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();

    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
}

/// A project whose description passes the compiler's prerequisite checks but cannot safely publish
/// operations is one the editor says nothing about.
///
/// These two are refused later inside `unique_operation`
/// (`crates/registry-evidencectl/src/authoring.rs:1536-1547`). Unlike a missing or invalid retained
/// document, they are not reasons to stop the earlier authoring diagnostics.
#[test]
fn a_description_unavailable_after_prerequisites_leaves_every_edge_alone() {
    let unreadable = [
        (
            "paths that is not an object",
            "openapi: 3.1.0\ninfo: {title: Example source, version: 1.0.0}\npaths: []\n".to_owned(),
        ),
        (
            "a path item behind a reference",
            OPERATION_OPENAPI.replace(
                "  /people/{person_id}:\n",
                "  /elsewhere:\n    $ref: '#/components/pathItems/elsewhere'\n  /people/{person_id}:\n",
            ),
        ),
    ];

    for (why, description) in unreadable {
        let project = EvidenceProject::new(&replacing(
            &speaks_when_the_description_is_read(),
            OPENAPI_PATH,
            &description,
        ));

        let index = project.index();

        assert!(
            index.diagnostics().is_empty(),
            "{why}: {:?}",
            index.diagnostics()
        );
    }
}

#[test]
fn a_project_with_no_description_leaves_every_edge_alone() {
    let project = EvidenceProject::new(&without(
        &speaks_when_the_description_is_read(),
        OPENAPI_PATH,
    ));
    let index = project.index();

    let reported = index.diagnostics();
    assert_eq!(reported.len(), 1, "{reported:?}");
    assert_eq!(
        reported[0].code.as_deref(),
        Some("evidence/openapi-prerequisite")
    );
}

/// A description past the authoring form's own ceiling is the one prerequisite diagnostic, which
/// is what `registry-evidencectl` does with the same file before reading dependent inputs.
#[test]
fn a_description_past_the_ceiling_the_authoring_form_sets_leaves_every_edge_alone() {
    let padding = "#".repeat(usize::try_from(MAX_OPENAPI_BYTES).expect("the ceiling fits a usize"));
    let project = EvidenceProject::new(&replacing(
        &speaks_when_the_description_is_read(),
        OPENAPI_PATH,
        &format!("{OPERATION_OPENAPI}{padding}\n"),
    ));
    let index = project.index();

    let reported = index.diagnostics();
    assert_eq!(reported.len(), 1, "{reported:?}");
    assert_eq!(
        reported[0].code.as_deref(),
        Some("evidence/openapi-prerequisite")
    );
    assert!(index
        .definitions_at(
            &project.path(QUESTION_PATH),
            project.cursor(QUESTION_PATH, "operation")
        )
        .is_empty());
}

/// A project whose question names an operation no description publishes, so that a reading of the
/// description reports it.
///
/// The degradation cases assert that the editor says nothing, and a project the compiler accepts
/// says nothing either way: the silence would prove only that the fixture was correct. This one
/// reports `evidence/unknown-operation` the moment the description is read at all
/// (`an_operation_the_description_does_not_publish_is_reported` is the same question against a
/// description that reads), so silence over it means the edge was never drawn.
fn speaks_when_the_description_is_read() -> Vec<ProjectFile> {
    replacing(
        &operation_question_project(),
        QUESTION_PATH,
        &OPERATION_QUESTION.replace(
            "operation: <|operation|>readPerson",
            "operation: <|operation|>listPeople",
        ),
    )
}

/// A description too large for the editor to record positions in is still analysed, and only the
/// place a definition points at degrades.
///
/// The operation still resolves, so the three edges that read one are still checked and the question
/// above still reports nothing. Going to the definition of the operation lands at the top of the
/// description instead of on the line that publishes it, which is the honest answer: the name is
/// published, and this editor did not index where.
#[test]
fn a_description_too_large_to_index_positions_in_still_resolves_at_the_start_of_the_file() {
    let padding = "#".repeat(2 * 1024 * 1024);
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        OPENAPI_PATH,
        &format!("{OPERATION_OPENAPI}{padding}\n"),
    ));
    let index = project.index();

    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    assert_eq!(
        index
            .definitions_at(
                &project.path(QUESTION_PATH),
                project.cursor(QUESTION_PATH, "operation")
            )
            .into_iter()
            .map(|location| (location.path, location.range.start.line))
            .collect::<Vec<_>>(),
        vec![(project.path(OPENAPI_PATH), 0)]
    );
}

/// A project written before the marker existed is an authoring project, and its compact-form edges
/// are drawn like any other's.
#[test]
fn a_project_with_no_marker_draws_the_same_edges() {
    let project =
        EvidenceProject::new(&without(&operation_question_project(), PROJECT_MARKER_FILE));
    let index = project.index();

    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    assert_eq!(
        index
            .definitions_at(
                &project.path(QUESTION_PATH),
                project.cursor(QUESTION_PATH, "operation")
            )
            .len(),
        1
    );
}

/// The only diagnostic one document reports, with the whole project's diagnostics in the failure
/// message when there is more than one.
fn only_diagnostic_in<'index>(
    index: &'index ProjectIndex,
    project: &EvidenceProject,
    relative: &str,
) -> &'index IndexedDiagnostic {
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

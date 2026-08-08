// SPDX-License-Identifier: Apache-2.0
//! The names offered where one is written, and what one already written turns out to be.
//!
//! Completion and hover answer from the same place navigation does: the reference under the cursor
//! knows the kind and the scope of the name it holds, so the list is every name that reference could
//! have held and the card is what the one it does hold resolves to. There is no second model of
//! which field takes which kind, because a second model is a model that can disagree.
//!
//! Three fields are spelled as paths rather than as names another document declares, and their lists
//! are the files the project holds in the directory the form puts them in. The file an author has
//! just created is exactly the file they are about to point at, and no document spells it yet, so a
//! list drawn from the documents alone would miss the moment it exists for.
//!
//! Neither one may report anything, and neither one may reach a document the loader refused. The
//! sentences an author has to act on stay in `evidence_index.rs` and `evidence_openapi.rs`.

mod support;

use registry_evidence_authoring::{
    layout::{MAX_CONCEPTS, MAX_QUESTIONS},
    testing::ProjectFile,
};
use registry_language_server::{CompletionCandidate, ProjectIndex};
use support::{
    adult_status_project, file, operation_question_project, replacing, EvidenceProject,
    ACCESS_POLICY_PATH, DERIVATION, FIXTURE, OPENAPI_PATH, OPERATION_OPENAPI, OPERATION_QUESTION,
    QUESTION, QUESTION_PATH, SCHEMA, SOURCE,
};
use tower_lsp_server::ls_types::{CompletionItemKind, Position};

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

/// A second source document beside the one the shared project holds, so a list of the sources a
/// question may read is longer than the name already written and cannot pass by echoing it.
fn project_with_two_sources() -> Vec<ProjectFile> {
    replacing(&adult_status_project(), "sources/ledger.yaml", SOURCE)
}

#[test]
fn the_sources_a_question_may_read_are_offered_where_it_names_one() {
    let project = EvidenceProject::new(&project_with_two_sources());
    let index = project.index();

    assert_eq!(
        labels_at(&index, &project, QUESTION_PATH, "source-ref"),
        vec!["ledger".to_owned(), "people".to_owned()]
    );
}

/// The list is the kind the field takes and nothing else. A question, a selector profile and a
/// concept are all names this project holds, and none of them is a name `source.ref` may be.
#[test]
fn a_field_is_offered_only_the_kind_of_name_it_holds() {
    let project = EvidenceProject::new(&project_with_two_sources());
    let index = project.index();

    let candidates = candidates_at(&index, &project, QUESTION_PATH, "source-ref");
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate.detail == "source"),
        "{candidates:?}"
    );
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate.kind == CompletionItemKind::MODULE),
        "{candidates:?}"
    );
}

/// A concept belongs to the question that answers it, and `disclosure.allow` may name only the
/// question's own. The second question below answers a concept of another name, and it does not
/// reach this question's list.
#[test]
fn a_scoped_name_is_offered_only_the_names_of_its_own_scope() {
    let second = QUESTION
        .replace("<|id|>adult-status", "residence-region")
        .replace("<|concept|>is_adult", "in_region")
        .replace("<|allow|>is_adult", "in_region")
        .replace("<|derivation|>", "")
        .replace("<|source-ref|>", "")
        .replace("<|subject-profile|>", "")
        .replace("<|fixtures|>", "");
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        "questions/residence-region.yaml",
        &second,
    ));
    let index = project.index();

    assert!(
        index
            .symbols()
            .iter()
            .any(|symbol| symbol.name == "in_region"),
        "the second question answers a concept, or this asserts nothing"
    );
    assert_eq!(
        labels_at(&index, &project, QUESTION_PATH, "allow"),
        vec!["is_adult".to_owned()]
    );
}

#[test]
fn the_operations_the_description_publishes_are_offered_where_a_question_names_one() {
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        OPENAPI_PATH,
        &format!(
            "{OPERATION_OPENAPI}  /people:\n    get:\n      operationId: listPeople\n      \
             responses:\n        '200':\n          description: Every person\n          \
             content:\n            application/json:\n              schema: {{type: object}}\n"
        ),
    ));
    let index = project.index();

    assert_eq!(
        labels_at(&index, &project, QUESTION_PATH, "operation"),
        vec!["listPeople".to_owned(), "readPerson".to_owned()]
    );
}

/// One name however many places define it. A description publishing two operations under one
/// identifier is a project the compiler builds, so the list an author reads over it is a menu with
/// one entry, not the same dish written twice.
#[test]
fn a_name_more_than_one_place_defines_is_offered_once() {
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        OPENAPI_PATH,
        &format!(
            "{OPERATION_OPENAPI}  /people:\n    get:\n      operationId: listPeople\n      \
             responses:\n        '200':\n          description: Every person\n          \
             content:\n            application/json:\n              schema: {{type: object}}\n  \
             /people/all:\n    get:\n      operationId: listPeople\n      responses:\n        \
             '200':\n          description: Every person, again\n          content:\n            \
             application/json:\n              schema: {{type: object}}\n"
        ),
    ));
    let index = project.index();

    assert_eq!(
        labels_at(&index, &project, QUESTION_PATH, "operation"),
        vec!["listPeople".to_owned(), "readPerson".to_owned()]
    );
}

/// The one list no author can write from memory: a JSON pointer into an operation's response.
///
/// These come from `Description::selectable`, the set the compiler selects against, so a path this
/// list offers is a path the build accepts.
#[test]
fn the_leaves_of_the_response_are_offered_where_a_fact_projects_one() {
    let described = OPERATION_OPENAPI.replace(
        "                type: object\n                properties:\n",
        "                type: object\n                properties:\n                  \
         record_count: {type: integer}\n",
    );
    assert_ne!(
        described, OPERATION_OPENAPI,
        "the description declares the response object this adds a second leaf to"
    );
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        OPENAPI_PATH,
        &described,
    ));
    let index = project.index();

    let candidates = candidates_at(&index, &project, QUESTION_PATH, "fact-path");
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.label.clone())
            .collect::<Vec<_>>(),
        vec![
            "/record_count".to_owned(),
            "/records/*/date_of_birth".to_owned()
        ]
    );
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate.detail == "selectable leaf"),
        "{candidates:?}"
    );
}

/// A fact path the response does not offer is the moment the list is worth most, so it is still
/// offered there. The diagnostic that names the mistake is `evidence_openapi.rs`'s; this asserts
/// only that asking for the list does not depend on the author having already been right.
#[test]
fn a_fact_path_that_resolves_to_nothing_is_still_offered_the_leaves() {
    let project = EvidenceProject::new(&replacing(
        &operation_question_project(),
        QUESTION_PATH,
        &OPERATION_QUESTION.replace(
            "path: <|fact-path|>/records/*/date_of_birth",
            "path: <|fact-path|>/records/*/date_of_b",
        ),
    ));
    let index = project.index();

    assert_eq!(
        labels_at(&index, &project, QUESTION_PATH, "fact-path"),
        vec!["/records/*/date_of_birth".to_owned()]
    );
}

/// The shared question with a structured answer, which is the one answer kind that names a schema,
/// so one document holds all three places the authoring form spells a file by its path.
fn question_pointing_at_three_files() -> String {
    let written = QUESTION.replace(
        "    type: boolean\n",
        "    type: reviewed-structured-value\n    \
         schema: <|answer-schema|>schemas/person-record.yaml\n    \
         maximumSerializedBytes: 4096\n",
    );
    assert_ne!(
        written, QUESTION,
        "the shared question writes the boolean answer this rewrites"
    );
    written
}

/// The same project with that question and the schema it names: a project the compiler accepts,
/// pointing at a schema, a fixtures document and a derivation it really holds.
fn three_pointers_project() -> Vec<ProjectFile> {
    let files = replacing(
        &adult_status_project(),
        QUESTION_PATH,
        &question_pointing_at_three_files(),
    );
    replacing(&files, "schemas/person-record.yaml", SCHEMA)
}

/// The same project with one file in each of those three directories that no document spells. This
/// is the project an author has a moment after creating a file and a moment before pointing at it.
fn project_holding_unspelled_files() -> Vec<ProjectFile> {
    let files = replacing(&three_pointers_project(), UNSPELLED_SCHEMA, SCHEMA);
    let files = replacing(&files, UNSPELLED_FIXTURE, FIXTURE);
    replacing(&files, UNSPELLED_DERIVATION, DERIVATION)
}

const UNSPELLED_SCHEMA: &str = "schemas/person-address.yaml";
const UNSPELLED_FIXTURE: &str = "fixtures/adult-status-edges.yaml";
const UNSPELLED_DERIVATION: &str = "derivations/adult-status-edges.rhai";

/// The three lists that are not the symbol table's. A file a document already spells is a file some
/// symbol stands for; the file the author just created is the one they are about to spell, and it is
/// the case the whole feature exists for.
#[test]
fn a_file_no_document_spells_is_offered_where_one_is_pointed_at() {
    let project = EvidenceProject::new(&project_holding_unspelled_files());
    let index = project.index();

    for (cursor, unspelled) in [
        ("answer-schema", UNSPELLED_SCHEMA),
        ("fixtures", UNSPELLED_FIXTURE),
        ("derivation", UNSPELLED_DERIVATION),
    ] {
        let labels = labels_at(&index, &project, QUESTION_PATH, cursor);
        assert!(
            labels.iter().any(|label| label == unspelled),
            "{cursor} offers {labels:?}, which does not hold {unspelled}"
        );
    }
}

/// A file is one thing the author may write, however many ways the editor learned of it. The three
/// paths the shared question spells are both files on disk and names some document declares, and
/// each one is one entry.
#[test]
fn a_file_a_document_already_spells_is_offered_once() {
    let project = EvidenceProject::new(&project_holding_unspelled_files());
    let index = project.index();

    for (cursor, spelled) in [
        ("answer-schema", "schemas/person-record.yaml"),
        ("fixtures", "fixtures/adult-status.yaml"),
        ("derivation", "derivations/adult-status.rhai"),
    ] {
        let labels = labels_at(&index, &project, QUESTION_PATH, cursor);
        assert_eq!(
            labels.iter().filter(|label| *label == spelled).count(),
            1,
            "{cursor} offers {labels:?}"
        );
    }
}

/// Every question names its own derivation file, so a file another question claims is a file this
/// one may not have. Reading the directory finds it anyway, and offering it would walk the author
/// into a refusal the editor could see coming.
#[test]
fn a_derivation_another_question_claims_is_not_offered() {
    const CLAIMED: &str = "derivations/residence-region.rhai";
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
        .replace("<|fixtures|>", "");
    let files = replacing(
        &project_holding_unspelled_files(),
        "questions/residence-region.yaml",
        &second,
    );
    let project = EvidenceProject::new(&replacing(&files, CLAIMED, DERIVATION));
    let index = project.index();

    let labels = labels_at(&index, &project, QUESTION_PATH, "derivation");
    assert!(
        labels.iter().any(|label| label == UNSPELLED_DERIVATION),
        "the file no question claims is still offered: {labels:?}"
    );
    assert!(
        !labels.iter().any(|label| label == CLAIMED),
        "the file the second question claims reached this question's list: {labels:?}"
    );
}

/// The guard the rest of this addition rests on. Reading a directory to fill a list must define
/// nothing, so a project pointing at a schema, a fixtures document and a derivation it holds is a
/// project the editor still reports nothing about: a second definition of one of those files would
/// answer it with a duplicate over a project the compiler accepts.
#[test]
fn a_project_pointing_at_files_it_holds_reports_nothing() {
    for files in [three_pointers_project(), project_holding_unspelled_files()] {
        let project = EvidenceProject::new(&files);
        let index = project.index();

        assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    }
}

/// An author who has not created `fixtures/` yet is not told anything about it. The compact form
/// holds neither a schema nor a fixtures directory, so the list at its one file pointer is read
/// while two of the three directories are absent.
#[test]
fn a_directory_the_project_does_not_hold_is_silent() {
    let project = EvidenceProject::new(&operation_question_project());
    let index = project.index();

    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    assert_eq!(
        labels_at(&index, &project, QUESTION_PATH, "derivation"),
        vec!["derivations/adult-status.rhai".to_owned()]
    );
}

/// A directory nobody bounded is a directory anything may be dropped into, and a list is work done
/// on every keystroke. The ceiling is the authoring form's own reading of how many files of one role
/// a project can usefully name, and hitting it offers fewer files rather than saying anything: the
/// pointer at a file past it still resolves, because the document that spells it defines it.
#[test]
fn a_directory_holding_more_files_than_the_form_can_name_offers_fewer() {
    let ceiling = MAX_QUESTIONS * MAX_CONCEPTS;
    let mut files = project_holding_unspelled_files();
    files.extend(
        (0..=ceiling).map(|number| file(&format!("fixtures/case-{number:05}.yaml"), FIXTURE)),
    );
    let project = EvidenceProject::new(&files);
    let index = project.index();

    let labels = labels_at(&index, &project, QUESTION_PATH, "fixtures");
    assert_eq!(labels.len(), ceiling, "the list is bounded by the ceiling");
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    assert!(
        !index
            .definitions_at(
                &project.path(QUESTION_PATH),
                project.cursor(QUESTION_PATH, "fixtures"),
            )
            .is_empty(),
        "the file the question points at still resolves"
    );
}

/// What the client replaces is the value the author wrote, whole. Anything narrower leaves half of
/// a wrong name behind the one that was picked.
#[test]
fn a_candidate_replaces_the_whole_value_the_author_wrote() {
    let project = EvidenceProject::new(&project_with_two_sources());
    let index = project.index();

    let candidate = candidates_at(&index, &project, QUESTION_PATH, "source-ref")
        .into_iter()
        .next()
        .expect("the field offers the sources the project holds");
    let start = project.cursor(QUESTION_PATH, "source-ref");
    assert_eq!(candidate.range.start, start);
    assert_eq!(
        candidate.range.end,
        Position::new(start.line, start.character + "people".len() as u32)
    );
}

/// Where a cursor actually is while a name is being typed: after the last character of it, not
/// before the first.
#[test]
fn the_end_of_a_written_value_offers_the_same_list_as_its_start() {
    let project = EvidenceProject::new(&project_with_two_sources());
    let index = project.index();
    let path = project.path(QUESTION_PATH);
    let start = project.cursor(QUESTION_PATH, "source-ref");
    let end = Position::new(start.line, start.character + "people".len() as u32);

    assert_eq!(
        index
            .completions_at(&path, end)
            .into_iter()
            .map(|candidate| candidate.label)
            .collect::<Vec<_>>(),
        vec!["ledger".to_owned(), "people".to_owned()]
    );
}

/// A name being declared is not a name being spelled back. Offering every question that exists
/// where the author is naming this one would offer the author their own neighbours to collide with.
#[test]
fn a_place_that_declares_a_name_is_offered_nothing() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();

    assert!(labels_at(&index, &project, QUESTION_PATH, "id").is_empty());
}

/// `evidence/layout.rs` keeps `secrets/` out of the project the editor reads. A list or a card over
/// a path there would be a way to ask about a file the loader refused, so neither answers.
#[test]
fn a_document_under_secrets_is_offered_nothing_and_describes_nothing() {
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        "secrets/source-token.yaml",
        "ref: people\n",
    ));
    let index = project.index();
    let secret = project.path("secrets/source-token.yaml");

    for line in 0..2 {
        for character in 0..12 {
            let position = Position::new(line, character);
            assert!(
                index.completions_at(&secret, position).is_empty(),
                "{position:?}"
            );
            assert!(index.hover_at(&secret, position).is_none(), "{position:?}");
        }
    }
}

#[test]
fn a_reference_describes_what_it_resolves_to_and_where_that_is() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();

    let hover = index
        .hover_at(
            &project.path(QUESTION_PATH),
            project.cursor(QUESTION_PATH, "source-ref"),
        )
        .expect("the source a question reads describes itself");
    assert!(hover.markdown.contains("**source**"), "{hover:?}");
    assert!(hover.markdown.contains("`people`"), "{hover:?}");
    assert!(hover.markdown.contains("sources/people.yaml"), "{hover:?}");
    assert_eq!(
        hover.range.start,
        project.cursor(QUESTION_PATH, "source-ref")
    );
}

/// A scoped name says which scope it belongs to, in the word the form uses for it.
#[test]
fn a_scoped_reference_names_the_question_it_belongs_to() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();

    let hover = index
        .hover_at(
            &project.path(QUESTION_PATH),
            project.cursor(QUESTION_PATH, "allow"),
        )
        .expect("a disclosed concept describes itself");
    assert!(hover.markdown.contains("**concept**"), "{hover:?}");
    assert!(hover.markdown.contains("`is_adult`"), "{hover:?}");
    assert!(
        hover.markdown.contains("in question `adult-status`"),
        "{hover:?}"
    );
}

#[test]
fn a_declaration_describes_itself() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();

    let hover = index
        .hover_at(
            &project.path(ACCESS_POLICY_PATH),
            project.cursor(ACCESS_POLICY_PATH, "policy-id"),
        )
        .expect("an access policy describes itself where it is declared");
    assert!(hover.markdown.contains("**access policy**"), "{hover:?}");
    assert!(hover.markdown.contains("`adult-checks`"), "{hover:?}");
}

/// A name with nothing behind it says nothing. The author is already being told about it by the
/// diagnostic that owns the mistake, and a card repeating it would be a second voice on one field.
#[test]
fn a_reference_that_resolves_to_nothing_describes_nothing() {
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        QUESTION_PATH,
        &QUESTION.replace("<|source-ref|>people", "<|source-ref|>ledger"),
    ));
    let index = project.index();

    assert!(index
        .hover_at(
            &project.path(QUESTION_PATH),
            project.cursor(QUESTION_PATH, "source-ref")
        )
        .is_none());
}

#[test]
fn a_position_holding_neither_a_name_nor_a_reference_describes_nothing() {
    let project = EvidenceProject::new(&adult_status_project());
    let index = project.index();

    assert!(index
        .hover_at(&project.path(QUESTION_PATH), Position::new(1, 3))
        .is_none());
}

/// A hover is rendered UI, so every name inside one is cut to the width a name is quoted at,
/// exactly as a name inside a diagnostic is. A source is named by its file, and a filesystem takes
/// a longer file name than anything worth drawing in a card.
#[test]
fn a_name_too_long_to_draw_is_cut_inside_the_card() {
    let long = "l".repeat(200);
    let project = EvidenceProject::new(&replacing(
        &replacing(
            &adult_status_project(),
            &format!("sources/{long}.yaml"),
            SOURCE,
        ),
        QUESTION_PATH,
        &QUESTION.replace("<|source-ref|>people", &format!("<|source-ref|>{long}")),
    ));
    let index = project.index();

    let hover = index
        .hover_at(
            &project.path(QUESTION_PATH),
            project.cursor(QUESTION_PATH, "source-ref"),
        )
        .expect("the source describes itself");
    assert!(
        !hover.markdown.contains(&long),
        "the whole name reached the card"
    );
    assert!(
        hover
            .markdown
            .contains(&format!("{}\u{2026}", "l".repeat(120))),
        "{hover:?}"
    );
}

/// A card is the one thing this server renders rather than states, and the names inside one come
/// from a project its reader did not write.
///
/// `bounded_value` makes a name safe to quote in a sentence a client draws as text, which says
/// nothing about the same name drawn as markup: a backtick the author wrote closes the span the name
/// is drawn in, and every character after it is the author's markup rather than this crate's. A name
/// carrying one is a name `evidence check` rejects, which is exactly why an editor sees it, because
/// an editor is what an author reads before it is rejected.
#[test]
fn a_name_carrying_markup_does_not_get_to_draw_it() {
    let payload = "is_adult` **not what it says**";
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        QUESTION_PATH,
        &QUESTION
            .replace("<|concept|>is_adult", &format!("<|concept|>{payload}"))
            .replace("<|allow|>is_adult", &format!("<|allow|>{payload}")),
    ));
    let index = project.index();

    let hover = index
        .hover_at(
            &project.path(QUESTION_PATH),
            project.cursor(QUESTION_PATH, "allow"),
        )
        .expect("the concept describes itself");
    assert!(
        !hover.markdown.contains(payload),
        "the author's backtick reached the card and closed the span the name is drawn in: {hover:?}"
    );
    assert!(
        hover
            .markdown
            .contains("is_adult\u{fffd} **not what it says**"),
        "the name is still the whole name the author wrote, minus the one character: {hover:?}"
    );
}

/// The scope a card names is written by the same author as the name it scopes, and reaches the card
/// by the same route. It is drawn in a span of its own so that a question id carrying markup cannot
/// draw the rest of the line either.
#[test]
fn a_scope_carrying_markup_does_not_get_to_draw_it_either() {
    let payload = "adult-status` [see](https://example.invalid)";
    let project = EvidenceProject::new(&replacing(
        &adult_status_project(),
        QUESTION_PATH,
        &QUESTION.replace("<|id|>adult-status", &format!("<|id|>{payload}")),
    ));
    let index = project.index();

    let hover = index
        .hover_at(
            &project.path(QUESTION_PATH),
            project.cursor(QUESTION_PATH, "allow"),
        )
        .expect("the concept describes itself");
    assert!(
        !hover.markdown.contains("[see](https://example.invalid)")
            || !hover.markdown.contains("adult-status`"),
        "the question id closed the span its scope is drawn in: {hover:?}"
    );
}

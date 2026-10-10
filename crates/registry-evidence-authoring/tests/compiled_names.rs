//! The authored names a compiled bundle would refuse, refused where they are
//! written.
//!
//! The bundle names a selector profile, a selector field, and a source with a
//! lowercase letter followed by up to 63 lowercase letters, digits, `_`, or
//! `-`: no dot, and 64 characters at most. The authoring form is wider, and a
//! question that reads an operation of the project's own OpenAPI description
//! has its selector profile and its source named after it. Each case below is
//! one name the form used to accept and the bundle then refused, held to the
//! member an author wrote it in.

use registry_evidence_authoring::{
    local_selector_profile_id, local_source_id, local_subject_selector_profile_id,
    validate_question, Finding, Question, MAX_COMPILED_NAME_BYTES,
};
use serde_json::{json, Value};

/// A question that reads an operation of the project's own OpenAPI
/// description, about one subject.
fn inline_question() -> Value {
    json!({
        "id": "record-check",
        "question": "Does the record carry the reviewed marker?",
        "purpose": "record-check",
        "subject": { "role": "holder", "selector": "record_key" },
        "source": {
            "operation": "getRecord",
            "facts": [{ "name": "marker", "path": "/marker", "combine": "exactly-one" }]
        },
        "answers": [{ "concept": "marked", "type": "boolean" }],
        "derivation": "derivations/record-check.rhai",
        "disclosure": { "allow": ["marked"] }
    })
}

/// A question that reads a source the project names.
fn referenced_question() -> Value {
    let mut document = inline_question();
    document["subject"] = json!({
        "role": "holder", "selector": "record_key", "profile": "record-key-v1"
    });
    document["source"] = json!({ "ref": "record-source" });
    document
}

fn check(document: Value) -> Vec<Finding> {
    validate_question(&serde_json::from_value::<Question>(document).expect("the question parses"))
}

/// The one finding a refused document reports, as its code, the pointer of the
/// member it names, and its sentence.
fn refusal(document: Value) -> (&'static str, String, String) {
    let findings = check(document);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let finding = &findings[0];
    (
        finding.code,
        finding.field.to_json_pointer(),
        finding.message.clone(),
    )
}

fn several_subjects(document: &mut Value, first_role: &str, second_role: &str) {
    document.as_object_mut().unwrap().remove("subject");
    document["subjects"] = json!([
        { "role": first_role, "selector": "record_key" },
        { "role": second_role, "selector": "other_key", "derivation": true },
    ]);
}

#[test]
fn an_inline_question_id_over_47_bytes_is_refused_at_the_id() {
    let mut document = inline_question();
    document["id"] = json!("a".repeat(47));
    assert_eq!(check(document), Vec::new());

    let mut document = inline_question();
    document["id"] = json!("a".repeat(48));
    assert_eq!(
        refusal(document),
        (
            "compiled-name-length",
            "/id".to_owned(),
            "question id must be at most 47 bytes: the selector profile it compiles to, \
             `local-subject-<id>-v1`, may hold 64"
                .to_owned()
        )
    );
}

#[test]
fn an_id_and_a_role_over_46_bytes_together_are_refused_at_the_role() {
    let mut document = inline_question();
    document["id"] = json!("a".repeat(20));
    several_subjects(&mut document, &"b".repeat(26), "other");
    assert_eq!(check(document), Vec::new());

    let mut document = inline_question();
    document["id"] = json!("a".repeat(20));
    several_subjects(&mut document, "holder", &"b".repeat(27));
    assert_eq!(
        refusal(document),
        (
            "compiled-name-length",
            "/subjects/1/role".to_owned(),
            "question id and subject role must be at most 46 bytes together: the selector \
             profile they compile to, `local-subject-<id>-<role>-v1`, may hold 64"
                .to_owned()
        )
    );
}

#[test]
fn a_role_with_a_dot_is_refused_where_it_names_a_selector_profile() {
    let mut document = inline_question();
    several_subjects(&mut document, "holder", "second.party");
    assert_eq!(
        refusal(document),
        (
            "compiled-name-dot",
            "/subjects/1/role".to_owned(),
            "subject role must not contain a dot: it names a selector profile in the compiled \
             bundle"
                .to_owned()
        )
    );

    // One subject's role enters no compiled name, and neither does a role of
    // a question that reads a named source.
    let mut document = inline_question();
    document["subject"]["role"] = json!("first.party");
    assert_eq!(check(document), Vec::new());
    let mut document = referenced_question();
    document["subject"]["role"] = json!("first.party");
    assert_eq!(check(document), Vec::new());
}

#[test]
fn a_selector_with_a_dot_is_refused_at_the_selector() {
    let sentence = "subject selector must not contain a dot: it names a selector field in the \
                    compiled bundle";
    let mut document = inline_question();
    document["subject"]["selector"] = json!("record.key");
    assert_eq!(
        refusal(document),
        (
            "compiled-name-dot",
            "/subject/selector".to_owned(),
            sentence.to_owned()
        )
    );

    let mut document = referenced_question();
    document["subject"]["selector"] = json!("record.key");
    assert_eq!(
        refusal(document),
        (
            "compiled-name-dot",
            "/subject/selector".to_owned(),
            sentence.to_owned()
        )
    );
}

#[test]
fn a_named_profile_with_a_dot_is_refused_at_the_profile() {
    let mut document = referenced_question();
    document["subject"]["profile"] = json!("record-key.v1");
    assert_eq!(
        refusal(document),
        (
            "compiled-name-dot",
            "/subject/profile".to_owned(),
            "subject profile must not contain a dot: it names a selector profile in the \
             compiled bundle"
                .to_owned()
        )
    );
}

#[test]
fn an_alternative_profile_with_a_dot_is_refused_at_its_position() {
    let mut document = referenced_question();
    document["subject"] = json!({
        "role": "holder", "profiles": ["record-key-v1", "record-key.v2"]
    });
    assert_eq!(
        refusal(document),
        (
            "compiled-name-dot",
            "/subject/profiles/1".to_owned(),
            "subject profile must not contain a dot: it names a selector profile in the \
             compiled bundle"
                .to_owned()
        )
    );
}

#[test]
fn a_source_reference_with_a_dot_is_refused_at_the_ref() {
    let mut document = referenced_question();
    document["source"]["ref"] = json!("record.source");
    assert_eq!(
        refusal(document),
        (
            "compiled-name-dot",
            "/source/ref".to_owned(),
            "source.ref must not contain a dot: it names a source in the compiled bundle"
                .to_owned()
        )
    );
}

#[test]
fn a_question_reading_a_named_source_keeps_the_whole_identifier_length() {
    let mut document = referenced_question();
    document["id"] = json!("a".repeat(64));
    assert_eq!(check(document), Vec::new());
}

#[test]
fn the_bounds_are_the_ones_the_compiled_names_leave() {
    assert_eq!(MAX_COMPILED_NAME_BYTES, 64);
    assert_eq!(
        local_selector_profile_id(&"a".repeat(47)).len(),
        MAX_COMPILED_NAME_BYTES
    );
    assert_eq!(
        local_subject_selector_profile_id(&"a".repeat(20), &"b".repeat(26), 2).len(),
        MAX_COMPILED_NAME_BYTES
    );
    assert_eq!(
        local_subject_selector_profile_id("record-check", "holder", 1),
        local_selector_profile_id("record-check")
    );
    // The source name is shorter than either profile name, so it fits
    // whenever they do.
    assert!(
        local_source_id("record-check").len() < local_selector_profile_id("record-check").len()
    );
}

//! The generated description of the authoring form, and the one direction of
//! agreement it owes the checks beside it.
//!
//! An editor reads a JSON Schema; `evidencectl` reads Rust. Both must describe
//! the same authored document, which is why the schema is derived from the
//! model rather than written next to it. These tests hold the derived documents
//! to the properties a committed artifact needs (a stable dialect, a stable
//! identifier, byte-identical regeneration) and to the one agreement that is
//! safe to assert: a document the schema turns away is a document the checks
//! turn away too.
//!
//! The reverse is deliberately not asserted, and one test pins that. The schema
//! describes shape; the checks describe meaning. A document can be perfectly
//! shaped and still name an identifier the form does not allow, and an editor
//! that reported nothing there would be telling the truth about the schema and
//! the wrong thing about the project.

#![cfg(feature = "schema")]

use jsonschema::{Draft, JSONSchema};
use registry_evidence_authoring::{
    model::Question,
    schema::{documents, PROJECT_MARKER_SCHEMA_FILE, QUESTION_SCHEMA_FILE},
    validate::validate_question,
};
use serde_json::Value;

/// A question that satisfies both the schema and the checks, and the base every
/// rejected document below departs from in exactly one way.
const VALID_QUESTION: &str = r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
  collectionBounds: {}
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#;

/// Authored questions the schema must turn away, each with the departure it
/// makes from [`VALID_QUESTION`].
const REJECTED_QUESTIONS: &[(&str, &str)] = &[
    (
        "an unknown top-level key",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
notes: this key is not part of the form
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#,
    ),
    (
        "a missing derivation",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
answers:
  - concept: is_adult
    type: boolean
disclosure:
  allow: [is_adult]
"#,
    ),
    (
        "answers written as a single mapping instead of a list",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
answers:
  concept: is_adult
  type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#,
    ),
    (
        "a fact combination the form does not offer",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: sometimes
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#,
    ),
    (
        "an answer type the form does not offer",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
answers:
  - concept: is_adult
    type: free-text
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#,
    ),
    (
        "a disclosure that lists nothing to allow",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure: {}
"#,
    ),
    (
        "an unknown key inside a subject",
        r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
  optional: true
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#,
    ),
    (
        "a question identifier written as a number",
        r#"id: 18
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#,
    ),
];

/// The marker documents the schema must turn away.
const REJECTED_MARKERS: &[(&str, &str)] = &[
    (
        "an unknown key",
        "version: 1\nproject: evidence-authoring\nextra: true\n",
    ),
    (
        "a project kind the marker does not name",
        "version: 1\nproject: relay-authoring\n",
    ),
    ("a missing project kind", "version: 1\n"),
];

fn compile(document: &str) -> JSONSchema {
    let value: Value = serde_json::from_str(document).expect("a generated schema is JSON");
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&value)
        .expect("a generated schema compiles as 2020-12")
}

fn yaml_as_json(document: &str) -> Value {
    serde_norway::from_str(document).expect("the corpus is well-formed YAML")
}

/// Read one authored question the way adopter tooling does: parse it into the
/// closed model, then run the checks. Either step may turn the document away.
fn question_is_accepted_by_the_checks(document: &str) -> bool {
    serde_norway::from_str::<Question>(document)
        .is_ok_and(|question| validate_question(&question).is_empty())
}

#[test]
fn the_generated_set_is_exactly_the_two_documents_a_rust_type_stands_behind() {
    let documents = documents().expect("the authoring schemas generate");
    assert_eq!(
        documents.keys().copied().collect::<Vec<_>>(),
        vec![PROJECT_MARKER_SCHEMA_FILE, QUESTION_SCHEMA_FILE],
    );
}

#[test]
fn every_generated_document_declares_the_shared_dialect_and_its_own_identifier() {
    let documents = documents().expect("the authoring schemas generate");
    let mut identifiers = Vec::new();
    for (name, document) in &documents {
        let value: Value = serde_json::from_str(document).expect("a generated schema is JSON");
        assert_eq!(
            value.get("$schema").and_then(Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema"),
            "{name} does not declare the 2020-12 dialect",
        );
        let identifier = value
            .get("$id")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{name} does not declare an identifier"))
            .to_owned();
        assert!(
            value.get("title").and_then(Value::as_str).is_some(),
            "{name} does not declare a title an editor can show",
        );
        identifiers.push(identifier);
    }
    identifiers.sort();
    identifiers.dedup();
    assert_eq!(
        identifiers.len(),
        documents.len(),
        "two generated schemas share one identifier",
    );
}

#[test]
fn generation_repeats_byte_for_byte() {
    assert_eq!(
        documents().expect("the authoring schemas generate"),
        documents().expect("the authoring schemas generate again"),
    );
}

#[test]
fn every_generated_document_is_canonical_pretty_json_with_a_trailing_newline() {
    for (name, document) in documents().expect("the authoring schemas generate") {
        assert!(
            document.ends_with('\n') && !document.ends_with("\n\n"),
            "{name} does not end with exactly one newline",
        );
        let value: Value = serde_json::from_str(&document).expect("a generated schema is JSON");
        let mut rendered =
            serde_json::to_string_pretty(&value).expect("a parsed schema renders again");
        rendered.push('\n');
        assert_eq!(
            document, rendered,
            "{name} is not the canonical rendering of its own value, so it cannot be reproduced",
        );
    }
}

#[test]
fn the_question_schema_closes_its_shape_and_requires_the_authored_keys() {
    let documents = documents().expect("the authoring schemas generate");
    let value: Value = serde_json::from_str(&documents[QUESTION_SCHEMA_FILE])
        .expect("the question schema is JSON");
    assert_eq!(value.get("additionalProperties"), Some(&Value::Bool(false)));
    let required = value
        .get("required")
        .and_then(Value::as_array)
        .expect("the question schema names its required keys")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    for key in [
        "answers",
        "derivation",
        "disclosure",
        "id",
        "purpose",
        "question",
        "source",
    ] {
        assert!(
            required.contains(&key),
            "the question schema does not require {key}"
        );
    }
    for key in ["governance", "responseFormats", "subject", "subjects"] {
        assert!(
            !required.contains(&key),
            "the question schema requires {key}, which an author may omit",
        );
    }
}

#[test]
fn the_project_marker_schema_names_the_one_project_kind() {
    let documents = documents().expect("the authoring schemas generate");
    let document = &documents[PROJECT_MARKER_SCHEMA_FILE];
    assert!(
        document.contains("evidence-authoring"),
        "the marker schema does not offer the one project kind this crate names",
    );
    let value: Value = serde_json::from_str(document).expect("the marker schema is JSON");
    assert_eq!(value.get("additionalProperties"), Some(&Value::Bool(false)));
}

#[test]
fn the_base_question_satisfies_both_the_schema_and_the_checks() {
    let documents = documents().expect("the authoring schemas generate");
    let schema = compile(&documents[QUESTION_SCHEMA_FILE]);
    assert!(
        schema.is_valid(&yaml_as_json(VALID_QUESTION)),
        "the corpus base must satisfy the schema, or every rejection below proves nothing",
    );
    assert!(
        question_is_accepted_by_the_checks(VALID_QUESTION),
        "the corpus base must satisfy the checks, or every rejection below proves nothing",
    );
}

#[test]
fn a_question_the_schema_turns_away_is_turned_away_by_the_checks() {
    let documents = documents().expect("the authoring schemas generate");
    let schema = compile(&documents[QUESTION_SCHEMA_FILE]);
    for (departure, document) in REJECTED_QUESTIONS {
        assert!(
            !schema.is_valid(&yaml_as_json(document)),
            "the schema accepts {departure}, so this case tests nothing",
        );
        assert!(
            !question_is_accepted_by_the_checks(document),
            "the schema turns away {departure} but adopter tooling accepts it",
        );
    }
}

#[test]
fn a_marker_the_schema_turns_away_is_turned_away_by_the_parser() {
    let documents = documents().expect("the authoring schemas generate");
    let schema = compile(&documents[PROJECT_MARKER_SCHEMA_FILE]);
    for (departure, document) in REJECTED_MARKERS {
        assert!(
            !schema.is_valid(&yaml_as_json(document)),
            "the schema accepts {departure}, so this case tests nothing",
        );
        assert!(
            registry_evidence_authoring::parse_project_marker(document.as_bytes()).is_err(),
            "the schema turns away {departure} but the marker parser accepts it",
        );
    }
}

#[test]
fn a_question_the_schema_accepts_may_still_be_turned_away_by_the_checks() {
    let documents = documents().expect("the authoring schemas generate");
    let schema = compile(&documents[QUESTION_SCHEMA_FILE]);
    // A capitalized identifier is a string of the right type in the right
    // place, so the schema has nothing to say about it. The form does.
    let document = VALID_QUESTION.replace("id: adult-status", "id: AdultStatus");
    assert!(
        schema.is_valid(&yaml_as_json(&document)),
        "the asymmetry case must satisfy the schema, or it does not show the asymmetry",
    );
    assert!(
        !question_is_accepted_by_the_checks(&document),
        "the checks must still turn this document away; the schema is structural, not semantic",
    );
}

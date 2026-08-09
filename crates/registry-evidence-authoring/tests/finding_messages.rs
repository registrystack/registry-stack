//! Every sentence these checks produce, held to its exact text.
//!
//! The rules in this crate were adopter tooling's rules first: they lived
//! inside the local project compiler, reported through `anyhow`, and stopped at
//! the first departure they found. Moving them into a library was allowed to
//! change where they run and what a caller may do with the answer. It was not
//! allowed to change a single word an author reads, because those words are
//! quoted in tutorials, matched in tests, and pasted into issues.
//!
//! So this file is a corpus rather than a sample: one deliberately broken
//! document per rule, asserted byte for byte against the sentence that rule
//! produced before the move. A message that drifts fails here, loudly, with the
//! rule named.

use registry_evidence_authoring::{
    validate_answer, validate_authored_answer, validate_question, Finding, Question, QuestionAnswer,
};
use serde_json::{json, Map, Value};

// --- the corpus --------------------------------------------------------------

/// A question that passes every check, so that each case below differs from a
/// usable document in exactly one way.
fn base_question() -> Value {
    json!({
        "id": "record-check",
        "question": "Does the record carry the reviewed marker?",
        "purpose": "record-check",
        "subject": { "role": "holder", "selector": "record-key" },
        "source": {
            "operation": "getRecord",
            "facts": [{ "name": "marker", "path": "/marker", "combine": "exactly-one" }]
        },
        "answers": [{ "concept": "marked", "type": "boolean" }],
        "derivation": "derivations/record-check.rhai",
        "disclosure": { "allow": ["marked"] }
    })
}

/// A derivation that passes every check.
const BASE_DERIVATION: &str = "fn answer(facts, selectors, context) { #{ marked: true } }";

struct Case<T> {
    rule: &'static str,
    build: fn() -> T,
    message: &'static str,
}

fn question_cases() -> Vec<Case<Question>> {
    vec![
        Case {
            rule: "question id",
            build: || question(|document| document["id"] = json!("Record")),
            message: "question id must be a lowercase local identifier",
        },
        Case {
            rule: "question purpose",
            build: || question(|document| document["purpose"] = json!("Record")),
            message: "question purpose must be a lowercase local identifier",
        },
        Case {
            rule: "both subject forms",
            build: || {
                question(|document| {
                    document["subjects"] =
                        json!([{ "role": "other", "selector": "record-key" }]);
                })
            },
            message: "question must declare either subject or subjects, not both",
        },
        Case {
            rule: "no subject at all",
            build: || {
                question(|document| {
                    object(document).remove("subject");
                })
            },
            message: "question must declare 1..=8 subjects",
        },
        Case {
            rule: "subject identifier spelling",
            build: || question(|document| document["subject"]["role"] = json!("Holder")),
            message: "question subjects must use lowercase local role, selector, and profile identifiers",
        },
        Case {
            rule: "repeated subject role",
            build: || {
                question(|document| {
                    object(document).remove("subject");
                    document["subjects"] = json!([
                        { "role": "holder", "selector": "record-key" },
                        { "role": "holder", "selector": "other-key" },
                    ]);
                })
            },
            message: "question subject roles must be unique",
        },
        Case {
            rule: "question text",
            build: || question(|document| document["question"] = json!("")),
            message: "question text must be a non-empty bounded line of text",
        },
        Case {
            rule: "answer count",
            build: || question(|document| document["answers"] = json!([])),
            message: "answers must contain 1..=16 governed concepts",
        },
        Case {
            rule: "response formats",
            build: || question(|document| document["responseFormats"] = json!(["sd-jwt-vc"])),
            message: "responseFormats must contain signed-jws exactly once and may add sd-jwt-vc once",
        },
        Case {
            rule: "answer concept spelling",
            build: || question(|document| document["answers"][0]["concept"] = json!("Marked")),
            message: "answer concept must be a lowercase local identifier",
        },
        Case {
            rule: "repeated answer concept",
            build: || {
                question(|document| {
                    document["answers"] = json!([
                        { "concept": "marked", "type": "boolean" },
                        { "concept": "marked", "type": "boolean" },
                    ]);
                })
            },
            message: "answer concepts must be unique",
        },
        Case {
            rule: "sd-jwt-vc projection without the format",
            build: || {
                question(|document| {
                    document["answers"] = json!([structured_answer("marked", "marker")]);
                })
            },
            message: "an sdJwtVc projection requires responseFormats to include sd-jwt-vc",
        },
        Case {
            rule: "repeated sd-jwt-vc claim",
            build: || {
                question(|document| {
                    document["responseFormats"] = json!(["signed-jws", "sd-jwt-vc"]);
                    document["answers"] = json!([
                        structured_answer("marked", "marker"),
                        structured_answer("noted", "marker"),
                    ]);
                    document["disclosure"]["allow"] = json!(["marked", "noted"]);
                })
            },
            message: "sdJwtVc.claim names must be unique within a question",
        },
        Case {
            rule: "source reference carrying more than a reference",
            build: || {
                question(|document| {
                    document["source"] = json!({
                        "ref": "records",
                        "facts": [{ "name": "marker", "path": "/marker", "combine": "exactly-one" }]
                    });
                })
            },
            message: "a source reference must contain only one valid ref",
        },
        Case {
            rule: "fact count",
            build: || question(|document| document["source"]["facts"] = json!([])),
            message: "source.facts must contain 1..=16 authored fact selections",
        },
        Case {
            rule: "fact name",
            build: || question(|document| document["source"]["facts"][0]["name"] = json!("Marker")),
            message: "source fact names must be unique lowercase local identifiers",
        },
        Case {
            rule: "fact path",
            build: || question(|document| document["source"]["facts"][0]["path"] = json!("marker")),
            message: "source fact paths must be unique bounded extended JSON Pointers",
        },
        Case {
            rule: "collect over a path that visits no collection",
            build: || {
                question(|document| document["source"]["facts"][0]["combine"] = json!("collect"))
            },
            message: "source fact `marker` uses `collect` but its path visits no collection",
        },
        Case {
            rule: "one value expected from a path that visits a collection",
            build: || {
                question(|document| {
                    document["source"]["facts"][0]["path"] = json!("/records/*/marker");
                })
            },
            message:
                "source fact `marker` visits a collection and must explicitly use `combine: collect`",
        },
        Case {
            rule: "collection bounds",
            build: || {
                question(|document| document["source"]["collectionBounds"] = json!({ "/records": 0 }))
            },
            message: "source.collectionBounds must contain bounded array pointers with values in 1..=256",
        },
        Case {
            rule: "operation identifier",
            build: || question(|document| document["source"]["operation"] = json!("")),
            message: "source.operation must name one bounded OpenAPI operationId",
        },
        Case {
            rule: "neither reference nor operation",
            build: || question(|document| document["source"] = json!({})),
            message: "source must declare either ref or operation with facts",
        },
        Case {
            rule: "disclosure allowance",
            build: || question(|document| document["disclosure"]["allow"] = json!(["other"])),
            message: "disclosure.allow must contain exactly the declared answer concepts",
        },
    ]
}

fn answer_cases() -> Vec<Case<QuestionAnswer>> {
    vec![
        Case {
            rule: "boolean answer",
            build: || answer(json!({ "concept": "marked", "type": "boolean", "values": ["yes"] })),
            message: "a boolean answer must not declare values or numeric bounds",
        },
        Case {
            rule: "controlled-category numeric bounds",
            build: || {
                answer(json!({
                    "concept": "marked",
                    "type": "controlled-category",
                    "values": ["one", "two"],
                    "minimum": 1
                }))
            },
            message: "a controlled-category answer must not declare numeric bounds",
        },
        Case {
            rule: "controlled-category values",
            build: || {
                answer(json!({
                    "concept": "marked",
                    "type": "controlled-category",
                    "values": ["only"]
                }))
            },
            message: "a controlled-category answer needs 2..=32 unique bounded values",
        },
        Case {
            rule: "bounded-integer category values",
            build: || {
                answer(json!({
                    "concept": "marked",
                    "type": "bounded-integer",
                    "values": ["one"],
                    "minimum": 0,
                    "maximum": 1
                }))
            },
            message: "a bounded-integer answer must not declare category values",
        },
        Case {
            rule: "bounded-integer missing bounds",
            build: || answer(json!({ "concept": "marked", "type": "bounded-integer" })),
            message: "a bounded-integer answer requires minimum and maximum",
        },
        Case {
            rule: "bounded-integer inconsistent bounds",
            build: || {
                answer(json!({
                    "concept": "marked",
                    "type": "bounded-integer",
                    "minimum": 5,
                    "maximum": 1
                }))
            },
            message: "a bounded-integer answer needs consistent JSON-safe bounds",
        },
        Case {
            rule: "reviewed structured scalar constraints",
            build: || {
                answer(json!({
                    "concept": "marked",
                    "type": "reviewed-structured-value",
                    "schema": "schemas/marker.yaml",
                    "maximumSerializedBytes": 1024,
                    "minimum": 1
                }))
            },
            message: "a reviewed structured answer must not declare scalar constraints",
        },
        Case {
            rule: "reviewed structured missing schema",
            build: || {
                answer(json!({
                    "concept": "marked",
                    "type": "reviewed-structured-value",
                    "maximumSerializedBytes": 1024
                }))
            },
            message: "a reviewed structured answer requires schema",
        },
        Case {
            rule: "reviewed structured schema path",
            build: || {
                answer(json!({
                    "concept": "marked",
                    "type": "reviewed-structured-value",
                    "schema": "marker.yaml",
                    "maximumSerializedBytes": 1024
                }))
            },
            message: "answer schema must be one schemas/<name>.yaml file",
        },
        Case {
            rule: "reviewed structured serialized size",
            build: || {
                answer(json!({
                    "concept": "marked",
                    "type": "reviewed-structured-value",
                    "schema": "schemas/marker.yaml",
                    "maximumSerializedBytes": 0
                }))
            },
            message: "a reviewed structured answer requires maximumSerializedBytes in 1..=65536",
        },
        Case {
            rule: "reserved sd-jwt-vc claim name",
            build: || {
                answer(json!({
                    "concept": "marked",
                    "type": "reviewed-structured-value",
                    "schema": "schemas/marker.yaml",
                    "maximumSerializedBytes": 1024,
                    "sdJwtVc": { "claim": "iss", "disclosure": "top-level" }
                }))
            },
            message: "sdJwtVc.claim must be a bounded JSON claim name",
        },
    ]
}

fn derivation_cases() -> Vec<Case<&'static str>> {
    vec![
        Case {
            rule: "program that does not compile",
            build: || "fn answer(facts, selectors, context) {",
            message: "authored derivation does not compile as Rhai",
        },
        Case {
            rule: "repeated function name",
            build: || {
                "fn helper(a) { a }\n\
                 fn helper(a, b) { a + b }\n\
                 fn answer(facts, selectors, context) { #{} }"
            },
            message: "authored derivation function names must be unique",
        },
        Case {
            rule: "reserved entry point",
            build: || {
                "fn derive() { 1 }\n\
                 fn answer(facts, selectors, context) { #{} }"
            },
            message: "the `derive` entry point is reserved for the generated concept binding",
        },
        Case {
            rule: "answer signature",
            build: || "fn answer(facts, selectors) { #{} }",
            message: "authored derivation must declare answer(facts, selectors, context)",
        },
        Case {
            rule: "no answer at all",
            build: || "fn helper() { 1 }",
            message:
                "authored derivation must declare exactly one answer(facts, selectors, context)",
        },
    ]
}

// --- the assertions ----------------------------------------------------------

#[test]
fn every_question_rule_reports_its_historical_sentence() {
    for case in question_cases() {
        let findings = validate_question(&(case.build)());
        assert_case(case.rule, case.message, &findings);
    }
}

#[test]
fn every_answer_rule_reports_its_historical_sentence() {
    for case in answer_cases() {
        let findings = validate_answer(&(case.build)());
        assert_case(case.rule, case.message, &findings);
    }
}

#[test]
fn every_derivation_rule_reports_its_historical_sentence() {
    for case in derivation_cases() {
        let findings = validate_authored_answer((case.build)());
        assert_case(case.rule, case.message, &findings);
    }
}

#[test]
fn a_usable_question_and_derivation_report_nothing() {
    assert_eq!(validate_question(&question(|_| {})), Vec::new());
    assert_eq!(validate_authored_answer(BASE_DERIVATION), Vec::new());
}

/// Every rule reports under a code, and the set of codes is itself a contract:
/// a caller may group, rank, or suppress findings by code rather than by
/// matching their text. Adding a rule is expected to change this list; renaming
/// a code silently is not.
///
/// Two pairs of cases share a code on purpose. `question-identifier` covers the
/// same spelling rule applied to two fields, and `fact-combination` covers the
/// two ways one fact can disagree with its own path; the field a finding names
/// is what tells those cases apart.
#[test]
fn the_set_of_rule_codes_is_the_expected_one() {
    let mut codes = Vec::new();
    for case in question_cases() {
        codes.push(first(&validate_question(&(case.build)())).code);
    }
    for case in answer_cases() {
        codes.push(first(&validate_answer(&(case.build)())).code);
    }
    for case in derivation_cases() {
        codes.push(first(&validate_authored_answer((case.build)())).code);
    }
    assert_eq!(codes.len(), 39, "codes were: {codes:?}");
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(
        codes,
        [
            "answer-concept-identifier",
            "answer-concept-unique",
            "answer-count",
            "answer-schema-path",
            "boolean-answer",
            "bounded-integer-bounds",
            "bounded-integer-bounds-missing",
            "bounded-integer-values",
            "collection-bounds",
            "controlled-category-bounds",
            "controlled-category-values",
            "derivation-answer-count",
            "derivation-answer-signature",
            "derivation-compile",
            "derivation-function-unique",
            "derivation-reserved-entry-point",
            "disclosure-allow",
            "fact-combination",
            "fact-count",
            "fact-name",
            "fact-path",
            "operation-identifier",
            "question-identifier",
            "question-text",
            "response-formats",
            "sd-jwt-vc-claim-name",
            "sd-jwt-vc-claim-unique",
            "sd-jwt-vc-format",
            "source-declaration",
            "source-reference",
            "structured-answer-constraints",
            "structured-answer-schema",
            "structured-answer-size",
            "subject-count",
            "subject-declaration",
            "subject-identifier",
            "subject-role-unique",
        ]
    );
}

fn assert_case(rule: &str, expected: &str, findings: &[Finding]) {
    let finding = first(findings);
    assert_eq!(
        finding.message, expected,
        "the `{rule}` rule changed the sentence it reports"
    );
    assert!(
        !finding.code.is_empty(),
        "the `{rule}` rule reports no code"
    );
}

fn first(findings: &[Finding]) -> &Finding {
    assert_eq!(
        findings.len(),
        1,
        "expected exactly one finding, got: {findings:?}"
    );
    &findings[0]
}

// --- corpus helpers ----------------------------------------------------------

fn question(mutate: impl FnOnce(&mut Value)) -> Question {
    let mut document = base_question();
    mutate(&mut document);
    serde_json::from_value(document).expect("the corpus builds parseable questions")
}

fn answer(document: Value) -> QuestionAnswer {
    serde_json::from_value(document).expect("the corpus builds parseable answers")
}

fn structured_answer(concept: &str, claim: &str) -> Value {
    json!({
        "concept": concept,
        "type": "reviewed-structured-value",
        "schema": "schemas/marker.yaml",
        "maximumSerializedBytes": 1024,
        "sdJwtVc": { "claim": claim, "disclosure": "top-level" }
    })
}

fn object(document: &mut Value) -> &mut Map<String, Value> {
    document
        .as_object_mut()
        .expect("the corpus builds JSON objects")
}

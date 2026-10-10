#![no_main]

//! The project-document stage of the authoring form: the project marker, the
//! question, answer, and access-policy documents an adopter writes, their
//! validation findings, and the authored Rhai derivation source
//! (`registry-evidence-authoring`).

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use registry_evidence_authoring::{
    formats::{check_access_policy, check_question},
    parse_project_marker, question_subjects, validate_access_policy, validate_answer,
    validate_answer_fact_reads, validate_answer_schema_document, validate_authored_answer,
    validate_question, AccessPolicy, Question, QuestionAnswer,
};

fuzz_target!(|data: &[u8]| {
    let _ = parse_project_marker("evidence-project.yaml", data);
    let _ = check_question("questions/fuzz.yaml", data);
    let _ = check_access_policy("access/policies/fuzz.yaml", data);
    let Some(text) = std::str::from_utf8(data)
        .ok()
        .map(|text| text.chars().take(8192).collect::<String>())
    else {
        return;
    };
    if let Ok(question) = serde_norway::from_str::<Question>(&text) {
        let _ = validate_question(&question);
        let _ = question_subjects(&question);
    }
    if let Ok(answer) = serde_norway::from_str::<QuestionAnswer>(&text) {
        let _ = validate_answer(&answer);
    }
    if let Ok(policy) = serde_norway::from_str::<AccessPolicy>(&text) {
        let _ = validate_access_policy(&policy);
    }
    if let Ok(document) = serde_json::from_str::<serde_json::Value>(&text) {
        let _ = validate_answer_schema_document(&document);
    }
    let _ = validate_authored_answer(&text);
    let _ = validate_answer_fact_reads(&text, &BTreeSet::new());
});

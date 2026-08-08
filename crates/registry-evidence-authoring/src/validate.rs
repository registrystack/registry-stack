//! The checks an authored question must pass.
//!
//! Each check reports through [`Finding`] rather than an error type, and the
//! sentences it produces are the ones adopters have been reading: the
//! extraction of these rules into a library changed where they live, not what
//! they say. `tests/finding_messages.rs` holds every sentence to its exact
//! text.
//!
//! The checks stop at the first departure they find, so a returned vector
//! holds at most one finding today. The vector is the shape of the answer, not
//! a promise that it is short: a caller that renders findings next to fields
//! should already be written to show all of them.

use std::{
    collections::BTreeSet,
    path::{Component, Path},
};

use crate::{
    finding::{FieldPath, Finding},
    layout::{MAX_CATEGORIES, MAX_CATEGORY_BYTES, MAX_CONCEPTS, SCHEMAS_DIRECTORY},
    model::{
        AnswerType, FactCombination, Question, QuestionAnswer, QuestionResponseFormat,
        QuestionSubject,
    },
};

fn one(field: FieldPath, code: &'static str, message: impl Into<String>) -> Vec<Finding> {
    vec![Finding::new(field, code, message)]
}

/// Check one authored question against the authoring form.
#[must_use]
pub fn validate_question(question: &Question) -> Vec<Finding> {
    for (label, value) in [
        ("id", question.id.as_str()),
        ("purpose", question.purpose.as_str()),
    ] {
        if !valid_local_identifier(value) {
            return one(
                FieldPath::root().key(label),
                "question-identifier",
                format!("question {label} must be a lowercase local identifier"),
            );
        }
    }
    let subjects = match question_subjects(question) {
        Ok(subjects) => subjects,
        Err(finding) => return vec![finding],
    };
    let mut roles = BTreeSet::new();
    for (position, subject) in subjects.iter().enumerate() {
        let field = subject_path(question, position);
        if !valid_local_identifier(&subject.role)
            || !valid_local_identifier(&subject.selector)
            || subject
                .profile
                .as_deref()
                .is_some_and(|profile| !valid_local_identifier(profile))
        {
            return one(
                field,
                "subject-identifier",
                "question subjects must use lowercase local role, selector, and profile identifiers",
            );
        }
        if !roles.insert(subject.role.as_str()) {
            return one(
                field.key("role"),
                "subject-role-unique",
                "question subject roles must be unique",
            );
        }
    }
    if question.question.is_empty()
        || question.question.len() > 512
        || question.question.chars().any(char::is_control)
    {
        return one(
            FieldPath::root().key("question"),
            "question-text",
            "question text must be a non-empty bounded line of text",
        );
    }
    if !(1..=MAX_CONCEPTS).contains(&question.answers.len()) {
        return one(
            FieldPath::root().key("answers"),
            "answer-count",
            format!("answers must contain 1..={MAX_CONCEPTS} governed concepts"),
        );
    }
    let response_formats = question
        .response_formats
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if response_formats.len() != question.response_formats.len()
        || !response_formats.contains(&QuestionResponseFormat::SignedJws)
    {
        return one(
            FieldPath::root().key("responseFormats"),
            "response-formats",
            "responseFormats must contain signed-jws exactly once and may add sd-jwt-vc once",
        );
    }
    let mut concepts = BTreeSet::new();
    let mut sd_jwt_claims = BTreeSet::new();
    for (position, answer) in question.answers.iter().enumerate() {
        let field = FieldPath::root().key("answers").index(position);
        if !valid_local_identifier(&answer.concept) {
            return one(
                field.key("concept"),
                "answer-concept-identifier",
                "answer concept must be a lowercase local identifier",
            );
        }
        if !concepts.insert(answer.concept.as_str()) {
            return one(
                field.key("concept"),
                "answer-concept-unique",
                "answer concepts must be unique",
            );
        }
        let findings = validate_answer(answer);
        if !findings.is_empty() {
            return findings
                .into_iter()
                .map(|finding| finding.under(&field))
                .collect();
        }
        if let Some(projection) = &answer.sd_jwt_vc {
            if !response_formats.contains(&QuestionResponseFormat::SdJwtVc) {
                return one(
                    field.key("sdJwtVc"),
                    "sd-jwt-vc-format",
                    "an sdJwtVc projection requires responseFormats to include sd-jwt-vc",
                );
            }
            if !sd_jwt_claims.insert(projection.claim.as_str()) {
                return one(
                    field.key("sdJwtVc").key("claim"),
                    "sd-jwt-vc-claim-unique",
                    "sdJwtVc.claim names must be unique within a question",
                );
            }
        }
    }
    let source = FieldPath::root().key("source");
    match (&question.source.source_ref, &question.source.operation) {
        (Some(source_ref), None) => {
            if !valid_local_identifier(source_ref)
                || !question.source.facts.is_empty()
                || !question.source.collection_bounds.is_empty()
            {
                return one(
                    source,
                    "source-reference",
                    "a source reference must contain only one valid ref",
                );
            }
        }
        (None, Some(operation)) => {
            if question.source.facts.is_empty() || question.source.facts.len() > 16 {
                return one(
                    source.key("facts"),
                    "fact-count",
                    "source.facts must contain 1..=16 authored fact selections",
                );
            }
            let mut names = BTreeSet::new();
            let mut paths = BTreeSet::new();
            for (position, fact) in question.source.facts.iter().enumerate() {
                let field = source.clone().key("facts").index(position);
                if !valid_field_name(&fact.name) || !names.insert(fact.name.as_str()) {
                    return one(
                        field.key("name"),
                        "fact-name",
                        "source fact names must be unique lowercase local identifiers",
                    );
                }
                if fact.path.is_empty()
                    || fact.path.len() > 256
                    || !fact.path.starts_with('/')
                    || fact.path.chars().any(char::is_control)
                    || !paths.insert(fact.path.as_str())
                {
                    return one(
                        field.key("path"),
                        "fact-path",
                        "source fact paths must be unique bounded extended JSON Pointers",
                    );
                }
                let repeated = fact.path.split('/').any(|segment| segment == "*");
                match (repeated, fact.combine) {
                    (false, FactCombination::ExactlyOne) | (true, FactCombination::Collect) => {}
                    (false, FactCombination::Collect) => {
                        return one(
                            field.key("combine"),
                            "fact-combination",
                            format!(
                                "source fact `{}` uses `collect` but its path visits no collection",
                                fact.name
                            ),
                        )
                    }
                    (true, FactCombination::ExactlyOne) => {
                        return one(
                            field.key("combine"),
                            "fact-combination",
                            format!(
                                "source fact `{}` visits a collection and must explicitly use `combine: collect`",
                                fact.name
                            ),
                        )
                    }
                }
            }
            if question.source.collection_bounds.len() > 16
                || question
                    .source
                    .collection_bounds
                    .iter()
                    .any(|(pointer, maximum)| {
                        pointer.is_empty()
                            || pointer.len() > 256
                            || !pointer.starts_with('/')
                            || pointer.chars().any(char::is_control)
                            || !(1..=256).contains(maximum)
                    })
            {
                return one(
                    source.key("collectionBounds"),
                    "collection-bounds",
                    "source.collectionBounds must contain bounded array pointers with values in 1..=256",
                );
            }
            if operation.is_empty()
                || operation.len() > 256
                || operation.chars().any(char::is_control)
            {
                return one(
                    source.key("operation"),
                    "operation-identifier",
                    "source.operation must name one bounded OpenAPI operationId",
                );
            }
        }
        _ => {
            return one(
                source,
                "source-declaration",
                "source must declare either ref or operation with facts",
            )
        }
    }
    let allowed = question
        .disclosure
        .allow
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if allowed != concepts || allowed.len() != question.disclosure.allow.len() {
        return one(
            FieldPath::root().key("disclosure").key("allow"),
            "disclosure-allow",
            "disclosure.allow must contain exactly the declared answer concepts",
        );
    }
    Vec::new()
}

/// The subjects a question asks about, however it declared them.
///
/// # Errors
///
/// Returns a finding when a question declares both forms, or neither, or more
/// of them than the form allows.
pub fn question_subjects(question: &Question) -> Result<Vec<&QuestionSubject>, Finding> {
    match (&question.subject, question.subjects.as_slice()) {
        (Some(subject), []) => Ok(vec![subject]),
        (None, subjects) if (1..=8).contains(&subjects.len()) => Ok(subjects.iter().collect()),
        (Some(_), _) => Err(Finding::new(
            FieldPath::root().key("subject"),
            "subject-declaration",
            "question must declare either subject or subjects, not both",
        )),
        (None, _) => Err(Finding::new(
            FieldPath::root().key("subjects"),
            "subject-count",
            "question must declare 1..=8 subjects",
        )),
    }
}

/// Where the subject at `position` was written, which depends on which of the
/// two declaration forms the question used.
fn subject_path(question: &Question, position: usize) -> FieldPath {
    if question.subject.is_some() {
        FieldPath::root().key("subject")
    } else {
        FieldPath::root().key("subjects").index(position)
    }
}

/// Check one authored answer against the shape its type allows.
///
/// Findings are reported against the answer itself; a caller holding the
/// answer's position in a question moves them with [`Finding::under`].
#[must_use]
pub fn validate_answer(answer: &QuestionAnswer) -> Vec<Finding> {
    match answer.answer_type {
        AnswerType::Boolean => {
            if !answer.values.is_empty()
                || answer.minimum.is_some()
                || answer.maximum.is_some()
                || answer.schema.is_some()
                || answer.maximum_serialized_bytes.is_some()
                || answer.sd_jwt_vc.is_some()
            {
                return one(
                    FieldPath::root(),
                    "boolean-answer",
                    "a boolean answer must not declare values or numeric bounds",
                );
            }
        }
        AnswerType::ControlledCategory => {
            if answer.minimum.is_some()
                || answer.maximum.is_some()
                || answer.schema.is_some()
                || answer.maximum_serialized_bytes.is_some()
                || answer.sd_jwt_vc.is_some()
            {
                return one(
                    FieldPath::root(),
                    "controlled-category-bounds",
                    "a controlled-category answer must not declare numeric bounds",
                );
            }
            if !(2..=MAX_CATEGORIES).contains(&answer.values.len())
                || answer.values.iter().collect::<BTreeSet<_>>().len() != answer.values.len()
                || answer.values.iter().any(|value| {
                    value.is_empty()
                        || value.len() > MAX_CATEGORY_BYTES
                        || value.chars().any(char::is_control)
                })
            {
                return one(
                    FieldPath::root().key("values"),
                    "controlled-category-values",
                    format!(
                        "a controlled-category answer needs 2..={MAX_CATEGORIES} unique bounded values"
                    ),
                );
            }
        }
        AnswerType::BoundedInteger => {
            if !answer.values.is_empty()
                || answer.schema.is_some()
                || answer.maximum_serialized_bytes.is_some()
                || answer.sd_jwt_vc.is_some()
            {
                return one(
                    FieldPath::root(),
                    "bounded-integer-values",
                    "a bounded-integer answer must not declare category values",
                );
            }
            let (Some(minimum), Some(maximum)) = (answer.minimum, answer.maximum) else {
                return one(
                    FieldPath::root(),
                    "bounded-integer-bounds-missing",
                    "a bounded-integer answer requires minimum and maximum",
                );
            };
            const JSON_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
            if !(-JSON_SAFE_INTEGER..=JSON_SAFE_INTEGER).contains(&minimum)
                || !(-JSON_SAFE_INTEGER..=JSON_SAFE_INTEGER).contains(&maximum)
                || minimum > maximum
            {
                return one(
                    FieldPath::root(),
                    "bounded-integer-bounds",
                    "a bounded-integer answer needs consistent JSON-safe bounds",
                );
            }
        }
        AnswerType::ReviewedStructuredValue => {
            if !answer.values.is_empty() || answer.minimum.is_some() || answer.maximum.is_some() {
                return one(
                    FieldPath::root(),
                    "structured-answer-constraints",
                    "a reviewed structured answer must not declare scalar constraints",
                );
            }
            let Some(schema) = answer.schema.as_deref() else {
                return one(
                    FieldPath::root().key("schema"),
                    "structured-answer-schema",
                    "a reviewed structured answer requires schema",
                );
            };
            let findings = validate_answer_schema_path(schema);
            if !findings.is_empty() {
                return findings;
            }
            if !matches!(answer.maximum_serialized_bytes, Some(1..=65_536)) {
                return one(
                    FieldPath::root().key("maximumSerializedBytes"),
                    "structured-answer-size",
                    "a reviewed structured answer requires maximumSerializedBytes in 1..=65536",
                );
            }
            if let Some(projection) = &answer.sd_jwt_vc {
                let findings = validate_sd_jwt_claim_name(&projection.claim);
                if !findings.is_empty() {
                    return findings;
                }
            }
        }
    }
    Vec::new()
}

/// Check that a structured answer names a schema the project can hold.
#[must_use]
pub fn validate_answer_schema_path(value: &str) -> Vec<Finding> {
    let path = Path::new(value);
    let components = path.components().collect::<Vec<_>>();
    if components.len() != 2
        || components.first() != Some(&Component::Normal(SCHEMAS_DIRECTORY.as_ref()))
        || !matches!(components.get(1), Some(Component::Normal(_)))
        || path.extension().and_then(|extension| extension.to_str()) != Some("yaml")
    {
        return one(
            FieldPath::root().key("schema"),
            "answer-schema-path",
            "answer schema must be one schemas/<name>.yaml file",
        );
    }
    Vec::new()
}

/// Check that a projected claim name is usable and does not take a name the
/// response format has already given a meaning.
#[must_use]
pub fn validate_sd_jwt_claim_name(value: &str) -> Vec<Finding> {
    const RESERVED: [&str; 24] = [
        "iss",
        "sub",
        "aud",
        "iat",
        "nbf",
        "exp",
        "vct",
        "id",
        "jti",
        "_sd",
        "_sd_alg",
        "cnf",
        "status",
        "issuedBy",
        "providedBy",
        "supportsRequirement",
        "purpose",
        "audience",
        "assuranceProfile",
        "observedAt",
        "configurationRevision",
        "requestNonce",
        "subjects",
        "structuredValues",
    ];
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !matches!(bytes.first(), Some(b'A'..=b'Z' | b'a'..=b'z'))
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        || RESERVED.contains(&value)
    {
        return one(
            FieldPath::root().key("sdJwtVc").key("claim"),
            "sd-jwt-vc-claim-name",
            "sdJwtVc.claim must be a bounded JSON claim name",
        );
    }
    Vec::new()
}

/// Whether a value is a lowercase local identifier: the one spelling the
/// authoring form accepts wherever an author names something.
#[must_use]
pub fn valid_local_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= 64
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// Whether a value may name a projected fact.
#[must_use]
pub fn valid_field_name(value: &str) -> bool {
    valid_local_identifier(value)
}

/// The collections one fact path visits, as the pointers that name them.
///
/// A fact path walks into arrays by writing `*` for the element, so
/// `/records/*/date_of_birth` visits the collection at `/records`, and each `*`
/// contributes the pointer that stands before it: a path with two of them names
/// the outer collection and the inner one, in that order. Those pointers are
/// what an author bounds under `source.collectionBounds`, and reading a path for
/// them is a rule of the authoring form rather than a step of any one caller's
/// algorithm, which is why it is written here once. A path visiting no
/// collection names none.
#[must_use]
pub fn collection_pointers(path: &str) -> Vec<String> {
    let mut walked = Vec::new();
    let mut collections = Vec::new();
    for segment in path.split('/').skip(1) {
        if segment == "*" {
            collections.push(format!("/{}", walked.join("/")));
        }
        walked.push(segment);
    }
    collections
}

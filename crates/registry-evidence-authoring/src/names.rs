//! The names a compiled bundle carries for what a question declares.
//!
//! A question that reads an operation of the project's own OpenAPI
//! description names no selector profile and no source: the compiler names
//! them after the question. Those names are written here once, so the checks
//! in [`crate::validate`] measure the very name the compiler writes.

/// The longest name a compiled bundle accepts for a selector profile, a
/// selector field, or a source, in bytes.
pub const MAX_COMPILED_NAME_BYTES: usize = 64;

/// The selector profile compiled for the one subject of a question that reads
/// an OpenAPI operation.
#[must_use]
pub fn local_selector_profile_id(question_id: &str) -> String {
    format!("local-subject-{question_id}-v1")
}

/// The selector profile compiled for one subject of a question that reads an
/// OpenAPI operation: named after the question alone when it has one subject,
/// and after the question and the subject's role when it has several.
#[must_use]
pub fn local_subject_selector_profile_id(
    question_id: &str,
    role: &str,
    subject_count: usize,
) -> String {
    if subject_count == 1 {
        local_selector_profile_id(question_id)
    } else {
        format!("local-subject-{question_id}-{role}-v1")
    }
}

/// The source compiled for a question that reads an OpenAPI operation.
#[must_use]
pub fn local_source_id(question_id: &str) -> String {
    format!("local-source-{question_id}")
}

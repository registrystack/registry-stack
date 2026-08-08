//! The shape of an authoring project on disk, and the ceilings its parts are
//! held to.
//!
//! These names and limits are the vocabulary of the authoring form, not a
//! description of any one project: a tool that reads a project and a tool that
//! offers completions inside one need the same answer to "what is this
//! directory called" and "how large may this file be". Opening any of it stays
//! with the caller.

/// The single OpenAPI description a project draws its operations from.
pub const OPENAPI_FILE: &str = "source.openapi.yaml";
/// Authored questions, one YAML document each.
pub const QUESTIONS_DIRECTORY: &str = "questions";
/// Source definitions a question may name instead of an inline operation.
pub const SOURCES_DIRECTORY: &str = "sources";
/// Selector definitions.
pub const SELECTORS_DIRECTORY: &str = "selectors";
/// Authored derivation programs, one Rhai file each.
pub const DERIVATIONS_DIRECTORY: &str = "derivations";
/// Schemas a structured answer may name.
pub const SCHEMAS_DIRECTORY: &str = "schemas";
/// Recorded request and response pairs a project is replayed against.
pub const FIXTURES_DIRECTORY: &str = "fixtures";
/// Key material a project needs to run locally.
pub const SECRETS_DIRECTORY: &str = "secrets";
/// Caller access material.
pub const ACCESS_DIRECTORY: &str = "access";
/// Access policy documents, below [`ACCESS_DIRECTORY`].
pub const ACCESS_POLICIES_DIRECTORY: &str = "policies";

/// The largest OpenAPI description a project may carry.
pub const MAX_OPENAPI_BYTES: u64 = 16 * 1024 * 1024;
/// The largest authored question document.
pub const MAX_QUESTION_BYTES: u64 = 64 * 1024;
/// The largest authored access policy document.
pub const MAX_ACCESS_POLICY_BYTES: u64 = 64 * 1024;
/// The largest authored derivation program.
pub const MAX_DERIVATION_BYTES: u64 = 64 * 1024;
/// The largest selector, source, or schema document.
pub const MAX_SOURCE_ARTIFACT_BYTES: u64 = 1024 * 1024;
/// The most questions one project may declare.
pub const MAX_QUESTIONS: usize = 128;
/// The most governed concepts one question may answer.
pub const MAX_CONCEPTS: usize = 16;
/// The most categories a controlled-category answer may offer.
pub const MAX_CATEGORIES: usize = 32;
/// The largest single controlled-category value.
pub const MAX_CATEGORY_BYTES: usize = 64;

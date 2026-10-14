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
/// Schemas a reviewed structured Output may name.
pub const SCHEMAS_DIRECTORY: &str = "schemas";
/// Recorded request and response pairs a project is replayed against.
pub const FIXTURES_DIRECTORY: &str = "fixtures";
/// Key material a project needs to run locally.
pub const SECRETS_DIRECTORY: &str = ".generated/secrets";
/// Caller access material.
pub const ACCESS_DIRECTORY: &str = "access";

/// The largest OpenAPI description a project may carry.
pub const MAX_OPENAPI_BYTES: u64 = 16 * 1024 * 1024;
/// The largest authored derivation program.
pub const MAX_DERIVATION_BYTES: u64 = 64 * 1024;
/// The largest selector, source, or schema document.
pub const MAX_SOURCE_ARTIFACT_BYTES: u64 = 1024 * 1024;

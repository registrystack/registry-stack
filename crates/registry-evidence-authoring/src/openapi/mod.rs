//! Reading an OpenAPI document as an authoring input.
//!
//! An adopter does not write a response schema by hand: they point at an
//! operation in a description they already publish, and the tooling works out
//! what that operation can be asked for. That reading is four stages, each a
//! module here: [`types`] is the vocabulary they pass between them, [`openapi`]
//! resolves one operation's response schema, [`flatten`] turns that schema into
//! the leaves an author may select, and [`narrow`] restricts a selection to the
//! closed response subset the runtime admits.
//!
//! Every stage is a pure function over values. The document arrives as text a
//! caller has already read, from a file, a URL, or an editor buffer that was
//! never saved, which is what lets the same reading serve a command line and a
//! language server.

use anyhow::Result;

pub mod flatten;
pub mod narrow;
#[allow(clippy::module_inception)]
pub mod openapi;
pub mod types;

use openapi::Spec;
use types::{CandidateLeaf, OperationKey, ResolvedResponse};

pub const JSON_RESPONSE_MEDIA_TYPES: [&str; 2] = ["application/json", "application/fhir+json"];

/// Resolve the preferred JSON representation Evidence authoring supports.
/// Generic JSON remains first for existing APIs; FHIR JSON is the one
/// registered structured-syntax representation admitted in addition.
pub fn json_response_schema(
    spec: &Spec,
    operation: &OperationKey,
) -> Result<(&'static str, ResolvedResponse)> {
    spec.response_schema_for_media_types(operation, "200", &JSON_RESPONSE_MEDIA_TYPES)
}

/// The leaves of `operation`'s success response that an author may select.
///
/// One operation has many responses, and an Evidence source reads exactly one
/// of them: the `200 application/json` or `application/fhir+json` body. Naming that pair in one place
/// keeps the drafting pipeline and the authoring checks offering the same set,
/// because a check that offered a different set from the one the draft was
/// built against would reject documents this tooling itself wrote.
///
/// The flattening warnings are dropped: a caller asking what may be selected is
/// asking for the set, and the parts of the schema that could not be flattened
/// are absent from it, which is the answer. A caller that wants the reasons
/// calls [`flatten::candidate_leaves`] directly.
pub fn selectable_leaves(spec: &Spec, operation: &OperationKey) -> Result<Vec<CandidateLeaf>> {
    let (_, resolved) = json_response_schema(spec, operation)?;
    let (leaves, _) = flatten::candidate_leaves(&resolved.schema);
    Ok(leaves)
}

// SPDX-License-Identifier: Apache-2.0
//! Closed, platform-owned JSON decoding for registry-data responses.
//!
//! The decoder consumes opaque destination data, validates the complete JSON
//! value, and releases only declared bounded scalar projections.
//!
//! Successful parse-tree strings and raw body bytes have zeroizing owners.
//! Rejected parses can create temporary allocations inside parser dependencies;
//! this crate cannot guarantee erasure of those internal copies. A decoder-owned
//! encoded-body ceiling and allocation-free structural preflight bound those
//! failure-path allocations before the parser runs.

mod contract;
mod decode;
mod preflight;
mod script_response;
mod typed_envelope;

/// Maximum encoded bytes accepted by the closed JSON decoder.
/// Code-owned ceiling shared with Relay's v1 reviewed source-response bound.
pub const MAX_CLOSED_JSON_ENCODED_BODY_BYTES: usize = 8 * 1_024 * 1_024;

pub use contract::{
    ClosedJsonDecoder, ClosedJsonDecoderBuildError, ClosedJsonField, ClosedJsonPresenceProjection,
    ClosedJsonRecordRoot, ClosedJsonScalarProjection, ClosedJsonSchema,
    MAX_CLOSED_JSON_ARRAY_ITEMS, MAX_CLOSED_JSON_EXPANDED_NODES, MAX_CLOSED_JSON_NAME_BYTES,
    MAX_CLOSED_JSON_OBJECT_FIELDS, MAX_CLOSED_JSON_PROJECTIONS, MAX_CLOSED_JSON_SCHEMA_DEPTH,
    MAX_CLOSED_JSON_SCHEMA_NODES, MAX_CLOSED_JSON_STRING_BYTES,
};
pub use decode::{
    ClosedJsonDecodeError, ClosedJsonOutcome, ProjectedJsonField, ProjectedJsonRecord,
    ProjectedJsonScalar,
};
pub use script_response::{
    decode_script_json, decode_script_text, ScriptJsonResponse, ScriptResponseDecodeError,
    ScriptTextResponse, MAX_SCRIPT_JSON_ARRAY_ITEMS, MAX_SCRIPT_JSON_DEPTH, MAX_SCRIPT_JSON_NODES,
    MAX_SCRIPT_JSON_OBJECT_MEMBERS, MAX_SCRIPT_JSON_STRING_BYTES,
};
pub use typed_envelope::{
    decode_typed_hash_envelope, decode_typed_hash_envelope_as, DecodedTypedHashEnvelope,
    TypedHashEnvelope, TypedHashEnvelopeError,
};

#[cfg(test)]
mod tests;

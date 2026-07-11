// SPDX-License-Identifier: Apache-2.0
//! Closed, platform-owned JSON decoding for registry-data responses.
//!
//! The decoder consumes opaque destination data, validates the complete JSON
//! value, and releases only declared bounded scalar projections.
//!
//! Successful parse-tree strings and raw body bytes have zeroizing owners.
//! Rejected parses can create temporary allocations inside parser dependencies;
//! this crate cannot guarantee erasure of those internal copies.

mod contract;
mod decode;

pub use contract::{
    ClosedJsonDecoder, ClosedJsonDecoderBuildError, ClosedJsonField, ClosedJsonRecordRoot,
    ClosedJsonScalarProjection, ClosedJsonSchema, MAX_CLOSED_JSON_ARRAY_ITEMS,
    MAX_CLOSED_JSON_EXPANDED_NODES, MAX_CLOSED_JSON_NAME_BYTES, MAX_CLOSED_JSON_OBJECT_FIELDS,
    MAX_CLOSED_JSON_PROJECTIONS, MAX_CLOSED_JSON_SCHEMA_DEPTH, MAX_CLOSED_JSON_SCHEMA_NODES,
    MAX_CLOSED_JSON_STRING_BYTES,
};
pub use decode::{
    ClosedJsonDecodeError, ClosedJsonOutcome, ProjectedJsonField, ProjectedJsonRecord,
    ProjectedJsonScalar,
};

#[cfg(test)]
mod tests;

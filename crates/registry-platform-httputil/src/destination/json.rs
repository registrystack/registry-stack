// SPDX-License-Identifier: Apache-2.0
//! Strict, bounded JSON decoding for script-visible registry-data responses.
//!
//! The decoder consumes opaque destination data, validates the complete JSON
//! value, and releases it only within code-owned structural limits.
//!
//! Raw body bytes have zeroizing owners. Rejected parses can create temporary
//! allocations inside parser dependencies; this crate cannot guarantee erasure
//! of those internal copies. A decoder-owned encoded-body ceiling and
//! allocation-free structural preflight bound those failure-path allocations
//! before the parser runs.

mod preflight;
mod script_response;

/// Maximum encoded bytes accepted by the JSON decoder.
/// Code-owned ceiling for bounded source responses.
pub const MAX_CLOSED_JSON_ENCODED_BODY_BYTES: usize = 8 * 1_024 * 1_024;

pub use script_response::{
    decode_script_json, ScriptJsonResponse, ScriptResponseDecodeError, MAX_SCRIPT_JSON_ARRAY_ITEMS,
    MAX_SCRIPT_JSON_DEPTH, MAX_SCRIPT_JSON_NODES, MAX_SCRIPT_JSON_OBJECT_MEMBERS,
    MAX_SCRIPT_JSON_STRING_BYTES,
};
#[cfg(test)]
mod tests;

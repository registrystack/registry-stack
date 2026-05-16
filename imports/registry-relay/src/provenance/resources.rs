// SPDX-License-Identifier: Apache-2.0
//! In-tree resource bytes (JSON Schemas, JSON-LD contexts).
//!
//! The unauthenticated `/contexts/...` and `/schemas/...` routes serve
//! these byte slices verbatim. Including them via `include_bytes!`
//! gives us:
//!
//! - One-step cryptographic stability: a tampered file would change
//!   the compiled binary, and the manifest test in
//!   `tests/resources_manifest.rs` re-hashes both the on-disk file and
//!   the compiled bytes to assert sha256 equality with the pinned
//!   value in `resources/MANIFEST.toml`.
//! - No filesystem dependency at runtime: the same binary serves the
//!   same bytes irrespective of working directory or container layout.
//!
//! Resource version slugs are tied to the URL path the gateway exposes.
//! Adding a v2 of any resource means adding a new constant and a new
//! lookup arm; the old version is never replaced or mutated.

/// JSON-LD 1.1 context for the data_gate provenance vocabulary (v1).
/// Mounted at `<context_base_url>/provenance/v1.jsonld`.
pub const PROVENANCE_CONTEXT_V1: &[u8] =
    include_bytes!("../../resources/jsonld/provenance/v1/context.jsonld");

/// Vendored W3C VC 2.0 context. Mounted at `<context_base_url>/credentials/v2`.
/// The vendored copy keeps verifiers working when the upstream W3C
/// host is unreachable; it is hash-pinned in `resources/MANIFEST.toml`.
pub const VC_V2_CONTEXT: &[u8] = include_bytes!("../../resources/jsonld/vc/v2/credentials.jsonld");

/// `VerifyResult` v1 JSON Schema (draft 2020-12).
pub const VERIFY_RESULT_V1: &[u8] = include_bytes!("../../resources/schemas/verify-result/v1.json");

/// `AggregateResult` v1 JSON Schema (draft 2020-12).
pub const AGGREGATE_RESULT_V1: &[u8] =
    include_bytes!("../../resources/schemas/aggregate-result/v1.json");

/// `EntityRecord` v1 JSON Schema (draft 2020-12).
pub const ENTITY_RECORD_V1: &[u8] = include_bytes!("../../resources/schemas/entity-record/v1.json");

/// Look up a JSON Schema by `<type>/<version>`. Returns `None` when no
/// schema is registered. The route handler maps `None` to
/// [`crate::error::ProvenanceError::UnknownResource`].
#[must_use]
pub fn lookup_schema(claim_type: &str, version: &str) -> Option<&'static [u8]> {
    match (claim_type, version) {
        ("verify-result", "v1.json") => Some(VERIFY_RESULT_V1),
        ("aggregate-result", "v1.json") => Some(AGGREGATE_RESULT_V1),
        ("entity-record", "v1.json") => Some(ENTITY_RECORD_V1),
        _ => None,
    }
}

/// Look up a JSON-LD context by `<vocab>/<version>`. Returns `None`
/// when no context is registered.
#[must_use]
pub fn lookup_context(vocab: &str, version: &str) -> Option<&'static [u8]> {
    match (vocab, version) {
        ("provenance", "v1.jsonld") => Some(PROVENANCE_CONTEXT_V1),
        ("credentials", "v2") => Some(VC_V2_CONTEXT),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_resource_is_non_empty() {
        assert!(!PROVENANCE_CONTEXT_V1.is_empty());
        assert!(!VC_V2_CONTEXT.is_empty());
        assert!(!VERIFY_RESULT_V1.is_empty());
        assert!(!AGGREGATE_RESULT_V1.is_empty());
        assert!(!ENTITY_RECORD_V1.is_empty());
    }

    #[test]
    fn lookup_schema_returns_some_for_known_types() {
        assert!(lookup_schema("verify-result", "v1.json").is_some());
        assert!(lookup_schema("aggregate-result", "v1.json").is_some());
        assert!(lookup_schema("entity-record", "v1.json").is_some());
        assert!(lookup_schema("verify-result", "v2.json").is_none());
        assert!(lookup_schema("unknown", "v1.json").is_none());
    }

    #[test]
    fn lookup_context_returns_some_for_known_vocabs() {
        assert!(lookup_context("provenance", "v1.jsonld").is_some());
        assert!(lookup_context("credentials", "v2").is_some());
        assert!(lookup_context("provenance", "v2.jsonld").is_none());
    }
}

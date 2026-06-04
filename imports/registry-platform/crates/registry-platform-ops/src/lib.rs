//! Public operations contract assets shared by Registry runtimes.
//!
//! The crate intentionally exposes static JSON assets instead of endpoint
//! implementations. Relay and Notary own route wiring, authorization, and local
//! posture collection.

pub const POSTURE_SCHEMA_V1: &str = include_str!("../schemas/registry.ops.posture.v1.schema.json");

pub const RELAY_POSTURE_EXAMPLE_V1: &str =
    include_str!("../examples/registry-relay.posture.valid.json");

pub const NOTARY_POSTURE_EXAMPLE_V1: &str =
    include_str!("../examples/registry-notary.posture.valid.json");

pub const DEFAULT_POSTURE_ALLOWLIST_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/default-allowlist.json");

pub const REDACTION_INPUT_SENSITIVE_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/redaction-input-sensitive.json");

pub const DEFAULT_REDACTED_POSTURE_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/default-redacted.posture.valid.json");

pub const RESTRICTED_POSTURE_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/restricted-posture.valid.json");

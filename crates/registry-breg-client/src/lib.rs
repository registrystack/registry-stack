//! Canonical bounded client for Base Registry Engine.
//!
//! One method performs one explicitly initiated exchange. The client does not
//! follow redirects, use an ambient proxy, fetch linked resources, or advance
//! a collection on its own.
//!
//! The client never generates an idempotency key. An idempotency-keyed
//! mutation whose outcome is unknown (a timeout or broken exchange after the
//! request was sent, or a 5xx answer) is resent, byte for byte and under the
//! same key and credential, at most
//! `BaseRegistryClientConfig::with_max_mutation_retries` times (2 by default,
//! 0 disables it). Reads and unkeyed exchanges, such as ingestion runs and
//! action target conditions, are never resent. A 5xx answer may follow a
//! commit: when `BaseRegistryClientError::is_outcome_unknown` is still true,
//! the safe recovery is the same request under the same key, never a new key.

mod actions;
mod attachment;
mod batch;
mod client;
mod config;
mod error;
mod extended_mutation;
mod geojson;
mod ingestion;
mod lifecycle;
mod metadata;
mod mutation;
mod query;
mod read;
mod recovery;
mod response;
mod statistics;
mod strict_json;
mod transport;
mod webhook;

pub use actions::*;
pub use attachment::*;
pub use batch::*;
pub use client::BaseRegistryClient;
pub use config::BaseRegistryClientConfig;
pub use error::{
    BRegPlanRefusal, BRegProblemCode, BRegProblemFieldPath, BRegProtocolFailure, BRegRefusalCode,
    BaseRegistryClientError, TransportKind,
};
pub use geojson::*;
pub use ingestion::*;
pub use lifecycle::*;
pub use metadata::*;
pub use mutation::*;
pub use query::*;
pub use read::*;
pub use recovery::{BRegPreparedCreate, BRegPreparedLifecycle};
pub use registry_platform_httputil::client::{
    BearerToken, PrivateKeyJwt, PrivateKeyJwtConfig, StaticToken, TokenError, TokenProvider,
    MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES,
};
pub use registry_record::{
    RegistryRecord, RegistryRecordCollectionResponse, RegistryRecordDecodeError,
    RegistryRecordJsonLdContext, RegistryRecordMeta, RegistryRecordPageInfo,
    RegistryRecordRepresentation, RegistryRecordResponse, RegistryRecordSingleResponse,
    REGISTRY_RECORD_CONTEXT_IDENTIFIER, REGISTRY_RECORD_PROFILE_IDENTIFIER,
    REGISTRY_RECORD_SCHEMA_IDENTIFIER,
};
pub use response::*;
pub use statistics::*;
pub use uuid::Uuid;
pub use webhook::*;

pub const DEFAULT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
pub const DEFAULT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// Invalid, duplicate-containing, overlarge, or numerically lossy JSON input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("JSON value is invalid or cannot be represented exactly")]
pub struct BRegExactJsonError;

/// Decode bounded JSON without duplicate members or silently rounded literals.
/// Mutation builders additionally enforce BReg's supported binary64 integer model.
pub fn decode_exact_json(bytes: &[u8]) -> Result<serde_json::Value, BRegExactJsonError> {
    if bytes.len() > DEFAULT_MAX_RESPONSE_BYTES as usize {
        return Err(BRegExactJsonError);
    }
    strict_json::from_slice(bytes).map_err(|()| BRegExactJsonError)
}

//! Canonical bounded client for Registry Relay V2.
//!
//! One method performs one exchange. The crate never follows redirects, uses an
//! ambient proxy, retries, fetches linked resources, or advances a collection
//! on its own. Product-specific routes, queries, Problems, entity tags, and
//! credential policies remain Relay-owned.

mod client;
mod config;
mod error;
mod model;
mod query;
mod response;
mod transport;

pub use client::RelayClient;
pub use config::{
    RelayClientConfig, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_REQUEST_TIMEOUT,
};
pub use error::{ProtocolFailure, RelayClientError, TransportKind};
pub use model::*;
pub use query::*;
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
pub use registry_relay_http_contract::ProblemCode;
pub use response::*;

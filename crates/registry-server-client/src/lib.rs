//! Canonical bounded client for Registry Server.
//!
//! One method performs one explicitly initiated exchange. The client does not
//! follow redirects, use an ambient proxy, retry, fetch linked resources, or
//! advance a collection on its own.

mod client;
mod config;
mod error;
mod lifecycle;
mod metadata;
mod mutation;
mod query;
mod response;
mod strict_json;
mod transport;

pub use client::RegistryServerClient;
pub use config::RegistryServerClientConfig;
pub use error::{
    RegistryServerClientError, RegistryServerPlanRefusal, RegistryServerProblemCode,
    RegistryServerProtocolFailure, TransportKind,
};
pub use lifecycle::*;
pub use metadata::*;
pub use mutation::*;
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
pub use response::*;

pub const DEFAULT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
pub const DEFAULT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

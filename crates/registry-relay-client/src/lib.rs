//! Canonical, bounded client for the fixed Registry Relay V2 HTTP surface.
//!
//! One method performs one exchange. The crate never follows redirects, uses an
//! ambient proxy, retries, fetches schemas, or advances a collection on its own.

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
pub use registry_relay_http_contract::ProblemCode;
pub use response::*;

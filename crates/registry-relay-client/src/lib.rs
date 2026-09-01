//! Canonical, bounded clients for Registry Relay V2 and Registry Server reads.
//!
//! One method performs one exchange. The crate never follows redirects, uses an
//! ambient proxy, retries, fetches linked resources, or advances a collection
//! on its own. Product-specific routes, queries, Problems, entity tags, and
//! credential policies remain separate.

mod client;
mod config;
mod error;
mod model;
mod query;
mod registry_record;
mod response;
mod server;
mod server_config;
mod server_error;
mod server_query;
mod server_response;
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
pub use registry_record::*;
pub use registry_relay_http_contract::ProblemCode;
pub use response::*;
pub use server::RegistryServerClient;
pub use server_config::RegistryServerClientConfig;
pub use server_error::{
    RegistryServerClientError, RegistryServerProblemCode, RegistryServerProtocolFailure,
};
pub use server_query::*;
pub use server_response::*;

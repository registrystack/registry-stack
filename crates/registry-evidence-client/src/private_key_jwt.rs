//! Compatibility re-exports for the product-neutral private-key-JWT provider.

pub use registry_platform_httputil::{
    PrivateKeyJwt, PrivateKeyJwtConfig, DEFAULT_ASSERTION_LIFETIME_SECONDS,
    DEFAULT_REFRESH_MARGIN_SECONDS, MAXIMUM_ASSERTION_LIFETIME_SECONDS,
    MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS,
};

//! Product-neutral primitives for outbound service clients.

use std::{fmt, ops::Deref, time::Duration};

use thiserror::Error;
use url::Url;

pub use crate::{MAXIMUM_TRUSTED_ROOT_CERTIFICATES, MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES};

mod outbound;
mod private_key_jwt;
mod token;

pub use outbound::{
    base_url_without_userinfo, build_client, read_failure_kind, send_failure_kind,
    transport_protects_the_credential, OutboundOptions,
};
pub use private_key_jwt::{
    PrivateKeyJwt, PrivateKeyJwtConfig, DEFAULT_ASSERTION_LIFETIME_SECONDS,
    DEFAULT_REFRESH_MARGIN_SECONDS, MAXIMUM_ASSERTION_LIFETIME_SECONDS,
    MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS, MAXIMUM_TOKEN_RESPONSE_BYTES,
};
pub use token::{BearerToken, OAuthErrorCode, StaticToken, TokenError, TokenProvider};

/// Default total request timeout for credential-bearing service clients.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default connection timeout for credential-bearing service clients.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Coarse, value-free reason an HTTP exchange did not complete.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportKind {
    #[error("connection setup failed")]
    Connect,
    #[error("the configured timeout elapsed")]
    Timeout,
    #[error("the exchange failed")]
    Exchange,
    #[error("the response body exceeded the configured maximum")]
    ResponseTooLarge,
}

impl TransportKind {
    /// Stable machine-readable classification.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Timeout => "timeout",
            Self::Exchange => "exchange",
            Self::ResponseTooLarge => "response_too_large",
        }
    }
}

/// A service base URL validated for sending credentials.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceBaseUrl(Url);

impl ServiceBaseUrl {
    /// Validate a URL once, before any credential-bearing request can be built.
    pub fn new(url: Url) -> Result<Self, ServiceBaseUrlError> {
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ServiceBaseUrlError::AuthorityOrSuffix);
        }
        if !transport_protects_the_credential(&url) {
            return Err(ServiceBaseUrlError::UnprotectedTransport);
        }
        if let Some(mut segments) = url.path_segments().map(Iterator::peekable) {
            while let Some(segment) = segments.next() {
                if segment.is_empty() && segments.peek().is_some() {
                    return Err(ServiceBaseUrlError::EmptyPathSegment);
                }
            }
        }
        Ok(Self(url))
    }

    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.0
    }

    #[must_use]
    pub fn into_url(self) -> Url {
        self.0
    }

    /// Join a relative service path to the validated deployment prefix.
    pub fn join(&self, path: &str) -> Result<Url, ServiceBaseUrlJoinError> {
        if path.is_empty()
            || path.starts_with('/')
            || path.contains(['?', '#'])
            || path
                .split('/')
                .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
        {
            return Err(ServiceBaseUrlJoinError);
        }
        let mut base = self.0.clone();
        let mut segments = base
            .path_segments_mut()
            .map_err(|_| ServiceBaseUrlJoinError)?;
        segments.pop_if_empty();
        for segment in path.split('/') {
            segments.push(segment);
        }
        drop(segments);
        Ok(base)
    }
}

impl Deref for ServiceBaseUrl {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for ServiceBaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ServiceBaseUrl")
            .field(&base_url_without_userinfo(&self.0))
            .finish()
    }
}

/// Fixed, value-free reason a service base URL is unusable.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceBaseUrlError {
    #[error("the service base URL must carry no credentials, query, or fragment")]
    AuthorityOrSuffix,
    #[error("the service base URL must use HTTPS, or HTTP with a loopback host")]
    UnprotectedTransport,
    #[error(
        "the service base URL path must carry no empty segment other than a trailing separator"
    )]
    EmptyPathSegment,
}

/// Value-free reason a relative service path cannot be appended safely.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("the service path must be non-empty relative segments without query or fragment")]
pub struct ServiceBaseUrlJoinError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_base_urls_preserve_prefixes_and_refuse_credential_leaks() {
        let base = ServiceBaseUrl::new(Url::parse("https://registry.example/prefix").unwrap())
            .expect("the HTTPS base URL is accepted");
        assert_eq!(
            base.join("v1/records").unwrap().as_str(),
            "https://registry.example/prefix/v1/records"
        );
        for path in ["", "/v1/records", "../records", "v1//records", "v1?secret"] {
            assert!(base.join(path).is_err(), "{path}");
        }
        for candidate in [
            "http://registry.example/",
            "https://secret@registry.example/",
            "https://registry.example/?secret=value",
            "https://registry.example/a//b",
        ] {
            let error = ServiceBaseUrl::new(Url::parse(candidate).unwrap())
                .expect_err("the unsafe base URL is refused");
            assert!(!error.to_string().contains("secret"));
            assert!(!format!("{error:?}").contains("secret"));
        }
    }
}

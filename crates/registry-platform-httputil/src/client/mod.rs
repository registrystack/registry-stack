//! Product-neutral primitives for outbound service clients.

use std::{fmt, ops::Deref, time::Duration};

use thiserror::Error;
use url::Url;

pub use crate::{MAXIMUM_TRUSTED_ROOT_CERTIFICATES, MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES};

mod exchange_authorization;
mod exchange_config;
mod outbound;
mod private_key_jwt;
mod retry;
mod token;

pub use exchange_authorization::{
    ExchangeAssertionSource, ExchangeAuthorization, ExchangeContext, FirstPartyAssertionSource,
    RemoteAssertionSource, SignedExchangeAssertion, UpstreamSubjectToken,
};
pub use exchange_config::exchange_authorization_from_json;
pub use outbound::{
    base_url_without_userinfo, build_client, is_loopback_host, read_failure_kind,
    send_failure_kind, transport_protects_the_credential, OutboundOptions,
};
pub use private_key_jwt::{
    valid_resource_uri, valid_scope_token, validate_requested_scopes, PrivateKeyJwt,
    PrivateKeyJwtConfig, RedeemedAuthorizationCode, SubjectTokenType,
    DEFAULT_ASSERTION_LIFETIME_SECONDS, DEFAULT_REFRESH_MARGIN_SECONDS,
    MAXIMUM_ASSERTION_LIFETIME_SECONDS, MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS,
    MAXIMUM_REQUESTED_SCOPES, MAXIMUM_REQUESTED_SCOPE_BYTES, MAXIMUM_SCOPE_PARAMETER_BYTES,
    MAXIMUM_TOKEN_RESPONSE_BYTES,
};
pub use retry::{
    classify_keyed_attempt, retry_keyed_mutation, KeyedMutationAttempt, RetryAfter,
    DEFAULT_MUTATION_RETRIES, MAXIMUM_MUTATION_RETRIES, MAXIMUM_MUTATION_RETRY_AFTER_SECONDS,
};
pub use token::{BearerToken, OAuthErrorCode, StaticToken, TokenError, TokenProvider};
// The bearer bound is public to the crate's own tests, which tie the
// open-member decode's credential bound to it.
#[cfg(test)]
pub(crate) use token::MAXIMUM_TOKEN_BYTES;

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
    /// Stable machine-readable classification, written in kebab-case.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Timeout => "timeout",
            Self::Exchange => "exchange",
            Self::ResponseTooLarge => "response-too-large",
        }
    }
}

/// A service base URL validated for sending credentials.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceBaseUrl(Url);

impl ServiceBaseUrl {
    /// Validate a URL once, before any credential-bearing request can be built.
    ///
    /// This is [`Self::selected`] with the selection that declares no
    /// transport and no range: https, or http to a loopback host.
    pub fn new(url: Url) -> Result<Self, ServiceBaseUrlError> {
        Self::check_authority(&url)?;
        let selected = crate::select::select_credential_destination(&url, None, &[])
            .map_err(|_| ServiceBaseUrlError::UnprotectedTransport)?;
        Self::selected(url, &selected)
    }

    /// Validate a URL against the selection made for it.
    ///
    /// The selection must be for the URL's own scheme, host and port. A
    /// private plain-text selection is refused: a service base URL carries
    /// credentials, and no credential travels over private plain text.
    pub fn selected(
        url: Url,
        selected: &crate::select::SelectedDestination,
    ) -> Result<Self, ServiceBaseUrlError> {
        Self::check_authority(&url)?;
        if url.origin() != selected.url().origin() || !selected.admits_credentials() {
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

    fn check_authority(url: &Url) -> Result<(), ServiceBaseUrlError> {
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ServiceBaseUrlError::AuthorityOrSuffix);
        }
        Ok(())
    }

    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.0
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

    /// The kind is what a binding carries across a language boundary, so
    /// every variant has one fixed kebab-case word.
    #[test]
    fn every_transport_failure_reports_its_own_kebab_case_kind() {
        let cases = [
            (TransportKind::Connect, "connect"),
            (TransportKind::Timeout, "timeout"),
            (TransportKind::Exchange, "exchange"),
            (TransportKind::ResponseTooLarge, "response-too-large"),
        ];
        for (kind, word) in cases {
            assert_eq!(kind.kind(), word);
        }
    }

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

    fn selection(
        raw: &str,
        declared: Option<crate::select::TransportClass>,
        ranges: &[&str],
    ) -> crate::select::SelectedDestination {
        let ranges: Vec<crate::loopback::PrivateRange> = ranges
            .iter()
            .map(|raw| raw.parse().expect("test range parses"))
            .collect();
        crate::select::select_destination(&Url::parse(raw).unwrap(), declared, &ranges)
            .expect("the destination selects")
    }

    #[test]
    fn a_selected_service_base_url_carries_credentials_only_over_tls_or_loopback() {
        for (raw, declared) in [
            ("https://registry.example/prefix", None),
            (
                "https://registry.example/prefix",
                Some(crate::select::TransportClass::VerifiedTls),
            ),
            ("http://localhost:8080/api/", None),
            (
                "http://127.0.0.1:8080/",
                Some(crate::select::TransportClass::LoopbackPlaintext),
            ),
        ] {
            let base =
                ServiceBaseUrl::selected(Url::parse(raw).unwrap(), &selection(raw, declared, &[]))
                    .unwrap_or_else(|error| panic!("{raw}: {error}"));
            assert_eq!(base.as_url().as_str(), Url::parse(raw).unwrap().as_str());
        }

        let private = selection(
            "http://breg:8080/",
            Some(crate::select::TransportClass::PrivateNetworkPlaintext),
            &["172.16.0.0/12"],
        );
        assert_eq!(
            ServiceBaseUrl::selected(Url::parse("http://breg:8080/").unwrap(), &private),
            Err(ServiceBaseUrlError::UnprotectedTransport),
            "no credential travels over private plain text"
        );

        let elsewhere = selection("https://other.example/", None, &[]);
        for raw in [
            "https://registry.example/",
            "http://other.example/",
            "https://other.example:8443/",
        ] {
            assert_eq!(
                ServiceBaseUrl::selected(Url::parse(raw).unwrap(), &elsewhere),
                Err(ServiceBaseUrlError::UnprotectedTransport),
                "{raw} was not selected"
            );
        }
        let same_origin =
            ServiceBaseUrl::selected(Url::parse("https://other.example/v2/").unwrap(), &elsewhere)
                .expect("the selection covers the origin, whatever the path");
        assert_eq!(same_origin.as_url().path(), "/v2/");

        for (raw, error) in [
            (
                "https://secret@registry.example/",
                ServiceBaseUrlError::AuthorityOrSuffix,
            ),
            (
                "https://registry.example/?secret=value",
                ServiceBaseUrlError::AuthorityOrSuffix,
            ),
            (
                "https://registry.example/a//b",
                ServiceBaseUrlError::EmptyPathSegment,
            ),
        ] {
            assert_eq!(
                ServiceBaseUrl::selected(Url::parse(raw).unwrap(), &selection(raw, None, &[])),
                Err(error),
                "{raw}"
            );
        }
    }

    /// `new` is the selection with no declared transport and no range, and
    /// keeps every answer it gave before the selector existed.
    #[test]
    fn a_service_base_url_without_a_selection_keeps_its_rule() {
        for raw in [
            "https://registry.example/",
            "http://127.0.0.1/",
            "http://[::1]:8080/",
            "http://[::ffff:127.0.0.1]/",
            "http://localhost:8080/",
            "http://LOCALHOST/",
        ] {
            ServiceBaseUrl::new(Url::parse(raw).unwrap())
                .unwrap_or_else(|error| panic!("{raw}: {error}"));
        }
        for raw in [
            "http://a.localhost/",
            "http://localhost./",
            "http://10.0.0.1/",
            "http://[::ffff:10.0.0.1]/",
            "http://0.0.0.0/",
            "http://registry.example/",
            "ftp://127.0.0.1/",
        ] {
            assert_eq!(
                ServiceBaseUrl::new(Url::parse(raw).unwrap()),
                Err(ServiceBaseUrlError::UnprotectedTransport),
                "{raw}"
            );
        }
    }
}

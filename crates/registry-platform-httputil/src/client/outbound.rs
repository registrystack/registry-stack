//! The one rule set every outbound exchange in this crate is built from.
//!
//! Credential-bearing service and token exchanges both hand a secret to a host
//! the integrator named, so both are built here rather than from rule sets that
//! could drift apart.

use std::{borrow::Cow, time::Duration};

use crate::BoundedReadError;
use url::Url;

use super::TransportKind;

/// The one host name a cleartext URL may carry. It is reserved for the loopback
/// interface, so a credential sent to it cannot leave the host.
const LOOPBACK_NAME: &str = "localhost";

/// What a caller may vary about an outbound client. Everything else is fixed by
/// [`build_client`].
#[derive(Debug, Clone, Copy)]
pub struct OutboundOptions<'a> {
    pub request_timeout: Duration,
    pub connect_timeout: Duration,
    pub user_agent: Option<&'a str>,
    pub trusted_root_certificates: Option<&'a [u8]>,
}

/// Build an outbound client.
///
/// A failure is fixed text naming what about the options is unusable. Each
/// caller wraps it in its own error vocabulary, because the two exchanges report
/// configuration failures to the adopter under different types.
pub fn build_client(options: OutboundOptions<'_>) -> Result<reqwest::Client, &'static str> {
    let mut builder = crate::OutboundClientBuilder::new()
        .timeout(options.request_timeout)
        .connect_timeout(options.connect_timeout);
    if let Some(user_agent) = options.user_agent {
        builder = builder.user_agent(user_agent);
    }
    if let Some(pem) = options.trusted_root_certificates {
        builder = builder.trusted_root_certificates(pem);
    }
    builder.try_build().map_err(|error| error.reason())
}

/// Whether this URL's transport keeps a secret sent to it away from the network.
///
/// A secret in cleartext is only acceptable when it cannot leave the host, which
/// is the local development and tutorial case. The accepted forms are the ones an
/// adopter types: either loopback numeric family, or the reserved name
/// `localhost`. Any other name is refused, because a name that happens to resolve
/// to a loopback address is still resolved off-host, and the answer can change.
pub fn transport_protects_the_credential(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => url.host().is_some_and(|host| match host {
            url::Host::Ipv4(ip) => ip.is_loopback(),
            url::Host::Ipv6(ip) => ip.is_loopback(),
            url::Host::Domain(name) => name == LOOPBACK_NAME,
        }),
        _ => false,
    }
}

/// The service URL with userinfo, query, and fragment removed for diagnostics.
///
/// Validation refuses a base URL carrying credentials, but diagnostic rendering
/// cannot rely on having been reached only after construction.
pub fn base_url_without_userinfo(base_url: &Url) -> Cow<'_, str> {
    if base_url.username().is_empty()
        && base_url.password().is_none()
        && base_url.query().is_none()
        && base_url.fragment().is_none()
    {
        return Cow::Borrowed(base_url.as_str());
    }
    let mut stripped = base_url.clone();
    // Both setters refuse only a URL that cannot carry userinfo at all, and this
    // point is reached only for a URL that carries some, so neither can refuse
    // here. A refusal withholds the whole URL rather than rendering a credential.
    if stripped.set_username("").is_err() || stripped.set_password(None).is_err() {
        return Cow::Borrowed("<a base URL whose userinfo could not be removed>");
    }
    stripped.set_query(None);
    stripped.set_fragment(None);
    Cow::Owned(stripped.into())
}

/// Why a send failed, in the terms the caller can act on.
pub fn send_failure_kind(error: &reqwest::Error) -> TransportKind {
    if error.is_timeout() {
        TransportKind::Timeout
    } else if error.is_connect() {
        // TLS negotiation failures arrive here too. Separating them would mean
        // reading a transport error chain whose text this crate must not copy
        // into a diagnostic.
        TransportKind::Connect
    } else {
        TransportKind::Exchange
    }
}

/// Why a bounded read failed, in the terms the caller can act on.
///
/// The distinction matters most for a timeout, which is the likely failure: the
/// configured total timeout runs until the body finishes, so an answer that
/// starts and stalls elapses here rather than at connection setup. No part of the
/// underlying error text is copied into the reported failure.
pub fn read_failure_kind(error: &BoundedReadError) -> TransportKind {
    match error {
        BoundedReadError::ContentLengthExceeded { .. }
        | BoundedReadError::BodyTooLarge { .. }
        | BoundedReadError::LengthOverflow => TransportKind::ResponseTooLarge,
        BoundedReadError::Transport(error) if error.is_timeout() => TransportKind::Timeout,
        // The reader's error type is open, so a variant this crate does not know
        // yet becomes the coarse exchange failure. It must never become a claim
        // about the response size, which is the one thing an adopter would act on
        // by raising their own bound.
        _ => TransportKind::Exchange,
    }
}

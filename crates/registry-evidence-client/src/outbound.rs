//! The one rule set every outbound exchange in this crate is built from.
//!
//! Two exchanges leave this crate: the Evidence request, which carries the
//! relying party's bearer credential, and the token request, which carries a
//! signed client assertion. Both hand a secret to a host the integrator named,
//! so both are built here rather than from two rule sets that could drift apart.

use std::{borrow::Cow, time::Duration};

use registry_platform_httputil::BoundedReadError;
use url::Url;

use crate::error::TransportKind;

/// The one host name a cleartext URL may carry. It is reserved for the loopback
/// interface, so a credential sent to it cannot leave the host.
const LOOPBACK_NAME: &str = "localhost";

/// What a caller may vary about an outbound client. Everything else is fixed by
/// [`build_client`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct OutboundOptions<'a> {
    pub(crate) request_timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) user_agent: Option<&'a str>,
    pub(crate) trusted_root_certificates: Option<&'a [u8]>,
}

/// Build an outbound client.
///
/// A failure is fixed text naming what about the options is unusable. Each
/// caller wraps it in its own error vocabulary, because the two exchanges report
/// configuration failures to the adopter under different types.
pub(crate) fn build_client(options: OutboundOptions<'_>) -> Result<reqwest::Client, &'static str> {
    let mut builder = reqwest::Client::builder()
        .timeout(options.request_timeout)
        .connect_timeout(options.connect_timeout)
        // A redirect is not part of the response contract, and following one
        // would present the relying party's credential to a host the integrator
        // never configured, on the say-so of a response header. The answer is
        // reported as it stands instead.
        .redirect(reqwest::redirect::Policy::none())
        // The proxy environment variables are ignored deliberately. An ambient
        // variable would otherwise route a credential through an intermediary the
        // integrator did not choose, and terminate the TLS session the pinned
        // certificate authorities were meant to authenticate.
        .no_proxy()
        // Select rustls explicitly. Cargo unifies reqwest's feature set across
        // a whole build, so another crate enabling reqwest's native-tls feature
        // must not silently change which TLS backend this client uses.
        .use_rustls_tls()
        // One prepared request is one exchange. A transport-level retry would
        // resend a nonce the relying party's policy has already committed to
        // and would duplicate an outbound call the caller did not ask for.
        .retry(reqwest::retry::never());
    if let Some(user_agent) = options.user_agent {
        builder = builder.user_agent(user_agent);
    }
    if let Some(pem) = options.trusted_root_certificates {
        let certificates = reqwest::Certificate::from_pem_bundle(pem)
            .map_err(|_| "the pinned certificate authority bundle is not readable PEM")?;
        if certificates.is_empty() {
            return Err("the pinned certificate authority bundle carries no certificate");
        }
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
        // Trust exactly what the integrator pinned. Leaving the platform store
        // enabled would mean any of its authorities could also vouch for the
        // deployment, which is the opposite of pinning.
        builder = builder.tls_built_in_root_certs(false);
    }
    builder
        .build()
        .map_err(|_| "the outbound client options are not usable")
}

/// Whether this URL's transport keeps a secret sent to it away from the network.
///
/// A secret in cleartext is only acceptable when it cannot leave the host, which
/// is the local development and tutorial case. The accepted forms are the ones an
/// adopter types: either loopback numeric family, or the reserved name
/// `localhost`. Any other name is refused, because a name that happens to resolve
/// to a loopback address is still resolved off-host, and the answer can change.
pub(crate) fn transport_protects_the_credential(url: &Url) -> bool {
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

/// The base URL with any userinfo removed.
///
/// [`EvidenceClientConfig::validate`] refuses a base URL carrying credentials,
/// but it runs inside `EvidenceClient::new`, so the rendering cannot rely on
/// having been reached after construction.
pub(crate) fn base_url_without_userinfo(base_url: &Url) -> Cow<'_, str> {
    if base_url.username().is_empty() && base_url.password().is_none() {
        return Cow::Borrowed(base_url.as_str());
    }
    let mut stripped = base_url.clone();
    // Both setters refuse only a URL that cannot carry userinfo at all, and this
    // point is reached only for a URL that carries some, so neither can refuse
    // here. A refusal withholds the whole URL rather than rendering a credential.
    if stripped.set_username("").is_err() || stripped.set_password(None).is_err() {
        return Cow::Borrowed("<a base URL whose userinfo could not be removed>");
    }
    Cow::Owned(stripped.into())
}

/// Why a send failed, in the terms the caller can act on.
pub(crate) fn send_failure_kind(error: &reqwest::Error) -> TransportKind {
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
pub(crate) fn read_failure_kind(error: &BoundedReadError) -> TransportKind {
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

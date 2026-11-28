//! One selector for every outbound destination.
//!
//! A destination is a URL, an optional declared [`TransportClass`] and a list
//! of private ranges. [`select_destination`] turns the three into a
//! [`SelectedDestination`], or refuses them with a coded
//! [`DestinationSelectionError`]. The three outbound families consume the
//! selection: [`crate::destination::FixedDestinationPolicy::from_selected`],
//! [`crate::ServiceBaseUrl::selected`] and
//! [`crate::OutboundClientBuilder::destination`]. A credential-free fetch
//! uses [`validate_selected_fetch`].
//!
//! The selection never relaxes anything by reading the URL. https selects
//! verified TLS and http to a loopback host selects loopback plain text, both
//! valid in every posture. http to any other host is refused until the
//! configuration declares `private-network-plaintext` with its ranges.

use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use ipnet::IpNet;
use reqwest::Url;
use thiserror::Error;

use crate::destination::{
    classify_private_service_address, classify_production_address, decode_well_known_nat64,
    is_always_denied_in_production, origin_uses_localhost_namespace,
    profile_admits_credential_exchange, retain_private_cidrs, DestinationPolicyError,
    DestinationProfile, DestinationSendError, MAX_DESTINATION_PRIVATE_CIDRS,
};
use crate::loopback::{PrivateRange, PrivateRangeError};
use crate::{is_cloud_metadata_ip, normalize_ipv4_mapped};

pub use registry_platform_loopback::TransportClass;

/// A destination URL with the profile, transport and ranges it was selected
/// for. Only [`select_destination`] makes one. `Debug` reports the profile,
/// the transport and the range count, never the URL.
#[derive(Clone, PartialEq, Eq)]
pub struct SelectedDestination {
    url: Url,
    profile: DestinationProfile,
    transport: TransportClass,
    allowed_private_cidrs: Vec<IpNet>,
}

impl SelectedDestination {
    /// The fixed-destination profile the selection maps to.
    #[must_use]
    pub fn profile(&self) -> DestinationProfile {
        self.profile
    }

    /// The transport, declared or inferred.
    #[must_use]
    pub fn transport(&self) -> TransportClass {
        self.transport
    }

    /// The private ranges, canonical, sorted and without repeats.
    #[must_use]
    pub fn allowed_private_cidrs(&self) -> &[IpNet] {
        &self.allowed_private_cidrs
    }

    /// Whether the destination is reached without TLS inside private ranges.
    #[must_use]
    pub fn is_private_plaintext(&self) -> bool {
        self.transport == TransportClass::PrivateNetworkPlaintext
    }

    /// Whether a credential may travel to this destination: https, or plain
    /// http to loopback. Private plain text never carries one.
    #[must_use]
    pub fn admits_credentials(&self) -> bool {
        profile_admits_credential_exchange(self.profile)
    }

    /// Whether `url` has the selection's own origin: the same scheme, host
    /// and port. A consumer that joins or follows URLs checks each one here
    /// before a client confined to this selection sends to it.
    #[must_use]
    pub fn admits_url(&self, url: &Url) -> bool {
        url.origin() == self.url.origin()
    }

    /// Whether `authority`, the value of a `Host` header, names the
    /// selection's own host and port. It is read with a bounded grammar and
    /// never through a URL parser, so no spelling is normalized into a match:
    ///
    /// - a name is ASCII letters, digits, `-`, `.` and `_`, compared as
    ///   written without case, root dot included, and a name whose last
    ///   label (ignoring one root dot) is a number, decimal or `0x` hex, is
    ///   refused unless it is an IPv4 address;
    /// - an IPv4 address is in dotted decimal with no leading zeros;
    /// - an IPv6 address is bracketed, with no zone, and compared as an
    ///   address, so its textual form does not matter;
    /// - a port, when written, is digits naming a port from 1 to 65535,
    ///   compared as a number whatever its leading zeros, and an elided port
    ///   is the scheme's default.
    ///
    /// Anything else, including an empty port, a percent-encoded byte,
    /// userinfo, a path, whitespace or a control character, is refused.
    pub(crate) fn admits_authority(&self, authority: &str) -> bool {
        let Some((host, port)) = split_authority(authority) else {
            return false;
        };
        let Some(selected_port) = self.url.port_or_known_default() else {
            return false;
        };
        let port = match port {
            None => match self.url.scheme() {
                "http" => Some(80),
                "https" => Some(443),
                _ => None,
            },
            Some(digits) => parse_port(digits),
        };
        if port != Some(selected_port) {
            return false;
        }
        match (self.url.host(), host) {
            (Some(::url::Host::Domain(selected)), AuthorityHost::Name(name)) => {
                selected.eq_ignore_ascii_case(name)
            }
            (Some(::url::Host::Ipv4(selected)), AuthorityHost::Ipv4(address)) => {
                selected == address
            }
            (Some(::url::Host::Ipv6(selected)), AuthorityHost::Ipv6(address)) => {
                selected == address
            }
            _ => false,
        }
    }

    /// Whether `name` is the selection's own host name, compared without
    /// case and without one trailing dot. A selection made for an address
    /// literal has no name to resolve.
    fn is_selected_name(&self, name: &str) -> bool {
        let Some(::url::Host::Domain(selected)) = self.url.host() else {
            return false;
        };
        fn unrooted(name: &str) -> &str {
            name.strip_suffix('.').unwrap_or(name)
        }
        unrooted(selected).eq_ignore_ascii_case(unrooted(name))
    }

    /// The URL the selection was made for.
    pub(crate) fn url(&self) -> &Url {
        &self.url
    }
}

/// The host of a `Host` header value, read by
/// [`SelectedDestination::admits_authority`].
enum AuthorityHost<'a> {
    Name(&'a str),
    Ipv4(std::net::Ipv4Addr),
    Ipv6(std::net::Ipv6Addr),
}

/// Split a `Host` value into its host and its written port, refusing any
/// spelling outside the bounded grammar `admits_authority` documents.
fn split_authority(authority: &str) -> Option<(AuthorityHost<'_>, Option<&str>)> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        if !inner
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b':' || byte == b'.')
        {
            return None;
        }
        (AuthorityHost::Ipv6(inner.parse().ok()?), port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        (authority_name_or_ipv4(host)?, port)
    };
    if port.is_some_and(|digits| parse_port(digits).is_none()) {
        return None;
    }
    Some((host, port))
}

/// A registered name, kept as written (root dot included), or an IPv4
/// address in dotted decimal. URL parsers read a host as IPv4 when its last
/// label, ignoring one terminal dot, is a number: all decimal digits, or `0x`
/// followed by hex digits. Such a host must be a dotted-decimal address here,
/// spelled without a root dot, or it is refused. Only one root dot is read:
/// a final label left empty after it, as in `objects.example..`, is refused.
fn authority_name_or_ipv4(host: &str) -> Option<AuthorityHost<'_>> {
    if host.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    {
        return None;
    }
    let unrooted = host.strip_suffix('.').unwrap_or(host);
    let last = unrooted.rsplit('.').next().unwrap_or(unrooted);
    if last.is_empty() {
        return None;
    }
    let numeric = last.bytes().all(|byte| byte.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .or_else(|| last.strip_prefix("0X"))
            .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if !numeric {
        return Some(AuthorityHost::Name(host));
    }
    // `Ipv4Addr` parses exactly four decimal octets and refuses a leading zero
    // or a root dot.
    host.parse().ok().map(AuthorityHost::Ipv4)
}

/// A written port: ASCII digits naming a port from 1 to 65535, read as a
/// number, so leading zeros do not change it.
fn parse_port(digits: &str) -> Option<u16> {
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let significant = digits.trim_start_matches('0');
    if significant.is_empty() {
        return None;
    }
    significant.parse().ok()
}

impl fmt::Debug for SelectedDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedDestination")
            .field("url", &"[REDACTED]")
            .field("profile", &self.profile)
            .field("transport", &self.transport)
            .field("private_cidr_count", &self.allowed_private_cidrs.len())
            .finish()
    }
}

/// Select the transport for one outbound destination.
///
/// `declared` is the destination's `transport` member, `None` when it is
/// omitted. `allowed_private_cidrs` is its `allowedPrivateCidrs` list. An
/// empty list names no private address under every transport.
///
/// | Scheme | Declared | Host | Result |
/// |---|---|---|---|
/// | https | none or verified TLS | any | [`DestinationProfile::ProductionHttps`] with the ranges |
/// | http | none or loopback plain text | loopback | [`DestinationProfile::LoopbackHttp`] |
/// | http | none | other | [`DestinationSelectionError::PrivateNetworkNotDeclared`] |
/// | http | loopback plain text | other | [`DestinationSelectionError::TransportHostMismatch`] |
/// | http | private plain text | loopback or the `localhost` namespace | [`DestinationSelectionError::TransportHostMismatch`] |
/// | http | private plain text | any, no range | [`DestinationSelectionError::PrivateNetworkRequiresRanges`] |
/// | http | private plain text | literal outside the ranges | [`DestinationSelectionError::LiteralOutsideRanges`] |
/// | http | private plain text | name, or literal inside the ranges | [`DestinationProfile::PrivateServiceHttp`] with the ranges |
/// | https | a plain-text transport | any | [`DestinationSelectionError::TransportSchemeMismatch`] |
/// | http | verified TLS | any | [`DestinationSelectionError::TransportSchemeMismatch`] |
/// | other | any | any | [`DestinationSelectionError::UnsupportedScheme`] |
///
/// The ranges are checked by the rule [`FixedDestinationPolicy::new`]
/// applies: at most [`MAX_DESTINATION_PRIVATE_CIDRS`], never a single cloud
/// metadata address.
///
/// [`FixedDestinationPolicy::new`]: crate::destination::FixedDestinationPolicy::new
pub fn select_destination(
    url: &Url,
    declared: Option<TransportClass>,
    allowed_private_cidrs: &[PrivateRange],
) -> Result<SelectedDestination, DestinationSelectionError> {
    let https = match url.scheme() {
        "https" => true,
        "http" => false,
        _ => return Err(DestinationSelectionError::UnsupportedScheme),
    };
    let declared_scheme_matches = match declared {
        None => true,
        Some(TransportClass::VerifiedTls) => https,
        Some(TransportClass::LoopbackPlaintext | TransportClass::PrivateNetworkPlaintext) => !https,
    };
    if !declared_scheme_matches {
        return Err(DestinationSelectionError::TransportSchemeMismatch);
    }
    let networks = private_networks(allowed_private_cidrs)?;
    let selected = |profile, transport| SelectedDestination {
        url: url.clone(),
        profile,
        transport,
        allowed_private_cidrs: networks.clone(),
    };
    if https {
        return Ok(selected(
            DestinationProfile::ProductionHttps,
            TransportClass::VerifiedTls,
        ));
    }

    // An http URL always carries a host, so an absent one is not loopback.
    let loopback = url
        .host_str()
        .and_then(crate::loopback::loopback_host)
        .is_some();
    match declared {
        None | Some(TransportClass::LoopbackPlaintext) if loopback => Ok(selected(
            DestinationProfile::LoopbackHttp,
            TransportClass::LoopbackPlaintext,
        )),
        None => Err(DestinationSelectionError::PrivateNetworkNotDeclared),
        Some(TransportClass::LoopbackPlaintext) => {
            Err(DestinationSelectionError::TransportHostMismatch)
        }
        Some(TransportClass::PrivateNetworkPlaintext) => {
            if loopback || origin_uses_localhost_namespace(url) {
                return Err(DestinationSelectionError::TransportHostMismatch);
            }
            if allowed_private_cidrs.is_empty() {
                return Err(DestinationSelectionError::PrivateNetworkRequiresRanges);
            }
            let literal = match url.host() {
                Some(::url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
                Some(::url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
                Some(::url::Host::Domain(_)) | None => None,
            };
            if literal
                .is_some_and(|ip| !allowed_private_cidrs.iter().any(|range| range.contains(ip)))
            {
                return Err(DestinationSelectionError::LiteralOutsideRanges);
            }
            Ok(selected(
                DestinationProfile::PrivateServiceHttp,
                TransportClass::PrivateNetworkPlaintext,
            ))
        }
        Some(TransportClass::VerifiedTls) => {
            Err(DestinationSelectionError::TransportSchemeMismatch)
        }
    }
}

/// Select the transport for a destination that carries a credential: a
/// token, a client secret, an API key, a signature key or a password.
///
/// This is [`select_destination`] with one more refusal: a credential never
/// travels over private plain text, so a destination that selects it is
/// refused with [`DestinationSelectionError::CredentialRequiresProtectedTransport`].
/// Every credential-bearing destination block calls this instead of
/// [`select_destination`].
pub fn select_credential_destination(
    url: &Url,
    declared: Option<TransportClass>,
    allowed_private_cidrs: &[PrivateRange],
) -> Result<SelectedDestination, DestinationSelectionError> {
    let selected = select_destination(url, declared, allowed_private_cidrs)?;
    if !selected.admits_credentials() {
        return Err(DestinationSelectionError::CredentialRequiresProtectedTransport);
    }
    Ok(selected)
}

/// Resolve the selected URL once, admit every answer, and pin the fetch to
/// the admitted addresses.
///
/// For a credential-free fetch only: the returned [`SelectedFetch`] sends one
/// GET to any selection, private plain text included, and hands out no
/// request builder, so no credential can be added to it. A destination that
/// carries a credential uses a client built with
/// [`crate::OutboundClientBuilder::destination`] instead.
///
/// Over https each answer, and an address literal, is admitted as a fixed
/// https destination admits it: a private address, CGNAT included, only
/// inside the selection's ranges, and never a cloud metadata, always-denied
/// or other non-global address. An explicit loopback literal is admitted, as
/// a selected client admits it. Under a plain-text selection an answer is
/// admitted as a selected client admits it. The name `localhost` is pinned
/// to the loopback addresses, never resolved. Any other name is resolved
/// through the operating system, which blocks the calling thread.
pub fn validate_selected_fetch(
    selected: &SelectedDestination,
) -> Result<SelectedFetch, crate::FetchUrlError> {
    validate_selected_fetch_resolved_by(selected, crate::resolve_host).map(SelectedFetch)
}

/// A credential-free fetch of one selected URL, from
/// [`validate_selected_fetch`]: one GET pinned to the admitted addresses,
/// with no redirect followed and no proxy used. It hands out no request
/// builder, so a caller cannot add a credential or any other header but
/// `Accept`, whatever transport the selection declares.
///
/// ```no_run
/// use registry_platform_httputil::select::{validate_selected_fetch, SelectedDestination};
///
/// async fn fetch(selected: &SelectedDestination) {
///     let fetch = validate_selected_fetch(selected).expect("the fetch validates");
///     let accept = reqwest::header::HeaderValue::from_static("application/json");
///     let _ = fetch.get(&accept, std::time::Duration::from_secs(5)).await;
/// }
/// ```
///
/// The same caller cannot take a request builder from it:
///
/// ```compile_fail
/// use registry_platform_httputil::select::{validate_selected_fetch, SelectedDestination};
///
/// fn builder(selected: &SelectedDestination) {
///     let fetch = validate_selected_fetch(selected).expect("the fetch validates");
///     let _ = fetch.immediate_get();
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedFetch(crate::ValidatedFetchUrl);

impl SelectedFetch {
    /// The selected URL the fetch sends to.
    #[must_use]
    pub fn url(&self) -> &Url {
        self.0.url()
    }

    /// Send the GET with `accept` as its only caller header, within
    /// `timeout`.
    ///
    /// # Errors
    ///
    /// [`crate::FetchUrlError::ClientBuild`] when the pinned client cannot be
    /// built, and [`crate::FetchUrlError::Request`] when the request fails.
    pub async fn get(
        &self,
        accept: &reqwest::header::HeaderValue,
        timeout: std::time::Duration,
    ) -> Result<reqwest::Response, crate::FetchUrlError> {
        self.pinned_get(accept, timeout)?
            .send()
            .await
            .map_err(crate::FetchUrlError::Request)
    }

    /// The one request [`Self::get`] sends, unsent.
    fn pinned_get(
        &self,
        accept: &reqwest::header::HeaderValue,
        timeout: std::time::Duration,
    ) -> Result<reqwest::RequestBuilder, crate::FetchUrlError> {
        Ok(self
            .0
            .immediate_get_with_timeout(timeout)?
            .header(reqwest::header::ACCEPT, accept))
    }
}

/// [`validate_selected_fetch`] with the addresses `lookup` answers. Tests
/// pass a fixed lookup; every other caller goes through
/// [`validate_selected_fetch`].
fn validate_selected_fetch_resolved_by(
    selected: &SelectedDestination,
    lookup: impl FnOnce(&Url) -> Result<Vec<SocketAddr>, crate::FetchUrlError>,
) -> Result<crate::ValidatedFetchUrl, crate::FetchUrlError> {
    let url = &selected.url;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(crate::FetchUrlError::UserInfoDenied);
    }
    let port = url
        .port_or_known_default()
        .ok_or(crate::FetchUrlError::MissingPort)?;
    let literal = |ip: IpAddr| -> Result<Vec<SocketAddr>, crate::FetchUrlError> {
        admit_fetch_literal(selected, ip)
            .map_err(crate::FetchUrlError::DestinationAddressDenied)?;
        Ok(vec![SocketAddr::new(ip, port)])
    };
    let resolved_addrs = match url.host().ok_or(crate::FetchUrlError::MissingHost)? {
        ::url::Host::Ipv4(ip) => literal(IpAddr::V4(ip))?,
        ::url::Host::Ipv6(ip) => literal(IpAddr::V6(ip))?,
        ::url::Host::Domain(crate::LOCALHOST_NAME) => vec![
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), port),
        ],
        ::url::Host::Domain(_) => {
            let answers = lookup(url)?;
            if answers.is_empty() {
                return Err(crate::FetchUrlError::NoAddresses);
            }
            for answer in &answers {
                admit_fetch_address(selected, answer.ip())
                    .map_err(crate::FetchUrlError::DestinationAddressDenied)?;
            }
            answers
        }
    };
    Ok(crate::ValidatedFetchUrl {
        url: url.clone(),
        resolved_addrs,
    })
}

/// The ranges as the fixed-destination family keeps them, refused by the
/// same rule: at most [`MAX_DESTINATION_PRIVATE_CIDRS`], each canonical and
/// private, never a single cloud metadata address.
fn private_networks(ranges: &[PrivateRange]) -> Result<Vec<IpNet>, DestinationSelectionError> {
    if ranges.len() > MAX_DESTINATION_PRIVATE_CIDRS {
        return Err(DestinationSelectionError::TooManyRanges);
    }
    let networks = ranges
        .iter()
        .map(|range| IpNet::new(range.network(), range.prefix()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| DestinationSelectionError::RangeMalformed)?;
    retain_private_cidrs(&networks).map_err(|error| match error {
        DestinationPolicyError::PrivateCidrNotCanonical => {
            DestinationSelectionError::RangeNotCanonical
        }
        DestinationPolicyError::TooManyPrivateCidrs => DestinationSelectionError::TooManyRanges,
        _ => DestinationSelectionError::RangeNotPrivate,
    })
}

/// Why a destination cannot be selected. Each refusal has a stable code and
/// one fix. The text never repeats a value read from configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DestinationSelectionError {
    #[error("the destination URL uses a scheme other than http or https")]
    UnsupportedScheme,
    #[error("the destination uses http to a host that is not loopback")]
    PrivateNetworkNotDeclared,
    #[error("the destination is private plain text with no private range")]
    PrivateNetworkRequiresRanges,
    #[error("the declared transport and the URL scheme disagree")]
    TransportSchemeMismatch,
    #[error("the declared transport and the URL host disagree")]
    TransportHostMismatch,
    #[error("the destination address is outside the allowed private ranges")]
    LiteralOutsideRanges,
    #[error("a private range is not a network address and a prefix length")]
    RangeMalformed,
    #[error(
        "a private range is not wholly inside private space, or is a single cloud metadata address"
    )]
    RangeNotPrivate,
    #[error("a private range has host bits set in its network address")]
    RangeNotCanonical,
    #[error("more than 16 private ranges are listed")]
    TooManyRanges,
    #[error("the destination carries a credential and is reached over private plain text")]
    CredentialRequiresProtectedTransport,
}

impl DestinationSelectionError {
    /// The stable code of the refusal.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedScheme => "platform.destination.unsupported-scheme",
            Self::PrivateNetworkNotDeclared => "platform.destination.private-network-not-declared",
            Self::PrivateNetworkRequiresRanges => {
                "platform.destination.private-network-requires-ranges"
            }
            Self::TransportSchemeMismatch => "platform.destination.transport-scheme-mismatch",
            Self::TransportHostMismatch => "platform.destination.transport-host-mismatch",
            Self::LiteralOutsideRanges => "platform.destination.literal-outside-ranges",
            Self::RangeMalformed => "platform.destination.range-malformed",
            Self::RangeNotPrivate => "platform.destination.range-not-private",
            Self::RangeNotCanonical => "platform.destination.range-not-canonical",
            Self::TooManyRanges => "platform.destination.too-many-ranges",
            Self::CredentialRequiresProtectedTransport => {
                "platform.destination.credential-requires-protected-transport"
            }
        }
    }

    /// What to write instead.
    #[must_use]
    pub fn fix(&self) -> &'static str {
        match self {
            Self::UnsupportedScheme => {
                "Use an https URL, or an http URL with the transport that matches its host."
            }
            Self::PrivateNetworkNotDeclared => {
                "Write transport: private-network-plaintext and allowedPrivateCidrs with the receiver's range, or serve it over https."
            }
            Self::PrivateNetworkRequiresRanges => {
                "Add the smallest range that contains the receiver to allowedPrivateCidrs."
            }
            Self::TransportSchemeMismatch => {
                "Use https with verified-tls, or http with a plain-text transport."
            }
            Self::TransportHostMismatch => {
                "Use the transport that matches the host: loopback-plaintext for localhost or a loopback address, private-network-plaintext for any other host."
            }
            Self::LiteralOutsideRanges => "Add its range to allowedPrivateCidrs or fix the address.",
            Self::RangeMalformed => {
                "Write each range as a network address and a prefix length, such as 172.16.0.0/12."
            }
            Self::RangeNotPrivate => {
                "Name only private ranges: inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 or fc00::/7."
            }
            Self::RangeNotCanonical => {
                "Write the network address, such as 10.0.0.0/8 and not 10.0.0.1/8."
            }
            Self::TooManyRanges => "Merge ranges until at most 16 remain.",
            Self::CredentialRequiresProtectedTransport => {
                "This destination carries a credential. Serve it over https, or reach it on loopback."
            }
        }
    }
}

/// A range written in code is refused with the code configuration gives it.
impl From<PrivateRangeError> for DestinationSelectionError {
    fn from(error: PrivateRangeError) -> Self {
        match error {
            PrivateRangeError::Malformed => Self::RangeMalformed,
            PrivateRangeError::NotCanonical => Self::RangeNotCanonical,
            PrivateRangeError::NotPrivate => Self::RangeNotPrivate,
        }
    }
}

/// Admit or refuse every address a client built for `selected` would dial.
/// One refused answer refuses them all, and no answer is a refusal.
pub(crate) fn admit_answers(
    selected: &SelectedDestination,
    answers: impl IntoIterator<Item = IpAddr>,
) -> Result<(), DestinationSendError> {
    let mut any = false;
    for answer in answers {
        any = true;
        admit_address(selected, answer)?;
    }
    if any {
        Ok(())
    } else {
        Err(DestinationSendError::NoResolverAnswers)
    }
}

/// The address literal of the selected URL, checked when the client is
/// built, since a client never resolves a literal.
///
/// Over https an explicit loopback literal is admitted: the loopback class
/// trusts a host written as loopback, while a name that resolves to loopback
/// stays refused by [`admit_answers`]. Refusing TLS where plain text to the
/// same address is admitted would only push an operator to drop TLS.
pub(crate) fn admit_literal_host(
    selected: &SelectedDestination,
) -> Result<(), DestinationSendError> {
    let ip = match selected.url.host() {
        Some(::url::Host::Ipv4(ip)) => IpAddr::V4(ip),
        Some(::url::Host::Ipv6(ip)) => IpAddr::V6(ip),
        Some(::url::Host::Domain(_)) | None => return Ok(()),
    };
    if selected.profile == DestinationProfile::ProductionHttps
        && crate::loopback::loopback_address(ip)
    {
        return Ok(());
    }
    admit_address(selected, ip)
}

/// The address literal of a credential-free fetch. Over https an explicit
/// loopback literal is admitted, as [`admit_literal_host`] admits it, and
/// any other literal answers to [`admit_fetch_address`].
fn admit_fetch_literal(
    selected: &SelectedDestination,
    ip: IpAddr,
) -> Result<(), DestinationSendError> {
    if selected.profile == DestinationProfile::ProductionHttps
        && crate::loopback::loopback_address(ip)
    {
        return Ok(());
    }
    admit_fetch_address(selected, ip)
}

/// One address a credential-free fetch would dial. Over https it is the rule
/// a fixed https destination applies, so a private answer needs a listed
/// range, as `FetchUrlPolicy::strict` refuses one with no range. Under a
/// plain-text selection it is the selected client's rule.
fn admit_fetch_address(
    selected: &SelectedDestination,
    ip: IpAddr,
) -> Result<(), DestinationSendError> {
    if selected.profile == DestinationProfile::ProductionHttps {
        return classify_production_address(
            normalize_ipv4_mapped(ip),
            &selected.allowed_private_cidrs,
        );
    }
    admit_address(selected, ip)
}

fn admit_address(selected: &SelectedDestination, ip: IpAddr) -> Result<(), DestinationSendError> {
    let ip = normalize_ipv4_mapped(ip);
    match selected.profile {
        DestinationProfile::PrivateServiceHttp => {
            classify_private_service_address(ip, &selected.allowed_private_cidrs)
        }
        DestinationProfile::LoopbackHttp => {
            if crate::loopback::loopback_address(ip) {
                Ok(())
            } else {
                Err(DestinationSendError::DevelopmentAddressDenied)
            }
        }
        DestinationProfile::ProductionHttps => admit_verified_tls_address(ip),
        // Only a fixed destination freezes this profile; no selection has it.
        DestinationProfile::LoopbackHttps => Err(DestinationSendError::InvalidFrozenPolicy),
        // The selector makes neither test profile.
        #[cfg(any(test, feature = "test-support"))]
        DestinationProfile::LocalPrivateDevelopmentHttp
        | DestinationProfile::PinnedLoopbackHttpsTest => {
            Err(DestinationSendError::InvalidFrozenPolicy)
        }
    }
}

/// https admits a private answer with no range, and refuses the cloud
/// metadata addresses and the always-denied ranges, judged after the
/// IPv4-mapped, IPv4-compatible, 6to4 and well-known NAT64 forms are decoded.
/// Other translation prefixes, such as local-use NAT64, are not decoded.
fn admit_verified_tls_address(ip: IpAddr) -> Result<(), DestinationSendError> {
    let ip = match ip {
        IpAddr::V6(v6) => embedded_ipv4(v6).map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    };
    if is_cloud_metadata_ip(ip) {
        return Err(DestinationSendError::CloudMetadataDenied);
    }
    if is_always_denied_in_production(ip) {
        return Err(DestinationSendError::AlwaysDeniedAddress);
    }
    Ok(())
}

/// The IPv4 address an IPv6 transition form carries: the well-known NAT64
/// prefix `64:ff9b::/96`, IPv4-compatible `::/96` other than `::` and `::1`,
/// and 6to4 `2002::/16`, whose address is the 32 bits after the prefix.
fn embedded_ipv4(ip: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(embedded) = decode_well_known_nat64(ip) {
        return Some(embedded);
    }
    let octets = ip.octets();
    if octets[..12] == [0; 12] && !ip.is_unspecified() && !ip.is_loopback() {
        return Some(std::net::Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    if octets[..2] == [0x20, 0x02] {
        return Some(std::net::Ipv4Addr::new(
            octets[2], octets[3], octets[4], octets[5],
        ));
    }
    None
}

/// A client resolver confined to one selection. It refuses any name other
/// than the selected host before `lookup` is asked, then refuses the request
/// unless [`admit_answers`] admits every answer. Names the client pins, such
/// as `localhost`, never reach it, and neither does an address literal.
pub(crate) struct SelectedResolver {
    selected: SelectedDestination,
    lookup: Arc<dyn reqwest::dns::Resolve>,
}

impl SelectedResolver {
    pub(crate) fn new(
        selected: SelectedDestination,
        lookup: Arc<dyn reqwest::dns::Resolve>,
    ) -> Self {
        Self { selected, lookup }
    }
}

impl reqwest::dns::Resolve for SelectedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        if !self.selected.is_selected_name(name.as_str()) {
            return Box::pin(std::future::ready(Err(
                DestinationSendError::DestinationNameMismatch.into(),
            )));
        }
        let selected = self.selected.clone();
        let lookup = self.lookup.resolve(name);
        Box::pin(async move {
            let answers: Vec<SocketAddr> = lookup
                .await
                .map_err(|_| DestinationSendError::ResolutionFailed)?
                .collect();
            admit_answers(&selected, answers.iter().map(SocketAddr::ip))?;
            let answers: reqwest::dns::Addrs = Box::new(answers.into_iter());
            Ok(answers)
        })
    }
}

/// The operating system's resolver, asked on the blocking pool. The port is
/// zero: the client takes the port from each request URL.
pub(crate) struct SystemLookup;

impl reqwest::dns::Resolve for SystemLookup {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let answers = tokio::task::spawn_blocking(move || {
                (host.as_str(), 0)
                    .to_socket_addrs()
                    .map(Iterator::collect::<Vec<_>>)
            })
            .await??;
            let answers: reqwest::dns::Addrs = Box::new(answers.into_iter());
            Ok(answers)
        })
    }
}

/// One row of the shared destination table (T1 to T26). Products render each
/// load row into their own configuration block and expect the same profile
/// or code. Rows whose behaviour is not a selection (a redirect, a proxy, the
/// credential slot, the issuer) are tested where that behaviour lives.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug)]
pub struct SelectCase {
    /// The row name in the table, such as `T8`.
    pub row: &'static str,
    /// The destination URL.
    pub url: &'static str,
    /// The `transport` member as configuration spells it, `None` when omitted.
    pub transport: Option<&'static str>,
    /// The `allowedPrivateCidrs` items as configuration spells them.
    pub allowed_private_cidrs: &'static [&'static str],
    /// The selected profile, or the refusal code.
    pub load: Result<DestinationProfile, &'static str>,
    /// Resolver answers for a send row, empty for a load-only row.
    pub answers: &'static [&'static str],
    /// What a fixed destination built from the selection does with `answers`.
    pub send: Option<Result<(), DestinationSendError>>,
}

#[cfg(any(test, feature = "test-support"))]
impl SelectCase {
    /// Parse the row's inputs and run [`select_destination`]. A range that
    /// does not parse is refused with the code configuration gives it.
    pub fn select(&self) -> Result<SelectedDestination, DestinationSelectionError> {
        let url = Url::parse(self.url).map_err(|_| DestinationSelectionError::UnsupportedScheme)?;
        let declared = self.transport.map(|spelling| match spelling {
            "verified-tls" => TransportClass::VerifiedTls,
            "loopback-plaintext" => TransportClass::LoopbackPlaintext,
            "private-network-plaintext" => TransportClass::PrivateNetworkPlaintext,
            other => panic!("the table spells no transport {other}"),
        });
        let ranges = self
            .allowed_private_cidrs
            .iter()
            .map(|text| text.parse::<PrivateRange>())
            .collect::<Result<Vec<_>, _>>()?;
        select_destination(&url, declared, &ranges)
    }
}

#[cfg(any(test, feature = "test-support"))]
const SEVENTEEN_RANGES: &[&str] = &[
    "10.0.0.0/16",
    "10.1.0.0/16",
    "10.2.0.0/16",
    "10.3.0.0/16",
    "10.4.0.0/16",
    "10.5.0.0/16",
    "10.6.0.0/16",
    "10.7.0.0/16",
    "10.8.0.0/16",
    "10.9.0.0/16",
    "10.10.0.0/16",
    "10.11.0.0/16",
    "10.12.0.0/16",
    "10.13.0.0/16",
    "10.14.0.0/16",
    "10.15.0.0/16",
    "10.16.0.0/16",
];

/// The rows of the shared destination table that a selection decides.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn select_cases() -> &'static [SelectCase] {
    use DestinationProfile::{LoopbackHttp, PrivateServiceHttp, ProductionHttps};
    use DestinationSendError::{CloudMetadataDenied, PrivateAddressNotAllowed};

    const PRIVATE: Option<&str> = Some("private-network-plaintext");
    &[
        SelectCase {
            row: "T1",
            url: "https://hooks.example.org/x",
            transport: None,
            allowed_private_cidrs: &[],
            load: Ok(ProductionHttps),
            answers: &["93.184.216.34"],
            send: Some(Ok(())),
        },
        SelectCase {
            row: "T2",
            url: "https://registry.internal/",
            transport: None,
            allowed_private_cidrs: &["10.0.0.0/8"],
            load: Ok(ProductionHttps),
            answers: &["10.1.2.3"],
            send: Some(Ok(())),
        },
        SelectCase {
            row: "T3",
            url: "https://registry.internal/",
            transport: None,
            allowed_private_cidrs: &[],
            load: Ok(ProductionHttps),
            answers: &["10.1.2.3"],
            send: Some(Err(PrivateAddressNotAllowed)),
        },
        SelectCase {
            row: "T4",
            url: "http://localhost:8080/",
            transport: None,
            allowed_private_cidrs: &[],
            load: Ok(LoopbackHttp),
            answers: &["127.0.0.1"],
            send: Some(Ok(())),
        },
        SelectCase {
            row: "T5",
            url: "http://127.0.0.1:8080/",
            transport: Some("loopback-plaintext"),
            allowed_private_cidrs: &[],
            load: Ok(LoopbackHttp),
            answers: &["127.0.0.1"],
            send: Some(Ok(())),
        },
        SelectCase {
            row: "T6",
            url: "http://hooks:8080/",
            transport: None,
            allowed_private_cidrs: &["10.0.0.0/8"],
            load: Err("platform.destination.private-network-not-declared"),
            answers: &[],
            send: None,
        },
        SelectCase {
            row: "T7",
            url: "http://hooks:8080/",
            transport: PRIVATE,
            allowed_private_cidrs: &[],
            load: Err("platform.destination.private-network-requires-ranges"),
            answers: &[],
            send: None,
        },
        SelectCase {
            row: "T8",
            url: "http://hooks:8080/",
            transport: PRIVATE,
            allowed_private_cidrs: &["172.16.0.0/12"],
            load: Ok(PrivateServiceHttp),
            answers: &["172.18.0.5"],
            send: Some(Ok(())),
        },
        SelectCase {
            row: "T9",
            url: "http://hooks:8080/",
            transport: PRIVATE,
            allowed_private_cidrs: &["172.16.0.0/12"],
            load: Ok(PrivateServiceHttp),
            answers: &["10.0.0.5"],
            send: Some(Err(PrivateAddressNotAllowed)),
        },
        SelectCase {
            row: "T10",
            url: "http://hooks:8080/",
            transport: PRIVATE,
            allowed_private_cidrs: &["172.16.0.0/12"],
            load: Ok(PrivateServiceHttp),
            answers: &["172.18.0.5", "93.184.216.34"],
            send: Some(Err(PrivateAddressNotAllowed)),
        },
        SelectCase {
            row: "T11",
            url: "http://hooks:8080/",
            transport: PRIVATE,
            allowed_private_cidrs: &["fd00::/8"],
            load: Ok(PrivateServiceHttp),
            answers: &["fd00:ec2::254"],
            send: Some(Err(CloudMetadataDenied)),
        },
        SelectCase {
            row: "T12",
            url: "http://hooks:8080/",
            transport: PRIVATE,
            allowed_private_cidrs: &["169.254.0.0/16"],
            load: Err("platform.destination.range-not-private"),
            answers: &[],
            send: None,
        },
        SelectCase {
            row: "T13",
            url: "http://hooks:8080/",
            transport: PRIVATE,
            allowed_private_cidrs: &["0.0.0.0/0"],
            load: Err("platform.destination.range-not-private"),
            answers: &[],
            send: None,
        },
        SelectCase {
            row: "T14",
            url: "http://hooks:8080/",
            transport: PRIVATE,
            allowed_private_cidrs: &["10.0.0.1/8"],
            load: Err("platform.destination.range-not-canonical"),
            answers: &[],
            send: None,
        },
        SelectCase {
            row: "T15",
            url: "http://hooks:8080/",
            transport: PRIVATE,
            allowed_private_cidrs: SEVENTEEN_RANGES,
            load: Err("platform.destination.too-many-ranges"),
            answers: &[],
            send: None,
        },
        SelectCase {
            row: "T16",
            url: "https://hooks:8443/",
            transport: PRIVATE,
            allowed_private_cidrs: &["10.0.0.0/8"],
            load: Err("platform.destination.transport-scheme-mismatch"),
            answers: &[],
            send: None,
        },
        SelectCase {
            row: "T17",
            url: "http://hooks:8080/",
            transport: Some("verified-tls"),
            allowed_private_cidrs: &[],
            load: Err("platform.destination.transport-scheme-mismatch"),
            answers: &[],
            send: None,
        },
        SelectCase {
            row: "T18",
            url: "http://localhost:8080/",
            transport: PRIVATE,
            allowed_private_cidrs: &["10.0.0.0/8"],
            load: Err("platform.destination.transport-host-mismatch"),
            answers: &[],
            send: None,
        },
        SelectCase {
            row: "T19",
            url: "http://hooks:8080/",
            transport: Some("loopback-plaintext"),
            allowed_private_cidrs: &[],
            load: Err("platform.destination.transport-host-mismatch"),
            answers: &[],
            send: None,
        },
        SelectCase {
            row: "T20",
            url: "http://10.1.2.3:8080/",
            transport: PRIVATE,
            allowed_private_cidrs: &["172.16.0.0/12"],
            load: Err("platform.destination.literal-outside-ranges"),
            answers: &[],
            send: None,
        },
        SelectCase {
            row: "T23",
            url: "https://169.254.169.254/",
            transport: None,
            allowed_private_cidrs: &[],
            load: Ok(ProductionHttps),
            answers: &["169.254.169.254"],
            send: Some(Err(CloudMetadataDenied)),
        },
        SelectCase {
            row: "T25",
            url: "ftp://hooks/",
            transport: None,
            allowed_private_cidrs: &[],
            load: Err("platform.destination.unsupported-scheme"),
            answers: &[],
            send: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(raw: &str) -> Url {
        Url::parse(raw).expect("test URL parses")
    }

    fn range(raw: &str) -> PrivateRange {
        raw.parse().expect("test range parses")
    }

    fn ip(raw: &str) -> IpAddr {
        raw.parse().expect("test address parses")
    }

    fn select(raw: &str, declared: Option<TransportClass>, ranges: &[&str]) -> SelectedDestination {
        let ranges: Vec<_> = ranges.iter().map(|raw| range(raw)).collect();
        select_destination(&url(raw), declared, &ranges).expect("the destination selects")
    }

    fn refusal(
        raw: &str,
        declared: Option<TransportClass>,
        ranges: &[&str],
    ) -> DestinationSelectionError {
        let ranges: Vec<_> = ranges.iter().map(|raw| range(raw)).collect();
        select_destination(&url(raw), declared, &ranges).expect_err("the destination is refused")
    }

    #[test]
    fn every_load_row_selects_the_profile_or_code_the_table_names() {
        let mut rows = 0;
        for case in select_cases() {
            let outcome = case
                .select()
                .map(|selected| selected.profile())
                .map_err(|error| error.code());
            assert_eq!(outcome, case.load, "row {}", case.row);
            rows += 1;
        }
        assert_eq!(rows, 22, "T1 to T20, T23 and T25");
    }

    #[test]
    fn an_accepted_row_reports_its_transport_and_ranges() {
        let tls = select("https://hooks.example.org/x", None, &[]);
        assert_eq!(tls.transport(), TransportClass::VerifiedTls);
        assert!(!tls.is_private_plaintext());
        assert!(tls.allowed_private_cidrs().is_empty());

        let loopback = select(
            "http://[::1]:8080/",
            Some(TransportClass::LoopbackPlaintext),
            &[],
        );
        assert_eq!(loopback.profile(), DestinationProfile::LoopbackHttp);
        assert_eq!(loopback.transport(), TransportClass::LoopbackPlaintext);

        let private = select(
            "http://hooks:8080/",
            Some(TransportClass::PrivateNetworkPlaintext),
            &["172.16.0.0/12", "10.0.0.0/8", "172.16.0.0/12"],
        );
        assert_eq!(private.transport(), TransportClass::PrivateNetworkPlaintext);
        assert!(private.is_private_plaintext());
        let ranges: Vec<String> = private
            .allowed_private_cidrs()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            ranges,
            ["10.0.0.0/8", "172.16.0.0/12"],
            "sorted, repeats removed"
        );
    }

    #[test]
    fn a_verified_tls_destination_keeps_its_ranges_for_private_answers() {
        let selected = select(
            "https://registry.internal/",
            Some(TransportClass::VerifiedTls),
            &["10.0.0.0/8"],
        );
        assert_eq!(selected.profile(), DestinationProfile::ProductionHttps);
        assert_eq!(selected.allowed_private_cidrs().len(), 1);
    }

    #[test]
    fn the_localhost_namespace_never_selects_private_plain_text() {
        for raw in [
            "http://localhost:8080/",
            "http://LOCALHOST:8080/",
            "http://127.0.0.1:8080/",
            "http://[::1]:8080/",
            "http://[::ffff:127.0.0.1]:8080/",
            "http://a.localhost:8080/",
            "http://localhost.:8080/",
        ] {
            assert_eq!(
                refusal(
                    raw,
                    Some(TransportClass::PrivateNetworkPlaintext),
                    &["10.0.0.0/8"]
                ),
                DestinationSelectionError::TransportHostMismatch,
                "{raw}"
            );
        }
        for raw in ["http://a.localhost:8080/", "http://localhost.:8080/"] {
            assert_eq!(
                refusal(raw, None, &[]),
                DestinationSelectionError::PrivateNetworkNotDeclared,
                "{raw} is not loopback"
            );
            assert_eq!(
                refusal(raw, Some(TransportClass::LoopbackPlaintext), &[]),
                DestinationSelectionError::TransportHostMismatch,
                "{raw} is not loopback"
            );
        }
    }

    #[test]
    fn an_address_literal_selects_private_plain_text_only_inside_a_range() {
        let inside = select(
            "http://172.18.0.5:8080/",
            Some(TransportClass::PrivateNetworkPlaintext),
            &["172.16.0.0/12"],
        );
        assert_eq!(inside.profile(), DestinationProfile::PrivateServiceHttp);
        let mapped = select(
            "http://[::ffff:172.18.0.5]:8080/",
            Some(TransportClass::PrivateNetworkPlaintext),
            &["172.16.0.0/12"],
        );
        assert_eq!(mapped.profile(), DestinationProfile::PrivateServiceHttp);
        for raw in [
            "http://10.1.2.3:8080/",
            "http://8.8.8.8/",
            "http://169.254.169.254/",
            "http://[fd00::1]/",
        ] {
            assert_eq!(
                refusal(
                    raw,
                    Some(TransportClass::PrivateNetworkPlaintext),
                    &["172.16.0.0/12"]
                ),
                DestinationSelectionError::LiteralOutsideRanges,
                "{raw}"
            );
        }
    }

    #[test]
    fn a_single_metadata_range_is_refused_like_a_fixed_destination_refuses_it() {
        for raw in ["100.100.100.200/32", "fd00:ec2::254/128"] {
            for declared in [None, Some(TransportClass::PrivateNetworkPlaintext)] {
                let target = if declared.is_some() {
                    "http://hooks:8080/"
                } else {
                    "https://hooks.example.org/"
                };
                assert_eq!(
                    refusal(target, declared, &[raw]),
                    DestinationSelectionError::RangeNotPrivate,
                    "{raw}"
                );
            }
        }
        select(
            "http://hooks:8080/",
            Some(TransportClass::PrivateNetworkPlaintext),
            &["fd00:ec2::/32"],
        );
    }

    #[test]
    fn sixteen_ranges_select_and_seventeen_are_refused_under_every_transport() {
        let sixteen = &SEVENTEEN_RANGES[..16];
        select("https://hooks.example.org/", None, sixteen);
        select(
            "http://hooks:8080/",
            Some(TransportClass::PrivateNetworkPlaintext),
            sixteen,
        );
        for (raw, declared) in [
            ("https://hooks.example.org/", None),
            ("http://localhost:8080/", None),
            (
                "http://hooks:8080/",
                Some(TransportClass::PrivateNetworkPlaintext),
            ),
        ] {
            assert_eq!(
                refusal(raw, declared, SEVENTEEN_RANGES),
                DestinationSelectionError::TooManyRanges,
                "{raw}"
            );
        }
    }

    /// D2 (b): a destination that carries a credential selects https or
    /// loopback http, and never private plain text.
    #[test]
    fn a_credential_destination_never_selects_private_plain_text() {
        let ranges = [range("10.0.0.0/8")];
        for (raw, declared) in [
            ("https://idp.example.test/token", None),
            (
                "https://idp.example.test/token",
                Some(TransportClass::VerifiedTls),
            ),
            ("http://localhost:8080/token", None),
            (
                "http://127.0.0.1:8080/token",
                Some(TransportClass::LoopbackPlaintext),
            ),
        ] {
            let selected = select_credential_destination(&url(raw), declared, &ranges)
                .unwrap_or_else(|error| panic!("{raw}: {error}"));
            assert!(selected.admits_credentials(), "{raw}");
        }
        for raw in ["http://idp:8080/token", "http://10.1.2.3:8080/token"] {
            let error = select_credential_destination(
                &url(raw),
                Some(TransportClass::PrivateNetworkPlaintext),
                &ranges,
            )
            .expect_err("a credential never selects private plain text");
            assert_eq!(
                error,
                DestinationSelectionError::CredentialRequiresProtectedTransport,
                "{raw}"
            );
            assert_eq!(
                error.code(),
                "platform.destination.credential-requires-protected-transport"
            );
            assert_eq!(
                error.fix(),
                "This destination carries a credential. Serve it over https, or reach it on loopback."
            );
            let selected = select(
                raw,
                Some(TransportClass::PrivateNetworkPlaintext),
                &["10.0.0.0/8"],
            );
            assert!(!selected.admits_credentials(), "{raw}");
        }
        assert_eq!(
            select_credential_destination(&url("http://idp:8080/"), None, &ranges).unwrap_err(),
            DestinationSelectionError::PrivateNetworkNotDeclared,
            "every other refusal is the selector's own"
        );
        assert_eq!(
            select_credential_destination(
                &url("http://idp:8080/"),
                Some(TransportClass::PrivateNetworkPlaintext),
                &[],
            )
            .unwrap_err(),
            DestinationSelectionError::PrivateNetworkRequiresRanges
        );
    }

    #[test]
    fn every_refusal_has_a_platform_code_and_a_value_free_fix() {
        let all = [
            DestinationSelectionError::UnsupportedScheme,
            DestinationSelectionError::PrivateNetworkNotDeclared,
            DestinationSelectionError::PrivateNetworkRequiresRanges,
            DestinationSelectionError::TransportSchemeMismatch,
            DestinationSelectionError::TransportHostMismatch,
            DestinationSelectionError::LiteralOutsideRanges,
            DestinationSelectionError::RangeMalformed,
            DestinationSelectionError::RangeNotPrivate,
            DestinationSelectionError::RangeNotCanonical,
            DestinationSelectionError::TooManyRanges,
            DestinationSelectionError::CredentialRequiresProtectedTransport,
        ];
        let mut codes: Vec<_> = all.iter().map(DestinationSelectionError::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len(), "one code per refusal");
        for error in all {
            assert!(
                error.code().starts_with("platform.destination."),
                "{error:?}"
            );
            assert!(!error.fix().is_empty());
            assert!(!error.to_string().is_empty());
        }
        assert_eq!(
            DestinationSelectionError::PrivateNetworkNotDeclared.fix(),
            "Write transport: private-network-plaintext and allowedPrivateCidrs with the receiver's range, or serve it over https."
        );
    }

    #[test]
    fn a_range_written_in_code_takes_the_code_configuration_gives_it() {
        for (text, code) in [
            ("10.0.0.0", "platform.destination.range-malformed"),
            ("10.0.0.1/8", "platform.destination.range-not-canonical"),
            ("169.254.0.0/16", "platform.destination.range-not-private"),
        ] {
            let error = DestinationSelectionError::from(
                text.parse::<PrivateRange>()
                    .expect_err("the range is refused"),
            );
            assert_eq!(error.code(), code, "{text}");
        }
    }

    #[test]
    fn debug_never_shows_the_url() {
        let selected = select(
            "http://receiver-canary:8080/",
            Some(TransportClass::PrivateNetworkPlaintext),
            &["10.0.0.0/8"],
        );
        let rendered = format!("{selected:?}");
        assert!(!rendered.contains("receiver-canary"), "{rendered}");
        assert!(rendered.contains("PrivateServiceHttp"), "{rendered}");
    }

    /// The client family admits what the fixed family admits, with one
    /// difference ruled for M8 (D4 (c)): https keeps today's rule for a
    /// private answer, so T3 is admitted here, while the metadata address
    /// and the always-denied ranges are refused.
    #[test]
    fn every_send_row_is_decided_by_the_client_resolver_as_the_fixed_family_decides_it() {
        let mut rows = 0;
        for case in select_cases() {
            let Some(send) = case.send else { continue };
            let selected = case.select().expect("a send row selects");
            let expected = if case.row == "T3" { Ok(()) } else { send };
            let answers = case.answers.iter().map(|raw| ip(raw));
            assert_eq!(
                admit_answers(&selected, answers),
                expected,
                "row {}",
                case.row
            );
            rows += 1;
        }
        assert_eq!(rows, 10, "T1 to T5, T8 to T11 and T23");
    }

    #[test]
    fn the_client_resolver_refuses_metadata_and_always_denied_answers_over_https() {
        let tls = select("https://registry.example.org/", None, &[]);
        for (raw, expected) in [
            ("169.254.169.254", DestinationSendError::CloudMetadataDenied),
            (
                "::ffff:169.254.169.254",
                DestinationSendError::CloudMetadataDenied,
            ),
            (
                "64:ff9b::a9fe:a9fe",
                DestinationSendError::CloudMetadataDenied,
            ),
            ("100.100.100.200", DestinationSendError::CloudMetadataDenied),
            ("fd00:ec2::254", DestinationSendError::CloudMetadataDenied),
            ("127.0.0.1", DestinationSendError::AlwaysDeniedAddress),
            ("::1", DestinationSendError::AlwaysDeniedAddress),
            ("0.0.0.0", DestinationSendError::AlwaysDeniedAddress),
            ("169.254.10.1", DestinationSendError::AlwaysDeniedAddress),
            ("fe80::1", DestinationSendError::AlwaysDeniedAddress),
            ("224.0.0.1", DestinationSendError::AlwaysDeniedAddress),
            ("64:ff9b::7f00:1", DestinationSendError::AlwaysDeniedAddress),
        ] {
            assert_eq!(admit_answers(&tls, [ip(raw)]), Err(expected), "{raw}");
        }
        for raw in ["93.184.216.34", "10.1.2.3", "fd42::4", "100.64.0.1"] {
            assert_eq!(
                admit_answers(&tls, [ip(raw)]),
                Ok(()),
                "{raw} keeps today's https rule"
            );
        }
        assert_eq!(
            admit_answers(&tls, [ip("93.184.216.34"), ip("127.0.0.1")]),
            Err(DestinationSendError::AlwaysDeniedAddress),
            "one refused answer refuses them all"
        );
        assert_eq!(
            admit_answers(&tls, []),
            Err(DestinationSendError::NoResolverAnswers)
        );
    }

    #[test]
    fn the_client_resolver_keeps_loopback_plain_text_on_loopback() {
        let loopback = select("http://localhost:8080/", None, &[]);
        for raw in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            assert_eq!(admit_answers(&loopback, [ip(raw)]), Ok(()), "{raw}");
        }
        for raw in ["10.0.0.5", "93.184.216.34", "169.254.169.254"] {
            assert_eq!(
                admit_answers(&loopback, [ip(raw)]),
                Err(DestinationSendError::DevelopmentAddressDenied),
                "{raw}"
            );
        }
    }

    /// Records each name a client resolver asks for, and answers with one
    /// documentation address.
    #[derive(Default)]
    struct RecordingLookup {
        asked: std::sync::Mutex<Vec<String>>,
    }

    impl reqwest::dns::Resolve for RecordingLookup {
        fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
            self.asked
                .lock()
                .expect("lookup record")
                .push(name.as_str().to_owned());
            let answers: reqwest::dns::Addrs =
                Box::new(std::iter::once(SocketAddr::new(ip("192.0.2.1"), 0)));
            Box::pin(std::future::ready(Ok(answers)))
        }
    }

    async fn resolve_through(
        selected: &SelectedDestination,
        lookup: &Arc<RecordingLookup>,
        name: &str,
    ) -> Result<Vec<SocketAddr>, Option<DestinationSendError>> {
        let lookup: Arc<dyn reqwest::dns::Resolve> = Arc::clone(lookup) as _;
        let resolver = SelectedResolver::new(selected.clone(), lookup);
        let name = name.parse().expect("test name parses");
        match reqwest::dns::Resolve::resolve(&resolver, name).await {
            Ok(answers) => Ok(answers.collect()),
            Err(error) => Err(error.downcast_ref::<DestinationSendError>().copied()),
        }
    }

    /// A selected client resolves only its own host name. Any other name
    /// is refused before the lookup is asked, so a request sent elsewhere
    /// never reaches the system resolver.
    #[tokio::test]
    async fn a_selected_resolver_asks_only_for_the_selected_name() {
        let lookup = Arc::new(RecordingLookup::default());
        let tls = select("https://receiver.example.test:8443/", None, &[]);
        for name in [
            "receiver.example.test",
            "RECEIVER.Example.Test",
            "receiver.example.test.",
        ] {
            assert_eq!(
                resolve_through(&tls, &lookup, name).await,
                Ok(vec![SocketAddr::new(ip("192.0.2.1"), 0)]),
                "{name}"
            );
        }
        for name in [
            "other.example.test",
            "sub.receiver.example.test",
            "receiver.example.test.evil",
            "receiver.example",
            "169.254.169.254",
        ] {
            assert_eq!(
                resolve_through(&tls, &lookup, name).await,
                Err(Some(DestinationSendError::DestinationNameMismatch)),
                "{name}"
            );
        }
        // A selection made for an address literal or for the pinned
        // `localhost` never resolves another name.
        for selected in [
            select("https://192.0.2.10/", None, &[]),
            select("http://localhost:8080/", None, &[]),
        ] {
            assert_eq!(
                resolve_through(&selected, &lookup, "receiver.example.test").await,
                Err(Some(DestinationSendError::DestinationNameMismatch)),
                "{selected:?}"
            );
        }
        assert_eq!(
            lookup.asked.lock().expect("lookup record").len(),
            3,
            "only the selected name reached the lookup"
        );
    }

    #[test]
    fn a_selection_admits_only_urls_of_its_own_origin() {
        let tls = select("https://receiver.example.test:8443/base/", None, &[]);
        for raw in [
            "https://receiver.example.test:8443/",
            "https://receiver.example.test:8443/base/next?page=2",
            "https://RECEIVER.example.test:8443/other",
        ] {
            assert!(tls.admits_url(&url(raw)), "{raw}");
        }
        for raw in [
            "http://receiver.example.test:8443/",
            "https://receiver.example.test/",
            "https://other.example.test:8443/",
            "https://169.254.169.254:8443/",
        ] {
            assert!(!tls.admits_url(&url(raw)), "{raw}");
        }
        let default_port = select("https://receiver.example.test/", None, &[]);
        assert!(
            default_port.admits_url(&url("https://receiver.example.test:443/next")),
            "the default port is the same origin"
        );
    }

    fn socket(raw: &str) -> SocketAddr {
        raw.parse().expect("test socket address parses")
    }

    /// The addresses a selected fetch pins, or its refusal, and whether the
    /// lookup was asked. The lookup answers `answers` on the URL's port.
    fn fetch(
        selected: &SelectedDestination,
        answers: &[&str],
    ) -> (Result<Vec<SocketAddr>, crate::FetchUrlError>, bool) {
        let asked = std::cell::Cell::new(false);
        let result = validate_selected_fetch_resolved_by(selected, |url| {
            asked.set(true);
            let port = url.port_or_known_default().expect("test URL has a port");
            Ok(answers
                .iter()
                .map(|raw| SocketAddr::new(ip(raw), port))
                .collect())
        })
        .map(|validated| {
            assert_eq!(validated.url(), selected.url(), "the selected URL");
            validated.resolved_addrs
        });
        (result, asked.get())
    }

    fn denied(
        result: Result<Vec<SocketAddr>, crate::FetchUrlError>,
    ) -> Option<DestinationSendError> {
        match result {
            Err(crate::FetchUrlError::DestinationAddressDenied(refusal)) => Some(refusal),
            _ => None,
        }
    }

    /// A private plain-text fetch, through an injected resolution, pins its
    /// private answer and builds one GET with the caller's `Accept` as its
    /// only header and no body. Nothing is dialled, so no private route is
    /// needed.
    #[test]
    fn a_private_plain_text_fetch_builds_one_get_with_accept_only() {
        let selected = select(
            "http://feed.internal.test:8080/feed",
            Some(TransportClass::PrivateNetworkPlaintext),
            &["10.0.0.0/8"],
        );
        let validated =
            validate_selected_fetch_resolved_by(&selected, |_| Ok(vec![socket("10.1.2.3:8080")]))
                .expect("a private answer inside the range is admitted");
        assert_eq!(validated.resolved_addrs, [socket("10.1.2.3:8080")]);
        let selected_fetch = SelectedFetch(validated);

        let accept = reqwest::header::HeaderValue::from_static("application/x-test");
        let timeout = std::time::Duration::from_secs(5);
        let request = selected_fetch
            .pinned_get(&accept, timeout)
            .expect("the pinned client builds")
            .build()
            .expect("the request builds");
        assert_eq!(request.method(), reqwest::Method::GET);
        assert_eq!(request.url(), selected.url());
        assert_eq!(request.headers().len(), 1, "{:?}", request.headers());
        assert_eq!(request.headers()[reqwest::header::ACCEPT], accept);
        assert!(request.body().is_none());
        assert_eq!(request.timeout(), Some(&timeout));

        let (outside, _) = fetch(&selected, &["192.168.1.1"]);
        assert_eq!(
            denied(outside),
            Some(DestinationSendError::PrivateAddressNotAllowed)
        );
    }

    /// D3: a credential-free fetch resolves the selected name once and pins
    /// the request to answers the selection admits. Over https each answer
    /// is admitted as a fixed https destination admits it: a private answer,
    /// CGNAT included, needs a listed range (D4 (c), today's strict rule).
    #[test]
    fn a_selected_fetch_pins_only_answers_its_selection_admits() {
        let tls = select("https://records.example.test/", None, &[]);
        let (result, asked) = fetch(&tls, &["93.184.216.34"]);
        assert_eq!(
            result.expect("a public answer over https"),
            vec![socket("93.184.216.34:443")]
        );
        assert!(asked, "a name is resolved");
        let listed = select(
            "https://records.example.test/",
            None,
            &["10.0.0.0/8", "100.64.0.0/10"],
        );
        assert_eq!(
            fetch(&listed, &["93.184.216.34", "10.1.2.3", "100.64.1.2"])
                .0
                .expect("private answers inside the listed ranges"),
            vec![
                socket("93.184.216.34:443"),
                socket("10.1.2.3:443"),
                socket("100.64.1.2:443")
            ]
        );
        for (answers, expected) in [
            (
                &["93.184.216.34", "10.1.2.3"][..],
                DestinationSendError::PrivateAddressNotAllowed,
            ),
            (
                &["100.64.1.2"][..],
                DestinationSendError::PrivateAddressNotAllowed,
            ),
            (
                &["192.0.2.1"][..],
                DestinationSendError::NonGlobalAddressDenied,
            ),
            (
                &["169.254.169.254"][..],
                DestinationSendError::CloudMetadataDenied,
            ),
            (
                &["93.184.216.34", "127.0.0.1"][..],
                DestinationSendError::AlwaysDeniedAddress,
            ),
        ] {
            assert_eq!(
                denied(fetch(&tls, answers).0),
                Some(expected),
                "{answers:?}"
            );
        }
        assert!(matches!(
            fetch(&tls, &[]).0,
            Err(crate::FetchUrlError::NoAddresses)
        ));

        let private = select(
            "http://records:8080/",
            Some(TransportClass::PrivateNetworkPlaintext),
            &["10.0.0.0/8"],
        );
        assert_eq!(
            fetch(&private, &["10.0.0.5"]).0.expect("inside the range"),
            vec![socket("10.0.0.5:8080")]
        );
        for (answers, expected) in [
            (
                &["172.16.0.5"][..],
                DestinationSendError::PrivateAddressNotAllowed,
            ),
            (
                &["10.0.0.5", "93.184.216.34"][..],
                DestinationSendError::PrivateAddressNotAllowed,
            ),
            (
                &["169.254.169.254"][..],
                DestinationSendError::CloudMetadataDenied,
            ),
        ] {
            assert_eq!(
                denied(fetch(&private, answers).0),
                Some(expected),
                "{answers:?}"
            );
        }
    }

    /// A literal is checked as a selected client checks it when it is
    /// built, and `localhost` is pinned to loopback. Neither is looked up.
    #[test]
    fn a_selected_fetch_checks_literals_and_pins_localhost_without_a_lookup() {
        let private = |raw| {
            select(
                raw,
                Some(TransportClass::PrivateNetworkPlaintext),
                &["10.0.0.0/8", "fd00::/8"],
            )
        };
        for (selected, expected) in [
            (
                select("https://127.0.0.1:9443/", None, &[]),
                vec![socket("127.0.0.1:9443")],
            ),
            (
                select("http://127.0.0.1:8080/", None, &[]),
                vec![socket("127.0.0.1:8080")],
            ),
            (
                select("http://localhost:8080/", None, &[]),
                vec![socket("127.0.0.1:8080"), socket("[::1]:8080")],
            ),
            (
                select("https://localhost/", None, &[]),
                vec![socket("127.0.0.1:443"), socket("[::1]:443")],
            ),
            (
                select("https://10.1.2.3/", None, &["10.0.0.0/8"]),
                vec![socket("10.1.2.3:443")],
            ),
            (
                private("http://10.1.2.3:8080/"),
                vec![socket("10.1.2.3:8080")],
            ),
            (
                private("http://[::ffff:10.1.2.3]:8080/"),
                vec![socket("[::ffff:10.1.2.3]:8080")],
            ),
        ] {
            let (result, asked) = fetch(&selected, &["93.184.216.34"]);
            assert_eq!(result.expect("admitted"), expected, "{selected:?}");
            assert!(!asked, "{selected:?} is not looked up");
        }
        for (selected, expected) in [
            (
                select("https://10.1.2.3/", None, &[]),
                DestinationSendError::PrivateAddressNotAllowed,
            ),
            (
                select("https://169.254.169.254/", None, &[]),
                DestinationSendError::CloudMetadataDenied,
            ),
            (
                select("https://[64:ff9b::a9fe:a9fe]/", None, &[]),
                DestinationSendError::CloudMetadataDenied,
            ),
            (
                private("http://[fd00:ec2::254]:8080/"),
                DestinationSendError::CloudMetadataDenied,
            ),
        ] {
            let (result, asked) = fetch(&selected, &["93.184.216.34"]);
            assert_eq!(denied(result), Some(expected), "{selected:?}");
            assert!(!asked, "{selected:?} is not looked up");
        }
    }

    #[test]
    fn a_selected_fetch_refuses_userinfo_without_echoing_it() {
        let selected = select(
            "https://reader:fetch-canary@records.example.test/",
            None,
            &[],
        );
        let (result, asked) = fetch(&selected, &["93.184.216.34"]);
        let error = result.expect_err("userinfo is refused");
        assert!(
            matches!(error, crate::FetchUrlError::UserInfoDenied),
            "{error:?}"
        );
        assert!(!error.to_string().contains("fetch-canary"), "{error}");
        assert!(!asked, "nothing is looked up");
    }

    /// Over https an explicit loopback literal is admitted, as the loopback
    /// class rule trusts an explicit loopback host (D1). A name that resolves
    /// to loopback stays refused at resolve, and a NAT64 spelling of loopback
    /// goes through a translator, so it is not loopback.
    #[test]
    fn a_literal_host_is_checked_when_the_client_is_built() {
        for (raw, expected) in [
            (
                "https://169.254.169.254/",
                DestinationSendError::CloudMetadataDenied,
            ),
            (
                "https://[::ffff:169.254.169.254]/",
                DestinationSendError::CloudMetadataDenied,
            ),
            (
                "https://[64:ff9b::a9fe:a9fe]/",
                DestinationSendError::CloudMetadataDenied,
            ),
            (
                "https://[fd00:ec2::254]/",
                DestinationSendError::CloudMetadataDenied,
            ),
            (
                "https://0.0.0.0/",
                DestinationSendError::AlwaysDeniedAddress,
            ),
            (
                "https://169.254.10.1/",
                DestinationSendError::AlwaysDeniedAddress,
            ),
            (
                "https://[64:ff9b::7f00:1]/",
                DestinationSendError::AlwaysDeniedAddress,
            ),
        ] {
            assert_eq!(
                admit_literal_host(&select(raw, None, &[])),
                Err(expected),
                "{raw}"
            );
        }
        for raw in [
            "https://127.0.0.1:9443/",
            "https://127.0.0.2/",
            "https://[::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://10.1.2.3/",
            "https://93.184.216.34/",
        ] {
            assert_eq!(admit_literal_host(&select(raw, None, &[])), Ok(()), "{raw}");
        }
        let mapped_inside = select(
            "http://[::ffff:10.1.2.3]:8080/",
            Some(TransportClass::PrivateNetworkPlaintext),
            &["10.0.0.0/8"],
        );
        assert_eq!(admit_literal_host(&mapped_inside), Ok(()));
        let metadata_in_range = select(
            "http://[fd00:ec2::254]:8080/",
            Some(TransportClass::PrivateNetworkPlaintext),
            &["fd00::/8"],
        );
        assert_eq!(
            admit_literal_host(&metadata_in_range),
            Err(DestinationSendError::CloudMetadataDenied)
        );
        let inside = select(
            "http://10.1.2.3:8080/",
            Some(TransportClass::PrivateNetworkPlaintext),
            &["10.0.0.0/8"],
        );
        assert_eq!(admit_literal_host(&inside), Ok(()));
        assert_eq!(
            admit_literal_host(&select("http://127.0.0.1:8080/", None, &[])),
            Ok(())
        );
        assert_eq!(
            admit_literal_host(&select("https://hooks.example.org/", None, &[])),
            Ok(()),
            "a name is checked when it resolves"
        );
    }

    /// Over https the client rule judges the IPv4 address an IPv4-compatible
    /// (`::/96`) or 6to4 (`2002::/16`) form carries, as it judges the
    /// IPv4-mapped and well-known NAT64 forms, for an answer and a literal.
    #[test]
    fn the_https_client_rule_decodes_ipv4_compatible_and_6to4_forms() {
        use DestinationSendError::{AlwaysDeniedAddress, CloudMetadataDenied};
        let tls = select("https://receiver.example.test/", None, &[]);
        for (raw, expected) in [
            ("::a9fe:a9fe", CloudMetadataDenied),
            ("2002:a9fe:a9fe::1", CloudMetadataDenied),
            ("::7f00:1", AlwaysDeniedAddress),
            ("2002:7f00:1::1", AlwaysDeniedAddress),
            ("2002:a9fe:a01::1", AlwaysDeniedAddress),
        ] {
            assert_eq!(admit_answers(&tls, [ip(raw)]), Err(expected), "{raw}");
            assert_eq!(
                admit_literal_host(&select(&format!("https://[{raw}]/"), None, &[])),
                Err(expected),
                "{raw}"
            );
        }
        for raw in ["::5db8:d822", "2002:5db8:d822::1", "2002:a01:203::1"] {
            assert_eq!(admit_answers(&tls, [ip(raw)]), Ok(()), "{raw}");
        }
        for raw in ["::", "::1"] {
            assert_eq!(
                admit_answers(&tls, [ip(raw)]),
                Err(AlwaysDeniedAddress),
                "{raw}"
            );
        }
    }
}

//! Misuse-resistant fixed-origin transport substrate.
//!
//! This is not a complete `BoundedHttpPlan` API. Until Relay has a reviewed
//! plan compiler, structural operation constructors remain test-only. The
//! eventual compiler will be the sole production path that can create the
//! opaque request consumed by [`FixedDestinationPolicy::send`].
//!
//! Sensitive buffers owned by this module are zeroized on drop. Reqwest,
//! hyper, rustls, and the operating system necessarily create internal copies;
//! this module cannot guarantee erasure of those copies. It limits their API
//! lifetime and never exposes them through the opaque transport types.

use std::fmt;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use hickory_resolver::config::ResolveHosts;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{Name, RData};
use hickory_resolver::TokioResolver;
use http::header::{
    HeaderName, HeaderValue, ACCEPT_ENCODING, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, COOKIE,
    FORWARDED, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING,
    UPGRADE,
};
use http::uri::PathAndQuery;
use http::{HeaderMap, StatusCode};
use ipnet::IpNet;
use reqwest::Url;
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::time::{timeout_at, Instant};
use zeroize::Zeroizing;

use crate::{is_cloud_metadata_ip, DEFAULT_VALIDATED_FETCH_CONNECT_TIMEOUT};

/// Maximum canonical origin identifier length.
pub const MAX_DESTINATION_ORIGIN_ID_BYTES: usize = 128;
/// Maximum serialized fixed-origin URL length.
pub const MAX_DESTINATION_ORIGIN_URL_BYTES: usize = 2_048;
/// Maximum exact private CIDRs retained by one destination.
pub const MAX_DESTINATION_PRIVATE_CIDRS: usize = 16;
/// Maximum complete A/AAAA answer set accepted from the resolver.
pub const MAX_DESTINATION_RESOLVER_ANSWERS: usize = 32;
/// Maximum operation path-and-query length.
pub const MAX_DESTINATION_TARGET_BYTES: usize = 4_096;
/// Maximum fixed query components on one reviewed request template.
pub const MAX_DESTINATION_REQUEST_QUERY_COMPONENTS: usize = 32;
/// Maximum static header count on one operation.
pub const MAX_DESTINATION_REQUEST_HEADERS: usize = 32;
/// Maximum bytes in one static or authorization header value.
pub const MAX_DESTINATION_HEADER_VALUE_BYTES: usize = 8_192;
/// Maximum aggregate static request-header name and value bytes.
pub const MAX_DESTINATION_REQUEST_HEADER_BYTES: usize = 32_768;
/// Maximum request-body bytes accepted by the platform transport.
pub const MAX_DESTINATION_REQUEST_BODY_BYTES: usize = 1_048_576;
/// Maximum response-body ceiling accepted by the platform transport.
pub const MAX_DESTINATION_RESPONSE_BODY_BYTES: usize = 16_777_216;
/// Maximum parsed upstream response-header count.
pub const MAX_DESTINATION_RESPONSE_HEADERS: usize = 64;
/// Maximum aggregate parsed upstream response-header name and value bytes.
pub const MAX_DESTINATION_RESPONSE_HEADER_BYTES: usize = 65_536;
/// Frozen hard maximum for DNS, connect, send, and response body read together.
pub const MAX_DESTINATION_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
/// Process-wide ceiling for concurrent destination DNS resolutions.
pub const MAX_CONCURRENT_DESTINATION_RESOLUTIONS: usize = 32;

/// Date of the pinned IANA special-purpose and IPv6 allocation registry snapshot.
///
/// Classification below follows the IANA IPv4 and IPv6 Special-Purpose Address
/// Registries and IPv6 unicast assignments as published on 2026-07-11. Updating
/// this date requires reviewing the tables and their boundary tests together.
/// See <https://www.iana.org/assignments/iana-ipv4-special-registry/>,
/// <https://www.iana.org/assignments/iana-ipv6-special-registry/>, and
/// <https://www.iana.org/assignments/ipv6-unicast-address-assignments/>.
pub const DESTINATION_IANA_REGISTRY_SNAPSHOT: &str = "2026-07-11";

static DESTINATION_DNS_PERMITS: Semaphore =
    Semaphore::const_new(MAX_CONCURRENT_DESTINATION_RESOLUTIONS);
static DESTINATION_SYSTEM_RESOLVER: OnceLock<Option<TokioResolver>> = OnceLock::new();

/// Allocated IPv6 global-unicast prefixes from the pinned IANA registry.
///
/// `2000::/3` is the assignable pool, not an assertion that every address in
/// that pool is allocated or publicly routable. Keep this list synchronized
/// with [`DESTINATION_IANA_REGISTRY_SNAPSHOT`] and its boundary tests.
const IPV6_GLOBAL_UNICAST_ALLOCATIONS: &[(Ipv6Addr, u32)] = &[
    (Ipv6Addr::new(0x2001, 0x0200, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x0400, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x0600, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x0800, 0, 0, 0, 0, 0, 0), 22),
    (Ipv6Addr::new(0x2001, 0x0c00, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x0e00, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x1200, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x1400, 0, 0, 0, 0, 0, 0), 22),
    (Ipv6Addr::new(0x2001, 0x1800, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x1a00, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x1c00, 0, 0, 0, 0, 0, 0), 22),
    (Ipv6Addr::new(0x2001, 0x2000, 0, 0, 0, 0, 0, 0), 19),
    (Ipv6Addr::new(0x2001, 0x4000, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x4200, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x4400, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x4600, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x4800, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x4a00, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x4c00, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x5000, 0, 0, 0, 0, 0, 0), 20),
    (Ipv6Addr::new(0x2001, 0x8000, 0, 0, 0, 0, 0, 0), 19),
    (Ipv6Addr::new(0x2001, 0xa000, 0, 0, 0, 0, 0, 0), 20),
    (Ipv6Addr::new(0x2001, 0xb000, 0, 0, 0, 0, 0, 0), 20),
    (Ipv6Addr::new(0x2003, 0, 0, 0, 0, 0, 0, 0), 18),
    (Ipv6Addr::new(0x2400, 0, 0, 0, 0, 0, 0, 0), 12),
    (Ipv6Addr::new(0x2410, 0, 0, 0, 0, 0, 0, 0), 12),
    (Ipv6Addr::new(0x2600, 0, 0, 0, 0, 0, 0, 0), 12),
    (Ipv6Addr::new(0x2610, 0, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2620, 0, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2630, 0, 0, 0, 0, 0, 0, 0), 12),
    (Ipv6Addr::new(0x2800, 0, 0, 0, 0, 0, 0, 0), 12),
    (Ipv6Addr::new(0x2a00, 0, 0, 0, 0, 0, 0, 0), 12),
    (Ipv6Addr::new(0x2a10, 0, 0, 0, 0, 0, 0, 0), 12),
    (Ipv6Addr::new(0x2c00, 0, 0, 0, 0, 0, 0, 0), 12),
];

mod sealed {
    pub trait Sealed {}
}

/// Type-level slot separating registry-data destinations from credential endpoints.
pub trait DestinationSlot: sealed::Sealed {
    #[doc(hidden)]
    const DEBUG_NAME: &'static str;
    #[doc(hidden)]
    const CREDENTIAL_EXCHANGE: bool;
}

/// Registry-data destination marker.
pub enum DataDestination {}

impl sealed::Sealed for DataDestination {}
impl DestinationSlot for DataDestination {
    const DEBUG_NAME: &'static str = "data";
    const CREDENTIAL_EXCHANGE: bool = false;
}

/// Credential-exchange destination marker.
pub enum CredentialDestination {}

impl sealed::Sealed for CredentialDestination {}
impl DestinationSlot for CredentialDestination {
    const DEBUG_NAME: &'static str = "credential";
    const CREDENTIAL_EXCHANGE: bool = true;
}

/// Runtime class for a fixed outbound destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationProfile {
    /// HTTPS with production address controls.
    ProductionHttps,
    /// Plain HTTP to an explicitly configured loopback host for development.
    LoopbackDevelopmentHttp,
    /// Test-only HTTPS profile that remains confined to loopback addresses.
    #[cfg(test)]
    PinnedLoopbackHttpsTest,
}

/// Fixed data or credential origin plus its exact private-network allowlist.
///
/// The slot parameter prevents data and credential policies from being
/// interchanged. This type intentionally exposes neither its origin URL nor
/// resolved addresses. Its `Debug` implementation redacts all binding values.
///
/// ```compile_fail
/// use registry_platform_httputil::destination::{
///     CredentialDestinationPolicy, DataDestinationRequest,
/// };
/// use std::time::Duration;
///
/// async fn cannot_cross_slots(
///     credential: &CredentialDestinationPolicy,
///     data_request: DataDestinationRequest,
/// ) {
///     credential
///         .send(data_request, Duration::from_secs(1))
///         .await
///         .unwrap();
/// }
/// ```
pub struct FixedDestinationPolicy<S: DestinationSlot> {
    origin_id: String,
    origin: Url,
    profile: DestinationProfile,
    allowed_private_cidrs: Vec<IpNet>,
    slot: PhantomData<fn() -> S>,
}

/// Registry-data fixed destination policy.
pub type DataDestinationPolicy = FixedDestinationPolicy<DataDestination>;
/// Credential-exchange fixed destination policy.
pub type CredentialDestinationPolicy = FixedDestinationPolicy<CredentialDestination>;

impl<S: DestinationSlot> fmt::Debug for FixedDestinationPolicy<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedDestinationPolicy")
            .field("slot", &S::DEBUG_NAME)
            .field("origin_id", &"[REDACTED]")
            .field("origin", &"[REDACTED]")
            .field("profile", &self.profile)
            .field("private_cidr_count", &self.allowed_private_cidrs.len())
            .finish()
    }
}

impl<S: DestinationSlot> FixedDestinationPolicy<S> {
    /// Validate and freeze a destination binding.
    ///
    /// Length and count bounds are checked before URL parsing or policy-owned
    /// allocation. An origin id is canonical lowercase ASCII using alphanumeric
    /// characters with internal `.`, `_`, `:`, or `-` separators. Each CIDR
    /// must be wholly contained by RFC 1918, RFC 6598 CGNAT, or IPv6 ULA space.
    pub fn new(
        origin_id: &str,
        origin: &str,
        profile: DestinationProfile,
        allowed_private_cidrs: &[IpNet],
    ) -> Result<Self, DestinationPolicyError> {
        if origin_id.len() > MAX_DESTINATION_ORIGIN_ID_BYTES {
            return Err(DestinationPolicyError::OriginIdTooLong);
        }
        if origin.len() > MAX_DESTINATION_ORIGIN_URL_BYTES {
            return Err(DestinationPolicyError::OriginUrlTooLong);
        }
        if allowed_private_cidrs.len() > MAX_DESTINATION_PRIVATE_CIDRS {
            return Err(DestinationPolicyError::TooManyPrivateCidrs);
        }
        if !is_canonical_origin_id(origin_id) {
            return Err(DestinationPolicyError::InvalidOriginId);
        }

        let origin = Url::parse(origin).map_err(|_| DestinationPolicyError::InvalidOriginUrl)?;
        if origin.as_str().len() > MAX_DESTINATION_ORIGIN_URL_BYTES {
            return Err(DestinationPolicyError::OriginUrlTooLong);
        }
        if !origin.username().is_empty() || origin.password().is_some() {
            return Err(DestinationPolicyError::OriginUserInfoDenied);
        }
        if origin.host().is_none() {
            return Err(DestinationPolicyError::OriginMissingHost);
        }
        let port = origin
            .port_or_known_default()
            .ok_or(DestinationPolicyError::OriginMissingPort)?;
        if port == 0 {
            return Err(DestinationPolicyError::OriginPortZero);
        }
        if origin.path() != "/" || origin.query().is_some() || origin.fragment().is_some() {
            return Err(DestinationPolicyError::OriginHasResourceComponents);
        }

        match profile {
            DestinationProfile::ProductionHttps if origin.scheme() != "https" => {
                return Err(DestinationPolicyError::ProductionRequiresHttps);
            }
            DestinationProfile::LoopbackDevelopmentHttp => {
                if origin.scheme() != "http" {
                    return Err(DestinationPolicyError::DevelopmentRequiresHttp);
                }
                if !origin_explicitly_denotes_loopback(&origin) {
                    return Err(DestinationPolicyError::DevelopmentRequiresLoopbackHost);
                }
            }
            #[cfg(test)]
            DestinationProfile::PinnedLoopbackHttpsTest if origin.scheme() != "https" => {
                return Err(DestinationPolicyError::ProductionRequiresHttps);
            }
            DestinationProfile::ProductionHttps => {}
            #[cfg(test)]
            DestinationProfile::PinnedLoopbackHttpsTest => {}
        }

        for cidr in allowed_private_cidrs {
            let canonical = cidr.trunc();
            if canonical != *cidr {
                return Err(DestinationPolicyError::PrivateCidrNotCanonical);
            }
            if !cidr_is_eligible_private(canonical) || cidr_is_metadata_singleton(canonical) {
                return Err(DestinationPolicyError::PrivateCidrDenied);
            }
        }

        let mut retained = Vec::with_capacity(allowed_private_cidrs.len());
        retained.extend(allowed_private_cidrs.iter().map(IpNet::trunc));
        retained.sort_unstable();
        retained.dedup();

        Ok(Self {
            origin_id: origin_id.to_owned(),
            origin,
            profile,
            allowed_private_cidrs: retained,
            slot: PhantomData,
        })
    }

    /// Stable non-secret identifier suitable for restricted audit metadata.
    #[must_use]
    pub fn origin_id(&self) -> &str {
        &self.origin_id
    }

    /// Resolve, validate, pin, and send exactly one bounded request.
    ///
    /// The caller supplies the remaining plan deadline. It must be positive and
    /// no greater than [`MAX_DESTINATION_OPERATION_TIMEOUT`]. DNS, connect, send,
    /// and the eventual bounded body read share one absolute deadline. The
    /// request is consumed, and neither a client nor request builder is exposed.
    pub async fn send(
        &self,
        request: BoundedDestinationRequest<S>,
        remaining: Duration,
    ) -> Result<BoundedDestinationResponse<S>, DestinationSendError> {
        self.send_with_resolver(request, remaining, &SystemResolver, TransportTrust::System)
            .await
    }

    async fn send_with_resolver<R: Resolver>(
        &self,
        request: BoundedDestinationRequest<S>,
        remaining: Duration,
        resolver: &R,
        trust: TransportTrust,
    ) -> Result<BoundedDestinationResponse<S>, DestinationSendError> {
        if remaining.is_zero() || remaining > MAX_DESTINATION_OPERATION_TIMEOUT {
            return Err(DestinationSendError::InvalidRemainingTimeout);
        }
        let deadline = Instant::now()
            .checked_add(remaining)
            .ok_or(DestinationSendError::InvalidRemainingTimeout)?;
        let host = self
            .origin
            .host_str()
            .ok_or(DestinationSendError::InvalidFrozenPolicy)?;
        let port = self
            .origin
            .port_or_known_default()
            .ok_or(DestinationSendError::InvalidFrozenPolicy)?;

        let answers = match self.origin.host() {
            Some(::url::Host::Domain(domain)) => {
                let permit = timeout_at(deadline, DESTINATION_DNS_PERMITS.acquire())
                    .await
                    .map_err(|_| DestinationSendError::DeadlineExceeded)?
                    .map_err(|_| DestinationSendError::ResolutionCapacityUnavailable)?;
                let answers = timeout_at(deadline, resolver.resolve(domain, port))
                    .await
                    .map_err(|_| DestinationSendError::DeadlineExceeded)??;
                drop(permit);
                answers
            }
            Some(::url::Host::Ipv4(ip)) => {
                ResolvedAnswers::try_collect([SocketAddr::new(IpAddr::V4(ip), port)])?
            }
            Some(::url::Host::Ipv6(ip)) => {
                ResolvedAnswers::try_collect([SocketAddr::new(IpAddr::V6(ip), port)])?
            }
            None => return Err(DestinationSendError::InvalidFrozenPolicy),
        };
        let pinned = self.classify_answers(answers)?;

        let request_remaining = deadline.saturating_duration_since(Instant::now());
        if request_remaining.is_zero() {
            return Err(DestinationSendError::DeadlineExceeded);
        }
        let client_builder = reqwest::Client::builder()
            .timeout(request_remaining)
            .connect_timeout(request_remaining.min(DEFAULT_VALIDATED_FETCH_CONNECT_TIMEOUT))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .retry(reqwest::retry::never())
            .pool_max_idle_per_host(0)
            // Freeze HTTP/1 so future feature unification cannot silently
            // introduce a different header-compression/allocation surface.
            // Hyper's HTTP/1 parser has its own finite pre-exposure limits;
            // `validate_response_headers` then enforces the tighter platform
            // acceptance bound before a response reaches the caller.
            .http1_only()
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .resolve_to_addrs(host, pinned.as_slice());
        let client_builder = match trust {
            TransportTrust::System => client_builder,
            #[cfg(test)]
            TransportTrust::TestRoot(root) => client_builder.add_root_certificate(root),
        };
        let client = client_builder
            .build()
            .map_err(|_| DestinationSendError::ClientBuildFailed)?;

        let BoundedDestinationRequest {
            method,
            target,
            headers,
            authorization,
            body,
            slot: _,
        } = request;
        let target = std::str::from_utf8(target.as_slice())
            .map_err(|_| DestinationSendError::InvalidFrozenRequest)?;
        let target = PathAndQuery::from_str(target)
            .map_err(|_| DestinationSendError::InvalidFrozenRequest)?;
        let mut operation_url = self.origin.clone();
        operation_url.set_path(target.path());
        operation_url.set_query(target.query());

        let mut reqwest_headers = HeaderMap::with_capacity(headers.len());
        for header in &headers {
            let mut value = HeaderValue::from_bytes(header.value.as_slice())
                .map_err(|_| DestinationSendError::InvalidFrozenRequest)?;
            value.set_sensitive(true);
            reqwest_headers.insert(header.name.clone(), value);
        }

        let mut builder = client
            .request(method.as_reqwest(), operation_url)
            .headers(reqwest_headers);
        if let Some(authorization) = authorization {
            let mut value = HeaderValue::from_bytes(authorization.value.as_slice())
                .map_err(|_| DestinationSendError::InvalidFrozenRequest)?;
            value.set_sensitive(true);
            builder = builder.header(AUTHORIZATION, value);
        }
        if let Some(body) = body {
            builder = builder.body(sensitive_reqwest_body(body));
        }

        let response = timeout_at(deadline, builder.send())
            .await
            .map_err(|_| DestinationSendError::DeadlineExceeded)?
            .map_err(|_| DestinationSendError::TransportFailed)?;
        validate_response_headers(response.headers())?;

        Ok(BoundedDestinationResponse {
            response,
            deadline,
            slot: PhantomData,
        })
    }

    fn classify_answers(
        &self,
        answers: ResolvedAnswers,
    ) -> Result<PinnedAddresses, DestinationSendError> {
        if answers.is_empty() {
            return Err(DestinationSendError::NoResolverAnswers);
        }
        let literal_origin_ip = self.origin.host().and_then(|host| match host {
            ::url::Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
            ::url::Host::Ipv6(ip) => Some(normalize_ipv4_mapped(IpAddr::V6(ip))),
            ::url::Host::Domain(_) => None,
        });

        let mut pinned = PinnedAddresses::new();
        for &answer in answers.as_slice() {
            let normalized = normalize_ipv4_mapped(answer.ip());
            if answer.port() != self.port() {
                return Err(DestinationSendError::ResolverPortMismatch);
            }
            if literal_origin_ip.is_some_and(|expected| expected != normalized) {
                return Err(DestinationSendError::LiteralOriginMismatch);
            }
            self.classify_address(normalized)?;
            pinned.push_unique(SocketAddr::new(normalized, answer.port()));
        }
        Ok(pinned)
    }

    fn classify_address(&self, ip: IpAddr) -> Result<(), DestinationSendError> {
        match self.profile {
            DestinationProfile::LoopbackDevelopmentHttp => {
                if is_loopback(ip) {
                    Ok(())
                } else {
                    Err(DestinationSendError::DevelopmentAddressDenied)
                }
            }
            #[cfg(test)]
            DestinationProfile::PinnedLoopbackHttpsTest => {
                if is_loopback(ip) {
                    Ok(())
                } else {
                    Err(DestinationSendError::DevelopmentAddressDenied)
                }
            }
            DestinationProfile::ProductionHttps => {
                if let IpAddr::V6(ipv6) = ip {
                    if let Some(embedded) = decode_well_known_nat64(ipv6) {
                        return self.classify_address(IpAddr::V4(embedded));
                    }
                }
                if is_cloud_metadata_ip(ip) {
                    return Err(DestinationSendError::CloudMetadataDenied);
                }
                if is_always_denied_in_production(ip) {
                    return Err(DestinationSendError::AlwaysDeniedAddress);
                }
                if is_globally_routable(ip) {
                    return Ok(());
                }
                if is_eligible_private_address(ip) {
                    if self
                        .allowed_private_cidrs
                        .iter()
                        .any(|cidr| cidr.contains(&ip))
                    {
                        return Ok(());
                    }
                    return Err(DestinationSendError::PrivateAddressNotAllowed);
                }
                Err(DestinationSendError::NonGlobalAddressDenied)
            }
        }
    }

    fn port(&self) -> u16 {
        self.origin
            .port_or_known_default()
            .expect("fixed destination construction proves a port")
    }
}

/// Owns the caller's zeroizing allocation while `Bytes` and reqwest retain it.
///
/// `Bytes::from_owner` lets the request body share this allocation without a
/// caller-created ordinary `Vec<u8>` copy. The owner zeroizes that allocation
/// when the last shared `Bytes` reference is dropped. Reqwest, hyper, TLS, and
/// operating-system transports may make additional internal copies whose
/// erasure this crate cannot control.
struct SensitiveRequestBodyOwner(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for SensitiveRequestBodyOwner {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SensitiveRequestBodyOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveRequestBodyOwner([REDACTED])")
    }
}

fn sensitive_reqwest_body(body: Zeroizing<Vec<u8>>) -> reqwest::Body {
    reqwest::Body::from(Bytes::from_owner(SensitiveRequestBodyOwner(body)))
}

/// Value-free fixed-destination configuration failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DestinationPolicyError {
    #[error("destination origin id exceeds the platform bound")]
    OriginIdTooLong,
    #[error("destination origin id is not canonical lowercase ASCII")]
    InvalidOriginId,
    #[error("destination origin URL exceeds the platform bound")]
    OriginUrlTooLong,
    #[error("destination has too many private CIDRs")]
    TooManyPrivateCidrs,
    #[error("destination origin URL is invalid")]
    InvalidOriginUrl,
    #[error("destination origin userinfo is denied")]
    OriginUserInfoDenied,
    #[error("destination origin is missing a host")]
    OriginMissingHost,
    #[error("destination origin is missing a port")]
    OriginMissingPort,
    #[error("destination origin port zero is denied")]
    OriginPortZero,
    #[error("destination origin contains resource components")]
    OriginHasResourceComponents,
    #[error("production destination requires HTTPS")]
    ProductionRequiresHttps,
    #[error("loopback development destination requires HTTP")]
    DevelopmentRequiresHttp,
    #[error("loopback development destination requires an explicit loopback host")]
    DevelopmentRequiresLoopbackHost,
    #[error("private CIDR is outside eligible private address space")]
    PrivateCidrDenied,
    #[error("private CIDR contains host bits instead of an exact network")]
    PrivateCidrNotCanonical,
}

/// Method class compiled into a bounded operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationMethod {
    Get,
    /// POST whose exact product operation has been independently reviewed as read-only.
    ReviewedReadOnlyPost,
    /// OAuth 2.0 client-credentials POST, valid only for a credential destination slot.
    OAuth2ClientCredentialsPost,
}

impl DestinationMethod {
    fn as_reqwest(self) -> reqwest::Method {
        match self {
            Self::Get => reqwest::Method::GET,
            Self::ReviewedReadOnlyPost | Self::OAuth2ClientCredentialsPost => reqwest::Method::POST,
        }
    }
}

/// Typed authorization injection. The header name cannot be caller-controlled.
pub struct DestinationAuthorization {
    value: Zeroizing<Vec<u8>>,
}

impl DestinationAuthorization {
    /// Retain a syntactically valid bounded authorization value in zeroizing memory.
    #[cfg(test)]
    fn new(value: Vec<u8>) -> Result<Self, DestinationRequestError> {
        let value = Zeroizing::new(value);
        if value.is_empty()
            || value.len() > MAX_DESTINATION_HEADER_VALUE_BYTES
            || !is_valid_header_value(&value)
        {
            return Err(DestinationRequestError::InvalidAuthorization);
        }
        Ok(Self { value })
    }
}

impl fmt::Debug for DestinationAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DestinationAuthorization([REDACTED])")
    }
}

/// Authorization presence, scheme, and maximum rendered header bytes frozen by a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationAuthorizationTemplate {
    Forbidden,
    Basic { max_value_bytes: usize },
    Bearer { max_value_bytes: usize },
}

impl DestinationAuthorizationTemplate {
    fn max_value_bytes(self) -> usize {
        match self {
            Self::Forbidden => 0,
            Self::Basic { max_value_bytes } | Self::Bearer { max_value_bytes } => max_value_bytes,
        }
    }
}

/// Request-body presence and byte ceiling frozen by a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationBodyTemplate {
    Forbidden,
    Required { max_bytes: usize },
}

impl DestinationBodyTemplate {
    fn max_bytes(self) -> usize {
        match self {
            Self::Forbidden => 0,
            Self::Required { max_bytes } => max_bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestinationAuthorizationKind {
    Basic,
    Bearer,
}

/// Opaque typed authorization value produced by a credential provider.
///
/// Callers provide only scheme payload bytes. The fixed header name and scheme
/// prefix are constructed here, and `Debug` never exposes the retained value.
pub struct DestinationAuthorizationValue {
    kind: DestinationAuthorizationKind,
    value: Zeroizing<Vec<u8>>,
}

impl DestinationAuthorizationValue {
    /// Build a Basic value from a provider-produced base64 credential payload.
    pub fn basic(encoded_credentials: Vec<u8>) -> Result<Self, DestinationRequestError> {
        Self::with_prefix(
            DestinationAuthorizationKind::Basic,
            b"Basic ",
            encoded_credentials,
        )
    }

    /// Build a Bearer value from a provider-produced token payload.
    pub fn bearer(token: Vec<u8>) -> Result<Self, DestinationRequestError> {
        Self::with_prefix(DestinationAuthorizationKind::Bearer, b"Bearer ", token)
    }

    fn with_prefix(
        kind: DestinationAuthorizationKind,
        prefix: &[u8],
        payload: Vec<u8>,
    ) -> Result<Self, DestinationRequestError> {
        let payload = Zeroizing::new(payload);
        if payload.is_empty() {
            return Err(DestinationRequestError::InvalidAuthorization);
        }
        let mut value = Zeroizing::new(Vec::with_capacity(prefix.len() + payload.len()));
        value.extend_from_slice(prefix);
        value.extend_from_slice(payload.as_slice());
        if value.len() > MAX_DESTINATION_HEADER_VALUE_BYTES || !is_valid_header_value(&value) {
            return Err(DestinationRequestError::InvalidAuthorization);
        }
        Ok(Self { kind, value })
    }
}

impl fmt::Debug for DestinationAuthorizationValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DestinationAuthorizationValue([REDACTED])")
    }
}

struct QueryValueTemplate {
    name: String,
    max_value_bytes: usize,
}

enum HeaderValueTemplate {
    Dynamic {
        name: HeaderName,
        max_value_bytes: usize,
    },
    Exact {
        name: HeaderName,
        value: Box<[u8]>,
    },
}

impl HeaderValueTemplate {
    fn name(&self) -> &HeaderName {
        match self {
            Self::Dynamic { name, .. } | Self::Exact { name, .. } => name,
        }
    }

    fn max_value_bytes(&self) -> usize {
        match self {
            Self::Dynamic {
                max_value_bytes, ..
            } => *max_value_bytes,
            Self::Exact { value, .. } => value.len(),
        }
    }

    fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic { .. })
    }
}

enum HeaderTemplateInput<'a> {
    Dynamic {
        name: &'a str,
        max_value_bytes: usize,
    },
    Exact {
        name: &'a str,
        value: &'a [u8],
    },
}

enum RequestTemplateKind {
    General(DestinationMethod),
    OAuth2ClientCredentials(OAuth2ClientCredentialsBodyFormat),
}

/// Slot-typed, immutable request shape compiled before any sensitive values exist.
///
/// The template freezes the method, fixed path, query/header names, and reviewed
/// worst-case sizes. Rendering accepts values only in that exact order, builds
/// the canonical target itself, rechecks the aggregate request budget, and is
/// the production constructor for the opaque request capability.
pub struct BoundedDestinationRequestTemplate<S: DestinationSlot> {
    method: DestinationMethod,
    fixed_path: String,
    query: Vec<QueryValueTemplate>,
    headers: Vec<HeaderValueTemplate>,
    authorization: DestinationAuthorizationTemplate,
    body: DestinationBodyTemplate,
    max_target_bytes: usize,
    max_request_bytes: usize,
    slot: PhantomData<fn() -> S>,
}

/// Reviewed data-destination request template.
pub type DataDestinationRequestTemplate = BoundedDestinationRequestTemplate<DataDestination>;
/// Reviewed credential-destination request template.
pub type CredentialDestinationRequestTemplate =
    BoundedDestinationRequestTemplate<CredentialDestination>;

/// Closed OAuth 2.0 client-credentials request-body encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuth2ClientCredentialsBodyFormat {
    JsonClientSecretBody,
    FormClientSecretBody,
}

impl BoundedDestinationRequestTemplate<CredentialDestination> {
    /// Compile the only credential-destination request shape accepted in v1.
    ///
    /// ```compile_fail
    /// use registry_platform_httputil::destination::{
    ///     CredentialDestinationRequestTemplate, DataDestinationRequest,
    ///     OAuth2ClientCredentialsBodyFormat,
    /// };
    ///
    /// fn data_only(_: DataDestinationRequest) {}
    ///
    /// let template = CredentialDestinationRequestTemplate::oauth2_client_credentials(
    ///     "/oauth/token",
    ///     OAuth2ClientCredentialsBodyFormat::JsonClientSecretBody,
    ///     1024,
    ///     2048,
    /// ).unwrap();
    /// let request = template.render(&[], &[], None, Some(b"{}".to_vec())).unwrap();
    /// data_only(request);
    /// ```
    pub fn oauth2_client_credentials(
        fixed_path: &str,
        format: OAuth2ClientCredentialsBodyFormat,
        max_body_bytes: usize,
        max_request_bytes: usize,
    ) -> Result<Self, DestinationRequestError> {
        let content_type: &[u8] = match format {
            OAuth2ClientCredentialsBodyFormat::JsonClientSecretBody => b"application/json",
            OAuth2ClientCredentialsBodyFormat::FormClientSecretBody => {
                b"application/x-www-form-urlencoded"
            }
        };
        let headers = [
            HeaderTemplateInput::Exact {
                name: "accept",
                value: b"application/json",
            },
            HeaderTemplateInput::Exact {
                name: "content-type",
                value: content_type,
            },
        ];
        Self::new_with_headers(
            RequestTemplateKind::OAuth2ClientCredentials(format),
            fixed_path,
            &[],
            &headers,
            DestinationAuthorizationTemplate::Forbidden,
            DestinationBodyTemplate::Required {
                max_bytes: max_body_bytes,
            },
            max_request_bytes,
        )
    }
}

impl<S: DestinationSlot> fmt::Debug for BoundedDestinationRequestTemplate<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedDestinationRequestTemplate")
            .field("slot", &S::DEBUG_NAME)
            .field("method", &self.method)
            .field("fixed_path", &"[REDACTED]")
            .field("query_count", &self.query.len())
            .field("header_count", &self.headers.len())
            .field("authorization", &self.authorization)
            .field("body", &self.body)
            .field("max_request_bytes", &self.max_request_bytes)
            .finish()
    }
}

impl<S: DestinationSlot> BoundedDestinationRequestTemplate<S> {
    /// Validate and freeze a reviewed request shape.
    pub fn new(
        method: DestinationMethod,
        fixed_path: &str,
        query: &[(&str, usize)],
        headers: &[(&str, usize)],
        authorization: DestinationAuthorizationTemplate,
        body: DestinationBodyTemplate,
        max_request_bytes: usize,
    ) -> Result<Self, DestinationRequestError> {
        if method == DestinationMethod::OAuth2ClientCredentialsPost {
            return Err(DestinationRequestError::MethodSlotMismatch);
        }
        let headers = headers
            .iter()
            .map(|(name, max_value_bytes)| HeaderTemplateInput::Dynamic {
                name,
                max_value_bytes: *max_value_bytes,
            })
            .collect::<Vec<_>>();
        Self::new_with_headers(
            RequestTemplateKind::General(method),
            fixed_path,
            query,
            &headers,
            authorization,
            body,
            max_request_bytes,
        )
    }

    /// Validate and freeze a request whose non-authorization header values are exact.
    pub fn new_with_exact_headers(
        method: DestinationMethod,
        fixed_path: &str,
        query: &[(&str, usize)],
        headers: &[(&str, &[u8])],
        authorization: DestinationAuthorizationTemplate,
        body: DestinationBodyTemplate,
        max_request_bytes: usize,
    ) -> Result<Self, DestinationRequestError> {
        if method == DestinationMethod::OAuth2ClientCredentialsPost {
            return Err(DestinationRequestError::MethodSlotMismatch);
        }
        let headers = headers
            .iter()
            .map(|(name, value)| HeaderTemplateInput::Exact { name, value })
            .collect::<Vec<_>>();
        Self::new_with_headers(
            RequestTemplateKind::General(method),
            fixed_path,
            query,
            &headers,
            authorization,
            body,
            max_request_bytes,
        )
    }

    fn new_with_headers(
        kind: RequestTemplateKind,
        fixed_path: &str,
        query: &[(&str, usize)],
        headers: &[HeaderTemplateInput<'_>],
        authorization: DestinationAuthorizationTemplate,
        body: DestinationBodyTemplate,
        max_request_bytes: usize,
    ) -> Result<Self, DestinationRequestError> {
        let (method, oauth_format) = match kind {
            RequestTemplateKind::General(method) => (method, None),
            RequestTemplateKind::OAuth2ClientCredentials(format) => {
                (DestinationMethod::OAuth2ClientCredentialsPost, Some(format))
            }
        };
        validate_fixed_destination_path(fixed_path)?;
        if query.len() > MAX_DESTINATION_REQUEST_QUERY_COMPONENTS {
            return Err(DestinationRequestError::TooManyQueryComponents);
        }
        if headers.len() + usize::from(authorization != DestinationAuthorizationTemplate::Forbidden)
            > MAX_DESTINATION_REQUEST_HEADERS
        {
            return Err(DestinationRequestError::TooManyHeaders);
        }
        if method == DestinationMethod::OAuth2ClientCredentialsPost
            && (!query.is_empty()
                || !closed_oauth_headers(
                    headers,
                    oauth_format.ok_or(DestinationRequestError::MethodSlotMismatch)?,
                ))
        {
            return Err(DestinationRequestError::MethodSlotMismatch);
        }
        let max_body_bytes = body.max_bytes();
        if max_body_bytes > MAX_DESTINATION_REQUEST_BODY_BYTES {
            return Err(DestinationRequestError::BodyTooLarge);
        }
        match method {
            DestinationMethod::Get if S::CREDENTIAL_EXCHANGE => {
                return Err(DestinationRequestError::MethodSlotMismatch);
            }
            DestinationMethod::Get if body != DestinationBodyTemplate::Forbidden => {
                return Err(DestinationRequestError::GetBodyDenied);
            }
            DestinationMethod::ReviewedReadOnlyPost
                if S::CREDENTIAL_EXCHANGE
                    || !matches!(body, DestinationBodyTemplate::Required { max_bytes } if max_bytes > 0) =>
            {
                return Err(DestinationRequestError::MethodSlotMismatch);
            }
            DestinationMethod::OAuth2ClientCredentialsPost
                if !S::CREDENTIAL_EXCHANGE
                    || authorization != DestinationAuthorizationTemplate::Forbidden
                    || !matches!(body, DestinationBodyTemplate::Required { max_bytes } if max_bytes > 0) =>
            {
                return Err(DestinationRequestError::MethodSlotMismatch);
            }
            _ => {}
        }
        let max_authorization_bytes = authorization.max_value_bytes();
        let authorization_bound_valid = match authorization {
            DestinationAuthorizationTemplate::Forbidden => true,
            DestinationAuthorizationTemplate::Basic { max_value_bytes } => {
                (7..=MAX_DESTINATION_HEADER_VALUE_BYTES).contains(&max_value_bytes)
            }
            DestinationAuthorizationTemplate::Bearer { max_value_bytes } => {
                (8..=MAX_DESTINATION_HEADER_VALUE_BYTES).contains(&max_value_bytes)
            }
        };
        if !authorization_bound_valid {
            return Err(DestinationRequestError::InvalidAuthorization);
        }

        let mut target_bytes = fixed_path.len();
        let mut retained_query = Vec::with_capacity(query.len());
        for (index, (name, max_value_bytes)) in query.iter().copied().enumerate() {
            if name.is_empty()
                || name.len() > 128
                || !name.is_ascii()
                || name.chars().any(char::is_control)
            {
                return Err(DestinationRequestError::InvalidTarget);
            }
            target_bytes = target_bytes
                .checked_add(usize::from(index == 0))
                .and_then(|total| total.checked_add(usize::from(index > 0)))
                .and_then(|total| total.checked_add(name.len().saturating_mul(3)))
                .and_then(|total| total.checked_add(1))
                .and_then(|total| total.checked_add(max_value_bytes.saturating_mul(3)))
                .ok_or(DestinationRequestError::TemplateBoundsExceeded)?;
            retained_query.push(QueryValueTemplate {
                name: name.to_owned(),
                max_value_bytes,
            });
        }
        if target_bytes > MAX_DESTINATION_TARGET_BYTES {
            return Err(DestinationRequestError::TargetTooLong);
        }

        let mut header_bytes = if max_authorization_bytes == 0 {
            0
        } else {
            AUTHORIZATION.as_str().len() + max_authorization_bytes
        };
        let mut retained_headers = Vec::with_capacity(headers.len());
        for (index, header) in headers.iter().enumerate() {
            let (raw_name, max_value_bytes, exact_value) = match header {
                HeaderTemplateInput::Dynamic {
                    name,
                    max_value_bytes,
                } => (*name, *max_value_bytes, None),
                HeaderTemplateInput::Exact { name, value } => (*name, value.len(), Some(*value)),
            };
            let name = HeaderName::from_str(raw_name)
                .map_err(|_| DestinationRequestError::ForbiddenHeader)?;
            if is_forbidden_static_request_header(&name) {
                return Err(DestinationRequestError::ForbiddenHeader);
            }
            if retained_headers[..index]
                .iter()
                .any(|prior: &HeaderValueTemplate| prior.name() == name)
            {
                return Err(DestinationRequestError::DuplicateHeader);
            }
            if max_value_bytes > MAX_DESTINATION_HEADER_VALUE_BYTES {
                return Err(DestinationRequestError::HeaderValueTooLong);
            }
            if exact_value.is_some_and(|value| !is_valid_header_value(value)) {
                return Err(DestinationRequestError::InvalidHeaderValue);
            }
            header_bytes = header_bytes
                .checked_add(name.as_str().len())
                .and_then(|total| total.checked_add(max_value_bytes))
                .ok_or(DestinationRequestError::HeaderBytesExceeded)?;
            retained_headers.push(match exact_value {
                Some(value) => HeaderValueTemplate::Exact {
                    name,
                    value: value.into(),
                },
                None => HeaderValueTemplate::Dynamic {
                    name,
                    max_value_bytes,
                },
            });
        }
        if header_bytes > MAX_DESTINATION_REQUEST_HEADER_BYTES {
            return Err(DestinationRequestError::HeaderBytesExceeded);
        }
        let worst_case = target_bytes
            .checked_add(header_bytes)
            .and_then(|total| total.checked_add(max_body_bytes))
            .ok_or(DestinationRequestError::TemplateBoundsExceeded)?;
        if worst_case > max_request_bytes {
            return Err(DestinationRequestError::TemplateBoundsExceeded);
        }

        Ok(Self {
            method,
            fixed_path: fixed_path.to_owned(),
            query: retained_query,
            headers: retained_headers,
            authorization,
            body,
            max_target_bytes: target_bytes,
            max_request_bytes,
            slot: PhantomData,
        })
    }

    /// Render bounded values into the opaque slot-typed request capability.
    pub fn render(
        &self,
        query_values: &[&str],
        header_values: &[&[u8]],
        authorization: Option<DestinationAuthorizationValue>,
        body: Option<Vec<u8>>,
    ) -> Result<BoundedDestinationRequest<S>, DestinationRequestError> {
        self.render_zeroizing(
            query_values,
            header_values,
            authorization,
            body.map(Zeroizing::new),
        )
    }

    /// Render a request while retaining a caller-produced sensitive body in zeroizing storage.
    pub fn render_zeroizing(
        &self,
        query_values: &[&str],
        header_values: &[&[u8]],
        authorization: Option<DestinationAuthorizationValue>,
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<BoundedDestinationRequest<S>, DestinationRequestError> {
        let dynamic_header_count = self
            .headers
            .iter()
            .filter(|header| header.is_dynamic())
            .count();
        if query_values.len() != self.query.len() || header_values.len() != dynamic_header_count {
            return Err(DestinationRequestError::TemplateValueCountMismatch);
        }
        if self
            .query
            .iter()
            .zip(query_values)
            .any(|(template, value)| value.len() > template.max_value_bytes)
            || self
                .headers
                .iter()
                .filter(|header| header.is_dynamic())
                .zip(header_values)
                .any(|(template, value)| value.len() > template.max_value_bytes())
            || body
                .as_ref()
                .is_some_and(|value| value.len() > self.body.max_bytes())
        {
            return Err(DestinationRequestError::TemplateBoundsExceeded);
        }
        match (self.authorization, authorization.as_ref()) {
            (DestinationAuthorizationTemplate::Forbidden, None) => {}
            (DestinationAuthorizationTemplate::Basic { .. }, Some(value))
                if value.kind == DestinationAuthorizationKind::Basic => {}
            (DestinationAuthorizationTemplate::Bearer { .. }, Some(value))
                if value.kind == DestinationAuthorizationKind::Bearer => {}
            _ => return Err(DestinationRequestError::AuthorizationShapeMismatch),
        }
        if authorization
            .as_ref()
            .is_some_and(|value| value.value.len() > self.authorization.max_value_bytes())
        {
            return Err(DestinationRequestError::TemplateBoundsExceeded);
        }
        match (self.body, body.as_ref()) {
            (DestinationBodyTemplate::Forbidden, None) => {}
            (DestinationBodyTemplate::Required { .. }, Some(value)) if !value.is_empty() => {}
            _ => return Err(DestinationRequestError::BodyPresenceMismatch),
        }

        let mut target = BoundedTargetWriter::new(self.max_target_bytes);
        target.extend_from_slice(self.fixed_path.as_bytes())?;
        for (index, (template, value)) in self.query.iter().zip(query_values).enumerate() {
            target.push(if index == 0 { b'?' } else { b'&' })?;
            append_form_component(&mut target, template.name.as_bytes())?;
            target.push(b'=')?;
            append_form_component(&mut target, value.as_bytes())?;
        }
        let target = target.into_inner();
        let mut dynamic_values = header_values.iter();
        let headers = self
            .headers
            .iter()
            .map(|template| match template {
                HeaderValueTemplate::Dynamic { name, .. } => {
                    let value = dynamic_values
                        .next()
                        .ok_or(DestinationRequestError::TemplateValueCountMismatch)?;
                    Ok((name.clone(), Zeroizing::new((*value).to_vec())))
                }
                HeaderValueTemplate::Exact { name, value } => {
                    Ok((name.clone(), Zeroizing::new(value.to_vec())))
                }
            })
            .collect::<Result<Vec<_>, DestinationRequestError>>()?;
        let actual_bytes = target
            .len()
            .checked_add(
                headers
                    .iter()
                    .map(|(name, value)| name.as_str().len() + value.len())
                    .sum::<usize>(),
            )
            .and_then(|total| {
                total.checked_add(
                    authorization
                        .as_ref()
                        .map_or(0, |value| AUTHORIZATION.as_str().len() + value.value.len()),
                )
            })
            .and_then(|total| total.checked_add(body.as_ref().map_or(0, |value| value.len())))
            .ok_or(DestinationRequestError::TemplateBoundsExceeded)?;
        if actual_bytes > self.max_request_bytes {
            return Err(DestinationRequestError::TemplateBoundsExceeded);
        }
        let authorization =
            authorization.map(|value| DestinationAuthorization { value: value.value });
        BoundedDestinationRequest::new_sensitive(self.method, target, headers, authorization, body)
    }
}

fn closed_oauth_headers(
    headers: &[HeaderTemplateInput<'_>],
    format: OAuth2ClientCredentialsBodyFormat,
) -> bool {
    if headers.len() != 2 {
        return false;
    }
    let mut accept = false;
    let mut content_type = false;
    for header in headers {
        let HeaderTemplateInput::Exact { name, value } = header else {
            return false;
        };
        match (*name, *value) {
            ("accept", b"application/json") => accept = true,
            ("content-type", b"application/json")
                if format == OAuth2ClientCredentialsBodyFormat::JsonClientSecretBody =>
            {
                content_type = true;
            }
            ("content-type", b"application/x-www-form-urlencoded")
                if format == OAuth2ClientCredentialsBodyFormat::FormClientSecretBody =>
            {
                content_type = true;
            }
            _ => return false,
        }
    }
    accept && content_type
}

struct BoundedTargetWriter {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}

impl BoundedTargetWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(limit)),
            limit,
        }
    }

    fn push(&mut self, byte: u8) -> Result<(), DestinationRequestError> {
        if self.bytes.len() >= self.limit || self.bytes.len() >= self.bytes.capacity() {
            return Err(DestinationRequestError::TemplateBoundsExceeded);
        }
        self.bytes.push(byte);
        Ok(())
    }

    fn extend_from_slice(&mut self, value: &[u8]) -> Result<(), DestinationRequestError> {
        let next_len = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(DestinationRequestError::TemplateBoundsExceeded)?;
        if next_len > self.limit || next_len > self.bytes.capacity() {
            return Err(DestinationRequestError::TemplateBoundsExceeded);
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

fn append_form_component(
    output: &mut BoundedTargetWriter,
    value: &[u8],
) -> Result<(), DestinationRequestError> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                output.push(*byte)?;
            }
            b' ' => output.push(b'+')?,
            _ => {
                output.push(b'%')?;
                output.push(HEX[usize::from(*byte >> 4)])?;
                output.push(HEX[usize::from(*byte & 0x0f)])?;
            }
        }
    }
    Ok(())
}

/// One bounded operation request tied to a data or credential destination slot.
///
/// The type is intentionally not `Clone`. Its custom `Debug` implementation
/// reveals no target, header, authorization, or body value.
/// Production dependents cannot mint this capability before the reviewed Relay
/// plan compiler exists:
///
/// ```compile_fail
/// use registry_platform_httputil::destination::{
///     DataDestinationRequest, DestinationMethod,
/// };
///
/// let _ = DataDestinationRequest::new(
///     DestinationMethod::Get,
///     "/records",
///     Vec::new(),
///     None,
///     None,
/// );
/// ```
pub struct BoundedDestinationRequest<S: DestinationSlot> {
    method: DestinationMethod,
    target: Zeroizing<Vec<u8>>,
    headers: Vec<SensitiveHeader>,
    authorization: Option<DestinationAuthorization>,
    body: Option<Zeroizing<Vec<u8>>>,
    slot: PhantomData<fn() -> S>,
}

struct SensitiveHeader {
    name: HeaderName,
    value: Zeroizing<Vec<u8>>,
}

/// Registry-data operation request.
pub type DataDestinationRequest = BoundedDestinationRequest<DataDestination>;
/// Credential-exchange operation request.
pub type CredentialDestinationRequest = BoundedDestinationRequest<CredentialDestination>;

impl<S: DestinationSlot> fmt::Debug for BoundedDestinationRequest<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedDestinationRequest")
            .field("slot", &S::DEBUG_NAME)
            .field("method", &self.method)
            .field("target", &"[REDACTED]")
            .field("headers", &"[REDACTED]")
            .field("authorization", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

impl<S: DestinationSlot> BoundedDestinationRequest<S> {
    /// Validate and consume a bounded operation shape.
    ///
    /// Static headers cannot set authority, framing, proxy, forwarding,
    /// cookie, or authorization fields. Authorization is accepted only through
    /// [`DestinationAuthorization`]. Header values are marked sensitive before
    /// retention.
    #[cfg(test)]
    fn new(
        method: DestinationMethod,
        target: &str,
        headers: Vec<(HeaderName, Vec<u8>)>,
        authorization: Option<DestinationAuthorization>,
        body: Option<Vec<u8>>,
    ) -> Result<Self, DestinationRequestError> {
        let target = Zeroizing::new(target.as_bytes().to_vec());
        let headers = headers
            .into_iter()
            .map(|(name, value)| (name, Zeroizing::new(value)))
            .collect();
        let body = body.map(Zeroizing::new);
        Self::new_sensitive(method, target, headers, authorization, body)
    }

    fn new_sensitive(
        method: DestinationMethod,
        target: Zeroizing<Vec<u8>>,
        headers: Vec<(HeaderName, Zeroizing<Vec<u8>>)>,
        authorization: Option<DestinationAuthorization>,
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<Self, DestinationRequestError> {
        let target_text =
            std::str::from_utf8(&target).map_err(|_| DestinationRequestError::InvalidTarget)?;
        validate_destination_target(target_text)?;
        if headers.len() + usize::from(authorization.is_some()) > MAX_DESTINATION_REQUEST_HEADERS {
            return Err(DestinationRequestError::TooManyHeaders);
        }
        if body
            .as_ref()
            .is_some_and(|body| body.len() > MAX_DESTINATION_REQUEST_BODY_BYTES)
        {
            return Err(DestinationRequestError::BodyTooLarge);
        }
        if method == DestinationMethod::Get && body.is_some() {
            return Err(DestinationRequestError::GetBodyDenied);
        }
        PathAndQuery::from_str(target_text).map_err(|_| DestinationRequestError::InvalidTarget)?;

        let mut aggregate_bytes = authorization.as_ref().map_or(0, |authorization| {
            AUTHORIZATION.as_str().len() + authorization.value.len()
        });
        if aggregate_bytes > MAX_DESTINATION_REQUEST_HEADER_BYTES {
            return Err(DestinationRequestError::HeaderBytesExceeded);
        }
        for (index, (name, value)) in headers.iter().enumerate() {
            if is_forbidden_static_request_header(name) {
                return Err(DestinationRequestError::ForbiddenHeader);
            }
            if headers[..index]
                .iter()
                .any(|(prior_name, _)| prior_name == name)
            {
                return Err(DestinationRequestError::DuplicateHeader);
            }
            if value.len() > MAX_DESTINATION_HEADER_VALUE_BYTES {
                return Err(DestinationRequestError::HeaderValueTooLong);
            }
            if !is_valid_header_value(value) {
                return Err(DestinationRequestError::InvalidHeaderValue);
            }
            aggregate_bytes = aggregate_bytes
                .checked_add(name.as_str().len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or(DestinationRequestError::HeaderBytesExceeded)?;
            if aggregate_bytes > MAX_DESTINATION_REQUEST_HEADER_BYTES {
                return Err(DestinationRequestError::HeaderBytesExceeded);
            }
        }

        let retained_headers = headers
            .into_iter()
            .map(|(name, value)| SensitiveHeader { name, value })
            .collect();

        Ok(Self {
            method,
            target,
            headers: retained_headers,
            authorization,
            body,
            slot: PhantomData,
        })
    }
}

/// Value-free operation-shape validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DestinationRequestError {
    #[error("operation target exceeds the platform bound")]
    TargetTooLong,
    #[error("operation target is invalid")]
    InvalidTarget,
    #[error("operation target is not canonical")]
    NonCanonicalTarget,
    #[error("operation has too many headers")]
    TooManyHeaders,
    #[error("operation has too many query components")]
    TooManyQueryComponents,
    #[error("operation header is forbidden")]
    ForbiddenHeader,
    #[error("operation header is duplicated")]
    DuplicateHeader,
    #[error("operation header value exceeds the platform bound")]
    HeaderValueTooLong,
    #[error("operation header value is invalid")]
    InvalidHeaderValue,
    #[error("operation aggregate header bytes exceed the platform bound")]
    HeaderBytesExceeded,
    #[error("authorization value is invalid")]
    InvalidAuthorization,
    #[error("GET request body is denied")]
    GetBodyDenied,
    #[error("operation method is not valid for the destination slot")]
    MethodSlotMismatch,
    #[error("operation request body exceeds the platform bound")]
    BodyTooLarge,
    #[error("operation values do not match the compiled request template")]
    TemplateValueCountMismatch,
    #[error("operation values exceed the compiled request-template bounds")]
    TemplateBoundsExceeded,
    #[error("operation authorization does not match the compiled request template")]
    AuthorizationShapeMismatch,
    #[error("operation body presence does not match the compiled request template")]
    BodyPresenceMismatch,
}

/// Value-free resolve, destination-policy, and transport failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DestinationSendError {
    #[error("remaining operation timeout is invalid")]
    InvalidRemainingTimeout,
    #[error("frozen destination policy is invalid")]
    InvalidFrozenPolicy,
    #[error("frozen destination request is invalid")]
    InvalidFrozenRequest,
    #[error("destination resolution failed")]
    ResolutionFailed,
    #[error("destination resolution capacity is unavailable")]
    ResolutionCapacityUnavailable,
    #[error("destination resolution returned too many answers")]
    TooManyResolverAnswers,
    #[error("destination resolution returned no answers")]
    NoResolverAnswers,
    #[error("destination resolver returned an unexpected port")]
    ResolverPortMismatch,
    #[error("literal destination did not resolve to itself")]
    LiteralOriginMismatch,
    #[error("cloud metadata destination is denied")]
    CloudMetadataDenied,
    #[error("destination is always denied in production")]
    AlwaysDeniedAddress,
    #[error("private destination is outside the exact allowlist")]
    PrivateAddressNotAllowed,
    #[error("non-global destination is denied")]
    NonGlobalAddressDenied,
    #[error("development destination is not loopback")]
    DevelopmentAddressDenied,
    #[error("destination client construction failed")]
    ClientBuildFailed,
    #[error("destination operation deadline was exceeded")]
    DeadlineExceeded,
    #[error("destination transport failed")]
    TransportFailed,
    #[error("upstream response has too many headers")]
    TooManyResponseHeaders,
    #[error("upstream response header bytes exceed the platform bound")]
    ResponseHeaderBytesExceeded,
}

/// One response from a consumed bounded destination request.
///
/// This wrapper intentionally exposes no request URL, remote address, reusable
/// client, or raw response. The body must be consumed through the bounded read.
/// Buffers owned by this module are zeroized, but reqwest and hyper necessarily
/// create internal URL, header, TLS, and body copies that this module cannot
/// zeroize or guarantee are erased. Those copies are never exposed through this
/// API.
pub struct BoundedDestinationResponse<S: DestinationSlot> {
    response: reqwest::Response,
    deadline: Instant,
    slot: PhantomData<fn() -> S>,
}

/// Registry-data response.
pub type DataDestinationResponse = BoundedDestinationResponse<DataDestination>;
/// Credential-exchange response.
pub type CredentialDestinationResponse = BoundedDestinationResponse<CredentialDestination>;

impl<S: DestinationSlot> fmt::Debug for BoundedDestinationResponse<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedDestinationResponse")
            .field("slot", &S::DEBUG_NAME)
            .field("response", &"[REDACTED]")
            .finish()
    }
}

impl<S: DestinationSlot> BoundedDestinationResponse<S> {
    /// Upstream HTTP status without exposing request destination metadata.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.response.status()
    }

    /// Consume the response body under both the operation deadline and byte cap.
    pub async fn read_bounded(
        self,
        max_bytes: usize,
    ) -> Result<BoundedDestinationBody<S>, DestinationResponseError> {
        if max_bytes > MAX_DESTINATION_RESPONSE_BODY_BYTES {
            return Err(DestinationResponseError::BodyLimitTooHigh);
        }
        let Self {
            mut response,
            deadline,
            slot: _,
        } = self;
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes as u64)
        {
            return Err(DestinationResponseError::BodyTooLarge);
        }

        let read = async move {
            let mut body = Zeroizing::new(Vec::with_capacity(max_bytes.min(8_192)));
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| DestinationResponseError::BodyReadFailed)?
            {
                let next_len = body
                    .len()
                    .checked_add(chunk.len())
                    .ok_or(DestinationResponseError::BodyTooLarge)?;
                if next_len > max_bytes {
                    return Err(DestinationResponseError::BodyTooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(BoundedDestinationBody {
                bytes: body,
                slot: PhantomData,
            })
        };

        timeout_at(deadline, read)
            .await
            .map_err(|_| DestinationResponseError::DeadlineExceeded)?
    }
}

/// Value-free bounded response-read failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DestinationResponseError {
    #[error("response body limit exceeds the platform bound")]
    BodyLimitTooHigh,
    #[error("response body exceeds its bound")]
    BodyTooLarge,
    #[error("response body read failed")]
    BodyReadFailed,
    #[error("destination operation deadline was exceeded")]
    DeadlineExceeded,
}

/// Marker-typed bounded response bytes.
///
/// Production code cannot inspect these bytes through this transport
/// foundation. The eventual plan compiler must expose separate, reviewed data
/// mapping and credential-token pathways instead of a generic raw-byte escape
/// hatch shared by both slots.
pub struct BoundedDestinationBody<S: DestinationSlot> {
    // Intentionally opaque until the reviewed plan compiler supplies
    // slot-specific response handling.
    #[cfg_attr(not(test), allow(dead_code))]
    bytes: Zeroizing<Vec<u8>>,
    slot: PhantomData<fn() -> S>,
}

/// Registry-data response bytes.
pub type DataDestinationBody = BoundedDestinationBody<DataDestination>;
/// Credential-exchange response bytes.
pub type CredentialDestinationBody = BoundedDestinationBody<CredentialDestination>;

impl<S: DestinationSlot> fmt::Debug for BoundedDestinationBody<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedDestinationBody")
            .field("slot", &S::DEBUG_NAME)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl<S: DestinationSlot> BoundedDestinationBody<S> {
    #[cfg(test)]
    #[must_use]
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrow sensitive response bytes only for the duration of `inspect`.
    #[cfg(test)]
    #[must_use]
    fn with_bytes<T>(&self, inspect: impl FnOnce(&[u8]) -> T) -> T {
        inspect(self.bytes.as_slice())
    }
}

trait Resolver {
    async fn resolve(&self, host: &str, port: u16)
        -> Result<ResolvedAnswers, DestinationSendError>;
}

enum TransportTrust {
    System,
    #[cfg(test)]
    TestRoot(reqwest::Certificate),
}

struct SystemResolver;

impl Resolver for SystemResolver {
    async fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> Result<ResolvedAnswers, DestinationSendError> {
        let resolver = destination_system_resolver()?;
        let absolute_name = absolute_dns_name(host)?;
        // These are deliberately independent RRset lookups. The caller's
        // timeout wraps this future and cancellation drops both in-flight
        // Hickory queries together.
        let (ipv4, ipv6) = tokio::join!(
            resolver.ipv4_lookup(absolute_name.clone()),
            resolver.ipv6_lookup(absolute_name)
        );
        let ipv4 = match ipv4 {
            Ok(records) => {
                FamilyResolution::from_addresses(records.answers().iter().filter_map(|record| {
                    match &record.data {
                        RData::A(address) => Some(IpAddr::V4(address.0)),
                        _ => None,
                    }
                }))
            }
            Err(error) => classify_hickory_family_error(&error),
        };
        let ipv6 = match ipv6 {
            Ok(records) => {
                FamilyResolution::from_addresses(records.answers().iter().filter_map(|record| {
                    match &record.data {
                        RData::AAAA(address) => Some(IpAddr::V6(address.0)),
                        _ => None,
                    }
                }))
            }
            Err(error) => classify_hickory_family_error(&error),
        };
        combine_family_resolutions(ipv4, ipv6, port)
    }
}

fn absolute_dns_name(host: &str) -> Result<Name, DestinationSendError> {
    let mut name = Name::from_ascii(host).map_err(|_| DestinationSendError::ResolutionFailed)?;
    // URL hosts are exact origins, never relative names. Marking the Hickory
    // query absolute prevents resolv.conf ndots/search expansion from
    // substituting `<host>.<search-domain>` in Kubernetes and other
    // search-domain environments while preserving the URL host for HTTP
    // authority and TLS identity.
    name.set_fqdn(true);
    Ok(name)
}

fn destination_system_resolver() -> Result<&'static TokioResolver, DestinationSendError> {
    DESTINATION_SYSTEM_RESOLVER
        .get_or_init(|| {
            let mut builder = TokioResolver::builder_tokio().ok()?;
            // Every outbound connection must query DNS, re-resolve, and
            // revalidate. Disabling both Hickory's cache and its process-wide
            // hosts-file snapshot prevents an earlier answer from becoming
            // input to a later connection.
            builder.options_mut().cache_size = 0;
            builder.options_mut().use_hosts_file = ResolveHosts::Never;
            builder.build().ok()
        })
        .as_ref()
        .ok_or(DestinationSendError::ResolutionFailed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FamilyResolutionKind {
    Answers,
    NoData,
    Failure,
    TooManyAnswers,
}

struct FamilyResolution {
    kind: FamilyResolutionKind,
    values: [IpAddr; MAX_DESTINATION_RESOLVER_ANSWERS],
    len: usize,
}

impl FamilyResolution {
    fn from_addresses(addresses: impl IntoIterator<Item = IpAddr>) -> Self {
        let mut values = [IpAddr::V4(Ipv4Addr::UNSPECIFIED); MAX_DESTINATION_RESOLVER_ANSWERS];
        let mut len = 0;
        for address in addresses {
            if len == MAX_DESTINATION_RESOLVER_ANSWERS {
                return Self::without_answers(FamilyResolutionKind::TooManyAnswers);
            }
            values[len] = address;
            len += 1;
        }
        if len == 0 {
            Self::without_answers(FamilyResolutionKind::NoData)
        } else {
            Self {
                kind: FamilyResolutionKind::Answers,
                values,
                len,
            }
        }
    }

    fn without_answers(kind: FamilyResolutionKind) -> Self {
        Self {
            kind,
            values: [IpAddr::V4(Ipv4Addr::UNSPECIFIED); MAX_DESTINATION_RESOLVER_ANSWERS],
            len: 0,
        }
    }

    fn no_data() -> Self {
        Self::without_answers(FamilyResolutionKind::NoData)
    }

    fn failure() -> Self {
        Self::without_answers(FamilyResolutionKind::Failure)
    }

    fn as_slice(&self) -> &[IpAddr] {
        &self.values[..self.len]
    }
}

fn classify_hickory_family_error(error: &NetError) -> FamilyResolution {
    let legitimate_nodata = matches!(
        error,
        NetError::Dns(DnsError::NoRecordsFound(no_records))
            if no_records.response_code == ResponseCode::NoError
    );
    if legitimate_nodata {
        FamilyResolution::no_data()
    } else {
        FamilyResolution::failure()
    }
}

fn combine_family_resolutions(
    ipv4: FamilyResolution,
    ipv6: FamilyResolution,
    port: u16,
) -> Result<ResolvedAnswers, DestinationSendError> {
    if [ipv4.kind, ipv6.kind].contains(&FamilyResolutionKind::Failure) {
        return Err(DestinationSendError::ResolutionFailed);
    }
    if [ipv4.kind, ipv6.kind].contains(&FamilyResolutionKind::TooManyAnswers) {
        return Err(DestinationSendError::TooManyResolverAnswers);
    }

    let addresses = ipv4
        .as_slice()
        .iter()
        .chain(ipv6.as_slice())
        .copied()
        .map(|ip| SocketAddr::new(ip, port));
    ResolvedAnswers::try_collect(addresses)
}

struct ResolvedAnswers {
    values: [SocketAddr; MAX_DESTINATION_RESOLVER_ANSWERS],
    len: usize,
}

impl ResolvedAnswers {
    fn try_collect(
        answers: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<Self, DestinationSendError> {
        let mut values = [empty_socket_address(); MAX_DESTINATION_RESOLVER_ANSWERS];
        let mut len = 0;
        for answer in answers {
            if len == MAX_DESTINATION_RESOLVER_ANSWERS {
                return Err(DestinationSendError::TooManyResolverAnswers);
            }
            values[len] = answer;
            len += 1;
        }
        Ok(Self { values, len })
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn as_slice(&self) -> &[SocketAddr] {
        &self.values[..self.len]
    }
}

struct PinnedAddresses {
    values: [SocketAddr; MAX_DESTINATION_RESOLVER_ANSWERS],
    len: usize,
}

impl PinnedAddresses {
    fn new() -> Self {
        Self {
            values: [empty_socket_address(); MAX_DESTINATION_RESOLVER_ANSWERS],
            len: 0,
        }
    }

    fn push_unique(&mut self, address: SocketAddr) {
        if !self.as_slice().contains(&address) {
            // A pinned set cannot exceed the already-bounded answer set.
            self.values[self.len] = address;
            self.len += 1;
        }
    }

    fn as_slice(&self) -> &[SocketAddr] {
        &self.values[..self.len]
    }
}

const fn empty_socket_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

fn is_canonical_origin_id(origin_id: &str) -> bool {
    let bytes = origin_id.as_bytes();
    if bytes.is_empty()
        || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
    {
        return false;
    }
    bytes.iter().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'_' | b':' | b'-')
    })
}

fn validate_destination_target(target: &str) -> Result<(), DestinationRequestError> {
    if target.len() > MAX_DESTINATION_TARGET_BYTES {
        return Err(DestinationRequestError::TargetTooLong);
    }
    if !target.starts_with('/')
        || target.starts_with("//")
        || target.contains(['#', '\\', '\r', '\n'])
    {
        return Err(DestinationRequestError::InvalidTarget);
    }
    let target =
        PathAndQuery::from_str(target).map_err(|_| DestinationRequestError::InvalidTarget)?;
    if !target_is_canonical(&target) || !path_percent_encoding_is_canonical(target.path()) {
        return Err(DestinationRequestError::NonCanonicalTarget);
    }
    Ok(())
}

/// Validate one exact fixed operation path using the same rules as rendering.
pub fn validate_fixed_destination_path(path: &str) -> Result<(), DestinationRequestError> {
    if path.contains('?') {
        return Err(DestinationRequestError::InvalidTarget);
    }
    validate_destination_target(path)
}

fn path_percent_encoding_is_canonical(path: &str) -> bool {
    let bytes = path.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        let Some(high) = bytes.get(index + 1).copied() else {
            return false;
        };
        let Some(low) = bytes.get(index + 2).copied() else {
            return false;
        };
        if !matches!(high, b'0'..=b'9' | b'A'..=b'F') || !matches!(low, b'0'..=b'9' | b'A'..=b'F') {
            return false;
        }
        let hex = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'A'..=b'F' => byte - b'A' + 10,
            _ => 0,
        };
        let decoded = (hex(high) << 4) | hex(low);
        if decoded.is_ascii() {
            return false;
        }
        index += 3;
    }
    true
}

fn target_is_canonical(target: &PathAndQuery) -> bool {
    let mut canonical =
        Url::parse("https://bounded.invalid/").expect("constant canonicalization URL is valid");
    canonical.set_path(target.path());
    canonical.set_query(target.query());
    let serialized = match target.query() {
        Some(query) => format!("{}?{query}", canonical.path()),
        None => canonical.path().to_owned(),
    };
    serialized == target.as_str()
}

fn is_forbidden_static_request_header(name: &HeaderName) -> bool {
    name == AUTHORIZATION
        || name == ACCEPT_ENCODING
        || name == HOST
        || name == CONNECTION
        || name == CONTENT_LENGTH
        || name == COOKIE
        || name == FORWARDED
        || name == PROXY_AUTHENTICATE
        || name == PROXY_AUTHORIZATION
        || name == TE
        || name == TRAILER
        || name == TRANSFER_ENCODING
        || name == UPGRADE
        || matches!(
            name.as_str(),
            "keep-alive" | "proxy-connection" | "x-real-ip"
        )
        || name.as_str().starts_with("x-forwarded-")
}

fn is_valid_header_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| *byte == b'\t' || (0x20..=0x7e).contains(byte) || *byte >= 0x80)
}

fn validate_response_headers(headers: &HeaderMap) -> Result<(), DestinationSendError> {
    if headers.len() > MAX_DESTINATION_RESPONSE_HEADERS {
        return Err(DestinationSendError::TooManyResponseHeaders);
    }
    let mut bytes = 0_usize;
    for (name, value) in headers {
        bytes = bytes
            .checked_add(name.as_str().len())
            .and_then(|total| total.checked_add(value.as_bytes().len()))
            .ok_or(DestinationSendError::ResponseHeaderBytesExceeded)?;
        if bytes > MAX_DESTINATION_RESPONSE_HEADER_BYTES {
            return Err(DestinationSendError::ResponseHeaderBytesExceeded);
        }
    }
    Ok(())
}

fn origin_explicitly_denotes_loopback(origin: &Url) -> bool {
    match origin.host() {
        Some(::url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(::url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(::url::Host::Ipv6(ip)) => is_loopback(normalize_ipv4_mapped(IpAddr::V6(ip))),
        None => false,
    }
}

fn is_loopback(ip: IpAddr) -> bool {
    match normalize_ipv4_mapped(ip) {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

fn is_always_denied_in_production(ip: IpAddr) -> bool {
    match normalize_ipv4_mapped(ip) {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 0
                || octets[0] == 127
                || (octets[0] == 169 && octets[1] == 254)
                || octets[0] >= 224
        }
        IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || is_ipv6_unicast_link_local(ip)
                || ip.is_multicast()
        }
    }
}

fn is_eligible_private_address(ip: IpAddr) -> bool {
    match normalize_ipv4_mapped(ip) {
        IpAddr::V4(ip) => ip.is_private() || is_ipv4_shared(ip),
        IpAddr::V6(ip) => ip.is_unique_local(),
    }
}

fn cidr_is_eligible_private(cidr: IpNet) -> bool {
    match cidr {
        IpNet::V4(cidr) => {
            let address = cidr.network();
            let prefix = cidr.prefix_len();
            (prefix >= 8 && ipv4_in_prefix(address, Ipv4Addr::new(10, 0, 0, 0), 8))
                || (prefix >= 12 && ipv4_in_prefix(address, Ipv4Addr::new(172, 16, 0, 0), 12))
                || (prefix >= 16 && ipv4_in_prefix(address, Ipv4Addr::new(192, 168, 0, 0), 16))
                || (prefix >= 10 && ipv4_in_prefix(address, Ipv4Addr::new(100, 64, 0, 0), 10))
        }
        IpNet::V6(cidr) => {
            cidr.prefix_len() >= 7
                && ipv6_in_prefix(
                    cidr.network(),
                    Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
                    7,
                )
        }
    }
}

fn cidr_is_metadata_singleton(cidr: IpNet) -> bool {
    match cidr {
        IpNet::V4(cidr) if cidr.prefix_len() == 32 => {
            is_cloud_metadata_ip(IpAddr::V4(cidr.network()))
        }
        IpNet::V6(cidr) if cidr.prefix_len() == 128 => {
            is_cloud_metadata_ip(IpAddr::V6(cidr.network()))
        }
        _ => false,
    }
}

/// Pinned to [`DESTINATION_IANA_REGISTRY_SNAPSHOT`].
fn is_globally_routable(ip: IpAddr) -> bool {
    match normalize_ipv4_mapped(ip) {
        IpAddr::V4(ip) => is_ipv4_globally_routable(ip),
        IpAddr::V6(ip) => decode_well_known_nat64(ip)
            .map(is_ipv4_globally_routable)
            .unwrap_or_else(|| is_ipv6_globally_routable(ip)),
    }
}

fn is_ipv4_globally_routable(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    !(octets[0] == 0
        || ip.is_private()
        || is_ipv4_shared(ip)
        || ip.is_loopback()
        || ip.is_link_local()
        || (octets[0] == 192
            && octets[1] == 0
            && octets[2] == 0
            && octets[3] != 9
            && octets[3] != 10)
        || is_ipv4_documentation(ip)
        || ipv4_in_prefix(ip, Ipv4Addr::new(192, 88, 99, 0), 24)
        || ipv4_in_prefix(ip, Ipv4Addr::new(198, 18, 0, 0), 15)
        || ip.is_multicast()
        || (octets[0] & 0xf0 == 0xf0 && ip != Ipv4Addr::BROADCAST)
        || ip == Ipv4Addr::BROADCAST)
}

fn is_ipv6_globally_routable(ip: Ipv6Addr) -> bool {
    let value = u128::from(ip);
    let special_global_exception = value == 0x2001_0001_0000_0000_0000_0000_0000_0001
        || value == 0x2001_0001_0000_0000_0000_0000_0000_0002
        || value == 0x2001_0001_0000_0000_0000_0000_0000_0003
        || ipv6_in_prefix(ip, Ipv6Addr::new(0x2001, 3, 0, 0, 0, 0, 0, 0), 32)
        || ipv6_in_prefix(ip, Ipv6Addr::new(0x2001, 4, 0x0112, 0, 0, 0, 0, 0), 48)
        || ipv6_in_prefix(ip, Ipv6Addr::new(0x2001, 0x20, 0, 0, 0, 0, 0, 0), 28)
        || ipv6_in_prefix(ip, Ipv6Addr::new(0x2001, 0x30, 0, 0, 0, 0, 0, 0), 28);
    if special_global_exception {
        return true;
    }

    IPV6_GLOBAL_UNICAST_ALLOCATIONS
        .iter()
        .any(|(network, prefix_len)| ipv6_in_prefix(ip, *network, *prefix_len))
        && !is_ipv6_documentation(ip)
}

fn decode_well_known_nat64(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if !ipv6_in_prefix(ip, Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96) {
        return None;
    }
    let octets = ip.octets();
    Some(Ipv4Addr::new(
        octets[12], octets[13], octets[14], octets[15],
    ))
}

fn is_ipv4_shared(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && octets[1] & 0b1100_0000 == 0b0100_0000
}

fn is_ipv4_documentation(ip: Ipv4Addr) -> bool {
    matches!(
        ip.octets(),
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
    )
}

fn is_ipv6_documentation(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x3fff && segments[1] <= 0x0fff)
}

fn ipv4_in_prefix(ip: Ipv4Addr, network: Ipv4Addr, prefix_len: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - prefix_len).unwrap_or(0);
    u32::from(ip) & mask == u32::from(network) & mask
}

fn ipv6_in_prefix(ip: Ipv6Addr, network: Ipv6Addr, prefix_len: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - prefix_len).unwrap_or(0);
    u128::from(ip) & mask == u128::from(network) & mask
}

fn normalize_ipv4_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        IpAddr::V4(ip) => IpAddr::V4(ip),
    }
}

fn is_ipv6_unicast_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::routing::{get, post};
    use axum::Router;
    use proptest::prelude::*;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().expect("test IP parses")
    }

    fn cidr(raw: &str) -> IpNet {
        raw.parse().expect("test CIDR parses")
    }

    fn answer(raw: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip(raw), port)
    }

    fn production(cidrs: &[&str]) -> DataDestinationPolicy {
        let cidrs: Vec<_> = cidrs.iter().map(|raw| cidr(raw)).collect();
        DataDestinationPolicy::new(
            "registry-data",
            "https://registry.example.test/",
            DestinationProfile::ProductionHttps,
            &cidrs,
        )
        .expect("production policy validates")
    }

    fn classify(
        policy: &DataDestinationPolicy,
        addresses: &[&str],
    ) -> Result<(), DestinationSendError> {
        let answers = ResolvedAnswers::try_collect(
            addresses
                .iter()
                .map(|address| answer(address, policy.port())),
        )?;
        policy.classify_answers(answers).map(|_| ())
    }

    async fn spawn_tls_server(
        subject_alt_name: &str,
    ) -> (SocketAddr, reqwest::Certificate, JoinHandle<Result<(), ()>>) {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec![subject_alt_name.to_owned()])
                .expect("generate test certificate");
        let certificate_der = cert.der().clone();
        let request_certificate = reqwest::Certificate::from_der(certificate_der.as_ref())
            .expect("parse test root certificate");
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key)
            .expect("build test TLS configuration");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TLS test server");
        let address = listener.local_addr().expect("TLS test server address");
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.map_err(|_| ())?;
            let mut stream = acceptor.accept(stream).await.map_err(|_| ())?;
            let mut request = Vec::with_capacity(1_024);
            loop {
                let mut chunk = [0_u8; 512];
                let read = stream.read(&mut chunk).await.map_err(|_| ())?;
                if read == 0 {
                    return Err(());
                }
                request.extend_from_slice(&chunk[..read]);
                if request.len() > 8_192 {
                    return Err(());
                }
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\ntls-pinned",
                )
                .await
                .map_err(|_| ())?;
            stream.shutdown().await.map_err(|_| ())?;
            Ok(())
        });
        (address, request_certificate, handle)
    }

    #[test]
    fn origin_id_url_and_cidr_bounds_are_checked_and_canonical() {
        let max_id = format!("a{}z", "b".repeat(MAX_DESTINATION_ORIGIN_ID_BYTES - 2));
        DataDestinationPolicy::new(
            &max_id,
            "https://registry.example.test/",
            DestinationProfile::ProductionHttps,
            &[],
        )
        .expect("identifier at bound accepted");

        for invalid in ["", "Registry", "registry data", "-registry", "registry-"] {
            assert_eq!(
                DataDestinationPolicy::new(
                    invalid,
                    "https://registry.example.test/",
                    DestinationProfile::ProductionHttps,
                    &[],
                )
                .unwrap_err(),
                DestinationPolicyError::InvalidOriginId
            );
        }

        let too_long_id = "a".repeat(MAX_DESTINATION_ORIGIN_ID_BYTES + 1);
        assert_eq!(
            DataDestinationPolicy::new(
                &too_long_id,
                "not parsed",
                DestinationProfile::ProductionHttps,
                &[],
            )
            .unwrap_err(),
            DestinationPolicyError::OriginIdTooLong
        );
        let too_long_url = "x".repeat(MAX_DESTINATION_ORIGIN_URL_BYTES + 1);
        assert_eq!(
            DataDestinationPolicy::new(
                "data",
                &too_long_url,
                DestinationProfile::ProductionHttps,
                &[],
            )
            .unwrap_err(),
            DestinationPolicyError::OriginUrlTooLong
        );
        let too_many = vec![cidr("10.0.0.0/8"); MAX_DESTINATION_PRIVATE_CIDRS + 1];
        assert_eq!(
            DataDestinationPolicy::new(
                "data",
                "https://registry.example.test/",
                DestinationProfile::ProductionHttps,
                &too_many,
            )
            .unwrap_err(),
            DestinationPolicyError::TooManyPrivateCidrs
        );
        assert_eq!(
            DataDestinationPolicy::new(
                "data",
                "https://registry.example.test/",
                DestinationProfile::ProductionHttps,
                &[cidr("10.20.30.40/16")],
            )
            .unwrap_err(),
            DestinationPolicyError::PrivateCidrNotCanonical
        );
    }

    #[test]
    fn origin_shape_and_runtime_profile_are_closed() {
        for (raw, error) in [
            (
                "http://registry.example.test/",
                DestinationPolicyError::ProductionRequiresHttps,
            ),
            (
                "https://user@registry.example.test/",
                DestinationPolicyError::OriginUserInfoDenied,
            ),
            (
                "https://registry.example.test/path",
                DestinationPolicyError::OriginHasResourceComponents,
            ),
            (
                "https://registry.example.test/?query=x",
                DestinationPolicyError::OriginHasResourceComponents,
            ),
            (
                "https://registry.example.test/#fragment",
                DestinationPolicyError::OriginHasResourceComponents,
            ),
        ] {
            assert_eq!(
                DataDestinationPolicy::new("data", raw, DestinationProfile::ProductionHttps, &[],)
                    .unwrap_err(),
                error
            );
        }

        for raw in [
            "http://localhost:8080/",
            "http://127.42.0.1:8080/",
            "http://[::1]:8080/",
            "http://[::ffff:127.0.0.1]:8080/",
        ] {
            DataDestinationPolicy::new(
                "dev-data",
                raw,
                DestinationProfile::LoopbackDevelopmentHttp,
                &[],
            )
            .unwrap_or_else(|error| panic!("{raw} should validate: {error}"));
        }
        assert_eq!(
            DataDestinationPolicy::new(
                "dev-data",
                "http://service.test:8080/",
                DestinationProfile::LoopbackDevelopmentHttp,
                &[],
            )
            .unwrap_err(),
            DestinationPolicyError::DevelopmentRequiresLoopbackHost
        );
    }

    #[test]
    fn only_rfc1918_cgnat_and_ula_subnets_are_configurable() {
        for allowed in [
            "10.0.0.0/8",
            "10.1.2.0/24",
            "172.16.0.0/12",
            "172.31.255.255/32",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "100.127.255.255/32",
            "fc00::/7",
            "fd12:3456::/32",
        ] {
            DataDestinationPolicy::new(
                "data",
                "https://registry.example.test/",
                DestinationProfile::ProductionHttps,
                &[cidr(allowed)],
            )
            .unwrap_or_else(|error| panic!("{allowed} should validate: {error}"));
        }

        for denied in [
            "0.0.0.0/0",
            "10.0.0.0/7",
            "100.0.0.0/9",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "192.0.2.0/24",
            "198.18.0.0/15",
            "224.0.0.0/4",
            "::/0",
            "fe80::/10",
            "2001:2::/48",
            "2001:db8::/32",
            "3fff::/20",
            "ff00::/8",
            "100.100.100.200/32",
            "fd00:ec2::254/128",
        ] {
            assert_eq!(
                DataDestinationPolicy::new(
                    "data",
                    "https://registry.example.test/",
                    DestinationProfile::ProductionHttps,
                    &[cidr(denied)],
                )
                .unwrap_err(),
                DestinationPolicyError::PrivateCidrDenied,
                "unexpected result for {denied}"
            );
        }
    }

    #[test]
    fn complete_always_denied_sets_and_metadata_override_private_allowlists() {
        let policy = production(&["100.64.0.0/10", "fc00::/7"]);
        for raw in [
            "0.1.2.3",
            "127.42.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "febf::1",
            "ff00::1",
            "ffff::1",
        ] {
            assert_eq!(
                classify(&policy, &[raw]),
                Err(DestinationSendError::AlwaysDeniedAddress),
                "unexpected result for {raw}"
            );
        }
        for raw in ["169.254.169.254", "100.100.100.200", "fd00:ec2::254"] {
            assert_eq!(
                classify(&policy, &[raw]),
                Err(DestinationSendError::CloudMetadataDenied),
                "unexpected result for {raw}"
            );
        }
    }

    #[test]
    fn current_global_routing_boundaries_are_applied() {
        let policy = production(&[]);
        for allowed in [
            "8.8.8.8",
            "192.0.0.9",
            "192.0.0.10",
            "64:ff9b::808:808",
            "2001:1::1",
            "2001:1::2",
            "2001:1::3",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2606:4700::1111",
        ] {
            classify(&policy, &[allowed])
                .unwrap_or_else(|error| panic!("{allowed} should be global: {error}"));
        }
        for denied in [
            "::2",
            "100:0:0:1::1",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.2",
            "198.18.0.1",
            "64:ff9b:1::1",
            "100::1",
            "2001:2::1",
            "2001:db8::1",
            "2001:1000::1",
            "2001:6000::1",
            "2004::1",
            "2002::1",
            "2420::1",
            "2640::1",
            "2b00::1",
            "2d00::1",
            "3000::1",
            "3800::1",
            "3fff::1",
            "4000::1",
            "5f00::1",
        ] {
            assert_eq!(
                classify(&policy, &[denied]),
                Err(DestinationSendError::NonGlobalAddressDenied),
                "unexpected result for {denied}"
            );
        }
    }

    #[test]
    fn every_pinned_ipv6_global_unicast_allocation_has_a_routable_representative() {
        for (network, prefix_len) in IPV6_GLOBAL_UNICAST_ALLOCATIONS {
            let representative = Ipv6Addr::from(u128::from(*network) + 1);
            assert!(
                is_ipv6_globally_routable(representative),
                "{network}/{prefix_len} representative should be globally routable"
            );
        }
    }

    #[test]
    fn well_known_nat64_recursively_applies_embedded_ipv4_policy() {
        let public_only = production(&[]);
        classify(&public_only, &["64:ff9b::808:808"])
            .expect("NAT64 embedding a public IPv4 address is accepted");

        for (raw, expected) in [
            ("64:ff9b::1:203", DestinationSendError::AlwaysDeniedAddress),
            ("64:ff9b::7f00:1", DestinationSendError::AlwaysDeniedAddress),
            (
                "64:ff9b::a00:1",
                DestinationSendError::PrivateAddressNotAllowed,
            ),
            (
                "64:ff9b::6440:1",
                DestinationSendError::PrivateAddressNotAllowed,
            ),
            (
                "64:ff9b::a9fe:a9fe",
                DestinationSendError::CloudMetadataDenied,
            ),
            (
                "64:ff9b::6464:64c8",
                DestinationSendError::CloudMetadataDenied,
            ),
        ] {
            assert_eq!(classify(&public_only, &[raw]), Err(expected), "{raw}");
        }

        let private = production(&["10.0.0.0/8", "100.64.0.0/10"]);
        classify(&private, &["64:ff9b::a00:1"])
            .expect("embedded RFC1918 address uses exact IPv4 CIDR");
        classify(&private, &["64:ff9b::6440:1"])
            .expect("embedded CGNAT address uses exact IPv4 CIDR");
    }

    #[test]
    fn private_addresses_require_exact_cidr_and_mixed_answers_fail_closed() {
        let none = production(&[]);
        assert_eq!(
            classify(&none, &["10.20.1.4"]),
            Err(DestinationSendError::PrivateAddressNotAllowed)
        );

        let exact = production(&["10.20.0.0/16"]);
        classify(&exact, &["10.20.1.4"]).expect("exact private CIDR accepted");
        assert_eq!(
            classify(&exact, &["10.21.1.4"]),
            Err(DestinationSendError::PrivateAddressNotAllowed)
        );
        assert_eq!(
            classify(&none, &["93.184.216.34", "192.168.1.10"]),
            Err(DestinationSendError::PrivateAddressNotAllowed)
        );
    }

    #[test]
    fn mapped_ipv4_and_literal_origins_are_bound_before_use() {
        let exact = production(&["10.20.0.0/16"]);
        classify(&exact, &["::ffff:10.20.1.4"])
            .expect("mapped address uses canonical IPv4 allowlist");
        assert_eq!(
            classify(&exact, &["::ffff:127.0.0.1"]),
            Err(DestinationSendError::AlwaysDeniedAddress)
        );

        let literal = DataDestinationPolicy::new(
            "data",
            "https://93.184.216.34/",
            DestinationProfile::ProductionHttps,
            &[],
        )
        .expect("literal policy validates");
        assert_eq!(
            classify(&literal, &["93.184.216.35"]),
            Err(DestinationSendError::LiteralOriginMismatch)
        );
    }

    #[test]
    fn answer_count_empty_set_and_port_are_bounded() {
        assert_eq!(
            ResolvedAnswers::try_collect(std::iter::empty())
                .map(|answers| answers.as_slice().len()),
            Ok(0)
        );
        let over_limit = (0..=MAX_DESTINATION_RESOLVER_ANSWERS)
            .map(|index| answer("93.184.216.34", u16::try_from(index + 1).unwrap()));
        assert!(matches!(
            ResolvedAnswers::try_collect(over_limit),
            Err(DestinationSendError::TooManyResolverAnswers)
        ));

        let policy = production(&[]);
        let empty = ResolvedAnswers::try_collect(std::iter::empty()).unwrap();
        assert!(matches!(
            policy.classify_answers(empty),
            Err(DestinationSendError::NoResolverAnswers)
        ));
        let wrong_port = ResolvedAnswers::try_collect([answer("93.184.216.34", 444)]).unwrap();
        assert!(matches!(
            policy.classify_answers(wrong_port),
            Err(DestinationSendError::ResolverPortMismatch)
        ));
    }

    #[test]
    fn independent_dns_family_results_fail_on_partial_uncertainty() {
        let ipv4 = FamilyResolution::from_addresses([ip("93.184.216.34")]);
        let ipv6_failure = FamilyResolution::failure();
        assert!(matches!(
            combine_family_resolutions(ipv4, ipv6_failure, 443),
            Err(DestinationSendError::ResolutionFailed)
        ));

        let ipv4_nodata = FamilyResolution::no_data();
        let ipv6 = FamilyResolution::from_addresses([ip("2606:4700::1111")]);
        let combined = combine_family_resolutions(ipv4_nodata, ipv6, 443)
            .expect("legitimate family NODATA combines with complete other family");
        assert_eq!(combined.as_slice(), &[answer("2606:4700::1111", 443)]);

        let empty = combine_family_resolutions(
            FamilyResolution::no_data(),
            FamilyResolution::no_data(),
            443,
        )
        .expect("two legitimate NODATA results form a complete empty answer set");
        assert!(empty.is_empty());
    }

    #[test]
    fn fixed_origin_dns_name_is_always_absolute() {
        for host in ["registry", "registry.example", "registry.example."] {
            let name = absolute_dns_name(host).expect("valid fixed host");
            assert!(name.is_fqdn(), "{host} must bypass search-domain expansion");
            assert!(name.to_ascii().ends_with('.'));
        }
    }

    #[test]
    fn only_dns_noerror_nodata_is_treated_as_an_empty_family() {
        use hickory_resolver::net::NoRecords;
        use hickory_resolver::proto::op::Query;
        use hickory_resolver::proto::rr::RecordType;

        let error = |response_code| {
            let query = Query::query(
                Name::from_ascii("registry.example.test.").expect("test DNS name"),
                RecordType::A,
            );
            NetError::from(NoRecords::new(query, response_code))
        };

        assert_eq!(
            classify_hickory_family_error(&error(ResponseCode::NoError)).kind,
            FamilyResolutionKind::NoData
        );
        for uncertain in [ResponseCode::NXDomain, ResponseCode::ServFail] {
            assert_eq!(
                classify_hickory_family_error(&error(uncertain)).kind,
                FamilyResolutionKind::Failure
            );
        }
    }

    #[test]
    fn request_shape_is_bounded_and_rejects_authority_or_header_smuggling() {
        DataDestinationRequest::new(
            DestinationMethod::Get,
            "/records?id=42",
            vec![(http::header::ACCEPT, b"application/json".to_vec())],
            None,
            None,
        )
        .expect("bounded GET validates");
        DataDestinationRequest::new(
            DestinationMethod::ReviewedReadOnlyPost,
            "/search",
            vec![(http::header::CONTENT_TYPE, b"application/json".to_vec())],
            None,
            Some(br#"{"id":"42"}"#.to_vec()),
        )
        .expect("reviewed read-only POST body validates");

        for target in [
            "https://evil.test/",
            "//evil.test/path",
            "/a/../admin",
            "/a/%2e%2e/admin",
            "/a\\admin",
            "/record#fragment",
        ] {
            assert!(DataDestinationRequest::new(
                DestinationMethod::Get,
                target,
                vec![],
                None,
                None,
            )
            .is_err());
        }

        for name in [
            ACCEPT_ENCODING,
            AUTHORIZATION,
            HOST,
            CONNECTION,
            CONTENT_LENGTH,
            COOKIE,
            FORWARDED,
            PROXY_AUTHORIZATION,
            TRANSFER_ENCODING,
            HeaderName::from_static("x-forwarded-host"),
            HeaderName::from_static("x-real-ip"),
        ] {
            assert_eq!(
                DataDestinationRequest::new(
                    DestinationMethod::Get,
                    "/records",
                    vec![(name, b"smuggled".to_vec())],
                    None,
                    None,
                )
                .unwrap_err(),
                DestinationRequestError::ForbiddenHeader
            );
        }
        assert_eq!(
            DataDestinationRequest::new(
                DestinationMethod::Get,
                "/records",
                vec![],
                None,
                Some(b"body".to_vec()),
            )
            .unwrap_err(),
            DestinationRequestError::GetBodyDenied
        );
    }

    #[test]
    fn compiled_request_template_renders_only_its_exact_bounded_shape() {
        let template = DataDestinationRequestTemplate::new(
            DestinationMethod::Get,
            "/records",
            &[("id", 3)],
            &[("accept", 32)],
            DestinationAuthorizationTemplate::Bearer {
                max_value_bytes: 32,
            },
            DestinationBodyTemplate::Forbidden,
            128,
        )
        .expect("reviewed template validates");
        template
            .render(
                &["42"],
                &[b"application/json"],
                Some(
                    DestinationAuthorizationValue::bearer(b"bounded".to_vec())
                        .expect("typed provider value"),
                ),
                None,
            )
            .expect("exact template values render");
        assert_eq!(
            template
                .render(
                    &["1234"],
                    &[b"application/json"],
                    Some(
                        DestinationAuthorizationValue::bearer(b"bounded".to_vec())
                            .expect("typed provider value"),
                    ),
                    None,
                )
                .unwrap_err(),
            DestinationRequestError::TemplateBoundsExceeded
        );
        assert_eq!(
            template
                .render(&[], &[b"application/json"], None, None)
                .unwrap_err(),
            DestinationRequestError::TemplateValueCountMismatch
        );
        assert_eq!(
            DataDestinationRequestTemplate::new(
                DestinationMethod::Get,
                "/records",
                &[],
                &[("x-forwarded-host", 8)],
                DestinationAuthorizationTemplate::Forbidden,
                DestinationBodyTemplate::Forbidden,
                128,
            )
            .unwrap_err(),
            DestinationRequestError::ForbiddenHeader
        );
        assert_eq!(
            template
                .render(&["42"], &[b"application/json"], None, None)
                .unwrap_err(),
            DestinationRequestError::AuthorizationShapeMismatch
        );
        let no_auth = DataDestinationRequestTemplate::new(
            DestinationMethod::Get,
            "/records",
            &[],
            &[],
            DestinationAuthorizationTemplate::Forbidden,
            DestinationBodyTemplate::Forbidden,
            32,
        )
        .expect("no-auth template");
        assert_eq!(
            no_auth
                .render(
                    &[],
                    &[],
                    Some(
                        DestinationAuthorizationValue::bearer(b"unexpected".to_vec())
                            .expect("typed provider value"),
                    ),
                    None,
                )
                .unwrap_err(),
            DestinationRequestError::AuthorizationShapeMismatch
        );
        let post = DataDestinationRequestTemplate::new(
            DestinationMethod::ReviewedReadOnlyPost,
            "/search",
            &[],
            &[],
            DestinationAuthorizationTemplate::Forbidden,
            DestinationBodyTemplate::Required { max_bytes: 16 },
            64,
        )
        .expect("required-body template");
        for body in [None, Some(Vec::new())] {
            assert_eq!(
                post.render(&[], &[], None, body).unwrap_err(),
                DestinationRequestError::BodyPresenceMismatch
            );
        }
        post.render(&[], &[], None, Some(b"{}".to_vec()))
            .expect("nonempty bounded POST body");
        let encoded = DataDestinationRequestTemplate::new(
            DestinationMethod::Get,
            "/records/%E2%9C%93",
            &[("selector:subject", 1)],
            &[],
            DestinationAuthorizationTemplate::Forbidden,
            DestinationBodyTemplate::Forbidden,
            128,
        )
        .expect("canonical escaped path and colon query name");
        let request = encoded
            .render(&["x"], &[], None, None)
            .expect("encoded query renders");
        assert_eq!(
            request.target.as_slice(),
            b"/records/%E2%9C%93?selector%3Asubject=x"
        );
        let query = (0..=MAX_DESTINATION_REQUEST_QUERY_COMPONENTS)
            .map(|index| format!("q{index}"))
            .collect::<Vec<_>>();
        let query = query
            .iter()
            .map(|name| (name.as_str(), 1_usize))
            .collect::<Vec<_>>();
        assert_eq!(
            DataDestinationRequestTemplate::new(
                DestinationMethod::Get,
                "/records",
                &query,
                &[],
                DestinationAuthorizationTemplate::Forbidden,
                DestinationBodyTemplate::Forbidden,
                512,
            )
            .unwrap_err(),
            DestinationRequestError::TooManyQueryComponents
        );
        assert!(!format!("{template:?}").contains("records"));
    }

    #[test]
    fn credential_request_template_has_one_closed_slot_and_header_shape() {
        let template = CredentialDestinationRequestTemplate::oauth2_client_credentials(
            "/oauth/token",
            OAuth2ClientCredentialsBodyFormat::JsonClientSecretBody,
            1_024,
            2_048,
        )
        .expect("closed OAuth template");
        template
            .render(
                &[],
                &[],
                None,
                Some(br#"{"grant_type":"client_credentials"}"#.to_vec()),
            )
            .expect("exact credential request");

        assert_eq!(
            DataDestinationRequestTemplate::new(
                DestinationMethod::OAuth2ClientCredentialsPost,
                "/oauth/token",
                &[],
                &[],
                DestinationAuthorizationTemplate::Forbidden,
                DestinationBodyTemplate::Required { max_bytes: 1_024 },
                2_048,
            )
            .unwrap_err(),
            DestinationRequestError::MethodSlotMismatch
        );
        assert_eq!(
            CredentialDestinationRequestTemplate::new(
                DestinationMethod::Get,
                "/oauth/token",
                &[],
                &[],
                DestinationAuthorizationTemplate::Forbidden,
                DestinationBodyTemplate::Forbidden,
                2_048,
            )
            .unwrap_err(),
            DestinationRequestError::MethodSlotMismatch
        );
        assert_eq!(
            CredentialDestinationRequestTemplate::new_with_exact_headers(
                DestinationMethod::OAuth2ClientCredentialsPost,
                "/oauth/token",
                &[],
                &[
                    ("accept", b"application/json"),
                    ("content-type", b"application/json"),
                ],
                DestinationAuthorizationTemplate::Forbidden,
                DestinationBodyTemplate::Required { max_bytes: 1_024 },
                2_048,
            )
            .unwrap_err(),
            DestinationRequestError::MethodSlotMismatch
        );
        assert_eq!(
            template
                .render(&[], &[b"text/plain"], None, Some(b"{}".to_vec()))
                .unwrap_err(),
            DestinationRequestError::TemplateValueCountMismatch
        );
    }

    #[test]
    fn sensitive_body_adapter_retains_the_zeroizing_owner_without_a_plain_vec_copy() {
        let body = sensitive_reqwest_body(Zeroizing::new(b"client-secret-body".to_vec()));
        assert_eq!(body.as_bytes(), Some(b"client-secret-body".as_slice()));

        let owner = SensitiveRequestBodyOwner(Zeroizing::new(b"never-in-debug".to_vec()));
        let debug = format!("{owner:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("never-in-debug"));

        let source = include_str!("destination.rs");
        let send_body_path = source
            .split_once("if let Some(body) = body {")
            .and_then(|(_, suffix)| suffix.split_once("let response = timeout_at"))
            .map(|(path, _)| path)
            .expect("bounded send body path remains inspectable");
        assert!(send_body_path.contains("sensitive_reqwest_body(body)"));
        assert!(!send_body_path.contains(".to_vec()"));
        assert!(!send_body_path.contains("Vec::from"));

        let adapter = source
            .split_once("fn sensitive_reqwest_body")
            .and_then(|(_, suffix)| suffix.split_once("/// Value-free fixed-destination"))
            .map(|(path, _)| path)
            .expect("sensitive adapter remains inspectable");
        assert!(adapter.contains("Bytes::from_owner(SensitiveRequestBodyOwner(body))"));
        assert!(!adapter.contains(".to_vec()"));
        assert!(!adapter.contains("Vec::from"));
    }

    #[test]
    fn request_and_policy_debug_are_redacted() {
        let policy = production(&["10.0.0.0/8"]);
        let authorization = DestinationAuthorization::new(b"Bearer top-secret-token".to_vec())
            .expect("authorization validates");
        let request = DataDestinationRequest::new(
            DestinationMethod::Get,
            "/secret-path?citizen=123",
            vec![(
                HeaderName::from_static("x-private-value"),
                b"private-header".to_vec(),
            )],
            Some(authorization),
            None,
        )
        .expect("request validates");

        let policy_debug = format!("{policy:?}");
        let request_debug = format!("{request:?}");
        for secret in [
            "registry.example.test",
            "registry-data",
            "10.0.0.0",
            "secret-path",
            "citizen",
            "private-header",
            "top-secret-token",
        ] {
            assert!(!policy_debug.contains(secret));
            assert!(!request_debug.contains(secret));
        }
    }

    #[test]
    fn parsed_response_headers_are_bounded_before_response_exposure() {
        let mut too_many = HeaderMap::new();
        for index in 0..=MAX_DESTINATION_RESPONSE_HEADERS {
            let name = HeaderName::from_bytes(format!("x-upstream-{index}").as_bytes())
                .expect("test header name");
            too_many.insert(name, HeaderValue::from_static("value"));
        }
        assert_eq!(
            validate_response_headers(&too_many),
            Err(DestinationSendError::TooManyResponseHeaders)
        );

        let mut too_large = HeaderMap::new();
        too_large.insert(
            HeaderName::from_static("x-upstream-large"),
            HeaderValue::from_bytes(&vec![b'a'; MAX_DESTINATION_RESPONSE_HEADER_BYTES])
                .expect("large test header value"),
        );
        assert_eq!(
            validate_response_headers(&too_large),
            Err(DestinationSendError::ResponseHeaderBytesExceeded)
        );
    }

    struct FakeResolver {
        answers: Vec<SocketAddr>,
        calls: AtomicUsize,
    }

    impl Resolver for FakeResolver {
        async fn resolve(
            &self,
            _host: &str,
            _port: u16,
        ) -> Result<ResolvedAnswers, DestinationSendError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ResolvedAnswers::try_collect(self.answers.iter().copied())
        }
    }

    #[tokio::test]
    async fn one_shot_send_uses_injected_resolution_and_preserves_host() {
        let hits = Arc::new(AtomicUsize::new(0));
        let route_hits = Arc::clone(&hits);
        let app = Router::new().route(
            "/record",
            get(move |headers: HeaderMap| {
                let route_hits = Arc::clone(&route_hits);
                async move {
                    route_hits.fetch_add(1, Ordering::SeqCst);
                    let host_ok = headers
                        .get(HOST)
                        .and_then(|value| value.to_str().ok())
                        .is_some_and(|host| host.starts_with("localhost:"));
                    let auth_ok = headers
                        .get(AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        == Some("Bearer source-secret");
                    if host_ok && auth_ok {
                        (StatusCode::OK, "one-shot")
                    } else {
                        (StatusCode::BAD_REQUEST, "binding-failed")
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });

        let policy = DataDestinationPolicy::new(
            "dev-data",
            &format!("http://localhost:{}/", address.port()),
            DestinationProfile::LoopbackDevelopmentHttp,
            &[],
        )
        .expect("development policy validates");
        let authorization = DestinationAuthorization::new(b"Bearer source-secret".to_vec())
            .expect("authorization validates");
        let request = DataDestinationRequest::new(
            DestinationMethod::Get,
            "/record",
            vec![],
            Some(authorization),
            None,
        )
        .expect("request validates");
        let resolver = FakeResolver {
            answers: vec![address],
            calls: AtomicUsize::new(0),
        };

        let response = policy
            .send_with_resolver(
                request,
                Duration::from_secs(2),
                &resolver,
                TransportTrust::System,
            )
            .await
            .expect("one-shot send succeeds");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.read_bounded(32).await.expect("bounded body reads");
        assert_eq!(body.as_bytes(), b"one-shot");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn credential_send_delivers_the_exact_owned_sensitive_body() {
        let captured = Arc::new(Mutex::new(None));
        let route_captured = Arc::clone(&captured);
        let app = Router::new().route(
            "/oauth/token",
            post(move |headers: HeaderMap, body: Bytes| {
                let route_captured = Arc::clone(&route_captured);
                async move {
                    let exact_headers = headers.get("accept").and_then(|value| value.to_str().ok())
                        == Some("application/json")
                        && headers
                            .get("content-type")
                            .and_then(|value| value.to_str().ok())
                            == Some("application/json");
                    *route_captured.lock().expect("capture lock") = Some(body.to_vec());
                    if exact_headers {
                        (StatusCode::OK, "accepted")
                    } else {
                        (StatusCode::BAD_REQUEST, "wrong headers")
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind credential test server");
        let address = listener.local_addr().expect("credential test address");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve credential test app");
        });

        let policy = CredentialDestinationPolicy::new(
            "dev-oauth",
            &format!("http://localhost:{}/", address.port()),
            DestinationProfile::LoopbackDevelopmentHttp,
            &[],
        )
        .expect("development credential policy validates");
        let template = CredentialDestinationRequestTemplate::oauth2_client_credentials(
            "/oauth/token",
            OAuth2ClientCredentialsBodyFormat::JsonClientSecretBody,
            1_024,
            2_048,
        )
        .expect("closed credential template");
        let expected =
            br#"{"grant_type":"client_credentials","client_id":"doctor","client_secret":"secret"}"#;
        let request = template
            .render_zeroizing(&[], &[], None, Some(Zeroizing::new(expected.to_vec())))
            .expect("credential request renders");
        let resolver = FakeResolver {
            answers: vec![address],
            calls: AtomicUsize::new(0),
        };

        let response = policy
            .send_with_resolver(
                request,
                Duration::from_secs(2),
                &resolver,
                TransportTrust::System,
            )
            .await
            .expect("credential send succeeds");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            captured.lock().expect("capture lock").as_deref(),
            Some(expected.as_slice())
        );
    }

    #[tokio::test]
    async fn pinned_domain_preserves_tls_san_identity() {
        let (address, root, server) = spawn_tls_server("registry.test").await;
        let policy = DataDestinationPolicy::new(
            "tls-data",
            &format!("https://registry.test:{}/", address.port()),
            DestinationProfile::PinnedLoopbackHttpsTest,
            &[],
        )
        .expect("test TLS policy validates");
        let request =
            DataDestinationRequest::new(DestinationMethod::Get, "/record", vec![], None, None)
                .expect("request validates");
        let resolver = FakeResolver {
            answers: vec![address],
            calls: AtomicUsize::new(0),
        };

        let response = policy
            .send_with_resolver(
                request,
                Duration::from_secs(2),
                &resolver,
                TransportTrust::TestRoot(root),
            )
            .await
            .expect("pinned domain passes its DNS SAN check");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.read_bounded(32).await.expect("bounded TLS body");
        assert!(body.with_bytes(|bytes| bytes == b"tls-pinned"));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        server
            .await
            .expect("TLS server task completed")
            .expect("TLS server completed");
    }

    #[tokio::test]
    async fn ip_literal_preserves_tls_ip_san_and_bypasses_dns() {
        let (address, root, server) = spawn_tls_server("127.0.0.1").await;
        let policy = DataDestinationPolicy::new(
            "tls-literal",
            &format!("https://127.0.0.1:{}/", address.port()),
            DestinationProfile::PinnedLoopbackHttpsTest,
            &[],
        )
        .expect("test TLS literal policy validates");
        let request =
            DataDestinationRequest::new(DestinationMethod::Get, "/record", vec![], None, None)
                .expect("request validates");
        let resolver = FakeResolver {
            answers: vec![answer("203.0.113.1", address.port())],
            calls: AtomicUsize::new(0),
        };

        let response = policy
            .send_with_resolver(
                request,
                Duration::from_secs(2),
                &resolver,
                TransportTrust::TestRoot(root),
            )
            .await
            .expect("IP literal passes its IP SAN check");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.read_bounded(32).await.expect("bounded TLS body");
        assert_eq!(body.as_bytes(), b"tls-pinned");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        server
            .await
            .expect("TLS server task completed")
            .expect("TLS server completed");
    }

    #[tokio::test]
    async fn pinned_domain_rejects_a_mismatched_tls_san() {
        let (address, wrong_root, server) = spawn_tls_server("other.test").await;
        let policy = DataDestinationPolicy::new(
            "tls-data",
            &format!("https://registry.test:{}/", address.port()),
            DestinationProfile::PinnedLoopbackHttpsTest,
            &[],
        )
        .expect("test TLS policy validates");
        let request =
            DataDestinationRequest::new(DestinationMethod::Get, "/record", vec![], None, None)
                .expect("request validates");
        let resolver = FakeResolver {
            answers: vec![address],
            calls: AtomicUsize::new(0),
        };

        let result = policy
            .send_with_resolver(
                request,
                Duration::from_secs(2),
                &resolver,
                TransportTrust::TestRoot(wrong_root),
            )
            .await;
        assert!(matches!(result, Err(DestinationSendError::TransportFailed)));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert!(server.await.expect("TLS server task completed").is_err());
    }

    #[tokio::test]
    async fn remaining_timeout_is_hard_bounded_before_resolution() {
        let policy = production(&[]);
        let request =
            DataDestinationRequest::new(DestinationMethod::Get, "/record", vec![], None, None)
                .expect("request validates");
        let resolver = FakeResolver {
            answers: vec![answer("93.184.216.34", 443)],
            calls: AtomicUsize::new(0),
        };
        let result = policy
            .send_with_resolver(request, Duration::ZERO, &resolver, TransportTrust::System)
            .await;
        assert!(matches!(
            result,
            Err(DestinationSendError::InvalidRemainingTimeout)
        ));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    proptest! {
        #[test]
        fn every_ipv4_address_in_frozen_denied_prefixes_is_rejected(
            selector in 0_u8..5,
            tail in any::<[u8; 3]>(),
        ) {
            let address = match selector {
                0 => Ipv4Addr::new(0, tail[0], tail[1], tail[2]),
                1 => Ipv4Addr::new(127, tail[0], tail[1], tail[2]),
                2 => Ipv4Addr::new(169, 254, tail[1], tail[2]),
                3 => Ipv4Addr::new(224 | (tail[0] & 0x0f), tail[0], tail[1], tail[2]),
                _ => Ipv4Addr::new(240 | (tail[0] & 0x0f), tail[0], tail[1], tail[2]),
            };
            prop_assert!(is_always_denied_in_production(IpAddr::V4(address)));
        }

        #[test]
        fn every_mapped_ipv4_address_has_the_same_address_class(octets in any::<[u8; 4]>()) {
            let v4 = Ipv4Addr::from(octets);
            let mapped = v4.to_ipv6_mapped();
            prop_assert_eq!(
                is_globally_routable(IpAddr::V4(v4)),
                is_globally_routable(IpAddr::V6(mapped)),
            );
            prop_assert_eq!(
                is_always_denied_in_production(IpAddr::V4(v4)),
                is_always_denied_in_production(IpAddr::V6(mapped)),
            );
        }
    }
}

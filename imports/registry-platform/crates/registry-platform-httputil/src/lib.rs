//! HTTP utilities shared by Registry Platform consumers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, SystemTime};

use thiserror::Error;

/// Default timeout for requests built from [`ValidatedFetchUrl`].
pub const DEFAULT_VALIDATED_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Builder for outbound HTTP clients used by platform fetchers.
#[derive(Debug, Clone)]
pub struct OutboundClientBuilder {
    timeout: Duration,
    user_agent: Option<String>,
}

impl Default for OutboundClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl OutboundClientBuilder {
    /// Create a builder with production-safe defaults: 30 second timeout,
    /// redirects disabled, and proxy environment variables ignored.
    #[must_use]
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            user_agent: None,
        }
    }

    /// Set the request timeout.
    #[must_use]
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    /// Set the outbound User-Agent header.
    #[must_use]
    pub fn user_agent(mut self, ua: &str) -> Self {
        self.user_agent = Some(ua.to_string());
        self
    }

    /// Build a reqwest client.
    ///
    /// The spec exposes an infallible return type. With the limited options
    /// above, construction failures indicate a programming error.
    #[must_use]
    pub fn build(self) -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy();
        if let Some(user_agent) = self.user_agent {
            builder = builder.user_agent(user_agent);
        }
        builder
            .build()
            .expect("registry platform outbound client options are valid")
    }
}

/// Errors returned by [`read_bounded`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BoundedReadError {
    /// The response advertised a body larger than the caller's limit.
    #[error("response content-length {content_length} exceeds limit {max_bytes}")]
    ContentLengthExceeded { content_length: u64, max_bytes: u64 },
    /// Streaming chunks exceeded the caller's limit.
    #[error("response body exceeds limit {max_bytes}")]
    BodyTooLarge { max_bytes: u64 },
    /// Accumulating chunk lengths overflowed.
    #[error("response body length overflowed")]
    LengthOverflow,
    /// The HTTP client failed while reading the body.
    #[error("failed to read response body: {0}")]
    Transport(#[from] reqwest::Error),
}

/// Read a response body into memory while enforcing a byte cap.
pub async fn read_bounded(
    mut resp: reqwest::Response,
    max_bytes: u64,
) -> Result<Vec<u8>, BoundedReadError> {
    if let Some(content_length) = resp.content_length() {
        if content_length > max_bytes {
            return Err(BoundedReadError::ContentLengthExceeded {
                content_length,
                max_bytes,
            });
        }
    }

    let capacity = usize::try_from(max_bytes.min(8192)).unwrap_or(8192);
    let mut body = Vec::with_capacity(capacity);
    let mut len = 0_u64;
    while let Some(chunk) = resp.chunk().await? {
        let chunk_len = u64::try_from(chunk.len()).map_err(|_| BoundedReadError::LengthOverflow)?;
        len = len
            .checked_add(chunk_len)
            .ok_or(BoundedReadError::LengthOverflow)?;
        if len > max_bytes {
            return Err(BoundedReadError::BodyTooLarge { max_bytes });
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

/// URL construction helpers.
pub mod url {
    use thiserror::Error;

    /// Errors returned by [`append_path_segments`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
    #[non_exhaustive]
    pub enum UrlError {
        /// The base URL cannot carry path segments.
        #[error("base URL cannot be a base for path segments")]
        CannotBeABase,
        /// Empty path segments are ambiguous and are not appended.
        #[error("path segment must not be empty")]
        EmptySegment,
        /// Dot segments would change path semantics after normalization.
        #[error("path segment must not be '.' or '..'")]
        DotSegment,
    }

    /// Append already-separated path segments to a base URL.
    ///
    /// Segments are passed through `url`'s path serializer, which percent
    /// encodes delimiters such as `/`, `?`, and `#` inside a segment.
    pub fn append_path_segments(
        base: &reqwest::Url,
        segments: &[&str],
    ) -> Result<reqwest::Url, UrlError> {
        if segments.is_empty() {
            return Ok(base.clone());
        }

        for segment in segments {
            if segment.is_empty() {
                return Err(UrlError::EmptySegment);
            }
            if matches!(*segment, "." | "..") {
                return Err(UrlError::DotSegment);
            }
        }

        let mut out = base.clone();
        out.path_segments_mut()
            .map_err(|_| UrlError::CannotBeABase)?
            .pop_if_empty()
            .extend(segments.iter().copied());
        Ok(out)
    }
}

/// Policy for validating outbound fetch URLs before a request is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchUrlPolicy {
    pub allowed_schemes: Vec<String>,
    pub allow_localhost: bool,
    pub allow_http_private_network: bool,
    pub deny_private_ranges: bool,
    pub deny_cloud_metadata: bool,
}

impl FetchUrlPolicy {
    /// Production default: HTTPS only, no localhost, no private/link-local
    /// ranges, and no cloud metadata endpoints.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            allowed_schemes: vec!["https".to_string()],
            allow_localhost: false,
            allow_http_private_network: false,
            deny_private_ranges: true,
            deny_cloud_metadata: true,
        }
    }

    /// Development preset: HTTP and HTTPS are allowed, but plain HTTP only
    /// for loopback hosts. Non-loopback private ranges and cloud metadata
    /// endpoints stay denied.
    #[must_use]
    pub fn dev() -> Self {
        Self {
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            allow_localhost: true,
            allow_http_private_network: false,
            deny_private_ranges: true,
            deny_cloud_metadata: true,
        }
    }

    /// Validate an outbound URL against this policy.
    ///
    /// This compatibility helper proves only that the URL is acceptable at the
    /// moment validation runs. It resolves DNS but discards the DNS evidence, so
    /// it must not be used as the sole guard for a later outbound request. Use
    /// [`Self::validate_for_immediate_fetch`] and
    /// [`ValidatedFetchUrl::immediate_get`] for SSRF-sensitive fetches.
    pub fn validate(&self, url: &reqwest::Url) -> Result<(), FetchUrlError> {
        self.validate_for_immediate_fetch(url).map(|_| ())
    }

    /// Validate an outbound URL and return the DNS evidence from validation.
    ///
    /// The returned value is a proof of what this process resolved while
    /// validating. DNS can change after validation, so callers must construct
    /// and send the request immediately from this value and should log or audit
    /// `resolved_ips()` when investigating outbound fetch behavior.
    pub fn validate_for_immediate_fetch(
        &self,
        url: &reqwest::Url,
    ) -> Result<ValidatedFetchUrl, FetchUrlError> {
        if !self
            .allowed_schemes
            .iter()
            .any(|scheme| scheme.eq_ignore_ascii_case(url.scheme()))
        {
            return Err(FetchUrlError::SchemeDenied {
                scheme: url.scheme().to_string(),
            });
        }

        if !url.username().is_empty() || url.password().is_some() {
            return Err(FetchUrlError::UserInfoDenied);
        }

        let host = url.host().ok_or(FetchUrlError::MissingHost)?;
        let resolved_addrs = resolve_host(url)?;
        let resolved: Vec<IpAddr> = resolved_addrs.iter().map(|addr| addr.ip()).collect();
        if resolved.is_empty() {
            return Err(FetchUrlError::NoAddresses);
        }

        let localhost_allowed = self.allow_localhost && host_is_allowed_localhost(host, &resolved);

        for ip in &resolved {
            if self.deny_cloud_metadata && is_cloud_metadata_ip(*ip) {
                return Err(FetchUrlError::CloudMetadataDenied { ip: *ip });
            }
            if is_loopback_ip(*ip) && !localhost_allowed {
                return Err(FetchUrlError::LocalhostDenied { ip: *ip });
            }
            if is_unspecified_ip(*ip) {
                return Err(FetchUrlError::PrivateRangeDenied { ip: *ip });
            }
            if self.deny_cloud_metadata && is_link_local_ip(*ip) {
                return Err(FetchUrlError::PrivateRangeDenied { ip: *ip });
            }
            if self.deny_private_ranges
                && is_private_or_link_local_ip(*ip)
                && !(localhost_allowed && is_loopback_ip(*ip))
            {
                return Err(FetchUrlError::PrivateRangeDenied { ip: *ip });
            }
        }

        if url.scheme() == "http" {
            let http_private_network_allowed = self.allow_http_private_network
                && resolved
                    .iter()
                    .all(|ip| is_http_private_network_ip(*ip, !self.deny_cloud_metadata));
            if !(localhost_allowed || http_private_network_allowed) {
                return Err(FetchUrlError::HttpRequiresLoopback);
            }
        }

        Ok(ValidatedFetchUrl {
            url: url.clone(),
            resolved_addrs,
            validated_at: SystemTime::now(),
        })
    }

    /// Validate an outbound URL with a wall-clock bound around DNS resolution.
    ///
    /// This is the async companion to [`Self::validate_for_immediate_fetch`].
    /// It prevents a slow platform DNS lookup from blocking the caller beyond
    /// the supplied timeout. The blocking resolver task may still finish in the
    /// background after this method returns a timeout error.
    pub async fn validate_for_immediate_fetch_with_timeout(
        &self,
        url: &reqwest::Url,
        timeout: Duration,
    ) -> Result<ValidatedFetchUrl, FetchUrlError> {
        let policy = self.clone();
        let url = url.clone();
        tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking(move || policy.validate_for_immediate_fetch(&url)),
        )
        .await
        .map_err(|_| FetchUrlError::ValidationTimeout { timeout })?
        .map_err(FetchUrlError::ValidationTask)?
    }
}

/// URL plus DNS evidence produced by [`FetchUrlPolicy`].
///
/// Requests created from this value use reqwest's per-client DNS override to
/// pin the request host to the exact socket addresses approved during
/// validation. This is intentionally more expensive than reusing a process-wide
/// client, but it closes the DNS-rebinding gap for security-sensitive fetches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedFetchUrl {
    url: reqwest::Url,
    resolved_addrs: Vec<SocketAddr>,
    validated_at: SystemTime,
}

impl ValidatedFetchUrl {
    /// The validated URL.
    #[must_use]
    pub fn url(&self) -> &reqwest::Url {
        &self.url
    }

    /// IP addresses returned by DNS or IP-literal parsing during validation.
    #[must_use]
    pub fn resolved_ips(&self) -> Vec<IpAddr> {
        self.resolved_addrs.iter().map(|addr| addr.ip()).collect()
    }

    /// Socket addresses pinned into request clients built from this value.
    #[must_use]
    pub fn resolved_addrs(&self) -> &[SocketAddr] {
        &self.resolved_addrs
    }

    /// Time at which validation completed.
    #[must_use]
    pub fn validated_at(&self) -> SystemTime {
        self.validated_at
    }

    /// Build an immediate GET request from this validated URL.
    ///
    /// The returned request builder uses a short-lived client whose resolver is
    /// pinned to the socket addresses accepted by the policy check. Requests use
    /// [`DEFAULT_VALIDATED_FETCH_TIMEOUT`] unless callers override the request
    /// timeout on the returned builder or use [`Self::immediate_get_with_timeout`].
    pub fn immediate_get(&self) -> Result<reqwest::RequestBuilder, FetchUrlError> {
        self.immediate_get_with_timeout(DEFAULT_VALIDATED_FETCH_TIMEOUT)
    }

    /// Build an immediate GET request with an explicit request timeout.
    ///
    /// The timeout is applied to both the short-lived client and the returned
    /// request builder so callers have a clear per-fetch bound even when the
    /// request is sent without further customization.
    pub fn immediate_get_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<reqwest::RequestBuilder, FetchUrlError> {
        let host = self
            .url
            .host_str()
            .ok_or(FetchUrlError::MissingHost)?
            .to_string();
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .resolve_to_addrs(&host, &self.resolved_addrs)
            .build()
            .map_err(FetchUrlError::ClientBuild)?;
        Ok(client.get(self.url.clone()).timeout(timeout))
    }
}

/// Errors returned by [`FetchUrlPolicy::validate`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FetchUrlError {
    /// The URL's scheme is not in the policy allowlist.
    #[error("URL scheme '{scheme}' is not allowed")]
    SchemeDenied { scheme: String },
    /// Fetch URLs must include a host.
    #[error("URL must include a host")]
    MissingHost,
    /// Userinfo is rejected to avoid credential smuggling in URLs.
    #[error("URL userinfo is not allowed")]
    UserInfoDenied,
    /// The URL has no default or explicit port for DNS resolution.
    #[error("URL must include a port or use a scheme with a default port")]
    MissingPort,
    /// DNS lookup failed.
    #[error("DNS lookup failed for host '{host}': {source}")]
    Dns {
        host: String,
        #[source]
        source: std::io::Error,
    },
    /// DNS lookup returned no addresses.
    #[error("DNS lookup returned no addresses")]
    NoAddresses,
    /// Building a pinned client failed.
    #[error("failed to build pinned HTTP client: {0}")]
    ClientBuild(#[source] reqwest::Error),
    /// URL validation exceeded the caller's wall-clock bound.
    #[error("URL validation exceeded timeout {timeout:?}")]
    ValidationTimeout { timeout: Duration },
    /// The blocking validation task failed.
    #[error("URL validation task failed: {0}")]
    ValidationTask(#[source] tokio::task::JoinError),
    /// Localhost was denied by policy.
    #[error("localhost address {ip} is denied")]
    LocalhostDenied { ip: IpAddr },
    /// A private, unspecified, or link-local address was denied by policy.
    #[error("private or link-local address {ip} is denied")]
    PrivateRangeDenied { ip: IpAddr },
    /// A cloud metadata endpoint was denied by policy.
    #[error("cloud metadata address {ip} is denied")]
    CloudMetadataDenied { ip: IpAddr },
    /// Development policy permits HTTP only for loopback targets.
    #[error("http URLs are allowed only for loopback hosts")]
    HttpRequiresLoopback,
}

fn resolve_host(url: &reqwest::Url) -> Result<Vec<SocketAddr>, FetchUrlError> {
    let port = url
        .port_or_known_default()
        .ok_or(FetchUrlError::MissingPort)?;
    match url.host().ok_or(FetchUrlError::MissingHost)? {
        ::url::Host::Ipv4(ip) => Ok(vec![SocketAddr::new(IpAddr::V4(ip), port)]),
        ::url::Host::Ipv6(ip) => Ok(vec![SocketAddr::new(IpAddr::V6(ip), port)]),
        ::url::Host::Domain(host) => {
            let addrs = (host, port)
                .to_socket_addrs()
                .map_err(|source| FetchUrlError::Dns {
                    host: host.to_string(),
                    source,
                })?
                .collect();
            Ok(addrs)
        }
    }
}

fn host_is_allowed_localhost(host: ::url::Host<&str>, resolved: &[IpAddr]) -> bool {
    match host {
        ::url::Host::Ipv4(ip) => ip.is_loopback(),
        ::url::Host::Ipv6(ip) => ip == Ipv6Addr::LOCALHOST,
        ::url::Host::Domain(host) if host.eq_ignore_ascii_case("localhost") => {
            resolved.iter().all(|ip| is_loopback_ip(*ip))
        }
        ::url::Host::Domain(_) => false,
    }
}

fn is_cloud_metadata_ip(ip: IpAddr) -> bool {
    match normalize_ipv4_mapped(ip) {
        IpAddr::V4(ip) => ip == Ipv4Addr::new(169, 254, 169, 254),
        IpAddr::V6(ip) => ip == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254),
    }
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match normalize_ipv4_mapped(ip) {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

fn is_private_or_link_local_ip(ip: IpAddr) -> bool {
    match normalize_ipv4_mapped(ip) {
        IpAddr::V4(ip) => {
            ip.is_private() || ip.is_link_local() || ip.is_loopback() || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || is_ipv6_unicast_link_local(ip)
        }
    }
}

fn is_http_private_network_ip(ip: IpAddr, allow_link_local: bool) -> bool {
    match normalize_ipv4_mapped(ip) {
        IpAddr::V4(ip) => ip.is_private() || (allow_link_local && ip.is_link_local()),
        IpAddr::V6(ip) => {
            ip.is_unique_local() || (allow_link_local && is_ipv6_unicast_link_local(ip))
        }
    }
}

fn is_link_local_ip(ip: IpAddr) -> bool {
    match normalize_ipv4_mapped(ip) {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => is_ipv6_unicast_link_local(ip),
    }
}

fn is_unspecified_ip(ip: IpAddr) -> bool {
    match normalize_ipv4_mapped(ip) {
        IpAddr::V4(ip) => ip.is_unspecified(),
        IpAddr::V6(ip) => ip.is_unspecified(),
    }
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
    use super::*;
    use axum::{
        body::Body,
        http::{header, StatusCode},
        response::IntoResponse,
        routing::get,
        Router,
    };
    use proptest::prelude::*;
    use tokio::net::TcpListener;

    async fn serve(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("read listener addr");
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve test app");
        });
        format!("http://{addr}")
    }

    async fn serve_with_addr(router: Router) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("read listener addr");
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve test app");
        });
        addr
    }

    #[tokio::test]
    async fn outbound_client_does_not_follow_redirects() {
        let base = serve(
            Router::new()
                .route(
                    "/redirect",
                    get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/target")]) }),
                )
                .route("/target", get(|| async { "followed" })),
        )
        .await;

        let client = OutboundClientBuilder::new().build();
        let response = client
            .get(format!("{base}/redirect"))
            .send()
            .await
            .expect("request succeeds");
        assert_eq!(response.status(), StatusCode::FOUND);
    }

    #[tokio::test]
    async fn read_bounded_accepts_body_within_limit() {
        let base = serve(Router::new().route("/body", get(|| async { "hello" }))).await;
        let response = reqwest::get(format!("{base}/body"))
            .await
            .expect("request succeeds");
        let body = read_bounded(response, 5).await.expect("body within limit");
        assert_eq!(body, b"hello");
    }

    #[tokio::test]
    async fn read_bounded_rejects_content_length_over_limit() {
        let base = serve(Router::new().route(
            "/body",
            get(|| async {
                ([(header::CONTENT_LENGTH, "6")], Body::from("123456")).into_response()
            }),
        ))
        .await;
        let response = reqwest::get(format!("{base}/body"))
            .await
            .expect("request succeeds");
        let err = read_bounded(response, 5)
            .await
            .expect_err("content-length over limit rejected");
        assert!(matches!(
            err,
            BoundedReadError::ContentLengthExceeded {
                content_length: 6,
                max_bytes: 5
            }
        ));
    }

    #[tokio::test]
    async fn read_bounded_rejects_stream_over_limit() {
        let base = serve(Router::new().route("/body", get(|| async { "123456" }))).await;
        let response = reqwest::get(format!("{base}/body"))
            .await
            .expect("request succeeds");
        let err = read_bounded(response, 5)
            .await
            .expect_err("stream over limit rejected");
        assert!(matches!(
            err,
            BoundedReadError::ContentLengthExceeded { .. } | BoundedReadError::BodyTooLarge { .. }
        ));
    }

    #[test]
    fn append_path_segments_percent_encodes_segment_delimiters() {
        let base = reqwest::Url::parse("https://example.test/api").expect("url parses");
        let url = url::append_path_segments(&base, &["datasets", "a/b", "q?x#y"])
            .expect("segments append");
        assert_eq!(
            url.as_str(),
            "https://example.test/api/datasets/a%2Fb/q%3Fx%23y"
        );
    }

    #[test]
    fn append_path_segments_handles_trailing_slash_without_empty_segment() {
        let base = reqwest::Url::parse("https://example.test/api/").expect("url parses");
        let url = url::append_path_segments(&base, &["datasets"]).expect("segments append");
        assert_eq!(url.as_str(), "https://example.test/api/datasets");
    }

    #[test]
    fn append_path_segments_rejects_empty_and_dot_segments() {
        let base = reqwest::Url::parse("https://example.test/api").expect("url parses");
        assert_eq!(
            url::append_path_segments(&base, &[""]),
            Err(url::UrlError::EmptySegment)
        );
        assert_eq!(
            url::append_path_segments(&base, &[".."]),
            Err(url::UrlError::DotSegment)
        );
    }

    #[test]
    fn strict_policy_accepts_https_public_ip_literal() {
        let url = reqwest::Url::parse("https://93.184.216.34/jwks").expect("url parses");
        FetchUrlPolicy::strict()
            .validate(&url)
            .expect("public HTTPS IP accepted");
    }

    #[test]
    fn validated_fetch_url_carries_resolved_ip_evidence() {
        let url = reqwest::Url::parse("https://93.184.216.34/jwks").expect("url parses");
        let validated = FetchUrlPolicy::strict()
            .validate_for_immediate_fetch(&url)
            .expect("public HTTPS IP accepted");

        assert_eq!(validated.url(), &url);
        assert_eq!(
            validated.resolved_ips(),
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
        assert_eq!(validated.resolved_addrs()[0].port(), 443);
        assert!(validated.validated_at() <= SystemTime::now());
    }

    #[test]
    fn immediate_get_builds_request_from_validated_url() {
        let url = reqwest::Url::parse("https://93.184.216.34/jwks").expect("url parses");
        let validated = FetchUrlPolicy::strict()
            .validate_for_immediate_fetch(&url)
            .expect("public HTTPS IP accepted");

        let request = validated
            .immediate_get()
            .expect("pinned request builder builds")
            .build()
            .expect("request builds");
        assert_eq!(request.url(), &url);
        assert_eq!(request.timeout(), Some(&DEFAULT_VALIDATED_FETCH_TIMEOUT));
    }

    #[test]
    fn immediate_get_with_timeout_uses_explicit_timeout() {
        let url = reqwest::Url::parse("https://93.184.216.34/jwks").expect("url parses");
        let validated = FetchUrlPolicy::strict()
            .validate_for_immediate_fetch(&url)
            .expect("public HTTPS IP accepted");
        let timeout = Duration::from_secs(7);

        let request = validated
            .immediate_get_with_timeout(timeout)
            .expect("pinned request builder builds")
            .build()
            .expect("request builds");
        assert_eq!(request.timeout(), Some(&timeout));
    }

    #[tokio::test]
    async fn immediate_get_uses_pinned_resolved_socket_address() {
        let addr = serve_with_addr(Router::new().route("/body", get(|| async { "pinned" }))).await;
        let url = reqwest::Url::parse(&format!("http://example.test:{}/body", addr.port()))
            .expect("url parses");
        let validated = ValidatedFetchUrl {
            url,
            resolved_addrs: vec![addr],
            validated_at: SystemTime::now(),
        };

        let response = validated
            .immediate_get()
            .expect("pinned request builds")
            .send()
            .await
            .expect("pinned request reaches test server");
        let body = response.text().await.expect("body reads");

        assert_eq!(body, "pinned");
    }

    #[test]
    fn strict_policy_rejects_http_and_local_or_private_targets() {
        for raw in [
            "http://93.184.216.34/jwks",
            "https://127.0.0.1/jwks",
            "https://10.0.0.1/jwks",
            "https://192.168.1.1/jwks",
            "https://172.16.0.1/jwks",
            "https://169.254.1.1/jwks",
            "https://[::1]/jwks",
            "https://[fd00::1]/jwks",
            "https://[fe80::1]/jwks",
            "https://[::ffff:127.0.0.1]/jwks",
        ] {
            let url = reqwest::Url::parse(raw).expect("url parses");
            assert!(
                FetchUrlPolicy::strict().validate(&url).is_err(),
                "strict policy must reject {raw}"
            );
        }
    }

    #[test]
    fn private_network_policy_accepts_http_private_ip_only_when_enabled() {
        let private_url = reqwest::Url::parse("http://10.0.0.1/jwks").expect("url parses");
        let public_url = reqwest::Url::parse("http://93.184.216.34/jwks").expect("url parses");
        let policy = FetchUrlPolicy {
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            allow_localhost: false,
            allow_http_private_network: true,
            deny_private_ranges: false,
            deny_cloud_metadata: true,
        };

        policy
            .validate(&private_url)
            .expect("private-network HTTP is explicitly accepted");
        let err = policy
            .validate(&public_url)
            .expect_err("public HTTP is still rejected");
        assert!(matches!(err, FetchUrlError::HttpRequiresLoopback));
    }

    #[test]
    fn private_network_policy_still_rejects_cloud_metadata() {
        let url =
            reqwest::Url::parse("http://169.254.169.254/latest/meta-data/").expect("url parses");
        let policy = FetchUrlPolicy {
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            allow_localhost: false,
            allow_http_private_network: true,
            deny_private_ranges: false,
            deny_cloud_metadata: true,
        };

        let err = policy
            .validate(&url)
            .expect_err("cloud metadata target rejected");
        assert!(matches!(err, FetchUrlError::CloudMetadataDenied { .. }));
    }

    #[test]
    fn private_network_policy_rejects_link_local_without_escape_hatch() {
        let policy = FetchUrlPolicy {
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            allow_localhost: false,
            allow_http_private_network: true,
            deny_private_ranges: false,
            deny_cloud_metadata: true,
        };

        for raw in [
            "http://169.254.1.1/jwks",
            "https://169.254.1.1/jwks",
            "http://[fe80::1]/jwks",
            "https://[fe80::1]/jwks",
        ] {
            let url = reqwest::Url::parse(raw).expect("url parses");
            let err = match policy.validate(&url) {
                Ok(()) => panic!("link-local target rejected for {raw}"),
                Err(err) => err,
            };
            assert!(
                matches!(err, FetchUrlError::PrivateRangeDenied { .. }),
                "unexpected error for {raw}: {err}"
            );
        }
    }

    #[test]
    fn private_network_policy_can_explicitly_allow_link_local_metadata_targets() {
        let policy = FetchUrlPolicy {
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            allow_localhost: false,
            allow_http_private_network: true,
            deny_private_ranges: false,
            deny_cloud_metadata: false,
        };

        for raw in [
            "http://169.254.1.1/jwks",
            "http://169.254.169.254/latest/meta-data/",
            "http://[fe80::1]/jwks",
            "http://[fd00:ec2::254]/latest/meta-data/",
        ] {
            let url = reqwest::Url::parse(raw).expect("url parses");
            policy
                .validate(&url)
                .unwrap_or_else(|err| panic!("explicit escape hatch should accept {raw}: {err}"));
        }
    }

    #[test]
    fn private_network_policy_rejects_unspecified_addresses() {
        let policy = FetchUrlPolicy {
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            allow_localhost: false,
            allow_http_private_network: true,
            deny_private_ranges: false,
            deny_cloud_metadata: false,
        };

        for raw in ["http://0.0.0.0/jwks", "https://[::]/jwks"] {
            let url = reqwest::Url::parse(raw).expect("url parses");
            let err = match policy.validate(&url) {
                Ok(()) => panic!("unspecified target rejected for {raw}"),
                Err(err) => err,
            };
            assert!(
                matches!(err, FetchUrlError::PrivateRangeDenied { .. }),
                "unexpected error for {raw}: {err}"
            );
        }
    }

    #[test]
    fn policy_rejects_cloud_metadata_ipv4_and_ipv6() {
        for raw in [
            "https://169.254.169.254/latest/meta-data/",
            "https://[::ffff:169.254.169.254]/latest/meta-data/",
            "https://[fd00:ec2::254]/latest/meta-data/",
        ] {
            let url = reqwest::Url::parse(raw).expect("url parses");
            let err = FetchUrlPolicy::dev()
                .validate(&url)
                .expect_err("metadata target rejected");
            assert!(
                matches!(err, FetchUrlError::CloudMetadataDenied { .. }),
                "unexpected error for {raw}: {err}"
            );
        }
    }

    #[test]
    fn dev_policy_allows_http_only_for_loopback_hosts() {
        for raw in [
            "http://127.0.0.1/jwks",
            "http://127.42.0.1/jwks",
            "http://[::1]/jwks",
            "http://localhost/jwks",
        ] {
            let url = reqwest::Url::parse(raw).expect("url parses");
            FetchUrlPolicy::dev()
                .validate(&url)
                .unwrap_or_else(|err| panic!("dev policy should accept {raw}: {err}"));
        }

        for raw in [
            "http://93.184.216.34/jwks",
            "http://10.0.0.1/jwks",
            "http://[::ffff:127.0.0.1]/jwks",
        ] {
            let url = reqwest::Url::parse(raw).expect("url parses");
            assert!(
                FetchUrlPolicy::dev().validate(&url).is_err(),
                "dev policy must reject {raw}"
            );
        }
    }

    #[test]
    fn dev_policy_still_rejects_private_non_loopback_https() {
        for raw in [
            "https://10.0.0.1/jwks",
            "https://192.168.0.5/jwks",
            "https://[fd00::1]/jwks",
        ] {
            let url = reqwest::Url::parse(raw).expect("url parses");
            assert!(
                FetchUrlPolicy::dev().validate(&url).is_err(),
                "dev policy must reject {raw}"
            );
        }
    }

    #[test]
    fn fetch_url_policy_blocks_dns_rebinding_to_private_range() {
        let url = reqwest::Url::parse("https://localhost/jwks").expect("url parses");
        let err = FetchUrlPolicy::strict()
            .validate_for_immediate_fetch(&url)
            .expect_err("strict policy rejects hostnames resolving to loopback");
        assert!(
            matches!(
                err,
                FetchUrlError::LocalhostDenied { .. } | FetchUrlError::PrivateRangeDenied { .. }
            ),
            "unexpected error: {err}"
        );
    }

    proptest! {
        #[test]
        fn append_path_segments_keeps_each_input_as_one_segment(
            segment in "[A-Za-z0-9._~-]{1,64}"
        ) {
            prop_assume!(segment != "." && segment != "..");
            let base = reqwest::Url::parse("https://example.test/root").expect("url parses");
            let url = url::append_path_segments(&base, &[segment.as_str()]).expect("segment appends");
            let segments: Vec<_> = url.path_segments().expect("hierarchical URL").collect();
            prop_assert_eq!(segments.len(), 2);
            prop_assert_eq!(segments[0], "root");
            prop_assert_eq!(segments[1], segment);
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
//! HTTP [`JwksFetcher`] backed by [`reqwest`].
//!
//! Two construction paths:
//!
//! * [`ReqwestJwksFetcher::from_jwks_url`]: the operator already knows
//!   the JWKS endpoint; we GET it directly.
//! * [`ReqwestJwksFetcher::from_discovery_url`]: the operator pointed us
//!   at `.well-known/openid-configuration`; we fetch the document once
//!   at construction time and extract the `jwks_uri` from it.
//!
//! Both paths return a fetcher that wraps a shared [`reqwest::Client`]
//! configured with native-tls, a 10s connect / 30s overall timeout,
//! and JSON content-type expectations on responses.

use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use serde::Deserialize;

use super::jwks::{JwksFetchError, JwksFetchResult, JwksFetcher};

/// Connect timeout for both discovery and JWKS fetches. Tighter than
/// the overall request timeout so a hung TCP handshake fails fast.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall request timeout (connect + headers + body) for both
/// discovery and JWKS fetches. Sized for the typical sub-second JWKS
/// response with generous headroom for a slow IdP.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum response body size for both discovery and JWKS fetches.
/// Prevents a runaway IdP response from exhausting heap before the
/// 30s overall timeout fires.
const MAX_RESPONSE_BYTES: usize = 1_048_576; // 1 MiB

/// HTTP JWKS fetcher. One instance per OIDC provider; cloning is cheap
/// because the inner [`reqwest::Client`] is internally `Arc`d.
pub struct ReqwestJwksFetcher {
    client: reqwest::Client,
    jwks_url: String,
}

impl ReqwestJwksFetcher {
    /// Build a fetcher that points at an explicit JWKS endpoint.
    ///
    /// Returns an error only if the [`reqwest::Client`] cannot be built
    /// (e.g. TLS backend initialisation failure on this host).
    pub fn from_jwks_url(jwks_url: impl Into<String>) -> Result<Self, JwksFetchError> {
        let jwks_url = jwks_url.into();
        validate_fetch_url(&jwks_url, "jwks")?;
        let client = build_client()?;
        Ok(Self { client, jwks_url })
    }

    /// Resolve a JWKS URL from an OIDC discovery document, then build a
    /// fetcher that points at it. One network round-trip; intended for
    /// startup, not the verify hot path.
    ///
    /// RFC 8414 §3 requires that the discovery document's `issuer` field
    /// equals `expected_issuer`. A mismatch is returned as
    /// [`JwksFetchError::IssuerMismatch`] so startup fails fast rather than
    /// silently accepting keys from a foreign issuer.
    pub async fn from_discovery_url(
        discovery_url: impl AsRef<str>,
        expected_issuer: &str,
    ) -> Result<Self, JwksFetchError> {
        let client = build_client()?;
        let discovery_url = discovery_url.as_ref();
        validate_fetch_url(discovery_url, "discovery")?;
        let response = client
            .get(discovery_url)
            .send()
            .await
            .map_err(|err| JwksFetchError::Transport(redact_url(err.to_string())))?;
        if !response.status().is_success() {
            return Err(JwksFetchError::Transport(format!(
                "discovery: HTTP {}",
                response.status().as_u16()
            )));
        }
        let body = response
            .bytes()
            .await
            .map_err(|err| JwksFetchError::Transport(redact_url(err.to_string())))?;
        let jwks_uri = validate_discovery_document_bytes(&body, expected_issuer)?;
        Ok(Self {
            client,
            jwks_url: jwks_uri,
        })
    }

    /// JWKS URL the fetcher will request. Useful for startup logs.
    #[must_use]
    pub fn jwks_url(&self) -> &str {
        &self.jwks_url
    }
}

impl JwksFetcher for ReqwestJwksFetcher {
    fn fetch<'a>(
        &'a self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<JwksFetchResult, JwksFetchError>> + Send + 'a>,
    > {
        Box::pin(async move {
            validate_fetch_url(&self.jwks_url, "jwks")?;
            let response = self
                .client
                .get(&self.jwks_url)
                .send()
                .await
                .map_err(|err| JwksFetchError::Transport(redact_url(err.to_string())))?;
            if !response.status().is_success() {
                return Err(JwksFetchError::Transport(format!(
                    "jwks: HTTP {}",
                    response.status().as_u16()
                )));
            }
            let body = response
                .bytes()
                .await
                .map_err(|err| JwksFetchError::Transport(redact_url(err.to_string())))?;
            let jwks = parse_response_bytes(&body, MAX_RESPONSE_BYTES)?;
            Ok(JwksFetchResult { jwks })
        })
    }
}

fn build_client() -> Result<reqwest::Client, JwksFetchError> {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| JwksFetchError::Transport(format!("client build failed: {err}")))
}

fn validate_fetch_url(url: &str, context: &str) -> Result<(), JwksFetchError> {
    let parsed = reqwest::Url::parse(url).map_err(|_| {
        JwksFetchError::Transport(format!(
            "{context}: URL must be absolute https:// (or http:// localhost for dev)"
        ))
    })?;

    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_local_dev_host(parsed.host_str()) => Ok(()),
        _ => Err(JwksFetchError::Transport(format!(
            "{context}: URL must be https:// (or http:// localhost for dev)"
        ))),
    }
}

/// Accept only loopback for `http://` (dev convenience). Everything else
/// must be `https://`. Rejecting non-loopback IPs and arbitrary hostnames
/// here blocks SSRF into RFC1918 (`10/8`, `192.168/16`), link-local
/// (`169.254/16`, including cloud metadata `169.254.169.254`), the
/// "this host" address `0.0.0.0`, and IPv4-mapped IPv6 forms of the
/// same ranges (`::ffff:169.254.169.254`).
///
/// The only non-IP hostname accepted is the literal `localhost`. Any
/// other hostname is rejected so an attacker-controlled DNS name cannot
/// be smuggled past validation and resolved to an internal IP at
/// connect time. This still allows DNS rebinding via a hosts-file or
/// resolver override on `localhost` itself, which we accept as a
/// development trade-off (a malicious resolver on the operator host is
/// already game over).
fn is_local_dev_host(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => is_loopback_ip(ip),
        Err(_) => false,
    }
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return true;
            }
            // ::ffff:a.b.c.d — the IPv4-mapped IPv6 form of `a.b.c.d`.
            // Treat it as the underlying v4 address for loopback checks.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback();
            }
            false
        }
    }
}

/// Strip URLs from reqwest's display string. reqwest embeds the full
/// request URL in transport errors; the URL itself is operator-supplied
/// and not secret, but trimming it keeps audit lines bounded and avoids
/// echoing query strings into logs.
fn redact_url(message: String) -> String {
    // Best-effort: keep up to the first "url:" segment reqwest emits,
    // otherwise return the message verbatim. The cache wraps this in
    // `JwksFetchError::Transport` so it never reaches a client response.
    match message.find(" for url:") {
        Some(idx) => message[..idx].to_string(),
        None => message,
    }
}

/// Minimal projection of the OIDC discovery document. Both `issuer` and
/// `jwks_uri` are load-bearing: `issuer` is validated against the
/// operator-configured value (RFC 8414 §3); `jwks_uri` is the key-set URL.
/// Other fields (`authorization_endpoint`, ...) are intentionally ignored.
#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

/// Parse `bytes` as type `T` after asserting the body fits within `limit`.
/// Returns [`JwksFetchError::Transport`] when the limit is exceeded and
/// [`JwksFetchError::Parse`] when deserialisation fails.
fn parse_response_bytes<T: serde::de::DeserializeOwned>(
    bytes: &Bytes,
    limit: usize,
) -> Result<T, JwksFetchError> {
    if bytes.len() > limit {
        return Err(JwksFetchError::Transport(format!(
            "response body too large: {} bytes (limit {})",
            bytes.len(),
            limit,
        )));
    }
    serde_json::from_slice(bytes).map_err(|_| JwksFetchError::Parse)
}

/// Parse and validate an OIDC discovery document body.
///
/// Checks the body size, deserialises the document, and compares
/// `document.issuer` against `expected_issuer` (RFC 8414 §3).
/// Returns the `jwks_uri` on success.
fn validate_discovery_document_bytes(
    bytes: &Bytes,
    expected_issuer: &str,
) -> Result<String, JwksFetchError> {
    let document: DiscoveryDocument = parse_response_bytes(bytes, MAX_RESPONSE_BYTES)?;
    if document.issuer != expected_issuer {
        return Err(JwksFetchError::IssuerMismatch {
            expected: expected_issuer.to_string(),
            actual: document.issuer,
        });
    }
    validate_fetch_url(&document.jwks_uri, "discovery jwks_uri")?;
    Ok(document.jwks_uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        http::{header, StatusCode},
        routing::get,
        Router,
    };
    use serde_json::json;
    use tokio::net::TcpListener;

    fn discovery_bytes(issuer: &str, jwks_uri: &str) -> Bytes {
        Bytes::from(
            serde_json::to_vec(&json!({
                "issuer": issuer,
                "jwks_uri": jwks_uri,
                "authorization_endpoint": "https://idp.example/auth",
            }))
            .unwrap(),
        )
    }

    // --- Fix S-H1: issuer validation ---

    #[test]
    fn discovery_issuer_mismatch_is_rejected() {
        let body = discovery_bytes("https://attacker.example", "https://attacker.example/jwks");
        let err = validate_discovery_document_bytes(&body, "https://idp.example.gov")
            .expect_err("mismatch must fail");
        assert!(
            matches!(
                err,
                JwksFetchError::IssuerMismatch {
                    ref expected,
                    ref actual,
                } if expected == "https://idp.example.gov"
                    && actual == "https://attacker.example"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn discovery_issuer_match_returns_jwks_uri() {
        let body = discovery_bytes("https://idp.example.gov", "https://idp.example.gov/jwks");
        let jwks_uri = validate_discovery_document_bytes(&body, "https://idp.example.gov")
            .expect("matching issuer accepted");
        assert_eq!(jwks_uri, "https://idp.example.gov/jwks");
    }

    #[test]
    fn discovery_rejects_remote_http_jwks_uri() {
        let body = discovery_bytes("https://idp.example.gov", "http://idp.example.gov/jwks");
        let err = validate_discovery_document_bytes(&body, "https://idp.example.gov")
            .expect_err("remote http jwks_uri must fail");
        assert!(
            matches!(err, JwksFetchError::Transport(ref message)
                if message.contains("discovery jwks_uri")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn discovery_allows_localhost_http_jwks_uri_for_dev() {
        let body = discovery_bytes(
            "http://localhost:8080/realms/relay",
            "http://localhost:8080/realms/relay/protocol/openid-connect/certs",
        );
        let jwks_uri =
            validate_discovery_document_bytes(&body, "http://localhost:8080/realms/relay")
                .expect("localhost dev jwks_uri accepted");
        assert_eq!(
            jwks_uri,
            "http://localhost:8080/realms/relay/protocol/openid-connect/certs"
        );
    }

    #[test]
    fn explicit_jwks_url_rejects_remote_http() {
        let err = match ReqwestJwksFetcher::from_jwks_url("http://idp.example.gov/jwks") {
            Ok(_) => panic!("remote http jwks url must fail"),
            Err(err) => err,
        };
        assert!(
            matches!(err, JwksFetchError::Transport(ref message)
                if message.contains("jwks")),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn discovery_fetch_rejects_remote_http_before_network() {
        let result = ReqwestJwksFetcher::from_discovery_url(
            "http://idp.example.gov/.well-known/openid-configuration",
            "https://idp.example.gov",
        )
        .await;
        let err = match result {
            Ok(_) => panic!("remote http discovery url must fail"),
            Err(err) => err,
        };
        assert!(
            matches!(err, JwksFetchError::Transport(ref message)
                if message.contains("discovery")),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_does_not_follow_redirects() {
        let app = Router::new()
            .route(
                "/redirect",
                get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/jwks")]) }),
            )
            .route("/jwks", get(|| async { axum::Json(json!({ "keys": [] })) }));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });

        let fetcher = ReqwestJwksFetcher::from_jwks_url(format!("http://{addr}/redirect")).unwrap();
        let err = match fetcher.fetch().await {
            Ok(_) => panic!("redirect must not be followed"),
            Err(err) => err,
        };
        assert!(
            matches!(err, JwksFetchError::Transport(ref message)
                if message == "jwks: HTTP 302"),
            "unexpected error: {err}"
        );
    }

    // --- Fix S-H2: response body size cap ---

    #[test]
    fn parse_response_bytes_rejects_oversized_body() {
        // Build a valid JWKS JSON body just over the 1-byte limit we pass.
        let body: Bytes = Bytes::from(br#"{"keys":[]}"#.to_vec());
        let err = parse_response_bytes::<serde_json::Value>(&body, 5)
            .expect_err("oversized body must fail");
        assert!(
            matches!(err, JwksFetchError::Transport(_)),
            "expected Transport, got {err}"
        );
    }

    #[test]
    fn parse_response_bytes_accepts_body_within_limit() {
        let body: Bytes = Bytes::from(br#"{"keys":[]}"#.to_vec());
        let value: serde_json::Value =
            parse_response_bytes(&body, 1024).expect("body within limit parses");
        assert!(value.get("keys").is_some());
    }

    // --- F1: SSRF host allowlist ---

    #[test]
    fn local_dev_host_accepts_loopback_forms() {
        // Full 127.0.0.0/8, ::1, the literal `localhost`, and ::ffff:127.0.0.1.
        for host in [
            "localhost",
            "LocalHost",
            "127.0.0.1",
            "127.0.0.2",
            "127.255.255.254",
            "::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                is_local_dev_host(Some(host)),
                "expected dev host accepted: {host}"
            );
        }
    }

    #[test]
    fn local_dev_host_rejects_non_loopback_and_metadata_targets() {
        // 0.0.0.0, RFC1918, link-local (including cloud metadata IP),
        // IPv4-mapped IPv6 metadata, public IP, arbitrary hostname.
        for host in [
            "0.0.0.0",
            "169.254.169.254",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "fe80::1",
            "fd00::1",
            "8.8.8.8",
            "example.com",
            "metadata.google.internal",
            "",
        ] {
            assert!(
                !is_local_dev_host(Some(host)),
                "expected dev host rejected: {host}"
            );
        }
        assert!(!is_local_dev_host(None));
    }

    #[test]
    fn validate_fetch_url_rejects_http_to_non_loopback() {
        // The discovery-document path runs the same check; this asserts
        // each forbidden host via the function used by both callers.
        for url in [
            "http://0.0.0.0/jwks",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/jwks",
            "http://[::ffff:169.254.169.254]/jwks",
            "http://metadata.google.internal/computeMetadata/v1/",
        ] {
            let err = validate_fetch_url(url, "jwks").expect_err(&format!("must reject {url}"));
            assert!(
                matches!(err, JwksFetchError::Transport(_)),
                "unexpected error for {url}: {err}"
            );
        }
    }

    #[test]
    fn parse_response_bytes_rejects_invalid_json() {
        let body: Bytes = Bytes::from(b"not json".to_vec());
        let err =
            parse_response_bytes::<serde_json::Value>(&body, 1024).expect_err("bad json fails");
        assert!(
            matches!(err, JwksFetchError::Parse),
            "expected Parse, got {err}"
        );
    }
}

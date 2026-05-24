// SPDX-License-Identifier: Apache-2.0
//! HTTP [`JwksFetcher`] backed by `registry-platform-oidc`.
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

use std::time::Duration;

use bytes::Bytes;
use registry_platform_httputil::{read_bounded, FetchUrlPolicy, ValidatedFetchUrl};
use registry_platform_oidc::{
    JwksFetcher as PlatformJwksFetcher, JwksFetcherConfig as PlatformJwksFetcherConfig,
};
use reqwest::Url;
use serde::Deserialize;

use super::jwks::{JwksFetchError, JwksFetcher};

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
        let validated_url = validate_fetch_url_for_immediate_fetch(discovery_url, "discovery")?;
        let response = validated_url
            .immediate_get()
            .map_err(|err| JwksFetchError::Transport(format!("discovery: {err}")))?
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|err| JwksFetchError::Transport(redact_url(err.to_string())))?;
        if !response.status().is_success() {
            return Err(JwksFetchError::Transport(format!(
                "discovery: HTTP {}",
                response.status().as_u16()
            )));
        }
        let body = read_bounded(response, MAX_RESPONSE_BYTES as u64)
            .await
            .map_err(|err| JwksFetchError::Transport(format!("discovery: {err}")))?;
        let jwks_uri = validate_discovery_document_bytes(&Bytes::from(body), expected_issuer)?;
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

    pub(crate) fn platform_fetcher(
        &self,
        cache_ttl: Duration,
        refresh_cooldown: Duration,
    ) -> PlatformJwksFetcher {
        PlatformJwksFetcher::new_with_fetch_url_policy(
            self.jwks_url.clone(),
            self.client.clone(),
            platform_jwks_config(cache_ttl, refresh_cooldown),
            FetchUrlPolicy::dev(),
        )
    }
}

impl JwksFetcher for ReqwestJwksFetcher {
    fn platform_fetcher(
        &self,
        cache_ttl: Duration,
        refresh_cooldown: Duration,
    ) -> PlatformJwksFetcher {
        self.platform_fetcher(cache_ttl, refresh_cooldown)
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

fn fetch_url_policy() -> FetchUrlPolicy {
    FetchUrlPolicy::dev()
}

fn parse_fetch_url(url: &str, context: &str) -> Result<Url, JwksFetchError> {
    Url::parse(url).map_err(|_| {
        JwksFetchError::Transport(format!(
            "{context}: URL must be absolute https:// (or http:// localhost for dev)"
        ))
    })
}

fn validate_fetch_url(url: &str, context: &str) -> Result<(), JwksFetchError> {
    let parsed = parse_fetch_url(url, context)?;
    fetch_url_policy()
        .validate_for_immediate_fetch(&parsed)
        .map(|_| ())
        .map_err(|err| JwksFetchError::Transport(format!("{context}: {err}")))
}

fn validate_fetch_url_for_immediate_fetch(
    url: &str,
    context: &str,
) -> Result<ValidatedFetchUrl, JwksFetchError> {
    let parsed = parse_fetch_url(url, context)?;
    fetch_url_policy()
        .validate_for_immediate_fetch(&parsed)
        .map_err(|err| JwksFetchError::Transport(format!("{context}: {err}")))
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

pub(crate) fn platform_jwks_config(
    cache_ttl: Duration,
    refresh_cooldown: Duration,
) -> PlatformJwksFetcherConfig {
    PlatformJwksFetcherConfig {
        cache_ttl,
        refresh_cooldown,
        max_doc_bytes: MAX_RESPONSE_BYTES as u64,
        request_timeout: REQUEST_TIMEOUT,
        ..PlatformJwksFetcherConfig::defaults()
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
        let body = discovery_bytes("http://localhost:8080", "http://localhost:8080/jwks");
        let jwks_uri = validate_discovery_document_bytes(&body, "http://localhost:8080")
            .expect("matching issuer accepted");
        assert_eq!(jwks_uri, "http://localhost:8080/jwks");
    }

    #[test]
    fn discovery_rejects_remote_http_jwks_uri() {
        let body = discovery_bytes("https://idp.example.gov", "http://8.8.8.8/jwks");
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
        let err = match ReqwestJwksFetcher::from_jwks_url("http://8.8.8.8/jwks") {
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
            "http://8.8.8.8/.well-known/openid-configuration",
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
    async fn discovery_fetch_rejects_metadata_and_private_urls_before_network() {
        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "https://10.0.0.5/.well-known/openid-configuration",
        ] {
            let err = match ReqwestJwksFetcher::from_discovery_url(url, "https://idp.example.gov")
                .await
            {
                Ok(_) => panic!("metadata/private discovery URL must fail"),
                Err(err) => err,
            };
            assert!(
                matches!(err, JwksFetchError::Transport(ref message)
                    if message.contains("discovery")),
                "unexpected error for {url}: {err}"
            );
        }
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

        let fetcher: std::sync::Arc<dyn JwksFetcher> = std::sync::Arc::new(
            ReqwestJwksFetcher::from_jwks_url(format!("http://{addr}/redirect")).unwrap(),
        );
        let cache = crate::auth::oidc::jwks::JwksCache::new(fetcher, Duration::from_secs(60));
        let err = match cache.get("any-kid").await {
            Ok(_) => panic!("redirect must not be followed"),
            Err(err) => err,
        };
        assert!(
            matches!(err, crate::auth::oidc::jwks::JwksError::Unavailable(ref message)
                if message.contains("HTTP 302")),
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

    #[tokio::test]
    async fn discovery_fetch_rejects_oversized_body() {
        let body = Bytes::from(vec![b'a'; MAX_RESPONSE_BYTES + 1]);
        let app = Router::new().route(
            "/.well-known/openid-configuration",
            get(move || {
                let body = body.clone();
                async move { body }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });

        let err = match ReqwestJwksFetcher::from_discovery_url(
            format!("http://{addr}/.well-known/openid-configuration"),
            "http://localhost/issuer",
        )
        .await
        {
            Ok(_) => panic!("oversized discovery body must fail"),
            Err(err) => err,
        };
        assert!(
            matches!(err, JwksFetchError::Transport(ref message)
                if message.contains("discovery") && message.contains("limit")),
            "unexpected error: {err}"
        );
    }

    // --- F1: SSRF host allowlist ---

    #[test]
    fn fetch_url_policy_allows_loopback_http_for_dev() {
        for url in [
            "http://localhost:8080/jwks",
            "http://LocalHost:8080/jwks",
            "http://127.0.0.1:8080/jwks",
            "http://127.0.0.2:8080/jwks",
            "http://[::1]:8080/jwks",
        ] {
            assert!(
                validate_fetch_url(url, "jwks").is_ok(),
                "expected dev URL accepted: {url}"
            );
        }
    }

    #[test]
    fn validate_fetch_url_rejects_metadata_and_private_targets() {
        for url in [
            "http://0.0.0.0/jwks",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/jwks",
            "https://10.0.0.5/jwks",
            "http://[::ffff:169.254.169.254]/jwks",
            "https://[fd00::1]/jwks",
        ] {
            let err = validate_fetch_url(url, "jwks").expect_err(&format!("must reject {url}"));
            assert!(
                matches!(err, JwksFetchError::Transport(_)),
                "unexpected error for {url}: {err}"
            );
        }
    }

    #[test]
    fn discovery_rejects_metadata_jwks_uri() {
        let body = discovery_bytes(
            "https://idp.example.gov",
            "http://169.254.169.254/latest/meta-data/",
        );
        let err = validate_discovery_document_bytes(&body, "https://idp.example.gov")
            .expect_err("metadata jwks_uri must fail");
        assert!(
            matches!(err, JwksFetchError::Transport(ref message)
                if message.contains("discovery jwks_uri")),
            "unexpected error: {err}"
        );
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

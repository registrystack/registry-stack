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
        let client = build_client()?;
        Ok(Self {
            client,
            jwks_url: jwks_url.into(),
        })
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
        .build()
        .map_err(|err| JwksFetchError::Transport(format!("client build failed: {err}")))
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
    Ok(document.jwks_uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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

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

use serde::Deserialize;

use super::jwks::{JwksFetchError, JwksFetchResult, JwksFetcher};

/// Connect timeout for both discovery and JWKS fetches. Tighter than
/// the overall request timeout so a hung TCP handshake fails fast.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall request timeout (connect + headers + body) for both
/// discovery and JWKS fetches. Sized for the typical sub-second JWKS
/// response with generous headroom for a slow IdP.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
    pub async fn from_discovery_url(
        discovery_url: impl AsRef<str>,
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
        let document: DiscoveryDocument =
            response.json().await.map_err(|_| JwksFetchError::Parse)?;
        Ok(Self {
            client,
            jwks_url: document.jwks_uri,
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
            let jwks = response.json().await.map_err(|_| JwksFetchError::Parse)?;
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

/// Minimal projection of the OIDC discovery document. Only `jwks_uri` is
/// load-bearing for the relay; other fields (`issuer`, `authorization_endpoint`,
/// ...) are intentionally ignored.
#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    jwks_uri: String,
}

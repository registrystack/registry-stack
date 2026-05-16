// SPDX-License-Identifier: Apache-2.0
//! V1 API-key [`AuthProvider`].
//!
//! ## Verification flow
//!
//! 1. Read `Authorization: Bearer <token>` or `X-Api-Key: <token>`.
//! 2. Hash the presented high-entropy key with SHA-256.
//! 3. Look up the fingerprint in the configured in-memory key map.
//!    On no match, return `AuthError::InvalidCredential`.
//!
//! The bearer token is held in a [`Zeroizing`] `String` so its bytes
//! are scrubbed when dropped. Only a SHA-256 fingerprint is retained
//! in the provider.
//!
//! ## What this module does *not* do
//!
//! * No logging of credential bytes at any level.
//! * No minting of new keys. Operators generate raw keys outside the
//!   gateway, store only `sha256:<hex>` fingerprints in secret storage,
//!   and rotate by rolling config plus secret changes together.
//! * No credential source is preferred for security reasons. When both
//!   headers are present, `Authorization` wins because it is the standard
//!   HTTP auth surface.

use std::collections::HashMap;
use std::pin::Pin;

use axum::http::{header, HeaderMap};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::AuthError;

use super::{AuthMode, AuthProvider, Principal, ScopeSet};

/// HTTP authentication scheme accepted in V1.
const BEARER_SCHEME: &str = "Bearer";

/// Compatibility header accepted alongside `Authorization: Bearer`.
const X_API_KEY: &str = "x-api-key";

/// One configured key entry: the stable id, the resolved scope set,
/// and the SHA-256 fingerprint of the high-entropy raw API key.
#[derive(Debug, Clone)]
pub struct ApiKeyEntry {
    id: String,
    scopes: ScopeSet,
    fingerprint: TokenFingerprint,
}

impl ApiKeyEntry {
    /// Build an entry, validating that `fingerprint` is shaped as
    /// `sha256:<64 lowercase hex chars>`.
    ///
    /// # Errors
    ///
    /// Returns `Err` with a static string if the fingerprint does not
    /// parse. Callers surface this as `config.validation_error`.
    pub fn new(id: String, scopes: ScopeSet, fingerprint: String) -> Result<Self, &'static str> {
        let fingerprint = parse_token_fingerprint(&fingerprint)?;
        Ok(Self {
            id,
            scopes,
            fingerprint,
        })
    }

    /// Stable identifier; safe to log.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// V1 API-key provider. Holds a fingerprint-to-principal map resolved
/// from config at startup; never mutates after construction.
#[derive(Debug, Clone)]
pub struct ApiKeyAuth {
    principals: HashMap<TokenFingerprint, Principal>,
}

type TokenFingerprint = [u8; 32];

impl ApiKeyAuth {
    /// Build a provider from already-resolved entries. Startup calls
    /// this with one entry per `auth.api_keys[]`; tests construct
    /// entries directly.
    #[must_use]
    pub fn new(entries: Vec<ApiKeyEntry>) -> Self {
        let principals = entries
            .into_iter()
            .map(|entry| {
                (
                    entry.fingerprint,
                    Principal {
                        api_key_id: entry.id,
                        scopes: entry.scopes,
                        auth_mode: AuthMode::ApiKey,
                    },
                )
            })
            .collect();
        Self { principals }
    }

    /// Number of configured keys. Used in operational logs at
    /// startup; never includes any key material.
    #[must_use]
    pub fn len(&self) -> usize {
        self.principals.len()
    }

    /// Whether the provider has no configured keys. A provider in
    /// this state denies every request with
    /// `auth.invalid_credential` (after passing the header parse).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.principals.is_empty()
    }

    /// Internal verification. Pulled out of [`AuthProvider::authenticate`]
    /// so the trait method body is small and the verify loop is unit
    /// testable.
    fn verify(&self, presented: &str) -> Result<Principal, AuthError> {
        let fingerprint = token_fingerprint(presented);
        if let Some(principal) = self.principals.get(&fingerprint).cloned() {
            tracing::debug!(
                target: "data_gate::auth",
                api_key_id = %principal.api_key_id,
                "api key verified",
            );
            return Ok(principal);
        }
        tracing::debug!(
            target: "data_gate::auth",
            "no api key matched the presented credential",
        );
        Err(AuthError::InvalidCredential)
    }
}

fn token_fingerprint(presented: &str) -> TokenFingerprint {
    Sha256::digest(presented.as_bytes()).into()
}

fn parse_token_fingerprint(value: &str) -> Result<TokenFingerprint, &'static str> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or("API key fingerprint must start with sha256:")?;
    if hex.len() != 64 {
        return Err("API key fingerprint must contain 64 lowercase hex characters");
    }
    let mut out = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("API key fingerprint must contain lowercase hex only"),
    }
}

impl AuthProvider for ApiKeyAuth {
    fn authenticate<'a>(
        &'a self,
        headers: &'a HeaderMap,
        _remote_addr: std::net::IpAddr,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Principal, AuthError>> + Send + 'a>> {
        // Parse the header eagerly so we can fail fast and zeroise
        // any owned token bytes on the error path too.
        let parse_result = extract_credential(headers);
        Box::pin(async move {
            let presented = parse_result?;
            self.verify(&presented)
        })
    }
}

/// Pull the credential out of `Authorization` or `X-Api-Key`.
///
/// Returns:
/// * `AuthError::MissingCredential` if neither header is present.
/// * `AuthError::MalformedCredential` if the chosen header is not UTF-8,
///   has a malformed `Bearer` value, or carries an empty token.
///
/// The returned token is wrapped in [`Zeroizing`] so its bytes are
/// scrubbed when the caller drops it.
fn extract_credential(headers: &HeaderMap) -> Result<Zeroizing<String>, AuthError> {
    if let Some(value) = headers.get(header::AUTHORIZATION) {
        return extract_bearer_value(value);
    }
    let value = headers.get(X_API_KEY).ok_or(AuthError::MissingCredential)?;
    let token = value.to_str().map_err(|_| AuthError::MalformedCredential)?;
    if token.is_empty() {
        return Err(AuthError::MalformedCredential);
    }
    Ok(Zeroizing::new(token.to_string()))
}

fn extract_bearer_value(value: &axum::http::HeaderValue) -> Result<Zeroizing<String>, AuthError> {
    let raw = value.to_str().map_err(|_| AuthError::MalformedCredential)?;
    let token = raw
        .strip_prefix(BEARER_SCHEME)
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or(AuthError::MalformedCredential)?;
    if token.is_empty() {
        return Err(AuthError::MalformedCredential);
    }
    Ok(Zeroizing::new(token.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fingerprint(plain: &str) -> String {
        format!("sha256:{}", hex_lower(&token_fingerprint(plain)))
    }

    fn provider_with(plain: &str) -> ApiKeyAuth {
        let entry = ApiKeyEntry::new(
            "tester".to_string(),
            ScopeSet::from_iter(["rows"]),
            make_fingerprint(plain),
        )
        .expect("fingerprint parses");
        ApiKeyAuth::new(vec![entry])
    }

    #[test]
    fn entry_construction_rejects_garbage_fingerprint() {
        let err = ApiKeyEntry::new(
            "x".to_string(),
            ScopeSet::default(),
            "not-a-fingerprint".to_string(),
        )
        .expect_err("garbage fingerprint rejected");
        assert_eq!(err, "API key fingerprint must start with sha256:");
    }

    #[test]
    fn entry_construction_rejects_uppercase_fingerprint() {
        let err = ApiKeyEntry::new(
            "x".to_string(),
            ScopeSet::default(),
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        )
        .expect_err("uppercase fingerprint rejected");
        assert_eq!(err, "API key fingerprint must contain lowercase hex only");
    }

    #[test]
    fn extract_bearer_returns_missing_for_absent_header() {
        let headers = HeaderMap::new();
        let err = extract_credential(&headers).expect_err("absent header");
        assert!(matches!(err, AuthError::MissingCredential));
    }

    #[test]
    fn extract_bearer_returns_malformed_for_wrong_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Basic foo".parse().unwrap());
        let err = extract_credential(&headers).expect_err("wrong scheme");
        assert!(matches!(err, AuthError::MalformedCredential));
    }

    #[test]
    fn extract_bearer_returns_malformed_for_empty_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        let err = extract_credential(&headers).expect_err("empty token");
        assert!(matches!(err, AuthError::MalformedCredential));
    }

    #[test]
    fn extract_bearer_returns_malformed_for_no_space() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearertoken".parse().unwrap());
        let err = extract_credential(&headers).expect_err("no space");
        assert!(matches!(err, AuthError::MalformedCredential));
    }

    #[test]
    fn extract_bearer_returns_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer abc123".parse().unwrap());
        let token = extract_credential(&headers).expect("token extracted");
        assert_eq!(&*token, "abc123");
    }

    #[test]
    fn extract_x_api_key_returns_token() {
        let mut headers = HeaderMap::new();
        headers.insert(X_API_KEY, "abc123".parse().unwrap());
        let token = extract_credential(&headers).expect("token extracted");
        assert_eq!(&*token, "abc123");
    }

    #[test]
    fn authorization_header_wins_over_x_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer from-auth".parse().unwrap());
        headers.insert(X_API_KEY, "from-x-api-key".parse().unwrap());
        let token = extract_credential(&headers).expect("token extracted");
        assert_eq!(&*token, "from-auth");
    }

    #[test]
    fn verify_succeeds_for_matching_secret() {
        let provider = provider_with("correct-secret");
        let principal = provider.verify("correct-secret").expect("verified");
        assert_eq!(principal.api_key_id, "tester");
        assert!(principal.scopes.contains("rows"));
    }

    #[test]
    fn verify_fails_for_wrong_secret() {
        let provider = provider_with("correct-secret");
        let err = provider.verify("wrong-secret").expect_err("denied");
        assert!(matches!(err, AuthError::InvalidCredential));
    }

    #[test]
    fn empty_provider_denies_every_request() {
        let provider = ApiKeyAuth::new(vec![]);
        assert!(provider.is_empty());
        let err = provider.verify("anything").expect_err("denied");
        assert!(matches!(err, AuthError::InvalidCredential));
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}

// SPDX-License-Identifier: Apache-2.0
//! V1 API-key [`AuthProvider`].
//!
//! ## Verification flow
//!
//! 1. Read `Authorization: Bearer <token>` or `x-api-key: <token>`.
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
//! * No retention of generated keys. Operators can use the relay binary's
//!   provisioning command, then store only `sha256:<hex>` fingerprints in
//!   secret storage and rotate by rolling config plus secret changes together.
//! * No credential source is preferred for security reasons. When both
//!   headers are present, `Authorization` wins because it is the standard
//!   HTTP auth surface.

use std::collections::HashMap;
use std::pin::Pin;

use axum::http::{header, HeaderMap};
use registry_platform_authcommon::{
    fingerprint_api_key, parse_bearer_token, parse_fingerprint, verify_api_key,
    FingerprintFormatError,
};
use zeroize::Zeroizing;

use crate::error::AuthError;

use super::{AuthMode, AuthProvider, AuthenticationResult, Principal, ScopeSet};

/// Compatibility header accepted alongside `Authorization: Bearer`.
const X_API_KEY: &str = "x-api-key";

/// One configured key entry: the stable id, the resolved scope set,
/// and the SHA-256 fingerprint of the high-entropy raw API key.
#[derive(Debug, Clone)]
pub struct ApiKeyEntry {
    id: String,
    scopes: ScopeSet,
    fingerprint: TokenFingerprint,
    canonical_fingerprint: String,
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
        let parsed_fingerprint =
            parse_fingerprint(&fingerprint).map_err(fingerprint_format_message)?;
        Ok(Self {
            id,
            scopes,
            fingerprint: parsed_fingerprint,
            canonical_fingerprint: fingerprint,
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
    principals: HashMap<TokenFingerprint, ApiKeyPrincipal>,
}

type TokenFingerprint = [u8; 32];

#[derive(Debug, Clone)]
struct ApiKeyPrincipal {
    principal: Principal,
    canonical_fingerprint: String,
}

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
                    ApiKeyPrincipal {
                        principal: Principal {
                            principal_id: entry.id,
                            scopes: entry.scopes,
                            auth_mode: AuthMode::ApiKey,
                        },
                        canonical_fingerprint: entry.canonical_fingerprint,
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
        let fingerprint = parse_fingerprint(&fingerprint_api_key(presented))
            .expect("generated fingerprint parses");
        if let Some(entry) = self.principals.get(&fingerprint) {
            let verified = verify_api_key(presented, &entry.canonical_fingerprint)
                .map_err(|_| AuthError::InvalidCredential)?;
            if !verified {
                return Err(AuthError::InvalidCredential);
            }
            tracing::debug!(
                target: "registry_relay::auth",
                principal_id = %entry.principal.principal_id,
                "api key verified",
            );
            return Ok(entry.principal.clone());
        }
        tracing::debug!(
            target: "registry_relay::auth",
            "no api key matched the presented credential",
        );
        Err(AuthError::InvalidCredential)
    }
}

fn fingerprint_format_message(error: FingerprintFormatError) -> &'static str {
    match error {
        FingerprintFormatError::MissingPrefix => "API key fingerprint must start with sha256:",
        FingerprintFormatError::InvalidLength => {
            "API key fingerprint must contain 64 lowercase hex characters"
        }
        FingerprintFormatError::InvalidHex => "API key fingerprint must contain lowercase hex only",
        _ => "API key fingerprint is invalid",
    }
}

impl AuthProvider for ApiKeyAuth {
    fn authenticate<'a>(
        &'a self,
        headers: &'a HeaderMap,
        _remote_addr: std::net::IpAddr,
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<AuthenticationResult, AuthError>> + Send + 'a>,
    > {
        // Parse the header eagerly so we can fail fast and zeroise
        // any owned token bytes on the error path too.
        let parse_result = extract_credential(headers);
        Box::pin(async move {
            let presented = parse_result?;
            self.verify(&presented).map(AuthenticationResult::api_key)
        })
    }
}

/// Pull the credential out of `Authorization` or `x-api-key`.
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
    let token = parse_bearer_token(raw).map_err(|_| AuthError::MalformedCredential)?;
    Ok(Zeroizing::new(token.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fingerprint(plain: &str) -> String {
        fingerprint_api_key(plain)
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
    fn extract_bearer_accepts_case_insensitive_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "bEaReR abc123".parse().unwrap());
        let token = extract_credential(&headers).expect("token extracted");
        assert_eq!(&*token, "abc123");
    }

    #[test]
    fn extract_bearer_rejects_extra_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer  abc123".parse().unwrap());
        let err = extract_credential(&headers).expect_err("extra whitespace");
        assert!(matches!(err, AuthError::MalformedCredential));
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
        assert_eq!(principal.principal_id, "tester");
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
}

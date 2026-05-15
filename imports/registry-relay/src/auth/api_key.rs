// SPDX-License-Identifier: Apache-2.0
//! V1 API-key [`AuthProvider`].
//!
//! ## Verification flow
//!
//! 1. Read `Authorization: Bearer <token>` or `X-Api-Key: <token>`.
//! 2. For each configured entry, run `Argon2::verify_password` against
//!    the parsed PHC string. Argon2's verifier is constant-time on the
//!    derived-hash comparison; we iterate sequentially because the
//!    expected entry count is small (single digits in practice) and
//!    parallelisation here adds no security and risks timing-channel
//!    surprises.
//! 3. On a match, return [`Principal`] with the configured id, scope
//!    set, and `AuthMode::ApiKey`. On no match, return
//!    `AuthError::InvalidCredential`.
//!
//! The bearer token is held in a [`Zeroizing`] `String` so its bytes
//! are scrubbed when dropped. `argon2::PasswordHash` takes `&str`, so
//! the verification call still sees plaintext, but it never leaves
//! this function frame.
//!
//! ## What this module does *not* do
//!
//! * No logging of credential bytes at any level.
//! * No hashing of new keys; rotation arrives in Wave 4 with the
//!   `auth.api_key` config parameters block (architect note risk #9).
//! * No credential source is preferred for security reasons. When both
//!   headers are present, `Authorization` wins because it is the standard
//!   HTTP auth surface.

use std::pin::Pin;

use argon2::password_hash::PasswordHash;
use argon2::{Argon2, PasswordVerifier};
use axum::http::{header, HeaderMap};
use zeroize::Zeroizing;

use crate::error::AuthError;

use super::{AuthMode, AuthProvider, Principal, ScopeSet};

/// HTTP authentication scheme accepted in V1.
const BEARER_SCHEME: &str = "Bearer";

/// Compatibility header accepted alongside `Authorization: Bearer`.
const X_API_KEY: &str = "x-api-key";

/// One configured key entry: the stable id, the resolved scope set,
/// and the parsed Argon2id PHC string. The PHC string is stored as
/// `String` because [`PasswordHash::new`] borrows `&str`; rotation
/// (Wave 4) will swap this for a token-rotation struct.
#[derive(Debug, Clone)]
pub struct ApiKeyEntry {
    id: String,
    scopes: ScopeSet,
    /// PHC-format Argon2id hash. Validated at construction; reparsed
    /// per verification because `PasswordHash<'a>` borrows `&'a str`
    /// and the verifier needs a fresh parse per call.
    phc_string: String,
}

impl ApiKeyEntry {
    /// Build an entry, validating that `phc` parses as a PHC hash so
    /// startup fails fast on bad fixtures instead of every request
    /// paying the parse-then-fail cost.
    ///
    /// # Errors
    ///
    /// Returns `Err` with a static string if the PHC string does not
    /// parse. Callers (the future Wave-4 config-to-auth wire-up)
    /// surface this as `config.validation_error`.
    pub fn new(id: String, scopes: ScopeSet, phc: String) -> Result<Self, &'static str> {
        // Validate now; the parsed reference is dropped because we
        // re-parse per verification call.
        let _ = PasswordHash::new(&phc).map_err(|_| "invalid Argon2 PHC string")?;
        Ok(Self {
            id,
            scopes,
            phc_string: phc,
        })
    }

    /// Stable identifier; safe to log.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// V1 API-key provider. Holds a `Vec<ApiKeyEntry>` resolved from
/// config at startup; never mutates after construction.
#[derive(Debug, Clone)]
pub struct ApiKeyAuth {
    entries: Vec<ApiKeyEntry>,
}

impl ApiKeyAuth {
    /// Build a provider from already-resolved entries. The Wave-0
    /// config-to-auth wire-up calls this with one entry per
    /// `auth.api_keys[]`; tests construct entries directly.
    #[must_use]
    pub fn new(entries: Vec<ApiKeyEntry>) -> Self {
        Self { entries }
    }

    /// Number of configured keys. Used in operational logs at
    /// startup; never includes any key material.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the provider has no configured keys. A provider in
    /// this state denies every request with
    /// `auth.invalid_credential` (after passing the header parse).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Internal verification. Pulled out of [`AuthProvider::authenticate`]
    /// so the trait method body is small and the verify loop is unit
    /// testable.
    fn verify(&self, presented: &str) -> Result<Principal, AuthError> {
        let argon = Argon2::default();
        for entry in &self.entries {
            let Ok(parsed) = PasswordHash::new(&entry.phc_string) else {
                // Constructor enforces validity; reaching this arm
                // means memory corruption or a panic-safe rebuild.
                // Skip rather than panic so the rest of the keyring
                // still works.
                tracing::trace!(
                    target: "data_gate::auth",
                    api_key_id = %entry.id,
                    "stored PHC string failed to parse; skipping entry"
                );
                continue;
            };
            if argon.verify_password(presented.as_bytes(), &parsed).is_ok() {
                tracing::debug!(
                    target: "data_gate::auth",
                    api_key_id = %entry.id,
                    "api key verified",
                );
                return Ok(Principal {
                    api_key_id: entry.id.clone(),
                    scopes: entry.scopes.clone(),
                    auth_mode: AuthMode::ApiKey,
                });
            }
        }
        tracing::debug!(
            target: "data_gate::auth",
            "no api key matched the presented credential",
        );
        Err(AuthError::InvalidCredential)
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
    use argon2::password_hash::SaltString;
    use argon2::PasswordHasher;

    fn make_phc(plain: &str) -> String {
        // Fixed salt is fine: tests are deterministic and the salt
        // is not load-bearing for verification, only for hash
        // derivation. Production hashes are minted out-of-band.
        let salt = SaltString::from_b64("dGVzdHNhbHRkZ3RmaXh0dXJl")
            .expect("static test salt parses as b64");
        Argon2::default()
            .hash_password(plain.as_bytes(), &salt)
            .expect("hash succeeds for test fixture")
            .to_string()
    }

    fn provider_with(plain: &str) -> ApiKeyAuth {
        let entry = ApiKeyEntry::new(
            "tester".to_string(),
            ScopeSet::from_iter(["rows"]),
            make_phc(plain),
        )
        .expect("phc parses");
        ApiKeyAuth::new(vec![entry])
    }

    #[test]
    fn entry_construction_rejects_garbage_phc() {
        let err = ApiKeyEntry::new(
            "x".to_string(),
            ScopeSet::default(),
            "not-a-phc-string".to_string(),
        )
        .expect_err("garbage PHC rejected");
        assert_eq!(err, "invalid Argon2 PHC string");
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
}

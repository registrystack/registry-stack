// SPDX-License-Identifier: Apache-2.0

//! The seam between the session store and the issuer: renewing an access
//! token with a refresh token, and revoking a refresh token. The caller of the
//! store owns the implementation, so the store and the check need no network.

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use registry_platform_httputil::BearerToken;
use serde_json::{Map, Value};

/// The refresh token type the session holds: zeroized on drop, never printed.
pub use registry_platform_httputil::client::RefreshToken;

/// Why the issuer did not renew or revoke a token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantError {
    /// The issuer refused the refresh token (`invalid_grant`): the session is
    /// over.
    Refused,
    /// The issuer could not be reached or answered something else: the
    /// refresh token may still be good.
    Unavailable,
}

impl fmt::Display for GrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Refused => "the issuer refused the refresh token",
            Self::Unavailable => "the issuer could not be reached",
        })
    }
}

impl std::error::Error for GrantError {}

/// What a renewal returns.
#[derive(Debug)]
pub struct Renewed {
    pub access_token: BearerToken,
    pub expires_at: Instant,
    /// The rotated refresh token. Absent when the issuer did not rotate it.
    pub refresh_token: Option<RefreshToken>,
}

/// Renewal and revocation, per kind of sign-in, for one audience.
pub trait Grants: Send + Sync + 'static {
    /// Exchange `refresh_token` for a fresh access token for `resource`.
    fn refresh(
        &self,
        kind: &str,
        refresh_token: &RefreshToken,
        resource: &str,
    ) -> impl Future<Output = Result<Renewed, GrantError>> + Send;

    /// Revoke `refresh_token` at the issuer.
    fn revoke(
        &self,
        kind: &str,
        refresh_token: &RefreshToken,
    ) -> impl Future<Output = Result<(), GrantError>> + Send;
}

impl<G: Grants> Grants for Arc<G> {
    fn refresh(
        &self,
        kind: &str,
        refresh_token: &RefreshToken,
        resource: &str,
    ) -> impl Future<Output = Result<Renewed, GrantError>> + Send {
        (**self).refresh(kind, refresh_token, resource)
    }

    fn revoke(
        &self,
        kind: &str,
        refresh_token: &RefreshToken,
    ) -> impl Future<Output = Result<(), GrantError>> + Send {
        (**self).revoke(kind, refresh_token)
    }
}

/// One authorization code to redeem, with everything the redemption must bind
/// it to.
pub struct Redemption<'a> {
    /// The kind of sign-in, which names the confidential client.
    pub kind: &'a str,
    pub code: &'a str,
    /// The PKCE verifier of the authorization request.
    pub verifier: &'a str,
    pub redirect_uri: &'a str,
    /// The audience the authorization request named.
    pub resource: &'a str,
    /// The nonce the ID token must carry.
    pub nonce: &'a str,
}

/// What a redeemed code yields. The ID token was verified (signature, issuer,
/// audience, expiry, nonce) before this value existed; it is not kept.
pub struct Redeemed {
    pub access_token: BearerToken,
    pub expires_at: Instant,
    pub refresh_token: Option<RefreshToken>,
    /// The verified ID token's `sub`.
    pub subject: String,
    /// Every claim of the verified ID token.
    pub claims: Map<String, Value>,
}

impl fmt::Debug for Redeemed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Redeemed").finish_non_exhaustive()
    }
}

/// Redeeming an authorization code and verifying the ID token it returns.
/// [`GrantError::Refused`] covers a code the issuer refused and an ID token
/// that failed verification.
pub trait Redeemer: Send + Sync + 'static {
    fn redeem(
        &self,
        redemption: &Redemption<'_>,
    ) -> impl Future<Output = Result<Redeemed, GrantError>> + Send;
}

impl<G: Redeemer> Redeemer for Arc<G> {
    fn redeem(
        &self,
        redemption: &Redemption<'_>,
    ) -> impl Future<Output = Result<Redeemed, GrantError>> + Send {
        (**self).redeem(redemption)
    }
}

#[cfg(test)]
pub(crate) mod fake;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refresh_token_never_prints() {
        let token = RefreshToken::new("refresh-canary-value").expect("token");
        assert!(!format!("{token:?}").contains("canary"));
        let renewed = Renewed {
            access_token: BearerToken::new("access-canary-value").expect("token"),
            expires_at: Instant::now(),
            refresh_token: Some(token.clone()),
        };
        assert!(!format!("{renewed:?}").contains("canary"));
        assert_eq!(token.clone().expose(), "refresh-canary-value");
    }
}

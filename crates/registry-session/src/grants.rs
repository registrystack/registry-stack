// SPDX-License-Identifier: Apache-2.0

//! The seam between the session store and the issuer: renewing an access
//! token with a refresh token, and revoking a refresh token. The caller of the
//! store owns the implementation, so the store and the check need no network.

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use registry_platform_httputil::BearerToken;
use zeroize::Zeroizing;

/// The refresh token type the session holds. One alias is the whole boundary
/// to the shared client's own type.
pub type RefreshToken = HeldRefreshToken;

/// A refresh token held for one audience: zeroized on drop, never printed.
pub struct HeldRefreshToken(Zeroizing<String>);

impl HeldRefreshToken {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The token text, for the one request that presents it to the issuer.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Clone for HeldRefreshToken {
    fn clone(&self) -> Self {
        Self::new(self.0.as_str())
    }
}

impl fmt::Debug for HeldRefreshToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshToken")
            .finish_non_exhaustive()
    }
}

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

#[cfg(test)]
pub(crate) mod fake;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refresh_token_never_prints() {
        let token = HeldRefreshToken::new("refresh-canary-value");
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

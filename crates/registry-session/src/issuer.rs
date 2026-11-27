// SPDX-License-Identifier: Apache-2.0

//! The real issuer: one confidential client per kind of sign-in, redeeming
//! codes, renewing and revoking over HTTP, and verifying ID tokens against the
//! issuer's published keys.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::Algorithm;
use registry_platform_config::SecretResolver;
use registry_platform_httputil::client::{
    ClientSecretClient, ClientSecretConfig, OAuthErrorCode, TokenError,
};
use registry_platform_oidc::{
    IssuerNetworkPolicy, JwksFetcher, JwksFetcherConfig, OidcError, TokenVerifier,
    TokenVerifierConfig,
};
use serde_json::{Map, Value};
use url::Url;
use zeroize::Zeroizing;

use crate::config::{describe_secret_failure, RuntimeConfig};
use crate::grants::{GrantError, Grants, Redeemed, Redeemer, Redemption, RefreshToken, Renewed};
use crate::runtime::RuntimeError;

/// Clock skew tolerated on an ID token's time claims.
const ID_TOKEN_LEEWAY: Duration = Duration::from_secs(60);
/// The asymmetric algorithms an ID token may be signed with.
const ID_TOKEN_ALGORITHMS: [Algorithm; 5] = [
    Algorithm::EdDSA,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::RS256,
    Algorithm::PS256,
];

struct KindClient {
    client: ClientSecretClient,
    verifier: TokenVerifier,
}

/// The token side of every kind of sign-in.
pub struct HttpIssuer {
    kinds: HashMap<String, KindClient>,
}

fn endpoint(text: &str) -> Result<Url, TokenError> {
    Url::parse(text).map_err(|_| TokenError::Configuration {
        reason: "an issuer endpoint is not a URL",
    })
}

impl HttpIssuer {
    /// Build one client per kind from the runtime file and the resolved client
    /// secrets. No network call is made.
    pub fn new(config: &RuntimeConfig, secrets: &SecretResolver) -> Result<Self, RuntimeError> {
        let issuer = config.issuer.id.as_str();
        let network = IssuerNetworkPolicy::new(issuer, false)
            .map_err(|error| RuntimeError::Issuer(error.to_string()))?;
        let policy = network.declared_jwks_fetch_policy();
        let jwks = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            config.issuer.jwks.as_str().to_owned(),
            JwksFetcherConfig::defaults(),
            policy.clone(),
        ));
        let mut kinds = HashMap::new();
        for sign_in in &config.sign_ins {
            let reference = sign_in.client_secret_ref.as_str();
            let secret = secrets.resolve(reference).map_err(|error| {
                RuntimeError::Secret(describe_secret_failure(
                    "signIns.clientSecretRef",
                    reference,
                    &error,
                ))
            })?;
            let secret = std::str::from_utf8(secret.expose_secret())
                .map(|text| Zeroizing::new(text.trim_end_matches(['\n', '\r']).to_owned()))
                .map_err(|_| RuntimeError::ClientSecret)?;
            let client_id = sign_in.client_id.as_str();
            let client_config = endpoint(config.issuer.token.as_str())
                .and_then(|token| ClientSecretConfig::new(token, client_id, secret))
                .and_then(|client_config| {
                    client_config
                        .with_revocation_endpoint(endpoint(config.issuer.revocation.as_str())?)
                })
                .map_err(|error| RuntimeError::Issuer(error.to_string()))?
                .with_fetch_url_policy(policy.clone());
            let client = ClientSecretClient::new(client_config)
                .map_err(|error| RuntimeError::Issuer(error.to_string()))?;
            let verifier = TokenVerifier::new(
                TokenVerifierConfig::access_token_profile(
                    issuer,
                    vec![client_id.to_owned()],
                    ID_TOKEN_ALGORITHMS.to_vec(),
                    Vec::new(),
                )
                .with_allowed_clients(vec![client_id.to_owned()])
                .with_leeway(ID_TOKEN_LEEWAY),
                jwks.clone(),
            );
            kinds.insert(
                sign_in.id.as_str().to_owned(),
                KindClient { client, verifier },
            );
        }
        Ok(Self { kinds })
    }
}

fn redeem_failure(error: &TokenError) -> GrantError {
    match error {
        TokenError::Transport { .. } | TokenError::Unavailable => GrantError::Unavailable,
        TokenError::Protocol { status } if *status >= 500 => GrantError::Unavailable,
        _ => GrantError::Refused,
    }
}

fn verification_failure(error: &OidcError) -> GrantError {
    match error {
        OidcError::Transport(_)
        | OidcError::BoundedRead(_)
        | OidcError::FetchUrl(_)
        | OidcError::HttpStatus(_)
        | OidcError::Parse => GrantError::Unavailable,
        _ => GrantError::Refused,
    }
}

impl Redeemer for HttpIssuer {
    async fn redeem(&self, redemption: &Redemption<'_>) -> Result<Redeemed, GrantError> {
        let kind = self.kinds.get(redemption.kind).ok_or(GrantError::Refused)?;
        let redirect_uri = Url::parse(redemption.redirect_uri).map_err(|_| GrantError::Refused)?;
        let issued = kind
            .client
            .redeem_authorization_code(
                redemption.code,
                &redirect_uri,
                redemption.verifier,
                Some(redemption.resource),
            )
            .await
            .map_err(|error| {
                tracing::warn!(kind = error.kind(), "the token request failed");
                redeem_failure(&error)
            })?;
        let parts = issued.into_parts();
        // A session never outlives its access token, so a token without a
        // stated lifetime opens none.
        let (Some(expires_at), Some(id_token)) = (parts.expires_at, parts.id_token.as_ref()) else {
            tracing::warn!("the token response lacked a lifetime or an ID token");
            revoke_quietly(kind, parts.refresh_token.as_ref()).await;
            return Err(GrantError::Refused);
        };
        let verified = match kind.verifier.verify_related_token(id_token).await {
            Ok(verified) => verified,
            Err(error) => {
                tracing::warn!(%error, "the ID token was refused");
                revoke_quietly(kind, parts.refresh_token.as_ref()).await;
                return Err(verification_failure(&error));
            }
        };
        let nonce = verified
            .claims
            .extra
            .get("nonce")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !crate::store::tokens_match(nonce, redemption.nonce) {
            tracing::warn!("the ID token carried the wrong nonce");
            revoke_quietly(kind, parts.refresh_token.as_ref()).await;
            return Err(GrantError::Refused);
        }
        let claims = match serde_json::to_value(&verified.claims) {
            Ok(Value::Object(claims)) => claims,
            _ => Map::new(),
        };
        Ok(Redeemed {
            access_token: parts.access_token,
            expires_at,
            refresh_token: parts.refresh_token,
            subject: verified.claims.sub.unwrap_or_default(),
            claims,
        })
    }
}

/// Revoke a refresh token the sign-in will not use, so nothing stays live at
/// the issuer. A failure is logged in fixed text.
async fn revoke_quietly(kind: &KindClient, token: Option<&RefreshToken>) {
    if let Some(token) = token {
        if kind.client.revoke_refresh_token(token).await.is_err() {
            tracing::warn!("a refresh token could not be revoked at the issuer");
        }
    }
}

impl Grants for HttpIssuer {
    async fn refresh(
        &self,
        kind: &str,
        refresh_token: &RefreshToken,
        resource: &str,
    ) -> Result<Renewed, GrantError> {
        let kind = self.kinds.get(kind).ok_or(GrantError::Unavailable)?;
        let issued = kind
            .client
            .refresh(refresh_token, Some(resource))
            .await
            .map_err(|error| match error {
                TokenError::Refused {
                    code: OAuthErrorCode::InvalidGrant,
                } => GrantError::Refused,
                other => {
                    tracing::warn!(kind = other.kind(), "a token renewal failed");
                    GrantError::Unavailable
                }
            })?;
        let parts = issued.into_parts();
        let Some(expires_at) = parts.expires_at else {
            tracing::warn!("a renewed access token has no stated lifetime");
            return Err(GrantError::Unavailable);
        };
        Ok(Renewed {
            access_token: parts.access_token,
            expires_at,
            refresh_token: parts.refresh_token,
        })
    }

    async fn revoke(&self, kind: &str, refresh_token: &RefreshToken) -> Result<(), GrantError> {
        let kind = self.kinds.get(kind).ok_or(GrantError::Unavailable)?;
        kind.client
            .revoke_refresh_token(refresh_token)
            .await
            .map_err(|error| {
                tracing::warn!(kind = error.kind(), "a token revocation failed");
                GrantError::Unavailable
            })
    }
}

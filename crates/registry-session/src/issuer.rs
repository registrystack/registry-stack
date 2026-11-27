// SPDX-License-Identifier: Apache-2.0

//! The real issuer: one confidential client per kind of sign-in, redeeming
//! codes, renewing and revoking over HTTP, and verifying ID tokens against the
//! issuer's published keys.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::Algorithm;
use registry_platform_config::SecretResolver;
use registry_platform_httputil::client::{
    ClientSecretClient, ClientSecretConfig, OAuthErrorCode, TokenError,
};
use registry_platform_httputil::BearerToken;
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
                .with_request_timeout(Duration::from_millis(
                    config.issuer.timeout_milliseconds.get(),
                ))
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

/// Why an ID token was refused, in fixed text: the error's own text can carry
/// what the token claimed, which the log never repeats.
fn refusal_reason(error: &OidcError) -> &'static str {
    match error {
        OidcError::IssuerMismatch { .. } => "the issuer does not match",
        OidcError::AudienceMismatch => "the audience does not match",
        OidcError::ClientNotAllowed => "the authorized party is not the client",
        OidcError::TokenExpired => "the token is expired",
        OidcError::TokenNotYetValid => "the token is not yet valid",
        OidcError::InvalidTimeClaims => "the time claims are missing or out of range",
        OidcError::SignatureInvalid => "the signature is invalid",
        OidcError::AlgorithmNotAllowed => "the algorithm is not allowed",
        OidcError::TokenTypeNotAllowed => "the token type is not allowed",
        OidcError::MissingKid | OidcError::KidTooLong | OidcError::UnknownKid => {
            "the signing key cannot be identified"
        }
        OidcError::MalformedToken | OidcError::InvalidToken => "the token is malformed",
        _ => "the token failed verification",
    }
}

/// What an access token's `aud` says about the resource a hop asked for.
#[derive(Debug, Eq, PartialEq)]
enum AudienceCheck {
    Matches,
    Mismatch,
    /// The token is not a JWT with a readable `aud`: only the issuer can say
    /// whom it is for.
    Unreadable,
}

/// Read the audience from the payload of `token`, a token the issuer's token
/// endpoint returned over the authenticated connection. The signature is not
/// checked: the check is a guard against an issuer that ignores the resource
/// the request named, not a verification of the token.
fn audience_check(token: &BearerToken, resource: &str) -> AudienceCheck {
    let header = token.authorization_header_value();
    let Some(text) = header
        .to_str()
        .ok()
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return AudienceCheck::Unreadable;
    };
    let mut parts = text.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return AudienceCheck::Unreadable;
    };
    let Some(claims) = URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    else {
        return AudienceCheck::Unreadable;
    };
    match claims.get("aud") {
        Some(Value::String(audience)) if audience == resource => AudienceCheck::Matches,
        Some(Value::Array(audiences))
            if audiences
                .iter()
                .any(|audience| audience.as_str() == Some(resource)) =>
        {
            AudienceCheck::Matches
        }
        Some(Value::String(_) | Value::Array(_)) => AudienceCheck::Mismatch,
        _ => AudienceCheck::Unreadable,
    }
}

/// Whether the access token an issuer returned may be kept for `resource`. An
/// unreadable token is kept, and the gap is logged.
fn audience_accepted(token: &BearerToken, resource: &str) -> bool {
    match audience_check(token, resource) {
        AudienceCheck::Matches => true,
        AudienceCheck::Mismatch => {
            tracing::warn!("the issuer returned an access token for another audience");
            false
        }
        AudienceCheck::Unreadable => {
            tracing::warn!("an access token's audience could not be read, so it is not checked");
            true
        }
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
                tracing::warn!(reason = refusal_reason(&error), "the ID token was refused");
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
        if !audience_accepted(&parts.access_token, redemption.resource) {
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
        // The rotated refresh token is revoked with the session the caller
        // ends on this refusal: nothing else holds it.
        if !audience_accepted(&parts.access_token, resource) {
            revoke_quietly(kind, parts.refresh_token.as_ref()).await;
            return Err(GrantError::Refused);
        }
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn jwt(claims: &Value) -> BearerToken {
        let part = |value: &Value| URL_SAFE_NO_PAD.encode(value.to_string());
        BearerToken::new(format!(
            "{}.{}.c2lnbmF0dXJl",
            part(&json!({"alg": "EdDSA"})),
            part(claims)
        ))
        .expect("token")
    }

    #[test]
    fn an_access_token_is_checked_against_the_resource_the_hop_asked_for() {
        let resource = "https://api.example/person";
        let check = |claims: Value| audience_check(&jwt(&claims), resource);
        assert_eq!(check(json!({"aud": resource})), AudienceCheck::Matches);
        assert_eq!(
            check(json!({"aud": ["https://other.example", resource]})),
            AudienceCheck::Matches
        );
        assert_eq!(
            check(json!({"aud": "https://other.example"})),
            AudienceCheck::Mismatch
        );
        assert_eq!(
            check(json!({"aud": ["https://other.example"]})),
            AudienceCheck::Mismatch
        );
        assert_eq!(
            check(json!({"aud": format!("{resource}/")})),
            AudienceCheck::Mismatch,
            "an audience is compared exactly"
        );
        assert_eq!(check(json!({"sub": "x"})), AudienceCheck::Unreadable);
        assert_eq!(check(json!({"aud": 7})), AudienceCheck::Unreadable);
    }

    #[test]
    fn a_token_that_is_not_a_jwt_cannot_be_checked_and_is_logged_as_such() {
        let opaque = BearerToken::new("opaque-token-value").expect("token");
        assert_eq!(audience_check(&opaque, "r"), AudienceCheck::Unreadable);
        let not_json = BearerToken::new("a.bm90IGpzb24.c").expect("token");
        assert_eq!(audience_check(&not_json, "r"), AudienceCheck::Unreadable);
        let four_parts = BearerToken::new("a.e30.c.d").expect("token");
        assert_eq!(audience_check(&four_parts, "r"), AudienceCheck::Unreadable);
        assert!(audience_accepted(&opaque, "r"));
    }

    #[test]
    fn a_refusal_reason_is_fixed_text_that_repeats_nothing_the_token_claimed() {
        let reason = refusal_reason(&OidcError::IssuerMismatch {
            expected: "https://id.example".to_owned(),
            actual: "https://evil.example".to_owned(),
        });
        assert_eq!(reason, "the issuer does not match");
        for error in [
            OidcError::AudienceMismatch,
            OidcError::TokenExpired,
            OidcError::SignatureInvalid,
            OidcError::UnknownKid,
        ] {
            assert!(!refusal_reason(&error).is_empty());
        }
    }
}

//! Bearer-token authentication against a configured OIDC issuer.
//!
//! One [`TokenAuthenticator`] verifies the applicant tokens a portal presents
//! to create a session. A second, built from the Evidence service credential
//! issuer block, is held for the result-read route. Both use the strict
//! access-token profile: an exact issuer, one audience, a closed algorithm list,
//! the RFC 9068 `typ` values, a ceiling on token lifetime, and keys resolved
//! only through the configured key source.

use std::{sync::Arc, time::Duration};

use registry_platform_authcommon::parse_bearer_token;
use registry_platform_config::{JwksSource, SecretResolver};
use registry_platform_oidc::{
    parse_static_jwks, IssuerNetworkPolicy, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig,
    OidcError, TokenVerifier, TokenVerifierConfig,
};

use crate::{config::TokenIssuerConfig, session::Principal};

/// The access-token types accepted: the two spellings RFC 9068 permits.
const ACCESS_TOKEN_TYPES: [&str; 2] = ["at+jwt", "application/at+jwt"];

/// Why a request was not authenticated.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthError {
    #[error("the request carried no bearer credential")]
    Missing,
    #[error("the presented credential was refused")]
    Refused,
    #[error("the issuer key set is unavailable")]
    KeySource,
}

/// Why an authenticator could not be built at startup.
#[derive(Debug, thiserror::Error)]
pub enum AuthSetupError {
    #[error("the issuer or its key source is invalid")]
    Issuer,
    #[error("the issuer key set could not be discovered")]
    Discovery,
    #[error("the static key set secret could not be read")]
    StaticKeySecret,
    #[error("the static key set is not a valid JWKS")]
    StaticKeySet,
}

/// Verifies bearer tokens from one issuer and extracts the caller.
pub struct TokenAuthenticator {
    verifier: TokenVerifier,
    issuer: String,
    required_scope: String,
}

impl std::fmt::Debug for TokenAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenAuthenticator")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl TokenAuthenticator {
    /// Build from the issuer block, resolving the key source.
    pub async fn build(
        config: &TokenIssuerConfig,
        secrets: &SecretResolver,
    ) -> Result<Self, AuthSetupError> {
        let provider = &config.provider;
        let issuer = provider.issuer.to_string();
        let network = IssuerNetworkPolicy::new(&issuer, provider.allow_insecure_http)
            .map_err(|_| AuthSetupError::Issuer)?;
        let fetcher = match &provider.jwks_source {
            JwksSource::Uri { uri } => JwksFetcher::new_with_fetch_url_policy(
                uri.to_string(),
                JwksFetcherConfig::defaults(),
                network.declared_jwks_fetch_policy(),
            ),
            JwksSource::Discovery {} => {
                let discovery = OidcDiscoveryConfig {
                    issuer: issuer.clone(),
                    jwks_uri_override: None,
                    discovery_timeout: Duration::from_secs(5),
                    max_doc_bytes: 1024 * 1024,
                };
                let (document, policy) = registry_platform_oidc::fetch_discovery_for_issuer(
                    &discovery,
                    provider.allow_insecure_http,
                )
                .await
                .map_err(|_| AuthSetupError::Discovery)?;
                JwksFetcher::new_with_fetch_url_policy(
                    document.jwks_uri,
                    JwksFetcherConfig::defaults(),
                    policy,
                )
            }
            JwksSource::Static { document_ref } => {
                let document = secrets
                    .resolve(document_ref)
                    .map_err(|_| AuthSetupError::StaticKeySecret)?;
                let jwks = parse_static_jwks(document.expose_secret())
                    .map_err(|_| AuthSetupError::StaticKeySet)?;
                JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults())
            }
        };
        let mut profile = TokenVerifierConfig::access_token_profile(
            issuer.clone(),
            vec![provider.audience.clone()],
            config
                .algorithms
                .iter()
                .map(|algorithm| algorithm.to_jsonwebtoken())
                .collect(),
            ACCESS_TOKEN_TYPES
                .iter()
                .map(|typ| (*typ).to_owned())
                .collect(),
        )
        .with_max_token_lifetime(Some(Duration::from_secs(
            config.maximum_token_lifetime_seconds,
        )));
        if let Some(client) = &config.allowed_client {
            profile = profile.with_allowed_clients(vec![client.clone()]);
        }
        Ok(Self {
            verifier: TokenVerifier::new(profile, Arc::new(fetcher)),
            issuer,
            required_scope: config.required_scope.clone(),
        })
    }

    /// Authenticate the value of an `Authorization` header.
    pub async fn authenticate(&self, authorization: Option<&str>) -> Result<Principal, AuthError> {
        let header = authorization.ok_or(AuthError::Missing)?;
        let token = parse_bearer_token(header).map_err(|_| AuthError::Missing)?;
        let verified = match self.verifier.verify(token).await {
            Ok(verified) => verified,
            Err(error) if is_key_source_failure(&error) => {
                tracing::warn!(
                    target: "registry_evidence_oid4vp::auth",
                    "the issuer key set is unavailable"
                );
                return Err(AuthError::KeySource);
            }
            Err(_) => return Err(AuthError::Refused),
        };
        // The scope gate runs on the verified token's scope set: a correctly
        // signed token for this audience without the scope grants nothing.
        if !verified
            .scopes
            .iter()
            .any(|scope| scope == &self.required_scope)
        {
            return Err(AuthError::Refused);
        }
        let client = match verified.matched_client_id() {
            Ok(Some(client)) => Some(client.to_owned()),
            Ok(None) => verified
                .claims
                .azp
                .clone()
                .or_else(|| verified.claims.client_id.clone()),
            Err(_) => return Err(AuthError::Refused),
        }
        .filter(|client| !client.is_empty());
        let subject = verified.claims.sub.clone().filter(|sub| !sub.is_empty());
        if client.is_none() && subject.is_none() {
            return Err(AuthError::Refused);
        }
        Ok(Principal {
            issuer: verified
                .claims
                .iss
                .clone()
                .unwrap_or_else(|| self.issuer.clone()),
            subject,
            client,
        })
    }
}

/// Whether a verification failure was the key source rather than the token.
/// Unknown failures default to the caller's side.
fn is_key_source_failure(error: &OidcError) -> bool {
    matches!(
        error,
        OidcError::Transport(_)
            | OidcError::BoundedRead(_)
            | OidcError::FetchUrl(_)
            | OidcError::HttpStatus(_)
            | OidcError::InvalidUrl
            | OidcError::Parse
            | OidcError::InvalidJwk
            | OidcError::EmptyKeySet
            | OidcError::MissingIssuer
    )
}

//! The authorization boundary of the adopter-facing offer endpoint.
//!
//! This is the resource-server half of the process. It verifies a Mint-issued
//! access token through `registry-platform-oidc`, on the same strict profile
//! Evidence's own authenticator builds: an exact issuer, a closed audience
//! list, a closed algorithm list, a closed access-token `typ` list, a ceiling
//! on token lifetime, and keys resolved only through the configured key set.
//!
//! The client half of the process, which authenticates *to* Mint with this
//! service's own private key, is [`crate::issuer`]. The two never share a code
//! path: nothing here reads the client key, nothing here is derived from the
//! client identity, and the two are configured by separate documents. A
//! deployment whose client key is unusable still authorizes offers, and a
//! deployment whose offer issuer is unreachable still requests credentials.

use std::{collections::HashSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{
    JwksFetcher, JwksFetcherConfig, OidcError, TokenVerifier, TokenVerifierConfig,
};

use crate::config::{AccessTokenAlgorithm, OfferAuthorizationConfig, ValidationMode};

/// The access-token types this service accepts, which are the two spellings
/// RFC 9068 permits for a JWT access token.
const ACCESS_TOKEN_TYPES: [&str; 2] = ["at+jwt", "application/at+jwt"];

/// What a verified offer token established.
///
/// Only what an audit record needs. Nothing derived from it reaches a wallet,
/// and the token itself is never retained.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthorizedOffer {
    /// The client identifier the issuer vouched for, when the token carried
    /// one.
    pub client: Option<String>,
    /// The token subject, when the token carried one.
    pub subject: Option<String>,
}

/// Why an offer was not authorized.
///
/// The two cases are kept apart because they point at different people: a
/// refused token is the caller's to fix, and an unreachable key set is the
/// operator's. Neither carries any part of the token.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error("the request carried no bearer credential")]
    Missing,
    #[error("the presented credential was refused")]
    Refused,
    #[error("the offer key set is unavailable")]
    KeySource,
}

/// The seam the offer endpoint authorizes through.
#[async_trait]
pub trait OfferAuthorizer: Send + Sync {
    async fn authorize(&self, credential: &str) -> Result<AuthorizedOffer, AuthorizationError>;
}

/// The Mint-issued access token verifier.
#[derive(Debug)]
pub struct MintResourceServer {
    verifier: Arc<TokenVerifier>,
}

impl MintResourceServer {
    /// Build the resource server from its own configuration document.
    ///
    /// Nothing about the client identity this service authenticates to Mint
    /// with is read here, on purpose: the offer boundary must be configurable,
    /// and auditable, without reference to who this service is elsewhere.
    #[must_use]
    pub fn from_config(config: &OfferAuthorizationConfig, mode: ValidationMode) -> Self {
        let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            config.jwks_uri.clone(),
            JwksFetcherConfig::defaults(),
            fetch_url_policy(config, mode),
        ));
        Self::new(Arc::new(TokenVerifier::new(
            verifier_profile(config),
            fetcher,
        )))
    }

    /// Build the resource server over an already constructed verifier, for a
    /// deployment that resolved its key source another way.
    #[must_use]
    pub fn new(verifier: Arc<TokenVerifier>) -> Self {
        Self { verifier }
    }
}

/// The token profile an offer credential is verified under.
///
/// Stated once and exported, so a deployment that resolved its key set another
/// way verifies under exactly the profile [`MintResourceServer::from_config`]
/// applies rather than a restatement of it that could drift from it.
#[must_use]
pub fn verifier_profile(config: &OfferAuthorizationConfig) -> TokenVerifierConfig {
    let algorithms = config
        .algorithms
        .iter()
        .map(|algorithm| match algorithm {
            AccessTokenAlgorithm::EdDSA => jsonwebtoken::Algorithm::EdDSA,
            AccessTokenAlgorithm::ES256 => jsonwebtoken::Algorithm::ES256,
            AccessTokenAlgorithm::RS256 => jsonwebtoken::Algorithm::RS256,
        })
        .collect();
    TokenVerifierConfig::access_token_profile(
        config.issuer.clone(),
        config.audiences.clone(),
        algorithms,
        ACCESS_TOKEN_TYPES
            .iter()
            .map(|typ| (*typ).to_owned())
            .collect(),
    )
    .with_allowed_clients(config.authorized_clients.clone())
    .with_denied_kids(HashSet::new())
    .with_max_token_lifetime(Some(Duration::from_secs(
        config.maximum_token_lifetime_seconds,
    )))
}

/// Plain HTTP only for a supervised local development group whose offer issuer
/// is itself on loopback. Every other deployment fetches its key set over
/// https, exactly as Evidence does.
fn fetch_url_policy(config: &OfferAuthorizationConfig, mode: ValidationMode) -> FetchUrlPolicy {
    let local = mode == ValidationMode::SupervisedLocalDevelopment
        && config.issuer.starts_with("http://127.0.0.1:")
        && config.jwks_uri.starts_with("http://127.0.0.1:");
    if local {
        return FetchUrlPolicy {
            allowed_schemes: vec!["http".to_owned()],
            allow_localhost: true,
            allow_http_private_network: false,
            deny_private_ranges: true,
            deny_cloud_metadata: true,
        };
    }
    FetchUrlPolicy {
        allowed_schemes: vec!["https".to_owned()],
        allow_localhost: true,
        allow_http_private_network: false,
        deny_private_ranges: false,
        deny_cloud_metadata: true,
    }
}

#[async_trait]
impl OfferAuthorizer for MintResourceServer {
    async fn authorize(&self, credential: &str) -> Result<AuthorizedOffer, AuthorizationError> {
        if credential.is_empty() {
            return Err(AuthorizationError::Missing);
        }
        match self.verifier.verify(credential).await {
            Ok(verified) => Ok(AuthorizedOffer {
                client: verified
                    .matched_client
                    .or_else(|| verified.claims.client_id.clone())
                    .or_else(|| verified.claims.azp.clone()),
                subject: verified.claims.sub.clone(),
            }),
            Err(error) if is_key_source_failure(&error) => {
                tracing::warn!(
                    target: "registry_evidence_oid4vci::authorizer",
                    "the offer key set is unavailable"
                );
                Err(AuthorizationError::KeySource)
            }
            Err(_) => Err(AuthorizationError::Refused),
        }
    }
}

/// Whether a verification failure was this deployment's key source rather than
/// the caller's token.
///
/// Every known failure is listed rather than folded into the wildcard, which
/// covers only variants added to the shared verifier after this was written.
/// Those default to the caller's side: a failure this code has never seen is
/// one it cannot honestly describe as an unreachable key set.
fn is_key_source_failure(error: &OidcError) -> bool {
    match error {
        OidcError::Transport(_)
        | OidcError::BoundedRead(_)
        | OidcError::FetchUrl(_)
        | OidcError::HttpStatus(_)
        | OidcError::InvalidUrl
        | OidcError::Parse
        | OidcError::InvalidJwk
        | OidcError::EmptyKeySet
        | OidcError::MissingIssuer => true,
        OidcError::IssuerMismatch { .. }
        | OidcError::MalformedToken
        | OidcError::AlgorithmNotAllowed
        | OidcError::TokenTypeNotAllowed
        | OidcError::MissingKid
        | OidcError::KidTooLong
        | OidcError::UnknownKid
        | OidcError::TokenExpired
        | OidcError::TokenNotYetValid
        | OidcError::AudienceMismatch
        | OidcError::SignatureInvalid
        | OidcError::InvalidToken
        | OidcError::ClientNotAllowed => false,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::tests::valid_config;

    #[tokio::test]
    async fn an_empty_credential_is_missing_rather_than_refused() {
        let config = valid_config();
        let server = MintResourceServer::from_config(&config.offers, config.validation_mode);
        assert_eq!(server.authorize("").await, Err(AuthorizationError::Missing));
    }

    #[test]
    fn the_resource_server_is_built_from_the_offer_document_alone() {
        // The construction takes the offer boundary and the validation mode.
        // There is no parameter for the Mint client identity, so no key or
        // identifier belonging to the client half can reach this one.
        let config = valid_config();
        let _server = MintResourceServer::from_config(&config.offers, config.validation_mode);
    }

    #[test]
    fn a_supervised_local_offer_issuer_is_the_only_plain_http_key_source() {
        let mut config = valid_config();
        assert_eq!(
            fetch_url_policy(&config.offers, ValidationMode::SupervisedLocalDevelopment)
                .allowed_schemes,
            ["https"],
            "an https issuer keeps its https key source in every mode"
        );

        config.offers.issuer = "http://127.0.0.1:8081".to_owned();
        config.offers.jwks_uri = "http://127.0.0.1:8081/.well-known/jwks.json".to_owned();
        assert_eq!(
            fetch_url_policy(&config.offers, ValidationMode::Strict).allowed_schemes,
            ["https"],
            "strict mode never opens a plain http key source"
        );
        let supervised =
            fetch_url_policy(&config.offers, ValidationMode::SupervisedLocalDevelopment);
        assert_eq!(supervised.allowed_schemes, ["http"]);
        assert!(supervised.deny_private_ranges);
    }
}

// SPDX-License-Identifier: Apache-2.0

//! Bearer access-token authentication for the document routes.
//!
//! There is no unauthenticated document route: every one resolves its
//! caller here first. Authentication answers, in order: is the credential a
//! verifiable RFC 9068 access token from the configured issuer, for this
//! deployment's audience, from a client it admits, signed by a key the
//! issuer published? Did it arrive through a token exchange this deployment
//! never declared? And which one access profile does the verified client
//! resolve to, with the scopes, actor kind, and principal claim that
//! profile demands?
//!
//! What a caller may do to a document is decided after this point against
//! the resolved profile and the document's frozen custody, never against
//! raw claims.

use std::sync::Arc;

use registry_documents_core::{
    AccessProfiles, AccessRefusal, ActorKind, ActorKindClaim, Caller, MissingScope,
    VerifiedTokenFacts,
};
use registry_platform_authcommon::validate_compact_access_token;
use registry_platform_oidc::{
    actor_kind, ClaimError, ClaimNames, JwksFetcher, OidcError, TokenVerifier, TokenVerifierConfig,
    ASSERTION_ISSUER_CLAIM,
};
use thiserror::Error;

pub struct DocumentsAuthenticator {
    verifier: TokenVerifier,
    /// The configured claim the verifier reads scopes from, named in the
    /// refusal log of a token that lacks a scope its profile requires.
    scope_claim: String,
    claim_names: ClaimNames,
    profiles: AccessProfiles,
    /// Whether the deployment declared any assertion authority at all.
    binds_assertion_issuers: bool,
}

impl DocumentsAuthenticator {
    #[must_use]
    pub fn new(
        verifier: TokenVerifierConfig,
        keys: Arc<JwksFetcher>,
        profiles: AccessProfiles,
        binds_assertion_issuers: bool,
    ) -> Self {
        let claim_names = ClaimNames::default();
        claim_names
            .validate()
            .expect("the default contextual claim names are valid");
        Self {
            scope_claim: verifier.scope_claim.clone(),
            verifier: TokenVerifier::new(verifier, keys),
            claim_names,
            profiles,
            binds_assertion_issuers,
        }
    }

    /// Verify one credential and resolve it to exactly one access profile.
    pub async fn authenticate(&self, token: &str) -> Result<Caller, AuthenticationError> {
        validate_compact_access_token(token).map_err(|_| AuthenticationError::Refused)?;
        let verified = self.verifier.verify(token).await.map_err(|error| {
            tracing::debug!(error = %error, "the Document Store bearer credential did not verify");
            verifier_failure(&error)
        })?;
        // An exchanged token names the authority whose assertion produced it.
        // The platform applies no rule while the deployment's map is empty,
        // so an empty map would trust every authority the issuer federates.
        // Refuse the exchange instead.
        if !self.binds_assertion_issuers
            && verified.claims.extra.contains_key(ASSERTION_ISSUER_CLAIM)
        {
            tracing::debug!(
                "an exchanged credential arrived at a deployment that declared no assertion authority"
            );
            return Err(AuthenticationError::Profile);
        }
        let client_id = verified
            .matched_client_id()
            .map_err(|_| AuthenticationError::Claims)?;
        let facts = VerifiedTokenFacts {
            issuer: verified.claims.iss.as_deref(),
            subject: verified.claims.sub.as_deref(),
            client_id,
            scopes: &verified.scopes,
            actor_kind: actor_kind_claim(actor_kind(&verified.claims, &self.claim_names)),
            claims: &verified.claims.extra,
        };
        self.profiles
            .resolve(&facts)
            .map_err(|refusal| match refusal {
                AccessRefusal::Profile => {
                    // A scope miss is the refusal an operator can fix. Log
                    // the configured claim and scope, never the token's own.
                    if let Some(missing) = self.profiles.missing_scope(&facts) {
                        tracing::info!(
                            "{}",
                            ScopeRefusal {
                                claim: &self.scope_claim,
                                missing,
                            }
                        );
                    }
                    AuthenticationError::Profile
                }
                AccessRefusal::Claims => AuthenticationError::Claims,
            })
    }
}

/// The value-free sentence logged when a token lacks a scope its access
/// profile requires.
struct ScopeRefusal<'a> {
    claim: &'a str,
    missing: MissingScope<'a>,
}

impl std::fmt::Display for ScopeRefusal<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "a Document Store request was refused because the token's `{}` claim does not carry the `{}` scope access profile `{}` requires; issue that scope to the client, or set authentication.oidc.scopeClaim to the claim the issuer emits",
            self.claim, self.missing.scope, self.missing.profile
        )
    }
}

impl std::fmt::Debug for DocumentsAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DocumentsAuthenticator")
            .field("verifier", &"<redacted>")
            .field("binds_assertion_issuers", &self.binds_assertion_issuers)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthenticationError {
    #[error("the bearer credential was refused")]
    Refused,
    #[error("the verified identity claims are invalid")]
    Claims,
    #[error("the caller's access profile is not authorized for this request")]
    Profile,
    /// The verifier could not reach a verdict at all.
    #[error("the credential could not be verified because this verifier cannot answer")]
    Unavailable,
}

/// Separate a verifier outage from a bad credential.
///
/// A 401 tells a caller its credential is the problem, so it is reserved
/// for credentials. When the issuer's discovery document or key set cannot
/// be fetched, read, parsed, or used, nothing has been learned about the
/// credential.
fn verifier_failure(error: &OidcError) -> AuthenticationError {
    match error {
        OidcError::Transport(_)
        | OidcError::BoundedRead(_)
        | OidcError::FetchUrl(_)
        | OidcError::HttpStatus(_)
        | OidcError::InvalidUrl
        | OidcError::Parse
        | OidcError::InvalidJwk
        | OidcError::EmptyKeySet
        | OidcError::MissingIssuer
        | OidcError::ConflictingEndpointConfiguration => AuthenticationError::Unavailable,
        // Every other outcome is a judgement about the credential, including
        // an unknown `kid`: a key the issuer never published is a forgery
        // signal. A variant the platform adds later reads as a refusal until
        // it is classified here, so a new outcome can never widen the door.
        _ => AuthenticationError::Refused,
    }
}

/// The verified actor kind as the access profiles read it. The Document
/// Store admits services and people; an agent is a well-formed kind no
/// profile admits.
fn actor_kind_claim(
    result: Result<registry_platform_oidc::ActorKind, ClaimError>,
) -> ActorKindClaim {
    use registry_platform_oidc::ActorKind as Verified;
    match result {
        Ok(Verified::Human) => ActorKindClaim::Present(ActorKind::Human),
        Ok(Verified::Service) => ActorKindClaim::Present(ActorKind::Service),
        Ok(Verified::Agent) => ActorKindClaim::Unadmitted,
        Err(ClaimError::Missing(_)) => ActorKindClaim::Absent,
        Err(_) => ActorKindClaim::Malformed,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use registry_documents_core::DocumentsProject;
    use registry_platform_oidc::JwksFetcherConfig;
    use serde_json::json;

    pub(crate) const ISSUER: &str = "https://identity.example.test/realms/registry";
    pub(crate) const AUDIENCE: &str = "urn:example:documents";
    const SECRET: &[u8] = b"01234567890123456789012345678901";

    pub(crate) fn project() -> DocumentsProject {
        DocumentsProject::decode(
            "documents.yaml",
            include_bytes!("../../../products/documents/examples/starter/documents.yaml"),
        )
        .unwrap()
        .value
    }

    fn keys() -> Arc<JwksFetcher> {
        Arc::new(JwksFetcher::new_static(
            serde_json::from_value(json!({"keys": [{
                "kty": "oct",
                "kid": "test",
                "alg": "HS256",
                "use": "sig",
                "k": URL_SAFE_NO_PAD.encode(SECRET),
            }]}))
            .unwrap(),
            JwksFetcherConfig::defaults(),
        ))
    }

    /// The verifier profile the runtime builds, with the symmetric test
    /// algorithm in place of the production asymmetric pair.
    fn verifier() -> TokenVerifierConfig {
        TokenVerifierConfig::access_token_profile(
            ISSUER,
            vec![AUDIENCE.to_owned()],
            vec![Algorithm::HS256],
            registry_platform_oidc::access_token_typ_set("at+jwt"),
        )
        .with_scope_claim("scope")
        .with_allowed_clients(vec![
            "civil-registry-app".to_owned(),
            "citizen-portal".to_owned(),
            "partner-portal".to_owned(),
            "case-portal".to_owned(),
            "unprofiled-client".to_owned(),
        ])
    }

    pub(crate) fn authenticator() -> DocumentsAuthenticator {
        DocumentsAuthenticator::new(verifier(), keys(), AccessProfiles::new(&project()), false)
    }

    /// Sign an access token, filling in the claims a real token always
    /// carries so a test only states what it varies.
    pub(crate) fn token(mut claims: serde_json::Value) -> String {
        let now = chrono::Utc::now().timestamp();
        let object = claims.as_object_mut().unwrap();
        object.entry("iss").or_insert(json!(ISSUER));
        object.entry("aud").or_insert(json!(AUDIENCE));
        object.entry("iat").or_insert(json!(now));
        object.entry("exp").or_insert(json!(now + 300));
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test".to_owned());
        header.typ = Some("at+jwt".to_owned());
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(SECRET)).unwrap()
    }

    pub(crate) fn citizen_claims() -> serde_json::Value {
        json!({
            "sub": "citizen-1",
            "azp": "citizen-portal",
            "scope": "documents:own",
            "registry_actor_kind": "human",
        })
    }

    #[tokio::test]
    async fn a_verified_token_resolves_to_its_profile_and_principal() {
        let caller = authenticator()
            .authenticate(&token(citizen_claims()))
            .await
            .unwrap();
        assert_eq!(caller.issuer, ISSUER);
        assert_eq!(caller.subject, "citizen-1");
        assert_eq!(caller.profile_id.as_str(), "citizen");
        assert_eq!(caller.kind, ActorKind::Human);
    }

    #[tokio::test]
    async fn a_malformed_or_foreign_credential_is_refused() {
        let authenticator = authenticator();
        assert_eq!(
            authenticator.authenticate("not-a-token").await,
            Err(AuthenticationError::Refused)
        );
        let mut foreign = citizen_claims();
        foreign["iss"] = json!("https://other.example.test");
        assert_eq!(
            authenticator.authenticate(&token(foreign)).await,
            Err(AuthenticationError::Refused)
        );
        let mut expired = citizen_claims();
        expired["exp"] = json!(chrono::Utc::now().timestamp() - 3_600);
        assert_eq!(
            authenticator.authenticate(&token(expired)).await,
            Err(AuthenticationError::Refused)
        );
    }

    #[tokio::test]
    async fn a_token_outside_every_profile_is_a_profile_refusal() {
        let authenticator = authenticator();
        let mut unscoped = citizen_claims();
        unscoped["scope"] = json!("documents:read");
        assert_eq!(
            authenticator.authenticate(&token(unscoped)).await,
            Err(AuthenticationError::Profile)
        );
        let mut unprofiled = citizen_claims();
        unprofiled["azp"] = json!("unprofiled-client");
        assert_eq!(
            authenticator.authenticate(&token(unprofiled)).await,
            Err(AuthenticationError::Profile)
        );
        let mut agent = citizen_claims();
        agent["registry_actor_kind"] = json!("agent");
        assert_eq!(
            authenticator.authenticate(&token(agent)).await,
            Err(AuthenticationError::Profile)
        );
        let mut service = citizen_claims();
        service["registry_actor_kind"] = json!("service");
        assert_eq!(
            authenticator.authenticate(&token(service)).await,
            Err(AuthenticationError::Profile)
        );
    }

    #[tokio::test]
    async fn an_exchanged_token_is_refused_where_no_assertion_authority_is_declared() {
        let mut exchanged = citizen_claims();
        exchanged[ASSERTION_ISSUER_CLAIM] = json!("https://partner.example.test");
        assert_eq!(
            authenticator().authenticate(&token(exchanged)).await,
            Err(AuthenticationError::Profile)
        );
    }

    #[test]
    fn a_key_set_outage_is_not_a_credential_refusal() {
        assert_eq!(
            verifier_failure(&OidcError::EmptyKeySet),
            AuthenticationError::Unavailable
        );
        assert_eq!(
            verifier_failure(&OidcError::Parse),
            AuthenticationError::Unavailable
        );
    }
}

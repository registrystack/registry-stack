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
    AccessProfiles, AccessRefusal, ActorKind, ActorKindClaim, Caller, VerifiedTokenFacts,
};
use registry_platform_authcommon::{validate_compact_access_token, DeclaredScope, FailedCheck};
use registry_platform_oidc::{
    actor_kind, ClaimError, ClaimNames, JwksFetcher, OidcError, TokenVerifier, TokenVerifierConfig,
    ASSERTION_ISSUER_CLAIM,
};
use thiserror::Error;

pub struct DocumentsAuthenticator {
    verifier: TokenVerifier,
    claim_names: ClaimNames,
    profiles: AccessProfiles,
    /// The claim the deployment reads scopes from, as configured.
    scope_claim: String,
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
    /// A refusal names the check it failed, for the operator's counter and
    /// log line. The answer to the caller does not carry it.
    pub async fn authenticate(&self, token: &str) -> Result<Caller, AuthenticationError> {
        self.authenticate_declaring(token)
            .await
            .map_err(|refusal| refusal.error)
    }

    /// As [`Self::authenticate`], and a scope refusal also carries what the
    /// deployment declared about it: the scope claim name, the scope the
    /// profile requires, and the profile's id. None of it comes from the
    /// token.
    pub async fn authenticate_declaring(&self, token: &str) -> Result<Caller, DeclaredRefusal> {
        validate_compact_access_token(token)
            .map_err(|_| AuthenticationError::Refused(FailedCheck::CredentialMalformed))?;
        let verified = self
            .verifier
            .verify(token)
            .await
            .map_err(|error| verifier_failure(&error))?;
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
            return Err(AuthenticationError::Profile(FailedCheck::TokenAssertionIssuer).into());
        }
        let client_id = verified
            .matched_client_id()
            .map_err(|_| AuthenticationError::Claims(FailedCheck::TokenClient))?;
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
                    let check = self.profile_check(&facts);
                    let declared = (check == FailedCheck::Scope)
                        .then(|| self.declared_scope(&facts))
                        .flatten();
                    DeclaredRefusal {
                        error: AuthenticationError::Profile(check),
                        declared,
                    }
                }
                AccessRefusal::Claims => AuthenticationError::Claims(claims_check(&facts)).into(),
            })
    }

    /// The scope claim, the scope and the access profile a scope refusal is
    /// about, all from configuration.
    fn declared_scope(&self, facts: &VerifiedTokenFacts<'_>) -> Option<DeclaredScope> {
        let missing = self.profiles.missing_scope(facts)?;
        Some(
            DeclaredScope::new(&self.scope_claim)
                .with_required_scope(missing.scope)
                .with_access_profile(missing.profile),
        )
    }

    /// Which check a profile refusal failed. The access profiles answer only
    /// that no profile admits the token. A missing scope is the one the
    /// profiles name themselves. Resolving the same facts under each kind a
    /// profile can admit separates a client no profile lists from a profile
    /// that wants another actor kind: when no kind reaches past the profile
    /// lookup, the client has no profile.
    fn profile_check(&self, facts: &VerifiedTokenFacts<'_>) -> FailedCheck {
        if facts.client_id.is_none() {
            return FailedCheck::TokenClient;
        }
        if self.profiles.missing_scope(facts).is_some() {
            return FailedCheck::Scope;
        }
        let profile_exists = ActorKind::ALL.into_iter().any(|kind| {
            let probe = VerifiedTokenFacts {
                actor_kind: ActorKindClaim::Present(kind),
                ..*facts
            };
            !matches!(self.profiles.resolve(&probe), Err(AccessRefusal::Profile))
        });
        if profile_exists {
            FailedCheck::ActorKind
        } else {
            FailedCheck::AccessProfile
        }
    }
}

/// Which check an identity-claims refusal failed: a malformed actor-kind
/// claim, or a principal or issuer the profile cannot use.
fn claims_check(facts: &VerifiedTokenFacts<'_>) -> FailedCheck {
    if facts.actor_kind == ActorKindClaim::Malformed {
        FailedCheck::ActorKind
    } else {
        FailedCheck::TokenClaims
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

/// A refusal of authentication with the values the deployment declared about
/// it, when it is a scope refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredRefusal {
    pub error: AuthenticationError,
    pub declared: Option<DeclaredScope>,
}

impl From<AuthenticationError> for DeclaredRefusal {
    fn from(error: AuthenticationError) -> Self {
        Self {
            error,
            declared: None,
        }
    }
}

/// Why authentication did not admit a caller. Each refusal carries the check
/// it failed, which is operator-side only and never written to a response.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthenticationError {
    #[error("the bearer credential was refused")]
    Refused(FailedCheck),
    #[error("the verified identity claims are invalid")]
    Claims(FailedCheck),
    #[error("the caller's access profile is not authorized for this request")]
    Profile(FailedCheck),
    /// The verifier could not reach a verdict at all.
    #[error("the credential could not be verified because this verifier cannot answer")]
    Unavailable,
}

impl AuthenticationError {
    /// The check this refusal failed. A new variant does not compile until it
    /// names its check.
    #[must_use]
    #[deny(clippy::wildcard_enum_match_arm)]
    pub const fn failed_check(&self) -> FailedCheck {
        match self {
            Self::Refused(check) | Self::Claims(check) | Self::Profile(check) => *check,
            Self::Unavailable => FailedCheck::KeySourceUnavailable,
        }
    }
}

/// Separate a verifier outage from a bad credential.
///
/// A 401 tells a caller its credential is the problem, so it is reserved
/// for credentials. When the issuer's discovery document or key set cannot
/// be fetched, read, parsed, or used, nothing has been learned about the
/// credential.
///
/// A refusal of the credential names the check the verifier says it failed.
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
        _ => AuthenticationError::Refused(error.failed_check()),
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

    pub(crate) fn keys() -> Arc<JwksFetcher> {
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

    /// The check `authenticate` reports for `claims`, signed as a real token.
    async fn refused_check(claims: serde_json::Value) -> FailedCheck {
        authenticator()
            .authenticate(&token(claims))
            .await
            .expect_err("the token is refused")
            .failed_check()
    }

    #[tokio::test]
    async fn a_malformed_or_foreign_credential_is_refused() {
        let authenticator = authenticator();
        assert_eq!(
            authenticator.authenticate("not-a-token").await,
            Err(AuthenticationError::Refused(
                FailedCheck::CredentialMalformed
            ))
        );
        let mut foreign = citizen_claims();
        foreign["iss"] = json!("https://other.example.test");
        assert_eq!(
            authenticator.authenticate(&token(foreign)).await,
            Err(AuthenticationError::Refused(FailedCheck::TokenIssuer))
        );
        let mut expired = citizen_claims();
        expired["exp"] = json!(chrono::Utc::now().timestamp() - 3_600);
        assert_eq!(
            authenticator.authenticate(&token(expired)).await,
            Err(AuthenticationError::Refused(FailedCheck::TokenTime))
        );
        let mut elsewhere = citizen_claims();
        elsewhere["aud"] = json!("urn:example:elsewhere");
        assert_eq!(
            authenticator.authenticate(&token(elsewhere)).await,
            Err(AuthenticationError::Refused(FailedCheck::TokenAudience))
        );
    }

    #[tokio::test]
    async fn a_scope_refusal_declares_the_configured_values_and_none_of_the_tokens() {
        let mut unscoped = citizen_claims();
        unscoped["scope"] = json!("canary-scope-from-the-token");
        let refusal = authenticator()
            .authenticate_declaring(&token(unscoped))
            .await
            .unwrap_err();
        assert_eq!(
            refusal.error,
            AuthenticationError::Profile(FailedCheck::Scope)
        );
        let declared = refusal.declared.expect("a scope refusal declares values");
        assert_eq!(declared.scope_claim(), "scope");
        assert_eq!(declared.required_scope(), Some("documents:own"));
        assert_eq!(declared.access_profile(), Some("citizen"));
        assert!(!format!("{declared:?}").contains("canary-scope-from-the-token"));
        // Another refusal declares nothing.
        let mut unprofiled = citizen_claims();
        unprofiled["azp"] = json!("unprofiled-client");
        let other = authenticator()
            .authenticate_declaring(&token(unprofiled))
            .await
            .unwrap_err();
        assert_eq!(other.declared, None);
    }

    #[tokio::test]
    async fn a_token_outside_every_profile_is_a_profile_refusal() {
        let mut unscoped = citizen_claims();
        unscoped["scope"] = json!("documents:read");
        assert_eq!(
            authenticator().authenticate(&token(unscoped)).await,
            Err(AuthenticationError::Profile(FailedCheck::Scope))
        );
        // The verifier admits this client and no access profile lists it.
        let mut unprofiled = citizen_claims();
        unprofiled["azp"] = json!("unprofiled-client");
        assert_eq!(
            authenticator().authenticate(&token(unprofiled)).await,
            Err(AuthenticationError::Profile(FailedCheck::AccessProfile))
        );
        let mut agent = citizen_claims();
        agent["registry_actor_kind"] = json!("agent");
        assert_eq!(
            authenticator().authenticate(&token(agent)).await,
            Err(AuthenticationError::Profile(FailedCheck::ActorKind))
        );
        let mut service = citizen_claims();
        service["registry_actor_kind"] = json!("service");
        assert_eq!(
            authenticator().authenticate(&token(service)).await,
            Err(AuthenticationError::Profile(FailedCheck::ActorKind))
        );
        let mut absent = citizen_claims();
        absent
            .as_object_mut()
            .unwrap()
            .remove("registry_actor_kind");
        assert_eq!(refused_check(absent).await, FailedCheck::ActorKind);
    }

    #[test]
    fn a_token_with_no_client_id_is_a_token_client_refusal() {
        let claims = serde_json::Map::new();
        let facts = VerifiedTokenFacts {
            issuer: Some(ISSUER),
            subject: Some("citizen-1"),
            client_id: None,
            scopes: &[],
            actor_kind: ActorKindClaim::Absent,
            claims: &claims,
        };
        assert_eq!(
            authenticator().profile_check(&facts),
            FailedCheck::TokenClient
        );
    }

    #[tokio::test]
    async fn a_client_no_profile_lists_is_not_a_missing_actor_kind() {
        // With no actor kind either, the profile lookup still fails first.
        let mut unprofiled = citizen_claims();
        unprofiled["azp"] = json!("unprofiled-client");
        unprofiled
            .as_object_mut()
            .unwrap()
            .remove("registry_actor_kind");
        assert_eq!(refused_check(unprofiled).await, FailedCheck::AccessProfile);
    }

    #[tokio::test]
    async fn identity_claims_a_profile_cannot_use_are_claims_refusals() {
        let mut malformed = citizen_claims();
        malformed["registry_actor_kind"] = json!(7);
        assert_eq!(
            authenticator().authenticate(&token(malformed)).await,
            Err(AuthenticationError::Claims(FailedCheck::ActorKind))
        );
        let mut principal = citizen_claims();
        principal["sub"] = json!("a principal\u{7}with a control");
        assert_eq!(
            authenticator().authenticate(&token(principal)).await,
            Err(AuthenticationError::Claims(FailedCheck::TokenClaims))
        );
        let mut unlisted = citizen_claims();
        unlisted["azp"] = json!("unlisted-client");
        assert_eq!(
            authenticator().authenticate(&token(unlisted)).await,
            Err(AuthenticationError::Refused(FailedCheck::TokenClient))
        );
    }

    #[tokio::test]
    async fn an_exchanged_token_is_refused_where_no_assertion_authority_is_declared() {
        let mut exchanged = citizen_claims();
        exchanged[ASSERTION_ISSUER_CLAIM] = json!("https://partner.example.test");
        assert_eq!(
            authenticator().authenticate(&token(exchanged)).await,
            Err(AuthenticationError::Profile(
                FailedCheck::TokenAssertionIssuer
            ))
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
        assert_eq!(
            AuthenticationError::Unavailable.failed_check(),
            FailedCheck::KeySourceUnavailable
        );
    }

    /// A key endpoint the verifier refuses to contact, or a static key set it
    /// cannot use, is counted under `key-source-unavailable` and answers the
    /// refusal a credential gets (401), not the 503 of a key set that could
    /// not be fetched or read. The operator pages say so.
    #[test]
    fn a_key_source_the_verifier_refuses_is_counted_unavailable_and_answers_a_refusal() {
        use registry_platform_oidc::{OidcEndpoint, StaticJwksError};
        for error in [
            OidcError::EndpointRefused {
                endpoint: OidcEndpoint::DiscoveredCrossOriginJwks,
                remedy: "declare the endpoint",
            },
            OidcError::InsecureHttpRequiresOptIn,
            OidcError::StaticKeySet(StaticJwksError::Empty),
        ] {
            assert_eq!(
                verifier_failure(&error),
                AuthenticationError::Refused(FailedCheck::KeySourceUnavailable),
                "{error:?}"
            );
        }
    }

    #[test]
    fn a_refused_credential_carries_the_check_the_verifier_names() {
        assert_eq!(
            verifier_failure(&OidcError::SignatureInvalid),
            AuthenticationError::Refused(FailedCheck::TokenSignature)
        );
        assert_eq!(
            verifier_failure(&OidcError::UnknownKid),
            AuthenticationError::Refused(FailedCheck::TokenKey)
        );
    }

    #[test]
    fn no_refusal_prints_a_value_the_caller_sent() {
        let canary = "canary-issuer.example.test";
        let error = verifier_failure(&OidcError::IssuerMismatch {
            expected: "expected".to_owned(),
            actual: canary.to_owned(),
        });
        assert!(!format!("{error} {error:?}").contains(canary));
    }
}

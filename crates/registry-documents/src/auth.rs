// SPDX-License-Identifier: Apache-2.0

//! Bearer access-token authentication for the document routes.
//!
//! There is no unauthenticated document route: every one resolves its
//! caller here first. Authentication answers, in order: is the credential a
//! verifiable access token from one of the configured issuers, for this
//! deployment's audience, from a client that issuer admits, signed by a key
//! the issuer published? Did it arrive through a token exchange this
//! deployment never declared? And which one access profile does the verified
//! client resolve to, with the scopes, actor kind, and principal claim that
//! profile demands?
//!
//! What a caller may do to a document is decided after this point against
//! the resolved profile and the document's frozen custody, never against
//! raw claims.

use std::collections::BTreeMap;
use std::sync::Arc;

use registry_documents_core::{
    AccessProfiles, AccessRefusal, ActorKind, ActorKindClaim, Caller, VerifiedTokenFacts,
};
use registry_platform_authcommon::{validate_compact_access_token, DeclaredScope, FailedCheck};
use registry_platform_oidc::{
    CallerKind, CallerRefusal, ClaimNames, DeclaredKinds, IssuerEntry, IssuerSet, IssuerSetError,
    JwksFetcher, OidcError, TokenVerifier, TokenVerifierConfig, VerifiedCaller,
    ASSERTION_ISSUER_CLAIM,
};
use thiserror::Error;

/// One configured issuer: its id, the verifier profile it is held to, the
/// source of its signing keys, and the caller kinds the operator declared for
/// it.
pub struct IssuerSource {
    id: String,
    verifier: TokenVerifierConfig,
    keys: Arc<JwksFetcher>,
    declared: DeclaredKinds,
}

impl IssuerSource {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        verifier: TokenVerifierConfig,
        keys: Arc<JwksFetcher>,
        declared: DeclaredKinds,
    ) -> Self {
        Self {
            id: id.into(),
            verifier,
            keys,
            declared,
        }
    }
}

/// What the deployment declared about one issuer entry, which a token it
/// verified is held to after verification.
struct IssuerSettings {
    /// The claim the entry reads scopes from, as configured.
    scope_claim: String,
    /// Whether the entry declared any assertion authority at all.
    binds_assertion_issuers: bool,
}

pub struct DocumentsAuthenticator {
    issuers: IssuerSet,
    profiles: AccessProfiles,
    /// The settings of each entry, by issuer id.
    settings: BTreeMap<String, IssuerSettings>,
}

impl DocumentsAuthenticator {
    /// The authenticator over `sources`, one entry per issuer. Two entries
    /// that name one issuer are refused.
    pub fn new(
        sources: Vec<IssuerSource>,
        profiles: AccessProfiles,
    ) -> Result<Self, IssuerSetError> {
        let mut settings = BTreeMap::new();
        let mut entries = Vec::new();
        for source in sources {
            settings.insert(
                source.id.clone(),
                IssuerSettings {
                    scope_claim: source.verifier.scope_claim.clone(),
                    binds_assertion_issuers: !source.verifier.assertion_issuers.is_empty(),
                },
            );
            entries.push(IssuerEntry::new(
                source.id,
                TokenVerifier::new(source.verifier, source.keys),
                source.declared,
            ));
        }
        Ok(Self {
            issuers: IssuerSet::new(entries, ClaimNames::default())?,
            profiles,
            settings,
        })
    }

    /// The issuer set's verdict on `token`, before any access profile is
    /// resolved: the entry that verified it with the caller kind settled, or
    /// the refusal with the check that failed.
    pub async fn verify(&self, token: &str) -> Result<VerifiedCaller, CallerRefusal> {
        self.issuers.verify(token).await
    }

    /// Verify one credential and resolve it to exactly one access profile.
    /// A refusal names the check it failed, for the operator's counter and
    /// log line. The answer to the caller does not carry it.
    pub async fn authenticate(&self, token: &str) -> Result<Caller, AuthenticationError> {
        self.authenticate_declaring(token)
            .await
            .map_err(|refusal| refusal.error)
    }

    /// As [`Self::authenticate`], and a refusal also carries what the
    /// deployment declared about it: for a scope refusal the scope claim
    /// name, the scope the profile requires, and the profile's id, and for a
    /// verifier refusal the sentence that names the setting involved. None of
    /// it comes from the token.
    pub async fn authenticate_declaring(&self, token: &str) -> Result<Caller, DeclaredRefusal> {
        validate_compact_access_token(token)
            .map_err(|_| AuthenticationError::Refused(FailedCheck::CredentialMalformed))?;
        let verified = self.verify(token).await.map_err(|refusal| {
            let mut declared = DeclaredRefusal::from(verifier_failure(&refusal.error));
            declared.remedy = refusal.remedy;
            declared
        })?;
        // The entry that verified a token is one the set was built from, so
        // its settings exist. A set that lost one cannot vouch for the token.
        let Some(settings) = self.settings.get(&*verified.issuer_id) else {
            tracing::error!("a verified token named an issuer entry the authenticator lost");
            return Err(AuthenticationError::Unavailable.into());
        };
        let claims = &verified.token.claims;
        // An exchanged token names the authority whose assertion produced it.
        // The platform applies no rule while the entry's map is empty, so an
        // empty map would trust every authority the issuer federates. Refuse
        // the exchange instead.
        if !settings.binds_assertion_issuers && claims.extra.contains_key(ASSERTION_ISSUER_CLAIM) {
            tracing::debug!(
                "an exchanged credential arrived at an issuer entry that declared no assertion authority"
            );
            return Err(AuthenticationError::Profile(FailedCheck::TokenAssertionIssuer).into());
        }
        let client_id = verified
            .token
            .matched_client_id()
            .map_err(|_| AuthenticationError::Claims(FailedCheck::TokenClient))?;
        let facts = VerifiedTokenFacts {
            issuer: claims.iss.as_deref(),
            subject: claims.sub.as_deref(),
            client_id,
            scopes: &verified.token.scopes,
            actor_kind: actor_kind_claim(verified.kind),
            claims: &claims.extra,
        };
        self.profiles
            .resolve(&facts)
            .map_err(|refusal| match refusal {
                AccessRefusal::Profile => {
                    let check = self.profile_check(&facts);
                    let declared = (check == FailedCheck::Scope)
                        .then(|| self.declared_scope(&facts, &settings.scope_claim))
                        .flatten();
                    DeclaredRefusal {
                        error: AuthenticationError::Profile(check),
                        declared,
                        remedy: None,
                    }
                }
                AccessRefusal::Claims => {
                    AuthenticationError::Claims(FailedCheck::TokenClaims).into()
                }
            })
    }

    /// The scope claim, the scope and the access profile a scope refusal is
    /// about, all from configuration.
    fn declared_scope(
        &self,
        facts: &VerifiedTokenFacts<'_>,
        scope_claim: &str,
    ) -> Option<DeclaredScope> {
        let missing = self.profiles.missing_scope(facts)?;
        Some(
            DeclaredScope::new(scope_claim)
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

impl std::fmt::Debug for DocumentsAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DocumentsAuthenticator")
            .field("issuers", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A refusal of authentication with the values the deployment declared about
/// it: the scope values of a scope refusal, and the sentence that names the
/// setting a verifier refusal involves. The sentence is for the operator's
/// log line and never enters a response body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredRefusal {
    pub error: AuthenticationError,
    pub declared: Option<DeclaredScope>,
    pub remedy: Option<&'static str>,
}

impl From<AuthenticationError> for DeclaredRefusal {
    fn from(error: AuthenticationError) -> Self {
        Self {
            error,
            declared: None,
            remedy: None,
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

/// The kind the verifier settled, as the access profiles read it. The
/// Document Store admits services and people, so an agent is a well-formed
/// kind no profile admits. A caller that neither the operator nor the token
/// gave a kind is unspecified, which every profile refuses because every
/// profile names a kind.
fn actor_kind_claim(kind: CallerKind) -> ActorKindClaim {
    use registry_platform_oidc::ActorKind as Verified;
    match kind.kind() {
        Some(Verified::Human) => ActorKindClaim::Present(ActorKind::Human),
        Some(Verified::Service) => ActorKindClaim::Present(ActorKind::Service),
        Some(Verified::Agent) => ActorKindClaim::Unadmitted,
        None => ActorKindClaim::Absent,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use registry_documents_core::DocumentsProject;
    use registry_platform_config::AccessTokenType;
    use registry_platform_oidc::{access_token_types, JwksFetcherConfig};
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

    pub(crate) const PARTNER_ISSUER: &str = "https://partner.example.test/realms/partner";
    pub(crate) const PARTNER_AUDIENCE: &str = "urn:example:documents-partner";
    const PARTNER_SECRET: &[u8] = b"abcdefghijabcdefghijabcdefghijab";

    fn keys_for(secret: &[u8]) -> Arc<JwksFetcher> {
        Arc::new(JwksFetcher::new_static(
            serde_json::from_value(json!({"keys": [{
                "kty": "oct",
                "kid": "test",
                "alg": "HS256",
                "use": "sig",
                "k": URL_SAFE_NO_PAD.encode(secret),
            }]}))
            .unwrap(),
            JwksFetcherConfig::defaults(),
        ))
    }

    /// The verifier profile the runtime builds, with the symmetric test
    /// algorithm in place of the production asymmetric pair.
    fn verifier() -> TokenVerifierConfig {
        verifier_typed(AccessTokenType::AtJwt)
    }

    /// The verifier profile of the `main` entry, with the token type its
    /// `accessTokenType` selects.
    fn verifier_typed(access_token_type: AccessTokenType) -> TokenVerifierConfig {
        TokenVerifierConfig::access_token_profile(
            ISSUER,
            vec![AUDIENCE.to_owned()],
            vec![Algorithm::HS256],
            access_token_types(access_token_type),
        )
        .with_scope_claim("scope")
        .with_allowed_clients(vec![
            "civil-registry-app".to_owned(),
            "citizen-portal".to_owned(),
            "case-portal".to_owned(),
            "unprofiled-client".to_owned(),
        ])
    }

    /// The verifier profile of the partner issuer: its own audience, scope
    /// claim and client.
    fn partner_verifier() -> TokenVerifierConfig {
        TokenVerifierConfig::access_token_profile(
            PARTNER_ISSUER,
            vec![PARTNER_AUDIENCE.to_owned()],
            vec![Algorithm::HS256],
            access_token_types(AccessTokenType::AtJwt),
        )
        .with_scope_claim("scp")
        .with_allowed_clients(vec!["partner-portal".to_owned()])
    }

    fn main_source(verifier: TokenVerifierConfig, declared: DeclaredKinds) -> IssuerSource {
        IssuerSource::new("main", verifier, keys(), declared)
    }

    fn partner_source() -> IssuerSource {
        IssuerSource::new(
            "partner",
            partner_verifier(),
            keys_for(PARTNER_SECRET),
            DeclaredKinds::None,
        )
    }

    pub(crate) fn authenticator() -> DocumentsAuthenticator {
        authenticator_with(verifier(), DeclaredKinds::None)
    }

    /// One issuer entry over `verifier` and the shared test keys.
    fn authenticator_with(
        verifier: TokenVerifierConfig,
        declared: DeclaredKinds,
    ) -> DocumentsAuthenticator {
        DocumentsAuthenticator::new(
            vec![main_source(verifier, declared)],
            AccessProfiles::new(&project()),
        )
        .unwrap()
    }

    /// Two issuers: `main` and `partner`, each with its own keys, audience,
    /// scope claim and client.
    fn two_issuers() -> DocumentsAuthenticator {
        DocumentsAuthenticator::new(
            vec![
                main_source(verifier(), DeclaredKinds::None),
                partner_source(),
            ],
            AccessProfiles::new(&project()),
        )
        .unwrap()
    }

    fn partner_claims() -> serde_json::Value {
        json!({
            "iss": PARTNER_ISSUER,
            "aud": PARTNER_AUDIENCE,
            "sub": "partner-reader",
            "azp": "partner-portal",
            "scp": "documents:read",
            "registry_actor_kind": "human",
        })
    }

    /// Sign `claims` as `typ` with `secret`, filling in the times.
    fn signed_as(claims: serde_json::Value, typ: &str, secret: &[u8]) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut claims = claims;
        let object = claims.as_object_mut().unwrap();
        object.entry("iss").or_insert(json!(ISSUER));
        object.entry("aud").or_insert(json!(AUDIENCE));
        object.entry("iat").or_insert(json!(now));
        object.entry("exp").or_insert(json!(now + 300));
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test".to_owned());
        header.typ = Some(typ.to_owned());
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(secret)).unwrap()
    }

    fn partner_token(claims: serde_json::Value) -> String {
        signed_as(claims, "at+jwt", PARTNER_SECRET)
    }

    /// A token typed as an ordinary JWT, as a provider that does not type its
    /// access tokens issues.
    pub(crate) fn jwt_typed(claims: serde_json::Value) -> String {
        signed_as(claims, "JWT", SECRET)
    }

    fn without(mut claims: serde_json::Value, key: &str) -> serde_json::Value {
        claims.as_object_mut().unwrap().remove(key);
        claims
    }

    fn with(
        mut claims: serde_json::Value,
        key: &str,
        value: serde_json::Value,
    ) -> serde_json::Value {
        claims[key] = value;
        claims
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
    async fn identity_claims_a_profile_cannot_use_are_refused() {
        let mut malformed = citizen_claims();
        malformed["registry_actor_kind"] = json!(7);
        assert_eq!(
            authenticator().authenticate(&token(malformed)).await,
            Err(AuthenticationError::Refused(FailedCheck::ActorKind))
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

    // The access token type (P2)

    #[tokio::test]
    async fn a_jwt_typed_token_is_refused_by_default_and_the_log_names_the_setting() {
        let refused = authenticator()
            .authenticate_declaring(&jwt_typed(citizen_claims()))
            .await
            .expect_err("a JWT-typed token is not an access token by default");
        assert_eq!(
            refused.error,
            AuthenticationError::Refused(FailedCheck::TokenType)
        );
        assert!(
            refused
                .remedy
                .is_some_and(|remedy| remedy.contains("accessTokenType")),
            "{:?}",
            refused.remedy
        );
    }

    #[tokio::test]
    async fn a_jwt_typed_token_is_admitted_when_the_issuer_states_it() {
        let stating = authenticator_with(verifier_typed(AccessTokenType::Jwt), DeclaredKinds::None);
        let caller = stating
            .authenticate(&jwt_typed(citizen_claims()))
            .await
            .expect("an entry that states accessTokenType: JWT admits a JWT-typed token");
        assert_eq!(caller.profile_id.as_str(), "citizen");
        assert_eq!(
            stating
                .authenticate(&token(citizen_claims()))
                .await
                .expect_err("JWT admits that type alone"),
            AuthenticationError::Refused(FailedCheck::TokenType)
        );
    }

    #[tokio::test]
    async fn an_id_token_is_refused_whether_or_not_jwt_is_admitted() {
        let mut id_claims = citizen_claims();
        id_claims["nonce"] = json!("n-0S6_WzA2Mj");
        id_claims["at_hash"] = json!("77QmUPtjPfzWtF2AnpK9RQ");
        let id_token = jwt_typed(id_claims);
        assert_eq!(
            authenticator().authenticate(&id_token).await,
            Err(AuthenticationError::Refused(FailedCheck::TokenType))
        );
        let stating = authenticator_with(verifier_typed(AccessTokenType::Jwt), DeclaredKinds::None);
        let refused = stating
            .authenticate_declaring(&id_token)
            .await
            .expect_err("an ID token is not an access token under JWT either");
        assert_eq!(
            refused.error,
            AuthenticationError::Refused(FailedCheck::TokenType)
        );
        assert!(
            refused.remedy.is_some(),
            "the log line names what to change"
        );
    }

    // The caller kind (P3)

    #[tokio::test]
    async fn a_token_without_a_kind_authenticates_as_unspecified() {
        let authenticator = authenticator();
        let verified = authenticator
            .verify(&token(without(citizen_claims(), "registry_actor_kind")))
            .await
            .expect("a token that names no kind authenticates");
        assert_eq!(verified.kind.kind(), None);
    }

    #[tokio::test]
    async fn a_human_only_profile_refuses_an_unspecified_kind() {
        assert_eq!(
            authenticator()
                .authenticate(&token(without(citizen_claims(), "registry_actor_kind")))
                .await,
            Err(AuthenticationError::Profile(FailedCheck::ActorKind))
        );
    }

    #[tokio::test]
    async fn a_declared_client_kind_admits_a_token_without_a_kind() {
        let declared = DeclaredKinds::Clients(
            [(
                "citizen-portal".to_owned(),
                registry_platform_oidc::ActorKind::Human,
            )]
            .into(),
        );
        let caller = authenticator_with(verifier(), declared)
            .authenticate(&token(without(citizen_claims(), "registry_actor_kind")))
            .await
            .expect("the declared kind stands for the missing claim");
        assert_eq!(caller.profile_id.as_str(), "citizen");
        assert_eq!(caller.kind, ActorKind::Human);
    }

    #[tokio::test]
    async fn a_token_kind_that_contradicts_the_declared_kind_is_refused() {
        let declared = DeclaredKinds::Issuer(registry_platform_oidc::ActorKind::Service);
        assert_eq!(
            authenticator_with(verifier(), declared)
                .authenticate(&token(citizen_claims()))
                .await,
            Err(AuthenticationError::Refused(FailedCheck::ActorKind))
        );
    }

    #[tokio::test]
    async fn an_unlisted_client_is_refused() {
        let stranger = token(with(citizen_claims(), "azp", json!("unrelated-app")));
        assert_eq!(
            authenticator().authenticate(&stranger).await,
            Err(AuthenticationError::Refused(FailedCheck::TokenClient))
        );
    }

    #[tokio::test]
    async fn an_identity_only_token_is_refused_without_a_declared_kind() {
        let identity_only = token(json!({
            "sub": "citizen-1",
            "azp": "citizen-portal",
            "scope": "openid profile email",
        }));
        assert_eq!(
            authenticator().authenticate(&identity_only).await,
            Err(AuthenticationError::Refused(FailedCheck::ActorKind))
        );
        let declared = DeclaredKinds::Clients(
            [(
                "citizen-portal".to_owned(),
                registry_platform_oidc::ActorKind::Human,
            )]
            .into(),
        );
        assert_eq!(
            authenticator_with(verifier(), declared)
                .authenticate(&identity_only)
                .await,
            Err(AuthenticationError::Profile(FailedCheck::Scope))
        );
    }

    // Several issuers (P5)

    #[tokio::test]
    async fn a_token_from_each_configured_issuer_is_verified_under_its_own_rules() {
        let auth = two_issuers();
        let main = auth
            .authenticate(&token(citizen_claims()))
            .await
            .expect("the main issuer's token authenticates");
        assert_eq!(main.profile_id.as_str(), "citizen");
        assert_eq!(main.issuer, ISSUER);
        let partner = auth
            .authenticate(&partner_token(partner_claims()))
            .await
            .expect("the partner issuer's token authenticates under its own scope claim");
        assert_eq!(partner.profile_id.as_str(), "reader");
        assert_eq!(partner.issuer, PARTNER_ISSUER);
        // The partner entry reads `scp`, not the main entry's claim.
        let wrong_claim = partner_token(with(
            with(partner_claims(), "scp", json!("documents:other")),
            "scope",
            json!("documents:read"),
        ));
        assert_eq!(
            auth.authenticate(&wrong_claim).await,
            Err(AuthenticationError::Profile(FailedCheck::Scope))
        );
        // The main entry's audience is not the partner's.
        let main_audience = partner_token(with(partner_claims(), "aud", json!(AUDIENCE)));
        assert_eq!(
            auth.authenticate(&main_audience).await,
            Err(AuthenticationError::Refused(FailedCheck::TokenAudience))
        );
    }

    #[tokio::test]
    async fn a_token_naming_one_issuer_signed_by_the_other_is_refused() {
        let auth = two_issuers();
        assert_eq!(
            auth.authenticate(&signed_as(partner_claims(), "at+jwt", SECRET))
                .await,
            Err(AuthenticationError::Refused(FailedCheck::TokenSignature))
        );
        assert_eq!(
            auth.authenticate(&signed_as(citizen_claims(), "at+jwt", PARTNER_SECRET))
                .await,
            Err(AuthenticationError::Refused(FailedCheck::TokenSignature))
        );
    }

    #[tokio::test]
    async fn a_token_from_an_unconfigured_issuer_is_refused() {
        let stranger = token(with(
            citizen_claims(),
            "iss",
            json!("https://elsewhere.test"),
        ));
        assert_eq!(
            two_issuers().authenticate(&stranger).await,
            Err(AuthenticationError::Refused(FailedCheck::TokenIssuer))
        );
    }

    #[test]
    fn an_authenticator_refuses_two_entries_that_name_one_issuer() {
        let error = DocumentsAuthenticator::new(
            vec![
                main_source(verifier(), DeclaredKinds::None),
                IssuerSource::new("second", verifier(), keys(), DeclaredKinds::None),
            ],
            AccessProfiles::new(&project()),
        )
        .expect_err("one issuer cannot be two entries");
        assert!(
            matches!(
                error,
                registry_platform_oidc::IssuerSetError::DuplicateIss { .. }
            ),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_client_listed_by_one_issuer_is_refused_in_a_token_from_another() {
        let auth = two_issuers();
        let partner_naming_main_client =
            partner_token(with(partner_claims(), "azp", json!("citizen-portal")));
        assert_eq!(
            auth.authenticate(&partner_naming_main_client).await,
            Err(AuthenticationError::Refused(FailedCheck::TokenClient))
        );
        let main_naming_partner_client =
            token(with(citizen_claims(), "azp", json!("partner-portal")));
        assert_eq!(
            auth.authenticate(&main_naming_partner_client).await,
            Err(AuthenticationError::Refused(FailedCheck::TokenClient))
        );
    }

    #[tokio::test]
    async fn an_exchanged_token_is_judged_by_its_own_entrys_assertion_authority() {
        let authority = "https://authority.example.test";
        let auth = DocumentsAuthenticator::new(
            vec![
                main_source(
                    verifier().with_assertion_issuers(BTreeMap::from([(
                        "citizen-portal".to_owned(),
                        vec![authority.to_owned()],
                    )])),
                    DeclaredKinds::None,
                ),
                partner_source(),
            ],
            AccessProfiles::new(&project()),
        )
        .unwrap();
        let mut declared = citizen_claims();
        declared[ASSERTION_ISSUER_CLAIM] = json!(authority);
        assert_eq!(
            auth.authenticate(&token(declared))
                .await
                .expect("the entry that declared the authority admits the exchange")
                .profile_id
                .as_str(),
            "citizen"
        );
        // The partner entry declared no authority, so its exchanged tokens are
        // refused whatever the other entry declared.
        let mut exchanged = partner_claims();
        exchanged[ASSERTION_ISSUER_CLAIM] = json!(authority);
        assert_eq!(
            auth.authenticate(&partner_token(exchanged)).await,
            Err(AuthenticationError::Profile(
                FailedCheck::TokenAssertionIssuer
            ))
        );
    }

    #[tokio::test]
    async fn a_scope_refusal_declares_the_scope_claim_of_the_entry_that_verified_the_token() {
        let auth = two_issuers();
        let main = auth
            .authenticate_declaring(&token(with(
                citizen_claims(),
                "scope",
                json!("documents:x"),
            )))
            .await
            .unwrap_err();
        assert_eq!(main.declared.expect("declared").scope_claim(), "scope");
        let partner = auth
            .authenticate_declaring(&partner_token(with(
                partner_claims(),
                "scp",
                json!("documents:x"),
            )))
            .await
            .unwrap_err();
        assert_eq!(partner.declared.expect("declared").scope_claim(), "scp");
    }
}

// SPDX-License-Identifier: Apache-2.0

//! Bearer access-token authentication for the Messaging HTTP surface.
//!
//! There is no unauthenticated mode: every `/v1` route resolves its caller
//! here first. Authentication answers, in order: is the credential a
//! verifiable access token from one of the configured issuers, for this
//! deployment's audience, from a client that issuer admits, signed by a key
//! the issuer published? Did it arrive through a token exchange this
//! deployment never declared? And which one access profile does the verified
//! client resolve to, with the scopes, actor kind, and principal claim that
//! profile demands?
//!
//! What a caller may send, and which messages it may see, is decided after
//! this point against the resolved profile, never against raw claims.

use std::collections::BTreeMap;
use std::sync::Arc;

use registry_messaging_core::{
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
/// source of its signing keys, and the caller kinds the operator declared
/// for it.
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

pub struct MessagingAuthenticator {
    issuers: IssuerSet,
    profiles: AccessProfiles,
    /// The settings of each entry, by issuer id.
    settings: BTreeMap<String, IssuerSettings>,
}

impl MessagingAuthenticator {
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
        let settings = self
            .settings
            .get(&*verified.issuer_id)
            .ok_or(AuthenticationError::Refused(FailedCheck::TokenIssuer))?;
        let claims = &verified.token.claims;
        // An exchanged token names the authority whose assertion produced it.
        // The platform applies no rule while the entry's map is empty, so an
        // empty map would trust every authority the issuer federates. Refuse
        // the exchange instead: a deployment that means to accept one says
        // which authorities, and which client may present them.
        if !settings.binds_assertion_issuers && claims.extra.contains_key(ASSERTION_ISSUER_CLAIM) {
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
            .map_err(|refusal| self.access_refusal(refusal, &facts, &settings.scope_claim))
    }

    /// The error a refused profile resolution answers with, and the check it
    /// names. A scope refusal also carries the values configuration declared
    /// for it.
    fn access_refusal(
        &self,
        refusal: AccessRefusal,
        facts: &VerifiedTokenFacts<'_>,
        scope_claim: &str,
    ) -> DeclaredRefusal {
        match refusal {
            AccessRefusal::Profile => {
                if let Some(missing) = self.profiles.missing_scope(facts) {
                    return DeclaredRefusal {
                        error: AuthenticationError::Profile(FailedCheck::Scope),
                        declared: Some(
                            DeclaredScope::new(scope_claim)
                                .with_required_scope(missing.scope)
                                .with_access_profile(missing.profile),
                        ),
                        remedy: None,
                    };
                }
                let check = if self.profiles.iter().any(|profile| {
                    facts.client_id.is_some_and(|client| {
                        profile
                            .requester_clients
                            .iter()
                            .any(|named| named == client)
                    })
                }) {
                    FailedCheck::ActorKind
                } else {
                    FailedCheck::AccessProfile
                };
                AuthenticationError::Profile(check).into()
            }
            AccessRefusal::Claims => AuthenticationError::Claims(FailedCheck::TokenClaims).into(),
        }
    }
}

impl std::fmt::Debug for MessagingAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MessagingAuthenticator")
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

/// Separate a verifier outage from a bad credential.
///
/// A 401 tells a caller its credential is the problem, so it is reserved for
/// credentials. When the issuer's discovery document or key set cannot be
/// fetched, read, parsed, or used, nothing has been learned about the
/// credential; a deployment whose own OIDC settings contradict each other is
/// the same kind of failure.
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
        // signal, and answering 503 there would let a caller probe the key
        // set. A variant the platform adds later reads as a refusal until it
        // is classified here, so a new outcome can never widen the door.
        _ => AuthenticationError::Refused(error.failed_check()),
    }
}

/// The kind the verifier settled, as the access profiles read it. An
/// unspecified caller is one that neither the operator nor the token gave a
/// kind, which only a profile that pins a kind refuses.
fn actor_kind_claim(kind: CallerKind) -> ActorKindClaim {
    use registry_platform_oidc::ActorKind as Verified;
    match kind.kind() {
        Some(Verified::Human) => ActorKindClaim::Present(ActorKind::Human),
        Some(Verified::Agent) => ActorKindClaim::Present(ActorKind::Agent),
        Some(Verified::Service) => ActorKindClaim::Present(ActorKind::Service),
        None => ActorKindClaim::Absent,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use chrono::Utc;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use registry_messaging_core::{AccessProfile, ActsAs};
    use registry_platform_config::AccessTokenType;
    use registry_platform_httputil::FetchUrlPolicy;
    use registry_platform_oidc::{
        access_token_types, AccessTokenAlgorithm, DeclaredKinds, IssuerSetError, JwksFetcherConfig,
    };
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    pub(crate) const ISSUER: &str = "https://task-token.test";
    pub(crate) const AUDIENCE: &str = "urn:registry-messaging:test";
    pub(crate) const SENDER_CLIENT: &str = "case-system";
    pub(crate) const OPERATOR_CLIENT: &str = "operations-console";
    /// Admitted by the verifier, but no access profile names it.
    pub(crate) const UNPROFILED_CLIENT: &str = "reporting-job";
    const SECRET: &[u8] = b"01234567890123456789012345678901";
    pub(crate) const PARTNER_ISSUER: &str = "https://partner-token.test";
    pub(crate) const PARTNER_CLIENT: &str = "partner-system";
    const PARTNER_AUDIENCE: &str = "urn:registry-messaging:partner";
    const PARTNER_SECRET: &[u8] = b"abcdefghijklmnopqrstuvwxyz012345";

    pub(crate) fn profiles() -> AccessProfiles {
        AccessProfiles::new(vec![
            AccessProfile {
                id: "case-notices".to_owned(),
                label: None,
                description: None,
                principal_claim: "sub".to_owned(),
                required_scopes: vec!["messaging:send".to_owned()],
                requester_clients: vec![SENDER_CLIENT.to_owned()],
                actor_kind: Some(ActorKind::Service),
                acts_as: ActsAs::Sender,
                sender_profiles: vec!["transactional".to_owned()],
                templates: vec!["appointment-reminder".to_owned()],
                allow_direct_content: false,
                requests_per_minute: 60,
                burst: 10,
                maximum_messages_per_day: None,
            },
            AccessProfile {
                id: "operations".to_owned(),
                label: None,
                description: None,
                principal_claim: "sub".to_owned(),
                required_scopes: vec!["messaging:operate".to_owned()],
                requester_clients: vec![OPERATOR_CLIENT.to_owned()],
                actor_kind: None,
                acts_as: ActsAs::Operator,
                sender_profiles: Vec::new(),
                templates: Vec::new(),
                allow_direct_content: false,
                requests_per_minute: 60,
                burst: 10,
                maximum_messages_per_day: None,
            },
            AccessProfile {
                id: "partner-notices".to_owned(),
                label: None,
                description: None,
                principal_claim: "sub".to_owned(),
                required_scopes: vec!["messaging:send".to_owned()],
                requester_clients: vec![PARTNER_CLIENT.to_owned()],
                actor_kind: None,
                acts_as: ActsAs::Sender,
                sender_profiles: vec!["transactional".to_owned()],
                templates: vec!["appointment-reminder".to_owned()],
                allow_direct_content: false,
                requests_per_minute: 60,
                burst: 10,
                maximum_messages_per_day: None,
            },
        ])
        .unwrap()
    }

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

    pub(crate) fn keys() -> Arc<JwksFetcher> {
        keys_for(SECRET)
    }

    /// The verifier profile the runtime builds, with the symmetric test
    /// algorithm in place of the production asymmetric pair.
    fn verifier(assertion_issuers: &[(&str, &str)]) -> TokenVerifierConfig {
        TokenVerifierConfig::access_token_profile(
            ISSUER,
            vec![AUDIENCE.to_owned()],
            vec![Algorithm::HS256],
            registry_platform_oidc::access_token_typ_set("at+jwt"),
        )
        .with_scope_claim("registry_scopes")
        .with_allowed_clients(vec![
            SENDER_CLIENT.to_owned(),
            OPERATOR_CLIENT.to_owned(),
            UNPROFILED_CLIENT.to_owned(),
        ])
        .with_assertion_issuers(
            assertion_issuers
                .iter()
                .map(|(client, issuer)| ((*client).to_owned(), vec![(*issuer).to_owned()]))
                .collect(),
        )
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
        .with_allowed_clients(vec![PARTNER_CLIENT.to_owned()])
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

    pub(crate) fn authenticator_over(keys: Arc<JwksFetcher>) -> MessagingAuthenticator {
        MessagingAuthenticator::new(
            vec![IssuerSource::new(
                "main",
                verifier(&[]),
                keys,
                DeclaredKinds::None,
            )],
            profiles(),
        )
        .unwrap()
    }

    /// One issuer entry over `verifier` and the shared test keys.
    fn authenticator_with(
        verifier: TokenVerifierConfig,
        declared: DeclaredKinds,
    ) -> MessagingAuthenticator {
        MessagingAuthenticator::new(vec![main_source(verifier, declared)], profiles()).unwrap()
    }

    /// Two issuers: `main` and `partner`, each with its own keys, audience,
    /// scope claim and client.
    fn two_issuers() -> MessagingAuthenticator {
        MessagingAuthenticator::new(
            vec![
                main_source(verifier(&[]), DeclaredKinds::None),
                partner_source(),
            ],
            profiles(),
        )
        .unwrap()
    }

    fn partner_claims() -> serde_json::Value {
        json!({
            "iss": PARTNER_ISSUER,
            "aud": PARTNER_AUDIENCE,
            "sub": "partner-principal",
            "azp": PARTNER_CLIENT,
            "scp": "messaging:send",
        })
    }

    /// Sign `claims` as `typ` with `secret`, filling in the times.
    fn signed_as(claims: serde_json::Value, typ: &str, secret: &[u8]) -> String {
        let now = Utc::now().timestamp();
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

    /// The verifier profile of the `main` entry, with the token type its
    /// `accessTokenType` selects.
    fn verifier_typed(access_token_type: AccessTokenType) -> TokenVerifierConfig {
        TokenVerifierConfig::access_token_profile(
            ISSUER,
            vec![AUDIENCE.to_owned()],
            vec![Algorithm::HS256],
            access_token_types(access_token_type),
        )
        .with_scope_claim("registry_scopes")
        .with_allowed_clients(vec![
            SENDER_CLIENT.to_owned(),
            OPERATOR_CLIENT.to_owned(),
            UNPROFILED_CLIENT.to_owned(),
        ])
    }

    pub(crate) fn authenticator() -> MessagingAuthenticator {
        authenticator_over(keys())
    }

    /// Sign an access token, filling in the claims a real token always
    /// carries so a test only states what it varies.
    pub(crate) fn token_signed_with(mut claims: serde_json::Value, secret: &[u8]) -> String {
        let now = Utc::now().timestamp();
        let object = claims.as_object_mut().unwrap();
        object.entry("iss").or_insert(json!(ISSUER));
        object.entry("aud").or_insert(json!(AUDIENCE));
        object.entry("iat").or_insert(json!(now));
        object.entry("exp").or_insert(json!(now + 300));
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test".to_owned());
        header.typ = Some("at+jwt".to_owned());
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(secret)).unwrap()
    }

    pub(crate) fn token(claims: serde_json::Value) -> String {
        token_signed_with(claims, SECRET)
    }

    pub(crate) fn sender_claims() -> serde_json::Value {
        json!({
            "sub": "case-system-principal",
            "azp": SENDER_CLIENT,
            "registry_scopes": "messaging:send",
            "registry_actor_kind": "service",
        })
    }

    pub(crate) fn operator_claims() -> serde_json::Value {
        json!({
            "sub": "operator-1",
            "azp": OPERATOR_CLIENT,
            "registry_scopes": "messaging:operate",
            "registry_actor_kind": "human",
        })
    }

    fn with(
        mut claims: serde_json::Value,
        key: &str,
        value: serde_json::Value,
    ) -> serde_json::Value {
        claims[key] = value;
        claims
    }

    async fn refusal(token: &str) -> AuthenticationError {
        authenticator()
            .authenticate(token)
            .await
            .expect_err("the credential was accepted")
    }

    #[tokio::test]
    async fn a_sender_resolves_to_its_one_profile_and_principal() {
        let caller = authenticator()
            .authenticate(&token(sender_claims()))
            .await
            .expect("a sender holding its profile's scope authenticates");
        assert_eq!(caller.profile.id, "case-notices");
        assert_eq!(caller.role(), ActsAs::Sender);
        assert_eq!(caller.identity.issuer, ISSUER);
        assert_eq!(caller.identity.subject, "case-system-principal");
        assert_eq!(caller.actor_kind, Some(ActorKind::Service));

        let operator = authenticator()
            .authenticate(&token(operator_claims()))
            .await
            .expect("an operator authenticates");
        assert_eq!(operator.role(), ActsAs::Operator);
    }

    #[tokio::test]
    async fn a_credential_that_is_not_a_compact_token_is_refused() {
        for credential in ["", "not-a-jwt", "a.b", "a b.c.d"] {
            assert_eq!(
                refusal(credential).await,
                AuthenticationError::Refused(FailedCheck::CredentialMalformed)
            );
        }
    }

    #[tokio::test]
    async fn a_forged_signature_is_refused() {
        let forged = token_signed_with(sender_claims(), b"another-secret-another-secret-another!");
        assert_eq!(
            refusal(&forged).await,
            AuthenticationError::Refused(FailedCheck::TokenSignature)
        );
    }

    #[tokio::test]
    async fn a_token_for_another_audience_or_issuer_is_refused() {
        let other_audience = token(with(sender_claims(), "aud", json!("urn:elsewhere")));
        assert_eq!(
            refusal(&other_audience).await,
            AuthenticationError::Refused(FailedCheck::TokenAudience)
        );
        let other_issuer = token(with(
            sender_claims(),
            "iss",
            json!("https://elsewhere.test"),
        ));
        assert_eq!(
            refusal(&other_issuer).await,
            AuthenticationError::Refused(FailedCheck::TokenIssuer)
        );
    }

    #[tokio::test]
    async fn an_expired_token_is_refused() {
        let now = Utc::now().timestamp();
        let expired = token(with(
            with(sender_claims(), "exp", json!(now - 600)),
            "iat",
            json!(now - 900),
        ));
        assert_eq!(
            refusal(&expired).await,
            AuthenticationError::Refused(FailedCheck::TokenTime)
        );
    }

    #[tokio::test]
    async fn a_token_that_is_not_an_access_token_is_refused() {
        let now = Utc::now().timestamp();
        let mut claims = sender_claims();
        claims["iss"] = json!(ISSUER);
        claims["aud"] = json!(AUDIENCE);
        claims["iat"] = json!(now);
        claims["exp"] = json!(now + 300);
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test".to_owned());
        header.typ = Some("JWT".to_owned());
        let id_token =
            jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(SECRET)).unwrap();
        assert_eq!(
            refusal(&id_token).await,
            AuthenticationError::Refused(FailedCheck::TokenType)
        );
    }

    #[tokio::test]
    async fn a_client_the_deployment_does_not_admit_is_refused() {
        let stranger = token(with(sender_claims(), "azp", json!("unrelated-app")));
        assert_eq!(
            refusal(&stranger).await,
            AuthenticationError::Refused(FailedCheck::TokenClient)
        );
    }

    #[tokio::test]
    async fn an_admitted_client_without_a_profile_is_not_authorized() {
        let unprofiled = token(with(sender_claims(), "azp", json!(UNPROFILED_CLIENT)));
        assert_eq!(
            refusal(&unprofiled).await,
            AuthenticationError::Profile(FailedCheck::AccessProfile)
        );
    }

    #[tokio::test]
    async fn a_missing_scope_is_not_authorized() {
        let no_scope = token(with(
            sender_claims(),
            "registry_scopes",
            json!("messaging:read"),
        ));
        assert_eq!(
            refusal(&no_scope).await,
            AuthenticationError::Profile(FailedCheck::Scope)
        );
        // A token that grants no scope at all is identity only, and no kind
        // was declared for its client, so it never reaches the profile.
        let mut absent = sender_claims();
        absent.as_object_mut().unwrap().remove("registry_scopes");
        assert_eq!(
            refusal(&token(absent)).await,
            AuthenticationError::Refused(FailedCheck::ActorKind)
        );
    }

    #[tokio::test]
    async fn an_actor_kind_the_profile_does_not_admit_is_not_authorized() {
        let human = token(with(sender_claims(), "registry_actor_kind", json!("human")));
        assert_eq!(
            refusal(&human).await,
            AuthenticationError::Profile(FailedCheck::ActorKind)
        );
        let mut absent = sender_claims();
        absent
            .as_object_mut()
            .unwrap()
            .remove("registry_actor_kind");
        assert_eq!(
            refusal(&token(absent)).await,
            AuthenticationError::Profile(FailedCheck::ActorKind)
        );
    }

    #[tokio::test]
    async fn a_malformed_actor_kind_is_refused_at_authentication() {
        let malformed = token(with(sender_claims(), "registry_actor_kind", json!("robot")));
        assert_eq!(
            refusal(&malformed).await,
            AuthenticationError::Refused(FailedCheck::ActorKind)
        );
        let operator = token(with(operator_claims(), "registry_actor_kind", json!(7)));
        assert_eq!(
            refusal(&operator).await,
            AuthenticationError::Refused(FailedCheck::ActorKind)
        );
    }

    #[tokio::test]
    async fn a_token_without_a_principal_is_a_claims_refusal() {
        let mut claims = sender_claims();
        claims.as_object_mut().unwrap().remove("sub");
        assert_eq!(
            refusal(&token(claims)).await,
            AuthenticationError::Claims(FailedCheck::TokenClaims)
        );
    }

    #[tokio::test]
    async fn an_exchanged_token_is_refused_when_no_authority_was_declared() {
        let exchanged = token(with(
            sender_claims(),
            registry_platform_oidc::ASSERTION_ISSUER_CLAIM,
            json!("https://assertions.example.test"),
        ));
        assert_eq!(
            refusal(&exchanged).await,
            AuthenticationError::Profile(FailedCheck::TokenAssertionIssuer)
        );

        let declaring = authenticator_with(
            verifier(&[(SENDER_CLIENT, "https://assertions.example.test")]),
            DeclaredKinds::None,
        );
        declaring
            .authenticate(&exchanged)
            .await
            .expect("a declared exchange authority is accepted");
    }

    #[tokio::test]
    async fn a_key_endpoint_outage_is_unavailable_not_a_refusal() {
        let issuer_keys = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&issuer_keys)
            .await;
        let during_outage = authenticator_over(Arc::new(JwksFetcher::new_with_fetch_url_policy(
            format!("{}/jwks.json", issuer_keys.uri()),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::https_or_loopback(),
        )));
        assert_eq!(
            during_outage
                .authenticate(&token(sender_claims()))
                .await
                .expect_err("no key set, no verdict"),
            AuthenticationError::Unavailable,
            "a key endpoint that cannot answer was reported as a bad credential"
        );
    }

    #[test]
    fn only_a_verifier_that_reached_no_verdict_is_unavailable() {
        for outage in [
            OidcError::HttpStatus(503),
            OidcError::InvalidUrl,
            OidcError::Parse,
            OidcError::InvalidJwk,
            OidcError::EmptyKeySet,
            OidcError::MissingIssuer,
            OidcError::ConflictingEndpointConfiguration,
        ] {
            assert_eq!(
                verifier_failure(&outage),
                AuthenticationError::Unavailable,
                "{outage} was blamed on the credential"
            );
        }
        for refusal in [
            OidcError::IssuerMismatch {
                expected: ISSUER.to_owned(),
                actual: "https://elsewhere.test".to_owned(),
            },
            OidcError::MalformedToken,
            OidcError::AlgorithmNotAllowed,
            OidcError::TokenTypeNotAllowed,
            OidcError::MissingKid,
            OidcError::KidTooLong,
            OidcError::UnknownKid,
            OidcError::TokenExpired,
            OidcError::TokenNotYetValid,
            OidcError::AudienceMismatch,
            OidcError::SignatureInvalid,
            OidcError::InvalidToken,
            OidcError::InvalidTimeClaims,
            OidcError::ClientNotAllowed,
            OidcError::AssertionIssuerNotAllowed,
        ] {
            assert_eq!(
                verifier_failure(&refusal),
                AuthenticationError::Refused(refusal.failed_check()),
                "{refusal} was excused as an outage"
            );
        }
    }
    #[tokio::test]
    async fn separate_resource_rs256_and_es256_profiles_refuse_cross_resource_reuse() {
        for algorithm in [AccessTokenAlgorithm::RS256, AccessTokenAlgorithm::ES256]
            .map(AccessTokenAlgorithm::to_jsonwebtoken)
        {
            let key = registry_platform_testing::access_token_test_key(algorithm);
            let jwks = serde_json::from_value(json!({"keys":[key.public()]})).unwrap();
            let source = Arc::new(JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults()));
            let verifier = TokenVerifierConfig::access_token_profile(
                ISSUER,
                vec![AUDIENCE.to_owned()],
                vec![algorithm],
                vec!["at+jwt".to_owned()],
            )
            .with_scope_claim("registry_scopes")
            .with_allowed_clients(vec![SENDER_CLIENT.to_owned()]);
            let auth = MessagingAuthenticator::new(
                vec![IssuerSource::new(
                    "main",
                    verifier,
                    source,
                    DeclaredKinds::None,
                )],
                profiles(),
            )
            .unwrap();
            let now = Utc::now().timestamp();
            let claims = {
                let mut c = sender_claims();
                c["iss"] = json!(ISSUER);
                c["aud"] = json!(AUDIENCE);
                c["iat"] = json!(now);
                c["exp"] = json!(now + 300);
                c
            };
            let sign = |claims: serde_json::Value, typ: &str| {
                registry_platform_testing::sign_compact_jwt_with_key(
                    &key,
                    typ,
                    "canary-resource-key",
                    claims,
                )
            };
            registry_platform_testing::assert_resource_audience_and_token_type_rules(
                &key,
                claims.clone(),
                |token: String| {
                    let auth = &auth;
                    async move { auth.authenticate(&token).await }
                },
                |error| matches!(error, AuthenticationError::Refused(_)),
            )
            .await;
            // A valid symmetric JWT is outside the asymmetric production baseline.
            let token = self::token(sender_claims());
            assert!(matches!(
                auth.authenticate(&token).await,
                Err(AuthenticationError::Refused(_))
            ));
            let mut wrong_actor = claims.clone();
            wrong_actor["registry_actor_kind"] = json!("canary-invalid-actor");
            let token = sign(wrong_actor, "at+jwt");
            assert!(matches!(
                auth.authenticate(&token).await,
                Err(AuthenticationError::Refused(_))
            ));
            let mut missing = claims.clone();
            missing["registry_scopes"] = json!("messaging:other");
            let token = sign(missing, "at+jwt");
            assert!(matches!(
                auth.authenticate(&token).await,
                Err(AuthenticationError::Profile(_))
            ));
        }
    }
    fn without(mut claims: serde_json::Value, key: &str) -> serde_json::Value {
        claims.as_object_mut().unwrap().remove(key);
        claims
    }

    /// A token typed as an ordinary JWT, as a provider that does not type its
    /// access tokens issues.
    fn jwt_typed(claims: serde_json::Value) -> String {
        signed_as(claims, "JWT", SECRET)
    }

    // The access token type (P2)

    #[tokio::test]
    async fn a_jwt_typed_token_is_refused_by_default_and_the_log_names_the_setting() {
        let refused = authenticator()
            .authenticate_declaring(&jwt_typed(sender_claims()))
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
            .authenticate(&jwt_typed(sender_claims()))
            .await
            .expect("an entry that states accessTokenType: JWT admits a JWT-typed token");
        assert_eq!(caller.profile.id, "case-notices");
        assert_eq!(
            stating
                .authenticate(&token(sender_claims()))
                .await
                .expect_err("JWT admits that type alone"),
            AuthenticationError::Refused(FailedCheck::TokenType)
        );
    }

    #[tokio::test]
    async fn an_id_token_is_refused_whether_or_not_jwt_is_admitted() {
        let mut id_claims = sender_claims();
        id_claims["nonce"] = json!("n-0S6_WzA2Mj");
        id_claims["at_hash"] = json!("77QmUPtjPfzWtF2AnpK9RQ");
        let id_token = jwt_typed(id_claims.clone());
        assert_eq!(
            refusal(&id_token).await,
            AuthenticationError::Refused(FailedCheck::TokenType)
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
        let mut typed_id = sender_claims();
        typed_id["typ"] = json!("ID");
        assert_eq!(
            stating
                .authenticate(&jwt_typed(typed_id))
                .await
                .expect_err("a typ claim of ID marks an ID token"),
            AuthenticationError::Refused(FailedCheck::TokenType)
        );
    }

    // The caller kind (P3)

    #[tokio::test]
    async fn a_token_without_a_kind_authenticates_as_unspecified() {
        let caller = authenticator()
            .authenticate(&token(without(operator_claims(), "registry_actor_kind")))
            .await
            .expect("a profile that pins no kind admits a token that names none");
        assert_eq!(caller.profile.id, "operations");
        assert_eq!(caller.actor_kind, None);
    }

    #[tokio::test]
    async fn a_human_only_profile_refuses_an_unspecified_kind() {
        // The sender profile pins a kind, so a token that names none reaches
        // the profile and is refused there, with the actor kind as the check.
        assert_eq!(
            refusal(&token(without(sender_claims(), "registry_actor_kind"))).await,
            AuthenticationError::Profile(FailedCheck::ActorKind)
        );
    }

    #[tokio::test]
    async fn a_declared_client_kind_admits_a_token_without_a_kind() {
        let declared = DeclaredKinds::Clients(
            [(
                SENDER_CLIENT.to_owned(),
                registry_platform_oidc::ActorKind::Service,
            )]
            .into(),
        );
        let caller = authenticator_with(verifier(&[]), declared)
            .authenticate(&token(without(sender_claims(), "registry_actor_kind")))
            .await
            .expect("the declared kind stands for the missing claim");
        assert_eq!(caller.profile.id, "case-notices");
        assert_eq!(caller.actor_kind, Some(ActorKind::Service));
    }

    #[tokio::test]
    async fn a_token_kind_that_contradicts_the_declared_kind_is_refused() {
        let declared = DeclaredKinds::Issuer(registry_platform_oidc::ActorKind::Service);
        let human = token(with(sender_claims(), "registry_actor_kind", json!("human")));
        assert_eq!(
            authenticator_with(verifier(&[]), declared)
                .authenticate(&human)
                .await
                .expect_err("a person's token is never served as a service"),
            AuthenticationError::Refused(FailedCheck::ActorKind)
        );
    }

    #[tokio::test]
    async fn an_unlisted_client_is_refused() {
        let stranger = token(with(sender_claims(), "azp", json!("unrelated-app")));
        assert_eq!(
            refusal(&stranger).await,
            AuthenticationError::Refused(FailedCheck::TokenClient)
        );
    }

    #[tokio::test]
    async fn an_identity_only_token_is_refused_without_a_declared_kind() {
        let identity_only = token(json!({
            "sub": "case-system-principal",
            "azp": SENDER_CLIENT,
            "registry_scopes": "openid profile email",
        }));
        assert_eq!(
            refusal(&identity_only).await,
            AuthenticationError::Refused(FailedCheck::ActorKind)
        );
        // The operator's statement of the client's kind lets it through
        // authentication. The profile still requires its scope.
        let declared = DeclaredKinds::Clients(
            [(
                SENDER_CLIENT.to_owned(),
                registry_platform_oidc::ActorKind::Service,
            )]
            .into(),
        );
        assert_eq!(
            authenticator_with(verifier(&[]), declared)
                .authenticate(&identity_only)
                .await
                .expect_err("the profile requires a scope the token lacks"),
            AuthenticationError::Profile(FailedCheck::Scope)
        );
    }

    // Several issuers (P5)

    #[tokio::test]
    async fn a_token_from_each_configured_issuer_is_verified_under_its_own_rules() {
        let auth = two_issuers();
        let main = auth
            .authenticate(&token(sender_claims()))
            .await
            .expect("the main issuer's token authenticates");
        assert_eq!(main.profile.id, "case-notices");
        assert_eq!(main.identity.issuer, ISSUER);
        let partner = auth
            .authenticate(&partner_token(partner_claims()))
            .await
            .expect("the partner issuer's token authenticates under its own scope claim");
        assert_eq!(partner.profile.id, "partner-notices");
        assert_eq!(partner.identity.issuer, PARTNER_ISSUER);
        // The partner entry reads `scp`, not the main entry's claim.
        let wrong_claim = partner_token(with(
            with(partner_claims(), "scp", json!("messaging:other")),
            "registry_scopes",
            json!("messaging:send"),
        ));
        assert_eq!(
            auth.authenticate(&wrong_claim)
                .await
                .expect_err("the partner entry does not read the main scope claim"),
            AuthenticationError::Profile(FailedCheck::Scope)
        );
        // The main entry's audience is not the partner's.
        let main_audience = partner_token(with(partner_claims(), "aud", json!(AUDIENCE)));
        assert_eq!(
            auth.authenticate(&main_audience)
                .await
                .expect_err("each entry holds its own audience"),
            AuthenticationError::Refused(FailedCheck::TokenAudience)
        );
    }

    #[tokio::test]
    async fn a_token_naming_one_issuer_signed_by_the_other_is_refused() {
        let auth = two_issuers();
        let main_signed_as_partner = signed_as(partner_claims(), "at+jwt", SECRET);
        assert_eq!(
            auth.authenticate(&main_signed_as_partner)
                .await
                .expect_err("the partner entry verifies with the partner's keys"),
            AuthenticationError::Refused(FailedCheck::TokenSignature)
        );
        let partner_signed_as_main = signed_as(sender_claims(), "at+jwt", PARTNER_SECRET);
        assert_eq!(
            auth.authenticate(&partner_signed_as_main)
                .await
                .expect_err("the main entry verifies with the main keys"),
            AuthenticationError::Refused(FailedCheck::TokenSignature)
        );
    }

    #[tokio::test]
    async fn a_token_from_an_unconfigured_issuer_is_refused() {
        let stranger = token(with(
            sender_claims(),
            "iss",
            json!("https://elsewhere.test"),
        ));
        assert_eq!(
            two_issuers()
                .authenticate(&stranger)
                .await
                .expect_err("no entry names this issuer"),
            AuthenticationError::Refused(FailedCheck::TokenIssuer)
        );
    }

    #[test]
    fn an_authenticator_refuses_two_entries_that_name_one_issuer() {
        let error = MessagingAuthenticator::new(
            vec![
                main_source(verifier(&[]), DeclaredKinds::None),
                IssuerSource::new("second", verifier(&[]), keys(), DeclaredKinds::None),
            ],
            profiles(),
        )
        .expect_err("one issuer cannot be two entries");
        assert!(
            matches!(error, IssuerSetError::DuplicateIss { .. }),
            "{error}"
        );
    }

    // The client rule binds a client to one issuer (D1)

    #[tokio::test]
    async fn a_client_listed_by_one_issuer_is_refused_in_a_token_from_another() {
        let auth = two_issuers();
        // The partner signs a token naming the main issuer's client.
        let partner_naming_main_client =
            partner_token(with(partner_claims(), "azp", json!(SENDER_CLIENT)));
        assert_eq!(
            auth.authenticate(&partner_naming_main_client)
                .await
                .expect_err("the partner entry admits only its own clients"),
            AuthenticationError::Refused(FailedCheck::TokenClient)
        );
        // The main issuer signs a token naming the partner's client.
        let main_naming_partner_client = token(with(sender_claims(), "azp", json!(PARTNER_CLIENT)));
        assert_eq!(
            auth.authenticate(&main_naming_partner_client)
                .await
                .expect_err("the main entry admits only its own clients"),
            AuthenticationError::Refused(FailedCheck::TokenClient)
        );
    }
}

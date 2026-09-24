// SPDX-License-Identifier: Apache-2.0

//! Bearer access-token authentication for the Messaging HTTP surface.
//!
//! There is no unauthenticated mode: every `/v1` route resolves its caller
//! here first. Authentication answers, in order: is the credential a
//! verifiable RFC 9068 access token from the configured issuer, for this
//! deployment's audience, from a client it admits, signed by a key the issuer
//! published? Did it arrive through a token exchange this deployment never
//! declared? And which one access profile does the verified client resolve
//! to, with the scopes, actor kind, and principal claim that profile demands?
//!
//! What a caller may send, and which messages it may see, is decided after
//! this point against the resolved profile, never against raw claims.

use std::sync::Arc;

use registry_messaging_core::{
    AccessProfiles, AccessRefusal, ActorKind, ActorKindClaim, Caller, VerifiedTokenFacts,
};
use registry_platform_authcommon::validate_compact_access_token;
use registry_platform_oidc::{
    actor_kind, ClaimError, ClaimNames, JwksFetcher, OidcError, TokenVerifier, TokenVerifierConfig,
    ASSERTION_ISSUER_CLAIM,
};
use thiserror::Error;

pub struct MessagingAuthenticator {
    verifier: TokenVerifier,
    claim_names: ClaimNames,
    profiles: AccessProfiles,
    /// Whether the deployment declared any assertion authority at all.
    binds_assertion_issuers: bool,
}

impl MessagingAuthenticator {
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
            tracing::debug!(error = %error, "the Messaging bearer credential did not verify");
            verifier_failure(&error)
        })?;
        // An exchanged token names the authority whose assertion produced it.
        // The platform applies no rule while the deployment's map is empty, so
        // an empty map would trust every authority the issuer federates.
        // Refuse the exchange instead: a deployment that means to accept one
        // says which authorities, and which client may present them.
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
                AccessRefusal::Profile => AuthenticationError::Profile,
                AccessRefusal::Claims => AuthenticationError::Claims,
            })
    }
}

impl std::fmt::Debug for MessagingAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MessagingAuthenticator")
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
        _ => AuthenticationError::Refused,
    }
}

fn actor_kind_claim(
    result: Result<registry_platform_oidc::ActorKind, ClaimError>,
) -> ActorKindClaim {
    use registry_platform_oidc::ActorKind as Verified;
    match result {
        Ok(Verified::Human) => ActorKindClaim::Present(ActorKind::Human),
        Ok(Verified::Agent) => ActorKindClaim::Present(ActorKind::Agent),
        Ok(Verified::Service) => ActorKindClaim::Present(ActorKind::Service),
        Err(ClaimError::Missing(_)) => ActorKindClaim::Absent,
        Err(_) => ActorKindClaim::Malformed,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use chrono::Utc;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use registry_messaging_core::{AccessProfile, AccessRole};
    use registry_platform_httputil::FetchUrlPolicy;
    use registry_platform_oidc::JwksFetcherConfig;
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

    pub(crate) fn profiles() -> AccessProfiles {
        AccessProfiles::new(vec![
            AccessProfile {
                id: "case-notices".to_owned(),
                principal_claim: "sub".to_owned(),
                required_scopes: vec!["messaging:send".to_owned()],
                requester_clients: vec![SENDER_CLIENT.to_owned()],
                actor_kind: Some(ActorKind::Service),
                role: AccessRole::Sender,
                sender_profiles: vec!["transactional".to_owned()],
                templates: vec!["appointment-reminder".to_owned()],
                allow_direct_content: false,
                requests_per_minute: 60,
                burst: 10,
                daily_limit: None,
            },
            AccessProfile {
                id: "operations".to_owned(),
                principal_claim: "sub".to_owned(),
                required_scopes: vec!["messaging:operate".to_owned()],
                requester_clients: vec![OPERATOR_CLIENT.to_owned()],
                actor_kind: None,
                role: AccessRole::Operator,
                sender_profiles: Vec::new(),
                templates: Vec::new(),
                allow_direct_content: false,
                requests_per_minute: 60,
                burst: 10,
                daily_limit: None,
            },
        ])
        .unwrap()
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

    pub(crate) fn authenticator_over(keys: Arc<JwksFetcher>) -> MessagingAuthenticator {
        MessagingAuthenticator::new(verifier(&[]), keys, profiles(), false)
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
        assert_eq!(caller.role(), AccessRole::Sender);
        assert_eq!(caller.identity.issuer, ISSUER);
        assert_eq!(caller.identity.subject, "case-system-principal");
        assert_eq!(caller.actor_kind, Some(ActorKind::Service));

        let operator = authenticator()
            .authenticate(&token(operator_claims()))
            .await
            .expect("an operator authenticates");
        assert_eq!(operator.role(), AccessRole::Operator);
    }

    #[tokio::test]
    async fn a_credential_that_is_not_a_compact_token_is_refused() {
        for credential in ["", "not-a-jwt", "a.b", "a b.c.d"] {
            assert_eq!(refusal(credential).await, AuthenticationError::Refused);
        }
    }

    #[tokio::test]
    async fn a_forged_signature_is_refused() {
        let forged = token_signed_with(sender_claims(), b"another-secret-another-secret-another!");
        assert_eq!(refusal(&forged).await, AuthenticationError::Refused);
    }

    #[tokio::test]
    async fn a_token_for_another_audience_or_issuer_is_refused() {
        let other_audience = token(with(sender_claims(), "aud", json!("urn:elsewhere")));
        assert_eq!(refusal(&other_audience).await, AuthenticationError::Refused);
        let other_issuer = token(with(
            sender_claims(),
            "iss",
            json!("https://elsewhere.test"),
        ));
        assert_eq!(refusal(&other_issuer).await, AuthenticationError::Refused);
    }

    #[tokio::test]
    async fn an_expired_token_is_refused() {
        let now = Utc::now().timestamp();
        let expired = token(with(
            with(sender_claims(), "exp", json!(now - 600)),
            "iat",
            json!(now - 900),
        ));
        assert_eq!(refusal(&expired).await, AuthenticationError::Refused);
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
        assert_eq!(refusal(&id_token).await, AuthenticationError::Refused);
    }

    #[tokio::test]
    async fn a_client_the_deployment_does_not_admit_is_refused() {
        let stranger = token(with(sender_claims(), "azp", json!("unrelated-app")));
        assert_eq!(refusal(&stranger).await, AuthenticationError::Refused);
    }

    #[tokio::test]
    async fn an_admitted_client_without_a_profile_is_not_authorized() {
        let unprofiled = token(with(sender_claims(), "azp", json!(UNPROFILED_CLIENT)));
        assert_eq!(refusal(&unprofiled).await, AuthenticationError::Profile);
    }

    #[tokio::test]
    async fn a_missing_scope_is_not_authorized() {
        let no_scope = token(with(
            sender_claims(),
            "registry_scopes",
            json!("messaging:read"),
        ));
        assert_eq!(refusal(&no_scope).await, AuthenticationError::Profile);
        let mut absent = sender_claims();
        absent.as_object_mut().unwrap().remove("registry_scopes");
        assert_eq!(refusal(&token(absent)).await, AuthenticationError::Profile);
    }

    #[tokio::test]
    async fn an_actor_kind_the_profile_does_not_admit_is_not_authorized() {
        let human = token(with(sender_claims(), "registry_actor_kind", json!("human")));
        assert_eq!(refusal(&human).await, AuthenticationError::Profile);
        let mut absent = sender_claims();
        absent
            .as_object_mut()
            .unwrap()
            .remove("registry_actor_kind");
        assert_eq!(refusal(&token(absent)).await, AuthenticationError::Profile);
    }

    #[tokio::test]
    async fn a_malformed_actor_kind_is_a_claims_refusal() {
        let malformed = token(with(sender_claims(), "registry_actor_kind", json!("robot")));
        assert_eq!(refusal(&malformed).await, AuthenticationError::Claims);
        let operator = token(with(operator_claims(), "registry_actor_kind", json!(7)));
        assert_eq!(refusal(&operator).await, AuthenticationError::Claims);
    }

    #[tokio::test]
    async fn a_token_without_a_principal_is_a_claims_refusal() {
        let mut claims = sender_claims();
        claims.as_object_mut().unwrap().remove("sub");
        assert_eq!(refusal(&token(claims)).await, AuthenticationError::Claims);
    }

    #[tokio::test]
    async fn an_exchanged_token_is_refused_when_no_authority_was_declared() {
        let exchanged = token(with(
            sender_claims(),
            registry_platform_oidc::ASSERTION_ISSUER_CLAIM,
            json!("https://assertions.example.test"),
        ));
        assert_eq!(refusal(&exchanged).await, AuthenticationError::Profile);

        let declaring = MessagingAuthenticator::new(
            verifier(&[(SENDER_CLIENT, "https://assertions.example.test")]),
            keys(),
            profiles(),
            true,
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
            FetchUrlPolicy::dev(),
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
            OidcError::ClientNotAllowed,
            OidcError::AssertionIssuerNotAllowed,
        ] {
            assert_eq!(
                verifier_failure(&refusal),
                AuthenticationError::Refused,
                "{refusal} was excused as an outage"
            );
        }
    }
}

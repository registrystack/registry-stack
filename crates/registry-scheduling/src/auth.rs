// SPDX-License-Identifier: Apache-2.0

//! Bearer access-token authentication for the Scheduling HTTP surface.
//!
//! There is no unauthenticated mode: every `/v1` route resolves its caller
//! here first. Authentication answers three questions in order. Is the
//! credential a verifiable access token from the configured issuer, for this
//! deployment's audience, signed by a key the issuer published? Which actor
//! kind does it claim, and does it carry a complete task grant? And does the
//! caller hold the scope the route's authentication profile demands?
//!
//! The three profiles mirror the route families. Readable routes take callers
//! holding the reads scope; the separately authorized explain path takes
//! callers holding its own scope; mutating routes demand no extra scope at
//! all, because their authority is the task grant, whose scheduling
//! permissions the service checks per offering.
//!
//! The task grant is extracted with the platform's contextual-authorization
//! claim profile. A token with no grant claims is an ordinary standing
//! caller: it may read, and the service refuses its mutations. A token with
//! partial grant claims is a malformed credential, refused here rather than
//! half-trusted later.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use registry_platform_authcommon::validate_compact_access_token;
use registry_platform_oidc::{
    actor_kind, grant_claims, ClaimNames, JwksFetcher, TokenVerifier, TokenVerifierConfig,
};
use thiserror::Error;

use crate::config::OidcConfig;
use crate::service::Caller;

pub struct SchedulingAuthenticator {
    verifier: TokenVerifier,
    claim_names: ClaimNames,
    audience: String,
    reads_scope: String,
    explain_scope: String,
}

impl SchedulingAuthenticator {
    #[must_use]
    pub fn new(oidc: &OidcConfig, verifier: TokenVerifierConfig, keys: Arc<JwksFetcher>) -> Self {
        // The default contextual-claim profile is the closed one this product
        // speaks; validating it here keeps a future name change honest.
        let claim_names = ClaimNames::default();
        claim_names
            .validate()
            .expect("the default contextual claim names are valid");
        Self {
            verifier: TokenVerifier::new(verifier, keys),
            claim_names,
            audience: oidc.audience.clone(),
            reads_scope: oidc.reads_scope.clone(),
            explain_scope: oidc.explain_scope.clone(),
        }
    }

    /// The profile every catalogue, availability, and owned-record read
    /// demands: the caller holds the configured reads scope.
    pub async fn authenticate_read(&self, token: &str) -> Result<Caller, AuthenticationError> {
        let (caller, scopes) = self.verified_caller(token).await?;
        scopes
            .iter()
            .any(|scope| scope == &self.reads_scope)
            .then_some(caller)
            .ok_or(AuthenticationError::Profile)
    }

    /// The profile the separately authorized explain path demands: the caller
    /// holds the explain scope, which is never the reads scope.
    pub async fn authenticate_explain(&self, token: &str) -> Result<Caller, AuthenticationError> {
        let (caller, scopes) = self.verified_caller(token).await?;
        scopes
            .iter()
            .any(|scope| scope == &self.explain_scope)
            .then_some(caller)
            .ok_or(AuthenticationError::Profile)
    }

    /// The profile the commitments demand: no product scope, because the
    /// authority for a mutation is the task grant the service checks against
    /// the offering's service, location, and action.
    pub async fn authenticate_mutate(&self, token: &str) -> Result<Caller, AuthenticationError> {
        self.verified_caller(token).await.map(|(caller, _)| caller)
    }

    /// Verify one credential and resolve its caller. A present grant is bound
    /// to the verified client and this deployment's audience before the
    /// caller ever reaches the service.
    async fn verified_caller(
        &self,
        token: &str,
    ) -> Result<(Caller, Vec<String>), AuthenticationError> {
        validate_compact_access_token(token).map_err(|_| AuthenticationError::Refused)?;
        let verified = self.verifier.verify(token).await.map_err(|error| {
            tracing::debug!(error = %error, "the Scheduling bearer credential did not verify");
            AuthenticationError::Refused
        })?;
        let kind = actor_kind(&verified.claims, &self.claim_names)
            .map_err(|_| AuthenticationError::Claims)?;
        let grant = grant_claims(&verified.claims, &self.claim_names, unix_now())
            .map_err(|_| AuthenticationError::Claims)?;
        if let Some(grant) = &grant {
            grant
                .verify_context(&verified, &self.audience)
                .map_err(|_| AuthenticationError::Profile)?;
        }
        let issuer = verified
            .claims
            .iss
            .clone()
            .filter(|issuer| !issuer.is_empty())
            .ok_or(AuthenticationError::Claims)?;
        let subject = verified
            .claims
            .sub
            .clone()
            .filter(|subject| !subject.is_empty())
            .ok_or(AuthenticationError::Claims)?;
        Ok((
            Caller {
                actor_kind: kind.as_str().to_owned(),
                issuer,
                subject,
                grant,
            },
            verified.scopes,
        ))
    }
}

impl std::fmt::Debug for SchedulingAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SchedulingAuthenticator")
            .field("verifier", &"<redacted>")
            .field("audience", &"<redacted>")
            .field("reads_scope", &self.reads_scope)
            .field("explain_scope", &self.explain_scope)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthenticationError {
    #[error("the bearer credential was refused")]
    Refused,
    #[error("the verified identity claims are invalid")]
    Claims,
    #[error("the caller's authentication profile is not authorized for this request")]
    Profile,
}

/// The observation of now the grant's expiry is judged against, in the same
/// units the token's own `exp` carries.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use chrono::Utc;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use registry_platform_oidc::{ActorKind, JwksFetcherConfig};
    use serde_json::json;

    const ISSUER: &str = "https://task-token.test";
    const AUDIENCE: &str = "urn:registry-scheduling:test";
    const CLIENT: &str = "task-agent";
    const SECRET: &[u8] = b"01234567890123456789012345678901";

    fn oidc() -> OidcConfig {
        OidcConfig {
            allowed_clients: vec![CLIENT.to_owned()],
            issuer: ISSUER.to_owned(),
            audience: AUDIENCE.to_owned(),
            jwks_uri: None,
            jwks_source: crate::config::OidcJwksSource::Discovery,
            scope_claim: "registry_scopes".to_owned(),
            reads_scope: "scheduling-read".to_owned(),
            explain_scope: "scheduling-explain".to_owned(),
        }
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

    fn authenticator() -> SchedulingAuthenticator {
        let verifier = TokenVerifierConfig::access_token_profile(
            ISSUER,
            vec![AUDIENCE.to_owned()],
            vec![Algorithm::HS256],
            vec!["at+jwt".to_owned()],
        )
        .with_scope_claim("registry_scopes")
        .with_allowed_clients(vec![CLIENT.to_owned()]);
        SchedulingAuthenticator::new(&oidc(), verifier, keys())
    }

    /// Sign an access token, filling in the claims a real token always
    /// carries so a test only has to state what it varies.
    fn token(mut claims: serde_json::Value) -> String {
        let now = Utc::now().timestamp();
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

    /// The complete task-grant claim set a mutating caller carries, with the
    /// bounds the test's permission assertions read.
    fn grant_claims_value(resource: &str) -> serde_json::Value {
        let now = Utc::now().timestamp();
        json!({
            "registry_actor_kind": "agent",
            "registry_purpose": "registry-update",
            "registry_grant_id": "grant-1",
            "registry_grant_source_issuer": "https://authority.test",
            "registry_grant_client": CLIENT,
            "registry_grant_resource": resource,
            "registry_grant_exp": now + 600,
            "registry_grant_bounds": {
                "type": "scheduling",
                "permissions": [{
                    "service": "registry-update",
                    "location": "north-counter",
                    "actions": ["hold.create", "appointment.create"],
                }],
            },
            "registry_approver": "approver-1",
        })
    }

    fn merged(scopes: &str, grant: serde_json::Value) -> serde_json::Value {
        let mut claims = json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": scopes,
            "registry_actor_kind": "service",
        });
        let object = claims.as_object_mut().unwrap();
        object.extend(
            grant
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        claims
    }

    #[tokio::test]
    async fn a_read_caller_with_the_reads_scope_authenticates_without_a_grant() {
        let credential = token(json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "scheduling-read",
            "registry_actor_kind": "service",
        }));
        let caller = authenticator()
            .authenticate_read(&credential)
            .await
            .expect("a standing caller holding the reads scope reads");
        assert_eq!(caller.actor_kind, "service");
        assert_eq!(caller.issuer, ISSUER);
        assert_eq!(caller.subject, "principal-1");
        assert!(caller.grant.is_none());
    }

    #[tokio::test]
    async fn a_read_without_the_reads_scope_is_a_profile_refusal_but_still_mutates() {
        let credential = token(json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "unrelated-scope",
            "registry_actor_kind": "service",
        }));
        let authenticator = authenticator();
        assert!(matches!(
            authenticator.authenticate_read(&credential).await,
            Err(AuthenticationError::Profile)
        ));
        // Mutating routes demand no product scope: their authority is the
        // task grant, checked per offering in the service.
        authenticator
            .authenticate_mutate(&credential)
            .await
            .expect("a caller without the reads scope still reaches a mutation");
    }

    #[tokio::test]
    async fn the_explain_path_demands_its_own_scope() {
        let authenticator = authenticator();
        let reader = token(json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "scheduling-read",
            "registry_actor_kind": "service",
        }));
        assert!(matches!(
            authenticator.authenticate_explain(&reader).await,
            Err(AuthenticationError::Profile)
        ));
        let explainer = token(json!({
            "sub": "principal-2",
            "azp": CLIENT,
            "registry_scopes": "scheduling-read scheduling-explain",
            "registry_actor_kind": "service",
        }));
        authenticator
            .authenticate_explain(&explainer)
            .await
            .expect("the explain scope opens the explain path");
    }

    #[tokio::test]
    async fn a_complete_task_grant_is_extracted_and_bound_to_the_deployment() {
        let credential = token(merged("scheduling-read", grant_claims_value(AUDIENCE)));
        let caller = authenticator()
            .authenticate_mutate(&credential)
            .await
            .expect("a complete grant authenticates");
        let grant = caller.grant.expect("the grant is extracted");
        assert_eq!(caller.actor_kind, "agent");
        let permissions = grant
            .bounds()
            .scheduling_permissions()
            .expect("the scheduling bounds travel with the grant");
        assert_eq!(permissions.len(), 1);
        assert_eq!(permissions[0].service(), "registry-update");
        assert_eq!(permissions[0].location(), "north-counter");
        assert!(permissions[0]
            .actions()
            .iter()
            .any(|action| action == "hold.create"));
    }

    #[tokio::test]
    async fn a_grant_naming_another_resource_is_a_profile_refusal() {
        let credential = token(merged(
            "scheduling-read",
            grant_claims_value("urn:registry:other-product"),
        ));
        assert!(matches!(
            authenticator().authenticate_mutate(&credential).await,
            Err(AuthenticationError::Profile)
        ));
    }

    #[tokio::test]
    async fn a_partial_grant_is_refused_as_invalid_claims() {
        let mut grant = grant_claims_value(AUDIENCE);
        let object = grant.as_object_mut().unwrap();
        object.remove("registry_grant_exp");
        object.remove("registry_grant_client");
        let credential = token(merged("scheduling-read", grant));
        assert!(matches!(
            authenticator().authenticate_mutate(&credential).await,
            Err(AuthenticationError::Claims)
        ));
    }

    #[tokio::test]
    async fn an_actor_kind_outside_the_vocabulary_is_refused() {
        let credential = token(json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "scheduling-read",
            "registry_actor_kind": "robot",
        }));
        assert!(matches!(
            authenticator().authenticate_read(&credential).await,
            Err(AuthenticationError::Claims)
        ));
    }

    #[tokio::test]
    async fn a_credential_signed_by_an_unknown_key_is_refused() {
        let mut claims = json!({
            "sub": "principal-1",
            "azp": CLIENT,
            "registry_scopes": "scheduling-read",
            "registry_actor_kind": ActorKind::Service.as_str(),
        });
        let now = Utc::now().timestamp();
        let object = claims.as_object_mut().unwrap();
        object.insert("iss".to_owned(), json!(ISSUER));
        object.insert("aud".to_owned(), json!(AUDIENCE));
        object.insert("iat".to_owned(), json!(now));
        object.insert("exp".to_owned(), json!(now + 300));
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test".to_owned());
        header.typ = Some("at+jwt".to_owned());
        let forged = jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_secret(b"another-secret-another-secret-another!"),
        )
        .unwrap();
        assert!(matches!(
            authenticator().authenticate_read(&forged).await,
            Err(AuthenticationError::Refused)
        ));
    }
}

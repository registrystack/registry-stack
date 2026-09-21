use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use registry_casework_core::{
    AccessProfile, ActorContext, CaseworkProject, CaseworkRole, IssuerPrincipal,
};
use registry_platform_authcommon::validate_compact_access_token;
use registry_platform_oidc::{JwksFetcher, TokenVerifier, TokenVerifierConfig};
use serde_json::Value;
use thiserror::Error;

use crate::HumanIdentityConfig;

pub struct CaseworkAuthenticator {
    verifier: TokenVerifier,
    profiles: BTreeMap<String, AccessProfile>,
    human_identity: HumanIdentityConfig,
}

impl CaseworkAuthenticator {
    /// Constructs an authenticator from a project already validated by
    /// [`CaseworkProject::load`] or [`CaseworkProject::check`].
    #[must_use]
    pub fn new(
        project: &CaseworkProject,
        verifier: TokenVerifierConfig,
        keys: Arc<JwksFetcher>,
        human_identity: HumanIdentityConfig,
    ) -> Self {
        Self {
            verifier: TokenVerifier::new(verifier, keys),
            profiles: project
                .access_profiles
                .iter()
                .cloned()
                .map(|profile| (profile.id.clone(), profile))
                .collect(),
            human_identity,
        }
    }

    pub(crate) async fn authenticate_task_client(
        &self,
        token: &str,
        scope: &str,
        kind: registry_platform_oidc::ActorKind,
    ) -> Result<registry_platform_oidc::VerifiedToken, AuthenticationError> {
        validate_compact_access_token(token).map_err(|_| AuthenticationError::Refused)?;
        let verified = self
            .verifier
            .verify(token)
            .await
            .map_err(|_| AuthenticationError::Refused)?;
        if !matches!(
            verified.claims.aud.as_ref(),
            Some(registry_platform_oidc::Audience::One(_))
        ) && !matches!(verified.claims.aud.as_ref(), Some(registry_platform_oidc::Audience::Many(values)) if values.len() == 1)
            || verified.claims.extra.contains_key("act")
            || !verified.scopes.iter().any(|value| value == scope)
            || verified.matched_client_id().ok().flatten().is_none()
            || registry_platform_oidc::actor_kind(
                &verified.claims,
                &registry_platform_oidc::ClaimNames::default(),
            )
            .ok()
                != Some(kind)
            || verified
                .claims
                .extra
                .keys()
                .any(|key| key.starts_with("registry_grant_"))
        {
            return Err(AuthenticationError::Refused);
        }
        Ok(verified)
    }

    pub async fn authenticate(
        &self,
        token: &str,
        selected_profile: &str,
    ) -> Result<ActorContext, AuthenticationError> {
        validate_compact_access_token(token).map_err(|_| AuthenticationError::Refused)?;
        let verified = self
            .verifier
            .verify(token)
            .await
            .map_err(|_| AuthenticationError::Refused)?;
        let profile = self
            .profiles
            .get(selected_profile)
            .ok_or(AuthenticationError::Profile)?;
        if profile.role != CaseworkRole::Requester
            && (verified.claims.extra.contains_key("act")
                || verified
                    .claims
                    .extra
                    .keys()
                    .any(|key| key.starts_with("registry_grant_")))
        {
            return Err(AuthenticationError::Refused);
        }
        let actual_scopes: BTreeSet<_> = verified.scopes.iter().map(String::as_str).collect();
        if !profile
            .required_scopes
            .iter()
            .all(|scope| actual_scopes.contains(scope.as_str()))
        {
            return Err(AuthenticationError::Profile);
        }
        if profile.role != CaseworkRole::Requester {
            let human_identity = verified
                .claims
                .extra
                .get(&self.human_identity.claim)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or(AuthenticationError::NotHuman)?;
            if human_identity != self.human_identity.value {
                return Err(AuthenticationError::NotHuman);
            }
        }
        let principal = if profile.principal_claim == "sub" {
            verified.claims.sub.as_deref()
        } else {
            verified
                .claims
                .extra
                .get(&profile.principal_claim)
                .and_then(Value::as_str)
        }
        .filter(|value| !value.is_empty())
        .ok_or(AuthenticationError::Claims)?;
        let issuer = verified
            .claims
            .iss
            .filter(|issuer| !issuer.is_empty())
            .ok_or(AuthenticationError::Claims)?;
        Ok(ActorContext {
            principal: IssuerPrincipal {
                issuer,
                subject: principal.to_owned(),
            },
            profile_id: profile.id.clone(),
            role: profile.role,
        })
    }
}

impl std::fmt::Debug for CaseworkAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaseworkAuthenticator")
            .field("verifier", &"<redacted>")
            .field("profiles", &self.profiles.keys())
            .field("human_identity_claim", &self.human_identity.claim)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthenticationError {
    #[error("the bearer credential was refused")]
    Refused,
    #[error("the selected Casework profile was refused")]
    Profile,
    #[error("the verified identity is not a human session")]
    NotHuman,
    #[error("the verified identity claims are invalid")]
    Claims,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use chrono::Utc;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use registry_casework_core::{CaseworkIdentity, InboxPolicy};
    use registry_platform_oidc::{ActorKind, JwksFetcherConfig};
    use serde_json::json;

    const ISSUER: &str = "https://task-token.test";
    const AUDIENCE: &str = "urn:casework:test";
    const CLIENT: &str = "task-agent";
    const SECRET: &[u8] = b"01234567890123456789012345678901";

    fn project() -> CaseworkProject {
        CaseworkProject {
            api_version: registry_casework_core::CASEWORK_API_VERSION.to_owned(),
            kind: registry_casework_core::CASEWORK_KIND.to_owned(),
            casework: CaseworkIdentity {
                id: "task-grant-fixture".to_owned(),
                version: "1".to_owned(),
            },
            access_profiles: Vec::new(),
            queues: Vec::new(),
            sources: Vec::new(),
            review_kinds: Vec::new(),
            review_producers: Vec::new(),
            calendars: Vec::new(),
            clocks: Vec::new(),
            inbox: InboxPolicy::default(),
            task_templates: Vec::new(),
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

    fn authenticator(assertion_issuers: BTreeMap<String, Vec<String>>) -> CaseworkAuthenticator {
        let verifier = TokenVerifierConfig::access_token_profile(
            ISSUER,
            vec![AUDIENCE.to_owned()],
            vec![Algorithm::HS256],
            vec!["at+jwt".to_owned()],
        )
        .with_scope_claim("scope")
        .with_allowed_clients(vec![CLIENT.to_owned()])
        .with_assertion_issuers(assertion_issuers);
        CaseworkAuthenticator::new(&project(), verifier, keys(), HumanIdentityConfig::default())
    }

    /// Sign a standing task-client access token, filling in the claims a real
    /// token always carries so a test only has to state what it varies.
    fn token(mut claims: Value) -> String {
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

    #[tokio::test]
    async fn a_standing_client_credentials_token_without_an_assertion_issuer_claim_is_accepted_while_assertion_issuers_are_configured(
    ) {
        let mut assertion_issuers = BTreeMap::new();
        assertion_issuers.insert(
            CLIENT.to_owned(),
            vec!["https://exchange.example.test".to_owned()],
        );
        let authenticator = authenticator(assertion_issuers);
        let credential = token(json!({
            "azp": CLIENT,
            "scope": "task-grant",
            "registry_actor_kind": "service",
        }));
        let verified = authenticator
            .authenticate_task_client(&credential, "task-grant", ActorKind::Service)
            .await
            .expect("a standing client-credentials token carries no assertion-issuer claim");
        assert!(!verified
            .claims
            .extra
            .contains_key(registry_platform_oidc::ASSERTION_ISSUER_CLAIM));
    }

    #[tokio::test]
    async fn a_token_asserting_an_authority_the_client_is_not_listed_for_is_refused_while_the_listed_authority_is_accepted(
    ) {
        let mut assertion_issuers = BTreeMap::new();
        assertion_issuers.insert(
            CLIENT.to_owned(),
            vec!["https://exchange.example.test".to_owned()],
        );
        let authenticator = authenticator(assertion_issuers);

        let disallowed = token(json!({
            "azp": CLIENT,
            "scope": "task-grant",
            "registry_actor_kind": "service",
            "registry_assertion_issuer": "https://unlisted-authority.example.test",
        }));
        let result = authenticator
            .authenticate_task_client(&disallowed, "task-grant", ActorKind::Service)
            .await;
        assert!(matches!(result, Err(AuthenticationError::Refused)));

        let allowed = token(json!({
            "azp": CLIENT,
            "scope": "task-grant",
            "registry_actor_kind": "service",
            "registry_assertion_issuer": "https://exchange.example.test",
        }));
        authenticator
            .authenticate_task_client(&allowed, "task-grant", ActorKind::Service)
            .await
            .expect("the listed assertion authority is accepted");
    }
}

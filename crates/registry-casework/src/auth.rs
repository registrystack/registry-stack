use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use registry_casework_core::{AccessProfile, ActorContext, CaseworkProject, IssuerPrincipal};
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
        let actual_scopes: BTreeSet<_> = verified.scopes.iter().map(String::as_str).collect();
        if !profile
            .required_scopes
            .iter()
            .all(|scope| actual_scopes.contains(scope.as_str()))
        {
            return Err(AuthenticationError::Profile);
        }
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

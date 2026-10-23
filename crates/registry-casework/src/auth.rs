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
    /// Requester profiles through which a person reads their own review
    /// requests; they authenticate a person as strictly as reviewer profiles.
    initiator_profiles: BTreeSet<String>,
    human_identity: HumanIdentityConfig,
}

impl CaseworkAuthenticator {
    pub(crate) fn record_header_refusal(&self) {
        registry_platform_oidc::log_authentication_refusal!(
            self.verifier,
            registry_platform_oidc::AuthenticationStage::Header,
            "Casework authentication refused"
        );
    }

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
            initiator_profiles: project
                .trusted_producers
                .iter()
                .filter_map(|producer| producer.initiator_profile.clone())
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
        validate_compact_access_token(token).map_err(|_| {
            self.record_header_refusal();
            AuthenticationError::Refused
        })?;
        let verified = self.verifier.verify(token).await.map_err(|error| {
            registry_platform_oidc::log_authentication_refusal!(
                self.verifier,
                error.authentication_stage(),
                "Casework authentication refused"
            );
            AuthenticationError::Refused
        })?;
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
        validate_compact_access_token(token).map_err(|_| {
            self.record_header_refusal();
            AuthenticationError::Refused
        })?;
        let verified = self.verifier.verify(token).await.map_err(|error| {
            registry_platform_oidc::log_authentication_refusal!(
                self.verifier,
                error.authentication_stage(),
                "Casework authentication refused"
            );
            AuthenticationError::Refused
        })?;
        let profile = self.profiles.get(selected_profile).ok_or_else(|| {
            self.profile_diagnostic();
            AuthenticationError::Profile
        })?;
        let requires_person = profile.role != CaseworkRole::Requester
            || self.initiator_profiles.contains(&profile.id);
        if requires_person
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
            registry_platform_oidc::log_authentication_refusal!(
                self.verifier,
                registry_platform_oidc::AuthenticationStage::Scope,
                "Casework authentication profile refused",
                remedy = "check authentication.oidc.scopeClaim and accessProfiles requiredScopes"
            );
            return Err(AuthenticationError::Profile);
        }
        if requires_person {
            let human_identity = verified
                .claims
                .extra
                .get(&self.human_identity.claim)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    self.profile_diagnostic();
                    AuthenticationError::NotHuman
                })?;
            if human_identity != self.human_identity.value {
                self.profile_diagnostic();
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

    fn profile_diagnostic(&self) {
        registry_platform_oidc::log_authentication_refusal!(
            self.verifier,
            registry_platform_oidc::AuthenticationStage::Profile,
            "Casework authentication profile refused",
            remedy = "check selected accessProfiles and authentication.oidc.humanIdentity profile category"
        );
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
    use registry_casework_core::{InboxPolicy, ProjectIdentity};
    use registry_platform_oidc::{ActorKind, JwksFetcherConfig};
    use serde_json::json;

    const ISSUER: &str = "https://task-token.test";
    const AUDIENCE: &str = "urn:casework:test";
    const CLIENT: &str = "task-agent";
    const SECRET: &[u8] = b"01234567890123456789012345678901";

    #[tokio::test]
    async fn equivalent_profile_refusals_share_one_bounded_value_free_diagnostic() {
        use tracing::instrument::WithSubscriber;
        #[derive(Clone)]
        struct Writer(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = Writer(Arc::clone(&output));
        let subscriber = tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .json()
                .without_time()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish(),
        );
        let mut p = project();
        p.access_profiles.push(AccessProfile {
            id: "staff".into(),
            principal_claim: "sub".into(),
            required_scopes: vec!["canary-private-scope".into()],
            role: CaseworkRole::Staff,
        });
        let verifier = TokenVerifierConfig::access_token_profile(
            ISSUER,
            vec![AUDIENCE.into()],
            vec![Algorithm::HS256],
            vec!["at+jwt".into()],
        );
        let auth = CaseworkAuthenticator::new(&p, verifier, keys(), HumanIdentityConfig::default());
        let base = json!({"sub":"canary-private-subject","scope":"canary-private-scope"});
        let credential = token(base.clone());
        assert_eq!(
            auth.authenticate(&credential, "canary-private-profile")
                .with_subscriber(subscriber.clone())
                .await
                .unwrap_err(),
            AuthenticationError::Profile
        );
        for kind in [None, Some(""), Some("canary-private-actor")] {
            let mut claims = base.clone();
            if let Some(kind) = kind {
                claims["registry_actor_kind"] = json!(kind);
            }
            let credential = token(claims);
            assert_eq!(
                auth.authenticate(&credential, "staff")
                    .with_subscriber(subscriber.clone())
                    .await
                    .unwrap_err(),
                AuthenticationError::NotHuman
            );
        }
        let rendered = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert_eq!(rendered.lines().count(), 1);
        assert!(rendered.contains("profile"));
        assert!(rendered.contains("authentication.oidc.humanIdentity"));
        assert!(!rendered.contains("canary-private"));
        assert!(!rendered.contains(&credential));
    }

    fn project() -> CaseworkProject {
        CaseworkProject {
            api_version: registry_casework_core::CASEWORK_API_VERSION.to_owned(),
            kind: registry_casework_core::CASEWORK_KIND.to_owned(),
            project: ProjectIdentity {
                id: "task-grant-fixture".parse().unwrap(),
                version: "1".to_owned(),
            },
            access_profiles: Vec::new(),
            queues: Vec::new(),
            teams: Vec::new(),
            context_providers: Vec::new(),
            review_policies: Vec::new(),
            trusted_producers: Vec::new(),
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
    #[tokio::test]
    async fn compact_token_admission_logs_one_value_free_header_diagnostic() {
        use registry_platform_testing::{malformed_access_token_fixtures, CapturedDiagnosticLogs};
        use tracing::instrument::WithSubscriber;
        let captured = CapturedDiagnosticLogs::default();
        let subscriber = captured.subscriber();
        let tokens = malformed_access_token_fixtures();
        let auth = authenticator(BTreeMap::new());
        for _ in 0..3 {
            for token in &tokens {
                assert!(matches!(
                    auth.authenticate(token, "requester")
                        .with_subscriber(subscriber.clone())
                        .await,
                    Err(AuthenticationError::Refused)
                ));
                assert!(matches!(
                    auth.authenticate_task_client(
                        token,
                        "casework:grants:status",
                        ActorKind::Service
                    )
                    .with_subscriber(subscriber.clone())
                    .await,
                    Err(AuthenticationError::Refused)
                ));
            }
        }
        captured.assert_one_value_free_header_diagnostic(&tokens);
    }

    #[tokio::test]
    async fn separate_resource_rs256_and_es256_profiles_refuse_cross_resource_reuse() {
        for algorithm in [Algorithm::RS256, Algorithm::ES256] {
            let key = registry_platform_testing::access_token_test_key(algorithm);
            let jwks = serde_json::from_value(json!({"keys":[key.public()]})).unwrap();
            let source = Arc::new(JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults()));
            let verifier = TokenVerifierConfig::access_token_profile(
                ISSUER,
                vec![AUDIENCE.to_owned()],
                vec![algorithm],
                vec!["at+jwt".to_owned()],
            )
            .with_scope_claim("scope")
            .with_allowed_clients(vec![CLIENT.to_owned()]);
            let mut p = project();
            p.access_profiles.push(AccessProfile {
                id: "staff".into(),
                principal_claim: "sub".into(),
                required_scopes: vec!["casework:staff".into()],
                role: CaseworkRole::Staff,
            });
            let auth =
                CaseworkAuthenticator::new(&p, verifier, source, HumanIdentityConfig::default());
            let now = Utc::now().timestamp();
            let claims = json!({"iss":ISSUER,"aud":AUDIENCE,"azp":CLIENT,"sub":"canary-person","scope":"casework:staff","registry_actor_kind":"human","iat":now,"exp":now+300});
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
                    async move { auth.authenticate(&token, "staff").await }
                },
                |error| matches!(error, AuthenticationError::Refused),
            )
            .await;
            // A valid symmetric JWT is outside the asymmetric production baseline.
            let token = self::token(
                json!({"azp":CLIENT,"scope":"casework:staff","registry_actor_kind":"human"}),
            );
            assert!(matches!(
                auth.authenticate(&token, "staff").await,
                Err(AuthenticationError::Refused)
            ));
            let mut wrong_actor = claims.clone();
            wrong_actor["registry_actor_kind"] = json!("canary-invalid-actor");
            let token = sign(wrong_actor, "at+jwt");
            assert!(matches!(
                auth.authenticate(&token, "staff").await,
                Err(AuthenticationError::NotHuman)
            ));
            let mut missing = claims.clone();
            missing["scope"] = json!("");
            let token = sign(missing, "at+jwt");
            assert!(matches!(
                auth.authenticate(&token, "staff").await,
                Err(AuthenticationError::Profile)
            ));
        }
    }
}

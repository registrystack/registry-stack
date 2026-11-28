use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use registry_casework_core::{
    AccessProfile, ActorContext, CaseworkActsAs, CaseworkProject, IssuerPrincipal,
};
use registry_platform_authcommon::{validate_compact_access_token, FailedCheck};
use registry_platform_oidc::{JwksFetcher, TokenVerifier, TokenVerifierConfig};
use serde_json::Value;
use thiserror::Error;

use crate::HumanIdentityConfig;

pub(crate) mod delegated;

pub struct CaseworkAuthenticator {
    verifier: TokenVerifier,
    source_verifier_config: TokenVerifierConfig,
    source_keys: Arc<JwksFetcher>,
    source_verifiers: BTreeMap<String, TokenVerifier>,
    audience: String,
    profiles: BTreeMap<String, AccessProfile>,
    /// Requester profiles through which a person reads their own review
    /// requests; they authenticate a person as strictly as reviewer profiles.
    initiator_profiles: BTreeSet<String>,
    human_identity: HumanIdentityConfig,
    delegated_staff_readers: BTreeMap<String, crate::DelegatedStaffReaderConfig>,
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
        let audience = verifier.audiences.first().cloned().unwrap_or_default();
        Self {
            source_verifier_config: verifier.clone(),
            source_keys: Arc::clone(&keys),
            source_verifiers: BTreeMap::new(),
            verifier: TokenVerifier::new(verifier, keys),
            audience,
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
            delegated_staff_readers: BTreeMap::new(),
        }
    }

    /// Source authentication shares existing issuer/key trust, never Casework
    /// client admission. BReg independently enforces source client authority.
    #[must_use]
    pub fn with_human_source_audiences(mut self, audiences: BTreeMap<String, String>) -> Self {
        for (provider, audience) in audiences {
            if audience == self.audience {
                continue;
            }
            // Reuse only cryptographic trust and lifetime policy. In particular,
            // Casework clients, assertion authorities and scope mappings are not
            // source admission policy; BReg owns those independent decisions.
            let existing = &self.source_verifier_config;
            let mut config = TokenVerifierConfig::access_token_profile(
                existing.issuer.clone(),
                vec![audience],
                existing.allowed_algorithms.clone(),
                existing.allowed_typ.clone(),
            );
            config.denied_kids = existing.denied_kids.clone();
            config.max_token_lifetime = existing.max_token_lifetime;
            config.leeway = existing.leeway;
            self.source_verifiers.insert(
                provider,
                TokenVerifier::new(config, Arc::clone(&self.source_keys)),
            );
        }
        self
    }

    pub(crate) async fn verify_human_source_pair(
        &self,
        casework: &str,
        source: &str,
        provider: &str,
    ) -> Result<(), AuthenticationError> {
        validate_compact_access_token(source)
            .map_err(|_| AuthenticationError::Refused(FailedCheck::CredentialMalformed))?;
        let source_verifier = self
            .source_verifiers
            .get(provider)
            .ok_or(AuthenticationError::Refused(FailedCheck::AccessProfile))?;
        let primary = self
            .verifier
            .verify(casework)
            .await
            .map_err(|error| AuthenticationError::Refused(error.failed_check()))?;
        let secondary = source_verifier
            .verify(source)
            .await
            .map_err(|error| AuthenticationError::Refused(error.failed_check()))?;
        for verified in [&primary, &secondary] {
            if !matches!(
                verified.claims.aud,
                Some(registry_platform_oidc::Audience::One(_))
            ) {
                return Err(AuthenticationError::Refused(FailedCheck::TokenAudience));
            }
            if verified.claims.sub.as_deref().is_none_or(str::is_empty) {
                return Err(AuthenticationError::Refused(FailedCheck::TokenClaims));
            }
            if verified
                .claims
                .extra
                .get("registry_actor_kind")
                .and_then(Value::as_str)
                != Some("human")
                || verified
                    .claims
                    .extra
                    .get(&self.human_identity.claim)
                    .and_then(Value::as_str)
                    != Some(self.human_identity.value.as_str())
            {
                return Err(AuthenticationError::Refused(FailedCheck::ActorKind));
            }
            if verified.claims.extra.contains_key("act") {
                return Err(AuthenticationError::Refused(FailedCheck::Delegation));
            }
            if verified
                .claims
                .extra
                .keys()
                .any(|key| key.starts_with("registry_grant_"))
            {
                return Err(AuthenticationError::Refused(FailedCheck::TaskGrantClaims));
            }
        }
        if primary.claims.iss != secondary.claims.iss || primary.claims.sub != secondary.claims.sub
        {
            return Err(AuthenticationError::Refused(FailedCheck::TokenClaims));
        }
        Ok(())
    }

    #[must_use]
    pub fn with_delegated_staff_readers(
        mut self,
        readers: BTreeMap<String, crate::DelegatedStaffReaderConfig>,
    ) -> Self {
        self.delegated_staff_readers = readers;
        self
    }

    pub(crate) async fn authenticate_task_client(
        &self,
        token: &str,
        scope: &str,
        kind: registry_platform_oidc::ActorKind,
    ) -> Result<registry_platform_oidc::VerifiedToken, AuthenticationError> {
        validate_compact_access_token(token)
            .map_err(|_| AuthenticationError::Refused(FailedCheck::CredentialMalformed))?;
        let verified = self
            .verifier
            .verify(token)
            .await
            .map_err(|error| AuthenticationError::Refused(error.failed_check()))?;
        if !matches!(
            verified.claims.aud.as_ref(),
            Some(registry_platform_oidc::Audience::One(_))
        ) && !matches!(verified.claims.aud.as_ref(), Some(registry_platform_oidc::Audience::Many(values)) if values.len() == 1)
        {
            return Err(AuthenticationError::Refused(FailedCheck::TokenAudience));
        }
        if verified.claims.extra.contains_key("act") {
            return Err(AuthenticationError::Refused(FailedCheck::Delegation));
        }
        if !verified.scopes.iter().any(|value| value == scope) {
            return Err(AuthenticationError::Refused(FailedCheck::Scope));
        }
        if verified.matched_client_id().ok().flatten().is_none() {
            return Err(AuthenticationError::Refused(FailedCheck::TokenClient));
        }
        if registry_platform_oidc::actor_kind(
            &verified.claims,
            &registry_platform_oidc::ClaimNames::default(),
        )
        .ok()
            != Some(kind)
        {
            return Err(AuthenticationError::Refused(FailedCheck::ActorKind));
        }
        if verified
            .claims
            .extra
            .keys()
            .any(|key| key.starts_with("registry_grant_"))
        {
            return Err(AuthenticationError::Refused(FailedCheck::TaskGrantClaims));
        }
        Ok(verified)
    }

    pub async fn authenticate(
        &self,
        token: &str,
        selected_profile: &str,
    ) -> Result<ActorContext, AuthenticationError> {
        validate_compact_access_token(token)
            .map_err(|_| AuthenticationError::Refused(FailedCheck::CredentialMalformed))?;
        let verified = self
            .verifier
            .verify(token)
            .await
            .map_err(|error| AuthenticationError::Refused(error.failed_check()))?;
        let matched_client = verified
            .matched_client_id()
            .map_err(|_| AuthenticationError::Refused(FailedCheck::TokenClient))?;
        for reader in self.delegated_staff_readers.values() {
            if matched_client != Some(reader.client.as_str()) {
                continue;
            }
            if verified.claims.extra.contains_key("act") {
                return Err(AuthenticationError::Refused(FailedCheck::Delegation));
            }
            if verified
                .scopes
                .iter()
                .any(|scope| scope == &reader.required_scope)
            {
                return Err(AuthenticationError::Refused(FailedCheck::Scope));
            }
        }
        let profile = self
            .profiles
            .get(selected_profile)
            .ok_or(AuthenticationError::Profile(FailedCheck::AccessProfile))?;
        let requires_person = profile.acts_as != CaseworkActsAs::Requester
            || self.initiator_profiles.contains(&profile.id);
        if requires_person {
            if verified.claims.extra.contains_key("act") {
                return Err(AuthenticationError::Refused(FailedCheck::Delegation));
            }
            if verified
                .claims
                .extra
                .keys()
                .any(|key| key.starts_with("registry_grant_"))
            {
                return Err(AuthenticationError::Refused(FailedCheck::TaskGrantClaims));
            }
        }
        let actual_scopes: BTreeSet<_> = verified.scopes.iter().map(String::as_str).collect();
        if !profile
            .required_scopes
            .iter()
            .all(|scope| actual_scopes.contains(scope.as_str()))
        {
            return Err(AuthenticationError::Profile(FailedCheck::Scope));
        }
        if requires_person {
            let human_identity = verified
                .claims
                .extra
                .get(&self.human_identity.claim)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or(AuthenticationError::NotHuman(FailedCheck::ActorKind))?;
            if human_identity != self.human_identity.value {
                return Err(AuthenticationError::NotHuman(FailedCheck::ActorKind));
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
        .ok_or(AuthenticationError::Claims(FailedCheck::TokenClaims))?;
        let issuer = verified
            .claims
            .iss
            .filter(|issuer| !issuer.is_empty())
            .ok_or(AuthenticationError::Claims(FailedCheck::TokenClaims))?;
        Ok(ActorContext {
            principal: IssuerPrincipal {
                issuer,
                subject: principal.to_owned(),
            },
            profile_id: profile.id.clone(),
            role: profile.acts_as,
        })
    }
}

impl std::fmt::Debug for CaseworkAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaseworkAuthenticator")
            .field("verifier", &"<redacted>")
            .field("profiles", &self.profiles.keys())
            .field(
                "delegated_staff_readers",
                &self.delegated_staff_readers.keys(),
            )
            .field("human_identity_claim", &self.human_identity.claim)
            .finish()
    }
}

/// Why authentication refused a request. Each variant names the check that
/// failed, which goes to the operator's counter and log and never to the
/// caller.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthenticationError {
    #[error("the bearer credential was refused")]
    Refused(FailedCheck),
    #[error("the selected Casework profile was refused")]
    Profile(FailedCheck),
    #[error("the verified identity is not a human session")]
    NotHuman(FailedCheck),
    #[error("the verified identity claims are invalid")]
    Claims(FailedCheck),
}

impl AuthenticationError {
    /// The check the request failed.
    #[must_use]
    pub const fn failed_check(self) -> FailedCheck {
        match self {
            Self::Refused(check)
            | Self::Profile(check)
            | Self::NotHuman(check)
            | Self::Claims(check) => check,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use chrono::Utc;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use registry_casework_core::{InboxPolicy, ProjectIdentity};
    use registry_platform_oidc::{AccessTokenAlgorithm, ActorKind, JwksFetcherConfig};
    use serde_json::json;

    const ISSUER: &str = "https://task-token.test";
    const AUDIENCE: &str = "urn:casework:test";
    const CLIENT: &str = "task-agent";
    const SECRET: &[u8] = b"01234567890123456789012345678901";

    #[tokio::test]
    async fn equivalent_profile_refusals_name_their_check_and_write_no_log_line() {
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
            label: None,
            description: None,
            principal_claim: "sub".into(),
            required_scopes: vec!["canary-private-scope".into()],
            acts_as: CaseworkActsAs::Staff,
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
            AuthenticationError::Profile(FailedCheck::AccessProfile)
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
                AuthenticationError::NotHuman(FailedCheck::ActorKind)
            );
        }
        // Recording belongs to the HTTP boundary, which counts and logs each
        // refusal once by its check. The authenticator writes nothing.
        let rendered = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(rendered.is_empty(), "{rendered}");
    }

    fn project() -> CaseworkProject {
        CaseworkProject {
            api_version: registry_casework_core::CASEWORK_API_VERSION.to_owned(),
            kind: registry_casework_core::CASEWORK_KIND.to_owned(),
            project: ProjectIdentity::new("task-grant-fixture".parse().unwrap(), "1".to_owned()),
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
        signed_token(claims)
    }

    fn signed_token(claims: Value) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test".to_owned());
        header.typ = Some("at+jwt".to_owned());
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(SECRET)).unwrap()
    }

    #[tokio::test]
    async fn separate_human_source_pair_uses_raw_subject_and_independent_source_client() {
        let mut project = project();
        project.access_profiles.push(AccessProfile {
            id: "staff".into(),
            label: None,
            description: None,
            principal_claim: "casework_principal".into(),
            required_scopes: vec!["casework-review".into()],
            acts_as: CaseworkActsAs::Staff,
        });
        let verifier = TokenVerifierConfig::access_token_profile(
            ISSUER,
            vec![AUDIENCE.into()],
            vec![Algorithm::HS256],
            vec!["at+jwt".into()],
        )
        .with_allowed_clients(vec![CLIENT.into()])
        .with_max_token_lifetime(Some(std::time::Duration::from_secs(600)));
        let auth = CaseworkAuthenticator::new(
            &project,
            verifier,
            keys(),
            HumanIdentityConfig {
                claim: "human_session".into(),
                value: "yes".into(),
            },
        )
        .with_human_source_audiences(BTreeMap::from([(
            "registry".into(),
            "urn:breg:source".into(),
        )]));
        let primary_claims = json!({"sub":"same-human", "casework_principal":"casework-alias", "client_id":CLIENT, "scope":"casework-review", "registry_actor_kind":"human", "human_session":"yes"});
        let source_claims = json!({"aud":"urn:breg:source", "sub":"same-human", "registry_principal":"source-alias", "client_id":"different-source-client", "scope":"source-only", "registry_actor_kind":"human", "human_session":"yes"});
        let primary = token(primary_claims.clone());
        let source = token(source_claims.clone());
        assert_eq!(
            auth.authenticate(&primary, "staff")
                .await
                .unwrap()
                .principal
                .subject,
            "casework-alias"
        );
        auth.verify_human_source_pair(&primary, &source, "registry")
            .await
            .expect("separate client and principal aliases do not alter verified raw sub");
        assert!(auth
            .verify_human_source_pair(&primary, &source, "unknown")
            .await
            .is_err());
        let now = Utc::now().timestamp();
        for patch in [
            json!({"sub":"another-human"}),
            json!({"sub":null}),
            json!({"sub":["same-human"]}),
            json!({"iss":"https://other.example.test"}),
            json!({"aud":AUDIENCE}),
            json!({"aud":["urn:breg:source"]}),
            json!({"aud":["urn:breg:source",AUDIENCE]}),
            json!({"registry_actor_kind":"service"}),
            json!({"registry_actor_kind":null}),
            json!({"human_session":"no"}),
            json!({"act":{"sub":"agent"}}),
            json!({"registry_grant_id":"grant"}),
            json!({"iat":now-7200,"exp":now-3600}),
            json!({"iat":now,"exp":now+1000}),
            json!({"nbf":now+3600}),
        ] {
            let mut claims = source_claims.clone();
            claims
                .as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            assert!(
                auth.verify_human_source_pair(&primary, &token(claims), "registry")
                    .await
                    .is_err(),
                "source mutation must fail"
            );
        }
        let mut array_primary = primary_claims.clone();
        array_primary["aud"] = json!([AUDIENCE]);
        assert!(auth
            .verify_human_source_pair(&token(array_primary), &source, "registry")
            .await
            .is_err());
        let mut other_primary = primary_claims.clone();
        other_primary["sub"] = json!("different-raw-sub");
        assert!(auth
            .verify_human_source_pair(&token(other_primary), &source, "registry")
            .await
            .is_err());
        // Same display principal cannot compensate for a different verified subject.
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test".into());
        header.typ = Some("at+jwt".into());
        let mut signed = source_claims.clone();
        signed["iss"] = json!(ISSUER);
        signed["iat"] = json!(now);
        signed["exp"] = json!(now + 300);
        let wrong_key = jsonwebtoken::encode(
            &header,
            &signed,
            &EncodingKey::from_secret(b"different-signing-key-not-trusted"),
        )
        .unwrap();
        assert!(auth
            .verify_human_source_pair(&primary, &wrong_key, "registry")
            .await
            .is_err());
        let mut disallowed = header.clone();
        disallowed.alg = Algorithm::HS512;
        let wrong_algorithm =
            jsonwebtoken::encode(&disallowed, &signed, &EncodingKey::from_secret(SECRET)).unwrap();
        assert!(auth
            .verify_human_source_pair(&primary, &wrong_algorithm, "registry")
            .await
            .is_err());
        header.typ = Some("JWT".into());
        let wrong_type =
            jsonwebtoken::encode(&header, &signed, &EncodingKey::from_secret(SECRET)).unwrap();
        assert!(auth
            .verify_human_source_pair(&primary, &wrong_type, "registry")
            .await
            .is_err());
        let mut auth = auth;
        auth.source_verifier_config
            .denied_kids
            .insert("test".into());
        let auth = auth.with_human_source_audiences(BTreeMap::from([(
            "registry".into(),
            "urn:breg:source".into(),
        )]));
        auth.authenticate(&primary, "staff")
            .await
            .expect("primary policy unchanged by source key refusal");
        assert!(auth
            .verify_human_source_pair(&primary, &source, "registry")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn separate_human_source_refusals_name_the_check_that_failed() {
        let auth = authenticator(BTreeMap::new()).with_human_source_audiences(BTreeMap::from([(
            "registry".into(),
            "urn:breg:source".into(),
        )]));
        let primary_claims = json!({"sub":"same-human", "client_id":CLIENT, "registry_actor_kind":"human", "human_session":"yes"});
        let source_claims = json!({"aud":"urn:breg:source", "sub":"same-human", "client_id":"source-client", "registry_actor_kind":"human", "human_session":"yes"});
        let primary = token(primary_claims.clone());
        let auth = {
            let mut auth = auth;
            auth.human_identity = HumanIdentityConfig {
                claim: "human_session".into(),
                value: "yes".into(),
            };
            auth
        };
        auth.verify_human_source_pair(&primary, &token(source_claims.clone()), "registry")
            .await
            .expect("the pair is the same human");
        assert_eq!(
            auth.verify_human_source_pair(&primary, &token(source_claims.clone()), "unknown")
                .await
                .unwrap_err(),
            AuthenticationError::Refused(FailedCheck::AccessProfile)
        );
        assert_eq!(
            auth.verify_human_source_pair(&primary, "not-a-token", "registry")
                .await
                .unwrap_err(),
            AuthenticationError::Refused(FailedCheck::CredentialMalformed)
        );
        for (patch, expected) in [
            (json!({"sub":"another-human"}), FailedCheck::TokenClaims),
            (json!({"aud":AUDIENCE}), FailedCheck::TokenAudience),
            (
                json!({"aud":["urn:breg:source"]}),
                FailedCheck::TokenAudience,
            ),
            (
                json!({"iss":"https://other.example.test"}),
                FailedCheck::TokenIssuer,
            ),
            (
                json!({"registry_actor_kind":"service"}),
                FailedCheck::ActorKind,
            ),
            (json!({"human_session":"no"}), FailedCheck::ActorKind),
            (json!({"act":{"sub":"agent"}}), FailedCheck::Delegation),
            (
                json!({"registry_grant_id":"grant"}),
                FailedCheck::TaskGrantClaims,
            ),
        ] {
            let mut claims = source_claims.clone();
            claims
                .as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            assert_eq!(
                auth.verify_human_source_pair(&primary, &token(claims), "registry")
                    .await
                    .unwrap_err(),
                AuthenticationError::Refused(expected),
                "{patch}"
            );
        }
    }

    #[tokio::test]
    async fn separate_human_source_refusals_never_log_credentials_or_subjects() {
        use tracing::instrument::WithSubscriber;
        #[derive(Clone)]
        struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, value: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(value);
                Ok(value.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = output.clone();
        let dispatch = tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .json()
                .without_time()
                .with_ansi(false)
                .with_writer(move || Capture(captured.clone()))
                .finish(),
        );
        let auth = authenticator(BTreeMap::new()).with_human_source_audiences(BTreeMap::from([(
            "registry".into(),
            "urn:breg:source".into(),
        )]));
        let primary = token(
            json!({"sub":"primary-human-canary", "client_id":CLIENT, "registry_actor_kind":"human"}),
        );
        let source = token(
            json!({"aud":"urn:breg:source", "sub":"different-source-human-canary", "client_id":"source-client-canary", "registry_actor_kind":"human"}),
        );
        assert!(auth
            .verify_human_source_pair(&primary, &source, "registry")
            .with_subscriber(dispatch)
            .await
            .is_err());
        let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        for canary in [
            primary.as_str(),
            source.as_str(),
            "primary-human-canary",
            "different-source-human-canary",
            "source-client-canary",
        ] {
            assert!(!logs.contains(canary));
        }
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
        assert_eq!(
            result.unwrap_err(),
            AuthenticationError::Refused(FailedCheck::TokenAssertionIssuer)
        );

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

    fn delegated_authenticator() -> CaseworkAuthenticator {
        let assertion_issuer = "https://people.example.test";
        let mut project = project();
        project.access_profiles.push(AccessProfile {
            id: "staff".into(),
            label: None,
            description: None,
            principal_claim: "sub".into(),
            required_scopes: vec!["casework:staff".into()],
            acts_as: CaseworkActsAs::Staff,
        });
        project.access_profiles.push(AccessProfile {
            id: "requester-overlap".into(),
            label: None,
            description: None,
            principal_claim: "sub".into(),
            required_scopes: vec!["casework:staff".into()],
            acts_as: CaseworkActsAs::Requester,
        });
        let verifier = TokenVerifierConfig::access_token_profile(
            ISSUER,
            vec![AUDIENCE.to_owned()],
            vec![Algorithm::HS256],
            vec!["at+jwt".to_owned()],
        )
        .with_scope_claim("scope")
        .with_allowed_clients(vec![CLIENT.to_owned()])
        .with_assertion_issuers(BTreeMap::from([(
            CLIENT.to_owned(),
            vec![assertion_issuer.to_owned()],
        )]));
        CaseworkAuthenticator::new(&project, verifier, keys(), HumanIdentityConfig::default())
            .with_delegated_staff_readers(BTreeMap::from([
                (
                    "staff-mcp".to_owned(),
                    crate::DelegatedStaffReaderConfig {
                        profile: "staff".to_owned(),
                        client: CLIENT.to_owned(),
                        actor_subject: "registry-mcp".to_owned(),
                        assertion_issuer: assertion_issuer.to_owned(),
                        required_scope: "casework:staff:delegated-read".to_owned(),
                        maximum_token_lifetime_seconds: 300,
                        source_profiles: vec!["review-agent".to_owned()],
                    },
                ),
                (
                    "other-reader".to_owned(),
                    crate::DelegatedStaffReaderConfig {
                        profile: "staff".to_owned(),
                        client: CLIENT.to_owned(),
                        actor_subject: "registry-mcp".to_owned(),
                        assertion_issuer: assertion_issuer.to_owned(),
                        required_scope: "casework:other-delegated-read".to_owned(),
                        maximum_token_lifetime_seconds: 300,
                        source_profiles: vec!["review-agent".to_owned()],
                    },
                ),
            ]))
    }

    fn delegated_token(mut claims: Value) -> String {
        let object = claims.as_object_mut().unwrap();
        object.entry("azp").or_insert(json!(CLIENT));
        object.entry("sub").or_insert(json!("officer-7"));
        object
            .entry("scope")
            .or_insert(json!("casework:staff casework:staff:delegated-read"));
        object
            .entry("registry_actor_kind")
            .or_insert(json!("human"));
        object
            .entry("registry_assertion_issuer")
            .or_insert(json!("https://people.example.test"));
        object.entry("act").or_insert(json!({
            "iss": ISSUER,
            "sub": "registry-mcp"
        }));
        token(claims)
    }

    #[tokio::test]
    async fn delegated_staff_read_is_separate_from_human_authentication() {
        let auth = delegated_authenticator();
        let credential = delegated_token(json!({}));
        let reader = auth
            .authenticate_staff_read(&credential, "staff-mcp", Some("review-agent"))
            .await
            .expect("the exact delegated reader is accepted");
        assert_eq!(reader.principal_for_test().subject, "officer-7");
        assert_eq!(
            auth.authenticate(&credential, "staff").await.unwrap_err(),
            AuthenticationError::Refused(FailedCheck::Delegation)
        );
        assert_eq!(
            auth.authenticate(&credential, "requester-overlap")
                .await
                .unwrap_err(),
            AuthenticationError::Refused(FailedCheck::Delegation)
        );
        let delegated_actor_without_reader_scope = delegated_token(json!({
            "scope": "casework:staff"
        }));
        assert_eq!(
            auth.authenticate(&delegated_actor_without_reader_scope, "requester-overlap")
                .await
                .unwrap_err(),
            AuthenticationError::Refused(FailedCheck::Delegation)
        );
        let second_policy = delegated_token(json!({
            "scope": "casework:staff casework:other-delegated-read"
        }));
        assert_eq!(
            auth.authenticate(&second_policy, "requester-overlap")
                .await
                .unwrap_err(),
            AuthenticationError::Refused(FailedCheck::Delegation)
        );
        let stripped = token(json!({
            "azp": CLIENT,
            "sub": "officer-7",
            "scope": "casework:staff casework:staff:delegated-read",
            "registry_actor_kind": "service"
        }));
        assert_eq!(
            auth.authenticate(&stripped, "requester-overlap")
                .await
                .unwrap_err(),
            AuthenticationError::Refused(FailedCheck::Scope)
        );
        let credential = delegated_token(json!({"aud": [AUDIENCE]}));
        auth.authenticate_staff_read(&credential, "staff-mcp", Some("review-agent"))
            .await
            .expect("one exact audience in the JWT array form is accepted");
    }

    #[tokio::test]
    async fn delegated_staff_read_refuses_changed_actor_scope_lifetime_and_source_profile() {
        let auth = delegated_authenticator();
        let now = Utc::now().timestamp();
        auth.authenticate_staff_read(
            &delegated_token(json!({
                "scope":"openid casework:staff casework:staff:delegated-read casework:unrelated"
            })),
            "staff-mcp",
            Some("review-agent"),
        )
        .await
        .expect("unrelated extra scopes grant no delegated route authority and are accepted");
        for (claims, expected) in [
            (
                json!({"act":{"iss":ISSUER,"sub":"other"}}),
                AuthenticationError::Refused(FailedCheck::Delegation),
            ),
            (
                json!({"act":{"iss":ISSUER,"sub":"registry-mcp","act":{"sub":"nested"}}}),
                AuthenticationError::Refused(FailedCheck::Delegation),
            ),
            (
                json!({"scope":"casework:staff:delegated-read"}),
                AuthenticationError::Profile(FailedCheck::Scope),
            ),
            (
                json!({"scope":"casework:staff"}),
                AuthenticationError::Profile(FailedCheck::Scope),
            ),
            (
                json!({"scope":"casework:staff casework:staff casework:staff:delegated-read"}),
                AuthenticationError::Profile(FailedCheck::Scope),
            ),
            (
                json!({"iat":now,"exp":now+301}),
                AuthenticationError::Refused(FailedCheck::TokenTime),
            ),
            (
                json!({"registry_grant_id":"not-allowed"}),
                AuthenticationError::Refused(FailedCheck::TaskGrantClaims),
            ),
            (
                json!({"aud":[AUDIENCE, AUDIENCE]}),
                AuthenticationError::Refused(FailedCheck::TokenAudience),
            ),
        ] {
            let credential = delegated_token(claims);
            assert_eq!(
                auth.authenticate_staff_read(&credential, "staff-mcp", Some("review-agent"))
                    .await
                    .unwrap_err(),
                expected
            );
        }
        let credential = delegated_token(json!({}));
        assert_eq!(
            auth.authenticate_staff_read(&credential, "staff-mcp", Some("other-source"))
                .await
                .unwrap_err(),
            AuthenticationError::Profile(FailedCheck::AccessProfile)
        );
    }

    #[tokio::test]
    async fn delegated_staff_reader_accepts_rfc_actor_and_rejects_actor_substitution() {
        let auth = delegated_authenticator();
        for act in [
            json!({"sub":"registry-mcp"}),
            json!({"iss":ISSUER,"sub":"registry-mcp"}),
            json!({"sub":"registry-mcp","client_id":"registry-mcp"}),
        ] {
            auth.authenticate_staff_read(
                &delegated_token(json!({"act":act})),
                "staff-mcp",
                Some("review-agent"),
            )
            .await
            .expect("the current actor is identified without requiring a nonstandard shape");
        }
        for act in [
            json!({"iss":"https://other-issuer.example.test","sub":"registry-mcp"}),
            json!({"sub":"other-gateway"}),
            json!({"sub":"registry-mcp","act":{"sub":"prior-gateway"}}),
        ] {
            assert_eq!(
                auth.authenticate_staff_read(
                    &delegated_token(json!({"act":act})),
                    "staff-mcp",
                    Some("review-agent"),
                )
                .await
                .unwrap_err(),
                AuthenticationError::Refused(FailedCheck::Delegation)
            );
        }
    }

    #[tokio::test]
    async fn delegated_staff_read_negative_cases_name_their_check_and_write_no_log_line() {
        use registry_platform_testing::CapturedDiagnosticLogs;
        use tracing::instrument::WithSubscriber;

        struct NegativeCase {
            name: &'static str,
            credential: String,
            policy: &'static str,
            source_profile: Option<&'static str>,
            expected_error: AuthenticationError,
            default_off: bool,
        }

        let now = Utc::now().timestamp();
        let without_act = token(json!({
            "azp": CLIENT,
            "sub": "canary-human-without-act",
            "scope": "casework:staff casework:staff:delegated-read",
            "registry_actor_kind": "human",
            "registry_assertion_issuer": "https://people.example.test"
        }));
        let missing_iat = signed_token(json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "azp": CLIENT,
            "sub": "canary-missing-iat",
            "exp": now + 300,
            "scope": "casework:staff casework:staff:delegated-read",
            "registry_actor_kind": "human",
            "registry_assertion_issuer": "https://people.example.test",
            "act": {"iss": ISSUER, "sub": "registry-mcp"}
        }));
        let cases = vec![
            NegativeCase {
                name: "human credential without delegated actor",
                credential: without_act,
                policy: "staff-mcp",
                source_profile: Some("review-agent"),
                expected_error: AuthenticationError::Refused(FailedCheck::Delegation),
                default_off: false,
            },
            NegativeCase {
                name: "wrong client",
                credential: delegated_token(json!({"azp": "canary-wrong-client"})),
                policy: "staff-mcp",
                source_profile: Some("review-agent"),
                expected_error: AuthenticationError::Refused(FailedCheck::TokenAssertionIssuer),
                default_off: false,
            },
            NegativeCase {
                name: "wrong assertion issuer",
                credential: delegated_token(json!({
                    "registry_assertion_issuer": "https://canary-wrong-assertion.example.test"
                })),
                policy: "staff-mcp",
                source_profile: Some("review-agent"),
                expected_error: AuthenticationError::Refused(FailedCheck::TokenAssertionIssuer),
                default_off: false,
            },
            NegativeCase {
                name: "non-human credential",
                credential: delegated_token(json!({"registry_actor_kind": "service"})),
                policy: "staff-mcp",
                source_profile: Some("review-agent"),
                expected_error: AuthenticationError::NotHuman(FailedCheck::ActorKind),
                default_off: false,
            },
            NegativeCase {
                name: "missing issued-at time",
                credential: missing_iat,
                policy: "staff-mcp",
                source_profile: Some("review-agent"),
                expected_error: AuthenticationError::Refused(FailedCheck::TokenTime),
                default_off: false,
            },
            NegativeCase {
                name: "unknown delegated reader policy",
                credential: delegated_token(json!({"sub": "canary-unknown-policy"})),
                policy: "canary-unknown-policy",
                source_profile: Some("review-agent"),
                expected_error: AuthenticationError::Profile(FailedCheck::AccessProfile),
                default_off: false,
            },
            NegativeCase {
                name: "unconfigured delegated reader",
                credential: delegated_token(json!({"sub": "canary-default-off"})),
                policy: "staff-mcp",
                source_profile: Some("review-agent"),
                expected_error: AuthenticationError::Profile(FailedCheck::AccessProfile),
                default_off: true,
            },
            NegativeCase {
                name: "unlisted source profile",
                credential: delegated_token(json!({"sub": "canary-source-profile"})),
                policy: "staff-mcp",
                source_profile: Some("canary-unlisted-source"),
                expected_error: AuthenticationError::Profile(FailedCheck::AccessProfile),
                default_off: false,
            },
        ];

        for case in cases {
            let mut auth = delegated_authenticator();
            if case.default_off {
                auth = auth.with_delegated_staff_readers(BTreeMap::new());
            }
            let captured = CapturedDiagnosticLogs::default();
            let result = auth
                .authenticate_staff_read(&case.credential, case.policy, case.source_profile)
                .with_subscriber(captured.subscriber())
                .await;
            assert_eq!(result.unwrap_err(), case.expected_error, "{}", case.name);
            // Recording belongs to the HTTP boundary. The authenticator
            // writes nothing, whatever the credential carries.
            assert_eq!(captured.text(), "", "{}", case.name);
        }
    }

    #[tokio::test]
    async fn compact_token_admission_refuses_a_malformed_token_as_malformed_and_writes_no_log_line()
    {
        use registry_platform_testing::{malformed_access_token_fixtures, CapturedDiagnosticLogs};
        use tracing::instrument::WithSubscriber;
        let captured = CapturedDiagnosticLogs::default();
        let subscriber = captured.subscriber();
        let tokens = malformed_access_token_fixtures();
        let auth = authenticator(BTreeMap::new());
        for _ in 0..3 {
            for token in &tokens {
                assert_eq!(
                    auth.authenticate(token, "requester")
                        .with_subscriber(subscriber.clone())
                        .await
                        .unwrap_err(),
                    AuthenticationError::Refused(FailedCheck::CredentialMalformed)
                );
                assert_eq!(
                    auth.authenticate_task_client(
                        token,
                        "casework:grants:status",
                        ActorKind::Service
                    )
                    .with_subscriber(subscriber.clone())
                    .await
                    .unwrap_err(),
                    AuthenticationError::Refused(FailedCheck::CredentialMalformed)
                );
            }
        }
        assert_eq!(captured.text(), "");
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
            .with_scope_claim("scope")
            .with_allowed_clients(vec![CLIENT.to_owned()]);
            let mut p = project();
            p.access_profiles.push(AccessProfile {
                id: "staff".into(),
                label: None,
                description: None,
                principal_claim: "sub".into(),
                required_scopes: vec!["casework:staff".into()],
                acts_as: CaseworkActsAs::Staff,
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
                |error| matches!(error, AuthenticationError::Refused(_)),
            )
            .await;
            // A valid symmetric JWT is outside the asymmetric production baseline.
            let token = self::token(
                json!({"azp":CLIENT,"scope":"casework:staff","registry_actor_kind":"human"}),
            );
            assert_eq!(
                auth.authenticate(&token, "staff").await.unwrap_err(),
                AuthenticationError::Refused(FailedCheck::TokenAlgorithm)
            );
            let mut wrong_actor = claims.clone();
            wrong_actor["registry_actor_kind"] = json!("canary-invalid-actor");
            let token = sign(wrong_actor, "at+jwt");
            assert_eq!(
                auth.authenticate(&token, "staff").await.unwrap_err(),
                AuthenticationError::NotHuman(FailedCheck::ActorKind)
            );
            let mut missing = claims.clone();
            missing["scope"] = json!("");
            let token = sign(missing, "at+jwt");
            assert_eq!(
                auth.authenticate(&token, "staff").await.unwrap_err(),
                AuthenticationError::Profile(FailedCheck::Scope)
            );
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Verified access-token ownership and exact deployment policy matching.
use crate::{store::Actor, PocError, Result};
use jsonwebtoken::Algorithm;
use registry_platform_config::{
    JwksSource, OidcClientsConfig, OidcIssuerConfig, SecretProvidersConfig,
};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{
    access_token_typ_set, fetch_discovery_with_policy, parse_static_jwks, JwksFetcher,
    JwksFetcherConfig, OidcDiscoveryConfig, TokenVerifier, TokenVerifierConfig,
    ASSERTION_ISSUER_CLAIM,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::BTreeSet, sync::Arc, time::Duration};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Start,
    Status,
    Inspect,
    RetrySame,
    Cancel,
    Reconcile,
    Doctor,
    RestoreHold,
    ReleaseRestoreHold,
    ReleaseAdmissionHold,
    CompleteExecutionRecovery,
    Retain,
}
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientPolicy {
    #[serde(deserialize_with = "crate::runtime::external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::ExternalId")
    )]
    pub client_id: String,
    #[serde(deserialize_with = "crate::runtime::unique_strings")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<registry_platform_yaml::ExternalId>",
            length(min = 1, max = 64)
        )
    )]
    pub required_scopes: Vec<String>,
    #[serde(deserialize_with = "crate::runtime::unique_strings")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<registry_platform_yaml::ExternalId>",
            length(min = 1, max = 64)
        )
    )]
    pub flows: Vec<String>,
    #[serde(deserialize_with = "unique_actions")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<Action>",
            length(min = 1, max = 12)
        )
    )]
    pub actions: Vec<Action>,
    #[serde(default)]
    pub operator: bool,
}
#[derive(Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessConfig {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuer"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub issuer: OidcIssuerConfig,
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-clients"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub clients: OidcClientsConfig,
    #[serde(default = "scope_claim")]
    #[serde(deserialize_with = "crate::runtime::external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::ExternalId")
    )]
    pub scope_claim: String,
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 64)))]
    pub policies: Vec<ClientPolicy>,
}
fn scope_claim() -> String {
    "registry_scopes".into()
}
impl AccessConfig {
    pub fn validate(&self, secrets: &SecretProvidersConfig, local: bool) -> Result<()> {
        self.findings(secrets, local)
            .into_iter()
            .next()
            .map_or(Ok(()), Err)
    }
    pub(crate) fn findings(&self, secrets: &SecretProvidersConfig, local: bool) -> Vec<PocError> {
        let mut errors = Vec::new();
        for result in [
            self.issuer.check("deployment.authentication", local),
            self.clients.check("deployment.authentication"),
        ] {
            if let Err(error) = result {
                errors.push(access_error(error.field(), &error.to_string()));
            }
        }
        if let Some(reference) = self.issuer.jwks_source.document_ref() {
            if let Err(error) = secrets.check_reference(
                "deployment.authentication.jwksSource.documentRef",
                reference,
            ) {
                errors.push(access_error(
                    error.field(),
                    "enable the provider named by the static JWKS document reference",
                ));
            }
        }
        if self.policies.is_empty() || self.policies.len() > 64 {
            errors.push(access_error(
                "deployment.authentication.policies",
                "declare one to sixty-four exact client policies",
            ));
        }
        if self.clients.allowed_clients.is_empty()
            || self.clients.allowed_clients.len() > 64
            || self
                .clients
                .allowed_clients
                .iter()
                .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
            || self
                .clients
                .allowed_clients
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.clients.allowed_clients.len()
        {
            errors.push(access_error("deployment.authentication.allowedClients", "list one to sixty-four distinct admitted client identities, each at most 128 bytes"));
        }
        if self.scope_claim.is_empty()
            || self.scope_claim.len() > 128
            || self.scope_claim.chars().any(char::is_control)
        {
            errors.push(access_error(
                "deployment.authentication.scopeClaim",
                "name one bounded scope claim without control characters",
            ));
        }
        let mut seen = BTreeSet::new();
        for (index, p) in self.policies.iter().enumerate() {
            let field = format!("deployment.authentication.policies.{index}");
            if !seen.insert(&p.client_id) || !self.clients.allowed_clients.contains(&p.client_id) {
                errors.push(access_error(
                    &format!("{field}.clientId"),
                    "name one admitted client exactly once",
                ));
            }
            if p.actions.is_empty()
                || p.actions.len() > 12
                || p.actions.iter().collect::<BTreeSet<_>>().len() != p.actions.len()
                || (!p.operator
                    && p.actions.iter().any(|a| {
                        matches!(
                            a,
                            Action::Doctor
                                | Action::RestoreHold
                                | Action::ReleaseRestoreHold
                                | Action::ReleaseAdmissionHold
                                | Action::CompleteExecutionRecovery
                                | Action::Retain
                        )
                    }))
            {
                errors.push(access_error(&format!("{field}.actions"), "list distinct authorized actions; recovery administration requires operator: true"));
            }
            if p.required_scopes.is_empty()
                || p.required_scopes.len() > 64
                || p.required_scopes.join(" ").len() > 1024
                || p.required_scopes
                    .iter()
                    .any(|s| !registry_platform_httputil::valid_scope_token(s))
                || p.required_scopes.iter().collect::<BTreeSet<_>>().len()
                    != p.required_scopes.len()
            {
                errors.push(access_error(&format!("{field}.requiredScopes"), "list one to sixty-four distinct OAuth scope tokens within the 1024-byte wire bound"));
            }
            if p.flows.is_empty()
                || p.flows.len() > 64
                || p.flows.iter().any(|f| !crate::definition::valid_name(f))
                || p.flows.iter().collect::<BTreeSet<_>>().len() != p.flows.len()
            {
                errors.push(access_error(
                    &format!("{field}.flows"),
                    "list one to sixty-four distinct exact workflow identifiers",
                ));
            }
        }
        errors
    }
    pub async fn authenticator(
        &self,
        secrets: &SecretProvidersConfig,
        local: bool,
    ) -> Result<Authenticator> {
        self.validate(secrets, local)?;
        let policy = if local {
            FetchUrlPolicy::dev()
        } else {
            FetchUrlPolicy::strict()
        };
        let keys = match &self.issuer.jwks_source {
            JwksSource::Static { document_ref } => {
                let value = secrets
                    .resolver()
                    .map_err(|_| refused())?
                    .resolve(document_ref)
                    .map_err(|_| refused())?;
                Arc::new(JwksFetcher::new_static(
                    parse_static_jwks(value.expose_secret()).map_err(|_| refused())?,
                    JwksFetcherConfig::defaults(),
                ))
            }
            source => {
                let uri = match source {
                    JwksSource::Uri { uri } => uri.clone(),
                    _ => {
                        fetch_discovery_with_policy(
                            &OidcDiscoveryConfig {
                                issuer: self.issuer.issuer.clone(),
                                jwks_uri_override: None,
                                discovery_timeout: Duration::from_secs(5),
                                max_doc_bytes: 1_048_576,
                            },
                            &policy,
                        )
                        .await
                        .map_err(|_| refused())?
                        .jwks_uri
                    }
                };
                Arc::new(JwksFetcher::new_with_fetch_url_policy(
                    uri,
                    JwksFetcherConfig::defaults(),
                    policy,
                ))
            }
        };
        keys.ensure_key_set().await.map_err(|_| refused())?;
        let profile = TokenVerifierConfig::access_token_profile(
            self.issuer.issuer.clone(),
            vec![self.issuer.audience.clone()],
            vec![Algorithm::RS256, Algorithm::ES256],
            access_token_typ_set("at+jwt"),
        )
        .with_scope_claim(&self.scope_claim)
        .with_allowed_clients(self.clients.allowed_clients.clone())
        .with_assertion_issuers(self.clients.assertion_issuers.clone())
        .with_max_token_lifetime(Some(Duration::from_secs(3600)));
        Ok(Authenticator::new(
            profile,
            keys,
            self.policies.clone(),
            !self.clients.assertion_issuers.is_empty(),
        ))
    }
}
pub struct Authenticator {
    verifier: TokenVerifier,
    policies: Vec<ClientPolicy>,
    assertion_issuers: bool,
}
pub struct Caller {
    pub actor: Actor,
    policy: ClientPolicy,
}
impl Caller {
    pub fn authorized_flows(&self, action: Action) -> Result<&[String]> {
        self.authorize(action, None)?;
        Ok(&self.policy.flows)
    }

    pub fn authorize(&self, action: Action, flow: Option<&str>) -> Result<()> {
        if !self.policy.actions.contains(&action)
            || flow.is_some_and(|flow| !self.policy.flows.iter().any(|f| f == flow))
        {
            return Err(PocError::new(
                "access.denied",
                "the caller policy does not authorize this operation",
            ));
        }
        Ok(())
    }
}
impl Authenticator {
    pub fn new(
        profile: TokenVerifierConfig,
        keys: Arc<JwksFetcher>,
        policies: Vec<ClientPolicy>,
        assertion_issuers: bool,
    ) -> Self {
        Self {
            verifier: TokenVerifier::new(profile, keys),
            policies,
            assertion_issuers,
        }
    }
    pub async fn authenticate(&self, token: &str) -> Result<Caller> {
        registry_platform_authcommon::validate_compact_access_token(token)
            .map_err(|_| unauthenticated())?;
        let verified = self.verifier.verify(token).await.map_err(|error| {
            use registry_platform_oidc::OidcError;
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
                | OidcError::ConflictingEndpointConfiguration => PocError::new(
                    "access.unavailable",
                    "the configured verifier cannot answer",
                ),
                _ => unauthenticated(),
            }
        })?;
        if !self.assertion_issuers && verified.claims.extra.contains_key(ASSERTION_ISSUER_CLAIM) {
            return Err(unauthenticated());
        }
        let client = verified
            .matched_client_id()
            .map_err(|_| unauthenticated())?
            .ok_or_else(unauthenticated)?;
        let issuer = verified
            .claims
            .iss
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(unauthenticated)?;
        let subject = verified
            .claims
            .sub
            .as_deref()
            .filter(|s| !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control))
            .ok_or_else(unauthenticated)?;
        let p = self
            .policies
            .iter()
            .find(|p| {
                p.client_id == client
                    && p.required_scopes
                        .iter()
                        .all(|s| verified.scopes.contains(s))
            })
            .ok_or_else(|| {
                PocError::new(
                    "access.denied",
                    "the caller policy does not authorize this operation",
                )
            })?;
        Ok(Caller {
            actor: Actor {
                issuer: issuer.into(),
                subject: subject.into(),
                client_id: client.into(),
                operator: p.operator,
            },
            policy: p.clone(),
        })
    }
}
fn refused() -> PocError {
    PocError::new(
        "access.configuration",
        "configure an exact OIDC issuer, admitted clients and one bounded policy per client",
    )
}
fn access_error(field: &str, advice: &str) -> PocError {
    PocError::new(
        "coordinator.access.configuration",
        "the access configuration was refused",
    )
    .at("runtime.yaml", crate::runtime::pointer(field))
    .suggest(advice)
}
fn unauthenticated() -> PocError {
    PocError::new(
        "access.unauthenticated",
        "a verified access token is required",
    )
}

fn unique_actions<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<Action>, D::Error> {
    registry_platform_yaml::UniqueList::<Action>::deserialize(d)
        .map(registry_platform_yaml::UniqueList::into_vec)
}

impl Serialize for AccessConfig {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("issuer", &self.issuer.issuer)?;
        map.serialize_entry("audience", &self.issuer.audience)?;
        map.serialize_entry("jwksSource", &self.issuer.jwks_source)?;
        map.serialize_entry("allowedClients", &self.clients.allowed_clients)?;
        if !self.clients.assertion_issuers.is_empty() {
            map.serialize_entry("assertionIssuers", &self.clients.assertion_issuers)?;
        }
        map.serialize_entry("scopeClaim", &self.scope_claim)?;
        map.serialize_entry("policies", &self.policies)?;
        map.end()
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Verified access-token ownership and exact deployment policy matching.
use crate::{store::Actor, CoordinatorError, Result};
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
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    ReviewCreate,
    ReviewRead,
    ReviewCancel,
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
impl Action {
    /// A deployment-wide action reaches every workflow the deployment serves at
    /// once. Only an operator takes it, and no workflow list scopes it.
    pub fn is_deployment_wide(self) -> bool {
        matches!(
            self,
            Action::Doctor
                | Action::RestoreHold
                | Action::ReleaseRestoreHold
                | Action::ReleaseAdmissionHold
                | Action::CompleteExecutionRecovery
                | Action::Retain
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_producer: Option<crate::review_provider::ReviewProducer>,
    #[serde(deserialize_with = "crate::runtime::unique_strings")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<registry_platform_yaml::ExternalId>",
            length(min = 1, max = 64)
        )
    )]
    pub required_scopes: Vec<String>,
    /// The workflows this policy's run actions reach: start, status, inspect,
    /// retry-same, cancel and reconcile. Required when the policy lists a run
    /// action and refused when it lists none.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "crate::runtime::unique_strings"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<registry_platform_yaml::ExternalId>",
            length(min = 1, max = 64)
        )
    )]
    pub workflows: Vec<String>,
    #[serde(deserialize_with = "unique_actions")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<Action>",
            length(min = 1, max = 15)
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
    /// Optional exchanged-token authority rules retain the shared OIDC checks.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "assertion_issuers"
    )]
    pub assertion_issuers: BTreeMap<String, Vec<String>>,
    #[serde(default = "scope_claim")]
    #[serde(deserialize_with = "crate::runtime::external")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::ExternalId")
    )]
    pub scope_claim: String,
    /// Exact verifier-established client IDs, within the trusted issuer.
    #[serde(deserialize_with = "client_policies")]
    #[cfg_attr(feature = "schema", schemars(with = "BTreeMap<registry_platform_yaml::ExternalId, ClientPolicy>", extend("minProperties" = 1, "maxProperties" = 64)))]
    pub policies: BTreeMap<String, ClientPolicy>,
}
fn client_policies<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<BTreeMap<String, ClientPolicy>, D::Error> {
    BTreeMap::<registry_platform_yaml::ExternalId, ClientPolicy>::deserialize(d).map(|map| {
        map.into_iter()
            .map(|(id, policy)| (id.into_string(), policy))
            .collect()
    })
}

fn assertion_issuers<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<BTreeMap<String, Vec<String>>, D::Error> {
    let map = BTreeMap::<
        registry_platform_yaml::ExternalId,
        registry_platform_yaml::UniqueList<registry_platform_yaml::ExternalId>,
    >::deserialize(d)?;
    if map.is_empty() || map.values().any(|issuers| issuers.is_empty()) {
        return Err(serde::de::Error::custom(
            registry_platform_yaml::Invalid::expected(
                "a non-empty map of client identities to non-empty issuer lists",
                "Omit assertionIssuers when no exchanged-token authority rules apply.",
            ),
        ));
    }
    Ok(map
        .into_iter()
        .map(|(client, issuers)| {
            (
                client.into_string(),
                issuers
                    .into_vec()
                    .into_iter()
                    .map(registry_platform_yaml::ExternalId::into_string)
                    .collect(),
            )
        })
        .collect())
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
    pub(crate) fn findings(
        &self,
        secrets: &SecretProvidersConfig,
        local: bool,
    ) -> Vec<CoordinatorError> {
        let mut errors = Vec::new();
        for result in [
            self.issuer.check("deployment.authentication", local),
            self.clients().check("deployment.authentication"),
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
        if self.scope_claim.is_empty()
            || self.scope_claim.len() > 128
            || self.scope_claim.chars().any(char::is_control)
        {
            errors.push(access_error(
                "deployment.authentication.scopeClaim",
                "name one bounded scope claim without control characters",
            ));
        }
        for (client, p) in &self.policies {
            let field = format!(
                "/deployment/authentication/policies/{}",
                client.replace('~', "~0").replace('/', "~1")
            );
            if client.is_empty() || client.len() > 128 || client.chars().any(char::is_control) {
                errors.push(access_error(
                    &field,
                    "use an exact client identity of at most 128 bytes without control characters",
                ));
            }
            if p.actions.is_empty()
                || p.actions.len() > 15
                || p.actions.iter().collect::<BTreeSet<_>>().len() != p.actions.len()
                || (!p.operator && p.actions.iter().any(|a| a.is_deployment_wide()))
            {
                errors.push(access_error(&format!("{field}/actions"), "list distinct authorized actions; recovery administration requires operator: true"));
            }
            let reviews = p.actions.iter().any(|action| {
                matches!(
                    action,
                    Action::ReviewCreate | Action::ReviewRead | Action::ReviewCancel
                )
            });
            if reviews != p.review_producer.is_some()
                || p.review_producer
                    .as_ref()
                    .is_some_and(|producer| !producer.check())
            {
                errors.push(access_error(&format!("{field}/reviewProducer"), "Review actions require an exact producer id, sourceNamespace, profile and nonempty distinct sources; omit reviewProducer for other actions"));
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
                errors.push(access_error(&format!("{field}/requiredScopes"), "list one to sixty-four distinct OAuth scope tokens within the 1024-byte wire bound"));
            }
            if !p.actions.iter().any(|a| !a.is_deployment_wide()) {
                if !p.workflows.is_empty() {
                    errors.push(access_error(
                        &format!("{field}/workflows"),
                        "remove workflows: it scopes only the run actions start, status, inspect, retry-same, cancel and reconcile, and deployment-wide actions reach every workflow",
                    ));
                }
            } else if p.workflows.is_empty()
                || p.workflows.len() > 64
                || p.workflows
                    .iter()
                    .any(|f| !crate::definition::valid_name(f))
                || p.workflows.iter().collect::<BTreeSet<_>>().len() != p.workflows.len()
            {
                errors.push(access_error(
                    &format!("{field}/workflows"),
                    "list one to sixty-four distinct exact workflow identifiers that this policy's run actions may reach",
                ));
            }
        }
        errors
    }
    /// The same policy keys supply closed verifier admission and policy lookup.
    fn clients(&self) -> OidcClientsConfig {
        OidcClientsConfig {
            allowed_clients: self.policies.keys().cloned().collect(),
            assertion_issuers: self.assertion_issuers.clone(),
        }
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
                    JwksSource::Uri { uri } => uri.to_string(),
                    _ => {
                        fetch_discovery_with_policy(
                            &OidcDiscoveryConfig {
                                issuer: self.issuer.issuer.to_string(),
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
        .with_allowed_clients(self.policies.keys().cloned().collect())
        .with_assertion_issuers(self.assertion_issuers.clone())
        .with_max_token_lifetime(Some(Duration::from_secs(3600)));
        Ok(Authenticator::new(
            profile,
            keys,
            self.policies.clone(),
            !self.assertion_issuers.is_empty(),
        ))
    }
}
pub struct Authenticator {
    verifier: TokenVerifier,
    policies: BTreeMap<String, ClientPolicy>,
    assertion_issuers: bool,
}
pub struct Caller {
    pub actor: Actor,
    policy: ClientPolicy,
}
impl Caller {
    pub(crate) fn review_producer(
        &self,
        profile: &str,
    ) -> Result<&crate::review_provider::ReviewProducer> {
        self.policy
            .review_producer
            .as_ref()
            .filter(|producer| producer.profile == profile)
            .ok_or_else(denied)
    }
    pub fn authorized_workflows(&self, action: Action) -> Result<&[String]> {
        self.authorize(action, None)?;
        Ok(&self.policy.workflows)
    }

    pub fn authorize(&self, action: Action, workflow: Option<&str>) -> Result<()> {
        if !self.policy.actions.contains(&action)
            || workflow.is_some_and(|workflow| !self.policy.workflows.iter().any(|f| f == workflow))
        {
            return Err(denied());
        }
        Ok(())
    }

    /// A deployment-wide action reaches every workflow this deployment serves,
    /// including workflows added after the policy was written. It is authorized
    /// by the listed action on an operator policy alone; `workflows` scopes run
    /// actions and plays no part here.
    pub fn authorize_deployment(&self, action: Action) -> Result<()> {
        if !action.is_deployment_wide()
            || !self.policy.operator
            || !self.policy.actions.contains(&action)
        {
            return Err(denied());
        }
        Ok(())
    }
}
fn denied() -> CoordinatorError {
    CoordinatorError::new(
        "access.denied",
        "the caller policy does not authorize this operation",
    )
}
impl Authenticator {
    pub fn new(
        profile: TokenVerifierConfig,
        keys: Arc<JwksFetcher>,
        policies: BTreeMap<String, ClientPolicy>,
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
                | OidcError::ConflictingEndpointConfiguration => CoordinatorError::new(
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
            .get(client)
            .filter(|p| {
                p.required_scopes
                    .iter()
                    .all(|s| verified.scopes.contains(s))
            })
            .ok_or_else(denied)?;
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
fn refused() -> CoordinatorError {
    CoordinatorError::new(
        "access.configuration",
        "configure an exact OIDC issuer, admitted clients and one bounded policy per client",
    )
}
fn access_error(field: &str, advice: &str) -> CoordinatorError {
    CoordinatorError::new(
        "coordinator.access.configuration",
        "the access configuration was refused",
    )
    .at("runtime.yaml", crate::runtime::pointer(field))
    .suggest(advice)
}
fn unauthenticated() -> CoordinatorError {
    CoordinatorError::new(
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
        if !self.assertion_issuers.is_empty() {
            map.serialize_entry("assertionIssuers", &self.assertion_issuers)?;
        }
        map.serialize_entry("scopeClaim", &self.scope_claim)?;
        map.serialize_entry("policies", &self.policies)?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(actions: Vec<Action>, workflows: &[&str], operator: bool) -> Caller {
        Caller {
            actor: Actor {
                issuer: "https://issuer.example".into(),
                subject: "subject".into(),
                client_id: "client".into(),
                operator,
            },
            policy: ClientPolicy {
                review_producer: None,
                required_scopes: vec!["coordinator:operate".into()],
                workflows: workflows
                    .iter()
                    .map(|workflow| (*workflow).to_owned())
                    .collect(),
                actions,
                operator,
            },
        }
    }

    #[test]
    fn deployment_wide_actions_need_an_operator_policy_listing_the_action_and_no_workflow() {
        let operator = caller(vec![Action::Doctor, Action::Retain], &[], true);
        operator.authorize_deployment(Action::Doctor).unwrap();
        operator.authorize_deployment(Action::Retain).unwrap();
        for refused in [Action::RestoreHold, Action::Status] {
            assert_eq!(
                operator.authorize_deployment(refused).unwrap_err().code,
                "access.denied"
            );
        }
        // Configuration refuses this policy; the route refuses it as well.
        let not_operator = caller(vec![Action::Doctor], &[], false);
        assert_eq!(
            not_operator
                .authorize_deployment(Action::Doctor)
                .unwrap_err()
                .code,
            "access.denied"
        );
        // Run actions keep their exact per-workflow check.
        let scoped = caller(vec![Action::Status, Action::Doctor], &["workflow-a"], true);
        scoped.authorize_deployment(Action::Doctor).unwrap();
        scoped
            .authorize(Action::Status, Some("workflow-a"))
            .unwrap();
        assert_eq!(
            scoped
                .authorize(Action::Status, Some("workflow-b"))
                .unwrap_err()
                .code,
            "access.denied"
        );
        assert_eq!(
            scoped.authorized_workflows(Action::Status).unwrap(),
            ["workflow-a"]
        );
    }
}

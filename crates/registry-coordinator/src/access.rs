// SPDX-License-Identifier: Apache-2.0
//! Verified access-token ownership and exact deployment policy matching.
use crate::{store::Actor, CoordinatorError, Result};
use registry_platform_authcommon::{DeclaredScope, FailedCheck};
use registry_platform_config::{
    AccessTokenType, Admitted, AdmittedClients, CallerIssuerCore, CallerIssuerEntry, CallerIssuers,
    ClientRule, JwksSource, OidcClientsConfig, PolicyClients, RuntimeFileCheck,
    SecretProvidersConfig,
};
use registry_platform_oidc::{
    fetch_discovery_for_issuer, parse_static_jwks, AccessTokenAlgorithm, CallerKind, ClaimNames,
    DeclaredKinds, IssuerEntry, IssuerNetworkPolicy, IssuerSet, JwksFetcher, JwksFetcherConfig,
    OidcDiscoveryConfig, OidcError, TokenVerifier, TokenVerifierConfig, ASSERTION_ISSUER_CLAIM,
};
use registry_platform_yaml::{escape_pointer_segment, Diagnostic, Related};
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
    /// The exact token `sub` values this policy admits, compared byte for
    /// byte as the issuer writes them: the client's own service-account
    /// subject, or the named operators an operator policy serves. Each is at
    /// most 512 bytes. A verified token from this client whose subject is not
    /// listed is refused, and the list has no unrestricted form.
    #[serde(deserialize_with = "crate::runtime::unique_strings")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<registry_platform_yaml::ExternalId>",
            length(min = 1, max = 64)
        )
    )]
    pub subjects: Vec<String>,
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
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuers"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub issuers: CallerIssuers<IssuerConfig>,
    /// Exact verifier-established client IDs.
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

const ISSUERS: &str = "/deployment/authentication/issuers";
const CLIENT_CONFLICT: &str = "platform.oidc.client-in-two-issuers";
const CLIENT_CONFLICT_ACTION: &str =
    "Admit each client through one issuer entry, so a client rule binds to one issuer.";

#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerConfig {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuer-core"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub core: CallerIssuerCore<PolicyClients>,
    #[serde(
        default,
        deserialize_with = "registry_platform_config::non_empty_assertion_issuers"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "registry_platform_config::assertion_issuers_schema")
    )]
    pub assertion_issuers: BTreeMap<String, Vec<String>>,
}

impl CallerIssuerEntry for IssuerConfig {
    type Clients = PolicyClients;

    fn core(&self) -> &CallerIssuerCore<Self::Clients> {
        &self.core
    }
}

impl AccessConfig {
    pub fn validate(&self, secrets: &SecretProvidersConfig) -> Result<()> {
        let diagnostics = self.issuer_diagnostics(secrets, None);
        if !diagnostics.is_empty() {
            return Err(CoordinatorError::from_diagnostics(&diagnostics));
        }
        self.findings().into_iter().next().map_or(Ok(()), Err)
    }

    pub(crate) fn findings(&self) -> Vec<CoordinatorError> {
        let mut errors = Vec::new();
        if self.policies.is_empty() || self.policies.len() > 64 {
            errors.push(access_error(
                "deployment.authentication.policies",
                "declare one to sixty-four exact client policies",
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
            if p.subjects.is_empty() || p.subjects.len() > 64 {
                errors.push(access_error(
                    &format!("{field}/subjects"),
                    "list one to sixty-four exact token subjects this client's tokens carry; the list has no unrestricted form because admission binds each policy to the identities it names",
                ));
            }
            if let Some(index) = p.subjects.iter().position(|s| !admitted_subject(s)) {
                errors.push(access_error(
                    &format!("{field}/subjects/{index}"),
                    "write each subject exactly as the issuer puts it in the token's sub claim, at most 512 bytes and without control characters",
                ));
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
    pub(crate) fn issuer_diagnostics(
        &self,
        secrets: &SecretProvidersConfig,
        file: Option<&RuntimeFileCheck<crate::runtime::RuntimeConfig>>,
    ) -> Vec<Diagnostic> {
        let mut diagnostics = file.map_or_else(
            || self.issuers.check(ISSUERS),
            |file| self.issuers.check_file(ISSUERS, file, crate::runtime::KIND),
        );
        let deferred = |path: &str| file.is_some_and(|file| file.defers_within(path));
        let entries: Vec<_> = self.issuers.iter().collect();
        let any_clients_deferred = entries
            .iter()
            .any(|(id, _)| deferred(&format!("{ISSUERS}/{id}/allowedClients")));
        let reading = entries
            .iter()
            .find(|(_, entry)| matches!(entry.core.allowed_clients, PolicyClients::FromPolicies));
        let mut product = Vec::new();
        for (id, entry) in &entries {
            let base = format!("{ISSUERS}/{id}");
            let clients_field = format!("{base}/allowedClients");
            let assertion_field = format!("{base}/assertionIssuers");
            let (clients, from_policies) = match entry.core.allowed_clients.admitted() {
                Admitted::FromPolicies => (self.policies.keys().cloned().collect(), true),
                Admitted::Listed(clients) => (clients.to_vec(), false),
                _ => continue,
            };
            let provider = &entry.core.provider;
            if let Err(error) = provider.check("issuerEntry") {
                let suffix = error
                    .field()
                    .strip_prefix("issuerEntry.")
                    .unwrap_or("issuer");
                let path = format!("{base}/{}", suffix.replace('.', "/"));
                if !deferred(&path) {
                    product.push(Diagnostic::error(
                        "coordinator.access.configuration",
                        path,
                        "the issuer configuration was refused",
                        error.to_string(),
                    ));
                }
            }
            let key_field = format!("{base}/jwksSource/documentRef");
            if let Some(reference) = provider.jwks_source.document_ref() {
                if !deferred(&key_field) && secrets.check_reference(&key_field, reference).is_err()
                {
                    product.push(Diagnostic::error(
                        "coordinator.access.configuration",
                        key_field,
                        "the static JWKS reference has no enabled provider",
                        "Enable the provider named by the static JWKS document reference.",
                    ));
                }
            }
            if !deferred(&clients_field) && !deferred(&assertion_field) {
                let config = OidcClientsConfig {
                    allowed_clients: clients.clone(),
                    assertion_issuers: entry.assertion_issuers.clone(),
                };
                if let Err(error) = config.check("issuerEntry") {
                    product.push(Diagnostic::error(
                        "coordinator.access.configuration",
                        assertion_field,
                        "the assertion issuer configuration was refused",
                        error.to_string(),
                    ));
                } else if config
                    .assertion_issuers
                    .keys()
                    .any(|client| !clients.contains(client))
                {
                    product.push(Diagnostic::error(
                        "coordinator.access.configuration",
                        assertion_field,
                        "assertionIssuers names a client this entry does not admit",
                        "Name only clients this entry admits through allowedClients.",
                    ));
                }
            }
            if from_policies {
                let audience = format!("{base}/audience");
                if !deferred(&clients_field)
                    && !deferred(&audience)
                    && !deferred(&format!("{base}/accessTokenType"))
                    && entry.core.access_token_type.get() == &AccessTokenType::Jwt
                    && clients.contains(&provider.audience)
                {
                    product.push(Diagnostic::error(
                        "platform.oidc.audience-is-a-client", audience,
                        "with accessTokenType JWT the audience is also one of the entry's clients",
                        "Use an audience that names this service and no client, so an ID token issued to a client is not read as an access token.",
                    ));
                }
                if let Some(kinds) = &entry.core.client_actor_kinds {
                    for client in kinds
                        .get()
                        .0
                        .keys()
                        .filter(|client| !self.policies.contains_key(client.as_str()))
                    {
                        let path = format!(
                            "{base}/clientActorKinds/{}",
                            escape_pointer_segment(client.as_str())
                        );
                        if !deferred(&clients_field) && !deferred(&path) {
                            product.push(Diagnostic::error(
                                "platform.oidc.actor-kind-for-unadmitted-client", path,
                                "clientActorKinds names a client this entry does not admit",
                                "Name only clients listed in allowedClients, or add the client to allowedClients.",
                            ));
                        }
                    }
                }
            } else if let Some((reading, _)) = reading.filter(|(reading, _)| {
                !deferred(&clients_field)
                    && !deferred(&format!("{ISSUERS}/{reading}/allowedClients"))
            }) {
                let mut diagnostic = Diagnostic::error(
                    "coordinator.access.listed-clients-without-policy",
                    &clients_field,
                    format!("the entry {reading} already admits every client with a policy"),
                    "Use from-policies on its own, or list clients explicitly in every issuer entry.",
                );
                diagnostic.related.push(related(
                    format!("{ISSUERS}/{reading}/allowedClients"),
                    format!("the entry {reading} reads its clients from the policies"),
                ));
                product.push(diagnostic);
                for (index, _) in clients
                    .iter()
                    .enumerate()
                    .filter(|(_, client)| self.policies.contains_key(*client))
                {
                    let mut diagnostic = Diagnostic::error(
                        CLIENT_CONFLICT,
                        format!("{clients_field}/{index}"),
                        format!("the client is already admitted by the entry {reading}"),
                        CLIENT_CONFLICT_ACTION,
                    );
                    diagnostic.related.push(related(
                        format!("{ISSUERS}/{reading}/allowedClients"),
                        format!("the entry {reading} reads its clients from the policies"),
                    ));
                    product.push(diagnostic);
                }
            }
        }
        if reading.is_none() && !any_clients_deferred {
            for client in self.policies.keys().filter(|client| {
                !entries.iter().any(|(_, entry)| {
                    matches!(entry.core.allowed_clients.admitted(), Admitted::Listed(list) if list.contains(client))
                })
            }) {
                let mut diagnostic = Diagnostic::error(
                    "coordinator.access.policy-client-not-allowed",
                    format!("/deployment/authentication/policies/{}", escape_pointer_segment(client)),
                    "the policy's client is not admitted by any issuer entry",
                    "List the policy's client in one issuer entry's allowedClients.",
                );
                diagnostic.related.extend(entries.iter().map(|(id, _)| related(
                    format!("{ISSUERS}/{id}/allowedClients"),
                    format!("the entry {id} lists the clients it admits"),
                )));
                product.push(diagnostic);
            }
        }
        for diagnostic in product {
            if let Some(file) = file {
                let mut positioned = file.error_at(
                    crate::runtime::KIND,
                    &diagnostic.code,
                    &diagnostic.path,
                    diagnostic.message,
                    diagnostic.suggested_action,
                );
                for related in diagnostic.related {
                    file.add_related_at(&mut positioned, &related.path, related.message);
                }
                diagnostics.push(positioned);
            } else {
                diagnostics.push(diagnostic);
            }
        }
        diagnostics
    }

    pub(crate) fn clients_for(&self, issuer: &IssuerConfig) -> Vec<String> {
        match &issuer.core.allowed_clients {
            PolicyClients::FromPolicies => self.policies.keys().cloned().collect(),
            PolicyClients::Listed(clients) => clients.clone(),
        }
    }

    pub async fn authenticator(&self, secrets: &SecretProvidersConfig) -> Result<Authenticator> {
        self.validate(secrets)?;
        let mut entries = Vec::new();
        for (id, entry) in self.issuers.iter() {
            let resolved = if matches!(entry.core.allowed_clients, PolicyClients::FromPolicies) {
                Some(AdmittedClients::new(self.clients_for(entry)).ok_or_else(refused)?)
            } else {
                None
            };
            let profile = TokenVerifierConfig::for_caller_issuer(
                &entry.core,
                vec![
                    AccessTokenAlgorithm::RS256.to_jsonwebtoken(),
                    AccessTokenAlgorithm::ES256.to_jsonwebtoken(),
                ],
                resolved.as_ref(),
            )
            .map_err(|error| CoordinatorError::new("access.configuration", error.to_string()))?
            .with_assertion_issuers(entry.assertion_issuers.clone())
            .with_max_token_lifetime(Some(Duration::from_secs(3600)));
            let scope_claim = profile.scope_claim.clone();
            let keys = entry.keys(secrets).await?;
            keys.ensure_key_set().await.map_err(|_| refused())?;
            let declared = DeclaredKinds::from_core(&entry.core).map_err(|error| {
                CoordinatorError::new("access.configuration", error.to_string())
            })?;
            entries.push((
                IssuerEntry::new(id.as_str(), TokenVerifier::new(profile, keys), declared),
                scope_claim,
                !entry.assertion_issuers.is_empty(),
            ));
        }
        Authenticator::new(entries, self.policies.clone())
    }
}

fn related(path: String, message: String) -> Related {
    Related {
        file: String::new(),
        line: None,
        column: None,
        path,
        message,
    }
}

impl IssuerConfig {
    async fn keys(&self, secrets: &SecretProvidersConfig) -> Result<Arc<JwksFetcher>> {
        let issuer = &self.core.provider;
        let network = IssuerNetworkPolicy::new(issuer.issuer.as_str(), issuer.allow_insecure_http)
            .map_err(|_| refused())?;
        let keys = match &issuer.jwks_source {
            JwksSource::Static { document_ref } | JwksSource::TestIssuer { document_ref } => {
                let value = secrets
                    .resolver()
                    .map_err(|_| refused())?
                    .resolve(document_ref)
                    .map_err(|_| refused())?;
                Arc::new(JwksFetcher::new_static(
                    parse_static_jwks(value.expose_secret()).map_err(|error| match error {
                        // The text names the rule broken, and the key's position for a rule about
                        // one key, never key material.
                        OidcError::StaticKeySet(_) => CoordinatorError::new(
                            "access.configuration",
                            error.to_string(),
                        )
                        .suggest(
                            "Correct the document that deployment.authentication.issuers.ISSUER_ID.jwksSource.documentRef names.",
                        ),
                        _ => refused(),
                    })?,
                    JwksFetcherConfig::defaults(),
                ))
            }
            source => {
                let uri = match source {
                    JwksSource::Uri { uri } => uri.to_string(),
                    _ => {
                        let (document, policy) = fetch_discovery_for_issuer(
                            &OidcDiscoveryConfig {
                                issuer: issuer.issuer.to_string(),
                                jwks_uri_override: None,
                                discovery_timeout: Duration::from_secs(5),
                                max_doc_bytes: 1_048_576,
                            },
                            issuer.allow_insecure_http,
                        )
                        .await
                        .map_err(|_| refused())?;
                        return Ok(Arc::new(JwksFetcher::new_with_fetch_url_policy(
                            document.jwks_uri,
                            JwksFetcherConfig::defaults(),
                            policy,
                        )));
                    }
                };
                let policy = network.declared_jwks_fetch_policy();
                Arc::new(JwksFetcher::new_with_fetch_url_policy(
                    uri,
                    JwksFetcherConfig::defaults(),
                    policy,
                ))
            }
        };
        Ok(keys)
    }
}

pub struct Authenticator {
    issuers: IssuerSet,
    policies: BTreeMap<String, ClientPolicy>,
    settings: BTreeMap<Arc<str>, IssuerSettings>,
}

struct IssuerSettings {
    scope_claim: String,
    assertion_issuers: bool,
}
pub struct Caller {
    pub actor: Actor,
    pub kind: CallerKind,
    policy: ClientPolicy,
}
impl Caller {
    pub fn authorized_workflows(&self, action: Action) -> Result<&[String]> {
        self.authorize(action, None)?;
        Ok(&self.policy.workflows)
    }

    pub fn authorize(&self, action: Action, workflow: Option<&str>) -> Result<()> {
        if !self.policy.actions.contains(&action)
            || workflow.is_some_and(|workflow| !self.policy.workflows.iter().any(|f| f == workflow))
        {
            return Err(denied(FailedCheck::Operation));
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
            return Err(denied(FailedCheck::Operation));
        }
        Ok(())
    }
}
/// A resolved caller for tests that need no token: the policy lists
/// `actions` on `workflows`.
#[cfg(test)]
pub(crate) fn synthetic_caller(actions: Vec<Action>, workflows: &[&str], operator: bool) -> Caller {
    Caller {
        kind: CallerKind::Unspecified,
        actor: Actor {
            issuer: "https://issuer.example".into(),
            subject: "subject".into(),
            client_id: "client".into(),
            operator,
        },
        policy: ClientPolicy {
            subjects: vec!["subject".into()],
            required_scopes: vec!["coordinator:operate".into()],
            workflows: workflows.iter().map(|w| (*w).to_owned()).collect(),
            actions,
            operator,
        },
    }
}
fn denied(check: FailedCheck) -> CoordinatorError {
    CoordinatorError::new(
        "access.denied",
        "the caller policy does not authorize this operation",
    )
    .failing(check)
}
/// The bound admission puts on a token subject, and so on every subject a
/// policy may list: non-empty, at most 512 bytes, no control characters.
fn admitted_subject(subject: &str) -> bool {
    !subject.is_empty() && subject.len() <= 512 && !subject.chars().any(char::is_control)
}
fn is_key_source_unavailable(error: &OidcError) -> bool {
    // Preserve Coordinator's service-unavailable boundary for verification errors.
    matches!(
        error,
        OidcError::Transport(_)
            | OidcError::BoundedRead(_)
            | OidcError::FetchUrl(_)
            | OidcError::HttpStatus(_)
            | OidcError::InvalidUrl
            | OidcError::Parse
            | OidcError::InvalidJwk
            | OidcError::EmptyKeySet
            | OidcError::MissingIssuer
            | OidcError::ConflictingEndpointConfiguration
    )
}

fn verification_error(refusal: registry_platform_oidc::CallerRefusal) -> CoordinatorError {
    if is_key_source_unavailable(&refusal.error) {
        CoordinatorError::new(
            "access.unavailable",
            "the configured verifier cannot answer",
        )
        .failing(FailedCheck::KeySourceUnavailable)
    } else {
        unauthenticated(refusal.failed_check()).with_remedy(refusal.remedy)
    }
}

impl Authenticator {
    pub fn new(
        entries: Vec<(IssuerEntry, String, bool)>,
        policies: BTreeMap<String, ClientPolicy>,
    ) -> Result<Self> {
        let mut settings = BTreeMap::new();
        let mut verifiers = Vec::with_capacity(entries.len());
        for (entry, scope_claim, assertion_issuers) in entries {
            if settings
                .insert(
                    Arc::clone(&entry.id),
                    IssuerSettings {
                        scope_claim,
                        assertion_issuers,
                    },
                )
                .is_some()
            {
                return Err(CoordinatorError::new(
                    "access.configuration",
                    format!("two issuer entries share the id {}", entry.id),
                ));
            }
            verifiers.push(entry);
        }
        let issuers = IssuerSet::new(verifiers, ClaimNames::default())
            .map_err(|error| CoordinatorError::new("access.configuration", error.to_string()))?;
        Ok(Self {
            issuers,
            policies,
            settings,
        })
    }
    pub async fn authenticate(&self, token: &str) -> Result<Caller> {
        registry_platform_authcommon::validate_compact_access_token(token)
            .map_err(|_| unauthenticated(FailedCheck::CredentialMalformed))?;
        let caller = self
            .issuers
            .verify(token)
            .await
            .map_err(verification_error)?;
        let settings = self.settings.get(&caller.issuer_id).ok_or_else(refused)?;
        let verified = caller.token;
        if !settings.assertion_issuers && verified.claims.extra.contains_key(ASSERTION_ISSUER_CLAIM)
        {
            return Err(unauthenticated(FailedCheck::TokenAssertionIssuer));
        }
        let client = verified
            .matched_client_id()
            .map_err(|_| unauthenticated(FailedCheck::TokenClient))?
            .ok_or_else(|| unauthenticated(FailedCheck::TokenClient))?;
        let issuer = verified
            .claims
            .iss
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| unauthenticated(FailedCheck::TokenClaims))?;
        let subject = verified
            .claims
            .sub
            .as_deref()
            .filter(|s| admitted_subject(s))
            .ok_or_else(|| unauthenticated(FailedCheck::TokenClaims))?;
        // A token carrying `act` was issued for someone other than the client
        // that presents it, typically a person delegated to that client. The
        // Coordinator admits only a client's own identities.
        if verified.claims.extra.contains_key("act") {
            return Err(denied(FailedCheck::Delegation));
        }
        let p = self
            .policies
            .get(client)
            .filter(|p| p.subjects.iter().any(|s| s == subject))
            .ok_or_else(|| denied(FailedCheck::AccessProfile))?;
        if let Some(missing) = p
            .required_scopes
            .iter()
            .find(|s| !verified.scopes.contains(s))
        {
            return Err(denied(FailedCheck::Scope).declaring(
                DeclaredScope::new(&settings.scope_claim).with_required_scope(missing),
            ));
        }
        Ok(Caller {
            kind: caller.kind,
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
pub(crate) fn unauthenticated(check: FailedCheck) -> CoordinatorError {
    CoordinatorError::new(
        "access.unauthenticated",
        "a verified access token is required",
    )
    .failing(check)
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
        let issuers: BTreeMap<_, _> = self
            .issuers
            .iter()
            .map(|(id, entry)| (id.as_str(), entry))
            .collect();
        map.serialize_entry("issuers", &issuers)?;
        map.serialize_entry("policies", &self.policies)?;
        map.end()
    }
}

impl Serialize for IssuerConfig {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let core = &self.core;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("issuer", &core.provider.issuer)?;
        map.serialize_entry("audience", &core.provider.audience)?;
        map.serialize_entry("jwksSource", &core.provider.jwks_source)?;
        if core.provider.allow_insecure_http {
            map.serialize_entry("allowInsecureHttp", &true)?;
        }
        if core.access_token_type.get() != &AccessTokenType::AtJwt {
            map.serialize_entry("accessTokenType", &core.access_token_type)?;
        }
        if core.scope_claim.get().as_str() != "scope" {
            map.serialize_entry("scopeClaim", &core.scope_claim)?;
        }
        map.serialize_entry("allowedClients", &core.allowed_clients)?;
        if let Some(kind) = &core.actor_kind {
            map.serialize_entry("actorKind", kind)?;
        }
        if let Some(kinds) = &core.client_actor_kinds {
            map.serialize_entry("clientActorKinds", kinds)?;
        }
        if !self.assertion_issuers.is_empty() {
            map.serialize_entry("assertionIssuers", &self.assertion_issuers)?;
        }
        map.end()
    }
}

#[cfg(test)]
mod token_characterisation;

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(actions: Vec<Action>, workflows: &[&str], operator: bool) -> Caller {
        synthetic_caller(actions, workflows, operator)
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

    #[test]
    fn a_policy_denial_after_authentication_names_the_operation_check() {
        let scoped = caller(vec![Action::Status, Action::Doctor], &["workflow-a"], true);
        let not_operator = caller(vec![Action::Doctor], &[], false);
        for denial in [
            scoped.authorize(Action::Start, Some("workflow-a")),
            scoped.authorize(Action::Status, Some("workflow-b")),
            scoped.authorized_workflows(Action::Start).map(|_| ()),
            scoped.authorize_deployment(Action::Status),
            not_operator.authorize_deployment(Action::Doctor),
        ] {
            let denial = denial.unwrap_err();
            assert_eq!(denial.code, "access.denied");
            assert_eq!(denial.check, Some(FailedCheck::Operation));
        }
    }
}

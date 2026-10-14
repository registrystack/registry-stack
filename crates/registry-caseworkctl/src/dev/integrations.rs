//! Explicit provider connections and optional shared issuer authority for local development.
use super::{config, private, State};
use anyhow::{bail, Context, Result};
use registry_casework_core::{typed, CaseworkProject, ConfigFinding};
use registry_thunderid_tooling::{description::*, local};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Integrations {
    /// Audience accepted by this Casework session.
    pub resource: String,
    /// Optional provider connections keyed by their declared deploymentRef.
    #[serde(
        default,
        deserialize_with = "typed::local_id_keys",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BTreeMap<registry_platform_yaml::LocalId, ContextProviderBinding>")
    )]
    pub context_providers: BTreeMap<String, ContextProviderBinding>,
    /// Owner-only files copied into the retained private secret root.
    #[serde(
        default,
        deserialize_with = "typed::local_id_keys",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BTreeMap<registry_platform_yaml::LocalId, PathBuf>")
    )]
    pub secret_files: BTreeMap<String, PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_clients: Vec<ServiceClient>,
    /// Interactive OAuth clients explicitly admitted from a borrowed issuer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub browser_clients: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_authority: Option<TaskAuthority>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ServiceClient {
    #[serde(deserialize_with = "typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    /// Omission means this Casework session's generated audience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    pub scopes: Vec<String>,
    /// Token claims of at most 256 bytes each, written as text.
    #[serde(
        default,
        deserialize_with = "typed::external_id_keys",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BTreeMap<registry_platform_yaml::ExternalId, String>")
    )]
    pub claims: BTreeMap<String, String>,
    #[serde(default)]
    pub task_exchange: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TaskAuthority {
    /// Logical issuer, independent of the local API transport URL; an
    /// `https` URL.
    #[serde(deserialize_with = "typed::url")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub issuer: String,
    /// Public-key-only listener, reachable from the stock issuer container.
    #[serde(deserialize_with = "typed::bounded_u16::<_, 1, 65_535>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, 65_535>")
    )]
    pub jwks_port: u16,
    #[serde(deserialize_with = "typed::local_id_keys")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BTreeMap<registry_platform_yaml::LocalId, String>")
    )]
    pub status_clients: BTreeMap<String, String>,
}

use registry_casework_breg::BregBinding as ContextProviderBinding;

const SERVICE_SCOPE_MESSAGE: &str =
    "expected an RFC 6749 scope-token of 1 to 128 bytes without '*': printable ASCII without space, '\"', or '\\'";

impl Integrations {
    /// Every finding of the integrations block against the clients beside it
    /// and the authored project, placed below `/integrations`.
    pub(super) fn validate(
        &self,
        clients: &config::Clients,
        policy: &CaseworkProject,
    ) -> Result<(), Vec<ConfigFinding>> {
        let mut found = Vec::new();
        if !registry_platform_httputil::valid_resource_uri(&self.resource) {
            found.push(ConfigFinding::new(
                "casework.dev-clients.invalid-resource",
                "/integrations/resource",
                "expected an absolute URI naming the audience this Casework session accepts",
                "Write the Casework audience as a URI, such as urn:casework:dev.",
            ));
        }
        let declared = policy
            .context_providers
            .iter()
            .map(|provider| &provider.deployment_ref)
            .collect::<BTreeSet<_>>();
        if self
            .context_providers
            .keys()
            .any(|key| !declared.contains(key))
        {
            found.push(ConfigFinding::new(
                "casework.dev-clients.provider-bindings-mismatch",
                "/integrations/contextProviders",
                "expected each connection key to name a declared provider deploymentRef",
                "Use the context provider deploymentRef as its connection key.",
            ));
        }
        for (key, length, maximum, what) in [
            ("secretFiles", self.secret_files.len(), 64, "secret files"),
            (
                "serviceClients",
                self.service_clients.len(),
                32,
                "service clients",
            ),
            (
                "browserClients",
                self.browser_clients.len(),
                8,
                "browser clients",
            ),
        ] {
            if length > maximum {
                found.push(ConfigFinding::new(
                    "casework.dev-clients.too-many-integrations",
                    format!("/integrations/{key}"),
                    format!("expected at most {maximum} {what}"),
                    format!("Keep at most {maximum} {what}."),
                ));
            }
        }
        for (name, path) in &self.secret_files {
            if !config::identifier(name) || !path.is_absolute() {
                found.push(ConfigFinding::new(
                    "casework.dev-clients.invalid-secret-file",
                    config::member("/integrations/secretFiles", name),
                    "expected a lowercase identifier and the absolute path of an owner-only file",
                    "Name the secret and write its absolute owner-only file path.",
                ));
            }
        }
        let mut ids = config::FirstSeen::default();
        for (index, client) in clients.clients.iter().enumerate() {
            ids.repeat(&client.id, &format!("/clients/{index}/id"));
        }
        for (index, client) in self.service_clients.iter().enumerate() {
            let at = format!("/integrations/serviceClients/{index}");
            client_id(&mut found, &mut ids, &client.id, &format!("{at}/id"));
            config::scope_findings(
                &mut found,
                &format!("{at}/scopes"),
                &client.scopes,
                128,
                SERVICE_SCOPE_MESSAGE,
            );
            if client.scopes.iter().any(|scope| scope.contains('*')) {
                found.push(ConfigFinding::new(
                    "casework.dev-clients.invalid-scope",
                    format!("{at}/scopes"),
                    SERVICE_SCOPE_MESSAGE,
                    "Write each scope exactly, without a wildcard.",
                ));
            }
            if client
                .resource
                .as_ref()
                .is_some_and(|resource| !registry_platform_httputil::valid_resource_uri(resource))
            {
                found.push(ConfigFinding::new(
                    "casework.dev-clients.invalid-resource",
                    format!("{at}/resource"),
                    "expected an absolute URI",
                    "Write the resource as a URI, or leave it out for this session's Casework audience.",
                ));
            }
            if client.claims.contains_key(config::HUMAN_CLAIM) {
                found.push(ConfigFinding::new(
                    "casework.dev-clients.service-client-human-claim",
                    config::member(&format!("{at}/claims"), config::HUMAN_CLAIM),
                    "a service client is a calling system, so it may not choose registry_actor_kind",
                    "Remove registry_actor_kind from this service client's claims.",
                ));
            }
            if client.task_exchange
                && (self.task_authority.is_none()
                    || client.resource.is_some()
                    || client.scopes != ["casework:grants:assert"])
            {
                found.push(ConfigFinding::new(
                    "casework.dev-clients.invalid-task-exchange",
                    format!("{at}/taskExchange"),
                    "a task-exchange client needs a taskAuthority, no resource, and exactly the scope casework:grants:assert",
                    "Declare taskAuthority, leave resource out, and write scopes: [casework:grants:assert].",
                ));
            }
        }
        for (index, id) in self.browser_clients.iter().enumerate() {
            client_id(
                &mut found,
                &mut ids,
                id,
                &format!("/integrations/browserClients/{index}"),
            );
        }
        if !policy.task_templates.is_empty() && self.task_authority.is_none() {
            found.push(ConfigFinding::new(
                "casework.dev-clients.missing-task-authority",
                "/integrations/taskAuthority",
                "casework.yaml declares task templates, which need a local taskAuthority",
                "Add taskAuthority with an issuer, a jwksPort, and its statusClients.",
            ));
        }
        if let Some(authority) = &self.task_authority {
            if !authority.issuer.starts_with("https://") {
                found.push(ConfigFinding::new(
                    "casework.dev-clients.invalid-task-authority-issuer",
                    "/integrations/taskAuthority/issuer",
                    "expected an https URL",
                    "Write the logical issuer as an https URL, such as https://casework.local.example.",
                ));
            }
            if authority.status_clients.len() > 32 {
                found.push(ConfigFinding::new(
                    "casework.dev-clients.too-many-integrations",
                    "/integrations/taskAuthority/statusClients",
                    "expected at most 32 status clients",
                    "Keep at most 32 status clients.",
                ));
            }
            for (id, resource) in &authority.status_clients {
                let exact = self.service_clients.iter().any(|client| {
                    &client.id == id
                        && !client.task_exchange
                        && client.resource.is_none()
                        && client.scopes == ["casework:grants:status"]
                });
                if !registry_platform_httputil::valid_resource_uri(resource) || !exact {
                    found.push(ConfigFinding::new(
                        "casework.dev-clients.invalid-status-client",
                        config::member("/integrations/taskAuthority/statusClients", id),
                        "expected a resource URI, keyed by a service client with exactly the scope casework:grants:status, no resource, and no taskExchange",
                        "Key the entry by such a service client and write its resource as a URI.",
                    ));
                }
            }
            for (index, template) in policy.task_templates.iter().enumerate() {
                if !self
                    .service_clients
                    .iter()
                    .any(|client| client.id == template.client && client.task_exchange)
                {
                    found.push(ConfigFinding::new(
                        "casework.dev-clients.missing-task-exchange-client",
                        "/integrations/serviceClients",
                        format!("no task-exchange service client is the client of the task template casework.yaml declares at /taskTemplates/{index}"),
                        "Declare that client under serviceClients with taskExchange: true.",
                    ));
                }
            }
        }
        if found.is_empty() {
            Ok(())
        } else {
            Err(found)
        }
    }

    pub(super) fn validate_session(&self, state: &State, policy: &CaseworkProject) -> Result<()> {
        let owner_instance = if policy.task_templates.is_empty() {
            None
        } else {
            super::borrowed_issuer(state)?
                .map(|owner_root| -> Result<String> {
                    let owner: Value = serde_json::from_slice(&private::read(
                        &owner_root.join("state.json"),
                        super::MAX_BYTES,
                    )?)?;
                    Ok(owner["instanceId"]
                        .as_str()
                        .filter(|id| !id.is_empty())
                        .ok_or_else(|| anyhow::anyhow!("shared issuer owner has no instance ID"))?
                        .to_owned())
                })
                .transpose()?
        };
        if !policy.task_templates.is_empty() {
            if let Some(owner_root) = super::borrowed_issuer(state)? {
                let owner_clients: Value = serde_json::from_slice(&private::read(
                    &owner_root.join("clients.json"),
                    super::MAX_BYTES,
                )?)?;
                let resources = owner_clients["issuer"]["resources"]
                    .as_array()
                    .context("shared issuer owner has no resource inventory")?;
                let default_resource = format!(
                    "urn:breg:dev:{}",
                    state.issuer_owner.as_deref().unwrap_or_default()
                );
                for template in &policy.task_templates {
                    let available = if template.resource == default_resource {
                        owner_clients["clients"]
                            .as_array()
                            .context("shared issuer owner has no client inventory")?
                            .iter()
                            .flat_map(|client| client["scopes"].as_array().into_iter().flatten())
                            .filter_map(Value::as_str)
                            .collect::<BTreeSet<_>>()
                    } else {
                        resources
                            .iter()
                            .find(|resource| resource["audience"] == template.resource)
                            .and_then(|resource| resource["scopes"].as_array())
                            .with_context(|| {
                                format!(
                                    "shared issuer owner has no task destination resource for template {}",
                                    template.id
                                )
                            })?
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<BTreeSet<_>>()
                    };
                    if template
                        .scopes
                        .iter()
                        .any(|scope| !available.contains(scope.as_str()))
                    {
                        bail!(
                            "shared issuer owner has no task destination scopes for template {}",
                            template.id
                        );
                    }
                }
            }
        }
        for template in &policy.task_templates {
            let expected = owner_instance
                .as_deref()
                .map(|instance| local::agent_id(instance, &template.client))
                .unwrap_or_else(|| config::principal(&template.client));
            if template.agent.subject != expected {
                return Err(super::DevFailure::integration(
                    "task template agent must use its exact local issuer identity",
                )
                .into());
            }
        }
        for binding in self.context_providers.values() {
            let generated = self.service_clients.iter().find(|client| {
                binding.client_id_ref == format!("secret:file/service-{}-id", client.id)
                    || binding.client_assertion_key_ref
                        == format!("secret:file/service-{}-key", client.id)
            });
            if let Some(client) = generated {
                if binding.client_id_ref != format!("secret:file/service-{}-id", client.id)
                    || binding.client_assertion_key_ref
                        != format!("secret:file/service-{}-key", client.id)
                    || client.task_exchange
                    || binding.resource.as_deref()
                        != Some(client.resource.as_deref().unwrap_or(&self.resource))
                    || binding.scopes.as_ref().is_none_or(|scopes| {
                        scopes.iter().collect::<BTreeSet<_>>()
                            != client.scopes.iter().collect::<BTreeSet<_>>()
                    })
                    || binding.token_endpoint != state.token_endpoint()
                    || binding.client_assertion_audience.as_deref()
                        != Some(state.issuer_origin().as_str())
                {
                    return Err(super::DevFailure::integration("provider credentials must select one generated service client with its exact resource, scopes and issuer").into());
                }
            } else {
                for reference in [&binding.client_id_ref, &binding.client_assertion_key_ref] {
                    let name = reference.strip_prefix("secret:file/");
                    if name.is_none_or(|name| !self.secret_files.contains_key(name)) {
                        return Err(super::DevFailure::integration("provider credentials must name generated service credentials or explicit owner-only secretFiles").into());
                    }
                }
            }
        }
        if let Some(authority) = &self.task_authority {
            if [state.casework_port, state.issuer_port, state.database_port]
                .contains(&authority.jwks_port)
            {
                bail!("the public task JWKS listener needs its own distinct port");
            }
        }
        if policy
            .task_templates
            .iter()
            .any(|template| template.agent.issuer != state.issuer_origin())
        {
            bail!("task templates must name this one local session issuer; no second issuer is trusted");
        }
        Ok(())
    }

    pub(super) fn prepare(
        &self,
        root: &Path,
        state: &State,
        mut description: Option<&mut IssuerDescription>,
        policy: &CaseworkProject,
    ) -> Result<()> {
        self.validate_session(state, policy)?;
        if let (Some(authority), Some(owner_root)) =
            (&self.task_authority, super::borrowed_issuer(state)?)
        {
            let owner_clients: Value = serde_json::from_slice(&private::read(
                &owner_root.join("clients.json"),
                super::MAX_BYTES,
            )?)?;
            let expected_jwks = format!(
                "http://host.docker.internal:{}/oauth2/jwks",
                authority.jwks_port
            );
            let paired = self
                .service_clients
                .iter()
                .filter(|client| client.task_exchange)
                .map(|client| client.id.as_str())
                .collect::<BTreeSet<_>>();
            let registered = owner_clients["issuer"]["exchangeIssuers"]
                .as_array()
                .is_some_and(|entries| {
                    entries.iter().any(|entry| {
                        entry["issuer"] == authority.issuer
                            && entry["jwksEndpoint"] == expected_jwks
                            && entry["mapping"] == "institutional-grant"
                            // The owner derives each exchange client's allowed
                            // assertion authority from the connection it is
                            // paired with, so a task client paired with one of
                            // the owner's other connections would reach its
                            // resource servers as that authority's.
                            && entry["clients"].as_array().is_some_and(|ids| {
                                ids.iter().filter_map(Value::as_str).collect::<BTreeSet<_>>()
                                    == paired
                            })
                    })
                });
            if !registered {
                return Err(super::DevFailure::SharedTaskAuthority { source: anyhow::anyhow!("shared issuer owner must pre-register the exact Casework task authority connection").into() }.into());
            }
        }
        if !self.browser_clients.is_empty() {
            let owner_root = super::borrowed_issuer(state)?.ok_or_else(|| {
                anyhow::anyhow!("interactive clients require a shared issuer owner")
            })?;
            let owner_clients: Value = serde_json::from_slice(&private::read(
                &owner_root.join("clients.json"),
                super::MAX_BYTES,
            )?)?;
            let owner_state: Value = serde_json::from_slice(&private::read(
                &owner_root.join("state.json"),
                super::MAX_BYTES,
            )?)?;
            let default_audience = format!(
                "urn:breg:dev:{}",
                owner_state["owner"].as_str().unwrap_or("")
            );
            for id in &self.browser_clients {
                let registered = owner_clients["issuer"]["interactiveApplications"]
                    .as_array()
                    .is_some_and(|apps| {
                        apps.iter().any(|app| {
                            app["id"].as_str() == Some(id.as_str())
                                && (app["audience"] == self.resource
                                    || (app["audience"].is_null()
                                        && self.resource == default_audience))
                        })
                    });
                if !registered {
                    bail!("shared issuer owner has no browser application for the Casework resource: {id}");
                }
            }
        }
        for (name, path) in &self.secret_files {
            let bytes = zeroize::Zeroizing::new(private::read(path, 64 * 1024)?);
            private::create(&root.join("secrets").join(name), &bytes)?;
        }
        if let Some(authority) = &self.task_authority {
            let directory = root.join("task-authority");
            let public = config::keypair(&directory)?;
            private::create(
                &directory.join("jwks.json"),
                &serde_json::to_vec(&json!({"keys":[public]}))?,
            )?;
            let key = zeroize::Zeroizing::new(private::read(
                &directory.join("assertion-key.jwk"),
                64 * 1024,
            )?);
            private::create(&root.join("secrets/task-authority-signing-key"), &key)?;
            if let Some(description) = description.as_deref_mut() {
                description.exchange_issuers.push(ExchangeIssuer {
                id: local::agent_id("casework-authority", &authority.issuer),
                name: "Casework task authority".into(),
                issuer: authority.issuer.clone(),
                jwks_endpoint: format!(
                    "http://host.docker.internal:{}/oauth2/jwks",
                    authority.jwks_port
                ),
                mapping:
                    registry_thunderid_tooling::description::ExchangeMapping::InstitutionalGrant,
                clients: vec![],
                token_attributes: BTreeMap::new(),
            });
            }
        }
        for client in &self.service_clients {
            let directory = root.join("credentials").join(&client.id);
            let mut attributes = client
                .claims
                .iter()
                .map(|(name, value)| (name.clone(), json!(value)))
                .collect::<BTreeMap<_, _>>();
            attributes.insert(
                "registry_actor_kind".into(),
                json!(if client.task_exchange {
                    "agent"
                } else {
                    "service"
                }),
            );
            let resource = client.resource.clone().unwrap_or_else(|| state.audience());
            let public = if state.issuer_project.is_some() {
                private::directory(&directory)?;
                config::borrow_client(
                    &directory,
                    state,
                    &client.id,
                    &client.scopes,
                    &json!(attributes),
                    &resource,
                    client.task_exchange,
                )?;
                serde_json::from_slice(&private::read(&directory.join("public.jwk"), 4096)?)?
            } else {
                let public = config::keypair(&directory)?;
                private::create(&directory.join("client-id"), client.id.as_bytes())?;
                public
            };
            private::create(
                &root
                    .join("secrets")
                    .join(format!("service-{}-id", client.id)),
                client.id.as_bytes(),
            )?;
            let key = zeroize::Zeroizing::new(private::read(
                &directory.join("assertion-key.jwk"),
                64 * 1024,
            )?);
            private::create(
                &root
                    .join("secrets")
                    .join(format!("service-{}-key", client.id)),
                &key,
            )?;
            if let Some(description) = description.as_deref_mut() {
                let server = local::declare_resource(description, &resource, &client.scopes)?;
                for name in attributes.keys() {
                    if !description.schema_attributes.contains(name) {
                        description.schema_attributes.push(name.clone());
                    }
                }
                let agent = config::principal(&client.id);
                description.roles.push(Role {
                    id: local::agent_id("casework-service-role", &client.id),
                    name: format!("Local {}", client.id),
                    description: "Explicit local service permissions".into(),
                    permissions: vec![(server.clone(), client.scopes.clone())],
                    assigned_agents: vec![agent.clone()],
                    assigned_users: vec![],
                    assigned_applications: vec![],
                });
                description.machine_clients.push(MachineClient {
                    agent_id: agent,
                    name: format!("Local {}", client.id),
                    description: "Explicit local service client".into(),
                    client_id: client.id.clone(),
                    public_jwks: json!({"keys":[public]}).to_string(),
                    token_attributes: attributes.keys().cloned().collect(),
                    attributes,
                    access_token_lifetime_seconds: 300,
                    token_exchange: client.task_exchange.then(|| TokenExchangeClient {
                        assertion_resource_server_id: server,
                        assertion_scope: "casework:grants:assert".into(),
                        ordinary_resource_permissions: Vec::new(),
                    }),
                });
            }
        }
        if let Some(description) = description {
            for template in &policy.task_templates {
                local::declare_resource(description, &template.resource, &template.scopes)?;
            }
            description.validate()?;
        }
        Ok(())
    }

    pub(super) fn operator(
        &self,
        state: &State,
        clients: &config::Clients,
        value: &mut Value,
    ) -> Result<()> {
        value["contextProviders"] = serde_json::to_value(&self.context_providers)?;
        // A borrowed session's issuer is the shared owner's, which holds every
        // other local project's clients as well. This list is what keeps them
        // out of this runtime, so it names the session's clients even when
        // the project adds none of its own beyond the ones it borrows.
        value["authentication"]["oidc"]["allowedClients"] = json!(clients
            .clients
            .iter()
            .map(|client| client.id.clone())
            .chain(self.service_clients.iter().map(|client| client.id.clone()))
            .chain(self.browser_clients.iter().cloned())
            .collect::<Vec<_>>());
        if let Some(authority) = &self.task_authority {
            // A task exchange client may present only this authority's
            // assertion. The borrowed issuer trusts every authority registered
            // by its owner, so naming the pairing here is what refuses a token
            // minted from one of the others.
            let assertion_issuers = self
                .service_clients
                .iter()
                .filter(|client| client.task_exchange)
                .map(|client| (client.id.clone(), vec![authority.issuer.clone()]))
                .collect::<BTreeMap<_, _>>();
            if !assertion_issuers.is_empty() {
                value["authentication"]["oidc"]["assertionIssuers"] = json!(assertion_issuers);
            }
            value["taskAuthority"] = json!({"issuer":authority.issuer,
                "exchangeAudience":state.issuer_origin(),"signingKeyRef":"secret:file/task-authority-signing-key",
                "statusClients":authority.status_clients});
        }
        Ok(())
    }

    pub(super) fn token_parameters(
        &self,
        state: &State,
        id: &str,
    ) -> Option<(String, Vec<String>)> {
        self.service_clients
            .iter()
            .find(|client| client.id == id)
            .map(|client| {
                (
                    client.resource.clone().unwrap_or_else(|| state.audience()),
                    client.scopes.clone(),
                )
            })
    }
}

/// Check the existing adapter contract entirely offline against the authored
/// project. The staging resolver reads generated secrets before the session is
/// atomically installed, and before its start builds the package the runtime
/// verifies, so the operator document is read without that verification.
pub(super) fn validate_bindings(root: &Path, project: &Path) -> Result<()> {
    let mut config = registry_casework::RuntimeConfig::loader()
        .load::<registry_casework::RuntimeConfig>(&root.join("operator.yaml"))?
        .config;
    config
        .secret_providers
        .file
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("local provider bindings require generated file secrets"))?
        .root = root.join("secrets");
    let secrets = registry_casework::secret_resolver(&config)?;
    let policy = crate::project::load_and_check_policy(project)?;
    for provider in &policy.context_providers {
        let Some(binding) = config.context_providers.get(&provider.deployment_ref) else {
            continue;
        };
        let description = provider
            .description
            .as_deref()
            .context("context provider export is missing")?;
        let bytes = crate::project::read_package_input(&crate::project::project_input_path(
            project,
            description,
        )?)?;
        registry_casework_breg::build_provider(binding, provider, &bytes, &secrets)
            .map_err(provider_binding_failure)?;
    }
    Ok(())
}

/// Only a typed invalid adapter contract is an authoring refusal. Operational
/// adapter failures keep their type for the owning CLI classifier.
pub(super) fn provider_binding_failure(
    error: registry_casework_core::ReviewContextError,
) -> anyhow::Error {
    if error == registry_casework_core::ReviewContextError::Invalid {
        super::DevFailure::ContextProviderBindingConfiguration {
            source: Box::new(error),
        }
        .into()
    } else {
        error.into()
    }
}

/// Report one service or browser client ID: its grammar, the reserved
/// issuer ID, and a repeat of any client ID before it.
fn client_id<'a>(
    found: &mut Vec<ConfigFinding>,
    ids: &mut config::FirstSeen<'a>,
    id: &'a str,
    pointer: &str,
) {
    if id == "issuer" {
        found.push(ConfigFinding::new(
            "casework.dev-clients.reserved-id",
            pointer,
            "the local token issuer reserves this client ID",
            "Choose another client ID.",
        ));
    } else if !config::identifier(id) {
        found.push(ConfigFinding::new(
            "casework.dev-clients.invalid-id",
            pointer,
            config::CLIENT_ID_MESSAGE,
            "Write a lowercase client ID, such as seed.",
        ));
    } else if let Some(first) = ids.repeat(id, pointer) {
        found.push(
            ConfigFinding::new(
                "casework.dev-clients.duplicate-id",
                pointer,
                "another client already declares this ID",
                "Give each client its own ID.",
            )
            .with_related(first, "first declared here"),
        );
    }
}

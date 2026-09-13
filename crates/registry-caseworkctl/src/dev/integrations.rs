//! Explicit source-backed development inputs. The ordinary standalone session
//! remains source-free unless this closed integration block is configured.
use super::{config, private, State};
use anyhow::{bail, Result};
use registry_casework_core::CaseworkProject;
use registry_thunderid_tooling::{description::*, local};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Integrations {
    /// Explicit shared audience accepted independently by Casework and each source.
    pub resource: String,
    #[serde(default)]
    pub sources: BTreeMap<String, registry_casework_breg::BregBinding>,
    /// Files copied once to source-prefixed references in the retained private root.
    #[serde(default)]
    pub secret_files: BTreeMap<String, PathBuf>,
    #[serde(default)]
    pub service_clients: Vec<ServiceClient>,
    #[serde(default)]
    pub task_authority: Option<TaskAuthority>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ServiceClient {
    pub id: String,
    /// Omission means this Casework session's generated audience.
    pub resource: Option<String>,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub claims: BTreeMap<String, Value>,
    #[serde(default)]
    pub task_exchange: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TaskAuthority {
    pub id: String,
    /// Logical authority identifier, independent of the local API transport URL.
    pub issuer: String,
    /// Public-key-only listener, reachable from the stock issuer container.
    pub jwks_port: u16,
    pub status_clients: BTreeMap<String, String>,
}

impl Integrations {
    pub fn validate(&self, clients: &config::Clients, policy: &CaseworkProject) -> Result<()> {
        if !registry_platform_httputil::valid_resource_uri(&self.resource) {
            bail!("integrations.resource must explicitly name the shared Casework/source audience");
        }
        let declared = policy
            .sources
            .iter()
            .map(|source| &source.id)
            .collect::<BTreeSet<_>>();
        if self.sources.keys().collect::<BTreeSet<_>>() != declared {
            bail!("source-backed development needs exactly the declared source bindings");
        }
        if self.secret_files.len() > 64 || self.service_clients.len() > 32 {
            bail!("local integrations exceed their bounded secret or service-client count");
        }
        for (name, path) in &self.secret_files {
            if !name.starts_with("source-") || !config::identifier(name) || !path.is_absolute() {
                bail!(
                    "source secret inputs need source-prefixed names and absolute owner-only files"
                );
            }
        }
        let mut ids = clients
            .clients
            .iter()
            .map(|client| &client.id)
            .collect::<BTreeSet<_>>();
        for client in &self.service_clients {
            if !config::identifier(&client.id)
                || client.id == "issuer"
                || !ids.insert(&client.id)
                || client.scopes.is_empty()
                || client.scopes.len() > 32
                || client.scopes.iter().collect::<BTreeSet<_>>().len() != client.scopes.len()
                || client.scopes.iter().any(|scope| {
                    scope.len() > 128
                        || scope.contains('*')
                        || !registry_platform_httputil::valid_scope_token(scope)
                })
                || client.resource.as_ref().is_some_and(|resource| {
                    !registry_platform_httputil::valid_resource_uri(resource)
                })
                || client.claims.contains_key("registry_actor_kind")
            {
                bail!("service clients need distinct IDs, exact resources/scopes and no caller-selected actor marker");
            }
            if client.task_exchange
                && (self.task_authority.is_none()
                    || client.resource.is_some()
                    || client.scopes != ["casework:grants:assert"])
            {
                bail!("task-exchange clients receive only casework:grants:assert at this session's Casework audience");
            }
        }
        if !policy.task_templates.is_empty() && self.task_authority.is_none() {
            bail!("governed task templates require an explicit local taskAuthority");
        }
        if let Some(authority) = &self.task_authority {
            if !config::identifier(&authority.id)
                || !authority.issuer.starts_with("https://")
                || !registry_platform_httputil::valid_resource_uri(&authority.issuer)
                || authority.jwks_port == 0
                || authority.status_clients.len() > 32
                || authority.status_clients.iter().any(|(id, resource)| {
                    !registry_platform_httputil::valid_resource_uri(resource)
                        || !self.service_clients.iter().any(|client| {
                            &client.id == id
                                && !client.task_exchange
                                && client.resource.is_none()
                                && client.scopes == ["casework:grants:status"]
                        })
                })
            {
                bail!("taskAuthority requires a distinct public JWKS port and exact local status clients");
            }
            for template in &policy.task_templates {
                if !self
                    .service_clients
                    .iter()
                    .any(|client| client.id == template.client && client.task_exchange)
                    || template.agent.subject != config::principal(&template.client)
                {
                    bail!("task templates must bind a declared task-exchange client and its exact dev identity");
                }
            }
        }
        Ok(())
    }

    pub fn validate_session(&self, state: &State, policy: &CaseworkProject) -> Result<()> {
        for binding in self.sources.values() {
            let reader = self.service_clients.iter().find(|client| {
                binding.client_id_ref == format!("secret:file/service-{}-id", client.id)
                    && binding.client_assertion_key_ref
                        == format!("secret:file/service-{}-key", client.id)
                    && !client.task_exchange
                    && client.resource.as_deref().unwrap_or(&self.resource) == self.resource
                    && binding.scopes.as_ref().is_some_and(|scopes| {
                        scopes.iter().collect::<BTreeSet<_>>()
                            == client.scopes.iter().collect::<BTreeSet<_>>()
                    })
            });
            if reader.is_none() {
                bail!("source reader references must select the same generated service client with exactly the binding resource and scopes");
            }
            if binding.token_endpoint != format!("{}/oauth2/token", state.issuer_origin())
                || binding.client_assertion_audience.as_deref()
                    != Some(state.issuer_origin().as_str())
                || binding.resource.as_deref() != Some(self.resource.as_str())
                || binding
                    .scopes
                    .as_ref()
                    .is_none_or(|scopes| scopes.is_empty())
            {
                bail!("source bindings must explicitly use the session issuer token endpoint/audience, integrations.resource and reader scopes; configure BREG to admit that resource with independent human profiles/scopes/clients");
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

    pub fn prepare(
        &self,
        root: &Path,
        state: &State,
        description: &mut IssuerDescription,
        policy: &CaseworkProject,
    ) -> Result<()> {
        self.validate_session(state, policy)?;
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
            description.exchange_issuers.push(ExchangeIssuer {
                id: local::agent_id("casework-authority", &authority.id),
                name: authority.id.clone(),
                issuer: authority.issuer.clone(),
                jwks_endpoint: format!(
                    "http://host.docker.internal:{}/oauth2/jwks",
                    authority.jwks_port
                ),
            });
        }
        for client in &self.service_clients {
            let directory = root.join("credentials").join(&client.id);
            let public = config::keypair(&directory)?;
            private::create(&directory.join("client-id"), client.id.as_bytes())?;
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
            let resource = client.resource.clone().unwrap_or_else(|| state.audience());
            let server = local::declare_resource(description, &resource, &client.scopes)?;
            let mut attributes = client.claims.clone();
            attributes.insert(
                "registry_actor_kind".into(),
                json!(if client.task_exchange {
                    "agent"
                } else {
                    "service"
                }),
            );
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
                }),
            });
        }
        for template in &policy.task_templates {
            local::declare_resource(description, &template.resource, &template.scopes)?;
        }
        description.validate()?;
        Ok(())
    }

    pub fn operator(
        &self,
        state: &State,
        clients: &config::Clients,
        value: &mut Value,
    ) -> Result<()> {
        value["sources"] = serde_json::to_value(&self.sources)?;
        if let Some(authority) = &self.task_authority {
            value["authentication"]["oidc"]["allowedClients"] = json!(clients
                .clients
                .iter()
                .map(|client| client.id.clone())
                .chain(self.service_clients.iter().map(|client| client.id.clone()))
                .collect::<Vec<_>>());
            value["taskAuthority"] = json!({"id":authority.id,"issuer":authority.issuer,
                "exchangeAudience":state.issuer_origin(),"signingKeyRef":"secret:file/task-authority-signing-key",
                "statusClients":authority.status_clients});
        }
        Ok(())
    }

    pub fn token_parameters(&self, state: &State, id: &str) -> Option<(String, Vec<String>)> {
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

/// Check the existing adapter contract entirely offline. The staging resolver
/// reads generated secrets before the session is atomically installed.
pub(super) fn validate_bindings(root: &Path, project: &Path) -> Result<()> {
    let mut config = registry_casework::RuntimeConfig::load(root.join("operator.yaml"))?;
    config
        .secret_providers
        .file
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("local source bindings require generated file secrets"))?
        .root = root.join("secrets");
    let secrets = registry_casework::secret_resolver(&config)?;
    let policy = crate::project::load_and_check_policy(project)?;
    for source in &policy.sources {
        config.sources.get(&source.id).ok_or_else(||anyhow::anyhow!("a declared source binding is missing"))?
            .build_adapter(source, project, &secrets)
            .map_err(|_| anyhow::anyhow!("local source binding is invalid; check its exact BREG event source, reader profile, source description and credential references before starting services"))?;
    }
    Ok(())
}

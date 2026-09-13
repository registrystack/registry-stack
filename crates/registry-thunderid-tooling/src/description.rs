//! The validated internal description an owning CLI supplies.
//!
//! This is an internal Rust input type, not a provisioning DSL: the owning
//! CLI keeps every authority decision — which principals, purposes, row
//! constraints, requester tags, and role assignments exist — and hands this
//! crate the closed set of upstream resources that implements them. Nothing
//! here may name a product entity, an institution, a person, or a business
//! purpose; the neutral vocabulary below is the whole of what this crate
//! understands, and review must keep it that way.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::ToolingError;

/// The pinned default agent schema's type name. Upstream v1.0.1 admits only
/// this agent type, so this crate neither invents others nor reaches for an
/// undocumented category workaround.
pub const DEFAULT_AGENT_TYPE: &str = "default";

/// Upstream's default organization unit, created by the bootstrap bundle. A
/// description may use it or state its own; it may not invent a third
/// spelling of either.
pub const DEFAULT_OU_HANDLE: &str = "default";

/// The bootstrap bundle's default organization unit id. A description using
/// this id and handle builds on the unit setup already created.
pub const DEFAULT_OU_ID: &str = "01900000-0000-7000-8000-000000000001";

/// The whole closed description of one issuer deployment.
#[derive(Debug, Clone)]
pub struct IssuerDescription {
    /// Ownership identity for this development session. The label names the
    /// container and volume; the id is a random value fixed at creation so a
    /// stale label on an unrelated resource can never be mistaken for
    /// ownership.
    pub session: SessionIdentity,
    /// The numeric loopback port the issuer's single listener is published on.
    /// The issuer URL is always `http://127.0.0.1:<port>`, and it never
    /// switches between host spellings across restarts.
    pub port: u16,
    /// The private, caller-owned directory this session's retained state
    /// lives in. This crate creates owner-only subdirectories inside it and
    /// writes private files with owner-only modes; it never removes the root.
    pub state_root: PathBuf,
    pub organization_unit: OrganizationUnit,
    pub resource_servers: Vec<ResourceServer>,
    pub roles: Vec<Role>,
    pub machine_clients: Vec<MachineClient>,
    pub compatibility_clients: Vec<CompatibilityClient>,
    /// External signed-assertion issuers. Every entry has the same protected issuer mapping.
    pub exchange_issuers: Vec<ExchangeIssuer>,
    /// Optional string attributes appended to the default agent schema so
    /// machine clients can carry static, issuer-governed attribute values.
    /// They are optional in the schema because non-Registry agents may use the
    /// same default schema.
    pub schema_attributes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SessionIdentity {
    /// A stable, filesystem- and docker-safe label unique to this project
    /// session, e.g. `breg-dev-alpha`.
    pub label: String,
    /// A random value fixed when the session is first created.
    pub id: String,
}

#[derive(Debug, Clone)]
pub struct OrganizationUnit {
    pub id: String,
    pub handle: String,
    pub name: String,
    pub description: String,
}

/// One resource server: the unit whose `identifier` is the exact access-token
/// audience its clients request with the RFC 8707 `resource` parameter.
#[derive(Debug, Clone)]
pub struct ResourceServer {
    pub id: String,
    pub name: String,
    pub identifier: String,
    pub description: String,
    pub resources: Vec<Resource>,
}

#[derive(Debug, Clone)]
pub struct Resource {
    pub name: String,
    pub handle: String,
    /// Upstream `parent` is a resource handle in this server. It constructs
    /// multi-segment permission names without rewriting the scope string.
    pub parent: Option<String>,
    pub description: String,
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone)]
pub struct Action {
    pub name: String,
    pub handle: String,
    pub description: String,
}

/// One role: named permission strings from one resource server, assigned
/// directly to agents. There is deliberately no group or synchronization
/// layer; the owning CLI's authority declarations are the source.
#[derive(Debug, Clone)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: String,
    /// (`resource server id`, permission strings) pairs.
    pub permissions: Vec<(String, Vec<String>)>,
    /// Agent ids this role is assigned to directly.
    pub assigned_agents: Vec<String>,
}

/// One machine client: a `private_key_jwt` agent whose own registered public
/// JWKS authenticates it. Its private key stays with the workload; this crate
/// only ever sees the public half.
#[derive(Debug, Clone)]
pub struct MachineClient {
    pub agent_id: String,
    pub name: String,
    pub description: String,
    pub client_id: String,
    /// This client's own public JWKS, as JSON text. Never a pooled set.
    pub public_jwks: String,
    /// Static, issuer-governed attribute values emitted into tokens for this
    /// client. Names must appear in `schema_attributes`.
    pub attributes: BTreeMap<String, serde_json::Value>,
    /// Which of those attribute names are embedded in access tokens.
    pub token_attributes: Vec<String>,
    pub access_token_lifetime_seconds: u32,
    /// Enable institutional exchange alongside a narrowly authorized bootstrap grant.
    pub token_exchange: Option<TokenExchangeClient>,
}

/// The only machine-client permission available before a task grant exists.
#[derive(Debug, Clone)]
pub struct TokenExchangeClient {
    pub assertion_resource_server_id: String,
    pub assertion_scope: String,
}

/// One external authority, rendered as a native exchange-only OIDC connection.
#[derive(Debug, Clone)]
pub struct ExchangeIssuer {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub jwks_endpoint: String,
}

/// Closed application profile. The issuer copies these signed values; consumers
/// still compare immutable client, resource, authority, scope and deadline bounds.
pub const GRANT_ATTRIBUTES: &[&str] = &[
    "registry_actor_kind",
    "registry_grant_id",
    "registry_grant_authority",
    "registry_grant_source_issuer",
    "registry_grant_client",
    "registry_grant_resource",
    "registry_purpose",
    "registry_grant_exp",
    "registry_grant_bounds",
    "identity",
    "registry_approver",
];

fn protected_attribute(name: &str) -> bool {
    name.starts_with("registry_grant_") || matches!(name, "identity" | "registry_approver")
}

/// A standard-authorization client that cannot sign: one explicitly
/// registered secret-based method. The secret itself never enters this crate;
/// `secret_file` names a caller-owned private file the renderer reads at
/// render time inside the private state directory.
#[derive(Debug, Clone)]
pub struct CompatibilityClient {
    pub agent_id: String,
    pub name: String,
    pub description: String,
    pub client_id: String,
    pub method: ClientSecretMethod,
    pub secret_file: PathBuf,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ClientSecretMethod {
    Basic,
    Post,
}

impl ClientSecretMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "client_secret_basic",
            Self::Post => "client_secret_post",
        }
    }
}

const MAXIMUM_IDENTIFIER_BYTES: usize = 256;

fn bounded(value: &str, bound: usize) -> bool {
    !value.is_empty() && value.len() <= bound
}

pub(crate) fn valid_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

/// A permission string is the scope a client will request and a resource
/// server will see: RFC 6749 scope-token bytes, which `:` belongs to.
fn valid_permission(value: &str) -> bool {
    registry_platform_httputil::valid_scope_token(value)
}

impl IssuerDescription {
    /// Validate the closed description. Every refusal here is fixed text
    /// about the shape, so an owning CLI can report it before anything is
    /// rendered or run.
    pub fn validate(&self) -> Result<(), ToolingError> {
        let refuse = |reason: &'static str| Err(ToolingError::InvalidDescription { reason });
        if self.port == 0 {
            return refuse("the listener port must be non-zero");
        }
        if !bounded(&self.session.label, 64)
            || !self
                .session
                .label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return refuse(
                "the session label must be 1..=64 bytes of lowercase digits and hyphens",
            );
        }
        if !bounded(&self.session.id, 64) {
            return refuse("the session identity must be 1..=64 bytes");
        }
        if !valid_uuid(&self.organization_unit.id) || !bounded(&self.organization_unit.handle, 64) {
            return refuse("the organization unit must carry a UUID id and a bounded handle");
        }
        if self.organization_unit.handle == DEFAULT_OU_HANDLE
            && self.organization_unit.name.is_empty()
        {
            return refuse("the organization unit must carry a name");
        }
        if self.resource_servers.is_empty() || self.resource_servers.len() > 8 {
            return refuse("the description states 1..=8 resource servers");
        }
        let mut identifiers = BTreeSet::new();
        let mut server_ids = BTreeSet::new();
        for server in &self.resource_servers {
            if !valid_uuid(&server.id) || !server_ids.insert(server.id.clone()) {
                return refuse("each resource server carries a distinct UUID id");
            }
            let parsed = url::Url::parse(&server.identifier).map_err(|_| {
                ToolingError::InvalidDescription {
                    reason: "each resource server identifier is an absolute URI",
                }
            })?;
            if parsed.fragment().is_some()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.scheme().is_empty()
                || !identifiers.insert(server.identifier.clone())
            {
                return refuse(
                    "each resource server identifier is a distinct absolute URI without a fragment or userinfo",
                );
            }
            if server.resources.is_empty() {
                return refuse("each resource server states at least one resource");
            }
            let mut handles = BTreeSet::new();
            for resource in &server.resources {
                if !bounded(&resource.handle, 64)
                    || !resource
                        .handle
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
                    || !handles.insert(resource.handle.clone())
                {
                    return refuse("resource handles are distinct, bounded, and URL-safe");
                }
                let mut action_handles = BTreeSet::new();
                for action in &resource.actions {
                    if !bounded(&action.handle, 64) || !action_handles.insert(action.handle.clone())
                    {
                        return refuse("action handles are distinct and bounded");
                    }
                }
            }
            if server.resources.iter().any(|resource| {
                resource
                    .parent
                    .as_ref()
                    .is_some_and(|parent| parent == &resource.handle || !handles.contains(parent))
            }) {
                return refuse(
                    "resource parents must name a distinct resource handle in the same server",
                );
            }
        }
        if self.roles.is_empty() {
            return refuse("the description states at least one role");
        }
        let mut issuer_ids = BTreeSet::new();
        let mut issuer_names = BTreeSet::new();
        let mut issuer_urls = BTreeSet::new();
        if self.exchange_issuers.len() > 8 {
            return refuse("at most eight external exchange issuers are supported");
        }
        for issuer in &self.exchange_issuers {
            if !valid_uuid(&issuer.id)
                || !issuer_ids.insert(&issuer.id)
                || !bounded(&issuer.name, 128)
                || !issuer_names.insert(&issuer.name)
                || !issuer_urls.insert(&issuer.issuer)
            {
                return refuse(
                    "exchange issuer IDs, names and issuer URLs must be distinct and bounded",
                );
            }
            for address in [&issuer.issuer, &issuer.jwks_endpoint] {
                let valid = url::Url::parse(address).is_ok_and(|url| {
                    url.host_str().is_some()
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.fragment().is_none()
                        && url.query().is_none()
                        && (url.scheme() == "https"
                            || (url.scheme() == "http"
                                && matches!(
                                    url.host_str(),
                                    Some("127.0.0.1" | "localhost" | "host.docker.internal")
                                )))
                });
                if !valid {
                    return refuse("exchange issuer and JWKS URLs require HTTPS or an explicit development host");
                }
            }
            if issuer.issuer == format!("http://127.0.0.1:{}", self.port) {
                return refuse("an external exchange issuer cannot name this issuer");
            }
        }
        let mut agent_ids = BTreeSet::new();
        for client in &self.machine_clients {
            if !valid_uuid(&client.agent_id) || !agent_ids.insert(client.agent_id.clone()) {
                return refuse("each machine client carries a distinct UUID agent id");
            }
            if !bounded(&client.client_id, 128) {
                return refuse("each machine client carries a bounded client id");
            }
            let jwks: serde_json::Value =
                serde_json::from_str(&client.public_jwks).map_err(|_| {
                    ToolingError::InvalidDescription {
                        reason: "each machine client's public JWKS is JSON",
                    }
                })?;
            let keys = jwks.get("keys").and_then(|keys| keys.as_array()).ok_or(
                ToolingError::InvalidDescription {
                    reason: "each machine client's public JWKS carries a keys array",
                },
            )?;
            if keys.is_empty() || keys.len() > 8 {
                return refuse("each machine client registers 1..=8 public keys of its own");
            }
            if !(60..=86_400).contains(&client.access_token_lifetime_seconds) {
                return refuse("the access token lifetime is 60..=86400 seconds");
            }
            if client
                .attributes
                .keys()
                .any(|name| protected_attribute(name))
                || client
                    .token_attributes
                    .iter()
                    .any(|name| protected_attribute(name))
            {
                return refuse("client credentials cannot emit the protected grant namespace");
            }
            if let Some(exchange) = &client.token_exchange {
                if self.exchange_issuers.is_empty()
                    || !server_ids.contains(&exchange.assertion_resource_server_id)
                    || !valid_permission(&exchange.assertion_scope)
                {
                    return refuse("exchange clients require an issuer and an exact registered bootstrap permission");
                }
                let permissions: Vec<_> = self
                    .roles
                    .iter()
                    .filter(|role| role.assigned_agents.contains(&client.agent_id))
                    .flat_map(|role| &role.permissions)
                    .collect();
                if permissions.is_empty()
                    || permissions.iter().any(|(server, scopes)| {
                        server != &exchange.assertion_resource_server_id
                            || scopes.is_empty()
                            || scopes
                                .iter()
                                .any(|scope| scope != &exchange.assertion_scope)
                    })
                {
                    return refuse("exchange clients may receive only their exact bootstrap permission through client credentials");
                }
            }
            if client.token_attributes.len() > 16 {
                return refuse("at most 16 token attributes are stated");
            }
            for value in client.attributes.values() {
                let valid = value.as_str().is_some_and(|value| bounded(value, 512))
                    || value.as_array().is_some_and(|values| {
                        !values.is_empty()
                            && values.len() <= 32
                            && values.iter().all(|value| {
                                value.as_str().is_some_and(|value| bounded(value, 512))
                            })
                    });
                if !valid {
                    return refuse(
                        "static client attributes are bounded strings or nonempty bounded string arrays",
                    );
                }
            }
        }
        for client in &self.compatibility_clients {
            if !valid_uuid(&client.agent_id) || !agent_ids.insert(client.agent_id.clone()) {
                return refuse("each compatibility client carries a distinct UUID agent id");
            }
            if !bounded(&client.client_id, 128) {
                return refuse("each compatibility client carries a bounded client id");
            }
        }
        let client_ids: BTreeSet<_> = self
            .machine_clients
            .iter()
            .map(|client| client.client_id.as_str())
            .chain(
                self.compatibility_clients
                    .iter()
                    .map(|client| client.client_id.as_str()),
            )
            .collect();
        if client_ids.len() != self.machine_clients.len() + self.compatibility_clients.len() {
            return refuse("client ids are distinct across every registration");
        }
        let mut role_ids = BTreeSet::new();
        for role in &self.roles {
            if !valid_uuid(&role.id) || !role_ids.insert(role.id.clone()) {
                return refuse("each role carries a distinct UUID id");
            }
            if role.permissions.is_empty() {
                return refuse("each role states at least one permission entry");
            }
            for (server_id, permissions) in &role.permissions {
                if !server_ids.contains(server_id) {
                    return refuse("each role permission names a stated resource server");
                }
                if permissions.is_empty()
                    || permissions.len() > 32
                    || permissions
                        .iter()
                        .any(|permission| !valid_permission(permission))
                {
                    return refuse("role permissions are 1..=32 RFC 6749 scope-tokens");
                }
            }
            for agent in &role.assigned_agents {
                if !agent_ids.contains(agent) {
                    return refuse("each role assignment names a stated agent");
                }
            }
        }
        let mut attribute_names = BTreeSet::new();
        for name in &self.schema_attributes {
            if protected_attribute(name) {
                return refuse("static agent schemas cannot declare protected grant attributes");
            }
            if !bounded(name, 128)
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                || !attribute_names.insert(name.clone())
            {
                return refuse("schema attributes are distinct, bounded snake_case names");
            }
            let mut array = None;
            for value in self
                .machine_clients
                .iter()
                .filter_map(|client| client.attributes.get(name))
            {
                let current = value.is_array();
                if array.replace(current).is_some_and(|prior| prior != current) {
                    return refuse("each static attribute has one consistent schema type");
                }
            }
        }
        for client in &self.machine_clients {
            for name in client.attributes.keys() {
                if !attribute_names.contains(name) {
                    return refuse("every client attribute is a stated schema attribute");
                }
            }
            for name in &client.token_attributes {
                if !client.attributes.contains_key(name) {
                    return refuse("every token attribute is a stated client attribute");
                }
            }
        }
        if self.session.label.len() > MAXIMUM_IDENTIFIER_BYTES {
            return refuse("unreachable bound");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn exchange_description() -> IssuerDescription {
        let mut description = crate::testing::synthetic_description();
        description.exchange_issuers.push(ExchangeIssuer {
            id: "0197aaaa-0000-7000-8000-0000000000d1".into(),
            name: "Synthetic Authority".into(),
            issuer: "https://authority.example".into(),
            jwks_endpoint: "https://authority.example/jwks".into(),
        });
        description.machine_clients[0].token_exchange = Some(TokenExchangeClient {
            assertion_resource_server_id: description.resource_servers[0].id.clone(),
            assertion_scope: "evidence:invoke".into(),
        });
        description
    }

    #[test]
    fn static_claim_paths_cannot_manufacture_grant_authority() {
        for name in GRANT_ATTRIBUTES
            .iter()
            .copied()
            .filter(|name| protected_attribute(name))
            .chain(["registry_grant_future_bound"])
        {
            let mut description = exchange_description();
            description.schema_attributes.push(name.into());
            assert!(description.validate().is_err(), "protected schema accepted");
            let mut description = exchange_description();
            description.machine_clients[0]
                .attributes
                .insert(name.into(), "synthetic".into());
            assert!(
                description.validate().is_err(),
                "protected client attribute accepted"
            );
            let mut description = exchange_description();
            description.machine_clients[0]
                .token_attributes
                .push(name.into());
            assert!(
                description.validate().is_err(),
                "protected client token attribute accepted"
            );
        }
    }

    #[test]
    fn every_assigned_role_is_limited_to_the_exact_bootstrap_permission() {
        let mut description = exchange_description();
        assert!(description.validate().is_ok());
        description.roles[0].permissions[0]
            .1
            .push("evidence:write".into());
        assert!(description.validate().is_err());
        let mut description = exchange_description();
        let mut extra_role = description.roles[0].clone();
        extra_role.id = "0197aaaa-0000-7000-8000-0000000000c2".into();
        extra_role.permissions[0].1 = vec!["evidence:write".into()];
        description.roles.push(extra_role);
        assert!(description.validate().is_err());
        let mut description = exchange_description();
        description.roles[0].assigned_agents.clear();
        assert!(description.validate().is_err());
    }

    #[test]
    fn exchange_requires_distinct_external_issuers_and_explicit_jwks_trust() {
        let mut description = exchange_description();
        description.exchange_issuers.clear();
        assert!(description.validate().is_err());
        let mut description = exchange_description();
        let mut duplicate = description.exchange_issuers[0].clone();
        duplicate.id = "0197aaaa-0000-7000-8000-0000000000d2".into();
        duplicate.name = "Other name".into();
        description.exchange_issuers.push(duplicate);
        assert!(description.validate().is_err());
        for address in [
            "http://authority.example/jwks",
            "file:///tmp/jwks",
            "https://user:secret@authority.example/jwks",
            "https://authority.example/jwks#fragment",
        ] {
            let mut description = exchange_description();
            description.exchange_issuers[0].jwks_endpoint = address.into();
            assert!(description.validate().is_err());
        }
    }
}

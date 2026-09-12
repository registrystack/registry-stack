//! Common construction for local adopter sessions. Product CLIs own the
//! declared clients and scopes, credential files, and interpretation of claims.
pub use crate::local_session::{start, stop};

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::description::{
    Action, IssuerDescription, MachineClient, OrganizationUnit, Resource, ResourceServer, Role,
    SessionIdentity, DEFAULT_OU_HANDLE, DEFAULT_OU_ID,
};
use crate::ToolingError;

#[derive(Debug, Clone)]
pub struct LocalClient {
    pub client_id: String,
    pub public_jwks: String,
    pub claims: BTreeMap<String, String>,
    pub scopes: Vec<String>,
    /// Only a local teaching fixture may mark a machine-issued token human.
    /// This never changes the consuming runtime's human-session policy.
    pub allow_human_fixture: bool,
}

#[derive(Debug, Clone)]
pub struct TypedLocalClient {
    pub client_id: String,
    pub public_jwks: String,
    pub claims: BTreeMap<String, Value>,
    pub scopes: Vec<String>,
    pub allow_human_fixture: bool,
}

/// Stable opaque native entity ID, matching the original BREG dev renderer.
/// It does not carry a timestamp and must not be decoded for identity facts.
pub fn agent_id(session_id: &str, client_id: &str) -> String {
    derived_uuid(&format!("{session_id}:agent:{client_id}"))
}

fn derived_uuid(seed: &str) -> String {
    let digest = Sha256::digest(seed.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut result = String::with_capacity(36);
    for (index, character) in hex.chars().take(32).enumerate() {
        result.push(match index {
            12 => '7',
            16 => '8',
            _ => character,
        });
        if matches!(index, 7 | 11 | 15 | 19) {
            result.push('-');
        }
    }
    result
}

fn add_scope(
    resources: &mut BTreeMap<Vec<String>, Resource>,
    scope: &str,
) -> Result<(), ToolingError> {
    let refuse = |reason| ToolingError::InvalidDescription { reason };
    let segments: Vec<_> = scope.split(':').collect();
    if segments.len() < 2
        || segments.iter().any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(refuse(
            "local scopes must be exact colon-delimited upstream handles",
        ));
    }
    let chain: Vec<String> = segments[..segments.len() - 1]
        .iter()
        .map(|part| (*part).into())
        .collect();
    let action = segments[segments.len() - 1];
    for depth in 1..=chain.len() {
        let prefix = chain[..depth].to_vec();
        resources.entry(prefix.clone()).or_insert_with(|| Resource {
            name: chain[depth - 1].clone(),
            handle: chain[depth - 1].clone(),
            parent: (depth > 1).then(|| chain[depth - 2].clone()),
            description: format!("local resource {}", prefix.join(":")),
            actions: vec![],
        });
    }
    let leaf = resources.get_mut(&chain).expect("inserted resource chain");
    if !leaf
        .actions
        .iter()
        .any(|existing| existing.handle == action)
    {
        leaf.actions.push(Action {
            name: action.into(),
            handle: action.into(),
            description: format!("local permission {scope}"),
        });
    }
    Ok(())
}

/// Declare exact scope handles for another audience in the same native issuer.
/// This creates no role assignment and gives no client any additional permission.
pub fn declare_resource(
    description: &mut IssuerDescription,
    audience: &str,
    scopes: &[String],
) -> Result<String, ToolingError> {
    let mut resources = BTreeMap::new();
    for scope in scopes {
        add_scope(&mut resources, scope)?;
    }
    let server = if let Some(index) = description
        .resource_servers
        .iter()
        .position(|server| server.identifier == audience)
    {
        &mut description.resource_servers[index]
    } else {
        description.resource_servers.push(ResourceServer {
            id: derived_uuid(&format!("{}:resource:{audience}", description.session.id)),
            name: "Configured local resource".into(),
            identifier: audience.into(),
            description: "Explicit local resource scope handles".into(),
            resources: vec![],
        });
        description
            .resource_servers
            .last_mut()
            .expect("inserted resource server")
    };
    for resource in resources.into_values() {
        if let Some(existing) = server
            .resources
            .iter_mut()
            .find(|entry| entry.handle == resource.handle)
        {
            if existing.parent != resource.parent {
                return Err(ToolingError::InvalidDescription {
                    reason: "local resource handles must have one unambiguous parent",
                });
            }
            for action in resource.actions {
                if !existing
                    .actions
                    .iter()
                    .any(|entry| entry.handle == action.handle)
                {
                    existing.actions.push(action);
                }
            }
        } else {
            server.resources.push(resource);
        }
    }
    Ok(server.id.clone())
}

/// Render one audience and the exact declared scope trees. Colon-delimited
/// handles must be directly representable by the pinned upstream grammar;
/// no permission is renamed or approximated. Institutional grants use the
/// separate exchange description and never ride static local attributes.
pub fn local_description(
    session: SessionIdentity,
    port: u16,
    state_root: PathBuf,
    audience: String,
    clients: Vec<LocalClient>,
) -> Result<IssuerDescription, ToolingError> {
    typed_local_description(
        session,
        port,
        state_root,
        audience,
        clients
            .into_iter()
            .map(|client| TypedLocalClient {
                client_id: client.client_id,
                public_jwks: client.public_jwks,
                claims: client
                    .claims
                    .into_iter()
                    .map(|(name, value)| (name, Value::String(value)))
                    .collect(),
                scopes: client.scopes,
                allow_human_fixture: client.allow_human_fixture,
            })
            .collect(),
    )
}

pub fn typed_local_description(
    session: SessionIdentity,
    port: u16,
    state_root: PathBuf,
    audience: String,
    clients: Vec<TypedLocalClient>,
) -> Result<IssuerDescription, ToolingError> {
    let refuse = |reason| ToolingError::InvalidDescription { reason };
    let server_id = derived_uuid(&format!("{}:server", session.id));
    let mut resources: BTreeMap<Vec<String>, Resource> = BTreeMap::new();
    let mut attributes = BTreeSet::new();
    let mut machine_clients = Vec::new();
    let mut roles = Vec::new();
    for client in clients {
        if client
            .claims
            .get("registry_actor_kind")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind == "human")
            && !client.allow_human_fixture
        {
            return Err(refuse(
                "human actor markers require an explicit local teaching fixture",
            ));
        }
        for scope in &client.scopes {
            add_scope(&mut resources, scope)?;
        }
        let native_id = agent_id(&session.id, &client.client_id);
        let role_id = derived_uuid(&format!("{}:role:{}", session.id, client.client_id));
        attributes.extend(client.claims.keys().cloned());
        roles.push(Role {
            id: role_id,
            name: format!("Local {}", client.client_id),
            description: "Explicit local client permissions".into(),
            permissions: vec![(server_id.clone(), client.scopes)],
            assigned_agents: vec![native_id.clone()],
        });
        machine_clients.push(MachineClient {
            agent_id: native_id,
            name: format!("Local {}", client.client_id),
            description: "Local teaching client".into(),
            client_id: client.client_id,
            public_jwks: client.public_jwks,
            token_attributes: client.claims.keys().cloned().collect(),
            attributes: client.claims,
            access_token_lifetime_seconds: 300,
            token_exchange: None,
        });
    }
    let description = IssuerDescription {
        session,
        port,
        state_root,
        organization_unit: OrganizationUnit {
            id: DEFAULT_OU_ID.into(),
            handle: DEFAULT_OU_HANDLE.into(),
            name: "Default".into(),
            description: "Default organization unit".into(),
        },
        resource_servers: vec![ResourceServer {
            id: server_id,
            name: "Local development".into(),
            identifier: audience,
            description: "Local development audience".into(),
            resources: resources.into_values().collect(),
        }],
        roles,
        machine_clients,
        compatibility_clients: vec![],
        exchange_issuers: vec![],
        schema_attributes: attributes.into_iter().collect(),
    };
    description.validate()?;
    Ok(description)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn client() -> LocalClient {
        LocalClient {
            client_id: "staff".into(),
            public_jwks: crate::testing::SYNTHETIC_CLIENT_PUBLIC_JWKS.into(),
            claims: BTreeMap::from([
                ("registry_actor_kind".into(), "service".into()),
                ("registry_purpose".into(), "synthetic".into()),
            ]),
            scopes: vec!["casework:grants:assert".into(), "casework:staff".into()],
            allow_human_fixture: false,
        }
    }
    fn build(client: LocalClient) -> Result<IssuerDescription, ToolingError> {
        local_description(
            SessionIdentity {
                label: "local-builder-test".into(),
                id: "synthetic-session".into(),
            },
            8091,
            PathBuf::from("/tmp/local-builder-test"),
            "urn:synthetic:local".into(),
            vec![client],
        )
    }
    #[test]
    fn native_principal_and_nested_scopes_remain_exact() {
        let description = build(client()).unwrap();
        assert_eq!(
            description.machine_clients[0].agent_id,
            agent_id("synthetic-session", "staff")
        );
        assert_eq!(
            description.roles[0].permissions[0].1,
            ["casework:grants:assert", "casework:staff"]
        );
        let resource = description.resource_servers[0]
            .resources
            .iter()
            .find(|r| r.handle == "grants")
            .unwrap();
        assert_eq!(resource.parent.as_deref(), Some("casework"));
        assert_eq!(resource.actions[0].handle, "assert");
        assert_ne!(
            agent_id("synthetic-session", "staff"),
            agent_id("other-session", "staff")
        );
        assert_ne!(
            agent_id("synthetic-session", "staff"),
            agent_id("synthetic-session", "other-client")
        );
    }
    #[test]
    fn teaching_human_requires_explicit_flag_and_never_admits_grants() {
        let mut client = client();
        client
            .claims
            .insert("registry_actor_kind".into(), "human".into());
        assert!(build(client.clone()).is_err());
        client.allow_human_fixture = true;
        assert!(build(client.clone()).is_ok());
        client
            .claims
            .insert("registry_grant_id".into(), "synthetic-grant".into());
        assert!(build(client).is_err());
    }
    #[test]
    fn unrepresentable_scope_and_ambiguous_resource_handles_fail_closed() {
        let mut client = client();
        client.scopes = vec!["unstructured".into()];
        assert!(build(client.clone()).is_err());
        client.scopes = vec!["a:records:get".into(), "b:records:get".into()];
        assert!(build(client).is_err());
    }

    #[test]
    fn typed_local_description_preserves_bounded_string_arrays() {
        let root = std::env::temp_dir().join(format!(
            "registry-thunderid-local-array-{}",
            crate::container::random_urlsafe(12).unwrap()
        ));
        let description = typed_local_description(
            SessionIdentity {
                label: "local-array-test".into(),
                id: "synthetic-array-session".into(),
            },
            8091,
            root.clone(),
            "urn:synthetic:local".into(),
            vec![TypedLocalClient {
                client_id: "staff".into(),
                public_jwks: crate::testing::SYNTHETIC_CLIENT_PUBLIC_JWKS.into(),
                claims: BTreeMap::from([
                    ("registry_actor_kind".into(), serde_json::json!("service")),
                    (
                        "evidence_tags".into(),
                        serde_json::json!(["policy-a", "policy-b"]),
                    ),
                ]),
                scopes: vec!["evidence:invoke".into()],
                allow_human_fixture: false,
            }],
        )
        .unwrap();
        let agent_type = crate::render::agent_type_document(&description).unwrap();
        let schema: serde_json::Value = serde_norway::from_str(&agent_type).unwrap();
        assert_eq!(schema["schema"]["evidence_tags"]["type"], "array");
        assert_eq!(schema["schema"]["evidence_tags"]["items"]["type"], "string");
        let rendered = crate::render::render(&description).unwrap();
        let agent = std::fs::read_to_string(rendered.bootstrap_dir.join(format!(
            "agents/{}.yaml",
            description.machine_clients[0].agent_id
        )))
        .unwrap();
        let agent: serde_json::Value = serde_norway::from_str(&agent).unwrap();
        assert_eq!(
            agent["attributes"]["evidence_tags"],
            serde_json::json!(["policy-a", "policy-b"])
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn declaring_an_exchange_target_adds_no_client_permission() {
        let mut description = build(client()).unwrap();
        let permissions = description
            .roles
            .iter()
            .map(|role| role.permissions.clone())
            .collect::<Vec<_>>();
        let id = declare_resource(
            &mut description,
            "urn:synthetic:destination",
            &["records:get".into()],
        )
        .unwrap();
        assert_eq!(
            declare_resource(
                &mut description,
                "urn:synthetic:destination",
                &["records:patch".into()]
            )
            .unwrap(),
            id
        );
        description.validate().unwrap();
        assert_eq!(
            description
                .roles
                .iter()
                .map(|role| role.permissions.clone())
                .collect::<Vec<_>>(),
            permissions
        );
        assert_eq!(
            description
                .resource_servers
                .iter()
                .filter(|server| server.identifier == "urn:synthetic:destination")
                .count(),
            1
        );
        assert_eq!(
            description
                .resource_servers
                .iter()
                .find(|server| server.id == id)
                .unwrap()
                .resources[0]
                .actions
                .len(),
            2
        );
    }
}

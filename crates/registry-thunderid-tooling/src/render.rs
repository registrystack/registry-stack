//! Rendering of the pinned release's native declarative resources.
//!
//! The output is upstream YAML in upstream's own schema, kept inspectable on
//! disk: it is the handoff an externally operated ThunderID loads, not an
//! internal format this crate ever reads back. Field names and document
//! shapes come from the pinned release itself (`resource_type`, `agents`,
//! `resource_servers`, `roles` directories; `inboundAuthConfig`;
//! `token.accessToken.clientConfig`; the JWKS `certificate`), never from a
//! parallel Registry-side schema.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::description::{ExchangeAttributeKind, ExchangeMapping, IssuerDescription};
use crate::ToolingError;

/// The pinned release's default `agent_type` document for the `default`
/// agent type, byte-for-byte as the image ships it. The schema update starts
/// from this and only appends optional attributes; it never rewrites,
/// renames, or drops upstream fields, and a deployment sharing this schema
/// with other agents merges rather than overwrites.
const PINNED_DEFAULT_AGENT_TYPE: &str = include_str!("../fixtures/default-agent-type-v1.0.1.yaml");

/// Where serving-time documents land, relative to the description's state
/// root. The pinned release reads these through composite stores, so the
/// files stay files: the resource servers and roles they name are the live
/// configuration, not a one-shot import.
pub const RESOURCES_DIR: &str = "resources";
/// The bootstrap provisioning directory the upstream one-shot consumes: the
/// additive agent-schema update plus every machine registration. The pinned
/// release's bootstrap importer is the path that persists a machine client's
/// JWKS certificate and static attributes; the serve-time file loader alone
/// does not, which is why registrations render here and not under
/// `resources/`.
pub const BOOTSTRAP_DIR: &str = "registry-schema";

/// Everything this render produced, including the digest an owning CLI
/// records only after the bootstrap one-shot has succeeded.
#[derive(Debug, Clone)]
pub struct RenderedResources {
    /// Absolute path of the inspectable upstream YAML directory.
    pub resources_dir: std::path::PathBuf,
    /// Absolute path of the bootstrap provisioning directory the one-shot
    /// consumes: the agent-schema update plus the machine registrations.
    pub bootstrap_dir: std::path::PathBuf,
    /// The pinned default agent schema document with this deployment's
    /// optional attributes appended, as written.
    pub agent_type_document: String,
    /// sha256 of that document, for recording after successful bootstrap.
    pub agent_type_sha256: String,
}

pub(crate) fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), ToolingError> {
    if path.exists() {
        return Err(ToolingError::Filesystem {
            reason: "a rendered document already exists; remove the session state explicitly",
        });
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| ToolingError::Filesystem {
            reason: "the state directory could not be created",
        })?;
        // Every created ancestor inside the caller's private root is made
        // owner-only, not just the deepest one. The walk stops at the first
        // ancestor already owner-only — the root the caller prepared — so no
        // directory this crate does not own is ever touched.
        let mut cursor = Some(parent);
        while let Some(directory) = cursor {
            let mode = fs::metadata(directory)
                .map_err(|_| ToolingError::Filesystem {
                    reason: "the state directory could not be inspected",
                })?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                fs::set_permissions(directory, fs::Permissions::from_mode(mode & 0o700)).map_err(
                    |_| ToolingError::Filesystem {
                        reason: "the state directory could not be made owner-only",
                    },
                )?;
                cursor = directory.parent();
            } else {
                break;
            }
        }
    }
    fs::write(path, bytes).map_err(|_| ToolingError::Filesystem {
        reason: "a rendered document could not be written",
    })?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|_| {
        ToolingError::Filesystem {
            reason: "a rendered document could not be made owner-only",
        }
    })?;
    Ok(())
}

fn prepare_private_root(root: &Path) -> Result<(), ToolingError> {
    fs::create_dir_all(root).map_err(|_| ToolingError::Filesystem {
        reason: "the state directory could not be created",
    })?;
    let metadata = fs::symlink_metadata(root).map_err(|_| ToolingError::Filesystem {
        reason: "the state directory could not be inspected",
    })?;
    if !metadata.file_type().is_dir() {
        return Err(ToolingError::Filesystem {
            reason: "the state directory must be an ordinary directory",
        });
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(|_| {
        ToolingError::Filesystem {
            reason: "the state directory could not be made owner-only",
        }
    })
}

/// Serialize one upstream document as YAML, with the `---` document start the
/// upstream loader's multi-document files carry.
fn yaml_document(value: &Value) -> Result<String, ToolingError> {
    serde_norway::to_string(value).map_err(|_| ToolingError::InvalidRender {
        reason: "a document did not serialize as YAML",
    })
}

/// Parse the pinned default `agent_type` document and append this
/// deployment's optional string attributes, preserving every upstream field.
///
/// The result contains no administrator, user, role, or password-template
/// material: it is exactly the default schema plus optional attribute
/// declarations, which is the whole reason the bootstrap one-shot can run it
/// against shared state without touching anyone else's fields.
pub fn agent_type_document(description: &IssuerDescription) -> Result<String, ToolingError> {
    let mut document: Value = serde_yaml_parse(PINNED_DEFAULT_AGENT_TYPE)?;
    let Some(schema) = document.get_mut("schema").and_then(Value::as_object_mut) else {
        return Err(ToolingError::InvalidRender {
            reason: "the pinned default agent schema did not parse with a schema map",
        });
    };
    let names: BTreeSet<_> = description
        .schema_attributes
        .iter()
        .cloned()
        .chain(
            description
                .exchange_issuers
                .iter()
                .filter(|issuer| issuer.mapping == ExchangeMapping::FirstParty)
                .flat_map(|issuer| issuer.token_attributes.keys().cloned()),
        )
        .collect();
    for name in names {
        let array = description.exchange_issuers.iter().any(|issuer| {
            issuer.token_attributes.get(&name) == Some(&ExchangeAttributeKind::StringArray)
        }) || description
            .machine_clients
            .iter()
            .filter_map(|client| client.attributes.get(&name))
            .any(Value::is_array);
        schema.insert(
            name.clone(),
            if array {
                json!({
                    "type": "array",
                    "items": {"type": "string"},
                    "displayName": name,
                    "required": false,
                })
            } else {
                json!({
                    "type": "string",
                    "displayName": name,
                    "required": false,
                })
            },
        );
    }
    yaml_document(&document)
}

fn serde_yaml_parse(text: &str) -> Result<Value, ToolingError> {
    serde_norway::from_str(text).map_err(|_| ToolingError::InvalidRender {
        reason: "a pinned upstream document did not parse",
    })
}

/// Render every native resource document for one validated description.
///
/// The caller validates first; this function refuses an unvalidated shape
/// rather than guessing. Documents land in the inspectable layout the
/// upstream loader reads (`resource_servers/`, `roles/`, `agents/`, plus the
/// organization unit), and the agent-schema update lands in its own
/// one-document directory for the bootstrap one-shot.
pub fn render(description: &IssuerDescription) -> Result<RenderedResources, ToolingError> {
    description.validate()?;
    // Establish the caller-declared ownership boundary before creating any
    // descendants. `write_owner_only` then stops its permission walk here and
    // never attempts to change a shared ancestor such as `/tmp`.
    prepare_private_root(&description.state_root)?;
    let root = description.state_root.join(RESOURCES_DIR);
    let bootstrap_root = description.state_root.join(BOOTSTRAP_DIR);

    // The bootstrap bundle already created the default organization unit,
    // and the upstream loader refuses a second document for an id the
    // database store holds. A description built on the default OU emits no
    // OU document at all; only a genuinely new OU becomes one.
    if description.organization_unit.id != crate::description::DEFAULT_OU_ID {
        let organization = json!({
            "resource_type": "organization_unit",
            "id": description.organization_unit.id,
            "handle": description.organization_unit.handle,
            "name": description.organization_unit.name,
            "description": description.organization_unit.description,
        });
        write_owner_only(
            &root
                .join("organization_units")
                .join(format!("{}.yaml", description.organization_unit.handle)),
            yaml_document(&organization)?.as_bytes(),
        )?;
    }

    for server in &description.resource_servers {
        let mut resources = Vec::new();
        for resource in &server.resources {
            let actions: Vec<Value> = resource
                .actions
                .iter()
                .map(|action| {
                    json!({
                        "name": action.name,
                        "handle": action.handle,
                        "description": action.description,
                        "kind": "resource",
                    })
                })
                .collect();
            let mut rendered_resource = json!({
                "name": resource.name,
                "handle": resource.handle,
                "description": resource.description,
                "actions": actions,
            });
            if let Some(parent) = &resource.parent {
                rendered_resource["parent"] = json!(parent);
            }
            resources.push(rendered_resource);
        }
        let document = json!({
            "resource_type": "resource_server",
            "id": server.id,
            "name": server.name,
            "description": server.description,
            "identifier": server.identifier,
            "ouHandle": description.organization_unit.handle,
            "delimiter": ":",
            "resources": resources,
        });
        write_owner_only(
            &root
                .join("resource_servers")
                .join(format!("{}.yaml", server.id)),
            yaml_document(&document)?.as_bytes(),
        )?;
    }

    for role in &description.roles {
        let permissions: Vec<Value> = role
            .permissions
            .iter()
            .map(|(server_id, permissions)| {
                json!({"resourceServerId": server_id, "permissions": permissions})
            })
            .collect();
        let assignments: Vec<Value> = role
            .assigned_agents
            .iter()
            .map(|agent_id| json!({"id": agent_id, "type": "agent"}))
            .chain(
                role.assigned_users
                    .iter()
                    .map(|user_id| json!({"id": user_id, "type": "user"})),
            )
            .chain(
                role.assigned_applications
                    .iter()
                    .map(|app_id| json!({"id": app_id, "type": "app"})),
            )
            .collect();
        let document = json!({
            "resource_type": "role",
            "id": role.id,
            "name": role.name,
            "description": role.description,
            "ouHandle": description.organization_unit.handle,
            "permissions": permissions,
            "assignments": assignments,
        });
        write_owner_only(
            &root.join("roles").join(format!("{}.yaml", role.id)),
            yaml_document(&document)?.as_bytes(),
        )?;
    }

    for issuer in &description.exchange_issuers {
        // Fixed user-type resolution selects mappings without consulting any
        // untrusted claim. Exchange never resolves this marker to a local user.
        let document = json!({
            "resource_type": "connection", "id": issuer.id, "type": "oidc",
            "name": issuer.name, "issuer": issuer.issuer,
            "jwksEndpoint": issuer.jwks_endpoint, "tokenExchangeEnabled": true,
            "attributeConfiguration": {
                "user_type_resolution": {"default": "registry-exchange"},
                "user_type_attribute_mappings": [{
                    "user_type": "registry-exchange", "attributes": match issuer.mapping {
                        ExchangeMapping::InstitutionalGrant => json!([{
                            "external_attribute": "iss", "local_attribute": "registry_grant_source_issuer"
                        }]),
                        ExchangeMapping::FirstParty => json!(issuer.token_attributes.keys().map(|name| {
                            json!({"external_attribute": name, "local_attribute": name})
                        }).collect::<Vec<_>>()),
                    }
                }]
            }
        });
        write_owner_only(
            &root.join("connections").join(format!("{}.yaml", issuer.id)),
            yaml_document(&document)?.as_bytes(),
        )?;
    }

    if !description.interactive_applications.is_empty() {
        let mut schema = serde_json::Map::new();
        for name in ["username", "email", "password"] {
            schema.insert(
                name.into(),
                json!({
                    "type": "string", "displayName": name,
                    "required": name == "username" || name == "email",
                    "unique": name == "username" || name == "email",
                    "credential": name == "password",
                }),
            );
        }
        for name in description
            .synthetic_users
            .iter()
            .flat_map(|user| user.attributes.keys())
        {
            schema.entry(name.clone()).or_insert_with(|| {
                json!({
                    "type": "string", "displayName": name,
                })
            });
        }
        let user_type = json!({
            "resource_type": "user_type",
            "id": "0197aaaa-0000-7000-8000-000000000010",
            "category": "user", "name": "RegistryPerson", "ouHandle": description.organization_unit.handle,
            "allowSelfRegistration": false,
            "systemAttributes": {"display": "username"},
            "schema": schema,
        });
        write_owner_only(
            &root.join("user_types/registry-person.yaml"),
            yaml_document(&user_type)?.as_bytes(),
        )?;
    }
    for user in &description.synthetic_users {
        let password = fs::read_to_string(description.state_root.join(&user.password_file))
            .map_err(|_| ToolingError::Filesystem {
                reason: "a synthetic user password file could not be read",
            })?;
        if password.trim().len() < 12 || password.trim().len() > 256 {
            return Err(ToolingError::InvalidDescription {
                reason: "synthetic user passwords are 12..=256 bytes",
            });
        }
        let mut attributes = serde_json::Map::from_iter([
            ("username".into(), json!(user.username)),
            ("email".into(), json!(user.email)),
        ]);
        attributes.extend(
            user.attributes
                .iter()
                .map(|(name, value)| (name.clone(), json!(value))),
        );
        let document = json!({
            "resource_type": "user", "id": user.id, "type": "RegistryPerson",
            "ouHandle": description.organization_unit.handle,
            "attributes": attributes, "credentials": {"password": password.trim()},
        });
        write_owner_only(
            &root.join("users").join(format!("{}.yaml", user.id)),
            yaml_document(&document)?.as_bytes(),
        )?;
    }
    for app in &description.interactive_applications {
        let secret = fs::read_to_string(description.state_root.join(&app.client_secret_file))
            .map_err(|_| ToolingError::Filesystem {
                reason: "a browser application secret file could not be read",
            })?;
        if secret.trim().len() < 16 || secret.trim().len() > 256 {
            return Err(ToolingError::InvalidDescription {
                reason: "browser application secrets are 16..=256 bytes",
            });
        }
        let document = json!({
            "resource_type": "application", "id": app.id,
            "name": app.client_id, "description": "Synthetic local browser application",
            "type": "fullstack", "ouHandle": description.organization_unit.handle,
            "url": app.origin,
            "authFlowId": "01900000-0000-7000-8000-000000000068",
            "isRegistrationFlowEnabled": false, "isRecoveryFlowEnabled": false,
            "allowedUserTypes": ["RegistryPerson"],
            "inboundAuthConfig": [{"type": "oauth2", "config": {
                "clientId": app.client_id, "clientSecret": secret.trim(),
                "redirectUris": app.redirect_uris,
                "postLogoutRedirectUris": [app.origin],
                "grantTypes": ["authorization_code"], "responseTypes": ["code"],
                "tokenEndpointAuthMethod": "client_secret_post", "pkceRequired": true, "publicClient": false,
                "token": {"accessToken": {"defaultAudience": app.audience,
                    "userConfig": {"validityPeriod": 300, "attributes": app.token_attributes}},
                    "idToken": {"validityPeriod": 3600, "userAttributes": app.token_attributes}},
            }}],
        });
        write_owner_only(
            &root.join("applications").join(format!("{}.yaml", app.id)),
            yaml_document(&document)?.as_bytes(),
        )?;
    }

    for client in &description.machine_clients {
        // The upstream `Certificate.Value` is a string field carrying the
        // client's own JWKS JSON, which the client-assertion verifier
        // unmarshals from that string — not a nested object.
        let mut document = json!({
            "resource_type": "agent",
            "id": client.agent_id,
            "type": crate::description::DEFAULT_AGENT_TYPE,
            "ouHandle": description.organization_unit.handle,
            "name": client.name,
            "description": client.description,
            "attributes": client.attributes,
            "inboundAuthConfig": [
                {
                    "type": "oauth2",
                    "config": {
                        "clientId": client.client_id,
                        "grantTypes": ["client_credentials"],
                        "tokenEndpointAuthMethod": "private_key_jwt",
                        "publicClient": false,
                        "certificate": {
                            "type": "JWKS",
                            "value": client.public_jwks,
                        },
                        "token": {
                            "accessToken": {
                                "clientConfig": {
                                    "validityPeriod": client.access_token_lifetime_seconds,
                                    "attributes": client.token_attributes,
                                }
                            }
                        }
                    }
                }
            ]
        });
        if client.token_exchange.is_some() {
            let config = &mut document["inboundAuthConfig"][0]["config"];
            let first_party = description.exchange_issuers.iter().find(|issuer| {
                issuer.mapping == ExchangeMapping::FirstParty
                    && issuer.clients.iter().any(|id| id == &client.client_id)
            });
            let mut exchange_attributes = if let Some(issuer) = first_party {
                issuer.token_attributes.keys().cloned().collect::<Vec<_>>()
            } else {
                crate::description::GRANT_ATTRIBUTES
                    .iter()
                    .map(|attribute| (*attribute).to_owned())
                    .collect::<Vec<_>>()
            };
            for attribute in &client.token_attributes {
                if !exchange_attributes.contains(attribute) {
                    exchange_attributes.push(attribute.clone());
                }
            }
            config["grantTypes"] = json!([
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange"
            ]);
            config["token"]["accessToken"]["userConfig"] = json!({
                "validityPeriod": client.access_token_lifetime_seconds,
                "attributes": exchange_attributes,
            });
        }
        write_owner_only(
            &bootstrap_root
                .join("agents")
                .join(format!("{}.yaml", client.agent_id)),
            yaml_document(&document)?.as_bytes(),
        )?;
    }

    for client in &description.compatibility_clients {
        // The secret is read here, inside the private state directory, and
        // written straight into the owner-only agent document that carries
        // it. It never appears in a returned value, a log line, or an argv.
        let secret =
            fs::read_to_string(description.state_root.join(&client.secret_file)).map_err(|_| {
                ToolingError::Filesystem {
                    reason: "a compatibility client secret file could not be read",
                }
            })?;
        if secret.trim().is_empty() || secret.len() > 256 {
            return Err(ToolingError::InvalidDescription {
                reason: "a compatibility client secret file is 1..=256 bytes",
            });
        }
        let document = json!({
            "resource_type": "agent",
            "id": client.agent_id,
            "type": crate::description::DEFAULT_AGENT_TYPE,
            "ouHandle": description.organization_unit.handle,
            "name": client.name,
            "description": client.description,
            "inboundAuthConfig": [
                {
                    "type": "oauth2",
                    "config": {
                        "clientId": client.client_id,
                        "grantTypes": ["client_credentials"],
                        "tokenEndpointAuthMethod": client.method.as_str(),
                        "publicClient": false,
                        "clientSecret": secret.trim(),
                        "token": {
                            "accessToken": {
                                "clientConfig": {
                                    "validityPeriod": 300,
                                }
                            }
                        }
                    }
                }
            ]
        });
        write_owner_only(
            &bootstrap_root
                .join("agents")
                .join(format!("{}.yaml", client.agent_id)),
            yaml_document(&document)?.as_bytes(),
        )?;
    }

    let agent_type = agent_type_document(description)?;
    write_owner_only(
        &bootstrap_root.join("agent-type.yaml"),
        agent_type.as_bytes(),
    )?;
    let digest = Sha256::digest(agent_type.as_bytes());

    Ok(RenderedResources {
        resources_dir: root,
        bootstrap_dir: bootstrap_root,
        agent_type_document: agent_type,
        agent_type_sha256: hex(&digest),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pinned_default_agent_schema_is_preserved_and_only_extended() {
        let pinned: Value = serde_yaml_parse(PINNED_DEFAULT_AGENT_TYPE).expect("pinned parses");
        let description = crate::testing::synthetic_description();
        let extended_text = agent_type_document(&description).expect("the schema renders");
        let extended: Value = serde_yaml_parse(&extended_text).expect("the extension parses");

        assert_eq!(extended["id"], pinned["id"], "the default type id changed");
        assert_eq!(extended["name"], pinned["name"]);
        assert_eq!(
            extended["schema"]["modelProvider"], pinned["schema"]["modelProvider"],
            "an upstream attribute was altered"
        );
        // The appended attribute is optional and additive.
        assert_eq!(
            extended["schema"]["synthetic_tag"]["required"],
            json!(false),
            "an appended attribute must stay optional"
        );
        assert_eq!(extended["schema"]["synthetic_tag"]["type"], json!("string"));
        // No administrator/user/role material exists in the document at all.
        for forbidden in ["password", "username", "role", "administrator"] {
            assert!(
                !extended_text.to_lowercase().contains(forbidden),
                "the schema document mentions {forbidden}"
            );
        }
    }

    #[test]
    fn a_full_description_renders_upstream_shaped_documents() {
        let mut description = crate::testing::synthetic_description();
        // A fresh state root per run: rendering refuses to overwrite, which
        // is the property under test elsewhere.
        description.state_root = std::env::temp_dir().join(format!(
            "registry-thunderid-tooling-render-{}-{:p}",
            std::process::id(),
            &description
        ));
        let _ = std::fs::remove_dir_all(&description.state_root);
        std::fs::create_dir_all(description.state_root.join("secrets"))
            .expect("the secrets directory exists");
        std::fs::write(
            description
                .state_root
                .join("secrets/compatibility-client-secret"),
            "fixture-secret-not-a-real-credential",
        )
        .expect("the fixture compatibility secret exists");
        let rendered = render(&description).expect("the description renders");
        let agent_text = fs::read_to_string(
            rendered
                .bootstrap_dir
                .join("agents/0197aaaa-0000-7000-8000-0000000000a1.yaml"),
        )
        .expect("the machine agent document exists");
        let agent: Value = serde_norway::from_str(&agent_text).expect("the agent document parses");
        assert_eq!(agent["resource_type"], json!("agent"));
        assert_eq!(agent["type"], json!("default"));
        let config = &agent["inboundAuthConfig"][0]["config"];
        assert_eq!(config["grantTypes"], json!(["client_credentials"]));
        assert_eq!(config["tokenEndpointAuthMethod"], json!("private_key_jwt"));
        assert_eq!(config["publicClient"], json!(false));
        assert_eq!(config["certificate"]["type"], json!("JWKS"));
        // The value is the JWKS JSON as a string — upstream's Certificate
        // field is a string — and it is this client's own key set, never a
        // pooled one.
        let embedded: Value = serde_json::from_str(
            config["certificate"]["value"]
                .as_str()
                .expect("the JWKS is embedded as a string"),
        )
        .expect("the embedded JWKS is JSON");
        assert_eq!(embedded["keys"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            config["token"]["accessToken"]["clientConfig"]["validityPeriod"],
            json!(300)
        );

        let server_text = fs::read_to_string(
            rendered
                .resources_dir
                .join("resource_servers/0197aaaa-0000-7000-8000-0000000000b1.yaml"),
        )
        .expect("the resource server document exists");
        let server: Value = serde_norway::from_str(&server_text).expect("it parses");
        assert_eq!(
            server["identifier"],
            json!("urn:registry:tooling-test:evidence")
        );
        assert_eq!(server["resources"][0]["handle"], json!("evidence"));
        assert_eq!(
            server["resources"][0]["actions"][0]["handle"],
            json!("invoke")
        );

        let role_text = fs::read_to_string(
            rendered
                .resources_dir
                .join("roles/0197aaaa-0000-7000-8000-0000000000c1.yaml"),
        )
        .expect("the role document exists");
        let role: Value = serde_norway::from_str(&role_text).expect("it parses");
        assert_eq!(
            role["permissions"][0]["permissions"],
            json!(["evidence:invoke"])
        );
        assert_eq!(role["assignments"][0]["type"], json!("agent"));
    }

    #[test]
    fn rendering_keeps_permissions_inside_the_declared_state_root() {
        let parent = std::env::temp_dir().join(format!(
            "registry-thunderid-tooling-parent-{}",
            crate::container::random_urlsafe(16).unwrap()
        ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();

        let mut description = crate::testing::synthetic_description();
        description.state_root = parent.join("state");
        fs::create_dir_all(description.state_root.join("secrets")).unwrap();
        fs::write(
            description
                .state_root
                .join("secrets/compatibility-client-secret"),
            "fixture-secret-not-a-real-credential",
        )
        .unwrap();

        render(&description).expect("the description renders");
        assert_eq!(
            fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o755,
            "rendering must not chmod an ancestor outside the state root"
        );
        assert_eq!(
            fs::metadata(&description.state_root)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "the declared state root must be owner-only"
        );

        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn exchange_uses_native_user_config_and_unconditional_verified_issuer_mapping() {
        use crate::description::{ExchangeIssuer, TokenExchangeClient, GRANT_ATTRIBUTES};
        let mut description = crate::testing::synthetic_description();
        description.compatibility_clients.clear();
        description.state_root = std::env::temp_dir().join(format!(
            "registry-exchange-render-{}",
            crate::container::random_urlsafe(16).unwrap()
        ));
        fs::create_dir(&description.state_root).unwrap();
        fs::set_permissions(&description.state_root, fs::Permissions::from_mode(0o700)).unwrap();
        description.exchange_issuers.push(ExchangeIssuer {
            id: "0197aaaa-0000-7000-8000-0000000000d1".into(),
            name: "Authority".into(),
            issuer: "https://authority.example".into(),
            jwks_endpoint: "https://authority.example/jwks".into(),
            mapping: ExchangeMapping::InstitutionalGrant,
            clients: vec![],
            token_attributes: Default::default(),
        });
        description.machine_clients[0].token_exchange = Some(TokenExchangeClient {
            assertion_resource_server_id: description.resource_servers[0].id.clone(),
            assertion_scope: "evidence:invoke".into(),
        });
        let rendered = render(&description).unwrap();
        let agent = serde_yaml_parse(
            &fs::read_to_string(
                rendered
                    .bootstrap_dir
                    .join("agents/0197aaaa-0000-7000-8000-0000000000a1.yaml"),
            )
            .unwrap(),
        )
        .unwrap();
        let config = &agent["inboundAuthConfig"][0]["config"];
        assert_eq!(
            config["grantTypes"],
            json!([
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange"
            ])
        );
        assert_eq!(
            config["token"]["accessToken"]["userConfig"]["attributes"],
            json!(GRANT_ATTRIBUTES
                .iter()
                .copied()
                .chain(["synthetic_tag"])
                .collect::<Vec<_>>())
        );
        assert_eq!(
            config["token"]["accessToken"]["clientConfig"]["attributes"],
            json!(["synthetic_tag"])
        );
        let connection = serde_yaml_parse(
            &fs::read_to_string(
                rendered
                    .resources_dir
                    .join("connections/0197aaaa-0000-7000-8000-0000000000d1.yaml"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(connection["resource_type"], "connection");
        assert_eq!(connection["tokenExchangeEnabled"], true);
        assert_eq!(
            connection["attributeConfiguration"]["user_type_resolution"],
            json!({"default":"registry-exchange"})
        );
        assert_eq!(
            connection["attributeConfiguration"]["user_type_attribute_mappings"][0]["attributes"],
            json!([{"external_attribute":"iss","local_attribute":"registry_grant_source_issuer"}])
        );
        assert!(
            render(&description).is_err(),
            "a second render must not overwrite session resources"
        );
        fs::remove_dir_all(&description.state_root).unwrap();
    }

    #[test]
    fn first_party_exchange_projects_only_declared_signed_claims() {
        use crate::description::{ExchangeAttributeKind, ExchangeIssuer, TokenExchangeClient};
        let mut description = crate::testing::synthetic_description();
        description.compatibility_clients.clear();
        description.state_root = std::env::temp_dir().join(format!(
            "registry-first-party-render-{}",
            crate::container::random_urlsafe(16).unwrap()
        ));
        fs::create_dir(&description.state_root).unwrap();
        fs::set_permissions(&description.state_root, fs::Permissions::from_mode(0o700)).unwrap();
        description.exchange_issuers.push(ExchangeIssuer {
            id: "0197aaaa-0000-7000-8000-0000000000d1".into(),
            name: "Local portal".into(),
            issuer: "http://127.0.0.1:3030".into(),
            jwks_endpoint: "http://host.docker.internal:3030/.well-known/jwks.json".into(),
            mapping: ExchangeMapping::FirstParty,
            clients: vec!["synthetic-machine-client".into()],
            token_attributes: [
                ("evidence_audience".into(), ExchangeAttributeKind::String),
                ("evidence_tags".into(), ExchangeAttributeKind::StringArray),
                ("registry_principal".into(), ExchangeAttributeKind::String),
            ]
            .into(),
        });
        description.machine_clients[0].token_exchange = Some(TokenExchangeClient {
            assertion_resource_server_id: description.resource_servers[0].id.clone(),
            assertion_scope: "evidence:invoke".into(),
        });
        let rendered = render(&description).unwrap();
        let connection: Value = serde_yaml_parse(
            &fs::read_to_string(
                rendered
                    .resources_dir
                    .join("connections/0197aaaa-0000-7000-8000-0000000000d1.yaml"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            connection["attributeConfiguration"]["user_type_attribute_mappings"][0]["attributes"],
            json!([
                {"external_attribute":"evidence_audience","local_attribute":"evidence_audience"},
                {"external_attribute":"evidence_tags","local_attribute":"evidence_tags"},
                {"external_attribute":"registry_principal","local_attribute":"registry_principal"},
            ])
        );
        let agent: Value = serde_yaml_parse(
            &fs::read_to_string(
                rendered
                    .bootstrap_dir
                    .join("agents/0197aaaa-0000-7000-8000-0000000000a1.yaml"),
            )
            .unwrap(),
        )
        .unwrap();
        let attributes = &agent["inboundAuthConfig"][0]["config"]["token"]["accessToken"]
            ["userConfig"]["attributes"];
        assert!(attributes
            .as_array()
            .unwrap()
            .contains(&json!("evidence_tags")));
        assert!(!attributes
            .as_array()
            .unwrap()
            .contains(&json!("registry_grant_id")));
        let schema: Value = serde_yaml_parse(&rendered.agent_type_document).unwrap();
        assert_eq!(schema["schema"]["evidence_tags"]["type"], "array");
        fs::remove_dir_all(&description.state_root).unwrap();
    }

    #[test]
    fn synthetic_browser_resources_use_pkce_and_explicit_user_attributes() {
        use crate::description::{InteractiveApplication, SyntheticUser};
        let mut description = crate::testing::synthetic_description();
        description.compatibility_clients.clear();
        description.state_root = std::env::temp_dir().join(format!(
            "registry-browser-render-{}",
            crate::container::random_urlsafe(16).unwrap()
        ));
        fs::create_dir(&description.state_root).unwrap();
        fs::set_permissions(&description.state_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(description.state_root.join("secrets")).unwrap();
        fs::set_permissions(
            description.state_root.join("secrets"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(
            description.state_root.join("secrets/app"),
            "synthetic-application-secret",
        )
        .unwrap();
        fs::write(
            description.state_root.join("secrets/user"),
            "synthetic-user-password",
        )
        .unwrap();
        description
            .interactive_applications
            .push(InteractiveApplication {
                id: "0197aaaa-0000-7000-8000-0000000000e1".into(),
                client_id: "synthetic-browser".into(),
                client_secret_file: "secrets/app".into(),
                origin: "http://127.0.0.1:3000".into(),
                redirect_uris: vec!["http://127.0.0.1:3000/auth/callback".into()],
                audience: description.resource_servers[0].identifier.clone(),
                token_attributes: vec!["registry_role".into()],
            });
        description.synthetic_users.push(SyntheticUser {
            id: "0197aaaa-0000-7000-8000-0000000000e2".into(),
            username: "staff-one".into(),
            email: "staff-one@example.test".into(),
            password_file: "secrets/user".into(),
            attributes: std::collections::BTreeMap::from([(
                "registry_role".into(),
                "staff".into(),
            )]),
        });
        description.roles[0]
            .assigned_users
            .push("0197aaaa-0000-7000-8000-0000000000e2".into());
        description.roles[0]
            .assigned_applications
            .push("0197aaaa-0000-7000-8000-0000000000e1".into());
        let rendered = render(&description).unwrap();
        let role: Value = serde_yaml_parse(
            &fs::read_to_string(
                rendered
                    .resources_dir
                    .join("roles/0197aaaa-0000-7000-8000-0000000000c1.yaml"),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(role["assignments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|assignment| assignment["type"] == "user"));
        assert!(role["assignments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|assignment| assignment["type"] == "app"));
        let app: Value = serde_yaml_parse(
            &fs::read_to_string(
                rendered
                    .resources_dir
                    .join("applications/0197aaaa-0000-7000-8000-0000000000e1.yaml"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(app["inboundAuthConfig"][0]["config"]["pkceRequired"], true);
        assert_eq!(
            app["inboundAuthConfig"][0]["config"]["token"]["accessToken"]["userConfig"]
                ["attributes"],
            json!(["registry_role"])
        );
        assert!(rendered
            .resources_dir
            .join("users/0197aaaa-0000-7000-8000-0000000000e2.yaml")
            .exists());
        fs::remove_dir_all(&description.state_root).unwrap();
    }
}

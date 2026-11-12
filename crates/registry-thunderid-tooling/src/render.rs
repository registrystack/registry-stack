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

use crate::description::{
    ExchangeAttributeKind, ExchangeMapping, IssuerDescription, ASSERTION_ISSUER_CLAIM,
};
use crate::ToolingError;

/// The pinned release's default `agent_type` document for the `default`
/// agent type, byte-for-byte as the image ships it. The schema update starts
/// from this and only appends optional attributes; it never rewrites,
/// renames, or drops upstream fields, and a deployment sharing this schema
/// with other agents merges rather than overwrites.
const PINNED_DEFAULT_AGENT_TYPE: &str = include_str!("../fixtures/default-agent-type-v1.0.1.yaml");
const INSTITUTIONAL_REQUESTER_ATTRIBUTES: [&str; 2] = ["evidence_audience", "evidence_tags"];
const BRANDING_METADATA: &str =
    include_str!("../../../products/identity/thunderid/branding/branding.json");
const BRANDING_THEME: &str =
    include_str!("../../../products/identity/thunderid/branding/theme.json");
const BRANDING_STYLESHEET: &str =
    include_str!("../../../products/identity/thunderid/branding/registry-stack.css");
const BRANDING_WORDMARK: &[u8] = include_bytes!(
    "../../../products/identity/thunderid/branding/assets/registry-stack-wordmark.svg"
);
const BRANDING_FONT: &[u8] = include_bytes!(
    "../../../products/identity/thunderid/branding/assets/fonts/public-sans-latin-wght-normal.woff2"
);
const BRANDING_FONT_LICENSE: &[u8] = include_bytes!(
    "../../../products/identity/thunderid/branding/assets/fonts/OFL-public-sans.txt"
);

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
/// Public presentation files rendered only for sessions with an interactive
/// application. The container mounts exactly this directory into Gate's
/// static asset tree, leaving the image's application files untouched.
pub const BRANDING_ASSETS_DIR: &str = "branding-assets";

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrandingMetadata {
    theme_id: String,
    layout_id: String,
    asset_base_path: String,
}

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
    let institutional = description
        .exchange_issuers
        .iter()
        .any(|issuer| issuer.mapping == ExchangeMapping::InstitutionalGrant);
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
        .chain(
            INSTITUTIONAL_REQUESTER_ATTRIBUTES
                .iter()
                .filter(|_| institutional)
                .map(|name| (*name).to_owned()),
        )
        .collect();
    for name in names {
        let array = (institutional && name == "evidence_tags")
            || description.exchange_issuers.iter().any(|issuer| {
                issuer.token_attributes.get(&name) == Some(&ExchangeAttributeKind::StringArray)
            })
            || description
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

#[allow(
    clippy::disallowed_methods,
    reason = "platform/thunderid-resources is registered as an external format: ThunderID owns the grammar of the pinned upstream document and of this crate's rendering of it (CFG-YAML-1)"
)]
fn serde_yaml_parse(text: &str) -> Result<Value, ToolingError> {
    serde_norway::from_str(text).map_err(|_| ToolingError::InvalidRender {
        reason: "a pinned upstream document did not parse",
    })
}

fn branding_metadata() -> Result<BrandingMetadata, ToolingError> {
    let metadata: BrandingMetadata =
        serde_json::from_str(BRANDING_METADATA).map_err(|_| ToolingError::InvalidRender {
            reason: "the embedded Registry Stack branding metadata did not parse",
        })?;
    if !metadata.asset_base_path.starts_with('/')
        || metadata.asset_base_path.starts_with("//")
        || metadata.asset_base_path.ends_with('/')
    {
        return Err(ToolingError::InvalidRender {
            reason: "the embedded Registry Stack asset path is not a root-relative directory",
        });
    }
    Ok(metadata)
}

fn render_branding(
    outputs: &mut Vec<Output>,
    assets: bool,
) -> Result<BrandingMetadata, ToolingError> {
    let metadata = branding_metadata()?;
    let mut theme: Value =
        serde_json::from_str(BRANDING_THEME).map_err(|_| ToolingError::InvalidRender {
            reason: "the embedded Registry Stack theme did not parse",
        })?;
    let Some(theme_fields) = theme.as_object_mut() else {
        return Err(ToolingError::InvalidRender {
            reason: "the embedded Registry Stack theme is not an object",
        });
    };
    theme_fields.insert("resource_type".into(), json!("theme"));
    theme_fields.insert("id".into(), json!(&metadata.theme_id));
    emit(
        outputs,
        Area::Resources,
        format!("themes/{}.yaml", metadata.theme_id),
        &theme,
    )?;

    let layout = json!({
        "resource_type": "layout",
        "id": metadata.layout_id,
        "handle": "registry-stack",
        "displayName": "Registry Stack",
        "layout": {
            "head": {
                "stylesheets": [{
                    "id": "registry-stack",
                    "type": "inline",
                    "content": BRANDING_STYLESHEET,
                }]
            }
        },
    });
    emit(
        outputs,
        Area::Resources,
        format!("layouts/{}.yaml", metadata.layout_id),
        &layout,
    )?;

    if assets {
        for (path, bytes) in [
            ("registry-stack-wordmark.svg", BRANDING_WORDMARK),
            ("fonts/public-sans-latin-wght-normal.woff2", BRANDING_FONT),
            ("fonts/OFL-public-sans.txt", BRANDING_FONT_LICENSE),
        ] {
            outputs.push(Output {
                area: Area::Assets,
                path: path.into(),
                bytes: bytes.to_vec(),
            });
        }
    }
    Ok(metadata)
}

/// Where a rendered document lands, relative to the output's roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Area {
    /// The serving-time documents (`resources/`).
    Resources,
    /// The bootstrap provisioning directory (`registry-schema/`).
    Bootstrap,
    /// Public branding files (`branding-assets/`).
    Assets,
}

/// One rendered file: its area, its path inside the area, and its bytes.
#[derive(Debug, Clone)]
pub(crate) struct Output {
    pub area: Area,
    pub path: std::path::PathBuf,
    pub bytes: Vec<u8>,
}

/// A user type beyond the generated `RegistryPerson`.
#[derive(Debug, Clone)]
pub(crate) struct ExtensionUserType {
    pub id: String,
    pub name: String,
    /// Optional string attributes, beyond username, email and password.
    pub attributes: Vec<String>,
}

/// What a hosted deployment states that the closed description does not
/// carry: extension user types, which type each user and application uses,
/// and each application's public logo.
#[derive(Debug, Clone, Default)]
pub(crate) struct DeploymentExtras {
    pub user_types: Vec<ExtensionUserType>,
    /// User id to the name of its extension user type.
    pub user_type_of: std::collections::BTreeMap<String, String>,
    /// Application id to the extension user types it admits.
    pub app_user_types: std::collections::BTreeMap<String, Vec<String>>,
    /// Application id to its public logo URL.
    pub app_logo_urls: std::collections::BTreeMap<String, String>,
}

/// How secrets reach the rendered documents.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Mode<'a> {
    /// A development session: each secret is read from its owner-only file
    /// under this root and written into the rendered document.
    Development { root: &'a Path },
    /// A hosted deployment: no secret is opened. Each secret renders as the
    /// `{{.NAME}}` placeholder ThunderID substitutes from its environment,
    /// where `NAME` is the final component of the secret's path.
    Deployment { extras: &'a DeploymentExtras },
}

impl Mode<'_> {
    fn extras(&self) -> Option<&DeploymentExtras> {
        match self {
            Self::Development { .. } => None,
            Self::Deployment { extras } => Some(extras),
        }
    }

    /// The text a document carries for the secret at `path`. In development
    /// the file is read and `check` refuses an unusable value; in a
    /// deployment `check` never runs because no value exists.
    fn secret(
        &self,
        path: &Path,
        unreadable: &'static str,
        check: impl FnOnce(&str) -> Result<(), ToolingError>,
    ) -> Result<String, ToolingError> {
        match self {
            Self::Development { root } => {
                let raw = fs::read_to_string(root.join(path))
                    .map_err(|_| ToolingError::Filesystem { reason: unreadable })?;
                check(&raw)?;
                Ok(raw.trim().to_owned())
            }
            Self::Deployment { .. } => {
                let name = path.file_name().and_then(|name| name.to_str()).ok_or(
                    ToolingError::InvalidRender {
                        reason: "a secret placeholder has no name",
                    },
                )?;
                Ok(format!("{{{{.{name}}}}}"))
            }
        }
    }
}

/// Everything one render produces, before any file is written.
#[derive(Debug)]
pub(crate) struct Built {
    pub outputs: Vec<Output>,
    pub agent_type: String,
}

fn emit(
    outputs: &mut Vec<Output>,
    area: Area,
    path: impl Into<std::path::PathBuf>,
    document: &Value,
) -> Result<(), ToolingError> {
    outputs.push(Output {
        area,
        path: path.into(),
        bytes: yaml_document(document)?.into_bytes(),
    });
    Ok(())
}

/// Native ThunderID 1.0.1 Basic SSO flow, specialized only by stable identity
/// and display text. The graph follows the Apache-2.0 upstream template at
/// ThunderID commit `12f517c4384004e360e26eb7eb1ab0501b678bb2`, file
/// `frontend/apps/console/src/features/flows/data/templates.json` (`BASIC_SSO`):
/// the SSO checkpoint may skip credential entry, but never the authorization
/// check or authentication assertion.
fn browser_authentication_flow(description: &IssuerDescription, app_id: &str, name: &str) -> Value {
    let id = crate::local::application_authentication_flow_id(&description.session.id, app_id);
    json!({
        "resource_type": "flow",
        "id": id,
        "name": format!("{name} sign-in"),
        "handle": format!("registry-auth-{id}"),
        "flowType": "AUTHENTICATION",
        "nodes": [
            {"id": "start", "type": "START", "onSuccess": "sso_check"},
            {
                "id": "sso_check", "type": "TASK_EXECUTION",
                "properties": {"checkpointRef": "session"},
                "executor": {"name": "SSOCheckExecutor"},
                "onSuccess": "session", "onFailure": "prompt_credentials",
            },
            {
                "id": "prompt_credentials", "type": "PROMPT",
                "meta": {"components": [
                    {
                        "alt": "{{ t(signin:images.app_logo.alt) }}",
                        "category": "DISPLAY", "height": "60", "id": "image",
                        "resourceType": "ELEMENT",
                        "src": "{{ meta(application.logoUrl) }}", "type": "IMAGE", "width": "",
                    },
                    {
                        "align": "center", "category": "DISPLAY", "id": "text_001",
                        "label": "{{ t(signin:forms.credentials.title) }}",
                        "resourceType": "ELEMENT", "type": "TEXT", "variant": "HEADING_1",
                    },
                    {
                        "category": "BLOCK", "id": "block_001", "resourceType": "ELEMENT",
                        "type": "BLOCK", "components": [
                            {
                                "category": "FIELD", "hint": "", "id": "input_001",
                                "inputType": "text",
                                "label": "{{ t(signin:forms.credentials.fields.username.label) }}",
                                "placeholder": "{{ t(signin:forms.credentials.fields.username.placeholder) }}",
                                "ref": "username", "required": true,
                                "resourceType": "ELEMENT", "type": "TEXT_INPUT",
                            },
                            {
                                "category": "FIELD", "hint": "", "id": "input_002",
                                "inputType": "text",
                                "label": "{{ t(signin:forms.credentials.fields.password.label) }}",
                                "placeholder": "{{ t(signin:forms.credentials.fields.password.placeholder) }}",
                                "ref": "password", "required": true,
                                "resourceType": "ELEMENT", "type": "PASSWORD_INPUT",
                            },
                            {
                                "category": "ACTION", "eventType": "SUBMIT", "id": "action_001",
                                "label": "{{ t(signin:forms.credentials.actions.submit.label) }}",
                                "resourceType": "ELEMENT", "type": "ACTION", "variant": "PRIMARY",
                            },
                        ],
                    },
                ]},
                "prompts": [{
                    "inputs": [
                        {"ref": "input_001", "type": "TEXT_INPUT", "identifier": "username", "required": true},
                        {"ref": "input_002", "type": "PASSWORD_INPUT", "identifier": "password", "required": true},
                    ],
                    "action": {"ref": "action_001", "nextNode": "credentials_auth"},
                }],
            },
            {
                "id": "credentials_auth", "type": "TASK_EXECUTION",
                "executor": {
                    "name": "CredentialsAuthExecutor",
                    "inputs": [
                        {"ref": "input_001", "type": "TEXT_INPUT", "identifier": "username", "required": true},
                        {"ref": "input_002", "type": "PASSWORD_INPUT", "identifier": "password", "required": true},
                    ],
                },
                "onSuccess": "session", "onIncomplete": "prompt_credentials",
            },
            {
                "id": "session", "type": "TASK_EXECUTION",
                "executor": {"name": "SessionExecutor"},
                "onSuccess": "authorization_check",
            },
            {
                "id": "authorization_check", "type": "TASK_EXECUTION",
                "executor": {"name": "AuthorizationExecutor"},
                "onSuccess": "auth_assert",
            },
            {
                "id": "auth_assert", "type": "TASK_EXECUTION",
                "executor": {"name": "AuthAssertExecutor"}, "onSuccess": "end",
            },
            {"id": "end", "type": "END"},
        ],
    })
}

/// Native ThunderID 1.0.1 Conditional Confirmation sign-out flow from the same
/// pinned Apache-2.0 upstream template file. App Kit sends a client id without
/// an ID-token hint, so `promptOnSignOut` must stay true: the issuer asks the
/// person before ending that app's SSO session.
fn browser_sign_out_flow(description: &IssuerDescription) -> Value {
    let id = crate::local::browser_sign_out_flow_id(&description.session.id);
    json!({
        "resource_type": "flow",
        "id": id,
        "name": "Registry browser sign-out",
        "handle": format!("registry-signout-{id}"),
        "flowType": "SIGNOUT",
        "nodes": [
            {"id": "start", "type": "START", "onSuccess": "session_signout"},
            {
                "id": "session_signout", "type": "TASK_EXECUTION",
                "properties": {"promptOnSignOut": true},
                "executor": {"name": "SessionSignOutExecutor"},
                "onSuccess": "end", "onIncomplete": "prompt_confirm",
            },
            {
                "id": "prompt_confirm", "type": "PROMPT",
                "meta": {"components": [
                    {
                        "align": "center", "category": "DISPLAY", "id": "text_signout_title",
                        "label": "{{ t(signout:forms.confirm.title) }}", "resourceType": "ELEMENT",
                        "type": "TEXT", "variant": "HEADING_1",
                    },
                    {
                        "align": "center", "category": "DISPLAY", "id": "text_signout_desc",
                        "label": "{{ t(signout:forms.confirm.description) }}", "resourceType": "ELEMENT",
                        "type": "TEXT", "variant": "BODY_1",
                    },
                    {
                        "category": "BLOCK", "id": "block_signout", "resourceType": "ELEMENT",
                        "type": "BLOCK", "components": [{
                            "actionType": "CONFIRM", "category": "ACTION", "eventType": "SUBMIT",
                            "id": "action_confirm",
                            "label": "{{ t(signout:forms.confirm.actions.submit.label) }}",
                            "resourceType": "ELEMENT", "type": "ACTION", "variant": "PRIMARY",
                        }],
                    },
                ]},
                "prompts": [{"action": {
                    "ref": "action_confirm", "type": "CONFIRM", "nextNode": "session_signout",
                }}],
            },
            {"id": "end", "type": "END"},
        ],
    })
}

/// Fixed Gate expressions emitted by the two pinned native flow graphs. The
/// hosted generator checks these exact multiplicities beside its secret
/// placeholders, so an authored string still cannot introduce template syntax.
pub(crate) fn gate_template_expression_counts(
    browser_applications: usize,
) -> [(&'static str, usize); 11] {
    let sign_out = usize::from(browser_applications > 0);
    [
        ("{{ t(signin:images.app_logo.alt) }}", browser_applications),
        ("{{ meta(application.logoUrl) }}", browser_applications),
        (
            "{{ t(signin:forms.credentials.title) }}",
            browser_applications,
        ),
        (
            "{{ t(signin:forms.credentials.fields.username.label) }}",
            browser_applications,
        ),
        (
            "{{ t(signin:forms.credentials.fields.username.placeholder) }}",
            browser_applications,
        ),
        (
            "{{ t(signin:forms.credentials.fields.password.label) }}",
            browser_applications,
        ),
        (
            "{{ t(signin:forms.credentials.fields.password.placeholder) }}",
            browser_applications,
        ),
        (
            "{{ t(signin:forms.credentials.actions.submit.label) }}",
            browser_applications,
        ),
        ("{{ t(signout:forms.confirm.title) }}", sign_out),
        ("{{ t(signout:forms.confirm.description) }}", sign_out),
        (
            "{{ t(signout:forms.confirm.actions.submit.label) }}",
            sign_out,
        ),
    ]
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
    let built = build(
        description,
        &Mode::Development {
            root: &description.state_root,
        },
    )?;
    for output in &built.outputs {
        let base = match output.area {
            Area::Resources => &root,
            Area::Bootstrap => &bootstrap_root,
            Area::Assets => &description.state_root.join(BRANDING_ASSETS_DIR),
        };
        write_owner_only(&base.join(&output.path), &output.bytes)?;
    }
    let digest = Sha256::digest(built.agent_type.as_bytes());
    Ok(RenderedResources {
        resources_dir: root,
        bootstrap_dir: bootstrap_root,
        agent_type_sha256: hex(&digest),
        agent_type_document: built.agent_type,
    })
}

/// Build every document for one validated description without writing any.
pub(crate) fn build(
    description: &IssuerDescription,
    mode: &Mode<'_>,
) -> Result<Built, ToolingError> {
    let mut outputs = Vec::new();
    let extras = mode.extras();
    let ou_handle = &description.organization_unit.handle;
    let branding = if description.interactive_applications.is_empty() {
        None
    } else {
        Some(render_branding(
            &mut outputs,
            matches!(mode, Mode::Development { .. }),
        )?)
    };

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
        emit(
            &mut outputs,
            Area::Resources,
            format!(
                "organization_units/{}.yaml",
                description.organization_unit.handle
            ),
            &organization,
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
            "ouHandle": ou_handle,
            "delimiter": ":",
            "resources": resources,
        });
        emit(
            &mut outputs,
            Area::Resources,
            format!("resource_servers/{}.yaml", server.id),
            &document,
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
            "ouHandle": ou_handle,
            "permissions": permissions,
            "assignments": assignments,
        });
        emit(
            &mut outputs,
            Area::Resources,
            format!("roles/{}.yaml", role.id),
            &document,
        )?;
    }

    for issuer in &description.exchange_issuers {
        // Fixed user-type resolution selects mappings without consulting any
        // untrusted claim. Exchange never resolves this marker to a local user.
        //
        // Every connection projects the verified `iss` into the assertion
        // issuer claim, so a first-party assertion carries the same provable
        // provenance an institutional grant does. The signer cannot choose the
        // value and cannot declare the claim itself: `protected_attribute`
        // keeps it out of first-party token attributes.
        let mut attributes = vec![json!({
            "external_attribute": "iss", "local_attribute": ASSERTION_ISSUER_CLAIM
        })];
        attributes.extend(match issuer.mapping {
            ExchangeMapping::InstitutionalGrant => vec![
                json!({"external_attribute": "iss", "local_attribute": "registry_grant_source_issuer"}),
                json!({"external_attribute": "evidence_audience", "local_attribute": "evidence_audience"}),
                json!({"external_attribute": "evidence_tags", "local_attribute": "evidence_tags"}),
            ],
            ExchangeMapping::FirstParty => issuer
                .token_attributes
                .keys()
                .map(|name| json!({"external_attribute": name, "local_attribute": name}))
                .collect(),
        });
        let document = json!({
            "resource_type": "connection", "id": issuer.id, "type": "oidc",
            "name": issuer.name, "issuer": issuer.issuer,
            "jwksEndpoint": issuer.jwks_endpoint, "tokenExchangeEnabled": true,
            "attributeConfiguration": {
                "user_type_resolution": {"default": "registry-exchange"},
                "user_type_attribute_mappings": [{
                    "user_type": "registry-exchange", "attributes": attributes
                }]
            }
        });
        emit(
            &mut outputs,
            Area::Resources,
            format!("connections/{}.yaml", issuer.id),
            &document,
        )?;
    }

    let user_type_name = |user_id: &str| {
        extras
            .and_then(|extras| extras.user_type_of.get(user_id))
            .map_or("RegistryPerson", String::as_str)
    };
    let user_schema = |attributes: &mut dyn Iterator<Item = &String>| {
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
        for name in attributes {
            schema.entry(name.clone()).or_insert_with(|| {
                json!({
                    "type": "string", "displayName": name,
                })
            });
        }
        schema
    };
    if !description.interactive_applications.is_empty() {
        let schema = user_schema(
            &mut description
                .synthetic_users
                .iter()
                .filter(|user| user_type_name(&user.id) == "RegistryPerson")
                .flat_map(|user| user.attributes.keys()),
        );
        let user_type = json!({
            "resource_type": "user_type",
            "id": "0197aaaa-0000-7000-8000-000000000010",
            "category": "user", "name": "RegistryPerson", "ouHandle": ou_handle,
            "allowSelfRegistration": false,
            "systemAttributes": {"display": "username"},
            "schema": schema,
        });
        emit(
            &mut outputs,
            Area::Resources,
            "user_types/registry-person.yaml",
            &user_type,
        )?;
    }
    for extension in extras.iter().flat_map(|extras| &extras.user_types) {
        let schema = user_schema(
            &mut extension.attributes.iter().chain(
                description
                    .synthetic_users
                    .iter()
                    .filter(|user| user_type_name(&user.id) == extension.name)
                    .flat_map(|user| user.attributes.keys()),
            ),
        );
        let user_type = json!({
            "resource_type": "user_type",
            "id": extension.id,
            "category": "user", "name": extension.name, "ouHandle": ou_handle,
            "allowSelfRegistration": false,
            "systemAttributes": {"display": "username"},
            "schema": schema,
        });
        emit(
            &mut outputs,
            Area::Resources,
            format!("user_types/{}.yaml", extension.id),
            &user_type,
        )?;
    }
    for user in &description.synthetic_users {
        let password = mode.secret(
            &user.password_file,
            "a synthetic user password file could not be read",
            |password| {
                if password.trim().len() < 12 || password.trim().len() > 256 {
                    return Err(ToolingError::InvalidDescription {
                        reason: "synthetic user passwords are 12..=256 bytes",
                    });
                }
                Ok(())
            },
        )?;
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
            "resource_type": "user", "id": user.id, "type": user_type_name(&user.id),
            "ouHandle": ou_handle,
            "attributes": attributes, "credentials": {"password": password},
        });
        emit(
            &mut outputs,
            Area::Resources,
            format!("users/{}.yaml", user.id),
            &document,
        )?;
    }
    let sign_out_flow_id = (!description.interactive_applications.is_empty())
        .then(|| crate::local::browser_sign_out_flow_id(&description.session.id));
    if let Some(id) = &sign_out_flow_id {
        emit(
            &mut outputs,
            Area::Resources,
            format!("flows/{id}.yaml"),
            &browser_sign_out_flow(description),
        )?;
    }
    for app in &description.interactive_applications {
        let branding = branding
            .as_ref()
            .expect("interactive applications render branding");
        let secret = mode.secret(
            &app.client_secret_file,
            "a browser application secret file could not be read",
            |secret| {
                if secret.trim().len() < 16 || secret.trim().len() > 256 {
                    return Err(ToolingError::InvalidDescription {
                        reason: "browser application secrets are 16..=256 bytes",
                    });
                }
                Ok(())
            },
        )?;
        let mut allowed_user_types = vec![json!("RegistryPerson")];
        allowed_user_types.extend(
            extras
                .and_then(|extras| extras.app_user_types.get(&app.id))
                .into_iter()
                .flatten()
                .map(|name| json!(name)),
        );
        let auth_flow_id =
            crate::local::application_authentication_flow_id(&description.session.id, &app.id);
        emit(
            &mut outputs,
            Area::Resources,
            format!("flows/{auth_flow_id}.yaml"),
            &browser_authentication_flow(description, &app.id, &app.client_id),
        )?;
        let grant_types = if app.refresh_tokens {
            json!(["authorization_code", "refresh_token"])
        } else {
            json!(["authorization_code"])
        };
        let mut post_logout_redirect_uris = vec![app.origin.clone()];
        if app.refresh_tokens {
            let mut account_switch =
                url::Url::parse(&app.origin).expect("the application origin was validated");
            account_switch.set_path("/auth/login");
            account_switch.set_query(None);
            post_logout_redirect_uris.push(account_switch.to_string());
        }
        let mut document = json!({
            "resource_type": "application", "id": app.id,
            "name": app.client_id,
            "description": if extras.is_some() {
                "Browser application"
            } else {
                "Synthetic local browser application"
            },
            "type": "fullstack", "ouHandle": ou_handle,
            "url": app.origin,
            "authFlowId": auth_flow_id,
            "signOutFlowId": sign_out_flow_id.as_deref().expect("browser apps render sign-out"),
            "themeId": branding.theme_id,
            "layoutId": branding.layout_id,
            "isRegistrationFlowEnabled": false, "isRecoveryFlowEnabled": false,
            "allowedUserTypes": allowed_user_types,
            "inboundAuthConfig": [{"type": "oauth2", "config": {
                "clientId": app.client_id, "clientSecret": secret,
                "redirectUris": app.redirect_uris,
                "postLogoutRedirectUris": post_logout_redirect_uris,
                "grantTypes": grant_types, "responseTypes": ["code"],
                "tokenEndpointAuthMethod": "client_secret_post", "pkceRequired": true, "publicClient": false,
                "token": {"accessToken": {"defaultAudience": app.audience,
                    "userConfig": {"validityPeriod": 300, "attributes": app.token_attributes}},
                    "idToken": {"validityPeriod": 3600, "userAttributes": app.token_attributes}},
            }}],
        });
        let logo = match extras {
            None => Some(format!(
                "http://127.0.0.1:{}{}/registry-stack-wordmark.svg",
                description.port, branding.asset_base_path
            )),
            Some(extras) => extras.app_logo_urls.get(&app.id).cloned(),
        };
        if let Some(logo) = logo {
            document["logoUrl"] = json!(logo);
        }
        emit(
            &mut outputs,
            Area::Resources,
            format!("applications/{}.yaml", app.id),
            &document,
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
            "ouHandle": ou_handle,
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
                    .chain(INSTITUTIONAL_REQUESTER_ATTRIBUTES.iter())
                    .map(|attribute| (*attribute).to_owned())
                    .collect::<Vec<_>>()
            };
            for attribute in &client.token_attributes {
                if !exchange_attributes.contains(attribute) {
                    exchange_attributes.push(attribute.clone());
                }
            }
            // Provenance travels with every exchanged token this client can
            // obtain, so a resource server can refuse an assertion authority
            // this client was never meant to exchange.
            exchange_attributes.push(ASSERTION_ISSUER_CLAIM.to_owned());
            config["grantTypes"] = json!([
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange"
            ]);
            config["token"]["accessToken"]["userConfig"] = json!({
                "validityPeriod": client.access_token_lifetime_seconds,
                "attributes": exchange_attributes,
            });
        }
        emit(
            &mut outputs,
            Area::Bootstrap,
            format!("agents/{}.yaml", client.agent_id),
            &document,
        )?;
    }

    for client in &description.compatibility_clients {
        // The secret is read here, inside the private state directory, and
        // written straight into the owner-only agent document that carries
        // it. It never appears in a returned value, a log line, or an argv.
        let secret = mode.secret(
            &client.secret_file,
            "a compatibility client secret file could not be read",
            |secret| {
                if secret.trim().is_empty() || secret.len() > 256 {
                    return Err(ToolingError::InvalidDescription {
                        reason: "a compatibility client secret file is 1..=256 bytes",
                    });
                }
                Ok(())
            },
        )?;
        let document = json!({
            "resource_type": "agent",
            "id": client.agent_id,
            "type": crate::description::DEFAULT_AGENT_TYPE,
            "ouHandle": ou_handle,
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
                        "clientSecret": secret,
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
        emit(
            &mut outputs,
            Area::Bootstrap,
            format!("agents/{}.yaml", client.agent_id),
            &document,
        )?;
    }

    let agent_type = agent_type_document(description)?;
    outputs.push(Output {
        area: Area::Bootstrap,
        path: "agent-type.yaml".into(),
        bytes: agent_type.clone().into_bytes(),
    });
    Ok(Built {
        outputs,
        agent_type,
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
        #[allow(
            clippy::disallowed_methods,
            reason = "reads back a ThunderID resource this crate rendered, an external format (platform/thunderid-resources) ThunderID owns, not configuration an operator writes"
        )]
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
        #[allow(
            clippy::disallowed_methods,
            reason = "reads back a ThunderID resource this crate rendered, an external format (platform/thunderid-resources) ThunderID owns, not configuration an operator writes"
        )]
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
        #[allow(
            clippy::disallowed_methods,
            reason = "reads back a ThunderID resource this crate rendered, an external format (platform/thunderid-resources) ThunderID owns, not configuration an operator writes"
        )]
        let role: Value = serde_norway::from_str(&role_text).expect("it parses");
        assert_eq!(
            role["permissions"][0]["permissions"],
            json!(["evidence:invoke"])
        );
        assert_eq!(role["assignments"][0]["type"], json!("agent"));
        assert!(
            !description.state_root.join(BRANDING_ASSETS_DIR).exists(),
            "machine-only sessions must not render presentation files"
        );
        assert!(!rendered.resources_dir.join("themes").exists());
        assert!(!rendered.resources_dir.join("layouts").exists());
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
        for ordinary in [false, true] {
            use crate::description::{ExchangeIssuer, TokenExchangeClient, GRANT_ATTRIBUTES};
            let mut description = crate::testing::synthetic_description();
            description.compatibility_clients.clear();
            description.state_root = std::env::temp_dir().join(format!(
                "registry-exchange-render-{}",
                crate::container::random_urlsafe(16).unwrap()
            ));
            fs::create_dir(&description.state_root).unwrap();
            fs::set_permissions(&description.state_root, fs::Permissions::from_mode(0o700))
                .unwrap();
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
                ordinary_resource_permissions: Vec::new(),
            });
            if ordinary {
                crate::local::declare_resource(
                    &mut description,
                    "urn:synthetic:ordinary",
                    &["records:read".into()],
                )
                .unwrap();
                let server = description.resource_servers.last().unwrap().id.clone();
                description.roles[0]
                    .permissions
                    .push((server.clone(), vec!["records:read".into()]));
                description.machine_clients[0]
                    .token_exchange
                    .as_mut()
                    .unwrap()
                    .ordinary_resource_permissions = vec![(server, vec!["records:read".into()])];
            }
            let rendered = render(&description).unwrap();
            let role: Value = serde_yaml_parse(
                &fs::read_to_string(
                    rendered
                        .resources_dir
                        .join(format!("roles/{}.yaml", description.roles[0].id)),
                )
                .unwrap(),
            )
            .unwrap();
            let expected: Vec<Value> = description.roles[0]
                .permissions
                .iter()
                .map(|(server, scopes)| json!({"resourceServerId":server,"permissions":scopes}))
                .collect();
            assert_eq!(role["permissions"], json!(expected));

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
            // An exchange client admits the provenance claim beside the grant and
            // requester attributes, so a resource server reading its token can tell
            // which assertion authority signed the subject token it came from.
            assert_eq!(
                config["token"]["accessToken"]["userConfig"]["attributes"],
                json!(GRANT_ATTRIBUTES
                    .iter()
                    .copied()
                    .chain(INSTITUTIONAL_REQUESTER_ATTRIBUTES)
                    .chain(["synthetic_tag", ASSERTION_ISSUER_CLAIM])
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
                connection["attributeConfiguration"]["user_type_attribute_mappings"][0]
                    ["attributes"],
                json!([
                    {"external_attribute":"iss","local_attribute":ASSERTION_ISSUER_CLAIM},
                    {"external_attribute":"iss","local_attribute":"registry_grant_source_issuer"},
                    {"external_attribute":"evidence_audience","local_attribute":"evidence_audience"},
                    {"external_attribute":"evidence_tags","local_attribute":"evidence_tags"},
                ])
            );
            let schema: Value = serde_yaml_parse(&rendered.agent_type_document).unwrap();
            assert_eq!(schema["schema"]["evidence_audience"]["type"], "string");
            assert_eq!(schema["schema"]["evidence_tags"]["type"], "array");
            assert_eq!(schema["schema"]["evidence_tags"]["items"]["type"], "string");
            assert!(
                render(&description).is_err(),
                "a second render must not overwrite session resources"
            );
            fs::remove_dir_all(&description.state_root).unwrap();
        }
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
            ordinary_resource_permissions: Vec::new(),
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
        // A first-party connection projects the verified issuer exactly as an
        // institutional one does, then only the claims the signer declared. The
        // signer can neither declare the provenance claim itself nor choose its
        // value, so the mapping is the sole source of it.
        assert_eq!(
            connection["attributeConfiguration"]["user_type_attribute_mappings"][0]["attributes"],
            json!([
                {"external_attribute":"iss","local_attribute":ASSERTION_ISSUER_CLAIM},
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
        assert!(attributes
            .as_array()
            .unwrap()
            .contains(&json!(ASSERTION_ISSUER_CLAIM)));
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
                refresh_tokens: false,
            });
        description
            .interactive_applications
            .push(InteractiveApplication {
                id: "0197aaaa-0000-7000-8000-0000000000e3".into(),
                client_id: "synthetic-citizen".into(),
                client_secret_file: "secrets/app".into(),
                origin: "http://127.0.0.1:3001".into(),
                redirect_uris: vec!["http://127.0.0.1:3001/auth/callback".into()],
                audience: description.resource_servers[0].identifier.clone(),
                token_attributes: vec!["registry_role".into()],
                refresh_tokens: false,
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
        let other_app: Value = serde_yaml_parse(
            &fs::read_to_string(
                rendered
                    .resources_dir
                    .join("applications/0197aaaa-0000-7000-8000-0000000000e3.yaml"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_ne!(app["authFlowId"], "01900000-0000-7000-8000-000000000068");
        assert_ne!(app["authFlowId"], other_app["authFlowId"]);
        assert!(app["authFlowId"].is_string());
        assert_eq!(app["signOutFlowId"], other_app["signOutFlowId"]);
        assert!(app["signOutFlowId"].is_string());

        let flows: Vec<Value> = fs::read_dir(rendered.resources_dir.join("flows"))
            .unwrap()
            .map(|entry| {
                serde_yaml_parse(&fs::read_to_string(entry.unwrap().path()).unwrap()).unwrap()
            })
            .collect();
        assert_eq!(
            flows.len(),
            3,
            "two authentication flows and one sign-out flow"
        );
        let auth_flow = flows
            .iter()
            .find(|flow| flow["id"] == app["authFlowId"])
            .unwrap();
        let executors: Vec<_> = auth_flow["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|node| node["executor"]["name"].as_str())
            .collect();
        assert_eq!(
            executors,
            [
                "SSOCheckExecutor",
                "CredentialsAuthExecutor",
                "SessionExecutor",
                "AuthorizationExecutor",
                "AuthAssertExecutor",
            ]
        );
        let sign_out_flow = flows
            .iter()
            .find(|flow| flow["id"] == app["signOutFlowId"])
            .unwrap();
        let sign_out = sign_out_flow["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["executor"]["name"] == "SessionSignOutExecutor")
            .unwrap();
        assert_eq!(sign_out["properties"]["promptOnSignOut"], true);
        assert_eq!(app["themeId"], "019a05b7-1000-7000-8000-000000000001");
        assert_eq!(app["layoutId"], "019a05b7-1000-7000-8000-000000000002");
        assert_eq!(
            app["logoUrl"],
            format!(
                "http://127.0.0.1:{}/gate/assets/registry-stack/registry-stack-wordmark.svg",
                description.port
            )
        );
        let oauth = &app["inboundAuthConfig"][0]["config"];
        assert_eq!(oauth["clientId"], "synthetic-browser");
        assert_eq!(oauth["clientSecret"], "synthetic-application-secret");
        assert_eq!(
            oauth["redirectUris"],
            json!(["http://127.0.0.1:3000/auth/callback"])
        );
        assert_eq!(
            oauth["postLogoutRedirectUris"],
            json!(["http://127.0.0.1:3000"])
        );
        assert_eq!(oauth["grantTypes"], json!(["authorization_code"]));
        assert_eq!(oauth["responseTypes"], json!(["code"]));
        assert_eq!(oauth["tokenEndpointAuthMethod"], "client_secret_post");
        assert_eq!(oauth["pkceRequired"], true);
        assert_eq!(oauth["publicClient"], false);
        assert_eq!(
            oauth["token"]["accessToken"]["defaultAudience"],
            "urn:registry:tooling-test:evidence"
        );
        assert_eq!(
            oauth["token"]["accessToken"]["userConfig"]["attributes"],
            json!(["registry_role"])
        );
        assert_eq!(
            oauth["token"]["accessToken"]["userConfig"]["validityPeriod"],
            300
        );
        assert_eq!(oauth["token"]["idToken"]["validityPeriod"], 3600);

        let theme: Value = serde_yaml_parse(
            &fs::read_to_string(
                rendered
                    .resources_dir
                    .join("themes/019a05b7-1000-7000-8000-000000000001.yaml"),
            )
            .unwrap(),
        )
        .unwrap();
        let source_theme: Value = serde_json::from_str(BRANDING_THEME).unwrap();
        assert_eq!(theme["resource_type"], "theme");
        assert_eq!(theme["id"], "019a05b7-1000-7000-8000-000000000001");
        for key in ["handle", "displayName", "description", "theme"] {
            assert_eq!(theme[key], source_theme[key], "theme field {key} drifted");
        }
        let layout: Value = serde_yaml_parse(
            &fs::read_to_string(
                rendered
                    .resources_dir
                    .join("layouts/019a05b7-1000-7000-8000-000000000002.yaml"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(layout["resource_type"], "layout");
        assert_eq!(layout["id"], "019a05b7-1000-7000-8000-000000000002");
        assert_eq!(layout["handle"], "registry-stack");
        assert_eq!(
            layout["layout"]["head"]["stylesheets"][0],
            json!({"id": "registry-stack", "type": "inline", "content": BRANDING_STYLESHEET})
        );
        let assets = description.state_root.join(BRANDING_ASSETS_DIR);
        assert_eq!(
            fs::read(assets.join("registry-stack-wordmark.svg")).unwrap(),
            BRANDING_WORDMARK
        );
        assert_eq!(
            fs::read(assets.join("fonts/public-sans-latin-wght-normal.woff2")).unwrap(),
            BRANDING_FONT
        );
        assert_eq!(
            fs::read(assets.join("fonts/OFL-public-sans.txt")).unwrap(),
            BRANDING_FONT_LICENSE
        );
        assert!(rendered
            .resources_dir
            .join("users/0197aaaa-0000-7000-8000-0000000000e2.yaml")
            .exists());
        fs::remove_dir_all(&description.state_root).unwrap();
    }

    #[test]
    fn a_machine_only_render_has_no_browser_flow() {
        let mut description = crate::testing::synthetic_description();
        description.state_root = std::env::temp_dir().join(format!(
            "registry-machine-render-{}",
            crate::container::random_urlsafe(16).unwrap()
        ));
        fs::create_dir(&description.state_root).unwrap();
        fs::set_permissions(&description.state_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(description.state_root.join("secrets")).unwrap();
        fs::write(
            description
                .state_root
                .join("secrets/compatibility-client-secret"),
            "fixture-compat-secret",
        )
        .unwrap();

        let rendered = render(&description).unwrap();
        assert!(!rendered.resources_dir.join("flows").exists());
        fs::remove_dir_all(&description.state_root).unwrap();
    }

    #[test]
    fn the_stylesheet_and_the_asset_mount_follow_the_declared_asset_path() {
        let metadata = branding_metadata().unwrap();
        assert!(
            BRANDING_STYLESHEET.contains(&format!(
                "url(\"{}/fonts/public-sans-latin-wght-normal.woff2\")",
                metadata.asset_base_path
            )),
            "registry-stack.css loads its font from a path branding.json does not declare"
        );
        assert!(
            metadata.asset_base_path.starts_with("/gate/"),
            "only Gate's static tree is mounted: {}",
            metadata.asset_base_path
        );
        assert_eq!(
            crate::container::BRANDING_ASSETS_MOUNT_POINT,
            format!("/opt/thunderid/apps{}", metadata.asset_base_path)
        );
    }
}

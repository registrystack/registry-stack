// SPDX-License-Identifier: Apache-2.0
//! Authored local teaching identities and generated private service bindings.

use super::{private, State, MIGRATION_ROLE};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::SigningKey;
use registry_casework_core::{
    findings_report, valid_directory_identifier, valid_profile_identifier, CaseworkProject,
    CaseworkRole, ConfigFinding,
};
use registry_platform_yaml::{
    escape_pointer_segment, ApiVersion, Decoded, EnvelopeRule, Expect, FormatSpec, LocalId, Reader,
    Refusal, RemovedKey, Report, ScalarHook, ScalarSite,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use zeroize::Zeroizing;

/// The identity claim a Casework human profile must carry, and the value the
/// generated operator configuration requires. Only explicitly declared local
/// teaching fixtures may carry a human marker on a machine-issued token.
pub(super) const HUMAN_CLAIM: &str = "registry_actor_kind";
pub(super) const HUMAN_VALUE: &str = "human";
const RESERVED_ACCESS_TOKEN_CLAIMS: [&str; 9] = [
    "iss",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "client_id",
    "sub",
    "scope",
];

pub(crate) const DEV_CLIENTS_API_VERSION: &str =
    "id.registrystack.org/formats/casework/dev-clients/v1alpha1";
pub(crate) const DEV_CLIENTS_KIND: &str = "CaseworkDevClients";

/// The format of `dev-clients.yaml`, the local teaching clients file
/// (CFG-ENV-1).
pub(crate) const DEV_CLIENTS_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: DEV_CLIENTS_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(DEV_CLIENTS_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/version",
            replacement: "Remove version; apiVersion and kind identify the file.",
        },
        RemovedKey {
            pointer: "/integrations/sources/*/requestTimeoutMilliseconds",
            replacement: "Remove it; the session uses the runtime default, and a deployed runtime configuration sets it.",
        },
        RemovedKey {
            pointer: "/integrations/sources/*/connectTimeoutMilliseconds",
            replacement: "Remove it; the session uses the runtime default, and a deployed runtime configuration sets it.",
        },
        RemovedKey {
            pointer: "/integrations/sources/*/reconciliationIntervalMilliseconds",
            replacement: "Remove it; the session uses the runtime default, and a deployed runtime configuration sets it.",
        },
    ],
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Clients {
    pub api_version: String,
    pub kind: String,
    /// One teaching client for each access profile `casework.yaml` declares.
    pub clients: Vec<Client>,
    /// The teams the first start seeds, one for each queue.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directory: Vec<DirectoryTeam>,
    /// Source-backed development: source bindings, service clients, and the
    /// local task authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrations: Option<super::integrations::Integrations>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Client {
    /// `issuer` is reserved for the local token issuer.
    #[serde(deserialize_with = "registry_casework_core::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    pub id: String,
    /// The access profile this client binds; each profile binds one client.
    pub access_profile: String,
    /// 1 to 32 distinct RFC 6749 scope-tokens of at most 256 bytes.
    pub scopes: Vec<String>,
    /// At most 32 token claims; registered access-token claims are reserved.
    #[serde(
        default,
        deserialize_with = "registry_casework_core::typed::external_id_keys",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BTreeMap<registry_platform_yaml::ExternalId, String>")
    )]
    pub claims: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DirectoryTeam {
    /// A lowercase letter, then at most 63 lowercase letters, digits, `_`,
    /// or `-`.
    pub team: String,
    /// The queue this team serves; one team serves each queue.
    pub queue: String,
    /// 1 to 32 clients bound to a Staff profile.
    pub staff: Vec<String>,
    /// At most 32 clients bound to a Supervisor profile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supervisors: Vec<String>,
}

/// Whether `value` is written as a local identifier, the grammar client and
/// team IDs share (CFG-ID-1).
pub(super) fn identifier(value: &str) -> bool {
    LocalId::new(value).is_ok()
}

/// Read a clients file through the shared reader, with every check that
/// needs no other file. `file` is the name diagnostics carry.
pub(crate) fn read(file: &str, bytes: &[u8]) -> Result<Decoded<Clients>, Report> {
    let mut hook = LiteralText;
    let decoded = Reader::new(file)
        .with_hook(&mut hook)
        .decode::<Clients>(bytes, &Expect::one(&DEV_CLIENTS_FORMAT))?;
    let found = findings(&decoded.value);
    if found.is_empty() {
        Ok(decoded)
    } else {
        Err(findings_report(&decoded.document, &found))
    }
}

/// Read a clients file and check it against the authored project: every
/// finding of both, placed in the clients file.
pub(crate) fn read_against(
    file: &str,
    bytes: &[u8],
    project: &CaseworkProject,
) -> Result<Decoded<Clients>, Report> {
    let decoded = read(file, bytes)?;
    match against(&decoded.value, project) {
        Ok(_) => Ok(decoded),
        Err(found) => Err(findings_report(&decoded.document, &found)),
    }
}

/// Read the session's copy of its clients file, `clients.json`, which the
/// start wrote from the file it checked.
pub(super) fn retained(bytes: &[u8]) -> Result<Clients> {
    Ok(read("clients.json", bytes)?.value)
}

/// Refuses every `${...}` expression: the clients file names local teaching
/// identities and is read as written.
struct LiteralText;

impl LiteralText {
    fn check(site: &ScalarSite<'_>) -> Result<(), Refusal> {
        if !registry_platform_config::contains_environment_expression(site.text) {
            return Ok(());
        }
        Err(Refusal {
            code: "config.substitution-not-allowed".to_owned(),
            message: "a `${...}` expression is written in the local clients file, which is read as written".to_owned(),
            suggested_action: "Write the value directly; dev-clients.yaml holds no secret.".to_owned(),
        })
    }
}

impl ScalarHook for LiteralText {
    fn key(&mut self, site: &ScalarSite<'_>) -> Result<(), Refusal> {
        Self::check(site)
    }

    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        Self::check(site).map(|()| None)
    }
}

/// Copy one pre-registered owner client into this private Casework session.
/// Exact claim, scope, audience and key checks prevent an ambient owner file
/// from silently changing the authority of the generated local workload.
pub(super) fn borrow_client(
    directory: &Path,
    state: &State,
    id: &str,
    scopes: &[String],
    claims: &Value,
    resource: &str,
    task_exchange: bool,
) -> Result<()> {
    let owner_root =
        super::borrowed_issuer(state)?.context("no shared issuer owner is configured")?;
    let clients: Value = serde_json::from_slice(&private::read(
        &owner_root.join("clients.json"),
        super::MAX_BYTES,
    )?)?;
    let registered = clients["clients"]
        .as_array()
        .and_then(|entries| entries.iter().find(|entry| entry["id"] == id))
        .with_context(|| format!("shared issuer owner has no registration for {id}"))?;
    let owner_resource = clients["issuer"]["clientResources"][id]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "urn:breg:dev:{}",
                state.issuer_owner.as_deref().unwrap_or_default()
            )
        });
    if registered["scopes"] != json!(scopes)
        || registered["claims"] != *claims
        || owner_resource != resource
    {
        bail!("shared issuer registration differs from Casework client {id}");
    }
    // An exchange client may present any assertion authority the shared issuer
    // trusts, and this session states a pairing only for the task exchange
    // clients it declares. A client the owner registered for exchange that
    // this project does not declare would be admitted with no pairing to
    // refuse the other authorities with, so the two declarations must agree
    // exactly rather than in one direction only.
    if clients["issuer"]["exchangeClients"]
        .as_array()
        .is_some_and(|ids| ids.iter().any(|entry| entry == id))
        != task_exchange
    {
        bail!("shared issuer owner and Casework disagree on exchange client {id}");
    }
    let source = owner_root.join("credentials").join(id);
    let client_id = Zeroizing::new(private::read(&source.join("client-id"), super::MAX_BYTES)?);
    let key = Zeroizing::new(private::read(
        &source.join("assertion-key.jwk"),
        super::MAX_BYTES,
    )?);
    let public = private::read(&source.join("public.jwk"), 4096)?;
    if client_id.as_slice() != id.as_bytes() {
        bail!("shared issuer client ID differs from {id}");
    }
    let jwk: Value = serde_json::from_slice(&key)?;
    let public_jwk: Value = serde_json::from_slice(&public)?;
    let d = Zeroizing::new(
        URL_SAFE_NO_PAD.decode(
            jwk["d"]
                .as_str()
                .context("owner key has no private coordinate")?,
        )?,
    );
    let signing = SigningKey::from_slice(&d).context("owner assertion key is invalid")?;
    let point = signing.verifying_key().to_encoded_point(false);
    if jwk["kty"] != "EC"
        || jwk["crv"] != "P-256"
        || jwk["alg"] != "ES256"
        || jwk["x"] != URL_SAFE_NO_PAD.encode(point.x().context("owner key has no x")?)
        || jwk["y"] != URL_SAFE_NO_PAD.encode(point.y().context("owner key has no y")?)
        || public_jwk["x"] != jwk["x"]
        || public_jwk["y"] != jwk["y"]
        || public_jwk["kid"] != jwk["kid"]
    {
        bail!("shared issuer assertion key does not match its registered public key");
    }
    private::create(&directory.join("client-id"), &client_id)?;
    private::create(&directory.join("assertion-key.jwk"), &key)?;
    private::create(&directory.join("public.jwk"), &public)
}

// Apply OAuth scope-token syntax before rendering exact issuer permissions.
fn valid_scope_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        })
}

fn valid_authorization_claim_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && valid_scope_token(value)
}

pub(super) const CLIENT_ID_MESSAGE: &str =
    "expected a lowercase letter, then at most 63 lowercase letters, digits, '_', or '-'";

/// The pointer of `key` below `parent`, escaped (RFC 6901).
pub(super) fn member(parent: &str, key: &str) -> String {
    format!("{parent}/{}", escape_pointer_segment(key))
}

/// Records the first pointer of each value, so a repeat is reported with the
/// place it repeats.
#[derive(Default)]
pub(super) struct FirstSeen<'a> {
    seen: BTreeMap<&'a str, String>,
}

impl<'a> FirstSeen<'a> {
    /// The pointer `value` was first seen at, after recording `pointer` for
    /// it when it is new.
    pub fn repeat(&mut self, value: &'a str, pointer: &str) -> Option<String> {
        match self.seen.get(value) {
            Some(first) => Some(first.clone()),
            None => {
                self.seen.insert(value, pointer.to_owned());
                None
            }
        }
    }
}

/// Every finding of the clients file that needs no other file, in document
/// order. The checks against the authored project are [`against`]'s.
pub(super) fn findings(clients: &Clients) -> Vec<ConfigFinding> {
    let mut found = Vec::new();
    if clients.clients.is_empty() || clients.clients.len() > 32 {
        found.push(ConfigFinding::new(
            "casework.dev-clients.clients-out-of-range",
            "/clients",
            "expected 1 to 32 clients",
            "Declare between 1 and 32 clients, one for each access profile casework.yaml declares.",
        ));
    }
    let mut ids = FirstSeen::default();
    let mut profiles = FirstSeen::default();
    for (index, client) in clients.clients.iter().enumerate() {
        let at = format!("/clients/{index}");
        let id = format!("{at}/id");
        if client.id == "issuer" {
            found.push(ConfigFinding::new(
                "casework.dev-clients.reserved-id",
                &id,
                "the local token issuer reserves this client ID",
                "Choose another client ID, such as staff.",
            ));
        } else if let Some(first) = ids.repeat(&client.id, &id) {
            found.push(
                ConfigFinding::new(
                    "casework.dev-clients.duplicate-id",
                    &id,
                    "another client already declares this ID",
                    "Give each client its own ID.",
                )
                .with_related(first, "first declared here"),
            );
        }
        let profile = format!("{at}/accessProfile");
        if !valid_profile_identifier(&client.access_profile) {
            found.push(ConfigFinding::new(
                "casework.dev-clients.invalid-access-profile",
                &profile,
                "expected 1 to 128 ASCII letters, digits, '-', '_', '.', or ':'",
                "Write the ID of an access profile casework.yaml declares.",
            ));
        } else if let Some(first) = profiles.repeat(&client.access_profile, &profile) {
            found.push(
                ConfigFinding::new(
                    "casework.dev-clients.duplicate-access-profile",
                    &profile,
                    "another client already binds this access profile; each binds exactly one client",
                    "Bind each access profile to one client.",
                )
                .with_related(first, "first bound here"),
            );
        }
        scope_findings(
            &mut found,
            &format!("{at}/scopes"),
            &client.scopes,
            256,
            "expected an RFC 6749 scope-token of 1 to 256 bytes: printable ASCII without space, '\"', or '\\'",
        );
        if client.claims.len() > 32 {
            found.push(ConfigFinding::new(
                "casework.dev-clients.too-many-claims",
                format!("{at}/claims"),
                "expected at most 32 claims",
                "Keep at most 32 claims on one client.",
            ));
        }
        for (name, value) in &client.claims {
            let claim = member(&format!("{at}/claims"), name);
            if !valid_authorization_claim_name(name) {
                found.push(ConfigFinding::new(
                    "casework.dev-clients.invalid-claim-name",
                    &claim,
                    "expected a claim name of 1 to 128 bytes: printable ASCII without space, '\"', or '\\'",
                    "Rename the claim, such as registry_principal.",
                ));
            } else if RESERVED_ACCESS_TOKEN_CLAIMS.contains(&name.as_str()) {
                found.push(ConfigFinding::new(
                    "casework.dev-clients.reserved-claim",
                    &claim,
                    "the token issuer sets this registered access-token claim (iss, aud, exp, iat, nbf, jti, client_id, sub, or scope)",
                    "Remove the claim; the issuer writes it.",
                ));
            }
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                found.push(ConfigFinding::new(
                    "casework.dev-clients.invalid-claim-value",
                    &claim,
                    "expected 1 to 256 bytes without control characters",
                    "Write the claim value on one line, in at most 256 bytes.",
                ));
            }
        }
    }
    if clients.directory.len() > 8 {
        found.push(ConfigFinding::new(
            "casework.dev-clients.too-many-teams",
            "/directory",
            "expected at most 8 teams",
            "Keep at most 8 teams in the local directory.",
        ));
    }
    let declared = clients
        .clients
        .iter()
        .map(|client| client.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut teams = FirstSeen::default();
    let mut queues = FirstSeen::default();
    for (index, team) in clients.directory.iter().enumerate() {
        let at = format!("/directory/{index}");
        let team_at = format!("{at}/team");
        if !identifier(&team.team) {
            found.push(ConfigFinding::new(
                "casework.dev-clients.invalid-team",
                &team_at,
                CLIENT_ID_MESSAGE,
                "Write a lowercase team ID, such as decisions-team.",
            ));
        } else if let Some(first) = teams.repeat(&team.team, &team_at) {
            found.push(
                ConfigFinding::new(
                    "casework.dev-clients.duplicate-team",
                    &team_at,
                    "another team already declares this ID",
                    "Give each team its own ID.",
                )
                .with_related(first, "first declared here"),
            );
        }
        let queue = format!("{at}/queue");
        if !valid_directory_identifier(&team.queue) {
            found.push(ConfigFinding::new(
                "casework.dev-clients.invalid-queue",
                &queue,
                "expected 1 to 128 ASCII letters, digits, '-', '_', or '.'",
                "Write the ID of a queue casework.yaml declares.",
            ));
        } else if let Some(first) = queues.repeat(&team.queue, &queue) {
            found.push(
                ConfigFinding::new(
                    "casework.dev-clients.duplicate-queue",
                    &queue,
                    "another team already serves this queue; one team serves each queue",
                    "Serve each queue from one team.",
                )
                .with_related(first, "first served here"),
            );
        }
        if team.staff.is_empty() || team.staff.len() > 32 {
            found.push(ConfigFinding::new(
                "casework.dev-clients.staff-out-of-range",
                format!("{at}/staff"),
                "expected 1 to 32 staff",
                "Name between 1 and 32 staff clients.",
            ));
        }
        if team.supervisors.len() > 32 {
            found.push(ConfigFinding::new(
                "casework.dev-clients.too-many-supervisors",
                format!("{at}/supervisors"),
                "expected at most 32 supervisors",
                "Name at most 32 supervisor clients.",
            ));
        }
        for (list, members) in [("staff", &team.staff), ("supervisors", &team.supervisors)] {
            let mut seen = FirstSeen::default();
            for (position, name) in members.iter().enumerate() {
                let pointer = format!("{at}/{list}/{position}");
                if !declared.contains(name.as_str()) {
                    found.push(ConfigFinding::new(
                        "casework.dev-clients.unknown-client",
                        &pointer,
                        "no client in this file declares this ID",
                        "Name the ID of a client under clients, or declare one.",
                    ));
                } else if let Some(first) = seen.repeat(name, &pointer) {
                    found.push(
                        ConfigFinding::new(
                            "casework.dev-clients.duplicate-member",
                            &pointer,
                            "this list already names this client",
                            "Name each client at most once in a list.",
                        )
                        .with_related(first, "first named here"),
                    );
                }
            }
        }
    }
    found
}

/// Report the scope list at `at`: its size, each scope's syntax, and each
/// repeat.
pub(super) fn scope_findings(
    found: &mut Vec<ConfigFinding>,
    at: &str,
    scopes: &[String],
    maximum_bytes: usize,
    message: &str,
) {
    if scopes.is_empty() || scopes.len() > 32 {
        found.push(ConfigFinding::new(
            "casework.dev-clients.scopes-out-of-range",
            at,
            "expected 1 to 32 scopes",
            "Write between 1 and 32 scopes.",
        ));
    }
    let mut seen = FirstSeen::default();
    for (index, scope) in scopes.iter().enumerate() {
        let pointer = format!("{at}/{index}");
        if scope.len() > maximum_bytes || !valid_scope_token(scope) {
            found.push(ConfigFinding::new(
                "casework.dev-clients.invalid-scope",
                &pointer,
                message,
                "Write the scope as casework.yaml's requiredScopes spell it, such as casework:staff.",
            ));
        } else if let Some(first) = seen.repeat(scope, &pointer) {
            found.push(
                ConfigFinding::new(
                    "casework.dev-clients.duplicate-scope",
                    &pointer,
                    "this list already names this scope",
                    "Write each scope once.",
                )
                .with_related(first, "first written here"),
            );
        }
    }
}

/// One local client resolved against the authored project: the access profile
/// it binds, that profile's role, and the principal the runtime will see.
#[derive(Debug)]
pub(super) struct Bound<'a> {
    pub client: &'a Client,
    pub role: CaseworkRole,
    pub principal: String,
}

/// Every finding of the clients file against the authored project, its
/// integrations included, or each client's binding when there is none.
pub(super) fn against<'a>(
    clients: &'a Clients,
    project: &CaseworkProject,
) -> Result<Vec<Bound<'a>>, Vec<ConfigFinding>> {
    let mut found = match &clients.integrations {
        Some(integrations) => integrations.validate(clients, project).err().unwrap_or_default(),
        None if !project.task_templates.is_empty() => vec![ConfigFinding::new(
            "casework.dev-clients.missing-integrations",
            "/integrations",
            "casework.yaml declares task templates, which need integrations with source bindings and a taskAuthority",
            "Add integrations with a binding for each source and a taskAuthority.",
        )],
        None => Vec::new(),
    };
    match bind(clients, project) {
        Ok(bound) if found.is_empty() => Ok(bound),
        Ok(_) => Err(found),
        Err(more) => {
            found.extend(more);
            Err(found)
        }
    }
}

/// Check the clients file against the authored policy and resolve each
/// client's principal. Refusing here, before any container or service starts,
/// tells the author which binding is missing while the fix is one edit away.
pub(super) fn bind<'a>(
    clients: &'a Clients,
    project: &CaseworkProject,
) -> Result<Vec<Bound<'a>>, Vec<ConfigFinding>> {
    let mut found = Vec::new();
    let mut bound = Vec::with_capacity(clients.clients.len());
    for (index, client) in clients.clients.iter().enumerate() {
        let at = format!("/clients/{index}");
        let Some(profile) = project
            .access_profiles
            .iter()
            .find(|profile| profile.id == client.access_profile)
        else {
            found.push(ConfigFinding::new(
                "casework.dev-clients.unknown-access-profile",
                format!("{at}/accessProfile"),
                "casework.yaml declares no access profile with this ID",
                "Write the ID of an access profile casework.yaml declares under accessProfiles.",
            ));
            continue;
        };
        if !profile
            .required_scopes
            .iter()
            .all(|scope| client.scopes.contains(scope))
        {
            found.push(ConfigFinding::new(
                "casework.dev-clients.missing-required-scope",
                format!("{at}/scopes"),
                "the client lacks a scope its access profile requires",
                "Add every scope of the access profile's requiredScopes to scopes.",
            ));
        }
        let claims = format!("{at}/claims");
        let human = client.claims.get(HUMAN_CLAIM).map(String::as_str);
        match profile.role {
            CaseworkRole::Requester if human.is_some() => found.push(ConfigFinding::new(
                "casework.dev-clients.requester-human-claim",
                member(&claims, HUMAN_CLAIM),
                "the client binds a Requester profile, a calling system rather than a person, so it carries no registry_actor_kind claim",
                "Remove registry_actor_kind from this client's claims.",
            )),
            CaseworkRole::Requester => (),
            _ if human != Some(HUMAN_VALUE) => found.push(ConfigFinding::new(
                "casework.dev-clients.missing-human-claim",
                member(&claims, HUMAN_CLAIM),
                "Casework serves this client's access profile only to a person, so the client needs the claim registry_actor_kind: human",
                "Add registry_actor_kind: human to this client's claims.",
            )),
            _ => (),
        }
        let principal = if profile.principal_claim == "sub" {
            principal(&client.id)
        } else if let Some(value) = client.claims.get(&profile.principal_claim) {
            value.clone()
        } else {
            found.push(ConfigFinding::new(
                "casework.dev-clients.missing-principal-claim",
                claims,
                "the client lacks the claim its access profile's principalClaim names",
                "Add the claim the access profile's principalClaim names to this client's claims.",
            ));
            continue;
        };
        bound.push(Bound {
            client,
            role: profile.role,
            principal,
        });
    }
    for (index, team) in clients.directory.iter().enumerate() {
        let at = format!("/directory/{index}");
        if !project.queues.iter().any(|queue| queue.id == team.queue) {
            found.push(ConfigFinding::new(
                "casework.dev-clients.unknown-queue",
                format!("{at}/queue"),
                "casework.yaml declares no queue with this ID",
                "Write the ID of a queue casework.yaml declares under queues.",
            ));
        }
        for (list, members, role, name) in [
            ("staff", &team.staff, CaseworkRole::Staff, "Staff"),
            (
                "supervisors",
                &team.supervisors,
                CaseworkRole::Supervisor,
                "Supervisor",
            ),
        ] {
            let mut principals = FirstSeen::default();
            for (position, member) in members.iter().enumerate() {
                let pointer = format!("{at}/{list}/{position}");
                // An undeclared member, or one whose client did not bind, is
                // already reported.
                let Some(entry) = bound.iter().find(|entry| &entry.client.id == member) else {
                    continue;
                };
                if entry.role == CaseworkRole::Requester {
                    found.push(ConfigFinding::new(
                        "casework.dev-clients.requester-member",
                        &pointer,
                        "this client binds a Requester profile; only a person serves a queue",
                        "Name a client bound to a Staff or Supervisor profile.",
                    ));
                } else if entry.role != role {
                    found.push(ConfigFinding::new(
                        "casework.dev-clients.member-role-mismatch",
                        &pointer,
                        format!("a member of {list} must bind a {name} access profile, and this client does not"),
                        format!("Name a client bound to a {name} profile, or move this client to the list its role serves."),
                    ));
                } else if let Some(first) = principals.repeat(&entry.principal, &pointer) {
                    found.push(
                        ConfigFinding::new(
                            "casework.dev-clients.repeated-principal",
                            &pointer,
                            format!("another member of {list} resolves to the same principal; each member is a distinct person"),
                            "Give each member's client its own principal claim value.",
                        )
                        .with_related(first, "first resolved here"),
                    );
                }
            }
        }
    }
    for (index, queue) in project.queues.iter().enumerate() {
        if !clients.directory.iter().any(|team| team.queue == queue.id) {
            found.push(ConfigFinding::new(
                "casework.dev-clients.unserved-queue",
                "/directory",
                format!("no team serves the queue casework.yaml declares at /queues/{index}, so caseworkctl doctor would not report ready"),
                "Add a directory team serving that queue.",
            ));
        }
    }
    if found.is_empty()
        && !bound
            .iter()
            .any(|entry| entry.role == CaseworkRole::Administrator)
    {
        found.push(ConfigFinding::new(
            "casework.dev-clients.missing-administrator",
            "/clients",
            "no client binds an Administrator profile, and the first start seeds the directory as one",
            "Add a client bound to an access profile whose role is administrator.",
        ));
    }
    if found.is_empty() {
        Ok(bound)
    } else {
        Err(found)
    }
}

/// The native issuer principal a local client speaks as. It is a local teaching
/// identity, never a deployment identity.
pub(super) fn principal(client_id: &str) -> String {
    registry_thunderid_tooling::local::agent_id("casework-local", client_id)
}

pub(super) fn require_stable_borrowed_principals(policy: &CaseworkProject) -> Result<()> {
    if policy
        .access_profiles
        .iter()
        .any(|profile| profile.principal_claim == "sub")
    {
        bail!("the shared BREG issuer requires explicit stable principal claims; principalClaim sub resolves to the owner's subject, not the Casework local subject");
    }
    Ok(())
}

pub(super) fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A random 32-byte secret as lowercase hexadecimal text.
///
/// Every generated secret is written as text, never as raw bytes: the shared
/// secret reader refuses any file containing a NUL byte, so a raw random file
/// fails roughly one start in eight (GitHub issue #976).
pub(super) fn hex_secret() -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).context("cannot generate a local secret")?;
    Ok(Zeroizing::new(hex_lower(bytes.as_ref())))
}

pub(super) fn keypair(root: &Path) -> Result<Value> {
    private::directory(root)?;
    let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let point = key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().context("generated key lacks x")?);
    let y = URL_SAFE_NO_PAD.encode(point.y().context("generated key lacks y")?);
    let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(
        &json!({"crv":"P-256","kty":"EC","x":x,"y":y}),
    )?));
    let public = json!({"kty":"EC","crv":"P-256","alg":"ES256","kid":kid,"x":x,"y":y});
    let mut private_key = public.clone();
    private_key["d"] = Value::String(URL_SAFE_NO_PAD.encode(key.to_bytes()));
    let bytes = Zeroizing::new(serde_json::to_vec(&private_key)?);
    private::create(&root.join("assertion-key.jwk"), &bytes)?;
    private::create(&root.join("public.jwk"), &serde_json::to_vec(&public)?)?;
    Ok(public)
}

/// Stage every private binding one session needs: credentials, secrets, the
/// local issuer, the database bootstrap material, and the operator
/// configuration the supervised `casework` children read.
pub(super) fn prepare(root: &Path, state: &State, clients: &Clients) -> Result<()> {
    for directory in [
        "credentials",
        "secrets",
        "tls",
        "issuer",
        "logs",
        "audit",
        "database",
    ] {
        private::directory(&root.join(directory))?;
    }
    let borrowed = !state.sources.is_empty() || state.issuer_project.is_some();
    let mut local_clients = Vec::new();
    for client in &clients.clients {
        let directory = root.join("credentials").join(&client.id);
        private::directory(&directory)?;
        if borrowed {
            if state.issuer_project.is_some() {
                borrow_client(
                    &directory,
                    state,
                    &client.id,
                    &client.scopes,
                    &serde_json::to_value(&client.claims)?,
                    &state.audience(),
                    false,
                )?;
            }
            continue;
        }
        let public = keypair(&directory)?;
        private::create(&directory.join("client-id"), client.id.as_bytes())?;
        local_clients.push(registry_thunderid_tooling::local::LocalClient {
            client_id: client.id.clone(),
            public_jwks: serde_json::to_string(&json!({"keys":[public]}))?,
            claims: client.claims.clone(),
            scopes: client.scopes.clone(),
            allow_human_fixture: true,
        });
    }
    // Stable teaching subjects are qualified by the exact local issuer URL.
    // The container label separately binds the randomly owned dev session.
    if !borrowed {
        let mut description = registry_thunderid_tooling::local::local_description(
            registry_thunderid_tooling::description::SessionIdentity {
                label: format!("casework-dev-{}", state.owner),
                id: "casework-local".into(),
            },
            state.issuer_port,
            root.join("issuer"),
            state.audience(),
            local_clients,
        )?;
        if let Some(integrations) = &clients.integrations {
            let policy = crate::project::load_and_check_policy(&state.project)?;
            integrations.prepare(root, state, Some(&mut description), &policy)?;
        }
        registry_thunderid_tooling::render::render(&description)?;
    } else if state.issuer_project.is_some() {
        if let Some(integrations) = &clients.integrations {
            let policy = crate::project::load_and_check_policy(&state.project)?;
            integrations.prepare(root, state, None, &policy)?;
        }
    }
    private::create(
        &root.join("secrets/casework-audit-key"),
        hex_secret()?.as_bytes(),
    )?;
    let password = Zeroizing::new(uuid::Uuid::new_v4().simple().to_string());
    private::create(
        &root.join("database/postgres.env"),
        format!(
            "POSTGRES_USER=postgres\nPOSTGRES_PASSWORD={}\nPOSTGRES_DB=postgres\n",
            password.as_str()
        )
        .as_bytes(),
    )?;
    database_credentials(root, state)?;
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;
    let server_key = rcgen::KeyPair::generate()?;
    let server = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])?
        .signed_by(
            &server_key,
            &rcgen::Issuer::from_params(&ca_params, &ca_key),
        )?;
    let ca_pem = pem("CERTIFICATE", ca.der());
    private::create(&root.join("tls/ca.pem"), ca_pem.as_bytes())?;
    // Casework pins this one generated root for its database connection. Left
    // unset, the runtime would fall back to the host's public roots, which
    // never sign this session's self-signed server certificate.
    private::create(&root.join("secrets/database-root.pem"), ca_pem.as_bytes())?;
    private::create(
        &root.join("tls/server.pem"),
        pem("CERTIFICATE", server.der()).as_bytes(),
    )?;
    private::create(
        &root.join("tls/server.key"),
        Zeroizing::new(pem("PRIVATE KEY", &server_key.serialize_der())).as_bytes(),
    )?;
    private::create(&root.join("database/pg_hba.conf"), b"local all all trust\nhostnossl all all 0.0.0.0/0 reject\nhostnossl all all ::/0 reject\nhostssl all all 0.0.0.0/0 scram-sha-256\nhostssl all all ::/0 scram-sha-256\n")?;
    if let Some(operator) = session_operator(state, clients)? {
        write_yaml(&root.join("operator.yaml"), &operator)?;
    }
    Ok(())
}

/// The operator configuration a session writes for its clients, or `None`
/// when the legacy source bridge writes it after exporting source credentials.
fn session_operator(state: &State, clients: &Clients) -> Result<Option<Value>> {
    // Explicit source bindings need a generated runtime for validation even
    // when the issuer is borrowed.
    let borrowed = !state.sources.is_empty() || state.issuer_project.is_some();
    if borrowed && clients.integrations.is_none() {
        return Ok(None);
    }
    let mut operator = operator(state);
    if let Some(integrations) = &clients.integrations {
        integrations.operator(state, clients, &mut operator)?;
    }
    Ok(Some(operator))
}

/// Rewrite a retained session's operator configuration from its state, so a
/// session an earlier release created carries every key this runtime reads.
/// The session owns this file; its database and records are left in place.
pub(super) fn refresh_operator(root: &Path, state: &State, clients: &Clients) -> Result<()> {
    if let Some(operator) = session_operator(state, clients)? {
        private::replace(
            &root.join("operator.yaml"),
            serde_norway::to_string(&operator)?.as_bytes(),
        )?;
    }
    Ok(())
}

/// Write the session's one database credential as both the runtime and the
/// migration URL. A dev session runs single-role, so apply records that the
/// runtime credential can write the activation ledger; split roles are the
/// production layout the operator templates show.
pub(super) fn database_credentials(root: &Path, state: &State) -> Result<()> {
    let password = Zeroizing::new(uuid::Uuid::new_v4().simple().to_string());
    private::create(
        &root.join("database/migration-password"),
        password.as_bytes(),
    )?;
    // The owned container publishes on 127.0.0.1 only. Naming the literal it
    // publishes keeps a host that resolves localhost to ::1 first from failing
    // to connect; the server certificate carries both names.
    let url = Zeroizing::new(format!(
        "postgresql://{MIGRATION_ROLE}:{}@127.0.0.1:{}/{}",
        password.as_str(),
        state.database_port,
        super::DATABASE_NAME
    ));
    for name in ["runtime-database-url", "migration-database-url"] {
        private::create(&root.join("secrets").join(name), url.as_bytes())?;
    }
    Ok(())
}

/// The operator configuration the supervised `casework` children read.
///
/// It binds the package each start builds from the authored project, so the
/// runtime verifies its package exactly as a deployed one does, and
/// `caseworkctl doctor --runtime-config <this file>` reports on the package
/// the session serves.
pub(super) fn operator(state: &State) -> Value {
    let root = state.root();
    let sources = state
        .sources
        .iter()
        .filter_map(|(id, source)| {
            source.binding.as_ref().map(|binding| (id.clone(), json!({
        "baseUrl": binding.breg_url,
        "readerProfile": "casework-reader",
        "tokenEndpoint": binding.token_endpoint,
        "clientAssertionAudience": state.issuer_origin(),
        "resource": binding.audience,
        "scopes": ["casework:source-reader"],
        "clientIdRef": format!("secret:file/{id}-reader-client-id"),
        "clientAssertionKeyRef": format!("secret:file/{id}-reader-assertion-key.jwk"),
        "webhookSecretRef": format!("secret:file/{id}-webhook-key"),
        "eventSource": binding.event_source,
        "reconciliationIntervalMilliseconds": 5000
    })))
        })
        .collect::<serde_json::Map<_, _>>();
    json!({
        "apiVersion": registry_casework::RUNTIME_CONFIG_API_VERSION,
        "kind": registry_casework::RUNTIME_CONFIG_KIND,
        // One session owns one local database, so a fixed name identifies it.
        "identity": {"databaseId": "casework-local-session"},
        "package": {"root": root.join(super::SESSION_PACKAGE)},
        "listener": {
            "bind": format!("127.0.0.1:{}", state.casework_port),
            "tlsTermination": "development-loopback",
            "networkExposure": "private-address"
        },
        "secretProviders": {"file": {"root": root.join("secrets")}},
        "database": {
            "runtimeUrlRef": "secret:file/runtime-database-url",
            "migrationUrlRef": "secret:file/migration-database-url",
            "trustedRootCertificateRef": "secret:file/database-root.pem"
        },
        "authentication": {"oidc": {
            "issuer": state.issuer_origin(),
            "audience": state.audience(),
            // The session's integrations replace this with the clients they
            // admit before the file is written.
            "allowedClients": "unrestricted",
            // The local issuer emits one space-delimited scope claim.
            "scopeClaim": "scope",
            // The local issuer's keys are generated beside this file, so the
            // runtime reads them directly instead of racing discovery.
            "jwksSource": {"type": "static", "documentRef": "secret:file/issuer-jwks"},
            "humanIdentity": {"claim": HUMAN_CLAIM, "value": HUMAN_VALUE}
        }},
        "audit": {
            "path": root.join("audit/casework.ndjson"),
            "hashKeyRef": "secret:file/casework-audit-key"
        },
        "sources": sources
    })
}

pub(super) fn write_yaml(path: &Path, value: &Value) -> Result<()> {
    private::create(path, serde_norway::to_string(value)?.as_bytes())
}

fn pem(label: &str, bytes: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut result = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        result.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        result.push('\n');
    }
    result.push_str(&format!("-----END {label}-----\n"));
    result
}

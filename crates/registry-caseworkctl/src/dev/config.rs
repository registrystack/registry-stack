// SPDX-License-Identifier: Apache-2.0
//! Authored local teaching identities and generated private service bindings.

use super::{private, State, MIGRATION_ROLE, RUNTIME_ROLE};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::SigningKey;
use registry_casework_core::{
    valid_directory_identifier, valid_profile_identifier, CaseworkProject, CaseworkRole,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Clients {
    pub version: u8,
    pub clients: Vec<Client>,
    #[serde(default)]
    pub directory: Vec<DirectoryTeam>,
    #[serde(default)]
    pub integrations: Option<super::integrations::Integrations>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Client {
    pub id: String,
    pub access_profile: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub claims: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DirectoryTeam {
    pub team: String,
    pub queue: String,
    pub staff: Vec<String>,
    #[serde(default)]
    pub supervisors: Vec<String>,
}

pub(super) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
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

/// Parse and check the clients file against the closed local clients v1
/// format, without reading the authored project. Everything here holds for
/// any project; `bind` adds the checks that need the authored policy.
pub(super) fn clients(bytes: &[u8]) -> Result<Clients> {
    let clients: Clients = serde_norway::from_slice(bytes).map_err(|_| {
        anyhow::anyhow!("clients file must match the closed local clients v1 format")
    })?;
    if clients.version != 1 || clients.clients.is_empty() || clients.clients.len() > 32 {
        bail!("local clients v1 requires 1..32 explicit clients");
    }
    let mut ids = BTreeSet::new();
    let mut profiles = BTreeSet::new();
    for client in &clients.clients {
        if client.id == "issuer" || !identifier(&client.id) || !ids.insert(&client.id) {
            bail!("local clients need unique bounded lowercase IDs, and issuer is reserved for the local token issuer");
        }
        if !valid_profile_identifier(&client.access_profile)
            || !profiles.insert(&client.access_profile)
        {
            bail!("each local access profile must bind to exactly one teaching client");
        }
        let unique_scopes = client.scopes.iter().collect::<BTreeSet<_>>();
        if client.scopes.is_empty()
            || client.scopes.len() > 32
            || unique_scopes.len() != client.scopes.len()
            || client
                .scopes
                .iter()
                .any(|scope| scope.len() > 256 || !valid_scope_token(scope))
        {
            bail!("each local client needs 1..32 unique 1..=256 byte RFC 6749 scope-tokens");
        }
        if client.claims.len() > 32 {
            bail!("a local client may declare at most 32 claims");
        }
        for (name, value) in &client.claims {
            if !valid_authorization_claim_name(name) {
                bail!("local client claim names must be 1..=128 byte RFC 6749 scope-tokens");
            }
            if RESERVED_ACCESS_TOKEN_CLAIMS.contains(&name.as_str()) {
                bail!("local client claims may not redefine registered access-token claims");
            }
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                bail!("local client claim values must be 1..=256 bytes without control characters");
            }
        }
    }
    if clients.directory.len() > 8 {
        bail!("local directory declares at most 8 teams");
    }
    let mut teams = BTreeSet::new();
    let mut queues = BTreeSet::new();
    for team in &clients.directory {
        if !identifier(&team.team)
            || !teams.insert(&team.team)
            || !valid_directory_identifier(&team.queue)
        {
            bail!("each local directory team needs a unique bounded ID and one bounded queue");
        }
        if !queues.insert(&team.queue) {
            bail!(
                "local directory queue {} may be assigned to only one team",
                team.queue
            );
        }
        if team.staff.is_empty() || team.staff.len() > 32 || team.supervisors.len() > 32 {
            bail!("a local directory team needs 1..32 staff and at most 32 supervisors");
        }
        if team.staff.iter().collect::<BTreeSet<_>>().len() != team.staff.len() {
            bail!(
                "local directory team {} staff list must name each client at most once",
                team.team
            );
        }
        if team.supervisors.iter().collect::<BTreeSet<_>>().len() != team.supervisors.len() {
            bail!(
                "local directory team {} supervisors list must name each client at most once",
                team.team
            );
        }
        for member in team.staff.iter().chain(&team.supervisors) {
            if !clients.clients.iter().any(|client| &client.id == member) {
                bail!("local directory team {} names client {member}, which the clients file does not declare", team.team);
            }
        }
    }
    Ok(clients)
}

/// One local client resolved against the authored project: the access profile
/// it binds, that profile's role, and the principal the runtime will see.
#[derive(Debug)]
pub(super) struct Bound<'a> {
    pub client: &'a Client,
    pub role: CaseworkRole,
    pub principal: String,
}

/// Check the clients file against the authored policy and resolve each
/// client's principal. Refusing here, before any container or service starts,
/// tells the author which binding is missing while the fix is one edit away.
pub(super) fn bind<'a>(clients: &'a Clients, project: &CaseworkProject) -> Result<Vec<Bound<'a>>> {
    let mut bound = Vec::with_capacity(clients.clients.len());
    for client in &clients.clients {
        let profile = project
            .access_profiles
            .iter()
            .find(|profile| profile.id == client.access_profile)
            .with_context(|| {
                format!(
                    "client {} binds access profile {}, which casework.yaml does not declare",
                    client.id, client.access_profile
                )
            })?;
        if !profile
            .required_scopes
            .iter()
            .all(|scope| client.scopes.contains(scope))
        {
            bail!(
                "client {} binds profile {}, so it must carry all of that profile's required scopes",
                client.id,
                profile.id
            );
        }
        let human = client.claims.get(HUMAN_CLAIM).map(String::as_str);
        match profile.role {
            CaseworkRole::Requester if human.is_some() => bail!(
                "client {} binds Requester profile {}, so it must not carry the {HUMAN_CLAIM} claim; a Requester is a calling system, not a person",
                client.id,
                profile.id
            ),
            CaseworkRole::Requester => (),
            _ if human != Some(HUMAN_VALUE) => bail!(
                "client {} binds profile {}, which Casework serves only to a person, so it needs the claim {HUMAN_CLAIM}: {HUMAN_VALUE}",
                client.id,
                profile.id
            ),
            _ => (),
        }
        let principal = if profile.principal_claim == "sub" {
            principal(&client.id)
        } else {
            client
                .claims
                .get(&profile.principal_claim)
                .with_context(|| {
                    format!(
                        "client {} binds profile {}, whose principalClaim is {}, so it needs that claim",
                        client.id, profile.id, profile.principal_claim
                    )
                })?
                .clone()
        };
        bound.push(Bound {
            client,
            role: profile.role,
            principal,
        });
    }
    for team in &clients.directory {
        if !project.queues.iter().any(|queue| queue.id == team.queue) {
            bail!(
                "local directory team {} serves queue {}, which casework.yaml does not declare",
                team.team,
                team.queue
            );
        }
        let mut staff_principals = BTreeSet::new();
        for member in &team.staff {
            let entry = bound
                .iter()
                .find(|entry| &entry.client.id == member)
                .context("directory member must be a declared client")?;
            if entry.role == CaseworkRole::Requester {
                bail!(
                    "local directory team {} names Requester client {member}; only a person serves a queue",
                    team.team
                );
            }
            if entry.role != CaseworkRole::Staff {
                bail!(
                    "local directory team {} names client {member} as staff, but that client does not bind a Staff profile",
                    team.team
                );
            }
            if !staff_principals.insert(entry.principal.as_str()) {
                bail!(
                    "local directory team {} staff clients must resolve to unique principals; client {member} repeats a resolved principal",
                    team.team
                );
            }
        }
        let mut supervisor_principals = BTreeSet::new();
        for member in &team.supervisors {
            let entry = bound
                .iter()
                .find(|entry| &entry.client.id == member)
                .context("directory member must be a declared client")?;
            if entry.role == CaseworkRole::Requester {
                bail!(
                    "local directory team {} names Requester client {member}; only a person serves a queue",
                    team.team
                );
            }
            if entry.role != CaseworkRole::Supervisor {
                bail!(
                    "local directory team {} names client {member} as a supervisor, but that client does not bind a Supervisor profile",
                    team.team
                );
            }
            if !supervisor_principals.insert(entry.principal.as_str()) {
                bail!(
                    "local directory team {} supervisor clients must resolve to unique principals; client {member} repeats a resolved principal",
                    team.team
                );
            }
        }
    }
    for queue in &project.queues {
        if !clients.directory.iter().any(|team| team.queue == queue.id) {
            bail!(
                "no local directory team serves queue {}; add one to the clients file so the seeded directory satisfies caseworkctl doctor",
                queue.id
            );
        }
    }
    if !bound
        .iter()
        .any(|entry| entry.role == CaseworkRole::Administrator)
    {
        bail!("local development needs one client bound to an Administrator profile; it seeds the directory");
    }
    Ok(bound)
}

/// The native issuer principal a local client speaks as. It is a local teaching
/// identity, never a deployment identity.
pub(super) fn principal(client_id: &str) -> String {
    registry_thunderid_tooling::local::agent_id("casework-local", client_id)
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
    let borrowed = !state.sources.is_empty();
    let mut local_clients = Vec::new();
    for client in &clients.clients {
        let directory = root.join("credentials").join(&client.id);
        private::directory(&directory)?;
        if borrowed {
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
            integrations.prepare(root, state, &mut description, &policy)?;
        }
        registry_thunderid_tooling::render::render(&description)?;
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
    let migration_password = Zeroizing::new(uuid::Uuid::new_v4().simple().to_string());
    let runtime_password = Zeroizing::new(uuid::Uuid::new_v4().simple().to_string());
    private::create(
        &root.join("database/migration-password"),
        migration_password.as_bytes(),
    )?;
    private::create(
        &root.join("database/runtime-password"),
        runtime_password.as_bytes(),
    )?;
    for (name, role, password) in [
        ("runtime-database-url", RUNTIME_ROLE, &runtime_password),
        (
            "migration-database-url",
            MIGRATION_ROLE,
            &migration_password,
        ),
    ] {
        // The owned container publishes on 127.0.0.1 only. Naming the literal
        // it publishes keeps a host that resolves localhost to ::1 first from
        // failing to connect; the server certificate carries both names.
        let url = Zeroizing::new(format!(
            "postgresql://{role}:{}@127.0.0.1:{}/{}",
            password.as_str(),
            state.database_port,
            super::DATABASE_NAME
        ));
        private::create(&root.join("secrets").join(name), url.as_bytes())?;
    }
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;
    let server_key = rcgen::KeyPair::generate()?;
    let server = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])?
        .signed_by(&server_key, &ca, &ca_key)?;
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
    if !borrowed {
        let mut operator = operator(state);
        if let Some(integrations) = &clients.integrations {
            integrations.operator(state, clients, &mut operator)?;
        }
        write_yaml(&root.join("operator.yaml"), &operator)?;
    }
    Ok(())
}

/// The operator configuration the supervised `casework` children read.
///
/// It binds the authored `casework.yaml` the reader edits, not a copy, so
/// `caseworkctl doctor --runtime-config <this file>` reports on the same
/// policy the reader's `caseworkctl check` reads.
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
        "package": {"root": state.project},
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
            // The local issuer emits one space-delimited scope claim.
            "scopeClaim": "scope",
            // The local issuer's keys are generated beside this file, so the
            // runtime reads them directly instead of racing discovery.
            "jwksSource": {"kind": "static", "documentRef": "secret:file/issuer-jwks"},
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

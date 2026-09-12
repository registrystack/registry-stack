// SPDX-License-Identifier: Apache-2.0
//! Authored local teaching identities and generated private service bindings.

use super::{private, State, DATABASE_ID, MAX_BYTES, MIGRATION_ROLE, RUNTIME_ROLE};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Clients {
    pub version: u8,
    pub clients: Vec<Client>,
    #[serde(default)]
    pub seed: Vec<Seed>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Client {
    pub id: String,
    /// The access profiles this client is the one local binding for. Empty
    /// means no journey step resolves to it and no seed may reference it.
    pub access_profiles: Vec<String>,
    /// Explicitly admits a profile-free integration client to BReg's
    /// `allowedClients`. The default is false, so a client carrying scopes or
    /// claims for another product cannot call BReg accidentally.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_breg_access: bool,
    pub scopes: Vec<String>,
    pub claims: BTreeMap<String, Value>,
    pub client_id_file: Option<PathBuf>,
    pub assertion_key_file: Option<PathBuf>,
}

fn is_false(value: &bool) -> bool {
    !value
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Seed {
    pub id: String,
    pub client: String,
    pub entity: String,
    pub access_profile: String,
    pub data: BTreeMap<String, Value>,
}

pub(super) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

pub(super) fn clients(bytes: &[u8]) -> Result<Clients> {
    let clients: Clients = serde_norway::from_slice(bytes).map_err(|_| {
        anyhow::anyhow!("clients file must match the closed local clients v1 format")
    })?;
    if clients.version != 1
        || clients.clients.is_empty()
        || clients.clients.len() > 32
        || clients.seed.len() > 100
    {
        bail!("local clients v1 requires 1..32 explicit clients and at most 100 seed records");
    }
    let mut ids = BTreeSet::new();
    let mut profiles = BTreeSet::new();
    let mut outputs = BTreeSet::new();
    for client in &clients.clients {
        if client.id == "issuer"
            || !identifier(&client.id)
            || !ids.insert(&client.id)
            || client.scopes.is_empty()
        {
            bail!("local clients need unique bounded IDs and explicit scopes");
        }
        for profile in &client.access_profiles {
            if !identifier(profile) || !profiles.insert(profile) {
                bail!("each local access profile must bind to exactly one teaching client");
            }
        }
        if client.scopes.len() > 32
            || client.claims.len() > 32
            || client
                .scopes
                .iter()
                .any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_whitespace))
        {
            bail!("local client scopes or claims exceed their bounds");
        }
        match (&client.client_id_file, &client.assertion_key_file) {
            (None, None) => (),
            (Some(id), Some(key)) if id != key => {
                for path in [id, key] {
                    if !path.is_absolute()
                        || path
                            .components()
                            .any(|c| matches!(c, std::path::Component::ParentDir))
                        || !outputs.insert(path)
                    {
                        bail!("credential pair outputs must be distinct absolute paths");
                    }
                    let parent = path
                        .parent()
                        .context("credential output requires a parent")?;
                    private::check(parent, true)?;
                    if fs::canonicalize(parent)? != parent {
                        bail!("credential output parent must be canonical");
                    }
                }
            }
            _ => bail!("declare both clientIdFile and assertionKeyFile or neither"),
        }
    }
    let mut seeds = BTreeSet::new();
    for seed in &clients.seed {
        if !identifier(&seed.id)
            || !seeds.insert(&seed.id)
            || !identifier(&seed.entity)
            || !clients.clients.iter().any(|client| {
                client.id == seed.client && client.access_profiles.contains(&seed.access_profile)
            })
        {
            bail!("seeds require unique IDs and an explicitly bound client and access profile");
        }
    }
    Ok(clients)
}

pub(super) fn hash(bytes: &[u8]) -> String {
    crate::hex_lower(&Sha256::digest(bytes))
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

pub(super) fn prepare(root: &Path, state: &State, clients: &Clients) -> Result<()> {
    for directory in [
        "credentials",
        "secrets",
        "tls",
        "issuer",
        "logs",
        "empty-package",
        "database",
    ] {
        private::directory(&root.join(directory))?;
    }
    for client in &clients.clients {
        let directory = root.join("credentials").join(&client.id);
        keypair(&directory)?;
        private::create(&directory.join("client-id"), client.id.as_bytes())?;
    }
    // The dev session's issuer is the pinned upstream ThunderID container,
    // rendered and provisioned through the shared tooling crate from these
    // same authored declarations. BREG keeps its database, seeding, retained
    // state, private outputs, and ownership behavior; only the token issuer
    // changes hands.
    let description = issuer_description(state, clients, root)?;
    registry_thunderid_tooling::render::render(&description)
        .map_err(|error| anyhow::anyhow!("the dev issuer registration was refused: {error}"))?;
    for filename in ["audit-key", "cursor-key"] {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).context("cannot generate local secret")?;
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref()));
        private::create(&root.join("secrets").join(filename), encoded.as_bytes())?;
    }
    if state.webhook_port.is_some() {
        webhook_secret(root)?;
    }
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
    for (name, role, database) in [
        ("runtime-database-url", RUNTIME_ROLE, "breg_dev"),
        ("migration-database-url", MIGRATION_ROLE, "breg_dev"),
        ("test-runtime-database-url", RUNTIME_ROLE, "breg_dev_test"),
        (
            "test-migration-database-url",
            MIGRATION_ROLE,
            "breg_dev_test",
        ),
    ] {
        let password = if role == MIGRATION_ROLE {
            &migration_password
        } else {
            &runtime_password
        };
        // The owned container publishes on 127.0.0.1 only. Naming the literal
        // it publishes keeps a host that resolves localhost to ::1 first from
        // failing to connect; the server certificate carries both names.
        let url = Zeroizing::new(format!(
            "postgresql://{role}:{}@127.0.0.1:{}/{database}",
            password.as_str(),
            state.database_port
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
    private::create(
        &root.join("tls/ca.pem"),
        pem("CERTIFICATE", ca.der()).as_bytes(),
    )?;
    private::create(
        &root.join("tls/server.pem"),
        pem("CERTIFICATE", server.der()).as_bytes(),
    )?;
    private::create(
        &root.join("tls/server.key"),
        Zeroizing::new(pem("PRIVATE KEY", &server_key.serialize_der())).as_bytes(),
    )?;
    private::create(&root.join("database/pg_hba.conf"), b"local all all trust\nhostnossl all all 0.0.0.0/0 reject\nhostnossl all all ::/0 reject\nhostssl all all 0.0.0.0/0 scram-sha-256\nhostssl all all ::/0 scram-sha-256\n")?;
    private::create(&root.join("trust-anchor.json"), b"{}")?;
    runtime(
        root,
        state,
        clients,
        &format!("sha256:{}", "1".repeat(64)),
        true,
    )?;
    Ok(())
}

/// The dev session's issuer description: one resource server whose
/// identifier is BREG's exact access-token audience, one role per authored
/// client carrying that client's scopes, and one machine agent per client
/// whose static attributes are the authored claims. Derived from the
/// reviewed client declarations only; nothing here reads the registry
/// project's business model.
pub(super) fn issuer_description(
    state: &State,
    clients: &Clients,
    root: &Path,
) -> Result<registry_thunderid_tooling::description::IssuerDescription> {
    use registry_thunderid_tooling::{
        description::SessionIdentity,
        local::{local_description, LocalClient},
    };
    let local_clients = clients
        .clients
        .iter()
        .map(|client| {
            let claims = client
                .claims
                .iter()
                .map(|(name, value)| {
                    let value = value.as_str().with_context(|| {
                        format!("claim {name:?} must be a string to ride a machine token")
                    })?;
                    Ok((name.clone(), value.to_owned()))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            let directory = root.join("credentials").join(&client.id);
            let public: Value =
                serde_json::from_slice(&private::read(&directory.join("public.jwk"), 4096)?)?;
            Ok(LocalClient {
                client_id: client.id.clone(),
                public_jwks: serde_json::to_string(&json!({"keys":[public]}))?,
                claims,
                scopes: client.scopes.clone(),
                allow_human_fixture: false,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    local_description(
        SessionIdentity {
            label: format!("breg-dev-{}", state.instance_id),
            id: state.instance_id.clone(),
        },
        state.issuer_port,
        root.join("issuer"),
        state.audience(),
        local_clients,
    )
    .map_err(Into::into)
}

/// Re-render an explicitly prepared, stopped-session successor in a separate
/// private tree, then publish only this session's native issuer documents.
/// The owning source-transition journal makes an interrupted publication
/// repeatable. Existing client keys and unrelated issuer database state stay
/// untouched.
pub(super) fn refresh_issuer_registration(state: &State, clients: &Clients) -> Result<()> {
    fn publish_tree(source: &Path, destination: &Path) -> Result<()> {
        private::directory(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let source = entry.path();
            let destination = destination.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                publish_tree(&source, &destination)?;
            } else {
                let bytes = private::read(&source, MAX_BYTES)?;
                private::replace(&destination, &bytes)?;
            }
        }
        Ok(())
    }

    let root = state.root();
    let staging = root.join(format!(".issuer-render-{}", uuid::Uuid::new_v4()));
    private::directory(&staging)?;
    let result: Result<()> = (|| {
        let mut description = issuer_description(state, clients, &root)?;
        description.state_root = staging.clone();
        registry_thunderid_tooling::render::render(&description).map_err(|error| {
            anyhow::anyhow!("the successor issuer registration was refused: {error}")
        })?;
        private::validate_tree(&staging)?;
        for directory in ["resources", "registry-schema"] {
            publish_tree(
                &staging.join(directory),
                &root.join("issuer").join(directory),
            )?;
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&staging);
    result?;
    cleanup.context("cannot remove the private issuer rendering stage")
}

pub(super) fn runtime(
    root: &Path,
    state: &State,
    clients: &Clients,
    revision: &str,
    test: bool,
) -> Result<()> {
    let final_root = state.root();
    let prefix = if test { "test-" } else { "" };
    let destinations = if let Some(port) = state.webhook_port {
        let compiled = crate::compile(&root.join("project"), crate::ProfileArg::Production, "dev")
            .map_err(|_| anyhow::anyhow!("captured event project no longer compiles"))?;
        event_destinations(&compiled, port)
    } else {
        json!({})
    };
    write_yaml(
        &root.join(if test {
            "runtime-test.yaml"
        } else {
            "runtime.yaml"
        }),
        &json!({
            "apiVersion":"registry.registrystack.org/breg-runtime/v1alpha1","kind":"BRegRuntimeConfig",
            "listener":{"bind":format!("127.0.0.1:{}",state.breg_port)},
            "identity":{"environment":"local","instanceId":state.instance_id,"databaseId":DATABASE_ID,"databaseInitializationEnvironment":"local"},
            "secretProviders":{"file":{"root":final_root.join("secrets")}},
            "database":{"runtimeUrlRef":format!("secret:file/{prefix}runtime-database-url"),"migrationUrlRef":format!("secret:file/{prefix}migration-database-url"),"pool":{"maxSize":4},"roles":{"migration":MIGRATION_ROLE,"runtime":RUNTIME_ROLE}},
            "package":{"root":final_root.join(if test {"empty-package"}else{"build/package"}),"trustAnchorPath":final_root.join("trust-anchor.json"),"compilerSourceRevision":state.source_revision,"activeRevision":revision,"activeSequence":state.sequence},
            "authentication":{"oidc":{"issuer":state.issuer_origin(),"audience":state.audience(),"allowedAlgorithm":"RS256","accessTokenType":"at+jwt","scopeClaim":"scope","scopeSeparator":" ","allowedClients":clients.clients.iter().filter(|client| !client.access_profiles.is_empty() || client.allow_breg_access).map(|client|&client.id).collect::<Vec<_>>(),"deniedKids":[],"maxTokenLifetimeSeconds":300,"leewayMilliseconds":30000,"jwksSource":{"kind":"static","documentRef":"secret:file/issuer-jwks"}},"authorityClaims":{"principal":"registry_principal","purpose":"registry_purpose"}},
            "audit":{"hashKeyRef":"secret:file/audit-key"},"cursor":{"secretRef":"secret:file/cursor-key"},"eventDestinations":destinations
        }),
    )
}

pub(super) fn webhook_secret(root: &Path) -> Result<()> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).context("cannot generate local webhook secret")?;
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref()));
    private::create(&root.join("secrets/webhook-key"), encoded.as_bytes())
}

/// Use the same compiled inventory as `explain events`. Shared destinations
/// use the tightest attempt ceilings and the highest projected classification.
fn event_destinations(compiled: &registry_breg::CompiledRegistry, port: u16) -> Value {
    let mut destinations = BTreeMap::new();
    for delivery in &compiled.event_deliveries().deliveries {
        let (classification, timeout, attempts) =
            destinations.entry(&delivery.destination_id).or_insert((
                delivery.classification_ceiling,
                delivery.attempt_timeout_ms,
                delivery.maximum_attempts,
            ));
        *classification = (*classification).max(delivery.classification_ceiling);
        *timeout = (*timeout).min(delivery.attempt_timeout_ms);
        *attempts = (*attempts).min(delivery.maximum_attempts);
    }
    Value::Object(destinations.into_iter().map(|(id, (classification, timeout, attempts))| {
        (id.clone(), json!({
            "origin":format!("http://127.0.0.1:{port}"),"path":"/events",
            "networkProfile":"loopbackDevelopmentHttp","dnsFamily":"dualStackStrict",
            "allowedPrivateCidrs":[],"hmacSha256KeyRef":"secret:file/webhook-key",
            "classificationCeiling":classification,
            "deliveryCeilings":{"attemptTimeoutMilliseconds":timeout,"maximumAttempts":attempts}
        }))
    }).collect())
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

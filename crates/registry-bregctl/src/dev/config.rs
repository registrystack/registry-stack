// SPDX-License-Identifier: Apache-2.0
//! Authored local teaching identities and generated private service bindings.

use super::{private, State, DATABASE_ID, MIGRATION_ROLE, RUNTIME_ROLE};
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
    /// means the client registers with Mint but is excluded from BReg's
    /// `allowedClients`: no journey step resolves to it, no seed may reference
    /// it, and it cannot authenticate to BReg.
    pub access_profiles: Vec<String>,
    pub scopes: Vec<String>,
    pub claims: BTreeMap<String, Value>,
    pub client_id_file: Option<PathBuf>,
    pub assertion_key_file: Option<PathBuf>,
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
        "mint",
        "logs",
        "empty-package",
        "database",
    ] {
        private::directory(&root.join(directory))?;
    }
    private::directory(&root.join("mint/clients"))?;
    private::directory(&root.join("mint/audit"))?;
    let mint_public = keypair(&root.join("credentials/issuer"))?;
    let mint_public_filename = format!(
        "{}.jwk.json",
        mint_public["kid"]
            .as_str()
            .context("generated issuer key ID missing")?
    );
    private::create(
        &root.join("credentials/issuer").join(&mint_public_filename),
        &serde_json::to_vec(&mint_public)?,
    )?;
    for client in &clients.clients {
        let directory = root.join("credentials").join(&client.id);
        let public = keypair(&directory)?;
        private::create(&directory.join("client-id"), client.id.as_bytes())?;
        write_yaml(
            &root
                .join("mint/clients")
                .join(format!("{}.yaml", client.id)),
            &json!({
                "clientId":client.id,"principal":format!("urn:breg:dev:{}",client.id),
                "authorization":{"scopes":client.scopes,"claims":client.claims},"keys":[public]
            }),
        )?;
    }
    for filename in ["audit-key", "cursor-key", "mint-audit-key"] {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).context("cannot generate local secret")?;
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref()));
        private::create(&root.join("secrets").join(filename), encoded.as_bytes())?;
    }
    if state.webhook_port.is_some() {
        webhook_secret(root)?;
    }
    private::create(
        &root.join("secrets/mint-jwks"),
        &serde_json::to_vec(&json!({"keys":[mint_public]}))?,
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
    let final_root = state.root();
    let mint_origin = state.mint_origin();
    write_yaml(
        &root.join("mint/mint.yaml"),
        &json!({
            "version":1,"validationMode":"supervised-local-development","issuer":mint_origin,
            "listener":{"address":"127.0.0.1","port":state.mint_port},
            "signing":{"algorithm":"ES256","activePublicJwkFile":final_root.join("credentials/issuer").join(mint_public_filename),"publishedPublicJwkFiles":[],"revokedKeyIds":[]},
            "signer":{"kind":"local-jwk","privateKeyRef":"secret:file/assertion-key.jwk"},
            "secretProviders":{"file":{"root":final_root.join("credentials/issuer")}},
            "audit":{"path":"audit/mint.jsonl","maximumFileBytes":10485760,"hashKeyRef":"secret:file/mint-audit-key","hashKeyVersion":1},
            "accessTokens":{"audiences":[state.audience()],"lifetimeSeconds":300},
            "clientAssertion":{"audience":format!("{mint_origin}/token"),"maximumLifetimeSeconds":120,"algorithms":["ES256"]},
            "clients":{"directory":"clients"}
        }),
    )?;
    // One secret root serves Mint signing and audit; no cross-directory secret references.
    private::create(
        &root.join("credentials/issuer/mint-audit-key"),
        &private::read(&root.join("secrets/mint-audit-key"), 64)?,
    )?;
    runtime(
        root,
        state,
        clients,
        &format!("sha256:{}", "1".repeat(64)),
        true,
    )?;
    Ok(())
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
            "authentication":{"oidc":{"issuer":state.mint_origin(),"audience":state.audience(),"allowedAlgorithm":"ES256","accessTokenType":"at+jwt","scopeClaim":"scope","scopeSeparator":" ","allowedClients":clients.clients.iter().filter(|client| !client.access_profiles.is_empty()).map(|client|&client.id).collect::<Vec<_>>(),"deniedKids":[],"maxTokenLifetimeSeconds":300,"leewayMilliseconds":30000,"jwksSource":{"kind":"static","documentRef":"secret:file/mint-jwks"}},"authorityClaims":{"principal":"registry_principal","purpose":"registry_purpose"}},
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

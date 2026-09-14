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
    #[serde(default)]
    pub issuer: IssuerComposition,
    /// Optional exact local webhook bindings. An empty map keeps the inbox.
    #[serde(default)]
    pub event_destinations: BTreeMap<String, LocalEventDestination>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LocalEventDestination {
    pub origin: String,
    pub path: String,
    pub hmac_key_file: PathBuf,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IssuerComposition {
    #[serde(default)]
    pub resources: Vec<IssuerResource>,
    #[serde(default)]
    pub exchange_issuers: Vec<IssuerConnection>,
    #[serde(default)]
    pub interactive_applications: Vec<BrowserApplication>,
    /// Owner-registered browser app IDs this borrower admits at its BREG resource.
    #[serde(default)]
    pub browser_clients: Vec<String>,
    #[serde(default)]
    pub synthetic_users: Vec<BrowserUser>,
    /// Client IDs mapped to a non-default resource audience.
    #[serde(default)]
    pub client_resources: BTreeMap<String, String>,
    /// Clients with one bootstrap scope that may exchange signed assertions.
    #[serde(default)]
    pub exchange_clients: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IssuerResource {
    pub audience: String,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IssuerConnection {
    pub id: String,
    pub issuer: String,
    pub jwks_endpoint: String,
    pub mapping: IssuerConnectionMapping,
    #[serde(default)]
    pub clients: Vec<String>,
    #[serde(default)]
    pub token_attributes:
        BTreeMap<String, registry_thunderid_tooling::description::ExchangeAttributeKind>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum IssuerConnectionMapping {
    InstitutionalGrant,
    FirstParty,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BrowserApplication {
    pub id: String,
    pub client_secret_file: PathBuf,
    pub origin: String,
    pub redirect_uris: Vec<String>,
    pub audience: Option<String>,
    /// Explicit permissions granted to this application, per resource audience.
    #[serde(default)]
    pub grants: Vec<LocalPermissionGrant>,
    pub token_attributes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BrowserUser {
    pub username: String,
    pub email: String,
    pub password_file: PathBuf,
    pub attributes: BTreeMap<String, String>,
    /// Explicit permissions granted to this user, per resource audience.
    #[serde(default)]
    pub grants: Vec<LocalPermissionGrant>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LocalPermissionGrant {
    /// Omit for the owner BREG resource; otherwise use a declared audience.
    pub audience: Option<String>,
    pub scopes: Vec<String>,
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
    /// Explicitly permits this local teaching client to carry the human actor
    /// marker. This does not admit the client to BReg's allowedClients.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_human_fixture: bool,
    pub scopes: Vec<String>,
    pub claims: BTreeMap<String, Value>,
    /// Exact schema-test steps that use this claim variant. Runtime requests
    /// still select an authored access profile; this field only disambiguates
    /// credentials for maintained local journeys.
    #[serde(default)]
    pub test_bindings: Vec<TestBinding>,
    pub client_id_file: Option<PathBuf>,
    pub assertion_key_file: Option<PathBuf>,
    /// Existing owner-only ES256 assertion key, for a client whose key is
    /// already governed by another local tool such as Evidence access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion_key_input_file: Option<PathBuf>,
}

fn is_false(value: &bool) -> bool {
    !value
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TestBinding {
    pub journey_id: String,
    pub step_id: String,
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

fn grant_scopes(clients: &Clients, audience: Option<&str>, scopes: &[String]) -> bool {
    let available: BTreeSet<_> = match audience {
        Some(audience) => clients
            .issuer
            .resources
            .iter()
            .find(|resource| resource.audience == audience)
            .map(|resource| resource.scopes.iter().map(String::as_str).collect())
            .unwrap_or_default(),
        None => clients
            .clients
            .iter()
            .filter(|client| !clients.issuer.client_resources.contains_key(&client.id))
            .flat_map(|client| client.scopes.iter().map(String::as_str))
            .collect(),
    };
    !scopes.is_empty()
        && scopes.len() <= 32
        && scopes.iter().collect::<BTreeSet<_>>().len() == scopes.len()
        && scopes
            .iter()
            .all(|scope| available.contains(scope.as_str()))
}

fn valid_grants(clients: &Clients, grants: &[LocalPermissionGrant]) -> bool {
    !grants.is_empty()
        && grants.len() <= 7
        && grants
            .iter()
            .all(|grant| grant_scopes(clients, grant.audience.as_deref(), &grant.scopes))
        && grants
            .iter()
            .map(|grant| grant.audience.as_deref())
            .collect::<BTreeSet<_>>()
            .len()
            == grants.len()
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
    let mut profile_defaults = BTreeSet::new();
    let mut test_bindings = BTreeSet::new();
    let mut outputs = BTreeSet::new();
    for client in &clients.clients {
        let mut client_profiles = BTreeSet::new();
        if client.id == "issuer"
            || !identifier(&client.id)
            || !ids.insert(&client.id)
            || client.scopes.is_empty()
        {
            bail!("local clients need unique bounded IDs and explicit scopes");
        }
        let carries_human_marker = client
            .claims
            .get("registry_actor_kind")
            .is_some_and(|kind| kind == "human");
        if client.allow_human_fixture != carries_human_marker {
            bail!("allowHumanFixture must be true exactly when registry_actor_kind is human");
        }
        for profile in &client.access_profiles {
            if !identifier(profile) || !client_profiles.insert(profile) {
                bail!(
                    "local access profile bindings must be unique bounded identifiers per client"
                );
            }
            if client.test_bindings.is_empty() && !profile_defaults.insert(profile) {
                bail!("a shared local access profile needs at most one default client; use exact testBindings for claim variants");
            }
        }
        if client.test_bindings.len() > 100 {
            bail!("one local client may bind at most 100 schema-test steps");
        }
        for binding in &client.test_bindings {
            if !identifier(&binding.journey_id)
                || !identifier(&binding.step_id)
                || !test_bindings.insert(binding.clone())
            {
                bail!("testBindings need unique exact bounded journeyId and stepId pairs");
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
        if let Some(path) = &client.assertion_key_input_file {
            if !path.is_absolute() {
                bail!("assertionKeyInputFile must be absolute");
            }
            private::check(path, false)?;
        }
    }
    if clients.issuer.resources.len() > 7
        || clients.issuer.exchange_issuers.len() > 8
        || clients.issuer.interactive_applications.len() > 8
        || clients.issuer.browser_clients.len() > 8
        || clients.issuer.synthetic_users.len() > 32
        || clients.issuer.client_resources.len() > 32
        || clients.issuer.exchange_clients.len() > 32
    {
        bail!("local issuer composition exceeds its bounded inventory");
    }
    if clients.event_destinations.len() > 16 {
        bail!("at most 16 local event destinations may be bound");
    }
    for (id, destination) in &clients.event_destinations {
        let origin = reqwest::Url::parse(&destination.origin)
            .context("local event destination origin must be an exact loopback HTTP URL")?;
        if !identifier(id)
            || origin.scheme() != "http"
            || origin.host_str() != Some("127.0.0.1")
            || origin.port().is_none()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || destination.path.len() > 256
            || !destination.path.starts_with('/')
            || destination.path.starts_with("//")
            || destination.path.contains(['?', '#', '\\'])
            || destination.path.chars().any(char::is_control)
        {
            bail!("local event destinations need bounded IDs, exact loopback origins, and absolute paths");
        }
        private::check(&destination.hmac_key_file, false)?;
    }
    let mut resource_ids = BTreeSet::new();
    for resource in &clients.issuer.resources {
        if !registry_platform_httputil::valid_resource_uri(&resource.audience)
            || !resource_ids.insert(&resource.audience)
            || resource.scopes.is_empty()
            || resource.scopes.len() > 32
            || resource
                .scopes
                .iter()
                .any(|scope| !registry_platform_httputil::valid_scope_token(scope))
        {
            bail!("local issuer resources require distinct audiences and exact bounded scopes");
        }
    }
    for (client, resource) in &clients.issuer.client_resources {
        if !ids.contains(client)
            || !resource_ids.contains(resource)
            || !clients
                .clients
                .iter()
                .find(|entry| &entry.id == client)
                .is_some_and(|entry| grant_scopes(&clients, Some(resource), &entry.scopes))
        {
            bail!("issuer client resource bindings need a declared client, audience, and resource scopes");
        }
    }
    let mut exchange_clients = BTreeSet::new();
    for id in &clients.issuer.exchange_clients {
        if !exchange_clients.insert(id)
            || clients.issuer.exchange_issuers.is_empty()
            || !clients
                .clients
                .iter()
                .any(|client| &client.id == id && client.scopes.len() == 1)
        {
            bail!("exchange clients need one exact bootstrap scope and an exchange issuer");
        }
    }
    let mut connection_ids = BTreeSet::new();
    for connection in &clients.issuer.exchange_issuers {
        if !identifier(&connection.id) || !connection_ids.insert(&connection.id) {
            bail!("local exchange connections require distinct bounded IDs");
        }
    }
    let mut app_ids = BTreeSet::new();
    for app in &clients.issuer.interactive_applications {
        if !identifier(&app.id)
            || !app_ids.insert(&app.id)
            || ids.contains(&app.id)
            || app
                .audience
                .as_ref()
                .is_some_and(|audience| !resource_ids.contains(audience))
            || !valid_grants(&clients, &app.grants)
        {
            bail!("browser applications need distinct IDs and exact declared resource permissions");
        }
        private::check(&app.client_secret_file, false)?;
    }
    for id in &clients.issuer.browser_clients {
        if !identifier(id) || !app_ids.insert(id) || ids.contains(id) {
            bail!("borrowed browser clients need distinct bounded IDs");
        }
    }
    let mut usernames = BTreeSet::new();
    for user in &clients.issuer.synthetic_users {
        if !identifier(&user.username) || !usernames.insert(&user.username) {
            bail!("synthetic users need distinct bounded usernames");
        }
        if !valid_grants(&clients, &user.grants) {
            bail!("synthetic user grants need distinct declared resources and exact permissions");
        }
        private::check(&user.password_file, false)?;
    }
    for (id, destination) in &clients.event_destinations {
        let key = Zeroizing::new(private::read(&destination.hmac_key_file, 1024)?);
        if key.len() < 32 {
            bail!("local event destination {id} needs at least 32 HMAC key bytes");
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
    if state.issuer_project.is_some() {
        validate_borrowed_issuer_composition(&clients.issuer)?;
    }
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
    let borrowed = super::borrowed_owner(state)?;
    let owner_clients: Option<Clients> = borrowed
        .as_ref()
        .map(|owner| {
            serde_json::from_slice(&private::read(
                &owner.root().join("clients.json"),
                MAX_BYTES,
            )?)
            .context("shared issuer owner has invalid retained clients")
        })
        .transpose()?;
    if !clients.issuer.browser_clients.is_empty() {
        let (Some(owner), Some(owner_clients)) = (&borrowed, &owner_clients) else {
            bail!("browserClients requires a ready BREG issuer owner");
        };
        check_borrowed_browser_clients(
            owner_clients,
            &clients.issuer.browser_clients,
            &state.audience(),
            &owner.audience(),
        )?;
    }
    for client in &clients.clients {
        let directory = root.join("credentials").join(&client.id);
        if let (Some(owner), Some(owner_clients)) = (&borrowed, &owner_clients) {
            let registered = owner_clients
                .clients
                .iter()
                .find(|entry| entry.id == client.id)
                .with_context(|| {
                    format!("shared issuer owner has no registration for {}", client.id)
                })?;
            if registered.scopes != client.scopes
                || registered.claims != client.claims
                || registered.allow_human_fixture != client.allow_human_fixture
                || owner_clients
                    .issuer
                    .client_resources
                    .contains_key(&client.id)
            {
                bail!("shared issuer registration differs from the local client or BREG audience for {}", client.id);
            }
            private::directory(&directory)?;
            let source = owner.root().join("credentials").join(&client.id);
            let id = Zeroizing::new(private::read(&source.join("client-id"), MAX_BYTES)?);
            let key = Zeroizing::new(private::read(&source.join("assertion-key.jwk"), MAX_BYTES)?);
            super::export_client::validate_pair(&id, &key, &client.id)?;
            private::create(&directory.join("client-id"), &id)?;
            private::create(&directory.join("assertion-key.jwk"), &key)?;
            private::create(
                &directory.join("public.jwk"),
                &private::read(&source.join("public.jwk"), 4096)?,
            )?;
        } else {
            if let Some(input) = &client.assertion_key_input_file {
                import_keypair(&directory, input, &client.id)?;
            } else {
                keypair(&directory)?;
            }
            private::create(&directory.join("client-id"), client.id.as_bytes())?;
        }
    }
    if !clients.issuer.interactive_applications.is_empty()
        || !clients.issuer.synthetic_users.is_empty()
    {
        private::directory(&root.join("issuer/secrets"))?;
    }
    for app in &clients.issuer.interactive_applications {
        let secret = Zeroizing::new(private::read(&app.client_secret_file, 1024)?);
        private::create(
            &root
                .join("issuer/secrets")
                .join(format!("application-{}", app.id)),
            &secret,
        )?;
    }
    for user in &clients.issuer.synthetic_users {
        let password = Zeroizing::new(private::read(&user.password_file, 1024)?);
        private::create(
            &root
                .join("issuer/secrets")
                .join(format!("user-{}", user.username)),
            &password,
        )?;
    }
    for (id, destination) in &clients.event_destinations {
        let key = Zeroizing::new(private::read(&destination.hmac_key_file, 1024)?);
        private::create(&root.join("secrets").join(format!("webhook-{id}")), &key)?;
    }
    // The dev session's issuer is the pinned upstream ThunderID container,
    // rendered and provisioned through the shared tooling crate from these
    // same authored declarations. BREG keeps its database, seeding, retained
    // state, private outputs, and ownership behavior; only the token issuer
    // changes hands.
    if borrowed.is_none() {
        let description = issuer_description(state, clients, root)?;
        registry_thunderid_tooling::render::render(&description)
            .map_err(|error| anyhow::anyhow!("the dev issuer registration was refused: {error}"))?;
    }
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
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "BREG local development CA");
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_key = rcgen::KeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;
    let server_key = rcgen::KeyPair::generate()?;
    let mut server_params =
        rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])?;
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "BREG local PostgreSQL");
    server_params.use_authority_key_identifier_extension = true;
    server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server = server_params.signed_by(&server_key, &ca, &ca_key)?;
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

fn validate_borrowed_issuer_composition(issuer: &IssuerComposition) -> Result<()> {
    if !issuer.resources.is_empty()
        || !issuer.exchange_issuers.is_empty()
        || !issuer.interactive_applications.is_empty()
        || !issuer.synthetic_users.is_empty()
        || !issuer.client_resources.is_empty()
        || !issuer.exchange_clients.is_empty()
    {
        bail!("a borrowed issuer cannot declare owner-only resources, exchange connections, applications, users, or client mappings; declare them on the issuer owner");
    }
    Ok(())
}

pub(super) fn check_borrowed_browser_clients(
    owner: &Clients,
    selected: &[String],
    audience: &str,
    owner_default: &str,
) -> Result<()> {
    for id in selected {
        let matched = owner.issuer.interactive_applications.iter().any(|app| {
            &app.id == id && app.audience.as_deref().unwrap_or(owner_default) == audience
        });
        if !matched {
            bail!("shared issuer owner has no browser application for this BREG resource: {id}");
        }
    }
    Ok(())
}

fn import_keypair(directory: &Path, input: &Path, id: &str) -> Result<()> {
    private::directory(directory)?;
    let key = Zeroizing::new(private::read(input, 16 * 1024)?);
    super::export_client::validate_pair(id.as_bytes(), &key, id)?;
    let private: Value = serde_json::from_slice(&key)?;
    let public = json!({
        "kty": private["kty"], "crv": private["crv"], "alg": private["alg"],
        "kid": private["kid"], "x": private["x"], "y": private["y"]
    });
    private::create(&directory.join("assertion-key.jwk"), &key)?;
    private::create(&directory.join("public.jwk"), &serde_json::to_vec(&public)?)
}

fn role_permissions(
    description: &registry_thunderid_tooling::description::IssuerDescription,
    state: &State,
    grants: &[LocalPermissionGrant],
) -> Result<Vec<(String, Vec<String>)>> {
    grants
        .iter()
        .map(|grant| {
            let audience = grant.audience.clone().unwrap_or_else(|| state.audience());
            let server = description
                .resource_servers
                .iter()
                .find(|server| server.identifier == audience)
                .context("local permission grant resource is missing")?;
            Ok((server.id.clone(), grant.scopes.clone()))
        })
        .collect()
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
        description::{
            ExchangeIssuer, ExchangeMapping, InteractiveApplication, Role, SessionIdentity,
            SyntheticUser, TokenExchangeClient,
        },
        local::{typed_local_description, TypedLocalClient},
    };
    let local_clients = clients
        .clients
        .iter()
        .map(|client| {
            let mut claims = client.claims.clone();
            // An omitted local marker describes the ordinary machine client.
            // Explicit human and agent teaching identities retain their kind.
            claims
                .entry("registry_actor_kind".to_owned())
                .or_insert_with(|| json!("service"));
            let directory = root.join("credentials").join(&client.id);
            let public: Value =
                serde_json::from_slice(&private::read(&directory.join("public.jwk"), 4096)?)?;
            Ok(TypedLocalClient {
                client_id: client.id.clone(),
                public_jwks: serde_json::to_string(&json!({"keys":[public]}))?,
                claims,
                scopes: client.scopes.clone(),
                allow_human_fixture: client.allow_human_fixture,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut description = typed_local_description(
        SessionIdentity {
            label: format!("breg-dev-{}", state.instance_id),
            id: state.instance_id.clone(),
        },
        state.issuer_port,
        root.join("issuer"),
        state.audience(),
        local_clients,
    )?;
    for resource in &clients.issuer.resources {
        registry_thunderid_tooling::local::declare_resource(
            &mut description,
            &resource.audience,
            &resource.scopes,
        )?;
    }
    for (client_id, audience) in &clients.issuer.client_resources {
        let server = description
            .resource_servers
            .iter()
            .find(|server| &server.identifier == audience)
            .context("a declared issuer resource is missing")?;
        let agent = registry_thunderid_tooling::local::agent_id(&state.instance_id, client_id);
        let role = description
            .roles
            .iter_mut()
            .find(|role| role.assigned_agents.contains(&agent))
            .context("a declared issuer client role is missing")?;
        role.permissions[0].0 = server.id.clone();
    }
    for id in &clients.issuer.exchange_clients {
        let client = clients
            .clients
            .iter()
            .find(|client| &client.id == id)
            .context("an exchange client is missing")?;
        let machine = description
            .machine_clients
            .iter_mut()
            .find(|machine| machine.client_id == *id)
            .context("an exchange registration is missing")?;
        let role = description
            .roles
            .iter()
            .find(|role| role.assigned_agents.contains(&machine.agent_id))
            .context("an exchange bootstrap role is missing")?;
        machine.token_exchange = Some(TokenExchangeClient {
            assertion_resource_server_id: role.permissions[0].0.clone(),
            assertion_scope: client.scopes[0].clone(),
        });
    }
    for issuer in &clients.issuer.exchange_issuers {
        description.exchange_issuers.push(ExchangeIssuer {
            id: registry_thunderid_tooling::local::agent_id(
                &state.instance_id,
                &format!("connection-{}", issuer.id),
            ),
            name: format!("Local {}", issuer.id),
            issuer: issuer.issuer.clone(),
            jwks_endpoint: issuer.jwks_endpoint.clone(),
            mapping: match issuer.mapping {
                IssuerConnectionMapping::InstitutionalGrant => ExchangeMapping::InstitutionalGrant,
                IssuerConnectionMapping::FirstParty => ExchangeMapping::FirstParty,
            },
            clients: issuer.clients.clone(),
            token_attributes: issuer.token_attributes.clone(),
        });
    }
    for app in &clients.issuer.interactive_applications {
        let app_id = registry_thunderid_tooling::local::agent_id(
            &state.instance_id,
            &format!("application-{}", app.id),
        );
        let audience = app.audience.clone().unwrap_or_else(|| state.audience());
        let permissions = role_permissions(&description, state, &app.grants)?;
        description
            .interactive_applications
            .push(InteractiveApplication {
                id: app_id.clone(),
                client_id: app.id.clone(),
                client_secret_file: format!("secrets/application-{}", app.id).into(),
                origin: app.origin.clone(),
                redirect_uris: app.redirect_uris.clone(),
                audience,
                token_attributes: app.token_attributes.clone(),
            });
        description.roles.push(Role {
            id: registry_thunderid_tooling::local::agent_id(
                &state.instance_id,
                &format!("application-role-{}", app.id),
            ),
            name: format!("Local browser {}", app.id),
            description: "Explicit local browser application permissions".into(),
            permissions,
            assigned_agents: vec![],
            assigned_users: vec![],
            assigned_applications: vec![app_id],
        });
    }
    for user in &clients.issuer.synthetic_users {
        let user_id = registry_thunderid_tooling::local::agent_id(
            &state.instance_id,
            &format!("user-{}", user.username),
        );
        description.synthetic_users.push(SyntheticUser {
            id: user_id.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            password_file: format!("secrets/user-{}", user.username).into(),
            attributes: user.attributes.clone(),
        });
        let permissions = role_permissions(&description, state, &user.grants)?;
        description.roles.push(Role {
            id: registry_thunderid_tooling::local::agent_id(
                &state.instance_id,
                &format!("user-role-{}", user.username),
            ),
            name: format!("Local user {}", user.username),
            description: "Explicit local synthetic user permissions".into(),
            permissions,
            assigned_agents: vec![],
            assigned_users: vec![user_id],
            assigned_applications: vec![],
        });
    }
    description.validate()?;
    Ok(description)
}

/// Re-render an explicitly prepared, stopped-session successor in a separate
/// private tree, then publish only this session's native issuer documents.
/// The owning source-transition journal makes an interrupted publication
/// repeatable. Existing client keys and unrelated issuer database state stay
/// untouched.
pub(super) fn refresh_issuer_registration(state: &State, clients: &Clients) -> Result<()> {
    if state.issuer_project.is_some() {
        return Ok(());
    }
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
    let destinations = if state.webhook_port.is_some() || !clients.event_destinations.is_empty() {
        let compiled = crate::compile(&root.join("project"), crate::ProfileArg::Production, "dev")
            .map_err(|_| anyhow::anyhow!("captured event project no longer compiles"))?;
        if let Some(port) = state.webhook_port {
            event_destinations(&compiled, port)
        } else {
            external_event_destinations(&compiled, &clients.event_destinations)?
        }
    } else {
        json!({})
    };
    // A browser application explicitly using this session's default BREG
    // audience is a local OAuth client. Other-resource apps remain outside
    // BREG admission; governed profiles and token scopes still authorize calls.
    let allowed_clients = clients
        .clients
        .iter()
        .filter(|client| !client.access_profiles.is_empty() || client.allow_breg_access)
        .map(|client| &client.id)
        .chain(
            clients
                .issuer
                .interactive_applications
                .iter()
                .filter(|app| app.audience.is_none())
                .map(|app| &app.id),
        )
        .chain(clients.issuer.browser_clients.iter())
        .collect::<Vec<_>>();
    write_yaml(
        &root.join(if test {
            "runtime-test.yaml"
        } else {
            "runtime.yaml"
        }),
        &json!({
            "apiVersion":"registry.registrystack.org/breg-runtime/v1alpha1","kind":"BRegRuntimeConfig",
            "listener":{"bind":format!("127.0.0.1:{}",state.breg_port),"publicOrigin":state.breg_origin()},
            "identity":{"environment":"local","instanceId":state.instance_id,"databaseId":DATABASE_ID,"databaseInitializationEnvironment":"local"},
            "secretProviders":{"file":{"root":final_root.join("secrets")}},
            "database":{"runtimeUrlRef":format!("secret:file/{prefix}runtime-database-url"),"migrationUrlRef":format!("secret:file/{prefix}migration-database-url"),"pool":{"maxSize":4},"roles":{"migration":MIGRATION_ROLE,"runtime":RUNTIME_ROLE}},
            "package":{"root":final_root.join(if test {"empty-package"}else{"build/package"}),"trustAnchorPath":final_root.join("trust-anchor.json"),"compilerSourceRevision":state.source_revision,"activeRevision":revision,"activeSequence":state.sequence},
            "authentication":{"oidc":{"issuer":state.issuer_origin(),"audience":state.audience(),"allowedAlgorithm":"RS256","accessTokenType":"at+jwt","scopeClaim":"scope","scopeSeparator":" ","allowedClients":allowed_clients,"deniedKids":[],"maxTokenLifetimeSeconds":300,"leewayMilliseconds":30000,"jwksSource":{"kind":"static","documentRef":"secret:file/issuer-jwks"}},"authorityClaims":{"principal":"registry_principal","purpose":"registry_purpose"}},
            "audit":{"hashKeyRef":"secret:file/audit-key"},"cursor":{"secretRef":"secret:file/cursor-key"},"eventDestinations":destinations
        }),
    )
}

pub(super) fn external_event_destinations(
    compiled: &registry_breg::CompiledRegistry,
    bindings: &BTreeMap<String, LocalEventDestination>,
) -> Result<Value> {
    let inventory = compiled
        .event_deliveries()
        .deliveries
        .iter()
        .map(|delivery| delivery.destination_id.clone())
        .collect::<BTreeSet<_>>();
    if inventory != bindings.keys().cloned().collect() {
        bail!("local event destinations must bind every compiled destination ID exactly");
    }
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
    Ok(Value::Object(destinations.into_iter().map(|(id, (classification, timeout, attempts))| {
        let binding = &bindings[id];
        (id.clone(), json!({
            "origin":binding.origin,"path":binding.path,
            "networkProfile":"loopbackDevelopmentHttp","dnsFamily":"dualStackStrict",
            "allowedPrivateCidrs":[],"hmacSha256KeyRef":format!("secret:file/webhook-{id}"),
            "classificationCeiling":classification,
            "deliveryCeilings":{"attemptTimeoutMilliseconds":timeout,"maximumAttempts":attempts}
        }))
    }).collect()))
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

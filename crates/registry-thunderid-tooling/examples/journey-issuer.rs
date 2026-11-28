// SPDX-License-Identifier: Apache-2.0
//! Stock ThunderID fixture for native service journeys. Credentials remain in the
//! private fixture directory and only the requested paths are printed.

#[cfg(not(feature = "session"))]
fn main() {
    eprintln!("Build journey-issuer with the session feature.");
    std::process::exit(2);
}

#[cfg(feature = "session")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    fixture::run()
}

#[cfg(feature = "session")]
#[path = "journey-fixture/grant.rs"]
mod grant;

#[cfg(feature = "session")]
mod fixture {
    use std::{
        collections::BTreeMap,
        fs::{self, DirBuilder, OpenOptions},
        io::Write,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
        path::Path,
    };

    use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm, PrivateJwk};
    use registry_platform_httputil::{PrivateKeyJwt, PrivateKeyJwtConfig, TokenProvider};
    use registry_thunderid_tooling::{
        container::Session,
        description::{ExchangeIssuer, ExchangeMapping, SessionIdentity, TokenExchangeClient},
        local, render,
        version::ThunderIdPin,
    };
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use zeroize::Zeroizing;

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    #[derive(Deserialize)]
    struct Registration {
        clients: Vec<Client>,
        #[serde(default)]
        issuer: Composition,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Client {
        id: String,
        scopes: Vec<String>,
        #[serde(default)]
        claims: BTreeMap<String, Value>,
        #[serde(default)]
        allow_human_fixture: bool,
        #[serde(default)]
        grants: Vec<Resource>,
    }

    #[derive(Default, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Composition {
        #[serde(default)]
        resources: Vec<Resource>,
        #[serde(default)]
        client_resources: BTreeMap<String, String>,
        #[serde(default)]
        exchange_clients: Vec<String>,
        #[serde(default)]
        exchange_issuers: Vec<Connection>,
    }

    #[derive(Deserialize)]
    struct Resource {
        audience: String,
        scopes: Vec<String>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Connection {
        id: String,
        issuer: String,
        jwks_endpoint: String,
        mapping: String,
    }

    #[derive(Deserialize, Serialize)]
    struct State {
        id: String,
        port: u16,
        resource: String,
    }

    fn write(path: &Path, data: &[u8]) -> Result<()> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?
            .write_all(data)?;
        Ok(())
    }

    fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }

    fn session<'a>(
        root: &'a Path,
        state: &'a State,
        label: &'a str,
        pin: &'a ThunderIdPin,
    ) -> Session<'a> {
        Session {
            label,
            id: &state.id,
            port: state.port,
            state_root: root,
            image: &pin.image,
        }
    }

    fn start(root: &Path, state: &State, registration: &Registration) -> Result<()> {
        let mut directory = DirBuilder::new();
        directory.mode(0o700);
        directory.create(root)?;
        directory.create(root.join("keys"))?;
        let mut clients = Vec::new();
        for client in &registration.clients {
            registry_platform_yaml::LocalId::new(client.id.as_str())?;
            let key = generate_private_jwk(GeneratedKeyAlgorithm::Es256)?;
            let public = serde_json::to_value(key.public())?;
            let mut private = Zeroizing::new(serde_json::to_string(&public)?);
            private.pop();
            private.push_str(&format!(
                ",\"d\":\"{}\"}}",
                key.d.as_deref().ok_or("EC key has no private member")?
            ));
            write(&root.join("keys").join(&client.id), private.as_bytes())?;
            let mut claims = client.claims.clone();
            claims
                .entry("registry_actor_kind".to_owned())
                .or_insert(json!("service"));
            clients.push(local::TypedLocalClient {
                client_id: client.id.clone(),
                public_jwks: json!({"keys": [public]}).to_string(),
                claims,
                scopes: client.scopes.clone(),
                allow_human_fixture: client.allow_human_fixture,
            });
        }
        let label = format!("journey-issuer-{}", state.id);
        let mut description = local::typed_local_description(
            SessionIdentity {
                label: label.clone(),
                id: state.id.clone(),
            },
            state.port,
            root.to_owned(),
            state.resource.clone(),
            clients,
        )?;
        for resource in &registration.issuer.resources {
            local::declare_resource(&mut description, &resource.audience, &resource.scopes)?;
        }
        for client in &registration.clients {
            let agent = local::agent_id(&state.id, &client.id);
            let role = description
                .roles
                .iter_mut()
                .find(|role| role.assigned_agents.contains(&agent))
                .ok_or("missing fixture role")?;
            if let Some(audience) = registration.issuer.client_resources.get(&client.id) {
                let resource = description
                    .resource_servers
                    .iter()
                    .find(|server| &server.identifier == audience)
                    .ok_or("missing fixture resource")?;
                role.permissions[0].0 = resource.id.clone();
            }
            let mut ordinary = Vec::new();
            for grant in &client.grants {
                let resource = description
                    .resource_servers
                    .iter()
                    .find(|server| server.identifier == grant.audience)
                    .ok_or("missing fixture grant resource")?;
                ordinary.push((resource.id.clone(), grant.scopes.clone()));
            }
            if registration.issuer.exchange_clients.contains(&client.id) {
                let machine = description
                    .machine_clients
                    .iter_mut()
                    .find(|machine| machine.client_id == client.id)
                    .ok_or("missing fixture exchange client")?;
                machine.token_exchange = Some(TokenExchangeClient {
                    assertion_resource_server_id: role.permissions[0].0.clone(),
                    assertion_scope: client
                        .scopes
                        .first()
                        .ok_or("missing fixture assertion scope")?
                        .clone(),
                    ordinary_resource_permissions: ordinary.clone(),
                });
            }
            role.permissions.extend(ordinary);
        }
        for entry in &registration.issuer.exchange_issuers {
            description.exchange_issuers.push(ExchangeIssuer {
                id: local::agent_id(&state.id, &format!("connection-{}", entry.id)),
                name: format!("Journey {}", entry.id),
                issuer: entry.issuer.clone(),
                jwks_endpoint: entry.jwks_endpoint.clone(),
                mapping: match entry.mapping.as_str() {
                    "institutional-grant" => ExchangeMapping::InstitutionalGrant,
                    _ => {
                        return Err("journey fixture only uses institutional-grant exchange".into())
                    }
                },
                clients: Vec::new(),
                token_attributes: BTreeMap::new(),
            });
        }
        render::render(&description)?;
        write(&root.join("fixture.json"), &serde_json::to_vec(state)?)?;
        let pin = ThunderIdPin::load()?;
        local::start(
            &session(root, state, &label, &pin),
            Path::new("docker"),
            &mut || false,
        )?;
        Ok(())
    }

    fn token(
        root: &Path,
        state: &State,
        client: &Client,
        resource: &str,
        output: &Path,
    ) -> Result<()> {
        let issuer = format!("http://127.0.0.1:{}", state.port);
        let secret = Zeroizing::new(fs::read_to_string(root.join("keys").join(&client.id))?);
        let key = PrivateJwk::parse(&secret)?;
        let mut config = PrivateKeyJwtConfig::new(
            format!("{issuer}/oauth2/token").parse()?,
            client.id.clone(),
            key,
        )
        .with_audience(issuer)
        .with_resource(resource.to_owned());
        if !client.scopes.is_empty() {
            config = config.with_scopes(client.scopes.clone());
        }
        let provider = PrivateKeyJwt::new(config)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mut header = Zeroizing::new(b"Authorization: ".to_vec());
        let credential = runtime.block_on(provider.bearer_token())?;
        header.extend_from_slice(credential.authorization_header_value().as_bytes());
        header.push(b'\n');
        write(output, &header)?;
        Ok(())
    }

    pub fn run() -> Result<()> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        match args.as_slice() {
            [command, root, file, id, port, resource] if command == "start" => {
                let registration = read(Path::new(file))?;
                start(Path::new(root), &State { id: id.clone(), port: port.parse()?, resource: resource.clone() }, &registration)
            }
            [command, root] if command == "stop" => {
                let root = Path::new(root);
                let state: State = read(&root.join("fixture.json"))?;
                let label = format!("journey-issuer-{}", state.id);
                let pin = ThunderIdPin::load()?;
                local::stop(&session(root, &state, &label, &pin), Path::new("docker"))?;
                Ok(())
            }
            [command, root, file, id, output, resource @ ..] if command == "token" && resource.len() <= 1 => {
                let root = Path::new(root);
                let state: State = read(&root.join("fixture.json"))?;
                let registration: Registration = read(Path::new(file))?;
                let client = registration.clients.iter().find(|client| &client.id == id).ok_or("unknown fixture client")?;
                let default_audience = registration.issuer.client_resources.get(id).unwrap_or(&state.resource);
                let audience = resource.first().unwrap_or(default_audience);
                token(root, &state, client, audience, Path::new(output))
            }
            [command, root, file, client, grant] if command == "grant" => {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                let root = Path::new(root);
                let state: State = read(&root.join("fixture.json"))?;
                let issuer = format!("http://127.0.0.1:{}", state.port);
                let header = runtime.block_on(super::grant::acquire_header(Path::new(file), root, client, grant, &issuer))?;
                println!("{}", header.display());
                Ok(())
            }
            _ => Err("usage: journey-issuer start ROOT CLIENTS ID PORT RESOURCE | stop ROOT | token ROOT CLIENTS CLIENT FILE | grant ROOT CONNECTION CLIENT GRANT".into()),
        }
    }
}

// SPDX-License-Identifier: Apache-2.0

//! A development session's generated material: its secrets, the database
//! certificate authority and server certificate, the local token signing
//! key and the key set the runtime verifies with, and the runtime
//! configuration that connects the package's providers to the local relay
//! and the mock gateway.

use std::path::Path;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use registry_messaging::http_provider::ReceiptCapability;
use registry_messaging::package::LoadedPackage;
use registry_messaging_core::{
    ProviderKind, MESSAGING_RUNTIME_API_VERSION, MESSAGING_RUNTIME_KIND,
};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::gateway::SIGNATURE_HEADER;
use super::{failed, private, refused, DevResult, DATABASE_NAME, MIGRATION_ROLE, RUNTIME_ROLE};

/// The issuer and audience the session's tokens carry.
pub(super) const ISSUER: &str = "https://issuer.messagingctl-dev.invalid";
pub(super) const AUDIENCE: &str = "urn:registrystack:messaging-dev";
/// The key id of the session's signing key.
const KEY_ID: &str = "messagingctl-dev";
/// How long a development token stays valid.
const TOKEN_SECONDS: i64 = 3600;
/// The claim the runtime reads an actor kind from.
const ACTOR_KIND_CLAIM: &str = "registry_actor_kind";
/// The claim the runtime reads scopes from when the configuration names
/// none.
const SCOPE_CLAIM: &str = "registry_scopes";

fn random_hex(bytes: usize) -> DevResult<Zeroizing<String>> {
    let mut buffer = Zeroizing::new(vec![0_u8; bytes]);
    aws_lc_rs::rand::fill(&mut buffer)
        .map_err(|_| failed("the system random source failed".to_owned()))?;
    Ok(Zeroizing::new(hex::encode(buffer.as_slice())))
}

fn write(path: &Path, bytes: &[u8]) -> DevResult<()> {
    private::create(path, bytes).map_err(|error| {
        failed(format!(
            "the session file {} could not be written: {error}",
            path.display()
        ))
    })
}

fn pem(label: &str, bytes: &[u8]) -> String {
    let encoded = STANDARD.encode(bytes);
    let mut rendered = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        rendered.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        rendered.push('\n');
    }
    rendered.push_str(&format!("-----END {label}-----\n"));
    rendered
}

/// The passwords `docker::postgres` provisions the two roles with.
pub(super) struct DatabasePasswords {
    pub migration: Zeroizing<String>,
    pub runtime: Zeroizing<String>,
}

/// Write every generated secret and certificate under `root`, a fresh
/// private session directory whose `secrets/`, `database/`, and `issuer/`
/// directories exist.
pub(super) fn generate(root: &Path) -> DevResult<DatabasePasswords> {
    let secrets = root.join("secrets");
    write(
        &secrets.join("messaging-audit-key"),
        random_hex(32)?.as_bytes(),
    )?;
    write(&secrets.join("gateway-token"), random_hex(32)?.as_bytes())?;
    write(
        &secrets.join("gateway-callback-key"),
        random_hex(32)?.as_bytes(),
    )?;
    let superuser = random_hex(24)?;
    write(
        &root.join("database/postgres.env"),
        Zeroizing::new(format!("POSTGRES_PASSWORD={}\n", superuser.as_str())).as_bytes(),
    )?;
    let passwords = DatabasePasswords {
        migration: random_hex(24)?,
        runtime: random_hex(24)?,
    };

    let refused_certificate =
        |error: rcgen::Error| failed(format!("the database certificate failed: {error}"));
    let mut authority =
        rcgen::CertificateParams::new(Vec::<String>::new()).map_err(refused_certificate)?;
    authority.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let authority_key = rcgen::KeyPair::generate().map_err(refused_certificate)?;
    let authority = authority
        .self_signed(&authority_key)
        .map_err(refused_certificate)?;
    let server_key = rcgen::KeyPair::generate().map_err(refused_certificate)?;
    let server =
        rcgen::CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .map_err(refused_certificate)?
            .signed_by(&server_key, &authority, &authority_key)
            .map_err(refused_certificate)?;
    write(
        &secrets.join("postgres-ca.pem"),
        pem("CERTIFICATE", authority.der()).as_bytes(),
    )?;
    write(
        &root.join("database/server.pem"),
        pem("CERTIFICATE", server.der()).as_bytes(),
    )?;
    write(
        &root.join("database/server.key"),
        Zeroizing::new(pem("PRIVATE KEY", &server_key.serialize_der())).as_bytes(),
    )?;
    write(
        &root.join("database/pg_hba.conf"),
        b"local all all trust\n\
          hostnossl all all 0.0.0.0/0 reject\n\
          hostnossl all all ::/0 reject\n\
          hostssl all all 0.0.0.0/0 scram-sha-256\n\
          hostssl all all ::/0 scram-sha-256\n",
    )?;

    let random = SystemRandom::new();
    let signing = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
        .map_err(|_| failed("the token signing key could not be generated".to_owned()))?;
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, signing.as_ref())
        .map_err(|_| failed("the token signing key could not be read".to_owned()))?;
    write(&root.join("issuer/signing-key.der"), signing.as_ref())?;
    write(
        &secrets.join("jwks.json"),
        jwks(pair.public_key().as_ref())?.to_string().as_bytes(),
    )?;
    Ok(passwords)
}

/// The public key set for an uncompressed P-256 point.
fn jwks(point: &[u8]) -> DevResult<Value> {
    if point.len() != 65 || point[0] != 4 {
        return Err(failed(
            "the token signing key is not a P-256 point".to_owned(),
        ));
    }
    Ok(json!({"keys": [{
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kid": KEY_ID,
        "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
        "y": URL_SAFE_NO_PAD.encode(&point[33..]),
    }]}))
}

/// Write the two database URLs once the database's port is known.
pub(super) fn database_urls(
    root: &Path,
    port: u16,
    passwords: &DatabasePasswords,
) -> DevResult<()> {
    for (name, role, password) in [
        ("runtime-database-url", RUNTIME_ROLE, &passwords.runtime),
        (
            "migration-database-url",
            MIGRATION_ROLE,
            &passwords.migration,
        ),
    ] {
        let url = Zeroizing::new(format!(
            "postgresql://{role}:{}@127.0.0.1:{port}/{DATABASE_NAME}",
            password.as_str()
        ));
        write(&root.join("secrets").join(name), url.as_bytes())?;
    }
    Ok(())
}

/// Where the session's local services listen.
pub(super) struct Endpoints {
    pub api_port: u16,
    pub metrics_port: u16,
    pub smtp_port: u16,
    pub gateway_port: u16,
}

/// The runtime configuration: a development listener on loopback, the
/// session's database, key set, and audit key, every `smtp` provider on the
/// local relay, and every `http` provider on the mock gateway.
pub(super) fn runtime_config(
    project: &Path,
    root: &Path,
    loaded: &LoadedPackage,
    endpoints: &Endpoints,
) -> Value {
    let mut allowed_clients: Vec<String> = loaded
        .package
        .access_profiles()
        .iter()
        .flat_map(|profile| profile.requester_clients.iter().cloned())
        .collect();
    allowed_clients.sort();
    allowed_clients.dedup();
    let providers: serde_json::Map<String, Value> = loaded
        .package
        .providers()
        .map(|provider| {
            let connection = match provider.kind {
                ProviderKind::Smtp => json!({
                    "kind": "smtp",
                    "host": "127.0.0.1",
                    "port": endpoints.smtp_port,
                    "tls": "development-loopback",
                }),
                ProviderKind::Http => {
                    let capabilities = loaded
                        .providers
                        .get(&provider.id)
                        .map(|source| &source.package.capabilities);
                    let mut connection = json!({
                        "kind": "http",
                        "baseUrl": format!(
                            "http://127.0.0.1:{}/{}/v1/",
                            endpoints.gateway_port, provider.id
                        ),
                        "timeoutMilliseconds": 10000,
                        "maximumResponseBytes": 16384,
                        "concurrencyLimit": capabilities.map_or(1, |capabilities| capabilities.concurrency_limit),
                        "redirects": "deny",
                        "authentication": {
                            "kind": "static-authorization",
                            "tokenRef": "secret:file/gateway-token",
                        },
                    });
                    if capabilities
                        .is_some_and(|capabilities| capabilities.receipts == ReceiptCapability::Callback)
                    {
                        connection["callbackVerifier"] = json!({
                            "kind": "hmac-sha256-body",
                            "header": SIGNATURE_HEADER,
                            "encoding": "hex",
                            "secretRef": "secret:file/gateway-callback-key",
                        });
                    }
                    connection
                }
            };
            (provider.id.clone(), connection)
        })
        .collect();
    json!({
        "apiVersion": MESSAGING_RUNTIME_API_VERSION,
        "kind": MESSAGING_RUNTIME_KIND,
        "package": {"root": project},
        "listener": {
            "bind": format!("127.0.0.1:{}", endpoints.api_port),
            "tlsTermination": "development-loopback",
            "networkExposure": "private-address",
        },
        "metricsListener": {"bind": format!("127.0.0.1:{}", endpoints.metrics_port)},
        "secretProviders": {"file": {"root": root.join("secrets")}},
        "database": {
            "runtimeUrlRef": "secret:file/runtime-database-url",
            "migrationUrlRef": "secret:file/migration-database-url",
            "trustedRootCertificateRef": "secret:file/postgres-ca.pem",
        },
        "authentication": {"oidc": {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "allowedClients": allowed_clients,
            // The session's signing key is generated beside this file, so
            // the runtime reads its key set directly.
            "jwksSource": {"kind": "static", "documentRef": "secret:file/jwks.json"},
        }},
        "audit": {
            "path": root.join("audit/messaging.ndjson"),
            "hashKeyRef": "secret:file/messaging-audit-key",
        },
        "providers": providers,
    })
}

/// Whether `client` is safe as a file name.
fn file_safe(client: &str) -> bool {
    !client.is_empty()
        && client.len() <= 128
        && !client.starts_with('.')
        && client
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Sign a one-hour access token for `client`, carrying the scopes, and the
/// actor kind if any, of the access profile that names it.
pub(super) fn token(
    root: &Path,
    loaded: &LoadedPackage,
    client: &str,
) -> DevResult<Zeroizing<String>> {
    let profiles = loaded.package.access_profiles();
    let Some(profile) = profiles.iter().find(|profile| {
        profile
            .requester_clients
            .iter()
            .any(|named| named == client)
    }) else {
        let mut clients: Vec<&str> = profiles
            .iter()
            .flat_map(|profile| profile.requester_clients.iter().map(String::as_str))
            .collect();
        clients.sort_unstable();
        return Err(refused(format!(
            "no access profile names the client `{client}`; the package's clients are: {}",
            clients.join(", ")
        )));
    };
    if !file_safe(client) {
        return Err(refused(format!(
            "the client `{client}` cannot name a header file; use letters, digits, `-`, `_`, or `.`"
        )));
    }
    let key = Zeroizing::new(
        private::read(&root.join("issuer/signing-key.der"), 4096).map_err(|error| {
            refused(format!(
                "no development session key is available ({error}); start one with messagingctl dev"
            ))
        })?,
    );
    let now = chrono::Utc::now().timestamp();
    let principal = format!("dev-{client}");
    let mut claims = json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": principal,
        "azp": client,
        "iat": now,
        "nbf": now,
        "exp": now + TOKEN_SECONDS,
        "jti": uuid::Uuid::new_v4().to_string(),
        SCOPE_CLAIM: profile.required_scopes.join(" "),
    });
    claims[profile.principal_claim.as_str()] = json!(principal);
    if let Some(kind) = profile.actor_kind {
        claims[ACTOR_KIND_CLAIM] = json!(kind.as_str());
    }
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(KEY_ID.to_owned());
    header.typ = Some("at+jwt".to_owned());
    let signed = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_ec_der(&key),
    )
    .map_err(|error| failed(format!("the token could not be signed: {error}")))?;
    Ok(Zeroizing::new(signed))
}

/// Write `Authorization: Bearer <token>` for `client` and return the file.
pub(super) fn header_file(root: &Path, client: &str, token: &str) -> DevResult<std::path::PathBuf> {
    let tokens = root.join("tokens");
    private::directory(&tokens)
        .map_err(|error| failed(format!("the token directory is unusable: {error}")))?;
    let path = tokens.join(format!("{client}.header"));
    let header = Zeroizing::new(format!("Authorization: Bearer {token}\n"));
    private::replace(&path, header.as_bytes())
        .map_err(|error| failed(format!("the header file could not be written: {error}")))?;
    Ok(path)
}

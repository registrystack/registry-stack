// SPDX-License-Identifier: Apache-2.0

//! Short-lived first-party assertions for multi-purpose dev journeys.
//!
//! ThunderID machine attributes are static. A schema-test step that selects a
//! different declared purpose therefore uses the issuer's native first-party
//! token exchange while keeping the authored machine client's verified
//! `client_id` identity. The assertion signer and its JWKS listener exist only
//! while the rehearsal tokens are acquired.

use std::{collections::BTreeMap, path::Path};

use anyhow::{bail, Context as _, Result};
use axum::{routing::get, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::{PrivateKeyJwt, PrivateKeyJwtConfig};
use registry_thunderid_tooling::description::{
    ExchangeAttributeKind, ExchangeIssuer, ExchangeMapping,
};
use serde_json::{json, Value};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{config, private};

pub(super) const KEY_DIR: &str = "purpose-authority";
const CONNECTION_LABEL: &str = "purpose-assertion-authority";
const MAX_ASSERTION_SECONDS: i64 = 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PurposeClient {
    pub client_id: String,
    pub subject: String,
    pub claims: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PurposeTokenRequest {
    pub client_id: String,
    pub subject: String,
    pub scopes: Vec<String>,
    pub purpose: String,
    pub claims: BTreeMap<String, Value>,
    pub output_id: String,
}

/// Create the retained signing key before the issuer description is rendered.
pub(super) fn prepare(root: &Path) -> Result<()> {
    let directory = root.join(KEY_DIR);
    let private_path = directory.join("assertion-key.jwk");
    let public_path = directory.join("public.jwk");
    match (private_path.try_exists()?, public_path.try_exists()?) {
        (false, false) => {
            config::keypair(&directory)?;
        }
        (true, true) => {
            private::check(&directory, true)?;
            let private_bytes = Zeroizing::new(private::read(&private_path, 4096)?);
            let private_text = std::str::from_utf8(&private_bytes)
                .context("the purpose assertion key is unreadable")?;
            let key = PrivateJwk::parse(private_text)
                .map_err(|_| anyhow::anyhow!("the purpose assertion key is unusable"))?;
            let expected = serde_json::to_value(key.public())?;
            let actual: Value = serde_json::from_slice(&private::read(&public_path, 4096)?)?;
            if actual != expected {
                bail!("the purpose assertion key halves disagree");
            }
        }
        _ => bail!("the purpose assertion key pair is incomplete"),
    }
    Ok(())
}

/// Describe the one native connection that may project a declared purpose.
pub(super) fn exchange_issuer(
    session_id: &str,
    port: u16,
    clients: &[PurposeClient],
) -> Result<ExchangeIssuer> {
    if port == 0 || clients.is_empty() {
        bail!("the purpose exchange connection needs a port and at least one client");
    }
    if clients.iter().any(|client| {
        client.subject != registry_thunderid_tooling::local::agent_id(session_id, &client.client_id)
    }) {
        bail!("a purpose client subject does not match its predeclared machine agent");
    }
    let token_attributes = projected_claim_types(clients)?;
    Ok(ExchangeIssuer {
        id: registry_thunderid_tooling::local::agent_id(session_id, CONNECTION_LABEL),
        name: "Local purpose assertion authority".into(),
        issuer: format!("http://127.0.0.1:{port}"),
        jwks_endpoint: format!("http://host.docker.internal:{port}/jwks.json"),
        mapping: ExchangeMapping::FirstParty,
        clients: clients
            .iter()
            .map(|client| client.client_id.clone())
            .collect(),
        token_attributes,
    })
}

/// Claim names the generated connection projects beyond the authored ones.
pub(super) const GENERATED_CLAIMS: [&str; 2] = ["registry_purpose", "scope"];

fn projected_claim_types(
    clients: &[PurposeClient],
) -> Result<BTreeMap<String, ExchangeAttributeKind>> {
    let mut projected = BTreeMap::new();
    for client in clients {
        for (name, value) in &client.claims {
            if reserved_claim(name) {
                bail!("a purpose client claim is reserved for verified token context");
            }
            let kind = if name == "registry_purpose" {
                if value.is_string()
                    || value.as_array().is_some_and(|values| {
                        !values.is_empty() && values.iter().all(Value::is_string)
                    })
                {
                    ExchangeAttributeKind::String
                } else {
                    bail!("the authored purpose list is invalid");
                }
            } else if value.is_string() {
                ExchangeAttributeKind::String
            } else if value
                .as_array()
                .is_some_and(|values| !values.is_empty() && values.iter().all(Value::is_string))
            {
                ExchangeAttributeKind::StringArray
            } else {
                bail!("purpose client claims must be bounded strings or string arrays");
            };
            if projected
                .insert(name.clone(), kind)
                .is_some_and(|prior| prior != kind)
            {
                bail!("purpose client claims need one consistent type");
            }
        }
    }
    projected.insert("registry_purpose".into(), ExchangeAttributeKind::String);
    // Thunder's first-party exchange does not copy the RFC 8693 assertion
    // scope into the access token unless the verified connection projects it.
    // The authored client cannot supply this member: `reserved_claim` keeps
    // the signer-generated, request-bound value as its only source.
    projected.insert("scope".into(), ExchangeAttributeKind::String);
    Ok(projected)
}

fn reserved_claim(name: &str) -> bool {
    matches!(
        name,
        "iss"
            | "sub"
            | "aud"
            | "iat"
            | "nbf"
            | "exp"
            | "jti"
            | "scope"
            | "client_id"
            | "azp"
            | "registry_assertion_issuer"
            | "identity"
            | "registry_approver"
    ) || name.starts_with("registry_grant_")
}

/// The address the transient JWKS listener binds.
///
/// ThunderID runs in a bridge-networked container and fetches the JWKS from
/// `host.docker.internal`. Docker Desktop and OrbStack on macOS forward that
/// name to the host's loopback interface, so loopback is enough there. Linux
/// Engine maps the name to the bridge gateway (`--add-host
/// host.docker.internal:host-gateway`), which a loopback-only listener never
/// sees, so Linux binds every interface. The listener serves one public key,
/// lives only while the rehearsal tokens are acquired, and carries no
/// protected endpoint.
fn jwks_bind_address() -> std::net::IpAddr {
    if cfg!(target_os = "linux") {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    }
}

/// Acquire all alternate-purpose credentials while one bounded JWKS listener
/// is live. Every exchange authenticates as the original authored client.
pub(super) async fn exchange_tokens(
    root: &Path,
    authority_root: &Path,
    thunder_issuer: &str,
    resource: &str,
    port: u16,
    requests: &[PurposeTokenRequest],
) -> Result<()> {
    if requests.is_empty() {
        return Ok(());
    }
    let authority = format!("http://127.0.0.1:{port}");
    let key_bytes = Zeroizing::new(private::read(
        &authority_root.join(KEY_DIR).join("assertion-key.jwk"),
        4096,
    )?);
    let key_text =
        std::str::from_utf8(&key_bytes).context("the purpose assertion key is unreadable")?;
    let authority_key = PrivateJwk::parse(key_text)
        .map_err(|_| anyhow::anyhow!("the purpose assertion key is unusable"))?;
    let public: Value = serde_json::from_slice(&private::read(
        &authority_root.join(KEY_DIR).join("public.jwk"),
        4096,
    )?)?;
    let jwks = json!({"keys": [public]});
    let app = Router::new().route(
        "/jwks.json",
        get(move || {
            let jwks = jwks.clone();
            async move { Json(jwks) }
        }),
    );
    let listener = tokio::net::TcpListener::bind((jwks_bind_address(), port))
        .await
        .context("the retained purpose assertion port is unavailable")?;
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .map_err(|_| anyhow::anyhow!("the purpose JWKS listener failed"))
    });
    tokio::task::yield_now().await;

    let result = exchange_all(
        root,
        thunder_issuer,
        resource,
        &authority,
        &authority_key,
        requests,
    )
    .await;
    server.abort();
    let _ = server.await;
    result
}

async fn exchange_all(
    root: &Path,
    thunder_issuer: &str,
    resource: &str,
    authority: &str,
    authority_key: &PrivateJwk,
    requests: &[PurposeTokenRequest],
) -> Result<()> {
    let endpoint: url::Url = format!("{thunder_issuer}/oauth2/token")
        .parse()
        .context("the dev issuer token endpoint is invalid")?;
    for request in requests {
        let client_key_bytes = Zeroizing::new(private::read(
            &root
                .join("credentials")
                .join(&request.client_id)
                .join("assertion-key.jwk"),
            4096,
        )?);
        let client_key_text = std::str::from_utf8(&client_key_bytes)
            .context("the retained client key is unreadable")?;
        let client_key = PrivateJwk::parse(client_key_text)
            .map_err(|_| anyhow::anyhow!("the retained client key is unusable"))?;
        let provider = PrivateKeyJwt::new(
            PrivateKeyJwtConfig::new(endpoint.clone(), request.client_id.clone(), client_key)
                .with_audience(thunder_issuer.to_owned())
                .with_resource(resource.to_owned())
                .with_scopes(request.scopes.clone()),
        )
        .map_err(|error| anyhow::anyhow!("the purpose exchange client is unusable: {error}"))?;
        let assertion = assertion(
            authority_key,
            authority,
            thunder_issuer,
            &request.subject,
            &request.scopes,
            &request.purpose,
            &request.claims,
        )?;
        let token = provider.exchange(&assertion).await.map_err(|error| {
            anyhow::anyhow!("the dev issuer declined the purpose exchange: {error}")
        })?;
        let header = token.authorization_header_value();
        let text = header
            .to_str()
            .context("the issued purpose credential is not header-safe")?
            .strip_prefix("Bearer ")
            .unwrap_or_default();
        if text.len() > 65536 || text.split('.').count() != 3 {
            bail!("the dev issuer returned an invalid compact purpose token");
        }
        private::replace(
            &root
                .join("secrets")
                .join(format!("{}-token", request.output_id)),
            text.as_bytes(),
        )?;
    }
    Ok(())
}

fn assertion(
    key: &PrivateJwk,
    issuer: &str,
    audience: &str,
    subject: &str,
    scopes: &[String],
    purpose: &str,
    authored_claims: &BTreeMap<String, Value>,
) -> Result<Zeroizing<String>> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let algorithm = key
        .algorithm()
        .map_err(|_| anyhow::anyhow!("the purpose assertion key algorithm is unusable"))?;
    let key_id = key
        .kid
        .as_deref()
        .context("the purpose assertion key has no key id")?;
    let header = json!({
        "alg": algorithm.jwa_name(),
        "kid": key_id,
        "typ": "JWT",
    });
    let declared_purposes = match authored_claims.get("registry_purpose") {
        Some(Value::String(value)) => vec![value.as_str()],
        Some(Value::Array(values)) => values
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .context("the authored purpose list is invalid")?,
        _ => bail!("a purpose exchange requires an authored purpose list"),
    };
    if !declared_purposes.contains(&purpose) {
        bail!("the selected purpose was not authored for this client");
    }
    let mut claims = authored_claims.clone();
    for name in claims.keys() {
        if reserved_claim(name) {
            bail!("a purpose client claim is reserved for verified token context");
        }
    }
    claims.insert("iss".into(), json!(issuer));
    claims.insert("sub".into(), json!(subject));
    claims.insert("aud".into(), json!(audience));
    claims.insert("iat".into(), json!(now));
    claims.insert("nbf".into(), json!(now));
    claims.insert("exp".into(), json!(now + MAX_ASSERTION_SECONDS));
    claims.insert("jti".into(), json!(Uuid::new_v4().to_string()));
    claims.insert("scope".into(), json!(scopes.join(" ")));
    claims.insert("registry_purpose".into(), json!(purpose));
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?),
    );
    let signature = registry_platform_crypto::sign(input.as_bytes(), key)
        .map_err(|_| anyhow::anyhow!("the purpose assertion could not be signed"))?;
    Ok(Zeroizing::new(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_preserves_original_clients_and_projects_reviewed_claims() {
        let session_id = "11111111-1111-4111-8111-111111111111";
        let connection = exchange_issuer(
            session_id,
            18092,
            &[PurposeClient {
                client_id: "case-agent".into(),
                subject: registry_thunderid_tooling::local::agent_id(session_id, "case-agent"),
                claims: [
                    ("registry_actor_kind".into(), json!("human")),
                    ("registry_principal".into(), json!("person-canary")),
                    (
                        "registry_purpose".into(),
                        json!(["enrolment", "correction"]),
                    ),
                    ("jurisdiction".into(), json!(["north", "west"])),
                ]
                .into(),
            }],
        )
        .unwrap();
        assert_eq!(connection.mapping, ExchangeMapping::FirstParty);
        assert_eq!(connection.clients, ["case-agent"]);
        assert_eq!(connection.issuer, "http://127.0.0.1:18092");
        assert_eq!(
            connection.token_attributes,
            [
                ("jurisdiction".into(), ExchangeAttributeKind::StringArray),
                ("registry_actor_kind".into(), ExchangeAttributeKind::String),
                ("registry_principal".into(), ExchangeAttributeKind::String),
                ("registry_purpose".into(), ExchangeAttributeKind::String),
                ("scope".into(), ExchangeAttributeKind::String),
            ]
            .into()
        );
    }

    #[test]
    fn jwks_listener_is_reachable_through_the_container_host_gateway() {
        let address = jwks_bind_address();
        if cfg!(target_os = "linux") {
            // host.docker.internal is the bridge gateway, not loopback.
            assert!(address.is_unspecified());
        } else {
            // Docker Desktop and OrbStack forward the name to loopback.
            assert!(address.is_loopback());
        }
    }

    #[test]
    fn assertion_carries_only_bounded_exchange_context_and_selected_purpose() {
        let key = registry_platform_crypto::generate_private_jwk(
            registry_platform_crypto::GeneratedKeyAlgorithm::Es256,
        )
        .unwrap();
        let assertion = assertion(
            &key,
            "http://127.0.0.1:18092",
            "http://127.0.0.1:18091",
            "11111111-1111-4111-8111-111111111112",
            &["records:write".into()],
            "correction",
            &[
                ("registry_actor_kind".into(), json!("human")),
                ("registry_principal".into(), json!("person-canary")),
                (
                    "registry_purpose".into(),
                    json!(["enrolment", "correction"]),
                ),
                ("jurisdiction".into(), json!("north")),
            ]
            .into(),
        )
        .unwrap();
        let claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(assertion.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(claims["sub"], "11111111-1111-4111-8111-111111111112");
        assert_eq!(claims["scope"], "records:write");
        assert_eq!(claims["registry_purpose"], "correction");
        assert_eq!(claims["registry_actor_kind"], "human");
        assert_eq!(claims["registry_principal"], "person-canary");
        assert_eq!(claims["jurisdiction"], "north");
        assert!(claims.get("client_id").is_none());
        assert!(claims.get("azp").is_none());
    }
}

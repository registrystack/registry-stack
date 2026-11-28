// SPDX-License-Identifier: Apache-2.0
//! Private exchange implementation used by operator tooling and the journey example.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::{PrivateKeyJwt, PrivateKeyJwtConfig, TokenProvider};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{endpoint, refused, GrantConnection, GrantCredential, ToolingError};

const ASSERTION_SCOPE: &str = "casework:grants:assert";
const MAXIMUM_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AssertionResponse {
    assertion: String,
    expires_at: u64,
    grant_expires_at: u64,
}

pub(super) async fn acquire(
    connection: &GrantConnection,
    client_id: &str,
    key: PrivateJwk,
    grant_id: &str,
    peer_policy: registry_platform_httputil::PeerPolicy,
) -> Result<GrantCredential, ToolingError> {
    let provider = |resource: &str, scopes: Vec<String>| {
        PrivateKeyJwt::new(
            PrivateKeyJwtConfig::new(
                endpoint(&connection.token_endpoint)?,
                client_id,
                key.clone(),
            )
            .with_audience(connection.client_assertion_audience.clone())
            .with_resource(resource)
            .with_scopes(scopes),
        )
        .map_err(|_| refused("the retained client credential is unusable"))
    };
    let bootstrap = provider(&connection.bootstrap_resource, vec![ASSERTION_SCOPE.into()])?
        .bearer_token()
        .await
        .map_err(|_| refused("the configured issuer refused the bootstrap credential"))?;
    let mut url = endpoint(&connection.casework_url)?;
    url.path_segments_mut()
        .map_err(|_| refused("the configured Casework endpoint is invalid"))?
        .pop_if_empty()
        .extend(["v1", "task-grants", grant_id, "assertion"]);
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| refused("the assertion transport is unavailable"))?;
    let mut response = http
        .post(url)
        .header(
            reqwest::header::AUTHORIZATION,
            bootstrap.authorization_header_value(),
        )
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| refused("the configured Casework authority is unavailable"))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(refused(
            "Casework refused the grant; check its approval, client, expiry and revocation",
        ));
    }
    registry_platform_httputil::validate_response_headers(response.headers(), peer_policy)
        .map_err(|error| match error {
            registry_platform_httputil::ResponseHeaderError::DevelopmentPeer => {
                refused("the Casework peer declared development and this tooling refuses it")
            }
            _ => refused("the Casework assertion headers exceed their bounds"),
        })?;
    if response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_none_or(|value| !value.trim().eq_ignore_ascii_case("application/json"))
        || response
            .headers()
            .contains_key(reqwest::header::CONTENT_ENCODING)
        || response
            .content_length()
            .is_some_and(|length| length > MAXIMUM_RESPONSE_BYTES as u64)
    {
        return Err(refused(
            "the Casework assertion response media type, encoding or size is invalid",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| refused("the Casework assertion response was interrupted"))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAXIMUM_RESPONSE_BYTES {
            return Err(refused("the Casework assertion response exceeds its bound"));
        }
        bytes.extend_from_slice(&chunk);
    }
    let assertion: AssertionResponse = serde_json::from_slice(&bytes)
        .map_err(|_| refused("the Casework assertion response is invalid"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| refused("the local clock is invalid"))?
        .as_secs();
    if assertion.assertion.is_empty()
        || assertion.assertion.len() > 32 * 1024
        || assertion.expires_at <= now
        || assertion.expires_at > assertion.grant_expires_at
        || assertion.expires_at > now.saturating_add(60)
    {
        return Err(refused(
            "the Casework assertion has no current bounded lifetime",
        ));
    }
    let token = provider(&connection.resource, connection.scopes.clone())?
        .exchange(&assertion.assertion)
        .await
        .map_err(|_| refused("the configured issuer refused the approved grant exchange"))?;
    Ok(GrantCredential {
        token,
        grant_expires_at: assertion.grant_expires_at,
    })
}

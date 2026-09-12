//! Acquire an existing Casework-approved task through standard OAuth exchange.
//! This helper never approves a task, signs an authority assertion, or accepts
//! selectors. The owning CLI supplies its retained connection and credential.
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::{BearerToken, PrivateKeyJwt, PrivateKeyJwtConfig, TokenProvider};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::ToolingError;

const ASSERTION_SCOPE: &str = "casework:grants:assert";
const MAXIMUM_RESPONSE_BYTES: usize = 64 * 1024;

/// Explicit trusted connection, retained with the local session. Scopes and
/// resource are requested ceilings, never a source of grant authority.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantConnection {
    pub casework_url: String,
    pub token_endpoint: String,
    pub client_assertion_audience: String,
    pub bootstrap_resource: String,
    pub resource: String,
    pub scopes: Vec<String>,
}

fn refused(reason: &'static str) -> ToolingError {
    ToolingError::GrantAcquisition { reason }
}

fn endpoint(address: &str) -> Result<Url, ToolingError> {
    let url = Url::parse(address).map_err(|_| refused("the configured endpoint is invalid"))?;
    if address.len() > 2048
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https"
            || (url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))))
        || url.host_str().is_none()
    {
        return Err(refused(
            "configured endpoints require HTTPS or explicit loopback HTTP",
        ));
    }
    Ok(url)
}

impl GrantConnection {
    pub fn validate(&self) -> Result<(), ToolingError> {
        endpoint(&self.casework_url)?;
        endpoint(&self.token_endpoint)?;
        if !registry_platform_httputil::valid_resource_uri(&self.client_assertion_audience)
            || !registry_platform_httputil::valid_resource_uri(&self.bootstrap_resource)
            || !registry_platform_httputil::valid_resource_uri(&self.resource)
            || self.scopes.is_empty()
            || self.scopes.len() > 32
            || self.scopes.iter().collect::<BTreeSet<_>>().len() != self.scopes.len()
            || self.scopes.iter().any(|scope| {
                scope.len() > 128
                    || scope.contains('*')
                    || !registry_platform_httputil::valid_scope_token(scope)
            })
        {
            return Err(refused(
                "the retained resource, assertion audience or scope ceiling is invalid",
            ));
        }
        Ok(())
    }
}

/// Deliberately lacks Debug and Serialize. The CLI may persist only the final
/// bearer in its owner-only grant-specific header, never the intermediate token.
pub struct GrantCredential {
    pub token: BearerToken,
    pub grant_expires_at: u64,
}

#[derive(Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AssertionResponse {
    assertion: String,
    expires_at: u64,
    grant_expires_at: u64,
}

/// Fresh bootstrap -> real Casework assertion -> uncached RFC 8693 exchange.
/// The grant UUID is the sole task selection input. No human profile headers
/// are sent. Redirects, response bodies in errors and ambient proxying are off.
pub async fn acquire(
    connection: &GrantConnection,
    client_id: &str,
    key: PrivateJwk,
    grant_id: &str,
) -> Result<GrantCredential, ToolingError> {
    connection.validate()?;
    if !crate::description::valid_uuid(grant_id) {
        return Err(refused("an approved grant UUID is required"));
    }
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
    registry_platform_httputil::validate_response_headers(response.headers())
        .map_err(|_| refused("the Casework assertion headers exceed their bounds"))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    fn connection() -> GrantConnection {
        GrantConnection {
            casework_url: "http://127.0.0.1:8100".into(),
            token_endpoint: "http://127.0.0.1:8091/oauth2/token".into(),
            client_assertion_audience: "http://127.0.0.1:8091".into(),
            bootstrap_resource: "urn:casework:local".into(),
            resource: "urn:breg:local".into(),
            scopes: vec!["records:get".into()],
        }
    }
    #[test]
    fn connection_refuses_ambiguous_or_unprotected_endpoints_and_scopes() {
        assert!(connection().validate().is_ok());
        for address in [
            "http://example.test",
            "https://user@example.test",
            "https://example.test/?key=value",
            "https://example.test/#fragment",
        ] {
            let mut candidate = connection();
            candidate.casework_url = address.into();
            assert!(candidate.validate().is_err());
        }
        let mut candidate = connection();
        candidate.scopes.push(candidate.scopes[0].clone());
        assert!(candidate.validate().is_err());
    }
}

#[cfg(test)]
#[path = "grant_tests.rs"]
mod wire_tests;

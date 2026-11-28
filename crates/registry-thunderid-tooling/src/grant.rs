//! Acquire an existing Casework-approved task through standard OAuth exchange.
//! This helper never approves a task, signs an authority assertion, or accepts
//! selectors. The owning CLI supplies its retained connection and credential.
use std::collections::BTreeSet;

use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::BearerToken;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::ToolingError;

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
                && url
                    .host_str()
                    .is_some_and(|host| registry_platform_loopback::loopback_host(host).is_some())))
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

#[path = "grant_exchange.rs"]
mod exchange;

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
    exchange::acquire(
        connection,
        client_id,
        key,
        grant_id,
        registry_platform_httputil::PeerPolicy::RefuseDevelopmentPeer,
    )
    .await
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
    fn plain_http_endpoints_follow_the_shared_loopback_rule() {
        for (host, loopback) in [
            ("127.0.0.1", true),
            ("127.0.0.2", true),
            ("[::1]", true),
            ("[::ffff:127.0.0.1]", true),
            ("localhost", true),
            ("LOCALHOST", true),
            ("a.localhost", false),
            ("localhost.", false),
            ("10.0.0.1", false),
            ("example.com", false),
        ] {
            assert_eq!(
                endpoint(&format!("http://{host}:8100")).is_ok(),
                loopback,
                "{host}"
            );
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

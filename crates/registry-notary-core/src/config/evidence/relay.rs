// SPDX-License-Identifier: Apache-2.0
//! Sealed Registry Relay connection configuration.

use super::*;

pub const DEFAULT_RELAY_MAX_IN_FLIGHT: usize = 8;
pub const MAX_RELAY_MAX_IN_FLIGHT: usize = 16;
const MAX_RELAY_BASE_URL_BYTES: usize = 2_048;
const MAX_RELAY_TOKEN_ENV_BYTES: usize = 128;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConnectionConfig {
    pub base_url: String,
    pub token_env: String,
    #[serde(default = "default_relay_max_in_flight")]
    pub max_in_flight: usize,
    #[serde(default)]
    pub allow_insecure_localhost: bool,
}

impl std::fmt::Debug for RelayConnectionConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayConnectionConfig")
            .field("base_url", &"<redacted>")
            .field("token_env", &"<redacted>")
            .field("max_in_flight", &self.max_in_flight)
            .field("allow_insecure_localhost", &self.allow_insecure_localhost)
            .finish()
    }
}

impl RelayConnectionConfig {
    pub(in crate::config) fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.base_url.is_empty()
            || self.base_url.len() > MAX_RELAY_BASE_URL_BYTES
            || self.base_url.trim() != self.base_url
        {
            return invalid_relay("base_url must be a non-empty URL of bounded length");
        }
        let Some(origin) = parse_relay_origin(&self.base_url) else {
            return invalid_relay(
                "base_url must be an absolute HTTP(S) origin with path exactly / and no credentials, query, or fragment",
            );
        };
        match origin.scheme() {
            "https" => {}
            "http" if self.allow_insecure_localhost && is_loopback_origin(&origin) => {}
            "http" => {
                return invalid_relay(
                    "base_url must use https unless allow_insecure_localhost permits an HTTP loopback URL",
                );
            }
            _ => return invalid_relay("base_url must use the http or https scheme"),
        }
        if self.token_env.is_empty()
            || self.token_env.len() > MAX_RELAY_TOKEN_ENV_BYTES
            || !is_environment_reference(&self.token_env)
        {
            return invalid_relay(
                "token_env must be a non-empty environment variable name of bounded length",
            );
        }
        if !(1..=MAX_RELAY_MAX_IN_FLIGHT).contains(&self.max_in_flight) {
            return invalid_relay("max_in_flight must be between 1 and 16");
        }
        Ok(())
    }

    #[must_use]
    pub fn uses_insecure_url(&self) -> bool {
        self.base_url.starts_with("http://")
    }
}

pub(in crate::config) const fn default_relay_max_in_flight() -> usize {
    DEFAULT_RELAY_MAX_IN_FLIGHT
}

fn is_loopback_origin(origin: &url::Url) -> bool {
    match origin.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(_)) | None => false,
    }
}

fn parse_relay_origin(value: &str) -> Option<url::Url> {
    let (scheme, rest) = value.split_once("://")?;
    if !matches!(scheme, "http" | "https") || rest.is_empty() || rest.contains(['?', '#']) {
        return None;
    }
    // Check the raw shape before URL normalization so `/private/..` cannot
    // normalize into the accepted root origin.
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty() || authority.contains('/') {
        return None;
    }
    let origin = url::Url::parse(value).ok()?;
    (!origin.cannot_be_a_base()
        && origin.host().is_some()
        && origin.port() != Some(0)
        && origin.username().is_empty()
        && origin.password().is_none()
        && origin.path() == "/"
        && origin.query().is_none()
        && origin.fragment().is_none())
    .then_some(origin)
}

fn is_environment_reference(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn invalid_relay<T>(reason: &str) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidRelayConfig {
        reason: reason.to_string(),
    })
}

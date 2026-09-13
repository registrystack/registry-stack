//! Closed JSON handoff shared by Node and Python client bindings.

use std::{sync::Arc, time::Duration};

use registry_platform_crypto::PrivateJwk;
use serde::Deserialize;
use serde_json::{Map, Value};
use url::Url;

use super::{
    exchange_authorization::{
        ExchangeAuthorization, ExchangeContext, FirstPartyAssertionSource, RemoteAssertionSource,
    },
    outbound::OutboundOptions,
    private_key_jwt::{PrivateKeyJwt, PrivateKeyJwtConfig},
    token::TokenError,
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
};

const MAX_CONFIG_BYTES: usize = 128 * 1024;

fn malformed() -> TokenError {
    TokenError::Configuration {
        reason: "the exchange authorization configuration is malformed",
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyClient {
    #[serde(alias = "token_endpoint")]
    token_endpoint: String,
    #[serde(alias = "client_id")]
    client_id: String,
    #[serde(alias = "client_key")]
    client_key: Value,
    audience: Option<String>,
    resource: String,
    scopes: Vec<String>,
    #[serde(alias = "assertion_lifetime_seconds")]
    assertion_lifetime_seconds: Option<i64>,
    #[serde(alias = "refresh_margin_seconds")]
    refresh_margin_seconds: Option<i64>,
    #[serde(alias = "request_timeout_milliseconds")]
    request_timeout_milliseconds: Option<u64>,
    #[serde(alias = "request_timeout_seconds")]
    request_timeout_seconds: Option<f64>,
    #[serde(alias = "connect_timeout_milliseconds")]
    connect_timeout_milliseconds: Option<u64>,
    #[serde(alias = "connect_timeout_seconds")]
    connect_timeout_seconds: Option<f64>,
    #[serde(alias = "user_agent")]
    user_agent: Option<String>,
    #[serde(alias = "trusted_root_certificates")]
    trusted_root_certificates: Option<String>,
}

impl KeyClient {
    fn build(self) -> Result<PrivateKeyJwt, TokenError> {
        if self.request_timeout_milliseconds.is_some() && self.request_timeout_seconds.is_some()
            || self.connect_timeout_milliseconds.is_some() && self.connect_timeout_seconds.is_some()
        {
            return Err(malformed());
        }
        let endpoint = Url::parse(&self.token_endpoint).map_err(|_| malformed())?;
        let key = PrivateJwk::parse(&self.client_key.to_string()).map_err(|_| malformed())?;
        let mut config = PrivateKeyJwtConfig::new(endpoint, self.client_id, key)
            .with_resource(self.resource)
            .with_scopes(self.scopes);
        if let Some(value) = self.audience {
            config = config.with_audience(value);
        }
        if let Some(value) = self.assertion_lifetime_seconds {
            config = config.with_assertion_lifetime_seconds(value);
        }
        if let Some(value) = self.refresh_margin_seconds {
            config = config.with_refresh_margin_seconds(value);
        }
        if let Some(value) = self.request_timeout_milliseconds {
            config = config.with_request_timeout(Duration::from_millis(value));
        }
        if let Some(value) = self.request_timeout_seconds {
            config = config
                .with_request_timeout(Duration::try_from_secs_f64(value).map_err(|_| malformed())?);
        }
        if let Some(value) = self.connect_timeout_milliseconds {
            config = config.with_connect_timeout(Duration::from_millis(value));
        }
        if let Some(value) = self.connect_timeout_seconds {
            config = config
                .with_connect_timeout(Duration::try_from_secs_f64(value).map_err(|_| malformed())?);
        }
        if let Some(value) = self.user_agent {
            config = config.with_user_agent(value);
        }
        if let Some(value) = self.trusted_root_certificates {
            config = config.with_trusted_root_certificates(value.into_bytes());
        }
        PrivateKeyJwt::new(config)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Context {
    issuer: String,
    subject: String,
    audience: String,
    generation: String,
    #[serde(alias = "deadline_seconds")]
    deadline_seconds: i64,
    #[serde(alias = "grant_id")]
    grant_id: Option<String>,
}

impl Context {
    fn build(self) -> Result<ExchangeContext, TokenError> {
        if let Some(grant) = self.grant_id {
            ExchangeContext::grant(
                self.issuer,
                self.subject,
                self.audience,
                self.generation,
                self.deadline_seconds,
                grant,
            )
        } else {
            ExchangeContext::first_party(
                self.issuer,
                self.subject,
                self.audience,
                self.generation,
                self.deadline_seconds,
            )
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FirstParty {
    key: Value,
    attributes: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Remote {
    endpoint: String,
    bootstrap: KeyClient,
    #[serde(alias = "bootstrap_resource")]
    bootstrap_resource: String,
    #[serde(alias = "bootstrap_scope")]
    bootstrap_scope: String,
    #[serde(alias = "request_timeout_milliseconds")]
    request_timeout_milliseconds: Option<u64>,
    #[serde(alias = "request_timeout_seconds")]
    request_timeout_seconds: Option<f64>,
    #[serde(alias = "connect_timeout_milliseconds")]
    connect_timeout_milliseconds: Option<u64>,
    #[serde(alias = "connect_timeout_seconds")]
    connect_timeout_seconds: Option<f64>,
    #[serde(alias = "user_agent")]
    user_agent: Option<String>,
    #[serde(alias = "trusted_root_certificates")]
    trusted_root_certificates: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    client: KeyClient,
    context: Context,
    #[serde(alias = "first_party")]
    first_party: Option<FirstParty>,
    remote: Option<Remote>,
}

/// Build the same bounded provider from Node or Python configuration.
/// Each binding has already bounded its input graph before calling this parser.
/// This second size and closed-field check also protects direct Rust callers.
pub fn exchange_authorization_from_json(
    value: &Value,
) -> Result<ExchangeAuthorization, TokenError> {
    if serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > MAX_CONFIG_BYTES) {
        return Err(malformed());
    }
    let parsed: Config = serde_json::from_value(value.clone()).map_err(|_| malformed())?;
    let context = parsed.context.build()?;
    let client = parsed.client.build()?;
    match (parsed.first_party, parsed.remote) {
        (Some(first), None) => {
            let key = PrivateJwk::parse(&first.key.to_string()).map_err(|_| malformed())?;
            let scopes = client.configured_resource_and_scopes().1.to_vec();
            let source = FirstPartyAssertionSource::new(key, first.attributes, scopes)?;
            ExchangeAuthorization::first_party(client, context, source)
        }
        (None, Some(remote)) => {
            if remote.request_timeout_milliseconds.is_some()
                && remote.request_timeout_seconds.is_some()
                || remote.connect_timeout_milliseconds.is_some()
                    && remote.connect_timeout_seconds.is_some()
            {
                return Err(malformed());
            }
            let endpoint = Url::parse(&remote.endpoint).map_err(|_| malformed())?;
            let bootstrap = remote.bootstrap.build()?;
            let roots = remote
                .trusted_root_certificates
                .as_deref()
                .map(str::as_bytes);
            let request_timeout = if let Some(value) = remote.request_timeout_milliseconds {
                Duration::from_millis(value)
            } else if let Some(value) = remote.request_timeout_seconds {
                Duration::try_from_secs_f64(value).map_err(|_| malformed())?
            } else {
                DEFAULT_REQUEST_TIMEOUT
            };
            let connect_timeout = if let Some(value) = remote.connect_timeout_milliseconds {
                Duration::from_millis(value)
            } else if let Some(value) = remote.connect_timeout_seconds {
                Duration::try_from_secs_f64(value).map_err(|_| malformed())?
            } else {
                DEFAULT_CONNECT_TIMEOUT
            };
            let source = RemoteAssertionSource::new(
                endpoint,
                bootstrap,
                &remote.bootstrap_resource,
                &remote.bootstrap_scope,
                OutboundOptions {
                    request_timeout,
                    connect_timeout,
                    user_agent: remote.user_agent.as_deref(),
                    trusted_root_certificates: roots,
                },
            )?;
            ExchangeAuthorization::from_authority(client, context, Arc::new(source))
        }
        _ => Err(malformed()),
    }
}

// SPDX-License-Identifier: Apache-2.0

//! One maintained BReg client carrying the edge's opaque per-call authorization.

use std::{sync::Arc, time::Duration};

use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig};
use registry_mcp_edge::ProviderAuthorization;
use registry_platform_httputil::client::TokenError;
use url::Url;

#[derive(Clone)]
pub(crate) struct BRegClientFactory {
    base_url: Url,
    attempt_timeout: Duration,
}

impl BRegClientFactory {
    pub(crate) fn new(
        base_url: Url,
        attempt_timeout: Duration,
    ) -> Result<Self, ClientFactoryError> {
        if attempt_timeout.is_zero() {
            return Err(ClientFactoryError);
        }
        Ok(Self {
            base_url,
            attempt_timeout,
        })
    }

    pub(crate) fn client(
        &self,
        authorization: ProviderAuthorization,
    ) -> Result<BaseRegistryClient, TokenError> {
        BaseRegistryClient::new(
            authorized(
                BaseRegistryClientConfig::new(self.base_url.clone()),
                authorization,
            )
            .with_attempt_timeout(self.attempt_timeout)
            // The gateway owns same-key recovery. Client retries stacked under
            // a host retry would multiply an interactive turn and obscure an
            // uncertain mutation result.
            .with_maximum_mutation_retries(0),
        )
        .map_err(|_| TokenError::Configuration {
            reason: "the registry client could not be configured",
        })
    }
}

/// The only point where a credential reaches the maintained BReg client. The
/// value is constructed by the edge and exposes no bearer or text constructor.
#[allow(clippy::disallowed_methods)]
fn authorized(
    config: BaseRegistryClientConfig,
    authorization: ProviderAuthorization,
) -> BaseRegistryClientConfig {
    config.with_token_provider(Arc::new(authorization))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the BReg provider client configuration is invalid")]
pub(crate) struct ClientFactoryError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_attempt_timeout_is_refused() {
        assert!(BRegClientFactory::new(
            Url::parse("https://registry.example.test/").expect("URL"),
            Duration::ZERO,
        )
        .is_err());
    }
}

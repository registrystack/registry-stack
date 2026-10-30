// SPDX-License-Identifier: Apache-2.0

use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::client::{
    ExchangeAuthorization, ExchangeContext, PrivateKeyJwt, PrivateKeyJwtConfig, SubjectTokenType,
    TokenError, TokenProvider, UpstreamSubjectToken,
};
use url::Url;

use crate::VerifiedCaller;

/// Opaque downstream authorization. It exposes only the maintained token-provider contract.
#[derive(Clone)]
pub struct ProviderAuthorization(Arc<dyn TokenProvider>);

impl ProviderAuthorization {
    fn new(provider: Arc<dyn TokenProvider>) -> Self {
        Self(provider)
    }
}

impl fmt::Debug for ProviderAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAuthorization")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl TokenProvider for ProviderAuthorization {
    async fn bearer_token(
        &self,
    ) -> Result<registry_platform_httputil::client::BearerToken, TokenError> {
        self.0.bearer_token().await
    }
}

/// Creates the authorization for exactly one invocation of one provider binding.
pub trait AuthorizationFactory: Send + Sync {
    fn authorization(
        &self,
        caller: &VerifiedCaller,
    ) -> Result<ProviderAuthorization, AuthorizationError>;
}

/// Value-free failure to create a provider authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthorizationError {
    #[error("provider authorization is unavailable")]
    Unavailable,
    #[error("provider authorization is not configured correctly")]
    Configuration,
}

impl From<TokenError> for AuthorizationError {
    fn from(error: TokenError) -> Self {
        match error {
            TokenError::Configuration { .. } => Self::Configuration,
            _ => Self::Unavailable,
        }
    }
}

/// A non-personal provider binding whose configured token provider is independent of the caller.
pub struct FixedAuthorizationFactory {
    provider: Arc<dyn TokenProvider>,
}

impl FixedAuthorizationFactory {
    #[must_use]
    pub fn new(provider: Arc<dyn TokenProvider>) -> Self {
        Self { provider }
    }
}

impl fmt::Debug for FixedAuthorizationFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedAuthorizationFactory")
            .finish_non_exhaustive()
    }
}

impl AuthorizationFactory for FixedAuthorizationFactory {
    fn authorization(
        &self,
        _caller: &VerifiedCaller,
    ) -> Result<ProviderAuthorization, AuthorizationError> {
        Ok(ProviderAuthorization::new(Arc::clone(&self.provider)))
    }
}

/// Configuration for per-call RFC 8693 delegation.
pub struct DelegationOptions {
    pub token_endpoint: Url,
    pub client_id: String,
    pub private_key: PrivateJwk,
    pub assertion_audience: Option<String>,
    pub gateway_resource: String,
    pub downstream_resource: String,
    pub downstream_scopes: Vec<String>,
    pub attempt_timeout: Duration,
    pub generation: String,
}

/// Per-binding delegation from the verified inbound caller to one downstream resource.
pub struct Delegation {
    token_endpoint: Url,
    client_id: String,
    key: PrivateJwk,
    assertion_audience: Option<String>,
    gateway_resource: String,
    downstream_resource: String,
    downstream_scopes: Vec<String>,
    attempt_timeout: Duration,
    generation: String,
    actor: Arc<PrivateKeyJwt>,
}

impl Delegation {
    pub fn new(options: DelegationOptions) -> Result<Self, AuthorizationError> {
        if options.client_id.is_empty()
            || options.gateway_resource.is_empty()
            || options.downstream_resource.is_empty()
            || options.downstream_scopes.is_empty()
            || options.generation.is_empty()
            || options.attempt_timeout.is_zero()
        {
            return Err(AuthorizationError::Configuration);
        }
        let actor = PrivateKeyJwt::new(
            client_config(
                &options.token_endpoint,
                &options.client_id,
                options.assertion_audience.as_deref(),
                &options.private_key,
                options.attempt_timeout,
            )
            .with_resource(options.gateway_resource.clone()),
        )
        .map_err(AuthorizationError::from)?;
        let delegation = Self {
            token_endpoint: options.token_endpoint,
            client_id: options.client_id,
            key: options.private_key,
            assertion_audience: options.assertion_audience,
            gateway_resource: options.gateway_resource,
            downstream_resource: options.downstream_resource,
            downstream_scopes: options.downstream_scopes,
            attempt_timeout: options.attempt_timeout,
            generation: options.generation,
            actor: Arc::new(actor),
        };
        delegation.exchange_provider()?;
        Ok(delegation)
    }

    fn exchange_provider(&self) -> Result<PrivateKeyJwt, AuthorizationError> {
        PrivateKeyJwt::new(
            client_config(
                &self.token_endpoint,
                &self.client_id,
                self.assertion_audience.as_deref(),
                &self.key,
                self.attempt_timeout,
            )
            .with_resource(self.downstream_resource.clone())
            .with_scopes(self.downstream_scopes.iter().cloned()),
        )
        .map_err(AuthorizationError::from)
    }

    fn authorization_with_actor(
        &self,
        caller: &VerifiedCaller,
        actor: Arc<PrivateKeyJwt>,
    ) -> Result<ProviderAuthorization, AuthorizationError> {
        let context = ExchangeContext::first_party(
            caller.issuer(),
            caller.subject(),
            self.gateway_resource.clone(),
            self.generation.clone(),
            caller.expires_at(),
        )?;
        let subject = UpstreamSubjectToken::new(
            caller.token(),
            SubjectTokenType::AccessToken,
            caller.expires_at(),
        )?;
        let authorization = ExchangeAuthorization::upstream(
            self.exchange_provider()?,
            context,
            subject,
            Some(actor),
        )?;
        Ok(ProviderAuthorization::new(Arc::new(authorization)))
    }

    #[cfg(test)]
    pub(crate) fn actor_for_test(&self) -> Arc<PrivateKeyJwt> {
        Arc::clone(&self.actor)
    }

    #[cfg(test)]
    pub(crate) fn authorization_with_actor_for_test(
        &self,
        caller: &VerifiedCaller,
        actor: Arc<PrivateKeyJwt>,
    ) -> Result<ProviderAuthorization, AuthorizationError> {
        self.authorization_with_actor(caller, actor)
    }
}

impl fmt::Debug for Delegation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Delegation")
            .field("downstream_scopes", &self.downstream_scopes.len())
            .field("attempt_timeout", &self.attempt_timeout)
            .finish_non_exhaustive()
    }
}

impl AuthorizationFactory for Delegation {
    fn authorization(
        &self,
        caller: &VerifiedCaller,
    ) -> Result<ProviderAuthorization, AuthorizationError> {
        self.authorization_with_actor(caller, Arc::clone(&self.actor))
    }
}

fn client_config(
    token_endpoint: &Url,
    client_id: &str,
    assertion_audience: Option<&str>,
    key: &PrivateJwk,
    timeout: Duration,
) -> PrivateKeyJwtConfig {
    let config = PrivateKeyJwtConfig::new(token_endpoint.clone(), client_id, key.clone())
        .with_attempt_timeout(timeout);
    match assertion_audience {
        Some(audience) => config.with_audience(audience),
        None => config,
    }
}

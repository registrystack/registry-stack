// SPDX-License-Identifier: Apache-2.0

//! Base Registry Engine tools behind the product-neutral MCP edge.
//!
//! This module is the reusable product seam. It owns the exact BReg tool
//! catalog, contract-derived schemas, caller-owned target binding, revisions,
//! and idempotency behavior. Transport, inbound authentication, delegation,
//! and tool-call audit stay in `registry-mcp-edge`.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use registry_mcp_edge::{
    AuthorizationError, Delegation, DelegationOptions, EffectCertainty, Invocation, Provider,
    ProviderAuthorization, ProviderBinding, ProviderBindingError, ProviderFailure, ProviderOutcome,
    ResolvedTool, VerifiedCaller,
};
use registry_platform_audit::AuditKeyHasher;
use registry_platform_crypto::PrivateJwk;
use rmcp::model::Tool;
use url::Url;

use crate::{
    client::BRegClientFactory,
    config::{ExchangeConfig, RegistryConfig, ServiceConfig},
    gateway::{Gateway, ServiceDescription},
    handler::tool_definitions,
    problems::ToolError,
    tools::{START_APPLICATION, TOOL_NAMES, UPDATE_APPLICATION},
};

const PROVIDER_ID: &str = "breg";
const OPERATION_VERSION: &str = "v1";
const EXCHANGE_GENERATION: &str = "breg-mcp-v1";

/// The unchanged public BReg tool ceiling exposed through the shared edge.
pub const BREG_TOOL_NAMES: [&str; 7] = TOOL_NAMES;

/// Product-owned settings needed to construct a BReg provider internally.
#[derive(Clone, Debug)]
struct BRegProviderOptions {
    base_url: Url,
    attempt_timeout: Duration,
    access_profile: String,
    details_record_type: String,
    action: String,
    target_input: String,
    service_name: String,
    service_description: String,
    service_disclosure: String,
    review_base_url: Url,
}

impl BRegProviderOptions {
    #[must_use]
    fn from_product_config(registry: &RegistryConfig, service: &ServiceConfig) -> Self {
        Self {
            base_url: registry.base_url.to_url(),
            attempt_timeout: Duration::from_millis(registry.attempt_timeout_milliseconds.get()),
            access_profile: registry.access_profile.to_string(),
            details_record_type: service.details.record_type.to_string(),
            action: service.application.action.to_string(),
            target_input: service.application.target_input.to_string(),
            service_name: service.name.as_str().to_owned(),
            service_description: service.description.as_str().to_owned(),
            service_disclosure: service.disclosure.as_str().to_owned(),
            review_base_url: service.review_base_url.to_url(),
        }
    }
}

/// BReg provider with no MCP transport or inbound-token access.
pub(crate) struct BRegProvider {
    gateway: Gateway,
}

impl BRegProvider {
    fn new(options: BRegProviderOptions, keys: AuditKeyHasher) -> Result<Self, BRegBindingError> {
        let client = BRegClientFactory::new(options.base_url, options.attempt_timeout)
            .map_err(|_| BRegBindingError::Client)?;
        Ok(Self {
            gateway: Gateway::new(
                client,
                crate::contract::ContractSpec {
                    access_profile: options.access_profile,
                    details_record_type: options.details_record_type,
                    action: options.action,
                    target_input: options.target_input,
                },
                ServiceDescription {
                    name: options.service_name,
                    description: options.service_description,
                    disclosure: options.service_disclosure,
                },
                options.review_base_url,
                keys,
            ),
        })
    }

    #[cfg(test)]
    pub(crate) fn pause_dispatch(&self) -> Arc<crate::gateway::DispatchBarrier> {
        self.gateway.pause_dispatch()
    }
}

fn breg_provider(
    registry: &RegistryConfig,
    service: &ServiceConfig,
    keys: AuditKeyHasher,
) -> Result<Arc<BRegProvider>, BRegBindingError> {
    Ok(Arc::new(BRegProvider::new(
        BRegProviderOptions::from_product_config(registry, service),
        keys,
    )?))
}

fn breg_delegation(
    registry: &RegistryConfig,
    exchange: &ExchangeConfig,
    gateway_resource: &str,
    key: PrivateJwk,
) -> Result<Arc<Delegation>, AuthorizationError> {
    Ok(Arc::new(Delegation::new(DelegationOptions {
        token_endpoint: exchange.token_endpoint.to_url(),
        client_id: exchange.client_id.to_string(),
        private_key: key,
        assertion_audience: exchange
            .assertion_audience
            .as_ref()
            .map(ToString::to_string),
        gateway_resource: gateway_resource.to_owned(),
        downstream_resource: registry.audience.as_str().to_owned(),
        downstream_scopes: registry
            .scopes
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect(),
        attempt_timeout: Duration::from_millis(registry.attempt_timeout_milliseconds.get()),
        generation: EXCHANGE_GENERATION.to_owned(),
    })?))
}

/// Why the product-owned provider and its matching delegation could not be bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BRegBindingError {
    #[error("the BReg provider client could not be configured")]
    Client,
    #[error("the BReg delegated authorization could not be configured")]
    Authorization,
    #[error("the BReg tool ceiling could not be configured")]
    Tools,
}

/// Construct one BReg provider together with its only supported per-call delegation.
///
/// The raw provider and authorization constructors are intentionally private, so
/// a consumer cannot pair the citizen tools with a static or unrelated credential.
///
/// ```compile_fail
/// use registry_breg_mcp::breg_provider;
/// ```
///
/// ```compile_fail
/// use registry_breg_mcp::breg_delegation;
/// ```
///
/// ```compile_fail
/// use registry_breg_mcp::BRegProvider;
/// ```
///
/// ```compile_fail
/// use registry_breg_mcp::BRegProviderOptions;
/// ```
pub fn breg_binding<I>(
    registry: &RegistryConfig,
    exchange: &ExchangeConfig,
    service: &ServiceConfig,
    gateway_resource: &str,
    private_key: PrivateJwk,
    audit_hasher: AuditKeyHasher,
    configured_tool_names: I,
) -> Result<ProviderBinding, BRegBindingError>
where
    I: IntoIterator<Item = String>,
{
    let provider = breg_provider(registry, service, audit_hasher)?;
    let authorization = breg_delegation(registry, exchange, gateway_resource, private_key)
        .map_err(|_| BRegBindingError::Authorization)?;
    let edge_provider: Arc<dyn Provider> = provider;
    ProviderBinding::new(edge_provider, authorization, configured_tool_names)
        .map_err(|_: ProviderBindingError| BRegBindingError::Tools)
}

#[cfg(test)]
pub(crate) fn breg_binding_for_test<I>(
    registry: &RegistryConfig,
    exchange: &ExchangeConfig,
    service: &ServiceConfig,
    gateway_resource: &str,
    private_key: PrivateJwk,
    audit_hasher: AuditKeyHasher,
    configured_tool_names: I,
) -> Result<(ProviderBinding, Arc<BRegProvider>), BRegBindingError>
where
    I: IntoIterator<Item = String>,
{
    let provider = breg_provider(registry, service, audit_hasher)?;
    let authorization = breg_delegation(registry, exchange, gateway_resource, private_key)
        .map_err(|_| BRegBindingError::Authorization)?;
    let edge_provider: Arc<dyn Provider> = provider.clone();
    let binding = ProviderBinding::new(edge_provider, authorization, configured_tool_names)
        .map_err(|_: ProviderBindingError| BRegBindingError::Tools)?;
    Ok((binding, provider))
}

#[async_trait]
impl Provider for BRegProvider {
    fn resolve_tool(&self, public_name: &str) -> Option<ResolvedTool> {
        TOOL_NAMES.contains(&public_name).then(|| {
            ResolvedTool::new(public_name, PROVIDER_ID, public_name, OPERATION_VERSION)
                .expect("the fixed BReg tool identity is valid")
        })
    }

    async fn list_tools(
        &self,
        _caller: &VerifiedCaller,
        authorization: ProviderAuthorization,
    ) -> Result<Vec<Tool>, ProviderFailure> {
        let contract = self
            .gateway
            .contract(authorization)
            .await
            .map_err(provider_failure)?;
        Ok(tool_definitions(&self.gateway.service().name, &contract))
    }

    async fn invoke(
        &self,
        caller: &VerifiedCaller,
        authorization: ProviderAuthorization,
        invocation: Invocation<'_>,
    ) -> ProviderOutcome {
        let name = invocation.tool.public_name();
        if self.resolve_tool(name).as_ref() != Some(invocation.tool) {
            return ProviderOutcome::failure(ProviderFailure::new(
                "invalid-arguments",
                "The arguments do not match what this tool accepts.",
                EffectCertainty::NoEffect,
            ));
        }
        match self
            .gateway
            .dispatch(caller, authorization, name, invocation.arguments)
            .await
        {
            Ok(value) => ProviderOutcome::success(value, success_effect(name)),
            Err(error) => ProviderOutcome::failure(provider_failure(error)),
        }
    }
}

fn success_effect(tool: &str) -> EffectCertainty {
    if matches!(tool, START_APPLICATION | UPDATE_APPLICATION) {
        EffectCertainty::Confirmed
    } else {
        EffectCertainty::NoEffect
    }
}

fn provider_failure(error: ToolError) -> ProviderFailure {
    let effect = if error.effect_unknown {
        EffectCertainty::Unknown
    } else {
        EffectCertainty::NoEffect
    };
    let mut failure = ProviderFailure::new(error.code.as_str(), error.code.message(), effect);
    if let Some(trace_id) = error.trace_id {
        failure = failure.with_trace_id(trace_id);
    }
    failure
}

#[cfg(test)]
mod tests {
    use registry_mcp_edge::{EffectCertainty, Provider as _};
    use registry_platform_audit::AuditProfile;
    use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
    use url::Url;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        config::tests::{outbound_sections, service},
        problems::ToolErrorCode,
        tools::TOOL_NAMES,
    };

    fn provider() -> BRegProvider {
        let profile = AuditProfile::production_from_secret_bytes(Zeroizing::new(vec![7; 32]))
            .expect("audit profile");
        BRegProvider::new(
            BRegProviderOptions {
                base_url: Url::parse("https://registry.example.test/").expect("registry URL"),
                attempt_timeout: std::time::Duration::from_secs(10),
                access_profile: "citizen-agent".to_owned(),
                details_record_type: "addresses".to_owned(),
                action: "correct-address".to_owned(),
                target_input: "address".to_owned(),
                service_name: "Address correction".to_owned(),
                service_description: "Correct the address held for you.".to_owned(),
                service_disclosure: "The assistant sees your current address.".to_owned(),
                review_base_url: Url::parse("https://review.example.test/").expect("review URL"),
            },
            profile.key_hasher(),
        )
        .expect("provider")
    }

    #[test]
    fn provider_resolves_exactly_the_existing_breg_tool_ceiling() {
        let provider = provider();
        for name in TOOL_NAMES {
            let tool = provider.resolve_tool(name).expect("configured BReg tool");
            assert_eq!(tool.public_name(), name);
            assert_eq!(tool.provider(), "breg");
            assert_eq!(tool.operation(), name);
            assert_eq!(tool.version(), "v1");
        }
        for forbidden in [
            "submit_application",
            "apply_application",
            "invoke_action",
            "create_record",
            "delete_record",
        ] {
            assert!(provider.resolve_tool(forbidden).is_none(), "{forbidden}");
        }
    }

    #[test]
    fn provider_failure_preserves_fixed_error_and_effect_disposition() {
        let no_effect = provider_failure(crate::problems::ToolError::new(
            ToolErrorCode::InvalidArguments,
        ));
        assert_eq!(no_effect.code(), "invalid-arguments");
        assert_eq!(no_effect.effect(), EffectCertainty::NoEffect);

        let unknown = provider_failure(
            crate::problems::ToolError::new(ToolErrorCode::RegistryUnavailable).after_mutation(),
        );
        assert_eq!(unknown.code(), "registry-unavailable");
        assert_eq!(unknown.effect(), EffectCertainty::Unknown);
    }

    #[test]
    fn binding_refuses_tools_outside_the_breg_ceiling() {
        let (registry, exchange) = outbound_sections(
            "https://registry.example.test/",
            "https://login.example.test/token",
        );
        let private_key = generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("private key");
        let profile = AuditProfile::production_from_secret_bytes(Zeroizing::new(vec![8; 32]))
            .expect("audit profile");

        let error = breg_binding(
            &registry,
            &exchange,
            &service(),
            "https://gateway.example.test/mcp",
            private_key,
            profile.key_hasher(),
            ["submit_application".to_owned()],
        )
        .err()
        .expect("unsupported tool is refused");

        assert_eq!(error, BRegBindingError::Tools);
    }
}

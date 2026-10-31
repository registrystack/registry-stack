// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, sync::Arc};

use rmcp::model::{CallToolResult, Tool};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    audit::ToolAudit, AuditOptions, AuthorizationError, AuthorizationFactory, EffectCertainty,
    Invocation, Provider, ProviderFailure, ProviderOutcome, ResolvedTool, ToolAuditLog,
    VerifiedCaller,
};

const MAXIMUM_IMPLEMENTATION_NAME_BYTES: usize = 4096;
const MAXIMUM_SERVICE_NAME_BYTES: usize = 16 * 1024;
const MAXIMUM_INSTRUCTIONS_BYTES: usize = 64 * 1024;

/// Display and MCP implementation identity supplied by a product wrapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayInfo {
    implementation_name: String,
    service_name: String,
    instructions: String,
}

impl GatewayInfo {
    pub fn new(
        implementation_name: impl Into<String>,
        service_name: impl Into<String>,
        instructions: impl Into<String>,
    ) -> Result<Self, GatewayBuildError> {
        let info = Self {
            implementation_name: implementation_name.into(),
            service_name: service_name.into(),
            instructions: instructions.into(),
        };
        if !valid_text(&info.implementation_name, MAXIMUM_IMPLEMENTATION_NAME_BYTES)
            || !valid_text(&info.service_name, MAXIMUM_SERVICE_NAME_BYTES)
            || !valid_text(&info.instructions, MAXIMUM_INSTRUCTIONS_BYTES)
        {
            return Err(GatewayBuildError::Info);
        }
        Ok(info)
    }

    #[must_use]
    pub fn implementation_name(&self) -> &str {
        &self.implementation_name
    }

    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    #[must_use]
    pub fn instructions(&self) -> &str {
        &self.instructions
    }
}

fn valid_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\t' | '\n' | '\r'))
}

/// One provider, its independent authorization factory, and its configured tool ceiling.
pub struct ProviderBinding {
    provider: Arc<dyn Provider>,
    authorization: Arc<dyn AuthorizationFactory>,
    tools: BTreeMap<String, ResolvedTool>,
}

impl ProviderBinding {
    pub fn new<I>(
        provider: Arc<dyn Provider>,
        authorization: Arc<dyn AuthorizationFactory>,
        configured_tools: I,
    ) -> Result<Self, ProviderBindingError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut tools = BTreeMap::new();
        for public_name in configured_tools {
            let resolved = provider
                .resolve_tool(&public_name)
                .filter(|resolved| resolved.public_name() == public_name)
                .ok_or(ProviderBindingError::UnsupportedTool)?;
            if tools.insert(public_name, resolved).is_some() {
                return Err(ProviderBindingError::DuplicateTool);
            }
        }
        if tools.is_empty() {
            return Err(ProviderBindingError::Empty);
        }
        Ok(Self {
            provider,
            authorization,
            tools,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProviderBindingError {
    #[error("a provider binding must configure at least one tool")]
    Empty,
    #[error("a provider binding configures the same tool more than once")]
    DuplicateTool,
    #[error("a provider binding names a tool the provider does not support")]
    UnsupportedTool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GatewayBuildError {
    #[error("the gateway identity or instructions are invalid")]
    Info,
    #[error("the gateway must configure at least one provider binding")]
    Empty,
    #[error("two provider bindings configure the same public tool name")]
    DuplicateTool,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CatalogError {
    #[error("the provider catalog is unavailable")]
    Provider(ProviderFailure),
    #[error("the provider catalog does not match the configured tool ceiling")]
    Contract,
}

impl CatalogError {
    pub(crate) fn to_value(&self) -> Value {
        match self {
            Self::Provider(failure) => failure.to_value(),
            Self::Contract => json!({"error": {
                "code": "catalog-invalid",
                "message": "The service catalog does not match its configured capabilities."
            }}),
        }
    }
}

#[derive(Clone)]
struct Route {
    binding: usize,
    tool: ResolvedTool,
}

/// Shared MCP catalog and invocation edge over independently authorized providers.
pub struct GatewayCore {
    bindings: Vec<ProviderBinding>,
    routes: BTreeMap<String, Route>,
    audit: ToolAuditLog,
    audit_options: AuditOptions,
    info: GatewayInfo,
}

impl GatewayCore {
    pub fn new<I>(
        bindings: I,
        audit: ToolAuditLog,
        audit_options: AuditOptions,
        info: GatewayInfo,
    ) -> Result<Self, GatewayBuildError>
    where
        I: IntoIterator<Item = ProviderBinding>,
    {
        let bindings: Vec<_> = bindings.into_iter().collect();
        if bindings.is_empty() {
            return Err(GatewayBuildError::Empty);
        }
        let mut routes = BTreeMap::new();
        for (binding, configured) in bindings.iter().enumerate() {
            for (name, tool) in &configured.tools {
                if routes
                    .insert(
                        name.clone(),
                        Route {
                            binding,
                            tool: tool.clone(),
                        },
                    )
                    .is_some()
                {
                    return Err(GatewayBuildError::DuplicateTool);
                }
            }
        }
        Ok(Self {
            bindings,
            routes,
            audit,
            audit_options,
            info,
        })
    }

    #[must_use]
    pub const fn info(&self) -> &GatewayInfo {
        &self.info
    }

    pub async fn ready(&self) -> bool {
        self.audit.ready().await
    }

    pub(crate) fn recognizes_tool(&self, name: &str) -> bool {
        self.routes.contains_key(name)
    }

    pub async fn list_tools(&self, caller: &VerifiedCaller) -> Result<Vec<Tool>, CatalogError> {
        let mut catalog = BTreeMap::<String, Tool>::new();
        let mut completed = 0usize;
        let mut last_failure = None;
        for (binding_index, binding) in self.bindings.iter().enumerate() {
            let authorization = match binding.authorization.authorization(caller) {
                Ok(authorization) => authorization,
                Err(AuthorizationError::Unavailable) => {
                    tracing::warn!(
                        binding = binding_index,
                        stage = "authorization",
                        reason = authorization_catalog_reason(AuthorizationError::Unavailable),
                        "provider catalog binding unavailable"
                    );
                    if last_failure.is_none() {
                        last_failure = Some(ProviderFailure::new(
                            "catalog-authorization-failed",
                            "The provider catalog authorization is not available right now.",
                            EffectCertainty::NoEffect,
                        ));
                    }
                    continue;
                }
                Err(AuthorizationError::Configuration) => return Err(CatalogError::Contract),
            };
            let tools = match binding.provider.list_tools(caller, authorization).await {
                Ok(tools) => tools,
                Err(failure) if failure.valid() => {
                    tracing::warn!(
                        binding = binding_index,
                        stage = "provider",
                        reason = "provider-unavailable",
                        "provider catalog binding unavailable"
                    );
                    last_failure = Some(failure);
                    continue;
                }
                Err(_) => return Err(CatalogError::Contract),
            };
            completed += 1;
            for tool in tools {
                let name = tool.name.as_ref();
                let Some(configured) = binding.tools.get(name) else {
                    continue;
                };
                if binding.provider.resolve_tool(name).as_ref() != Some(configured)
                    || catalog.insert(name.to_owned(), tool).is_some()
                {
                    return Err(CatalogError::Contract);
                }
            }
        }
        if completed == 0 {
            return Err(CatalogError::Provider(last_failure.expect(
                "a configured binding that did not complete has a failure",
            )));
        }
        Ok(catalog.into_values().collect())
    }

    pub async fn call(
        &self,
        caller: &VerifiedCaller,
        tool: &str,
        arguments: Option<&Map<String, Value>>,
    ) -> CallToolResult {
        let Some(route) = self.routes.get(tool) else {
            return failure_result(&ProviderFailure::new(
                "unknown-tool",
                "The requested tool is not configured.",
                EffectCertainty::NoEffect,
            ));
        };
        let audit_record = ToolAudit {
            tool: route.tool.public_name(),
            principal_pseudonym: caller.principal_pseudonym(),
            client_pseudonym: caller.client_pseudonym(),
        };
        let request_id = Uuid::new_v4();
        let mut audit_request = match self
            .audit
            .begin(request_id.to_string(), &self.audit_options, &audit_record)
            .await
        {
            Ok(request) => request,
            Err(error) => {
                tracing::error!(
                    request_id = %request_id,
                    reason = ?error.reason(),
                    "tool audit request refused"
                );
                return service_unavailable();
            }
        };
        let binding = &self.bindings[route.binding];
        let outcome = match binding.authorization.authorization(caller) {
            Ok(authorization) => {
                binding
                    .provider
                    .invoke(
                        caller,
                        authorization,
                        Invocation {
                            request_id,
                            tool: &route.tool,
                            arguments,
                        },
                    )
                    .await
            }
            Err(_) => ProviderOutcome::failure(ProviderFailure::new(
                "authorization-failed",
                "The downstream authorization is not available right now.",
                EffectCertainty::NoEffect,
            )),
        };
        let (result, audit_outcome, reason) = result_and_audit(outcome);
        if let Err(error) = audit_request
            .respond(audit_record.response(self.audit_options.event(), audit_outcome, reason))
            .await
        {
            tracing::error!(
                request_id = %request_id,
                reason = ?error.reason(),
                "tool audit response refused"
            );
            return service_unavailable();
        }
        tracing::info!(
            request_id = %request_id,
            tool = route.tool.public_name(),
            outcome = audit_outcome,
            reason = call_log_reason(audit_outcome),
            "tool call"
        );
        result
    }
}

fn result_and_audit(
    outcome: ProviderOutcome,
) -> (CallToolResult, &'static str, Option<&'static str>) {
    match outcome {
        ProviderOutcome::Success { value, effect } => match effect {
            EffectCertainty::NoEffect | EffectCertainty::Confirmed => {
                (CallToolResult::structured(value), "ok", None)
            }
            EffectCertainty::Unknown => {
                (service_unavailable(), "unfinished", Some("effect-unknown"))
            }
        },
        ProviderOutcome::Failure(failure) if !failure.valid() => {
            if failure.effect() == EffectCertainty::Unknown {
                (service_unavailable(), "unfinished", Some("effect-unknown"))
            } else {
                (
                    service_unavailable(),
                    "refused",
                    Some("service-unavailable"),
                )
            }
        }
        ProviderOutcome::Failure(failure) => {
            let audit_outcome = if failure.effect() == EffectCertainty::Unknown {
                "unfinished"
            } else {
                "refused"
            };
            let reason = failure.code();
            (failure_result(&failure), audit_outcome, Some(reason))
        }
    }
}

fn call_log_reason(audit_outcome: &str) -> &'static str {
    match audit_outcome {
        "ok" => "none",
        "unfinished" => "effect-unknown",
        _ => "provider-refused",
    }
}

const fn authorization_catalog_reason(error: AuthorizationError) -> &'static str {
    match error {
        AuthorizationError::Unavailable => "authorization-unavailable",
        AuthorizationError::Configuration => "authorization-configuration",
    }
}

fn failure_result(failure: &ProviderFailure) -> CallToolResult {
    CallToolResult::structured_error(failure.to_value())
}

fn service_unavailable() -> CallToolResult {
    failure_result(&ProviderFailure::new(
        "service-unavailable",
        "This service is not available right now.",
        EffectCertainty::NoEffect,
    ))
}

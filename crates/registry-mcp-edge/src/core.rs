// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, sync::Arc};

use rmcp::model::{CallToolResult, Tool};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    audit::ToolAudit, AuditOptions, AuthorizationFactory, EffectCertainty, Invocation, Provider,
    ProviderFailure, ProviderOutcome, ResolvedTool, ToolAuditLog, VerifiedCaller,
};

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
        if [
            &info.implementation_name,
            &info.service_name,
            &info.instructions,
        ]
        .into_iter()
        .any(|value| !valid_text(value))
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

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CatalogError {
    #[error("the provider catalog is unavailable")]
    Provider,
    #[error("the provider catalog does not match the configured tool ceiling")]
    Contract,
}

impl CatalogError {
    pub(crate) fn to_value(self) -> Value {
        let (code, message) = match self {
            Self::Provider => (
                "service-unavailable",
                "The service catalog is not available right now.",
            ),
            Self::Contract => (
                "catalog-invalid",
                "The service catalog does not match its configured capabilities.",
            ),
        };
        json!({"error": {"code": code, "message": message}})
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
        for binding in &self.bindings {
            let authorization = binding
                .authorization
                .authorization(caller)
                .map_err(|_| CatalogError::Provider)?;
            let tools = binding
                .provider
                .list_tools(caller, authorization)
                .await
                .map_err(|failure| {
                    if failure.valid() {
                        CatalogError::Provider
                    } else {
                        CatalogError::Contract
                    }
                })?;
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
        let Ok(mut audit_request) = self
            .audit
            .begin(request_id.to_string(), &self.audit_options, &audit_record)
            .await
        else {
            return service_unavailable();
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
        if audit_request
            .respond(audit_record.response(self.audit_options.event(), audit_outcome, reason))
            .await
            .is_err()
        {
            return service_unavailable();
        }
        tracing::info!(
            request_id = %request_id,
            tool = route.tool.public_name(),
            outcome = audit_outcome,
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
            EffectCertainty::AcceptedPending => {
                (CallToolResult::structured(value), "accepted", None)
            }
            EffectCertainty::Unknown => {
                (service_unavailable(), "unfinished", Some("effect-unknown"))
            }
        },
        ProviderOutcome::Failure(failure) if !failure.valid() => (
            service_unavailable(),
            "refused",
            Some("service-unavailable"),
        ),
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

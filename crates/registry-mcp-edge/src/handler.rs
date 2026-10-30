// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use rmcp::{
    model::{
        CacheScope, CallToolRequestParams, CallToolResponse, Implementation, InitializeResult,
        ListToolsResult, PaginatedRequestParams, ServerCapabilities,
    },
    service::RequestContext,
    ErrorData as McpError, RoleServer, ServerHandler,
};

use crate::{GatewayCore, VerifiedCaller};

#[derive(Clone)]
pub(crate) struct GatewayHandler {
    gateway: Arc<GatewayCore>,
}

impl GatewayHandler {
    pub(crate) const fn new(gateway: Arc<GatewayCore>) -> Self {
        Self { gateway }
    }
}

fn verified_caller(context: &RequestContext<RoleServer>) -> Result<Arc<VerifiedCaller>, McpError> {
    context
        .extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<Arc<VerifiedCaller>>())
        .cloned()
        .ok_or_else(|| McpError::internal_error("the request carries no verified caller", None))
}

impl ServerHandler for GatewayHandler {
    fn get_info(&self) -> InitializeResult {
        let info = self.gateway.info();
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                info.implementation_name(),
                registry_platform_buildinfo::DISPLAY_VERSION,
            ))
            .with_instructions(info.instructions().to_owned())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let caller = verified_caller(&context)?;
        let tools = self.gateway.list_tools(&caller).await.map_err(|error| {
            McpError::internal_error("the service catalog is unavailable", Some(error.to_value()))
        })?;
        Ok(ListToolsResult::with_all_items(tools)
            .with_cache_scope(CacheScope::Private)
            .with_ttl_ms(0))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        if !self.gateway.recognizes_tool(&request.name) {
            return Err(McpError::invalid_params("unknown tool", None));
        }
        let caller = verified_caller(&context)?;
        Ok(self
            .gateway
            .call(&caller, &request.name, request.arguments.as_ref())
            .await
            .into())
    }
}

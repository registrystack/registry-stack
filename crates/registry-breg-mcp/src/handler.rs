// SPDX-License-Identifier: Apache-2.0

//! The MCP protocol surface: tool listing and tool calls over [`Gateway`].
//!
//! The handler never reads an identity from the MCP message. The citizen is
//! the [`VerifiedCaller`] the resource-server middleware attached to the HTTP
//! request, which rmcp hands through as the request's `http::request::Parts`.

use std::sync::Arc;

use rmcp::{
    model::{
        CacheScope, CallToolRequestParams, CallToolResponse, Implementation, InitializeResult,
        ListToolsResult, PaginatedRequestParams, ServerCapabilities, Tool, ToolAnnotations,
    },
    service::RequestContext,
    ErrorData as McpError, RoleServer, ServerHandler,
};

use crate::{
    contract::Contract,
    gateway::Gateway,
    inbound::VerifiedCaller,
    tools::{
        application_input_schema, empty_input_schema, start_input_schema, update_input_schema,
        DESCRIBE_SERVICE, GET_APPLICATION_STATUS, GET_MY_DETAILS, PREPARE_REVIEW,
        START_APPLICATION, TOOL_NAMES, UPDATE_APPLICATION,
    },
};

/// One MCP server instance over the shared gateway. rmcp builds one per
/// request, so it holds nothing but the shared gateway.
#[derive(Clone)]
pub(crate) struct GatewayHandler {
    gateway: Arc<Gateway>,
}

impl GatewayHandler {
    pub(crate) const fn new(gateway: Arc<Gateway>) -> Self {
        Self { gateway }
    }
}

/// The verified caller the resource-server middleware attached to this
/// request. Its absence means the endpoint was mounted without that
/// middleware, which is a deployment fault and never an anonymous call.
fn verified_caller(context: &RequestContext<RoleServer>) -> Result<Arc<VerifiedCaller>, McpError> {
    context
        .extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<Arc<VerifiedCaller>>())
        .cloned()
        .ok_or_else(|| McpError::internal_error("the request carries no verified caller", None))
}

/// The six tool definitions, with the start and update schemas taken from
/// the contract the registry publishes for this caller.
pub(crate) fn tool_definitions(service_name: &str, contract: &Contract) -> Vec<Tool> {
    vec![
        Tool::new(
            DESCRIBE_SERVICE,
            format!(
                "Describe the {service_name} service and what the chat host will see. \
                 Returns no personal data."
            ),
            empty_input_schema(),
        )
        .with_title("Describe the service")
        .with_annotations(read_only()),
        Tool::new(
            GET_MY_DETAILS,
            "Read the signed-in citizen's own record, as labelled registry data.",
            empty_input_schema(),
        )
        .with_title("Read my details")
        .with_annotations(read_only()),
        Tool::new(
            START_APPLICATION,
            "Start a draft application for the signed-in citizen's own record. The draft \
             is not submitted; the citizen reviews and submits it on the service's own page.",
            start_input_schema(contract),
        )
        .with_title("Start an application")
        .with_annotations(
            ToolAnnotations::new()
                .read_only(false)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        ),
        Tool::new(
            UPDATE_APPLICATION,
            "Change fields of one of the citizen's own draft applications. Name the \
             revision the edits were made against.",
            update_input_schema(contract),
        )
        .with_title("Update an application")
        .with_annotations(
            ToolAnnotations::new()
                .read_only(false)
                .destructive(true)
                .idempotent(true)
                .open_world(false),
        ),
        Tool::new(
            PREPARE_REVIEW,
            "Return the link where the citizen reviews and submits one of their own \
             applications. Nothing is submitted by this tool.",
            application_input_schema(),
        )
        .with_title("Prepare the review")
        .with_annotations(read_only()),
        Tool::new(
            GET_APPLICATION_STATUS,
            "Report the status of one of the citizen's own applications, as the registry \
             records it.",
            application_input_schema(),
        )
        .with_title("Get an application's status")
        .with_annotations(read_only()),
    ]
}

fn read_only() -> ToolAnnotations {
    ToolAnnotations::new()
        .read_only(true)
        .destructive(false)
        .idempotent(true)
        .open_world(false)
}

impl ServerHandler for GatewayHandler {
    fn get_info(&self) -> InitializeResult {
        let service = self.gateway.service();
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "breg-mcp",
                registry_platform_buildinfo::DISPLAY_VERSION,
            ))
            .with_instructions(format!(
                "{}\n\n{}\n\nThe citizen is always the signed-in user. Applications are \
                 submitted only on the review page prepare_review returns.",
                service.name, service.description
            ))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let caller = verified_caller(&context)?;
        // The schemas are read fresh for this caller on every listing, so a
        // change of identity or registry revision never serves a stale one.
        let contract = self.gateway.contract(&caller).await.map_err(|error| {
            McpError::internal_error(
                "the registry contract is unavailable",
                Some(error.to_value()),
            )
        })?;
        Ok(ListToolsResult::with_all_items(tool_definitions(
            &self.gateway.service().name,
            &contract,
        ))
        .with_cache_scope(CacheScope::Private)
        .with_ttl_ms(0))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        if !TOOL_NAMES.contains(&request.name.as_ref()) {
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

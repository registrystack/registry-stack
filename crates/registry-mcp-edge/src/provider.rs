// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use rmcp::model::Tool;
use serde_json::{json, Map, Value};

use crate::{ProviderAuthorization, VerifiedCaller};

const MAXIMUM_IDENTITY_BYTES: usize = 256;

/// Stable configured identity for one public tool and its provider operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedTool {
    public_name: String,
    provider: String,
    operation: String,
    version: String,
}

impl ResolvedTool {
    pub fn new(
        public_name: impl Into<String>,
        provider: impl Into<String>,
        operation: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, ToolIdentityError> {
        let identity = Self {
            public_name: public_name.into(),
            provider: provider.into(),
            operation: operation.into(),
            version: version.into(),
        };
        if !valid_tool_name(&identity.public_name)
            || !valid_identity(&identity.provider)
            || !valid_identity(&identity.operation)
            || !valid_identity(&identity.version)
        {
            return Err(ToolIdentityError);
        }
        Ok(identity)
    }

    #[must_use]
    pub fn public_name(&self) -> &str {
        &self.public_name
    }

    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
}

fn valid_tool_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_IDENTITY_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_IDENTITY_BYTES
        && !value.chars().any(char::is_control)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the provider tool identity is invalid")]
pub struct ToolIdentityError;

/// What is known about the protected effect after a provider returns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectCertainty {
    /// A read or a refusal with no protected effect.
    NoEffect,
    /// The provider confirmed the effect.
    Confirmed,
    /// A request may have taken effect, but its result is not known.
    Unknown,
}

/// A fixed, value-free provider failure safe to return to an MCP caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderFailure {
    code: &'static str,
    message: &'static str,
    trace_id: Option<String>,
    effect: EffectCertainty,
}

impl ProviderFailure {
    #[must_use]
    pub const fn new(code: &'static str, message: &'static str, effect: EffectCertainty) -> Self {
        Self {
            code,
            message,
            trace_id: None,
            effect,
        }
    }

    #[must_use]
    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn effect(&self) -> EffectCertainty {
        self.effect
    }

    pub(crate) fn valid(&self) -> bool {
        valid_error_code(self.code)
            && !self.message.is_empty()
            && self.message.len() <= 1024
            && !self.message.chars().any(char::is_control)
            && self
                .trace_id
                .as_ref()
                .is_none_or(|trace| valid_identity(trace))
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut error = json!({"code": self.code, "message": self.message});
        if let Some(trace_id) = &self.trace_id {
            error["traceId"] = Value::String(trace_id.clone());
        }
        json!({"error": error})
    }
}

fn valid_error_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// One provider result together with its protected-effect disposition.
#[derive(Clone, Debug, PartialEq)]
pub enum ProviderOutcome {
    Success {
        value: Value,
        effect: EffectCertainty,
    },
    Failure(ProviderFailure),
}

impl ProviderOutcome {
    #[must_use]
    pub fn success(value: Value, effect: EffectCertainty) -> Self {
        Self::Success { value, effect }
    }

    #[must_use]
    pub fn failure(failure: ProviderFailure) -> Self {
        Self::Failure(failure)
    }
}

/// A configured invocation. Tool identity comes from the binding, never the caller.
#[derive(Clone, Copy, Debug)]
pub struct Invocation<'a> {
    /// Gateway-minted random audit correlation; it carries no caller identifier.
    pub request_id: uuid::Uuid,
    pub tool: &'a ResolvedTool,
    pub arguments: Option<&'a Map<String, Value>>,
}

/// Product-specific catalog and invocation behind the shared MCP edge.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Resolve a public tool name against this provider's configured operation ceiling.
    fn resolve_tool(&self, public_name: &str) -> Option<ResolvedTool>;

    /// Return the caller-filtered catalog. The edge applies the static binding ceiling again.
    async fn list_tools(
        &self,
        caller: &VerifiedCaller,
        authorization: ProviderAuthorization,
    ) -> Result<Vec<Tool>, ProviderFailure>;

    /// Invoke one tool whose identity the binding already resolved.
    async fn invoke(
        &self,
        caller: &VerifiedCaller,
        authorization: ProviderAuthorization,
        invocation: Invocation<'_>,
    ) -> ProviderOutcome;
}

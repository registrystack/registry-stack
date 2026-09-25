// SPDX-License-Identifier: Apache-2.0
//! Node.js binding for the canonical Registry Messaging client.

#![deny(unsafe_code)]

use std::time::Duration;

use napi::{Error as NapiError, Result};
use napi_derive::napi;
use registry_messaging_client::{
    BearerToken, MessagingClient as CoreClient, MessagingClientConfig as CoreConfig,
    MessagingClientError, MessagingComplete, MessagingProtocolFailure, SubmitMessageRequest,
    TemplatePreviewRequest,
};
use serde::Serialize;
use serde_json::{json, Value};
use url::Url;

const MAXIMUM_JAVASCRIPT_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[napi(object)]
pub struct MessagingClientConfig {
    pub base_url: String,
    pub request_timeout_milliseconds: Option<u32>,
    pub connect_timeout_milliseconds: Option<u32>,
    pub max_response_bytes: Option<u32>,
    pub user_agent: Option<String>,
    pub trusted_root_certificates: Option<String>,
}

#[napi(object)]
pub struct MessagingOutcome {
    pub kind: String,
    pub value: Value,
    pub trace_id: String,
}

#[napi(js_name = "MessagingClient")]
pub struct MessagingClient {
    inner: CoreClient,
}

#[napi]
impl MessagingClient {
    #[napi(constructor)]
    pub fn new(config: MessagingClientConfig) -> Result<Self> {
        let base_url = Url::parse(&config.base_url).map_err(|_| {
            binding_error("configuration", "Messaging client configuration is invalid")
        })?;
        let mut core = CoreConfig::new(base_url);
        if let Some(value) = config.request_timeout_milliseconds {
            core = core.with_request_timeout(Duration::from_millis(u64::from(value)));
        }
        if let Some(value) = config.connect_timeout_milliseconds {
            core = core.with_connect_timeout(Duration::from_millis(u64::from(value)));
        }
        if let Some(value) = config.max_response_bytes {
            core = core.with_max_response_bytes(u64::from(value));
        }
        if let Some(value) = config.user_agent {
            core = core.with_user_agent(value);
        }
        if let Some(value) = config.trusted_root_certificates {
            core = core.with_trusted_root_certificates(value.into_bytes());
        }
        CoreClient::new(core)
            .map(|inner| Self { inner })
            .map_err(client_error)
    }

    #[napi]
    pub async fn health(&self) -> Result<MessagingOutcome> {
        outcome(self.inner.health().await)
    }

    #[napi]
    pub async fn ready(&self) -> Result<MessagingOutcome> {
        outcome(self.inner.ready().await)
    }

    #[napi]
    pub async fn submit(
        &self,
        token: String,
        idempotency_key: String,
        request: Value,
    ) -> Result<MessagingOutcome> {
        let token = bearer(token)?;
        let request: SubmitMessageRequest = input(request)?;
        outcome(self.inner.submit(&token, &idempotency_key, &request).await)
    }

    #[napi]
    pub async fn message(&self, token: String, message_id: String) -> Result<MessagingOutcome> {
        let token = bearer(token)?;
        outcome(self.inner.message(&token, &message_id).await)
    }

    #[napi]
    pub async fn cancel(&self, token: String, message_id: String) -> Result<MessagingOutcome> {
        let token = bearer(token)?;
        outcome(self.inner.cancel(&token, &message_id).await)
    }

    #[napi]
    pub async fn preview(
        &self,
        token: String,
        template_id: String,
        version: String,
        request: Value,
    ) -> Result<MessagingOutcome> {
        let token = bearer(token)?;
        let request: TemplatePreviewRequest = input(request)?;
        outcome(
            self.inner
                .preview(&token, &template_id, &version, &request)
                .await,
        )
    }
}

fn bearer(value: String) -> Result<BearerToken> {
    BearerToken::new(value)
        .map_err(|_| binding_error("invalid_request", "the bearer token is invalid"))
}

fn input<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    if contains_unsafe_integer(&value) {
        return Err(binding_error(
            "invalid_request",
            "Messaging client arguments are invalid",
        ));
    }
    serde_json::from_value(value)
        .map_err(|_| binding_error("invalid_request", "Messaging client arguments are invalid"))
}

fn outcome<T: Serialize>(
    value: std::result::Result<MessagingComplete<T>, MessagingClientError>,
) -> Result<MessagingOutcome> {
    let value = value.map_err(client_error)?;
    let serialized = serde_json::to_value(value.value)
        .map_err(|_| binding_error("protocol", "Messaging result is not representable"))?;
    ensure_safe_integers(&serialized)?;
    Ok(MessagingOutcome {
        kind: "complete".into(),
        value: serialized,
        trace_id: value.trace_id,
    })
}

fn ensure_safe_integers(value: &Value) -> Result<()> {
    if contains_unsafe_integer(value) {
        return Err(binding_error(
            "protocol",
            "Messaging returned an integer outside the JavaScript safe range",
        ));
    }
    Ok(())
}

fn contains_unsafe_integer(value: &Value) -> bool {
    match value {
        Value::Number(number)
            if number.as_i64().is_some_and(|value| {
                value.unsigned_abs() > MAXIMUM_JAVASCRIPT_SAFE_INTEGER as u64
            }) || number
                .as_u64()
                .is_some_and(|value| value > MAXIMUM_JAVASCRIPT_SAFE_INTEGER as u64)
                || number.as_f64().is_some_and(|value| {
                    value.fract() == 0.0 && value.abs() > MAXIMUM_JAVASCRIPT_SAFE_INTEGER as f64
                }) =>
        {
            true
        }
        Value::Array(values) => values.iter().any(contains_unsafe_integer),
        Value::Object(values) => values.values().any(contains_unsafe_integer),
        _ => false,
    }
}

fn client_error(error: MessagingClientError) -> NapiError {
    NapiError::from_reason(
        serde_json::to_string(&error_envelope(error)).unwrap_or_else(|_| {
            r#"{"kind":"protocol","message":"the failure could not be described"}"#.into()
        }),
    )
}

fn error_envelope(error: MessagingClientError) -> Value {
    match error {
        MessagingClientError::Configuration { .. } => json!({
            "kind": "configuration",
            "message": "Messaging client configuration is invalid",
        }),
        MessagingClientError::InvalidRequest { .. } => json!({
            "kind": "invalid_request",
            "message": "Messaging client arguments are invalid",
        }),
        MessagingClientError::Transport { kind } => json!({
            "kind": "transport",
            "transportKind": kind.kind(),
            "message": "Registry Messaging exchange did not complete",
        }),
        MessagingClientError::Problem {
            status,
            code,
            trace_id,
            retry_after_seconds,
        } => json!({
            "kind": "problem",
            "status": status,
            "code": code.code(),
            "traceId": trace_id,
            "retryAfterSeconds": retry_after_seconds,
            "title": code.title(),
            "detail": code.detail(),
            "message": code.detail(),
        }),
        MessagingClientError::Protocol {
            status,
            failure,
            trace_id,
        } => json!({
            "kind": "protocol",
            "status": status,
            "protocolFailure": protocol_failure(failure),
            "traceId": trace_id,
            "message": "Registry Messaging returned an invalid response",
        }),
        _ => json!({
            "kind": "protocol",
            "message": "Registry Messaging client failed",
        }),
    }
}

fn protocol_failure(failure: MessagingProtocolFailure) -> &'static str {
    match failure {
        MessagingProtocolFailure::HeaderBounds => "header_bounds",
        MessagingProtocolFailure::TraceContext => "trace_context",
        MessagingProtocolFailure::MediaType => "media_type",
        MessagingProtocolFailure::Body => "body",
        MessagingProtocolFailure::Problem => "problem",
        MessagingProtocolFailure::Status => "status",
        _ => "protocol",
    }
}

fn binding_error(kind: &'static str, message: &'static str) -> NapiError {
    NapiError::from_reason(json!({ "kind": kind, "message": message }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_response_integer_is_refused() {
        assert!(ensure_safe_integers(&json!(9_007_199_254_740_992_u64)).is_err());
    }

    #[test]
    fn protocol_failures_use_the_public_snake_case_vocabulary() {
        assert_eq!(
            protocol_failure(MessagingProtocolFailure::HeaderBounds),
            "header_bounds"
        );
        assert_eq!(
            protocol_failure(MessagingProtocolFailure::TraceContext),
            "trace_context"
        );
        assert_eq!(
            protocol_failure(MessagingProtocolFailure::MediaType),
            "media_type"
        );
        assert_eq!(protocol_failure(MessagingProtocolFailure::Body), "body");
        assert_eq!(
            protocol_failure(MessagingProtocolFailure::Problem),
            "problem"
        );
        assert_eq!(protocol_failure(MessagingProtocolFailure::Status), "status");
    }
}

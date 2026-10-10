// SPDX-License-Identifier: Apache-2.0
//! Node.js binding for the canonical Registry Coordinator client.

#![deny(unsafe_code)]

use std::time::Duration;

use napi::{Error as NapiError, Result};
use napi_derive::napi;
use registry_coordinator_client::{
    BearerToken, CoordinatorClient as CoreClient, CoordinatorClientConfig as CoreConfig,
    CoordinatorClientError, CoordinatorComplete, CoordinatorProtocolFailure, StartRunRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;
use uuid::Uuid;

const MAXIMUM_JAVASCRIPT_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// The client settings. Unknown members are refused so a misspelled setting
/// cannot silently keep its default.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CoordinatorClientConfig {
    base_url: String,
    request_timeout_milliseconds: Option<f64>,
    connect_timeout_milliseconds: Option<f64>,
    max_response_bytes: Option<f64>,
    user_agent: Option<String>,
    trusted_root_certificates: Option<String>,
}

#[napi(object)]
pub struct CoordinatorOutcome {
    #[napi(ts_type = "'complete'")]
    pub kind: String,
    #[napi(ts_type = "unknown")]
    pub value: Value,
}

#[napi(js_name = "CoordinatorClient")]
pub struct CoordinatorClient {
    inner: CoreClient,
}

#[napi]
impl CoordinatorClient {
    #[napi(
        constructor,
        ts_args_type = "config: import('./client').CoordinatorClientConfig"
    )]
    pub fn new(config: Value) -> Result<Self> {
        let config: CoordinatorClientConfig = serde_json::from_value(config).map_err(|_| {
            binding_error(
                "configuration",
                "Coordinator client configuration is invalid",
            )
        })?;
        let base_url = Url::parse(&config.base_url).map_err(|_| {
            binding_error(
                "configuration",
                "Coordinator client configuration is invalid",
            )
        })?;
        let mut core = CoreConfig::new(base_url);
        if let Some(value) = config.request_timeout_milliseconds {
            core = core.with_request_timeout(Duration::from_millis(whole_number(value)?));
        }
        if let Some(value) = config.connect_timeout_milliseconds {
            core = core.with_connect_timeout(Duration::from_millis(whole_number(value)?));
        }
        if let Some(value) = config.max_response_bytes {
            core = core.with_max_response_bytes(whole_number(value)?);
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

    #[napi(
        ts_args_type = "token: string, idempotencyKey: string, request: import('./client').StartRunRequest",
        ts_return_type = "Promise<import('./client').CoordinatorOutcome<import('./client').RunStatus>>"
    )]
    pub async fn start(
        &self,
        token: String,
        idempotency_key: String,
        request: Value,
    ) -> Result<CoordinatorOutcome> {
        let token = bearer(token)?;
        let request: StartRunRequest = input(request)?;
        outcome(self.inner.start(&token, &idempotency_key, &request).await)
    }

    #[napi(
        ts_args_type = "token: string, runId: import('./client').RunId",
        ts_return_type = "Promise<import('./client').CoordinatorOutcome<import('./client').RunStatus>>"
    )]
    pub async fn status(&self, token: String, run_id: String) -> Result<CoordinatorOutcome> {
        let token = bearer(token)?;
        let run_id = run_id_value(run_id)?;
        outcome(self.inner.status(&token, run_id).await)
    }

    #[napi(
        ts_args_type = "token: string, runId: import('./client').RunId",
        ts_return_type = "Promise<import('./client').CoordinatorOutcome<import('./client').RunInspection>>"
    )]
    pub async fn inspect(&self, token: String, run_id: String) -> Result<CoordinatorOutcome> {
        let token = bearer(token)?;
        let run_id = run_id_value(run_id)?;
        outcome(self.inner.inspect(&token, run_id).await)
    }

    #[napi(
        ts_args_type = "token: string, runId: import('./client').RunId, reason: string",
        ts_return_type = "Promise<import('./client').CoordinatorOutcome<import('./client').RunInspection>>"
    )]
    pub async fn reconcile(
        &self,
        token: String,
        run_id: String,
        reason: String,
    ) -> Result<CoordinatorOutcome> {
        let token = bearer(token)?;
        let run_id = run_id_value(run_id)?;
        outcome(self.inner.reconcile(&token, run_id, &reason).await)
    }
}

fn bearer(value: String) -> Result<BearerToken> {
    BearerToken::new(value)
        .map_err(|_| binding_error("invalid_request", "the bearer token is invalid"))
}

fn run_id_value(value: String) -> Result<Uuid> {
    Uuid::parse_str(&value).map_err(|_| {
        binding_error(
            "invalid_request",
            "Coordinator client arguments are invalid",
        )
    })
}

fn input<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    if contains_unsafe_integer(&value) {
        return Err(binding_error(
            "invalid_request",
            "Coordinator client arguments are invalid",
        ));
    }
    serde_json::from_value(value).map_err(|_| {
        binding_error(
            "invalid_request",
            "Coordinator client arguments are invalid",
        )
    })
}

fn outcome<T: Serialize>(
    value: std::result::Result<CoordinatorComplete<T>, CoordinatorClientError>,
) -> Result<CoordinatorOutcome> {
    let value = value.map_err(client_error)?;
    let serialized = serde_json::to_value(value.value)
        .map_err(|_| binding_error("protocol", "Coordinator result is not representable"))?;
    ensure_safe_integers(&serialized)?;
    Ok(CoordinatorOutcome {
        kind: "complete".into(),
        value: serialized,
    })
}

fn ensure_safe_integers(value: &Value) -> Result<()> {
    if contains_unsafe_integer(value) {
        return Err(binding_error(
            "protocol",
            "Coordinator returned an integer outside the JavaScript safe range",
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

fn client_error(error: CoordinatorClientError) -> NapiError {
    NapiError::from_reason(
        serde_json::to_string(&error_envelope(error)).unwrap_or_else(|_| {
            r#"{"kind":"protocol","message":"the failure could not be described","outcomeUnknown":true}"#.into()
        }),
    )
}

fn error_envelope(error: CoordinatorClientError) -> Value {
    let outcome_unknown = error.is_outcome_unknown();
    let mut envelope = match error {
        CoordinatorClientError::Configuration { .. } => json!({
            "kind": "configuration",
            "message": "Coordinator client configuration is invalid",
        }),
        CoordinatorClientError::InvalidRequest { .. } => json!({
            "kind": "invalid_request",
            "message": "Coordinator client arguments are invalid",
        }),
        CoordinatorClientError::Transport { kind } => json!({
            "kind": "transport",
            "transportKind": kind.kind(),
            "message": "Registry Coordinator exchange did not complete",
        }),
        CoordinatorClientError::Problem { status, code } => json!({
            "kind": "problem",
            "status": status,
            "code": code,
            "message": "Registry Coordinator refused the request",
        }),
        CoordinatorClientError::Protocol { status, failure } => json!({
            "kind": "protocol",
            "status": status,
            "protocolFailure": protocol_failure(failure),
            "message": "Registry Coordinator returned an invalid response",
        }),
        _ => json!({
            "kind": "protocol",
            "message": "Registry Coordinator client failed",
        }),
    };
    envelope["outcomeUnknown"] = Value::Bool(outcome_unknown);
    envelope
}

fn protocol_failure(failure: CoordinatorProtocolFailure) -> &'static str {
    match failure {
        CoordinatorProtocolFailure::HeaderBounds => "header_bounds",
        CoordinatorProtocolFailure::MediaType => "media_type",
        CoordinatorProtocolFailure::Body => "body",
        CoordinatorProtocolFailure::Problem => "problem",
        CoordinatorProtocolFailure::Status => "status",
        _ => "protocol",
    }
}

/// A failure detected in the binding. Only a protocol failure follows a
/// possible exchange, so only that category leaves the outcome unknown.
fn binding_error(kind: &'static str, message: &'static str) -> NapiError {
    NapiError::from_reason(
        json!({ "kind": kind, "message": message, "outcomeUnknown": kind == "protocol" })
            .to_string(),
    )
}

fn whole_number(value: f64) -> Result<u64> {
    if value.fract() == 0.0 && (0.0..=MAXIMUM_JAVASCRIPT_SAFE_INTEGER as f64).contains(&value) {
        Ok(value as u64)
    } else {
        Err(binding_error(
            "configuration",
            "Coordinator client configuration is invalid",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_response_integer_is_refused() {
        assert!(ensure_safe_integers(&json!(9_007_199_254_740_992_u64)).is_err());
    }

    #[test]
    fn configuration_counts_are_whole_numbers_in_the_safe_range() {
        assert_eq!(whole_number(1500.0).ok(), Some(1500));
        assert_eq!(whole_number(4_294_967_296.0).ok(), Some(4_294_967_296));
        for value in [-1.0, 1.5, 9_007_199_254_740_992.0, f64::NAN, f64::INFINITY] {
            assert!(whole_number(value).is_err(), "{value}");
        }
    }

    #[test]
    fn protocol_failures_use_the_public_snake_case_vocabulary() {
        assert_eq!(
            protocol_failure(CoordinatorProtocolFailure::HeaderBounds),
            "header_bounds"
        );
        assert_eq!(
            protocol_failure(CoordinatorProtocolFailure::MediaType),
            "media_type"
        );
        assert_eq!(protocol_failure(CoordinatorProtocolFailure::Body), "body");
        assert_eq!(
            protocol_failure(CoordinatorProtocolFailure::Problem),
            "problem"
        );
        assert_eq!(
            protocol_failure(CoordinatorProtocolFailure::Status),
            "status"
        );
    }
}

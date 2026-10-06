// SPDX-License-Identifier: Apache-2.0
//! Node.js binding for the canonical Registry Scheduling client.

#![deny(unsafe_code)]

use std::time::Duration;

use chrono::{DateTime, Utc};
use napi::{Error as NapiError, Result};
use napi_derive::napi;
use registry_scheduling_client::{
    AdmissionRequest, BearerToken, CancelAppointmentRequest, CreateAppointmentRequest,
    ExternalReference, RescheduleAppointmentRequest, SchedulingAuth,
    SchedulingClient as CoreClient, SchedulingClientConfig as CoreConfig, SchedulingClientError,
    SchedulingComplete, SchedulingProtocolFailure,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

const MAXIMUM_JAVASCRIPT_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const INVALID_ARGUMENTS: &str = "Scheduling client arguments are invalid";

#[napi(object)]
pub struct SchedulingClientConfig {
    pub base_url: String,
    pub request_timeout_milliseconds: Option<f64>,
    pub connect_timeout_milliseconds: Option<f64>,
    pub max_response_bytes: Option<f64>,
    pub user_agent: Option<String>,
    pub trusted_root_certificates: Option<String>,
    /// How many times a keyed command whose outcome is unknown is resent under
    /// the same idempotency key: 0 to 2, default 2, and 0 disables the resend.
    pub max_mutation_retries: Option<f64>,
}

#[napi(object)]
pub struct SchedulingOutcome {
    pub kind: String,
    pub value: Value,
    pub trace_id: String,
}

/// The optional availability bounds, with instants as RFC 3339 text.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AvailabilityQuery {
    start: Option<String>,
    end: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

/// The optional page bounds of an appointment listing.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageQuery {
    cursor: Option<String>,
    limit: Option<u32>,
}

#[napi(js_name = "SchedulingClient")]
pub struct SchedulingClient {
    inner: CoreClient,
}

#[napi]
impl SchedulingClient {
    #[napi(constructor)]
    pub fn new(config: SchedulingClientConfig) -> Result<Self> {
        let base_url = Url::parse(&config.base_url).map_err(|_| {
            binding_error(
                "configuration",
                "Scheduling client configuration is invalid",
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
        if let Some(value) = config.max_mutation_retries {
            core = core.with_max_mutation_retries(mutation_retries(value)?);
        }
        CoreClient::new(core)
            .map(|inner| Self { inner })
            .map_err(client_error)
    }

    #[napi]
    pub async fn get_scheduling(&self, token: String) -> Result<SchedulingOutcome> {
        let token = bearer(token)?;
        outcome(self.inner.get_scheduling(SchedulingAuth::new(&token)).await)
    }

    #[napi]
    pub async fn list_services(
        &self,
        token: String,
        cursor: Option<String>,
    ) -> Result<SchedulingOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .list_services(SchedulingAuth::new(&token), cursor.as_deref())
                .await,
        )
    }

    #[napi]
    pub async fn list_offerings(
        &self,
        token: String,
        cursor: Option<String>,
    ) -> Result<SchedulingOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .list_offerings(SchedulingAuth::new(&token), cursor.as_deref())
                .await,
        )
    }

    #[napi]
    pub async fn availability(
        &self,
        token: String,
        offering: String,
        query: Option<Value>,
    ) -> Result<SchedulingOutcome> {
        let token = bearer(token)?;
        let query: AvailabilityQuery = optional_input(query)?;
        let start = query.start.as_deref().map(instant).transpose()?;
        let end = query.end.as_deref().map(instant).transpose()?;
        outcome(
            self.inner
                .availability(
                    SchedulingAuth::new(&token),
                    &offering,
                    start,
                    end,
                    query.cursor.as_deref(),
                    query.limit,
                )
                .await,
        )
    }

    #[napi]
    pub async fn explain(
        &self,
        token: String,
        offering: String,
        start: String,
    ) -> Result<SchedulingOutcome> {
        let token = bearer(token)?;
        let start = instant(&start)?;
        outcome(
            self.inner
                .explain(SchedulingAuth::new(&token), &offering, start)
                .await,
        )
    }

    #[napi]
    pub async fn create_hold(
        &self,
        token: String,
        idempotency_key: String,
        request: Value,
    ) -> Result<SchedulingOutcome> {
        let token = bearer(token)?;
        let request: AdmissionRequest = input(request)?;
        outcome(
            self.inner
                .create_hold(SchedulingAuth::new(&token), &idempotency_key, &request)
                .await,
        )
    }

    #[napi]
    pub async fn release_hold(&self, token: String, hold_id: String) -> Result<SchedulingOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .release_hold(SchedulingAuth::new(&token), &hold_id)
                .await,
        )
    }

    #[napi]
    pub async fn create_appointment(
        &self,
        token: String,
        idempotency_key: String,
        request: Value,
    ) -> Result<SchedulingOutcome> {
        let token = bearer(token)?;
        let request: CreateAppointmentRequest = input(request)?;
        outcome(
            self.inner
                .create_appointment(SchedulingAuth::new(&token), &idempotency_key, &request)
                .await,
        )
    }

    #[napi]
    pub async fn get_appointment(
        &self,
        token: String,
        appointment_id: String,
    ) -> Result<SchedulingOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .get_appointment(SchedulingAuth::new(&token), &appointment_id)
                .await,
        )
    }

    #[napi]
    pub async fn list_appointments(
        &self,
        token: String,
        reference: Value,
        page: Option<Value>,
    ) -> Result<SchedulingOutcome> {
        let token = bearer(token)?;
        let reference: ExternalReference = input(reference)?;
        let page: PageQuery = optional_input(page)?;
        outcome(
            self.inner
                .list_appointments(
                    SchedulingAuth::new(&token),
                    &reference,
                    page.cursor.as_deref(),
                    page.limit,
                )
                .await,
        )
    }

    #[napi]
    pub async fn reschedule_appointment(
        &self,
        token: String,
        appointment_id: String,
        idempotency_key: String,
        request: Value,
    ) -> Result<SchedulingOutcome> {
        let token = bearer(token)?;
        let request: RescheduleAppointmentRequest = input(request)?;
        outcome(
            self.inner
                .reschedule_appointment(
                    SchedulingAuth::new(&token),
                    &appointment_id,
                    &idempotency_key,
                    &request,
                )
                .await,
        )
    }

    #[napi]
    pub async fn cancel_appointment(
        &self,
        token: String,
        appointment_id: String,
        idempotency_key: String,
        request: Value,
    ) -> Result<SchedulingOutcome> {
        let token = bearer(token)?;
        let request: CancelAppointmentRequest = input(request)?;
        outcome(
            self.inner
                .cancel_appointment(
                    SchedulingAuth::new(&token),
                    &appointment_id,
                    &idempotency_key,
                    &request,
                )
                .await,
        )
    }

    #[napi]
    pub async fn appointment_history(
        &self,
        token: String,
        appointment_id: String,
        cursor: Option<String>,
    ) -> Result<SchedulingOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .appointment_history(
                    SchedulingAuth::new(&token),
                    &appointment_id,
                    cursor.as_deref(),
                )
                .await,
        )
    }

    #[napi]
    pub async fn list_resources(
        &self,
        token: String,
        cursor: Option<String>,
    ) -> Result<SchedulingOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .list_resources(SchedulingAuth::new(&token), cursor.as_deref())
                .await,
        )
    }

    #[napi]
    pub async fn list_locations(
        &self,
        token: String,
        cursor: Option<String>,
    ) -> Result<SchedulingOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .list_locations(SchedulingAuth::new(&token), cursor.as_deref())
                .await,
        )
    }
}

fn bearer(value: String) -> Result<BearerToken> {
    BearerToken::new(value)
        .map_err(|_| binding_error("invalid_request", "the bearer token is invalid"))
}

/// One RFC 3339 instant, normalized to UTC.
fn instant(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|_| binding_error("invalid_request", INVALID_ARGUMENTS))
}

fn input<T: DeserializeOwned>(value: Value) -> Result<T> {
    if contains_unsafe_integer(&value) {
        return Err(binding_error("invalid_request", INVALID_ARGUMENTS));
    }
    serde_json::from_value(value).map_err(|_| binding_error("invalid_request", INVALID_ARGUMENTS))
}

fn optional_input<T: DeserializeOwned + Default>(value: Option<Value>) -> Result<T> {
    value.map_or_else(|| Ok(T::default()), input)
}

fn outcome<T: Serialize>(
    value: std::result::Result<SchedulingComplete<T>, SchedulingClientError>,
) -> Result<SchedulingOutcome> {
    let value = value.map_err(client_error)?;
    let serialized = serde_json::to_value(value.value)
        .map_err(|_| binding_error("protocol", "Scheduling result is not representable"))?;
    ensure_safe_integers(&serialized)?;
    Ok(SchedulingOutcome {
        kind: "complete".into(),
        value: serialized,
        trace_id: value.trace_id,
    })
}

fn ensure_safe_integers(value: &Value) -> Result<()> {
    if contains_unsafe_integer(value) {
        return Err(binding_error(
            "protocol",
            "Scheduling returned an integer outside the JavaScript safe range",
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

fn client_error(error: SchedulingClientError) -> NapiError {
    NapiError::from_reason(
        serde_json::to_string(&error_envelope(error)).unwrap_or_else(|_| {
            r#"{"kind":"protocol","message":"the failure could not be described","outcomeUnknown":true}"#.into()
        }),
    )
}

fn error_envelope(error: SchedulingClientError) -> Value {
    let outcome_unknown = error.is_outcome_unknown();
    let mut envelope = match error {
        SchedulingClientError::Configuration { .. } => json!({
            "kind": "configuration",
            "message": "Scheduling client configuration is invalid",
        }),
        SchedulingClientError::InvalidRequest { .. } => json!({
            "kind": "invalid_request",
            "message": INVALID_ARGUMENTS,
        }),
        SchedulingClientError::Transport { kind } => json!({
            "kind": "transport",
            "transportKind": kind.kind(),
            "message": "Registry Scheduling exchange did not complete",
        }),
        SchedulingClientError::Problem {
            status,
            code,
            trace_id,
        } => json!({
            "kind": "problem",
            "status": status,
            "code": code.code(),
            "traceId": trace_id,
            "title": code.title(),
            "detail": code.detail(),
            "message": code.detail(),
        }),
        SchedulingClientError::Protocol {
            status,
            failure,
            trace_id,
        } => json!({
            "kind": "protocol",
            "status": status,
            "protocolFailure": protocol_failure(failure),
            "traceId": trace_id,
            "message": "Registry Scheduling returned an invalid response",
        }),
        _ => json!({
            "kind": "protocol",
            "message": "Registry Scheduling client failed",
        }),
    };
    envelope["outcomeUnknown"] = Value::Bool(outcome_unknown);
    envelope
}

fn protocol_failure(failure: SchedulingProtocolFailure) -> &'static str {
    match failure {
        SchedulingProtocolFailure::HeaderBounds => "header_bounds",
        SchedulingProtocolFailure::TraceContext => "trace_context",
        SchedulingProtocolFailure::MediaType => "media_type",
        SchedulingProtocolFailure::Body => "body",
        SchedulingProtocolFailure::Problem => "problem",
        SchedulingProtocolFailure::Status => "status",
        _ => "protocol",
    }
}

/// A failure the binding detects itself. Only a protocol failure follows an
/// exchange, a result the binding cannot represent, so only it leaves the
/// outcome unknown.
fn binding_error(kind: &'static str, message: &'static str) -> NapiError {
    NapiError::from_reason(
        json!({ "kind": kind, "message": message, "outcomeUnknown": kind == "protocol" })
            .to_string(),
    )
}

/// A millisecond or byte count as a JavaScript number. Only a whole number in
/// the safe integer range reaches the client, which applies its own bounds; a
/// 32-bit conversion would wrap a negative, fractional, or larger number.
fn whole_number(value: f64) -> Result<u64> {
    if value.fract() == 0.0 && (0.0..=MAXIMUM_JAVASCRIPT_SAFE_INTEGER as f64).contains(&value) {
        Ok(value as u64)
    } else {
        Err(binding_error(
            "configuration",
            "Scheduling client configuration is invalid",
        ))
    }
}

/// The retry ceiling as a JavaScript number. Only a whole number in the
/// `u8` range reaches the client, which refuses one above its own bound.
fn mutation_retries(value: f64) -> Result<u8> {
    if value.fract() == 0.0 && (0.0..=f64::from(u8::MAX)).contains(&value) {
        Ok(value as u8)
    } else {
        Err(binding_error(
            "configuration",
            "Scheduling client configuration is invalid",
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
        assert_eq!(
            whole_number(MAXIMUM_JAVASCRIPT_SAFE_INTEGER as f64).ok(),
            Some(MAXIMUM_JAVASCRIPT_SAFE_INTEGER as u64)
        );
        for value in [-1.0, 1.5, 9_007_199_254_740_992.0, f64::NAN, f64::INFINITY] {
            assert!(whole_number(value).is_err(), "{value}");
        }
    }

    #[test]
    fn instants_are_rfc_3339_normalized_to_utc() {
        let parsed = instant("2026-10-05T12:00:00+03:00").expect("an RFC 3339 instant");
        assert_eq!(parsed.to_rfc3339(), "2026-10-05T09:00:00+00:00");
        assert!(instant("2026-10-05").is_err());
        assert!(instant("tomorrow").is_err());
    }

    #[test]
    fn query_objects_refuse_an_undeclared_member() {
        assert!(optional_input::<AvailabilityQuery>(Some(json!({ "offering": "x" }))).is_err());
        assert!(optional_input::<PageQuery>(Some(json!({ "limit": -1 }))).is_err());
        assert!(optional_input::<PageQuery>(None).is_ok());
    }

    #[test]
    fn protocol_failures_use_the_public_snake_case_vocabulary() {
        assert_eq!(
            protocol_failure(SchedulingProtocolFailure::HeaderBounds),
            "header_bounds"
        );
        assert_eq!(
            protocol_failure(SchedulingProtocolFailure::TraceContext),
            "trace_context"
        );
        assert_eq!(
            protocol_failure(SchedulingProtocolFailure::MediaType),
            "media_type"
        );
        assert_eq!(protocol_failure(SchedulingProtocolFailure::Body), "body");
        assert_eq!(
            protocol_failure(SchedulingProtocolFailure::Problem),
            "problem"
        );
        assert_eq!(
            protocol_failure(SchedulingProtocolFailure::Status),
            "status"
        );
    }
}

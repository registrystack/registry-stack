// SPDX-License-Identifier: Apache-2.0
//! Environment-free product fixture execution over compiled Relay plans.
//!
//! This surface accepts only caller-owned observations. It has no transport,
//! credential, policy, filesystem, or configurable callback capability.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::fmt;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use registry_platform_httputil::destination::json::{
    decode_script_fixture_json, decode_script_fixture_text, ClosedJsonDecodeError,
    ClosedJsonOutcome, ProjectedJsonScalar,
};
use registry_platform_httputil::destination::signed_dci::{
    SignedDciDecodeError, SignedDciDecoder, SignedDciExactComponent, SignedDciExpectation,
};
use registry_platform_httputil::destination::ScriptRequestBodyFormat;
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::rhai_worker::{
    HostFailure, OutputSchema as RhaiOutputSchema, OutputType as RhaiOutputType, ScriptFailure,
    SourceCall, SourceHost, SourceResponse, TypedValue as RhaiTypedValue, WorkerLimits,
    WorkerOutcome, WorkerOutput, WorkerProcess, WorkerRequest,
};
use crate::source_backend::decode_snapshot_rows;
use crate::source_plan::{
    CompiledInputType, CompiledInputValue, CompiledRhaiOutputType, CompiledSourcePlan,
    CompiledSourcePlanRegistry, CompiledStatusOutcome, SourcePlanArtifactBundle,
    SourcePlanCompileError, SourcePlanKind,
};

use super::executor::{
    is_anchor_execution_step, validate_bounded_http_activation, validate_snapshot_exact_activation,
};
use super::response::ValidatedOutputMap;
use super::types::ParsedConsultationScalar;
use super::ConsultationOutcome;

const DCI_FIXTURE_MESSAGE_ID: &str = "01JZ0000000000000000000000";

/// Exact public profile pin required for every offline fixture execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineProfilePin {
    pub id: String,
    pub version: u64,
    pub contract_hash: String,
}

/// One caller-owned source observation. No variant can initiate source access.
#[derive(Clone, PartialEq)]
pub enum OfflineSourceResponse {
    Http {
        status: u16,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    },
    DeclaredBodyBytes {
        status: u16,
        body_bytes: u64,
    },
    Timeout,
    CredentialSuccess,
    NoMatch,
    Unavailable,
}

impl fmt::Debug for OfflineSourceResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http { status, body, .. } => formatter
                .debug_struct("Http")
                .field("status", status)
                .field("body_bytes", &body.len())
                .finish(),
            Self::DeclaredBodyBytes { status, body_bytes } => formatter
                .debug_struct("DeclaredBodyBytes")
                .field("status", status)
                .field("body_bytes", body_bytes)
                .finish(),
            Self::Timeout => formatter.write_str("Timeout"),
            Self::CredentialSuccess => formatter.write_str("CredentialSuccess"),
            Self::NoMatch => formatter.write_str("NoMatch"),
            Self::Unavailable => formatter.write_str("Unavailable"),
        }
    }
}

/// Synthetic request expectation paired with one caller-owned response.
#[derive(Clone, PartialEq)]
pub struct OfflineInteraction {
    pub request: OfflineExpectedRequest,
    pub response: OfflineSourceResponse,
}

impl fmt::Debug for OfflineInteraction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineInteraction")
            .field("method", &self.request.method)
            .field("path", &"[SYNTHETIC]")
            .field("query_count", &self.request.query.len())
            .field("header_count", &self.request.headers.len())
            .field("has_body", &self.request.body.is_some())
            .field("response", &self.response)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineRequestMethod {
    Get,
    Post,
}

/// Exact synthetic method, relative target components, and body shape.
#[derive(Clone, PartialEq)]
pub struct OfflineExpectedRequest {
    pub method: OfflineRequestMethod,
    pub path: String,
    pub query: BTreeMap<String, Value>,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Value>,
}

impl fmt::Debug for OfflineExpectedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineExpectedRequest")
            .field("method", &self.method)
            .field("path", &"[SYNTHETIC]")
            .field("query_count", &self.query.len())
            .field("header_count", &self.headers.len())
            .field("has_body", &self.body.is_some())
            .finish()
    }
}

/// Closed fixture input for one exact compiled profile.
#[derive(Clone, PartialEq)]
pub struct OfflineFixtureRequest {
    pub profile: OfflineProfilePin,
    pub input: BTreeMap<String, String>,
    pub interactions: Vec<OfflineInteraction>,
}

impl fmt::Debug for OfflineFixtureRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineFixtureRequest")
            .field("profile", &self.profile)
            .field("input_slots", &self.input.keys().collect::<Vec<_>>())
            .field("interaction_count", &self.interactions.len())
            .finish()
    }
}

/// Public consultation outcome observed through the production decoder path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineFixtureOutcome {
    Match,
    NoMatch,
    Ambiguous,
}

/// Value-minimized result. Raw records and source response bytes never escape.
#[derive(Debug, Clone, PartialEq)]
pub struct OfflineFixtureObservation {
    pub outcome: OfflineFixtureOutcome,
    pub outputs: BTreeMap<String, Value>,
    pub calls: Vec<String>,
}

/// Stable, value-free fixture failure classes aligned with production failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OfflineFixtureError {
    #[error("fixture profile pin does not select one exact compiled plan")]
    ProfileNotFound,
    #[error("fixture input violates the compiled contract")]
    InvalidInput,
    #[error("fixture names a source operation outside the compiled plan")]
    UnknownSourceOperation,
    #[error("fixture omits an observed source operation")]
    MissingSourceObservation,
    #[error("fixture expected request does not match the rendered request or call order")]
    RequestMismatch,
    #[error("fixture source deadline was exceeded")]
    SourceDeadlineExceeded,
    #[error("fixture source is unavailable")]
    SourceUnavailable,
    #[error("fixture source status was rejected")]
    SourceStatusRejected,
    #[error("fixture source response exceeded its bound")]
    SourceResponseTooLarge,
    #[error("fixture source response violated its closed contract")]
    SourceResponseMalformed,
    #[error("fixture source cardinality contract was violated")]
    SourceCardinalityViolation,
    #[error("fixture source echoed a different subject identifier")]
    SubjectMismatch,
    #[error("fixture execution violated the compiled plan")]
    ExecutionContractViolation,
}

/// Immutable offline harness compiled with the exact runtime source-plan compiler.
pub struct OfflineRelayFixture {
    plans: CompiledSourcePlanRegistry,
    rhai_worker_program: Option<PathBuf>,
}

impl OfflineRelayFixture {
    pub fn compile(bundle: &SourcePlanArtifactBundle<'_>) -> Result<Self, SourcePlanCompileError> {
        Ok(Self {
            plans: CompiledSourcePlanRegistry::compile_for_authoring_validation(bundle)?,
            rhai_worker_program: None,
        })
    }

    /// Compile the fixture closure and launch Rhai through an executable that
    /// embeds Relay's exact hidden worker mode. Registry project authoring uses
    /// this to remain self-contained instead of depending on an ambient Relay
    /// installation.
    pub fn compile_with_worker_program(
        bundle: &SourcePlanArtifactBundle<'_>,
        program: impl Into<PathBuf>,
    ) -> Result<Self, SourcePlanCompileError> {
        Ok(Self {
            plans: CompiledSourcePlanRegistry::compile_for_authoring_validation(bundle)?,
            rhai_worker_program: Some(program.into()),
        })
    }

    pub fn execute(
        &self,
        request: OfflineFixtureRequest,
    ) -> Result<OfflineFixtureObservation, OfflineFixtureError> {
        self.execute_inner(request, false)
    }

    /// Execute the exact same closed fixture while returning a deterministic,
    /// value-free description of each rendered interaction in `calls`.
    pub fn execute_with_trace(
        &self,
        request: OfflineFixtureRequest,
    ) -> Result<OfflineFixtureObservation, OfflineFixtureError> {
        self.execute_inner(request, true)
    }

    fn execute_inner(
        &self,
        request: OfflineFixtureRequest,
        trace: bool,
    ) -> Result<OfflineFixtureObservation, OfflineFixtureError> {
        let plan = self
            .plans
            .iter()
            .find(|plan| {
                plan.profile().id().as_str() == request.profile.id
                    && plan.profile().version().get() == request.profile.version
                    && plan.profile().contract_hash().as_str() == request.profile.contract_hash
            })
            .ok_or(OfflineFixtureError::ProfileNotFound)?;
        let inputs = OfflineBoundInputs::try_new(plan, request.input)?;
        match plan.kind() {
            SourcePlanKind::SnapshotExact => {
                execute_snapshot(plan, &inputs, request.interactions, trace)
            }
            SourcePlanKind::BoundedHttp => execute_http(plan, &inputs, request.interactions, trace),
            SourcePlanKind::Script => execute_rhai(
                plan,
                &inputs,
                request.interactions,
                self.rhai_worker_program.as_deref(),
                trace,
            ),
        }
    }
}

/// Production-equivalent sealed selector capability for the offline runner.
///
/// Values remain in their zeroizing compiled owners. This type deliberately
/// implements neither `Clone` nor `Debug`, and exposes values only by compiled
/// slot index to the closed fixture executors below.
struct OfflineBoundInputs {
    values: Box<[CompiledInputValue]>,
}

struct OfflineInteractionQueue {
    interactions: VecDeque<OfflineInteraction>,
    calls: Vec<String>,
    trace: bool,
}

impl OfflineInteractionQueue {
    fn new(
        interactions: Vec<OfflineInteraction>,
        trace: bool,
    ) -> Result<Self, OfflineFixtureError> {
        if interactions.is_empty() || interactions.len() > 16 {
            return Err(OfflineFixtureError::RequestMismatch);
        }
        Ok(Self {
            interactions: interactions.into(),
            calls: Vec::new(),
            trace,
        })
    }

    fn take(
        &mut self,
        operation: &str,
        canonical_path: &str,
        actual: &OfflineRenderedRequest,
    ) -> Result<OfflineSourceResponse, OfflineFixtureError> {
        let interaction = self
            .interactions
            .pop_front()
            .ok_or(OfflineFixtureError::MissingSourceObservation)?;
        if !offline_request_matches(&interaction.request, actual) {
            return Err(OfflineFixtureError::RequestMismatch);
        }
        self.calls.push(if self.trace {
            safe_interaction_trace(self.calls.len() + 1, operation, canonical_path, actual)
        } else {
            operation.to_owned()
        });
        Ok(interaction.response)
    }

    fn finish(self) -> Result<Vec<String>, OfflineFixtureError> {
        if !self.interactions.is_empty() {
            return Err(OfflineFixtureError::RequestMismatch);
        }
        Ok(self.calls)
    }
}

fn safe_interaction_trace(
    call_order: usize,
    operation: &str,
    canonical_path: &str,
    request: &OfflineRenderedRequest,
) -> String {
    let method = match request.method {
        OfflineRequestMethod::Get => "GET",
        OfflineRequestMethod::Post => "POST",
    };
    let query = request.query.keys().cloned().collect::<Vec<_>>().join(",");
    let mut headers = request
        .headers
        .keys()
        .map(|name| name.to_ascii_lowercase())
        .collect::<Vec<_>>();
    headers.sort_unstable();
    headers.dedup();
    let body = request
        .body
        .as_ref()
        .map_or_else(|| "none".to_string(), |body| safe_json_shape(body, 0));
    format!(
        "call={call_order} operation={operation} method={method} path={canonical_path} query=[{query}] headers=[{}] body={body}",
        headers.join(",")
    )
}

fn safe_json_shape(value: &Value, depth: usize) -> String {
    const MAX_TRACE_DEPTH: usize = 4;
    if depth >= MAX_TRACE_DEPTH {
        return "nested".to_string();
    }
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(_) => "boolean".to_string(),
        Value::Number(_) => "number".to_string(),
        Value::String(_) => "string".to_string(),
        Value::Array(values) => {
            let mut shapes = values
                .iter()
                .map(|value| safe_json_shape(value, depth + 1))
                .collect::<Vec<_>>();
            shapes.sort_unstable();
            shapes.dedup();
            format!("array(len={};items=[{}])", values.len(), shapes.join(","))
        }
        Value::Object(values) => {
            let mut shapes = values
                .values()
                .map(|value| safe_json_shape(value, depth + 1))
                .collect::<Vec<_>>();
            shapes.sort_unstable();
            shapes.dedup();
            format!(
                "object(fields={};values=[{}])",
                values.len(),
                shapes.join(",")
            )
        }
    }
}

struct OfflineRenderedRequest {
    method: OfflineRequestMethod,
    path: String,
    query: BTreeMap<String, Vec<String>>,
    headers: BTreeMap<String, String>,
    body: Option<Value>,
}

fn offline_request_matches(
    expected: &OfflineExpectedRequest,
    actual: &OfflineRenderedRequest,
) -> bool {
    if expected.method != actual.method
        || expected.path != actual.path
        || expected.headers.len() != actual.headers.len()
        || expected.headers.iter().any(|(name, value)| {
            actual
                .headers
                .iter()
                .find(|(actual, _)| actual.eq_ignore_ascii_case(name))
                .is_none_or(|(_, actual)| actual != value)
        })
    {
        return false;
    }
    let expected_query = expected
        .query
        .iter()
        .map(|(name, value)| fixture_query_values(value).map(|values| (name.clone(), values)))
        .collect::<Option<BTreeMap<_, _>>>();
    expected_query.as_ref() == Some(&actual.query)
        && match (&expected.body, &actual.body) {
            (None, None) => true,
            (Some(expected), Some(actual)) => fixture_value_matches(expected, actual),
            _ => false,
        }
}

fn fixture_query_values(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::Array(values) => values.iter().map(fixture_scalar_text).collect(),
        _ => fixture_scalar_text(value).map(|value| vec![value]),
    }
}

fn fixture_scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("null".to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::String(value) => Some(value.clone()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

fn fixture_value_matches(expected: &Value, actual: &Value) -> bool {
    if let Some(object) = expected
        .as_object()
        .filter(|object| object.contains_key("generated"))
    {
        let Some(generated) = object
            .get("generated")
            .filter(|_| object.len() == 1)
            .and_then(Value::as_str)
        else {
            return false;
        };
        return match generated {
            "dci-correlation" => actual.as_str().is_some_and(|value| {
                ulid::Ulid::from_string(value).is_ok_and(|parsed| parsed.to_string() == value)
            }),
            "rfc3339-timestamp" => actual.as_str().is_some_and(|value| {
                value.len() <= 64
                    && time::OffsetDateTime::parse(
                        value,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .is_ok()
            }),
            _ => false,
        };
    }
    match (expected, actual) {
        (Value::Array(expected), Value::Array(actual)) => {
            expected.len() == actual.len()
                && expected
                    .iter()
                    .zip(actual)
                    .all(|(expected, actual)| fixture_value_matches(expected, actual))
        }
        (Value::Object(expected), Value::Object(actual)) => {
            expected.len() == actual.len()
                && expected.iter().all(|(name, expected)| {
                    actual
                        .get(name)
                        .is_some_and(|actual| fixture_value_matches(expected, actual))
                })
        }
        _ => expected == actual,
    }
}

impl OfflineBoundInputs {
    fn try_new(
        plan: &CompiledSourcePlan,
        mut raw: BTreeMap<String, String>,
    ) -> Result<Self, OfflineFixtureError> {
        let slot_count = plan.inputs().len();
        if !(1..=16).contains(&slot_count) || raw.len() != slot_count {
            return Err(OfflineFixtureError::InvalidInput);
        }
        let slots = plan.inputs().collect::<Vec<_>>();
        if slots
            .windows(2)
            .any(|pair| pair[0].name().as_bytes() >= pair[1].name().as_bytes())
        {
            return Err(OfflineFixtureError::InvalidInput);
        }
        let values = slots
            .into_iter()
            .enumerate()
            .map(|(index, slot)| {
                let candidate = raw
                    .remove(slot.name())
                    .ok_or(OfflineFixtureError::InvalidInput)?;
                let parsed = match slot.input_type() {
                    CompiledInputType::String | CompiledInputType::FullDate => {
                        ParsedConsultationScalar::String(Zeroizing::new(candidate))
                    }
                    CompiledInputType::Boolean => match candidate.as_str() {
                        "true" => ParsedConsultationScalar::Boolean(true),
                        "false" => ParsedConsultationScalar::Boolean(false),
                        "null" if slot.nullable() => ParsedConsultationScalar::Null,
                        _ => return Err(OfflineFixtureError::InvalidInput),
                    },
                    CompiledInputType::Integer => match candidate.parse::<i64>() {
                        Ok(value) => ParsedConsultationScalar::Integer(value),
                        Err(_) if candidate == "null" && slot.nullable() => {
                            ParsedConsultationScalar::Null
                        }
                        Err(_) => return Err(OfflineFixtureError::InvalidInput),
                    },
                };
                let value = slot
                    .canonicalize_and_validate(&parsed)
                    .ok_or(OfflineFixtureError::InvalidInput)?;
                value
                    .binding_matches(
                        plan.profile().contract_hash(),
                        slot.name(),
                        index,
                        slot.input_type(),
                    )
                    .then_some(value)
                    .ok_or(OfflineFixtureError::InvalidInput)
            })
            .collect::<Result<Box<[_]>, _>>()?;
        if !raw.is_empty() {
            return Err(OfflineFixtureError::InvalidInput);
        }
        Ok(Self { values })
    }

    fn get(&self, index: usize) -> Result<&CompiledInputValue, OfflineFixtureError> {
        self.values
            .get(index)
            .ok_or(OfflineFixtureError::ExecutionContractViolation)
    }

    fn iter(&self) -> impl ExactSizeIterator<Item = &CompiledInputValue> {
        self.values.iter()
    }

    fn is_bound_to(&self, plan: &CompiledSourcePlan) -> bool {
        self.values.len() == plan.inputs().len()
            && plan.inputs().enumerate().all(|(index, slot)| {
                self.values.get(index).is_some_and(|value| {
                    value.binding_matches(
                        plan.profile().contract_hash(),
                        slot.name(),
                        index,
                        slot.input_type(),
                    )
                })
            })
    }
}

struct OperationMemory {
    prior_outputs: Vec<ProjectedJsonScalar>,
    present: bool,
}

struct OfflineRhaiHost<'a> {
    plan: &'a CompiledSourcePlan,
    interactions: OfflineInteractionQueue,
    credential_used: bool,
    request_bytes: u64,
    source_bytes: u64,
    terminal_error: Option<OfflineFixtureError>,
}

#[async_trait]
impl SourceHost for OfflineRhaiHost<'_> {
    async fn call(&mut self, call: SourceCall) -> Result<SourceResponse, HostFailure> {
        if let SourceCall::DciSearch { options, .. } = call {
            return match self.call_dci(options) {
                Ok(response) => Ok(response),
                Err(error) => {
                    self.terminal_error = Some(error);
                    Err(match error {
                        OfflineFixtureError::SourceDeadlineExceeded
                        | OfflineFixtureError::SourceUnavailable
                        | OfflineFixtureError::SourceStatusRejected => {
                            HostFailure::SourceUnavailable
                        }
                        OfflineFixtureError::SourceResponseTooLarge => HostFailure::BudgetExceeded,
                        _ => HostFailure::ContractViolation,
                    })
                }
            };
        }
        if !super::executor::generic_script_source_calls_allowed(self.plan) {
            // Mirror production: only the verified protocol helper may use a
            // signed DCI authority. Raw generic responses never reach Rhai.
            return Err(HostFailure::ContractViolation);
        }
        let (method, target, query, headers, body_format, body) = match &call {
            SourceCall::Get {
                target, options, ..
            } => (
                crate::source_plan::ReadMethod::Get,
                target.as_str(),
                &options.query,
                &options.headers,
                None,
                None,
            ),
            SourceCall::PostJson {
                target,
                body,
                options,
                ..
            } => (
                crate::source_plan::ReadMethod::ReadOnlyPost,
                target.as_str(),
                &options.query,
                &options.headers,
                Some(ScriptRequestBodyFormat::Json),
                Some(body.clone()),
            ),
            SourceCall::PostForm {
                target,
                fields,
                options,
                ..
            } => (
                crate::source_plan::ReadMethod::ReadOnlyPost,
                target.as_str(),
                &options.query,
                &options.headers,
                Some(ScriptRequestBodyFormat::Form),
                Some(Value::Object(fields.clone().into_iter().collect())),
            ),
            SourceCall::DciSearch { .. } => unreachable!("handled above"),
        };
        let target = self
            .plan
            .data_destination()
            .ok_or(HostFailure::ContractViolation)?
            .canonicalize_same_origin_target(target)
            .map_err(|_| HostFailure::ContractViolation)?;
        let actual = rendered_script_request(method, &target, query, headers, body.clone())
            .map_err(|_| HostFailure::ContractViolation)?;
        let canonical_target = super::executor::canonical_rhai_target(&target, query.clone())?;
        let header_names = headers.keys().map(String::as_str).collect::<Vec<_>>();
        let authority = self
            .plan
            .script_authority()
            .ok_or(HostFailure::ContractViolation)?;
        let rules = authority
            .allow()
            .filter(|rule| {
                rule.method() == method
                    && rule
                        .transport_template()
                        .validate_script_request_shape(
                            &canonical_target,
                            &header_names,
                            body_format,
                        )
                        .is_ok()
            })
            .collect::<Vec<_>>();
        let [rule] = rules.as_slice() else {
            return Err(HostFailure::ContractViolation);
        };
        let encoded_body_bytes = match (body_format, body.as_ref()) {
            (Some(ScriptRequestBodyFormat::Json), Some(body)) => serde_json::to_vec(body)
                .map_err(|_| HostFailure::ContractViolation)?
                .len(),
            (Some(ScriptRequestBodyFormat::Form), Some(Value::Object(fields))) => {
                super::executor::encode_rhai_form(
                    fields
                        .iter()
                        .map(|(name, value)| (name.clone(), value.clone()))
                        .collect(),
                )?
                .len()
            }
            (None, None) => 0,
            _ => return Err(HostFailure::ContractViolation),
        };
        let authored_bytes = canonical_target
            .len()
            .checked_add(
                headers
                    .iter()
                    .try_fold(0_usize, |total, (name, value)| {
                        total.checked_add(name.len())?.checked_add(value.len())
                    })
                    .ok_or(HostFailure::BudgetExceeded)?,
            )
            .and_then(|total| total.checked_add(encoded_body_bytes))
            .and_then(|total| u64::try_from(total).ok())
            .ok_or(HostFailure::BudgetExceeded)?;
        self.request_bytes = self
            .request_bytes
            .checked_add(authored_bytes)
            .filter(|total| *total <= u64::from(authority.request_max_bytes()))
            .ok_or(HostFailure::BudgetExceeded)?;
        if !self.credential_used {
            if let Some(credential) = self.plan.credential_operation() {
                let credential_request = rendered_credential_request_effect(
                    credential
                        .render_request(
                            Zeroizing::new(b"synthetic-client".to_vec()),
                            Zeroizing::new(b"synthetic-secret".to_vec()),
                        )
                        .map_err(|_| HostFailure::ContractViolation)?,
                )
                .map_err(|_| HostFailure::ContractViolation)?;
                let observed = match self.interactions.take(
                    credential.id().as_str(),
                    credential_request.path.as_str(),
                    &credential_request,
                ) {
                    Ok(observed) => observed,
                    Err(error) => {
                        self.terminal_error = Some(error);
                        return Err(HostFailure::SourceAuth);
                    }
                };
                require_basic_success(observed, 64 * 1024).map_err(|_| HostFailure::SourceAuth)?;
                self.credential_used = true;
            }
        }
        let observed =
            match self
                .interactions
                .take("script-source-call", rule.audit_path(), &actual)
            {
                Ok(observed) => observed,
                Err(error) => {
                    self.terminal_error = Some(error);
                    return Err(HostFailure::ContractViolation);
                }
            };
        match observed {
            OfflineSourceResponse::Http {
                status,
                headers,
                body,
            } => {
                match status {
                    401 | 403 => return Err(HostFailure::SourceAuth),
                    429 => return Err(HostFailure::SourceRateLimited),
                    _ => {}
                }
                let encoded_bytes =
                    u64::try_from(body.len()).map_err(|_| HostFailure::BudgetExceeded)?;
                self.source_bytes = self
                    .source_bytes
                    .checked_add(encoded_bytes)
                    .filter(|total| {
                        *total <= self.plan.limits().operation().max_source_bytes
                            && encoded_bytes <= u64::from(authority.response_max_bytes())
                    })
                    .ok_or(HostFailure::BudgetExceeded)?;
                let decoded = match authority.response_format() {
                    crate::source_plan::CompiledResponseFormat::Json => {
                        decode_script_fixture_json(body).map(|decoded| decoded.into_parts().0)
                    }
                    crate::source_plan::CompiledResponseFormat::Text => {
                        decode_script_fixture_text(body)
                            .map(|decoded| Value::String(decoded.into_parts().0.to_string()))
                    }
                };
                let body = match decoded {
                    Ok(body) => body,
                    Err(_) => {
                        self.terminal_error = Some(OfflineFixtureError::SourceResponseMalformed);
                        return Err(HostFailure::ContractViolation);
                    }
                };
                let selected_headers = authority
                    .response_headers()
                    .map(|name| (name.to_owned(), headers.get(name).cloned()))
                    .collect();
                Ok(SourceResponse {
                    status,
                    body,
                    headers: selected_headers,
                })
            }
            OfflineSourceResponse::NoMatch => Ok(SourceResponse {
                status: 404,
                body: Value::Null,
                headers: BTreeMap::new(),
            }),
            OfflineSourceResponse::Timeout => {
                self.terminal_error = Some(OfflineFixtureError::SourceDeadlineExceeded);
                Err(HostFailure::SourceUnavailable)
            }
            OfflineSourceResponse::Unavailable => Err(HostFailure::SourceUnavailable),
            OfflineSourceResponse::DeclaredBodyBytes { .. } => {
                self.terminal_error = Some(OfflineFixtureError::SourceResponseTooLarge);
                Err(HostFailure::BudgetExceeded)
            }
            OfflineSourceResponse::CredentialSuccess => Err(HostFailure::ContractViolation),
        }
    }
}

impl OfflineRhaiHost<'_> {
    fn call_dci(
        &mut self,
        options: crate::rhai_worker::DciSearchOptions,
    ) -> Result<SourceResponse, OfflineFixtureError> {
        if !options.parameters.is_empty() {
            return Err(OfflineFixtureError::ExecutionContractViolation);
        }
        let authored_request_bytes = u64::try_from(
            serde_json::to_vec(&options)
                .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?
                .len(),
        )
        .map_err(|_| OfflineFixtureError::SourceResponseTooLarge)?;
        let authority = self
            .plan
            .script_authority()
            .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
        let dci = authority
            .signed_dci()
            .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
        self.request_bytes = self
            .request_bytes
            .checked_add(authored_request_bytes)
            .filter(|total| *total <= u64::from(dci.request_max_bytes()))
            .ok_or(OfflineFixtureError::SourceResponseTooLarge)?;
        let components = match dci.selector() {
            crate::source_plan::CompiledDciSelector::ExactAnd { components, .. } => components,
        };
        let expected_names = components
            .iter()
            .map(|component| {
                self.plan
                    .inputs()
                    .nth(component.input_index())
                    .map(|input| input.name())
                    .ok_or(OfflineFixtureError::ExecutionContractViolation)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if options.selectors.len() != expected_names.len()
            || options
                .selectors
                .keys()
                .map(String::as_str)
                .ne(expected_names.iter().copied())
        {
            return Err(OfflineFixtureError::ExecutionContractViolation);
        }
        let component_values = expected_names
            .iter()
            .map(|name| {
                options
                    .selectors
                    .get(*name)
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or(OfflineFixtureError::ExecutionContractViolation)
            })
            .collect::<Result<Vec<_>, _>>()?;

        if !self.credential_used {
            let credential = self
                .plan
                .credential_operation()
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
            let credential_request = rendered_credential_request_effect(
                credential
                    .render_request(
                        Zeroizing::new(b"synthetic-client".to_vec()),
                        Zeroizing::new(b"synthetic-secret".to_vec()),
                    )
                    .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?,
            )?;
            require_basic_success(
                self.interactions.take(
                    credential.id().as_str(),
                    credential_request.path.as_str(),
                    &credential_request,
                )?,
                64 * 1024,
            )?;
            self.credential_used = true;
        }

        let verification = dci.verification();
        let verification_request = verification
            .transport_template()
            .render(&[], &[], None, None)
            .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
        let verification_request = rendered_request_from_effect(
            verification_request.noncredential_effect_value("fixture-verification"),
        )?;
        let jwks = require_http_body(
            self.interactions.take(
                verification.id().as_str(),
                verification.fixed_path(),
                &verification_request,
            )?,
            verification.response_max_bytes(),
        )?;
        let data_request = rendered_dci_request_values(dci, &component_values)?;
        let response = require_http_body(
            self.interactions
                .take("script-source-call", &data_request.path, &data_request)?,
            dci.response_max_bytes(),
        )?;
        self.source_bytes = self
            .source_bytes
            .checked_add(
                u64::try_from(jwks.len())
                    .map_err(|_| OfflineFixtureError::SourceResponseTooLarge)?,
            )
            .and_then(|total| {
                u64::try_from(response.len())
                    .ok()
                    .and_then(|bytes| total.checked_add(bytes))
            })
            .filter(|total| *total <= self.plan.limits().operation().max_source_bytes)
            .ok_or(OfflineFixtureError::SourceResponseTooLarge)?;
        let expectation = offline_dci_expectation(dci, &component_values)?;
        let payload = SignedDciDecoder::new_script(expectation)
            .decode_verified_payload_offline_fixture(&jwks, &response)
            .map_err(map_dci_decode)?;
        Ok(SourceResponse {
            status: 200,
            body: payload,
            headers: BTreeMap::new(),
        })
    }
}

fn rendered_script_request(
    method: crate::source_plan::ReadMethod,
    target: &str,
    option_query: &BTreeMap<String, Value>,
    headers: &BTreeMap<String, String>,
    body: Option<Value>,
) -> Result<OfflineRenderedRequest, OfflineFixtureError> {
    let (path, raw_query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    let mut query = BTreeMap::<String, Vec<String>>::new();
    if let Some(raw_query) = raw_query {
        for component in raw_query.split('&') {
            let (name, value) = component
                .split_once('=')
                .ok_or(OfflineFixtureError::RequestMismatch)?;
            query
                .entry(percent_decode_fixture_component(name)?)
                .or_default()
                .push(percent_decode_fixture_component(value)?);
        }
    }
    for (name, value) in option_query {
        if query
            .insert(
                name.clone(),
                fixture_query_values(value).ok_or(OfflineFixtureError::RequestMismatch)?,
            )
            .is_some()
        {
            return Err(OfflineFixtureError::RequestMismatch);
        }
    }
    Ok(OfflineRenderedRequest {
        method: match method {
            crate::source_plan::ReadMethod::Get => OfflineRequestMethod::Get,
            crate::source_plan::ReadMethod::ReadOnlyPost => OfflineRequestMethod::Post,
        },
        path: path.to_owned(),
        query,
        headers: headers.clone(),
        body,
    })
}

fn rendered_credential_request_effect(
    request: registry_platform_httputil::destination::CredentialDestinationRequest,
) -> Result<OfflineRenderedRequest, OfflineFixtureError> {
    let effect = request.credential_exchange_effect_value("fixture-credential");
    let mut rendered = rendered_request_from_effect(effect)?;
    rendered.body = Some(serde_json::json!({"grant_type": "client_credentials"}));
    Ok(rendered)
}

fn rendered_request_from_effect(
    effect: Value,
) -> Result<OfflineRenderedRequest, OfflineFixtureError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let object = effect
        .as_object()
        .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
    let method = match object.get("method").and_then(Value::as_str) {
        Some("GET") => OfflineRequestMethod::Get,
        Some("POST") => OfflineRequestMethod::Post,
        _ => return Err(OfflineFixtureError::ExecutionContractViolation),
    };
    let target = object
        .get("target")
        .and_then(Value::as_str)
        .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
    let (path, raw_query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    let mut query = BTreeMap::<String, Vec<String>>::new();
    if let Some(raw_query) = raw_query {
        for component in raw_query.split('&') {
            let (name, value) = component
                .split_once('=')
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
            query
                .entry(percent_decode_fixture_component(name)?)
                .or_default()
                .push(percent_decode_fixture_component(value)?);
        }
    }
    let headers = object
        .get("headers")
        .and_then(Value::as_array)
        .ok_or(OfflineFixtureError::ExecutionContractViolation)?
        .iter()
        .map(|header| {
            let name = header
                .get("name")
                .and_then(Value::as_str)
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
            let encoded = header
                .get("value_base64url")
                .and_then(Value::as_str)
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
            let bytes = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
            let value = String::from_utf8(bytes)
                .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
            Ok((name.to_owned(), value))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let body = object
        .get("body_base64url")
        .and_then(Value::as_str)
        .map(|encoded| {
            let bytes = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
            serde_json::from_slice(&bytes)
                .map_err(|_| OfflineFixtureError::ExecutionContractViolation)
        })
        .transpose()?;
    Ok(OfflineRenderedRequest {
        method,
        path: path.to_owned(),
        query,
        headers,
        body,
    })
}

fn percent_decode_fixture_component(value: &str) -> Result<String, OfflineFixtureError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let hex = bytes
            .get(index + 1..index + 3)
            .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        decoded.push(
            digit(hex[0])
                .zip(digit(hex[1]))
                .map(|(high, low)| high * 16 + low)
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?,
        );
        index += 3;
    }
    String::from_utf8(decoded).map_err(|_| OfflineFixtureError::ExecutionContractViolation)
}

fn execute_rhai(
    plan: &CompiledSourcePlan,
    inputs: &OfflineBoundInputs,
    interactions: Vec<OfflineInteraction>,
    worker_program: Option<&Path>,
    trace: bool,
) -> Result<OfflineFixtureObservation, OfflineFixtureError> {
    let request = build_rhai_request(plan, inputs)?;
    let mut host = OfflineRhaiHost {
        plan,
        interactions: OfflineInteractionQueue::new(interactions, trace)?,
        credential_used: false,
        request_bytes: 0,
        source_bytes: 0,
        terminal_error: None,
    };
    let output = run_rhai_worker(&request, &mut host, worker_program);
    if let Some(error) = host.terminal_error {
        return Err(error);
    }
    let output = output?;
    let calls = host.interactions.finish()?;
    finalize_rhai_observation(plan, output, calls)
}

fn finalize_rhai_observation(
    plan: &CompiledSourcePlan,
    output: WorkerOutput,
    calls: Vec<String>,
) -> Result<OfflineFixtureObservation, OfflineFixtureError> {
    match output {
        WorkerOutput::Success {
            outcome: WorkerOutcome::NoMatch,
            ..
        } => Ok(observation(
            OfflineFixtureOutcome::NoMatch,
            Vec::new(),
            calls,
        )),
        WorkerOutput::Success {
            outcome: WorkerOutcome::Ambiguous,
            ..
        } => Ok(observation(
            OfflineFixtureOutcome::Ambiguous,
            Vec::new(),
            calls,
        )),
        WorkerOutput::Success {
            outcome: WorkerOutcome::Match,
            outputs,
        } => {
            let outputs = outputs
                .into_iter()
                .map(|(name, value)| rhai_output(value).map(|value| (name.into_boxed_str(), value)))
                .collect::<Result<Vec<_>, _>>()?;
            validated_observation(plan, OfflineFixtureOutcome::Match, outputs, calls)
        }
        WorkerOutput::Failure { failure } => Err(match failure {
            ScriptFailure::SourceUnavailable => OfflineFixtureError::SourceUnavailable,
            ScriptFailure::SourceRejected => OfflineFixtureError::SourceStatusRejected,
            ScriptFailure::SubjectMismatch => OfflineFixtureError::SubjectMismatch,
        }),
    }
}

fn build_rhai_request(
    plan: &CompiledSourcePlan,
    inputs: &OfflineBoundInputs,
) -> Result<WorkerRequest, OfflineFixtureError> {
    let (script, entrypoint) = plan
        .rhai_program()
        .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
    let limits = plan
        .runtime_profile()
        .dispatch()
        .script_limits()
        .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
    let mut request = WorkerRequest::v1(
        script,
        entrypoint,
        WorkerLimits {
            max_operations: limits.instructions(),
            max_call_levels: limits.call_depth() as usize,
            max_expr_depth: limits.call_depth() as usize,
            max_string_bytes: limits.string_bytes() as usize,
            max_array_items: limits.array_items() as usize,
            max_map_entries: limits.map_entries() as usize,
            max_output_bytes: limits.output_bytes() as usize,
            max_ipc_frame_bytes: limits.ipc_frame_bytes() as usize,
            max_memory_bytes: limits.memory_bytes(),
            wall_time_ms: u64::from(limits.cpu_ms()),
            max_source_calls: u32::from(limits.max_calls()),
        },
    );
    for (index, slot) in plan.inputs().enumerate() {
        let value = inputs.get(index)?.transient_json_value();
        request.input.insert(
            slot.name().to_owned(),
            match (slot.input_type(), value) {
                (CompiledInputType::String, Value::String(value)) => {
                    RhaiTypedValue::String { value: Some(value) }
                }
                (CompiledInputType::FullDate, Value::String(value)) => {
                    RhaiTypedValue::Date { value: Some(value) }
                }
                (CompiledInputType::Boolean, Value::Bool(value)) => {
                    RhaiTypedValue::Boolean { value: Some(value) }
                }
                (CompiledInputType::Integer, Value::Number(value)) => RhaiTypedValue::Integer {
                    value: value.as_i64(),
                },
                (CompiledInputType::String, Value::Null) => RhaiTypedValue::String { value: None },
                (CompiledInputType::FullDate, Value::Null) => RhaiTypedValue::Date { value: None },
                (CompiledInputType::Boolean, Value::Null) => {
                    RhaiTypedValue::Boolean { value: None }
                }
                (CompiledInputType::Integer, Value::Null) => {
                    RhaiTypedValue::Integer { value: None }
                }
                _ => return Err(OfflineFixtureError::ExecutionContractViolation),
            },
        );
    }
    for output in plan.rhai_outputs() {
        let (output_type, max_bytes, minimum, maximum) = match output.output_type() {
            CompiledRhaiOutputType::String { max_bytes } => {
                (RhaiOutputType::String, Some(max_bytes as usize), None, None)
            }
            CompiledRhaiOutputType::Boolean => (RhaiOutputType::Boolean, None, None, None),
            CompiledRhaiOutputType::Integer { minimum, maximum } => {
                (RhaiOutputType::Integer, None, Some(minimum), Some(maximum))
            }
            CompiledRhaiOutputType::Date => (RhaiOutputType::Date, None, None, None),
        };
        request.output_schema.insert(
            output.name().to_owned(),
            RhaiOutputSchema {
                output_type,
                nullable: output.nullable(),
                max_bytes,
                minimum,
                maximum,
            },
        );
    }
    if super::executor::signed_dci_script_host_required(plan)
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?
    {
        request.enable_signed_dci_search();
    }
    Ok(request)
}

fn run_rhai_worker(
    request: &WorkerRequest,
    host: &mut OfflineRhaiHost<'_>,
    worker_program: Option<&Path>,
) -> Result<crate::rhai_worker::WorkerOutput, OfflineFixtureError> {
    let worker = worker_program
        .map_or_else(WorkerProcess::dedicated_executable, |program| {
            Ok(WorkerProcess::with_program(program))
        })
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?
        .block_on(worker.evaluate_with_host(request, host))
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)
}

fn rhai_output(value: RhaiTypedValue) -> Result<ProjectedJsonScalar, OfflineFixtureError> {
    Ok(match value {
        RhaiTypedValue::String { value } | RhaiTypedValue::Date { value } => value
            .map_or(ProjectedJsonScalar::Null, |value| {
                ProjectedJsonScalar::String(value.into())
            }),
        RhaiTypedValue::Boolean { value } => {
            value.map_or(ProjectedJsonScalar::Null, ProjectedJsonScalar::Boolean)
        }
        RhaiTypedValue::Integer { value } => {
            value.map_or(ProjectedJsonScalar::Null, ProjectedJsonScalar::Integer)
        }
    })
}

fn rendered_compiled_operation_request(
    plan: &CompiledSourcePlan,
    operation: &crate::source_plan::CompiledOperation,
    inputs: &OfflineBoundInputs,
    memory: &[Option<OperationMemory>],
) -> Result<OfflineRenderedRequest, OfflineFixtureError> {
    use crate::source_plan::CompiledSourceAuth;
    use registry_platform_httputil::destination::DestinationAuthorizationValue;

    let mut query = operation
        .query()
        .map(|entry| render_offline_text(plan, inputs, memory, entry.value()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut headers = operation
        .headers()
        .map(|entry| render_offline_text(plan, inputs, memory, entry.value()))
        .collect::<Result<Vec<_>, _>>()?;
    let path_segment = operation
        .path_segment()
        .map(|expression| render_offline_text(plan, inputs, memory, expression))
        .transpose()?;
    let body_value = operation
        .body()
        .map(|body| render_offline_body(plan, inputs, memory, body))
        .transpose()?;
    let body = body_value
        .as_ref()
        .map(|body| serde_json::to_vec(body).map(Zeroizing::new))
        .transpose()
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    match operation.auth() {
        CompiledSourceAuth::ApiKeyHeader => headers.push("synthetic-api-key".to_string()),
        CompiledSourceAuth::ApiKeyQuery => query.push("synthetic-api-key".to_string()),
        _ => {}
    }
    let query_refs = query.iter().map(String::as_str).collect::<Vec<_>>();
    let header_refs = headers
        .iter()
        .map(|value| value.as_bytes())
        .collect::<Vec<_>>();
    let authorization = match operation.auth() {
        CompiledSourceAuth::Basic => Some(
            DestinationAuthorizationValue::basic(b"c3ludGhldGljOnN5bnRoZXRpYw==".to_vec())
                .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?,
        ),
        CompiledSourceAuth::StaticBearer | CompiledSourceAuth::OAuthClientCredentials => Some(
            DestinationAuthorizationValue::bearer(b"synthetic-token".to_vec())
                .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?,
        ),
        CompiledSourceAuth::None
        | CompiledSourceAuth::ApiKeyHeader
        | CompiledSourceAuth::ApiKeyQuery => None,
    };
    let request = match path_segment.as_deref() {
        Some(segment) => operation
            .transport_template()
            .render_zeroizing_with_path_segment(
                segment,
                &query_refs,
                &header_refs,
                authorization,
                body,
            ),
        None => operation.transport_template().render_zeroizing(
            &query_refs,
            &header_refs,
            authorization,
            body,
        ),
    }
    .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    let effect = match operation.auth() {
        CompiledSourceAuth::ApiKeyHeader => {
            request.effect_value_without_api_key_header("fixture-data")
        }
        CompiledSourceAuth::ApiKeyQuery => {
            request.effect_value_without_api_key_query("fixture-data")
        }
        _ => request.noncredential_effect_value("fixture-data"),
    };
    rendered_request_from_effect(effect)
}

fn render_offline_text(
    plan: &CompiledSourcePlan,
    inputs: &OfflineBoundInputs,
    memory: &[Option<OperationMemory>],
    expression: &crate::source_plan::CompiledValueExpression,
) -> Result<String, OfflineFixtureError> {
    use crate::source_plan::CompiledValueExpression;
    Ok(match expression {
        CompiledValueExpression::Literal(value) => value.to_string(),
        CompiledValueExpression::ConsultationInput { input_index } => {
            inputs.get(*input_index)?.as_str().to_owned()
        }
        CompiledValueExpression::DeploymentParameter { parameter_index } => plan
            .deployment_parameter_value(*parameter_index)
            .ok_or(OfflineFixtureError::ExecutionContractViolation)?
            .to_owned(),
        CompiledValueExpression::PriorStepOutput {
            operation_index,
            output_slot_index,
        } => match memory
            .get(*operation_index)
            .and_then(Option::as_ref)
            .and_then(|memory| memory.prior_outputs.get(*output_slot_index))
            .ok_or(OfflineFixtureError::ExecutionContractViolation)?
        {
            ProjectedJsonScalar::String(value) => value.to_string(),
            ProjectedJsonScalar::Boolean(value) => value.to_string(),
            ProjectedJsonScalar::Integer(value) => value.to_string(),
            ProjectedJsonScalar::Null | ProjectedJsonScalar::Number(_) => {
                return Err(OfflineFixtureError::ExecutionContractViolation)
            }
        },
    })
}

fn render_offline_body(
    plan: &CompiledSourcePlan,
    inputs: &OfflineBoundInputs,
    memory: &[Option<OperationMemory>],
    body: &crate::source_plan::CompiledBodyTemplate,
) -> Result<Value, OfflineFixtureError> {
    use crate::source_plan::{CompiledBodyTemplate, CompiledValueExpression};
    Ok(match body {
        CompiledBodyTemplate::Null => Value::Null,
        CompiledBodyTemplate::Boolean(value) => Value::Bool(*value),
        CompiledBodyTemplate::Integer(value) => Value::from(*value),
        CompiledBodyTemplate::StringLiteral(value) => Value::String(value.to_string()),
        CompiledBodyTemplate::Expression(CompiledValueExpression::ConsultationInput {
            input_index,
        }) => inputs.get(*input_index)?.transient_json_value(),
        CompiledBodyTemplate::Expression(CompiledValueExpression::PriorStepOutput {
            operation_index,
            output_slot_index,
        }) => memory
            .get(*operation_index)
            .and_then(Option::as_ref)
            .and_then(|memory| memory.prior_outputs.get(*output_slot_index))
            .ok_or(OfflineFixtureError::ExecutionContractViolation)
            .and_then(projected_scalar_json)?,
        CompiledBodyTemplate::Expression(expression) => {
            Value::String(render_offline_text(plan, inputs, memory, expression)?)
        }
        CompiledBodyTemplate::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| render_offline_body(plan, inputs, memory, item))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        CompiledBodyTemplate::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|field| {
                    render_offline_body(plan, inputs, memory, field.value())
                        .map(|value| (field.name().to_owned(), value))
                })
                .collect::<Result<serde_json::Map<_, _>, _>>()?,
        ),
    })
}

fn projected_scalar_json(value: &ProjectedJsonScalar) -> Result<Value, OfflineFixtureError> {
    Ok(match value {
        ProjectedJsonScalar::Null => Value::Null,
        ProjectedJsonScalar::String(value) => Value::String(value.to_string()),
        ProjectedJsonScalar::Boolean(value) => Value::Bool(*value),
        ProjectedJsonScalar::Integer(value) => Value::from(*value),
        ProjectedJsonScalar::Number(value) => serde_json::Number::from_f64(*value)
            .map(Value::Number)
            .ok_or(OfflineFixtureError::ExecutionContractViolation)?,
    })
}

fn execute_http(
    plan: &CompiledSourcePlan,
    inputs: &OfflineBoundInputs,
    interactions: Vec<OfflineInteraction>,
    trace: bool,
) -> Result<OfflineFixtureObservation, OfflineFixtureError> {
    if plan
        .operations()
        .any(|operation| operation.dci_exact().is_some())
    {
        return execute_dci(plan, inputs, interactions, trace);
    }
    validate_bounded_http_activation(plan)
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    if !inputs.is_bound_to(plan) {
        return Err(OfflineFixtureError::ExecutionContractViolation);
    }
    let mut interactions = OfflineInteractionQueue::new(interactions, trace)?;
    let operations = plan.operations().collect::<Vec<_>>();
    let mut memory = (0..operations.len()).map(|_| None).collect::<Vec<_>>();
    let mut outputs = Vec::new();
    let mut credential_used = false;
    for (step_position, step) in plan.compiled_steps().enumerate() {
        let index = step.operation_index();
        let operation = operations
            .get(index)
            .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
        if !offline_step_should_execute(step, &memory)? {
            append_absent(operation, &mut outputs);
            memory[index] = Some(OperationMemory {
                prior_outputs: (0..operation.response().prior_outputs().len())
                    .map(|_| ProjectedJsonScalar::Null)
                    .collect(),
                present: false,
            });
            continue;
        }
        if !credential_used {
            if let Some(credential) = plan.credential_operation() {
                let request = rendered_credential_request_effect(
                    credential
                        .render_request(
                            Zeroizing::new(b"synthetic-client".to_vec()),
                            Zeroizing::new(b"synthetic-secret".to_vec()),
                        )
                        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?,
                )?;
                require_basic_success(
                    interactions.take(credential.id().as_str(), request.path.as_str(), &request)?,
                    64 * 1024,
                )?;
                credential_used = true;
            }
        }
        let request = rendered_compiled_operation_request(plan, operation, inputs, &memory)?;
        let response = interactions.take(
            operation.id().as_str(),
            canonical_operation_path(operation).as_str(),
            &request,
        )?;
        let decoded = decode_operation(operation, response)?;
        match decoded {
            ClosedJsonOutcome::Ambiguous => {
                return Ok(observation(
                    OfflineFixtureOutcome::Ambiguous,
                    Vec::new(),
                    interactions.finish()?,
                ))
            }
            ClosedJsonOutcome::NoMatch
                if is_anchor_execution_step(index, Some(step_position), step_position, false) =>
            {
                return Ok(observation(
                    OfflineFixtureOutcome::NoMatch,
                    Vec::new(),
                    interactions.finish()?,
                ))
            }
            ClosedJsonOutcome::NoMatch => {
                append_absent(operation, &mut outputs);
                memory[index] = Some(OperationMemory {
                    prior_outputs: (0..operation.response().prior_outputs().len())
                        .map(|_| ProjectedJsonScalar::Null)
                        .collect(),
                    present: false,
                });
            }
            ClosedJsonOutcome::One(record) => {
                let output_count = operation.response().outputs().len();
                let mut projected = record.into_fields().into_vec();
                if projected.len() != output_count + operation.response().prior_outputs().len() {
                    return Err(OfflineFixtureError::ExecutionContractViolation);
                }
                let prior_outputs = projected
                    .drain(output_count..)
                    .map(|field| field.into_parts().1)
                    .collect();
                outputs.extend(projected.into_iter().map(|field| field.into_parts()));
                memory[index] = Some(OperationMemory {
                    prior_outputs,
                    present: true,
                });
            }
        }
    }
    validated_observation(
        plan,
        OfflineFixtureOutcome::Match,
        outputs,
        interactions.finish()?,
    )
}

fn decode_operation(
    operation: &crate::source_plan::CompiledOperation,
    response: OfflineSourceResponse,
) -> Result<ClosedJsonOutcome, OfflineFixtureError> {
    let OfflineSourceResponse::Http { status, body, .. } = response else {
        return match response {
            OfflineSourceResponse::DeclaredBodyBytes { status, body_bytes } => {
                validate_status(operation, status)?;
                if body_bytes > u64::from(operation.response_max_bytes()) {
                    Err(OfflineFixtureError::SourceResponseTooLarge)
                } else {
                    Err(OfflineFixtureError::SourceResponseMalformed)
                }
            }
            OfflineSourceResponse::Timeout => Err(OfflineFixtureError::SourceDeadlineExceeded),
            OfflineSourceResponse::CredentialSuccess => {
                Err(OfflineFixtureError::SourceResponseMalformed)
            }
            OfflineSourceResponse::Unavailable => Err(OfflineFixtureError::SourceUnavailable),
            OfflineSourceResponse::NoMatch => Ok(ClosedJsonOutcome::NoMatch),
            OfflineSourceResponse::Http { .. } => unreachable!(),
        };
    };
    validate_status(operation, status)?;
    if let Some(outcome) = operation.response().status_outcome(status) {
        return Ok(match outcome {
            CompiledStatusOutcome::NoMatch => ClosedJsonOutcome::NoMatch,
            CompiledStatusOutcome::Ambiguous => ClosedJsonOutcome::Ambiguous,
        });
    }
    if body.len() > operation.response_max_bytes() as usize {
        return Err(OfflineFixtureError::SourceResponseTooLarge);
    }
    operation
        .response_decoder()
        .decode_offline_fixture(&body)
        .map_err(map_closed_decode)
}

fn execute_dci(
    plan: &CompiledSourcePlan,
    inputs: &OfflineBoundInputs,
    interactions: Vec<OfflineInteraction>,
    trace: bool,
) -> Result<OfflineFixtureObservation, OfflineFixtureError> {
    let operation = plan
        .operations()
        .next()
        .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
    let dci = operation
        .dci_exact()
        .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
    let verification = dci.verification();
    let credential = plan
        .credential_operation()
        .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
    let mut interactions = OfflineInteractionQueue::new(interactions, trace)?;
    let credential_request = rendered_credential_request_effect(
        credential
            .render_request(
                Zeroizing::new(b"synthetic-client".to_vec()),
                Zeroizing::new(b"synthetic-secret".to_vec()),
            )
            .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?,
    )?;
    require_basic_success(
        interactions.take(
            credential.id().as_str(),
            credential_request.path.as_str(),
            &credential_request,
        )?,
        64 * 1024,
    )?;
    let verification_request = verification
        .transport_template()
        .render(&[], &[], None, None)
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    let verification_request = rendered_request_from_effect(
        verification_request.noncredential_effect_value("fixture-verification"),
    )?;
    let jwks = require_http_body(
        interactions.take(
            verification.id().as_str(),
            verification.fixed_path(),
            &verification_request,
        )?,
        verification.response_max_bytes(),
    )?;
    let data_request = rendered_dci_request(operation, inputs)?;
    let response = require_http_body(
        interactions.take(
            operation.id().as_str(),
            canonical_operation_path(operation).as_str(),
            &data_request,
        )?,
        operation.response_max_bytes(),
    )?;
    let calls = interactions.finish()?;
    let exact_components = match dci.selector() {
        crate::source_plan::CompiledDciSelector::ExactAnd { components, .. } => components
            .iter()
            .map(|component| {
                Ok(SignedDciExactComponent {
                    response_pointer: component.response_pointer(),
                    expected_value: inputs.get(component.input_index())?.as_str(),
                })
            })
            .collect::<Result<Vec<_>, OfflineFixtureError>>()?,
    };
    let expectation = match dci.selector() {
        crate::source_plan::CompiledDciSelector::ExactAnd {
            identifier_type: Some(identifier_type),
            ..
        } => SignedDciExpectation::new_idtype_value(
            DCI_FIXTURE_MESSAGE_ID,
            dci.sender_id(),
            dci.receiver_id(),
            inputs.get(0)?.as_str(),
            dci.protocol_version(),
            dci.registry_type()
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?,
            dci.record_type()
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?,
            identifier_type,
            dci.locale(),
            u64::from(dci.page_number()),
            u64::from(operation.max_source_records()),
            verification.response_max_bytes() as usize,
            operation.response_max_bytes() as usize,
        ),
        crate::source_plan::CompiledDciSelector::ExactAnd {
            identifier_type: None,
            ..
        } => SignedDciExpectation::new_exact_and(
            DCI_FIXTURE_MESSAGE_ID,
            dci.sender_id(),
            dci.receiver_id(),
            &exact_components,
            dci.protocol_version(),
            dci.registry_type()
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?,
            dci.record_type()
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?,
            dci.locale(),
            u64::from(dci.page_number()),
            u64::from(operation.max_source_records()),
            verification.response_max_bytes() as usize,
            operation.response_max_bytes() as usize,
        ),
    }
    .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    let decoded = SignedDciDecoder::new(expectation, operation.response_decoder())
        .decode_offline_fixture(&jwks, &response)
        .map_err(map_dci_decode)?;
    match decoded {
        ClosedJsonOutcome::NoMatch => Ok(observation(
            OfflineFixtureOutcome::NoMatch,
            Vec::new(),
            calls,
        )),
        ClosedJsonOutcome::Ambiguous => Ok(observation(
            OfflineFixtureOutcome::Ambiguous,
            Vec::new(),
            calls,
        )),
        ClosedJsonOutcome::One(record) => validated_observation(
            plan,
            OfflineFixtureOutcome::Match,
            record
                .into_fields()
                .into_vec()
                .into_iter()
                .map(|field| field.into_parts())
                .collect(),
            calls,
        ),
    }
}

fn canonical_operation_path(operation: &crate::source_plan::CompiledOperation) -> String {
    if operation.path_segment().is_some() {
        format!("{}*", operation.fixed_path())
    } else {
        operation.fixed_path().to_string()
    }
}

fn rendered_dci_request(
    operation: &crate::source_plan::CompiledOperation,
    inputs: &OfflineBoundInputs,
) -> Result<OfflineRenderedRequest, OfflineFixtureError> {
    let dci = operation
        .dci_exact()
        .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
    let values = match dci.selector() {
        crate::source_plan::CompiledDciSelector::ExactAnd { components, .. } => components
            .iter()
            .map(|component| {
                inputs
                    .get(component.input_index())
                    .map(CompiledInputValue::as_str)
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    rendered_dci_request_values(dci, &values)
}

fn rendered_dci_request_values(
    dci: &crate::source_plan::CompiledDciExact,
    component_values: &[&str],
) -> Result<OfflineRenderedRequest, OfflineFixtureError> {
    use crate::source_plan::codec::dci::{
        DciExactAndComponentInput, DciExactAndSearchRequestInput, DciExactSearchRequest,
        DciExactSearchRequestInput,
    };
    use registry_platform_httputil::destination::DestinationAuthorizationValue;

    let message_timestamp = time::OffsetDateTime::parse(
        "2026-01-01T00:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    let components = match dci.selector() {
        crate::source_plan::CompiledDciSelector::ExactAnd { components, .. } => components
            .iter()
            .zip(component_values)
            .map(|(component, value)| DciExactAndComponentInput {
                field: component.field(),
                value,
            })
            .collect::<Vec<_>>(),
    };
    if components.len() != component_values.len() {
        return Err(OfflineFixtureError::ExecutionContractViolation);
    }
    let request = match dci.selector() {
        crate::source_plan::CompiledDciSelector::ExactAnd {
            identifier_type: Some(identifier_type),
            ..
        } => DciExactSearchRequest::try_new(DciExactSearchRequestInput {
            protocol_version: dci.protocol_version(),
            message_id: DCI_FIXTURE_MESSAGE_ID,
            message_timestamp,
            sender_id: dci.sender_id(),
            receiver_id: dci.receiver_id(),
            registry_type: dci.registry_type(),
            registry_event_type: dci.registry_event_type(),
            record_type: dci.record_type(),
            identifier_type,
            selector: component_values
                .first()
                .copied()
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?,
            requested_max: dci.max_source_records(),
            page_number: dci.page_number(),
            signature: None,
        }),
        crate::source_plan::CompiledDciSelector::ExactAnd {
            identifier_type: None,
            ..
        } => DciExactSearchRequest::try_new_exact_and(DciExactAndSearchRequestInput {
            protocol_version: dci.protocol_version(),
            message_id: DCI_FIXTURE_MESSAGE_ID,
            message_timestamp,
            sender_id: dci.sender_id(),
            receiver_id: dci.receiver_id(),
            registry_type: dci.registry_type(),
            registry_event_type: dci.registry_event_type(),
            record_type: dci.record_type(),
            components: &components,
            requested_max: dci.max_source_records(),
            page_number: dci.page_number(),
            signature: None,
        }),
    }
    .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    let body = request
        .to_json_body()
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    let authorization = DestinationAuthorizationValue::bearer(b"synthetic-token".to_vec())
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    let rendered = dci
        .data_transport()
        .ok_or(OfflineFixtureError::ExecutionContractViolation)?
        .render_zeroizing(
            &[],
            &[],
            Some(authorization),
            Some(body.into_zeroizing_bytes()),
        )
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    rendered_request_from_effect(rendered.noncredential_effect_value("fixture-data"))
}

fn offline_dci_expectation<'a>(
    dci: &crate::source_plan::CompiledDciExact,
    component_values: &'a [&'a str],
) -> Result<SignedDciExpectation, OfflineFixtureError> {
    let components = match dci.selector() {
        crate::source_plan::CompiledDciSelector::ExactAnd { components, .. } => components
            .iter()
            .zip(component_values)
            .map(|(component, value)| SignedDciExactComponent {
                response_pointer: component.response_pointer(),
                expected_value: value,
            })
            .collect::<Vec<_>>(),
    };
    if components.len() != component_values.len() {
        return Err(OfflineFixtureError::ExecutionContractViolation);
    }
    match dci.selector() {
        crate::source_plan::CompiledDciSelector::ExactAnd {
            identifier_type: Some(identifier_type),
            ..
        } => SignedDciExpectation::new_idtype_value(
            DCI_FIXTURE_MESSAGE_ID,
            dci.sender_id(),
            dci.receiver_id(),
            component_values
                .first()
                .copied()
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?,
            dci.protocol_version(),
            dci.registry_type()
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?,
            dci.record_type()
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?,
            identifier_type,
            dci.locale(),
            u64::from(dci.page_number()),
            u64::from(dci.max_source_records()),
            dci.verification().response_max_bytes() as usize,
            dci.response_max_bytes() as usize,
        ),
        crate::source_plan::CompiledDciSelector::ExactAnd {
            identifier_type: None,
            ..
        } => SignedDciExpectation::new_exact_and(
            DCI_FIXTURE_MESSAGE_ID,
            dci.sender_id(),
            dci.receiver_id(),
            &components,
            dci.protocol_version(),
            dci.registry_type()
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?,
            dci.record_type()
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?,
            dci.locale(),
            u64::from(dci.page_number()),
            u64::from(dci.max_source_records()),
            dci.verification().response_max_bytes() as usize,
            dci.response_max_bytes() as usize,
        ),
    }
    .map_err(|_| OfflineFixtureError::ExecutionContractViolation)
}

fn execute_snapshot(
    plan: &CompiledSourcePlan,
    inputs: &OfflineBoundInputs,
    interactions: Vec<OfflineInteraction>,
    trace: bool,
) -> Result<OfflineFixtureObservation, OfflineFixtureError> {
    validate_snapshot_exact_activation(plan)
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    let binding = plan
        .snapshot_binding()
        .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
    let canonical_inputs = inputs.iter().map(CompiledInputValue::as_str);
    if binding.keys().len() != canonical_inputs.len()
        || !binding
            .keys()
            .zip(canonical_inputs)
            .zip(plan.inputs())
            .all(|((key, _value), slot)| key.0 == slot.name())
    {
        return Err(OfflineFixtureError::ExecutionContractViolation);
    }
    let mut interactions = OfflineInteractionQueue::new(interactions, trace)?;
    let response = interactions.take(
        "snapshot",
        "/snapshot",
        &OfflineRenderedRequest {
            method: OfflineRequestMethod::Get,
            path: "/snapshot".to_string(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: None,
        },
    )?;
    let calls = interactions.finish()?;
    let rows = match response {
        OfflineSourceResponse::NoMatch => Vec::new(),
        OfflineSourceResponse::Unavailable => return Err(OfflineFixtureError::SourceUnavailable),
        OfflineSourceResponse::Timeout => return Err(OfflineFixtureError::SourceDeadlineExceeded),
        OfflineSourceResponse::CredentialSuccess => {
            return Err(OfflineFixtureError::SourceResponseMalformed)
        }
        OfflineSourceResponse::DeclaredBodyBytes { .. } => {
            return Err(OfflineFixtureError::SourceResponseTooLarge)
        }
        OfflineSourceResponse::Http {
            status: 200, body, ..
        } => {
            let value: Value = registry_platform_crypto::parse_json_strict(&body)
                .map_err(|_| OfflineFixtureError::SourceResponseMalformed)?;
            match value {
                Value::Array(rows) => rows,
                Value::Object(_) => vec![value],
                _ => return Err(OfflineFixtureError::SourceResponseMalformed),
            }
        }
        OfflineSourceResponse::Http { .. } => {
            return Err(OfflineFixtureError::SourceStatusRejected)
        }
    };
    let (outcome, record, _, _) =
        decode_snapshot_rows(plan, rows).map_err(|error| match error {
            crate::source_backend::SnapshotExactBackendError::CardinalityViolation => {
                OfflineFixtureError::SourceCardinalityViolation
            }
            crate::source_backend::SnapshotExactBackendError::Unavailable => {
                OfflineFixtureError::SourceUnavailable
            }
            _ => OfflineFixtureError::SourceResponseMalformed,
        })?;
    let public = map_outcome(outcome);
    let outputs = match record {
        Some(record) => plan
            .runtime_profile()
            .output()
            .map(|field| {
                snapshot_projected_value(field.shape(), field.name(), record.fields())
                    .map(|value| (field.name().into(), value))
            })
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
    };
    if public == OfflineFixtureOutcome::Match {
        validated_observation(plan, public, outputs, calls)
    } else {
        Ok(observation(public, Vec::new(), calls))
    }
}

fn snapshot_projected_value(
    shape: crate::source_plan::runtime_profile::CompiledOutputShape,
    name: &str,
    fields: &serde_json::Map<String, Value>,
) -> Result<ProjectedJsonScalar, OfflineFixtureError> {
    let _ = shape;
    fields
        .get(name)
        .map(json_scalar)
        .ok_or(OfflineFixtureError::SourceResponseMalformed)
}

fn require_basic_success(
    response: OfflineSourceResponse,
    max_bytes: u32,
) -> Result<(), OfflineFixtureError> {
    match response {
        OfflineSourceResponse::CredentialSuccess => Ok(()),
        other => require_http_body(other, max_bytes).map(drop),
    }
}

fn require_http_body(
    response: OfflineSourceResponse,
    max_bytes: u32,
) -> Result<Vec<u8>, OfflineFixtureError> {
    match response {
        OfflineSourceResponse::Http {
            status: 200, body, ..
        } if body.len() <= max_bytes as usize => Ok(body),
        OfflineSourceResponse::Http { status: 200, .. } => {
            Err(OfflineFixtureError::SourceResponseTooLarge)
        }
        OfflineSourceResponse::DeclaredBodyBytes {
            status: 200,
            body_bytes,
        } if body_bytes > u64::from(max_bytes) => Err(OfflineFixtureError::SourceResponseTooLarge),
        OfflineSourceResponse::DeclaredBodyBytes { status: 200, .. } => {
            Err(OfflineFixtureError::SourceResponseMalformed)
        }
        OfflineSourceResponse::Http { .. } | OfflineSourceResponse::DeclaredBodyBytes { .. } => {
            Err(OfflineFixtureError::SourceStatusRejected)
        }
        OfflineSourceResponse::Timeout => Err(OfflineFixtureError::SourceDeadlineExceeded),
        OfflineSourceResponse::CredentialSuccess
        | OfflineSourceResponse::NoMatch
        | OfflineSourceResponse::Unavailable => Err(OfflineFixtureError::SourceUnavailable),
    }
}

fn validate_status(
    operation: &crate::source_plan::CompiledOperation,
    status: u16,
) -> Result<(), OfflineFixtureError> {
    operation
        .response()
        .accepted_statuses()
        .any(|accepted| accepted == status)
        .then_some(())
        .ok_or(OfflineFixtureError::SourceStatusRejected)
}

fn validated_observation(
    plan: &CompiledSourcePlan,
    outcome: OfflineFixtureOutcome,
    outputs: Vec<(Box<str>, ProjectedJsonScalar)>,
    calls: Vec<String>,
) -> Result<OfflineFixtureObservation, OfflineFixtureError> {
    let outputs = ValidatedOutputMap::try_new(plan.runtime_profile(), outputs)
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    Ok(OfflineFixtureObservation {
        outcome,
        outputs: outputs
            .fields()
            .map(|(name, value)| (name.to_owned(), scalar_value(value)))
            .collect(),
        calls,
    })
}

fn observation(
    outcome: OfflineFixtureOutcome,
    outputs: Vec<(String, Value)>,
    calls: Vec<String>,
) -> OfflineFixtureObservation {
    OfflineFixtureObservation {
        outcome,
        outputs: outputs.into_iter().collect(),
        calls,
    }
}

fn scalar_value(value: &ProjectedJsonScalar) -> Value {
    match value {
        ProjectedJsonScalar::Null => Value::Null,
        ProjectedJsonScalar::String(value) => Value::String(value.as_str().to_owned()),
        ProjectedJsonScalar::Boolean(value) => Value::Bool(*value),
        ProjectedJsonScalar::Integer(value) => Value::from(*value),
        ProjectedJsonScalar::Number(value) => {
            serde_json::Number::from_f64(*value).map_or(Value::Null, Value::Number)
        }
    }
}

fn json_scalar(value: &Value) -> ProjectedJsonScalar {
    match value {
        Value::Null => ProjectedJsonScalar::Null,
        Value::String(value) => ProjectedJsonScalar::String(value.clone().into()),
        Value::Bool(value) => ProjectedJsonScalar::Boolean(*value),
        Value::Number(value) => value.as_i64().map_or_else(
            || ProjectedJsonScalar::Number(value.as_f64().unwrap_or(f64::NAN)),
            ProjectedJsonScalar::Integer,
        ),
        Value::Array(_) | Value::Object(_) => ProjectedJsonScalar::Null,
    }
}

fn append_absent(
    operation: &crate::source_plan::CompiledOperation,
    outputs: &mut Vec<(Box<str>, ProjectedJsonScalar)>,
) {
    outputs.extend(
        operation
            .response()
            .outputs()
            .map(|field| (field.field().into(), ProjectedJsonScalar::Null)),
    );
}

fn offline_step_should_execute(
    step: &crate::source_plan::CompiledStep,
    memory: &[Option<OperationMemory>],
) -> Result<bool, OfflineFixtureError> {
    let Some(predicate) = step.condition() else {
        return Ok(true);
    };
    let source = memory
        .get(
            step.condition_source_index()
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?,
        )
        .and_then(Option::as_ref)
        .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
    if step.condition_uses_presence() {
        return Ok(match predicate {
            crate::source_plan::CompiledStepPredicate::Exists => source.present,
            crate::source_plan::CompiledStepPredicate::BooleanEquals(expected) => {
                source.present == *expected
            }
            _ => false,
        });
    }
    let value = source
        .prior_outputs
        .get(
            step.condition_output_slot_index()
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?,
        )
        .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
    Ok(match (predicate, value) {
        (crate::source_plan::CompiledStepPredicate::Exists, ProjectedJsonScalar::Null) => false,
        (crate::source_plan::CompiledStepPredicate::Exists, _) => true,
        (
            crate::source_plan::CompiledStepPredicate::StringEquals(expected),
            ProjectedJsonScalar::String(value),
        ) => value.as_str() == expected.as_ref(),
        (
            crate::source_plan::CompiledStepPredicate::BooleanEquals(expected),
            ProjectedJsonScalar::Boolean(value),
        ) => expected == value,
        (
            crate::source_plan::CompiledStepPredicate::IntegerEquals(expected),
            ProjectedJsonScalar::Integer(value),
        ) => expected == value,
        _ => false,
    })
}

const fn map_outcome(outcome: ConsultationOutcome) -> OfflineFixtureOutcome {
    match outcome {
        ConsultationOutcome::Match => OfflineFixtureOutcome::Match,
        ConsultationOutcome::NoMatch => OfflineFixtureOutcome::NoMatch,
        ConsultationOutcome::Ambiguous => OfflineFixtureOutcome::Ambiguous,
    }
}

const fn map_closed_decode(error: ClosedJsonDecodeError) -> OfflineFixtureError {
    match error {
        ClosedJsonDecodeError::CardinalityViolation => {
            OfflineFixtureError::SourceCardinalityViolation
        }
        _ => OfflineFixtureError::SourceResponseMalformed,
    }
}

const fn map_dci_decode(error: SignedDciDecodeError) -> OfflineFixtureError {
    match error {
        SignedDciDecodeError::JwksTooLarge | SignedDciDecodeError::ResponseTooLarge => {
            OfflineFixtureError::SourceResponseTooLarge
        }
        SignedDciDecodeError::CardinalityViolation => {
            OfflineFixtureError::SourceCardinalityViolation
        }
        SignedDciDecodeError::SourceRejected => OfflineFixtureError::SourceUnavailable,
        _ => OfflineFixtureError::SourceResponseMalformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::source_plan::authoring::{
        compile_consultation_contract, compile_integration_pack, compile_private_binding,
    };
    use crate::source_plan::{EvidenceClass, PinnedEvidenceArtifact, PinnedSourcePlanArtifact};
    use sha2::{Digest, Sha256};

    const PACK: &[u8] =
        include_bytes!("../../profiles/dhis2-2.41.9-enrollment-status/integration-pack.json");
    const CONTRACT: &[u8] =
        include_bytes!("../../profiles/dhis2-2.41.9-enrollment-status/public-contract.json");
    const BINDING: &[u8] = include_bytes!(
        "../../profiles/dhis2-2.41.9-enrollment-status/private-binding.example.json"
    );
    const CONFORMANCE: &[u8] =
        include_bytes!("../../profiles/dhis2-2.41.9-enrollment-status/evidence/conformance.json");
    const NEGATIVE: &[u8] = include_bytes!(
        "../../profiles/dhis2-2.41.9-enrollment-status/evidence/negative-security.json"
    );
    const MINIMIZATION: &[u8] =
        include_bytes!("../../profiles/dhis2-2.41.9-enrollment-status/evidence/minimization.json");

    fn harness() -> (OfflineRelayFixture, OfflineProfilePin) {
        let pack = compile_integration_pack(PACK).expect("pack");
        let contract = compile_consultation_contract(CONTRACT).expect("contract");
        let binding = compile_private_binding(BINDING).expect("binding");
        let contracts = [PinnedSourcePlanArtifact::new(
            contract.artifact().canonical_json(),
            contract.artifact().typed_hash(),
        )];
        let packs = [PinnedSourcePlanArtifact::new(
            pack.canonical_json(),
            pack.typed_hash(),
        )];
        let bindings = [binding.canonical_json()];
        let evidence_bytes = [CONFORMANCE, NEGATIVE, MINIMIZATION];
        let evidence_classes = [
            EvidenceClass::Conformance,
            EvidenceClass::NegativeSecurity,
            EvidenceClass::Minimization,
        ];
        let hashes = evidence_bytes
            .iter()
            .map(|bytes| {
                let digest = Sha256::digest(bytes);
                let mut value = String::from("sha256:");
                for byte in digest {
                    use std::fmt::Write as _;
                    write!(&mut value, "{byte:02x}").expect("string write");
                }
                value
            })
            .collect::<Vec<_>>();
        let evidence = evidence_bytes
            .iter()
            .zip(evidence_classes)
            .zip(&hashes)
            .map(|((bytes, class), hash)| PinnedEvidenceArtifact::new(class, bytes, hash))
            .collect::<Vec<_>>();
        let bundle =
            SourcePlanArtifactBundle::new(&contracts, &packs, &bindings).with_evidence(&evidence);
        (
            OfflineRelayFixture::compile(&bundle).expect("offline harness"),
            OfflineProfilePin {
                id: "dhis2.tracker.enrollment-status.exact".to_owned(),
                version: 1,
                contract_hash: contract.artifact().typed_hash().to_owned(),
            },
        )
    }

    fn harness_with_input_count(count: usize) -> (OfflineRelayFixture, OfflineProfilePin) {
        assert!((1..=16).contains(&count));
        let mut pack: Value = serde_json::from_slice(PACK).expect("pack JSON");
        let mut contract: Value = serde_json::from_slice(CONTRACT).expect("contract JSON");
        let mut binding: Value = serde_json::from_slice(BINDING).expect("binding JSON");
        let additions = [
            (
                "birth_date",
                "birthDate",
                serde_json::json!({
                    "role": "selector",
                    "type": "string",
                    "format": "date",
                    "maxLength": 10,
                    "x-registry-max-bytes": 10,
                    "x-registry-canonicalization": "identity"
                }),
            ),
            (
                "country_code",
                "countryCode",
                serde_json::json!({
                    "role": "selector",
                    "type": "string",
                    "maxLength": 2,
                    "x-registry-max-bytes": 8,
                    "pattern": "^[A-Z][A-Z]$",
                    "x-registry-canonicalization": "identity"
                }),
            ),
            (
                "zone",
                "zone",
                serde_json::json!({
                    "role": "selector",
                    "type": "string",
                    "maxLength": 5,
                    "x-registry-max-bytes": 20,
                    "pattern": "^[a-z][a-z][a-z][a-z][a-z]$",
                    "x-registry-canonicalization": "ascii_lowercase"
                }),
            ),
        ];
        for (name, parameter, schema) in additions.into_iter().take(count - 1) {
            pack["spec"]["input_slots"][name] = schema.clone();
            contract["spec"]["inputs"][name] = schema;
            pack["spec"]["reviewed_acquisition"]["selector"]["components"][name] =
                serde_json::json!({"type": "query", "parameter": parameter});
            pack["spec"]["plan"]["operations"][0]["query"][parameter] =
                serde_json::json!({"source": "consultation_input", "name": name});
        }
        for index in 4..count {
            let name = format!("parameter_{index:02}");
            let parameter = format!("parameter{index:02}");
            let schema = serde_json::json!({
                "role": if index < 8 { "selector" } else { "parameter" },
                "type": "string",
                "maxLength": 8,
                "x-registry-max-bytes": 32,
                "pattern": "^[a-z0-9]+$",
                "x-registry-canonicalization": "identity"
            });
            pack["spec"]["input_slots"][&name] = schema.clone();
            contract["spec"]["inputs"][&name] = schema;
            if index < 8 {
                pack["spec"]["reviewed_acquisition"]["selector"]["components"][&name] =
                    serde_json::json!({"type": "query", "parameter": parameter});
            }
            pack["spec"]["plan"]["operations"][0]["query"][&parameter] =
                serde_json::json!({"source": "consultation_input", "name": name});
        }

        let pack_bytes = serde_json::to_vec(&pack).expect("pack bytes");
        let pack = compile_integration_pack(&pack_bytes)
            .unwrap_or_else(|error| panic!("{count}-input composite pack: {error:?}"));
        let contract_bytes = serde_json::to_vec(&contract).expect("contract bytes");
        let contract = compile_consultation_contract(&contract_bytes).expect("composite contract");
        binding["integration_pack"]["hash"] = Value::String(pack.typed_hash().to_owned());
        let binding_bytes = serde_json::to_vec(&binding).expect("binding bytes");
        let binding = compile_private_binding(&binding_bytes).expect("composite binding");

        let contracts = [PinnedSourcePlanArtifact::new(
            contract.artifact().canonical_json(),
            contract.artifact().typed_hash(),
        )];
        let packs = [PinnedSourcePlanArtifact::new(
            pack.canonical_json(),
            pack.typed_hash(),
        )];
        let bindings = [binding.canonical_json()];
        let evidence_bytes = [CONFORMANCE, NEGATIVE, MINIMIZATION];
        let evidence_classes = [
            EvidenceClass::Conformance,
            EvidenceClass::NegativeSecurity,
            EvidenceClass::Minimization,
        ];
        let hashes = evidence_bytes
            .iter()
            .map(|bytes| {
                let digest = Sha256::digest(bytes);
                let mut value = String::from("sha256:");
                for byte in digest {
                    use std::fmt::Write as _;
                    write!(&mut value, "{byte:02x}").expect("string write");
                }
                value
            })
            .collect::<Vec<_>>();
        let evidence = evidence_bytes
            .iter()
            .zip(evidence_classes)
            .zip(&hashes)
            .map(|((bytes, class), hash)| PinnedEvidenceArtifact::new(class, bytes, hash))
            .collect::<Vec<_>>();
        let bundle =
            SourcePlanArtifactBundle::new(&contracts, &packs, &bindings).with_evidence(&evidence);
        (
            OfflineRelayFixture::compile(&bundle).expect("composite offline harness"),
            OfflineProfilePin {
                id: "dhis2.tracker.enrollment-status.exact".to_owned(),
                version: 1,
                contract_hash: contract.artifact().typed_hash().to_owned(),
            },
        )
    }

    fn request(profile: OfflineProfilePin, input: &str, body: Value) -> OfflineFixtureRequest {
        OfflineFixtureRequest {
            profile,
            input: BTreeMap::from([("tracked_entity".to_owned(), input.to_owned())]),
            interactions: vec![OfflineInteraction {
                request: OfflineExpectedRequest {
                    method: OfflineRequestMethod::Get,
                    path: "/stable-2-41-9/api/tracker/enrollments".to_owned(),
                    query: BTreeMap::from([
                        ("fields".to_owned(), Value::String("status".to_owned())),
                        ("orgUnitMode".to_owned(), Value::String("ALL".to_owned())),
                        ("pageSize".to_owned(), Value::String("2".to_owned())),
                        (
                            "program".to_owned(),
                            Value::String("IpHINAT79UW".to_owned()),
                        ),
                        ("trackedEntity".to_owned(), Value::String(input.to_owned())),
                    ]),
                    headers: BTreeMap::new(),
                    body: None,
                },
                response: OfflineSourceResponse::Http {
                    status: 200,
                    headers: BTreeMap::new(),
                    body: serde_json::to_vec(&body).expect("body"),
                },
            }],
        }
    }

    fn dhis2_body(statuses: &[&str]) -> Value {
        serde_json::json!({
            "enrollments": statuses.iter().map(|status| serde_json::json!({"status": status})).collect::<Vec<_>>(),
            "page": 1,
            "pageSize": 2,
            "pager": {"page": 1, "pageSize": 2}
        })
    }

    #[test]
    fn exact_closed_decoder_releases_match_no_match_and_ambiguity_only() {
        let (harness, profile) = harness();
        let matched = harness
            .execute(request(
                profile.clone(),
                "Abc12345678",
                dhis2_body(&["ACTIVE"]),
            ))
            .expect("match");
        assert_eq!(matched.outcome, OfflineFixtureOutcome::Match);
        assert_eq!(
            matched.outputs,
            BTreeMap::from([("status".to_owned(), Value::String("ACTIVE".to_owned()))])
        );
        assert_eq!(matched.calls, ["lookup-enrollment-status"]);

        let no_match = harness
            .execute(request(profile.clone(), "Abc12345678", dhis2_body(&[])))
            .expect("no match");
        assert_eq!(no_match.outcome, OfflineFixtureOutcome::NoMatch);
        assert!(no_match.outputs.is_empty());

        let ambiguous = harness
            .execute(request(
                profile,
                "Abc12345678",
                dhis2_body(&["ACTIVE", "COMPLETED"]),
            ))
            .expect("ambiguity");
        assert_eq!(ambiguous.outcome, OfflineFixtureOutcome::Ambiguous);
        assert!(ambiguous.outputs.is_empty());
    }

    #[test]
    fn exact_decoder_rejects_input_schema_and_body_bounds_without_values() {
        let (harness, profile) = harness();
        assert_eq!(
            harness.execute(request(profile.clone(), "bad", dhis2_body(&[]))),
            Err(OfflineFixtureError::InvalidInput)
        );
        assert_eq!(
            harness.execute(request(
                profile.clone(),
                "Abc12345678",
                serde_json::json!({"enrollments": [], "unknown": true})
            )),
            Err(OfflineFixtureError::SourceResponseMalformed)
        );
        let mut oversized = request(profile, "Abc12345678", dhis2_body(&[]));
        oversized.interactions[0].response = OfflineSourceResponse::DeclaredBodyBytes {
            status: 200,
            body_bytes: 8193,
        };
        assert_eq!(
            harness.execute(oversized),
            Err(OfflineFixtureError::SourceResponseTooLarge)
        );
    }

    #[test]
    fn exact_input_binding_rejects_missing_and_extra_components() {
        let (harness, profile) = harness();
        let mut missing = request(profile.clone(), "Abc12345678", dhis2_body(&[]));
        missing.input.clear();
        assert_eq!(
            harness.execute(missing),
            Err(OfflineFixtureError::InvalidInput)
        );

        let mut extra = request(profile, "Abc12345678", dhis2_body(&[]));
        extra
            .input
            .insert("caller_selected".to_owned(), "secret-extra".to_owned());
        assert_eq!(
            harness.execute(extra),
            Err(OfflineFixtureError::InvalidInput)
        );
    }

    #[test]
    fn one_through_sixteen_typed_inputs_execute_in_compiled_byte_order() {
        for count in 1..=16 {
            let (harness, profile) = harness_with_input_count(count);
            let mut fixture = request(profile, "Abc12345678", dhis2_body(&["ACTIVE"]));
            if count >= 2 {
                fixture
                    .input
                    .insert("birth_date".to_owned(), "2000-02-29".to_owned());
                fixture.interactions[0].request.query.insert(
                    "birthDate".to_owned(),
                    Value::String("2000-02-29".to_owned()),
                );
            }
            if count >= 3 {
                fixture
                    .input
                    .insert("country_code".to_owned(), "TH".to_owned());
                fixture.interactions[0]
                    .request
                    .query
                    .insert("countryCode".to_owned(), Value::String("TH".to_owned()));
            }
            if count >= 4 {
                fixture.input.insert("zone".to_owned(), "NORTH".to_owned());
                fixture.interactions[0]
                    .request
                    .query
                    .insert("zone".to_owned(), Value::String("north".to_owned()));
            }
            for index in 4..count {
                fixture
                    .input
                    .insert(format!("parameter_{index:02}"), format!("value{index:02}"));
                fixture.interactions[0].request.query.insert(
                    format!("parameter{index:02}"),
                    Value::String(format!("value{index:02}")),
                );
            }
            let observed = harness.execute(fixture).expect("exact-and execution");
            assert_eq!(observed.outcome, OfflineFixtureOutcome::Match);
        }
    }

    #[test]
    fn full_date_input_is_calendar_valid_and_diagnostics_remain_value_free() {
        let (harness, profile) = harness_with_input_count(2);
        let mut fixture = request(profile, "Abc12345678", dhis2_body(&[]));
        fixture
            .input
            .insert("birth_date".to_owned(), "2001-02-29".to_owned());
        assert_eq!(
            harness.execute(fixture),
            Err(OfflineFixtureError::InvalidInput)
        );
    }

    #[test]
    fn exact_profile_pin_and_rendered_request_fail_closed() {
        let (runner, mut profile) = harness();
        profile.contract_hash = format!("sha256:{}", "0".repeat(64));
        assert_eq!(
            runner.execute(request(profile, "Abc12345678", dhis2_body(&[]))),
            Err(OfflineFixtureError::ProfileNotFound)
        );
        let (runner, profile) = harness();
        let mut unknown = request(profile, "Abc12345678", dhis2_body(&[]));
        unknown.interactions[0].request.path = "/attacker-selected".to_owned();
        assert_eq!(
            runner.execute(unknown),
            Err(OfflineFixtureError::RequestMismatch)
        );
    }

    #[test]
    fn script_no_match_discards_the_complete_worker_output_map() {
        let plan = crate::source_plan::rhai_runtime_vector_plan_fixture();
        let result = finalize_rhai_observation(
            &plan,
            WorkerOutput::Success {
                outcome: WorkerOutcome::NoMatch,
                outputs: BTreeMap::new(),
            },
            vec!["lookup".to_owned()],
        )
        .expect("no-match observation");
        assert_eq!(result.outcome, OfflineFixtureOutcome::NoMatch);
        assert!(result.outputs.is_empty());
        assert_eq!(result.calls, ["lookup"]);
    }

    #[tokio::test]
    async fn offline_script_responses_use_production_json_semantics() {
        let duplicate = br#"{"id":1,"id":2}"#.to_vec();
        let nested = format!(
            "{}0{}",
            "[".repeat(registry_platform_httputil::destination::json::MAX_SCRIPT_JSON_DEPTH,),
            "]".repeat(registry_platform_httputil::destination::json::MAX_SCRIPT_JSON_DEPTH,)
        )
        .into_bytes();

        for body in [duplicate, nested] {
            let plan = crate::source_plan::rhai_runtime_vector_plan_fixture();
            let interaction = OfflineInteraction {
                request: OfflineExpectedRequest {
                    method: OfflineRequestMethod::Get,
                    path: "/api/person/status/0".to_owned(),
                    query: BTreeMap::new(),
                    headers: BTreeMap::new(),
                    body: None,
                },
                response: OfflineSourceResponse::Http {
                    status: 200,
                    headers: BTreeMap::new(),
                    body,
                },
            };
            let mut host = OfflineRhaiHost {
                plan: &plan,
                interactions: OfflineInteractionQueue::new(vec![interaction], false)
                    .expect("one closed interaction"),
                credential_used: true,
                request_bytes: 0,
                source_bytes: 0,
                terminal_error: None,
            };

            assert_eq!(
                host.call(SourceCall::Get {
                    call_id: 0,
                    target: "/api/person/status/0".to_owned(),
                    options: crate::rhai_worker::SourceOptions {
                        query: BTreeMap::new(),
                        headers: BTreeMap::new(),
                    },
                })
                .await,
                Err(HostFailure::ContractViolation)
            );
            assert_eq!(
                host.terminal_error,
                Some(OfflineFixtureError::SourceResponseMalformed)
            );
        }
    }

    #[tokio::test]
    async fn signed_dci_script_rejects_generic_post_before_raw_fixture_response() {
        let plan = crate::source_plan::signed_dci_script_runtime_plan_fixture();
        let interaction = OfflineInteraction {
            request: OfflineExpectedRequest {
                method: OfflineRequestMethod::Post,
                path: "/registry/sync/search".to_owned(),
                query: BTreeMap::new(),
                headers: BTreeMap::new(),
                body: Some(serde_json::json!({"selector": "reviewed"})),
            },
            response: OfflineSourceResponse::Http {
                status: 200,
                headers: BTreeMap::new(),
                body: br#"{"unverified":"must-not-reach-rhai"}"#.to_vec(),
            },
        };
        let mut host = OfflineRhaiHost {
            plan: &plan,
            interactions: OfflineInteractionQueue::new(vec![interaction], false)
                .expect("one closed interaction"),
            credential_used: false,
            request_bytes: 0,
            source_bytes: 0,
            terminal_error: None,
        };

        assert_eq!(
            host.call(SourceCall::PostJson {
                call_id: 0,
                target: "/registry/sync/search".to_owned(),
                body: serde_json::json!({"selector": "reviewed"}),
                options: crate::rhai_worker::SourceOptions {
                    query: BTreeMap::new(),
                    headers: BTreeMap::new(),
                },
            })
            .await,
            Err(HostFailure::ContractViolation)
        );
        assert_eq!(host.interactions.interactions.len(), 1);
        assert!(host.terminal_error.is_none());
    }

    #[test]
    fn snapshot_match_projects_only_declared_physical_fields() {
        let fields = serde_json::Map::from_iter([
            (
                "registration_status".to_owned(),
                Value::String("active".to_owned()),
            ),
            ("eligible".to_owned(), Value::Bool(true)),
        ]);
        let status = snapshot_projected_value(
            crate::source_plan::runtime_profile::CompiledOutputShape::String {
                nullable: true,
                max_bytes: 32,
            },
            "registration_status",
            &fields,
        )
        .expect("logical projected field");
        assert!(matches!(
            status,
            ProjectedJsonScalar::String(value) if value.as_str() == "active"
        ));
        assert!(matches!(
            snapshot_projected_value(
                crate::source_plan::runtime_profile::CompiledOutputShape::Boolean {
                    nullable: true,
                },
                "missing",
                &fields,
            ),
            Err(OfflineFixtureError::SourceResponseMalformed)
        ));
    }

    #[test]
    fn error_debug_and_display_never_include_fixture_values() {
        for error in [
            OfflineFixtureError::InvalidInput,
            OfflineFixtureError::SourceResponseMalformed,
            OfflineFixtureError::SourceCardinalityViolation,
        ] {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("secret"));
            assert!(!rendered.contains(DCI_FIXTURE_MESSAGE_ID));
        }

        let (harness, profile) = harness();
        let request = request(
            profile,
            "secret-selector",
            serde_json::json!({"secret-body": "secret-source-value"}),
        );
        let rendered = format!("{request:?} {:?}", request.interactions.first());
        assert!(!rendered.contains("secret-selector"));
        assert!(!rendered.contains("secret-body"));
        assert!(!rendered.contains("secret-source-value"));
        drop(harness);
    }

    #[test]
    fn safe_trace_reports_body_structure_without_keys_or_values() {
        let request = OfflineRenderedRequest {
            method: OfflineRequestMethod::Post,
            path: "/records/selector-marker".to_string(),
            query: BTreeMap::from([("subject".to_string(), vec!["query-marker".to_string()])]),
            headers: BTreeMap::from([("X-Profile".to_string(), "header-marker".to_string())]),
            body: Some(serde_json::json!({
                "dynamic-selector-marker": "body-marker",
                "items": [true, false]
            })),
        };
        let trace = safe_interaction_trace(2, "lookup", "/records/*", &request);
        assert_eq!(
            trace,
            "call=2 operation=lookup method=POST path=/records/* query=[subject] headers=[x-profile] body=object(fields=2;values=[array(len=2;items=[boolean]),string])"
        );
        for sensitive in [
            "selector-marker",
            "query-marker",
            "header-marker",
            "dynamic-selector-marker",
            "body-marker",
        ] {
            assert!(!trace.contains(sensitive));
        }
    }

    #[test]
    fn trace_queue_records_only_matched_call_order() {
        let expected = |path: &str| OfflineExpectedRequest {
            method: OfflineRequestMethod::Get,
            path: path.to_string(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: None,
        };
        let interactions = ["/first/value-one", "/second/value-two"]
            .into_iter()
            .map(|path| OfflineInteraction {
                request: expected(path),
                response: OfflineSourceResponse::NoMatch,
            })
            .collect();
        let mut queue = OfflineInteractionQueue::new(interactions, true).expect("trace queue");
        for (operation, canonical, actual) in [
            ("first", "/first/*", "/first/value-one"),
            ("second", "/second/*", "/second/value-two"),
        ] {
            queue
                .take(
                    operation,
                    canonical,
                    &OfflineRenderedRequest {
                        method: OfflineRequestMethod::Get,
                        path: actual.to_string(),
                        query: BTreeMap::new(),
                        headers: BTreeMap::new(),
                        body: None,
                    },
                )
                .expect("matched interaction");
        }
        assert_eq!(
            queue.finish().expect("complete queue"),
            [
                "call=1 operation=first method=GET path=/first/* query=[] headers=[] body=none",
                "call=2 operation=second method=GET path=/second/* query=[] headers=[] body=none",
            ]
        );
    }

    #[test]
    fn generated_matchers_are_narrow_and_do_not_weaken_sibling_fields() {
        let expected = serde_json::json!({
            "message_id": {"generated": "dci-correlation"},
            "timestamp": {"generated": "rfc3339-timestamp"},
            "selector": "SYNTHETIC-001"
        });
        let actual = serde_json::json!({
            "message_id": DCI_FIXTURE_MESSAGE_ID,
            "timestamp": "2026-01-01T00:00:00Z",
            "selector": "SYNTHETIC-001"
        });
        assert!(fixture_value_matches(&expected, &actual));
        let mut wrong = actual;
        wrong["selector"] = Value::String("SYNTHETIC-002".to_owned());
        assert!(!fixture_value_matches(&expected, &wrong));
        assert!(!fixture_value_matches(
            &serde_json::json!({"generated": "unknown"}),
            &Value::String(DCI_FIXTURE_MESSAGE_ID.to_owned())
        ));
        assert!(!fixture_value_matches(
            &serde_json::json!({
                "generated": "dci-correlation",
                "chosen": "value"
            }),
            &serde_json::json!({
                "generated": "dci-correlation",
                "chosen": "value"
            })
        ));
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Environment-free product fixture execution over compiled Relay plans.
//!
//! This surface accepts only caller-owned observations. It has no transport,
//! credential, policy, filesystem, or configurable callback capability.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use registry_platform_httputil::destination::json::{
    ClosedJsonDecodeError, ClosedJsonOutcome, ProjectedJsonScalar,
};
use registry_platform_httputil::destination::opencrvs::{
    SignedDciDecodeError, SignedDciDecoder, SignedDciExactComponent, SignedDciExpectation,
};
use serde_json::Value;
use thiserror::Error;

use crate::rhai_worker::{
    FactSchema as RhaiFactSchema, FactType as RhaiFactType, TypedValue as RhaiTypedValue,
    WorkerLimits, WorkerProcess, WorkerRequest,
};
use crate::source_backend::decode_snapshot_rows;
use crate::source_plan::{
    CompiledInputType, CompiledInputValue, CompiledRhaiFactType, CompiledScalarShape,
    CompiledSourcePlan, CompiledSourcePlanRegistry, CompiledStatusOutcome,
    SourcePlanArtifactBundle, SourcePlanCompileError, SourcePlanKind,
};

use super::executor::{
    is_anchor_execution_step, validate_bounded_http_activation, validate_snapshot_exact_activation,
};
use super::response::ValidatedFactMap;
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
    Http { status: u16, body: Vec<u8> },
    DeclaredBodyBytes { status: u16, body_bytes: u64 },
    Timeout,
    CredentialSuccess,
    NoMatch,
    Unavailable,
}

impl fmt::Debug for OfflineSourceResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http { status, body } => formatter
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

/// Closed fixture input for one exact compiled profile.
#[derive(Clone, PartialEq)]
pub struct OfflineFixtureRequest {
    pub profile: OfflineProfilePin,
    pub input: BTreeMap<String, String>,
    pub source: BTreeMap<String, OfflineSourceResponse>,
}

impl fmt::Debug for OfflineFixtureRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineFixtureRequest")
            .field("profile", &self.profile)
            .field("input_slots", &self.input.keys().collect::<Vec<_>>())
            .field("source_operations", &self.source.keys().collect::<Vec<_>>())
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
    pub facts: BTreeMap<String, Value>,
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
    #[error("fixture execution violated the compiled plan")]
    ExecutionContractViolation,
}

/// Immutable offline harness compiled with the exact runtime source-plan compiler.
pub struct OfflineRelayFixture {
    plans: CompiledSourcePlanRegistry,
}

impl OfflineRelayFixture {
    pub fn compile(bundle: &SourcePlanArtifactBundle<'_>) -> Result<Self, SourcePlanCompileError> {
        Ok(Self {
            plans: CompiledSourcePlanRegistry::compile_for_authoring_validation(bundle)?,
        })
    }

    pub fn execute(
        &self,
        request: OfflineFixtureRequest,
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
            SourcePlanKind::SnapshotExact => execute_snapshot(plan, &inputs, request.source),
            SourcePlanKind::BoundedHttp => execute_http(plan, &inputs, request.source),
            SourcePlanKind::SandboxedRhai => execute_rhai(plan, &inputs, request.source),
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

impl OfflineBoundInputs {
    fn try_new(
        plan: &CompiledSourcePlan,
        mut raw: BTreeMap<String, String>,
    ) -> Result<Self, OfflineFixtureError> {
        let slot_count = plan.inputs().len();
        if !(1..=4).contains(&slot_count) || raw.len() != slot_count {
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
                let value = slot
                    .canonicalize_and_validate(&candidate)
                    .ok_or(OfflineFixtureError::InvalidInput)?;
                value
                    .binding_matches(plan.profile().contract_hash(), slot.name(), index)
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
                    value.binding_matches(plan.profile().contract_hash(), slot.name(), index)
                })
            })
    }
}

struct OperationMemory {
    prior_outputs: Vec<ProjectedJsonScalar>,
    present: bool,
}

fn execute_rhai(
    plan: &CompiledSourcePlan,
    inputs: &OfflineBoundInputs,
    mut source: BTreeMap<String, OfflineSourceResponse>,
) -> Result<OfflineFixtureObservation, OfflineFixtureError> {
    let operations = plan.operations().collect::<Vec<_>>();
    let allowed = operations
        .iter()
        .map(|operation| operation.id().as_str())
        .chain(plan.credential_operation().map(|value| value.id().as_str()))
        .collect::<BTreeSet<_>>();
    if source.keys().any(|name| !allowed.contains(name.as_str())) {
        return Err(OfflineFixtureError::UnknownSourceOperation);
    }
    let mut memory = (0..operations.len()).map(|_| None).collect::<Vec<_>>();
    let mut executed = BTreeSet::new();
    let mut calls = Vec::new();
    let mut credential_used = false;
    loop {
        let output = run_rhai_worker(&build_rhai_request(plan, inputs, &memory, &executed)?)?;
        if output.operation_choices.is_empty() {
            return finalize_rhai_observation(plan, &memory, output, calls);
        }
        let mut selected = Vec::new();
        for choice in output.operation_choices {
            let index = operations
                .iter()
                .position(|operation| operation.id().as_str() == choice)
                .filter(|index| !executed.contains(index))
                .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
            if selected.contains(&index) {
                return Err(OfflineFixtureError::ExecutionContractViolation);
            }
            selected.push(index);
        }
        if executed.is_empty() && selected.first() != Some(&0) {
            return Err(OfflineFixtureError::ExecutionContractViolation);
        }
        let max_calls = plan
            .runtime_profile()
            .dispatch()
            .sandboxed_rhai_limits()
            .ok_or(OfflineFixtureError::ExecutionContractViolation)?
            .max_calls();
        if executed.len() + selected.len() > usize::from(max_calls) {
            return Err(OfflineFixtureError::ExecutionContractViolation);
        }
        for index in selected {
            let operation = operations[index];
            if !credential_used {
                if let Some(credential) = plan.credential_operation() {
                    calls.push(credential.id().as_str().to_owned());
                    require_basic_success(
                        source
                            .remove(credential.id().as_str())
                            .ok_or(OfflineFixtureError::MissingSourceObservation)?,
                        64 * 1024,
                    )?;
                    credential_used = true;
                }
            }
            calls.push(operation.id().as_str().to_owned());
            let decoded = decode_operation(
                operation,
                source
                    .remove(operation.id().as_str())
                    .ok_or(OfflineFixtureError::MissingSourceObservation)?,
            )?;
            memory[index] = Some(match decoded {
                ClosedJsonOutcome::Ambiguous => {
                    return Ok(observation(
                        OfflineFixtureOutcome::Ambiguous,
                        Vec::new(),
                        calls,
                    ))
                }
                ClosedJsonOutcome::NoMatch => OperationMemory {
                    prior_outputs: (0..operation.response().prior_outputs().len())
                        .map(|_| ProjectedJsonScalar::Null)
                        .collect(),
                    present: false,
                },
                ClosedJsonOutcome::One(record) => {
                    let mut fields = record.into_fields().into_vec();
                    let outputs = operation.response().outputs().len();
                    if fields.len() != outputs + operation.response().prior_outputs().len() {
                        return Err(OfflineFixtureError::ExecutionContractViolation);
                    }
                    OperationMemory {
                        prior_outputs: fields
                            .drain(outputs..)
                            .map(|field| field.into_parts().1)
                            .collect(),
                        present: true,
                    }
                }
            });
            executed.insert(index);
        }
    }
}

fn finalize_rhai_observation(
    plan: &CompiledSourcePlan,
    memory: &[Option<OperationMemory>],
    output: crate::rhai_worker::WorkerOutput,
    calls: Vec<String>,
) -> Result<OfflineFixtureObservation, OfflineFixtureError> {
    if !memory.iter().flatten().any(|value| value.present) {
        return Ok(observation(
            OfflineFixtureOutcome::NoMatch,
            Vec::new(),
            calls,
        ));
    }
    let facts = output
        .facts
        .into_iter()
        .map(|(name, value)| rhai_output(value).map(|value| (name.into_boxed_str(), value)))
        .collect::<Result<Vec<_>, _>>()?;
    validated_observation(plan, OfflineFixtureOutcome::Match, facts, calls)
}

fn build_rhai_request(
    plan: &CompiledSourcePlan,
    inputs: &OfflineBoundInputs,
    memory: &[Option<OperationMemory>],
    executed: &BTreeSet<usize>,
) -> Result<WorkerRequest, OfflineFixtureError> {
    let (script, entrypoint) = plan
        .rhai_program()
        .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
    let limits = plan
        .runtime_profile()
        .dispatch()
        .sandboxed_rhai_limits()
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
        },
    );
    for (index, slot) in plan.inputs().enumerate() {
        let value = inputs.get(index)?.as_str().to_owned();
        request.input.insert(
            slot.name().to_owned(),
            match slot.input_type() {
                CompiledInputType::String => RhaiTypedValue::String { value: Some(value) },
                CompiledInputType::FullDate => RhaiTypedValue::Date { value: Some(value) },
            },
        );
    }
    for fact in plan.rhai_facts() {
        let (fact_type, max_bytes, minimum, maximum) = match fact.fact_type() {
            CompiledRhaiFactType::String { max_bytes } => {
                (RhaiFactType::String, Some(max_bytes as usize), None, None)
            }
            CompiledRhaiFactType::Boolean => (RhaiFactType::Boolean, None, None, None),
            CompiledRhaiFactType::Integer { minimum, maximum } => {
                (RhaiFactType::Integer, None, Some(minimum), Some(maximum))
            }
            CompiledRhaiFactType::Date => (RhaiFactType::Date, None, None, None),
            CompiledRhaiFactType::Presence => (RhaiFactType::Presence, None, None, None),
        };
        request.fact_schema.insert(
            fact.name().to_owned(),
            RhaiFactSchema {
                fact_type,
                nullable: fact.nullable(),
                max_bytes,
                minimum,
                maximum,
            },
        );
    }
    for (index, operation) in plan.operations().enumerate() {
        if !executed.contains(&index) {
            request
                .allowed_operations
                .insert(operation.id().as_str().to_owned());
        }
        let Some(observed) = memory.get(index).and_then(Option::as_ref) else {
            continue;
        };
        let mut prior = BTreeMap::from([(
            "presence".to_owned(),
            RhaiTypedValue::Presence {
                value: observed.present,
            },
        )]);
        for (slot, value) in operation
            .response()
            .prior_outputs()
            .zip(&observed.prior_outputs)
        {
            prior.insert(
                slot.name().to_owned(),
                rhai_prior(slot.shape(), slot.is_date(), value)?,
            );
        }
        request
            .prior_outputs
            .insert(operation.id().as_str().to_owned(), prior);
    }
    Ok(request)
}

fn run_rhai_worker(
    request: &WorkerRequest,
) -> Result<crate::rhai_worker::WorkerOutput, OfflineFixtureError> {
    let current =
        std::env::current_exe().map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    let directory = if current
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "deps")
    {
        current.parent().and_then(Path::parent)
    } else {
        current.parent()
    }
    .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
    let program = directory.join(format!(
        "registry-relay-rhai-worker{}",
        std::env::consts::EXE_SUFFIX
    ));
    if !program.is_file() {
        return Err(OfflineFixtureError::ExecutionContractViolation);
    }
    let worker = WorkerProcess::with_program(program);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?
        .block_on(worker.evaluate(request))
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)
}

fn rhai_prior(
    shape: &CompiledScalarShape,
    is_date: bool,
    value: &ProjectedJsonScalar,
) -> Result<RhaiTypedValue, OfflineFixtureError> {
    match (shape, value) {
        (CompiledScalarShape::String { .. }, ProjectedJsonScalar::String(value)) if is_date => {
            Ok(RhaiTypedValue::Date {
                value: Some(value.as_str().to_owned()),
            })
        }
        (CompiledScalarShape::String { .. }, ProjectedJsonScalar::String(value)) => {
            Ok(RhaiTypedValue::String {
                value: Some(value.as_str().to_owned()),
            })
        }
        (CompiledScalarShape::Boolean { .. }, ProjectedJsonScalar::Boolean(value)) => {
            Ok(RhaiTypedValue::Boolean {
                value: Some(*value),
            })
        }
        (CompiledScalarShape::Integer { .. }, ProjectedJsonScalar::Integer(value)) => {
            Ok(RhaiTypedValue::Integer {
                value: Some(*value),
            })
        }
        (CompiledScalarShape::String { .. }, ProjectedJsonScalar::Null) if is_date => {
            Ok(RhaiTypedValue::Date { value: None })
        }
        (CompiledScalarShape::String { .. }, ProjectedJsonScalar::Null) => {
            Ok(RhaiTypedValue::String { value: None })
        }
        (CompiledScalarShape::Boolean { .. }, ProjectedJsonScalar::Null) => {
            Ok(RhaiTypedValue::Boolean { value: None })
        }
        (CompiledScalarShape::Integer { .. }, ProjectedJsonScalar::Null) => {
            Ok(RhaiTypedValue::Integer { value: None })
        }
        _ => Err(OfflineFixtureError::ExecutionContractViolation),
    }
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
        RhaiTypedValue::Presence { value } => ProjectedJsonScalar::Boolean(value),
    })
}

fn execute_http(
    plan: &CompiledSourcePlan,
    inputs: &OfflineBoundInputs,
    mut source: BTreeMap<String, OfflineSourceResponse>,
) -> Result<OfflineFixtureObservation, OfflineFixtureError> {
    if plan
        .operations()
        .any(|operation| operation.dci_exact().is_some())
    {
        return execute_dci(plan, inputs, source);
    }
    validate_bounded_http_activation(plan)
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    if !inputs.is_bound_to(plan) {
        return Err(OfflineFixtureError::ExecutionContractViolation);
    }
    let allowed = plan
        .operations()
        .map(|operation| operation.id().as_str())
        .chain(
            plan.credential_operation()
                .map(|operation| operation.id().as_str()),
        )
        .collect::<BTreeSet<_>>();
    if source.keys().any(|name| !allowed.contains(name.as_str())) {
        return Err(OfflineFixtureError::UnknownSourceOperation);
    }
    let operations = plan.operations().collect::<Vec<_>>();
    let mut memory = (0..operations.len()).map(|_| None).collect::<Vec<_>>();
    let mut facts = Vec::new();
    let mut calls = Vec::new();
    let mut credential_used = false;
    for (step_position, step) in plan.compiled_steps().enumerate() {
        let index = step.operation_index();
        let operation = operations
            .get(index)
            .ok_or(OfflineFixtureError::ExecutionContractViolation)?;
        if !offline_step_should_execute(step, &memory)? {
            append_absent(operation, &mut facts);
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
                calls.push(credential.id().as_str().to_owned());
                require_basic_success(
                    source
                        .remove(credential.id().as_str())
                        .ok_or(OfflineFixtureError::MissingSourceObservation)?,
                    64 * 1024,
                )?;
                credential_used = true;
            }
        }
        calls.push(operation.id().as_str().to_owned());
        let response = source
            .remove(operation.id().as_str())
            .ok_or(OfflineFixtureError::MissingSourceObservation)?;
        let decoded = decode_operation(operation, response)?;
        match decoded {
            ClosedJsonOutcome::Ambiguous => {
                return Ok(observation(
                    OfflineFixtureOutcome::Ambiguous,
                    Vec::new(),
                    calls,
                ))
            }
            ClosedJsonOutcome::NoMatch
                if is_anchor_execution_step(index, Some(step_position), step_position, false) =>
            {
                return Ok(observation(
                    OfflineFixtureOutcome::NoMatch,
                    Vec::new(),
                    calls,
                ))
            }
            ClosedJsonOutcome::NoMatch => {
                append_absent(operation, &mut facts);
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
                facts.extend(projected.into_iter().map(|field| field.into_parts()));
                facts.extend(
                    operation
                        .response()
                        .presence_outputs()
                        .map(|field| (field.field().into(), ProjectedJsonScalar::Boolean(true))),
                );
                memory[index] = Some(OperationMemory {
                    prior_outputs,
                    present: true,
                });
            }
        }
    }
    validated_observation(plan, OfflineFixtureOutcome::Match, facts, calls)
}

fn decode_operation(
    operation: &crate::source_plan::CompiledOperation,
    response: OfflineSourceResponse,
) -> Result<ClosedJsonOutcome, OfflineFixtureError> {
    let OfflineSourceResponse::Http { status, body } = response else {
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
    if let Some(fhir) = operation.fhir_r4_search() {
        return match registry_platform_httputil::destination::fhir::normalize_r4_searchset_offline_fixture(
            &body,
            fhir.resource_type(),
            operation.response().max_records(),
        )
        .map_err(|_| OfflineFixtureError::SourceResponseMalformed)?
        {
            registry_platform_httputil::destination::fhir::FhirR4SearchsetOutcome::NoMatch => {
                Ok(ClosedJsonOutcome::NoMatch)
            }
            registry_platform_httputil::destination::fhir::FhirR4SearchsetOutcome::Ambiguous => {
                Ok(ClosedJsonOutcome::Ambiguous)
            }
            registry_platform_httputil::destination::fhir::FhirR4SearchsetOutcome::Records(body) => {
                operation.response_decoder().decode(body).map_err(map_closed_decode)
            }
        };
    }
    operation
        .response_decoder()
        .decode_offline_fixture(&body)
        .map_err(map_closed_decode)
}

fn execute_dci(
    plan: &CompiledSourcePlan,
    inputs: &OfflineBoundInputs,
    mut source: BTreeMap<String, OfflineSourceResponse>,
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
    let allowed = [
        credential.id().as_str(),
        verification.id().as_str(),
        operation.id().as_str(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if source.keys().any(|name| !allowed.contains(name.as_str())) {
        return Err(OfflineFixtureError::UnknownSourceOperation);
    }
    let calls = vec![
        credential.id().as_str().to_owned(),
        verification.id().as_str().to_owned(),
        operation.id().as_str().to_owned(),
    ];
    require_basic_success(
        source
            .remove(credential.id().as_str())
            .ok_or(OfflineFixtureError::MissingSourceObservation)?,
        64 * 1024,
    )?;
    let jwks = require_http_body(
        source
            .remove(verification.id().as_str())
            .ok_or(OfflineFixtureError::MissingSourceObservation)?,
        verification.response_max_bytes(),
    )?;
    let response = require_http_body(
        source
            .remove(operation.id().as_str())
            .ok_or(OfflineFixtureError::MissingSourceObservation)?,
        operation.response_max_bytes(),
    )?;
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
        } => SignedDciExpectation::new_generic(
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
        } => SignedDciExpectation::new_generic_exact_and(
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
                .chain(
                    operation
                        .response()
                        .presence_outputs()
                        .map(|field| (field.field().into(), ProjectedJsonScalar::Boolean(true))),
                )
                .collect(),
            calls,
        ),
    }
}

fn execute_snapshot(
    plan: &CompiledSourcePlan,
    inputs: &OfflineBoundInputs,
    mut source: BTreeMap<String, OfflineSourceResponse>,
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
    if source.keys().any(|name| name != "snapshot") {
        return Err(OfflineFixtureError::UnknownSourceOperation);
    }
    let response = source
        .remove("snapshot")
        .ok_or(OfflineFixtureError::MissingSourceObservation)?;
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
        OfflineSourceResponse::Http { status: 200, body } => {
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
    let facts = match record {
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
        validated_observation(plan, public, facts, vec!["snapshot".to_owned()])
    } else {
        Ok(observation(public, Vec::new(), vec!["snapshot".to_owned()]))
    }
}

fn snapshot_projected_value(
    shape: crate::source_plan::runtime_profile::CompiledOutputShape,
    name: &str,
    fields: &serde_json::Map<String, Value>,
) -> Result<ProjectedJsonScalar, OfflineFixtureError> {
    if matches!(
        shape,
        crate::source_plan::runtime_profile::CompiledOutputShape::Presence
    ) {
        return Ok(ProjectedJsonScalar::Boolean(true));
    }
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
        OfflineSourceResponse::Http { status: 200, body } if body.len() <= max_bytes as usize => {
            Ok(body)
        }
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
    facts: Vec<(Box<str>, ProjectedJsonScalar)>,
    calls: Vec<String>,
) -> Result<OfflineFixtureObservation, OfflineFixtureError> {
    let facts = ValidatedFactMap::try_new(plan.runtime_profile(), facts)
        .map_err(|_| OfflineFixtureError::ExecutionContractViolation)?;
    Ok(OfflineFixtureObservation {
        outcome,
        facts: facts
            .fields()
            .map(|(name, value)| (name.to_owned(), scalar_value(value)))
            .collect(),
        calls,
    })
}

fn observation(
    outcome: OfflineFixtureOutcome,
    facts: Vec<(String, Value)>,
    calls: Vec<String>,
) -> OfflineFixtureObservation {
    OfflineFixtureObservation {
        outcome,
        facts: facts.into_iter().collect(),
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
    facts: &mut Vec<(Box<str>, ProjectedJsonScalar)>,
) {
    facts.extend(
        operation
            .response()
            .outputs()
            .map(|field| (field.field().into(), ProjectedJsonScalar::Null)),
    );
    facts.extend(
        operation
            .response()
            .presence_outputs()
            .map(|field| (field.field().into(), ProjectedJsonScalar::Boolean(false))),
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
        assert!((1..=4).contains(&count));
        let mut pack: Value = serde_json::from_slice(PACK).expect("pack JSON");
        let mut contract: Value = serde_json::from_slice(CONTRACT).expect("contract JSON");
        let mut binding: Value = serde_json::from_slice(BINDING).expect("binding JSON");
        let additions = [
            (
                "birth_date",
                "birthDate",
                serde_json::json!({
                    "type": "full_date",
                    "max_bytes": 10,
                    "pattern": "^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$",
                    "canonicalization": "identity"
                }),
            ),
            (
                "country_code",
                "countryCode",
                serde_json::json!({
                    "type": "string",
                    "max_bytes": 2,
                    "pattern": "^[A-Z][A-Z]$",
                    "canonicalization": "identity"
                }),
            ),
            (
                "zone",
                "zone",
                serde_json::json!({
                    "type": "string",
                    "max_bytes": 5,
                    "pattern": "^[a-z][a-z][a-z][a-z][a-z]$",
                    "canonicalization": "ascii_lowercase"
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

        let pack_bytes = serde_json::to_vec(&pack).expect("pack bytes");
        let pack = compile_integration_pack(&pack_bytes)
            .unwrap_or_else(|error| panic!("{count}-input composite pack: {error:?}"));
        contract["spec"]["integration_pack"]["hash"] = Value::String(pack.typed_hash().to_owned());
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
            source: BTreeMap::from([(
                "lookup-enrollment-status".to_owned(),
                OfflineSourceResponse::Http {
                    status: 200,
                    body: serde_json::to_vec(&body).expect("body"),
                },
            )]),
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
            matched.facts,
            BTreeMap::from([("status".to_owned(), Value::String("ACTIVE".to_owned()))])
        );
        assert_eq!(matched.calls, ["lookup-enrollment-status"]);

        let no_match = harness
            .execute(request(profile.clone(), "Abc12345678", dhis2_body(&[])))
            .expect("no match");
        assert_eq!(no_match.outcome, OfflineFixtureOutcome::NoMatch);
        assert!(no_match.facts.is_empty());

        let ambiguous = harness
            .execute(request(
                profile,
                "Abc12345678",
                dhis2_body(&["ACTIVE", "COMPLETED"]),
            ))
            .expect("ambiguity");
        assert_eq!(ambiguous.outcome, OfflineFixtureOutcome::Ambiguous);
        assert!(ambiguous.facts.is_empty());
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
        oversized.source.insert(
            "lookup-enrollment-status".to_owned(),
            OfflineSourceResponse::DeclaredBodyBytes {
                status: 200,
                body_bytes: 8193,
            },
        );
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
    fn one_through_four_exact_inputs_execute_in_compiled_byte_order() {
        for count in 1..=4 {
            let (harness, profile) = harness_with_input_count(count);
            let mut fixture = request(profile, "Abc12345678", dhis2_body(&["ACTIVE"]));
            if count >= 2 {
                fixture
                    .input
                    .insert("birth_date".to_owned(), "2000-02-29".to_owned());
            }
            if count >= 3 {
                fixture
                    .input
                    .insert("country_code".to_owned(), "TH".to_owned());
            }
            if count >= 4 {
                fixture.input.insert("zone".to_owned(), "NORTH".to_owned());
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
    fn exact_profile_pin_and_source_closure_fail_closed() {
        let (runner, mut profile) = harness();
        profile.contract_hash = format!("sha256:{}", "0".repeat(64));
        assert_eq!(
            runner.execute(request(profile, "Abc12345678", dhis2_body(&[]))),
            Err(OfflineFixtureError::ProfileNotFound)
        );
        let (runner, profile) = harness();
        let mut unknown = request(profile, "Abc12345678", dhis2_body(&[]));
        unknown.source.insert(
            "attacker-selected".to_owned(),
            OfflineSourceResponse::Unavailable,
        );
        assert_eq!(
            runner.execute(unknown),
            Err(OfflineFixtureError::UnknownSourceOperation)
        );
    }

    #[test]
    fn sandboxed_rhai_no_match_discards_the_complete_worker_fact_map() {
        let plan = crate::source_plan::rhai_runtime_vector_plan_fixture();
        let facts = plan
            .rhai_facts()
            .map(|fact| {
                let value = match fact.fact_type() {
                    CompiledRhaiFactType::String { .. } => RhaiTypedValue::String {
                        value: (!fact.nullable()).then(|| "absent".to_owned()),
                    },
                    CompiledRhaiFactType::Boolean => RhaiTypedValue::Boolean {
                        value: (!fact.nullable()).then_some(false),
                    },
                    CompiledRhaiFactType::Integer { minimum, .. } => RhaiTypedValue::Integer {
                        value: (!fact.nullable()).then_some(minimum),
                    },
                    CompiledRhaiFactType::Date => RhaiTypedValue::Date {
                        value: (!fact.nullable()).then(|| "2000-01-01".to_owned()),
                    },
                    CompiledRhaiFactType::Presence => RhaiTypedValue::Presence { value: false },
                };
                (fact.name().to_owned(), value)
            })
            .collect::<BTreeMap<_, _>>();
        assert!(!facts.is_empty());
        let memory = plan
            .operations()
            .map(|operation| {
                Some(OperationMemory {
                    prior_outputs: (0..operation.response().prior_outputs().len())
                        .map(|_| ProjectedJsonScalar::Null)
                        .collect(),
                    present: false,
                })
            })
            .collect::<Vec<_>>();
        let result = finalize_rhai_observation(
            &plan,
            &memory,
            crate::rhai_worker::WorkerOutput {
                operation_choices: Vec::new(),
                facts,
            },
            vec!["lookup".to_owned()],
        )
        .expect("no-match observation");
        assert_eq!(result.outcome, OfflineFixtureOutcome::NoMatch);
        assert!(result.facts.is_empty());
        assert_eq!(result.calls, ["lookup"]);
    }

    #[test]
    fn snapshot_match_materializes_presence_without_a_physical_presence_field() {
        let fields = serde_json::Map::from_iter([
            (
                "registration_status".to_owned(),
                Value::String("active".to_owned()),
            ),
            ("eligible".to_owned(), Value::Bool(true)),
        ]);
        assert!(matches!(
            snapshot_projected_value(
                crate::source_plan::runtime_profile::CompiledOutputShape::Presence,
                "exists",
                &fields,
            ),
            Ok(ProjectedJsonScalar::Boolean(true))
        ));
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
        let rendered = format!("{request:?} {:?}", request.source.values().next());
        assert!(!rendered.contains("secret-selector"));
        assert!(!rendered.contains("secret-body"));
        assert!(!rendered.contains("secret-source-value"));
        drop(harness);
    }
}

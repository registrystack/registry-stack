// SPDX-License-Identifier: Apache-2.0
//! One-shot, process-isolated Rhai normalization worker.
//!
//! The parent sends only typed integration inputs, typed prior operation
//! outputs, the closed fact schema, and names of precompiled operations. The
//! child has no source, credential, authorization, policy, or provenance
//! authority. It evaluates one request and exits.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    io::{BufRead, Read, Write},
    path::PathBuf,
    process::{ExitCode, Stdio},
    time::{Duration, Instant},
};

use rhai::{
    packages::{
        BasicArrayPackage, BasicMapPackage, BasicMathPackage, CorePackage, LogicPackage,
        MoreStringPackage, Package,
    },
    serde::{from_dynamic, to_dynamic},
    Dynamic, Engine, EvalAltResult, Scope,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::Date;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    process::Command,
    time as tokio_time,
};

const WORKER_MODE: &str = "__registry-relay-rhai-worker-v1";
const PROTOCOL_VERSION: u8 = 1;
const MAX_IPC_REQUEST_BYTES: usize = 512 * 1024;
const MAX_SCRIPT_BYTES: usize = 128 * 1024;
const MAX_NAMES: usize = 64;
const MAX_PRIOR_OPERATIONS: usize = 16;
const MAX_NAME_BYTES: usize = 128;
const MAX_VALUE_STRING_BYTES: usize = 64 * 1024;
const MIN_OUTPUT_BYTES: usize = 256;
const MAX_OUTPUT_BYTES: usize = 256 * 1024;
const MIN_IPC_FRAME_BYTES: usize = 256;
const MIN_MEMORY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MEMORY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_OPERATIONS: u64 = 5_000_000;
const MAX_CALL_LEVELS: usize = 64;
const MAX_EXPR_DEPTH: usize = 128;
const MAX_COLLECTION_ITEMS: usize = 4_096;
const MAX_WALL_TIME_MS: u64 = 5_000;
const WORKER_STARTUP_GRACE: Duration = if cfg!(debug_assertions) {
    // Unoptimized Relay and registryctl binaries can take several seconds to
    // fault in under a loaded test runner. This does not widen the child
    // engine or OS execution budgets.
    Duration::from_secs(10)
} else {
    Duration::from_secs(2)
};
const MAX_JSON_INTEROPERABLE_INTEGER: i64 = (1_i64 << 53) - 1;

/// Resource limits enforced independently by the parent, child process, and
/// Rhai engine.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerLimits {
    pub max_operations: u64,
    pub max_call_levels: usize,
    pub max_expr_depth: usize,
    pub max_string_bytes: usize,
    pub max_array_items: usize,
    pub max_map_entries: usize,
    pub max_output_bytes: usize,
    pub max_ipc_frame_bytes: usize,
    pub max_memory_bytes: u64,
    pub wall_time_ms: u64,
}

impl Default for WorkerLimits {
    fn default() -> Self {
        Self {
            max_operations: 100_000,
            max_call_levels: 24,
            max_expr_depth: 64,
            max_string_bytes: 16 * 1024,
            max_array_items: 256,
            max_map_entries: 256,
            max_output_bytes: 64 * 1024,
            max_ipc_frame_bytes: 128 * 1024,
            max_memory_bytes: MAX_MEMORY_BYTES,
            wall_time_ms: 2_000,
        }
    }
}

/// The closed v1 fact types. Floating-point values are intentionally absent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FactType {
    String,
    Boolean,
    Integer,
    Date,
    Presence,
}

/// Expected type and nullability for one output fact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FactSchema {
    pub fact_type: FactType,
    #[serde(default)]
    pub nullable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<i64>,
}

/// A typed value crossing the worker boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypedValue {
    String { value: Option<String> },
    Boolean { value: Option<bool> },
    Integer { value: Option<i64> },
    Date { value: Option<String> },
    Presence { value: bool },
}

impl TypedValue {
    fn fact_type(&self) -> FactType {
        match self {
            Self::String { .. } => FactType::String,
            Self::Boolean { .. } => FactType::Boolean,
            Self::Integer { .. } => FactType::Integer,
            Self::Date { .. } => FactType::Date,
            Self::Presence { .. } => FactType::Presence,
        }
    }

    fn is_null(&self) -> bool {
        match self {
            Self::String { value } => value.is_none(),
            Self::Boolean { value } => value.is_none(),
            Self::Integer { value } => value.is_none(),
            Self::Date { value } => value.is_none(),
            Self::Presence { .. } => false,
        }
    }

    fn validate(&self, max_string_bytes: usize) -> Result<(), WorkerError> {
        match self {
            Self::String { value: Some(value) } if value.len() > max_string_bytes => {
                Err(WorkerError::ContractViolation)
            }
            Self::Date { value: Some(value) }
                if value.len() != 10
                    || Date::parse(
                        value,
                        &time::macros::format_description!("[year]-[month]-[day]"),
                    )
                    .is_err() =>
            {
                Err(WorkerError::ContractViolation)
            }
            _ => Ok(()),
        }
    }

    fn as_script_value(&self) -> serde_json::Value {
        match self {
            Self::String { value } | Self::Date { value } => value
                .as_ref()
                .map_or(serde_json::Value::Null, |value| value.clone().into()),
            Self::Boolean { value } => {
                value.map_or(serde_json::Value::Null, serde_json::Value::Bool)
            }
            Self::Integer { value } => value.map_or(serde_json::Value::Null, |value| value.into()),
            Self::Presence { value } => serde_json::Value::Bool(*value),
        }
    }
}

/// Complete input for one isolated evaluation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequest {
    pub protocol_version: u8,
    pub script: String,
    pub entrypoint: String,
    pub input: BTreeMap<String, TypedValue>,
    pub prior_outputs: BTreeMap<String, BTreeMap<String, TypedValue>>,
    pub allowed_operations: BTreeSet<String>,
    pub fact_schema: BTreeMap<String, FactSchema>,
    pub limits: WorkerLimits,
}

impl WorkerRequest {
    /// Builds a request for the fixed v1 protocol.
    pub fn v1(
        script: impl Into<String>,
        entrypoint: impl Into<String>,
        limits: WorkerLimits,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            script: script.into(),
            entrypoint: entrypoint.into(),
            input: BTreeMap::new(),
            prior_outputs: BTreeMap::new(),
            allowed_operations: BTreeSet::new(),
            fact_schema: BTreeMap::new(),
            limits,
        }
    }
}

/// Closed result from a successful worker evaluation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerOutput {
    #[serde(rename = "operations")]
    pub operation_choices: Vec<String>,
    pub outputs: BTreeMap<String, TypedValue>,
}

/// Non-sensitive failure classes. Script source, typed inputs, prior outputs,
/// and child output are never included in errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkerError {
    #[error("Rhai worker request violates the closed contract")]
    ContractViolation,
    #[error("Rhai worker request exceeds a resource limit")]
    RequestTooLarge,
    #[error("Rhai worker could not be started")]
    SpawnFailed,
    #[error("Rhai worker IPC failed")]
    IpcFailed,
    #[error("Rhai worker timed out")]
    TimedOut,
    #[error("Rhai worker exceeded a resource budget")]
    BudgetExceeded,
    #[error("Rhai script was rejected")]
    ScriptRejected,
    #[error("Rhai worker sandbox could not be established")]
    SandboxUnavailable,
}

/// A fresh-process launcher. Every call spawns one worker, sends one request,
/// receives one response, and waits for that process to exit.
#[derive(Clone, Debug)]
pub struct WorkerProcess {
    program: PathBuf,
}

impl WorkerProcess {
    /// Uses the currently running Relay executable as the worker program.
    pub fn current_executable() -> Result<Self, WorkerError> {
        std::env::current_exe()
            .map(|program| Self { program })
            .map_err(|_| WorkerError::SpawnFailed)
    }

    /// Selects the code-owned minimal worker installed beside Relay.
    ///
    /// The path is derived only from the running executable. Configuration,
    /// environment variables, scripts, and callers cannot select a program.
    pub fn dedicated_executable() -> Result<Self, WorkerError> {
        let current = std::env::current_exe().map_err(|_| WorkerError::SpawnFailed)?;
        let parent = current.parent().ok_or(WorkerError::SpawnFailed)?;
        let directory = if parent
            .file_name()
            .is_some_and(|name| name == OsStr::new("deps"))
        {
            parent.parent().ok_or(WorkerError::SpawnFailed)?
        } else {
            parent
        };
        let program = directory.join(format!(
            "registry-relay-rhai-worker{}",
            std::env::consts::EXE_SUFFIX
        ));
        program
            .is_file()
            .then_some(Self { program })
            .ok_or(WorkerError::SpawnFailed)
    }

    /// Uses an explicitly selected Relay executable.
    pub fn with_program(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }

    /// Executes one request in a fresh, environment-scrubbed child process.
    pub async fn evaluate(&self, request: &WorkerRequest) -> Result<WorkerOutput, WorkerError> {
        validate_request(request)?;
        let mut request_line = serde_json::to_vec(request).map_err(|_| WorkerError::IpcFailed)?;
        if request_line.len() + 1 > request.limits.max_ipc_frame_bytes {
            return Err(WorkerError::RequestTooLarge);
        }
        request_line.push(b'\n');

        let response_cap = request
            .limits
            .max_ipc_frame_bytes
            .min(request.limits.max_output_bytes.saturating_add(512))
            + 1;
        // The child enforces the reviewed execution budget after startup with
        // its Rhai deadline and OS resource limits. Keep process loading and
        // IPC setup outside that script budget, but bound them by one fixed,
        // non-configurable parent grace interval.
        let timeout =
            Duration::from_millis(request.limits.wall_time_ms).saturating_add(WORKER_STARTUP_GRACE);
        let mut command = Command::new(&self.program);
        command
            .arg(WORKER_MODE)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|_| WorkerError::SpawnFailed)?;
        let mut stdin = child.stdin.take().ok_or(WorkerError::IpcFailed)?;
        let stdout = child.stdout.take().ok_or(WorkerError::IpcFailed)?;
        let exchange = async {
            stdin
                .write_all(&request_line)
                .await
                .map_err(|_| WorkerError::IpcFailed)?;
            stdin.shutdown().await.map_err(|_| WorkerError::IpcFailed)?;
            drop(stdin);
            let mut response = Vec::with_capacity(response_cap.min(8 * 1024));
            tokio::io::BufReader::new(stdout)
                .take(response_cap as u64)
                .read_until(b'\n', &mut response)
                .await
                .map_err(|_| WorkerError::IpcFailed)?;
            let _ = child.kill().await;
            let _ = child.wait().await;
            Ok::<_, WorkerError>(response)
        };
        let response = match tokio_time::timeout(timeout, exchange).await {
            Ok(result) => result?,
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(WorkerError::TimedOut);
            }
        };
        if response.len() >= response_cap {
            return Err(WorkerError::BudgetExceeded);
        }
        let envelope = decode_response_line(&response)?;
        match envelope {
            WorkerEnvelope::Ok { output } => {
                validate_output(request, &output)?;
                Ok(output)
            }
            WorkerEnvelope::Error { error } => Err(error.into()),
        }
    }
}

/// Compiles a reviewed script under the production language surface and
/// verifies its authored two-argument entrypoint without executing it.
/// Activation can use this probe before minting a worker capability.
pub fn probe_script(
    script: &str,
    entrypoint: &str,
    limits: WorkerLimits,
) -> Result<(), WorkerError> {
    validate_limits(&limits)?;
    if script.is_empty() || script.len() > MAX_SCRIPT_BYTES {
        return Err(WorkerError::ContractViolation);
    }
    validate_entrypoint(entrypoint)?;
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(limits.wall_time_ms))
        .ok_or(WorkerError::ContractViolation)?;
    let engine = hardened_engine(&limits, deadline);
    let ast = engine
        .compile(script)
        .map_err(|_| WorkerError::ScriptRejected)?;
    if ast
        .iter_functions()
        .any(|function| function.name == entrypoint && function.params.len() == 2)
    {
        Ok(())
    } else {
        Err(WorkerError::ScriptRejected)
    }
}

/// Returns true only for the exact internal worker invocation.
#[doc(hidden)]
pub fn is_worker_invocation<I>(args: I) -> bool
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let _program = args.next();
    matches!(args.next().as_deref(), Some(mode) if mode == OsStr::new(WORKER_MODE))
        && args.next().is_none()
}

/// Runs the hidden one-shot worker protocol on standard input/output.
#[doc(hidden)]
pub fn run_worker_stdio() -> ExitCode {
    let mut frame_limit = MAX_IPC_REQUEST_BYTES;
    let result = match read_request_line() {
        Ok(request) => {
            frame_limit = request
                .limits
                .max_ipc_frame_bytes
                .min(MAX_IPC_REQUEST_BYTES);
            (|| {
                validate_request(&request)?;
                apply_process_sandbox(&request.limits)?;
                evaluate_in_process(&request)
            })()
        }
        Err(error) => Err(error),
    }
    .and_then(|output| {
        let envelope = WorkerEnvelope::Ok { output };
        write_response_line(&envelope, frame_limit)
    });

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let envelope = WorkerEnvelope::Error {
                error: error.into(),
            };
            let _ = write_response_line(&envelope, frame_limit);
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum WorkerEnvelope {
    Ok { output: WorkerOutput },
    Error { error: WorkerFailure },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WorkerFailure {
    ContractViolation,
    RequestTooLarge,
    IpcFailed,
    BudgetExceeded,
    ScriptRejected,
    SandboxUnavailable,
}

impl From<WorkerError> for WorkerFailure {
    fn from(error: WorkerError) -> Self {
        match error {
            WorkerError::ContractViolation => Self::ContractViolation,
            WorkerError::RequestTooLarge => Self::RequestTooLarge,
            WorkerError::BudgetExceeded => Self::BudgetExceeded,
            WorkerError::ScriptRejected => Self::ScriptRejected,
            WorkerError::SandboxUnavailable => Self::SandboxUnavailable,
            WorkerError::SpawnFailed | WorkerError::IpcFailed | WorkerError::TimedOut => {
                Self::IpcFailed
            }
        }
    }
}

impl From<WorkerFailure> for WorkerError {
    fn from(error: WorkerFailure) -> Self {
        match error {
            WorkerFailure::ContractViolation => Self::ContractViolation,
            WorkerFailure::RequestTooLarge => Self::RequestTooLarge,
            WorkerFailure::IpcFailed => Self::IpcFailed,
            WorkerFailure::BudgetExceeded => Self::BudgetExceeded,
            WorkerFailure::ScriptRejected => Self::ScriptRejected,
            WorkerFailure::SandboxUnavailable => Self::SandboxUnavailable,
        }
    }
}

fn validate_limits(limits: &WorkerLimits) -> Result<(), WorkerError> {
    if !(1..=MAX_OPERATIONS).contains(&limits.max_operations)
        || !(1..=MAX_CALL_LEVELS).contains(&limits.max_call_levels)
        || !(1..=MAX_EXPR_DEPTH).contains(&limits.max_expr_depth)
        || !(1..=MAX_VALUE_STRING_BYTES).contains(&limits.max_string_bytes)
        || !(1..=MAX_COLLECTION_ITEMS).contains(&limits.max_array_items)
        || !(1..=MAX_COLLECTION_ITEMS).contains(&limits.max_map_entries)
        || !(MIN_OUTPUT_BYTES..=MAX_OUTPUT_BYTES).contains(&limits.max_output_bytes)
        || !(MIN_IPC_FRAME_BYTES..=MAX_IPC_REQUEST_BYTES).contains(&limits.max_ipc_frame_bytes)
        || !(MIN_MEMORY_BYTES..=MAX_MEMORY_BYTES).contains(&limits.max_memory_bytes)
        || !(1..=MAX_WALL_TIME_MS).contains(&limits.wall_time_ms)
    {
        return Err(WorkerError::ContractViolation);
    }
    Ok(())
}

fn validate_request(request: &WorkerRequest) -> Result<(), WorkerError> {
    validate_limits(&request.limits)?;
    if request.protocol_version != PROTOCOL_VERSION
        || request.script.is_empty()
        || request.script.len() > MAX_SCRIPT_BYTES
        || request.input.len() > MAX_NAMES
        || request.prior_outputs.len() > MAX_PRIOR_OPERATIONS
        || request.allowed_operations.len() > MAX_NAMES
        || request.fact_schema.len() > MAX_NAMES
    {
        return Err(WorkerError::ContractViolation);
    }
    validate_entrypoint(&request.entrypoint)?;
    let encoded = serde_json::to_vec(request).map_err(|_| WorkerError::ContractViolation)?;
    if encoded.len() + 1 > request.limits.max_ipc_frame_bytes {
        return Err(WorkerError::RequestTooLarge);
    }
    for name in request
        .input
        .keys()
        .chain(request.prior_outputs.keys())
        .chain(request.allowed_operations.iter())
        .chain(request.fact_schema.keys())
    {
        validate_name(name)?;
    }
    for value in request.input.values() {
        value.validate(request.limits.max_string_bytes)?;
    }
    for schema in request.fact_schema.values() {
        validate_fact_schema(schema, request.limits.max_string_bytes)?;
    }
    for output in request.prior_outputs.values() {
        if output.len() > MAX_NAMES {
            return Err(WorkerError::ContractViolation);
        }
        for (name, value) in output {
            validate_name(name)?;
            value.validate(request.limits.max_string_bytes)?;
        }
    }
    Ok(())
}

fn validate_fact_schema(schema: &FactSchema, max_string_bytes: usize) -> Result<(), WorkerError> {
    let valid = match schema.fact_type {
        FactType::String => {
            schema
                .max_bytes
                .is_some_and(|value| (1..=max_string_bytes).contains(&value))
                && schema.minimum.is_none()
                && schema.maximum.is_none()
        }
        FactType::Integer => {
            schema.max_bytes.is_none()
                && matches!((schema.minimum, schema.maximum), (Some(minimum), Some(maximum))
                    if minimum <= maximum
                        && minimum >= -MAX_JSON_INTEROPERABLE_INTEGER
                        && maximum <= MAX_JSON_INTEROPERABLE_INTEGER)
        }
        FactType::Boolean | FactType::Date | FactType::Presence => {
            schema.max_bytes.is_none() && schema.minimum.is_none() && schema.maximum.is_none()
        }
    };
    valid.then_some(()).ok_or(WorkerError::ContractViolation)
}

fn validate_name(name: &str) -> Result<(), WorkerError> {
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(WorkerError::ContractViolation);
    }
    Ok(())
}

fn validate_entrypoint(entrypoint: &str) -> Result<(), WorkerError> {
    let mut bytes = entrypoint.bytes();
    if !matches!(bytes.next(), Some(b'a'..=b'z'))
        || entrypoint.len() > 96
        || !bytes.all(|byte| {
            matches!(
                byte,
                b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'-'
            )
        })
    {
        return Err(WorkerError::ContractViolation);
    }
    Ok(())
}

fn validate_output(request: &WorkerRequest, output: &WorkerOutput) -> Result<(), WorkerError> {
    let mut choices = BTreeSet::new();
    for choice in &output.operation_choices {
        if !request.allowed_operations.contains(choice) || !choices.insert(choice) {
            return Err(WorkerError::ContractViolation);
        }
    }
    if !output.operation_choices.is_empty() {
        if !output.outputs.is_empty() {
            return Err(WorkerError::ContractViolation);
        }
        return validate_output_size(request, output);
    }
    if output.outputs.keys().ne(request.fact_schema.keys()) {
        return Err(WorkerError::ContractViolation);
    }
    for (name, value) in &output.outputs {
        let schema = request
            .fact_schema
            .get(name)
            .ok_or(WorkerError::ContractViolation)?;
        if value.fact_type() != schema.fact_type || (value.is_null() && !schema.nullable) {
            return Err(WorkerError::ContractViolation);
        }
        value.validate(request.limits.max_string_bytes)?;
        let within_fact_bound = match (value, schema.fact_type) {
            (TypedValue::String { value: Some(value) }, FactType::String) => schema
                .max_bytes
                .is_some_and(|maximum| value.len() <= maximum),
            (TypedValue::Integer { value: Some(value) }, FactType::Integer) => matches!(
                (schema.minimum, schema.maximum),
                (Some(minimum), Some(maximum)) if (minimum..=maximum).contains(value)
            ),
            _ => true,
        };
        if !within_fact_bound {
            return Err(WorkerError::ContractViolation);
        }
    }
    validate_output_size(request, output)
}

fn validate_output_size(request: &WorkerRequest, output: &WorkerOutput) -> Result<(), WorkerError> {
    let encoded = serde_json::to_vec(output).map_err(|_| WorkerError::ContractViolation)?;
    if encoded.len() > request.limits.max_output_bytes {
        return Err(WorkerError::BudgetExceeded);
    }
    Ok(())
}

fn build_input(request: &WorkerRequest) -> BTreeMap<String, serde_json::Value> {
    request
        .input
        .iter()
        .map(|(name, value)| (name.clone(), value.as_script_value()))
        .collect()
}

fn build_prior_outputs(
    request: &WorkerRequest,
) -> BTreeMap<String, BTreeMap<String, serde_json::Value>> {
    request
        .prior_outputs
        .iter()
        .map(|(operation, facts)| {
            (
                operation.clone(),
                facts
                    .iter()
                    .map(|(name, value)| (name.clone(), value.as_script_value()))
                    .collect(),
            )
        })
        .collect()
}

fn hardened_engine(limits: &WorkerLimits, deadline: Instant) -> Engine {
    let mut engine = Engine::new_raw();
    CorePackage::new().register_into_engine(&mut engine);
    LogicPackage::new().register_into_engine(&mut engine);
    BasicMathPackage::new().register_into_engine(&mut engine);
    BasicArrayPackage::new().register_into_engine(&mut engine);
    BasicMapPackage::new().register_into_engine(&mut engine);
    MoreStringPackage::new().register_into_engine(&mut engine);

    engine
        .set_max_operations(limits.max_operations)
        .set_max_call_levels(limits.max_call_levels)
        .set_max_expr_depths(limits.max_expr_depth, limits.max_expr_depth)
        .set_max_string_size(limits.max_string_bytes)
        .set_max_array_size(limits.max_array_items)
        .set_max_map_size(limits.max_map_entries)
        .set_max_modules(0)
        .set_max_variables(256)
        .set_max_functions(64)
        .disable_symbol("eval")
        .disable_symbol("import")
        .disable_symbol("export")
        .disable_symbol("print")
        .disable_symbol("debug")
        .disable_symbol("timestamp");
    engine.on_print(|_| {});
    engine.on_debug(|_, _, _| {});
    engine.on_progress(move |_| (Instant::now() >= deadline).then_some(Dynamic::UNIT));
    engine
}

fn evaluate_in_process(request: &WorkerRequest) -> Result<WorkerOutput, WorkerError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(request.limits.wall_time_ms))
        .ok_or(WorkerError::ContractViolation)?;
    let engine = hardened_engine(&request.limits, deadline);
    let ast = engine
        .compile(&request.script)
        .map_err(|_| WorkerError::ScriptRejected)?;
    let input = to_dynamic(build_input(request)).map_err(|_| WorkerError::ContractViolation)?;
    let prior =
        to_dynamic(build_prior_outputs(request)).map_err(|_| WorkerError::ContractViolation)?;
    let dynamic = engine
        .call_fn::<Dynamic>(&mut Scope::new(), &ast, &request.entrypoint, (input, prior))
        .map_err(classify_rhai_error)?;
    let output =
        from_dynamic::<WorkerOutput>(&dynamic).map_err(|_| WorkerError::ContractViolation)?;
    validate_output(request, &output)?;
    Ok(output)
}

fn classify_rhai_error(error: Box<EvalAltResult>) -> WorkerError {
    if rhai_budget_error(&error) {
        WorkerError::BudgetExceeded
    } else {
        WorkerError::ScriptRejected
    }
}

fn rhai_budget_error(error: &EvalAltResult) -> bool {
    match error {
        EvalAltResult::ErrorTooManyOperations(_)
        | EvalAltResult::ErrorTooManyVariables(_)
        | EvalAltResult::ErrorTooManyModules(_)
        | EvalAltResult::ErrorStackOverflow(_)
        | EvalAltResult::ErrorDataTooLarge(_, _)
        | EvalAltResult::ErrorTerminated(_, _) => true,
        EvalAltResult::ErrorInFunctionCall(_, _, source, _)
        | EvalAltResult::ErrorInModule(_, source, _) => rhai_budget_error(source),
        _ => false,
    }
}

fn read_request_line() -> Result<WorkerRequest, WorkerError> {
    let mut bytes = Vec::with_capacity(8 * 1024);
    std::io::BufReader::new(std::io::stdin().lock())
        .take((MAX_IPC_REQUEST_BYTES + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| WorkerError::IpcFailed)?;
    if bytes.is_empty() || bytes.len() > MAX_IPC_REQUEST_BYTES || bytes.last() != Some(&b'\n') {
        return Err(WorkerError::RequestTooLarge);
    }
    bytes.pop();
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return Err(WorkerError::ContractViolation);
    }
    serde_json::from_slice(&bytes).map_err(|_| WorkerError::ContractViolation)
}

fn write_response_line(
    envelope: &WorkerEnvelope,
    max_frame_bytes: usize,
) -> Result<(), WorkerError> {
    let mut bytes = serde_json::to_vec(envelope).map_err(|_| WorkerError::IpcFailed)?;
    if bytes.len() + 1 > max_frame_bytes.min(MAX_IPC_REQUEST_BYTES) {
        return Err(WorkerError::BudgetExceeded);
    }
    bytes.push(b'\n');
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&bytes)
        .and_then(|()| stdout.flush())
        .map_err(|_| WorkerError::IpcFailed)
}

fn decode_response_line(bytes: &[u8]) -> Result<WorkerEnvelope, WorkerError> {
    if bytes.is_empty() || bytes.last() != Some(&b'\n') {
        return Err(WorkerError::IpcFailed);
    }
    let body = &bytes[..bytes.len() - 1];
    if body.contains(&b'\n') || body.contains(&b'\r') {
        return Err(WorkerError::IpcFailed);
    }
    serde_json::from_slice(body).map_err(|_| WorkerError::IpcFailed)
}

#[cfg(unix)]
fn apply_process_sandbox(limits: &WorkerLimits) -> Result<(), WorkerError> {
    use nix::sys::resource::{setrlimit, Resource};

    let set = |resource, value| {
        setrlimit(resource, value, value).map_err(|_| WorkerError::SandboxUnavailable)
    };
    let cpu_seconds = limits.wall_time_ms.div_ceil(1_000).max(1);
    set(Resource::RLIMIT_CPU, cpu_seconds)?;
    set(Resource::RLIMIT_FSIZE, limits.max_output_bytes as u64)?;
    set(Resource::RLIMIT_NOFILE, 16)?;
    set(Resource::RLIMIT_CORE, 0)?;
    #[cfg(target_os = "linux")]
    {
        set(Resource::RLIMIT_DATA, limits.max_memory_bytes)?;
        set(Resource::RLIMIT_AS, limits.max_memory_bytes)?;
        set(Resource::RLIMIT_NPROC, 1)?;
        nix::sys::prctl::set_no_new_privs().map_err(|_| WorkerError::SandboxUnavailable)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_process_sandbox(_limits: &WorkerLimits) -> Result<(), WorkerError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(script: &str) -> WorkerRequest {
        let mut request = WorkerRequest::v1(script, "consult", WorkerLimits::default());
        request.allowed_operations.insert("lookup".to_string());
        request.fact_schema.insert(
            "active".to_string(),
            FactSchema {
                fact_type: FactType::Boolean,
                nullable: false,
                max_bytes: None,
                minimum: None,
                maximum: None,
            },
        );
        request
    }

    #[test]
    fn deterministic_typed_output_is_closed() {
        let request = request(
            r#"
                fn consult(input, prior) {
                    #{ operations: [], outputs: #{
                        active: #{ type: "boolean", value: true }
                    }}
                }
            "#,
        );
        let first = evaluate_in_process(&request).expect("first evaluation");
        let second = evaluate_in_process(&request).expect("second evaluation");
        assert_eq!(first, second);
        assert!(first.operation_choices.is_empty());
    }

    #[test]
    fn iterative_choice_has_no_outputs_and_final_result_has_exact_outputs() {
        let script = r#"
            fn consult(input, prior) {
                if prior.contains("lookup") {
                    #{ operations: [], outputs: #{
                        active: #{ type: "boolean", value: prior.lookup.active }
                    }}
                } else {
                    #{ operations: ["lookup"], outputs: #{} }
                }
            }
        "#;
        let mut request = request(script);
        let choice = evaluate_in_process(&request).expect("operation choice");
        assert_eq!(choice.operation_choices, ["lookup"]);
        assert!(choice.outputs.is_empty());

        request.prior_outputs.insert(
            "lookup".to_string(),
            BTreeMap::from([(
                "active".to_string(),
                TypedValue::Boolean { value: Some(true) },
            )]),
        );
        let final_output = evaluate_in_process(&request).expect("final typed outputs");
        assert!(final_output.operation_choices.is_empty());
        assert_eq!(
            final_output.outputs.get("active"),
            Some(&TypedValue::Boolean { value: Some(true) })
        );
    }

    #[test]
    fn legacy_facts_result_key_is_rejected_without_an_alias() {
        let request = request(
            r#"
                fn consult(input, prior) {
                    #{ operations: [], facts: #{
                        active: #{ type: "boolean", value: true }
                    }}
                }
            "#,
        );

        assert_eq!(
            evaluate_in_process(&request),
            Err(WorkerError::ContractViolation)
        );
    }

    #[test]
    fn terminal_outputs_cannot_exceed_their_compiled_string_or_integer_bounds() {
        let mut string_request = WorkerRequest::v1(
            r#"fn consult(input, prior) { #{ operations: [], outputs: #{ value: #{ type: "string", value: "12345" } } } }"#,
            "consult",
            WorkerLimits::default(),
        );
        string_request.fact_schema.insert(
            "value".to_string(),
            FactSchema {
                fact_type: FactType::String,
                nullable: false,
                max_bytes: Some(4),
                minimum: None,
                maximum: None,
            },
        );
        assert_eq!(
            evaluate_in_process(&string_request),
            Err(WorkerError::ContractViolation)
        );

        let mut integer_request = WorkerRequest::v1(
            r#"fn consult(input, prior) { #{ operations: [], outputs: #{ value: #{ type: "integer", value: 3 } } } }"#,
            "consult",
            WorkerLimits::default(),
        );
        integer_request.fact_schema.insert(
            "value".to_string(),
            FactSchema {
                fact_type: FactType::Integer,
                nullable: false,
                max_bytes: None,
                minimum: Some(-2),
                maximum: Some(2),
            },
        );
        assert_eq!(
            evaluate_in_process(&integer_request),
            Err(WorkerError::ContractViolation)
        );
    }

    #[test]
    fn instruction_and_call_depth_limits_deny_execution() {
        let mut loop_request = request("fn consult(input, prior) { while true {} }");
        loop_request.limits.max_operations = 100;
        assert_eq!(
            evaluate_in_process(&loop_request),
            Err(WorkerError::BudgetExceeded)
        );

        let mut depth_request =
            request("fn recurse(n) { recurse(n + 1) } fn consult(input, prior) { recurse(0) }");
        depth_request.limits.max_call_levels = 4;
        assert_eq!(
            evaluate_in_process(&depth_request),
            Err(WorkerError::BudgetExceeded)
        );
    }

    #[test]
    fn output_and_expression_depth_limits_deny_execution() {
        let payload = "x".repeat(400);
        let mut output_request = WorkerRequest::v1(
            format!(
                r#"fn consult(input, prior) {{
                    #{{ operations: [], outputs: #{{ payload:
                        #{{ type: "string", value: "{payload}" }}
                    }} }}
                }}"#
            ),
            "consult",
            WorkerLimits::default(),
        );
        output_request.fact_schema.insert(
            "payload".to_string(),
            FactSchema {
                fact_type: FactType::String,
                nullable: false,
                max_bytes: Some(512),
                minimum: None,
                maximum: None,
            },
        );
        output_request.limits.max_output_bytes = MIN_OUTPUT_BYTES;
        assert_eq!(
            evaluate_in_process(&output_request),
            Err(WorkerError::BudgetExceeded)
        );

        let mut depth_request = request("fn consult(input, prior) { let x = [[[[[[1]]]]]]; x }");
        depth_request.limits.max_expr_depth = 2;
        assert_eq!(
            evaluate_in_process(&depth_request),
            Err(WorkerError::ScriptRejected)
        );
    }

    #[test]
    fn ambient_and_nondeterministic_apis_are_absent() {
        for expression in [
            "timestamp()",
            "env_var(\"HOME\")",
            "open(\"/etc/passwd\")",
            "exec(\"true\")",
            "random()",
        ] {
            let script = format!("fn consult(input, prior) {{ {expression} }}");
            assert_eq!(
                evaluate_in_process(&request(&script)),
                Err(WorkerError::ScriptRejected),
                "{expression} must be unavailable"
            );
        }
    }

    #[test]
    fn hidden_mode_requires_exact_argument_shape() {
        assert!(is_worker_invocation([
            OsString::from("relay"),
            OsString::from(WORKER_MODE),
        ]));
        assert!(!is_worker_invocation([
            OsString::from("relay"),
            OsString::from(WORKER_MODE),
            OsString::from("extra"),
        ]));
    }
}

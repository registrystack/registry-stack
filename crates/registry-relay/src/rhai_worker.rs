// SPDX-License-Identifier: Apache-2.0
//! Process-isolated, interactive Rhai consultation worker.
//!
//! One fresh worker evaluates one reviewed script. Source effects stay in the
//! Relay parent: the child can only request bounded calls over framed IPC and
//! receive bounded responses. It has no destination, credential, filesystem,
//! socket, environment, subprocess, clock, random, or logging authority.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    io::{BufRead, Read, Write},
    path::PathBuf,
    process::{ExitCode, Stdio},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use rhai::{
    packages::{
        BasicArrayPackage, BasicMapPackage, BasicMathPackage, CorePackage, LogicPackage,
        MoreStringPackage, Package,
    },
    serde::{from_dynamic, to_dynamic},
    Dynamic, Engine, EvalAltResult, Map, Module, Scope,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use time::Date;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as AsyncBufReader},
    process::Command,
    time as tokio_time,
};

pub mod xw;

const WORKER_MODE: &str = "__registry-relay-rhai-worker-v1";
const PROTOCOL_VERSION: u8 = 1;
// One frame must carry the 8 MiB source-response ceiling plus the fixed JSON
// protocol envelope and selected response headers. Frames remain one-at-a-time,
// output is independently capped at 64 KiB, and the worker process retains its
// 128 MiB address-space ceiling.
const MAX_IPC_FRAME_BYTES: usize = 9 * 1024 * 1024;
const MAX_SCRIPT_BYTES: usize = 128 * 1024;
const MAX_NAMES: usize = 64;
const MAX_NAME_BYTES: usize = 128;
const MAX_VALUE_STRING_BYTES: usize = 8 * 1024 * 1024;
const MIN_OUTPUT_BYTES: usize = 256;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MIN_IPC_FRAME_BYTES: usize = 256;
const MIN_MEMORY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MEMORY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_OPERATIONS: u64 = 5_000_000;
const MAX_CALL_LEVELS: usize = 64;
const MAX_EXPR_DEPTH: usize = 128;
const MAX_COLLECTION_ITEMS: usize = 4_096;
const MAX_WALL_TIME_MS: u64 = 60_000;
const MAX_SOURCE_CALLS: u32 = 16;
const MAX_JSON_INTEROPERABLE_INTEGER: i64 = (1_i64 << 53) - 1;
const WORKER_STARTUP_GRACE: Duration = if cfg!(debug_assertions) {
    Duration::from_secs(10)
} else {
    Duration::from_secs(2)
};

/// Resource limits independently enforced by the parent, child, and engine.
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
    pub max_source_calls: u32,
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
            wall_time_ms: 15_000,
            max_source_calls: 5,
        }
    }
}

/// Closed output types. Presence is an outcome, never an authored output.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputType {
    String,
    Boolean,
    Integer,
    Date,
}

/// Expected type and semantic bounds for one output.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSchema {
    pub output_type: OutputType,
    #[serde(default)]
    pub nullable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<i64>,
}

/// A typed value crossing the process boundary.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypedValue {
    String { value: Option<String> },
    Boolean { value: Option<bool> },
    Integer { value: Option<i64> },
    Date { value: Option<String> },
}

impl std::fmt::Debug for TypedValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TypedValue")
            .field("type", &self.output_type())
            .field("value", &if self.is_null() { "null" } else { "[REDACTED]" })
            .finish()
    }
}

impl TypedValue {
    fn output_type(&self) -> OutputType {
        match self {
            Self::String { .. } => OutputType::String,
            Self::Boolean { .. } => OutputType::Boolean,
            Self::Integer { .. } => OutputType::Integer,
            Self::Date { .. } => OutputType::Date,
        }
    }

    fn is_null(&self) -> bool {
        match self {
            Self::String { value } | Self::Date { value } => value.is_none(),
            Self::Boolean { value } => value.is_none(),
            Self::Integer { value } => value.is_none(),
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

    fn as_script_value(&self) -> Value {
        match self {
            Self::String { value } | Self::Date { value } => value
                .as_ref()
                .map_or(Value::Null, |value| value.clone().into()),
            Self::Boolean { value } => value.map_or(Value::Null, Value::Bool),
            Self::Integer { value } => value.map_or(Value::Null, Into::into),
        }
    }
}

/// Complete input for one isolated consultation.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequest {
    pub protocol_version: u8,
    pub script: String,
    pub entrypoint: String,
    pub input: BTreeMap<String, TypedValue>,
    pub output_schema: BTreeMap<String, OutputSchema>,
    /// Enables the host-owned signed-DCI search function for this reviewed
    /// integration. The function is absent from scripts without the compiled
    /// protocol profile.
    pub signed_dci_search: bool,
    pub limits: WorkerLimits,
}

impl std::fmt::Debug for WorkerRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerRequest")
            .field("protocol_version", &self.protocol_version)
            .field("script", &"[REDACTED]")
            .field("entrypoint", &self.entrypoint)
            .field("input", &"[REDACTED]")
            .field("input_count", &self.input.len())
            .field("output_schema_count", &self.output_schema.len())
            .field("signed_dci_search", &self.signed_dci_search)
            .field("limits", &self.limits)
            .finish()
    }
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
            output_schema: BTreeMap::new(),
            signed_dci_search: false,
            limits,
        }
    }

    pub fn enable_signed_dci_search(&mut self) {
        self.signed_dci_search = true;
    }
}

/// Successful and reviewed script outcomes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerOutcome {
    Match,
    NoMatch,
    Ambiguous,
}

/// Fixed failures a reviewed script may intentionally return.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptFailure {
    SourceRejected,
    SourceUnavailable,
    SubjectMismatch,
}

/// Closed terminal result from a worker evaluation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerOutput {
    Success {
        outcome: WorkerOutcome,
        outputs: BTreeMap<String, TypedValue>,
    },
    Failure {
        failure: ScriptFailure,
    },
}

impl std::fmt::Debug for WorkerOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success { outcome, outputs } => formatter
                .debug_struct("WorkerOutput")
                .field("outcome", outcome)
                .field("outputs", &"[REDACTED]")
                .field("output_count", &outputs.len())
                .finish(),
            Self::Failure { failure } => formatter
                .debug_struct("WorkerOutput")
                .field("failure", failure)
                .finish(),
        }
    }
}

impl WorkerOutput {
    pub fn outputs(&self) -> Option<&BTreeMap<String, TypedValue>> {
        match self {
            Self::Success { outputs, .. } => Some(outputs),
            Self::Failure { .. } => None,
        }
    }
}

/// Request options whose authority is revalidated by the Relay parent.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceOptions {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

/// Script-supplied, non-authority signed-DCI search values. The compiled
/// protocol profile owns destinations, paths, identities, correlation,
/// cryptography, pagination, and selector response bindings.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DciSearchOptions {
    pub selectors: BTreeMap<String, Value>,
    pub parameters: BTreeMap<String, Value>,
}

impl std::fmt::Debug for DciSearchOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DciSearchOptions")
            .field("selectors", &"[REDACTED]")
            .field("selector_count", &self.selectors.len())
            .field("parameters", &"[REDACTED]")
            .field("parameter_count", &self.parameters.len())
            .finish()
    }
}

impl std::fmt::Debug for SourceOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceOptions")
            .field("query", &"[REDACTED]")
            .field("query_count", &self.query.len())
            .field("headers", &"[REDACTED]")
            .field("header_count", &self.headers.len())
            .finish()
    }
}

/// One host-call request emitted by the isolated worker.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceCall {
    Get {
        call_id: u32,
        target: String,
        options: SourceOptions,
    },
    PostJson {
        call_id: u32,
        target: String,
        body: Value,
        options: SourceOptions,
    },
    PostForm {
        call_id: u32,
        target: String,
        fields: BTreeMap<String, Value>,
        options: SourceOptions,
    },
    DciSearch {
        call_id: u32,
        options: DciSearchOptions,
    },
}

impl std::fmt::Debug for SourceCall {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (method, call_id, options, has_body) = match self {
            Self::Get {
                call_id, options, ..
            } => ("get", call_id, options, false),
            Self::PostJson {
                call_id, options, ..
            } => ("post_json", call_id, options, true),
            Self::PostForm {
                call_id, options, ..
            } => ("post_form", call_id, options, true),
            Self::DciSearch { call_id, .. } => {
                return formatter
                    .debug_struct("SourceCall")
                    .field("method", &"dci_search")
                    .field("call_id", call_id)
                    .field("options", &"[REDACTED]")
                    .finish();
            }
        };
        formatter
            .debug_struct("SourceCall")
            .field("method", &method)
            .field("call_id", call_id)
            .field("target", &"[REDACTED]")
            .field("options", options)
            .field("body", &has_body.then_some("[REDACTED]"))
            .finish()
    }
}

impl SourceCall {
    pub const fn call_id(&self) -> u32 {
        match self {
            Self::Get { call_id, .. }
            | Self::PostJson { call_id, .. }
            | Self::PostForm { call_id, .. }
            | Self::DciSearch { call_id, .. } => *call_id,
        }
    }
}

/// Bounded source response visible to the script.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceResponse {
    pub status: u16,
    pub body: Value,
    #[serde(default)]
    pub headers: BTreeMap<String, Option<String>>,
}

impl std::fmt::Debug for SourceResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceResponse")
            .field("status", &self.status)
            .field("body", &"[REDACTED]")
            .field("headers", &"[REDACTED]")
            .field("header_count", &self.headers.len())
            .finish()
    }
}

/// Fixed parent-owned failure classes. These are never catchable script data.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostFailure {
    SourceAuth,
    SourceRateLimited,
    SourceUnavailable,
    ContractViolation,
    BudgetExceeded,
}

/// Relay-owned source dispatcher for one interactive consultation.
#[async_trait]
pub trait SourceHost: Send {
    async fn call(&mut self, call: SourceCall) -> Result<SourceResponse, HostFailure>;
}

/// Non-sensitive worker failures. Scripts, inputs, responses, and credentials
/// are deliberately absent from error rendering.
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
    #[error("Relay source host rejected the worker call")]
    HostFailed(HostFailure),
}

/// A fresh-process launcher. Every evaluation uses one process for the full
/// interactive consultation and forcibly terminates it on any protocol error.
#[derive(Clone, Debug)]
pub struct WorkerProcess {
    program: PathBuf,
}

impl WorkerProcess {
    pub fn current_executable() -> Result<Self, WorkerError> {
        std::env::current_exe()
            .map(|program| Self { program })
            .map_err(|_| WorkerError::SpawnFailed)
    }

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

    pub fn with_program(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }

    /// Evaluates a script that is not permitted to perform source calls.
    pub async fn evaluate(&self, request: &WorkerRequest) -> Result<WorkerOutput, WorkerError> {
        self.evaluate_with_host(request, &mut RejectingHost).await
    }

    /// Evaluates one interactive consultation with a Relay-owned source host.
    pub async fn evaluate_with_host<H: SourceHost + ?Sized>(
        &self,
        request: &WorkerRequest,
        host: &mut H,
    ) -> Result<WorkerOutput, WorkerError> {
        validate_request(request)?;
        let request_line = encode_line(request, request.limits.max_ipc_frame_bytes)?;
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
        let frame_limit = request.limits.max_ipc_frame_bytes;
        let exchange = async {
            stdin
                .write_all(&request_line)
                .await
                .map_err(|_| WorkerError::IpcFailed)?;
            let mut stdout = AsyncBufReader::new(stdout);
            let mut expected_call_id = 0_u32;
            loop {
                let frame = read_async_frame::<ChildFrame>(&mut stdout, frame_limit).await?;
                match frame {
                    ChildFrame::HostCall { call } => {
                        if call.call_id() != expected_call_id
                            || expected_call_id >= request.limits.max_source_calls
                        {
                            return Err(WorkerError::IpcFailed);
                        }
                        expected_call_id += 1;
                        validate_source_call(&call, &request.limits)?;
                        let response = host.call(call).await.map_err(WorkerError::HostFailed)?;
                        validate_source_response(&response, &request.limits)?;
                        let response = ParentFrame::HostResponse {
                            call_id: expected_call_id - 1,
                            response,
                        };
                        let bytes = encode_line(&response, frame_limit)?;
                        stdin
                            .write_all(&bytes)
                            .await
                            .map_err(|_| WorkerError::IpcFailed)?;
                    }
                    ChildFrame::Complete { output } => {
                        validate_output(request, &output)?;
                        return Ok(output);
                    }
                    ChildFrame::Error { error } => return Err(error.into()),
                }
            }
        };
        let result = tokio_time::timeout(timeout, exchange).await;
        let _ = child.kill().await;
        let _ = child.wait().await;
        match result {
            Ok(result) => result,
            Err(_) => Err(WorkerError::TimedOut),
        }
    }
}

struct RejectingHost;

#[async_trait]
impl SourceHost for RejectingHost {
    async fn call(&mut self, _call: SourceCall) -> Result<SourceResponse, HostFailure> {
        Err(HostFailure::ContractViolation)
    }
}

/// Stable, value-free reason a reviewed script failed its static probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScriptProbeCause {
    ContractViolation,
    SyntaxError,
    UnknownFunction,
    UnsupportedFunctionSignature,
}

impl ScriptProbeCause {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContractViolation => "closed_contract_violation",
            Self::SyntaxError => "syntax_error",
            Self::UnknownFunction => "unknown_function",
            Self::UnsupportedFunctionSignature => "unsupported_function_signature",
        }
    }
}

/// Safe source location and reason returned by a static script probe.
///
/// Source text, inputs, selector values, and credentials are deliberately not
/// retained in this diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptProbeDiagnostic {
    cause: ScriptProbeCause,
    line: Option<usize>,
    column: Option<usize>,
    function: Option<String>,
    valid_signatures: Vec<&'static str>,
}

impl ScriptProbeDiagnostic {
    const fn without_position(cause: ScriptProbeCause) -> Self {
        Self {
            cause,
            line: None,
            column: None,
            function: None,
            valid_signatures: Vec::new(),
        }
    }

    #[must_use]
    pub const fn cause(&self) -> ScriptProbeCause {
        self.cause
    }

    #[must_use]
    pub const fn line(&self) -> Option<usize> {
        self.line
    }

    #[must_use]
    pub const fn column(&self) -> Option<usize> {
        self.column
    }

    #[must_use]
    pub fn function(&self) -> Option<&str> {
        self.function.as_deref()
    }

    #[must_use]
    pub fn valid_signatures(&self) -> &[&'static str] {
        &self.valid_signatures
    }

    const fn worker_error(&self) -> WorkerError {
        match self.cause {
            ScriptProbeCause::ContractViolation => WorkerError::ContractViolation,
            ScriptProbeCause::SyntaxError
            | ScriptProbeCause::UnknownFunction
            | ScriptProbeCause::UnsupportedFunctionSignature => WorkerError::ScriptRejected,
        }
    }
}

impl std::fmt::Display for ScriptProbeDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.cause.as_str())
    }
}

impl std::error::Error for ScriptProbeDiagnostic {}

/// Compiles a reviewed script and verifies its one-context entrypoint without
/// executing it or granting a source capability.
pub fn probe_script_diagnostic(
    script: &str,
    entrypoint: &str,
    limits: WorkerLimits,
) -> Result<(), ScriptProbeDiagnostic> {
    validate_limits(&limits).map_err(|_| {
        ScriptProbeDiagnostic::without_position(ScriptProbeCause::ContractViolation)
    })?;
    if script.is_empty() || script.len() > MAX_SCRIPT_BYTES {
        return Err(ScriptProbeDiagnostic::without_position(
            ScriptProbeCause::ContractViolation,
        ));
    }
    validate_entrypoint(entrypoint).map_err(|_| {
        ScriptProbeDiagnostic::without_position(ScriptProbeCause::ContractViolation)
    })?;
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(limits.wall_time_ms))
        .ok_or_else(|| {
            ScriptProbeDiagnostic::without_position(ScriptProbeCause::ContractViolation)
        })?;
    let engine = hardened_engine(&limits, deadline, None, true);
    let normalized = normalize_host_namespace_syntax(script);
    let ast = engine.compile(normalized).map_err(|error| {
        let position = error.position();
        ScriptProbeDiagnostic {
            cause: ScriptProbeCause::SyntaxError,
            line: position.line(),
            column: position.position(),
            function: None,
            valid_signatures: Vec::new(),
        }
    })?;
    if ast
        .iter_functions()
        .any(|function| function.name == entrypoint && function.params.len() == 1)
    {
        return validate_host_calls(script);
    }
    let cause = if ast
        .iter_functions()
        .any(|function| function.name == entrypoint)
    {
        ScriptProbeCause::UnsupportedFunctionSignature
    } else {
        ScriptProbeCause::UnknownFunction
    };
    Err(ScriptProbeDiagnostic {
        cause,
        line: None,
        column: None,
        function: Some(entrypoint.to_string()),
        valid_signatures: vec!["consult(context)"],
    })
}

struct ScriptHostCall {
    function: String,
    canonical_function: String,
    argument_count: usize,
    byte_index: usize,
    line: usize,
    column: usize,
}

fn validate_host_calls(script: &str) -> Result<(), ScriptProbeDiagnostic> {
    let mut calls = scan_host_calls(script, "xw", false);
    calls.extend(scan_host_calls(script, "source", true));
    calls.sort_by_key(|call| call.byte_index);
    for call in calls {
        if call.canonical_function.starts_with("xw.") {
            validate_xw_call(call)?;
        } else {
            validate_source_host_call(call)?;
        }
    }
    Ok(())
}

fn validate_xw_call(call: ScriptHostCall) -> Result<(), ScriptProbeDiagnostic> {
    let candidates = xw::XW_V1_FUNCTIONS
        .iter()
        .filter(|candidate| {
            call.canonical_function == format!("{}.{}", candidate.namespace, candidate.name)
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Err(ScriptProbeDiagnostic {
            cause: ScriptProbeCause::UnknownFunction,
            line: Some(call.line),
            column: Some(call.column),
            function: Some(call.function),
            valid_signatures: closest_xw_signatures(&call.canonical_function),
        });
    }
    if candidates
        .iter()
        .any(|candidate| candidate.accepted_types.len() == call.argument_count)
    {
        return Ok(());
    }
    Err(ScriptProbeDiagnostic {
        cause: ScriptProbeCause::UnsupportedFunctionSignature,
        line: Some(call.line),
        column: Some(call.column),
        function: Some(call.function),
        valid_signatures: candidates
            .into_iter()
            .map(|candidate| candidate.signature)
            .collect(),
    })
}

fn validate_source_host_call(call: ScriptHostCall) -> Result<(), ScriptProbeDiagnostic> {
    let candidate = SOURCE_HOST_FUNCTIONS
        .iter()
        .find(|candidate| call.canonical_function == candidate.authored_name);
    let Some(candidate) = candidate else {
        return Err(ScriptProbeDiagnostic {
            cause: ScriptProbeCause::UnknownFunction,
            line: Some(call.line),
            column: Some(call.column),
            function: Some(call.function),
            valid_signatures: closest_source_signatures(
                &call.canonical_function,
                call.argument_count,
            ),
        });
    };
    if candidate
        .signatures
        .iter()
        .any(|signature| signature.arity == call.argument_count)
    {
        return Ok(());
    }
    Err(ScriptProbeDiagnostic {
        cause: ScriptProbeCause::UnsupportedFunctionSignature,
        line: Some(call.line),
        column: Some(call.column),
        function: Some(call.function),
        valid_signatures: candidate
            .signatures
            .iter()
            .map(|signature| signature.text)
            .collect(),
    })
}

fn closest_xw_signatures(function: &str) -> Vec<&'static str> {
    let mut distance = usize::MAX;
    let mut signatures = Vec::new();
    for candidate in xw::XW_V1_FUNCTIONS {
        let candidate_name = format!("{}.{}", candidate.namespace, candidate.name);
        let candidate_distance = edit_distance(function, &candidate_name);
        match candidate_distance.cmp(&distance) {
            std::cmp::Ordering::Less => {
                distance = candidate_distance;
                signatures.clear();
                signatures.push(candidate.signature);
            }
            std::cmp::Ordering::Equal => signatures.push(candidate.signature),
            std::cmp::Ordering::Greater => {}
        }
    }
    signatures
}

fn closest_source_signatures(function: &str, argument_count: usize) -> Vec<&'static str> {
    let mut distance = usize::MAX;
    let mut candidates = Vec::new();
    for candidate in SOURCE_HOST_FUNCTIONS {
        let candidate_distance = edit_distance(function, candidate.authored_name);
        match candidate_distance.cmp(&distance) {
            std::cmp::Ordering::Less => {
                distance = candidate_distance;
                candidates.clear();
                candidates.push(candidate);
            }
            std::cmp::Ordering::Equal => candidates.push(candidate),
            std::cmp::Ordering::Greater => {}
        }
    }
    let matching_arity = candidates
        .iter()
        .flat_map(|candidate| candidate.signatures)
        .filter(|signature| signature.arity == argument_count)
        .map(|signature| signature.text)
        .collect::<Vec<_>>();
    if matching_arity.is_empty() {
        candidates
            .into_iter()
            .flat_map(|candidate| candidate.signatures)
            .map(|signature| signature.text)
            .collect()
    } else {
        matching_arity
    }
}

fn edit_distance(left: &str, right: &str) -> usize {
    let mut prior = (0..=right.chars().count()).collect::<Vec<_>>();
    let mut current = vec![0; prior.len()];
    for (left_index, left) in left.chars().enumerate() {
        current[0] = left_index + 1;
        for (right_index, right) in right.chars().enumerate() {
            current[right_index + 1] = (prior[right_index + 1] + 1)
                .min(current[right_index] + 1)
                .min(prior[right_index] + usize::from(left != right));
        }
        std::mem::swap(&mut prior, &mut current);
    }
    prior[right.chars().count()]
}

fn scan_host_calls(
    script: &str,
    namespace: &str,
    allow_qualified_separator: bool,
) -> Vec<ScriptHostCall> {
    let mut calls = Vec::new();
    scan_host_calls_in_region(
        script,
        namespace.as_bytes(),
        allow_qualified_separator,
        0,
        script.len(),
        0,
        &mut calls,
    );
    calls
}

fn scan_host_calls_in_region(
    script: &str,
    namespace: &[u8],
    allow_qualified_separator: bool,
    start: usize,
    end: usize,
    depth: usize,
    calls: &mut Vec<ScriptHostCall>,
) {
    if depth > MAX_EXPR_DEPTH {
        return;
    }
    let bytes = script.as_bytes();
    let mut index = start;
    while index < end {
        match bytes[index] {
            b'"' | b'\'' => {
                index = skip_quoted_script_value(bytes, index);
                continue;
            }
            b'`' => {
                index = scan_interpolated_script_string(
                    script,
                    namespace,
                    allow_qualified_separator,
                    index,
                    end,
                    depth,
                    calls,
                );
                continue;
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index = bytes[index + 2..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(end, |offset| (index + 2 + offset + 1).min(end));
                continue;
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index = skip_nested_block_comment(bytes, index, end);
                continue;
            }
            byte if byte == namespace[0]
                && bytes[index..].starts_with(namespace)
                && index
                    .checked_sub(1)
                    .and_then(|prior| bytes.get(prior))
                    .is_none_or(|byte| !script_identifier_byte(*byte)) =>
            {
                if let Some((function, canonical_function, open_parenthesis)) =
                    parse_host_function(bytes, index, namespace, allow_qualified_separator)
                {
                    if let Some((argument_count, _end)) =
                        count_script_call_arguments(bytes, open_parenthesis)
                    {
                        let (line, column) = script_position(script, index);
                        calls.push(ScriptHostCall {
                            function,
                            canonical_function,
                            argument_count,
                            byte_index: index,
                            line,
                            column,
                        });
                    }
                }
            }
            _ => {}
        }
        index += 1;
    }
}

fn scan_interpolated_script_string(
    script: &str,
    namespace: &[u8],
    allow_qualified_separator: bool,
    start: usize,
    end: usize,
    depth: usize,
    calls: &mut Vec<ScriptHostCall>,
) -> usize {
    let bytes = script.as_bytes();
    let mut cursor = start + 1;
    while cursor < end {
        match bytes[cursor] {
            b'\\' => cursor = (cursor + 2).min(end),
            b'`' => return cursor + 1,
            b'$' if bytes.get(cursor + 1) == Some(&b'{') => {
                let expression_start = cursor + 2;
                let Some(expression_end) =
                    find_interpolation_end(bytes, expression_start, end, depth)
                else {
                    return end;
                };
                scan_host_calls_in_region(
                    script,
                    namespace,
                    allow_qualified_separator,
                    expression_start,
                    expression_end,
                    depth + 1,
                    calls,
                );
                cursor = expression_end + 1;
            }
            _ => cursor += 1,
        }
    }
    end
}

fn parse_host_function(
    bytes: &[u8],
    start: usize,
    namespace: &[u8],
    allow_qualified_separator: bool,
) -> Option<(String, String, usize)> {
    let mut cursor = start + namespace.len();
    let mut function = String::from(std::str::from_utf8(namespace).ok()?);
    let mut canonical_function = function.clone();
    let mut segments = 0;
    loop {
        cursor = skip_ascii_whitespace(bytes, cursor);
        let separator = if bytes.get(cursor) == Some(&b'.') {
            "."
        } else if allow_qualified_separator && bytes.get(cursor..cursor + 2) == Some(b"::") {
            "::"
        } else {
            break;
        };
        cursor = skip_ascii_whitespace(bytes, cursor + separator.len());
        let segment_start = cursor;
        while bytes
            .get(cursor)
            .is_some_and(|byte| script_identifier_byte(*byte))
        {
            cursor += 1;
        }
        if cursor == segment_start {
            return None;
        }
        let segment = std::str::from_utf8(&bytes[segment_start..cursor]).ok()?;
        function.push_str(separator);
        function.push_str(segment);
        canonical_function.push('.');
        canonical_function.push_str(segment);
        segments += 1;
    }
    cursor = skip_ascii_whitespace(bytes, cursor);
    (segments > 0 && bytes.get(cursor) == Some(&b'(')).then_some((
        function,
        canonical_function,
        cursor,
    ))
}

fn find_interpolation_end(bytes: &[u8], start: usize, end: usize, depth: usize) -> Option<usize> {
    if depth > MAX_EXPR_DEPTH {
        return None;
    }
    let mut cursor = start;
    let mut braces = 1_usize;
    while cursor < end {
        match bytes[cursor] {
            b'"' | b'\'' => {
                cursor = skip_quoted_script_value(bytes, cursor);
                continue;
            }
            b'`' => {
                cursor = skip_interpolated_script_string(bytes, cursor, end, depth + 1);
                continue;
            }
            b'/' if bytes.get(cursor + 1) == Some(&b'/') => {
                cursor = bytes[cursor + 2..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(end, |offset| (cursor + 2 + offset + 1).min(end));
                continue;
            }
            b'/' if bytes.get(cursor + 1) == Some(&b'*') => {
                cursor = skip_nested_block_comment(bytes, cursor, end);
                continue;
            }
            b'{' => braces += 1,
            b'}' => {
                braces = braces.checked_sub(1)?;
                if braces == 0 {
                    return Some(cursor);
                }
            }
            _ => {}
        }
        cursor += 1;
    }
    None
}

fn count_script_call_arguments(bytes: &[u8], open: usize) -> Option<(usize, usize)> {
    let mut cursor = open + 1;
    let mut parentheses = 1_usize;
    let mut brackets = 0_usize;
    let mut braces = 0_usize;
    let mut commas = 0_usize;
    let mut has_argument = false;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'"' | b'\'' => {
                has_argument = true;
                cursor = skip_quoted_script_value(bytes, cursor);
                continue;
            }
            b'`' => {
                has_argument = true;
                cursor = skip_interpolated_script_string(bytes, cursor, bytes.len(), 0);
                continue;
            }
            b'/' if bytes.get(cursor + 1) == Some(&b'/') => {
                cursor = bytes[cursor + 2..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(bytes.len(), |offset| cursor + 2 + offset + 1);
                continue;
            }
            b'/' if bytes.get(cursor + 1) == Some(&b'*') => {
                cursor = skip_nested_block_comment(bytes, cursor, bytes.len());
                continue;
            }
            b'(' => parentheses += 1,
            b')' if parentheses == 1 && brackets == 0 && braces == 0 => {
                return Some((usize::from(has_argument) + commas, cursor + 1));
            }
            b')' => parentheses = parentheses.checked_sub(1)?,
            b'[' => brackets += 1,
            b']' => brackets = brackets.checked_sub(1)?,
            b'{' => braces += 1,
            b'}' => braces = braces.checked_sub(1)?,
            b',' if parentheses == 1 && brackets == 0 && braces == 0 => commas += 1,
            byte if !byte.is_ascii_whitespace() => has_argument = true,
            _ => {}
        }
        cursor += 1;
    }
    None
}

fn skip_quoted_script_value(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let mut cursor = start + 1;
    let mut escaped = false;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        cursor += 1;
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == quote {
            break;
        }
    }
    cursor
}

fn skip_nested_block_comment(bytes: &[u8], start: usize, end: usize) -> usize {
    let mut cursor = start + 2;
    let mut depth = 1_usize;
    while cursor < end {
        if bytes.get(cursor..cursor + 2) == Some(b"/*") {
            depth += 1;
            cursor += 2;
        } else if bytes.get(cursor..cursor + 2) == Some(b"*/") {
            depth -= 1;
            cursor += 2;
            if depth == 0 {
                return cursor;
            }
        } else {
            cursor += 1;
        }
    }
    end
}

fn skip_interpolated_script_string(bytes: &[u8], start: usize, end: usize, depth: usize) -> usize {
    if depth > MAX_EXPR_DEPTH {
        return end;
    }
    let mut cursor = start + 1;
    while cursor < end {
        match bytes[cursor] {
            b'\\' => cursor = (cursor + 2).min(end),
            b'`' => return cursor + 1,
            b'$' if bytes.get(cursor + 1) == Some(&b'{') => {
                let Some(expression_end) =
                    find_interpolation_end(bytes, cursor + 2, end, depth + 1)
                else {
                    return end;
                };
                cursor = expression_end + 1;
            }
            _ => cursor += 1,
        }
    }
    end
}

fn skip_ascii_whitespace(bytes: &[u8], mut cursor: usize) -> usize {
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    cursor
}

const fn script_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn script_position(script: &str, byte_index: usize) -> (usize, usize) {
    let prefix = &script[..byte_index];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, line)| line)
        .chars()
        .count()
        + 1;
    (line, column)
}

/// Closed runtime probe used while compiling source plans. Developer tooling
/// should use [`probe_script_diagnostic`] to preserve safe source locations.
pub fn probe_script(
    script: &str,
    entrypoint: &str,
    limits: WorkerLimits,
) -> Result<(), WorkerError> {
    probe_script_diagnostic(script, entrypoint, limits)
        .map_err(|diagnostic| diagnostic.worker_error())
}

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

/// Runs the hidden interactive worker protocol on standard input/output.
#[doc(hidden)]
pub fn run_worker_stdio() -> ExitCode {
    let mut frame_limit = MAX_IPC_FRAME_BYTES;
    let result = read_sync_frame::<WorkerRequest>(MAX_IPC_FRAME_BYTES).and_then(|request| {
        frame_limit = request.limits.max_ipc_frame_bytes.min(MAX_IPC_FRAME_BYTES);
        validate_request(&request)?;
        apply_process_sandbox(&request.limits)?;
        evaluate_in_process(&request, Arc::new(StdioTransport { frame_limit }))
    });
    let frame = match result {
        Ok(output) => ChildFrame::Complete { output },
        Err(error) => ChildFrame::Error {
            error: error.into(),
        },
    };
    let success = matches!(frame, ChildFrame::Complete { .. });
    let _ = write_sync_frame(&frame, frame_limit);
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
enum ChildFrame {
    HostCall { call: SourceCall },
    Complete { output: WorkerOutput },
    Error { error: WorkerFailure },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
enum ParentFrame {
    HostResponse {
        call_id: u32,
        response: SourceResponse,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
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
            WorkerError::SpawnFailed
            | WorkerError::IpcFailed
            | WorkerError::TimedOut
            | WorkerError::HostFailed(_) => Self::IpcFailed,
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
        || !(MIN_IPC_FRAME_BYTES..=MAX_IPC_FRAME_BYTES).contains(&limits.max_ipc_frame_bytes)
        || !(MIN_MEMORY_BYTES..=MAX_MEMORY_BYTES).contains(&limits.max_memory_bytes)
        || !(1..=MAX_WALL_TIME_MS).contains(&limits.wall_time_ms)
        || !(1..=MAX_SOURCE_CALLS).contains(&limits.max_source_calls)
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
        || request.output_schema.len() > MAX_NAMES
    {
        return Err(WorkerError::ContractViolation);
    }
    validate_entrypoint(&request.entrypoint)?;
    let encoded = serde_json::to_vec(request).map_err(|_| WorkerError::ContractViolation)?;
    if encoded.len() + 1 > request.limits.max_ipc_frame_bytes {
        return Err(WorkerError::RequestTooLarge);
    }
    for name in request.input.keys().chain(request.output_schema.keys()) {
        validate_name(name)?;
    }
    for value in request.input.values() {
        value.validate(request.limits.max_string_bytes)?;
    }
    for schema in request.output_schema.values() {
        validate_output_schema(schema, request.limits.max_string_bytes)?;
    }
    Ok(())
}

fn validate_output_schema(
    schema: &OutputSchema,
    max_string_bytes: usize,
) -> Result<(), WorkerError> {
    let valid = match schema.output_type {
        OutputType::String => {
            schema
                .max_bytes
                .is_some_and(|value| (1..=max_string_bytes).contains(&value))
                && schema.minimum.is_none()
                && schema.maximum.is_none()
        }
        OutputType::Integer => {
            schema.max_bytes.is_none()
                && matches!((schema.minimum, schema.maximum), (Some(minimum), Some(maximum))
                    if minimum <= maximum
                        && minimum >= -MAX_JSON_INTEROPERABLE_INTEGER
                        && maximum <= MAX_JSON_INTEROPERABLE_INTEGER)
        }
        OutputType::Boolean | OutputType::Date => {
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
        || !bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'-'))
    {
        return Err(WorkerError::ContractViolation);
    }
    Ok(())
}

fn validate_output(request: &WorkerRequest, output: &WorkerOutput) -> Result<(), WorkerError> {
    match output {
        WorkerOutput::Success { outcome, outputs } => {
            if *outcome == WorkerOutcome::Match {
                if outputs.keys().ne(request.output_schema.keys()) {
                    return Err(WorkerError::ContractViolation);
                }
                for (name, value) in outputs {
                    validate_typed_output(request, name, value)?;
                }
            } else if !outputs.is_empty() {
                return Err(WorkerError::ContractViolation);
            }
        }
        WorkerOutput::Failure { .. } => {}
    }
    let encoded = serde_json::to_vec(output).map_err(|_| WorkerError::ContractViolation)?;
    if encoded.len() > request.limits.max_output_bytes {
        return Err(WorkerError::BudgetExceeded);
    }
    Ok(())
}

fn validate_typed_output(
    request: &WorkerRequest,
    name: &str,
    value: &TypedValue,
) -> Result<(), WorkerError> {
    let schema = request
        .output_schema
        .get(name)
        .ok_or(WorkerError::ContractViolation)?;
    if value.output_type() != schema.output_type || (value.is_null() && !schema.nullable) {
        return Err(WorkerError::ContractViolation);
    }
    value.validate(request.limits.max_string_bytes)?;
    let within_bound = match (value, schema.output_type) {
        (TypedValue::String { value: Some(value) }, OutputType::String) => schema
            .max_bytes
            .is_some_and(|maximum| value.len() <= maximum),
        (TypedValue::Integer { value: Some(value) }, OutputType::Integer) => matches!(
            (schema.minimum, schema.maximum),
            (Some(minimum), Some(maximum)) if (minimum..=maximum).contains(value)
        ),
        _ => true,
    };
    within_bound
        .then_some(())
        .ok_or(WorkerError::ContractViolation)
}

fn validate_source_call(call: &SourceCall, limits: &WorkerLimits) -> Result<(), WorkerError> {
    let encoded = serde_json::to_vec(call).map_err(|_| WorkerError::ContractViolation)?;
    if encoded.len() + 1 > limits.max_ipc_frame_bytes {
        return Err(WorkerError::BudgetExceeded);
    }
    match call {
        SourceCall::Get {
            target, options, ..
        } => validate_source_parts(target, options, None, limits),
        SourceCall::PostJson {
            target,
            body,
            options,
            ..
        } => validate_source_parts(target, options, Some(body), limits),
        SourceCall::PostForm {
            target,
            fields,
            options,
            ..
        } => {
            validate_source_parts(target, options, None, limits)?;
            for value in fields.values() {
                validate_query_value(value, limits)?;
            }
            Ok(())
        }
        SourceCall::DciSearch { options, .. } => {
            if options.selectors.is_empty()
                || options.selectors.len() > MAX_NAMES
                || options.parameters.len() > MAX_NAMES
            {
                return Err(WorkerError::ContractViolation);
            }
            for (name, value) in options.selectors.iter().chain(&options.parameters) {
                validate_name(name)?;
                validate_dci_scalar(value, limits)?;
            }
            Ok(())
        }
    }
}

fn validate_dci_scalar(value: &Value, limits: &WorkerLimits) -> Result<(), WorkerError> {
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::String(value) => (value.len() <= limits.max_string_bytes)
            .then_some(())
            .ok_or(WorkerError::BudgetExceeded),
        Value::Number(number)
            if number.as_i64().is_some_and(|value| {
                (-MAX_JSON_INTEROPERABLE_INTEGER..=MAX_JSON_INTEROPERABLE_INTEGER).contains(&value)
            }) =>
        {
            Ok(())
        }
        Value::Number(_) | Value::Array(_) | Value::Object(_) => {
            Err(WorkerError::ContractViolation)
        }
    }
}

fn validate_source_parts(
    target: &str,
    options: &SourceOptions,
    body: Option<&Value>,
    limits: &WorkerLimits,
) -> Result<(), WorkerError> {
    if target.is_empty() || target.len() > limits.max_string_bytes || target.contains(['\r', '\n'])
    {
        return Err(WorkerError::ContractViolation);
    }
    for (name, value) in &options.headers {
        validate_name(name)?;
        if value.len() > limits.max_string_bytes || value.contains(['\r', '\n']) {
            return Err(WorkerError::ContractViolation);
        }
    }
    for value in options.query.values() {
        validate_query_value(value, limits)?;
    }
    if let Some(body) = body {
        validate_json_value(body, limits, true)?;
    }
    Ok(())
}

fn validate_query_value(value: &Value, limits: &WorkerLimits) -> Result<(), WorkerError> {
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::String(value) => (value.len() <= limits.max_string_bytes)
            .then_some(())
            .ok_or(WorkerError::BudgetExceeded),
        Value::Number(number)
            if number.as_i64().is_some_and(|value| {
                (-MAX_JSON_INTEROPERABLE_INTEGER..=MAX_JSON_INTEROPERABLE_INTEGER).contains(&value)
            }) =>
        {
            Ok(())
        }
        Value::Array(values) if values.len() <= limits.max_array_items => {
            for value in values {
                if matches!(value, Value::Array(_) | Value::Object(_)) {
                    return Err(WorkerError::ContractViolation);
                }
                validate_query_value(value, limits)?;
            }
            Ok(())
        }
        Value::Array(_) => Err(WorkerError::BudgetExceeded),
        Value::Number(_) | Value::Object(_) => Err(WorkerError::ContractViolation),
    }
}

fn validate_source_response(
    response: &SourceResponse,
    limits: &WorkerLimits,
) -> Result<(), WorkerError> {
    if !(100..=599).contains(&response.status) {
        return Err(WorkerError::ContractViolation);
    }
    for (name, value) in &response.headers {
        validate_name(name)?;
        if value.as_ref().is_some_and(|value| {
            value.len() > limits.max_string_bytes || value.contains(['\r', '\n'])
        }) {
            return Err(WorkerError::ContractViolation);
        }
    }
    validate_json_value(&response.body, limits, true)?;
    let encoded = serde_json::to_vec(response).map_err(|_| WorkerError::ContractViolation)?;
    if encoded.len() + 1 > limits.max_ipc_frame_bytes {
        return Err(WorkerError::BudgetExceeded);
    }
    Ok(())
}

fn validate_json_value(
    value: &Value,
    limits: &WorkerLimits,
    allow_float: bool,
) -> Result<(), WorkerError> {
    fn visit(
        value: &Value,
        limits: &WorkerLimits,
        allow_float: bool,
        depth: usize,
        nodes: &mut usize,
    ) -> Result<(), WorkerError> {
        *nodes = nodes.saturating_add(1);
        if depth > limits.max_expr_depth || *nodes > MAX_COLLECTION_ITEMS * 4 {
            return Err(WorkerError::BudgetExceeded);
        }
        match value {
            Value::Null | Value::Bool(_) => Ok(()),
            Value::Number(number) => {
                let integer = number.as_i64().is_some_and(|value| {
                    (-MAX_JSON_INTEROPERABLE_INTEGER..=MAX_JSON_INTEROPERABLE_INTEGER)
                        .contains(&value)
                });
                (integer || (allow_float && number.as_f64().is_some()))
                    .then_some(())
                    .ok_or(WorkerError::ContractViolation)
            }
            Value::String(value) => (value.len() <= limits.max_string_bytes)
                .then_some(())
                .ok_or(WorkerError::BudgetExceeded),
            Value::Array(values) => {
                if values.len() > limits.max_array_items {
                    return Err(WorkerError::BudgetExceeded);
                }
                for value in values {
                    visit(value, limits, allow_float, depth + 1, nodes)?;
                }
                Ok(())
            }
            Value::Object(values) => {
                if values.len() > limits.max_map_entries {
                    return Err(WorkerError::BudgetExceeded);
                }
                for (name, value) in values {
                    if name.len() > limits.max_string_bytes {
                        return Err(WorkerError::BudgetExceeded);
                    }
                    visit(value, limits, allow_float, depth + 1, nodes)?;
                }
                Ok(())
            }
        }
    }
    visit(value, limits, allow_float, 0, &mut 0)
}

#[derive(Clone)]
struct ScriptContext {
    input: Map,
}

#[derive(Clone)]
struct TerminalResult {
    outcome: TerminalOutcome,
    outputs: Map,
}

#[derive(Clone, Copy)]
enum TerminalOutcome {
    Match,
    NoMatch,
    Ambiguous,
    Failure(ScriptFailure),
}

trait BlockingTransport: Send + Sync {
    fn exchange(&self, call: SourceCall) -> Result<SourceResponse, WorkerError>;
}

struct StdioTransport {
    frame_limit: usize,
}

impl BlockingTransport for StdioTransport {
    fn exchange(&self, call: SourceCall) -> Result<SourceResponse, WorkerError> {
        let expected_call_id = call.call_id();
        write_sync_frame(&ChildFrame::HostCall { call }, self.frame_limit)?;
        match read_sync_frame::<ParentFrame>(self.frame_limit)? {
            ParentFrame::HostResponse { call_id, response } if call_id == expected_call_id => {
                Ok(response)
            }
            ParentFrame::HostResponse { .. } => Err(WorkerError::IpcFailed),
        }
    }
}

#[derive(Clone)]
struct SourceApi {
    next_call_id: Arc<AtomicU32>,
    max_calls: u32,
    transport: Arc<dyn BlockingTransport>,
    limits: WorkerLimits,
}

impl SourceApi {
    fn call(
        &mut self,
        call: impl FnOnce(u32) -> SourceCall,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        let call_id = self.next_call_id.fetch_add(1, Ordering::SeqCst);
        if call_id >= self.max_calls {
            return Err(rhai_error(WorkerError::BudgetExceeded));
        }
        let call = call(call_id);
        validate_source_call(&call, &self.limits).map_err(rhai_error)?;
        let response = self.transport.exchange(call).map_err(rhai_error)?;
        validate_source_response(&response, &self.limits).map_err(rhai_error)?;
        to_dynamic(BTreeMap::from([
            ("status".to_string(), Value::from(response.status)),
            ("body".to_string(), response.body),
            (
                "headers".to_string(),
                serde_json::to_value(response.headers)
                    .map_err(|_| rhai_error(WorkerError::IpcFailed))?,
            ),
        ]))
        .map_err(|_| rhai_error(WorkerError::IpcFailed))
    }
}

// This code-owned catalogue is shared by preflight diagnostics, authored
// namespace normalization, and Rhai module registration. It contains only
// public ABI shape, so diagnostics never need to retain argument values or
// inspect engine state.
#[derive(Clone, Copy)]
struct SourceHostSignature {
    arity: usize,
    text: &'static str,
}

struct SourceHostFunction {
    authored_name: &'static str,
    normalized_name: &'static str,
    module_name: &'static str,
    signatures: &'static [SourceHostSignature],
}

const SOURCE_PATH: SourceHostFunction = SourceHostFunction {
    authored_name: "source.path",
    normalized_name: "source::path",
    module_name: "path",
    signatures: &[SourceHostSignature {
        arity: 2,
        text: "source.path(template: string, values: map) -> string",
    }],
};
const SOURCE_GET: SourceHostFunction = SourceHostFunction {
    authored_name: "source.get",
    normalized_name: "source::get",
    module_name: "get",
    signatures: &[
        SourceHostSignature {
            arity: 1,
            text: "source.get(target: string) -> response",
        },
        SourceHostSignature {
            arity: 2,
            text: "source.get(target: string, options: map) -> response",
        },
    ],
};
const SOURCE_POST_JSON: SourceHostFunction = SourceHostFunction {
    authored_name: "source.post_json",
    normalized_name: "source::post_json",
    module_name: "post_json",
    signatures: &[
        SourceHostSignature {
            arity: 2,
            text: "source.post_json(target: string, body: value) -> response",
        },
        SourceHostSignature {
            arity: 3,
            text: "source.post_json(target: string, body: value, options: map) -> response",
        },
    ],
};
const SOURCE_POST_FORM: SourceHostFunction = SourceHostFunction {
    authored_name: "source.post_form",
    normalized_name: "source::post_form",
    module_name: "post_form",
    signatures: &[
        SourceHostSignature {
            arity: 2,
            text: "source.post_form(target: string, fields: map) -> response",
        },
        SourceHostSignature {
            arity: 3,
            text: "source.post_form(target: string, fields: map, options: map) -> response",
        },
    ],
};
const SOURCE_HOST_FUNCTIONS: &[SourceHostFunction] =
    &[SOURCE_PATH, SOURCE_GET, SOURCE_POST_JSON, SOURCE_POST_FORM];

fn hardened_engine(
    limits: &WorkerLimits,
    deadline: Instant,
    source_transport: Option<Arc<dyn BlockingTransport>>,
    signed_dci_search: bool,
) -> Engine {
    let mut engine = Engine::new_raw();
    CorePackage::new().register_into_engine(&mut engine);
    LogicPackage::new().register_into_engine(&mut engine);
    BasicMathPackage::new().register_into_engine(&mut engine);
    BasicArrayPackage::new().register_into_engine(&mut engine);
    BasicMapPackage::new().register_into_engine(&mut engine);
    MoreStringPackage::new().register_into_engine(&mut engine);
    xw::register(&mut engine, *limits);

    engine.register_type_with_name::<ScriptContext>("ConsultationContext");
    engine.register_get("input", |ctx: &mut ScriptContext| ctx.input.clone());
    engine.register_type_with_name::<TerminalResult>("ConsultationResult");
    engine.register_type_with_name::<ScriptFailure>("FailureCode");
    let mut result_module = Module::new();
    result_module.set_native_fn("matched", |outputs: Map| {
        Ok(TerminalResult {
            outcome: TerminalOutcome::Match,
            outputs,
        })
    });
    result_module.set_native_fn("no_match", || {
        Ok(TerminalResult {
            outcome: TerminalOutcome::NoMatch,
            outputs: Map::new(),
        })
    });
    result_module.set_native_fn("ambiguous", || {
        Ok(TerminalResult {
            outcome: TerminalOutcome::Ambiguous,
            outputs: Map::new(),
        })
    });
    result_module.set_native_fn("fail", |failure: ScriptFailure| {
        Ok(TerminalResult {
            outcome: TerminalOutcome::Failure(failure),
            outputs: Map::new(),
        })
    });
    engine.register_static_module("result", result_module.into());

    let mut failure_module = Module::new();
    failure_module.set_var("source_rejected", ScriptFailure::SourceRejected);
    failure_module.set_var("source_unavailable", ScriptFailure::SourceUnavailable);
    failure_module.set_var("subject_mismatch", ScriptFailure::SubjectMismatch);
    engine.register_static_module("failure", failure_module.into());

    if let Some(transport) = source_transport {
        let api = Arc::new(Mutex::new(SourceApi {
            next_call_id: Arc::new(AtomicU32::new(0)),
            max_calls: limits.max_source_calls,
            transport,
            limits: *limits,
        }));
        let mut source_module = Module::new();
        source_module.set_native_fn(SOURCE_PATH.module_name, source_path);
        let get = Arc::clone(&api);
        source_module.set_native_fn(SOURCE_GET.module_name, move |target: &str| {
            get.lock()
                .map_err(|_| rhai_error(WorkerError::IpcFailed))?
                .call(|call_id| SourceCall::Get {
                    call_id,
                    target: target.to_string(),
                    options: SourceOptions::default(),
                })
        });
        let get = Arc::clone(&api);
        source_module.set_native_fn(SOURCE_GET.module_name, move |target: &str, options: Map| {
            let options = parse_options(options)?;
            get.lock()
                .map_err(|_| rhai_error(WorkerError::IpcFailed))?
                .call(|call_id| SourceCall::Get {
                    call_id,
                    target: target.to_string(),
                    options,
                })
        });
        let post_json = Arc::clone(&api);
        source_module.set_native_fn(
            SOURCE_POST_JSON.module_name,
            move |target: &str, body: Dynamic| {
                let body = from_dynamic::<Value>(&body)
                    .map_err(|_| rhai_error(WorkerError::ContractViolation))?;
                post_json
                    .lock()
                    .map_err(|_| rhai_error(WorkerError::IpcFailed))?
                    .call(|call_id| SourceCall::PostJson {
                        call_id,
                        target: target.to_string(),
                        body,
                        options: SourceOptions::default(),
                    })
            },
        );
        let post_json = Arc::clone(&api);
        source_module.set_native_fn(
            SOURCE_POST_JSON.module_name,
            move |target: &str, body: Dynamic, options: Map| {
                let body = from_dynamic::<Value>(&body)
                    .map_err(|_| rhai_error(WorkerError::ContractViolation))?;
                let options = parse_options(options)?;
                post_json
                    .lock()
                    .map_err(|_| rhai_error(WorkerError::IpcFailed))?
                    .call(|call_id| SourceCall::PostJson {
                        call_id,
                        target: target.to_string(),
                        body,
                        options,
                    })
            },
        );
        let post_form = Arc::clone(&api);
        source_module.set_native_fn(
            SOURCE_POST_FORM.module_name,
            move |target: &str, fields: Map| {
                let fields = map_to_values(fields)?;
                post_form
                    .lock()
                    .map_err(|_| rhai_error(WorkerError::IpcFailed))?
                    .call(|call_id| SourceCall::PostForm {
                        call_id,
                        target: target.to_string(),
                        fields,
                        options: SourceOptions::default(),
                    })
            },
        );
        let post_form = Arc::clone(&api);
        source_module.set_native_fn(
            SOURCE_POST_FORM.module_name,
            move |target: &str, fields: Map, options: Map| {
                let fields = map_to_values(fields)?;
                let options = parse_options(options)?;
                post_form
                    .lock()
                    .map_err(|_| rhai_error(WorkerError::IpcFailed))?
                    .call(|call_id| SourceCall::PostForm {
                        call_id,
                        target: target.to_string(),
                        fields,
                        options,
                    })
            },
        );
        engine.register_static_module("source", source_module.into());

        if signed_dci_search {
            let dci = Arc::clone(&api);
            let mut dci_module = Module::new();
            dci_module.set_native_fn("search", move |options: Map| {
                let options = from_dynamic::<DciSearchOptions>(&Dynamic::from_map(options))
                    .map_err(|_| rhai_error(WorkerError::ContractViolation))?;
                let response = dci
                    .lock()
                    .map_err(|_| rhai_error(WorkerError::IpcFailed))?
                    .call(|call_id| SourceCall::DciSearch { call_id, options })?;
                let response = from_dynamic::<BTreeMap<String, Value>>(&response)
                    .map_err(|_| rhai_error(WorkerError::IpcFailed))?;
                let body = response
                    .get("body")
                    .cloned()
                    .ok_or_else(|| rhai_error(WorkerError::IpcFailed))?;
                to_dynamic(body).map_err(|_| rhai_error(WorkerError::IpcFailed))
            });
            engine.register_static_module("protocol_dci", dci_module.into());
        }
    } else if signed_dci_search {
        // Script probing compiles the closed ABI without granting a source
        // capability or executing this function.
        let mut dci_module = Module::new();
        dci_module.set_native_fn("search", |_options: Map| {
            Err::<Dynamic, _>(rhai_error(WorkerError::ContractViolation))
        });
        engine.register_static_module("protocol_dci", dci_module.into());
    }

    let mut fhir_module = Module::new();
    fhir_module.set_native_fn(
        "parse_searchset",
        |response: Dynamic, resource_type: &str| parse_fhir_searchset(response, resource_type),
    );
    engine.register_static_module("protocol_fhir", fhir_module.into());

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

fn parse_options(options: Map) -> Result<SourceOptions, Box<EvalAltResult>> {
    from_dynamic::<SourceOptions>(&Dynamic::from_map(options))
        .map_err(|_| rhai_error(WorkerError::ContractViolation))
}

fn map_to_values(map: Map) -> Result<BTreeMap<String, Value>, Box<EvalAltResult>> {
    from_dynamic::<BTreeMap<String, Value>>(&Dynamic::from_map(map))
        .map_err(|_| rhai_error(WorkerError::ContractViolation))
}

fn parse_fhir_searchset(
    response: Dynamic,
    expected_resource_type: &str,
) -> Result<Dynamic, Box<EvalAltResult>> {
    if expected_resource_type.is_empty()
        || expected_resource_type.len() > MAX_NAME_BYTES
        || !expected_resource_type
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic())
        || matches!(expected_resource_type, "Bundle" | "OperationOutcome")
    {
        return Err(rhai_error(WorkerError::ContractViolation));
    }
    let response =
        from_dynamic::<Value>(&response).map_err(|_| rhai_error(WorkerError::ContractViolation))?;
    let body = response
        .get("body")
        .ok_or_else(|| rhai_error(WorkerError::ContractViolation))?;
    let bundle = body
        .as_object()
        .ok_or_else(|| rhai_error(WorkerError::ContractViolation))?;
    if bundle.get("resourceType").and_then(Value::as_str) != Some("Bundle")
        || bundle.get("type").and_then(Value::as_str) != Some("searchset")
    {
        return Err(rhai_error(WorkerError::ContractViolation));
    }
    let mut next: Option<String> = None;
    if let Some(links) = bundle.get("link") {
        for link in links
            .as_array()
            .ok_or_else(|| rhai_error(WorkerError::ContractViolation))?
        {
            let link = link
                .as_object()
                .ok_or_else(|| rhai_error(WorkerError::ContractViolation))?;
            let relation = link
                .get("relation")
                .and_then(Value::as_str)
                .ok_or_else(|| rhai_error(WorkerError::ContractViolation))?;
            let url = link
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| rhai_error(WorkerError::ContractViolation))?;
            if relation == "next" && next.replace(url.to_owned()).is_some() {
                return Err(rhai_error(WorkerError::ContractViolation));
            }
        }
    }
    let mut matches = Vec::new();
    let mut included = Vec::new();
    let mut outcomes = Vec::new();
    if let Some(entries) = bundle.get("entry") {
        for entry in entries
            .as_array()
            .ok_or_else(|| rhai_error(WorkerError::ContractViolation))?
        {
            let entry = entry
                .as_object()
                .ok_or_else(|| rhai_error(WorkerError::ContractViolation))?;
            let resource = entry
                .get("resource")
                .filter(|resource| resource.is_object())
                .ok_or_else(|| rhai_error(WorkerError::ContractViolation))?;
            let resource_type = resource
                .get("resourceType")
                .and_then(Value::as_str)
                .ok_or_else(|| rhai_error(WorkerError::ContractViolation))?;
            let mode = entry
                .get("search")
                .and_then(Value::as_object)
                .and_then(|search| search.get("mode"))
                .and_then(Value::as_str)
                .unwrap_or("match");
            match (mode, resource_type) {
                ("match", actual) if actual == expected_resource_type => {
                    matches.push(resource.clone())
                }
                ("include", "OperationOutcome") | ("outcome", "OperationOutcome") => {
                    outcomes.push(resource.clone())
                }
                ("include", _) => included.push(resource.clone()),
                _ => return Err(rhai_error(WorkerError::ContractViolation)),
            }
        }
    }
    to_dynamic(BTreeMap::from([
        ("matches".to_owned(), Value::Array(matches)),
        ("included".to_owned(), Value::Array(included)),
        ("outcomes".to_owned(), Value::Array(outcomes)),
        ("next".to_owned(), next.map_or(Value::Null, Value::String)),
    ]))
    .map_err(|_| rhai_error(WorkerError::IpcFailed))
}

/// Rhai reserves `match` and uses `::` for static modules. The reviewed public
/// ABI deliberately uses language-neutral dotted namespaces, so normalize only
/// recognized host tokens in code, including backtick interpolation expressions,
/// never inside string literal portions or comments.
fn normalize_host_namespace_syntax(script: &str) -> String {
    const REPLACEMENTS: &[(&str, &str)] = &[
        (
            "protocol.fhir.parse_searchset",
            "protocol_fhir::parse_searchset",
        ),
        ("protocol.dci.search", "protocol_dci::search"),
        ("result.match", "result::matched"),
        ("result.no_match", "result::no_match"),
        ("result.ambiguous", "result::ambiguous"),
        ("result.fail", "result::fail"),
        ("failure.source_rejected", "failure::source_rejected"),
        ("failure.source_unavailable", "failure::source_unavailable"),
        ("failure.subject_mismatch", "failure::subject_mismatch"),
    ];
    let mut output = String::with_capacity(script.len());
    normalize_host_region(script, 0, script.len(), 0, REPLACEMENTS, &mut output);
    output
}

fn normalize_host_region(
    script: &str,
    start: usize,
    end: usize,
    depth: usize,
    replacements: &[(&str, &str)],
    output: &mut String,
) {
    if depth > MAX_EXPR_DEPTH {
        output.push_str(&script[start..end]);
        return;
    }
    let bytes = script.as_bytes();
    let mut index = start;
    while index < end {
        match bytes[index] {
            b'"' | b'\'' => {
                let next = skip_quoted_script_value(bytes, index).min(end);
                output.push_str(&script[index..next]);
                index = next;
                continue;
            }
            b'`' => {
                index = normalize_interpolated_script_string(
                    script,
                    index,
                    end,
                    depth,
                    replacements,
                    output,
                );
                continue;
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                let next = bytes[index + 2..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(end, |offset| (index + 2 + offset + 1).min(end));
                output.push_str(&script[index..next]);
                index = next;
                continue;
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let next = skip_nested_block_comment(bytes, index, end);
                output.push_str(&script[index..next]);
                index = next;
                continue;
            }
            _ => {}
        }
        let prior_is_identifier =
            index > 0 && (bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_');
        let replacement = (!prior_is_identifier).then(|| {
            SOURCE_HOST_FUNCTIONS
                .iter()
                .map(|function| (function.authored_name, function.normalized_name))
                .chain(replacements.iter().copied())
                .find(|(source, _)| {
                    bytes[index..end].starts_with(source.as_bytes())
                        && bytes
                            .get(index + source.len())
                            .is_none_or(|next| !next.is_ascii_alphanumeric() && *next != b'_')
                })
        });
        if let Some(Some((source, target))) = replacement {
            output.push_str(target);
            index += source.len();
        } else {
            let character = script[index..end]
                .chars()
                .next()
                .expect("index remains on a character boundary");
            output.push(character);
            index += character.len_utf8();
        }
    }
}

fn normalize_interpolated_script_string(
    script: &str,
    start: usize,
    end: usize,
    depth: usize,
    replacements: &[(&str, &str)],
    output: &mut String,
) -> usize {
    let bytes = script.as_bytes();
    let mut cursor = start + 1;
    let mut literal_start = start;
    while cursor < end {
        match bytes[cursor] {
            b'\\' => cursor = (cursor + 2).min(end),
            b'`' => {
                output.push_str(&script[literal_start..=cursor]);
                return cursor + 1;
            }
            b'$' if bytes.get(cursor + 1) == Some(&b'{') => {
                output.push_str(&script[literal_start..cursor + 2]);
                let expression_start = cursor + 2;
                let Some(expression_end) =
                    find_interpolation_end(bytes, expression_start, end, depth)
                else {
                    output.push_str(&script[expression_start..end]);
                    return end;
                };
                normalize_host_region(
                    script,
                    expression_start,
                    expression_end,
                    depth + 1,
                    replacements,
                    output,
                );
                output.push('}');
                cursor = expression_end + 1;
                literal_start = cursor;
            }
            _ => cursor += 1,
        }
    }
    output.push_str(&script[literal_start..end]);
    end
}

fn source_path(template: &str, values: Map) -> Result<String, Box<EvalAltResult>> {
    if !template.starts_with('/') || template.contains(['?', '#', '\r', '\n']) {
        return Err(rhai_error(WorkerError::ContractViolation));
    }
    let mut values = values;
    let mut used = BTreeSet::new();
    let mut rendered = Vec::new();
    for (index, segment) in template.split('/').enumerate() {
        if index == 0 {
            continue;
        }
        if let Some(name) = segment
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
        {
            if name.is_empty() || segment.len() != name.len() + 2 || !used.insert(name.to_string())
            {
                return Err(rhai_error(WorkerError::ContractViolation));
            }
            let value = values
                .remove(name)
                .ok_or_else(|| rhai_error(WorkerError::ContractViolation))?;
            let value = scalar_path_value(value)?;
            rendered.push(percent_encode_segment(&value));
        } else {
            if segment.is_empty()
                || matches!(segment, "." | "..")
                || segment.contains(['{', '}'])
                || contains_encoded_separator(segment)
            {
                return Err(rhai_error(WorkerError::ContractViolation));
            }
            rendered.push(segment.to_string());
        }
    }
    if !values.is_empty() || rendered.is_empty() {
        return Err(rhai_error(WorkerError::ContractViolation));
    }
    Ok(format!("/{}", rendered.join("/")))
}

fn scalar_path_value(value: Dynamic) -> Result<String, Box<EvalAltResult>> {
    if value.is::<String>() {
        let value = value.cast::<String>();
        if value.is_empty() || matches!(value.as_str(), "." | "..") {
            return Err(rhai_error(WorkerError::ContractViolation));
        }
        Ok(value)
    } else if value.is::<bool>() {
        Ok(value.cast::<bool>().to_string())
    } else if value.is::<rhai::INT>() {
        Ok(value.cast::<rhai::INT>().to_string())
    } else {
        Err(rhai_error(WorkerError::ContractViolation))
    }
}

fn percent_encode_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn contains_encoded_separator(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("%2f") || lower.contains("%5c") || lower.contains("%2e")
}

fn evaluate_in_process(
    request: &WorkerRequest,
    transport: Arc<dyn BlockingTransport>,
) -> Result<WorkerOutput, WorkerError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(request.limits.wall_time_ms))
        .ok_or(WorkerError::ContractViolation)?;
    let engine = hardened_engine(
        &request.limits,
        deadline,
        Some(transport.clone()),
        request.signed_dci_search,
    );
    let normalized = normalize_host_namespace_syntax(&request.script);
    let ast = engine
        .compile(normalized)
        .map_err(|_| WorkerError::ScriptRejected)?;
    let input = request
        .input
        .iter()
        .map(|(name, value)| (name.clone(), value.as_script_value()))
        .collect::<BTreeMap<_, _>>();
    let input = to_dynamic(input).map_err(|_| WorkerError::ContractViolation)?;
    let input = input
        .try_cast::<Map>()
        .ok_or(WorkerError::ContractViolation)?;
    let context = ScriptContext { input };
    let mut scope = Scope::new();
    xw::push_into_scope(&mut scope);
    let dynamic = engine
        .call_fn::<Dynamic>(&mut scope, &ast, &request.entrypoint, (context,))
        .map_err(classify_rhai_error)?;
    let terminal = dynamic
        .try_cast::<TerminalResult>()
        .ok_or(WorkerError::ContractViolation)?;
    let output = terminal_to_output(request, terminal)?;
    validate_output(request, &output)?;
    Ok(output)
}

fn terminal_to_output(
    request: &WorkerRequest,
    terminal: TerminalResult,
) -> Result<WorkerOutput, WorkerError> {
    match terminal.outcome {
        TerminalOutcome::Match => {
            if terminal
                .outputs
                .keys()
                .map(|name| name.as_str())
                .ne(request.output_schema.keys().map(String::as_str))
            {
                return Err(WorkerError::ContractViolation);
            }
            let mut outputs = BTreeMap::new();
            for (name, dynamic) in terminal.outputs {
                let schema = request
                    .output_schema
                    .get(name.as_str())
                    .ok_or(WorkerError::ContractViolation)?;
                outputs.insert(name.to_string(), dynamic_to_typed(dynamic, schema)?);
            }
            Ok(WorkerOutput::Success {
                outcome: WorkerOutcome::Match,
                outputs,
            })
        }
        TerminalOutcome::NoMatch => Ok(WorkerOutput::Success {
            outcome: WorkerOutcome::NoMatch,
            outputs: BTreeMap::new(),
        }),
        TerminalOutcome::Ambiguous => Ok(WorkerOutput::Success {
            outcome: WorkerOutcome::Ambiguous,
            outputs: BTreeMap::new(),
        }),
        TerminalOutcome::Failure(failure) => Ok(WorkerOutput::Failure { failure }),
    }
}

fn dynamic_to_typed(value: Dynamic, schema: &OutputSchema) -> Result<TypedValue, WorkerError> {
    if value.is_unit() {
        if !schema.nullable {
            return Err(WorkerError::ContractViolation);
        }
        return Ok(match schema.output_type {
            OutputType::String => TypedValue::String { value: None },
            OutputType::Boolean => TypedValue::Boolean { value: None },
            OutputType::Integer => TypedValue::Integer { value: None },
            OutputType::Date => TypedValue::Date { value: None },
        });
    }
    match schema.output_type {
        OutputType::String => value
            .try_cast::<String>()
            .map(|value| TypedValue::String { value: Some(value) })
            .ok_or(WorkerError::ContractViolation),
        OutputType::Boolean => value
            .try_cast::<bool>()
            .map(|value| TypedValue::Boolean { value: Some(value) })
            .ok_or(WorkerError::ContractViolation),
        OutputType::Integer => value
            .try_cast::<rhai::INT>()
            .map(|value| TypedValue::Integer { value: Some(value) })
            .ok_or(WorkerError::ContractViolation),
        OutputType::Date => value
            .try_cast::<String>()
            .map(|value| TypedValue::Date { value: Some(value) })
            .ok_or(WorkerError::ContractViolation),
    }
}

fn classify_rhai_error(error: Box<EvalAltResult>) -> WorkerError {
    if let EvalAltResult::ErrorRuntime(value, _) = error.as_ref() {
        if let Some(code) = value.clone().try_cast::<u8>() {
            return match code {
                1 => WorkerError::BudgetExceeded,
                2 => WorkerError::IpcFailed,
                3 => WorkerError::ContractViolation,
                _ => WorkerError::ScriptRejected,
            };
        }
    }
    if rhai_budget_error(&error) {
        WorkerError::BudgetExceeded
    } else {
        WorkerError::ScriptRejected
    }
}

fn rhai_error(error: WorkerError) -> Box<EvalAltResult> {
    let code = match error {
        WorkerError::BudgetExceeded => 1_u8,
        WorkerError::IpcFailed => 2,
        WorkerError::ContractViolation => 3,
        _ => 4,
    };
    EvalAltResult::ErrorRuntime(Dynamic::from(code), rhai::Position::NONE).into()
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

fn encode_line<T: Serialize>(value: &T, max_frame_bytes: usize) -> Result<Vec<u8>, WorkerError> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| WorkerError::IpcFailed)?;
    if bytes.len() + 1 > max_frame_bytes.min(MAX_IPC_FRAME_BYTES) {
        return Err(WorkerError::RequestTooLarge);
    }
    bytes.push(b'\n');
    Ok(bytes)
}

async fn read_async_frame<T: for<'de> Deserialize<'de>>(
    reader: &mut AsyncBufReader<tokio::process::ChildStdout>,
    max_frame_bytes: usize,
) -> Result<T, WorkerError> {
    let mut bytes = Vec::with_capacity(8 * 1024);
    (&mut *reader)
        .take((max_frame_bytes + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .await
        .map_err(|_| WorkerError::IpcFailed)?;
    decode_line(&bytes, max_frame_bytes)
}

fn read_sync_frame<T: for<'de> Deserialize<'de>>(max_frame_bytes: usize) -> Result<T, WorkerError> {
    let mut bytes = Vec::with_capacity(8 * 1024);
    std::io::BufReader::new(std::io::stdin().lock())
        .take((max_frame_bytes + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| WorkerError::IpcFailed)?;
    decode_line(&bytes, max_frame_bytes)
}

fn decode_line<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    max_frame_bytes: usize,
) -> Result<T, WorkerError> {
    if bytes.is_empty()
        || bytes.len() > max_frame_bytes
        || bytes.last() != Some(&b'\n')
        || bytes[..bytes.len() - 1].contains(&b'\n')
        || bytes[..bytes.len() - 1].contains(&b'\r')
    {
        return Err(WorkerError::IpcFailed);
    }
    serde_json::from_slice(&bytes[..bytes.len() - 1]).map_err(|_| WorkerError::IpcFailed)
}

fn write_sync_frame<T: Serialize>(value: &T, max_frame_bytes: usize) -> Result<(), WorkerError> {
    let bytes = encode_line(value, max_frame_bytes)?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&bytes)
        .and_then(|()| stdout.flush())
        .map_err(|_| WorkerError::IpcFailed)
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

    struct FixedTransport(std::sync::Mutex<Option<SourceResponse>>);

    impl FixedTransport {
        fn one(response: SourceResponse) -> Self {
            Self(std::sync::Mutex::new(Some(response)))
        }
    }

    impl BlockingTransport for FixedTransport {
        fn exchange(&self, _call: SourceCall) -> Result<SourceResponse, WorkerError> {
            self.0
                .lock()
                .map_err(|_| WorkerError::IpcFailed)?
                .take()
                .ok_or(WorkerError::IpcFailed)
        }
    }

    fn request(script: &str) -> WorkerRequest {
        let mut request = WorkerRequest::v1(script, "consult", WorkerLimits::default());
        request.output_schema.insert(
            "active".to_string(),
            OutputSchema {
                output_type: OutputType::Boolean,
                nullable: false,
                max_bytes: None,
                minimum: None,
                maximum: None,
            },
        );
        request
    }

    fn evaluate(request: &WorkerRequest) -> Result<WorkerOutput, WorkerError> {
        evaluate_in_process(
            request,
            Arc::new(FixedTransport::one(SourceResponse {
                status: 200,
                body: serde_json::json!({"active": true}),
                headers: BTreeMap::new(),
            })),
        )
    }

    #[test]
    fn natural_output_map_is_closed_and_deterministic() {
        let request = request("fn consult(ctx) { result.match(#{ active: true }) }");
        assert_eq!(evaluate(&request), evaluate(&request));
        assert_eq!(
            evaluate(&request),
            Ok(WorkerOutput::Success {
                outcome: WorkerOutcome::Match,
                outputs: BTreeMap::from([(
                    "active".to_string(),
                    TypedValue::Boolean { value: Some(true) }
                )]),
            })
        );
    }

    #[test]
    fn fhir_protocol_helper_returns_only_validated_search_categories_and_next() {
        let request = request(
            r#"fn consult(ctx) {
                let parsed = protocol.fhir.parse_searchset(source.get("/Patient"), "Patient");
                result.match(#{ active:
                    parsed.matches.len == 1
                    && parsed.included.len == 1
                    && parsed.outcomes.len == 1
                    && parsed.next == "https://registry.example/Patient?page=2"
                })
            }"#,
        );
        let output = evaluate_in_process(
            &request,
            Arc::new(FixedTransport::one(SourceResponse {
                status: 200,
                body: serde_json::json!({
                    "resourceType": "Bundle",
                    "type": "searchset",
                    "link": [{"relation": "next", "url": "https://registry.example/Patient?page=2"}],
                    "entry": [
                        {"search": {"mode": "match"}, "resource": {"resourceType": "Patient", "id": "one"}},
                        {"search": {"mode": "include"}, "resource": {"resourceType": "Organization", "id": "org"}},
                        {"search": {"mode": "outcome"}, "resource": {"resourceType": "OperationOutcome", "issue": []}}
                    ]
                }),
                headers: BTreeMap::new(),
            })),
        );
        assert_eq!(
            output,
            Ok(WorkerOutput::Success {
                outcome: WorkerOutcome::Match,
                outputs: BTreeMap::from([(
                    "active".to_owned(),
                    TypedValue::Boolean { value: Some(true) }
                )]),
            })
        );
    }

    #[test]
    fn signed_dci_helper_is_profile_gated_and_releases_only_the_host_response_body() {
        let script = r#"fn consult(ctx) {
            let verified = protocol.dci.search(#{
                selectors: #{ uin: "1234567890" },
                parameters: #{}
            });
            result.match(#{ active: verified.message.search_response.len == 1 })
        }"#;
        let disabled = request(script);
        assert_eq!(evaluate(&disabled), Err(WorkerError::ScriptRejected));

        let mut enabled = request(script);
        enabled.enable_signed_dci_search();
        let output = evaluate_in_process(
            &enabled,
            Arc::new(FixedTransport::one(SourceResponse {
                status: 200,
                body: serde_json::json!({
                    "message": {"search_response": [{"verified": true}]}
                }),
                headers: BTreeMap::new(),
            })),
        );
        assert_eq!(
            output,
            Ok(WorkerOutput::Success {
                outcome: WorkerOutcome::Match,
                outputs: BTreeMap::from([(
                    "active".to_owned(),
                    TypedValue::Boolean { value: Some(true) }
                )]),
            })
        );
    }

    #[test]
    fn outcome_constructors_do_not_carry_outputs() {
        for (constructor, outcome) in [
            ("no_match", WorkerOutcome::NoMatch),
            ("ambiguous", WorkerOutcome::Ambiguous),
        ] {
            let request = request(&format!("fn consult(ctx) {{ result.{constructor}() }}"));
            assert_eq!(
                evaluate(&request),
                Ok(WorkerOutput::Success {
                    outcome,
                    outputs: BTreeMap::new()
                })
            );
        }
        let request = request("fn consult(ctx) { result.fail(failure.subject_mismatch) }");
        assert_eq!(
            evaluate(&request),
            Ok(WorkerOutput::Failure {
                failure: ScriptFailure::SubjectMismatch
            })
        );
    }

    #[test]
    fn old_two_argument_and_operation_result_contracts_are_rejected() {
        assert_eq!(
            probe_script(
                "fn consult(input, prior) { #{} }",
                "consult",
                WorkerLimits::default()
            ),
            Err(WorkerError::ScriptRejected)
        );
        let request =
            request("fn consult(ctx) { #{ operations: [], outputs: #{ active: true } } }");
        assert_eq!(evaluate(&request), Err(WorkerError::ContractViolation));
    }

    #[test]
    fn script_probe_reports_safe_position_and_entrypoint_causes() {
        let syntax = probe_script_diagnostic(
            "fn consult(ctx) {\n  let value = ;\n}",
            "consult",
            WorkerLimits::default(),
        )
        .expect_err("syntax error rejects");
        assert_eq!(syntax.cause(), ScriptProbeCause::SyntaxError);
        assert_eq!(syntax.line(), Some(2));
        assert!(syntax.column().is_some());
        assert_eq!(syntax.to_string(), "syntax_error");

        let unknown = probe_script_diagnostic(
            "fn other(ctx) { result.no_match() }",
            "consult",
            WorkerLimits::default(),
        )
        .expect_err("missing entrypoint rejects");
        assert_eq!(unknown.cause(), ScriptProbeCause::UnknownFunction);
        assert_eq!(unknown.line(), None);
        assert_eq!(unknown.function(), Some("consult"));
        assert_eq!(unknown.valid_signatures(), ["consult(context)"]);
        assert_eq!(unknown.to_string(), "unknown_function");

        let signature = probe_script_diagnostic(
            "fn consult(left, right) { result.no_match() }",
            "consult",
            WorkerLimits::default(),
        )
        .expect_err("unsupported signature rejects");
        assert_eq!(
            signature.cause(),
            ScriptProbeCause::UnsupportedFunctionSignature
        );
        assert_eq!(signature.function(), Some("consult"));
        assert_eq!(signature.valid_signatures(), ["consult(context)"]);
        assert_eq!(signature.to_string(), "unsupported_function_signature");
    }

    #[test]
    fn script_probe_reports_unknown_xw_helper_with_closest_signature() {
        let diagnostic = probe_script_diagnostic(
            "fn consult(ctx) {\n  let value = xw.text.lowercase(\"argument-marker-7766\");\n  result.no_match()\n}",
            "consult",
            WorkerLimits::default(),
        )
        .expect_err("unknown xw helper rejects during preflight");
        assert_eq!(diagnostic.cause(), ScriptProbeCause::UnknownFunction);
        assert_eq!(diagnostic.function(), Some("xw.text.lowercase"));
        assert_eq!(diagnostic.line(), Some(2));
        assert!(diagnostic.column().is_some());
        assert_eq!(
            diagnostic.valid_signatures(),
            ["xw.text.lower_ascii(value: string) -> string"]
        );
        let rendered = format!("{diagnostic:?} {diagnostic}");
        assert!(!rendered.contains("argument-marker-7766"));
    }

    #[test]
    fn script_probe_reports_wrong_xw_arity_and_ignores_noncode_text() {
        let diagnostic = probe_script_diagnostic(
            r#"fn consult(ctx) {
                let example = "xw.text.lowercase(argument-marker)";
                // xw.text.lowercase(argument-marker)
                let value = xw.text.lower_ascii("left", "right");
                result.no_match()
            }"#,
            "consult",
            WorkerLimits::default(),
        )
        .expect_err("wrong xw signature rejects during preflight");
        assert_eq!(
            diagnostic.cause(),
            ScriptProbeCause::UnsupportedFunctionSignature
        );
        assert_eq!(diagnostic.function(), Some("xw.text.lower_ascii"));
        assert_eq!(
            diagnostic.valid_signatures(),
            ["xw.text.lower_ascii(value: string) -> string"]
        );

        probe_script_diagnostic(
            r#"fn consult(ctx) {
                let nested = xw.text.trim(xw.text.lower_ascii("ABC"));
                result.no_match()
            }"#,
            "consult",
            WorkerLimits::default(),
        )
        .expect("registered nested xw calls pass preflight");
    }

    #[test]
    fn script_probe_reports_unknown_source_call_with_authored_location_and_signature() {
        let diagnostic = probe_script_diagnostic(
            "fn consult(ctx) {\n  let response = source.gett(\"request-value-marker-9081\");\n  result.no_match()\n}",
            "consult",
            WorkerLimits::default(),
        )
        .expect_err("unknown source helper rejects during preflight");
        assert_eq!(diagnostic.cause(), ScriptProbeCause::UnknownFunction);
        assert_eq!(diagnostic.function(), Some("source.gett"));
        assert_eq!(diagnostic.line(), Some(2));
        assert_eq!(diagnostic.column(), Some(18));
        assert_eq!(
            diagnostic.valid_signatures(),
            ["source.get(target: string) -> response"]
        );
        let rendered = format!("{diagnostic:?} {diagnostic}");
        assert!(!rendered.contains("request-value-marker-9081"));
        assert!(!rendered.contains("Engine"));
    }

    #[test]
    fn script_probe_keeps_truly_unknown_source_call_bounded_and_value_free() {
        let diagnostic = probe_script_diagnostic(
            r#"fn consult(ctx) {
                source.teleport(#{ credential: "credential-marker-4412" });
                source.publish("response-marker-6673");
                result.no_match()
            }"#,
            "consult",
            WorkerLimits::default(),
        )
        .expect_err("the first unknown source helper is the primary diagnostic");
        assert_eq!(diagnostic.cause(), ScriptProbeCause::UnknownFunction);
        assert_eq!(diagnostic.function(), Some("source.teleport"));
        assert_eq!(diagnostic.line(), Some(2));
        assert!(diagnostic.column().is_some());
        assert!(!diagnostic.valid_signatures().is_empty());
        assert!(diagnostic.valid_signatures().len() <= 2);
        assert!(diagnostic
            .valid_signatures()
            .iter()
            .all(|signature| signature.starts_with("source.")));
        let rendered = format!("{diagnostic:?} {diagnostic}");
        assert!(!rendered.contains("credential-marker-4412"));
        assert!(!rendered.contains("response-marker-6673"));
        assert!(!rendered.contains("source.publish"));
    }

    #[test]
    fn script_probe_checks_source_arity_and_ignores_noncode_text() {
        let diagnostic = probe_script_diagnostic(
            r#"fn consult(ctx) {
                let example = "source.gett(request-value-marker)";
                // source.teleport(request-value-marker)
                /* source.publish(request-value-marker) */
                source.get();
                result.no_match()
            }"#,
            "consult",
            WorkerLimits::default(),
        )
        .expect_err("wrong source signature rejects during preflight");
        assert_eq!(
            diagnostic.cause(),
            ScriptProbeCause::UnsupportedFunctionSignature
        );
        assert_eq!(diagnostic.function(), Some("source.get"));
        assert_eq!(diagnostic.line(), Some(5));
        assert_eq!(
            diagnostic.valid_signatures(),
            [
                "source.get(target: string) -> response",
                "source.get(target: string, options: map) -> response",
            ]
        );

        probe_script_diagnostic(
            r#"fn consult(ctx) {
                let example = "source.gett(request-value-marker)";
                // source.teleport(request-value-marker)
                /* source.publish(request-value-marker) */
                let response = source.get("/reviewed");
                result.no_match()
            }"#,
            "consult",
            WorkerLimits::default(),
        )
        .expect("unknown source calls in comments and strings are ignored");
    }

    #[test]
    fn script_probe_normalizes_and_checks_calls_inside_backtick_interpolation() {
        let known = r#"fn consult(ctx) {
  let message = `literal source.get("/literal") source.gett(ignored-marker) ${source.get("/reviewed").status}`;
  result.no_match()
}"#;
        let normalized = normalize_host_namespace_syntax(known);
        assert!(
            normalized.contains(r#"literal source.get("/literal") source.gett(ignored-marker)"#)
        );
        assert!(normalized.contains(r#"${source::get("/reviewed").status}"#));
        probe_script_diagnostic(known, "consult", WorkerLimits::default())
            .expect("known source call inside interpolation passes preflight");

        let unknown = r#"fn consult(ctx) {
  let message = `${source.gett("interpolation-value-marker-1168")}`;
  result.no_match()
}"#;
        let diagnostic = probe_script_diagnostic(unknown, "consult", WorkerLimits::default())
            .expect_err("unknown source call inside interpolation rejects");
        assert_eq!(diagnostic.cause(), ScriptProbeCause::UnknownFunction);
        assert_eq!(diagnostic.function(), Some("source.gett"));
        assert_eq!(diagnostic.line(), Some(2));
        assert_eq!(diagnostic.column(), Some(20));
        assert_eq!(
            diagnostic.valid_signatures(),
            ["source.get(target: string) -> response"]
        );
        assert!(!format!("{diagnostic:?} {diagnostic}").contains("interpolation-value-marker-1168"));

        let wrong_arity = r#"fn consult(ctx) {
  let message = `${source.get()}`;
  result.no_match()
}"#;
        let diagnostic = probe_script_diagnostic(wrong_arity, "consult", WorkerLimits::default())
            .expect_err("wrong source arity inside interpolation rejects");
        assert_eq!(
            diagnostic.cause(),
            ScriptProbeCause::UnsupportedFunctionSignature
        );
        assert_eq!(diagnostic.function(), Some("source.get"));
        assert_eq!(diagnostic.line(), Some(2));
        assert_eq!(diagnostic.column(), Some(20));
    }

    #[test]
    fn script_probe_ignores_host_calls_in_nested_block_comments() {
        let ordinary = r#"fn consult(ctx) {
            /* outer source.get("/literal") and source.gett("ordinary-value-marker")
                `literal ${source.teleport("ordinary-value-marker")}`
                /* nested xw.text.lowercase("ordinary-value-marker") */
                source.publish("ordinary-value-marker")
            */
            let response = source.get("/reviewed");
            result.no_match()
        }"#;
        let normalized = normalize_host_namespace_syntax(ordinary);
        assert!(normalized.contains(r#"outer source.get("/literal")"#));
        assert!(normalized.contains("${source.teleport"));
        probe_script_diagnostic(ordinary, "consult", WorkerLimits::default())
            .expect("host-like text in an ordinary nested block comment is ignored");

        let interpolated = r#"fn consult(ctx) {
            let message = `${
                /* outer source.get("/literal") and source.gett("interpolation-value-marker")
                    /* nested xw.text.lowercase("interpolation-value-marker") */
                    source.publish("interpolation-value-marker")
                */
                source.get("/reviewed").status
            }`;
            result.no_match()
        }"#;
        let normalized = normalize_host_namespace_syntax(interpolated);
        assert!(normalized.contains(r#"outer source.get("/literal")"#));
        assert!(normalized.contains(r#"source::get("/reviewed").status"#));
        probe_script_diagnostic(interpolated, "consult", WorkerLimits::default())
            .expect("host-like text in an interpolated nested block comment is ignored");
    }

    #[test]
    fn script_probe_leaves_unterminated_nested_comment_to_rhai_syntax_diagnostics() {
        let script = r#"fn consult(ctx) {
            /* outer
                /* nested source.gett("nested-value-marker-5529") */
                source.publish("outer-value-marker-8841")
            result.no_match()
        }"#;
        let diagnostic = probe_script_diagnostic(script, "consult", WorkerLimits::default())
            .expect_err("Rhai rejects the unterminated outer block comment");
        assert_eq!(diagnostic.cause(), ScriptProbeCause::SyntaxError);
        assert_eq!(diagnostic.function(), None);
        assert!(diagnostic.valid_signatures().is_empty());
        let rendered = format!("{diagnostic:?} {diagnostic}");
        assert!(!rendered.contains("nested-value-marker-5529"));
        assert!(!rendered.contains("outer-value-marker-8841"));
    }

    #[test]
    fn script_probe_checks_qualified_source_calls() {
        probe_script_diagnostic(
            r#"fn consult(ctx) {
                let response = source::get("/reviewed");
                result.no_match()
            }"#,
            "consult",
            WorkerLimits::default(),
        )
        .expect("known qualified source call passes preflight");

        let diagnostic = probe_script_diagnostic(
            "fn consult(ctx) {\n  let response = source::gett(\"qualified-value-marker-7732\");\n  result.no_match()\n}",
            "consult",
            WorkerLimits::default(),
        )
        .expect_err("unknown qualified source call rejects");
        assert_eq!(diagnostic.cause(), ScriptProbeCause::UnknownFunction);
        assert_eq!(diagnostic.function(), Some("source::gett"));
        assert_eq!(diagnostic.line(), Some(2));
        assert_eq!(diagnostic.column(), Some(18));
        assert_eq!(
            diagnostic.valid_signatures(),
            ["source.get(target: string) -> response"]
        );
        assert!(!format!("{diagnostic:?} {diagnostic}").contains("qualified-value-marker-7732"));

        let diagnostic = probe_script_diagnostic(
            "fn consult(ctx) {\n  source::post_json(\"/reviewed\");\n  result.no_match()\n}",
            "consult",
            WorkerLimits::default(),
        )
        .expect_err("wrong qualified source arity rejects");
        assert_eq!(
            diagnostic.cause(),
            ScriptProbeCause::UnsupportedFunctionSignature
        );
        assert_eq!(diagnostic.function(), Some("source::post_json"));
        assert_eq!(diagnostic.line(), Some(2));
        assert_eq!(diagnostic.column(), Some(3));
        assert_eq!(
            diagnostic.valid_signatures(),
            [
                "source.post_json(target: string, body: value) -> response",
                "source.post_json(target: string, body: value, options: map) -> response",
            ]
        );
    }

    #[test]
    fn script_probe_selects_first_host_call_across_namespaces() {
        for (script, expected) in [
            (
                "fn consult(ctx) {\n  source.gett(\"first\");\n  xw.text.lowercase(\"second\");\n  result.no_match()\n}",
                "source.gett",
            ),
            (
                "fn consult(ctx) {\n  xw.text.lowercase(\"first\");\n  source.gett(\"second\");\n  result.no_match()\n}",
                "xw.text.lowercase",
            ),
        ] {
            let diagnostic = probe_script_diagnostic(script, "consult", WorkerLimits::default())
                .expect_err("first authored unknown host call rejects");
            assert_eq!(diagnostic.function(), Some(expected));
            assert_eq!(diagnostic.line(), Some(2));
        }
    }

    #[test]
    fn source_path_encodes_one_whole_segment_and_rejects_unsafe_shapes() {
        assert_eq!(
            source_path(
                "/records/{id}",
                Map::from_iter([("id".into(), Dynamic::from("A/B C"))])
            )
            .expect("safe path"),
            "/records/A%2FB%20C"
        );
        assert!(source_path(
            "/records/{id}",
            Map::from_iter([
                ("id".into(), Dynamic::from("value")),
                ("extra".into(), Dynamic::from("value"))
            ])
        )
        .is_err());
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
            let request = request(&format!("fn consult(ctx) {{ {expression} }}"));
            assert_eq!(
                evaluate(&request),
                Err(WorkerError::ScriptRejected),
                "{expression} must be unavailable"
            );
        }
    }

    #[test]
    fn ipc_debug_rendering_never_exposes_script_or_source_data() {
        let mut worker_request = request(
            "fn consult(ctx) { let marker = \"script-marker-1188\"; result.match(#{ active: true }) }",
        );
        worker_request.input.insert(
            "subject".to_owned(),
            TypedValue::String {
                value: Some("input-marker-2299".to_owned()),
            },
        );
        let source_call = SourceCall::PostJson {
            call_id: 0,
            target: "/records/target-marker-3300".to_owned(),
            body: serde_json::json!({"secret": "body-marker-4411"}),
            options: SourceOptions {
                query: BTreeMap::from([(
                    "selector".to_owned(),
                    Value::String("query-marker-5522".to_owned()),
                )]),
                headers: BTreeMap::from([(
                    "x-profile".to_owned(),
                    "header-marker-6633".to_owned(),
                )]),
            },
        };
        let source_response = SourceResponse {
            status: 200,
            body: serde_json::json!({"record": "response-marker-7744"}),
            headers: BTreeMap::from([(
                "location".to_owned(),
                Some("response-header-marker-8855".to_owned()),
            )]),
        };
        let output = WorkerOutput::Success {
            outcome: WorkerOutcome::Match,
            outputs: BTreeMap::from([(
                "active".to_owned(),
                TypedValue::String {
                    value: Some("output-marker-9966".to_owned()),
                },
            )]),
        };
        let source_call_debug = format!("{source_call:?}");
        let source_response_debug = format!("{source_response:?}");
        let rendered = format!(
            "{worker_request:?} {source_call_debug} {source_response_debug} {output:?} {:?} {:?}",
            ChildFrame::HostCall { call: source_call },
            ParentFrame::HostResponse {
                call_id: 0,
                response: source_response,
            }
        );
        for marker in [
            "script-marker-1188",
            "input-marker-2299",
            "target-marker-3300",
            "body-marker-4411",
            "query-marker-5522",
            "header-marker-6633",
            "response-marker-7744",
            "response-header-marker-8855",
            "output-marker-9966",
        ] {
            assert!(!rendered.contains(marker), "Debug leaked {marker}");
        }
        assert!(rendered.contains("[REDACTED]"));
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

// SPDX-License-Identifier: Apache-2.0
//! Hardened CEL worker client and line protocol.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crosswalk_core::{
    MappingRuntime, RuntimeOptions, SecurityLimits, StandaloneEvalError, StandaloneExpressionInput,
};
use registry_notary_core::RegistryNotaryCelConfig;
use registry_notary_worker_harness::{
    WorkerCommand, WorkerError, WorkerPool, WorkerPoolConfig, WorkerPoolSnapshot,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::OnceCell;

use crate::metrics::AppMetrics;

pub const CEL_WORKER_PROTOCOL_V1: &str = "registry-notary-cel-worker/v1";
pub const CEL_WORKER_REQUEST_ENVELOPE_BYTES: usize = 4096;
pub const CEL_WORKER_MAX_STDIN_BYTES: usize =
    1024 * 1024 + 256 * 1024 + CEL_WORKER_REQUEST_ENVELOPE_BYTES;

#[derive(Clone, Debug)]
pub struct CelWorkerConfig {
    pub command: PathBuf,
    pub command_args: Vec<OsString>,
    pub command_envs: Vec<(OsString, OsString)>,
    pub current_dir: Option<PathBuf>,
    pub forbidden_env_names: BTreeSet<OsString>,
    pub max_workers: usize,
    pub request_timeout: Duration,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_stderr_bytes: usize,
    pub max_memory_bytes: Option<u64>,
    pub allow_regex: bool,
    pub limits: CelWorkerLimits,
}

impl CelWorkerConfig {
    #[must_use]
    pub fn for_current_exe_subcommand() -> Self {
        let mut forbidden_env_names = BTreeSet::new();
        for name in [
            "REGISTRY_NOTARY_PKCS11_PIN",
            "REGISTRY_NOTARY_PKCS11_USER_PIN",
            "REGISTRY_NOTARY_HSM_PIN",
            "REGISTRY_NOTARY_API_KEY",
            "REGISTRY_NOTARY_BEARER_TOKEN",
            "REGISTRY_NOTARY_SOURCE_TOKEN",
            "REGISTRY_NOTARY_SOURCE_CREDENTIAL_JSON",
            "REGISTRY_NOTARY_DCI_CLIENT_SECRET",
            "REGISTRY_NOTARY_AUDIT_HASH_SECRET",
        ] {
            forbidden_env_names.insert(OsString::from(name));
        }
        let (command, command_args) = default_worker_command();
        Self {
            command,
            command_args,
            command_envs: Vec::new(),
            current_dir: None,
            forbidden_env_names,
            max_workers: 2,
            request_timeout: Duration::from_secs(2),
            max_request_bytes: 64 * 1024,
            max_response_bytes: 16 * 1024,
            max_stderr_bytes: 1024,
            max_memory_bytes: Some(128 * 1024 * 1024),
            allow_regex: false,
            limits: CelWorkerLimits::default(),
        }
    }

    #[must_use]
    pub fn from_standalone_config(config: &RegistryNotaryCelConfig) -> Self {
        let mut worker = Self::for_current_exe_subcommand();
        worker.max_workers = config.worker_count;
        worker.request_timeout = Duration::from_millis(config.eval_timeout_ms);
        worker.max_request_bytes = config
            .max_binding_json_bytes
            .saturating_add(config.max_expression_bytes)
            .saturating_add(CEL_WORKER_REQUEST_ENVELOPE_BYTES);
        worker.max_response_bytes = config
            .max_result_json_bytes
            .saturating_add(2048)
            .max(config.max_result_json_bytes);
        worker.max_stderr_bytes = config.worker_stderr_bytes;
        worker.max_memory_bytes = Some(config.worker_memory_bytes);
        worker.allow_regex = config.allow_regex;
        worker.limits = CelWorkerLimits::from(config);
        worker
    }
}

pub struct CelWorker {
    config: Arc<CelWorkerConfig>,
    pool: OnceCell<WorkerPool>,
    metrics: Option<Arc<AppMetrics>>,
}

impl std::fmt::Debug for CelWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CelWorker").finish_non_exhaustive()
    }
}

impl CelWorker {
    #[must_use]
    pub fn lazy(config: CelWorkerConfig) -> Self {
        Self {
            config: Arc::new(config),
            pool: OnceCell::new(),
            metrics: None,
        }
    }

    #[must_use]
    pub(crate) fn with_metrics(mut self, metrics: Arc<AppMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub async fn new(config: CelWorkerConfig) -> Result<Self, CelWorkerError> {
        let worker = Self::lazy(config);
        worker.pool().await?;
        Ok(worker)
    }

    async fn pool(&self) -> Result<&WorkerPool, CelWorkerError> {
        self.pool
            .get_or_try_init(|| async {
                WorkerPool::new(worker_pool_config((*self.config).clone()))
                    .await
                    .map_err(CelWorkerError::Harness)
            })
            .await
    }

    pub fn validate_config(&self) -> Result<(), CelWorkerError> {
        if command_requires_existing_path(&self.config.command) && !self.config.command.is_file() {
            return Err(CelWorkerError::Harness(WorkerError::InvalidConfig {
                reason: "worker command path must exist",
            }));
        }
        worker_pool_config((*self.config).clone())
            .validate()
            .map_err(CelWorkerError::Harness)
    }

    pub async fn evaluate(
        &self,
        expression: &str,
        root_bindings: Value,
    ) -> Result<Value, CelWorkerError> {
        let started_at = Instant::now();
        let policy_hash = cel_policy_hash(expression);
        let request = CelWorkerRequest {
            protocol: CEL_WORKER_PROTOCOL_V1,
            expression,
            policy_hash: Some(policy_hash.clone()),
            allow_regex: self.config.allow_regex,
            limits: self.config.limits.clone(),
            root_bindings,
        };
        let pool = match self.pool().await {
            Ok(pool) => pool,
            Err(error) => {
                self.record_evaluation(&error, started_at.elapsed());
                return Err(error);
            }
        };
        let value = match pool.execute_json(request).await {
            Ok(value) => value,
            Err(error) => {
                let error = CelWorkerError::Harness(error);
                self.record_evaluation(&error, started_at.elapsed());
                return Err(error);
            }
        };
        let snapshot = pool.snapshot().await;
        self.record_snapshot(&snapshot);
        let response = match serde_json::from_value::<CelWorkerResponse>(value) {
            Ok(response) => response,
            Err(_) => {
                let error = CelWorkerError::Protocol;
                self.record_evaluation(&error, started_at.elapsed());
                return Err(error);
            }
        };
        if response.protocol != CEL_WORKER_PROTOCOL_V1 {
            let error = CelWorkerError::Protocol;
            self.record_evaluation(&error, started_at.elapsed());
            return Err(error);
        }
        if response.policy_hash.as_deref() != Some(policy_hash.as_str()) {
            let error = CelWorkerError::Protocol;
            self.record_evaluation(&error, started_at.elapsed());
            return Err(error);
        }
        if let Some(result) = response.value {
            self.record_evaluation_success(started_at.elapsed());
            return Ok(result);
        }
        let error = match response.error.as_deref() {
            Some("compile") => Err(CelWorkerError::Compile),
            Some("evaluate") => Err(CelWorkerError::Evaluate),
            Some("invalid_request") => Err(CelWorkerError::Protocol),
            _ => Err(CelWorkerError::Protocol),
        };
        if let Err(error) = &error {
            self.record_evaluation(error, started_at.elapsed());
        }
        error
    }

    pub async fn snapshot(&self) -> Result<WorkerPoolSnapshot, CelWorkerError> {
        let snapshot = self.pool().await?.snapshot().await;
        self.record_snapshot(&snapshot);
        Ok(snapshot)
    }

    pub async fn check_ready(&self) -> bool {
        let Ok(pool) = self.pool().await else {
            return false;
        };
        let ready = pool.check_ready().await;
        let snapshot = pool.snapshot().await;
        self.record_snapshot(&snapshot);
        ready
    }

    fn record_evaluation_success(&self, duration: Duration) {
        if let Some(metrics) = &self.metrics {
            metrics.record_cel_evaluation("success", duration.as_millis() as u64);
        }
    }

    fn record_evaluation(&self, error: &CelWorkerError, duration: Duration) {
        if let Some(metrics) = &self.metrics {
            metrics.record_cel_evaluation(error.metric_outcome(), duration.as_millis() as u64);
        }
    }

    fn record_snapshot(&self, snapshot: &WorkerPoolSnapshot) {
        if let Some(metrics) = &self.metrics {
            metrics.set_cel_worker_pool("max", snapshot.max_workers as u64);
            metrics.set_cel_worker_pool("idle", snapshot.idle_workers as u64);
            metrics.set_cel_worker_pool("in_flight", snapshot.in_flight as u64);
            metrics.set_cel_worker_pool("replacements_total", snapshot.replacements_total);
            metrics.set_cel_worker_pool("circuit_open", u64::from(snapshot.circuit_open));
        }
    }
}

#[must_use]
pub fn cel_policy_hash(expression: &str) -> String {
    format!(
        "sha256:{}",
        hex_encode(&Sha256::digest(expression.as_bytes()))
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn worker_pool_config(config: CelWorkerConfig) -> WorkerPoolConfig {
    let mut command = WorkerCommand::new(config.command);
    for arg in config.command_args {
        command = command.arg(arg);
    }
    for (key, value) in config.command_envs {
        command = command.env(key, value);
    }
    if let Some(current_dir) = config.current_dir {
        command = command.current_dir(current_dir);
    }
    WorkerPoolConfig {
        command,
        forbidden_env_names: config.forbidden_env_names,
        max_workers: config.max_workers,
        request_timeout: config.request_timeout,
        max_request_bytes: config.max_request_bytes,
        max_stdout_bytes: config.max_response_bytes,
        max_stderr_bytes: config.max_stderr_bytes,
        max_memory_bytes: config.max_memory_bytes,
        replacement_window: Duration::from_secs(60),
        max_replacements_per_window: config.max_workers.saturating_mul(4).max(4),
        circuit_breaker_cooldown: Duration::from_secs(30),
    }
}

fn default_worker_command() -> (PathBuf, Vec<OsString>) {
    if let Some(command) = std::env::var_os("REGISTRY_NOTARY_CEL_WORKER_COMMAND") {
        return (PathBuf::from(command), Vec::new());
    }
    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("registry-notary"));
    if let Some(sibling) = sibling_worker_binary(&current_exe) {
        return (sibling, Vec::new());
    }
    (current_exe, vec![OsString::from("cel-worker")])
}

fn command_requires_existing_path(command: &Path) -> bool {
    command.is_absolute() || command.components().count() > 1
}

fn sibling_worker_binary(current_exe: &Path) -> Option<PathBuf> {
    let parent = current_exe.parent()?;
    for candidate_parent in [Some(parent), parent.parent()].into_iter().flatten() {
        let candidate = candidate_parent.join("registry-notary-cel-worker");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[derive(Debug, Error)]
pub enum CelWorkerError {
    #[error("CEL worker harness failed")]
    Harness(#[source] WorkerError),
    #[error("CEL worker protocol mismatch")]
    Protocol,
    #[error("CEL expression did not compile")]
    Compile,
    #[error("CEL expression evaluation failed")]
    Evaluate,
}

impl CelWorkerError {
    fn metric_outcome(&self) -> &'static str {
        match self {
            Self::Harness(WorkerError::Saturated { .. }) => "saturated",
            Self::Harness(WorkerError::CircuitOpen { .. }) => "circuit_open",
            Self::Harness(WorkerError::Timeout { .. }) => "timeout",
            Self::Harness(WorkerError::RequestTooLarge { .. }) => "request_too_large",
            Self::Harness(WorkerError::StdoutTooLarge { .. }) => "output_too_large",
            Self::Harness(WorkerError::InvalidOutput { .. }) | Self::Protocol => "protocol_error",
            Self::Harness(
                WorkerError::InvalidConfig { .. }
                | WorkerError::Encode { .. }
                | WorkerError::Spawn { .. }
                | WorkerError::WorkerExited { .. }
                | WorkerError::Io { .. },
            ) => "worker_error",
            Self::Compile => "compile_error",
            Self::Evaluate => "evaluate_error",
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CelWorkerRequest<'a> {
    pub protocol: &'a str,
    pub expression: &'a str,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(default)]
    pub allow_regex: bool,
    #[serde(default)]
    pub limits: CelWorkerLimits,
    pub root_bindings: Value,
}

#[derive(Serialize, Deserialize)]
pub struct CelWorkerResponse {
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CelWorkerLimits {
    pub max_expression_bytes: usize,
    pub max_binding_json_bytes: usize,
    pub max_output_json_bytes: usize,
    pub max_list_len: usize,
    pub max_string_bytes: usize,
    pub max_object_depth: usize,
    pub max_object_keys: usize,
}

impl Default for CelWorkerLimits {
    fn default() -> Self {
        Self::from(&RegistryNotaryCelConfig::default())
    }
}

impl From<&RegistryNotaryCelConfig> for CelWorkerLimits {
    fn from(config: &RegistryNotaryCelConfig) -> Self {
        Self {
            max_expression_bytes: config.max_expression_bytes,
            max_binding_json_bytes: config.max_binding_json_bytes,
            max_output_json_bytes: config.max_result_json_bytes,
            max_list_len: config.max_list_items,
            max_string_bytes: config.max_string_bytes,
            max_object_depth: config.max_object_depth,
            max_object_keys: config.max_object_keys,
        }
    }
}

impl From<&CelWorkerLimits> for SecurityLimits {
    fn from(limits: &CelWorkerLimits) -> Self {
        Self {
            max_expression_bytes: limits.max_expression_bytes,
            max_output_json_bytes: limits.max_output_json_bytes,
            max_list_len: limits.max_list_len,
            max_string_bytes: limits.max_string_bytes,
            ..SecurityLimits::default()
        }
    }
}

pub fn run_stdio_worker() {
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let mut stdout = io::stdout();
    let mut line = Vec::new();

    loop {
        line.clear();
        match read_worker_stdin_frame(&mut stdin, &mut line) {
            Ok(Some(())) => {}
            Ok(None) => break,
            Err(_) => process::exit(2),
        }
        let response = match serde_json::from_slice::<CelWorkerRequest<'_>>(line.trim_ascii_end()) {
            Ok(request) => handle_worker_request(request),
            Err(_) => CelWorkerResponse {
                protocol: CEL_WORKER_PROTOCOL_V1.to_string(),
                policy_hash: None,
                value: None,
                error: Some("invalid_request".to_string()),
            },
        };
        if serde_json::to_writer(&mut stdout, &response).is_err() {
            process::exit(2);
        }
        if writeln!(stdout).and_then(|_| stdout.flush()).is_err() {
            process::exit(2);
        }
    }
}

fn read_worker_stdin_frame<R: BufRead>(
    reader: &mut R,
    line: &mut Vec<u8>,
) -> io::Result<Option<()>> {
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(()))
            };
        }

        let (consumed, payload_bytes) =
            if let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
                (newline + 1, newline)
            } else {
                (buffer.len(), buffer.len())
            };

        if line.len() + payload_bytes > CEL_WORKER_MAX_STDIN_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CEL worker stdin frame exceeds configured limit",
            ));
        }

        line.extend_from_slice(&buffer[..consumed]);
        reader.consume(consumed);
        if line.last() == Some(&b'\n') {
            return Ok(Some(()));
        }
    }
}

fn handle_worker_request(request: CelWorkerRequest<'_>) -> CelWorkerResponse {
    if request.protocol != CEL_WORKER_PROTOCOL_V1 {
        return worker_error(None, "invalid_request");
    }
    let policy_hash = cel_policy_hash(request.expression);
    if request
        .policy_hash
        .as_deref()
        .is_some_and(|provided| provided != policy_hash)
    {
        return worker_error(Some(policy_hash), "invalid_request");
    }
    if !request.allow_regex && cel_expression_uses_regex(request.expression) {
        return worker_error(Some(policy_hash), "compile");
    }
    let security_limits = SecurityLimits::from(&request.limits);
    if security_limits.check_expr(request.expression).is_err()
        || validate_worker_json_limits(&request.root_bindings, &request.limits).is_err()
    {
        return worker_error(Some(policy_hash), "invalid_request");
    }
    let Value::Object(bindings) = request.root_bindings else {
        return worker_error(Some(policy_hash), "invalid_request");
    };
    let mut runtime = MappingRuntime::new(RuntimeOptions::default());
    runtime.limits = security_limits;
    match runtime.evaluate_cel_expression_with_input(
        request.expression,
        StandaloneExpressionInput::new(bindings.into_iter().collect()),
    ) {
        Ok(value) => CelWorkerResponse {
            protocol: CEL_WORKER_PROTOCOL_V1.to_string(),
            policy_hash: Some(policy_hash),
            value: Some(value),
            error: None,
        },
        Err(StandaloneEvalError::Compile(_))
        | Err(StandaloneEvalError::InvalidBindingName { .. }) => {
            worker_error(Some(policy_hash), "compile")
        }
        Err(StandaloneEvalError::Evaluate { .. }) => worker_error(Some(policy_hash), "evaluate"),
    }
}
fn worker_error(policy_hash: Option<String>, error: &str) -> CelWorkerResponse {
    CelWorkerResponse {
        protocol: CEL_WORKER_PROTOCOL_V1.to_string(),
        policy_hash,
        value: None,
        error: Some(error.to_string()),
    }
}

#[must_use]
pub fn cel_expression_uses_regex(expression: &str) -> bool {
    if expression.contains("=~") {
        return true;
    }
    cel_function_calls(expression).into_iter().any(|call| {
        let final_segment = call.rsplit('.').next().unwrap_or(call.as_str());
        matches!(
            final_segment,
            "matches"
                | "regex_replace"
                | "regex_extract"
                | "text_matches"
                | "text_regex_replace"
                | "text_regex_extract"
                | "validate_matches"
                | "id_is_valid"
        )
    })
}

fn cel_function_calls(expression: &str) -> Vec<String> {
    let bytes = expression.as_bytes();
    let mut calls = Vec::new();
    let mut index = 0;
    let mut quote: Option<u8> = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(active_quote) = quote {
            if byte == b'\\' {
                index = index.saturating_add(2);
                continue;
            }
            if byte == active_quote {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
            index += 1;
            continue;
        }
        if !is_cel_identifier_start_byte(byte) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len()
            && (is_cel_identifier_continue_byte(bytes[index]) || bytes[index] == b'.')
        {
            index += 1;
        }
        let mut lookahead = index;
        while lookahead < bytes.len() && bytes[lookahead].is_ascii_whitespace() {
            lookahead += 1;
        }
        if bytes.get(lookahead) == Some(&b'(') {
            calls.push(expression[start..index].to_string());
        }
    }
    calls
}

fn is_cel_identifier_start_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_cel_identifier_continue_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn validate_worker_json_limits(value: &Value, limits: &CelWorkerLimits) -> Result<(), ()> {
    if serialized_json_len(value)? > limits.max_binding_json_bytes {
        return Err(());
    }
    let mut stack = vec![(value, 0_usize)];
    while let Some((value, depth)) = stack.pop() {
        if depth > limits.max_object_depth {
            return Err(());
        }
        match value {
            Value::String(value) if value.len() > limits.max_string_bytes => return Err(()),
            Value::Array(values) => {
                if values.len() > limits.max_list_len {
                    return Err(());
                }
                for value in values {
                    stack.push((value, depth + 1));
                }
            }
            Value::Object(values) => {
                if values.len() > limits.max_object_keys {
                    return Err(());
                }
                for value in values.values() {
                    stack.push((value, depth + 1));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn serialized_json_len(value: &Value) -> Result<usize, ()> {
    struct CountingWriter {
        count: usize,
    }

    impl std::io::Write for CountingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.count = self
                .count
                .checked_add(buf.len())
                .ok_or_else(|| std::io::Error::other("serialized JSON length overflow"))?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut writer = CountingWriter { count: 0 };
    serde_json::to_writer(&mut writer, value).map_err(|_| ())?;
    Ok(writer.count)
}

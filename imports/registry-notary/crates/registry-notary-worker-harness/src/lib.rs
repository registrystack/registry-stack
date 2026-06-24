use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    collections::VecDeque,
    ffi::OsString,
    fmt,
    path::PathBuf,
    process::ExitStatus,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{
    io::{self, AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
    sync::Mutex,
    task::JoinHandle,
    time,
};
use tracing::error;

#[derive(Clone, Eq, PartialEq)]
pub struct WorkerCommand {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub envs: Vec<(OsString, OsString)>,
    pub current_dir: Option<PathBuf>,
}

impl fmt::Debug for WorkerCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerCommand")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("env_count", &self.envs.len())
            .field("current_dir", &self.current_dir)
            .finish()
    }
}

impl WorkerCommand {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            envs: Vec::new(),
            current_dir: None,
        }
    }

    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.envs.push((key.into(), value.into()));
        self
    }

    pub fn current_dir(mut self, current_dir: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(current_dir.into());
        self
    }
}

#[derive(Clone, Debug)]
pub struct WorkerPoolConfig {
    pub command: WorkerCommand,
    pub forbidden_env_names: BTreeSet<OsString>,
    pub max_workers: usize,
    pub request_timeout: Duration,
    pub max_request_bytes: usize,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub max_memory_bytes: Option<u64>,
    pub replacement_window: Duration,
    pub max_replacements_per_window: usize,
    pub circuit_breaker_cooldown: Duration,
}

impl WorkerPoolConfig {
    pub fn validate(&self) -> Result<(), WorkerError> {
        if self.max_workers == 0 {
            return Err(WorkerError::InvalidConfig {
                reason: "max_workers must be greater than zero",
            });
        }
        if self.request_timeout.is_zero() {
            return Err(WorkerError::InvalidConfig {
                reason: "request_timeout must be greater than zero",
            });
        }
        if self.max_request_bytes == 0 {
            return Err(WorkerError::InvalidConfig {
                reason: "max_request_bytes must be greater than zero",
            });
        }
        if self.max_stdout_bytes == 0 {
            return Err(WorkerError::InvalidConfig {
                reason: "max_stdout_bytes must be greater than zero",
            });
        }
        if self.replacement_window.is_zero() {
            return Err(WorkerError::InvalidConfig {
                reason: "replacement_window must be greater than zero",
            });
        }
        if self.max_replacements_per_window == 0 {
            return Err(WorkerError::InvalidConfig {
                reason: "max_replacements_per_window must be greater than zero",
            });
        }
        if self.circuit_breaker_cooldown.is_zero() {
            return Err(WorkerError::InvalidConfig {
                reason: "circuit_breaker_cooldown must be greater than zero",
            });
        }
        if self
            .command
            .envs
            .iter()
            .any(|(key, _)| self.forbidden_env_names.contains(key))
        {
            return Err(WorkerError::InvalidConfig {
                reason: "worker command env must not include credential or token env names",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapturedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

impl CapturedOutput {
    fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            truncated: false,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

impl fmt::Debug for CapturedOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedOutput")
            .field("bytes_len", &self.bytes.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

#[derive(Error)]
pub enum WorkerError {
    #[error("invalid worker pool config: {reason}")]
    InvalidConfig { reason: &'static str },
    #[error("worker pool saturated: all {max_workers} workers are busy")]
    Saturated { max_workers: usize },
    #[error("worker replacement circuit breaker is open; retry after {retry_after:?}")]
    CircuitOpen { retry_after: Duration },
    #[error("worker request too large: {bytes} bytes exceeds limit {limit}")]
    RequestTooLarge { bytes: usize, limit: usize },
    #[error("failed to encode worker request: {source}")]
    Encode {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to spawn worker: {source}")]
    Spawn {
        #[source]
        source: io::Error,
    },
    #[error("worker {worker_id} timed out after {timeout:?}; stderr bytes captured: {stderr_len}, truncated: {stderr_truncated}")]
    Timeout {
        worker_id: u64,
        timeout: Duration,
        stderr_len: usize,
        stderr_truncated: bool,
        stderr: CapturedOutput,
    },
    #[error("worker {worker_id} stdout exceeded limit {limit}; stderr bytes captured: {stderr_len}, truncated: {stderr_truncated}")]
    StdoutTooLarge {
        worker_id: u64,
        limit: usize,
        stderr_len: usize,
        stderr_truncated: bool,
        stderr: CapturedOutput,
    },
    #[error("worker {worker_id} returned invalid JSON: {source}; stderr bytes captured: {stderr_len}, truncated: {stderr_truncated}")]
    InvalidOutput {
        worker_id: u64,
        #[source]
        source: serde_json::Error,
        stderr_len: usize,
        stderr_truncated: bool,
        stderr: CapturedOutput,
    },
    #[error("worker {worker_id} exited before returning a response with status {status:?}; stderr bytes captured: {stderr_len}, truncated: {stderr_truncated}")]
    WorkerExited {
        worker_id: u64,
        status: Option<ExitStatus>,
        stderr_len: usize,
        stderr_truncated: bool,
        stderr: CapturedOutput,
    },
    #[error("worker {worker_id} IO failure: {source}; stderr bytes captured: {stderr_len}, truncated: {stderr_truncated}")]
    Io {
        worker_id: u64,
        #[source]
        source: io::Error,
        stderr_len: usize,
        stderr_truncated: bool,
        stderr: CapturedOutput,
    },
}

impl fmt::Debug for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { reason } => f
                .debug_struct("InvalidConfig")
                .field("reason", reason)
                .finish(),
            Self::Saturated { max_workers } => f
                .debug_struct("Saturated")
                .field("max_workers", max_workers)
                .finish(),
            Self::CircuitOpen { retry_after } => f
                .debug_struct("CircuitOpen")
                .field("retry_after", retry_after)
                .finish(),
            Self::RequestTooLarge { bytes, limit } => f
                .debug_struct("RequestTooLarge")
                .field("bytes", bytes)
                .field("limit", limit)
                .finish(),
            Self::Encode { source } => f.debug_struct("Encode").field("source", source).finish(),
            Self::Spawn { source } => f.debug_struct("Spawn").field("source", source).finish(),
            Self::Timeout {
                worker_id,
                timeout,
                stderr_len,
                stderr_truncated,
                ..
            } => f
                .debug_struct("Timeout")
                .field("worker_id", worker_id)
                .field("timeout", timeout)
                .field("stderr_len", stderr_len)
                .field("stderr_truncated", stderr_truncated)
                .finish(),
            Self::StdoutTooLarge {
                worker_id,
                limit,
                stderr_len,
                stderr_truncated,
                ..
            } => f
                .debug_struct("StdoutTooLarge")
                .field("worker_id", worker_id)
                .field("limit", limit)
                .field("stderr_len", stderr_len)
                .field("stderr_truncated", stderr_truncated)
                .finish(),
            Self::InvalidOutput {
                worker_id,
                source,
                stderr_len,
                stderr_truncated,
                ..
            } => f
                .debug_struct("InvalidOutput")
                .field("worker_id", worker_id)
                .field("source", source)
                .field("stderr_len", stderr_len)
                .field("stderr_truncated", stderr_truncated)
                .finish(),
            Self::WorkerExited {
                worker_id,
                status,
                stderr_len,
                stderr_truncated,
                ..
            } => f
                .debug_struct("WorkerExited")
                .field("worker_id", worker_id)
                .field("status", status)
                .field("stderr_len", stderr_len)
                .field("stderr_truncated", stderr_truncated)
                .finish(),
            Self::Io {
                worker_id,
                source,
                stderr_len,
                stderr_truncated,
                ..
            } => f
                .debug_struct("Io")
                .field("worker_id", worker_id)
                .field("source", source)
                .field("stderr_len", stderr_len)
                .field("stderr_truncated", stderr_truncated)
                .finish(),
        }
    }
}

impl WorkerError {
    pub fn worker_id(&self) -> Option<u64> {
        match self {
            Self::Timeout { worker_id, .. }
            | Self::StdoutTooLarge { worker_id, .. }
            | Self::InvalidOutput { worker_id, .. }
            | Self::WorkerExited { worker_id, .. }
            | Self::Io { worker_id, .. } => Some(*worker_id),
            _ => None,
        }
    }

    pub fn stderr(&self) -> Option<&CapturedOutput> {
        match self {
            Self::Timeout { stderr, .. }
            | Self::StdoutTooLarge { stderr, .. }
            | Self::InvalidOutput { stderr, .. }
            | Self::WorkerExited { stderr, .. }
            | Self::Io { stderr, .. } => Some(stderr),
            _ => None,
        }
    }

    fn timeout(worker_id: u64, timeout: Duration, stderr: CapturedOutput) -> Self {
        Self::Timeout {
            worker_id,
            timeout,
            stderr_len: stderr.len(),
            stderr_truncated: stderr.is_truncated(),
            stderr,
        }
    }

    fn with_stderr(self, stderr: CapturedOutput) -> Self {
        match self {
            Self::Timeout {
                worker_id, timeout, ..
            } => Self::Timeout {
                worker_id,
                timeout,
                stderr_len: stderr.len(),
                stderr_truncated: stderr.is_truncated(),
                stderr,
            },
            Self::StdoutTooLarge {
                worker_id, limit, ..
            } => Self::StdoutTooLarge {
                worker_id,
                limit,
                stderr_len: stderr.len(),
                stderr_truncated: stderr.is_truncated(),
                stderr,
            },
            Self::InvalidOutput {
                worker_id, source, ..
            } => Self::InvalidOutput {
                worker_id,
                source,
                stderr_len: stderr.len(),
                stderr_truncated: stderr.is_truncated(),
                stderr,
            },
            Self::WorkerExited {
                worker_id, status, ..
            } => Self::WorkerExited {
                worker_id,
                status,
                stderr_len: stderr.len(),
                stderr_truncated: stderr.is_truncated(),
                stderr,
            },
            Self::Io {
                worker_id, source, ..
            } => Self::Io {
                worker_id,
                source,
                stderr_len: stderr.len(),
                stderr_truncated: stderr.is_truncated(),
                stderr,
            },
            error => error,
        }
    }
}

#[derive(Clone)]
pub struct WorkerPool {
    inner: Arc<WorkerPoolInner>,
}

struct WorkerPoolInner {
    config: WorkerPoolConfig,
    idle: Mutex<VecDeque<Worker>>,
    replenish: Mutex<()>,
    next_worker_id: AtomicU64,
    in_flight: AtomicUsize,
    completed_total: AtomicU64,
    replacements_total: AtomicU64,
    started_at: Instant,
    active_since: Mutex<Option<Instant>>,
    last_completed: Mutex<Option<Instant>>,
    replacement_events: Mutex<VecDeque<Instant>>,
    circuit_open_until: Mutex<Option<Instant>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerPoolSnapshot {
    pub max_workers: usize,
    pub idle_workers: usize,
    pub in_flight: usize,
    pub completed_total: u64,
    pub replacements_total: u64,
    pub circuit_open: bool,
    pub active_for: Option<Duration>,
    pub completed_within: Option<Duration>,
    pub pool_age: Duration,
}

#[derive(Debug)]
pub struct WorkerExecution {
    pub value: Value,
    pub worker_id: u64,
}

impl WorkerPool {
    pub async fn new(config: WorkerPoolConfig) -> Result<Self, WorkerError> {
        config.validate()?;

        let inner = Arc::new(WorkerPoolInner {
            config,
            idle: Mutex::new(VecDeque::new()),
            replenish: Mutex::new(()),
            next_worker_id: AtomicU64::new(1),
            in_flight: AtomicUsize::new(0),
            completed_total: AtomicU64::new(0),
            replacements_total: AtomicU64::new(0),
            started_at: Instant::now(),
            active_since: Mutex::new(None),
            last_completed: Mutex::new(None),
            replacement_events: Mutex::new(VecDeque::new()),
            circuit_open_until: Mutex::new(None),
        });

        for _ in 0..inner.config.max_workers {
            let worker = inner.spawn_worker().await?;
            inner.idle.lock().await.push_back(worker);
        }

        Ok(Self { inner })
    }

    pub async fn execute_json(&self, request: impl Serialize) -> Result<Value, WorkerError> {
        self.execute_json_with_metadata(request)
            .await
            .map(|execution| execution.value)
    }

    pub async fn execute_json_with_metadata(
        &self,
        request: impl Serialize,
    ) -> Result<WorkerExecution, WorkerError> {
        if let Some(retry_after) = self.inner.circuit_retry_after().await {
            return Err(WorkerError::CircuitOpen { retry_after });
        }
        let request_line = encode_request(request, self.inner.config.max_request_bytes)?;
        let Some((mut worker, _in_flight)) = self.inner.take_idle_worker_or_replenish().await
        else {
            return Err(WorkerError::Saturated {
                max_workers: self.inner.config.max_workers,
            });
        };
        let worker_id = worker.id;

        let result = worker
            .request(
                &request_line,
                self.inner.config.request_timeout,
                self.inner.config.max_stdout_bytes,
            )
            .await;

        match result {
            Ok(response) => {
                self.inner.mark_completed().await;
                if worker.is_running().unwrap_or(false) {
                    self.inner.idle.lock().await.push_back(worker);
                } else {
                    self.inner.replace_worker().await;
                }
                Ok(WorkerExecution {
                    value: response,
                    worker_id,
                })
            }
            Err(error) => {
                self.inner.mark_completed().await;
                self.inner.replace_worker().await;
                Err(error)
            }
        }
    }

    pub async fn snapshot(&self) -> WorkerPoolSnapshot {
        self.inner.snapshot().await
    }

    pub async fn check_ready(&self) -> bool {
        if self.inner.circuit_retry_after().await.is_some() {
            return false;
        }
        let mut missing_workers = 0_usize;
        let mut running_workers = VecDeque::new();
        {
            let mut idle = self.inner.idle.lock().await;
            while let Some(mut worker) = idle.pop_front() {
                match worker.is_running() {
                    Ok(true) => running_workers.push_back(worker),
                    Ok(false) | Err(_) => {
                        missing_workers = missing_workers.saturating_add(1);
                        tokio::spawn(async move {
                            let _ = worker.finish_failed_worker().await;
                        });
                    }
                }
            }
            *idle = running_workers;
        }

        let mut replaced_missing_worker = false;
        if missing_workers > 0 {
            let _replenish = self.inner.replenish.lock().await;
            for _ in 0..missing_workers {
                self.inner.replace_worker().await;
                replaced_missing_worker = true;
            }
        }

        if replaced_missing_worker {
            return false;
        }
        let snapshot = self.snapshot().await;
        let current_workers = snapshot.idle_workers + snapshot.in_flight;
        if current_workers < snapshot.max_workers {
            let _replenish = self.inner.replenish.lock().await;
            for _ in 0..snapshot.max_workers - current_workers {
                self.inner.replace_worker().await;
            }
            return false;
        }
        current_workers == snapshot.max_workers
    }
}

impl WorkerPoolInner {
    async fn spawn_worker(&self) -> Result<Worker, WorkerError> {
        let worker_id = self.next_worker_id.fetch_add(1, Ordering::Relaxed);
        Worker::spawn(worker_id, &self.config).await
    }

    async fn replace_worker(&self) {
        if self.circuit_retry_after().await.is_some() {
            return;
        }
        if self.record_replacement_and_maybe_open_circuit().await {
            return;
        }
        match self.spawn_worker().await {
            Ok(worker) => {
                self.replacements_total.fetch_add(1, Ordering::Relaxed);
                self.idle.lock().await.push_back(worker);
            }
            Err(error) => {
                error!(error = ?error, "failed to replace worker process");
            }
        }
    }

    async fn take_idle_worker_or_replenish(self: &Arc<Self>) -> Option<(Worker, InFlightGuard)> {
        if let Some(worker) = self.idle.lock().await.pop_front() {
            let in_flight = InFlightGuard::new(self.clone()).await;
            return Some((worker, in_flight));
        }
        let _replenish = self.replenish.lock().await;
        if let Some(worker) = self.idle.lock().await.pop_front() {
            let in_flight = InFlightGuard::new(self.clone()).await;
            return Some((worker, in_flight));
        }
        let current_workers = self.in_flight.load(Ordering::Relaxed);
        if current_workers >= self.config.max_workers {
            return None;
        }
        for _ in 0..self.config.max_workers - current_workers {
            self.replace_worker().await;
        }
        let worker = self.idle.lock().await.pop_front()?;
        let in_flight = InFlightGuard::new(self.clone()).await;
        Some((worker, in_flight))
    }

    async fn circuit_retry_after(&self) -> Option<Duration> {
        let now = Instant::now();
        let mut open_until = self.circuit_open_until.lock().await;
        match *open_until {
            Some(until) if until > now => Some(until.saturating_duration_since(now)),
            Some(_) => {
                *open_until = None;
                None
            }
            None => None,
        }
    }

    async fn record_replacement_and_maybe_open_circuit(&self) -> bool {
        let now = Instant::now();
        let cutoff = now
            .checked_sub(self.config.replacement_window)
            .unwrap_or(now);
        let mut events = self.replacement_events.lock().await;
        while events.front().is_some_and(|instant| *instant <= cutoff) {
            events.pop_front();
        }
        events.push_back(now);
        if events.len() > self.config.max_replacements_per_window {
            *self.circuit_open_until.lock().await =
                Some(now + self.config.circuit_breaker_cooldown);
            events.clear();
            true
        } else {
            false
        }
    }

    async fn mark_completed(&self) {
        self.completed_total.fetch_add(1, Ordering::Relaxed);
        *self.last_completed.lock().await = Some(Instant::now());
    }

    async fn snapshot(&self) -> WorkerPoolSnapshot {
        let now = Instant::now();
        let idle_workers = self.idle.lock().await.len();
        let active_since = *self.active_since.lock().await;
        let last_completed = *self.last_completed.lock().await;
        let circuit_open = self.circuit_retry_after().await.is_some();
        WorkerPoolSnapshot {
            max_workers: self.config.max_workers,
            idle_workers,
            in_flight: self.in_flight.load(Ordering::Relaxed),
            completed_total: self.completed_total.load(Ordering::Relaxed),
            replacements_total: self.replacements_total.load(Ordering::Relaxed),
            circuit_open,
            active_for: active_since.map(|instant| now.saturating_duration_since(instant)),
            completed_within: last_completed.map(|instant| now.saturating_duration_since(instant)),
            pool_age: now.saturating_duration_since(self.started_at),
        }
    }
}

struct InFlightGuard {
    inner: Arc<WorkerPoolInner>,
}

impl InFlightGuard {
    async fn new(inner: Arc<WorkerPoolInner>) -> Self {
        if inner.in_flight.fetch_add(1, Ordering::Relaxed) == 0 {
            *inner.active_since.lock().await = Some(Instant::now());
        }
        Self { inner }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.inner.in_flight.fetch_sub(1, Ordering::Relaxed) == 1 {
            let inner = self.inner.clone();
            tokio::spawn(async move {
                *inner.active_since.lock().await = None;
            });
        }
    }
}

struct Worker {
    id: u64,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr: SharedStderrCapture,
    stderr_task: JoinHandle<io::Result<()>>,
}

impl Worker {
    async fn spawn(id: u64, config: &WorkerPoolConfig) -> Result<Self, WorkerError> {
        let mut command = Command::new(&config.command.program);
        command
            .args(&config.command.args)
            .env_clear()
            .envs(minimal_worker_env())
            .envs(config.command.envs.iter().cloned())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            let max_memory_bytes = config.max_memory_bytes;
            command.process_group(0);
            unsafe {
                command.pre_exec(move || {
                    if let Some(bytes) = max_memory_bytes {
                        apply_memory_limit(bytes)?;
                    }
                    apply_worker_resource_limits()?;
                    Ok(())
                });
            }
        }

        if let Some(current_dir) = &config.command.current_dir {
            command.current_dir(current_dir);
        }

        let mut child = command
            .spawn()
            .map_err(|source| WorkerError::Spawn { source })?;
        let stdin = child.stdin.take().ok_or_else(|| WorkerError::Spawn {
            source: io::Error::other("worker stdin was not piped"),
        })?;
        let stdout = child.stdout.take().ok_or_else(|| WorkerError::Spawn {
            source: io::Error::other("worker stdout was not piped"),
        })?;
        let stderr_pipe = child.stderr.take().ok_or_else(|| WorkerError::Spawn {
            source: io::Error::other("worker stderr was not piped"),
        })?;

        let stderr = SharedStderrCapture::new(config.max_stderr_bytes);
        let stderr_task = tokio::spawn(capture_stderr(stderr.clone(), stderr_pipe));

        Ok(Self {
            id,
            child,
            stdin,
            stdout: BufReader::new(stdout),
            stderr,
            stderr_task,
        })
    }

    async fn request(
        &mut self,
        request_line: &[u8],
        timeout: Duration,
        stdout_limit: usize,
    ) -> Result<Value, WorkerError> {
        self.stderr.reset().await;

        let response = time::timeout(timeout, async {
            let worker_id = self.id;
            let stdin = &mut self.stdin;
            let stdout = &mut self.stdout;
            let write_request = async {
                stdin.write_all(request_line).await?;
                stdin.flush().await
            };
            let read_response = async {
                read_line_capped(stdout, stdout_limit)
                    .await
                    .map_err(|error| match error {
                        ReadLineError::TooLarge => worker_stdout_too_large(
                            worker_id,
                            stdout_limit,
                            CapturedOutput::empty(),
                        ),
                        ReadLineError::Io(source) => {
                            worker_io_error(worker_id, source, CapturedOutput::empty())
                        }
                    })
            };
            let (_, line) = tokio::try_join!(
                async {
                    write_request.await.map_err(|source| {
                        worker_io_error(worker_id, source, CapturedOutput::empty())
                    })
                },
                read_response,
            )?;

            match line {
                Some(line) => serde_json::from_slice(line.trim_ascii_end()).map_err(|source| {
                    worker_invalid_output(worker_id, source, CapturedOutput::empty())
                }),
                None => {
                    let status = self.child.wait().await.ok();
                    Err(worker_exited(worker_id, status, CapturedOutput::empty()))
                }
            }
        })
        .await;

        match response {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error @ WorkerError::WorkerExited { .. })) => {
                let stderr = self.finish_failed_worker().await;
                Err(error.with_stderr(stderr))
            }
            Ok(Err(error @ WorkerError::StdoutTooLarge { .. })) => {
                let stderr = self.kill_failed_worker().await;
                Err(error.with_stderr(stderr))
            }
            Ok(Err(error @ WorkerError::InvalidOutput { .. })) => {
                let stderr = self.kill_failed_worker().await;
                Err(error.with_stderr(stderr))
            }
            Ok(Err(error @ WorkerError::Io { .. })) => {
                let stderr = self.kill_failed_worker().await;
                Err(error.with_stderr(stderr))
            }
            Ok(Err(error)) => Err(error),
            Err(_) => {
                let stderr = self.kill_failed_worker().await;
                Err(WorkerError::timeout(self.id, timeout, stderr))
            }
        }
    }

    fn is_running(&mut self) -> io::Result<bool> {
        self.child.try_wait().map(|status| status.is_none())
    }

    async fn kill_failed_worker(&mut self) -> CapturedOutput {
        kill_worker_process(&mut self.child).await;
        self.finish_failed_worker().await
    }

    async fn finish_failed_worker(&mut self) -> CapturedOutput {
        let _ = self.child.wait().await;
        let _ = (&mut self.stderr_task).await;
        self.stderr.snapshot().await
    }
}

fn worker_stdout_too_large(worker_id: u64, limit: usize, stderr: CapturedOutput) -> WorkerError {
    WorkerError::StdoutTooLarge {
        worker_id,
        limit,
        stderr_len: stderr.len(),
        stderr_truncated: stderr.is_truncated(),
        stderr,
    }
}

fn worker_invalid_output(
    worker_id: u64,
    source: serde_json::Error,
    stderr: CapturedOutput,
) -> WorkerError {
    WorkerError::InvalidOutput {
        worker_id,
        source,
        stderr_len: stderr.len(),
        stderr_truncated: stderr.is_truncated(),
        stderr,
    }
}

fn worker_exited(
    worker_id: u64,
    status: Option<ExitStatus>,
    stderr: CapturedOutput,
) -> WorkerError {
    WorkerError::WorkerExited {
        worker_id,
        status,
        stderr_len: stderr.len(),
        stderr_truncated: stderr.is_truncated(),
        stderr,
    }
}

fn worker_io_error(worker_id: u64, source: io::Error, stderr: CapturedOutput) -> WorkerError {
    WorkerError::Io {
        worker_id,
        source,
        stderr_len: stderr.len(),
        stderr_truncated: stderr.is_truncated(),
        stderr,
    }
}

#[cfg(unix)]
#[cfg(target_os = "linux")]
fn apply_memory_limit(bytes: u64) -> io::Result<()> {
    apply_resource_limit(libc::RLIMIT_DATA, bytes).or_else(|error| {
        if error.raw_os_error() == Some(libc::EINVAL) {
            apply_resource_limit(libc::RLIMIT_AS, bytes)
        } else {
            Err(error)
        }
    })
}

#[cfg(unix)]
#[cfg(not(target_os = "linux"))]
fn apply_memory_limit(bytes: u64) -> io::Result<()> {
    apply_resource_limit(libc::RLIMIT_AS, bytes).or_else(|error| {
        if error.raw_os_error() == Some(libc::EINVAL) {
            apply_resource_limit(libc::RLIMIT_DATA, bytes).or_else(|data_error| {
                if data_error.raw_os_error() == Some(libc::EINVAL) {
                    Ok(())
                } else {
                    Err(data_error)
                }
            })
        } else {
            Err(error)
        }
    })
}

#[cfg(unix)]
fn apply_worker_resource_limits() -> io::Result<()> {
    apply_resource_limit(libc::RLIMIT_CPU, 60 * 60)?;
    apply_resource_limit(libc::RLIMIT_FSIZE, 1024 * 1024)?;
    apply_resource_limit(libc::RLIMIT_NOFILE, 64)?;
    apply_resource_limit(libc::RLIMIT_CORE, 0)?;
    #[cfg(target_os = "linux")]
    {
        apply_resource_limit(libc::RLIMIT_NPROC, 1024)?;
    }
    Ok(())
}

#[cfg(unix)]
#[cfg(target_os = "linux")]
type RlimitResource = libc::__rlimit_resource_t;

#[cfg(unix)]
#[cfg(not(target_os = "linux"))]
type RlimitResource = libc::c_int;

#[cfg(unix)]
fn apply_resource_limit(resource: RlimitResource, bytes: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: bytes as libc::rlim_t,
        rlim_max: bytes as libc::rlim_t,
    };
    let result = unsafe { libc::setrlimit(resource, &limit) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn minimal_worker_env() -> Vec<(OsString, OsString)> {
    const ALLOWED: &[&str] = &["PATH", "HOME", "TMPDIR", "TEMP", "TMP"];
    ALLOWED
        .iter()
        .filter_map(|key| std::env::var_os(key).map(|value| (OsString::from(key), value)))
        .collect()
}

async fn kill_worker_process(child: &mut Child) {
    #[cfg(unix)]
    {
        if let Some(pid) = child.id() {
            unsafe {
                let _ = kill(-(pid as i32), SIGKILL);
            }
        }
        let _ = child.kill().await;
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill().await;
    }
}

#[cfg(unix)]
const SIGKILL: i32 = 9;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[derive(Clone)]
struct SharedStderrCapture {
    limit: usize,
    inner: Arc<Mutex<CapturedOutput>>,
}

impl SharedStderrCapture {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            inner: Arc::new(Mutex::new(CapturedOutput::empty())),
        }
    }

    async fn reset(&self) {
        *self.inner.lock().await = CapturedOutput::empty();
    }

    async fn append(&self, chunk: &[u8]) {
        let mut output = self.inner.lock().await;
        let remaining = self.limit.saturating_sub(output.bytes.len());
        let retained = remaining.min(chunk.len());
        output.bytes.extend_from_slice(&chunk[..retained]);
        if retained < chunk.len() {
            output.truncated = true;
        }
    }

    async fn snapshot(&self) -> CapturedOutput {
        self.inner.lock().await.clone()
    }
}

async fn capture_stderr(capture: SharedStderrCapture, mut stderr: ChildStderr) -> io::Result<()> {
    let mut buffer = [0_u8; 8192];
    loop {
        let bytes_read = stderr.read(&mut buffer).await?;
        if bytes_read == 0 {
            return Ok(());
        }
        capture.append(&buffer[..bytes_read]).await;
    }
}

fn encode_request(
    request: impl Serialize,
    max_request_bytes: usize,
) -> Result<Vec<u8>, WorkerError> {
    let mut line = serde_json::to_vec(&request).map_err(|source| WorkerError::Encode { source })?;
    let bytes = line.len();
    if bytes > max_request_bytes {
        return Err(WorkerError::RequestTooLarge {
            bytes,
            limit: max_request_bytes,
        });
    }
    line.push(b'\n');
    Ok(line)
}

#[derive(Debug)]
enum ReadLineError {
    TooLarge,
    Io(io::Error),
}

async fn read_line_capped(
    stdout: &mut (impl AsyncBufRead + Unpin),
    limit: usize,
) -> Result<Option<Vec<u8>>, ReadLineError> {
    let mut line = Vec::new();

    loop {
        let buffer = stdout.fill_buf().await.map_err(ReadLineError::Io)?;
        if buffer.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }

        let (consumed, payload_bytes) =
            if let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
                (newline + 1, newline)
            } else {
                (buffer.len(), buffer.len())
            };

        if line.len() + payload_bytes > limit {
            return Err(ReadLineError::TooLarge);
        }

        line.extend_from_slice(&buffer[..consumed]);
        stdout.consume(consumed);

        if line.last() == Some(&b'\n') {
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn read_line_capped_allows_newline_after_exact_payload_limit() {
        let mut reader = BufReader::new(&b"abcd\n"[..]);
        let line = read_line_capped(&mut reader, 4)
            .await
            .expect("line read succeeds")
            .expect("line exists");
        assert_eq!(line, b"abcd\n");
    }

    #[tokio::test]
    async fn read_line_capped_rejects_payload_over_limit() {
        let mut reader = BufReader::new(&b"abcde\n"[..]);
        assert!(matches!(
            read_line_capped(&mut reader, 4).await,
            Err(ReadLineError::TooLarge)
        ));
    }
}

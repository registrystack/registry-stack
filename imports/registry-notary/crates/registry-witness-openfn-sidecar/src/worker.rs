use serde::Serialize;
use serde_json::Value;
use std::{
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
    io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
    sync::Mutex,
    task::JoinHandle,
    time,
};

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
    pub max_workers: usize,
    pub request_timeout: Duration,
    pub max_request_bytes: usize,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub max_memory_bytes: Option<u64>,
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

pub struct WorkerPool {
    inner: Arc<WorkerPoolInner>,
}

struct WorkerPoolInner {
    config: WorkerPoolConfig,
    idle: Mutex<VecDeque<Worker>>,
    next_worker_id: AtomicU64,
    in_flight: AtomicUsize,
    completed_total: AtomicU64,
    started_at: Instant,
    active_since: Mutex<Option<Instant>>,
    last_completed: Mutex<Option<Instant>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerPoolSnapshot {
    pub max_workers: usize,
    pub idle_workers: usize,
    pub in_flight: usize,
    pub completed_total: u64,
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
            next_worker_id: AtomicU64::new(1),
            in_flight: AtomicUsize::new(0),
            completed_total: AtomicU64::new(0),
            started_at: Instant::now(),
            active_since: Mutex::new(None),
            last_completed: Mutex::new(None),
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
        let request_line = encode_request(request, self.inner.config.max_request_bytes)?;
        let Some(mut worker) = self.inner.idle.lock().await.pop_front() else {
            return Err(WorkerError::Saturated {
                max_workers: self.inner.config.max_workers,
            });
        };
        let _in_flight = InFlightGuard::new(self.inner.clone()).await;
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
}

impl WorkerPoolInner {
    async fn spawn_worker(&self) -> Result<Worker, WorkerError> {
        let worker_id = self.next_worker_id.fetch_add(1, Ordering::Relaxed);
        Worker::spawn(worker_id, &self.config).await
    }

    async fn replace_worker(&self) {
        if let Ok(worker) = self.spawn_worker().await {
            self.idle.lock().await.push_back(worker);
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
        WorkerPoolSnapshot {
            max_workers: self.config.max_workers,
            idle_workers,
            in_flight: self.in_flight.load(Ordering::Relaxed),
            completed_total: self.completed_total.load(Ordering::Relaxed),
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
            self.stdin
                .write_all(request_line)
                .await
                .map_err(|source| self.io_error(source, CapturedOutput::empty()))?;
            self.stdin
                .flush()
                .await
                .map_err(|source| self.io_error(source, CapturedOutput::empty()))?;

            match read_line_capped(&mut self.stdout, stdout_limit).await {
                Ok(Some(line)) => serde_json::from_slice(line.trim_ascii_end())
                    .map_err(|source| self.invalid_output(source, CapturedOutput::empty())),
                Ok(None) => {
                    let status = self.child.wait().await.ok();
                    Err(self.worker_exited(status, CapturedOutput::empty()))
                }
                Err(ReadLineError::TooLarge) => {
                    Err(self.stdout_too_large(stdout_limit, CapturedOutput::empty()))
                }
                Err(ReadLineError::Io(source)) => {
                    Err(self.io_error(source, CapturedOutput::empty()))
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

    fn stdout_too_large(&self, limit: usize, stderr: CapturedOutput) -> WorkerError {
        WorkerError::StdoutTooLarge {
            worker_id: self.id,
            limit,
            stderr_len: stderr.len(),
            stderr_truncated: stderr.is_truncated(),
            stderr,
        }
    }

    fn invalid_output(&self, source: serde_json::Error, stderr: CapturedOutput) -> WorkerError {
        WorkerError::InvalidOutput {
            worker_id: self.id,
            source,
            stderr_len: stderr.len(),
            stderr_truncated: stderr.is_truncated(),
            stderr,
        }
    }

    fn worker_exited(&self, status: Option<ExitStatus>, stderr: CapturedOutput) -> WorkerError {
        WorkerError::WorkerExited {
            worker_id: self.id,
            status,
            stderr_len: stderr.len(),
            stderr_truncated: stderr.is_truncated(),
            stderr,
        }
    }

    fn io_error(&self, source: io::Error, stderr: CapturedOutput) -> WorkerError {
        WorkerError::Io {
            worker_id: self.id,
            source,
            stderr_len: stderr.len(),
            stderr_truncated: stderr.is_truncated(),
            stderr,
        }
    }
}

#[cfg(unix)]
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

enum ReadLineError {
    TooLarge,
    Io(io::Error),
}

async fn read_line_capped(
    stdout: &mut BufReader<ChildStdout>,
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

        let consumed = if let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
            newline + 1
        } else {
            buffer.len()
        };

        if line.len() + consumed > limit {
            return Err(ReadLineError::TooLarge);
        }

        line.extend_from_slice(&buffer[..consumed]);
        stdout.consume(consumed);

        if line.last() == Some(&b'\n') {
            return Ok(Some(line));
        }
    }
}

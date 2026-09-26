// SPDX-License-Identifier: Apache-2.0
//! The audit writer every Registry Stack product uses.
//!
//! One JSON object per line, two entries per audited request: a `request`
//! entry before protected I/O and a `response` entry carrying the outcome, both
//! with the same `correlation`. Entries are not chained. Tamper evidence is a
//! deployment concern: ship the stream to append-only storage.
//!
//! The `file` destination is durable: [`AuditWriter::append`] returns only
//! after the entry's bytes are `fsync`ed, and appends arriving during one
//! durable write share the next write and `fsync` (group commit). The `stdout`
//! destination writes one line and flushes; it is best-effort by nature.

use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, ErrorKind, Write},
    os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use time::{format_description::FormatItem, macros::format_description, OffsetDateTime};
use uuid::Uuid;

use crate::AuditError;

/// Default size at which the active file is sealed and a fresh one opened.
pub const DEFAULT_AUDIT_ROTATE_BYTES: u64 = 100 * 1024 * 1024;
/// Default age after which sealed files are deleted at rotation.
pub const DEFAULT_AUDIT_RETAIN_DAYS: u32 = 90;
/// Smallest accepted rotation size. It is also the largest accepted entry.
pub const MIN_AUDIT_ROTATE_BYTES: u64 = 1024 * 1024;
/// Largest accepted retention, in days.
pub const MAX_AUDIT_RETAIN_DAYS: u32 = 36_500;

const MAX_ENTRY_BYTES: usize = 1024 * 1024;
const MAX_SCHEMA_BYTES: usize = 128;
const MAX_CORRELATION_BYTES: usize = 256;
const SEGMENT_SEQUENCE_DIGITS: usize = 8;
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
const TIME_FORMAT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

/// Which half of an audited request an entry records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditPhase {
    /// Written before protected I/O. If it is not accepted, the request is
    /// refused and no protected I/O happens.
    Request,
    /// Written with the outcome. A disclosure is returned only after its
    /// response entry is accepted.
    Response,
}

/// One audit entry before the writer assigns its `eventId` and `time`.
#[derive(Clone, Debug, PartialEq)]
pub struct AuditEntry {
    schema: String,
    phase: AuditPhase,
    correlation: String,
    record: Value,
}

impl AuditEntry {
    /// A `request` entry. `record` must be a JSON object holding only the
    /// product's minimized, closed-vocabulary fields.
    #[must_use]
    pub fn request(
        schema: impl Into<String>,
        correlation: impl Into<String>,
        record: Value,
    ) -> Self {
        Self::new(schema, AuditPhase::Request, correlation, record)
    }

    /// A `response` entry sharing its request entry's `correlation`.
    #[must_use]
    pub fn response(
        schema: impl Into<String>,
        correlation: impl Into<String>,
        record: Value,
    ) -> Self {
        Self::new(schema, AuditPhase::Response, correlation, record)
    }

    #[must_use]
    pub fn new(
        schema: impl Into<String>,
        phase: AuditPhase,
        correlation: impl Into<String>,
        record: Value,
    ) -> Self {
        Self {
            schema: schema.into(),
            phase,
            correlation: correlation.into(),
            record,
        }
    }

    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    #[must_use]
    pub fn phase(&self) -> AuditPhase {
        self.phase
    }

    #[must_use]
    pub fn correlation(&self) -> &str {
        &self.correlation
    }

    #[must_use]
    pub fn record(&self) -> &Value {
        &self.record
    }

    fn to_line(&self) -> Result<String, AuditUnavailable> {
        let schema_valid = !self.schema.is_empty()
            && self.schema.len() <= MAX_SCHEMA_BYTES
            && self
                .schema
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\');
        let correlation_valid = !self.correlation.is_empty()
            && self.correlation.len() <= MAX_CORRELATION_BYTES
            && !self.correlation.chars().any(char::is_control);
        let Value::Object(record) = &self.record else {
            return Err(AuditUnavailable::new(AuditUnavailableReason::InvalidEntry));
        };
        if !schema_valid || !correlation_valid {
            return Err(AuditUnavailable::new(AuditUnavailableReason::InvalidEntry));
        }
        let now = OffsetDateTime::now_utc();
        let time = now
            .format(TIME_FORMAT)
            .map_err(|_| AuditUnavailable::new(AuditUnavailableReason::InvalidEntry))?;
        let line = WireEntry {
            schema: &self.schema,
            event_id: Uuid::new_v4().to_string(),
            time,
            phase: self.phase,
            correlation: &self.correlation,
            record,
        };
        let mut text = serde_json::to_string(&line)
            .map_err(|_| AuditUnavailable::new(AuditUnavailableReason::InvalidEntry))?;
        text.push('\n');
        if text.len() > MAX_ENTRY_BYTES {
            return Err(AuditUnavailable::new(AuditUnavailableReason::EntryTooLarge));
        }
        Ok(text)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireEntry<'a> {
    schema: &'a str,
    event_id: String,
    time: String,
    phase: AuditPhase,
    correlation: &'a str,
    record: &'a Map<String, Value>,
}

/// Why an append was not accepted. The message carries no entry content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditUnavailableReason {
    /// The entry is malformed: empty or oversized schema or correlation, or a
    /// record that is not a JSON object.
    InvalidEntry,
    /// The serialized entry is larger than the writer accepts.
    EntryTooLarge,
    /// The destination failed to accept the write.
    WriteFailed,
    /// An earlier write failed, so the writer refuses every later append until
    /// the process restarts.
    Stopped,
}

/// The writer did not accept an entry. Products map this to their existing
/// audit-unavailable refusal and perform no protected I/O or disclosure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("audit destination is unavailable")]
pub struct AuditUnavailable {
    reason: AuditUnavailableReason,
}

impl AuditUnavailable {
    fn new(reason: AuditUnavailableReason) -> Self {
        Self { reason }
    }

    #[must_use]
    pub fn reason(&self) -> AuditUnavailableReason {
        self.reason
    }
}

/// The configured audit destination kind, as written in product configuration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum AuditDestinationKind {
    /// Durable, rotated JSON Lines file.
    #[default]
    File,
    /// One JSON line per entry on standard output, flushed per entry.
    Stdout,
}

/// A configuration error in the shared audit destination shape.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuditDestinationError {
    #[error("audit.path is required when audit.destination is file")]
    MissingPath,
    #[error("audit.path must be absolute")]
    RelativePath,
    #[error("audit.{field} applies only when audit.destination is file")]
    FileOnlyField { field: &'static str },
    #[error("audit.rotateBytes must be between {minimum} and {maximum}")]
    RotateBytesOutOfRange { minimum: u64, maximum: u64 },
    #[error("audit.retainDays must be between 1 and {maximum}")]
    RetainDaysOutOfRange { maximum: u32 },
    #[error("an audit process role is 1 to 32 lowercase ASCII letters, digits, or hyphens")]
    InvalidProcessRole,
}

/// Where the writer sends entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditDestination {
    File(FileDestination),
    Stdout,
    /// Standard error, for a companion command whose own report owns stdout.
    /// Configuration never selects it; [`AuditDestination::for_process`]
    /// derives it from `stdout`.
    Stderr,
}

/// A durable, size-rotated JSON Lines file with age-based retention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileDestination {
    path: PathBuf,
    rotate_bytes: u64,
    retain_days: u32,
}

impl FileDestination {
    /// A file destination with the default rotation and retention.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, AuditDestinationError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(AuditDestinationError::RelativePath);
        }
        Ok(Self {
            path,
            rotate_bytes: DEFAULT_AUDIT_ROTATE_BYTES,
            retain_days: DEFAULT_AUDIT_RETAIN_DAYS,
        })
    }

    pub fn with_rotate_bytes(mut self, rotate_bytes: u64) -> Result<Self, AuditDestinationError> {
        if !(MIN_AUDIT_ROTATE_BYTES..=u64::from(u32::MAX)).contains(&rotate_bytes) {
            return Err(AuditDestinationError::RotateBytesOutOfRange {
                minimum: MIN_AUDIT_ROTATE_BYTES,
                maximum: u64::from(u32::MAX),
            });
        }
        self.rotate_bytes = rotate_bytes;
        Ok(self)
    }

    pub fn with_retain_days(mut self, retain_days: u32) -> Result<Self, AuditDestinationError> {
        if !(1..=MAX_AUDIT_RETAIN_DAYS).contains(&retain_days) {
            return Err(AuditDestinationError::RetainDaysOutOfRange {
                maximum: MAX_AUDIT_RETAIN_DAYS,
            });
        }
        self.retain_days = retain_days;
        Ok(self)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn rotate_bytes(&self) -> u64 {
        self.rotate_bytes
    }

    #[must_use]
    pub fn retain_days(&self) -> u32 {
        self.retain_days
    }

    /// Check, without taking the writer lock or writing an entry, that a
    /// writer could open this destination: the directory exists or can be
    /// created, is owned by this user and not group- or world-writable, and
    /// any existing lock companion and active file are owner-only regular
    /// files the writer can open, and the active file's final entry is
    /// complete.
    pub fn check_writable(&self) -> Result<(), AuditError> {
        let parent = parent(&self.path)?;
        match fs::symlink_metadata(parent) {
            Ok(_) => validate_directory(parent)?,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let mut ancestor = parent;
                while !ancestor.exists() {
                    ancestor = ancestor.parent().ok_or_else(|| {
                        AuditError::Io(io::Error::new(
                            ErrorKind::NotFound,
                            "audit directory has no existing ancestor",
                        ))
                    })?;
                }
                if rustix::fs::access(ancestor, rustix::fs::Access::WRITE_OK).is_err() {
                    return Err(AuditError::Io(io::Error::new(
                        ErrorKind::PermissionDenied,
                        "audit directory cannot be created",
                    )));
                }
                return Ok(());
            }
            Err(error) => return Err(AuditError::Io(error)),
        }
        if rustix::fs::access(parent, rustix::fs::Access::WRITE_OK).is_err() {
            return Err(AuditError::Io(io::Error::new(
                ErrorKind::PermissionDenied,
                "audit directory is not writable",
            )));
        }
        // The writer opens the lock companion for write, on the same terms
        // as the active file, before it opens the active file.
        let lock = lock_path(&self.path);
        match fs::symlink_metadata(&lock) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Err(symlink_error()),
            Ok(metadata) => {
                validate_active_metadata(&metadata)?;
                rustix::fs::access(&lock, rustix::fs::Access::WRITE_OK).map_err(|_| {
                    AuditError::Io(io::Error::new(
                        ErrorKind::PermissionDenied,
                        "audit lock file is not writable",
                    ))
                })?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(AuditError::Io(error)),
        }
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(symlink_error()),
            Ok(metadata) => {
                validate_active_metadata(&metadata)?;
                // The writer opens the active file for read and append.
                rustix::fs::access(
                    &self.path,
                    rustix::fs::Access::READ_OK | rustix::fs::Access::WRITE_OK,
                )
                .map_err(|_| {
                    AuditError::Io(io::Error::new(
                        ErrorKind::PermissionDenied,
                        "audit file is not readable and writable",
                    ))
                })?;
                let active = OpenOptions::new()
                    .read(true)
                    .custom_flags(open_flags())
                    .open(&self.path)
                    .map_err(AuditError::Io)?;
                require_complete_final_entry(&active)
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AuditError::Io(error)),
        }
    }
}

impl AuditDestination {
    /// Build a destination from the shared configuration shape, applying
    /// defaults and refusing file-only settings on `stdout`.
    pub fn from_settings(
        kind: AuditDestinationKind,
        path: Option<PathBuf>,
        rotate_bytes: Option<u64>,
        retain_days: Option<u32>,
    ) -> Result<Self, AuditDestinationError> {
        match kind {
            AuditDestinationKind::File => {
                let mut file =
                    FileDestination::new(path.ok_or(AuditDestinationError::MissingPath)?)?;
                if let Some(rotate_bytes) = rotate_bytes {
                    file = file.with_rotate_bytes(rotate_bytes)?;
                }
                if let Some(retain_days) = retain_days {
                    file = file.with_retain_days(retain_days)?;
                }
                Ok(Self::File(file))
            }
            AuditDestinationKind::Stdout => {
                for (present, field) in [
                    (path.is_some(), "path"),
                    (rotate_bytes.is_some(), "rotateBytes"),
                    (retain_days.is_some(), "retainDays"),
                ] {
                    if present {
                        return Err(AuditDestinationError::FileOnlyField { field });
                    }
                }
                Ok(Self::Stdout)
            }
        }
    }

    #[must_use]
    pub fn kind(&self) -> AuditDestinationKind {
        match self {
            Self::File(_) => AuditDestinationKind::File,
            // `stderr` reports the configured kind it derives from.
            Self::Stdout | Self::Stderr => AuditDestinationKind::Stdout,
        }
    }

    /// Check that a writer could open this destination. A stream always
    /// passes.
    pub fn check_writable(&self) -> Result<(), AuditError> {
        match self {
            Self::File(file) => file.check_writable(),
            Self::Stdout | Self::Stderr => Ok(()),
        }
    }

    /// The destination a companion process (operator tooling or a one-shot
    /// subcommand) writes to while the service may hold this one. A file
    /// destination becomes a sibling file with `role` before the extension
    /// (`audit.jsonl` becomes `audit.<role>.jsonl`) and the same rotation and
    /// retention, so it takes its own single-writer lock. A `stdout`
    /// destination becomes `stderr`, so a companion command's own report
    /// keeps stdout.
    pub fn for_process(&self, role: &str) -> Result<Self, AuditDestinationError> {
        let valid = (1..=32).contains(&role.len())
            && !role.starts_with('-')
            && role
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !valid {
            return Err(AuditDestinationError::InvalidProcessRole);
        }
        match self {
            Self::File(file) => {
                let stem = file
                    .path
                    .file_stem()
                    .ok_or(AuditDestinationError::MissingPath)?;
                let mut name = stem.to_os_string();
                name.push(".");
                name.push(role);
                if let Some(extension) = file.path.extension() {
                    name.push(".");
                    name.push(extension);
                }
                Ok(Self::File(FileDestination {
                    path: file.path.with_file_name(name),
                    rotate_bytes: file.rotate_bytes,
                    retain_days: file.retain_days,
                }))
            }
            Self::Stdout | Self::Stderr => Ok(Self::Stderr),
        }
    }
}

/// The audit writer. Cheap to clone; clones share one destination.
#[derive(Clone)]
pub struct AuditWriter {
    inner: Arc<WriterInner>,
}

enum WriterInner {
    File(Arc<GroupCommitFile>),
    Stream(LineStream),
}

impl std::fmt::Debug for AuditWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("AuditWriter");
        match self.inner.as_ref() {
            WriterInner::File(file) => debug
                .field("destination", &"file")
                .field("path", &file.file.path),
            WriterInner::Stream(_) => debug.field("destination", &"stdout"),
        };
        debug.finish_non_exhaustive()
    }
}

impl AuditWriter {
    /// Open the destination. The file destination takes a process-lifetime
    /// single-writer lock beside the active file and applies retention.
    pub async fn open(destination: AuditDestination) -> Result<Self, AuditError> {
        let inner = match destination {
            AuditDestination::File(file) => {
                let opened = tokio::task::spawn_blocking(move || SegmentedFile::open(file))
                    .await
                    .map_err(|error| AuditError::Io(io::Error::other(error)))??;
                WriterInner::File(Arc::new(GroupCommitFile::new(opened)))
            }
            AuditDestination::Stdout => {
                WriterInner::Stream(LineStream::new(Box::new(io::stdout())))
            }
            AuditDestination::Stderr => {
                WriterInner::Stream(LineStream::new(Box::new(io::stderr())))
            }
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// A writer over an arbitrary line sink, with `stdout` semantics. For
    /// tests that need to observe emitted lines without a file.
    #[must_use]
    pub fn from_line_sink(sink: Box<dyn Write + Send>) -> Self {
        Self {
            inner: Arc::new(WriterInner::Stream(LineStream::new(sink))),
        }
    }

    /// Append one entry. For the file destination this returns only after the
    /// entry's bytes are durable. Canceling the caller does not cancel an
    /// enqueued file write or the other entries in its group commit.
    pub async fn append(&self, entry: AuditEntry) -> Result<(), AuditUnavailable> {
        let line = entry.to_line()?;
        match self.inner.as_ref() {
            WriterInner::File(file) => {
                let file = Arc::clone(file);
                tokio::spawn(async move { file.append(line).await })
                    .await
                    .map_err(|_| AuditUnavailable::new(AuditUnavailableReason::Stopped))?
            }
            WriterInner::Stream(stream) => stream.append(&line),
        }
    }

    /// Report whether the writer can still accept entries. For the file
    /// destination this also confirms the writer still owns the active file.
    pub async fn ready(&self) -> bool {
        match self.inner.as_ref() {
            WriterInner::File(file) => file.ready().await,
            WriterInner::Stream(stream) => stream.healthy(),
        }
    }

    #[must_use]
    pub fn kind(&self) -> AuditDestinationKind {
        match self.inner.as_ref() {
            WriterInner::File(_) => AuditDestinationKind::File,
            WriterInner::Stream(_) => AuditDestinationKind::Stdout,
        }
    }

    /// The active file path, for the file destination.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self.inner.as_ref() {
            WriterInner::File(file) => Some(&file.file.path),
            WriterInner::Stream(_) => None,
        }
    }

    /// Number of durable writes (each one `fsync`) this process performed.
    /// Always zero for `stdout`.
    #[must_use]
    pub fn durable_writes(&self) -> u64 {
        match self.inner.as_ref() {
            WriterInner::File(file) => file.durable_writes.load(Ordering::Relaxed),
            WriterInner::Stream(_) => 0,
        }
    }
}

struct LineStream {
    out: StdMutex<Box<dyn Write + Send>>,
    healthy: AtomicBool,
    #[cfg(test)]
    before_lock_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl LineStream {
    fn new(out: Box<dyn Write + Send>) -> Self {
        Self {
            out: StdMutex::new(out),
            healthy: AtomicBool::new(true),
            #[cfg(test)]
            before_lock_hook: None,
        }
    }

    fn healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    fn append(&self, line: &str) -> Result<(), AuditUnavailable> {
        if !self.healthy() {
            return Err(AuditUnavailable::new(AuditUnavailableReason::Stopped));
        }
        #[cfg(test)]
        if let Some(hook) = &self.before_lock_hook {
            hook();
        }
        let mut out = self
            .out
            .lock()
            .map_err(|_| AuditUnavailable::new(AuditUnavailableReason::Stopped))?;
        // A prior holder can stop the stream while this append waits.
        if !self.healthy() {
            return Err(AuditUnavailable::new(AuditUnavailableReason::Stopped));
        }
        match out.write_all(line.as_bytes()).and_then(|()| out.flush()) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.healthy.store(false, Ordering::Release);
                tracing::error!(%error, "audit stream write failed; refusing later audited requests");
                Err(AuditUnavailable::new(AuditUnavailableReason::WriteFailed))
            }
        }
    }
}

/// Group commit over one [`SegmentedFile`]: appends that arrive while a
/// durable write is in flight share the next write and `fsync`.
struct GroupCommitFile {
    file: SegmentedFile,
    state: tokio::sync::Mutex<PendingState>,
    flush: tokio::sync::Mutex<()>,
    durable: AtomicU64,
    durable_writes: AtomicU64,
}

struct PendingState {
    pending: Vec<String>,
    enqueued: u64,
    stopped: bool,
}

impl GroupCommitFile {
    fn new(file: SegmentedFile) -> Self {
        Self {
            file,
            state: tokio::sync::Mutex::new(PendingState {
                pending: Vec::new(),
                enqueued: 0,
                stopped: false,
            }),
            flush: tokio::sync::Mutex::new(()),
            durable: AtomicU64::new(0),
            durable_writes: AtomicU64::new(0),
        }
    }

    async fn append(&self, line: String) -> Result<(), AuditUnavailable> {
        let position = {
            let mut state = self.state.lock().await;
            if state.stopped {
                return Err(AuditUnavailable::new(AuditUnavailableReason::Stopped));
            }
            state.pending.push(line);
            state.enqueued = state.enqueued.saturating_add(1);
            state.enqueued
        };
        loop {
            if self.durable.load(Ordering::Acquire) >= position {
                return Ok(());
            }
            let _writer = self.flush.lock().await;
            if self.durable.load(Ordering::Acquire) >= position {
                return Ok(());
            }
            self.flush_once().await?;
        }
    }

    async fn flush_once(&self) -> Result<(), AuditUnavailable> {
        let (lines, through) = {
            let mut state = self.state.lock().await;
            if state.stopped {
                return Err(AuditUnavailable::new(AuditUnavailableReason::Stopped));
            }
            if state.pending.is_empty() {
                return Ok(());
            }
            (std::mem::take(&mut state.pending), state.enqueued)
        };
        self.durable_writes.fetch_add(1, Ordering::Relaxed);
        match self.file.write_lines(lines).await {
            Ok(()) => {
                self.durable.store(through, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                self.state.lock().await.stopped = true;
                tracing::error!(%error, "audit file write failed; refusing later audited requests");
                Err(AuditUnavailable::new(AuditUnavailableReason::WriteFailed))
            }
        }
    }

    async fn ready(&self) -> bool {
        if self.state.lock().await.stopped {
            return false;
        }
        self.file.ready().await
    }
}

/// A single-writer JSON Lines file with online size rotation and age-based
/// retention of sealed files.
///
/// The active file stays at `path`. Rotation renames it to
/// `<path>.<sequence>` with an ascending eight-digit sequence and opens a
/// fresh active file. The writer pins the active file's identity and length
/// and stops if anything else changes it.
struct SegmentedFile {
    path: PathBuf,
    lock_path: PathBuf,
    rotate_bytes: u64,
    retain: Duration,
    state: tokio::sync::Mutex<FileState>,
    healthy: AtomicBool,
    lock_fingerprint: FileFingerprint,
    writer_lock: File,
    #[cfg(test)]
    sync_hook: Option<SyncHook>,
}

#[cfg(test)]
type SyncHook = Arc<dyn Fn() -> io::Result<()> + Send + Sync>;

struct FileState {
    active: File,
    fingerprint: FileFingerprint,
    next_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileFingerprint {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl SegmentedFile {
    fn open(destination: FileDestination) -> Result<Self, AuditError> {
        let FileDestination {
            path,
            rotate_bytes,
            retain_days,
        } = destination;
        let parent = parent(&path)?.to_path_buf();
        create_directory(&parent)?;
        validate_directory(&parent)?;

        let lock_path = lock_path(&path);
        let lock_created = !lock_path.exists();
        let writer_lock = open_lock(&lock_path)?;
        validate_active_file(&writer_lock)?;
        match writer_lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(AuditError::SinkLocked {
                    path: lock_path.display().to_string(),
                });
            }
            Err(TryLockError::Error(error)) => return Err(AuditError::Io(error)),
        }

        let created = !path.exists();
        let active = open_append(&path)?;
        validate_active_file(&active)?;
        require_complete_final_entry(&active)?;
        active.sync_all().map_err(AuditError::Io)?;
        if created || lock_created {
            sync_directory(&parent)?;
        }
        let retain = Duration::from_secs(u64::from(retain_days) * SECONDS_PER_DAY);
        apply_retention(&path, retain)?;

        let fingerprint = file_fingerprint(&active)?;
        let lock_fingerprint = file_fingerprint(&writer_lock)?;
        let next_sequence = sealed_segments(&path)?
            .pop()
            .map_or(1, |(sequence, _)| sequence.saturating_add(1));
        Ok(Self {
            path,
            lock_path,
            rotate_bytes,
            retain,
            state: tokio::sync::Mutex::new(FileState {
                active,
                fingerprint,
                next_sequence,
            }),
            healthy: AtomicBool::new(true),
            lock_fingerprint,
            writer_lock,
            #[cfg(test)]
            sync_hook: None,
        })
    }

    async fn ready(&self) -> bool {
        if !self.healthy.load(Ordering::Acquire) {
            return false;
        }
        let state = self.state.lock().await;
        let (Ok(active), Ok(writer_lock)) =
            (state.active.try_clone(), self.writer_lock.try_clone())
        else {
            return false;
        };
        let path = self.path.clone();
        let lock_path = self.lock_path.clone();
        let fingerprint = state.fingerprint;
        let lock_fingerprint = self.lock_fingerprint;
        // Hold the state guard until the check completes so an append cannot
        // legitimately change the active file's fingerprint mid-check.
        let ready = tokio::task::spawn_blocking(move || {
            validate_pinned(&path, &active, fingerprint)?;
            validate_pinned(&lock_path, &writer_lock, lock_fingerprint)
        })
        .await
        .ok()
        .and_then(Result::ok)
        .is_some();
        drop(state);
        ready
    }

    async fn write_lines(&self, lines: Vec<String>) -> Result<(), AuditError> {
        if !self.healthy.load(Ordering::Acquire) {
            return Err(AuditError::Io(io::Error::other(
                "audit writer stopped after a failed write",
            )));
        }
        let mut state = self.state.lock().await;
        let request = AppendRequest {
            path: self.path.clone(),
            rotate_bytes: self.rotate_bytes,
            retain: self.retain,
            lines,
            active: state.active.try_clone().map_err(AuditError::Io)?,
            fingerprint: state.fingerprint,
            lock_path: self.lock_path.clone(),
            writer_lock: self.writer_lock.try_clone().map_err(AuditError::Io)?,
            lock_fingerprint: self.lock_fingerprint,
            next_sequence: state.next_sequence,
            #[cfg(test)]
            sync_hook: self.sync_hook.clone(),
        };
        let outcome = tokio::task::spawn_blocking(move || request.run())
            .await
            .map_err(|error| AuditError::Io(io::Error::other(error)))
            .and_then(|result| result);
        match outcome {
            Ok(result) => {
                if let Some(active) = result.replacement {
                    state.active = active;
                }
                state.fingerprint = result.fingerprint;
                state.next_sequence = result.next_sequence;
                Ok(())
            }
            Err(error) => {
                self.healthy.store(false, Ordering::Release);
                Err(error)
            }
        }
    }
}

struct AppendRequest {
    path: PathBuf,
    rotate_bytes: u64,
    retain: Duration,
    lines: Vec<String>,
    active: File,
    fingerprint: FileFingerprint,
    lock_path: PathBuf,
    writer_lock: File,
    lock_fingerprint: FileFingerprint,
    next_sequence: u64,
    #[cfg(test)]
    sync_hook: Option<SyncHook>,
}

struct AppendResult {
    replacement: Option<File>,
    fingerprint: FileFingerprint,
    next_sequence: u64,
}

impl AppendRequest {
    fn run(mut self) -> Result<AppendResult, AuditError> {
        validate_pinned(&self.path, &self.active, self.fingerprint)?;
        validate_pinned(&self.lock_path, &self.writer_lock, self.lock_fingerprint)?;

        let mut current = self.fingerprint.length;
        let mut replacement = None;
        let mut run = String::new();
        let lines = std::mem::take(&mut self.lines);
        for line in &lines {
            let incoming = u64::try_from(line.len()).map_err(|_| entry_size_error())?;
            if incoming > self.rotate_bytes {
                return Err(entry_size_error());
            }
            if current > 0 && current.saturating_add(incoming) > self.rotate_bytes {
                self.active
                    .write_all(run.as_bytes())
                    .map_err(AuditError::Io)?;
                run.clear();
                let fresh = self.rotate()?;
                self.active = fresh.try_clone().map_err(AuditError::Io)?;
                replacement = Some(fresh);
                current = 0;
            }
            run.push_str(line);
            current = current.saturating_add(incoming);
        }
        self.active
            .write_all(run.as_bytes())
            .map_err(AuditError::Io)?;
        self.sync_active()?;
        let fingerprint = file_fingerprint(&self.active)?;
        validate_pinned(&self.path, &self.active, fingerprint)?;
        validate_pinned(&self.lock_path, &self.writer_lock, self.lock_fingerprint)?;
        Ok(AppendResult {
            replacement,
            fingerprint,
            next_sequence: self.next_sequence,
        })
    }

    fn sync_active(&self) -> Result<(), AuditError> {
        self.active.sync_all().map_err(AuditError::Io)?;
        #[cfg(test)]
        if let Some(hook) = &self.sync_hook {
            hook().map_err(AuditError::Io)?;
        }
        Ok(())
    }

    /// Seal the active file under the next sequence, open a fresh active file,
    /// and delete sealed files older than the retention period.
    fn rotate(&mut self) -> Result<File, AuditError> {
        self.sync_active()?;
        let mut sequence = self.next_sequence;
        let mut sealed = segment_path(&self.path, sequence);
        while fs::symlink_metadata(&sealed).is_ok() {
            sequence = next_sequence(sequence)?;
            sealed = segment_path(&self.path, sequence);
        }
        fs::rename(&self.path, &sealed).map_err(AuditError::Io)?;
        let fresh = open_append(&self.path)?;
        validate_active_file(&fresh)?;
        if fresh.metadata().map_err(AuditError::Io)?.len() != 0 {
            return Err(AuditError::Io(io::Error::other(
                "replacement audit file is not empty",
            )));
        }
        fresh.sync_all().map_err(AuditError::Io)?;
        sync_directory(parent(&self.path)?)?;
        self.next_sequence = next_sequence(sequence)?;
        apply_retention(&self.path, self.retain)?;
        Ok(fresh)
    }
}

/// Delete sealed files whose last modification is older than `retain`.
fn apply_retention(path: &Path, retain: Duration) -> Result<(), AuditError> {
    let Some(cutoff) = SystemTime::now().checked_sub(retain) else {
        return Ok(());
    };
    let mut removed = false;
    for (_, sealed) in sealed_segments(path)? {
        let metadata = fs::symlink_metadata(&sealed).map_err(AuditError::Io)?;
        if !metadata.is_file() {
            continue;
        }
        if metadata.modified().map_err(AuditError::Io)? < cutoff {
            fs::remove_file(&sealed).map_err(AuditError::Io)?;
            removed = true;
        }
    }
    if removed {
        sync_directory(parent(path)?)?;
    }
    Ok(())
}

fn next_sequence(sequence: u64) -> Result<u64, AuditError> {
    sequence
        .checked_add(1)
        .ok_or_else(|| AuditError::Io(io::Error::other("audit file sequence is exhausted")))
}

/// Sealed files, oldest first.
fn sealed_segments(path: &Path) -> Result<Vec<(u64, PathBuf)>, AuditError> {
    let mut sealed = Vec::new();
    for entry in fs::read_dir(parent(path)?).map_err(AuditError::Io)? {
        let candidate = entry.map_err(AuditError::Io)?.path();
        if let Some(sequence) = segment_sequence(path, &candidate) {
            sealed.push((sequence, candidate));
        }
    }
    sealed.sort_unstable_by_key(|(sequence, _)| *sequence);
    Ok(sealed)
}

fn segment_sequence(path: &Path, candidate: &Path) -> Option<u64> {
    let active = path.file_name()?.to_str()?;
    let suffix = candidate
        .file_name()?
        .to_str()?
        .strip_prefix(active)?
        .strip_prefix('.')?;
    if suffix.len() != SEGMENT_SEQUENCE_DIGITS || !suffix.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    suffix.parse().ok()
}

fn segment_path(path: &Path, sequence: u64) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(format!(".{sequence:0SEGMENT_SEQUENCE_DIGITS$}"));
    PathBuf::from(value)
}

fn lock_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

/// Refuse an active file whose last entry was torn by an interrupted write.
fn require_complete_final_entry(active: &File) -> Result<(), AuditError> {
    let length = active.metadata().map_err(AuditError::Io)?.len();
    if length > 0 {
        let mut last = [0];
        active
            .read_exact_at(&mut last, length - 1)
            .map_err(AuditError::Io)?;
        if last[0] != b'\n' {
            return Err(AuditError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "audit file has an incomplete final entry; archive it and restart with a fresh path",
            )));
        }
    }
    Ok(())
}

fn open_append(path: &Path) -> Result<File, AuditError> {
    reject_symlink(path)?;
    OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .mode(0o600)
        .custom_flags(open_flags())
        .open(path)
        .map_err(AuditError::Io)
}

fn open_lock(path: &Path) -> Result<File, AuditError> {
    reject_symlink(path)?;
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(open_flags())
        .open(path)
        .map_err(AuditError::Io)
}

fn open_read(path: &Path) -> Result<File, AuditError> {
    reject_symlink(path)?;
    OpenOptions::new()
        .read(true)
        .custom_flags(open_flags())
        .open(path)
        .map_err(AuditError::Io)
}

fn open_flags() -> i32 {
    (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32
}

fn reject_symlink(path: &Path) -> Result<(), AuditError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(symlink_error()),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AuditError::Io(error)),
    }
}

fn symlink_error() -> AuditError {
    AuditError::Io(io::Error::new(
        ErrorKind::PermissionDenied,
        "audit paths must not be symlinks",
    ))
}

fn create_directory(path: &Path) -> Result<(), AuditError> {
    if fs::symlink_metadata(path).is_ok() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(AuditError::Io)
}

/// The audit directory must be a real directory owned by this user and not
/// writable by group or others, so no other account can replace audit files.
fn validate_directory(path: &Path) -> Result<(), AuditError> {
    let metadata = fs::symlink_metadata(path).map_err(AuditError::Io)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(AuditError::Io(io::Error::new(
            ErrorKind::PermissionDenied,
            "audit directory must be owned by this user and not group- or world-writable",
        )));
    }
    Ok(())
}

fn validate_active_file(file: &File) -> Result<(), AuditError> {
    validate_active_metadata(&file.metadata().map_err(AuditError::Io)?)
}

fn validate_active_metadata(metadata: &fs::Metadata) -> Result<(), AuditError> {
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(AuditError::Io(io::Error::new(
            ErrorKind::PermissionDenied,
            "audit files must be owner-only, singly linked regular files",
        )));
    }
    Ok(())
}

fn file_fingerprint(file: &File) -> Result<FileFingerprint, AuditError> {
    Ok(metadata_fingerprint(
        &file.metadata().map_err(AuditError::Io)?,
    ))
}

fn metadata_fingerprint(metadata: &fs::Metadata) -> FileFingerprint {
    FileFingerprint {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

/// Confirm the pinned descriptor and the file now at `path` are the same
/// owner-only file, unchanged since this writer last touched it.
fn validate_pinned(
    path: &Path,
    pinned: &File,
    expected: FileFingerprint,
) -> Result<(), AuditError> {
    let pinned_metadata = pinned.metadata().map_err(AuditError::Io)?;
    validate_active_metadata(&pinned_metadata)?;
    let candidate = open_read(path)?;
    let candidate_metadata = candidate.metadata().map_err(AuditError::Io)?;
    validate_active_metadata(&candidate_metadata)?;
    if metadata_fingerprint(&pinned_metadata) != expected
        || metadata_fingerprint(&candidate_metadata) != expected
    {
        return Err(AuditError::Io(io::Error::other(
            "audit file changed outside the writer",
        )));
    }
    Ok(())
}

fn parent(path: &Path) -> Result<&Path, AuditError> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            AuditError::Io(io::Error::new(
                ErrorKind::InvalidInput,
                "audit path has no parent directory",
            ))
        })
}

fn sync_directory(path: &Path) -> Result<(), AuditError> {
    validate_directory(path)?;
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(AuditError::Io)
}

fn entry_size_error() -> AuditError {
    AuditError::Io(io::Error::other("audit entry exceeds the rotation size"))
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        os::unix::fs::PermissionsExt,
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Arc, Mutex,
        },
        time::{Duration, SystemTime},
    };

    use serde_json::{json, Value};

    use super::*;

    fn directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("owner-only tempdir");
        directory
    }

    fn file_destination(directory: &tempfile::TempDir) -> FileDestination {
        FileDestination::new(directory.path().join("audit").join("audit.jsonl"))
            .expect("absolute path")
    }

    async fn open_with_hook(destination: FileDestination, hook: SyncHook) -> AuditWriter {
        let mut file = tokio::task::spawn_blocking(move || SegmentedFile::open(destination))
            .await
            .expect("join")
            .expect("open");
        file.sync_hook = Some(hook);
        AuditWriter {
            inner: Arc::new(WriterInner::File(Arc::new(GroupCommitFile::new(file)))),
        }
    }

    fn request(correlation: &str) -> AuditEntry {
        AuditEntry::request(
            "registry.test.audit/v2",
            correlation,
            json!({"operationId": "read", "outcome": null}),
        )
    }

    fn lines(path: &Path) -> Vec<Value> {
        fs::read_to_string(path)
            .expect("read audit file")
            .lines()
            .map(|line| serde_json::from_str(line).expect("json line"))
            .collect()
    }

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("buffer").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailingSink;

    impl Write for FailingSink {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("stream closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("stream closed"))
        }
    }

    #[tokio::test]
    async fn file_entries_carry_only_the_envelope_fields() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("open");
        writer.append(request("req-1")).await.expect("request");
        writer
            .append(AuditEntry::response(
                "registry.test.audit/v2",
                "req-1",
                json!({"outcome": "returned"}),
            ))
            .await
            .expect("response");

        let entries = lines(&path);
        assert_eq!(entries.len(), 2);
        for (entry, phase) in entries.iter().zip(["request", "response"]) {
            let object = entry.as_object().expect("object");
            let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                [
                    "correlation",
                    "eventId",
                    "phase",
                    "record",
                    "schema",
                    "time"
                ]
            );
            assert_eq!(entry["phase"], phase);
            assert_eq!(entry["correlation"], "req-1");
            assert_eq!(entry["schema"], "registry.test.audit/v2");
            Uuid::parse_str(entry["eventId"].as_str().expect("eventId")).expect("uuid");
            let time = entry["time"].as_str().expect("time");
            assert!(time.ends_with('Z'), "{time}");
            OffsetDateTime::parse(time, &time::format_description::well_known::Rfc3339)
                .expect("RFC 3339 time");
        }
        assert_ne!(entries[0]["eventId"], entries[1]["eventId"]);
        let text = fs::read_to_string(&path).expect("read");
        for chain_field in [
            "prev_hash",
            "record_hash",
            "prevHash",
            "recordHash",
            "sequence",
        ] {
            assert!(!text.contains(chain_field), "{chain_field} leaked");
        }
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[tokio::test]
    async fn restart_refuses_an_incomplete_final_entry_without_changing_the_file() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let writer = AuditWriter::open(AuditDestination::File(destination.clone()))
            .await
            .expect("open");
        writer.append(request("accepted")).await.expect("append");
        drop(writer);
        // A failed write or process interruption can leave only part of the
        // next entry. Restart must not join a later accepted entry to it.
        OpenOptions::new()
            .append(true)
            .open(&path)
            .and_then(|mut file| file.write_all(b"{\"schema\":"))
            .expect("partial entry");
        let before = fs::read(&path).expect("read before restart");

        let error = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect_err("incomplete final entry must refuse startup");
        assert!(
            matches!(error, AuditError::Io(ref error) if error.kind() == ErrorKind::InvalidData)
        );
        assert_eq!(fs::read(&path).expect("read after restart"), before);
    }

    #[tokio::test]
    async fn restart_appends_after_a_complete_final_entry() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let writer = AuditWriter::open(AuditDestination::File(destination.clone()))
            .await
            .expect("open");
        writer.append(request("before")).await.expect("append");
        drop(writer);

        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("reopen complete stream");
        writer
            .append(request("after"))
            .await
            .expect("append after restart");
        let entries = lines(&path);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["correlation"], "before");
        assert_eq!(entries[1]["correlation"], "after");
    }

    #[tokio::test]
    async fn append_returns_only_after_the_entry_is_synced() {
        let directory = directory();
        let (release, gate) = mpsc::channel::<()>();
        let gate = Arc::new(Mutex::new(gate));
        let synced = Arc::new(AtomicUsize::new(0));
        let hook_synced = Arc::clone(&synced);
        let hook: SyncHook = Arc::new(move || {
            gate.lock()
                .expect("gate")
                .recv_timeout(Duration::from_secs(10))
                .map_err(io::Error::other)?;
            hook_synced.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let writer = open_with_hook(file_destination(&directory), hook).await;

        let pending = tokio::spawn({
            let writer = writer.clone();
            async move { writer.append(request("req-1")).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!pending.is_finished(), "append returned before its sync");
        assert_eq!(synced.load(Ordering::SeqCst), 0);

        release.send(()).expect("release sync");
        pending.await.expect("join").expect("append");
        assert_eq!(synced.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_appends_share_durable_writes() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let hook: SyncHook = Arc::new(|| {
            std::thread::sleep(Duration::from_millis(20));
            Ok(())
        });
        let writer = open_with_hook(destination, hook).await;

        let appends = 64;
        let mut tasks = Vec::new();
        for index in 0..appends {
            let writer = writer.clone();
            tasks.push(tokio::spawn(async move {
                writer.append(request(&format!("req-{index}"))).await
            }));
        }
        for task in tasks {
            task.await.expect("join").expect("append");
        }

        assert_eq!(lines(&path).len(), appends);
        let durable_writes = writer.durable_writes();
        assert!(
            durable_writes < appends as u64 / 2,
            "{durable_writes} durable writes for {appends} appends"
        );
    }

    async fn wait_for_pending(file: &GroupCommitFile, expected: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while file.state.lock().await.pending.len() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pending batch reached expected size");
    }

    #[tokio::test]
    async fn cancelling_a_flush_owner_keeps_every_waiting_entry_durable() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("open");
        let WriterInner::File(file) = writer.inner.as_ref() else {
            panic!("file writer");
        };
        // Enqueue both callers in one batch, then hold its file-state lock so
        // cancellation lands after the batch was removed from pending.
        let file_guard = file.file.state.lock().await;
        let flush_guard = file.flush.lock().await;
        let owner = tokio::spawn({
            let writer = writer.clone();
            async move { writer.append(request("owner")).await }
        });
        wait_for_pending(file, 1).await;
        let waiter = tokio::spawn({
            let writer = writer.clone();
            async move { writer.append(request("waiter")).await }
        });
        wait_for_pending(file, 2).await;
        drop(flush_guard);
        wait_for_pending(file, 0).await;
        owner.abort();
        assert!(owner.await.expect_err("owner cancelled").is_cancelled());
        drop(file_guard);
        tokio::time::timeout(Duration::from_secs(5), writer.append(request("later")))
            .await
            .expect("later completes")
            .expect("later accepted");
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("waiter completes")
            .expect("waiter joined")
            .expect("waiter accepted");
        let correlations: Vec<Value> = lines(&path)
            .into_iter()
            .map(|entry| entry["correlation"].clone())
            .collect();
        assert_eq!(
            correlations,
            vec![json!("owner"), json!("waiter"), json!("later")]
        );
        assert!(writer.ready().await);
    }

    #[tokio::test]
    async fn cancelling_during_file_sync_keeps_the_pinned_state_current() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let (release, gate) = mpsc::channel::<()>();
        let gate = Arc::new(Mutex::new(gate));
        let syncing = Arc::new(AtomicUsize::new(0));
        let hook_syncing = Arc::clone(&syncing);
        let hook: SyncHook = Arc::new(move || {
            if hook_syncing.fetch_add(1, Ordering::SeqCst) == 0 {
                gate.lock()
                    .expect("gate")
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(io::Error::other)?;
            }
            Ok(())
        });
        let writer = open_with_hook(destination, hook).await;
        let owner = tokio::spawn({
            let writer = writer.clone();
            async move { writer.append(request("owner")).await }
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while syncing.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("file sync started");
        owner.abort();
        assert!(owner.await.expect_err("owner cancelled").is_cancelled());
        release.send(()).expect("finish sync");
        writer
            .append(request("later"))
            .await
            .expect("later accepted");
        assert_eq!(lines(&path).len(), 2);
        assert!(writer.ready().await);
    }

    #[tokio::test]
    async fn a_failed_sync_refuses_the_append_and_every_later_one() {
        let directory = directory();
        let hook: SyncHook = Arc::new(|| Err(io::Error::other("disk full")));
        let writer = open_with_hook(file_destination(&directory), hook).await;

        let first = writer.append(request("req-1")).await.expect_err("refused");
        assert_eq!(first.reason(), AuditUnavailableReason::WriteFailed);
        assert_eq!(first.to_string(), "audit destination is unavailable");
        let second = writer.append(request("req-2")).await.expect_err("refused");
        assert_eq!(second.reason(), AuditUnavailableReason::Stopped);
        assert!(!writer.ready().await);
    }

    #[tokio::test]
    async fn an_externally_changed_active_file_stops_the_writer() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("open");
        writer.append(request("req-1")).await.expect("append");
        assert!(writer.ready().await);

        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .and_then(|mut file| file.write_all(b"{}\n"))
            .expect("external write");

        assert!(!writer.ready().await);
        let refused = writer.append(request("req-2")).await.expect_err("refused");
        assert_eq!(refused.reason(), AuditUnavailableReason::WriteFailed);
    }

    #[tokio::test]
    async fn a_second_writer_on_the_same_path_is_refused() {
        let directory = directory();
        let destination = file_destination(&directory);
        let _first = AuditWriter::open(AuditDestination::File(destination.clone()))
            .await
            .expect("first");
        let second = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect_err("second writer");
        assert!(
            matches!(second, AuditError::SinkLocked { .. }),
            "{second:?}"
        );
    }

    #[tokio::test]
    async fn invalid_entries_are_refused_without_stopping_the_writer() {
        let directory = directory();
        let writer = AuditWriter::open(AuditDestination::File(file_destination(&directory)))
            .await
            .expect("open");
        for entry in [
            AuditEntry::request("", "req", json!({})),
            AuditEntry::request("schema/v2", "", json!({})),
            AuditEntry::request("schema/v2", "req\n", json!({})),
            AuditEntry::request("schema with space", "req", json!({})),
            AuditEntry::request("schema/v2", "req", json!(["not", "an", "object"])),
        ] {
            let refused = writer.append(entry).await.expect_err("invalid");
            assert_eq!(refused.reason(), AuditUnavailableReason::InvalidEntry);
        }
        let oversized = AuditEntry::request(
            "schema/v2",
            "req",
            json!({"value": "x".repeat(MAX_ENTRY_BYTES)}),
        );
        let refused = writer.append(oversized).await.expect_err("oversized");
        assert_eq!(refused.reason(), AuditUnavailableReason::EntryTooLarge);
        writer.append(request("req-1")).await.expect("still open");
    }

    #[tokio::test]
    async fn size_rotation_seals_segments_and_keeps_every_entry() {
        let directory = directory();
        let destination = file_destination(&directory)
            .with_rotate_bytes(MIN_AUDIT_ROTATE_BYTES)
            .expect("rotation");
        let path = destination.path().to_path_buf();
        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("open");
        let padding = "x".repeat(4096);
        let appends = 600;
        for index in 0..appends {
            writer
                .append(AuditEntry::request(
                    "schema/v2",
                    format!("req-{index}"),
                    json!({"padding": padding}),
                ))
                .await
                .expect("append");
        }

        let sealed = sealed_segments(&path).expect("sealed");
        assert!(sealed.len() >= 2, "{} sealed segments", sealed.len());
        assert_eq!(sealed[0].0, 1);
        let mut total = lines(&path).len();
        for (_, segment) in &sealed {
            let size = fs::metadata(segment).expect("segment").len();
            assert!(size <= MIN_AUDIT_ROTATE_BYTES, "{size}");
            let mode = fs::metadata(segment).expect("segment").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            total += lines(segment).len();
        }
        assert_eq!(total, appends);
    }

    #[tokio::test]
    async fn retention_deletes_only_expired_sealed_segments() {
        let directory = directory();
        let destination = file_destination(&directory)
            .with_retain_days(1)
            .expect("retention");
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        let old = SystemTime::now() - Duration::from_secs(3 * SECONDS_PER_DAY);
        let expired = segment_path(&path, 1);
        let recent = segment_path(&path, 2);
        let unrelated = path.with_file_name("audit.jsonl.backup");
        for file in [&expired, &recent, &unrelated] {
            fs::write(file, "{}\n").expect("seed file");
            fs::set_permissions(file, fs::Permissions::from_mode(0o600)).expect("mode");
        }
        for file in [&expired, &unrelated] {
            File::options()
                .write(true)
                .open(file)
                .and_then(|handle| handle.set_modified(old))
                .expect("age file");
        }

        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("open");
        assert!(!expired.exists(), "expired sealed segment kept");
        assert!(recent.exists(), "recent sealed segment deleted");
        assert!(unrelated.exists(), "unrelated file deleted");

        writer.append(request("req-1")).await.expect("append");
        let sealed = sealed_segments(&path).expect("sealed");
        assert_eq!(
            sealed
                .iter()
                .map(|(sequence, _)| *sequence)
                .collect::<Vec<_>>(),
            [2]
        );
    }

    #[tokio::test]
    async fn rotation_continues_after_the_highest_sealed_sequence() {
        let directory = directory();
        let destination = file_destination(&directory)
            .with_rotate_bytes(MIN_AUDIT_ROTATE_BYTES)
            .expect("rotation");
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        let existing = segment_path(&path, 7);
        fs::write(&existing, "{}\n").expect("seed");
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o600)).expect("mode");

        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("open");
        let padding = "x".repeat(4096);
        for index in 0..300 {
            writer
                .append(AuditEntry::request(
                    "schema/v2",
                    format!("req-{index}"),
                    json!({"padding": padding}),
                ))
                .await
                .expect("append");
        }
        let sequences: Vec<u64> = sealed_segments(&path)
            .expect("sealed")
            .into_iter()
            .map(|(sequence, _)| sequence)
            .collect();
        assert_eq!(sequences[..2], [7, 8]);
    }

    #[tokio::test]
    async fn stream_destination_emits_one_json_line_per_entry() {
        let buffer = SharedBuffer::default();
        let writer = AuditWriter::from_line_sink(Box::new(buffer.clone()));
        assert_eq!(writer.kind(), AuditDestinationKind::Stdout);
        writer.append(request("req-1")).await.expect("request");
        writer
            .append(AuditEntry::response(
                "registry.test.audit/v2",
                "req-1",
                json!({}),
            ))
            .await
            .expect("response");

        let text = String::from_utf8(buffer.0.lock().expect("buffer").clone()).expect("utf8");
        let entries: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("json line"))
            .collect();
        assert_eq!(entries.len(), 2);
        assert!(text.ends_with('\n'));
        assert_eq!(entries[0]["phase"], "request");
        assert_eq!(entries[1]["phase"], "response");
        assert_eq!(entries[1]["correlation"], "req-1");
    }

    #[tokio::test]
    async fn a_failing_stream_refuses_the_append_and_every_later_one() {
        let writer = AuditWriter::from_line_sink(Box::new(FailingSink));
        let first = writer.append(request("req-1")).await.expect_err("refused");
        assert_eq!(first.reason(), AuditUnavailableReason::WriteFailed);
        let second = writer.append(request("req-2")).await.expect_err("refused");
        assert_eq!(second.reason(), AuditUnavailableReason::Stopped);
        assert!(!writer.ready().await);
    }

    #[test]
    fn queued_stream_append_stays_stopped_after_an_earlier_write_fails() {
        struct FailOnce {
            entered: std::sync::mpsc::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
            writes: Arc<AtomicU64>,
        }

        impl Write for FailOnce {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.writes.fetch_add(1, Ordering::Relaxed) == 0 {
                    self.entered.send(()).expect("first write entered");
                    self.release
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(io::Error::other)?;
                    return Err(io::Error::other("first write failed"));
                }
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let (entered, first_write) = std::sync::mpsc::channel();
        let (queued, second_append) = std::sync::mpsc::channel();
        let (release, failure_gate) = std::sync::mpsc::channel();
        let writes = Arc::new(AtomicU64::new(0));
        let mut stream = LineStream::new(Box::new(FailOnce {
            entered,
            release: failure_gate,
            writes: writes.clone(),
        }));
        let calls = AtomicU64::new(0);
        stream.before_lock_hook = Some(Arc::new(move || {
            if calls.fetch_add(1, Ordering::Relaxed) == 1 {
                queued.send(()).expect("second append passed readiness");
            }
        }));
        std::thread::scope(|scope| {
            let first = scope.spawn(|| stream.append("first\n"));
            first_write
                .recv_timeout(Duration::from_secs(5))
                .expect("first write started");
            let second = scope.spawn(|| stream.append("second\n"));
            second_append
                .recv_timeout(Duration::from_secs(5))
                .expect("second append queued");
            release.send(()).expect("release failed write");
            assert_eq!(
                first
                    .join()
                    .expect("first joined")
                    .expect_err("first refused")
                    .reason(),
                AuditUnavailableReason::WriteFailed
            );
            assert_eq!(
                second
                    .join()
                    .expect("second joined")
                    .expect_err("queued append refused")
                    .reason(),
                AuditUnavailableReason::Stopped
            );
        });
        assert_eq!(writes.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn settings_apply_defaults_and_refuse_file_only_keys_on_stdout() {
        let path = PathBuf::from("/var/lib/registry/audit.jsonl");
        let AuditDestination::File(file) = AuditDestination::from_settings(
            AuditDestinationKind::File,
            Some(path.clone()),
            None,
            None,
        )
        .expect("file") else {
            panic!("expected a file destination");
        };
        assert_eq!(file.path(), path);
        assert_eq!(file.rotate_bytes(), DEFAULT_AUDIT_ROTATE_BYTES);
        assert_eq!(file.retain_days(), DEFAULT_AUDIT_RETAIN_DAYS);

        assert_eq!(
            AuditDestination::from_settings(AuditDestinationKind::File, None, None, None),
            Err(AuditDestinationError::MissingPath)
        );
        assert_eq!(
            AuditDestination::from_settings(
                AuditDestinationKind::File,
                Some(PathBuf::from("relative/audit.jsonl")),
                None,
                None
            ),
            Err(AuditDestinationError::RelativePath)
        );
        assert!(matches!(
            AuditDestination::from_settings(
                AuditDestinationKind::File,
                Some(path.clone()),
                Some(1),
                None
            ),
            Err(AuditDestinationError::RotateBytesOutOfRange { .. })
        ));
        assert!(matches!(
            AuditDestination::from_settings(
                AuditDestinationKind::File,
                Some(path.clone()),
                None,
                Some(0)
            ),
            Err(AuditDestinationError::RetainDaysOutOfRange { .. })
        ));
        assert_eq!(
            AuditDestination::from_settings(AuditDestinationKind::Stdout, None, None, None),
            Ok(AuditDestination::Stdout)
        );
        assert_eq!(
            AuditDestination::from_settings(AuditDestinationKind::Stdout, Some(path), None, None),
            Err(AuditDestinationError::FileOnlyField { field: "path" })
        );
        assert_eq!(
            AuditDestination::from_settings(AuditDestinationKind::Stdout, None, None, Some(7)),
            Err(AuditDestinationError::FileOnlyField {
                field: "retainDays"
            })
        );
    }

    #[tokio::test]
    async fn a_process_role_gets_its_own_sibling_file() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("audit").join("registry.jsonl");
        let service = AuditDestination::File(
            FileDestination::new(&path)
                .and_then(|file| file.with_rotate_bytes(2 * MIN_AUDIT_ROTATE_BYTES))
                .and_then(|file| file.with_retain_days(7))
                .expect("file"),
        );
        let AuditDestination::File(tool) = service.for_process("bregctl").expect("role") else {
            panic!("expected a file destination");
        };
        assert_eq!(
            tool.path(),
            directory
                .path()
                .join("audit")
                .join("registry.bregctl.jsonl")
        );
        assert_eq!(tool.rotate_bytes(), 2 * MIN_AUDIT_ROTATE_BYTES);
        assert_eq!(tool.retain_days(), 7);

        let AuditDestination::File(bare) = AuditDestination::File(
            FileDestination::new(directory.path().join("audit").join("journal")).expect("file"),
        )
        .for_process("breg-migrate")
        .expect("role") else {
            panic!("expected a file destination");
        };
        assert_eq!(
            bare.path(),
            directory.path().join("audit").join("journal.breg-migrate")
        );

        // A companion command's own report owns stdout, so its audit moves to
        // stderr and keeps the configured stdout kind.
        let companion = AuditDestination::Stdout
            .for_process("schedulingctl")
            .expect("role");
        assert_eq!(companion, AuditDestination::Stderr);
        assert_eq!(companion.kind(), AuditDestinationKind::Stdout);
        assert!(companion.check_writable().is_ok());
        assert_eq!(
            companion.for_process("schedulingctl"),
            Ok(AuditDestination::Stderr)
        );
        let companion_writer = AuditWriter::open(companion).await.expect("stderr");
        assert_eq!(companion_writer.kind(), AuditDestinationKind::Stdout);
        for role in ["", "-x", "Bregctl", "a/b", "a.b", &"x".repeat(33)] {
            assert_eq!(
                service.for_process(role),
                Err(AuditDestinationError::InvalidProcessRole),
                "{role:?}"
            );
        }

        let _service_writer = AuditWriter::open(service.clone()).await.expect("service");
        let tool_writer = AuditWriter::open(service.for_process("bregctl").expect("role"))
            .await
            .expect("a companion process opens its own file beside a running service");
        tool_writer
            .append(AuditEntry::response(
                "test/v1",
                "job-1",
                json!({"outcome": "ok"}),
            ))
            .await
            .expect("append");
    }

    #[test]
    fn destination_kind_uses_lowercase_names() {
        assert_eq!(
            serde_json::to_value(AuditDestinationKind::File).expect("json"),
            json!("file")
        );
        assert_eq!(
            serde_json::from_value::<AuditDestinationKind>(json!("stdout")).expect("kind"),
            AuditDestinationKind::Stdout
        );
    }

    #[test]
    fn check_writable_accepts_a_fresh_path_and_refuses_an_unsafe_directory() {
        let directory = directory();
        file_destination(&directory)
            .check_writable()
            .expect("fresh path is writable");

        let open = directory.path().join("open");
        fs::create_dir(&open).expect("dir");
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).expect("mode");
        FileDestination::new(open.join("audit.jsonl"))
            .expect("absolute")
            .check_writable()
            .expect_err("world-writable directory");

        let loose = directory.path().join("loose");
        fs::create_dir(&loose).expect("dir");
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o700)).expect("mode");
        fs::write(loose.join("audit.jsonl"), "").expect("file");
        fs::set_permissions(loose.join("audit.jsonl"), fs::Permissions::from_mode(0o644))
            .expect("mode");
        FileDestination::new(loose.join("audit.jsonl"))
            .expect("absolute")
            .check_writable()
            .expect_err("group-readable audit file");
    }

    #[test]
    fn check_writable_refuses_an_existing_file_the_writer_cannot_append_to() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        fs::write(&path, "").expect("file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).expect("mode");
        destination
            .check_writable()
            .expect_err("read-only audit file");
    }

    #[test]
    fn check_writable_refuses_a_directory_the_writer_cannot_search() {
        let directory = directory();
        let destination = file_destination(&directory);
        let parent = destination.path().parent().expect("parent").to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&parent)
            .expect("audit directory");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o600)).expect("mode");
        let refused = destination.check_writable();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).expect("restore");
        refused.expect_err("unsearchable audit directory");
    }

    #[test]
    fn check_writable_refuses_a_lock_companion_the_writer_refuses() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        let lock = lock_path(&path);
        fs::write(&lock, "").expect("lock");
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).expect("mode");
        destination.check_writable().expect("owner-only lock");
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).expect("mode");
        destination
            .check_writable()
            .expect_err("group-readable lock");
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o400)).expect("mode");
        destination.check_writable().expect_err("read-only lock");
        fs::remove_file(&lock).expect("remove lock");
        std::os::unix::fs::symlink(directory.path().join("elsewhere"), &lock).expect("symlink");
        destination.check_writable().expect_err("symlinked lock");
    }

    #[test]
    fn check_writable_refuses_an_existing_file_with_an_incomplete_final_entry() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        fs::write(&path, "{}\n").expect("file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        destination.check_writable().expect("complete final entry");
        fs::write(&path, "{}\n{").expect("torn file");
        destination
            .check_writable()
            .expect_err("incomplete final entry");
    }

    #[test]
    fn check_writable_refuses_a_missing_directory_below_an_unusable_ancestor() {
        let directory = directory();
        let file = directory.path().join("file");
        fs::write(&file, "").expect("file");
        FileDestination::new(file.join("audit").join("audit.jsonl"))
            .expect("absolute")
            .check_writable()
            .expect_err("ancestor is a regular file");

        let unsearchable = directory.path().join("unsearchable");
        fs::create_dir(&unsearchable).expect("dir");
        fs::set_permissions(&unsearchable, fs::Permissions::from_mode(0o600)).expect("mode");
        let refused = FileDestination::new(unsearchable.join("audit").join("audit.jsonl"))
            .expect("absolute")
            .check_writable();
        fs::set_permissions(&unsearchable, fs::Permissions::from_mode(0o700)).expect("mode");
        refused.expect_err("ancestor cannot be searched");
    }

    #[tokio::test]
    async fn open_refuses_a_symlinked_active_file() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        let target = directory.path().join("elsewhere.jsonl");
        fs::write(&target, "").expect("target");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");
        AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect_err("symlinked active file");
    }
}

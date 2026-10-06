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
    io::{self, ErrorKind, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
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

/// The JSON Schema pattern of a path [`FileDestination::new`] accepts: an
/// absolute path with no `..` segment that ends in a file name, stated for
/// runtime configuration schemas so an editor refuses what startup refuses.
/// The file name's length limit and the companion suffixes it must not end in
/// are checked at startup only.
pub const ABSOLUTE_AUDIT_PATH_PATTERN: &str =
    r"^/+(?:(?:[^/.][^/]*|\.(?:[^/.][^/]*|\.[^/]+)?)/+)*(?:[^/.][^/]*|\.(?:[^/.][^/]*|\.[^/]+))$";

const MAX_ENTRY_BYTES: usize = 1024 * 1024;
const MAX_SCHEMA_BYTES: usize = 128;
const MAX_CORRELATION_BYTES: usize = 256;
const SEGMENT_SEQUENCE_DIGITS: usize = 8;
/// The suffix of the lock companion beside the active file.
const LOCK_SUFFIX: &str = ".lock";
/// The suffix of the companion that records the next sealed-segment
/// sequence, so retention deleting every sealed segment cannot reset it.
const SEQUENCE_SUFFIX: &str = ".seq";
/// The suffix the sequence companion is written under before it is renamed
/// into place.
const SEQUENCE_TEMPORARY_SUFFIX: &str = ".seq.tmp";
/// The suffix of the owner-only side file a torn final line is moved to when
/// the writer opens, so the active file ends in a complete entry again.
const TORN_LINE_SUFFIX: &str = ".torn";
/// Every companion suffix the writer names after its active file, with the
/// companion each one names, for refusals that name a collision.
const COMPANION_SUFFIXES: [(&str, &str); 4] = [
    (LOCK_SUFFIX, "lock"),
    (SEQUENCE_SUFFIX, "sequence companion"),
    (SEQUENCE_TEMPORARY_SUFFIX, "temporary sequence companion"),
    (TORN_LINE_SUFFIX, "torn-line side file"),
];
/// The longest file name common filesystems accept.
const MAX_FILE_NAME_BYTES: usize = 255;
/// The longest active file name that leaves room for every sibling the
/// writer names after it: a sealed segment adds `.` and the sequence digits,
/// the longest suffix, and the lock, sequence, and torn-line companions add
/// [`LOCK_SUFFIX`], [`SEQUENCE_SUFFIX`], [`SEQUENCE_TEMPORARY_SUFFIX`], and
/// [`TORN_LINE_SUFFIX`].
const MAX_AUDIT_FILE_NAME_BYTES: usize = MAX_FILE_NAME_BYTES - 1 - SEGMENT_SEQUENCE_DIGITS;
const _: () = assert!(LOCK_SUFFIX.len() <= 1 + SEGMENT_SEQUENCE_DIGITS);
const _: () = assert!(SEQUENCE_SUFFIX.len() <= 1 + SEGMENT_SEQUENCE_DIGITS);
const _: () = assert!(SEQUENCE_TEMPORARY_SUFFIX.len() <= 1 + SEGMENT_SEQUENCE_DIGITS);
const _: () = assert!(TORN_LINE_SUFFIX.len() <= 1 + SEGMENT_SEQUENCE_DIGITS);
const DETACHED_LOCK_ATTEMPTS: usize = 1024;
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
    #[error("audit.path must not contain a `.` or `..` component")]
    InvalidPathComponent,
    #[error("audit.path must end in a file name, not `/` or a `.` segment")]
    NoFileName,
    #[error(
        "audit.path must end in a file name of at most {maximum} bytes, so the \
         writer's rotated and lock files fit the {MAX_FILE_NAME_BYTES}-byte file-name limit"
    )]
    FileNameTooLong { maximum: usize },
    #[error("audit.{field} applies only when audit.destination is file")]
    FileOnlyField { field: &'static str },
    #[error("audit.rotateBytes must be between {minimum} and {maximum}")]
    RotateBytesOutOfRange { minimum: u64, maximum: u64 },
    #[error("audit.retainDays must be between 1 and {maximum}")]
    RetainDaysOutOfRange { maximum: u32 },
    #[error("an audit process role is 1 to 32 lowercase ASCII letters, digits, or hyphens")]
    InvalidProcessRole,
    #[error(
        "the audit process role names a file the configured audit.path reserves: \
         a sealed segment, the lock, the sequence companion, or the torn-line side file"
    )]
    ProcessRoleOverlapsStream,
    #[error(
        "audit.path names the {companion} of an audit stream at `{stream}`: a file name \
         ending in `{suffix}` is reserved for it, and a writer there would rename or \
         replace this file; choose a file name without that suffix"
    )]
    PathNamesReservedCompanion {
        /// The file name of the stream whose companion the path names.
        stream: String,
        /// The reserved suffix the file name ends in.
        suffix: &'static str,
        /// The companion that suffix names.
        companion: &'static str,
    },
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
    /// Set by [`AuditDestination::for_process`] to the companion role this
    /// destination is the sibling file for. `None` for the destination the
    /// service opens directly.
    role: Option<String>,
}

impl FileDestination {
    /// A file destination with the default rotation and retention.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, AuditDestinationError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(AuditDestinationError::RelativePath);
        }
        // A `..` component would put the file outside the hierarchy the
        // configured path appears to name.
        if !path.components().all(|component| {
            matches!(
                component,
                Component::RootDir | Component::Prefix(_) | Component::Normal(_)
            )
        }) {
            return Err(AuditDestinationError::InvalidPathComponent);
        }
        // `Path` drops a trailing `/` or `.`, so `/a/b/` and `/a/b/.` would
        // be checked as the file `b` in `/a` and then fail to open as one.
        let name = path
            .as_os_str()
            .as_bytes()
            .rsplit(|byte| *byte == b'/')
            .next();
        let Some(name) = name.filter(|name| !matches!(*name, b"" | b".")) else {
            return Err(AuditDestinationError::NoFileName);
        };
        // A name the writer could open but not rotate would stop it at the
        // first rotation.
        if name.len() > MAX_AUDIT_FILE_NAME_BYTES {
            return Err(AuditDestinationError::FileNameTooLong {
                maximum: MAX_AUDIT_FILE_NAME_BYTES,
            });
        }
        // A writer at the shorter name would rename its sequence companion
        // over this file, delete it as an expired sealed segment, or take it
        // for its lock or torn-line side file.
        if let Some(collision) = reserved_companion_collision(name) {
            return Err(collision);
        }
        Ok(Self {
            path,
            rotate_bytes: DEFAULT_AUDIT_ROTATE_BYTES,
            retain_days: DEFAULT_AUDIT_RETAIN_DAYS,
            role: None,
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
    /// writer could open this destination: the directory exists and the
    /// writer can list, write, and search it, or the nearest existing
    /// ancestor is a directory it can create it in; the directory is owned by
    /// this user and not group- or world-writable; and any existing lock
    /// companion and active file are owner-only regular files the writer can
    /// open, and the active file's final entry is complete or is a torn line
    /// the writer would move to its side file at open.
    pub fn check_writable(&self) -> Result<(), AuditError> {
        let parent = parent(&self.path)?;
        match fs::symlink_metadata(parent) {
            Ok(_) => validate_directory(parent)?,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                // `symlink_metadata` sees a dangling link that `exists()`
                // reports as absent; the writer's recursive create follows
                // the nearest existing ancestor, so it must be a directory.
                let mut ancestor = parent;
                loop {
                    match fs::symlink_metadata(ancestor) {
                        Ok(_) => break,
                        Err(error) if error.kind() == ErrorKind::NotFound => {}
                        Err(error) => return Err(AuditError::Io(error)),
                    }
                    ancestor = ancestor.parent().ok_or_else(|| {
                        AuditError::Io(io::Error::new(
                            ErrorKind::NotFound,
                            "audit directory has no existing ancestor",
                        ))
                    })?;
                }
                require_creatable_below(ancestor)?;
                return validate_creation_ancestor(ancestor);
            }
            Err(error) => return Err(AuditError::Io(error)),
        }
        // The writer creates, renames, and deletes files in the directory,
        // lists it to apply retention, and opens it to sync it.
        if rustix::fs::access(
            parent,
            rustix::fs::Access::READ_OK
                | rustix::fs::Access::WRITE_OK
                | rustix::fs::Access::EXEC_OK,
        )
        .is_err()
        {
            return Err(AuditError::Io(io::Error::new(
                ErrorKind::PermissionDenied,
                "audit directory is not readable, writable, and searchable",
            )));
        }
        // The writer opens the lock companion for read and write, on the
        // same terms as the active file, before it opens the active file, and
        // reopens it for read on every append to check it is still pinned.
        let lock = lock_path(&self.path);
        match fs::symlink_metadata(&lock) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Err(symlink_error()),
            Ok(metadata) => {
                validate_active_metadata(&metadata)?;
                rustix::fs::access(
                    &lock,
                    rustix::fs::Access::READ_OK | rustix::fs::Access::WRITE_OK,
                )
                .map_err(|_| {
                    AuditError::Io(io::Error::new(
                        ErrorKind::PermissionDenied,
                        "audit lock file is not readable and writable",
                    ))
                })?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(AuditError::Io(error)),
        }
        // The writer reads the sequence companion when it opens.
        read_next_sequence(&self.path)?;
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
                let torn = torn_tail(&active)?;
                require_current_entry_format(&active, torn.as_ref())?;
                match torn {
                    Some(torn) => {
                        side_file_holds(&AuditSegments::new(&self.path), &torn).map(|_| ())
                    }
                    None => Ok(()),
                }
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
                if name.len() > MAX_AUDIT_FILE_NAME_BYTES {
                    return Err(AuditDestinationError::FileNameTooLong {
                        maximum: MAX_AUDIT_FILE_NAME_BYTES - 1 - role.len(),
                    });
                }
                let path = file.path.with_file_name(name);
                if namespaces_overlap(&file.path, &path) {
                    return Err(AuditDestinationError::ProcessRoleOverlapsStream);
                }
                Ok(Self::File(FileDestination {
                    path,
                    rotate_bytes: file.rotate_bytes,
                    retain_days: file.retain_days,
                    role: Some(role.to_owned()),
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
    open: Arc<OpenRequests>,
}

/// The schema and correlation a request entry and its responses share.
type RequestKey = (String, String);

/// One request entry still owed a response: whether one was accepted, and
/// the state its handle shares with the responses being written.
#[derive(Clone)]
struct OpenRequest {
    answered: Arc<AtomicBool>,
    state: Arc<StdMutex<RequestState>>,
}

/// The request entries whose [`AuditRequest`] still owes a response, by
/// schema and correlation, oldest first.
#[derive(Default)]
struct OpenRequests(StdMutex<std::collections::HashMap<RequestKey, Vec<OpenRequest>>>);

impl OpenRequests {
    fn open(&self, key: RequestKey, request: OpenRequest) {
        match self.0.lock() {
            Ok(mut open) => open.entry(key).or_default().push(request),
            // The request is still owed by its handle, which writes its
            // unfinished response; only a response appended elsewhere can
            // no longer answer it.
            Err(_) => tracing::error!(
                "the open audit requests are poisoned; a response appended elsewhere will not answer this request"
            ),
        }
    }

    /// Claim the oldest open request under `key` with no response in
    /// flight, neither an appended one that claimed it nor one its own
    /// handle is writing, counting that response as in flight on it, so its
    /// handle dropped meanwhile leaves the request to that response.
    fn claim(&self, key: &RequestKey) -> Option<OpenRequest> {
        let open = self.0.lock().ok()?;
        open.get(key)?.iter().find_map(|request| {
            let mut state = request.state.lock().ok()?;
            if state.claimed || state.in_flight > 0 {
                return None;
            }
            state.claimed = true;
            state.in_flight += 1;
            Some(request.clone())
        })
    }

    /// Close `answered` under `key` once a response to it was accepted.
    fn answer(&self, key: &RequestKey, answered: &Arc<AtomicBool>) {
        if let Ok(mut open) = self.0.lock() {
            Self::remove(&mut open, key, answered);
        }
    }

    /// Close `answered` under `key` for its unfinished response, reporting
    /// whether it is still owed one: not when a response was accepted, and
    /// not when one is in flight on it, since that response settles the
    /// request itself. Checked and removed under the lock [`Self::claim`]
    /// takes, so a response cannot be claimed after the owner decided it had
    /// none.
    fn close_unanswered(
        &self,
        key: &RequestKey,
        answered: &Arc<AtomicBool>,
        state: &StdMutex<RequestState>,
    ) -> bool {
        let Ok(mut open) = self.0.lock() else {
            return !answered.load(Ordering::Acquire);
        };
        if answered.load(Ordering::Acquire) {
            return false;
        }
        if state.lock().is_ok_and(|state| state.in_flight > 0) {
            return false;
        }
        Self::remove(&mut open, key, answered);
        true
    }

    fn remove(
        open: &mut std::collections::HashMap<RequestKey, Vec<OpenRequest>>,
        key: &RequestKey,
        answered: &Arc<AtomicBool>,
    ) {
        if let Some(waiting) = open.get_mut(key) {
            waiting.retain(|candidate| !Arc::ptr_eq(&candidate.answered, answered));
            if waiting.is_empty() {
                open.remove(key);
            }
        }
    }
}

/// One response counted in flight on the request it answers. Dropping it
/// settles that count, whether its write finished or its task was dropped
/// before it could, such as by a runtime shutting down, so the request's
/// handle is never left waiting on a response that will not come.
struct InFlightResponse {
    writer: AuditWriter,
    key: RequestKey,
    answered: Arc<AtomicBool>,
    state: Arc<StdMutex<RequestState>>,
    /// The response was appended through [`AuditWriter::append`] and holds
    /// the request's claim.
    claimed: bool,
}

impl InFlightResponse {
    /// Record that the response was accepted, answering this request and
    /// not an older one open under its correlation.
    fn accepted(&self) {
        self.writer.open.answer(&self.key, &self.answered);
        self.answered.store(true, Ordering::Release);
    }
}

impl Drop for InFlightResponse {
    fn drop(&mut self) {
        let owes_unfinished = self.state.lock().is_ok_and(|mut state| {
            if self.claimed {
                state.claimed = false;
            }
            state.in_flight -= 1;
            state.in_flight == 0 && state.dropped
        });
        if owes_unfinished {
            settle_unanswered(
                &self.writer,
                std::mem::take(&mut self.key),
                &self.answered,
                &self.state,
            );
        }
    }
}

enum WriterInner {
    File(Arc<GroupCommitFile>),
    Stream(Arc<LineStream>, DetachedLines),
}

impl std::fmt::Debug for AuditWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("AuditWriter");
        match self.inner.as_ref() {
            WriterInner::File(file) => debug
                .field("destination", &"file")
                .field("path", &file.file.path),
            WriterInner::Stream(..) => debug.field("destination", &"stdout"),
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
            AuditDestination::Stdout => WriterInner::stream(Box::new(io::stdout())),
            AuditDestination::Stderr => WriterInner::stream(Box::new(io::stderr())),
        };
        Ok(Self {
            inner: Arc::new(inner),
            open: Arc::default(),
        })
    }

    /// A writer over an arbitrary line sink, with `stdout` semantics. For
    /// tests that need to observe emitted lines without a file.
    #[must_use]
    pub fn from_line_sink(sink: Box<dyn Write + Send>) -> Self {
        Self {
            inner: Arc::new(WriterInner::stream(sink)),
            open: Arc::default(),
        }
    }

    /// Append one entry. For the file destination this returns only after the
    /// entry's bytes are durable. Canceling the caller does not cancel an
    /// enqueued file write or the other entries in its group commit.
    ///
    /// An accepted `response` entry answers the oldest [`AuditRequest`] still
    /// open under the same schema and correlation with no response of its own
    /// being written.
    pub async fn append(&self, entry: AuditEntry) -> Result<(), AuditUnavailable> {
        // The write and the bookkeeping it implies run in one task that
        // outlives a canceled caller, so an accepted response always answers
        // its request, whether or not the caller is still waiting. The
        // request is claimed before that task starts, so a handle dropped
        // while the response is written leaves the request to it.
        let claimed = if entry.phase == AuditPhase::Response {
            let key = (entry.schema.clone(), entry.correlation.clone());
            self.open.claim(&key).map(|request| InFlightResponse {
                writer: self.clone(),
                key,
                answered: request.answered,
                state: request.state,
                claimed: true,
            })
        } else {
            None
        };
        let writer = self.clone();
        tokio::spawn(async move {
            let result = writer.write(&entry).await;
            if let Some(claimed) = claimed {
                if result.is_ok() {
                    claimed.accepted();
                }
            }
            result
        })
        .await
        .map_err(|_| AuditUnavailable::new(AuditUnavailableReason::Stopped))?
    }

    async fn write(&self, entry: &AuditEntry) -> Result<(), AuditUnavailable> {
        let line = entry.to_line()?;
        match self.inner.as_ref() {
            WriterInner::File(file) => {
                let file = Arc::clone(file);
                tokio::spawn(async move { file.append(line).await })
                    .await
                    .map_err(|_| AuditUnavailable::new(AuditUnavailableReason::Stopped))?
            }
            WriterInner::Stream(stream, _) => {
                let stream = Arc::clone(stream);
                tokio::task::spawn_blocking(move || stream.append(&line))
                    .await
                    .map_err(|_| AuditUnavailable::new(AuditUnavailableReason::Stopped))?
            }
        }
    }

    /// Append the `request` entry of one audited operation and return the
    /// [`AuditRequest`] that owes its `response` entry.
    ///
    /// `request` and `unfinished` are the product's minimized records. The
    /// handle writes `unfinished` as the `response` entry if it is dropped
    /// before any response is accepted, so an early return, an error, a
    /// panic, or a canceled future still pairs the request entry. Every
    /// `response` the handle writes carries the request's schema and
    /// correlation. A response appended through [`Self::append`] under the
    /// same schema and correlation answers it too, so an operation whose
    /// outcome is written elsewhere only holds the handle until it returns.
    ///
    /// That pairing holds while the process runs. A process killed or
    /// exited without unwinding, or a runtime shut down while an entry is
    /// being written, can leave a request entry without its response.
    pub async fn begin(
        &self,
        schema: impl Into<String>,
        correlation: impl Into<String>,
        request: Value,
        unfinished: Value,
    ) -> Result<AuditRequest, AuditUnavailable> {
        let schema = schema.into();
        let correlation = correlation.into();
        // The unfinished response must be writable before the request is:
        // a request accepted with a response it could never write would stay
        // unpaired.
        AuditEntry::response(schema.clone(), correlation.clone(), unfinished.clone()).to_line()?;
        // The request is written and its handle registered in one task that
        // outlives a canceled caller. A caller that stops waiting drops the
        // finished handle with the task's output, which writes the
        // unfinished response.
        let writer = self.clone();
        tokio::spawn(async move {
            writer
                .write(&AuditEntry::request(
                    schema.clone(),
                    correlation.clone(),
                    request,
                ))
                .await?;
            let answered = Arc::new(AtomicBool::new(false));
            let state = Arc::new(StdMutex::new(RequestState {
                unfinished: Some(unfinished),
                in_flight: 0,
                claimed: false,
                dropped: false,
            }));
            writer.open.open(
                (schema.clone(), correlation.clone()),
                OpenRequest {
                    answered: Arc::clone(&answered),
                    state: Arc::clone(&state),
                },
            );
            Ok(AuditRequest {
                writer,
                schema,
                correlation,
                answered,
                state,
            })
        })
        .await
        .map_err(|_| AuditUnavailable::new(AuditUnavailableReason::Stopped))?
    }

    /// Block until every response entry a dropped [`AuditRequest`] handed
    /// to a stream destination has been written. Those entries are written
    /// on a dedicated thread so a drop never blocks the runtime; this is for
    /// tests and shutdown paths that read the stream right after a drop. A
    /// file destination queues its entries into the group commit instead,
    /// and this returns at once for it.
    pub fn wait_for_detached_entries(&self) {
        if let WriterInner::Stream(_, detached) = self.inner.as_ref() {
            detached.wait();
        }
    }

    /// Write `entry` without waiting for the destination to accept it.
    fn append_detached(&self, entry: &AuditEntry) {
        let line = match entry.to_line() {
            Ok(line) => line,
            Err(_) => {
                tracing::error!("an unfinished response entry is malformed and was not written");
                return;
            }
        };
        match self.inner.as_ref() {
            WriterInner::File(file) => file.enqueue_detached(line),
            // A dedicated thread writes it, so a drop never blocks a runtime
            // thread on a slow stream, and the thread is joined when the
            // writer is dropped, so shutdown does not lose it.
            WriterInner::Stream(_, detached) => detached.send(line),
        }
    }

    /// Report whether the writer can still accept entries. For the file
    /// destination this also confirms the writer still owns the active file.
    pub async fn ready(&self) -> bool {
        match self.inner.as_ref() {
            WriterInner::File(file) => file.ready().await,
            WriterInner::Stream(stream, _) => stream.healthy(),
        }
    }

    #[must_use]
    pub fn kind(&self) -> AuditDestinationKind {
        match self.inner.as_ref() {
            WriterInner::File(_) => AuditDestinationKind::File,
            WriterInner::Stream(..) => AuditDestinationKind::Stdout,
        }
    }

    /// The active file path, for the file destination.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self.inner.as_ref() {
            WriterInner::File(file) => Some(&file.file.path),
            WriterInner::Stream(..) => None,
        }
    }

    /// Number of durable writes (each one `fsync`) this process performed.
    /// Always zero for `stdout`.
    #[must_use]
    pub fn durable_writes(&self) -> u64 {
        match self.inner.as_ref() {
            WriterInner::File(file) => file.durable_writes.load(Ordering::Relaxed),
            WriterInner::Stream(..) => 0,
        }
    }
}

/// An accepted `request` entry that still owes its `response` entry.
///
/// [`AuditRequest::respond`] appends a `response` entry and waits for the
/// destination to accept it; an operation may respond more than once. A
/// handle dropped before any response was accepted writes the `unfinished`
/// record given to [`AuditWriter::begin`] as its `response` entry. That write
/// cannot be awaited, so an operation with a known outcome, a refusal
/// included, responds with it instead of relying on the drop.
#[must_use = "an audit request writes its unfinished response entry when dropped"]
pub struct AuditRequest {
    writer: AuditWriter,
    schema: String,
    correlation: String,
    /// Set once a response entry under this schema and correlation was
    /// accepted.
    answered: Arc<AtomicBool>,
    /// The unfinished record and the responses still being written, shared
    /// with those writes so the last one to settle owns the drop's duty.
    state: Arc<StdMutex<RequestState>>,
}

struct RequestState {
    /// The record written if the request ends unanswered.
    unfinished: Option<Value>,
    /// Responses whose write has started and not yet settled.
    in_flight: usize,
    /// A response appended through [`AuditWriter::append`] claimed this
    /// request and has not settled.
    claimed: bool,
    /// The handle was dropped while a response was in flight.
    dropped: bool,
}

impl std::fmt::Debug for AuditRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuditRequest")
            .field("schema", &self.schema)
            .field("answered", &self.is_answered())
            .finish_non_exhaustive()
    }
}

impl AuditRequest {
    /// The correlation its request and response entries share.
    #[must_use]
    pub fn correlation(&self) -> &str {
        &self.correlation
    }

    /// Whether a response entry was accepted.
    #[must_use]
    pub fn is_answered(&self) -> bool {
        self.answered.load(Ordering::Acquire)
    }

    /// Append one `response` entry. A refused entry leaves the request
    /// unanswered, so a later drop still writes the unfinished record. The
    /// write and its bookkeeping outlive a canceled caller: a response
    /// accepted after the caller stopped waiting still answers the request,
    /// and a drop while it is in flight writes the unfinished record only if
    /// that response is refused.
    pub async fn respond(&mut self, record: Value) -> Result<(), AuditUnavailable> {
        if let Ok(mut state) = self.state.lock() {
            state.in_flight += 1;
        }
        // A poisoned state skips both the count and its release.
        let in_flight = InFlightResponse {
            writer: self.writer.clone(),
            key: (self.schema.clone(), self.correlation.clone()),
            answered: Arc::clone(&self.answered),
            state: Arc::clone(&self.state),
            claimed: false,
        };
        let entry = AuditEntry::response(self.schema.clone(), self.correlation.clone(), record);
        tokio::spawn(async move {
            let result = in_flight.writer.write(&entry).await;
            if result.is_ok() {
                in_flight.accepted();
            }
            result
        })
        .await
        .map_err(|_| AuditUnavailable::new(AuditUnavailableReason::Stopped))?
    }

    /// Append `record` as the only `response` entry and release the handle.
    pub async fn finish(mut self, record: Value) -> Result<(), AuditUnavailable> {
        self.respond(record).await
    }
}

/// Write the unfinished record of a request still owed a response.
fn settle_unanswered(
    writer: &AuditWriter,
    key: RequestKey,
    answered: &Arc<AtomicBool>,
    state: &StdMutex<RequestState>,
) {
    if !writer.open.close_unanswered(&key, answered, state) {
        return;
    }
    let unfinished = state
        .lock()
        .ok()
        .and_then(|mut state| state.unfinished.take());
    if let Some(unfinished) = unfinished {
        writer.append_detached(&AuditEntry::response(key.0, key.1, unfinished));
    }
}

impl Drop for AuditRequest {
    fn drop(&mut self) {
        // A response still being written settles the request itself.
        let in_flight = self.state.lock().is_ok_and(|mut state| {
            state.dropped = true;
            state.in_flight > 0
        });
        if in_flight {
            return;
        }
        let key = (
            std::mem::take(&mut self.schema),
            std::mem::take(&mut self.correlation),
        );
        settle_unanswered(&self.writer, key, &self.answered, &self.state);
    }
}

/// The unfinished response entries dropped requests hand to a stream
/// destination, written in order on one dedicated thread.
struct DetachedLines {
    stream: Arc<LineStream>,
    sender: StdMutex<Option<std::sync::mpsc::Sender<String>>>,
    thread: StdMutex<Option<std::thread::JoinHandle<()>>>,
    /// Lines handed over and not yet written, with a signal on each write.
    pending: Arc<(StdMutex<usize>, std::sync::Condvar)>,
}

impl DetachedLines {
    fn new(stream: Arc<LineStream>) -> Self {
        Self {
            stream,
            sender: StdMutex::new(None),
            thread: StdMutex::new(None),
            pending: Arc::new((StdMutex::new(0), std::sync::Condvar::new())),
        }
    }

    fn send(&self, line: String) {
        let Ok(mut sender) = self.sender.lock() else {
            tracing::error!("an unfinished response entry was not written");
            return;
        };
        if sender.is_none() {
            let (lines, received) = std::sync::mpsc::channel::<String>();
            let stream = Arc::clone(&self.stream);
            let pending = Arc::clone(&self.pending);
            let spawned = std::thread::Builder::new()
                .name("audit-detached".to_owned())
                .spawn(move || {
                    for line in received {
                        if stream.append(&line).is_err() {
                            tracing::error!("an unfinished response entry was not accepted");
                        }
                        let (count, written) = &*pending;
                        if let Ok(mut count) = count.lock() {
                            *count = count.saturating_sub(1);
                        }
                        written.notify_all();
                    }
                });
            match spawned {
                Ok(thread) => {
                    if let Ok(mut slot) = self.thread.lock() {
                        *slot = Some(thread);
                    }
                    *sender = Some(lines);
                }
                Err(error) => {
                    tracing::error!(%error, "an unfinished response entry was not written");
                    return;
                }
            }
        }
        if let Ok(mut count) = self.pending.0.lock() {
            *count += 1;
        }
        if sender
            .as_ref()
            .is_some_and(|lines| lines.send(line).is_err())
        {
            tracing::error!("an unfinished response entry was not written");
            if let Ok(mut count) = self.pending.0.lock() {
                *count = count.saturating_sub(1);
            }
        }
    }

    fn wait(&self) {
        let (count, written) = &*self.pending;
        let Ok(mut count) = count.lock() else {
            return;
        };
        while *count > 0 {
            count = match written.wait(count) {
                Ok(count) => count,
                Err(_) => return,
            };
        }
    }
}

impl Drop for DetachedLines {
    /// Close the queue and let the thread write what is left.
    fn drop(&mut self) {
        if let Ok(mut sender) = self.sender.lock() {
            sender.take();
        }
        let thread = self.thread.lock().ok().and_then(|mut thread| thread.take());
        if let Some(thread) = thread {
            let _ = thread.join();
        }
    }
}

impl WriterInner {
    fn stream(out: Box<dyn Write + Send>) -> Self {
        let stream = Arc::new(LineStream::new(out));
        Self::Stream(Arc::clone(&stream), DetachedLines::new(stream))
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
        self.wait_durable(position).await
    }

    /// Wait until the line queued at `position` is durable, flushing the
    /// queue when no other append is.
    async fn wait_durable(&self, position: u64) -> Result<(), AuditUnavailable> {
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

    /// Queue `line` without waiting for it to be durable, then flush it on
    /// the current runtime. A line queued when no runtime can flush it, or
    /// whose flush is canceled at shutdown, is written by the next append or
    /// when the last reference to the file is dropped.
    fn enqueue_detached(self: &Arc<Self>, line: String) {
        let runtime = tokio::runtime::Handle::try_current().ok();
        let mut line = Some(line);
        // Every holder of the state lock releases it without awaiting, so a
        // short wait is usually enough; a line still not queued after it is
        // queued below under a wait for the lock. The lock never poisons: a
        // stop shows as `stopped` once the lock is taken.
        for _ in 0..DETACHED_LOCK_ATTEMPTS {
            if let Ok(mut state) = self.state.try_lock() {
                if state.stopped {
                    tracing::error!(
                        "audit writer stopped; an unfinished response entry was not written"
                    );
                    return;
                }
                state.pending.extend(line.take());
                state.enqueued = state.enqueued.saturating_add(1);
                break;
            }
            std::thread::yield_now();
        }
        let Some(runtime) = runtime else {
            // Outside a runtime nothing can flush the line later, so it is
            // queued under a blocking wait for the lock, which no holder
            // keeps across an await; the file's drop or the next group
            // commit writes it.
            if let Some(line) = line {
                let mut state = self.state.blocking_lock();
                if state.stopped {
                    tracing::error!(
                        "audit writer stopped; an unfinished response entry was not written"
                    );
                    return;
                }
                state.pending.push(line);
                state.enqueued = state.enqueued.saturating_add(1);
            }
            return;
        };
        let file = Arc::clone(self);
        // A line not queued yet is lost if the runtime drops this task
        // before it runs, such as at shutdown; that loss is reported.
        let unqueued = line.map(|line| UnqueuedLine(Some(line)));
        runtime.spawn(async move {
            let result = match unqueued {
                Some(mut unqueued) => {
                    let position = {
                        let mut state = file.state.lock().await;
                        if state.stopped {
                            Err(AuditUnavailable::new(AuditUnavailableReason::Stopped))
                        } else {
                            state.pending.extend(unqueued.0.take());
                            state.enqueued = state.enqueued.saturating_add(1);
                            Ok(state.enqueued)
                        }
                    };
                    match position {
                        Ok(position) => file.wait_durable(position).await,
                        Err(error) => Err(error),
                    }
                }
                None => {
                    let _writer = file.flush.lock().await;
                    file.flush_once().await
                }
            };
            if result.is_err() {
                tracing::error!("an unfinished response entry was not accepted");
            }
        });
    }
}

/// A detached line not yet handed to the group commit, which reports its
/// loss if dropped still holding it.
struct UnqueuedLine(Option<String>);

impl Drop for UnqueuedLine {
    fn drop(&mut self) {
        if self.0.is_some() {
            tracing::error!("an unfinished response entry was dropped before it was written");
        }
    }
}

impl Drop for GroupCommitFile {
    /// Write the lines still queued, such as an unfinished response whose
    /// flush was canceled when the runtime shut down.
    fn drop(&mut self) {
        let state = self.state.get_mut();
        if state.stopped || state.pending.is_empty() {
            return;
        }
        let lines = std::mem::take(&mut state.pending);
        if let Err(error) = self.file.write_lines_blocking(lines) {
            tracing::error!(%error, "queued audit entries were not written at shutdown");
        }
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
    in_flight: Arc<AtomicUsize>,
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
}

impl SegmentedFile {
    fn open(destination: FileDestination) -> Result<Self, AuditError> {
        let FileDestination {
            path,
            rotate_bytes,
            retain_days,
            role,
        } = destination;
        let parent = parent(&path)?.to_path_buf();
        create_directory(&parent)?;
        validate_directory(&parent)?;

        let lock_path = lock_path(&path);
        let writer_lock = open_lock(&lock_path)?;
        validate_active_file(&writer_lock)?;
        match writer_lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(AuditError::SinkLocked {
                    path: lock_path.display().to_string(),
                    role,
                });
            }
            Err(TryLockError::Error(error)) => return Err(AuditError::Io(error)),
        }

        let active = open_append(&path)?;
        validate_active_file(&active)?;
        // A file in another format is refused before a torn line moves, so
        // recovery never touches a file this writer did not produce.
        let torn = torn_tail(&active)?;
        require_current_entry_format(&active, torn.as_ref())?;
        if let Some(torn) = torn {
            recover_torn_tail(&AuditSegments::new(&path), &active, torn)?;
        }
        active.sync_all().map_err(AuditError::Io)?;
        // An earlier open may have crashed after creating the lock or active
        // file but before syncing their names, so every open syncs them.
        sync_directory(&parent)?;
        // The next sequence is derived before retention deletes anything and
        // recorded durably first, and rotation records it again before each
        // sealed name appears, so a restart after retention or a shipper
        // removed every sealed segment cannot reuse a name already sealed.
        let recorded = read_next_sequence(&path)?;
        let next_sequence = AuditSegments::new(&path).next_sequence()?;
        if next_sequence > recorded.unwrap_or(1) {
            write_next_sequence(&path, next_sequence)?;
        }
        let retain = Duration::from_secs(u64::from(retain_days) * SECONDS_PER_DAY);
        retain_or_log(&path, retain);

        let fingerprint = file_fingerprint(&active)?;
        let lock_fingerprint = file_fingerprint(&writer_lock)?;
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
            in_flight: Arc::new(AtomicUsize::new(0)),
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
        let request = self.append_request(&state, lines)?;
        let in_flight = InFlightWrite::start(&self.in_flight);
        let outcome = tokio::task::spawn_blocking(move || {
            let _in_flight = in_flight;
            request.run()
        })
        .await
        .map_err(|error| AuditError::Io(io::Error::other(error)))
        .and_then(|result| result);
        self.settle(&mut state, outcome)
    }

    /// Write `lines` on the calling thread, outside any runtime. The owner of
    /// the last reference calls it, so no other write can hold the state.
    fn write_lines_blocking(&self, lines: Vec<String>) -> Result<(), AuditError> {
        if !self.healthy.load(Ordering::Acquire) {
            return Err(AuditError::Io(io::Error::other(
                "audit writer stopped after a failed write",
            )));
        }
        // A canceled caller can leave its blocking write running; writing
        // beside it could interleave two runs of lines in the active file.
        if self.in_flight.load(Ordering::Acquire) != 0 {
            return Err(AuditError::Io(io::Error::other(
                "an earlier audit write is still in flight",
            )));
        }
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| AuditError::Io(io::Error::other("audit file state is held")))?;
        let outcome = self
            .append_request(&state, lines)
            .and_then(AppendRequest::run);
        self.settle(&mut state, outcome)
    }

    fn append_request(
        &self,
        state: &FileState,
        lines: Vec<String>,
    ) -> Result<AppendRequest, AuditError> {
        Ok(AppendRequest {
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
        })
    }

    fn settle(
        &self,
        state: &mut FileState,
        outcome: Result<AppendResult, AuditError>,
    ) -> Result<(), AuditError> {
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

/// Counts one blocking write from its start until its thread finishes it,
/// even when the caller that awaited it was canceled.
struct InFlightWrite(Arc<AtomicUsize>);

impl InFlightWrite {
    fn start(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::AcqRel);
        Self(Arc::clone(counter))
    }
}

impl Drop for InFlightWrite {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
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
        // A length other than the bytes this writer holds means another
        // process wrote to or truncated the file during the append.
        if fingerprint.length != current {
            return Err(AuditError::Io(io::Error::other(
                "audit file changed outside the writer",
            )));
        }
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
        // Retention ages a sealed file by its last modification, and a rename
        // keeps it, so sealing stamps it: a file last written longer ago than
        // the retention period is not deleted by the rotation that seals it.
        self.active
            .set_modified(SystemTime::now())
            .map_err(AuditError::Io)?;
        self.sync_active()?;
        let mut sequence = self.next_sequence;
        let mut sealed = segment_path(&self.path, sequence);
        while fs::symlink_metadata(&sealed).is_ok() {
            sequence = next_sequence(sequence)?;
            sealed = segment_path(&self.path, sequence);
        }
        write_next_sequence(&self.path, next_sequence(sequence)?)?;
        // The rename seals whatever file is at the path, so confirm it is the
        // one this writer holds before sealing it.
        let held = self.active.metadata().map_err(AuditError::Io)?;
        let at_path = fs::symlink_metadata(&self.path).map_err(AuditError::Io)?;
        if (at_path.dev(), at_path.ino()) != (held.dev(), held.ino()) {
            return Err(AuditError::Io(io::Error::other(
                "audit file changed outside the writer",
            )));
        }
        fs::rename(&self.path, &sealed).map_err(AuditError::Io)?;
        #[cfg(test)]
        if SHIPPED_ON_SEAL
            .lock()
            .expect("shipped on seal")
            .iter()
            .any(|shipped| shipped == &self.path)
        {
            fs::remove_file(&sealed).map_err(AuditError::Io)?;
        }
        // Confirm the sealed name holds that file too, unless a shipper has
        // already taken it.
        match fs::symlink_metadata(&sealed) {
            Ok(sealed_metadata)
                if (sealed_metadata.dev(), sealed_metadata.ino()) != (held.dev(), held.ino()) =>
            {
                return Err(AuditError::Io(io::Error::other(
                    "audit file changed outside the writer",
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(AuditError::Io(error)),
        }
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
        retain_or_log(&self.path, self.retain);
        Ok(fresh)
    }
}

/// Active paths whose retention pass fails, so a test can observe the writer
/// carry on after a sealed segment it could not delete.
#[cfg(test)]
static RETENTION_REFUSED: StdMutex<Vec<PathBuf>> = StdMutex::new(Vec::new());

#[cfg(test)]
fn refuse_retention(path: &Path) {
    RETENTION_REFUSED
        .lock()
        .expect("retention refusals")
        .push(path.to_path_buf());
}

#[cfg(test)]
fn allow_retention(path: &Path) {
    RETENTION_REFUSED
        .lock()
        .expect("retention refusals")
        .retain(|refused| refused != path);
}

/// Active paths whose sealed segment a simulated shipper removes the moment
/// rotation seals it.
#[cfg(test)]
static SHIPPED_ON_SEAL: StdMutex<Vec<PathBuf>> = StdMutex::new(Vec::new());

#[cfg(test)]
fn ship_on_seal(path: &Path) {
    SHIPPED_ON_SEAL
        .lock()
        .expect("shipped on seal")
        .push(path.to_path_buf());
}

/// Directories [`sync_directory`] synced, so a test can observe the sync.
#[cfg(test)]
static DIRECTORY_SYNCS: StdMutex<Vec<PathBuf>> = StdMutex::new(Vec::new());

#[cfg(test)]
fn forget_directory_syncs(directory: &Path) {
    DIRECTORY_SYNCS
        .lock()
        .expect("directory syncs")
        .retain(|synced| synced != directory);
}

#[cfg(test)]
fn directory_synced(directory: &Path) -> bool {
    DIRECTORY_SYNCS
        .lock()
        .expect("directory syncs")
        .iter()
        .any(|synced| synced == directory)
}

/// Apply retention without stopping the writer: a sealed segment that could
/// not be deleted costs disk space, never an audit entry, and the next
/// rotation or open retries it.
fn retain_or_log(path: &Path, retain: Duration) {
    if let Err(error) = apply_retention(path, retain) {
        tracing::error!(
            %error,
            "audit retention failed; expired sealed segments stay until the next rotation or restart"
        );
    }
}

/// Delete sealed files whose last modification is older than `retain`, from
/// the oldest sequence up to the first one still inside the period, so a
/// segment whose time was reset never opens a gap in the sealed sequence.
fn apply_retention(path: &Path, retain: Duration) -> Result<(), AuditError> {
    let Some(cutoff) = SystemTime::now().checked_sub(retain) else {
        return Ok(());
    };
    let mut removed = false;
    for sealed in AuditSegments::new(path).sealed(usize::MAX)? {
        let sealed = sealed.path;
        let metadata = fs::symlink_metadata(&sealed).map_err(AuditError::Io)?;
        if !metadata.is_file() {
            continue;
        }
        if metadata.modified().map_err(AuditError::Io)? < cutoff {
            #[cfg(test)]
            if RETENTION_REFUSED
                .lock()
                .expect("retention refusals")
                .iter()
                .any(|refused| refused == path)
            {
                return Err(AuditError::Io(io::Error::from(ErrorKind::PermissionDenied)));
            }
            fs::remove_file(&sealed).map_err(AuditError::Io)?;
            removed = true;
        } else {
            break;
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

/// The names a file destination's writer owns beside its active file: sealed
/// segments `<path>.<8 digits>`, the lock `<path>.lock`, the sequence
/// companion `<path>.seq` and its temporary `<path>.seq.tmp`, and the
/// torn-line side file `<path>.torn`.
///
/// It is read-only: it names and lists files and never creates, renames, or
/// deletes one, so tooling that inspects a stopped stream reads the same
/// namespace the writer manages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditSegments {
    path: PathBuf,
}

/// One sealed segment of an [`AuditSegments`] namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedSegment {
    /// The eight-digit sequence rotation sealed it under.
    pub sequence: u64,
    /// `<path>.<sequence>`.
    pub path: PathBuf,
}

impl AuditSegments {
    /// The namespace of the active file at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The active file.
    #[must_use]
    pub fn active(&self) -> &Path {
        &self.path
    }

    /// The single-writer lock companion, `<path>.lock`.
    #[must_use]
    pub fn lock(&self) -> PathBuf {
        lock_path(&self.path)
    }

    /// The companion recording the next sealed-segment sequence, `<path>.seq`.
    #[must_use]
    pub fn sequence(&self) -> PathBuf {
        sequence_path(&self.path)
    }

    /// The owner-only side file a torn final line is moved to at open,
    /// `<path>.torn`.
    #[must_use]
    pub fn torn_line(&self) -> PathBuf {
        companion_path(&self.path, TORN_LINE_SUFFIX)
    }

    /// Whether `candidate` is the active file or a name the writer owns
    /// beside it.
    #[must_use]
    pub fn reserves(&self, candidate: &Path) -> bool {
        reserved_by(&self.path, candidate)
    }

    /// The sealed segments present, oldest first: the order they were
    /// written in and the order retention deletes them. A name that has a
    /// lock companion is the active file of another stream configured at
    /// that name, never a sealed segment, and is left out. More than
    /// `maximum` segment-shaped names, those left out included, is refused
    /// while scanning rather than listed partially, so the listing never
    /// holds more than `maximum` names whatever the directory holds.
    pub fn sealed(&self, maximum: usize) -> Result<Vec<SealedSegment>, AuditError> {
        let mut sealed = Vec::new();
        for (sequence, path) in self.segment_names(maximum)? {
            // A lock name past the file-name limit cannot exist.
            let lock = lock_path(&path);
            if lock
                .file_name()
                .is_some_and(|name| name.len() <= MAX_FILE_NAME_BYTES)
            {
                match fs::symlink_metadata(&lock) {
                    Ok(_) => continue,
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => return Err(AuditError::Io(error)),
                }
            }
            sealed.push(SealedSegment { sequence, path });
        }
        Ok(sealed)
    }

    /// The sequence the next rotation seals under: past both the one the
    /// sequence companion records and every name in the namespace that looks
    /// sealed, so neither retention nor a shipper removing every sealed
    /// segment can make a restart reuse a name.
    pub fn next_sequence(&self) -> Result<u64, AuditError> {
        let mut highest = None;
        self.scan_segment_names(|sequence, _| {
            highest = highest.max(Some(sequence));
            Ok(())
        })?;
        let scanned = highest.map_or(1, |sequence: u64| sequence.saturating_add(1));
        Ok(read_next_sequence(&self.path)?.map_or(scanned, |recorded| recorded.max(scanned)))
    }

    /// Every name shaped like a sealed segment, oldest first. More than
    /// `maximum` names is refused as soon as the scan meets one too many.
    fn segment_names(&self, maximum: usize) -> Result<Vec<(u64, PathBuf)>, AuditError> {
        let mut names = Vec::new();
        self.scan_segment_names(|sequence, candidate| {
            if names.len() == maximum {
                return Err(AuditError::Io(io::Error::other(
                    "audit segment count exceeds the listing bound",
                )));
            }
            names.push((sequence, candidate));
            Ok(())
        })?;
        names.sort_unstable_by_key(|(sequence, _)| *sequence);
        Ok(names)
    }

    /// Visit every name shaped like a sealed segment, in directory order.
    fn scan_segment_names(
        &self,
        mut visit: impl FnMut(u64, PathBuf) -> Result<(), AuditError>,
    ) -> Result<(), AuditError> {
        for entry in fs::read_dir(parent(&self.path)?).map_err(AuditError::Io)? {
            let candidate = entry.map_err(AuditError::Io)?.path();
            if let Some(sequence) = segment_sequence(&self.path, &candidate) {
                visit(sequence, candidate)?;
            }
        }
        Ok(())
    }
}

fn segment_sequence(path: &Path, candidate: &Path) -> Option<u64> {
    let active = path.file_name()?.to_str()?;
    let suffix = candidate
        .file_name()?
        .to_str()?
        .strip_prefix(active)?
        .strip_prefix('.')?;
    sequence_suffix(suffix)
}

/// The sequence an eight-digit segment suffix, without its dot, names.
fn sequence_suffix(digits: &str) -> Option<u64> {
    if digits.len() != SEGMENT_SEQUENCE_DIGITS || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    digits.parse().ok()
}

fn segment_path(path: &Path, sequence: u64) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(format!(".{sequence:0SEGMENT_SEQUENCE_DIGITS$}"));
    PathBuf::from(value)
}

fn lock_path(path: &Path) -> PathBuf {
    companion_path(path, LOCK_SUFFIX)
}

fn sequence_path(path: &Path) -> PathBuf {
    companion_path(path, SEQUENCE_SUFFIX)
}

fn companion_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

/// The refusal for an active file name that a writer at a shorter name would
/// give one of its own files: a companion, or a sealed segment.
fn reserved_companion_collision(name: &[u8]) -> Option<AuditDestinationError> {
    let named = |stream: &[u8], suffix: &'static str, companion: &'static str| {
        // A bare suffix leaves no file name for the other stream.
        (!matches!(stream, b"" | b".")).then(|| AuditDestinationError::PathNamesReservedCompanion {
            stream: String::from_utf8_lossy(stream).into_owned(),
            suffix,
            companion,
        })
    };
    for (suffix, companion) in COMPANION_SUFFIXES {
        if let Some(stream) = name.strip_suffix(suffix.as_bytes()) {
            if let Some(collision) = named(stream, suffix, companion) {
                return Some(collision);
            }
        }
    }
    let split = name.len().checked_sub(1 + SEGMENT_SEQUENCE_DIGITS)?;
    let (stream, suffix) = name.split_at(split);
    let digits = std::str::from_utf8(suffix.strip_prefix(b".")?).ok()?;
    sequence_suffix(digits)?;
    named(stream, ".<8 digits>", "sealed segment")
}

/// Whether `candidate` is `path` or a file the writer at `path` names after
/// it: a sealed segment or a lock, sequence, or torn-line companion.
fn reserved_by(path: &Path, candidate: &Path) -> bool {
    if candidate == path {
        return true;
    }
    if candidate.parent() != path.parent() {
        return false;
    }
    let (Some(active), Some(name)) = (path.file_name(), candidate.file_name()) else {
        return false;
    };
    let Some(suffix) = name.as_bytes().strip_prefix(active.as_bytes()) else {
        return false;
    };
    segment_sequence(path, candidate).is_some()
        || COMPANION_SUFFIXES
            .iter()
            .any(|(reserved, _)| suffix == reserved.as_bytes())
}

/// Whether two writers at `a` and `b` would name a file the other owns.
fn namespaces_overlap(a: &Path, b: &Path) -> bool {
    reserved_by(a, b) || reserved_by(b, a)
}

/// The next sealed-segment sequence the sequence companion records, if it
/// exists. It must be an owner-only regular file holding a decimal number.
fn read_next_sequence(path: &Path) -> Result<Option<u64>, AuditError> {
    let sequence = sequence_path(path);
    let file = match open_read(&sequence) {
        Ok(file) => file,
        Err(AuditError::Io(error)) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    validate_active_file(&file)?;
    let mut content = String::new();
    file.take(32)
        .read_to_string(&mut content)
        .map_err(AuditError::Io)?;
    content
        .strip_suffix('\n')
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|digits| digits.parse().ok())
        .map(Some)
        .ok_or_else(|| {
            AuditError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "audit sequence file is malformed; it must hold the next sealed segment sequence as one decimal number and a newline",
            ))
        })
}

/// Record `next` in the sequence companion, replacing it atomically.
fn write_next_sequence(path: &Path, next: u64) -> Result<(), AuditError> {
    let temporary = companion_path(path, SEQUENCE_TEMPORARY_SUFFIX);
    let file = open_owned(&temporary, OpenOptions::new().write(true))?;
    validate_active_file(&file)?;
    file.set_len(0).map_err(AuditError::Io)?;
    (&file)
        .write_all(format!("{next}\n").as_bytes())
        .map_err(AuditError::Io)?;
    file.sync_all().map_err(AuditError::Io)?;
    fs::rename(&temporary, sequence_path(path)).map_err(AuditError::Io)?;
    sync_directory(parent(path)?)
}

/// The bytes an interrupted write left after the active file's last complete
/// line, and the length that keeps every complete line.
#[derive(Debug)]
struct TornTail {
    complete: u64,
    bytes: Vec<u8>,
}

/// Find a torn final line: bytes after the last newline. A line is
/// acknowledged only after its whole batch is written and synced, so these
/// bytes belong to no acknowledged entry. A tail at least as long as the
/// largest entry is not one this writer's write left, and is refused.
fn torn_tail(active: &File) -> Result<Option<TornTail>, AuditError> {
    let length = active.metadata().map_err(AuditError::Io)?.len();
    if length == 0 {
        return Ok(None);
    }
    let mut last = [0];
    active
        .read_exact_at(&mut last, length - 1)
        .map_err(AuditError::Io)?;
    if last[0] == b'\n' {
        return Ok(None);
    }
    // A torn line is a strict prefix of an entry, and an entry, newline
    // included, is at most `MAX_ENTRY_BYTES`.
    let window = length.min(MAX_ENTRY_BYTES as u64);
    let start = length - window;
    #[allow(clippy::cast_possible_truncation)]
    let mut buffer = vec![0; window as usize];
    active
        .read_exact_at(&mut buffer, start)
        .map_err(AuditError::Io)?;
    let complete = match buffer.iter().rposition(|byte| *byte == b'\n') {
        Some(newline) => newline + 1,
        None if start == 0 && window < MAX_ENTRY_BYTES as u64 => 0,
        None => {
            return Err(AuditError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "audit file ends in more bytes without a newline than any entry holds; \
                 archive it and restart with a fresh path",
            )))
        }
    };
    let bytes = buffer.split_off(complete);
    Ok(Some(TornTail {
        complete: start + complete as u64,
        bytes,
    }))
}

/// Whether the torn-line side file already holds exactly `torn`'s bytes, as
/// after a crash between copying them and truncating the active file.
/// `false` means there is no side file. A side file holding anything else is
/// never overwritten: it is the only copy of an earlier torn line.
fn side_file_holds(segments: &AuditSegments, torn: &TornTail) -> Result<bool, AuditError> {
    let side = match open_read(&segments.torn_line()) {
        Ok(side) => side,
        Err(AuditError::Io(error)) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    validate_active_file(&side)?;
    let mut held = Vec::with_capacity(torn.bytes.len());
    (&side)
        .take(torn.bytes.len() as u64 + 1)
        .read_to_end(&mut held)
        .map_err(AuditError::Io)?;
    if held != torn.bytes {
        return Err(AuditError::Io(io::Error::new(
            ErrorKind::AlreadyExists,
            "audit file has an incomplete final entry and its torn-line side file \
             `<audit.path>.torn` already holds other bytes; archive the side file and restart",
        )));
    }
    // The earlier run may have crashed before the copy was synced.
    side.sync_all().map_err(AuditError::Io)?;
    Ok(true)
}

/// Copy a torn final line to the owner-only side file, sync it and its name,
/// then truncate the active file to its last complete line, so an entry
/// appended after restart is never joined to the torn bytes. Only the side
/// file's path and the byte count are logged, never the bytes.
fn recover_torn_tail(
    segments: &AuditSegments,
    active: &File,
    torn: TornTail,
) -> Result<(), AuditError> {
    let side = segments.torn_line();
    let directory = parent(segments.active())?;
    if !side_file_holds(segments, &torn)? {
        reject_symlink(&side)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(open_flags())
            .open(&side)
            .map_err(AuditError::Io)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(AuditError::Io)?;
        (&file).write_all(&torn.bytes).map_err(AuditError::Io)?;
        file.sync_all().map_err(AuditError::Io)?;
    }
    sync_directory(directory)?;
    active.set_len(torn.complete).map_err(AuditError::Io)?;
    active.sync_all().map_err(AuditError::Io)?;
    let bytes = torn.bytes.len() as u64;
    #[cfg(test)]
    TORN_RECOVERIES.lock().expect("torn recoveries").push((
        segments.active().to_path_buf(),
        side.clone(),
        bytes,
    ));
    tracing::error!(
        side_file = %side.display(),
        bytes,
        "audit file ended in a torn final line, left by an interrupted write; its bytes were \
         moved to an owner-only side file and the active file was truncated to its last \
         complete line. No acknowledged entry was lost. Inspect the side file and archive it \
         with the sealed segments"
    );
    Ok(())
}

/// Torn-line recoveries, so a test can observe what was logged.
#[cfg(test)]
static TORN_RECOVERIES: StdMutex<Vec<(PathBuf, PathBuf, u64)>> = StdMutex::new(Vec::new());

/// Refuse an active file whose first entry was not produced by this writer,
/// such as a leftover journal from the pre-simplification hash-chained
/// writer. Every entry this writer appends carries `eventId`, `schema`,
/// `time`, `phase`, and `correlation`; an old-format entry carries none of
/// them. Only the first line is read, bounded to the largest entry this
/// writer accepts, since a file this writer manages never mixes formats. A
/// torn final line is not part of the first entry the check reads.
fn require_current_entry_format(active: &File, torn: Option<&TornTail>) -> Result<(), AuditError> {
    let length = match torn {
        Some(torn) => torn.complete,
        None => active.metadata().map_err(AuditError::Io)?.len(),
    };
    if length == 0 {
        return Ok(());
    }
    let read_len = length.min(MAX_ENTRY_BYTES as u64);
    #[allow(clippy::cast_possible_truncation)]
    let mut buffer = vec![0; read_len as usize];
    active
        .read_exact_at(&mut buffer, 0)
        .map_err(AuditError::Io)?;
    let first_line = buffer.split(|&byte| byte == b'\n').next().unwrap_or(&[]);
    let is_current_format = serde_json::from_slice::<Value>(first_line)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .is_some_and(|entry| {
            entry.get("eventId").is_some_and(Value::is_string)
                && entry.get("schema").is_some_and(Value::is_string)
                && entry.get("time").is_some_and(Value::is_string)
                && entry.get("correlation").is_some_and(Value::is_string)
                && matches!(
                    entry.get("phase").and_then(Value::as_str),
                    Some("request" | "response")
                )
        });
    if !is_current_format {
        return Err(AuditError::Io(io::Error::new(
            ErrorKind::InvalidData,
            "audit file's first entry is not in the format this writer produces; archive it and restart with a fresh path",
        )));
    }
    Ok(())
}

fn open_append(path: &Path) -> Result<File, AuditError> {
    open_owned(path, OpenOptions::new().read(true).append(true))
}

fn open_lock(path: &Path) -> Result<File, AuditError> {
    open_owned(path, OpenOptions::new().read(true).write(true))
}

/// Open `path`, creating it when absent. A created file is set to owner read
/// and write explicitly, since the process umask can mask the requested mode.
fn open_owned(path: &Path, options: &mut OpenOptions) -> Result<File, AuditError> {
    reject_symlink(path)?;
    options.mode(0o600).custom_flags(open_flags());
    match options.clone().create_new(true).open(path) {
        Ok(file) => {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(AuditError::Io)?;
            Ok(file)
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            options.open(path).map_err(AuditError::Io)
        }
        Err(error) => Err(AuditError::Io(error)),
    }
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
    create_directory_with(path, sync_created_parent)
}

/// [`create_directory`] with the step that syncs the directory holding each
/// created one, so a test can observe it.
fn create_directory_with(
    path: &Path,
    mut sync_parent: impl FnMut(&Path) -> Result<(), AuditError>,
) -> Result<(), AuditError> {
    if fs::symlink_metadata(path).is_ok() {
        return Ok(());
    }
    // Each missing directory is created and then set to owner-only access
    // explicitly, since the process umask can mask the requested mode.
    let mut missing = Vec::new();
    let mut ancestor = path;
    while fs::symlink_metadata(ancestor).is_err() {
        missing.push(ancestor);
        match ancestor.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => ancestor = parent,
            _ => break,
        }
    }
    if fs::symlink_metadata(ancestor).is_ok() {
        validate_creation_ancestor(ancestor)?;
    }
    for directory in missing.into_iter().rev() {
        match fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .map_err(AuditError::Io)?,
            // Another process created it between the check and here. It
            // may be another account's, so it must meet the requirements a
            // pre-existing audit directory meets before anything is created
            // inside it.
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                validate_directory(directory)?;
            }
            Err(error) => return Err(AuditError::Io(error)),
        }
        // The new entry is durable only once the directory holding it is
        // synced, whichever process created it.
        let holder = directory.parent().ok_or_else(|| {
            AuditError::Io(io::Error::new(
                ErrorKind::NotFound,
                "audit directory has no parent",
            ))
        })?;
        sync_parent(holder)?;
    }
    Ok(())
}

/// Check that the writer's recursive create can make a directory inside
/// `ancestor`, the nearest existing ancestor of a missing audit directory.
fn require_creatable_below(ancestor: &Path) -> Result<(), AuditError> {
    if !fs::metadata(ancestor).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(AuditError::Io(io::Error::new(
            ErrorKind::NotADirectory,
            "audit directory cannot be created",
        )));
    }
    // Creating an entry in a directory needs search as well as write
    // permission on it, and the writer opens it to sync that entry.
    if rustix::fs::access(
        ancestor,
        rustix::fs::Access::READ_OK | rustix::fs::Access::WRITE_OK | rustix::fs::Access::EXEC_OK,
    )
    .is_err()
    {
        return Err(AuditError::Io(io::Error::new(
            ErrorKind::PermissionDenied,
            "audit directory cannot be created",
        )));
    }
    Ok(())
}

/// The nearest existing ancestor of a missing audit directory holds the first
/// directory the writer creates. Any account could swap that directory once
/// it exists if the ancestor is world-writable and not sticky, so such an
/// ancestor is refused. A sticky one, like `/tmp`, lets only an entry's owner
/// rename it, and a group-writable one, like `/var/log`, admits only accounts
/// the host already trusts with its logs. A raced directory created there by
/// another account is refused by [`validate_directory`].
fn validate_creation_ancestor(ancestor: &Path) -> Result<(), AuditError> {
    // The recursive create follows a linked ancestor, so the check does too.
    let metadata = fs::metadata(ancestor).map_err(AuditError::Io)?;
    if !metadata.is_dir() || (metadata.mode() & 0o002 != 0 && metadata.mode() & 0o1000 == 0) {
        return Err(AuditError::Io(io::Error::new(
            ErrorKind::PermissionDenied,
            "audit directory's nearest existing ancestor is world-writable and not sticky; \
             create the audit directory yourself, owned by the service user, mode 0700",
        )));
    }
    Ok(())
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
            "audit directory must be owned by this user and not group- or world-writable; chown it to the service user and chmod it 0700",
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
            "audit files must be owner-only, singly linked regular files; chmod them 0600 and remove any extra hard link",
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

/// Sync the directory holding a directory [`create_directory`] made, so
/// the created entry survives a power loss. It may be an ancestor this user
/// does not own, so unlike [`sync_directory`] it is not validated.
fn sync_created_parent(path: &Path) -> Result<(), AuditError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(AuditError::Io)
}

fn sync_directory(path: &Path) -> Result<(), AuditError> {
    validate_directory(path)?;
    #[cfg(test)]
    DIRECTORY_SYNCS
        .lock()
        .expect("directory syncs")
        .push(path.to_path_buf());
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
            open: Arc::default(),
        }
    }

    fn request(correlation: &str) -> AuditEntry {
        AuditEntry::request(
            "registry.test.audit/v2",
            correlation,
            json!({"operationId": "read", "outcome": null}),
        )
    }

    fn current_format_line(correlation: &str) -> String {
        request(correlation).to_line().expect("line")
    }

    /// Every name shaped like a sealed segment of `path`, oldest first.
    fn sealed_segments(path: &Path) -> Result<Vec<(u64, PathBuf)>, AuditError> {
        AuditSegments::new(path).segment_names(usize::MAX)
    }

    fn recorded_torn_recoveries(path: &Path) -> Vec<(PathBuf, u64)> {
        TORN_RECOVERIES
            .lock()
            .expect("torn recoveries")
            .iter()
            .filter(|(active, _, _)| active == path)
            .map(|(_, side, bytes)| (side.clone(), *bytes))
            .collect()
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

    /// Seed `path` with one accepted entry followed by `torn`, the part of a
    /// later entry an interrupted write left, and return the accepted bytes.
    async fn seed_torn_tail(destination: &FileDestination, torn: &[u8]) -> Vec<u8> {
        let path = destination.path().to_path_buf();
        let writer = AuditWriter::open(AuditDestination::File(destination.clone()))
            .await
            .expect("open");
        writer.append(request("accepted")).await.expect("append");
        drop(writer);
        let accepted = fs::read(&path).expect("read accepted entry");
        OpenOptions::new()
            .append(true)
            .open(&path)
            .and_then(|mut file| file.write_all(torn))
            .expect("partial entry");
        accepted
    }

    #[tokio::test]
    async fn restart_moves_a_torn_final_line_to_an_owner_only_side_file() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        // A failed write or process interruption can leave only part of the
        // next entry. Restart must not join a later accepted entry to it.
        let torn = b"{\"schema\":\"registry.test.audit/v2\",\"corr";
        let accepted = seed_torn_tail(&destination, torn).await;

        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("a torn final line is recovered at open");
        let side = AuditSegments::new(&path).torn_line();
        assert_eq!(
            side,
            directory.path().join("audit").join("audit.jsonl.torn")
        );
        assert_eq!(fs::read(&side).expect("side file"), torn);
        let mode = fs::metadata(&side).expect("side file").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(fs::read(&path).expect("active file"), accepted);
        assert_eq!(
            recorded_torn_recoveries(&path),
            [(side.clone(), torn.len() as u64)]
        );

        writer.append(request("after")).await.expect("append");
        let entries = lines(&path);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["correlation"], "accepted");
        assert_eq!(entries[1]["correlation"], "after");
    }

    #[tokio::test]
    async fn a_file_that_is_only_a_torn_line_is_emptied_into_the_side_file() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        let torn = b"{\"eventId\":\"5b1b";
        fs::write(&path, torn).expect("torn file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");

        AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("a torn first line is recovered at open");
        assert_eq!(
            fs::read(AuditSegments::new(&path).torn_line()).expect("side"),
            torn
        );
        assert!(fs::read(&path).expect("active file").is_empty());
    }

    #[tokio::test]
    async fn restart_leaves_a_clean_file_and_creates_no_side_file() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let writer = AuditWriter::open(AuditDestination::File(destination.clone()))
            .await
            .expect("open");
        writer.append(request("before")).await.expect("append");
        drop(writer);
        let before = fs::read(&path).expect("read before restart");

        let _writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("reopen complete stream");
        assert_eq!(fs::read(&path).expect("read after restart"), before);
        assert!(!AuditSegments::new(&path).torn_line().exists());
        assert!(recorded_torn_recoveries(&path).is_empty());
    }

    #[tokio::test]
    async fn an_existing_side_file_is_never_overwritten() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        seed_torn_tail(&destination, b"{\"schema\":").await;
        let side = AuditSegments::new(&path).torn_line();
        fs::write(&side, b"an earlier torn line").expect("earlier side file");
        fs::set_permissions(&side, fs::Permissions::from_mode(0o600)).expect("mode");
        let before = fs::read(&path).expect("read before restart");

        destination
            .check_writable()
            .expect_err("check refuses a side file holding other bytes");
        let error = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect_err("open refuses a side file holding other bytes");
        assert!(
            matches!(error, AuditError::Io(ref error) if error.kind() == ErrorKind::AlreadyExists)
        );
        assert_eq!(
            error.operator_description(),
            "the audit file could not be opened: audit file has an incomplete final entry and \
             its torn-line side file `<audit.path>.torn` already holds other bytes; archive the \
             side file and restart"
        );
        assert_eq!(fs::read(&side).expect("side file"), b"an earlier torn line");
        assert_eq!(fs::read(&path).expect("read after restart"), before);
        assert!(recorded_torn_recoveries(&path).is_empty());
    }

    #[tokio::test]
    async fn a_side_file_already_holding_the_torn_line_finishes_the_recovery() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let torn = b"{\"schema\":";
        let accepted = seed_torn_tail(&destination, torn).await;
        // A crash after the copy was synced but before the truncation leaves
        // the same bytes in both places.
        let side = AuditSegments::new(&path).torn_line();
        fs::write(&side, torn).expect("copied side file");
        fs::set_permissions(&side, fs::Permissions::from_mode(0o600)).expect("mode");

        destination
            .check_writable()
            .expect("check accepts the copy");
        AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("open finishes the recovery");
        assert_eq!(fs::read(&side).expect("side file"), torn);
        assert_eq!(fs::read(&path).expect("active file"), accepted);
    }

    #[tokio::test]
    async fn a_torn_tail_longer_than_any_entry_is_refused_unchanged() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        seed_torn_tail(&destination, &vec![b'x'; MAX_ENTRY_BYTES]).await;
        let before = fs::read(&path).expect("read before restart");

        destination
            .check_writable()
            .expect_err("check refuses a tail no write of this writer left");
        let error = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect_err("open refuses a tail no write of this writer left");
        assert_eq!(
            error.operator_description(),
            "the audit file could not be opened: audit file ends in more bytes without a newline \
             than any entry holds; archive it and restart with a fresh path"
        );
        assert_eq!(fs::read(&path).expect("read after restart"), before);
        assert!(!AuditSegments::new(&path).torn_line().exists());
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

    #[test]
    fn an_owner_masking_umask_still_creates_usable_audit_files() {
        const CHILD: &str = "REGISTRY_AUDIT_UMASK_CHILD";
        // The umask is process wide, so the check runs in a child process
        // rather than beside the other tests.
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "writer::tests::an_owner_masking_umask_still_creates_usable_audit_files",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .status()
                .expect("child test");
            assert!(status.success(), "child test failed");
            return;
        }
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        fs::create_dir(path.parent().expect("parent")).expect("audit directory");
        fs::set_permissions(
            path.parent().expect("parent"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("owner-only audit directory");
        let previous = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o777));

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let writer = AuditWriter::open(AuditDestination::File(destination))
                    .await
                    .expect("open");
                writer.append(request("req-1")).await.expect("append");
                assert!(writer.ready().await);
            });
        // Files the child writes at exit, such as coverage profiles, must
        // stay readable by the parent.
        rustix::process::umask(previous);
        assert_eq!(lines(&path).len(), 1);
    }

    #[test]
    fn creating_the_audit_directory_syncs_the_parent_of_each_created_directory() {
        let directory = directory();
        let base = directory.path().to_path_buf();
        let target = base.join("a").join("b").join("c");
        let mut synced = Vec::new();
        create_directory_with(&target, |parent| {
            assert!(parent
                .join(
                    target
                        .strip_prefix(parent)
                        .expect("an ancestor of the target")
                        .components()
                        .next()
                        .expect("a created child")
                )
                .is_dir());
            synced.push(parent.to_path_buf());
            Ok(())
        })
        .expect("created");
        assert!(target.is_dir());
        assert_eq!(
            synced,
            [base.clone(), base.join("a"), base.join("a").join("b")]
        );
    }

    #[test]
    fn an_intermediate_directory_won_by_a_concurrent_creator_is_validated() {
        // Another account creates the next missing level between the scan
        // and the create: once as a group- and world-writable directory, once
        // as a symlink to a directory. Each is refused like a pre-existing
        // unsafe directory, and nothing is created below it.
        for raced_kind in ["writable", "symlink"] {
            let directory = directory();
            let base = directory.path().to_path_buf();
            let raced = base.join("a").join("b");
            let target = raced.join("c");
            let elsewhere = base.join("elsewhere");
            fs::create_dir(&elsewhere).expect("dir");
            let refused = create_directory_with(&target, |parent| {
                if parent == base {
                    if raced_kind == "writable" {
                        fs::create_dir(&raced).expect("raced dir");
                        fs::set_permissions(&raced, fs::Permissions::from_mode(0o777))
                            .expect("mode");
                    } else {
                        std::os::unix::fs::symlink(&elsewhere, &raced).expect("raced symlink");
                    }
                }
                Ok(())
            });
            let error = refused.expect_err(raced_kind);
            assert!(
                matches!(&error, AuditError::Io(error) if error.kind() == ErrorKind::PermissionDenied),
                "{raced_kind}: {error:?}"
            );
            assert!(fs::symlink_metadata(&target).is_err(), "{raced_kind}");
            assert!(
                fs::symlink_metadata(elsewhere.join("c")).is_err(),
                "{raced_kind}"
            );
        }
    }

    #[tokio::test]
    async fn a_missing_directory_below_an_ancestor_it_cannot_list_is_refused() {
        if rustix::process::geteuid().is_root() {
            eprintln!("skipped: root lists every directory");
            return;
        }
        let directory = directory();
        let unlistable = directory.path().join("unlistable");
        fs::create_dir(&unlistable).expect("dir");
        // The writer opens the ancestor to sync the directory it creates.
        fs::set_permissions(&unlistable, fs::Permissions::from_mode(0o300)).expect("mode");
        let destination =
            FileDestination::new(unlistable.join("audit").join("audit.jsonl")).expect("absolute");
        let refused = destination.check_writable();
        let opened = AuditWriter::open(AuditDestination::File(destination)).await;
        fs::set_permissions(&unlistable, fs::Permissions::from_mode(0o700)).expect("restore");
        opened.expect_err("the writer cannot sync the ancestor");
        refused.expect_err("ancestor cannot be listed");
    }

    #[test]
    fn an_owner_masking_umask_still_creates_usable_audit_directories() {
        const CHILD: &str = "REGISTRY_AUDIT_UMASK_DIRECTORY_CHILD";
        // The umask is process wide, so the check runs in a child process
        // rather than beside the other tests.
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "writer::tests::an_owner_masking_umask_still_creates_usable_audit_directories",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .status()
                .expect("child test");
            assert!(status.success(), "child test failed");
            return;
        }
        let directory = directory();
        let path = directory
            .path()
            .join("audit")
            .join("service")
            .join("audit.jsonl");
        let destination = FileDestination::new(path.clone()).expect("absolute path");
        let previous = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o777));

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let writer = AuditWriter::open(AuditDestination::File(destination))
                    .await
                    .expect("open");
                writer.append(request("req-1")).await.expect("append");
                assert!(writer.ready().await);
            });
        // Files the child writes at exit, such as coverage profiles, must
        // stay readable by the parent.
        rustix::process::umask(previous);
        assert_eq!(lines(&path).len(), 1);
        for created in [
            directory.path().join("audit"),
            directory.path().join("audit").join("service"),
        ] {
            let mode = fs::metadata(&created)
                .expect("directory")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "{}", created.display());
        }
    }

    #[tokio::test]
    async fn a_change_during_the_write_refuses_the_append() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let hook_path = path.clone();
        let hook: SyncHook = Arc::new(move || {
            fs::OpenOptions::new()
                .append(true)
                .open(&hook_path)
                .and_then(|mut file| file.write_all(b"{}\n"))
        });
        let writer = open_with_hook(destination, hook).await;

        let refused = writer.append(request("req-1")).await.expect_err("refused");
        assert_eq!(refused.reason(), AuditUnavailableReason::WriteFailed);
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
        // `role` is `None` for the service's own destination: whoever holds
        // this lock can only be another instance of the service itself.
        assert!(
            matches!(second, AuditError::SinkLocked { role: None, .. }),
            "{second:?}"
        );
    }

    #[tokio::test]
    async fn a_second_companion_writer_on_the_same_role_names_that_role() {
        let directory = directory();
        let destination = AuditDestination::File(file_destination(&directory))
            .for_process("caseworkctl")
            .expect("companion destination");
        let _first = AuditWriter::open(destination.clone())
            .await
            .expect("first companion writer");
        let second = AuditWriter::open(destination)
            .await
            .expect_err("second companion writer");
        // The lock is on the companion sibling file, so only another
        // `caseworkctl` invocation can be holding it, never the service.
        assert!(
            matches!(
                second,
                AuditError::SinkLocked { role: Some(ref role), .. } if role == "caseworkctl"
            ),
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
    async fn rotation_refuses_to_seal_a_replaced_active_file() {
        let directory = directory();
        let destination = file_destination(&directory)
            .with_rotate_bytes(MIN_AUDIT_ROTATE_BYTES)
            .expect("rotation");
        let path = destination.path().to_path_buf();
        let hook_path = path.clone();
        let syncs = Arc::new(AtomicUsize::new(0));
        let hook_syncs = Arc::clone(&syncs);
        // The second sync is the one rotation takes before sealing; replace
        // the active path there, while the writer still holds the original.
        let hook: SyncHook = Arc::new(move || {
            if hook_syncs.fetch_add(1, Ordering::SeqCst) == 1 {
                fs::rename(&hook_path, hook_path.with_file_name("displaced.jsonl"))?;
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&hook_path)?;
            }
            Ok(())
        });
        let writer = open_with_hook(destination, hook).await;
        let padding = "x".repeat(700 * 1024);
        let entry = |correlation: &str| {
            AuditEntry::request("schema/v2", correlation, json!({"padding": padding}))
        };

        writer.append(entry("req-1")).await.expect("first append");
        let refused = writer.append(entry("req-2")).await.expect_err("refused");
        assert_eq!(refused.reason(), AuditUnavailableReason::WriteFailed);
        assert!(!writer.ready().await);
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
    async fn rotation_keeps_the_segment_it_seals_after_a_quiet_period() {
        let directory = directory();
        let destination = file_destination(&directory)
            .with_rotate_bytes(MIN_AUDIT_ROTATE_BYTES)
            .expect("rotation")
            .with_retain_days(1)
            .expect("retention");
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        let filler = format!("{{\"padding\":\"{}\"}}\n", "x".repeat(1000));
        let seeded = usize::try_from(MIN_AUDIT_ROTATE_BYTES).expect("size") / filler.len();
        // The first line must be current format; only it is checked at open,
        // and the rest are filler this test does not otherwise inspect.
        let mut content = current_format_line("seed");
        content.push_str(&filler.repeat(seeded - 1));
        fs::write(&path, content).expect("nearly full active file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        // The active file was last written before the retention period.
        File::options()
            .write(true)
            .open(&path)
            .and_then(|handle| {
                handle.set_modified(SystemTime::now() - Duration::from_secs(3 * SECONDS_PER_DAY))
            })
            .expect("age active file");

        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("open");
        writer
            .append(AuditEntry::request(
                "schema/v2",
                "req-1",
                json!({"padding": "x".repeat(4096)}),
            ))
            .await
            .expect("append rotates");

        let sealed = sealed_segments(&path).expect("sealed");
        assert_eq!(
            sealed.len(),
            1,
            "the segment sealed by this rotation is kept"
        );
        assert_eq!(lines(&sealed[0].1).len(), seeded);
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
    fn a_blocked_stream_append_does_not_stall_other_runtime_work() {
        struct BlockingSink {
            entered: std::sync::mpsc::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
        }

        impl Write for BlockingSink {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.entered.send(()).expect("write entered");
                self.release.recv().expect("write released");
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let (entered, write_entered) = std::sync::mpsc::channel();
        let (release, write_released) = std::sync::mpsc::channel();
        let (other_done, other_finished) = std::sync::mpsc::channel();

        // Drive the writer from a current-thread runtime on its own OS
        // thread, so this test's own assertions cannot become part of the
        // stall it is checking for.
        let runtime_thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("current-thread runtime");
            runtime.block_on(async move {
                let writer = AuditWriter::from_line_sink(Box::new(BlockingSink {
                    entered,
                    release: write_released,
                }));
                let blocked = tokio::spawn({
                    let writer = writer.clone();
                    async move { writer.append(request("blocked")).await }
                });
                tokio::spawn(async move {
                    other_done.send(()).expect("other task signaled");
                });
                blocked.await.expect("join").expect("append");
            });
        });

        write_entered
            .recv_timeout(Duration::from_secs(5))
            .expect("the blocked write started");
        // A current-thread runtime has exactly one worker: the other task can
        // only complete here if the stream append runs off that worker.
        other_finished
            .recv_timeout(Duration::from_millis(200))
            .expect("another task made progress while the stream append was blocked");
        release.send(()).expect("release the blocked write");
        runtime_thread.join().expect("runtime thread joined");
    }

    #[test]
    fn a_path_that_does_not_end_in_a_file_name_is_refused() {
        for path in [
            "/",
            "//",
            "/var/lib/audit/events.jsonl/",
            "/var/lib/audit/.",
        ] {
            assert_eq!(
                FileDestination::new(path),
                Err(AuditDestinationError::NoFileName),
                "{path:?}"
            );
        }
        assert!(FileDestination::new("/var/lib/./audit/.events.jsonl").is_ok());
    }

    #[tokio::test]
    async fn a_file_name_leaves_room_for_the_longest_sibling_the_writer_names() {
        let directory = directory();
        let longest = "a".repeat(MAX_AUDIT_FILE_NAME_BYTES);
        let too_long = "a".repeat(MAX_AUDIT_FILE_NAME_BYTES + 1);
        assert_eq!(
            FileDestination::new(directory.path().join(&too_long)),
            Err(AuditDestinationError::FileNameTooLong {
                maximum: MAX_AUDIT_FILE_NAME_BYTES
            })
        );
        let service = AuditDestination::File(
            FileDestination::new(directory.path().join(&longest)).expect("longest"),
        );
        // A process role lengthens the name by the role and its separator.
        assert_eq!(
            service.for_process("bregctl"),
            Err(AuditDestinationError::FileNameTooLong {
                maximum: MAX_AUDIT_FILE_NAME_BYTES - ".bregctl".len()
            })
        );
        let shorter = "a".repeat(MAX_AUDIT_FILE_NAME_BYTES - ".bregctl".len());
        AuditDestination::File(FileDestination::new(directory.path().join(shorter)).expect("fits"))
            .for_process("bregctl")
            .expect("the role still fits");

        // The longest accepted name still rotates on a 255-byte name limit.
        let AuditDestination::File(file) = service else {
            unreachable!()
        };
        let path = file.path().to_path_buf();
        let writer = AuditWriter::open(AuditDestination::File(
            file.with_rotate_bytes(MIN_AUDIT_ROTATE_BYTES)
                .expect("rotation"),
        ))
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
                .expect("append across a rotation");
        }
        assert!(!sealed_segments(&path).expect("sealed").is_empty());
    }

    #[test]
    fn the_schema_path_pattern_accepts_exactly_the_file_destination_paths() {
        let pattern = regex::Regex::new(ABSOLUTE_AUDIT_PATH_PATTERN).expect("pattern compiles");
        let segments = ["a", ".", "..", "...", ".a", "..a", "a..", "a.b", " "];
        let mut paths = vec![String::new(), "/".to_owned(), "//".to_owned()];
        for first in segments {
            paths.push(first.to_owned());
            paths.push(format!("/{first}"));
            paths.push(format!("/{first}/"));
            for second in segments {
                paths.push(format!("/{first}/{second}"));
                paths.push(format!("/{first}//{second}/"));
                paths.push(format!("{first}/{second}"));
            }
        }
        for path in paths {
            assert_eq!(
                pattern.is_match(&path),
                FileDestination::new(&path).is_ok(),
                "{path:?}"
            );
        }
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
        assert_eq!(
            AuditDestination::from_settings(
                AuditDestinationKind::File,
                Some(PathBuf::from("/var/lib/audit/../tmp/audit.jsonl")),
                None,
                None
            ),
            Err(AuditDestinationError::InvalidPathComponent)
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

    #[tokio::test]
    async fn check_writable_refuses_a_directory_the_writer_cannot_list() {
        let directory = directory();
        let destination = file_destination(&directory);
        let parent = destination.path().parent().expect("parent").to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&parent)
            .expect("audit directory");
        // Opening applies retention, which lists the directory.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o300)).expect("mode");
        let refused = destination.check_writable();
        let opened = AuditWriter::open(AuditDestination::File(destination)).await;
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).expect("restore");
        opened.expect_err("the writer cannot list the directory");
        refused.expect_err("unlistable audit directory");
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
        // Every append reopens the lock for read to check it is still pinned.
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o200)).expect("mode");
        destination.check_writable().expect_err("write-only lock");
        fs::remove_file(&lock).expect("remove lock");
        std::os::unix::fs::symlink(directory.path().join("elsewhere"), &lock).expect("symlink");
        destination.check_writable().expect_err("symlinked lock");
    }

    #[test]
    fn check_writable_accepts_a_torn_final_line_without_changing_anything() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        let entry = current_format_line("existing");
        fs::write(&path, &entry).expect("file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        destination.check_writable().expect("complete final entry");
        fs::write(&path, format!("{entry}{{")).expect("torn file");
        destination
            .check_writable()
            .expect("a torn final line the writer would recover");
        assert_eq!(
            fs::read(&path).expect("active file"),
            format!("{entry}{{").as_bytes()
        );
        assert!(!AuditSegments::new(&path).torn_line().exists());
    }

    #[tokio::test]
    async fn a_torn_file_in_another_format_is_refused_before_anything_moves() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        let content = "{\"envelope_id\":\"01J000000000000000000000\"}\n{\"envelope_id\"";
        fs::write(&path, content).expect("old-format file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect_err("leftover journal with a torn tail");
        assert_eq!(fs::read_to_string(&path).expect("active file"), content);
        assert!(!AuditSegments::new(&path).torn_line().exists());
    }

    #[test]
    fn check_writable_refuses_a_file_whose_first_entry_is_not_current_format() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        // Shape of an entry written by the pre-simplification hash-chained
        // writer (`AuditEnvelope` in `crates/registry-platform-audit/src/lib.rs`
        // on `origin/main`): `envelope_id`/`prev_hash`/`record_hash`, none of
        // which this writer's `eventId`/`schema`/`phase`/`correlation` shape has.
        fs::write(
            &path,
            "{\"envelope_id\":\"01J000000000000000000000\",\"timestamp_unix_ms\":0,\
             \"prev_hash\":null,\"record\":{},\"record_hash\":\"sha256:00\"}\n",
        )
        .expect("old-format file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        destination
            .check_writable()
            .expect_err("leftover hash-chained journal");

        fs::write(&path, "{}\n").expect("unrelated shape");
        destination
            .check_writable()
            .expect_err("first entry missing the current format's fields");
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

        let dangling = directory.path().join("dangling");
        std::os::unix::fs::symlink(directory.path().join("absent"), &dangling).expect("symlink");
        FileDestination::new(dangling.join("audit").join("audit.jsonl"))
            .expect("absolute")
            .check_writable()
            .expect_err("ancestor is a dangling symlink");

        let linked_file = directory.path().join("linked-file");
        std::os::unix::fs::symlink(&file, &linked_file).expect("symlink");
        FileDestination::new(linked_file.join("audit").join("audit.jsonl"))
            .expect("absolute")
            .check_writable()
            .expect_err("ancestor links to a regular file");

        let real = directory.path().join("real");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&real)
            .expect("dir");
        let linked_directory = directory.path().join("linked-directory");
        std::os::unix::fs::symlink(&real, &linked_directory).expect("symlink");
        FileDestination::new(linked_directory.join("audit").join("audit.jsonl"))
            .expect("absolute")
            .check_writable()
            .expect("the writer creates the directory through a linked ancestor");
    }

    #[test]
    fn check_writable_refuses_to_create_below_an_ancestor_it_cannot_search() {
        if rustix::process::geteuid().is_root() {
            eprintln!("skipped: root searches every directory");
            return;
        }
        let directory = directory();
        let write_only = directory.path().join("write-only");
        fs::create_dir(&write_only).expect("dir");
        fs::set_permissions(&write_only, fs::Permissions::from_mode(0o200)).expect("mode");
        let direct = require_creatable_below(&write_only);
        let refused = FileDestination::new(write_only.join("audit").join("audit.jsonl"))
            .expect("absolute")
            .check_writable();
        fs::set_permissions(&write_only, fs::Permissions::from_mode(0o700)).expect("restore");
        direct.expect_err("mkdir below the ancestor needs search permission on it");
        refused.expect_err("ancestor is writable but cannot be searched");
    }

    #[tokio::test]
    async fn a_missing_directory_is_refused_only_below_a_world_writable_non_sticky_ancestor() {
        // Any account could swap the directory the writer creates in a
        // world-writable, non-sticky ancestor. In a sticky one, like `/tmp`,
        // only the entry's owner can rename it, and a group-writable one,
        // like `/var/log`, admits only accounts the host trusts with its logs.
        for (mode, accepted) in [(0o777, false), (0o1777, true), (0o775, true)] {
            let directory = directory();
            let shared = directory.path().join("shared");
            fs::create_dir(&shared).expect("dir");
            fs::set_permissions(&shared, fs::Permissions::from_mode(mode)).expect("mode");
            let destination =
                FileDestination::new(shared.join("audit").join("audit.jsonl")).expect("absolute");
            let checked = destination.check_writable();
            let opened = AuditWriter::open(AuditDestination::File(destination)).await;
            if accepted {
                checked.expect("sticky or group-writable ancestor");
                opened.expect("sticky or group-writable ancestor");
                assert!(shared.join("audit").is_dir());
            } else {
                let error = checked.expect_err("non-sticky shared ancestor");
                assert!(
                    matches!(&error, AuditError::Io(error) if error.kind() == ErrorKind::PermissionDenied),
                    "{error:?}"
                );
                assert!(
                    error.operator_description().contains(
                        "create the audit directory yourself, owned by the service user, mode 0700"
                    ),
                    "the refusal names the fix: {error:?}"
                );
                opened.expect_err("non-sticky shared ancestor");
                assert!(
                    fs::symlink_metadata(shared.join("audit")).is_err(),
                    "nothing is created below a non-sticky shared ancestor"
                );
            }
        }
    }

    #[tokio::test]
    async fn rotation_after_every_sealed_segment_expired_uses_a_fresh_sequence() {
        let directory = directory();
        let destination = file_destination(&directory)
            .with_rotate_bytes(MIN_AUDIT_ROTATE_BYTES)
            .expect("rotation")
            .with_retain_days(1)
            .expect("retention");
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        // Every sealed segment has aged past retention while the service was
        // stopped, so the first open deletes all of them.
        let old = SystemTime::now() - Duration::from_secs(3 * SECONDS_PER_DAY);
        for sequence in [1, 2, 3] {
            let sealed = segment_path(&path, sequence);
            fs::write(&sealed, "{}\n").expect("seed");
            fs::set_permissions(&sealed, fs::Permissions::from_mode(0o600)).expect("mode");
            File::options()
                .write(true)
                .open(&sealed)
                .and_then(|handle| handle.set_modified(old))
                .expect("age file");
        }
        let first = AuditWriter::open(AuditDestination::File(destination.clone()))
            .await
            .expect("open");
        assert!(sealed_segments(&path).expect("sealed").is_empty());
        drop(first);

        // A second restart finds no sealed segment at all.
        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("reopen");
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
        assert_eq!(sequences.first(), Some(&4), "{sequences:?}");
    }

    #[tokio::test]
    async fn a_malformed_or_shared_sequence_file_is_refused() {
        for (content, mode) in [("not a number\n", 0o600), ("4\n", 0o644)] {
            let directory = directory();
            let destination = file_destination(&directory);
            let path = destination.path().to_path_buf();
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path.parent().expect("parent"))
                .expect("audit directory");
            let sequence = sequence_path(&path);
            fs::write(&sequence, content).expect("seed");
            fs::set_permissions(&sequence, fs::Permissions::from_mode(mode)).expect("mode");
            destination
                .check_writable()
                .expect_err("check refuses the sequence file");
            AuditWriter::open(AuditDestination::File(destination))
                .await
                .expect_err("open refuses the sequence file");
        }
    }

    /// Seal `sequence` at `path` with a last modification `age_days` ago.
    fn seed_segment(path: &Path, sequence: u64, age_days: u64) -> PathBuf {
        let segment = segment_path(path, sequence);
        fs::write(&segment, current_format_line("sealed")).expect("segment");
        fs::set_permissions(&segment, fs::Permissions::from_mode(0o600)).expect("mode");
        File::options()
            .write(true)
            .open(&segment)
            .and_then(|handle| {
                handle.set_modified(
                    SystemTime::now() - Duration::from_secs(age_days * SECONDS_PER_DAY),
                )
            })
            .expect("age segment");
        segment
    }

    #[tokio::test]
    async fn retention_deletes_only_the_oldest_run_of_expired_segments() {
        let directory = directory();
        let destination = file_destination(&directory)
            .with_retain_days(1)
            .expect("retention");
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        let first = seed_segment(&path, 1, 3);
        let second = seed_segment(&path, 2, 0);
        // A later segment whose modification time is older, as a copy or a
        // restore can leave it, must not open a gap in the sealed sequence.
        let third = seed_segment(&path, 3, 3);
        let fourth = seed_segment(&path, 4, 0);

        let _writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("open");

        assert!(!first.exists(), "the oldest expired segment is deleted");
        for kept in [&second, &third, &fourth] {
            assert!(kept.exists(), "{} deleted out of order", kept.display());
        }
    }

    #[tokio::test]
    async fn a_retention_failure_neither_refuses_open_nor_stops_rotation() {
        let directory = directory();
        let destination = file_destination(&directory)
            .with_rotate_bytes(MIN_AUDIT_ROTATE_BYTES)
            .expect("rotation")
            .with_retain_days(1)
            .expect("retention");
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        let expired = seed_segment(&path, 1, 3);
        let filler = format!("{{\"padding\":\"{}\"}}\n", "x".repeat(1000));
        let seeded = usize::try_from(MIN_AUDIT_ROTATE_BYTES).expect("size") / filler.len();
        let mut content = current_format_line("seed");
        content.push_str(&filler.repeat(seeded - 1));
        fs::write(&path, content).expect("nearly full active file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        refuse_retention(&path);

        let writer = AuditWriter::open(AuditDestination::File(destination.clone()))
            .await
            .expect("a retention failure does not refuse open");
        assert!(expired.exists());
        writer
            .append(AuditEntry::request(
                "schema/v2",
                "req-1",
                json!({"padding": "x".repeat(4096)}),
            ))
            .await
            .expect("a retention failure does not refuse the rotating append");
        assert_eq!(sealed_segments(&path).expect("sealed").len(), 2);
        writer
            .append(request("after-rotation"))
            .await
            .expect("the writer keeps accepting entries");
        assert!(expired.exists());
        drop(writer);

        allow_retention(&path);
        let _writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("reopen");
        assert!(
            !expired.exists(),
            "the next pass deletes the expired segment"
        );
    }

    /// Fill the active file at `path` to just under the minimum rotation
    /// size, so the next padded append rotates it.
    fn seed_nearly_full_active(path: &Path) {
        let filler = format!("{{\"padding\":\"{}\"}}\n", "x".repeat(1000));
        let seeded = usize::try_from(MIN_AUDIT_ROTATE_BYTES).expect("size") / filler.len();
        // Only the first line is checked at open, so it alone is current
        // format and the rest is filler.
        let mut content = current_format_line("seed");
        content.push_str(&filler.repeat(seeded - 1));
        fs::write(path, content).expect("nearly full active file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
    }

    fn rotating_entry(correlation: &str) -> AuditEntry {
        AuditEntry::request(
            "schema/v2",
            correlation,
            json!({"padding": "x".repeat(4096)}),
        )
    }

    #[tokio::test]
    async fn a_restart_after_every_sealed_segment_was_shipped_does_not_reuse_a_sequence() {
        let directory = directory();
        let destination = file_destination(&directory)
            .with_rotate_bytes(MIN_AUDIT_ROTATE_BYTES)
            .expect("rotation");
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        seed_nearly_full_active(&path);
        let writer = AuditWriter::open(AuditDestination::File(destination.clone()))
            .await
            .expect("open");
        writer
            .append(rotating_entry("req-1"))
            .await
            .expect("append rotates");
        drop(writer);
        // A shipper takes every sealed segment before the restart.
        fs::remove_file(segment_path(&path, 1)).expect("ship the sealed segment");

        seed_nearly_full_active(&path);
        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("reopen");
        writer
            .append(rotating_entry("req-2"))
            .await
            .expect("append rotates");
        assert_eq!(
            sealed_segments(&path)
                .expect("sealed")
                .into_iter()
                .map(|(sequence, _)| sequence)
                .collect::<Vec<_>>(),
            [2],
            "a shipped sequence is never sealed again"
        );
    }

    #[tokio::test]
    async fn rotation_carries_on_when_the_sealed_segment_is_shipped_at_once() {
        let directory = directory();
        let destination = file_destination(&directory)
            .with_rotate_bytes(MIN_AUDIT_ROTATE_BYTES)
            .expect("rotation");
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        seed_nearly_full_active(&path);
        ship_on_seal(&path);
        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("open");

        writer
            .append(rotating_entry("req-1"))
            .await
            .expect("a shipped sealed segment does not stop the rotating append");
        assert!(!segment_path(&path, 1).exists());
        assert!(writer.ready().await);
        writer
            .append(request("after-rotation"))
            .await
            .expect("the writer keeps accepting entries");
    }

    #[tokio::test]
    async fn reopening_an_existing_destination_syncs_its_directory() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let parent = path.parent().expect("parent").to_path_buf();
        drop(
            AuditWriter::open(AuditDestination::File(destination.clone()))
                .await
                .expect("first open creates the lock and active file"),
        );
        forget_directory_syncs(&parent);

        let _writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("reopen");
        // A crash after creating the names but before the directory sync
        // leaves them undurable; the reopen must sync before acknowledging.
        assert!(directory_synced(&parent));
    }

    #[tokio::test]
    async fn reapplying_the_active_file_mode_does_not_stop_the_writer() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("open");
        writer.append(request("req-1")).await.expect("append");

        // Configuration management re-applying the mode it already has
        // changes only the inode change time.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        fs::set_permissions(lock_path(&path), fs::Permissions::from_mode(0o600))
            .expect("chmod lock");

        assert!(writer.ready().await);
        writer.append(request("req-2")).await.expect("append");
    }

    #[tokio::test]
    async fn a_copy_truncated_active_file_stops_the_writer() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("open");
        writer.append(request("req-1")).await.expect("append");

        fs::copy(&path, path.with_file_name("copied.jsonl")).expect("copy");
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_len(0))
            .expect("truncate");

        assert!(!writer.ready().await);
        let refused = writer.append(request("req-2")).await.expect_err("refused");
        assert_eq!(refused.reason(), AuditUnavailableReason::WriteFailed);
    }

    #[tokio::test]
    async fn an_in_place_rewrite_of_the_active_file_stops_the_writer() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("open");
        writer.append(request("req-1")).await.expect("append");
        // Keep the length: only the modification time can show the change.
        std::thread::sleep(Duration::from_millis(20));
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|file| file.write_all_at(b"{", 0))
            .expect("rewrite in place");

        assert!(!writer.ready().await);
    }

    #[tokio::test]
    async fn retention_keeps_another_stream_named_like_a_sealed_segment() {
        let directory = directory();
        let destination = file_destination(&directory)
            .with_retain_days(1)
            .expect("retention");
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        // A stream configured at `<path>.00000001` is an active file with its
        // own lock companion, never a segment this stream sealed. Such a path
        // is now refused as configuration, but a directory may still hold a
        // stream configured before that refusal.
        let other = segment_path(&path, 1);
        assert!(matches!(
            FileDestination::new(&other),
            Err(AuditDestinationError::PathNamesReservedCompanion { .. })
        ));
        for file in [&other, &lock_path(&other)] {
            fs::write(file, current_format_line("other")).expect("other stream");
            fs::set_permissions(file, fs::Permissions::from_mode(0o600)).expect("mode");
        }
        File::options()
            .append(true)
            .open(&other)
            .and_then(|handle| {
                handle.set_modified(SystemTime::now() - Duration::from_secs(3 * SECONDS_PER_DAY))
            })
            .expect("age other stream");

        let _writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("open");
        assert!(other.exists(), "another stream's active file deleted");
    }

    #[test]
    fn a_path_named_like_another_streams_companion_is_refused() {
        let directory = directory();
        let audit = directory.path().join("audit");
        for (name, suffix, companion) in [
            ("events.lock", ".lock", "lock"),
            ("events.seq", ".seq", "sequence companion"),
            ("events.seq.tmp", ".seq.tmp", "temporary sequence companion"),
            ("events.torn", ".torn", "torn-line side file"),
            ("events.00000001", ".<8 digits>", "sealed segment"),
        ] {
            let error = FileDestination::new(audit.join(name)).expect_err(name);
            assert_eq!(
                error,
                AuditDestinationError::PathNamesReservedCompanion {
                    stream: "events".to_owned(),
                    suffix,
                    companion,
                },
                "{name}"
            );
            assert_eq!(
                error.to_string(),
                format!(
                    "audit.path names the {companion} of an audit stream at `events`: a file \
                     name ending in `{suffix}` is reserved for it, and a writer there would \
                     rename or replace this file; choose a file name without that suffix"
                )
            );
            assert_eq!(
                AuditDestination::from_settings(
                    AuditDestinationKind::File,
                    Some(audit.join(name)),
                    None,
                    None,
                ),
                Err(error),
                "{name}"
            );
        }
        for name in [
            "events.locks",
            "events.0000001",
            "events.000000001",
            "events.tmp",
            "events.jsonl",
            ".lock.jsonl",
        ] {
            FileDestination::new(audit.join(name)).expect(name);
        }
    }

    #[test]
    fn a_process_role_cannot_name_the_torn_line_side_file() {
        let directory = directory();
        let bare = AuditDestination::File(
            FileDestination::new(directory.path().join("audit").join("journal")).expect("file"),
        );
        assert_eq!(
            bare.for_process("torn"),
            Err(AuditDestinationError::ProcessRoleOverlapsStream)
        );
    }

    #[test]
    fn the_segment_namespace_names_every_file_the_writer_owns() {
        let segments = AuditSegments::new("/var/audit/events.jsonl");
        assert_eq!(segments.active(), Path::new("/var/audit/events.jsonl"));
        assert_eq!(segments.lock(), Path::new("/var/audit/events.jsonl.lock"));
        assert_eq!(
            segments.sequence(),
            Path::new("/var/audit/events.jsonl.seq")
        );
        assert_eq!(
            segments.torn_line(),
            Path::new("/var/audit/events.jsonl.torn")
        );
        assert_eq!(
            segment_path(segments.active(), 7),
            Path::new("/var/audit/events.jsonl.00000007")
        );
        assert_eq!(
            segment_sequence(
                segments.active(),
                Path::new("/var/audit/events.jsonl.00000007")
            ),
            Some(7)
        );
        for other in [
            "/var/audit/events.jsonl.0000007",
            "/var/audit/events.jsonl.lock",
            "/var/audit/other.jsonl.00000007",
        ] {
            assert_eq!(
                segment_sequence(segments.active(), Path::new(other)),
                None,
                "{other}"
            );
        }
        for reserved in [
            "/var/audit/events.jsonl",
            "/var/audit/events.jsonl.lock",
            "/var/audit/events.jsonl.seq",
            "/var/audit/events.jsonl.seq.tmp",
            "/var/audit/events.jsonl.torn",
            "/var/audit/events.jsonl.00000001",
        ] {
            assert!(segments.reserves(Path::new(reserved)), "{reserved}");
        }
        assert!(!segments.reserves(Path::new("/var/audit/events.jsonl.tmp")));
        assert!(!segments.reserves(Path::new("/elsewhere/events.jsonl.00000007")));
    }

    #[test]
    fn the_segment_namespace_lists_sealed_segments_oldest_first() {
        let directory = directory();
        let path = directory.path().join("events.jsonl");
        let segments = AuditSegments::new(&path);
        for name in [
            "events.jsonl",
            "events.jsonl.00000010",
            "events.jsonl.00000002",
            "events.jsonl.0000003",
            "events.jsonl.lock",
            "events.jsonl.torn",
            "other.jsonl.00000001",
            // Another stream configured at a sealed-looking name.
            "events.jsonl.00000005",
            "events.jsonl.00000005.lock",
        ] {
            fs::write(directory.path().join(name), "").expect(name);
        }
        let sealed = segments.sealed(usize::MAX).expect("listing");
        assert_eq!(
            sealed,
            [
                SealedSegment {
                    sequence: 2,
                    path: directory.path().join("events.jsonl.00000002"),
                },
                SealedSegment {
                    sequence: 10,
                    path: directory.path().join("events.jsonl.00000010"),
                },
            ]
        );
        // The bound counts every segment-shaped name the scan meets,
        // including the one left out for its lock companion.
        assert_eq!(segments.sealed(3).expect("within the bound"), sealed);
        segments.sealed(2).expect_err("over the bound");
        // The next sequence passes every sealed-looking name, another
        // stream's included, and the recorded one.
        assert_eq!(segments.next_sequence().expect("next"), 11);
        fs::write(segments.sequence(), "40\n").expect("sequence");
        fs::set_permissions(segments.sequence(), fs::Permissions::from_mode(0o600)).expect("mode");
        assert_eq!(segments.next_sequence().expect("next"), 40);
    }

    #[test]
    fn the_segment_listing_refuses_one_segment_shaped_name_past_the_bound() {
        let directory = directory();
        let path = directory.path().join("events.jsonl");
        let segments = AuditSegments::new(&path);
        for name in [
            "events.jsonl.00000004",
            "events.jsonl.00000001",
            "events.jsonl.00000003",
            // Skipped from the listing, but counted by the bounded scan.
            "events.jsonl.00000002",
            "events.jsonl.00000002.lock",
        ] {
            fs::write(directory.path().join(name), "").expect(name);
        }
        let refused = segments.sealed(3).expect_err("over the bound");
        assert_eq!(
            refused.to_string(),
            AuditError::Io(io::Error::other(
                "audit segment count exceeds the listing bound"
            ))
            .to_string()
        );
        let sequences: Vec<u64> = segments
            .sealed(4)
            .expect("within the bound")
            .into_iter()
            .map(|sealed| sealed.sequence)
            .collect();
        assert_eq!(sequences, [1, 3, 4]);
    }

    #[test]
    fn a_process_role_that_names_a_file_the_stream_owns_is_refused() {
        let directory = directory();
        let bare = AuditDestination::File(
            FileDestination::new(directory.path().join("audit").join("journal")).expect("file"),
        );
        for role in ["lock", "seq", "00000001"] {
            assert_eq!(
                bare.for_process(role),
                Err(AuditDestinationError::ProcessRoleOverlapsStream),
                "{role}"
            );
        }
        bare.for_process("0000001")
            .expect("seven digits name no segment");
        bare.for_process("locks").expect("not a companion name");
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

    #[tokio::test]
    async fn open_refuses_a_lock_companion_it_cannot_reopen_for_read() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        let lock = lock_path(&path);
        fs::write(&lock, "").expect("lock");
        // Every append reopens the lock for read to check it is still pinned,
        // so a write-only lock would stop the writer on its first entry.
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o200)).expect("mode");
        AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect_err("write-only lock");
    }

    #[tokio::test]
    async fn open_refuses_a_leftover_hash_chained_journal_file() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().expect("parent"))
            .expect("audit directory");
        // Shape of an entry written by the pre-simplification hash-chained
        // writer, left behind at this path by an operator who restarted a
        // service here without archiving it first.
        fs::write(
            &path,
            "{\"envelope_id\":\"01J000000000000000000000\",\"timestamp_unix_ms\":0,\
             \"prev_hash\":null,\"record\":{},\"record_hash\":\"sha256:00\"}\n",
        )
        .expect("old-format file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect_err("leftover hash-chained journal");
    }

    const SCHEMA: &str = "registry.test.audit/v2";

    fn unfinished() -> Value {
        json!({"operationId": "read", "outcome": "unfinished"})
    }

    fn buffered() -> (AuditWriter, SharedBuffer) {
        let buffer = SharedBuffer::default();
        (
            AuditWriter::from_line_sink(Box::new(buffer.clone())),
            buffer,
        )
    }

    fn buffered_lines(buffer: &SharedBuffer) -> Vec<Value> {
        String::from_utf8(buffer.0.lock().expect("buffer").clone())
            .expect("utf-8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("json line"))
            .collect()
    }

    /// The lines accepted once every detached unfinished response is
    /// written.
    fn settled_lines(writer: &AuditWriter, buffer: &SharedBuffer) -> Vec<Value> {
        writer.wait_for_detached_entries();
        buffered_lines(buffer)
    }

    fn assert_paired(entries: &[Value], outcome: &str) {
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entries[0]["phase"], "request");
        assert_eq!(entries[1]["phase"], "response");
        assert_eq!(entries[1]["schema"], entries[0]["schema"]);
        assert_eq!(entries[1]["correlation"], entries[0]["correlation"]);
        assert_eq!(entries[1]["record"]["outcome"], outcome);
    }

    #[tokio::test]
    async fn an_answered_request_writes_only_its_responses() {
        let (writer, buffer) = buffered();
        let mut request = writer
            .begin(
                SCHEMA,
                "req-1",
                json!({"operationId": "read"}),
                unfinished(),
            )
            .await
            .expect("request");
        assert_eq!(request.correlation(), "req-1");
        assert!(!request.is_answered());
        request
            .respond(json!({"outcome": "returned"}))
            .await
            .expect("response");
        assert!(request.is_answered());
        request
            .respond(json!({"outcome": "returned"}))
            .await
            .expect("second response");
        drop(request);
        let entries = settled_lines(&writer, &buffer);
        assert_eq!(entries.len(), 3);
        assert!(entries[1..]
            .iter()
            .all(|entry| entry["record"]["outcome"] == "returned"
                && entry["correlation"] == "req-1"
                && entry["schema"] == SCHEMA));
    }

    #[tokio::test]
    async fn a_response_appended_elsewhere_answers_the_open_request() {
        let (writer, buffer) = buffered();
        let request = writer
            .begin(
                SCHEMA,
                "req-1",
                json!({"operationId": "read"}),
                unfinished(),
            )
            .await
            .expect("request");
        writer
            .append(AuditEntry::response(
                SCHEMA,
                "req-1",
                json!({"outcome": "returned"}),
            ))
            .await
            .expect("response");
        assert!(request.is_answered());
        drop(request);
        assert_paired(&settled_lines(&writer, &buffer), "returned");
    }

    #[tokio::test]
    async fn a_response_in_another_schema_does_not_answer_the_request() {
        let (writer, buffer) = buffered();
        let request = writer
            .begin(SCHEMA, "req-1", json!({"operationId": "run"}), unfinished())
            .await
            .expect("request");
        writer
            .append(AuditEntry::response(
                "registry.test.other/v1",
                "req-1",
                json!({"outcome": "refused"}),
            ))
            .await
            .expect("other schema");
        assert!(!request.is_answered());
        drop(request);
        let entries = settled_lines(&writer, &buffer);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2]["schema"], SCHEMA);
        assert_eq!(entries[2]["correlation"], "req-1");
        assert_eq!(entries[2]["record"]["outcome"], "unfinished");
    }

    #[tokio::test]
    async fn one_response_answers_one_of_two_requests_sharing_a_correlation() {
        let (writer, buffer) = buffered();
        let first = writer
            .begin(SCHEMA, "shared", json!({"n": 1}), unfinished())
            .await
            .expect("first");
        let mut second = writer
            .begin(SCHEMA, "shared", json!({"n": 2}), unfinished())
            .await
            .expect("second");
        second
            .respond(json!({"outcome": "returned"}))
            .await
            .expect("second answers itself");
        assert!(!first.is_answered(), "the second's response is its own");
        drop(second);
        drop(first);
        let outcomes: Vec<_> = settled_lines(&writer, &buffer)
            .iter()
            .filter(|entry| entry["phase"] == "response")
            .map(|entry| entry["record"]["outcome"].clone())
            .collect();
        assert_eq!(outcomes, [json!("returned"), json!("unfinished")]);
    }

    #[tokio::test]
    async fn a_request_dropped_unanswered_writes_its_unfinished_response() {
        let (writer, buffer) = buffered();
        let request = writer
            .begin(
                SCHEMA,
                "req-1",
                json!({"operationId": "read"}),
                unfinished(),
            )
            .await
            .expect("request");
        drop(request);
        assert_paired(&settled_lines(&writer, &buffer), "unfinished");
    }

    #[tokio::test]
    async fn an_early_error_return_pairs_the_request() {
        async fn refused(writer: &AuditWriter) -> Result<(), &'static str> {
            let _request = writer
                .begin(
                    SCHEMA,
                    "req-1",
                    json!({"operationId": "read"}),
                    unfinished(),
                )
                .await
                .map_err(|_| "audit")?;
            Err("not found")?;
            Ok(())
        }
        let (writer, buffer) = buffered();
        assert_eq!(refused(&writer).await, Err("not found"));
        assert_paired(&settled_lines(&writer, &buffer), "unfinished");
    }

    #[tokio::test]
    async fn a_refused_response_leaves_the_request_owed() {
        let (writer, buffer) = buffered();
        let mut request = writer
            .begin(
                SCHEMA,
                "req-1",
                json!({"operationId": "read"}),
                unfinished(),
            )
            .await
            .expect("request");
        let refused = request.respond(json!(["not", "an", "object"])).await;
        assert_eq!(
            refused.map_err(|error| error.reason()),
            Err(AuditUnavailableReason::InvalidEntry)
        );
        assert!(!request.is_answered());
        drop(request);
        assert_paired(&settled_lines(&writer, &buffer), "unfinished");
    }

    #[tokio::test]
    async fn an_unfinished_record_that_is_not_an_object_writes_no_request() {
        let (writer, buffer) = buffered();
        let refused = writer
            .begin(
                SCHEMA,
                "req-1",
                json!({"operationId": "read"}),
                json!("gone"),
            )
            .await;
        assert!(refused.is_err());
        assert!(settled_lines(&writer, &buffer).is_empty());
    }

    #[tokio::test]
    async fn a_canceled_operation_pairs_its_request_in_the_file() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let writer = AuditWriter::open(AuditDestination::File(destination))
            .await
            .expect("open");
        let (started, begun) = tokio::sync::oneshot::channel();
        let operation = tokio::spawn({
            let writer = writer.clone();
            async move {
                let _request = writer
                    .begin(
                        SCHEMA,
                        "req-1",
                        json!({"operationId": "read"}),
                        unfinished(),
                    )
                    .await
                    .expect("request");
                started.send(()).expect("signal");
                std::future::pending::<()>().await;
            }
        });
        begun.await.expect("begun");
        operation.abort();
        assert!(operation.await.expect_err("aborted").is_cancelled());
        // A later append is ordered after the queued unfinished response.
        writer
            .append(AuditEntry::response(SCHEMA, "other", json!({})))
            .await
            .expect("later entry");
        let entries = lines(&path);
        assert_paired(&entries[..2], "unfinished");
        assert_eq!(entries[2]["correlation"], "other");
    }

    #[tokio::test]
    async fn a_panicking_operation_pairs_its_request() {
        let (writer, buffer) = buffered();
        let operation = tokio::spawn({
            let writer = writer.clone();
            async move {
                let _request = writer
                    .begin(
                        SCHEMA,
                        "req-1",
                        json!({"operationId": "read"}),
                        unfinished(),
                    )
                    .await
                    .expect("request");
                panic!("handler failed");
            }
        });
        assert!(operation.await.expect_err("panicked").is_panic());
        assert_paired(&settled_lines(&writer, &buffer), "unfinished");
    }

    #[test]
    fn a_command_that_exits_after_an_early_return_pairs_its_request() {
        // An operator command runs on a current-thread runtime and exits as
        // soon as its future returns, before a spawned flush can run.
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let result: Result<(), &str> = runtime.block_on(async move {
            let writer = AuditWriter::open(AuditDestination::File(destination))
                .await
                .expect("open");
            let _request = writer
                .begin(
                    SCHEMA,
                    "req-1",
                    json!({"operationId": "erase"}),
                    unfinished(),
                )
                .await
                .expect("request");
            Err("database unavailable")
        });
        assert_eq!(result, Err("database unavailable"));
        drop(runtime);
        assert_paired(&lines(&path), "unfinished");
    }

    #[test]
    fn a_request_dropped_outside_a_runtime_while_the_file_is_busy_still_pairs() {
        let directory = directory();
        let destination = file_destination(&directory);
        let path = destination.path().to_path_buf();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let (writer, request) = runtime.block_on(async move {
            let writer = AuditWriter::open(AuditDestination::File(destination))
                .await
                .expect("open");
            let request = writer
                .begin(
                    SCHEMA,
                    "req-1",
                    json!({"operationId": "erase"}),
                    unfinished(),
                )
                .await
                .expect("request");
            (writer, request)
        });
        drop(runtime);
        let WriterInner::File(file) = writer.inner.as_ref() else {
            panic!("a file destination");
        };
        let file = Arc::clone(file);
        let (held, holding) = std::sync::mpsc::channel();
        // Another thread holds the file state for longer than any bounded
        // wait while the handle is dropped outside a runtime.
        let holder = std::thread::spawn(move || {
            let _state = file.state.blocking_lock();
            held.send(()).expect("signal");
            std::thread::sleep(Duration::from_millis(200));
        });
        holding.recv().expect("the state is held");
        drop(request);
        holder.join().expect("holder");
        drop(writer);
        assert_paired(&lines(&path), "unfinished");
    }

    #[tokio::test]
    async fn a_stopped_writer_refuses_the_request_and_writes_nothing() {
        let writer = AuditWriter::from_line_sink(Box::new(FailingSink));
        assert!(writer
            .begin(
                SCHEMA,
                "req-1",
                json!({"operationId": "read"}),
                unfinished()
            )
            .await
            .is_err());
        assert!(!writer.ready().await);
    }

    /// A line sink that holds each write until the test releases it.
    #[derive(Clone)]
    struct GatedSink {
        buffer: SharedBuffer,
        open: Arc<(Mutex<bool>, std::sync::Condvar)>,
        entered: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl GatedSink {
        fn new() -> Self {
            Self {
                buffer: SharedBuffer::default(),
                open: Arc::new((Mutex::new(false), std::sync::Condvar::new())),
                entered: Arc::default(),
            }
        }

        fn release(&self) {
            *self.open.0.lock().expect("gate") = true;
            self.open.1.notify_all();
        }

        async fn wait_entered(&self, writes: usize) {
            for _ in 0..500 {
                if self.entered.load(Ordering::SeqCst) >= writes {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("the sink never received write {writes}");
        }
    }

    impl Write for GatedSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.entered.fetch_add(1, Ordering::SeqCst);
            let mut open = self.open.0.lock().expect("gate");
            while !*open {
                open = self.open.1.wait(open).expect("gate");
            }
            drop(open);
            self.buffer.write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The accepted lines once `count` of them arrived.
    async fn lines_eventually(buffer: &SharedBuffer, count: usize) -> Vec<Value> {
        for _ in 0..500 {
            let lines = buffered_lines(buffer);
            if lines.len() >= count {
                return lines;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        buffered_lines(buffer)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_canceled_while_its_entry_is_written_is_still_paired() {
        let sink = GatedSink::new();
        let writer = AuditWriter::from_line_sink(Box::new(sink.clone()));
        let begun = tokio::spawn({
            let writer = writer.clone();
            async move {
                writer
                    .begin(
                        SCHEMA,
                        "req-1",
                        json!({"operationId": "read"}),
                        unfinished(),
                    )
                    .await
            }
        });
        sink.wait_entered(1).await;
        // The caller goes away while its request entry is being written.
        begun.abort();
        sink.release();
        assert_paired(&lines_eventually(&sink.buffer, 2).await, "unfinished");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_response_accepted_after_its_caller_left_is_the_only_answer() {
        let sink = GatedSink::new();
        sink.release();
        let writer = AuditWriter::from_line_sink(Box::new(sink.clone()));
        let request = writer
            .begin(
                SCHEMA,
                "req-1",
                json!({"operationId": "read"}),
                unfinished(),
            )
            .await
            .expect("request");
        *sink.open.0.lock().expect("gate") = false;
        let responding = tokio::spawn(async move {
            let mut request = request;
            request.respond(json!({"outcome": "returned"})).await
        });
        sink.wait_entered(2).await;
        // The caller and its handle go away while the response is written.
        responding.abort();
        sink.release();
        let lines = lines_eventually(&sink.buffer, 2).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        writer.wait_for_detached_entries();
        assert_eq!(buffered_lines(&sink.buffer).len(), 2, "{lines:?}");
        assert_paired(&lines, "returned");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_response_appended_after_its_caller_left_still_answers_the_request() {
        let sink = GatedSink::new();
        sink.release();
        let writer = AuditWriter::from_line_sink(Box::new(sink.clone()));
        let request = writer
            .begin(
                SCHEMA,
                "req-1",
                json!({"operationId": "read"}),
                unfinished(),
            )
            .await
            .expect("request");
        *sink.open.0.lock().expect("gate") = false;
        let appending = tokio::spawn({
            let writer = writer.clone();
            async move {
                writer
                    .append(AuditEntry::response(
                        SCHEMA,
                        "req-1",
                        json!({"outcome": "returned"}),
                    ))
                    .await
            }
        });
        sink.wait_entered(2).await;
        // The caller goes away while the response is written.
        appending.abort();
        sink.release();
        lines_eventually(&sink.buffer, 2).await;
        for _ in 0..500 {
            if request.is_answered() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        drop(request);
        writer.wait_for_detached_entries();
        assert_paired(&buffered_lines(&sink.buffer), "returned");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_dropped_while_an_appended_response_is_written_is_answered_once() {
        let sink = GatedSink::new();
        sink.release();
        let writer = AuditWriter::from_line_sink(Box::new(sink.clone()));
        let request = writer
            .begin(
                SCHEMA,
                "req-1",
                json!({"operationId": "read"}),
                unfinished(),
            )
            .await
            .expect("request");
        *sink.open.0.lock().expect("gate") = false;
        let appending = tokio::spawn({
            let writer = writer.clone();
            async move {
                writer
                    .append(AuditEntry::response(
                        SCHEMA,
                        "req-1",
                        json!({"outcome": "returned"}),
                    ))
                    .await
            }
        });
        sink.wait_entered(2).await;
        // The caller and its handle go away while the appended response is
        // written: that response answers the request, and the drop writes
        // nothing more.
        appending.abort();
        drop(request);
        sink.release();
        lines_eventually(&sink.buffer, 2).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        writer.wait_for_detached_entries();
        let lines = buffered_lines(&sink.buffer);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_paired(&lines, "returned");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_appended_response_skips_a_request_whose_own_response_is_in_flight() {
        let sink = GatedSink::new();
        sink.release();
        let writer = AuditWriter::from_line_sink(Box::new(sink.clone()));
        let first = writer
            .begin(SCHEMA, "shared", json!({"n": 1}), unfinished())
            .await
            .expect("first");
        let second = writer
            .begin(SCHEMA, "shared", json!({"n": 2}), unfinished())
            .await
            .expect("second");
        let first_state = Arc::clone(&first.state);
        *sink.open.0.lock().expect("gate") = false;
        // The first request's own response is being written.
        let responding = tokio::spawn(async move {
            let mut first = first;
            let result = first.respond(json!({"outcome": "returned"})).await;
            (first, result)
        });
        sink.wait_entered(3).await;
        // A response appended elsewhere under the same correlation is meant
        // for the second request, the only one still owed a response.
        let appending = tokio::spawn({
            let writer = writer.clone();
            async move {
                writer
                    .append(AuditEntry::response(
                        SCHEMA,
                        "shared",
                        json!({"outcome": "returned"}),
                    ))
                    .await
            }
        });
        for _ in 0..500 {
            if first_state.lock().expect("state").claimed
                || second.state.lock().expect("state").claimed
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        sink.release();
        let (first, responded) = responding.await.expect("respond task");
        responded.expect("first response");
        appending
            .await
            .expect("append task")
            .expect("appended response");
        assert!(first.is_answered());
        assert!(
            second.is_answered(),
            "the appended response is the second's"
        );
        drop(first);
        drop(second);
        tokio::time::sleep(Duration::from_millis(100)).await;
        writer.wait_for_detached_entries();
        let outcomes: Vec<_> = buffered_lines(&sink.buffer)
            .iter()
            .filter(|entry| entry["phase"] == "response")
            .map(|entry| entry["record"]["outcome"].clone())
            .collect();
        assert_eq!(outcomes, [json!("returned"), json!("returned")]);
    }

    #[tokio::test]
    async fn an_unfinished_record_too_large_to_write_refuses_the_request() {
        let (writer, buffer) = buffered();
        let oversized = json!({"outcome": "unfinished", "padding": "x".repeat(MAX_ENTRY_BYTES)});
        assert!(writer
            .begin(SCHEMA, "req-1", json!({"operationId": "read"}), oversized)
            .await
            .is_err());
        assert!(buffered_lines(&buffer).is_empty());
        assert!(writer.ready().await, "a refused request stops nothing");
    }

    #[test]
    fn dropping_a_request_never_waits_on_a_stalled_stream() {
        let sink = GatedSink::new();
        sink.release();
        let writer = AuditWriter::from_line_sink(Box::new(sink.clone()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let request = runtime
            .block_on(writer.begin(
                SCHEMA,
                "req-1",
                json!({"operationId": "read"}),
                unfinished(),
            ))
            .expect("request");
        *sink.open.0.lock().expect("gate") = false;
        // The stream stalls; the drop must still return to the runtime.
        let started = std::time::Instant::now();
        runtime.block_on(async move { drop(request) });
        assert!(started.elapsed() < Duration::from_secs(1));
        sink.release();
        writer.wait_for_detached_entries();
        assert_paired(&buffered_lines(&sink.buffer), "unfinished");
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_response_claimed_while_its_request_is_dropped_is_the_only_answer() {
        let sink = GatedSink::new();
        sink.release();
        let writer = AuditWriter::from_line_sink(Box::new(sink.clone()));
        let request = writer
            .begin(
                SCHEMA,
                "req-1",
                json!({"operationId": "read"}),
                unfinished(),
            )
            .await
            .expect("request");
        // The drop's first half: it marks the handle dropped and finds no
        // response in flight.
        let in_flight = request.state.lock().is_ok_and(|mut state| {
            state.dropped = true;
            state.in_flight > 0
        });
        assert!(!in_flight);
        // A response appended elsewhere claims the request before the drop
        // settles it.
        *sink.open.0.lock().expect("gate") = false;
        let appending = tokio::spawn({
            let writer = writer.clone();
            async move {
                writer
                    .append(AuditEntry::response(
                        SCHEMA,
                        "req-1",
                        json!({"outcome": "returned"}),
                    ))
                    .await
            }
        });
        sink.wait_entered(2).await;
        // The drop's second half.
        settle_unanswered(
            &writer,
            (SCHEMA.to_owned(), "req-1".to_owned()),
            &request.answered,
            &request.state,
        );
        sink.release();
        appending
            .await
            .expect("append task")
            .expect("the claimed response");
        drop(request);
        tokio::time::sleep(Duration::from_millis(100)).await;
        writer.wait_for_detached_entries();
        let lines = buffered_lines(&sink.buffer);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_paired(&lines, "returned");
    }

    #[test]
    fn a_response_task_dropped_at_runtime_shutdown_leaves_the_request_to_its_handle() {
        let (writer, buffer) = buffered();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let mut request = runtime
            .block_on(writer.begin(
                SCHEMA,
                "req-1",
                json!({"operationId": "read"}),
                unfinished(),
            ))
            .expect("request");
        // The response's task is spawned and never runs: the runtime shuts
        // down first and drops it.
        runtime.block_on(async {
            tokio::select! {
                biased;
                _ = request.respond(json!({"outcome": "returned"})) => {
                    panic!("the response task never ran")
                }
                () = std::future::ready(()) => {}
            }
        });
        drop(runtime);
        drop(request);
        assert_paired(&settled_lines(&writer, &buffer), "unfinished");
    }

    #[test]
    fn an_append_task_dropped_at_runtime_shutdown_leaves_the_request_to_its_handle() {
        let (writer, buffer) = buffered();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let request = runtime
            .block_on(writer.begin(
                SCHEMA,
                "req-1",
                json!({"operationId": "read"}),
                unfinished(),
            ))
            .expect("request");
        // The appended response claims the request, and its task is dropped
        // by the runtime's shutdown before it runs.
        runtime.block_on(async {
            tokio::select! {
                biased;
                _ = writer.append(AuditEntry::response(
                    SCHEMA,
                    "req-1",
                    json!({"outcome": "returned"}),
                )) => panic!("the append task never ran"),
                () = std::future::ready(()) => {}
            }
        });
        drop(runtime);
        drop(request);
        assert_paired(&settled_lines(&writer, &buffer), "unfinished");
    }
}

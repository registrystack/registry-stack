// SPDX-License-Identifier: Apache-2.0
//! Evidence-grade, non-destructive segmented JSONL audit storage.
//!
//! This lives beside the legacy rolling [`super::JsonlFileSink`] so adopters
//! can migrate without changing that sink's retention contract. Rotation seals
//! the active file under an ascending sequence; it never deletes history.

use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use registry_platform_canonical_json::parse_json_strict;

use super::{
    verify_jsonl_lines_with_hasher, AuditChainHasher, AuditEnvelope, AuditError, AuditSink,
    OptionalHashHex,
};

const SEGMENT_SEQUENCE_DIGITS: usize = 8;
const MAX_AUDIT_LINE_BYTES: usize = 1024 * 1024;

/// Full-chain verification result for a non-destructive segmented JSONL sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentedAuditSummary {
    pub segments: usize,
    pub records: usize,
    pub last_hash: Option<[u8; 32]>,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    /// False when a live writer owns the active segment, which cannot be read
    /// safely while an append may be in flight.
    pub active_verified: bool,
}

/// A durable single-writer sink with online, non-destructive size rotation.
///
/// The active file remains at `path`. Rotation renames it to
/// `<path>.<sequence>`, using an ascending zero-padded eight-digit sequence,
/// then opens a fresh active file. The keyed chain continues across the seam.
/// Sealed segments are never deleted or compacted.
pub struct DurableSegmentedJsonlSink {
    path: PathBuf,
    lock_path: PathBuf,
    maximum_file_bytes: u64,
    state: tokio::sync::Mutex<SinkState>,
    healthy: Arc<AtomicBool>,
    lock_fingerprint: FileFingerprint,
    _writer_lock: File,
}

struct SinkState {
    audit_file: File,
    fingerprint: FileFingerprint,
    next_sequence: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl std::fmt::Debug for DurableSegmentedJsonlSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableSegmentedJsonlSink")
            .field("path", &self.path)
            .field("maximum_file_bytes", &self.maximum_file_bytes)
            .field("healthy", &self.healthy.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl DurableSegmentedJsonlSink {
    /// Open an active audit segment and take the process-lifetime writer lock.
    pub fn open(path: impl Into<PathBuf>, maximum_file_bytes: u64) -> Result<Self, AuditError> {
        if maximum_file_bytes == 0 {
            return Err(file_size_error());
        }
        let path = path.into();
        super::ensure_parent_dir(&path)?;
        let parent = parent(&path)?;
        validate_owner_only_directory(parent)?;

        let created = !path.exists();
        let audit_file = open_append(&path)?;
        validate_owner_only_active_file(&audit_file)?;
        audit_file.sync_all().map_err(AuditError::Io)?;
        if created {
            sync_parent(&path)?;
        }

        let lock_path = lock_path(&path);
        let lock_created = !lock_path.exists();
        let writer_lock = open_lock(&lock_path)?;
        validate_owner_only_active_file(&writer_lock)?;
        match writer_lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(AuditError::SinkLocked {
                    path: lock_path.display().to_string(),
                });
            }
            Err(TryLockError::Error(error)) => return Err(AuditError::Io(error)),
        }
        writer_lock.sync_all().map_err(AuditError::Io)?;
        if lock_created {
            sync_parent(&path)?;
        }

        let fingerprint = file_fingerprint(&audit_file)?;
        let lock_fingerprint = file_fingerprint(&writer_lock)?;
        let next_sequence =
            newest_sealed_sequence(&path)?.map_or(1, |sequence| sequence.saturating_add(1));
        Ok(Self {
            path,
            lock_path,
            maximum_file_bytes,
            state: tokio::sync::Mutex::new(SinkState {
                audit_file,
                fingerprint,
                next_sequence,
            }),
            healthy: Arc::new(AtomicBool::new(true)),
            lock_fingerprint,
            _writer_lock: writer_lock,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    /// Check that the writer is healthy and still owns the pinned active and
    /// lock paths. This performs filesystem work and belongs on a readiness
    /// path, not in a synchronous request admission check.
    pub async fn ready(&self) -> bool {
        if !self.healthy() {
            return false;
        }
        let state = self.state.lock().await;
        let Ok(audit_file) = state.audit_file.try_clone() else {
            return false;
        };
        let Ok(writer_lock) = self._writer_lock.try_clone() else {
            return false;
        };
        let path = self.path.clone();
        let lock_path = self.lock_path.clone();
        let fingerprint = state.fingerprint;
        let lock_fingerprint = self.lock_fingerprint;
        // Keep the state guard until the check completes so an append cannot
        // legitimately change the active-file fingerprint mid-readiness check.
        tokio::task::spawn_blocking(move || {
            validate_pinned_file(&path, &audit_file, fingerprint)?;
            validate_pinned_file(&lock_path, &writer_lock, lock_fingerprint)?;
            audit_file.sync_all().map_err(AuditError::Io)?;
            validate_pinned_file(&path, &audit_file, fingerprint)?;
            validate_pinned_file(&lock_path, &writer_lock, lock_fingerprint)
        })
        .await
        .ok()
        .and_then(Result::ok)
        .is_some()
    }

    fn poison(&self) {
        self.healthy.store(false, Ordering::Release);
    }

    fn check_writable(&self) -> Result<(), AuditError> {
        if !self.healthy() {
            return Err(AuditError::Io(io::Error::other(
                "audit sink stopped after a failed durable write",
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl AuditSink for DurableSegmentedJsonlSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        self.check_writable()?;
        let line = envelope.to_jsonl()?;
        let incoming = u64::try_from(line.len()).map_err(|_| file_size_error())?;
        if incoming > self.maximum_file_bytes {
            return Err(file_size_error());
        }

        let mut state = self.state.lock().await;
        self.check_writable()?;
        let request = AppendRequest {
            path: self.path.clone(),
            maximum_file_bytes: self.maximum_file_bytes,
            line,
            expected_previous: envelope.prev_hash,
            audit_file: state.audit_file.try_clone().map_err(AuditError::Io)?,
            fingerprint: state.fingerprint,
            lock_path: self.lock_path.clone(),
            writer_lock: self._writer_lock.try_clone().map_err(AuditError::Io)?,
            lock_fingerprint: self.lock_fingerprint,
            next_sequence: state.next_sequence,
        };
        match tokio::task::spawn_blocking(move || request.run()).await {
            Ok(Ok(result)) => {
                if let Some(active) = result.active {
                    state.audit_file = active;
                }
                state.fingerprint = result.fingerprint;
                state.next_sequence = result.next_sequence;
                Ok(())
            }
            Ok(Err(error)) => {
                self.poison();
                Err(error)
            }
            Err(error) => {
                self.poison();
                Err(AuditError::Io(io::Error::other(error)))
            }
        }
    }

    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        self.tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
            .await
    }

    async fn tail_hash_with_hasher(
        &self,
        hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        let state = self.state.lock().await;
        self.check_writable()?;
        let path = self.path.clone();
        let file = state.audit_file.try_clone().map_err(AuditError::Io)?;
        let fingerprint = state.fingerprint;
        let lock_path = self.lock_path.clone();
        let writer_lock = self._writer_lock.try_clone().map_err(AuditError::Io)?;
        let lock_fingerprint = self.lock_fingerprint;
        let hasher = hasher.clone();
        tokio::task::spawn_blocking(move || {
            validate_pinned_file(&path, &file, fingerprint)?;
            validate_pinned_file(&lock_path, &writer_lock, lock_fingerprint)?;
            let sealed_head = sealed_tail_hash(&path, &hasher)?;
            let verification = verify_segment(file, &hasher, sealed_head)?;
            validate_pinned_file(&path, &verification.file, fingerprint)?;
            validate_pinned_file(&lock_path, &writer_lock, lock_fingerprint)?;
            Ok(verification.head)
        })
        .await
        .map_err(|error| AuditError::Io(io::Error::other(error)))?
    }
}

struct AppendRequest {
    path: PathBuf,
    maximum_file_bytes: u64,
    line: String,
    expected_previous: Option<[u8; 32]>,
    audit_file: File,
    fingerprint: FileFingerprint,
    lock_path: PathBuf,
    writer_lock: File,
    lock_fingerprint: FileFingerprint,
    next_sequence: u64,
}

struct AppendResult {
    active: Option<File>,
    fingerprint: FileFingerprint,
    next_sequence: u64,
}

impl AppendRequest {
    fn run(mut self) -> Result<AppendResult, AuditError> {
        validate_pinned_file(&self.path, &self.audit_file, self.fingerprint)?;
        validate_pinned_file(&self.lock_path, &self.writer_lock, self.lock_fingerprint)?;
        let on_disk_tail = current_tail_hash(&self.path)?;
        if on_disk_tail != self.expected_previous {
            return Err(AuditError::ChainForkDetected {
                expected: OptionalHashHex(self.expected_previous),
                found: OptionalHashHex(on_disk_tail),
            });
        }

        let incoming = u64::try_from(self.line.len()).map_err(|_| file_size_error())?;
        let current = self.audit_file.metadata().map_err(AuditError::Io)?.len();
        let mut replacement = None;
        if current > 0 && current.saturating_add(incoming) > self.maximum_file_bytes {
            let sealed = seal_active_segment(&self.path, &self.audit_file, self.next_sequence)?;
            self.audit_file = sealed.active.try_clone().map_err(AuditError::Io)?;
            replacement = Some(sealed.active);
            self.next_sequence = sealed.next_sequence;
        }

        self.audit_file
            .write_all(self.line.as_bytes())
            .map_err(AuditError::Io)?;
        self.audit_file.sync_all().map_err(AuditError::Io)?;
        sync_parent(&self.path)?;
        validate_owner_only_active_file(&self.audit_file)?;
        let fingerprint = file_fingerprint(&self.audit_file)?;
        validate_pinned_file(&self.path, &self.audit_file, fingerprint)?;
        validate_pinned_file(&self.lock_path, &self.writer_lock, self.lock_fingerprint)?;
        Ok(AppendResult {
            active: replacement,
            fingerprint,
            next_sequence: self.next_sequence,
        })
    }
}

struct SealedSegment {
    active: File,
    next_sequence: u64,
}

fn seal_active_segment(
    path: &Path,
    active: &File,
    sequence: u64,
) -> Result<SealedSegment, AuditError> {
    active.sync_all().map_err(AuditError::Io)?;
    let mut sequence = sequence;
    let mut sealed = segment_path(path, sequence);
    while fs::symlink_metadata(&sealed).is_ok() {
        sequence = next_sequence(sequence)?;
        sealed = segment_path(path, sequence);
    }
    fs::rename(path, &sealed).map_err(AuditError::Io)?;
    let replacement = open_append(path)?;
    validate_owner_only_active_file(&replacement)?;
    if replacement.metadata().map_err(AuditError::Io)?.len() != 0 {
        return Err(AuditError::Io(io::Error::other(
            "replacement audit segment is not empty",
        )));
    }
    replacement.sync_all().map_err(AuditError::Io)?;
    sync_parent(path)?;
    Ok(SealedSegment {
        active: replacement,
        next_sequence: next_sequence(sequence)?,
    })
}

fn next_sequence(sequence: u64) -> Result<u64, AuditError> {
    sequence
        .checked_add(1)
        .ok_or_else(|| AuditError::Io(io::Error::other("audit segment sequence is exhausted")))
}

/// Enumerate sealed segments oldest first, followed by the active segment.
pub fn segmented_audit_paths(path: &Path) -> Result<Vec<PathBuf>, AuditError> {
    let mut paths: Vec<PathBuf> = sealed_segments(path)?
        .into_iter()
        .map(|(_, path)| path)
        .collect();
    if fs::symlink_metadata(path).is_ok() {
        paths.push(path.to_path_buf());
    }
    Ok(paths)
}

/// Verify all sealed history and, when no writer is running, the active segment.
///
/// A missing sequence inside the retained sealed range is reported distinctly.
/// An archived prefix is allowed and identified by `first_sequence`.
pub fn verify_segmented_audit_chain(
    path: &Path,
    hasher: &AuditChainHasher,
) -> Result<SegmentedAuditSummary, AuditError> {
    let parent = parent(path)?;
    validate_owner_only_directory(parent)?;
    let guard = verification_lock(path)?;
    let active_available = match guard.try_lock() {
        Ok(()) => true,
        Err(TryLockError::WouldBlock) => false,
        Err(TryLockError::Error(error)) => return Err(AuditError::Io(error)),
    };

    let sealed = sealed_segments(path)?;
    let first_sequence = sealed.first().map(|(sequence, _)| *sequence);
    let last_sequence = sealed.last().map(|(sequence, _)| *sequence);
    if let Some(first) = first_sequence {
        for (offset, (sequence, _)) in sealed.iter().enumerate() {
            let expected = first.saturating_add(offset as u64);
            if *sequence != expected {
                return Err(AuditError::SegmentMissing { sequence: expected });
            }
        }
    }

    let mut head = None;
    let mut records = 0usize;
    let mut segments = 0usize;
    for (_, path) in &sealed {
        let file = open_sealed(path)?;
        let verification = verify_segment(file, hasher, head)?;
        head = verification.head;
        records = records.saturating_add(verification.records);
        segments = segments.saturating_add(1);
    }

    let active_verified = active_available && path.is_file();
    if active_verified {
        let file = open_read(path)?;
        validate_owner_only_active_file(&file)?;
        let verification = verify_segment(file, hasher, head)?;
        head = verification.head;
        records = records.saturating_add(verification.records);
        segments = segments.saturating_add(1);
    }

    Ok(SegmentedAuditSummary {
        segments,
        records,
        last_hash: head,
        first_sequence,
        last_sequence,
        active_verified,
    })
}

struct SegmentVerification {
    file: File,
    head: Option<[u8; 32]>,
    records: usize,
}

fn verify_segment(
    file: File,
    hasher: &AuditChainHasher,
    expected_head: Option<[u8; 32]>,
) -> Result<SegmentVerification, AuditError> {
    let mut reader = BufReader::new(file);
    let mut expected_previous = expected_head;
    let mut records = 0usize;
    while let Some(line) = read_bounded_jsonl_line(&mut reader)? {
        let exact = line.trim_end_matches('\n');
        let verification = verify_one_line(exact, hasher)?;
        if verification.start_prev_hash != expected_previous {
            return Err(AuditError::ChainForkDetected {
                expected: OptionalHashHex(expected_previous),
                found: OptionalHashHex(verification.start_prev_hash),
            });
        }
        expected_previous = verification.last_hash;
        records = records.saturating_add(verification.records);
    }
    Ok(SegmentVerification {
        file: reader.into_inner(),
        head: expected_previous,
        records,
    })
}

fn sealed_tail_hash(
    path: &Path,
    hasher: &AuditChainHasher,
) -> Result<Option<[u8; 32]>, AuditError> {
    let Some((_, newest)) = sealed_segments(path)?.pop() else {
        return Ok(None);
    };
    let file = open_sealed(&newest)?;
    let Some(line) = last_jsonl_line(file)? else {
        return Err(AuditError::Io(io::Error::new(
            ErrorKind::InvalidData,
            "sealed audit segment holds no records",
        )));
    };
    let verification = verify_one_line(line.trim_end_matches('\n'), hasher)?;
    Ok(verification.last_hash)
}

fn current_tail_hash(path: &Path) -> Result<Option<[u8; 32]>, AuditError> {
    let active = open_read(path)?;
    if let Some(line) = last_jsonl_line(active)? {
        let envelope = parse_envelope_strict(line.trim_end_matches('\n'))?;
        return Ok(Some(envelope.record_hash));
    }
    let Some((_, newest)) = sealed_segments(path)?.pop() else {
        return Ok(None);
    };
    let Some(line) = last_jsonl_line(open_sealed(&newest)?)? else {
        return Err(AuditError::Io(io::Error::new(
            ErrorKind::InvalidData,
            "sealed audit segment holds no records",
        )));
    };
    let envelope = parse_envelope_strict(line.trim_end_matches('\n'))?;
    Ok(Some(envelope.record_hash))
}

fn verify_one_line(
    line: &str,
    hasher: &AuditChainHasher,
) -> Result<super::ChainVerification, AuditError> {
    parse_envelope_strict(line)?;
    verify_jsonl_lines_with_hasher([line], hasher).map_err(AuditError::ChainVerification)
}

fn parse_envelope_strict(line: &str) -> Result<AuditEnvelope, AuditError> {
    let value = parse_json_strict(line.as_bytes()).map_err(|_| invalid_audit_data())?;
    serde_json::from_value(value).map_err(|_| invalid_audit_data())
}

fn read_bounded_jsonl_line(reader: &mut BufReader<File>) -> Result<Option<String>, AuditError> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(AuditError::Io)?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Err(AuditError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "audit JSONL has an incomplete final record",
            )));
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > MAX_AUDIT_LINE_BYTES {
            return Err(file_size_error());
        }
        let found_newline = available[take - 1] == b'\n';
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if found_newline {
            return String::from_utf8(line).map(Some).map_err(|_| {
                AuditError::Io(io::Error::new(
                    ErrorKind::InvalidData,
                    "audit JSONL is not UTF-8",
                ))
            });
        }
    }
}

fn last_jsonl_line(mut file: File) -> Result<Option<String>, AuditError> {
    let length = file.metadata().map_err(AuditError::Io)?.len();
    if length == 0 {
        return Ok(None);
    }
    let bound = u64::try_from(MAX_AUDIT_LINE_BYTES.saturating_add(1)).unwrap_or(u64::MAX);
    let window = bound.min(length);
    file.seek(SeekFrom::Start(length - window))
        .map_err(AuditError::Io)?;
    let mut tail = vec![0u8; usize::try_from(window).map_err(|_| file_size_error())?];
    file.read_exact(&mut tail).map_err(AuditError::Io)?;
    if tail.pop() != Some(b'\n') {
        return Err(AuditError::Io(io::Error::new(
            ErrorKind::InvalidData,
            "audit segment has an incomplete final record",
        )));
    }
    let start = tail
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    if start == 0 && window < length {
        return Err(file_size_error());
    }
    String::from_utf8(tail[start..].to_vec())
        .map(Some)
        .map_err(|_| {
            AuditError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "audit JSONL is not UTF-8",
            ))
        })
}

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

fn newest_sealed_sequence(path: &Path) -> Result<Option<u64>, AuditError> {
    Ok(sealed_segments(path)?.pop().map(|(sequence, _)| sequence))
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

fn verification_lock(path: &Path) -> Result<File, AuditError> {
    let path = lock_path(path);
    let file = open_lock(&path)?;
    validate_owner_only_active_file(&file)?;
    Ok(file)
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

fn open_sealed(path: &Path) -> Result<File, AuditError> {
    let file = open_read(path)?;
    validate_owner_only_sealed_file(&file)?;
    Ok(file)
}

fn reject_symlink(path: &Path) -> Result<(), AuditError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(AuditError::Io(io::Error::new(
            ErrorKind::PermissionDenied,
            "audit paths must not be symlinks",
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AuditError::Io(error)),
    }
}

fn validate_owner_only_directory(path: &Path) -> Result<(), AuditError> {
    let metadata = fs::symlink_metadata(path).map_err(AuditError::Io)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(AuditError::Io(io::Error::new(
            ErrorKind::PermissionDenied,
            "audit directory must be owner-only",
        )));
    }
    Ok(())
}

fn validate_owner_only_active_file(file: &File) -> Result<(), AuditError> {
    let metadata = file.metadata().map_err(AuditError::Io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(AuditError::Io(io::Error::new(
            ErrorKind::PermissionDenied,
            "active audit files must be owner-only, singly linked regular files",
        )));
    }
    Ok(())
}

fn validate_owner_only_sealed_file(file: &File) -> Result<(), AuditError> {
    let metadata = file.metadata().map_err(AuditError::Io)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(AuditError::Io(io::Error::new(
            ErrorKind::PermissionDenied,
            "sealed audit files must be owner-only regular files",
        )));
    }
    Ok(())
}

fn file_fingerprint(file: &File) -> Result<FileFingerprint, AuditError> {
    let metadata = file.metadata().map_err(AuditError::Io)?;
    Ok(FileFingerprint {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn validate_pinned_file(
    path: &Path,
    pinned: &File,
    expected: FileFingerprint,
) -> Result<(), AuditError> {
    validate_owner_only_active_file(pinned)?;
    let candidate = open_read(path)?;
    validate_owner_only_active_file(&candidate)?;
    if file_fingerprint(pinned)? != expected || file_fingerprint(&candidate)? != expected {
        return Err(AuditError::Io(io::Error::other(
            "audit file changed outside the initialized writer",
        )));
    }
    Ok(())
}

fn parent(path: &Path) -> Result<&Path, AuditError> {
    path.parent().ok_or_else(|| {
        AuditError::Io(io::Error::new(
            ErrorKind::InvalidInput,
            "audit path has no parent",
        ))
    })
}

fn sync_parent(path: &Path) -> Result<(), AuditError> {
    let parent = parent(path)?;
    validate_owner_only_directory(parent)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(AuditError::Io)
}

fn file_size_error() -> AuditError {
    AuditError::Io(io::Error::other("audit file size bound exceeded"))
}

fn invalid_audit_data() -> AuditError {
    AuditError::Io(io::Error::new(
        ErrorKind::InvalidData,
        "audit record is invalid",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditHashSecret, ChainState};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> (tempfile::TempDir, PathBuf, AuditChainHasher) {
        let directory = tempfile::tempdir().expect("temp dir");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("restrict temp dir");
        let path = directory.path().join("audit.jsonl");
        let secret =
            AuditHashSecret::new(b"0123456789abcdef0123456789abcdef".to_vec()).expect("secret");
        (directory, path, AuditChainHasher::keyed(secret))
    }

    #[tokio::test]
    async fn rotation_is_non_destructive_and_the_chain_crosses_segments() {
        let (_directory, path, hasher) = fixture();
        let sink = DurableSegmentedJsonlSink::open(&path, 700).expect("sink opens");
        let chain = ChainState::bootstrap_or_start_empty(&sink, hasher.clone())
            .await
            .expect("chain starts");
        for index in 0..12 {
            chain
                .append(&sink, json!({"index": index, "padding": "x".repeat(160)}))
                .await
                .expect("record appends");
        }
        drop(chain);
        drop(sink);

        let summary = verify_segmented_audit_chain(&path, &hasher).expect("chain verifies");
        assert_eq!(summary.records, 12);
        assert!(summary.segments > 1);
        assert_eq!(summary.first_sequence, Some(1));
        assert!(path.with_extension("jsonl.00000001").exists());
    }

    #[tokio::test]
    async fn restart_continues_from_the_newest_sealed_tail() {
        let (_directory, path, hasher) = fixture();
        {
            let sink = DurableSegmentedJsonlSink::open(&path, 500).expect("sink opens");
            let chain = ChainState::bootstrap_or_start_empty(&sink, hasher.clone())
                .await
                .expect("chain starts");
            for index in 0..6 {
                chain
                    .append(&sink, json!({"index": index, "padding": "x".repeat(160)}))
                    .await
                    .expect("record appends");
            }
        }
        {
            let sink = DurableSegmentedJsonlSink::open(&path, 500).expect("sink restarts");
            let chain = ChainState::bootstrap_or_start_empty(&sink, hasher.clone())
                .await
                .expect("chain resumes");
            chain
                .append(&sink, json!({"after": "restart"}))
                .await
                .expect("post-restart record appends");
        }
        assert_eq!(
            verify_segmented_audit_chain(&path, &hasher)
                .expect("chain verifies")
                .records,
            7
        );
    }

    #[tokio::test]
    async fn a_gap_inside_retained_history_is_reported() {
        let (_directory, path, hasher) = fixture();
        {
            let sink = DurableSegmentedJsonlSink::open(&path, 450).expect("sink opens");
            let chain = ChainState::bootstrap_or_start_empty(&sink, hasher.clone())
                .await
                .expect("chain starts");
            for index in 0..12 {
                chain
                    .append(&sink, json!({"index": index, "padding": "x".repeat(160)}))
                    .await
                    .expect("record appends");
            }
        }
        let segments = sealed_segments(&path).expect("segments enumerate");
        assert!(segments.len() >= 3);
        fs::remove_file(&segments[1].1).expect("archive middle segment");
        assert!(matches!(
            verify_segmented_audit_chain(&path, &hasher),
            Err(AuditError::SegmentMissing { .. })
        ));
    }

    #[tokio::test]
    async fn a_live_verifier_proves_only_sealed_history() {
        let (_directory, path, hasher) = fixture();
        let sink = DurableSegmentedJsonlSink::open(&path, 1_048_576).expect("sink opens");
        let chain = ChainState::bootstrap_or_start_empty(&sink, hasher.clone())
            .await
            .expect("chain starts");
        chain
            .append(&sink, json!({"decision": "issued"}))
            .await
            .expect("record appends");

        let summary = verify_segmented_audit_chain(&path, &hasher).expect("sealed history checks");
        assert!(!summary.active_verified);
        assert_eq!(summary.records, 0);
        assert_eq!(summary.segments, 0);
    }

    #[test]
    fn a_second_writer_is_rejected() {
        let (_directory, path, _hasher) = fixture();
        let first = DurableSegmentedJsonlSink::open(&path, 1_048_576).expect("first writer opens");
        assert!(matches!(
            DurableSegmentedJsonlSink::open(&path, 1_048_576),
            Err(AuditError::SinkLocked { .. })
        ));
        drop(first);
    }

    #[tokio::test]
    async fn an_oversized_record_is_rejected_without_poisoning_the_sink() {
        let (_directory, path, hasher) = fixture();
        let sink = DurableSegmentedJsonlSink::open(&path, 500).expect("sink opens");
        let chain = ChainState::bootstrap_or_start_empty(&sink, hasher.clone())
            .await
            .expect("chain starts");
        assert!(chain
            .append(&sink, json!({"padding": "x".repeat(1000)}))
            .await
            .is_err());
        assert!(sink.healthy());
        chain
            .append(&sink, json!({"decision": "rejected"}))
            .await
            .expect("a bounded record still appends");
        drop(chain);
        drop(sink);
        assert_eq!(
            verify_segmented_audit_chain(&path, &hasher)
                .expect("chain verifies")
                .records,
            1
        );
    }

    #[tokio::test]
    async fn replacing_the_active_path_poisons_the_writer() {
        let (_directory, path, hasher) = fixture();
        let sink = DurableSegmentedJsonlSink::open(&path, 1_048_576).expect("sink opens");
        let chain = ChainState::bootstrap_or_start_empty(&sink, hasher)
            .await
            .expect("chain starts");
        let moved = path.with_extension("moved");
        fs::rename(&path, moved).expect("move active file outside the writer");
        fs::write(&path, []).expect("replace active path");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("restrict replacement");

        assert!(chain
            .append(&sink, json!({"decision": "issued"}))
            .await
            .is_err());
        assert!(!sink.healthy());
    }

    #[tokio::test]
    async fn duplicate_json_members_are_rejected_during_verification() {
        let (_directory, path, hasher) = fixture();
        {
            let sink = DurableSegmentedJsonlSink::open(&path, 1_048_576).expect("sink opens");
            let chain = ChainState::bootstrap_or_start_empty(&sink, hasher.clone())
                .await
                .expect("chain starts");
            chain
                .append(&sink, json!({"decision": "issued"}))
                .await
                .expect("record appends");
        }
        let original = fs::read_to_string(&path).expect("audit reads");
        let ambiguous = original.replacen("\"record\":", "\"record\":{},\"record\":", 1);
        fs::write(&path, ambiguous).expect("duplicate member is planted");
        assert!(verify_segmented_audit_chain(&path, &hasher).is_err());
    }

    #[tokio::test]
    async fn replacing_the_lock_path_fails_readiness_and_poisons_the_writer() {
        let (_directory, path, hasher) = fixture();
        let sink = DurableSegmentedJsonlSink::open(&path, 1_048_576).expect("sink opens");
        let chain = ChainState::bootstrap_or_start_empty(&sink, hasher)
            .await
            .expect("chain starts");
        let lock = lock_path(&path);
        fs::rename(&lock, lock.with_extension("moved")).expect("move writer lock");
        fs::write(&lock, []).expect("replace writer lock");
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))
            .expect("restrict replacement");

        assert!(!sink.ready().await);
        assert!(chain
            .append(&sink, json!({"decision": "issued"}))
            .await
            .is_err());
        assert!(!sink.healthy());
    }
}

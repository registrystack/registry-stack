//! Fail-closed native Evidence audit with a durable keyed JSONL chain.

use std::{
    fs::{File, TryLockError},
    io::{BufRead as _, BufReader, Error as IoError, ErrorKind, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_audit::{
    verify_jsonl_lines_with_hasher, AuditChainHasher, AuditEnvelope, AuditError, AuditHashSecret,
    AuditKeyHasher, AuditSink, ChainState, OptionalHashHex,
};
use serde::Serialize;
use thiserror::Error;

const AUDIT_SCHEMA: &str = "registry.evidence.audit/v1";
const MAX_AUDIT_LINE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditPhase {
    AccessAttempt,
    DisclosureRelease,
    Denial,
    TransientFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditDecision {
    Authorized,
    Released,
    NoMatch,
    Ambiguous,
    FactMissing,
    DependencyFailure,
    EvaluationFailure,
    SigningFailure,
}

/// Closed non-secret response-protection mode resolved with authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseProtection {
    Signed,
    Unsigned,
    SdJwtVc,
}

impl ResponseProtection {
    /// Report whether release under this mode is cryptographically protected
    /// and therefore records the signing key identifier.
    pub fn is_signed(self) -> bool {
        matches!(self, Self::Signed | Self::SdJwtVc)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityKind {
    Statutory,
    Organizational,
    Consent,
    Delegated,
    ExplicitRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditAuthority {
    pub kind: AuthorityKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_pseudonym: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditSubject {
    pub role: String,
    pub selector_profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_bundle_pseudonym: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceAuditEvent {
    pub schema: &'static str,
    pub event_id: String,
    pub occurred_at: String,
    pub operation: String,
    pub phase: AuditPhase,
    pub requirement: String,
    pub bundle_revision: String,
    pub purpose: String,
    pub requester_pseudonym: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_pseudonym: Option<String>,
    pub authority: AuditAuthority,
    pub subjects: Vec<AuditSubject>,
    pub response_protection: ResponseProtection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter_id: Option<String>,
    pub decision: AuditDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disclosed_concepts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_error_category: Option<String>,
    pub duration_milliseconds: u64,
}

impl EvidenceAuditEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: String,
        phase: AuditPhase,
        requirement: String,
        bundle_revision: String,
        purpose: String,
        requester_pseudonym: String,
        authority: AuditAuthority,
        subjects: Vec<AuditSubject>,
        response_protection: ResponseProtection,
        decision: AuditDecision,
        duration_milliseconds: u64,
    ) -> Self {
        Self {
            schema: AUDIT_SCHEMA,
            event_id: format!("urn:ulid:{}", ulid::Ulid::new()),
            occurred_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            operation,
            phase,
            requirement,
            bundle_revision,
            purpose,
            requester_pseudonym,
            actor_pseudonym: None,
            authority,
            subjects,
            response_protection,
            source_id: None,
            adapter_id: None,
            decision,
            disclosed_concepts: None,
            evidence_id: None,
            signing_key_id: None,
            safe_error_category: None,
            duration_milliseconds,
        }
    }

    pub fn validate_phase_fields(&self) -> Result<(), EvidenceAuditError> {
        let any_release_field = self.disclosed_concepts.is_some() || self.evidence_id.is_some();
        let all_release_fields = self.disclosed_concepts.is_some() && self.evidence_id.is_some();
        if (self.phase == AuditPhase::DisclosureRelease && !all_release_fields)
            || (self.phase != AuditPhase::DisclosureRelease && any_release_field)
        {
            return Err(EvidenceAuditError::InvalidEvent);
        }
        // A signing key identity exists exactly for cryptographically
        // protected disclosure release.
        let signing_key_required =
            self.phase == AuditPhase::DisclosureRelease && self.response_protection.is_signed();
        if self.signing_key_id.is_some() != signing_key_required {
            return Err(EvidenceAuditError::InvalidEvent);
        }
        if self.subjects.is_empty()
            || self.subjects.len() > 8
            || !(16..=128).contains(&self.operation.len())
            || self.duration_milliseconds > 86_400_000
        {
            return Err(EvidenceAuditError::InvalidEvent);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum EvidenceAuditError {
    #[error("audit configuration is invalid")]
    Configuration,
    #[error("audit event is invalid")]
    InvalidEvent,
    #[error("audit initialization or write failed")]
    Audit(#[from] AuditError),
}

pub struct EvidenceAuditLog {
    sink: Arc<DurableJsonlSink>,
    chain: ChainState,
    key_hasher: AuditKeyHasher,
    key_version: u32,
}

impl std::fmt::Debug for EvidenceAuditLog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceAuditLog")
            .field("path", &self.sink.path)
            .field("key_version", &self.key_version)
            .finish_non_exhaustive()
    }
}

impl EvidenceAuditLog {
    pub async fn initialize(
        path: impl Into<PathBuf>,
        maximum_file_bytes: u64,
        master_secret: Vec<u8>,
        key_version: u32,
    ) -> Result<Self, EvidenceAuditError> {
        if maximum_file_bytes == 0 || key_version == 0 {
            return Err(EvidenceAuditError::Configuration);
        }
        let secret = AuditHashSecret::new(master_secret)?;
        let chain_hasher = AuditChainHasher::keyed(secret.clone());
        let key_hasher = AuditKeyHasher::Keyed(secret);
        let sink = Arc::new(DurableJsonlSink::open(path.into(), maximum_file_bytes)?);
        let chain = ChainState::bootstrap_or_start_empty(sink.as_ref(), chain_hasher).await?;
        Ok(Self {
            sink,
            chain,
            key_hasher,
            key_version,
        })
    }

    pub fn pseudonym(
        &self,
        class: &str,
        scope: &str,
        protected_input: &[u8],
    ) -> Result<String, EvidenceAuditError> {
        if protected_input.is_empty() {
            return Err(EvidenceAuditError::InvalidEvent);
        }
        let transient = URL_SAFE_NO_PAD.encode(protected_input);
        let digest = self
            .key_hasher
            .audit_reference_hash(class, scope, &transient)
            .map_err(|_| EvidenceAuditError::InvalidEvent)?;
        Ok(format!("hmac-sha256:v{}:{digest}", self.key_version))
    }

    pub async fn append(
        &self,
        event: EvidenceAuditEvent,
    ) -> Result<AuditEnvelope, EvidenceAuditError> {
        event.validate_phase_fields()?;
        self.chain
            .append(self.sink.as_ref(), event)
            .await
            .map_err(EvidenceAuditError::Audit)
    }

    pub async fn ready(&self) -> bool {
        let Some(expected_tail) = self.chain.try_last_hash() else {
            return false;
        };
        self.sink.ready(expected_tail).await
    }
}

struct DurableJsonlSink {
    path: PathBuf,
    lock_path: PathBuf,
    maximum_file_bytes: u64,
    state: tokio::sync::Mutex<SinkState>,
    audit_file: File,
    _writer_lock: File,
    #[cfg(test)]
    full_verifications: AtomicUsize,
}

#[derive(Clone, Copy)]
struct SinkState {
    verified: bool,
    fingerprint: FileFingerprint,
    tail_hash: Option<[u8; 32]>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    length: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
}

impl std::fmt::Debug for DurableJsonlSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableJsonlSink")
            .field("path", &self.path)
            .field("maximum_file_bytes", &self.maximum_file_bytes)
            .finish_non_exhaustive()
    }
}

impl DurableJsonlSink {
    fn open(path: PathBuf, maximum_file_bytes: u64) -> Result<Self, AuditError> {
        if !path.is_absolute() {
            return Err(AuditError::Io(IoError::new(
                ErrorKind::InvalidInput,
                "audit path must be absolute",
            )));
        }
        let parent = path.parent().ok_or_else(|| {
            AuditError::Io(IoError::new(
                ErrorKind::InvalidInput,
                "audit path has no parent",
            ))
        })?;
        if !parent.is_dir() {
            return Err(AuditError::Io(IoError::new(
                ErrorKind::NotFound,
                "audit parent directory is unavailable",
            )));
        }

        let created = !path.exists();
        let file = open_append_nofollow(&path)?;
        validate_owner_only_regular_file(&file)?;
        if file.metadata().map_err(AuditError::Io)?.len() > maximum_file_bytes {
            return Err(file_size_error());
        }
        file.sync_all().map_err(AuditError::Io)?;
        if created {
            sync_parent(parent)?;
        }

        let lock_path = lock_path(&path);
        let lock_created = !lock_path.exists();
        let writer_lock = open_lock_nofollow(&lock_path)?;
        validate_owner_only_regular_file(&writer_lock)?;
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
            sync_parent(parent)?;
        }

        let fingerprint = file_fingerprint(&file)?;
        Ok(Self {
            path,
            lock_path,
            maximum_file_bytes,
            state: tokio::sync::Mutex::new(SinkState {
                verified: false,
                fingerprint,
                tail_hash: None,
            }),
            audit_file: file,
            _writer_lock: writer_lock,
            #[cfg(test)]
            full_verifications: AtomicUsize::new(0),
        })
    }

    async fn ready(&self, expected_tail: Option<[u8; 32]>) -> bool {
        // Readiness probes must never queue behind audit writes or one another.
        // The startup scan establishes the authenticated chain head; steady
        // state checks are constant-time fingerprint and pinned-file checks.
        let Ok(state) = self.state.try_lock() else {
            return false;
        };
        if !state.verified || state.tail_hash != expected_tail {
            return false;
        }
        let path = self.path.clone();
        let lock_path = self.lock_path.clone();
        let maximum = self.maximum_file_bytes;
        let expected_fingerprint = state.fingerprint;
        let Ok(file) = self.audit_file.try_clone() else {
            return false;
        };
        let Ok(writer_lock) = self._writer_lock.try_clone() else {
            return false;
        };
        tokio::task::spawn_blocking(move || -> Result<bool, AuditError> {
            validate_pinned_path(&path, &file)?;
            validate_pinned_path(&lock_path, &writer_lock)?;
            let metadata = file.metadata().map_err(AuditError::Io)?;
            if !metadata.is_file()
                || metadata.len() > maximum
                || file_fingerprint(&file)? != expected_fingerprint
            {
                return Ok(false);
            }
            file.sync_all().map_err(AuditError::Io)?;
            validate_pinned_path(&path, &file)?;
            validate_pinned_path(&lock_path, &writer_lock)?;
            Ok(true)
        })
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false)
    }

    fn verify_and_tail(
        file: File,
        maximum_file_bytes: u64,
        hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        let length = file.metadata().map_err(AuditError::Io)?.len();
        if length > maximum_file_bytes {
            return Err(file_size_error());
        }
        verify_reader(file, hasher)
    }
}

#[async_trait]
impl AuditSink for DurableJsonlSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        let line = envelope.to_jsonl()?;
        let expected_prev = envelope.prev_hash;
        let mut state = self.state.lock().await;
        if !state.verified || state.tail_hash != expected_prev {
            return Err(AuditError::ChainForkDetected {
                expected: OptionalHashHex(state.tail_hash),
                found: OptionalHashHex(expected_prev),
            });
        }
        let path = self.path.clone();
        let lock_path = self.lock_path.clone();
        let maximum = self.maximum_file_bytes;
        let expected_fingerprint = state.fingerprint;
        let mut file = self.audit_file.try_clone().map_err(AuditError::Io)?;
        let writer_lock = self._writer_lock.try_clone().map_err(AuditError::Io)?;
        let next_fingerprint = tokio::task::spawn_blocking(move || {
            validate_pinned_path(&path, &file)?;
            validate_pinned_path(&lock_path, &writer_lock)?;
            if file_fingerprint(&file)? != expected_fingerprint {
                return Err(AuditError::Io(IoError::other(
                    "audit file changed outside the initialized writer",
                )));
            }
            let current = file.metadata().map_err(AuditError::Io)?.len();
            let incoming = u64::try_from(line.len()).map_err(|_| file_size_error())?;
            if current.saturating_add(incoming) > maximum {
                return Err(file_size_error());
            }
            file.write_all(line.as_bytes()).map_err(AuditError::Io)?;
            file.flush().map_err(AuditError::Io)?;
            file.sync_all().map_err(AuditError::Io)?;
            validate_pinned_path(&path, &file)?;
            validate_pinned_path(&lock_path, &writer_lock)?;
            let fingerprint = file_fingerprint(&file)?;
            if fingerprint.length != current.saturating_add(incoming) {
                return Err(AuditError::Io(IoError::other(
                    "audit file length changed during append",
                )));
            }
            Ok(fingerprint)
        })
        .await
        .map_err(|error| AuditError::Io(IoError::other(error)))??;
        state.fingerprint = next_fingerprint;
        state.tail_hash = Some(envelope.record_hash);
        Ok(())
    }

    #[allow(deprecated)]
    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        self.tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
            .await
    }

    async fn tail_hash_with_hasher(
        &self,
        hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        let mut state = self.state.lock().await;
        let path = self.path.clone();
        let lock_path = self.lock_path.clone();
        let maximum = self.maximum_file_bytes;
        let hasher = hasher.clone();
        let file = self.audit_file.try_clone().map_err(AuditError::Io)?;
        let writer_lock = self._writer_lock.try_clone().map_err(AuditError::Io)?;
        #[cfg(test)]
        self.full_verifications.fetch_add(1, Ordering::Relaxed);
        let (tail_hash, fingerprint) = tokio::task::spawn_blocking(move || {
            validate_pinned_path(&path, &file)?;
            validate_pinned_path(&lock_path, &writer_lock)?;
            let tail_hash =
                Self::verify_and_tail(file.try_clone().map_err(AuditError::Io)?, maximum, &hasher)?;
            Ok((tail_hash, file_fingerprint(&file)?))
        })
        .await
        .map_err(|error| AuditError::Io(IoError::other(error)))??;
        state.verified = true;
        state.fingerprint = fingerprint;
        state.tail_hash = tail_hash;
        Ok(tail_hash)
    }
}

#[cfg(unix)]
fn file_fingerprint(file: &File) -> Result<FileFingerprint, AuditError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata().map_err(AuditError::Io)?;
    Ok(FileFingerprint {
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(not(unix))]
fn file_fingerprint(file: &File) -> Result<FileFingerprint, AuditError> {
    let metadata = file.metadata().map_err(AuditError::Io)?;
    Ok(FileFingerprint {
        length: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

fn verify_reader(
    mut file: File,
    hasher: &AuditChainHasher,
) -> Result<Option<[u8; 32]>, AuditError> {
    file.seek(SeekFrom::Start(0)).map_err(AuditError::Io)?;
    let mut reader = BufReader::new(file);
    let mut expected_previous = None;
    let mut records = 0usize;
    while let Some(line) = read_bounded_jsonl_line(&mut reader)? {
        let verification = verify_jsonl_lines_with_hasher([line.trim_end_matches('\n')], hasher)
            .map_err(AuditError::ChainVerification)?;
        if records == 0 {
            if verification.start_prev_hash.is_some() {
                return Err(AuditError::ChainForkDetected {
                    expected: OptionalHashHex(None),
                    found: OptionalHashHex(verification.start_prev_hash),
                });
            }
        } else if verification.start_prev_hash != expected_previous {
            return Err(AuditError::ChainForkDetected {
                expected: OptionalHashHex(expected_previous),
                found: OptionalHashHex(verification.start_prev_hash),
            });
        }
        expected_previous = verification.last_hash;
        records += verification.records;
    }
    Ok(expected_previous)
}

fn read_bounded_jsonl_line(reader: &mut BufReader<File>) -> Result<Option<String>, AuditError> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(AuditError::Io)?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Err(AuditError::Io(IoError::new(
                ErrorKind::InvalidData,
                "audit JSONL has an incomplete final record",
            )));
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > MAX_AUDIT_LINE_BYTES {
            return Err(AuditError::Io(IoError::new(
                ErrorKind::InvalidData,
                "audit JSONL record exceeds its bound",
            )));
        }
        let found_newline = available[take - 1] == b'\n';
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if found_newline {
            let line = String::from_utf8(line).map_err(|_| {
                AuditError::Io(IoError::new(
                    ErrorKind::InvalidData,
                    "audit JSONL is not UTF-8",
                ))
            })?;
            return Ok(Some(line));
        }
    }
}

fn file_size_error() -> AuditError {
    AuditError::Io(IoError::other("audit file size bound exceeded"))
}

fn lock_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(".lock");
    PathBuf::from(value)
}

fn validate_pinned_path(path: &Path, pinned: &File) -> Result<(), AuditError> {
    let candidate = open_read_nofollow(path)?;
    validate_owner_only_regular_file(pinned)?;
    validate_owner_only_regular_file(&candidate)?;
    if !same_file(pinned, &candidate)? {
        return Err(AuditError::Io(IoError::other(
            "audit path no longer names the initialized file",
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_owner_only_regular_file(file: &File) -> Result<(), AuditError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata().map_err(AuditError::Io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(AuditError::Io(IoError::new(
            ErrorKind::PermissionDenied,
            "audit files must be owner-only, singly linked regular files",
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_only_regular_file(file: &File) -> Result<(), AuditError> {
    if file.metadata().map_err(AuditError::Io)?.is_file() {
        Ok(())
    } else {
        Err(AuditError::Io(IoError::new(
            ErrorKind::InvalidInput,
            "audit file is not regular",
        )))
    }
}

#[cfg(unix)]
fn same_file(left: &File, right: &File) -> Result<bool, AuditError> {
    use std::os::unix::fs::MetadataExt as _;

    let left = left.metadata().map_err(AuditError::Io)?;
    let right = right.metadata().map_err(AuditError::Io)?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(not(unix))]
fn same_file(_left: &File, _right: &File) -> Result<bool, AuditError> {
    Ok(true)
}

#[cfg(unix)]
fn open_append_nofollow(path: &Path) -> Result<File, AuditError> {
    use rustix::fs::{Mode, OFlags};
    rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::APPEND | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map(File::from)
    .map_err(|error| AuditError::Io(error.into()))
}

#[cfg(not(unix))]
fn open_append_nofollow(path: &Path) -> Result<File, AuditError> {
    reject_symlink(path)?;
    std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)
        .map_err(AuditError::Io)
}

#[cfg(unix)]
fn open_lock_nofollow(path: &Path) -> Result<File, AuditError> {
    use rustix::fs::{Mode, OFlags};
    rustix::fs::open(
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map(File::from)
    .map_err(|error| AuditError::Io(error.into()))
}

#[cfg(not(unix))]
fn open_lock_nofollow(path: &Path) -> Result<File, AuditError> {
    reject_symlink(path)?;
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(path)
        .map_err(AuditError::Io)
}

#[cfg(unix)]
fn open_read_nofollow(path: &Path) -> Result<File, AuditError> {
    use rustix::fs::{Mode, OFlags};
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| AuditError::Io(error.into()))
}

#[cfg(not(unix))]
fn open_read_nofollow(path: &Path) -> Result<File, AuditError> {
    reject_symlink(path)?;
    File::open(path).map_err(AuditError::Io)
}

#[cfg(not(unix))]
fn reject_symlink(path: &Path) -> Result<(), AuditError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(AuditError::Io(IoError::new(
            ErrorKind::InvalidInput,
            "audit path is a symlink",
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AuditError::Io(error)),
    }
}

fn sync_parent(parent: &Path) -> Result<(), AuditError> {
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(AuditError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(log: &EvidenceAuditLog) -> EvidenceAuditEvent {
        EvidenceAuditEvent::new(
            "01K1EXAMPLE0000000000000000".to_string(),
            AuditPhase::AccessAttempt,
            "urn:example:requirement:v1".to_string(),
            format!("sha256:{}", "0".repeat(64)),
            "casework".to_string(),
            log.pseudonym("requester-v1", "urn:example:trust", b"principal-canary")
                .expect("pseudonym builds"),
            AuditAuthority {
                kind: AuthorityKind::Statutory,
                grant_pseudonym: None,
            },
            vec![AuditSubject {
                role: "subject".to_string(),
                selector_profile: "person-v1".to_string(),
                selector_bundle_pseudonym: Some(
                    log.pseudonym("subject-v1", "casework", b"selector-canary")
                        .expect("pseudonym builds"),
                ),
            }],
            ResponseProtection::Signed,
            AuditDecision::Authorized,
            5,
        )
    }

    #[test]
    fn frozen_audit_fixture_matches_native_event_shape_and_phase_rules() {
        let fixture: serde_json::Value = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/fixtures/conformance/audit-events.yaml"
        ))
        .expect("frozen audit fixture parses");
        assert_eq!(
            fixture["fixture"],
            serde_json::json!("registry.evidence.audit-events/v1")
        );
        assert_eq!(fixture["synthetic_only"], serde_json::json!(true));

        let access = EvidenceAuditEvent {
            schema: AUDIT_SCHEMA,
            event_id: "urn:example:fixture:audit:access-001".to_owned(),
            occurred_at: "2026-08-02T00:00:00Z".to_owned(),
            operation: "fixture-operation-00000001".to_owned(),
            phase: AuditPhase::AccessAttempt,
            requirement: "urn:example:fixture:requirement:property:v1".to_owned(),
            bundle_revision:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
            purpose: "fixture-procedure".to_owned(),
            requester_pseudonym:
                "hmac-sha256:v1:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_owned(),
            actor_pseudonym: None,
            authority: AuditAuthority {
                kind: AuthorityKind::Statutory,
                grant_pseudonym: None,
            },
            subjects: vec![AuditSubject {
                role: "subject".to_owned(),
                selector_profile: "opaque-record-v1".to_owned(),
                selector_bundle_pseudonym: Some(
                    "hmac-sha256:v1:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_owned(),
                ),
            }],
            response_protection: ResponseProtection::Signed,
            source_id: Some("source-a".to_owned()),
            adapter_id: Some("adapter-a".to_owned()),
            decision: AuditDecision::Authorized,
            disclosed_concepts: None,
            evidence_id: None,
            signing_key_id: None,
            safe_error_category: None,
            duration_milliseconds: 2,
        };
        access
            .validate_phase_fields()
            .expect("fixture access event satisfies native phase rules");
        assert_eq!(
            serde_json::to_value(&access).expect("access event serializes"),
            fixture["access_attempt"]
        );

        let mut release = access.clone();
        release.event_id = "urn:example:fixture:audit:release-001".to_owned();
        release.occurred_at = "2026-08-02T00:00:01Z".to_owned();
        release.phase = AuditPhase::DisclosureRelease;
        release.decision = AuditDecision::Released;
        release.disclosed_concepts = Some(vec!["urn:example:fixture:concept:boolean-a".to_owned()]);
        release.evidence_id = Some("urn:example:fixture:evidence:001".to_owned());
        release.signing_key_id = Some("fixture-key-2026-01".to_owned());
        release.duration_milliseconds = 12;
        release
            .validate_phase_fields()
            .expect("fixture release event satisfies native phase rules");
        assert_eq!(
            serde_json::to_value(&release).expect("release event serializes"),
            fixture["disclosure_release"]
        );

        let mut unsigned_release = release.clone();
        unsigned_release.event_id = "urn:example:fixture:audit:release-002".to_owned();
        unsigned_release.occurred_at = "2026-08-02T00:00:02Z".to_owned();
        unsigned_release.response_protection = ResponseProtection::Unsigned;
        unsigned_release.signing_key_id = None;
        unsigned_release
            .validate_phase_fields()
            .expect("fixture unsigned release event satisfies native phase rules");
        assert_eq!(
            serde_json::to_value(&unsigned_release).expect("unsigned release event serializes"),
            fixture["unsigned_disclosure_release"]
        );
        unsigned_release.signing_key_id = Some("fixture-key-2026-01".to_owned());
        assert!(matches!(
            unsigned_release.validate_phase_fields(),
            Err(EvidenceAuditError::InvalidEvent)
        ));

        let mut signed_release_without_key = release.clone();
        signed_release_without_key.signing_key_id = None;
        assert!(matches!(
            signed_release_without_key.validate_phase_fields(),
            Err(EvidenceAuditError::InvalidEvent)
        ));

        let mut release_fields_on_access = access;
        release_fields_on_access.disclosed_concepts = release.disclosed_concepts.clone();
        release_fields_on_access.evidence_id = release.evidence_id.clone();
        release_fields_on_access.signing_key_id = release.signing_key_id.clone();
        assert!(matches!(
            release_fields_on_access.validate_phase_fields(),
            Err(EvidenceAuditError::InvalidEvent)
        ));
        release.evidence_id = None;
        assert!(matches!(
            release.validate_phase_fields(),
            Err(EvidenceAuditError::InvalidEvent)
        ));

        assert_eq!(
            fixture["order"],
            serde_json::json!({
                "access_attempt_durable_before": ["credential-resolution", "source-access"],
                "disclosure_release_durable_after": ["signing"],
                "disclosure_release_durable_before": ["response-release"]
            })
        );
        assert_eq!(
            fixture["negative"],
            serde_json::json!([
                "raw-principal",
                "raw-actor-or-grant",
                "raw-selector-value",
                "separate-field-hash",
                "plain-sha256-subject-hash",
                "base64url-reencoded-audit-hmac",
                "globally-stable-subject-pseudonym",
                "source-or-supported-value",
                "credential-token-or-private-key",
                "candidate-count-score-hint-or-comparison",
                "release-fields-on-access-event",
                "missing-release-fields-on-release-event",
                "signing-key-on-unsigned-release-event",
                "missing-signing-key-on-signed-release-event",
                "request-nonce-in-any-event"
            ])
        );
    }

    #[tokio::test]
    async fn audit_is_durable_keyed_and_redacted() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        assert_eq!(log.sink.full_verifications.load(Ordering::Relaxed), 1);
        assert!(log.ready().await, "an empty verified chain is ready");
        log.append(event(&log)).await.expect("event appends");
        assert!(log.ready().await);
        assert_eq!(
            log.sink.full_verifications.load(Ordering::Relaxed),
            1,
            "steady-state appends and readiness must not rescan the audit file"
        );

        let contents = std::fs::read_to_string(&path).expect("audit reads");
        assert!(!contents.contains("principal-canary"));
        assert!(!contents.contains("selector-canary"));
        assert!(contents.contains("hmac-sha256:v1:"));
        assert!(contents.ends_with('\n'));

        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .and_then(|mut file| file.write_all(b"{}\n"))
            .expect("tamper audit file");
        assert!(!log.ready().await, "readiness detects chain tampering");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_appends_extend_one_keyed_chain_without_forking() {
        // Every evaluation shares one `EvidenceAuditLog` through an `Arc`, so many
        // requests can append at once. The keyed chain must serialize each event's
        // prev-hash read with its durable write: if two appends observed the same
        // tail hash in parallel they would fork the chain and surface as a
        // `ChainForkDetected` error (a spurious 503) or a broken linkage. Drive a
        // burst of concurrent appends across worker threads and prove each one
        // succeeds and the resulting chain still verifies end to end.
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = Arc::new(
            EvidenceAuditLog::initialize(
                &path,
                256 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes"),
        );

        const CONCURRENCY: usize = 16;
        let mut handles = Vec::with_capacity(CONCURRENCY);
        for _ in 0..CONCURRENCY {
            let log = Arc::clone(&log);
            handles.push(tokio::spawn(async move {
                let event = event(log.as_ref());
                log.append(event).await
            }));
        }
        for handle in handles {
            handle
                .await
                .expect("append task joins")
                .expect("a concurrent append never forks the keyed chain");
        }

        assert!(
            log.ready().await,
            "the chain verifies after concurrent appends"
        );
        assert_eq!(
            log.sink.full_verifications.load(Ordering::Relaxed),
            1,
            "concurrent appends extend the chain incrementally without rescanning it"
        );
        let lines = std::fs::read_to_string(&path)
            .expect("audit reads")
            .lines()
            .count();
        assert_eq!(
            lines, CONCURRENCY,
            "every concurrent append is durably recorded exactly once"
        );

        // Release the single-writer sink lock before reopening: the sink holds an
        // exclusive lock for one writer per file, so a fresh reader can only
        // re-verify the chain once this handle is dropped.
        drop(log);

        // A fresh reader re-verifies the whole keyed chain from disk, proving the
        // prev-hash linkage stayed consistent under concurrent appends.
        let reopened = EvidenceAuditLog::initialize(
            &path,
            256 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("a chain grown under concurrency verifies on restart");
        assert!(
            reopened.ready().await,
            "the reopened chain verifies end to end"
        );
    }

    #[tokio::test]
    async fn restart_verifies_a_nonempty_keyed_chain_before_accepting_appends() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                64 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            log.append(event(&log)).await.expect("event appends");
        }

        let restarted = EvidenceAuditLog::initialize(
            &path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("a valid nonempty chain verifies on restart");
        assert!(restarted.ready().await);
        assert_eq!(restarted.sink.full_verifications.load(Ordering::Relaxed), 1);
        restarted
            .append(event(&restarted))
            .await
            .expect("verified restarted chain accepts an append");
    }

    #[tokio::test]
    async fn restart_rejects_same_length_chain_corruption() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                64 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            log.append(event(&log)).await.expect("event appends");
        }

        let mut external = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("audit file opens for corruption");
        external
            .seek(SeekFrom::Start(0))
            .and_then(|_| external.write_all(b"["))
            .and_then(|_| external.sync_all())
            .expect("same-length corruption persists");

        assert!(
            EvidenceAuditLog::initialize(
                &path,
                64 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .is_err(),
            "restart must reject a corrupted keyed chain"
        );
    }

    #[tokio::test]
    async fn restart_rejects_a_truncated_final_record() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                64 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            log.append(event(&log)).await.expect("event appends");
        }

        let original_length = std::fs::metadata(&path)
            .expect("audit metadata reads")
            .len();
        assert!(original_length > 8, "fixture record has truncation room");
        let external = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("audit file opens for truncation");
        external
            .set_len(original_length - 8)
            .and_then(|_| external.sync_all())
            .expect("truncation persists");

        assert!(
            EvidenceAuditLog::initialize(
                &path,
                64 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .is_err(),
            "restart must reject a truncated keyed chain"
        );
    }

    #[tokio::test]
    async fn restart_rejects_the_wrong_audit_key() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                64 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            log.append(event(&log)).await.expect("event appends");
        }

        assert!(
            EvidenceAuditLog::initialize(
                &path,
                64 * 1024,
                b"fedcba9876543210fedcba9876543210".to_vec(),
                1,
            )
            .await
            .is_err(),
            "restart must reject a keyed chain under a different audit secret"
        );
    }

    #[tokio::test]
    async fn same_length_external_mutation_fails_readiness_and_future_appends() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        log.append(event(&log)).await.expect("event appends");

        std::thread::sleep(std::time::Duration::from_millis(2));
        let mut external = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("audit file opens for mutation");
        external
            .seek(SeekFrom::Start(0))
            .and_then(|_| external.write_all(b"["))
            .and_then(|_| external.sync_all())
            .expect("same-length mutation persists");

        assert!(!log.ready().await);
        assert!(log.append(event(&log)).await.is_err());
        assert_eq!(log.sink.full_verifications.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn invalid_release_shape_and_size_limit_fail_closed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log =
            EvidenceAuditLog::initialize(&path, 1, b"0123456789abcdef0123456789abcdef".to_vec(), 1)
                .await
                .expect("audit initializes");
        assert!(log.append(event(&log)).await.is_err());

        let mut invalid = event(&log);
        invalid.phase = AuditPhase::DisclosureRelease;
        assert!(matches!(
            log.append(invalid).await,
            Err(EvidenceAuditError::InvalidEvent)
        ));
    }

    #[tokio::test]
    async fn second_writer_is_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let first = EvidenceAuditLog::initialize(
            &path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("first initializes");
        let second = EvidenceAuditLog::initialize(
            &path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await;
        assert!(second.is_err());
        drop(first);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pathname_replacement_never_redirects_the_pinned_audit_writer() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let displaced = directory.path().join("displaced.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            64 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");

        std::fs::rename(&path, &displaced).expect("initialized file is displaced");
        std::fs::write(&path, b"replacement-canary\n").expect("replacement is created");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("replacement mode is owner-only");

        assert!(log.append(event(&log)).await.is_err());
        assert!(!log.ready().await);
        assert_eq!(
            std::fs::read_to_string(&path).expect("replacement reads"),
            "replacement-canary\n"
        );
        assert_eq!(
            std::fs::read_to_string(&displaced).expect("pinned file reads"),
            ""
        );
    }
}

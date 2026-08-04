//! Fail-closed native Evidence audit with a durable keyed JSONL chain.

use std::{
    fs::{File, TryLockError},
    io::{BufRead as _, BufReader, Error as IoError, ErrorKind, Read as _, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_audit::{
    verify_jsonl_lines_with_hasher, AuditChainHasher, AuditEnvelope, AuditError, AuditHashSecret,
    AuditKeyHasher, OptionalHashHex,
};
use serde::Serialize;
use thiserror::Error;

use crate::config::AssuranceProfile;

const AUDIT_SCHEMA: &str = "registry.evidence.audit/v1";
const MAX_AUDIT_LINE_BYTES: usize = 1024 * 1024;
/// Sealed segments are named `<path>.<sequence>` with a zero-padded,
/// fixed-width sequence, so lexical order matches chain order and the sink's
/// `.lock` companion can never be mistaken for a segment.
const SEGMENT_SEQUENCE_DIGITS: usize = 8;

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
    pub assurance_profile: AssuranceProfile,
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
        assurance_profile: AssuranceProfile,
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
            assurance_profile,
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
    /// A span of sealed history is absent. Reported separately from a hash
    /// break so an operator can tell deliberate archival from tampering.
    #[error("audit chain is missing sealed segment {sequence}")]
    SegmentMissing { sequence: u64 },
}

/// The chain's on-disk footprint, sealed segments and the active segment
/// together.
///
/// Rotation never deletes a sealed segment, so this only falls when an
/// operator archives one. That is why it is measured by walking the segment
/// directory rather than accumulated in a counter: a counter would keep
/// reporting bytes an operator had already reclaimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditStorageUsage {
    pub segments: usize,
    pub bytes: u64,
}

pub struct EvidenceAuditLog {
    sink: Arc<DurableJsonlSink>,
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
        let sink = Arc::new(DurableJsonlSink::open(
            path.into(),
            maximum_file_bytes,
            chain_hasher,
        )?);
        // The sink owns the chain head rather than a separate chain object,
        // because the head has to advance in the same lock that claims a place
        // in the pending batch.
        sink.verify_startup().await?;
        Ok(Self {
            sink,
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

    /// Measure the chain's footprint for the capacity gauge.
    ///
    /// This walks the audit directory, so it runs on the blocking pool: the
    /// number of sealed segments grows without bound and the caller is a
    /// scrape handler on the async runtime. A segment that disappears midway
    /// through the walk is skipped rather than failing the read, because an
    /// operator archiving history concurrently is expected, not an error.
    pub async fn storage_usage(&self) -> Result<AuditStorageUsage, EvidenceAuditError> {
        let path = self.sink.path.clone();
        tokio::task::spawn_blocking(move || {
            let segments = audit_segment_paths(&path)?;
            let mut bytes = 0u64;
            let mut counted = 0usize;
            for segment in &segments {
                match std::fs::symlink_metadata(segment) {
                    Ok(metadata) => {
                        counted += 1;
                        bytes = bytes.saturating_add(metadata.len());
                    }
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => return Err(AuditError::Io(error)),
                }
            }
            Ok(AuditStorageUsage {
                segments: counted,
                bytes,
            })
        })
        .await
        .map_err(|error| AuditError::Io(IoError::other(error)))?
        .map_err(EvidenceAuditError::from)
    }

    pub async fn append(
        &self,
        event: EvidenceAuditEvent,
    ) -> Result<AuditEnvelope, EvidenceAuditError> {
        event.validate_phase_fields()?;
        let record = serde_json::to_value(event).map_err(AuditError::Json)?;
        self.sink
            .append_record(record)
            .await
            .map_err(EvidenceAuditError::Audit)
    }

    pub async fn ready(&self) -> bool {
        self.sink.ready().await
    }

    /// Durable writes performed so far, for proving that concurrent appends
    /// share them rather than each paying an `fsync`.
    #[cfg(test)]
    pub(crate) fn durable_writes(&self) -> usize {
        self.sink.durable_writes.load(Ordering::Relaxed)
    }
}

struct DurableJsonlSink {
    path: PathBuf,
    lock_path: PathBuf,
    maximum_file_bytes: u64,
    hasher: AuditChainHasher,
    state: tokio::sync::Mutex<SinkState>,
    /// Held by whichever caller is performing the current durable write, so
    /// exactly one runs at a time and the rest queue behind it. Separate from
    /// `state` because the write must not hold the state lock: appends arriving
    /// during it are what form the next batch.
    flush: tokio::sync::Mutex<()>,
    /// Highest enqueue position known to be on disk. Compared against a
    /// caller's own position to decide whether it still has to write.
    durable: AtomicU64,
    _writer_lock: File,
    #[cfg(test)]
    full_verifications: AtomicUsize,
    #[cfg(test)]
    durable_writes: AtomicUsize,
}

/// Writer state guarded by the sink mutex. The active segment handle lives here
/// rather than on the sink because rotation replaces it, and the replacement
/// must become visible to the next writer atomically with the sequence and
/// fingerprint it belongs to.
struct SinkState {
    verified: bool,
    fingerprint: FileFingerprint,
    tail_hash: Option<[u8; 32]>,
    audit_file: File,
    next_sequence: u64,
    /// Serialized records that have taken a chain position but are not on disk
    /// yet. Always exactly the records between `durable` and `enqueued`.
    pending: Vec<String>,
    /// Chain positions handed out so far, counting from one.
    enqueued: u64,
    /// Why the sink stopped accepting writes. Set when a durable write fails,
    /// which leaves the in-memory head ahead of the disk.
    poison: Option<String>,
}

impl SinkState {
    /// Refuse work the sink can no longer perform safely.
    ///
    /// A poisoned sink stays poisoned for the process's life. That is
    /// deliberate: after a failed durable write the head has advanced past
    /// records the disk never received, so any later append would chain onto
    /// something that does not exist. Failing every request is visible;
    /// continuing would fork the chain silently.
    fn check_writable(&self) -> Result<(), AuditError> {
        if let Some(reason) = &self.poison {
            return Err(AuditError::Io(IoError::other(format!(
                "audit sink stopped after a failed durable write: {reason}"
            ))));
        }
        if !self.verified {
            return Err(AuditError::Io(IoError::other(
                "audit chain was not verified at startup",
            )));
        }
        Ok(())
    }
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
    fn open(
        path: PathBuf,
        maximum_file_bytes: u64,
        hasher: AuditChainHasher,
    ) -> Result<Self, AuditError> {
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

        // A pre-existing active segment larger than the configured bound is not
        // an error: `maximum_file_bytes` is a rotation threshold, so an
        // oversized segment is simply sealed by the next append. Refusing to
        // start would turn a lowered bound into an outage.
        let created = !path.exists();
        let file = open_append_nofollow(&path)?;
        validate_owner_only_regular_file(&file)?;
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
        let next_sequence = newest_sealed_sequence(&path)?
            .map_or(1, |sequence| sequence.checked_add(1).unwrap_or(sequence));
        Ok(Self {
            path,
            lock_path,
            maximum_file_bytes,
            hasher,
            state: tokio::sync::Mutex::new(SinkState {
                verified: false,
                fingerprint,
                tail_hash: None,
                audit_file: file,
                next_sequence,
                pending: Vec::new(),
                enqueued: 0,
                poison: None,
            }),
            flush: tokio::sync::Mutex::new(()),
            durable: AtomicU64::new(0),
            _writer_lock: writer_lock,
            #[cfg(test)]
            full_verifications: AtomicUsize::new(0),
            #[cfg(test)]
            durable_writes: AtomicUsize::new(0),
        })
    }

    async fn ready(&self) -> bool {
        // Waiting for this lock is safe and a non-blocking acquire would not be:
        // the writer holds it only long enough to claim a chain position, never
        // across a durable write, so contention here means the service is busy
        // rather than unhealthy and refusing to wait would report a working
        // service as unready under its own load. The one long hold, the startup
        // scan that establishes the authenticated chain head, completes before
        // the service serves.
        let state = self.state.lock().await;
        if state.check_writable().is_err() {
            return false;
        }
        let path = self.path.clone();
        let lock_path = self.lock_path.clone();
        let Ok(file) = state.audit_file.try_clone() else {
            return false;
        };
        let Ok(writer_lock) = self._writer_lock.try_clone() else {
            return false;
        };
        // The recorded fingerprint only describes the file between durable
        // writes, so it is only compared when nothing is queued and everything
        // enqueued is on disk. While a write is in flight the file legitimately
        // differs from it, and that write validates its own pinned identity and
        // resulting length before reporting success, so an append is never the
        // thing that has to be caught here. Both reads happen under the lock the
        // writer advances them under: outside it, the service's own traffic
        // would look like external mutation.
        let quiescent =
            state.pending.is_empty() && self.durable.load(Ordering::Acquire) == state.enqueued;
        if quiescent {
            let Ok(metadata) = file.metadata() else {
                return false;
            };
            let Ok(observed) = file_fingerprint(&file) else {
                return false;
            };
            if !metadata.is_file() || observed != state.fingerprint {
                return false;
            }
        }
        // The probe's own sync must not hold the state lock: appends take it to
        // claim a chain position, and readiness is not allowed to stall them.
        drop(state);
        // Segment length is deliberately not a health property: with rotation a
        // full segment is a routine state the next append resolves, and a
        // lowered bound would otherwise wedge the service permanently unready.
        tokio::task::spawn_blocking(move || -> Result<bool, AuditError> {
            validate_pinned_path(&path, &file)?;
            validate_pinned_path(&lock_path, &writer_lock)?;
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

    /// Establish the authenticated chain head at startup.
    ///
    /// Only the active segment is replayed. The head it continues from is the
    /// last record of the newest sealed segment, read on its own, so restart
    /// cost is bounded by one segment rather than by all retained history.
    /// Proving sealed segments is the job of [`verify_audit_chain`], run out of
    /// band; corruption inside an already sealed segment is therefore not
    /// caught at startup.
    fn verify_and_tail(
        path: &Path,
        file: File,
        hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        let sealed_head = sealed_tail_hash(path, hasher)?;
        Ok(verify_reader(file, hasher, sealed_head)?.head)
    }
}

impl DurableJsonlSink {
    /// Enqueue one record and return once it is durable.
    ///
    /// The chain head advances under `state`, so records take chain positions
    /// in enqueue order. Nothing under that lock touches the filesystem, which
    /// is what lets appends arriving during a durable write join the next one
    /// instead of queueing behind an `fsync`.
    async fn append_record(&self, record: serde_json::Value) -> Result<AuditEnvelope, AuditError> {
        let (envelope, position) = {
            let mut state = self.state.lock().await;
            state.check_writable()?;
            let envelope = AuditEnvelope::new_with_hasher(record, state.tail_hash, &self.hasher)?;
            let line = envelope.to_jsonl()?;
            // Checked before the head advances, so a record too large for an
            // empty segment fails on its own rather than poisoning the batch it
            // would otherwise have joined.
            let incoming = u64::try_from(line.len()).map_err(|_| file_size_error())?;
            if incoming > self.maximum_file_bytes {
                return Err(file_size_error());
            }
            state.pending.push(line);
            state.enqueued = state.enqueued.saturating_add(1);
            state.tail_hash = Some(envelope.record_hash);
            (envelope, state.enqueued)
        };
        self.flush_through(position).await?;
        Ok(envelope)
    }

    /// Return once every record up to `position` is on disk.
    ///
    /// The first caller to arrive while no write is in flight writes everything
    /// queued so far; the rest wait and find their records already durable.
    /// There is no timer and no configured window: a batch is exactly what
    /// accumulated during the previous write, so it is one record on an idle
    /// service and grows by itself under load.
    async fn flush_through(&self, position: u64) -> Result<(), AuditError> {
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

    /// Write and sync everything currently queued.
    ///
    /// The caller holds `flush`, so exactly one of these runs at a time and the
    /// batch it takes is never split with another writer.
    async fn flush_once(&self) -> Result<(), AuditError> {
        let (request, through) = {
            let mut state = self.state.lock().await;
            state.check_writable()?;
            if state.pending.is_empty() {
                return Ok(());
            }
            let request = BlockingAppend {
                lines: std::mem::take(&mut state.pending),
                path: self.path.clone(),
                lock_path: self.lock_path.clone(),
                maximum: self.maximum_file_bytes,
                expected_fingerprint: state.fingerprint,
                sequence: state.next_sequence,
                file: state.audit_file.try_clone().map_err(AuditError::Io)?,
                writer_lock: self._writer_lock.try_clone().map_err(AuditError::Io)?,
            };
            (request, state.enqueued)
        };
        #[cfg(test)]
        self.durable_writes.fetch_add(1, Ordering::Relaxed);
        let (rotated, appended) = tokio::task::spawn_blocking(move || request.run())
            .await
            .map_err(|error| AuditError::Io(IoError::other(error)))?;

        let mut state = self.state.lock().await;
        // Adopt a replaced segment even when the write that triggered the
        // rotation then failed. The rename already happened on disk, so leaving
        // the pinned handle on the sealed segment would fail
        // `validate_pinned_path` on every later append and wedge the sink.
        if let Some(sealed) = rotated {
            state.audit_file = sealed.active;
            state.next_sequence = sealed.next_sequence;
            state.fingerprint = file_fingerprint(&state.audit_file)?;
        }
        match appended {
            Ok(fingerprint) => {
                state.fingerprint = fingerprint;
                drop(state);
                self.durable.store(through, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                state.poison = Some(error.to_string());
                Err(error)
            }
        }
    }

    /// Establish the authenticated chain head at startup.
    async fn verify_startup(&self) -> Result<Option<[u8; 32]>, AuditError> {
        let mut state = self.state.lock().await;
        let path = self.path.clone();
        let lock_path = self.lock_path.clone();
        let hasher = self.hasher.clone();
        let file = state.audit_file.try_clone().map_err(AuditError::Io)?;
        let writer_lock = self._writer_lock.try_clone().map_err(AuditError::Io)?;
        #[cfg(test)]
        self.full_verifications.fetch_add(1, Ordering::Relaxed);
        let (tail_hash, fingerprint) = tokio::task::spawn_blocking(move || {
            validate_pinned_path(&path, &file)?;
            validate_pinned_path(&lock_path, &writer_lock)?;
            let tail_hash =
                Self::verify_and_tail(&path, file.try_clone().map_err(AuditError::Io)?, &hasher)?;
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

/// The record hash a segment ended on, and how many records it held.
struct SegmentVerification {
    head: Option<[u8; 32]>,
    records: usize,
}

/// Replay one segment, requiring its first record to continue `expected_head`.
/// `None` means the segment must start the chain at genesis, which is what the
/// only segment of an unrotated chain does.
fn verify_reader(
    mut file: File,
    hasher: &AuditChainHasher,
    expected_head: Option<[u8; 32]>,
) -> Result<SegmentVerification, AuditError> {
    file.seek(SeekFrom::Start(0)).map_err(AuditError::Io)?;
    let mut reader = BufReader::new(file);
    let mut expected_previous = expected_head;
    let mut records = 0usize;
    while let Some(line) = read_bounded_jsonl_line(&mut reader)? {
        let verification = verify_jsonl_lines_with_hasher([line.trim_end_matches('\n')], hasher)
            .map_err(AuditError::ChainVerification)?;
        if verification.start_prev_hash != expected_previous {
            return Err(AuditError::ChainForkDetected {
                expected: OptionalHashHex(expected_previous),
                found: OptionalHashHex(verification.start_prev_hash),
            });
        }
        expected_previous = verification.last_hash;
        records += verification.records;
    }
    Ok(SegmentVerification {
        head: expected_previous,
        records,
    })
}

/// A sealed segment and the sequence the next rotation will claim.
struct SealedSegment {
    active: File,
    next_sequence: u64,
}

/// The blocking half of one durable append.
///
/// This is a struct rather than a closure so that a rotation can be reported
/// back to the caller on the failure path as well as the success path: once the
/// rename has happened the writer state must follow it regardless of what the
/// subsequent write did.
struct BlockingAppend {
    lines: Vec<String>,
    path: PathBuf,
    lock_path: PathBuf,
    maximum: u64,
    expected_fingerprint: FileFingerprint,
    sequence: u64,
    file: File,
    writer_lock: File,
}

impl BlockingAppend {
    fn run(mut self) -> (Option<SealedSegment>, Result<FileFingerprint, AuditError>) {
        let mut rotated = None;
        let appended = self.append(&mut rotated);
        (rotated, appended)
    }

    /// Write the whole batch and sync once.
    ///
    /// The batch is one `fsync` regardless of how many records it holds, which
    /// is the whole point: the cost that bounds append throughput is the sync,
    /// not the bytes. A batch that crosses the segment bound is split, and each
    /// outgoing segment is synced by its own seal before the rename.
    fn append(
        &mut self,
        rotated: &mut Option<SealedSegment>,
    ) -> Result<FileFingerprint, AuditError> {
        // This check stays first, ahead of any rotation decision. It is what
        // separates a legitimate rotation, which renames a path whose inode
        // still matches the writer's own handle, from an external rename, which
        // leaves the pinned handle naming a file the path no longer resolves to.
        validate_pinned_path(&self.path, &self.file)?;
        validate_pinned_path(&self.lock_path, &self.writer_lock)?;
        if file_fingerprint(&self.file)? != self.expected_fingerprint {
            return Err(AuditError::Io(IoError::other(
                "audit file changed outside the initialized writer",
            )));
        }
        let mut current = self.file.metadata().map_err(AuditError::Io)?.len();
        let lines = std::mem::take(&mut self.lines);
        let mut run = String::new();
        for line in &lines {
            let incoming = u64::try_from(line.len()).map_err(|_| file_size_error())?;
            // A record that cannot fit an empty segment must fail closed rather
            // than rotate forever looking for room it will never find.
            if incoming > self.maximum {
                return Err(file_size_error());
            }
            if current.saturating_add(incoming) > self.maximum && current > 0 {
                // Everything buffered for the outgoing segment has to reach it
                // before the seal, because the seal is what syncs and renames
                // it. `seal_active_segment` relies on a sealed segment never
                // holding a torn record.
                self.file
                    .write_all(run.as_bytes())
                    .map_err(AuditError::Io)?;
                self.file.flush().map_err(AuditError::Io)?;
                run.clear();
                let sealed = seal_active_segment(&self.path, &self.file, self.sequence)?;
                self.file = sealed.active.try_clone().map_err(AuditError::Io)?;
                self.sequence = sealed.next_sequence;
                current = 0;
                // Only the newest replacement matters to the caller: it is the
                // handle and sequence the writer state must adopt.
                *rotated = Some(sealed);
            }
            run.push_str(line);
            current = current.saturating_add(incoming);
        }
        self.file
            .write_all(run.as_bytes())
            .map_err(AuditError::Io)?;
        self.file.flush().map_err(AuditError::Io)?;
        self.file.sync_all().map_err(AuditError::Io)?;
        validate_pinned_path(&self.path, &self.file)?;
        validate_pinned_path(&self.lock_path, &self.writer_lock)?;
        let fingerprint = file_fingerprint(&self.file)?;
        if fingerprint.length != current {
            return Err(AuditError::Io(IoError::other(
                "audit file length changed during append",
            )));
        }
        Ok(fingerprint)
    }
}

fn segment_path(path: &Path, sequence: u64) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(format!(
        ".{sequence:0width$}",
        width = SEGMENT_SEQUENCE_DIGITS
    ));
    PathBuf::from(value)
}

/// Recognize `candidate` as a sealed segment of the chain rooted at `path` and
/// return its sequence.
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

/// Enumerate the sealed segments of the chain rooted at `path`, oldest first.
///
/// Enumeration reads the directory and parses suffixes rather than probing
/// sequences upward from one, so a missing middle segment shows up as a gap
/// instead of silently truncating the set to the segments before it.
fn sealed_segments(path: &Path) -> Result<Vec<(u64, PathBuf)>, AuditError> {
    let parent = path.parent().ok_or_else(|| {
        AuditError::Io(IoError::new(
            ErrorKind::InvalidInput,
            "audit path has no parent",
        ))
    })?;
    let mut sealed = Vec::new();
    for entry in std::fs::read_dir(parent).map_err(AuditError::Io)? {
        let candidate = entry.map_err(AuditError::Io)?.path();
        if let Some(sequence) = segment_sequence(path, &candidate) {
            sealed.push((sequence, candidate));
        }
    }
    sealed.sort_unstable_by_key(|(sequence, _)| *sequence);
    Ok(sealed)
}

/// Enumerate the chain's segments oldest first: every sealed segment in
/// sequence order, then the active segment when it exists.
pub fn audit_segment_paths(path: &Path) -> Result<Vec<PathBuf>, AuditError> {
    let mut segments: Vec<PathBuf> = sealed_segments(path)?
        .into_iter()
        .map(|(_, path)| path)
        .collect();
    if std::fs::symlink_metadata(path).is_ok() {
        segments.push(path.to_path_buf());
    }
    Ok(segments)
}

fn newest_sealed_segment(path: &Path) -> Result<Option<(u64, PathBuf)>, AuditError> {
    Ok(sealed_segments(path)?.pop())
}

fn newest_sealed_sequence(path: &Path) -> Result<Option<u64>, AuditError> {
    Ok(newest_sealed_segment(path)?.map(|(sequence, _)| sequence))
}

/// Seal the active segment under the next free sequence and open an empty
/// replacement at the configured path.
///
/// Chain continuity needs nothing extra here: the head lives in memory and
/// survives rotation, so the first record written after this call carries the
/// sealed segment's last record hash as its predecessor.
///
/// Crashing between the rename and the replacement leaves no active segment.
/// Startup recreates it and recovers the head from the sealed tail, so the seam
/// still closes. This assumes the filesystem does not reorder the rename after
/// the create; a filesystem that does could lose a segment silently.
///
/// One invariant here is load-bearing for reading a sealed segment's last
/// record on its own: a sealed segment can never hold a torn final record,
/// because rotation only ever renames a file every one of whose records
/// returned from a successful `sync_all`.
fn seal_active_segment(
    path: &Path,
    active: &File,
    sequence: u64,
) -> Result<SealedSegment, AuditError> {
    let parent = path.parent().ok_or_else(|| {
        AuditError::Io(IoError::new(
            ErrorKind::InvalidInput,
            "audit path has no parent",
        ))
    })?;
    active.sync_all().map_err(AuditError::Io)?;

    // Never rename over an existing sealed segment: that would erase history.
    // The exclusive writer lock makes this process the only Evidence writer for
    // this chain, so probing for a free sequence cannot race another sink.
    let mut sequence = sequence;
    let mut sealed = segment_path(path, sequence);
    while std::fs::symlink_metadata(&sealed).is_ok() {
        sequence = next_sequence(sequence)?;
        sealed = segment_path(path, sequence);
    }
    std::fs::rename(path, &sealed).map_err(AuditError::Io)?;

    let replacement = open_append_nofollow(path)?;
    validate_owner_only_regular_file(&replacement)?;
    if replacement.metadata().map_err(AuditError::Io)?.len() != 0 {
        return Err(AuditError::Io(IoError::other(
            "replacement audit segment is not empty",
        )));
    }
    replacement.sync_all().map_err(AuditError::Io)?;
    sync_parent(parent)?;
    Ok(SealedSegment {
        active: replacement,
        next_sequence: next_sequence(sequence)?,
    })
}

fn next_sequence(sequence: u64) -> Result<u64, AuditError> {
    sequence
        .checked_add(1)
        .ok_or_else(|| AuditError::Io(IoError::other("audit segment sequence is exhausted")))
}

/// Recover the chain head an active segment continues from by reading only the
/// last record of the newest sealed segment.
fn sealed_tail_hash(
    path: &Path,
    hasher: &AuditChainHasher,
) -> Result<Option<[u8; 32]>, AuditError> {
    let Some((_, newest)) = newest_sealed_segment(path)? else {
        return Ok(None);
    };
    let file = open_sealed_segment(&newest)?;
    // An empty newest sealed segment is a hard error, never a fall back to
    // genesis: otherwise truncating the sealed tail and the active segment to
    // zero would start a clean chain in a directory full of history.
    let Some(line) = last_jsonl_line(file)? else {
        return Err(AuditError::Io(IoError::new(
            ErrorKind::InvalidData,
            "sealed audit segment holds no records",
        )));
    };
    let verification = verify_jsonl_lines_with_hasher([line.trim_end_matches('\n')], hasher)
        .map_err(AuditError::ChainVerification)?;
    Ok(verification.last_hash)
}

/// Read a segment's final complete record without reading the segment, bounded
/// by the same per-record limit the forward reader enforces.
fn last_jsonl_line(mut file: File) -> Result<Option<String>, AuditError> {
    let length = file.metadata().map_err(AuditError::Io)?.len();
    if length == 0 {
        return Ok(None);
    }
    let bound = u64::try_from(MAX_AUDIT_LINE_BYTES.saturating_add(1)).unwrap_or(u64::MAX);
    let window = bound.min(length);
    file.seek(SeekFrom::Start(length - window))
        .map_err(AuditError::Io)?;
    let mut tail = vec![
        0u8;
        usize::try_from(window).map_err(|_| AuditError::Io(IoError::other(
            "audit segment tail is unreadable"
        )))?
    ];
    file.read_exact(&mut tail).map_err(AuditError::Io)?;
    if tail.pop() != Some(b'\n') {
        return Err(AuditError::Io(IoError::new(
            ErrorKind::InvalidData,
            "sealed audit segment has an incomplete final record",
        )));
    }
    let start = tail
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    if start == 0 && window < length {
        return Err(AuditError::Io(IoError::new(
            ErrorKind::InvalidData,
            "audit JSONL record exceeds its bound",
        )));
    }
    let line = String::from_utf8(tail[start..].to_vec()).map_err(|_| {
        AuditError::Io(IoError::new(
            ErrorKind::InvalidData,
            "audit JSONL is not UTF-8",
        ))
    })?;
    Ok(Some(line))
}

/// Open a sealed segment for reading.
///
/// Sealed segments are read-only history, so link count is deliberately not
/// checked here: the single-link rule exists to pin the *active* writer's file,
/// while an operator archiving sealed history with a hard link is legitimate.
/// Ownership and mode still are checked, so a segment another user could have
/// written is never read, and `O_NOFOLLOW` still rejects a symlink planted at a
/// segment name.
fn open_sealed_segment(path: &Path) -> Result<File, AuditError> {
    let file = open_read_nofollow(path)?;
    validate_owner_only_readable_file(&file)?;
    Ok(file)
}

/// Result of an out-of-band verification pass over a whole audit chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditChainSummary {
    /// Segments actually replayed.
    pub segments: usize,
    pub records: usize,
    pub head: Option<[u8; 32]>,
    /// Sequence of the oldest and newest sealed segments, absent when the chain
    /// has never rotated.
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    /// Whether the active segment was replayed. False when a running writer
    /// holds the chain, in which case only sealed history was proven.
    pub active_verified: bool,
}

/// Verify every segment of an audit chain, sealed history included.
///
/// Startup verification is deliberately bounded to the active segment so that
/// restart time does not grow with retained history. This is its counterpart:
/// a full replay across every seam, meant to run out of band, and the only
/// check that detects tampering inside an already sealed segment.
///
/// A gap in the sealed sequence is reported as [`EvidenceAuditError::SegmentMissing`]
/// naming the absent sequence, not as a hash break, so that history an operator
/// archived is distinguishable from history someone rewrote.
///
/// The active segment is only replayed when the writer lock is free. Against a
/// running service it would race an in-flight append and report a partially
/// written final record as corruption, so it is skipped and `active_verified`
/// says so.
pub fn verify_audit_chain(
    path: &Path,
    master_secret: &AuditHashSecret,
) -> Result<AuditChainSummary, EvidenceAuditError> {
    let hasher = AuditChainHasher::keyed(master_secret.clone());
    let sealed = sealed_segments(path).map_err(EvidenceAuditError::Audit)?;
    let first_sequence = sealed.first().map(|(sequence, _)| *sequence);
    let last_sequence = sealed.last().map(|(sequence, _)| *sequence);
    if let Some(first) = first_sequence {
        for (offset, (sequence, _)) in sealed.iter().enumerate() {
            let expected = first.saturating_add(offset as u64);
            if *sequence != expected {
                return Err(EvidenceAuditError::SegmentMissing { sequence: expected });
            }
        }
    }

    let mut head = None;
    let mut records = 0usize;
    let mut segments = 0usize;
    for (_, segment) in &sealed {
        let file = open_sealed_segment(segment).map_err(EvidenceAuditError::Audit)?;
        let verification = verify_reader(file, &hasher, head).map_err(EvidenceAuditError::Audit)?;
        head = verification.head;
        records = records.saturating_add(verification.records);
        segments = segments.saturating_add(1);
    }

    let active_verified = match active_segment_if_quiescent(path)? {
        Some(file) => {
            let verification =
                verify_reader(file, &hasher, head).map_err(EvidenceAuditError::Audit)?;
            head = verification.head;
            records = records.saturating_add(verification.records);
            segments = segments.saturating_add(1);
            true
        }
        None => false,
    };

    Ok(AuditChainSummary {
        first_sequence,
        last_sequence,
        active_verified,
        segments,
        records,
        head,
    })
}

/// Open the active segment for verification, but only if no writer holds the
/// chain. Returns `None` when a live Evidence process owns the lock, or when
/// the active segment is absent because a crash landed between the rename and
/// the replacement.
fn active_segment_if_quiescent(path: &Path) -> Result<Option<File>, EvidenceAuditError> {
    let lock_path = lock_path(path);
    if lock_path.exists() {
        let guard = open_lock_nofollow(&lock_path).map_err(EvidenceAuditError::Audit)?;
        match guard.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Ok(None),
            Err(TryLockError::Error(error)) => {
                return Err(EvidenceAuditError::Audit(AuditError::Io(error)))
            }
        }
    }
    if !std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file()) {
        return Ok(None);
    }
    let file = open_read_nofollow(path).map_err(EvidenceAuditError::Audit)?;
    validate_owner_only_regular_file(&file).map_err(EvidenceAuditError::Audit)?;
    Ok(Some(file))
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

/// The owner-only checks that apply to any audit file, with the single-link
/// requirement left out. See [`open_sealed_segment`] for why sealed history is
/// allowed more than one name.
#[cfg(unix)]
fn validate_owner_only_readable_file(file: &File) -> Result<(), AuditError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata().map_err(AuditError::Io)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(AuditError::Io(IoError::new(
            ErrorKind::PermissionDenied,
            "audit files must be owner-only regular files",
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_only_readable_file(file: &File) -> Result<(), AuditError> {
    validate_owner_only_regular_file(file)
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
            AssuranceProfile::EvidenceGrade,
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
            assurance_profile: AssuranceProfile::EvidenceGrade,
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

    fn audit_secret() -> AuditHashSecret {
        AuditHashSecret::new(b"0123456789abcdef0123456789abcdef".to_vec())
            .expect("audit secret builds")
    }

    /// Change one byte of a record without changing its length, so the record
    /// no longer matches the hash the chain recorded for it.
    fn corrupt_line(line: &str) -> String {
        let mut bytes = line.as_bytes().to_vec();
        for byte in bytes.iter_mut() {
            if byte.is_ascii_lowercase() {
                *byte = if *byte == b'z' { b'y' } else { *byte + 1 };
                break;
            }
        }
        String::from_utf8(bytes).expect("a corrupted record stays UTF-8")
    }

    fn rewrite_segment_line(path: &Path, index: usize, rewrite: impl Fn(&str) -> String) {
        let contents = std::fs::read_to_string(path).expect("segment reads");
        let mut lines: Vec<String> = contents.lines().map(str::to_owned).collect();
        lines[index] = rewrite(&lines[index]);
        let mut rewritten = lines.join("\n");
        rewritten.push('\n');
        std::fs::write(path, rewritten).expect("segment rewrites");
    }

    /// Readiness reports on the chain, not on how busy the writer is. The
    /// fingerprint it compares is the one the writer advances on every append,
    /// so a probe that read it outside the writer's lock would see the
    /// service's own traffic as external mutation and flap under load.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn readiness_holds_while_appends_are_in_flight() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = Arc::new(
            EvidenceAuditLog::initialize(
                &path,
                1024 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes"),
        );

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut writers = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let log = Arc::clone(&log);
            let stop = Arc::clone(&stop);
            writers.spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    log.append(event(&log)).await.expect("event appends");
                }
            });
        }

        // Probe often enough to land inside a durable write rather than only in
        // the gaps between them, which is the window the race lives in.
        let mut probes = 0usize;
        let mut unready = 0usize;
        for _ in 0..200 {
            if log.ready().await {
                probes += 1;
            } else {
                unready += 1;
            }
            tokio::task::yield_now().await;
        }
        stop.store(true, Ordering::Relaxed);
        while let Some(result) = writers.join_next().await {
            result.expect("writer task joins");
        }

        assert_eq!(
            unready, 0,
            "readiness stayed true through {probes} probes but reported unready {unready} times while the service was writing its own audit records"
        );
    }

    /// The point of group commit: appends that arrive while a durable write is
    /// in flight join the next one instead of each paying their own `fsync`.
    #[tokio::test]
    async fn concurrent_appends_share_durable_writes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = Arc::new(
            EvidenceAuditLog::initialize(
                &path,
                1024 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes"),
        );

        const APPENDS: usize = 64;
        let mut appends = tokio::task::JoinSet::new();
        for _ in 0..APPENDS {
            let log = Arc::clone(&log);
            appends.spawn(async move { log.append(event(&log)).await.expect("event appends") });
        }
        let mut hashes = Vec::new();
        while let Some(result) = appends.join_next().await {
            hashes.push(result.expect("append task joins").record_hash);
        }
        hashes.sort_unstable();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            APPENDS,
            "every concurrent append gets its own chain position"
        );

        let writes = log.durable_writes();
        assert!(
            writes < APPENDS,
            "concurrent appends must share durable writes, saw {writes} for {APPENDS} records"
        );
        drop(log);

        let summary = verify_audit_chain(&path, &audit_secret()).expect("chain verifies");
        assert_eq!(
            summary.records, APPENDS,
            "batching must not drop or duplicate a record"
        );
        assert!(summary.active_verified);
    }

    /// A durable write that fails leaves the in-memory head ahead of the disk,
    /// so the sink must refuse everything afterwards rather than chain onto a
    /// record that was never written.
    #[tokio::test]
    async fn a_failed_durable_write_poisons_the_sink_instead_of_forking_the_chain() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            1024 * 1024,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        log.append(event(&log)).await.expect("event appends");
        assert!(log.ready().await);

        // Truncating through a second handle leaves the writer's pinned handle
        // valid but the file no longer the one it fingerprinted.
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("external truncation opens");

        let failed = log.append(event(&log)).await;
        assert!(
            failed.is_err(),
            "an externally modified file fails the write"
        );

        let after = log.append(event(&log)).await;
        assert!(
            after.is_err(),
            "the sink stays failed rather than continuing on a head the disk never received"
        );
        assert!(
            !log.ready().await,
            "a poisoned sink never reports itself ready again"
        );
    }

    /// Callers wait for a batch they did not write, so a batch that fails has
    /// to hand every one of them the failure. Waiting on a durable write that
    /// will never arrive would hang the request that asked for the audit
    /// record, which is a worse outcome than refusing it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_poisoned_sink_fails_concurrent_waiters_instead_of_hanging_them() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = Arc::new(
            EvidenceAuditLog::initialize(
                &path,
                1024 * 1024,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes"),
        );
        log.append(event(&log)).await.expect("event appends");
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("external truncation opens");
        assert!(
            log.append(event(&log)).await.is_err(),
            "an externally modified file fails the write"
        );

        let mut waiters = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let log = Arc::clone(&log);
            waiters.spawn(async move { log.append(event(&log)).await });
        }
        let outcomes = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut outcomes = Vec::new();
            while let Some(result) = waiters.join_next().await {
                outcomes.push(result.expect("append task joins"));
            }
            outcomes
        })
        .await
        .expect("a poisoned sink answers every waiter rather than hanging one");

        assert_eq!(outcomes.len(), 32);
        assert!(
            outcomes.iter().all(Result::is_err),
            "every waiter is told the chain stopped, none is handed a position that was never written"
        );
    }

    #[tokio::test]
    async fn storage_usage_counts_every_segment_and_grows_across_rotation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");

        let empty = log.storage_usage().await.expect("usage reads");
        assert_eq!(
            empty.segments, 1,
            "the active segment counts before any append"
        );
        assert_eq!(empty.bytes, 0);

        log.append(event(&log)).await.expect("event appends");
        let single = log.storage_usage().await.expect("usage reads");
        assert_eq!(single.segments, 1);
        assert!(single.bytes > 0, "an appended record occupies bytes");

        const RECORDS: usize = 24;
        for _ in 0..RECORDS {
            log.append(event(&log)).await.expect("event appends");
        }

        let rolled = log.storage_usage().await.expect("usage reads");
        assert!(
            rolled.segments > 1,
            "a bound smaller than the appended volume must roll at least once"
        );
        assert_eq!(
            rolled.segments,
            audit_segment_paths(&path)
                .expect("segments enumerate")
                .len(),
            "usage counts sealed segments as well as the active one"
        );
        assert!(
            rolled.bytes > single.bytes,
            "sealed history keeps counting toward the footprint after rotation"
        );

        // Retention is the operator's, so archiving a sealed segment must show
        // up as a smaller footprint rather than being masked by a counter that
        // only ever accumulates.
        let sealed = sealed_segments(&path).expect("sealed segments enumerate");
        let (_, oldest) = sealed.first().expect("rotation sealed a segment");
        let archived = std::fs::metadata(oldest).expect("sealed metadata").len();
        std::fs::remove_file(oldest).expect("sealed segment archives away");

        let pruned = log.storage_usage().await.expect("usage reads");
        assert_eq!(pruned.segments, rolled.segments - 1);
        assert_eq!(pruned.bytes, rolled.bytes - archived);
    }

    /// Append past the per-segment bound and prove the sealed segment and the
    /// active segment are one chain, not two independent ones.
    #[tokio::test]
    async fn appends_rotate_into_sealed_segments_and_the_chain_spans_the_seam() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");

        const RECORDS: usize = 24;
        for _ in 0..RECORDS {
            log.append(event(&log)).await.expect("event appends");
        }

        let segments = audit_segment_paths(&path).expect("segments enumerate");
        assert!(
            segments.len() > 1,
            "a bound smaller than the appended volume must roll at least once"
        );
        assert_eq!(
            segments.last().expect("an active segment exists"),
            &path,
            "the configured path stays the active segment"
        );
        assert!(
            log.ready().await,
            "the chain stays ready across its own rotation"
        );

        // Against a live writer the verifier proves sealed history only, rather
        // than racing an in-flight append and calling a partial line corruption.
        let live = verify_audit_chain(&path, &audit_secret())
            .expect("sealed history verifies while the writer runs");
        assert!(!live.active_verified);
        assert_eq!(live.segments, segments.len() - 1);
        drop(log);

        let summary = verify_audit_chain(&path, &audit_secret())
            .expect("the chain verifies across every seam");
        assert!(summary.active_verified);
        assert_eq!(summary.records, RECORDS, "no record is lost to rotation");
        assert_eq!(summary.segments, segments.len());
        assert_eq!(summary.first_sequence, Some(1));
        assert_eq!(summary.last_sequence, Some(segments.len() as u64 - 1));
    }

    /// Rotation must never be reachable ahead of the pinned-path check, or an
    /// external rename would be laundered into a legitimate-looking seal.
    #[tokio::test]
    async fn pathname_replacement_is_rejected_even_when_the_append_would_rotate() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        // Fill the active segment so the next append is one that would rotate.
        while std::fs::metadata(&path)
            .expect("active segment reads")
            .len()
            == 0
            || audit_segment_paths(&path)
                .expect("segments enumerate")
                .len()
                < 2
        {
            log.append(event(&log)).await.expect("event appends");
        }
        let sealed_before = audit_segment_paths(&path)
            .expect("segments enumerate")
            .len();

        let displaced = directory.path().join("displaced.jsonl");
        std::fs::rename(&path, &displaced).expect("the active segment is renamed away");
        std::fs::write(&path, "").expect("a replacement is planted");

        assert!(
            log.append(event(&log)).await.is_err(),
            "an append must not continue onto a replaced pathname, rotation or not"
        );
        assert!(!log.ready().await);
        assert_eq!(
            audit_segment_paths(&path)
                .expect("segments enumerate")
                .len(),
            sealed_before,
            "a rejected append must not seal anything"
        );
    }

    /// A gap in sealed history is reported as a missing segment, not as a hash
    /// break, so an operator can tell archival from tampering.
    #[tokio::test]
    async fn an_archived_middle_segment_is_reported_as_missing_not_as_corruption() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                2048,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            for _ in 0..48 {
                log.append(event(&log)).await.expect("event appends");
            }
        }
        let segments = audit_segment_paths(&path).expect("segments enumerate");
        assert!(
            segments.len() >= 4,
            "the fixture needs a sealed segment that is neither first nor last"
        );
        std::fs::remove_file(&segments[1]).expect("a middle segment is archived away");

        assert!(
            matches!(
                verify_audit_chain(&path, &audit_secret()),
                Err(EvidenceAuditError::SegmentMissing { sequence: 2 })
            ),
            "a gap must name the absent sequence rather than look like tampering"
        );
    }

    /// A restart after rotation must resume the sealed chain rather than
    /// starting a second one.
    #[tokio::test]
    async fn a_restart_after_rotation_continues_from_the_sealed_tail() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        const BEFORE: usize = 24;
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                4096,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            for _ in 0..BEFORE {
                log.append(event(&log)).await.expect("event appends");
            }
            assert!(
                audit_segment_paths(&path)
                    .expect("segments enumerate")
                    .len()
                    > 1
            );
        }

        let restarted = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("a rotated chain verifies on restart");
        restarted
            .append(event(&restarted))
            .await
            .expect("a restarted rotated chain accepts an append");
        drop(restarted);

        let summary = verify_audit_chain(&path, &audit_secret())
            .expect("the chain verifies after a restart across a seam");
        assert_eq!(summary.records, BEFORE + 1);
    }

    /// Crashing between the rename and the creation of the replacement leaves
    /// no active segment. Restart must recover the chain head from the sealed
    /// tail instead of silently beginning a new chain at genesis.
    #[tokio::test]
    async fn a_missing_active_segment_recovers_from_the_sealed_tail() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        const BEFORE: usize = 24;
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                4096,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            for _ in 0..BEFORE {
                log.append(event(&log)).await.expect("event appends");
            }
        }
        let segments = audit_segment_paths(&path).expect("segments enumerate");
        assert!(segments.len() > 1, "the fixture must have rolled");
        let sealed_records: usize = segments[..segments.len() - 1]
            .iter()
            .map(|segment| {
                std::fs::read_to_string(segment)
                    .expect("sealed segment reads")
                    .lines()
                    .count()
            })
            .sum();
        std::fs::remove_file(&path).expect("the active segment is lost to a crash");

        let restarted = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("a missing active segment is recreated");
        restarted
            .append(event(&restarted))
            .await
            .expect("appends resume after the active segment is lost");
        drop(restarted);

        let summary = verify_audit_chain(&path, &audit_secret())
            .expect("the recovered chain still spans its seams");
        assert_eq!(
            summary.records,
            sealed_records + 1,
            "the record written after recovery continues sealed history, and the \
             records lost with the active segment are not silently replaced"
        );
        assert!(
            summary.records < BEFORE + 1,
            "the fixture must actually have lost the active segment's records"
        );
        assert!(
            summary.head.is_some(),
            "the recovered chain continues rather than restarting at genesis"
        );
    }

    /// The chain head is recovered from the last record of the newest sealed
    /// segment, so corrupting that record is caught at startup.
    #[tokio::test]
    async fn a_corrupt_sealed_tail_is_rejected_at_startup() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                4096,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            for _ in 0..24 {
                log.append(event(&log)).await.expect("event appends");
            }
        }

        let segments = audit_segment_paths(&path).expect("segments enumerate");
        let newest_sealed = segments[segments.len() - 2].clone();
        let sealed_lines = std::fs::read_to_string(&newest_sealed)
            .expect("sealed segment reads")
            .lines()
            .count();
        rewrite_segment_line(&newest_sealed, sealed_lines - 1, corrupt_line);

        assert!(
            EvidenceAuditLog::initialize(
                &path,
                4096,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .is_err(),
            "a corrupt sealed tail must not be accepted as the chain head"
        );
    }

    /// Boot-time verification deliberately covers only the active segment and
    /// the sealed tail it chains to, so history is bounded rather than replayed
    /// from genesis. This pins the accepted cost: corruption inside an already
    /// sealed segment starts the service and is caught by the out-of-band
    /// verifier instead.
    #[tokio::test]
    async fn sealed_segment_corruption_passes_startup_and_fails_the_verifier() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                4096,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            for _ in 0..24 {
                log.append(event(&log)).await.expect("event appends");
            }
        }

        let segments = audit_segment_paths(&path).expect("segments enumerate");
        let oldest_sealed = segments[0].clone();
        assert!(
            std::fs::read_to_string(&oldest_sealed)
                .expect("sealed segment reads")
                .lines()
                .count()
                > 1,
            "the corrupted record must not be the sealed tail"
        );
        rewrite_segment_line(&oldest_sealed, 0, corrupt_line);

        let restarted = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("startup does not replay sealed history");
        assert!(restarted.ready().await);
        drop(restarted);

        assert!(
            verify_audit_chain(&path, &audit_secret()).is_err(),
            "the out-of-band verifier is what catches sealed-segment corruption"
        );
    }
}

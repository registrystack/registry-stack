// SPDX-License-Identifier: Apache-2.0
//! Tamper-evident audit envelopes, async sinks, and redaction helpers.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::OffsetDateTime;
use ulid::Ulid;
use zeroize::Zeroizing;

const DEFAULT_MAX_SIZE_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_MAX_FILES: u32 = 5;
const MIN_AUDIT_SECRET_BYTES: usize = 32;
const KEYED_HASH_PREFIX: &str = "hmac-sha256:";
const UNKEYED_HASH_PREFIX: &str = "sha256:";

/// One chained audit record.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEnvelope {
    /// ULID assigned by the chain when the record is appended.
    pub envelope_id: String,
    /// UTC Unix timestamp in milliseconds.
    pub timestamp_unix_ms: i64,
    /// Previous envelope hash, or `None` for the genesis record.
    #[serde(with = "option_hash_hex")]
    pub prev_hash: Option<[u8; 32]>,
    /// Consumer-owned audit event body.
    pub record: Value,
    /// Hash of `{ envelope_id, timestamp_unix_ms, prev_hash, record }`,
    /// serialized as lowercase hex in JSONL.
    #[serde(with = "hash_hex")]
    pub record_hash: [u8; 32],
}

impl fmt::Debug for AuditEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditEnvelope")
            .field("envelope_id", &self.envelope_id)
            .field("timestamp_unix_ms", &self.timestamp_unix_ms)
            .field("prev_hash", &self.prev_hash)
            .field("record", &"<redacted>")
            .field("record_hash", &self.record_hash)
            .finish()
    }
}

impl AuditEnvelope {
    fn new(record: Value, prev_hash: Option<[u8; 32]>) -> Result<Self, AuditError> {
        let envelope_id = Ulid::new().to_string();
        let timestamp_unix_ms = now_unix_ms();
        let record_hash =
            record_hash(&envelope_id, timestamp_unix_ms, prev_hash.as_ref(), &record)?;
        Ok(Self {
            envelope_id,
            timestamp_unix_ms,
            prev_hash,
            record,
            record_hash,
        })
    }

    /// Serialize as one JSON line terminated by `\n`.
    pub fn to_jsonl(&self) -> Result<String, AuditError> {
        let mut line = serde_json::to_string(self).map_err(AuditError::Json)?;
        line.push('\n');
        Ok(line)
    }
}

/// Mutable tamper-evident chain state.
#[derive(Debug, Default)]
pub struct ChainState {
    last_hash: tokio::sync::Mutex<Option<[u8; 32]>>,
}

impl ChainState {
    /// Start a fresh chain with no previous hash.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bootstrap a chain from a sink's current tail hash.
    pub async fn bootstrap(sink: &dyn AuditSink) -> Result<Self, AuditError> {
        Ok(Self {
            last_hash: tokio::sync::Mutex::new(sink.tail_hash().await?),
        })
    }

    /// Return the current in-memory tail hash.
    pub async fn last_hash(&self) -> Option<[u8; 32]> {
        *self.last_hash.lock().await
    }

    /// Append a serializable record, persist it through `sink`, and advance the chain.
    ///
    /// The state advances only after the sink write succeeds. Concurrent appends are
    /// serialized so every record observes the previous successful write.
    pub async fn append<T: Serialize + Send>(
        &self,
        sink: &dyn AuditSink,
        record: T,
    ) -> Result<AuditEnvelope, AuditError> {
        let record = serde_json::to_value(record).map_err(AuditError::Json)?;
        let mut last_hash = self.last_hash.lock().await;
        let envelope = AuditEnvelope::new(record, *last_hash)?;
        sink.write(&envelope).await?;
        *last_hash = Some(envelope.record_hash);
        Ok(envelope)
    }
}

#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError>;
    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError>;
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuditError {
    #[error("audit JSON serialization or parsing failed: {0}")]
    Json(#[source] serde_json::Error),
    #[error("audit sink I/O failure: {0}")]
    Io(#[source] std::io::Error),
    #[error("audit hash secret environment variable name is empty")]
    EmptyEnvVarName,
    #[error("audit hash secret environment variable {name} is not set: {source}")]
    EnvVar {
        name: String,
        #[source]
        source: env::VarError,
    },
    #[error("audit hash secret environment variable {name} is empty")]
    EmptySecret { name: String },
    #[error("audit hash secret from {name} must be at least {min_bytes} bytes")]
    WeakSecret { name: String, min_bytes: usize },
    #[error("audit hash field {field} is not a valid lowercase sha256 hex string")]
    InvalidHashHex { field: &'static str },
    #[error("audit chain hash mismatch")]
    HashMismatch,
    #[error("audit chain verification failed: {0}")]
    ChainVerification(#[source] ChainVerificationError),
}

/// JSONL sink with in-process size rotation.
#[derive(Debug, Clone)]
pub struct JsonlFileSink {
    inner: Arc<JsonlFileSinkInner>,
}

#[derive(Debug)]
struct JsonlFileSinkInner {
    path: PathBuf,
    max_size_bytes: u64,
    max_files: u32,
    lock: tokio::sync::Mutex<()>,
}

impl JsonlFileSink {
    /// Construct a file sink with a 10 MiB active file and 5 retained files.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_rotation(path, DEFAULT_MAX_SIZE_BYTES, DEFAULT_MAX_FILES)
    }

    /// Construct a file sink with byte-based rotation.
    ///
    /// `max_size_bytes = 0` disables rotation. `max_files` counts the active file;
    /// values below 1 are treated as 1.
    #[must_use]
    pub fn with_rotation(path: impl Into<PathBuf>, max_size_bytes: u64, max_files: u32) -> Self {
        Self {
            inner: Arc::new(JsonlFileSinkInner {
                path: path.into(),
                max_size_bytes,
                max_files: max_files.max(1),
                lock: tokio::sync::Mutex::new(()),
            }),
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.inner.path
    }
}

#[async_trait]
impl AuditSink for JsonlFileSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        let line = envelope.to_jsonl()?;
        let _guard = self.inner.lock.lock().await;
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.write_line_blocking(&line))
            .await
            .map_err(join_error_to_io)?
    }

    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        let _guard = self.inner.lock.lock().await;
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            tail_hash_from_files(&inner.path, inner.max_size_bytes, inner.max_files)
        })
        .await
        .map_err(join_error_to_io)?
    }
}

impl JsonlFileSinkInner {
    fn write_line_blocking(&self, line: &str) -> Result<(), AuditError> {
        ensure_parent_dir(&self.path)?;
        self.rotate_if_needed(line.len() as u64)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(AuditError::Io)?;
        file.write_all(line.as_bytes()).map_err(AuditError::Io)?;
        file.flush().map_err(AuditError::Io)
    }

    fn rotate_if_needed(&self, incoming_bytes: u64) -> Result<(), AuditError> {
        if self.max_size_bytes == 0 {
            return Ok(());
        }

        let current_size = match fs::metadata(&self.path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(AuditError::Io(error)),
        };

        if current_size.saturating_add(incoming_bytes) <= self.max_size_bytes {
            return Ok(());
        }

        self.rotate()
    }

    fn rotate(&self) -> Result<(), AuditError> {
        if self.max_files <= 1 {
            return match fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
                Err(error) => Err(AuditError::Io(error)),
            };
        }

        let last_index = self.max_files - 1;
        remove_file_if_exists(&rotated_path(&self.path, last_index))?;

        for index in (1..last_index).rev() {
            let from = rotated_path(&self.path, index);
            let to = rotated_path(&self.path, index + 1);
            rename_if_exists(&from, &to)?;
        }

        rename_if_exists(&self.path, &rotated_path(&self.path, 1))
    }
}

/// JSONL sink that writes one envelope per line to process stdout.
#[derive(Debug, Default, Clone)]
pub struct JsonlStdoutSink;

impl JsonlStdoutSink {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AuditSink for JsonlStdoutSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        let line = envelope.to_jsonl()?;
        tokio::task::spawn_blocking(move || {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle.write_all(line.as_bytes()).map_err(AuditError::Io)?;
            handle.flush().map_err(AuditError::Io)
        })
        .await
        .map_err(join_error_to_io)?
    }

    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(None)
    }
}

/// Syslog sink over a local Unix datagram socket.
#[derive(Debug, Clone)]
pub struct SyslogSink {
    socket_path: PathBuf,
}

impl SyslogSink {
    #[must_use]
    pub fn new() -> Self {
        Self::with_socket_path(default_syslog_socket_path())
    }

    #[must_use]
    pub fn with_socket_path(path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: path.into(),
        }
    }
}

impl Default for SyslogSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditSink for SyslogSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        let line = envelope.to_jsonl()?;
        let frame = rfc5424_frame(line.trim_end());
        send_syslog_datagram(&self.socket_path, frame.as_bytes()).await
    }

    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(None)
    }
}

/// Shared per-deployment HMAC secret for audit identifiers.
#[derive(Clone)]
pub struct AuditHashSecret(Arc<[u8]>);

impl AuditHashSecret {
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, AuditError> {
        let secret = secret.into();
        if secret.len() < MIN_AUDIT_SECRET_BYTES {
            return Err(AuditError::WeakSecret {
                name: "explicit secret".to_string(),
                min_bytes: MIN_AUDIT_SECRET_BYTES,
            });
        }
        Ok(Self(Arc::from(secret.into_boxed_slice())))
    }

    fn from_env_value(name: &str, value: String) -> Result<Self, AuditError> {
        let value = Zeroizing::new(value);
        if value.is_empty() {
            return Err(AuditError::EmptySecret {
                name: name.to_string(),
            });
        }
        let bytes = Zeroizing::new(value.as_bytes().to_vec());
        if bytes.len() < MIN_AUDIT_SECRET_BYTES {
            return Err(AuditError::WeakSecret {
                name: name.to_string(),
                min_bytes: MIN_AUDIT_SECRET_BYTES,
            });
        }
        Ok(Self(Arc::from(bytes.as_slice())))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for AuditHashSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditHashSecret")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Deterministic audit identifier hasher.
#[derive(Clone, Debug)]
pub enum AuditKeyHasher {
    Keyed(AuditHashSecret),
    UnkeyedDevOnly,
}

impl AuditKeyHasher {
    /// Load an HMAC secret from the named environment variable.
    ///
    /// This fails closed when the env var name is empty, unset, empty, or shorter
    /// than 32 bytes. Unkeyed hashing requires [`Self::unkeyed_dev_only`].
    pub fn from_env(env_var_name: &str) -> Result<Self, AuditError> {
        if env_var_name.trim().is_empty() {
            return Err(AuditError::EmptyEnvVarName);
        }
        let value = env::var(env_var_name).map_err(|source| AuditError::EnvVar {
            name: env_var_name.to_string(),
            source,
        })?;
        Ok(Self::Keyed(AuditHashSecret::from_env_value(
            env_var_name,
            value,
        )?))
    }

    /// Explicit unkeyed mode for tests and local development.
    #[must_use]
    pub fn unkeyed_dev_only() -> Self {
        Self::UnkeyedDevOnly
    }

    /// Hash a raw audit identifier.
    #[must_use]
    pub fn hash(&self, raw: &str) -> String {
        match self {
            Self::Keyed(secret) => hmac_sha256_hex(secret.as_bytes(), raw.as_bytes()),
            Self::UnkeyedDevOnly => sha256_hex(raw.as_bytes()),
        }
    }
}

pub mod redact {
    use super::*;

    const SECRET_PARAM_NAMES: &[&str] = &[
        "token",
        "key",
        "api_key",
        "apikey",
        "password",
        "secret",
        "authorization",
        "auth",
    ];

    /// Fully redact an email address without preserving local-part or domain.
    #[must_use]
    pub fn email(s: &str) -> String {
        if s.is_empty() {
            String::new()
        } else {
            "redacted".to_string()
        }
    }

    /// Fully redact a phone number without preserving digits.
    #[must_use]
    pub fn phone(s: &str) -> String {
        if s.is_empty() {
            String::new()
        } else {
            "redacted".to_string()
        }
    }

    /// Redacts URL query parameters into a stable JSON object.
    #[derive(Debug, Clone, Default)]
    pub struct QueryRedactor {
        sensitive_fields: BTreeSet<String>,
        hasher: Option<AuditKeyHasher>,
    }

    impl QueryRedactor {
        /// Construct a redactor that redacts sensitive values without lookup hashes.
        #[must_use]
        pub fn new<I, S>(sensitive_fields: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            Self {
                sensitive_fields: sensitive_fields
                    .into_iter()
                    .map(|field| field.into().to_ascii_lowercase())
                    .collect(),
                hasher: None,
            }
        }

        /// Construct a redactor that hashes sensitive lookup values.
        #[must_use]
        pub fn with_hasher<I, S>(hasher: AuditKeyHasher, sensitive_fields: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            Self {
                hasher: Some(hasher),
                ..Self::new(sensitive_fields)
            }
        }

        #[must_use]
        pub fn redact_query(&self, query: &str) -> Value {
            self.try_redact_query(query).unwrap_or_else(|error| {
                json!({
                    "_error": {
                        "code": "invalid_query_encoding",
                        "detail": error.to_string(),
                    }
                })
            })
        }

        pub fn try_redact_query(&self, query: &str) -> Result<Value, QueryRedactionError> {
            if query.is_empty() {
                return Ok(json!({}));
            }

            let mut out = BTreeMap::new();
            for pair in query.split('&').filter(|pair| !pair.is_empty()) {
                let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
                let name = decode_query_component(raw_name)?;
                let value = decode_query_component(raw_value)?;
                let (field, op) = split_field_operator(&name);
                let field_key = field.to_ascii_lowercase();

                let entry = if is_secret_param_name(field) {
                    json!({ "op": "redacted" })
                } else if self.sensitive_fields.contains(&field_key) {
                    match &self.hasher {
                        Some(hasher) => json!({
                            "op": op,
                            "value_hash": hasher.hash(&format!("{field}\0{value}")),
                        }),
                        None => json!({ "op": "redacted" }),
                    }
                } else {
                    json!({ "op": op })
                };

                out.insert(name, entry);
            }

            Ok(serde_json::to_value(out).unwrap_or_else(|_| json!({})))
        }
    }

    #[derive(Debug, Error, PartialEq, Eq)]
    pub enum QueryRedactionError {
        #[error("query component is not valid UTF-8")]
        InvalidUtf8,
    }

    fn is_secret_param_name(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        SECRET_PARAM_NAMES.iter().any(|secret| *secret == lower)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainVerification {
    pub records: usize,
    pub start_prev_hash: Option<[u8; 32]>,
    pub last_hash: Option<[u8; 32]>,
}

/// External anchors used to turn chain consistency checks into anchored
/// verification.
///
/// `trusted_start_prev_hash` verifies a retained suffix starts after a hash
/// stored outside the JSONL set. `trusted_last_hash` verifies the retained set
/// still ends at a previously stored tail/head hash. Callers should store these
/// anchor values in a location an audit-log writer cannot rewrite.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ChainVerificationAnchors {
    pub trusted_start_prev_hash: Option<[u8; 32]>,
    pub trusted_last_hash: Option<[u8; 32]>,
}

impl ChainVerificationAnchors {
    #[must_use]
    pub fn from_trusted_start_prev_hash(trusted_start_prev_hash: Option<[u8; 32]>) -> Self {
        Self {
            trusted_start_prev_hash,
            trusted_last_hash: None,
        }
    }

    #[must_use]
    pub fn from_trusted_last_hash(trusted_last_hash: [u8; 32]) -> Self {
        Self {
            trusted_start_prev_hash: None,
            trusted_last_hash: Some(trusted_last_hash),
        }
    }

    #[must_use]
    pub fn with_trusted_last_hash(mut self, trusted_last_hash: [u8; 32]) -> Self {
        self.trusted_last_hash = Some(trusted_last_hash);
        self
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainVerificationError {
    #[error("audit chain line {line} is not valid JSON: {message}")]
    InvalidJson { line: usize, message: String },
    #[error("audit chain line {line} expected prev_hash {expected:?}, got {actual:?}")]
    PrevHashMismatch {
        line: usize,
        expected: Option<[u8; 32]>,
        actual: Option<[u8; 32]>,
    },
    #[error("audit chain line {line} has an invalid record_hash")]
    RecordHashMismatch { line: usize },
    #[error("audit chain last hash mismatch")]
    LastHashMismatch {
        expected: [u8; 32],
        actual: Option<[u8; 32]>,
    },
}

pub fn verify_chain(
    envelopes: &[AuditEnvelope],
) -> Result<ChainVerification, ChainVerificationError> {
    verify_chain_expected_prev_hash(envelopes, None)
}

pub fn verify_chain_with_anchors(
    envelopes: &[AuditEnvelope],
    anchors: ChainVerificationAnchors,
) -> Result<ChainVerification, ChainVerificationError> {
    let verification = verify_chain_expected_prev_hash(envelopes, anchors.trusted_start_prev_hash)?;
    if let Some(expected) = anchors.trusted_last_hash {
        if verification.last_hash != Some(expected) {
            return Err(ChainVerificationError::LastHashMismatch {
                expected,
                actual: verification.last_hash,
            });
        }
    }
    Ok(verification)
}

fn verify_chain_expected_prev_hash(
    envelopes: &[AuditEnvelope],
    expected_start_prev_hash: Option<[u8; 32]>,
) -> Result<ChainVerification, ChainVerificationError> {
    let mut records = 0usize;
    let mut previous_hash = expected_start_prev_hash;
    let mut start_prev_hash = None;
    let mut last_hash = None;

    for (index, envelope) in envelopes.iter().enumerate() {
        let line = index + 1;
        if records == 0 {
            start_prev_hash = envelope.prev_hash;
        }

        if envelope.prev_hash != previous_hash {
            return Err(ChainVerificationError::PrevHashMismatch {
                line,
                expected: previous_hash,
                actual: envelope.prev_hash,
            });
        }

        let expected_hash = record_hash(
            &envelope.envelope_id,
            envelope.timestamp_unix_ms,
            envelope.prev_hash.as_ref(),
            &envelope.record,
        )
        .map_err(|_| ChainVerificationError::InvalidJson {
            line,
            message: "hash input serialization failed".to_string(),
        })?;
        if !hashes_equal(&expected_hash, &envelope.record_hash) {
            return Err(ChainVerificationError::RecordHashMismatch { line });
        }

        previous_hash = Some(envelope.record_hash);
        last_hash = Some(envelope.record_hash);
        records += 1;
    }

    Ok(ChainVerification {
        records,
        start_prev_hash,
        last_hash,
    })
}

pub fn verify_jsonl_lines<I, S>(lines: I) -> Result<ChainVerification, ChainVerificationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let envelopes = parse_jsonl_lines(lines)?;
    verify_chain(&envelopes)
}

pub fn verify_jsonl_lines_with_anchors<I, S>(
    lines: I,
    anchors: ChainVerificationAnchors,
) -> Result<ChainVerification, ChainVerificationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let envelopes = parse_jsonl_lines(lines)?;
    verify_chain_with_anchors(&envelopes, anchors)
}

fn parse_jsonl_lines<I, S>(lines: I) -> Result<Vec<AuditEnvelope>, ChainVerificationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut envelopes = Vec::new();
    for (index, line) in lines.into_iter().enumerate() {
        let line_no = index + 1;
        let line = line.as_ref().trim();
        if line.is_empty() {
            continue;
        }
        envelopes.push(
            serde_json::from_str::<AuditEnvelope>(line).map_err(|source| {
                ChainVerificationError::InvalidJson {
                    line: line_no,
                    message: source.to_string(),
                }
            })?,
        );
    }
    Ok(envelopes)
}

fn tail_hash_from_files(
    path: &Path,
    max_size_bytes: u64,
    max_files: u32,
) -> Result<Option<[u8; 32]>, AuditError> {
    let paths = existing_audit_paths(path, max_files);
    if paths.is_empty() {
        return Ok(None);
    }

    let mut contents = String::new();
    for path in &paths {
        let file_contents = read_audit_file(path)?;
        contents.push_str(&file_contents);
        if !contents.ends_with('\n') {
            contents.push('\n');
        }
    }

    let envelopes = parse_jsonl_lines(contents.lines()).map_err(AuditError::ChainVerification)?;
    if envelopes.is_empty() {
        return Ok(None);
    }
    let retained_suffix = max_size_bytes != 0
        && paths.len() == max_files as usize
        && envelopes[0].prev_hash.is_some();
    let verification = if retained_suffix {
        verify_chain_expected_prev_hash(&envelopes, envelopes[0].prev_hash)
    } else {
        verify_chain(&envelopes)
    }
    .map_err(AuditError::ChainVerification)?;
    Ok(verification.last_hash)
}

fn read_audit_file(path: &Path) -> Result<String, AuditError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(AuditError::Io(error)),
    };
    Ok(contents)
}

fn existing_audit_paths(path: &Path, max_files: u32) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for index in (1..max_files).rev() {
        let rotated = rotated_path(path, index);
        if rotated.exists() {
            paths.push(rotated);
        }
    }
    if path.exists() {
        paths.push(path.to_path_buf());
    }
    paths
}

fn record_hash(
    envelope_id: &str,
    timestamp_unix_ms: i64,
    prev_hash: Option<&[u8; 32]>,
    record: &Value,
) -> Result<[u8; 32], AuditError> {
    #[derive(Serialize)]
    struct HashInput<'a> {
        envelope_id: &'a str,
        timestamp_unix_ms: i64,
        prev_hash: Option<String>,
        record: &'a Value,
    }

    let input = HashInput {
        envelope_id,
        timestamp_unix_ms,
        prev_hash: prev_hash.map(|hash| hex_lower(hash)),
        record,
    };
    let bytes = serde_json::to_vec(&input).map_err(AuditError::Json)?;
    Ok(sha256_bytes(&bytes))
}

fn hashes_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    bool::from(left.ct_eq(right))
}

fn now_unix_ms() -> i64 {
    let millis = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    match i64::try_from(millis) {
        Ok(millis) => millis,
        Err(_) if millis.is_negative() => i64::MIN,
        Err(_) => i64::MAX,
    }
}

fn ensure_parent_dir(path: &Path) -> Result<(), AuditError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(AuditError::Io)?;
    }
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<(), AuditError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AuditError::Io(error)),
    }
}

fn rename_if_exists(from: &Path, to: &Path) -> Result<(), AuditError> {
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AuditError::Io(error)),
    }
}

fn rotated_path(path: &Path, index: u32) -> PathBuf {
    PathBuf::from(format!("{}.{}", path.display(), index))
}

fn join_error_to_io(error: tokio::task::JoinError) -> AuditError {
    AuditError::Io(std::io::Error::other(error))
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{UNKEYED_HASH_PREFIX}{}", hex_lower(&sha256_bytes(bytes)))
}

fn hmac_sha256_hex(secret: &[u8], bytes: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(bytes);
    let tag = mac.finalize().into_bytes();
    format!("{KEYED_HASH_PREFIX}{}", hex_lower(&tag))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn parse_hash_hex(value: &str, field: &'static str) -> Result<[u8; 32], AuditError> {
    if value.len() != 64 {
        return Err(AuditError::InvalidHashHex { field });
    }

    let mut out = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_value(chunk[0]).ok_or(AuditError::InvalidHashHex { field })?;
        let lo = hex_value(chunk[1]).ok_or(AuditError::InvalidHashHex { field })?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn split_field_operator(name: &str) -> (&str, &str) {
    match name.rsplit_once('.') {
        Some((field, op)) if !field.is_empty() && !op.is_empty() => (field, op),
        _ => (name, "eq"),
    }
}

fn decode_query_component(raw: &str) -> Result<String, redact::QueryRedactionError> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match (hex_value_any(bytes[i + 1]), hex_value_any(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi << 4) | lo);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| redact::QueryRedactionError::InvalidUtf8)
}

fn hex_value_any(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn rfc5424_frame(message: &str) -> String {
    let timestamp = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "-".to_string());
    format!("<134>1 {timestamp} - registry-platform-audit - - - {message}")
}

#[cfg(unix)]
async fn send_syslog_datagram(socket_path: &Path, bytes: &[u8]) -> Result<(), AuditError> {
    let socket = tokio::net::UnixDatagram::unbound().map_err(AuditError::Io)?;
    socket
        .send_to(bytes, socket_path)
        .await
        .map_err(AuditError::Io)?;
    Ok(())
}

#[cfg(not(unix))]
async fn send_syslog_datagram(_socket_path: &Path, _bytes: &[u8]) -> Result<(), AuditError> {
    Err(AuditError::Io(std::io::Error::new(
        ErrorKind::Unsupported,
        "syslog audit sink requires Unix datagram sockets",
    )))
}

#[cfg(target_os = "macos")]
fn default_syslog_socket_path() -> PathBuf {
    PathBuf::from("/var/run/syslog")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn default_syslog_socket_path() -> PathBuf {
    PathBuf::from("/dev/log")
}

#[cfg(not(unix))]
fn default_syslog_socket_path() -> PathBuf {
    PathBuf::new()
}

mod hash_hex {
    use super::*;

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_lower(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        parse_hash_hex(&value, "record_hash").map_err(serde::de::Error::custom)
    }
}

mod option_hash_hex {
    use super::*;

    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&hex_lower(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        value
            .as_deref()
            .map(|hash| parse_hash_hex(hash, "prev_hash"))
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::{redact::QueryRedactor, *};

    #[tokio::test]
    async fn audit_chain_bootstraps_from_sink_tail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);
        let chain = ChainState::bootstrap(&sink).await.expect("bootstrap empty");

        let first = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("first append");
        let second = chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("second append");

        assert!(first.prev_hash.is_none());
        assert_eq!(second.prev_hash, Some(first.record_hash));
        assert_eq!(
            sink.tail_hash().await.expect("tail"),
            Some(second.record_hash)
        );

        let bootstrapped = ChainState::bootstrap(&sink).await.expect("bootstrap tail");
        let third = bootstrapped
            .append(&sink, json!({ "event": "third" }))
            .await
            .expect("third append");
        assert_eq!(third.prev_hash, Some(second.record_hash));

        let contents = fs::read_to_string(path).expect("audit file");
        let verification = verify_jsonl_lines(contents.lines()).expect("valid chain");
        assert_eq!(verification.records, 3);
        assert_eq!(verification.last_hash, Some(third.record_hash));
    }

    #[tokio::test]
    async fn audit_chain_detects_inserted_envelope() {
        let sink = MemorySink::default();
        let chain = ChainState::new();
        let first = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("first append");
        let _second = chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("second append");
        let third = chain
            .append(&sink, json!({ "event": "third" }))
            .await
            .expect("third append");

        let err = verify_chain(&[first, third]).expect_err("gap detected");
        assert!(matches!(
            err,
            ChainVerificationError::PrevHashMismatch { line: 2, .. }
        ));
    }

    #[test]
    fn audit_envelope_debug_redacts_record() {
        let envelope = AuditEnvelope::new(
            json!({
                "event": "credential.issued",
                "token": "secret-token",
                "email": "jeremi@example.test",
            }),
            None,
        )
        .expect("envelope");

        let debug = format!("{envelope:?}");

        assert!(debug.contains("AuditEnvelope"));
        assert!(debug.contains("record: \"<redacted>\""));
        assert!(debug.contains(&envelope.envelope_id));
        assert!(!debug.contains("secret-token"));
        assert!(!debug.contains("jeremi@example.test"));
        assert!(!debug.contains("credential.issued"));
    }

    #[test]
    fn audit_chain_detects_tampered_record() {
        let first = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        let mut second = AuditEnvelope::new(json!({ "event": "second" }), Some(first.record_hash))
            .expect("second");
        second.record["event"] = json!("changed");

        let err = verify_chain(&[first, second]).expect_err("tamper detected");
        assert_eq!(err, ChainVerificationError::RecordHashMismatch { line: 2 });
    }

    #[test]
    fn audit_chain_detects_tampered_timestamp() {
        let mut envelope = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        envelope.timestamp_unix_ms += 1;

        let err = verify_chain(&[envelope]).expect_err("tamper detected");
        assert_eq!(err, ChainVerificationError::RecordHashMismatch { line: 1 });
    }

    #[test]
    fn audit_chain_detects_tampered_envelope_id() {
        let mut envelope = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        envelope.envelope_id = Ulid::new().to_string();

        let err = verify_chain(&[envelope]).expect_err("tamper detected");
        assert_eq!(err, ChainVerificationError::RecordHashMismatch { line: 1 });
    }

    #[tokio::test]
    async fn file_sink_rejects_missing_first_line_in_tail_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);
        let chain = ChainState::new();
        let first = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("first append");
        let _second = chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("second append");

        let contents = fs::read_to_string(&path).expect("audit file");
        let rewritten = contents.lines().skip(1).collect::<Vec<_>>().join("\n") + "\n";
        fs::write(&path, rewritten).expect("rewrite without first line");

        assert!(matches!(
            sink.tail_hash().await,
            Err(AuditError::ChainVerification(
                ChainVerificationError::PrevHashMismatch {
                    line: 1,
                    expected: None,
                    actual: Some(actual),
                }
            )) if actual == first.record_hash
        ));
    }

    #[tokio::test]
    async fn file_sink_bootstrap_rejects_missing_first_line() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);
        let chain = ChainState::new();
        chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("first append");
        chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("second append");

        let contents = fs::read_to_string(&path).expect("audit file");
        let rewritten = contents.lines().skip(1).collect::<Vec<_>>().join("\n") + "\n";
        fs::write(&path, rewritten).expect("rewrite without first line");

        assert!(matches!(
            ChainState::bootstrap(&sink).await,
            Err(AuditError::ChainVerification(
                ChainVerificationError::PrevHashMismatch {
                    line: 1,
                    expected: None,
                    actual: Some(_),
                }
            ))
        ));
    }

    #[tokio::test]
    async fn file_sink_bootstrap_continues_from_retained_rotated_suffix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::with_rotation(&path, 1, 2);
        let chain = ChainState::new();
        let mut third_hash = None;
        for event in ["first", "second", "third"] {
            let envelope = chain
                .append(&sink, json!({ "event": event }))
                .await
                .expect("append");
            third_hash = Some(envelope.record_hash);
        }

        assert_eq!(sink.tail_hash().await.expect("tail"), third_hash);
        let bootstrapped = ChainState::bootstrap(&sink).await.expect("bootstrap");
        let fourth = bootstrapped
            .append(&sink, json!({ "event": "fourth" }))
            .await
            .expect("fourth append");
        assert_eq!(fourth.prev_hash, third_hash);
    }

    #[tokio::test]
    async fn file_sink_retained_suffix_detects_tampered_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::with_rotation(&path, 1, 2);
        let chain = ChainState::new();
        for event in ["first", "second", "third"] {
            chain
                .append(&sink, json!({ "event": event }))
                .await
                .expect("append");
        }

        let contents = fs::read_to_string(&path).expect("active audit file");
        fs::write(&path, contents.replace("\"third\"", "\"tampered\""))
            .expect("tamper active file");

        assert!(matches!(
            sink.tail_hash().await,
            Err(AuditError::ChainVerification(
                ChainVerificationError::RecordHashMismatch { line: 2 }
            ))
        ));
    }

    #[test]
    fn verify_jsonl_lines_remains_genesis_strict_for_suffix() {
        let first = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        let second = AuditEnvelope::new(json!({ "event": "second" }), Some(first.record_hash))
            .expect("second");
        let third = AuditEnvelope::new(json!({ "event": "third" }), Some(second.record_hash))
            .expect("third");
        let suffix = [second.to_jsonl().unwrap(), third.to_jsonl().unwrap()];

        assert!(matches!(
            verify_jsonl_lines(suffix.iter()),
            Err(ChainVerificationError::PrevHashMismatch {
                line: 1,
                expected: None,
                actual: Some(_),
            })
        ));
    }

    #[test]
    fn verify_chain_with_anchors_accepts_trusted_retained_suffix() {
        let first = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        let second = AuditEnvelope::new(json!({ "event": "second" }), Some(first.record_hash))
            .expect("second");
        let third = AuditEnvelope::new(json!({ "event": "third" }), Some(second.record_hash))
            .expect("third");

        let verification = verify_chain_with_anchors(
            &[second.clone(), third.clone()],
            ChainVerificationAnchors::from_trusted_start_prev_hash(Some(first.record_hash))
                .with_trusted_last_hash(third.record_hash),
        )
        .expect("anchored suffix verifies");

        assert_eq!(verification.records, 2);
        assert_eq!(verification.start_prev_hash, Some(first.record_hash));
        assert_eq!(verification.last_hash, Some(third.record_hash));
    }

    #[test]
    fn verify_chain_with_trusted_tail_rejects_full_rewrite() {
        let first = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        let second = AuditEnvelope::new(json!({ "event": "second" }), Some(first.record_hash))
            .expect("second");
        let rewritten_first =
            AuditEnvelope::new(json!({ "event": "fake-first" }), None).expect("fake first");
        let rewritten_second = AuditEnvelope::new(
            json!({ "event": "fake-second" }),
            Some(rewritten_first.record_hash),
        )
        .expect("fake second");

        let rewritten = [rewritten_first, rewritten_second];
        assert!(verify_chain(&rewritten).is_ok());

        let err = verify_chain_with_anchors(
            &rewritten,
            ChainVerificationAnchors::from_trusted_last_hash(second.record_hash),
        )
        .expect_err("trusted tail detects full rewrite");

        assert!(matches!(
            err,
            ChainVerificationError::LastHashMismatch { .. }
        ));
    }

    #[test]
    fn verify_jsonl_lines_with_anchors_checks_trusted_tail() {
        let first = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        let second = AuditEnvelope::new(json!({ "event": "second" }), Some(first.record_hash))
            .expect("second");
        let lines = [first.to_jsonl().unwrap(), second.to_jsonl().unwrap()];

        let verification = verify_jsonl_lines_with_anchors(
            lines.iter(),
            ChainVerificationAnchors::from_trusted_last_hash(second.record_hash),
        )
        .expect("anchored JSONL verifies");

        assert_eq!(verification.records, 2);
        assert_eq!(verification.last_hash, Some(second.record_hash));

        let err = verify_jsonl_lines_with_anchors(
            lines.iter(),
            ChainVerificationAnchors::from_trusted_last_hash([42; 32]),
        )
        .expect_err("wrong trusted tail rejected");
        assert!(matches!(
            err,
            ChainVerificationError::LastHashMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn file_sink_bootstrap_accepts_max_files_one_retained_tail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::with_rotation(&path, 1, 1);
        let chain = ChainState::new();
        let first = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("first append");
        let second = chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("second append");

        assert_eq!(second.prev_hash, Some(first.record_hash));
        let bootstrapped = ChainState::bootstrap(&sink).await.expect("bootstrap");
        let third = bootstrapped
            .append(&sink, json!({ "event": "third" }))
            .await
            .expect("third append");
        assert_eq!(third.prev_hash, Some(second.record_hash));
    }

    #[test]
    fn audit_hasher_from_env_returns_err_when_unset() {
        let name = "REGISTRY_PLATFORM_AUDIT_TEST_UNSET";
        env::remove_var(name);
        assert!(matches!(
            AuditKeyHasher::from_env(name),
            Err(AuditError::EnvVar { .. })
        ));
    }

    #[test]
    fn audit_hasher_requires_explicit_unkeyed_dev_mode() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();
        let hashed = hasher.hash("subject-123");
        assert!(hashed.starts_with(UNKEYED_HASH_PREFIX));
    }

    #[test]
    fn audit_hasher_from_env_uses_hmac_secret() {
        let name = "REGISTRY_PLATFORM_AUDIT_TEST_SECRET";
        env::set_var(name, "0123456789abcdef0123456789abcdef");
        let hasher = AuditKeyHasher::from_env(name).expect("hasher");
        env::remove_var(name);

        let hashed = hasher.hash("subject-123");
        assert!(hashed.starts_with(KEYED_HASH_PREFIX));
        assert_ne!(
            hashed,
            AuditKeyHasher::unkeyed_dev_only().hash("subject-123")
        );
    }

    #[test]
    fn query_redactor_redacts_secrets_and_hashes_sensitive_fields() {
        let redactor =
            QueryRedactor::with_hasher(AuditKeyHasher::unkeyed_dev_only(), ["email", "person_id"]);
        let redacted = redactor
            .redact_query("email=jeremi%40example.test&token=secret&limit=10&person_id.gte=abc");

        assert_eq!(redacted["token"]["op"], "redacted");
        assert_eq!(redacted["limit"]["op"], "eq");
        assert_eq!(redacted["email"]["op"], "eq");
        assert!(redacted["email"]["value_hash"]
            .as_str()
            .expect("hash")
            .starts_with(UNKEYED_HASH_PREFIX));
        assert_eq!(redacted["person_id.gte"]["op"], "gte");
        assert!(!redacted.to_string().contains("jeremi"));
        assert!(!redacted.to_string().contains("secret"));
        assert!(!redacted.to_string().contains("abc"));
    }

    #[test]
    fn query_redactor_surfaces_invalid_utf8() {
        let redactor = QueryRedactor::new(["email"]);

        let err = redactor
            .try_redact_query("email=%FF")
            .expect_err("invalid UTF-8 is not silently lossy-decoded");
        assert_eq!(err, redact::QueryRedactionError::InvalidUtf8);

        let redacted = redactor.redact_query("email=%FF");
        assert_eq!(redacted["_error"]["code"], "invalid_query_encoding");
    }

    #[tokio::test]
    async fn file_sink_rejects_tampered_tail_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);
        let chain = ChainState::new();
        let mut envelope = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("append");
        envelope.record["event"] = json!("changed");
        fs::write(&path, envelope.to_jsonl().expect("jsonl")).expect("rewrite");

        assert!(matches!(
            sink.tail_hash().await,
            Err(AuditError::ChainVerification(
                ChainVerificationError::RecordHashMismatch { line: 1 }
            ))
        ));
    }

    #[derive(Default)]
    struct MemorySink {
        envelopes: tokio::sync::Mutex<Vec<AuditEnvelope>>,
    }

    #[async_trait]
    impl AuditSink for MemorySink {
        async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
            self.envelopes.lock().await.push(envelope.clone());
            Ok(())
        }

        async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(self
                .envelopes
                .lock()
                .await
                .last()
                .map(|envelope| envelope.record_hash))
        }
    }
}

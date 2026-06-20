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

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use async_trait::async_trait;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::OffsetDateTime;
use ulid::Ulid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const DEFAULT_MAX_SIZE_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_MAX_FILES: u32 = 5;
const MIN_AUDIT_SECRET_BYTES: usize = 32;
const KEYED_HASH_PREFIX: &str = "hmac-sha256:";
const UNKEYED_HASH_PREFIX: &str = "sha256:";
const CHAIN_HMAC_CONTEXT: &[u8] = b"registry-platform-audit-chain-v1";
const AUDIT_REFERENCE_HASH_CONTEXT: &str = "registry-platform:audit-reference:v1";

/// HKDF-Expand `info` label deriving the chain-integrity sub-key (AUDIT-03).
const CHAIN_KEY_DERIVATION_INFO: &[u8] = b"registry-platform-audit/chain-key/v1";
/// HKDF-Expand `info` label deriving the identifier-hashing sub-key (AUDIT-03).
const IDENTIFIER_KEY_DERIVATION_INFO: &[u8] = b"registry-platform-audit/identifier-key/v1";

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
    #[cfg(test)]
    fn new(record: Value, prev_hash: Option<[u8; 32]>) -> Result<Self, AuditError> {
        Self::new_with_hasher(record, prev_hash, &AuditChainHasher::unkeyed_dev_only())
    }

    fn new_with_hasher(
        record: Value,
        prev_hash: Option<[u8; 32]>,
        hasher: &AuditChainHasher,
    ) -> Result<Self, AuditError> {
        let envelope_id = Ulid::new().to_string();
        let timestamp_unix_ms = now_unix_ms();
        let record_hash = record_hash(
            &envelope_id,
            timestamp_unix_ms,
            prev_hash.as_ref(),
            &record,
            hasher,
        )?;
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

/// Mutable audit chain state.
#[derive(Debug)]
pub struct ChainState {
    hasher: AuditChainHasher,
    last_hash: tokio::sync::Mutex<Option<[u8; 32]>>,
}

impl ChainState {
    /// Start a fresh production chain using a keyed audit-chain hasher.
    #[must_use]
    pub fn new(hasher: AuditChainHasher) -> Self {
        Self {
            hasher,
            last_hash: tokio::sync::Mutex::new(None),
        }
    }

    /// Start a fresh unkeyed chain for tests and local development.
    #[must_use]
    pub fn unkeyed_dev_only() -> Self {
        Self::new(AuditChainHasher::unkeyed_dev_only())
    }

    /// Bootstrap a production chain from a tailable sink's current tail hash.
    pub async fn bootstrap(
        sink: &dyn AuditSink,
        hasher: AuditChainHasher,
    ) -> Result<Self, AuditError> {
        let Some(tail_hash) = sink.tail_hash_with_hasher(&hasher).await? else {
            return Err(AuditError::NonTailableSink);
        };
        Ok(Self {
            hasher,
            last_hash: tokio::sync::Mutex::new(Some(tail_hash)),
        })
    }

    /// Bootstrap from a sink that may be empty, using an explicit keyed hasher.
    pub async fn bootstrap_or_start_empty(
        sink: &dyn AuditSink,
        hasher: AuditChainHasher,
    ) -> Result<Self, AuditError> {
        let last_hash = sink.tail_hash_with_hasher(&hasher).await?;
        Ok(Self {
            hasher,
            last_hash: tokio::sync::Mutex::new(last_hash),
        })
    }

    /// Bootstrap or restart from genesis for tests and local development.
    pub async fn bootstrap_unkeyed_dev_only(sink: &dyn AuditSink) -> Result<Self, AuditError> {
        let hasher = AuditChainHasher::unkeyed_dev_only();
        let last_hash = sink.tail_hash_with_hasher(&hasher).await?;
        Ok(Self {
            hasher,
            last_hash: tokio::sync::Mutex::new(last_hash),
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
        let envelope = AuditEnvelope::new_with_hasher(record, *last_hash, &self.hasher)?;
        sink.write(&envelope).await?;
        *last_hash = Some(envelope.record_hash);
        Ok(envelope)
    }
}

/// Named audit-chain profile for applications that need to bootstrap a chain
/// without owning the low-level hash mode selection.
#[derive(Clone, Debug)]
pub struct AuditChainProfile {
    hasher: AuditChainHasher,
}

impl AuditChainProfile {
    /// Production profile backed by the HMAC secret in `env_var_name`.
    ///
    /// The chain key is an HKDF-derived sub-key of the master env secret so it is
    /// domain-separated from the identifier key derived by [`AuditProfile`]
    /// (AUDIT-03). Both profiles derive the same chain sub-key from the same env
    /// secret, so a chain bootstrapped via either profile stays consistent.
    pub fn production_from_env(env_var_name: &str) -> Result<Self, AuditError> {
        Ok(Self {
            hasher: AuditChainHasher::from_env_derived(env_var_name)?,
        })
    }

    /// Registry Relay production audit-chain profile.
    pub fn registry_relay_from_env(env_var_name: &str) -> Result<Self, AuditError> {
        Self::production_from_env(env_var_name)
    }

    /// Registry Notary production audit-chain profile.
    pub fn registry_notary_from_env(env_var_name: &str) -> Result<Self, AuditError> {
        Self::production_from_env(env_var_name)
    }

    /// Explicit test and local-development profile.
    #[must_use]
    pub fn dev_unkeyed() -> Self {
        Self {
            hasher: AuditChainHasher::unkeyed_dev_only(),
        }
    }

    #[must_use]
    pub fn hasher(&self) -> AuditChainHasher {
        self.hasher.clone()
    }

    pub async fn bootstrap_or_start_empty(
        &self,
        sink: &dyn AuditSink,
    ) -> Result<ChainState, AuditError> {
        ChainState::bootstrap_or_start_empty(sink, self.hasher()).await
    }
}

/// Shared application audit profile for keyed chain integrity and identifier
/// hashing.
#[derive(Clone, Debug)]
pub struct AuditProfile {
    chain_hasher: AuditChainHasher,
    key_hasher: AuditKeyHasher,
}

impl AuditProfile {
    /// Production profile backed by the HMAC secret in `env_var_name`.
    ///
    /// The chain key and identifier key are independent HKDF-derived sub-keys of
    /// the master env secret, each bound to a distinct per-purpose `info` label
    /// (AUDIT-03). A leak of one derived sub-key reveals neither the master nor
    /// the sibling. The chain sub-key matches the one derived by
    /// [`AuditChainProfile::production_from_env`] for the same env secret.
    pub fn production_from_env(env_var_name: &str) -> Result<Self, AuditError> {
        Ok(Self {
            chain_hasher: AuditChainHasher::from_env_derived(env_var_name)?,
            key_hasher: AuditKeyHasher::from_env_derived(env_var_name)?,
        })
    }

    /// Registry Relay production audit profile.
    pub fn registry_relay_from_env(env_var_name: &str) -> Result<Self, AuditError> {
        Self::production_from_env(env_var_name)
    }

    /// Registry Notary production audit profile.
    pub fn registry_notary_from_env(env_var_name: &str) -> Result<Self, AuditError> {
        Self::production_from_env(env_var_name)
    }

    /// Explicit test and local-development profile.
    #[must_use]
    pub fn unkeyed_dev_only() -> Self {
        Self {
            chain_hasher: AuditChainHasher::unkeyed_dev_only(),
            key_hasher: AuditKeyHasher::unkeyed_dev_only(),
        }
    }

    #[must_use]
    pub fn chain_hasher(&self) -> AuditChainHasher {
        self.chain_hasher.clone()
    }

    #[must_use]
    pub fn key_hasher(&self) -> AuditKeyHasher {
        self.key_hasher.clone()
    }

    pub async fn bootstrap_or_start_empty(
        &self,
        sink: &dyn AuditSink,
    ) -> Result<ChainState, AuditError> {
        ChainState::bootstrap_or_start_empty(sink, self.chain_hasher()).await
    }
}

#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError>;

    /// Return the chain tail hash using the sink's own default hash mode.
    ///
    /// WARNING (AUDIT-06): for tailable sinks that recompute hashes while reading
    /// (such as [`JsonlFileSink`]) this path is **UNKEYED / dev-only**. It cannot
    /// authenticate a retained chain against the deployment HMAC secret, so an
    /// attacker who rewrites the log can forge a self-consistent tail. Production
    /// code MUST use [`Self::tail_hash_with_hasher`] with a keyed
    /// [`AuditChainHasher`] (e.g. via [`ChainState::bootstrap_or_start_empty`]).
    ///
    /// Implementors must still provide this method (it is the read primitive);
    /// the `#[deprecated]` marker is a guardrail against *calling* the bare,
    /// unkeyed convenience from production code.
    #[deprecated(
        note = "tail_hash() recomputes UNKEYED for tailable sinks (dev/test only); use tail_hash_with_hasher with a keyed AuditChainHasher in production"
    )]
    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError>;

    /// Return the chain tail hash recomputed under the caller-selected `hasher`.
    ///
    /// This is the keyed, production-safe entry point. The default implementation
    /// IGNORES `hasher` and delegates to the UNKEYED [`Self::tail_hash`]; sinks
    /// that recompute the chain while reading (such as [`JsonlFileSink`]) MUST
    /// override this method so the keyed mode is actually honored. Sinks that
    /// never recompute hashes (stdout, syslog) may keep the default.
    async fn tail_hash_with_hasher(
        &self,
        hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        let _ = hasher;
        #[allow(deprecated)]
        self.tail_hash().await
    }
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
    #[error("audit sink cannot provide a tail hash; use bootstrap_or_start_empty with an external anchor or explicit dev-only restart mode")]
    NonTailableSink,
    #[error("audit chain hash mismatch")]
    HashMismatch,
    #[error("audit chain verification failed: {0}")]
    ChainVerification(#[source] ChainVerificationError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AuditReferenceHashError {
    #[error("audit reference class is empty")]
    EmptyClass,
    #[error("audit reference canonical input is empty")]
    EmptyCanonicalInput,
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

    /// WARNING (AUDIT-06): this recomputes the retained chain with an **UNKEYED**
    /// hasher and is dev/test only. It cannot detect a rewrite by a writer that
    /// lacks the deployment HMAC secret. Production callers MUST use
    /// [`Self::tail_hash_with_hasher`] with a keyed [`AuditChainHasher`].
    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        self.tail_hash_blocking(AuditChainHasher::unkeyed_dev_only())
            .await
    }

    /// Recompute the retained chain tail under the caller-selected `hasher`.
    ///
    /// This is the keyed, production-safe path: pass a keyed [`AuditChainHasher`]
    /// to authenticate the retained JSONL set against the deployment secret.
    async fn tail_hash_with_hasher(
        &self,
        hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        self.tail_hash_blocking(hasher.clone()).await
    }
}

impl JsonlFileSink {
    async fn tail_hash_blocking(
        &self,
        hasher: AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        let _guard = self.inner.lock.lock().await;
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            tail_hash_from_files(&inner.path, inner.max_size_bytes, inner.max_files, &hasher)
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
            .audit_file_mode()
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

/// Inner key bytes for [`AuditHashSecret`].
///
/// The raw HMAC key is zeroized when the last shared reference is dropped, so a
/// leaked process image is far less likely to retain the deployment secret after
/// the audit profile is torn down.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretBytes(Vec<u8>);

/// Shared per-deployment HMAC secret for audit identifiers.
///
/// The key material is held behind an `Arc<SecretBytes>` whose inner bytes are
/// zeroized on drop of the last clone (AUDIT-02).
#[derive(Clone)]
pub struct AuditHashSecret(Arc<SecretBytes>);

impl AuditHashSecret {
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, AuditError> {
        // Own the bytes directly: on the success path they move into the
        // `ZeroizeOnDrop` `SecretBytes` with no intermediate copy; on the error
        // path the rejected (too-short) secret is scrubbed explicitly.
        let mut secret = secret.into();
        if secret.len() < MIN_AUDIT_SECRET_BYTES {
            secret.zeroize();
            return Err(AuditError::WeakSecret {
                name: "explicit secret".to_string(),
                min_bytes: MIN_AUDIT_SECRET_BYTES,
            });
        }
        Ok(Self(Arc::new(SecretBytes(secret))))
    }

    fn from_env_value(name: &str, value: String) -> Result<Self, AuditError> {
        // Keep ownership of the env value so it can move into `SecretBytes`
        // (`String::into_bytes` is allocation-free) instead of being copied;
        // rejected values are scrubbed before returning.
        let mut value = value;
        if value.is_empty() {
            return Err(AuditError::EmptySecret {
                name: name.to_string(),
            });
        }
        if value.len() < MIN_AUDIT_SECRET_BYTES {
            value.zeroize();
            return Err(AuditError::WeakSecret {
                name: name.to_string(),
                min_bytes: MIN_AUDIT_SECRET_BYTES,
            });
        }
        Ok(Self(Arc::new(SecretBytes(value.into_bytes()))))
    }

    fn from_bytes(secret: Vec<u8>) -> Self {
        Self(Arc::new(SecretBytes(secret)))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0 .0
    }
}

impl fmt::Debug for AuditHashSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditHashSecret")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Audit-chain record hasher.
///
/// Keyed mode protects the retained JSONL chain from a file writer that cannot
/// read the deployment HMAC secret. Unkeyed mode is retained only for tests,
/// fixtures, and migration checks of legacy pre-beta logs.
#[derive(Clone, Debug)]
pub enum AuditChainHasher {
    Keyed(AuditHashSecret),
    UnkeyedDevOnly,
}

impl AuditChainHasher {
    #[must_use]
    pub fn keyed(secret: AuditHashSecret) -> Self {
        Self::Keyed(secret)
    }

    /// Load an HMAC chain secret from the named environment variable.
    ///
    /// The raw env value is used directly as the chain key. Prefer
    /// [`Self::from_env_derived`] at the profile boundary so the chain key and
    /// sibling identifier key are cryptographically separated sub-keys of the
    /// master env secret (AUDIT-03).
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

    /// Load a chain hasher whose key is an HKDF-derived sub-key of the master
    /// env secret, domain-separated from the identifier key (AUDIT-03).
    pub fn from_env_derived(env_var_name: &str) -> Result<Self, AuditError> {
        Ok(Self::Keyed(derive_subkey_from_env(
            env_var_name,
            CHAIN_KEY_DERIVATION_INFO,
        )?))
    }

    /// Explicit unkeyed mode for tests, fixtures, and legacy pre-beta logs.
    #[must_use]
    pub fn unkeyed_dev_only() -> Self {
        Self::UnkeyedDevOnly
    }

    fn hash_record(&self, bytes: &[u8]) -> [u8; 32] {
        match self {
            Self::Keyed(secret) => hmac_sha256_bytes(secret.as_bytes(), CHAIN_HMAC_CONTEXT, bytes),
            Self::UnkeyedDevOnly => sha256_bytes(bytes),
        }
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

    /// Load an identifier hasher whose key is an HKDF-derived sub-key of the
    /// master env secret, domain-separated from the chain key (AUDIT-03).
    pub fn from_env_derived(env_var_name: &str) -> Result<Self, AuditError> {
        Ok(Self::Keyed(derive_subkey_from_env(
            env_var_name,
            IDENTIFIER_KEY_DERIVATION_INFO,
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

    /// Hash a service-owned canonical audit reference under a versioned class
    /// and scope.
    ///
    /// `class` separates reference families such as matched subjects, table ids,
    /// or primary keys. `scope` may be empty when the service has no narrower
    /// purpose or tenant boundary. `canonical_input` is owned by the caller and
    /// must already be stable and privacy-reviewed for that product surface.
    pub fn audit_reference_hash(
        &self,
        class: &str,
        scope: &str,
        canonical_input: &str,
    ) -> Result<String, AuditReferenceHashError> {
        if class.is_empty() {
            return Err(AuditReferenceHashError::EmptyClass);
        }
        if canonical_input.is_empty() {
            return Err(AuditReferenceHashError::EmptyCanonicalInput);
        }
        let input = audit_reference_hash_input(class, scope, canonical_input);
        Ok(self.hash(&input))
    }

    /// Hash a sensitive audit lookup value under a field-bound platform class.
    ///
    /// This is appropriate for generic redaction surfaces such as URL query
    /// parameters. Services that need product-specific pseudonym classes should
    /// call [`Self::audit_reference_hash`] with their own canonical input.
    #[must_use]
    pub fn sensitive_value_hash(&self, field: &str, value: &str) -> String {
        let canonical_input = format!("value\0{}\0{value}", value.len());
        self.audit_reference_hash("sensitive-value-v1", field, &canonical_input)
            .expect("platform sensitive-value class and canonical input are non-empty")
    }
}

fn audit_reference_hash_input(class: &str, scope: &str, canonical_input: &str) -> String {
    format!(
        "{AUDIT_REFERENCE_HASH_CONTEXT}\0{}\0{class}\0{}\0{scope}\0{}\0{canonical_input}",
        class.len(),
        scope.len(),
        canonical_input.len()
    )
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
        // AUDIT-05: OAuth / OIDC / generic credential parameter names.
        "access_token",
        "refresh_token",
        "id_token",
        "client_secret",
        "client_assertion",
        "assertion",
        "bearer",
        "code",
        "private_key",
        "credential",
        "credentials",
        "passwd",
        "pwd",
        "session_token",
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
                            "value_hash": hasher.sensitive_value_hash(field, &value),
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
    #[non_exhaustive]
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

/// Verify a retained audit chain with the caller-selected hash mode.
///
/// This checks internal consistency over the provided records. Store external
/// anchors off-host and use [`verify_chain_with_anchors`] when continuity across
/// retained sets matters.
pub fn verify_chain(
    envelopes: &[AuditEnvelope],
    hasher: &AuditChainHasher,
) -> Result<ChainVerification, ChainVerificationError> {
    verify_chain_expected_prev_hash(envelopes, None, hasher)
}

pub fn verify_chain_with_anchors(
    envelopes: &[AuditEnvelope],
    anchors: ChainVerificationAnchors,
    hasher: &AuditChainHasher,
) -> Result<ChainVerification, ChainVerificationError> {
    let verification =
        verify_chain_expected_prev_hash(envelopes, anchors.trusted_start_prev_hash, hasher)?;
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
    hasher: &AuditChainHasher,
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
            hasher,
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

/// Verify a retained audit chain from JSONL lines using **UNKEYED** hashing.
///
/// This helper hardcodes [`AuditChainHasher::unkeyed_dev_only`], so it provides
/// NO protection against an attacker who can rewrite the JSONL set: an adversary
/// without the deployment HMAC secret can still forge a fully self-consistent
/// chain. It is intended only for tests, fixtures, and migration checks of
/// legacy pre-beta logs.
///
/// Production verification MUST use [`verify_jsonl_lines_with_hasher`] with an
/// explicit keyed [`AuditChainHasher`] (and ideally
/// [`verify_jsonl_lines_with_anchors`] with off-host anchors).
#[deprecated(
    note = "performs UNKEYED verification (dev/test only); use verify_jsonl_lines_with_hasher with an explicit AuditChainHasher in production"
)]
pub fn verify_jsonl_lines<I, S>(lines: I) -> Result<ChainVerification, ChainVerificationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let envelopes = parse_jsonl_lines(lines)?;
    verify_chain(&envelopes, &AuditChainHasher::unkeyed_dev_only())
}

pub fn verify_jsonl_lines_with_hasher<I, S>(
    lines: I,
    hasher: &AuditChainHasher,
) -> Result<ChainVerification, ChainVerificationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let envelopes = parse_jsonl_lines(lines)?;
    verify_chain(&envelopes, hasher)
}

pub fn verify_jsonl_lines_with_anchors<I, S>(
    lines: I,
    anchors: ChainVerificationAnchors,
    hasher: &AuditChainHasher,
) -> Result<ChainVerification, ChainVerificationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let envelopes = parse_jsonl_lines(lines)?;
    verify_chain_with_anchors(&envelopes, anchors, hasher)
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
    hasher: &AuditChainHasher,
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
        verify_chain_expected_prev_hash(&envelopes, envelopes[0].prev_hash, hasher)
    } else {
        verify_chain(&envelopes, hasher)
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
    hasher: &AuditChainHasher,
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
    Ok(hasher.hash_record(&bytes))
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
        create_audit_dir_all(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
trait AuditFileMode {
    fn audit_file_mode(&mut self) -> &mut Self;
}

#[cfg(unix)]
impl AuditFileMode for OpenOptions {
    fn audit_file_mode(&mut self) -> &mut Self {
        self.mode(0o600)
    }
}

#[cfg(not(unix))]
trait AuditFileMode {
    fn audit_file_mode(&mut self) -> &mut Self;
}

#[cfg(not(unix))]
impl AuditFileMode for OpenOptions {
    fn audit_file_mode(&mut self) -> &mut Self {
        self
    }
}

#[cfg(unix)]
fn create_audit_dir_all(path: &Path) -> Result<(), AuditError> {
    if path.exists() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(path).map_err(AuditError::Io)
}

#[cfg(not(unix))]
fn create_audit_dir_all(path: &Path) -> Result<(), AuditError> {
    fs::create_dir_all(path).map_err(AuditError::Io)
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
    format!(
        "{KEYED_HASH_PREFIX}{}",
        hex_lower(&hmac_sha256_bytes(secret, b"", bytes))
    )
}

fn hmac_sha256_bytes(secret: &[u8], context: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts any key length");
    if !context.is_empty() {
        mac.update(context);
        mac.update(&[0]);
    }
    mac.update(bytes);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// HKDF-Expand (RFC 5869) over SHA-256, producing one 32-byte output block.
///
/// The master env secret is already operator-supplied high-entropy material of
/// at least 32 bytes, so it is used directly as the HKDF pseudorandom key (PRK)
/// without a separate Extract step (Expand-only); a distinct per-purpose `info`
/// label domain-separates each derived sub-key. Because the SHA-256 output is a
/// single block, the counter byte is always `0x01` and no `T(0)` carry is
/// needed. The caller moves the returned bytes straight into the
/// `ZeroizeOnDrop` [`SecretBytes`] backing an [`AuditHashSecret`], so the
/// derived sub-key is scrubbed on drop without an intermediate copy.
fn hkdf_expand_sha256(prk: &[u8], info: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(prk).expect("HMAC-SHA256 accepts any key length");
    mac.update(info);
    mac.update(&[0x01]);
    mac.finalize().into_bytes().to_vec()
}

/// Derive a domain-separated [`AuditHashSecret`] sub-key from a master env
/// secret using [`hkdf_expand_sha256`] (AUDIT-03).
///
/// A leak of one derived sub-key reveals neither the master secret nor the
/// sibling sub-key, because each is a one-way HMAC over an independent `info`
/// label.
fn derive_subkey_from_env(env_var_name: &str, info: &[u8]) -> Result<AuditHashSecret, AuditError> {
    if env_var_name.trim().is_empty() {
        return Err(AuditError::EmptyEnvVarName);
    }
    let value = Zeroizing::new(env::var(env_var_name).map_err(|source| AuditError::EnvVar {
        name: env_var_name.to_string(),
        source,
    })?);
    if value.is_empty() {
        return Err(AuditError::EmptySecret {
            name: env_var_name.to_string(),
        });
    }
    // `value` (a `Zeroizing<String>`) owns and scrubs the master secret across
    // every return path; borrow its bytes for the length check and HKDF rather
    // than allocating a separate copy of the secret.
    if value.len() < MIN_AUDIT_SECRET_BYTES {
        return Err(AuditError::WeakSecret {
            name: env_var_name.to_string(),
            min_bytes: MIN_AUDIT_SECRET_BYTES,
        });
    }
    let derived = hkdf_expand_sha256(value.as_bytes(), info);
    Ok(AuditHashSecret::from_bytes(derived))
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
        let chain = ChainState::bootstrap_unkeyed_dev_only(&sink)
            .await
            .expect("bootstrap empty");

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
            sink.tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
                .await
                .expect("tail"),
            Some(second.record_hash)
        );

        let bootstrapped = ChainState::bootstrap_unkeyed_dev_only(&sink)
            .await
            .expect("bootstrap tail");
        let third = bootstrapped
            .append(&sink, json!({ "event": "third" }))
            .await
            .expect("third append");
        assert_eq!(third.prev_hash, Some(second.record_hash));

        let contents = fs::read_to_string(path).expect("audit file");
        let verification =
            verify_jsonl_lines_with_hasher(contents.lines(), &AuditChainHasher::unkeyed_dev_only())
                .expect("valid chain");
        assert_eq!(verification.records, 3);
        assert_eq!(verification.last_hash, Some(third.record_hash));
    }

    #[tokio::test]
    async fn keyed_chain_rejects_full_rewrite_without_secret() {
        let sink = MemorySink::default();
        let secret =
            AuditHashSecret::new(b"this-is-a-32-byte-chain-secret-ok".to_vec()).expect("secret");
        let hasher = AuditChainHasher::keyed(secret);
        let chain = ChainState::new(hasher.clone());
        let first = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("first append");
        let second = chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("second append");

        verify_chain(&[first.clone(), second.clone()], &hasher).expect("keyed chain verifies");

        let fake_first = AuditEnvelope::new(json!({ "event": "fake-first" }), None)
            .expect("attacker can build legacy first");
        let fake_second = AuditEnvelope::new(
            json!({ "event": "fake-second" }),
            Some(fake_first.record_hash),
        )
        .expect("attacker can build legacy second");

        assert!(matches!(
            verify_chain(&[fake_first, fake_second], &hasher),
            Err(ChainVerificationError::RecordHashMismatch { line: 1 })
        ));
    }

    #[tokio::test]
    async fn production_bootstrap_rejects_non_tailable_sink() {
        let hasher = AuditChainHasher::keyed(
            AuditHashSecret::new(b"this-is-a-32-byte-chain-secret-ok".to_vec()).expect("secret"),
        );

        assert!(matches!(
            ChainState::bootstrap(&JsonlStdoutSink::new(), hasher).await,
            Err(AuditError::NonTailableSink)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_sink_creates_private_file_and_directory_modes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let audit_dir = dir.path().join("private-audit");
        let path = audit_dir.join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);
        let chain = ChainState::unkeyed_dev_only();

        chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("append");

        let file_mode = fs::metadata(&path)
            .expect("file metadata")
            .permissions()
            .mode()
            & 0o777;
        let dir_mode = fs::metadata(&audit_dir)
            .expect("dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
    }

    #[tokio::test]
    async fn audit_chain_detects_inserted_envelope() {
        let sink = MemorySink::default();
        let chain = ChainState::unkeyed_dev_only();
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

        let err = verify_chain(&[first, third], &AuditChainHasher::unkeyed_dev_only())
            .expect_err("gap detected");
        assert!(matches!(
            err,
            ChainVerificationError::PrevHashMismatch { line: 2, .. }
        ));
    }

    #[test]
    fn audit_hash_secret_debug_never_exposes_raw_bytes() {
        let raw_bytes = b"this-is-a-32-byte-secret-1234567";
        let secret = AuditHashSecret::new(raw_bytes.to_vec()).expect("secret builds");

        let debug = format!("{secret:?}");

        assert!(
            debug.contains("<redacted>"),
            "debug must contain <redacted>"
        );
        assert!(
            !debug.contains("this-is-a-32-byte-secret-1234567"),
            "debug must not expose the raw secret bytes"
        );
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

        let err = verify_chain(&[first, second], &AuditChainHasher::unkeyed_dev_only())
            .expect_err("tamper detected");
        assert_eq!(err, ChainVerificationError::RecordHashMismatch { line: 2 });
    }

    #[test]
    fn audit_chain_detects_tampered_timestamp() {
        let mut envelope = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        envelope.timestamp_unix_ms += 1;

        let err = verify_chain(&[envelope], &AuditChainHasher::unkeyed_dev_only())
            .expect_err("tamper detected");
        assert_eq!(err, ChainVerificationError::RecordHashMismatch { line: 1 });
    }

    #[test]
    fn audit_chain_detects_tampered_envelope_id() {
        let mut envelope = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        envelope.envelope_id = Ulid::new().to_string();

        let err = verify_chain(&[envelope], &AuditChainHasher::unkeyed_dev_only())
            .expect_err("tamper detected");
        assert_eq!(err, ChainVerificationError::RecordHashMismatch { line: 1 });
    }

    #[tokio::test]
    async fn file_sink_rejects_missing_first_line_in_tail_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);
        let chain = ChainState::unkeyed_dev_only();
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
            sink.tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
                .await,
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
        let chain = ChainState::unkeyed_dev_only();
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
            ChainState::bootstrap_unkeyed_dev_only(&sink).await,
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
        let chain = ChainState::unkeyed_dev_only();
        let mut third_hash = None;
        for event in ["first", "second", "third"] {
            let envelope = chain
                .append(&sink, json!({ "event": event }))
                .await
                .expect("append");
            third_hash = Some(envelope.record_hash);
        }

        assert_eq!(
            sink.tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
                .await
                .expect("tail"),
            third_hash
        );
        let bootstrapped = ChainState::bootstrap_unkeyed_dev_only(&sink)
            .await
            .expect("bootstrap");
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
        let chain = ChainState::unkeyed_dev_only();
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
            sink.tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
                .await,
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
            verify_jsonl_lines_with_hasher(suffix.iter(), &AuditChainHasher::unkeyed_dev_only()),
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
            &AuditChainHasher::unkeyed_dev_only(),
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
        assert!(verify_chain(&rewritten, &AuditChainHasher::unkeyed_dev_only()).is_ok());

        let err = verify_chain_with_anchors(
            &rewritten,
            ChainVerificationAnchors::from_trusted_last_hash(second.record_hash),
            &AuditChainHasher::unkeyed_dev_only(),
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
            &AuditChainHasher::unkeyed_dev_only(),
        )
        .expect("anchored JSONL verifies");

        assert_eq!(verification.records, 2);
        assert_eq!(verification.last_hash, Some(second.record_hash));

        let err = verify_jsonl_lines_with_anchors(
            lines.iter(),
            ChainVerificationAnchors::from_trusted_last_hash([42; 32]),
            &AuditChainHasher::unkeyed_dev_only(),
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
        let chain = ChainState::unkeyed_dev_only();
        let first = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("first append");
        let second = chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("second append");

        assert_eq!(second.prev_hash, Some(first.record_hash));
        let bootstrapped = ChainState::bootstrap_unkeyed_dev_only(&sink)
            .await
            .expect("bootstrap");
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

    #[tokio::test]
    async fn audit_profile_uses_one_secret_for_chain_and_identifier_hashing() {
        let name = "REGISTRY_PLATFORM_AUDIT_PROFILE_TEST_SECRET";
        env::set_var(name, "0123456789abcdef0123456789abcdef");
        let profile = AuditProfile::registry_notary_from_env(name).expect("profile");
        env::remove_var(name);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);

        let chain = profile
            .bootstrap_or_start_empty(&sink)
            .await
            .expect("chain bootstraps");
        chain
            .append(&sink, json!({ "event": "profiled" }))
            .await
            .expect("append");
        let contents = fs::read_to_string(&path).expect("audit file");

        assert!(verify_jsonl_lines_with_hasher(
            contents.lines(),
            &AuditChainHasher::unkeyed_dev_only()
        )
        .is_err());
        verify_jsonl_lines_with_hasher(contents.lines(), &profile.chain_hasher())
            .expect("profile chain verifies");
        assert!(profile
            .key_hasher()
            .hash("subject-123")
            .starts_with(KEYED_HASH_PREFIX));
    }

    #[test]
    fn audit_profile_dev_mode_is_explicitly_unkeyed() {
        let profile = AuditProfile::unkeyed_dev_only();

        assert!(profile
            .key_hasher()
            .hash("subject-123")
            .starts_with(UNKEYED_HASH_PREFIX));
    }

    #[test]
    fn audit_reference_hash_is_domain_class_and_scope_separated() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();

        let base = hasher
            .audit_reference_hash(
                "matched-reference-v1",
                "purpose-a",
                r#"{"role":"target","handle":"abc"}"#,
            )
            .expect("reference hash");
        let other_class = hasher
            .audit_reference_hash(
                "matching-attempt-v1",
                "purpose-a",
                r#"{"role":"target","handle":"abc"}"#,
            )
            .expect("reference hash");
        let other_scope = hasher
            .audit_reference_hash(
                "matched-reference-v1",
                "purpose-b",
                r#"{"role":"target","handle":"abc"}"#,
            )
            .expect("reference hash");

        assert!(base.starts_with(UNKEYED_HASH_PREFIX));
        assert_ne!(base, hasher.hash(r#"{"role":"target","handle":"abc"}"#));
        assert_ne!(base, other_class);
        assert_ne!(base, other_scope);
    }

    #[test]
    fn audit_reference_hash_rejects_empty_class_or_input_but_allows_empty_scope() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();

        assert!(matches!(
            hasher.audit_reference_hash("", "scope", "canonical"),
            Err(AuditReferenceHashError::EmptyClass)
        ));
        assert!(matches!(
            hasher.audit_reference_hash("class", "scope", ""),
            Err(AuditReferenceHashError::EmptyCanonicalInput)
        ));
        assert!(hasher
            .audit_reference_hash("class", "", "canonical")
            .expect("empty scope is explicit")
            .starts_with(UNKEYED_HASH_PREFIX));
    }

    #[test]
    fn sensitive_value_hash_is_field_bound_and_reference_domain_separated() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();

        let first = hasher.sensitive_value_hash("person_id", "IND-001");
        let second = hasher.sensitive_value_hash("person_id", "IND-001");
        let other_field = hasher.sensitive_value_hash("household_id", "IND-001");

        assert_eq!(first, second);
        assert_ne!(first, other_field);
        assert_ne!(first, hasher.hash("person_id\0IND-001"));
        assert!(hasher
            .sensitive_value_hash("empty", "")
            .starts_with(UNKEYED_HASH_PREFIX));
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
        let chain = ChainState::unkeyed_dev_only();
        let mut envelope = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("append");
        envelope.record["event"] = json!("changed");
        fs::write(&path, envelope.to_jsonl().expect("jsonl")).expect("rewrite");

        assert!(matches!(
            sink.tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
                .await,
            Err(AuditError::ChainVerification(
                ChainVerificationError::RecordHashMismatch { line: 1 }
            ))
        ));
    }

    #[test]
    fn audit_hash_secret_round_trips_and_clones_share_bytes() {
        // AUDIT-02: zeroize-on-drop newtype must not change observable behavior.
        let raw = b"this-is-a-32-byte-chain-secret-ok".to_vec();
        let secret = AuditHashSecret::new(raw.clone()).expect("secret builds");
        assert_eq!(secret.as_bytes(), raw.as_slice());

        let cloned = secret.clone();
        // Clones share the same underlying Arc<SecretBytes> and observe equal bytes.
        assert_eq!(cloned.as_bytes(), secret.as_bytes());

        // Dropping one clone must not disturb the surviving clone's key material.
        drop(secret);
        assert_eq!(cloned.as_bytes(), raw.as_slice());

        // The hasher built from the secret still produces stable keyed output.
        let hasher = AuditKeyHasher::Keyed(cloned);
        let hashed = hasher.hash("subject-123");
        assert!(hashed.starts_with(KEYED_HASH_PREFIX));
    }

    #[test]
    fn audit_hash_secret_rejects_weak_secret() {
        // AUDIT-02: short keys still fail closed after the newtype change.
        assert!(matches!(
            AuditHashSecret::new(b"too-short".to_vec()),
            Err(AuditError::WeakSecret { .. })
        ));
    }

    #[test]
    fn production_profile_derives_separated_chain_and_identifier_keys() {
        // AUDIT-03: the chain key and identifier key must be independent derived
        // sub-keys of the master env secret, and neither may equal the master.
        let name = "REGISTRY_PLATFORM_AUDIT_KDF_TEST_SECRET";
        let master = "0123456789abcdef0123456789abcdef-master";
        env::set_var(name, master);

        let chain_key = derive_subkey_from_env(name, CHAIN_KEY_DERIVATION_INFO).expect("chain key");
        let ident_key =
            derive_subkey_from_env(name, IDENTIFIER_KEY_DERIVATION_INFO).expect("identifier key");
        env::remove_var(name);

        // Sub-keys differ from each other.
        assert_ne!(chain_key.as_bytes(), ident_key.as_bytes());
        // Sub-keys differ from the raw master env material.
        assert_ne!(chain_key.as_bytes(), master.as_bytes());
        assert_ne!(ident_key.as_bytes(), master.as_bytes());
        // HKDF-Expand over SHA-256 yields a single 32-byte block.
        assert_eq!(chain_key.as_bytes().len(), 32);
        assert_eq!(ident_key.as_bytes().len(), 32);
    }

    #[test]
    fn production_profile_key_derivation_is_deterministic_and_stable() {
        // AUDIT-03: the same env secret must yield the same derived sub-keys, so
        // a chain stays verifiable across process restarts.
        let name = "REGISTRY_PLATFORM_AUDIT_KDF_STABLE_SECRET";
        let master = "stable-master-secret-0123456789abcdef";
        env::set_var(name, master);

        let chain_a = derive_subkey_from_env(name, CHAIN_KEY_DERIVATION_INFO).expect("chain a");
        let chain_b = derive_subkey_from_env(name, CHAIN_KEY_DERIVATION_INFO).expect("chain b");
        env::remove_var(name);

        assert_eq!(chain_a.as_bytes(), chain_b.as_bytes());

        // Known-answer vector pins the HKDF-Expand-only construction.
        let expected = hkdf_expand_sha256(master.as_bytes(), CHAIN_KEY_DERIVATION_INFO);
        assert_eq!(chain_a.as_bytes(), expected.as_slice());
    }

    #[tokio::test]
    async fn audit_profile_chain_and_identifier_keys_are_domain_separated() {
        // AUDIT-03: the two profiles must agree on the derived chain key while
        // the identifier key stays distinct.
        let name = "REGISTRY_PLATFORM_AUDIT_PROFILE_KDF_SECRET";
        env::set_var(name, "profile-master-secret-0123456789abcdef");
        let profile = AuditProfile::production_from_env(name).expect("profile");
        let chain_profile = AuditChainProfile::production_from_env(name).expect("chain profile");
        env::remove_var(name);

        // Both profiles derive the same chain key, so a chain bootstrapped via
        // either verifies under the other's chain hasher.
        let first = AuditEnvelope::new_with_hasher(
            json!({ "event": "first" }),
            None,
            &profile.chain_hasher(),
        )
        .expect("first");
        verify_chain(std::slice::from_ref(&first), &chain_profile.hasher())
            .expect("cross-profile chain agrees");

        // The identifier key is keyed but domain-separated from the chain key.
        let identifier_hash = profile.key_hasher().hash("subject-123");
        assert!(identifier_hash.starts_with(KEYED_HASH_PREFIX));
        let unkeyed = AuditKeyHasher::unkeyed_dev_only().hash("subject-123");
        assert_ne!(identifier_hash, unkeyed);
    }

    #[test]
    fn query_redactor_redacts_oauth_and_credential_param_names() {
        // AUDIT-05: extended denylist covers OAuth/OIDC and credential params.
        let redactor = QueryRedactor::new(Vec::<String>::new());
        let redacted =
            redactor.redact_query("access_token=x&refresh_token=y&client_secret=z&bearer=b");

        assert_eq!(redacted["access_token"]["op"], "redacted");
        assert_eq!(redacted["refresh_token"]["op"], "redacted");
        assert_eq!(redacted["client_secret"]["op"], "redacted");
        assert_eq!(redacted["bearer"]["op"], "redacted");

        let serialized = redacted.to_string();
        assert!(!serialized.contains("\"x\""));
        assert!(!serialized.contains("\"y\""));
        assert!(!serialized.contains("\"z\""));
        assert!(!serialized.contains("\"b\""));
    }

    #[test]
    fn query_redactor_redacts_remaining_new_credential_param_names() {
        // AUDIT-05: exercise the rest of the added names for coverage.
        let redactor = QueryRedactor::new(Vec::<String>::new());
        let redacted = redactor.redact_query(
            "id_token=a&client_assertion=b&assertion=c&code=d&private_key=e&credential=f&credentials=g&passwd=h&pwd=i&session_token=j",
        );

        for name in [
            "id_token",
            "client_assertion",
            "assertion",
            "code",
            "private_key",
            "credential",
            "credentials",
            "passwd",
            "pwd",
            "session_token",
        ] {
            assert_eq!(redacted[name]["op"], "redacted", "{name} must be redacted");
        }
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

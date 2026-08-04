//! Fail-closed Mint audit over one durable, keyed JSONL chain.

use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use registry_platform_audit::{
    verify_jsonl_lines_with_hasher, AuditChainHasher, AuditEnvelope, AuditError, AuditHashSecret,
    AuditKeyHasher, AuditSink, ChainState, JsonlFileSink,
};
use registry_platform_canonical_json::canonicalize_json;
use serde::Serialize;
use thiserror::Error;

use crate::{
    assertion::AuthenticatedClient,
    config::AuditConfig,
    secretfile::{self, SecretFileError},
    token::MintedToken,
};

const AUDIT_SCHEMA: &str = "registry.mint.audit/v1";

#[derive(Debug, Error)]
pub enum MintAuditError {
    #[error("the audit hash key could not be read")]
    Secret(#[source] SecretFileError),
    #[error("the audit chain could not be initialized or written")]
    Audit(#[from] AuditError),
    #[error("an audit-safe reference could not be constructed")]
    Reference,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AuditPhase {
    TokenRelease,
    Denial,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AuditDecision {
    Issued,
    Rejected,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MintAuditEvent {
    schema: &'static str,
    operation: String,
    phase: AuditPhase,
    decision: AuditDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_pseudonym: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authority_pseudonym: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_pseudonym: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject_pseudonym: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at_unix: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    safe_error_category: Option<String>,
}

/// Minimal operator report returned by `mint verify-audit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintAuditSummary {
    pub records: usize,
    pub last_hash: Option<[u8; 32]>,
}

/// Process-lifetime Mint audit boundary.
pub struct MintAuditLog {
    sink: DurableJsonlSink,
    chain: ChainState,
    key_hasher: AuditKeyHasher,
    key_version: u32,
    scope: String,
}

impl std::fmt::Debug for MintAuditLog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MintAuditLog")
            .field("path", &self.sink.path)
            .field("key_version", &self.key_version)
            .finish_non_exhaustive()
    }
}

impl MintAuditLog {
    pub async fn initialize(config: &AuditConfig, issuer: &str) -> Result<Self, MintAuditError> {
        let secret =
            secretfile::read_owner_only(&config.hash_key_file).map_err(MintAuditError::Secret)?;
        let secret = AuditHashSecret::new(secret.as_bytes().to_vec())?;
        let chain_hasher = AuditChainHasher::keyed(secret.clone());
        let key_hasher = AuditKeyHasher::Keyed(secret);
        let sink = DurableJsonlSink::open(config.path.clone())?;
        let chain = ChainState::bootstrap_or_start_empty(&sink, chain_hasher).await?;
        Ok(Self {
            sink,
            chain,
            key_hasher,
            key_version: config.hash_key_version,
            scope: issuer.to_owned(),
        })
    }

    /// Verify the retained chain without taking the serving writer lock.
    pub fn verify(config: &AuditConfig) -> Result<MintAuditSummary, MintAuditError> {
        let secret =
            secretfile::read_owner_only(&config.hash_key_file).map_err(MintAuditError::Secret)?;
        let secret = AuditHashSecret::new(secret.as_bytes().to_vec())?;
        let hasher = AuditChainHasher::keyed(secret);
        let contents = match fs::read_to_string(&config.path) {
            Ok(contents) => {
                reject_unsafe_existing_path(&config.path)?;
                let parent = config.path.parent().ok_or_else(|| {
                    AuditError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Mint audit path has no parent",
                    ))
                })?;
                validate_owner_only_directory(parent)?;
                contents
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(AuditError::Io(error).into()),
        };
        let summary = verify_jsonl_lines_with_hasher(contents.lines(), &hasher)
            .map_err(AuditError::ChainVerification)?;
        Ok(MintAuditSummary {
            records: summary.records,
            last_hash: summary.last_hash,
        })
    }

    pub async fn append_issued(
        &self,
        operation: &str,
        authenticated: &AuthenticatedClient,
        token: &MintedToken,
    ) -> Result<AuditEnvelope, MintAuditError> {
        let client_pseudonym = self.pseudonym("client", authenticated.client.client_id())?;
        let grant = authenticated
            .client
            .grant()
            .map(|grant| serde_json::json!({"id": grant.id, "authority": grant.authority}));
        let authority = serde_json::json!({
            "principal": authenticated.client.principal(),
            "evidenceAudience": authenticated.client.evidence_audience(),
            "requesterTags": authenticated.client.requester_tags(),
            "grant": grant,
        });
        let authority = canonicalize_json(&authority).map_err(|_| MintAuditError::Reference)?;
        let authority = String::from_utf8(authority).map_err(|_| MintAuditError::Reference)?;
        let authority_pseudonym = self.pseudonym("authority", &authority)?;
        let (actor_pseudonym, subject_pseudonym) = match &authenticated.delegation {
            Some(delegation) => {
                let actor = self.pseudonym("actor", delegation.actor())?;
                let subject = serde_json::to_value(delegation.subject())
                    .map_err(|_| MintAuditError::Reference)?;
                let subject = canonicalize_json(&subject).map_err(|_| MintAuditError::Reference)?;
                let subject = String::from_utf8(subject).map_err(|_| MintAuditError::Reference)?;
                (Some(actor), Some(self.pseudonym("subject", &subject)?))
            }
            None => (None, None),
        };
        self.append(MintAuditEvent {
            schema: AUDIT_SCHEMA,
            operation: operation.to_owned(),
            phase: AuditPhase::TokenRelease,
            decision: AuditDecision::Issued,
            client_pseudonym: Some(client_pseudonym),
            authority_pseudonym: Some(authority_pseudonym),
            actor_pseudonym,
            subject_pseudonym,
            token_id: Some(token.token_id().to_owned()),
            signing_key_id: Some(token.signing_key_id().to_owned()),
            expires_at_unix: Some(token.expires_at_unix()),
            delegated: Some(authenticated.delegation.is_some()),
            safe_error_category: None,
        })
        .await
    }

    pub async fn append_rejected(
        &self,
        operation: &str,
        safe_error_category: &str,
    ) -> Result<AuditEnvelope, MintAuditError> {
        self.append(MintAuditEvent {
            schema: AUDIT_SCHEMA,
            operation: operation.to_owned(),
            phase: AuditPhase::Denial,
            decision: AuditDecision::Rejected,
            client_pseudonym: None,
            authority_pseudonym: None,
            actor_pseudonym: None,
            subject_pseudonym: None,
            token_id: None,
            signing_key_id: None,
            expires_at_unix: None,
            delegated: None,
            safe_error_category: Some(safe_error_category.to_owned()),
        })
        .await
    }

    #[must_use]
    pub fn ready(&self) -> bool {
        !self.sink.poisoned.load(Ordering::Acquire) && self.chain.try_last_hash().is_some()
    }

    fn pseudonym(&self, class: &str, protected: &str) -> Result<String, MintAuditError> {
        if protected.is_empty() {
            return Err(MintAuditError::Reference);
        }
        let digest = self
            .key_hasher
            .audit_reference_hash(class, &self.scope, protected)
            .map_err(|_| MintAuditError::Reference)?;
        Ok(format!("hmac-sha256:v{}:{digest}", self.key_version))
    }

    async fn append(&self, event: MintAuditEvent) -> Result<AuditEnvelope, MintAuditError> {
        self.chain
            .append(&self.sink, event)
            .await
            .map_err(MintAuditError::from)
    }
}

/// Platform JSONL chaining plus an fsync boundary and permanent poisoning after
/// an uncertain write. Rotation is deliberately absent: retention remains an
/// explicit operator action and no retained Mint history is silently deleted.
struct DurableJsonlSink {
    inner: JsonlFileSink,
    path: PathBuf,
    poisoned: Arc<AtomicBool>,
}

impl std::fmt::Debug for DurableJsonlSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableJsonlSink")
            .field("path", &self.path)
            .field("poisoned", &self.poisoned.load(Ordering::Relaxed))
            .finish()
    }
}

impl DurableJsonlSink {
    fn open(path: PathBuf) -> Result<Self, AuditError> {
        reject_unsafe_existing_path(&path)?;
        let inner = JsonlFileSink::with_rotation_single_writer(&path, 0, 1)?;
        let parent = path.parent().ok_or_else(|| {
            AuditError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Mint audit path has no parent",
            ))
        })?;
        validate_owner_only_directory(parent)?;
        reject_unsafe_existing_path(&lock_path(&path))?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .map_err(AuditError::Io)?;
        validate_owner_only_file(&file)?;
        sync_file_and_parent(&path)?;
        Ok(Self {
            inner,
            path,
            poisoned: Arc::new(AtomicBool::new(false)),
        })
    }

    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }

    fn check_writable(&self) -> Result<(), AuditError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(AuditError::Io(io::Error::other(
                "Mint audit stopped after a failed durable write",
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl AuditSink for DurableJsonlSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        self.check_writable()?;
        if let Err(error) = self.inner.write(envelope).await {
            self.poison();
            return Err(error);
        }
        let path = self.path.clone();
        match tokio::task::spawn_blocking(move || sync_file_and_parent(&path)).await {
            Ok(Ok(())) => Ok(()),
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
        self.inner
            .tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
            .await
    }

    async fn tail_hash_with_hasher(
        &self,
        hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        self.inner.tail_hash_with_hasher(hasher).await
    }
}

fn reject_unsafe_existing_path(path: &Path) -> Result<(), AuditError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
            {
                return Err(AuditError::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Mint audit file is not an owner-only, single-link regular file",
                )));
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
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
            io::ErrorKind::PermissionDenied,
            "Mint audit directory is not an owner-only directory",
        )));
    }
    Ok(())
}

fn lock_path(path: &Path) -> PathBuf {
    let mut raw = path.as_os_str().to_os_string();
    raw.push(".lock");
    PathBuf::from(raw)
}

fn validate_owner_only_file(file: &File) -> Result<(), AuditError> {
    let metadata = file.metadata().map_err(AuditError::Io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(AuditError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Mint audit file is not an owner-only, single-link regular file",
        )));
    }
    Ok(())
}

fn sync_file_and_parent(path: &Path) -> Result<(), AuditError> {
    reject_unsafe_existing_path(path)?;
    let file = File::open(path).map_err(AuditError::Io)?;
    validate_owner_only_file(&file)?;
    file.sync_all().map_err(AuditError::Io)?;
    let parent = path.parent().ok_or_else(|| {
        AuditError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Mint audit path has no parent",
        ))
    })?;
    validate_owner_only_directory(parent)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(AuditError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> (tempfile::TempDir, AuditConfig) {
        let directory = tempfile::tempdir().expect("temp dir");
        let secret = directory.path().join("audit-key");
        fs::write(&secret, "0123456789abcdef0123456789abcdef").expect("write audit key");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).expect("restrict key");
        let config = AuditConfig {
            path: directory.path().join("audit/mint.jsonl"),
            hash_key_file: secret,
            hash_key_version: 1,
        };
        (directory, config)
    }

    #[tokio::test]
    async fn a_keyed_chain_restarts_and_verifies() {
        let (_directory, config) = fixture();
        {
            let audit = MintAuditLog::initialize(&config, "https://mint.example.org")
                .await
                .expect("audit initializes");
            audit
                .append_rejected("urn:ulid:01K00000000000000000000000", "invalid-client")
                .await
                .expect("first decision is durable");
        }
        {
            let audit = MintAuditLog::initialize(&config, "https://mint.example.org")
                .await
                .expect("audit restarts");
            audit
                .append_rejected("urn:ulid:01K00000000000000000000001", "invalid-request")
                .await
                .expect("second decision is durable");
        }
        let summary = MintAuditLog::verify(&config).expect("chain verifies");
        assert_eq!(summary.records, 2);
        assert!(summary.last_hash.is_some());
    }

    #[tokio::test]
    async fn a_second_writer_is_refused() {
        let (_directory, config) = fixture();
        let first = MintAuditLog::initialize(&config, "https://mint.example.org")
            .await
            .expect("first writer initializes");
        let second = MintAuditLog::initialize(&config, "https://mint.example.org").await;
        assert!(second.is_err(), "a second writer must not fork the chain");
        drop(first);
    }

    #[tokio::test]
    async fn corruption_is_refused_at_restart_and_verification() {
        let (_directory, config) = fixture();
        {
            let audit = MintAuditLog::initialize(&config, "https://mint.example.org")
                .await
                .expect("audit initializes");
            audit
                .append_rejected("urn:ulid:01K00000000000000000000000", "invalid-client")
                .await
                .expect("decision is durable");
        }
        let mut contents = fs::read_to_string(&config.path).expect("read chain");
        contents = contents.replace("invalid-client", "invalid-request");
        fs::write(&config.path, contents).expect("tamper with chain");
        assert!(MintAuditLog::verify(&config).is_err());
        assert!(
            MintAuditLog::initialize(&config, "https://mint.example.org")
                .await
                .is_err()
        );
    }
}

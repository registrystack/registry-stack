// SPDX-License-Identifier: Apache-2.0
//! Local file-backed provenance signer with on-use reload.

use std::fs;
use std::sync::RwLock;
use std::time::SystemTime;

use registry_platform_crypto::KeyReadiness;
use serde_json::Value;
use sha2::Digest as _;
use zeroize::Zeroizing;

use crate::config::FileWatchSignerConfig;

use super::super::signer::{Signer, SignerError, SigningAlgorithm};
use super::software::SoftwareSigner;

struct FileWatchState {
    signer: SoftwareSigner,
    readiness: KeyReadiness,
    key_mtime: SystemTime,
    last_content_digest: Option<[u8; 32]>,
}

/// Signer backed by a local private JWK file.
///
/// The file mtime is checked on signer use. A valid replacement for the same
/// public key identity becomes active for new requests without process restart.
/// A malformed or different-key replacement degrades readiness but keeps the
/// last good signer available.
pub struct FileWatchSigner {
    algorithm: SigningAlgorithm,
    verification_method_id: String,
    path: std::path::PathBuf,
    expected_public_jwk: Value,
    state: RwLock<FileWatchState>,
}

impl std::fmt::Debug for FileWatchSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileWatchSigner")
            .field("algorithm", &self.algorithm)
            .field("verification_method_id", &self.verification_method_id)
            .field("readiness", &self.readiness())
            .finish_non_exhaustive()
    }
}

impl FileWatchSigner {
    pub fn from_config(
        cfg: &FileWatchSignerConfig,
        verification_method_id: String,
    ) -> Result<Self, SignerError> {
        let algorithm = cfg.signing_algorithm.into();
        let key_mtime = key_file_mtime(&cfg.path)?;
        let raw = read_key_file(&cfg.path)?;
        let last_content_digest = key_file_content_digest(&cfg.path).ok();
        let signer = SoftwareSigner::from_jwk_str(&raw, algorithm, verification_method_id.clone())?;
        let expected_public_jwk = signer.public_jwk();
        Ok(Self {
            algorithm,
            verification_method_id,
            path: cfg.path.clone(),
            expected_public_jwk,
            state: RwLock::new(FileWatchState {
                signer,
                readiness: KeyReadiness::Ready,
                key_mtime,
                last_content_digest,
            }),
        })
    }

    fn refresh_if_changed(&self) {
        let Ok(key_mtime) = key_file_mtime(&self.path) else {
            if let Ok(mut state) = self.state.write() {
                let was_ready = state.readiness == KeyReadiness::Ready;
                state.readiness = KeyReadiness::Degraded;
                if was_ready {
                    tracing::warn!(
                        event = "provenance.file_watch_key_unreadable",
                        verification_method_id = %self.verification_method_id,
                        "file_watch signer key file could not be read; keeping last good signer",
                    );
                }
            }
            return;
        };

        // Compute a content digest to detect same-mtime replacements (e.g. `cp -p`,
        // snapshot restore, coarse filesystem timestamp resolution). This read happens
        // at most once per call, and key files are small, so the cost is negligible.
        let content_digest = key_file_content_digest(&self.path).ok();

        if self
            .state
            .read()
            .map(|state| {
                let mtime_unchanged = state.key_mtime == key_mtime;
                let digest_unchanged =
                    content_digest.is_some() && state.last_content_digest == content_digest;
                mtime_unchanged && digest_unchanged
            })
            .unwrap_or(false)
        {
            return;
        }

        let Ok(mut state) = self.state.write() else {
            return;
        };
        // Re-check under the write lock.
        let mtime_unchanged = state.key_mtime == key_mtime;
        let digest_unchanged =
            content_digest.is_some() && state.last_content_digest == content_digest;
        if mtime_unchanged && digest_unchanged {
            return;
        }

        // Update both mtime and digest whenever we attempt a reload, regardless of outcome.
        state.key_mtime = key_mtime;
        state.last_content_digest = content_digest;

        let Ok(raw) = read_key_file(&self.path) else {
            state.readiness = KeyReadiness::Degraded;
            tracing::warn!(
                event = "provenance.file_watch_key_unreadable",
                verification_method_id = %self.verification_method_id,
                "file_watch signer key file could not be read after change detected; keeping last good signer",
            );
            return;
        };
        match SoftwareSigner::from_jwk_str(
            &raw,
            self.algorithm,
            self.verification_method_id.clone(),
        ) {
            Ok(signer) if signer.public_jwk() == self.expected_public_jwk => {
                state.signer = signer;
                state.readiness = KeyReadiness::Ready;
            }
            Ok(_) => {
                state.readiness = KeyReadiness::Degraded;
                tracing::warn!(
                    event = "provenance.file_watch_key_mismatch",
                    verification_method_id = %self.verification_method_id,
                    "file_watch signer replacement key did not match the configured public key; keeping last good signer",
                );
            }
            Err(error) => {
                state.readiness = KeyReadiness::Degraded;
                tracing::warn!(
                    event = "provenance.file_watch_key_invalid",
                    verification_method_id = %self.verification_method_id,
                    error = %error,
                    "file_watch signer replacement key could not be loaded; keeping last good signer",
                );
            }
        }
    }
}

fn key_file_content_digest(path: &std::path::Path) -> Result<[u8; 32], SignerError> {
    let bytes = fs::read(path).map_err(|_| SignerError::KeyLoad {
        reason: "file_watch key file could not be read",
    })?;
    Ok(sha2::Sha256::digest(&bytes).into())
}

fn key_file_mtime(path: &std::path::Path) -> Result<SystemTime, SignerError> {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .map_err(|_| SignerError::KeyLoad {
            reason: "file_watch key file could not be read",
        })
}

fn read_key_file(path: &std::path::Path) -> Result<Zeroizing<String>, SignerError> {
    fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|_| SignerError::KeyLoad {
            reason: "file_watch key file could not be read",
        })
}

impl Signer for FileWatchSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    fn verification_method_id(&self) -> &str {
        &self.verification_method_id
    }

    fn sign(&self, header: Value, payload: Value) -> Result<String, SignerError> {
        self.refresh_if_changed();
        let state = self.state.read().map_err(|_| SignerError::Unavailable)?;
        state.signer.sign(header, payload)
    }

    fn public_jwk(&self) -> Value {
        self.refresh_if_changed();
        self.state
            .read()
            .map(|state| state.signer.public_jwk())
            .unwrap_or(Value::Null)
    }

    fn readiness(&self) -> KeyReadiness {
        self.refresh_if_changed();
        self.state
            .read()
            .map(|state| state.readiness)
            .unwrap_or(KeyReadiness::NotReady)
    }
}

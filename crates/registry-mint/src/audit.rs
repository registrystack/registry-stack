//! Fail-closed Mint audit over one durable, segmented keyed JSONL chain.

use registry_platform_audit::{
    verify_segmented_audit_chain, AuditEnvelope, AuditError, AuditKeyHasher, AuditProfile,
    ChainState, DurableSegmentedJsonlSink,
};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::{SecretError, SecretProvider, SecretResolver};
use serde::Serialize;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    assertion::AuthenticatedClient,
    config::{AuditConfig, SecretProvidersConfig},
    token::MintedToken,
};

const AUDIT_SCHEMA: &str = "registry.mint.audit/v1";

#[derive(Debug, Error)]
pub enum MintAuditError {
    #[error("the audit hash key could not be read")]
    Secret(#[source] SecretError),
    #[error("the audit chain could not be initialized or written")]
    Audit(#[from] AuditError),
    #[error("an audit-safe reference could not be constructed")]
    Reference,
    #[error(
        "sealed segment {sequence} is archived or missing from the chain; this is not corruption"
    )]
    SegmentMissing { sequence: u64 },
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
    pub segments: usize,
    pub records: usize,
    pub last_hash: Option<[u8; 32]>,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub active_verified: bool,
}

/// Process-lifetime Mint audit boundary.
pub struct MintAuditLog {
    sink: DurableSegmentedJsonlSink,
    chain: ChainState,
    key_hasher: AuditKeyHasher,
    key_version: u32,
    scope: String,
}

impl std::fmt::Debug for MintAuditLog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MintAuditLog")
            .field("path", &self.sink.path())
            .field("key_version", &self.key_version)
            .finish_non_exhaustive()
    }
}

impl MintAuditLog {
    pub async fn initialize(
        config: &AuditConfig,
        secrets: &SecretProvidersConfig,
        issuer: &str,
    ) -> Result<Self, MintAuditError> {
        let profile = audit_profile(config, secrets)?;
        let sink = DurableSegmentedJsonlSink::open(config.path.clone(), config.maximum_file_bytes)?;
        let chain = profile.bootstrap_or_start_empty(&sink).await?;
        Ok(Self {
            sink,
            chain,
            key_hasher: profile.key_hasher(),
            key_version: config.hash_key_version,
            scope: issuer.to_owned(),
        })
    }

    /// Check the audit configuration without taking the serving writer lock.
    ///
    /// `mint check` reads a configuration while the deployment it describes is
    /// usually still serving, and the chain admits one writer for the life of
    /// that process. Opening the sink here would report a healthy deployment
    /// back as a broken one. The hash key is what a misconfigured deployment
    /// actually gets wrong, and reading it takes nothing the writer holds.
    pub fn check(
        config: &AuditConfig,
        secrets: &SecretProvidersConfig,
    ) -> Result<(), MintAuditError> {
        audit_profile(config, secrets)?;
        Ok(())
    }

    /// Verify the retained chain without taking the serving writer lock.
    pub fn verify(
        config: &AuditConfig,
        secrets: &SecretProvidersConfig,
    ) -> Result<MintAuditSummary, MintAuditError> {
        let profile = audit_profile(config, secrets)?;
        let summary = verify_segmented_audit_chain(&config.path, &profile.chain_hasher()).map_err(
            |error| match error {
                AuditError::SegmentMissing { sequence } => {
                    MintAuditError::SegmentMissing { sequence }
                }
                error => MintAuditError::Audit(error),
            },
        )?;
        Ok(MintAuditSummary {
            segments: summary.segments,
            records: summary.records,
            last_hash: summary.last_hash,
            first_sequence: summary.first_sequence,
            last_sequence: summary.last_sequence,
            active_verified: summary.active_verified,
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
    pub async fn ready(&self) -> bool {
        self.chain.try_last_hash().is_some() && self.sink.ready().await
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

fn audit_profile(
    config: &AuditConfig,
    secrets: &SecretProvidersConfig,
) -> Result<AuditProfile, MintAuditError> {
    let resolver = SecretResolver::new([SecretProvider::File], secrets.file.root.clone())
        .map_err(MintAuditError::Secret)?;
    let secret = resolver
        .resolve(&config.hash_key_ref)
        .map_err(MintAuditError::Secret)?;
    AuditProfile::production_from_secret_bytes(Zeroizing::new(secret.expose_secret().to_vec()))
        .map_err(MintAuditError::Audit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    // A fixed, non-secret audit HMAC key. Held as a byte literal rather than
    // written inline so a secret scanner does not read the write call as an
    // assignment of a live credential.
    const AUDIT_HASH_KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn fixture() -> (tempfile::TempDir, AuditConfig, SecretProvidersConfig) {
        let directory = tempfile::tempdir().expect("temp dir");
        let secret = directory.path().join("audit-key");
        fs::write(&secret, AUDIT_HASH_KEY).expect("write audit key");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).expect("restrict key");
        let config = AuditConfig {
            path: directory.path().join("audit/mint.jsonl"),
            maximum_file_bytes: 1_048_576,
            hash_key_ref: "secret:file/audit-key".to_owned(),
            hash_key_version: 1,
        };
        let secrets = SecretProvidersConfig {
            file: crate::config::FileSecretProviderConfig {
                root: directory.path().to_path_buf(),
            },
        };
        (directory, config, secrets)
    }

    #[tokio::test]
    async fn a_keyed_chain_restarts_and_verifies() {
        let (_directory, config, secrets) = fixture();
        {
            let audit = MintAuditLog::initialize(&config, &secrets, "https://mint.example.org")
                .await
                .expect("audit initializes");
            audit
                .append_rejected("urn:ulid:01K00000000000000000000000", "invalid-client")
                .await
                .expect("first decision is durable");
        }
        {
            let audit = MintAuditLog::initialize(&config, &secrets, "https://mint.example.org")
                .await
                .expect("audit restarts");
            audit
                .append_rejected("urn:ulid:01K00000000000000000000001", "invalid-request")
                .await
                .expect("second decision is durable");
        }
        let summary = MintAuditLog::verify(&config, &secrets).expect("chain verifies");
        assert_eq!(summary.segments, 1);
        assert_eq!(summary.records, 2);
        assert!(summary.last_hash.is_some());
        assert!(summary.active_verified);
    }

    #[tokio::test]
    async fn a_second_writer_is_refused() {
        let (_directory, config, secrets) = fixture();
        let first = MintAuditLog::initialize(&config, &secrets, "https://mint.example.org")
            .await
            .expect("first writer initializes");
        let second = MintAuditLog::initialize(&config, &secrets, "https://mint.example.org").await;
        assert!(second.is_err(), "a second writer must not fork the chain");
        drop(first);
    }

    #[tokio::test]
    async fn corruption_is_refused_at_restart_and_verification() {
        let (_directory, config, secrets) = fixture();
        {
            let audit = MintAuditLog::initialize(&config, &secrets, "https://mint.example.org")
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
        assert!(MintAuditLog::verify(&config, &secrets).is_err());
        assert!(
            MintAuditLog::initialize(&config, &secrets, "https://mint.example.org")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_replacement_master_cannot_append_to_an_existing_epoch() {
        let (directory, config, secrets) = fixture();
        {
            let audit = MintAuditLog::initialize(&config, &secrets, "https://mint.example.org")
                .await
                .expect("audit initializes");
            audit
                .append_rejected("urn:ulid:01K00000000000000000000000", "invalid-client")
                .await
                .expect("decision is durable");
        }
        fs::write(
            directory.path().join("audit-key"),
            b"abcdef0123456789abcdef0123456789",
        )
        .expect("replace audit key");

        assert!(MintAuditLog::verify(&config, &secrets).is_err());
        assert!(
            MintAuditLog::initialize(&config, &secrets, "https://mint.example.org")
                .await
                .is_err(),
            "a new audit master must start a fresh path and epoch"
        );
    }

    #[tokio::test]
    async fn rotation_seals_history_without_breaking_restart_or_verification() {
        let (_directory, mut config, secrets) = fixture();
        config.maximum_file_bytes = 550;
        {
            let audit = MintAuditLog::initialize(&config, &secrets, "https://mint.example.org")
                .await
                .expect("audit initializes");
            for index in 0..8 {
                audit
                    .append_rejected(
                        &format!("urn:ulid:01K0000000000000000000000{index}"),
                        "invalid-client",
                    )
                    .await
                    .expect("decision is durable");
            }
        }
        let first_segment = config.path.with_extension("jsonl.00000001");
        assert!(first_segment.exists(), "rotation seals the active segment");
        let summary = MintAuditLog::verify(&config, &secrets).expect("segmented chain verifies");
        assert_eq!(summary.records, 8);
        assert!(summary.segments > 1);
        assert_eq!(summary.first_sequence, Some(1));

        let restarted = MintAuditLog::initialize(&config, &secrets, "https://mint.example.org")
            .await
            .expect("audit restarts from the segmented tail");
        restarted
            .append_rejected("urn:ulid:01K00000000000000000000009", "invalid-request")
            .await
            .expect("post-restart decision is durable");
    }
}

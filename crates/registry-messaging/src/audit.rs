// SPDX-License-Identifier: Apache-2.0

//! The audit journal: one keyed hash chain the runtime appends every
//! audited act to, and the keyed pseudonym that names a principal in it.
//!
//! A record names a caller only by pseudonym: an HMAC over the verified
//! issuer and subject, under the identifier sub-key the audit master secret
//! derives. The journal never carries the subject, a contact, message
//! content, or template data.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use registry_messaging_core::{CallerIdentity, Recipient};
use registry_platform_audit::{
    segmented_audit_paths, AuditEnvelope, AuditError, AuditKeyHasher, AuditProfile,
    AuditReferenceHashError, AuditSink, ChainState, DurableSegmentedJsonlSink,
};
use registry_platform_canonical_json::{canonicalize_json, JcsError};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

/// The largest active audit segment before the sink seals it and opens the
/// next one.
const MAXIMUM_AUDIT_SEGMENT_BYTES: u64 = 10 * 1024 * 1024;

/// The reference class principal pseudonyms are hashed under.
const PRINCIPAL_PSEUDONYM_CLASS: &str = "messaging-principal-v1";

/// The reference class recipient references are hashed under, scoped by
/// channel.
const RECIPIENT_REFERENCE_CLASS: &str = "messaging-recipient-v1";

/// Why a principal pseudonym could not be derived. No variant carries the
/// identity it was derived from.
#[derive(Debug, Error)]
pub enum PseudonymError {
    #[error("the principal could not be written canonically: {0}")]
    Canonical(#[from] JcsError),
    #[error("the canonical principal is not UTF-8")]
    Encoding,
    #[error(transparent)]
    Hash(#[from] AuditReferenceHashError),
}

pub struct AuditJournal {
    sink: Arc<dyn AuditSink>,
    chain: ChainState,
    keys: AuditKeyHasher,
    /// The journal file, when the journal is durable.
    path: Option<PathBuf>,
}

impl std::fmt::Debug for AuditJournal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuditJournal")
            .finish_non_exhaustive()
    }
}

impl AuditJournal {
    /// Open the durable journal at `path`, recovering the chain it holds
    /// under the profile's keyed chain hasher.
    pub async fn open(path: &Path, profile: &AuditProfile) -> Result<Self, AuditError> {
        let sink = Arc::new(DurableSegmentedJsonlSink::open(
            path,
            MAXIMUM_AUDIT_SEGMENT_BYTES,
        )?);
        let chain = profile.bootstrap_or_start_empty(sink.as_ref()).await?;
        let mut journal = Self::new(sink, chain, profile.key_hasher());
        journal.path = Some(path.to_path_buf());
        Ok(journal)
    }

    #[must_use]
    pub fn new(sink: Arc<dyn AuditSink>, chain: ChainState, keys: AuditKeyHasher) -> Self {
        Self {
            sink,
            chain,
            keys,
            path: None,
        }
    }

    /// The `eventId` of the journal's most recent outbox record, when the
    /// journal is durable and holds one. Records the runtime appends
    /// directly carry no event id and are passed over. The outbox publisher
    /// marks the id published before appending anything, so a crash between
    /// an append and its mark never appends one record twice.
    pub fn last_event_id(&self) -> Result<Option<Uuid>, AuditError> {
        let Some(path) = &self.path else {
            return Ok(None);
        };
        for candidate in segmented_audit_paths(path)?.into_iter().rev() {
            let contents = match std::fs::read_to_string(&candidate) {
                Ok(contents) => contents,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(AuditError::Io(error)),
            };
            for line in contents.lines().rev().filter(|line| !line.is_empty()) {
                let envelope = serde_json::from_str::<AuditEnvelope>(line)
                    .map_err(|error| AuditError::Io(std::io::Error::other(error)))?;
                let Some(value) = envelope.record.get("eventId") else {
                    continue;
                };
                let event_id = value
                    .as_str()
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .ok_or_else(|| {
                        AuditError::Io(std::io::Error::other("audit record eventId is malformed"))
                    })?;
                return Ok(Some(event_id));
            }
        }
        Ok(None)
    }

    /// Append one record to the chain. The record is durable when this
    /// returns; a failure leaves the chain where it was.
    pub async fn append<T: Serialize + Send>(&self, record: T) -> Result<(), AuditError> {
        self.chain.append(self.sink.as_ref(), record).await?;
        Ok(())
    }

    /// The keyed pseudonym that names `identity` in the journal: a hash of
    /// the canonical JSON array `[issuer, subject]`, so no two identities
    /// share an input.
    pub fn principal_pseudonym(&self, identity: &CallerIdentity) -> Result<String, PseudonymError> {
        let canonical = canonicalize_json(&serde_json::Value::from(vec![
            identity.issuer.as_str(),
            identity.subject.as_str(),
        ]))?;
        let canonical = std::str::from_utf8(&canonical).map_err(|_| PseudonymError::Encoding)?;
        Ok(self
            .keys
            .audit_reference_hash(PRINCIPAL_PSEUDONYM_CLASS, "", canonical)?)
    }

    /// The keyed reference that names `recipient` in the journal, scoped by
    /// its channel. An email address is compared without letter case, so
    /// one mailbox written two ways has one reference.
    pub fn recipient_reference(
        &self,
        recipient: &Recipient,
    ) -> Result<String, AuditReferenceHashError> {
        let normalized = match recipient {
            Recipient::Email(address) => address.to_ascii_lowercase(),
            Recipient::Phone(number) => number.clone(),
        };
        self.keys.audit_reference_hash(
            RECIPIENT_REFERENCE_CLASS,
            recipient.channel().as_str(),
            &normalized,
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::sync::Mutex;

    use async_trait::async_trait;
    use registry_platform_audit::{AuditChainHasher, AuditEnvelope};
    use serde_json::Value;

    /// An in-memory sink that can be told to refuse writes.
    #[derive(Default)]
    pub(crate) struct MemorySink {
        pub(crate) records: Mutex<Vec<Value>>,
        pub(crate) refuse: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl AuditSink for MemorySink {
        async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
            if self.refuse.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(AuditError::Io(std::io::Error::other("refused")));
            }
            self.records
                .lock()
                .unwrap()
                .push(serde_json::to_value(&envelope.record).unwrap());
            Ok(())
        }

        async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(None)
        }

        async fn tail_hash_with_hasher(
            &self,
            _hasher: &AuditChainHasher,
        ) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(None)
        }
    }

    pub(crate) fn memory_journal() -> (Arc<MemorySink>, AuditJournal) {
        let sink = Arc::new(MemorySink::default());
        let journal = AuditJournal::new(
            Arc::clone(&sink) as Arc<dyn AuditSink>,
            ChainState::unkeyed_dev_only(),
            AuditKeyHasher::unkeyed_dev_only(),
        );
        (sink, journal)
    }

    #[tokio::test]
    async fn the_last_event_id_passes_over_records_appended_directly() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit").join("messaging.jsonl");
        let profile =
            AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(vec![7u8; 32]))
                .unwrap();
        let journal = AuditJournal::open(&path, &profile).await.unwrap();
        assert_eq!(journal.last_event_id().unwrap(), None);
        journal
            .append(serde_json::json!({"event": "direct"}))
            .await
            .unwrap();
        assert_eq!(journal.last_event_id().unwrap(), None);
        let event_id = Uuid::from_u128(42);
        journal
            .append(serde_json::json!({"event": "outbox", "eventId": event_id.to_string()}))
            .await
            .unwrap();
        journal
            .append(serde_json::json!({"event": "direct"}))
            .await
            .unwrap();
        assert_eq!(journal.last_event_id().unwrap(), Some(event_id));
        let (_, memory) = memory_journal();
        assert_eq!(memory.last_event_id().unwrap(), None);
    }

    #[test]
    fn a_pseudonym_is_keyed_stable_and_never_the_subject() {
        let identity = CallerIdentity {
            issuer: "https://identity.example.test".to_owned(),
            subject: "subject-1".to_owned(),
        };
        let first =
            AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(vec![7u8; 32]))
                .unwrap();
        let second =
            AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(vec![8u8; 32]))
                .unwrap();
        let (_, journal) = memory_journal();
        let keyed = AuditJournal::new(
            Arc::new(MemorySink::default()),
            ChainState::unkeyed_dev_only(),
            first.key_hasher(),
        );
        let other_key = AuditJournal::new(
            Arc::new(MemorySink::default()),
            ChainState::unkeyed_dev_only(),
            second.key_hasher(),
        );
        let pseudonym = keyed.principal_pseudonym(&identity).unwrap();
        assert_eq!(pseudonym, keyed.principal_pseudonym(&identity).unwrap());
        assert_ne!(pseudonym, other_key.principal_pseudonym(&identity).unwrap());
        assert_ne!(pseudonym, journal.principal_pseudonym(&identity).unwrap());
        assert!(!pseudonym.contains("subject-1"));
        let other_subject = CallerIdentity {
            subject: "subject-2".to_owned(),
            ..identity
        };
        assert_ne!(
            pseudonym,
            keyed.principal_pseudonym(&other_subject).unwrap()
        );
    }

    /// The pseudonym keys stored idempotency records and journal entries,
    /// so its input bytes must never change: they are the JSON array
    /// `[issuer, subject]` as written before the canonical form was used.
    #[test]
    fn a_pseudonym_hashes_the_same_bytes_for_every_identity() {
        let profile =
            AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(vec![7u8; 32]))
                .unwrap();
        let journal = AuditJournal::new(
            Arc::new(MemorySink::default()),
            ChainState::unkeyed_dev_only(),
            profile.key_hasher(),
        );
        let identity = CallerIdentity {
            issuer: "https://identity.example.test".to_owned(),
            subject: "subject-1".to_owned(),
        };
        assert_eq!(
            journal.principal_pseudonym(&identity).unwrap(),
            "hmac-sha256:19a895369f72bc0bdbb87af912bc8ddbbb71e033f88db2703d3dd1d5dad58b9a"
        );
        for (issuer, subject) in [
            ("https://identity.example.test/", "quote\" back\\slash"),
            ("https://identity.example.test", "tab\t newline\n return\r"),
            (
                "https://identity.example.test",
                "control\u{1}\u{8}\u{c}\u{1f}\u{7f}",
            ),
            (
                "https://identity.example.test",
                "\u{e9} \u{65e5}\u{672c} \u{1f600} \u{2028}",
            ),
            ("", "slash/</script>"),
        ] {
            let identity = CallerIdentity {
                issuer: issuer.to_owned(),
                subject: subject.to_owned(),
            };
            let written = serde_json::Value::from(vec![issuer, subject]).to_string();
            assert_eq!(
                journal.principal_pseudonym(&identity).unwrap(),
                journal
                    .keys
                    .audit_reference_hash(PRINCIPAL_PSEUDONYM_CLASS, "", &written)
                    .unwrap()
            );
        }
    }
}

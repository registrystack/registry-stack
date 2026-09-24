// SPDX-License-Identifier: Apache-2.0

//! The audit journal: one keyed hash chain the runtime appends every
//! audited act to, and the keyed pseudonym that names a principal in it.
//!
//! A record names a caller only by pseudonym: an HMAC over the verified
//! issuer and subject, under the identifier sub-key the audit master secret
//! derives. The journal never carries the subject, a contact, message
//! content, or template data.

use std::path::Path;
use std::sync::Arc;

use registry_messaging_core::CallerIdentity;
use registry_platform_audit::{
    AuditError, AuditKeyHasher, AuditProfile, AuditReferenceHashError, AuditSink, ChainState,
    DurableSegmentedJsonlSink,
};
use serde::Serialize;

/// The largest active audit segment before the sink seals it and opens the
/// next one.
const MAXIMUM_AUDIT_SEGMENT_BYTES: u64 = 10 * 1024 * 1024;

/// The reference class principal pseudonyms are hashed under.
const PRINCIPAL_PSEUDONYM_CLASS: &str = "messaging-principal-v1";

pub struct AuditJournal {
    sink: Arc<dyn AuditSink>,
    chain: ChainState,
    keys: AuditKeyHasher,
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
        Ok(Self::new(sink, chain, profile.key_hasher()))
    }

    #[must_use]
    pub fn new(sink: Arc<dyn AuditSink>, chain: ChainState, keys: AuditKeyHasher) -> Self {
        Self { sink, chain, keys }
    }

    /// Append one record to the chain. The record is durable when this
    /// returns; a failure leaves the chain where it was.
    pub async fn append<T: Serialize + Send>(&self, record: T) -> Result<(), AuditError> {
        self.chain.append(self.sink.as_ref(), record).await?;
        Ok(())
    }

    /// The keyed pseudonym that names `identity` in the journal: a hash of
    /// the JSON array `[issuer, subject]`, so no two identities share an
    /// input.
    pub fn principal_pseudonym(
        &self,
        identity: &CallerIdentity,
    ) -> Result<String, AuditReferenceHashError> {
        let canonical =
            serde_json::Value::from(vec![identity.issuer.as_str(), identity.subject.as_str()])
                .to_string();
        self.keys
            .audit_reference_hash(PRINCIPAL_PSEUDONYM_CLASS, "", &canonical)
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
}

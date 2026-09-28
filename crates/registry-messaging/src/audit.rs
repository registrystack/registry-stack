// SPDX-License-Identifier: Apache-2.0

//! Messaging audit entries and keyed references.

use registry_messaging_core::{CallerIdentity, Recipient};
use registry_platform_audit::{
    AuditEntry, AuditKeyHasher, AuditReferenceHashError, AuditRequest, AuditUnavailable,
    AuditWriter,
};
use registry_platform_canonical_json::{canonicalize_json, JcsError};
use serde_json::{json, Value};
use thiserror::Error;
use uuid::Uuid;

pub const MESSAGING_AUDIT_SCHEMA: &str = "registry-messaging-audit/v1";
const PRINCIPAL_PSEUDONYM_CLASS: &str = "messaging-principal-v1";
const RECIPIENT_REFERENCE_CLASS: &str = "messaging-recipient-v1";

#[derive(Debug, Error)]
pub enum PseudonymError {
    #[error("the principal could not be written canonically: {0}")]
    Canonical(#[from] JcsError),
    #[error("the canonical principal is not UTF-8")]
    Encoding,
    #[error(transparent)]
    Hash(#[from] AuditReferenceHashError),
}

/// One process's destination and the key used only for minimized references.
#[derive(Clone)]
pub struct MessagingAudit {
    writer: AuditWriter,
    keys: AuditKeyHasher,
}

impl std::fmt::Debug for MessagingAudit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MessagingAudit")
            .field("writer", &self.writer)
            .finish_non_exhaustive()
    }
}

impl MessagingAudit {
    #[must_use]
    pub fn new(writer: AuditWriter, keys: AuditKeyHasher) -> Self {
        Self { writer, keys }
    }

    pub async fn ready(&self) -> bool {
        self.writer.ready().await
    }

    pub async fn append(&self, entry: AuditEntry) -> Result<(), AuditUnavailable> {
        self.writer.append(entry).await
    }

    /// Begin one audited invocation with a fresh correlation. A dropped guard
    /// records the same event with the `unfinished` outcome while possible.
    pub async fn begin(&self, record: Value) -> Result<AuditRequest, AuditUnavailable> {
        let event = record
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or("messaging.operation")
            .to_owned();
        self.writer
            .begin(
                MESSAGING_AUDIT_SCHEMA,
                Uuid::new_v4().to_string(),
                record,
                json!({"event": event, "outcome": "unfinished"}),
            )
            .await
    }

    pub async fn append_background(&self, record: Value) -> Result<(), AuditUnavailable> {
        self.append(AuditEntry::response(
            MESSAGING_AUDIT_SCHEMA,
            Uuid::new_v4().to_string(),
            record,
        ))
        .await
    }

    #[cfg(test)]
    pub(crate) fn wait_for_detached_entries(&self) {
        self.writer.wait_for_detached_entries();
    }

    pub fn principal_pseudonym(&self, identity: &CallerIdentity) -> Result<String, PseudonymError> {
        let canonical = canonicalize_json(&Value::from(vec![
            identity.issuer.as_str(),
            identity.subject.as_str(),
        ]))?;
        let canonical = std::str::from_utf8(&canonical).map_err(|_| PseudonymError::Encoding)?;
        Ok(self
            .keys
            .audit_reference_hash(PRINCIPAL_PSEUDONYM_CLASS, "", canonical)?)
    }

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
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    pub(crate) struct MemorySink {
        bytes: Arc<Mutex<Vec<u8>>>,
        pub(crate) refuse: Arc<AtomicBool>,
        writes: Arc<AtomicUsize>,
        refuse_after: Arc<Mutex<Option<usize>>>,
    }

    impl MemorySink {
        pub(crate) fn entries(&self) -> Vec<Value> {
            String::from_utf8(self.bytes.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .collect()
        }

        pub(crate) fn records(&self) -> Vec<Value> {
            self.entries()
                .into_iter()
                .filter(|entry| entry["phase"] == "response")
                .map(|entry| entry["record"].clone())
                .collect()
        }

        pub(crate) fn refuse_after(&self, accepted_writes: usize) {
            *self.refuse_after.lock().unwrap() = Some(accepted_writes);
        }
    }

    impl Write for MemorySink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let write = self.writes.fetch_add(1, Ordering::SeqCst);
            if self.refuse.load(Ordering::SeqCst)
                || self
                    .refuse_after
                    .lock()
                    .unwrap()
                    .is_some_and(|accepted| write >= accepted)
            {
                return Err(io::Error::other("the test audit sink refused the write"));
            }
            self.bytes.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub(crate) fn memory_journal() -> (Arc<MemorySink>, MessagingAudit) {
        let sink = Arc::new(MemorySink::default());
        let writer = AuditWriter::from_line_sink(Box::new((*sink).clone()));
        (
            sink,
            MessagingAudit::new(writer, AuditKeyHasher::unkeyed_dev_only()),
        )
    }

    #[test]
    fn a_pseudonym_hashes_the_same_bytes_for_every_identity() {
        let profile = registry_platform_audit::AuditProfile::production_from_secret_bytes(
            zeroize::Zeroizing::new(vec![7u8; 32]),
        )
        .unwrap();
        let audit = MessagingAudit::new(
            AuditWriter::from_line_sink(Box::new(io::sink())),
            profile.key_hasher(),
        );
        let identity = CallerIdentity {
            issuer: "https://identity.example.test".to_owned(),
            subject: "subject-1".to_owned(),
        };
        assert_eq!(
            audit.principal_pseudonym(&identity).unwrap(),
            "hmac-sha256:19a895369f72bc0bdbb87af912bc8ddbbb71e033f88db2703d3dd1d5dad58b9a"
        );
    }
}

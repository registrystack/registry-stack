// SPDX-License-Identifier: Apache-2.0

//! The Document Store audit journal: one request entry before an audited
//! operation acts and one response entry with its outcome after, through
//! `registry-platform-audit`. Callers are recorded only as keyed references
//! bound to their actor kind, never by their identifiers.

use registry_documents_core::ActorKind;
use registry_platform_audit::{
    AuditEntry, AuditKeyHasher, AuditReferenceHashError, AuditRequest, AuditUnavailable,
    AuditWriter,
};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Value};
use thiserror::Error;
use uuid::Uuid;

/// The schema every Document Store audit entry carries.
pub const DOCUMENTS_AUDIT_SCHEMA: &str = "registry-documents-audit/v1";

/// The audited events.
pub const UPLOAD_RESERVATION_EVENT: &str = "documents.upload-reservation";
pub const UPLOAD_CONTENT_EVENT: &str = "documents.upload-content";
pub const CONTENT_DOWNLOAD_EVENT: &str = "documents.content-download";
pub const CONTENT_VERIFICATION_EVENT: &str = "documents.content-verification";
pub const GRANT_ISSUE_EVENT: &str = "documents.grant-issue";
pub const GRANT_REVOKE_EVENT: &str = "documents.grant-revoke";
pub const PACKAGE_ACTIVATION_EVENT: &str = "documents.package-activation";
pub const ERASURE_REQUEST_EVENT: &str = "documents.erasure-request";
pub const ERASURE_EVENT: &str = "documents.erasure";
pub const UPLOAD_EXPIRY_EVENT: &str = "documents.upload-expiry";
pub const ORPHAN_ERASURE_EVENT: &str = "documents.orphan-erasure";
pub const HOOK_DELIVERY_EVENT: &str = "documents.hook-delivery";

const ACTOR_REFERENCE_CLASS: &str = "documents-actor-v1";
const ACTIVATION_REFERENCE_CLASS: &str = "documents-activation-reference-v1";

/// The actor reference could not be computed.
#[derive(Debug, Error)]
pub enum ActorReferenceError {
    #[error("the actor could not be written canonically")]
    Canonical,
    #[error(transparent)]
    Hash(#[from] AuditReferenceHashError),
}

/// One process's audit destination and the key its references are made
/// with.
#[derive(Clone)]
pub struct DocumentsAudit {
    writer: AuditWriter,
    keys: AuditKeyHasher,
}

impl std::fmt::Debug for DocumentsAudit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DocumentsAudit")
            .field("writer", &self.writer)
            .finish_non_exhaustive()
    }
}

impl DocumentsAudit {
    #[must_use]
    pub fn new(writer: AuditWriter, keys: AuditKeyHasher) -> Self {
        Self { writer, keys }
    }

    /// Write the request entry of one audited invocation under a fresh
    /// correlation. A guard dropped before it is finished records the same
    /// event with the `unfinished` outcome.
    pub async fn begin(
        &self,
        event: &str,
        record: Value,
    ) -> Result<AuditRequest, AuditUnavailable> {
        self.writer
            .begin(
                DOCUMENTS_AUDIT_SCHEMA,
                Uuid::new_v4().to_string(),
                record,
                json!({"event": event, "outcome": "unfinished"}),
            )
            .await
    }

    /// Write one request entry under `correlation`.
    pub async fn request(&self, correlation: &str, record: Value) -> Result<(), AuditUnavailable> {
        self.writer
            .append(AuditEntry::request(
                DOCUMENTS_AUDIT_SCHEMA,
                correlation.to_owned(),
                record,
            ))
            .await
    }

    /// Whether the destination can take an entry now: the file is still the
    /// one this process opened, or the stream has not failed or stalled.
    pub async fn ready(&self) -> bool {
        self.writer.ready().await
    }

    /// Write one entry another component built whole, such as a hook
    /// delivery attempt's entry from the shared delivery worker.
    pub async fn append(&self, entry: AuditEntry) -> Result<(), AuditUnavailable> {
        self.writer.append(entry).await
    }

    /// Write one response entry under `correlation`.
    pub async fn response(&self, correlation: &str, record: Value) -> Result<(), AuditUnavailable> {
        self.writer
            .append(AuditEntry::response(
                DOCUMENTS_AUDIT_SCHEMA,
                correlation.to_owned(),
                record,
            ))
            .await
    }

    /// The keyed reference of a caller: the same issuer, subject, and actor
    /// kind always give the same reference under one audit key, a human and
    /// a service sharing an issuer and subject get different references, and
    /// the reference reveals neither identifier.
    pub fn actor_reference(
        &self,
        issuer: &str,
        subject: &str,
        kind: ActorKind,
    ) -> Result<String, ActorReferenceError> {
        let canonical = canonicalize_json(&Value::from(vec![issuer, subject, kind.as_str()]))
            .map_err(|_| ActorReferenceError::Canonical)?;
        let canonical =
            std::str::from_utf8(&canonical).map_err(|_| ActorReferenceError::Canonical)?;
        Ok(self
            .keys
            .audit_reference_hash(ACTOR_REFERENCE_CLASS, "", canonical)?)
    }

    /// The keyed reference of an operator's change reference, bound to the
    /// activation it was given for: the ledger and the journal carry the
    /// reference, never the text.
    pub fn activation_reference(
        &self,
        activation_id: Uuid,
        reference: &str,
    ) -> Result<String, AuditReferenceHashError> {
        self.keys.audit_reference_hash(
            ACTIVATION_REFERENCE_CLASS,
            &activation_id.to_string(),
            reference,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_audit::AuditProfile;

    fn audit() -> DocumentsAudit {
        let profile =
            AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(vec![7u8; 32]))
                .unwrap();
        DocumentsAudit::new(
            AuditWriter::from_line_sink(Box::new(std::io::sink())),
            profile.key_hasher(),
        )
    }

    #[test]
    fn an_actor_reference_is_stable_and_reveals_no_identifier() {
        let audit = audit();
        let issuer = "https://identity.example.test";
        let first = audit
            .actor_reference(issuer, "custodian-1", ActorKind::Service)
            .unwrap();
        assert_eq!(
            first,
            audit
                .actor_reference(issuer, "custodian-1", ActorKind::Service)
                .unwrap()
        );
        assert_ne!(
            first,
            audit
                .actor_reference(issuer, "custodian-2", ActorKind::Service)
                .unwrap()
        );
        assert!(!first.contains("custodian-1"));
        assert!(!first.contains("identity.example.test"));
    }

    #[test]
    fn an_actor_reference_tells_a_human_from_a_service_with_the_same_subject() {
        let audit = audit();
        let issuer = "https://identity.example.test";
        assert_ne!(
            audit
                .actor_reference(issuer, "shared-subject", ActorKind::Human)
                .unwrap(),
            audit
                .actor_reference(issuer, "shared-subject", ActorKind::Service)
                .unwrap()
        );
    }

    #[test]
    fn an_activation_reference_is_bound_to_its_activation_and_hides_the_text() {
        let audit = audit();
        let activation = Uuid::new_v4();
        let first = audit.activation_reference(activation, "CHG-1042").unwrap();
        assert_eq!(
            first,
            audit.activation_reference(activation, "CHG-1042").unwrap()
        );
        assert_ne!(
            first,
            audit
                .activation_reference(Uuid::new_v4(), "CHG-1042")
                .unwrap()
        );
        assert!(!first.contains("CHG-1042"));
    }
}

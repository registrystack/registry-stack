// SPDX-License-Identifier: Apache-2.0

//! The Document Store audit journal: one request entry before an audited
//! operation acts and one response entry with its outcome after, through
//! `registry-platform-audit`. Callers are recorded only as keyed references,
//! never by their identifiers.

use registry_platform_audit::{
    AuditEntry, AuditKeyHasher, AuditReferenceHashError, AuditRequest, AuditUnavailable,
    AuditWriter,
};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::actor::Actor;

/// The schema every Document Store audit entry carries.
pub const DOCUMENTS_AUDIT_SCHEMA: &str = "registry-documents-audit/v1";

/// The audited events.
pub const UPLOAD_RESERVATION_EVENT: &str = "documents.upload-reservation";
pub const UPLOAD_CONTENT_EVENT: &str = "documents.upload-content";
pub const CONTENT_DOWNLOAD_EVENT: &str = "documents.content-download";
pub const CONTENT_VERIFICATION_EVENT: &str = "documents.content-verification";

const ACTOR_REFERENCE_CLASS: &str = "documents-actor-v1";

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

    /// The keyed reference of a caller: the same issuer and subject always
    /// give the same reference under one audit key, and the reference
    /// reveals neither.
    pub fn actor_reference(&self, actor: &Actor) -> Result<String, ActorReferenceError> {
        let canonical = canonicalize_json(&Value::from(vec![
            actor.issuer.as_str(),
            actor.subject.as_str(),
        ]))
        .map_err(|_| ActorReferenceError::Canonical)?;
        let canonical =
            std::str::from_utf8(&canonical).map_err(|_| ActorReferenceError::Canonical)?;
        Ok(self
            .keys
            .audit_reference_hash(ACTOR_REFERENCE_CLASS, "", canonical)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::ActorKind;
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

    fn actor(subject: &str) -> Actor {
        Actor {
            issuer: "https://identity.example.test".to_owned(),
            subject: subject.to_owned(),
            kind: ActorKind::Service,
            client_id: "civil-registry-app".to_owned(),
            access_profile_id: "custodian-app".to_owned(),
            issuing_institution: "civil-registry".to_owned(),
        }
    }

    #[test]
    fn an_actor_reference_is_stable_and_reveals_no_identifier() {
        let audit = audit();
        let first = audit.actor_reference(&actor("custodian-1")).unwrap();
        assert_eq!(first, audit.actor_reference(&actor("custodian-1")).unwrap());
        assert_ne!(first, audit.actor_reference(&actor("custodian-2")).unwrap());
        assert!(!first.contains("custodian-1"));
        assert!(!first.contains("identity.example.test"));
    }
}

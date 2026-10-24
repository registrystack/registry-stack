//! Durable, privacy-safe attribution for the adapter-owned delivery boundary.
//!
//! Evidence separately audits credential access and release under this
//! adapter's outbound service identity. This journal records the authenticated
//! client and/or subject that created the wallet exchange and the terminal
//! delivery outcome, joined only by a server-generated opaque exchange
//! identifier.

use registry_platform_audit::{
    AuditDestination, AuditError, AuditKeyHasher, AuditProfile, AuditRequest, AuditUnavailable,
    AuditWriter,
};
use serde_json::{json, Map, Value};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::authorizer::AuthorizedOffer;

/// The schema carried by every adapter-owned audit entry.
pub const OID4VCI_AUDIT_SCHEMA: &str = "registry-evidence-oid4vci-audit/v1";

const CLIENT_CLASS: &str = "evidence-oid4vci-offer-client-v1";
const SUBJECT_CLASS: &str = "evidence-oid4vci-offer-subject-v1";

/// An audit profile or destination refused startup or an entry.
#[derive(Debug, Error)]
pub enum DeliveryAuditError {
    #[error("the audit profile or destination is unavailable")]
    Initialization(#[from] AuditError),
    #[error("the audit destination did not accept the entry")]
    Unavailable(#[from] AuditUnavailable),
    #[error("the audit identity could not be pseudonymized")]
    InvalidIdentity,
}

/// The closed terminal outcomes after an access token has been claimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialDeliveryOutcome {
    Released,
    ProofRefused,
    EvidenceRefused,
    EvidenceUnavailable,
    InternalError,
}

impl CredentialDeliveryOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Released => "released",
            Self::ProofRefused => "proof_refused",
            Self::EvidenceRefused => "evidence_refused",
            Self::EvidenceUnavailable => "evidence_unavailable",
            Self::InternalError => "internal_error",
        }
    }
}

/// The process-wide adapter audit destination and identifier hasher.
#[derive(Clone, Debug)]
pub struct DeliveryAudit {
    writer: AuditWriter,
    key_hasher: AuditKeyHasher,
}

impl DeliveryAudit {
    /// Resolve the pseudonym key and open the destination before serving.
    pub async fn initialize(
        destination: AuditDestination,
        master_secret: Zeroizing<Vec<u8>>,
    ) -> Result<Self, DeliveryAuditError> {
        let profile = AuditProfile::production_from_secret_bytes(master_secret)?;
        let writer = AuditWriter::open(destination).await?;
        Ok(Self {
            writer,
            key_hasher: profile.key_hasher(),
        })
    }

    /// Build over an already-open writer for focused tests.
    pub fn with_writer(
        writer: AuditWriter,
        master_secret: Vec<u8>,
    ) -> Result<Self, DeliveryAuditError> {
        let profile = AuditProfile::production_from_secret_bytes(Zeroizing::new(master_secret))?;
        Ok(Self {
            writer,
            key_hasher: profile.key_hasher(),
        })
    }

    /// Report whether the required audit destination can accept entries.
    pub async fn ready(&self) -> bool {
        self.writer.ready().await
    }

    /// Begin an authenticated offer creation before exchange state is written.
    pub async fn begin_offer_creation(
        &self,
        exchange_id: &str,
        authorized: &AuthorizedOffer,
    ) -> Result<OfferCreationAudit, DeliveryAuditError> {
        let has_client = authorized
            .client
            .as_deref()
            .is_some_and(|client| !client.is_empty());
        let has_subject = authorized
            .subject
            .as_deref()
            .is_some_and(|subject| !subject.is_empty());
        if !has_client && !has_subject {
            return Err(DeliveryAuditError::InvalidIdentity);
        }

        let mut record = Map::from_iter([
            ("operation".to_owned(), Value::from("offer_creation")),
            ("outcome".to_owned(), Value::from("attempted")),
        ]);
        if let Some(client) = authorized.client.as_deref() {
            record.insert(
                "clientPseudonym".to_owned(),
                Value::from(self.pseudonym(CLIENT_CLASS, client)?),
            );
        }
        if let Some(subject) = authorized.subject.as_deref() {
            record.insert(
                "subjectPseudonym".to_owned(),
                Value::from(self.pseudonym(SUBJECT_CLASS, subject)?),
            );
        }
        let request = self
            .writer
            .begin(
                OID4VCI_AUDIT_SCHEMA,
                exchange_id,
                Value::Object(record),
                json!({"operation":"offer_creation","outcome":"unfinished"}),
            )
            .await?;
        Ok(OfferCreationAudit { request })
    }

    /// Begin the terminal wallet-delivery operation before proof processing or
    /// Evidence I/O. Dropping the returned handle records `unfinished`, which
    /// covers timeout, cancellation, panic, and early-return mistakes.
    pub async fn begin_credential_delivery(
        &self,
        exchange_id: &str,
    ) -> Result<CredentialDeliveryAudit, DeliveryAuditError> {
        let request = self
            .writer
            .begin(
                OID4VCI_AUDIT_SCHEMA,
                exchange_id,
                json!({"operation":"credential_delivery","outcome":"attempted"}),
                json!({"operation":"credential_delivery","outcome":"unfinished"}),
            )
            .await?;
        Ok(CredentialDeliveryAudit { request })
    }

    fn pseudonym(&self, class: &str, value: &str) -> Result<String, DeliveryAuditError> {
        self.key_hasher
            .audit_reference_hash(class, "", value)
            .map_err(|_| DeliveryAuditError::InvalidIdentity)
    }
}

/// An offer attempt whose terminal creation decision is still owed.
pub struct OfferCreationAudit {
    request: AuditRequest,
}

impl OfferCreationAudit {
    pub async fn created(mut self) -> Result<(), DeliveryAuditError> {
        self.request
            .respond(json!({"operation":"offer_creation","outcome":"created"}))
            .await?;
        Ok(())
    }

    pub async fn refused(mut self) -> Result<(), DeliveryAuditError> {
        self.request
            .respond(json!({"operation":"offer_creation","outcome":"refused"}))
            .await?;
        Ok(())
    }
}

/// A claimed exchange whose terminal wallet-delivery outcome is still owed.
pub struct CredentialDeliveryAudit {
    request: AuditRequest,
}

impl CredentialDeliveryAudit {
    pub async fn finish(
        mut self,
        outcome: CredentialDeliveryOutcome,
    ) -> Result<(), DeliveryAuditError> {
        self.request
            .respond(json!({
                "operation":"credential_delivery",
                "outcome": outcome.as_str(),
            }))
            .await?;
        Ok(())
    }
}

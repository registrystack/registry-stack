//! Durable audit of session creation, request-object fetches, wallet
//! responses, and Evidence reads.
//!
//! An entry names the policy, a pseudonym of the creating client and subject,
//! and the session's digest. It never carries the session reference, the
//! request id, the nonce, the `state`, or any key: the journal joins entries by
//! a digest that cannot be turned back into a handle on the exchange.

use registry_platform_audit::{
    AuditDestination, AuditError, AuditKeyHasher, AuditProfile, AuditRequest, AuditUnavailable,
    AuditWriter,
};
use serde_json::{json, Map, Value};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::session::Principal;

/// The schema carried by every audit entry of this service.
pub const OID4VP_AUDIT_SCHEMA: &str = "registry-evidence-oid4vp-audit/v1";

const CLIENT_CLASS: &str = "evidence-oid4vp-session-client-v1";
const SUBJECT_CLASS: &str = "evidence-oid4vp-session-subject-v1";

/// An audit profile or destination refused startup or an entry.
#[derive(Debug, Error)]
pub enum AuditFailure {
    #[error("the audit profile or destination is unavailable")]
    Initialization(#[from] AuditError),
    #[error("the audit destination did not accept the entry")]
    Unavailable(#[from] AuditUnavailable),
    #[error("the audit identity could not be pseudonymized")]
    InvalidIdentity,
}

/// The process-wide audit destination and identifier hasher.
#[derive(Clone, Debug)]
pub struct SessionAudit {
    writer: AuditWriter,
    key_hasher: AuditKeyHasher,
}

impl SessionAudit {
    /// Resolve the pseudonym key and open the destination before serving.
    pub async fn initialize(
        destination: AuditDestination,
        master_secret: Zeroizing<Vec<u8>>,
    ) -> Result<Self, AuditFailure> {
        let profile = AuditProfile::production_from_secret_bytes(master_secret)?;
        let writer = AuditWriter::open(destination).await?;
        Ok(Self {
            writer,
            key_hasher: profile.key_hasher(),
        })
    }

    /// Build over an already-open writer for focused tests.
    pub fn with_writer(writer: AuditWriter, master_secret: Vec<u8>) -> Result<Self, AuditFailure> {
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

    /// Begin a session creation before the session is released to the caller.
    pub async fn begin_session_creation(
        &self,
        audit_ref: &str,
        policy_id: &str,
        principal: &Principal,
    ) -> Result<Pending, AuditFailure> {
        let mut record = Map::from_iter([
            ("operation".to_owned(), Value::from("session_creation")),
            ("outcome".to_owned(), Value::from("attempted")),
            ("policy".to_owned(), Value::from(policy_id)),
        ]);
        if let Some(client) = principal.client.as_deref() {
            record.insert(
                "clientPseudonym".to_owned(),
                Value::from(self.pseudonym(CLIENT_CLASS, client)?),
            );
        }
        if let Some(subject) = principal.subject.as_deref() {
            record.insert(
                "subjectPseudonym".to_owned(),
                Value::from(self.pseudonym(SUBJECT_CLASS, subject)?),
            );
        }
        let request = self
            .writer
            .begin(
                OID4VP_AUDIT_SCHEMA,
                audit_ref,
                Value::Object(record),
                json!({"operation":"session_creation","outcome":"unfinished"}),
            )
            .await?;
        Ok(Pending {
            request,
            operation: "session_creation",
        })
    }

    /// Begin serving a request object before it is signed or released.
    pub async fn begin_request_fetch(
        &self,
        audit_ref: &str,
        policy_id: &str,
    ) -> Result<Pending, AuditFailure> {
        let request = self
            .writer
            .begin(
                OID4VP_AUDIT_SCHEMA,
                audit_ref,
                json!({"operation":"request_fetch","outcome":"attempted","policy":policy_id}),
                json!({"operation":"request_fetch","outcome":"unfinished"}),
            )
            .await?;
        Ok(Pending {
            request,
            operation: "request_fetch",
        })
    }

    /// Begin accepting a wallet's presentation. The presentation itself is
    /// never part of the entry.
    pub async fn begin_response_acceptance(
        &self,
        audit_ref: &str,
        policy_id: &str,
    ) -> Result<Pending, AuditFailure> {
        self.begin_plain(
            "response_acceptance",
            audit_ref,
            Some(policy_id),
            None,
            Map::new(),
        )
        .await
    }

    /// Begin recording a wallet's error. `category` is from the closed
    /// [`crate::session::FailureCategory`] set.
    pub async fn begin_wallet_error(
        &self,
        audit_ref: &str,
        policy_id: &str,
        category: &'static str,
    ) -> Result<Pending, AuditFailure> {
        self.begin_plain(
            "wallet_error",
            audit_ref,
            Some(policy_id),
            Some(category),
            Map::new(),
        )
        .await
    }

    /// Record a refused wallet response of a known session.
    pub async fn record_response_refusal(
        &self,
        audit_ref: &str,
        policy_id: &str,
        category: &'static str,
    ) -> Result<(), AuditFailure> {
        self.begin_plain(
            "response_refusal",
            audit_ref,
            Some(policy_id),
            None,
            Map::new(),
        )
        .await?
        .finish(category)
        .await
    }

    /// Begin an Evidence read before the result is released. `policy_id` is
    /// absent when the reference names no session; `audit_ref` is then the
    /// digest of whatever reference the caller sent.
    pub async fn begin_evidence_read(
        &self,
        audit_ref: &str,
        policy_id: Option<&str>,
        reader: &Principal,
    ) -> Result<Pending, AuditFailure> {
        let mut extra = Map::new();
        if let Some(client) = reader.client.as_deref() {
            extra.insert(
                "clientPseudonym".to_owned(),
                Value::from(self.pseudonym(CLIENT_CLASS, client)?),
            );
        }
        self.begin_plain("evidence_read", audit_ref, policy_id, None, extra)
            .await
    }

    async fn begin_plain(
        &self,
        operation: &'static str,
        audit_ref: &str,
        policy_id: Option<&str>,
        category: Option<&'static str>,
        extra: Map<String, Value>,
    ) -> Result<Pending, AuditFailure> {
        let mut record = extra;
        record.extend([
            ("operation".to_owned(), Value::from(operation)),
            ("outcome".to_owned(), Value::from("attempted")),
        ]);
        if let Some(policy_id) = policy_id {
            record.insert("policy".to_owned(), Value::from(policy_id));
        }
        if let Some(category) = category {
            record.insert("category".to_owned(), Value::from(category));
        }
        let request = self
            .writer
            .begin(
                OID4VP_AUDIT_SCHEMA,
                audit_ref,
                Value::Object(record),
                json!({"operation": operation, "outcome": "unfinished"}),
            )
            .await?;
        Ok(Pending { request, operation })
    }

    fn pseudonym(&self, class: &str, value: &str) -> Result<String, AuditFailure> {
        self.key_hasher
            .audit_reference_hash(class, "", value)
            .map_err(|_| AuditFailure::InvalidIdentity)
    }
}

/// An operation whose terminal outcome is still owed. Dropping it records
/// `unfinished`, which covers timeout, cancellation, and early return.
pub struct Pending {
    request: AuditRequest,
    operation: &'static str,
}

impl Pending {
    /// Record the terminal outcome.
    pub async fn finish(mut self, outcome: &'static str) -> Result<(), AuditFailure> {
        self.request
            .respond(json!({"operation": self.operation, "outcome": outcome}))
            .await?;
        Ok(())
    }
}

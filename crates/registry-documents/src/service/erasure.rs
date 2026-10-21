// SPDX-License-Identifier: Apache-2.0

//! Removal from custody: the custodian asks for a document's erasure.
//!
//! Besides a rejection, the request is the custody clock's only trigger.
//! In one transaction it records the document's removal, moves the version
//! to `erasure pending` with the policy's cleanup grace frozen into its due
//! time (a version a rejection already armed keeps the rejection's),
//! suspends release, revokes every active grant on the document and
//! captures one grant event for each, and cancels any verification still
//! pending, so nothing releases the version once the request commits. The bytes are erased by the cleanup sweep once
//! the version is due. No grant expiry or revocation ever starts this clock.

use registry_documents_core::{may_request_erasure, Caller, DocumentView, ProblemCode};
use serde_json::{json, Value};
use tokio_postgres::Transaction;
use uuid::Uuid;

use super::{timestamp, unavailable, DocumentService};
use crate::audit::ERASURE_REQUEST_EVENT;
use crate::hooks::GrantChange;

/// What one erasure request changed.
struct Requested {
    view: DocumentView,
    /// The document's removal was already requested; nothing changed.
    repeated: bool,
    revoked_grants: u64,
    due_at: String,
}

impl DocumentService {
    /// Ask for the erasure of `document_id`. Only its custodian may; a
    /// caller that does not see the document is answered as if it did not
    /// exist. Repeating the request changes nothing and answers the
    /// document as it stands.
    pub async fn request_erasure(
        &self,
        caller: &Caller,
        document_id: Uuid,
    ) -> Result<DocumentView, ProblemCode> {
        let reference = self.actor_reference(caller)?;
        let audit = self
            .begin(
                ERASURE_REQUEST_EVENT,
                json!({
                    "event": ERASURE_REQUEST_EVENT,
                    "actor": reference,
                    "profile": caller.profile_id,
                    "documentId": document_id.to_string(),
                }),
            )
            .await?;
        let result = self.request_erasure_inner(caller, document_id).await;
        let success = match &result {
            Ok(requested) => json!({
                "event": ERASURE_REQUEST_EVENT,
                "outcome": "erasure-requested",
                "versionId": requested.view.version.id,
                "repeated": requested.repeated,
                "revokedGrants": requested.revoked_grants,
                "erasureDueAt": requested.due_at,
            }),
            Err(_) => Value::Null,
        };
        Self::finish(audit, ERASURE_REQUEST_EVENT, &result, success).await?;
        result.map(|requested| requested.view)
    }

    async fn request_erasure_inner(
        &self,
        caller: &Caller,
        document_id: Uuid,
    ) -> Result<Requested, ProblemCode> {
        let record = self
            .record(document_id)
            .await?
            .ok_or(ProblemCode::ResourceNotFound)?;
        let access = self.access(caller, &record).await?;
        if !access.sees() {
            return Err(ProblemCode::ResourceNotFound);
        }
        if !may_request_erasure(access.standing) {
            return Err(ProblemCode::ProfileNotAuthorized);
        }
        // A custodian sees the document only under a declared policy.
        let policy = self
            .policy(&record.policy_id)
            .ok_or(ProblemCode::ResourceNotFound)?;
        let grace = i32::try_from(policy.mandatory_restrictions.cleanup_grace_hours.get())
            .map_err(|error| unavailable("erasure grace", &error))?;
        let version_id = record.version_id;
        let mut client = self.client().await?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| unavailable("erasure transaction", &error))?;
        // The document's removal state decides first request or repeat, not
        // its version's: a rejected version is already erasing, yet its
        // document was never removed and may still list active grants.
        let repeated = transaction
            .execute(
                "UPDATE documents_documents SET removal_requested_at = transaction_timestamp()
                  WHERE document_id = $1 AND removal_requested_at IS NULL",
                &[&document_id],
            )
            .await
            .map_err(|error| unavailable("erasure request", &error))?
            == 0;
        let revoked_grants = if repeated {
            0
        } else {
            // A version a rejection already armed keeps the rejection's due
            // time.
            transaction
                .execute(
                    "UPDATE documents_versions
                        SET erasure_state = 'pending', eligibility = 'suspended',
                            revision = revision + 1,
                            erasure_requested_at = transaction_timestamp(),
                            erasure_due_at = transaction_timestamp() + make_interval(hours => $2)
                      WHERE version_id = $1 AND erasure_state = 'none'",
                    &[&version_id, &grace],
                )
                .await
                .map_err(|error| unavailable("erasure request", &error))?;
            let revoked = transaction
                .query(
                    "UPDATE documents_grants
                        SET revoked_at = transaction_timestamp(), revision = revision + 1
                      WHERE document_id = $1 AND revoked_at IS NULL
                        AND expires_at > transaction_timestamp()
                      RETURNING grant_id",
                    &[&document_id],
                )
                .await
                .map_err(|error| unavailable("erasure grant revocation", &error))?;
            // Each grant the removal revokes reports its revocation inside
            // this transaction, through the path a direct revocation uses.
            for row in &revoked {
                let grant_id: Uuid = row
                    .try_get(0)
                    .map_err(|error| unavailable("erasure grant revocation", &error))?;
                self.capture_grant_event(&transaction, caller, grant_id, GrantChange::Revoked)
                    .await?;
            }
            transaction
                .execute(
                    "UPDATE documents_verification_jobs
                        SET state = 'cancelled', next_attempt_at = NULL,
                            updated_at = transaction_timestamp()
                      WHERE version_id = $1 AND state = 'pending'",
                    &[&version_id],
                )
                .await
                .map_err(|error| unavailable("erasure verification cancel", &error))?;
            revoked.len() as u64
        };
        let due: chrono::DateTime<chrono::Utc> = transaction
            .query_one(
                "SELECT erasure_due_at FROM documents_versions WHERE version_id = $1",
                &[&version_id],
            )
            .await
            .and_then(|row| row.try_get(0))
            .map_err(|error| unavailable("erasure read", &error))?;
        transaction
            .commit()
            .await
            .map_err(|error| unavailable("erasure commit", &error))?;
        Ok(Requested {
            view: self.current_view(caller, document_id).await?,
            repeated,
            revoked_grants,
            due_at: timestamp(due),
        })
    }

    /// Refuse a grant on a version whose removal was requested. The row is
    /// held until `transaction` ends, so an erasure request, which revokes
    /// every active grant in its own transaction, cannot commit between
    /// this check and the grant it admits.
    pub(super) async fn refuse_erasing(
        transaction: &Transaction<'_>,
        version_id: Uuid,
    ) -> Result<(), ProblemCode> {
        let erasing: bool = transaction
            .query_one(
                "SELECT erasure_state <> 'none' FROM documents_versions
                  WHERE version_id = $1 FOR SHARE",
                &[&version_id],
            )
            .await
            .and_then(|row| row.try_get(0))
            .map_err(|error| unavailable("grant erasure check", &error))?;
        if erasing {
            return Err(ProblemCode::DocumentVersionNotReleasable);
        }
        Ok(())
    }
}

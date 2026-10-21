// SPDX-License-Identifier: Apache-2.0

//! Document grants: one named recipient, one exact version, and an expiry
//! frozen at issue. A grant is issued and revoked by the document's
//! custodian or the system that placed it in custody, when its profile is
//! one the policy lets grant. A grant is never extended, and revocation is
//! final. There is no organizational recipient and no invitation.
//!
//! A grant is pushed, not evaluated: release checks that the grant exists,
//! is unrevoked and unexpired, names the caller, and names the exact
//! version, and that the caller's profile is one of the policy's recipient
//! profiles. No live predicate is consulted.

use chrono::{DateTime, Utc};
use registry_documents_core::{
    grant_expiry_hours, is_recipient, Caller, DocumentGrantPage, DocumentGrantView, GrantState,
    GranteeRef, IssueGrantRequest, ProblemCode,
};
use registry_platform_yaml::ExternalId;
use serde_json::{json, Value};
use tokio_postgres::Row;
use uuid::Uuid;

use super::{
    key_digest, next_cursor, record_key, replay, request_digest, timestamp, unavailable, Cursor,
    DocumentService, PageRequest, Record, Replay,
};
use crate::audit::{GRANT_ISSUE_EVENT, GRANT_REVOKE_EVENT};

/// The columns [`Grant::from_row`] reads, by name.
const GRANT_COLUMNS: &str = "grant_record.grant_id, grant_record.document_id,
    grant_record.version_id, grant_record.grantee_subject, grant_record.issued_at,
    grant_record.expires_at, grant_record.revoked_at,
    grant_record.expires_at <= now() AS lapsed";

/// One stored grant.
struct Grant {
    id: Uuid,
    document_id: Uuid,
    version_id: Uuid,
    grantee: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    lapsed: bool,
}

impl Grant {
    fn from_row(row: &Row) -> Result<Self, String> {
        fn get<'a, T: tokio_postgres::types::FromSql<'a>>(
            row: &'a Row,
            name: &str,
        ) -> Result<T, String> {
            row.try_get(name).map_err(|error| error.to_string())
        }
        Ok(Self {
            id: get(row, "grant_id")?,
            document_id: get(row, "document_id")?,
            version_id: get(row, "version_id")?,
            grantee: get(row, "grantee_subject")?,
            issued_at: get(row, "issued_at")?,
            expires_at: get(row, "expires_at")?,
            revoked_at: get(row, "revoked_at")?,
            lapsed: get(row, "lapsed")?,
        })
    }

    fn cursor(&self) -> Cursor {
        Cursor {
            at: self.issued_at,
            id: self.id,
        }
    }

    fn view(&self) -> Result<DocumentGrantView, String> {
        let state = match (self.revoked_at, self.lapsed) {
            (Some(_), _) => GrantState::Revoked,
            (None, true) => GrantState::Expired,
            (None, false) => GrantState::Active,
        };
        Ok(DocumentGrantView {
            id: self.id.to_string(),
            document_id: self.document_id.to_string(),
            version_id: self.version_id.to_string(),
            grantee: GranteeRef {
                subject: ExternalId::new(self.grantee.clone())
                    .map_err(|error| error.to_string())?,
            },
            state,
            issued_at: timestamp(self.issued_at),
            expires_at: timestamp(self.expires_at),
            revoked_at: self.revoked_at.map(timestamp),
        })
    }
}

fn decode_grants(rows: &[Row]) -> Result<Vec<Grant>, ProblemCode> {
    rows.iter()
        .map(Grant::from_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| unavailable("grant decode", &error))
}

fn grant_views(grants: &[Grant], limit: u32) -> Result<Vec<DocumentGrantView>, ProblemCode> {
    grants
        .iter()
        .take(limit as usize)
        .map(Grant::view)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| unavailable("grant decode", &error))
}

/// The idempotency operation a grant issue on `document_id` is keyed under.
fn issue_operation(document_id: Uuid) -> String {
    format!("document.grant:{document_id}")
}

impl DocumentService {
    /// The document `caller` may manage the grants of. A caller that may
    /// not see the document is answered as if it did not exist; one that
    /// sees it without a granting profile is `profile.not-authorized`.
    async fn grantable(
        &self,
        caller: &Caller,
        document_id: Uuid,
        managing: bool,
    ) -> Result<Record, ProblemCode> {
        let record = self
            .record(document_id)
            .await?
            .ok_or(ProblemCode::ResourceNotFound)?;
        let access = self.access(caller, &record).await?;
        if !access.sees() {
            return Err(ProblemCode::ResourceNotFound);
        }
        let allowed = if managing {
            access.standing.may_grant
        } else {
            access.standing.sees()
        };
        if !allowed {
            return Err(ProblemCode::ProfileNotAuthorized);
        }
        Ok(record)
    }

    /// Issue one grant on the exact version `request` names, under the
    /// idempotency key `key`. The expiry is fixed now: the policy default,
    /// or the asked hours up to the policy maximum. A repeated key re-runs
    /// authorization and answers with the grant as it stands.
    pub async fn issue_grant(
        &self,
        caller: &Caller,
        key: &str,
        document_id: Uuid,
        request: &IssueGrantRequest,
    ) -> Result<DocumentGrantView, ProblemCode> {
        let reference = self.actor_reference(caller)?;
        let audit = self
            .begin(
                GRANT_ISSUE_EVENT,
                json!({
                    "event": GRANT_ISSUE_EVENT,
                    "actor": reference,
                    "profile": caller.profile_id,
                    "documentId": document_id.to_string(),
                    "versionId": request.version_id,
                }),
            )
            .await?;
        let result = self.issue_inner(caller, key, document_id, request).await;
        let success = match &result {
            Ok(view) => json!({
                "event": GRANT_ISSUE_EVENT,
                "outcome": "issued",
                "grantId": view.id,
                "expiresAt": view.expires_at,
            }),
            Err(_) => Value::Null,
        };
        Self::finish(audit, GRANT_ISSUE_EVENT, &result, success).await?;
        result
    }

    async fn issue_inner(
        &self,
        caller: &Caller,
        key: &str,
        document_id: Uuid,
        request: &IssueGrantRequest,
    ) -> Result<DocumentGrantView, ProblemCode> {
        let record = self.grantable(caller, document_id, true).await?;
        let version_id = Uuid::parse_str(&request.version_id)
            .ok()
            .filter(|id| *id == record.version_id)
            .ok_or(ProblemCode::ResourceNotFound)?;
        if record
            .releasable_digest(&self.settings.verifier_binding)
            .is_none()
        {
            return Err(ProblemCode::DocumentVersionNotReleasable);
        }
        let policy = self
            .policy(&record.policy_id)
            .ok_or(ProblemCode::ResourceNotFound)?;
        let hours = i32::try_from(grant_expiry_hours(policy, request.expiry_hours)?)
            .map_err(|_| ProblemCode::RequestUnprocessable)?;
        let days = i32::try_from(self.settings.idempotency_days)
            .map_err(|error| unavailable("idempotency retention", &error))?;
        let key = key_digest(caller, &issue_operation(document_id), key);
        let digest = request_digest(request)?;
        let mut client = self.client().await?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| unavailable("grant transaction", &error))?;
        let grant_id = match replay(&transaction, &key, &digest).await? {
            Replay::Repeat(grant_id) => grant_id,
            Replay::Fresh => {
                let grant_id = Uuid::new_v4();
                transaction
                    .execute(
                        "INSERT INTO documents_grants
                             (grant_id, document_id, version_id, grantee_issuer, grantee_subject,
                              granted_by_issuer, granted_by_subject, granted_by_profile,
                              issued_at, expires_at)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, transaction_timestamp(),
                                 transaction_timestamp() + make_interval(hours => $9))",
                        &[
                            &grant_id,
                            &document_id,
                            &version_id,
                            &caller.issuer,
                            &request.grantee.subject.as_str(),
                            &caller.issuer,
                            &caller.subject,
                            &caller.profile_id.as_str(),
                            &hours,
                        ],
                    )
                    .await
                    .map_err(|error| unavailable("grant insert", &error))?;
                record_key(&transaction, &key, &digest, grant_id, days).await?;
                grant_id
            }
        };
        let row = transaction
            .query_opt(
                &format!(
                    "SELECT {GRANT_COLUMNS} FROM documents_grants AS grant_record
                      WHERE grant_record.grant_id = $1 AND grant_record.document_id = $2"
                ),
                &[&grant_id, &document_id],
            )
            .await
            .map_err(|error| unavailable("grant read", &error))?
            .ok_or_else(|| unavailable("grant read", &"the recorded grant is missing"))?;
        transaction
            .commit()
            .await
            .map_err(|error| unavailable("grant commit", &error))?;
        Grant::from_row(&row)
            .and_then(|grant| grant.view())
            .map_err(|error| unavailable("grant decode", &error))
    }

    /// Revoke one grant. Revocation is final and repeating it changes
    /// nothing; a release already admitted completes within its deadline.
    pub async fn revoke_grant(
        &self,
        caller: &Caller,
        grant_id: Uuid,
    ) -> Result<DocumentGrantView, ProblemCode> {
        let reference = self.actor_reference(caller)?;
        let audit = self
            .begin(
                GRANT_REVOKE_EVENT,
                json!({
                    "event": GRANT_REVOKE_EVENT,
                    "actor": reference,
                    "profile": caller.profile_id,
                    "grantId": grant_id.to_string(),
                }),
            )
            .await?;
        let result = self.revoke_inner(caller, grant_id).await;
        let success = match &result {
            Ok(view) => json!({
                "event": GRANT_REVOKE_EVENT,
                "outcome": "revoked",
                "revokedAt": view.revoked_at,
            }),
            Err(_) => Value::Null,
        };
        Self::finish(audit, GRANT_REVOKE_EVENT, &result, success).await?;
        result
    }

    async fn revoke_inner(
        &self,
        caller: &Caller,
        grant_id: Uuid,
    ) -> Result<DocumentGrantView, ProblemCode> {
        let document_id: Uuid = {
            let client = self.client().await?;
            client
                .query_opt(
                    "SELECT document_id FROM documents_grants WHERE grant_id = $1",
                    &[&grant_id],
                )
                .await
                .map_err(|error| unavailable("grant read", &error))?
                .ok_or(ProblemCode::ResourceNotFound)?
                .try_get(0)
                .map_err(|error| unavailable("grant decode", &error))?
        };
        self.grantable(caller, document_id, true).await?;
        let client = self.client().await?;
        let row = client
            .query_one(
                &format!(
                    "UPDATE documents_grants AS grant_record
                        SET revoked_at = COALESCE(grant_record.revoked_at, now())
                      WHERE grant_record.grant_id = $1
                  RETURNING {GRANT_COLUMNS}"
                ),
                &[&grant_id],
            )
            .await
            .map_err(|error| unavailable("grant revoke", &error))?;
        Grant::from_row(&row)
            .and_then(|grant| grant.view())
            .map_err(|error| unavailable("grant decode", &error))
    }

    /// Every grant on one document, in every state, oldest first.
    pub async fn document_grants(
        &self,
        caller: &Caller,
        document_id: Uuid,
        page: &PageRequest,
    ) -> Result<DocumentGrantPage, ProblemCode> {
        self.grantable(caller, document_id, false).await?;
        let (after, after_id) = Cursor::bounds(page.cursor);
        let client = self.client().await?;
        let rows = client
            .query(
                &format!(
                    "SELECT {GRANT_COLUMNS} FROM documents_grants AS grant_record
                      WHERE grant_record.document_id = $1
                        AND ($2::timestamptz IS NULL
                             OR (grant_record.issued_at, grant_record.grant_id) > ($2, $3))
                      ORDER BY grant_record.issued_at, grant_record.grant_id
                      LIMIT $4"
                ),
                &[&document_id, &after, &after_id, &page.fetch()],
            )
            .await
            .map_err(|error| unavailable("grant list", &error))?;
        let grants = decode_grants(&rows)?;
        Ok(DocumentGrantPage {
            next_cursor: next_cursor(&grants, page.limit, Grant::cursor),
            items: grant_views(&grants, page.limit)?,
        })
    }

    /// The active grants that name `caller` under a profile the policy
    /// admits as a recipient, oldest first.
    pub async fn received_grants(
        &self,
        caller: &Caller,
        page: &PageRequest,
    ) -> Result<DocumentGrantPage, ProblemCode> {
        let (after, after_id) = Cursor::bounds(page.cursor);
        let client = self.client().await?;
        let rows = client
            .query(
                &format!(
                    "SELECT {GRANT_COLUMNS}, document.policy_id
                       FROM documents_grants AS grant_record
                       JOIN documents_documents AS document
                         ON document.document_id = grant_record.document_id
                      WHERE grant_record.grantee_issuer = $1
                        AND grant_record.grantee_subject = $2
                        AND grant_record.revoked_at IS NULL
                        AND grant_record.expires_at > now()
                        AND ($3::timestamptz IS NULL
                             OR (grant_record.issued_at, grant_record.grant_id) > ($3, $4))
                      ORDER BY grant_record.issued_at, grant_record.grant_id
                      LIMIT $5"
                ),
                &[
                    &caller.issuer,
                    &caller.subject,
                    &after,
                    &after_id,
                    &page.fetch(),
                ],
            )
            .await
            .map_err(|error| unavailable("grant list", &error))?;
        drop(client);
        let grants = decode_grants(&rows)?;
        let next_cursor = next_cursor(&grants, page.limit, Grant::cursor);
        let mut items = Vec::new();
        for (grant, row) in grants.iter().zip(&rows).take(page.limit as usize) {
            let policy_id: String = row
                .try_get("policy_id")
                .map_err(|error| unavailable("grant decode", &error))?;
            if self
                .policy(&policy_id)
                .is_some_and(|policy| is_recipient(policy, caller))
            {
                items.push(
                    grant
                        .view()
                        .map_err(|error| unavailable("grant decode", &error))?,
                );
            }
        }
        Ok(DocumentGrantPage { items, next_cursor })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grant_issue_key_is_scoped_to_its_document() {
        assert_ne!(issue_operation(Uuid::nil()), issue_operation(Uuid::max()));
    }
}

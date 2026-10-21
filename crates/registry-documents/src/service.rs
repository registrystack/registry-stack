// SPDX-License-Identifier: Apache-2.0

//! Document operations: reserve a document, accept its content, read it,
//! and release its content.
//!
//! Every operation acts for one [`Actor`] and answers with a document view
//! or a problem from the closed vocabulary. A store, storage, or audit
//! failure is logged and answered as `service.unavailable`; nothing is
//! released or finalized past a failure.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, SecondsFormat, Utc};
use futures::Stream;
use registry_documents_core::{
    admit_reservation, check_custodian_quota, CustodianRef, DocumentStatus, DocumentVersionView,
    DocumentView, DocumentsProject, Eligibility, PolicyBinding, ProblemCode, ReservationAsk,
    ReservationView, ReserveDocumentRequest, UploadState, VerificationState,
};
use registry_platform_dispatch::postgres::{enqueue, JobKey, JobTable};
use registry_platform_yaml::{Digest, ExternalId, LocalId};
use serde_json::{json, Value};
use tokio::sync::Semaphore;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::actor::Actor;
use crate::audit::{
    DocumentsAudit, CONTENT_DOWNLOAD_EVENT, UPLOAD_CONTENT_EVENT, UPLOAD_RESERVATION_EVENT,
};
use crate::content::{digest_hex, pin_storage, read_hashing, BodyRefusal, ContentStorage};
use crate::store::PostgresStore;
use crate::verification::job_part;

/// The longest one upload body may take to arrive.
pub const TRANSFER_DEADLINE: Duration = Duration::from_secs(5 * 60);

/// The bytes all uploads in flight may hold at once. The number of
/// concurrent uploads is this divided by the deployment ceiling, and at
/// least one.
pub const UPLOAD_BUFFER_BYTES: u64 = 256 * 1024 * 1024;

/// The route an upload's content is sent to.
#[must_use]
pub fn upload_path(upload_id: Uuid) -> String {
    format!("/uploads/{upload_id}/content")
}

/// Content released to a reader: the exact bytes of one version, checked
/// against its digest and length.
#[derive(Debug)]
pub struct ReleasedContent {
    pub media_type: String,
    pub bytes: Vec<u8>,
}

/// The document operations of one deployment.
pub struct DocumentService {
    store: PostgresStore,
    project: Arc<DocumentsProject>,
    storage: Arc<ContentStorage>,
    verifier_binding: String,
    jobs: JobTable,
    audit: DocumentsAudit,
    uploads: Arc<Semaphore>,
    ceiling: u64,
}

impl std::fmt::Debug for DocumentService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DocumentService")
            .finish_non_exhaustive()
    }
}

/// Log a failure the caller is answered `service.unavailable` for.
fn unavailable(stage: &'static str, error: &dyn std::fmt::Display) -> ProblemCode {
    tracing::error!(stage, error = %error, "a document operation failed");
    ProblemCode::ServiceUnavailable
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// The columns [`view_from_row`] reads, in order.
const VIEW_COLUMNS: &str = "document.document_id, document.policy_id, document.policy_version,
    document.policy_digest, document.custodian_subject, version.version_id, version.upload_state,
    version.verification_state, version.eligibility, version.media_type, version.expected_digest,
    version.length, version.reserved_at, version.finalized_at";
const VIEW_FROM: &str = "documents_documents AS document
    JOIN documents_versions AS version ON version.document_id = document.document_id";

fn parse_upload(text: &str) -> Option<UploadState> {
    match text {
        "reserved" => Some(UploadState::Reserved),
        "finalized" => Some(UploadState::Finalized),
        "expired" => Some(UploadState::Expired),
        _ => None,
    }
}

fn parse_verification(text: &str) -> Option<VerificationState> {
    match text {
        "pending" => Some(VerificationState::Pending),
        "approved" => Some(VerificationState::Approved),
        "rejected" => Some(VerificationState::Rejected),
        _ => None,
    }
}

fn parse_eligibility(text: &str) -> Option<Eligibility> {
    match text {
        "suspended" => Some(Eligibility::Suspended),
        "releasable" => Some(Eligibility::Releasable),
        _ => None,
    }
}

/// The view of the document and version on `row`, read from
/// [`VIEW_COLUMNS`] at their positions.
fn view_from_row(row: &Row) -> Result<DocumentView, String> {
    let text = |index: usize| -> Result<String, String> {
        row.try_get::<_, String>(index)
            .map_err(|error| error.to_string())
    };
    let document_id: Uuid = row.try_get(0).map_err(|error| error.to_string())?;
    let version_id: Uuid = row.try_get(5).map_err(|error| error.to_string())?;
    let status = DocumentStatus::derive(
        parse_upload(&text(6)?).ok_or("an unknown upload state")?,
        parse_verification(&text(7)?).ok_or("an unknown verification state")?,
        parse_eligibility(&text(8)?).ok_or("an unknown eligibility")?,
    );
    let length: i64 = row.try_get(11).map_err(|error| error.to_string())?;
    let reserved_at: DateTime<Utc> = row.try_get(12).map_err(|error| error.to_string())?;
    let finalized_at: Option<DateTime<Utc>> = row.try_get(13).map_err(|error| error.to_string())?;
    Ok(DocumentView {
        id: document_id.to_string(),
        policy: PolicyBinding {
            id: LocalId::new(text(1)?).map_err(|error| error.to_string())?,
            version: text(2)?,
            digest: Digest::new(text(3)?).map_err(|error| error.to_string())?,
        },
        custodian: CustodianRef {
            subject: ExternalId::new(text(4)?).map_err(|error| error.to_string())?,
        },
        version: DocumentVersionView {
            id: version_id.to_string(),
            status,
            media_type: text(9)?,
            expected_digest: Digest::new(text(10)?).map_err(|error| error.to_string())?,
            length: u64::try_from(length).map_err(|error| error.to_string())?,
            reserved_at: timestamp(reserved_at),
            finalized_at: finalized_at.map(timestamp),
        },
    })
}

/// Whether `actor` may read the document: it is the custodian, or the
/// caller that reserved it.
fn may_read(actor: &Actor, custodian: &str, issuer: &str, subject: &str) -> bool {
    actor.subject == custodian || (actor.issuer == issuer && actor.subject == subject)
}

impl DocumentService {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        store: PostgresStore,
        project: Arc<DocumentsProject>,
        storage: Arc<ContentStorage>,
        verifier_binding: String,
        jobs: JobTable,
        audit: DocumentsAudit,
        ceiling: u64,
    ) -> Self {
        let permits = usize::try_from((UPLOAD_BUFFER_BYTES / ceiling.max(1)).max(1)).unwrap_or(1);
        Self {
            store,
            project,
            storage,
            verifier_binding,
            jobs,
            audit,
            uploads: Arc::new(Semaphore::new(permits)),
            ceiling,
        }
    }

    /// How many uploads may be read at once.
    #[must_use]
    pub fn upload_permits(&self) -> usize {
        self.uploads.available_permits()
    }

    fn actor_reference(&self, actor: &Actor) -> Result<String, ProblemCode> {
        if !actor.is_complete() {
            return Err(unavailable(
                "actor",
                &"the actor source returned an incomplete actor",
            ));
        }
        self.audit
            .actor_reference(actor)
            .map_err(|error| unavailable("audit actor reference", &error))
    }

    async fn begin(
        &self,
        event: &'static str,
        record: Value,
    ) -> Result<registry_platform_audit::AuditRequest, ProblemCode> {
        self.audit
            .begin(event, record)
            .await
            .map_err(|error| unavailable("audit request", &error))
    }

    /// Reserve one document and the upload of its single version. Size,
    /// media type, and the custodian's quota are refused here, before any
    /// byte moves. The quota is counted and the reservation written under
    /// one lock per custodian and policy, so concurrent reservations cannot
    /// pass it together.
    pub async fn reserve(
        &self,
        actor: &Actor,
        request: &ReserveDocumentRequest,
    ) -> Result<ReservationView, ProblemCode> {
        let reference = self.actor_reference(actor)?;
        let audit = self
            .begin(
                UPLOAD_RESERVATION_EVENT,
                json!({
                    "event": UPLOAD_RESERVATION_EVENT,
                    "actor": reference,
                    "policyId": request.policy_id,
                    "length": request.length,
                    "mediaType": request.media_type,
                }),
            )
            .await?;
        let result = self.reserve_inner(actor, request).await;
        let record = match &result {
            Ok(view) => json!({
                "event": UPLOAD_RESERVATION_EVENT,
                "outcome": "reserved",
                "documentId": view.document.id,
                "versionId": view.document.version.id,
            }),
            Err(problem) => json!({
                "event": UPLOAD_RESERVATION_EVENT,
                "outcome": "refused",
                "code": problem.code(),
            }),
        };
        audit
            .finish(record)
            .await
            .map_err(|error| unavailable("audit response", &error))?;
        result
    }

    async fn reserve_inner(
        &self,
        actor: &Actor,
        request: &ReserveDocumentRequest,
    ) -> Result<ReservationView, ProblemCode> {
        let admitted = admit_reservation(
            &self.project,
            ReservationAsk {
                policy_id: &request.policy_id,
                declared_length: request.length,
                media_type: &request.media_type,
            },
        )?;
        let binding = admitted
            .policy
            .binding(admitted.policy_id)
            .map_err(|error| unavailable("policy binding", &error))?;
        let custodian = request.custodian.subject.as_str();
        let grace = i32::try_from(
            admitted
                .policy
                .mandatory_restrictions
                .cleanup_grace_hours
                .get()
                .max(1),
        )
        .map_err(|error| unavailable("upload window", &error))?;
        let length = i64::try_from(request.length).map_err(|_| ProblemCode::DocumentTooLarge)?;
        let mut client = self
            .store
            .client()
            .await
            .map_err(|error| unavailable("database connection", &error))?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| unavailable("reservation transaction", &error))?;
        let lock = format!("{custodian}\n{}", admitted.policy_id.as_str());
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&lock],
            )
            .await
            .map_err(|error| unavailable("quota lock", &error))?;
        let held: i64 = transaction
            .query_one(
                "SELECT COALESCE(SUM(version.length), 0)::bigint
                   FROM documents_versions AS version
                   JOIN documents_documents AS document
                     ON document.document_id = version.document_id
                  WHERE document.custodian_subject = $1 AND document.policy_id = $2
                    AND (version.upload_state = 'finalized'
                         OR (version.upload_state = 'reserved'
                             AND version.upload_expires_at > transaction_timestamp()))",
                &[&custodian, &admitted.policy_id.as_str()],
            )
            .await
            .and_then(|row| row.try_get(0))
            .map_err(|error| unavailable("quota count", &error))?;
        check_custodian_quota(
            admitted.policy,
            u64::try_from(held).map_err(|error| unavailable("quota count", &error))?,
            request.length,
        )?;
        let document_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        let upload_id = Uuid::new_v4();
        transaction
            .execute(
                "INSERT INTO documents_documents
                     (document_id, policy_id, policy_version, policy_digest, custodian_subject,
                      created_at)
                 VALUES ($1, $2, $3, $4, $5, transaction_timestamp())",
                &[
                    &document_id,
                    &binding.id.as_str(),
                    &binding.version,
                    &binding.digest.as_str(),
                    &custodian,
                ],
            )
            .await
            .map_err(|error| unavailable("document insert", &error))?;
        let expires: DateTime<Utc> = transaction
            .query_one(
                "INSERT INTO documents_versions
                     (version_id, document_id, upload_id, upload_state, verification_state,
                      eligibility, media_type, expected_digest, length, actor_issuer,
                      actor_subject, actor_kind, client_id, access_profile_id,
                      issuing_institution, reserved_at, upload_expires_at)
                 VALUES ($1, $2, $3, 'reserved', 'pending', 'suspended', $4, $5, $6, $7, $8,
                         $9, $10, $11, $12, transaction_timestamp(),
                         transaction_timestamp() + make_interval(hours => $13))
                 RETURNING upload_expires_at",
                &[
                    &version_id,
                    &document_id,
                    &upload_id,
                    &admitted.media_type.as_str(),
                    &request.expected_digest.as_str(),
                    &length,
                    &actor.issuer,
                    &actor.subject,
                    &actor.kind.as_str(),
                    &actor.client_id,
                    &actor.access_profile_id,
                    &actor.issuing_institution,
                    &grace,
                ],
            )
            .await
            .and_then(|row| row.try_get(0))
            .map_err(|error| unavailable("version insert", &error))?;
        let view = self.view_in(&*transaction, document_id).await?;
        transaction
            .commit()
            .await
            .map_err(|error| unavailable("reservation commit", &error))?;
        Ok(ReservationView {
            document: view,
            upload_path: upload_path(upload_id),
            upload_expires_at: timestamp(expires),
        })
    }

    async fn view_in<C: tokio_postgres::GenericClient>(
        &self,
        client: &C,
        document_id: Uuid,
    ) -> Result<DocumentView, ProblemCode> {
        let row = client
            .query_one(
                &format!("SELECT {VIEW_COLUMNS} FROM {VIEW_FROM} WHERE document.document_id = $1"),
                &[&document_id],
            )
            .await
            .map_err(|error| unavailable("document read", &error))?;
        view_from_row(&row).map_err(|error| unavailable("document decode", &error))
    }

    /// Accept the content of a reserved upload. The body is hashed while it
    /// is read and cut off at the reserved length plus one byte; content
    /// that differs from the reserved length or digest keeps nothing. The
    /// version is finalized in one transaction with its verification job,
    /// and a concurrent attempt that lost finds it finalized and answers
    /// with the same document.
    pub async fn put_content<S, E>(
        &self,
        actor: &Actor,
        upload_id: Uuid,
        content_type: Option<&str>,
        content_length: Option<u64>,
        body: S,
    ) -> Result<DocumentView, ProblemCode>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
    {
        let reference = self.actor_reference(actor)?;
        let reservation = self.reservation(actor, upload_id).await?;
        if content_type != Some(reservation.media_type.as_str()) {
            return Err(ProblemCode::UploadContentTypeMismatch);
        }
        match content_length {
            Some(length) if length > self.ceiling => return Err(ProblemCode::RequestBodyTooLarge),
            Some(length) if length != reservation.length => {
                return Err(ProblemCode::UploadLengthMismatch)
            }
            _ => {}
        }
        let Ok(_permit) = Arc::clone(&self.uploads).try_acquire_owned() else {
            tracing::warn!("every upload slot is in use; the upload was refused");
            return Err(ProblemCode::ServiceUnavailable);
        };
        let audit = self
            .begin(
                UPLOAD_CONTENT_EVENT,
                json!({
                    "event": UPLOAD_CONTENT_EVENT,
                    "actor": reference,
                    "versionId": reservation.version_id.to_string(),
                    "length": reservation.length,
                }),
            )
            .await?;
        let result = self.accept_content(&reservation, body).await;
        let record = match &result {
            Ok(_) => json!({
                "event": UPLOAD_CONTENT_EVENT,
                "outcome": "finalized",
                "byteCount": reservation.length,
            }),
            Err(problem) => json!({
                "event": UPLOAD_CONTENT_EVENT,
                "outcome": "refused",
                "code": problem.code(),
                "byteCount": 0,
            }),
        };
        audit
            .finish(record)
            .await
            .map_err(|error| unavailable("audit response", &error))?;
        result
    }

    /// The reservation `actor` holds under `upload_id`, if it still accepts
    /// content.
    async fn reservation(
        &self,
        actor: &Actor,
        upload_id: Uuid,
    ) -> Result<Reservation, ProblemCode> {
        let client = self
            .store
            .client()
            .await
            .map_err(|error| unavailable("database connection", &error))?;
        let row = client
            .query_opt(
                "SELECT version_id, document_id, actor_issuer, actor_subject, upload_state,
                        upload_expires_at <= now(), media_type, expected_digest, length
                   FROM documents_versions WHERE upload_id = $1",
                &[&upload_id],
            )
            .await
            .map_err(|error| unavailable("reservation read", &error))?
            .ok_or(ProblemCode::RequestNotFound)?;
        let read = |error: tokio_postgres::Error| unavailable("reservation decode", &error);
        let issuer: String = row.try_get(2).map_err(read)?;
        let subject: String = row.try_get(3).map_err(read)?;
        if issuer != actor.issuer || subject != actor.subject {
            return Err(ProblemCode::RequestNotFound);
        }
        let state: String = row.try_get(4).map_err(read)?;
        let lapsed: bool = row.try_get(5).map_err(read)?;
        match state.as_str() {
            "finalized" => return Err(ProblemCode::UploadFinalized),
            "expired" => return Err(ProblemCode::UploadExpired),
            _ if lapsed => return Err(ProblemCode::UploadExpired),
            _ => {}
        }
        let length: i64 = row.try_get(8).map_err(read)?;
        Ok(Reservation {
            version_id: row.try_get(0).map_err(read)?,
            document_id: row.try_get(1).map_err(read)?,
            media_type: row.try_get(6).map_err(read)?,
            expected_digest: row.try_get(7).map_err(read)?,
            length: u64::try_from(length)
                .map_err(|error| unavailable("reservation decode", &error))?,
        })
    }

    async fn accept_content<S, E>(
        &self,
        reservation: &Reservation,
        body: S,
    ) -> Result<DocumentView, ProblemCode>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
    {
        let body =
            match tokio::time::timeout(TRANSFER_DEADLINE, read_hashing(body, reservation.length))
                .await
            {
                Ok(Ok(body)) => body,
                Ok(Err(BodyRefusal::Longer | BodyRefusal::Shorter)) => {
                    return Err(ProblemCode::UploadLengthMismatch)
                }
                Ok(Err(BodyRefusal::Unreadable)) | Err(_) => {
                    return Err(ProblemCode::RequestInvalid)
                }
            };
        if body.digest() != reservation.expected_digest {
            return Err(ProblemCode::UploadDigestMismatch);
        }
        let digest = body.digest();
        let object_id = match self.storage.as_ref() {
            ContentStorage::Database { .. } => None,
            ContentStorage::S3 { .. } => Some(
                self.stage_object(reservation, &body.sha256_hex, body.bytes.clone())
                    .await?,
            ),
        };
        self.finalize(reservation, &digest, object_id, body.bytes)
            .await
    }

    /// Write the content to its own fresh object, after committing the
    /// staged row that names it, so an object a failed attempt leaves
    /// behind stays findable.
    async fn stage_object(
        &self,
        reservation: &Reservation,
        sha256: &str,
        bytes: Vec<u8>,
    ) -> Result<Uuid, ProblemCode> {
        let object_id = Uuid::new_v4();
        let store = self
            .storage
            .object(object_id)
            .await
            .map_err(|error| unavailable("object storage", &error))?;
        let length = i64::try_from(reservation.length)
            .map_err(|error| unavailable("object length", &error))?;
        let client = self
            .store
            .client()
            .await
            .map_err(|error| unavailable("database connection", &error))?;
        client
            .execute(
                "INSERT INTO documents_staged_objects
                     (object_id, version_id, binding_digest, sha256, length, staged_at)
                 VALUES ($1, $2, $3, $4, $5, now())",
                &[
                    &object_id,
                    &reservation.version_id,
                    &store.binding_digest(),
                    &sha256,
                    &length,
                ],
            )
            .await
            .map_err(|error| unavailable("staged object insert", &error))?;
        store
            .put(sha256, bytes)
            .await
            .map_err(|error| unavailable("object write", &error))?;
        Ok(object_id)
    }

    async fn finalize(
        &self,
        reservation: &Reservation,
        digest: &str,
        object_id: Option<Uuid>,
        bytes: Vec<u8>,
    ) -> Result<DocumentView, ProblemCode> {
        let version_id = reservation.version_id;
        let mut client = self
            .store
            .client()
            .await
            .map_err(|error| unavailable("database connection", &error))?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| unavailable("finalize transaction", &error))?;
        let row = transaction
            .query_one(
                "SELECT upload_state, computed_digest,
                        upload_expires_at <= transaction_timestamp()
                   FROM documents_versions WHERE version_id = $1 FOR UPDATE",
                &[&version_id],
            )
            .await
            .map_err(|error| unavailable("finalize lock", &error))?;
        let read = |error: tokio_postgres::Error| unavailable("finalize decode", &error);
        let state: String = row.try_get(0).map_err(read)?;
        let computed: Option<String> = row.try_get(1).map_err(read)?;
        let lapsed: bool = row.try_get(2).map_err(read)?;
        match state.as_str() {
            "finalized" if computed.as_deref() == Some(digest) => {
                return self.view_in(&*transaction, reservation.document_id).await;
            }
            "finalized" => return Err(ProblemCode::UploadFinalized),
            "expired" => return Err(ProblemCode::UploadExpired),
            _ if lapsed => return Err(ProblemCode::UploadExpired),
            _ => {}
        }
        if !pin_storage(&*transaction, &self.storage)
            .await
            .map_err(|error| unavailable("storage pin", &error))?
        {
            return Err(unavailable(
                "storage pin",
                &"the pinned storage binding is not this deployment's",
            ));
        }
        match object_id {
            None => {
                transaction
                    .execute(
                        "INSERT INTO documents_contents (version_id, content) VALUES ($1, $2)",
                        &[&version_id, &bytes],
                    )
                    .await
                    .map_err(|error| unavailable("content insert", &error))?;
            }
            Some(object_id) => {
                let committed = transaction
                    .execute(
                        "UPDATE documents_staged_objects SET committed = true
                          WHERE object_id = $1 AND version_id = $2 AND NOT committed",
                        &[&object_id, &version_id],
                    )
                    .await
                    .map_err(|error| unavailable("staged object commit", &error))?;
                if committed != 1 {
                    return Err(unavailable(
                        "staged object commit",
                        &"the staged object row is missing",
                    ));
                }
            }
        }
        transaction
            .execute(
                "UPDATE documents_versions
                    SET upload_state = 'finalized', computed_digest = $2,
                        finalized_at = transaction_timestamp(), storage_backend = $3,
                        object_id = $4, verification_binding_digest = $5
                  WHERE version_id = $1",
                &[
                    &version_id,
                    &digest,
                    &self.storage.backend(),
                    &object_id,
                    &self.verifier_binding,
                ],
            )
            .await
            .map_err(|error| unavailable("version finalize", &error))?;
        let key = JobKey::new(version_id, job_part(version_id, &self.verifier_binding))
            .map_err(|error| unavailable("verification job key", &error))?;
        enqueue(&transaction, &self.jobs, &key, None)
            .await
            .map_err(|error| unavailable("verification job enqueue", &error))?;
        let view = self.view_in(&*transaction, reservation.document_id).await?;
        transaction
            .commit()
            .await
            .map_err(|error| unavailable("finalize commit", &error))?;
        Ok(view)
    }

    /// The document `actor` may read.
    pub async fn read(
        &self,
        actor: &Actor,
        document_id: Uuid,
    ) -> Result<DocumentView, ProblemCode> {
        let client = self
            .store
            .client()
            .await
            .map_err(|error| unavailable("database connection", &error))?;
        let row = client
            .query_opt(
                &format!(
                    "SELECT {VIEW_COLUMNS}, version.actor_issuer, version.actor_subject
                       FROM {VIEW_FROM} WHERE document.document_id = $1"
                ),
                &[&document_id],
            )
            .await
            .map_err(|error| unavailable("document read", &error))?
            .ok_or(ProblemCode::RequestNotFound)?;
        let view = view_from_row(&row).map_err(|error| unavailable("document decode", &error))?;
        let issuer: String = row
            .try_get(14)
            .map_err(|error| unavailable("document decode", &error))?;
        let subject: String = row
            .try_get(15)
            .map_err(|error| unavailable("document decode", &error))?;
        if !may_read(actor, view.custodian.subject.as_str(), &issuer, &subject) {
            return Err(ProblemCode::RequestNotFound);
        }
        Ok(view)
    }

    /// Release the exact content of one version. Only a `ready` version
    /// whose approval is bound to its digest, its media type, and the
    /// current verifier binding is released, and its bytes are checked
    /// against the digest and length before the first byte is handed back.
    pub async fn download(
        &self,
        actor: &Actor,
        document_id: Uuid,
        version_id: Uuid,
    ) -> Result<ReleasedContent, ProblemCode> {
        let reference = self.actor_reference(actor)?;
        let client = self
            .store
            .client()
            .await
            .map_err(|error| unavailable("database connection", &error))?;
        let row = client
            .query_opt(
                "SELECT document.custodian_subject, version.actor_issuer, version.actor_subject,
                        version.upload_state, version.verification_state, version.eligibility,
                        version.verified_binding_digest, version.verified_digest,
                        version.verified_media_type, version.computed_digest, version.media_type,
                        version.length, version.object_id
                   FROM documents_documents AS document
                   JOIN documents_versions AS version
                     ON version.document_id = document.document_id
                  WHERE document.document_id = $1 AND version.version_id = $2",
                &[&document_id, &version_id],
            )
            .await
            .map_err(|error| unavailable("version read", &error))?
            .ok_or(ProblemCode::RequestNotFound)?;
        let read = |error: tokio_postgres::Error| unavailable("version decode", &error);
        let custodian: String = row.try_get(0).map_err(read)?;
        let issuer: String = row.try_get(1).map_err(read)?;
        let subject: String = row.try_get(2).map_err(read)?;
        if !may_read(actor, &custodian, &issuer, &subject) {
            return Err(ProblemCode::RequestNotFound);
        }
        let status = DocumentStatus::derive(
            parse_upload(&row.try_get::<_, String>(3).map_err(read)?)
                .ok_or(ProblemCode::ServiceUnavailable)?,
            parse_verification(&row.try_get::<_, String>(4).map_err(read)?)
                .ok_or(ProblemCode::ServiceUnavailable)?,
            parse_eligibility(&row.try_get::<_, String>(5).map_err(read)?)
                .ok_or(ProblemCode::ServiceUnavailable)?,
        );
        let verified_binding: Option<String> = row.try_get(6).map_err(read)?;
        let verified_digest: Option<String> = row.try_get(7).map_err(read)?;
        let verified_media_type: Option<String> = row.try_get(8).map_err(read)?;
        let computed: Option<String> = row.try_get(9).map_err(read)?;
        let media_type: String = row.try_get(10).map_err(read)?;
        let length: i64 = row.try_get(11).map_err(read)?;
        let object_id: Option<Uuid> = row.try_get(12).map_err(read)?;
        let releasable = status.is_releasable()
            && verified_binding.as_deref() == Some(self.verifier_binding.as_str())
            && computed.is_some()
            && verified_digest == computed
            && verified_media_type.as_deref() == Some(media_type.as_str());
        let Some(digest) = computed.filter(|_| releasable) else {
            return Err(ProblemCode::DocumentVersionNotReleasable);
        };
        if digest_hex(&digest).is_none() {
            return Err(ProblemCode::DocumentVersionNotReleasable);
        }
        let length =
            u64::try_from(length).map_err(|error| unavailable("version decode", &error))?;
        let audit = self
            .begin(
                CONTENT_DOWNLOAD_EVENT,
                json!({
                    "event": CONTENT_DOWNLOAD_EVENT,
                    "actor": reference,
                    "versionId": version_id.to_string(),
                }),
            )
            .await?;
        let content = self
            .storage
            .read(&**client, version_id, object_id, &digest, length)
            .await;
        match content {
            Ok(bytes) => {
                audit
                    .finish(json!({
                        "event": CONTENT_DOWNLOAD_EVENT,
                        "outcome": "released",
                        "byteCount": bytes.len(),
                    }))
                    .await
                    .map_err(|error| unavailable("audit response", &error))?;
                Ok(ReleasedContent { media_type, bytes })
            }
            Err(error) => {
                tracing::error!(
                    version = %version_id,
                    error = %error,
                    "stored content failed its integrity check; nothing was released"
                );
                audit
                    .finish(json!({
                        "event": CONTENT_DOWNLOAD_EVENT,
                        "outcome": "storage-integrity",
                        "byteCount": 0,
                    }))
                    .await
                    .map_err(|error| unavailable("audit response", &error))?;
                Err(ProblemCode::ServiceUnavailable)
            }
        }
    }
}

/// A reservation that still accepts content.
struct Reservation {
    version_id: Uuid,
    document_id: Uuid,
    media_type: String,
    expected_digest: String,
    length: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::ActorKind;

    fn actor(issuer: &str, subject: &str) -> Actor {
        Actor {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
            kind: ActorKind::Service,
            client_id: "civil-registry-app".to_owned(),
            access_profile_id: "custodian-app".to_owned(),
            issuing_institution: "civil-registry".to_owned(),
        }
    }

    #[test]
    fn the_custodian_and_the_reserving_caller_may_read() {
        let issuer = "https://identity.example.test";
        assert!(may_read(
            &actor(issuer, "citizen-1"),
            "citizen-1",
            issuer,
            "app"
        ));
        assert!(may_read(&actor(issuer, "app"), "citizen-1", issuer, "app"));
        assert!(!may_read(
            &actor(issuer, "citizen-2"),
            "citizen-1",
            issuer,
            "app"
        ));
        assert!(!may_read(
            &actor("https://other.example.test", "app"),
            "citizen-1",
            issuer,
            "app"
        ));
    }

    #[test]
    fn the_upload_path_names_the_upload() {
        let id = Uuid::nil();
        assert_eq!(
            upload_path(id),
            "/uploads/00000000-0000-0000-0000-000000000000/content"
        );
    }
}

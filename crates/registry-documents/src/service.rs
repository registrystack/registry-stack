// SPDX-License-Identifier: Apache-2.0

//! Document operations: reserve a document, accept its content, read and
//! list documents, release content, and issue, revoke, and list document
//! grants.
//!
//! Every operation acts for one verified [`Caller`] and answers with a view
//! or a problem from the closed vocabulary. What the caller may do is
//! decided against its resolved access profile and the document's frozen
//! custody, never against a value the request carries. A caller that is
//! neither the custodian nor the holder of a grant that releases the
//! document learns nothing about it: an unknown document and one it may
//! not see answer the same `resource.not-found`.
//!
//! A store, storage, or audit failure is logged and answered as
//! `service.unavailable`; nothing is released or finalized past a failure.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use chrono::{DateTime, SecondsFormat, Utc};
use futures::Stream;
use registry_documents_core::{
    admit_reservation, allowed_actions, check_custodian_quota, place_custody, standing, ActorKind,
    Caller, ContentType, CustodianRef, Custody, CustodyAsk, DocumentPage, DocumentPolicy,
    DocumentPolicyList, DocumentPolicyView, DocumentStatus, DocumentVersionView, DocumentView,
    DocumentsProject, Eligibility, ErasureState, PolicyBinding, ProblemCode, ReservationAsk,
    ReservationView, ReserveDocumentRequest, Reserver, Standing, UploadState, VerificationState,
    MAXIMUM_PAGE_SIZE, UPLOAD_CONTENT_PATH,
};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_dispatch::postgres::{enqueue, JobKey, JobTable};
use registry_platform_yaml::{Digest, ExternalId, LocalId};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::audit::{
    DocumentsAudit, CONTENT_DOWNLOAD_EVENT, UPLOAD_CONTENT_EVENT, UPLOAD_RESERVATION_EVENT,
};
use crate::content::{digest_hex, pin_storage, read_hashing, BodyRefusal, ContentStorage};
use crate::hooks::ActivatedHooks;
use crate::store::PostgresStore;
use crate::transfer::{ReleaseBody, TransferBudget, TransferDeadline};
use crate::verification::job_part;

mod erasure;
mod grants;

/// The idempotency operation a reservation is keyed under.
const RESERVE_OPERATION: &str = "document.reserve";

/// The route an upload's content is sent to.
#[must_use]
pub fn upload_path(upload_id: Uuid) -> String {
    UPLOAD_CONTENT_PATH.replace("{uploadId}", &upload_id.to_string())
}

/// Content released to a reader: the exact bytes of one version, checked
/// against its digest and length before the first byte, streamed under the
/// transfer budget until the deadline.
pub struct ReleasedContent {
    pub media_type: String,
    pub length: u64,
    pub body: ReleaseBody,
}

impl std::fmt::Debug for ReleasedContent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReleasedContent")
            .field("media_type", &self.media_type)
            .field("length", &self.length)
            .finish_non_exhaustive()
    }
}

/// The answer to a content upload. `Accepted` finalized the version now;
/// `Repeated` found it finalized with the same content already.
#[derive(Debug)]
pub enum UploadOutcome {
    Accepted(DocumentView),
    Repeated(DocumentView),
}

impl UploadOutcome {
    #[must_use]
    pub fn into_view(self) -> DocumentView {
        match self {
            Self::Accepted(view) | Self::Repeated(view) => view,
        }
    }
}

/// One page request: where the previous page ended, and at most how many
/// items to return.
#[derive(Clone, Debug, Default)]
pub struct PageRequest {
    pub cursor: Option<Cursor>,
    pub limit: u32,
}

impl PageRequest {
    /// Read a page request from its query values. A malformed cursor or a
    /// limit outside one to [`MAXIMUM_PAGE_SIZE`] is `request.invalid`.
    pub fn parse(cursor: Option<&str>, limit: Option<&str>) -> Result<Self, ProblemCode> {
        let limit = match limit {
            None => registry_documents_core::DEFAULT_PAGE_SIZE,
            Some(text) => text
                .parse::<u32>()
                .ok()
                .filter(|limit| (1..=MAXIMUM_PAGE_SIZE).contains(limit))
                .ok_or(ProblemCode::RequestInvalid)?,
        };
        let cursor = cursor
            .map(|text| Cursor::decode(text).ok_or(ProblemCode::RequestInvalid))
            .transpose()?;
        Ok(Self { cursor, limit })
    }

    fn fetch(&self) -> i64 {
        i64::from(self.limit) + 1
    }
}

/// The longest cursor a caller may hand back.
pub const MAXIMUM_CURSOR_BYTES: usize = 256;

/// A position in a list: the ordering instant and the identifier that
/// breaks its ties. Encoded opaquely; a caller only hands it back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cursor {
    at: DateTime<Utc>,
    id: Uuid,
}

impl Cursor {
    fn encode(self) -> String {
        hex::encode(format!("{}:{}", self.at.timestamp_micros(), self.id))
    }

    fn decode(text: &str) -> Option<Self> {
        if text.len() > MAXIMUM_CURSOR_BYTES {
            return None;
        }
        let bytes = hex::decode(text).ok()?;
        let text = std::str::from_utf8(&bytes).ok()?;
        let (micros, id) = text.split_once(':')?;
        Some(Self {
            at: DateTime::from_timestamp_micros(micros.parse().ok()?)?,
            id: Uuid::parse_str(id).ok()?,
        })
    }

    fn bounds(cursor: Option<Self>) -> (Option<DateTime<Utc>>, Uuid) {
        cursor.map_or((None, Uuid::nil()), |cursor| (Some(cursor.at), cursor.id))
    }
}

/// The cursor of the next page when `rows` holds more than `limit` rows,
/// at the last row of this page.
fn next_cursor<T>(rows: &[T], limit: u32, position: impl Fn(&T) -> Cursor) -> Option<String> {
    let limit = usize::try_from(limit).ok()?;
    (rows.len() > limit).then(|| position(&rows[limit - 1]).encode())
}

/// The settings a service is built with.
#[derive(Clone, Debug)]
pub struct ServiceSettings {
    /// The binding digest of the active content verifier.
    pub verifier_binding: String,
    /// The deployment ceiling, `storage.maximumDocumentBytes`.
    pub ceiling: u64,
    /// The in-flight byte budget shared with content verification.
    pub budget: TransferBudget,
    pub deadline: TransferDeadline,
    /// How long a replay of an idempotency key is answered,
    /// `retention.receiptRetentionDays`. After it the key stays spent.
    pub idempotency_days: u32,
}

/// The document operations of one deployment.
pub struct DocumentService {
    store: PostgresStore,
    project: Arc<DocumentsProject>,
    storage: Arc<ContentStorage>,
    jobs: JobTable,
    audit: DocumentsAudit,
    settings: ServiceSettings,
    hooks: ActivatedHooks,
}

impl std::fmt::Debug for DocumentService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DocumentService")
            .finish_non_exhaustive()
    }
}

/// The journal's marker for a request value that does not parse.
const UNPARSED: &str = "unparsed";

/// What the journal records for an identifier a caller sent: the value
/// once it parses under its bounded grammar, and [`UNPARSED`] when it does
/// not, so no unchecked text reaches the journal.
fn checked<T: std::fmt::Display>(parsed: Option<T>) -> String {
    parsed.map_or_else(|| UNPARSED.to_owned(), |value| value.to_string())
}

/// Log a failure the caller is answered `service.unavailable` for.
fn unavailable(stage: &'static str, error: &dyn std::fmt::Display) -> ProblemCode {
    tracing::error!(stage, error = %error, "a document operation failed");
    ProblemCode::ServiceUnavailable
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// The columns [`Record::from_row`] reads, by name.
const RECORD_COLUMNS: &str = "document.document_id, document.policy_id, document.policy_version,
    document.policy_digest, document.custodian_issuer, document.custodian_subject,
    document.custodian_kind, document.represented_principal_subject, document.label,
    document.created_at, version.version_id, version.upload_id, version.upload_state,
    version.upload_expires_at, version.upload_expires_at <= now() AS upload_lapsed,
    version.verification_state, version.eligibility, version.media_type,
    version.expected_digest, version.length, version.reserved_at, version.finalized_at,
    version.actor_issuer, version.actor_subject, version.actor_kind,
    version.verified_binding_digest,
    version.verified_digest, version.verified_media_type, version.computed_digest,
    version.object_id, version.erasure_state";
const RECORD_FROM: &str = "documents_documents AS document
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

fn parse_erasure(text: &str) -> Option<ErasureState> {
    match text {
        "none" => Some(ErasureState::None),
        "pending" => Some(ErasureState::Pending),
        "erased" => Some(ErasureState::Erased),
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

/// One document and its single version, as stored.
#[derive(Clone, Debug)]
struct Record {
    document_id: Uuid,
    policy_id: String,
    policy: PolicyBinding,
    custody: Custody,
    label: Option<String>,
    created_at: DateTime<Utc>,
    version_id: Uuid,
    upload_id: Uuid,
    upload: UploadState,
    upload_expires_at: DateTime<Utc>,
    upload_lapsed: bool,
    status: DocumentStatus,
    media_type: String,
    expected_digest: String,
    length: u64,
    reserved_at: DateTime<Utc>,
    finalized_at: Option<DateTime<Utc>>,
    reserver_issuer: String,
    reserver_subject: String,
    reserver_kind: ActorKind,
    verified_binding: Option<String>,
    verified_digest: Option<String>,
    verified_media_type: Option<String>,
    computed_digest: Option<String>,
    object_id: Option<Uuid>,
}

impl Record {
    fn from_row(row: &Row) -> Result<Self, String> {
        fn get<'a, T: tokio_postgres::types::FromSql<'a>>(
            row: &'a Row,
            name: &str,
        ) -> Result<T, String> {
            row.try_get(name).map_err(|error| error.to_string())
        }
        let text = |name: &str| get::<String>(row, name);
        let upload = parse_upload(&text("upload_state")?).ok_or("an unknown upload state")?;
        let status = DocumentStatus::derive(
            parse_erasure(&text("erasure_state")?).ok_or("an unknown erasure state")?,
            upload,
            parse_verification(&text("verification_state")?)
                .ok_or("an unknown verification state")?,
            parse_eligibility(&text("eligibility")?).ok_or("an unknown eligibility")?,
        );
        let length: i64 = get(row, "length")?;
        Ok(Self {
            document_id: get(row, "document_id")?,
            policy_id: text("policy_id")?,
            policy: PolicyBinding {
                id: LocalId::new(text("policy_id")?).map_err(|error| error.to_string())?,
                version: text("policy_version")?,
                digest: Digest::new(text("policy_digest")?).map_err(|error| error.to_string())?,
            },
            custody: Custody {
                issuer: text("custodian_issuer")?,
                subject: text("custodian_subject")?,
                kind: ActorKind::from_str_exact(&text("custodian_kind")?)
                    .ok_or("an unknown custodian kind")?,
                represented_principal: get(row, "represented_principal_subject")?,
            },
            label: get(row, "label")?,
            created_at: get(row, "created_at")?,
            version_id: get(row, "version_id")?,
            upload_id: get(row, "upload_id")?,
            upload,
            upload_expires_at: get(row, "upload_expires_at")?,
            upload_lapsed: get(row, "upload_lapsed")?,
            status,
            media_type: text("media_type")?,
            expected_digest: text("expected_digest")?,
            length: u64::try_from(length).map_err(|error| error.to_string())?,
            reserved_at: get(row, "reserved_at")?,
            finalized_at: get(row, "finalized_at")?,
            reserver_issuer: text("actor_issuer")?,
            reserver_subject: text("actor_subject")?,
            reserver_kind: ActorKind::from_str_exact(&text("actor_kind")?)
                .ok_or("an unknown reserving actor kind")?,
            verified_binding: get(row, "verified_binding_digest")?,
            verified_digest: get(row, "verified_digest")?,
            verified_media_type: get(row, "verified_media_type")?,
            computed_digest: get(row, "computed_digest")?,
            object_id: get(row, "object_id")?,
        })
    }

    fn reserver(&self) -> Reserver<'_> {
        Reserver {
            issuer: &self.reserver_issuer,
            subject: &self.reserver_subject,
            kind: self.reserver_kind,
        }
    }

    fn cursor(&self) -> Cursor {
        Cursor {
            at: self.created_at,
            id: self.document_id,
        }
    }

    /// The digest of the content this version may release under
    /// `verifier_binding`: a `ready` version whose approval is bound to its
    /// computed digest, its media type, and that verifier binding.
    fn releasable_digest(&self, verifier_binding: &str) -> Option<&str> {
        let computed = self.computed_digest.as_deref()?;
        let bound = self.status.is_releasable()
            && self.verified_binding.as_deref() == Some(verifier_binding)
            && self.verified_digest.as_deref() == Some(computed)
            && self.verified_media_type.as_deref() == Some(self.media_type.as_str());
        (bound && digest_hex(computed).is_some()).then_some(computed)
    }

    fn view(
        &self,
        status: DocumentStatus,
        actions: Vec<registry_documents_core::DocumentAction>,
    ) -> Result<DocumentView, String> {
        Ok(DocumentView {
            id: self.document_id.to_string(),
            policy: self.policy.clone(),
            custodian: CustodianRef {
                subject: ExternalId::new(self.custody.subject.clone())
                    .map_err(|error| error.to_string())?,
            },
            version: DocumentVersionView {
                id: self.version_id.to_string(),
                status,
                media_type: self.media_type.clone(),
                expected_digest: Digest::new(self.expected_digest.clone())
                    .map_err(|error| error.to_string())?,
                length: self.length,
                reserved_at: timestamp(self.reserved_at),
                finalized_at: self.finalized_at.map(timestamp),
            },
            label: self.label.clone(),
            actions,
        })
    }
}

/// What one caller is to one stored document, all things considered.
#[derive(Clone, Copy, Debug, Default)]
struct Access {
    standing: Standing,
    /// The caller holds an active grant on the exact version, its profile
    /// is one of the policy's recipient profiles, and the version is
    /// releasable now.
    released_by_grant: bool,
}

impl Access {
    fn sees(self) -> bool {
        self.standing.sees() || self.released_by_grant
    }
}

/// The digest an idempotency key is stored under: the key scoped to the
/// caller's issuer and subject and to the operation.
fn key_digest(caller: &Caller, operation: &str, key: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [
        caller.issuer.as_str(),
        caller.subject.as_str(),
        operation,
        key,
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

/// The digest of a request body in canonical JSON.
fn request_digest(body: &impl serde::Serialize) -> Result<String, ProblemCode> {
    let value =
        serde_json::to_value(body).map_err(|error| unavailable("request digest", &error))?;
    let canonical =
        canonicalize_json(&value).map_err(|error| unavailable("request digest", &error))?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

/// What an idempotency key already records.
enum Replay {
    /// The key is new; the operation runs and records it.
    Fresh,
    /// The same request already ran and created this resource.
    Repeat(Uuid),
}

/// Look up `key` inside `transaction`, holding a lock on it until the
/// transaction ends so two requests under one key cannot both run. A key
/// past its retention is `idempotency.expired`; a key that names another
/// request is `idempotency.key-reused`.
async fn replay(
    transaction: &tokio_postgres::Transaction<'_>,
    key: &str,
    request: &str,
) -> Result<Replay, ProblemCode> {
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 1))",
            &[&key],
        )
        .await
        .map_err(|error| unavailable("idempotency lock", &error))?;
    let row = transaction
        .query_opt(
            "SELECT request_digest, resource_id, expires_at <= transaction_timestamp()
               FROM documents_idempotency WHERE key_digest = $1",
            &[&key],
        )
        .await
        .map_err(|error| unavailable("idempotency read", &error))?;
    let Some(row) = row else {
        return Ok(Replay::Fresh);
    };
    let read = |error: tokio_postgres::Error| unavailable("idempotency decode", &error);
    let recorded: String = row.try_get(0).map_err(read)?;
    let resource: Uuid = row.try_get(1).map_err(read)?;
    let expired: bool = row.try_get(2).map_err(read)?;
    if expired {
        return Err(ProblemCode::IdempotencyExpired);
    }
    if recorded != request {
        return Err(ProblemCode::IdempotencyKeyReused);
    }
    Ok(Replay::Repeat(resource))
}

/// Record that `key` created `resource`. A replay is answered for the
/// retention period; after it the row stays, holding only digests and the
/// resource id, so the key stays spent and answers `idempotency.expired`.
async fn record_key(
    transaction: &tokio_postgres::Transaction<'_>,
    key: &str,
    request: &str,
    resource: Uuid,
    days: i32,
) -> Result<(), ProblemCode> {
    transaction
        .execute(
            "INSERT INTO documents_idempotency
                 (key_digest, request_digest, resource_id, created_at, expires_at)
             VALUES ($1, $2, $3, transaction_timestamp(),
                     transaction_timestamp() + make_interval(days => $4))",
            &[&key, &request, &resource, &days],
        )
        .await
        .map_err(|error| unavailable("idempotency insert", &error))?;
    Ok(())
}

/// A reservation the content route found.
struct Reservation {
    record: Record,
}

/// Where accepted content is held until the finalizing transaction.
enum Stored {
    Database(Vec<u8>),
    Object(Uuid),
}

impl DocumentService {
    #[must_use]
    pub fn new(
        store: PostgresStore,
        project: Arc<DocumentsProject>,
        storage: Arc<ContentStorage>,
        jobs: JobTable,
        audit: DocumentsAudit,
        settings: ServiceSettings,
        hooks: ActivatedHooks,
    ) -> Self {
        Self {
            store,
            project,
            storage,
            jobs,
            audit,
            settings,
            hooks,
        }
    }

    /// This service with `audit` as its journal, so a suite can prove a
    /// request whose audit entry cannot be written is refused.
    #[cfg(feature = "postgres-test")]
    #[must_use]
    pub fn with_audit(&self, audit: DocumentsAudit) -> Self {
        Self {
            store: self.store.clone(),
            project: Arc::clone(&self.project),
            storage: Arc::clone(&self.storage),
            jobs: self.jobs.clone(),
            audit,
            settings: self.settings.clone(),
            hooks: self.hooks.clone(),
        }
    }

    /// The in-flight byte budget this service and content verification
    /// share.
    #[must_use]
    pub fn budget(&self) -> &TransferBudget {
        &self.settings.budget
    }

    fn actor_reference(&self, caller: &Caller) -> Result<String, ProblemCode> {
        self.audit
            .actor_reference(&caller.issuer, &caller.subject)
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

    async fn finish<T>(
        audit: registry_platform_audit::AuditRequest,
        event: &'static str,
        result: &Result<T, ProblemCode>,
        success: Value,
    ) -> Result<(), ProblemCode> {
        let record = match result {
            Ok(_) => success,
            Err(problem) => json!({
                "event": event,
                "outcome": "refused",
                "code": problem.code(),
            }),
        };
        audit
            .finish(record)
            .await
            .map_err(|error| unavailable("audit response", &error))
    }

    /// The policy a stored document names, if the deployed project still
    /// declares it. A document whose policy is gone is shown to nobody.
    fn policy(&self, id: &str) -> Option<&DocumentPolicy> {
        let policy = self
            .project
            .document_policies
            .iter()
            .find(|(key, _)| key.as_str() == id)
            .map(|(_, policy)| policy);
        if policy.is_none() {
            tracing::warn!(
                policy = id,
                "a stored document names a policy the deployed project does not declare; access was denied"
            );
        }
        policy
    }

    async fn client(&self) -> Result<deadpool_postgres::Client, ProblemCode> {
        self.store
            .client()
            .await
            .map_err(|error| unavailable("database connection", &error))
    }

    async fn record_in<C: tokio_postgres::GenericClient>(
        client: &C,
        document_id: Uuid,
    ) -> Result<Option<Record>, ProblemCode> {
        client
            .query_opt(
                &format!(
                    "SELECT {RECORD_COLUMNS} FROM {RECORD_FROM} WHERE document.document_id = $1"
                ),
                &[&document_id],
            )
            .await
            .map_err(|error| unavailable("document read", &error))?
            .map(|row| {
                Record::from_row(&row).map_err(|error| unavailable("document decode", &error))
            })
            .transpose()
    }

    async fn record(&self, document_id: Uuid) -> Result<Option<Record>, ProblemCode> {
        let client = self.client().await?;
        Self::record_in(&**client, document_id).await
    }

    /// Whether `caller`, by issuer, subject, and actor kind, holds an
    /// active grant on `version_id`.
    async fn holds_grant(&self, caller: &Caller, version_id: Uuid) -> Result<bool, ProblemCode> {
        let client = self.client().await?;
        let row = client
            .query_one(
                "SELECT EXISTS (
                     SELECT 1 FROM documents_grants
                      WHERE version_id = $1 AND grantee_issuer = $2 AND grantee_subject = $3
                        AND grantee_kind = $4 AND revoked_at IS NULL AND expires_at > now())",
                &[
                    &version_id,
                    &caller.issuer,
                    &caller.subject,
                    &caller.kind.as_str(),
                ],
            )
            .await
            .map_err(|error| unavailable("grant read", &error))?;
        row.try_get(0)
            .map_err(|error| unavailable("grant decode", &error))
    }

    /// Decide what `caller` is to `record`.
    async fn access(&self, caller: &Caller, record: &Record) -> Result<Access, ProblemCode> {
        let Some(policy) = self.policy(&record.policy_id) else {
            return Ok(Access::default());
        };
        let standing = standing(policy, &record.custody, record.reserver(), caller);
        let released_by_grant = !standing.custodian
            && registry_documents_core::is_recipient(policy, caller)
            && record
                .releasable_digest(&self.settings.verifier_binding)
                .is_some()
            && self.holds_grant(caller, record.version_id).await?;
        Ok(Access {
            standing,
            released_by_grant,
        })
    }

    /// The view `access` shows of `record`. A version approved under
    /// another verifier binding, or whose approval names other content, is
    /// shown `suspended`: it is not releasable now.
    fn present(&self, record: &Record, access: Access) -> Result<DocumentView, ProblemCode> {
        let mut status = record.status;
        if status.is_releasable()
            && record
                .releasable_digest(&self.settings.verifier_binding)
                .is_none()
        {
            status = DocumentStatus::Suspended;
        }
        record
            .view(
                status,
                allowed_actions(access.standing, status, access.released_by_grant),
            )
            .map_err(|error| unavailable("document decode", &error))
    }

    /// The policies `caller` may place documents under, by id.
    #[must_use]
    pub fn placeable_policies(&self, caller: &Caller) -> DocumentPolicyList {
        let items = self
            .project
            .document_policies
            .iter()
            .filter(|(_, policy)| policy.custody_profiles.contains(&caller.profile_id))
            .map(|(id, policy)| {
                let restrictions = &policy.mandatory_restrictions;
                DocumentPolicyView {
                    id: id.clone(),
                    version: policy.version.clone(),
                    label: policy.label.as_str().to_owned(),
                    maximum_document_bytes: restrictions.maximum_document_bytes.get(),
                    allowed_content_types: restrictions.allowed_content_types.as_slice().to_vec(),
                    grant_expiry_hours: restrictions.grant_expiry_hours.get(),
                    maximum_grant_expiry_hours: restrictions.maximum_grant_expiry_hours.get(),
                }
            })
            .collect();
        DocumentPolicyList { items }
    }

    /// Reserve one document and the upload of its single version, under
    /// the idempotency key `key`. Custody, size, media type, and the
    /// custodian's quota are refused here, before any byte moves. The
    /// quota is counted and the reservation written under one lock per
    /// custodian and policy, so concurrent reservations cannot pass it
    /// together. A repeated key re-runs authorization and answers with the
    /// reservation the first request made.
    pub async fn reserve(
        &self,
        caller: &Caller,
        key: &str,
        request: &ReserveDocumentRequest,
    ) -> Result<ReservationView, ProblemCode> {
        let reference = self.actor_reference(caller)?;
        let audit = self
            .begin(
                UPLOAD_RESERVATION_EVENT,
                json!({
                    "event": UPLOAD_RESERVATION_EVENT,
                    "actor": reference,
                    "profile": caller.profile_id,
                    "policyId": checked(LocalId::new(request.policy_id.as_str()).ok()),
                    "length": request.length,
                    "mediaType": checked(ContentType::new(request.media_type.as_str()).ok()),
                }),
            )
            .await?;
        let result = self.reserve_inner(caller, key, request).await;
        let success = match &result {
            Ok(view) => json!({
                "event": UPLOAD_RESERVATION_EVENT,
                "outcome": "reserved",
                "documentId": view.document.id,
                "versionId": view.document.version.id,
            }),
            Err(_) => Value::Null,
        };
        Self::finish(audit, UPLOAD_RESERVATION_EVENT, &result, success).await?;
        result
    }

    async fn reserve_inner(
        &self,
        caller: &Caller,
        key: &str,
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
        let custody = place_custody(
            admitted.policy,
            caller,
            CustodyAsk {
                subject: request.custodian.subject.as_str(),
                issuing_institution: request.issuing_institution.as_ref().map(ExternalId::as_str),
            },
        )?;
        let binding = admitted
            .policy
            .binding(admitted.policy_id)
            .map_err(|error| unavailable("policy binding", &error))?;
        let grace = i32::try_from(
            admitted
                .policy
                .mandatory_restrictions
                .cleanup_grace_hours
                .get(),
        )
        .map_err(|error| unavailable("upload window", &error))?;
        let days = i32::try_from(self.settings.idempotency_days)
            .map_err(|error| unavailable("idempotency retention", &error))?;
        let length = i64::try_from(request.length).map_err(|_| ProblemCode::DocumentTooLarge)?;
        let key = key_digest(caller, RESERVE_OPERATION, key);
        let digest = request_digest(request)?;
        let mut client = self.client().await?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| unavailable("reservation transaction", &error))?;
        if let Replay::Repeat(document_id) = replay(&transaction, &key, &digest).await? {
            let record = Self::record_in(&*transaction, document_id)
                .await?
                .ok_or_else(|| {
                    unavailable("idempotency replay", &"the recorded document is missing")
                })?;
            transaction
                .commit()
                .await
                .map_err(|error| unavailable("reservation commit", &error))?;
            return self.reservation_view(caller, &record).await;
        }
        let lock = format!(
            "{}\n{}\n{}",
            custody.issuer,
            custody.subject,
            admitted.policy_id.as_str()
        );
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
                  WHERE document.custodian_issuer = $1 AND document.custodian_subject = $2
                    AND document.policy_id = $3 AND version.erasure_state <> 'erased'
                    AND (version.upload_state = 'finalized'
                         OR (version.upload_state = 'reserved'
                             AND version.upload_expires_at > transaction_timestamp()))",
                &[
                    &custody.issuer,
                    &custody.subject,
                    &admitted.policy_id.as_str(),
                ],
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
        let label = request.label.as_ref().map(|label| label.as_str());
        transaction
            .execute(
                "INSERT INTO documents_documents
                     (document_id, policy_id, policy_version, policy_digest, custodian_issuer,
                      custodian_subject, custodian_kind, represented_principal_subject, label,
                      created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, transaction_timestamp())",
                &[
                    &document_id,
                    &binding.id.as_str(),
                    &binding.version,
                    &binding.digest.as_str(),
                    &custody.issuer,
                    &custody.subject,
                    &custody.kind.as_str(),
                    &custody.represented_principal,
                    &label,
                ],
            )
            .await
            .map_err(|error| unavailable("document insert", &error))?;
        let institution = caller.institution.as_ref().map(ExternalId::as_str);
        transaction
            .execute(
                "INSERT INTO documents_versions
                     (version_id, document_id, upload_id, upload_state, verification_state,
                      eligibility, media_type, expected_digest, length, actor_issuer,
                      actor_subject, actor_kind, client_id, access_profile_id,
                      issuing_institution, reserved_at, upload_expires_at)
                 VALUES ($1, $2, $3, 'reserved', 'pending', 'suspended', $4, $5, $6, $7, $8,
                         $9, $10, $11, $12, transaction_timestamp(),
                         transaction_timestamp() + make_interval(hours => $13))",
                &[
                    &version_id,
                    &document_id,
                    &upload_id,
                    &admitted.media_type.as_str(),
                    &request.expected_digest.as_str(),
                    &length,
                    &caller.issuer,
                    &caller.subject,
                    &caller.kind.as_str(),
                    &caller.client_id,
                    &caller.profile_id.as_str(),
                    &institution,
                    &grace,
                ],
            )
            .await
            .map_err(|error| unavailable("version insert", &error))?;
        record_key(&transaction, &key, &digest, document_id, days).await?;
        let record = Self::record_in(&*transaction, document_id)
            .await?
            .ok_or_else(|| unavailable("reservation read", &"the reserved document is missing"))?;
        transaction
            .commit()
            .await
            .map_err(|error| unavailable("reservation commit", &error))?;
        self.reservation_view(caller, &record).await
    }

    async fn reservation_view(
        &self,
        caller: &Caller,
        record: &Record,
    ) -> Result<ReservationView, ProblemCode> {
        let access = self.access(caller, record).await?;
        Ok(ReservationView {
            document: self.present(record, access)?,
            upload_path: upload_path(record.upload_id),
            upload_expires_at: timestamp(record.upload_expires_at),
        })
    }

    /// Accept the content of a reserved upload. The body is hashed while it
    /// is read, under the transfer budget and deadline, and cut off at the
    /// reserved length plus one byte; content that differs from the
    /// reserved length or digest keeps nothing. The version is finalized in
    /// one transaction with its verification job. Content sent again to a
    /// finalized upload answers with the document when it is the same
    /// content and `upload.finalized` when it differs.
    pub async fn put_content<S, E>(
        &self,
        caller: &Caller,
        upload_id: Uuid,
        content_type: Option<&str>,
        content_length: Option<u64>,
        body: S,
    ) -> Result<UploadOutcome, ProblemCode>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
    {
        let reference = self.actor_reference(caller)?;
        let audit = self
            .begin(
                UPLOAD_CONTENT_EVENT,
                json!({
                    "event": UPLOAD_CONTENT_EVENT,
                    "actor": reference,
                    "uploadId": upload_id.to_string(),
                }),
            )
            .await?;
        let result = async {
            let reservation = self.reservation(caller, upload_id).await?;
            let outcome = self
                .accept_content(caller, &reservation, content_type, content_length, body)
                .await?;
            Ok((reservation.record, outcome))
        }
        .await;
        let success = match &result {
            Ok((record, UploadOutcome::Accepted(_))) => json!({
                "event": UPLOAD_CONTENT_EVENT,
                "outcome": "finalized",
                "versionId": record.version_id.to_string(),
                "byteCount": record.length,
            }),
            Ok((record, UploadOutcome::Repeated(_))) => json!({
                "event": UPLOAD_CONTENT_EVENT,
                "outcome": "already-finalized",
                "versionId": record.version_id.to_string(),
                "byteCount": 0,
            }),
            Err(_) => Value::Null,
        };
        Self::finish(audit, UPLOAD_CONTENT_EVENT, &result, success).await?;
        result.map(|(_, outcome)| outcome)
    }

    /// The reservation `caller` made under `upload_id`. An upload another
    /// principal reserved answers as one that does not exist.
    async fn reservation(
        &self,
        caller: &Caller,
        upload_id: Uuid,
    ) -> Result<Reservation, ProblemCode> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                &format!("SELECT {RECORD_COLUMNS} FROM {RECORD_FROM} WHERE version.upload_id = $1"),
                &[&upload_id],
            )
            .await
            .map_err(|error| unavailable("reservation read", &error))?
            .ok_or(ProblemCode::ResourceNotFound)?;
        let record =
            Record::from_row(&row).map_err(|error| unavailable("reservation decode", &error))?;
        if record.reserver_issuer != caller.issuer
            || record.reserver_subject != caller.subject
            || record.reserver_kind != caller.kind
        {
            return Err(ProblemCode::ResourceNotFound);
        }
        Ok(Reservation { record })
    }

    async fn accept_content<S, E>(
        &self,
        caller: &Caller,
        reservation: &Reservation,
        content_type: Option<&str>,
        content_length: Option<u64>,
        body: S,
    ) -> Result<UploadOutcome, ProblemCode>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
    {
        let record = &reservation.record;
        let finalized = record.upload == UploadState::Finalized;
        // A removed document takes no content: its reservation answers as
        // lapsed.
        if !finalized
            && (record.upload == UploadState::Expired
                || record.upload_lapsed
                || record.status.is_erasing())
        {
            return Err(ProblemCode::UploadExpired);
        }
        if content_type != Some(record.media_type.as_str()) {
            return Err(if finalized {
                ProblemCode::UploadFinalized
            } else {
                ProblemCode::UploadContentTypeMismatch
            });
        }
        match content_length {
            Some(length) if length > self.settings.ceiling => {
                return Err(ProblemCode::RequestBodyTooLarge)
            }
            Some(length) if length != record.length => {
                return Err(if finalized {
                    ProblemCode::UploadFinalized
                } else {
                    ProblemCode::UploadLengthMismatch
                })
            }
            _ => {}
        }
        let Some(_permit) = self.settings.budget.try_reserve(record.length) else {
            tracing::warn!("the transfer budget is spent; the upload was refused");
            return Err(ProblemCode::ServiceUnavailable);
        };
        let deadline = self.settings.deadline.for_length(record.length);
        let body = match tokio::time::timeout(deadline, read_hashing(body, record.length)).await {
            Ok(Ok(body)) => body,
            Ok(Err(BodyRefusal::Longer | BodyRefusal::Shorter)) => {
                return Err(if finalized {
                    ProblemCode::UploadFinalized
                } else {
                    ProblemCode::UploadLengthMismatch
                })
            }
            Ok(Err(BodyRefusal::Unreadable)) => return Err(ProblemCode::RequestInvalid),
            Err(_) => {
                tracing::warn!("an upload body did not arrive within its transfer deadline");
                return Err(ProblemCode::ServiceUnavailable);
            }
        };
        let digest = body.digest();
        if finalized {
            return if record.computed_digest.as_deref() == Some(digest.as_str()) {
                Ok(UploadOutcome::Repeated(
                    self.current_view(caller, record.document_id).await?,
                ))
            } else {
                Err(ProblemCode::UploadFinalized)
            };
        }
        if digest != record.expected_digest {
            return Err(ProblemCode::UploadDigestMismatch);
        }
        let sha256 = body.sha256_hex;
        let stored = match self.storage.as_ref() {
            ContentStorage::Database { .. } => Stored::Database(body.bytes),
            ContentStorage::S3 { .. } => {
                Stored::Object(self.stage_object(record, &sha256, body.bytes).await?)
            }
        };
        let accepted = self.finalize(record, &digest, stored).await?;
        let view = self.current_view(caller, record.document_id).await?;
        Ok(if accepted {
            UploadOutcome::Accepted(view)
        } else {
            UploadOutcome::Repeated(view)
        })
    }

    async fn current_view(
        &self,
        caller: &Caller,
        document_id: Uuid,
    ) -> Result<DocumentView, ProblemCode> {
        let record = self
            .record(document_id)
            .await?
            .ok_or_else(|| unavailable("document read", &"the document is missing"))?;
        let access = self.access(caller, &record).await?;
        self.present(&record, access)
    }

    /// Write the content to its own fresh object, after committing the
    /// staged row that names it, so an object a failed attempt leaves
    /// behind stays findable. The bytes are moved into the store, never
    /// copied.
    async fn stage_object(
        &self,
        record: &Record,
        sha256: &str,
        bytes: Vec<u8>,
    ) -> Result<Uuid, ProblemCode> {
        let object_id = Uuid::new_v4();
        let store = self
            .storage
            .object(object_id)
            .await
            .map_err(|error| unavailable("object storage", &error))?;
        let length =
            i64::try_from(record.length).map_err(|error| unavailable("object length", &error))?;
        {
            let client = self.client().await?;
            client
                .execute(
                    "INSERT INTO documents_staged_objects
                         (object_id, version_id, binding_digest, sha256, length, staged_at)
                     VALUES ($1, $2, $3, $4, $5, now())",
                    &[
                        &object_id,
                        &record.version_id,
                        &store.binding_digest(),
                        &sha256,
                        &length,
                    ],
                )
                .await
                .map_err(|error| unavailable("staged object insert", &error))?;
        }
        store
            .put(sha256, bytes)
            .await
            .map_err(|error| unavailable("object write", &error))?;
        Ok(object_id)
    }

    /// Finalize the version with its content. `Ok(false)` when a concurrent
    /// attempt finalized the same content first; that attempt's content is
    /// kept and this one's is not.
    async fn finalize(
        &self,
        record: &Record,
        digest: &str,
        stored: Stored,
    ) -> Result<bool, ProblemCode> {
        let version_id = record.version_id;
        let mut client = self.client().await?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| unavailable("finalize transaction", &error))?;
        let row = transaction
            .query_one(
                "SELECT upload_state, computed_digest,
                        upload_expires_at <= transaction_timestamp(), erasure_state <> 'none'
                   FROM documents_versions WHERE version_id = $1 FOR UPDATE",
                &[&version_id],
            )
            .await
            .map_err(|error| unavailable("finalize lock", &error))?;
        let read = |error: tokio_postgres::Error| unavailable("finalize decode", &error);
        let state: String = row.try_get(0).map_err(read)?;
        let computed: Option<String> = row.try_get(1).map_err(read)?;
        let lapsed: bool = row.try_get(2).map_err(read)?;
        let erasing: bool = row.try_get(3).map_err(read)?;
        match state.as_str() {
            "finalized" if computed.as_deref() == Some(digest) => return Ok(false),
            "finalized" => return Err(ProblemCode::UploadFinalized),
            "expired" => return Err(ProblemCode::UploadExpired),
            _ if lapsed || erasing => return Err(ProblemCode::UploadExpired),
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
        let object_id = match stored {
            Stored::Database(bytes) => {
                transaction
                    .execute(
                        "INSERT INTO documents_contents (version_id, content) VALUES ($1, $2)",
                        &[&version_id, &bytes],
                    )
                    .await
                    .map_err(|error| unavailable("content insert", &error))?;
                None
            }
            Stored::Object(object_id) => {
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
                Some(object_id)
            }
        };
        transaction
            .execute(
                "UPDATE documents_versions
                    SET upload_state = 'finalized', computed_digest = $2,
                        finalized_at = transaction_timestamp(), storage_backend = $3,
                        object_id = $4, verification_binding_digest = $5,
                        revision = revision + 1
                  WHERE version_id = $1",
                &[
                    &version_id,
                    &digest,
                    &self.storage.backend(),
                    &object_id,
                    &self.settings.verifier_binding,
                ],
            )
            .await
            .map_err(|error| unavailable("version finalize", &error))?;
        let key = JobKey::new(
            version_id,
            job_part(version_id, &self.settings.verifier_binding),
        )
        .map_err(|error| unavailable("verification job key", &error))?;
        enqueue(&transaction, &self.jobs, &key, None)
            .await
            .map_err(|error| unavailable("verification job enqueue", &error))?;
        transaction
            .commit()
            .await
            .map_err(|error| unavailable("finalize commit", &error))?;
        Ok(true)
    }

    /// The document `caller` may see: as its custodian, as the caller that
    /// reserved it, or as the holder of a grant that releases its version
    /// now. Every other caller is answered as if it did not exist.
    pub async fn read(
        &self,
        caller: &Caller,
        document_id: Uuid,
    ) -> Result<DocumentView, ProblemCode> {
        let record = self
            .record(document_id)
            .await?
            .ok_or(ProblemCode::ResourceNotFound)?;
        let access = self.access(caller, &record).await?;
        if !access.sees() {
            return Err(ProblemCode::ResourceNotFound);
        }
        self.present(&record, access)
    }

    /// The documents `caller` holds in custody or reserved, oldest first.
    pub async fn list(
        &self,
        caller: &Caller,
        page: &PageRequest,
    ) -> Result<DocumentPage, ProblemCode> {
        let (after, after_id) = Cursor::bounds(page.cursor);
        let rows = {
            let client = self.client().await?;
            client
                .query(
                    &format!(
                        "SELECT {RECORD_COLUMNS} FROM {RECORD_FROM}
                          WHERE ((document.custodian_issuer = $1 AND document.custodian_subject = $2
                                  AND document.custodian_kind = $3)
                                 OR (version.actor_issuer = $1 AND version.actor_subject = $2
                                     AND version.actor_kind = $3))
                            AND ($4::timestamptz IS NULL
                                 OR (document.created_at, document.document_id) > ($4, $5))
                          ORDER BY document.created_at, document.document_id
                          LIMIT $6"
                    ),
                    &[
                        &caller.issuer,
                        &caller.subject,
                        &caller.kind.as_str(),
                        &after,
                        &after_id,
                        &page.fetch(),
                    ],
                )
                .await
                .map_err(|error| unavailable("document list", &error))?
        };
        let records = rows
            .iter()
            .map(Record::from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| unavailable("document decode", &error))?;
        let next_cursor = next_cursor(&records, page.limit, Record::cursor);
        let mut items = Vec::new();
        for record in records.iter().take(page.limit as usize) {
            let access = self.access(caller, record).await?;
            if access.standing.sees() {
                items.push(self.present(record, access)?);
            }
        }
        Ok(DocumentPage { items, next_cursor })
    }

    /// Release the exact content of one version: to its custodian, or to
    /// the holder of an active grant on that exact version whose profile is
    /// one of the policy's recipient profiles. Only a `ready` version whose
    /// approval is bound to its digest, its media type, and the current
    /// verifier binding is released, and its bytes are checked against the
    /// digest and length before the first byte is handed back. Every
    /// decision is audited. A caller that sees the document without being
    /// released its content, the owning system that is not its custodian,
    /// is answered `profile.not-authorized`; every other caller that may not
    /// have the content is answered as if the version did not exist, and the
    /// audit record carries only that answer.
    pub async fn download(
        &self,
        caller: &Caller,
        document_id: Uuid,
        version_id: Uuid,
    ) -> Result<ReleasedContent, ProblemCode> {
        let started = Instant::now();
        let reference = self.actor_reference(caller)?;
        let audit = self
            .begin(
                CONTENT_DOWNLOAD_EVENT,
                json!({
                    "event": CONTENT_DOWNLOAD_EVENT,
                    "actor": reference,
                    "documentId": document_id.to_string(),
                    "versionId": version_id.to_string(),
                }),
            )
            .await?;
        let result = self.release(caller, document_id, version_id).await;
        let (record, result) = match result {
            Ok((bytes, permit, media_type)) => {
                let length = bytes.len() as u64;
                let deadline = self
                    .settings
                    .deadline
                    .for_length(length)
                    .saturating_sub(started.elapsed());
                (
                    json!({
                        "event": CONTENT_DOWNLOAD_EVENT,
                        "outcome": "released",
                        "byteCount": length,
                    }),
                    Ok((bytes, permit, media_type, deadline)),
                )
            }
            Err(Release::Refused(problem)) => (
                json!({
                    "event": CONTENT_DOWNLOAD_EVENT,
                    "outcome": "refused",
                    "code": problem.code(),
                }),
                Err(problem),
            ),
            Err(Release::Integrity) => (
                json!({
                    "event": CONTENT_DOWNLOAD_EVENT,
                    "outcome": "storage-integrity",
                    "byteCount": 0,
                }),
                Err(ProblemCode::ServiceUnavailable),
            ),
        };
        audit
            .finish(record)
            .await
            .map_err(|error| unavailable("audit response", &error))?;
        let (bytes, permit, media_type, deadline) = result?;
        Ok(ReleasedContent {
            media_type,
            length: bytes.len() as u64,
            body: ReleaseBody::new(bytes, permit, deadline),
        })
    }

    async fn release(
        &self,
        caller: &Caller,
        document_id: Uuid,
        version_id: Uuid,
    ) -> Result<(Vec<u8>, crate::transfer::TransferPermit, String), Release> {
        let record = self
            .record(document_id)
            .await?
            .filter(|record| record.version_id == version_id)
            .ok_or(ProblemCode::ResourceNotFound)?;
        let access = self.access(caller, &record).await?;
        let digest = match record.releasable_digest(&self.settings.verifier_binding) {
            Some(digest) if access.standing.custodian || access.released_by_grant => digest,
            None if access.standing.custodian => {
                return Err(ProblemCode::DocumentVersionNotReleasable.into())
            }
            // The owning system sees the document but is never released it.
            _ if access.standing.sees() => return Err(ProblemCode::ProfileNotAuthorized.into()),
            _ => return Err(ProblemCode::ResourceNotFound.into()),
        };
        let Some(permit) = self.settings.budget.try_reserve(record.length) else {
            tracing::warn!("the transfer budget is spent; the download was refused");
            return Err(ProblemCode::ServiceUnavailable.into());
        };
        match self
            .storage
            .read(
                &self.store,
                version_id,
                record.object_id,
                digest,
                record.length,
            )
            .await
        {
            Ok(bytes) => Ok((bytes, permit, record.media_type.clone())),
            Err(error) => {
                tracing::error!(
                    version = %version_id,
                    error = %error,
                    "stored content failed its integrity check; nothing was released"
                );
                Err(Release::Integrity)
            }
        }
    }
}

/// Why a release did not happen.
enum Release {
    Refused(ProblemCode),
    /// The stored content failed its integrity check.
    Integrity,
}

impl From<ProblemCode> for Release {
    fn from(problem: ProblemCode) -> Self {
        Self::Refused(problem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_upload_path_names_the_upload() {
        let id = Uuid::nil();
        assert_eq!(
            upload_path(id),
            "/uploads/00000000-0000-0000-0000-000000000000/content"
        );
    }

    #[test]
    fn a_cursor_survives_its_own_encoding_and_nothing_else_decodes() {
        let cursor = Cursor {
            at: DateTime::from_timestamp_micros(1_790_000_000_123_456).unwrap(),
            id: Uuid::new_v4(),
        };
        assert_eq!(Cursor::decode(&cursor.encode()), Some(cursor));
        for refused in [
            "",
            "zz",
            "00",
            &hex::encode("12:not-a-uuid"),
            &"a".repeat(300),
        ] {
            assert_eq!(Cursor::decode(refused), None, "{refused}");
        }
    }

    #[test]
    fn a_page_size_is_one_to_the_hard_cap() {
        assert_eq!(PageRequest::parse(None, None).unwrap().limit, 50);
        assert_eq!(PageRequest::parse(None, Some("100")).unwrap().limit, 100);
        for refused in ["0", "101", "-1", "ten"] {
            assert_eq!(
                PageRequest::parse(None, Some(refused)).unwrap_err(),
                ProblemCode::RequestInvalid
            );
        }
        assert_eq!(
            PageRequest::parse(Some("not-a-cursor"), None).unwrap_err(),
            ProblemCode::RequestInvalid
        );
    }

    #[test]
    fn the_next_cursor_is_set_only_when_a_further_row_exists() {
        let rows = [1_i64, 2, 3];
        let at = |n: &i64| Cursor {
            at: DateTime::from_timestamp_micros(*n).unwrap(),
            id: Uuid::nil(),
        };
        assert_eq!(next_cursor(&rows, 3, at), None);
        assert_eq!(next_cursor(&rows, 2, at), Some(at(&2).encode()));
    }

    fn caller(subject: &str) -> Caller {
        Caller {
            issuer: "https://identity.example.test".to_owned(),
            subject: subject.to_owned(),
            kind: ActorKind::Service,
            client_id: "civil-registry-app".to_owned(),
            profile_id: LocalId::new("custodian-app").unwrap(),
            role: registry_documents_core::AccessRole::Custodian,
            institution: None,
        }
    }

    #[test]
    fn an_idempotency_key_is_scoped_to_the_principal_and_the_operation() {
        let key = key_digest(&caller("app"), RESERVE_OPERATION, "k-1");
        assert_eq!(key, key_digest(&caller("app"), RESERVE_OPERATION, "k-1"));
        assert_ne!(key, key_digest(&caller("other"), RESERVE_OPERATION, "k-1"));
        assert_ne!(key, key_digest(&caller("app"), "document.grant", "k-1"));
        assert_ne!(key, key_digest(&caller("app"), RESERVE_OPERATION, "k-2"));
        // The parts are separated, so moving a byte between them changes it.
        assert_ne!(
            key_digest(&caller("ap"), RESERVE_OPERATION, "pk-1"),
            key_digest(&caller("app"), RESERVE_OPERATION, "k-1")
        );
    }
}

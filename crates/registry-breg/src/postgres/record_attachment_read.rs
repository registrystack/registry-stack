// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::api::HeldRecordAttachment;
use crate::attachment_storage::AttachmentStorage;

impl PostgresRecordReadService {
    /// Release one record slot's file to a profile whose `get` authority sees
    /// the record and whose grant names the slot. The record's visibility,
    /// the slot reference and the bytes are read in one RLS-bound snapshot,
    /// under the content-hash lock that deletion also takes.
    pub(super) async fn read_record_attachment(
        &self,
        mut request: RecordReadRequest,
        slot_id: String,
    ) -> Result<Option<HeldRecordAttachment>, ReadServiceError> {
        if !profile_is_keyed(self.audit.profile()) {
            return Err(ReadServiceError::Unavailable);
        }
        let plan = ReadPlan::from_request(&self.registry, &self.expected, &self.cursors, &request)
            .map_err(|_| ReadServiceError::Unavailable)?;
        let granted = plan
            .entity
            .access_profiles
            .get(request.context.selected_profile())
            .is_some_and(|profile| profile.readable_attachments.contains(&slot_id));
        if plan.operation != Operation::Get
            || plan.read_path.is_some()
            || !plan.entity.attachments.contains_key(&slot_id)
            || !granted
            || !request.selected_fields.is_empty()
        {
            return Err(ReadServiceError::Unavailable);
        }
        let record_id = match &request.kind {
            RecordReadKind::Get { id } if valid_canonical_uuid(id) => id.clone(),
            _ => return Err(ReadServiceError::Unavailable),
        };
        let record_uuid = Uuid::parse_str(&record_id).map_err(|_| ReadServiceError::Unavailable)?;
        let claims = strict_claim_context(&self.registry, &request.context, &request.entity_id)?;
        if claims.principal().is_none() {
            return Err(ReadServiceError::Unavailable);
        }
        // A distinct operation identity keeps the operational audit truthful:
        // this endpoint releases file bytes and does not read the record body.
        // The slot is configuration, not a value, so the identity names it.
        request.operation_id.push_str(":attachment:");
        request.operation_id.push_str(&slot_id);
        let _attempt = begin_pre_io_audit(
            &self.audit,
            &self.expected,
            &claims,
            PreIoAudit {
                kind: PreIoAuditKind::Attempt,
                method: request.method,
                operation_id: &request.operation_id,
                target_record: Some(&record_id),
                refusal_reason: None,
                correlation: &request.correlation,
            },
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        // A read abandoned at its deadline stops its statement and gives up
        // the session rather than leaving the backend running.
        let mut session = QueryCancellationGuard::new(self.pool.clone(), client);
        let read = async {
            let transaction = begin_record_transaction(
                session.client(),
                self.lock_key,
                self.lock_timeout,
                &self.expected,
                &claims,
            )
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
            #[cfg(feature = "postgres-test")]
            self.outrun_request_deadline_for_test(transaction.transaction())
                .await?;
            install_evaluation_date(transaction.transaction(), &self.registry, None).await?;
            // The record's own GET source relation answers visibility, so row
            // boundaries, consent and lifecycle apply exactly as on GET.
            let relations = ReadRelations::collection(&plan.entity, None, &[])?;
            let visible = transaction
                .transaction()
                .query_typed(
                    &format!(
                        "SELECT 1 FROM {} WHERE {} = $1::text::uuid LIMIT 1",
                        relations.from_sql, relations.id_expression
                    ),
                    &[(&record_id, Type::TEXT)],
                )
                .await
                .map_err(|_| ReadServiceError::Unavailable)?;
            if visible.is_empty() {
                transaction
                    .commit()
                    .await
                    .map_err(|_| ReadServiceError::Unavailable)?;
                return Ok(None);
            }
            let Some(stored) = crate::attachment_store::load_record_attachment(
                transaction.transaction(),
                &plan.entity.id,
                record_uuid,
                &slot_id,
            )
            .await
            .map_err(|_| ReadServiceError::Unavailable)?
            else {
                transaction
                    .commit()
                    .await
                    .map_err(|_| ReadServiceError::Unavailable)?;
                return Ok(None);
            };
            // External bytes are fetched while the hash lock is held, so
            // deletion cannot remove them between the reference and the read.
            let bytes = self.stored_record_attachment_bytes(&stored).await?;
            if u64::try_from(bytes.len()).ok() != Some(stored.byte_size)
                || crate::attachment_store::content_hash(&bytes) != stored.sha256
            {
                tracing::error!("a record attachment's stored bytes do not match its digest");
                return Err(ReadServiceError::Unavailable);
            }
            let held = HeldRecordAttachment {
                response: HeldReadResponse::from_attachment(bytes, stored.content_type)?,
                sha256: stored.sha256,
            };
            crate::subject_access_log::record_reads(
                transaction.transaction(),
                self.read_alerts.as_ref(),
                &plan.entity,
                &request.entity_id,
                &request.context,
                std::slice::from_ref(&record_id),
                &request.operation_id,
                &self.expected,
                &request.correlation,
                &self.audit,
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| ReadServiceError::Unavailable)?;
            Ok::<_, ReadServiceError>(Some(held))
        }
        .await;
        session.disarm();
        let read = match read {
            Ok(read) => read,
            Err(error) => return Err(self.refused_read(&request, &claims, &plan, error).await),
        };
        let Some(held) = read else {
            self.record_read_terminal_audit(
                &request,
                self.terminal(
                    &request,
                    &claims,
                    &plan,
                    TerminalAuditOutcome::Refused,
                    0,
                    None,
                )?,
            )
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
            return Ok(None);
        };
        self.fault.fail_at(ReadFaultPoint::BeforeTerminalAudit)?;
        self.record_read_terminal_audit(
            &request,
            self.terminal(
                &request,
                &claims,
                &plan,
                TerminalAuditOutcome::Returned,
                1,
                None,
            )?,
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
        Ok(Some(held))
    }

    /// Bytes from the storage binding the reference was written under. A
    /// changed binding cannot read content another binding retains.
    async fn stored_record_attachment_bytes(
        &self,
        stored: &crate::attachment_store::StoredRecordAttachment,
    ) -> Result<Vec<u8>, ReadServiceError> {
        if stored.backend_id != self.attachment_storage.binding_digest() {
            tracing::error!("a record attachment is retained under another storage binding");
            return Err(ReadServiceError::Unavailable);
        }
        match &self.attachment_storage {
            AttachmentStorage::Database => {
                stored.content.clone().ok_or(ReadServiceError::Unavailable)
            }
            AttachmentStorage::S3(store) => store
                .get(&stored.sha256, stored.byte_size)
                .await
                .map_err(|_| ReadServiceError::Unavailable),
        }
    }
}

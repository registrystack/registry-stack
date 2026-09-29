// SPDX-License-Identifier: Apache-2.0

use super::*;

impl PostgresRecordReadService {
    pub(super) async fn read_access_log(
        &self,
        mut request: RecordReadRequest,
        cursor: Option<String>,
        limit: u16,
    ) -> Result<Option<HeldReadResponse>, ReadServiceError> {
        if !profile_is_keyed(self.audit.profile()) || !(1..=100).contains(&limit) {
            return Err(ReadServiceError::Unavailable);
        }
        let plan = ReadPlan::from_request(&self.registry, &self.expected, &self.cursors, &request)
            .map_err(|_| ReadServiceError::Unavailable)?;
        let policy = plan
            .entity
            .access_log
            .as_ref()
            .ok_or(ReadServiceError::Unavailable)?;
        let record_id = match &request.kind {
            RecordReadKind::Get { id } if valid_canonical_uuid(id) => id.clone(),
            _ => return Err(ReadServiceError::Unavailable),
        };
        if cursor
            .as_deref()
            .is_some_and(|value| !valid_canonical_uuid(value))
        {
            return Err(ReadServiceError::CursorInvalid);
        }
        let claims = strict_claim_context(&self.registry, &request.context, &request.entity_id)?;
        let principal = claims.principal().ok_or(ReadServiceError::Unavailable)?;
        // A distinct operation identity keeps the operational audit truthful:
        // this endpoint reads access metadata and does not read the record body.
        request.operation_id.push_str(":access-log");
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
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        let transaction = begin_record_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            &claims,
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
        crate::mutation::install_request_visibility_context(
            transaction.transaction(),
            &plan.entity,
            &claims,
            self.audit.profile(),
            &self.expected.database_id,
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
        let subject_field = plan
            .entity
            .fields
            .get(&policy.subject_field)
            .ok_or(ReadServiceError::Unavailable)?;
        // GET RLS and the stored subject binding are checked in the same SQL
        // snapshot as the log page. An officer with registry-wide GET cannot
        // read somebody else's history, even during a change of record owner.
        // The outer join distinguishes an owned empty log from an unseen row.
        let sql = format!("SELECT entry.event_id::text,
                to_char(accessed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                requester, service_client, purpose, operation_id,
                to_char(visible_after AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                exemption_reason
            FROM (SELECT record_id FROM registry_data.{}
                  WHERE record_id = $2::text::uuid AND {} = $5
                    AND record_lifecycle = 'active' LIMIT 1) AS owned
            LEFT JOIN LATERAL (
            SELECT * FROM registry_internal.registry_subject_access_log AS entry
            WHERE entity_id = $1 AND record_id = owned.record_id
              AND visible_after <= transaction_timestamp() AND expires_at > transaction_timestamp()
              AND ($3::text IS NULL OR (accessed_at, event_id) < (
                SELECT accessed_at, event_id FROM registry_internal.registry_subject_access_log
                WHERE event_id = $3::text::uuid AND entity_id = $1 AND record_id = $2::text::uuid
                  AND visible_after <= transaction_timestamp() AND expires_at > transaction_timestamp()))
            ORDER BY accessed_at DESC, event_id DESC LIMIT $4
            ) AS entry ON TRUE
            ORDER BY accessed_at DESC, entry.event_id DESC",
            quote_identifier(&plan.entity.physical_table), quote_identifier(&subject_field.physical_name));
        let maximum = i64::from(limit) + 1;
        let rows = transaction
            .transaction()
            .query_typed(
                &sql,
                &[
                    (&plan.entity.id, Type::TEXT),
                    (&record_id, Type::TEXT),
                    (&cursor, Type::TEXT),
                    (&maximum, Type::INT8),
                    (&principal, Type::TEXT),
                ],
            )
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        if rows.is_empty() {
            transaction
                .commit()
                .await
                .map_err(|_| ReadServiceError::Unavailable)?;
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
        }
        let rows = rows
            .iter()
            .filter(|row| row.get::<_, Option<String>>(0).is_some())
            .collect::<Vec<_>>();
        let has_more = rows.len() > usize::from(limit);
        let events = rows.iter().take(usize::from(limit)).map(|row| {
            json!({"id":row.get::<_,String>(0), "accessedAt":row.get::<_,String>(1),
                "requester":row.get::<_,String>(2), "serviceClient":row.get::<_,Option<String>>(3),
                "purpose":row.get::<_,Option<String>>(4), "operationId":row.get::<_,String>(5),
                "visibleAfter":row.get::<_,String>(6), "exemptionReason":row.get::<_,Option<String>>(7)})
        }).collect::<Vec<_>>();
        let next_cursor = has_more.then(|| events.last().expect("nonempty page")["id"].clone());
        let held = HeldReadResponse::from_json(&json!({"events":events,"nextCursor":next_cursor}))?;
        transaction
            .commit()
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        self.fault.fail_at(ReadFaultPoint::BeforeTerminalAudit)?;
        self.record_read_terminal_audit(
            &request,
            self.terminal(
                &request,
                &claims,
                &plan,
                TerminalAuditOutcome::Returned,
                events.len(),
                None,
            )?,
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
        Ok(Some(held))
    }
}

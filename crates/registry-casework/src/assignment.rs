// SPDX-License-Identifier: Apache-2.0
use crate::{CaseworkService, PostgresStore, ServiceError, StoreError};
use chrono::{TimeDelta, Utc};
use registry_casework_core::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use tokio_postgres::Transaction;
use uuid::Uuid;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AbsenceDeleteReplay {
    revision: i64,
    person: IssuerPrincipal,
    cover: IssuerPrincipal,
}
impl PostgresStore {
    pub async fn directory_targets(
        &self,
        actor: &ActorContext,
        purpose: DirectoryTargetPurpose,
        queue: Option<&str>,
        person: Option<&IssuerPrincipal>,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<DirectoryTargetPage, StoreError> {
        let valid_shape = match purpose {
            DirectoryTargetPurpose::Assignment => {
                queue.is_some_and(|queue| !queue.is_empty()) && person.is_none()
            }
            DirectoryTargetPurpose::AbsencePerson => queue.is_none() && person.is_none(),
            DirectoryTargetPurpose::AbsenceCover => {
                queue.is_none()
                    && person.is_some_and(|person| {
                        valid_directory_principals(std::slice::from_ref(person))
                    })
            }
        };
        if !valid_shape {
            return Err(StoreError::Invalid);
        }
        let context_hash = assignment_hash(&(purpose, queue, person))?;
        let desired = limit.clamp(1, 100);
        let query_limit = i64::try_from(desired + 1).map_err(|_| StoreError::Invalid)?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;

        // Every directory mutation takes this row for update before changing
        // memberships. Holding a share lock makes the authority check, page,
        // and any issued cursor one current directory snapshot.
        transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR SHARE",
                &[],
            )
            .await?;
        let after = if let Some(cursor) = cursor {
            let cursor_id = Uuid::parse_str(cursor).map_err(|_| StoreError::CursorInvalid)?;
            let row = transaction
                .query_opt(
                    "SELECT issuer,subject,profile_id,context_hash,last_issuer,last_subject,expires_at FROM casework_directory_target_cursors WHERE cursor_id=$1 FOR UPDATE",
                    &[&cursor_id],
                )
                .await?
                .ok_or(StoreError::CursorInvalid)?;
            if row.get::<_, String>(0) != actor.principal.issuer
                || row.get::<_, String>(1) != actor.principal.subject
                || row.get::<_, String>(2) != actor.profile_id
                || row.get::<_, String>(3) != context_hash
            {
                return Err(StoreError::CursorInvalid);
            }
            if row.get::<_, chrono::DateTime<Utc>>(6) <= Utc::now() {
                return Err(StoreError::CursorExpired);
            }
            (row.get::<_, String>(4), row.get::<_, String>(5))
        } else {
            (String::new(), String::new())
        };

        let rows = match purpose {
            DirectoryTargetPurpose::Assignment => {
                let queue = queue.ok_or(StoreError::Invalid)?;
                let authorized = match actor.role {
                    CaseworkRole::Staff => {
                        is_staff_for_queue(&transaction, &actor.principal, queue).await?
                    }
                    CaseworkRole::Supervisor => {
                        can_assign_queue(&transaction, actor, queue).await?
                    }
                    CaseworkRole::Administrator | CaseworkRole::Requester => false,
                };
                if !authorized {
                    return Err(StoreError::Forbidden);
                }
                transaction
                    .query(
                        "SELECT m.issuer,m.subject,m.display_name FROM casework_queue_service q JOIN casework_memberships m ON m.team_id=q.team_id WHERE q.queue_id=$1 AND m.membership_kind='staff' AND (m.issuer,m.subject)>($2,$3) ORDER BY m.issuer,m.subject LIMIT $4",
                        &[&queue, &after.0, &after.1, &query_limit],
                    )
                    .await?
            }
            DirectoryTargetPurpose::AbsencePerson => match actor.role {
                CaseworkRole::Staff => {
                    transaction
                        .query(
                            "SELECT m.issuer,m.subject,min(m.display_name) FROM casework_memberships m WHERE m.issuer=$1 AND m.subject=$2 AND m.membership_kind='staff' AND (m.issuer,m.subject)>($3,$4) GROUP BY m.issuer,m.subject ORDER BY m.issuer,m.subject LIMIT $5",
                            &[&actor.principal.issuer, &actor.principal.subject, &after.0, &after.1, &query_limit],
                        )
                        .await?
                }
                CaseworkRole::Supervisor => {
                    transaction
                        .query(
                            "SELECT person.issuer,person.subject,min(person.display_name) FROM casework_memberships person JOIN casework_memberships lead ON lead.team_id=person.team_id WHERE person.membership_kind='staff' AND lead.issuer=$1 AND lead.subject=$2 AND lead.membership_kind='supervisor' AND (person.issuer,person.subject)>($3,$4) GROUP BY person.issuer,person.subject ORDER BY person.issuer,person.subject LIMIT $5",
                            &[&actor.principal.issuer, &actor.principal.subject, &after.0, &after.1, &query_limit],
                        )
                        .await?
                }
                CaseworkRole::Administrator => {
                    transaction
                        .query(
                            "SELECT m.issuer,m.subject,min(m.display_name) FROM casework_memberships m WHERE m.membership_kind='staff' AND (m.issuer,m.subject)>($1,$2) GROUP BY m.issuer,m.subject ORDER BY m.issuer,m.subject LIMIT $3",
                            &[&after.0, &after.1, &query_limit],
                        )
                        .await?
                }
                CaseworkRole::Requester => return Err(StoreError::Forbidden),
            },
            DirectoryTargetPurpose::AbsenceCover => {
                let person = person.ok_or(StoreError::Invalid)?;
                if !can_manage_person(&transaction, actor, person).await? {
                    return Err(StoreError::Forbidden);
                }
                if actor.role == CaseworkRole::Supervisor {
                    // A supervisor covers only inside the teams they lead, so a
                    // second team the absent person belongs to stays unseen.
                    transaction
                        .query(
                            "SELECT cover.issuer,cover.subject,min(cover.display_name) FROM casework_memberships person JOIN casework_memberships cover ON cover.team_id=person.team_id JOIN casework_memberships lead ON lead.team_id=cover.team_id WHERE person.issuer=$1 AND person.subject=$2 AND person.membership_kind='staff' AND cover.membership_kind='staff' AND lead.issuer=$3 AND lead.subject=$4 AND lead.membership_kind='supervisor' AND (cover.issuer,cover.subject)<>($1,$2) AND (cover.issuer,cover.subject)>($5,$6) GROUP BY cover.issuer,cover.subject ORDER BY cover.issuer,cover.subject LIMIT $7",
                            &[&person.issuer, &person.subject, &actor.principal.issuer, &actor.principal.subject, &after.0, &after.1, &query_limit],
                        )
                        .await?
                } else {
                    transaction
                        .query(
                            "SELECT cover.issuer,cover.subject,min(cover.display_name) FROM casework_memberships person JOIN casework_memberships cover ON cover.team_id=person.team_id WHERE person.issuer=$1 AND person.subject=$2 AND person.membership_kind='staff' AND cover.membership_kind='staff' AND (cover.issuer,cover.subject)<>($1,$2) AND (cover.issuer,cover.subject)>($3,$4) GROUP BY cover.issuer,cover.subject ORDER BY cover.issuer,cover.subject LIMIT $5",
                            &[&person.issuer, &person.subject, &after.0, &after.1, &query_limit],
                        )
                        .await?
                }
            }
        };
        let more = rows.len() > desired;
        let items = rows
            .into_iter()
            .take(desired)
            .map(|row| DirectoryMember {
                issuer: row.get(0),
                subject: row.get(1),
                display_name: row.get(2),
            })
            .collect::<Vec<_>>();
        let next_cursor = if more {
            let last = items.last().ok_or(StoreError::Corrupt)?;
            let cursor_id = Uuid::new_v4();
            let expires_at = Utc::now() + TimeDelta::minutes(15);
            transaction
                .execute(
                    "INSERT INTO casework_directory_target_cursors(cursor_id,issuer,subject,profile_id,context_hash,last_issuer,last_subject,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
                    &[&cursor_id, &actor.principal.issuer, &actor.principal.subject, &actor.profile_id, &context_hash, &last.issuer, &last.subject, &expires_at],
                )
                .await?;
            Some(cursor_id.to_string())
        } else {
            None
        };
        transaction.commit().await?;
        Ok(Page {
            items,
            next_cursor,
            status: PageStatus::Complete,
        })
    }
    pub async fn erase_expired_directory_target_cursors(&self) -> Result<usize, StoreError> {
        let client = self.client().await?;
        let affected = client
            .execute(
                "WITH due AS (SELECT cursor_id FROM casework_directory_target_cursors WHERE expires_at<=now() ORDER BY expires_at,cursor_id LIMIT 100 FOR UPDATE SKIP LOCKED) DELETE FROM casework_directory_target_cursors c USING due WHERE c.cursor_id=due.cursor_id",
                &[],
            )
            .await?;
        usize::try_from(affected).map_err(|_| StoreError::Corrupt)
    }
    pub async fn update_directory_team(
        &self,
        actor: &ActorContext,
        expected_directory_revision: i64,
        team_id: &str,
        request: &DirectoryTeamUpdateRequest,
        idempotency_key: &str,
    ) -> Result<i64, StoreError> {
        if actor.role != CaseworkRole::Administrator {
            return Err(StoreError::Forbidden);
        }
        validate_reason(
            idempotency_key,
            MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES,
            false,
        )?;
        let operation = "directory.team.update";
        let request_hash = assignment_hash(&(expected_directory_revision, team_id, request))?;
        let mut audit = self
            .begin_audit(crate::audit::request_record(
                "team-updated",
                Some(actor),
                &actor.profile_id,
                json!({"teamId": team_id}),
            ))
            .await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        lock_assignment_key(&transaction, actor, operation, team_id, idempotency_key).await?;
        if let Some(response) = assignment_replay(
            &transaction,
            actor,
            operation,
            team_id,
            idempotency_key,
            &request_hash,
        )
        .await?
        {
            let revision = response
                .get("revision")
                .and_then(Value::as_i64)
                .ok_or(StoreError::Corrupt)?;
            audit.record_outcome(crate::audit::AuditOutcome::Replayed);
            audit.commit(transaction).await?;
            return Ok(revision);
        }
        let actual: i64 = transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR UPDATE",
                &[],
            )
            .await?
            .get(0);
        if actual != expected_directory_revision {
            return Err(StoreError::Conflict);
        }
        if transaction
            .query_opt(
                "SELECT queue_id FROM casework_queue_service WHERE queue_id=ANY($1) AND team_id<>$2 ORDER BY queue_id LIMIT 1 FOR UPDATE",
                &[&request.served_queues, &team_id],
            )
            .await?
            .is_some()
        {
            return Err(StoreError::Conflict);
        }
        let next = actual.checked_add(1).ok_or(StoreError::Corrupt)?;
        transaction
            .execute(
                "INSERT INTO casework_teams(team_id,revision) VALUES($1,$2) ON CONFLICT(team_id) DO UPDATE SET revision=EXCLUDED.revision",
                &[&team_id, &next],
            )
            .await?;
        transaction
            .execute(
                "DELETE FROM casework_memberships WHERE team_id=$1",
                &[&team_id],
            )
            .await?;
        for person in &request.staff {
            transaction.execute("INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind,display_name) VALUES($1,$2,$3,'staff',$4)", &[&team_id,&person.issuer,&person.subject,&person.display_name]).await?;
        }
        for person in &request.supervisors {
            transaction.execute("INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind,display_name) VALUES($1,$2,$3,'supervisor',$4)", &[&team_id,&person.issuer,&person.subject,&person.display_name]).await?;
        }
        transaction
            .execute(
                "DELETE FROM casework_queue_service WHERE team_id=$1",
                &[&team_id],
            )
            .await?;
        for queue in &request.served_queues {
            transaction.execute("INSERT INTO casework_queue_service(queue_id,team_id,revision) VALUES($1,$2,$3)", &[queue,&team_id,&next]).await?;
        }
        transaction
            .execute(
                "UPDATE casework_meta SET directory_revision=$1 WHERE singleton=true",
                &[&next],
            )
            .await?;
        crate::store::directory_snapshot(&transaction, next).await?;
        append_directory_assignment_event(
            &transaction,
            &mut audit,
            actor,
            next,
            "team-updated",
            json!({
                "teamId": team_id,
                "staffCount": request.staff.len(),
                "supervisorCount": request.supervisors.len(),
                "servedQueues": request.served_queues,
            }),
        )
        .await?;
        insert_assignment_replay(
            &transaction,
            actor,
            operation,
            team_id,
            idempotency_key,
            &request_hash,
            &json!({"revision":next}),
        )
        .await?;
        audit.commit(transaction).await?;
        Ok(next)
    }
    pub(crate) async fn absences_page(
        &self,
        actor: &ActorContext,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<AbsenceList, StoreError> {
        if !matches!(
            actor.role,
            CaseworkRole::Staff | CaseworkRole::Supervisor | CaseworkRole::Administrator
        ) {
            return Err(StoreError::Forbidden);
        }
        if !(1..=1_000).contains(&limit) {
            return Err(StoreError::Invalid);
        }
        let context_hash = assignment_hash(&(role_name(actor.role), limit))?;
        let query_limit = i64::try_from(limit + 1).map_err(|_| StoreError::Invalid)?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let directory_revision: i64 = transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR SHARE",
                &[],
            )
            .await?
            .get(0);
        let after: Option<(chrono::DateTime<Utc>, Uuid)> = if let Some(cursor) = cursor {
            let cursor_id = Uuid::parse_str(cursor).map_err(|_| StoreError::CursorInvalid)?;
            let row = transaction
                .query_opt(
                    "SELECT issuer,subject,profile_id,context_hash,directory_revision,last_starts_at,last_absence_id,expires_at FROM casework_absence_cursors WHERE cursor_id=$1 FOR UPDATE",
                    &[&cursor_id],
                )
                .await?
                .ok_or(StoreError::CursorInvalid)?;
            if row.get::<_, String>(0) != actor.principal.issuer
                || row.get::<_, String>(1) != actor.principal.subject
                || row.get::<_, String>(2) != actor.profile_id
                || row.get::<_, String>(3) != context_hash
            {
                return Err(StoreError::CursorInvalid);
            }
            if row.get::<_, chrono::DateTime<Utc>>(7) <= Utc::now() {
                return Err(StoreError::CursorExpired);
            }
            if row.get::<_, i64>(4) != directory_revision {
                return Err(StoreError::CursorInvalid);
            }
            Some((row.get(5), row.get(6)))
        } else {
            None
        };
        let after_starts_at = after.as_ref().map(|position| position.0);
        let after_absence_id = after.as_ref().map(|position| position.1);
        let rows = transaction
            .query(
                "SELECT a.absence_id,a.person_issuer,a.person_subject,a.starts_at,a.ends_at,a.cover_issuer,a.cover_subject,a.revision FROM casework_absences a WHERE ($1='administrator' OR ($1='staff' AND a.person_issuer=$2 AND a.person_subject=$3 AND EXISTS(SELECT 1 FROM casework_memberships self_membership WHERE self_membership.issuer=$2 AND self_membership.subject=$3 AND self_membership.membership_kind='staff')) OR ($1='supervisor' AND EXISTS(SELECT 1 FROM casework_memberships person JOIN casework_memberships lead ON lead.team_id=person.team_id WHERE person.issuer=a.person_issuer AND person.subject=a.person_subject AND person.membership_kind='staff' AND lead.issuer=$2 AND lead.subject=$3 AND lead.membership_kind='supervisor'))) AND ($4::timestamptz IS NULL OR (a.starts_at,a.absence_id)>($4,$5)) ORDER BY a.starts_at,a.absence_id LIMIT $6",
                &[&role_name(actor.role), &actor.principal.issuer, &actor.principal.subject, &after_starts_at, &after_absence_id, &query_limit],
            )
            .await?;
        let fetched = rows.len();
        let cursor_placeholder = Some(Uuid::nil().to_string());
        let empty_page = AbsenceList {
            directory_revision,
            items: Vec::new(),
            next_cursor: cursor_placeholder,
        };
        let mut serialized_bytes = serde_json::to_vec(&empty_page)?.len();
        let mut items = Vec::with_capacity(limit.min(fetched));
        for row in rows.into_iter().take(limit) {
            let item = absence_from_row(row)?;
            let next_size = serialized_bytes
                .checked_add(serde_json::to_vec(&item)?.len())
                .and_then(|size| size.checked_add(usize::from(!items.is_empty())))
                .ok_or(StoreError::Corrupt)?;
            if next_size > crate::store::MAXIMUM_BOUNDED_RESPONSE_BYTES {
                break;
            }
            serialized_bytes = next_size;
            items.push(item);
        }
        if items.is_empty() && fetched > 0 {
            return Err(StoreError::Corrupt);
        }
        let more = items.len() < fetched;
        let next_cursor = if more {
            let last = items.last().ok_or(StoreError::Corrupt)?;
            let cursor_id = Uuid::new_v4();
            let expires_at = Utc::now() + TimeDelta::minutes(15);
            transaction
                .execute(
                    "INSERT INTO casework_absence_cursors(cursor_id,issuer,subject,profile_id,context_hash,directory_revision,last_starts_at,last_absence_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                    &[&cursor_id, &actor.principal.issuer, &actor.principal.subject, &actor.profile_id, &context_hash, &directory_revision, &last.from, &last.absence_id, &expires_at],
                )
                .await?;
            Some(cursor_id.to_string())
        } else {
            None
        };
        let page = AbsenceList {
            directory_revision,
            items,
            next_cursor,
        };
        if serde_json::to_vec(&page)?.len() > crate::store::MAXIMUM_BOUNDED_RESPONSE_BYTES {
            return Err(StoreError::Corrupt);
        }
        transaction.commit().await?;
        Ok(page)
    }
    pub async fn erase_expired_absence_cursors(&self) -> Result<usize, StoreError> {
        let client = self.client().await?;
        let affected = client
            .execute(
                "WITH due AS (SELECT cursor_id FROM casework_absence_cursors WHERE expires_at<=now() ORDER BY expires_at,cursor_id LIMIT 100 FOR UPDATE SKIP LOCKED) DELETE FROM casework_absence_cursors c USING due WHERE c.cursor_id=due.cursor_id",
                &[],
            )
            .await?;
        usize::try_from(affected).map_err(|_| StoreError::Corrupt)
    }
    pub async fn create_absence(
        &self,
        actor: &ActorContext,
        expected_directory_revision: i64,
        input: &AbsenceInput,
        idempotency_key: &str,
    ) -> Result<AbsenceRecord, StoreError> {
        self.write_absence(
            actor,
            None,
            expected_directory_revision,
            input,
            idempotency_key,
        )
        .await
    }
    pub async fn update_absence(
        &self,
        actor: &ActorContext,
        absence_id: Uuid,
        expected_directory_revision: i64,
        input: &AbsenceInput,
        idempotency_key: &str,
    ) -> Result<AbsenceRecord, StoreError> {
        self.write_absence(
            actor,
            Some(absence_id),
            expected_directory_revision,
            input,
            idempotency_key,
        )
        .await
    }
    async fn write_absence(
        &self,
        actor: &ActorContext,
        absence_id: Option<Uuid>,
        expected_directory_revision: i64,
        input: &AbsenceInput,
        idempotency_key: &str,
    ) -> Result<AbsenceRecord, StoreError> {
        validate_reason(
            idempotency_key,
            MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES,
            false,
        )?;
        let operation = if absence_id.is_some() {
            "directory.absence.update"
        } else {
            "directory.absence.create"
        };
        let resource = absence_id.map_or_else(|| "absences".to_owned(), |id| id.to_string());
        let request_hash = assignment_hash(&(expected_directory_revision, input))?;
        let mut audit = self
            .begin_audit(crate::audit::request_record(
                if absence_id.is_some() {
                    "absence-updated"
                } else {
                    "absence-created"
                },
                Some(actor),
                &actor.profile_id,
                json!({}),
            ))
            .await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        lock_assignment_key(&transaction, actor, operation, &resource, idempotency_key).await?;
        let actual: i64 = transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR UPDATE",
                &[],
            )
            .await?
            .get(0);
        let existing_record = if let Some(id) = absence_id {
            let row = transaction
                .query_opt(
                    "SELECT absence_id,person_issuer,person_subject,starts_at,ends_at,cover_issuer,cover_subject,revision FROM casework_absences WHERE absence_id=$1 FOR UPDATE",
                    &[&id],
                )
                .await?
                .ok_or(StoreError::NotFound)?;
            let record = absence_from_row(row)?;
            if record.person != input.person {
                return Err(StoreError::Invalid);
            }
            Some(record)
        } else {
            None
        };
        let managed_person = existing_record
            .as_ref()
            .map_or(&input.person, |record| &record.person);
        if !can_manage_person(&transaction, actor, managed_person).await?
            || !valid_absence_cover(&transaction, actor, managed_person, &input.cover).await?
        {
            return Err(StoreError::Forbidden);
        }
        if let Some(response) = assignment_replay(
            &transaction,
            actor,
            operation,
            &resource,
            idempotency_key,
            &request_hash,
        )
        .await?
        {
            let record = serde_json::from_value(response).map_err(StoreError::Json)?;
            audit.record_outcome(crate::audit::AuditOutcome::Replayed);
            audit.commit(transaction).await?;
            return Ok(record);
        }
        if actual != expected_directory_revision {
            return Err(StoreError::Conflict);
        }
        let rows=transaction.query("SELECT absence_id,person_issuer,person_subject,starts_at,ends_at,cover_issuer,cover_subject,revision FROM casework_absences WHERE ($1::uuid IS NULL OR absence_id<>$1) ORDER BY starts_at,absence_id FOR UPDATE",&[&absence_id]).await?;
        let existing = rows
            .into_iter()
            .map(absence_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        validate_absence(&existing, input)?;
        let next = actual.checked_add(1).ok_or(StoreError::Corrupt)?;
        let id = absence_id.unwrap_or_else(Uuid::new_v4);
        if absence_id.is_some() {
            let changed=transaction.execute("UPDATE casework_absences SET person_issuer=$2,person_subject=$3,starts_at=$4,ends_at=$5,cover_issuer=$6,cover_subject=$7,revision=$8 WHERE absence_id=$1",&[&id,&input.person.issuer,&input.person.subject,&input.from,&input.until,&input.cover.issuer,&input.cover.subject,&next]).await?;
            if changed != 1 {
                return Err(StoreError::NotFound);
            }
        } else {
            transaction.execute("INSERT INTO casework_absences(absence_id,person_issuer,person_subject,starts_at,ends_at,cover_issuer,cover_subject,revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",&[&id,&input.person.issuer,&input.person.subject,&input.from,&input.until,&input.cover.issuer,&input.cover.subject,&next]).await?;
        }
        transaction
            .execute(
                "UPDATE casework_meta SET directory_revision=$1 WHERE singleton=true",
                &[&next],
            )
            .await?;
        let record = AbsenceRecord {
            absence_id: id,
            person: input.person.clone(),
            from: input.from,
            until: input.until,
            cover: input.cover.clone(),
            revision: next,
        };
        append_directory_assignment_event(
            &transaction,
            &mut audit,
            actor,
            next,
            if absence_id.is_some() {
                "absence-updated"
            } else {
                "absence-created"
            },
            json!({"absence":record}),
        )
        .await?;
        insert_assignment_replay(
            &transaction,
            actor,
            operation,
            &resource,
            idempotency_key,
            &request_hash,
            &serde_json::to_value(&record)?,
        )
        .await?;
        audit.commit(transaction).await?;
        Ok(record)
    }
    pub async fn delete_absence(
        &self,
        actor: &ActorContext,
        absence_id: Uuid,
        expected_directory_revision: i64,
        idempotency_key: &str,
    ) -> Result<i64, StoreError> {
        let operation = "directory.absence.delete";
        let resource = absence_id.to_string();
        let request_hash = assignment_hash(&expected_directory_revision)?;
        let mut audit = self
            .begin_audit(crate::audit::request_record(
                "absence-deleted",
                Some(actor),
                &actor.profile_id,
                json!({}),
            ))
            .await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        lock_assignment_key(&transaction, actor, operation, &resource, idempotency_key).await?;
        if let Some(response) = assignment_replay(
            &transaction,
            actor,
            operation,
            &resource,
            idempotency_key,
            &request_hash,
        )
        .await?
        {
            let replay: AbsenceDeleteReplay =
                serde_json::from_value(response).map_err(StoreError::Json)?;
            if !can_manage_person(&transaction, actor, &replay.person).await? {
                return Err(StoreError::Forbidden);
            }
            audit.record_outcome(crate::audit::AuditOutcome::Replayed);
            audit.commit(transaction).await?;
            return Ok(replay.revision);
        }
        let actual: i64 = transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR UPDATE",
                &[],
            )
            .await?
            .get(0);
        if actual != expected_directory_revision {
            return Err(StoreError::Conflict);
        }
        let row=transaction.query_opt("SELECT absence_id,person_issuer,person_subject,starts_at,ends_at,cover_issuer,cover_subject,revision FROM casework_absences WHERE absence_id=$1 FOR UPDATE",&[&absence_id]).await?.ok_or(StoreError::NotFound)?;
        let record = absence_from_row(row)?;
        if !can_manage_person(&transaction, actor, &record.person).await? {
            return Err(StoreError::Forbidden);
        }
        let next = actual.checked_add(1).ok_or(StoreError::Corrupt)?;
        transaction
            .execute(
                "DELETE FROM casework_absences WHERE absence_id=$1",
                &[&absence_id],
            )
            .await?;
        transaction
            .execute(
                "UPDATE casework_meta SET directory_revision=$1 WHERE singleton=true",
                &[&next],
            )
            .await?;
        append_directory_assignment_event(
            &transaction,
            &mut audit,
            actor,
            next,
            "absence-deleted",
            json!({"absenceId":absence_id,"previous":record}),
        )
        .await?;
        let response = serde_json::to_value(AbsenceDeleteReplay {
            revision: next,
            person: record.person.clone(),
            cover: record.cover.clone(),
        })?;
        insert_assignment_replay(
            &transaction,
            actor,
            operation,
            &resource,
            idempotency_key,
            &request_hash,
            &response,
        )
        .await?;
        audit.commit(transaction).await?;
        Ok(next)
    }
}

impl CaseworkService {
    pub async fn bootstrap_directory(
        &self,
        actor: &ActorContext,
        expected_directory_revision: i64,
        request: &BootstrapDirectoryRequest,
        idempotency_key: &str,
    ) -> Result<i64, ServiceError> {
        if actor.role != CaseworkRole::Administrator {
            return Err(StoreError::Forbidden.into());
        }
        if expected_directory_revision < 0
            || !valid_directory_identifier(&request.team_id)
            || !valid_directory_principals(&request.staff)
            || !valid_directory_principals(&request.supervisors)
            || !valid_directory_identifier(&request.queue_id)
            || !self
                .project
                .queues
                .iter()
                .any(|configured| configured.id == request.queue_id)
        {
            return Err(StoreError::Invalid.into());
        }
        self.store
            .bootstrap_directory(actor, expected_directory_revision, request, idempotency_key)
            .await
            .map_err(ServiceError::from)
    }
    pub async fn update_directory_team(
        &self,
        actor: &ActorContext,
        expected_directory_revision: i64,
        team_id: &str,
        request: &DirectoryTeamUpdateRequest,
        idempotency_key: &str,
    ) -> Result<i64, ServiceError> {
        if actor.role != CaseworkRole::Administrator {
            return Err(StoreError::Forbidden.into());
        }
        if expected_directory_revision < 0
            || !valid_directory_identifier(team_id)
            || !valid_directory_people(&request.staff)
            || !valid_directory_people(&request.supervisors)
            || request.served_queues.len() > MAXIMUM_DIRECTORY_SERVED_QUEUES
            || request
                .served_queues
                .iter()
                .any(|queue| !valid_directory_identifier(queue))
            || request.served_queues.iter().collect::<BTreeSet<_>>().len()
                != request.served_queues.len()
            || request.served_queues.iter().any(|queue| {
                !self
                    .project
                    .queues
                    .iter()
                    .any(|configured| configured.id == *queue)
            })
        {
            return Err(StoreError::Invalid.into());
        }
        self.store
            .update_directory_team(
                actor,
                expected_directory_revision,
                team_id,
                request,
                idempotency_key,
            )
            .await
            .map_err(ServiceError::from)
    }
    pub async fn absences(&self, actor: &ActorContext) -> Result<AbsenceList, ServiceError> {
        self.absences_page(actor, 1_000, None).await
    }
    pub async fn absences_page(
        &self,
        actor: &ActorContext,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<AbsenceList, ServiceError> {
        self.store
            .absences_page(actor, limit, cursor)
            .await
            .map_err(ServiceError::from)
    }
    pub async fn create_absence(
        &self,
        actor: &ActorContext,
        expected_directory_revision: i64,
        input: &AbsenceInput,
        idempotency_key: &str,
    ) -> Result<AbsenceRecord, ServiceError> {
        self.store
            .create_absence(actor, expected_directory_revision, input, idempotency_key)
            .await
            .map_err(ServiceError::from)
    }
    pub async fn update_absence(
        &self,
        actor: &ActorContext,
        absence_id: Uuid,
        expected_directory_revision: i64,
        input: &AbsenceInput,
        idempotency_key: &str,
    ) -> Result<AbsenceRecord, ServiceError> {
        self.store
            .update_absence(
                actor,
                absence_id,
                expected_directory_revision,
                input,
                idempotency_key,
            )
            .await
            .map_err(ServiceError::from)
    }
    pub async fn delete_absence(
        &self,
        actor: &ActorContext,
        absence_id: Uuid,
        expected_directory_revision: i64,
        idempotency_key: &str,
    ) -> Result<i64, ServiceError> {
        self.store
            .delete_absence(
                actor,
                absence_id,
                expected_directory_revision,
                idempotency_key,
            )
            .await
            .map_err(ServiceError::from)
    }
    pub async fn directory_targets(
        &self,
        actor: &ActorContext,
        purpose: DirectoryTargetPurpose,
        queue: Option<&str>,
        person: Option<&IssuerPrincipal>,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<DirectoryTargetPage, ServiceError> {
        self.store
            .directory_targets(actor, purpose, queue, person, limit, cursor)
            .await
            .map_err(ServiceError::from)
    }
    pub async fn erase_expired_directory_target_cursors(&self) -> Result<usize, ServiceError> {
        self.store
            .erase_expired_directory_target_cursors()
            .await
            .map_err(ServiceError::from)
    }
    pub async fn erase_expired_absence_cursors(&self) -> Result<usize, ServiceError> {
        self.store
            .erase_expired_absence_cursors()
            .await
            .map_err(ServiceError::from)
    }
}

fn absence_from_row(row: tokio_postgres::Row) -> Result<AbsenceRecord, StoreError> {
    Ok(AbsenceRecord {
        absence_id: row.get(0),
        person: IssuerPrincipal {
            issuer: row.get(1),
            subject: row.get(2),
        },
        from: row.get(3),
        until: row.get(4),
        cover: IssuerPrincipal {
            issuer: row.get(5),
            subject: row.get(6),
        },
        revision: row.get(7),
    })
}

fn role_name(role: CaseworkRole) -> &'static str {
    match role {
        CaseworkRole::Staff => "staff",
        CaseworkRole::Supervisor => "supervisor",
        CaseworkRole::Administrator => "administrator",
        CaseworkRole::Requester => "requester",
    }
}

fn valid_directory_principals(people: &[IssuerPrincipal]) -> bool {
    people.len() <= MAXIMUM_DIRECTORY_PRINCIPALS
        && people.iter().collect::<BTreeSet<_>>().len() == people.len()
        && people.iter().all(|person| {
            !person.issuer.is_empty()
                && person.issuer.len() <= MAXIMUM_DIRECTORY_PRINCIPAL_COMPONENT_BYTES
                && !person.subject.is_empty()
                && person.subject.len() <= MAXIMUM_DIRECTORY_PRINCIPAL_COMPONENT_BYTES
                && !person.issuer.chars().any(char::is_control)
                && !person.subject.chars().any(char::is_control)
        })
}

fn valid_directory_people(people: &[DirectoryMember]) -> bool {
    people.len() <= MAXIMUM_DIRECTORY_PRINCIPALS
        && people
            .iter()
            .map(|person| (&person.issuer, &person.subject))
            .collect::<BTreeSet<_>>()
            .len()
            == people.len()
        && people.iter().all(|person| {
            !person.issuer.is_empty()
                && person.issuer.len() <= MAXIMUM_DIRECTORY_PRINCIPAL_COMPONENT_BYTES
                && !person.subject.is_empty()
                && person.subject.len() <= MAXIMUM_DIRECTORY_PRINCIPAL_COMPONENT_BYTES
                && !person.issuer.chars().any(char::is_control)
                && !person.subject.chars().any(char::is_control)
                && person.display_name.as_ref().is_none_or(|display_name| {
                    !display_name.is_empty()
                        && display_name.len() <= MAXIMUM_DIRECTORY_DISPLAY_NAME_BYTES
                        && !display_name.chars().any(char::is_control)
                })
        })
}

fn validate_reason(value: &str, maximum: usize, allow_empty: bool) -> Result<(), StoreError> {
    if (!allow_empty && value.is_empty())
        || value.len() > maximum
        || value.chars().any(char::is_control)
    {
        Err(StoreError::Invalid)
    } else {
        Ok(())
    }
}

fn assignment_hash<T: Serialize>(value: &T) -> Result<String, StoreError> {
    let bytes = serde_json::to_vec(value)?;
    let digest = Sha256::digest(bytes);
    Ok(format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

async fn can_manage_person(
    tx: &Transaction<'_>,
    actor: &ActorContext,
    person: &IssuerPrincipal,
) -> Result<bool, StoreError> {
    if actor.role == CaseworkRole::Administrator {
        return Ok(true);
    }
    let owns = actor.role == CaseworkRole::Staff
        && actor.principal == *person
        && tx.query_opt(
            "SELECT 1 FROM casework_memberships person WHERE person.issuer=$1 AND person.subject=$2 AND person.membership_kind='staff' FOR KEY SHARE OF person",
            &[&person.issuer, &person.subject],
        )
        .await?
        .is_some();
    let supervises=actor.role==CaseworkRole::Supervisor&&tx.query_opt("SELECT 1 FROM casework_memberships person JOIN casework_memberships lead ON lead.team_id=person.team_id WHERE person.issuer=$1 AND person.subject=$2 AND person.membership_kind='staff' AND lead.issuer=$3 AND lead.subject=$4 AND lead.membership_kind='supervisor' FOR KEY SHARE OF person,lead",&[&person.issuer,&person.subject,&actor.principal.issuer,&actor.principal.subject]).await?.is_some();
    Ok(owns || supervises)
}

async fn valid_absence_cover(
    tx: &Transaction<'_>,
    actor: &ActorContext,
    person: &IssuerPrincipal,
    cover: &IssuerPrincipal,
) -> Result<bool, StoreError> {
    if actor.role == CaseworkRole::Supervisor {
        return Ok(tx.query_opt("SELECT 1 FROM casework_memberships person JOIN casework_memberships cover ON cover.team_id=person.team_id JOIN casework_memberships lead ON lead.team_id=person.team_id WHERE person.issuer=$1 AND person.subject=$2 AND person.membership_kind='staff' AND cover.issuer=$3 AND cover.subject=$4 AND cover.membership_kind='staff' AND lead.issuer=$5 AND lead.subject=$6 AND lead.membership_kind='supervisor' FOR KEY SHARE OF person,cover,lead",&[&person.issuer,&person.subject,&cover.issuer,&cover.subject,&actor.principal.issuer,&actor.principal.subject]).await?.is_some());
    }
    Ok(tx.query_opt("SELECT 1 FROM casework_memberships person JOIN casework_memberships cover ON cover.team_id=person.team_id WHERE person.issuer=$1 AND person.subject=$2 AND person.membership_kind='staff' AND cover.issuer=$3 AND cover.subject=$4 AND cover.membership_kind='staff' FOR KEY SHARE OF person,cover",&[&person.issuer,&person.subject,&cover.issuer,&cover.subject]).await?.is_some())
}

async fn can_assign_queue(
    tx: &Transaction<'_>,
    actor: &ActorContext,
    queue: &str,
) -> Result<bool, StoreError> {
    Ok(actor.role==CaseworkRole::Supervisor&&tx.query_opt("SELECT 1 FROM casework_queue_service q JOIN casework_memberships m ON m.team_id=q.team_id WHERE q.queue_id=$1 AND m.issuer=$2 AND m.subject=$3 AND m.membership_kind='supervisor' FOR KEY SHARE OF q,m",&[&queue,&actor.principal.issuer,&actor.principal.subject]).await?.is_some())
}

async fn is_staff_for_queue(
    tx: &Transaction<'_>,
    person: &IssuerPrincipal,
    queue: &str,
) -> Result<bool, StoreError> {
    Ok(tx.query_opt("SELECT 1 FROM casework_queue_service q JOIN casework_memberships m ON m.team_id=q.team_id WHERE q.queue_id=$1 AND m.issuer=$2 AND m.subject=$3 AND m.membership_kind='staff' FOR KEY SHARE OF q,m",&[&queue,&person.issuer,&person.subject]).await?.is_some())
}

async fn lock_assignment_key(
    tx: &Transaction<'_>,
    actor: &ActorContext,
    operation: &str,
    resource: &str,
    key: &str,
) -> Result<(), StoreError> {
    validate_reason(key, MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES, false)?;
    let binding = format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{operation}\u{1f}{resource}\u{1f}{key}",
        actor.principal.issuer, actor.principal.subject, actor.profile_id
    );
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
        &[&binding],
    )
    .await?;
    Ok(())
}

async fn assignment_replay(
    tx: &Transaction<'_>,
    actor: &ActorContext,
    operation: &str,
    resource: &str,
    key: &str,
    hash: &str,
) -> Result<Option<Value>, StoreError> {
    let row=tx.query_opt("SELECT request_hash,response FROM casework_idempotency WHERE issuer=$1 AND subject=$2 AND profile_id=$3 AND operation=$4 AND resource=$5 AND idempotency_key=$6 FOR UPDATE",&[&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&operation,&resource,&key]).await?;
    match row {
        Some(row) if row.get::<_, String>(0) == hash => row
            .get::<_, Option<Value>>(1)
            .map(Some)
            .ok_or(StoreError::IdempotencyExpired),
        Some(_) => Err(StoreError::IdempotencyConflict),
        None => Ok(None),
    }
}

async fn insert_assignment_replay(
    tx: &Transaction<'_>,
    actor: &ActorContext,
    operation: &str,
    resource: &str,
    key: &str,
    hash: &str,
    response: &Value,
) -> Result<(), StoreError> {
    tx.execute("INSERT INTO casework_idempotency(issuer,subject,profile_id,operation,resource,idempotency_key,request_hash,response,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",&[&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&operation,&resource,&key,&hash,&response,&Utc::now()]).await?;
    Ok(())
}

async fn append_directory_assignment_event(
    tx: &Transaction<'_>,
    audit: &mut crate::audit::AuditOperation,
    actor: &ActorContext,
    revision: i64,
    kind: &str,
    detail: Value,
) -> Result<(), StoreError> {
    let event_id = Uuid::new_v4();
    let now = Utc::now();
    tx.execute("INSERT INTO casework_directory_events(event_id,directory_revision,event_kind,occurred_at,actor_issuer,actor_subject,profile_id,detail) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",&[&event_id,&revision,&kind,&now,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&detail]).await?;
    audit.record(
        event_id,
        json!({"event":format!("casework.{kind}"),"directoryRevision":revision,"actor":{"issuer":actor.principal.issuer,"subject":actor.principal.subject},"profileId":actor.profile_id,"detail":detail}),
    )
}

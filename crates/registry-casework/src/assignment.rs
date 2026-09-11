// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use chrono::{TimeDelta, Utc};
use registry_casework_core::{
    resolve_absence_cover, validate_absence, AbsenceInput, AbsenceList, AbsenceRecord,
    ActorContext, AssignmentContext, AssignmentRequest, CaseloadApplyRequest, CaseloadItemOutcome,
    CaseloadItemResult, CaseloadMoveRequest, CaseloadPreviewPage, CaseworkRole, DelegateRequest,
    DirectoryMember, DirectoryTargetPage, DirectoryTargetPurpose, DirectoryTeamUpdateRequest,
    HistoryKind, IssuerPrincipal, Page, PageStatus, SourceAdapterError, StaffingDiagnostic,
    WorkItem, MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES, MAXIMUM_DIRECTORY_DISPLAY_NAME_BYTES,
    MAXIMUM_DIRECTORY_IDENTIFIER_BYTES, MAXIMUM_DIRECTORY_PRINCIPALS,
    MAXIMUM_DIRECTORY_PRINCIPAL_COMPONENT_BYTES, MAXIMUM_DIRECTORY_SERVED_QUEUES,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::{CaseworkService, PostgresStore, ServiceError, StoreError};

const MAXIMUM_REASON_BYTES: usize = 2_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AssignmentOrigin {
    Source,
    Hosted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AssignmentMutation {
    pub origin: AssignmentOrigin,
    pub item_id: Uuid,
    pub revision: i64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AssignmentCandidate {
    pub origin: AssignmentOrigin,
    pub item_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AbsenceDeleteReplay {
    revision: i64,
    person: IssuerPrincipal,
    cover: IssuerPrincipal,
}

impl PostgresStore {
    #[allow(clippy::too_many_arguments)]
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
            transaction.commit().await?;
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
        append_directory_assignment_event(
            &transaction,
            actor,
            next,
            "team_updated",
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
        transaction.commit().await?;
        Ok(next)
    }

    pub(crate) async fn absences(
        &self,
        actor: &ActorContext,
    ) -> Result<(i64, Vec<AbsenceRecord>), StoreError> {
        if !matches!(
            actor.role,
            CaseworkRole::Staff | CaseworkRole::Supervisor | CaseworkRole::Administrator
        ) {
            return Err(StoreError::Forbidden);
        }
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let directory_revision = transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR SHARE",
                &[],
            )
            .await?
            .get(0);
        let rows = transaction.query(
            "SELECT a.absence_id,a.person_issuer,a.person_subject,a.starts_at,a.ends_at,a.cover_issuer,a.cover_subject,a.revision FROM casework_absences a WHERE $1='administrator' OR ($1='staff' AND a.person_issuer=$2 AND a.person_subject=$3 AND EXISTS(SELECT 1 FROM casework_memberships self_membership WHERE self_membership.issuer=$2 AND self_membership.subject=$3 AND self_membership.membership_kind='staff')) OR ($1='supervisor' AND EXISTS(SELECT 1 FROM casework_memberships person JOIN casework_memberships lead ON lead.team_id=person.team_id WHERE person.issuer=a.person_issuer AND person.subject=a.person_subject AND person.membership_kind='staff' AND lead.issuer=$2 AND lead.subject=$3 AND lead.membership_kind='supervisor')) ORDER BY a.starts_at,a.absence_id LIMIT 1001",
            &[&role_name(actor.role),&actor.principal.issuer,&actor.principal.subject],
        ).await?;
        if rows.len() > 1_000 {
            return Err(StoreError::Invalid);
        }
        let records = rows
            .into_iter()
            .map(absence_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().await?;
        Ok((directory_revision, records))
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
            transaction.commit().await?;
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
            actor,
            next,
            if absence_id.is_some() {
                "absence_updated"
            } else {
                "absence_created"
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
        transaction.commit().await?;
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
            transaction.commit().await?;
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
            actor,
            next,
            "absence_deleted",
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
        transaction.commit().await?;
        Ok(next)
    }

    pub(crate) async fn assignment_origin(
        &self,
        item_id: Uuid,
    ) -> Result<AssignmentOrigin, StoreError> {
        let client = self.client().await?;
        let row=client.query_one("SELECT EXISTS(SELECT 1 FROM casework_items WHERE item_id=$1 AND erased_at IS NULL),EXISTS(SELECT 1 FROM casework_hosted_items WHERE item_id=$1)",&[&item_id]).await?;
        match (row.get(0), row.get(1)) {
            (true, false) => Ok(AssignmentOrigin::Source),
            (false, true) => Ok(AssignmentOrigin::Hosted),
            (false, false) => Err(StoreError::NotFound),
            _ => Err(StoreError::Corrupt),
        }
    }

    pub(crate) async fn caseload_candidates(
        &self,
        actor: &ActorContext,
        source_profile_id: Option<&str>,
        movement: &CaseloadMoveRequest,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<Page<AssignmentCandidate>, StoreError> {
        if actor.role != CaseworkRole::Supervisor {
            return Err(StoreError::Forbidden);
        }
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let context_hash = assignment_hash(&(source_profile_id, movement))?;
        let after = if let Some(cursor) = cursor {
            let cursor_id = Uuid::parse_str(cursor).map_err(|_| StoreError::CursorInvalid)?;
            let row=transaction.query_opt("SELECT issuer,subject,profile_id,context_hash,last_item_id,expires_at FROM casework_assignment_cursors WHERE cursor_id=$1",&[&cursor_id]).await?.ok_or(StoreError::CursorInvalid)?;
            if row.get::<_, String>(0) != actor.principal.issuer
                || row.get::<_, String>(1) != actor.principal.subject
                || row.get::<_, String>(2) != actor.profile_id
                || row.get::<_, String>(3) != context_hash
            {
                return Err(StoreError::CursorInvalid);
            }
            if row.get::<_, chrono::DateTime<Utc>>(5) <= Utc::now() {
                return Err(StoreError::CursorExpired);
            }
            row.get(4)
        } else {
            Uuid::nil()
        };
        let desired = limit.clamp(1, 100);
        let query_limit = i64::try_from(desired + 1).map_err(|_| StoreError::Invalid)?;
        let rows=transaction.query(
            "SELECT origin,item_id FROM (SELECT 'source'::text origin,i.item_id,i.queue_id FROM casework_items i WHERE i.erased_at IS NULL AND i.holder_issuer=$1 AND i.holder_subject=$2 AND i.state NOT IN ('completed','superseded','cancelled') UNION ALL SELECT 'hosted'::text origin,i.item_id,i.queue_id FROM casework_hosted_items i WHERE i.holder_issuer=$1 AND i.holder_subject=$2 AND i.state IN ('open','claimed')) candidates WHERE ($3::text IS NULL OR queue_id=$3) AND item_id>$4 AND EXISTS(SELECT 1 FROM casework_queue_service q JOIN casework_memberships m ON m.team_id=q.team_id WHERE q.queue_id=candidates.queue_id AND m.issuer=$5 AND m.subject=$6 AND m.membership_kind='supervisor') ORDER BY item_id LIMIT $7",
            &[&movement.from.issuer,&movement.from.subject,&movement.queue_id,&after,&actor.principal.issuer,&actor.principal.subject,&query_limit],
        ).await?;
        let more = rows.len() > desired;
        let items = rows
            .into_iter()
            .take(desired)
            .map(|row| {
                Ok(AssignmentCandidate {
                    origin: match row.get::<_, String>(0).as_str() {
                        "source" => AssignmentOrigin::Source,
                        "hosted" => AssignmentOrigin::Hosted,
                        _ => return Err(StoreError::Corrupt),
                    },
                    item_id: row.get(1),
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let next_cursor = if more {
            let last = items.last().ok_or(StoreError::Corrupt)?.item_id;
            let id = Uuid::new_v4();
            let expires = Utc::now() + TimeDelta::minutes(15);
            transaction.execute("INSERT INTO casework_assignment_cursors(cursor_id,issuer,subject,profile_id,context_hash,last_item_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)",&[&id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&context_hash,&last,&expires]).await?;
            Some(id.to_string())
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

    pub(crate) async fn issue_caseload_cursor(
        &self,
        actor: &ActorContext,
        source_profile_id: Option<&str>,
        movement: &CaseloadMoveRequest,
        last_item_id: Uuid,
    ) -> Result<String, StoreError> {
        let client = self.client().await?;
        let cursor_id = Uuid::new_v4();
        let context_hash = assignment_hash(&(source_profile_id, movement))?;
        let expires_at = Utc::now() + TimeDelta::minutes(15);
        client.execute(
            "INSERT INTO casework_assignment_cursors(cursor_id,issuer,subject,profile_id,context_hash,last_item_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
            &[&cursor_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&context_hash,&last_item_id,&expires_at],
        ).await?;
        Ok(cursor_id.to_string())
    }

    pub async fn erase_expired_assignment_cursors(&self) -> Result<usize, StoreError> {
        let client = self.client().await?;
        let affected = client.execute(
            "WITH due AS (SELECT cursor_id FROM casework_assignment_cursors WHERE expires_at<=now() ORDER BY expires_at,cursor_id LIMIT 100 FOR UPDATE SKIP LOCKED) DELETE FROM casework_assignment_cursors c USING due WHERE c.cursor_id=due.cursor_id",
            &[],
        ).await?;
        usize::try_from(affected).map_err(|_| StoreError::Corrupt)
    }

    pub async fn reconcile_ineligible_assignments(
        &self,
        limit: usize,
    ) -> Result<usize, StoreError> {
        let client = self.client().await?;
        let limit = i64::try_from(limit.clamp(1, 100)).map_err(|_| StoreError::Invalid)?;
        let rows = client
            .query(
                "SELECT origin,item_id FROM (SELECT 'source'::text AS origin,i.item_id FROM casework_items i WHERE i.erased_at IS NULL AND i.state='claimed' AND i.holder_issuer IS NOT NULL AND NOT EXISTS(SELECT 1 FROM casework_queue_service q JOIN casework_memberships m ON m.team_id=q.team_id WHERE q.queue_id=i.queue_id AND m.issuer=i.holder_issuer AND m.subject=i.holder_subject AND m.membership_kind='staff') AND NOT EXISTS(SELECT 1 FROM casework_attempts a WHERE a.item_id=i.item_id AND a.state IN ('pending','uncertain')) UNION ALL SELECT 'hosted'::text AS origin,i.item_id FROM casework_hosted_items i WHERE i.state='claimed' AND i.holder_issuer IS NOT NULL AND NOT EXISTS(SELECT 1 FROM casework_queue_service q JOIN casework_memberships m ON m.team_id=q.team_id WHERE q.queue_id=i.queue_id AND m.issuer=i.holder_issuer AND m.subject=i.holder_subject AND m.membership_kind='staff')) candidates ORDER BY item_id LIMIT $1",
                &[&limit],
            )
            .await?;
        let mut released = 0usize;
        for row in rows {
            let origin = match row.get::<_, String>(0).as_str() {
                "source" => AssignmentOrigin::Source,
                "hosted" => AssignmentOrigin::Hosted,
                _ => return Err(StoreError::Corrupt),
            };
            if self
                .release_ineligible_assignment(origin, row.get(1))
                .await?
            {
                released += 1;
            }
        }
        Ok(released)
    }

    async fn release_ineligible_assignment(
        &self,
        origin: AssignmentOrigin,
        item_id: Uuid,
    ) -> Result<bool, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let table = match origin {
            AssignmentOrigin::Source => "casework_items",
            AssignmentOrigin::Hosted => "casework_hosted_items",
        };
        let visible = match origin {
            AssignmentOrigin::Source => " AND erased_at IS NULL",
            AssignmentOrigin::Hosted => "",
        };
        let row = transaction
            .query_opt(
                &format!(
                    "SELECT queue_id,state,holder_issuer,holder_subject,revision FROM {table} WHERE item_id=$1{visible} FOR UPDATE"
                ),
                &[&item_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let directory_revision: i64 = transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR SHARE",
                &[],
            )
            .await?
            .get(0);
        let queue: String = row.get(0);
        let state: String = row.get(1);
        let Some(holder) = principal_columns(&row, 2, 3)? else {
            transaction.commit().await?;
            return Ok(false);
        };
        if state != "claimed" || is_staff_for_queue(&transaction, &holder, &queue).await? {
            transaction.commit().await?;
            return Ok(false);
        }
        if origin == AssignmentOrigin::Source {
            match ensure_no_source_attempt(&transaction, item_id).await {
                Ok(()) => {}
                Err(StoreError::AttemptPending) => {
                    transaction.commit().await?;
                    return Ok(false);
                }
                Err(error) => return Err(error),
            }
        }
        let revision = row
            .get::<_, i64>(4)
            .checked_add(1)
            .ok_or(StoreError::Corrupt)?;
        let now = Utc::now();
        transaction
            .execute(
                &format!(
                    "UPDATE {table} SET state='open',holder_issuer=NULL,holder_subject=NULL,assignment_owner_issuer=NULL,assignment_owner_subject=NULL,assigned_by_issuer=NULL,assigned_by_subject=NULL,assignment_absence_ids='{{}}',staffing_diagnostic=NULL,revision=$2,updated_at=$3 WHERE item_id=$1"
                ),
                &[&item_id, &revision, &now],
            )
            .await?;
        let system_actor = ActorContext {
            principal: IssuerPrincipal {
                issuer: "urn:registry-stack:casework".to_owned(),
                subject: "directory-reconciliation".to_owned(),
            },
            profile_id: "system:directory-reconciliation".to_owned(),
            role: CaseworkRole::Administrator,
        };
        let detail = json!({
            "previousHolder": holder,
            "reason": "directory_membership_changed",
            "directoryRevision": directory_revision,
        });
        match origin {
            AssignmentOrigin::Source => {
                let updated = transaction
                    .query_one("SELECT * FROM casework_items WHERE item_id=$1", &[&item_id])
                    .await?;
                crate::store::append_item_event(
                    &transaction,
                    &crate::store::row_to_item(&updated)?,
                    HistoryKind::Released,
                    Some(&system_actor),
                    &system_actor.profile_id,
                    detail,
                )
                .await?;
            }
            AssignmentOrigin::Hosted => {
                crate::hosted::append_hosted_history(
                    &transaction,
                    item_id,
                    revision,
                    "released",
                    &system_actor,
                    detail,
                )
                .await?;
            }
        }
        transaction.commit().await?;
        Ok(true)
    }

    pub(crate) async fn assign_person(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        request: &AssignmentRequest,
        idempotency_key: &str,
    ) -> Result<AssignmentMutation, StoreError> {
        self.change_assignment(
            actor,
            item_id,
            expected_revision,
            &request.assignee,
            None,
            None,
            request.reason.as_deref(),
            "assigned",
            idempotency_key,
            false,
        )
        .await
    }

    pub(crate) async fn delegate_person(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        request: &DelegateRequest,
        idempotency_key: &str,
    ) -> Result<AssignmentMutation, StoreError> {
        self.change_assignment(
            actor,
            item_id,
            expected_revision,
            &request.delegate,
            None,
            None,
            request.reason.as_deref(),
            "delegated",
            idempotency_key,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn move_caseload_item(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        from: &IssuerPrincipal,
        to: &IssuerPrincipal,
        queue: Option<&str>,
        reason: &str,
        idempotency_key: &str,
    ) -> Result<AssignmentMutation, StoreError> {
        self.change_assignment(
            actor,
            item_id,
            expected_revision,
            to,
            Some(from),
            queue,
            Some(reason),
            "caseload_moved",
            idempotency_key,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn change_assignment(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        target: &IssuerPrincipal,
        required_holder: Option<&IssuerPrincipal>,
        required_queue: Option<&str>,
        reason: Option<&str>,
        kind: &str,
        idempotency_key: &str,
        delegate: bool,
    ) -> Result<AssignmentMutation, StoreError> {
        if let Some(reason) = reason {
            validate_reason(reason, MAXIMUM_REASON_BYTES, false)?;
        }
        let origin = self.assignment_origin(item_id).await?;
        let operation = format!("item.{kind}");
        let resource = item_id.to_string();
        let request_hash = assignment_hash(&(
            expected_revision,
            target,
            required_holder,
            required_queue,
            reason,
            delegate,
        ))?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        lock_assignment_key(&transaction, actor, &operation, &resource, idempotency_key).await?;
        let replay = assignment_replay(
            &transaction,
            actor,
            &operation,
            &resource,
            idempotency_key,
            &request_hash,
        )
        .await?;
        let table = match origin {
            AssignmentOrigin::Source => "casework_items",
            AssignmentOrigin::Hosted => "casework_hosted_items",
        };
        let visible = match origin {
            AssignmentOrigin::Source => " AND erased_at IS NULL",
            AssignmentOrigin::Hosted => "",
        };
        let sql=format!("SELECT queue_id,state,holder_issuer,holder_subject,assignment_owner_issuer,assignment_owner_subject,revision FROM {table} WHERE item_id=$1{visible} FOR UPDATE");
        let row = transaction
            .query_opt(&sql, &[&item_id])
            .await?
            .ok_or(StoreError::NotFound)?;
        // Absence mutations hold this row for update. The share lock keeps the
        // cover chain current until this assignment transaction commits.
        transaction
            .query_one(
                "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR SHARE",
                &[],
            )
            .await?;
        let queue: String = row.get(0);
        let state: String = row.get(1);
        let revision: i64 = row.get(6);
        if required_queue.is_some_and(|expected| expected != queue) {
            return Err(StoreError::Conflict);
        }
        let holder = principal_columns(&row, 2, 3)?;
        let owner = principal_columns(&row, 4, 5)?;
        if delegate {
            let controls_assignment = if replay.is_some() {
                owner.as_ref() == Some(&actor.principal)
                    || holder.as_ref() == Some(&actor.principal)
            } else {
                holder.as_ref() == Some(&actor.principal)
            };
            let current_authority = match actor.role {
                CaseworkRole::Staff => {
                    is_staff_for_queue(&transaction, &actor.principal, &queue).await?
                }
                CaseworkRole::Supervisor => can_assign_queue(&transaction, actor, &queue).await?,
                CaseworkRole::Administrator | CaseworkRole::Requester => false,
            };
            if !controls_assignment || !current_authority {
                return Err(StoreError::Forbidden);
            }
        } else if !can_assign_queue(&transaction, actor, &queue).await? {
            return Err(StoreError::Forbidden);
        }
        if let Some(response) = replay {
            let result = serde_json::from_value(response).map_err(StoreError::Json)?;
            transaction.commit().await?;
            return Ok(result);
        }
        if required_holder.is_some_and(|expected| holder.as_ref() != Some(expected)) {
            return Err(StoreError::Conflict);
        }
        if revision != expected_revision {
            return Err(StoreError::Conflict);
        }
        if origin == AssignmentOrigin::Source {
            ensure_no_source_attempt(&transaction, item_id).await?;
        }
        if !matches!(state.as_str(), "open" | "claimed") {
            return Err(StoreError::Conflict);
        }
        if !is_staff_for_queue(&transaction, target, &queue).await? {
            return Err(StoreError::Forbidden);
        }
        let now = Utc::now();
        let absences = active_absences(&transaction, target, now).await?;
        let cover =
            resolve_absence_cover(target, now, &absences).map_err(|_| StoreError::Corrupt)?;
        let eligible = is_staff_for_queue(&transaction, &cover.person, &queue).await?;
        if !eligible && cover.absence_ids.is_empty() {
            return Err(StoreError::Forbidden);
        }
        let next = revision.checked_add(1).ok_or(StoreError::Corrupt)?;
        let next_holder = eligible.then_some(&cover.person);
        let assignment_owner = if delegate {
            owner.as_ref().or(holder.as_ref()).unwrap_or(target)
        } else {
            target
        };
        let diagnostic = (!eligible).then_some("no_cover_available");
        let update=format!("UPDATE {table} SET holder_issuer=$2,holder_subject=$3,assignment_owner_issuer=$4,assignment_owner_subject=$5,assigned_by_issuer=$6,assigned_by_subject=$7,assignment_absence_ids=$8,staffing_diagnostic=$9,state=$10,revision=$11,updated_at=$12 WHERE item_id=$1");
        transaction
            .execute(
                &update,
                &[
                    &item_id,
                    &next_holder.map(|p| &p.issuer),
                    &next_holder.map(|p| &p.subject),
                    &assignment_owner.issuer,
                    &assignment_owner.subject,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &cover.absence_ids,
                    &diagnostic,
                    &if eligible { "claimed" } else { "open" },
                    &next,
                    &now,
                ],
            )
            .await?;
        let assignment = AssignmentContext {
            owner: Some(assignment_owner.clone()),
            assigned_by: Some(actor.principal.clone()),
            absence_ids: cover.absence_ids.clone(),
            staffing_diagnostic: (!eligible).then_some(StaffingDiagnostic::NoCoverAvailable),
        };
        let detail = json!({"previousHolder":holder,"assignment":assignment,"reason":reason});
        match origin {
            AssignmentOrigin::Source => {
                let updated = transaction
                    .query_one("SELECT * FROM casework_items WHERE item_id=$1", &[&item_id])
                    .await?;
                let item = crate::store::row_to_item(&updated)?;
                let history_kind = match kind {
                    "assigned" => HistoryKind::Assigned,
                    "delegated" => HistoryKind::Delegated,
                    "caseload_moved" => HistoryKind::CaseloadMoved,
                    _ => return Err(StoreError::Corrupt),
                };
                crate::store::append_item_event(
                    &transaction,
                    &item,
                    history_kind,
                    Some(actor),
                    &actor.profile_id,
                    detail,
                )
                .await?;
            }
            AssignmentOrigin::Hosted => {
                crate::hosted::append_hosted_history(
                    &transaction,
                    item_id,
                    next,
                    kind,
                    actor,
                    detail,
                )
                .await?;
            }
        }
        let result = AssignmentMutation {
            origin,
            item_id,
            revision: next,
        };
        insert_assignment_replay(
            &transaction,
            actor,
            &operation,
            &resource,
            idempotency_key,
            &request_hash,
            &serde_json::to_value(&result)?,
        )
        .await?;
        transaction.commit().await?;
        Ok(result)
    }

    pub(crate) async fn reserve_caseload_apply(
        &self,
        actor: &ActorContext,
        request: &CaseloadApplyRequest,
        idempotency_key: &str,
    ) -> Result<(), StoreError> {
        let operation = "caseload.apply";
        let resource = "items";
        let request_hash = assignment_hash(request)?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        lock_assignment_key(&transaction, actor, operation, resource, idempotency_key).await?;
        if assignment_replay(
            &transaction,
            actor,
            operation,
            resource,
            idempotency_key,
            &request_hash,
        )
        .await?
        .is_none()
        {
            insert_assignment_replay(
                &transaction,
                actor,
                operation,
                resource,
                idempotency_key,
                &request_hash,
                &json!({"reserved":true}),
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }
}

impl CaseworkService {
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
        let (directory_revision, items) = self.store.absences(actor).await?;
        Ok(AbsenceList {
            directory_revision,
            items,
        })
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

    #[allow(clippy::too_many_arguments)]
    pub async fn assign_item(
        &self,
        actor: &ActorContext,
        source_profile_id: Option<&str>,
        token: &str,
        item_id: Uuid,
        expected_revision: i64,
        request: &AssignmentRequest,
        idempotency_key: &str,
    ) -> Result<WorkItem, ServiceError> {
        let origin = self
            .assignment_visible_item(actor, source_profile_id, token, item_id)
            .await?
            .0;
        self.store
            .assign_person(actor, item_id, expected_revision, request, idempotency_key)
            .await?;
        self.assignment_visible_item_for_origin(actor, source_profile_id, token, item_id, origin)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn delegate_item(
        &self,
        actor: &ActorContext,
        source_profile_id: Option<&str>,
        token: &str,
        item_id: Uuid,
        expected_revision: i64,
        request: &DelegateRequest,
        idempotency_key: &str,
    ) -> Result<WorkItem, ServiceError> {
        let origin = self
            .assignment_visible_item(actor, source_profile_id, token, item_id)
            .await?
            .0;
        self.store
            .delegate_person(actor, item_id, expected_revision, request, idempotency_key)
            .await?;
        self.assignment_visible_item_for_origin(actor, source_profile_id, token, item_id, origin)
            .await
    }

    pub async fn preview_caseload_move(
        &self,
        actor: &ActorContext,
        source_profile_id: Option<&str>,
        token: &str,
        movement: &CaseloadMoveRequest,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<CaseloadPreviewPage, ServiceError> {
        validate_reason(&movement.reason, MAXIMUM_REASON_BYTES, false)?;
        if movement.from == movement.to {
            return Err(StoreError::Invalid.into());
        }
        let desired = limit.clamp(1, 100);
        let policy = &self.project.inbox;
        let started = Instant::now();
        let deadline = Duration::from_millis(policy.page_deadline_milliseconds);
        let mut visible = Vec::new();
        let mut next = cursor.map(str::to_owned);
        let mut scanned = 0usize;
        let mut source_reads = 0usize;
        let mut last_examined = None;
        loop {
            if scanned >= policy.maximum_candidate_scan || started.elapsed() >= deadline {
                let next_cursor = match last_examined {
                    Some(item_id) => Some(
                        self.store
                            .issue_caseload_cursor(actor, source_profile_id, movement, item_id)
                            .await?,
                    ),
                    None => next,
                };
                return Ok(Page {
                    items: visible,
                    next_cursor,
                    status: PageStatus::BudgetExhausted,
                });
            }
            let batch_limit = (policy.maximum_candidate_scan - scanned).min(100);
            let batch = self
                .store
                .caseload_candidates(
                    actor,
                    source_profile_id,
                    movement,
                    batch_limit,
                    next.as_deref(),
                )
                .await?;
            let batch_len = batch.items.len();
            let batch_next = batch.next_cursor;
            for (index, candidate) in batch.items.into_iter().enumerate() {
                if started.elapsed() >= deadline
                    || (candidate.origin == AssignmentOrigin::Source
                        && source_reads >= policy.maximum_source_reads)
                {
                    let next_cursor = match last_examined {
                        Some(item_id) => Some(
                            self.store
                                .issue_caseload_cursor(actor, source_profile_id, movement, item_id)
                                .await?,
                        ),
                        None => next,
                    };
                    return Ok(Page {
                        items: visible,
                        next_cursor,
                        status: PageStatus::BudgetExhausted,
                    });
                }
                scanned += 1;
                let read = self.assignment_visible_item_for_origin(
                    actor,
                    source_profile_id,
                    token,
                    candidate.item_id,
                    candidate.origin,
                );
                let result = if candidate.origin == AssignmentOrigin::Source {
                    source_reads += 1;
                    tokio::time::timeout(deadline.saturating_sub(started.elapsed()), read)
                        .await
                        .map_err(|_| ServiceError::Adapter(SourceAdapterError::Unavailable))?
                } else {
                    read.await
                };
                match result {
                    Ok(item) => visible.push(item),
                    Err(
                        ServiceError::NotFound
                        | ServiceError::Store(StoreError::NotFound)
                        | ServiceError::Adapter(
                            SourceAdapterError::Concealed | SourceAdapterError::Denied,
                        ),
                    ) => {}
                    Err(error) => return Err(error),
                }
                last_examined = Some(candidate.item_id);
                if visible.len() == desired {
                    let more = index + 1 < batch_len || batch_next.is_some();
                    let next_cursor = if more {
                        Some(
                            self.store
                                .issue_caseload_cursor(
                                    actor,
                                    source_profile_id,
                                    movement,
                                    candidate.item_id,
                                )
                                .await?,
                        )
                    } else {
                        None
                    };
                    return Ok(Page {
                        items: visible,
                        next_cursor,
                        status: PageStatus::Complete,
                    });
                }
                if scanned == policy.maximum_candidate_scan {
                    let more = index + 1 < batch_len || batch_next.is_some();
                    let next_cursor = if more {
                        Some(
                            self.store
                                .issue_caseload_cursor(
                                    actor,
                                    source_profile_id,
                                    movement,
                                    candidate.item_id,
                                )
                                .await?,
                        )
                    } else {
                        None
                    };
                    return Ok(Page {
                        items: visible,
                        next_cursor,
                        status: if more {
                            PageStatus::BudgetExhausted
                        } else {
                            PageStatus::Complete
                        },
                    });
                }
            }
            let Some(cursor) = batch_next else {
                return Ok(Page {
                    items: visible,
                    next_cursor: None,
                    status: PageStatus::Complete,
                });
            };
            next = Some(cursor);
        }
    }

    pub async fn apply_caseload_move(
        &self,
        actor: &ActorContext,
        source_profile_id: Option<&str>,
        token: &str,
        request: &CaseloadApplyRequest,
        idempotency_key: &str,
    ) -> Result<Vec<CaseloadItemResult>, ServiceError> {
        validate_reason(
            idempotency_key,
            MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES,
            false,
        )?;
        validate_reason(&request.movement.reason, MAXIMUM_REASON_BYTES, false)?;
        if request.items.is_empty()
            || request.items.len() > 100
            || request.movement.from == request.movement.to
            || request.items.iter().any(|item| item.expected_revision <= 0)
            || request
                .items
                .iter()
                .map(|item| item.item_id)
                .collect::<BTreeSet<_>>()
                .len()
                != request.items.len()
        {
            return Err(ServiceError::Store(StoreError::Invalid));
        }
        if actor.role != CaseworkRole::Supervisor {
            return Err(ServiceError::Store(StoreError::Forbidden));
        }
        self.store
            .reserve_caseload_apply(actor, request, idempotency_key)
            .await?;
        let mut results = Vec::with_capacity(request.items.len());
        for selection in &request.items {
            match self
                .assignment_visible_item(actor, source_profile_id, token, selection.item_id)
                .await
            {
                Ok(_) => {}
                Err(
                    ServiceError::NotFound
                    | ServiceError::Store(StoreError::NotFound)
                    | ServiceError::Adapter(
                        registry_casework_core::SourceAdapterError::Concealed
                        | registry_casework_core::SourceAdapterError::Denied,
                    ),
                ) => {
                    results.push(CaseloadItemResult {
                        item_id: selection.item_id,
                        result: CaseloadItemOutcome::NotVisible,
                        revision: None,
                    });
                    continue;
                }
                Err(error) => return Err(error),
            }
            let key = assignment_hash(&(idempotency_key, selection.item_id))?;
            let moved = self
                .store
                .move_caseload_item(
                    actor,
                    selection.item_id,
                    selection.expected_revision,
                    &request.movement.from,
                    &request.movement.to,
                    request.movement.queue_id.as_deref(),
                    &request.movement.reason,
                    &key,
                )
                .await;
            let result = match moved {
                Ok(value) => CaseloadItemResult {
                    item_id: selection.item_id,
                    result: CaseloadItemOutcome::Moved,
                    revision: Some(value.revision),
                },
                Err(StoreError::Conflict) => CaseloadItemResult {
                    item_id: selection.item_id,
                    result: CaseloadItemOutcome::Conflict,
                    revision: None,
                },
                Err(StoreError::AttemptPending) => CaseloadItemResult {
                    item_id: selection.item_id,
                    result: CaseloadItemOutcome::AttemptInProgress,
                    revision: None,
                },
                Err(StoreError::Forbidden) => CaseloadItemResult {
                    item_id: selection.item_id,
                    result: CaseloadItemOutcome::NotEligible,
                    revision: None,
                },
                Err(StoreError::NotFound) => CaseloadItemResult {
                    item_id: selection.item_id,
                    result: CaseloadItemOutcome::NotVisible,
                    revision: None,
                },
                Err(error) => return Err(error.into()),
            };
            results.push(result);
        }
        Ok(results)
    }

    async fn assignment_visible_item(
        &self,
        actor: &ActorContext,
        source_profile_id: Option<&str>,
        token: &str,
        item_id: Uuid,
    ) -> Result<(AssignmentOrigin, WorkItem), ServiceError> {
        let origin = self.store.assignment_origin(item_id).await?;
        let item = self
            .assignment_visible_item_for_origin(actor, source_profile_id, token, item_id, origin)
            .await?;
        Ok((origin, item))
    }
    async fn assignment_visible_item_for_origin(
        &self,
        actor: &ActorContext,
        source_profile_id: Option<&str>,
        token: &str,
        item_id: Uuid,
        origin: AssignmentOrigin,
    ) -> Result<WorkItem, ServiceError> {
        match origin {
            AssignmentOrigin::Source => self
                .caller_item(
                    actor,
                    item_id,
                    source_profile_id.ok_or(ServiceError::NotFound)?,
                    token,
                )
                .await
                .map(|value| value.0),
            AssignmentOrigin::Hosted => self.hosted_work_item(actor, item_id).await,
        }
    }

    pub async fn erase_expired_assignment_cursors(&self) -> Result<usize, ServiceError> {
        self.store
            .erase_expired_assignment_cursors()
            .await
            .map_err(ServiceError::from)
    }

    #[allow(clippy::too_many_arguments)]
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

    pub async fn reconcile_ineligible_assignments(
        &self,
        limit: usize,
    ) -> Result<usize, ServiceError> {
        self.store
            .reconcile_ineligible_assignments(limit)
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
fn valid_directory_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_DIRECTORY_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
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
fn principal_columns(
    row: &tokio_postgres::Row,
    issuer: usize,
    subject: usize,
) -> Result<Option<IssuerPrincipal>, StoreError> {
    match (
        row.get::<_, Option<String>>(issuer),
        row.get::<_, Option<String>>(subject),
    ) {
        (Some(issuer), Some(subject)) => Ok(Some(IssuerPrincipal { issuer, subject })),
        (None, None) => Ok(None),
        _ => Err(StoreError::Corrupt),
    }
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
async fn active_absences(
    tx: &Transaction<'_>,
    person: &IssuerPrincipal,
    now: chrono::DateTime<Utc>,
) -> Result<Vec<AbsenceRecord>, StoreError> {
    let rows = tx.query(
        "WITH RECURSIVE chain(absence_id,person_issuer,person_subject,starts_at,ends_at,cover_issuer,cover_subject,revision,depth) AS (SELECT absence_id,person_issuer,person_subject,starts_at,ends_at,cover_issuer,cover_subject,revision,1 FROM casework_absences WHERE person_issuer=$1 AND person_subject=$2 AND starts_at<=$3 AND $3<ends_at UNION ALL SELECT a.absence_id,a.person_issuer,a.person_subject,a.starts_at,a.ends_at,a.cover_issuer,a.cover_subject,a.revision,c.depth+1 FROM casework_absences a JOIN chain c ON a.person_issuer=c.cover_issuer AND a.person_subject=c.cover_subject WHERE a.starts_at<=$3 AND $3<a.ends_at AND c.depth<101) SELECT absence_id,person_issuer,person_subject,starts_at,ends_at,cover_issuer,cover_subject,revision,depth FROM chain ORDER BY depth,starts_at,absence_id LIMIT 102",
        &[&person.issuer,&person.subject,&now],
    ).await?;
    if rows.len() > 101 || rows.iter().any(|row| row.get::<_, i32>(8) >= 101) {
        return Err(StoreError::Corrupt);
    }
    rows.into_iter().map(absence_from_row).collect()
}
async fn ensure_no_source_attempt(tx: &Transaction<'_>, item_id: Uuid) -> Result<(), StoreError> {
    let exists:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM casework_attempts WHERE item_id=$1 AND state IN ('pending','uncertain'))",&[&item_id]).await?.get(0);
    if exists {
        Err(StoreError::AttemptPending)
    } else {
        Ok(())
    }
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
    actor: &ActorContext,
    revision: i64,
    kind: &str,
    detail: Value,
) -> Result<(), StoreError> {
    let event_id = Uuid::new_v4();
    let now = Utc::now();
    tx.execute("INSERT INTO casework_directory_events(event_id,directory_revision,event_kind,occurred_at,actor_issuer,actor_subject,profile_id,detail) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",&[&event_id,&revision,&kind,&now,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&detail]).await?;
    tx.execute("INSERT INTO casework_audit_outbox(event_id,audit_record) VALUES($1,$2)",&[&event_id,&json!({"event":format!("casework.{kind}"),"directoryRevision":revision,"actor":{"issuer":actor.principal.issuer,"subject":actor.principal.subject},"profileId":actor.profile_id,"detail":detail})]).await?;
    Ok(())
}

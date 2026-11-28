// SPDX-License-Identifier: Apache-2.0
//! Local answers are committed atomically with their revision and delivery job.
use super::*;
use crate::problem_location::RequestLocation;
use crate::review_store::asks::{answer_time, AnswerMutation};
use chrono::{DateTime, Utc};
use registry_platform_authcommon::FailedCheck;

impl MutationTransaction {
    pub(super) async fn commit_ask_answer(
        &self,
        tx: &Transaction<'_>,
        document: &ProposalDocument,
        answer: &AnswerMutation,
        actor: &str,
    ) -> Result<(), MutationError> {
        let row = tx.query_opt(
            "SELECT a.authority,a.review_request_id,a.wants,a.asked_at_wire,a.due_at_wire,a.state,
                    s.producer_id, EXISTS(SELECT 1 FROM registry_internal.registry_proposal_review_ask_answers x
                      WHERE x.authority=a.authority AND x.review_request_id=a.review_request_id AND x.ask_id=a.ask_id)
             FROM registry_internal.registry_proposal_review_asks a
             JOIN registry_internal.registry_proposal_review_submissions s USING(action_id,proposal_id,submission_version)
             WHERE a.action_id=$1 AND a.proposal_id=$2 AND a.submission_version=$3 AND a.ask_id=$4
               AND a.detail_erased_at IS NULL AND NOT s.withdrawn AND s.state='accepted'
               AND s.authority=a.authority AND s.accepted_binding->>'requestId'=a.review_request_id::text",
            &[&document.action_id,&document.proposal_id,&document.header.submission_version,&answer.ask_id]
        ).await.map_err(map_database_error)?.ok_or(MutationError::AuthorizationRefused(FailedCheck::Visibility))?;
        let now = Utc::now();
        let due = row
            .get::<_, Option<String>>(4)
            .map(|at| {
                at.parse::<DateTime<Utc>>()
                    .map_err(|_| MutationError::Unavailable)
            })
            .transpose()?;
        if row.get::<_, String>(5) != "open"
            || row.get::<_, bool>(7)
            || due.is_some_and(|at| at <= now)
        {
            return Err(MutationError::PreconditionFailed);
        }
        let wants: Vec<registry_review_client::ReviewAskWant> =
            serde_json::from_value(row.get(2)).map_err(|_| MutationError::Unavailable)?;
        answer.body.validate(&wants).map_err(|field| {
            MutationError::InvalidRequestAt(if field == "text" {
                RequestLocation::proposal_answer_text()
            } else {
                RequestLocation::proposal_answer_additions()
            })
        })?;
        let asked: DateTime<Utc> = row
            .get::<_, String>(3)
            .parse()
            .map_err(|_| MutationError::Unavailable)?;
        let answered_at = answer_time(now, asked).ok_or(MutationError::Unavailable)?;
        if due.is_some_and(|at| answered_at > at) {
            return Err(MutationError::PreconditionFailed);
        }
        let authority: String = row.get(0);
        let request: Uuid = row.get(1);
        let producer: String = row.get(6);
        let configured = self
            .review_authorities
            .as_ref()
            .filter(|configured| configured.contains_binding(&authority, &producer))
            .ok_or(MutationError::Unavailable)?;
        let days = configured
            .recovery_days(&authority)
            .ok_or(MutationError::Unavailable)?;
        let deadline = answered_at
            .checked_add_signed(chrono::Duration::days(i64::from(days)))
            .ok_or(MutationError::Unavailable)?;
        let earliest_file = answer_time(asked, asked).ok_or(MutationError::Unavailable)?;
        let eligible: i64 = tx.query_one("SELECT count(*) FROM registry_internal.registry_proposal_additions f WHERE f.action_id=$1 AND f.proposal_id=$2 AND f.submission_version=$3 AND f.addition_id=ANY($4::uuid[]) AND f.erased_at IS NULL AND f.added_at >= $5 AND NOT EXISTS (SELECT 1 FROM registry_internal.registry_proposal_review_ask_files c WHERE c.action_id=f.action_id AND c.proposal_id=f.proposal_id AND c.submission_version=f.submission_version AND c.addition_id=f.addition_id)",&[&document.action_id,&document.proposal_id,&document.header.submission_version,&answer.body.additions,&earliest_file]).await.map_err(map_database_error)?.get(0);
        if eligible != answer.body.additions.len() as i64 {
            return Err(MutationError::InvalidRequestAt(
                RequestLocation::proposal_answer_additions(),
            ));
        }
        let key_material = canonicalize_json(
            &json!({"authority":authority,"requestId":request,"askId":answer.ask_id}),
        )
        .map_err(|_| MutationError::Unavailable)?;
        let key = format!(
            "proposal-answer:{}",
            hex_bytes(&Sha256::digest(key_material))
        );
        tx.execute("INSERT INTO registry_internal.registry_proposal_review_ask_answers (authority,review_request_id,ask_id,action_id,proposal_id,submission_version,text,answered_by,answered_at,delivery_key,delivery_state,delivery_deadline) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending',$11)",&[&authority,&request,&answer.ask_id,&document.action_id,&document.proposal_id,&document.header.submission_version,&answer.body.text,&actor,&answered_at,&key,&deadline]).await.map_err(map_database_error)?;
        for addition in &answer.body.additions {
            tx.execute("INSERT INTO registry_internal.registry_proposal_review_ask_files(authority,review_request_id,ask_id,action_id,proposal_id,submission_version,addition_id) VALUES($1,$2,$3,$4,$5,$6,$7)",&[&authority,&request,&answer.ask_id,&document.action_id,&document.proposal_id,&document.header.submission_version,addition]).await.map_err(map_database_error)?;
        }
        // The mirror keeps the provider's state. The local answer row makes
        // the applicant document answered and ends the party's turn immediately.
        Ok(())
    }
}

impl MutationTransaction {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn append_public_asks(
        &self,
        tx: &Transaction<'_>,
        registry: &CompiledRegistry,
        document: &ProposalDocument,
        current: &ProposalAuthority,
        claims: &crate::api::VerifiedRequestClaims,
        frozen: Option<&crate::proposal_workflow::ProposalSnapshot>,
        value: &mut Value,
    ) -> Result<(), MutationError> {
        let rows = ask_rows(tx, document, None).await?;
        if rows.is_empty() {
            return Ok(());
        }
        let action = proposal_action(registry, &document.action_id)?;
        let write = crate::api::proposals::authorize(
            registry,
            action,
            claims,
            Some(current.common.access_profile()),
            ProposalAuthorityOperation::Lifecycle(ProposalOperation::Answer),
            Some(document.proposal_id),
        );
        // Questions and answers reach only the party who may answer on this
        // Proposal. The Answer admission carries the human test, so other Get
        // holders, agents and services receive no `asks` member at all.
        let Some(write) = write else {
            return Ok(());
        };
        if !link_readable(
            self.check_proposal_document(tx, registry, document, &write, false)
                .await,
        )? {
            return Ok(());
        }
        let progress = match frozen {
            Some(frozen) => review_progress(tx, document, frozen).await?,
            None => ProposalReviewProgress::NotRequired,
        };
        let shared = if document.header.state == "applied" {
            Some(LinkRefusal::AlreadyApplied)
        } else if document.header.state == "rejected" {
            Some(LinkRefusal::Rejected)
        } else if document.header.state != "submitted" || document.header.current_proposal_erased {
            Some(LinkRefusal::WrongState)
        } else if document.blocked_reason.as_deref() == Some("application-refused") {
            Some(LinkRefusal::ReviseInput)
        } else if document.blocked_reason.as_deref() == Some("application-rebase") {
            Some(LinkRefusal::TargetChanged)
        } else if document.blocked_reason.is_some()
            || document.action_revision != action.definition_revision
        {
            Some(LinkRefusal::PackageChanged)
        } else if !matches!(
            progress,
            ProposalReviewProgress::Pending | ProposalReviewProgress::Retrying
        ) {
            Some(match progress {
                ProposalReviewProgress::Rejected => LinkRefusal::ReviewRejected,
                ProposalReviewProgress::ChangesRequested => LinkRefusal::ChangesRequested,
                _ => LinkRefusal::ReviewEnded,
            })
        } else {
            None
        };
        let now = Utc::now();
        let mut asks = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.get(0);
            let answered: bool = row.get(6);
            let due: Option<String> = row.get(4);
            let state: String = row.get(5);
            let due_passed = due
                .as_deref()
                .map(|due| {
                    due.parse::<DateTime<Utc>>()
                        .map(|due| due <= now)
                        .map_err(|_| MutationError::Unavailable)
                })
                .transpose()?
                .unwrap_or(false);
            let mut ask = ask_value(&row);
            let refusal = shared.or_else(|| {
                if answered {
                    Some(LinkRefusal::AskAnswered)
                } else if state != "open" {
                    Some(LinkRefusal::AskClosed)
                } else if due_passed {
                    Some(LinkRefusal::AskDuePassed)
                } else {
                    None
                }
            });
            ask["links"] = json!({"answer":{"method":"POST","path":format!("/v1/proposals/{}/asks/{id}/answer",document.proposal_id),"accessProfile":write.common.access_profile(),"operation":"answer","ifMatch":self.proposal_etag(document,&write)?,"availability":ProposalAvailability::new(document.header.workflow_revision as u64,refusal)}});
            asks.push(ask);
        }
        value["asks"] = json!(asks);
        Ok(())
    }
}

/// Fixed disclosure markers and admitted download correlation, never answer contents.
#[derive(Default)]
pub(crate) struct ProposalReadDisclosure {
    pub(crate) field_set_reference: Option<&'static str>,
    pub(crate) asks: bool,
    pub(crate) ask_download: Option<(Uuid, Uuid)>,
}
const ASK_REFERENCE: &str = "proposal-review-ask";
impl ProposalReadDisclosure {
    pub(crate) fn for_value(value: &Value) -> Self {
        Self {
            field_set_reference: value
                .pointer("/decision/publicReason")
                .is_some()
                .then_some(PUBLIC_REASON_REFERENCE),
            asks: value
                .get("asks")
                .or_else(|| value.pointer("/context/asks"))
                .and_then(Value::as_array)
                .is_some_and(|asks| !asks.is_empty()),
            ask_download: None,
        }
    }
    pub(crate) fn for_list(value: &Value, action: &str) -> Self {
        let mut disclosure = Self::default();
        if let Some(items) = value["items"].as_array() {
            for item in items
                .iter()
                .filter(|item| item["actionId"].as_str() == Some(action))
            {
                let next = Self::for_value(item);
                disclosure.asks |= next.asks;
                disclosure.field_set_reference =
                    disclosure.field_set_reference.or(next.field_set_reference);
            }
        }
        disclosure
    }
    pub(super) fn annotate(
        &self,
        entry: AuditEntry,
        correlation: &RequestCorrelation,
    ) -> AuditEntry {
        let mut record = entry.record().clone();
        if self.asks {
            record["askFieldSetReference"] = json!(ASK_REFERENCE);
            if self.field_set_reference.is_none() {
                record["fieldSetReference"] = json!(ASK_REFERENCE);
            }
        }
        if let Some((ask, file)) = self.ask_download {
            record["reviewAskId"] = json!(ask);
            record["additionId"] = json!(file);
        }
        AuditEntry::response(
            crate::audit::AUDIT_SCHEMA,
            correlation.request_id().to_string(),
            record,
        )
    }
}

async fn ask_rows(
    tx: &Transaction<'_>,
    document: &ProposalDocument,
    binding: Option<(&str, Uuid)>,
) -> Result<Vec<tokio_postgres::Row>, MutationError> {
    tx.query("SELECT a.ask_id,a.text,a.wants,a.asked_at_wire,a.due_at_wire,a.state,x.ask_id IS NOT NULL,x.text,x.answered_at,ARRAY(SELECT c.addition_id FROM registry_internal.registry_proposal_review_ask_files c WHERE c.authority=a.authority AND c.review_request_id=a.review_request_id AND c.ask_id=a.ask_id ORDER BY c.addition_id) FROM registry_internal.registry_proposal_review_asks a LEFT JOIN registry_internal.registry_proposal_review_ask_answers x USING(authority,review_request_id,ask_id) WHERE a.action_id=$1 AND a.proposal_id=$2 AND a.submission_version=$3 AND a.text IS NOT NULL AND a.detail_erased_at IS NULL AND ($4::text IS NULL OR (a.authority=$4 AND a.review_request_id=$5 AND EXISTS (SELECT 1 FROM registry_internal.registry_proposal_review_submissions s WHERE s.action_id=a.action_id AND s.proposal_id=a.proposal_id AND s.submission_version=a.submission_version AND s.authority=a.authority AND s.accepted_binding->>'requestId'=a.review_request_id::text AND NOT s.withdrawn AND s.state='accepted'))) ORDER BY a.asked_at_wire DESC,a.ask_id DESC LIMIT $6",&[&document.action_id,&document.proposal_id,&document.header.submission_version,&binding.map(|b|b.0),&binding.map(|b|b.1),&(crate::contract::MAX_MIRRORED_REVIEW_ASKS as i64)]).await.map_err(map_database_error)
}

fn ask_value(row: &tokio_postgres::Row) -> Value {
    let answered: bool = row.get(6);
    let state: String = row.get(5);
    let mut value = json!({"id":row.get::<_,Uuid>(0),"text":row.get::<_,String>(1),"wants":row.get::<_,Value>(2),"askedAt":row.get::<_,String>(3),"state":if answered{"answered"}else{&state}});
    if let Some(due) = row.get::<_, Option<String>>(4) {
        value["dueAt"] = json!(due);
    }
    if answered {
        let at: DateTime<Utc> = row.get(8);
        let files: Vec<Uuid> = row.get(9);
        let mut answer = json!({"additions":files,"answeredAt":at});
        if let Some(text) = row.get::<_, Option<String>>(7) {
            answer["text"] = json!(text);
        }
        value["answer"] = answer;
    }
    value
}

impl MutationTransaction {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn intrinsic_asks(
        &self,
        tx: &Transaction<'_>,
        registry: &CompiledRegistry,
        document: &ProposalDocument,
        authority: &ProposalAuthority,
        frozen: &crate::proposal_workflow::ProposalSnapshot,
        schema_digest: &str,
    ) -> Result<Value, MutationError> {
        let CompiledProposalReview::Required {
            authority: review_authority,
            ..
        } = frozen.review_requirement()
        else {
            return Ok(json!([]));
        };
        let Some(binding) = crate::review_store::load_status_binding(
            tx,
            registry,
            &document.action_id,
            document.proposal_id,
            frozen,
        )
        .await?
        else {
            return Ok(json!([]));
        };
        let rows = ask_rows(tx, document, Some((review_authority, binding.request_id))).await?;
        let has_files = rows
            .iter()
            .any(|row| !row.get::<_, Vec<Uuid>>(9).is_empty());
        let metadata = if has_files {
            self.verify_proposal_attachment_binding(tx).await?;
            let action = proposal_action(registry, &document.action_id)?;
            let CompiledActionExecution::Proposal { proposal } = &action.execution else {
                return Err(MutationError::Unavailable);
            };
            let slot = proposal
                .additions
                .as_ref()
                .ok_or(MutationError::Unavailable)?;
            crate::attachment_store::additions::metadata(
                tx,
                &document.action_id,
                document.proposal_id,
                document.header.submission_version,
                &slot.id,
            )
            .await?
        } else {
            Vec::new()
        };
        let mut asks = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.get(0);
            let files: Vec<Uuid> = row.get(9);
            let mut ask = ask_value(&row);
            if let Some(answer) = ask.get_mut("answer").and_then(Value::as_object_mut) {
                answer.remove("additions");
                let mut documents = Vec::with_capacity(files.len());
                for file in files {
                    let file = metadata
                        .iter()
                        .find(|item| item.id == file)
                        .ok_or(MutationError::Unavailable)?;
                    let mut descriptor = json!({"id":file.id,"sha256":file.file.sha256,"contentType":file.file.content_type,"byteSize":file.file.byte_size,"verificationStatus":file.file.verification_status});
                    if file.file.verification_status.permits_content() {
                        let path=format!("/v1/proposals/{}/additions/{}?submissionVersion={}&reviewAskId={id}&effectDigest={}&contextSchemaDigest={}",document.proposal_id,file.id,frozen.version().get(),frozen.effect_digest().as_str().replace(':',"%3A"),schema_digest.replace(':',"%3A"));
                        descriptor["download"] = json!({"method":"GET","operation":"get-review-context","accessProfile":authority.common.access_profile(),"path":path});
                    }
                    documents.push(descriptor);
                }
                answer.insert("documents".into(), json!(documents));
            }
            asks.push(ask);
        }
        Ok(json!(asks))
    }
}

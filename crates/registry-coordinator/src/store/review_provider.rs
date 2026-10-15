// SPDX-License-Identifier: Apache-2.0
//! Review bindings live in their ordinary Run and share its admission fence.
use super::*;
use crate::review_provider::{
    RetainedReview, ReviewAdmission, ReviewCancellation, ReviewOutcome, ReviewProducer,
};
use registry_review_protocol::{
    ReviewCancelRequest, ReviewCancelResponse, ReviewCreateRequest, ReviewRequestAccepted,
    ReviewRequestLifecycle, ReviewRequestView, ReviewResult, ReviewResultFeedEntry,
    ReviewResultFeedPage, ReviewResultStatus,
};

pub enum ReviewLookup {
    Available(Box<ReviewResult>),
    Pending,
    Expired,
}

impl Store {
    fn review_owner(&self, actor: &Actor, producer: &ReviewProducer) -> Result<String> {
        self.owner(actor)?;
        if !producer.check() {
            return Err(refused(
                "access.denied",
                "an admitted Review producer is required",
            ));
        }
        Ok(self.security.keys.commitment(
            "review-owner",
            &[
                self.security.database_id.as_bytes(),
                actor.issuer.as_bytes(),
                actor.subject.as_bytes(),
                actor.client_id.as_bytes(),
                producer.id.as_bytes(),
                producer.source_namespace.as_bytes(),
            ],
        ))
    }

    fn review_admission_input(
        &self,
        request: &ReviewCreateRequest,
        actor: &Actor,
        producer: &ReviewProducer,
    ) -> Result<(Value, String)> {
        request
            .check()
            .map_err(|_| refused("request.invalid", "supply a bounded Review request"))?;
        if !producer.sources.contains(&request.subject.source) {
            return Err(refused(
                "access.denied",
                "the admitted producer and exact Review policy must match",
            ));
        }
        let owner = self.review_owner(actor, producer)?;
        let input = serde_json::to_value(request)
            .map_err(|_| refused("input-invalid", "cannot encode the Review input"))?;
        Ok((input, owner))
    }

    pub(super) async fn recover_review_admission(
        &self,
        tx: &Transaction<'_>,
        identity: &str,
        input_digest: &str,
    ) -> Result<Option<ReviewRequestAccepted>> {
        let Some(row) = tx.query_opt(
            &format!("SELECT run_id,input_digest,event_binding,review FROM {}.runs WHERE start_identity=$1", self.namespace),
            &[&identity],
        ).await.map_err(unavailable)? else {
            return Ok(None);
        };
        if row.get::<_, String>(1) != input_digest || row.get::<_, Option<String>>(2).is_some() {
            return Err(refused(
                "start-conflict",
                "this producer, workflow and idempotency key already names different admitted work",
            ));
        }
        // Return the original concrete acceptance without consulting an active
        // package. Erasure never recreates acceptance from current configuration.
        let run_id = row.get(0);
        let sealed = row
            .get::<_, Option<Value>>(3)
            .ok_or_else(|| refused("payload-erased", "the Review request payload was erased"))?;
        let retained: RetainedReview = self.open_value(run_id, "review", "", &sealed)?;
        Ok(Some(retained.accepted))
    }

    /// Caller workflow authorization is checked by the HTTP boundary; current
    /// producer ownership and source authorization also apply before replay.
    /// The HTTP boundary audits replay and fresh admission as one operation.
    pub(crate) async fn recover_review_owned(
        &self,
        request: &ReviewCreateRequest,
        actor: &Actor,
        producer: &ReviewProducer,
        key: &str,
    ) -> Result<Option<ReviewRequestAccepted>> {
        let (input, owner) = self.review_admission_input(request, actor, producer)?;
        let (identity, input_digest) =
            self.admission_identity(&request.policy.id, &owner, key, &input)?;
        let mut client = self.client().await.map_err(unavailable)?;
        let tx = client.transaction().await.map_err(unavailable)?;
        self.lock_admission(&tx).await?;
        let accepted = self
            .recover_review_admission(&tx, &identity, &input_digest)
            .await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(accepted)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Review admission binds caller, producer, exact policy and runtime independently"
    )]
    pub async fn admit_review_owned(
        &self,
        definition: &Definition,
        request: ReviewCreateRequest,
        actor: &Actor,
        producer: &ReviewProducer,
        key: &str,
        binding: &str,
        runtime: &crate::runtime::RuntimeConfig,
    ) -> Result<ReviewRequestAccepted> {
        self.audited("review-admit", actor, None, None, async {
            self.admit_review_bound(definition, request, actor, producer, key, binding, runtime)
                .await
        })
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Review admission binds caller, producer, exact policy and runtime independently"
    )]
    pub(crate) async fn admit_review_bound(
        &self,
        definition: &Definition,
        request: ReviewCreateRequest,
        actor: &Actor,
        producer: &ReviewProducer,
        key: &str,
        binding: &str,
        runtime: &crate::runtime::RuntimeConfig,
    ) -> Result<ReviewRequestAccepted> {
        let (input, owner) = self.review_admission_input(&request, actor, producer)?;
        let admission = ReviewAdmission {
            request,
            producer: producer.clone(),
        };
        let admission = self
            .admit_bound(
                definition,
                input,
                &owner,
                key,
                binding,
                Some(runtime),
                &definition.digest,
                Some(&admission),
                None,
            )
            .await?;
        admission
            .accepted_review
            .ok_or_else(|| unavailable("Review admission did not retain its accepted binding"))
    }

    fn review_sources(&self, owner: &str, producer: &ReviewProducer) -> Vec<String> {
        producer
            .sources
            .iter()
            .map(|source| {
                self.security.keys.commitment(
                    "review-source",
                    &[
                        self.security.database_id.as_bytes(),
                        owner.as_bytes(),
                        source.as_bytes(),
                    ],
                )
            })
            .collect()
    }

    /// Current producer ownership and workflow authorization apply to every
    /// protected read, even when a request has an immutable terminal result.
    async fn review_row(
        &self,
        tx: &Transaction<'_>,
        run: Uuid,
        actor: &Actor,
        producer: &ReviewProducer,
        workflows: &[String],
    ) -> Result<(Row, DateTime<Utc>)> {
        self.verify_transaction(tx).await.map_err(unavailable)?;
        // Restore takes control before Run rows. Holding this shared fence
        // before the job/Run locks keeps result release linear with a hold.
        tx.query_one(
            &format!(
                "SELECT restore_hold FROM {}.control WHERE id FOR SHARE",
                self.namespace
            ),
            &[],
        )
        .await
        .map_err(unavailable)?;
        let owner = self.review_owner(actor, producer)?;
        let sources = self.review_sources(&owner, producer);
        let predicate = "r.run_id=$1 AND r.owner_hash=$2 AND r.workflow_id=ANY($3) AND r.review_available_until IS NOT NULL AND r.review_source=ANY($4)";
        let query = format!("SELECT r.review,r.admitted_at,r.completed_at,r.deadline_at,r.state,r.outcome,r.payload_erased_at,r.step,r.snapshot,j.state,j.uncertain,r.authored_cancel_requested,EXISTS(SELECT 1 FROM {0}.completion_waits w WHERE w.run_id=r.run_id AND w.step=r.step),r.review_available_until,r.review_completed_at,r.restore_review_required,r.cancel_requested,(SELECT restore_hold FROM {0}.control WHERE id) FROM {0}.jobs j JOIN {0}.runs r ON r.run_id=j.run_id AND r.step=j.step WHERE {predicate} FOR UPDATE OF j,r", self.namespace);
        // READ COMMITTED may discard the old joined job after a worker advances
        // the locked Run. Four attempts tolerate nearby transitions while
        // bounding work; exhaustion is unavailable, never a false absence.
        for _ in 0..4 {
            tx.batch_execute("SAVEPOINT review_lookup")
                .await
                .map_err(unavailable)?;
            if let Some(row) = tx
                .query_opt(&query, &[&run, &owner, &workflows, &sources])
                .await
                .map_err(unavailable)?
            {
                tx.batch_execute("RELEASE SAVEPOINT review_lookup")
                    .await
                    .map_err(unavailable)?;
                // A SELECT projection can run before LockRows. Read the clock
                // separately after every required lock and retry has finished.
                let now = tx
                    .query_one("SELECT clock_timestamp()", &[])
                    .await
                    .map_err(unavailable)?
                    .get(0);
                return Ok((row, now));
            }
            // Release every attempted job/Run lock before any fresh lookup.
            // The control fence was acquired before the savepoint and remains.
            tx.batch_execute(
                "ROLLBACK TO SAVEPOINT review_lookup; RELEASE SAVEPOINT review_lookup",
            )
            .await
            .map_err(unavailable)?;
            let visible = tx
                .query_opt(
                    &format!("SELECT EXISTS(SELECT 1 FROM {0}.jobs j WHERE j.run_id=r.run_id AND j.step=r.step) FROM {0}.runs r WHERE {predicate}", self.namespace),
                    &[&run, &owner, &workflows, &sources],
                )
                .await
                .map_err(unavailable)?
                .ok_or_else(|| refused("run-absent", "Review request was not found"))?;
            if !visible.get::<_, bool>(0) {
                return Err(unavailable("the authorized Review has no current job"));
            }
        }
        Err(unavailable("the authorized Review kept advancing"))
    }

    async fn review_from_row(
        &self,
        tx: &Transaction<'_>,
        run: Uuid,
        row: &Row,
        producer: &ReviewProducer,
    ) -> Result<Option<RetainedReview>> {
        let Some(sealed) = row.get::<_, Option<Value>>(0) else {
            return Ok(None);
        };
        let mut review: RetainedReview = self.open_value(run, "review", "", &sealed)?;
        if !producer.sources.contains(&review.accepted.subject.source) {
            return Err(refused("run-absent", "Review request was not found"));
        }
        if review.result.is_none() {
            if row.get::<_, bool>(15) || row.get::<_, bool>(17) {
                return Ok(Some(review));
            }
            let completed_at: Option<DateTime<Utc>> = row.get(2);
            let deadline: DateTime<Utc> = row.get(3);
            let outcome: Option<String> = row.get(5);
            let mapping = if row.get::<_, String>(4) == "finished"
                && completed_at.is_some_and(|completed| completed <= deadline)
            {
                outcome.and_then(|outcome| review.policy.outcomes.get(&outcome).cloned())
            } else if matches!(
                row.get::<_, String>(4).as_str(),
                "cancelled" | "cancelled-after-effect"
            ) && completed_at.is_some_and(|completed| completed <= deadline)
            {
                Some(ReviewOutcome {
                    status: ReviewResultStatus::Cancelled,
                    outcome: None,
                })
            } else {
                None
            };
            if let (Some(mapping), Some(completed_at)) = (mapping, completed_at) {
                let result = review.terminal(&mapping, completed_at)?;
                self.save_review_result(tx, run, &mut review, result)
                    .await?;
            }
        }
        Ok(Some(review))
    }

    async fn save_review_result(
        &self,
        tx: &Transaction<'_>,
        run: Uuid,
        review: &mut RetainedReview,
        result: ReviewResult,
    ) -> Result<()> {
        let completed = result.completed_at;
        let until = result.available_until;
        review.result = Some(result);
        tx.execute(&format!("UPDATE {}.runs SET review=$2,review_completed_at=$3,review_available_until=$4 WHERE run_id=$1", self.namespace), &[&run,&self.seal(run,"review","",review)?,&completed,&until]).await.map_err(unavailable)?;
        Ok(())
    }

    pub async fn review_request_owned(
        &self,
        run: Uuid,
        actor: &Actor,
        producer: &ReviewProducer,
        workflows: &[String],
    ) -> Result<ReviewRequestView> {
        self.audited("review-status", actor, Some(run), None, async {
            let mut client = self.client().await.map_err(unavailable)?;
            let tx = client.transaction().await.map_err(unavailable)?;
            let (row, _) = self
                .review_row(&tx, run, actor, producer, workflows)
                .await?;
            let review = self
                .review_from_row(&tx, run, &row, producer)
                .await?
                .ok_or_else(|| {
                    refused("payload-erased", "the Review request payload was erased")
                })?;
            let held = row.get::<_, bool>(15) || row.get::<_, bool>(17);
            let lifecycle = if held {
                ReviewRequestLifecycle::Reviewing
            } else {
                review
                    .result
                    .as_ref()
                    .map_or(ReviewRequestLifecycle::Reviewing, |result| {
                        lifecycle(result.status)
                    })
            };
            let view = ReviewRequestView {
                request_id: run,
                subject: review.accepted.subject,
                policy: review.accepted.policy,
                submission_digest: review.accepted.submission_digest,
                requester_reference: review.requester_reference,
                lifecycle,
                active_stage: matches!(lifecycle, ReviewRequestLifecycle::Reviewing)
                    .then(|| row.get(7)),
                created_at: row.get(1),
                updated_at: if held {
                    row.get(1)
                } else {
                    review
                        .result
                        .map_or_else(|| row.get(1), |result| result.completed_at)
                },
            };
            tx.commit().await.map_err(unavailable)?;
            Ok(view)
        })
        .await
    }

    pub async fn review_result_owned(
        &self,
        run: Uuid,
        actor: &Actor,
        producer: &ReviewProducer,
        workflows: &[String],
    ) -> Result<ReviewLookup> {
        self.audited("review-result", actor, Some(run), None, async {
            let mut client = self.client().await.map_err(unavailable)?;
            let tx = client.transaction().await.map_err(unavailable)?;
            let (row, now) = self
                .review_row(&tx, run, actor, producer, workflows)
                .await?;
            let review = self.review_from_row(&tx, run, &row, producer).await?;
            let lookup = match review
                .filter(|_| !row.get::<_, bool>(15) && !row.get::<_, bool>(17))
                .and_then(|review| review.result)
            {
                Some(result) if now < result.available_until => {
                    ReviewLookup::Available(Box::new(result))
                }
                Some(_) => ReviewLookup::Expired,
                None if row.get::<_, Option<DateTime<Utc>>>(6).is_some()
                    || now >= row.get::<_, DateTime<Utc>>(3) =>
                {
                    ReviewLookup::Expired
                }
                None => ReviewLookup::Pending,
            };
            tx.commit().await.map_err(unavailable)?;
            Ok(lookup)
        })
        .await
    }

    pub async fn cancel_review_owned(
        &self,
        run: Uuid,
        actor: &Actor,
        producer: &ReviewProducer,
        workflows: &[String],
        key: &str,
        cancellation: &ReviewCancelRequest,
    ) -> Result<ReviewCancelResponse> {
        cancellation.check().map_err(|_| {
            refused(
                "request.invalid",
                "supply the bound subject and bounded cancellation reason",
            )
        })?;
        if key.is_empty() || key.len() > 256 {
            return Err(refused(
                "start-key-invalid",
                "supply a bounded cancellation key",
            ));
        }
        self.audited("review-cancel",actor,Some(run),Some(&cancellation.reason),async {
            let mut client=self.client().await.map_err(unavailable)?;
            let tx=client.transaction().await.map_err(unavailable)?;
            let (row,now)=self.review_row(&tx,run,actor,producer,workflows).await?;
            if row.get::<_,bool>(15) || row.get::<_,bool>(17) { return Err(refused("restore-hold","Review cancellation and result release remain held until recovery is attested")); }
            let mut review=self.review_from_row(&tx,run,&row,producer).await?.ok_or_else(||refused("review-result-expired","the Review result expired"))?;
            if review.result.as_ref().is_some_and(|result|now>=result.available_until)
                || (review.result.is_none() && now>=row.get::<_,DateTime<Utc>>(3)) {
                return Err(refused("review-result-expired","the original Review availability expired; cancellation cannot renew it"));
            }
            if cancellation.subject!=review.accepted.subject { return Err(refused("start-conflict","the cancellation subject does not match")); }
            let key_digest=self.security.keys.commitment("review-cancel-key",&[run.as_bytes(),key.as_bytes()]);
            let bytes=registry_review_protocol::canonical_bytes(cancellation).map_err(|_|refused("request.invalid","supply a bounded cancellation"))?;
            let request_digest=self.security.keys.commitment("review-cancel-input",&[run.as_bytes(),&bytes]);
            if let Some(previous)=&review.cancellation {
                if previous.key_digest==key_digest && previous.request_digest!=request_digest {return Err(refused("start-conflict","the cancellation key already names different work"));}
            }
            if let Some(result)=review.result {
                tx.commit().await.map_err(unavailable)?;
                return Ok(ReviewCancelResponse::AlreadyTerminal{result});
            }
            // Match Dispatch's job-then-run lock order. The upstream decision
            // is final immediately; authored downstream withdrawal may continue.
            let step:String=row.get(7);
            let job_state:String=row.get(9);
            let authored=if row.get::<_,bool>(12) && !row.get::<_,bool>(11) {
                let snapshot:Option<Value>=row.get(8);
                let snapshot:String=self.open_value(run,"snapshot","",snapshot.as_ref().ok_or_else(||unavailable("active Review wait has no snapshot"))?)?;
                let definition=self.definition(&snapshot)?;
                if matches!(definition.workflow.steps.get(&step),Some(Step::WaitFor{on_cancel:Some(_),..})) { Some(definition) } else { None }
            } else {None};
            if let Some(definition)=authored {
                if job_state=="leased" {
                    tx.execute(&format!("UPDATE {}.runs SET authored_cancel_requested=true,authored_cancel_pending_step=$2 WHERE run_id=$1",self.namespace),&[&run,&step]).await.map_err(unavailable)?;
                } else {self.route_authored_cancel(&tx,run,&step,&definition,true).await.map_err(unavailable)?;}
            } else {
                tx.execute(&format!("UPDATE {}.runs SET cancel_requested=true,state=CASE WHEN $2='leased' OR $3 THEN 'attention' ELSE 'cancelled' END,completed_at=CASE WHEN $2='leased' OR $3 THEN completed_at ELSE transaction_timestamp() END WHERE run_id=$1",self.namespace),&[&run,&job_state,&row.get::<_,bool>(10)]).await.map_err(unavailable)?;
                self.end_waits(&tx,run,&step,false).await.map_err(unavailable)?;
            }
            review.cancellation=Some(ReviewCancellation{key_digest,request_digest});
            let result=review.terminal(&ReviewOutcome{status:ReviewResultStatus::Cancelled,outcome:None},now)?;
            self.save_review_result(&tx,run,&mut review,result.clone()).await?;
            tx.commit().await.map_err(unavailable)?;
            Ok(ReviewCancelResponse::Cancelled{result})
        }).await
    }

    pub async fn review_results_owned(
        &self,
        actor: &Actor,
        producer: &ReviewProducer,
        workflows: &[String],
        cursor: Option<Uuid>,
        limit: u32,
    ) -> Result<ReviewResultFeedPage> {
        self.audited("review-feed",actor,None,None,async {
            const MAX_SCANNED_CANDIDATES: usize = 1_000;
            if !(1..=100).contains(&limit) { return Err(refused("request.invalid","choose a Review feed limit from 1 to 100")); }
            let mut client=self.client().await.map_err(unavailable)?;
            let tx=client.transaction().await.map_err(unavailable)?;
            self.verify_transaction(&tx).await.map_err(unavailable)?;
            let owner=self.review_owner(actor,producer)?;
            let sources=self.review_sources(&owner,producer);
            let after=if let Some(cursor)=cursor {
                Some(tx.query_opt(&format!("SELECT COALESCE(review_completed_at,completed_at) FROM {}.runs WHERE run_id=$1 AND owner_hash=$2 AND workflow_id=ANY($3) AND review_available_until IS NOT NULL AND review_source=ANY($4)",self.namespace),&[&cursor,&owner,&workflows,&sources]).await.map_err(unavailable)?.and_then(|row|row.get::<_,Option<DateTime<Utc>>>(0)).ok_or_else(||refused("request.invalid","use a cursor from this producer's Review feed"))?)
            } else {None};
            let mut scan_after=after;
            let mut scan_cursor=cursor;
            let mut scanned=0;
            let mut items=Vec::new();
            loop {
                let ids=tx.query(&format!("SELECT run_id,COALESCE(review_completed_at,completed_at) FROM {0}.runs WHERE owner_hash=$1 AND workflow_id=ANY($2) AND review IS NOT NULL AND review_available_until>transaction_timestamp() AND (review_completed_at IS NOT NULL OR completed_at+(review_available_until-deadline_at)>transaction_timestamp()) AND review_source=ANY($6) AND NOT restore_review_required AND NOT(SELECT restore_hold FROM {0}.control WHERE id) AND (review_completed_at IS NOT NULL OR (state IN ('finished','cancelled','cancelled-after-effect') AND completed_at<=deadline_at)) AND ($3::timestamptz IS NULL OR (COALESCE(review_completed_at,completed_at),run_id)>($3,$4)) ORDER BY COALESCE(review_completed_at,completed_at),run_id LIMIT $5",self.namespace),&[&owner,&workflows,&scan_after,&scan_cursor,&(i64::from(limit)+1),&sources]).await.map_err(unavailable)?;
                let exhausted=ids.len()<=limit as usize;
                for id in ids {
                    if scanned==MAX_SCANNED_CANDIDATES {
                        return Err(unavailable("Review feed candidates changed during the page; retry the page"));
                    }
                    scanned+=1;
                    let run:Uuid=id.get(0);
                    scan_after=Some(id.get(1));
                    scan_cursor=Some(run);
                    let (row,now)=self.review_row(&tx,run,actor,producer,workflows).await?;
                    if let Some(result)=self.review_from_row(&tx,run,&row,producer).await?.and_then(|review|review.result).filter(|result| result.available_until>now && !row.get::<_,bool>(15) && !row.get::<_,bool>(17)) {
                        items.push(ReviewResultFeedEntry{event_id:result.result_id,request_id:run,result_id:result.result_id,completed_at:result.completed_at});
                    }
                    if items.len()>limit as usize { break; }
                }
                // A row can become held after the candidate query and before
                // its protected reload. Refill instead of treating the short
                // filtered window as the end of the producer's feed.
                if items.len()>limit as usize || exhausted { break; }
            }
            let next_cursor=if items.len()>limit as usize {items.truncate(limit as usize);items.last().map(|entry|entry.event_id)}else{None};
            tx.commit().await.map_err(unavailable)?;
            Ok(ReviewResultFeedPage{items,next_cursor})
        }).await
    }
}

fn lifecycle(status: ReviewResultStatus) -> ReviewRequestLifecycle {
    match status {
        ReviewResultStatus::Approved => ReviewRequestLifecycle::Approved,
        ReviewResultStatus::Rejected => ReviewRequestLifecycle::Rejected,
        ReviewResultStatus::ChangesRequested => ReviewRequestLifecycle::ChangesRequested,
        ReviewResultStatus::Answered => ReviewRequestLifecycle::Answered,
        ReviewResultStatus::Cancelled => ReviewRequestLifecycle::Cancelled,
        ReviewResultStatus::Superseded => ReviewRequestLifecycle::Superseded,
    }
}

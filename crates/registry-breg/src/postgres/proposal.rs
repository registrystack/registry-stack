// SPDX-License-Identifier: Apache-2.0

//! Pool orchestration keeps authenticated external review observations outside
//! PostgreSQL transactions and connections. The coordinator owns effects.
use super::*;
use crate::api::proposals::{ProposalListQuery, ProposalMutationInput};
use crate::api::VerifiedRequestClaims;
use crate::model::ProposalOperation;
use crate::mutation::ProposalApplyPreflight;
use crate::postgres::{begin_proposal_transaction, ProposalAuthority, ProposalAuthorityOperation};
use crate::proposal_store;
use std::collections::BTreeMap;

impl PostgresRecordMutationService {
    #[cfg(feature = "postgres-test")]
    async fn pause_proposal_read_for_test(&self) {
        if let Some(barrier) = &self.proposal_read_barrier_for_test {
            barrier.loaded.notify_one();
            barrier.resume.notified().await;
        }
    }

    async fn admitted_proposal_read_client(
        &self,
        authority: &ProposalAuthority,
        correlation: &crate::correlation::RequestCorrelation,
        deadline: tokio::time::Instant,
    ) -> Result<deadpool_postgres::Client, MutationError> {
        let result = tokio::time::timeout_at(deadline, async {
            if let Some(binding) = &authority.task_grant {
                self.coordinator.check_task_authority(binding).await?;
            }
            self.pool
                .get()
                .await
                .map_err(|_| MutationError::Unavailable)
        })
        .await
        .map_err(|_| MutationError::Unavailable)
        .and_then(|result| result);
        if result.is_err() {
            self.coordinator
                .record_proposal_refusal(authority, crate::model::HttpMethod::Get, correlation)
                .await?;
        }
        result
    }
    pub(crate) async fn record_proposal_http_refusal(
        &self,
        authority: &ProposalAuthority,
        method: crate::model::HttpMethod,
        correlation: &crate::correlation::RequestCorrelation,
    ) -> Result<(), MutationError> {
        self.coordinator
            .record_proposal_refusal(authority, method, correlation)
            .await
    }
    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub fn with_proposal_review_substitute_for_test(
        mut self,
        authorities: std::sync::Arc<crate::review_store::ReviewAuthorityRegistry>,
        source: std::sync::Arc<dyn crate::review_store::ReviewResultSource>,
    ) -> Self {
        self.coordinator = self.coordinator.with_review_authorities(authorities);
        self.review_result_source = Some(source);
        self
    }
    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub async fn run_automatic_proposal_once_for_test(&self) -> Result<bool, MutationError> {
        self.run_automatic_proposal_once().await
    }
    /// One bounded engine-owned automatic attempt. Claim and final effects are
    /// separately fenced; no caller token or profile is replayed by the worker.
    pub(crate) async fn run_automatic_proposal_once(&self) -> Result<bool, MutationError> {
        let claim = {
            let mut client = self
                .pool
                .get()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            let guarded = crate::postgres::context::begin_registry_transaction(
                &mut client,
                self.lock_key,
                self.lock_timeout,
                &self.expected,
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
            let tx = guarded.transaction();
            tx.execute("UPDATE registry_internal.registry_proposal_application_jobs
                SET state='blocked',claim_token=NULL,last_error_code='application-attempts-exhausted',
                    updated_at=transaction_timestamp()
                WHERE executor='builtin' AND attempt_count>=maximum_attempts
                  AND (state='queued' OR (state='applying' AND next_attempt_at<=transaction_timestamp()))",&[])
                .await.map_err(|_|MutationError::Unavailable)?;
            let token = Uuid::new_v4();
            let lease = i64::try_from(self.action_timeout.as_millis().saturating_add(30_000))
                .map_err(|_| MutationError::Unavailable)?;
            #[cfg(feature = "postgres-test")]
            let lease = self
                .automatic_proposal_lease_for_test
                .map(|override_lease| i64::try_from(override_lease.as_millis()).unwrap_or(lease))
                .unwrap_or(lease);
            let deadline = tokio::time::Instant::now() + self.action_timeout;
            let row=tx.query_opt("UPDATE registry_internal.registry_proposal_application_jobs j
                SET state='applying',attempt_count=j.attempt_count+1,claim_token=$1,
                    next_attempt_at=clock_timestamp()+($2::bigint*interval '1 millisecond'),updated_at=clock_timestamp()
                WHERE (j.action_id,j.proposal_id,j.submission_version)=(
                    SELECT q.action_id,q.proposal_id,q.submission_version
                    FROM registry_internal.registry_proposal_application_jobs q
                    JOIN registry_internal.registry_proposal_state s USING(action_id,proposal_id)
                    WHERE q.executor='builtin' AND q.state IN ('queued','applying')
                      AND q.attempt_count<q.maximum_attempts AND q.next_attempt_at<=transaction_timestamp()
                      AND s.state='submitted' AND s.submission_version=q.submission_version
                      AND s.blocked_reason IS NULL AND s.detail_erased_at IS NULL
                    ORDER BY q.next_attempt_at,q.created_at FOR UPDATE OF q SKIP LOCKED LIMIT 1)
                RETURNING j.action_id,j.proposal_id,j.submission_version,j.job_id,j.proposal_digest,j.system_grant_revision",
                &[&token,&lease]).await.map_err(|_|MutationError::Unavailable)?;
            let row = if let Some(row) = row {
                let action_id: String = row.get(0);
                let id: Uuid = row.get(1);
                let version: i64 = row.get(2);
                let workflow = proposal_store::load(tx, &action_id, id, false).await?;
                let frozen = workflow
                    .current_proposal()
                    .ok_or(MutationError::PreconditionFailed)?
                    .clone();
                if i64::from(frozen.version().get()) != version
                    || frozen.effect_digest().as_str() != row.get::<_, String>(4)
                    || frozen.system_grant_revision() != Some(row.get::<_, String>(5).as_str())
                {
                    return Err(MutationError::PreconditionFailed);
                }
                Some((
                    action_id,
                    id,
                    row.get::<_, Uuid>(3),
                    token,
                    frozen,
                    deadline,
                ))
            } else {
                None
            };
            guarded
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            row
        };
        let Some((action_id, id, job_id, claim_token, frozen, deadline)) = claim else {
            return Ok(false);
        };
        let result = async {
            let (authority, etag) = {
                let mut client = tokio::time::timeout_at(deadline, self.pool.get())
                    .await
                    .map_err(|_| MutationError::Unavailable)?
                    .map_err(|_| MutationError::Unavailable)?;
                let guarded = crate::postgres::context::begin_registry_transaction(
                    &mut client,
                    self.lock_key,
                    self.lock_timeout,
                    &self.expected,
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
                guarded
                    .set_statement_budget(
                        deadline.saturating_duration_since(tokio::time::Instant::now()),
                    )
                    .await
                    .map_err(|_| MutationError::Unavailable)?;
                let authority = ProposalAuthority::for_system(
                    guarded.transaction(),
                    &self.expected,
                    &self.registry,
                    &action_id,
                    id,
                    &frozen,
                )
                .await
                .map_err(|_| MutationError::PreconditionFailed)?;
                let document = proposal_store::load_document(
                    guarded.transaction(),
                    id,
                    proposal_store::DocumentLock::None,
                )
                .await?;
                let etag = self.coordinator.proposal_etag(&document, &authority)?;
                guarded
                    .commit()
                    .await
                    .map_err(|_| MutationError::Unavailable)?;
                (authority, etag)
            };
            let correlation = crate::correlation::RequestCorrelation::breg_created();
            let key = format!("breg-proposal-automatic-{job_id}");
            self.proposal_mutation_with_deadline(
                ProposalMutationInput {
                    action_id: &action_id,
                    proposal_id: Some(id),
                    operation: ProposalAuthorityOperation::Lifecycle(ProposalOperation::Apply),
                    authority: &authority,
                    idempotency_key: &key,
                    expected_etag: Some(&etag),
                    input: None,
                    submission_version: Some(frozen.version().get()),
                    effect_digest: Some(frozen.effect_digest().as_str()),
                    reason: None,
                    executor_lease: Some(crate::api::proposals::ExecutorLease {
                        job_id,
                        claim_token,
                    }),
                    rebase_start_authority: None,
                    attachment: None,
                    correlation: &correlation,
                    human_identity: None,
                    claims: None,
                },
                deadline,
            )
            .await
        }
        .await;
        if let Err(error) = result {
            let transient = matches!(
                error,
                MutationError::Unavailable | MutationError::CommitUnresolved
            );
            let client = self
                .pool
                .get()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            client.execute("UPDATE registry_internal.registry_proposal_application_jobs
                SET state=CASE WHEN ($6 OR next_attempt_at<=clock_timestamp()) AND attempt_count<maximum_attempts THEN 'queued' ELSE 'blocked' END,
                    claim_token=NULL,last_error_code=CASE WHEN next_attempt_at<=clock_timestamp() THEN 'lease-expired'
                        WHEN $6 THEN 'dependency-outage' ELSE 'application-refused' END,
                    next_attempt_at=transaction_timestamp()+interval '5 seconds',updated_at=transaction_timestamp()
                WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3 AND job_id=$4 AND claim_token=$5 AND state='applying'",
                &[&action_id,&id,&i64::from(frozen.version().get()),&job_id,&claim_token,&transient])
                .await.map_err(|_|MutationError::Unavailable)?;
        }
        Ok(true)
    }

    pub(crate) async fn proposal_attachment_download(
        &self,
        id: Uuid,
        version: u32,
        slot: &str,
        authority: &ProposalAuthority,
        correlation: &crate::correlation::RequestCorrelation,
    ) -> Result<(String, Vec<u8>), MutationError> {
        let _attempt = self
            .coordinator
            .begin_proposal_read_audit(authority, correlation)
            .await?;
        let deadline = tokio::time::Instant::now() + self.action_timeout;
        let client = self
            .admitted_proposal_read_client(authority, correlation, deadline)
            .await?;
        let mut guard = QueryCancellationGuard::new(self.pool.clone(), client);
        let result = tokio::time::timeout_at(deadline, async {
            let guarded = begin_proposal_transaction(
                guard.client(),
                self.lock_key,
                self.lock_timeout,
                &self.expected,
                authority,
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
            guarded
                .set_statement_budget(
                    deadline.saturating_duration_since(tokio::time::Instant::now()),
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
            let document = proposal_store::load_document(
                guarded.transaction(),
                id,
                proposal_store::DocumentLock::Update,
            )
            .await?;
            self.coordinator
                .authorize_proposal_document(
                    guarded.transaction(),
                    &self.registry,
                    &document,
                    authority,
                )
                .await?;
            if document.header.submission_version != i64::from(version) {
                return Err(MutationError::PreconditionFailed);
            }
            self.coordinator
                .verify_proposal_attachment_binding(guarded.transaction())
                .await?;
            let attachment = crate::attachment_store::load(
                guarded.transaction(),
                &document.action_id,
                id,
                i64::from(version),
                slot,
            )
            .await?
            .ok_or(MutationError::PreconditionFailed)?;
            // Current target, slot, quarantine and deletion-lock admission precede
            // the configured adapter's exact-hash read.
            if authority
                .task_grant
                .as_ref()
                .is_some_and(|binding| !binding.is_current())
            {
                return Err(MutationError::PreconditionFailed);
            }
            let bytes = self
                .coordinator
                .read_proposal_attachment(&attachment)
                .await?;
            if bytes.len() as u64 != attachment.metadata.byte_size
                || crate::attachment_store::content_hash(&bytes) != attachment.metadata.sha256
            {
                return Err(MutationError::Unavailable);
            }
            if authority
                .task_grant
                .as_ref()
                .is_some_and(|binding| !binding.is_current())
            {
                return Err(MutationError::PreconditionFailed);
            }
            guarded
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            self.coordinator
                .finish_proposal_read_audit(authority, Some(&document), 1, correlation)
                .await?;
            Ok((attachment.metadata.content_type, bytes))
        })
        .await;
        let result = match result {
            Ok(result) => {
                guard.disarm();
                result
            }
            Err(_) => {
                guard.cancel_and_discard().await;
                Err(MutationError::Unavailable)
            }
        };
        if result.is_err() {
            self.coordinator
                .record_proposal_refusal(authority, crate::model::HttpMethod::Get, correlation)
                .await?;
        }
        result
    }

    pub(crate) async fn proposal_action_id(
        &self,
        id: Uuid,
    ) -> Result<Option<String>, MutationError> {
        let deadline = tokio::time::Instant::now() + self.action_timeout;
        let client = tokio::time::timeout_at(deadline, self.pool.get())
            .await
            .map_err(|_| MutationError::Unavailable)?
            .map_err(|_| MutationError::Unavailable)?;
        let mut guard = QueryCancellationGuard::new(self.pool.clone(), client);
        match tokio::time::timeout_at(deadline,guard.client().query_opt(
            "SELECT action_id FROM registry_internal.registry_proposal_state WHERE proposal_id=$1",&[&id])).await {
            Ok(row)=>{guard.disarm();Ok(row.map_err(|_|MutationError::Unavailable)?.map(|row|row.get(0)))},
            Err(_)=>{guard.cancel_and_discard().await;Err(MutationError::Unavailable)},
        }
    }

    pub(crate) async fn proposal_mutation(
        &self,
        input: ProposalMutationInput<'_>,
    ) -> Result<MutationOutcome, MutationError> {
        self.proposal_mutation_with_deadline(
            input,
            tokio::time::Instant::now() + self.action_timeout,
        )
        .await
    }
    async fn proposal_mutation_with_deadline(
        &self,
        input: ProposalMutationInput<'_>,
        deadline: tokio::time::Instant,
    ) -> Result<MutationOutcome, MutationError> {
        let _audit = self.coordinator.begin_proposal_audit(&input).await?;
        let authority = input.authority;
        let correlation = input.correlation;
        let method = match &input.attachment {
            Some(attachment) if attachment.bytes.is_some() => crate::model::HttpMethod::Patch,
            Some(_) => crate::model::HttpMethod::Delete,
            None => crate::model::HttpMethod::Post,
        };
        let result = self.proposal_mutation_after_attempt(input, deadline).await;
        if result.is_err() {
            self.coordinator
                .record_proposal_refusal(authority, method, correlation)
                .await?;
        }
        result
    }

    async fn proposal_mutation_after_attempt(
        &self,
        input: ProposalMutationInput<'_>,
        deadline: tokio::time::Instant,
    ) -> Result<MutationOutcome, MutationError> {
        if let Some(binding) = &input.authority.task_grant {
            tokio::time::timeout_at(deadline, self.coordinator.check_task_authority(binding))
                .await
                .map_err(|_| MutationError::Unavailable)??;
        }
        let (review_evidence, commit_requests) =
            if input.operation == ProposalAuthorityOperation::Lifecycle(ProposalOperation::Apply) {
                let preflight = {
                    let client = tokio::time::timeout_at(deadline, self.pool.get())
                        .await
                        .map_err(|_| MutationError::Unavailable)?
                        .map_err(|_| MutationError::Unavailable)?;
                    let mut guard = QueryCancellationGuard::new(self.pool.clone(), client);
                    let preflight = tokio::time::timeout_at(
                        deadline,
                        self.coordinator.preflight_proposal_apply(
                            guard.client(),
                            &self.registry,
                            &input,
                        ),
                    )
                    .await;
                    match preflight {
                        Ok(result) => {
                            guard.disarm();
                            result?
                        }
                        Err(_) => {
                            guard.cancel_and_discard().await;
                            return Err(MutationError::Unavailable);
                        }
                    }
                };
                match preflight {
                    ProposalApplyPreflight::Receipt(receipt) => return Ok(receipt),
                    ProposalApplyPreflight::Continue {
                        review: None,
                        evidence,
                    } => (None, evidence),
                    ProposalApplyPreflight::Continue {
                        review: Some((authority, accepted, result_id)),
                        evidence,
                    } => {
                        let source = self
                            .review_result_source
                            .as_ref()
                            .ok_or(MutationError::Unavailable)?;
                        let fresh = tokio::time::timeout_at(
                            deadline,
                            source.approved_evidence(&authority, &accepted),
                        )
                        .await
                        .map_err(|_| MutationError::Unavailable)??;
                        if result_id.is_some_and(|result_id| fresh.result_id() != result_id) {
                            return Err(MutationError::PreconditionFailed);
                        }
                        (Some(fresh), evidence)
                    }
                }
            } else {
                (None, vec![])
            };
        // Preflight admitted and projected only the frozen guard selectors.
        // Reuse the configured, pinned provider adapter with no checked-out
        // database connection; the coordinator rechecks those same selectors.
        let commit_evidence = if commit_requests.is_empty() {
            Vec::new()
        } else {
            self.evidence_evaluator
                .as_ref()
                .ok_or(MutationError::Unavailable)?
                .acquire_preconditions(commit_requests, deadline.into_std())
                .await?
        };
        let client = tokio::time::timeout_at(deadline, self.pool.get())
            .await
            .map_err(|_| MutationError::Unavailable)?
            .map_err(|_| MutationError::Unavailable)?;
        let mut guard = QueryCancellationGuard::new(self.pool.clone(), client);
        let staging = tokio::time::timeout_at(
            deadline,
            self.coordinator.stage_proposal_attachment(
                guard.client(),
                &self.registry,
                &input,
                deadline,
            ),
        )
        .await;
        match staging {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                guard.disarm();
                return Err(error);
            }
            Err(_) => {
                guard.cancel_and_discard().await;
                return Err(MutationError::Unavailable);
            }
        }
        match tokio::time::timeout_at(
            deadline,
            self.coordinator.execute_proposal(
                guard.client(),
                &self.registry,
                input,
                review_evidence.as_ref(),
                &commit_evidence,
                deadline,
            ),
        )
        .await
        {
            Ok(result) => {
                guard.disarm();
                result
            }
            Err(_) => {
                guard.cancel_and_discard().await;
                Err(MutationError::Unavailable)
            }
        }
    }

    pub(crate) async fn proposal_document(
        &self,
        id: Uuid,
        authority: &ProposalAuthority,
        claims: &VerifiedRequestClaims,
        correlation: &crate::correlation::RequestCorrelation,
    ) -> Result<(Value, String), MutationError> {
        let _attempt = self
            .coordinator
            .begin_proposal_read_audit(authority, correlation)
            .await?;
        let deadline = tokio::time::Instant::now() + self.action_timeout;
        let client = self
            .admitted_proposal_read_client(authority, correlation, deadline)
            .await?;
        let mut guard = QueryCancellationGuard::new(self.pool.clone(), client);
        let result = tokio::time::timeout_at(deadline, async {
            let guarded = begin_proposal_transaction(
                guard.client(),
                self.lock_key,
                self.lock_timeout,
                &self.expected,
                authority,
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
            guarded
                .set_statement_budget(
                    deadline.saturating_duration_since(tokio::time::Instant::now()),
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
            // Keep the lifecycle, frozen submission, review and application
            // projection coherent while current target authority is checked.
            let document = proposal_store::load_document(
                guarded.transaction(),
                id,
                proposal_store::DocumentLock::Share,
            )
            .await?;
            #[cfg(feature = "postgres-test")]
            self.pause_proposal_read_for_test().await;
            self.coordinator
                .authorize_proposal_document(
                    guarded.transaction(),
                    &self.registry,
                    &document,
                    authority,
                )
                .await?;
            let value = self
                .coordinator
                .proposal_public_value(
                    guarded.transaction(),
                    &self.registry,
                    &document,
                    Some(claims),
                    authority,
                )
                .await?;
            let etag = self.coordinator.proposal_etag(&document, authority)?;
            if authority
                .task_grant
                .as_ref()
                .is_some_and(|binding| !binding.is_current())
            {
                return Err(MutationError::PreconditionFailed);
            }
            guarded
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            self.coordinator
                .finish_proposal_read_audit(authority, Some(&document), 1, correlation)
                .await?;
            Ok((value, etag))
        })
        .await;
        let result = match result {
            Ok(result) => {
                guard.disarm();
                result
            }
            Err(_) => {
                guard.cancel_and_discard().await;
                Err(MutationError::Unavailable)
            }
        };
        if result.is_err() {
            self.coordinator
                .record_proposal_refusal(authority, crate::model::HttpMethod::Get, correlation)
                .await?;
        }
        result
    }

    pub(crate) async fn proposal_review_read(
        &self,
        id: Uuid,
        authority: &ProposalAuthority,
        records: &BTreeMap<String, crate::api::proposals::ProposalRecordReadAuthority>,
        correlation: &crate::correlation::RequestCorrelation,
    ) -> Result<(Value, String), MutationError> {
        let _attempt = self
            .coordinator
            .begin_proposal_read_audit(authority, correlation)
            .await?;
        let deadline = tokio::time::Instant::now() + self.action_timeout;
        let client = self
            .admitted_proposal_read_client(authority, correlation, deadline)
            .await?;
        let mut guard = QueryCancellationGuard::new(self.pool.clone(), client);
        let result = tokio::time::timeout_at(deadline, async {
            let guarded = begin_proposal_transaction(
                guard.client(),
                self.lock_key,
                self.lock_timeout,
                &self.expected,
                authority,
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
            guarded
                .set_statement_budget(
                    deadline.saturating_duration_since(tokio::time::Instant::now()),
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
            let document = proposal_store::load_document(
                guarded.transaction(),
                id,
                proposal_store::DocumentLock::Share,
            )
            .await?;
            #[cfg(feature = "postgres-test")]
            self.pause_proposal_read_for_test().await;
            self.coordinator
                .authorize_proposal_review_read(
                    guarded.transaction(),
                    &self.registry,
                    &document,
                    authority,
                )
                .await?;
            let value = self
                .coordinator
                .proposal_review_value(
                    guarded.transaction(),
                    &self.registry,
                    &document,
                    authority,
                    records,
                )
                .await?;
            let etag = self.coordinator.proposal_etag(&document, authority)?;
            if authority
                .task_grant
                .as_ref()
                .is_some_and(|binding| !binding.is_current())
            {
                return Err(MutationError::PreconditionFailed);
            }
            guarded
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            self.coordinator
                .finish_proposal_read_audit(authority, Some(&document), 1, correlation)
                .await?;
            Ok((value, etag))
        })
        .await;
        let result = match result {
            Ok(result) => {
                guard.disarm();
                result
            }
            Err(_) => {
                guard.cancel_and_discard().await;
                Err(MutationError::Unavailable)
            }
        };
        if result.is_err() {
            self.coordinator
                .record_proposal_refusal(authority, crate::model::HttpMethod::Get, correlation)
                .await?;
        }
        result
    }

    pub(crate) async fn list_proposals(
        &self,
        authorities: &[ProposalAuthority],
        query: &ProposalListQuery,
        claims: &VerifiedRequestClaims,
        correlation: &crate::correlation::RequestCorrelation,
    ) -> Result<Value, MutationError> {
        let deadline = tokio::time::Instant::now() + self.action_timeout;
        let mut attempts = Vec::new();
        for authority in authorities {
            attempts.push(
                self.coordinator
                    .begin_proposal_read_audit(authority, correlation)
                    .await?,
            );
        }
        let client = tokio::time::timeout_at(deadline, async {
            for authority in authorities {
                if let Some(binding) = &authority.task_grant {
                    self.coordinator.check_task_authority(binding).await?;
                }
            }
            self.pool
                .get()
                .await
                .map_err(|_| MutationError::Unavailable)
        })
        .await
        .map_err(|_| MutationError::Unavailable)
        .and_then(|result| result);
        let client = match client {
            Ok(client) => client,
            Err(error) => {
                for authority in authorities {
                    self.coordinator
                        .record_proposal_refusal(
                            authority,
                            crate::model::HttpMethod::Get,
                            correlation,
                        )
                        .await?;
                }
                return Err(error);
            }
        };
        let mut guard = QueryCancellationGuard::new(self.pool.clone(), client);
        let result = match tokio::time::timeout_at(
            deadline,
            self.list_proposals_in(
                guard.client(),
                authorities,
                query,
                claims,
                correlation,
                deadline,
            ),
        )
        .await
        {
            Ok(result) => {
                guard.disarm();
                result
            }
            Err(_) => {
                guard.cancel_and_discard().await;
                Err(MutationError::Unavailable)
            }
        };
        if result.is_err() {
            for authority in authorities {
                self.coordinator
                    .record_proposal_refusal(authority, crate::model::HttpMethod::Get, correlation)
                    .await?;
            }
        }
        result
    }

    async fn list_proposals_in(
        &self,
        client: &mut deadpool_postgres::Client,
        authorities: &[ProposalAuthority],
        query: &ProposalListQuery,
        claims: &VerifiedRequestClaims,
        correlation: &crate::correlation::RequestCorrelation,
        deadline: tokio::time::Instant,
    ) -> Result<Value, MutationError> {
        const MAXIMUM_PAGE_BYTES: usize = 1024 * 1024;
        let mut page_bytes = 0usize;
        let action_ids = authorities
            .iter()
            .map(|authority| authority.common.action_id().to_owned())
            .collect::<Vec<_>>();
        let mut after = query.after;
        let mut items = Vec::new();
        let mut has_more = false;
        'pages: loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(MutationError::Unavailable);
            }
            // The collection authority restricts Actions before any caller
            // filter. Row/ownership concealment precedes filtering and counts.
            let candidates = client
                .query(
                    "SELECT proposal_id,action_id FROM registry_internal.registry_proposal_state
                WHERE action_id=ANY($1) AND ($2::uuid IS NULL OR proposal_id>$2)
                ORDER BY proposal_id LIMIT 200",
                    &[&action_ids, &after],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
            if candidates.is_empty() {
                break;
            }
            let count = candidates.len();
            for candidate in candidates {
                let id: Uuid = candidate.get(0);
                let action_id: String = candidate.get(1);
                after = Some(id);
                let Some(authority) = authorities
                    .iter()
                    .find(|authority| authority.common.action_id() == action_id)
                else {
                    continue;
                };
                let guarded = begin_proposal_transaction(
                    client,
                    self.lock_key,
                    self.lock_timeout,
                    &self.expected,
                    authority,
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
                let document = proposal_store::load_document(
                    guarded.transaction(),
                    id,
                    proposal_store::DocumentLock::Share,
                )
                .await?;
                #[cfg(feature = "postgres-test")]
                self.pause_proposal_read_for_test().await;
                match self
                    .coordinator
                    .authorize_proposal_document(
                        guarded.transaction(),
                        &self.registry,
                        &document,
                        authority,
                    )
                    .await
                {
                    Ok(()) => {}
                    Err(
                        MutationError::AuthorizationRefused | MutationError::PreconditionFailed,
                    ) => {
                        guarded
                            .rollback()
                            .await
                            .map_err(|_| MutationError::Unavailable)?;
                        continue;
                    }
                    Err(error) => return Err(error),
                }
                let matches = query
                    .action
                    .as_ref()
                    .is_none_or(|action| *action == document.action_id)
                    && query
                        .state
                        .as_ref()
                        .is_none_or(|state| *state == document.header.state)
                    && (query.owner.is_none()
                        || document.header.owner_reference
                            == self
                                .coordinator
                                .proposal_owner_reference(authority.common.principal()))
                    && query.target.is_none_or(|target| {
                        document.input_targets.iter().any(|(_, id)| *id == target)
                    });
                if matches {
                    if items.len() == query.limit {
                        has_more = true;
                        guarded
                            .commit()
                            .await
                            .map_err(|_| MutationError::Unavailable)?;
                        break 'pages;
                    }
                    let value = self
                        .coordinator
                        .proposal_public_value(
                            guarded.transaction(),
                            &self.registry,
                            &document,
                            Some(claims),
                            authority,
                        )
                        .await?;
                    let value_bytes = serde_json::to_vec(&value)
                        .map_err(|_| MutationError::Unavailable)?
                        .len();
                    if page_bytes
                        .checked_add(value_bytes)
                        .is_none_or(|total| total > MAXIMUM_PAGE_BYTES)
                    {
                        if items.is_empty() {
                            return Err(MutationError::Unavailable);
                        }
                        has_more = true;
                        guarded
                            .commit()
                            .await
                            .map_err(|_| MutationError::Unavailable)?;
                        break 'pages;
                    }
                    page_bytes += value_bytes;
                    items.push(value);
                }
                guarded
                    .commit()
                    .await
                    .map_err(|_| MutationError::Unavailable)?;
            }
            if count < 200 {
                break;
            }
        }
        let mut value = json!({"items":items});
        if authorities.iter().any(|authority| {
            authority
                .task_grant
                .as_ref()
                .is_some_and(|binding| !binding.is_current())
        }) {
            return Err(MutationError::PreconditionFailed);
        }
        if has_more {
            if let Some(id) = value["items"]
                .as_array()
                .and_then(|items| items.last())
                .and_then(|item| item.get("id"))
            {
                value["nextCursor"] = id.clone();
            }
        }
        for authority in authorities {
            self.coordinator
                .finish_proposal_read_audit(
                    authority,
                    None,
                    value["items"].as_array().map_or(0, |items| {
                        items
                            .iter()
                            .filter(|item| {
                                item["actionId"].as_str() == Some(authority.common.action_id())
                            })
                            .count()
                    }),
                    correlation,
                )
                .await?;
        }
        if authorities.iter().any(|authority| {
            authority
                .task_grant
                .as_ref()
                .is_some_and(|binding| !binding.is_current())
        }) {
            return Err(MutationError::PreconditionFailed);
        }
        Ok(value)
    }
}

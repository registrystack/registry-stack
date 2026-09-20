// SPDX-License-Identifier: Apache-2.0

//! Durable source-owned review submission, completion, and application state.
//!
//! Network calls are deliberately separated from every database transaction.
//! A claimed job is committed before I/O and every response is written through
//! an exact proposal and submission-digest comparison.

use chrono::{DateTime, Utc};
use registry_platform_httputil::client::{
    build_client, OutboundOptions, ServiceBaseUrl, TokenProvider,
};
use registry_platform_httputil::{read_bounded, validate_response_headers};
use registry_review_client::{
    submission_digest, BearerToken, ReviewClient, ReviewClientError, ReviewCompletion,
    ReviewCompletionType, ReviewCreateRequest, ReviewRequestAccepted, ReviewResult,
    ReviewResultResponse, ReviewResultsQuery, SourceContextBinding, SubjectBinding,
};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, IF_MATCH};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio_postgres::{GenericClient, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::model::{
    CompiledChangeRequestOnApprovedMode, CompiledChangeRequestReview, CompiledRegistry,
};
use crate::mutation::MutationError;
use crate::postgres::SqlIdentifier;
use crate::request_workflow::ProposalSnapshot;

const SUBJECT_TYPE: &str = "change-request";
const SUBMISSION_LEASE_SECONDS: i64 = 30;
const MAX_APPLICATION_ATTEMPTS: i32 = 1_000;
const APPLICATION_ATTEMPTS_EXHAUSTED: &str = "application-attempts-exhausted";
const MAX_APPLICATION_RESPONSE_BYTES: u64 = 256 * 1024;
pub(crate) const MAXIMUM_COMPLETION_RECIPIENT_BYTES: usize = 256;
pub(crate) const MAXIMUM_REVIEW_RECOVERY_DAYS: u32 = 3_650;

pub(crate) fn valid_completion_recipient(recipient: &str) -> bool {
    !recipient.trim().is_empty()
        && recipient.len() <= MAXIMUM_COMPLETION_RECIPIENT_BYTES
        && !recipient.chars().any(char::is_control)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewConfigurationError;

impl std::fmt::Display for ReviewConfigurationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid review integration configuration")
    }
}

impl std::error::Error for ReviewConfigurationError {}

pub struct ReviewExecutorClient {
    executor: String,
    http: reqwest::Client,
    base_url: ServiceBaseUrl,
    token: BearerToken,
    registry_id: String,
    access_profile: String,
    request_routes: BTreeMap<String, String>,
}

impl ReviewExecutorClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        executor: String,
        endpoint: reqwest::Url,
        token: BearerToken,
        registry_id: String,
        access_profile: String,
        request_routes: BTreeMap<String, String>,
        request_timeout: std::time::Duration,
    ) -> Result<Self, ReviewConfigurationError> {
        if executor.trim().is_empty()
            || executor.len() > 128
            || registry_id.trim().is_empty()
            || registry_id.len() > 128
            || access_profile.trim().is_empty()
            || access_profile.len() > 128
            || request_routes.is_empty()
            || request_routes.iter().any(|(entity, route)| {
                entity.is_empty()
                    || entity.len() > 128
                    || route.is_empty()
                    || route.len() > 128
                    || !route.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'-' | b'_')
                    })
            })
        {
            return Err(ReviewConfigurationError);
        }
        let base_url = ServiceBaseUrl::new(endpoint).map_err(|_| ReviewConfigurationError)?;
        let http = build_client(OutboundOptions {
            request_timeout,
            connect_timeout: request_timeout,
            user_agent: Some("registry-breg-review-executor"),
            trusted_root_certificates: None,
        })
        .map_err(|_| ReviewConfigurationError)?;
        Ok(Self {
            executor,
            http,
            base_url,
            token,
            registry_id,
            access_profile,
            request_routes,
        })
    }
}

pub struct ReviewExecutorRegistry {
    executors: BTreeMap<String, Arc<ReviewExecutorClient>>,
}

impl ReviewExecutorRegistry {
    pub fn new(
        executors: BTreeMap<String, Arc<ReviewExecutorClient>>,
    ) -> Result<Self, ReviewConfigurationError> {
        if executors.is_empty()
            || executors
                .iter()
                .any(|(id, executor)| id != &executor.executor)
        {
            return Err(ReviewConfigurationError);
        }
        Ok(Self { executors })
    }

    fn contains_binding(&self, executor: &str, request_entity_id: &str) -> bool {
        self.executors
            .get(executor)
            .is_some_and(|configured| configured.request_routes.contains_key(request_entity_id))
    }

    async fn run_one(&self, client: &mut tokio_postgres::Client) -> Result<bool, MutationError> {
        let exhausted = client
            .execute(
                "UPDATE registry_internal.registry_request_application_jobs
                    SET state='blocked',claim_token=NULL,last_error_code=$1,
                        updated_at=transaction_timestamp()
                  WHERE attempt_count >= $2
                    AND (state='queued' OR (state='applying'
                         AND next_attempt_at <= transaction_timestamp()))",
                &[&APPLICATION_ATTEMPTS_EXHAUSTED, &MAX_APPLICATION_ATTEMPTS],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        if exhausted != 0 {
            return Ok(true);
        }
        let Some(row) = client
            .query_opt(
                "SELECT executor,job_id
                   FROM registry_internal.registry_request_application_jobs
                  WHERE state IN ('queued','applying')
                    AND attempt_count < $1
                    AND next_attempt_at <= transaction_timestamp()
                  ORDER BY next_attempt_at,created_at LIMIT 1",
                &[&MAX_APPLICATION_ATTEMPTS],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
        else {
            return Ok(false);
        };
        let executor: String = row.get(0);
        let Some(configured) = self.executors.get(&executor) else {
            let job_id: Uuid = row.get(1);
            client
                .execute(
                    "UPDATE registry_internal.registry_request_application_jobs
                        SET state='blocked',claim_token=NULL,
                            last_error_code='executor-unconfigured',
                            updated_at=transaction_timestamp()
                      WHERE job_id=$1
                        AND (state='queued' OR (state='applying'
                             AND next_attempt_at <= transaction_timestamp()))",
                    &[&job_id],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
            return Ok(true);
        };
        run_one_application(client, configured).await
    }
}

/// Refuse an activation that would strand durable work accepted under the
/// previous package. Operators may retain superseded bindings until their jobs
/// finish; only then may those bindings be removed from runtime configuration.
pub async fn verify_retained_bindings(
    pool: &crate::postgres::RuntimePool,
    authorities: Option<&ReviewAuthorityRegistry>,
    executors: Option<&ReviewExecutorRegistry>,
) -> Result<(), MutationError> {
    let client = pool.get().await.map_err(|_| MutationError::Unavailable)?;
    let authority_rows = client
        .query(
            "SELECT DISTINCT authority,producer_id
               FROM registry_internal.registry_request_review_submissions s
              WHERE state IN ('pending','submitting','uncertain','cancelling')
                 OR (state='accepted' AND NOT EXISTS (
                        SELECT 1 FROM registry_internal.registry_request_review_results r
                         WHERE (r.request_entity_id,r.request_id,r.proposal_version)=
                               (s.request_entity_id,s.request_id,s.proposal_version)))
                 OR EXISTS (
                        SELECT 1 FROM registry_internal.registry_request_application_jobs j
                         WHERE (j.request_entity_id,j.request_id,j.proposal_version)=
                               (s.request_entity_id,s.request_id,s.proposal_version)
                           AND j.state IN ('queued','applying'))",
            &[],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    if authority_rows.iter().any(|row| {
        authorities.is_none_or(|configured| {
            !configured.contains_binding(
                row.get::<_, String>(0).as_str(),
                row.get::<_, String>(1).as_str(),
            )
        })
    }) {
        return Err(MutationError::PreconditionFailed);
    }
    let executor_rows = client
        .query(
            "SELECT DISTINCT executor,request_entity_id
               FROM registry_internal.registry_request_application_jobs
              WHERE state IN ('queued','applying')",
            &[],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    if executor_rows.iter().any(|row| {
        executors.is_none_or(|configured| {
            !configured.contains_binding(
                row.get::<_, String>(0).as_str(),
                row.get::<_, String>(1).as_str(),
            )
        })
    }) {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn run_review_application_once_for_test(
    client: &mut tokio_postgres::Client,
    executor: &ReviewExecutorClient,
) -> Result<bool, MutationError> {
    run_one_application(client, executor).await
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn run_review_authority_once_for_test(
    pool: &crate::postgres::RuntimePool,
    authorities: &ReviewAuthorityRegistry,
) -> Result<bool, MutationError> {
    let mut client = pool.get().await.map_err(|_| MutationError::Unavailable)?;
    authorities.run_one(&mut client).await
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn install_review_storage_for_test(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), MutationError> {
    install(client, runtime_role).await
}

#[async_trait::async_trait]
pub trait ReviewResultSource: Send + Sync {
    async fn approved_evidence(
        &self,
        authority: &str,
        accepted: &ReviewRequestAccepted,
    ) -> Result<crate::review_integration::AcceptedReviewEvidence, MutationError>;
}

pub struct ReviewAuthorityClient {
    authority: String,
    client: ReviewClient,
    token_provider: Arc<dyn TokenProvider>,
    producer_id: String,
    recovery_days: u32,
    completion_token: Option<Zeroizing<String>>,
    completion_recipient: Option<String>,
}

impl ReviewAuthorityClient {
    pub fn new(
        authority: String,
        client: ReviewClient,
        token_provider: Arc<dyn TokenProvider>,
        producer_id: String,
        recovery_days: u32,
        completion_token: Option<Zeroizing<String>>,
        completion_recipient: Option<String>,
    ) -> Result<Self, ReviewConfigurationError> {
        if authority.trim().is_empty()
            || authority.len() > 128
            || producer_id.trim().is_empty()
            || producer_id.len() > 128
            || producer_id.chars().any(char::is_control)
            || !(1..=MAXIMUM_REVIEW_RECOVERY_DAYS).contains(&recovery_days)
            || completion_token.is_some() != completion_recipient.is_some()
            || completion_token.as_ref().is_some_and(|token| {
                token.is_empty() || token.len() > 4096 || token.chars().any(char::is_control)
            })
            || completion_recipient
                .as_ref()
                .is_some_and(|recipient| !valid_completion_recipient(recipient))
        {
            return Err(ReviewConfigurationError);
        }
        Ok(Self {
            authority,
            client,
            token_provider,
            producer_id,
            recovery_days,
            completion_token,
            completion_recipient,
        })
    }
}

pub struct ReviewAuthorityRegistry {
    authorities: BTreeMap<String, Arc<ReviewAuthorityClient>>,
}

impl ReviewAuthorityRegistry {
    pub fn new(
        authorities: BTreeMap<String, Arc<ReviewAuthorityClient>>,
    ) -> Result<Self, ReviewConfigurationError> {
        if authorities.is_empty()
            || authorities
                .iter()
                .any(|(id, authority)| id != &authority.authority)
        {
            return Err(ReviewConfigurationError);
        }
        Ok(Self { authorities })
    }

    pub fn contains(&self, authority: &str) -> bool {
        self.authorities.contains_key(authority)
    }

    fn contains_binding(&self, authority: &str, producer_id: &str) -> bool {
        self.authorities
            .get(authority)
            .is_some_and(|configured| configured.producer_id == producer_id)
    }

    fn submission_binding(&self, authority: &str) -> Option<(&str, u32)> {
        self.authorities
            .get(authority)
            .map(|configured| (configured.producer_id.as_str(), configured.recovery_days))
    }

    fn recovery_days(&self, authority: &str) -> Option<u32> {
        self.authorities
            .get(authority)
            .map(|configured| configured.recovery_days)
    }

    /// Resolve a completion sender only when both its independently configured
    /// bearer credential and logical recipient match one authority exactly.
    pub fn completion_authority(&self, token: &str, recipient: &str) -> Option<&str> {
        let mut matched = None;
        for (authority, configured) in &self.authorities {
            let Some(expected_token) = configured.completion_token.as_ref() else {
                continue;
            };
            let Some(expected_recipient) = configured.completion_recipient.as_ref() else {
                continue;
            };
            let token_matches = expected_token.len() == token.len()
                && expected_token
                    .as_bytes()
                    .ct_eq(token.as_bytes())
                    .unwrap_u8()
                    == 1;
            let recipient_matches = expected_recipient.len() == recipient.len()
                && expected_recipient
                    .as_bytes()
                    .ct_eq(recipient.as_bytes())
                    .unwrap_u8()
                    == 1;
            if token_matches && recipient_matches {
                if matched.is_some() {
                    return None;
                }
                matched = Some(authority.as_str());
            }
        }
        matched
    }

    async fn authorities_for_pending(
        &self,
        client: &tokio_postgres::Client,
        states: &[&str],
    ) -> Result<Vec<Arc<ReviewAuthorityClient>>, MutationError> {
        // Bind an owned PostgreSQL text array. A slice of borrowed `&str`
        // values is not a supported tokio-postgres array parameter and fails
        // before the query reaches PostgreSQL.
        let states = states
            .iter()
            .map(|state| (*state).to_owned())
            .collect::<Vec<_>>();
        let rows = client
            .query(
                "SELECT authority,min(next_attempt_at) AS ready_at
                   FROM registry_internal.registry_request_review_submissions
                  WHERE state=ANY($1) AND next_attempt_at <= transaction_timestamp()
                    AND (state<>'submitting' OR lease_until < transaction_timestamp())
                    AND (state<>'cancelling' OR lease_until IS NULL
                         OR lease_until < transaction_timestamp())
                  GROUP BY authority ORDER BY ready_at,authority",
                &[&states],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        rows.into_iter()
            .map(|row| {
                self.authorities
                    .get(row.get::<_, String>(0).as_str())
                    .cloned()
                    .ok_or(MutationError::Unavailable)
            })
            .collect()
    }

    async fn back_off_token_failure(
        client: &tokio_postgres::Client,
        authority: &str,
        states: &[&str],
    ) -> Result<(), MutationError> {
        let states = states
            .iter()
            .map(|state| (*state).to_owned())
            .collect::<Vec<_>>();
        client
            .execute(
                "UPDATE registry_internal.registry_request_review_submissions
                    SET state=CASE WHEN state='submitting' THEN 'uncertain' ELSE state END,
                        lease_until=NULL,last_error_code='token-unavailable',
                        next_attempt_at=transaction_timestamp()+interval '5 seconds',
                        updated_at=transaction_timestamp()
                  WHERE authority=$1 AND state=ANY($2)
                    AND next_attempt_at <= transaction_timestamp()
                    AND (state<>'submitting' OR lease_until < transaction_timestamp())",
                &[&authority, &states],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        Ok(())
    }

    async fn run_one(&self, client: &mut tokio_postgres::Client) -> Result<bool, MutationError> {
        let erased_completions = erase_expired_review_completions(client).await?;
        if erased_completions > 0 {
            tracing::debug!(
                erased = erased_completions,
                "BReg review completion retention pass erased expired rows"
            );
            return Ok(true);
        }
        let correlated_completions = correlate_stored_review_completions(client).await?;
        if correlated_completions > 0 {
            tracing::debug!(
                correlated = correlated_completions,
                "BReg review completion reconciliation matched stored results"
            );
            return Ok(true);
        }
        if client
            .execute(
                "UPDATE registry_internal.registry_request_review_submissions
                    SET state='failed',lease_until=NULL,last_error_code='submission-recovery-expired',
                        updated_at=transaction_timestamp()
                  WHERE accepted_binding IS NULL AND recovery_deadline <= transaction_timestamp()
                    AND state IN ('pending','submitting','uncertain')",
                &[],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            > 0
        {
            return Ok(true);
        }
        let mut authority_unavailable = false;
        for authority in self
            .authorities_for_pending(client, &["pending", "uncertain", "submitting"])
            .await?
        {
            let token = match authority.token_provider.bearer_token().await {
                Ok(token) => token,
                Err(_) => {
                    authority_unavailable = true;
                    Self::back_off_token_failure(
                        client,
                        &authority.authority,
                        &["pending", "uncertain", "submitting"],
                    )
                    .await?;
                    continue;
                }
            };
            if run_one_submission(client, &authority.authority, &authority.client, &token).await? {
                return Ok(true);
            }
        }
        for authority in self
            .authorities_for_pending(client, &["cancelling"])
            .await?
        {
            let token = match authority.token_provider.bearer_token().await {
                Ok(token) => token,
                Err(_) => {
                    authority_unavailable = true;
                    Self::back_off_token_failure(client, &authority.authority, &["cancelling"])
                        .await?;
                    continue;
                }
            };
            if run_one_cancellation(client, &authority.authority, &authority.client, &token).await?
            {
                return Ok(true);
            }
        }
        let mut unavailable_feeds = 0usize;
        let mut unavailable_lookups = 0usize;
        for authority in self.authorities.values() {
            match consume_result_feed(client, authority).await {
                Ok(true) => {
                    if unavailable_feeds > 0 {
                        tracing::warn!(
                            unavailable = unavailable_feeds,
                            "BReg review result feeds are temporarily unavailable"
                        );
                    }
                    return Ok(true);
                }
                Ok(false) => {}
                Err(_) => {
                    authority_unavailable = true;
                    unavailable_feeds += 1;
                }
            }
        }
        let rows = client
            .query(
                "SELECT DISTINCT authority
                   FROM registry_internal.registry_request_review_submissions s
                  WHERE state='accepted' AND NOT EXISTS (
                    SELECT 1 FROM registry_internal.registry_request_review_results r
                     WHERE r.request_entity_id=s.request_entity_id AND r.request_id=s.request_id
                       AND r.proposal_version=s.proposal_version)
                    AND next_result_poll_at <= transaction_timestamp()
                  ORDER BY authority",
                &[],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        for row in rows {
            let authority_id = row.get::<_, String>(0);
            let Some(authority) = self.authorities.get(authority_id.as_str()) else {
                authority_unavailable = true;
                unavailable_lookups += 1;
                continue;
            };
            let outcome = match authority.token_provider.bearer_token().await {
                Ok(token) => {
                    poll_one_result(client, &authority.authority, &authority.client, &token).await
                }
                Err(_) => Err(MutationError::Unavailable),
            };
            match outcome {
                Ok(true) => {
                    if unavailable_feeds > 0 {
                        tracing::warn!(
                            unavailable = unavailable_feeds,
                            "BReg review result feeds are temporarily unavailable"
                        );
                    }
                    if unavailable_lookups > 0 {
                        tracing::warn!(
                            unavailable = unavailable_lookups,
                            "BReg review result lookups are temporarily unavailable"
                        );
                    }
                    return Ok(true);
                }
                Ok(false) => {}
                Err(_) => {
                    authority_unavailable = true;
                    unavailable_lookups += 1;
                    client
                        .execute(
                            "UPDATE registry_internal.registry_request_review_submissions
                                SET next_result_poll_at=transaction_timestamp()+interval '5 seconds',
                                    updated_at=transaction_timestamp()
                              WHERE authority=$1 AND state='accepted'
                                AND next_result_poll_at <= transaction_timestamp()",
                            &[&authority.authority],
                        )
                        .await
                        .map_err(|_| MutationError::Unavailable)?;
                }
            }
        }
        if unavailable_feeds > 0 {
            tracing::warn!(
                unavailable = unavailable_feeds,
                "BReg review result feeds are temporarily unavailable"
            );
        }
        if unavailable_lookups > 0 {
            tracing::warn!(
                unavailable = unavailable_lookups,
                "BReg review result lookups are temporarily unavailable"
            );
        }
        if authority_unavailable {
            Err(MutationError::Unavailable)
        } else {
            Ok(false)
        }
    }
}

async fn erase_expired_review_completions(
    client: &impl GenericClient,
) -> Result<u64, MutationError> {
    client
        .execute(
            "DELETE FROM registry_internal.registry_request_review_completions
              WHERE expires_at <= transaction_timestamp()",
            &[],
        )
        .await
        .map_err(|_| MutationError::Unavailable)
}

async fn correlate_stored_review_completions(
    client: &impl GenericClient,
) -> Result<u64, MutationError> {
    client
        .execute(
            "UPDATE registry_internal.registry_request_review_completions c
                SET state='correlated'
               FROM registry_internal.registry_request_review_submissions s
               JOIN registry_internal.registry_request_review_results r
                 USING (request_entity_id,request_id,proposal_version)
              WHERE c.state IN ('pending','unmatched')
                AND c.authority=s.authority AND r.authority=s.authority
                AND s.accepted_binding->>'requestId'=c.review_request_id::text
                AND r.result_id=c.result_id",
            &[],
        )
        .await
        .map_err(|_| MutationError::Unavailable)
}

async fn consume_result_feed(
    client: &mut tokio_postgres::Client,
    authority: &ReviewAuthorityClient,
) -> Result<bool, MutationError> {
    let token = authority
        .token_provider
        .bearer_token()
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let cursor = client
        .query_opt(
            "SELECT cursor FROM registry_internal.registry_request_review_feed_checkpoints
              WHERE authority=$1",
            &[&authority.authority],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .and_then(|row| row.get::<_, Option<String>>(0));
    let page = match authority
        .client
        .requester_results(
            &token,
            &ReviewResultsQuery {
                cursor: cursor.as_deref(),
                limit: Some(100),
            },
        )
        .await
    {
        Ok(page) => page.value,
        Err(ReviewClientError::Problem { status: 410, .. }) if cursor.is_some() => {
            client
                .execute(
                    "INSERT INTO registry_internal.registry_request_review_feed_checkpoints
                     (authority,cursor,updated_at) VALUES ($1,NULL,transaction_timestamp())
                     ON CONFLICT (authority) DO UPDATE
                         SET cursor=NULL,updated_at=transaction_timestamp()",
                    &[&authority.authority],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
            return Ok(true);
        }
        Err(_) => return Err(MutationError::Unavailable),
    };
    let had_items = !page.items.is_empty();
    let checkpoint = page
        .next_cursor
        .clone()
        .or_else(|| page.items.last().map(|item| item.event_id.to_string()))
        .or(cursor);
    let transaction = client
        .transaction()
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let expires_at =
        chrono::Utc::now() + chrono::Duration::days(i64::from(authority.recovery_days));
    for item in page.items {
        receive_completion(
            &transaction,
            &authority.authority,
            &ReviewCompletion {
                event_type: ReviewCompletionType::ReviewCompleted,
                event_id: item.event_id,
                request_id: item.request_id,
                result_id: item.result_id,
                completed_at: item.completed_at,
            },
            expires_at,
        )
        .await?;
    }
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_review_feed_checkpoints
             (authority,cursor,updated_at) VALUES ($1,$2,transaction_timestamp())
             ON CONFLICT (authority) DO UPDATE
                 SET cursor=EXCLUDED.cursor,updated_at=transaction_timestamp()",
            &[&authority.authority, &checkpoint],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| MutationError::Unavailable)?;
    Ok(had_items)
}

pub struct ReviewCompletionReceiver {
    pool: crate::postgres::RuntimePool,
    authorities: Arc<ReviewAuthorityRegistry>,
}

impl ReviewCompletionReceiver {
    pub fn new(
        pool: crate::postgres::RuntimePool,
        authorities: Arc<ReviewAuthorityRegistry>,
    ) -> Self {
        Self { pool, authorities }
    }

    pub fn authority(&self, token: &str, recipient: &str) -> Option<(String, u32)> {
        let authority = self.authorities.completion_authority(token, recipient)?;
        let recovery_days = self.authorities.recovery_days(authority)?;
        Some((authority.to_owned(), recovery_days))
    }

    pub async fn receive(
        &self,
        authority: &str,
        completion: &ReviewCompletion,
    ) -> Result<(), MutationError> {
        if !self.authorities.contains(authority) {
            return Err(MutationError::InvalidRequest);
        }
        let recovery_days = self
            .authorities
            .recovery_days(authority)
            .ok_or(MutationError::InvalidRequest)?;
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        receive_completion(
            &transaction,
            authority,
            completion,
            chrono::Utc::now() + chrono::Duration::days(i64::from(recovery_days)),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| MutationError::Unavailable)
    }
}

pub struct ReviewWorker {
    pool: crate::postgres::RuntimePool,
    authorities: Option<Arc<ReviewAuthorityRegistry>>,
    executors: Option<Arc<ReviewExecutorRegistry>>,
}

impl ReviewWorker {
    pub fn new(
        pool: crate::postgres::RuntimePool,
        authorities: Option<Arc<ReviewAuthorityRegistry>>,
        executors: Option<Arc<ReviewExecutorRegistry>>,
    ) -> Self {
        Self {
            pool,
            authorities,
            executors,
        }
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow() {
                return;
            }
            let worked = match self.pool.get().await {
                Ok(mut client) => {
                    let housekeeping_worked = erase_expired_review_completions(&**client)
                        .await
                        .unwrap_or(0)
                        > 0;
                    // A source apply whose response was lost is retried against
                    // BReg before another Casework exchange. The source's
                    // idempotency receipt is the application authority.
                    let application_worked = if housekeeping_worked {
                        false
                    } else {
                        match &self.executors {
                            Some(executors) => {
                                executors.run_one(&mut client).await.unwrap_or(false)
                            }
                            None => false,
                        }
                    };
                    if housekeeping_worked || application_worked {
                        true
                    } else {
                        match &self.authorities {
                            Some(authorities) => {
                                authorities.run_one(&mut client).await.unwrap_or(false)
                            }
                            None => false,
                        }
                    }
                }
                Err(_) => false,
            };
            if worked {
                continue;
            }
            tokio::select! {
                _ = shutdown.changed() => {},
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {},
            }
        }
    }
}

#[async_trait::async_trait]
impl ReviewResultSource for ReviewAuthorityRegistry {
    async fn approved_evidence(
        &self,
        authority: &str,
        accepted: &ReviewRequestAccepted,
    ) -> Result<crate::review_integration::AcceptedReviewEvidence, MutationError> {
        self.authorities
            .get(authority)
            .ok_or(MutationError::PreconditionFailed)?
            .approved_evidence(authority, accepted)
            .await
    }
}

#[async_trait::async_trait]
impl ReviewResultSource for ReviewAuthorityClient {
    async fn approved_evidence(
        &self,
        authority: &str,
        accepted: &ReviewRequestAccepted,
    ) -> Result<crate::review_integration::AcceptedReviewEvidence, MutationError> {
        if authority != self.authority {
            return Err(MutationError::PreconditionFailed);
        }
        let result = match self
            .client
            .result(
                &self
                    .token_provider
                    .bearer_token()
                    .await
                    .map_err(|_| MutationError::Unavailable)?,
                accepted,
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
        {
            ReviewResultResponse::Available(complete) => complete.value,
            ReviewResultResponse::Pending { .. }
            | ReviewResultResponse::ConcealedOrUnknown { .. }
            | ReviewResultResponse::Expired { .. } => {
                return Err(MutationError::PreconditionFailed)
            }
            _ => return Err(MutationError::Unavailable),
        };
        if result.available_until <= chrono::Utc::now() {
            return Err(MutationError::PreconditionFailed);
        }
        crate::review_integration::AcceptedReviewEvidence::from_protocol(
            authority, accepted, &result,
        )
        .map_err(|_| MutationError::PreconditionFailed)
    }
}

pub(crate) async fn load_accepted_binding(
    client: &impl GenericClient,
    request_entity_id: &str,
    request_id: Uuid,
    proposal_version: i64,
    proposal_digest: &str,
) -> Result<(String, ReviewRequestAccepted), MutationError> {
    let row = client
        .query_opt(
            "SELECT authority,accepted_binding
               FROM registry_internal.registry_request_review_submissions
              WHERE request_entity_id=$1 AND request_id=$2 AND proposal_version=$3
                AND proposal_digest=$4 AND state='accepted'",
            &[
                &request_entity_id,
                &request_id,
                &proposal_version,
                &proposal_digest,
            ],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::PreconditionFailed)?;
    let accepted = serde_json::from_value(row.get(1)).map_err(|_| MutationError::Unavailable)?;
    Ok((row.get(0), accepted))
}

pub(crate) const REVIEW_TABLES: &[(&str, &[&str])] = &[
    (
        "registry_request_review_submissions",
        &["INSERT", "SELECT", "UPDATE"],
    ),
    (
        "registry_request_review_completions",
        &["INSERT", "SELECT", "UPDATE", "DELETE"],
    ),
    (
        "registry_request_review_results",
        &["INSERT", "SELECT", "UPDATE"],
    ),
    (
        "registry_request_review_feed_checkpoints",
        &["INSERT", "SELECT", "UPDATE"],
    ),
    (
        "registry_request_application_jobs",
        &["INSERT", "SELECT", "UPDATE"],
    ),
];

pub(crate) async fn install(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), MutationError> {
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_request_review_submissions (
                 request_entity_id text NOT NULL CHECK (request_entity_id <> ''),
                 request_id uuid NOT NULL,
                 proposal_version bigint NOT NULL CHECK (proposal_version BETWEEN 1 AND 4294967295),
                 proposal_digest text NOT NULL CHECK (proposal_digest ~ '^sha256:[0-9a-f]{64}$'),
                 job_id uuid NOT NULL UNIQUE,
                 authority text NOT NULL CHECK (authority <> '' AND octet_length(authority) <= 128),
                 producer_id text NOT NULL CHECK (producer_id <> '' AND octet_length(producer_id) <= 128),
                 policy_id text NOT NULL CHECK (policy_id <> '' AND octet_length(policy_id) <= 128),
                 idempotency_key text NOT NULL UNIQUE CHECK (
                     idempotency_key <> '' AND octet_length(idempotency_key) <= 128
                 ),
                 create_request jsonb NOT NULL CHECK (
                     jsonb_typeof(create_request) = 'object'
                     AND octet_length(create_request::text) <= 98304
                 ),
                 expected_submission_digest text NOT NULL
                     CHECK (expected_submission_digest ~ '^sha256:[0-9a-f]{64}$'),
                 on_approved_mode text NOT NULL CHECK (on_approved_mode IN ('manual','automatic')),
                 executor text CHECK (executor IS NULL OR (executor <> '' AND octet_length(executor) <= 128)),
                 state text NOT NULL CHECK (state IN
                     ('pending','submitting','accepted','uncertain','cancelling','cancelled','failed')),
                 accepted_binding jsonb CHECK (
                     accepted_binding IS NULL OR (
                         jsonb_typeof(accepted_binding) = 'object'
                         AND octet_length(accepted_binding::text) <= 8192
                     )
                 ),
                 attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 1000),
                 withdrawn boolean NOT NULL DEFAULT false,
                 recovery_deadline timestamptz NOT NULL
                     DEFAULT (transaction_timestamp()+interval '30 days'),
                 result_poll_attempts integer NOT NULL DEFAULT 0
                     CHECK (result_poll_attempts BETWEEN 0 AND 1000),
                 next_result_poll_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 next_attempt_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 lease_until timestamptz,
                 last_error_code text CHECK (
                     last_error_code IS NULL OR
                     (last_error_code <> '' AND octet_length(last_error_code) <= 128)
                 ),
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (request_entity_id, request_id, proposal_version),
                 FOREIGN KEY (request_entity_id, request_id, proposal_version)
                     REFERENCES registry_internal.registry_request_proposals,
                 CHECK ((on_approved_mode = 'manual' AND executor IS NULL)
                     OR (on_approved_mode = 'automatic' AND executor IS NOT NULL)),
                 CHECK ((state IN ('accepted','cancelling','cancelled') AND accepted_binding IS NOT NULL)
                     OR (state NOT IN ('accepted','cancelling','cancelled')))
             );
             ALTER TABLE registry_internal.registry_request_review_submissions
                 ADD COLUMN IF NOT EXISTS withdrawn boolean NOT NULL DEFAULT false;
             ALTER TABLE registry_internal.registry_request_review_submissions
                 ADD COLUMN IF NOT EXISTS producer_id text;
             DO $$ BEGIN
                 IF EXISTS (
                     SELECT 1 FROM registry_internal.registry_request_review_submissions
                      WHERE producer_id IS NULL
                 ) THEN
                     RAISE EXCEPTION 'legacy review submissions require explicit producer cutover';
                 END IF;
             END $$;
             ALTER TABLE registry_internal.registry_request_review_submissions
                 ALTER COLUMN producer_id SET NOT NULL;
             ALTER TABLE registry_internal.registry_request_review_submissions
                 ADD COLUMN IF NOT EXISTS recovery_deadline timestamptz NOT NULL
                     DEFAULT (transaction_timestamp()+interval '30 days');
             ALTER TABLE registry_internal.registry_request_review_submissions
                 ADD COLUMN IF NOT EXISTS result_poll_attempts integer NOT NULL DEFAULT 0;
             ALTER TABLE registry_internal.registry_request_review_submissions
                 ADD COLUMN IF NOT EXISTS next_result_poll_at timestamptz NOT NULL
                     DEFAULT transaction_timestamp();
             CREATE INDEX IF NOT EXISTS registry_request_review_submission_jobs
                 ON registry_internal.registry_request_review_submissions
                 (next_attempt_at, created_at)
                 WHERE state IN ('pending','submitting','uncertain');
             CREATE TABLE IF NOT EXISTS registry_internal.registry_request_review_completions (
                 authority text NOT NULL CHECK (authority <> '' AND octet_length(authority) <= 128),
                 event_id uuid NOT NULL,
                 review_request_id uuid NOT NULL,
                 result_id uuid NOT NULL,
                 completed_at timestamptz NOT NULL,
                 state text NOT NULL CHECK (state IN
                     ('pending','correlated','unmatched','applied','exhausted')),
                 received_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 expires_at timestamptz NOT NULL,
                 PRIMARY KEY (authority, event_id),
                 CHECK (expires_at > received_at)
             );
             CREATE INDEX IF NOT EXISTS registry_request_review_completion_reconcile
                 ON registry_internal.registry_request_review_completions
                 (state, received_at) WHERE state IN ('pending','unmatched');
             CREATE TABLE IF NOT EXISTS registry_internal.registry_request_review_results (
                 request_entity_id text NOT NULL,
                 request_id uuid NOT NULL,
                 proposal_version bigint NOT NULL CHECK (proposal_version BETWEEN 1 AND 4294967295),
                 authority text NOT NULL CHECK (authority <> '' AND octet_length(authority) <= 128),
                 result_id uuid NOT NULL,
                 result jsonb NOT NULL,
                 status text NOT NULL CHECK (status IN
                     ('approved','rejected','changes_requested','answered','cancelled','superseded')),
                 completed_at timestamptz NOT NULL,
                 available_until timestamptz NOT NULL,
                 verified_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (request_entity_id, request_id, proposal_version),
                 UNIQUE (authority, result_id),
                 FOREIGN KEY (request_entity_id, request_id, proposal_version)
                     REFERENCES registry_internal.registry_request_review_submissions,
                 CHECK (available_until > completed_at)
             );
             ALTER TABLE registry_internal.registry_request_review_results
                 DROP CONSTRAINT IF EXISTS registry_request_review_results_result_check;
             ALTER TABLE registry_internal.registry_request_review_results
                 DROP CONSTRAINT IF EXISTS registry_request_review_results_result_size;
             ALTER TABLE registry_internal.registry_request_review_results
                 ADD CONSTRAINT registry_request_review_results_result_size CHECK (
                     jsonb_typeof(result)='object'
                     AND octet_length(result::text)<=1048576
                 );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_request_review_feed_checkpoints (
                 authority text PRIMARY KEY CHECK (authority <> '' AND octet_length(authority) <= 128),
                 cursor text CHECK (cursor IS NULL OR (cursor <> '' AND octet_length(cursor) <= 4096)),
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_request_application_jobs (
                 request_entity_id text NOT NULL,
                 request_id uuid NOT NULL,
                 proposal_version bigint NOT NULL CHECK (proposal_version BETWEEN 1 AND 4294967295),
                 job_id uuid NOT NULL UNIQUE,
                 proposal_digest text NOT NULL CHECK (proposal_digest ~ '^sha256:[0-9a-f]{64}$'),
                 result_id uuid NOT NULL,
                 executor text NOT NULL CHECK (executor <> '' AND octet_length(executor) <= 128),
                 state text NOT NULL CHECK (state IN ('queued','applying','applied','blocked')),
                 attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 1000),
                 next_attempt_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 claim_token uuid,
                 last_error_code text CHECK (
                     last_error_code IS NULL OR
                     (last_error_code <> '' AND octet_length(last_error_code) <= 128)
                 ),
                 action_href text CHECK (
                     action_href IS NULL OR
                     (action_href <> '' AND octet_length(action_href) <= 2048)
                 ),
                 action_if_match text CHECK (
                     action_if_match IS NULL OR
                     (action_if_match <> '' AND octet_length(action_if_match) <= 1024)
                 ),
                 application_id uuid,
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (request_entity_id, request_id, proposal_version),
                 FOREIGN KEY (request_entity_id, request_id, proposal_version)
                     REFERENCES registry_internal.registry_request_review_results,
                 CHECK ((state = 'applied' AND application_id IS NOT NULL)
                     OR (state <> 'applied' AND application_id IS NULL)),
                 CHECK ((action_href IS NULL) = (action_if_match IS NULL))
             );",
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    client
        .batch_execute(
            "ALTER TABLE registry_internal.registry_request_review_feed_checkpoints
                 DROP CONSTRAINT IF EXISTS registry_request_review_feed_checkpoints_cursor_check;
             ALTER TABLE registry_internal.registry_request_review_feed_checkpoints
                 ADD CONSTRAINT registry_request_review_feed_checkpoints_cursor_check
                 CHECK (cursor IS NULL OR
                     (cursor <> '' AND octet_length(cursor) <= 4096));
             ALTER TABLE registry_internal.registry_request_application_jobs
                 ADD COLUMN IF NOT EXISTS claim_token uuid;
             ALTER TABLE registry_internal.registry_request_application_jobs
                 ADD COLUMN IF NOT EXISTS action_href text;
             ALTER TABLE registry_internal.registry_request_application_jobs
                 ADD COLUMN IF NOT EXISTS action_if_match text;
             DO $$ BEGIN
                 ALTER TABLE registry_internal.registry_request_application_jobs
                     ADD CONSTRAINT registry_request_application_jobs_action_href_check
                     CHECK (action_href IS NULL OR
                         (action_href <> '' AND octet_length(action_href) <= 2048));
             EXCEPTION WHEN duplicate_object THEN NULL; END $$;
             DO $$ BEGIN
                 ALTER TABLE registry_internal.registry_request_application_jobs
                     ADD CONSTRAINT registry_request_application_jobs_action_if_match_check
                     CHECK (action_if_match IS NULL OR
                         (action_if_match <> '' AND octet_length(action_if_match) <= 1024));
             EXCEPTION WHEN duplicate_object THEN NULL; END $$;
             DO $$ BEGIN
                 ALTER TABLE registry_internal.registry_request_application_jobs
                     ADD CONSTRAINT registry_request_application_jobs_action_binding_check
                     CHECK ((action_href IS NULL) = (action_if_match IS NULL));
             EXCEPTION WHEN duplicate_object THEN NULL; END $$;",
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    for (table, privileges) in REVIEW_TABLES {
        let role = runtime_role.as_str();
        client
            .batch_execute(&format!(
                "REVOKE ALL ON registry_internal.{table} FROM PUBLIC, \"{role}\";
                 GRANT {} ON registry_internal.{table} TO \"{role}\";",
                privileges.join(", ")
            ))
            .await
            .map_err(|_| MutationError::Unavailable)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Preserve each source and authority binding explicitly.
pub(crate) async fn enqueue_submission(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    request_entity_id: &str,
    request_id: Uuid,
    proposal: &ProposalSnapshot,
    requester_reference: &str,
    initiator: Option<&registry_review_client::HumanIdentity>,
    authorities: &ReviewAuthorityRegistry,
) -> Result<(), MutationError> {
    let CompiledChangeRequestReview::Required(requirement) = proposal.review_requirement() else {
        return Ok(());
    };
    let source_namespace = registry.registry_id();
    let (producer_id, recovery_days) = authorities
        .submission_binding(&requirement.authority)
        .ok_or(MutationError::Unavailable)?;
    let source_reference = format!(
        "breg:{source_namespace}:{request_entity_id}:{request_id}:{}",
        proposal.version().get()
    );
    let create = ReviewCreateRequest {
        kind: requirement.policy_id.clone(),
        subject: SubjectBinding {
            source: source_namespace.to_owned(),
            subject_type: SUBJECT_TYPE.to_owned(),
            id: request_id.to_string(),
            version: proposal.version().get().to_string(),
            digest: registry_review_client::ContentDigest::parse(proposal.effect_digest().as_str())
                .map_err(|_| MutationError::Unavailable)?,
        },
        requester_reference: requester_reference.to_owned(),
        initiator: initiator.cloned(),
        context: registry_review_client::ReviewContext::Source {
            binding: SourceContextBinding {
                reference: source_reference,
            },
        },
        result_constraints: None,
    };
    let expected_digest = submission_digest(producer_id, source_namespace, &create)
        .map_err(|_| MutationError::InvalidRequest)?;
    let job_id = Uuid::new_v4();
    let idempotency_key = format!("breg-review-{job_id}");
    let create_value = serde_json::to_value(&create).map_err(|_| MutationError::Unavailable)?;
    let (mode, executor) = match proposal.on_approved().mode {
        CompiledChangeRequestOnApprovedMode::Manual => ("manual", None),
        CompiledChangeRequestOnApprovedMode::Automatic => (
            "automatic",
            Some(
                proposal
                    .on_approved()
                    .executor
                    .as_deref()
                    .ok_or(MutationError::InvalidRequest)?,
            ),
        ),
    };
    let inserted = transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_review_submissions
             (request_entity_id, request_id, proposal_version, proposal_digest,
              job_id, authority, producer_id, policy_id, idempotency_key, create_request,
              expected_submission_digest, on_approved_mode, executor, state,recovery_deadline)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending',
                     transaction_timestamp()+($14::bigint * interval '1 day'))
             ON CONFLICT DO NOTHING",
            &[
                &request_entity_id,
                &request_id,
                &i64::from(proposal.version().get()),
                &proposal.effect_digest().as_str(),
                &job_id,
                &requirement.authority,
                &producer_id,
                &requirement.policy_id,
                &idempotency_key,
                &create_value,
                &expected_digest.as_str(),
                &mode,
                &executor,
                &i64::from(recovery_days),
            ],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    if inserted != 1 {
        let row = transaction
            .query_one(
                "SELECT proposal_digest, authority, producer_id, policy_id, create_request,
                        expected_submission_digest, on_approved_mode, executor
                   FROM registry_internal.registry_request_review_submissions
                  WHERE request_entity_id=$1 AND request_id=$2 AND proposal_version=$3",
                &[
                    &request_entity_id,
                    &request_id,
                    &i64::from(proposal.version().get()),
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let exact = row.get::<_, String>(0) == proposal.effect_digest().as_str()
            && row.get::<_, String>(1) == requirement.authority
            && row.get::<_, String>(2) == producer_id
            && row.get::<_, String>(3) == requirement.policy_id
            && row.get::<_, Value>(4) == create_value
            && row.get::<_, String>(5) == expected_digest.as_str()
            && row.get::<_, String>(6) == mode
            && row.get::<_, Option<String>>(7).as_deref() == executor;
        if !exact {
            return Err(MutationError::IdempotencyConflict);
        }
    }
    Ok(())
}

pub(crate) async fn schedule_cancellation(
    transaction: &Transaction<'_>,
    request_entity_id: &str,
    request_id: Uuid,
    proposal_version: i64,
) -> Result<(), MutationError> {
    transaction
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET withdrawn=true,
                    state=CASE
                        WHEN accepted_binding IS NOT NULL THEN 'cancelling'
                        WHEN state='pending' AND attempt_count=0 THEN 'cancelled'
                        WHEN state IN ('submitting','uncertain') THEN 'uncertain'
                        ELSE state
                    END,
                    lease_until=NULL,next_attempt_at=transaction_timestamp(),
                    updated_at=transaction_timestamp()
              WHERE request_entity_id=$1 AND request_id=$2 AND proposal_version=$3
                AND state NOT IN ('cancelled','failed')",
            &[&request_entity_id, &request_id, &proposal_version],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ClaimedReviewSubmission {
    pub request_entity_id: String,
    pub request_id: Uuid,
    pub proposal_version: i64,
    pub authority: String,
    pub idempotency_key: String,
    pub request: ReviewCreateRequest,
    pub expected_submission_digest: registry_review_client::SubmissionDigest,
    pub lease_until: DateTime<Utc>,
}

pub async fn claim_submission(
    client: &impl GenericClient,
    authority: &str,
) -> Result<Option<ClaimedReviewSubmission>, MutationError> {
    let row = client
        .query_opt(
            "WITH candidate AS (
                 SELECT s.request_entity_id, s.request_id, s.proposal_version
                   FROM registry_internal.registry_request_review_submissions s
                  WHERE next_attempt_at <= transaction_timestamp()
                    AND authority=$2
                    AND recovery_deadline > transaction_timestamp()
                    AND (state IN ('pending','uncertain')
                         OR (state='submitting' AND lease_until < transaction_timestamp()))
                    AND (
                        withdrawn OR NOT EXISTS (
                            SELECT 1
                             FROM registry_internal.registry_request_review_submissions older
                             WHERE older.request_entity_id=s.request_entity_id
                               AND older.request_id=s.request_id
                               AND older.proposal_version<s.proposal_version
                               AND older.withdrawn
                               AND older.state IN ('pending','submitting','uncertain','cancelling')
                        )
                    )
                  ORDER BY next_attempt_at, created_at
                  FOR UPDATE SKIP LOCKED LIMIT 1
             )
             UPDATE registry_internal.registry_request_review_submissions s
                SET state='submitting', attempt_count=LEAST(attempt_count+1,1000),
                    lease_until=transaction_timestamp()+($1::bigint * interval '1 second'),
                    updated_at=transaction_timestamp()
               FROM candidate c
              WHERE s.request_entity_id=c.request_entity_id
                AND s.request_id=c.request_id AND s.proposal_version=c.proposal_version
             RETURNING s.request_entity_id,s.request_id,s.proposal_version,s.authority,
                       s.idempotency_key,s.create_request,s.expected_submission_digest,
                       s.lease_until",
            &[&SUBMISSION_LEASE_SECONDS, &authority],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    row.map(|row| {
        Ok(ClaimedReviewSubmission {
            request_entity_id: row.get(0),
            request_id: row.get(1),
            proposal_version: row.get(2),
            authority: row.get(3),
            idempotency_key: row.get(4),
            request: serde_json::from_value(row.get(5)).map_err(|_| MutationError::Unavailable)?,
            expected_submission_digest: registry_review_client::SubmissionDigest::parse(
                &row.get::<_, String>(6),
            )
            .map_err(|_| MutationError::Unavailable)?,
            lease_until: row.get(7),
        })
    })
    .transpose()
}

pub async fn run_one_submission(
    client: &impl GenericClient,
    authority: &str,
    review_client: &ReviewClient,
    token: &BearerToken,
) -> Result<bool, MutationError> {
    let Some(job) = claim_submission(client, authority).await? else {
        return Ok(false);
    };
    let response = review_client
        .create_or_recover_request(
            token,
            &job.idempotency_key,
            &job.request,
            &job.expected_submission_digest,
        )
        .await;
    match response {
        Ok(complete) => {
            let accepted =
                serde_json::to_value(&complete.value).map_err(|_| MutationError::Unavailable)?;
            let updated = client
                .execute(
                    "UPDATE registry_internal.registry_request_review_submissions
                        SET state=CASE WHEN withdrawn THEN 'cancelling' ELSE 'accepted' END,
                            accepted_binding=$4,lease_until=NULL,
                            last_error_code=NULL,updated_at=transaction_timestamp()
                      WHERE request_entity_id=$1 AND request_id=$2 AND proposal_version=$3
                        AND state='submitting' AND expected_submission_digest=$5
                        AND lease_until=$6",
                    &[
                        &job.request_entity_id,
                        &job.request_id,
                        &job.proposal_version,
                        &accepted,
                        &job.expected_submission_digest.as_str(),
                        &job.lease_until,
                    ],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
            if updated != 1 {
                return Err(MutationError::PreconditionFailed);
            }
        }
        Err(_error) => {
            client
                .execute(
                    "UPDATE registry_internal.registry_request_review_submissions
                        SET state='uncertain',lease_until=NULL,last_error_code='remote-uncertain',
                            next_attempt_at=transaction_timestamp()+interval '5 seconds',
                            updated_at=transaction_timestamp()
                      WHERE request_entity_id=$1 AND request_id=$2 AND proposal_version=$3
                        AND state='submitting' AND lease_until=$4",
                    &[
                        &job.request_entity_id,
                        &job.request_id,
                        &job.proposal_version,
                        &job.lease_until,
                    ],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
        }
    }
    Ok(true)
}

pub async fn run_one_cancellation(
    client: &mut tokio_postgres::Client,
    authority_id: &str,
    review_client: &ReviewClient,
    token: &BearerToken,
) -> Result<bool, MutationError> {
    let Some(row) = client
        .query_opt(
            "UPDATE registry_internal.registry_request_review_submissions
                SET lease_until=transaction_timestamp()+($1::bigint * interval '1 second'),
                    attempt_count=LEAST(attempt_count+1,1000),updated_at=transaction_timestamp()
              WHERE (request_entity_id,request_id,proposal_version)=(
                    SELECT request_entity_id,request_id,proposal_version
                      FROM registry_internal.registry_request_review_submissions
                     WHERE state='cancelling' AND authority=$2
                       AND next_attempt_at <= transaction_timestamp()
                       AND (lease_until IS NULL OR lease_until < transaction_timestamp())
                     ORDER BY next_attempt_at,created_at FOR UPDATE SKIP LOCKED LIMIT 1)
              RETURNING request_entity_id,request_id,proposal_version,authority,
                        idempotency_key,accepted_binding,lease_until",
            &[&SUBMISSION_LEASE_SECONDS, &authority_id],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
    else {
        return Ok(false);
    };
    let entity_id: String = row.get(0);
    let request_id: Uuid = row.get(1);
    let version: i64 = row.get(2);
    let authority: String = row.get(3);
    let key = format!("{}-cancel", row.get::<_, String>(4));
    let accepted: ReviewRequestAccepted =
        serde_json::from_value(row.get(5)).map_err(|_| MutationError::Unavailable)?;
    let lease_until: chrono::DateTime<chrono::Utc> = row.get(6);
    let cancellation = registry_review_client::ReviewCancelRequest {
        subject: accepted.subject.clone(),
        reason: "source proposal withdrawn or superseded".to_owned(),
    };
    match review_client
        .cancel_request(token, accepted.request_id, &key, &cancellation)
        .await
    {
        Ok(complete) => {
            let result = match complete.value {
                registry_review_client::ReviewCancelResponse::Cancelled { result }
                | registry_review_client::ReviewCancelResponse::AlreadyTerminal { result } => {
                    result
                }
            };
            let transaction = client
                .transaction()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            let updated = transaction
                .execute(
                    "UPDATE registry_internal.registry_request_review_submissions
                        SET state='cancelled',lease_until=NULL,last_error_code=NULL,
                            updated_at=transaction_timestamp()
                      WHERE request_entity_id=$1 AND request_id=$2 AND proposal_version=$3
                        AND state='cancelling' AND lease_until=$4",
                    &[&entity_id, &request_id, &version, &lease_until],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
            if updated == 0 {
                transaction
                    .rollback()
                    .await
                    .map_err(|_| MutationError::Unavailable)?;
                return Ok(true);
            }
            reconcile_result(&transaction, &authority, &accepted, &result).await?;
            transaction
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
        }
        Err(_) => {
            client
                .execute(
                    "UPDATE registry_internal.registry_request_review_submissions
                        SET lease_until=NULL,last_error_code='cancellation-uncertain',
                            next_attempt_at=transaction_timestamp()+interval '5 seconds',
                            updated_at=transaction_timestamp()
                      WHERE request_entity_id=$1 AND request_id=$2 AND proposal_version=$3
                        AND state='cancelling' AND lease_until=$4",
                    &[&entity_id, &request_id, &version, &lease_until],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
        }
    }
    Ok(true)
}

pub async fn receive_completion(
    transaction: &Transaction<'_>,
    authority: &str,
    completion: &ReviewCompletion,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), MutationError> {
    // Reconciliation locks this same submission before storing its result and
    // updating early completions. Taking the lock here closes the inverse
    // ordering, where a result commits immediately before a late completion.
    let matched = transaction
        .query_opt(
            "SELECT 1 FROM registry_internal.registry_request_review_submissions
              WHERE authority=$1 AND accepted_binding->>'requestId'=$2
              FOR UPDATE",
            &[&authority, &completion.request_id.to_string()],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let state = if matched.is_some() {
        if transaction
            .query_opt(
                "SELECT 1
                   FROM registry_internal.registry_request_review_results r
                   JOIN registry_internal.registry_request_review_submissions s
                     USING (request_entity_id,request_id,proposal_version)
                  WHERE r.authority=$1 AND s.authority=r.authority
                    AND s.accepted_binding->>'requestId'=$2 AND r.result_id=$3",
                &[
                    &authority,
                    &completion.request_id.to_string(),
                    &completion.result_id,
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            .is_some()
        {
            "correlated"
        } else {
            "pending"
        }
    } else {
        "unmatched"
    };
    let persisted = transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_review_completions
             (authority,event_id,review_request_id,result_id,completed_at,state,expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (authority,event_id) DO UPDATE
                 SET state=registry_request_review_completions.state
               WHERE registry_request_review_completions.review_request_id=EXCLUDED.review_request_id
                 AND registry_request_review_completions.result_id=EXCLUDED.result_id
                 AND registry_request_review_completions.completed_at=EXCLUDED.completed_at",
            &[
                &authority,
                &completion.event_id,
                &completion.request_id,
                &completion.result_id,
                &completion.completed_at,
                &state,
                &expires_at,
            ],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    if persisted != 1 {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}

pub async fn reconcile_result(
    transaction: &Transaction<'_>,
    authority: &str,
    accepted: &ReviewRequestAccepted,
    result: &ReviewResult,
) -> Result<(), MutationError> {
    result
        .check()
        .map_err(|_| MutationError::PreconditionFailed)?;
    if result.request_id != accepted.request_id
        || result.subject != accepted.subject
        || result.policy != accepted.policy
        || result.submission_digest != accepted.submission_digest
    {
        return Err(MutationError::PreconditionFailed);
    }
    let row = transaction
        .query_opt(
            "SELECT request_entity_id,request_id,proposal_version,proposal_digest,
                    on_approved_mode,executor,withdrawn
               FROM registry_internal.registry_request_review_submissions
              WHERE authority=$1 AND accepted_binding=$2 AND state IN ('accepted','cancelling')
              FOR UPDATE",
            &[
                &authority,
                &serde_json::to_value(accepted).map_err(|_| MutationError::Unavailable)?,
            ],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::PreconditionFailed)?;
    let entity_id: String = row.get(0);
    let request_id: Uuid = row.get(1);
    let version: i64 = row.get(2);
    let proposal_digest: String = row.get(3);
    if result.subject.id != request_id.to_string()
        || result.subject.version != version.to_string()
        || result.subject.digest.as_str() != proposal_digest
    {
        return Err(MutationError::PreconditionFailed);
    }
    let status = result_status(result.status);
    let value = serde_json::to_value(result).map_err(|_| MutationError::Unavailable)?;
    let persisted = transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_review_results
             (request_entity_id,request_id,proposal_version,authority,result_id,result,
              status,completed_at,available_until)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             ON CONFLICT (request_entity_id,request_id,proposal_version) DO UPDATE
                 SET result=EXCLUDED.result
               WHERE registry_request_review_results.result_id=EXCLUDED.result_id
                 AND registry_request_review_results.result=EXCLUDED.result",
            &[
                &entity_id,
                &request_id,
                &version,
                &authority,
                &result.result_id,
                &value,
                &status,
                &result.completed_at,
                &result.available_until,
            ],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    if persisted != 1 {
        return Err(MutationError::PreconditionFailed);
    }
    transaction
        .execute(
            "UPDATE registry_internal.registry_request_review_completions
                SET state='correlated'
              WHERE authority=$1 AND review_request_id=$2 AND result_id=$3
                AND state IN ('pending','unmatched')",
            &[&authority, &result.request_id, &result.result_id],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let mode: String = row.get(4);
    let executor: Option<String> = row.get(5);
    let withdrawn: bool = row.get(6);
    if status == "approved" && mode == "automatic" && !withdrawn {
        let executor = executor.ok_or(MutationError::Unavailable)?;
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_application_jobs
                 (request_entity_id,request_id,proposal_version,job_id,proposal_digest,
                  result_id,executor,state)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,'queued') ON CONFLICT DO NOTHING",
                &[
                    &entity_id,
                    &request_id,
                    &version,
                    &Uuid::new_v4(),
                    &proposal_digest,
                    &result.result_id,
                    &executor,
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
    }
    Ok(())
}

pub async fn poll_one_result(
    client: &mut tokio_postgres::Client,
    authority_id: &str,
    review_client: &ReviewClient,
    token: &BearerToken,
) -> Result<bool, MutationError> {
    let Some(row) = client
        .query_opt(
            "SELECT authority,accepted_binding
               FROM registry_internal.registry_request_review_submissions s
              WHERE state='accepted' AND authority=$1
                AND next_result_poll_at <= transaction_timestamp()
                AND NOT EXISTS (
                    SELECT 1 FROM registry_internal.registry_request_review_results r
                     WHERE r.request_entity_id=s.request_entity_id AND r.request_id=s.request_id
                       AND r.proposal_version=s.proposal_version)
              ORDER BY updated_at LIMIT 1",
            &[&authority_id],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
    else {
        return Ok(false);
    };
    let authority: String = row.get(0);
    let accepted: ReviewRequestAccepted =
        serde_json::from_value(row.get(1)).map_err(|_| MutationError::Unavailable)?;
    let response = review_client
        .result(token, &accepted)
        .await
        .map_err(|_| MutationError::Unavailable)?;
    match response {
        ReviewResultResponse::Available(complete) => {
            let transaction = client
                .transaction()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            reconcile_result(&transaction, &authority, &accepted, &complete.value).await?;
            transaction
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
        }
        ReviewResultResponse::Pending { .. } | ReviewResultResponse::ConcealedOrUnknown { .. } => {
            client
                .execute(
                    "UPDATE registry_internal.registry_request_review_submissions
                        SET result_poll_attempts=LEAST(result_poll_attempts+1,1000),
                            next_result_poll_at=transaction_timestamp()+
                              (LEAST(60,5*LEAST(result_poll_attempts+1,1000)) * interval '1 second'),
                            updated_at=transaction_timestamp()
                      WHERE authority=$1 AND accepted_binding=$2 AND state='accepted'",
                    &[
                        &authority,
                        &serde_json::to_value(&accepted).map_err(|_| MutationError::Unavailable)?,
                    ],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
        }
        ReviewResultResponse::Expired { .. } => {
            client
                .execute(
                    "UPDATE registry_internal.registry_request_review_submissions
                        SET state='failed',last_error_code='result-expired',
                            updated_at=transaction_timestamp()
                      WHERE authority=$1 AND accepted_binding=$2 AND state='accepted'",
                    &[
                        &authority,
                        &serde_json::to_value(&accepted).map_err(|_| MutationError::Unavailable)?,
                    ],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
        }
        _ => return Err(MutationError::Unavailable),
    }
    Ok(true)
}

struct ApplicationJob {
    entity_id: String,
    request_id: Uuid,
    proposal_version: i64,
    job_id: Uuid,
    proposal_digest: String,
    claim_token: Uuid,
    attempt_count: i32,
    action_href: Option<String>,
    action_if_match: Option<String>,
}

enum ApplicationDiscovery {
    Action { href: String, if_match: String },
    Applied(Uuid),
}

async fn run_one_application(
    client: &mut tokio_postgres::Client,
    executor: &ReviewExecutorClient,
) -> Result<bool, MutationError> {
    let claim_token = Uuid::new_v4();
    let Some(row) = client
        .query_opt(
            "UPDATE registry_internal.registry_request_application_jobs j
                SET state='applying',attempt_count=attempt_count+1,
                    next_attempt_at=transaction_timestamp()+interval '30 seconds',
                    claim_token=$2,last_error_code=NULL,updated_at=transaction_timestamp()
              WHERE (request_entity_id,request_id,proposal_version)=(
                    SELECT q.request_entity_id,q.request_id,q.proposal_version
                      FROM registry_internal.registry_request_application_jobs q
                     WHERE q.executor=$1 AND q.state IN ('queued','applying')
                       AND q.attempt_count < $3
                       AND q.next_attempt_at <= transaction_timestamp()
                     ORDER BY q.next_attempt_at,q.created_at LIMIT 1 FOR UPDATE SKIP LOCKED)
          RETURNING request_entity_id,request_id,proposal_version,job_id,proposal_digest,
                    action_href,action_if_match,attempt_count",
            &[&executor.executor, &claim_token, &MAX_APPLICATION_ATTEMPTS],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
    else {
        return Ok(false);
    };
    let mut job = ApplicationJob {
        entity_id: row.get(0),
        request_id: row.get(1),
        proposal_version: row.get(2),
        job_id: row.get(3),
        proposal_digest: row.get(4),
        claim_token,
        action_href: row.get(5),
        action_if_match: row.get(6),
        attempt_count: row.get(7),
    };
    if job.action_href.is_none() {
        match discover_application(executor, &job).await {
            Ok(ApplicationDiscovery::Applied(application_id)) => {
                finish_application_job(client, &job, application_id).await?;
                return Ok(true);
            }
            Ok(ApplicationDiscovery::Action { href, if_match }) => {
                let updated = client
                    .execute(
                        "UPDATE registry_internal.registry_request_application_jobs
                            SET action_href=$2,action_if_match=$3,updated_at=transaction_timestamp()
                          WHERE job_id=$1 AND state='applying'
                            AND claim_token=$4
                            AND action_href IS NULL AND action_if_match IS NULL",
                        &[&job.job_id, &href, &if_match, &job.claim_token],
                    )
                    .await
                    .map_err(|_| MutationError::Unavailable)?;
                if updated != 1 {
                    return Err(MutationError::Unavailable);
                }
                job.action_href = Some(href);
                job.action_if_match = Some(if_match);
            }
            Err(ApplicationExchangeError::Denied) => {
                block_application_job(client, &job, "executor-denied").await?;
                return Ok(true);
            }
            Err(ApplicationExchangeError::UnavailableAction) => {
                block_application_job(client, &job, "source-action-unavailable").await?;
                return Ok(true);
            }
            Err(ApplicationExchangeError::Transient) => {
                exhaust_application_job_if_limit(client, &job).await?;
                return Ok(true);
            }
            Err(ApplicationExchangeError::InvalidResponse) => {
                block_application_job(client, &job, "source-response-invalid").await?;
                return Ok(true);
            }
            Err(ApplicationExchangeError::Stale) => {
                if exhaust_application_job_if_limit(client, &job).await? {
                    return Ok(true);
                }
                return Err(MutationError::Unavailable);
            }
        }
    }
    match send_application(executor, &job).await {
        Ok(application_id) => finish_application_job(client, &job, application_id).await?,
        Err(ApplicationExchangeError::Denied) => {
            block_application_job(client, &job, "executor-denied").await?
        }
        Err(ApplicationExchangeError::UnavailableAction) => {
            block_application_job(client, &job, "source-action-unavailable").await?
        }
        Err(ApplicationExchangeError::InvalidResponse) => {
            block_application_job(client, &job, "source-response-invalid").await?
        }
        Err(ApplicationExchangeError::Stale) => {
            let updated = client
                .execute(
                    "UPDATE registry_internal.registry_request_application_jobs
                        SET state=CASE WHEN attempt_count >= $3 THEN 'blocked' ELSE 'queued' END,
                            action_href=NULL,action_if_match=NULL,
                            claim_token=NULL,
                            next_attempt_at=transaction_timestamp(),
                            last_error_code=CASE WHEN attempt_count >= $3 THEN $4
                                ELSE 'source-precondition-changed' END,
                            updated_at=transaction_timestamp()
                      WHERE job_id=$1 AND state='applying' AND claim_token=$2",
                    &[
                        &job.job_id,
                        &job.claim_token,
                        &MAX_APPLICATION_ATTEMPTS,
                        &APPLICATION_ATTEMPTS_EXHAUSTED,
                    ],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
            if updated != 1 {
                return Err(MutationError::Unavailable);
            }
        }
        Err(ApplicationExchangeError::Transient) => {
            exhaust_application_job_if_limit(client, &job).await?;
        }
    }
    Ok(true)
}

async fn exhaust_application_job_if_limit(
    client: &tokio_postgres::Client,
    job: &ApplicationJob,
) -> Result<bool, MutationError> {
    if job.attempt_count < MAX_APPLICATION_ATTEMPTS {
        return Ok(false);
    }
    let updated = client
        .execute(
            "UPDATE registry_internal.registry_request_application_jobs
                SET state='blocked',claim_token=NULL,last_error_code=$2,
                    updated_at=transaction_timestamp()
              WHERE job_id=$1 AND state='applying' AND claim_token=$3",
            &[
                &job.job_id,
                &APPLICATION_ATTEMPTS_EXHAUSTED,
                &job.claim_token,
            ],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    if updated != 1 {
        return Err(MutationError::Unavailable);
    }
    Ok(true)
}

#[derive(Clone, Copy, Debug)]
enum ApplicationExchangeError {
    Denied,
    UnavailableAction,
    InvalidResponse,
    Stale,
    Transient,
}

async fn discover_application(
    executor: &ReviewExecutorClient,
    job: &ApplicationJob,
) -> Result<ApplicationDiscovery, ApplicationExchangeError> {
    let route = executor
        .request_routes
        .get(&job.entity_id)
        .ok_or(ApplicationExchangeError::InvalidResponse)?;
    let mut url = executor
        .base_url
        .join(&format!("v1/records/{route}/{}", job.request_id))
        .map_err(|_| ApplicationExchangeError::InvalidResponse)?;
    url.query_pairs_mut()
        .append_pair("accessProfile", &executor.access_profile);
    let response = executor
        .http
        .get(url)
        .header(AUTHORIZATION, executor.token.authorization_header_value())
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| ApplicationExchangeError::Transient)?;
    if matches!(response.status().as_u16(), 401 | 403 | 404) {
        return Err(ApplicationExchangeError::Denied);
    }
    if response.status() != reqwest::StatusCode::OK {
        return if response.status().is_server_error() {
            Err(ApplicationExchangeError::Transient)
        } else {
            Err(ApplicationExchangeError::InvalidResponse)
        };
    }
    validate_response_headers(response.headers())
        .map_err(|_| ApplicationExchangeError::InvalidResponse)?;
    let body = read_bounded(response, MAX_APPLICATION_RESPONSE_BYTES)
        .await
        .map_err(|_| ApplicationExchangeError::Transient)?;
    decode_application_discovery(executor, job, &body)
}

fn decode_application_discovery(
    executor: &ReviewExecutorClient,
    job: &ApplicationJob,
    body: &[u8],
) -> Result<ApplicationDiscovery, ApplicationExchangeError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| ApplicationExchangeError::InvalidResponse)?;
    let root = value
        .as_object()
        .ok_or(ApplicationExchangeError::InvalidResponse)?;
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .ok_or(ApplicationExchangeError::InvalidResponse)?;
    let meta = root
        .get("meta")
        .and_then(Value::as_object)
        .ok_or(ApplicationExchangeError::InvalidResponse)?;
    if meta.get("registryIdentifier").and_then(Value::as_str) != Some(executor.registry_id.as_str())
        || meta.get("entityTypeIdentifier").and_then(Value::as_str) != Some(job.entity_id.as_str())
        || data.get("recordIdentifier").and_then(Value::as_str)
            != Some(job.request_id.to_string().as_str())
    {
        return Err(ApplicationExchangeError::InvalidResponse);
    }
    let request = data
        .get("request")
        .and_then(Value::as_object)
        .ok_or(ApplicationExchangeError::InvalidResponse)?;
    if request.get("proposalVersion").and_then(Value::as_i64) != Some(job.proposal_version)
        || request.get("effectDigest").and_then(Value::as_str) != Some(job.proposal_digest.as_str())
    {
        return Err(ApplicationExchangeError::InvalidResponse);
    }
    if request.get("bregState").and_then(Value::as_str) == Some("applied") {
        let application_id = request
            .get("application")
            .and_then(Value::as_object)
            .and_then(|application| application.get("applicationId"))
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or(ApplicationExchangeError::InvalidResponse)?;
        return Ok(ApplicationDiscovery::Applied(application_id));
    }
    if request.get("bregState").and_then(Value::as_str) != Some("submitted") {
        return Err(ApplicationExchangeError::UnavailableAction);
    }
    let actions = request
        .get("actions")
        .and_then(Value::as_array)
        .ok_or(ApplicationExchangeError::UnavailableAction)?;
    let mut matches = actions.iter().filter_map(|action| {
        let action = action.as_object()?;
        (action.get("operation")?.as_str()? == "apply_request"
            && action.get("method")?.as_str()? == "POST"
            && action.get("proposalVersion")?.as_i64()? == job.proposal_version
            && action.get("effectDigest")?.as_str()? == job.proposal_digest)
            .then_some(action)
    });
    let action = matches
        .next()
        .filter(|_| matches.next().is_none())
        .ok_or(ApplicationExchangeError::UnavailableAction)?;
    let href = action
        .get("href")
        .and_then(Value::as_str)
        .ok_or(ApplicationExchangeError::InvalidResponse)?;
    validate_application_href(executor, job, href)?;
    let if_match = action
        .get("ifMatch")
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() <= 1024
                && value.starts_with('"')
                && value.ends_with('"')
                && value.bytes().all(|byte| byte >= 0x21 && byte != 0x7f)
        })
        .ok_or(ApplicationExchangeError::InvalidResponse)?;
    Ok(ApplicationDiscovery::Action {
        href: href.to_owned(),
        if_match: if_match.to_owned(),
    })
}

fn validate_application_href(
    executor: &ReviewExecutorClient,
    job: &ApplicationJob,
    href: &str,
) -> Result<(), ApplicationExchangeError> {
    if href.is_empty()
        || href.len() > 2048
        || !href.starts_with("/v1/records/")
        || href.starts_with("//")
        || href.contains('#')
    {
        return Err(ApplicationExchangeError::InvalidResponse);
    }
    let (path, query) = href
        .split_once('?')
        .ok_or(ApplicationExchangeError::InvalidResponse)?;
    let route = executor
        .request_routes
        .get(&job.entity_id)
        .ok_or(ApplicationExchangeError::InvalidResponse)?;
    let expected_path = format!("/v1/records/{route}/{}/actions/apply", job.request_id);
    if path != expected_path
        || query
            != format!(
                "accessProfile={}",
                percent_encode_query(&executor.access_profile)
            )
    {
        return Err(ApplicationExchangeError::InvalidResponse);
    }
    Ok(())
}

fn percent_encode_query(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    output
}

async fn send_application(
    executor: &ReviewExecutorClient,
    job: &ApplicationJob,
) -> Result<Uuid, ApplicationExchangeError> {
    let href = job
        .action_href
        .as_deref()
        .ok_or(ApplicationExchangeError::InvalidResponse)?;
    validate_application_href(executor, job, href)?;
    let (path, query) = href
        .trim_start_matches('/')
        .split_once('?')
        .ok_or(ApplicationExchangeError::InvalidResponse)?;
    let mut url = executor
        .base_url
        .join(path)
        .map_err(|_| ApplicationExchangeError::InvalidResponse)?;
    url.set_query(Some(query));
    let response = executor
        .http
        .post(url)
        .header(AUTHORIZATION, executor.token.authorization_header_value())
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/json")
        .header(
            IF_MATCH,
            job.action_if_match
                .as_deref()
                .ok_or(ApplicationExchangeError::InvalidResponse)?,
        )
        .header("idempotency-key", format!("review-apply-{}", job.job_id))
        .json(&json!({
            "proposalVersion": job.proposal_version,
            "effectDigest": job.proposal_digest,
        }))
        .send()
        .await
        .map_err(|_| ApplicationExchangeError::Transient)?;
    if matches!(response.status().as_u16(), 401 | 403 | 404) {
        return Err(ApplicationExchangeError::Denied);
    }
    if matches!(response.status().as_u16(), 409 | 412) {
        return Err(ApplicationExchangeError::Stale);
    }
    if response.status() != reqwest::StatusCode::OK {
        return if response.status().is_server_error() {
            Err(ApplicationExchangeError::Transient)
        } else {
            Err(ApplicationExchangeError::InvalidResponse)
        };
    }
    validate_response_headers(response.headers())
        .map_err(|_| ApplicationExchangeError::InvalidResponse)?;
    let body = read_bounded(response, MAX_APPLICATION_RESPONSE_BYTES)
        .await
        .map_err(|_| ApplicationExchangeError::Transient)?;
    decode_application_receipt(job, &body)
}

fn decode_application_receipt(
    job: &ApplicationJob,
    body: &[u8],
) -> Result<Uuid, ApplicationExchangeError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| ApplicationExchangeError::InvalidResponse)?;
    let root = value
        .as_object()
        .ok_or(ApplicationExchangeError::InvalidResponse)?;
    let request = root
        .get("request")
        .and_then(Value::as_object)
        .ok_or(ApplicationExchangeError::InvalidResponse)?;
    if root.get("id").and_then(Value::as_str) != Some(job.request_id.to_string().as_str())
        || request.get("bregState").and_then(Value::as_str) != Some("applied")
        || request.get("proposalVersion").and_then(Value::as_i64) != Some(job.proposal_version)
        || request.get("effectDigest").and_then(Value::as_str) != Some(job.proposal_digest.as_str())
    {
        return Err(ApplicationExchangeError::InvalidResponse);
    }
    let application = request
        .get("application")
        .and_then(Value::as_object)
        .ok_or(ApplicationExchangeError::InvalidResponse)?;
    if application.get("proposalVersion").and_then(Value::as_i64) != Some(job.proposal_version)
        || application.get("effectDigest").and_then(Value::as_str)
            != Some(job.proposal_digest.as_str())
    {
        return Err(ApplicationExchangeError::InvalidResponse);
    }
    application
        .get("applicationId")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(ApplicationExchangeError::InvalidResponse)
}

async fn finish_application_job(
    client: &tokio_postgres::Client,
    job: &ApplicationJob,
    application_id: Uuid,
) -> Result<(), MutationError> {
    let updated = client
        .execute(
            "UPDATE registry_internal.registry_request_application_jobs
                SET state='applied',application_id=$2,claim_token=NULL,last_error_code=NULL,
                    updated_at=transaction_timestamp()
              WHERE job_id=$1 AND state='applying' AND claim_token=$3",
            &[&job.job_id, &application_id, &job.claim_token],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    if updated != 1 {
        let converged = client
            .query_opt(
                "SELECT 1 FROM registry_internal.registry_request_application_jobs
                  WHERE job_id=$1 AND state='applied' AND application_id=$2",
                &[&job.job_id, &application_id],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            .is_some();
        if !converged {
            return Err(MutationError::Unavailable);
        }
    }
    Ok(())
}

async fn block_application_job(
    client: &tokio_postgres::Client,
    job: &ApplicationJob,
    code: &'static str,
) -> Result<(), MutationError> {
    let updated = client
        .execute(
            "UPDATE registry_internal.registry_request_application_jobs
                SET state='blocked',claim_token=NULL,last_error_code=$2,
                    updated_at=transaction_timestamp()
              WHERE job_id=$1 AND state='applying' AND claim_token=$3",
            &[&job.job_id, &code, &job.claim_token],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    if updated != 1 {
        return Err(MutationError::Unavailable);
    }
    Ok(())
}

fn result_status(status: registry_review_client::ReviewResultStatus) -> &'static str {
    match status {
        registry_review_client::ReviewResultStatus::Approved => "approved",
        registry_review_client::ReviewResultStatus::Rejected => "rejected",
        registry_review_client::ReviewResultStatus::ChangesRequested => "changes_requested",
        registry_review_client::ReviewResultStatus::Answered => "answered",
        registry_review_client::ReviewResultStatus::Cancelled => "cancelled",
        registry_review_client::ReviewResultStatus::Superseded => "superseded",
    }
}

pub(crate) async fn read_projection(
    transaction: &Transaction<'_>,
    request_entity_id: &str,
    request_id: Uuid,
    proposal: &ProposalSnapshot,
) -> Result<Option<Value>, MutationError> {
    let CompiledChangeRequestReview::Required(requirement) = proposal.review_requirement() else {
        return Ok(None);
    };
    let row = transaction
        .query_opt(
            "SELECT s.state,s.authority,s.accepted_binding,s.on_approved_mode,s.executor,
                    r.status,r.result_id,
                    to_char(r.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                    to_char(r.available_until AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                    j.state,j.application_id,COALESCE(j.last_error_code,s.last_error_code),
                    c.state,c.event_id,
                    to_char(c.received_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                    s.withdrawn
               FROM registry_internal.registry_request_review_submissions s
               LEFT JOIN registry_internal.registry_request_review_results r
                 USING (request_entity_id,request_id,proposal_version)
               LEFT JOIN registry_internal.registry_request_application_jobs j
                 USING (request_entity_id,request_id,proposal_version)
               LEFT JOIN LATERAL (
                    SELECT state,event_id,received_at
                      FROM registry_internal.registry_request_review_completions c
                     WHERE c.authority=s.authority
                       AND c.review_request_id=(s.accepted_binding->>'requestId')::uuid
                     ORDER BY received_at DESC LIMIT 1
               ) c ON s.accepted_binding IS NOT NULL
              WHERE s.request_entity_id=$1 AND s.request_id=$2 AND s.proposal_version=$3",
            &[
                &request_entity_id,
                &request_id,
                &i64::from(proposal.version().get()),
            ],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let Some(row) = row else {
        return Ok(Some(json!({
            "submission":{"state":"pending","authority":requirement.authority},
            "result":{"state":"pending"},
            "delivery":{"state":"polling"},
            "application":{"mode":application_mode(proposal),"state":"awaitingReview"},
            "recovery":{"state":"none"}
        })));
    };
    let withdrawn: bool = row.get(15);
    let submission_state = match row.get::<_, String>(0).as_str() {
        "pending" | "submitting" | "uncertain" if withdrawn => "cancelling",
        "pending" | "submitting" => "pending",
        "accepted" => "accepted",
        "uncertain" => "uncertain",
        "cancelling" => "cancelling",
        "cancelled" => "cancelled",
        "failed" => "failed",
        _ => return Err(MutationError::Unavailable),
    };
    let accepted: Option<Value> = row.get(2);
    let mut submission = json!({
        "state": submission_state,
        "authority": row.get::<_, String>(1),
    });
    if let Some(accepted) = accepted {
        submission["requestId"] = accepted["requestId"].clone();
        submission["submissionDigest"] = accepted["submissionDigest"].clone();
        submission["policy"] = accepted["policy"].clone();
    }
    let result_state = match row.get::<_, Option<String>>(5).as_deref() {
        None => "pending",
        Some("approved") => "approved",
        Some("rejected") => "rejected",
        Some("changes_requested") => "changesRequested",
        Some("answered") => "answered",
        Some("cancelled") => "cancelled",
        Some("superseded") => "superseded",
        Some(_) => return Err(MutationError::Unavailable),
    };
    let mut result = json!({"state": result_state});
    if let Some(result_id) = row.get::<_, Option<Uuid>>(6) {
        result["resultId"] = json!(result_id);
        if let Some(completed_at) = row.get::<_, Option<String>>(7) {
            result["completedAt"] = json!(completed_at);
        }
        if let Some(available_until) = row.get::<_, Option<String>>(8) {
            result["availableUntil"] = json!(available_until);
        }
    }
    let delivery_state = match row.get::<_, Option<String>>(12).as_deref() {
        None => "polling",
        Some("pending") => "received",
        Some("correlated" | "applied") => "reconciled",
        Some("unmatched") => "unmatched",
        Some("exhausted") => "exhausted",
        Some(_) => return Err(MutationError::Unavailable),
    };
    let mut delivery = json!({"state":delivery_state});
    if let Some(event_id) = row.get::<_, Option<Uuid>>(13) {
        delivery["eventId"] = json!(event_id);
        if let Some(received_at) = row.get::<_, Option<String>>(14) {
            delivery["receivedAt"] = json!(received_at);
        }
    }
    let application_state = match row.get::<_, Option<String>>(9).as_deref() {
        Some("queued") => "queued",
        Some("applying") => "applying",
        Some("applied") => "applied",
        Some("blocked") => "blocked",
        Some(_) => return Err(MutationError::Unavailable),
        None if row.get::<_, Option<String>>(5).as_deref() == Some("approved") => "ready",
        None => "awaitingReview",
    };
    let mode: String = row.get(3);
    let mut application = json!({"mode":mode,"state":application_state});
    if let Some(executor) = row.get::<_, Option<String>>(4) {
        application["executor"] = json!(executor);
    }
    if let Some(application_id) = row.get::<_, Option<Uuid>>(10) {
        application["applicationId"] = json!(application_id);
    }
    let recovery = match row.get::<_, Option<String>>(11) {
        None => json!({"state":"none"}),
        Some(code) => json!({"state":"operatorAttention","code":code}),
    };
    Ok(Some(json!({
        "submission":submission,"result":result,"delivery":delivery,
        "application":application,"recovery":recovery
    })))
}

fn application_mode(proposal: &ProposalSnapshot) -> &'static str {
    match proposal.on_approved().mode {
        CompiledChangeRequestOnApprovedMode::Manual => "manual",
        CompiledChangeRequestOnApprovedMode::Automatic => "automatic",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn executor() -> ReviewExecutorClient {
        ReviewExecutorClient::new(
            "registry-automatic".to_owned(),
            "http://127.0.0.1:8080/registry-prefix/"
                .parse()
                .expect("URL"),
            BearerToken::new("ordinary-executor-token").expect("token"),
            "registry-a".to_owned(),
            "automatic-applier".to_owned(),
            BTreeMap::from([("requests".to_owned(), "requests".to_owned())]),
            std::time::Duration::from_secs(1),
        )
        .expect("executor")
    }

    fn application_job() -> ApplicationJob {
        ApplicationJob {
            entity_id: "requests".to_owned(),
            request_id: Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap(),
            proposal_version: 7,
            job_id: Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap(),
            proposal_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            claim_token: Uuid::parse_str("00000000-0000-4000-8000-000000000006").unwrap(),
            attempt_count: 1,
            action_href: None,
            action_if_match: None,
        }
    }

    fn authority(id: &str, completion: Option<(&str, &str)>) -> Arc<ReviewAuthorityClient> {
        let client = ReviewClient::new(
            registry_review_client::ReviewClientConfig::new(
                "https://casework.example.test/".parse().expect("URL"),
            )
            .with_profile("producer"),
        )
        .expect("client");
        Arc::new(
            ReviewAuthorityClient::new(
                id.to_owned(),
                client,
                Arc::new(
                    registry_platform_httputil::StaticToken::new("outgoing-token".to_owned())
                        .expect("outgoing token"),
                ),
                format!("{id}-producer"),
                30,
                completion.map(|(token, _)| Zeroizing::new(token.to_owned())),
                completion.map(|(_, recipient)| recipient.to_owned()),
            )
            .expect("authority"),
        )
    }

    #[test]
    fn completion_sender_requires_exact_independent_token_and_recipient() {
        let registry = ReviewAuthorityRegistry::new(BTreeMap::from([
            (
                "casework-a".to_owned(),
                authority("casework-a", Some(("sender-a", "registry-a"))),
            ),
            (
                "casework-b".to_owned(),
                authority("casework-b", Some(("sender-b", "registry-b"))),
            ),
        ]))
        .expect("registry");

        assert_eq!(
            registry.completion_authority("sender-a", "registry-a"),
            Some("casework-a")
        );
        assert_eq!(
            registry.completion_authority("sender-a", "registry-b"),
            None
        );
        assert_eq!(
            registry.completion_authority("sender-b", "registry-a"),
            None
        );
        assert_eq!(
            registry.completion_authority("outgoing-token", "registry-a"),
            None
        );
    }

    #[test]
    fn completion_recipient_accepts_the_shared_byte_bound() {
        let at_bound = "x".repeat(MAXIMUM_COMPLETION_RECIPIENT_BYTES);
        authority("casework-a", Some(("sender-a", &at_bound)));

        let over_bound = "x".repeat(MAXIMUM_COMPLETION_RECIPIENT_BYTES + 1);
        let client = ReviewClient::new(
            registry_review_client::ReviewClientConfig::new(
                "https://casework.example.test/".parse().expect("URL"),
            )
            .with_profile("producer"),
        )
        .expect("client");
        assert!(
            ReviewAuthorityClient::new(
                "casework-a".to_owned(),
                client,
                Arc::new(
                    registry_platform_httputil::StaticToken::new("outgoing-token".to_owned())
                        .expect("outgoing token"),
                ),
                "registry-producer".to_owned(),
                30,
                Some(Zeroizing::new("sender-a".to_owned())),
                Some(over_bound),
            )
            .is_err(),
            "a completion recipient over the shared byte bound is refused"
        );
    }

    #[test]
    fn review_authority_accepts_the_casework_recovery_bound() {
        let configured = |recovery_days| {
            ReviewAuthorityClient::new(
                "casework-a".to_owned(),
                ReviewClient::new(
                    registry_review_client::ReviewClientConfig::new(
                        "https://casework.example.test/".parse().expect("URL"),
                    )
                    .with_profile("producer"),
                )
                .expect("client"),
                Arc::new(
                    registry_platform_httputil::StaticToken::new("outgoing-token".to_owned())
                        .expect("outgoing token"),
                ),
                "registry-producer".to_owned(),
                recovery_days,
                None,
                None,
            )
        };

        assert!(configured(91).is_ok());
        assert!(configured(MAXIMUM_REVIEW_RECOVERY_DAYS).is_ok());
        assert!(configured(0).is_err());
        assert!(configured(MAXIMUM_REVIEW_RECOVERY_DAYS + 1).is_err());
    }

    #[test]
    fn polling_only_authority_has_no_completion_sender() {
        let registry = ReviewAuthorityRegistry::new(BTreeMap::from([(
            "casework-a".to_owned(),
            authority("casework-a", None),
        )]))
        .expect("registry");

        assert_eq!(
            registry.completion_authority("any-token", "any-recipient"),
            None
        );
        assert_eq!(
            registry.submission_binding("casework-a"),
            Some(("casework-a-producer", 30))
        );
    }

    #[test]
    fn automatic_executor_discovers_only_the_exact_source_action_binding() {
        let executor = executor();
        let job = application_job();
        let response = json!({
            "data": {
                "recordIdentifier": job.request_id,
                "revisionIdentifier": "3",
                "domainData": {},
                "request": {
                    "bregState": "submitted",
                    "proposalVersion": job.proposal_version,
                    "effectDigest": job.proposal_digest,
                    "editable": false,
                    "actions": [{
                        "operation": "apply_request",
                        "method": "POST",
                        "href": format!(
                            "/v1/records/requests/{}/actions/apply?accessProfile=automatic-applier",
                            job.request_id
                        ),
                        "ifMatch": "\"breg-request-etag\"",
                        "proposalVersion": job.proposal_version,
                        "effectDigest": job.proposal_digest,
                    }]
                }
            },
            "meta": {
                "registryIdentifier": "registry-a",
                "datasetIdentifier": "requests",
                "entityTypeIdentifier": "requests"
            }
        });
        let decoded =
            decode_application_discovery(&executor, &job, &serde_json::to_vec(&response).unwrap());
        assert!(matches!(decoded, Ok(ApplicationDiscovery::Action { .. })));

        for pointer in [
            "/meta/registryIdentifier",
            "/data/request/effectDigest",
            "/data/request/actions/0/effectDigest",
            "/data/request/actions/0/href",
        ] {
            let mut substituted = response.clone();
            *substituted.pointer_mut(pointer).expect("fixture pointer") =
                Value::String("substituted".to_owned());
            assert!(matches!(
                decode_application_discovery(
                    &executor,
                    &job,
                    &serde_json::to_vec(&substituted).unwrap()
                ),
                Err(ApplicationExchangeError::InvalidResponse)
                    | Err(ApplicationExchangeError::UnavailableAction)
            ));
        }
    }

    #[tokio::test]
    async fn automatic_executor_refuses_substituted_apply_hrefs_before_http() {
        let executor = executor();
        let mut job = application_job();
        job.action_if_match = Some("\"breg-request-etag\"".to_owned());
        for href in [
            format!(
                "/v1/records/other/{}/actions/apply?accessProfile=automatic-applier",
                job.request_id
            ),
            "/v1/records/requests/00000000-0000-4000-8000-000000000099/actions/apply?accessProfile=automatic-applier".to_owned(),
            format!(
                "/v1/records/requests/{}/actions/cancel?accessProfile=automatic-applier",
                job.request_id
            ),
            format!(
                "/v1/records/requests/{}/actions/apply/extra?accessProfile=automatic-applier",
                job.request_id
            ),
            format!(
                "/v1/records/requests/{}/actions/apply?accessProfile=substituted",
                job.request_id
            ),
        ] {
            job.action_href = Some(href);
            assert!(matches!(
                send_application(&executor, &job).await,
                Err(ApplicationExchangeError::InvalidResponse)
            ));
        }
    }

    #[test]
    fn automatic_executor_accepts_only_an_exact_application_receipt() {
        let job = application_job();
        let application_id = Uuid::parse_str("00000000-0000-4000-8000-000000000003").unwrap();
        let receipt = json!({
            "id": job.request_id,
            "revision": 4,
            "snapshot": "breg1_00000000-0000-4000-8000-000000000004",
            "actorReference": "actor",
            "request": {
                "bregState": "applied",
                "proposalVersion": job.proposal_version,
                "effectDigest": job.proposal_digest,
                "application": {
                    "applicationId": application_id,
                    "proposalVersion": job.proposal_version,
                    "effectDigest": job.proposal_digest,
                    "appliedAt": "2026-09-19T00:00:00Z"
                }
            }
        });
        assert_eq!(
            decode_application_receipt(&job, &serde_json::to_vec(&receipt).unwrap())
                .expect("exact receipt"),
            application_id
        );

        for pointer in [
            "/id",
            "/request/proposalVersion",
            "/request/application/effectDigest",
            "/request/application/applicationId",
        ] {
            let mut substituted = receipt.clone();
            *substituted.pointer_mut(pointer).expect("fixture pointer") =
                Value::String("substituted".to_owned());
            assert!(matches!(
                decode_application_receipt(&job, &serde_json::to_vec(&substituted).unwrap()),
                Err(ApplicationExchangeError::InvalidResponse)
            ));
        }
    }
}

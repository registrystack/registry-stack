// SPDX-License-Identifier: Apache-2.0

//! Durable source-owned review submission, completion, and application state.
//!
//! Network calls are deliberately separated from every database transaction.
//! A claimed job is committed before I/O and every response is written through
//! an exact proposal and submission-digest comparison.

use chrono::{DateTime, Utc};
use registry_platform_httputil::client::TokenProvider;
use registry_review_client::{
    submission_digest, BearerToken, ReviewAuth, ReviewClient, ReviewClientError, ReviewCompletion,
    ReviewCompletionType, ReviewCreateRequest, ReviewRequestAccepted, ReviewResult,
    ReviewResultResponse, ReviewResultsQuery, SourceContextBinding, SubjectBinding,
    SubmissionDigest,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio_postgres::{GenericClient, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::model::{CompiledProposalReview, CompiledRegistry};
use crate::mutation::MutationError;
use crate::postgres::SqlIdentifier;
use crate::proposal_workflow::ProposalSnapshot;

const APPLICATION_LEASE_MINIMUM_SECONDS: i64 = 30;
pub(crate) const MAXIMUM_COMPLETION_RECIPIENT_BYTES: usize = 256;
pub(crate) const MAXIMUM_REVIEW_RECOVERY_DAYS: u32 = 3_650;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StoredSubmissionDigestCompatibility {
    Current,
    LegacyRegistryId,
}

/// Verify the digest retained with one frozen Review request. Current work is
/// keyed by its configured source. Accepted work created before that correction
/// may retain the registry-id-keyed digest, but only when the same complete
/// request and accepted binding carry that exact historical digest.
pub(crate) fn stored_submission_digest_compatibility(
    producer: &str,
    registry_id: &str,
    request: &ReviewCreateRequest,
    stored: &SubmissionDigest,
    accepted: Option<&ReviewRequestAccepted>,
) -> Result<(StoredSubmissionDigestCompatibility, SubmissionDigest), MutationError> {
    let current = submission_digest(producer, &request.subject.source, request)
        .map_err(|_| MutationError::PreconditionFailed)?;
    let compatibility = if *stored == current {
        StoredSubmissionDigestCompatibility::Current
    } else {
        let legacy = submission_digest(producer, registry_id, request)
            .map_err(|_| MutationError::PreconditionFailed)?;
        if *stored != legacy {
            return Err(MutationError::PreconditionFailed);
        }
        StoredSubmissionDigestCompatibility::LegacyRegistryId
    };
    if accepted.is_some_and(|accepted| accepted.submission_digest != *stored) {
        return Err(MutationError::PreconditionFailed);
    }
    Ok((compatibility, current))
}

/// A review submission is claimable once it is due and no live lease holds
/// it: a `submitting` claim stays with its holder until its lease expires,
/// and a `cancelling` row is free when it has no lease or an expired one.
/// The worker selects its authorities and backs off token failures with this
/// predicate, and the metrics queue-age sample shares it, so a submission
/// the worker would claim always ages the review submission queue. Column
/// names are unqualified: every query this is spliced into reads only the
/// submissions table.
pub(crate) const REVIEW_SUBMISSION_CLAIMABLE: &str = "next_attempt_at <= transaction_timestamp()
        AND (state<>'submitting' OR lease_until < transaction_timestamp())
        AND (state<>'cancelling' OR lease_until IS NULL
             OR lease_until < transaction_timestamp())";

fn outbound_lease_seconds(request_timeout: Duration) -> i64 {
    // The claim lease must outlive the outbound call it guards: an expiry
    // inside the request timeout lets another instance treat the job as
    // unclaimed while the original request is still in flight. A five second
    // grace absorbs scheduling delay and database clock difference; short
    // timeouts keep the thirty second floor so fast-failing jobs are retried
    // promptly.
    (i64::try_from(request_timeout.as_secs()).unwrap_or(i64::MAX) + 5)
        .max(APPLICATION_LEASE_MINIMUM_SECONDS)
}

pub(crate) fn valid_completion_recipient(recipient: &str) -> bool {
    !recipient.is_empty()
        && recipient.len() <= MAXIMUM_COMPLETION_RECIPIENT_BYTES
        && recipient.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn valid_completion_token(token: &str) -> bool {
    registry_platform_authcommon::parse_bearer_token(&format!("Bearer {token}"))
        .is_ok_and(|parsed| parsed == token)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewConfigurationError;

impl std::fmt::Display for ReviewConfigurationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid review integration configuration")
    }
}

impl std::error::Error for ReviewConfigurationError {}

/// Why retained review work cannot be served by the candidate runtime
/// bindings. The missing-authority case carries only the authored logical
/// identifier and an aggregate count; request identifiers and stored review
/// values remain outside startup diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetainedReviewBindingError {
    MissingAuthority {
        authority: String,
        retained_submissions: u64,
    },
    Refused,
    Unavailable,
}

impl std::fmt::Display for RetainedReviewBindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAuthority {
                authority,
                retained_submissions,
            } => write!(
                formatter,
                "review authority {authority} is required by {retained_submissions} retained submissions"
            ),
            Self::Refused => formatter.write_str("retained review bindings were refused"),
            Self::Unavailable => {
                formatter.write_str("retained review bindings could not be inspected")
            }
        }
    }
}

impl std::error::Error for RetainedReviewBindingError {}

/// Configured bindings must retain the producer identity of accepted work.
/// Missing bindings leave that immutable work pending and inspectable until
/// the dependency is restored, while unrelated registry operations stay usable.
pub async fn verify_retained_bindings(
    pool: &crate::postgres::RuntimePool,
    registry: &CompiledRegistry,
    authorities: Option<&ReviewAuthorityRegistry>,
) -> Result<(), RetainedReviewBindingError> {
    let client = pool
        .get()
        .await
        .map_err(|_| RetainedReviewBindingError::Unavailable)?;
    let authority_rows = client
        .query(
            "SELECT authority,
                        array_agg(DISTINCT producer_id ORDER BY producer_id),
                        count(*)::bigint
               FROM registry_internal.registry_proposal_review_submissions s
              WHERE state IN ('pending','submitting','uncertain','cancelling')
                 OR (s.state='accepted' AND EXISTS (
                         SELECT 1 FROM registry_internal.registry_proposal_state w
                          WHERE (w.action_id,w.proposal_id,w.submission_version)=
                                (s.action_id,s.proposal_id,s.submission_version)
                            AND w.state='submitted'))
              GROUP BY authority
              ORDER BY authority",
            &[],
        )
        .await
        .map_err(|_| RetainedReviewBindingError::Unavailable)?;
    for row in &authority_rows {
        let authority = row.get::<_, String>(0);
        // Missing configuration is a recoverable dependency outage. If a
        // binding is supplied, its retained producer identity must still match.
        let Some(configured) = authorities.filter(|configured| configured.contains(&authority))
        else {
            continue;
        };
        let producer_ids = row.get::<_, Vec<String>>(1);
        if producer_ids
            .iter()
            .any(|producer_id| !configured.contains_binding(&authority, producer_id))
        {
            return Err(RetainedReviewBindingError::Refused);
        }
    }
    if let Some(configured) = authorities {
        let current = registry
            .actions()
            .actions
            .iter()
            .filter_map(|action| match &action.execution {
                crate::model::CompiledActionExecution::Proposal { proposal } => match &proposal
                    .review
                {
                    CompiledProposalReview::Required { authority, .. } => Some(authority.as_str()),
                    CompiledProposalReview::None => None,
                },
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        if configured.authorities.keys().any(|authority| {
            !current.contains(authority.as_str())
                && !authority_rows
                    .iter()
                    .any(|row| row.get::<_, String>(0) == *authority)
        }) {
            return Err(RetainedReviewBindingError::Refused);
        }
    }
    Ok(())
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn run_review_authority_once_for_test(
    pool: &crate::postgres::RuntimePool,
    authorities: &ReviewAuthorityRegistry,
    mutations: &crate::postgres::PostgresRecordMutationService,
) -> Result<bool, MutationError> {
    let mut client = pool.get().await.map_err(|_| MutationError::Unavailable)?;
    authorities.run_one(&mut client, mutations).await
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn back_off_review_token_failure_for_test(
    client: &tokio_postgres::Client,
    authority: &str,
    states: &[&str],
) -> Result<(), MutationError> {
    ReviewAuthorityRegistry::back_off_token_failure(client, authority, states).await
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn install_review_storage_for_test(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), MutationError> {
    install(client, runtime_role).await
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn schedule_cancellation_for_test(
    transaction: &Transaction<'_>,
    action_id: &str,
    proposal_id: Uuid,
    submission_version: i64,
) -> Result<(), MutationError> {
    schedule_cancellation(transaction, action_id, proposal_id, submission_version).await
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
    profile: String,
    producer_id: String,
    recovery_days: u32,
    completion_token: Option<Zeroizing<String>>,
    completion_recipient: Option<String>,
    lease_seconds: i64,
}

impl ReviewAuthorityClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority: String,
        client: ReviewClient,
        token_provider: Arc<dyn TokenProvider>,
        profile: String,
        producer_id: String,
        recovery_days: u32,
        completion_token: Option<Zeroizing<String>>,
        completion_recipient: Option<String>,
    ) -> Result<Self, ReviewConfigurationError> {
        if authority.trim().is_empty()
            || authority.len() > 128
            || profile.is_empty()
            || profile.len() > 128
            || !profile.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
            || producer_id.trim().is_empty()
            || producer_id.len() > 128
            || producer_id.chars().any(char::is_control)
            || !(1..=MAXIMUM_REVIEW_RECOVERY_DAYS).contains(&recovery_days)
            || completion_token.is_some() != completion_recipient.is_some()
            || completion_token
                .as_ref()
                .is_some_and(|token| token.len() > 4096 || !valid_completion_token(token))
            || completion_recipient
                .as_ref()
                .is_some_and(|recipient| !valid_completion_recipient(recipient))
        {
            return Err(ReviewConfigurationError);
        }
        // Submission, cancellation, and result-poll claims all guard one
        // outbound exchange on this authority's client, so their lease is
        // sized from that client's per-attempt timeout.
        let lease_seconds = outbound_lease_seconds(client.attempt_timeout());
        Ok(Self {
            authority,
            client,
            token_provider,
            profile,
            producer_id,
            recovery_days,
            completion_token,
            completion_recipient,
            lease_seconds,
        })
    }
}

pub struct ReviewAuthorityRegistry {
    authorities: BTreeMap<String, Arc<ReviewAuthorityClient>>,
    /// Result-feed backoff by authority. An authority with no entry is
    /// available and its feed is fetched on every worker pass.
    feed_backoff: std::sync::Mutex<BTreeMap<String, FeedBackoff>>,
    feed_clock: FeedClock,
}

/// The time result-feed backoff is measured against: the runtime clock, or
/// one a test drives.
type FeedClock = Arc<dyn Fn() -> tokio::time::Instant + Send + Sync>;

/// The first wait after a result feed fetch fails. Each further consecutive
/// failure doubles it, up to [`FEED_BACKOFF_CEILING`].
const FEED_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// The longest wait between fetches of an unavailable result feed, the same
/// ceiling `next_result_poll_at` applies to result polls.
const FEED_BACKOFF_CEILING: Duration = Duration::from_secs(60);

/// The consecutive failures of one authority's result feed and when it may
/// be fetched again.
struct FeedBackoff {
    failures: u32,
    retry_at: tokio::time::Instant,
}

/// The wait after `failures` consecutive failed fetches: 1, 2, 4, ... seconds,
/// capped at the ceiling.
fn feed_backoff_delay(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(6);
    FEED_BACKOFF_INITIAL
        .saturating_mul(1 << doublings)
        .min(FEED_BACKOFF_CEILING)
}

impl ReviewAuthorityRegistry {
    /// Read the original accepted closure through its configured authority.
    /// The exchange sends only the retained request UUID, with no Proposal
    /// input, context payload, or creation/recovery key.
    pub(crate) async fn prove_accepted_closure(
        &self,
        authority: &str,
        producer: &str,
        accepted: &ReviewRequestAccepted,
        retained_result: Option<&ReviewResult>,
    ) -> Result<Vec<u8>, MutationError> {
        let configured = self
            .authorities
            .get(authority)
            .ok_or(MutationError::Unavailable)?;
        if configured.producer_id != producer {
            return Err(MutationError::PreconditionFailed);
        }
        let token = configured
            .token_provider
            .bearer_token()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let view = configured
            .client
            .request(
                ReviewAuth::new(&token, &configured.profile),
                accepted.request_id,
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            .value;
        if view.request_id != accepted.request_id
            || view.subject != accepted.subject
            || view.policy != accepted.policy
            || view.submission_digest != accepted.submission_digest
        {
            return Err(MutationError::PreconditionFailed);
        }
        let result = if let Some(retained) = retained_result {
            let ReviewResultResponse::Available(current) = configured
                .client
                .result(ReviewAuth::new(&token, &configured.profile), accepted)
                .await
                .map_err(|_| MutationError::Unavailable)?
            else {
                return Err(MutationError::PreconditionFailed);
            };
            if current.value != *retained || current.value.available_until <= Utc::now() {
                return Err(MutationError::PreconditionFailed);
            }
            Some(current.value)
        } else {
            None
        };
        registry_platform_canonical_json::canonicalize_json(&serde_json::json!({
            "authority":authority,"producer":producer,"accepted":accepted,"request":view,"result":result,
        })).map_err(|_|MutationError::Unavailable)
    }

    pub fn new(
        authorities: BTreeMap<String, Arc<ReviewAuthorityClient>>,
    ) -> Result<Self, ReviewConfigurationError> {
        if authorities.is_empty()
            || authorities
                .iter()
                .any(|(id, authority)| id != &authority.authority)
            || authorities.values().enumerate().any(|(index, authority)| {
                authorities
                    .values()
                    .skip(index + 1)
                    .any(|other| same_completion_binding(authority, other))
            })
        {
            return Err(ReviewConfigurationError);
        }
        Ok(Self {
            authorities,
            feed_backoff: std::sync::Mutex::new(BTreeMap::new()),
            feed_clock: Arc::new(tokio::time::Instant::now),
        })
    }

    fn feed_backoff(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, FeedBackoff>> {
        self.feed_backoff
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether `authority`'s result feed may be fetched on this pass: always
    /// while it is available, and once its backoff has elapsed after failures.
    fn feed_due(&self, authority: &str) -> bool {
        let now = (self.feed_clock)();
        self.feed_backoff()
            .get(authority)
            .is_none_or(|backoff| now >= backoff.retry_at)
    }

    /// Record the outcome of one result feed fetch. A failure schedules the
    /// next fetch on a doubling backoff; a successful page ends the backoff.
    /// Only the transitions warn, so an authority that stays unavailable is
    /// logged once instead of on every pass.
    fn record_feed_outcome(&self, authority: &str, available: bool) {
        let mut backoff = self.feed_backoff();
        if available {
            if let Some(ended) = backoff.remove(authority) {
                tracing::warn!(
                    authority,
                    failed_fetches = ended.failures,
                    "BReg review result feed is available again"
                );
            }
            return;
        }
        let failures = backoff
            .get(authority)
            .map_or(1, |backoff| backoff.failures.saturating_add(1));
        let delay = feed_backoff_delay(failures);
        backoff.insert(
            authority.to_owned(),
            FeedBackoff {
                failures,
                retry_at: (self.feed_clock)() + delay,
            },
        );
        if failures == 1 {
            tracing::warn!(
                authority,
                retry_in_seconds = delay.as_secs(),
                "BReg review result feed is unavailable; retrying with backoff"
            );
        } else {
            tracing::debug!(
                authority,
                failures,
                retry_in_seconds = delay.as_secs(),
                "BReg review result feed is still unavailable"
            );
        }
    }

    /// Measure result-feed backoff against `clock` instead of the runtime
    /// clock, so a test can drive many worker passes without waiting.
    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    #[must_use]
    pub fn with_feed_clock_for_test(
        mut self,
        clock: Arc<dyn Fn() -> tokio::time::Instant + Send + Sync>,
    ) -> Self {
        self.feed_clock = clock;
        self
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
                &format!(
                    "SELECT authority,min(next_attempt_at) AS ready_at
                       FROM registry_internal.registry_proposal_review_submissions
                      WHERE state=ANY($1) AND {REVIEW_SUBMISSION_CLAIMABLE}
                      GROUP BY authority ORDER BY ready_at,authority"
                ),
                &[&states],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                self.authorities
                    .get(row.get::<_, String>(0).as_str())
                    .cloned()
            })
            .collect())
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
                &format!(
                    "UPDATE registry_internal.registry_proposal_review_submissions
                        SET state=CASE WHEN state='submitting' THEN 'uncertain' ELSE state END,
                            lease_until=NULL,last_error_code='token-unavailable',
                            next_attempt_at=transaction_timestamp()+interval '5 seconds',
                            updated_at=transaction_timestamp()
                      WHERE authority=$1 AND state=ANY($2) AND {REVIEW_SUBMISSION_CLAIMABLE}"
                ),
                &[&authority, &states],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        Ok(())
    }

    async fn run_one(
        &self,
        client: &mut tokio_postgres::Client,
        mutations: &crate::postgres::PostgresRecordMutationService,
    ) -> Result<bool, MutationError> {
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
                "UPDATE registry_internal.registry_proposal_review_submissions
                    SET state='failed',lease_until=NULL,last_error_code='submission-recovery-expired',
                        updated_at=transaction_timestamp()
                  WHERE accepted_binding IS NULL AND recovery_deadline <= transaction_timestamp()
                    AND state IN ('pending','submitting','uncertain')
                    AND (state<>'submitting' OR lease_until IS NULL
                         OR lease_until < transaction_timestamp())",
                &[],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            > 0
        {
            return Ok(true);
        }
        // A cancelling submission whose result is already stored must not be
        // failed: the stored result proves the remote request settled, so the
        // submission converges to cancelled while retaining its binding.
        if client
            .execute(
                "UPDATE registry_internal.registry_proposal_review_submissions s
                    SET state='cancelled',lease_until=NULL,last_error_code=NULL,
                        updated_at=transaction_timestamp()
                  WHERE s.state='cancelling' AND s.accepted_binding IS NOT NULL
                    AND (s.recovery_deadline <= transaction_timestamp()
                         OR s.attempt_count >= 1000)
                    AND EXISTS (
                        SELECT 1 FROM registry_internal.registry_proposal_review_results r
                         WHERE (r.action_id,r.proposal_id,r.submission_version)
                               = (s.action_id,s.proposal_id,s.submission_version)
                    )",
                &[],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            > 0
        {
            return Ok(true);
        }
        if client
            .execute(
                // The binding is kept, not cleared: `receive_completion` and an
                // operator reading the row both correlate a late Casework
                // settlement by the same `accepted_binding` a live cancellation
                // used, exactly as the result-bearing sweep above retains it.
                "UPDATE registry_internal.registry_proposal_review_submissions
                    SET state='failed',lease_until=NULL,
                        last_error_code=CASE
                            WHEN recovery_deadline <= transaction_timestamp()
                            THEN 'cancellation-recovery-expired'
                            ELSE 'cancellation-attempts-exhausted'
                        END,
                        updated_at=transaction_timestamp()
                  WHERE state='cancelling'
                    AND (recovery_deadline <= transaction_timestamp() OR attempt_count >= 1000)
                    AND (lease_until IS NULL OR lease_until < transaction_timestamp())",
                &[],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            > 0
        {
            return Ok(true);
        }
        // An accepted row whose result lookup keeps failing has no other give-up
        // path: it never returns to `pending`/`cancelling`, so without this sweep
        // a permanently broken result endpoint would poll forever. Only the
        // saturated poll-attempt budget bounds it. The recovery deadline bounds
        // idempotent submission replay, not the life of a review the authority
        // accepted: a review may stay pending for as long as the authority
        // holds it, and a pending answer never spends this budget. The binding
        // is preserved for the same late-correlation reason as above.
        if client
            .execute(
                "UPDATE registry_internal.registry_proposal_review_submissions s
                    SET state='failed',lease_until=NULL,
                        last_error_code='result-poll-attempts-exhausted',
                        updated_at=transaction_timestamp()
                  WHERE s.state='accepted'
                    AND s.result_poll_attempts >= 1000
                    AND (s.lease_until IS NULL OR s.lease_until < transaction_timestamp())
                    AND NOT EXISTS (
                        SELECT 1 FROM registry_internal.registry_proposal_review_results r
                         WHERE (r.action_id,r.proposal_id,r.submission_version)
                               = (s.action_id,s.proposal_id,s.submission_version))",
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
            if run_one_submission(
                client,
                &authority.authority,
                &authority.client,
                &authority.profile,
                &token,
                authority.lease_seconds,
            )
            .await?
            {
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
            if run_one_cancellation(
                client,
                &authority.authority,
                &authority.client,
                &authority.profile,
                &token,
                authority.lease_seconds,
                mutations,
            )
            .await?
            {
                return Ok(true);
            }
        }
        let mut unavailable_lookups = 0usize;
        // The feed also carries completions for submissions in every other
        // state, including ones not yet bound or already given up, so it is
        // read even for an authority with no accepted or cancelling review.
        // A failing feed backs off on its own schedule instead.
        for authority in self.authorities.values() {
            if !self.feed_due(&authority.authority) {
                continue;
            }
            let outcome = consume_result_feed(client, authority).await;
            self.record_feed_outcome(&authority.authority, outcome.is_ok());
            match outcome {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(_) => authority_unavailable = true,
            }
        }
        let rows = client
            .query(
                "SELECT DISTINCT authority
                   FROM registry_internal.registry_proposal_review_submissions s
                  WHERE state='accepted' AND NOT EXISTS (
                    SELECT 1 FROM registry_internal.registry_proposal_review_results r
                     WHERE r.action_id=s.action_id AND r.proposal_id=s.proposal_id
                       AND r.submission_version=s.submission_version)
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
            let (outcome, outage_code) = match authority.token_provider.bearer_token().await {
                Ok(token) => (
                    poll_one_result(
                        client,
                        &authority.authority,
                        &authority.client,
                        &authority.profile,
                        &token,
                        authority.lease_seconds,
                        mutations,
                    )
                    .await,
                    None,
                ),
                Err(_) => (Err(MutationError::Unavailable), Some("token-unavailable")),
            };
            match outcome {
                Ok(true) => {
                    if unavailable_lookups > 0 {
                        crate::startup::OperationalEvent::ReviewResultLookupsUnavailable.emit();
                    }
                    return Ok(true);
                }
                Ok(false) => {}
                Err(_) => {
                    authority_unavailable = true;
                    unavailable_lookups += 1;
                    // Due rows back off without spending poll budget, so a
                    // healed outage resumes polling. Only a credential outage
                    // is authority-wide, so only it records operator attention
                    // on every due row; a failed lookup already recorded its
                    // code on the one row it claimed. A later answered lookup
                    // (pending or 404) or reconciled result clears the code.
                    // Another worker's live lookup keeps its own schedule.
                    client
                        .execute(
                            "UPDATE registry_internal.registry_proposal_review_submissions s
                                SET next_result_poll_at=transaction_timestamp()+interval '5 seconds',
                                    last_error_code=COALESCE($2,last_error_code),
                                    updated_at=transaction_timestamp()
                              WHERE s.authority=$1 AND s.state='accepted'
                                AND s.next_result_poll_at <= transaction_timestamp()
                                AND (s.lease_until IS NULL OR s.lease_until < transaction_timestamp())
                                AND NOT EXISTS (
                                    SELECT 1 FROM registry_internal.registry_proposal_review_results r
                                     WHERE (r.action_id,r.proposal_id,r.submission_version)
                                           = (s.action_id,s.proposal_id,s.submission_version))",
                            &[&authority.authority, &outage_code],
                        )
                        .await
                        .map_err(|_| MutationError::Unavailable)?;
                }
            }
        }
        if unavailable_lookups > 0 {
            crate::startup::OperationalEvent::ReviewResultLookupsUnavailable.emit();
        }
        if authority_unavailable {
            Err(MutationError::Unavailable)
        } else {
            Ok(false)
        }
    }
}

fn same_completion_binding(left: &ReviewAuthorityClient, right: &ReviewAuthorityClient) -> bool {
    let (Some(left_token), Some(left_recipient)) =
        (&left.completion_token, &left.completion_recipient)
    else {
        return false;
    };
    let (Some(right_token), Some(right_recipient)) =
        (&right.completion_token, &right.completion_recipient)
    else {
        return false;
    };
    left_token.len() == right_token.len()
        && left_token
            .as_bytes()
            .ct_eq(right_token.as_bytes())
            .unwrap_u8()
            == 1
        && left_recipient.len() == right_recipient.len()
        && left_recipient
            .as_bytes()
            .ct_eq(right_recipient.as_bytes())
            .unwrap_u8()
            == 1
}

fn terminal_submission_error(error: &ReviewClientError) -> bool {
    match error {
        ReviewClientError::Configuration { .. } | ReviewClientError::InvalidRequest { .. } => true,
        ReviewClientError::Problem { status, .. } => terminal_submission_problem_status(*status),
        _ => false,
    }
}

fn terminal_submission_problem_status(status: u16) -> bool {
    (400..=499).contains(&status) && status != 429
}

async fn erase_expired_review_completions(
    client: &impl GenericClient,
) -> Result<u64, MutationError> {
    client
        .execute(
            "DELETE FROM registry_internal.registry_proposal_review_completions
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
            "UPDATE registry_internal.registry_proposal_review_completions c
                SET state='correlated'
               FROM registry_internal.registry_proposal_review_submissions s
               JOIN registry_internal.registry_proposal_review_results r
                 USING (action_id,proposal_id,submission_version)
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
            "SELECT cursor FROM registry_internal.registry_proposal_review_feed_checkpoints
              WHERE authority=$1",
            &[&authority.authority],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .and_then(|row| row.get::<_, Option<Uuid>>(0));
    let page = match authority
        .client
        .requester_results(
            ReviewAuth::new(&token, &authority.profile),
            &ReviewResultsQuery {
                cursor,
                limit: Some(100),
            },
        )
        .await
    {
        Ok(page) => page.value,
        Err(ReviewClientError::Problem { status: 410, .. }) if cursor.is_some() => {
            client
                .execute(
                    "INSERT INTO registry_internal.registry_proposal_review_feed_checkpoints
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
        .or_else(|| page.items.last().map(|item| item.event_id))
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
            "INSERT INTO registry_internal.registry_proposal_review_feed_checkpoints
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
    mutations: Arc<crate::postgres::PostgresRecordMutationService>,
    last_success: Arc<crate::metrics::LastSuccess>,
}

impl ReviewWorker {
    pub fn new(
        pool: crate::postgres::RuntimePool,
        authorities: Option<Arc<ReviewAuthorityRegistry>>,
        mutations: Arc<crate::postgres::PostgresRecordMutationService>,
    ) -> Self {
        Self {
            pool,
            authorities,
            mutations,
            last_success: Arc::default(),
        }
    }

    /// The handle this worker notes each iteration without failure on.
    #[must_use]
    pub fn last_success(&self) -> Arc<crate::metrics::LastSuccess> {
        Arc::clone(&self.last_success)
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow() {
                return;
            }
            let mut failed = false;
            let worked = match self.pool.get().await {
                Ok(mut client) => {
                    let housekeeping_worked =
                        match erase_expired_review_completions(&**client).await {
                            Ok(erased) => erased > 0,
                            Err(_) => {
                                failed = true;
                                false
                            }
                        };
                    // Authority recovery keeps a fair turn on every iteration:
                    // a sustained application backlog must not starve
                    // submissions, cancellations, result feeds, and polls.
                    let authority_worked = if housekeeping_worked {
                        false
                    } else {
                        match &self.authorities {
                            Some(authorities) => {
                                match authorities.run_one(&mut client, &self.mutations).await {
                                    Ok(worked) => worked,
                                    Err(_) => {
                                        failed = true;
                                        false
                                    }
                                }
                            }
                            None => false,
                        }
                    };
                    housekeeping_worked || authority_worked
                }
                Err(_) => {
                    failed = true;
                    false
                }
            };
            // Drop the review/housekeeping checkout before automatic apply
            // can acquire fresh dependency observations or its own transaction.
            let application_worked = match self.mutations.run_automatic_proposal_once().await {
                Ok(worked) => worked,
                Err(_) => {
                    failed = true;
                    false
                }
            };
            let worked = worked || application_worked;
            if failed {
                crate::startup::OperationalEvent::ReviewWorkerIterationFailed.emit();
            } else {
                self.last_success.record();
            }
            if worked {
                continue;
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                }
                () = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
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
                ReviewAuth::new(
                    &self
                        .token_provider
                        .bearer_token()
                        .await
                        .map_err(|_| MutationError::Unavailable)?,
                    &self.profile,
                ),
                accepted,
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
        {
            ReviewResultResponse::Available(complete) => complete.value,
            ReviewResultResponse::Pending { .. }
            | ReviewResultResponse::ConcealedOrUnknown { .. }
            | ReviewResultResponse::Expired { .. } => {
                return Err(MutationError::PreconditionFailed);
            }
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

/// Read the exact accepted correlation without treating worker state as authority.
/// In particular, cancellation keeps the original accepted binding while it settles.
pub(crate) async fn load_status_binding(
    client: &impl GenericClient,
    registry: &CompiledRegistry,
    action_id: &str,
    proposal_id: Uuid,
    frozen: &ProposalSnapshot,
) -> Result<Option<ReviewRequestAccepted>, MutationError> {
    let CompiledProposalReview::Required {
        authority: expected_authority,
        source,
        policy,
    } = frozen.review_requirement()
    else {
        return Err(MutationError::PreconditionFailed);
    };
    let row = client
        .query_opt(
            "SELECT authority,proposal_digest,expected_policy,create_request,
            producer_id,expected_submission_digest,accepted_binding
            FROM registry_internal.registry_proposal_review_submissions
            WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
            &[&action_id, &proposal_id, &i64::from(frozen.version().get())],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::PreconditionFailed)?;
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(row.get(3)).map_err(|_| MutationError::PreconditionFailed)?;
    create
        .check()
        .map_err(|_| MutationError::PreconditionFailed)?;
    let context_reference = format!(
        "breg:{}:{}:{}:{}",
        registry.registry_id(),
        action_id,
        proposal_id,
        frozen.version().get()
    );
    let stored_digest = SubmissionDigest::parse(&row.get::<_, String>(5))
        .map_err(|_| MutationError::PreconditionFailed)?;
    let accepted = row
        .get::<_, Option<Value>>(6)
        .map(serde_json::from_value::<registry_review_client::ReviewRequestAccepted>)
        .transpose()
        .map_err(|_| MutationError::PreconditionFailed)?;
    if row.get::<_, String>(0) != *expected_authority
        || row.get::<_, String>(1) != frozen.effect_digest().as_str()
        || row.get::<_, Value>(2)
            != serde_json::to_value(policy).map_err(|_| MutationError::Unavailable)?
        || create.policy != *policy
        || create.subject.source != *source
        || create.subject.subject_type != "proposal"
        || create.subject.id != proposal_id.to_string()
        || create.subject.version != frozen.version().get().to_string()
        || create.subject.digest.as_str() != frozen.effect_digest().as_str()
        || !matches!(&create.context,registry_review_client::ReviewContext::CurrentSource { binding }
                if binding.reference == context_reference)
        || accepted.as_ref().is_some_and(|accepted| {
            accepted.request_id.is_nil()
                || accepted.subject.check().is_err()
                || accepted.policy.check().is_err()
                || accepted.subject != create.subject
                || !policy.matches(&accepted.policy)
        })
    {
        return Err(MutationError::PreconditionFailed);
    }
    stored_submission_digest_compatibility(
        &row.get::<_, String>(4),
        registry.registry_id(),
        &create,
        &stored_digest,
        accepted.as_ref(),
    )?;
    Ok(accepted)
}

/// Load the accepted binding only while the source still owns a current,
/// non-withdrawn review acceptance. Status reads intentionally retain their
/// historical correlation through cancellation; task context must not.
pub(crate) async fn load_task_context_binding(
    client: &impl GenericClient,
    registry: &CompiledRegistry,
    action_id: &str,
    proposal_id: Uuid,
    frozen: &ProposalSnapshot,
) -> Result<ReviewRequestAccepted, MutationError> {
    let accepted = load_status_binding(client, registry, action_id, proposal_id, frozen)
        .await?
        .ok_or(MutationError::PreconditionFailed)?;
    let row = client
        .query_opt(
            "SELECT state,withdrawn FROM registry_internal.registry_proposal_review_submissions
            WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3 FOR SHARE",
            &[&action_id, &proposal_id, &i64::from(frozen.version().get())],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::PreconditionFailed)?;
    if row.get::<_, String>(0) != "accepted" || row.get::<_, bool>(1) {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(accepted)
}

pub(crate) async fn load_accepted_binding(
    client: &impl GenericClient,
    action_id: &str,
    proposal_id: Uuid,
    submission_version: i64,
    proposal_digest: &str,
) -> Result<(String, ReviewRequestAccepted), MutationError> {
    let row = client
        .query_opt(
            "SELECT authority,accepted_binding
               FROM registry_internal.registry_proposal_review_submissions
              WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                AND proposal_digest=$4 AND state='accepted'",
            &[
                &action_id,
                &proposal_id,
                &submission_version,
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
        "registry_proposal_review_submissions",
        &["INSERT", "SELECT", "UPDATE"],
    ),
    (
        "registry_proposal_review_completions",
        &["INSERT", "SELECT", "UPDATE", "DELETE"],
    ),
    (
        "registry_proposal_review_results",
        &["INSERT", "SELECT", "UPDATE"],
    ),
    (
        "registry_proposal_review_feed_checkpoints",
        &["INSERT", "SELECT", "UPDATE"],
    ),
    (
        "registry_proposal_application_jobs",
        &["INSERT", "SELECT", "UPDATE"],
    ),
];

pub(crate) async fn install(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), MutationError> {
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_review_submissions (
                 action_id text NOT NULL CHECK (action_id <> ''),
                 proposal_id uuid NOT NULL,
                 submission_version bigint NOT NULL CHECK (submission_version BETWEEN 1 AND 4294967295),
                 proposal_digest text NOT NULL CHECK (proposal_digest ~ '^sha256:[0-9a-f]{64}$'),
                 job_id uuid NOT NULL UNIQUE,
                 authority text NOT NULL CHECK (authority <> '' AND octet_length(authority) <= 128),
                 producer_id text NOT NULL CHECK (producer_id <> '' AND octet_length(producer_id) <= 128),
                 policy_id text NOT NULL CHECK (policy_id <> '' AND octet_length(policy_id) <= 128),
                 expected_policy jsonb NOT NULL CHECK (jsonb_typeof(expected_policy) = 'object'),
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
                 PRIMARY KEY (action_id, proposal_id, submission_version),
                 FOREIGN KEY (action_id, proposal_id, submission_version)
                     REFERENCES registry_internal.registry_proposal_submissions,
                 CHECK ((on_approved_mode = 'manual' AND executor IS NULL)
                     OR (on_approved_mode = 'automatic' AND executor IS NOT NULL)),
                 CHECK ((state IN ('accepted','cancelling') AND accepted_binding IS NOT NULL)
                     OR state NOT IN ('accepted','cancelling'))
             );
             CREATE INDEX IF NOT EXISTS registry_proposal_review_submission_jobs
                 ON registry_internal.registry_proposal_review_submissions
                 (next_attempt_at, created_at)
                 WHERE state IN ('pending','submitting','uncertain');
             CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_review_completions (
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
             CREATE INDEX IF NOT EXISTS registry_proposal_review_completion_reconcile
                 ON registry_internal.registry_proposal_review_completions
                 (state, received_at) WHERE state IN ('pending','unmatched');
             CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_review_results (
                 action_id text NOT NULL,
                 proposal_id uuid NOT NULL,
                 submission_version bigint NOT NULL CHECK (submission_version BETWEEN 1 AND 4294967295),
                 authority text NOT NULL CHECK (authority <> '' AND octet_length(authority) <= 128),
                 result_id uuid NOT NULL,
                 result jsonb NOT NULL,
                 status text NOT NULL CHECK (status IN
                     ('approved','rejected','changes-requested','answered','cancelled','superseded')),
                 completed_at timestamptz NOT NULL,
                 available_until timestamptz NOT NULL,
                 verified_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (action_id, proposal_id, submission_version),
                 UNIQUE (authority, result_id),
                 FOREIGN KEY (action_id, proposal_id, submission_version)
                     REFERENCES registry_internal.registry_proposal_review_submissions,
                 CHECK (available_until > completed_at),
                 CONSTRAINT registry_proposal_review_results_result_size CHECK (
                     jsonb_typeof(result)='object'
                     AND octet_length(result::text)<=1048576
                 )
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_review_feed_checkpoints (
                 authority text PRIMARY KEY CHECK (authority <> '' AND octet_length(authority) <= 128),
                 cursor uuid,
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_application_jobs (
                 action_id text NOT NULL,
                 proposal_id uuid NOT NULL,
                 submission_version bigint NOT NULL CHECK (submission_version BETWEEN 1 AND 4294967295),
                 job_id uuid NOT NULL UNIQUE,
                 proposal_digest text NOT NULL CHECK (proposal_digest ~ '^sha256:[0-9a-f]{64}$'),
                 result_id uuid,
                 executor text NOT NULL CHECK (executor <> '' AND octet_length(executor) <= 128),
                 maximum_attempts integer NOT NULL CHECK (maximum_attempts BETWEEN 1 AND 1000),
                 system_grant_revision text NOT NULL CHECK (system_grant_revision ~ '^sha256:[0-9a-f]{64}$'),
                 state text NOT NULL CHECK (state IN ('queued','applying','applied','blocked','cancelled')),
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
                 receipt_recovered boolean NOT NULL DEFAULT false,
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (action_id, proposal_id, submission_version),
                 FOREIGN KEY (action_id, proposal_id, submission_version)
                     REFERENCES registry_internal.registry_proposal_submissions,
                 CHECK ((state = 'applied' AND application_id IS NOT NULL)
                     OR (state <> 'applied' AND application_id IS NULL)),
                 CONSTRAINT registry_proposal_application_jobs_receipt_recovered_check
                     CHECK (NOT receipt_recovered OR state = 'applied'),
                 CONSTRAINT registry_proposal_application_jobs_action_binding_check
                     CHECK ((action_href IS NULL) = (action_if_match IS NULL))
             );",
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let revoke_grantees = crate::postgres::RuntimeRevoke::detect(client, runtime_role)
        .await
        .map_err(|_| MutationError::Unavailable)?
        .with_public();
    for (table, privileges) in REVIEW_TABLES {
        let role = runtime_role.as_str();
        client
            .batch_execute(&format!(
                "REVOKE ALL ON registry_internal.{table} FROM {revoke_grantees};
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
    action_id: &str,
    proposal_id: Uuid,
    proposal: &ProposalSnapshot,
    requester_reference: &str,
    initiator: Option<&registry_review_client::HumanIdentity>,
    authorities: &ReviewAuthorityRegistry,
) -> Result<(), MutationError> {
    let CompiledProposalReview::Required {
        authority,
        source,
        policy,
    } = proposal.review_requirement()
    else {
        return Ok(());
    };
    let registry_id = registry.registry_id();
    let (producer_id, recovery_days) = authorities
        .submission_binding(authority)
        .ok_or(MutationError::Unavailable)?;
    let source_reference = format!(
        "breg:{registry_id}:{action_id}:{proposal_id}:{}",
        proposal.version().get()
    );
    let create = ReviewCreateRequest {
        policy: policy.clone(),
        subject: SubjectBinding {
            source: source.clone(),
            subject_type: "proposal".to_owned(),
            id: proposal_id.to_string(),
            version: proposal.version().get().to_string(),
            digest: registry_review_client::ContentDigest::parse(proposal.effect_digest().as_str())
                .map_err(|_| MutationError::Unavailable)?,
        },
        requester_reference: requester_reference.to_owned(),
        initiator: initiator.cloned(),
        context: registry_review_client::ReviewContext::CurrentSource {
            binding: SourceContextBinding {
                reference: source_reference,
            },
        },
        result_constraints: None,
    };
    let expected_digest = submission_digest(producer_id, source, &create)
        .map_err(|_| MutationError::InvalidRequest)?;
    let job_id = Uuid::new_v4();
    let idempotency_key = format!("breg-review-{job_id}");
    let create_value = serde_json::to_value(&create).map_err(|_| MutationError::Unavailable)?;
    let mode = if proposal.application_policy().is_automatic() {
        "automatic"
    } else {
        "manual"
    };
    let executor = proposal
        .application_policy()
        .is_automatic()
        .then_some("builtin");
    let inserted = transaction
        .execute(
            "INSERT INTO registry_internal.registry_proposal_review_submissions
             (action_id, proposal_id, submission_version, proposal_digest,
              job_id, authority, producer_id, policy_id, idempotency_key, create_request,
              expected_submission_digest, on_approved_mode, executor, state,recovery_deadline,expected_policy)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending',
                     transaction_timestamp()+($14::bigint * interval '1 day'),$15)
             ON CONFLICT DO NOTHING",
            &[
                &action_id,
                &proposal_id,
                &i64::from(proposal.version().get()),
                &proposal.effect_digest().as_str(),
                &job_id,
                &authority,
                &producer_id,
                &policy.id,
                &idempotency_key,
                &create_value,
                &expected_digest.as_str(),
                &mode,
                &executor,
                &i64::from(recovery_days),
                &serde_json::to_value(policy).map_err(|_|MutationError::Unavailable)?,
            ],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    if inserted != 1 {
        let row = transaction
            .query_one(
                "SELECT proposal_digest, authority, producer_id, policy_id, create_request,
                        expected_submission_digest, on_approved_mode, executor, expected_policy
                   FROM registry_internal.registry_proposal_review_submissions
                  WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
                &[
                    &action_id,
                    &proposal_id,
                    &i64::from(proposal.version().get()),
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let exact = row.get::<_, String>(0) == proposal.effect_digest().as_str()
            && row.get::<_, String>(1) == *authority
            && row.get::<_, String>(2) == producer_id
            && row.get::<_, String>(3) == policy.id
            && row.get::<_, Value>(4) == create_value
            && row.get::<_, String>(5) == expected_digest.as_str()
            && row.get::<_, String>(6) == mode
            && row.get::<_, Option<String>>(7).as_deref() == executor
            && row.get::<_, Value>(8)
                == serde_json::to_value(policy).map_err(|_| MutationError::Unavailable)?;
        if !exact {
            return Err(MutationError::IdempotencyConflict);
        }
    }
    Ok(())
}

const CLOSE_APPLICATION_JOBS_SQL: &str =
    "UPDATE registry_internal.registry_proposal_application_jobs j
    SET state='cancelled',claim_token=NULL,updated_at=transaction_timestamp()
    WHERE j.state IN ('queued','applying','blocked')";

/// Close every unapplied application job of a Proposal being cancelled, or
/// whose submitted version is being revised or rebased, in that lifecycle
/// transaction. A closed job is never claimed or recovered again.
pub(crate) async fn close_application_jobs(
    transaction: &impl GenericClient,
    action_id: &str,
    proposal_id: Uuid,
) -> Result<(), MutationError> {
    transaction
        .execute(
            &format!("{CLOSE_APPLICATION_JOBS_SQL} AND j.action_id=$1 AND j.proposal_id=$2"),
            &[&action_id, &proposal_id],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    Ok(())
}

/// Queue the engine's own authority. This row contains no author credential.
pub(crate) async fn enqueue_automatic_application(
    transaction: &Transaction<'_>,
    action_id: &str,
    proposal_id: Uuid,
    proposal: &ProposalSnapshot,
) -> Result<(), MutationError> {
    if !proposal.application_policy().is_automatic() {
        return Err(MutationError::InvalidRequest);
    }
    let grant = proposal
        .system_grant_revision()
        .ok_or(MutationError::PreconditionFailed)?;
    let maximum = i32::from(proposal.application_policy().maximum_attempts());
    let version = i64::from(proposal.version().get());
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_proposal_application_jobs
        (action_id,proposal_id,submission_version,job_id,proposal_digest,result_id,executor,
         maximum_attempts,system_grant_revision,state)
        SELECT $1,$2,$3,$4,$5,r.result_id,'builtin',$6,$7,'queued'
        FROM (SELECT 1) anchor LEFT JOIN registry_internal.registry_proposal_review_results r
          ON r.action_id=$1 AND r.proposal_id=$2 AND r.submission_version=$3
        ON CONFLICT DO NOTHING",
            &[
                &action_id,
                &proposal_id,
                &version,
                &Uuid::new_v4(),
                &proposal.effect_digest().as_str(),
                &maximum,
                &grant,
            ],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let row = transaction
        .query_one(
            "SELECT proposal_digest,maximum_attempts,system_grant_revision
        FROM registry_internal.registry_proposal_application_jobs
        WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
            &[&action_id, &proposal_id, &version],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    if row.get::<_, String>(0) != proposal.effect_digest().as_str()
        || row.get::<_, i32>(1) != maximum
        || row.get::<_, String>(2) != grant
    {
        return Err(MutationError::IdempotencyConflict);
    }
    Ok(())
}

/// Retry retained work without changing its immutable plan, job key, or budget.
pub(crate) async fn submission_work_is_retryable(
    client: &impl GenericClient,
    action_id: &str,
    proposal_id: Uuid,
    version: i64,
) -> Result<bool, MutationError> {
    client.query_one("SELECT EXISTS (
        SELECT 1 FROM registry_internal.registry_proposal_application_jobs
        WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3 AND state='blocked'
          AND attempt_count<maximum_attempts AND last_error_code IN
            ('dependency-outage','source-unavailable','executor-unavailable','lease-expired')
        UNION ALL SELECT 1 FROM registry_internal.registry_proposal_review_submissions s
        WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3 AND NOT withdrawn
          AND state IN ('pending','uncertain','accepted') AND lease_until IS NULL
          AND NOT EXISTS (SELECT 1 FROM registry_internal.registry_proposal_review_results r
            WHERE (r.action_id,r.proposal_id,r.submission_version)=(s.action_id,s.proposal_id,s.submission_version)))",
        &[&action_id,&proposal_id,&version]).await.map(|row|row.get(0)).map_err(|_|MutationError::Unavailable)
}

pub(crate) async fn retry_submission_work(
    transaction: &Transaction<'_>,
    action_id: &str,
    proposal_id: Uuid,
    proposal: &ProposalSnapshot,
) -> Result<(), MutationError> {
    let version = i64::from(proposal.version().get());
    let application=transaction.execute("UPDATE registry_internal.registry_proposal_application_jobs
        SET state='queued',claim_token=NULL,last_error_code=NULL,next_attempt_at=transaction_timestamp(),
            updated_at=transaction_timestamp()
        WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3 AND state='blocked'
          AND attempt_count<maximum_attempts AND last_error_code IN
            ('dependency-outage','source-unavailable','executor-unavailable','lease-expired')",
        &[&action_id,&proposal_id,&version]).await.map_err(|_|MutationError::Unavailable)?;
    let review=transaction.execute("UPDATE registry_internal.registry_proposal_review_submissions s
        SET next_attempt_at=transaction_timestamp(),next_result_poll_at=transaction_timestamp(),
            last_error_code=NULL,updated_at=transaction_timestamp()
        WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3 AND NOT withdrawn
          AND state IN ('pending','uncertain','accepted') AND lease_until IS NULL
          AND NOT EXISTS (SELECT 1 FROM registry_internal.registry_proposal_review_results r
            WHERE (r.action_id,r.proposal_id,r.submission_version)=(s.action_id,s.proposal_id,s.submission_version))",
        &[&action_id,&proposal_id,&version]).await.map_err(|_|MutationError::Unavailable)?;
    if application + review == 0 {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}

// Failed rounds still need withdrawal when the source ends them. A retained
// acceptance can be cancelled; an exhausted delivery without one stays failed.
// Do not reopen an already withdrawn failed cancellation on later activations.
const SCHEDULE_CANCELLATION_SQL: &str =
    "UPDATE registry_internal.registry_proposal_review_submissions s
    SET withdrawn=true,
        attempt_count=CASE
            WHEN s.accepted_binding IS NOT NULL AND s.state<>'cancelling' THEN 0
            ELSE s.attempt_count
        END,
        state=CASE
            WHEN s.accepted_binding IS NOT NULL THEN 'cancelling'
            WHEN s.state='pending' AND s.attempt_count=0 THEN 'cancelled'
            WHEN s.state IN ('submitting','uncertain') THEN 'uncertain'
            ELSE s.state
        END,
        lease_until=NULL,next_attempt_at=transaction_timestamp(),
        updated_at=transaction_timestamp()
    WHERE (s.state NOT IN ('cancelled','failed') OR (s.state='failed' AND NOT s.withdrawn))";

pub(crate) async fn schedule_cancellation(
    transaction: &impl GenericClient,
    action_id: &str,
    proposal_id: Uuid,
    submission_version: i64,
) -> Result<(), MutationError> {
    transaction
        .execute(
            &format!(
                "{SCHEDULE_CANCELLATION_SQL}
                AND s.action_id=$1 AND s.proposal_id=$2 AND s.submission_version=$3"
            ),
            &[&action_id, &proposal_id, &submission_version],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    Ok(())
}

/// Withdraw work for the Proposals an activation classified as incompatible.
/// The caller supplies that classification independently of the durable
/// blocked reason, whose application refusal remains dominant until Rebase.
/// Jobs close across versions; only the current submitted Review round is
/// withdrawn. Ordinary lifecycle calls share the same state transitions above.
pub(crate) async fn withdraw_incompatible_proposals(
    transaction: &impl GenericClient,
    action_id: &str,
    proposal_ids: &[Uuid],
) -> Result<(), MutationError> {
    if proposal_ids.is_empty() {
        return Ok(());
    }
    let proposal_ids = proposal_ids.to_vec();
    transaction
        .execute(
            &format!(
                "{CLOSE_APPLICATION_JOBS_SQL} AND EXISTS (
            SELECT 1 FROM registry_internal.registry_proposal_state p
             WHERE p.action_id=$1 AND p.action_id=j.action_id AND p.proposal_id=j.proposal_id
               AND p.state='submitted' AND p.proposal_id=ANY($2::uuid[]))"
            ),
            &[&action_id, &proposal_ids],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    transaction
        .execute(
            &format!(
                "{SCHEDULE_CANCELLATION_SQL} AND EXISTS (
            SELECT 1 FROM registry_internal.registry_proposal_state p
             WHERE p.action_id=$1 AND p.action_id=s.action_id AND p.proposal_id=s.proposal_id
               AND p.submission_version=s.submission_version
               AND p.state='submitted' AND p.proposal_id=ANY($2::uuid[]))"
            ),
            &[&action_id, &proposal_ids],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ClaimedReviewSubmission {
    pub attempt_count: i32,
    pub legacy_digest_repairable: bool,
    pub producer_id: String,
    pub action_id: String,
    pub proposal_id: Uuid,
    pub submission_version: i64,
    pub proposal_digest: String,
    pub authority: String,
    pub idempotency_key: String,
    pub request: ReviewCreateRequest,
    pub expected_submission_digest: registry_review_client::SubmissionDigest,
    pub lease_until: DateTime<Utc>,
    pub expected_policy: registry_review_protocol::PolicySelection,
    pub accepted_binding: Option<ReviewRequestAccepted>,
}

pub async fn claim_submission(
    client: &impl GenericClient,
    authority: &str,
    lease_seconds: i64,
) -> Result<Option<ClaimedReviewSubmission>, MutationError> {
    let row = client
        .query_opt(
            "WITH candidate AS (
                 SELECT s.action_id, s.proposal_id, s.submission_version,
                        s.state='pending' AND s.attempt_count=0
                            AND s.accepted_binding IS NULL AND s.updated_at=s.created_at
                            AS legacy_digest_repairable
                   FROM registry_internal.registry_proposal_review_submissions s
                  WHERE next_attempt_at <= transaction_timestamp()
                    AND authority=$2
                    AND recovery_deadline > transaction_timestamp()
                    AND (withdrawn OR EXISTS (
                        SELECT 1 FROM registry_internal.registry_proposal_state p
                         WHERE (p.action_id,p.proposal_id)=(s.action_id,s.proposal_id)
                           AND p.state='submitted' AND p.submission_version=s.submission_version
                           AND p.blocked_reason IS NULL
                    ))
                    AND (state IN ('pending','uncertain')
                         OR (state='submitting' AND lease_until < transaction_timestamp()))
                    AND (
                        withdrawn OR NOT EXISTS (
                            SELECT 1
                             FROM registry_internal.registry_proposal_review_submissions older
                             WHERE older.action_id=s.action_id
                               AND older.proposal_id=s.proposal_id
                               AND older.submission_version<s.submission_version
                               AND older.withdrawn
                               AND older.state IN ('pending','submitting','uncertain','cancelling')
                        )
                    )
                  ORDER BY next_attempt_at, created_at
                  FOR UPDATE SKIP LOCKED LIMIT 1
             )
             UPDATE registry_internal.registry_proposal_review_submissions s
                SET state='submitting', attempt_count=LEAST(attempt_count+1,1000),
                    lease_until=transaction_timestamp()+($1::bigint * interval '1 second'),
                    updated_at=transaction_timestamp()
               FROM candidate c
              WHERE s.action_id=c.action_id
                AND s.proposal_id=c.proposal_id AND s.submission_version=c.submission_version
             RETURNING s.action_id,s.proposal_id,s.submission_version,s.authority,
                       s.idempotency_key,s.create_request,s.expected_submission_digest,
                       s.lease_until,s.expected_policy,s.accepted_binding,s.producer_id,s.attempt_count,
                       s.proposal_digest,c.legacy_digest_repairable",
            &[&lease_seconds, &authority],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    row.map(|row| {
        Ok(ClaimedReviewSubmission {
            attempt_count: row.get(11),
            legacy_digest_repairable: row.get(13),
            producer_id: row.get(10),
            action_id: row.get(0),
            proposal_id: row.get(1),
            submission_version: row.get(2),
            proposal_digest: row.get(12),
            authority: row.get(3),
            idempotency_key: row.get(4),
            request: serde_json::from_value(row.get(5)).map_err(|_| MutationError::Unavailable)?,
            expected_submission_digest: registry_review_client::SubmissionDigest::parse(
                &row.get::<_, String>(6),
            )
            .map_err(|_| MutationError::Unavailable)?,
            lease_until: row.get(7),
            expected_policy: serde_json::from_value(row.get(8))
                .map_err(|_| MutationError::Unavailable)?,
            accepted_binding: row
                .get::<_, Option<serde_json::Value>>(9)
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| MutationError::Unavailable)?,
        })
    })
    .transpose()
}

pub async fn run_one_submission(
    client: &impl GenericClient,
    authority: &str,
    review_client: &ReviewClient,
    profile: &str,
    token: &BearerToken,
    lease_seconds: i64,
) -> Result<bool, MutationError> {
    let Some(mut job) = claim_submission(client, authority, lease_seconds).await? else {
        return Ok(false);
    };
    job.request
        .check()
        .map_err(|_| MutationError::PreconditionFailed)?;
    let registry_review_client::ReviewContext::CurrentSource { binding } = &job.request.context
    else {
        return Err(MutationError::PreconditionFailed);
    };
    let suffix = format!(
        ":{}:{}:{}",
        job.action_id, job.proposal_id, job.submission_version
    );
    let registry_id = binding
        .reference
        .strip_prefix("breg:")
        .and_then(|reference| reference.strip_suffix(&suffix))
        .filter(|id| !id.is_empty())
        .ok_or(MutationError::PreconditionFailed)?;
    if job.authority != authority
        || job.request.policy != job.expected_policy
        || job.request.subject.subject_type != "proposal"
        || job.request.subject.id != job.proposal_id.to_string()
        || job.request.subject.version != job.submission_version.to_string()
        || job.request.subject.digest.as_str() != job.proposal_digest
        || job.accepted_binding.as_ref().is_some_and(|accepted| {
            accepted.request_id.is_nil()
                || accepted.subject.check().is_err()
                || accepted.policy.check().is_err()
                || accepted.subject != job.request.subject
                || !job.expected_policy.matches(&accepted.policy)
        })
    {
        return Err(MutationError::PreconditionFailed);
    }
    let (compatibility, current_digest) = stored_submission_digest_compatibility(
        &job.producer_id,
        registry_id,
        &job.request,
        &job.expected_submission_digest,
        job.accepted_binding.as_ref(),
    )?;
    if compatibility == StoredSubmissionDigestCompatibility::LegacyRegistryId
        && job.accepted_binding.is_none()
        && job.attempt_count == 1
        && job.legacy_digest_repairable
    {
        // The claim increments attempt_count before returning the job. One is
        // necessary but not sufficient because operator resubmission resets the
        // delivery budget; the candidate flag also requires the untouched
        // initial row. Preserve every possibly delivered digest because its
        // acceptance may exist remotely without a local accepted binding.
        let updated = client
            .execute(
                "UPDATE registry_internal.registry_proposal_review_submissions
                SET expected_submission_digest=$7,updated_at=transaction_timestamp()
              WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                AND state='submitting' AND lease_until=$4
                AND expected_submission_digest=$5 AND producer_id=$6
                AND accepted_binding IS NULL",
                &[
                    &job.action_id,
                    &job.proposal_id,
                    &job.submission_version,
                    &job.lease_until,
                    &job.expected_submission_digest.as_str(),
                    &job.producer_id,
                    &current_digest.as_str(),
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        if updated != 1 {
            return Err(MutationError::PreconditionFailed);
        }
        job.expected_submission_digest = current_digest;
    }
    let proposal_reference =
        registry_review_client::ContentDigest::for_bytes(job.proposal_id.to_string().as_bytes());
    if job.attempt_count == 1 {
        tracing::info!(
            authority,
            proposal_reference = %proposal_reference,
            attempt = job.attempt_count,
            "BReg review handoff started"
        );
    }
    let response = review_client
        .create_or_recover_request_for_producer(
            ReviewAuth::new(token, profile),
            &job.idempotency_key,
            &job.request,
            &job.expected_submission_digest,
            &job.producer_id,
        )
        .await;
    match response {
        Ok(complete) => {
            let refusal = if job
                .accepted_binding
                .as_ref()
                .is_some_and(|accepted| accepted != &complete.value)
            {
                Some("review-acceptance-changed")
            } else if !job.expected_policy.matches(&complete.value.policy) {
                Some("review-policy-changed")
            } else {
                None
            };
            if let Some(code) = refusal {
                client
                    .execute(
                        "UPDATE registry_internal.registry_proposal_review_submissions
                        SET state='failed',lease_until=NULL,last_error_code=$5
                      WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                        AND state='submitting' AND lease_until=$4",
                        &[
                            &job.action_id,
                            &job.proposal_id,
                            &job.submission_version,
                            &job.lease_until,
                            &code,
                        ],
                    )
                    .await
                    .map_err(|_| MutationError::Unavailable)?;
                return Ok(true);
            }
            let accepted =
                serde_json::to_value(&complete.value).map_err(|_| MutationError::Unavailable)?;
            let updated = client
                .execute(
                    "UPDATE registry_internal.registry_proposal_review_submissions
                        SET state=CASE WHEN withdrawn THEN 'cancelling' ELSE 'accepted' END,
                            accepted_binding=$4,lease_until=NULL,
                            attempt_count=CASE WHEN withdrawn THEN 0 ELSE attempt_count END,
                            last_error_code=NULL,updated_at=transaction_timestamp()
                      WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                        AND state='submitting' AND expected_submission_digest=$5
                        AND lease_until=$6",
                    &[
                        &job.action_id,
                        &job.proposal_id,
                        &job.submission_version,
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
            tracing::info!(
                authority,
                proposal_reference = %proposal_reference,
                attempt = job.attempt_count,
                answer = "accepted",
                "BReg review handoff settled"
            );
        }
        Err(ReviewClientError::ProducerIdentityMismatch {
            expected, actual, ..
        }) => {
            let updated = client.execute(
                "UPDATE registry_internal.registry_proposal_review_submissions
                    SET state='failed',lease_until=NULL,last_error_code='producer-identity-mismatch',
                        updated_at=transaction_timestamp()
                  WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                    AND state='submitting' AND lease_until=$4",
                &[&job.action_id, &job.proposal_id, &job.submission_version, &job.lease_until],
            ).await.map_err(|_| MutationError::Unavailable)?;
            if updated == 1 {
                tracing::warn!(
                    configured_producer_id = %expected,
                    provider_producer_id = %actual,
                    "BReg review handoff recorded producer-identity-mismatch; align reviewAuthorities producerId with the provider's trustedProducers identity before new submissions; the provider may retain the mismatched review"
                );
            }
        }
        Err(error) if terminal_submission_error(&error) => {
            let updated = client
                .execute(
                    "UPDATE registry_internal.registry_proposal_review_submissions
                        SET state='failed',lease_until=NULL,last_error_code='remote-refused',
                            updated_at=transaction_timestamp()
                      WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                        AND state='submitting' AND lease_until=$4",
                    &[
                        &job.action_id,
                        &job.proposal_id,
                        &job.submission_version,
                        &job.lease_until,
                    ],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
            if updated == 1 {
                let (status, problem_code) = match &error {
                    ReviewClientError::Problem { status, problem } => {
                        (Some(*status), Some(problem.code.as_str()))
                    }
                    _ => (None, None),
                };
                tracing::warn!(
                    authority,
                    status,
                    problem_code,
                    "BReg review handoff was refused by the review authority and recorded remote-refused; \
                     check the review producer configuration and its grant at the authority; the Proposal reads review-ended and its author revises it"
                );
            }
        }
        Err(_) => {
            let updated = client
                .execute(
                    "UPDATE registry_internal.registry_proposal_review_submissions
                        SET state='uncertain',lease_until=NULL,last_error_code='remote-uncertain',
                            next_attempt_at=transaction_timestamp()+interval '5 seconds',
                            updated_at=transaction_timestamp()
                      WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                        AND state='submitting' AND lease_until=$4",
                    &[
                        &job.action_id,
                        &job.proposal_id,
                        &job.submission_version,
                        &job.lease_until,
                    ],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
            if updated == 1 {
                tracing::warn!(
                    authority,
                    proposal_reference = %proposal_reference,
                    attempt = job.attempt_count,
                    answer = "remote-uncertain",
                    "BReg review handoff recorded remote-uncertain; retry the same submission to recover its acceptance"
                );
            }
        }
    }
    Ok(true)
}

pub async fn run_one_cancellation(
    client: &mut tokio_postgres::Client,
    authority_id: &str,
    review_client: &ReviewClient,
    profile: &str,
    token: &BearerToken,
    lease_seconds: i64,
    mutations: &crate::postgres::PostgresRecordMutationService,
) -> Result<bool, MutationError> {
    let Some(row) = client
        .query_opt(
            "UPDATE registry_internal.registry_proposal_review_submissions
                SET lease_until=transaction_timestamp()+($1::bigint * interval '1 second'),
                    attempt_count=LEAST(attempt_count+1,1000),updated_at=transaction_timestamp()
              WHERE (action_id,proposal_id,submission_version)=(
                    SELECT action_id,proposal_id,submission_version
                      FROM registry_internal.registry_proposal_review_submissions
                     WHERE state='cancelling' AND authority=$2
                       AND next_attempt_at <= transaction_timestamp()
                       AND (lease_until IS NULL OR lease_until < transaction_timestamp())
                     ORDER BY next_attempt_at,created_at FOR UPDATE SKIP LOCKED LIMIT 1)
              RETURNING action_id,proposal_id,submission_version,authority,
                        idempotency_key,accepted_binding,lease_until",
            &[&lease_seconds, &authority_id],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
    else {
        return Ok(false);
    };
    let entity_id: String = row.get(0);
    let proposal_id: Uuid = row.get(1);
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
        .cancel_request(
            ReviewAuth::new(token, profile),
            &accepted,
            &key,
            &cancellation,
        )
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
            reconcile_result(&transaction, &authority, &accepted, &result, mutations).await?;
            let updated = transaction
                .execute(
                    "UPDATE registry_internal.registry_proposal_review_submissions
                        SET state='cancelled',lease_until=NULL,last_error_code=NULL,
                            updated_at=transaction_timestamp()
                      WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                        AND state='cancelling' AND lease_until=$4",
                    &[&entity_id, &proposal_id, &version, &lease_until],
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
            transaction
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
        }
        Err(_) => {
            client
                .execute(
                    "UPDATE registry_internal.registry_proposal_review_submissions
                        SET lease_until=NULL,last_error_code='cancellation-uncertain',
                            next_attempt_at=transaction_timestamp()+interval '5 seconds',
                            updated_at=transaction_timestamp()
                      WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                        AND state='cancelling' AND lease_until=$4",
                    &[&entity_id, &proposal_id, &version, &lease_until],
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
            "SELECT 1 FROM registry_internal.registry_proposal_review_submissions
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
                   FROM registry_internal.registry_proposal_review_results r
                   JOIN registry_internal.registry_proposal_review_submissions s
                     USING (action_id,proposal_id,submission_version)
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
            "INSERT INTO registry_internal.registry_proposal_review_completions
             (authority,event_id,review_request_id,result_id,completed_at,state,expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (authority,event_id) DO UPDATE
                 SET state=registry_proposal_review_completions.state
               WHERE registry_proposal_review_completions.review_request_id=EXCLUDED.review_request_id
                 AND registry_proposal_review_completions.result_id=EXCLUDED.result_id
                 AND registry_proposal_review_completions.completed_at=EXCLUDED.completed_at",
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
    if state == "pending" {
        // The authority announced a result BReg does not hold yet, so the
        // review's lookup is due now instead of after its backoff.
        transaction
            .execute(
                "UPDATE registry_internal.registry_proposal_review_submissions
                    SET next_result_poll_at=LEAST(next_result_poll_at,transaction_timestamp())
                  WHERE authority=$1 AND accepted_binding->>'requestId'=$2
                    AND state='accepted'",
                &[&authority, &completion.request_id.to_string()],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
    }
    Ok(())
}

pub async fn reconcile_result(
    transaction: &Transaction<'_>,
    authority: &str,
    accepted: &ReviewRequestAccepted,
    result: &ReviewResult,
    mutations: &crate::postgres::PostgresRecordMutationService,
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
    // The accepted subject and result agree above. Lock that lifecycle row
    // before the review submission, matching mutations and public observations.
    // The exact accepted-binding lookup and id/version/digest checks below
    // prove it is the same Proposal before retaining a result or creating a job.
    let locked_proposal =
        Uuid::parse_str(&accepted.subject.id).map_err(|_| MutationError::PreconditionFailed)?;
    let lifecycle = transaction
        .query_opt(
            "SELECT state,submission_version,blocked_reason
               FROM registry_internal.registry_proposal_state
              WHERE proposal_id=$1 FOR UPDATE",
            &[&locked_proposal],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::PreconditionFailed)?;
    let accepted_value = serde_json::to_value(accepted).map_err(|_| MutationError::Unavailable)?;
    let row = transaction
        .query_opt(
            "SELECT action_id,proposal_id,submission_version,proposal_digest,
                    on_approved_mode,executor,withdrawn
               FROM registry_internal.registry_proposal_review_submissions
              WHERE authority=$1 AND accepted_binding=$2 AND state IN ('accepted','cancelling')
              FOR UPDATE",
            &[&authority, &accepted_value],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::PreconditionFailed)?;
    let entity_id: String = row.get(0);
    let proposal_id: Uuid = row.get(1);
    let version: i64 = row.get(2);
    let proposal_digest: String = row.get(3);
    if proposal_id != locked_proposal
        || result.subject.id != proposal_id.to_string()
        || result.subject.version != version.to_string()
        || result.subject.digest.as_str() != proposal_digest
    {
        return Err(MutationError::PreconditionFailed);
    }
    let status = result_status(result.status);
    let value = serde_json::to_value(result).map_err(|_| MutationError::Unavailable)?;
    let persisted = transaction
        .execute(
            "INSERT INTO registry_internal.registry_proposal_review_results
             (action_id,proposal_id,submission_version,authority,result_id,result,
              status,completed_at,available_until)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             ON CONFLICT (action_id,proposal_id,submission_version) DO UPDATE
                 SET result=EXCLUDED.result
               WHERE registry_proposal_review_results.result_id=EXCLUDED.result_id
                 AND registry_proposal_review_results.result=EXCLUDED.result",
            &[
                &entity_id,
                &proposal_id,
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
    // The recorded result settles the review, so an error an earlier lookup
    // or delivery left on the submission no longer calls for operator
    // attention. A later failure on this row records its own code again.
    transaction
        .execute(
            "UPDATE registry_internal.registry_proposal_review_submissions
                SET last_error_code=NULL,updated_at=transaction_timestamp()
              WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
            &[&entity_id, &proposal_id, &version],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    transaction
        .execute(
            "UPDATE registry_internal.registry_proposal_review_completions
                SET state='correlated'
              WHERE authority=$1 AND review_request_id=$2 AND result_id=$3
                AND state IN ('pending','unmatched')",
            &[&authority, &result.request_id, &result.result_id],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let mode: String = row.get(4);
    let withdrawn: bool = row.get(6);
    // Retain exact historical evidence even when activation or the requester
    // ended this round. Only the current unblocked round can advance work.
    let current = lifecycle.get::<_, String>(0) == "submitted"
        && lifecycle.get::<_, i64>(1) == version
        && lifecycle.get::<_, Option<String>>(2).is_none();
    if status == "approved" && mode == "automatic" && !withdrawn && current {
        let workflow =
            crate::proposal_store::load(transaction, &entity_id, proposal_id, false).await?;
        let frozen = workflow
            .current_proposal()
            .ok_or(MutationError::PreconditionFailed)?;
        if i64::from(frozen.version().get()) != version
            || frozen.effect_digest().as_str() != proposal_digest
        {
            return Err(MutationError::PreconditionFailed);
        }
        enqueue_automatic_application(transaction, &entity_id, proposal_id, frozen).await?;
    }
    if !withdrawn && current {
        mutations
            .record_review_result(
                transaction,
                authority,
                &entity_id,
                proposal_id,
                version,
                status,
            )
            .await?;
    }
    Ok(())
}

pub async fn poll_one_result(
    client: &mut tokio_postgres::Client,
    authority_id: &str,
    review_client: &ReviewClient,
    profile: &str,
    token: &BearerToken,
    lease_seconds: i64,
    mutations: &crate::postgres::PostgresRecordMutationService,
) -> Result<bool, MutationError> {
    // The lookup is claimed with a lease before the outbound exchange so two
    // instances cannot both act on one submission's result at once. Among due
    // reviews, one a hook completion already announced goes first, and one
    // the authority last answered as unknown goes last, so reviews an
    // authority lost (a restored or replaced review environment) cannot hold
    // back live ones. Every due review is still reached in turn. A completed
    // exchange releases its claim; next_result_poll_at owns the backoff.
    let Some(row) = client
        .query_opt(
            "UPDATE registry_internal.registry_proposal_review_submissions s
                SET lease_until=transaction_timestamp()+($2::bigint * interval '1 second'),
                    updated_at=transaction_timestamp()
              WHERE (s.action_id,s.proposal_id,s.submission_version)=(
                    SELECT c.action_id,c.proposal_id,c.submission_version
                      FROM registry_internal.registry_proposal_review_submissions c
                     WHERE c.state='accepted' AND c.authority=$1
                       AND c.next_result_poll_at <= transaction_timestamp()
                       AND (c.lease_until IS NULL OR c.lease_until < transaction_timestamp())
                       AND NOT EXISTS (
                           SELECT 1 FROM registry_internal.registry_proposal_review_results r
                            WHERE r.action_id=c.action_id
                              AND r.proposal_id=c.proposal_id
                              AND r.submission_version=c.submission_version)
                     ORDER BY EXISTS (
                                  SELECT 1
                                    FROM registry_internal.registry_proposal_review_completions k
                                   WHERE k.authority=c.authority AND k.state='pending'
                                     AND k.review_request_id::text=c.accepted_binding->>'requestId')
                                  DESC,
                              c.last_error_code IS NOT DISTINCT FROM 'result-unknown-to-authority',
                              c.updated_at
                     FOR UPDATE SKIP LOCKED LIMIT 1)
              RETURNING s.action_id,s.proposal_id,s.submission_version,
                        s.authority,s.accepted_binding,s.lease_until",
            &[&authority_id, &lease_seconds],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
    else {
        return Ok(false);
    };
    let entity_id: String = row.get(0);
    let proposal_id: Uuid = row.get(1);
    let version: i64 = row.get(2);
    let authority: String = row.get(3);
    let accepted: ReviewRequestAccepted =
        serde_json::from_value(row.get(4)).map_err(|_| MutationError::Unavailable)?;
    let lease_until: chrono::DateTime<chrono::Utc> = row.get(5);
    let response = match review_client
        .result(ReviewAuth::new(token, profile), &accepted)
        .await
    {
        Ok(response) => response,
        Err(_) => {
            // A failed lookup leaves row-level evidence and spends the give-up
            // budget, so an indefinitely failing endpoint is bounded by the
            // poll-attempt sweep in `run_one` instead of polling forever in
            // silence.
            client
                .execute(
                    "UPDATE registry_internal.registry_proposal_review_submissions
                        SET lease_until=NULL,
                            result_poll_attempts=LEAST(result_poll_attempts+1,1000),
                            last_error_code='result-lookup-uncertain',
                            next_result_poll_at=transaction_timestamp()+
                              (LEAST(60,5*LEAST(result_poll_attempts+1,1000)) * interval '1 second'),
                            updated_at=transaction_timestamp()
                      WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                        AND state='accepted' AND lease_until=$4",
                    &[&entity_id, &proposal_id, &version, &lease_until],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
            return Err(MutationError::Unavailable);
        }
    };
    match response {
        ReviewResultResponse::Available(complete) => {
            let transaction = client
                .transaction()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            reconcile_result(
                &transaction,
                &authority,
                &accepted,
                &complete.value,
                mutations,
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
        }
        ReviewResultResponse::Pending { .. } => {
            // A conforming 202 proves the result endpoint works and the
            // authority still holds the review open, and the authority, not
            // BReg, owns how long a review may take. So a pending answer
            // never spends the give-up budget: it settles the count at the
            // step where the backoff reaches its 60-second ceiling, which
            // also forgives earlier failed lookups, and it clears the lookup
            // error those failures recorded. The lease fence keeps a worker
            // that lost its claim from republishing over the new holder.
            client
                .execute(
                    "UPDATE registry_internal.registry_proposal_review_submissions
                        SET lease_until=NULL,
                            result_poll_attempts=LEAST(result_poll_attempts+1,12),
                            last_error_code=NULL,
                            next_result_poll_at=transaction_timestamp()+
                              (LEAST(60,5*LEAST(result_poll_attempts+1,12)) * interval '1 second'),
                            updated_at=transaction_timestamp()
                      WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                        AND state='accepted' AND lease_until=$4",
                    &[&entity_id, &proposal_id, &version, &lease_until],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
        }
        ReviewResultResponse::ConcealedOrUnknown { .. } => {
            // An empty 404 cannot tell a live review from a lost or concealed
            // one, so it spends the give-up budget like a failed lookup. The
            // lease fence keeps a worker that lost its claim (expired lease,
            // reclaimed row) from republishing a backoff over the new
            // holder's schedule. The lookup itself answered, so its own code
            // replaces the lookup error a previous failure or credential
            // outage recorded: the authority reached BReg and does not know
            // the review, which a slow reviewer never produces.
            client
                .execute(
                    "UPDATE registry_internal.registry_proposal_review_submissions
                        SET lease_until=NULL,
                            result_poll_attempts=LEAST(result_poll_attempts+1,1000),
                            last_error_code='result-unknown-to-authority',
                            next_result_poll_at=transaction_timestamp()+
                              (LEAST(60,5*LEAST(result_poll_attempts+1,1000)) * interval '1 second'),
                            updated_at=transaction_timestamp()
                      WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                        AND state='accepted' AND lease_until=$4",
                    &[&entity_id, &proposal_id, &version, &lease_until],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
        }
        ReviewResultResponse::Expired { .. } => {
            // Terminal failure is fenced the same way, and never marks a
            // submission another worker already reconciled a result for.
            client
                .execute(
                    "UPDATE registry_internal.registry_proposal_review_submissions
                        SET state='failed',last_error_code='result-expired',lease_until=NULL,
                            updated_at=transaction_timestamp()
                      WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                        AND state='accepted' AND lease_until=$4
                        AND NOT EXISTS (
                            SELECT 1 FROM registry_internal.registry_proposal_review_results r
                             WHERE r.action_id=$1 AND r.proposal_id=$2
                               AND r.submission_version=$3)",
                    &[&entity_id, &proposal_id, &version, &lease_until],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
        }
    }
    Ok(true)
}

fn result_status(status: registry_review_client::ReviewResultStatus) -> &'static str {
    match status {
        registry_review_client::ReviewResultStatus::Approved => "approved",
        registry_review_client::ReviewResultStatus::Rejected => "rejected",
        registry_review_client::ReviewResultStatus::ChangesRequested => "changes-requested",
        registry_review_client::ReviewResultStatus::Answered => "answered",
        registry_review_client::ReviewResultStatus::Cancelled => "cancelled",
        registry_review_client::ReviewResultStatus::Superseded => "superseded",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_digest_accepts_only_current_or_exact_legacy_request_and_binding() {
        let proposal_id = Uuid::new_v4();
        let request = ReviewCreateRequest {
            policy: serde_json::from_value(serde_json::json!({"id":"review-policy"})).unwrap(),
            subject: SubjectBinding {
                source: "shared.registry:v1".to_owned(),
                subject_type: "proposal".to_owned(),
                id: proposal_id.to_string(),
                version: "1".to_owned(),
                digest: registry_review_client::ContentDigest::for_bytes(b"effect"),
            },
            requester_reference: "proposal-reference".to_owned(),
            initiator: None,
            context: registry_review_client::ReviewContext::CurrentSource {
                binding: SourceContextBinding {
                    reference: format!("breg:registry-id:correct-name:{proposal_id}:1"),
                },
            },
            result_constraints: None,
        };
        let producer = "proposal-producer";
        let current = submission_digest(producer, &request.subject.source, &request).unwrap();
        let legacy = submission_digest(producer, "registry-id", &request).unwrap();
        assert_ne!(current, legacy);
        let mut accepted = ReviewRequestAccepted {
            request_id: Uuid::new_v4(),
            subject: request.subject.clone(),
            policy: serde_json::from_value(serde_json::json!({
                "id":"review-policy",
                "version":"1",
                "digest":registry_review_client::ContentDigest::for_bytes(b"policy"),
            }))
            .unwrap(),
            submission_digest: legacy.clone(),
        };

        assert_eq!(
            stored_submission_digest_compatibility(
                producer,
                "registry-id",
                &request,
                &current,
                None,
            )
            .unwrap()
            .0,
            StoredSubmissionDigestCompatibility::Current
        );
        assert_eq!(
            stored_submission_digest_compatibility(
                producer,
                "registry-id",
                &request,
                &legacy,
                Some(&accepted),
            )
            .unwrap(),
            (
                StoredSubmissionDigestCompatibility::LegacyRegistryId,
                current.clone(),
            )
        );

        let arbitrary = SubmissionDigest::parse(&format!("sha256:{}", "c".repeat(64))).unwrap();
        assert!(stored_submission_digest_compatibility(
            producer,
            "registry-id",
            &request,
            &arbitrary,
            None,
        )
        .is_err());
        accepted.submission_digest = current;
        assert!(stored_submission_digest_compatibility(
            producer,
            "registry-id",
            &request,
            &legacy,
            Some(&accepted),
        )
        .is_err());
        let mut rebound_source = request.clone();
        rebound_source.subject.source = "another-source".to_owned();
        let mut rebound_policy = request.clone();
        rebound_policy.policy =
            serde_json::from_value(serde_json::json!({"id":"another-policy"})).unwrap();
        let mut rebound_action = request.clone();
        rebound_action.context = registry_review_client::ReviewContext::CurrentSource {
            binding: SourceContextBinding {
                reference: format!("breg:registry-id:other-action:{proposal_id}:1"),
            },
        };
        let mut rebound_input = request.clone();
        rebound_input.requester_reference = "another-reference".to_owned();
        let mut rebound_effect = request;
        rebound_effect.subject.digest =
            registry_review_client::ContentDigest::for_bytes(b"another-effect");
        for altered in [
            rebound_source,
            rebound_policy,
            rebound_action,
            rebound_input,
            rebound_effect,
        ] {
            assert!(stored_submission_digest_compatibility(
                producer,
                "registry-id",
                &altered,
                &legacy,
                None,
            )
            .is_err());
        }
    }

    fn authority(id: &str, completion: Option<(&str, &str)>) -> Arc<ReviewAuthorityClient> {
        let client = ReviewClient::new(registry_review_client::ReviewClientConfig::new(
            "https://casework.example.test/".parse().expect("URL"),
        ))
        .expect("client");
        Arc::new(
            ReviewAuthorityClient::new(
                id.to_owned(),
                client,
                Arc::new(
                    registry_platform_httputil::StaticToken::new("outgoing-token".to_owned())
                        .expect("outgoing token"),
                ),
                "producer".to_owned(),
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
    fn completion_sender_bindings_must_be_unique_pairs() {
        assert!(ReviewAuthorityRegistry::new(BTreeMap::from([
            (
                "casework-a".to_owned(),
                authority("casework-a", Some(("shared-sender", "registry-a"))),
            ),
            (
                "casework-b".to_owned(),
                authority("casework-b", Some(("shared-sender", "registry-a"))),
            ),
        ]))
        .is_err());

        assert!(ReviewAuthorityRegistry::new(BTreeMap::from([
            (
                "casework-a".to_owned(),
                authority("casework-a", Some(("shared-sender", "registry-a"))),
            ),
            (
                "casework-b".to_owned(),
                authority("casework-b", Some(("shared-sender", "registry-b"))),
            ),
            (
                "casework-c".to_owned(),
                authority("casework-c", Some(("other-sender", "registry-a"))),
            ),
        ]))
        .is_ok());
    }

    #[test]
    fn submission_error_classification_retries_only_uncertain_failures() {
        assert!(terminal_submission_error(
            &ReviewClientError::Configuration {
                reason: "invalid configuration"
            }
        ));
        assert!(terminal_submission_error(
            &ReviewClientError::InvalidRequest {
                reason: "invalid request"
            }
        ));
        assert!(!terminal_submission_error(&ReviewClientError::Protocol {
            status: 201,
            failure: registry_review_client::ReviewProtocolFailure::Body,
            trace_id: None,
        }));
        assert!(terminal_submission_problem_status(409));
        assert!(!terminal_submission_problem_status(429));
        assert!(!terminal_submission_problem_status(503));
        assert!(!terminal_submission_error(&ReviewClientError::Transport {
            kind: registry_platform_httputil::client::TransportKind::Timeout,
        }));
    }

    #[test]
    fn completion_sender_rejects_tokens_outside_the_inbound_bearer_grammar() {
        for token in ["sender token", "sender,token"] {
            let client = ReviewClient::new(registry_review_client::ReviewClientConfig::new(
                "https://casework.example.test/".parse().expect("URL"),
            ))
            .expect("client");
            assert!(
                ReviewAuthorityClient::new(
                    "casework-a".to_owned(),
                    client,
                    Arc::new(
                        registry_platform_httputil::StaticToken::new("outgoing-token".to_owned(),)
                            .expect("outgoing token"),
                    ),
                    "producer".to_owned(),
                    "registry-producer".to_owned(),
                    30,
                    Some(Zeroizing::new(token.to_owned())),
                    Some("registry-a".to_owned()),
                )
                .is_err(),
                "completion token {token:?} cannot authenticate the inbound route"
            );
        }
    }

    #[test]
    fn completion_recipient_accepts_only_bounded_visible_ascii() {
        let at_bound = "x".repeat(MAXIMUM_COMPLETION_RECIPIENT_BYTES);
        authority("casework-a", Some(("sender-a", &at_bound)));

        for recipient in ["contains space", "contains\t tab", "récepteur"] {
            assert!(
                !valid_completion_recipient(recipient),
                "recipient {recipient:?} cannot be represented by the callback header contract"
            );
        }

        let over_bound = "x".repeat(MAXIMUM_COMPLETION_RECIPIENT_BYTES + 1);
        let client = ReviewClient::new(registry_review_client::ReviewClientConfig::new(
            "https://casework.example.test/".parse().expect("URL"),
        ))
        .expect("client");
        assert!(
            ReviewAuthorityClient::new(
                "casework-a".to_owned(),
                client,
                Arc::new(
                    registry_platform_httputil::StaticToken::new("outgoing-token".to_owned())
                        .expect("outgoing token"),
                ),
                "producer".to_owned(),
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
                ReviewClient::new(registry_review_client::ReviewClientConfig::new(
                    "https://casework.example.test/".parse().expect("URL"),
                ))
                .expect("client"),
                Arc::new(
                    registry_platform_httputil::StaticToken::new("outgoing-token".to_owned())
                        .expect("outgoing token"),
                ),
                "producer".to_owned(),
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
}

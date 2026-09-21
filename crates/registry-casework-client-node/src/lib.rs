// SPDX-License-Identifier: Apache-2.0
//! Node.js binding for the canonical Registry Casework client.

#![deny(unsafe_code)]

use registry_casework_client::DirectoryTeamUpdateRequest;
use std::time::Duration;

use napi::{Error as NapiError, Result};
use napi_derive::napi;
use registry_casework_client::{
    AbsenceInput, AbsencesQuery, AssignmentRequest, BootstrapDirectoryRequest,
    CaseloadApplyRequest, CaseloadMoveRequest, CaseloadPreviewQuery, CaseworkAction, CaseworkAuth,
    CaseworkClient as CoreClient, CaseworkClientConfig as CoreConfig, CaseworkClientError,
    ClockRecomputeApplyRequest, ClockRecomputeRequest, DecideRequest, DelegateRequest,
    DirectoryTargetsQuery, HoldingsQuery, HolidaySetRevisionInput, NextWorkItemQuery,
    RecoverAttemptRequest, ReviewCancelRequest, ReviewCreateRequest, ReviewNoteRequest,
    ReviewPageQuery, ReviewRequestAccepted, ReviewResultResponse, ReviewTaskDecisionRequest,
    ReviewTaskDraftInput, ReviewTaskQuery, SaveDraftRequest, SubmissionDigest,
    WorkItemHistoryQuery,
};
use serde::Serialize;
use serde_json::{json, Value};
use url::Url;
use uuid::Uuid;

const MAXIMUM_JAVASCRIPT_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[napi(object)]
pub struct CaseworkClientConfig {
    pub base_url: String,
    pub request_timeout_milliseconds: Option<u32>,
    pub connect_timeout_milliseconds: Option<u32>,
    pub max_response_bytes: Option<u32>,
    pub user_agent: Option<String>,
    pub trusted_root_certificates: Option<String>,
}

#[napi(object)]
pub struct CaseworkOutcome {
    pub kind: String,
    pub value: Value,
    pub trace_id: String,
}

#[napi(js_name = "CaseworkClient")]
pub struct CaseworkClient {
    inner: CoreClient,
}

#[napi]
impl CaseworkClient {
    #[napi(constructor)]
    pub fn new(config: CaseworkClientConfig) -> Result<Self> {
        let base_url = Url::parse(&config.base_url).map_err(|_| {
            binding_error("configuration", "Casework client configuration is invalid")
        })?;
        let mut core = CoreConfig::new(base_url);
        if let Some(value) = config.request_timeout_milliseconds {
            core = core.with_request_timeout(Duration::from_millis(u64::from(value)));
        }
        if let Some(value) = config.connect_timeout_milliseconds {
            core = core.with_connect_timeout(Duration::from_millis(u64::from(value)));
        }
        if let Some(value) = config.max_response_bytes {
            core = core.with_max_response_bytes(u64::from(value));
        }
        if let Some(value) = config.user_agent {
            core = core.with_user_agent(value);
        }
        if let Some(value) = config.trusted_root_certificates {
            core = core.with_trusted_root_certificates(value.into_bytes());
        }
        CoreClient::new(core)
            .map(|inner| Self { inner })
            .map_err(client_error)
    }

    #[napi]
    pub async fn description(&self, token: String, profile: String) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .description(CaseworkAuth::new(&token, &profile))
                .await,
        )
    }

    #[napi]
    pub async fn create_or_recover_review_request(
        &self,
        token: String,
        profile: String,
        idempotency_key: String,
        request: Value,
        expected_submission_digest: String,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let request: ReviewCreateRequest = input(request)?;
        let digest = SubmissionDigest::parse(&expected_submission_digest)
            .map_err(|_| binding_error("invalid_request", "the submission digest is invalid"))?;
        outcome(
            self.inner
                .create_or_recover_review_request(
                    CaseworkAuth::new(&token, &profile),
                    &idempotency_key,
                    &request,
                    &digest,
                )
                .await,
        )
    }

    #[napi]
    pub async fn review_request(
        &self,
        token: String,
        profile: String,
        request_id: String,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .review_request(CaseworkAuth::new(&token, &profile), uuid(&request_id)?)
                .await,
        )
    }

    #[napi]
    pub async fn review_result(
        &self,
        token: String,
        profile: String,
        accepted: Value,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let accepted = input(accepted)?;
        review_result_outcome(
            self.inner
                .review_result(CaseworkAuth::new(&token, &profile), &accepted)
                .await,
        )
    }

    #[napi]
    pub async fn review_results(
        &self,
        token: String,
        profile: String,
        query: Option<Value>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let query: ReviewPageQuery = query.map(input).transpose()?.unwrap_or_default();
        outcome(
            self.inner
                .review_results(CaseworkAuth::new(&token, &profile), &query)
                .await,
        )
    }

    #[napi]
    pub async fn cancel_review_request(
        &self,
        token: String,
        profile: String,
        accepted: Value,
        idempotency_key: String,
        request: Value,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let accepted: ReviewRequestAccepted = input(accepted)?;
        let request: ReviewCancelRequest = input(request)?;
        outcome(
            self.inner
                .cancel_review_request(
                    CaseworkAuth::new(&token, &profile),
                    &accepted,
                    &idempotency_key,
                    &request,
                )
                .await,
        )
    }

    #[napi]
    pub async fn review_kinds(&self, token: String, profile: String) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .review_kinds(CaseworkAuth::new(&token, &profile))
                .await,
        )
    }

    #[napi]
    pub async fn review_kind(
        &self,
        token: String,
        profile: String,
        kind_id: String,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .review_kind(CaseworkAuth::new(&token, &profile), &kind_id)
                .await,
        )
    }

    #[napi]
    pub async fn review_tasks(
        &self,
        token: String,
        profile: String,
        query: Option<Value>,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let query: ReviewTaskQuery = query.map(input).transpose()?.unwrap_or_default();
        outcome(
            self.inner
                .review_tasks(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    &query,
                )
                .await,
        )
    }

    #[napi]
    pub async fn review_task(
        &self,
        token: String,
        profile: String,
        task_id: String,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .review_task(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    uuid(&task_id)?,
                )
                .await,
        )
    }

    #[napi]
    pub async fn review_task_context(
        &self,
        token: String,
        profile: String,
        task_id: String,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .review_task_context(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    uuid(&task_id)?,
                )
                .await,
        )
    }

    #[napi]
    pub async fn preview_review_task_templates(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        task_id: String,
    ) -> Result<CaseworkOutcome> {
        let task_id = uuid(&task_id)?;
        let token = bearer(token)?;
        outcome(
            self.inner
                .preview_review_task_templates(auth(&token, &profile, &source_profile), task_id)
                .await,
        )
    }

    #[napi]
    pub async fn list_review_task_grants(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        task_id: String,
    ) -> Result<CaseworkOutcome> {
        let task_id = uuid(&task_id)?;
        let token = bearer(token)?;
        outcome(
            self.inner
                .list_review_task_grants(auth(&token, &profile, &source_profile), task_id)
                .await,
        )
    }

    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub async fn approve_review_task_grant(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        task_id: String,
        expected_revision: i64,
        idempotency_key: String,
        approval: Value,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let task_id = uuid(&task_id)?;
        let approval: registry_casework_client::TaskApprovalRequest = input(approval)?;
        let token = bearer(token)?;
        outcome(
            self.inner
                .approve_review_task_grant(
                    auth(&token, &profile, &source_profile),
                    task_id,
                    expected_revision,
                    &idempotency_key,
                    &approval,
                )
                .await,
        )
    }

    #[napi]
    pub async fn revoke_review_task_grant(
        &self,
        token: String,
        profile: String,
        task_id: String,
        grant_id: String,
    ) -> Result<CaseworkOutcome> {
        let task_id = uuid(&task_id)?;
        let grant_id = uuid(&grant_id)?;
        let token = bearer(token)?;
        outcome(
            self.inner
                .revoke_review_task_grant(
                    optional_source_auth(&token, &profile, None),
                    task_id,
                    grant_id,
                )
                .await,
        )
    }

    #[napi]
    pub async fn claim_review_task(
        &self,
        token: String,
        profile: String,
        task_id: String,
        expected_revision: i64,
        idempotency_key: String,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        outcome(
            self.inner
                .claim_review_task(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    uuid(&task_id)?,
                    expected_revision,
                    &idempotency_key,
                )
                .await,
        )
    }

    #[napi]
    pub async fn release_review_task(
        &self,
        token: String,
        profile: String,
        task_id: String,
        expected_revision: i64,
        idempotency_key: String,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        outcome(
            self.inner
                .release_review_task(
                    CaseworkAuth::new(&token, &profile),
                    uuid(&task_id)?,
                    expected_revision,
                    &idempotency_key,
                )
                .await,
        )
    }

    #[napi]
    #[allow(clippy::too_many_arguments)] // The public binding keeps auth, revision, retry, and source context explicit.
    pub async fn assign_review_task(
        &self,
        token: String,
        profile: String,
        task_id: String,
        expected_revision: i64,
        idempotency_key: String,
        request: Value,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        let request: AssignmentRequest = input(request)?;
        outcome(
            self.inner
                .assign_review_task(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    uuid(&task_id)?,
                    expected_revision,
                    &idempotency_key,
                    &request,
                )
                .await,
        )
    }

    #[napi]
    #[allow(clippy::too_many_arguments)] // The public binding keeps auth, revision, retry, and source context explicit.
    pub async fn delegate_review_task(
        &self,
        token: String,
        profile: String,
        task_id: String,
        expected_revision: i64,
        idempotency_key: String,
        request: Value,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        let request: DelegateRequest = input(request)?;
        outcome(
            self.inner
                .delegate_review_task(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    uuid(&task_id)?,
                    expected_revision,
                    &idempotency_key,
                    &request,
                )
                .await,
        )
    }

    #[napi]
    pub async fn review_task_draft(
        &self,
        token: String,
        profile: String,
        task_id: String,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .review_task_draft(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    uuid(&task_id)?,
                )
                .await,
        )
    }

    #[napi]
    #[allow(clippy::too_many_arguments)] // The public binding keeps auth, revision, retry, and source context explicit.
    pub async fn save_review_task_draft(
        &self,
        token: String,
        profile: String,
        task_id: String,
        expected_revision: i64,
        idempotency_key: String,
        draft: Value,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        let draft: ReviewTaskDraftInput = input(draft)?;
        outcome(
            self.inner
                .save_review_task_draft(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    uuid(&task_id)?,
                    expected_revision,
                    &idempotency_key,
                    &draft,
                )
                .await,
        )
    }

    #[napi]
    pub async fn delete_review_task_draft(
        &self,
        token: String,
        profile: String,
        task_id: String,
        expected_revision: i64,
        idempotency_key: String,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        outcome(
            self.inner
                .delete_review_task_draft(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    uuid(&task_id)?,
                    expected_revision,
                    &idempotency_key,
                )
                .await,
        )
    }

    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub async fn decide_review_task(
        &self,
        token: String,
        profile: String,
        task_id: String,
        expected_revision: i64,
        idempotency_key: String,
        decision: Value,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        let decision: ReviewTaskDecisionRequest = input(decision)?;
        outcome(
            self.inner
                .decide_review_task(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    uuid(&task_id)?,
                    expected_revision,
                    &idempotency_key,
                    &decision,
                )
                .await,
        )
    }

    #[napi]
    pub async fn review_history(
        &self,
        token: String,
        profile: String,
        request_id: String,
        query: Option<Value>,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let query: ReviewPageQuery = query.map(input).transpose()?.unwrap_or_default();
        outcome(
            self.inner
                .review_history(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    uuid(&request_id)?,
                    &query,
                )
                .await,
        )
    }

    #[napi]
    pub async fn add_review_note(
        &self,
        token: String,
        profile: String,
        request_id: String,
        idempotency_key: String,
        note: Value,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let note: ReviewNoteRequest = input(note)?;
        outcome(
            self.inner
                .add_review_note(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    uuid(&request_id)?,
                    &idempotency_key,
                    &note,
                )
                .await,
        )
    }

    #[napi]
    pub async fn review_clocks(
        &self,
        token: String,
        profile: String,
        request_id: String,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .review_clocks(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    uuid(&request_id)?,
                )
                .await,
        )
    }

    #[napi]
    pub async fn review_accountability(
        &self,
        token: String,
        profile: String,
        event_id: String,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .review_accountability(CaseworkAuth::new(&token, &profile), uuid(&event_id)?)
                .await,
        )
    }

    #[napi]
    pub async fn list_work_items(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        query: Value,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let query = input(query)?;
        outcome(
            self.inner
                .list_work_items(auth(&token, &profile, &source_profile), &query)
                .await,
        )
    }

    #[napi]
    pub async fn next_work_item(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        query: Option<Value>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let query: NextWorkItemQuery = query.map(input).transpose()?.unwrap_or_default();
        outcome(
            self.inner
                .next_work_item(auth(&token, &profile, &source_profile), &query)
                .await,
        )
    }

    #[napi]
    pub async fn get_work_item(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        item_id: String,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .get_work_item(auth(&token, &profile, &source_profile), uuid(&item_id)?)
                .await,
        )
    }

    #[napi]
    pub async fn preview_task_templates(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        item_id: String,
    ) -> Result<CaseworkOutcome> {
        let item_id = uuid(&item_id)?;
        let token = bearer(token)?;
        outcome(
            self.inner
                .preview_task_templates(auth(&token, &profile, &source_profile), item_id)
                .await,
        )
    }

    #[napi]
    pub async fn list_task_grants(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        item_id: String,
    ) -> Result<CaseworkOutcome> {
        let item_id = uuid(&item_id)?;
        let token = bearer(token)?;
        outcome(
            self.inner
                .list_task_grants(auth(&token, &profile, &source_profile), item_id)
                .await,
        )
    }

    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub async fn approve_task_grant(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        item_id: String,
        expected_revision: i64,
        idempotency_key: String,
        approval: Value,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let item_id = uuid(&item_id)?;
        let approval: registry_casework_client::TaskApprovalRequest = input(approval)?;
        let token = bearer(token)?;
        outcome(
            self.inner
                .approve_task_grant(
                    auth(&token, &profile, &source_profile),
                    item_id,
                    expected_revision,
                    &idempotency_key,
                    &approval,
                )
                .await,
        )
    }
    #[napi]
    pub async fn revoke_task_grant(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        item_id: String,
        grant_id: String,
    ) -> Result<CaseworkOutcome> {
        let item_id = uuid(&item_id)?;
        let grant_id = uuid(&grant_id)?;
        let token = bearer(token)?;
        outcome(
            self.inner
                .revoke_task_grant(auth(&token, &profile, &source_profile), item_id, grant_id)
                .await,
        )
    }
    #[napi]
    pub async fn task_assertion(&self, token: String, grant_id: String) -> Result<CaseworkOutcome> {
        let grant_id = uuid(&grant_id)?;
        let token = bearer(token)?;
        outcome(self.inner.task_assertion(&token, grant_id).await)
    }
    #[napi]
    pub fn task_assertion_endpoint(&self, grant_id: String) -> Result<String> {
        self.inner
            .task_assertion_endpoint(uuid(&grant_id)?)
            .map(|value| value.to_string())
            .map_err(client_error)
    }
    #[napi]
    pub async fn task_grant_status(
        &self,
        token: String,
        grant_id: String,
    ) -> Result<CaseworkOutcome> {
        let grant_id = uuid(&grant_id)?;
        let token = bearer(token)?;
        outcome(self.inner.task_grant_status(&token, grant_id).await)
    }

    #[napi]
    pub async fn claim_work_item(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        action: Value,
        idempotency_key: String,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let action: CaseworkAction = input(action)?;
        outcome(
            self.inner
                .claim_work_item(
                    auth(&token, &profile, &source_profile),
                    &action,
                    &idempotency_key,
                )
                .await,
        )
    }

    #[napi]
    pub async fn release_work_item(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        action: Value,
        idempotency_key: String,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let action: CaseworkAction = input(action)?;
        outcome(
            self.inner
                .release_work_item(
                    auth(&token, &profile, &source_profile),
                    &action,
                    &idempotency_key,
                )
                .await,
        )
    }

    #[napi]
    pub async fn get_draft(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        item_id: String,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .get_draft(auth(&token, &profile, &source_profile), uuid(&item_id)?)
                .await,
        )
    }

    #[napi]
    #[allow(clippy::too_many_arguments)] // The public binding keeps per-call auth and mutation inputs explicit.
    pub async fn save_draft(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        item_id: String,
        expected_revision: i64,
        idempotency_key: String,
        draft: Value,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        let draft: SaveDraftRequest = input(draft)?;
        outcome(
            self.inner
                .save_draft(
                    auth(&token, &profile, &source_profile),
                    uuid(&item_id)?,
                    expected_revision,
                    &idempotency_key,
                    &draft,
                )
                .await,
        )
    }

    #[napi]
    pub async fn delete_draft(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        item_id: String,
        expected_revision: i64,
        idempotency_key: String,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        outcome(
            self.inner
                .delete_draft(
                    auth(&token, &profile, &source_profile),
                    uuid(&item_id)?,
                    expected_revision,
                    &idempotency_key,
                )
                .await,
        )
    }

    #[napi]
    pub async fn decide_work_item(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        action: Value,
        idempotency_key: String,
        decision: Value,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let action: CaseworkAction = input(action)?;
        let decision: DecideRequest = input(decision)?;
        outcome(
            self.inner
                .decide_work_item(
                    auth(&token, &profile, &source_profile),
                    &action,
                    &idempotency_key,
                    &decision,
                )
                .await,
        )
    }

    #[napi]
    pub async fn recover_decision(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        item_id: String,
        attempt_id: String,
        recovery: Value,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let recovery: RecoverAttemptRequest = input(recovery)?;
        outcome(
            self.inner
                .recover_decision(
                    auth(&token, &profile, &source_profile),
                    uuid(&item_id)?,
                    uuid(&attempt_id)?,
                    &recovery,
                )
                .await,
        )
    }

    #[napi]
    pub async fn recover_decision_by_key(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        item_id: String,
        idempotency_key: String,
        recovery: Value,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let recovery: RecoverAttemptRequest = input(recovery)?;
        outcome(
            self.inner
                .recover_decision_by_key(
                    auth(&token, &profile, &source_profile),
                    uuid(&item_id)?,
                    &idempotency_key,
                    &recovery,
                )
                .await,
        )
    }

    #[napi]
    pub async fn work_item_history(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        item_id: String,
        query: Option<Value>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let query: WorkItemHistoryQuery = query.map(input).transpose()?.unwrap_or_default();
        outcome(
            self.inner
                .work_item_history(
                    auth(&token, &profile, &source_profile),
                    uuid(&item_id)?,
                    &query,
                )
                .await,
        )
    }

    #[napi]
    pub async fn holdings(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        query: Option<Value>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let query: HoldingsQuery = query.map(input).transpose()?.unwrap_or_default();
        outcome(
            self.inner
                .holdings(auth(&token, &profile, &source_profile), &query)
                .await,
        )
    }

    #[napi]
    pub async fn directory(&self, token: String, profile: String) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .directory(CaseworkAuth::new(&token, &profile))
                .await,
        )
    }

    #[napi]
    pub async fn directory_targets(
        &self,
        token: String,
        profile: String,
        query: Value,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let query: DirectoryTargetsQuery = input(query)?;
        outcome(
            self.inner
                .directory_targets(CaseworkAuth::new(&token, &profile), &query)
                .await,
        )
    }

    #[napi]
    pub async fn bootstrap_directory(
        &self,
        token: String,
        profile: String,
        expected_revision: i64,
        idempotency_key: String,
        bootstrap: Value,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        let bootstrap: BootstrapDirectoryRequest = input(bootstrap)?;
        outcome(
            self.inner
                .bootstrap_directory(
                    CaseworkAuth::new(&token, &profile),
                    expected_revision,
                    &idempotency_key,
                    &bootstrap,
                )
                .await,
        )
    }
}

#[napi]
impl CaseworkClient {
    #[napi]
    pub async fn absences(
        &self,
        token: String,
        profile: String,
        query: Option<Value>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let query: AbsencesQuery = query.map(input).transpose()?.unwrap_or_default();
        outcome(
            self.inner
                .absences_page(CaseworkAuth::new(&token, &profile), &query)
                .await,
        )
    }

    #[napi]
    pub async fn create_absence(
        &self,
        token: String,
        profile: String,
        expected_revision: i64,
        idempotency_key: String,
        request: Value,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        let request: AbsenceInput = input(request)?;
        outcome(
            self.inner
                .create_absence(
                    CaseworkAuth::new(&token, &profile),
                    expected_revision,
                    &idempotency_key,
                    &request,
                )
                .await,
        )
    }

    #[napi]
    pub async fn update_absence(
        &self,
        token: String,
        profile: String,
        absence_id: String,
        expected_revision: i64,
        idempotency_key: String,
        request: Value,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        let request: AbsenceInput = input(request)?;
        outcome(
            self.inner
                .update_absence(
                    CaseworkAuth::new(&token, &profile),
                    uuid(&absence_id)?,
                    expected_revision,
                    &idempotency_key,
                    &request,
                )
                .await,
        )
    }

    #[napi]
    pub async fn delete_absence(
        &self,
        token: String,
        profile: String,
        absence_id: String,
        expected_revision: i64,
        idempotency_key: String,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        outcome(
            self.inner
                .delete_absence(
                    CaseworkAuth::new(&token, &profile),
                    uuid(&absence_id)?,
                    expected_revision,
                    &idempotency_key,
                )
                .await,
        )
    }

    #[napi]
    #[allow(clippy::too_many_arguments)] // Auth, revision and retry key remain explicit per call.
    pub async fn assign_work_item(
        &self,
        token: String,
        profile: String,
        item_id: String,
        expected_revision: i64,
        idempotency_key: String,
        request: Value,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        let request: AssignmentRequest = input(request)?;
        outcome(
            self.inner
                .assign_work_item(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    uuid(&item_id)?,
                    expected_revision,
                    &idempotency_key,
                    &request,
                )
                .await,
        )
    }

    #[napi]
    #[allow(clippy::too_many_arguments)] // Auth, revision and retry key remain explicit per call.
    pub async fn delegate_work_item(
        &self,
        token: String,
        profile: String,
        item_id: String,
        expected_revision: i64,
        idempotency_key: String,
        request: Value,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        let request: DelegateRequest = input(request)?;
        outcome(
            self.inner
                .delegate_work_item(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    uuid(&item_id)?,
                    expected_revision,
                    &idempotency_key,
                    &request,
                )
                .await,
        )
    }

    #[napi]
    pub async fn preview_caseload_move(
        &self,
        token: String,
        profile: String,
        movement: Value,
        query: Option<Value>,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let movement: CaseloadMoveRequest = input(movement)?;
        let query: CaseloadPreviewQuery = query.map(input).transpose()?.unwrap_or_default();
        outcome(
            self.inner
                .preview_caseload_move(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    &movement,
                    &query,
                )
                .await,
        )
    }

    #[napi]
    pub async fn apply_caseload_move(
        &self,
        token: String,
        profile: String,
        idempotency_key: String,
        request: Value,
        source_profile: Option<String>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let request: CaseloadApplyRequest = input(request)?;
        for item in &request.items {
            safe_revision(item.expected_revision)?;
        }
        outcome(
            self.inner
                .apply_caseload_move(
                    optional_source_auth(&token, &profile, source_profile.as_deref()),
                    &idempotency_key,
                    &request,
                )
                .await,
        )
    }
}

#[napi]
impl CaseworkClient {
    #[napi]
    pub async fn update_directory_team(
        &self,
        token: String,
        profile: String,
        team_id: String,
        expected_revision: i64,
        idempotency_key: String,
        request: Value,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        let request: DirectoryTeamUpdateRequest = input(request)?;
        outcome(
            self.inner
                .update_directory_team(
                    CaseworkAuth::new(&token, &profile),
                    &team_id,
                    expected_revision,
                    &idempotency_key,
                    &request,
                )
                .await,
        )
    }

    #[napi]
    pub async fn work_item_clocks(
        &self,
        token: String,
        profile: String,
        source_profile: String,
        item_id: String,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .work_item_clocks(auth(&token, &profile, &source_profile), uuid(&item_id)?)
                .await,
        )
    }

    #[napi]
    pub async fn holiday_revision(
        &self,
        token: String,
        profile: String,
        holiday_set: String,
        revision: i64,
    ) -> Result<CaseworkOutcome> {
        safe_revision(revision)?;
        let token = bearer(token)?;
        outcome(
            self.inner
                .holiday_revision(
                    CaseworkAuth::new(&token, &profile),
                    &holiday_set,
                    revision as u64,
                )
                .await,
        )
    }

    #[napi]
    pub async fn create_holiday_revision(
        &self,
        token: String,
        profile: String,
        idempotency_key: String,
        request: Value,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let request: HolidaySetRevisionInput = input(request)?;
        outcome(
            self.inner
                .create_holiday_revision(
                    CaseworkAuth::new(&token, &profile),
                    &idempotency_key,
                    &request,
                )
                .await,
        )
    }

    #[napi]
    pub async fn preview_clock_recompute(
        &self,
        token: String,
        profile: String,
        request: Value,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let request: ClockRecomputeRequest = input(request)?;
        outcome(
            self.inner
                .preview_clock_recompute(CaseworkAuth::new(&token, &profile), &request)
                .await,
        )
    }

    #[napi]
    pub async fn apply_clock_recompute(
        &self,
        token: String,
        profile: String,
        idempotency_key: String,
        request: Value,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let request: ClockRecomputeApplyRequest = input(request)?;
        outcome(
            self.inner
                .apply_clock_recompute(
                    CaseworkAuth::new(&token, &profile),
                    &idempotency_key,
                    &request,
                )
                .await,
        )
    }
}

fn optional_source_auth<'a>(
    token: &'a registry_casework_client::BearerToken,
    profile: &'a str,
    source_profile: Option<&'a str>,
) -> CaseworkAuth<'a> {
    let auth = CaseworkAuth::new(token, profile);
    match source_profile {
        Some(source) => auth.with_source_profile(source),
        None => auth,
    }
}

fn bearer(value: String) -> Result<registry_casework_client::BearerToken> {
    registry_casework_client::BearerToken::new(value)
        .map_err(|_| binding_error("invalid_request", "the bearer token is invalid"))
}

fn auth<'a>(
    token: &'a registry_casework_client::BearerToken,
    profile: &'a str,
    source_profile: &'a str,
) -> CaseworkAuth<'a> {
    CaseworkAuth::new(token, profile).with_source_profile(source_profile)
}

fn uuid(value: &str) -> Result<Uuid> {
    Uuid::parse_str(value).map_err(|_| binding_error("invalid_request", "the UUID is invalid"))
}

fn safe_revision(value: i64) -> Result<()> {
    if (0..=MAXIMUM_JAVASCRIPT_SAFE_INTEGER).contains(&value) {
        Ok(())
    } else {
        Err(binding_error(
            "invalid_request",
            "the revision is outside the JavaScript safe integer range",
        ))
    }
}

fn input<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    if contains_unsafe_integer(&value) {
        return Err(binding_error(
            "invalid_request",
            "Casework client arguments are invalid",
        ));
    }
    serde_json::from_value(value)
        .map_err(|_| binding_error("invalid_request", "Casework client arguments are invalid"))
}

fn outcome<T: Serialize>(
    value: std::result::Result<registry_casework_client::CaseworkComplete<T>, CaseworkClientError>,
) -> Result<CaseworkOutcome> {
    let value = value.map_err(client_error)?;
    let serialized = serde_json::to_value(value.value)
        .map_err(|_| binding_error("protocol", "Casework result is not representable"))?;
    ensure_safe_integers(&serialized)?;
    Ok(CaseworkOutcome {
        kind: "complete".into(),
        value: serialized,
        trace_id: value.trace_id,
    })
}

fn review_result_outcome(
    value: std::result::Result<ReviewResultResponse, CaseworkClientError>,
) -> Result<CaseworkOutcome> {
    let value = value.map_err(client_error)?;
    let (kind, value, trace_id) = match value {
        ReviewResultResponse::Available(complete) => (
            "available",
            serde_json::to_value(complete.value)
                .map_err(|_| binding_error("protocol", "Casework result is not representable"))?,
            complete.trace_id,
        ),
        ReviewResultResponse::Pending { trace_id } => ("pending", Value::Null, trace_id),
        ReviewResultResponse::ConcealedOrUnknown { trace_id } => {
            ("concealed_or_unknown", Value::Null, trace_id)
        }
        ReviewResultResponse::Expired { trace_id } => ("expired", Value::Null, trace_id),
    };
    ensure_safe_integers(&value)?;
    Ok(CaseworkOutcome {
        kind: kind.to_owned(),
        value,
        trace_id,
    })
}

fn ensure_safe_integers(value: &Value) -> Result<()> {
    if contains_unsafe_integer(value) {
        return Err(binding_error(
            "protocol",
            "Casework returned an integer outside the JavaScript safe range",
        ));
    }
    Ok(())
}

fn contains_unsafe_integer(value: &Value) -> bool {
    match value {
        Value::Number(number)
            if number.as_i64().is_some_and(|value| {
                value.unsigned_abs() > MAXIMUM_JAVASCRIPT_SAFE_INTEGER as u64
            }) || number
                .as_u64()
                .is_some_and(|value| value > MAXIMUM_JAVASCRIPT_SAFE_INTEGER as u64)
                || number.as_f64().is_some_and(|value| {
                    value.fract() == 0.0 && value.abs() > MAXIMUM_JAVASCRIPT_SAFE_INTEGER as f64
                }) =>
        {
            true
        }
        Value::Array(values) => values.iter().any(contains_unsafe_integer),
        Value::Object(values) => values.values().any(contains_unsafe_integer),
        _ => false,
    }
}

fn client_error(error: CaseworkClientError) -> NapiError {
    let value = match error {
        CaseworkClientError::Configuration { .. } => json!({
            "kind": "configuration",
            "message": "Casework client configuration is invalid",
        }),
        CaseworkClientError::InvalidRequest { .. } => json!({
            "kind": "invalid_request",
            "message": "Casework client arguments are invalid",
        }),
        CaseworkClientError::Transport { kind } => json!({
            "kind": "transport",
            "transportKind": kind.kind(),
            "message": "Registry Casework exchange did not complete",
        }),
        CaseworkClientError::Problem {
            status,
            code,
            detail,
            trace_id,
            original_attempt_id,
            validation,
        } => {
            let message = detail
                .clone()
                .unwrap_or_else(|| "Registry Casework refused the request".to_owned());
            json!({
                "kind": "problem",
                "status": status,
                "code": code.code(),
                "traceId": trace_id,
                "originalAttemptId": original_attempt_id,
                "validation": validation.map(|validation| json!({
                    "path": validation.path,
                    "reason": validation.reason,
                })),
                "detail": detail,
                "message": message,
            })
        }
        CaseworkClientError::Protocol {
            status,
            failure,
            trace_id,
        } => json!({
            "kind": "protocol",
            "status": status,
            "protocolFailure": protocol_failure(failure),
            "traceId": trace_id,
            "message": "Registry Casework returned an invalid response",
        }),
        _ => json!({
            "kind": "protocol",
            "message": "Registry Casework client failed",
        }),
    };
    NapiError::from_reason(serde_json::to_string(&value).unwrap_or_else(|_| {
        r#"{"kind":"protocol","message":"the failure could not be described"}"#.into()
    }))
}

fn protocol_failure(failure: registry_casework_client::CaseworkProtocolFailure) -> &'static str {
    use registry_casework_client::CaseworkProtocolFailure;

    match failure {
        CaseworkProtocolFailure::HeaderBounds => "header_bounds",
        CaseworkProtocolFailure::TraceContext => "trace_context",
        CaseworkProtocolFailure::MediaType => "media_type",
        CaseworkProtocolFailure::Body => "body",
        CaseworkProtocolFailure::Problem => "problem",
        CaseworkProtocolFailure::Status => "status",
        _ => "protocol",
    }
}

fn binding_error(kind: &'static str, message: &'static str) -> NapiError {
    NapiError::from_reason(json!({ "kind": kind, "message": message }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_response_integer_is_refused() {
        assert!(ensure_safe_integers(&json!(9_007_199_254_740_992_u64)).is_err());
    }

    #[test]
    fn protocol_failures_use_the_public_snake_case_vocabulary() {
        use registry_casework_client::CaseworkProtocolFailure;

        assert_eq!(
            protocol_failure(CaseworkProtocolFailure::HeaderBounds),
            "header_bounds"
        );
        assert_eq!(
            protocol_failure(CaseworkProtocolFailure::TraceContext),
            "trace_context"
        );
        assert_eq!(
            protocol_failure(CaseworkProtocolFailure::MediaType),
            "media_type"
        );
        assert_eq!(protocol_failure(CaseworkProtocolFailure::Body), "body");
        assert_eq!(
            protocol_failure(CaseworkProtocolFailure::Problem),
            "problem"
        );
        assert_eq!(protocol_failure(CaseworkProtocolFailure::Status), "status");
    }
}

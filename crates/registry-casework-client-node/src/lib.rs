// SPDX-License-Identifier: Apache-2.0
//! Node.js binding for the canonical Registry Casework client.

#![deny(unsafe_code)]

use registry_casework_client::DirectoryTeamUpdateRequest;
use std::time::Duration;

use napi::{Error as NapiError, Result};
use napi_derive::napi;
use registry_casework_client::{
    AbsenceInput, AssignmentRequest, BootstrapDirectoryRequest, CaseloadApplyRequest,
    CaseloadMoveRequest, CaseloadPreviewQuery, CaseworkAction, CaseworkAuth,
    CaseworkClient as CoreClient, CaseworkClientConfig as CoreConfig, CaseworkClientError,
    ClockRecomputeApplyRequest, ClockRecomputeRequest, DecideRequest, DelegateRequest,
    HoldingsQuery, HolidaySetRevisionInput, HostedCancelRequest, HostedCreateRequest,
    HostedDecisionRequest, HostedNoteRequest, HostedPageQuery, HostedTerminalQuery,
    ListWorkItemsQuery, NextWorkItemQuery, RecoverAttemptRequest, SaveDraftRequest,
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
    pub async fn create_hosted_item(
        &self,
        token: String,
        profile: String,
        idempotency_key: String,
        request: Value,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let request: HostedCreateRequest = input(request)?;
        outcome(
            self.inner
                .create_hosted_item(
                    CaseworkAuth::new(&token, &profile),
                    &idempotency_key,
                    &request,
                )
                .await,
        )
    }

    #[napi]
    pub async fn get_hosted_item(
        &self,
        token: String,
        profile: String,
        item_id: String,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .get_hosted_item(CaseworkAuth::new(&token, &profile), uuid(&item_id)?)
                .await,
        )
    }

    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub async fn add_hosted_note(
        &self,
        token: String,
        profile: String,
        item_id: String,
        expected_revision: i64,
        idempotency_key: String,
        note: Value,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        let note: HostedNoteRequest = input(note)?;
        outcome(
            self.inner
                .add_hosted_note(
                    CaseworkAuth::new(&token, &profile),
                    uuid(&item_id)?,
                    expected_revision,
                    &idempotency_key,
                    &note,
                )
                .await,
        )
    }

    #[napi]
    pub async fn requester_hosted_notes(
        &self,
        token: String,
        profile: String,
        item_id: String,
        query: Option<Value>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let query: HostedPageQuery = query.map(input).transpose()?.unwrap_or_default();
        outcome(
            self.inner
                .requester_hosted_notes(
                    CaseworkAuth::new(&token, &profile),
                    uuid(&item_id)?,
                    &query,
                )
                .await,
        )
    }

    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub async fn cancel_hosted_item(
        &self,
        token: String,
        profile: String,
        item_id: String,
        expected_revision: i64,
        idempotency_key: String,
        cancellation: Value,
    ) -> Result<CaseworkOutcome> {
        safe_revision(expected_revision)?;
        let token = bearer(token)?;
        let cancellation: HostedCancelRequest = input(cancellation)?;
        outcome(
            self.inner
                .cancel_hosted_item(
                    CaseworkAuth::new(&token, &profile),
                    uuid(&item_id)?,
                    expected_revision,
                    &idempotency_key,
                    &cancellation,
                )
                .await,
        )
    }

    #[napi]
    pub async fn hosted_terminal_items(
        &self,
        token: String,
        profile: String,
        query: Option<Value>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let query: HostedTerminalQuery = query.map(input).transpose()?.unwrap_or_default();
        outcome(
            self.inner
                .hosted_terminal_items(CaseworkAuth::new(&token, &profile), &query)
                .await,
        )
    }

    #[napi]
    pub async fn list_hosted_work_items(
        &self,
        token: String,
        profile: String,
        query: Value,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let query: ListWorkItemsQuery = input(query)?;
        outcome(
            self.inner
                .list_hosted_work_items(CaseworkAuth::new(&token, &profile), &query)
                .await,
        )
    }

    #[napi]
    pub async fn get_hosted_work_item(
        &self,
        token: String,
        profile: String,
        item_id: String,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .get_hosted_work_item(CaseworkAuth::new(&token, &profile), uuid(&item_id)?)
                .await,
        )
    }

    #[napi]
    pub async fn hosted_work_item_history(
        &self,
        token: String,
        profile: String,
        item_id: String,
        query: Option<Value>,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let query: HostedPageQuery = query.map(input).transpose()?.unwrap_or_default();
        outcome(
            self.inner
                .hosted_work_item_history(
                    CaseworkAuth::new(&token, &profile),
                    uuid(&item_id)?,
                    &query,
                )
                .await,
        )
    }

    #[napi]
    pub async fn hosted_accountability_record(
        &self,
        token: String,
        profile: String,
        event_id: String,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .hosted_accountability_record(CaseworkAuth::new(&token, &profile), uuid(&event_id)?)
                .await,
        )
    }

    #[napi]
    pub async fn claim_hosted_work_item(
        &self,
        token: String,
        profile: String,
        action: Value,
        idempotency_key: String,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let action: CaseworkAction = input(action)?;
        outcome(
            self.inner
                .claim_hosted_work_item(
                    CaseworkAuth::new(&token, &profile),
                    &action,
                    &idempotency_key,
                )
                .await,
        )
    }

    #[napi]
    pub async fn release_hosted_work_item(
        &self,
        token: String,
        profile: String,
        action: Value,
        idempotency_key: String,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let action: CaseworkAction = input(action)?;
        outcome(
            self.inner
                .release_hosted_work_item(
                    CaseworkAuth::new(&token, &profile),
                    &action,
                    &idempotency_key,
                )
                .await,
        )
    }

    #[napi]
    pub async fn decide_hosted_work_item(
        &self,
        token: String,
        profile: String,
        action: Value,
        idempotency_key: String,
        decision: Value,
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        let action: CaseworkAction = input(action)?;
        let decision: HostedDecisionRequest = input(decision)?;
        outcome(
            self.inner
                .decide_hosted_work_item(
                    CaseworkAuth::new(&token, &profile),
                    &action,
                    &idempotency_key,
                    &decision,
                )
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
    ) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .work_item_history(auth(&token, &profile, &source_profile), uuid(&item_id)?)
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
    pub async fn absences(&self, token: String, profile: String) -> Result<CaseworkOutcome> {
        let token = bearer(token)?;
        outcome(
            self.inner
                .absences(CaseworkAuth::new(&token, &profile))
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

fn ensure_safe_integers(value: &Value) -> Result<()> {
    match value {
        Value::Number(number)
            if number.as_i64().is_some_and(|value| {
                value.unsigned_abs() > MAXIMUM_JAVASCRIPT_SAFE_INTEGER as u64
            }) || number
                .as_u64()
                .is_some_and(|value| value > MAXIMUM_JAVASCRIPT_SAFE_INTEGER as u64) =>
        {
            return Err(binding_error(
                "protocol",
                "Casework returned an integer outside the JavaScript safe range",
            ));
        }
        Value::Number(_) => {}
        Value::Array(values) => {
            for value in values {
                ensure_safe_integers(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                ensure_safe_integers(value)?;
            }
        }
        _ => {}
    }
    Ok(())
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
            "protocolFailure": format!("{failure:?}").to_ascii_lowercase(),
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
}

// SPDX-License-Identifier: Apache-2.0

//! The Casework client, reached only through the facade.
//!
//! A caller who depends on this crate alone must be able to name every type a
//! Casework method takes and returns. The signatures below are compiled, never
//! run: a type the facade does not re-export cannot be named here, so the
//! build fails rather than the caller's. The catalogue test then holds the
//! re-export list level with the client's own public surface in both
//! directions, so a name added to the client reaches the facade too.

use std::collections::BTreeSet;

use registry_stack_client::casework::{
    AbsenceInput, AbsenceList, AbsenceRecord, AbsencesQuery, AssignmentRequest, BearerToken,
    BootstrapDirectoryRequest, CaseloadApplyRequest, CaseloadItemResult, CaseloadMoveRequest,
    CaseloadPreviewPage, CaseloadPreviewQuery, CaseworkAction, CaseworkAuth, CaseworkClient,
    CaseworkClientConfig, CaseworkClientError, CaseworkComplete, ClockOccurrenceView,
    ClockRecomputeApplyRequest, ClockRecomputePreview, ClockRecomputeRequest, ClockRecomputeResult,
    DecideRequest, DelegateRequest, Description, DirectoryResponse, DirectoryTargetPage,
    DirectoryTargetsQuery, DirectoryTeamUpdateRequest, DraftResponse, HistoryPage, HoldingsPage,
    HoldingsQuery, HolidaySetDocument, HolidaySetRevisionInput, ListWorkItemsQuery,
    MutationResponse, NextWorkItemQuery, RecoverAttemptRequest, ReviewAccountabilityRecord,
    ReviewCancelRequest, ReviewCancelResponse, ReviewCreateRequest, ReviewHistoryEntry,
    ReviewHistoryPage, ReviewKindPolicySnapshot, ReviewNoteRequest, ReviewPageQuery,
    ReviewRequestAccepted, ReviewRequestView, ReviewResultFeedPage, ReviewTaskContext,
    ReviewTaskDecisionRequest, ReviewTaskDraft, ReviewTaskDraftInput, ReviewTaskPage,
    ReviewTaskQuery, ReviewerTask, SaveDraftRequest, SubmissionDigest, Uuid, WorkItem,
    WorkItemHistoryQuery, WorkItemPage,
};

/// The client's public surface, read from the crate that publishes it.
const CLIENT_SOURCE: &str = include_str!("../../registry-casework-client/src/lib.rs");

/// The facade's own source, read to compare the two lists as written.
const FACADE_SOURCE: &str = include_str!("../src/lib.rs");

/// Every Casework method, with its parameter and return types named through
/// the facade alone. Each call takes its own authentication, because one
/// `CaseworkAuth` authenticates exactly one request.
#[allow(clippy::too_many_arguments)]
async fn every_casework_method_names_its_types(
    config: CaseworkClientConfig,
    token: &BearerToken,
    profile: &str,
    item_id: Uuid,
    attempt_id: Uuid,
    event_id: Uuid,
    absence_id: Uuid,
    team_id: &str,
    holiday_set: &str,
    holiday_revision_number: u64,
    expected_revision: i64,
    idempotency_key: &str,
    action: &CaseworkAction,
    review_create: &ReviewCreateRequest,
    expected_submission_digest: &SubmissionDigest,
    review_accepted: &ReviewRequestAccepted,
    review_cancel: &ReviewCancelRequest,
    review_note: &ReviewNoteRequest,
    review_decision: &ReviewTaskDecisionRequest,
    review_draft: &ReviewTaskDraftInput,
    review_page: &ReviewPageQuery,
    work_item_history_query: &WorkItemHistoryQuery,
    review_task_query: &ReviewTaskQuery,
    list_query: &ListWorkItemsQuery,
    next_query: &NextWorkItemQuery,
    draft: &SaveDraftRequest,
    decision: &DecideRequest,
    recovery: &RecoverAttemptRequest,
    holdings_query: &HoldingsQuery,
    targets_query: &DirectoryTargetsQuery,
    bootstrap: &BootstrapDirectoryRequest,
    absence: &AbsenceInput,
    absences_query: &AbsencesQuery,
    assignment: &AssignmentRequest,
    delegation: &DelegateRequest,
    caseload_move: &CaseloadMoveRequest,
    caseload_preview: &CaseloadPreviewQuery,
    caseload_apply: &CaseloadApplyRequest,
    team_update: &DirectoryTeamUpdateRequest,
    holiday_input: &HolidaySetRevisionInput,
    recompute: &ClockRecomputeRequest,
    recompute_apply: &ClockRecomputeApplyRequest,
) -> Result<(), CaseworkClientError> {
    let client: CaseworkClient = CaseworkClient::new(config)?;
    let _: CaseworkComplete<Description> = client
        .description(CaseworkAuth::new(token, profile))
        .await?;
    let _: CaseworkComplete<ReviewRequestAccepted> = client
        .create_or_recover_review_request(
            CaseworkAuth::new(token, profile),
            idempotency_key,
            review_create,
            expected_submission_digest,
        )
        .await?;
    let _: CaseworkComplete<ReviewRequestView> = client
        .review_request(CaseworkAuth::new(token, profile), item_id)
        .await?;
    let _ = client
        .review_result(CaseworkAuth::new(token, profile), review_accepted)
        .await?;
    let _: CaseworkComplete<ReviewResultFeedPage> = client
        .review_results(CaseworkAuth::new(token, profile), review_page)
        .await?;
    let _: CaseworkComplete<ReviewCancelResponse> = client
        .cancel_review_request(
            CaseworkAuth::new(token, profile),
            item_id,
            idempotency_key,
            review_cancel,
        )
        .await?;
    let _: CaseworkComplete<Vec<ReviewKindPolicySnapshot>> = client
        .review_kinds(CaseworkAuth::new(token, profile))
        .await?;
    let _: CaseworkComplete<ReviewKindPolicySnapshot> = client
        .review_kind(CaseworkAuth::new(token, profile), "payment")
        .await?;
    let _: CaseworkComplete<ReviewTaskPage> = client
        .review_tasks(CaseworkAuth::new(token, profile), review_task_query)
        .await?;
    let _: CaseworkComplete<ReviewerTask> = client
        .review_task(CaseworkAuth::new(token, profile), item_id)
        .await?;
    let _: CaseworkComplete<ReviewTaskContext> = client
        .review_task_context(CaseworkAuth::new(token, profile), item_id)
        .await?;
    let _: CaseworkComplete<ReviewerTask> = client
        .claim_review_task(
            CaseworkAuth::new(token, profile),
            item_id,
            expected_revision,
            idempotency_key,
        )
        .await?;
    let _: CaseworkComplete<ReviewerTask> = client
        .release_review_task(
            CaseworkAuth::new(token, profile),
            item_id,
            expected_revision,
            idempotency_key,
        )
        .await?;
    let _: CaseworkComplete<ReviewerTask> = client
        .assign_review_task(
            CaseworkAuth::new(token, profile),
            item_id,
            expected_revision,
            idempotency_key,
            assignment,
        )
        .await?;
    let _: CaseworkComplete<ReviewerTask> = client
        .delegate_review_task(
            CaseworkAuth::new(token, profile),
            item_id,
            expected_revision,
            idempotency_key,
            delegation,
        )
        .await?;
    let _: CaseworkComplete<Option<ReviewTaskDraft>> = client
        .review_task_draft(CaseworkAuth::new(token, profile), item_id)
        .await?;
    let _: CaseworkComplete<ReviewTaskDraft> = client
        .save_review_task_draft(
            CaseworkAuth::new(token, profile),
            item_id,
            expected_revision,
            idempotency_key,
            review_draft,
        )
        .await?;
    let _: CaseworkComplete<()> = client
        .delete_review_task_draft(
            CaseworkAuth::new(token, profile),
            item_id,
            expected_revision,
            idempotency_key,
        )
        .await?;
    let _: CaseworkComplete<()> = client
        .decide_review_task(
            CaseworkAuth::new(token, profile),
            item_id,
            expected_revision,
            idempotency_key,
            review_decision,
        )
        .await?;
    let _: CaseworkComplete<ReviewHistoryPage> = client
        .review_history(CaseworkAuth::new(token, profile), item_id, review_page)
        .await?;
    let _: CaseworkComplete<ReviewHistoryEntry> = client
        .add_review_note(
            CaseworkAuth::new(token, profile),
            item_id,
            idempotency_key,
            review_note,
        )
        .await?;
    let _: CaseworkComplete<Vec<registry_casework_client::ReviewClockOccurrence>> = client
        .review_clocks(CaseworkAuth::new(token, profile), item_id)
        .await?;
    let _: CaseworkComplete<ReviewAccountabilityRecord> = client
        .review_accountability(CaseworkAuth::new(token, profile), event_id)
        .await?;
    let _: CaseworkComplete<WorkItemPage> = client
        .list_work_items(CaseworkAuth::new(token, profile), list_query)
        .await?;
    let _: CaseworkComplete<WorkItemPage> = client
        .next_work_item(CaseworkAuth::new(token, profile), next_query)
        .await?;
    let _: CaseworkComplete<WorkItem> = client
        .get_work_item(CaseworkAuth::new(token, profile), item_id)
        .await?;
    let _: CaseworkComplete<MutationResponse> = client
        .claim_work_item(CaseworkAuth::new(token, profile), action, idempotency_key)
        .await?;
    let _: CaseworkComplete<MutationResponse> = client
        .release_work_item(CaseworkAuth::new(token, profile), action, idempotency_key)
        .await?;
    let _: CaseworkComplete<DraftResponse> = client
        .get_draft(CaseworkAuth::new(token, profile), item_id)
        .await?;
    let _: CaseworkComplete<DraftResponse> = client
        .save_draft(
            CaseworkAuth::new(token, profile),
            item_id,
            expected_revision,
            idempotency_key,
            draft,
        )
        .await?;
    let _: CaseworkComplete<()> = client
        .delete_draft(
            CaseworkAuth::new(token, profile),
            item_id,
            expected_revision,
            idempotency_key,
        )
        .await?;
    let _: CaseworkComplete<MutationResponse> = client
        .decide_work_item(
            CaseworkAuth::new(token, profile),
            action,
            idempotency_key,
            decision,
        )
        .await?;
    let _: CaseworkComplete<MutationResponse> = client
        .recover_decision(
            CaseworkAuth::new(token, profile),
            item_id,
            attempt_id,
            recovery,
        )
        .await?;
    let _: CaseworkComplete<MutationResponse> = client
        .recover_decision_by_key(
            CaseworkAuth::new(token, profile),
            item_id,
            idempotency_key,
            recovery,
        )
        .await?;
    let _: CaseworkComplete<HistoryPage> = client
        .work_item_history(
            CaseworkAuth::new(token, profile),
            item_id,
            work_item_history_query,
        )
        .await?;
    let _: CaseworkComplete<HoldingsPage> = client
        .holdings(CaseworkAuth::new(token, profile), holdings_query)
        .await?;
    let _: CaseworkComplete<DirectoryResponse> =
        client.directory(CaseworkAuth::new(token, profile)).await?;
    let _: CaseworkComplete<DirectoryTargetPage> = client
        .directory_targets(CaseworkAuth::new(token, profile), targets_query)
        .await?;
    let _: CaseworkComplete<DirectoryResponse> = client
        .bootstrap_directory(
            CaseworkAuth::new(token, profile),
            expected_revision,
            idempotency_key,
            bootstrap,
        )
        .await?;
    let _: CaseworkComplete<AbsenceList> =
        client.absences(CaseworkAuth::new(token, profile)).await?;
    let _: CaseworkComplete<AbsenceList> = client
        .absences_page(CaseworkAuth::new(token, profile), absences_query)
        .await?;
    let _: CaseworkComplete<AbsenceRecord> = client
        .create_absence(
            CaseworkAuth::new(token, profile),
            expected_revision,
            idempotency_key,
            absence,
        )
        .await?;
    let _: CaseworkComplete<AbsenceRecord> = client
        .update_absence(
            CaseworkAuth::new(token, profile),
            absence_id,
            expected_revision,
            idempotency_key,
            absence,
        )
        .await?;
    let _: CaseworkComplete<()> = client
        .delete_absence(
            CaseworkAuth::new(token, profile),
            absence_id,
            expected_revision,
            idempotency_key,
        )
        .await?;
    let _: CaseworkComplete<MutationResponse> = client
        .assign_work_item(
            CaseworkAuth::new(token, profile),
            item_id,
            expected_revision,
            idempotency_key,
            assignment,
        )
        .await?;
    let _: CaseworkComplete<MutationResponse> = client
        .delegate_work_item(
            CaseworkAuth::new(token, profile),
            item_id,
            expected_revision,
            idempotency_key,
            delegation,
        )
        .await?;
    let _: CaseworkComplete<CaseloadPreviewPage> = client
        .preview_caseload_move(
            CaseworkAuth::new(token, profile),
            caseload_move,
            caseload_preview,
        )
        .await?;
    let _: CaseworkComplete<Vec<CaseloadItemResult>> = client
        .apply_caseload_move(
            CaseworkAuth::new(token, profile),
            idempotency_key,
            caseload_apply,
        )
        .await?;
    let _: CaseworkComplete<DirectoryResponse> = client
        .update_directory_team(
            CaseworkAuth::new(token, profile),
            team_id,
            expected_revision,
            idempotency_key,
            team_update,
        )
        .await?;
    let _: CaseworkComplete<Vec<ClockOccurrenceView>> = client
        .work_item_clocks(CaseworkAuth::new(token, profile), item_id)
        .await?;
    let _: CaseworkComplete<HolidaySetDocument> = client
        .holiday_revision(
            CaseworkAuth::new(token, profile),
            holiday_set,
            holiday_revision_number,
        )
        .await?;
    let _: CaseworkComplete<HolidaySetDocument> = client
        .create_holiday_revision(
            CaseworkAuth::new(token, profile),
            idempotency_key,
            holiday_input,
        )
        .await?;
    let _: CaseworkComplete<ClockRecomputePreview> = client
        .preview_clock_recompute(CaseworkAuth::new(token, profile), recompute)
        .await?;
    let _: CaseworkComplete<ClockRecomputeResult> = client
        .apply_clock_recompute(
            CaseworkAuth::new(token, profile),
            idempotency_key,
            recompute_apply,
        )
        .await?;
    Ok(())
}

/// Every name one `pub use` statement publishes, whether braced or single.
fn published_names(statement: &str) -> Vec<String> {
    if let Some(open) = statement.find('{') {
        let close = statement
            .rfind('}')
            .unwrap_or_else(|| panic!("a re-export opens a brace it never closes: {statement}"));
        return statement[open + 1..close]
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(ToOwned::to_owned)
            .collect();
    }
    let name = statement
        .rsplit("::")
        .next()
        .unwrap_or_else(|| panic!("a re-export names nothing: {statement}"))
        .trim();
    vec![name.to_owned()]
}

/// Every name a source re-exports with `pub use`, refusing a glob because a
/// glob hides the names this test compares.
fn re_exported_names(source: &str, publisher: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for (index, _) in source.match_indices("pub use ") {
        let rest = &source[index + "pub use ".len()..];
        let end = rest
            .find(';')
            .unwrap_or_else(|| panic!("{publisher} opens a re-export it never ends"));
        let statement = &rest[..end];
        for name in published_names(statement) {
            assert_ne!(
                name, "*",
                "{publisher} re-exports {statement} as a glob, so this test cannot read its names"
            );
            assert!(
                names.insert(name.clone()),
                "{publisher} re-exports {name} twice"
            );
        }
    }
    names
}

/// The body of the facade's Casework module, so re-exports of other products
/// are not read as Casework names.
fn facade_casework_module() -> &'static str {
    let start = FACADE_SOURCE
        .find("pub mod casework {")
        .expect("the facade carries a casework module");
    let body = &FACADE_SOURCE[start..];
    let end = body
        .find("\n}\n")
        .expect("the facade's casework module is never closed");
    &body[..end]
}

#[test]
fn the_facade_names_every_casework_method_signature() {
    // Naming the function is what keeps the signatures above compiled; calling
    // one would need a Casework service.
    let _ = every_casework_method_names_its_types;
}

#[test]
fn the_facade_re_exports_every_public_client_name() {
    let client = re_exported_names(CLIENT_SOURCE, "crates/registry-casework-client");
    let facade = re_exported_names(facade_casework_module(), "the facade's casework module");
    for name in &client {
        assert!(
            facade.contains(name),
            "the facade is behind the client: casework::{name} cannot be named through it"
        );
    }
    for name in &facade {
        assert!(
            client.contains(name),
            "the facade is ahead of the client: casework::{name} is not a public client name"
        );
    }
}

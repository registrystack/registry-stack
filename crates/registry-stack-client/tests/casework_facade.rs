// SPDX-License-Identifier: Apache-2.0
//! The Casework surface can be reached and named solely through the facade.
use registry_stack_client::casework::*;
use std::collections::BTreeSet;
const CLIENT_SOURCE: &str = include_str!("../../registry-casework-client/src/lib.rs");
const FACADE_SOURCE: &str = include_str!("../src/lib.rs");
#[allow(dead_code, clippy::too_many_arguments)]
async fn every_casework_method_names_its_types(
    client: &CaseworkClient,
    token: &BearerToken,
    profile: &str,
    reader_policy: &str,
    task_id: Uuid,
    request_id: Uuid,
    event_id: Uuid,
    revision: i64,
    key: &str,
    admission: &ReviewCreateRequest,
    digest: &SubmissionDigest,
    accepted: &ReviewRequestAccepted,
    cancel: &ReviewCancelRequest,
    staffing: &ReviewStaffingQuery,
    page: &ReviewPageQuery,
    assignment: &AssignmentRequest,
    delegation: &DelegateRequest,
    draft: &ReviewTaskDraftInput,
    decision: &ReviewTaskDecisionRequest,
    move_request: &ReviewCaseloadMoveRequest,
    move_apply: &ReviewCaseloadApplyRequest,
    clock_request: &ReviewClockRecomputeRequest,
    clock_apply: &ReviewClockRecomputeApplyRequest,
) -> Result<(), CaseworkClientError> {
    let auth = || CaseworkAuth::new(token, profile);
    let delegated_auth =
        || DelegatedStaffReadAuth::new(token, reader_policy).with_source_profile(profile);
    let _: CaseworkComplete<Description> = client.description(auth()).await?;
    let _: CaseworkComplete<Vec<ReviewPolicyClosure>> = client.review_policies(auth()).await?;
    let _: CaseworkComplete<ReviewPolicyClosure> = client.review_policy(auth(), "review").await?;
    let _: CaseworkComplete<ReviewRequestAccepted> = client
        .create_or_recover_review_request(auth(), key, admission, digest)
        .await?;
    let _: CaseworkComplete<ReviewRequestView> = client.review_request(auth(), request_id).await?;
    let _: ReviewResultResponse = client.review_result(auth(), accepted).await?;
    let _: CaseworkComplete<ReviewResultFeedPage> = client.review_results(auth(), page).await?;
    let _: CaseworkComplete<ReviewCancelResponse> = client
        .cancel_review_request(auth(), accepted, key, cancel)
        .await?;
    let _: CaseworkComplete<ReviewTaskPage> = client.review_tasks(auth(), staffing).await?;
    let _: CaseworkComplete<Option<ReviewTask>> = client.next_review_task(auth(), staffing).await?;
    let _: CaseworkComplete<ReviewTaskPage> = client.review_task_holdings(auth(), staffing).await?;
    let _: CaseworkComplete<ReviewTask> = client.review_task(auth(), task_id).await?;
    let _: CaseworkComplete<ReviewTaskContext> =
        client.review_task_context(auth(), task_id).await?;
    let _: CaseworkComplete<ReviewTaskPage> = client
        .delegated_review_tasks(delegated_auth(), None, 10)
        .await?;
    let _: CaseworkComplete<ReviewTaskContext> = client
        .delegated_review_task_context(delegated_auth(), task_id)
        .await?;
    let _: CaseworkComplete<ReviewTask> = client
        .claim_review_task(auth(), task_id, revision, key)
        .await?;
    let _: CaseworkComplete<ReviewTask> = client
        .release_review_task(auth(), task_id, revision, key)
        .await?;
    let _: CaseworkComplete<ReviewTask> = client
        .assign_review_task(auth(), task_id, revision, key, assignment)
        .await?;
    let _: CaseworkComplete<ReviewTask> = client
        .delegate_review_task(auth(), task_id, revision, key, delegation)
        .await?;
    let _: CaseworkComplete<Option<ReviewTaskDraft>> =
        client.review_task_draft(auth(), task_id).await?;
    let _: CaseworkComplete<ReviewTaskDraft> = client
        .save_review_task_draft(auth(), task_id, revision, key, draft)
        .await?;
    let _: CaseworkComplete<()> = client
        .delete_review_task_draft(auth(), task_id, revision, key)
        .await?;
    let _: CaseworkComplete<()> = client
        .decide_review_task(auth(), task_id, revision, key, decision)
        .await?;
    let _: CaseworkComplete<ReviewHistoryPage> =
        client.review_history(auth(), request_id, page).await?;
    let _: CaseworkComplete<Vec<ReviewClockOccurrence>> =
        client.review_clocks(auth(), request_id).await?;
    let _: CaseworkComplete<ReviewAccountabilityRecord> =
        client.review_accountability(auth(), event_id).await?;
    let _: CaseworkComplete<ReviewCaseloadPreview> =
        client.preview_caseload_move(auth(), move_request).await?;
    let _: CaseworkComplete<ReviewCaseloadResult> =
        client.apply_caseload_move(auth(), key, move_apply).await?;
    let _: CaseworkComplete<ReviewClockRecomputePreview> = client
        .preview_clock_recompute(auth(), clock_request)
        .await?;
    let _: CaseworkComplete<ReviewClockRecomputeResult> = client
        .apply_clock_recompute(auth(), key, clock_apply)
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

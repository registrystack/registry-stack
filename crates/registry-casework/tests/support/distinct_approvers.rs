// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
async fn second_approval_claim_names_distinct_approver_rule_without_membership_disclosure() {
    let idp = MockIdp::start().await;
    let mut policy = project(&idp.issuer());
    policy.review_policies[0].stages[0].required_approvals = 2;
    let (app, _, _, _, _, _, database) = app_with_project(&idp, policy).await;
    let request = review_request_for_subject("distinct-canary", "distinct-canary", &idp.issuer());
    let (accepted, first) = create_task(&app, &database, &idp, &request).await;
    let second: Uuid = database
        .query_one(
            "SELECT task_id FROM casework_review_tasks WHERE request_id=$1 AND task_id<>$2",
            &[&accepted.request_id, &first],
        )
        .await
        .unwrap()
        .get(0);
    let (client, server) = native_review_client(app.clone()).await;
    let reviewer = human_token(&idp, "reviewer", "staff");
    let auth = || CaseworkAuth::new(&reviewer, "staff").with_source_profile("reviewer-source");
    let held = client
        .claim_review_task(auth(), first, 1, "claim-distinct-first")
        .await
        .unwrap()
        .value;
    client
        .decide_review_task(
            auth(),
            first,
            held.revision,
            "approve-distinct-first",
            &registry_casework_client::ReviewTaskDecisionRequest {
                decision: DecisionKind::Approve {
                    outcome: "approved".into(),
                    public_reason: None,
                },
            },
        )
        .await
        .unwrap();

    let refused = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/review-tasks/{second}/claim"))
                .header("authorization", format!("Bearer {}", reviewer_token(&idp)))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .header("if-match", "\"1\"")
                .header("idempotency-key", "claim-distinct-second")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(refused.into_body(), 32768).await.unwrap();
    let problem: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem["code"], "review.distinct-approver-required");
    let text = String::from_utf8(body.to_vec()).unwrap();
    for private in ["colleague", "review-team", "distinct-canary"] {
        assert!(
            !text.contains(private),
            "refusal disclosed private membership or source data"
        );
    }
    let colleague = human_token(&idp, "colleague", "staff");
    client
        .claim_review_task(
            CaseworkAuth::new(&colleague, "staff").with_source_profile("reviewer-source"),
            second,
            1,
            "claim-distinct-colleague",
        )
        .await
        .expect("a different eligible reviewer can claim the remaining slot");
    server.abort();
    idp.stop().await;
}

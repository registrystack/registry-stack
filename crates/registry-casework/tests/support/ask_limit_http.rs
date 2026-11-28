// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
async fn the_ask_limit_is_a_conflict_problem_without_changing_the_task() {
    let idp = MockIdp::start().await;
    let project = asks_http_project(&idp);
    let (app, _, _, _, _, _, database) = app_with_project(&idp, project).await;
    let mut input =
        review_request_for_subject("ask-limit-http", "ask-limit-http-ref", &idp.issuer());
    input.context = ReviewContext::Submitted {
        snapshot: json!({"summary":"Ask limit"}),
    };
    let (created, task) = create_task(&app, &database, &idp, &input).await;
    let reviewer = reviewer_token(&idp);
    claim_task_over_http(&app, task, &reviewer, "claim").await;
    let ids = (0..50).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    database.execute("INSERT INTO casework_review_asks(ask_id,request_id,task_id,stage_index,text,wants,state,asked_at,asked_by_ref,closed_at) SELECT x,$1,$2,0,'Earlier ask','[]','closed',transaction_timestamp()-interval '1 hour','synthetic-reviewer',transaction_timestamp() FROM unnest($3::uuid[]) x",&[&created.request_id,&task,&ids]).await.unwrap();
    database.execute("UPDATE casework_review_asks SET state='expired',due_at=transaction_timestamp()-interval '1 minute' WHERE ask_id=$1",&[&ids[0]]).await.unwrap();
    let staff = vec![
        ("authorization", format!("Bearer {reviewer}")),
        (CASEWORK_PROFILE_HEADER, "staff".into()),
    ];
    let uri = format!("/v1/review-tasks/{task}");
    let before = http_json(&app, "GET", uri.clone(), &staff, None).await;
    assert_eq!(before.0, StatusCode::OK);
    let mut headers = staff.clone();
    headers.extend([
        ("if-match", "\"2\"".into()),
        ("idempotency-key", "ask-51".into()),
    ]);
    let response = http_json(
        &app,
        "POST",
        format!("{uri}/asks"),
        &headers,
        Some(json!({"text":"Why?","wants":[]})),
    )
    .await;
    assert_eq!(response.0, StatusCode::CONFLICT);
    let problem: Value = serde_json::from_slice(&response.2).unwrap();
    assert_eq!(problem["code"], "review.ask-limit-reached");
    assert_eq!(
        problem["type"],
        "https://id.registrystack.org/problems/registry-casework/review/ask-limit-reached"
    );
    assert_eq!(problem["title"], "Review ask limit reached");
    assert_eq!(problem["detail"],"This review request has reached its limit of 50 asks. Continue the review without opening another ask.");
    assert_eq!(http_json(&app, "GET", uri, &staff, None).await.2, before.2);
    assert_eq!(
        database
            .query_one(
                "SELECT count(*) FROM casework_review_asks WHERE request_id=$1",
                &[&created.request_id]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        50
    );
}

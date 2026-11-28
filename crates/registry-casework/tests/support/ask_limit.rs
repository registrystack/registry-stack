// SPDX-License-Identifier: Apache-2.0
use super::*;

async fn mutation_state(fixture: &Fixture, request: Uuid) -> serde_json::Value {
    fixture.database.query_one(
        "SELECT jsonb_build_object(
            'request',to_jsonb(r),
            'tasks',(SELECT jsonb_agg(to_jsonb(t) ORDER BY task_id) FROM casework_review_tasks t WHERE request_id=$1),
            'clocks',(SELECT jsonb_agg(to_jsonb(c) ORDER BY clock_occurrence_id) FROM casework_review_clock_occurrences c WHERE request_id=$1),
            'asks',(SELECT count(*) FROM casework_review_asks WHERE request_id=$1),
            'events',(SELECT count(*) FROM casework_review_ask_events WHERE request_id=$1),
            'history',(SELECT count(*) FROM casework_review_history WHERE request_id=$1),
            'idempotency',(SELECT count(*) FROM casework_idempotency WHERE resource LIKE '%' || $1::text || '%' OR resource IN (SELECT 'review-task:' || task_id::text FROM casework_review_tasks WHERE request_id=$1))
        ) FROM casework_review_requests r WHERE request_id=$1",
        &[&request]).await.unwrap().get(0)
}

#[tokio::test]
async fn the_fifty_first_ask_is_refused_before_state_or_clocks_change() {
    let fixture = fixture().await;
    let service = timed_asks_service(&fixture, true);
    let (request, task, create) = claimed_for_asks(&fixture, &service, "ask-limit").await;
    let mut revision = 2;
    let mut last = None;
    for index in 0..50 {
        let expected = revision;
        let asked = service
            .ask_applicant(
                &fixture.reviewer_a,
                task,
                ask_request("Why?"),
                None,
                "",
                expected,
                &format!("ask-{index}"),
            )
            .await
            .unwrap();
        revision = asked.task.revision;
        service
            .answer_review_ask(
                &fixture.producer,
                request,
                asked.ask.ask_id,
                ReviewAskAnswer {
                    subject: create.subject.clone(),
                    answered_at: asked.ask.asked_at,
                },
                &format!("answer-{index}"),
            )
            .await
            .unwrap();
        revision += 1;
        last = Some((expected, asked));
    }
    assert_eq!(ask_states(&fixture, request).await.len(), 50);
    let before = mutation_state(&fixture, request).await;
    assert_eq!(before["clocks"].as_array().unwrap().len(), 1);
    assert_eq!(before["clocks"][0]["state"], "running");
    let refused = service
        .ask_applicant(
            &fixture.reviewer_a,
            task,
            ask_request("One too many"),
            None,
            "",
            revision,
            "ask-51",
        )
        .await;
    assert!(refused.is_err(), "the fifty-first ask must be refused");
    assert_eq!(
        format!("{:?}", refused.unwrap_err()),
        "ReviewAskLimitReached"
    );
    assert_eq!(
        mutation_state(&fixture, request).await,
        before,
        "a refused ask changes no request, task, clock, feed, history or idempotency state"
    );
    let (expected, last) = last.unwrap();
    let replay = service
        .ask_applicant(
            &fixture.reviewer_a,
            task,
            ask_request("Why?"),
            None,
            "",
            expected,
            "ask-49",
        )
        .await
        .unwrap();
    assert_eq!(
        replay, last,
        "the limit does not spend or block an earlier successful key"
    );
    assert_eq!(mutation_state(&fixture, request).await, before);
    let (_, other, _) = claimed_for_asks(&fixture, &service, "another-ask-limit").await;
    assert!(
        service
            .ask_applicant(
                &fixture.reviewer_a,
                other,
                ask_request("First ask"),
                None,
                "",
                2,
                "another-first"
            )
            .await
            .is_ok(),
        "the cap belongs to the request"
    );
}

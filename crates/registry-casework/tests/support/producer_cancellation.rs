// SPDX-License-Identifier: Apache-2.0
//! Producer cancellation settles concealed work through the existing authority.
use super::*;

#[tokio::test]
async fn producer_cancellation_settles_concealed_tasks_and_clocks_without_source_reads() {
    let idp = MockIdp::start().await;
    let mut policy = project(&idp.issuer());
    policy.calendars = vec![CalendarPolicy {
        id: "office".into(),
        timezone: "UTC".into(),
        holiday_set: "office-holidays".into(),
        working_weekdays: vec![
            WorkingWeekday::Monday,
            WorkingWeekday::Tuesday,
            WorkingWeekday::Wednesday,
            WorkingWeekday::Thursday,
            WorkingWeekday::Friday,
            WorkingWeekday::Saturday,
            WorkingWeekday::Sunday,
        ],
    }];
    policy.clocks = vec![ClockPolicy::Stage {
        id: "review-deadline".into(),
        anchor: StageClockAnchor {
            kind: StageClockAnchorType::StageEntered,
        },
        calendar: "office".into(),
        after: WorkingDays { working_days: 1 },
        due_time: "17:00".into(),
        at_risk: None,
        reminders: vec![],
        steps: vec![],
    }];
    policy.review_policies[0].clocks = vec!["review-deadline".into()];
    let (app, service, revoked, _, failure, _, database) = app_with_project(&idp, policy).await;
    service
        .create_holiday_revision(
            &ActorContext {
                principal: IssuerPrincipal {
                    issuer: idp.issuer(),
                    subject: "administrator".into(),
                },
                profile_id: "administrator".into(),
                role: CaseworkRole::Administrator,
            },
            &HolidaySetDocument {
                holiday_set: "office-holidays".into(),
                revision: 1,
                dates: vec![],
            },
            "holiday-canary",
        )
        .await
        .unwrap();
    let request = review_request("activation-cancellation-canary", &idp.issuer());
    let (accepted, task) = create_task(&app, &database, &idp, &request).await;
    let clocks = database
        .query(
            "SELECT state FROM casework_review_clock_occurrences WHERE request_id=$1",
            &[&accepted.request_id],
        )
        .await
        .unwrap();
    assert_eq!(clocks.len(), 1);
    assert_eq!(clocks[0].get::<_, String>(0), "running");
    let (client, server) = native_review_client(app).await;
    revoked.store(true, Ordering::SeqCst);
    let reviewer = human_token(&idp, "reviewer", "staff");
    assert_client_status(
        client
            .review_task(
                CaseworkAuth::new(&reviewer, "staff").with_source_profile("reviewer-source"),
                task,
            )
            .await
            .expect_err("concealed task stays unavailable to reviewers"),
        404,
    );
    let supervisor = human_token(&idp, "supervisor", "supervisor");
    let page = client
        .supervisory_review_tasks(
            CaseworkAuth::new(&supervisor, "supervisor").with_source_profile("reviewer-source"),
            &SupervisoryReviewTaskQuery {
                request_id: Some(accepted.request_id),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .value;
    assert!(
        page.items.is_empty(),
        "producer cancellation grants no supervisor visibility"
    );

    // Any source call from this point fails the test. Cancellation must use
    // the admitted producer and retained exact binding alone.
    failure.store(3, Ordering::SeqCst);
    let cancellation = ReviewCancelRequest {
        subject: accepted.subject.clone(),
        reason: "source proposal blocked by package change".into(),
    };
    let other = BearerToken::new(idp.mint_token(
        json!({"aud":AUDIENCE,"registry_principal":"registry-service",
        "scope":"casework:producer-alternate","registry_actor_kind":"service"}),
    ))
    .unwrap();
    assert_client_status(
        client
            .cancel_review_request(
                CaseworkAuth::new(&other, "producer-alternate"),
                &accepted,
                "wrong-producer-canary",
                &cancellation,
            )
            .await
            .expect_err("another producer cannot cancel"),
        404,
    );
    let producer = BearerToken::new(token(&idp)).unwrap();
    let cancelled = client
        .cancel_review_request(
            CaseworkAuth::new(&producer, "producer"),
            &accepted,
            "cancel-package-change",
            &cancellation,
        )
        .await
        .unwrap()
        .value;
    let replay = client
        .cancel_review_request(
            CaseworkAuth::new(&producer, "producer"),
            &accepted,
            "cancel-package-change",
            &cancellation,
        )
        .await
        .unwrap()
        .value;
    assert_eq!(cancelled, replay);
    let ReviewCancelResponse::Cancelled { result } = cancelled else {
        panic!("producer cancellation settles the live review")
    };
    assert_eq!(result.status, ReviewResultStatus::Cancelled);
    assert!(result.result.is_none());
    assert!(result.public_reason.is_none());
    assert_eq!(
        database
            .query_one(
                "SELECT lifecycle FROM casework_review_requests WHERE request_id=$1",
                &[&accepted.request_id]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "cancelled"
    );
    let closed = database
        .query_one(
            "SELECT state,settled_at IS NOT NULL FROM casework_review_tasks WHERE task_id=$1",
            &[&task],
        )
        .await
        .unwrap();
    assert_eq!(closed.get::<_, String>(0), "closed");
    assert!(closed.get::<_, bool>(1));
    let clock = database.query_one("SELECT state,next_action_at IS NULL FROM casework_review_clock_occurrences WHERE request_id=$1", &[&accepted.request_id]).await.unwrap();
    assert_eq!(clock.get::<_, String>(0), "cancelled");
    assert!(clock.get::<_, bool>(1));
    assert_eq!(
        database
            .query_one(
                "SELECT count(*) FROM casework_review_results WHERE request_id=$1",
                &[&accepted.request_id]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    server.abort();
    idp.stop().await;
}

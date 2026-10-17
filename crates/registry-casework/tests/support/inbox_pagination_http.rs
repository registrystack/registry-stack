// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
async fn ordinary_http_inbox_pages_a_queue_larger_than_its_scan_budget() {
    for sort in ["due", "subject"] {
        let idp = MockIdp::start().await;
        let mut policy = project(&idp.issuer());
        policy.inbox.default_page_size = 2;
        policy.inbox.maximum_candidate_scan = 4;
        policy.inbox.maximum_source_reads = 4;
        let (app, _, _, _, _, _, database) = app_with_project(&idp, policy).await;
        let mut expected = Vec::new();
        for i in (0..9).rev() {
            let name = format!("ordinary-{i:02}");
            let body = review_request_for_subject(&name, &name, &idp.issuer());
            let (_, task) = create_task(&app, &database, &idp, &body).await;
            database.execute("UPDATE casework_review_tasks SET deadline_at=TIMESTAMPTZ '2030-01-01 00:00:00Z'+($2::bigint * interval '1 minute') WHERE task_id=$1", &[&task, &(i as i64)]).await.unwrap();
            expected.push(name);
        }
        expected.sort();
        let mut cursor = None;
        let mut seen = Vec::new();
        for _ in 0..10 {
            let mut uri = format!("/v1/review-tasks?sort={sort}&limit=2");
            if let Some(cursor) = cursor {
                uri.push_str(&format!("&cursor={cursor}"));
            }
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header("authorization", format!("Bearer {}", reviewer_token(&idp)))
                        .header(CASEWORK_PROFILE_HEADER, "staff")
                        .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "a broad ordinary queue is pageable"
            );
            let page: ReviewTaskPage =
                serde_json::from_slice(&to_bytes(response.into_body(), 32768).await.unwrap())
                    .unwrap();
            assert_eq!(page.status, PageStatus::Complete);
            assert!(!page.items.is_empty() && page.items.len() <= 2);
            seen.extend(page.items.into_iter().map(|task| task.subject.id));
            assert!(page.next_cursor.is_none() || page.next_cursor != cursor);
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert!(cursor.is_none());
        assert_eq!(seen, expected);
        idp.stop().await;
    }
}

#[tokio::test]
async fn live_reference_http_queries_keep_the_complete_scan_refusal() {
    let idp = MockIdp::start().await;
    let mut policy = project(&idp.issuer());
    policy.inbox.default_page_size = 1;
    policy.inbox.maximum_candidate_scan = 2;
    policy.inbox.maximum_source_reads = 2;
    let (app, _, _, _, _, _, database) = app_with_project(&idp, policy).await;
    for i in 0..4 {
        let name = format!("reference-canary-{i}");
        let body = review_request_for_subject(&name, &name, &idp.issuer());
        create_task(&app, &database, &idp, &body).await;
    }
    for query in ["sort=reference", "reference=reference-canary-3"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/review-tasks?limit=1&{query}"))
                    .header("authorization", format!("Bearer {}", reviewer_token(&idp)))
                    .header(CASEWORK_PROFILE_HEADER, "staff")
                    .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = to_bytes(response.into_body(), 32768).await.unwrap();
        let problem: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(problem["code"], "review.query-too-broad");
        assert!(!String::from_utf8(bytes.to_vec())
            .unwrap()
            .contains("reference-canary"));
    }
    idp.stop().await;
}

#[tokio::test]
async fn staffing_notice_counts_distinct_available_reviewers_without_exposing_members() {
    for sufficient in [false, true] {
        let idp = MockIdp::start().await;
        let mut policy = project(&idp.issuer());
        policy.review_policies[0].stages[0].required_approvals = 2;
        let (app, _, _, _, _, _, database) = app_with_project(&idp, policy).await;
        if !sufficient {
            database.execute("DELETE FROM casework_memberships WHERE subject='colleague' AND membership_kind='staff'", &[]).await.unwrap();
        }
        let body = review_request_for_subject("staffing-canary", "staffing-canary", &idp.issuer());
        let (accepted, task) = create_task(&app, &database, &idp, &body).await;
        let (client, server) = native_review_client(app).await;
        let supervisor = human_token(&idp, "supervisor", "supervisor");
        let auth =
            || CaseworkAuth::new(&supervisor, "supervisor").with_source_profile("reviewer-source");
        let staff = human_token(&idp, "reviewer", "staff");
        let staff_auth =
            || CaseworkAuth::new(&staff, "staff").with_source_profile("reviewer-source");
        let supervision = client
            .supervisory_review_tasks(
                auth(),
                &SupervisoryReviewTaskQuery {
                    request_id: Some(accepted.request_id),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .value;
        assert_eq!(
            supervision
                .items
                .iter()
                .find(|row| row.task_id == task)
                .unwrap()
                .staffing_diagnostic,
            (!sufficient).then_some(StaffingDiagnostic::InsufficientDistinctApprovers),
            "supervision derives the notice before any assignment"
        );
        let initial = client.review_task(staff_auth(), task).await.unwrap().value;
        assert_eq!(
            initial.staffing_diagnostic,
            (!sufficient).then_some(StaffingDiagnostic::InsufficientDistinctApprovers)
        );
        let assigned = client
            .assign_review_task(
                auth(),
                task,
                1,
                "staffing-count",
                &AssignmentRequest {
                    assignee: IssuerPrincipal {
                        issuer: idp.issuer(),
                        subject: "reviewer".into(),
                    },
                    reason: None,
                },
            )
            .await
            .unwrap()
            .value;
        let wire = serde_json::to_value(&assigned).unwrap();
        if sufficient {
            assert!(wire.get("staffingDiagnostic").is_none());
        } else {
            assert_eq!(
                wire["staffingDiagnostic"],
                "insufficient-distinct-approvers"
            );
        }
        let page = client
            .supervisory_review_tasks(
                auth(),
                &SupervisoryReviewTaskQuery {
                    request_id: Some(accepted.request_id),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .value;
        let row = page.items.iter().find(|row| row.task_id == task).unwrap();
        let wire = serde_json::to_value(row).unwrap();
        if !sufficient {
            assert_eq!(
                wire["staffingDiagnostic"],
                "insufficient-distinct-approvers"
            );
        }
        if !sufficient {
            database.execute("INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind)
                SELECT team_id,$1,'colleague','staff' FROM casework_queue_service WHERE queue_id='review'
                ON CONFLICT DO NOTHING", &[&idp.issuer()]).await.unwrap();
            let current = client.review_task(staff_auth(), task).await.unwrap().value;
            assert_eq!(
                current.staffing_diagnostic, None,
                "a current Directory repair clears the notice without another assignment"
            );
            let supervision = client
                .supervisory_review_tasks(
                    auth(),
                    &SupervisoryReviewTaskQuery {
                        request_id: Some(accepted.request_id),
                        ..Default::default()
                    },
                )
                .await
                .unwrap()
                .value;
            assert_eq!(
                supervision
                    .items
                    .iter()
                    .find(|row| row.task_id == task)
                    .unwrap()
                    .staffing_diagnostic,
                None,
                "the same Directory repair clears the supervisory notice"
            );
        }
        let text = wire.to_string();
        for private in ["reviewer", "colleague", "review-team", "staffing-canary"] {
            assert!(
                !text.contains(private),
                "supervisory notice must not disclose identities or source data"
            );
        }
        server.abort();
        idp.stop().await;
    }
}

#[tokio::test]
async fn staffing_notice_excludes_absent_people_and_the_initiator() {
    let idp = MockIdp::start().await;
    let mut policy = project(&idp.issuer());
    policy.review_policies[0].stages[0].required_approvals = 2;
    let (app, _, _, _, _, _, database) = app_with_project(&idp, policy).await;
    let body = review_request_for_subject(
        "eligible-staff-canary",
        "eligible-staff-canary",
        &idp.issuer(),
    );
    let (_, task) = create_task(&app, &database, &idp, &body).await;
    let (client, server) = native_review_client(app).await;
    let staff = human_token(&idp, "reviewer", "staff");
    let auth = || CaseworkAuth::new(&staff, "staff").with_source_profile("reviewer-source");
    assert_eq!(
        client
            .review_task(auth(), task)
            .await
            .unwrap()
            .value
            .staffing_diagnostic,
        None
    );
    database.execute("INSERT INTO casework_absences(absence_id,person_issuer,person_subject,starts_at,ends_at,cover_issuer,cover_subject,revision)
        VALUES($1,$2,'colleague',now()-interval '1 hour',now()+interval '1 hour',$2,'reviewer',1)",
        &[&Uuid::new_v4(),&idp.issuer()]).await.unwrap();
    database
        .execute(
            "INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind)
        VALUES('review-team',$1,'initiator','staff')",
            &[&idp.issuer()],
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .review_task(auth(), task)
            .await
            .unwrap()
            .value
            .staffing_diagnostic,
        Some(StaffingDiagnostic::InsufficientDistinctApprovers),
        "an absent reviewer and excluded initiator cannot supply the second approval"
    );
    database.batch_execute("UPDATE casework_absences SET starts_at=now()-interval '2 hours',ends_at=now()-interval '1 hour'").await.unwrap();
    assert_eq!(
        client
            .review_task(auth(), task)
            .await
            .unwrap()
            .value
            .staffing_diagnostic,
        None,
        "a returned reviewer restores sufficient staffing on the next read"
    );
    server.abort();
    idp.stop().await;
}

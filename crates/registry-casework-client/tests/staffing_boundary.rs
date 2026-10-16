//! ReviewTask staffing, pre-I/O refusal, and atomic preview handoffs.
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use registry_casework_client::*;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use url::Url;
const TRACE: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
type Seen = Arc<Mutex<Vec<(String, HeaderMap, Value)>>>;
fn task() -> Value {
    json!({"taskId":Uuid::from_u128(1),"requestId":Uuid::from_u128(2),"subject":{"source":"records","type":"proposal","id":"proposal-7","version":"3","digest":ContentDigest::for_bytes(b"proposal")},"requesterReference":"REF-7","displayReference":"REF-7","deadlineAt":"2026-10-20T00:00:00Z","createdAt":"2026-10-14T00:00:00Z","stageIndex":0,"stageId":"review","queue":"review","revision":3,"eligibleProfiles":["staff"],"state":{"held":{"holder":{"issuer":"https://issuer.example","subject":"staff-1"}}}})
}
async fn read(State(seen): State<Seen>, uri: Uri, headers: HeaderMap) -> impl IntoResponse {
    seen.lock()
        .unwrap()
        .push((uri.to_string(), headers, json!(null)));
    let mut selected = task();
    if uri
        .query()
        .is_some_and(|query| query.contains("ownership=unclaimed"))
    {
        selected["state"] = json!("open");
        selected["staffingDiagnostic"] = json!("no-cover-available");
    }
    let value = if uri.path().ends_with("next") {
        selected
    } else {
        json!({"items":[selected],"status":"complete"})
    };
    (
        StatusCode::OK,
        [("content-type", "application/json"), ("traceparent", TRACE)],
        value.to_string(),
    )
}
async fn mutate(
    State(seen): State<Seen>,
    uri: Uri,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> impl IntoResponse {
    seen.lock().unwrap().push((uri.to_string(), headers, body));
    let selected = json!({"taskId":Uuid::from_u128(1),"revision":3});
    let value = if uri.path().contains("caseload") {
        if uri.path().ends_with("preview") {
            json!({"previewId":Uuid::from_u128(9),"directoryRevision":4,"tasks":[selected],"expiresAt":"2026-10-14T01:00:00Z"})
        } else {
            json!({"moved":[selected]})
        }
    } else {
        let selected =
            json!({"taskId":Uuid::from_u128(1),"revision":4,"deadlineAt":"2026-10-20T00:00:00Z"});
        if uri.path().ends_with("preview") {
            json!({"previewId":Uuid::from_u128(10),"directoryRevision":4,"tasks":[selected],"expiresAt":"2026-10-14T01:00:00Z"})
        } else {
            json!({"tasks":[selected]})
        }
    };
    (
        StatusCode::OK,
        [("content-type", "application/json"), ("traceparent", TRACE)],
        value.to_string(),
    )
}
#[tokio::test]
async fn staffing_selectors_and_preview_ids_cross_the_exact_public_routes() {
    let seen = Seen::default();
    let app = Router::new()
        .route("/tenant/v1/review-tasks", get(read))
        .route("/tenant/v1/review-tasks/next", get(read))
        .route("/tenant/v1/review-tasks/holdings", get(read))
        .route("/tenant/v1/directory/caseload/preview", post(mutate))
        .route("/tenant/v1/directory/caseload/apply", post(mutate))
        .route(
            "/tenant/v1/directory/clocks/recompute/preview",
            post(mutate),
        )
        .route("/tenant/v1/directory/clocks/recompute/apply", post(mutate))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse(&format!("http://{address}/tenant")).unwrap(),
    ))
    .unwrap();
    let token = BearerToken::new("staff-token").unwrap();
    let auth = || CaseworkAuth::new(&token, "staff");
    let query = ReviewStaffingQuery {
        queue: Some("review".into()),
        ownership: Some(ReviewTaskOwnership::AssignedToMe),
        subject_source: Some("records".into()),
        subject_type: Some("proposal".into()),
        subject_id: Some("proposal-7".into()),
        subject_version: Some("3".into()),
        subject_digest: Some(ContentDigest::for_bytes(b"proposal")),
        reference: Some("REF-7".into()),
        sort: ReviewTaskSort::Reference,
        limit: Some(25),
        ..Default::default()
    };
    assert_eq!(
        client
            .review_tasks(auth(), &query)
            .await
            .unwrap()
            .value
            .items
            .len(),
        1
    );
    assert_eq!(
        client
            .next_review_task(auth(), &query)
            .await
            .unwrap()
            .value
            .unwrap()
            .task_id,
        Uuid::from_u128(1)
    );
    assert_eq!(
        client
            .review_task_holdings(auth(), &query)
            .await
            .unwrap()
            .value
            .items
            .len(),
        1
    );
    let movement = ReviewCaseloadMoveRequest {
        from: IssuerPrincipal {
            issuer: "https://issuer.example".into(),
            subject: "staff-1".into(),
        },
        to: IssuerPrincipal {
            issuer: "https://issuer.example".into(),
            subject: "staff-2".into(),
        },
        queue: Some("review".into()),
        reason: "Cover".into(),
    };
    let preview = client
        .preview_caseload_move(auth(), &movement)
        .await
        .unwrap()
        .value;
    assert_eq!(
        client
            .apply_caseload_move(
                auth(),
                "move-7",
                &ReviewCaseloadApplyRequest {
                    preview_id: preview.preview_id
                }
            )
            .await
            .unwrap()
            .value
            .moved
            .len(),
        1
    );
    let preview = client
        .preview_clock_recompute(
            auth(),
            &ReviewClockRecomputeRequest {
                task_ids: vec![Uuid::from_u128(1)],
            },
        )
        .await
        .unwrap()
        .value;
    assert_eq!(
        client
            .apply_clock_recompute(
                auth(),
                "clock-7",
                &ReviewClockRecomputeApplyRequest {
                    preview_id: preview.preview_id
                }
            )
            .await
            .unwrap()
            .value
            .tasks
            .len(),
        1
    );
    let blocked = client
        .review_tasks(
            auth(),
            &ReviewStaffingQuery {
                ownership: Some(ReviewTaskOwnership::Unclaimed),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        blocked.value.items[0].staffing_diagnostic,
        Some(StaffingDiagnostic::NoCoverAvailable)
    );
    let calls = seen.lock().unwrap();
    assert_eq!(calls.len(), 8);
    for (path, headers, _) in calls.iter() {
        assert!(path.starts_with("/tenant/v1/"));
        assert_eq!(headers["authorization"], "Bearer staff-token");
        assert_eq!(headers["registry-casework-profile"], "staff");
        assert!(!headers.contains_key("registry-source-profile"));
    }
    assert!(calls[0].0.contains("subjectVersion=3"));
    assert!(calls[0].0.contains("sort=reference"));
    assert_eq!(calls[4].2, json!({"previewId":Uuid::from_u128(9)}));
    assert_eq!(calls[4].1["idempotency-key"], "move-7");
    assert_eq!(calls[6].1["idempotency-key"], "clock-7");
    server.abort();
}
#[tokio::test]
async fn invalid_staffing_inputs_fail_before_io() {
    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse("http://127.0.0.1:1/").unwrap(),
    ))
    .unwrap();
    let token = BearerToken::new("token").unwrap();
    let auth = || CaseworkAuth::new(&token, "staff");
    let query = ReviewStaffingQuery {
        subject_id: Some("private-canary".into()),
        ..Default::default()
    };
    for result in [
        client.review_tasks(auth(), &query).await.map(|_| ()),
        client.next_review_task(auth(), &query).await.map(|_| ()),
        client
            .review_task_holdings(auth(), &query)
            .await
            .map(|_| ()),
        client
            .preview_clock_recompute(
                auth(),
                &ReviewClockRecomputeRequest {
                    task_ids: vec![Uuid::from_u128(1); 2],
                },
            )
            .await
            .map(|_| ()),
        client
            .apply_caseload_move(
                auth(),
                "move",
                &ReviewCaseloadApplyRequest {
                    preview_id: Uuid::nil(),
                },
            )
            .await
            .map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(CaseworkClientError::InvalidRequest { .. })
        ));
        assert!(!result.unwrap_err().to_string().contains("private-canary"));
    }
}

#[tokio::test]
async fn staffing_pages_refuse_duplicate_tasks_and_substituted_ordering() {
    for (sort, response) in [
        (
            ReviewTaskSort::Due,
            json!({"items":[task(),task()],"status":"complete"}),
        ),
        (ReviewTaskSort::Due, {
            let first = task();
            let mut second = task();
            second["taskId"] = json!(Uuid::from_u128(3));
            second["deadlineAt"] = json!("2026-10-19T00:00:00Z");
            json!({"items":[first,second],"status":"complete"})
        }),
        (ReviewTaskSort::Reference, {
            let mut first = task();
            let mut second = task();
            second["taskId"] = json!(Uuid::from_u128(3));
            first["displayReference"] = json!("Z-7");
            second["displayReference"] = json!("A-7");
            json!({"items":[first,second],"status":"complete"})
        }),
        (ReviewTaskSort::Subject, {
            let mut first = task();
            let mut second = task();
            second["taskId"] = json!(Uuid::from_u128(3));
            first["subject"]["id"] = json!("z");
            second["subject"]["id"] = json!("a");
            json!({"items":[first,second],"status":"complete"})
        }),
    ] {
        let app = Router::new()
            .route(
                "/v1/review-tasks",
                get(|State(value): State<Value>| async move {
                    (
                        [("content-type", "application/json"), ("traceparent", TRACE)],
                        value.to_string(),
                    )
                }),
            )
            .with_state(response);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = CaseworkClient::new(CaseworkClientConfig::new(
            Url::parse(&format!("http://{address}/")).unwrap(),
        ))
        .unwrap();
        let token = BearerToken::new("staff-token").unwrap();
        assert!(matches!(
            client
                .review_tasks(
                    CaseworkAuth::new(&token, "staff"),
                    &ReviewStaffingQuery {
                        sort,
                        ..Default::default()
                    }
                )
                .await,
            Err(CaseworkClientError::Protocol {
                failure: CaseworkProtocolFailure::Body,
                ..
            })
        ));
        server.abort();
    }
}

#[tokio::test]
async fn decision_and_private_draft_bounds_fail_before_io() {
    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse("http://127.0.0.1:1/").unwrap(),
    ))
    .unwrap();
    let token = BearerToken::new("staff-token").unwrap();
    let auth = || CaseworkAuth::new(&token, "staff");
    for result in [
        Some(json!([])),
        Some(json!({"private-canary":"x".repeat(17*1024)})),
        Some(json!({"count":9_007_199_254_740_992_u64})),
    ] {
        let input = ReviewTaskDecisionRequest {
            decision: DecisionKind::Answer {
                outcome: "answered".into(),
                public_reason: None,
                reason: None,
                result,
            },
        };
        let error = client
            .decide_review_task(auth(), Uuid::from_u128(1), 1, "decision-7", &input)
            .await
            .unwrap_err();
        assert!(matches!(error, CaseworkClientError::InvalidRequest { .. }));
        assert!(!error.to_string().contains("private-canary"));
    }
    let error = client
        .save_review_task_draft(
            auth(),
            Uuid::from_u128(1),
            1,
            "draft-7",
            &ReviewTaskDraftInput {
                body: json!({"private-canary":"x".repeat(17*1024)}),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(error, CaseworkClientError::InvalidRequest { .. }));
    assert!(!error.to_string().contains("private-canary"));
}

#[tokio::test]
async fn draft_response_json_rejects_duplicate_members_in_arbitrary_private_body() {
    let body = r#"{"taskId":"00000000-0000-0000-0000-000000000001","author":{"issuer":"https://issuer.example","subject":"staff-1"},"body":{"private-canary":"first","private-canary":"second"},"revision":1,"updatedAt":"2026-10-14T00:00:00Z"}"#;
    let app = Router::new().route(
        "/v1/review-tasks/{id}/draft",
        get(move || async move {
            (
                [("content-type", "application/json"), ("traceparent", TRACE)],
                body,
            )
        })
        .put(move || async move {
            (
                [("content-type", "application/json"), ("traceparent", TRACE)],
                body,
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse(&format!("http://{address}/")).unwrap(),
    ))
    .unwrap();
    let token = BearerToken::new("staff-token").unwrap();
    for result in [
        client
            .review_task_draft(CaseworkAuth::new(&token, "staff"), Uuid::from_u128(1))
            .await
            .map(|_| ()),
        client
            .save_review_task_draft(
                CaseworkAuth::new(&token, "staff"),
                Uuid::from_u128(1),
                1,
                "draft-7",
                &ReviewTaskDraftInput {
                    body: json!({"private-canary":"second"}),
                },
            )
            .await
            .map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(CaseworkClientError::Protocol {
                failure: CaseworkProtocolFailure::Body,
                ..
            })
        ));
    }
    server.abort();
}

/// A page that stopped early must say where to resume; every paged read whose
/// runtime emits a status refuses a stopped page without a `nextCursor`.
#[tokio::test]
async fn paged_reads_refuse_a_stopped_page_without_a_cursor() {
    let cursor = Uuid::from_u128(7).to_string();
    let cases = [
        (json!({"items":[],"status":"budget-exhausted"}), false),
        (json!({"items":[],"status":"source-unavailable"}), false),
        (json!({"items":[],"status":"complete"}), true),
        (
            json!({"items":[],"nextCursor":cursor,"status":"complete"}),
            true,
        ),
        (
            json!({"items":[],"nextCursor":cursor,"status":"budget-exhausted"}),
            true,
        ),
        (
            json!({"items":[],"nextCursor":cursor,"status":"source-unavailable"}),
            true,
        ),
    ];
    for (response, accepted) in cases {
        let page = |State(value): State<Value>| async move {
            (
                [("content-type", "application/json"), ("traceparent", TRACE)],
                value.to_string(),
            )
        };
        let app = Router::new()
            .route("/v1/review-tasks", get(page))
            .route("/v1/review-tasks/holdings", get(page))
            .route("/v1/review-tasks/own-decisions", get(page))
            .route("/v1/review-tasks/supervision", get(page))
            .route("/v1/directory/targets", get(page))
            .with_state(response.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = CaseworkClient::new(CaseworkClientConfig::new(
            Url::parse(&format!("http://{address}/")).unwrap(),
        ))
        .unwrap();
        let token = BearerToken::new("staff-token").unwrap();
        let auth = || CaseworkAuth::new(&token, "staff");
        let check = |read: &str, result: Result<(), CaseworkClientError>| {
            if accepted {
                assert!(result.is_ok(), "{read} refused {response}: {result:?}");
            } else {
                assert!(
                    matches!(
                        result,
                        Err(CaseworkClientError::Protocol {
                            failure: CaseworkProtocolFailure::Body,
                            ..
                        })
                    ),
                    "{read} accepted {response}: {result:?}"
                );
            }
        };
        let staffing = ReviewStaffingQuery::default();
        check(
            "review tasks",
            client.review_tasks(auth(), &staffing).await.map(drop),
        );
        check(
            "review task holdings",
            client
                .review_task_holdings(auth(), &staffing)
                .await
                .map(drop),
        );
        check(
            "own review decisions",
            client
                .own_review_decisions(auth(), &OwnReviewDecisionQuery::default())
                .await
                .map(drop),
        );
        check(
            "supervisory review tasks",
            client
                .supervisory_review_tasks(auth(), &SupervisoryReviewTaskQuery::default())
                .await
                .map(drop),
        );
        check(
            "directory targets",
            client
                .directory_targets(
                    auth(),
                    &DirectoryTargetsQuery {
                        purpose: DirectoryTargetPurpose::AbsencePerson,
                        queue: None,
                        person_issuer: None,
                        person_subject: None,
                        cursor: None,
                        limit: Some(25),
                    },
                )
                .await
                .map(drop),
        );
        server.abort();
    }
}

/// Casework issues random cursors, never the nil identifier: a nil cursor is
/// refused before the request on every UUID-cursored read, and a page that
/// offers one as its continuation is refused.
#[tokio::test]
async fn uuid_paged_reads_refuse_a_nil_cursor() {
    let requests = Arc::new(Mutex::new(0_usize));
    let page = |State((requests, value)): State<(Arc<Mutex<usize>>, Value)>| async move {
        *requests.lock().unwrap() += 1;
        (
            [("content-type", "application/json"), ("traceparent", TRACE)],
            value.to_string(),
        )
    };
    let nil = Uuid::nil().to_string();
    let response = json!({"items":[],"nextCursor":nil,"status":"budget-exhausted"});
    let app = Router::new()
        .route("/v1/review-tasks", get(page))
        .route("/v1/review-tasks/next", get(page))
        .route("/v1/review-tasks/holdings", get(page))
        .route("/v1/review-tasks/own-decisions", get(page))
        .route("/v1/review-tasks/supervision", get(page))
        .route("/v1/review-requests/{id}/history", get(page))
        .with_state((requests.clone(), response));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = CaseworkClient::new(CaseworkClientConfig::new(
        Url::parse(&format!("http://{address}/")).unwrap(),
    ))
    .unwrap();
    let token = BearerToken::new("staff-token").unwrap();
    let auth = || CaseworkAuth::new(&token, "staff");

    let staffing = ReviewStaffingQuery {
        cursor: Some(Uuid::nil()),
        ..Default::default()
    };
    for (read, result) in [
        (
            "review tasks",
            client.review_tasks(auth(), &staffing).await.map(drop),
        ),
        (
            "next review task",
            client.next_review_task(auth(), &staffing).await.map(drop),
        ),
        (
            "review task holdings",
            client
                .review_task_holdings(auth(), &staffing)
                .await
                .map(drop),
        ),
        (
            "own review decisions",
            client
                .own_review_decisions(
                    auth(),
                    &OwnReviewDecisionQuery {
                        cursor: Some(Uuid::nil()),
                        ..Default::default()
                    },
                )
                .await
                .map(drop),
        ),
        (
            "supervisory review tasks",
            client
                .supervisory_review_tasks(
                    auth(),
                    &SupervisoryReviewTaskQuery {
                        cursor: Some(Uuid::nil()),
                        ..Default::default()
                    },
                )
                .await
                .map(drop),
        ),
        (
            "review history",
            client
                .review_history(
                    auth(),
                    Uuid::from_u128(1),
                    &ReviewPageQuery {
                        cursor: Some(Uuid::nil()),
                        limit: None,
                    },
                )
                .await
                .map(drop),
        ),
    ] {
        assert!(
            matches!(result, Err(CaseworkClientError::InvalidRequest { .. })),
            "{read} sent a nil cursor: {result:?}"
        );
    }
    assert_eq!(*requests.lock().unwrap(), 0);

    let staffing = ReviewStaffingQuery::default();
    for (read, result) in [
        (
            "review tasks",
            client.review_tasks(auth(), &staffing).await.map(drop),
        ),
        (
            "review task holdings",
            client
                .review_task_holdings(auth(), &staffing)
                .await
                .map(drop),
        ),
        (
            "own review decisions",
            client
                .own_review_decisions(auth(), &OwnReviewDecisionQuery::default())
                .await
                .map(drop),
        ),
        (
            "supervisory review tasks",
            client
                .supervisory_review_tasks(auth(), &SupervisoryReviewTaskQuery::default())
                .await
                .map(drop),
        ),
    ] {
        assert!(
            matches!(
                result,
                Err(CaseworkClientError::Protocol {
                    failure: CaseworkProtocolFailure::Body,
                    ..
                })
            ),
            "{read} accepted a nil next cursor: {result:?}"
        );
    }
    server.abort();
}

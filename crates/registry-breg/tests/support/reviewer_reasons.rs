// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_reviewer_reasons_are_bounded_replayed_and_read_by_permission() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(reason_registry());
    let identity = install_registry(&database, &registry, "two-stage-change-request", false).await;
    let app = change_request_router(
        &database,
        registry,
        identity,
        "two-stage-change-request",
        None,
    );
    let submitter = claims("submitter", SUBMITTER, None);
    let reviewer = claims("reviewer", REVIEWER, Some("review"));
    let (request, digest) = submit_two_stage_correction(&app).await;
    let review = reason_read(&app, &request.id, "reviewer", reviewer.clone()).await;
    let revise = action(&review.body, "request_revision", Some("review"));
    let reject = action(&review.body, "reject_request", Some("review"));
    let approve = action(&review.body, "approve_request", Some("review"));

    for (index, invalid) in [
        json!(null),
        json!(17),
        json!(false),
        json!([]),
        json!({}),
        json!("é".repeat(4097)),
    ]
    .into_iter()
    .enumerate()
    {
        for decision in [&revise, &reject] {
            let response = send_action(
                &app,
                decision,
                &format!("reason-invalid-{index}"),
                reviewer.clone(),
                json!({"proposalVersion": 1, "effectDigest": digest, "reason": invalid}),
            )
            .await;
            assert_eq!(
                response.status,
                StatusCode::BAD_REQUEST,
                "{}",
                response.body
            );
        }
    }
    for decision in [&revise, &reject] {
        let response = send_action(
            &app,
            decision,
            "reason-unknown",
            reviewer.clone(),
            json!({"proposalVersion": 1, "effectDigest": digest, "reason": "check", "extra": true}),
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
    }
    let refused_approval = send_action(
        &app,
        &approve,
        "reason-on-approval",
        reviewer.clone(),
        json!({"proposalVersion": 1, "effectDigest": digest, "reason": "not an approval input"}),
    )
    .await;
    assert_eq!(refused_approval.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        reason_read(&app, &request.id, "submitter", submitter.clone())
            .await
            .body["request"]["bregState"],
        "submitted"
    );

    // The bound counts Unicode scalar values, not UTF-8 bytes, and text is exact.
    let reason = format!(" {}\n", "é".repeat(4094));
    let body = json!({"proposalVersion": 1, "effectDigest": digest, "reason": reason});
    let returned = send_action(
        &app,
        &revise,
        "reason-return",
        reviewer.clone(),
        body.clone(),
    )
    .await;
    assert_eq!(returned.status, StatusCode::OK, "{}", returned.body);
    assert_eq!(returned.body["request"]["bregState"], "needs_changes");
    let replayed = send_action(&app, &revise, "reason-return", reviewer.clone(), body).await;
    assert_eq!(replayed.status, StatusCode::OK);
    assert_eq!(
        replayed.body, returned.body,
        "exact request replays the original receipt"
    );
    let changed = send_action(
        &app,
        &revise,
        "reason-return",
        reviewer.clone(),
        json!({"proposalVersion": 1, "effectDigest": digest, "reason": "changed explanation"}),
    )
    .await;
    assert_eq!(changed.status, StatusCode::CONFLICT);
    assert!(!changed.body.to_string().contains("changed explanation"));

    let owner_read = reason_read(&app, &request.id, "submitter", submitter.clone()).await;
    assert_decision(
        &owner_read.body["request"]["decisions"][0],
        "request_revision",
        Some(&reason),
    );
    assert_decision(
        &owner_read.body["request"]["history"]["proposals"][0]["decisions"][0],
        "request_revision",
        Some(&reason),
    );
    let hidden = reason_read(&app, &request.id, "reason-hidden", submitter.clone()).await;
    assert_eq!(
        hidden.body["request"]["decisions"][0]["reasonPresent"],
        true
    );
    assert!(hidden.body["request"]["decisions"][0]
        .get("reason")
        .is_none());
    assert!(!hidden.body.to_string().contains(&"é".repeat(20)));
    let denied = response_parts(
        send(
            &app,
            Method::GET,
            &format!(
                "/v1/records/correction-requests/{}?accessProfile=reviewer",
                request.id
            ),
            Some(submitter.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert!(!denied.status.is_success());
    assert!(!denied.body.to_string().contains(&"é".repeat(20)));
    let anonymous = response_parts(
        send(
            &app,
            Method::GET,
            &format!(
                "/v1/records/correction-requests/{}?accessProfile=submitter",
                request.id
            ),
            None,
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert!(!anonymous.status.is_success());
    assert!(!anonymous.body.to_string().contains(&"é".repeat(20)));

    let revise_draft = action(&owner_read.body, "revise_request", None);
    let draft = send_action(
        &app,
        &revise_draft,
        "reason-revise",
        submitter.clone(),
        json!({"rebase":true}),
    )
    .await;
    assert_eq!(draft.status, StatusCode::OK, "{}", draft.body);
    assert_eq!(draft.body["request"]["proposalVersion"], 2);
    let submitted = run_action(
        &app,
        &request.id,
        "correction-requests",
        "submitter",
        submitter.clone(),
        "reason-resubmit",
        "submit_request",
        None,
        |_| json!({}),
    )
    .await;
    assert_eq!(submitted["request"]["proposalVersion"], 2);
    let review_v2 = reason_read(&app, &request.id, "reviewer", reviewer.clone()).await;
    assert!(review_v2.body["request"]["decisions"]
        .as_array()
        .unwrap()
        .is_empty());
    let reject_v2 = action(&review_v2.body, "reject_request", Some("review"));
    let rejected = send_action(&app, &reject_v2, "reason-reject", reviewer,
        json!({"proposalVersion": 2, "effectDigest": reject_v2.effect_digest, "reason": "The proposed site remains incorrect."})).await;
    assert_eq!(rejected.status, StatusCode::OK, "{}", rejected.body);
    let final_read = reason_read(&app, &request.id, "submitter", submitter).await;
    assert_eq!(final_read.body["request"]["bregState"], "rejected");
    assert_decision(
        &final_read.body["request"]["decisions"][0],
        "reject",
        Some("The proposed site remains incorrect."),
    );
    let proposals = final_read.body["request"]["history"]["proposals"]
        .as_array()
        .unwrap();
    let prior = proposals
        .iter()
        .find(|proposal| proposal["proposalVersion"] == 1)
        .unwrap();
    assert_decision(&prior["decisions"][0], "request_revision", Some(&reason));

    let rows = database.admin.query("SELECT convert_from(payload, 'UTF8') FROM registry_internal.registry_outbox WHERE trigger = 'request_lifecycle' ORDER BY record_revision", &[]).await.unwrap();
    assert_eq!(rows.len(), 2);
    let returned_event: Value = serde_json::from_str(&rows[0].get::<_, String>(0)).unwrap();
    assert_eq!(returned_event["request"]["reason"], reason);
    assert_eq!(returned_event["request"]["reasonPresent"], true);
    assert_eq!(
        returned_event["values"]["reason"], "two-stage correction",
        "authored proposal reason stays distinct from reviewer explanation"
    );
    let rejected_event: Value = serde_json::from_str(&rows[1].get::<_, String>(0)).unwrap();
    assert_eq!(
        rejected_event["request"]["reason"],
        "The proposed site remains incorrect."
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_reviewer_reason_event_failure_rolls_back_decision_and_retry_is_safe() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(reason_registry());
    let identity = install_registry(&database, &registry, "two-stage-change-request", false).await;
    let app = change_request_router(
        &database,
        registry,
        identity,
        "two-stage-change-request",
        None,
    );
    let reviewer = claims("reviewer", REVIEWER, Some("review"));
    let (request, digest) = submit_two_stage_correction(&app).await;
    let before = reason_read(&app, &request.id, "reviewer", reviewer.clone()).await;
    let reject = action(&before.body, "reject_request", Some("review"));
    database.admin.batch_execute("CREATE FUNCTION registry_internal.fail_reason_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test outbox refusal'; END; $$; CREATE TRIGGER fail_reason_event BEFORE INSERT ON registry_internal.registry_outbox FOR EACH ROW EXECUTE FUNCTION registry_internal.fail_reason_event();").await.unwrap();
    let body = json!({"proposalVersion":1,"effectDigest":digest,"reason":"Review explanation requiring atomic persistence"});
    let failed = send_action(
        &app,
        &reject,
        "reason-atomic-reject",
        reviewer.clone(),
        body.clone(),
    )
    .await;
    assert!(failed.status.is_server_error(), "{}", failed.body);
    let after = reason_read(&app, &request.id, "reviewer", reviewer.clone()).await;
    assert_eq!(after.etag, before.etag);
    assert_eq!(after.body["request"]["bregState"], "submitted");
    assert!(after.body["request"]["decisions"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        database
            .admin
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_outbox",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    database.admin.batch_execute("DROP TRIGGER fail_reason_event ON registry_internal.registry_outbox; DROP FUNCTION registry_internal.fail_reason_event();").await.unwrap();
    let retried = send_action(&app, &reject, "reason-atomic-reject", reviewer, body).await;
    assert_eq!(retried.status, StatusCode::OK, "{}", retried.body);
    let owner = reason_read(
        &app,
        &request.id,
        "submitter",
        claims("submitter", SUBMITTER, None),
    )
    .await;
    assert_eq!(
        owner.body["request"]["decisions"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        database
            .admin
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_outbox",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_no_reason_review_remains_compatible_and_apply_refuses_reason() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(reason_registry());
    let identity = install_registry(&database, &registry, "two-stage-change-request", false).await;
    let app = change_request_router(
        &database,
        registry,
        identity,
        "two-stage-change-request",
        None,
    );
    let submitter = claims("submitter", SUBMITTER, None);
    let reviewer = claims("reviewer", REVIEWER, Some("review"));
    let (request, _) = submit_two_stage_correction(&app).await;
    let returned = run_action(&app, &request.id, "correction-requests", "reviewer", reviewer.clone(),
        "no-reason-return", "request_revision", Some("review"), |action| json!({"proposalVersion":action.proposal_version,"effectDigest":action.effect_digest})).await;
    assert_eq!(returned["request"]["bregState"], "needs_changes");
    let owner = reason_read(&app, &request.id, "submitter", submitter.clone()).await;
    assert_decision(
        &owner.body["request"]["decisions"][0],
        "request_revision",
        None,
    );
    let event: Value = serde_json::from_str(
        &database
            .admin
            .query_one(
                "SELECT convert_from(payload, 'UTF8') FROM registry_internal.registry_outbox",
                &[],
            )
            .await
            .unwrap()
            .get::<_, String>(0),
    )
    .unwrap();
    assert_eq!(event["request"]["reasonPresent"], false);
    assert!(event["request"].get("reason").is_none());
    run_action(
        &app,
        &request.id,
        "correction-requests",
        "submitter",
        submitter.clone(),
        "no-reason-revise",
        "revise_request",
        None,
        |_| json!({"rebase":true}),
    )
    .await;
    run_action(
        &app,
        &request.id,
        "correction-requests",
        "submitter",
        submitter,
        "no-reason-resubmit",
        "submit_request",
        None,
        |_| json!({}),
    )
    .await;
    run_action(&app, &request.id, "correction-requests", "reviewer", reviewer,
        "no-reason-approve", "approve_request", Some("review"), |action| json!({"proposalVersion":action.proposal_version,"effectDigest":action.effect_digest})).await;
    let applier = claims("applier", APPLIER, Some("apply"));
    let ready = reason_read(&app, &request.id, "applier", applier.clone()).await;
    let apply = action(&ready.body, "apply_request", None);
    let refused = send_action(&app, &apply, "reason-on-apply", applier.clone(),
        json!({"proposalVersion":apply.proposal_version,"effectDigest":apply.effect_digest,"reason":"unsupported"})).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    let applied = send_action(
        &app,
        &apply,
        "no-reason-apply",
        applier,
        json!({"proposalVersion":apply.proposal_version,"effectDigest":apply.effect_digest}),
    )
    .await;
    assert_eq!(applied.status, StatusCode::OK, "{}", applied.body);
    assert_eq!(applied.body["request"]["bregState"], "applied");
    database.cleanup().await;
}

fn assert_decision(decision: &Value, kind: &str, reason: Option<&str>) {
    assert_eq!(decision["stageId"], "review");
    assert_eq!(decision["kind"], kind);
    assert!(decision["decidedAt"].is_string());
    assert_eq!(decision["reasonPresent"], reason.is_some());
    assert_eq!(decision.get("reason").and_then(Value::as_str), reason);
    if reason.is_none() {
        assert!(decision.get("reason").is_none());
    }
    assert!(decision.get("actor").is_none());
    assert!(decision.get("actorPrincipal").is_none());
    assert!(decision.get("effectDigest").is_none());
}

async fn reason_read(
    app: &axum::Router,
    id: &str,
    profile: &str,
    caller: VerifiedRequestClaims,
) -> ResponseParts {
    get_record(
        app,
        &format!("/v1/records/correction-requests/{id}?accessProfile={profile}"),
        caller,
    )
    .await
}

fn reason_registry() -> registry_breg::CompiledRegistry {
    let mut source = serde_json::to_value(two_stage_project()).expect("fixture serializes");
    let request = source["entities"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entity| entity["id"] == "correction-request")
        .unwrap();
    request["changeRequest"]["review"]["stages"]
        .as_array_mut()
        .unwrap()
        .truncate(1);
    request["events"] = json!([{
        "id":"review-returned", "trigger":"request_lifecycle", "projection":["reason"],
        "when":{"kind":"request_lifecycle", "transitions":["reject","request_revision"], "toStates":["rejected","needs_changes"], "stages":["review"]}
    }]);
    let profiles = source["accessProfiles"].as_array_mut().unwrap();
    profiles.retain(|profile| profile["id"] != "final-reviewer");
    let mut hidden = profiles
        .iter()
        .find(|profile| profile["id"] == "submitter")
        .unwrap()
        .clone();
    hidden["id"] = json!("reason-hidden");
    hidden["permissions"][0]["readableRequestFields"] = json!([]);
    profiles.push(hidden);
    let project =
        parse_project_json(&serde_json::to_vec(&source).unwrap()).expect("reason fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("reason fixture compiles")
}

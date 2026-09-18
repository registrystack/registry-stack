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
        for decision in [&revise, &reject, &approve] {
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
    for decision in [&revise, &reject, &approve] {
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
    let returned_event = event_data(&rows[0].get::<_, String>(0));
    assert_eq!(returned_event["request"]["reason"], reason);
    assert_eq!(returned_event["request"]["reasonPresent"], true);
    assert_eq!(
        returned_event["values"]["reason"], "two-stage correction",
        "authored proposal reason stays distinct from reviewer explanation"
    );
    let rejected_event = event_data(&rows[1].get::<_, String>(0));
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
async fn real_postgres_http_no_reason_review_remains_compatible_and_reasoned_decisions_apply_and_are_read_back(
) {
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
    let event = event_data(
        &database
            .admin
            .query_one(
                "SELECT convert_from(payload, 'UTF8') FROM registry_internal.registry_outbox",
                &[],
            )
            .await
            .unwrap()
            .get::<_, String>(0),
    );
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
        submitter.clone(),
        "no-reason-resubmit",
        "submit_request",
        None,
        |_| json!({}),
    )
    .await;
    let approval_note = "Favourable; re-verify the applicant next cycle.";
    let approved = run_action(&app, &request.id, "correction-requests", "reviewer", reviewer,
        "reasoned-approve", "approve_request", Some("review"), |action| json!({"proposalVersion":action.proposal_version,"effectDigest":action.effect_digest,"reason":approval_note})).await;
    assert_eq!(approved["request"]["bregState"], "approved");
    let owner = reason_read(&app, &request.id, "submitter", submitter.clone()).await;
    assert_decision(
        &owner.body["request"]["decisions"][0],
        "approve",
        Some(approval_note),
    );
    let applier = claims("applier", APPLIER, Some("apply"));
    let ready = reason_read(&app, &request.id, "applier", applier.clone()).await;
    let apply = action(&ready.body, "apply_request", None);
    let apply_note = "Applied following the registrar's sign-off.";
    let applied = send_action(&app, &apply, "reasoned-apply", applier.clone(),
        json!({"proposalVersion":apply.proposal_version,"effectDigest":apply.effect_digest,"reason":apply_note})).await;
    assert_eq!(applied.status, StatusCode::OK, "{}", applied.body);
    assert_eq!(applied.body["request"]["bregState"], "applied");
    let final_read = reason_read(&app, &request.id, "submitter", submitter.clone()).await;
    assert_eq!(final_read.body["request"]["bregState"], "applied");
    assert_eq!(
        final_read.body["request"]["application"]["reasonPresent"],
        true
    );
    assert_eq!(
        final_read.body["request"]["application"]["reason"],
        apply_note
    );
    let hidden = reason_read(
        &app,
        &request.id,
        "reason-hidden",
        claims("submitter", SUBMITTER, None),
    )
    .await;
    assert_eq!(hidden.body["request"]["application"]["reasonPresent"], true);
    assert!(hidden.body["request"]["application"]
        .get("reason")
        .is_none());
    assert!(!hidden.body.to_string().contains(apply_note));
    let replayed_apply = send_action(&app, &apply, "reasoned-apply", applier.clone(),
        json!({"proposalVersion":apply.proposal_version,"effectDigest":apply.effect_digest,"reason":apply_note})).await;
    assert_eq!(replayed_apply.status, StatusCode::OK);
    assert_eq!(replayed_apply.body, applied.body);
    let changed_apply = send_action(&app, &apply, "reasoned-apply", applier.clone(),
        json!({"proposalVersion":apply.proposal_version,"effectDigest":apply.effect_digest,"reason":"changed"})).await;
    assert_eq!(changed_apply.status, StatusCode::CONFLICT);
    let rows = database.admin.query("SELECT convert_from(payload, 'UTF8') FROM registry_internal.registry_outbox WHERE trigger = 'request_lifecycle' ORDER BY record_revision", &[]).await.unwrap();
    let approve_event = event_data(&rows[1].get::<_, String>(0));
    assert_eq!(approve_event["request"]["transition"], "approve");
    assert_eq!(approve_event["request"]["reason"], approval_note);
    let apply_event = event_data(&rows[2].get::<_, String>(0));
    assert_eq!(apply_event["request"]["transition"], "apply");
    assert_eq!(apply_event["request"]["reason"], apply_note);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_reasoned_approval_before_the_last_stage_is_recorded_and_published() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(compile_reason_registry(2, false));
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
    let final_reviewer = claims("final-reviewer", "final-reviewer-principal", Some("final"));
    let (request, digest) = submit_two_stage_correction(&app).await;
    let review = reason_read(&app, &request.id, "reviewer", reviewer.clone()).await;
    let stage_approve = action(&review.body, "approve_request", Some("review"));
    let stage_note = "Stage one is satisfied; the final reviewer still decides.";
    let stage_approved = send_action(
        &app,
        &stage_approve,
        "stage-reason-approve",
        reviewer,
        json!({"proposalVersion": 1, "effectDigest": digest, "reason": stage_note}),
    )
    .await;
    assert_eq!(
        stage_approved.status,
        StatusCode::OK,
        "{}",
        stage_approved.body
    );
    assert_eq!(
        stage_approved.body["request"]["bregState"], "submitted",
        "an approval before the last stage leaves the request under review"
    );
    let pending = reason_read(&app, &request.id, "submitter", submitter.clone()).await;
    assert_decision(
        &pending.body["request"]["decisions"][0],
        "approve",
        Some(stage_note),
    );

    let final_review =
        reason_read(&app, &request.id, "final-reviewer", final_reviewer.clone()).await;
    let final_approve = action(&final_review.body, "approve_request", Some("final"));
    let final_note = "Final sign-off recorded.";
    let approved = send_action(
        &app,
        &final_approve,
        "final-reason-approve",
        final_reviewer,
        json!({"proposalVersion": 1, "effectDigest": digest, "reason": final_note}),
    )
    .await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert_eq!(approved.body["request"]["bregState"], "approved");
    let decided = reason_read(&app, &request.id, "submitter", submitter).await;
    let decisions = decided.body["request"]["decisions"]
        .as_array()
        .expect("decisions are an array");
    assert_eq!(decisions.len(), 2);
    let last_decision = decisions
        .iter()
        .find(|decision| decision["stageId"] == "final")
        .expect("the last stage decision is retained");
    assert_eq!(last_decision["kind"], "approve");
    assert_eq!(last_decision["reasonPresent"], true);
    assert_eq!(last_decision["reason"], final_note);

    let rows = database.admin.query("SELECT convert_from(payload, 'UTF8') FROM registry_internal.registry_outbox WHERE trigger = 'request_lifecycle' ORDER BY record_revision", &[]).await.unwrap();
    assert_eq!(rows.len(), 2);
    let stage_event = event_data(&rows[0].get::<_, String>(0));
    assert_eq!(stage_event["request"]["transition"], "approve");
    assert_eq!(stage_event["request"]["toState"], "submitted");
    assert_eq!(stage_event["request"]["reasonPresent"], true);
    assert_eq!(stage_event["request"]["reason"], stage_note);
    let final_event = event_data(&rows[1].get::<_, String>(0));
    assert_eq!(final_event["request"]["toState"], "approved");
    assert_eq!(final_event["request"]["reason"], final_note);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_request_detail_erasure_keeps_reason_presence_without_reason_text() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(compile_reason_registry(1, true));
    let identity = install_registry(&database, &registry, "two-stage-change-request", false).await;
    let app = change_request_router(
        &database,
        registry.clone(),
        identity.clone(),
        "two-stage-change-request",
        None,
    );
    let submitter = claims("submitter", SUBMITTER, None);
    let reviewer = claims("reviewer", REVIEWER, Some("review"));
    let applier = claims("applier", APPLIER, Some("apply"));
    let (request, digest) = submit_two_stage_correction(&app).await;
    let approval_note = "Approved against the site register.";
    let apply_note = "Applied under the registrar's standing instruction.";
    let review = reason_read(&app, &request.id, "reviewer", reviewer.clone()).await;
    let approve = action(&review.body, "approve_request", Some("review"));
    let approved = send_action(
        &app,
        &approve,
        "erasure-reason-approve",
        reviewer,
        json!({"proposalVersion": 1, "effectDigest": digest, "reason": approval_note}),
    )
    .await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let ready = reason_read(&app, &request.id, "applier", applier.clone()).await;
    let apply = action(&ready.body, "apply_request", None);
    let applied = send_action(&app, &apply, "erasure-reason-apply", applier,
        json!({"proposalVersion": apply.proposal_version, "effectDigest": apply.effect_digest, "reason": apply_note})).await;
    assert_eq!(applied.status, StatusCode::OK, "{}", applied.body);
    assert_eq!(applied.body["request"]["bregState"], "applied");

    let retention = registry_breg::request_retention::RequestRetentionOperatorService::new_for_test(
        registry.as_ref().clone(),
        identity,
        registry_breg::postgres::ExpectedManagedCatalog::compiled(&registry),
        RegistryLockKey::derive("two-stage-change-request").unwrap(),
        database.migration_config.clone(),
        database.migration_role.clone(),
        database.runtime_role.clone(),
        AuditProfile::production_from_secret_bytes(vec![0x7c; 32].into()).unwrap(),
    );
    let erased = retention
        .erase(
            registry_breg::request_retention::RequestDetailErasureScope {
                request_entity_id: "correction-request",
                request_id: Uuid::parse_str(&request.id).unwrap(),
                proposal_version: 1,
            },
        )
        .await
        .expect("terminal request detail erases through the operator boundary");
    assert_eq!(erased.erasure.decision_reasons, 1);
    assert_eq!(erased.erasure.application_reasons, 1);

    let read = reason_read(&app, &request.id, "submitter", submitter).await;
    assert_eq!(read.body["request"]["detailErased"], true);
    assert_eq!(read.body["request"]["application"]["reasonPresent"], true);
    assert!(read.body["request"]["application"].get("reason").is_none());
    assert_eq!(read.body["request"]["decisions"][0]["reasonPresent"], true);
    assert!(read.body["request"]["decisions"][0].get("reason").is_none());
    let body = read.body.to_string();
    assert!(!body.contains(approval_note));
    assert!(!body.contains(apply_note));
    database.cleanup().await;
}

/// The event data one stored outbox envelope carries.
fn event_data(payload: &str) -> Value {
    let envelope: Value = serde_json::from_str(payload).expect("stored payload is JSON");
    envelope["data"].clone()
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
    compile_reason_registry(1, false)
}

/// The reviewer-explanation fixture, kept to `stages` review stages and
/// optionally admitting operator erasure of retained request detail.
fn compile_reason_registry(stages: usize, operator_erase: bool) -> registry_breg::CompiledRegistry {
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
        .truncate(stages);
    if operator_erase {
        request["changeRequest"]["retention"] = json!({"mode": "operator_erase"});
    }
    request["hooks"] = json!([{
        "phase": "after",
        "id":"review-returned", "trigger":"request_lifecycle", "projection":["reason"],
        "when":{"kind":"request_lifecycle", "transitions":["reject","request_revision"], "toStates":["rejected","needs_changes"], "stages":["review"]}
    }, {
        "phase": "after",
        "id":"review-decided", "trigger":"request_lifecycle", "projection":["reason"],
        "when":{"kind":"request_lifecycle", "transitions":["approve","apply"], "toStates":["submitted","approved","applied"]}
    }]);
    let profiles = source["accessProfiles"].as_array_mut().unwrap();
    if stages < 2 {
        profiles.retain(|profile| profile["id"] != "final-reviewer");
    }
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

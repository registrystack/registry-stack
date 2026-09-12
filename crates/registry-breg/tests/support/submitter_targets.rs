// SPDX-License-Identifier: Apache-2.0
use super::*;
fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn starter_source() -> Value {
    let mut source: Value = serde_json::from_slice(include_bytes!(
        "../../../../products/breg/starters/professional-licences/core/registry.yaml"
    ))
    .expect("starter parses");
    let reviewer = source["accessProfiles"]
        .as_array_mut()
        .expect("starter access profiles")
        .iter_mut()
        .find(|profile| profile["id"] == "reviewer")
        .expect("starter reviewer profile")
        .as_object_mut()
        .expect("reviewer profile is an object");
    // This module injects claims after token verification. Contextual actor and
    // client admission has its own authentication tests; these cases isolate
    // current target predicates, locks, replay, and request atomicity.
    reviewer.remove("actorKind");
    reviewer.remove("requesterClients");
    source
}

fn starter() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(&starter_source()).unwrap())
        .expect("starter parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("holder target admission compiles")
}

fn actor(
    profile: &str,
    principal: &str,
    person: Option<VerifiedClaimValue>,
) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        BTreeSet::from([format!("starter:{profile}")]),
        Some("starter-learning".to_owned()),
        person
            .map(|value| BTreeMap::from([("person_reference".to_owned(), value)]))
            .unwrap_or_default(),
    )
    .expect("verified synthetic actor")
}

fn holder(principal: &str, person: &str) -> VerifiedRequestClaims {
    actor(
        "holder",
        principal,
        Some(VerifiedClaimValue::direct_string(person).expect("person claim")),
    )
}

fn correction(record: &str) -> Value {
    json!({"record": record, "licensedActivities":["example-assessment"],"authorizationConditions":"corrected scope", "reason":"recorded transcription correction", "supportingReference":"https://example.test/synthetic-reference"})
}

async fn create_request(
    app: &axum::Router,
    claims: VerifiedRequestClaims,
    key: &str,
    record: &str,
) -> ResponseParts {
    response_parts(
        send(
            app,
            Method::POST,
            "/v1/records/scope-corrections?accessProfile=holder",
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", key),
            ],
            serde_json::to_vec(&json!({"data":correction(record)})).unwrap(),
        )
        .await,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_reference_submitter_admission_is_live_and_atomic() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(starter());
    let identity = install_registry(&database, &registry, "holder-admission", false).await;
    let app = change_request_router(
        &database,
        registry.clone(),
        identity,
        "holder-admission",
        None,
    );
    let own_list = get_record(
        &app,
        "/v1/records/professional-licenses?accessProfile=holder",
        holder("holder-none", "person:none"),
    )
    .await;
    assert_eq!(own_list.status, StatusCode::OK);
    assert_eq!(own_list.body["items"], json!([]));
    let registrar = actor("editor", "registrar", None);
    let first = holder("holder-a", "person:a");
    let second = holder("holder-b", "person:b");
    let mut licences = Vec::new();
    for (identifier, person) in [("A1", "person:a"), ("A2", "person:a"), ("B1", "person:b")] {
        licences.push(create_record(&app, "/v1/records/professional-licenses?accessProfile=editor", registrar.clone(), identifier,
            json!({"localIdentifier":identifier,"personReference":person,"regulatorReference":"regulator:synthetic","jurisdictionReference":"jurisdiction:synthetic","professionCode":"example-nursing","licenceStatus":"recorded-active","validFrom":"2026-01-01","licensedActivities":["example-assessment"],"authorizationConditions":"original scope"})).await);
    }
    let own = &licences[0];
    let other = &licences[2];
    assert_not_found(
        &app,
        &format!(
            "/v1/records/professional-licenses/{}?accessProfile=holder",
            other.id
        ),
        first.clone(),
    )
    .await;
    let missing_target = create_request(
        &app,
        first.clone(),
        "missing-target",
        &Uuid::new_v4().to_string(),
    )
    .await;
    assert_eq!(missing_target.status, StatusCode::PRECONDITION_FAILED);
    let cross = create_request(&app, first.clone(), "cross-create", &other.id).await;
    assert_eq!(
        cross.status,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        cross.body
    );
    for missing in [
        actor("holder", "holder-a", None),
        actor(
            "holder",
            "holder-a",
            Some(VerifiedClaimValue::direct_string_set(["person:a", "person:b"]).unwrap()),
        ),
    ] {
        let denied = create_request(&app, missing, "missing-person", &own.id).await;
        assert_eq!(denied.status, StatusCode::NOT_FOUND);
    }
    let created = create_request(&app, first.clone(), "own-create", &own.id).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let replay = create_request(&app, first.clone(), "own-create", &own.id).await;
    assert_eq!(replay.body, created.body);
    let changed_claim =
        create_request(&app, holder("holder-a", "person:b"), "own-create", &own.id).await;
    assert_eq!(changed_claim.status, StatusCode::CONFLICT);
    assert_eq!(changed_claim.body["code"], "idempotency.conflict");
    let id = created.body["id"].as_str().unwrap();
    let uri = format!("/v1/records/scope-corrections/{id}?accessProfile=holder");
    assert_not_found(&app, &uri, second).await;
    let patched = response_parts(
        send(
            &app,
            Method::PATCH,
            &uri,
            Some(first.clone()),
            &[
                ("content-type", "application/json-patch+json"),
                ("idempotency-key", "cross-retarget"),
                ("if-match", &created.etag),
            ],
            serde_json::to_vec(&json!([{"op":"replace","path":"/data/record","value":other.id}]))
                .unwrap(),
        )
        .await,
    )
    .await;
    assert_eq!(
        patched.status,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        patched.body
    );
    let own_patch = response_parts(send(&app,Method::PATCH,&uri,Some(first.clone()),&[("content-type","application/json-patch+json"),("idempotency-key","own-reason-edit"),("if-match",&created.etag)],serde_json::to_vec(&json!([{"op":"replace","path":"/data/reason","value":"amended correction reason"}])).unwrap()).await).await;
    assert_eq!(
        own_patch.status,
        StatusCode::OK,
        "an unchanged target is admitted on ordinary draft edits"
    );
    let current = get_record(&app, &uri, first.clone()).await;
    assert_eq!(current.body["data"]["record"], own.id);
    let submit = action(&current.body, "submit_request", None);
    let submitted = send_action(&app, &submit, "own-submit", first.clone(), json!({})).await;
    assert_eq!(submitted.status, StatusCode::OK, "{}", submitted.body);
    let submitted_retry = send_action(&app, &submit, "own-submit", first.clone(), json!({})).await;
    assert_eq!(submitted_retry.body, submitted.body);
    let approved_page = get_record(
        &app,
        &format!("/v1/records/scope-corrections/{id}?accessProfile=reviewer"),
        actor("reviewer", "reviewer", None),
    )
    .await;
    let approve = action(&approved_page.body, "approve_request", Some("review"));
    let approved = send_action(
        &app,
        &approve,
        "review-own",
        actor("reviewer", "reviewer", None),
        json!({"proposalVersion":approve.proposal_version,"effectDigest":approve.effect_digest}),
    )
    .await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let approved_owner = get_record(&app, &uri, first.clone()).await;
    let rebase = action(&approved_owner.body, "revise_request", None);
    // A trusted administrative ownership change must stop fresh intake and preparation.
    let entity = &registry.entities()["professional-license"];
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{} SET {} = 'person:b' WHERE record_id = $1::text::uuid",
                quote(&entity.physical_table),
                quote(&entity.fields["person-reference"].physical_name)
            ),
            &[&own.id],
        )
        .await
        .unwrap();
    let after = get_record(&app, &uri, first.clone()).await;
    assert_eq!(
        after.status,
        StatusCode::OK,
        "ownership of the request remains visible"
    );
    let replay_after = send_action(&app, &submit, "own-submit", first.clone(), json!({})).await;
    assert_eq!(
        replay_after.status,
        StatusCode::PRECONDITION_FAILED,
        "current target authority gates replay"
    );
    let rebased = send_action(
        &app,
        &rebase,
        "cross-rebase",
        first.clone(),
        json!({"rebase":true}),
    )
    .await;
    assert_eq!(rebased.status, StatusCode::PRECONDITION_FAILED);
    let old_create = create_request(&app, first.clone(), "own-create", &own.id).await;
    assert_eq!(
        old_create.status,
        StatusCode::PRECONDITION_FAILED,
        "cached create data retains current target authority"
    );
    let draft = create_request(&app, first.clone(), "changed-target", &own.id).await;
    assert_eq!(draft.status, StatusCode::PRECONDITION_FAILED);
    let cancel = action(&after.body, "cancel_request", None);
    let cancelled = send_action(&app, &cancel, "cancel-after-transfer", first, json!({})).await;
    assert_eq!(
        cancelled.status,
        StatusCode::OK,
        "request cancellation retains owner authority: {}",
        cancelled.body
    );
    // An uncommitted target transfer holds admission until its final state is visible.
    let remaining = &licences[1];
    let draft = create_request(
        &app,
        holder("holder-a", "person:a"),
        "draft-before-transfer",
        &remaining.id,
    )
    .await;
    assert_eq!(draft.status, StatusCode::CREATED);
    let draft_uri = format!(
        "/v1/records/scope-corrections/{}?accessProfile=holder",
        draft.body["id"].as_str().unwrap()
    );
    let draft_page = get_record(&app, &draft_uri, holder("holder-a", "person:a")).await;
    let draft_submit = action(&draft_page.body, "submit_request", None);
    database.admin.batch_execute("BEGIN").await.unwrap();
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{} SET {} = 'person:b' WHERE record_id = $1::text::uuid",
                quote(&entity.physical_table),
                quote(&entity.fields["person-reference"].physical_name)
            ),
            &[&remaining.id],
        )
        .await
        .unwrap();
    let concurrent_app = app.clone();
    let concurrent_id = remaining.id.clone();
    let blocked = tokio::spawn(async move {
        create_request(
            &concurrent_app,
            holder("holder-a", "person:a"),
            "concurrent-transfer",
            &concurrent_id,
        )
        .await
    });
    let mut waiting = false;
    for _ in 0..40 {
        waiting = database.admin.query_one("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation = $1::text::regclass AND mode = 'ShareLock' AND NOT granted)", &[&format!("registry_data.{}",entity.physical_table)]).await.unwrap().get(0);
        if waiting {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(waiting, "admission waits on target write lock");
    database.admin.batch_execute("COMMIT").await.unwrap();
    let blocked_result = blocked.await.unwrap();
    assert_eq!(blocked_result.status, StatusCode::PRECONDITION_FAILED);
    let submit_after = send_action(
        &app,
        &draft_submit,
        "submit-after-transfer",
        holder("holder-a", "person:a"),
        json!({}),
    )
    .await;
    assert_eq!(submit_after.status, StatusCode::PRECONDITION_FAILED);
    let patch_after = response_parts(
        send(
            &app,
            Method::PATCH,
            &draft_uri,
            Some(holder("holder-a", "person:a")),
            &[
                ("content-type", "application/json-patch+json"),
                ("idempotency-key", "patch-after-transfer"),
                ("if-match", &draft.etag),
            ],
            serde_json::to_vec(
                &json!([{"op":"replace","path":"/data/reason","value":"new reason"}]),
            )
            .unwrap(),
        )
        .await,
    )
    .await;
    assert_eq!(patch_after.status, StatusCode::PRECONDITION_FAILED);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_snapshots_require_current_target_authority() {
    let mut source = starter_source();
    let reviewer = source["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|profile| profile["id"] == "reviewer")
        .unwrap();
    reviewer["permissions"][1]["reviewStages"][0]["targets"][0]["rowBoundaries"] =
        json!([{"field":"person-reference","claim":"person_reference","operator":"equals"}]);
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let registry = Arc::new(compile_project(&project, &[], CompileProfile::Authoring).unwrap());
    let database = TestDatabase::create(8).await;
    let identity = install_registry(&database, &registry, "current-review-context", false).await;
    let app = change_request_router(
        &database,
        registry.clone(),
        identity,
        "current-review-context",
        None,
    );
    let licence = create_record(&app,"/v1/records/professional-licenses?accessProfile=editor",actor("editor","registrar",None),"context-licence",json!({"localIdentifier":"CTX1","personReference":"person:a","regulatorReference":"regulator:synthetic","jurisdictionReference":"jurisdiction:synthetic","professionCode":"example-nursing","licenceStatus":"recorded-active","validFrom":"2026-01-01","licensedActivities":["example-assessment"],"authorizationConditions":"prior scope canary"})).await;
    let request = create_request(
        &app,
        holder("holder-a", "person:a"),
        "context-request",
        &licence.id,
    )
    .await;
    assert_eq!(request.status, StatusCode::CREATED);
    let id = request.body["id"].as_str().unwrap();
    let owner_uri = format!("/v1/records/scope-corrections/{id}?accessProfile=holder");
    let page = get_record(&app, &owner_uri, holder("holder-a", "person:a")).await;
    let submit = action(&page.body, "submit_request", None);
    assert_eq!(
        send_action(
            &app,
            &submit,
            "context-submit",
            holder("holder-a", "person:a"),
            json!({})
        )
        .await
        .status,
        StatusCode::OK
    );
    let reviewer_claims = actor(
        "reviewer",
        "reviewer",
        Some(VerifiedClaimValue::direct_string("person:a").unwrap()),
    );
    let reviewer_uri = format!("/v1/records/scope-corrections/{id}?accessProfile=reviewer");
    let before = get_record(&app, &reviewer_uri, reviewer_claims.clone()).await;
    assert!(before.body.to_string().contains("prior scope canary"));
    let entity = &registry.entities()["professional-license"];
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{} SET {} = 'person:b' WHERE record_id = $1::text::uuid",
                quote(&entity.physical_table),
                quote(&entity.fields["person-reference"].physical_name)
            ),
            &[&licence.id],
        )
        .await
        .unwrap();
    let after = get_record(&app, &reviewer_uri, reviewer_claims).await;
    assert_eq!(after.status, StatusCode::OK);
    assert!(
        !after.body.to_string().contains("prior scope canary"),
        "frozen target context must not bypass current authority"
    );
    database.cleanup().await;
}

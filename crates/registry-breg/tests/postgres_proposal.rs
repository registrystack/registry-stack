// SPDX-License-Identifier: Apache-2.0
//! Durable Proposal journeys over the public client and PostgreSQL RLS.
#![cfg(feature = "postgres-test")]
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use registry_breg::api::{VerifiedClaimValue, VerifiedRequestClaims};
use registry_breg::compiler::{compile_project, compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_json, ModuleAssetSource};
use registry_breg_client::{
    BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
    BRegProblemCode, BRegProposalDecisionStatus, BRegProposalQuery, BRegProposalState,
    BRegProposalTurn, BRegRecordFormat,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

fn claims(subject: &str, jurisdiction: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        subject,
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string(jurisdiction).unwrap(),
        )]),
        registry_platform_oidc::ActorKind::Human,
    )
    .unwrap()
}
fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).unwrap()
}
fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}
async fn application_queue_age(fixture: &client_http::ClientFixture) -> f64 {
    use tower::util::ServiceExt;
    let router = registry_breg::metrics::metrics_app(std::sync::Arc::new(
        registry_breg::metrics::Metrics::with_pool_for_test(fixture.pool.clone()),
    ));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri("/metrics")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
        .await
        .unwrap();
    let rendered = std::str::from_utf8(&bytes).unwrap();
    rendered
        .lines()
        .find_map(|line| {
            line.strip_prefix(
                "breg_queue_oldest_pending_age_seconds{queue=\"review-application\"} ",
            )
        })
        .expect("current Proposal tables produce the queue sample")
        .parse()
        .unwrap()
}
fn registry_source(automatic: bool) -> Value {
    let source = json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"proposal-test","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://proposal.example.test"},
        "datasets":[{"id":"directory"}],
        "recordTypes":[{"id":"target","primaryDataset":"directory","route":"targets","mutationMode":"mutable",
            "mutationPolicy":{"patch":"proposal-required"},
            "fields":[{"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"}]}],
        "actions":[{"id":"correct-name","execution":{"mode":"proposal","proposal":{
            "review":{"type":"none"},"application":if automatic{json!({"mode":"automatic","maximumAttempts":3})}else{json!({"mode":"manual"})},
            "retention":{"mode":"operator-erase"},"attachments":[{"id":"support","required":false,"maximumBytes":4096,
                "contentTypes":["text/plain"],"classification":"restricted"}]}},
            "inputs":[{"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
                {"id":"value","type":"string","required":true,"maximumLength":64,"classification":"internal"}],
            "commitGuards":{"targets":[{"input":"target","revision":"unchanged"}]},
            "plan":{"type":"fixed","effects":[{"id":"name","target":{"fromInput":"target"},"operation":"patch","set":{"name":{"fromInput":"value"}}}]}}],
        "accessProfiles":[{"id":"clerk","default":true,"principalClaim":"sub","requiredScopes":["proposal:manage"],
            "requiredPurposes":["registry-administration"],"permissions":{
                "records":[{"recordType":"target","operations":["create","get","list"],"readableFields":["name","jurisdiction"],
                    "writableFields":["name","jurisdiction"],"rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}],
                "actions":[{"action":"correct-name","operations":["start"],"targets":[{"recordType":"target",
                    "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}],
                "proposals":[{"action":"correct-name","operations":["get","list","edit","submit","revise","rebase","retry","cancel","apply"],
                    "ownership":"caller","readableAttachments":["support"],"writableAttachments":["support"],"targets":[{"recordType":"target",
                    "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}]}}]});
    source
}
fn compile(source: Value) -> registry_breg::CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).expect("standalone Proposal compiles")
}
fn registry(automatic: bool) -> registry_breg::CompiledRegistry {
    compile(registry_source(automatic))
}

#[tokio::test]
async fn holder_identity_is_a_draft_value_but_submit_authority_remains_server_owned() {
    let mut source = registry_source(false);
    source["accessProfiles"][0]["default"] = json!(false);
    source["recordTypes"][0]
        .as_object_mut()
        .unwrap()
        .remove("mutationPolicy");
    source["recordTypes"][0]["fields"][1]["id"] = json!("applicant");
    source["actions"][0]["inputs"][0] = json!({"id":"applicant","type":"string","maximumLength":64,"required":true,"classification":"internal"});
    source["actions"][0]["commitGuards"] = json!({});
    source["actions"][0]["plan"] = json!({"type":"fixed","effects":[{"id":"application","operation":"create","target":{"recordType":"target"},"set":{"name":{"fromInput":"value"},"applicant":{"fromInput":"applicant"}}}]});
    source["accessProfiles"][0]["permissions"]["records"] = json!([{"recordType":"target","operations":["get","list"],"readableFields":["name","applicant"],"rowBoundaries":[{"field":"applicant","claim":"sub","operator":"equals"}]}]);
    for family in ["actions", "proposals"] {
        source["accessProfiles"][0]["permissions"][family][0]["targets"][0]["rowBoundaries"] =
            json!([{"field":"applicant","claim":"sub","operator":"equals"}]);
    }
    let mut staff = source["accessProfiles"][0].clone();
    staff["id"] = json!("on-behalf");
    staff["default"] = json!(false);
    staff["requiredScopes"] = json!(["proposal:staff"]);
    for family in ["records", "actions", "proposals"] {
        let grant = &mut staff["permissions"][family][0];
        if family == "records" {
            grant["rowBoundaries"] = json!("unrestricted");
        } else {
            grant["targets"][0]["rowBoundaries"] = json!("unrestricted");
        }
    }
    source["accessProfiles"].as_array_mut().unwrap().push(staff);
    let holder = VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        "holder",
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "sub".into(),
            VerifiedClaimValue::direct_string("holder").unwrap(),
        )]),
        registry_platform_oidc::ActorKind::Human,
    )
    .unwrap();
    let fixture = client_http::ClientFixture::start(compile(source), holder).await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap().value;
    assert!(metadata.select_action("correct-name", "on-behalf").is_err());
    let action = metadata.select_action("correct-name", "clerk").unwrap();
    for suffix in [
        "",
        "?accessProfile=on-behalf",
        "?accessProfile=unknown-profile-canary",
    ] {
        let response = reqwest::Client::new()
            .post(format!(
                "{}{}{suffix}",
                fixture.http.base_url,
                action.invoke_path()
            ))
            .header("Idempotency-Key", "concealed-profile")
            .json(&json!({"input":{"applicant":"holder","value":"Application"}}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
        let problem: Value = response.json().await.unwrap();
        assert_eq!(problem["code"], "resource.not_found");
        for hidden in ["on-behalf", "unknown-profile-canary", "clerk"] {
            assert!(!problem.to_string().contains(hidden));
        }
    }
    // An incomplete or mismatched draft executes no plan and discloses no target existence.
    for (index, applicant) in ["holder", "another-holder"].into_iter().enumerate() {
        let request = BRegActionInvocationRequest::new(
            &action,
            map(json!({"applicant":applicant,"value":"Application"})),
            None,
        )
        .unwrap();
        let draft = client
            .start_proposal(&action, &request, &key(&format!("holder-start-{index}")))
            .await
            .unwrap()
            .value;
        let submit = client
            .prepare_proposal(
                &draft,
                "submit",
                json!({}),
                &key(&format!("holder-submit-{index}")),
            )
            .unwrap();
        let result = client.execute_proposal(&submit).await;
        if applicant == "holder" {
            assert_eq!(result.unwrap().value.state(), BRegProposalState::Submitted);
        } else {
            assert!(
                result.is_err(),
                "client-filled identity cannot create authority"
            );
        }
    }
    let staff_claims = VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        "officer",
        BTreeSet::from(["proposal:staff".into()]),
        Some("registry-administration".into()),
        BTreeMap::new(),
        registry_platform_oidc::ActorKind::Human,
    )
    .unwrap();
    let staff = fixture.client_for(staff_claims).await;
    let metadata = staff
        .client
        .registry_contract(Some("on-behalf"))
        .await
        .unwrap()
        .value;
    let action = metadata.select_action("correct-name", "on-behalf").unwrap();
    let request = BRegActionInvocationRequest::new(
        &action,
        map(json!({"applicant":"another-holder","value":"Staff application"})),
        None,
    )
    .unwrap();
    let draft = staff
        .client
        .start_proposal(&action, &request, &key("on-behalf-start"))
        .await
        .unwrap()
        .value;
    let submit = staff
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("on-behalf-submit"))
        .unwrap();
    assert_eq!(
        staff
            .client
            .execute_proposal(&submit)
            .await
            .unwrap()
            .value
            .state(),
        BRegProposalState::Submitted
    );
    drop(staff);
    fixture.finish().await;
}

#[tokio::test]
async fn required_inputs_are_completed_at_submit_and_supplied_draft_values_stay_typed() {
    let mut source = registry_source(false);
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableInputs"] =
        json!(["target", "value"]);
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let request = BRegActionInvocationRequest::new(&action, Map::new(), None)
        .expect("a required input may be absent in a Proposal draft");
    let draft = client
        .start_proposal(&action, &request, &key("incomplete-start"))
        .await
        .unwrap()
        .value;
    assert_eq!(draft.state(), BRegProposalState::Draft);
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("incomplete-submit"))
        .unwrap();
    let error = client.execute_proposal(&submit).await.unwrap_err();
    let registry_breg_client::BaseRegistryClientError::Problem {
        code, field_path, ..
    } = error
    else {
        panic!("bounded problem")
    };
    assert_eq!(code, BRegProblemCode::RequestInvalid);
    assert_eq!(field_path.unwrap().as_str(), "/input/target");
    assert!(BRegActionInvocationRequest::new(&action, map(json!({"value":42})), None).is_err());
    for (index, value) in [json!(42), Value::Null, json!(["value-canary"])]
        .into_iter()
        .enumerate()
    {
        let response = reqwest::Client::new()
            .post(format!(
                "{}{}?accessProfile=clerk",
                fixture.http.base_url,
                action.invoke_path()
            ))
            .header("Idempotency-Key", format!("draft-invalid-{index}"))
            .json(&json!({"input":{"value":value}}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        let problem: Value = response.json().await.unwrap();
        assert_eq!(problem["code"], "request.invalid");
        assert!(!problem.to_string().contains("value-canary"));
    }

    let complete = start(&fixture, "Completed", "complete-source").await;
    let complete = client.read_proposal(&complete).await.unwrap().value;
    let edit = client
        .prepare_proposal(
            &draft,
            "edit",
            json!({"input":complete.input().unwrap()}),
            &key("incomplete-edit"),
        )
        .unwrap();
    let edited = client.execute_proposal(&edit).await.unwrap().value;
    let submit = client
        .prepare_proposal(&edited, "submit", json!({}), &key("complete-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    assert_eq!(submitted.state(), BRegProposalState::Submitted);
    assert!(submitted.effect_digest().is_some());
    let revise = client
        .prepare_proposal(
            &submitted,
            "revise",
            json!({"input":{}}),
            &key("incomplete-revise"),
        )
        .unwrap();
    let revised = client.execute_proposal(&revise).await.unwrap().value;
    assert_eq!(revised.state(), BRegProposalState::Draft);
    assert_eq!(revised.submission_version(), 2);
    let revised = client.read_proposal(&revised).await.unwrap().value;
    assert!(revised.input().unwrap().is_empty());
    let rebase = client
        .prepare_proposal(
            &revised,
            "rebase",
            json!({"input":{}}),
            &key("incomplete-rebase"),
        )
        .unwrap();
    let rebased = client.execute_proposal(&rebase).await.unwrap().value;
    assert_eq!(rebased.state(), BRegProposalState::Draft);
    let submit = client
        .prepare_proposal(&rebased, "submit", json!({}), &key("incomplete-resubmit"))
        .unwrap();
    assert_eq!(
        client
            .execute_proposal(&submit)
            .await
            .unwrap_err()
            .problem_code(),
        Some(BRegProblemCode::RequestInvalid)
    );
    fixture.finish().await;
}

#[tokio::test]
async fn pending_manual_application_filter_precedes_pagination_and_keeps_authority() {
    let mut source = registry_source(false);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let unreviewed = source["actions"][0].clone();
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":{"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))}});
    for (id, automatic) in [("unreviewed-name", false), ("automatic-name", true)] {
        let mut action = unreviewed.clone();
        action["id"] = json!(id);
        if automatic {
            action["execution"]["proposal"]["application"] =
                json!({"mode":"automatic","maximumAttempts":3});
        }
        source["actions"].as_array_mut().unwrap().push(action);
        for family in ["actions", "proposals"] {
            let mut grant = source["accessProfiles"][0]["permissions"][family][0].clone();
            grant["action"] = json!(id);
            source["accessProfiles"][0]["permissions"][family]
                .as_array_mut()
                .unwrap()
                .push(grant);
        }
    }
    let review = std::sync::Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let injected = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
        },
    )
    .await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap().value;
    let collection = metadata.select_proposals("clerk").unwrap();
    for query in [
        "pendingManualApplication=TRUE",
        "pendingManualApplication=true&pendingManualApplication=false",
    ] {
        let response = reqwest::Client::new()
            .get(format!(
                "{}/v1/proposals?accessProfile=clerk&{query}",
                fixture.http.base_url
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "malformed list queries preserve concealment"
        );
    }
    let mut expected = BTreeSet::new();
    let mut drafts = Vec::new();
    for index in 0..24 {
        drafts.push(start(&fixture, "Queue", &format!("queue-{index}")).await);
    }
    drafts.sort_by(|left, right| left.id().cmp(right.id()));
    // More nonmatching rows than the eight-row scan bound sort before all
    // required-review matches. UUID randomness cannot mask post-scan filtering.
    for (index, draft) in drafts.iter().enumerate().skip(12) {
        let submit = client
            .prepare_proposal(
                draft,
                "submit",
                json!({}),
                &key(&format!("queue-submit-{index}")),
            )
            .unwrap();
        let submitted = client.execute_proposal(&submit).await.unwrap().value;
        let category = (index - 12) % 6;
        if category != 0 {
            let status = if category == 3 {
                registry_review_client::ReviewResultStatus::ChangesRequested
            } else {
                registry_review_client::ReviewResultStatus::Approved
            };
            retain_queue_review(
                &fixture,
                &submitted,
                &review,
                status,
                category == 2,
                category == 4 && index == 16,
            )
            .await;
        }
        if category == 1 {
            expected.insert(submitted.id().to_owned());
        }
        if category == 5 {
            let id = uuid::Uuid::parse_str(submitted.id()).unwrap();
            fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET withdrawn=true WHERE proposal_id=$1", &[&id]).await.unwrap();
            let current = client.read_proposal(&submitted).await.unwrap().value;
            assert_ne!(
                serde_json::to_value(&current).unwrap()["applicationStatus"]["state"],
                "pending"
            );
        }
        if category == 4 {
            let current = client.read_proposal(&submitted).await.unwrap().value;
            let (operation, body) = if index == 16 {
                (
                    "apply",
                    json!({"submissionVersion":current.submission_version(),"effectDigest":current.effect_digest().unwrap()}),
                )
            } else {
                ("cancel", json!({}))
            };
            let attempt = client
                .prepare_proposal(
                    &current,
                    operation,
                    body,
                    &key(&format!("queue-terminal-{index}")),
                )
                .unwrap();
            client.execute_proposal(&attempt).await.unwrap();
        }
    }
    for id in ["unreviewed-name", "automatic-name"] {
        let draft = start_action(&fixture, id, "Queue", &format!("queue-{id}")).await;
        let submit = client
            .prepare_proposal(
                &draft,
                "submit",
                json!({}),
                &key(&format!("queue-submit-{id}")),
            )
            .unwrap();
        let submitted = client.execute_proposal(&submit).await.unwrap().value;
        if id == "unreviewed-name" {
            expected.insert(submitted.id().to_owned());
        }
    }
    let calls = review.calls.load(std::sync::atomic::Ordering::SeqCst);
    let plan = fixture
        .mutations
        .pending_manual_list_plan_for_test(&[
            "correct-name".into(),
            "unreviewed-name".into(),
            "automatic-name".into(),
        ])
        .await
        .unwrap();
    assert_eq!(plan[0]["Plan"]["Node Type"], "Limit");
    assert!(plan.to_string().contains("applicationPolicy"));
    let mut query = BRegProposalQuery {
        pending_manual_application: true,
        limit: Some(2),
        ..Default::default()
    };
    let mut observed = BTreeSet::new();
    loop {
        let page = client
            .list_proposals(&collection, &query)
            .await
            .unwrap()
            .value;
        assert!(!page.items.is_empty());
        for item in &page.items {
            assert!(
                observed.insert(item.id().to_owned()),
                "each result occurs once"
            );
            let value = serde_json::to_value(item).unwrap();
            assert_eq!(value["applicationStatus"]["mode"], "manual");
            assert_eq!(value["applicationStatus"]["state"], "pending");
        }
        query.cursor = page.next_cursor;
        if query.cursor.is_none() {
            break;
        }
    }
    assert_eq!(observed, expected);
    assert_eq!(
        review.calls.load(std::sync::atomic::Ordering::SeqCst),
        calls,
        "listing performs no per-Proposal Review calls"
    );
    let other = fixture.client_for(claims("other", "zone-a")).await;
    let metadata = other
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap()
        .value;
    let page = other
        .client
        .list_proposals(
            &metadata.select_proposals("clerk").unwrap(),
            &BRegProposalQuery {
                pending_manual_application: true,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .value;
    assert!(page.items.is_empty());
    assert!(
        page.next_cursor.is_none(),
        "a concealed collection has no continuation"
    );
    drop(other);
    fixture.finish().await;
}

#[tokio::test]
async fn proposal_list_scans_hidden_rows_without_exposing_their_continuation() {
    let mut source = registry_source(false);
    source["accessProfiles"][0]["permissions"]["proposals"][0]
        .as_object_mut()
        .unwrap()
        .remove("ownership");
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    let mut drafts = Vec::new();
    for index in 0..12 {
        let draft = start(&fixture, "Visible", &format!("concealed-prefix-{index}")).await;
        let submit = fixture
            .http
            .client
            .prepare_proposal(
                &draft,
                "submit",
                json!({}),
                &key(&format!("concealed-submit-{index}")),
            )
            .unwrap();
        drafts.push(
            fixture
                .http
                .client
                .execute_proposal(&submit)
                .await
                .unwrap()
                .value,
        );
    }
    drafts.sort_by(|left, right| left.id().cmp(right.id()));
    let visible = drafts.last().unwrap();
    let id = uuid::Uuid::parse_str(visible.id()).unwrap();
    let input: Value = fixture
        .database
        .admin
        .query_one(
            "SELECT input FROM registry_internal.registry_proposal_state WHERE proposal_id=$1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    let target = uuid::Uuid::parse_str(input["target"].as_str().unwrap()).unwrap();
    let entity = &fixture.registry.entities()["target"];
    fixture
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.\"{}\" SET \"{}\"=$2 WHERE record_id=$1",
                entity.physical_table, entity.fields["jurisdiction"].physical_name
            ),
            &[&target, &"zone-b"],
        )
        .await
        .unwrap();
    for (jurisdiction, expected) in [("zone-c", None), ("zone-b", Some(visible.id()))] {
        let reader = fixture.client_for(claims("reader", jurisdiction)).await;
        let metadata = reader
            .client
            .registry_contract(Some("clerk"))
            .await
            .unwrap()
            .value;
        let page = reader
            .client
            .list_proposals(
                &metadata.select_proposals("clerk").unwrap(),
                &BRegProposalQuery {
                    pending_manual_application: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .value;
        assert_eq!(
            page.items.iter().map(|item| item.id()).collect::<Vec<_>>(),
            expected.into_iter().collect::<Vec<_>>()
        );
        assert!(
            page.next_cursor.is_none(),
            "hidden UUIDs never become cursors"
        );
        drop(reader);
    }
    fixture.finish().await;
}

#[tokio::test]
async fn proposal_list_deadline_refuses_a_partial_page_and_cancels_the_wait() {
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(false),
        claims("author", "zone-a"),
        |mutations| mutations.with_action_timeout_for_test(std::time::Duration::from_secs(2)),
    )
    .await;
    let mut drafts = Vec::new();
    for index in 0..2 {
        drafts.push(start(&fixture, "Draft", &format!("deadline-draft-{index}")).await);
    }
    drafts.sort_by(|left, right| left.id().cmp(right.id()));
    let id = uuid::Uuid::parse_str(drafts[1].id()).unwrap();
    let (mut blocker, task) = fixture.database.connect_migration().await;
    let transaction = blocker.transaction().await.unwrap();
    transaction.query_one("SELECT proposal_id FROM registry_internal.registry_proposal_state WHERE proposal_id=$1 FOR UPDATE", &[&id]).await.unwrap();
    let metadata = fixture
        .http
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap()
        .value;
    let error = fixture
        .http
        .client
        .list_proposals(
            &metadata.select_proposals("clerk").unwrap(),
            &BRegProposalQuery::default(),
        )
        .await
        .err()
        .expect("a deadline cannot return partial success");
    assert_eq!(
        error.problem_code(),
        Some(BRegProblemCode::ServiceUnavailable)
    );
    let waits: i64 = fixture.database.admin.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%registry_proposal_state%' AND query LIKE '%FOR SHARE%'", &[]).await.unwrap().get(0);
    assert_eq!(
        waits, 0,
        "the timed-out list releases its query and connection"
    );
    transaction.rollback().await.unwrap();
    drop(blocker);
    task.abort();
    fixture.finish().await;
}

async fn retain_queue_review(
    fixture: &client_http::ClientFixture,
    proposal: &registry_breg_client::BRegProposal,
    review: &LocalReview,
    status: registry_review_client::ReviewResultStatus,
    expired: bool,
    apply_result: bool,
) {
    let id = uuid::Uuid::parse_str(proposal.id()).unwrap();
    let version = i64::from(proposal.submission_version());
    let row = fixture.database.admin.query_one("SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1 AND submission_version=$2", &[&id,&version]).await.unwrap();
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(row.get(0)).unwrap();
    let accepted = registry_review_client::ReviewRequestAccepted {
        request_id: uuid::Uuid::new_v4(),
        subject: create.subject,
        policy: serde_json::from_value(serde_json::to_value(create.policy).unwrap()).unwrap(),
        submission_digest: serde_json::from_value(json!(row.get::<_, String>(1))).unwrap(),
    };
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1 WHERE proposal_id=$2 AND submission_version=$3", &[&serde_json::to_value(&accepted).unwrap(),&id,&version]).await.unwrap();
    let mut result = review.result(&accepted);
    if !apply_result {
        result.result_id = uuid::Uuid::new_v4();
    }
    result.status = status;
    result.outcome = Some(
        if status == registry_review_client::ReviewResultStatus::ChangesRequested {
            "changes-requested"
        } else {
            "approved"
        }
        .to_owned(),
    );
    if status == registry_review_client::ReviewResultStatus::ChangesRequested {
        result.public_reason = Some("Confirm the final terms.".into());
    }
    if expired {
        result.completed_at = chrono::Utc::now() - chrono::Duration::hours(2);
        result.available_until = chrono::Utc::now() - chrono::Duration::hours(1);
    }
    let status = serde_json::to_value(status)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    fixture.database.admin.execute("INSERT INTO registry_internal.registry_proposal_review_results (action_id,proposal_id,submission_version,authority,result_id,result,status,completed_at,available_until) VALUES ('correct-name',$1,$2,'local-review',$3,$4,$5,$6,$7)", &[&id,&version,&result.result_id,&serde_json::to_value(&result).unwrap(),&status,&result.completed_at,&result.available_until]).await.unwrap();
}

async fn proposal_state_lock_wait(fixture: &client_http::ClientFixture, minimum: i64) -> bool {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: i64 = fixture
                .database
                .admin
                .query_one(
                    "SELECT count(*) FROM pg_stat_activity
                 WHERE datname=current_database() AND wait_event_type='Lock'
                   AND query LIKE '%registry_proposal_state%'
                   AND (query LIKE '%FOR UPDATE%' OR query LIKE '%FOR SHARE%')",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            if waiting >= minimum {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn coherent_observation_waits_for_automatic_application() {
    use std::time::Duration;
    let fixture =
        client_http::ClientFixture::start(registry(true), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Coherent", "coherent-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("coherent-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let table = &fixture.registry.entities()["target"].physical_table;
    // Pause the actual automatic write after it owns the lifecycle row. The
    // advisory lock is only a deterministic fixture barrier, not a runtime hook.
    fixture.database.admin.batch_execute(&format!(
        "CREATE FUNCTION registry_data.pause_application() RETURNS trigger LANGUAGE plpgsql AS $body$
         BEGIN PERFORM pg_advisory_xact_lock(732995001); RETURN NEW; END $body$;
         CREATE TRIGGER pause_application BEFORE UPDATE ON registry_data.\"{table}\"
         FOR EACH ROW EXECUTE FUNCTION registry_data.pause_application()"
    )).await.unwrap();
    let (barrier, barrier_task) = fixture.database.connect_migration().await;
    barrier
        .execute("SELECT pg_advisory_lock(732995001)", &[])
        .await
        .unwrap();
    let mutations = fixture.mutations.clone();
    let applying =
        tokio::spawn(async move { mutations.run_automatic_proposal_once_for_test().await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: i64 = fixture
                .database
                .admin
                .query_one(
                    "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted
                 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            if waiting != 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("automatic writer reached the fixture barrier while owning Proposal state");
    {
        let observation = client.read_proposal(&submitted);
        tokio::pin!(observation);
        let query = BRegProposalQuery::default();
        let listing = client.list_proposals(&collection, &query);
        tokio::pin!(listing);
        let waited = tokio::select! {
            _ = &mut observation => false,
            _ = &mut listing => false,
            waited = proposal_state_lock_wait(&fixture, 2) => waited,
        };
        // Always release the writer, including on the pre-fix failure path.
        barrier
            .execute("SELECT pg_advisory_unlock(732995001)", &[])
            .await
            .unwrap();
        assert!(applying.await.unwrap().unwrap());
        assert!(
            waited,
            "a composed observation must wait for the lifecycle writer"
        );
        let current = observation.await.unwrap().value;
        assert_eq!(current.state(), BRegProposalState::Applied);
        assert_eq!(
            current.application().unwrap().effect_digest.as_str(),
            submitted.effect_digest().unwrap()
        );
        let page = listing.await.unwrap().value;
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].state(), BRegProposalState::Applied);
        assert_eq!(page.items[0].effect_digest(), submitted.effect_digest());
        drop(barrier);
        barrier_task.abort();
    }
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn coherent_observation_fences_review_approval_and_job_creation() {
    let mut source = registry_source(true);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}", "b".repeat(64))});
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
    let review = std::sync::Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let injected = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
        },
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Reviewed coherent", "coherent-review-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("coherent-review-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let row = fixture.database.admin.query_one("SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions", &[]).await.unwrap();
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(row.get(0)).unwrap();
    let accepted = registry_review_client::ReviewRequestAccepted {
        request_id: uuid::Uuid::new_v4(),
        subject: create.subject,
        policy: serde_json::from_value(policy).unwrap(),
        submission_digest: serde_json::from_value(json!(row.get::<_, String>(1))).unwrap(),
    };
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1", &[&serde_json::to_value(&accepted).unwrap()]).await.unwrap();
    let result = review.result(&accepted);
    let (mut reader, reader_task) = fixture.database.connect_migration().await;
    let read = reader.transaction().await.unwrap();
    // A read may already have observed job absence. Approval plus job enqueue
    // must wait for that same lifecycle observation to finish.
    read.query_one("SELECT proposal_id FROM registry_internal.registry_proposal_state WHERE proposal_id=$1 FOR UPDATE", &[&uuid::Uuid::parse_str(submitted.id()).unwrap()]).await.unwrap();
    assert_eq!(
        read.query_one(
            "SELECT count(*) FROM registry_internal.registry_proposal_application_jobs",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    let (mut writer, writer_task) = fixture.database.connect_migration().await;
    let write = writer.transaction().await.unwrap();
    let retained = {
        let reconciliation = registry_breg::review_store::reconcile_result(
            &write,
            "local-review",
            &accepted,
            &result,
            &fixture.mutations,
        );
        tokio::pin!(reconciliation);
        let waited = tokio::select! {
            _ = &mut reconciliation => false,
            waited = proposal_state_lock_wait(&fixture, 1) => waited,
        };
        let retained: i64 = read
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_proposal_review_results",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        read.commit().await.unwrap();
        assert!(
            waited,
            "approval and automatic enqueue must take state before submission/job locks"
        );
        reconciliation.await.unwrap();
        retained
    };
    write.commit().await.unwrap();
    assert_eq!(retained, 0);
    let current = client.read_proposal(&submitted).await.unwrap().value;
    assert_eq!(current.state(), BRegProposalState::Submitted);
    assert_eq!(
        serde_json::to_value(current).unwrap()["applicationStatus"]["state"],
        "pending"
    );
    assert_eq!(
        fixture
            .database
            .admin
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_proposal_application_jobs",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    drop(reader);
    drop(writer);
    reader_task.abort();
    writer_task.abort();
    fixture.finish().await;
}

#[test]
fn proposal_input_disclosure_grants_require_declared_inputs_and_get_authority() {
    for (readable, operations) in [
        (json!(["missing"]), json!(["get"])),
        (json!(["value"]), json!(["list"])),
    ] {
        let mut source = registry_source(false);
        source["accessProfiles"][0]["permissions"]["proposals"][0]["readableInputs"] = readable;
        source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"] = operations;
        source["accessProfiles"][0]["permissions"]["proposals"][0]["readableAttachments"] =
            json!([]);
        source["accessProfiles"][0]["permissions"]["proposals"][0]["writableAttachments"] =
            json!([]);
        let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
        let error = compile_project(&project, &[], CompileProfile::Authoring).unwrap_err();
        assert!(format!("{error:?}").contains("breg.proposal.input-grant-invalid"));
    }
}

async fn start(
    fixture: &client_http::ClientFixture,
    value: &str,
    key_name: &str,
) -> registry_breg_client::BRegProposal {
    start_action(fixture, "correct-name", value, key_name).await
}

async fn start_action(
    fixture: &client_http::ClientFixture,
    action_id: &str,
    value: &str,
    key_name: &str,
) -> registry_breg_client::BRegProposal {
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Before","jurisdiction":"zone-a"}))).unwrap(),
            &key(&format!("{key_name}-record")),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let action = metadata.value.select_action(action_id, "clerk").unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"target":record.value.data.record_identifier,"value":value})),
        None,
    )
    .unwrap();
    client
        .start_proposal(&action, &input, &key(key_name))
        .await
        .unwrap()
        .value
}

#[tokio::test]
async fn known_proposal_http_authorization_refusals_are_value_free_and_audit_gated() {
    let mut source = registry_source(false);
    source["actions"][0]["execution"]["proposal"]["reviewContext"] = json!({
        "id":"review-name","fields":{
            "currentName":{"type":"record","input":"target","field":"name"},
            "proposedName":{"type":"input","input":"value"}}});
    for id in [
        "reviewer",
        "missing-record-claim",
        "rebase-only",
        "no-bytes",
        "no-lifecycle",
    ] {
        let mut profile = source["accessProfiles"][0].clone();
        profile["id"] = json!(id);
        profile["default"] = json!(false);
        match id {
            "reviewer" | "missing-record-claim" => {
                profile["permissions"]["proposals"][0]["operations"] =
                    json!(["get", "get-review-context", "get-review-status"]);
                profile["permissions"]["proposals"][0]["readableContextFields"] =
                    json!(["currentName", "proposedName"]);
                profile["permissions"]["proposals"][0]["writableAttachments"] = json!([]);
                if id == "missing-record-claim" {
                    profile["permissions"]["records"][0]["rowBoundaries"][0]["claim"] =
                        json!("recordZone");
                }
            }
            "rebase-only" => {
                profile["permissions"]["actions"] = json!([]);
            }
            "no-bytes" => {
                profile["permissions"]["proposals"][0]["readableAttachments"] = json!([]);
                profile["permissions"]["proposals"][0]["writableAttachments"] = json!([]);
            }
            "no-lifecycle" => {
                profile["permissions"]["proposals"] = json!([]);
            }
            _ => unreachable!(),
        }
        source["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .push(profile);
    }
    let fixture = client_http::ClientFixture::start(
        compile(source),
        claims("audit-private-principal-canary", "zone-a"),
    )
    .await;
    let draft = start(
        &fixture,
        "audit-private-value-canary",
        "audit-refusal-start",
    )
    .await;
    let uploaded = fixture
        .http
        .client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"audit-private-attachment-canary",
            &key("audit-refusal-upload"),
        )
        .await
        .unwrap()
        .value;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&uploaded, "submit", json!({}), &key("audit-refusal-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let id = submitted.id().to_owned();
    let cases = [
        (
            "GET",
            "review-context?accessProfile=clerk",
            "get-review-context",
        ),
        (
            "GET",
            "review-status?accessProfile=clerk",
            "get-review-status",
        ),
        (
            "GET",
            "review-context?accessProfile=missing-record-claim",
            "get-review-context",
        ),
        ("POST", "rebase?accessProfile=rebase-only", "rebase"),
        (
            "GET",
            "attachments/support?accessProfile=no-lifecycle&submissionVersion=1",
            "get",
        ),
        (
            "PATCH",
            "attachments/support?accessProfile=no-lifecycle",
            "edit",
        ),
        (
            "DELETE",
            "attachments/support?accessProfile=no-lifecycle",
            "edit",
        ),
        (
            "GET",
            "attachments/support?accessProfile=no-bytes&submissionVersion=1",
            "get",
        ),
        (
            "PATCH",
            "attachments/support?accessProfile=no-bytes",
            "edit",
        ),
        (
            "DELETE",
            "attachments/support?accessProfile=no-bytes",
            "edit",
        ),
    ];
    let mut unaudited = Vec::new();
    for (method, suffix, operation) in cases {
        let before = fixture.audit_capture.entries().len();
        let response = reqwest::Client::new()
            .request(
                method.parse().unwrap(),
                format!("{}/v1/proposals/{id}/{suffix}", fixture.http.base_url),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "{method} {suffix}"
        );
        assert!(response.headers().get("etag").is_none());
        let public = response.text().await.unwrap();
        let entries = fixture.audit_capture.entries();
        let refusals = entries[before..]
            .iter()
            .filter(|entry| entry["record"]["phase"] == "refusal")
            .collect::<Vec<_>>();
        if refusals.is_empty() {
            unaudited.push(format!("{method} {suffix}"));
            continue;
        }
        assert_eq!(refusals.len(), 1, "{method} {suffix}");
        let refusal = refusals[0];
        assert_eq!(refusal["record"]["actionId"], "correct-name");
        assert_eq!(
            refusal["record"]["operationId"],
            format!("proposals.correct-name.{operation}")
        );
        assert_eq!(refusal["record"]["method"], method);
        for canary in [
            "audit-private-principal-canary",
            "audit-private-value-canary",
            "audit-private-attachment-canary",
            id.as_str(),
        ] {
            assert!(
                !serde_json::to_string(&entries[before..])
                    .unwrap()
                    .contains(canary),
                "audit disclosed {canary}"
            );
            assert!(!public.contains(canary), "refusal disclosed {canary}");
        }
    }
    assert!(
        unaudited.is_empty(),
        "known Action refusals missed audit: {unaudited:?}"
    );
    for suffix in ["review-context", "review-status"] {
        let before = fixture.audit_capture.entries().len();
        let response = reqwest::get(format!(
            "{}/v1/proposals/{id}/{suffix}?accessProfile=reviewer",
            fixture.http.base_url
        ))
        .await
        .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK, "{suffix}");
        let entries = fixture.audit_capture.entries();
        assert_eq!(
            entries[before..].len(),
            2,
            "permitted {suffix} pairs its audit"
        );
        assert_eq!(entries[before]["phase"], "request");
        assert_eq!(entries[before + 1]["phase"], "response");
        assert_eq!(
            entries[before]["correlation"],
            entries[before + 1]["correlation"]
        );
    }
    for suffix in [
        "review-context?accessProfile=clerk",
        "attachments/support?accessProfile=no-bytes&submissionVersion=1",
    ] {
        let before = fixture.audit_capture.entries().len();
        let response = reqwest::get(format!(
            "{}/v1/proposals/{}/{suffix}",
            fixture.http.base_url,
            uuid::Uuid::new_v4()
        ))
        .await
        .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
        assert_eq!(
            fixture.audit_capture.entries().len(),
            before,
            "unknown Proposal has no known Action attribution"
        );
    }
    fixture.audit_capture.fail_after(0);
    for (method, suffix, _) in cases {
        let response = reqwest::Client::new()
            .request(
                method.parse().unwrap(),
                format!("{}/v1/proposals/{id}/{suffix}", fixture.http.base_url),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "{method} {suffix} must fail closed on audit loss"
        );
    }
    fixture.finish().await;
}

#[tokio::test]
async fn proposal_review_reads_release_no_values_when_either_audit_append_fails() {
    for (suffix, accepted) in [
        ("review-context", 0),
        ("review-context", 1),
        ("review-status", 0),
        ("review-status", 1),
    ] {
        let mut source = registry_source(false);
        source["actions"][0]["execution"]["proposal"]["reviewContext"] = json!({
            "id":"review-name","fields":{"proposedName":{"type":"input","input":"value"}}});
        source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"] =
            json!(["get", "submit", "get-review-context", "get-review-status"]);
        source["accessProfiles"][0]["permissions"]["proposals"][0]["readableContextFields"] =
            json!(["proposedName"]);
        source["accessProfiles"][0]["permissions"]["proposals"][0]["writableAttachments"] =
            json!([]);
        let fixture =
            client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
        let draft = start(&fixture, "audit-gate-value-canary", "audit-gate-start").await;
        let submit = fixture
            .http
            .client
            .prepare_proposal(&draft, "submit", json!({}), &key("audit-gate-submit"))
            .unwrap();
        let submitted = fixture
            .http
            .client
            .execute_proposal(&submit)
            .await
            .unwrap()
            .value;
        let before = fixture.audit_capture.entries().len();
        fixture.audit_capture.fail_after(accepted);
        let response = reqwest::get(format!(
            "{}/v1/proposals/{}/{suffix}?accessProfile=clerk",
            fixture.http.base_url,
            submitted.id()
        ))
        .await
        .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "{suffix}, {accepted} accepted appends"
        );
        assert!(response.headers().get("etag").is_none());
        assert!(!response
            .text()
            .await
            .unwrap()
            .contains("audit-gate-value-canary"));
        let entries = fixture.audit_capture.entries();
        assert_eq!(entries.len(), before + accepted);
        if accepted == 1 {
            assert_eq!(entries[before]["phase"], "request");
            assert_eq!(entries[before]["record"]["phase"], "attempt");
        }
        fixture.finish().await;
    }
}

#[tokio::test]
async fn proposal_list_pages_valid_large_inputs_without_losing_later_proposals() {
    let mut source = registry_source(false);
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"memo","type":"text","required":true,
            "maximumLength":320_000,"classification":"internal"}));
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableInputs"] = json!(["memo"]);
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    // JSON encoding makes this legal text input nearly 2 MiB on the wire.
    let large_value = "\u{0001}".repeat(320_000);
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Before","jurisdiction":"zone-a"}))).unwrap(),
            &key("large-list-record"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let mut created = BTreeSet::new();
    for index in 0..4 {
        let input = BRegActionInvocationRequest::new(
            &action,
            map(json!({"target":record.value.data.record_identifier,
                "value":"After","memo":large_value})),
            None,
        )
        .unwrap();
        let draft = client
            .start_proposal(&action, &input, &key(&format!("large-list-{index}")))
            .await
            .unwrap()
            .value;
        created.insert(draft.id().to_owned());
    }
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let mut seen = BTreeSet::new();
    let mut sizes = Vec::new();
    let mut cursor = None;
    loop {
        let page = client
            .list_proposals(
                &collection,
                &BRegProposalQuery {
                    cursor,
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .value;
        assert!(serde_json::to_vec(&page).unwrap().len() < 8 * 1024 * 1024);
        sizes.push(page.items.len());
        for item in page.items {
            assert_eq!(
                item.input().unwrap()["memo"].as_str(),
                Some(large_value.as_str())
            );
            assert!(seen.insert(item.id().to_owned()));
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
        assert!(sizes.len() < 4, "pagination must make progress");
    }
    assert_eq!(sizes, [2, 2]);
    assert_eq!(seen, created);
    fixture.finish().await;
}

#[tokio::test]
async fn manual_apply_unique_conflict_blocks_apply_while_stale_revision_stays_rebasable() {
    let mut source = registry_source(false);
    source["recordTypes"][0]["constraints"] =
        json!([{"id":"unique-name","type":"unique","fields":["name"]}]);
    let fixture =
        client_http::ClientFixture::start(compile(source.clone()), claims("author", "zone-a"))
            .await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();

    let original = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Original","jurisdiction":"zone-a"})))
                .unwrap(),
            &key("unique-apply-original"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap()
        .value;
    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"target":original.data.record_identifier,"value":"Reserved"})),
        None,
    )
    .unwrap();
    let draft = client
        .start_proposal(&action, &input, &key("unique-apply-start"))
        .await
        .unwrap()
        .value;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("unique-apply-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let pending_query = BRegProposalQuery {
        pending_manual_application: true,
        ..Default::default()
    };
    let pending = client
        .list_proposals(&collection, &pending_query)
        .await
        .unwrap()
        .value;
    assert!(pending.items.iter().any(|item| item.id() == submitted.id()));
    client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Reserved","jurisdiction":"zone-a"})))
                .unwrap(),
            &key("unique-apply-race"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let apply = client
        .prepare_proposal(
            &submitted,
            "apply",
            json!({"submissionVersion":submitted.submission_version(),
                "effectDigest":submitted.effect_digest().unwrap()}),
            &key("unique-apply-conflict"),
        )
        .unwrap();
    let audit_before = fixture.audit_capture.entries().len();
    let refusal = client.execute_proposal(&apply).await.unwrap_err();
    assert_eq!(
        refusal.problem_code(),
        Some(BRegProblemCode::MutationConflict)
    );
    assert!(
        refusal.constraint().is_none(),
        "unique conflict stays value-free"
    );
    let audit = fixture.audit_capture.entries();
    let terminal = audit[audit_before..]
        .iter()
        .find(|entry| {
            entry["record"]["phase"] == "terminal"
                && entry["record"]["operationId"] == "proposals.correct-name.apply"
        })
        .expect("the refused Apply records its terminal outcome");
    assert_eq!(terminal["record"]["outcome"], "refused");
    assert!(
        terminal["record"].get("changedInputs").is_none(),
        "a refused Apply reports no committed input changes"
    );
    assert!(
        terminal["record"].get("applicationReference").is_none(),
        "a refused Apply did not retain an application"
    );

    let blocked = client.read_proposal(&submitted).await.unwrap().value;
    let pending = client
        .list_proposals(&collection, &pending_query)
        .await
        .unwrap()
        .value;
    assert!(
        pending.items.iter().all(|item| item.id() != blocked.id()),
        "a durably refused Apply leaves the pending manual queue"
    );
    let blocked_json = serde_json::to_value(&blocked).unwrap();
    assert_eq!(blocked.state(), BRegProposalState::Submitted);
    assert_eq!(blocked.blocked_reason(), None);
    assert_eq!(blocked_json["applicationStatus"]["state"], "blocked");
    assert_eq!(
        blocked_json["applicationStatus"]["reason"],
        "application-refused"
    );
    assert_eq!(
        blocked_json["links"]["apply"]["availability"],
        json!({"available":false,"observedRevision":blocked.revision(),
            "reason":"invalid-input","recovery":"correct-input"})
    );
    assert!(
        blocked
            .link("rebase")
            .unwrap()
            .availability()
            .unwrap()
            .available
    );
    assert_eq!(
        client
            .execute_proposal(&apply)
            .await
            .unwrap_err()
            .problem_code(),
        Some(BRegProblemCode::PreconditionFailed),
        "the original Apply attempt is no longer executable"
    );
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_proposal_applications",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 0, "conflicting effects roll back");
    #[cfg(feature = "tooling")]
    let (compatible, blocked, create, action) = {
        let mut next = source;
        next["actions"][0]["display"] = json!({"label":"Correct the name"});
        let mut incompatible = next.clone();
        incompatible["actions"][0]["inputs"]
            .as_array_mut()
            .unwrap()
            .push(
                json!({"id":"activation-note","type":"string","maximumLength":32,
                "required":false,"classification":"internal"}),
            );
        let mut registry = (*fixture.registry).clone();
        let mut identity = fixture.identity.clone();
        let mut activated = None;
        for candidate in [&next, &incompatible, &next] {
            let (package, current_identity) = proposal_activation::activate_with_compatibility(
                &fixture, &registry, &identity, candidate, None,
            )
            .await;
            registry = package.registry().clone();
            identity = current_identity;
            let current = successor_client(&fixture, registry.clone(), identity.clone()).await;
            let metadata = current
                .client
                .registry_contract(Some("clerk"))
                .await
                .unwrap();
            let BRegDirectWrite::Create(create) = metadata
                .value
                .select_direct_write("records.target.create", "clerk")
                .unwrap()
            else {
                panic!("create");
            };
            let action = metadata
                .value
                .select_action("correct-name", "clerk")
                .unwrap();
            let collection = metadata.value.select_proposals("clerk").unwrap();
            let proposal = current
                .client
                .list_proposals(&collection, &BRegProposalQuery::default())
                .await
                .unwrap()
                .value
                .items
                .into_iter()
                .find(|proposal| proposal.id() == blocked.id())
                .expect("the refused Proposal remains listed after activation");
            let current_json = serde_json::to_value(&proposal).unwrap();
            assert_eq!(
                current_json["applicationStatus"]["reason"], "application-refused",
                "package activation retains the durable Apply refusal"
            );
            assert_eq!(proposal.effect_digest(), blocked.effect_digest());
            assert!(
                !proposal
                    .link("apply")
                    .unwrap()
                    .availability()
                    .unwrap()
                    .available
            );
            assert!(
                proposal
                    .link("rebase")
                    .unwrap()
                    .availability()
                    .unwrap()
                    .available
            );
            activated = Some((current, proposal, create, action));
        }
        activated.expect("the original Action is restored after the incompatible successor")
    };
    #[cfg(feature = "tooling")]
    let client = &compatible.client;
    let rebase = client
        .prepare_proposal(
            &blocked,
            "rebase",
            json!({"input":{"target":original.data.record_identifier,"value":"Reserved"}}),
            &key("unique-apply-rebase"),
        )
        .unwrap();
    let rebased = client.execute_proposal(&rebase).await.unwrap().value;
    assert_eq!(rebased.state(), BRegProposalState::Draft);
    assert!(rebased.application_status().is_none());
    assert!(rebased.blocked_reason().is_none());

    let stale_record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Stale","jurisdiction":"zone-a"}))).unwrap(),
            &key("stale-apply-record"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap()
        .value;
    let stale_input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"target":stale_record.data.record_identifier,"value":"Fresh"})),
        None,
    )
    .unwrap();
    let stale_draft = client
        .start_proposal(&action, &stale_input, &key("stale-apply-start"))
        .await
        .unwrap()
        .value;
    let stale_submit = client
        .prepare_proposal(
            &stale_draft,
            "submit",
            json!({}),
            &key("stale-apply-submit"),
        )
        .unwrap();
    let stale_submitted = client.execute_proposal(&stale_submit).await.unwrap().value;
    let entity = &fixture.registry.entities()["target"];
    let stale_id = uuid::Uuid::parse_str(&stale_record.data.record_identifier).unwrap();
    fixture
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.\"{}\" SET record_revision=record_revision+1 WHERE record_id=$1",
                entity.physical_table
            ),
            &[&stale_id],
        )
        .await
        .unwrap();
    let stale_apply = client
        .prepare_proposal(
            &stale_submitted,
            "apply",
            json!({"submissionVersion":stale_submitted.submission_version(),
                "effectDigest":stale_submitted.effect_digest().unwrap()}),
            &key("stale-apply-conflict"),
        )
        .unwrap();
    assert_eq!(
        client
            .execute_proposal(&stale_apply)
            .await
            .unwrap_err()
            .problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    let stale_current = client.read_proposal(&stale_submitted).await.unwrap().value;
    assert!(stale_current.blocked_reason().is_none());
    assert!(
        stale_current
            .link("apply")
            .unwrap()
            .availability()
            .unwrap()
            .available
    );
    assert!(
        stale_current
            .link("rebase")
            .unwrap()
            .availability()
            .unwrap()
            .available
    );
    fixture.finish().await;
}

#[tokio::test]
async fn proposal_list_pages_by_limit_and_refuses_top_naming_limit() {
    let fixture =
        client_http::ClientFixture::start(registry(false), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Before","jurisdiction":"zone-a"}))).unwrap(),
            &key("limit-list-record"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    for index in 0..2 {
        let input = BRegActionInvocationRequest::new(
            &action,
            map(json!({"target":record.value.data.record_identifier,"value":"After"})),
            None,
        )
        .unwrap();
        client
            .start_proposal(&action, &input, &key(&format!("limit-list-{index}")))
            .await
            .unwrap();
    }
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let page = client
        .list_proposals(
            &collection,
            &BRegProposalQuery {
                limit: Some(1),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .value;
    assert_eq!(page.items.len(), 1);
    assert!(page.next_cursor.is_some());
    let response = reqwest::get(format!(
        "{}/v1/proposals?accessProfile=clerk&top=1",
        fixture.http.base_url
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let problem: Value = response.json().await.unwrap();
    assert_eq!(problem["code"], "query.invalid", "{problem}");
    assert!(
        problem["detail"].as_str().unwrap().contains("`limit`"),
        "{problem}"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn proposal_turn_filter_pages_a_bounded_scan_without_gaps_or_duplicates() {
    use std::time::Duration;

    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(false),
        claims("author", "zone-a"),
        |mutations| mutations.with_action_timeout_for_test(Duration::from_secs(2)),
    )
    .await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Before","jurisdiction":"zone-a"}))).unwrap(),
            &key("turn-filter-record"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let mut expected = BTreeSet::new();
    for index in 0..70 {
        let input = BRegActionInvocationRequest::new(
            &action,
            map(json!({"target":record.value.data.record_identifier,"value":"After"})),
            None,
        )
        .unwrap();
        let draft = client
            .start_proposal(&action, &input, &key(&format!("turn-filter-{index}")))
            .await
            .unwrap()
            .value;
        if index % 23 == 0 {
            let submit = client
                .prepare_proposal(
                    &draft,
                    "submit",
                    json!({}),
                    &key(&format!("turn-filter-submit-{index}")),
                )
                .unwrap();
            let submitted = client.execute_proposal(&submit).await.unwrap().value;
            expected.insert(submitted.id().to_owned());
        }
    }
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let mut cursor = None;
    let mut seen = BTreeSet::new();
    let mut pages = 0usize;
    loop {
        let page = tokio::time::timeout(
            Duration::from_secs(3),
            client.list_proposals(
                &collection,
                &BRegProposalQuery {
                    cursor,
                    limit: Some(100),
                    turn: Some(BRegProposalTurn::Official),
                    ..Default::default()
                },
            ),
        )
        .await
        .expect("a turn-filtered page stays inside its bounded scan")
        .unwrap()
        .value;
        pages += 1;
        for item in page.items {
            assert_eq!(item.turn(), Some(BRegProposalTurn::Official));
            assert!(seen.insert(item.id().to_owned()), "Proposal repeated");
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
        assert!(pages < 12, "turn-filter pagination must make progress");
    }
    assert!(pages > 1, "the turn filter must stop at its scan budget");
    assert_eq!(seen, expected);
    fixture.finish().await;
}

#[tokio::test]
async fn proposal_list_audit_counts_only_each_actions_returned_items() {
    let mut source = registry_source(false);
    for id in ["correct-alternate", "correct-empty"] {
        let mut action = source["actions"][0].clone();
        action["id"] = json!(id);
        source["actions"].as_array_mut().unwrap().push(action);
        for permission in ["actions", "proposals"] {
            let mut grant = source["accessProfiles"][0]["permissions"][permission][0].clone();
            grant["action"] = json!(id);
            source["accessProfiles"][0]["permissions"][permission]
                .as_array_mut()
                .unwrap()
                .push(grant);
        }
    }
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    start(&fixture, "First", "audit-list-first").await;
    start(&fixture, "Second", "audit-list-second").await;
    start_action(&fixture, "correct-alternate", "Other", "audit-list-other").await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    for (action, expected) in [
        (None, [2usize, 1, 0]),
        (Some("correct-name"), [2, 0, 0]),
        (Some("correct-empty"), [0, 0, 0]),
    ] {
        let before = fixture.audit_capture.entries().len();
        let page = client
            .list_proposals(
                &collection,
                &BRegProposalQuery {
                    action: action.map(str::to_owned),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(page.value.items.len(), expected.iter().sum::<usize>());
        let entries = fixture.audit_capture.entries();
        let terminal = entries[before..]
            .iter()
            .filter_map(|entry| {
                let record = &entry["record"];
                (record["phase"] == "terminal"
                    && record["operationId"]
                        .as_str()
                        .is_some_and(|id| id.ends_with(".list")))
                .then_some(record)
            })
            .collect::<Vec<_>>();
        assert_eq!(terminal.len(), 3);
        for (id, count) in ["correct-name", "correct-alternate", "correct-empty"]
            .into_iter()
            .zip(expected)
        {
            let record = terminal
                .iter()
                .find(|record| record["actionId"] == id)
                .unwrap();
            assert_eq!(record["resultCount"], count, "{action:?}/{id}");
            assert_eq!(
                record["outcome"],
                if count == 0 { "empty" } else { "returned" }
            );
        }
    }
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn manual_no_review_attachments_cas_concealment_and_exact_receipt() {
    let fixture = client_http::ClientFixture::start(
        registry(false),
        claims("private-author-canary", "zone-a"),
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "After", "manual-start").await;
    assert_eq!(draft.state(), BRegProposalState::Draft);
    assert!(serde_json::to_value(&draft).unwrap().get("input").is_none());
    let uploaded = client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"synthetic-support",
            &key("manual-upload"),
        )
        .await
        .unwrap()
        .value;
    assert!(uploaded.revision() > draft.revision());
    assert_eq!(
        client
            .download_proposal_attachment(&uploaded, "support")
            .await
            .unwrap()
            .value
            .as_bytes(),
        b"synthetic-support"
    );
    let stale = client
        .prepare_proposal(&draft, "submit", json!({}), &key("manual-stale"))
        .unwrap();
    assert_eq!(
        client
            .execute_proposal(&stale)
            .await
            .unwrap_err()
            .problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    let submit = client
        .prepare_proposal(&uploaded, "submit", json!({}), &key("manual-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    assert_eq!(submitted.state(), BRegProposalState::Submitted);
    assert!(
        !submitted
            .link("retry")
            .unwrap()
            .availability()
            .unwrap()
            .available,
        "a manual no-review submission has no queued work to retry"
    );
    let provenance = fixture
        .database
        .admin
        .query_one(
            "SELECT submission.snapshot ->> 'originatingPackage', state.active_activation_id::text
         FROM registry_internal.registry_proposal_submissions AS submission
         CROSS JOIN registry_internal.registry_state AS state
         WHERE submission.proposal_id = $1 AND state.singleton",
            &[&uuid::Uuid::parse_str(submitted.id()).unwrap()],
        )
        .await
        .expect("native frozen submission retains its current activation provenance");
    let origin: String = provenance.get(0);
    assert_eq!(origin, provenance.get::<_, String>(1));
    assert!(!uuid::Uuid::parse_str(&origin).unwrap().is_nil());
    let apply = client
        .prepare_proposal(
            &submitted,
            "apply",
            json!({"submissionVersion":submitted.submission_version(),
        "effectDigest":submitted.effect_digest().unwrap(),"reason":"proposal-reason-canary"}),
            &key("manual-apply"),
        )
        .unwrap();
    let first = client.execute_proposal(&apply).await.unwrap();
    let replay = client.execute_proposal(&apply).await.unwrap();
    assert_eq!(
        serde_json::to_value(&first.value).unwrap(),
        serde_json::to_value(&replay.value).unwrap()
    );
    assert_eq!(first.value.state(), BRegProposalState::Applied);
    let public = serde_json::to_value(&first.value).unwrap();
    let serialized = serde_json::to_string(&public).unwrap();
    assert!(!serialized.contains("private-author-canary"));
    assert!(!serialized.contains("proposal-reason-canary"));
    for hidden in [
        "appliedBy",
        "appliedAt",
        "reason",
        "reasonPresent",
        "acceptedBinding",
        "result",
    ] {
        assert!(
            public["application"].get(hidden).is_none(),
            "internal application field {hidden}"
        );
    }
    let reason = fixture
        .database
        .admin
        .query_one(
            "SELECT reason FROM registry_internal.registry_proposal_applications",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(reason.get::<_, String>(0), "proposal-reason-canary");
    let rows = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_proposal_applications",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.get::<_, i64>(0), 1);
    let review_rows = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_proposal_review_submissions",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(review_rows.get::<_, i64>(0), 0);
    let observer = fixture.client_for(claims("other-author", "zone-a")).await;
    let hidden = observer
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let collection = hidden.value.select_proposals("clerk").unwrap();
    let page = observer
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap();
    assert!(page.value.items.is_empty());
    drop(observer);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attachment_binding_integrity_and_detail_erasure_preserve_record_history() {
    let fixture =
        client_http::ClientFixture::start(registry(false), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Retained record", "erase-start").await;
    let bytes = b"synthetic-support";
    let uploaded = client
        .upload_proposal_attachment(&draft, "support", "text/plain", bytes, &key("erase-upload"))
        .await
        .unwrap()
        .value;
    let mut corrupt = bytes.to_vec();
    corrupt[0] = b'X';
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_attachment_blobs SET content=$1",
            &[&corrupt],
        )
        .await
        .unwrap();
    assert!(client
        .download_proposal_attachment(&uploaded, "support")
        .await
        .is_err());
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_attachment_blobs SET content=$1",
            &[&bytes.to_vec()],
        )
        .await
        .unwrap();
    fixture.database.admin.execute("UPDATE registry_internal.registry_attachment_storage_binding SET verification_policy='different-policy'",&[]).await.unwrap();
    assert!(
        client
            .download_proposal_attachment(&uploaded, "support")
            .await
            .is_err(),
        "a changed verification binding cannot release bytes"
    );
    let wrong = client
        .prepare_proposal(&uploaded, "submit", json!({}), &key("erase-wrong-binding"))
        .unwrap();
    assert!(client.execute_proposal(&wrong).await.is_err());
    fixture.database.admin.execute("UPDATE registry_internal.registry_attachment_storage_binding SET verification_policy='disabled'",&[]).await.unwrap();
    assert_eq!(
        client
            .download_proposal_attachment(&uploaded, "support")
            .await
            .unwrap()
            .value
            .as_bytes(),
        bytes
    );
    let submit = client
        .prepare_proposal(&uploaded, "submit", json!({}), &key("erase-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let apply = client
        .prepare_proposal(
            &submitted,
            "apply",
            json!({"submissionVersion":1,"effectDigest":submitted.effect_digest().unwrap(),
        "reason":"erasure-reason-canary"}),
            &key("erase-apply"),
        )
        .unwrap();
    let applied = client.execute_proposal(&apply).await.unwrap().value;
    let before = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_revisions",
            &[],
        )
        .await
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(before, 2);
    let (mut migration, task) = fixture.database.connect_migration().await;
    let erasure = registry_breg::proposal_retention::erase_proposal_detail(
        &mut migration,
        &fixture.registry,
        registry_breg::proposal_retention::ProposalDetailErasureScope {
            action_id: "correct-name",
            proposal_id: uuid::Uuid::parse_str(applied.id()).unwrap(),
            submission_version: 1,
        },
    )
    .await
    .unwrap();
    assert_eq!(erasure.proposal_snapshots, 1);
    assert_eq!(erasure.attachment_references, 1);
    drop(migration);
    task.abort();
    assert!(
        client.execute_proposal(&apply).await.is_err(),
        "erased exact receipts retain spent-key refusal"
    );
    assert!(client
        .download_proposal_attachment(&applied, "support")
        .await
        .is_err());
    let current = client.read_proposal(&applied).await.unwrap().value;
    assert_eq!(current.state(), BRegProposalState::Applied);
    assert!(current.application().is_none());
    let row=fixture.database.admin.query_one("SELECT (SELECT count(*) FROM registry_internal.registry_revisions),
        (SELECT count(*) FROM registry_internal.registry_attachment_blobs),
        (SELECT count(*) FROM registry_internal.registry_proposal_applications WHERE reason IS NOT NULL)",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), before);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, i64>(2), 0);
    fixture.finish().await;
}

/// Cancel closes the queued automatic application job in its own
/// transaction, so no inert queued work outlives the Proposal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_closes_the_queued_automatic_application_job() {
    let fixture = client_http::ClientFixture::start(
        compile(registry_source(true)),
        claims("author", "zone-a"),
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Cancelled", "cancel-job-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("cancel-job-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let job_state = || async {
        fixture
            .database
            .admin
            .query_one(
                "SELECT state FROM registry_internal.registry_proposal_application_jobs",
                &[],
            )
            .await
            .unwrap()
            .get::<_, String>(0)
    };
    assert_eq!(job_state().await, "queued");
    let cancel = client
        .prepare_proposal(&submitted, "cancel", json!({}), &key("cancel-job-cancel"))
        .unwrap();
    let cancelled = client.execute_proposal(&cancel).await.unwrap().value;
    assert_eq!(cancelled.state(), BRegProposalState::Cancelled);
    assert_eq!(job_state().await, "cancelled");
    assert!(!fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    assert_eq!(job_state().await, "cancelled");
    fixture.finish().await;
}

/// Revise closes the superseded version's queued automatic application job,
/// which the worker could otherwise never claim again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revise_closes_the_superseded_versions_queued_automatic_application_job() {
    let fixture = client_http::ClientFixture::start(
        compile(registry_source(true)),
        claims("author", "zone-a"),
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Revised", "revise-job-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("revise-job-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let job_states = || async {
        fixture
            .database
            .admin
            .query(
                "SELECT submission_version, state
                 FROM registry_internal.registry_proposal_application_jobs
                 ORDER BY submission_version",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| (row.get::<_, i64>(0), row.get::<_, String>(1)))
            .collect::<Vec<_>>()
    };
    assert_eq!(job_states().await, [(1, "queued".to_owned())]);
    let revise = client
        .prepare_proposal(&submitted, "revise", json!({}), &key("revise-job-revise"))
        .unwrap();
    let revised = client.execute_proposal(&revise).await.unwrap().value;
    assert_eq!(revised.state(), BRegProposalState::Draft);
    assert_eq!(job_states().await, [(1, "cancelled".to_owned())]);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_automatic_uses_current_builtin_grant_and_one_atomic_receipt() {
    let mut source = registry_source(true);
    source["actions"][0]["execution"]["proposal"]
        .as_object_mut()
        .unwrap()
        .remove("application");
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    let draft = start(&fixture, "Automatic", "automatic-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("automatic-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    assert_eq!(submitted.state(), BRegProposalState::Submitted);
    let pending = serde_json::to_value(&submitted).unwrap();
    assert_eq!(
        pending["applicationStatus"],
        json!({"state":"pending","mode":"automatic","automaticRetry":{"scheduled":true,"attempts":0,"maximumAttempts":3}})
    );
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs SET next_attempt_at=transaction_timestamp()-interval '1 minute'",&[]).await.unwrap();
    assert!(application_queue_age(&fixture).await >= 60.0);
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    assert!(!fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let current = fixture
        .http
        .client
        .read_proposal(&submitted)
        .await
        .unwrap()
        .value;
    assert_eq!(current.state(), BRegProposalState::Applied);
    let applied = serde_json::to_value(&current).unwrap();
    assert_eq!(
        applied["applicationStatus"],
        json!({"state":"applied","mode":"automatic"})
    );
    assert_eq!(
        applied["application"]["submissionVersion"],
        pending["submissionVersion"]
    );
    assert_eq!(
        applied["application"]["effectDigest"],
        pending["effectDigest"]
    );
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT state,attempt_count,maximum_attempts,executor,application_id IS NOT NULL
        FROM registry_internal.registry_proposal_application_jobs",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "applied");
    assert_eq!(row.get::<_, i32>(1), 1);
    assert_eq!(row.get::<_, i32>(2), 3);
    assert_eq!(row.get::<_, String>(3), "builtin");
    assert!(row.get::<_, bool>(4));
    assert_eq!(application_queue_age(&fixture).await, 0.0);
    fixture.finish().await;
}

// Observe an actual row-lock wait, rather than guessing when the writer has
// reached the lifecycle boundary. Row locks wait on the owning transaction;
// its granted relation lock identifies the reader holding the Proposal row.
async fn proposal_lifecycle_writer_waits(admin: &tokio_postgres::Client, pid: Option<i32>) {
    loop {
        let waiting: bool = admin
            .query_one(
                "SELECT EXISTS (
                    SELECT 1 FROM pg_stat_activity writer
                    JOIN pg_locks pending ON pending.pid=writer.pid AND NOT pending.granted
                    WHERE writer.datname=current_database()
                      AND ($1::integer IS NULL OR writer.pid=$1)
                      AND writer.query LIKE '%registry_proposal_state%'
                      AND EXISTS (
                          SELECT 1 FROM pg_locks reader
                          WHERE reader.pid=ANY(pg_blocking_pids(writer.pid))
                            AND reader.relation='registry_internal.registry_proposal_state'::regclass
                            AND reader.mode='RowShareLock' AND reader.granted
                      )
                )",
                &[&pid],
            )
            .await
            .unwrap()
            .get(0);
        if waiting {
            return;
        }
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordinary_get_remains_coherent_while_automatic_application_commits() {
    use registry_breg_client::BRegProposalApplicationState;
    use std::sync::Arc;
    use std::time::Duration;

    let fixture =
        client_http::ClientFixture::start(registry(true), claims("author", "zone-a")).await;
    let draft = start(&fixture, "Concurrent automatic", "observation-auto-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("observation-auto-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let loaded = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let observer = fixture
        .client_with_mutations(
            claims("author", "zone-a"),
            (*fixture.mutations)
                .clone()
                .with_proposal_read_barrier_for_test(loaded.clone(), resume.clone()),
        )
        .await;
    let metadata = observer
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let get = metadata.value.select_proposal_get("clerk").unwrap();
    let (observation, (progress, application)) = tokio::join!(
        async {
            tokio::time::timeout(
                Duration::from_secs(5),
                observer.client.get_proposal(&get, submitted.id()),
            )
            .await
        },
        async {
            tokio::time::timeout(Duration::from_secs(1), loaded.notified())
                .await
                .expect("ordinary HTTP Get loaded its lifecycle header");
            let application = fixture.mutations.run_automatic_proposal_once_for_test();
            tokio::pin!(application);
            // Without the shared lifecycle lock, the worker commits here and
            // the one resumed Get deterministically composes Submitted with
            // an Applied job. Do not hide that refusal behind a retry.
            let progress = tokio::time::timeout(Duration::from_secs(1), async {
                tokio::select! {
                    result = &mut application => Some(result),
                    () = proposal_lifecycle_writer_waits(&fixture.database.admin, None) => None,
                }
            })
            .await;
            resume.notify_one();
            match progress {
                Ok(Some(result)) => (Ok(true), result),
                other => (
                    other.map(|_| false),
                    tokio::time::timeout(Duration::from_secs(3), application)
                        .await
                        .expect("automatic application completes after Get releases its row lock"),
                ),
            }
        }
    );
    let current = fixture.http.client.read_proposal(&submitted).await;
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT state,attempt_count,application_id,
                    (SELECT count(*) FROM registry_internal.registry_proposal_applications)
               FROM registry_internal.registry_proposal_application_jobs",
            &[],
        )
        .await
        .unwrap();
    let idle = fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await;
    drop(observer);
    fixture.finish().await;

    let observed = observation
        .expect("ordinary Get finishes within its deadline")
        .expect("an unchanged authorized caller must not receive a transient 404")
        .value;
    assert!(progress.is_ok(), "worker reached its lifecycle boundary");
    assert!(
        !progress.unwrap(),
        "Get holds the lifecycle lock until projection finishes"
    );
    assert!(application.unwrap());
    assert_eq!(observed.state(), BRegProposalState::Submitted);
    assert_eq!(observed.revision(), submitted.revision());
    assert_eq!(
        observed.submission_version(),
        submitted.submission_version()
    );
    assert_eq!(observed.effect_digest(), submitted.effect_digest());
    assert_eq!(
        observed.application_status().unwrap().state,
        BRegProposalApplicationState::Applying
    );
    assert!(observed.application().is_none());
    let applied = current.unwrap().value;
    assert_eq!(applied.state(), BRegProposalState::Applied);
    assert_eq!(applied.submission_version(), submitted.submission_version());
    assert_eq!(applied.effect_digest(), submitted.effect_digest());
    assert_eq!(
        applied.application_status().unwrap().state,
        BRegProposalApplicationState::Applied
    );
    let receipt = applied.application().unwrap();
    assert_eq!(receipt.submission_version, submitted.submission_version());
    assert_eq!(
        Some(receipt.effect_digest.as_str()),
        submitted.effect_digest()
    );
    assert_eq!(
        receipt.application_id,
        row.get::<_, uuid::Uuid>(2).to_string()
    );
    assert_eq!(row.get::<_, String>(0), "applied");
    assert_eq!(row.get::<_, i32>(1), 1);
    assert_eq!(row.get::<_, i64>(3), 1);
    assert!(
        !idle.unwrap(),
        "one frozen submission is applied exactly once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_lease_expiring_during_a_write_rolls_back_and_recovers_within_its_budget() {
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(true),
        claims("author", "zone-a"),
        |mutations| {
            mutations
                .with_action_timeout_for_test(std::time::Duration::from_secs(2))
                .with_automatic_proposal_lease_for_test(std::time::Duration::from_millis(400))
        },
    )
    .await;
    let draft = start(&fixture, "Lease fenced", "lease-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("lease-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let table = &fixture.registry.entities()["target"].physical_table;
    // The sequence is deliberately nontransactional: it proves the write
    // trigger ran, even when the expired-lease transaction rolls back.
    fixture.database.admin.batch_execute(&format!("CREATE SEQUENCE registry_data.lease_probe;
        GRANT USAGE,SELECT ON SEQUENCE registry_data.lease_probe TO \"{}\";
        CREATE FUNCTION registry_data.expire_during_write() RETURNS trigger LANGUAGE plpgsql AS $body$
        BEGIN PERFORM nextval('registry_data.lease_probe'); PERFORM pg_sleep(0.65); RETURN NEW; END $body$;
        CREATE TRIGGER expire_lease BEFORE UPDATE ON registry_data.\"{}\" FOR EACH ROW EXECUTE FUNCTION registry_data.expire_during_write()",
        fixture.database.runtime_role.as_str(),table)).await.unwrap();
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let row = fixture
        .database
        .admin
        .query_one("SELECT is_called FROM registry_data.lease_probe", &[])
        .await
        .unwrap();
    assert!(
        row.get::<_, bool>(0),
        "the final fence is exercised after write execution began"
    );
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT state,attempt_count,last_error_code,
        (SELECT count(*) FROM registry_internal.registry_proposal_applications),
        (SELECT count(*) FROM registry_internal.registry_revisions)
        FROM registry_internal.registry_proposal_application_jobs",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "queued");
    assert_eq!(row.get::<_, i32>(1), 1);
    assert_eq!(row.get::<_, String>(2), "lease-expired");
    assert_eq!(row.get::<_, i64>(3), 0);
    assert_eq!(row.get::<_, i64>(4), 1);
    assert_eq!(
        fixture
            .http
            .client
            .read_proposal(&submitted)
            .await
            .unwrap()
            .value
            .state(),
        BRegProposalState::Submitted
    );
    fixture
        .database
        .admin
        .batch_execute(&format!(
            "DROP TRIGGER expire_lease ON registry_data.\"{}\"",
            table
        ))
        .await
        .unwrap();
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs SET next_attempt_at=clock_timestamp()",&[]).await.unwrap();
    // Only the first attempt deliberately expires inside its write. Recovery
    // retains the two-second action deadline, with lease headroom so ordinary
    // CI contention cannot turn this success check into a second expiry probe.
    let recovery_worker = fixture
        .mutations
        .as_ref()
        .clone()
        .with_automatic_proposal_lease_for_test(std::time::Duration::from_secs(5));
    assert!(recovery_worker
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let row=fixture.database.admin.query_one("SELECT state,attempt_count,(SELECT count(*) FROM registry_internal.registry_proposal_applications),last_error_code
        FROM registry_internal.registry_proposal_application_jobs",&[]).await.unwrap();
    assert_eq!(
        row.get::<_, String>(0),
        "applied",
        "recovery error: {:?}",
        row.get::<_, Option<String>>(3)
    );
    assert_eq!(row.get::<_, i32>(1), 2);
    assert_eq!(row.get::<_, i64>(2), 1);
    fixture.finish().await;
}

struct NoToken;
#[async_trait::async_trait]
impl registry_platform_httputil::TokenProvider for NoToken {
    async fn bearer_token(
        &self,
    ) -> Result<registry_platform_httputil::BearerToken, registry_platform_httputil::TokenError>
    {
        Err(registry_platform_httputil::TokenError::Unavailable)
    }
}
fn local_review_binding() -> std::sync::Arc<registry_breg::review_store::ReviewAuthorityRegistry> {
    use registry_breg::review_store::{ReviewAuthorityClient, ReviewAuthorityRegistry};
    let client = registry_review_client::ReviewClient::new(
        registry_review_client::ReviewClientConfig::new("http://127.0.0.1:9/".parse().unwrap()),
    )
    .unwrap();
    let authority = std::sync::Arc::new(
        ReviewAuthorityClient::new(
            "local-review".into(),
            client,
            std::sync::Arc::new(NoToken),
            "producer".into(),
            "proposal-producer".into(),
            7,
            None,
            None,
        )
        .unwrap(),
    );
    std::sync::Arc::new(
        ReviewAuthorityRegistry::new(BTreeMap::from([("local-review".into(), authority)])).unwrap(),
    )
}
struct LocalReview {
    calls: std::sync::atomic::AtomicUsize,
    mode: std::sync::atomic::AtomicUsize,
    result_id: uuid::Uuid,
}
impl LocalReview {
    fn result(
        &self,
        accepted: &registry_review_client::ReviewRequestAccepted,
    ) -> registry_review_client::ReviewResult {
        let now = chrono::Utc::now();
        let mode = self.mode.load(std::sync::atomic::Ordering::SeqCst);
        let mut result = registry_review_client::ReviewResult {
            result_id: self.result_id,
            request_id: accepted.request_id,
            subject: accepted.subject.clone(),
            policy: accepted.policy.clone(),
            submission_digest: accepted.submission_digest.clone(),
            status: registry_review_client::ReviewResultStatus::Approved,
            outcome: Some("approved".to_owned()),
            public_reason: None,
            result: None,
            completed_at: now - chrono::Duration::seconds(2),
            available_until: now + chrono::Duration::minutes(5),
        };
        if mode == 1 {
            result.policy.version = "different-policy".into();
        }
        if mode == 2 {
            result.available_until = now - chrono::Duration::seconds(1);
        }
        result
    }
}
#[async_trait::async_trait]
impl registry_breg::review_store::ReviewResultSource for LocalReview {
    async fn approved_evidence(
        &self,
        authority: &str,
        accepted: &registry_review_client::ReviewRequestAccepted,
    ) -> Result<
        registry_breg::review_integration::AcceptedReviewEvidence,
        registry_breg::mutation::MutationError,
    > {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.mode.load(std::sync::atomic::Ordering::SeqCst) == 3 {
            return Err(registry_breg::mutation::MutationError::Unavailable);
        }
        registry_breg::review_integration::AcceptedReviewEvidence::from_protocol(
            authority,
            accepted,
            &self.result(accepted),
        )
        .map_err(|_| registry_breg::mutation::MutationError::PreconditionFailed)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordinary_get_excludes_review_result_and_job_publication_until_observation_finishes() {
    use registry_breg_client::BRegProposalApplicationState;
    use std::sync::Arc;
    use std::time::Duration;

    let mut source = registry_source(true);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
    let review = Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let injected = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
        },
    )
    .await;
    let draft = start(&fixture, "Concurrent approval", "observation-review-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(
            &draft,
            "submit",
            json!({}),
            &key("observation-review-submit"),
        )
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT create_request,expected_submission_digest,
                    (SELECT snapshot FROM registry_internal.registry_proposal_submissions)
               FROM registry_internal.registry_proposal_review_submissions",
            &[],
        )
        .await
        .unwrap();
    let frozen: Value = row.get(2);
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(row.get(0)).unwrap();
    let accepted = registry_review_client::ReviewRequestAccepted {
        request_id: uuid::Uuid::new_v4(),
        subject: create.subject,
        policy: serde_json::from_value(policy).unwrap(),
        submission_digest: serde_json::from_value(json!(row.get::<_, String>(1))).unwrap(),
    };
    fixture.database.admin.execute(
        "UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1",
        &[&serde_json::to_value(&accepted).unwrap()],
    ).await.unwrap();
    let result = review.result(&accepted);
    let loaded = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let observer = fixture
        .client_with_mutations(
            claims("author", "zone-a"),
            (*fixture.mutations)
                .clone()
                .with_proposal_read_barrier_for_test(loaded.clone(), resume.clone()),
        )
        .await;
    let metadata = observer
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let get = metadata.value.select_proposal_get("clerk").unwrap();
    let (mut migration, connection) = fixture.database.connect_migration().await;
    let writer_pid: i32 = migration
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let (observation, (progress, before_release, reconciled)) = tokio::join!(
        async {
            tokio::time::timeout(
                Duration::from_secs(5),
                observer.client.get_proposal(&get, submitted.id()),
            )
            .await
        },
        async {
            tokio::time::timeout(Duration::from_secs(1), loaded.notified())
                .await
                .expect("ordinary HTTP Get loaded its lifecycle header");
            let reconcile = async {
                let tx = migration.transaction().await.unwrap();
                registry_breg::review_store::reconcile_result(
                    &tx,
                    "local-review",
                    &accepted,
                    &result,
                    &fixture.mutations,
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|_| registry_breg::mutation::MutationError::Unavailable)
            };
            tokio::pin!(reconcile);
            // This proves writer exclusion at the lifecycle boundary. The
            // barrier is before projection, so it does not itself force the
            // narrower job-None then approved-result statement interleaving.
            let progress = tokio::time::timeout(Duration::from_secs(1), async {
                tokio::select! {
                    result = &mut reconcile => Some(result),
                    () = proposal_lifecycle_writer_waits(&fixture.database.admin, Some(writer_pid)) => None,
                }
            })
            .await;
            let before_release = fixture
                .database
                .admin
                .query_one(
                    "SELECT (SELECT count(*) FROM registry_internal.registry_proposal_review_results),
                            (SELECT count(*) FROM registry_internal.registry_proposal_application_jobs)",
                    &[],
                )
                .await
                .unwrap();
            resume.notify_one();
            let (progress, reconciled) = match progress {
                Ok(Some(result)) => (Ok(true), result),
                other => (
                    other.map(|_| false),
                    tokio::time::timeout(Duration::from_secs(3), reconcile)
                        .await
                        .expect(
                            "review publication finishes after the reader releases its row lock",
                        ),
                ),
            };
            (progress, before_release, reconciled)
        }
    );
    drop(migration);
    connection.abort();
    let current = fixture.http.client.read_proposal(&submitted).await;
    let published = fixture
        .database
        .admin
        .query_one(
            "SELECT r.result_id,r.result,r.status,j.result_id,j.proposal_digest,
                    j.submission_version,j.system_grant_revision,s.snapshot,
                    (SELECT count(*) FROM registry_internal.registry_proposal_review_results),
                    (SELECT count(*) FROM registry_internal.registry_proposal_application_jobs)
               FROM registry_internal.registry_proposal_review_results r
               JOIN registry_internal.registry_proposal_application_jobs j
                 USING(action_id,proposal_id,submission_version)
               JOIN registry_internal.registry_proposal_submissions s
                 USING(action_id,proposal_id,submission_version)",
            &[],
        )
        .await;
    drop(observer);
    fixture.finish().await;

    assert!(
        progress.is_ok(),
        "reconciler reached its lifecycle boundary"
    );
    assert!(
        !progress.unwrap(),
        "the no-job observer excludes review publication"
    );
    assert_eq!(before_release.get::<_, i64>(0), 0);
    assert_eq!(before_release.get::<_, i64>(1), 0);
    reconciled.unwrap();
    let observed = observation
        .expect("ordinary Get finishes within its deadline")
        .expect("an unchanged authorized caller can observe the pending review")
        .value;
    assert_eq!(observed.state(), BRegProposalState::Submitted);
    assert_eq!(observed.revision(), submitted.revision());
    assert_eq!(
        observed.submission_version(),
        submitted.submission_version()
    );
    assert_eq!(observed.effect_digest(), submitted.effect_digest());
    let status = observed.application_status().unwrap();
    assert_eq!(status.state, BRegProposalApplicationState::AwaitingReview);
    assert!(!status.automatic_retry.as_ref().unwrap().scheduled);
    let current = current.unwrap().value;
    assert_eq!(current.state(), BRegProposalState::Submitted);
    assert_eq!(current.revision(), submitted.revision());
    assert_eq!(current.submission_version(), submitted.submission_version());
    assert_eq!(current.effect_digest(), submitted.effect_digest());
    let status = current.application_status().unwrap();
    assert_eq!(status.state, BRegProposalApplicationState::Pending);
    assert!(status.automatic_retry.as_ref().unwrap().scheduled);
    assert!(current.application().is_none());
    let published = published.expect("approval and its application job are published together");
    assert_eq!(published.get::<_, uuid::Uuid>(0), result.result_id);
    assert_eq!(
        published.get::<_, Value>(1),
        serde_json::to_value(&result).unwrap()
    );
    assert_eq!(published.get::<_, String>(2), "approved");
    assert_eq!(published.get::<_, uuid::Uuid>(3), result.result_id);
    assert_eq!(
        Some(published.get::<_, String>(4).as_str()),
        submitted.effect_digest()
    );
    assert_eq!(
        published.get::<_, i64>(5),
        i64::from(submitted.submission_version())
    );
    assert_eq!(
        published.get::<_, String>(6),
        frozen["systemGrantRevision"].as_str().unwrap()
    );
    assert_eq!(published.get::<_, Value>(7), frozen);
    assert_eq!(published.get::<_, i64>(8), 1);
    assert_eq!(published.get::<_, i64>(9), 1);
    assert_eq!(review.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reviewed_apply_requires_fresh_exact_approval_and_receipt_recovery_is_local() {
    let mut source = registry_source(false);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
    source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .push(json!("get-review-status"));
    let review = std::sync::Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let injected = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
        },
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Reviewed", "review-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("review-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let row=fixture.database.admin.query_one("SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions",&[]).await.unwrap();
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(row.get(0)).unwrap();
    let expected =
        registry_review_client::submission_digest("proposal-producer", "proposal-test", &create)
            .unwrap();
    assert_eq!(expected.as_str(), row.get::<_, String>(1));
    assert_eq!(create.subject.id, submitted.id());
    assert_eq!(
        create.subject.digest.as_str(),
        submitted.effect_digest().unwrap()
    );
    let accepted = registry_review_client::ReviewRequestAccepted {
        request_id: uuid::Uuid::new_v4(),
        subject: create.subject,
        policy: serde_json::from_value(policy).unwrap(),
        submission_digest: expected,
    };
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1",
        &[&serde_json::to_value(&accepted).unwrap()]).await.unwrap();
    registry_breg::review_store::verify_retained_bindings(&fixture.pool, &fixture.registry, None)
        .await
        .unwrap();
    registry_breg::review_store::verify_retained_bindings(
        &fixture.pool,
        &fixture.registry,
        Some(local_review_binding().as_ref()),
    )
    .await
    .unwrap();
    let result = review.result(&accepted);
    fixture.database.admin.execute("INSERT INTO registry_internal.registry_proposal_review_results
        (action_id,proposal_id,submission_version,authority,result_id,result,status,completed_at,available_until)
        VALUES ('correct-name',$1,1,'local-review',$2,$3,'approved',$4,$5)",
        &[&uuid::Uuid::parse_str(submitted.id()).unwrap(),&result.result_id,&serde_json::to_value(&result).unwrap(),&result.completed_at,&result.available_until]).await.unwrap();
    let current = client.read_proposal(&submitted).await.unwrap().value;
    review.mode.store(1, std::sync::atomic::Ordering::SeqCst);
    let wrong = client
        .prepare_proposal(
            &current,
            "apply",
            json!({"submissionVersion":1,"effectDigest":current.effect_digest().unwrap()}),
            &key("review-wrong-policy"),
        )
        .unwrap();
    assert_eq!(
        client
            .execute_proposal(&wrong)
            .await
            .unwrap_err()
            .problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    review.mode.store(2, std::sync::atomic::Ordering::SeqCst);
    let expired = client
        .prepare_proposal(
            &current,
            "apply",
            json!({"submissionVersion":1,"effectDigest":current.effect_digest().unwrap()}),
            &key("review-expired"),
        )
        .unwrap();
    assert_eq!(
        client
            .execute_proposal(&expired)
            .await
            .unwrap_err()
            .problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    review.mode.store(0, std::sync::atomic::Ordering::SeqCst);
    let apply = client
        .prepare_proposal(
            &current,
            "apply",
            json!({"submissionVersion":1,"effectDigest":current.effect_digest().unwrap()}),
            &key("review-valid"),
        )
        .unwrap();
    let applied = client.execute_proposal(&apply).await.unwrap();
    assert_eq!(applied.value.state(), BRegProposalState::Applied);
    follow_retained_review_status_link(
        &fixture.http.base_url,
        &serde_json::to_value(client.read_proposal(&applied.value).await.unwrap().value).unwrap(),
        "approved",
    )
    .await;
    let calls = review.calls.load(std::sync::atomic::Ordering::SeqCst);
    review.mode.store(3, std::sync::atomic::Ordering::SeqCst);
    let recovered = client.execute_proposal(&apply).await.unwrap();
    assert_eq!(
        serde_json::to_value(applied.value).unwrap(),
        serde_json::to_value(recovered.value).unwrap()
    );
    assert_eq!(
        review.calls.load(std::sync::atomic::Ordering::SeqCst),
        calls
    );
    fixture.finish().await;
}

/// applicationStatus reports application progress only. A review outcome
/// reaches the caller through Apply availability, never as an application
/// refusal, in either application mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_outcomes_read_as_apply_availability_not_application_status() {
    for automatic in [false, true] {
        let mut source = registry_source(automatic);
        source["reviewAuthorities"] =
            json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
        let policy = json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
        source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
        let review = std::sync::Arc::new(LocalReview {
            calls: 0.into(),
            mode: 0.into(),
            result_id: uuid::Uuid::new_v4(),
        });
        let injected = review.clone();
        let fixture = client_http::ClientFixture::start_with_mutations(
            compile(source),
            claims("author", "zone-a"),
            move |mutations| {
                mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
            },
        )
        .await;
        let client = &fixture.http.client;
        let draft = start(&fixture, "Reviewed", &format!("outcome-{automatic}-start")).await;
        let submit = client
            .prepare_proposal(
                &draft,
                "submit",
                json!({}),
                &key(&format!("outcome-{automatic}-submit")),
            )
            .unwrap();
        let submitted = client.execute_proposal(&submit).await.unwrap().value;
        let row=fixture.database.admin.query_one("SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions",&[]).await.unwrap();
        let create: registry_review_client::ReviewCreateRequest =
            serde_json::from_value(row.get(0)).unwrap();
        let accepted = registry_review_client::ReviewRequestAccepted {
            request_id: uuid::Uuid::new_v4(),
            subject: create.subject,
            policy: serde_json::from_value(policy).unwrap(),
            submission_digest: serde_json::from_value(json!(row.get::<_, String>(1))).unwrap(),
        };
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1",
            &[&serde_json::to_value(&accepted).unwrap()]).await.unwrap();
        let observe = || async {
            let current =
                serde_json::to_value(client.read_proposal(&submitted).await.unwrap().value)
                    .unwrap();
            (
                current["applicationStatus"].clone(),
                current["links"]["apply"]["availability"].clone(),
                current["links"]["revise"]["availability"]["available"].clone(),
                current["turn"].clone(),
            )
        };
        let (status, apply, _, turn) = observe().await;
        assert_eq!(turn, "official", "a pending review waits on its reviewer");
        assert_eq!(status["state"], "awaiting-review");
        assert!(status.get("reason").is_none() && status.get("recovery").is_none());
        assert_eq!(apply["reason"], "pending-review");
        assert_eq!(apply["recovery"], "refresh");
        let result = review.result(&accepted);
        fixture.database.admin.execute("INSERT INTO registry_internal.registry_proposal_review_results
            (action_id,proposal_id,submission_version,authority,result_id,result,status,completed_at,available_until)
            VALUES ('correct-name',$1,1,'local-review',$2,$3,'rejected',$4,$5)",
            &[&uuid::Uuid::parse_str(submitted.id()).unwrap(),&result.result_id,&serde_json::to_value(&result).unwrap(),&result.completed_at,&result.available_until]).await.unwrap();
        for (outcome, reason, recovery) in [
            ("rejected", "review-rejected", "revise"),
            ("changes-requested", "review-changes-requested", "revise"),
            ("cancelled", "review-ended", "revise"),
            ("superseded", "review-ended", "revise"),
            ("answered", "review-ended", "revise"),
        ] {
            fixture
                .database
                .admin
                .execute(
                    "UPDATE registry_internal.registry_proposal_review_results SET status=$1",
                    &[&outcome],
                )
                .await
                .unwrap();
            let (status, apply, revise, turn) = observe().await;
            assert_eq!(turn, "party", "{outcome}");
            assert_eq!(status["state"], "awaiting-review", "{outcome}");
            assert!(
                status.get("reason").is_none() && status.get("recovery").is_none(),
                "{outcome} is a review outcome, not an application refusal"
            );
            assert_eq!(
                status["mode"],
                if automatic { "automatic" } else { "manual" }
            );
            assert_eq!(apply["available"], false, "{outcome}");
            assert_eq!(apply["reason"], reason, "{outcome}");
            assert_eq!(apply["recovery"], recovery, "{outcome}");
            assert_eq!(revise, true, "{outcome}");
        }
        // Automatic application commits its job with the approval, so only
        // manual application observes an approval without one.
        if !automatic {
            // An approval past its availability cannot be applied; the party
            // revises to ask again.
            fixture
                .database
                .admin
                .execute(
                    "UPDATE registry_internal.registry_proposal_review_results
                     SET status='approved',available_until=transaction_timestamp()-interval '1 second'",
                    &[],
                )
                .await
                .unwrap();
            let (_, apply, revise, turn) = observe().await;
            assert_eq!(
                (&apply["available"], &apply["reason"], &apply["recovery"]),
                (&json!(false), &json!("review-ended"), &json!("revise"))
            );
            assert_eq!((revise, turn), (json!(true), json!("party")));
            fixture
                .database
                .admin
                .execute(
                    "UPDATE registry_internal.registry_proposal_review_results
                     SET status='approved',available_until=$1",
                    &[&result.available_until],
                )
                .await
                .unwrap();
            let (status, apply, _, turn) = observe().await;
            assert_eq!(status["state"], "pending");
            assert_eq!(apply["available"], true);
            assert_eq!(turn, "official", "a manual approval waits on its applier");
        }
        // Without a result, a submission the provider keeps refusing reads as
        // a dependency outage the caller retries, and a failed one as ended.
        fixture
            .database
            .admin
            .execute(
                "DELETE FROM registry_internal.registry_proposal_review_results",
                &[],
            )
            .await
            .unwrap();
        fixture
            .database
            .admin
            .execute(
                "UPDATE registry_internal.registry_proposal_review_submissions
                 SET state='pending',lease_until=NULL,last_error_code='unavailable'",
                &[],
            )
            .await
            .unwrap();
        let (_, apply, _, turn) = observe().await;
        assert_eq!(
            (&apply["reason"], &apply["recovery"], &turn),
            (
                &json!("dependency-outage"),
                &json!("retry"),
                &json!("official")
            )
        );
        fixture
            .database
            .admin
            .execute(
                "UPDATE registry_internal.registry_proposal_review_submissions SET state='failed'",
                &[],
            )
            .await
            .unwrap();
        let (_, apply, revise, turn) = observe().await;
        assert_eq!(
            (&apply["reason"], &apply["recovery"], &turn),
            (&json!("review-ended"), &json!("revise"), &json!("party"))
        );
        assert_eq!(revise, true);
        fixture.finish().await;
    }
}

/// A Proposal whose review was decided keeps its review-status link, and
/// following that link serves the retained result.
async fn follow_retained_review_status_link(base_url: &str, document: &Value, state: &str) {
    let link = &document["links"]["reviewStatus"];
    assert_eq!(link["method"], "GET", "{state}: {document}");
    assert_eq!(
        link["availability"]["available"], true,
        "{state}: {document}"
    );
    let response = reqwest::Client::new()
        .get(format!(
            "{}{}",
            base_url.trim_end_matches('/'),
            link["path"].as_str().unwrap()
        ))
        .query(&[("accessProfile", link["accessProfile"].as_str().unwrap())])
        .send()
        .await
        .unwrap();
    let code = response.status();
    let body: Value = response.json().await.unwrap();
    assert_eq!(code, reqwest::StatusCode::OK, "{state}: {body}");
    assert_eq!(body["result"]["state"], state, "{body}");
}

/// Posts every Proposal command through the link a rejected Proposal serves,
/// as a client holding the inert link would, and checks each answers 409
/// `proposal.rejected` with the detail naming how to try again. Attachment
/// upload and removal are Edit writes, so they answer the same.
async fn post_every_command_to_a_rejected_proposal(
    base_url: &str,
    document: &Value,
    input: &Value,
    label: &str,
) {
    assert!(input.is_object(), "{label}: draft input: {input}");
    let apply = json!({"submissionVersion":document["submissionVersion"],
        "effectDigest":document["effectDigest"]});
    for (command, body) in [
        ("submit", json!({})),
        ("edit", json!({"input":input})),
        ("revise", json!({})),
        ("rebase", json!({"input":input})),
        ("apply", apply),
        ("retry", json!({})),
        ("cancel", json!({})),
    ] {
        let link = &document["links"][command];
        assert_eq!(
            link["availability"]["reason"], "review-rejected",
            "{label}: {command}: {document}"
        );
        assert_eq!(link["availability"]["recovery"], "receipt-only");
        let response = reqwest::Client::new()
            .post(format!(
                "{}{}",
                base_url.trim_end_matches('/'),
                link["path"].as_str().unwrap()
            ))
            .query(&[("accessProfile", link["accessProfile"].as_str().unwrap())])
            .header("content-type", "application/json")
            .header("if-match", link["ifMatch"].as_str().unwrap())
            .header("idempotency-key", format!("{label}-{command}"))
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let status = response.status();
        let problem: Value = response.json().await.unwrap();
        assert_eq!(
            status,
            reqwest::StatusCode::CONFLICT,
            "{label}: {command}: {problem}"
        );
        assert_eq!(
            problem["code"], "proposal.rejected",
            "{label}: {command}: {problem}"
        );
        assert!(
            problem["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("changes-requested")),
            "{label}: {command}: {problem}"
        );
    }
    // A rejected Proposal serves no attachment write link, so a client sends
    // the attachment write with the current Edit precondition.
    let edit = &document["links"]["edit"];
    let attachment = format!(
        "{}/v1/proposals/{}/attachments/support",
        base_url.trim_end_matches('/'),
        document["id"].as_str().unwrap()
    );
    for (operation, request) in [
        (
            "upload",
            reqwest::Client::new()
                .patch(&attachment)
                .header("content-type", "text/plain")
                .body("synthetic-rejected"),
        ),
        ("remove", reqwest::Client::new().delete(&attachment)),
    ] {
        let response = request
            .query(&[("accessProfile", edit["accessProfile"].as_str().unwrap())])
            .header("if-match", edit["ifMatch"].as_str().unwrap())
            .header("idempotency-key", format!("{label}-attachment-{operation}"))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let problem: Value = response.json().await.unwrap();
        assert_eq!(
            status,
            reqwest::StatusCode::CONFLICT,
            "{label}: {operation}: {problem}"
        );
        assert_eq!(
            problem["code"], "proposal.rejected",
            "{label}: {operation}: {problem}"
        );
    }
}

/// A rejection ends the Proposal: it reaches `rejected`, records its own
/// event, and refuses Revise. A request for changes keeps it submitted and
/// revisable and records `review-returned`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_rejection_is_terminal_and_changes_requested_returns_to_the_party() {
    for (outcome, state, transition, turn) in [
        ("rejected", "rejected", "proposal.rejected", "nobody"),
        (
            "changes-requested",
            "submitted",
            "proposal.review-returned",
            "party",
        ),
    ] {
        let mut source = registry_source(false);
        source["reviewAuthorities"] =
            json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
        let policy = json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
        source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
        // The inputs are readable so the test can send a well-formed Edit or
        // Rebase body to the rejected Proposal.
        source["accessProfiles"][0]["permissions"]["proposals"][0]["readableInputs"] =
            json!(["target", "value"]);
        source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"]
            .as_array_mut()
            .unwrap()
            .push(json!("get-review-status"));
        let review = std::sync::Arc::new(LocalReview {
            calls: 0.into(),
            mode: 0.into(),
            result_id: uuid::Uuid::new_v4(),
        });
        let injected = review.clone();
        let fixture = client_http::ClientFixture::start_with_mutations(
            compile(source.clone()),
            claims("author", "zone-a"),
            move |mutations| {
                mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
            },
        )
        .await;
        let client = &fixture.http.client;
        let draft = start(&fixture, "Reviewed", &format!("{outcome}-start")).await;
        let draft_input = json!(client
            .read_proposal(&draft)
            .await
            .unwrap()
            .value
            .input()
            .expect("readable draft input"));
        let submit = client
            .prepare_proposal(
                &draft,
                "submit",
                json!({}),
                &key(&format!("{outcome}-submit")),
            )
            .unwrap();
        let submitted = client.execute_proposal(&submit).await.unwrap().value;
        let row=fixture.database.admin.query_one("SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions",&[]).await.unwrap();
        let create: registry_review_client::ReviewCreateRequest =
            serde_json::from_value(row.get(0)).unwrap();
        let accepted = registry_review_client::ReviewRequestAccepted {
            request_id: uuid::Uuid::new_v4(),
            subject: create.subject,
            policy: serde_json::from_value(policy).unwrap(),
            submission_digest: serde_json::from_value(json!(row.get::<_, String>(1))).unwrap(),
        };
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1",
            &[&serde_json::to_value(&accepted).unwrap()]).await.unwrap();
        let mut result = review.result(&accepted);
        result.status = serde_json::from_value(json!(outcome)).unwrap();
        result.outcome = Some(outcome.to_owned());
        result.public_reason = Some("Public reason canary".to_owned());
        let (mut migration, task) = fixture.database.connect_migration().await;
        let tx = migration.transaction().await.unwrap();
        registry_breg::review_store::reconcile_result(
            &tx,
            "local-review",
            &accepted,
            &result,
            &fixture.mutations,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        drop(migration);
        task.abort();

        let before = fixture.audit_capture.entries().len();
        let current =
            serde_json::to_value(client.read_proposal(&submitted).await.unwrap().value).unwrap();
        assert_eq!(current["state"], state, "{outcome}");
        assert_eq!(current["turn"], turn, "{outcome}");
        assert_eq!(current["decision"]["status"], outcome);
        assert_eq!(current["decision"]["publicReason"], "Public reason canary");
        follow_retained_review_status_link(&fixture.http.base_url, &current, outcome).await;
        let entries = fixture.audit_capture.entries();
        assert!(entries[before..].iter().any(|entry| {
            entry["record"]["phase"] == "terminal"
                && entry["record"]["fieldSetReference"] == "proposal-review-public-reason"
        }));
        assert!(!entries[before..]
            .iter()
            .any(|entry| entry.to_string().contains("Public reason canary")));
        // The turn is a list filter over the same derivation Get serves.
        let collection = client
            .registry_contract(Some("clerk"))
            .await
            .unwrap()
            .value
            .select_proposals("clerk")
            .unwrap();
        for filter in [
            BRegProposalTurn::Party,
            BRegProposalTurn::Official,
            BRegProposalTurn::Nobody,
        ] {
            let page = client
                .list_proposals(
                    &collection,
                    &BRegProposalQuery {
                        turn: Some(filter),
                        ..Default::default()
                    },
                )
                .await
                .unwrap()
                .value;
            let ids = page
                .items
                .iter()
                .map(|item| item.id().to_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                ids.contains(&submitted.id().to_owned()),
                json!(filter) == json!(turn),
                "{outcome}: {filter:?}"
            );
            assert!(page.items.iter().all(|item| item.turn() == Some(filter)));
        }
        let revise = &current["links"]["revise"]["availability"];
        assert_eq!(
            revise["available"],
            outcome != "rejected",
            "{outcome}: {current}"
        );

        let events = fixture
            .database
            .admin
            .query(
                "SELECT event_type,payload FROM registry_internal.registry_outbox ORDER BY outbox_id",
                &[],
            )
            .await
            .unwrap();
        let last = events.last().unwrap();
        assert_eq!(last.get::<_, String>(0), transition, "{outcome}");
        let envelope = registry_platform_hooks::HookEnvelope::from_canonical_bytes(
            &last.get::<_, Vec<u8>>(1),
            &registry_platform_hooks::EnvelopeLimits::default(),
        )
        .unwrap();
        assert_eq!(envelope.data["fromState"], "submitted");
        assert_eq!(envelope.data["state"], state);
        assert_eq!(envelope.data["authorityKind"], "review");
        assert_eq!(envelope.data["turn"], turn);
        assert!(
            !String::from_utf8_lossy(&last.get::<_, Vec<u8>>(1)).contains("Public reason canary"),
            "a lifecycle event never carries reviewer text"
        );

        // Reconciling the same result again records nothing new.
        let (mut migration, task) = fixture.database.connect_migration().await;
        let tx = migration.transaction().await.unwrap();
        registry_breg::review_store::reconcile_result(
            &tx,
            "local-review",
            &accepted,
            &result,
            &fixture.mutations,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        drop(migration);
        task.abort();
        let after: i64 = fixture
            .database
            .admin
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_outbox",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(after, i64::try_from(events.len()).unwrap(), "{outcome}");

        if outcome == "rejected" {
            let fresh = client.read_proposal(&submitted).await.unwrap().value;
            assert_eq!(fresh.state(), BRegProposalState::Rejected);
            assert!(
                client
                    .prepare_proposal(&fresh, "revise", json!({}), &key("rejected-revise"))
                    .is_err(),
                "the client offers no Revise of a rejected Proposal"
            );
            // The server refuses every exact inert link too, naming the way
            // to allow another attempt.
            let wire = serde_json::to_value(&fresh).unwrap();
            post_every_command_to_a_rejected_proposal(
                &fixture.http.base_url,
                &wire,
                &draft_input,
                "rejected-terminal",
            )
            .await;
            // A package activation that changes the Action revision does not
            // turn the final answer into a precondition failure.
            #[cfg(feature = "tooling")]
            {
                let mut next = source.clone();
                next["actions"][0]["execution"]["proposal"]["review"]["policy"]["digest"] =
                    json!(format!("sha256:{}", "c".repeat(64)));
                let (registry, identity) =
                    proposal_activation::activate_successor(&fixture, &next).await;
                let current = successor_client(&fixture, registry, identity).await;
                let metadata = current
                    .client
                    .registry_contract(Some("clerk"))
                    .await
                    .unwrap();
                let collection = metadata.value.select_proposals("clerk").unwrap();
                let moved = current
                    .client
                    .list_proposals(&collection, &BRegProposalQuery::default())
                    .await
                    .unwrap()
                    .value
                    .items
                    .into_iter()
                    .find(|proposal| proposal.id() == submitted.id())
                    .unwrap();
                let wire = serde_json::to_value(&moved).unwrap();
                assert_ne!(
                    moved.action_revision(),
                    metadata
                        .value
                        .select_action("correct-name", "clerk")
                        .unwrap()
                        .definition_revision(),
                    "the activation changes the Action revision"
                );
                post_every_command_to_a_rejected_proposal(
                    &current.base_url,
                    &wire,
                    &draft_input,
                    "rejected-after-activation",
                )
                .await;
                drop(current);
            }
        }
        fixture.finish().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submission_read_reports_each_version_separately_and_is_gone_after_its_windows() {
    let mut source = registry_source(false);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
    let review = std::sync::Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let injected = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
        },
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Historical", "history-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("history-submit-1"))
        .unwrap();
    let first = client.execute_proposal(&submit).await.unwrap().value;
    let first_digest = serde_json::to_value(&first).unwrap()["effectDigest"].clone();
    let id = first.id().to_owned();
    let read = |version: &str, profile: &str| {
        let url = format!(
            "{}/v1/proposals/{id}/submissions/{version}?accessProfile={profile}",
            fixture.http.base_url
        );
        async move {
            let response = reqwest::get(url).await.unwrap();
            let status = response.status();
            (
                status,
                response.json::<Value>().await.unwrap_or(Value::Null),
            )
        }
    };
    let (status, body) = read("1", "clerk").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["id"], json!(id));
    assert_eq!(body["submissionVersion"], 1);
    assert_eq!(body["current"], true);
    assert_eq!(body["effectDigest"], first_digest);
    assert_eq!(body["review"], json!({"state":"pending"}));
    assert_eq!(body["application"]["state"], "awaiting-review");

    let row=fixture.database.admin.query_one("SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions",&[]).await.unwrap();
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(row.get(0)).unwrap();
    let accepted = registry_review_client::ReviewRequestAccepted {
        request_id: uuid::Uuid::new_v4(),
        subject: create.subject,
        policy: serde_json::from_value(policy).unwrap(),
        submission_digest: serde_json::from_value(json!(row.get::<_, String>(1))).unwrap(),
    };
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1",
        &[&serde_json::to_value(&accepted).unwrap()]).await.unwrap();
    let mut result = review.result(&accepted);
    result.status = registry_review_client::ReviewResultStatus::Rejected;
    result.outcome = Some("rejected".to_owned());
    result.public_reason = Some("Historical public reason".to_owned());
    result.result = Some(json!({"privateNote":"Reviewer-only canary"}));
    result.completed_at = chrono::SubsecRound::trunc_subsecs(result.completed_at, 6);
    fixture.database.admin.execute("INSERT INTO registry_internal.registry_proposal_review_results
        (action_id,proposal_id,submission_version,authority,result_id,result,status,completed_at,available_until)
        VALUES ('correct-name',$1,1,'local-review',$2,$3,'rejected',$4,$5)",
        &[&uuid::Uuid::parse_str(&id).unwrap(),&result.result_id,&serde_json::to_value(&result).unwrap(),&result.completed_at,&result.available_until]).await.unwrap();

    let current = client.read_proposal(&first).await.unwrap().value;
    let revise = client
        .prepare_proposal(&current, "revise", json!({}), &key("history-revise"))
        .unwrap();
    let revised = client.execute_proposal(&revise).await.unwrap().value;
    let submit = client
        .prepare_proposal(&revised, "submit", json!({}), &key("history-submit-2"))
        .unwrap();
    let second = client.execute_proposal(&submit).await.unwrap().value;
    assert_eq!(second.submission_version(), 2);

    // The superseded version keeps its own review outcome and reports no
    // application progress, which belongs to the current version alone.
    let (status, body) = read("1", "clerk").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["current"], false);
    assert_eq!(body["effectDigest"], first_digest);
    assert_eq!(body["review"]["state"], "rejected");
    assert_eq!(body["review"]["resultId"], json!(result.result_id));
    assert!(body["application"].is_null(), "{body}");
    // The decision names the outcome, its time and the public reason; the
    // reviewer's private result is never served.
    assert_eq!(
        body["decision"],
        json!({"status":"rejected",
            "decidedAt":result.completed_at.to_rfc3339_opts(chrono::SecondsFormat::Micros,true),
            "publicReason":"Historical public reason"})
    );
    assert!(!body.to_string().contains("Reviewer-only canary"), "{body}");
    let before = fixture.audit_capture.entries().len();
    let historical = client
        .read_proposal_submission(&second, 1)
        .await
        .unwrap()
        .value;
    assert!(!historical.current);
    let decision = historical.decision.as_ref().unwrap();
    assert_eq!(decision.status, BRegProposalDecisionStatus::Rejected);
    assert_eq!(
        decision.public_reason.as_deref(),
        Some("Historical public reason")
    );
    // The journal records that a public reason was served, never its text.
    let entries = fixture.audit_capture.entries();
    let terminal = entries[before..]
        .iter()
        .map(|entry| &entry["record"])
        .find(|record| record["phase"] == "terminal")
        .unwrap();
    assert_eq!(terminal["resultCount"], 1);
    assert_eq!(
        terminal["fieldSetReference"],
        "proposal-review-public-reason"
    );
    assert!(!entries[before..]
        .iter()
        .any(|entry| entry.to_string().contains("Historical public reason")));
    let (status, body) = read("2", "clerk").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["current"], true);
    assert_eq!(body["review"], json!({"state":"pending"}));
    assert_eq!(body["application"]["state"], "awaiting-review");
    assert!(body.get("decision").is_none(), "{body}");
    let before = fixture.audit_capture.entries().len();
    let pending = client
        .read_proposal_submission(&second, 2)
        .await
        .unwrap()
        .value;
    assert!(pending.current && pending.decision.is_none());
    let entries = fixture.audit_capture.entries();
    assert!(entries[before..]
        .iter()
        .all(|entry| entry["record"].get("fieldSetReference").is_none()));

    // A version never submitted, a malformed version and a profile without
    // Get authority are all concealed alike.
    for (version, profile) in [
        ("3", "clerk"),
        ("0", "clerk"),
        ("01", "clerk"),
        ("1", "missing"),
    ] {
        let (status, _) = read(version, profile).await;
        assert_eq!(
            status,
            reqwest::StatusCode::NOT_FOUND,
            "{version} {profile}"
        );
    }

    // Once the superseded version's result window lapses it retains nothing
    // to report, and the read says so instead of concealing the version.
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_review_results
             SET completed_at=transaction_timestamp()-interval '2 minutes',
                 available_until=transaction_timestamp()-interval '1 minute'
             WHERE submission_version=1",
            &[],
        )
        .await
        .unwrap();
    let before = fixture.audit_capture.entries().len();
    let (status, body) = read("1", "clerk").await;
    assert_eq!(status, reqwest::StatusCode::GONE);
    assert_eq!(body["code"], "proposal.submission_expired");
    // The lapsed version returns nothing, so its read audits as empty.
    let entries = fixture.audit_capture.entries();
    let terminal = entries[before..]
        .iter()
        .map(|entry| &entry["record"])
        .find(|record| record["phase"] == "terminal")
        .unwrap();
    assert_eq!(terminal["resultCount"], 0);
    assert_eq!(terminal["outcome"], "empty");
    assert_eq!(
        client
            .read_proposal_submission(&second, 1)
            .await
            .unwrap_err()
            .problem_code(),
        Some(BRegProblemCode::ProposalSubmissionExpired)
    );
    let (status, _) = read("2", "clerk").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn application_actor_requires_its_dedicated_get_grant_and_is_issuer_scoped() {
    async fn applied_under(issuer: &str) -> String {
        let mut source = registry_source(false);
        source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"]
            .as_array_mut()
            .unwrap()
            .push(json!("get-application-actor"));
        let mut observer = source["accessProfiles"][0].clone();
        observer["id"] = json!("observer");
        observer["default"] = json!(false);
        observer["permissions"]["actions"] = json!([]);
        observer["permissions"]["proposals"][0]["operations"] = json!(["get", "list"]);
        observer["permissions"]["proposals"][0]["readableAttachments"] = json!([]);
        observer["permissions"]["proposals"][0]["writableAttachments"] = json!([]);
        source["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .push(observer);
        let policy = registry_breg::idempotency::IdempotencyPolicy::new(issuer, 7).unwrap();
        let fixture = client_http::ClientFixture::start_with_mutations(
            compile(source),
            claims("author", "zone-a"),
            move |mutations| mutations.with_idempotency_policy(policy),
        )
        .await;
        let client = &fixture.http.client;
        let draft = start(&fixture, "Receipt", "receipt-start").await;
        let submit = client
            .prepare_proposal(&draft, "submit", json!({}), &key("receipt-submit"))
            .unwrap();
        let submitted = client.execute_proposal(&submit).await.unwrap().value;
        let body = json!({"submissionVersion":submitted.submission_version(),"effectDigest":submitted.effect_digest().unwrap()});
        let apply = client
            .prepare_proposal(&submitted, "apply", body, &key("receipt-apply"))
            .unwrap();
        let applied_receipt = client.execute_proposal(&apply).await.unwrap().value;
        let applied = serde_json::to_value(&applied_receipt).unwrap();
        assert!(
            applied.pointer("/application/appliedBy").is_none(),
            "{applied}"
        );
        assert!(
            applied.pointer("/application/appliedAt").is_none(),
            "{applied}"
        );
        let stored = fixture.database.admin.query_one(
            "SELECT applied_by,to_char(applied_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
             FROM registry_internal.registry_proposal_applications WHERE proposal_id=$1",
            &[&uuid::Uuid::parse_str(submitted.id()).unwrap()],
        ).await.unwrap();
        let stored_actor: String = stored.get(0);
        let stored_time: String = stored.get(1);
        let decoded = client.read_proposal(&applied_receipt).await.unwrap().value;
        let decoded_application = decoded.application().unwrap();
        assert_eq!(
            decoded_application.applied_by.as_deref(),
            Some(stored_actor.as_str())
        );
        assert_eq!(
            decoded_application.applied_at.as_deref(),
            Some(stored_time.as_str())
        );
        let decoded_submission = client
            .read_proposal_submission(&decoded, 1)
            .await
            .unwrap()
            .value;
        let decoded_submission_application = decoded_submission.application.unwrap();
        assert_eq!(
            decoded_submission_application.applied_by.as_deref(),
            Some(stored_actor.as_str())
        );
        assert_eq!(
            decoded_submission_application.applied_at.as_deref(),
            Some(stored_time.as_str())
        );

        let get = |profile: &str| {
            let url = format!(
                "{}/v1/proposals/{}?accessProfile={profile}",
                fixture.http.base_url,
                submitted.id()
            );
            async move {
                reqwest::get(url)
                    .await
                    .unwrap()
                    .json::<Value>()
                    .await
                    .unwrap()
            }
        };
        let submission = |profile: &str| {
            let url = format!(
                "{}/v1/proposals/{}/submissions/1?accessProfile={profile}",
                fixture.http.base_url,
                submitted.id()
            );
            async move {
                reqwest::get(url)
                    .await
                    .unwrap()
                    .json::<Value>()
                    .await
                    .unwrap()
            }
        };
        let privileged = get("clerk").await;
        assert_eq!(privileged["application"]["appliedBy"], stored_actor);
        assert_eq!(privileged["application"]["appliedAt"], stored_time);
        let privileged_submission = submission("clerk").await;
        assert_eq!(privileged_submission["application"]["state"], "applied");
        assert_eq!(
            privileged_submission["application"]["applicationId"],
            applied["application"]["applicationId"]
        );
        assert_eq!(
            privileged_submission["application"]["appliedBy"],
            stored_actor
        );
        assert_eq!(
            privileged_submission["application"]["appliedAt"],
            stored_time
        );

        for redacted in [get("observer").await, submission("observer").await] {
            assert_eq!(redacted["id"], submitted.id(), "{redacted}");
            assert!(
                redacted.pointer("/application/appliedBy").is_none(),
                "{redacted}"
            );
            assert!(
                redacted.pointer("/application/appliedAt").is_none(),
                "{redacted}"
            );
        }
        for profile in ["clerk", "observer"] {
            let listed = reqwest::get(format!(
                "{}/v1/proposals?accessProfile={profile}",
                fixture.http.base_url
            ))
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
            let item = listed["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["id"] == submitted.id())
                .unwrap();
            assert_eq!(item["state"], "applied", "{listed}");
            assert_eq!(
                item["application"]["applicationId"], applied["application"]["applicationId"],
                "{listed}"
            );
            assert!(item.pointer("/application/appliedBy").is_none(), "{listed}");
            assert!(item.pointer("/application/appliedAt").is_none(), "{listed}");
        }
        fixture.finish().await;
        stored_actor
    }

    let first = applied_under("https://issuer-one.example").await;
    let second = applied_under("https://issuer-two.example").await;
    assert_ne!(
        first, second,
        "the issuer must scope the keyed actor pseudonym"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn required_review_automatic_requires_fresh_exact_approval_even_with_a_cached_result() {
    for mode in [1, 2, 3, 0] {
        let mut source = registry_source(true);
        source["reviewAuthorities"] =
            json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
        let policy = json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
        source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
        let review = std::sync::Arc::new(LocalReview {
            calls: 0.into(),
            mode: 0.into(),
            result_id: uuid::Uuid::new_v4(),
        });
        let injected = review.clone();
        let fixture = client_http::ClientFixture::start_with_mutations(
            compile(source),
            claims("author", "zone-a"),
            move |mutations| {
                mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
            },
        )
        .await;
        let draft = start(
            &fixture,
            "Reviewed automatic",
            &format!("review-auto-{mode}-start"),
        )
        .await;
        let submit = fixture
            .http
            .client
            .prepare_proposal(
                &draft,
                "submit",
                json!({}),
                &key(&format!("review-auto-{mode}-submit")),
            )
            .unwrap();
        let submitted = fixture
            .http
            .client
            .execute_proposal(&submit)
            .await
            .unwrap()
            .value;
        let row=fixture.database.admin.query_one("SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions",&[]).await.unwrap();
        let create: registry_review_client::ReviewCreateRequest =
            serde_json::from_value(row.get(0)).unwrap();
        let accepted = registry_review_client::ReviewRequestAccepted {
            request_id: uuid::Uuid::new_v4(),
            subject: create.subject,
            policy: serde_json::from_value(policy).unwrap(),
            submission_digest: serde_json::from_value(json!(row.get::<_, String>(1))).unwrap(),
        };
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1",
            &[&serde_json::to_value(&accepted).unwrap()]).await.unwrap();
        let (mut migration, task) = fixture.database.connect_migration().await;
        let tx = migration.transaction().await.unwrap();
        registry_breg::review_store::reconcile_result(
            &tx,
            "local-review",
            &accepted,
            &review.result(&accepted),
            &fixture.mutations,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        drop(migration);
        task.abort();
        review.mode.store(mode, std::sync::atomic::Ordering::SeqCst);
        assert!(fixture
            .mutations
            .run_automatic_proposal_once_for_test()
            .await
            .unwrap());
        assert_eq!(
            review.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an uncommitted attempt fetches fresh authority evidence"
        );
        let current = fixture
            .http
            .client
            .read_proposal(&submitted)
            .await
            .unwrap()
            .value;
        let row=fixture.database.admin.query_one("SELECT state,attempt_count,(SELECT count(*) FROM registry_internal.registry_proposal_applications)
            FROM registry_internal.registry_proposal_application_jobs",&[]).await.unwrap();
        if mode == 0 {
            assert_eq!(current.state(), BRegProposalState::Applied);
            assert_eq!(row.get::<_, String>(0), "applied");
            assert_eq!(row.get::<_, i64>(2), 1);
            assert!(!fixture
                .mutations
                .run_automatic_proposal_once_for_test()
                .await
                .unwrap());
            assert_eq!(review.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        } else {
            assert_eq!(current.state(), BRegProposalState::Submitted);
            assert_eq!(
                row.get::<_, i64>(2),
                0,
                "cached approval cannot substitute for current authenticated evidence"
            );
            assert_eq!(
                row.get::<_, String>(0),
                if mode == 3 { "queued" } else { "blocked" }
            );
        }
        assert_eq!(row.get::<_, i32>(1), 1);
        fixture.finish().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proposal_inputs_require_an_explicit_selected_profile_allowlist() {
    let mut source = registry_source(false);
    source["actions"][0]["inputs"][0]["apiName"] = json!("accountRef");
    let mut reader = source["accessProfiles"][0].clone();
    reader["id"] = json!("input-reader");
    reader["default"] = json!(false);
    reader["permissions"]["actions"] = json!([]);
    reader["permissions"]["records"] = json!([]);
    reader["permissions"]["proposals"][0]["operations"] = json!(["get", "list"]);
    reader["permissions"]["proposals"][0]["writableAttachments"] = json!([]);
    reader["permissions"]["proposals"][0]["readableInputs"] = json!(["target"]);
    source["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(reader);
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let target = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Before","jurisdiction":"zone-a"}))).unwrap(),
            &key("input-record"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap()
        .value
        .data
        .record_identifier;
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"accountRef":target,"value":"input-secret-canary"})),
        None,
    )
    .unwrap();
    let draft = client
        .start_proposal(&action, &input, &key("input-start"))
        .await
        .unwrap()
        .value;
    assert!(serde_json::to_value(&draft).unwrap().get("input").is_none());
    let metadata = client
        .registry_contract(Some("input-reader"))
        .await
        .unwrap();
    let collection = metadata.value.select_proposals("input-reader").unwrap();
    let page = client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap();
    assert_eq!(page.value.items.len(), 1);
    let value = serde_json::to_value(&page.value.items[0]).unwrap();
    assert_eq!(value["input"], json!({"accountRef":target}));
    assert!(!serde_json::to_string(&value)
        .unwrap()
        .contains("input-secret-canary"));
    fixture.finish().await;
}

// Pause only the first external observation, after its durable claim commits.
// The successor observes the same approval without sharing the fixture barrier.
struct PausedReview {
    review: LocalReview,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
    observations: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl registry_breg::review_store::ReviewResultSource for PausedReview {
    async fn approved_evidence(
        &self,
        authority: &str,
        accepted: &registry_review_client::ReviewRequestAccepted,
    ) -> Result<
        registry_breg::review_integration::AcceptedReviewEvidence,
        registry_breg::mutation::MutationError,
    > {
        if self
            .observations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            == 0
        {
            self.entered.notify_one();
            self.resume.notified().await;
        }
        registry_breg::review_store::ReviewResultSource::approved_evidence(
            &self.review,
            authority,
            accepted,
        )
        .await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replaced_automatic_worker_resumes_without_changing_successor_or_effects() {
    use std::time::Duration;
    let mut source = registry_source(true);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
    let review = std::sync::Arc::new(PausedReview {
        review: LocalReview {
            calls: 0.into(),
            mode: 0.into(),
            result_id: uuid::Uuid::new_v4(),
        },
        entered: Default::default(),
        resume: Default::default(),
        observations: 0.into(),
    });
    let injected = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
        },
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Reclaimed once", "replaced-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("replaced-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let id = uuid::Uuid::parse_str(submitted.id()).unwrap();
    let row = fixture.database.admin.query_one("SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&id]).await.unwrap();
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(row.get(0)).unwrap();
    let accepted = registry_review_client::ReviewRequestAccepted {
        request_id: uuid::Uuid::new_v4(),
        subject: create.subject,
        policy: serde_json::from_value(policy).unwrap(),
        submission_digest: serde_json::from_value(json!(row.get::<_, String>(1))).unwrap(),
    };
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$2 WHERE proposal_id=$1", &[&id,&json!(accepted)]).await.unwrap();
    let (mut migration, task) = fixture.database.connect_migration().await;
    let tx = migration.transaction().await.unwrap();
    registry_breg::review_store::reconcile_result(
        &tx,
        "local-review",
        &accepted,
        &review.review.result(&accepted),
        &fixture.mutations,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    drop(migration);
    task.abort();
    let mutations = fixture.mutations.clone();
    let original =
        tokio::spawn(async move { mutations.run_automatic_proposal_once_for_test().await });
    tokio::time::timeout(Duration::from_secs(5), review.entered.notified())
        .await
        .expect("original worker reached external observation after claiming");
    let old_token: uuid::Uuid = fixture.database.admin.query_one("SELECT claim_token FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1", &[&id]).await.unwrap().get(0);
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE proposal_id=$1", &[&id]).await.unwrap();
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let job_sql = "SELECT to_jsonb(j) FROM registry_internal.registry_proposal_application_jobs j WHERE proposal_id=$1";
    let successor: Value = fixture
        .database
        .admin
        .query_one(job_sql, &[&id])
        .await
        .unwrap()
        .get(0);
    assert_eq!(successor["state"], "applied");
    assert_eq!(successor["attempt_count"], 2);
    assert!(successor["claim_token"].is_null());
    assert_ne!(successor["claim_token"], json!(old_token));
    let applied = client.read_proposal(&submitted).await.unwrap().value;
    let receipt = serde_json::to_value(applied.application().unwrap()).unwrap();
    review.resume.notify_one();
    assert!(tokio::time::timeout(Duration::from_secs(5), original)
        .await
        .expect("replaced worker resumes")
        .unwrap()
        .unwrap());
    let after: Value = fixture
        .database
        .admin
        .query_one(job_sql, &[&id])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        after, successor,
        "stale worker cannot overwrite any successor job state"
    );
    let recovered = client.read_proposal(&submitted).await.unwrap().value;
    assert_eq!(
        serde_json::to_value(recovered.application().unwrap()).unwrap(),
        receipt
    );
    let counts = fixture.database.admin.query_one("SELECT (SELECT count(*) FROM registry_internal.registry_proposal_applications),(SELECT count(*) FROM registry_internal.registry_revisions)",&[]).await.unwrap();
    assert_eq!(counts.get::<_, i64>(0), 1);
    assert_eq!(
        counts.get::<_, i64>(1),
        2,
        "one create and one applied revision"
    );
    assert!(!fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_claim_pins_digest_grant_and_lease_before_any_effect() {
    let fixture =
        client_http::ClientFixture::start(registry(true), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Fenced", "fenced-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("fenced-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let id = uuid::Uuid::parse_str(submitted.id()).unwrap();
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT proposal_digest,system_grant_revision
        FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    let digest: String = row.get(0);
    let grant: String = row.get(1);
    let wrong = format!("sha256:{}", "f".repeat(64));
    for column in ["proposal_digest", "system_grant_revision"] {
        fixture.database.admin.execute(&format!("UPDATE registry_internal.registry_proposal_application_jobs SET {column}=$2 WHERE proposal_id=$1"),&[&id,&wrong]).await.unwrap();
        assert!(fixture
            .mutations
            .run_automatic_proposal_once_for_test()
            .await
            .is_err());
        let untouched=fixture.database.admin.query_one("SELECT state,attempt_count,(SELECT count(*) FROM registry_internal.registry_proposal_applications)
            FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1",&[&id]).await.unwrap();
        assert_eq!(untouched.get::<_, String>(0), "queued");
        assert_eq!(untouched.get::<_, i32>(1), 0);
        assert_eq!(untouched.get::<_, i64>(2), 0);
        fixture.database.admin.execute(&format!("UPDATE registry_internal.registry_proposal_application_jobs SET {column}=$2 WHERE proposal_id=$1"),
            &[&id,&if column=="proposal_digest"{&digest}else{&grant}]).await.unwrap();
    }
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs
        SET state='blocked',attempt_count=1,last_error_code='dependency-outage' WHERE proposal_id=$1",&[&id]).await.unwrap();
    let (mut migration, task) = fixture.database.connect_migration().await;
    let tx = migration.transaction().await.unwrap();
    registry_breg::review_recovery::retry_application_for_test(
        &tx,
        registry_breg::review_recovery::ReviewRecoveryScope {
            action_id: "correct-name",
            proposal_id: id,
            submission_version: 1,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let row=fixture.database.admin.query_one("SELECT state,attempt_count FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1",&[&id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "queued");
    assert_eq!(
        row.get::<_, i32>(1),
        1,
        "operator recovery preserves consumed attempts"
    );
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs
        SET state='blocked',attempt_count=maximum_attempts,last_error_code='dependency-outage' WHERE proposal_id=$1",&[&id]).await.unwrap();
    let tx = migration.transaction().await.unwrap();
    assert!(registry_breg::review_recovery::retry_application_for_test(
        &tx,
        registry_breg::review_recovery::ReviewRecoveryScope {
            action_id: "correct-name",
            proposal_id: id,
            submission_version: 1
        }
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    drop(migration);
    task.abort();
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_application_jobs
        SET state='queued',attempt_count=0,last_error_code=NULL WHERE proposal_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs
        SET state='applying',claim_token=$2,next_attempt_at=transaction_timestamp()+interval '1 minute'
        WHERE proposal_id=$1",&[&id,&uuid::Uuid::new_v4()]).await.unwrap();
    assert!(!fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_application_jobs
        SET next_attempt_at=transaction_timestamp()-interval '1 second' WHERE proposal_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let applied = client.read_proposal(&submitted).await.unwrap().value;
    assert_eq!(applied.state(), BRegProposalState::Applied);
    let row=fixture.database.admin.query_one("SELECT state,attempt_count,claim_token FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1",&[&id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "applied");
    assert_eq!(row.get::<_, i32>(1), 1);
    assert!(row.get::<_, Option<uuid::Uuid>>(2).is_none());
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_submit_and_apply_each_commit_once_under_revision_fences() {
    let fixture =
        client_http::ClientFixture::start(registry(false), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Raced", "raced-start").await;
    let first = client
        .prepare_proposal(&draft, "submit", json!({}), &key("raced-submit-a"))
        .unwrap();
    let second = client
        .prepare_proposal(&draft, "submit", json!({}), &key("raced-submit-b"))
        .unwrap();
    let (a, b) = tokio::join!(
        client.execute_proposal(&first),
        client.execute_proposal(&second)
    );
    let submitted = match (a, b) {
        (Ok(value), Err(error)) | (Err(error), Ok(value)) => {
            assert_eq!(
                error.problem_code(),
                Some(BRegProblemCode::PreconditionFailed)
            );
            value.value
        }
        _ => panic!("exactly one submission must commit"),
    };
    let body = json!({"submissionVersion":submitted.submission_version(),"effectDigest":submitted.effect_digest().unwrap()});
    let first = client
        .prepare_proposal(&submitted, "apply", body.clone(), &key("raced-apply-a"))
        .unwrap();
    let second = client
        .prepare_proposal(&submitted, "apply", body, &key("raced-apply-b"))
        .unwrap();
    let (a, b) = tokio::join!(
        client.execute_proposal(&first),
        client.execute_proposal(&second)
    );
    match (a, b) {
        (Ok(value), Err(error)) | (Err(error), Ok(value)) => {
            assert_eq!(value.value.state(), BRegProposalState::Applied);
            assert_eq!(
                error.problem_code(),
                Some(BRegProblemCode::PreconditionFailed)
            );
        }
        _ => panic!("exactly one application must commit"),
    }
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_internal.registry_proposal_submissions),
        (SELECT count(*) FROM registry_internal.registry_proposal_applications)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_lifecycle_recovery_uses_current_authority_and_the_original_exact_condition() {
    let mut source = registry_source(false);
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableInputs"] =
        json!(["target", "value"]);
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Recover lifecycle", "recover-start").await;
    assert!(
        draft.input().is_none(),
        "mutation receipts retain no optional input disclosure"
    );
    let current = client.read_proposal(&draft).await.unwrap().value;
    let original_input = current.input().unwrap().clone();
    let submit = client
        .prepare_proposal(&current, "submit", json!({}), &key("recover-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let recovered = client.recover_proposal(&submitted, &submit).unwrap();
    assert_eq!(
        serde_json::to_value(client.execute_proposal(&recovered).await.unwrap().value).unwrap(),
        serde_json::to_value(&submitted).unwrap()
    );
    let revise = client
        .prepare_proposal(&submitted, "revise", json!({}), &key("recover-revise"))
        .unwrap();
    let revised = client.execute_proposal(&revise).await.unwrap().value;
    assert_eq!(
        revised.submission_version(),
        submitted.submission_version() + 1
    );
    let recovered = client.recover_proposal(&revised, &revise).unwrap();
    assert_eq!(
        serde_json::to_value(client.execute_proposal(&recovered).await.unwrap().value).unwrap(),
        serde_json::to_value(&revised).unwrap()
    );
    let rebase = client
        .prepare_proposal(
            &revised,
            "rebase",
            json!({"input":original_input}),
            &key("recover-rebase"),
        )
        .unwrap();
    let rebased = client.execute_proposal(&rebase).await.unwrap().value;
    assert_eq!(rebased.submission_version(), revised.submission_version());
    let recovered = client.recover_proposal(&rebased, &rebase).unwrap();
    assert_eq!(
        serde_json::to_value(client.execute_proposal(&recovered).await.unwrap().value).unwrap(),
        serde_json::to_value(&rebased).unwrap()
    );
    let rows = fixture
        .database
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_internal.registry_proposal_submissions),
        (SELECT count(*) FROM registry_internal.registry_proposal_applications)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.get::<_, i64>(0), 1);
    assert_eq!(rows.get::<_, i64>(1), 0);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reference_only_targets_are_locked_and_readmitted_at_submit_and_apply() {
    let mut source = registry_source(false);
    source["actions"][0]["inputs"].as_array_mut().unwrap().push(json!({"id":"linked","type":"reference","target":"target","required":true,"classification":"internal"}));
    let mut fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let mut ids = Vec::new();
    for (name, key_name) in [
        ("Primary", "linked-primary"),
        ("Reference only", "linked-other"),
    ] {
        ids.push(
            client
                .create_record(
                    &create,
                    &BRegCreateRequest::new(map(json!({"name":name,"jurisdiction":"zone-a"})))
                        .unwrap(),
                    &key(key_name),
                    BRegRecordFormat::Json,
                )
                .await
                .unwrap()
                .value
                .data
                .record_identifier,
        );
    }
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"target":ids[0],"linked":ids[1],"value":"Changed"})),
        None,
    )
    .unwrap();
    let draft = client
        .start_proposal(&action, &input, &key("linked-start"))
        .await
        .unwrap()
        .value;
    let linked = uuid::Uuid::parse_str(&ids[1]).unwrap();
    let entity = &fixture.registry.entities()["target"];
    let change = format!(
        "UPDATE registry_data.\"{}\" SET \"{}\"=$2 WHERE record_id=$1",
        entity.physical_table, entity.fields["jurisdiction"].physical_name
    );
    let tx = fixture.database.admin.transaction().await.unwrap();
    tx.execute(&change, &[&linked, &"zone-b"]).await.unwrap();
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("linked-submit-denied"))
        .unwrap();
    let refused = {
        let waiting = client.execute_proposal(&submit);
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(75), &mut waiting)
                .await
                .is_err(),
            "submit must wait for the reference-only row lock"
        );
        tx.commit().await.unwrap();
        waiting.await.unwrap_err()
    };
    assert_eq!(
        refused.problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    fixture
        .database
        .admin
        .execute(&change, &[&linked, &"zone-a"])
        .await
        .unwrap();
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("linked-submit-valid"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let tx = fixture.database.admin.transaction().await.unwrap();
    tx.execute(&change, &[&linked, &"zone-b"]).await.unwrap();
    let apply = client
        .prepare_proposal(
            &submitted,
            "apply",
            json!({"submissionVersion":1,"effectDigest":submitted.effect_digest().unwrap()}),
            &key("linked-apply-denied"),
        )
        .unwrap();
    let refused = {
        let waiting = client.execute_proposal(&apply);
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(75), &mut waiting)
                .await
                .is_err(),
            "apply must wait for the reference-only row lock"
        );
        tx.commit().await.unwrap();
        waiting.await.unwrap_err()
    };
    assert_eq!(
        refused.problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_proposal_applications",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    let state = fixture
        .database
        .admin
        .query_one(
            "SELECT state FROM registry_internal.registry_proposal_state",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(state.get::<_, String>(0), "submitted");
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_review_binding_preserves_unrelated_builtin_work_and_fails_review_closed() {
    let mut source = registry_source(true);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let mut reviewed = source["actions"][0].clone();
    reviewed["id"] = json!("reviewed-name");
    reviewed["execution"]["proposal"]["application"] = json!({"mode":"manual"});
    reviewed["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test",
        "policy":{"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))}});
    source["actions"].as_array_mut().unwrap().push(reviewed);
    for family in ["actions", "proposals"] {
        let mut grant = source["accessProfiles"][0]["permissions"][family][0].clone();
        grant["action"] = json!("reviewed-name");
        source["accessProfiles"][0]["permissions"][family]
            .as_array_mut()
            .unwrap()
            .push(grant);
    }
    let registry = compile(source);
    let runtime = registry_breg::runtime_config::parse_runtime_config(include_str!(
        "../../../products/breg/examples/minimal/runtime.example.yaml"
    ))
    .unwrap();
    assert!(
        runtime
            .activate_review_authorities(&registry)
            .unwrap()
            .is_none(),
        "an absent optional Review mapping must not disable the registry"
    );
    assert_eq!(
        runtime.unbound_review_authorities(&registry),
        vec!["local-review".to_owned()]
    );
    let fixture = client_http::ClientFixture::start(registry, claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Independent", "independent-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("independent-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let applied = client.read_proposal(&submitted).await.unwrap().value;
    assert_eq!(applied.state(), BRegProposalState::Applied);
    let record = applied.application().unwrap().result_links[0]
        .record_id
        .clone();
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let reviewed = metadata
        .value
        .select_action("reviewed-name", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &reviewed,
        map(json!({"target":record,"value":"Must remain unapplied"})),
        None,
    )
    .unwrap();
    let blocked = client
        .start_proposal(&reviewed, &input, &key("unavailable-review-start"))
        .await
        .unwrap()
        .value;
    let link = blocked
        .link("submit")
        .expect("unavailable transition is inspectable");
    assert!(!link.availability().unwrap().available);
    assert_eq!(
        link.availability().unwrap().reason,
        Some(registry_breg_client::BRegAvailabilityReason::DependencyOutage)
    );
    // Exercise refusal on the exact inert server link without promoting it in
    // the client or reconstructing a lifecycle route.
    let wire = serde_json::to_value(link).unwrap();
    let response = reqwest::Client::new()
        .post(format!(
            "{}{}",
            fixture.http.base_url.trim_end_matches('/'),
            wire["path"].as_str().unwrap()
        ))
        .query(&[("accessProfile", wire["accessProfile"].as_str().unwrap())])
        .header("content-type", "application/json")
        .header("if-match", wire["ifMatch"].as_str().unwrap())
        .header("idempotency-key", "unavailable-review-submit")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let current = client.read_proposal(&blocked).await.unwrap().value;
    assert_eq!(current.state(), BRegProposalState::Draft);
    let cancel = client
        .prepare_proposal(
            &current,
            "cancel",
            json!({}),
            &key("unavailable-review-cancel"),
        )
        .unwrap();
    assert_eq!(
        client
            .execute_proposal(&cancel)
            .await
            .unwrap()
            .value
            .state(),
        BRegProposalState::Cancelled
    );
    let rows = fixture
        .database
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_internal.registry_proposal_review_submissions),
        (SELECT count(*) FROM registry_internal.registry_proposal_applications)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.get::<_, i64>(0), 0);
    assert_eq!(rows.get::<_, i64>(1), 1);
    fixture.finish().await;
}

#[cfg(feature = "tooling")]
#[path = "support/proposal_activation.rs"]
mod proposal_activation;
#[cfg(feature = "tooling")]
#[path = "support/proposal_review_authority.rs"]
mod proposal_review_authority;
struct ActiveReady;
impl registry_breg::api::ReadinessProbe for ActiveReady {
    fn is_ready(&self) -> registry_breg::api::ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
#[cfg(feature = "tooling")]
async fn successor_client(
    fixture: &client_http::ClientFixture,
    registry: registry_breg::CompiledRegistry,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
) -> client_http::ClientHttp {
    client_with_audit_key(
        fixture,
        registry,
        identity,
        0x61,
        claims("author", "zone-a"),
    )
    .await
}
async fn client_with_audit_key(
    fixture: &client_http::ClientFixture,
    registry: registry_breg::CompiledRegistry,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    audit_key: u8,
    caller: VerifiedRequestClaims,
) -> client_http::ClientHttp {
    use registry_breg::api::{HttpService, ReadRuntimeIdentity};
    use registry_breg::postgres::{
        PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    };
    use std::sync::Arc;
    let registry = Arc::new(registry);
    let lock = RegistryLockKey::derive(registry.registry_id()).unwrap();
    let audit = registry_breg::audit::test_support::capturing(
        registry_platform_audit::AuditProfile::production_from_secret_bytes(
            vec![audit_key; 32].into(),
        )
        .unwrap(),
    )
    .0;
    let cursors = Arc::new(
        registry_breg::cursor::CursorCodec::new(
            zeroize::Zeroizing::new(vec![0x62; 32]),
            std::time::Duration::from_secs(300),
        )
        .unwrap(),
    );
    let records = PostgresRecordReadService::new(
        fixture.pool.clone(),
        registry.clone(),
        identity.clone(),
        lock,
        std::time::Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    );
    let mutations = PostgresRecordMutationService::new(
        fixture.pool.clone(),
        registry.clone(),
        identity.clone(),
        "client-capability-test",
        lock,
        std::time::Duration::from_secs(2),
        audit,
    );
    let service = HttpService::new(
        registry,
        ReadRuntimeIdentity {
            package_revision: identity.activation_id,
            schema_fingerprint: identity.schema_fingerprint,
        },
        Arc::new(records),
        Arc::new(ActiveReady),
        cursors,
    )
    .with_postgres_mutations(Arc::new(mutations));
    client_http::ClientHttp::start(registry_breg::api::router(Arc::new(service)), caller).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audit_key_rotation_preserves_stable_ownership_and_exact_replay_but_not_other_callers() {
    let mut source = registry_source(false);
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableInputs"] =
        json!(["target", "value"]);
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    let applied_draft = start(&fixture, "Before rotation", "owner-applied-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(
            &applied_draft,
            "submit",
            json!({}),
            &key("owner-applied-submit"),
        )
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let apply = fixture
        .http
        .client
        .prepare_proposal(
            &submitted,
            "apply",
            json!({"submissionVersion":1,"effectDigest":submitted.effect_digest().unwrap()}),
            &key("owner-applied-apply"),
        )
        .unwrap();
    let applied = fixture
        .http
        .client
        .execute_proposal(&apply)
        .await
        .unwrap()
        .value;
    let draft = start(&fixture, "After rotation", "owner-draft-start").await;
    let saved: Value = serde_json::from_slice(apply.as_bytes()).unwrap();
    let rotated = client_with_audit_key(
        &fixture,
        (*fixture.registry).clone(),
        fixture.identity.clone(),
        0x72,
        claims("author", "zone-a"),
    )
    .await;
    let metadata = rotated
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let page = rotated
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap()
        .value;
    assert_eq!(page.items.len(), 2);
    let owned = page
        .items
        .iter()
        .find(|proposal| proposal.id() == draft.id())
        .unwrap();
    let owned = rotated.client.read_proposal(owned).await.unwrap().value;
    let mut input = owned.input().unwrap().clone();
    input.insert("value".into(), json!("Edited after rotation"));
    let edit = rotated
        .client
        .prepare_proposal(&owned, "edit", json!({"input":input}), &key("owner-edit"))
        .unwrap();
    let edited = rotated.client.execute_proposal(&edit).await.unwrap().value;
    let submit = rotated
        .client
        .prepare_proposal(&edited, "submit", json!({}), &key("owner-submit"))
        .unwrap();
    let submitted = rotated
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let cancel = rotated
        .client
        .prepare_proposal(&submitted, "cancel", json!({}), &key("owner-cancel"))
        .unwrap();
    assert_eq!(
        rotated
            .client
            .execute_proposal(&cancel)
            .await
            .unwrap()
            .value
            .state(),
        BRegProposalState::Cancelled
    );
    let response = reqwest::Client::new()
        .post(format!(
            "{}{}",
            rotated.base_url.trim_end_matches('/'),
            saved["link"]["path"].as_str().unwrap()
        ))
        .query(&[(
            "accessProfile",
            saved["link"]["accessProfile"].as_str().unwrap(),
        )])
        .header("content-type", "application/json")
        .header("if-match", saved["link"]["ifMatch"].as_str().unwrap())
        .header("idempotency-key", saved["key"].as_str().unwrap())
        .body(saved["body"].as_str().unwrap().to_owned())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        serde_json::to_value(applied).unwrap()
    );
    let other = client_with_audit_key(
        &fixture,
        (*fixture.registry).clone(),
        fixture.identity.clone(),
        0x72,
        claims("different-author", "zone-a"),
    )
    .await;
    let metadata = other.client.registry_contract(Some("clerk")).await.unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    assert!(other
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap()
        .value
        .items
        .is_empty());
    let response = reqwest::Client::new()
        .post(format!(
            "{}{}",
            other.base_url.trim_end_matches('/'),
            saved["link"]["path"].as_str().unwrap()
        ))
        .query(&[(
            "accessProfile",
            saved["link"]["accessProfile"].as_str().unwrap(),
        )])
        .header("content-type", "application/json")
        .header("if-match", saved["link"]["ifMatch"].as_str().unwrap())
        .header("idempotency-key", saved["key"].as_str().unwrap())
        .body(saved["body"].as_str().unwrap().to_owned())
        .send()
        .await
        .unwrap();
    assert_ne!(response.status(), reqwest::StatusCode::OK);
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_proposal_applications",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    drop(other);
    drop(rotated);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(feature = "tooling")]
async fn compatible_verified_activation_keeps_the_frozen_submission_applicable() {
    let source = registry_source(false);
    let fixture =
        client_http::ClientFixture::start(compile(source.clone()), claims("author", "zone-a"))
            .await;
    let draft = start(&fixture, "After compatible activation", "compatible-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("compatible-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let mut next = source;
    next["actions"][0]["display"] = json!({"label":"Correct the name"});
    let candidate = compile(next.clone());
    assert_eq!(
        fixture.registry.actions().actions[0].definition_revision,
        candidate.actions().actions[0].definition_revision
    );
    let (registry, identity) = proposal_activation::activate_successor(&fixture, &next).await;
    assert_ne!(identity.activation_id, fixture.identity.activation_id);
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT migration_kind FROM registry_internal.registry_migrations WHERE activation_id::text = $1",
            &[&identity.activation_id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "metadata-only");
    let current = successor_client(&fixture, registry, identity).await;
    let metadata = current
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let proposal = current
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap()
        .value
        .items
        .into_iter()
        .find(|proposal| proposal.id() == submitted.id())
        .unwrap();
    assert!(proposal.blocked_reason().is_none());
    assert_eq!(proposal.effect_digest(), submitted.effect_digest());
    let apply = current
        .client
        .prepare_proposal(
            &proposal,
            "apply",
            json!({"submissionVersion":1,"effectDigest":proposal.effect_digest().unwrap()}),
            &key("compatible-apply"),
        )
        .unwrap();
    assert_eq!(
        current
            .client
            .execute_proposal(&apply)
            .await
            .unwrap()
            .value
            .state(),
        BRegProposalState::Applied
    );
    drop(current);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(feature = "tooling")]
async fn narrowed_attachment_disclosure_refuses_the_old_exact_receipt_without_reexecution() {
    let source = registry_source(false);
    let fixture =
        client_http::ClientFixture::start(compile(source.clone()), claims("author", "zone-a"))
            .await;
    let draft = start(&fixture, "Disclosure narrowed", "narrow-start").await;
    let uploaded = fixture
        .http
        .client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"private-slot-canary",
            &key("narrow-upload"),
        )
        .await
        .unwrap()
        .value;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&uploaded, "submit", json!({}), &key("narrow-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let apply = fixture
        .http
        .client
        .prepare_proposal(
            &submitted,
            "apply",
            json!({"submissionVersion":1,"effectDigest":submitted.effect_digest().unwrap()}),
            &key("narrow-apply"),
        )
        .unwrap();
    let applied = fixture
        .http
        .client
        .execute_proposal(&apply)
        .await
        .unwrap()
        .value;
    assert!(
        serde_json::to_value(&applied).unwrap()["attachments"]["support"]
            .get("value")
            .is_some()
    );
    let saved: Value = serde_json::from_slice(apply.as_bytes()).unwrap();
    let mut next = source;
    next["accessProfiles"][0]["permissions"]["proposals"][0]["readableAttachments"] = json!([]);
    assert_eq!(
        fixture.registry.actions().actions[0].definition_revision,
        compile(next.clone()).actions().actions[0].definition_revision
    );
    let (registry, identity) = proposal_activation::activate_successor(&fixture, &next).await;
    let current = successor_client(&fixture, registry, identity).await;
    let response = reqwest::Client::new()
        .post(format!(
            "{}{}",
            current.base_url.trim_end_matches('/'),
            saved["link"]["path"].as_str().unwrap()
        ))
        .query(&[(
            "accessProfile",
            saved["link"]["accessProfile"].as_str().unwrap(),
        )])
        .header("content-type", "application/json")
        .header("if-match", saved["link"]["ifMatch"].as_str().unwrap())
        .header("idempotency-key", saved["key"].as_str().unwrap())
        .body(saved["body"].as_str().unwrap().to_owned())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
    let refused = response.text().await.unwrap();
    assert!(!refused.contains("private-slot-canary"));
    assert!(!refused.contains("sha256"));
    let metadata = current
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let page = current
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap();
    assert!(
        serde_json::to_value(&page.value.items[0]).unwrap()["attachments"]["support"]
            .get("value")
            .is_none()
    );
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_internal.registry_proposal_applications),
        (SELECT count(*) FROM registry_internal.registry_revisions)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 2);
    drop(current);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(feature = "tooling")]
async fn review_context_refuses_active_action_mapping_for_a_retained_submission() {
    let mut source = registry_source(false);
    source["actions"][0]["execution"]["proposal"]["reviewContext"] = json!({
        "id":"review-name","fields":{
            "proposedName":{"type":"input","input":"value"},
            "currentName":{"type":"record","input":"target","field":"name"},
            "changes":{"type":"changes","recordType":"target","fields":["name"]}
        }
    });
    source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .extend([json!("get-review-context"), json!("get-review-status")]);
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableContextFields"] =
        json!(["proposedName", "currentName", "changes"]);
    let fixture =
        client_http::ClientFixture::start(compile(source.clone()), claims("author", "zone-a"))
            .await;
    let draft = start(&fixture, "frozen-name-canary", "mapping-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("mapping-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let path = format!(
        "/v1/proposals/{}/review-context?accessProfile=clerk",
        submitted.id()
    );
    let response = reqwest::get(format!("{}{path}", fixture.http.base_url))
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let original: Value = response.json().await.unwrap();
    assert_eq!(
        original["actionRevision"],
        fixture.registry.actions().actions[0].definition_revision
    );
    assert_eq!(
        original["context"]["fields"]["proposedName"],
        "frozen-name-canary"
    );
    assert_eq!(
        original["context"]["fields"]["changes"][0]["after"]["name"],
        "frozen-name-canary"
    );

    let mut next = source;
    // The same public field now means a different frozen input. Even though both
    // values exist, the current mapping must not reinterpret the old submission.
    next["actions"][0]["execution"]["proposal"]["reviewContext"]["fields"]["proposedName"] =
        json!({"type":"input","input":"target"});
    assert_ne!(
        fixture.registry.actions().actions[0].definition_revision,
        compile(next.clone()).actions().actions[0].definition_revision
    );
    let (registry, identity) = proposal_activation::activate_successor(&fixture, &next).await;
    let current_schema = registry_breg::compiler::review_context::compile_schema(
        &registry,
        &registry.actions().actions[0],
    )
    .unwrap()
    .unwrap();
    let current = successor_client(&fixture, registry, identity).await;
    let response = reqwest::get(format!("{}{path}", current.base_url))
        .await
        .unwrap();
    let status = response.status();
    let refused = response.text().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND, "{refused}");
    for hidden in [
        "frozen-name-canary",
        "proposedName",
        "currentName",
        "sha256:",
    ] {
        assert!(!refused.contains(hidden), "refusal disclosed {hidden}");
    }
    let status = reqwest::get(format!(
        "{}/v1/proposals/{}/review-status?accessProfile=clerk",
        current.base_url,
        submitted.id(),
    ))
    .await
    .unwrap();
    assert_eq!(status.status(), reqwest::StatusCode::OK);
    let status: Value = status.json().await.unwrap();
    assert_eq!(status["actionRevision"], original["actionRevision"]);
    assert!(status["context"].get("fields").is_none());
    assert_eq!(
        status["context"]["contract"],
        json!({
            "id":current_schema.id,"revision":current_schema.revision,"schemaDigest":current_schema.digest,
        })
    );
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_internal.registry_proposal_applications),
            (SELECT count(*) FROM registry_internal.registry_revisions),
            action_revision FROM registry_internal.registry_proposal_state",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(
        row.get::<_, String>(2),
        original["actionRevision"].as_str().unwrap()
    );
    drop(current);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_context_projects_an_omitted_optional_input_as_null() {
    let mut source = registry_source(false);
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .extend([
            json!({"id":"note","type":"string","required":false,"maximumLength":64,"classification":"internal"}),
            json!({"id":"related","type":"reference","target":"target","required":false,"classification":"internal"}),
        ]);
    source["actions"][0]["execution"]["proposal"]["reviewContext"] = json!({
        "id":"review-optional","fields":{
            "proposedName":{"type":"input","input":"value"},
            "note":{"type":"input","input":"note"},
            "relatedName":{"type":"record","input":"related","field":"name"}
        }
    });
    source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .push(json!("get-review-context"));
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableContextFields"] =
        json!(["proposedName", "note", "relatedName"]);
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    // The shared helper supplies only the required inputs.
    let draft = start(&fixture, "optional-omitted", "optional-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("optional-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let response = reqwest::get(format!(
        "{}/v1/proposals/{}/review-context?accessProfile=clerk",
        fixture.http.base_url,
        submitted.id()
    ))
    .await
    .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    let context: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        context["context"]["fields"],
        json!({"proposedName":"optional-omitted","note":null,"relatedName":null})
    );
    let missing = uuid::Uuid::new_v4().to_string();
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/proposals/review-context",
            fixture.http.base_url
        ))
        .query(&[
            ("accessProfile", "clerk"),
            ("ids", &format!("{},{}", submitted.id(), missing)),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "bounded context exchange is served"
    );
    let batch: Value = response.json().await.unwrap();
    assert_eq!(batch["items"].as_array().unwrap().len(), 2);
    assert_eq!(
        batch["items"][0],
        json!({"id": submitted.id(), "status":"visible", "context": context})
    );
    assert_eq!(
        batch["items"][1],
        json!({"id": missing, "status":"concealed"})
    );
    let before = fixture.audit_capture.entries().len();
    let excessive = (0..101)
        .map(|_| uuid::Uuid::new_v4().to_string())
        .collect::<Vec<_>>()
        .join(",");
    for ids in [
        String::new(),
        format!("{},{}", submitted.id(), submitted.id()),
        excessive,
        "not-a-proposal".into(),
    ] {
        let response = reqwest::Client::new()
            .get(format!(
                "{}/v1/proposals/review-context",
                fixture.http.base_url
            ))
            .query(&[("accessProfile", "clerk"), ("ids", &ids)])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    }
    assert_eq!(
        fixture.audit_capture.entries().len(),
        before,
        "malformed batches are refused before per-item work"
    );
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/proposals/review-context",
            fixture.http.base_url
        ))
        .query(&[
            ("accessProfile", "ungranted-canary"),
            ("ids", submitted.id()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({"items":[{"id":submitted.id(),"status":"concealed"}]})
    );

    let second_draft = start(&fixture, "second-visible-canary", "second-start").await;
    let second_submit = fixture
        .http
        .client
        .prepare_proposal(&second_draft, "submit", json!({}), &key("second-submit"))
        .unwrap();
    let second = fixture
        .http
        .client
        .execute_proposal(&second_submit)
        .await
        .unwrap()
        .value;
    let before = fixture.audit_capture.entries().len();
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/proposals/review-context",
            fixture.http.base_url
        ))
        .query(&[
            ("accessProfile", "clerk"),
            ("ids", &format!("{},{}", submitted.id(), second.id())),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let visible: Value = response.json().await.unwrap();
    assert_eq!(visible["items"][0]["status"], "visible");
    assert_eq!(visible["items"][1]["status"], "visible");
    assert_eq!(fixture.audit_capture.entries().len() - before, 4);

    // Admit the first item's complete audit pair and the second item's start.
    // Refuse the second terminal entry after the first context was prepared.
    fixture.audit_capture.fail_after(3);
    let before = fixture.audit_capture.entries().len();
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/proposals/review-context",
            fixture.http.base_url
        ))
        .query(&[
            ("accessProfile", "clerk"),
            ("ids", &format!("{},{}", submitted.id(), second.id())),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let refused = response.text().await.unwrap();
    assert!(!refused.contains("optional-omitted"));
    assert!(!refused.contains("second-visible-canary"));
    assert!(!refused.contains("\"items\""));
    assert_eq!(fixture.audit_capture.entries().len() - before, 3);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(feature = "tooling")]
async fn retained_attachment_download_survives_tighter_current_upload_policy() {
    let mut source = registry_source(false);
    source["actions"][0]["execution"]["proposal"]["reviewContext"] = json!({"id":"retained-document","fields":{"document":{"type":"document","slot":"support"}}});
    source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .push(json!("get-review-context"));
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableContextFields"] =
        json!(["document"]);
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableInputs"] =
        json!(["target", "value"]);
    let fixture =
        client_http::ClientFixture::start(compile(source.clone()), claims("author", "zone-a"))
            .await;
    let draft = start(&fixture, "Retained attachment", "retained-start").await;
    let bytes = b"historical-text-attachment-canary";
    let uploaded = fixture
        .http
        .client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            bytes,
            &key("retained-upload"),
        )
        .await
        .unwrap()
        .value;
    let target = fixture
        .http
        .client
        .read_proposal(&uploaded)
        .await
        .unwrap()
        .value
        .input()
        .unwrap()["target"]
        .clone();
    let submit = fixture
        .http
        .client
        .prepare_proposal(&uploaded, "submit", json!({}), &key("retained-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let old_metadata = fixture
        .http
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap()
        .value;
    let old_binding = old_metadata
        .select_proposal_review_context("clerk", "correct-name")
        .unwrap();
    let old_context = fixture
        .http
        .client
        .read_proposal_review_by_id(&old_binding, submitted.id())
        .await
        .unwrap()
        .value;
    let mut next = source;
    next["actions"][0]["execution"]["proposal"]["attachments"][0]["maximumBytes"] = json!(8);
    next["actions"][0]["execution"]["proposal"]["attachments"][0]["contentTypes"] =
        json!(["application/octet-stream"]);
    let (registry, identity) = proposal_activation::activate_successor(&fixture, &next).await;
    let current_schema = registry_breg::compiler::review_context::compile_schema(
        &registry,
        &registry.actions().actions[0],
    )
    .unwrap()
    .unwrap();
    let current = successor_client(&fixture, registry, identity).await;
    let metadata = current
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let listed = current
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap()
        .value
        .items
        .into_iter()
        .find(|proposal| proposal.id() == submitted.id())
        .unwrap();
    let retained = current.client.read_proposal(&listed).await.unwrap().value;
    let value = serde_json::to_value(&retained).unwrap();
    assert_eq!(value["attachments"]["support"]["maximumBytes"], 8);
    assert_eq!(
        value["attachments"]["support"]["contentTypes"],
        json!(["application/octet-stream"])
    );
    assert_eq!(
        value["attachments"]["support"]["value"]["byteSize"],
        bytes.len()
    );
    assert_eq!(
        value["attachments"]["support"]["value"]["contentType"],
        "text/plain"
    );
    let raw = reqwest::get(format!(
        "{}/v1/proposals/{}/attachments/support?accessProfile=clerk&submissionVersion=1",
        current.base_url,
        retained.id()
    ))
    .await
    .unwrap();
    assert_eq!(raw.status(), reqwest::StatusCode::OK);
    assert_eq!(raw.headers()["content-type"], "text/plain");
    assert_eq!(raw.bytes().await.unwrap().as_ref(), bytes);
    let binding = metadata
        .value
        .select_proposal_review_context("clerk", "correct-name")
        .unwrap();
    assert!(
        current
            .client
            .read_proposal_review_by_id(&binding, submitted.id())
            .await
            .is_err(),
        "a fresh context must not reinterpret the retained submission under a changed Action"
    );
    assert!(
        current
            .client
            .download_proposal_review_document(&binding, &old_context, "document")
            .await
            .is_err(),
        "a saved review link cannot release bytes after the Action revision changes"
    );

    let saved_path = old_context.context.fields.as_ref().unwrap()["document"]["download"]["path"]
        .as_str()
        .unwrap();
    let current_schema_path = saved_path.replace(
        &old_context
            .context
            .contract
            .as_ref()
            .unwrap()
            .schema_digest
            .replace(':', "%3A"),
        &current_schema.digest.replace(':', "%3A"),
    );
    for path in [saved_path, current_schema_path.as_str()] {
        let response = reqwest::get(format!("{}{path}&accessProfile=clerk", current.base_url))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "review bytes require the frozen Action even with today's context schema"
        );
        assert!(!response
            .text()
            .await
            .unwrap()
            .contains("historical-text-attachment-canary"));
    }

    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"target":target,"value":"Current draft"})),
        None,
    )
    .unwrap();
    let current_draft = current
        .client
        .start_proposal(&action, &input, &key("current-policy-start"))
        .await
        .unwrap()
        .value;
    for (content_type, upload, expected) in [
        (
            "application/octet-stream",
            bytes.as_slice(),
            reqwest::StatusCode::BAD_REQUEST,
        ),
        (
            "text/plain",
            b"ok".as_slice(),
            reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
    ] {
        assert!(current
            .client
            .upload_proposal_attachment(
                &current_draft,
                "support",
                content_type,
                upload,
                &key("current-policy-refused")
            )
            .await
            .is_err());
        let value = serde_json::to_value(&current_draft).unwrap();
        let response = reqwest::Client::new()
            .patch(format!(
                "{}/v1/proposals/{}/attachments/support?accessProfile=clerk",
                current.base_url,
                current_draft.id()
            ))
            .header("content-type", content_type)
            .header("idempotency-key", "current-policy-raw-refused")
            .header(
                "if-match",
                value["attachments"]["support"]["links"]["upload"]["ifMatch"]
                    .as_str()
                    .unwrap(),
            )
            .body(upload.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    current
        .client
        .upload_proposal_attachment(
            &current_draft,
            "support",
            "application/octet-stream",
            b"ok",
            &key("current-policy-accepted"),
        )
        .await
        .unwrap();
    assert_eq!(current.client.download_proposal_attachment(&retained, "support").await
        .expect("authorized retained content uses its stored size rather than today's upload ceiling").value.as_bytes(), bytes);
    drop(current);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(feature = "tooling")]
async fn review_pin_only_verified_activation_blocks_apply_but_preserves_inspection_and_cancel() {
    let mut source = registry_source(false);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test",
        "policy":{"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))}});
    let review = std::sync::Arc::new(LocalReview {
        calls: 0.into(),
        mode: 3.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source.clone()),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), review)
        },
    )
    .await;
    let draft = start(&fixture, "Must not apply old policy", "pin-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("pin-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let mut next = source;
    next["actions"][0]["execution"]["proposal"]["review"]["policy"]["digest"] =
        json!(format!("sha256:{}", "c".repeat(64)));
    let candidate = compile(next.clone());
    assert_ne!(
        fixture.registry.actions().actions[0].definition_revision,
        candidate.actions().actions[0].definition_revision
    );
    let (registry, identity) = proposal_activation::activate_successor(&fixture, &next).await;
    let current = successor_client(&fixture, registry, identity).await;
    let metadata = current
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let proposal = current
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap()
        .value
        .items
        .into_iter()
        .find(|proposal| proposal.id() == submitted.id())
        .unwrap();
    assert_eq!(proposal.blocked_reason(), Some("package-changed"));
    assert_eq!(proposal.effect_digest(), submitted.effect_digest());
    let apply = proposal.link("apply").unwrap().availability().unwrap();
    assert!(!apply.available);
    assert_eq!(
        apply.reason,
        Some(registry_breg_client::BRegAvailabilityReason::ContractChanged)
    );
    let cancel = current
        .client
        .prepare_proposal(&proposal, "cancel", json!({}), &key("pin-cancel"))
        .unwrap();
    assert_eq!(
        current
            .client
            .execute_proposal(&cancel)
            .await
            .unwrap()
            .value
            .state(),
        BRegProposalState::Cancelled
    );
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_internal.registry_proposal_applications),
        (SELECT count(*) FROM registry_internal.registry_migrations WHERE outcome='applied')",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 2);
    drop(current);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_receipt_replay_refuses_a_task_grant_expiring_at_the_idempotency_lock() {
    use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
    use registry_breg::task_grant::{TaskGrantBinding, TaskGrantError, TaskGrantStatusChecker};
    use registry_platform_httputil::FetchUrlPolicy;
    use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
    use registry_platform_testing::{oidc_verifier_config, MockIdp};
    use std::{sync::Arc, time::Duration};
    struct Current;
    impl TaskGrantStatusChecker for Current {
        fn check<'a>(
            &'a self,
            _: &'a TaskGrantBinding,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), TaskGrantError>> + Send + 'a>,
        > {
            Box::pin(async { Ok(()) })
        }
    }
    let mut source = registry_source(false);
    let mut permission = source["accessProfiles"][0]["permissions"]["proposals"][0].clone();
    permission["operations"] = json!(["get", "apply"]);
    permission["readableAttachments"] = json!([]);
    permission["writableAttachments"] = json!([]);
    source["accessProfiles"].as_array_mut().unwrap().push(json!({"id":"task-applier","actorKind":"agent",
        "requesterClients":["agent-client"],"principalClaim":"sub","requiredScopes":["proposal:manage"],
        "requiredPurposes":["registry-administration"],"taskGrant":{"sourceIssuer":"https://casework.example"},
        "permissions":{"proposals":[permission]}}));
    let registry = compile(source);
    let idp = MockIdp::start().await;
    let mut verifier = oidc_verifier_config(idp.issuer(), vec!["urn:example:breg".into()]);
    verifier.allowed_clients = vec!["agent-client".into()];
    let auth = RegistryAuthenticator::new(
        &registry,
        verifier,
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )),
        AuthorityClaimConfig::new("sub", Some("registry_purpose".into())),
    )
    .unwrap();
    let human = json!({"aud":"urn:example:breg","sub":"author","azp":"agent-client","registry_actor_kind":"human",
        "registry_purpose":"registry-administration","scope":"proposal:manage","jurisdiction":"zone-a"});
    let human = auth.authenticate(&idp.mint_token(human)).await.unwrap();
    let fixture = client_http::ClientFixture::start_with_mutations(registry, human, |mutations| {
        mutations
            .with_task_status(Arc::new(Current))
            .with_action_timeout_for_test(Duration::from_secs(8))
    })
    .await;
    let draft = start(&fixture, "One retained application", "expiry-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("expiry-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3;
    let token = json!({"aud":"urn:example:breg","sub":"author","azp":"agent-client","registry_actor_kind":"agent",
        "registry_purpose":"registry-administration","scope":"proposal:manage",
        "registry_grant_id":"00000000-0000-4000-8000-000000000071","registry_approver":"h:approver",
        "registry_grant_source_issuer":"https://casework.example","registry_grant_client":"agent-client",
        "registry_grant_resource":"urn:example:breg","registry_grant_exp":expiry,
        "registry_grant_bounds":{"type":"breg","permissions":[{"collection":format!("proposal:{}",submitted.id()),"operations":["get","apply"]}]},
        "identity":{"jurisdiction":"zone-a"},"jurisdiction":"zone-b"});
    let caller = auth.authenticate(&idp.mint_token(token)).await.unwrap();
    let audit = registry_breg::audit::test_support::capturing(
        registry_platform_audit::AuditProfile::production_from_secret_bytes(vec![0x61; 32].into())
            .unwrap(),
    )
    .0;
    let service = registry_breg::postgres::PostgresRecordMutationService::new(
        fixture.pool.clone(),
        fixture.registry.clone(),
        fixture.identity.clone(),
        "task-expiry",
        registry_breg::postgres::RegistryLockKey::derive(fixture.registry.registry_id()).unwrap(),
        Duration::from_secs(10),
        audit,
    )
    .with_task_status(Arc::new(Current))
    .with_action_timeout_for_test(Duration::from_secs(8));
    let task = fixture.client_with_mutations(caller, service).await;
    let metadata = task
        .client
        .registry_contract(Some("task-applier"))
        .await
        .unwrap();
    let get = metadata.value.select_proposal_get("task-applier").unwrap();
    let proposal = task
        .client
        .get_proposal(&get, submitted.id())
        .await
        .unwrap()
        .value;
    let apply = task
        .client
        .prepare_proposal(
            &proposal,
            "apply",
            json!({"submissionVersion":proposal.submission_version(),
        "effectDigest":proposal.effect_digest().unwrap()}),
            &key("expiry-apply"),
        )
        .unwrap();
    task.client.execute_proposal(&apply).await.unwrap();
    let lock_ref:String=fixture.database.admin.query_one("SELECT key_reference FROM registry_internal.registry_idempotency WHERE idempotency_key='expiry-apply'",&[])
        .await.unwrap().get(0);
    fixture
        .database
        .admin
        .execute(
            "SELECT pg_advisory_lock(pg_catalog.hashtextextended($1,0))",
            &[&lock_ref],
        )
        .await
        .unwrap();
    let waiting = task.client.execute_proposal(&apply);
    let release = async {
        tokio::time::timeout(Duration::from_secs(1),async{loop{
            let blocked:i64=fixture.database.admin.query_one("SELECT count(*)::bigint FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())",&[]).await.unwrap().get(0);
            if blocked>0{break;}tokio::time::sleep(Duration::from_millis(10)).await;
        }}).await.expect("replay passed current admission and reached the idempotency lock");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        tokio::time::sleep(Duration::from_millis(
            (u128::from(expiry) * 1000).saturating_sub(now) as u64 + 30,
        ))
        .await;
        fixture
            .database
            .admin
            .execute(
                "SELECT pg_advisory_unlock(pg_catalog.hashtextextended($1,0))",
                &[&lock_ref],
            )
            .await
            .unwrap();
    };
    let (outcome, ()) = tokio::join!(waiting, release);
    assert_eq!(
        outcome.unwrap_err().problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    let row=fixture.database.admin.query_one("SELECT (SELECT count(*) FROM registry_internal.registry_proposal_applications),(SELECT count(*) FROM registry_internal.registry_idempotency WHERE idempotency_key='expiry-apply')",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(
        row.get::<_, i64>(1),
        1,
        "expired replay neither reexecutes nor replaces the receipt"
    );
    drop(task);
    fixture.finish().await;
}

#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compatible_legacy_review_closure_survives_status_apply_successors_and_role_reactivation() {
    use registry_breg::migration::{
        apply_verified_package, ActivationDeployment, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
        ApplyVerifiedPackageRequest,
    };
    let mut source = registry_source(true);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let old_policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
    let review_source = "shared.facility.registry:v1";
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":review_source,"policy":old_policy});
    source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .push(json!("get-review-status"));
    let authority = proposal_review_authority::LocalAuthority::start_for_registry(
        serde_json::from_value(old_policy.clone()).unwrap(),
        review_source,
    )
    .await;
    let configured = authority.registry.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source.clone()),
        claims("author", "zone-a"),
        move |mutations| mutations.with_review_result_source(configured),
    )
    .await;
    let runtime = fixture.pool.get_for_test().await.unwrap();
    let _:i64=runtime.query_one("SELECT count(*)::bigint FROM registry_internal.registry_proposal_activation_compatibility",&[]).await.unwrap().get(0);
    for statement in [
        "INSERT INTO registry_internal.registry_proposal_activation_compatibility(action_id) SELECT 'synthetic' WHERE false",
        "UPDATE registry_internal.registry_proposal_activation_compatibility SET closure_digest=closure_digest WHERE false",
        "DELETE FROM registry_internal.registry_proposal_activation_compatibility WHERE false",
    ] {
        let error = runtime
            .execute(statement, &[])
            .await
            .expect_err("runtime compatibility authority is SELECT only");
        assert_eq!(error.code().map(|code| code.code()), Some("42501"));
    }
    drop(runtime);
    let draft = start(&fixture, "Retain original review closure", "closure-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("closure-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT state FROM registry_internal.registry_proposal_review_submissions",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "pending");
    // The ordinary durable handoff completes before proof preparation. The
    // activation factory performs GETs only and never sends creation payloads.
    assert!(
        registry_breg::review_store::run_review_authority_once_for_test(
            &fixture.pool,
            &authority.registry,
            &fixture.mutations,
        )
        .await
        .unwrap()
    );
    assert!(
        registry_breg::review_store::run_review_authority_once_for_test(
            &fixture.pool,
            &authority.registry,
            &fixture.mutations,
        )
        .await
        .unwrap()
    );
    let retained = fixture
        .database
        .admin
        .query_one(
            "SELECT q.create_request,q.producer_id,q.idempotency_key,q.expected_submission_digest,
                q.accepted_binding,r.result
           FROM registry_internal.registry_proposal_review_submissions q
           JOIN registry_internal.registry_proposal_review_results r
             USING(action_id,proposal_id,submission_version)",
            &[],
        )
        .await
        .unwrap();
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(retained.get(0)).unwrap();
    let producer: String = retained.get(1);
    let legacy_digest = registry_review_client::submission_digest(
        &producer,
        fixture.registry.registry_id(),
        &create,
    )
    .unwrap();
    assert_ne!(
        legacy_digest.as_str(),
        retained.get::<_, String>(3),
        "the regression needs the historical registry-id digest to differ"
    );
    let mut accepted: registry_review_client::ReviewRequestAccepted =
        serde_json::from_value(retained.get(4)).unwrap();
    accepted.submission_digest = legacy_digest.clone();
    let mut result: registry_review_client::ReviewResult =
        serde_json::from_value(retained.get(5)).unwrap();
    result.submission_digest = legacy_digest.clone();
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_review_submissions
            SET expected_submission_digest=$1,accepted_binding=$2",
            &[&legacy_digest.as_str(), &json!(accepted)],
        )
        .await
        .unwrap();
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_review_results SET result=$1",
            &[&json!(result)],
        )
        .await
        .unwrap();
    authority.replace_submission_digest_for_test(legacy_digest.clone());
    let immutable_review: Value = fixture
        .database
        .admin
        .query_one(
            "SELECT jsonb_build_object(
                    'request',create_request,
                    'key',idempotency_key,
                    'digest',expected_submission_digest,
                    'binding',accepted_binding)
           FROM registry_internal.registry_proposal_review_submissions",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let status = reqwest::Client::new()
        .get(format!(
            "{}/v1/proposals/{}/review-status?accessProfile=clerk",
            fixture.http.base_url,
            submitted.id(),
        ))
        .send()
        .await
        .unwrap();
    let status_code = status.status();
    let status_body: Value = status.json().await.unwrap();
    assert_eq!(status_code, reqwest::StatusCode::OK, "{status_body}");
    assert_eq!(status_body["result"]["state"], "approved");
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT snapshot FROM registry_internal.registry_proposal_submissions",
            &[],
        )
        .await
        .unwrap();
    let original: Value = row.get(0);
    let mut next = source.clone();
    next["actions"][0]["execution"]["proposal"]["review"]["policy"]["digest"] =
        json!(format!("sha256:{}", "c".repeat(64)));
    let (package_b, identity_b) = proposal_activation::activate_with_compatibility(
        &fixture,
        &fixture.registry,
        &fixture.identity,
        &next,
        Some(&authority.registry),
    )
    .await;
    let inspection =
        successor_client(&fixture, package_b.registry().clone(), identity_b.clone()).await;
    let contract = inspection
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let get = contract.value.select_proposal_get("clerk").unwrap();
    let current = inspection
        .client
        .get_proposal(&get, submitted.id())
        .await
        .unwrap()
        .value;
    let revise = current.link("revise").unwrap();
    let availability = revise.availability().unwrap();
    assert!(
        !availability.available,
        "ordinary Revise never changes the frozen Action revision"
    );
    assert_eq!(
        availability.reason,
        Some(registry_breg_client::BRegAvailabilityReason::ContractChanged)
    );
    assert_eq!(
        availability.recovery,
        Some(registry_breg_client::BRegRecoveryHint::Refresh)
    );
    assert!(
        current
            .link("rebase")
            .unwrap()
            .availability()
            .unwrap()
            .available,
        "explicit Rebase remains available with current Start authority"
    );
    let response = reqwest::Client::new()
        .post(format!(
            "{}/v1/proposals/{}/revise?accessProfile=clerk",
            inspection.base_url,
            submitted.id()
        ))
        .header("idempotency-key", "compatible-cannot-revise-contract")
        .header(
            "if-match",
            serde_json::to_value(&current).unwrap()["links"]["revise"]["ifMatch"]
                .as_str()
                .unwrap(),
        )
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::PRECONDITION_FAILED);
    drop(inspection);
    let mut third = next.clone();
    third["actions"][0]["display"] = json!({"label":"Current correction label"});
    let (package_c, identity_c) = proposal_activation::activate_with_compatibility(
        &fixture,
        package_b.registry(),
        &identity_b,
        &third,
        Some(&authority.registry),
    )
    .await;
    let inventory = registry_breg::proposal_retention::prepare_proposal_activation_compatibility(
        &fixture.pool,
        &identity_c,
        &package_c,
        &authority.registry,
        std::time::Duration::from_secs(2),
    )
    .await
    .unwrap();
    // A role-only same-package activation repairs a deliberately missing
    // runtime read grant. It appends proof under a new activation identity.
    fixture.database.admin.batch_execute(&format!("REVOKE SELECT ON registry_internal.registry_proposal_activation_compatibility FROM \"{}\"",
        fixture.database.runtime_role.as_str())).await.unwrap();
    let identity_d = apply_verified_package(
        ApplyVerifiedPackageRequest::new(
            &fixture.database.migration_config,
            &package_c,
            ActivationDeployment::new("local", "proposal-role-repair", &identity_c.database_id),
            ApplyPrecondition::RoleChange {
                current: &identity_c,
            },
            ApplyRoles::new(
                &fixture.database.migration_role,
                &fixture.database.runtime_role,
            ),
            ApplyTimeouts::new(
                std::time::Duration::from_secs(2),
                std::time::Duration::from_secs(10),
            )
            .unwrap(),
            fixture.database.activation_audit(),
        )
        .with_proposal_activation_compatibility(&inventory),
    )
    .await
    .unwrap();
    assert_eq!(identity_d.package_digest, identity_c.package_digest);
    assert_ne!(identity_d.activation_id, identity_c.activation_id);
    let row=fixture.database.admin.query_one("SELECT count(*)::bigint FROM registry_internal.registry_proposal_activation_compatibility",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 3);
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT blocked_reason,action_revision FROM registry_internal.registry_proposal_state",
            &[],
        )
        .await
        .unwrap();
    assert!(row.get::<_, Option<String>>(0).is_none());
    assert_eq!(
        row.get::<_, String>(1),
        fixture.registry.actions().actions[0].definition_revision
    );
    let before = authority.counts();
    assert_eq!(before.0, 1);
    assert_eq!(before.1, 3);
    let registry = std::sync::Arc::new(package_c.registry().clone());
    let audit = registry_breg::audit::test_support::capturing(
        registry_platform_audit::AuditProfile::production_from_secret_bytes(vec![0x61; 32].into())
            .unwrap(),
    )
    .0;
    let mutations = registry_breg::postgres::PostgresRecordMutationService::new(
        fixture.pool.clone(),
        registry.clone(),
        identity_d,
        "client-capability-test",
        registry_breg::postgres::RegistryLockKey::derive(registry.registry_id()).unwrap(),
        std::time::Duration::from_secs(2),
        audit,
    )
    .with_review_result_source(authority.registry.clone());
    assert!(mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    assert_eq!(
        authority.counts().0,
        1,
        "activation never re-creates an old review under the new policy"
    );
    assert_eq!(
        authority.counts().2,
        before.2 + 1,
        "uncommitted automatic apply fetches fresh original approval"
    );
    let row=fixture.database.admin.query_one("SELECT s.snapshot,w.state,q.expected_policy,
        (SELECT count(*) FROM registry_internal.registry_proposal_applications)
        FROM registry_internal.registry_proposal_submissions s JOIN registry_internal.registry_proposal_state w USING(action_id,proposal_id,submission_version)
        JOIN registry_internal.registry_proposal_review_submissions q USING(action_id,proposal_id,submission_version)",&[]).await.unwrap();
    assert_eq!(row.get::<_, Value>(0), original);
    assert_eq!(row.get::<_, String>(1), "applied");
    assert_eq!(row.get::<_, Value>(2), old_policy);
    assert_eq!(row.get::<_, i64>(3), 1);
    assert_eq!(submitted.submission_version(), 1);
    let after: Value = fixture
        .database
        .admin
        .query_one(
            "SELECT jsonb_build_object(
                    'request',create_request,
                    'key',idempotency_key,
                    'digest',expected_submission_digest,
                    'binding',accepted_binding)
           FROM registry_internal.registry_proposal_review_submissions",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        after, immutable_review,
        "status, activation, and Apply preserve the historical accepted closure"
    );
    fixture.finish().await;
}

#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compatibility_inventory_refuses_rebound_frozen_review_subject_context_and_result() {
    use sha2::{Digest, Sha256};
    let mut source = registry_source(true);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let old_policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":old_policy});
    let authority = proposal_review_authority::LocalAuthority::start(
        serde_json::from_value(old_policy).unwrap(),
    )
    .await;
    let configured = authority.registry.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source.clone()),
        claims("author", "zone-a"),
        move |mutations| mutations.with_review_result_source(configured),
    )
    .await;
    let draft = start(
        &fixture,
        "Frozen closure tamper must refuse",
        "tamper-start",
    )
    .await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("tamper-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    assert!(
        registry_breg::review_store::run_review_authority_once_for_test(
            &fixture.pool,
            &authority.registry,
            &fixture.mutations,
        )
        .await
        .unwrap()
    );
    assert!(
        registry_breg::review_store::run_review_authority_once_for_test(
            &fixture.pool,
            &authority.registry,
            &fixture.mutations,
        )
        .await
        .unwrap()
    );
    let mut next = source;
    next["actions"][0]["execution"]["proposal"]["review"]["policy"]["digest"] =
        json!(format!("sha256:{}", "c".repeat(64)));
    let candidate = proposal_activation::verified_successor(
        &fixture,
        &fixture.registry,
        &fixture.identity,
        &next,
    )
    .await;
    let saved=fixture.database.admin.query_one("SELECT p.snapshot,q.create_request,q.expected_submission_digest,r.completed_at,q.accepted_binding,r.result
        FROM registry_internal.registry_proposal_submissions p JOIN registry_internal.registry_proposal_review_submissions q USING(action_id,proposal_id,submission_version)
        JOIN registry_internal.registry_proposal_review_results r USING(action_id,proposal_id,submission_version)",&[]).await.unwrap();
    let original: Value = saved.get(0);
    let create: Value = saved.get(1);
    let expected: String = saved.get(2);
    let completed: chrono::DateTime<chrono::Utc> = saved.get(3);
    let accepted_binding: Value = saved.get(4);
    let retained_result: Value = saved.get(5);
    let packet_key = registry_breg::proposal_workflow::ProposalKey::new(
        registry_breg::proposal_workflow::EntityId::new("correct-name").unwrap(),
        registry_breg::proposal_workflow::RecordId::new(submitted.id()).unwrap(),
    );
    // This packet has a valid recomputed digest and matching state/queued
    // digest. The independently authenticated old queued Review remains Required.
    let mut downgraded = original.clone();
    downgraded["reviewRequirement"] = json!({"type":"none"});
    let mut digest_input = json!({"schema":"breg.proposal/v1","inputs":downgraded["inputs"],"inputTargets":downgraded["inputTargets"],
        "proposal":packet_key,"submissionVersion":downgraded["submissionVersion"],"inputRevision":downgraded["inputRevision"],
        "contractFingerprint":downgraded["contractFingerprint"],"originatingPackage":downgraded["originatingPackage"],
        "review":downgraded["reviewRequirement"],"application":downgraded["applicationPolicy"],"systemGrantRevision":downgraded["systemGrantRevision"],
        "planningBinding":downgraded["planningBinding"],"effects":downgraded["effects"]});
    if let Some(value) = downgraded.get("applicationPreconditions") {
        digest_input["applicationPreconditions"] = value.clone();
    }
    if let Some(value) = downgraded.get("attachments") {
        digest_input["attachments"] = value.clone();
    }
    let bytes = registry_platform_canonical_json::canonicalize_json(&digest_input).unwrap();
    let digest = format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    downgraded["effectDigest"] = json!(digest);
    let frozen: registry_breg::proposal_workflow::ProposalSnapshot =
        serde_json::from_value(downgraded.clone()).unwrap();
    frozen
        .verify_digest(&packet_key)
        .expect("negative reaches closure validation after valid packet digest");
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_submissions SET snapshot=$1,effect_digest=$2",&[&downgraded,&digest]).await.unwrap();
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_review_submissions SET proposal_digest=$1",
            &[&digest],
        )
        .await
        .unwrap();
    let proof = registry_breg::proposal_retention::prepare_proposal_activation_compatibility(
        &fixture.pool,
        &fixture.identity,
        &candidate,
        &authority.registry,
        std::time::Duration::from_secs(2),
    )
    .await;
    assert!(
        proof.is_err(),
        "frozen Review=None cannot reuse an authenticated Required closure"
    );
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_submissions SET snapshot=$1,effect_digest=$2",&[&original,&submitted.effect_digest().unwrap()]).await.unwrap();
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_review_submissions SET proposal_digest=$1",
            &[&submitted.effect_digest().unwrap()],
        )
        .await
        .unwrap();
    for (field, value) in [
        (
            "subject",
            json!({"source":"another-source","type":"proposal","id":submitted.id(),"version":"1","digest":submitted.effect_digest().unwrap()}),
        ),
        (
            "context",
            json!({"mode":"current-source","binding":{"reference":"breg:wrong:correct-name:other:1"}}),
        ),
        ("policy-id", json!("other-policy")),
        ("policy-version", json!("2")),
        (
            "policy-digest",
            json!(registry_review_client::ContentDigest::for_bytes(
                b"other-policy"
            )),
        ),
    ] {
        let mut altered = create.clone();
        if let Some(policy_field) = field.strip_prefix("policy-") {
            altered["policy"][policy_field] = value;
        } else {
            altered[field] = value;
        }
        let request: registry_review_client::ReviewCreateRequest =
            serde_json::from_value(altered.clone()).unwrap();
        let recomputed = registry_review_client::submission_digest(
            "proposal-producer",
            "proposal-test",
            &request,
        )
        .unwrap();
        // Keep the local digest evidence internally consistent: the frozen
        // expected policy must independently reject the substituted request.
        let mut altered_binding = accepted_binding.clone();
        altered_binding["submissionDigest"] = json!(recomputed);
        let mut altered_result = retained_result.clone();
        altered_result["submissionDigest"] = json!(recomputed);
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET create_request=$1,expected_submission_digest=$2,accepted_binding=$3",
            &[&altered,&recomputed.as_str(),&altered_binding]).await.unwrap();
        fixture
            .database
            .admin
            .execute(
                "UPDATE registry_internal.registry_proposal_review_results SET result=$1",
                &[&altered_result],
            )
            .await
            .unwrap();
        let calls = authority.counts();
        assert!(
            registry_breg::proposal_retention::prepare_proposal_activation_compatibility(
                &fixture.pool,
                &fixture.identity,
                &candidate,
                &authority.registry,
                std::time::Duration::from_secs(2)
            )
            .await
            .is_err(),
            "rebound {field} refuses"
        );
        assert_eq!(
            authority.counts(),
            calls,
            "reject {field} before remote proof"
        );
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET create_request=$1,expected_submission_digest=$2,accepted_binding=$3",&[&create,&expected,&accepted_binding]).await.unwrap();
        fixture
            .database
            .admin
            .execute(
                "UPDATE registry_internal.registry_proposal_review_results SET result=$1",
                &[&retained_result],
            )
            .await
            .unwrap();
    }
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_results SET completed_at=completed_at+interval '1 microsecond'",&[]).await.unwrap();
    assert!(
        registry_breg::proposal_retention::prepare_proposal_activation_compatibility(
            &fixture.pool,
            &fixture.identity,
            &candidate,
            &authority.registry,
            std::time::Duration::from_secs(2)
        )
        .await
        .is_err(),
        "result column timestamp must equal immutable result"
    );
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_review_results SET completed_at=$1",
            &[&completed],
        )
        .await
        .unwrap();
    let count:i64=fixture.database.admin.query_one("SELECT count(*)::bigint FROM registry_internal.registry_proposal_activation_compatibility",&[]).await.unwrap().get(0);
    assert_eq!(count, 0, "no negative proof persists compatibility");
    assert_eq!(
        authority.counts().1,
        0,
        "tampered closure refuses before HTTP proof reads"
    );
    fixture.finish().await;
}

#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn incompatible_or_expired_inventory_cannot_activate_or_change_proposals_and_records() {
    use registry_breg::migration::{
        apply_verified_package, ActivationDeployment, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
        ApplyVerifiedPackageRequest,
    };
    use std::time::Duration;
    for expired in [false, true] {
        let mut source = registry_source(true);
        source["reviewAuthorities"] =
            json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
        let old_policy = json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
        source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":old_policy});
        let authority = proposal_review_authority::LocalAuthority::start(
            serde_json::from_value(old_policy).unwrap(),
        )
        .await;
        let configured = authority.registry.clone();
        let fixture = client_http::ClientFixture::start_with_mutations(
            compile(source.clone()),
            claims("author", "zone-a"),
            move |mutations| mutations.with_review_result_source(configured),
        )
        .await;
        let draft = start(
            &fixture,
            "Refused activation keeps original work",
            if expired {
                "expired-proof-start"
            } else {
                "wrong-proof-start"
            },
        )
        .await;
        let submit = fixture
            .http
            .client
            .prepare_proposal(&draft, "submit", json!({}), &key("rollback-submit"))
            .unwrap();
        fixture.http.client.execute_proposal(&submit).await.unwrap();
        assert!(
            registry_breg::review_store::run_review_authority_once_for_test(
                &fixture.pool,
                &authority.registry,
                &fixture.mutations,
            )
            .await
            .unwrap()
        );
        assert!(
            registry_breg::review_store::run_review_authority_once_for_test(
                &fixture.pool,
                &authority.registry,
                &fixture.mutations,
            )
            .await
            .unwrap()
        );
        let original: Value = fixture
            .database
            .admin
            .query_one(
                "SELECT snapshot FROM registry_internal.registry_proposal_submissions",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let before:i64=fixture.database.admin.query_one("SELECT count(*)::bigint FROM registry_internal.registry_migrations WHERE outcome='applied'",&[]).await.unwrap().get(0);
        let table = &fixture.registry.entities()["target"].physical_table;
        let before_records:Value=fixture.database.admin.query_one(&format!("SELECT jsonb_agg(to_jsonb(t) ORDER BY record_id) FROM registry_data.\"{table}\" t"),&[]).await.unwrap().get(0);
        source["actions"][0]["execution"]["proposal"]["review"]["policy"]["digest"] =
            json!(format!("sha256:{}", "c".repeat(64)));
        let candidate = proposal_activation::verified_successor(
            &fixture,
            &fixture.registry,
            &fixture.identity,
            &source,
        )
        .await;
        let inventory =
            registry_breg::proposal_retention::prepare_proposal_activation_compatibility(
                &fixture.pool,
                &fixture.identity,
                &candidate,
                &authority.registry,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(
            authority.counts().1,
            1,
            "genuine accepted closure was authenticated before the negative"
        );
        let other;
        let requested = if expired {
            // Validity is an engine-owned 30s bound. No editable/deserialized
            // proof or testing bypass controls its timestamp.
            tokio::time::sleep(Duration::from_secs(31)).await;
            &candidate
        } else {
            let mut unrelated = source.clone();
            unrelated["actions"][0]["display"] = json!({"label":"Different candidate package"});
            other = proposal_activation::verified_successor(
                &fixture,
                &fixture.registry,
                &fixture.identity,
                &unrelated,
            )
            .await;
            assert_ne!(candidate.package_digest(), other.package_digest());
            &other
        };
        let result = apply_verified_package(
            ApplyVerifiedPackageRequest::new(
                &fixture.database.migration_config,
                requested,
                ActivationDeployment::new(
                    "local",
                    "refused-compatibility-proof",
                    &fixture.identity.database_id,
                ),
                ApplyPrecondition::Successor {
                    current: &fixture.identity,
                },
                ApplyRoles::new(
                    &fixture.database.migration_role,
                    &fixture.database.runtime_role,
                ),
                ApplyTimeouts::new(Duration::from_secs(2), Duration::from_secs(10)).unwrap(),
                fixture.database.activation_audit(),
            )
            .with_proposal_activation_compatibility(&inventory),
        )
        .await;
        assert!(
            result.is_err(),
            "wrong or expired opaque proof cannot activate"
        );
        let state=fixture.database.admin.query_one("SELECT active_package_digest,active_activation_id::text,maintenance_status FROM registry_internal.registry_state WHERE singleton",&[]).await.unwrap();
        assert_eq!(state.get::<_, String>(0), fixture.identity.package_digest);
        assert_eq!(state.get::<_, String>(1), fixture.identity.activation_id);
        assert!(
            matches!(state.get::<_, String>(2).as_str(), "ready" | "failed"),
            "the attempted maintenance may record failure"
        );
        let after:i64=fixture.database.admin.query_one("SELECT count(*)::bigint FROM registry_internal.registry_migrations WHERE outcome='applied'",&[]).await.unwrap().get(0);
        assert_eq!(after, before, "no successful activation ledger entry");
        let row=fixture.database.admin.query_one("SELECT p.snapshot,s.blocked_reason,
            (SELECT count(*) FROM registry_internal.registry_proposal_activation_compatibility),
            (SELECT count(*) FROM registry_internal.registry_proposal_applications)
            FROM registry_internal.registry_proposal_submissions p JOIN registry_internal.registry_proposal_state s USING(action_id,proposal_id,submission_version)",&[]).await.unwrap();
        assert_eq!(row.get::<_, Value>(0), original);
        assert!(row.get::<_, Option<String>>(1).is_none());
        assert_eq!(row.get::<_, i64>(2), 0);
        assert_eq!(row.get::<_, i64>(3), 0);
        let after_records:Value=fixture.database.admin.query_one(&format!("SELECT jsonb_agg(to_jsonb(t) ORDER BY record_id) FROM registry_data.\"{table}\" t"),&[]).await.unwrap().get(0);
        assert_eq!(
            after_records, before_records,
            "refused activation preserves exact Record rows"
        );
        fixture.finish().await;
    }
}

#[test]
fn automatic_recovery_grants_refuse_known_service_and_agent_profiles() {
    compile(registry_source(true));
    for actor in ["service", "agent"] {
        let mut source = registry_source(true);
        source["accessProfiles"][0]["actorKind"] = json!(actor);
        source["accessProfiles"][0]["requesterClients"] = json!(["synthetic-recovery-client"]);
        // Reach the recovery ceiling rather than the independent standing
        // agent ceiling on native Record writes.
        source["accessProfiles"][0]["permissions"]["records"][0]["operations"] =
            json!(["get", "list"]);
        source["accessProfiles"][0]["permissions"]["records"][0]["writableFields"] = json!([]);
        let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
        let error = compile_project(&project, &[], CompileProfile::Authoring).unwrap_err();
        assert!(
            format!("{error:?}").contains("breg.proposal.automatic-recovery-requires-human"),
            "{error:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_application_status_exposes_bounded_block_and_human_recovery() {
    let mut source = registry_source(true);
    let mut service = source["accessProfiles"][0].clone();
    service["id"] = json!("status-service");
    service["default"] = json!(false);
    service["permissions"]["proposals"][0]["operations"] = json!(["get"]);
    service["permissions"]["proposals"][0]["writableAttachments"] = json!([]);
    service["permissions"]
        .as_object_mut()
        .unwrap()
        .remove("actions");
    source["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(service);
    let human_claims = VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        "author",
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
        registry_platform_oidc::ActorKind::Human,
    )
    .unwrap();
    let fixture = client_http::ClientFixture::start(compile(source), human_claims).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Human recovery", "status-start").await;
    assert!(draft.application_status().is_none());
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("status-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let frozen = (
        submitted.submission_version(),
        submitted.effect_digest().unwrap().to_string(),
    );
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs SET state='blocked',last_error_code='dependency-outage',attempt_count=1", &[]).await.unwrap();
    let blocked = client.read_proposal(&submitted).await.unwrap().value;
    let public = serde_json::to_value(&blocked).unwrap();
    assert_eq!(
        public["applicationStatus"],
        json!({"state":"blocked","mode":"automatic","reason":"dependency-outage","recovery":"retry","automaticRetry":{"scheduled":false,"attempts":1,"maximumAttempts":3}})
    );
    assert_eq!(blocked.submission_version(), frozen.0);
    assert_eq!(blocked.effect_digest(), Some(frozen.1.as_str()));
    assert!(blocked.application().is_none());
    let service_claims = VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        "author",
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
        registry_platform_oidc::ActorKind::Service,
    )
    .unwrap();
    let service = fixture.client_for(service_claims).await;
    let metadata = service
        .client
        .registry_contract(Some("status-service"))
        .await
        .unwrap();
    let get = metadata
        .value
        .select_proposal_get("status-service")
        .unwrap();
    let ordinary = service
        .client
        .get_proposal(&get, blocked.id())
        .await
        .unwrap()
        .value;
    assert_eq!(ordinary.application_status(), blocked.application_status());
    assert!(ordinary.link("apply").is_none());
    assert!(ordinary.link("retry").is_none());
    for operation in ["apply", "retry"] {
        let body = if operation == "apply" {
            json!({"submissionVersion":blocked.submission_version(),"effectDigest":blocked.effect_digest().unwrap()})
        } else {
            json!({})
        };
        let prepared = client
            .prepare_proposal(
                &blocked,
                operation,
                body,
                &key(&format!("service-denied-{operation}")),
            )
            .unwrap();
        // The second fixture has a distinct HTTP origin. Prepared SDK attempts
        // are intentionally origin-bound, so send the owner's exact promoted
        // HTTP contract to exercise the runtime's verified service refusal.
        let wire: Value = serde_json::from_slice(prepared.as_bytes()).unwrap();
        let refused = reqwest::Client::new()
            .post(format!(
                "{}{}?accessProfile=clerk",
                service.base_url,
                wire["link"]["path"].as_str().unwrap()
            ))
            .header("if-match", wire["link"]["ifMatch"].as_str().unwrap())
            .header("idempotency-key", wire["key"].as_str().unwrap())
            .json(&serde_json::from_str::<Value>(wire["body"].as_str().unwrap()).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(
            refused.status(),
            reqwest::StatusCode::NOT_FOUND,
            "a service cannot reuse the explicit human recovery grant"
        );
    }
    let retry = client
        .prepare_proposal(&blocked, "retry", json!({}), &key("human-status-retry"))
        .unwrap();
    let retried = client.execute_proposal(&retry).await.unwrap().value;
    assert_eq!(
        retried.application_status().unwrap().state,
        registry_breg_client::BRegProposalApplicationState::Pending
    );
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let applied = client.read_proposal(&retried).await.unwrap().value;
    assert_eq!(applied.state(), BRegProposalState::Applied);
    assert_eq!(
        applied.application_status().unwrap().state,
        registry_breg_client::BRegProposalApplicationState::Applied
    );
    assert_eq!(applied.application().unwrap().effect_digest, frozen.1);
    drop(service);
    fixture.finish().await;
}

#[path = "support/review_apply_412.rs"]
mod review_apply_412;

fn writable_inputs_source() -> Value {
    let mut source = registry_source(false);
    source["actions"][0]["inputs"].as_array_mut().unwrap().push(
        json!({"id":"note","type":"string","required":false,"maximumLength":64,
            "classification":"internal"}),
    );
    let clerk = &mut source["accessProfiles"][0]["permissions"]["proposals"][0];
    clerk["readableInputs"] = json!(["target", "value", "note"]);
    let mut officer = source["accessProfiles"][0].clone();
    officer["id"] = json!("officer");
    officer["default"] = json!(false);
    source["accessProfiles"][0]["permissions"]["proposals"][0]["writableInputs"] =
        json!(["target", "value"]);
    source["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(officer);
    source
}

fn nullable_writable_inputs_registry() -> registry_breg::CompiledRegistry {
    let mut source = writable_inputs_source();
    source["functions"] = json!([{
        "id":"nullable-note-plan", "runtime":"rhai", "source":"plans/nullable-note.rhai",
        "entrypoint":"plan", "abi":"registry.action-plan/v1"
    }]);
    source["actions"][0]["plan"] = json!({
        "type":"function", "function":"nullable-note-plan", "inputs":["target","value","note"],
        "writes":[{"id":"name","target":{"fromInput":"target"},"operation":"patch","fields":["name"]}]
    });
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/nullable-note.rhai".into(),
            bytes: br#"fn plan(ctx) {
                let name = ctx.inputs.value;
                if "note" in ctx.inputs {
                    name = if ctx.inputs.note == () { "null-branch-canary" } else { ctx.inputs.note };
                }
                #{effects:[#{id:"name",set:#{name:name}}]}
            }"#
            .to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .expect("nullable-input Proposal compiles")
}

/// One refused input write: a located `request.invalid` with no value echoed,
/// and exactly one audited refusal that names no value either.
async fn assert_input_write_refused(
    fixture: &client_http::ClientFixture,
    result: Result<
        registry_breg_client::BRegComplete<registry_breg_client::BRegProposal>,
        registry_breg_client::BaseRegistryClientError,
    >,
    before: usize,
    operation: &str,
) {
    let error = result.expect_err("a fixed input write is refused");
    assert_eq!(error.status(), Some(400), "{operation}");
    assert_eq!(
        error.problem_code(),
        Some(BRegProblemCode::RequestInvalid),
        "{operation}"
    );
    assert_eq!(
        error.field_path().map(|path| path.as_str()),
        Some("/input/note"),
        "{operation}"
    );
    let entries = fixture.audit_capture.entries();
    let refusals = entries[before..]
        .iter()
        .filter(|entry| entry["record"]["phase"] == "refusal")
        .collect::<Vec<_>>();
    assert_eq!(refusals.len(), 1, "{operation}: {:?}", &entries[before..]);
    assert_eq!(
        refusals[0]["record"]["operationId"],
        format!("proposals.correct-name.{operation}")
    );
    let audited = serde_json::to_string(&entries[before..]).unwrap();
    for canary in ["writable-input-canary", "officer-note-canary"] {
        assert!(
            !audited.contains(canary),
            "{operation}: audit disclosed {canary}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writable_inputs_treat_explicit_null_as_a_write() {
    let fixture = client_http::ClientFixture::start(
        nullable_writable_inputs_registry(),
        claims("author", "zone-a"),
    )
    .await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let target = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Before","jurisdiction":"zone-a"}))).unwrap(),
            &key("nullable-writable-record"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap()
        .value
        .data
        .record_identifier;
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let clerk_get = metadata.value.select_proposal_get("clerk").unwrap();

    let before = fixture.audit_capture.entries().len();
    let refused = client
        .start_proposal(
            &action,
            &BRegActionInvocationRequest::new(
                &action,
                map(json!({"target":target,"value":"Started","note":null})),
                None,
            )
            .unwrap(),
            &key("nullable-start-refused"),
        )
        .await;
    assert_input_write_refused(&fixture, refused, before, "start").await;

    let draft_receipt = client
        .start_proposal(
            &action,
            &BRegActionInvocationRequest::new(
                &action,
                map(json!({"target":target,"value":"Started"})),
                None,
            )
            .unwrap(),
            &key("nullable-start"),
        )
        .await
        .unwrap()
        .value;
    let draft = client
        .get_proposal(&clerk_get, draft_receipt.id())
        .await
        .unwrap()
        .value;
    let mut edited_input = draft.input().unwrap().clone();
    edited_input.insert("note".into(), Value::Null);
    let before = fixture.audit_capture.entries().len();
    let edit = client
        .prepare_proposal(
            &draft,
            "edit",
            json!({"input":edited_input}),
            &key("nullable-edit-refused"),
        )
        .unwrap();
    assert_input_write_refused(
        &fixture,
        client.execute_proposal(&edit).await,
        before,
        "edit",
    )
    .await;

    let officer_metadata = client
        .registry_contract(Some("officer"))
        .await
        .unwrap()
        .value;
    let officer_get = officer_metadata.select_proposal_get("officer").unwrap();
    let officer_view = client
        .get_proposal(&officer_get, draft.id())
        .await
        .unwrap()
        .value;
    let mut officer_input = officer_view.input().unwrap().clone();
    officer_input.insert("note".into(), Value::Null);
    let officer_edit = client
        .prepare_proposal(
            &officer_view,
            "edit",
            json!({"input":officer_input}),
            &key("nullable-officer-add-null"),
        )
        .unwrap();
    let with_null_receipt = client.execute_proposal(&officer_edit).await.unwrap().value;
    let with_null = client
        .get_proposal(&officer_get, with_null_receipt.id())
        .await
        .unwrap()
        .value;
    assert_eq!(with_null.input().unwrap().get("note"), Some(&Value::Null));

    let clerk_view = client
        .get_proposal(&clerk_get, draft.id())
        .await
        .unwrap()
        .value;
    let mut omitted_input = clerk_view.input().unwrap().clone();
    omitted_input.remove("note");
    let before = fixture.audit_capture.entries().len();
    let edit = client
        .prepare_proposal(
            &clerk_view,
            "edit",
            json!({"input":omitted_input}),
            &key("nullable-edit-omitted-refused"),
        )
        .unwrap();
    assert_input_write_refused(
        &fixture,
        client.execute_proposal(&edit).await,
        before,
        "edit",
    )
    .await;

    let officer_view = client
        .get_proposal(&officer_get, draft.id())
        .await
        .unwrap()
        .value;
    let mut officer_input = officer_view.input().unwrap().clone();
    officer_input.remove("note");
    let officer_edit = client
        .prepare_proposal(
            &officer_view,
            "edit",
            json!({"input":officer_input}),
            &key("nullable-officer-remove-null"),
        )
        .unwrap();
    client.execute_proposal(&officer_edit).await.unwrap();
    let draft = client
        .get_proposal(&clerk_get, draft.id())
        .await
        .unwrap()
        .value;
    assert!(!draft.input().unwrap().contains_key("note"));

    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("nullable-submit"))
        .unwrap();
    let submitted_receipt = client.execute_proposal(&submit).await.unwrap().value;
    let submitted = client
        .get_proposal(&clerk_get, submitted_receipt.id())
        .await
        .unwrap()
        .value;
    let mut revised_input = submitted.input().unwrap().clone();
    revised_input.insert("note".into(), Value::Null);
    let before = fixture.audit_capture.entries().len();
    let revise = client
        .prepare_proposal(
            &submitted,
            "revise",
            json!({"input":revised_input}),
            &key("nullable-revise-refused"),
        )
        .unwrap();
    assert_input_write_refused(
        &fixture,
        client.execute_proposal(&revise).await,
        before,
        "revise",
    )
    .await;

    let revise = client
        .prepare_proposal(
            &submitted,
            "revise",
            json!({"input":submitted.input().unwrap()}),
            &key("nullable-revise"),
        )
        .unwrap();
    let revised_receipt = client.execute_proposal(&revise).await.unwrap().value;
    let revised = client
        .get_proposal(&clerk_get, revised_receipt.id())
        .await
        .unwrap()
        .value;
    let mut rebased_input = revised.input().unwrap().clone();
    rebased_input.insert("note".into(), Value::Null);
    let before = fixture.audit_capture.entries().len();
    let rebase = client
        .prepare_proposal(
            &revised,
            "rebase",
            json!({"input":rebased_input}),
            &key("nullable-rebase-refused"),
        )
        .unwrap();
    assert_input_write_refused(
        &fixture,
        client.execute_proposal(&rebase).await,
        before,
        "rebase",
    )
    .await;
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writable_inputs_bound_start_edit_revise_and_rebase_to_the_named_inputs() {
    let fixture = client_http::ClientFixture::start(
        compile(writable_inputs_source()),
        claims("author", "zone-a"),
    )
    .await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let target = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Before","jurisdiction":"zone-a"}))).unwrap(),
            &key("writable-record"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap()
        .value
        .data
        .record_identifier;
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();

    // Start: a value for an input outside the grant is refused before any draft exists.
    let before = fixture.audit_capture.entries().len();
    let refused = client
        .start_proposal(
            &action,
            &BRegActionInvocationRequest::new(
                &action,
                map(json!({"target":target,"value":"Started","note":"writable-input-canary"})),
                None,
            )
            .unwrap(),
            &key("writable-start-refused"),
        )
        .await;
    assert_input_write_refused(&fixture, refused, before, "start").await;
    let page = client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap();
    assert!(
        page.value.items.is_empty(),
        "a refused Start leaves no draft"
    );
    let draft = client
        .start_proposal(
            &action,
            &BRegActionInvocationRequest::new(
                &action,
                map(json!({"target":target,"value":"Started"})),
                None,
            )
            .unwrap(),
            &key("writable-start"),
        )
        .await
        .unwrap()
        .value;

    // A grant without writableInputs keeps every input writable.
    let officer_metadata = client.registry_contract(Some("officer")).await.unwrap();
    let officer_collection = officer_metadata.value.select_proposals("officer").unwrap();
    let officer_page = client
        .list_proposals(&officer_collection, &BRegProposalQuery::default())
        .await
        .unwrap()
        .value;
    let officer_view = client
        .read_proposal(&officer_page.items[0])
        .await
        .unwrap()
        .value;
    let mut officer_input = officer_view.input().unwrap().clone();
    officer_input.insert("note".into(), json!("officer-note-canary"));
    let edit = client
        .prepare_proposal(
            &officer_view,
            "edit",
            json!({"input":officer_input}),
            &key("officer-edit"),
        )
        .unwrap();
    client.execute_proposal(&edit).await.unwrap();

    // Edit: changing or dropping a fixed input is refused and leaves the draft unchanged.
    let current = client.read_proposal(&draft).await.unwrap().value;
    assert_eq!(
        current.input().unwrap()["note"],
        json!("officer-note-canary")
    );
    let mut changed = current.input().unwrap().clone();
    changed.insert("note".into(), json!("writable-input-canary"));
    let mut dropped = current.input().unwrap().clone();
    dropped.remove("note");
    for (input, name) in [
        (changed, "writable-edit-changed"),
        (dropped, "writable-edit-dropped"),
    ] {
        let before = fixture.audit_capture.entries().len();
        let edit = client
            .prepare_proposal(&current, "edit", json!({"input":input}), &key(name))
            .unwrap();
        let result = client.execute_proposal(&edit).await;
        assert_input_write_refused(&fixture, result, before, "edit").await;
        let unchanged = client.read_proposal(&draft).await.unwrap().value;
        assert_eq!(
            serde_json::to_value(&unchanged).unwrap(),
            serde_json::to_value(&current).unwrap(),
            "{name}: a refused Edit leaves the draft unchanged"
        );
    }

    // Edit: restating the fixed input unchanged while changing a writable one is accepted.
    let mut same = current.input().unwrap().clone();
    same.insert("value".into(), json!("Edited"));
    let edit = client
        .prepare_proposal(
            &current,
            "edit",
            json!({"input":same}),
            &key("writable-edit"),
        )
        .unwrap();
    let edited = client.execute_proposal(&edit).await.unwrap().value;
    let edited = client.read_proposal(&edited).await.unwrap().value;
    assert_eq!(edited.input().unwrap()["value"], json!("Edited"));
    assert_eq!(
        edited.input().unwrap()["note"],
        json!("officer-note-canary")
    );

    // Revise from a submitted version compares with that version's input.
    let submit = client
        .prepare_proposal(&edited, "submit", json!({}), &key("writable-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let mut revised_input = edited.input().unwrap().clone();
    revised_input.insert("note".into(), json!("writable-input-canary"));
    let before = fixture.audit_capture.entries().len();
    let revise = client
        .prepare_proposal(
            &submitted,
            "revise",
            json!({"input":revised_input}),
            &key("writable-revise-refused"),
        )
        .unwrap();
    let result = client.execute_proposal(&revise).await;
    assert_input_write_refused(&fixture, result, before, "revise").await;
    let mut revised_input = edited.input().unwrap().clone();
    revised_input.insert("value".into(), json!("Revised"));
    let revise = client
        .prepare_proposal(
            &submitted,
            "revise",
            json!({"input":revised_input}),
            &key("writable-revise"),
        )
        .unwrap();
    let revised = client.execute_proposal(&revise).await.unwrap().value;
    let revised = client.read_proposal(&revised).await.unwrap().value;
    assert_eq!(revised.input().unwrap()["value"], json!("Revised"));

    // Rebase is an input write too.
    let mut rebased_input = revised.input().unwrap().clone();
    rebased_input.insert("note".into(), json!("writable-input-canary"));
    let before = fixture.audit_capture.entries().len();
    let rebase = client
        .prepare_proposal(
            &revised,
            "rebase",
            json!({"input":rebased_input}),
            &key("writable-rebase-refused"),
        )
        .unwrap();
    let result = client.execute_proposal(&rebase).await;
    assert_input_write_refused(&fixture, result, before, "rebase").await;
    let rebase = client
        .prepare_proposal(
            &revised,
            "rebase",
            json!({"input":revised.input().unwrap()}),
            &key("writable-rebase"),
        )
        .unwrap();
    client.execute_proposal(&rebase).await.unwrap();
    let entries = fixture.audit_capture.entries();
    assert!(entries
        .iter()
        .any(|entry| entry["record"]["changedInputs"] == json!(["value"])));
    assert!(entries
        .iter()
        .any(|entry| entry["record"]["changedInputs"] == json!(["note"])));
    let audit = serde_json::to_string(&entries).unwrap();
    for canary in [
        "officer-note-canary",
        "writable-input-canary",
        "Revised",
        "Edited",
    ] {
        assert!(!audit.contains(canary));
    }
    fixture.finish().await;
}

#[tokio::test]
async fn standing_officer_grant_revises_only_named_inputs_and_withdraws_exact_review() {
    let mut source = writable_inputs_source();
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":{"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))}});
    source["accessProfiles"][1]["requiredScopes"] = json!(["proposal:officer"]);
    let grant = &mut source["accessProfiles"][1]["permissions"]["proposals"][0];
    grant.as_object_mut().unwrap().remove("ownership");
    grant["writableInputs"] = json!(["value"]);
    let review = std::sync::Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let injected = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
        },
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Original terms", "officer-source").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("officer-first-submit"))
        .unwrap();
    let first = client.execute_proposal(&submit).await.unwrap().value;
    retain_queue_review(
        &fixture,
        &first,
        &review,
        registry_review_client::ReviewResultStatus::ChangesRequested,
        false,
        false,
    )
    .await;
    let officer_claims = VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        "officer",
        BTreeSet::from(["proposal:officer".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
        registry_platform_oidc::ActorKind::Human,
    )
    .unwrap();
    let officer = fixture.client_for(officer_claims).await;
    let metadata = officer
        .client
        .registry_contract(Some("officer"))
        .await
        .unwrap()
        .value;
    let binding = metadata.select_proposal_get("officer").unwrap();
    let current = officer
        .client
        .get_proposal(&binding, first.id())
        .await
        .unwrap()
        .value;
    let revise = officer
        .client
        .prepare_proposal(&current, "revise", json!({}), &key("standing-revise"))
        .unwrap();
    let revised = officer
        .client
        .execute_proposal(&revise)
        .await
        .unwrap()
        .value;
    assert_eq!(revised.submission_version(), 2);
    let history = officer
        .client
        .read_proposal_submission(&revised, 1)
        .await
        .unwrap()
        .value;
    let history = serde_json::to_value(history).unwrap();
    assert_eq!(history["current"], false);
    assert_eq!(
        history["decision"]["publicReason"],
        "Confirm the final terms."
    );
    let cancellation=fixture.database.admin.query_one("SELECT withdrawn,state FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1 AND submission_version=1",&[&uuid::Uuid::parse_str(first.id()).unwrap()]).await.unwrap();
    assert!(cancellation.get::<_, bool>(0));
    assert_eq!(cancellation.get::<_, String>(1), "cancelling");
    let revised = officer.client.read_proposal(&revised).await.unwrap().value;
    let mut values = revised.input().unwrap().clone();
    values.insert("note".into(), json!("must-not-leak-canary"));
    let refused = officer
        .client
        .prepare_proposal(
            &revised,
            "edit",
            json!({"input":values}),
            &key("standing-refused"),
        )
        .unwrap();
    let refusal = officer.client.execute_proposal(&refused).await.unwrap_err();
    assert_eq!(
        refusal.problem_code(),
        Some(BRegProblemCode::RequestInvalid)
    );
    assert_eq!(refusal.field_path().unwrap().as_str(), "/input/note");
    let mut values = revised.input().unwrap().clone();
    values.insert("value".into(), json!("Final terms canary"));
    let edit = officer
        .client
        .prepare_proposal(
            &revised,
            "edit",
            json!({"input":values}),
            &key("standing-edit"),
        )
        .unwrap();
    let edited = officer.client.execute_proposal(&edit).await.unwrap().value;
    let audit_before = fixture.audit_capture.entries().len();
    let replay = officer.client.execute_proposal(&edit).await.unwrap();
    assert_eq!(
        serde_json::to_value(&replay.value).unwrap(),
        serde_json::to_value(&edited).unwrap(),
        "replaying the edit retains the exact receipt"
    );
    let audit = fixture.audit_capture.entries();
    let terminal = audit[audit_before..]
        .iter()
        .find(|entry| {
            entry["record"]["phase"] == "terminal"
                && entry["record"]["operationId"] == "proposals.correct-name.edit"
        })
        .expect("the replayed edit records its terminal outcome");
    assert_eq!(terminal["record"]["outcome"], "replayed");
    assert!(
        terminal["record"].get("changedInputs").is_none(),
        "a replay reports no committed input changes"
    );
    let submit = officer
        .client
        .prepare_proposal(&edited, "submit", json!({}), &key("standing-submit"))
        .unwrap();
    let second = officer
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    assert_eq!(second.submission_version(), 2);
    assert_ne!(first.effect_digest(), second.effect_digest());
    let submissions=fixture.database.admin.query("SELECT snapshot->>'submittedBy' FROM registry_internal.registry_proposal_submissions WHERE proposal_id=$1 ORDER BY submission_version",&[&uuid::Uuid::parse_str(first.id()).unwrap()]).await.unwrap();
    assert_ne!(
        submissions[0].get::<_, String>(0),
        submissions[1].get::<_, String>(0)
    );
    let audit = fixture.audit_capture.entries();
    assert!(audit
        .iter()
        .any(|entry| entry["record"]["changedInputs"] == json!(["value"])));
    let audit = serde_json::to_string(&audit).unwrap();
    assert!(!audit.contains("Final terms canary"));
    assert!(!audit.contains("must-not-leak-canary"));
    drop(officer);
    fixture.finish().await;
}

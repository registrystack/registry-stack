// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::sync::Arc;

pub(super) fn require_review(source: &mut Value) {
    source["reviewAuthorities"] =
        json!({"local-review":{"protocol":"id.registrystack.org/protocols/review/v1"}});
    source["actions"]["correct-name"]["execution"]["proposal"]["review"] = json!({"type":"required",
        "authority":"local-review","source":"proposal-test",
        "policy":{"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))}});
}

pub(super) async fn pending_review_fixture(
    registry: registry_breg::CompiledRegistry,
) -> client_http::ClientFixture {
    let review = Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    client_http::ClientFixture::start_with_mutations(
        registry,
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), review)
        },
    )
    .await
}

async fn fixture(required: bool) -> (client_http::ClientFixture, Arc<LocalReview>) {
    let mut source = registry_source(false);
    let review = Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let fixture = if required {
        source["reviewAuthorities"] =
            json!({"local-review":{"protocol":"id.registrystack.org/protocols/review/v1"}});
        source["actions"]["correct-name"]["execution"]["proposal"]["review"] = json!({"type":"required",
            "authority":"local-review","source":"proposal-test",
            "policy":{"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))}});
        let injected = review.clone();
        client_http::ClientFixture::start_with_mutations(
            compile(source),
            claims("author", "zone-a"),
            move |mutations| {
                mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
            },
        )
        .await
    } else {
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await
    };
    (fixture, review)
}

async fn submit(
    fixture: &client_http::ClientFixture,
    prefix: &str,
) -> registry_breg_client::BRegProposal {
    let draft = start(fixture, "Status test", &format!("{prefix}-start")).await;
    fixture
        .http
        .client
        .execute_proposal(
            &fixture
                .http
                .client
                .prepare_proposal(
                    &draft,
                    "submit",
                    json!({}),
                    &key(&format!("{prefix}-submit")),
                )
                .unwrap(),
        )
        .await
        .unwrap()
        .value
}

async fn observations(
    fixture: &client_http::ClientFixture,
    command: &registry_breg_client::BRegProposal,
    status: &str,
    turn: &str,
) {
    let value = serde_json::to_value(command).unwrap();
    assert_eq!(value["status"], status, "command/read document");
    assert_eq!(value["turn"], turn);
    let current = fixture
        .http
        .client
        .read_proposal(command)
        .await
        .unwrap()
        .value;
    let value = serde_json::to_value(&current).unwrap();
    assert_eq!(value["status"], status, "Get");
    assert_eq!(value["turn"], turn);
    let metadata = fixture
        .http
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap()
        .value;
    let collection = metadata.select_proposals("clerk").unwrap();
    let page = fixture
        .http
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap()
        .value;
    let item = page
        .items
        .iter()
        .find(|item| item.id() == command.id())
        .unwrap();
    let item = serde_json::to_value(item).unwrap();
    assert_eq!(item["status"], status, "List");
    assert_eq!(item["turn"], turn);
}

pub(super) async fn raw_command(
    fixture: &client_http::ClientFixture,
    proposal: &registry_breg_client::BRegProposal,
    operation: &str,
) -> reqwest::Response {
    let value = serde_json::to_value(proposal).unwrap();
    reqwest::Client::new()
        .post(format!(
            "{}/v1/proposals/{}/{operation}?accessProfile=clerk",
            fixture.http.base_url,
            proposal.id()
        ))
        .header(
            "if-match",
            value["links"][operation]["ifMatch"].as_str().unwrap(),
        )
        .header("idempotency-key", format!("status-{operation}"))
        .json(&if operation == "rebase" {
            json!({"input": value["input"]})
        } else {
            json!({})
        })
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn proposal_status_is_served_on_draft_review_approval_and_application() {
    let (fixture, review) = fixture(true).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Status test", "status-draft-start").await;
    observations(&fixture, &draft, "draft", "party").await;
    let submitted = client
        .execute_proposal(
            &client
                .prepare_proposal(&draft, "submit", json!({}), &key("status-draft-submit"))
                .unwrap(),
        )
        .await
        .unwrap()
        .value;
    observations(&fixture, &submitted, "in-review", "official").await;
    retain_queue_review(
        &fixture,
        &submitted,
        &review,
        registry_review_client::ReviewResultStatus::Approved,
        false,
        true,
    )
    .await;
    let approved = client.read_proposal(&submitted).await.unwrap().value;
    observations(&fixture, &approved, "approved", "official").await;
    let value = serde_json::to_value(&approved).unwrap();
    for operation in ["revise", "rebase"] {
        let availability = &value["links"][operation]["availability"];
        assert_eq!(availability["available"], false);
        assert_eq!(availability["reason"], "application-pending");
        assert_eq!(availability["recovery"], "refresh");
    }
    let applied=client.execute_proposal(&client.prepare_proposal(&approved,"apply",
        json!({"submissionVersion":approved.submission_version(),"effectDigest":approved.effect_digest().unwrap()}),
        &key("status-apply")).unwrap()).await.unwrap().value;
    observations(&fixture, &applied, "applied", "nobody").await;
    for row in fixture.database.admin.query("SELECT payload FROM registry_internal.registry_outbox WHERE event_type LIKE 'proposal.%'",&[]).await.unwrap() {
        let bytes:Vec<u8>=row.get(0);
        let payload:Value=serde_json::from_slice(&bytes).unwrap();
        assert!(payload.get("status").is_none(),"lifecycle event vocabulary stays unchanged");
    }
    assert_eq!(
        reqwest::get(format!(
            "{}/v1/proposals?accessProfile=clerk&status=approved",
            fixture.http.base_url
        ))
        .await
        .unwrap()
        .status(),
        400,
        "status is not a collection filter"
    );
    fixture.finish().await;
}

async fn approval_refuses(operation: &str) {
    let (fixture, review) = fixture(true).await;
    let submitted = submit(&fixture, &format!("approved-{operation}")).await;
    retain_queue_review(
        &fixture,
        &submitted,
        &review,
        registry_review_client::ReviewResultStatus::Approved,
        false,
        true,
    )
    .await;
    let approved = fixture
        .http
        .client
        .read_proposal(&submitted)
        .await
        .unwrap()
        .value;
    let fresh = reqwest::get(format!(
        "{}/v1/proposals/{}?accessProfile=clerk",
        fixture.http.base_url,
        approved.id()
    ))
    .await
    .unwrap();
    let etag = fresh.headers()["etag"].to_str().unwrap().to_owned();
    let served: Value = fresh.json().await.unwrap();
    assert_eq!(served["links"][operation]["ifMatch"], etag);
    assert_eq!(
        served["links"][operation]["availability"],
        json!({
            "available":false,"observedRevision":approved.revision(),
            "reason":"application-pending","recovery":"refresh"
        })
    );
    assert!(served["input"]["target"].is_string());
    assert!(served["input"]["value"].is_string());
    let response = raw_command(&fixture, &approved, operation).await;
    let status = response.status();
    let problem: Value = response.json().await.unwrap();
    assert_eq!(problem["code"], "precondition.failed");
    assert_eq!(
        problem["type"],
        "https://id.registrystack.org/problems/registry-breg/precondition/failed"
    );
    assert_eq!(problem["detail"], "The mutation precondition failed.");
    let current = fixture
        .http
        .client
        .read_proposal(&approved)
        .await
        .unwrap()
        .value;
    let state = current.state();
    let version = current.submission_version();
    fixture.finish().await;
    assert_eq!(
        status, 412,
        "an approval cannot be discarded by {operation}"
    );
    assert_eq!(state, BRegProposalState::Submitted);
    assert_eq!(version, 1);
}

#[tokio::test]
async fn proposal_status_prevents_revise_from_discarding_an_approval() {
    approval_refuses("revise").await;
}

#[tokio::test]
async fn proposal_status_prevents_rebase_from_discarding_an_approval() {
    approval_refuses("rebase").await;
}

#[tokio::test]
async fn proposal_link_checks_do_not_lock_target_rows() {
    let mut source = registry_source(false);
    require_review(&mut source);
    source["actions"]["correct-name"]["execution"]["proposal"]["additions"] = json!({
        "id":"other","maximumBytes":32,"maximumCount":2,"contentTypes":["text/plain"],"classification":"restricted"
    });
    let grant = &mut source["accessProfiles"]["clerk"]["permissions"]["proposals"][0];
    grant["operations"]
        .as_array_mut()
        .unwrap()
        .push(json!("add"));
    grant["readableAttachments"] = json!(["support", "other"]);
    grant["writableAttachments"] = json!(["support", "other"]);
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    let draft = start(&fixture, "Lock probe", "status-read-lock").await;
    let value = serde_json::to_value(&draft).unwrap();
    let target = uuid::Uuid::parse_str(value["input"]["target"].as_str().unwrap()).unwrap();
    // Hold the target on an independent connection while serving every lifecycle link.
    fixture.database.admin.batch_execute("BEGIN").await.unwrap();
    fixture
        .database
        .admin
        .query_one(
            &format!(
                "SELECT record_id FROM registry_data.\"{}\" WHERE record_id=$1 FOR UPDATE",
                fixture.registry.entities()["target"].physical_table
            ),
            &[&target],
        )
        .await
        .unwrap();
    let response = reqwest::get(format!(
        "{}/v1/proposals/{}?accessProfile=clerk",
        fixture.http.base_url,
        draft.id()
    ))
    .await
    .unwrap();
    let status = response.status();
    let served: Value = response.json().await.unwrap();
    let command = reqwest::Client::new()
        .post(format!(
            "{}/v1/proposals/{}/edit?accessProfile=clerk",
            fixture.http.base_url,
            draft.id()
        ))
        .header(
            "if-match",
            value["links"]["edit"]["ifMatch"].as_str().unwrap(),
        )
        .header("idempotency-key", "status-lock-edit")
        .json(&json!({"input":value["input"]}))
        .send()
        .await
        .unwrap();
    let command_status = command.status();
    fixture
        .database
        .admin
        .batch_execute("ROLLBACK")
        .await
        .unwrap();
    fixture.finish().await;
    assert_eq!(
        status, 200,
        "link checks must read through another transaction's target lock"
    );
    assert!(served["attachments"]["support"]["links"]["upload"].is_object());
    assert!(served["additions"]["other"]["links"]["add"].is_object());
    assert_eq!(
        command_status, 503,
        "the command must still acquire the target lock"
    );
}

async fn concealed_target_is_not_a_recovery_block(deleted: bool) {
    let (fixture, _) = fixture(false).await;
    let proposal = submit(
        &fixture,
        if deleted {
            "deleted-target"
        } else {
            "hidden-target"
        },
    )
    .await;
    let value = serde_json::to_value(&proposal).unwrap();
    let target = uuid::Uuid::parse_str(value["input"]["target"].as_str().unwrap()).unwrap();
    let entity = &fixture.registry.entities()["target"];
    // This fixture exposes only name corrections, with no Delete or jurisdiction
    // mutation. Model an independent writer removing this caller's target access.
    let statement = if deleted {
        format!(
            "UPDATE registry_data.\"{}\" SET record_lifecycle='tombstoned' WHERE record_id=$1",
            entity.physical_table
        )
    } else {
        format!(
            "UPDATE registry_data.\"{}\" SET \"{}\"='zone-b' WHERE record_id=$1",
            entity.physical_table, entity.fields["jurisdiction"].physical_name
        )
    };
    fixture
        .database
        .admin
        .execute(&statement, &[&target])
        .await
        .unwrap();
    let refused = fixture.http.client.execute_proposal(&fixture.http.client.prepare_proposal(&proposal,"apply",
        json!({"submissionVersion":proposal.submission_version(),"effectDigest":proposal.effect_digest().unwrap()}),
        &key("concealed-target-apply")).unwrap()).await.unwrap_err();
    assert_eq!(
        refused.problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    let read = reqwest::get(format!(
        "{}/v1/proposals/{}?accessProfile=clerk",
        fixture.http.base_url,
        proposal.id()
    ))
    .await
    .unwrap();
    assert_eq!(read.status(), 404);
    let id = uuid::Uuid::parse_str(proposal.id()).unwrap();
    let row = fixture.database.admin.query_one(
        "SELECT blocked_reason,workflow_revision FROM registry_internal.registry_proposal_state WHERE proposal_id=$1",&[&id]).await.unwrap();
    assert_eq!(row.get::<_, Option<String>>(0), None);
    assert_eq!(row.get::<_, i64>(1), proposal.revision() as i64);
    fixture.finish().await;
}

#[tokio::test]
async fn a_deleted_target_stays_concealed_without_an_application_block() {
    concealed_target_is_not_a_recovery_block(true).await;
}

#[tokio::test]
async fn a_target_outside_the_current_boundary_stays_concealed_without_an_application_block() {
    concealed_target_is_not_a_recovery_block(false).await;
}

#[tokio::test]
async fn proposal_status_returns_changes_requested_to_the_party_for_revise() {
    let (fixture, review) = fixture(true).await;
    let submitted = submit(&fixture, "status-returned").await;
    retain_queue_review(
        &fixture,
        &submitted,
        &review,
        registry_review_client::ReviewResultStatus::ChangesRequested,
        false,
        true,
    )
    .await;
    let returned = fixture
        .http
        .client
        .read_proposal(&submitted)
        .await
        .unwrap()
        .value;
    observations(&fixture, &returned, "awaiting-party", "party").await;
    assert_eq!(
        serde_json::to_value(&returned).unwrap()["links"]["revise"]["availability"]["available"],
        true
    );
    let revised = fixture
        .http
        .client
        .execute_proposal(
            &fixture
                .http
                .client
                .prepare_proposal(
                    &returned,
                    "revise",
                    json!({}),
                    &key("status-returned-revise"),
                )
                .unwrap(),
        )
        .await
        .unwrap()
        .value;
    assert_eq!(revised.submission_version(), 2);
    observations(&fixture, &revised, "draft", "party").await;
    fixture.finish().await;
}

#[tokio::test]
async fn proposal_status_distinguishes_rejection_and_cancellation() {
    for terminal in ["rejected", "cancelled"] {
        let (fixture, review) = fixture(true).await;
        let submitted = submit(&fixture, &format!("status-{terminal}")).await;
        let closed = if terminal == "cancelled" {
            fixture
                .http
                .client
                .execute_proposal(
                    &fixture
                        .http
                        .client
                        .prepare_proposal(&submitted, "cancel", json!({}), &key("status-cancel"))
                        .unwrap(),
                )
                .await
                .unwrap()
                .value
        } else {
            let policy = json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
            inject_review_decision(&fixture, &review, policy, "rejected").await;
            fixture
                .http
                .client
                .read_proposal(&submitted)
                .await
                .unwrap()
                .value
        };
        observations(&fixture, &closed, terminal, "nobody").await;
        fixture.finish().await;
    }
}

#[tokio::test]
async fn proposal_status_processing_preserves_a_review_free_manual_submission() {
    let (fixture, _) = fixture(false).await;
    let submitted = submit(&fixture, "status-processing").await;
    let current = fixture
        .http
        .client
        .read_proposal(&submitted)
        .await
        .unwrap()
        .value;
    let response = raw_command(&fixture, &current, "revise").await;
    let status = response.status();
    if status != 412 {
        fixture.finish().await;
        assert_eq!(status, 412, "processing work cannot be revised");
        return;
    }
    assert_eq!(
        raw_command(&fixture, &current, "rebase").await.status(),
        412
    );
    observations(&fixture, &current, "processing", "official").await;
    fixture.finish().await;
}

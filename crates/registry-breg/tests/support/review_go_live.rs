// SPDX-License-Identifier: Apache-2.0
//! Real package activation closes superseded review and application work.
use super::*;
use registry_breg::{
    postgres::{
        ExpectedManagedCatalog, ExpectedRegistryIdentity, PostgresRecordMutationService,
        RegistryLockKey,
    },
    proposal_retention::ProposalRetentionOperatorService,
    review_recovery::{ReviewRecoveryError, ReviewRecoveryOperatorService, ReviewRecoveryScope},
};

async fn automatic_fixture(authority: &Authority) -> (client_http::ClientFixture, Value) {
    reviewed_fixture(authority, true).await
}

async fn reviewed_fixture(
    authority: &Authority,
    automatic: bool,
) -> (client_http::ClientFixture, Value) {
    reviewed_fixture_with_recovery(authority, automatic, false).await
}

async fn reviewed_fixture_with_recovery(
    authority: &Authority,
    automatic: bool,
    recovery_contract: bool,
) -> (client_http::ClientFixture, Value) {
    let mut source = registry_source(json!(policy()));
    source["actions"][0]["execution"]["proposal"]["application"] =
        json!({"mode":if automatic { "automatic" } else { "manual" }});
    source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"] =
        json!(["get", "list", "submit", "cancel", "rebase"]);
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableInputs"] =
        json!(["target", "value"]);
    if recovery_contract {
        source["actions"][0]["execution"]["proposal"]["reviewContext"] = json!({
            "id":"review-name",
            "fields":{"proposedName":{"type":"input","input":"value"}}
        });
        source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"] = json!([
            "get",
            "list",
            "edit",
            "submit",
            "revise",
            "cancel",
            "rebase",
            "retry",
            "get-review-status",
            "get-review-context"
        ]);
        source["accessProfiles"][0]["permissions"]["proposals"][0]["readableContextFields"] =
            json!(["proposedName"]);
    }
    if !automatic {
        source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"]
            .as_array_mut()
            .unwrap()
            .push(json!("apply"));
    }
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let registry = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    let bindings = authority.registry.clone();
    let fixture =
        client_http::ClientFixture::start_with_mutations(registry, claims(), move |service| {
            service.with_review_result_source(bindings)
        })
        .await;
    (fixture, source)
}

async fn activate(
    fixture: &client_http::ClientFixture,
    source: &Value,
    authority: &Authority,
) -> (
    registry_breg::package::VerifiedPackage,
    ExpectedRegistryIdentity,
) {
    let mut successor = source.clone();
    successor["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"extra","type":"boolean","required":false,"classification":"internal"}));
    proposal_activation::activate_with_compatibility(
        fixture,
        &fixture.registry,
        &fixture.identity,
        &successor,
        Some(&authority.registry),
    )
    .await
}

fn recovery(
    fixture: &client_http::ClientFixture,
    registry: &registry_breg::CompiledRegistry,
    identity: &ExpectedRegistryIdentity,
) -> ReviewRecoveryOperatorService {
    ReviewRecoveryOperatorService::over_retention_service_for_test(
        ProposalRetentionOperatorService::new_for_test(
            registry.clone(),
            identity.clone(),
            ExpectedManagedCatalog::compiled(registry),
            RegistryLockKey::derive(registry.registry_id()).unwrap(),
            fixture.database.migration_config.clone(),
            fixture.database.migration_role.clone(),
            fixture.database.runtime_role.clone(),
            fixture.database.activation_audit(),
        ),
    )
}

fn scope(id: Uuid) -> ReviewRecoveryScope<'static> {
    ReviewRecoveryScope {
        action_id: "correct-name",
        proposal_id: id,
        submission_version: 1,
    }
}

fn blocked_refusal(
    result: Result<registry_breg::review_recovery::ReviewRecovery, ReviewRecoveryError>,
) {
    let ReviewRecoveryError::Ineligible { reason, .. } =
        result.expect_err("blocked work cannot be retried")
    else {
        panic!("the package-change block must be named");
    };
    assert_eq!(reason.as_str(), "package-changed");
}

async fn send(fixture: &client_http::ClientFixture, authority: &Authority) {
    let client = fixture.pool.get_for_test().await.unwrap();
    assert!(run_one_submission(
        &**client,
        AUTHORITY,
        &authority.client,
        "producer",
        &BearerToken::new(OUTGOING_TOKEN).unwrap(),
        30
    )
    .await
    .unwrap());
}

async fn approve(
    fixture: &client_http::ClientFixture,
    authority: &Authority,
) -> ReviewRequestAccepted {
    send(fixture, authority).await;
    let accepted = authority.state.accepted.lock().unwrap().clone().unwrap();
    reconcile(fixture, &accepted).await;
    accepted
}

async fn reconcile(fixture: &client_http::ClientFixture, accepted: &ReviewRequestAccepted) {
    let mut client = fixture.pool.get_for_test().await.unwrap();
    let tx = client.transaction().await.unwrap();
    reconcile_result(
        &tx,
        AUTHORITY,
        accepted,
        &result(accepted, Uuid::new_v4(), ReviewResultStatus::Approved),
        &fixture.mutations,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn application_jobs(fixture: &client_http::ClientFixture, id: Uuid) -> Vec<String> {
    fixture.database.admin.query(
        "SELECT state FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1 ORDER BY submission_version",
        &[&id],
    ).await.unwrap().into_iter().map(|row| row.get(0)).collect()
}

async fn draft(fixture: &client_http::ClientFixture, key_name: &str) -> Uuid {
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create")
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(
                json!({"name":"Before","jurisdiction":"zone-a"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap(),
            &BRegIdempotencyKey::parse(format!("{key_name}-record")).unwrap(),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        json!({"target":record.value.data.record_identifier,"value":"After"})
            .as_object()
            .unwrap()
            .clone(),
        None,
    )
    .unwrap();
    let proposal = client
        .start_proposal(
            &action,
            &input,
            &BRegIdempotencyKey::parse(format!("{key_name}-start")).unwrap(),
        )
        .await
        .unwrap()
        .value;
    Uuid::parse_str(proposal.id()).unwrap()
}

#[tokio::test]
async fn go_live_blocked_proposals_name_rebase_and_hide_stale_review_context() {
    for automatic in [false, true] {
        assert_go_live_blocked_proposals(automatic).await;
    }
}

async fn assert_go_live_blocked_proposals(automatic: bool) {
    use registry_breg_client::BRegProposalState;

    let mode = if automatic { "automatic" } else { "manual" };
    let authority = Authority::start(false, true).await;
    let (fixture, source) = reviewed_fixture_with_recovery(&authority, automatic, true).await;
    let approved = submitted(&fixture, &format!("{mode}-approved")).await;
    approve(&fixture, &authority).await;
    let awaiting_review = submitted(&fixture, &format!("{mode}-awaiting-review")).await;
    let draft = draft(&fixture, &format!("{mode}-draft")).await;

    let (package, active) = activate(&fixture, &source, &authority).await;
    let (http, mutations) =
        active_package_client(&fixture, package.registry(), &active, &authority, claims()).await;
    let metadata = http.client.registry_contract(Some("clerk")).await.unwrap();
    let get = metadata.value.select_proposal_get("clerk").unwrap();
    let mut fresh_application = None;

    for (label, id, state, blocked_operations) in [
        (
            "draft",
            draft,
            BRegProposalState::Draft,
            &["edit", "submit"][..],
        ),
        (
            "awaiting-review",
            awaiting_review,
            BRegProposalState::Submitted,
            if automatic {
                &["revise"][..]
            } else {
                &["revise", "retry", "apply"][..]
            },
        ),
        (
            "approved",
            approved,
            BRegProposalState::Submitted,
            if automatic {
                &["revise"][..]
            } else {
                &["revise", "retry", "apply"][..]
            },
        ),
    ] {
        let proposal = http
            .client
            .get_proposal(&get, &id.to_string())
            .await
            .unwrap()
            .value;
        assert_eq!(proposal.state(), state, "{mode}/{label}");
        assert_eq!(
            proposal.blocked_reason(),
            Some("package-changed"),
            "{mode}/{label}"
        );
        for operation in blocked_operations {
            let availability = serde_json::to_value(
                proposal
                    .link(operation)
                    .unwrap_or_else(|| panic!("{mode}/{label}/{operation}"))
                    .availability()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                availability["available"], false,
                "{mode}/{label}/{operation}"
            );
            assert_eq!(
                availability["reason"], "package-changed",
                "{mode}/{label}/{operation}"
            );
            assert_eq!(
                availability["recovery"], "rebase",
                "{mode}/{label}/{operation}"
            );
        }
        for operation in ["rebase", "cancel"] {
            assert!(
                proposal
                    .link(operation)
                    .unwrap_or_else(|| panic!("{mode}/{label}/{operation}"))
                    .availability()
                    .unwrap()
                    .available,
                "{mode}/{label}/{operation}"
            );
        }

        if state == BRegProposalState::Submitted {
            if automatic {
                assert!(proposal.link("retry").is_none(), "{mode}/{label}");
                assert!(proposal.link("apply").is_none(), "{mode}/{label}");
            }
            let status = serde_json::to_value(proposal.application_status().unwrap()).unwrap();
            assert_eq!(status["state"], "blocked", "{mode}/{label}");
            assert_eq!(status["reason"], "package-changed", "{mode}/{label}");
            assert_eq!(status["recovery"], "rebase", "{mode}/{label}");
            assert!(proposal.link("reviewContext").is_none(), "{mode}/{label}");
            assert!(
                proposal
                    .link("reviewStatus")
                    .unwrap()
                    .availability()
                    .unwrap()
                    .available,
                "{mode}/{label}"
            );
            let review = http
                .client
                .read_proposal_review_status(&proposal)
                .await
                .unwrap()
                .value;
            assert!(!review.reviewable, "{mode}/{label}");
        } else {
            assert!(proposal.application_status().is_none(), "{mode}/{label}");
        }

        let rebase = http
            .client
            .prepare_proposal(
                &proposal,
                "rebase",
                json!({"input":proposal.input().unwrap()}),
                &BRegIdempotencyKey::parse(format!("{mode}-{label}-rebase")).unwrap(),
            )
            .unwrap();
        let rebased = http.client.execute_proposal(&rebase).await.unwrap().value;
        assert_eq!(rebased.state(), BRegProposalState::Draft, "{mode}/{label}");
        assert_eq!(rebased.blocked_reason(), None, "{mode}/{label}");
        assert!(
            rebased
                .link("submit")
                .unwrap()
                .availability()
                .unwrap()
                .available,
            "{mode}/{label}"
        );
        if id == approved {
            fresh_application = Some(rebased);
        }
    }

    let fresh_application = fresh_application.unwrap();
    let submit = http
        .client
        .prepare_proposal(
            &fresh_application,
            "submit",
            json!({}),
            &BRegIdempotencyKey::parse(format!("{mode}-fresh-submit")).unwrap(),
        )
        .unwrap();
    let submitted = http.client.execute_proposal(&submit).await.unwrap().value;
    assert_eq!(submitted.state(), BRegProposalState::Submitted);
    assert_eq!(submitted.blocked_reason(), None);
    let review = http
        .client
        .read_proposal_review_status(&submitted)
        .await
        .unwrap()
        .value;
    assert_eq!(
        review.result.as_ref().map(|result| result.state.as_str()),
        Some("pending"),
        "{mode}: verified compatibility permits a fresh review submission"
    );
    if automatic {
        assert!(submitted.link("apply").is_none(), "{mode}");
        assert_eq!(
            serde_json::to_value(submitted.application_status().unwrap()).unwrap()["state"],
            "awaiting-review",
            "{mode}: automatic application waits for fresh review"
        );
    } else {
        let apply = submitted.link("apply").unwrap().availability().unwrap();
        assert!(!apply.available, "{mode}");
        assert_eq!(
            serde_json::to_value(apply).unwrap(),
            json!({
                "available":false,
                "observedRevision":submitted.revision(),
                "reason":"pending-review",
                "recovery":"refresh"
            }),
            "{mode}: Apply waits for the fresh review"
        );
    }

    drop(mutations);
    drop(http);
    fixture.finish().await;
}

#[tokio::test]
async fn activation_cancels_unsent_review_before_worker_delivery() {
    let authority = Authority::start(false, true).await;
    let (fixture, source) = automatic_fixture(&authority).await;
    let id = submitted(&fixture, "activation-pending-canary").await;
    let _ = activate(&fixture, &source, &authority).await;
    let client = fixture.pool.get_for_test().await.unwrap();
    let ran = run_one_submission(
        &**client,
        AUTHORITY,
        &authority.client,
        "producer",
        &BearerToken::new(OUTGOING_TOKEN).unwrap(),
        30,
    )
    .await
    .unwrap();
    assert!(!ran, "activation-blocked work must never be submitted");
    assert!(authority.state.creates.lock().unwrap().is_empty());
    assert_eq!(job(&fixture, id).await["state"], "cancelled");
    assert!(application_jobs(&fixture, id).await.is_empty());
    drop(client);
    fixture.finish().await;
}

#[tokio::test]
async fn activation_closes_queued_application_jobs() {
    let authority = Authority::start(false, true).await;
    let (fixture, source) = automatic_fixture(&authority).await;
    let id = submitted(&fixture, "activation-queued-canary").await;
    approve(&fixture, &authority).await;
    assert_eq!(application_jobs(&fixture, id).await, ["queued"]);
    let _ = activate(&fixture, &source, &authority).await;
    assert_eq!(application_jobs(&fixture, id).await, ["cancelled"]);
    assert_eq!(job(&fixture, id).await["state"], "cancelling");
    fixture.finish().await;
}

#[tokio::test]
async fn activation_blocked_application_remains_counted_without_queue_age() {
    use tower::ServiceExt;
    let authority = Authority::start(false, true).await;
    let (fixture, source) = automatic_fixture(&authority).await;
    let id = submitted(&fixture, "activation-metrics-canary").await;
    approve(&fixture, &authority).await;
    let _ = activate(&fixture, &source, &authority).await;
    let response = registry_breg::metrics::metrics_app(Arc::new(
        registry_breg::metrics::Metrics::with_pool_for_test(fixture.pool.clone()),
    ))
    .oneshot(
        axum::http::Request::builder()
            .uri("/metrics")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    let body = axum::body::to_bytes(response.into_body(), 128 * 1024)
        .await
        .unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("breg_proposal_application_blocked_jobs 1\n"),
        "closed package-blocked jobs remain observable: {text}"
    );
    assert!(
        text.contains("breg_queue_oldest_pending_age_seconds{queue=\"review-application\"} 0\n")
    );
    assert!(!text.contains(&id.to_string()));
    fixture.finish().await;
}

#[tokio::test]
async fn activation_blocked_retry_names_package_change() {
    let authority = Authority::start(false, true).await;
    let (fixture, source) = automatic_fixture(&authority).await;
    let id = submitted(&fixture, "activation-recovery-canary").await;
    approve(&fixture, &authority).await;
    let (package, active) = activate(&fixture, &source, &authority).await;
    let operator = recovery(&fixture, package.registry(), &active);
    blocked_refusal(operator.retry_application(scope(id)).await);
    fixture.finish().await;
}

#[tokio::test]
async fn late_approval_after_activation_retains_evidence_without_application() {
    late_approval_after_activation(true, false).await;
}

#[tokio::test]
async fn manual_late_approval_after_activation_remains_readable_without_apply_authority() {
    late_approval_after_activation(false, false).await;
}

#[tokio::test]
async fn already_terminal_approval_after_activation_remains_readable_without_a_job() {
    late_approval_after_activation(true, true).await;
}

async fn late_approval_after_activation(automatic: bool, already_terminal: bool) {
    let authority = Authority::start(false, true).await;
    let (fixture, source) = reviewed_fixture(&authority, automatic).await;
    let id = submitted(&fixture, "activation-late-result-canary").await;
    send(&fixture, &authority).await;
    let accepted = authority.state.accepted.lock().unwrap().clone().unwrap();
    let (package, active) = activate(&fixture, &source, &authority).await;
    if already_terminal {
        authority
            .state
            .cancel_already_terminal
            .store(true, Ordering::SeqCst);
        let mut client = fixture.pool.get_for_test().await.unwrap();
        assert!(run_one_cancellation(
            &mut client,
            AUTHORITY,
            &authority.client,
            "producer",
            &BearerToken::new(OUTGOING_TOKEN).unwrap(),
            30,
            &fixture.mutations,
        )
        .await
        .unwrap());
    } else {
        reconcile(&fixture, &accepted).await;
    }
    assert!(
        application_jobs(&fixture, id).await.is_empty(),
        "late approval cannot enqueue a blocked submission"
    );
    assert_eq!(
        result_count(&fixture).await,
        1,
        "historical review evidence is retained"
    );
    assert_eq!(
        job(&fixture, id).await["state"],
        if already_terminal {
            "cancelled"
        } else {
            "cancelling"
        }
    );
    assert_withdrawn_proposal_readable(
        &fixture,
        package.registry(),
        &active,
        &authority,
        id,
        automatic,
        true,
    )
    .await;
    fixture.finish().await;
}

#[tokio::test]
async fn rollback_does_not_revive_cancelled_review_or_application() {
    let authority = Authority::start(false, true).await;
    let (fixture, source) = automatic_fixture(&authority).await;
    let id = submitted(&fixture, "activation-rollback-canary").await;
    approve(&fixture, &authority).await;
    // An Action-only change makes returning to the exact frozen revision a
    // metadata migration, without destructive database-shape rollback.
    let mut successor = source.clone();
    successor["actions"][0]["inputs"].as_array_mut().unwrap().push(
        json!({"id":"review-note","type":"string","maximumLength":32,"required":false,"classification":"internal"}),
    );
    let (package, active) = proposal_activation::activate_with_compatibility(
        &fixture,
        &fixture.registry,
        &fixture.identity,
        &successor,
        Some(&authority.registry),
    )
    .await;
    let (rollback, rolled_back) = proposal_activation::activate_with_compatibility(
        &fixture,
        package.registry(),
        &active,
        &source,
        Some(&authority.registry),
    )
    .await;
    assert_eq!(
        rollback.registry().actions().actions[0].definition_revision,
        fixture.registry.actions().actions[0].definition_revision
    );
    assert_eq!(application_jobs(&fixture, id).await, ["cancelled"]);
    assert!(matches!(
        job(&fixture, id).await["state"].as_str(),
        Some("cancelling" | "cancelled")
    ));
    let audit = registry_breg::audit::test_support::capturing(
        registry_platform_audit::AuditProfile::production_from_secret_bytes(vec![0x61; 32].into())
            .unwrap(),
    )
    .0;
    let mutations = PostgresRecordMutationService::new(
        fixture.pool.clone(),
        Arc::new(rollback.registry().clone()),
        rolled_back,
        "rollback-test",
        RegistryLockKey::derive(fixture.registry.registry_id()).unwrap(),
        Duration::from_secs(2),
        audit,
    )
    .with_review_result_source(authority.registry.clone());
    assert!(!mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    fixture.finish().await;
}

#[tokio::test]
async fn activation_delivers_existing_producer_cancellation() {
    let authority = Authority::start(false, true).await;
    let (fixture, source) = automatic_fixture(&authority).await;
    let id = submitted(&fixture, "activation-cancellation-canary").await;
    send(&fixture, &authority).await;
    let _ = activate(&fixture, &source, &authority).await;
    let mut client = fixture.pool.get_for_test().await.unwrap();
    assert!(
        run_one_cancellation(
            &mut client,
            AUTHORITY,
            &authority.client,
            "producer",
            &BearerToken::new(OUTGOING_TOKEN).unwrap(),
            30,
            &fixture.mutations
        )
        .await
        .unwrap(),
        "activation must schedule the producer cancellation"
    );
    assert_eq!(job(&fixture, id).await["state"], "cancelled");
    assert_eq!(result_count(&fixture).await, 1);
    assert!(application_jobs(&fixture, id).await.is_empty());
    drop(client);
    fixture.finish().await;
}

#[tokio::test]
async fn late_approval_after_rollback_cannot_reopen_a_withdrawn_round_without_a_job() {
    late_approval_after_rollback(false, true).await;
}

#[tokio::test]
async fn late_approval_after_rollback_cannot_replace_a_completed_cancellation() {
    late_approval_after_rollback(true, true).await;
}

#[tokio::test]
async fn manual_late_approval_after_rollback_keeps_the_requester_turn() {
    late_approval_after_rollback(false, false).await;
}

async fn late_approval_after_rollback(finish_cancellation: bool, automatic: bool) {
    let authority = Authority::start(false, true).await;
    let (fixture, source) = reviewed_fixture(&authority, automatic).await;
    let id = submitted(&fixture, "rollback-late-approval-canary").await;
    send(&fixture, &authority).await;
    let accepted = authority.state.accepted.lock().unwrap().clone().unwrap();
    assert!(application_jobs(&fixture, id).await.is_empty());
    let mut successor = source.clone();
    successor["actions"][0]["inputs"].as_array_mut().unwrap().push(
        json!({"id":"review-note","type":"string","maximumLength":32,"required":false,"classification":"internal"}),
    );
    let (package, active) = proposal_activation::activate_with_compatibility(
        &fixture,
        &fixture.registry,
        &fixture.identity,
        &successor,
        Some(&authority.registry),
    )
    .await;
    if finish_cancellation {
        let mut client = fixture.pool.get_for_test().await.unwrap();
        assert!(run_one_cancellation(
            &mut client,
            AUTHORITY,
            &authority.client,
            "producer",
            &BearerToken::new(OUTGOING_TOKEN).unwrap(),
            30,
            &fixture.mutations
        )
        .await
        .unwrap());
    }
    let (rollback, rolled_back) = proposal_activation::activate_with_compatibility(
        &fixture,
        package.registry(),
        &active,
        &source,
        Some(&authority.registry),
    )
    .await;
    let row = fixture.database.admin.query_one(
        "SELECT blocked_reason FROM registry_internal.registry_proposal_state WHERE proposal_id=$1", &[&id],
    ).await.unwrap();
    assert!(
        row.get::<_, Option<String>>(0).is_none(),
        "the restored Action clears the package block"
    );
    let mut client = fixture.pool.get_for_test().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let reconciled = reconcile_result(
        &tx,
        AUTHORITY,
        &accepted,
        &result(&accepted, Uuid::new_v4(), ReviewResultStatus::Approved),
        &fixture.mutations,
    )
    .await;
    if finish_cancellation {
        assert!(
            matches!(reconciled, Err(MutationError::PreconditionFailed)),
            "terminal cancellation is immutable"
        );
        tx.rollback().await.unwrap();
    } else {
        reconciled.unwrap();
        tx.commit().await.unwrap();
    }
    assert!(
        application_jobs(&fixture, id).await.is_empty(),
        "rollback must not revive a withdrawn review even without a prior job"
    );
    let refusal = recovery(&fixture, rollback.registry(), &rolled_back)
        .resubmit(scope(id))
        .await
        .unwrap_err();
    assert!(matches!(
        refusal,
        ReviewRecoveryError::Ineligible {
            reason: registry_breg::review_recovery::ReviewRecoveryRefusal::Withdrawn,
            ..
        }
    ));
    assert_eq!(
        result_count(&fixture).await,
        1,
        "the historical terminal evidence remains retained"
    );
    drop(client);
    assert_withdrawn_proposal_readable(
        &fixture,
        rollback.registry(),
        &rolled_back,
        &authority,
        id,
        automatic,
        false,
    )
    .await;
    fixture.finish().await;
}

async fn assert_withdrawn_proposal_readable(
    fixture: &client_http::ClientFixture,
    registry: &registry_breg::CompiledRegistry,
    identity: &ExpectedRegistryIdentity,
    authority: &Authority,
    id: Uuid,
    automatic: bool,
    blocked: bool,
) {
    use registry_breg_client::{BRegProposalQuery, BRegProposalState, BRegProposalTurn};
    let (http, mutations) =
        active_package_client(fixture, registry, identity, authority, claims()).await;
    let metadata = http.client.registry_contract(Some("clerk")).await.unwrap();
    let get = metadata.value.select_proposal_get("clerk").unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    // Execute both reads before asserting so a failed Get cannot hide a broken List.
    let observed = http.client.get_proposal(&get, &id.to_string()).await;
    let listed = http
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await;
    assert!(
        observed.is_ok() && listed.is_ok(),
        "withdrawn review must remain readable: Get={:?}, List={:?}",
        observed.as_ref().err(),
        listed.as_ref().err()
    );
    let observed = observed.unwrap().value;
    let listed = listed
        .unwrap()
        .value
        .items
        .into_iter()
        .find(|item| item.id() == id.to_string())
        .expect("the authorized List must retain the withdrawn Proposal");
    for proposal in [&observed, &listed] {
        assert_eq!(proposal.state(), BRegProposalState::Submitted);
        assert_eq!(
            proposal.blocked_reason(),
            blocked.then_some("package-changed")
        );
        assert_eq!(
            proposal.turn(),
            Some(BRegProposalTurn::Party),
            "withdrawal ends this review even if its retained result is approved"
        );
        for operation in ["rebase", "cancel"] {
            assert!(
                proposal
                    .link(operation)
                    .unwrap()
                    .availability()
                    .unwrap()
                    .available
            );
        }
        if automatic {
            let status = serde_json::to_value(proposal.application_status().unwrap()).unwrap();
            assert_eq!(status["state"], "blocked");
            assert_eq!(status["reason"], "package-changed");
            assert_eq!(status["recovery"], "rebase");
            assert_eq!(status["automaticRetry"]["scheduled"], false);
        } else {
            let apply =
                serde_json::to_value(proposal.link("apply").unwrap().availability().unwrap())
                    .unwrap();
            assert_eq!(
                apply["available"], false,
                "withdrawn approval grants no Apply authority"
            );
            if !blocked {
                assert_eq!(apply["reason"], "review-ended");
            }
        }
    }
    let party_page = http
        .client
        .list_proposals(
            &collection,
            &BRegProposalQuery {
                turn: Some(BRegProposalTurn::Party),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .value;
    assert!(party_page
        .items
        .iter()
        .any(|item| item.id() == id.to_string()));
    let retained = activation_work_snapshot(&fixture.database.admin).await;
    assert!(!mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    assert_eq!(
        activation_work_snapshot(&fixture.database.admin).await,
        retained
    );
    assert!(application_jobs(fixture, id).await.is_empty());
    for (subject, jurisdiction) in [
        ("other-author-canary", "zone-a"),
        ("author-canary", "zone-b"),
    ] {
        let caller = VerifiedRequestClaims::authenticated(
            "sub",
            subject,
            BTreeSet::from(["proposal:manage".into()]),
            Some("registry-administration".into()),
            BTreeMap::from([(
                "jurisdiction".into(),
                VerifiedClaimValue::direct_string(jurisdiction).unwrap(),
            )]),
        )
        .unwrap();
        let (other, _) =
            active_package_client(fixture, registry, identity, authority, caller).await;
        let metadata = other.client.registry_contract(Some("clerk")).await.unwrap();
        let get = metadata.value.select_proposal_get("clerk").unwrap();
        assert!(matches!(
            other.client.get_proposal(&get, &id.to_string()).await,
            Err(registry_breg_client::BaseRegistryClientError::Problem { status: 404, .. })
        ));
        let collection = metadata.value.select_proposals("clerk").unwrap();
        assert!(other
            .client
            .list_proposals(&collection, &BRegProposalQuery::default())
            .await
            .unwrap()
            .value
            .items
            .is_empty());
    }
    if automatic {
        assert!(observed.link("apply").is_none());
        let original: String = fixture.database.admin.query_one(
            "SELECT proposal_digest FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&id],
        ).await.unwrap().get(0);
        fixture.database.admin.execute(
            "UPDATE registry_internal.registry_proposal_review_submissions SET proposal_digest=$2 WHERE proposal_id=$1",
            &[&id, &format!("sha256:{}", "a".repeat(64))],
        ).await.unwrap();
        assert!(
            matches!(
                http.client.get_proposal(&get, &id.to_string()).await,
                Err(registry_breg_client::BaseRegistryClientError::Problem { status: 404, .. })
            ),
            "withdrawal cannot excuse a mismatched retained binding"
        );
        fixture.database.admin.execute(
            "UPDATE registry_internal.registry_proposal_review_submissions SET proposal_digest=$2,withdrawn=false WHERE proposal_id=$1",
            &[&id, &original],
        ).await.unwrap();
        // An approved current automatic round must have a job. Only actual withdrawal
        // explains the legitimate no-job case under test.
        let status: String = fixture.database.admin.query_one(
            "SELECT status FROM registry_internal.registry_proposal_review_results WHERE proposal_id=$1", &[&id],
        ).await.unwrap().get(0);
        if status == "approved" {
            assert!(matches!(
                http.client.get_proposal(&get, &id.to_string()).await,
                Err(registry_breg_client::BaseRegistryClientError::Problem { status: 404, .. })
            ));
        }
        fixture.database.admin.execute(
            "UPDATE registry_internal.registry_proposal_review_submissions SET withdrawn=true WHERE proposal_id=$1", &[&id],
        ).await.unwrap();
    } else {
        // Bypass the SDK's unavailable-link refusal to prove the actual runtime
        // still refuses an attempt to use the retained approval.
        let link = serde_json::to_value(observed.link("apply").unwrap()).unwrap();
        let refused = reqwest::Client::new()
            .post(format!(
                "{}{}?accessProfile=clerk",
                http.base_url,
                link["path"].as_str().unwrap()
            ))
            .header("if-match", link["ifMatch"].as_str().unwrap())
            .header("idempotency-key", "withdrawn-apply-canary")
            .json(&json!({"submissionVersion":1,"effectDigest":observed.effect_digest().unwrap()}))
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), reqwest::StatusCode::PRECONDITION_FAILED);
        assert_eq!(
            activation_work_snapshot(&fixture.database.admin).await,
            retained
        );
    }
    // Activation recovery rebases and submits for fresh Review; exact rollback
    // recovery cancels. Neither can reuse the retained approval or create an old job.
    if blocked {
        let rebase = http
            .client
            .prepare_proposal(
                &observed,
                "rebase",
                json!({"input":observed.input().unwrap()}),
                &BRegIdempotencyKey::parse("rebase-late-approval-canary").unwrap(),
            )
            .unwrap();
        let draft = http.client.execute_proposal(&rebase).await.unwrap().value;
        assert_eq!(draft.state(), BRegProposalState::Draft);
        let submit = http
            .client
            .prepare_proposal(
                &draft,
                "submit",
                json!({}),
                &BRegIdempotencyKey::parse("submit-late-approval-canary").unwrap(),
            )
            .unwrap();
        let fresh = http.client.execute_proposal(&submit).await.unwrap().value;
        assert_eq!(fresh.submission_version(), 2);
        assert_eq!(fresh.state(), BRegProposalState::Submitted);
        let rounds = fixture.database.admin.query(
            "SELECT submission_version,state,withdrawn,accepted_binding IS NULL
             FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1 ORDER BY submission_version", &[&id],
        ).await.unwrap();
        assert_eq!(rounds.len(), 2);
        assert!(rounds[0].get::<_, bool>(2));
        assert_eq!(rounds[1].get::<_, i64>(0), 2);
        assert_eq!(rounds[1].get::<_, String>(1), "pending");
        assert!(!rounds[1].get::<_, bool>(2));
        assert!(rounds[1].get::<_, bool>(3));
        assert!(application_jobs(fixture, id).await.is_empty());
        assert_eq!(result_count(fixture).await, 1);
        return;
    }
    let cancel = http
        .client
        .prepare_proposal(
            &observed,
            "cancel",
            json!({}),
            &BRegIdempotencyKey::parse("cancel-late-approval-canary").unwrap(),
        )
        .unwrap();
    let cancelled = http.client.execute_proposal(&cancel).await.unwrap().value;
    assert_eq!(cancelled.state(), BRegProposalState::Cancelled);
    assert!(application_jobs(fixture, id).await.is_empty());
    assert_eq!(
        result_count(fixture).await,
        1,
        "Cancel preserves the historical result"
    );
}

#[tokio::test]
async fn activation_blocked_resubmit_names_package_change_instead_of_resending() {
    let authority = Authority::start(false, true).await;
    let (fixture, source) = automatic_fixture(&authority).await;
    let id = submitted(&fixture, "activation-resubmit-canary").await;
    send(&fixture, &authority).await;
    fixture.database.admin.execute(
        "UPDATE registry_internal.registry_proposal_review_submissions SET last_error_code='result-unknown-to-authority' WHERE proposal_id=$1",
        &[&id],
    ).await.unwrap();
    let (package, active) = activate(&fixture, &source, &authority).await;
    blocked_refusal(
        recovery(&fixture, package.registry(), &active)
            .resubmit(scope(id))
            .await,
    );
    fixture.finish().await;
}

#[tokio::test]
async fn activation_fences_inflight_submission_and_recovers_only_to_cancel() {
    let authority = Authority::start(true, true).await;
    let (fixture, source) = automatic_fixture(&authority).await;
    let id = submitted(&fixture, "activation-inflight-canary").await;
    let submit = || {
        let pool = fixture.pool.clone();
        let review = authority.client.clone();
        tokio::spawn(async move {
            let client = pool.get_for_test().await.unwrap();
            run_one_submission(
                &**client,
                AUTHORITY,
                &review,
                "producer",
                &BearerToken::new(OUTGOING_TOKEN).unwrap(),
                30,
            )
            .await
        })
    };
    let first = submit();
    authority.state.gates[0].reached().await;
    let _ = activate(&fixture, &source, &authority).await;
    authority.state.gates[0].release.notify_one();
    let first = tokio::time::timeout(Duration::from_secs(5), first)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(first, Err(MutationError::PreconditionFailed)),
        "activation fences a late acceptance"
    );
    assert_eq!(job(&fixture, id).await["state"], "uncertain");
    let recovery = submit();
    authority.state.gates[1].reached().await;
    authority.state.gates[1].release.notify_one();
    assert!(tokio::time::timeout(Duration::from_secs(5), recovery)
        .await
        .unwrap()
        .unwrap()
        .unwrap());
    assert_eq!(job(&fixture, id).await["state"], "cancelling");
    {
        let creates = authority.state.creates.lock().unwrap();
        assert_eq!(creates.len(), 2);
        assert_eq!(
            creates[0], creates[1],
            "recovery keeps the exact request and idempotency key"
        );
    }
    let mut client = fixture.pool.get_for_test().await.unwrap();
    assert!(run_one_cancellation(
        &mut client,
        AUTHORITY,
        &authority.client,
        "producer",
        &BearerToken::new(OUTGOING_TOKEN).unwrap(),
        30,
        &fixture.mutations
    )
    .await
    .unwrap());
    assert_eq!(job(&fixture, id).await["state"], "cancelled");
    assert!(application_jobs(&fixture, id).await.is_empty());
    drop(client);
    fixture.finish().await;
}

#[tokio::test]
async fn rollback_cannot_resubmit_a_review_failed_before_activation() {
    failed_review_stays_withdrawn_after_rollback(true).await;
}

#[tokio::test]
async fn rollback_cannot_resubmit_an_unaccepted_failed_review() {
    failed_review_stays_withdrawn_after_rollback(false).await;
}

async fn failed_review_stays_withdrawn_after_rollback(accepted: bool) {
    let authority = Authority::start(false, true).await;
    let (fixture, source) = automatic_fixture(&authority).await;
    let id = submitted(&fixture, "rollback-failed-review-canary").await;
    if accepted {
        send(&fixture, &authority).await;
        let closed = recovery(&fixture, &fixture.registry, &fixture.identity)
            .close(scope(id))
            .await
            .unwrap();
        assert_eq!(closed.state, "failed");
        assert_eq!(closed.code, Some("operator-closed"));
    } else {
        fixture.database.admin.execute(
            "UPDATE registry_internal.registry_proposal_review_submissions SET state='failed',last_error_code='submission-recovery-expired' WHERE proposal_id=$1",
            &[&id],
        ).await.unwrap();
    }
    let mut successor = source.clone();
    successor["actions"][0]["inputs"].as_array_mut().unwrap().push(
        json!({"id":"review-note","type":"string","maximumLength":32,"required":false,"classification":"internal"}),
    );
    let (package, active) = proposal_activation::activate_with_compatibility(
        &fixture,
        &fixture.registry,
        &fixture.identity,
        &successor,
        Some(&authority.registry),
    )
    .await;
    let (rollback, rolled_back) = proposal_activation::activate_with_compatibility(
        &fixture,
        package.registry(),
        &active,
        &source,
        Some(&authority.registry),
    )
    .await;
    let row = fixture.database.admin.query_one(
        "SELECT blocked_reason FROM registry_internal.registry_proposal_state WHERE proposal_id=$1", &[&id],
    ).await.unwrap();
    assert!(row.get::<_, Option<String>>(0).is_none());
    let refusal = recovery(&fixture, rollback.registry(), &rolled_back)
        .resubmit(scope(id))
        .await
        .expect_err("activation permanently withdraws this round");
    assert!(matches!(
        refusal,
        ReviewRecoveryError::Ineligible {
            reason: registry_breg::review_recovery::ReviewRecoveryRefusal::Withdrawn,
            ..
        }
    ));
    assert_eq!(
        job(&fixture, id).await["state"],
        if accepted { "cancelling" } else { "failed" }
    );
    assert!(application_jobs(&fixture, id).await.is_empty());
    assert_eq!(
        authority.state.creates.lock().unwrap().len(),
        usize::from(accepted)
    );
    fixture.finish().await;
}

async fn cancelled_blocked_recovery_reports_withdrawal(retry_application: bool) {
    let authority = Authority::start(false, true).await;
    let (fixture, _) = automatic_fixture(&authority).await;
    let id = submitted(&fixture, "cancel-blocked-recovery-canary").await;
    approve(&fixture, &authority).await;
    let http = &fixture.http;
    let metadata = http.client.registry_contract(Some("clerk")).await.unwrap();
    let get = metadata.value.select_proposal_get("clerk").unwrap();
    let proposal = http
        .client
        .get_proposal(&get, &id.to_string())
        .await
        .unwrap()
        .value;
    let cancel = http
        .client
        .prepare_proposal(
            &proposal,
            "cancel",
            json!({}),
            &BRegIdempotencyKey::parse("cancel-blocked-canary").unwrap(),
        )
        .unwrap();
    // Isolate the terminal recovery diagnosis: native activation tests above
    // prove how this block is installed. Cancel itself goes through the real API.
    fixture.database.admin.execute(
        "UPDATE registry_internal.registry_proposal_state SET blocked_reason='package-changed' WHERE proposal_id=$1", &[&id],
    ).await.unwrap();
    let cancelled = http.client.execute_proposal(&cancel).await.unwrap().value;
    assert_eq!(
        cancelled.state(),
        registry_breg_client::BRegProposalState::Cancelled
    );
    let row = fixture.database.admin.query_one(
        "SELECT state,blocked_reason FROM registry_internal.registry_proposal_state WHERE proposal_id=$1", &[&id],
    ).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "cancelled");
    assert_eq!(
        row.get::<_, Option<String>>(1).as_deref(),
        Some("package-changed")
    );
    let operator = recovery(&fixture, &fixture.registry, &fixture.identity);
    let outcome = if retry_application {
        operator.retry_application(scope(id)).await
    } else {
        operator.resubmit(scope(id)).await
    };
    let ReviewRecoveryError::Ineligible { reason, .. } = outcome.unwrap_err() else {
        panic!("cancelled work must remain ineligible");
    };
    assert_eq!(
        reason.as_str(),
        "withdrawn",
        "terminal work must not be told to Rebase or Cancel again"
    );
    assert_eq!(application_jobs(&fixture, id).await, ["cancelled"]);
    fixture.finish().await;
}

#[tokio::test]
async fn cancelled_blocked_resubmit_reports_withdrawal() {
    cancelled_blocked_recovery_reports_withdrawal(false).await;
}

#[tokio::test]
async fn cancelled_blocked_application_retry_reports_withdrawal() {
    cancelled_blocked_recovery_reports_withdrawal(true).await;
}

async fn active_package_client(
    fixture: &client_http::ClientFixture,
    registry: &registry_breg::CompiledRegistry,
    identity: &ExpectedRegistryIdentity,
    authority: &Authority,
    caller: VerifiedRequestClaims,
) -> (client_http::ClientHttp, Arc<PostgresRecordMutationService>) {
    use registry_breg::api::{HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture};
    struct Ready;
    impl ReadinessProbe for Ready {
        fn is_ready(&self) -> ServiceFuture<'_, bool> {
            Box::pin(async { true })
        }
    }
    let registry = Arc::new(registry.clone());
    let lock = RegistryLockKey::derive(registry.registry_id()).unwrap();
    let audit = registry_breg::audit::test_support::capturing(
        registry_platform_audit::AuditProfile::production_from_secret_bytes(vec![0x61; 32].into())
            .unwrap(),
    )
    .0;
    let cursors = Arc::new(
        registry_breg::cursor::CursorCodec::new(
            Zeroizing::new(vec![0x62; 32]),
            Duration::from_secs(300),
        )
        .unwrap(),
    );
    let records = registry_breg::postgres::PostgresRecordReadService::new(
        fixture.pool.clone(),
        registry.clone(),
        identity.clone(),
        lock,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    );
    let mutations = Arc::new(
        PostgresRecordMutationService::new(
            fixture.pool.clone(),
            registry.clone(),
            identity.clone(),
            "client-capability-test",
            lock,
            Duration::from_secs(2),
            audit,
        )
        .with_review_result_source(authority.registry.clone()),
    );
    let service = HttpService::new(
        registry,
        ReadRuntimeIdentity {
            package_revision: identity.activation_id.clone(),
            schema_fingerprint: identity.schema_fingerprint.clone(),
        },
        Arc::new(records),
        Arc::new(Ready),
        cursors,
    )
    .with_postgres_mutations(mutations.clone());
    let http =
        client_http::ClientHttp::start(registry_breg::api::router(Arc::new(service)), caller).await;
    (http, mutations)
}

async fn activated_automatic_proposal_preserves_requester_recovery(rollback: bool, rebase: bool) {
    let authority = Authority::start(false, true).await;
    let (fixture, source) = automatic_fixture(&authority).await;
    let id = submitted(&fixture, "closed-application-projection-canary").await;
    approve(&fixture, &authority).await;
    let mut successor = source.clone();
    successor["actions"][0]["inputs"].as_array_mut().unwrap().push(
        json!({"id":"review-note","type":"string","maximumLength":32,"required":false,"classification":"internal"}),
    );
    let (mut package, mut active) = proposal_activation::activate_with_compatibility(
        &fixture,
        &fixture.registry,
        &fixture.identity,
        &successor,
        Some(&authority.registry),
    )
    .await;
    if rollback {
        (package, active) = proposal_activation::activate_with_compatibility(
            &fixture,
            package.registry(),
            &active,
            &source,
            Some(&authority.registry),
        )
        .await;
        assert_eq!(
            package.registry().actions().actions[0].definition_revision,
            fixture.registry.actions().actions[0].definition_revision
        );
    }
    let (http, mutations) =
        active_package_client(&fixture, package.registry(), &active, &authority, claims()).await;
    let metadata = http.client.registry_contract(Some("clerk")).await.unwrap();
    let get = metadata.value.select_proposal_get("clerk").unwrap();
    let proposal = http
        .client
        .get_proposal(&get, &id.to_string())
        .await
        .expect("authorized Get must preserve requester recovery after activation closes the job")
        .value;
    assert_eq!(
        proposal.state(),
        registry_breg_client::BRegProposalState::Submitted
    );
    assert_eq!(
        proposal.blocked_reason(),
        (!rollback).then_some("package-changed")
    );
    let status = serde_json::to_value(proposal.application_status().unwrap()).unwrap();
    assert_eq!(status["state"], "blocked");
    assert_eq!(status["reason"], "package-changed");
    assert_eq!(status["recovery"], "rebase");
    assert_eq!(status["automaticRetry"]["scheduled"], false);
    assert!(
        proposal
            .link("rebase")
            .unwrap()
            .availability()
            .unwrap()
            .available
    );
    assert!(
        proposal
            .link("cancel")
            .unwrap()
            .availability()
            .unwrap()
            .available
    );
    let retained = activation_work_snapshot(&fixture.database.admin).await;
    assert!(!mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    assert_eq!(
        activation_work_snapshot(&fixture.database.admin).await,
        retained,
        "observing or running the executor cannot revive closed work after activation or rollback"
    );
    assert_eq!(application_jobs(&fixture, id).await, ["cancelled"]);
    assert_eq!(retained["reviews"][0]["withdrawn"], true);
    assert!(retained["jobs"][0]["claim_token"].is_null());

    // A readable closure still requires the exact retained application binding.
    for (column, bad) in [
        ("proposal_digest", format!("sha256:{}", "a".repeat(64))),
        (
            "system_grant_revision",
            format!("sha256:{}", "b".repeat(64)),
        ),
        ("executor", "other-executor-canary".to_owned()),
    ] {
        let original: String = fixture.database.admin.query_one(
            "SELECT to_jsonb(j)->>$2 FROM registry_internal.registry_proposal_application_jobs j WHERE proposal_id=$1",
            &[&id, &column],
        ).await.unwrap().get(0);
        fixture.database.admin.execute(
            &format!("UPDATE registry_internal.registry_proposal_application_jobs SET {column}=$2 WHERE proposal_id=$1"),
            &[&id, &bad],
        ).await.unwrap();
        assert!(
            matches!(
                http.client.get_proposal(&get, &id.to_string()).await,
                Err(registry_breg_client::BaseRegistryClientError::Problem { status: 404, .. })
            ),
            "{column}"
        );
        fixture.database.admin.execute(
            &format!("UPDATE registry_internal.registry_proposal_application_jobs SET {column}=$2 WHERE proposal_id=$1"),
            &[&id, &original],
        ).await.unwrap();
    }
    // A different terminal job state is still inconsistent with a submitted Proposal.
    fixture.database.admin.execute(
        "UPDATE registry_internal.registry_proposal_application_jobs SET state='applied',application_id=$2 WHERE proposal_id=$1",
        &[&id, &Uuid::new_v4()],
    ).await.unwrap();
    assert!(matches!(
        http.client.get_proposal(&get, &id.to_string()).await,
        Err(registry_breg_client::BaseRegistryClientError::Problem { status: 404, .. })
    ));
    fixture.database.admin.execute(
        "UPDATE registry_internal.registry_proposal_application_jobs SET state='cancelled',application_id=NULL WHERE proposal_id=$1", &[&id],
    ).await.unwrap();
    for (subject, jurisdiction) in [
        ("other-author-canary", "zone-a"),
        ("author-canary", "zone-b"),
    ] {
        let caller = VerifiedRequestClaims::authenticated(
            "sub",
            subject,
            BTreeSet::from(["proposal:manage".into()]),
            Some("registry-administration".into()),
            BTreeMap::from([(
                "jurisdiction".into(),
                VerifiedClaimValue::direct_string(jurisdiction).unwrap(),
            )]),
        )
        .unwrap();
        let (other, _) =
            active_package_client(&fixture, package.registry(), &active, &authority, caller).await;
        let metadata = other.client.registry_contract(Some("clerk")).await.unwrap();
        let get = metadata.value.select_proposal_get("clerk").unwrap();
        assert!(matches!(
            other.client.get_proposal(&get, &id.to_string()).await,
            Err(registry_breg_client::BaseRegistryClientError::Problem { status: 404, .. })
        ));
    }
    let proposal = http
        .client
        .get_proposal(&get, &id.to_string())
        .await
        .unwrap()
        .value;
    if rebase {
        let prepared = http
            .client
            .prepare_proposal(
                &proposal,
                "rebase",
                json!({"input":proposal.input().unwrap()}),
                &BRegIdempotencyKey::parse("rebase-closed-application-canary").unwrap(),
            )
            .unwrap();
        let draft = http.client.execute_proposal(&prepared).await.unwrap().value;
        assert_eq!(
            draft.state(),
            registry_breg_client::BRegProposalState::Draft
        );
        let submit = http
            .client
            .prepare_proposal(
                &draft,
                "submit",
                json!({}),
                &BRegIdempotencyKey::parse("submit-rebased-application-canary").unwrap(),
            )
            .unwrap();
        let current = http.client.execute_proposal(&submit).await.unwrap().value;
        assert_eq!(current.submission_version(), 2);
        let rounds = fixture
            .database
            .admin
            .query(
                "SELECT submission_version,state,withdrawn,accepted_binding IS NULL
             FROM registry_internal.registry_proposal_review_submissions
             WHERE proposal_id=$1 ORDER BY submission_version",
                &[&id],
            )
            .await
            .unwrap();
        assert_eq!(rounds.len(), 2);
        assert!(rounds[0].get::<_, bool>(2), "the old round stays withdrawn");
        assert_eq!(rounds[1].get::<_, i64>(0), 2);
        assert_eq!(rounds[1].get::<_, String>(1), "pending");
        assert!(!rounds[1].get::<_, bool>(2));
        assert!(
            rounds[1].get::<_, bool>(3),
            "fresh Review cannot inherit old acceptance"
        );
        assert_eq!(application_jobs(&fixture, id).await, ["cancelled"]);
        assert!(!mutations
            .run_automatic_proposal_once_for_test()
            .await
            .unwrap());
        drop(mutations);
        drop(http);
        fixture.finish().await;
        return;
    }
    let cancel = http
        .client
        .prepare_proposal(
            &proposal,
            "cancel",
            json!({}),
            &BRegIdempotencyKey::parse("cancel-closed-application-canary").unwrap(),
        )
        .unwrap();
    let cancelled = http.client.execute_proposal(&cancel).await.unwrap().value;
    assert_eq!(
        cancelled.state(),
        registry_breg_client::BRegProposalState::Cancelled
    );
    let operator = recovery(&fixture, package.registry(), &active);
    for outcome in [
        operator.resubmit(scope(id)).await,
        operator.retry_application(scope(id)).await,
    ] {
        let ReviewRecoveryError::Ineligible { reason, .. } = outcome.unwrap_err() else {
            panic!("cancelled work must remain ineligible");
        };
        assert_eq!(reason.as_str(), "withdrawn");
    }
    assert_eq!(application_jobs(&fixture, id).await, ["cancelled"]);
    drop(mutations);
    drop(http);
    fixture.finish().await;
}

#[tokio::test]
async fn activation_closed_application_remains_readable_and_cancellable() {
    activated_automatic_proposal_preserves_requester_recovery(false, false).await;
}

#[tokio::test]
async fn rollback_closed_application_remains_readable_without_reviving_work() {
    activated_automatic_proposal_preserves_requester_recovery(true, false).await;
}

#[tokio::test]
async fn activation_closed_application_rebases_to_fresh_review_without_reviving_old_job() {
    activated_automatic_proposal_preserves_requester_recovery(false, true).await;
}

async fn activation_work_snapshot(client: &impl tokio_postgres::GenericClient) -> Value {
    client.query_one(
        "SELECT jsonb_build_object(
            'proposals',(SELECT jsonb_agg(to_jsonb(p) ORDER BY proposal_id) FROM registry_internal.registry_proposal_state p),
            'reviews',(SELECT jsonb_agg(to_jsonb(s) ORDER BY proposal_id,submission_version) FROM registry_internal.registry_proposal_review_submissions s),
            'jobs',(SELECT jsonb_agg(to_jsonb(j) ORDER BY proposal_id,submission_version) FROM registry_internal.registry_proposal_application_jobs j))",
        &[],
    ).await.unwrap().get(0)
}

async fn activation_statement_counts(extra_pending: usize) -> Vec<(String, i64)> {
    let authority = Authority::start(false, true).await;
    let (fixture, source) = automatic_fixture(&authority).await;
    // Bound and unbound rounds exercise the same cases as ordinary withdrawal.
    // The counters are fixture-only; the native activation tests above separately
    // exercise the closed-catalog gate that intentionally refuses these triggers.
    let mut cases = vec![
        ("pending", false, false, 0, "cancelled", 0),
        ("submitting", false, false, 2, "uncertain", 2),
        ("uncertain", false, false, 3, "uncertain", 3),
        ("accepted", true, false, 4, "cancelling", 0),
        ("cancelling", true, true, 5, "cancelling", 5),
        ("failed", true, false, 6, "cancelling", 0),
        ("failed", false, false, 6, "failed", 6),
        ("failed", true, true, 7, "failed", 7),
        ("cancelled", true, true, 8, "cancelled", 8),
    ];
    cases.extend((0..extra_pending).map(|_| ("pending", false, false, 0, "cancelled", 0)));
    let mut ids = Vec::new();
    for (index, (state, bound, withdrawn, attempts, _, _)) in cases.iter().enumerate() {
        let id = submitted(&fixture, &format!("batch-round-{index}-canary")).await;
        if *bound {
            let accepted = retained_binding(&fixture, id).await;
            accept(&fixture, id, &accepted).await;
            reconcile(&fixture, &accepted).await;
            let job_state = ["queued", "applying", "blocked"][index % 3];
            fixture.database.admin.execute(
                "UPDATE registry_internal.registry_proposal_application_jobs SET state=$2,claim_token=$3 WHERE proposal_id=$1",
                &[&id, &job_state, &Uuid::new_v4()],
            ).await.unwrap();
        }
        fixture.database.admin.execute(
            "UPDATE registry_internal.registry_proposal_review_submissions
                SET state=$2,withdrawn=$3,attempt_count=$4,lease_until=transaction_timestamp()+interval '1 hour'
              WHERE proposal_id=$1",
            &[&id, state, withdrawn, attempts],
        ).await.unwrap();
        ids.push(id);
    }
    let terminal = submitted(&fixture, "batch-terminal-canary").await;
    let metadata = fixture
        .http
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let get = metadata.value.select_proposal_get("clerk").unwrap();
    let proposal = fixture
        .http
        .client
        .get_proposal(&get, &terminal.to_string())
        .await
        .unwrap()
        .value;
    let cancel = fixture
        .http
        .client
        .prepare_proposal(
            &proposal,
            "cancel",
            json!({}),
            &BRegIdempotencyKey::parse("batch-terminal-cancel-canary").unwrap(),
        )
        .unwrap();
    fixture.http.client.execute_proposal(&cancel).await.unwrap();

    // A fresh second submission leaves an older round and job behind. Only the
    // current round may be withdrawn, but every unfinished application must close.
    let versioned = submitted(&fixture, "batch-versioned-canary").await;
    let accepted = retained_binding(&fixture, versioned).await;
    accept(&fixture, versioned, &accepted).await;
    reconcile(&fixture, &accepted).await;
    let proposal = fixture
        .http
        .client
        .get_proposal(&get, &versioned.to_string())
        .await
        .unwrap()
        .value;
    let rebase = fixture
        .http
        .client
        .prepare_proposal(
            &proposal,
            "rebase",
            json!({"input":proposal.input().unwrap()}),
            &BRegIdempotencyKey::parse("batch-rebase-canary").unwrap(),
        )
        .unwrap();
    let draft = fixture
        .http
        .client
        .execute_proposal(&rebase)
        .await
        .unwrap()
        .value;
    let submit = fixture
        .http
        .client
        .prepare_proposal(
            &draft,
            "submit",
            json!({}),
            &BRegIdempotencyKey::parse("batch-resubmit-canary").unwrap(),
        )
        .unwrap();
    let current = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    assert_eq!(current.submission_version(), 2);
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_review_submissions
            SET state='failed',attempt_count=7,last_error_code='cancellation-recovery-expired'
          WHERE proposal_id=$1 AND submission_version=1",
            &[&versioned],
        )
        .await
        .unwrap();
    fixture.database.admin.execute(
        "UPDATE registry_internal.registry_proposal_application_jobs SET state='applying',claim_token=$2
          WHERE proposal_id=$1 AND submission_version=1", &[&versioned, &Uuid::new_v4()],
    ).await.unwrap();

    let before = activation_work_snapshot(&fixture.database.admin).await;
    let mut successor = source.clone();
    successor["actions"][0]["inputs"].as_array_mut().unwrap().push(
        json!({"id":"review-note","type":"string","maximumLength":32,"required":false,"classification":"internal"}),
    );
    let project = parse_project_json(&serde_json::to_vec(&successor).unwrap()).unwrap();
    let candidate = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    let (mut admin, task) = fixture.database.connect_admin().await;
    let tx = admin.transaction().await.unwrap();
    tx.batch_execute(
        "CREATE TEMP TABLE activation_statements (table_name text NOT NULL);
         CREATE FUNCTION public.count_activation_statement() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN INSERT INTO pg_temp.activation_statements VALUES (TG_TABLE_NAME); RETURN NULL; END $$;
         CREATE TRIGGER count_activation_statement AFTER UPDATE ON registry_internal.registry_proposal_state
             FOR EACH STATEMENT EXECUTE FUNCTION public.count_activation_statement();
         CREATE TRIGGER count_activation_statement AFTER UPDATE ON registry_internal.registry_proposal_review_submissions
             FOR EACH STATEMENT EXECUTE FUNCTION public.count_activation_statement();
         CREATE TRIGGER count_activation_statement AFTER UPDATE ON registry_internal.registry_proposal_application_jobs
             FOR EACH STATEMENT EXECUTE FUNCTION public.count_activation_statement();",
    ).await.unwrap();
    registry_breg::proposal_retention::mark_incompatible_proposals_for_test(
        &tx,
        &candidate,
        &format!("sha256:{}", "c".repeat(64)),
        &Uuid::new_v4().to_string(),
    )
    .await
    .unwrap();
    for (id, (prior_state, bound, prior_withdrawn, _, next_state, next_attempts)) in
        ids.iter().zip(&cases)
    {
        let row = tx.query_one(
            "SELECT state,withdrawn,attempt_count,lease_until IS NULL FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[id],
        ).await.unwrap();
        assert_eq!(row.get::<_, String>(0), *next_state);
        assert!(row.get::<_, bool>(1));
        assert_eq!(row.get::<_, i32>(2), *next_attempts);
        let unchanged =
            *prior_state == "cancelled" || (*prior_state == "failed" && *prior_withdrawn);
        assert_eq!(row.get::<_, bool>(3), !unchanged);
        if *bound {
            let row = tx.query_one(
                "SELECT state,claim_token IS NULL FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1", &[id],
            ).await.unwrap();
            assert_eq!(row.get::<_, String>(0), "cancelled");
            assert!(row.get::<_, bool>(1));
        }
    }
    let after = activation_work_snapshot(&tx).await;
    for key in ["proposals", "reviews", "jobs"] {
        let retained: Vec<_> = before[key]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| {
                row["proposal_id"] == json!(terminal)
                    || (key == "reviews"
                        && row["proposal_id"] == json!(versioned)
                        && row["submission_version"] == 1)
            })
            .collect();
        for row in retained {
            assert!(
                after[key].as_array().unwrap().contains(row),
                "unaffected {key} row changed"
            );
        }
    }
    let current = tx.query_one(
        "SELECT state,withdrawn FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1 AND submission_version=2", &[&versioned],
    ).await.unwrap();
    assert_eq!(current.get::<_, String>(0), "cancelled");
    assert!(current.get::<_, bool>(1));
    assert_eq!(tx.query_one(
        "SELECT state FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1 AND submission_version=1", &[&versioned],
    ).await.unwrap().get::<_, String>(0), "cancelled");
    let counts = tx.query(
        "SELECT table_name,count(*) FROM activation_statements GROUP BY table_name ORDER BY table_name", &[],
    ).await.unwrap().into_iter().map(|row| (row.get(0), row.get(1))).collect();
    tx.rollback().await.unwrap();
    assert_eq!(
        activation_work_snapshot(&fixture.database.admin).await,
        before,
        "all lifecycle and application changes roll back together"
    );
    drop(admin);
    task.abort();
    fixture.finish().await;
    counts
}

#[tokio::test]
async fn activation_withdrawal_statement_count_does_not_grow_with_submitted_work() {
    let small = activation_statement_counts(1).await;
    let larger = activation_statement_counts(8).await;
    assert!(
        !small.is_empty(),
        "the regression must observe actual work updates"
    );
    assert_eq!(
        small, larger,
        "per-Action statement count must not grow with submitted work"
    );
}

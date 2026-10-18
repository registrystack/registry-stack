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
    let mut source = registry_source(json!(policy()));
    source["actions"][0]["execution"]["proposal"]["application"] = json!({"mode":"automatic"});
    source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"] =
        json!(["get", "list", "submit", "cancel", "rebase"]);
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
    let authority = Authority::start(false, true).await;
    let (fixture, source) = automatic_fixture(&authority).await;
    let id = submitted(&fixture, "activation-late-result-canary").await;
    send(&fixture, &authority).await;
    let accepted = authority.state.accepted.lock().unwrap().clone().unwrap();
    let _ = activate(&fixture, &source, &authority).await;
    reconcile(&fixture, &accepted).await;
    assert!(
        application_jobs(&fixture, id).await.is_empty(),
        "late approval cannot enqueue a blocked submission"
    );
    assert_eq!(
        result_count(&fixture).await,
        1,
        "historical review evidence is retained"
    );
    assert_eq!(job(&fixture, id).await["state"], "cancelling");
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
    late_approval_after_rollback(false).await;
}

#[tokio::test]
async fn late_approval_after_rollback_cannot_replace_a_completed_cancellation() {
    late_approval_after_rollback(true).await;
}

async fn late_approval_after_rollback(finish_cancellation: bool) {
    let authority = Authority::start(false, true).await;
    let (fixture, source) = automatic_fixture(&authority).await;
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
    fixture.finish().await;
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

// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::middleware::Next;
use postgres_harness::TestDatabase;
use registry_platform_audit::AuditProfile;
use registry_relay_client::{
    RegistryRecordSingleResponse, RegistryServerClient, RegistryServerClientConfig,
    RegistryServerIdempotencyKey, RegistryServerLifecycleAction,
    RegistryServerLifecycleActionReceipt, RegistryServerLifecycleAuthority,
    RegistryServerLifecycleOperation, RegistryServerProblemCode, RegistryServerRequestMetadata,
    RegistryServerRequestState, ServerRecordOptions, StaticToken,
};
use registry_server::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::cursor::CursorCodec;
use registry_server::mutation::MutationFaultPoint;
use registry_server::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, PostgresRevisionReadService,
    RegistryLockKey, RegistryStateTestIdentity,
};
use registry_server::startup::with_request_timeout_for_test;
use serde_json::{json, Value};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "change-request-http-registry";
const INSTANCE_ID: &str = "change-request-http-instance";
const DATABASE_ID: &str = "change-request-http-database";
const PACKAGE_REVISION: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TENANT: &str = "tenant-a";
const SUBMITTER: &str = "submitter-principal";
const REVIEWER: &str = "reviewer-principal";
const APPLIER: &str = "applier-principal";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_change_request_correction_uses_frozen_review_and_apply_path() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(compiled_registry());
    let (migration, migration_task) = database.connect_migration().await;
    database
        .admin
        .batch_execute("CREATE EXTENSION IF NOT EXISTS btree_gist")
        .await
        .expect("administrator installs temporal exclusion prerequisite");
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("change-request schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("active change-request identity initializes");
    drop(migration);
    migration_task.abort();

    let app = change_request_router(&database, registry.clone(), identity, PACKAGE_ID, None);
    let steward = claims("steward", "steward-principal", None);
    let submitter = claims("submitter", SUBMITTER, None);
    let reviewer = claims("reviewer", REVIEWER, Some("review"));
    let applier = claims("applier", APPLIER, Some("apply"));
    assert_served_action_openapi_refs(&app, reviewer.clone(), applier.clone()).await;

    let old_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "create-old-site",
        json!({"tenant": TENANT, "name": "warehouse-old"}),
    )
    .await;
    let new_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "create-new-site",
        json!({"tenant": TENANT, "name": "warehouse-new"}),
    )
    .await;
    let placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=steward",
        steward.clone(),
        "create-placement",
        json!({
            "tenant": TENANT,
            "site": old_site.id,
            "validFrom": "2026-08-31",
            "validTo": Value::Null
        }),
    )
    .await;

    let direct_patch = send(
        &app,
        Method::PATCH,
        &format!(
            "/v1/records/placements/{}?accessProfile=steward",
            placement.id
        ),
        Some(steward.clone()),
        &[
            ("content-type", "application/json-patch+json"),
            ("idempotency-key", "direct-controlled-patch"),
            ("if-match", &placement.etag),
        ],
        format!(
            r#"[{{"op":"replace","path":"/data/site","value":"{}"}}]"#,
            new_site.id
        )
        .into_bytes(),
    )
    .await;
    assert_eq!(
        direct_patch.status(),
        StatusCode::NOT_FOUND,
        "the controlled target PATCH route is not a usable bypass"
    );
    assert_eq!(body_json(direct_patch).await["code"], "resource.not_found");

    let request = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=submitter",
        submitter.clone(),
        "create-correction-request",
        json!({
            "tenant": TENANT,
            "placement": placement.id,
            "proposedSite": new_site.id,
            "reason": "correct the recorded site"
        }),
    )
    .await;

    let before_submit = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=submitter",
            request.id
        ),
        submitter.clone(),
    )
    .await;
    assert_eq!(before_submit.body["request"]["serverState"], "draft");
    assert_eq!(before_submit.body["request"]["proposalVersion"], 1);
    assert_eq!(before_submit.body["request"]["effectDigest"], Value::Null);
    let submit_action = action(&before_submit.body, "submit_request", None);

    let submitted = action_response(
        &app,
        &submit_action.href,
        "submit-correction-request",
        &submit_action.if_match,
        submitter.clone(),
        json!({}),
    )
    .await;
    assert_eq!(submitted["request"]["serverState"], "submitted");
    assert_eq!(submitted["request"]["proposalVersion"], 1);
    let effect_digest = submitted["request"]["effectDigest"]
        .as_str()
        .expect("submission freezes an effect digest")
        .to_owned();
    assert!(effect_digest.starts_with("sha256:"));
    assert_eq!(submitted["request"]["application"], Value::Null);

    let before_review = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=reviewer",
            request.id
        ),
        reviewer.clone(),
    )
    .await;
    assert_eq!(before_review.body["request"]["serverState"], "submitted");
    assert_eq!(before_review.body["request"]["effectDigest"], effect_digest);
    let approve_action = action(&before_review.body, "approve_request", Some("review"));
    assert_eq!(approve_action.proposal_version, Some(1));
    assert_eq!(
        approve_action.effect_digest.as_deref(),
        Some(effect_digest.as_str())
    );
    let targets = approve_action.review["targets"]
        .as_array()
        .expect("review action exposes target snapshots");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0]["entityId"], "asset-placement");
    assert_eq!(targets[0]["recordId"], placement.id);
    assert_eq!(targets[0]["operation"], "patch");
    assert_eq!(targets[0]["baseRevision"], 1);
    assert_eq!(targets[0]["before"], json!({"site": old_site.id}));
    assert_eq!(targets[0]["after"], json!({"site": new_site.id}));

    let approved = action_response(
        &app,
        &approve_action.href,
        "approve-correction-request",
        &approve_action.if_match,
        reviewer.clone(),
        json!({"proposalVersion": 1, "effectDigest": effect_digest}),
    )
    .await;
    assert_eq!(approved["request"]["serverState"], "approved");
    assert_eq!(approved["request"]["application"], Value::Null);

    let before_apply = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=applier",
            request.id
        ),
        applier.clone(),
    )
    .await;
    assert_eq!(before_apply.body["request"]["serverState"], "approved");
    let apply_action = action(&before_apply.body, "apply_request", None);
    assert_eq!(apply_action.proposal_version, Some(1));

    let applied = action_response(
        &app,
        &apply_action.href,
        "apply-correction-request",
        &apply_action.if_match,
        applier.clone(),
        json!({
            "proposalVersion": apply_action.proposal_version,
            "effectDigest": apply_action.effect_digest
        }),
    )
    .await;
    assert_eq!(applied["request"]["serverState"], "applied");
    assert_ne!(applied["request"]["application"], Value::Null);

    let changed_placement = get_record(
        &app,
        &format!(
            "/v1/records/placements/{}?accessProfile=steward",
            placement.id
        ),
        steward.clone(),
    )
    .await;
    assert_eq!(changed_placement.body["revision"], 2);
    assert_eq!(changed_placement.body["data"]["tenant"], TENANT);
    assert_eq!(changed_placement.body["data"]["site"], new_site.id);

    let placement_revisions = revision_items(
        &app,
        &format!(
            "/v1/records/placements/{}/revisions?accessProfile=steward",
            placement.id
        ),
        steward.clone(),
    )
    .await;
    assert_eq!(placement_revisions[0]["revision"], 2);
    assert_eq!(placement_revisions[0]["mutationKind"], "patch");
    assert_eq!(
        placement_revisions[0]["operationId"],
        "records.asset-placement.patch"
    );
    assert!(!placement_revisions[0]["operationId"]
        .as_str()
        .expect("operation id")
        .contains("correction-request"));

    let request_revisions = revision_items(
        &app,
        &format!(
            "/v1/records/correction-requests/{}/revisions?accessProfile=submitter",
            request.id
        ),
        submitter.clone(),
    )
    .await;
    assert_revision_operations_include(
        &request_revisions,
        &[
            "records.correction-request.request.apply",
            "records.correction-request.request.stages.review.approve",
            "records.correction-request.request.submit",
            "records.correction-request.create",
        ],
    );

    let after_apply = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=applier",
            request.id
        ),
        applier,
    )
    .await;
    assert_eq!(after_apply.body["request"]["serverState"], "applied");
    assert_eq!(
        after_apply.body["request"]["application"]["proposalVersion"],
        1
    );
    assert_eq!(
        after_apply.body["request"]["application"]["effectDigest"],
        applied["request"]["effectDigest"]
    );

    assert_eq!(application_result_count(&database).await, 1);
    assert_eq!(
        target_revision(&database, "asset-placement", &placement.id).await,
        2
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registry_server_client_drives_every_real_postgres_change_request_lifecycle_operation() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(compiled_registry());
    let identity = install_registry(
        &database,
        &registry,
        "registry-server-client-lifecycle",
        true,
    )
    .await;
    let app = change_request_router(
        &database,
        registry,
        identity,
        "registry-server-client-lifecycle",
        None,
    );

    // Direct mutations only prepare the records that the lifecycle journey
    // consumes. Every change-request transition below crosses the real HTTP
    // boundary through RegistryServerClient.
    let steward = claims("steward", "client-lifecycle-steward", None);
    let submitter = claims("submitter", SUBMITTER, None);
    let old_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "client-lifecycle-create-old-site",
        json!({"tenant": TENANT, "name": "client-lifecycle-old"}),
    )
    .await;
    let new_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "client-lifecycle-create-new-site",
        json!({"tenant": TENANT, "name": "client-lifecycle-new"}),
    )
    .await;
    let placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=steward",
        steward,
        "client-lifecycle-create-placement",
        json!({
            "tenant": TENANT,
            "site": old_site.id,
            "validFrom": "2026-09-01",
            "validTo": Value::Null
        }),
    )
    .await;
    let applied_request = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=submitter",
        submitter.clone(),
        "client-lifecycle-create-applied-request",
        json!({
            "tenant": TENANT,
            "placement": placement.id,
            "proposedSite": new_site.id,
            "reason": "exercise revision, approval, and application"
        }),
    )
    .await;
    let rejected_request = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=submitter",
        submitter.clone(),
        "client-lifecycle-create-rejected-request",
        json!({
            "tenant": TENANT,
            "placement": placement.id,
            "proposedSite": old_site.id,
            "reason": "exercise rejection"
        }),
    )
    .await;
    let canceled_request = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=submitter",
        submitter,
        "client-lifecycle-create-canceled-request",
        json!({
            "tenant": TENANT,
            "placement": placement.id,
            "proposedSite": new_site.id,
            "reason": "exercise cancellation"
        }),
    )
    .await;

    let server = serve_change_request_client_http(app).await;
    let submitter_client = change_request_client(server.base_url(), "submitter-token");
    let reviewer_client = change_request_client(server.base_url(), "reviewer-token");
    let applier_client = change_request_client(server.base_url(), "applier-token");
    let steward_client = change_request_client(server.base_url(), "steward-token");

    // Runtime metadata is caller-filtered and remains the sole authority that
    // can promote the actor-specific links carried by a request record.
    let submitter_authority = lifecycle_authority(&submitter_client, "submitter").await;
    let reviewer_authority = lifecycle_authority(&reviewer_client, "reviewer").await;
    let applier_authority = lifecycle_authority(&applier_client, "applier").await;
    let mut exercised = BTreeSet::new();

    let before_submit =
        client_request_record(&submitter_client, &applied_request.id, "submitter").await;
    assert_eq!(
        request_metadata(&before_submit).server_state(),
        RegistryServerRequestState::Draft
    );
    let submit_action = promoted_client_action(
        &submitter_client,
        &submitter_authority,
        &before_submit,
        RegistryServerLifecycleOperation::SubmitRequest,
    );
    let submit_key = idempotency_key("client-lifecycle-submit-v1");
    let submitted = submitter_client
        .execute_lifecycle_action(&submit_action, &submit_key)
        .await
        .expect("the metadata- and record-bound submit action succeeds");
    exercised.insert(RegistryServerLifecycleOperation::SubmitRequest);
    let after_submit =
        client_request_record(&submitter_client, &applied_request.id, "submitter").await;
    assert_client_receipt_matches_refetch(&submitted.value, &after_submit);
    assert_eq!(
        request_metadata(&after_submit).server_state(),
        RegistryServerRequestState::Submitted
    );

    let replayed_submit = submitter_client
        .execute_lifecycle_action(&submit_action, &submit_key)
        .await
        .expect("a caller retry reuses the exact action and idempotency key");
    assert_eq!(replayed_submit.value, submitted.value);
    let stale_submit = submitter_client
        .execute_lifecycle_action(
            &submit_action,
            &idempotency_key("client-lifecycle-stale-submit"),
        )
        .await
        .expect_err("a stale action cannot be rebound under a different caller key");
    assert_eq!(
        stale_submit.problem_code(),
        Some(RegistryServerProblemCode::PreconditionFailed)
    );

    let before_revision =
        client_request_record(&reviewer_client, &applied_request.id, "reviewer").await;
    let request_revision_action = promoted_client_action(
        &reviewer_client,
        &reviewer_authority,
        &before_revision,
        RegistryServerLifecycleOperation::RequestRevision,
    );
    let review = request_revision_action
        .review()
        .expect("a review decision carries frozen target snapshots");
    assert_eq!(review.targets().len(), 1);
    assert_eq!(review.targets()[0].entity_identifier(), "asset-placement");
    assert_eq!(review.targets()[0].record_identifier(), placement.id);
    let needs_changes = execute_client_action_and_refetch(
        &reviewer_client,
        &request_revision_action,
        "client-lifecycle-request-revision",
        &applied_request.id,
        "reviewer",
    )
    .await;
    exercised.insert(RegistryServerLifecycleOperation::RequestRevision);
    assert_eq!(
        request_metadata(&needs_changes).server_state(),
        RegistryServerRequestState::NeedsChanges
    );

    let before_revise =
        client_request_record(&submitter_client, &applied_request.id, "submitter").await;
    let revise_action = promoted_client_action(
        &submitter_client,
        &submitter_authority,
        &before_revise,
        RegistryServerLifecycleOperation::ReviseRequest,
    );
    let revised = execute_client_action_and_refetch(
        &submitter_client,
        &revise_action,
        "client-lifecycle-revise",
        &applied_request.id,
        "submitter",
    )
    .await;
    exercised.insert(RegistryServerLifecycleOperation::ReviseRequest);
    assert_eq!(
        request_metadata(&revised).server_state(),
        RegistryServerRequestState::Draft
    );
    assert_eq!(request_metadata(&revised).proposal_version().get(), 2);

    let resubmit_action = promoted_client_action(
        &submitter_client,
        &submitter_authority,
        &revised,
        RegistryServerLifecycleOperation::SubmitRequest,
    );
    let resubmitted = execute_client_action_and_refetch(
        &submitter_client,
        &resubmit_action,
        "client-lifecycle-submit-v2",
        &applied_request.id,
        "submitter",
    )
    .await;
    assert_eq!(
        request_metadata(&resubmitted).server_state(),
        RegistryServerRequestState::Submitted
    );

    let before_approve =
        client_request_record(&reviewer_client, &applied_request.id, "reviewer").await;
    let approve_action = promoted_client_action(
        &reviewer_client,
        &reviewer_authority,
        &before_approve,
        RegistryServerLifecycleOperation::ApproveRequest,
    );
    assert_eq!(approve_action.stage(), Some("review"));
    let approved = execute_client_action_and_refetch(
        &reviewer_client,
        &approve_action,
        "client-lifecycle-approve",
        &applied_request.id,
        "reviewer",
    )
    .await;
    exercised.insert(RegistryServerLifecycleOperation::ApproveRequest);
    assert_eq!(
        request_metadata(&approved).server_state(),
        RegistryServerRequestState::Approved
    );

    let before_apply = client_request_record(&applier_client, &applied_request.id, "applier").await;
    let apply_action = promoted_client_action(
        &applier_client,
        &applier_authority,
        &before_apply,
        RegistryServerLifecycleOperation::ApplyRequest,
    );
    let applied = execute_client_action_and_refetch(
        &applier_client,
        &apply_action,
        "client-lifecycle-apply",
        &applied_request.id,
        "applier",
    )
    .await;
    exercised.insert(RegistryServerLifecycleOperation::ApplyRequest);
    let applied_metadata = request_metadata(&applied);
    assert_eq!(
        applied_metadata.server_state(),
        RegistryServerRequestState::Applied
    );
    assert!(applied_metadata.application().is_some());
    let changed_placement =
        client_record(&steward_client, "placements", &placement.id, "steward").await;
    assert_eq!(
        changed_placement.data.domain_data.get("site"),
        Some(&Value::String(new_site.id.clone()))
    );

    let rejected_draft =
        client_request_record(&submitter_client, &rejected_request.id, "submitter").await;
    let rejected_submit = promoted_client_action(
        &submitter_client,
        &submitter_authority,
        &rejected_draft,
        RegistryServerLifecycleOperation::SubmitRequest,
    );
    execute_client_action_and_refetch(
        &submitter_client,
        &rejected_submit,
        "client-lifecycle-reject-submit",
        &rejected_request.id,
        "submitter",
    )
    .await;
    let before_reject =
        client_request_record(&reviewer_client, &rejected_request.id, "reviewer").await;
    let reject_action = promoted_client_action(
        &reviewer_client,
        &reviewer_authority,
        &before_reject,
        RegistryServerLifecycleOperation::RejectRequest,
    );
    let rejected = execute_client_action_and_refetch(
        &reviewer_client,
        &reject_action,
        "client-lifecycle-reject",
        &rejected_request.id,
        "reviewer",
    )
    .await;
    exercised.insert(RegistryServerLifecycleOperation::RejectRequest);
    assert_eq!(
        request_metadata(&rejected).server_state(),
        RegistryServerRequestState::Rejected
    );

    let canceled_draft =
        client_request_record(&submitter_client, &canceled_request.id, "submitter").await;
    let cancel_action = promoted_client_action(
        &submitter_client,
        &submitter_authority,
        &canceled_draft,
        RegistryServerLifecycleOperation::CancelRequest,
    );
    let canceled = execute_client_action_and_refetch(
        &submitter_client,
        &cancel_action,
        "client-lifecycle-cancel",
        &canceled_request.id,
        "submitter",
    )
    .await;
    exercised.insert(RegistryServerLifecycleOperation::CancelRequest);
    assert_eq!(
        request_metadata(&canceled).server_state(),
        RegistryServerRequestState::Canceled
    );

    assert_eq!(
        exercised,
        RegistryServerLifecycleOperation::ALL.into_iter().collect(),
        "the real PostgreSQL client journey covers the closed lifecycle operation set"
    );

    server.finish().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_change_request_apply_lost_response_replays_same_and_different_key_receipts(
) {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(compiled_registry());
    let identity =
        install_registry(&database, &registry, "lost-response-change-request", true).await;
    let app = change_request_router(
        &database,
        registry.clone(),
        identity.clone(),
        "lost-response-change-request",
        None,
    );
    let lost_response_app = change_request_router(
        &database,
        registry.clone(),
        identity,
        "lost-response-change-request",
        Some(MutationFaultPoint::AfterCommitBeforeResponseRelease),
    );
    let steward = claims("steward", "lost-response-steward", None);
    let submitter = claims("submitter", "lost-response-submitter", None);
    let reviewer = claims("reviewer", "lost-response-reviewer", Some("review"));
    let applier = claims("applier", "lost-response-applier", Some("apply"));

    let old_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "lost-create-old-site",
        json!({"tenant": TENANT, "name": "lost-old"}),
    )
    .await;
    let new_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "lost-create-new-site",
        json!({"tenant": TENANT, "name": "lost-new"}),
    )
    .await;
    let placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=steward",
        steward.clone(),
        "lost-create-placement",
        json!({
            "tenant": TENANT,
            "site": old_site.id,
            "validFrom": "2026-08-31",
            "validTo": Value::Null
        }),
    )
    .await;
    let request = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=submitter",
        submitter.clone(),
        "lost-create-correction-request",
        json!({
            "tenant": TENANT,
            "placement": placement.id,
            "proposedSite": new_site.id,
            "reason": "lost response replay proof"
        }),
    )
    .await;

    let submitted = run_action(
        &app,
        &request.id,
        "correction-requests",
        "submitter",
        submitter,
        "lost-submit-correction-request",
        "submit_request",
        None,
        |_| json!({}),
    )
    .await;
    let effect_digest = submitted["request"]["effectDigest"]
        .as_str()
        .expect("submission freezes digest")
        .to_owned();
    run_action(
        &app,
        &request.id,
        "correction-requests",
        "reviewer",
        reviewer,
        "lost-approve-correction-request",
        "approve_request",
        Some("review"),
        |_| json!({"proposalVersion": 1, "effectDigest": effect_digest}),
    )
    .await;

    let before_apply = get_record(
        &lost_response_app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=applier",
            request.id
        ),
        applier.clone(),
    )
    .await;
    let apply = action(&before_apply.body, "apply_request", None);
    let apply_body = json!({
        "proposalVersion": apply.proposal_version,
        "effectDigest": apply.effect_digest.clone()
    });
    let before_apply_history = history_commit_counts(&database).await;
    let lost = send_action(
        &lost_response_app,
        &apply,
        "lost-apply-correction-request",
        applier.clone(),
        apply_body.clone(),
    )
    .await;
    assert_eq!(lost.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(lost.body["code"], "service.unavailable");
    let after_apply_history = history_commit_counts(&database).await;
    assert_eq!(
        after_apply_history.commits - before_apply_history.commits,
        1,
        "fresh apply must allocate exactly one history commit"
    );
    assert_eq!(
        after_apply_history.members - before_apply_history.members,
        2,
        "apply commit must include the request lifecycle revision and target revision"
    );

    let replayed = send_action(
        &app,
        &apply,
        "lost-apply-correction-request",
        applier.clone(),
        apply_body.clone(),
    )
    .await;
    assert_eq!(
        replayed.status,
        StatusCode::OK,
        "same idempotency key must release the committed application receipt, body {}",
        replayed.body
    );
    assert_eq!(replayed.body["request"]["serverState"], "applied");
    assert_snapshot_reference(&replayed.body["snapshot"]);
    let apply_members = history_members_for_snapshot(&database, &replayed.body["snapshot"]).await;
    assert_eq!(apply_members.len(), 2);
    assert!(
        apply_members.iter().any(|member| {
            member.entity_id == "correction-request"
                && member.record_id.to_string() == request.id
                && member.record_revision
                    == replayed.body["revision"]
                        .as_i64()
                        .expect("apply response carries request revision")
        }),
        "apply commit includes the request lifecycle revision"
    );
    assert!(
        apply_members.iter().any(|member| {
            member.entity_id == "asset-placement"
                && member.record_id == Uuid::parse_str(&placement.id).expect("placement id parses")
                && member.record_revision == 2
        }),
        "apply commit includes the target record revision"
    );
    assert_eq!(
        history_commit_counts(&database).await,
        after_apply_history,
        "same-key apply replay must not allocate another commit position"
    );

    let application_receipt = replayed.body["request"]["application"].clone();
    let replayed_revision = replayed.body["revision"].clone();
    let different_key = send_action(
        &app,
        &apply,
        "lost-apply-correction-request-different-key",
        applier.clone(),
        apply_body.clone(),
    )
    .await;
    assert_eq!(
        different_key.status,
        StatusCode::OK,
        "a new key for the exact applied proposal must recover the authorized receipt, body {}",
        different_key.body
    );
    assert_eq!(different_key.body["request"]["serverState"], "applied");
    assert_eq!(
        different_key.body["request"]["application"],
        application_receipt
    );
    assert_eq!(different_key.body["revision"], replayed_revision);
    assert_eq!(
        history_commit_counts(&database).await,
        after_apply_history,
        "different-key applied-state recovery must not allocate another commit position"
    );
    assert_eq!(application_result_count(&database).await, 1);
    assert_eq!(
        target_revision(&database, "asset-placement", &placement.id).await,
        2
    );

    let idempotency_rows_before_bad_precondition = idempotency_result_count(&database).await;
    let bogus_precondition = RequestAction {
        href: apply.href.clone(),
        if_match: tampered_if_match(&apply.if_match),
        proposal_version: apply.proposal_version,
        effect_digest: apply.effect_digest.clone(),
        review: Value::Null,
    };
    let bad_precondition = send_action(
        &app,
        &bogus_precondition,
        "lost-apply-correction-request-bogus-precondition",
        applier.clone(),
        apply_body.clone(),
    )
    .await;
    assert_eq!(bad_precondition.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(bad_precondition.body["code"], "precondition.failed");
    assert_eq!(
        idempotency_result_count(&database).await,
        idempotency_rows_before_bad_precondition,
        "failed applied-state recovery must not bind a new idempotency row"
    );
    assert_eq!(application_result_count(&database).await, 1);
    assert_eq!(
        target_revision(&database, "asset-placement", &placement.id).await,
        2
    );

    let wrong_version_body = json!({
        "proposalVersion": 2,
        "effectDigest": apply.effect_digest.clone()
    });
    let wrong_version = send_action(
        &app,
        &apply,
        "lost-apply-correction-request-wrong-version",
        applier.clone(),
        wrong_version_body,
    )
    .await;
    assert_eq!(wrong_version.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(wrong_version.body["code"], "precondition.failed");

    let wrong_digest = send_action(
        &app,
        &apply,
        "lost-apply-correction-request-wrong-digest",
        applier,
        json!({
            "proposalVersion": apply.proposal_version,
            "effectDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }),
    )
    .await;
    assert_eq!(wrong_digest.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(wrong_digest.body["code"], "precondition.failed");

    let changed_placement = get_record(
        &app,
        &format!(
            "/v1/records/placements/{}?accessProfile=steward",
            placement.id
        ),
        steward,
    )
    .await;
    assert_eq!(changed_placement.body["revision"], 2);
    assert_eq!(changed_placement.body["data"]["site"], new_site.id);
    assert_eq!(application_result_count(&database).await, 1);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_change_request_approval_history_commit_replays_without_new_position() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(compiled_registry());
    let identity = install_registry(
        &database,
        &registry,
        "approval-history-change-request",
        true,
    )
    .await;
    let app = change_request_router(
        &database,
        registry.clone(),
        identity,
        "approval-history-change-request",
        None,
    );
    let steward = claims("steward", "approval-history-steward", None);
    let submitter = claims("submitter", "approval-history-submitter", None);
    let reviewer = claims("reviewer", "approval-history-reviewer", Some("review"));

    let old_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "approval-history-create-old-site",
        json!({"tenant": TENANT, "name": "approval-history-old"}),
    )
    .await;
    let new_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "approval-history-create-new-site",
        json!({"tenant": TENANT, "name": "approval-history-new"}),
    )
    .await;
    let placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=steward",
        steward,
        "approval-history-create-placement",
        json!({
            "tenant": TENANT,
            "site": old_site.id,
            "validFrom": "2026-08-31",
            "validTo": Value::Null
        }),
    )
    .await;
    let request = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=submitter",
        submitter.clone(),
        "approval-history-create-correction-request",
        json!({
            "tenant": TENANT,
            "placement": placement.id,
            "proposedSite": new_site.id,
            "reason": "approval history commit proof"
        }),
    )
    .await;
    let submitted = run_action(
        &app,
        &request.id,
        "correction-requests",
        "submitter",
        submitter,
        "approval-history-submit-correction-request",
        "submit_request",
        None,
        |_| json!({}),
    )
    .await;
    let effect_digest = submitted["request"]["effectDigest"]
        .as_str()
        .expect("submission freezes digest")
        .to_owned();

    let before_review = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=reviewer",
            request.id
        ),
        reviewer.clone(),
    )
    .await;
    let approve = action(&before_review.body, "approve_request", Some("review"));
    let approve_body = json!({"proposalVersion": 1, "effectDigest": effect_digest});
    let before_history = history_commit_counts(&database).await;
    let approved = send_action(
        &app,
        &approve,
        "approval-history-approve-correction-request",
        reviewer.clone(),
        approve_body.clone(),
    )
    .await;
    assert_eq!(
        approved.status,
        StatusCode::OK,
        "approval failed with body {}",
        approved.body
    );
    assert_eq!(approved.body["request"]["serverState"], "approved");
    assert_snapshot_reference(&approved.body["snapshot"]);
    let after_approval_history = history_commit_counts(&database).await;
    assert_eq!(
        after_approval_history.commits - before_history.commits,
        1,
        "fresh approval must allocate exactly one history commit"
    );
    assert_eq!(
        after_approval_history.members - before_history.members,
        1,
        "approval commits only the request row revision"
    );
    let members = history_members_for_snapshot(&database, &approved.body["snapshot"]).await;
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].entity_id, "correction-request");
    assert_eq!(members[0].record_id.to_string(), request.id);
    assert_eq!(
        members[0].record_revision,
        approved.body["revision"]
            .as_i64()
            .expect("approval response carries request revision")
    );

    let replayed = send_action(
        &app,
        &approve,
        "approval-history-approve-correction-request",
        reviewer,
        approve_body,
    )
    .await;
    assert_eq!(
        replayed.status,
        StatusCode::OK,
        "approval replay failed with body {}",
        replayed.body
    );
    assert_eq!(replayed.body, approved.body);
    assert_eq!(
        history_commit_counts(&database).await,
        after_approval_history,
        "idempotent approval replay must not allocate another commit position"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_change_request_apply_concurrent_same_and_different_keys_return_one_receipt(
) {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(compiled_registry());
    let identity = install_registry(
        &database,
        &registry,
        "concurrent-apply-change-request",
        true,
    )
    .await;
    let app = change_request_router(
        &database,
        registry.clone(),
        identity,
        "concurrent-apply-change-request",
        None,
    );
    let steward = claims("steward", "concurrent-steward", None);
    let submitter = claims("submitter", "concurrent-submitter", None);
    let reviewer = claims("reviewer", "concurrent-reviewer", Some("review"));
    let applier = claims("applier", "concurrent-applier", Some("apply"));
    let approved = create_approved_correction(
        &app,
        steward.clone(),
        submitter,
        reviewer,
        "concurrent",
        "concurrent correction",
    )
    .await;

    let before_apply = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=applier",
            approved.request_id
        ),
        applier.clone(),
    )
    .await;
    let apply = action(&before_apply.body, "apply_request", None);
    let apply_body = json!({
        "proposalVersion": apply.proposal_version,
        "effectDigest": apply.effect_digest.clone()
    });

    let same_a = send_action(
        &app,
        &apply,
        "concurrent-apply-same-key",
        applier.clone(),
        apply_body.clone(),
    );
    let same_b = send_action(
        &app,
        &apply,
        "concurrent-apply-same-key",
        applier.clone(),
        apply_body.clone(),
    );
    let different = send_action(
        &app,
        &apply,
        "concurrent-apply-different-key",
        applier,
        apply_body,
    );
    let (same_a, same_b, different) = tokio::join!(same_a, same_b, different);
    for response in [&same_a, &same_b, &different] {
        assert_eq!(
            response.status,
            StatusCode::OK,
            "concurrent exact apply must return an application receipt, body {}",
            response.body
        );
        assert_eq!(response.body["request"]["serverState"], "applied");
    }
    assert_eq!(
        same_a.body["request"]["application"],
        same_b.body["request"]["application"]
    );
    assert_eq!(
        same_a.body["request"]["application"],
        different.body["request"]["application"]
    );

    let changed_placement = get_record(
        &app,
        &format!(
            "/v1/records/placements/{}?accessProfile=steward",
            approved.placement_id
        ),
        steward,
    )
    .await;
    assert_eq!(changed_placement.body["revision"], 2);
    assert_eq!(changed_placement.body["data"]["site"], approved.new_site_id);
    assert_eq!(application_result_count(&database).await, 1);
    assert_eq!(
        target_revision(&database, "asset-placement", &approved.placement_id).await,
        2
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_change_request_apply_terminal_fault_rolls_back_request_and_target() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(compiled_registry());
    let identity =
        install_registry(&database, &registry, "terminal-fault-change-request", true).await;
    let app = change_request_router(
        &database,
        registry.clone(),
        identity.clone(),
        "terminal-fault-change-request",
        None,
    );
    let terminal_fault_app = change_request_router(
        &database,
        registry.clone(),
        identity,
        "terminal-fault-change-request",
        Some(MutationFaultPoint::BeforeTerminalAudit),
    );
    let steward = claims("steward", "terminal-steward", None);
    let submitter = claims("submitter", "terminal-submitter", None);
    let reviewer = claims("reviewer", "terminal-reviewer", Some("review"));
    let applier = claims("applier", "terminal-applier", Some("apply"));
    let approved = create_approved_correction(
        &app,
        steward.clone(),
        submitter,
        reviewer,
        "terminal",
        "terminal rollback correction",
    )
    .await;

    let before_apply = get_record(
        &terminal_fault_app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=applier",
            approved.request_id
        ),
        applier.clone(),
    )
    .await;
    let apply = action(&before_apply.body, "apply_request", None);
    let failed = send_action(
        &terminal_fault_app,
        &apply,
        "terminal-fault-apply",
        applier.clone(),
        json!({
            "proposalVersion": apply.proposal_version,
            "effectDigest": apply.effect_digest.clone()
        }),
    )
    .await;
    assert_eq!(failed.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(failed.body["code"], "service.unavailable");

    let unchanged_placement = get_record(
        &app,
        &format!(
            "/v1/records/placements/{}?accessProfile=steward",
            approved.placement_id
        ),
        steward,
    )
    .await;
    assert_eq!(unchanged_placement.body["revision"], 1);
    assert_eq!(
        unchanged_placement.body["data"]["site"],
        approved.old_site_id
    );
    let request_after_fault = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=applier",
            approved.request_id
        ),
        applier,
    )
    .await;
    assert_eq!(
        request_after_fault.body["request"]["serverState"],
        "approved"
    );
    assert_eq!(
        request_after_fault.body["request"]["application"],
        Value::Null
    );
    assert_eq!(application_result_count(&database).await, 0);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_change_request_oversized_prepared_packet_refuses_before_request_lock() {
    let mut database = TestDatabase::create(8).await;
    let registry = Arc::new(bounded_snapshot_registry());
    let identity = install_registry(
        &database,
        &registry,
        "bounded-snapshot-change-request",
        false,
    )
    .await;
    let app = change_request_router(
        &database,
        registry.clone(),
        identity,
        "bounded-snapshot-change-request",
        None,
    );
    let steward = claims("steward", "bounded-steward", None);
    let submitter = claims("submitter", "bounded-submitter", None);
    let old_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "bounded-create-old-site",
        json!({"tenant": TENANT, "name": "bounded-old"}),
    )
    .await;
    let new_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "bounded-create-new-site",
        json!({"tenant": TENANT, "name": "bounded-new"}),
    )
    .await;
    let large_note = "x".repeat(1_060_000);
    let placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=steward",
        steward,
        "bounded-create-placement",
        json!({"tenant": TENANT, "site": old_site.id, "note": large_note}),
    )
    .await;
    let request = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=submitter",
        submitter.clone(),
        "bounded-create-correction-request",
        json!({
            "tenant": TENANT,
            "placement": placement.id,
            "proposedSite": new_site.id,
            "reason": "bounded preparation proof"
        }),
    )
    .await;
    let before_submit = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=submitter",
            request.id
        ),
        submitter.clone(),
    )
    .await;
    let submit = action(&before_submit.body, "submit_request", None);

    let lock_transaction = database
        .admin
        .transaction()
        .await
        .expect("request row lock transaction starts");
    let request_table = registry.entities()["correction-request"]
        .physical_table
        .replace('"', "\"\"");
    lock_transaction
        .query_one(
            &format!(
                "SELECT 1 FROM registry_data.\"{request_table}\" WHERE record_id = $1::text::uuid FOR UPDATE"
            ),
            &[&request.id],
        )
        .await
        .expect("request row lock is held");

    let started = tokio::time::Instant::now();
    let refused = tokio::time::timeout(
        Duration::from_millis(1_500),
        send_action(
            &app,
            &submit,
            "bounded-submit-correction-request",
            submitter,
            json!({}),
        ),
    )
    .await
    .expect("oversized submit is refused before waiting on the held request row lock");
    assert!(
        started.elapsed() < Duration::from_millis(1_500),
        "oversized submit waited for the held mutation lock"
    );
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(refused.body["code"], "request.invalid");
    drop(lock_transaction);
    assert_eq!(
        proposal_count(&database, "correction-request", &request.id).await,
        0
    );
    assert_eq!(application_result_count(&database).await, 0);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn long_logical_request_entity_id_matches_installed_physical_catalog() {
    let database = TestDatabase::create(2).await;
    let registry = Arc::new(long_logical_id_registry());
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("long logical request entity schema installs");
    initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: "long-logical-change-request",
            environment: "local",
            instance_id: "long-logical-change-request-instance",
            database_id: "long-logical-change-request-database",
            package_revision: PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("compiled physical identifiers and installed catalog must match");
    drop(migration);
    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_change_request_registration_applies_reserved_creates_atomically() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(registration_registry());
    let identity =
        install_registry(&database, &registry, "registration-change-request", false).await;
    let app = change_request_router(
        &database,
        registry.clone(),
        identity,
        "registration-change-request",
        None,
    );
    let steward = claims("steward", "registration-steward", None);
    let operator = claims("operator", "registration-operator", None);

    let household = create_record(
        &app,
        "/v1/records/households?accessProfile=steward",
        steward.clone(),
        "create-household",
        json!({"tenant": TENANT, "label": "household one"}),
    )
    .await;
    let request = create_record(
        &app,
        "/v1/records/registration-requests?accessProfile=operator",
        operator.clone(),
        "create-registration-request",
        json!({"tenant": TENANT, "household": household.id, "name": "Ada Lovelace"}),
    )
    .await;

    let submitted = run_action(
        &app,
        &request.id,
        "registration-requests",
        "operator",
        operator.clone(),
        "submit-registration-request",
        "submit_request",
        None,
        |_| json!({}),
    )
    .await;
    let digest = submitted["request"]["effectDigest"]
        .as_str()
        .expect("submission freezes digest")
        .to_owned();
    let before_approve = get_record(
        &app,
        &format!(
            "/v1/records/registration-requests/{}?accessProfile=operator",
            request.id
        ),
        operator.clone(),
    )
    .await;
    let approve = action(&before_approve.body, "approve_request", Some("review"));
    let targets = approve.review["targets"]
        .as_array()
        .expect("target snapshots");
    assert_eq!(targets.len(), 3);
    let person_id = target_record_id(targets, "person");
    let membership_id = target_record_id(targets, "membership");
    assert_ne!(person_id, membership_id);
    assert_eq!(
        target_after(targets, "person"),
        json!({"tenant": TENANT, "displayName": "Ada Lovelace"})
    );
    assert_eq!(
        target_after(targets, "membership"),
        json!({"tenant": TENANT, "household": household.id, "person": person_id})
    );
    assert_eq!(
        target_after(targets, "household"),
        json!({"contactPerson": person_id})
    );

    let approved = action_response(
        &app,
        &approve.href,
        "approve-registration-request",
        &approve.if_match,
        operator.clone(),
        json!({"proposalVersion": 1, "effectDigest": digest}),
    )
    .await;
    assert_eq!(approved["request"]["serverState"], "approved");

    let applied = run_action(
        &app,
        &request.id,
        "registration-requests",
        "operator",
        operator.clone(),
        "apply-registration-request",
        "apply_request",
        None,
        |apply| {
            json!({
                "proposalVersion": apply.proposal_version,
                "effectDigest": apply.effect_digest
            })
        },
    )
    .await;
    assert_eq!(applied["request"]["serverState"], "applied");

    let person = get_record(
        &app,
        &format!("/v1/records/people/{person_id}?accessProfile=operator"),
        operator.clone(),
    )
    .await;
    assert_eq!(person.body["revision"], 1);
    assert_eq!(person.body["data"]["displayName"], "Ada Lovelace");

    let membership = get_record(
        &app,
        &format!("/v1/records/memberships/{membership_id}?accessProfile=operator"),
        operator.clone(),
    )
    .await;
    assert_eq!(membership.body["revision"], 1);
    assert_eq!(membership.body["data"]["person"], person_id);
    assert_eq!(membership.body["data"]["household"], household.id);

    let changed_household = get_record(
        &app,
        &format!(
            "/v1/records/households/{}?accessProfile=operator",
            household.id
        ),
        operator.clone(),
    )
    .await;
    assert_eq!(changed_household.body["revision"], 2);
    assert_eq!(changed_household.body["data"]["contactPerson"], person_id);

    let person_revisions = revision_items(
        &app,
        &format!("/v1/records/people/{person_id}/revisions?accessProfile=operator"),
        operator.clone(),
    )
    .await;
    assert_eq!(person_revisions[0]["operationId"], "records.person.create");
    assert!(!person_revisions[0]["operationId"]
        .as_str()
        .expect("operation id")
        .contains("registration-request"));
    let membership_revisions = revision_items(
        &app,
        &format!("/v1/records/memberships/{membership_id}/revisions?accessProfile=operator"),
        operator.clone(),
    )
    .await;
    assert_eq!(
        membership_revisions[0]["operationId"],
        "records.membership.create"
    );
    assert!(!membership_revisions[0]["operationId"]
        .as_str()
        .expect("operation id")
        .contains("registration-request"));
    let household_revisions = revision_items(
        &app,
        &format!(
            "/v1/records/households/{}/revisions?accessProfile=operator",
            household.id
        ),
        operator.clone(),
    )
    .await;
    assert_eq!(
        household_revisions[0]["operationId"],
        "records.household.patch"
    );
    assert!(!household_revisions[0]["operationId"]
        .as_str()
        .expect("operation id")
        .contains("registration-request"));

    let request_revisions = revision_items(
        &app,
        &format!(
            "/v1/records/registration-requests/{}/revisions?accessProfile=operator",
            request.id
        ),
        operator,
    )
    .await;
    assert_revision_operations_include(
        &request_revisions,
        &[
            "records.registration-request.request.apply",
            "records.registration-request.request.stages.review.approve",
            "records.registration-request.request.submit",
            "records.registration-request.create",
        ],
    );
    assert_eq!(application_result_count(&database).await, 3);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_change_request_registration_rolls_back_after_partial_apply_fault() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(registration_registry());
    let identity = install_registry(
        &database,
        &registry,
        "registration-change-request-fault",
        false,
    )
    .await;
    let setup_app = change_request_router(
        &database,
        registry.clone(),
        identity.clone(),
        "registration-change-request-fault",
        None,
    );
    let fault_app = change_request_router(
        &database,
        registry.clone(),
        identity,
        "registration-change-request-fault",
        Some(MutationFaultPoint::AfterFirstBatchItem),
    );
    let steward = claims("steward", "fault-steward", None);
    let operator = claims("operator", "fault-operator", None);
    let household = create_record(
        &setup_app,
        "/v1/records/households?accessProfile=steward",
        steward,
        "fault-create-household",
        json!({"tenant": TENANT, "label": "fault household"}),
    )
    .await;
    let request = create_record(
        &setup_app,
        "/v1/records/registration-requests?accessProfile=operator",
        operator.clone(),
        "fault-create-registration-request",
        json!({"tenant": TENANT, "household": household.id, "name": "Grace Hopper"}),
    )
    .await;
    let submitted = run_action(
        &setup_app,
        &request.id,
        "registration-requests",
        "operator",
        operator.clone(),
        "fault-submit-registration-request",
        "submit_request",
        None,
        |_| json!({}),
    )
    .await;
    let digest = submitted["request"]["effectDigest"]
        .as_str()
        .expect("submission freezes digest")
        .to_owned();
    let before_approve = get_record(
        &setup_app,
        &format!(
            "/v1/records/registration-requests/{}?accessProfile=operator",
            request.id
        ),
        operator.clone(),
    )
    .await;
    let approve = action(&before_approve.body, "approve_request", Some("review"));
    let approved = action_response(
        &setup_app,
        &approve.href,
        "fault-approve-registration-request",
        &approve.if_match,
        operator.clone(),
        json!({"proposalVersion": 1, "effectDigest": digest}),
    )
    .await;
    assert_eq!(approved["request"]["serverState"], "approved");
    let targets = approve.review["targets"]
        .as_array()
        .expect("target snapshots");
    let person_id = target_record_id(targets, "person");
    let membership_id = target_record_id(targets, "membership");

    let before_apply = get_record(
        &fault_app,
        &format!(
            "/v1/records/registration-requests/{}?accessProfile=operator",
            request.id
        ),
        operator.clone(),
    )
    .await;
    let apply = action(&before_apply.body, "apply_request", None);
    let failed = send(
        &fault_app,
        Method::POST,
        &apply.href,
        Some(operator.clone()),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "fault-apply-registration-request"),
            ("if-match", &apply.if_match),
        ],
        serde_json::to_vec(&json!({
            "proposalVersion": apply.proposal_version,
            "effectDigest": apply.effect_digest
        }))
        .expect("apply body serializes"),
    )
    .await;
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(failed).await["code"], "service.unavailable");
    assert_not_found(
        &setup_app,
        &format!("/v1/records/people/{person_id}?accessProfile=operator"),
        operator.clone(),
    )
    .await;
    assert_not_found(
        &setup_app,
        &format!("/v1/records/memberships/{membership_id}?accessProfile=operator"),
        operator.clone(),
    )
    .await;
    let unchanged_household = get_record(
        &setup_app,
        &format!(
            "/v1/records/households/{}?accessProfile=operator",
            household.id
        ),
        operator,
    )
    .await;
    assert_eq!(unchanged_household.body["revision"], 1);
    assert_eq!(
        unchanged_household.body["data"]["contactPerson"],
        Value::Null
    );
    assert_eq!(application_result_count(&database).await, 0);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_change_request_apply_serialization_retries_are_bounded_and_stable() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(registration_registry());
    let identity = install_registry(
        &database,
        &registry,
        "registration-change-request-sql-retry",
        false,
    )
    .await;
    install_serialization_retry_trigger(&database, &registry, "membership", 3).await;
    let app = change_request_router(
        &database,
        registry.clone(),
        identity,
        "registration-change-request-sql-retry",
        None,
    );
    let steward = claims("steward", "sql-retry-steward", None);
    let operator = claims("operator", "sql-retry-operator", None);

    let failed = create_approved_registration(
        &app,
        steward.clone(),
        operator.clone(),
        "sql-retry-exhausted",
    )
    .await;
    let failed_apply = send_registration_apply(
        &app,
        &failed.request_id,
        operator.clone(),
        "sql-retry-exhausted-apply",
    )
    .await;
    assert_eq!(failed_apply.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(failed_apply.body["code"], "service.unavailable");
    assert_eq!(
        serialization_retry_attempts(&database).await,
        3,
        "real SQLSTATE 40001 aborts must stop after the bounded retry budget"
    );
    assert_not_found(
        &app,
        &format!(
            "/v1/records/people/{}?accessProfile=operator",
            failed.person_id
        ),
        operator.clone(),
    )
    .await;
    assert_not_found(
        &app,
        &format!(
            "/v1/records/memberships/{}?accessProfile=operator",
            failed.membership_id
        ),
        operator.clone(),
    )
    .await;
    let failed_household = get_record(
        &app,
        &format!(
            "/v1/records/households/{}?accessProfile=operator",
            failed.household_id
        ),
        operator.clone(),
    )
    .await;
    assert_eq!(failed_household.body["revision"], 1);
    assert_eq!(failed_household.body["data"]["contactPerson"], Value::Null);
    assert_eq!(application_result_count(&database).await, 0);

    set_serialization_retry_failures(&database, 2).await;
    let approved =
        create_approved_registration(&app, steward, operator.clone(), "sql-retry-succeeds").await;
    let applied = send_registration_apply(
        &app,
        &approved.request_id,
        operator.clone(),
        "sql-retry-succeeds-apply",
    )
    .await;
    assert_eq!(
        applied.status,
        StatusCode::OK,
        "apply after two SQLSTATE 40001 aborts failed with body {}",
        applied.body
    );
    assert_eq!(applied.body["request"]["serverState"], "applied");
    assert_eq!(
        serialization_retry_attempts(&database).await,
        3,
        "success on the third database attempt must not spin past the retry budget"
    );
    let person = get_record(
        &app,
        &format!(
            "/v1/records/people/{}?accessProfile=operator",
            approved.person_id
        ),
        operator.clone(),
    )
    .await;
    assert_eq!(person.body["id"], approved.person_id);
    let membership = get_record(
        &app,
        &format!(
            "/v1/records/memberships/{}?accessProfile=operator",
            approved.membership_id
        ),
        operator.clone(),
    )
    .await;
    assert_eq!(membership.body["id"], approved.membership_id);
    assert_eq!(membership.body["data"]["person"], approved.person_id);
    let household = get_record(
        &app,
        &format!(
            "/v1/records/households/{}?accessProfile=operator",
            approved.household_id
        ),
        operator,
    )
    .await;
    assert_eq!(household.body["revision"], 2);
    assert_eq!(household.body["data"]["contactPerson"], approved.person_id);
    assert_eq!(
        target_revision(&database, "person", &approved.person_id).await,
        1
    );
    assert_eq!(
        target_revision(&database, "membership", &approved.membership_id).await,
        1
    );
    assert_eq!(
        target_revision(&database, "household", &approved.household_id).await,
        2
    );
    assert_eq!(application_result_count(&database).await, 3);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "exercises the hard-coded 30 second request-action deadline with blocked PostgreSQL"]
async fn real_postgres_http_change_request_apply_deadline_cancels_blocked_sql() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(registration_registry());
    let identity = install_registry(
        &database,
        &registry,
        "registration-change-request-sql-deadline",
        false,
    )
    .await;
    install_delayed_sql_trigger(&database, &registry, "person", 8).await;
    install_blocked_sql_trigger(&database, &registry, "membership").await;
    let app = change_request_router(
        &database,
        registry.clone(),
        identity,
        "registration-change-request-sql-deadline",
        None,
    );
    let steward = claims("steward", "sql-deadline-steward", None);
    let operator = claims("operator", "sql-deadline-operator", None);
    let approved =
        create_approved_registration(&app, steward, operator.clone(), "sql-deadline").await;

    let started = Instant::now();
    let blocked = send_registration_apply(
        &app,
        &approved.request_id,
        operator.clone(),
        "sql-deadline-apply",
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(
        blocked.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "blocked apply should fail closed with body {}",
        blocked.body
    );
    assert!(
        elapsed < Duration::from_secs(32),
        "blocked SQL was not bounded by the shared action deadline: elapsed {elapsed:?}"
    );
    assert_blocked_sql_canceled(&database, &registry, "membership").await;
    assert_not_found(
        &app,
        &format!(
            "/v1/records/people/{}?accessProfile=operator",
            approved.person_id
        ),
        operator.clone(),
    )
    .await;
    assert_not_found(
        &app,
        &format!(
            "/v1/records/memberships/{}?accessProfile=operator",
            approved.membership_id
        ),
        operator.clone(),
    )
    .await;
    let household = get_record(
        &app,
        &format!(
            "/v1/records/households/{}?accessProfile=operator",
            approved.household_id
        ),
        operator,
    )
    .await;
    assert_eq!(household.body["revision"], 1);
    assert_eq!(household.body["data"]["contactPerson"], Value::Null);
    assert_eq!(application_result_count(&database).await, 0);
    tokio::time::sleep(Duration::from_secs(15)).await;
    assert_eq!(
        application_result_count(&database).await,
        0,
        "canceled SQL must not complete silently after the timeout response"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_change_request_apply_cancels_when_startup_timeout_drops_future() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(registration_registry());
    let identity = install_registry(
        &database,
        &registry,
        "registration-change-request-startup-timeout",
        false,
    )
    .await;
    install_delayed_sql_trigger(&database, &registry, "person", 8).await;
    install_blocked_sql_trigger(&database, &registry, "membership").await;
    let app = with_request_timeout_for_test(
        change_request_router(
            &database,
            registry.clone(),
            identity,
            "registration-change-request-startup-timeout",
            None,
        ),
        Duration::from_secs(10),
    );
    let steward = claims("steward", "startup-timeout-steward", None);
    let operator = claims("operator", "startup-timeout-operator", None);
    let approved =
        create_approved_registration(&app, steward, operator.clone(), "startup-timeout").await;

    let started = Instant::now();
    let timed_out = send_registration_apply(
        &app,
        &approved.request_id,
        operator.clone(),
        "startup-timeout-apply",
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(timed_out.status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(timed_out.body["code"], "request.timeout");
    assert!(
        elapsed < Duration::from_secs(12),
        "startup timeout did not bound the request action future: elapsed {elapsed:?}"
    );
    assert_blocked_sql_canceled(&database, &registry, "membership").await;
    assert_not_found(
        &app,
        &format!(
            "/v1/records/people/{}?accessProfile=operator",
            approved.person_id
        ),
        operator.clone(),
    )
    .await;
    assert_not_found(
        &app,
        &format!(
            "/v1/records/memberships/{}?accessProfile=operator",
            approved.membership_id
        ),
        operator.clone(),
    )
    .await;
    let household = get_record(
        &app,
        &format!(
            "/v1/records/households/{}?accessProfile=operator",
            approved.household_id
        ),
        operator,
    )
    .await;
    assert_eq!(household.body["revision"], 1);
    assert_eq!(household.body["data"]["contactPerson"], Value::Null);
    assert_eq!(application_result_count(&database).await, 0);
    tokio::time::sleep(Duration::from_secs(15)).await;
    assert_eq!(
        application_result_count(&database).await,
        0,
        "startup timeout cancellation must not allow a late application commit"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_change_request_two_stage_stale_rebase_and_cancel_are_bound() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(two_stage_registry());
    let identity = install_registry(&database, &registry, "two-stage-change-request", true).await;
    let app = change_request_router(
        &database,
        registry.clone(),
        identity,
        "two-stage-change-request",
        None,
    );
    let steward = claims("steward", "two-stage-steward", None);
    let submitter = claims("submitter", SUBMITTER, None);
    let reviewer = claims("reviewer", REVIEWER, Some("review"));
    let final_reviewer = claims("final-reviewer", "final-reviewer-principal", Some("final"));
    let applier = claims("applier", APPLIER, Some("apply"));

    let old_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "two-create-old-site",
        json!({"tenant": TENANT, "name": "two-old"}),
    )
    .await;
    let new_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "two-create-new-site",
        json!({"tenant": TENANT, "name": "two-new"}),
    )
    .await;
    let placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=steward",
        steward,
        "two-create-placement",
        json!({"tenant": TENANT, "site": old_site.id}),
    )
    .await;
    let request = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=submitter",
        submitter.clone(),
        "two-create-correction-request",
        json!({
            "tenant": TENANT,
            "placement": placement.id,
            "proposedSite": new_site.id,
            "reason": "two-stage correction"
        }),
    )
    .await;
    let submitted = run_action(
        &app,
        &request.id,
        "correction-requests",
        "submitter",
        submitter.clone(),
        "two-submit-correction-request",
        "submit_request",
        None,
        |_| json!({}),
    )
    .await;
    let digest = submitted["request"]["effectDigest"]
        .as_str()
        .expect("submission freezes digest")
        .to_owned();

    let first_review = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=reviewer",
            request.id
        ),
        reviewer.clone(),
    )
    .await;
    let first_approve = action(&first_review.body, "approve_request", Some("review"));
    action_response(
        &app,
        &first_approve.href,
        "two-first-approval",
        &first_approve.if_match,
        reviewer.clone(),
        json!({"proposalVersion": 1, "effectDigest": digest}),
    )
    .await;

    let no_apply_yet = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=applier",
            request.id
        ),
        applier.clone(),
    )
    .await;
    assert!(
        no_apply_yet.body["request"]["actions"]
            .as_array()
            .is_none_or(|actions| actions
                .iter()
                .all(|action| action["operation"] != "apply_request")),
        "apply must not be advertised before the final stage approval"
    );
    let stale_duplicate = send_action(
        &app,
        &first_approve,
        "two-stale-duplicate-approval",
        reviewer,
        json!({"proposalVersion": 1, "effectDigest": first_approve.effect_digest.clone()}),
    )
    .await;
    assert_eq!(stale_duplicate.status, StatusCode::PRECONDITION_FAILED);

    let final_review = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=final-reviewer",
            request.id
        ),
        final_reviewer.clone(),
    )
    .await;
    assert!(final_review.body["request"]["actions"]
        .as_array()
        .expect("actions")
        .iter()
        .any(|action| action["stage"] == "final"));
    let revision = action(&final_review.body, "request_revision", Some("final"));
    let needs_changes = action_response(
        &app,
        &revision.href,
        "two-request-revision",
        &revision.if_match,
        final_reviewer,
        json!({"proposalVersion": 1, "effectDigest": revision.effect_digest.clone()}),
    )
    .await;
    assert_eq!(needs_changes["request"]["serverState"], "needs_changes");

    let before_rebase = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=submitter",
            request.id
        ),
        submitter.clone(),
    )
    .await;
    let rebase = action(&before_rebase.body, "revise_request", None);
    let draft_v2 = action_response(
        &app,
        &rebase.href,
        "two-rebase-correction-request",
        &rebase.if_match,
        submitter.clone(),
        json!({"rebase": true}),
    )
    .await;
    assert_eq!(draft_v2["request"]["serverState"], "draft");
    assert_eq!(draft_v2["request"]["proposalVersion"], 2);

    let stale_v1_approval = send_action(
        &app,
        &first_approve,
        "two-stale-v1-approval",
        claims("reviewer", REVIEWER, Some("review")),
        json!({"proposalVersion": 1, "effectDigest": first_approve.effect_digest.clone()}),
    )
    .await;
    assert_eq!(stale_v1_approval.status, StatusCode::PRECONDITION_FAILED);

    let cancel = run_action(
        &app,
        &request.id,
        "correction-requests",
        "submitter",
        submitter,
        "two-cancel-correction-request",
        "cancel_request",
        None,
        |_| json!({}),
    )
    .await;
    assert_eq!(cancel["request"]["serverState"], "canceled");
    database.cleanup().await;
}

struct ChangeRequestClientHttpServer {
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl ChangeRequestClientHttpServer {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn finish(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.await
                .expect("change-request client HTTP listener task joins");
        }
    }
}

impl Drop for ChangeRequestClientHttpServer {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn serve_change_request_client_http(app: axum::Router) -> ChangeRequestClientHttpServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("change-request client listener binds on loopback");
    let address = listener
        .local_addr()
        .expect("change-request client listener has an address");
    let app = app.layer(axum::middleware::from_fn(
        inject_change_request_client_claims,
    ));
    let (shutdown, shutdown_receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_receiver.await;
            })
            .await
            .expect("change-request client listener serves the real Router");
    });
    ChangeRequestClientHttpServer {
        base_url: format!("http://{address}"),
        shutdown: Some(shutdown),
        task: Some(task),
    }
}

async fn inject_change_request_client_claims(
    mut request: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let claims = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| match value {
            "Bearer submitter-token" => Some(claims("submitter", SUBMITTER, None)),
            "Bearer reviewer-token" => Some(claims("reviewer", REVIEWER, Some("review"))),
            "Bearer applier-token" => Some(claims("applier", APPLIER, Some("apply"))),
            "Bearer steward-token" => Some(claims("steward", "client-lifecycle-steward", None)),
            _ => None,
        });
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    next.run(request).await
}

fn change_request_client(base_url: &str, token: &str) -> RegistryServerClient {
    let config = RegistryServerClientConfig::new(
        base_url
            .parse()
            .expect("change-request client loopback URL parses"),
    )
    .with_token_provider(Arc::new(
        StaticToken::new(token).expect("change-request client token is an outbound bearer value"),
    ));
    RegistryServerClient::new(config).expect("change-request client config is valid")
}

async fn lifecycle_authority(
    client: &RegistryServerClient,
    access_profile: &str,
) -> RegistryServerLifecycleAuthority {
    client
        .registry_contract(Some(access_profile))
        .await
        .expect("caller receives bounded runtime Registry Metadata")
        .value
        .select_lifecycle("correction-request", access_profile)
        .expect("caller-filtered metadata selects lifecycle authority")
}

async fn client_record(
    client: &RegistryServerClient,
    entity_route: &str,
    record_identifier: &str,
    access_profile: &str,
) -> RegistryRecordSingleResponse {
    let options = ServerRecordOptions::default()
        .access_profile(access_profile)
        .expect("compiled access profile is a valid client identifier");
    client
        .get_record(entity_route, record_identifier, &options)
        .await
        .expect("RegistryServerClient reads one real PostgreSQL Registry Record")
        .value
}

async fn client_request_record(
    client: &RegistryServerClient,
    record_identifier: &str,
    access_profile: &str,
) -> RegistryRecordSingleResponse {
    client_record(
        client,
        "correction-requests",
        record_identifier,
        access_profile,
    )
    .await
}

fn request_metadata(record: &RegistryRecordSingleResponse) -> RegistryServerRequestMetadata {
    RegistryServerRequestMetadata::from_record(&record.data)
        .expect("request extension conforms to the client lifecycle profile")
        .expect("correction-request record exposes request metadata")
}

fn promoted_client_action(
    client: &RegistryServerClient,
    authority: &RegistryServerLifecycleAuthority,
    record: &RegistryRecordSingleResponse,
    operation: RegistryServerLifecycleOperation,
) -> RegistryServerLifecycleAction {
    client
        .lifecycle_actions(authority, record)
        .expect("actor actions promote against metadata and the exact record")
        .into_iter()
        .find(|action| action.operation() == operation)
        .unwrap_or_else(|| panic!("record advertises {}", operation.identifier()))
}

fn idempotency_key(value: &str) -> RegistryServerIdempotencyKey {
    RegistryServerIdempotencyKey::parse(value)
        .expect("journey provides a valid caller idempotency key")
}

async fn execute_client_action_and_refetch(
    client: &RegistryServerClient,
    action: &RegistryServerLifecycleAction,
    key: &str,
    record_identifier: &str,
    access_profile: &str,
) -> RegistryRecordSingleResponse {
    let receipt = client
        .execute_lifecycle_action(action, &idempotency_key(key))
        .await
        .expect("promoted lifecycle action succeeds with its action-specific If-Match");
    let refetched = client_request_record(client, record_identifier, access_profile).await;
    assert_client_receipt_matches_refetch(&receipt.value, &refetched);
    refetched
}

fn assert_client_receipt_matches_refetch(
    receipt: &RegistryServerLifecycleActionReceipt,
    refetched: &RegistryRecordSingleResponse,
) {
    assert_eq!(
        receipt.record_identifier(),
        refetched.data.record_identifier
    );
    assert_eq!(
        receipt.revision().to_string(),
        refetched.data.revision_identifier
    );
    assert_eq!(
        receipt.request().server_state(),
        request_metadata(refetched).server_state()
    );
}

fn change_request_router(
    database: &TestDatabase,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: registry_server::postgres::ExpectedRegistryIdentity,
    package_id: &str,
    fault: Option<MutationFaultPoint>,
) -> axum::Router {
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(package_id).expect("lock key derives");
    let audit = AuditProfile::production_from_secret_bytes(vec![0x9a; 32].into())
        .expect("test audit profile is keyed");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x49; 32]), Duration::from_secs(300))
            .expect("cursor codec builds"),
    );
    let reads = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    ));
    let revisions = Arc::new(PostgresRevisionReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
    ));
    let mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit,
    );
    let mutations = match fault {
        Some(fault) => mutations.with_fault_for_test(fault),
        None => mutations,
    };
    let mutations = Arc::new(mutations);
    router(Arc::new(
        HttpService::new(
            registry,
            ReadRuntimeIdentity {
                package_revision: identity.package_revision,
                schema_fingerprint: identity.schema_fingerprint,
            },
            reads,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_postgres_revisions(revisions)
        .with_postgres_mutations(mutations),
    ))
}

#[derive(Clone)]
struct CreatedRecord {
    id: String,
    etag: String,
}

struct ApprovedCorrection {
    request_id: String,
    placement_id: String,
    old_site_id: String,
    new_site_id: String,
}

struct ApprovedRegistration {
    request_id: String,
    household_id: String,
    person_id: String,
    membership_id: String,
}

async fn create_approved_correction(
    app: &axum::Router,
    steward: VerifiedRequestClaims,
    submitter: VerifiedRequestClaims,
    reviewer: VerifiedRequestClaims,
    key_prefix: &str,
    reason: &str,
) -> ApprovedCorrection {
    let old_site = create_record(
        app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        &format!("{key_prefix}-create-old-site"),
        json!({"tenant": TENANT, "name": format!("{key_prefix}-old")}),
    )
    .await;
    let new_site = create_record(
        app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        &format!("{key_prefix}-create-new-site"),
        json!({"tenant": TENANT, "name": format!("{key_prefix}-new")}),
    )
    .await;
    let placement = create_record(
        app,
        "/v1/records/placements?accessProfile=steward",
        steward,
        &format!("{key_prefix}-create-placement"),
        json!({
            "tenant": TENANT,
            "site": old_site.id,
            "validFrom": "2026-08-31",
            "validTo": Value::Null
        }),
    )
    .await;
    let request = create_record(
        app,
        "/v1/records/correction-requests?accessProfile=submitter",
        submitter.clone(),
        &format!("{key_prefix}-create-correction-request"),
        json!({
            "tenant": TENANT,
            "placement": placement.id,
            "proposedSite": new_site.id,
            "reason": reason
        }),
    )
    .await;
    let submitted = run_action(
        app,
        &request.id,
        "correction-requests",
        "submitter",
        submitter,
        &format!("{key_prefix}-submit-correction-request"),
        "submit_request",
        None,
        |_| json!({}),
    )
    .await;
    let effect_digest = submitted["request"]["effectDigest"]
        .as_str()
        .expect("submission freezes digest")
        .to_owned();
    run_action(
        app,
        &request.id,
        "correction-requests",
        "reviewer",
        reviewer,
        &format!("{key_prefix}-approve-correction-request"),
        "approve_request",
        Some("review"),
        |_| json!({"proposalVersion": 1, "effectDigest": effect_digest}),
    )
    .await;
    ApprovedCorrection {
        request_id: request.id,
        placement_id: placement.id,
        old_site_id: old_site.id,
        new_site_id: new_site.id,
    }
}

async fn create_approved_registration(
    app: &axum::Router,
    steward: VerifiedRequestClaims,
    operator: VerifiedRequestClaims,
    key_prefix: &str,
) -> ApprovedRegistration {
    let household = create_record(
        app,
        "/v1/records/households?accessProfile=steward",
        steward,
        &format!("{key_prefix}-create-household"),
        json!({"tenant": TENANT, "label": format!("{key_prefix} household")}),
    )
    .await;
    let request = create_record(
        app,
        "/v1/records/registration-requests?accessProfile=operator",
        operator.clone(),
        &format!("{key_prefix}-create-registration-request"),
        json!({"tenant": TENANT, "household": household.id, "name": "Ada Lovelace"}),
    )
    .await;
    let submitted = run_action(
        app,
        &request.id,
        "registration-requests",
        "operator",
        operator.clone(),
        &format!("{key_prefix}-submit-registration-request"),
        "submit_request",
        None,
        |_| json!({}),
    )
    .await;
    let digest = submitted["request"]["effectDigest"]
        .as_str()
        .expect("submission freezes digest")
        .to_owned();
    let before_approve = get_record(
        app,
        &format!(
            "/v1/records/registration-requests/{}?accessProfile=operator",
            request.id
        ),
        operator.clone(),
    )
    .await;
    let approve = action(&before_approve.body, "approve_request", Some("review"));
    let targets = approve.review["targets"]
        .as_array()
        .expect("approval action carries target snapshots");
    let person_id = target_record_id(targets, "person");
    let membership_id = target_record_id(targets, "membership");
    let approved = action_response(
        app,
        &approve.href,
        &format!("{key_prefix}-approve-registration-request"),
        &approve.if_match,
        operator,
        json!({"proposalVersion": 1, "effectDigest": digest}),
    )
    .await;
    assert_eq!(approved["request"]["serverState"], "approved");
    ApprovedRegistration {
        request_id: request.id,
        household_id: household.id,
        person_id,
        membership_id,
    }
}

async fn send_registration_apply(
    app: &axum::Router,
    request_id: &str,
    operator: VerifiedRequestClaims,
    key: &str,
) -> ResponseParts {
    let before_apply = get_record(
        app,
        &format!("/v1/records/registration-requests/{request_id}?accessProfile=operator"),
        operator.clone(),
    )
    .await;
    let apply = action(&before_apply.body, "apply_request", None);
    send_action(
        app,
        &apply,
        key,
        operator,
        json!({
            "proposalVersion": apply.proposal_version,
            "effectDigest": apply.effect_digest
        }),
    )
    .await
}

async fn create_record(
    app: &axum::Router,
    uri: &str,
    claims: VerifiedRequestClaims,
    key: &str,
    data: Value,
) -> CreatedRecord {
    let response = response_parts(
        send(
            app,
            Method::POST,
            uri,
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", key),
            ],
            serde_json::to_vec(&json!({ "data": data })).expect("create body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::CREATED,
        "create {uri} failed with body {}",
        response.body
    );
    let id = response.body["id"]
        .as_str()
        .expect("created response includes id")
        .to_owned();
    assert!(Uuid::parse_str(&id).is_ok_and(|uuid| uuid.to_string() == id));
    assert_eq!(response.body["revision"], 1);
    assert!(response.etag.starts_with("\"rs-"));
    CreatedRecord {
        id,
        etag: response.etag,
    }
}

async fn get_record(app: &axum::Router, uri: &str, claims: VerifiedRequestClaims) -> ResponseParts {
    let response =
        response_parts(send(app, Method::GET, uri, Some(claims), &[], Vec::new()).await).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "GET {uri} failed with body {}",
        response.body
    );
    response
}

async fn action_response(
    app: &axum::Router,
    href: &str,
    key: &str,
    if_match: &str,
    claims: VerifiedRequestClaims,
    body: Value,
) -> Value {
    let response = response_parts(
        send(
            app,
            Method::POST,
            href,
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", key),
                ("if-match", if_match),
            ],
            serde_json::to_vec(&body).expect("action body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "action {href} failed with body {}",
        response.body
    );
    response.body
}

#[derive(Debug)]
struct RequestAction {
    href: String,
    if_match: String,
    proposal_version: Option<u64>,
    effect_digest: Option<String>,
    review: Value,
}

fn action(body: &Value, operation: &str, stage: Option<&str>) -> RequestAction {
    let actions = body["request"]["actions"]
        .as_array()
        .expect("request read exposes action links");
    let action = actions
        .iter()
        .find(|action| {
            action["operation"] == operation
                && stage.map_or(action.get("stage").is_none(), |stage| {
                    action["stage"] == stage
                })
        })
        .unwrap_or_else(|| panic!("missing {operation} action in {actions:?}"));
    RequestAction {
        href: action["href"].as_str().expect("action has href").to_owned(),
        if_match: action["ifMatch"]
            .as_str()
            .expect("action has precondition")
            .to_owned(),
        proposal_version: action["proposalVersion"].as_u64(),
        effect_digest: action["effectDigest"].as_str().map(str::to_owned),
        review: action.get("review").cloned().unwrap_or(Value::Null),
    }
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .expect("request builds");
    for (name, value) in headers {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("test header name"),
            HeaderValue::from_str(value).expect("test header value"),
        );
    }
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router returns response")
}

struct ResponseParts {
    status: StatusCode,
    body: Value,
    etag: String,
}

async fn response_parts(response: axum::response::Response) -> ResponseParts {
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body is bounded")
        .to_vec();
    ResponseParts {
        status,
        body: normalize_record_response(
            serde_json::from_slice(&bytes).expect("response body is JSON"),
        ),
        etag: headers
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
    }
}

fn normalize_record_response(mut value: Value) -> Value {
    let Some(object) = value.as_object_mut() else {
        return value;
    };
    if object.contains_key("meta")
        && object
            .get("data")
            .is_some_and(|data| data.get("recordIdentifier").is_some())
    {
        assert_record_meta(object.remove("meta").expect("record response has meta"));
        return normalize_record_member(object.remove("data").expect("record response has data"));
    }
    if object.contains_key("meta") && object.contains_key("items") {
        assert_record_meta(object.remove("meta").expect("record collection has meta"));
        let items = object
            .get_mut("items")
            .and_then(Value::as_array_mut)
            .expect("record collection has items");
        for item in items {
            *item = normalize_record_member(item.take());
        }
    }
    value
}

fn normalize_record_member(value: Value) -> Value {
    let mut member = value
        .as_object()
        .cloned()
        .expect("record member is an object");
    let identifier = member
        .remove("recordIdentifier")
        .and_then(|value| value.as_str().map(str::to_owned))
        .expect("record member has recordIdentifier");
    let revision = member
        .remove("revisionIdentifier")
        .and_then(|value| value.as_str().and_then(|value| value.parse::<u64>().ok()))
        .expect("record member has numeric revisionIdentifier");
    let domain_data = member
        .remove("domainData")
        .filter(Value::is_object)
        .expect("record member has domainData");
    if let Some(operation) = member.remove("operationIdentifier") {
        member.insert("operationId".to_owned(), operation);
    }
    let mut legacy = serde_json::Map::from_iter([
        ("id".to_owned(), Value::String(identifier)),
        ("revision".to_owned(), json!(revision)),
        ("data".to_owned(), domain_data),
    ]);
    legacy.extend(member);
    Value::Object(legacy)
}

fn assert_record_meta(meta: Value) {
    let meta = meta.as_object().expect("record meta is an object");
    assert_eq!(meta.len(), 3, "record meta is closed");
    for name in [
        "registryIdentifier",
        "datasetIdentifier",
        "entityTypeIdentifier",
    ] {
        assert!(
            meta.get(name)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty()),
            "record meta contains {name}"
        );
    }
}

async fn assert_served_action_openapi_refs(
    app: &axum::Router,
    reviewer: VerifiedRequestClaims,
    applier: VerifiedRequestClaims,
) {
    let reviewer_openapi = response_parts(
        send(
            app,
            Method::GET,
            "/openapi.json?accessProfile=reviewer",
            Some(reviewer),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(reviewer_openapi.status, StatusCode::OK);
    assert_action_input_component(
        &reviewer_openapi.body,
        "/v1/records/correction-requests/{record_id}/actions/stages/review/approve",
        "approve_request",
    );

    let applier_openapi = response_parts(
        send(
            app,
            Method::GET,
            "/openapi.json?accessProfile=applier",
            Some(applier),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(applier_openapi.status, StatusCode::OK);
    assert_action_input_component(
        &applier_openapi.body,
        "/v1/records/correction-requests/{record_id}/actions/apply",
        "apply_request",
    );
}

fn assert_action_input_component(openapi: &Value, path: &str, operation: &str) {
    let action = &openapi["paths"][path]["post"];
    assert_eq!(action["x-registry-requestAction"]["operation"], operation);
    let schema_ref = action["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        .as_str()
        .unwrap_or_else(|| panic!("{operation} requestBody must use a local schema ref"));
    let component = schema_ref
        .strip_prefix("#/components/schemas/")
        .unwrap_or_else(|| panic!("{operation} requestBody ref must be local: {schema_ref}"));
    assert_eq!(
        action["x-registry-requestAction"]["inputSchema"], component,
        "action metadata must name the served input component"
    );
    let schema = &openapi["components"]["schemas"][component];
    assert!(
        schema.is_object(),
        "{operation} input component must resolve"
    );
    assert_eq!(schema["type"], "object");
    assert_eq!(
        schema["required"],
        json!(["proposalVersion", "effectDigest"])
    );
    let properties = schema["properties"]
        .as_object()
        .unwrap_or_else(|| panic!("{operation} input component has properties"));
    assert_eq!(
        properties.keys().map(String::as_str).collect::<Vec<_>>(),
        ["effectDigest", "proposalVersion"]
    );
    assert_eq!(properties["proposalVersion"]["type"], "integer");
    assert_eq!(properties["effectDigest"]["type"], "string");
}

async fn revision_items(
    app: &axum::Router,
    uri: &str,
    claims: VerifiedRequestClaims,
) -> Vec<Value> {
    let response = get_record(app, uri, claims).await;
    response.body["items"]
        .as_array()
        .expect("revision list returns items")
        .clone()
}

fn assert_revision_operations_include(items: &[Value], expected: &[&str]) {
    let operations = items
        .iter()
        .map(|item| item["operationId"].as_str().expect("operation id"))
        .collect::<Vec<_>>();
    for operation in expected {
        assert!(
            operations.iter().any(|candidate| candidate == operation),
            "missing revision operation {operation} in {operations:?}"
        );
    }
}

async fn body_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body is bounded"),
    )
    .expect("response body is JSON")
}

fn claims(profile: &str, principal: &str, purpose: Option<&str>) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        BTreeSet::new(),
        purpose.map(str::to_owned),
        BTreeMap::from([(
            "tenant_claim".to_owned(),
            VerifiedClaimValue::direct_string(TENANT).expect("tenant claim is a direct string"),
        )]),
    )
    .unwrap_or_else(|_| panic!("{profile} claims are verified"))
}

async fn application_result_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_request_results",
            &[],
        )
        .await
        .expect("administrator can inspect request result rows")
        .get(0)
}

async fn target_revision(database: &TestDatabase, entity: &str, record_id: &str) -> i64 {
    let record_id = Uuid::parse_str(record_id).expect("record id parses");
    database
        .admin
        .query_one(
            "SELECT target_revision
             FROM registry_internal.registry_request_results
             WHERE target_entity_id = $1 AND target_record_id = $2",
            &[&entity, &record_id],
        )
        .await
        .expect("request result row exists")
        .get(0)
}

async fn idempotency_result_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_idempotency",
            &[],
        )
        .await
        .expect("administrator can inspect idempotency rows")
        .get(0)
}

#[derive(Debug, Eq, PartialEq)]
struct HistoryCommitCounts {
    commits: i64,
    members: i64,
}

async fn history_commit_counts(database: &TestDatabase) -> HistoryCommitCounts {
    let row = database
        .admin
        .query_one(
            "SELECT
                 (SELECT count(*) FROM registry_internal.registry_revision_commits),
                 (SELECT count(*) FROM registry_internal.registry_revision_commit_members)",
            &[],
        )
        .await
        .expect("administrator can inspect history commits");
    HistoryCommitCounts {
        commits: row.get(0),
        members: row.get(1),
    }
}

struct HistoryCommitMember {
    entity_id: String,
    record_id: Uuid,
    record_revision: i64,
}

async fn history_members_for_snapshot(
    database: &TestDatabase,
    snapshot: &Value,
) -> Vec<HistoryCommitMember> {
    let snapshot_id = snapshot_uuid(snapshot);
    database
        .admin
        .query(
            "SELECT member.entity_id, member.record_id, member.record_revision
               FROM registry_internal.registry_revision_commits AS revision_commit
               JOIN registry_internal.registry_revision_commit_members AS member
                 ON member.commit_position = revision_commit.commit_position
              WHERE revision_commit.snapshot_reference = $1
              ORDER BY member.member_index",
            &[&snapshot_id],
        )
        .await
        .expect("administrator can inspect history commit members")
        .into_iter()
        .map(|row| HistoryCommitMember {
            entity_id: row.get(0),
            record_id: row.get(1),
            record_revision: row.get(2),
        })
        .collect()
}

fn assert_snapshot_reference(value: &Value) {
    let snapshot = value.as_str().expect("response carries snapshot reference");
    assert_eq!(snapshot.len(), 40);
    assert!(snapshot.starts_with("rs1_"));
    Uuid::parse_str(&snapshot[4..]).expect("snapshot suffix is a UUID");
}

fn snapshot_uuid(value: &Value) -> Uuid {
    let snapshot = value.as_str().expect("response carries snapshot reference");
    assert_eq!(snapshot.len(), 40);
    assert!(snapshot.starts_with("rs1_"));
    Uuid::parse_str(&snapshot[4..]).expect("snapshot suffix is a UUID")
}

fn tampered_if_match(value: &str) -> String {
    let mut bytes = value.as_bytes().to_vec();
    let index = bytes
        .iter()
        .rposition(|byte| byte.is_ascii_hexdigit())
        .expect("action etag contains a hex digit");
    bytes[index] = match bytes[index] {
        b'a' => b'b',
        b'A' => b'B',
        b'0' => b'1',
        _ => b'0',
    };
    String::from_utf8(bytes).expect("tampered etag stays ASCII")
}

async fn proposal_count(database: &TestDatabase, entity: &str, record_id: &str) -> i64 {
    let record_id = Uuid::parse_str(record_id).expect("record id parses");
    database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_request_proposals
             WHERE request_entity_id = $1 AND request_id = $2",
            &[&entity, &record_id],
        )
        .await
        .expect("administrator can inspect request proposals")
        .get(0)
}

async fn install_registry(
    database: &TestDatabase,
    registry: &Arc<registry_server::CompiledRegistry>,
    package_id: &str,
    temporal: bool,
) -> registry_server::postgres::ExpectedRegistryIdentity {
    let (migration, migration_task) = database.connect_migration().await;
    if temporal {
        database
            .admin
            .batch_execute("CREATE EXTENSION IF NOT EXISTS btree_gist")
            .await
            .expect("administrator installs temporal exclusion prerequisite");
    }
    install_compiled_schema(&migration, registry, &database.runtime_role)
        .await
        .expect("compiled change-request schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        registry,
        RegistryStateTestIdentity {
            package_id,
            environment: "local",
            instance_id: "change-request-test-instance",
            database_id: "change-request-test-database",
            package_revision: PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("active package identity initializes");
    drop(migration);
    migration_task.abort();
    identity
}

async fn install_serialization_retry_trigger(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    entity_id: &str,
    max_failures: i64,
) {
    let table = quote_sql_identifier(
        &registry
            .entities()
            .get(entity_id)
            .unwrap_or_else(|| panic!("missing {entity_id} entity"))
            .physical_table,
    );
    database
        .admin
        .batch_execute(&format!(
            r#"
            CREATE TABLE registry_internal.cr08_retry_control (
              singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
              max_failures bigint NOT NULL CHECK (max_failures >= 0)
            );
            INSERT INTO registry_internal.cr08_retry_control (singleton, max_failures)
            VALUES (true, {max_failures});
            CREATE SEQUENCE registry_internal.cr08_retry_attempts;
            CREATE OR REPLACE FUNCTION registry_internal.cr08_raise_serialization_for_target()
            RETURNS trigger
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, registry_internal
            AS $$
            DECLARE
              attempt bigint;
              configured_failures bigint;
            BEGIN
              SELECT max_failures INTO configured_failures
              FROM registry_internal.cr08_retry_control
              WHERE singleton;
              attempt := nextval('registry_internal.cr08_retry_attempts'::regclass);
              IF attempt <= configured_failures THEN
                RAISE EXCEPTION 'cr08 forced serialization failure attempt %', attempt
                  USING ERRCODE = '40001';
              END IF;
              RETURN NEW;
            END;
            $$;
            CREATE TRIGGER cr08_raise_serialization_for_target
            BEFORE INSERT ON registry_data.{table}
            FOR EACH ROW EXECUTE FUNCTION registry_internal.cr08_raise_serialization_for_target();
            "#
        ))
        .await
        .expect("test installs serialization retry trigger");
}

async fn set_serialization_retry_failures(database: &TestDatabase, max_failures: i64) {
    database
        .admin
        .execute(
            "UPDATE registry_internal.cr08_retry_control SET max_failures = $1 WHERE singleton",
            &[&max_failures],
        )
        .await
        .expect("test updates serialization retry trigger control");
    database
        .admin
        .batch_execute("ALTER SEQUENCE registry_internal.cr08_retry_attempts RESTART WITH 1")
        .await
        .expect("test resets serialization retry attempt sequence");
}

async fn serialization_retry_attempts(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT last_value FROM registry_internal.cr08_retry_attempts",
            &[],
        )
        .await
        .expect("administrator can inspect serialization retry attempts")
        .get(0)
}

async fn install_blocked_sql_trigger(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    entity_id: &str,
) {
    let table = quote_sql_identifier(
        &registry
            .entities()
            .get(entity_id)
            .unwrap_or_else(|| panic!("missing {entity_id} entity"))
            .physical_table,
    );
    database
        .admin
        .batch_execute(&format!(
            r#"
            CREATE OR REPLACE FUNCTION registry_internal.cr08_block_target_write()
            RETURNS trigger
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, registry_internal
            AS $$
            BEGIN
              PERFORM pg_catalog.pg_sleep(35);
              RETURN NEW;
            END;
            $$;
            CREATE TRIGGER cr08_block_target_write
            BEFORE INSERT ON registry_data.{table}
            FOR EACH ROW EXECUTE FUNCTION registry_internal.cr08_block_target_write();
            "#
        ))
        .await
        .expect("test installs blocked SQL trigger");
}

async fn install_delayed_sql_trigger(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    entity_id: &str,
    seconds: i32,
) {
    let table = quote_sql_identifier(
        &registry
            .entities()
            .get(entity_id)
            .unwrap_or_else(|| panic!("missing {entity_id} entity"))
            .physical_table,
    );
    database
        .admin
        .batch_execute(&format!(
            r#"
            CREATE OR REPLACE FUNCTION registry_internal.cr08_delay_target_write()
            RETURNS trigger
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, registry_internal
            AS $$
            BEGIN
              PERFORM pg_catalog.pg_sleep({seconds});
              RETURN NEW;
            END;
            $$;
            CREATE TRIGGER cr08_delay_target_write
            BEFORE INSERT ON registry_data.{table}
            FOR EACH ROW EXECUTE FUNCTION registry_internal.cr08_delay_target_write();
            "#
        ))
        .await
        .expect("test installs delayed SQL trigger");
}

async fn assert_blocked_sql_canceled(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    entity_id: &str,
) {
    let table = quote_sql_identifier(
        &registry
            .entities()
            .get(entity_id)
            .unwrap_or_else(|| panic!("missing {entity_id} entity"))
            .physical_table,
    );
    let pattern = format!("%registry_data.{table}%");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let count: i64 = database
            .admin
            .query_one(
                "SELECT count(*)
                 FROM pg_catalog.pg_stat_activity
                 WHERE datname = current_database()
                   AND pid <> pg_catalog.pg_backend_pid()
                   AND state = 'active'
                   AND query LIKE $1",
                &[&pattern],
            )
            .await
            .expect("administrator can inspect active queries")
            .get(0);
        if count == 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "blocked SQL remained active after timeout cancellation"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn quote_sql_identifier(value: &str) -> String {
    assert!(
        !value.contains('\0'),
        "SQL identifiers cannot contain NUL bytes"
    );
    format!("\"{}\"", value.replace('"', "\"\""))
}

// Test helper keeps the complete HTTP action tuple visible at each call site.
#[allow(clippy::too_many_arguments)]
async fn run_action(
    app: &axum::Router,
    record_id: &str,
    route: &str,
    profile: &str,
    claims: VerifiedRequestClaims,
    key: &str,
    operation: &str,
    stage: Option<&str>,
    body: impl FnOnce(&RequestAction) -> Value,
) -> Value {
    let before = get_record(
        app,
        &format!("/v1/records/{route}/{record_id}?accessProfile={profile}"),
        claims.clone(),
    )
    .await;
    let action = action(&before.body, operation, stage);
    action_response(
        app,
        &action.href,
        key,
        &action.if_match,
        claims,
        body(&action),
    )
    .await
}

async fn send_action(
    app: &axum::Router,
    action: &RequestAction,
    key: &str,
    claims: VerifiedRequestClaims,
    body: Value,
) -> ResponseParts {
    response_parts(
        send(
            app,
            Method::POST,
            &action.href,
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", key),
                ("if-match", &action.if_match),
            ],
            serde_json::to_vec(&body).expect("action body serializes"),
        )
        .await,
    )
    .await
}

async fn assert_not_found(app: &axum::Router, uri: &str, claims: VerifiedRequestClaims) {
    let response =
        response_parts(send(app, Method::GET, uri, Some(claims), &[], Vec::new()).await).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND, "{uri}");
    assert_eq!(response.body["code"], "resource.not_found");
}

fn target_record_id(targets: &[Value], entity: &str) -> String {
    targets
        .iter()
        .find(|target| target["entityId"] == entity)
        .and_then(|target| target["recordId"].as_str())
        .unwrap_or_else(|| panic!("missing {entity} target in {targets:?}"))
        .to_owned()
}

fn target_after(targets: &[Value], entity: &str) -> Value {
    targets
        .iter()
        .find(|target| target["entityId"] == entity)
        .map(|target| target["after"].clone())
        .unwrap_or_else(|| panic!("missing {entity} target in {targets:?}"))
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn bounded_snapshot_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"bounded-snapshot-change-request","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[
            {
              "id":"asset-site","primaryDataset":"test-dataset","route":"sites","mutationMode":"create_only","classification":"internal",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"name","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}
              ]
            },
            {
              "id":"asset-placement","primaryDataset":"test-dataset","route":"placements","mutationMode":"mutable","classification":"internal",
              "changeControl":{"requiredFor":["patch"]},
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"site","type":"reference","target":"asset-site","required":true,"classification":"internal"},
                {"id":"note","type":"text","maxLength":2000000,"classification":"internal"}
              ]
            },
            {
              "id":"correction-request","primaryDataset":"test-dataset","route":"correction-requests","mutationMode":"mutable","classification":"internal",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"placement","type":"reference","target":"asset-placement","required":true,"classification":"internal"},
                {"id":"proposed-site","type":"reference","target":"asset-site","required":true,"classification":"internal"},
                {"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"internal"}
              ],
              "changeRequest":{
                "effects":[{
                  "target":{"fromField":"placement"},
                  "operation":"patch",
                  "set":{"site":{"fromField":"proposed-site"}}
                }],
                "review":{"stages":[{"id":"review","approvals":1,"excludeSubmitter":true}]}
              }
            }
          ],
          "accessProfiles":[
            {
              "id":"steward","default":true,"principalClaim":"registry_principal",
              "grants":[{
                "entity":"asset-site",
                "operations":["create","get","list"],
                "readableFields":["tenant","name"],
                "writableFields":["tenant","name"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
              },{
                "entity":"asset-placement",
                "operations":["create","get","list"],
                "readableFields":["tenant","site","note"],
                "writableFields":["tenant","site","note"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "requestPresence":[{"requestType":"correction-request","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
              }]
            },
            {
              "id":"submitter","default":true,"principalClaim":"registry_principal",
              "grants":[{
                "entity":"correction-request",
                "operations":["create","get","list","revisions","patch","submit_request","revise_request","cancel_request"],
                "revisionAccess":true,
                "readableFields":["tenant","placement","proposed-site","reason"],
                "writableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
              }]
            },
            {
              "id":"reviewer","principalClaim":"registry_principal","requiredPurposes":["review"],
              "grants":[{
                "entity":"correction-request",
                "operations":["get","list","approve_request","reject_request","request_revision"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "reviewStages":[{"stage":"review","targets":[{
                  "entity":"asset-placement",
                  "readableFields":["site"],
                  "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
                }]}]
              }]
            },
            {
              "id":"applier","principalClaim":"registry_principal","requiredPurposes":["apply"],
              "grants":[{
                "entity":"correction-request",
                "operations":["get","apply_request"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "applyTargets":[{"entity":"asset-placement","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
              }]
            }
          ]
        }"#,
    )
    .expect("bounded snapshot change-request fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("bounded snapshot change-request fixture compiles")
}

fn long_logical_id_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"long-logical-change-request","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[
            {
              "id":"asset-site","primaryDataset":"test-dataset","route":"sites","mutationMode":"create_only","classification":"internal",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"name","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}
              ]
            },
            {
              "id":"asset-placement","primaryDataset":"test-dataset","route":"placements","mutationMode":"mutable","classification":"internal",
              "changeControl":{"requiredFor":["patch"]},
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"site","type":"reference","target":"asset-site","required":true,"classification":"internal"}
              ]
            },
            {
              "id":"placement-correction-request","primaryDataset":"test-dataset","route":"placement-correction-requests","mutationMode":"mutable","classification":"internal",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"placement","type":"reference","target":"asset-placement","required":true,"classification":"internal"},
                {"id":"proposed-site","type":"reference","target":"asset-site","required":true,"classification":"internal"},
                {"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"internal"}
              ],
              "changeRequest":{
                "effects":[{
                  "target":{"fromField":"placement"},
                  "operation":"patch",
                  "set":{"site":{"fromField":"proposed-site"}}
                }],
                "review":{"stages":[{"id":"review","approvals":1,"excludeSubmitter":true}]}
              }
            }
          ],
          "accessProfiles":[{
            "id":"reviewer","default":true,"principalClaim":"registry_principal","grants":[{
              "entity":"placement-correction-request",
              "operations":["get","list","submit_request","approve_request","apply_request"],
              "readableFields":["tenant","placement","proposed-site","reason"],
              "reviewStages":[{"stage":"review","targets":[{"entity":"asset-placement","readableFields":["site"]}]}],
              "applyTargets":[{"entity":"asset-placement"}]
            }]
          }]
        }"#,
    )
    .expect("long logical change-request fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("long logical change-request fixture compiles")
}

fn registration_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"registration-change-request","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[
            {
              "id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable","classification":"internal",
              "changeControl":{"requiredFor":["create"]},
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"display-name","type":"string","maxLength":200,"required":true,"classification":"internal"}
              ]
            },
            {
              "id":"membership","primaryDataset":"test-dataset","route":"memberships","mutationMode":"mutable","classification":"internal",
              "changeControl":{"requiredFor":["create"]},
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"person","type":"reference","target":"person","required":true,"classification":"internal"},
                {"id":"household","type":"reference","target":"household","required":true,"classification":"internal"}
              ]
            },
            {
              "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable","classification":"internal",
              "changeControl":{"requiredFor":["patch"]},
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"label","type":"string","maxLength":200,"required":true,"classification":"internal"},
                {"id":"contact-person","type":"reference","target":"person","classification":"internal"}
              ]
            },
            {
              "id":"registration-request","primaryDataset":"test-dataset","route":"registration-requests","mutationMode":"mutable","classification":"internal",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"household","type":"reference","target":"household","required":true,"classification":"internal"},
                {"id":"name","type":"string","maxLength":200,"required":true,"classification":"internal"}
              ],
              "changeRequest":{
                "effects":[
                  {"id":"person","target":{"entity":"person"},"operation":"create","set":{"tenant":{"fromField":"tenant"},"display-name":{"fromField":"name"}}},
                  {"id":"membership","target":{"entity":"membership"},"operation":"create","set":{"tenant":{"fromField":"tenant"},"person":{"fromEffect":"person"},"household":{"fromField":"household"}}},
                  {"target":{"fromField":"household"},"operation":"patch","set":{"contact-person":{"fromEffect":"person"}}}
                ],
                "review":{"stages":[{"id":"review","approvals":1}]}
              }
            }
          ],
          "accessProfiles":[
            {
              "id":"steward","default":true,"principalClaim":"registry_principal",
              "grants":[{
                "entity":"household",
                "operations":["create"],
                "readableFields":["tenant","label","contact-person"],
                "writableFields":["tenant","label","contact-person"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "requestPresence":[{"requestType":"registration-request","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
              }]
            },
            {
              "id":"operator","default":true,"principalClaim":"registry_principal",
              "grants":[
                {
                  "entity":"registration-request",
                  "operations":["create","get","list","revisions","patch","submit_request","approve_request","reject_request","request_revision","revise_request","cancel_request","apply_request"],
                  "revisionAccess":true,
                  "readableFields":["tenant","household","name"],
                  "writableFields":["tenant","household","name"],
                  "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                  "reviewStages":[{"stage":"review","targets":[
                    {"entity":"person","readableFields":["tenant","display-name"],"rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]},
                    {"entity":"membership","readableFields":["tenant","person","household"],"rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]},
                    {"entity":"household","readableFields":["contact-person"],"rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}
                  ]}],
                  "applyTargets":[
                    {"entity":"person","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]},
                    {"entity":"membership","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]},
                    {"entity":"household","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}
                  ]
                },
                {
                  "entity":"person",
                  "operations":["get","list","revisions"],
                  "revisionAccess":true,
                  "readableFields":["tenant","display-name"],
                  "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
                },
                {
                  "entity":"membership",
                  "operations":["get","list","revisions"],
                  "revisionAccess":true,
                  "readableFields":["tenant","person","household"],
                  "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
                },
                {
                  "entity":"household",
                  "operations":["get","list","revisions"],
                  "revisionAccess":true,
                  "readableFields":["tenant","label","contact-person"],
                  "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                  "requestPresence":[{"requestType":"registration-request","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
                }
              ]
            }
          ]
        }"#,
    )
    .expect("registration change-request fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("registration change-request fixture compiles")
}

fn two_stage_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"two-stage-change-request","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[
            {
              "id":"asset-site","primaryDataset":"test-dataset","route":"sites","mutationMode":"create_only","classification":"internal",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"name","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}
              ]
            },
            {
              "id":"asset-placement","primaryDataset":"test-dataset","route":"placements","mutationMode":"mutable","classification":"internal",
              "changeControl":{"requiredFor":["patch"]},
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"site","type":"reference","target":"asset-site","required":true,"classification":"internal"}
              ]
            },
            {
              "id":"correction-request","primaryDataset":"test-dataset","route":"correction-requests","mutationMode":"mutable","classification":"internal",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"placement","type":"reference","target":"asset-placement","required":true,"classification":"internal"},
                {"id":"proposed-site","type":"reference","target":"asset-site","required":true,"classification":"internal"},
                {"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"internal"}
              ],
              "changeRequest":{
                "effects":[{
                  "target":{"fromField":"placement"},
                  "operation":"patch",
                  "set":{"site":{"fromField":"proposed-site"}}
                }],
                "review":{"stages":[
                  {"id":"review","approvals":1,"excludeSubmitter":true},
                  {"id":"final","approvals":1,"excludeSubmitter":true}
                ]}
              }
            }
          ],
          "accessProfiles":[
            {
              "id":"steward","default":true,"principalClaim":"registry_principal",
              "grants":[{
                "entity":"asset-site",
                "operations":["create","get","list"],
                "readableFields":["tenant","name"],
                "writableFields":["tenant","name"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
              },{
                "entity":"asset-placement",
                "operations":["create","get","list"],
                "readableFields":["tenant","site"],
                "writableFields":["tenant","site"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "requestPresence":[{"requestType":"correction-request","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
              }]
            },
            {
              "id":"submitter","principalClaim":"registry_principal",
              "grants":[{
                "entity":"correction-request",
                "operations":["create","get","list","revisions","patch","submit_request","revise_request","cancel_request"],
                "revisionAccess":true,
                "readableFields":["tenant","placement","proposed-site","reason"],
                "writableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
              }]
            },
            {
              "id":"reviewer","default":true,"principalClaim":"registry_principal","requiredPurposes":["review"],
              "grants":[{
                "entity":"correction-request",
                "operations":["get","list","approve_request","reject_request","request_revision"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "reviewStages":[{"stage":"review","targets":[{
                  "entity":"asset-placement",
                  "readableFields":["site"],
                  "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
                }]}]
              }]
            },
            {
              "id":"final-reviewer","principalClaim":"registry_principal","requiredPurposes":["final"],
              "grants":[{
                "entity":"correction-request",
                "operations":["get","list","approve_request","reject_request","request_revision"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "reviewStages":[{"stage":"final","targets":[{
                  "entity":"asset-placement",
                  "readableFields":["site"],
                  "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
                }]}]
              }]
            },
            {
              "id":"applier","principalClaim":"registry_principal","requiredPurposes":["apply"],
              "grants":[{
                "entity":"correction-request",
                "operations":["get","apply_request"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "applyTargets":[{"entity":"asset-placement","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
              }]
            }
          ]
        }"#,
    )
    .expect("two-stage change-request fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("two-stage change-request fixture compiles")
}

fn compiled_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"change-request-http-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[
            {
              "id":"asset-site","primaryDataset":"test-dataset","route":"sites","mutationMode":"create_only","classification":"internal",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"name","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}
              ]
            },
            {
              "id":"asset-placement","primaryDataset":"test-dataset","route":"placements","mutationMode":"mutable","classification":"internal",
              "changeControl":{"requiredFor":["patch"]},
              "temporal":{"startField":"valid-from","endField":"valid-to","scopeFields":["site"]},
              "constraints":[{
                "kind":"temporal-non-overlap",
                "scopeFields":["site"],
                "startField":"valid-from",
                "endField":"valid-to"
              }],
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"site","type":"reference","target":"asset-site","required":true,"classification":"internal"},
                {"id":"valid-from","type":"date","required":true,"classification":"internal"},
                {"id":"valid-to","type":"date","classification":"internal"}
              ]
            },
            {
              "id":"correction-request","primaryDataset":"test-dataset","route":"correction-requests","mutationMode":"mutable","classification":"internal",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"placement","type":"reference","target":"asset-placement","required":true,"classification":"internal"},
                {"id":"proposed-site","type":"reference","target":"asset-site","required":true,"classification":"internal"},
                {"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"internal"}
              ],
              "changeRequest":{
                "effects":[{
                  "target":{"fromField":"placement"},
                  "operation":"patch",
                  "set":{"site":{"fromField":"proposed-site"}}
                }],
                "review":{"stages":[{"id":"review","approvals":1,"excludeSubmitter":true}]}
              }
            }
          ],
          "accessProfiles":[
            {
              "id":"steward","default":true,"principalClaim":"registry_principal",
              "grants":[{
                "entity":"asset-site",
                "operations":["create","get","list"],
                "readableFields":["tenant","name"],
                "writableFields":["tenant","name"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
              },{
                "entity":"asset-placement",
                "operations":["create","get","list","revisions"],
                "revisionAccess":true,
                "readableFields":["tenant","site","valid-from","valid-to"],
                "writableFields":["tenant","site","valid-from","valid-to"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "requestPresence":[{"requestType":"correction-request","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
              }]
            },
            {
              "id":"submitter","default":true,"principalClaim":"registry_principal",
              "grants":[{
                "entity":"correction-request",
                "operations":["create","get","list","revisions","patch","submit_request","revise_request","cancel_request"],
                "revisionAccess":true,
                "readableFields":["tenant","placement","proposed-site","reason"],
                "writableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
              }]
            },
            {
              "id":"reviewer","principalClaim":"registry_principal","requiredPurposes":["review"],
              "grants":[{
                "entity":"correction-request",
                "operations":["get","list","approve_request","reject_request","request_revision"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "reviewStages":[{
                  "stage":"review",
                  "targets":[{
                    "entity":"asset-placement",
                    "readableFields":["site"],
                    "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
                  }]
                }]
              }]
            },
            {
              "id":"applier","principalClaim":"registry_principal","requiredPurposes":["apply"],
              "grants":[{
                "entity":"correction-request",
                "operations":["get","apply_request"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "applyTargets":[{
                  "entity":"asset-placement",
                  "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
                }]
              }]
            }
          ]
        }"#,
    )
    .expect("change-request HTTP fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("change-request HTTP fixture compiles")
}

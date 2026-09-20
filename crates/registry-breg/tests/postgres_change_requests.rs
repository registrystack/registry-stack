// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/action_evidence_provider.rs"]
#[allow(dead_code)]
mod action_evidence_provider;
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::extract::{Path, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use postgres_harness::TestDatabase;
use registry_breg as breg;
use registry_breg::action_evidence::ActionEvidenceEvaluator;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::compiler::{compile_project, compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_json, ModuleAssetSource};
use registry_breg::cursor::CursorCodec;
use registry_breg::mutation::MutationFaultPoint;
use registry_breg::postgres::{
    begin_record_transaction, initialize_compiled_registry_state_for_test, install_compiled_schema,
    ClaimContext, PostgresRecordMutationService, PostgresRecordReadService,
    PostgresRevisionReadService, RegistryLockKey, RegistryStateTestIdentity, RowBoundaryContext,
};
use registry_breg::review_store::{
    run_review_application_once_for_test, ReviewAuthorityClient, ReviewAuthorityRegistry,
    ReviewExecutorClient,
};
use registry_breg::startup::with_request_timeout_for_test;
use registry_breg_client::{
    BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey, BRegLifecycleOperation,
    BRegPatchRequest, BRegPreparedLifecycle, BRegRecordFormat, BRegRecordOptions,
    BRegRequestMetadata, BaseRegistryClient, BaseRegistryClientConfig, StaticToken,
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use action_evidence_provider::EvidenceProvider;

const PACKAGE_ID: &str = "change-request-http-registry";
const INSTANCE_ID: &str = "change-request-http-instance";
const DATABASE_ID: &str = "change-request-http-database";
const PACKAGE_REVISION: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TENANT: &str = "tenant-a";
const SUBMITTER: &str = "submitter-principal";
const OTHER_SUBMITTER: &str = "other-submitter-principal";
const REVIEWER: &str = "reviewer-principal";
const APPLIER: &str = "applier-principal";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reviewed_application_guard_rejects_changed_target_without_partial_effects() {
    let database = TestDatabase::create(8).await;
    let mut source = serde_json::to_value(two_stage_project()).unwrap();
    source["entities"][2]["changeRequest"]["application"] = json!({
        "preconditions":{"targets":[{
            "id":"placement-guard", "entity":"asset-placement", "fromField":"placement",
            "requires":[{"field":"tenant", "equalsFromRequestField":"tenant"}]
        }]}
    });
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let registry = Arc::new(compile_project(&project, &[], CompileProfile::Authoring).unwrap());
    let identity = install_registry(&database, &registry, "guarded-change-request", false).await;
    let app = change_request_router(
        &database,
        registry.clone(),
        identity,
        "guarded-change-request",
        None,
    );
    let (request, digest) = submit_two_stage_correction(&app).await;
    let placement = &registry.entities()["asset-placement"];
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{} SET record_revision = record_revision + 1 WHERE record_id = $1",
                quote_sql_identifier(&placement.physical_table)
            ),
            &[&database
                .admin
                .query_one(
                    "SELECT target_record_id FROM registry_internal.registry_request_targets WHERE request_entity_id='correction-request' AND request_id=$1 AND proposal_version=1 AND target_entity_id='asset-placement'",
                    &[&Uuid::parse_str(&request.id).unwrap()],
                )
                .await
                .unwrap()
                .get::<_, Uuid>(0)],
        )
        .await
        .unwrap();
    let applier = claims("applier", APPLIER, Some("apply"));
    let before = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=applier",
            request.id
        ),
        applier.clone(),
    )
    .await;
    let apply = action(&before.body, "apply_request", None);
    let response = send_action(
        &app,
        &apply,
        "guard-apply",
        applier,
        json!({"proposalVersion":1,"effectDigest":digest}),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        response.body
    );
    assert_eq!(
        database
            .admin
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_request_applications",
                &[],
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cached_review_result_cannot_authorize_fresh_apply_but_committed_receipt_recovers_offline()
{
    let (endpoint, authority_state, authority_server) = serve_review_result_authority().await;
    let reviews = review_authority_registry(endpoint);
    let database = TestDatabase::create(8).await;
    let mut source = serde_json::to_value(two_stage_project()).unwrap();
    source["entities"][2]["changeRequest"]["review"] =
        json!({"authority":"casework-a","policyId":"correction-review"});
    let registry = Arc::new(
        compile_project(
            &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
            &[],
            CompileProfile::Authoring,
        )
        .unwrap(),
    );
    let identity = install_registry(&database, &registry, "fresh-review-manual", false).await;
    let (service, _) = change_request_service_with_evidence_options(
        &database,
        registry,
        identity,
        "fresh-review-manual",
        None,
        None,
        registry_breg::attachment_storage::AttachmentStorage::Database,
        None,
        registry_breg::attachment_verification::AttachmentVerification::Disabled,
        None,
        Some(reviews),
    );
    let app = router(service);
    let (request, digest) = submit_two_stage_correction(&app).await;
    let result = reconcile_cached_external_approval(&database, &request.id, false).await;
    *authority_state.result.lock().unwrap() = result;
    let applier = claims("applier", APPLIER, Some("apply"));
    let before = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=applier",
            request.id
        ),
        applier.clone(),
    )
    .await;
    let apply = action(&before.body, "apply_request", None);

    let unavailable = send_action(
        &app,
        &apply,
        "cached-review-unavailable",
        applier.clone(),
        json!({"proposalVersion":1,"effectDigest":digest}),
    )
    .await;
    assert_eq!(unavailable.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(application_result_count(&database).await, 0);
    assert_eq!(authority_state.lookups.load(Ordering::SeqCst), 1);

    authority_state.mode.store(2, Ordering::SeqCst);
    let expired = send_action(
        &app,
        &apply,
        "cached-review-expired",
        applier.clone(),
        json!({"proposalVersion":1,"effectDigest":digest}),
    )
    .await;
    assert_eq!(expired.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(application_result_count(&database).await, 0);
    assert_eq!(authority_state.lookups.load(Ordering::SeqCst), 2);

    authority_state.result.lock().unwrap()["availableUntil"] = json!("2099-09-20T00:00:00Z");
    let applied = send_action(
        &app,
        &apply,
        "fresh-review-apply",
        applier.clone(),
        json!({"proposalVersion":1,"effectDigest":digest}),
    )
    .await;
    assert_eq!(applied.status, StatusCode::OK, "{}", applied.body);
    assert_eq!(application_result_count(&database).await, 1);
    assert_eq!(authority_state.lookups.load(Ordering::SeqCst), 3);

    authority_state.mode.store(0, Ordering::SeqCst);
    let replay = send_action(
        &app,
        &apply,
        "fresh-review-apply",
        applier,
        json!({"proposalVersion":1,"effectDigest":digest}),
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK, "{}", replay.body);
    assert_eq!(replay.body, applied.body);
    assert_eq!(
        authority_state.lookups.load(Ordering::SeqCst),
        3,
        "an exact committed receipt recovers without Casework"
    );

    authority_server.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_online_review_blocks_final_automatic_attempt_until_authorized_recovery() {
    let (endpoint, authority_state, authority_server) = serve_review_result_authority().await;
    let reviews = review_authority_registry(endpoint);
    let mut database = TestDatabase::create(8).await;
    let mut source = serde_json::to_value(two_stage_project()).unwrap();
    source["entities"][2]["changeRequest"]["review"] =
        json!({"authority":"casework-a","policyId":"correction-review"});
    source["entities"][2]["changeRequest"]["onApproved"] =
        json!({"mode":"automatic","executor":"registry-automatic"});
    source["accessProfiles"][4]["permissions"][0]["readableRequestFields"] =
        json!(["reason", "review_state"]);
    let registry = Arc::new(
        compile_project(
            &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
            &[],
            CompileProfile::Authoring,
        )
        .unwrap(),
    );
    let identity = install_registry(&database, &registry, "fresh-review-automatic", false).await;
    let (service, _) = change_request_service_with_evidence_options(
        &database,
        registry,
        identity,
        "fresh-review-automatic",
        None,
        None,
        registry_breg::attachment_storage::AttachmentStorage::Database,
        None,
        registry_breg::attachment_verification::AttachmentVerification::Disabled,
        None,
        Some(reviews),
    );
    let app = router(service);
    let (request, digest) = submit_two_stage_correction(&app).await;
    let result = reconcile_cached_external_approval(&database, &request.id, true).await;
    *authority_state.result.lock().unwrap() = result;
    authority_state.mode.store(1, Ordering::SeqCst);
    let server = serve_change_request_client_http(app.clone()).await;
    let executor = ReviewExecutorClient::new(
        "registry-automatic".to_owned(),
        format!("{}/", server.base_url()).parse().unwrap(),
        registry_review_client::BearerToken::new("applier-token").unwrap(),
        "two-stage-change-request".to_owned(),
        "applier".to_owned(),
        BTreeMap::from([(
            "correction-request".to_owned(),
            "correction-requests".to_owned(),
        )]),
        Duration::from_secs(2),
    )
    .unwrap();

    assert!(
        run_review_application_once_for_test(&mut database.admin, &executor)
            .await
            .expect("final automatic attempt settles")
    );
    assert_eq!(application_result_count(&database).await, 0);
    let job = database
        .admin
        .query_one(
            "SELECT state,attempt_count,claim_token,last_error_code
               FROM registry_internal.registry_request_application_jobs
              WHERE request_id=$1",
            &[&Uuid::parse_str(&request.id).unwrap()],
        )
        .await
        .unwrap();
    assert_eq!(job.get::<_, String>(0), "blocked");
    assert_eq!(job.get::<_, i32>(1), 1_000);
    assert_eq!(job.get::<_, Option<Uuid>>(2), None);
    assert_eq!(
        job.get::<_, Option<String>>(3).as_deref(),
        Some("application-attempts-exhausted")
    );
    assert_eq!(authority_state.lookups.load(Ordering::SeqCst), 1);
    assert!(
        !run_review_application_once_for_test(&mut database.admin, &executor)
            .await
            .expect("blocked automatic job stays terminal")
    );

    let applier = claims("applier", APPLIER, Some("apply"));
    let blocked = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=applier",
            request.id
        ),
        applier.clone(),
    )
    .await;
    assert_eq!(
        blocked.body["request"]["review"]["application"]["state"],
        "blocked"
    );
    assert_eq!(
        blocked.body["request"]["review"]["recovery"]["code"],
        "application-attempts-exhausted"
    );

    authority_state.result.lock().unwrap()["availableUntil"] = json!("2099-09-20T00:00:00Z");
    authority_state.mode.store(2, Ordering::SeqCst);
    let apply = action(&blocked.body, "apply_request", None);
    let recovered = send_action(
        &app,
        &apply,
        "authorized-exhaustion-recovery",
        applier,
        json!({"proposalVersion":1,"effectDigest":digest}),
    )
    .await;
    assert_eq!(recovered.status, StatusCode::OK, "{}", recovered.body);
    let state: String = database
        .admin
        .query_one(
            "SELECT state FROM registry_internal.registry_request_application_jobs
              WHERE request_id=$1",
            &[&Uuid::parse_str(&request.id).unwrap()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(state, "applied");

    server.finish().await;
    authority_server.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reviewed_evidence_application_releases_postgres_and_replays_the_atomic_receipt() {
    let provider = EvidenceProvider::start().await;
    let database = TestDatabase::create(8).await;
    let mut source = serde_json::to_value(two_stage_project()).unwrap();
    // This guard has no mutation effect or ordinary UPDATE privilege. It must
    // still be lockable during apply without becoming writable.
    source["accessProfiles"][4]["permissions"][0]["applyTargets"]
        .as_array_mut().unwrap().push(json!({
            "entity":"asset-site", "rowBoundaries":[{"field":"tenant","claim":"guard_tenant_claim","operator":"equals"}]
        }));
    source["evidenceProviders"] = json!([{
        "id":"farmer-registry",
        "contracts":"evidence/farmer-contracts.json",
        "subjectResolution":"trusted-provider-exact-selector"
    }]);
    source["entities"][2]["changeRequest"]["application"] = json!({
        "preconditions":{"targets":[{
            "id":"site-guard", "entity":"asset-site", "fromField":"proposed-site",
            "requires":[{"field":"tenant", "equalsFromRequestField":"tenant"}]
        }],"evidence":[{
            "id":"farmer-status",
            "provider":"farmer-registry",
            "requirement":"urn:example:farmer:status-v1",
            "subjects":{"farmer":{
                "profile":"farmer-number-v1",
                "selectors":{"farmer-number":{
                    "source":"request_field", "field":"tenant"
                },"placement-site":{
                    "source":"target_field", "target":"site-guard", "field":"name"
                }}
            }},
            "requires":[{"output":"active", "equals":true}],
            "maximumObservationAgeSeconds":60
        }]}
    });
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let contracts = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../products/breg/acceptance/farmer-landholding-evidence/evidence/farmer-contracts.json",
    ))
    .unwrap();
    let mut contracts: Value = serde_json::from_slice(&contracts).unwrap();
    contracts["definitions"][0]["subjects"][0]["selector"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"type":"string", "name":"placement-site", "minimumBytes":3, "maximumBytes":77}),
        );
    let registry = Arc::new(
        compile_project_with_assets(
            &project,
            &[],
            &[ModuleAssetSource {
                module: None,
                path: "evidence/farmer-contracts.json".into(),
                bytes: serde_json::to_vec(&contracts).unwrap(),
            }],
            CompileProfile::Authoring,
        )
        .unwrap(),
    );
    let identity = install_registry(&database, &registry, "evidence-change-request", false).await;
    let evaluator = Arc::new(ActionEvidenceEvaluator::new(provider.client()));
    let (fault_service, pool) = change_request_service_with_evidence_options(
        &database,
        registry.clone(),
        identity.clone(),
        "evidence-change-request",
        Some(MutationFaultPoint::AfterCommitBeforeResponseRelease),
        None,
        registry_breg::attachment_storage::AttachmentStorage::Database,
        None,
        registry_breg::attachment_verification::AttachmentVerification::Disabled,
        Some(evaluator.clone()),
        None,
    );
    let fault_app = router(fault_service);
    let (replay_service, _) = change_request_service_with_evidence_options(
        &database,
        registry.clone(),
        identity.clone(),
        "evidence-change-request",
        None,
        None,
        registry_breg::attachment_storage::AttachmentStorage::Database,
        None,
        registry_breg::attachment_verification::AttachmentVerification::Disabled,
        Some(evaluator),
        None,
    );
    let replay_app = router(replay_service);
    let (request, digest) = submit_two_stage_correction(&replay_app).await;
    let target = &registry.entities()["asset-site"];
    let table = quote_sql_identifier(&target.physical_table);
    let name_column = quote_sql_identifier(&target.fields["name"].physical_name);
    let guard_row = database
        .admin
        .query_one(
            &format!("SELECT record_id, record_revision FROM registry_data.{table} WHERE {name_column} = $1"),
            &[&"two-new"],
        )
        .await
        .unwrap();
    let guard_id: Uuid = guard_row.get(0);
    let guard_revision: i64 = guard_row.get(1);
    let guard_plan = registry.entities()["correction-request"]
        .change_request
        .as_ref()
        .unwrap();
    let guard_context = json!({
        "version":1,"phase":{"kind":"application"},
        "requestEntityId":"correction-request","requestId":request.id,
        "proposalVersion":1,"actorReference":"synthetic-guard-lock-actor",
        "contractFingerprint":guard_plan.contract_fingerprint,
        "effectDigest":digest,"activePackageRevision":PACKAGE_REVISION,
        "selectedAccessProfile":"applier","principal":APPLIER,"purpose":"apply",
        "effectId":"site-guard","targetEntityId":"asset-site",
        "targetRecordId":guard_id.to_string(),"operation":"patch",
        "fields":["name","tenant"],"expectedRevision":guard_revision,
        "targetRowBoundaries":[{"field":"tenant","operator":"equals","values":[TENANT]}]
    });
    let applier_context = ClaimContext::for_compiled(
        &registry,
        "correction-request",
        Some(APPLIER.to_owned()),
        "applier",
        Some("apply".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "tenant".to_owned(),
            value: TENANT.to_owned(),
        }],
    )
    .unwrap();
    let guard_pool = database.runtime_config.build_pool().unwrap();
    let mut guard_client = guard_pool.get_for_test().await.unwrap();
    let guard_transaction = begin_record_transaction(
        &mut guard_client,
        RegistryLockKey::derive("evidence-change-request").unwrap(),
        Duration::from_secs(1),
        &identity,
        &applier_context,
    )
    .await
    .unwrap();
    let mut wrong_digest_context = guard_context.clone();
    wrong_digest_context["effectDigest"] =
        json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
    guard_transaction
        .transaction_for_test()
        .execute(
            "SELECT set_config('registry.change_request_target_context', $1, true)",
            &[&wrong_digest_context.to_string()],
        )
        .await
        .unwrap();
    let wrong_digest_row = guard_transaction
        .transaction_for_test()
        .query_opt(
            &format!("SELECT record_id FROM registry_data.{table} WHERE record_id = $1 FOR UPDATE"),
            &[&guard_id],
        )
        .await
        .unwrap();
    assert!(
        wrong_digest_row.is_none(),
        "a different proposal digest cannot read or lock the guard"
    );
    let other_guard_id: Uuid = database
        .admin
        .query_one(
            &format!("SELECT record_id FROM registry_data.{table} WHERE record_id <> $1 LIMIT 1"),
            &[&guard_id],
        )
        .await
        .unwrap()
        .get(0);
    for (key, value, queried_id) in [
        (
            "targetRecordId",
            json!(other_guard_id.to_string()),
            other_guard_id,
        ),
        ("expectedRevision", json!(guard_revision + 1), guard_id),
    ] {
        let mut forged = guard_context.clone();
        forged[key] = value;
        guard_transaction
            .transaction_for_test()
            .execute(
                "SELECT set_config('registry.change_request_target_context', $1, true)",
                &[&forged.to_string()],
            )
            .await
            .unwrap();
        let row = guard_transaction
            .transaction_for_test()
            .query_opt(
                &format!(
                    "SELECT record_id FROM registry_data.{table} WHERE record_id = $1 FOR UPDATE"
                ),
                &[&queried_id],
            )
            .await
            .unwrap();
        assert!(
            row.is_none(),
            "forged {key} cannot read or lock a guard row"
        );
    }
    guard_transaction
        .transaction_for_test()
        .execute(
            "SELECT set_config('registry.change_request_target_context', $1, true)",
            &[&guard_context.to_string()],
        )
        .await
        .unwrap();
    let locked = guard_transaction
        .transaction_for_test()
        .query_opt(
            &format!("SELECT record_id FROM registry_data.{table} WHERE record_id = $1 FOR UPDATE"),
            &[&guard_id],
        )
        .await
        .unwrap();
    assert!(
        locked.is_some(),
        "exact guard context can lock its target row"
    );
    let unauthorized_write = guard_transaction
        .transaction_for_test()
        .execute(
            &format!("UPDATE registry_data.{table} SET record_revision = record_revision + 1 WHERE record_id = $1"),
            &[&guard_id],
        )
        .await;
    assert_eq!(
        unauthorized_write.unwrap_err().code(),
        Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE),
        "read-only guard lock context cannot write its target row"
    );
    guard_transaction.rollback().await.unwrap();
    let applier_claims = |guard_tenant: &str| {
        VerifiedRequestClaims::authenticated(
            "registry_principal",
            APPLIER,
            BTreeSet::new(),
            Some("apply".to_owned()),
            BTreeMap::from([
                (
                    "tenant_claim".to_owned(),
                    VerifiedClaimValue::direct_string(TENANT).unwrap(),
                ),
                (
                    "guard_tenant_claim".to_owned(),
                    VerifiedClaimValue::direct_string(guard_tenant).unwrap(),
                ),
            ]),
        )
        .unwrap()
    };
    let applier = applier_claims(TENANT);
    let before = get_record(
        &replay_app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=applier",
            request.id
        ),
        applier.clone(),
    )
    .await;
    let apply = action(&before.body, "apply_request", None);
    let wrong_guard_before = get_record(
        &replay_app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=applier",
            request.id
        ),
        applier_claims("tenant-b"),
    )
    .await;
    let wrong_guard_apply = action(&wrong_guard_before.body, "apply_request", None);
    // Each fresh acquisition must pass both cryptographic verification and the
    // frozen application policy. None of these failures may leave a partial
    // application, retained Evidence use, result, or idempotency receipt.
    for mode in ["nonce", "expired", "inactive", "unavailable"] {
        provider.mode(mode);
        let failed = send_action(
            &replay_app,
            &apply,
            &format!("guard-refusal-{mode}"),
            applier.clone(),
            json!({"proposalVersion":1,"effectDigest":digest}),
        )
        .await;
        assert!(!failed.status.is_success(), "{mode} must not apply");
        let counts = database
            .admin
            .query_one(
                "SELECT (SELECT count(*) FROM registry_internal.registry_request_applications),
                    (SELECT count(*) FROM registry_internal.registry_request_evidence_uses),
                    (SELECT count(*) FROM registry_internal.registry_request_results)",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            [counts.get::<_, i64>(0), counts.get(1), counts.get(2)],
            [0, 0, 0]
        );
    }
    provider.mode("");
    let expected_calls = provider.calls() + 1;
    provider.pause();
    let invocation = send_action(
        &fault_app,
        &apply,
        "evidence-ambiguous-apply",
        applier.clone(),
        json!({"proposalVersion":1,"effectDigest":digest}),
    );
    let inspect = async {
        provider.wait_for_calls(expected_calls).await;
        assert_eq!(pool.status().available, pool.status().size);
        let active: i64 = database
            .admin
            .query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND xact_start IS NOT NULL",
                &[&database.runtime_role.as_str()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            active, 0,
            "remote Evidence I/O holds no runtime transaction"
        );
        provider.resume();
    };
    let (ambiguous, ()) = tokio::join!(invocation, inspect);
    assert_eq!(ambiguous.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(provider.calls(), expected_calls);
    let row = database
        .admin
        .query_one(
            "SELECT
               (SELECT count(*) FROM registry_internal.registry_request_applications),
               (SELECT count(*) FROM registry_internal.registry_request_evidence_uses),
               (SELECT count(*) FROM registry_internal.registry_request_results)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!([row.get::<_, i64>(0), row.get(1), row.get(2)], [1, 1, 1]);
    let replay = send_action(
        &replay_app,
        &apply,
        "evidence-ambiguous-apply",
        applier.clone(),
        json!({"proposalVersion":1,"effectDigest":digest}),
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK, "{}", replay.body);
    assert_eq!(replay.body["request"]["application"]["proposalVersion"], 1);
    assert_eq!(
        provider.calls(),
        expected_calls,
        "receipt replay performs no acquisition"
    );
    let row = database
        .admin
        .query_one(
            "SELECT
               (SELECT count(*) FROM registry_internal.registry_request_applications),
               (SELECT count(*) FROM registry_internal.registry_request_evidence_uses),
               (SELECT count(*) FROM registry_internal.registry_request_results)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!([row.get::<_, i64>(0), row.get(1), row.get(2)], [1, 1, 1]);
    provider.mode("unavailable");
    let idempotency_before_guard_refusal = idempotency_result_count(&database).await;
    let refused_same_key_guard = send_action(
        &replay_app,
        &wrong_guard_apply,
        "evidence-ambiguous-apply",
        applier_claims("tenant-b"),
        json!({"proposalVersion":1,"effectDigest":digest}),
    )
    .await;
    assert_eq!(
        refused_same_key_guard.status,
        StatusCode::CONFLICT,
        "a changed guard claim cannot reuse the original receipt key: {}",
        refused_same_key_guard.body
    );
    assert_eq!(refused_same_key_guard.body["code"], "idempotency.conflict");
    let refused_guard = send_action(
        &replay_app,
        &wrong_guard_apply,
        "evidence-ambiguous-apply-wrong-guard",
        applier_claims("tenant-b"),
        json!({"proposalVersion":1,"effectDigest":digest}),
    )
    .await;
    assert_eq!(
        refused_guard.status,
        StatusCode::PRECONDITION_FAILED,
        "an excluded guard row cannot release the application receipt: {}",
        refused_guard.body
    );
    assert_eq!(provider.calls(), expected_calls);
    assert_eq!(
        idempotency_result_count(&database).await,
        idempotency_before_guard_refusal,
        "guard refusal cannot bind a recovery key"
    );
    let different_key = send_action(
        &replay_app,
        &apply,
        "evidence-ambiguous-apply-different-key",
        applier.clone(),
        json!({"proposalVersion":1,"effectDigest":digest}),
    )
    .await;
    assert_eq!(
        different_key.status,
        StatusCode::OK,
        "{}",
        different_key.body
    );
    assert_eq!(
        different_key.body["request"]["application"],
        replay.body["request"]["application"]
    );
    assert_eq!(different_key.body["revision"], replay.body["revision"]);
    assert_eq!(
        provider.calls(),
        expected_calls,
        "recovery performs no Evidence acquisition"
    );
    let row = database
        .admin
        .query_one(
            "SELECT
               (SELECT count(*) FROM registry_internal.registry_request_applications),
               (SELECT count(*) FROM registry_internal.registry_request_evidence_uses)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!([row.get::<_, i64>(0), row.get(1)], [1, 1]);
    let idempotency_before_refusal = idempotency_result_count(&database).await;
    let bogus_precondition = RequestAction {
        href: apply.href.clone(),
        if_match: tampered_if_match(&apply.if_match),
        proposal_version: apply.proposal_version,
        effect_digest: apply.effect_digest.clone(),
    };
    let refused = send_action(
        &replay_app,
        &bogus_precondition,
        "evidence-ambiguous-apply-bogus-precondition",
        applier,
        json!({"proposalVersion":1,"effectDigest":digest}),
    )
    .await;
    assert_eq!(
        refused.status,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        refused.body
    );
    assert_eq!(provider.calls(), expected_calls);
    assert_eq!(
        idempotency_result_count(&database).await,
        idempotency_before_refusal
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_attachment_downloads_bind_owner_projection_version_and_terminal_audit() {
    attachment_download_journey(registry_breg::attachment_storage::AttachmentStorage::Database)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_attachment_apply_access_checks_frozen_guard_row_boundaries() {
    let database = TestDatabase::create(8).await;
    let mut source = serde_json::to_value(attachment_project()).unwrap();
    source["entities"][2]["changeRequest"]["application"] = json!({
        "preconditions":{"targets":[{
            "id":"site-guard", "entity":"asset-site", "fromField":"proposed-site",
            "requires":[{"field":"tenant", "equalsFromRequestField":"tenant"}]
        }]}
    });
    let applier = source["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|profile| profile["id"] == "applier")
        .unwrap();
    applier["permissions"][0]["applyTargets"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "entity":"asset-site",
            "rowBoundaries":[{"field":"tenant","claim":"guard_tenant_claim","operator":"equals"}]
        }));
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let registry = Arc::new(compile_project(&project, &[], CompileProfile::Authoring).unwrap());
    let identity = install_registry(&database, &registry, PACKAGE_ID, false).await;
    let app = router(change_request_service_with_attachment_storage(
        &database,
        registry,
        identity,
        PACKAGE_ID,
        None,
        None,
        registry_breg::attachment_storage::AttachmentStorage::Database,
    ));
    let steward = claims("steward", "guard-attachment-steward", None);
    let submitter = claims("submitter", SUBMITTER, None);
    let old_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "guard-attachment-old-site",
        json!({"tenant":TENANT,"name":"old"}),
    )
    .await;
    let new_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "guard-attachment-new-site",
        json!({"tenant":TENANT,"name":"new"}),
    )
    .await;
    let placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=steward",
        steward,
        "guard-attachment-placement",
        json!({"tenant":TENANT,"site":old_site.id}),
    )
    .await;
    let draft = create_record(&app, "/v1/records/correction-requests?accessProfile=submitter", submitter.clone(),
        "guard-attachment-request", json!({"tenant":TENANT,"placement":placement.id,"proposedSite":new_site.id,"reason":"guard attachment"})).await;
    let record_uri = format!(
        "/v1/records/correction-requests/{}?accessProfile=submitter",
        draft.id
    );
    let before = get_record(&app, &record_uri, submitter.clone()).await;
    let upload_uri = format!(
        "/v1/records/correction-requests/{}/attachments/evidence?accessProfile=submitter",
        draft.id
    );
    let uploaded = send(
        &app,
        Method::PATCH,
        &upload_uri,
        Some(submitter.clone()),
        &[
            ("content-type", "application/octet-stream"),
            ("idempotency-key", "guard-attachment-upload"),
            ("if-match", &before.etag),
        ],
        b"guard attachment".to_vec(),
    )
    .await;
    assert_eq!(uploaded.status(), StatusCode::OK);
    run_action(
        &app,
        &draft.id,
        "correction-requests",
        "submitter",
        submitter,
        "guard-attachment-submit",
        "submit_request",
        None,
        |_| json!({}),
    )
    .await;

    let uri = format!("/v1/records/correction-requests/{}/attachments/evidence?proposalVersion=1&accessProfile=applier", draft.id);
    let applier_claims = |guard_tenant: &str| {
        VerifiedRequestClaims::authenticated(
            "registry_principal",
            APPLIER,
            BTreeSet::new(),
            Some("apply".to_owned()),
            BTreeMap::from([
                (
                    "tenant_claim".to_owned(),
                    VerifiedClaimValue::direct_string(TENANT).unwrap(),
                ),
                (
                    "guard_tenant_claim".to_owned(),
                    VerifiedClaimValue::direct_string(guard_tenant).unwrap(),
                ),
            ]),
        )
        .unwrap()
    };
    assert_eq!(
        send(
            &app,
            Method::GET,
            &uri,
            Some(applier_claims("tenant-b")),
            &[],
            vec![]
        )
        .await
        .status(),
        StatusCode::NOT_FOUND,
        "an excluded guard row cannot authorize attachment disclosure"
    );
    assert_eq!(
        send(
            &app,
            Method::GET,
            &uri,
            Some(applier_claims(TENANT)),
            &[],
            vec![]
        )
        .await
        .status(),
        StatusCode::OK,
        "the frozen guard row satisfies the current apply grant"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires disposable PostgreSQL and BREG_TEST_S3_ENDPOINT/BREG_TEST_S3_BUCKET"]
async fn real_s3_http_attachments_preserve_proposals_and_complete_operator_erasure() {
    let (_cleanup_secrets, cleanup_storage) = attachment_s3_storage().await;
    s3_cleanup_with_all_requests_retained(cleanup_storage).await;
    let (_secrets, storage) = attachment_s3_storage().await;
    attachment_download_journey(storage).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_attachment_verification_quarantines_exact_bytes_and_survives_worker_failures(
) {
    use registry_breg::attachment_storage::AttachmentStorage;
    use registry_breg::attachment_verification_worker::AttachmentVerificationWorker;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let calls = Arc::new(AtomicUsize::new(0));
    let mode = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let observed = Arc::new(std::sync::Mutex::new(
        Vec::<(String, String, Vec<u8>)>::new(),
    ));
    let hook = axum::Router::new().route(
        "/verify",
        axum::routing::post({
            let (calls, mode, entered, resume, observed) = (
                calls.clone(),
                mode.clone(),
                entered.clone(),
                resume.clone(),
                observed.clone(),
            );
            move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                let (calls, mode, entered, resume, observed) = (
                    calls.clone(),
                    mode.clone(),
                    entered.clone(),
                    resume.clone(),
                    observed.clone(),
                );
                async move {
                    assert_eq!(headers["authorization"], "Bearer synthetic-verifier-token");
                    calls.fetch_add(1, Ordering::SeqCst);
                    observed.lock().unwrap().push((
                        headers["content-type"].to_str().unwrap().to_owned(),
                        headers["x-content-sha256"].to_str().unwrap().to_owned(),
                        body.to_vec(),
                    ));
                    let mode = mode.load(Ordering::SeqCst);
                    if mode == 3 {
                        entered.notify_one();
                        resume.notified().await;
                    }
                    if mode == 2 {
                        (StatusCode::SERVICE_UNAVAILABLE, axum::Json(json!({})))
                    } else {
                        (
                            StatusCode::OK,
                            axum::Json(
                                json!({"verdict": if mode == 1 {"rejected"} else {"approved"}}),
                            ),
                        )
                    }
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/verify", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, hook).await.unwrap();
    });
    let secrets = tempfile::tempdir().unwrap();
    let root = secrets.path().canonicalize().unwrap();
    std::fs::write(root.join("verifier"), "synthetic-verifier-token").unwrap();
    std::fs::set_permissions(
        root.join("verifier"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut raw = attachment_runtime_config(&root);
    raw["attachmentVerification"] = json!({"kind":"http","endpoint":endpoint,"authorizationRef":"secret:file/verifier","policyId":"synthetic-policy-v1","timeoutMilliseconds":5000});
    let verification = registry_breg::runtime_config::parse_runtime_config(&raw.to_string())
        .unwrap()
        .activate_attachment_verification()
        .unwrap();
    let database = TestDatabase::create(8).await;
    let mut project = attachment_project();
    project
        .entities
        .iter_mut()
        .find(|entity| entity.id == "correction-request")
        .unwrap()
        .attachments[0]
        .content_types
        .push("application/pdf".to_owned());
    let registry = Arc::new(compile_project(&project, &[], CompileProfile::Authoring).unwrap());
    let identity = install_registry(&database, &registry, PACKAGE_ID, false).await;
    let app = router(change_request_service_with_attachment_verification(
        &database,
        registry.clone(),
        identity.clone(),
        PACKAGE_ID,
        None,
        None,
        AttachmentStorage::Database,
        None,
        verification.clone(),
    ));
    let verification_policy = verification.binding_digest();
    let worker = AttachmentVerificationWorker::new(
        database.runtime_config.build_pool().unwrap(),
        identity.clone(),
        RegistryLockKey::derive(PACKAGE_ID).unwrap(),
        Duration::from_secs(2),
        AuditProfile::production_from_secret_bytes(vec![0x9a; 32].into()).unwrap(),
        AttachmentStorage::Database,
        verification,
    );
    let steward = claims("steward", "verification-steward", None);
    let submitter = claims("submitter", SUBMITTER, None);
    let site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "verification-site",
        json!({"tenant":TENANT,"name":"site"}),
    )
    .await;
    let placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=steward",
        steward,
        "verification-placement",
        json!({"tenant":TENANT,"site":site.id}),
    )
    .await;
    let draft = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=submitter",
        submitter.clone(),
        "verification-draft",
        json!({"tenant":TENANT,"placement":placement.id,"proposedSite":site.id,"reason":"verify"}),
    )
    .await;
    let record_uri = format!(
        "/v1/records/correction-requests/{}?accessProfile=submitter",
        draft.id
    );
    let upload_uri = format!(
        "/v1/records/correction-requests/{}/attachments/evidence?accessProfile=submitter",
        draft.id
    );
    let download_uri = format!("{upload_uri}&proposalVersion=1");
    let bytes = vec![0, 1, 2, 255];
    let upload = |mime: &'static str, bytes: Vec<u8>, key: &'static str| {
        let (app, record_uri, upload_uri, submitter) = (
            app.clone(),
            record_uri.clone(),
            upload_uri.clone(),
            submitter.clone(),
        );
        async move {
            let before = get_record(&app, &record_uri, submitter.clone()).await;
            let response = response_parts(
                send(
                    &app,
                    Method::PATCH,
                    &upload_uri,
                    Some(submitter.clone()),
                    &[
                        ("content-type", mime),
                        ("idempotency-key", key),
                        ("if-match", &before.etag),
                    ],
                    bytes,
                )
                .await,
            )
            .await;
            assert_eq!(response.status, StatusCode::OK, "{}", response.body);
            let current = get_record(&app, &record_uri, submitter).await;
            assert_eq!(response.etag, current.etag);
            current
        }
    };
    let pending = upload(
        "application/octet-stream",
        bytes.clone(),
        "verification-upload",
    )
    .await;
    assert_eq!(
        pending.body["data"]["evidence"]["verificationStatus"],
        "pending"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "upload never contacts the verifier"
    );
    assert_eq!(
        send(
            &app,
            Method::GET,
            &download_uri,
            Some(submitter.clone()),
            &[],
            vec![]
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    let submit_action = action(&pending.body, "submit_request", None);
    assert_eq!(
        send(
            &app,
            Method::POST,
            &submit_action.href,
            Some(submitter.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "verification-pending-submit"),
                ("if-match", &submit_action.if_match)
            ],
            b"{}".to_vec()
        )
        .await
        .status(),
        StatusCode::PRECONDITION_FAILED
    );

    // An audit attempt refusal prevents the first outbound byte and rolls back
    // the lease, so an ordinary restarted worker can immediately claim it.
    database.admin.batch_execute("CREATE FUNCTION public.refuse_verifier_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF convert_from(NEW.envelope,'UTF8')::jsonb #>> '{record,kind}' = 'attachmentVerification' THEN RAISE EXCEPTION 'synthetic audit fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER refuse_verifier_audit BEFORE INSERT ON registry_internal.registry_audit FOR EACH ROW EXECUTE FUNCTION public.refuse_verifier_audit()").await.unwrap();
    assert!(worker.run_once().await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    database
        .admin
        .batch_execute("DROP TRIGGER refuse_verifier_audit ON registry_internal.registry_audit")
        .await
        .unwrap();
    assert!(worker.clone().run_once().await.unwrap());
    let approved = get_record(&app, &record_uri, submitter.clone()).await;
    assert_eq!(
        approved.body["data"]["evidence"]["verificationStatus"],
        "approved"
    );
    assert_ne!(
        approved.etag, pending.etag,
        "verification changes strong representation ETag"
    );
    assert_eq!(approved.body["revision"], pending.body["revision"]);
    let response = send(
        &app,
        Method::GET,
        &download_uri,
        Some(submitter.clone()),
        &[],
        vec![],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap().to_vec(),
        bytes
    );

    // Approval is bound to MIME as well as bytes and the configured policy.
    let pending = upload("application/pdf", bytes.clone(), "verification-new-mime").await;
    assert_eq!(
        pending.body["data"]["evidence"]["verificationStatus"],
        "pending"
    );
    mode.store(1, Ordering::SeqCst);
    assert!(worker.run_once().await.unwrap());
    let rejected = get_record(&app, &record_uri, submitter.clone()).await;
    assert_eq!(
        rejected.body["data"]["evidence"]["verificationStatus"],
        "rejected"
    );
    assert_eq!(
        send(
            &app,
            Method::GET,
            &download_uri,
            Some(submitter.clone()),
            &[],
            vec![]
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    let submit_action = action(&rejected.body, "submit_request", None);
    assert_eq!(
        send(
            &app,
            Method::POST,
            &submit_action.href,
            Some(submitter.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "verification-rejected-submit"),
                ("if-match", &submit_action.if_match)
            ],
            b"{}".to_vec()
        )
        .await
        .status(),
        StatusCode::PRECONDITION_FAILED
    );

    let replacement = vec![3, 4, 5, 6];
    let pending = upload(
        "application/octet-stream",
        replacement.clone(),
        "verification-replacement",
    )
    .await;
    assert_eq!(
        pending.body["data"]["evidence"]["verificationStatus"],
        "pending"
    );
    let replacement_hash = pending.body["data"]["evidence"]["sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    // A crash-held lease is durable and becomes reclaimable after expiry.
    database.admin.execute("UPDATE registry_internal.registry_attachment_verification SET lease_id=$1,lease_expires_at=transaction_timestamp()-interval '1 second' WHERE verdict='pending'", &[&Uuid::new_v4()]).await.unwrap();
    mode.store(0, Ordering::SeqCst);
    database.admin.batch_execute("CREATE OR REPLACE FUNCTION public.refuse_verifier_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF convert_from(NEW.envelope,'UTF8')::jsonb #>> '{record,kind}' = 'attachmentVerification' AND convert_from(NEW.envelope,'UTF8')::jsonb #>> '{record,phase}' = 'terminal' THEN RAISE EXCEPTION 'synthetic terminal audit fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER refuse_verifier_audit BEFORE INSERT ON registry_internal.registry_audit FOR EACH ROW EXECUTE FUNCTION public.refuse_verifier_audit()").await.unwrap();
    assert!(worker.run_once().await.is_err());
    assert_eq!(
        get_record(&app, &record_uri, submitter.clone()).await.body["data"]["evidence"]
            ["verificationStatus"],
        "pending"
    );
    assert_eq!(
        send(
            &app,
            Method::GET,
            &download_uri,
            Some(submitter.clone()),
            &[],
            vec![]
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    database.admin.batch_execute("DROP TRIGGER refuse_verifier_audit ON registry_internal.registry_audit; UPDATE registry_internal.registry_attachment_verification SET lease_expires_at=transaction_timestamp()-interval '1 second' WHERE lease_id IS NOT NULL").await.unwrap();
    assert!(worker.clone().run_once().await.unwrap());
    assert_eq!(
        get_record(&app, &record_uri, submitter.clone()).await.body["data"]["evidence"]
            ["verificationStatus"],
        "approved"
    );
    let captured = observed.lock().unwrap().clone();
    assert_eq!(captured[0].0, "application/octet-stream");
    assert_eq!(captured[0].2, bytes);
    assert_eq!(captured[1].0, "application/pdf");
    assert_eq!(captured.last().unwrap().1, replacement_hash);
    assert_eq!(captured.last().unwrap().2, replacement);

    // Retention can finish while the verifier is out of process. Its late
    // approved verdict is discarded and cannot recreate an erased reference.
    upload(
        "application/octet-stream",
        vec![9, 8, 7],
        "verification-erasure",
    )
    .await;
    run_action(
        &app,
        &draft.id,
        "correction-requests",
        "submitter",
        submitter.clone(),
        "verification-cancel",
        "cancel_request",
        None,
        |_| json!({}),
    )
    .await;
    mode.store(3, Ordering::SeqCst);
    let running_worker = worker.clone();
    let pending_worker = tokio::spawn(async move { running_worker.run_once().await });
    tokio::time::timeout(Duration::from_secs(3), entered.notified())
        .await
        .unwrap();
    let retention =
        registry_breg::request_retention::RequestRetentionOperatorService::new_for_test(
            registry.as_ref().clone(),
            identity,
            registry_breg::postgres::ExpectedManagedCatalog::compiled(&registry),
            RegistryLockKey::derive(PACKAGE_ID).unwrap(),
            database.migration_config.clone(),
            database.migration_role.clone(),
            database.runtime_role.clone(),
            AuditProfile::production_from_secret_bytes(vec![0x9a; 32].into()).unwrap(),
        )
        .with_verification_policy_for_test(verification_policy);
    let erased = retention
        .erase(
            registry_breg::request_retention::RequestDetailErasureScope {
                request_entity_id: "correction-request",
                request_id: Uuid::parse_str(&draft.id).unwrap(),
                proposal_version: 1,
            },
        )
        .await;
    resume.notify_one();
    assert_eq!(erased.unwrap().erasure.attachment_references, 1);
    assert!(pending_worker.await.unwrap().unwrap());
    assert_eq!(
        send(
            &app,
            Method::GET,
            &download_uri,
            Some(submitter),
            &[],
            vec![]
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(database.admin.query_one("SELECT count(*) FROM registry_internal.registry_attachment_verification WHERE verdict='pending'", &[]).await.unwrap().get::<_,i64>(0),0);
    server.abort();
    database.cleanup().await;
}

async fn s3_cleanup_with_all_requests_retained(
    storage: registry_breg::attachment_storage::AttachmentStorage,
) {
    use sha2::{Digest, Sha256};
    let registry_breg::attachment_storage::AttachmentStorage::S3(store) = &storage else {
        unreachable!()
    };
    let database = TestDatabase::create(8).await;
    let mut project = attachment_project();
    for entity in &mut project.entities {
        if let Some(request) = &mut entity.change_request {
            request.retention.mode =
                registry_breg::contract::ChangeRequestRetentionModeSource::Retain;
        }
    }
    let registry = Arc::new(compile_project(&project, &[], CompileProfile::Authoring).unwrap());
    let identity = install_registry(&database, &registry, PACKAGE_ID, false).await;
    let app = router(change_request_service_with_attachment_storage(
        &database,
        registry.clone(),
        identity.clone(),
        PACKAGE_ID,
        None,
        None,
        storage.clone(),
    ));
    let steward = claims("steward", "cleanup-steward", None);
    let submitter = claims("submitter", SUBMITTER, None);
    let site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "cleanup-site",
        json!({"tenant":TENANT,"name":"site"}),
    )
    .await;
    let placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=steward",
        steward,
        "cleanup-placement",
        json!({"tenant":TENANT,"site":site.id}),
    )
    .await;
    let mut drafts = Vec::new();
    let bytes = b"shared retained content".to_vec();
    let live_hash = hex::encode(Sha256::digest(&bytes));
    for key in ["cleanup-first", "cleanup-second"] {
        let draft = create_record(&app, "/v1/records/correction-requests?accessProfile=submitter", submitter.clone(), key, json!({"tenant":TENANT,"placement":placement.id,"proposedSite":site.id,"reason":"retain"})).await;
        let uri = format!(
            "/v1/records/correction-requests/{}/attachments/evidence?accessProfile=submitter",
            draft.id
        );
        let response = send(
            &app,
            Method::PATCH,
            &uri,
            Some(submitter.clone()),
            &[
                ("content-type", "application/octet-stream"),
                ("idempotency-key", &format!("{key}-upload")),
                ("if-match", &draft.etag),
            ],
            bytes.clone(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        drafts.push(draft);
    }
    assert_eq!(database.admin.query_one("SELECT count(*) FROM registry_internal.registry_request_attachments WHERE sha256=$1 AND erased_at IS NULL", &[&live_hash]).await.unwrap().get::<_,i64>(0),2,"two live references share one object");
    let record_uri = format!(
        "/v1/records/correction-requests/{}?accessProfile=submitter",
        drafts[0].id
    );
    let upload_uri = format!(
        "/v1/records/correction-requests/{}/attachments/evidence?accessProfile=submitter",
        drafts[0].id
    );
    let before = get_record(&app, &record_uri, submitter.clone()).await;
    let orphan = b"replaced and removed draft bytes".to_vec();
    let orphan_hash = hex::encode(Sha256::digest(&orphan));
    let response = send(
        &app,
        Method::PATCH,
        &upload_uri,
        Some(submitter.clone()),
        &[
            ("content-type", "application/octet-stream"),
            ("idempotency-key", "cleanup-orphan"),
            ("if-match", &before.etag),
        ],
        orphan,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let before = get_record(&app, &record_uri, submitter.clone()).await;
    assert_eq!(
        send(
            &app,
            Method::DELETE,
            &upload_uri,
            Some(submitter.clone()),
            &[
                ("idempotency-key", "cleanup-remove-body-refused"),
                ("if-match", &before.etag)
            ],
            vec![1]
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get_record(&app, &record_uri, submitter.clone()).await.etag,
        before.etag
    );
    assert_eq!(
        send(
            &app,
            Method::DELETE,
            &upload_uri,
            Some(submitter.clone()),
            &[
                ("idempotency-key", "cleanup-remove"),
                ("if-match", &before.etag)
            ],
            vec![]
        )
        .await
        .status(),
        StatusCode::OK
    );
    let staged = b"interrupted staged object".to_vec();
    let staged_hash = hex::encode(Sha256::digest(&staged));
    let (migration, migration_task) = database.connect_migration().await;
    registry_breg::attachment_store::test_support::stage(
        &migration,
        &staged_hash,
        staged.len() as u64,
        &storage.binding_digest(),
    )
    .await
    .unwrap();
    store.put(&staged_hash, staged).await.unwrap();
    database.admin.execute("UPDATE registry_internal.registry_attachment_blobs SET created_at=transaction_timestamp()-interval '11 minutes' WHERE sha256=$1",&[&staged_hash]).await.unwrap();
    drop(migration);
    migration_task.abort();
    let cleanup = registry_breg::request_retention::RequestRetentionOperatorService::new_for_test(
        registry.as_ref().clone(),
        identity,
        registry_breg::postgres::ExpectedManagedCatalog::compiled(&registry),
        RegistryLockKey::derive(PACKAGE_ID).unwrap(),
        database.migration_config.clone(),
        database.migration_role.clone(),
        database.runtime_role.clone(),
        AuditProfile::production_from_secret_bytes(vec![0x9a; 32].into()).unwrap(),
    )
    .with_attachment_storage_for_test(storage.clone());
    assert_eq!(
        cleanup
            .erase(
                registry_breg::request_retention::RequestDetailErasureScope {
                    request_entity_id: "correction-request",
                    request_id: Uuid::parse_str(&drafts[0].id).unwrap(),
                    proposal_version: 1
                }
            )
            .await
            .unwrap_err(),
        registry_breg::request_retention::RequestRetentionError::RetainMode
    );
    let cleaned = cleanup.cleanup_attachments().await.unwrap();
    assert_eq!(cleaned.pending_external_deletions, 0);
    assert!(cleaned.external_deletion_tombstones >= 2);
    for hash in [&orphan_hash, &staged_hash] {
        assert!(matches!(
            store.get(hash, 1024).await,
            Err(registry_breg::attachment_storage::AttachmentStorageError::Missing)
        ));
    }
    assert_eq!(
        store.get(&live_hash, bytes.len() as u64).await.unwrap(),
        bytes
    );
    let live_uri = format!("/v1/records/correction-requests/{}/attachments/evidence?accessProfile=submitter&proposalVersion=1",drafts[1].id);
    let response = send(
        &app,
        Method::GET,
        &live_uri,
        Some(submitter.clone()),
        &[],
        vec![],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap().to_vec(),
        bytes
    );
    let current = get_record(&app, &record_uri, submitter).await;
    assert_eq!(current.body["request"]["bregState"], "draft");
    assert!(current.body["data"]["evidence"].is_null());
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_attachment_projection_locks_exclude_scalar_reads_and_lookahead() {
    let database = TestDatabase::create(8).await;
    let registry =
        Arc::new(compile_project(&attachment_project(), &[], CompileProfile::Authoring).unwrap());
    let identity = install_registry(&database, &registry, PACKAGE_ID, false).await;
    let storage = registry_breg::attachment_storage::AttachmentStorage::Database;
    let app = router(change_request_service_with_attachment_storage(
        &database,
        registry.clone(),
        identity.clone(),
        PACKAGE_ID,
        None,
        None,
        storage.clone(),
    ));
    let steward = claims("steward", "projection-steward", None);
    let submitter = claims("submitter", SUBMITTER, None);
    let site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "projection-site",
        json!({"tenant":TENANT,"name":"site"}),
    )
    .await;
    let placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=steward",
        steward,
        "projection-placement",
        json!({"tenant":TENANT,"site":site.id}),
    )
    .await;
    let mut drafts = Vec::new();
    for key in ["projection-first", "projection-second"] {
        drafts.push(create_record(&app, "/v1/records/correction-requests?accessProfile=submitter", submitter.clone(), key, json!({"tenant":TENANT,"placement":placement.id,"proposedSite":site.id,"reason":"initial reason"})).await);
    }
    drafts.sort_by(|left, right| left.id.cmp(&right.id));
    for (case, uri, target) in [
        (
            "scalar-get",
            format!(
                "/v1/records/correction-requests/{}?accessProfile=submitter&$select=reason",
                drafts[0].id
            ),
            &drafts[0],
        ),
        (
            "scalar-list",
            "/v1/records/correction-requests?accessProfile=submitter&$select=reason&$top=1"
                .to_owned(),
            &drafts[0],
        ),
        (
            "attachment-lookahead",
            "/v1/records/correction-requests?accessProfile=submitter&$select=evidence&$top=1"
                .to_owned(),
            &drafts[1],
        ),
    ] {
        let write_uri = format!(
            "/v1/records/correction-requests/{}?accessProfile=submitter",
            target.id
        );
        let before = get_record(&app, &write_uri, submitter.clone()).await;
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let paused = router(change_request_service_with_attachment_pause(
            &database,
            registry.clone(),
            identity.clone(),
            PACKAGE_ID,
            None,
            None,
            storage.clone(),
            Some((entered.clone(), resume.clone())),
        ));
        let actor = submitter.clone();
        let reader = tokio::spawn(async move {
            response_parts(send(&paused, Method::GET, &uri, Some(actor), &[], vec![]).await).await
        });
        tokio::time::timeout(Duration::from_secs(3), entered.notified())
            .await
            .expect("read reaches source materialization barrier");
        let writer_app = app.clone();
        let actor = submitter.clone();
        let mut writer = tokio::spawn(async move {
            response_parts(
                send(
                    &writer_app,
                    Method::PATCH,
                    &write_uri,
                    Some(actor),
                    &[
                        ("content-type", "application/json-patch+json"),
                        ("idempotency-key", case),
                        ("if-match", &before.etag),
                    ],
                    serde_json::to_vec(
                        &json!([{"op":"replace","path":"/data/reason","value":case}]),
                    )
                    .unwrap(),
                )
                .await,
            )
            .await
        });
        let completed = tokio::time::timeout(Duration::from_secs(1), &mut writer).await;
        resume.notify_one();
        let read = reader.await.unwrap();
        assert_eq!(read.status, StatusCode::OK, "{case}: {}", read.body);
        let written = match completed {
            Ok(result) => result.unwrap(),
            Err(_) => {
                writer.await.unwrap();
                panic!("{case} unnecessarily locked a record whose attachment metadata was not returned");
            }
        };
        assert_eq!(written.status, StatusCode::OK, "{case}: {}", written.body);
        if case == "attachment-lookahead" {
            assert_eq!(read.body["items"].as_array().unwrap().len(), 1);
            assert_eq!(read.body["items"][0]["id"], drafts[0].id);
        }
    }
    database.cleanup().await;
}

async fn attachment_s3_storage() -> (
    tempfile::TempDir,
    registry_breg::attachment_storage::AttachmentStorage,
) {
    use std::os::unix::fs::PermissionsExt;
    let secrets = tempfile::tempdir().unwrap();
    let root = secrets.path().canonicalize().unwrap();
    for (file, variable) in [
        ("access", "BREG_TEST_S3_ACCESS_KEY"),
        ("secret", "BREG_TEST_S3_SECRET_KEY"),
    ] {
        let value = std::env::var(variable).expect("synthetic S3 credentials required");
        let path = root.join(file);
        std::fs::write(&path, value).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut raw = attachment_runtime_config(&root);
    raw["attachmentStorage"] = json!({"kind":"s3","endpoint":std::env::var("BREG_TEST_S3_ENDPOINT").expect("disposable S3 endpoint required"),"bucket":std::env::var("BREG_TEST_S3_BUCKET").expect("precreated disposable unversioned S3 bucket required"),"region":"us-east-1","accessKeyIdRef":"secret:file/access","secretAccessKeyRef":"secret:file/secret"});
    let config = registry_breg::runtime_config::parse_runtime_config(&raw.to_string())
        .expect("operator S3 runtime configuration validates");
    let storage = config
        .activate_attachment_storage("attachment-http")
        .await
        .expect("real configured S3 backend activates");
    (secrets, storage)
}

fn attachment_runtime_config(root: &std::path::Path) -> Value {
    json!({
        "apiVersion":registry_breg::runtime_config::RUNTIME_CONFIG_API_VERSION,
        "kind":registry_breg::runtime_config::RUNTIME_CONFIG_KIND,
        "listener":{"bind":"127.0.0.1:8080"},
        "identity":{"environment":"local","instanceId":"attachment-http-test","databaseId":Uuid::new_v4().to_string(),"databaseInitializationEnvironment":"local"},
        "secretProviders":{"file":{"root":root}},
        "database":{"runtimeUrlRef":"secret:file/database","migrationUrlRef":"secret:file/migration","pool":{"maxSize":4,"waitTimeoutMilliseconds":1000,"createTimeoutMilliseconds":1000,"recycleTimeoutMilliseconds":1000},"roles":{"migration":"registry_migration","runtime":"registry_runtime"}},
        "package":{"root":root,"trustAnchorPath":root.join("anchor"),"compilerSourceRevision":"test-source","activeRevision":PACKAGE_REVISION,"activeSequence":1},
        "authentication":{"oidc":{"issuer":"https://issuer.example","audience":"urn:breg:test","allowedAlgorithm":"EdDSA","accessTokenType":"JWT","scopeClaim":"scope","scopeSeparator":" ","allowedClients":["registry-client"],"deniedKids":[],"maxTokenLifetimeSeconds":300,"leewayMilliseconds":60000,"jwksCache":{"cacheTtlSeconds":600,"negativeCacheTtlSeconds":60,"refreshCooldownSeconds":30,"maxDocumentBytes":65536,"requestTimeoutMilliseconds":5000,"outageToleranceSeconds":900}},"authorityClaims":{"principal":"registry_principal","purpose":"registry_purpose"}},
        "audit":{"hashKeyRef":"secret:file/audit"},
        "cursor":{"secretRef":"secret:file/cursor","maxAgeSeconds":300},
        "eventDestinations":{},
        "operationalTimeouts":{"httpRequestMilliseconds":10000,"shutdownGraceMilliseconds":30000,"recordLockMilliseconds":5000,"migrationLockMilliseconds":30000,"migrationStatementMilliseconds":60000}
    })
}

fn attachment_project() -> registry_breg::contract::RegistryProject {
    let mut project = two_stage_project();
    project
        .entities
        .iter_mut()
        .find(|entity| entity.id == "correction-request")
        .unwrap()
        .change_request
        .as_mut()
        .unwrap()
        .retention
        .mode = registry_breg::contract::ChangeRequestRetentionModeSource::OperatorErase;

    project
        .entities
        .iter_mut()
        .find(|entity| entity.id == "correction-request")
        .unwrap()
        .attachments
        .push(registry_breg::contract::AttachmentSlotSource {
            id: "evidence".to_owned(),
            required: true,
            maximum_bytes: 1024,
            content_types: vec!["application/octet-stream".to_owned()],
            classification: registry_breg::contract::Classification::Internal,
        });
    for profile in &mut project.access_profiles {
        for grant in profile
            .permissions
            .iter_mut()
            .filter(|grant| grant.entity == "correction-request")
        {
            grant.readable_fields.insert("evidence".to_owned());
            if profile.id == "submitter" {
                grant.writable_fields.insert("evidence".to_owned());
                grant.request_visibility =
                    Some(registry_breg::contract::RequestVisibilitySource::Owner);
            }
        }
    }
    let mut hidden = project
        .access_profiles
        .iter()
        .find(|profile| profile.id == "submitter")
        .unwrap()
        .clone();
    hidden.id = "hidden-owner".to_owned();
    hidden.permissions[0].readable_fields.remove("evidence");
    hidden.permissions[0].writable_fields.remove("evidence");
    project.access_profiles.push(hidden);
    let mut other_target = project
        .access_profiles
        .iter()
        .find(|profile| profile.id == "reviewer")
        .unwrap()
        .clone();
    other_target.id = "other-target-reviewer".to_owned();
    other_target.default = false;
    other_target.permissions[0].row_boundaries[0].claim = "target_tenant_claim".to_owned();
    project.access_profiles.push(other_target);

    for variant in [
        "reviewer-no-slot",
        "reviewer-empty-slot",
        "reviewer-other-stage",
        "reviewer-self-reason",
    ] {
        let mut profile = project
            .access_profiles
            .iter()
            .find(|profile| profile.id == "reviewer")
            .unwrap()
            .clone();
        profile.id = variant.to_owned();
        profile.default = false;
        let grant = &mut profile.permissions[0];
        match variant {
            "reviewer-no-slot" | "reviewer-empty-slot" | "reviewer-other-stage" => {
                grant.readable_fields.remove("evidence");
            }
            _ => grant
                .row_boundaries
                .push(registry_breg::contract::RowBoundarySource {
                    field: "reason".to_owned(),
                    claim: "self_reason_claim".to_owned(),
                    operator: registry_breg::contract::BoundaryOperator::Equals,
                }),
        }
        project.access_profiles.push(profile);
    }
    let mut self_applier = project
        .access_profiles
        .iter()
        .find(|profile| profile.id == "applier")
        .unwrap()
        .clone();
    self_applier.id = "applier-self-reason".to_owned();
    self_applier.default = false;
    self_applier.permissions[0].apply_targets.push(
        registry_breg::contract::ApplyTargetPermissionSource {
            entity: "correction-request".to_owned(),
            row_boundaries: vec![registry_breg::contract::RowBoundarySource {
                field: "reason".to_owned(),
                claim: "self_reason_claim".to_owned(),
                operator: registry_breg::contract::BoundaryOperator::Equals,
            }],
        },
    );
    project.access_profiles.push(self_applier);

    project
}

fn attachment_self_reason_claims(profile: &str, reason: &str) -> VerifiedRequestClaims {
    let (principal, purpose) = if profile.starts_with("applier") {
        (APPLIER, "apply")
    } else {
        (REVIEWER, "review")
    };
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        BTreeSet::new(),
        Some(purpose.to_owned()),
        BTreeMap::from([
            (
                "tenant_claim".to_owned(),
                VerifiedClaimValue::direct_string(TENANT).unwrap(),
            ),
            (
                "self_reason_claim".to_owned(),
                VerifiedClaimValue::direct_string(reason).unwrap(),
            ),
        ]),
    )
    .unwrap()
}

async fn attachment_audit_records(
    database: &TestDatabase,
    operation_id: &str,
    phase: &str,
) -> Vec<Value> {
    database.admin.query("SELECT convert_from(envelope, 'UTF8')::jsonb -> 'record' FROM registry_internal.registry_audit WHERE convert_from(envelope, 'UTF8')::jsonb #>> '{record,operationId}' = $1 AND convert_from(envelope, 'UTF8')::jsonb #>> '{record,phase}' = $2", &[&operation_id, &phase]).await.unwrap().iter().map(|row| row.get(0)).collect()
}

async fn attachment_download_journey(
    storage: registry_breg::attachment_storage::AttachmentStorage,
) {
    let database = TestDatabase::create(8).await;
    let project = attachment_project();

    let registry = Arc::new(
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("attachment fixture compiles"),
    );
    let attachment_operation = |operation, method| {
        let base = registry
            .routes()
            .routes
            .iter()
            .find(|route| route.entity_id == "correction-request" && route.operation == operation)
            .unwrap();
        format!("{}.attachment.evidence.{method}", base.id)
    };
    let patch_operation = attachment_operation(registry_breg::contract::Operation::Patch, "patch");
    let delete_operation =
        attachment_operation(registry_breg::contract::Operation::Patch, "delete");
    let get_operation = attachment_operation(registry_breg::contract::Operation::Get, "get");
    let identity = install_registry(&database, &registry, PACKAGE_ID, false).await;
    let app = router(change_request_service_with_attachment_storage(
        &database,
        registry.clone(),
        identity.clone(),
        PACKAGE_ID,
        None,
        None,
        storage.clone(),
    ));
    let steward = claims("steward", "attachment-steward", None);
    let submitter = claims("submitter", SUBMITTER, None);
    let old_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "attachment-site-old",
        json!({"tenant":TENANT,"name":"old"}),
    )
    .await;
    let new_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "attachment-site-new",
        json!({"tenant":TENANT,"name":"new"}),
    )
    .await;
    let placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=steward",
        steward,
        "attachment-placement",
        json!({"tenant":TENANT,"site":old_site.id}),
    )
    .await;
    let draft = create_record(&app, "/v1/records/correction-requests?accessProfile=submitter", submitter.clone(), "attachment-draft", json!({"tenant":TENANT,"placement":placement.id,"proposedSite":new_site.id,"reason":"attachment test"})).await;
    let record_uri = format!(
        "/v1/records/correction-requests/{}?accessProfile=submitter",
        draft.id
    );
    let before = get_record(&app, &record_uri, submitter.clone()).await;
    assert!(before.body["data"]["evidence"].is_null());
    let submit_action = action(&before.body, "submit_request", None);
    let incomplete = send(
        &app,
        Method::POST,
        &submit_action.href,
        Some(submitter.clone()),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "attachment-incomplete"),
            ("if-match", &submit_action.if_match),
        ],
        b"{}".to_vec(),
    )
    .await;
    assert_eq!(incomplete.status(), StatusCode::PRECONDITION_FAILED);
    let upload_uri = format!(
        "/v1/records/correction-requests/{}/attachments/evidence?accessProfile=submitter",
        draft.id
    );
    for (headers, status) in [
        (
            vec![
                ("content-type", "application/octet-stream"),
                ("idempotency-key", "missing-precondition"),
            ],
            StatusCode::PRECONDITION_REQUIRED,
        ),
        (
            vec![
                ("content-type", "application/octet-stream"),
                ("if-match", before.etag.as_str()),
            ],
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let count = attachment_audit_records(&database, &patch_operation, "refusal")
            .await
            .len();
        let response = send(
            &app,
            Method::PATCH,
            &upload_uri,
            Some(submitter.clone()),
            &headers,
            vec![1],
        )
        .await;
        assert_eq!(response.status(), status);
        let records = attachment_audit_records(&database, &patch_operation, "refusal").await;
        assert_eq!(records.len(), count + 1);
        assert!(records
            .iter()
            .all(|record| record["method"] == "PATCH"
                && record["attachment"]["slotId"] == "evidence"));
    }
    for (mime, body, status, key) in [
        (
            "text/plain",
            vec![1],
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "attachment-wrong-mime",
        ),
        (
            "application/octet-stream",
            vec![1; 1025],
            StatusCode::BAD_REQUEST,
            "attachment-too-large",
        ),
    ] {
        let refusal_count = attachment_audit_records(&database, &patch_operation, "refusal")
            .await
            .len();
        let refused = send(
            &app,
            Method::PATCH,
            &upload_uri,
            Some(submitter.clone()),
            &[
                ("content-type", mime),
                ("content-length", "1"),
                ("idempotency-key", key),
                ("if-match", &before.etag),
            ],
            body,
        )
        .await;
        assert_eq!(refused.status(), status);
        assert_eq!(
            attachment_audit_records(&database, &patch_operation, "refusal")
                .await
                .len(),
            refusal_count + 1
        );
    }
    struct InterruptedUpload(bool);
    impl futures_core::Stream for InterruptedUpload {
        type Item = Result<Vec<u8>, std::io::Error>;
        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Ready(Some(if self.0 {
                Err(std::io::Error::other("synthetic upload interruption"))
            } else {
                self.0 = true;
                Ok(vec![1, 2, 3])
            }))
        }
    }
    let mut interrupted = Request::builder()
        .method(Method::PATCH)
        .uri(&upload_uri)
        .header("content-type", "application/octet-stream")
        .header("idempotency-key", "attachment-interrupted")
        .header("if-match", &before.etag)
        .body(Body::from_stream(InterruptedUpload(false)))
        .unwrap();
    interrupted.extensions_mut().insert(submitter.clone());
    assert_eq!(
        app.clone().call(interrupted).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let forged =
        json!([{"op":"add","path":"/data/evidence","value":{"sha256":"forged","byteSize":1}}]);
    let refused = send(
        &app,
        Method::PATCH,
        &record_uri,
        Some(submitter.clone()),
        &[
            ("content-type", "application/json-patch+json"),
            ("idempotency-key", "attachment-forged-patch"),
            ("if-match", &before.etag),
        ],
        serde_json::to_vec(&forged).unwrap(),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let mut forged_create = before.body["data"].clone();
    forged_create["evidence"] = json!({"sha256":"forged","byteSize":1});
    let refused = send(
        &app,
        Method::POST,
        "/v1/records/correction-requests?accessProfile=submitter",
        Some(submitter.clone()),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "attachment-forged-create"),
        ],
        serde_json::to_vec(&json!({"data":forged_create})).unwrap(),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        get_record(&app, &record_uri, submitter.clone()).await.etag,
        before.etag,
        "refusals preserve the request revision"
    );
    assert_eq!(
        database
            .admin
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_attachment_blobs",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0,
        "refusals never stage or persist blobs"
    );
    let bytes = vec![0, 255, 13, 10, 42, 1];
    let uploaded = response_parts(
        send(
            &app,
            Method::PATCH,
            &upload_uri,
            Some(submitter.clone()),
            &[
                ("content-type", "application/octet-stream"),
                ("idempotency-key", "attachment-upload"),
                ("if-match", &before.etag),
            ],
            bytes.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(uploaded.status, StatusCode::OK, "{}", uploaded.body);
    let replayed = response_parts(
        send(
            &app,
            Method::PATCH,
            &upload_uri,
            Some(submitter.clone()),
            &[
                ("content-type", "application/octet-stream"),
                ("idempotency-key", "attachment-upload"),
                ("if-match", &before.etag),
            ],
            bytes.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(replayed.status, StatusCode::OK);
    assert_eq!(replayed.body, uploaded.body);
    assert_eq!(replayed.etag, uploaded.etag);
    let conflicting = send(
        &app,
        Method::PATCH,
        &upload_uri,
        Some(submitter.clone()),
        &[
            ("content-type", "application/octet-stream"),
            ("idempotency-key", "attachment-upload"),
            ("if-match", &before.etag),
        ],
        vec![9; bytes.len()],
    )
    .await;
    assert_eq!(conflicting.status(), StatusCode::CONFLICT);

    let patch_audits = attachment_audit_records(&database, &patch_operation, "terminal").await;
    for outcome in ["committed", "replayed"] {
        assert!(patch_audits
            .iter()
            .any(|record| record["outcome"] == outcome
                && record["method"] == "PATCH"
                && record["attachment"]["slotId"] == "evidence"));
    }
    let delete_refusal_count = attachment_audit_records(&database, &delete_operation, "refusal")
        .await
        .len();
    let delete_refused = send(
        &app,
        Method::DELETE,
        &upload_uri,
        Some(submitter.clone()),
        &[
            ("idempotency-key", "attachment-remove-invalid-body"),
            ("if-match", &uploaded.etag),
        ],
        vec![1],
    )
    .await;
    assert_eq!(delete_refused.status(), StatusCode::BAD_REQUEST);
    let delete_refusals = attachment_audit_records(&database, &delete_operation, "refusal").await;
    assert_eq!(delete_refusals.len(), delete_refusal_count + 1);
    assert!(
        delete_refusals
            .iter()
            .all(|record| record["method"] == "DELETE"
                && record["attachment"]["slotId"] == "evidence")
    );
    let removed = response_parts(
        send(
            &app,
            Method::DELETE,
            &upload_uri,
            Some(submitter.clone()),
            &[
                ("idempotency-key", "attachment-remove"),
                ("if-match", &uploaded.etag),
            ],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.body);
    let delete_audits = attachment_audit_records(&database, &delete_operation, "terminal").await;
    assert!(delete_audits
        .iter()
        .any(|record| record["outcome"] == "committed"
            && record["method"] == "DELETE"
            && record["attachment"]["slotId"] == "evidence"));
    let restored = response_parts(
        send(
            &app,
            Method::PATCH,
            &upload_uri,
            Some(submitter.clone()),
            &[
                ("content-type", "application/octet-stream"),
                ("idempotency-key", "attachment-restore"),
                ("if-match", &removed.etag),
            ],
            bytes.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(restored.status, StatusCode::OK, "{}", restored.body);
    let current = get_record(&app, &record_uri, submitter.clone()).await;
    assert_eq!(current.body["data"]["evidence"]["byteSize"], bytes.len());
    assert_eq!(current.body["data"]["evidence"]["proposalVersion"], 1);
    assert_ne!(current.etag, before.etag);
    let (upload_race, patch_race) = tokio::time::timeout(Duration::from_secs(5), async {
        let upload_headers = [
            ("content-type", "application/octet-stream"),
            ("idempotency-key", "attachment-cross-route-race"),
            ("if-match", current.etag.as_str()),
        ];
        let patch_headers = [
            ("content-type", "application/json-patch+json"),
            ("idempotency-key", "attachment-cross-route-race"),
            ("if-match", current.etag.as_str()),
        ];
        tokio::join!(
            send(
                &app,
                Method::PATCH,
                &upload_uri,
                Some(submitter.clone()),
                &upload_headers,
                bytes.clone()
            ),
            send(
                &app,
                Method::PATCH,
                &record_uri,
                Some(submitter.clone()),
                &patch_headers,
                serde_json::to_vec(
                    &json!([{"op":"replace","path":"/data/reason","value":"same-key race"}])
                )
                .unwrap()
            )
        )
    })
    .await
    .expect("same-key cross-route operations must not deadlock");
    let mut statuses = [upload_race.status().as_u16(), patch_race.status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, [200, 409]);
    let original_hash = current.body["data"]["evidence"]["sha256"]
        .as_str()
        .unwrap()
        .to_owned();

    // Pause after the typed row query. A writer must remain blocked until the
    // metadata and its ETag have been materialized from that same row revision.
    for (index, uri) in [
        record_uri.as_str(),
        "/v1/records/correction-requests?accessProfile=submitter&$select=evidence",
    ]
    .into_iter()
    .enumerate()
    {
        let snapshot = get_record(&app, &record_uri, submitter.clone()).await;
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let paused = router(change_request_service_with_attachment_pause(
            &database,
            registry.clone(),
            identity.clone(),
            PACKAGE_ID,
            None,
            None,
            storage.clone(),
            Some((entered.clone(), resume.clone())),
        ));
        let read_claims = submitter.clone();
        let read_uri = uri.to_owned();
        let reader = tokio::spawn(async move {
            response_parts(
                send(
                    &paused,
                    Method::GET,
                    &read_uri,
                    Some(read_claims),
                    &[],
                    vec![],
                )
                .await,
            )
            .await
        });
        if tokio::time::timeout(Duration::from_secs(3), entered.notified())
            .await
            .is_err()
        {
            resume.notify_one();
            let early = reader.await.unwrap();
            panic!(
                "read {index} missed metadata barrier: {} {}",
                early.status, early.body
            );
        }
        let write_app = app.clone();
        let write_uri = upload_uri.clone();
        let write_claims = submitter.clone();
        let write_etag = snapshot.etag.clone();
        let write_bytes = bytes.clone();
        let writer = tokio::spawn(async move {
            response_parts(
                send(
                    &write_app,
                    Method::PATCH,
                    &write_uri,
                    Some(write_claims),
                    &[
                        ("content-type", "application/octet-stream"),
                        (
                            "idempotency-key",
                            &format!("attachment-consistency-{index}"),
                        ),
                        ("if-match", &write_etag),
                    ],
                    write_bytes,
                )
                .await,
            )
            .await
        });
        let blocked = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let blocked: bool = database.admin.query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid <> pg_backend_pid() AND cardinality(pg_blocking_pids(pid)) > 0)", &[]
                ).await.unwrap().get(0);
                if blocked { break; }
                tokio::task::yield_now().await;
            }
        }).await;
        resume.notify_one();
        let observed = reader.await.unwrap();
        let written = writer.await.unwrap();
        blocked.expect("attachment write waits for the request-state read lock");
        assert_eq!(observed.status, StatusCode::OK, "{}", observed.body);
        assert_eq!(written.status, StatusCode::OK, "{}", written.body);
        let observed_data = if index == 0 {
            &observed.body["data"]
        } else {
            &observed.body["items"][0]["data"]
        };
        assert_eq!(observed_data["evidence"], snapshot.body["data"]["evidence"]);
        if index == 0 {
            assert_eq!(observed.etag, snapshot.etag);
        }
        assert_ne!(written.etag, snapshot.etag);
    }

    let list = response_parts(
        send(
            &app,
            Method::GET,
            "/v1/records/correction-requests?accessProfile=submitter&$select=evidence",
            Some(submitter.clone()),
            &[],
            vec![],
        )
        .await,
    )
    .await;
    assert_eq!(
        list.status,
        StatusCode::OK,
        "attachment-only list projection {}",
        list.body
    );
    assert_eq!(
        list.body["items"][0]["data"]["evidence"]["byteSize"],
        bytes.len()
    );
    assert!(list.body["items"][0]["data"].get("reason").is_none());

    let download_uri = format!("/v1/records/correction-requests/{}/attachments/evidence?proposalVersion=1&accessProfile=submitter",draft.id);
    let downloaded = send(
        &app,
        Method::GET,
        &download_uri,
        Some(submitter.clone()),
        &[],
        vec![],
    )
    .await;
    assert_eq!(downloaded.status(), StatusCode::OK);
    assert_eq!(
        downloaded.headers()["content-type"],
        "application/octet-stream"
    );
    assert_eq!(downloaded.headers()["cache-control"], "no-store");
    assert_eq!(downloaded.headers()["x-content-type-options"], "nosniff");
    assert!(downloaded.headers()["content-disposition"]
        .to_str()
        .unwrap()
        .starts_with("attachment"));
    assert_eq!(
        to_bytes(downloaded.into_body(), 1024)
            .await
            .unwrap()
            .as_ref(),
        bytes
    );
    let audit: Value = database.admin.query_one(
        "SELECT convert_from(envelope, 'UTF8')::jsonb -> 'record' FROM registry_internal.registry_audit WHERE convert_from(envelope, 'UTF8')::jsonb #>> '{record,attachment,slotId}' = 'evidence' AND convert_from(envelope, 'UTF8')::jsonb #>> '{record,method}' = 'GET' LIMIT 1", &[]
    ).await.unwrap().get(0);
    assert_eq!(
        audit["attachment"],
        json!({"slotId":"evidence","proposalVersion":1})
    );
    assert_eq!(audit["entityId"], "correction-request");
    assert!(audit.get("actionId").is_none());
    assert_eq!(audit["outcome"], "returned");
    assert_eq!(audit["operationId"], get_operation);
    assert!(
        !attachment_audit_records(&database, &get_operation, "attempt")
            .await
            .is_empty()
    );
    for (uri, actor) in [
        (
            download_uri.clone(),
            Some(claims("submitter", OTHER_SUBMITTER, None)),
        ),
        (download_uri.clone(), None),
        (
            download_uri.replace("accessProfile=submitter", "accessProfile=hidden-owner"),
            Some(submitter.clone()),
        ),
        (
            download_uri.replace("proposalVersion=1", "proposalVersion=2"),
            Some(submitter.clone()),
        ),
        (
            download_uri.replace("/evidence?", "/undeclared?"),
            Some(submitter.clone()),
        ),
    ] {
        let denied = send(&app, Method::GET, &uri, actor, &[], vec![]).await;
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);
    }
    let submitted = run_action(
        &app,
        &draft.id,
        "correction-requests",
        "submitter",
        submitter.clone(),
        "attachment-submit",
        "submit_request",
        None,
        |_| json!({}),
    )
    .await;
    assert_eq!(submitted["request"]["proposalVersion"], 1);
    for profile in [
        "reviewer-no-slot",
        "reviewer-empty-slot",
        "reviewer-other-stage",
    ] {
        let actor = claims(profile, REVIEWER, Some("review"));
        let metadata = get_record(
            &app,
            &record_uri.replace(
                "accessProfile=submitter",
                &format!("accessProfile={profile}"),
            ),
            actor.clone(),
        )
        .await;
        assert_eq!(metadata.body["data"]["evidence"]["sha256"], Value::Null);
        assert_eq!(
            send(
                &app,
                Method::GET,
                &download_uri.replace(
                    "accessProfile=submitter",
                    &format!("accessProfile={profile}")
                ),
                Some(actor),
                &[],
                vec![]
            )
            .await
            .status(),
            StatusCode::NOT_FOUND,
            "{profile} cannot borrow a slot grant from GET or a different stage"
        );
    }
    let first_reason = get_record(&app, &record_uri, submitter.clone()).await.body["data"]
        ["reason"]
        .as_str()
        .unwrap()
        .to_owned();
    for profile in ["reviewer-self-reason", "applier-self-reason"] {
        for (reason, expected) in [
            (first_reason.as_str(), StatusCode::OK),
            ("unrelated reason", StatusCode::NOT_FOUND),
        ] {
            let uri = download_uri.replace(
                "accessProfile=submitter",
                &format!("accessProfile={profile}"),
            );
            assert_eq!(
                send(
                    &app,
                    Method::GET,
                    &uri,
                    Some(attachment_self_reason_claims(profile, reason)),
                    &[],
                    vec![]
                )
                .await
                .status(),
                expected,
                "request-self boundary controls {profile}"
            );
        }
    }

    for (profile, principal, purpose) in [
        ("reviewer", REVIEWER, "review"),
        ("applier", APPLIER, "apply"),
    ] {
        let uri = download_uri.replace(
            "accessProfile=submitter",
            &format!("accessProfile={profile}"),
        );
        let response = send(
            &app,
            Method::GET,
            &uri,
            Some(claims(profile, principal, Some(purpose))),
            &[],
            vec![],
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{profile} exact frozen target grant permits download"
        );
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
            bytes
        );
    }
    let wrong_target_claims = VerifiedRequestClaims::authenticated(
        "registry_principal",
        REVIEWER,
        BTreeSet::new(),
        Some("review".to_owned()),
        BTreeMap::from([
            (
                "tenant_claim".to_owned(),
                VerifiedClaimValue::direct_string(TENANT).unwrap(),
            ),
            (
                "target_tenant_claim".to_owned(),
                VerifiedClaimValue::direct_string("tenant-b").unwrap(),
            ),
        ]),
    )
    .unwrap();
    let denied = send(
        &app,
        Method::GET,
        &download_uri.replace(
            "accessProfile=submitter",
            "accessProfile=other-target-reviewer",
        ),
        Some(wrong_target_claims.clone()),
        &[],
        vec![],
    )
    .await;
    assert_eq!(
        denied.status(),
        StatusCode::NOT_FOUND,
        "request GET cannot bypass target grant boundaries"
    );
    let revised = run_action(
        &app,
        &draft.id,
        "correction-requests",
        "submitter",
        submitter.clone(),
        "attachment-revise",
        "revise_request",
        None,
        |_| json!({"rebase":true}),
    )
    .await;
    assert_eq!(revised["request"]["proposalVersion"], 2);
    let current = get_record(&app, &record_uri, submitter.clone()).await;
    let edited = send(
        &app,
        Method::PATCH,
        &record_uri,
        Some(submitter.clone()),
        &[
            ("content-type", "application/json-patch+json"),
            ("idempotency-key", "attachment-second-reason"),
            ("if-match", &current.etag),
        ],
        serde_json::to_vec(
            &json!([{"op":"replace","path":"/data/reason","value":"second proposal reason"}]),
        )
        .unwrap(),
    )
    .await;
    assert_eq!(edited.status(), StatusCode::OK);
    let current = get_record(&app, &record_uri, submitter.clone()).await;
    let replacement = vec![1, 2, 3, 4, 5];
    let replaced = response_parts(
        send(
            &app,
            Method::PATCH,
            &upload_uri,
            Some(submitter.clone()),
            &[
                ("content-type", "application/octet-stream"),
                ("idempotency-key", "attachment-replace"),
                ("if-match", &current.etag),
            ],
            replacement.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(replaced.status, StatusCode::OK, "{}", replaced.body);
    for (version, expected) in [(1, bytes.as_slice()), (2, replacement.as_slice())] {
        let uri = download_uri.replace("proposalVersion=1", &format!("proposalVersion={version}"));
        let response = send(
            &app,
            Method::GET,
            &uri,
            Some(submitter.clone()),
            &[],
            vec![],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
            expected,
            "replacement preserves the frozen prior version"
        );
    }
    run_action(
        &app,
        &draft.id,
        "correction-requests",
        "submitter",
        submitter.clone(),
        "attachment-resubmit",
        "submit_request",
        None,
        |_| json!({}),
    )
    .await;
    for profile in ["applier-self-reason"] {
        for (version, reason, expected) in [
            (1, first_reason.as_str(), StatusCode::OK),
            (1, "second proposal reason", StatusCode::NOT_FOUND),
            (2, "second proposal reason", StatusCode::OK),
        ] {
            let uri = download_uri
                .replace(
                    "accessProfile=submitter",
                    &format!("accessProfile={profile}"),
                )
                .replace("proposalVersion=1", &format!("proposalVersion={version}"));
            assert_eq!(
                send(
                    &app,
                    Method::GET,
                    &uri,
                    Some(attachment_self_reason_claims(profile, reason)),
                    &[],
                    vec![]
                )
                .await
                .status(),
                expected,
                "{profile} version {version} with reason {reason:?} reads only the exact proposal's authorized intake"
            );
        }
    }
    let previous = send(
        &app,
        Method::GET,
        &download_uri.replace("accessProfile=submitter", "accessProfile=reviewer"),
        Some(claims("reviewer", REVIEWER, Some("review"))),
        &[],
        vec![],
    )
    .await;
    assert_eq!(
        previous.status(),
        StatusCode::OK,
        "a directly authorized reader can retrieve the retained prior attachment"
    );
    assert_eq!(
        to_bytes(previous.into_body(), 1024).await.unwrap().as_ref(),
        bytes
    );
    if matches!(
        storage,
        registry_breg::attachment_storage::AttachmentStorage::Database
    ) {
        let corrupt = vec![7u8; bytes.len()];
        database
            .admin
            .execute(
                "UPDATE registry_internal.registry_attachment_blobs SET content=$1 WHERE sha256=$2",
                &[&corrupt, &original_hash],
            )
            .await
            .unwrap();
        let withheld_corrupt = send(
            &app,
            Method::GET,
            &download_uri,
            Some(submitter.clone()),
            &[],
            vec![],
        )
        .await;
        assert_eq!(
            withheld_corrupt.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "stored hash mismatch never releases a successful binary response"
        );
        database
            .admin
            .execute(
                "UPDATE registry_internal.registry_attachment_blobs SET content=$1 WHERE sha256=$2",
                &[&bytes, &original_hash],
            )
            .await
            .unwrap();
    }
    let faulty = router(change_request_service_with_attachment_storage(
        &database,
        registry.clone(),
        identity.clone(),
        PACKAGE_ID,
        None,
        Some(registry_breg::postgres::ReadFaultPoint::BeforeTerminalAudit),
        storage.clone(),
    ));
    let withheld = send(
        &faulty,
        Method::GET,
        &download_uri,
        Some(submitter.clone()),
        &[],
        vec![],
    )
    .await;
    assert_eq!(withheld.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!to_bytes(withheld.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .windows(bytes.len())
        .any(|window| window == bytes));
    drop(faulty);
    run_action(
        &app,
        &draft.id,
        "correction-requests",
        "submitter",
        submitter.clone(),
        "attachment-cancel",
        "cancel_request",
        None,
        |_| json!({}),
    )
    .await;
    // A same-schema successor may narrow future uploads after the active
    // proposal becomes terminal. Its current read grant still admits the
    // immutable bytes accepted by the earlier proposal declaration.
    let mut successor_project = project.clone();
    let mut successor_identity = identity.clone();
    let mut successor_registry = registry.clone();
    for (index, narrow_mime) in [false, true].into_iter().enumerate() {
        let slot = &mut successor_project
            .entities
            .iter_mut()
            .find(|entity| entity.id == "correction-request")
            .unwrap()
            .attachments[0];
        slot.maximum_bytes = 1;
        if narrow_mime {
            slot.content_types = vec!["application/pdf".to_owned()];
        }
        successor_registry =
            Arc::new(compile_project(&successor_project, &[], CompileProfile::Authoring).unwrap());
        let (migration, migration_task) = database.connect_migration().await;
        registry_breg::request_retention::guard_successor_activation(
            &migration,
            &successor_registry,
        )
        .await
        .unwrap();
        assert_eq!(
            registry_breg::postgres::managed_schema_fingerprint(
                &migration,
                &database.runtime_role,
                &registry_breg::postgres::ExpectedManagedCatalog::compiled(&successor_registry)
            )
            .await
            .unwrap(),
            identity.schema_fingerprint,
            "attachment upload policy narrowing preserves installed scalar schema"
        );
        drop(migration);
        migration_task.abort();
        successor_identity.package_revision = format!("attachment-policy-successor-{index}");
        successor_identity.package_sequence += 1;
        database.admin.execute("UPDATE registry_internal.registry_state SET active_package_revision=$1, package_sequence=$2 WHERE singleton", &[&successor_identity.package_revision, &successor_identity.package_sequence]).await.unwrap();
        let successor = router(change_request_service_with_attachment_storage(
            &database,
            successor_registry.clone(),
            successor_identity.clone(),
            PACKAGE_ID,
            None,
            None,
            storage.clone(),
        ));
        for (version, expected) in [(1, bytes.as_slice()), (2, replacement.as_slice())] {
            let uri =
                download_uri.replace("proposalVersion=1", &format!("proposalVersion={version}"));
            for (profile, actor) in [
                ("submitter", submitter.clone()),
                ("reviewer", claims("reviewer", REVIEWER, Some("review"))),
                ("applier", claims("applier", APPLIER, Some("apply"))),
            ] {
                let uri = uri.replace(
                    "accessProfile=submitter",
                    &format!("accessProfile={profile}"),
                );
                let response = send(&successor, Method::GET, &uri, Some(actor), &[], vec![]).await;
                assert_eq!(
                    response.status(),
                    StatusCode::OK,
                    "retained version {version} remains readable after policy narrowing {index}"
                );
                assert_eq!(
                    response.headers()["content-type"],
                    "application/octet-stream"
                );
                assert_eq!(
                    to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
                    expected
                );
            }
            let denied = send(
                &successor,
                Method::GET,
                &uri.replace(
                    "accessProfile=submitter",
                    "accessProfile=other-target-reviewer",
                ),
                Some(wrong_target_claims.clone()),
                &[],
                vec![],
            )
            .await;
            assert_eq!(denied.status(), StatusCode::NOT_FOUND, "historical attachment authorization still requires exact selected target boundaries");
            assert_eq!(
                send(
                    &successor,
                    Method::GET,
                    &uri.replace("accessProfile=submitter", "accessProfile=hidden-owner"),
                    Some(submitter.clone()),
                    &[],
                    vec![]
                )
                .await
                .status(),
                StatusCode::NOT_FOUND,
                "successor still enforces current selected slot readability"
            );
        }
    }
    let registry = successor_registry;
    let identity = successor_identity;
    let app = router(change_request_service_with_attachment_storage(
        &database,
        registry.clone(),
        identity.clone(),
        PACKAGE_ID,
        None,
        None,
        storage.clone(),
    ));
    let retention =
        registry_breg::request_retention::RequestRetentionOperatorService::new_for_test(
            registry.as_ref().clone(),
            identity,
            registry_breg::postgres::ExpectedManagedCatalog::compiled(&registry),
            RegistryLockKey::derive(PACKAGE_ID).unwrap(),
            database.migration_config.clone(),
            database.migration_role.clone(),
            database.runtime_role.clone(),
            AuditProfile::production_from_secret_bytes(vec![0x9a; 32].into()).unwrap(),
        )
        .with_attachment_storage_for_test(storage.clone());
    for version in [1, 2] {
        let scope = registry_breg::request_retention::RequestDetailErasureScope {
            request_entity_id: "correction-request",
            request_id: Uuid::parse_str(&draft.id).unwrap(),
            proposal_version: version,
        };
        assert_eq!(
            retention
                .dry_run(scope.clone())
                .await
                .unwrap()
                .erasure
                .attachment_references,
            1
        );
        let erased = retention.erase(scope).await.unwrap();
        assert_eq!(erased.erasure.attachment_references, 1);
        assert_eq!(erased.pending_external_deletions, 0);
        if let registry_breg::attachment_storage::AttachmentStorage::S3(store) = &storage {
            assert!(erased.external_deletion_tombstones >= 1);
            if version == 1 {
                assert_eq!(
                    store
                        .get(&original_hash, bytes.len() as u64)
                        .await
                        .unwrap_err(),
                    registry_breg::attachment_storage::AttachmentStorageError::Missing
                );
            }
        }
        let uri = download_uri.replace("proposalVersion=1", &format!("proposalVersion={version}"));
        assert_eq!(
            send(
                &app,
                Method::GET,
                &uri,
                Some(submitter.clone()),
                &[],
                vec![]
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }
    let erased = get_record(&app, &record_uri, submitter).await;
    let metadata = &erased.body["data"]["evidence"];
    assert_eq!(metadata["erased"], true);
    assert!(metadata.get("uploadedBy").is_none());
    assert!(metadata.get("uploadedAt").is_none());
    assert_eq!(metadata["byteSize"], replacement.len());
    drop(app);
    database.cleanup().await;
}

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
    let applier = claims("applier", APPLIER, Some("apply"));
    assert_served_action_openapi_refs(&app, applier.clone()).await;

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
    assert_eq!(before_submit.body["request"]["bregState"], "draft");
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
    assert_eq!(submitted["request"]["bregState"], "submitted");
    assert_eq!(submitted["request"]["proposalVersion"], 1);
    let effect_digest = submitted["request"]["effectDigest"]
        .as_str()
        .expect("submission freezes an effect digest")
        .to_owned();
    assert!(effect_digest.starts_with("sha256:"));
    assert_eq!(submitted["request"]["application"], Value::Null);

    let targets = request_targets(&database, "correction-request", &request.id).await;
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0]["entityId"], "asset-placement");
    assert_eq!(targets[0]["recordId"], placement.id);
    assert_eq!(targets[0]["operation"], "patch");
    assert_eq!(targets[0]["baseRevision"], 1);
    assert_eq!(
        targets[0]["before"],
        json!({"tenant":TENANT,"site":old_site.id,"valid-from":"2026-08-31","valid-to":null})
    );
    assert_eq!(
        targets[0]["after"],
        json!({"tenant":TENANT,"site":new_site.id,"valid-from":"2026-08-31","valid-to":null})
    );

    let before_apply = get_record(
        &app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=applier",
            request.id
        ),
        applier.clone(),
    )
    .await;
    assert_eq!(before_apply.body["request"]["bregState"], "submitted");
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
    assert_eq!(applied["request"]["bregState"], "applied");
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
    assert_eq!(after_apply.body["request"]["bregState"], "applied");
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
    assert!(submitted["request"]["effectDigest"].is_string());

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
    assert_eq!(replayed.body["request"]["bregState"], "applied");
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
    assert_eq!(different_key.body["request"]["bregState"], "applied");
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
        assert_eq!(response.body["request"]["bregState"], "applied");
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
        request_after_fault.body["request"]["bregState"],
        "submitted"
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
    // Preparation retains both before and after target snapshots. Keep this
    // fixture above the internal stored-packet limit as that limit grows to
    // accommodate encrypted-envelope expansion.
    let large_note =
        "x".repeat(registry_breg::request_workflow::MAX_REQUEST_SNAPSHOT_BYTES / 2 + 64 * 1024);
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
    let server = serve_change_request_client_http(app.clone()).await;
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
    assert!(submitted["request"]["effectDigest"].is_string());
    let targets = request_targets(&database, "registration-request", &request.id).await;
    assert_eq!(targets.len(), 3);
    let person_id = target_record_id(&targets, "person");
    let membership_id = target_record_id(&targets, "membership");
    assert_ne!(person_id, membership_id);
    assert_eq!(
        target_after(&targets, "person"),
        json!({"tenant": TENANT, "display-name": "Ada Lovelace"})
    );
    assert_eq!(
        target_after(&targets, "membership"),
        json!({"tenant": TENANT, "household": household.id, "person": person_id})
    );
    assert_eq!(
        target_after(&targets, "household"),
        json!({"tenant":TENANT,"label":"household one","contact-person":person_id})
    );

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
    assert_eq!(applied["request"]["bregState"], "applied");

    let operator_client = change_request_client(server.base_url(), "operator-token");
    let options = BRegRecordOptions::default()
        .access_profile("operator")
        .expect("operator profile is valid");
    let request_record = operator_client
        .get_record("registration-requests", &request.id, &options)
        .await
        .expect("the maintained client reads retained request results");
    let request_metadata = BRegRequestMetadata::from_record(&request_record.value.data)
        .expect("retained request metadata conforms")
        .expect("registration request metadata is present");
    let request_identifier = Uuid::parse_str(&request.id).expect("request id is a UUID");
    let proposal_version = request_metadata.proposal_version();
    let application_identifier = match request_metadata
        .application()
        .expect("the applied request retains application identity")
    {
        registry_breg_client::BRegRecordApplication::Retained(application) => {
            application.application_identifier()
        }
        registry_breg_client::BRegRecordApplication::Erased(application) => {
            application.application_identifier()
        }
    };
    let application_identifier =
        Uuid::parse_str(application_identifier).expect("application id is a UUID");
    let proposal = request_metadata
        .retained_history()
        .expect("the applied proposal is loaded explicitly")
        .find_application(
            &request_record.value.meta.entity_type_identifier,
            request_identifier,
            proposal_version,
            application_identifier,
        )
        .expect("the loaded page contains the exact applied proposal");
    assert_eq!(proposal.result_link_count(), 3);
    assert_eq!(proposal.result_references().len(), 3);
    let person_result = proposal
        .result_references()
        .iter()
        .find(|result| result.target_entity_identifier() == "person")
        .expect("the operator sees the created person result");
    assert_eq!(
        person_result.target_record_identifier().to_string(),
        person_id
    );
    assert_eq!(person_result.target_revision(), 1);

    let current_person = operator_client
        .get_record("people", &person_id, &options)
        .await
        .expect("an ordinary authorized GET resolves the current person");
    assert_eq!(current_person.value.data.revision_identifier, "1");
    let contract = operator_client
        .registry_contract(Some("operator"))
        .await
        .expect("caller-filtered metadata loads");
    let BRegDirectWrite::Patch(person_patch) = contract
        .value
        .select_direct_write("records.person.patch", "operator")
        .expect("operator selects the ordinary person PATCH")
    else {
        panic!("person Patch binding")
    };
    let patch = BRegPatchRequest::builder()
        .replace("displayName", json!("Ada Byron"))
        .expect("displayName is writable")
        .build()
        .expect("person PATCH is bounded");
    let current_etag = current_person
        .metadata
        .etag()
        .expect("ordinary GET returns the current record ETag")
        .clone();
    let advanced_person = operator_client
        .patch_record(
            &person_patch,
            Uuid::parse_str(&person_id).expect("captured person id is a UUID"),
            &current_etag,
            &patch,
            &BRegIdempotencyKey::parse("advance-applied-person").unwrap(),
            BRegRecordFormat::Json,
        )
        .await
        .expect("ordinary authorized PATCH advances the target");
    assert_eq!(advanced_person.value.data.revision_identifier, "2");
    let refreshed_request = operator_client
        .get_record("registration-requests", &request.id, &options)
        .await
        .expect("fresh result navigation rechecks current authority");
    let refreshed_metadata = BRegRequestMetadata::from_record(&refreshed_request.value.data)
        .unwrap()
        .unwrap();
    let refreshed_proposal = refreshed_metadata
        .retained_history()
        .unwrap()
        .find_application(
            &refreshed_request.value.meta.entity_type_identifier,
            request_identifier,
            proposal_version,
            application_identifier,
        )
        .expect("the exact applied proposal remains selectable");
    let refreshed_person_result = refreshed_proposal
        .result_references()
        .iter()
        .find(|result| result.target_entity_identifier() == "person")
        .unwrap();
    assert_eq!(
        refreshed_person_result.target_revision(),
        1,
        "the result revision remains application provenance after the target advances"
    );

    let person = get_record(
        &app,
        &format!("/v1/records/people/{person_id}?accessProfile=operator"),
        operator.clone(),
    )
    .await;
    assert_eq!(person.body["revision"], 2);
    assert_eq!(person.body["data"]["displayName"], "Ada Byron");

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
    assert_revision_operations_include(
        &person_revisions,
        &["records.person.create", "records.person.patch"],
    );
    assert!(person_revisions
        .iter()
        .all(|revision| !revision["operationId"]
            .as_str()
            .expect("operation id")
            .contains("registration-request")));
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
            "records.registration-request.request.submit",
            "records.registration-request.create",
        ],
    );
    assert_eq!(application_result_count(&database).await, 3);
    server.finish().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sdk_prepared_lifecycle_recovery_replays_after_the_original_action_disappears() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(registration_registry());
    let identity =
        install_registry(&database, &registry, "registration-change-request", false).await;
    let app = change_request_router(
        &database,
        registry,
        identity,
        "registration-change-request",
        None,
    );
    let operator = claims("operator", "registration-operator", None);
    let household = create_record(
        &app,
        "/v1/records/households?accessProfile=steward",
        claims("steward", "registration-steward", None),
        "sdk-recovery-household",
        json!({"tenant": TENANT, "label": "recovery household"}),
    )
    .await;
    let http = client_http::ClientHttp::start(app, operator).await;
    let client = &http.client;
    let contract = client.registry_contract(Some("operator")).await.unwrap();
    let BRegDirectWrite::Create(create_binding) = contract
        .value
        .select_direct_write("records.registration-request.create", "operator")
        .unwrap()
    else {
        panic!("Create binding")
    };
    let authority = contract
        .value
        .select_lifecycle("registration-request", "operator")
        .unwrap();
    let request = BRegCreateRequest::new(
        json!({"tenant":TENANT,"household":household.id,"name":"Prepared recovery"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .unwrap();
    let created = client
        .create_record(
            &create_binding,
            &request,
            &BRegIdempotencyKey::parse("sdk-lifecycle-create").unwrap(),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let record_id = created.value.data.record_identifier.clone();
    let options = BRegRecordOptions::default()
        .access_profile("operator")
        .unwrap();
    let draft = client
        .get_record("registration-requests", &record_id, &options)
        .await
        .unwrap();
    let submit = client
        .lifecycle_actions(&authority, &draft.value)
        .unwrap()
        .into_iter()
        .find(|action| action.operation() == BRegLifecycleOperation::SubmitRequest)
        .expect("draft advertises SubmitRequest");
    let original_key = BRegIdempotencyKey::parse("sdk-lifecycle-submit").unwrap();
    let prepared = client
        .prepare_lifecycle_action(&authority, &draft.value, &submit, &original_key)
        .unwrap();
    let saved = BRegPreparedLifecycle::from_slice(prepared.as_bytes()).unwrap();
    let committed = client
        .execute_lifecycle_action(&submit, &original_key)
        .await
        .unwrap();

    let current = client
        .get_record("registration-requests", &record_id, &options)
        .await
        .unwrap();
    assert!(client
        .lifecycle_actions(&authority, &current.value)
        .unwrap()
        .iter()
        .all(|action| action.operation() != BRegLifecycleOperation::SubmitRequest));

    let fresh_contract = client.registry_contract(Some("operator")).await.unwrap();
    let fresh_authority = fresh_contract
        .value
        .select_lifecycle("registration-request", "operator")
        .unwrap();
    let (recovered, recovered_key) = client
        .recover_lifecycle_action(&fresh_authority, &saved)
        .unwrap();
    assert_eq!(recovered.operation(), BRegLifecycleOperation::SubmitRequest);
    assert_eq!(recovered.href(), submit.href());
    assert_eq!(recovered.if_match(), submit.if_match());
    assert_eq!(recovered_key.as_str(), original_key.as_str());
    let replayed = client
        .execute_lifecycle_action(&recovered, &recovered_key)
        .await
        .unwrap();
    assert_eq!(replayed.value, committed.value);

    drop(http);
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
    assert!(submitted["request"]["effectDigest"].is_string());
    let targets = request_targets(&database, "registration-request", &request.id).await;
    let person_id = target_record_id(&targets, "person");
    let membership_id = target_record_id(&targets, "membership");

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
        &database,
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
    let approved = create_approved_registration(
        &database,
        &app,
        steward,
        operator.clone(),
        "sql-retry-succeeds",
    )
    .await;
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
    assert_eq!(applied.body["request"]["bregState"], "applied");
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
        create_approved_registration(&database, &app, steward, operator.clone(), "sql-deadline")
            .await;

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
    let approved = create_approved_registration(
        &database,
        &app,
        steward,
        operator.clone(),
        "startup-timeout",
    )
    .await;

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
async fn real_postgres_http_change_request_cancel_belongs_to_the_request_owner() {
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
    let owner = claims("submitter", SUBMITTER, None);
    let other = claims("submitter", OTHER_SUBMITTER, None);

    let old_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "owner-cancel-old-site",
        json!({"tenant": TENANT, "name": "owner-cancel-old"}),
    )
    .await;
    let new_site = create_record(
        &app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "owner-cancel-new-site",
        json!({"tenant": TENANT, "name": "owner-cancel-new"}),
    )
    .await;
    let placement = create_record(
        &app,
        "/v1/records/placements?accessProfile=steward",
        steward,
        "owner-cancel-placement",
        json!({"tenant": TENANT, "site": old_site.id}),
    )
    .await;
    let request = create_record(
        &app,
        "/v1/records/correction-requests?accessProfile=submitter",
        owner.clone(),
        "owner-cancel-correction-request",
        json!({
            "tenant": TENANT,
            "placement": placement.id,
            "proposedSite": new_site.id,
            "reason": "owner-only cancel"
        }),
    )
    .await;
    let uri = format!(
        "/v1/records/correction-requests/{}?accessProfile=submitter",
        request.id
    );

    let owner_draft = get_record(&app, &uri, owner.clone()).await;
    let draft_cancel = action(&owner_draft.body, "cancel_request", None);

    // A missing required header names itself so the fix does not require
    // reading the generated OpenAPI: the header name is fixed, known
    // constant, never request content.
    let missing_idempotency = response_parts(
        send(
            &app,
            Method::POST,
            &draft_cancel.href,
            Some(owner.clone()),
            &[
                ("content-type", "application/json"),
                ("if-match", &draft_cancel.if_match),
            ],
            serde_json::to_vec(&json!({})).expect("action body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(missing_idempotency.status, StatusCode::BAD_REQUEST);
    assert_eq!(missing_idempotency.body["code"], "request.invalid");
    assert_eq!(missing_idempotency.body["fieldPath"], "Idempotency-Key");
    let still_draft_before_cancel = get_record(&app, &uri, owner.clone()).await;
    assert_eq!(
        action(&still_draft_before_cancel.body, "cancel_request", None).if_match,
        draft_cancel.if_match,
        "a header refusal leaves the record and workflow revisions where they were"
    );

    let other_draft = get_record(&app, &uri, other.clone()).await;
    assert_eq!(
        other_draft.body["request"]["bregState"], "draft",
        "the second submitter shares the tenant boundary and reads the request"
    );
    assert_cancel_is_not_offered(&other_draft.body);

    let refused_draft = send_action(
        &app,
        &draft_cancel,
        "owner-cancel-other-principal-draft",
        other.clone(),
        json!({}),
    )
    .await;
    assert_eq!(refused_draft.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(refused_draft.body["code"], "precondition.failed");

    let still_draft = get_record(&app, &uri, owner.clone()).await;
    assert_eq!(still_draft.body["request"]["bregState"], "draft");
    assert_eq!(
        action(&still_draft.body, "cancel_request", None).if_match,
        draft_cancel.if_match,
        "a refused cancel leaves the record and workflow revisions where they were"
    );

    let submitted = run_action(
        &app,
        &request.id,
        "correction-requests",
        "submitter",
        owner.clone(),
        "owner-cancel-submit",
        "submit_request",
        None,
        |_| json!({}),
    )
    .await;
    assert_eq!(submitted["request"]["bregState"], "submitted");

    let owner_submitted = get_record(&app, &uri, owner.clone()).await;
    let submitted_cancel = action(&owner_submitted.body, "cancel_request", None);

    let other_submitted = get_record(&app, &uri, other.clone()).await;
    assert_cancel_is_not_offered(&other_submitted.body);

    let refused_submitted = send_action(
        &app,
        &submitted_cancel,
        "owner-cancel-other-principal-submitted",
        other,
        json!({}),
    )
    .await;
    assert_eq!(refused_submitted.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(refused_submitted.body["code"], "precondition.failed");

    let still_submitted = get_record(&app, &uri, owner.clone()).await;
    assert_eq!(still_submitted.body["request"]["bregState"], "submitted");
    assert_eq!(
        action(&still_submitted.body, "cancel_request", None).if_match,
        submitted_cancel.if_match,
        "a refused cancel leaves the record and workflow revisions where they were"
    );

    let canceled = action_response(
        &app,
        &submitted_cancel.href,
        "owner-cancel-own-request",
        &submitted_cancel.if_match,
        owner,
        json!({}),
    )
    .await;
    assert_eq!(canceled["request"]["bregState"], "cancelled");
    database.cleanup().await;
}

fn assert_cancel_is_not_offered(body: &Value) {
    let actions = body["request"]["actions"].clone();
    assert!(
        actions.as_array().is_none_or(|actions| actions
            .iter()
            .all(|action| action["operation"] != "cancel_request")),
        "cancel is the owner's withdrawal and must not be offered to another principal: {actions}"
    );
}

struct ChangeRequestClientHttpServer {
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

struct ReviewResultAuthorityState {
    mode: AtomicUsize,
    lookups: AtomicUsize,
    result: Mutex<Value>,
}

async fn controlled_review_result(
    State(state): State<Arc<ReviewResultAuthorityState>>,
    Path(request_id): Path<Uuid>,
) -> axum::response::Response {
    state.lookups.fetch_add(1, Ordering::SeqCst);
    match state.mode.load(Ordering::SeqCst) {
        0 => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        1 => (
            StatusCode::GONE,
            [(
                "traceparent",
                "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
            )],
        )
            .into_response(),
        2 => {
            let result = state.result.lock().expect("review result state").clone();
            assert_eq!(result["requestId"], request_id.to_string());
            (
                StatusCode::OK,
                [(
                    "traceparent",
                    "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
                )],
                axum::Json(result),
            )
                .into_response()
        }
        mode => panic!("unexpected review authority mode {mode}"),
    }
}

async fn serve_review_result_authority() -> (
    reqwest::Url,
    Arc<ReviewResultAuthorityState>,
    JoinHandle<()>,
) {
    let state = Arc::new(ReviewResultAuthorityState {
        mode: AtomicUsize::new(0),
        lookups: AtomicUsize::new(0),
        result: Mutex::new(json!({})),
    });
    let app = axum::Router::new()
        .route(
            "/v1/review-requests/{request_id}/result",
            axum::routing::get(controlled_review_result),
        )
        .with_state(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("review authority listener");
    let endpoint = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("review authority serves")
    });
    (endpoint, state, task)
}

fn review_authority_registry(endpoint: reqwest::Url) -> Arc<ReviewAuthorityRegistry> {
    let client = registry_review_client::ReviewClient::new(
        registry_review_client::ReviewClientConfig::new(endpoint).with_profile("producer-profile"),
    )
    .expect("review client");
    let authority = Arc::new(
        ReviewAuthorityClient::new(
            "casework-a".to_owned(),
            client,
            Arc::new(
                registry_platform_httputil::StaticToken::new("producer-token".to_owned())
                    .expect("review token"),
            ),
            "registry-producer".to_owned(),
            7,
            None,
            None,
        )
        .expect("review authority"),
    );
    Arc::new(
        ReviewAuthorityRegistry::new(BTreeMap::from([("casework-a".to_owned(), authority)]))
            .expect("review authority registry"),
    )
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
            "Bearer operator-token" => Some(claims("operator", "registration-operator", None)),
            _ => None,
        });
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    next.run(request).await
}

fn change_request_client(base_url: &str, token: &str) -> BaseRegistryClient {
    let config = BaseRegistryClientConfig::new(
        base_url
            .parse()
            .expect("change-request client loopback URL parses"),
    )
    .with_token_provider(Arc::new(
        StaticToken::new(token).expect("change-request client token is an outbound bearer value"),
    ));
    BaseRegistryClient::new(config).expect("change-request client config is valid")
}

fn change_request_router(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    package_id: &str,
    fault: Option<MutationFaultPoint>,
) -> axum::Router {
    router(change_request_service(
        database, registry, identity, package_id, fault,
    ))
}

fn change_request_service(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    package_id: &str,
    fault: Option<MutationFaultPoint>,
) -> Arc<HttpService> {
    change_request_service_with_read_fault(database, registry, identity, package_id, fault, None)
}

fn change_request_service_with_read_fault(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    package_id: &str,
    fault: Option<MutationFaultPoint>,
    read_fault: Option<registry_breg::postgres::ReadFaultPoint>,
) -> Arc<HttpService> {
    change_request_service_with_attachment_storage(
        database,
        registry,
        identity,
        package_id,
        fault,
        read_fault,
        registry_breg::attachment_storage::AttachmentStorage::Database,
    )
}

fn change_request_service_with_attachment_storage(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    package_id: &str,
    fault: Option<MutationFaultPoint>,
    read_fault: Option<registry_breg::postgres::ReadFaultPoint>,
    storage: registry_breg::attachment_storage::AttachmentStorage,
) -> Arc<HttpService> {
    change_request_service_with_attachment_pause(
        database, registry, identity, package_id, fault, read_fault, storage, None,
    )
}

#[allow(clippy::too_many_arguments)]
fn change_request_service_with_attachment_pause(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    package_id: &str,
    fault: Option<MutationFaultPoint>,
    read_fault: Option<registry_breg::postgres::ReadFaultPoint>,
    storage: registry_breg::attachment_storage::AttachmentStorage,
    pause: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
) -> Arc<HttpService> {
    change_request_service_with_attachment_verification(
        database,
        registry,
        identity,
        package_id,
        fault,
        read_fault,
        storage,
        pause,
        registry_breg::attachment_verification::AttachmentVerification::Disabled,
    )
}

#[allow(clippy::too_many_arguments)]
fn change_request_service_with_attachment_verification(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    package_id: &str,
    fault: Option<MutationFaultPoint>,
    read_fault: Option<registry_breg::postgres::ReadFaultPoint>,
    storage: registry_breg::attachment_storage::AttachmentStorage,
    pause: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    verification: registry_breg::attachment_verification::AttachmentVerification,
) -> Arc<HttpService> {
    change_request_service_with_evidence_options(
        database,
        registry,
        identity,
        package_id,
        fault,
        read_fault,
        storage,
        pause,
        verification,
        None,
        None,
    )
    .0
}

#[allow(clippy::too_many_arguments)]
fn change_request_service_with_evidence_options(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    package_id: &str,
    fault: Option<MutationFaultPoint>,
    read_fault: Option<registry_breg::postgres::ReadFaultPoint>,
    storage: registry_breg::attachment_storage::AttachmentStorage,
    pause: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    verification: registry_breg::attachment_verification::AttachmentVerification,
    evidence: Option<Arc<ActionEvidenceEvaluator>>,
    reviews: Option<Arc<ReviewAuthorityRegistry>>,
) -> (Arc<HttpService>, registry_breg::postgres::RuntimePool) {
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(package_id).expect("lock key derives");
    let audit = AuditProfile::production_from_secret_bytes(vec![0x9a; 32].into())
        .expect("test audit profile is keyed");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x49; 32]), Duration::from_secs(300))
            .expect("cursor codec builds"),
    );
    let reads = PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    );
    let reads = reads
        .with_attachment_storage(storage.clone())
        .with_attachment_verification(verification.clone());
    let reads = match pause {
        Some((entered, resume)) => reads.with_attachment_metadata_pause_for_test(entered, resume),
        None => reads,
    };
    let reads = Arc::new(match read_fault {
        Some(fault) => reads.with_fault_for_test(fault),
        None => reads,
    });
    let revisions = Arc::new(PostgresRevisionReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
    ));
    let mutations = PostgresRecordMutationService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit,
    );
    let mutations = mutations
        .with_attachment_storage(storage)
        .with_attachment_verification(verification);
    let mutations = match evidence {
        Some(evidence) => mutations.with_evidence_evaluator(evidence),
        None => mutations,
    };
    let mutations = match reviews {
        Some(reviews) => mutations.with_review_result_source(reviews),
        None => mutations,
    };
    let mutations = match fault {
        Some(fault) => mutations.with_fault_for_test(fault),
        None => mutations,
    };
    let mutations = Arc::new(mutations);
    let service = Arc::new(
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
    );
    (service, pool)
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

async fn submit_two_stage_correction(app: &axum::Router) -> (CreatedRecord, String) {
    let steward = claims("steward", "two-stage-steward", None);
    let submitter = claims("submitter", SUBMITTER, None);
    let old_site = create_record(
        app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "two-create-old-site",
        json!({"tenant": TENANT, "name": "two-old"}),
    )
    .await;
    let new_site = create_record(
        app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        "two-create-new-site",
        json!({"tenant": TENANT, "name": "two-new"}),
    )
    .await;
    let placement = create_record(
        app,
        "/v1/records/placements?accessProfile=steward",
        steward,
        "two-create-placement",
        json!({"tenant": TENANT, "site": old_site.id}),
    )
    .await;
    let request = create_record(
        app,
        "/v1/records/correction-requests?accessProfile=submitter",
        submitter.clone(),
        "two-create-correction-request",
        json!({
            "tenant": TENANT,
            "placement": placement.id,
            "proposedSite": new_site.id,
            "reason": "direct application correction"
        }),
    )
    .await;
    let submitted = run_action(
        app,
        &request.id,
        "correction-requests",
        "submitter",
        submitter,
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
    (request, digest)
}

async fn reconcile_cached_external_approval(
    database: &TestDatabase,
    request_id: &str,
    automatic: bool,
) -> Value {
    let request_id = Uuid::parse_str(request_id).expect("request id");
    let row = database
        .admin
        .query_one(
            "SELECT create_request,expected_submission_digest,proposal_digest
               FROM registry_internal.registry_request_review_submissions
              WHERE request_entity_id='correction-request' AND request_id=$1",
            &[&request_id],
        )
        .await
        .expect("queued review submission");
    let create: Value = row.get(0);
    let submission_digest: String = row.get(1);
    let proposal_digest: String = row.get(2);
    let review_request_id = Uuid::new_v4();
    let result_id = Uuid::new_v4();
    let accepted = json!({
        "requestId": review_request_id,
        "subject": create["subject"].clone(),
        "policy": {
            "id": create["kind"].clone(),
            "version": "1",
            "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        "submissionDigest": submission_digest,
    });
    let result = json!({
        "resultId": result_id,
        "requestId": review_request_id,
        "subject": accepted["subject"].clone(),
        "policy": accepted["policy"].clone(),
        "submissionDigest": accepted["submissionDigest"].clone(),
        "status": "approved",
        "completedAt": "2026-09-01T00:00:00Z",
        "availableUntil": "2026-09-02T00:00:00Z"
    });
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET state='accepted',accepted_binding=$2
              WHERE request_entity_id='correction-request' AND request_id=$1",
            &[&request_id, &accepted],
        )
        .await
        .expect("review submission accepted");
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_request_review_results
             (request_entity_id,request_id,proposal_version,authority,result_id,result,status,
              completed_at,available_until)
             VALUES ('correction-request',$1,1,'casework-a',$2,$3,'approved',
                     '2026-09-01T00:00:00Z','2026-09-02T00:00:00Z')",
            &[&request_id, &result_id, &result],
        )
        .await
        .expect("stale reconciled review result");
    if automatic {
        database
            .admin
            .execute(
                "INSERT INTO registry_internal.registry_request_application_jobs
                 (request_entity_id,request_id,proposal_version,job_id,proposal_digest,result_id,
                  executor,state,attempt_count)
                 VALUES ('correction-request',$1,1,$2,$3,$4,'registry-automatic','queued',999)",
                &[&request_id, &Uuid::new_v4(), &proposal_digest, &result_id],
            )
            .await
            .expect("automatic application job");
    }
    result
}

async fn create_approved_correction(
    app: &axum::Router,
    steward: VerifiedRequestClaims,
    submitter: VerifiedRequestClaims,
    _reader: VerifiedRequestClaims,
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
    run_action(
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
    ApprovedCorrection {
        request_id: request.id,
        placement_id: placement.id,
        old_site_id: old_site.id,
        new_site_id: new_site.id,
    }
}

async fn create_approved_registration(
    database: &TestDatabase,
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
    run_action(
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
    let targets = request_targets(database, "registration-request", &request.id).await;
    let person_id = target_record_id(&targets, "person");
    let membership_id = target_record_id(&targets, "membership");
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
    assert!(response.etag.starts_with("\"breg-"));
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

async fn assert_served_action_openapi_refs(app: &axum::Router, applier: VerifiedRequestClaims) {
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
        ["effectDigest", "proposalVersion", "reason"]
    );
    assert_eq!(properties["proposalVersion"]["type"], "integer");
    assert_eq!(properties["effectDigest"]["type"], "string");
    assert_eq!(properties["reason"]["type"], "string");
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
    let suffix = snapshot
        .strip_prefix("breg1_")
        .expect("snapshot reference carries the breg1_ prefix");
    assert_eq!(suffix.len(), 36);
    Uuid::parse_str(suffix).expect("snapshot suffix is a UUID");
}

fn snapshot_uuid(value: &Value) -> Uuid {
    let snapshot = value.as_str().expect("response carries snapshot reference");
    let suffix = snapshot
        .strip_prefix("breg1_")
        .expect("snapshot reference carries the breg1_ prefix");
    assert_eq!(suffix.len(), 36);
    Uuid::parse_str(suffix).expect("snapshot suffix is a UUID")
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
    registry: &Arc<registry_breg::CompiledRegistry>,
    package_id: &str,
    temporal: bool,
) -> registry_breg::postgres::ExpectedRegistryIdentity {
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
    registry: &registry_breg::CompiledRegistry,
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
    registry: &registry_breg::CompiledRegistry,
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
    registry: &registry_breg::CompiledRegistry,
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
    registry: &registry_breg::CompiledRegistry,
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

async fn request_targets(
    database: &TestDatabase,
    request_entity_id: &str,
    request_id: &str,
) -> Vec<Value> {
    let request_id = Uuid::parse_str(request_id).expect("request id is a UUID");
    database
        .admin
        .query(
            "SELECT target_entity_id,target_record_id,operation,expected_revision,
                    base_snapshot,after_snapshot
             FROM registry_internal.registry_request_targets
             WHERE request_entity_id=$1 AND request_id=$2 AND proposal_version=1
             ORDER BY target_entity_id,target_record_id",
            &[&request_entity_id, &request_id],
        )
        .await
        .expect("frozen request targets load")
        .into_iter()
        .map(|row| {
            json!({
                "entityId": row.get::<_, String>(0),
                "recordId": row.get::<_, Uuid>(1).to_string(),
                "operation": row.get::<_, String>(2),
                "baseRevision": row.get::<_, Option<i64>>(3),
                "before": row.get::<_, Option<Value>>(4),
                "after": row.get::<_, Option<Value>>(5),
            })
        })
        .collect()
}

fn bounded_snapshot_registry() -> registry_breg::CompiledRegistry {
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
                "review":{"mode":"none"},
                "onApproved":{"mode":"manual"}
              }
            }
          ],
          "accessProfiles":[
            {
              "id":"steward","default":true,"principalClaim":"registry_principal",
              "permissions":[{
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
              "permissions":[{
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
              "permissions":[{
                "entity":"correction-request",
                "operations":["get","list"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
              }]
            },
            {
              "id":"applier","principalClaim":"registry_principal","requiredPurposes":["apply"],
              "permissions":[{
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

fn long_logical_id_registry() -> registry_breg::CompiledRegistry {
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
                "review":{"mode":"none"},
                "onApproved":{"mode":"manual"}
              }
            }
          ],
          "accessProfiles":[{
            "id":"reviewer","default":true,"principalClaim":"registry_principal","permissions":[{
              "entity":"placement-correction-request",
              "operations":["get","list","submit_request","apply_request"],
              "readableFields":["tenant","placement","proposed-site","reason"],
              "applyTargets":[{"entity":"asset-placement", "rowBoundaries": []}],
              "rowBoundaries": []
            }]
          }]
        }"#,
    )
    .expect("long logical change-request fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("long logical change-request fixture compiles")
}

fn registration_registry() -> registry_breg::CompiledRegistry {
    registration_registry_with_pattern(None)
}

fn registration_registry_with_pattern(pattern: Option<&str>) -> registry_breg::CompiledRegistry {
    let mut project = parse_project_json(
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
                "review":{"mode":"none"},
                "onApproved":{"mode":"manual"}
              }
            }
          ],
          "accessProfiles":[
            {
              "id":"steward","default":true,"principalClaim":"registry_principal",
              "permissions":[{
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
              "permissions":[
                {
                  "entity":"registration-request",
                  "operations":["create","get","list","revisions","patch","submit_request","revise_request","cancel_request","apply_request"],
                  "revisionAccess":true,
                  "readableFields":["tenant","household","name"],
                  "writableFields":["tenant","household","name"],
                  "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                  "applyTargets":[
                    {"entity":"person","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]},
                    {"entity":"membership","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]},
                    {"entity":"household","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}
                  ]
                },
                {
                  "entity":"person",
                  "operations":["get","list","revisions","patch"],
                  "revisionAccess":true,
                  "readableFields":["tenant","display-name"],
                  "writableFields":["display-name"],
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
    project
        .entities
        .iter_mut()
        .find(|entity| entity.id == "membership")
        .unwrap()
        .fields
        .iter_mut()
        .find(|field| field.id == "tenant")
        .unwrap()
        .pattern = pattern.map(str::to_owned);
    if pattern.is_some() {
        let mut applier = project
            .access_profiles
            .iter()
            .find(|profile| profile.id == "operator")
            .unwrap()
            .clone();
        applier.id = "blind-applier".to_owned();
        applier.default = false;
        applier
            .permissions
            .retain(|grant| grant.entity == "registration-request");
        let grant = &mut applier.permissions[0];
        grant.operations = BTreeSet::from([
            registry_breg::contract::Operation::Get,
            registry_breg::contract::Operation::ApplyRequest,
        ]);
        grant.writable_fields.clear();
        grant.revision_access = false;
        project.access_profiles.push(applier);
    }
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("registration change-request fixture compiles")
}

fn two_stage_registry() -> registry_breg::CompiledRegistry {
    compile_project(&two_stage_project(), &[], CompileProfile::Authoring)
        .expect("two-stage change-request fixture compiles")
}

fn two_stage_project() -> registry_breg::contract::RegistryProject {
    parse_project_json(
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
                "review":{"mode":"none"},
                "onApproved":{"mode":"manual"}
              }
            }
          ],
          "accessProfiles":[
            {
              "id":"steward","default":true,"principalClaim":"registry_principal",
              "permissions":[{
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
              "permissions":[{
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
              "permissions":[{
                "entity":"correction-request",
                "operations":["get","list"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
              }]
            },
            {
              "id":"final-reviewer","principalClaim":"registry_principal","requiredPurposes":["final"],
              "permissions":[{
                "entity":"correction-request",
                "operations":["get","list"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
              }]
            },
            {
              "id":"applier","principalClaim":"registry_principal","requiredPurposes":["apply"],
              "permissions":[{
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
    .expect("two-stage change-request fixture parses")
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
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
                "review":{"mode":"none"},
                "onApproved":{"mode":"manual"}
              }
            }
          ],
          "accessProfiles":[
            {
              "id":"steward","default":true,"principalClaim":"registry_principal",
              "permissions":[{
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
              "permissions":[{
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
              "permissions":[{
                "entity":"correction-request",
                "operations":["get","list"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
              }]
            },
            {
              "id":"applier","principalClaim":"registry_principal","requiredPurposes":["apply"],
              "permissions":[{
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reviewed_native_pattern_failure_rolls_back_prior_effect_and_preserves_frozen_approval() {
    let database = TestDatabase::create(4).await;
    let registry = Arc::new(registration_registry_with_pattern(Some("^other-tenant$")));
    let identity =
        install_registry(&database, &registry, "registration-change-request", false).await;
    let app = change_request_router(
        &database,
        registry.clone(),
        identity,
        "registration-change-request",
        None,
    );
    let operator = claims("operator", "pattern-operator", None);
    let approved = create_approved_registration(
        &database,
        &app,
        claims("steward", "pattern-steward", None),
        operator.clone(),
        "pattern-frozen",
    )
    .await;
    let uri = format!(
        "/v1/records/registration-requests/{}?accessProfile=operator",
        approved.request_id
    );
    let before = get_record(&app, &uri, operator.clone()).await;
    let revisions: i64 = database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_revisions",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let response = send_registration_apply(
        &app,
        &approved.request_id,
        operator.clone(),
        "pattern-refused-apply",
    )
    .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.body["code"], "mutation.conflict");
    assert!(response.body.get("entityId").is_none());
    assert!(response.body.get("fieldId").is_none());
    assert!(!response.body.to_string().contains("other-tenant"));
    assert!(!response
        .body
        .to_string()
        .contains(&registry.entities()["membership"].physical_table));
    let blind_applier = claims("blind-applier", "application-only-actor", None);
    assert!(!registry.entities()["membership"]
        .access_profiles
        .contains_key("blind-applier"));
    let blind_request = get_record(
        &app,
        &format!(
            "/v1/records/registration-requests/{}?accessProfile=blind-applier",
            approved.request_id
        ),
        blind_applier.clone(),
    )
    .await;
    let apply = action(&blind_request.body, "apply_request", None);
    let blind_response = send_action(
        &app,
        &apply,
        "pattern-blind-apply",
        blind_applier,
        json!({"proposalVersion": apply.proposal_version, "effectDigest": apply.effect_digest}),
    )
    .await;
    assert_eq!(blind_response.status, StatusCode::CONFLICT);
    assert_eq!(blind_response.body["code"], "mutation.conflict");
    for hidden in ["entityId", "fieldId"] {
        assert!(blind_response.body.get(hidden).is_none());
    }
    for hidden in [
        "membership",
        "tenant",
        "other-tenant",
        "registry_data",
        "breg_pattern_",
    ] {
        assert!(!blind_response.body.to_string().contains(hidden));
    }
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
    let after = get_record(&app, &uri, operator.clone()).await;
    assert_eq!(
        after.body["request"], before.body["request"],
        "failed application preserves frozen proposal and approved state"
    );
    assert_eq!(after.body["revision"], before.body["revision"]);
    let after_revisions: i64 = database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_revisions",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        after_revisions, revisions,
        "later pattern failure rolls back the earlier create revision"
    );
    assert_eq!(application_result_count(&database).await, 0);
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
    database.cleanup().await;
}

#[path = "support/submitter_targets.rs"]
mod submitter_targets;

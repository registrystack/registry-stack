// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

#[path = "support/immediate_action_review_regressions.rs"]
mod review_regressions;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_platform_audit::AuditProfile;
use registry_server::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::cursor::CursorCodec;
use registry_server::mutation::MutationFaultPoint;
use registry_server::postgres::{
    begin_record_transaction, initialize_registry_state_for_catalog_test, install_compiled_schema,
    ClaimContext, ExpectedManagedCatalog, PostgresRecordMutationService, PostgresRecordReadService,
    RegistryLockKey, RegistryStateTestIdentity, RowBoundaryContext,
};
use serde_json::{json, Value};
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "immediate-action-registry";
const INSTANCE_ID: &str = "immediate-action-instance";
const DATABASE_ID: &str = "immediate-action-database";
const HOUSEHOLD_ID: &str = "00000000-0000-4000-8000-000000000101";
const OTHER_HOUSEHOLD_ID: &str = "00000000-0000-4000-8000-000000000202";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn immediate_action_acquires_conditions_applies_atomically_and_replays_by_normalized_body() {
    let database = TestDatabase::create(10).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs action RLS with compiled schema");
    let catalog = ExpectedManagedCatalog::compiled(&registry);
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &catalog,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: "package-action-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("migration initializes registry identity");
    drop(migration);
    migration_task.abort();
    seed_household(
        &database,
        &registry,
        &identity,
        HOUSEHOLD_ID,
        "H-001",
        "zone-a",
    )
    .await;
    seed_household(
        &database,
        &registry,
        &identity,
        OTHER_HOUSEHOLD_ID,
        "H-002",
        "zone-b",
    )
    .await;

    let app = action_router(&database, registry.clone(), identity.clone());
    let claims = action_claims();
    let condition = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact/target-conditions",
            Some(claims.clone()),
            &[("content-type", "application/json")],
            br#"{"input":{"householdId":"00000000-0000-4000-8000-000000000101"}}"#.to_vec(),
        )
        .await,
    )
    .await;
    assert_eq!(condition.status, StatusCode::OK);
    let returned_preconditions = condition.body["preconditions"].clone();
    let token = returned_preconditions["householdId"]["ifMatch"]
        .as_str()
        .expect("condition response carries an opaque strong token")
        .to_owned();
    assert!(
        condition.content_type.starts_with("application/json"),
        "condition endpoint returns JSON"
    );
    assert!(
        condition.body["preconditions"].get("household").is_none(),
        "conditions expose the public input name, not the logical action id"
    );

    let first = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "register-contact"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "householdId": HOUSEHOLD_ID,
                    "personCode": "P-001",
                    "legalName": "Alex Example",
                    "jurisdiction": "zone-a"
                },
                "preconditions": returned_preconditions
            }))
            .expect("action body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    assert_eq!(first.body["action"], "register-household-contact");
    let person_id = first.body["results"]["person"]["id"]
        .as_str()
        .expect("create result exposes only identifiers")
        .to_owned();
    let membership_id = first.body["results"]["membership"]["id"]
        .as_str()
        .expect("second create result exposes only identifiers")
        .to_owned();
    assert_eq!(
        first.body["results"]["household"]["id"].as_str(),
        Some(HOUSEHOLD_ID)
    );
    assert_eq!(household_contact(&database, &registry).await, person_id);
    assert_eq!(
        membership_links(&database, &registry, &membership_id).await,
        (person_id.clone(), HOUSEHOLD_ID.to_owned())
    );
    assert_eq!(
        action_outbox_application_reference_count(&database).await,
        3,
        "each configured entity event carries protected action application provenance"
    );

    let replay = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "register-contact"),
            ],
            format!(
                r#"{{
                  "preconditions":{{"householdId":{{"ifMatch":{condition}}}}},
                  "input":{{"jurisdiction":"zone-a","legalName":"Alex Example","personCode":"P-001","householdId":"{HOUSEHOLD_ID}"}}
                }}"#,
                condition = serde_json::to_string(&token).expect("token serializes")
            )
            .into_bytes(),
        )
        .await,
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK, "{}", replay.body);
    assert_eq!(
        replay.body, first.body,
        "same normalized action request replays the receipt"
    );
    assert_eq!(
        action_terminal_application_audit_count(&database).await,
        2,
        "commit and replay terminal audit both retain the application reference without response bytes"
    );

    let changed_same_key = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "register-contact"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "householdId": HOUSEHOLD_ID,
                    "personCode": "P-001",
                    "legalName": "Changed Name",
                    "jurisdiction": "zone-a"
                },
                "preconditions": {"householdId": {"ifMatch": token}}
            }))
            .expect("changed action body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(changed_same_key.status, StatusCode::CONFLICT);

    let stale = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact",
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "register-contact-stale"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "householdId": HOUSEHOLD_ID,
                    "personCode": "P-002",
                    "legalName": "Blake Example",
                    "jurisdiction": "zone-a"
                },
                "preconditions": {"householdId": {"ifMatch": token}}
            }))
            .expect("stale action body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);

    let profile_conflict = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact?accessProfile=contact-shadow",
            Some(shadow_claims()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "register-contact"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "householdId": HOUSEHOLD_ID,
                    "personCode": "P-001",
                    "legalName": "Alex Example",
                    "jurisdiction": "zone-a"
                },
                "preconditions": {"householdId": {"ifMatch": token}}
            }))
            .expect("profile conflict body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(profile_conflict.status, StatusCode::CONFLICT);

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_only_action_requires_no_condition_and_replays_without_crud_grants() {
    let (database, registry, identity) = setup_action_registry().await;
    let app = action_router(&database, registry.clone(), identity);
    let crud_read = send(
        &app,
        Method::GET,
        &format!("/v1/households/{HOUSEHOLD_ID}"),
        Some(action_claims()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(crud_read.status(), StatusCode::NOT_FOUND);
    let body = json!({
        "input": {
            "personCode": "P-CREATE-ONLY",
            "legalName": "Casey Create",
            "jurisdiction": "zone-a"
        }
    });

    let first = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/create-local-person",
            Some(action_claims()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "create-only-key"),
            ],
            serde_json::to_vec(&body).expect("create-only body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    assert_eq!(first.body["action"], "create-local-person");
    assert!(first.body["results"].get("person-only").is_some());
    assert_eq!(first.body["results"].as_object().unwrap().len(), 1);
    assert!(first.body.to_string().contains("applicationId"));
    assert!(!first.body.to_string().contains("Casey Create"));

    let replay = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/create-local-person",
            Some(action_claims()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "create-only-key"),
            ],
            br#"{"input":{"jurisdiction":"zone-a","legalName":"Casey Create","personCode":"P-CREATE-ONLY"}}"#.to_vec(),
        )
        .await,
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK, "{}", replay.body);
    assert_eq!(replay.body, first.body);
    assert_eq!(entity_count(&database, &registry, "person").await, 1);
    assert_eq!(immediate_action_receipt_count(&database).await, 1);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_conditions_and_invocation_refuse_aliases_wrong_records_and_boundary_escapes() {
    let (database, registry, identity) = setup_action_registry().await;
    let app = action_router(&database, registry.clone(), identity);
    let claims = action_claims();

    let unauthorized = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact/target-conditions",
            None,
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"input":{"householdId":HOUSEHOLD_ID}}))
                .expect("condition body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(unauthorized.status, StatusCode::NOT_FOUND);

    let extra_condition_input = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact/target-conditions",
            Some(claims.clone()),
            &[("content-type", "application/json")],
            serde_json::to_vec(
                &json!({"input":{"householdId":HOUSEHOLD_ID,"personCode":"P-IGNORED"}}),
            )
            .expect("extra condition body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(extra_condition_input.status, StatusCode::BAD_REQUEST);

    let out_of_scope_condition = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact/target-conditions",
            Some(claims.clone()),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"input":{"householdId":OTHER_HOUSEHOLD_ID}}))
                .expect("out-of-scope condition body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(out_of_scope_condition.status, StatusCode::NOT_FOUND);

    let condition = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact/target-conditions",
            Some(claims.clone()),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"input":{"householdId":HOUSEHOLD_ID}}))
                .expect("condition body serializes"),
        )
        .await,
    )
    .await;
    let token = condition.body["preconditions"]["householdId"]["ifMatch"]
        .as_str()
        .expect("condition token")
        .to_owned();

    let logical_alias = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "logical-alias"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "householdId": HOUSEHOLD_ID,
                    "personCode": "P-ALIAS",
                    "legalName": "Alias Refused",
                    "jurisdiction": "zone-a"
                },
                "preconditions": {"household": {"ifMatch": token}}
            }))
            .expect("logical alias body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(logical_alias.status, StatusCode::BAD_REQUEST);

    let wrong_record = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "wrong-record"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "householdId": OTHER_HOUSEHOLD_ID,
                    "personCode": "P-WRONG-RECORD",
                    "legalName": "Wrong Record",
                    "jurisdiction": "zone-a"
                },
                "preconditions": {"householdId": {"ifMatch": token}}
            }))
            .expect("wrong record body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(wrong_record.status, StatusCode::PRECONDITION_FAILED);

    let before = action_counts(&database, &registry).await;
    let boundary_escape = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact",
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "boundary-escape"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "householdId": HOUSEHOLD_ID,
                    "personCode": "P-ESCAPE",
                    "legalName": "Boundary Escape",
                    "jurisdiction": "zone-b"
                },
                "preconditions": {"householdId": {"ifMatch": token}}
            }))
            .expect("boundary escape body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(boundary_escape.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        action_counts(&database, &registry).await.without_audit(),
        before.without_audit()
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn immediate_action_recovery_erasure_and_current_authority_do_not_reexecute() {
    let (database, registry, identity) = setup_action_registry().await;
    let normal_app = action_router(&database, registry.clone(), identity.clone());
    let fault_app = action_router_with_fault(
        &database,
        registry.clone(),
        identity,
        Some(MutationFaultPoint::AfterCommitBeforeResponseRelease),
    );
    let claims = action_claims();
    let condition = response_parts(
        send(
            &normal_app,
            Method::POST,
            "/v1/actions/register-household-contact/target-conditions",
            Some(claims.clone()),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"input":{"householdId":HOUSEHOLD_ID}}))
                .expect("condition body serializes"),
        )
        .await,
    )
    .await;
    let token = condition.body["preconditions"]["householdId"]["ifMatch"]
        .as_str()
        .expect("condition token")
        .to_owned();
    let body = json!({
        "input": {
            "householdId": HOUSEHOLD_ID,
            "personCode": "P-LOST",
            "legalName": "Lost Response",
            "jurisdiction": "zone-a"
        },
        "preconditions": {"householdId": {"ifMatch": token}}
    });

    let lost = response_parts(
        send(
            &fault_app,
            Method::POST,
            "/v1/actions/register-household-contact",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "lost-response"),
            ],
            serde_json::to_vec(&body).expect("lost response body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(lost.status, StatusCode::SERVICE_UNAVAILABLE);
    let after_lost_commit = action_counts(&database, &registry).await;
    assert_eq!(after_lost_commit.idempotency, 1);

    let replay = response_parts(
        send(
            &normal_app,
            Method::POST,
            "/v1/actions/register-household-contact",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "lost-response"),
            ],
            serde_json::to_vec(&body).expect("replay body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK, "{}", replay.body);
    assert_eq!(
        action_counts(&database, &registry).await.without_audit(),
        after_lost_commit.without_audit()
    );

    move_household_to_jurisdiction(&database, &registry, HOUSEHOLD_ID, "zone-b").await;
    let current_authority_denial = response_parts(
        send(
            &normal_app,
            Method::POST,
            "/v1/actions/register-household-contact",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "lost-response"),
            ],
            serde_json::to_vec(&body).expect("authority replay body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(
        current_authority_denial.status,
        StatusCode::PRECONDITION_FAILED
    );
    move_household_to_jurisdiction(&database, &registry, HOUSEHOLD_ID, "zone-a").await;

    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_idempotency
                SET response_body = NULL, erased_at = transaction_timestamp()
              WHERE result_kind = 'immediate_action'",
            &[],
        )
        .await
        .expect("administrator erases retained immediate-action body");
    let erased = response_parts(
        send(
            &normal_app,
            Method::POST,
            "/v1/actions/register-household-contact",
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "lost-response"),
            ],
            serde_json::to_vec(&body).expect("erased replay body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(erased.status, StatusCode::CONFLICT);
    assert_eq!(
        action_counts(&database, &registry).await.without_audit(),
        after_lost_commit.without_audit()
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn immediate_action_faults_roll_back_rows_revisions_outbox_audit_and_receipt() {
    let (database, registry, identity) = setup_action_registry().await;
    let normal_app = action_router(&database, registry.clone(), identity.clone());
    let claims = action_claims();
    let condition = response_parts(
        send(
            &normal_app,
            Method::POST,
            "/v1/actions/register-household-contact/target-conditions",
            Some(claims.clone()),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"input":{"householdId":HOUSEHOLD_ID}}))
                .expect("condition body serializes"),
        )
        .await,
    )
    .await;
    let token = condition.body["preconditions"]["householdId"]["ifMatch"]
        .as_str()
        .expect("condition token")
        .to_owned();

    for (index, fault) in [
        MutationFaultPoint::BeforeCurrentRow,
        MutationFaultPoint::BeforeRevision,
        MutationFaultPoint::BeforeOutbox,
        MutationFaultPoint::BeforeTerminalAudit,
        MutationFaultPoint::BeforeIdempotency,
        MutationFaultPoint::BeforeCommit,
    ]
    .into_iter()
    .enumerate()
    {
        let fault_app =
            action_router_with_fault(&database, registry.clone(), identity.clone(), Some(fault));
        let before = action_counts(&database, &registry).await;
        let key = format!("fault-{index}");
        let failed = response_parts(
            send(
                &fault_app,
                Method::POST,
                "/v1/actions/register-household-contact",
                Some(claims.clone()),
                &[
                    ("content-type", "application/json"),
                    ("idempotency-key", &key),
                ],
                serde_json::to_vec(&json!({
                    "input": {
                        "householdId": HOUSEHOLD_ID,
                        "personCode": format!("P-FAULT-{index}"),
                        "legalName": "Faulted Attempt",
                        "jurisdiction": "zone-a"
                    },
                    "preconditions": {"householdId": {"ifMatch": token}}
                }))
                .expect("fault body serializes"),
            )
            .await,
        )
        .await;
        assert_eq!(
            failed.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "fault {fault:?}"
        );
        assert_eq!(
            action_counts(&database, &registry).await.without_audit(),
            before.without_audit()
        );
    }
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_key_concurrent_invocation_commits_once_and_replays_once() {
    let (database, registry, identity) = setup_action_registry().await;
    let app = action_router(&database, registry.clone(), identity);
    let claims = action_claims();
    let condition = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact/target-conditions",
            Some(claims.clone()),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"input":{"householdId":HOUSEHOLD_ID}}))
                .expect("condition body serializes"),
        )
        .await,
    )
    .await;
    let token = condition.body["preconditions"]["householdId"]["ifMatch"]
        .as_str()
        .expect("condition token")
        .to_owned();
    let body = serde_json::to_vec(&json!({
        "input": {
            "householdId": HOUSEHOLD_ID,
            "personCode": "P-CONCURRENT",
            "legalName": "Concurrent Apply",
            "jurisdiction": "zone-a"
        },
        "preconditions": {"householdId": {"ifMatch": token}}
    }))
    .expect("concurrent body serializes");

    let concurrent_headers = [
        ("content-type", "application/json"),
        ("idempotency-key", "same-key-concurrent"),
    ];
    let left = send(
        &app,
        Method::POST,
        "/v1/actions/register-household-contact",
        Some(claims.clone()),
        &concurrent_headers,
        body.clone(),
    );
    let right = send(
        &app,
        Method::POST,
        "/v1/actions/register-household-contact",
        Some(claims),
        &concurrent_headers,
        body,
    );
    let (left, right) = tokio::join!(left, right);
    let left = response_parts(left).await;
    let right = response_parts(right).await;
    assert_eq!(left.status, StatusCode::OK, "{}", left.body);
    assert_eq!(right.status, StatusCode::OK, "{}", right.body);
    assert_eq!(left.body, right.body);
    assert_eq!(entity_count(&database, &registry, "person").await, 1);
    assert_eq!(
        entity_count(&database, &registry, "group-membership").await,
        1
    );
    assert_eq!(immediate_action_receipt_count(&database).await, 1);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aliased_patch_effects_share_one_revision_and_distinct_results() {
    let (database, registry, identity) = setup_action_registry().await;
    let app = action_router(&database, registry.clone(), identity);
    let claims = action_claims();
    let condition = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/rename-household-local/target-conditions",
            Some(claims.clone()),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"input":{"householdId":HOUSEHOLD_ID}}))
                .expect("condition body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(condition.status, StatusCode::OK, "{}", condition.body);
    let before_revision_count =
        revision_count_for_record(&database, "household", HOUSEHOLD_ID).await;
    let before_outbox_count = outbox_count_for_entity(&database, "household").await;
    install_household_group_context_probe(&database, &registry).await;

    let applied = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/rename-household-local",
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "alias-fold"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "householdId": HOUSEHOLD_ID,
                    "householdCode": "H-RENAMED",
                    "statusNote": "folded alias patch"
                },
                "preconditions": condition.body["preconditions"].clone()
            }))
            .expect("alias patch body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(applied.status, StatusCode::OK, "{}", applied.body);
    assert_eq!(applied.body["results"].as_object().unwrap().len(), 2);
    assert_eq!(
        applied.body["results"]["household-code-update"]["id"],
        HOUSEHOLD_ID
    );
    assert_eq!(
        applied.body["results"]["household-note-update"]["id"],
        HOUSEHOLD_ID
    );
    assert_eq!(
        applied.body["results"]["household-code-update"]["revision"],
        applied.body["results"]["household-note-update"]["revision"],
        "aliased effects return separate result references for the same final row revision"
    );
    assert_eq!(
        revision_count_for_record(&database, "household", HOUSEHOLD_ID).await,
        before_revision_count + 1,
        "non-overlapping alias effects fold into one revision"
    );
    assert_eq!(
        outbox_count_for_entity(&database, "household").await,
        before_outbox_count + 1,
        "non-overlapping alias effects fold into one outbox event"
    );
    assert_eq!(
        household_code_note_revision(&database, &registry, HOUSEHOLD_ID).await,
        (
            "H-RENAMED".to_owned(),
            Some("folded alias patch".to_owned()),
            2
        )
    );
    assert_eq!(
        household_group_context_probe(&database).await,
        (
            json!(["household-code-update", "household-note-update"]),
            json!(["household-code", "status-note"]),
            1,
        ),
        "the actual folded UPDATE sees the grouped target context and stores the same application id as the receipt"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn link_only_reference_requires_current_target_authority_without_condition() {
    let (database, registry, identity) = setup_action_registry().await;
    let app = action_router(&database, registry.clone(), identity);
    let claims = action_claims();

    let linked = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/link-household-member",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "link-only-authorized"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "householdId": HOUSEHOLD_ID,
                    "personCode": "P-LINK-OK",
                    "legalName": "Link Only Granted",
                    "jurisdiction": "zone-a"
                }
            }))
            .expect("link-only body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(linked.status, StatusCode::OK, "{}", linked.body);
    let before_denied = action_counts(&database, &registry).await;

    let denied = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/link-household-member",
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "link-only-denied"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "householdId": OTHER_HOUSEHOLD_ID,
                    "personCode": "P-LINK-DENIED",
                    "legalName": "Link Only Denied",
                    "jurisdiction": "zone-a"
                }
            }))
            .expect("denied link-only body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(
        denied.status,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        denied.body
    );
    assert_eq!(
        action_counts(&database, &registry).await.without_audit(),
        before_denied.without_audit(),
        "link-only authority refusal does not create dependent rows or receipts"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replay_uses_current_granted_results_without_stale_revision_or_hidden_reads() {
    let (database, registry, identity) = setup_action_registry().await;
    let app = action_router(&database, registry.clone(), identity);
    let claims = action_claims();

    let silent = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/create-silent-person",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "silent-create"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "personCode": "P-SILENT",
                    "legalName": "Silent Result",
                    "jurisdiction": "zone-a"
                }
            }))
            .expect("silent body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(silent.status, StatusCode::OK, "{}", silent.body);
    assert_eq!(silent.body["results"].as_object().unwrap().len(), 0);
    move_person_by_code_to_jurisdiction(&database, &registry, "P-SILENT", "zone-b").await;
    let silent_replay = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/create-silent-person",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "silent-create"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "personCode": "P-SILENT",
                    "legalName": "Silent Result",
                    "jurisdiction": "zone-a"
                }
            }))
            .expect("silent replay body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(
        silent_replay.status,
        StatusCode::OK,
        "{}",
        silent_replay.body
    );
    assert_eq!(silent_replay.body, silent.body);

    let condition = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/rename-household-local/target-conditions",
            Some(claims.clone()),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"input":{"householdId":HOUSEHOLD_ID}}))
                .expect("condition body serializes"),
        )
        .await,
    )
    .await;
    let body = json!({
        "input": {
            "householdId": HOUSEHOLD_ID,
            "householdCode": "H-REPLAY-STALE",
            "statusNote": "stored old revision"
        },
        "preconditions": condition.body["preconditions"].clone()
    });
    let first = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/rename-household-local",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "revision-independent-replay"),
            ],
            serde_json::to_vec(&body).expect("rename body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    bump_household_revision_same_boundary(&database, &registry, HOUSEHOLD_ID).await;
    let replay = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/rename-household-local",
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "revision-independent-replay"),
            ],
            serde_json::to_vec(&body).expect("rename replay body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK, "{}", replay.body);
    assert_eq!(replay.body, first.body);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retryable_abort_keeps_one_receipt_and_deadline_cancels_without_late_commit() {
    let (database, registry, identity) = setup_action_registry().await;
    install_person_retry_once_trigger(&database, &registry).await;
    let retry_app = action_router(&database, registry.clone(), identity.clone());
    let claims = action_claims();
    let retried = response_parts(
        send(
            &retry_app,
            Method::POST,
            "/v1/actions/create-local-person",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "retry-known-abort"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "personCode": "P-RETRY",
                    "legalName": "Retry Abort",
                    "jurisdiction": "zone-a"
                }
            }))
            .expect("retry body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(retried.status, StatusCode::OK, "{}", retried.body);
    assert_eq!(
        retry_probe_value(&database).await,
        2,
        "database raised one known abort before the successful retry"
    );
    assert_eq!(entity_count(&database, &registry, "person").await, 1);
    assert_eq!(immediate_action_receipt_count(&database).await, 1);

    install_person_sleep_trigger(&database, &registry).await;
    let timeout_app = action_router_with_timeout(
        &database,
        registry.clone(),
        identity,
        Duration::from_millis(10),
    );
    let before_timeout = action_counts(&database, &registry).await;
    let timed_out = response_parts(
        send(
            &timeout_app,
            Method::POST,
            "/v1/actions/create-local-person",
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "deadline-no-late-commit"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "personCode": "P-TIMEOUT",
                    "legalName": "Timeout Abort",
                    "jurisdiction": "zone-a"
                }
            }))
            .expect("timeout body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(
        timed_out.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        timed_out.body
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        action_counts(&database, &registry).await.without_audit(),
        before_timeout.without_audit(),
        "deadline cancellation discards the timed-out connection before a late commit can become visible"
    );
    database.cleanup().await;
}

async fn setup_action_registry() -> (
    TestDatabase,
    Arc<registry_server::CompiledRegistry>,
    registry_server::postgres::ExpectedRegistryIdentity,
) {
    let database = TestDatabase::create(10).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs action RLS with compiled schema");
    let catalog = ExpectedManagedCatalog::compiled(&registry);
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &catalog,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: "package-action-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("migration initializes registry identity");
    drop(migration);
    migration_task.abort();
    seed_household(
        &database,
        &registry,
        &identity,
        HOUSEHOLD_ID,
        "H-001",
        "zone-a",
    )
    .await;
    seed_household(
        &database,
        &registry,
        &identity,
        OTHER_HOUSEHOLD_ID,
        "H-002",
        "zone-b",
    )
    .await;
    (database, registry, identity)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActionCounts {
    people: i64,
    memberships: i64,
    contacted_households: i64,
    revisions: i64,
    outbox: i64,
    terminal_audit: i64,
    idempotency: i64,
    applications: i64,
    results: i64,
}

impl ActionCounts {
    fn without_audit(self) -> (i64, i64, i64, i64, i64, i64, i64, i64) {
        (
            self.people,
            self.memberships,
            self.contacted_households,
            self.revisions,
            self.outbox,
            self.idempotency,
            self.applications,
            self.results,
        )
    }
}

async fn action_counts(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
) -> ActionCounts {
    let person = &registry.entities()["person"];
    let household = &registry.entities()["household"];
    let membership = &registry.entities()["group-membership"];
    let contact = &household.fields["contact-person"].physical_name;
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT
                   (SELECT count(*) FROM registry_data.{person_table}),
                   (SELECT count(*) FROM registry_data.{membership_table}),
                   (SELECT count(*) FROM registry_data.{household_table} WHERE {contact} IS NOT NULL),
                   (SELECT count(*) FROM registry_internal.registry_revisions),
                   (SELECT count(*) FROM registry_internal.registry_outbox),
                   (SELECT count(*) FROM registry_internal.registry_audit
                      WHERE convert_from(envelope, 'UTF8') LIKE '%\"phase\":\"terminal\"%'),
                   (SELECT count(*) FROM registry_internal.registry_idempotency
                      WHERE result_kind = 'immediate_action'),
                   (SELECT count(*) FROM registry_internal.registry_immediate_action_applications),
                   (SELECT count(*) FROM registry_internal.registry_immediate_action_results)",
                person_table = q(&person.physical_table),
                membership_table = q(&membership.physical_table),
                household_table = q(&household.physical_table),
                contact = q(contact),
            ),
            &[],
        )
        .await
        .expect("administrator inspects immediate-action effects");
    ActionCounts {
        people: row.get(0),
        memberships: row.get(1),
        contacted_households: row.get(2),
        revisions: row.get(3),
        outbox: row.get(4),
        terminal_audit: row.get(5),
        idempotency: row.get(6),
        applications: row.get(7),
        results: row.get(8),
    }
}

async fn household_code_note_revision(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    household_id: &str,
) -> (String, Option<String>, i64) {
    let household = &registry.entities()["household"];
    let table = &household.physical_table;
    let code = &household.fields["household-code"].physical_name;
    let note = &household.fields["status-note"].physical_name;
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT {code}, {note}, record_revision FROM registry_data.{table} WHERE record_id = $1",
                table = q(table),
                code = q(code),
                note = q(note),
            ),
            &[&Uuid::parse_str(household_id).expect("household UUID")],
        )
        .await
        .expect("administrator reads household values");
    (row.get(0), row.get(1), row.get(2))
}

async fn revision_count_for_record(
    database: &TestDatabase,
    entity_id: &str,
    record_id: &str,
) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_revisions
              WHERE entity_id = $1 AND record_id = $2",
            &[
                &entity_id,
                &Uuid::parse_str(record_id).expect("record UUID"),
            ],
        )
        .await
        .expect("administrator counts revisions for record")
        .get(0)
}

async fn outbox_count_for_entity(database: &TestDatabase, entity_id: &str) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_outbox
              WHERE entity_id = $1",
            &[&entity_id],
        )
        .await
        .expect("administrator counts outbox for entity")
        .get(0)
}

async fn action_terminal_application_audit_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_audit
              WHERE convert_from(envelope, 'UTF8') LIKE '%\"applicationReference\"%'
                AND convert_from(envelope, 'UTF8') LIKE '%\"actionId\"%'",
            &[],
        )
        .await
        .expect("administrator counts action application audit references")
        .get(0)
}

async fn bump_household_revision_same_boundary(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    household_id: &str,
) {
    let household = &registry.entities()["household"];
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{table}
                    SET record_revision = record_revision + 1
                  WHERE record_id = $1",
                table = q(&household.physical_table),
            ),
            &[&Uuid::parse_str(household_id).expect("household UUID")],
        )
        .await
        .expect("administrator bumps household revision without changing authority boundary");
}

async fn move_person_by_code_to_jurisdiction(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    person_code: &str,
    jurisdiction: &str,
) {
    let person = &registry.entities()["person"];
    let code = &person.fields["person-code"].physical_name;
    let jurisdiction_field = &person.fields["jurisdiction"].physical_name;
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{table}
                    SET {jurisdiction_field} = $1,
                        record_revision = record_revision + 1
                  WHERE {code} = $2",
                table = q(&person.physical_table),
                jurisdiction_field = q(jurisdiction_field),
                code = q(code),
            ),
            &[&jurisdiction, &person_code],
        )
        .await
        .expect("administrator moves person authority boundary");
}

async fn install_person_retry_once_trigger(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
) {
    let person = &registry.entities()["person"];
    database
        .admin
        .batch_execute(&format!(
            "CREATE SEQUENCE registry_internal.immediate_action_retry_probe_seq;
             CREATE FUNCTION registry_internal.immediate_action_retry_once()
             RETURNS trigger
             LANGUAGE plpgsql
             SECURITY DEFINER
             SET search_path = registry_internal, pg_temp
             AS $$
             BEGIN
                 IF nextval('registry_internal.immediate_action_retry_probe_seq') = 1 THEN
                     RAISE EXCEPTION 'immediate action retry probe' USING ERRCODE = '40001';
                 END IF;
                 RETURN NEW;
             END;
             $$;
             CREATE TRIGGER immediate_action_retry_once
             BEFORE INSERT ON registry_data.{table}
             FOR EACH ROW EXECUTE FUNCTION registry_internal.immediate_action_retry_once();",
            table = q(&person.physical_table),
        ))
        .await
        .expect("administrator installs retry-once trigger");
}

async fn retry_probe_value(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT last_value FROM registry_internal.immediate_action_retry_probe_seq",
            &[],
        )
        .await
        .expect("administrator reads retry probe sequence")
        .get(0)
}

async fn install_person_sleep_trigger(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
) {
    let person = &registry.entities()["person"];
    database
        .admin
        .batch_execute(&format!(
            "DROP TRIGGER IF EXISTS immediate_action_retry_once ON registry_data.{table};
             CREATE FUNCTION registry_internal.immediate_action_sleep_before_insert()
             RETURNS trigger
             LANGUAGE plpgsql
             SECURITY DEFINER
             SET search_path = registry_internal, pg_temp
             AS $$
             BEGIN
                 PERFORM pg_sleep(0.2);
                 RETURN NEW;
             END;
             $$;
             CREATE TRIGGER immediate_action_sleep_before_insert
             BEFORE INSERT ON registry_data.{table}
             FOR EACH ROW EXECUTE FUNCTION registry_internal.immediate_action_sleep_before_insert();",
            table = q(&person.physical_table),
        ))
        .await
        .expect("administrator installs sleep trigger");
}

async fn install_household_group_context_probe(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
) {
    let household = &registry.entities()["household"];
    database
        .admin
        .batch_execute(&format!(
            "CREATE TABLE registry_internal.immediate_action_group_context_probe(
                 application_id uuid NOT NULL,
                 effect_ids jsonb NOT NULL,
                 fields jsonb NOT NULL
             );
             CREATE FUNCTION registry_internal.capture_immediate_action_group_context()
             RETURNS trigger
             LANGUAGE plpgsql
             SECURITY DEFINER
             SET search_path = registry_internal, pg_temp
             AS $$
             DECLARE
                 ctx jsonb;
             BEGIN
                 ctx := NULLIF(current_setting('registry.immediate_action_target_context', true), '')::jsonb;
                 IF ctx ->> 'actionId' = 'rename-household-local'
                    AND ctx ->> 'applicationId' IS NOT NULL THEN
                     INSERT INTO registry_internal.immediate_action_group_context_probe(
                         application_id, effect_ids, fields
                     ) VALUES (
                         (ctx ->> 'applicationId')::uuid,
                         ctx -> 'effectIds',
                         ctx -> 'fields'
                     );
                 END IF;
                 RETURN NEW;
             END;
             $$;
             CREATE TRIGGER capture_immediate_action_group_context
             BEFORE UPDATE ON registry_data.{table}
             FOR EACH ROW EXECUTE FUNCTION registry_internal.capture_immediate_action_group_context();",
            table = q(&household.physical_table),
        ))
        .await
        .expect("administrator installs action group context probe");
}

async fn household_group_context_probe(database: &TestDatabase) -> (Value, Value, i64) {
    let row = database
        .admin
        .query_one(
            "SELECT probe.effect_ids,
                    probe.fields,
                    (SELECT count(*)
                       FROM registry_internal.registry_immediate_action_applications applications
                      WHERE applications.application_id = probe.application_id
                        AND applications.action_id = 'rename-household-local')
               FROM registry_internal.immediate_action_group_context_probe probe",
            &[],
        )
        .await
        .expect("administrator reads action group context probe");
    (row.get(0), row.get(1), row.get(2))
}

async fn action_outbox_application_reference_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_outbox
              WHERE application_reference IS NOT NULL",
            &[],
        )
        .await
        .expect("administrator counts action outbox provenance")
        .get(0)
}

async fn entity_count(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    entity_id: &str,
) -> i64 {
    let entity = &registry.entities()[entity_id];
    database
        .admin
        .query_one(
            &format!(
                "SELECT count(*) FROM registry_data.{}",
                q(&entity.physical_table)
            ),
            &[],
        )
        .await
        .expect("administrator counts entity rows")
        .get(0)
}

async fn immediate_action_receipt_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_idempotency
              WHERE result_kind = 'immediate_action'",
            &[],
        )
        .await
        .expect("administrator counts immediate-action receipts")
        .get(0)
}

async fn move_household_to_jurisdiction(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    household_id: &str,
    jurisdiction: &str,
) {
    let household = &registry.entities()["household"];
    let table = &household.physical_table;
    let jurisdiction_field = &household.fields["jurisdiction"].physical_name;
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{table}
                    SET {jurisdiction_field} = $1
                  WHERE record_id = $2",
                table = q(table),
                jurisdiction_field = q(jurisdiction_field),
            ),
            &[
                &jurisdiction,
                &Uuid::parse_str(household_id).expect("household UUID"),
            ],
        )
        .await
        .expect("administrator moves household boundary for replay check");
}

fn q(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn action_router(
    database: &TestDatabase,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: registry_server::postgres::ExpectedRegistryIdentity,
) -> axum::Router {
    action_router_with_fault_and_timeout(database, registry, identity, None, None)
}

fn action_router_with_fault(
    database: &TestDatabase,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: registry_server::postgres::ExpectedRegistryIdentity,
    fault: Option<MutationFaultPoint>,
) -> axum::Router {
    action_router_with_fault_and_timeout(database, registry, identity, fault, None)
}

fn action_router_with_timeout(
    database: &TestDatabase,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: registry_server::postgres::ExpectedRegistryIdentity,
    timeout: Duration,
) -> axum::Router {
    action_router_with_fault_and_timeout(database, registry, identity, None, Some(timeout))
}

fn action_router_with_fault_and_timeout(
    database: &TestDatabase,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: registry_server::postgres::ExpectedRegistryIdentity,
    fault: Option<MutationFaultPoint>,
    action_timeout: Option<Duration>,
) -> axum::Router {
    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let profile = AuditProfile::production_from_secret_bytes(vec![0x42; 32].into())
        .expect("test owns a keyed audit profile");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x63; 32]), Duration::from_secs(300))
            .expect("test cursor key is valid"),
    );
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        profile.clone(),
        cursors.clone(),
    ));
    let read_identity = ReadRuntimeIdentity {
        package_revision: identity.package_revision.clone(),
        schema_fingerprint: identity.schema_fingerprint.clone(),
    };
    let mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity,
        lock_key,
        Duration::from_secs(2),
        profile,
    );
    let mutations = match fault {
        Some(fault) => mutations.with_fault_for_test(fault),
        None => mutations,
    };
    let mutations = match action_timeout {
        Some(timeout) => mutations.with_action_timeout_for_test(timeout),
        None => mutations,
    };
    router(Arc::new(
        HttpService::new(
            registry,
            read_identity,
            records,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_postgres_mutations(Arc::new(mutations)),
    ))
}

async fn seed_household(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    identity: &registry_server::postgres::ExpectedRegistryIdentity,
    household_id: &str,
    household_code: &str,
    jurisdiction: &str,
) {
    let household = &registry.entities()["household"];
    let table = &household.physical_table;
    let code = &household.fields["household-code"].physical_name;
    let jurisdiction_field = &household.fields["jurisdiction"].physical_name;
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds for RLS-safe seed");
    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available for RLS-safe seed");
    let claims = seed_claims(registry, jurisdiction);
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(2),
        identity,
        &claims,
    )
    .await
    .expect("seed transaction installs compiled RLS context");
    transaction
        .transaction_for_test()
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                    (record_id, record_revision, record_lifecycle, active_package_revision, {code}, {jurisdiction_field})
                 VALUES ($1, 1, 'active', $2, $3, $4)",
                table = q(table),
                code = q(code),
                jurisdiction_field = q(jurisdiction_field),
            ),
            &[
                &Uuid::parse_str(household_id).expect("seed UUID"),
                &identity.package_revision,
                &household_code,
                &jurisdiction,
            ],
        )
        .await
        .expect("compiled seed context admits exact household target");
    transaction
        .commit()
        .await
        .expect("RLS-safe seed transaction commits");
}

fn seed_claims(registry: &registry_server::CompiledRegistry, jurisdiction: &str) -> ClaimContext {
    ClaimContext::for_compiled(
        registry,
        "household",
        Some("seed-principal".to_owned()),
        "household-seed-writer",
        None,
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: jurisdiction.to_owned(),
        }],
    )
    .expect("seed claims are compiler-bound")
}

async fn household_contact(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
) -> String {
    let household = &registry.entities()["household"];
    let table = &household.physical_table;
    let contact = &household.fields["contact-person"].physical_name;
    let row = database
        .admin
        .query_one(
            &format!("SELECT {contact}::text FROM registry_data.{table} WHERE record_id = $1"),
            &[&Uuid::parse_str(HOUSEHOLD_ID).expect("seed UUID")],
        )
        .await
        .expect("household row exists");
    row.get(0)
}

async fn membership_links(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    membership_id: &str,
) -> (String, String) {
    let membership = &registry.entities()["group-membership"];
    let table = &membership.physical_table;
    let person = &membership.fields["person"].physical_name;
    let household = &membership.fields["household"].physical_name;
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT {person}::text, {household}::text FROM registry_data.{table} WHERE record_id = $1"
            ),
            &[&Uuid::parse_str(membership_id).expect("membership UUID")],
        )
        .await
        .expect("membership row exists");
    (row.get(0), row.get(1))
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
            HeaderName::from_bytes(name.as_bytes()).expect("header name is valid"),
            HeaderValue::from_str(value).expect("header value is valid"),
        );
    }
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router responds")
}

struct ResponseParts {
    status: StatusCode,
    body: Value,
    content_type: String,
}

async fn response_parts(response: axum::response::Response) -> ResponseParts {
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body");
    ResponseParts {
        status,
        body: serde_json::from_slice(&body).expect("response is JSON"),
        content_type: headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
    }
}

#[derive(Clone)]
struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn action_claims() -> VerifiedRequestClaims {
    action_claims_for("registry:contact:register", "zone-a")
}

fn shadow_claims() -> VerifiedRequestClaims {
    action_claims_for("registry:contact:shadow", "zone-a")
}

fn action_claims_for(scope: &str, jurisdiction: &str) -> VerifiedRequestClaims {
    let mut direct_claims = BTreeMap::new();
    direct_claims.insert(
        "jurisdiction".to_owned(),
        VerifiedClaimValue::direct_string(jurisdiction).expect("direct claim"),
    );
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "registrar-principal",
        BTreeSet::from([scope.to_owned()]),
        Some("contact-registration".to_owned()),
        direct_claims,
    )
    .expect("authenticated action claims are valid")
}

fn compiled_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"immediate-action-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable",
            "constraints":[{"kind":"unique","fields":["person-code"]}],
            "fields":[
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"},
              {"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"}
            ],
            "events":[{"id":"person-created","trigger":"created","projection":["person-code"]}]
          },{
            "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable",
            "fields":[
              {"id":"household-code","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"contact-person","apiName":"contactPerson","type":"reference","target":"person","classification":"restricted"},
              {"id":"status-note","apiName":"statusNote","type":"string","maxLength":160,"classification":"restricted"}
            ],
            "events":[{"id":"household-patched","trigger":"patched","projection":["contact-person"]}]
          },{
            "id":"group-membership","primaryDataset":"test-dataset","route":"group-memberships","mutationMode":"mutable",
            "fields":[
              {"id":"person","type":"reference","target":"person","required":true,"classification":"restricted"},
              {"id":"household","type":"reference","target":"household","required":true,"classification":"restricted"},
              {"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"}
            ],
            "events":[{"id":"membership-created","trigger":"created","projection":["person","household"]}]
          }],
          "actions":[{
            "id":"register-household-contact",
            "inputs":[
              {"id":"household","apiName":"householdId","type":"reference","target":"household","required":true,"classification":"restricted"},
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"},
              {"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"}
            ],
            "effects":[
              {"id":"person","target":{"entity":"person"},"operation":"create",
                "set":{"person-code":{"fromField":"person-code"},"legal-name":{"fromField":"legal-name"},"jurisdiction":{"fromField":"jurisdiction"}}},
              {"id":"membership","target":{"entity":"group-membership"},"operation":"create",
                "set":{"person":{"fromEffect":"person"},"household":{"fromField":"household"},"jurisdiction":{"fromField":"jurisdiction"}}},
              {"id":"household","target":{"fromField":"household"},"operation":"patch",
                "set":{"contact-person":{"fromEffect":"person"}}}
            ]
          },{
            "id":"rename-household-local",
            "inputs":[
              {"id":"household","apiName":"householdId","type":"reference","target":"household","required":true,"classification":"restricted"},
              {"id":"household-code","apiName":"householdCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"status-note","apiName":"statusNote","type":"string","maxLength":160,"required":true,"classification":"restricted"}
            ],
            "effects":[
              {"id":"household-code-update","target":{"fromField":"household"},"operation":"patch",
                "set":{"household-code":{"fromField":"household-code"}}},
              {"id":"household-note-update","target":{"fromField":"household"},"operation":"patch",
                "set":{"status-note":{"fromField":"status-note"}}}
            ]
          },{
            "id":"link-household-member",
            "inputs":[
              {"id":"household","apiName":"householdId","type":"reference","target":"household","required":true,"classification":"restricted"},
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"},
              {"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"}
            ],
            "effects":[
              {"id":"linked-person","target":{"entity":"person"},"operation":"create",
                "set":{"person-code":{"fromField":"person-code"},"legal-name":{"fromField":"legal-name"},"jurisdiction":{"fromField":"jurisdiction"}}},
              {"id":"linked-membership","target":{"entity":"group-membership"},"operation":"create",
                "set":{"person":{"fromEffect":"linked-person"},"household":{"fromField":"household"},"jurisdiction":{"fromField":"jurisdiction"}}}
            ]
          },{
            "id":"create-silent-person",
            "inputs":[
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"},
              {"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"}
            ],
            "effects":[
              {"id":"silent-person","target":{"entity":"person"},"operation":"create",
                "set":{"person-code":{"fromField":"person-code"},"legal-name":{"fromField":"legal-name"},"jurisdiction":{"fromField":"jurisdiction"}}}
            ]
          },{
            "id":"create-local-person",
            "inputs":[
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"},
              {"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"}
            ],
            "effects":[
              {"id":"person-only","target":{"entity":"person"},"operation":"create",
                "set":{"person-code":{"fromField":"person-code"},"legal-name":{"fromField":"legal-name"},"jurisdiction":{"fromField":"jurisdiction"}}}
            ]
          }],
          "accessProfiles":[{
            "id":"contact-registrar",
            "default":true,
            "principalClaim":"registry_principal",
            "requiredScopes":["registry:contact:register"],
            "requiredPurposes":["contact-registration"],
            "grants":[{
              "action":"register-household-contact",
              "operations":["invoke"],
              "targets":[
                {"entity":"household","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]},
                {"entity":"person","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]},
                {"entity":"group-membership","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}
              ],
              "results":["person","membership","household"]
            },{
              "action":"rename-household-local",
              "operations":["invoke"],
              "targets":[
                {"entity":"household","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}
              ],
              "results":["household-code-update","household-note-update"]
            },{
              "action":"link-household-member",
              "operations":["invoke"],
              "targets":[
                {"entity":"household","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]},
                {"entity":"person","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]},
                {"entity":"group-membership","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}
              ],
              "results":["linked-person","linked-membership"]
            },{
              "action":"create-silent-person",
              "operations":["invoke"],
              "targets":[
                {"entity":"person","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}
              ],
              "results":[]
            },{
              "action":"create-local-person",
              "operations":["invoke"],
              "targets":[
                {"entity":"person","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}
              ],
              "results":["person-only"]
            }]
          },{
            "id":"contact-shadow",
            "principalClaim":"registry_principal",
            "requiredScopes":["registry:contact:shadow"],
            "requiredPurposes":["contact-registration"],
            "grants":[{
              "action":"register-household-contact",
              "operations":["invoke"],
              "targets":[
                {"entity":"household","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]},
                {"entity":"person","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]},
                {"entity":"group-membership","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}
              ],
              "results":["household"]
            }]
          },{
            "id":"household-seed-writer",
            "principalClaim":"registry_principal",
            "grants":[{
              "entity":"household",
              "operations":["create"],
              "readableFields":["household-code","jurisdiction"],
              "writableFields":["household-code","jurisdiction"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]
          }]
        }"#,
    )
    .expect("action project parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("action project compiles")
}

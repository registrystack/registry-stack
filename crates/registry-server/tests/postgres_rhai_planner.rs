// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/pilot_acceptance_harness.rs"]
#[allow(dead_code)]
mod pilot_acceptance_harness;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use pilot_acceptance_harness::{response_bytes, PilotHarness};
use postgres_harness::TestDatabase;
use registry_platform_audit::AuditProfile;
use registry_server::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedRequestClaims,
};
use registry_server::compiler::{compile_project_with_assets, CompileProfile};
use registry_server::contract::{parse_project_json, ModuleAssetSource};
use registry_server::cursor::CursorCodec;
use registry_server::mutation::MutationFaultPoint;
use registry_server::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, PostgresRevisionReadService,
    RegistryLockKey, RegistryStateTestIdentity,
};
use registry_server::rhai_planner::{
    reset_test_planner_invocation_count, test_planner_invocation_count,
};
use serde_json::{json, Value};
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

static PLANNER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rhai_planner_automatic_transition_requires_same_profile_and_is_atomic() {
    let _test_guard = PLANNER_TEST_LOCK.lock().await;
    let harness = PilotHarness::start("person-name-change-rhai").await;
    reset_test_planner_invocation_count();
    let operator = harness.token("person-maintenance", &[]);
    let submitter =
        harness.token_with_scopes("person-name-change", &[], &["registry:person-name:submit"]);
    let unrelated_applier = harness.token_with_scopes(
        "person-name-apply",
        &[],
        &["registry:person-name:apply-assisted"],
    );

    let person = create_record(
        &harness,
        "/v1/records/persons?accessProfile=person-operator",
        &operator,
        "rhai-atomic-create-person",
        json!({"personCode":"SEC-RHAI-001","displayName":"Before Planner"}),
    )
    .await;
    let request = create_record(
        &harness,
        "/v1/records/person-name-change-requests?accessProfile=name-change-submitter",
        &submitter,
        "rhai-atomic-create-request",
        json!({
            "person": person.id,
            "givenName": "  Katherine  ",
            "familyName": "  Johnson  ",
            "handling": "routine"
        }),
    )
    .await;

    // Authority stays with the selected profile. An actor holding the separate
    // assisted application profile cannot borrow the submitter profile's
    // request authority or make the automatic transition available.
    let cross_profile = harness
        .send(
            Method::GET,
            &format!(
                "/v1/records/person-name-change-requests/{}?accessProfile=name-change-submitter",
                request.id
            ),
            Some(&unrelated_applier),
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(cross_profile.status(), StatusCode::NOT_FOUND);

    let before_submit = get_record(
        &harness,
        &format!(
            "/v1/records/person-name-change-requests/{}?accessProfile=name-change-submitter",
            request.id
        ),
        &submitter,
    )
    .await;
    assert_eq!(before_submit.body["request"]["serverState"], "draft");
    assert_eq!(before_submit.body["data"]["givenName"], "  Katherine  ");
    assert_eq!(before_submit.body["data"]["familyName"], "  Johnson  ");
    assert_eq!(test_planner_invocation_count(), 0);
    let submit = action(&before_submit.body, "submit_request");

    let first = send_action(
        &harness,
        &submit,
        &submitter,
        "rhai-atomic-submit-and-apply",
        json!({}),
    )
    .await;
    assert_eq!(
        first.status,
        StatusCode::OK,
        "{}; planner invocations={}",
        first.body,
        test_planner_invocation_count()
    );
    assert_eq!(first.body["request"]["serverState"], "applied");
    assert_eq!(first.body["request"]["proposalVersion"], 1);
    assert_eq!(first.body["request"]["application"]["proposalVersion"], 1);
    assert_eq!(test_planner_invocation_count(), 1);

    // Lost-response recovery returns the one stored terminal response. It does
    // not re-run Rhai, apply the effect twice, or split the request transition
    // from the authoritative mutation.
    let replay = send_action(
        &harness,
        &submit,
        &submitter,
        "rhai-atomic-submit-and-apply",
        json!({}),
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK, "{}", replay.body);
    assert_eq!(replay.bytes, first.bytes);
    assert_eq!(test_planner_invocation_count(), 1);

    let changed = get_record(
        &harness,
        &format!(
            "/v1/records/persons/{}?accessProfile=person-operator",
            person.id
        ),
        &operator,
    )
    .await;
    assert_eq!(changed.body["revision"], 2);
    assert_eq!(changed.body["data"]["displayName"], "Katherine Johnson");
    assert_eq!(test_planner_invocation_count(), 1);

    let application_count: i64 = harness
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_request_applications \
             WHERE request_entity_id = 'person-name-change-request' AND request_id = $1",
            &[&uuid::Uuid::parse_str(&request.id).expect("request id is a UUID")],
        )
        .await
        .expect("application ledger count reads")
        .get(0);
    assert_eq!(application_count, 1);

    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rhai_planner_assisted_queue_applies_frozen_effects_without_rerun() {
    let _test_guard = PLANNER_TEST_LOCK.lock().await;
    let harness = PilotHarness::start("person-name-change-rhai").await;
    reset_test_planner_invocation_count();
    let operator = harness.token("person-maintenance", &[]);
    let submitter =
        harness.token_with_scopes("person-name-change", &[], &["registry:person-name:submit"]);
    let assisted_applier = harness.token_with_scopes(
        "person-name-apply",
        &[],
        &["registry:person-name:apply-assisted"],
    );

    let person = create_record(
        &harness,
        "/v1/records/persons?accessProfile=person-operator",
        &operator,
        "rhai-assisted-create-person",
        json!({"personCode":"SEC-RHAI-002","displayName":"Before Assisted Planner"}),
    )
    .await;
    let request = create_record(
        &harness,
        "/v1/records/person-name-change-requests?accessProfile=name-change-submitter",
        &submitter,
        "rhai-assisted-create-request",
        json!({
            "person": person.id,
            "givenName": "  Grace  ",
            "familyName": "  Hopper  ",
            "handling": "assisted"
        }),
    )
    .await;
    let before_submit = get_record(
        &harness,
        &format!(
            "/v1/records/person-name-change-requests/{}?accessProfile=name-change-submitter",
            request.id
        ),
        &submitter,
    )
    .await;
    let submit = action(&before_submit.body, "submit_request");

    let queued = send_action(
        &harness,
        &submit,
        &submitter,
        "rhai-assisted-submit-and-queue",
        json!({}),
    )
    .await;
    assert_eq!(queued.status, StatusCode::OK, "{}", queued.body);
    assert_eq!(queued.body["request"]["serverState"], "approved");
    assert_eq!(queued.body["request"]["proposal"]["reviewMode"], "none");
    assert_eq!(
        queued.body["request"]["proposal"]["applicationDisposition"],
        "queue"
    );
    assert_eq!(
        queued.body["request"]["proposal"]["queueReason"],
        json!({
            "code": "assisted-review",
            "label": "Assisted review requested by synthetic handling."
        })
    );
    assert_eq!(queued.body["request"]["application"], Value::Null);
    assert_eq!(test_planner_invocation_count(), 1);

    let before_apply = get_record(
        &harness,
        &format!(
            "/v1/records/person-name-change-requests/{}?accessProfile=assisted-applier",
            request.id
        ),
        &assisted_applier,
    )
    .await;
    assert_eq!(before_apply.body["request"]["serverState"], "approved");
    assert_eq!(test_planner_invocation_count(), 1);
    let apply = action(&before_apply.body, "apply_request");
    let applied = send_action(
        &harness,
        &apply,
        &assisted_applier,
        "rhai-assisted-apply-frozen",
        json!({
            "proposalVersion": before_apply.body["request"]["proposalVersion"],
            "effectDigest": before_apply.body["request"]["effectDigest"]
        }),
    )
    .await;
    assert_eq!(applied.status, StatusCode::OK, "{}", applied.body);
    assert_eq!(applied.body["request"]["serverState"], "applied");
    assert_eq!(test_planner_invocation_count(), 1);

    let changed = get_record(
        &harness,
        &format!(
            "/v1/records/persons/{}?accessProfile=person-operator",
            person.id
        ),
        &operator,
    )
    .await;
    assert_eq!(changed.body["revision"], 2);
    assert_eq!(changed.body["data"]["displayName"], "Grace Hopper");
    assert_eq!(test_planner_invocation_count(), 1);

    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_rhai_final_approval_applies_atomically_and_faults_roll_back_every_surface() {
    let _test_guard = PLANNER_TEST_LOCK.lock().await;
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(staged_rhai_registry());
    let package_id = "staged-rhai-final-approval";
    let identity = install_staged_registry(&database, &registry, package_id).await;
    let app = staged_router(
        &database,
        registry.clone(),
        identity.clone(),
        package_id,
        None,
    );
    let before_current_row = staged_router(
        &database,
        registry.clone(),
        identity.clone(),
        package_id,
        Some(MutationFaultPoint::BeforeCurrentRow),
    );
    let after_first_target = staged_router(
        &database,
        registry,
        identity,
        package_id,
        Some(MutationFaultPoint::AfterFirstBatchItem),
    );
    reset_test_planner_invocation_count();
    let operator = verified_claims("staged-operator", "person-maintenance", &[]);
    let submitter = verified_claims(
        "staged-submitter",
        "person-name-change",
        &["registry:person-name:submit"],
    );
    let final_reviewer = verified_claims("staged-final-reviewer", "person-name-final", &[]);

    let person = direct_create_record(
        &app,
        "/v1/records/persons?accessProfile=person-operator",
        operator.clone(),
        "staged-rhai-create-person",
        json!({"personCode":"SEC-RHAI-STAGED","displayName":"Before Staged Planner"}),
    )
    .await;
    let request = direct_create_record(
        &app,
        "/v1/records/person-name-change-requests?accessProfile=name-change-submitter",
        submitter.clone(),
        "staged-rhai-create-request",
        json!({
            "person": person.id,
            "givenName": "  Dorothy  ",
            "familyName": "  Vaughan  ",
            "handling": "routine"
        }),
    )
    .await;
    let draft = direct_get_record(
        &app,
        &format!(
            "/v1/records/person-name-change-requests/{}?accessProfile=name-change-submitter",
            request.id
        ),
        submitter.clone(),
    )
    .await;
    let submit = action(&draft.body, "submit_request");
    let submitted =
        direct_send_action(&app, &submit, submitter, "staged-rhai-submit", json!({})).await;
    assert_eq!(submitted.status, StatusCode::OK, "{}", submitted.body);
    assert_eq!(submitted.body["request"]["serverState"], "submitted");
    assert_eq!(
        submitted.body["request"]["proposal"]["applicationDisposition"],
        "apply"
    );
    assert_eq!(test_planner_invocation_count(), 1);

    let pending = direct_get_record(
        &app,
        &format!(
            "/v1/records/person-name-change-requests/{}?accessProfile=staged-final-reviewer",
            request.id
        ),
        final_reviewer.clone(),
    )
    .await;
    let approve = action(&pending.body, "approve_request");
    let approve_body = json!({
        "proposalVersion": pending.body["request"]["proposalVersion"],
        "effectDigest": pending.body["request"]["effectDigest"]
    });
    for (fault_app, key) in [
        (&before_current_row, "staged-rhai-fault-before-current"),
        (&after_first_target, "staged-rhai-fault-after-first-target"),
    ] {
        let before_fault = staged_persistence_snapshot(&database, &request.id).await;
        let failed = direct_send_action(
            fault_app,
            &approve,
            final_reviewer.clone(),
            key,
            approve_body.clone(),
        )
        .await;
        assert_eq!(failed.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(failed.body["code"], "service.unavailable");
        let mut after_fault = staged_persistence_snapshot(&database, &request.id).await;
        assert_eq!(
            after_fault.audit,
            before_fault.audit + 1,
            "fault {key} must produce exactly one durable failure audit"
        );
        after_fault.audit = before_fault.audit;
        assert_eq!(
            after_fault,
            before_fault,
            "fault {key} must not retain a decision, application, target write, event, audit, or receipt"
        );
        let unchanged_request = direct_get_record(
            &app,
            &format!(
                "/v1/records/person-name-change-requests/{}?accessProfile=staged-final-reviewer",
                request.id
            ),
            final_reviewer.clone(),
        )
        .await;
        assert_eq!(
            unchanged_request.body["request"]["serverState"],
            "submitted"
        );
        assert_eq!(unchanged_request.body["revision"], pending.body["revision"]);
        let unchanged_person = direct_get_record(
            &app,
            &format!(
                "/v1/records/persons/{}?accessProfile=person-operator",
                person.id
            ),
            operator.clone(),
        )
        .await;
        assert_eq!(unchanged_person.body["revision"], 1);
        assert_eq!(
            unchanged_person.body["data"]["displayName"],
            "Before Staged Planner"
        );
        assert_eq!(test_planner_invocation_count(), 1);
    }

    let applied = direct_send_action(
        &app,
        &approve,
        final_reviewer.clone(),
        "staged-rhai-final-approve",
        approve_body.clone(),
    )
    .await;
    assert_eq!(applied.status, StatusCode::OK, "{}", applied.body);
    assert_eq!(applied.body["request"]["serverState"], "applied");
    assert_eq!(test_planner_invocation_count(), 1);
    let replay = direct_send_action(
        &app,
        &approve,
        final_reviewer,
        "staged-rhai-final-approve",
        approve_body,
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK, "{}", replay.body);
    assert_eq!(replay.bytes, applied.bytes);
    assert_eq!(test_planner_invocation_count(), 1);

    let changed = direct_get_record(
        &app,
        &format!(
            "/v1/records/persons/{}?accessProfile=person-operator",
            person.id
        ),
        operator,
    )
    .await;
    assert_eq!(changed.body["revision"], 2);
    assert_eq!(changed.body["data"]["displayName"], "Dorothy Vaughan");
    let terminal = staged_persistence_snapshot(&database, &request.id).await;
    assert_eq!(terminal.state, "applied");
    assert_eq!(terminal.decisions, 1);
    assert_eq!(terminal.applications, 1);
    assert_eq!(terminal.results, 1);

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failing_rhai_planner_refuses_the_submission_and_records_its_kind() {
    let _test_guard = PLANNER_TEST_LOCK.lock().await;
    let database = TestDatabase::create(4).await;
    let registry = Arc::new(refusing_rhai_registry());
    let package_id = "refusing-rhai-planner";
    let identity = install_staged_registry(&database, &registry, package_id).await;
    let app = staged_router(&database, registry, identity, package_id, None);
    reset_test_planner_invocation_count();
    let operator = verified_claims("refusing-operator", "person-maintenance", &[]);
    let submitter = verified_claims(
        "refusing-submitter",
        "person-name-change",
        &["registry:person-name:submit"],
    );

    let person = direct_create_record(
        &app,
        "/v1/records/persons?accessProfile=person-operator",
        operator.clone(),
        "refusing-rhai-create-person",
        json!({"personCode":"SEC-RHAI-REFUSED","displayName":"Before Refusing Planner"}),
    )
    .await;
    let request = direct_create_record(
        &app,
        "/v1/records/person-name-change-requests?accessProfile=name-change-submitter",
        submitter.clone(),
        "refusing-rhai-create-request",
        json!({
            "person": person.id,
            "givenName": "  Mary  ",
            "familyName": "  Jackson  ",
            "handling": "routine"
        }),
    )
    .await;
    let draft = direct_get_record(
        &app,
        &format!(
            "/v1/records/person-name-change-requests/{}?accessProfile=name-change-submitter",
            request.id
        ),
        submitter.clone(),
    )
    .await;
    let submit = action(&draft.body, "submit_request");
    let refused =
        direct_send_action(&app, &submit, submitter, "refusing-rhai-submit", json!({})).await;

    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert_eq!(refused.body["code"], "request.plan_refused");
    assert_eq!(
        refused.body["detail"],
        "The change-request planner refused the submission: change_request.planner.execution."
    );
    assert_eq!(test_planner_invocation_count(), 1);

    // The refusal names the closed planner vocabulary and nothing else: not the
    // script, not the authored request values, not the target it would change.
    let refusal_text = String::from_utf8(refused.bytes.clone()).expect("problem body is UTF-8");
    for withheld in [
        "refuse_this_submission",
        "Mary",
        "Jackson",
        person.id.as_str(),
        request.id.as_str(),
    ] {
        assert!(
            !refusal_text.contains(withheld),
            "the refusal must withhold {withheld}: {refusal_text}"
        );
    }

    // A refused plan freezes nothing and leaves the target untouched.
    let snapshot = staged_persistence_snapshot(&database, &request.id).await;
    assert_eq!(snapshot.state, "draft");
    assert_eq!(snapshot.proposals, 0);
    assert_eq!(snapshot.targets, 0);
    assert_eq!(snapshot.applications, 0);
    assert_eq!(snapshot.results, 0);
    let unchanged = direct_get_record(
        &app,
        &format!(
            "/v1/records/persons/{}?accessProfile=person-operator",
            person.id
        ),
        operator,
    )
    .await;
    assert_eq!(unchanged.body["revision"], 1);
    assert_eq!(
        unchanged.body["data"]["displayName"],
        "Before Refusing Planner"
    );

    // The refusal is journaled with the same closed vocabulary the caller saw.
    let refusals = audit_refusal_reasons(&database).await;
    assert_eq!(
        refusals,
        vec!["change_request.planner.execution".to_owned()]
    );

    database.cleanup().await;
}

async fn audit_refusal_reasons(database: &TestDatabase) -> Vec<String> {
    let rows = database
        .admin
        .query("SELECT envelope FROM registry_internal.registry_audit", &[])
        .await
        .expect("administrator can inspect audit envelopes");
    rows.iter()
        .filter_map(|row| {
            let envelope: Value = serde_json::from_slice(&row.get::<_, Vec<u8>>(0))
                .expect("audit envelope is strict JSON");
            envelope["record"]["refusalReason"]
                .as_str()
                .map(str::to_owned)
        })
        .collect()
}

/// A planner that compiles and declares the committed fixture's write, then
/// fails while it runs. It is the shortest way to reach the planner failure
/// path with every other part of the fixture contract left alone.
const REFUSING_PLANNER_SCRIPT: &str = r#"
fn plan(ctx) {
    ctx.request["given-name"].refuse_this_submission();
    #{
        effects: [#{
            target: #{fromField: "person"},
            operation: "patch",
            set: #{"display-name": "unreachable"}
        }],
        disposition: "apply"
    }
}
"#;

fn refusing_rhai_registry() -> registry_server::CompiledRegistry {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/registry-server/acceptance/person-name-change-rhai");
    let project_bytes = std::fs::read(root.join("registry.yaml"))
        .expect("committed Rhai fixture project is readable");
    let project: Value =
        serde_norway::from_slice(&project_bytes).expect("Rhai fixture YAML converts to JSON");
    let project = parse_project_json(
        &serde_json::to_vec(&project).expect("refusing Rhai project serializes"),
    )
    .expect("refusing Rhai project follows the strict contract");
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "scripts/person-name-change.rhai".to_owned(),
            bytes: REFUSING_PLANNER_SCRIPT.as_bytes().to_vec(),
        }],
        CompileProfile::Production,
    )
    .expect("refusing Rhai project closes under the Production compiler")
}

fn staged_rhai_registry() -> registry_server::CompiledRegistry {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/registry-server/acceptance/person-name-change-rhai");
    let project_bytes = std::fs::read(root.join("registry.yaml"))
        .expect("committed Rhai fixture project is readable");
    let mut project: Value =
        serde_norway::from_slice(&project_bytes).expect("Rhai fixture YAML converts to JSON");
    let request = project["entities"]
        .as_array_mut()
        .expect("fixture entities are an array")
        .iter_mut()
        .find(|entity| entity["id"] == "person-name-change-request")
        .expect("fixture request entity exists");
    request["changeRequest"]["review"] = json!({
        "stages": [{"id": "final", "approvals": 1}]
    });
    project["accessProfiles"]
        .as_array_mut()
        .expect("fixture profiles are an array")
        .push(json!({
            "id": "staged-final-reviewer",
            "principalClaim": "registry_principal",
            "requiredPurposes": ["person-name-final"],
            "grants": [{
                "entity": "person-name-change-request",
                "operations": ["get", "approve_request", "apply_request"],
                "readableFields": ["person", "given-name", "family-name", "handling"],
                "reviewStages": [{
                    "stage": "final",
                    "targets": [{"entity": "person", "readableFields": ["display-name"]}]
                }],
                "applyTargets": [{"entity": "person", "rowBoundaries": []}]
            }]
        }));
    let project =
        parse_project_json(&serde_json::to_vec(&project).expect("staged Rhai project serializes"))
            .expect("staged Rhai project follows the strict contract");
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "scripts/person-name-change.rhai".to_owned(),
            bytes: std::fs::read(root.join("scripts/person-name-change.rhai"))
                .expect("committed Rhai planner is readable"),
        }],
        CompileProfile::Production,
    )
    .expect("staged Rhai project closes under the Production compiler")
}

async fn install_staged_registry(
    database: &TestDatabase,
    registry: &Arc<registry_server::CompiledRegistry>,
    package_id: &str,
) -> registry_server::postgres::ExpectedRegistryIdentity {
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, registry, &database.runtime_role)
        .await
        .expect("staged Rhai schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        registry,
        RegistryStateTestIdentity {
            package_id,
            environment: "local",
            instance_id: "staged-rhai-test-instance",
            database_id: "staged-rhai-test-database",
            package_revision:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            package_sequence: 1,
        },
    )
    .await
    .expect("staged Rhai registry identity initializes");
    drop(migration);
    migration_task.abort();
    identity
}

fn staged_router(
    database: &TestDatabase,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: registry_server::postgres::ExpectedRegistryIdentity,
    package_id: &str,
    fault: Option<MutationFaultPoint>,
) -> axum::Router {
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(package_id).expect("lock key derives");
    let audit = AuditProfile::production_from_secret_bytes(vec![0x5a; 32].into())
        .expect("test audit profile is keyed");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x2d; 32]), Duration::from_secs(300))
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
        .with_postgres_mutations(Arc::new(mutations)),
    ))
}

fn verified_claims(principal: &str, purpose: &str, scopes: &[&str]) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        Some(purpose.to_owned()),
        BTreeMap::new(),
    )
    .expect("direct staged claims are verified")
}

async fn direct_send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: VerifiedRequestClaims,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .expect("direct staged request builds");
    for (name, value) in headers {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("direct staged header name is valid"),
            HeaderValue::from_str(value).expect("direct staged header value is valid"),
        );
    }
    request.extensions_mut().insert(claims);
    let mut app = app.clone();
    app.call(request)
        .await
        .expect("direct staged Router responds")
}

async fn direct_create_record(
    app: &axum::Router,
    uri: &str,
    claims: VerifiedRequestClaims,
    idempotency_key: &str,
    data: Value,
) -> CreatedRecord {
    let response = direct_send(
        app,
        Method::POST,
        uri,
        claims,
        &[
            ("content-type", "application/json"),
            ("idempotency-key", idempotency_key),
        ],
        serde_json::to_vec(&json!({"data": data})).expect("direct create body serializes"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "{uri}");
    let body = normalized_json(response).await;
    CreatedRecord {
        id: body["id"]
            .as_str()
            .expect("created record has an identifier")
            .to_owned(),
    }
}

async fn direct_get_record(
    app: &axum::Router,
    uri: &str,
    claims: VerifiedRequestClaims,
) -> RecordResponse {
    let response = direct_send(app, Method::GET, uri, claims, &[], Vec::new()).await;
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    RecordResponse {
        body: normalized_json(response).await,
    }
}

async fn direct_send_action(
    app: &axum::Router,
    action: &Action,
    claims: VerifiedRequestClaims,
    idempotency_key: &str,
    body: Value,
) -> ActionResponse {
    let response = direct_send(
        app,
        Method::POST,
        &action.href,
        claims,
        &[
            ("content-type", "application/json"),
            ("idempotency-key", idempotency_key),
            ("if-match", &action.if_match),
        ],
        serde_json::to_vec(&body).expect("direct action body serializes"),
    )
    .await;
    let status = response.status();
    let bytes = response_bytes(response).await;
    let body = normalize_record_response(
        serde_json::from_slice(&bytes).expect("direct action response is strict JSON"),
    );
    ActionResponse {
        status,
        body,
        bytes,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct StagedPersistenceSnapshot {
    state: String,
    workflow_revision: i64,
    proposals: i64,
    targets: i64,
    decisions: i64,
    applications: i64,
    results: i64,
    outbox: i64,
    audit: i64,
    idempotency: i64,
}

async fn staged_persistence_snapshot(
    database: &TestDatabase,
    request_id: &str,
) -> StagedPersistenceSnapshot {
    let request_id = Uuid::parse_str(request_id).expect("request id is a UUID");
    let row = database
        .admin
        .query_one(
            "SELECT state, workflow_revision,
                    (SELECT count(*) FROM registry_internal.registry_request_proposals
                      WHERE request_entity_id = 'person-name-change-request' AND request_id = $1),
                    (SELECT count(*) FROM registry_internal.registry_request_targets
                      WHERE request_entity_id = 'person-name-change-request' AND request_id = $1),
                    (SELECT count(*) FROM registry_internal.registry_request_decisions
                      WHERE request_entity_id = 'person-name-change-request' AND request_id = $1),
                    (SELECT count(*) FROM registry_internal.registry_request_applications
                      WHERE request_entity_id = 'person-name-change-request' AND request_id = $1),
                    (SELECT count(*) FROM registry_internal.registry_request_results
                      WHERE request_entity_id = 'person-name-change-request' AND request_id = $1),
                    (SELECT count(*) FROM registry_internal.registry_outbox),
                    (SELECT count(*) FROM registry_internal.registry_audit),
                    (SELECT count(*) FROM registry_internal.registry_idempotency)
               FROM registry_internal.registry_request_state
              WHERE request_entity_id = 'person-name-change-request' AND request_id = $1",
            &[&request_id],
        )
        .await
        .expect("administrator can inspect staged Rhai persistence");
    StagedPersistenceSnapshot {
        state: row.get(0),
        workflow_revision: row.get(1),
        proposals: row.get(2),
        targets: row.get(3),
        decisions: row.get(4),
        applications: row.get(5),
        results: row.get(6),
        outbox: row.get(7),
        audit: row.get(8),
        idempotency: row.get(9),
    }
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

struct CreatedRecord {
    id: String,
}

struct RecordResponse {
    body: Value,
}

struct Action {
    href: String,
    if_match: String,
}

struct ActionResponse {
    status: StatusCode,
    body: Value,
    bytes: Vec<u8>,
}

async fn create_record(
    harness: &PilotHarness,
    uri: &str,
    token: &str,
    idempotency_key: &str,
    data: Value,
) -> CreatedRecord {
    let response = harness
        .send_json(
            Method::POST,
            uri,
            Some(token),
            Some(idempotency_key),
            json!({"data": data}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED, "{uri}");
    let body = normalized_json(response).await;
    CreatedRecord {
        id: body["id"]
            .as_str()
            .expect("created record has an identifier")
            .to_owned(),
    }
}

async fn get_record(harness: &PilotHarness, uri: &str, token: &str) -> RecordResponse {
    let response = harness
        .send(Method::GET, uri, Some(token), &[], Vec::new())
        .await;
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    RecordResponse {
        body: normalized_json(response).await,
    }
}

fn action(body: &Value, operation: &str) -> Action {
    let actions = body["request"]["actions"]
        .as_array()
        .expect("request response has finite actions");
    let selected = actions
        .iter()
        .find(|candidate| candidate["operation"] == operation)
        .unwrap_or_else(|| panic!("missing {operation} action in {actions:?}"));
    Action {
        href: selected["href"]
            .as_str()
            .expect("action has href")
            .to_owned(),
        if_match: selected["ifMatch"]
            .as_str()
            .expect("action has ifMatch")
            .to_owned(),
    }
}

async fn send_action(
    harness: &PilotHarness,
    action: &Action,
    token: &str,
    idempotency_key: &str,
    body: Value,
) -> ActionResponse {
    let response = harness
        .send(
            Method::POST,
            &action.href,
            Some(token),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", idempotency_key),
                ("if-match", &action.if_match),
            ],
            serde_json::to_vec(&body).expect("action body serializes"),
        )
        .await;
    let status = response.status();
    let bytes = response_bytes(response).await;
    let body = normalize_record_response(
        serde_json::from_slice(&bytes).expect("action response is strict JSON"),
    );
    ActionResponse {
        status,
        body,
        bytes,
    }
}

async fn normalized_json(response: axum::response::Response<Body>) -> Value {
    let bytes = response_bytes(response).await;
    normalize_record_response(
        serde_json::from_slice(&bytes).expect("record response is strict JSON"),
    )
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
        return normalize_record_member(object.remove("data").expect("record response has data"));
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
        .expect("record member has identifier");
    let revision = member
        .remove("revisionIdentifier")
        .and_then(|value| value.as_str().and_then(|value| value.parse::<u64>().ok()))
        .expect("record member has numeric revision");
    let domain_data = member
        .remove("domainData")
        .expect("record member has domain data");
    let mut normalized = serde_json::Map::from_iter([
        ("id".to_owned(), identifier),
        ("revision".to_owned(), json!(revision)),
        ("data".to_owned(), domain_data),
    ]);
    normalized.extend(member);
    Value::Object(normalized)
}

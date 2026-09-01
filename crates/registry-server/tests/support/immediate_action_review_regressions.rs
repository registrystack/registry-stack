// SPDX-License-Identifier: Apache-2.0

use super::*;
use registry_platform_audit::AuditEnvelope;
use tokio_postgres::error::SqlState;

const LOCK_RECORD_X: &str = "00000000-0000-4000-8000-000000000301";
const LOCK_RECORD_Y: &str = "00000000-0000-4000-8000-000000000302";
const WIDE_RECORD_ID: &str = "00000000-0000-4000-8000-000000000128";
const WIDE_EFFECT_COUNT: usize = 128;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replay_authorizes_only_disclosed_result_subset_after_hidden_results_change() {
    let (database, registry, identity) = setup_action_registry().await;
    let app = action_router(&database, registry.clone(), identity);
    let claims = shadow_claims();

    let condition = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact/target-conditions?accessProfile=contact-shadow",
            Some(claims.clone()),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"input":{"householdId":HOUSEHOLD_ID}}))
                .expect("condition body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(condition.status, StatusCode::OK, "{}", condition.body);

    let body = json!({
        "input": {
            "householdId": HOUSEHOLD_ID,
            "personCode": "P-HIDDEN-RESULT",
            "legalName": "Hidden Result Boundary Change",
            "jurisdiction": "zone-a"
        },
        "preconditions": condition.body["preconditions"].clone()
    });
    let first = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact?accessProfile=contact-shadow",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "shadow-result-subset-replay"),
            ],
            serde_json::to_vec(&body).expect("action body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    assert_eq!(
        first
            .body
            .get("results")
            .and_then(Value::as_object)
            .expect("results object")
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["household".to_owned()],
        "shadow profile receives only its granted nonempty result subset"
    );
    assert_eq!(first.body["results"]["household"]["entity"], "household");
    assert_eq!(first.body["results"]["household"]["id"], HOUSEHOLD_ID);
    assert!(first.body["results"].get("person").is_none());
    assert!(first.body["results"].get("membership").is_none());

    let after_commit = action_counts(&database, &registry).await;
    move_hidden_register_contact_results_out_of_boundary(
        &database,
        &registry,
        "P-HIDDEN-RESULT",
        "zone-b",
    )
    .await;

    let replay = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact?accessProfile=contact-shadow",
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "shadow-result-subset-replay"),
            ],
            serde_json::to_vec(&body).expect("action replay body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK, "{}", replay.body);
    assert_eq!(
        replay.body, first.body,
        "same-key replay returns the exact held bytes even when undisclosed created rows no longer satisfy current boundaries"
    );
    assert_eq!(
        action_counts(&database, &registry).await.without_audit(),
        after_commit.without_audit(),
        "replay reauthorizes the disclosed household result without reapplying effects"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn condition_read_terminal_audit_gates_metadata_and_stays_minimized() {
    let (database, registry, identity) = setup_action_registry().await;
    let app = action_router(&database, registry.clone(), identity);
    let claims = action_claims();

    let success = response_parts(
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
    assert_eq!(success.status, StatusCode::OK, "{}", success.body);
    assert_eq!(
        success.body,
        json!({"preconditions":{"householdId":{"ifMatch":success.body["preconditions"]["householdId"]["ifMatch"].clone()}}}),
        "condition read returns only the public condition role and opaque validator"
    );

    let records = audit_records(&database).await;
    let terminal = records
        .iter()
        .find(|record| {
            record["phase"] == "terminal"
                && record["outcome"] == "returned"
                && record["operationId"] == "actions.register-household-contact.target_conditions"
        })
        .expect("successful condition read records a terminal audit");
    assert_eq!(terminal["actionId"], "register-household-contact");
    assert_eq!(terminal["selectedAccessProfile"], "contact-registrar");
    assert_eq!(terminal["purposePresent"], true);
    assert_eq!(terminal["resultCount"], 1);
    for excluded in [
        "applicationReference",
        "entityId",
        "recordReference",
        "recordRevision",
        "fieldSetReference",
        "input",
        "preconditions",
        "response",
        "householdId",
        "ifMatch",
    ] {
        assert!(
            terminal.get(excluded).is_none(),
            "condition terminal audit must not contain {excluded}"
        );
    }

    install_condition_terminal_audit_failure(&database).await;
    let before_failure = action_counts(&database, &registry).await;
    let failed = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-household-contact/target-conditions",
            Some(claims),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"input":{"householdId":HOUSEHOLD_ID}}))
                .expect("faulted condition body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(
        failed.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        failed.body
    );
    assert_eq!(failed.body["code"], "service.unavailable");
    assert!(
        failed.body.get("preconditions").is_none(),
        "terminal audit failure withholds condition metadata"
    );
    assert!(!failed.body.to_string().contains(HOUSEHOLD_ID));
    assert_eq!(
        action_counts(&database, &registry).await.without_audit(),
        before_failure.without_audit(),
        "condition-read audit failure does not mutate action state or receipts"
    );

    let after_records = audit_records(&database).await;
    assert!(
        after_records.iter().any(|record| {
            record["phase"] == "attempt"
                && record["operationId"] == "actions.register-household-contact.target_conditions"
        }),
        "the failed condition read keeps its durable attempt audit"
    );
    let refusal = after_records
        .iter()
        .find(|record| {
            record["phase"] == "refusal"
                && record["operationId"] == "actions.register-household-contact.target_conditions"
        })
        .expect("the failed condition read records a value-free refusal audit");
    assert_eq!(refusal["actionId"], "register-household-contact");
    assert_eq!(refusal["selectedAccessProfile"], "contact-registrar");
    assert!(refusal.get("recordReference").is_none());
    assert!(refusal.get("recordRevision").is_none());
    assert!(!refusal.to_string().contains(HOUSEHOLD_ID));
    assert!(!refusal.to_string().contains("ifMatch"));
    assert_eq!(
        after_records
            .iter()
            .filter(|record| {
                record["phase"] == "terminal"
                    && record["operationId"]
                        == "actions.register-household-contact.target_conditions"
            })
            .count(),
        1,
        "the rejected terminal audit insert is rolled back rather than leaking a partial terminal record"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_known_abort_retry_reuses_reserved_create_and_application_ids() {
    let (database, registry, identity) = setup_action_registry().await;
    install_late_application_retry_probe(&database, &registry).await;
    let app = action_router(&database, registry.clone(), identity);

    let response = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/create-local-person",
            Some(action_claims()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "late-application-known-abort"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "personCode": "P-STABLE-RETRY",
                    "legalName": "Stable Retry",
                    "jurisdiction": "zone-a"
                }
            }))
            .expect("retry body serializes"),
        )
        .await,
    )
    .await;

    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    let (captured_application_id, captured_person_id) = captured_late_retry_ids(&database).await;
    assert_eq!(
        late_application_retry_attempts(&database).await,
        2,
        "the application insert trigger forced exactly one serialization abort before success"
    );
    assert_eq!(
        response.body["applicationId"]
            .as_str()
            .and_then(|id| Uuid::parse_str(id).ok()),
        Some(captured_application_id),
        "known-abort retry reuses the original reserved application id"
    );
    assert_eq!(
        response.body["results"]["person-only"]["id"]
            .as_str()
            .and_then(|id| Uuid::parse_str(id).ok()),
        Some(captured_person_id),
        "known-abort retry reuses the original reserved create id"
    );
    assert_eq!(entity_count(&database, &registry, "person").await, 1);
    assert_eq!(immediate_action_receipt_count(&database).await, 1);

    let row = database
        .admin
        .query_one(
            "SELECT a.application_id, r.target_record_id
               FROM registry_internal.registry_immediate_action_applications a
               JOIN registry_internal.registry_immediate_action_results r
                 ON r.key_reference = a.key_reference
              WHERE a.action_id = 'create-local-person'
                AND r.effect_id = 'person-only'",
            &[],
        )
        .await
        .expect("administrator inspects durable immediate-action receipt");
    assert_eq!(row.get::<_, Uuid>(0), captured_application_id);
    assert_eq!(row.get::<_, Uuid>(1), captured_person_id);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wide_patch_action_returns_and_replays_the_full_mutation_ceiling_result_set() {
    let (database, registry, identity) = setup_wide_action_registry().await;
    let app = action_router(&database, registry.clone(), identity);
    let claims = action_claims();

    let condition = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/patch-wide-flags/target-conditions",
            Some(claims.clone()),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"input":{"selectedRecordId":WIDE_RECORD_ID}}))
                .expect("wide condition body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(condition.status, StatusCode::OK, "{}", condition.body);

    let mut input =
        serde_json::Map::from_iter([("selectedRecordId".to_owned(), json!(WIDE_RECORD_ID))]);
    for index in 1..=WIDE_EFFECT_COUNT {
        input.insert(wide_flag_api_name(index), json!(true));
    }
    let body = json!({
        "input": input,
        "preconditions": condition.body["preconditions"].clone()
    });

    let first = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/patch-wide-flags",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "wide-128-result-replay"),
            ],
            serde_json::to_vec(&body).expect("wide action body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    assert_wide_results_share_one_record_revision(&first.body);
    assert_eq!(wide_record_revision(&database, &registry).await, 2);
    assert_eq!(wide_revision_rows(&database).await, 1);
    assert_eq!(
        wide_action_result_rows(&database).await,
        WIDE_EFFECT_COUNT as i64
    );
    assert_eq!(
        wide_true_flag_count(&database, &registry).await,
        WIDE_EFFECT_COUNT as i64
    );

    let replay = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/patch-wide-flags",
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "wide-128-result-replay"),
            ],
            serde_json::to_vec(&body).expect("wide action replay body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK, "{}", replay.body);
    assert_eq!(replay.body, first.body);
    assert_wide_results_share_one_record_revision(&replay.body);
    assert_eq!(wide_record_revision(&database, &registry).await, 2);
    assert_eq!(wide_revision_rows(&database).await, 1);
    assert_eq!(
        wide_action_result_rows(&database).await,
        WIDE_EFFECT_COUNT as i64
    );
    assert_wide_receipt_preserves_batch_result_count_bounds(&database).await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn link_only_and_patch_targets_share_one_global_lock_order() {
    let (database, registry, identity) = setup_lock_order_action_registry().await;
    let app = action_router(&database, registry.clone(), identity);
    let claims = action_claims();

    let condition_x = lock_order_condition(&app, claims.clone(), LOCK_RECORD_X).await;
    let condition_y = lock_order_condition(&app, claims.clone(), LOCK_RECORD_Y).await;

    lock_order_hold_record(&database, &registry, LOCK_RECORD_X).await;
    let left = spawn_lock_order_action(
        app.clone(),
        claims.clone(),
        "lock-order-left",
        LOCK_RECORD_Y,
        LOCK_RECORD_X,
        condition_y.body["preconditions"].clone(),
    );
    let right = spawn_lock_order_action(
        app,
        claims,
        "lock-order-right",
        LOCK_RECORD_X,
        LOCK_RECORD_Y,
        condition_x.body["preconditions"].clone(),
    );

    if !wait_for_lock_order_waiters(&database, &registry).await {
        left.abort();
        right.abort();
        database
            .admin
            .batch_execute("ROLLBACK")
            .await
            .expect("administrator releases timed-out lock-order probe");
        database.cleanup().await;
        panic!("expected two swapped immediate actions to wait on the held X row before probing Y");
    }
    if !probe_lock_order_y_is_unlocked(&database, &registry).await {
        left.abort();
        right.abort();
        database
            .admin
            .batch_execute("ROLLBACK")
            .await
            .expect("administrator releases blocked lock-order probe");
        database.cleanup().await;
        panic!(
            "link-only and patch target prelocks must use one global order; swapped invocation locked Y before both waiters cleared X"
        );
    }
    database
        .admin
        .batch_execute("COMMIT")
        .await
        .expect("administrator releases lock-order probe");

    let left = await_lock_order_response(left, "left swapped link action").await;
    let right = await_lock_order_response(right, "right swapped link action").await;
    assert_eq!(left.status, StatusCode::OK, "{}", left.body);
    assert_eq!(right.status, StatusCode::OK, "{}", right.body);
    assert_lock_order_result(&left.body, LOCK_RECORD_Y);
    assert_lock_order_result(&right.body, LOCK_RECORD_X);
    assert_eq!(
        lock_order_linked_record(&database, &registry, LOCK_RECORD_Y).await,
        LOCK_RECORD_X
    );
    assert_eq!(
        lock_order_linked_record(&database, &registry, LOCK_RECORD_X).await,
        LOCK_RECORD_Y
    );
    assert_eq!(
        lock_order_revisions(&database, LOCK_RECORD_X).await,
        1,
        "right action writes exactly one revision for X"
    );
    assert_eq!(
        lock_order_revisions(&database, LOCK_RECORD_Y).await,
        1,
        "left action writes exactly one revision for Y"
    );
    database.cleanup().await;
}

async fn move_hidden_register_contact_results_out_of_boundary(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    person_code_value: &str,
    jurisdiction_value: &str,
) {
    let person = &registry.entities()["person"];
    let person_table = &person.physical_table;
    let person_code = &person.fields["person-code"].physical_name;
    let person_jurisdiction = &person.fields["jurisdiction"].physical_name;
    let person_id: Uuid = database
        .admin
        .query_one(
            &format!(
                "UPDATE registry_data.{table}
                    SET {jurisdiction} = $2, record_revision = record_revision + 1
                  WHERE {code} = $1
                  RETURNING record_id",
                table = q(person_table),
                jurisdiction = q(person_jurisdiction),
                code = q(person_code),
            ),
            &[&person_code_value, &jurisdiction_value],
        )
        .await
        .expect("administrator moves hidden person boundary")
        .get(0);

    let membership = &registry.entities()["group-membership"];
    let membership_table = &membership.physical_table;
    let membership_person = &membership.fields["person"].physical_name;
    let membership_jurisdiction = &membership.fields["jurisdiction"].physical_name;
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{table}
                    SET {jurisdiction} = $2, record_revision = record_revision + 1
                  WHERE {person} = $1",
                table = q(membership_table),
                jurisdiction = q(membership_jurisdiction),
                person = q(membership_person),
            ),
            &[&person_id, &jurisdiction_value],
        )
        .await
        .expect("administrator moves hidden membership boundary");
}

async fn setup_lock_order_action_registry() -> (
    TestDatabase,
    Arc<registry_server::CompiledRegistry>,
    registry_server::postgres::ExpectedRegistryIdentity,
) {
    let database = TestDatabase::create(10).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_lock_order_action_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs lock-order action schema");
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
            package_revision: "package-action-lock-order",
            package_sequence: 1,
        },
    )
    .await
    .expect("migration initializes lock-order action registry identity");
    drop(migration);
    migration_task.abort();
    seed_lock_order_records(&database, &registry, &identity).await;
    (database, registry, identity)
}

fn compiled_lock_order_action_registry() -> registry_server::CompiledRegistry {
    let project = json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {
            "id": PACKAGE_ID,
            "version": "1",
            "defaultLanguage": "en"
        },
        "entities": [{
            "id": "lock-record",
            "route": "lock-records",
            "mutationMode": "mutable",
            "fields": [{
                "id": "jurisdiction",
                "apiName": "jurisdiction",
                "type": "string",
                "maxLength": 64,
                "required": true,
                "classification": "restricted"
            }, {
                "id": "linked-record",
                "apiName": "linkedRecord",
                "type": "reference",
                "target": "lock-record",
                "classification": "restricted"
            }]
        }],
        "actions": [{
            "id": "cross-link-lock-record",
            "inputs": [{
                "id": "target",
                "apiName": "targetReference",
                "type": "reference",
                "target": "lock-record",
                "required": true,
                "classification": "restricted"
            }, {
                "id": "link",
                "apiName": "linkReference",
                "type": "reference",
                "target": "lock-record",
                "required": true,
                "classification": "restricted"
            }],
            "effects": [{
                "id": "link-write",
                "target": {"fromField": "target"},
                "operation": "patch",
                "set": {"linked-record": {"fromField": "link"}}
            }]
        }],
        "accessProfiles": [{
            "id": "lock-order-runner",
            "default": true,
            "principalClaim": "registry_principal",
            "requiredScopes": ["registry:contact:register"],
            "requiredPurposes": ["contact-registration"],
            "grants": [{
                "action": "cross-link-lock-record",
                "operations": ["invoke"],
                "targets": [{
                    "entity": "lock-record",
                    "rowBoundaries": [{
                        "field": "jurisdiction",
                        "claim": "jurisdiction",
                        "operator": "equals"
                    }]
                }],
                "results": ["link-write"]
            }]
        }]
    });
    let bytes = serde_json::to_vec(&project).expect("lock-order action project serializes");
    let project = parse_project_json(&bytes).expect("lock-order action project parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("lock-order action compiles")
}

async fn seed_lock_order_records(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    identity: &registry_server::postgres::ExpectedRegistryIdentity,
) {
    let entity = &registry.entities()["lock-record"];
    database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                    (record_id, record_revision, record_lifecycle, active_package_revision,
                     {jurisdiction})
                 VALUES ($1, 1, 'active', $3, $4),
                        ($2, 1, 'active', $3, $4)",
                table = q(&entity.physical_table),
                jurisdiction = q(&entity.fields["jurisdiction"].physical_name),
            ),
            &[
                &Uuid::parse_str(LOCK_RECORD_X).expect("lock-order X UUID"),
                &Uuid::parse_str(LOCK_RECORD_Y).expect("lock-order Y UUID"),
                &identity.package_revision,
                &"zone-a",
            ],
        )
        .await
        .expect("administrator seeds lock-order action targets");
}

async fn lock_order_condition(
    app: &axum::Router,
    claims: VerifiedRequestClaims,
    target_id: &str,
) -> ResponseParts {
    let condition = response_parts(
        send(
            app,
            Method::POST,
            "/v1/actions/cross-link-lock-record/target-conditions",
            Some(claims),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"input":{"targetReference":target_id}}))
                .expect("lock-order condition body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(condition.status, StatusCode::OK, "{}", condition.body);
    condition
}

fn spawn_lock_order_action(
    app: axum::Router,
    claims: VerifiedRequestClaims,
    idempotency_key: &'static str,
    target_id: &'static str,
    link_id: &'static str,
    preconditions: Value,
) -> tokio::task::JoinHandle<ResponseParts> {
    tokio::spawn(async move {
        response_parts(
            send(
                &app,
                Method::POST,
                "/v1/actions/cross-link-lock-record",
                Some(claims),
                &[
                    ("content-type", "application/json"),
                    ("idempotency-key", idempotency_key),
                ],
                serde_json::to_vec(&json!({
                    "input": {
                        "targetReference": target_id,
                        "linkReference": link_id
                    },
                    "preconditions": preconditions
                }))
                .expect("lock-order action body serializes"),
            )
            .await,
        )
        .await
    })
}

async fn lock_order_hold_record(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    record_id: &str,
) {
    let entity = &registry.entities()["lock-record"];
    database
        .admin
        .batch_execute("BEGIN")
        .await
        .expect("administrator starts lock-order transaction");
    database
        .admin
        .query_one(
            &format!(
                "SELECT 1 FROM registry_data.{table} WHERE record_id = $1 FOR UPDATE",
                table = q(&entity.physical_table),
            ),
            &[&Uuid::parse_str(record_id).expect("lock-order UUID")],
        )
        .await
        .expect("administrator locks the first lock-order row");
}

async fn wait_for_lock_order_waiters(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
) -> bool {
    let entity = &registry.entities()["lock-record"];
    let table_pattern = format!("%registry_data.{}%", q(&entity.physical_table));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        database
            .admin
            .query_one("SELECT pg_stat_clear_snapshot()", &[])
            .await
            .expect("administrator refreshes the pg_stat_activity snapshot");
        let waiters: i64 = database
            .admin
            .query_one(
                "SELECT count(*)
                   FROM pg_stat_activity
                  WHERE datname = current_database()
                    AND wait_event_type = 'Lock'
                    AND array_length(pg_blocking_pids(pid), 1) > 0
                    AND query LIKE $1
                    AND query LIKE '%FOR UPDATE%'",
                &[&table_pattern],
            )
            .await
            .expect("administrator observes bounded lock waiters")
            .get(0);
        if waiters >= 2 {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn probe_lock_order_y_is_unlocked(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
) -> bool {
    let entity = &registry.entities()["lock-record"];
    database
        .admin
        .batch_execute("SAVEPOINT lock_order_probe")
        .await
        .expect("administrator starts lock-order savepoint");
    let result = database
        .admin
        .query_one(
            &format!(
                "SELECT 1 FROM registry_data.{table} WHERE record_id = $1 FOR UPDATE NOWAIT",
                table = q(&entity.physical_table),
            ),
            &[&Uuid::parse_str(LOCK_RECORD_Y).expect("lock-order Y UUID")],
        )
        .await;
    database
        .admin
        .batch_execute("ROLLBACK TO SAVEPOINT lock_order_probe")
        .await
        .expect("administrator releases any Y probe lock");
    database
        .admin
        .batch_execute("RELEASE SAVEPOINT lock_order_probe")
        .await
        .expect("administrator clears lock-order savepoint");
    match result {
        Ok(_) => true,
        Err(error) if error.code() == Some(&SqlState::LOCK_NOT_AVAILABLE) => false,
        Err(error) => panic!("unexpected lock-order Y probe failure: {error}"),
    }
}

async fn await_lock_order_response(
    mut handle: tokio::task::JoinHandle<ResponseParts>,
    label: &str,
) -> ResponseParts {
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(timeout);
    tokio::select! {
        result = &mut handle => result.expect("lock-order action task completes"),
        _ = &mut timeout => {
            handle.abort();
            panic!("{label} did not complete after the held X row was released");
        }
    }
}

fn assert_lock_order_result(body: &Value, expected_id: &str) {
    assert_eq!(body["action"], "cross-link-lock-record");
    assert_eq!(body["results"]["link-write"]["entity"], "lock-record");
    assert_eq!(body["results"]["link-write"]["id"], expected_id);
    assert_eq!(body["results"]["link-write"]["revision"], 2);
}

async fn lock_order_linked_record(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    record_id: &str,
) -> String {
    let entity = &registry.entities()["lock-record"];
    database
        .admin
        .query_one(
            &format!(
                "SELECT {linked}::text FROM registry_data.{table} WHERE record_id = $1",
                table = q(&entity.physical_table),
                linked = q(&entity.fields["linked-record"].physical_name),
            ),
            &[&Uuid::parse_str(record_id).expect("lock-order UUID")],
        )
        .await
        .expect("administrator reads lock-order link")
        .get(0)
}

async fn lock_order_revisions(database: &TestDatabase, record_id: &str) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*)
               FROM registry_internal.registry_revisions
              WHERE entity_id = 'lock-record'
                AND record_id = $1",
            &[&Uuid::parse_str(record_id).expect("lock-order UUID")],
        )
        .await
        .expect("administrator counts lock-order revision rows")
        .get(0)
}

async fn setup_wide_action_registry() -> (
    TestDatabase,
    Arc<registry_server::CompiledRegistry>,
    registry_server::postgres::ExpectedRegistryIdentity,
) {
    let database = TestDatabase::create(10).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_wide_action_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs wide action schema");
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
            package_revision: "package-action-wide-128",
            package_sequence: 1,
        },
    )
    .await
    .expect("migration initializes wide action registry identity");
    drop(migration);
    migration_task.abort();
    seed_wide_record(&database, &registry, &identity).await;
    (database, registry, identity)
}

fn compiled_wide_action_registry() -> registry_server::CompiledRegistry {
    let flag_fields = (1..=WIDE_EFFECT_COUNT)
        .map(|index| {
            json!({
                "id": wide_flag_id(index),
                "apiName": wide_flag_api_name(index),
                "type": "boolean",
                "required": true,
                "classification": "restricted"
            })
        })
        .collect::<Vec<_>>();
    let mut entity_fields = vec![json!({
        "id": "jurisdiction",
        "apiName": "jurisdiction",
        "type": "string",
        "maxLength": 64,
        "required": true,
        "classification": "restricted"
    })];
    entity_fields.extend(flag_fields.clone());

    let mut action_inputs = vec![json!({
        "id": "record",
        "apiName": "selectedRecordId",
        "type": "reference",
        "target": "wide-record",
        "required": true,
        "classification": "restricted"
    })];
    action_inputs.extend(flag_fields);

    let effects = (1..=WIDE_EFFECT_COUNT)
        .map(|index| {
            let field = wide_flag_id(index);
            let mut set = serde_json::Map::new();
            set.insert(field.clone(), json!({"fromField": field}));
            json!({
                "id": wide_effect_id(index),
                "target": {"fromField": "record"},
                "operation": "patch",
                "set": set
            })
        })
        .collect::<Vec<_>>();
    let results = (1..=WIDE_EFFECT_COUNT)
        .map(wide_effect_id)
        .collect::<Vec<_>>();
    let project = json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {
            "id": PACKAGE_ID,
            "version": "1",
            "defaultLanguage": "en"
        },
        "entities": [{
            "id": "wide-record",
            "route": "wide-records",
            "mutationMode": "mutable",
            "fields": entity_fields
        }],
        "actions": [{
            "id": "patch-wide-flags",
            "inputs": action_inputs,
            "effects": effects
        }],
        "accessProfiles": [{
            "id": "wide-action-runner",
            "default": true,
            "principalClaim": "registry_principal",
            "requiredScopes": ["registry:contact:register"],
            "requiredPurposes": ["contact-registration"],
            "grants": [{
                "action": "patch-wide-flags",
                "operations": ["invoke"],
                "targets": [{
                    "entity": "wide-record",
                    "rowBoundaries": [{
                        "field": "jurisdiction",
                        "claim": "jurisdiction",
                        "operator": "equals"
                    }]
                }],
                "results": results
            }]
        }]
    });
    let bytes = serde_json::to_vec(&project).expect("wide action project serializes");
    let project = parse_project_json(&bytes).expect("wide action project parses");
    let registry =
        compile_project(&project, &[], CompileProfile::Authoring).expect("wide action compiles");
    assert_eq!(
        registry.actions().actions[0].maximum_field_mutations,
        WIDE_EFFECT_COUNT as u16
    );
    registry
}

async fn seed_wide_record(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    identity: &registry_server::postgres::ExpectedRegistryIdentity,
) {
    let entity = &registry.entities()["wide-record"];
    let flag_columns = (1..=WIDE_EFFECT_COUNT)
        .map(|index| q(&entity.fields[&wide_flag_id(index)].physical_name))
        .collect::<Vec<_>>()
        .join(", ");
    let flag_values = std::iter::repeat("false")
        .take(WIDE_EFFECT_COUNT)
        .collect::<Vec<_>>()
        .join(", ");
    database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                    (record_id, record_revision, record_lifecycle, active_package_revision,
                     {jurisdiction}, {flag_columns})
                 VALUES ($1, 1, 'active', $2, $3, {flag_values})",
                table = q(&entity.physical_table),
                jurisdiction = q(&entity.fields["jurisdiction"].physical_name),
            ),
            &[
                &Uuid::parse_str(WIDE_RECORD_ID).expect("wide seed UUID"),
                &identity.package_revision,
                &"zone-a",
            ],
        )
        .await
        .expect("administrator seeds one wide action target");
}

fn assert_wide_results_share_one_record_revision(body: &Value) {
    assert_eq!(body["action"], "patch-wide-flags");
    let results = body["results"].as_object().expect("wide results object");
    assert_eq!(results.len(), WIDE_EFFECT_COUNT);
    let mut revision = None;
    for index in 1..=WIDE_EFFECT_COUNT {
        let effect = wide_effect_id(index);
        let result = results.get(&effect).expect("wide effect has result");
        assert_eq!(result["entity"], "wide-record");
        assert_eq!(result["id"], WIDE_RECORD_ID);
        let current = result["revision"].as_i64().expect("result revision");
        assert_eq!(current, 2);
        match revision {
            Some(previous) => assert_eq!(current, previous),
            None => revision = Some(current),
        }
    }
}

async fn wide_record_revision(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
) -> i64 {
    let entity = &registry.entities()["wide-record"];
    database
        .admin
        .query_one(
            &format!(
                "SELECT record_revision FROM registry_data.{table} WHERE record_id = $1",
                table = q(&entity.physical_table),
            ),
            &[&Uuid::parse_str(WIDE_RECORD_ID).expect("wide record UUID")],
        )
        .await
        .expect("administrator reads wide record revision")
        .get(0)
}

async fn wide_true_flag_count(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
) -> i64 {
    let entity = &registry.entities()["wide-record"];
    let terms = (1..=WIDE_EFFECT_COUNT)
        .map(|index| {
            format!(
                "CASE WHEN {} THEN 1 ELSE 0 END",
                q(&entity.fields[&wide_flag_id(index)].physical_name)
            )
        })
        .collect::<Vec<_>>()
        .join(" + ");
    database
        .admin
        .query_one(
            &format!(
                "SELECT ({terms})::bigint FROM registry_data.{table} WHERE record_id = $1",
                table = q(&entity.physical_table),
            ),
            &[&Uuid::parse_str(WIDE_RECORD_ID).expect("wide record UUID")],
        )
        .await
        .expect("administrator counts true wide flags")
        .get(0)
}

async fn wide_revision_rows(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*)
               FROM registry_internal.registry_revisions
              WHERE entity_id = 'wide-record'
                AND record_id = $1",
            &[&Uuid::parse_str(WIDE_RECORD_ID).expect("wide record UUID")],
        )
        .await
        .expect("administrator counts wide revision rows")
        .get(0)
}

async fn wide_action_result_rows(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*)
               FROM registry_internal.registry_immediate_action_results
              WHERE action_id = 'patch-wide-flags'",
            &[],
        )
        .await
        .expect("administrator counts wide action result links")
        .get(0)
}

async fn assert_wide_receipt_preserves_batch_result_count_bounds(database: &TestDatabase) {
    for allowed in [1_i16, 100] {
        assert_wide_receipt_batch_result_count_update(database, allowed)
            .await
            .expect("batch result_count 1 and 100 remain valid");
    }
    for rejected in [0_i16, 101] {
        let error = assert_wide_receipt_batch_result_count_update(database, rejected)
            .await
            .expect_err("batch result_count 0 and 101 are rejected by SQL constraints");
        assert_eq!(
            error.code(),
            Some(&SqlState::CHECK_VIOLATION),
            "batch result_count {rejected} must fail as a CHECK violation"
        );
    }
    let row = database
        .admin
        .query_one(
            "SELECT result_kind, result_count
               FROM registry_internal.registry_idempotency
              WHERE key_reference = (
                    SELECT key_reference
                      FROM registry_internal.registry_immediate_action_applications
                     WHERE action_id = 'patch-wide-flags'
              )",
            &[],
        )
        .await
        .expect("administrator rechecks wide immediate-action receipt");
    assert_eq!(
        (row.get::<_, String>(0), row.get::<_, i16>(1)),
        ("immediate_action".to_owned(), WIDE_EFFECT_COUNT as i16),
        "batch-bound probes are rolled back and leave the immediate-action receipt intact"
    );
}

async fn assert_wide_receipt_batch_result_count_update(
    database: &TestDatabase,
    result_count: i16,
) -> Result<(), tokio_postgres::Error> {
    database.admin.batch_execute("BEGIN").await?;
    let result = database
        .admin
        .execute(
            "UPDATE registry_internal.registry_idempotency
                SET result_kind = 'batch',
                    result_count = $1
              WHERE key_reference = (
                    SELECT key_reference
                      FROM registry_internal.registry_immediate_action_applications
                     WHERE action_id = 'patch-wide-flags'
              )",
            &[&result_count],
        )
        .await
        .map(|updated| {
            assert_eq!(
                updated, 1,
                "wide receipt batch-bound probe updates exactly one row"
            );
        });
    database.admin.batch_execute("ROLLBACK").await?;
    result
}

fn wide_flag_id(index: usize) -> String {
    format!("flag-{index:03}")
}

fn wide_flag_api_name(index: usize) -> String {
    format!("flag{index:03}")
}

fn wide_effect_id(index: usize) -> String {
    format!("flag-{index:03}-patch")
}

async fn install_late_application_retry_probe(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
) {
    let person = &registry.entities()["person"];
    let person_table = &person.physical_table;
    let person_code = &person.fields["person-code"].physical_name;
    database
        .admin
        .batch_execute(&format!(
            "CREATE SEQUENCE registry_internal.ia_retry_application_attempt_seq;
             CREATE SEQUENCE registry_internal.ia_retry_app_chunk_1 MINVALUE 0 MAXVALUE 4294967295 START WITH 0;
             CREATE SEQUENCE registry_internal.ia_retry_app_chunk_2 MINVALUE 0 MAXVALUE 4294967295 START WITH 0;
             CREATE SEQUENCE registry_internal.ia_retry_app_chunk_3 MINVALUE 0 MAXVALUE 4294967295 START WITH 0;
             CREATE SEQUENCE registry_internal.ia_retry_app_chunk_4 MINVALUE 0 MAXVALUE 4294967295 START WITH 0;
             CREATE SEQUENCE registry_internal.ia_retry_person_chunk_1 MINVALUE 0 MAXVALUE 4294967295 START WITH 0;
             CREATE SEQUENCE registry_internal.ia_retry_person_chunk_2 MINVALUE 0 MAXVALUE 4294967295 START WITH 0;
             CREATE SEQUENCE registry_internal.ia_retry_person_chunk_3 MINVALUE 0 MAXVALUE 4294967295 START WITH 0;
             CREATE SEQUENCE registry_internal.ia_retry_person_chunk_4 MINVALUE 0 MAXVALUE 4294967295 START WITH 0;

             CREATE FUNCTION registry_internal.capture_late_application_retry_ids()
             RETURNS trigger
             LANGUAGE plpgsql
             SECURITY DEFINER
             SET search_path = pg_catalog, registry_internal, pg_temp
             AS $$
             DECLARE
                 attempt bigint;
                 app_hex text;
                 person_hex text;
                 person_id uuid;
             BEGIN
                 IF NEW.action_id <> 'create-local-person' THEN
                     RETURN NEW;
                 END IF;
                 attempt := nextval('registry_internal.ia_retry_application_attempt_seq');
                 IF attempt = 1 THEN
                     SELECT record_id INTO person_id
                       FROM registry_data.{person_table}
                      WHERE {person_code} = 'P-STABLE-RETRY';
                     IF person_id IS NULL THEN
                         RAISE EXCEPTION 'late retry probe missing reserved person id' USING ERRCODE = 'XX000';
                     END IF;

                     app_hex := replace(NEW.application_id::text, '-', '');
                     person_hex := replace(person_id::text, '-', '');
                     PERFORM setval('registry_internal.ia_retry_app_chunk_1', (('x' || substr(app_hex, 1, 8))::bit(32)::bigint), true);
                     PERFORM setval('registry_internal.ia_retry_app_chunk_2', (('x' || substr(app_hex, 9, 8))::bit(32)::bigint), true);
                     PERFORM setval('registry_internal.ia_retry_app_chunk_3', (('x' || substr(app_hex, 17, 8))::bit(32)::bigint), true);
                     PERFORM setval('registry_internal.ia_retry_app_chunk_4', (('x' || substr(app_hex, 25, 8))::bit(32)::bigint), true);
                     PERFORM setval('registry_internal.ia_retry_person_chunk_1', (('x' || substr(person_hex, 1, 8))::bit(32)::bigint), true);
                     PERFORM setval('registry_internal.ia_retry_person_chunk_2', (('x' || substr(person_hex, 9, 8))::bit(32)::bigint), true);
                     PERFORM setval('registry_internal.ia_retry_person_chunk_3', (('x' || substr(person_hex, 17, 8))::bit(32)::bigint), true);
                     PERFORM setval('registry_internal.ia_retry_person_chunk_4', (('x' || substr(person_hex, 25, 8))::bit(32)::bigint), true);
                     RAISE EXCEPTION 'late immediate action retry probe' USING ERRCODE = '40001';
                 END IF;
                 RETURN NEW;
             END;
             $$;

             CREATE TRIGGER capture_late_application_retry_ids
             BEFORE INSERT ON registry_internal.registry_immediate_action_applications
             FOR EACH ROW EXECUTE FUNCTION registry_internal.capture_late_application_retry_ids();",
            person_table = q(person_table),
            person_code = q(person_code),
        ))
        .await
        .expect("administrator installs late application retry probe");
}

async fn captured_late_retry_ids(database: &TestDatabase) -> (Uuid, Uuid) {
    let row = database
        .admin
        .query_one(
            "SELECT
                (SELECT last_value FROM registry_internal.ia_retry_app_chunk_1),
                (SELECT last_value FROM registry_internal.ia_retry_app_chunk_2),
                (SELECT last_value FROM registry_internal.ia_retry_app_chunk_3),
                (SELECT last_value FROM registry_internal.ia_retry_app_chunk_4),
                (SELECT last_value FROM registry_internal.ia_retry_person_chunk_1),
                (SELECT last_value FROM registry_internal.ia_retry_person_chunk_2),
                (SELECT last_value FROM registry_internal.ia_retry_person_chunk_3),
                (SELECT last_value FROM registry_internal.ia_retry_person_chunk_4)",
            &[],
        )
        .await
        .expect("administrator reads nontransactional retry UUID chunks");
    (
        uuid_from_chunks([row.get(0), row.get(1), row.get(2), row.get(3)]),
        uuid_from_chunks([row.get(4), row.get(5), row.get(6), row.get(7)]),
    )
}

async fn late_application_retry_attempts(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT last_value FROM registry_internal.ia_retry_application_attempt_seq",
            &[],
        )
        .await
        .expect("administrator reads retry attempt sequence")
        .get(0)
}

fn uuid_from_chunks(chunks: [i64; 4]) -> Uuid {
    let hex = format!(
        "{:08x}{:08x}{:08x}{:08x}",
        chunks[0], chunks[1], chunks[2], chunks[3]
    );
    Uuid::parse_str(&format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
    .expect("captured retry chunks reconstruct a UUID")
}

async fn install_condition_terminal_audit_failure(database: &TestDatabase) {
    database
        .admin
        .batch_execute(
            "CREATE FUNCTION registry_internal.reject_condition_terminal_audit()
             RETURNS trigger
             LANGUAGE plpgsql
             SECURITY DEFINER
             SET search_path = pg_catalog, registry_internal, pg_temp
             AS $$
             BEGIN
                 IF convert_from(NEW.envelope, 'UTF8') LIKE '%\"phase\":\"terminal\"%'
                    AND convert_from(NEW.envelope, 'UTF8') LIKE '%\"operationId\":\"actions.register-household-contact.target_conditions\"%' THEN
                     RAISE EXCEPTION 'condition terminal audit failure probe' USING ERRCODE = 'XX000';
                 END IF;
                 RETURN NEW;
             END;
             $$;
             CREATE TRIGGER reject_condition_terminal_audit
             BEFORE INSERT ON registry_internal.registry_audit
             FOR EACH ROW EXECUTE FUNCTION registry_internal.reject_condition_terminal_audit();",
        )
        .await
        .expect("administrator installs terminal audit failure probe");
}

async fn audit_records(database: &TestDatabase) -> Vec<Value> {
    database
        .admin
        .query(
            "SELECT envelope
             FROM registry_internal.registry_audit
             ORDER BY created_at, envelope_id",
            &[],
        )
        .await
        .expect("administrator inspects audit envelopes")
        .into_iter()
        .map(|row| {
            serde_json::from_slice::<AuditEnvelope>(&row.get::<_, Vec<u8>>(0))
                .expect("audit envelope is canonical platform JSON")
                .record
        })
        .collect()
}

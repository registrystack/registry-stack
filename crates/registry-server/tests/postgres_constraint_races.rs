// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::BTreeSet;
use std::time::Duration;

use postgres_harness::TestDatabase;
use registry_platform_audit::AuditProfile;
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::mutation::{
    MutationBody, MutationCoordinator, MutationError, MutationPlan, MutationRequest,
};
use registry_server::postgres::{
    initialize_registry_state_for_catalog_test, install_compiled_schema, ClaimContext,
    ExpectedManagedCatalog, RegistryLockKey, RegistryStateTestIdentity,
};
use serde_json::{Map, Value};
use tokio_postgres::Client;

const PACKAGE_ID: &str = "constraint-race-registry";
const PACKAGE_REVISION: &str = "constraint-race-package-1";
const PARENT_KEY: &str = "parent-create-key";
const CHILD_KEY_CANARY: &str = "reference-race-idempotency-canary";
const UNIQUE_FIRST_KEY_CANARY: &str = "unique-race-first-idempotency-canary";
const UNIQUE_SECOND_KEY_CANARY: &str = "unique-race-second-idempotency-canary";
const UNIQUE_VALUE_CANARY: &str = "unique-race-value-canary";
const TEMPORAL_FIRST_KEY_CANARY: &str = "temporal-race-first-idempotency-canary";
const TEMPORAL_SECOND_KEY_CANARY: &str = "temporal-race-second-idempotency-canary";
const TEMPORAL_NON_OVERLAP_KEY_CANARY: &str = "temporal-non-overlap-idempotency-canary";
const PRINCIPAL_CANARY: &str = "constraint-race-principal-canary";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_reference_and_temporal_races_leave_no_dangling_or_overlapping_records() {
    let mut database = TestDatabase::create(8).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the compiled temporal prerequisite");
    let (migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs the compiler-owned constraint schema");
    let catalog = ExpectedManagedCatalog::compiled(&registry);
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &catalog,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: "constraint-race-instance",
            database_id: "constraint-race-database",
            package_revision: PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("migration initializes the exact active package identity");
    migration_task.abort();

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x71; 32].into())
        .expect("test owns a strong keyed audit profile");
    let coordinator = MutationCoordinator::new(
        RegistryLockKey::derive(PACKAGE_ID).expect("registry lock key is bounded"),
        Duration::from_secs(5),
        identity,
        audit_profile,
    );
    let parent_plan = MutationPlan::from_compiled(&registry, "records.parent.create")
        .expect("parent create plan is compiler-owned");
    let child_plan = MutationPlan::from_compiled(&registry, "records.child.create")
        .expect("child create plan is compiler-owned");
    let unique_plan = MutationPlan::from_compiled(&registry, "records.unique-entry.create")
        .expect("unique entry create plan is compiler-owned");
    let temporal_plan = MutationPlan::from_compiled(&registry, "records.period.create")
        .expect("temporal create plan is compiler-owned");
    let parent_claims = claims(&registry, "parent");
    let child_claims = claims(&registry, "child");
    let unique_claims = claims(&registry, "unique-entry");
    let temporal_claims = claims(&registry, "period");

    let mut parent_client = pool
        .get_for_test()
        .await
        .expect("parent mutation connection is available");
    let parent = coordinator
        .execute(
            &mut parent_client,
            create_request(
                &parent_plan,
                PARENT_KEY,
                &parent_claims,
                Map::from_iter([("name".to_owned(), Value::String("parent-a".to_owned()))]),
                &["name"],
            ),
        )
        .await
        .expect("parent exists before the competing removal");
    let parent_id = response_id(&parent);

    let parent_table = quoted(&registry.entities()["parent"].physical_table);
    let child = &registry.entities()["child"];
    let optional_reference = &child.fields["alternate-parent"].physical_name;
    let optional_reference_is_required: bool = database
        .admin
        .query_one(
            "SELECT attribute.attnotnull
               FROM pg_catalog.pg_attribute attribute
               JOIN pg_catalog.pg_class relation ON relation.oid = attribute.attrelid
               JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
              WHERE namespace.nspname = 'registry_data'
                AND relation.relname = $1
                AND attribute.attname = $2",
            &[&child.physical_table, optional_reference],
        )
        .await
        .expect("installed optional reference column is visible")
        .get(0);
    assert!(!optional_reference_is_required);
    let restrict_references: i64 = database
        .admin
        .query_one(
            "SELECT count(*)
               FROM pg_catalog.pg_constraint constraint_record
               JOIN pg_catalog.pg_class relation ON relation.oid = constraint_record.conrelid
               JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
              WHERE namespace.nspname = 'registry_data'
                AND relation.relname = $1
                AND constraint_record.contype = 'f'
                AND constraint_record.confdeltype = 'r'",
            &[&child.physical_table],
        )
        .await
        .expect("installed reference deletion behavior is visible")
        .get(0);
    assert_eq!(restrict_references, 2);
    let child_table = quoted(&child.physical_table);
    let child_parent = quoted(&child.fields["parent"].physical_name);
    let (observer, observer_task) = database.connect_migration().await;
    let mut child_client = pool
        .get_for_test()
        .await
        .expect("child mutation connection is available");
    let child_pid = backend_pid(&child_client).await;

    let removal = database
        .admin
        .transaction()
        .await
        .expect("administrator begins the competing parent removal");
    let removal_pid: i32 = removal
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("parent removal backend pid is available")
        .get(0);
    assert_eq!(
        removal
            .execute(
                &format!(
                    "DELETE FROM registry_data.{parent_table} WHERE record_id = $1::text::uuid"
                ),
                &[&parent_id],
            )
            .await
            .expect("administrator holds the parent removal open"),
        1
    );

    let child_data = Map::from_iter([
        ("parent".to_owned(), Value::String(parent_id.clone())),
        ("name".to_owned(), Value::String("child-a".to_owned())),
    ]);
    let child_create = coordinator.execute(
        &mut child_client,
        create_request(
            &child_plan,
            CHILD_KEY_CANARY,
            &child_claims,
            child_data,
            &["parent", "name"],
        ),
    );
    let release_removal = async {
        wait_until_blocked_by(&observer, &[child_pid], removal_pid).await;
        removal
            .commit()
            .await
            .expect("parent removal commits after the child reaches its foreign-key check");
    };
    let (child_result, ()) = tokio::join!(child_create, release_removal);
    let child_error = child_result.expect_err("the committed parent removal wins the FK race");
    assert_value_free_conflict(
        "reference race",
        child_error,
        &registry,
        &[CHILD_KEY_CANARY, &parent_id],
    );

    let state = database
        .admin
        .query_one(
            &format!(
                "SELECT
                   (SELECT count(*) FROM registry_data.{parent_table}),
                   (SELECT count(*) FROM registry_data.{child_table}),
                   (SELECT count(*)
                      FROM registry_data.{child_table} child
                      LEFT JOIN registry_data.{parent_table} parent
                        ON parent.record_id = child.{child_parent}
                     WHERE parent.record_id IS NULL)"
            ),
            &[],
        )
        .await
        .expect("administrator verifies the final reference state");
    assert_eq!(state.get::<_, i64>(0), 0, "the parent removal won");
    assert_eq!(
        state.get::<_, i64>(1),
        0,
        "the refused child did not commit"
    );
    assert_eq!(state.get::<_, i64>(2), 0, "no dangling reference exists");

    let unique_table = quoted(&registry.entities()["unique-entry"].physical_table);
    let mut unique_first_client = pool
        .get_for_test()
        .await
        .expect("first unique connection is available");
    let mut unique_second_client = pool
        .get_for_test()
        .await
        .expect("second unique connection is available");
    let unique_first_pid = backend_pid(&unique_first_client).await;
    let unique_second_pid = backend_pid(&unique_second_client).await;
    let unique_barrier = database
        .admin
        .transaction()
        .await
        .expect("administrator begins the uniqueness race barrier");
    let unique_barrier_pid: i32 = unique_barrier
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("uniqueness barrier backend pid is available")
        .get(0);
    unique_barrier
        .batch_execute(&format!(
            "LOCK TABLE registry_data.{unique_table} IN SHARE MODE"
        ))
        .await
        .expect("table barrier holds both unique inserts at PostgreSQL");

    let unique_data = || {
        Map::from_iter([
            ("scope".to_owned(), Value::String("scope-a".to_owned())),
            (
                "code".to_owned(),
                Value::String(UNIQUE_VALUE_CANARY.to_owned()),
            ),
        ])
    };
    let unique_first = coordinator.execute(
        &mut unique_first_client,
        create_request(
            &unique_plan,
            UNIQUE_FIRST_KEY_CANARY,
            &unique_claims,
            unique_data(),
            &["scope", "code"],
        ),
    );
    let unique_second = coordinator.execute(
        &mut unique_second_client,
        create_request(
            &unique_plan,
            UNIQUE_SECOND_KEY_CANARY,
            &unique_claims,
            unique_data(),
            &["scope", "code"],
        ),
    );
    let release_unique_barrier = async {
        wait_until_blocked_by(
            &observer,
            &[unique_first_pid, unique_second_pid],
            unique_barrier_pid,
        )
        .await;
        unique_barrier
            .commit()
            .await
            .expect("barrier releases both unique inserts together");
    };
    let (unique_first, unique_second, ()) =
        tokio::join!(unique_first, unique_second, release_unique_barrier);
    let unique_outcomes = [unique_first, unique_second];
    assert_eq!(
        unique_outcomes
            .iter()
            .filter(|result| result.is_ok())
            .count(),
        1,
        "PostgreSQL commits exactly one equal composite key"
    );
    let unique_error = unique_outcomes
        .into_iter()
        .find_map(Result::err)
        .expect("one equal composite key is refused");
    assert_value_free_conflict(
        "unique race",
        unique_error,
        &registry,
        &[
            UNIQUE_FIRST_KEY_CANARY,
            UNIQUE_SECOND_KEY_CANARY,
            UNIQUE_VALUE_CANARY,
        ],
    );
    assert_eq!(
        current_count(&database, &unique_table).await,
        1,
        "the database unique constraint prevents a duplicate current row"
    );

    let period_table = quoted(&registry.entities()["period"].physical_table);
    let period_scope = quoted(&registry.entities()["period"].fields["scope"].physical_name);
    let period_start = quoted(&registry.entities()["period"].fields["valid-from"].physical_name);
    let period_end = quoted(&registry.entities()["period"].fields["valid-to"].physical_name);
    let mut first_client = pool
        .get_for_test()
        .await
        .expect("first temporal connection is available");
    let mut second_client = pool
        .get_for_test()
        .await
        .expect("second temporal connection is available");
    let first_pid = backend_pid(&first_client).await;
    let second_pid = backend_pid(&second_client).await;
    let barrier = database
        .admin
        .transaction()
        .await
        .expect("administrator begins the temporal race barrier");
    let barrier_pid: i32 = barrier
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("temporal barrier backend pid is available")
        .get(0);
    barrier
        .batch_execute(&format!(
            "LOCK TABLE registry_data.{period_table} IN SHARE MODE"
        ))
        .await
        .expect("table barrier holds both inserts at PostgreSQL");

    let first_data = temporal_data("2026-01-01T00:00:00Z", "2026-01-10T00:00:00Z");
    let second_data = temporal_data("2026-01-05T00:00:00Z", "2026-01-15T00:00:00Z");
    let first_create = coordinator.execute(
        &mut first_client,
        create_request(
            &temporal_plan,
            TEMPORAL_FIRST_KEY_CANARY,
            &temporal_claims,
            first_data,
            &["scope", "valid-from", "valid-to"],
        ),
    );
    let second_create = coordinator.execute(
        &mut second_client,
        create_request(
            &temporal_plan,
            TEMPORAL_SECOND_KEY_CANARY,
            &temporal_claims,
            second_data,
            &["scope", "valid-from", "valid-to"],
        ),
    );
    let release_barrier = async {
        wait_until_blocked_by(&observer, &[first_pid, second_pid], barrier_pid).await;
        barrier
            .commit()
            .await
            .expect("barrier releases both database inserts together");
    };
    let (first, second, ()) = tokio::join!(first_create, second_create, release_barrier);
    let outcomes = [first, second];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    let temporal_error = outcomes
        .into_iter()
        .find_map(Result::err)
        .expect("one overlapping interval is refused");
    assert_value_free_temporal_refusal(
        temporal_error,
        &registry,
        &[TEMPORAL_FIRST_KEY_CANARY, TEMPORAL_SECOND_KEY_CANARY],
    );
    assert_eq!(
        current_count(&database, &period_table).await,
        1,
        "the exclusion constraint commits exactly one overlapping interval"
    );

    let mut non_overlap_client = pool
        .get_for_test()
        .await
        .expect("non-overlapping temporal connection is available");
    coordinator
        .execute(
            &mut non_overlap_client,
            create_request(
                &temporal_plan,
                TEMPORAL_NON_OVERLAP_KEY_CANARY,
                &temporal_claims,
                temporal_data("2026-01-15T00:00:00Z", "2026-01-20T00:00:00Z"),
                &["scope", "valid-from", "valid-to"],
            ),
        )
        .await
        .expect("a non-overlapping interval commits after the race");
    assert_eq!(current_count(&database, &period_table).await, 2);
    let overlaps: i64 = database
        .admin
        .query_one(
            &format!(
                "SELECT count(*)
                   FROM registry_data.{period_table} left_period
                   JOIN registry_data.{period_table} right_period
                     ON left_period.record_id < right_period.record_id
                    AND left_period.{period_scope} = right_period.{period_scope}
                    AND tstzrange(left_period.{period_start}, left_period.{period_end}, '[)')
                        && tstzrange(right_period.{period_start}, right_period.{period_end}, '[)')"
            ),
            &[],
        )
        .await
        .expect("administrator checks final temporal ranges")
        .get(0);
    assert_eq!(overlaps, 0, "no committed periods overlap in one scope");

    let refusal_count: i64 = database
        .admin
        .query_one(
            "SELECT count(*)
               FROM registry_internal.registry_audit
              WHERE convert_from(envelope, 'UTF8') LIKE '%\"phase\":\"refusal\"%'",
            &[],
        )
        .await
        .expect("administrator verifies all constraint refusals were audited")
        .get(0);
    assert_eq!(refusal_count, 3);
    assert_diagnostics_are_minimized(&database, &parent_id).await;

    observer_task.abort();
    database.cleanup().await;
}

fn compiled_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"constraint-race-registry","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"parent","route":"parents","mutationMode":"create_only","classification":"public",
            "fields":[{"id":"name","type":"string","maxLength":64,"required":true,"classification":"public"}],
            "accessProfiles":[{
              "id":"operator","default":true,"principalClaim":"principal","requiredPurposes":["operations"],
              "operations":["create","get"],"readableFields":["name"],"writableFields":["name"]
            }]
          },{
            "id":"child","route":"children","mutationMode":"create_only","classification":"public",
            "fields":[
              {"id":"parent","type":"reference","target":"parent","onDelete":"restrict","required":true,"classification":"public"},
              {"id":"alternate-parent","type":"reference","target":"parent","onDelete":"restrict","classification":"public"},
              {"id":"name","type":"string","maxLength":64,"required":true,"classification":"public"}
            ],
            "accessProfiles":[{
              "id":"operator","default":true,"principalClaim":"principal","requiredPurposes":["operations"],
              "operations":["create","get"],"readableFields":["parent","alternate-parent","name"],"writableFields":["parent","alternate-parent","name"]
            }]
          },{
            "id":"unique-entry","route":"unique-entries","mutationMode":"create_only","classification":"public",
            "fields":[
              {"id":"scope","type":"string","maxLength":64,"required":true,"classification":"public"},
              {"id":"code","type":"string","maxLength":64,"required":true,"classification":"public"}
            ],
            "constraints":[{"kind":"unique","fields":["scope","code"]}],
            "accessProfiles":[{
              "id":"operator","default":true,"principalClaim":"principal","requiredPurposes":["operations"],
              "operations":["create","get"],"readableFields":["scope","code"],"writableFields":["scope","code"]
            }]
          },{
            "id":"period","route":"periods","mutationMode":"create_only","classification":"public",
            "fields":[
              {"id":"scope","type":"string","maxLength":64,"required":true,"classification":"public"},
              {"id":"valid-from","type":"timestamp","required":true,"classification":"public"},
              {"id":"valid-to","type":"timestamp","required":false,"classification":"public"}
            ],
            "temporal":{"startField":"valid-from","endField":"valid-to","scopeFields":["scope"]},
            "constraints":[{
              "kind":"temporal-non-overlap","scopeFields":["scope"],
              "startField":"valid-from","endField":"valid-to"
            }],
            "accessProfiles":[{
              "id":"operator","default":true,"principalClaim":"principal","requiredPurposes":["operations"],
              "operations":["create","get"],
              "readableFields":["scope","valid-from","valid-to"],
              "writableFields":["scope","valid-from","valid-to"]
            }]
          }]
        }"#,
    )
    .expect("constraint race fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("constraint race fixture compiles")
}

fn claims(registry: &registry_server::CompiledRegistry, entity_id: &str) -> ClaimContext {
    ClaimContext::for_compiled(
        registry,
        entity_id,
        Some(PRINCIPAL_CANARY.to_owned()),
        "operator",
        Some("operations".to_owned()),
        Vec::new(),
    )
    .expect("claim context is compiler-bound")
}

fn create_request<'a>(
    plan: &'a MutationPlan,
    idempotency_key: &'a str,
    claims: &'a ClaimContext,
    data: Map<String, Value>,
    response_fields: &[&str],
) -> MutationRequest<'a> {
    MutationRequest {
        plan,
        idempotency_key,
        claims,
        record_id: None,
        expected_etag: None,
        body: MutationBody::Create(data),
        response_fields: response_fields
            .iter()
            .map(|field| (*field).to_owned())
            .collect::<BTreeSet<_>>(),
    }
}

fn temporal_data(start: &str, end: &str) -> Map<String, Value> {
    Map::from_iter([
        ("scope".to_owned(), Value::String("scope-a".to_owned())),
        ("validFrom".to_owned(), Value::String(start.to_owned())),
        ("validTo".to_owned(), Value::String(end.to_owned())),
    ])
}

fn response_id(outcome: &registry_server::mutation::MutationOutcome) -> String {
    let body: Value = serde_json::from_slice(outcome.response().body())
        .expect("mutation response is canonical JSON");
    body["id"]
        .as_str()
        .expect("create response contains its record id")
        .to_owned()
}

async fn backend_pid(client: &Client) -> i32 {
    client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("backend pid is available")
        .get(0)
}

async fn wait_until_blocked_by(observer: &Client, blocked_pids: &[i32], blocker_pid: i32) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let mut all_blocked = true;
            for blocked_pid in blocked_pids {
                let blocked: bool = observer
                    .query_one(
                        "SELECT $1::integer = ANY(pg_blocking_pids($2::integer))",
                        &[&blocker_pid, blocked_pid],
                    )
                    .await
                    .expect("observer checks PostgreSQL blockers")
                    .get(0);
                all_blocked &= blocked;
            }
            if all_blocked {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both operations reach the intended PostgreSQL race before release");
}

fn assert_value_free_conflict(
    race: &str,
    error: MutationError,
    registry: &registry_server::CompiledRegistry,
    canaries: &[&str],
) {
    assert_eq!(error, MutationError::Conflict, "{race} public error");
    assert_eq!(error.to_string(), "mutation conflicts with current state");
    let rendered = format!("{error:?} {error}");
    for canary in canaries.iter().copied().chain([PRINCIPAL_CANARY]) {
        assert!(!rendered.contains(canary));
    }
    for entity in registry.entities().values() {
        assert!(!rendered.contains(&entity.physical_table));
        for field in entity.fields.values() {
            assert!(!rendered.contains(&field.physical_name));
        }
    }
}

fn assert_value_free_temporal_refusal(
    error: MutationError,
    registry: &registry_server::CompiledRegistry,
    canaries: &[&str],
) {
    let expected = match error {
        MutationError::Conflict => "mutation conflicts with current state",
        MutationError::Unavailable => "mutation service is unavailable",
        other => panic!("temporal PostgreSQL race returned unexpected public error: {other}"),
    };
    assert_eq!(error.to_string(), expected);
    let rendered = format!("{error:?} {error}");
    for canary in canaries.iter().copied().chain([PRINCIPAL_CANARY]) {
        assert!(!rendered.contains(canary));
    }
    for entity in registry.entities().values() {
        assert!(!rendered.contains(&entity.physical_table));
        for field in entity.fields.values() {
            assert!(!rendered.contains(&field.physical_name));
        }
    }
}

async fn current_count(database: &TestDatabase, quoted_table: &str) -> i64 {
    database
        .admin
        .query_one(
            &format!("SELECT count(*) FROM registry_data.{quoted_table}"),
            &[],
        )
        .await
        .expect("administrator counts final current rows")
        .get(0)
}

async fn assert_diagnostics_are_minimized(database: &TestDatabase, parent_id: &str) {
    let audit = database
        .admin
        .query("SELECT envelope FROM registry_internal.registry_audit", &[])
        .await
        .expect("administrator inspects minimized audit envelopes")
        .into_iter()
        .flat_map(|row| row.get::<_, Vec<u8>>(0))
        .collect::<Vec<_>>();
    let audit = String::from_utf8_lossy(&audit);
    for canary in [
        PRINCIPAL_CANARY,
        CHILD_KEY_CANARY,
        UNIQUE_FIRST_KEY_CANARY,
        UNIQUE_SECOND_KEY_CANARY,
        UNIQUE_VALUE_CANARY,
        TEMPORAL_FIRST_KEY_CANARY,
        TEMPORAL_SECOND_KEY_CANARY,
        TEMPORAL_NON_OVERLAP_KEY_CANARY,
        parent_id,
    ] {
        assert!(!audit.contains(canary));
    }

    let references = database
        .admin
        .query(
            "SELECT key_reference, binding_reference
               FROM registry_internal.registry_idempotency",
            &[],
        )
        .await
        .expect("administrator inspects only keyed idempotency references");
    for row in references {
        let key_reference: String = row.get(0);
        let binding_reference: String = row.get(1);
        for canary in [
            PRINCIPAL_CANARY,
            PARENT_KEY,
            CHILD_KEY_CANARY,
            UNIQUE_FIRST_KEY_CANARY,
            UNIQUE_SECOND_KEY_CANARY,
            UNIQUE_VALUE_CANARY,
            TEMPORAL_FIRST_KEY_CANARY,
            TEMPORAL_SECOND_KEY_CANARY,
            TEMPORAL_NON_OVERLAP_KEY_CANARY,
            parent_id,
        ] {
            assert!(!key_reference.contains(canary));
            assert!(!binding_reference.contains(canary));
        }
    }
}

fn quoted(identifier: &str) -> String {
    format!("\"{identifier}\"")
}

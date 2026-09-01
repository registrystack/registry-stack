// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

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
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use serde_json::{json, Value};
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "temporal-corrections";
const PACKAGE_REVISION: &str = "temporal-corrections-package-1";
const PRINCIPAL: &str = "temporal-correction-principal-canary";
const SUBJECT_A_FIRST: &str = "household-correction-a-first";
const SUBJECT_B_FIRST: &str = "household-correction-b-first";
const SUBJECT_OVERLAP: &str = "household-correction-overlap";
const SUBJECT_STALE: &str = "household-correction-stale";
const SUBJECT_FAULT: &str = "household-correction-fault";
const SUBJECT_RACE: &str = "household-correction-race";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_temporal_correction_batches_validate_only_completed_intervals() {
    let database = TestDatabase::create(8).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the compiled temporal prerequisite");
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs the compiler-owned temporal schema");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: "temporal-corrections-instance",
            database_id: "temporal-corrections-database",
            package_revision: PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("migration initializes the active package identity");
    migration_task.abort();

    assert_temporal_constraints_are_narrowly_deferrable(&database, &registry).await;

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("registry lock key is valid");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x58; 32].into())
        .expect("test audit profile is keyed");
    let app = mutation_router(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        audit_profile.clone(),
        None,
    );
    let claims = claims();
    let table = &registry.entities()["membership"].physical_table;

    let a_first = seed_pair(&app, &claims, SUBJECT_A_FIRST, "a-first").await;
    let before = effect_counts(&database, table).await;
    let response = send_json(
        &app,
        "/v1/records/memberships:batch",
        Some(claims.clone()),
        "correct-a-first",
        correction_body(&a_first, true),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_batch_corrected(response, &a_first).await;
    assert_effect_delta(&database, table, before, EffectDelta::batch_success(2)).await;
    assert_adjacent_intervals(&database, &registry, SUBJECT_A_FIRST, "2026-06-15").await;

    let b_first = seed_pair(&app, &claims, SUBJECT_B_FIRST, "b-first").await;
    let before = effect_counts(&database, table).await;
    let response = send_json(
        &app,
        "/v1/records/memberships:batch",
        Some(claims.clone()),
        "correct-b-first",
        correction_body(&b_first, false),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_batch_corrected(response, &b_first).await;
    assert_effect_delta(&database, table, before, EffectDelta::batch_success(2)).await;
    assert_adjacent_intervals(&database, &registry, SUBJECT_B_FIRST, "2026-06-15").await;

    let overlap = seed_pair(&app, &claims, SUBJECT_OVERLAP, "overlap").await;
    let before = effect_counts(&database, table).await;
    let response = send_json(
        &app,
        "/v1/records/memberships:batch",
        Some(claims.clone()),
        "final-overlap",
        json!({"items":[{
            "operation":"patch",
            "recordId":overlap.a_id,
            "ifMatch":overlap.a_etag,
            "patch":[{"op":"replace","path":"/data/validTo","value":"2026-06-15"}]
        }]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_problem_code(response, "mutation.conflict").await;
    assert_effect_delta(&database, table, before, EffectDelta::no_mutation()).await;
    assert_adjacent_intervals(&database, &registry, SUBJECT_OVERLAP, "2026-06-01").await;

    let before = effect_counts(&database, table).await;
    let response = send_json(
        &app,
        "/v1/records/memberships:batch",
        Some(claims.clone()),
        "reversed-interval",
        json!({"items":[{
            "operation":"create",
            "data":{
                "subject":"household-correction-reversed",
                "group":"A",
                "validFrom":"2026-06-15",
                "validTo":"2026-06-01"
            }
        }]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_problem_code(response, "mutation.conflict").await;
    assert_effect_delta(&database, table, before, EffectDelta::no_mutation()).await;

    let stale = seed_pair(&app, &claims, SUBJECT_STALE, "stale").await;
    let before = effect_counts(&database, table).await;
    let response = send_json(
        &app,
        "/v1/records/memberships:batch",
        Some(claims.clone()),
        "stale-later-item",
        json!({"items":[
            {
                "operation":"create",
                "data":{
                    "subject":"household-correction-stale-prefix",
                    "group":"A",
                    "validFrom":"2026-01-01",
                    "validTo":"2026-02-01"
                }
            },
            {
                "operation":"patch",
                "recordId":stale.b_id,
                "ifMatch":"\"rs-stale-etag\"",
                "patch":[{"op":"replace","path":"/data/validFrom","value":"2026-06-15"}]
            }
        ]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    assert_problem_code(response, "precondition.failed").await;
    assert_effect_delta(&database, table, before, EffectDelta::no_mutation()).await;

    let fault = seed_pair(&app, &claims, SUBJECT_FAULT, "fault").await;
    let fault_app = mutation_router(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        audit_profile.clone(),
        Some(MutationFaultPoint::AfterFirstBatchItem),
    );
    let before = effect_counts(&database, table).await;
    let response = send_json(
        &fault_app,
        "/v1/records/memberships:batch",
        Some(claims.clone()),
        "fault-after-first-item",
        correction_body(&fault, true),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_problem_code(response, "service.unavailable").await;
    assert_effect_delta(&database, table, before, EffectDelta::no_mutation()).await;
    assert_adjacent_intervals(&database, &registry, SUBJECT_FAULT, "2026-06-01").await;

    let race = seed_pair(&app, &claims, SUBJECT_RACE, "race").await;
    let before = effect_counts(&database, table).await;
    let left = send_json(
        &app,
        "/v1/records/memberships:batch",
        Some(claims.clone()),
        "race-a-first",
        correction_body(&race, true),
    );
    let right = send_json(
        &app,
        "/v1/records/memberships:batch",
        Some(claims.clone()),
        "race-b-first",
        correction_body(&race, false),
    );
    let (left, right) = tokio::join!(left, right);
    let statuses = [left.status(), right.status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1,
        "exactly one correction may commit from the same strong ETags"
    );
    let refused = if left.status() == StatusCode::OK {
        right
    } else {
        left
    };
    assert!(
        matches!(
            refused.status(),
            StatusCode::PRECONDITION_FAILED
                | StatusCode::CONFLICT
                | StatusCode::SERVICE_UNAVAILABLE
        ),
        "competing correction refusal is value-free and non-successful: {}",
        refused.status()
    );
    assert_effect_delta(&database, table, before, EffectDelta::batch_success(2)).await;
    assert_adjacent_intervals(&database, &registry, SUBJECT_RACE, "2026-06-15").await;

    database.cleanup().await;
}

fn compiled_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"temporal-corrections","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"membership","route":"memberships","mutationMode":"mutable","classification":"internal",
            "batch":{"maximumItems":4,"maximumBytes":16384},
            "fields":[
              {"id":"subject","type":"string","maxLength":96,"required":true,"classification":"internal"},
              {"id":"group","type":"vocabulary-code","vocabulary":"membership-group","required":true,"classification":"internal"},
              {"id":"valid-from","type":"date","required":true,"classification":"internal"},
              {"id":"valid-to","type":"date","classification":"internal"},
              {"id":"source-reference","type":"string","maxLength":120,"classification":"restricted"}
            ],
            "temporal":{"startField":"valid-from","endField":"valid-to"},
            "constraints":[{
              "kind":"temporal-non-overlap",
              "scopeFields":["subject"],
              "startField":"valid-from",
              "endField":"valid-to"
            }],
            "events":[
              {"id":"membership-created","trigger":"created","projection":["subject","group","valid-from","valid-to"]},
              {"id":"membership-patched","trigger":"patched","projection":["subject","group","valid-from","valid-to"]}
            ]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"registry_principal",
            "requiredPurposes":["history-maintenance"],"requiredScopes":["history-maintain"],
            "grants":[{
              "entity":"membership","operations":["create","get","patch","batch"],
              "readableFields":["subject","group","valid-from","valid-to"],
              "writableFields":["subject","group","valid-from","valid-to","source-reference"]
            }]
          }],
          "vocabularies":[{"id":"membership-group","values":["A","B"]}]
        }"#,
    )
    .expect("temporal correction fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("temporal correction fixture compiles")
}

fn mutation_router(
    pool: registry_server::postgres::RuntimePool,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: registry_server::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    profile: AuditProfile,
    fault: Option<MutationFaultPoint>,
) -> axum::Router {
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x4f; 32]), Duration::from_secs(300))
            .expect("cursor key is valid"),
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
    let mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        profile,
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
            records,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_postgres_mutations(Arc::new(mutations)),
    ))
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

#[derive(Clone)]
struct MembershipPair {
    a_id: String,
    a_etag: String,
    b_id: String,
    b_etag: String,
}

async fn seed_pair(
    app: &axum::Router,
    claims: &VerifiedRequestClaims,
    subject: &str,
    key_prefix: &str,
) -> MembershipPair {
    let a = send_json(
        app,
        "/v1/records/memberships",
        Some(claims.clone()),
        &format!("{key_prefix}-create-a"),
        json!({"data":{
            "subject":subject,
            "group":"A",
            "validFrom":"2026-01-01",
            "validTo":"2026-06-01",
            "sourceReference":"seed-a"
        }}),
    )
    .await;
    assert_eq!(a.status(), StatusCode::CREATED);
    let a_etag = header(&a, "etag");
    let a_body = body_json(a).await;
    let a_id = a_body["id"].as_str().expect("A record id").to_owned();

    let b = send_json(
        app,
        "/v1/records/memberships",
        Some(claims.clone()),
        &format!("{key_prefix}-create-b"),
        json!({"data":{
            "subject":subject,
            "group":"B",
            "validFrom":"2026-06-01",
            "validTo":null,
            "sourceReference":"seed-b"
        }}),
    )
    .await;
    assert_eq!(b.status(), StatusCode::CREATED);
    let b_etag = header(&b, "etag");
    let b_body = body_json(b).await;
    let b_id = b_body["id"].as_str().expect("B record id").to_owned();
    MembershipPair {
        a_id,
        a_etag,
        b_id,
        b_etag,
    }
}

fn correction_body(pair: &MembershipPair, a_first: bool) -> Value {
    let a = json!({
        "operation":"patch",
        "recordId":pair.a_id,
        "ifMatch":pair.a_etag,
        "patch":[
            {"op":"test","path":"/data/validTo","value":"2026-06-01"},
            {"op":"replace","path":"/data/validTo","value":"2026-06-15"}
        ]
    });
    let b = json!({
        "operation":"patch",
        "recordId":pair.b_id,
        "ifMatch":pair.b_etag,
        "patch":[
            {"op":"test","path":"/data/validFrom","value":"2026-06-01"},
            {"op":"replace","path":"/data/validFrom","value":"2026-06-15"}
        ]
    });
    let items = if a_first { vec![a, b] } else { vec![b, a] };
    json!({
        "changeContext":{
            "kind":"correction",
            "reasonCode":"effective_date_corrected",
            "sourceReferences":["case-document:temporal-correction"]
        },
        "items":items
    })
}

async fn assert_batch_corrected(response: axum::response::Response, pair: &MembershipPair) {
    let body = body_json(response).await;
    assert_snapshot_reference(&body["snapshot"]);
    let results = body["results"]
        .as_array()
        .expect("batch response has ordered results");
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|item| {
        item["id"] == pair.a_id
            && item["revision"] == 2
            && item["data"]["group"] == "A"
            && item["data"]["validTo"] == "2026-06-15"
    }));
    assert!(results.iter().any(|item| {
        item["id"] == pair.b_id
            && item["revision"] == 2
            && item["data"]["group"] == "B"
            && item["data"]["validFrom"] == "2026-06-15"
    }));
}

async fn assert_temporal_constraints_are_narrowly_deferrable(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
) {
    let entity = &registry.entities()["membership"];
    let table = &entity.physical_table;
    let expected_exclusion_names = registry.physical_names().entities["membership"]
        .constraints
        .values()
        .cloned()
        .collect::<BTreeSet<_>>();
    let rows = database
        .admin
        .query(
            "SELECT constraint_row.conname, constraint_row.contype::text,
                    constraint_row.condeferrable, constraint_row.condeferred
               FROM pg_catalog.pg_constraint AS constraint_row
               JOIN pg_catalog.pg_class AS relation
                 ON relation.oid = constraint_row.conrelid
               JOIN pg_catalog.pg_namespace AS namespace
                 ON namespace.oid = relation.relnamespace
              WHERE namespace.nspname = 'registry_data'
                AND relation.relname = $1
              ORDER BY constraint_row.conname",
            &[table],
        )
        .await
        .expect("administrator inspects compiled temporal constraints");
    let mut exclusion_count = 0;
    let mut temporal_order_count = 0;
    for row in rows {
        let constraint_name: String = row.get(0);
        let constraint_type: String = row.get(1);
        let deferrable: bool = row.get(2);
        let initially_deferred: bool = row.get(3);
        if constraint_type == "x" {
            exclusion_count += 1;
            assert!(
                expected_exclusion_names.contains(&constraint_name),
                "temporal exclusion uses only the compiler-owned generated name"
            );
            assert!(deferrable, "temporal exclusion can be deferred by name");
            assert!(
                !initially_deferred,
                "temporal exclusion remains INITIALLY IMMEDIATE outside correction batches"
            );
        } else if constraint_name.contains("temporal_order") {
            temporal_order_count += 1;
            assert!(
                !deferrable,
                "interval order checks remain immediate and are not swept into batch deferral"
            );
        }
    }
    assert_eq!(exclusion_count, 1);
    assert_eq!(temporal_order_count, 1);
}

async fn assert_adjacent_intervals(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
    subject: &str,
    boundary: &str,
) {
    let entity = &registry.entities()["membership"];
    let table = quote(&entity.physical_table);
    let subject_column = quote(&entity.fields["subject"].physical_name);
    let group_column = quote(&entity.fields["group"].physical_name);
    let start_column = quote(&entity.fields["valid-from"].physical_name);
    let end_column = quote(&entity.fields["valid-to"].physical_name);
    let rows = database
        .admin
        .query(
            &format!(
                "SELECT {group_column}, {start_column}::text, {end_column}::text
                   FROM registry_data.{table}
                  WHERE {subject_column} = $1
                  ORDER BY {group_column}"
            ),
            &[&subject],
        )
        .await
        .expect("administrator reads final temporal intervals");
    assert_eq!(rows.len(), 2);
    let a_group: String = rows[0].get(0);
    let a_start: String = rows[0].get(1);
    let a_end: Option<String> = rows[0].get(2);
    let b_group: String = rows[1].get(0);
    let b_start: String = rows[1].get(1);
    let b_end: Option<String> = rows[1].get(2);
    assert_eq!(a_group, "A");
    assert_eq!(a_start, "2026-01-01");
    assert_eq!(a_end.as_deref(), Some(boundary));
    assert_eq!(b_group, "B");
    assert_eq!(b_start, boundary);
    assert_eq!(b_end, None);

    let overlaps: i64 = database
        .admin
        .query_one(
            &format!(
                "SELECT count(*)
                   FROM registry_data.{table} left_membership
                   JOIN registry_data.{table} right_membership
                     ON left_membership.record_id < right_membership.record_id
                    AND left_membership.{subject_column} = right_membership.{subject_column}
                    AND daterange(left_membership.{start_column}, left_membership.{end_column}, '[)')
                        && daterange(right_membership.{start_column}, right_membership.{end_column}, '[)')
                  WHERE left_membership.{subject_column} = $1"
            ),
            &[&subject],
        )
        .await
        .expect("administrator verifies final non-overlap")
        .get(0);
    assert_eq!(overlaps, 0);
}

fn claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        PRINCIPAL,
        BTreeSet::from(["history-maintain".to_owned()]),
        Some("history-maintenance".to_owned()),
        BTreeMap::from([(
            "unused".to_owned(),
            VerifiedClaimValue::direct_string("unused").expect("direct claim"),
        )]),
    )
    .expect("verified claims are bounded")
}

async fn send_json(
    app: &axum::Router,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    key: &str,
    body: Value,
) -> axum::response::Response {
    send(
        app,
        Method::POST,
        uri,
        claims,
        &[
            ("content-type", "application/json"),
            ("idempotency-key", key),
        ],
        serde_json::to_vec(&body).expect("request JSON"),
    )
    .await
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

fn header(response: &axum::response::Response, name: &str) -> String {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .expect("response header is present")
        .to_owned()
}

async fn assert_problem_code(response: axum::response::Response, code: &str) {
    assert_eq!(body_json(response).await["code"], code);
}

async fn body_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response_bytes(response).await).expect("JSON response")
}

async fn response_bytes(response: axum::response::Response) -> Vec<u8> {
    to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body")
        .to_vec()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectCounts {
    current: i64,
    revisions: i64,
    outbox: i64,
    audit: i64,
    idempotency: i64,
    commits: i64,
    commit_members: i64,
}

#[derive(Clone, Copy)]
struct EffectDelta {
    current: i64,
    revisions: i64,
    outbox: i64,
    idempotency: i64,
    commits: i64,
    commit_members: i64,
}

impl EffectDelta {
    fn batch_success(result_count: i64) -> Self {
        Self {
            current: 0,
            revisions: result_count,
            outbox: result_count,
            idempotency: 1,
            commits: 1,
            commit_members: result_count,
        }
    }

    fn no_mutation() -> Self {
        Self {
            current: 0,
            revisions: 0,
            outbox: 0,
            idempotency: 0,
            commits: 0,
            commit_members: 0,
        }
    }
}

async fn assert_effect_delta(
    database: &TestDatabase,
    table: &str,
    before: EffectCounts,
    expected: EffectDelta,
) {
    let after = effect_counts(database, table).await;
    assert_eq!(after.current - before.current, expected.current);
    assert_eq!(after.revisions - before.revisions, expected.revisions);
    assert_eq!(after.outbox - before.outbox, expected.outbox);
    assert_eq!(after.idempotency - before.idempotency, expected.idempotency);
    assert_eq!(after.commits - before.commits, expected.commits);
    assert_eq!(
        after.commit_members - before.commit_members,
        expected.commit_members
    );
}

async fn effect_counts(database: &TestDatabase, table: &str) -> EffectCounts {
    let table = quote(table);
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT
                   (SELECT count(*) FROM registry_data.{table}),
                   (SELECT count(*) FROM registry_internal.registry_revisions),
                   (SELECT count(*) FROM registry_internal.registry_outbox),
                   (SELECT count(*) FROM registry_internal.registry_audit),
                   (SELECT count(*) FROM registry_internal.registry_idempotency),
                   (SELECT count(*) FROM registry_internal.registry_revision_commits),
                   (SELECT count(*) FROM registry_internal.registry_revision_commit_members)"
            ),
            &[],
        )
        .await
        .expect("administrator inspects mutation effects");
    EffectCounts {
        current: row.get(0),
        revisions: row.get(1),
        outbox: row.get(2),
        audit: row.get(3),
        idempotency: row.get(4),
        commits: row.get(5),
        commit_members: row.get(6),
    }
}

fn assert_snapshot_reference(value: &Value) {
    let snapshot = value.as_str().expect("response carries snapshot reference");
    assert_eq!(snapshot.len(), 40);
    assert!(snapshot.starts_with("rs1_"));
    Uuid::parse_str(&snapshot[4..]).expect("snapshot suffix is a UUID");
}

fn quote(identifier: &str) -> String {
    assert!(identifier
        .bytes()
        .all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit()));
    format!("\"{identifier}\"")
}

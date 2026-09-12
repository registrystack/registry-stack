// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_json, ModuleAssetSource};
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    begin_record_transaction, initialize_registry_state_for_catalog_test, install_compiled_schema,
    ClaimContext, ExpectedManagedCatalog, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity, RowBoundaryContext,
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tower::Service as _;
use zeroize::Zeroizing;

const RECORD: &str = "00000000-0000-4000-8000-000000000001";
const PACKAGE: &str = "read-dependencies";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_collection_reads_use_only_reached_derived_relations() {
    exercise_read_dependencies("valid", false, "r.amount > 0").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_unused_invalid_relation_does_not_break_narrow_reads() {
    exercise_read_dependencies("unused-invalid", true, "r.amount > 0").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_selected_derived_sql_changes_answer_with_same_field_contract() {
    exercise_read_dependencies("selected-changed", false, "r.amount < 0").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_distinct_derived_dependencies_preserve_filtered_hidden_sort_continuations() {
    exercise_read_dependencies("combined", false, "r.amount > 30").await;
}

async fn exercise_read_dependencies(case: &str, invalid_population: bool, active_expression: &str) {
    let registry = Arc::new(compiled_registry(
        invalid_population,
        active_expression,
        case == "combined",
    ));
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("compiled fixture installs, including the reviewed derived SQL");
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(&registry),
        RegistryStateTestIdentity {
            package_id: PACKAGE,
            environment: "local",
            instance_id: "dependencies-instance",
            database_id: "dependencies-database",
            package_revision: case,
            package_sequence: 1,
        },
    )
    .await
    .expect("compiled catalog binds the active fixture identity");
    migration_task.abort();
    let pool = database.runtime_config.build_pool().expect("bounded pool");
    let lock_key = RegistryLockKey::derive(PACKAGE).expect("bounded lock key");
    let entity = &registry.entities()["entry"];
    let mut client = pool.get_for_test().await.expect("seed connection");
    for tenant in ["visible", "hidden"] {
        let context = ClaimContext::for_compiled(
            &registry,
            "entry",
            Some("test-principal".to_owned()),
            "reader",
            None,
            vec![RowBoundaryContext::Equals {
                field: "tenant".to_owned(),
                value: tenant.to_owned(),
            }],
        )
        .expect("seed uses the compiled tenant boundary");
        let transaction = begin_record_transaction(
            &mut client,
            lock_key,
            Duration::from_secs(2),
            &identity,
            &context,
        )
        .await
        .expect("seed installs RLS context");
        for index in 1..=32 {
            let record_id = if tenant == "visible" {
                format!("00000000-0000-4000-8000-{index:012}")
            } else {
                format!("00000000-0000-4000-8001-{index:012}")
            };
            transaction
                .transaction_for_test()
                .execute(
                    &format!(
                        "INSERT INTO registry_data.\"{}\" (record_id, \"{}\", \"{}\", \"{}\")
                             VALUES ($1::text::uuid, $2, $3, $4)",
                        entity.physical_table,
                        entity.fields["tenant"].physical_name,
                        entity.fields["code"].physical_name,
                        entity.fields["amount"].physical_name,
                    ),
                    &[
                        &record_id,
                        &tenant,
                        &format!("code-{index:02}"),
                        &i64::from(index),
                    ],
                )
                .await
                .expect("synthetic seed row obeys its tenant authority");
        }
        transaction.commit().await.expect("seed commits");
    }
    drop(client);
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x41; 32]), Duration::from_secs(300))
            .expect("test cursor key"),
    );
    let plans = Arc::new(Mutex::new(Vec::new()));
    let service = PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        AuditProfile::production_from_secret_bytes(vec![0x42; 32].into()).expect("keyed audit"),
        cursors.clone(),
    )
    .with_query_plan_for_test(plans.clone());
    let app = router(Arc::new(HttpService::new(
        registry,
        ReadRuntimeIdentity {
            package_revision: identity.package_revision,
            schema_fingerprint: identity.schema_fingerprint,
        },
        Arc::new(service),
        Arc::new(AlwaysReady),
        cursors,
    )));

    if case == "combined" {
        exercise_combined_dependencies(&app, &plans).await;
        drop(app);
        drop(pool);
        database.cleanup().await;
        return;
    }

    let (status, body) = send(
        &app,
        "/v1/records/entries:lookup?$select=code",
        true,
        "visible",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{case}: {body}");
    assert_eq!(body["data"]["recordIdentifier"], RECORD);
    assert_eq!(body["data"]["domainData"], json!({"code": "code-01"}));
    let narrow_work = take_plan(&plans, 0);

    let (status, body) = send(
        &app,
        "/v1/records/entries:lookup?$select=code,active",
        true,
        "visible",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{case}: {body}");
    assert_eq!(
        body["data"]["domainData"],
        json!({
            "code": "code-01", "active": case != "selected-changed"
        })
    );
    // Both SQL variants have the same declared boolean field. The reached
    // SQL body changes the answer despite that identical output contract.
    take_plan(&plans, 1);

    let (status, body) = send(
        &app,
        &format!("/v1/records/entries/{RECORD}?$select=code"),
        false,
        "visible",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{case}: {body}");
    take_plan(&plans, 0);
    let (status, body) = send(
        &app,
        &format!("/v1/records/entries/{RECORD}?$select=code,active"),
        false,
        "other",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{case}: {body}");
    plans.lock().expect("plan lock").clear();

    let (status, body) = send(
        &app,
        "/v1/records/entries?$select=code&$count=true",
        false,
        "visible",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{case}: {body}");
    assert_eq!(body["items"].as_array().expect("list items").len(), 32);
    assert_eq!(body["count"], 32, "count preserves the tenant RLS boundary");
    take_plan(&plans, 0);

    let (status, body) = send(
        &app,
        "/v1/records/entries:lookup?$select=code,population",
        true,
        "visible",
    )
    .await;
    if invalid_population {
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{case}: {body}");
        assert!(!body.to_string().contains("division"));
        assert!(!body.to_string().contains("registry_derived"));
    } else {
        assert_eq!(status, StatusCode::OK, "{case}: {body}");
        assert_eq!(body["data"]["domainData"]["population"], 32);
        let derived_work = take_plan(&plans, 1);
        assert!(
            derived_work > narrow_work,
            "joined aggregate processes extra rows"
        );
        eprintln!("{case}: narrow plan row visits={narrow_work}, selected aggregate plan row visits={derived_work}");
    }

    // Neither field is returned. Recursive filter predicates and ordering
    // still reach their derived relation, including its cardinality guard.
    for query in [
            "/v1/records/entries?$select=code&$filter=not%20(population%20lt%2032%20or%20population%20gt%2032)&$count=true",
            "/v1/records/entries?$select=code&$orderby=population&$top=1",
        ] {
            let (status, body) = send(&app, query, false, "visible").await;
            if invalid_population {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{case}: {body}");
            } else {
                assert_eq!(status, StatusCode::OK, "{case}: {body}");
                assert_eq!(body["items"][0]["domainData"], json!({"code": "code-01"}));
                take_plan(&plans, 1);
            }
        }
    drop(app);
    drop(pool);
    database.cleanup().await;
}

async fn exercise_combined_dependencies(app: &axum::Router, plans: &Mutex<Vec<Value>>) {
    // The projection, filter, and order each reach a different derived view.
    // The filter's left branch is stored-only, so only its nested right branch
    // discovers population. Priority is hidden and reverses canonical-id order.
    let mut uri = "/v1/records/entries?$select=code,active&$filter=code%20eq%20'code-01'%20or%20(not%20(population%20lt%2032)%20and%20amount%20gt%2028)&$orderby=priority&$top=2&$count=true".to_owned();
    for expected_indices in [&[32, 31][..], &[30, 29][..], &[1][..]] {
        let (status, body) = send(app, &uri, false, "visible").await;
        assert_eq!(status, StatusCode::OK, "combined dependencies: {body}");
        assert_eq!(
            body["count"], 5,
            "count retains the whole authorized filter on every page"
        );
        let items = body["items"].as_array().expect("projected page items");
        let ids = items
            .iter()
            .map(|item| item["recordIdentifier"].as_str().expect("canonical id"))
            .collect::<Vec<_>>();
        let expected_ids = expected_indices
            .iter()
            .map(|index| format!("00000000-0000-4000-8000-{index:012}"))
            .collect::<Vec<_>>();
        assert_eq!(
            ids, expected_ids,
            "hidden derived ASC ordering survives continuation"
        );
        for (item, index) in items.iter().zip(expected_indices) {
            assert_eq!(
                item["domainData"],
                json!({
                    "code": format!("code-{index:02}"),
                    "active": *index > 30,
                }),
                "filter and order inputs remain outside the response projection"
            );
        }
        take_plan(plans, 3);
        if expected_indices == [1] {
            assert!(
                body["pageInfo"]["nextCursor"].is_null(),
                "the exact five-row result is exhausted"
            );
        } else {
            let cursor = body["pageInfo"]["nextCursor"]
                .as_str()
                .expect("bounded page continuation");
            uri = format!("/v1/records/entries?$skiptoken={cursor}");
        }
    }
}

fn take_plan(plans: &Mutex<Vec<Value>>, expected_windows: usize) -> f64 {
    let nodes = std::mem::take(&mut *plans.lock().expect("plan lock"));
    assert!(
        !nodes.is_empty(),
        "the runtime statement was actually explained"
    );
    assert_eq!(
        nodes
            .iter()
            .filter(|node| node["nodeType"] == "WindowAgg")
            .count(),
        expected_windows,
        "each reached derived relation retains its cardinality window: {nodes:?}"
    );
    nodes
        .iter()
        .map(|node| {
            node["actualRows"].as_f64().expect("ANALYZE row count")
                * node["actualLoops"].as_f64().expect("ANALYZE loop count")
        })
        .sum()
}

async fn send(app: &axum::Router, uri: &str, lookup: bool, tenant: &str) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(if lookup { Method::POST } else { Method::GET })
        .uri(uri)
        .header("content-type", "application/json")
        .body(if lookup {
            Body::from(json!({"selector": "by-code", "values": {"code": "code-01"}}).to_string())
        } else {
            Body::empty()
        })
        .expect("bounded synthetic request");
    request.extensions_mut().insert(
        VerifiedRequestClaims::authenticated(
            "registry_principal",
            "test-principal",
            BTreeSet::new(),
            None,
            BTreeMap::from([(
                "tenant".to_owned(),
                VerifiedClaimValue::direct_string(tenant).expect("direct tenant claim"),
            )]),
        )
        .expect("verified request claims"),
    );
    let response = app.clone().call(request).await.expect("router response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("bounded body");
    (
        status,
        serde_json::from_slice(&bytes).expect("JSON response"),
    )
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn compiled_registry(
    invalid_population: bool,
    active_expression: &str,
    combined_dependencies: bool,
) -> registry_breg::CompiledRegistry {
    let mut project = parse_project_json(br#"{
        "apiVersion":"registry.registrystack.org/v1alpha1",
        "kind":"RegistryProject",
        "registry":{"id":"read-dependencies","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://example.test"},
        "entities":[{
            "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable",
            "fields":[
                {"id":"code","type":"string","required":true,"maxLength":32,"classification":"internal"},
                {"id":"tenant","type":"string","required":true,"maxLength":32,"classification":"internal"},
                {"id":"amount","type":"int64","required":true,"classification":"internal"}
            ],
            "selectorProfiles":[{"id":"by-code","fields":["code"]}],
            "derived":[
                {"id":"status","sql":"status.sql","key":"id","execution":"live","fields":[{"id":"active","type":"boolean","classification":"internal"}]},
                {"id":"population","sql":"population.sql","key":"id","execution":"live","fields":[{"id":"population","type":"int64","classification":"internal"}]}
            ]
        }],
        "accessProfiles":[{
            "id":"reader","default":true,"principalClaim":"registry_principal",
            "permissions":[{
                "entity":"entry","operations":["create","get","list","lookup"],
                "readableFields":["code","active","population"],
                "writableFields":["code","tenant","amount"],
                "filterableFields":["population"],"sortableFields":["population"],
                "lookups":[{"selector":"by-code","valueOrigin":"request"}],"allowCount":true,
                "rowBoundaries":[{"field":"tenant","claim":"tenant","operator":"equals"}]
            }]
        }]
    }"#).expect("derived dependency fixture parses");
    let population = if invalid_population {
        "SELECT r.id AS id, other.amount AS population FROM registry_source.entry r JOIN registry_source.entry other ON other.tenant = r.tenant"
    } else {
        "SELECT r.id AS id, count(other.id) AS population FROM registry_source.entry r JOIN registry_source.entry other ON other.tenant = r.tenant GROUP BY r.id"
    };
    let mut assets = vec![
        ModuleAssetSource {
            module: None,
            path: "status.sql".to_owned(),
            bytes: format!(
                "SELECT r.id AS id, {active_expression} AS active FROM registry_source.entry r"
            )
            .into_bytes(),
        },
        ModuleAssetSource {
            module: None,
            path: "population.sql".to_owned(),
            bytes: population.as_bytes().to_vec(),
        },
    ];
    if combined_dependencies {
        project.entities[0].derived.push(
            serde_json::from_value(json!({
                "id": "priority", "sql": "priority.sql", "key": "id", "execution": "live",
                "fields": [{"id": "priority", "type": "int64", "classification": "internal"}]
            }))
            .expect("third independent derived relation"),
        );
        let grant = &mut project.access_profiles[0].permissions[0];
        grant.readable_fields.insert("priority".to_owned());
        grant.readable_fields.insert("amount".to_owned());
        grant.filterable_fields.insert("code".to_owned());
        grant.filterable_fields.insert("amount".to_owned());
        grant.sortable_fields.insert("priority".to_owned());
        assets.push(ModuleAssetSource {
            module: None,
            path: "priority.sql".to_owned(),
            bytes: b"SELECT r.id AS id, 33 - r.amount AS priority FROM registry_source.entry r"
                .to_vec(),
        });
    }
    compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring)
        .expect("derived dependency fixture compiles")
}

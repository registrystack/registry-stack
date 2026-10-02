// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, Method, Request, Response, StatusCode};
use chrono::{Datelike, Days, NaiveDate, Utc};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::audit::RegistryAudit;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    begin_record_transaction, initialize_compiled_registry_state_for_test, install_compiled_schema,
    ClaimContext, PostgresRecordReadService, PostgresStatisticsService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tower::Service as _;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "statistics-http-registry";
const DATABASE_ID: &str = "statistics-http-database";
const PRINCIPAL_CANARY: &str = "statistics-principal-must-not-enter-audit";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn statistical_http_full_journey_preserves_visibility_release_and_withdrawal_rules() {
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-http-1",
        },
    )
    .await
    .expect("runtime identity and empty history baseline initialize");
    migration_task.abort();

    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let today = Utc::now().date_naive();
    let current_period = month_code(today);
    let prior_date = today
        .with_day(1)
        .expect("current month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("previous month exists");
    let prior_period = month_code(prior_date);
    seed_records(&pool, lock_key, &identity, &compiled, today, prior_date).await;

    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x72; 32].into())
            .expect("audit profile is keyed"),
    );
    let app = statistics_router(pool, compiled, identity, lock_key, audit);

    let analyst = claims("analyst", true);
    let count = send(
        &app,
        Method::GET,
        "/v1/records/records?accessProfile=analyst&$filter=active%20eq%20true&$count=true&$top=1",
        Some(analyst.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(count.status(), StatusCode::OK);
    let count = body_json(count).await["count"]
        .as_u64()
        .expect("ordinary list returns its authorized count");
    assert_eq!(count, 8, "the row boundary excludes the other jurisdiction");

    let live = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category:live?accessProfile=analyst&from={prior_period}&to={current_period}"
        ),
        Some(analyst.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(live.status(), StatusCode::OK);
    assert!(live.headers().contains_key("repr-digest"));
    let live = body_json(live).await;
    assert_eq!(
        total_cell(&live, &prior_period) + total_cell(&live, &current_period),
        count
    );
    assert_eq!(live["live"]["accessProfile"], "analyst");
    assert!(live.get("disclosure").is_none());

    let before_first = send(
        &app,
        Method::GET,
        "/v1/statistics/records-by-category:live?accessProfile=analyst&from=2024-12&to=2024-12",
        Some(analyst.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(before_first.status(), StatusCode::BAD_REQUEST);

    let reader = claims("reader", false);
    let reader_entity = send(
        &app,
        Method::GET,
        "/v1/records/records?accessProfile=reader",
        Some(reader.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(reader_entity.status(), StatusCode::NOT_FOUND);
    let reader_live = send(
        &app,
        Method::GET,
        "/v1/statistics/records-by-category:live?accessProfile=reader",
        Some(reader.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(reader_live.status(), StatusCode::NOT_FOUND);

    let publisher = claims("publisher", false);
    let unended = publish(&app, &current_period, "unended", "final", publisher.clone()).await;
    assert_eq!(unended.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body_json(unended).await["refusalCode"], "period-not-ended");

    let first = publish(
        &app,
        &prior_period,
        "release-one",
        "provisional",
        publisher.clone(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::CREATED);
    assert!(first.headers().contains_key("repr-digest"));
    let first_bytes = body_bytes(first).await;
    let first_header: Value = serde_json::from_slice(&first_bytes).expect("header is JSON");
    assert_eq!(first_header["version"], 1);
    assert_eq!(first_header["status"], "provisional");

    let replay = publish(
        &app,
        &prior_period,
        "release-one",
        "provisional",
        publisher.clone(),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(body_bytes(replay).await, first_bytes);
    let conflict = publish(
        &app,
        &prior_period,
        "release-one",
        "final",
        publisher.clone(),
    )
    .await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);

    let latest = send(
        &app,
        Method::GET,
        &format!("/v1/statistics/records-by-category/releases/{prior_period}?accessProfile=reader"),
        Some(reader.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(latest.status(), StatusCode::OK);
    let latest_json = body_json(latest).await;
    assert_eq!(latest_json["release"]["version"], 1);
    assert!(latest_json.get("live").is_none());
    assert!(latest_json.get("disclosure").is_some());

    let csv = send(
        &app,
        Method::GET,
        &format!("/v1/statistics/records-by-category/releases/{prior_period}?accessProfile=reader"),
        Some(reader.clone()),
        &[("accept", "text/csv")],
        Vec::new(),
    )
    .await;
    assert_eq!(csv.status(), StatusCode::OK);
    assert_eq!(csv.headers()["content-type"], "text/csv; charset=utf-8");
    let csv_text = String::from_utf8(body_bytes(csv).await).expect("CSV is UTF-8");
    assert!(csv_text.starts_with("period,category,value,status\r\n"));

    let unauthorized_publish = publish(
        &app,
        &prior_period,
        "reader-cannot-publish",
        "final",
        reader.clone(),
    )
    .await;
    assert_eq!(unauthorized_publish.status(), StatusCode::NOT_FOUND);

    let withdrawn = withdraw(&app, &prior_period, 1, "withdraw-one", publisher.clone()).await;
    assert_eq!(withdrawn.status(), StatusCode::OK);
    let withdrawal_header = body_json(withdrawn).await;
    assert_eq!(
        withdrawal_header["withdrawal"]["reason"],
        "source-data-error"
    );

    let explicit_withdrawn = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category/releases/{prior_period}/versions/1?accessProfile=reader"
        ),
        Some(reader.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(explicit_withdrawn.status(), StatusCode::GONE);
    assert_eq!(
        body_json(explicit_withdrawn).await["reasonCode"],
        "source-data-error"
    );

    let no_latest = send(
        &app,
        Method::GET,
        &format!("/v1/statistics/records-by-category/releases/{prior_period}?accessProfile=reader"),
        Some(reader.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(no_latest.status(), StatusCode::NOT_FOUND);

    let second = publish(
        &app,
        &prior_period,
        "release-two",
        "final",
        publisher.clone(),
    )
    .await;
    assert_eq!(second.status(), StatusCode::CREATED);
    assert_eq!(body_json(second).await["version"], 2);
    let provisional_after_final = publish(
        &app,
        &prior_period,
        "late-provisional",
        "provisional",
        publisher,
    )
    .await;
    assert_eq!(
        provisional_after_final.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        body_json(provisional_after_final).await["refusalCode"],
        "provisional-after-final"
    );

    let series = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category/releases:series?accessProfile=reader&from={prior_period}&to={prior_period}&status=final"
        ),
        Some(reader.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(series.status(), StatusCode::OK);
    let series = body_json(series).await;
    assert_eq!(series["periods"][0]["version"]["version"], 2);

    let releases = send(
        &app,
        Method::GET,
        "/v1/statistics/records-by-category/releases?accessProfile=reader&$top=1",
        Some(reader),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(releases.status(), StatusCode::OK);
    let releases = body_json(releases).await;
    assert_eq!(
        releases["items"].as_array().expect("release items").len(),
        1
    );
    assert_eq!(releases["pageInfo"]["hasMore"], true);
    assert!(releases["pageInfo"]["nextCursor"].is_string());

    database.assert_every_audit_request_answered_once();
    let audit_text = serde_json::to_string(&database.audit_entries()).expect("audit serializes");
    assert!(!audit_text.contains(PRINCIPAL_CANARY));
    database.cleanup().await;
}

fn statistics_router(
    pool: registry_breg::postgres::RuntimePool,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    audit: RegistryAudit,
) -> axum::Router {
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x31; 32]), Duration::from_secs(300))
            .expect("cursor key is valid"),
    );
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    ));
    let statistics = Arc::new(PostgresStatisticsService::new(
        pool,
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit,
    ));
    router(Arc::new(
        HttpService::new(
            registry,
            ReadRuntimeIdentity {
                package_revision: identity.activation_id,
                schema_fingerprint: identity.schema_fingerprint,
            },
            records,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_statistics(statistics),
    ))
}

async fn seed_records(
    pool: &registry_breg::postgres::RuntimePool,
    lock_key: RegistryLockKey,
    identity: &registry_breg::postgres::ExpectedRegistryIdentity,
    registry: &registry_breg::CompiledRegistry,
    today: NaiveDate,
    prior: NaiveDate,
) {
    let claims = ClaimContext::for_compiled(
        registry,
        "record",
        Some("fixture-seeder".to_owned()),
        "seed",
        None,
        Vec::new(),
    )
    .expect("seed context is compiler-bound");
    let mut client = pool.get_for_test().await.expect("runtime connection opens");
    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(2),
        identity,
        &claims,
    )
    .await
    .expect("seed transaction opens");
    let entity = &registry.entities()["record"];
    let table = quote_identifier(&entity.physical_table);
    let active = quote_identifier(&entity.fields["active"].physical_name);
    let category = quote_identifier(&entity.fields["category"].physical_name);
    let event_date = quote_identifier(&entity.fields["event-date"].physical_name);
    let jurisdiction = quote_identifier(&entity.fields["jurisdiction"].physical_name);
    let sql = format!(
        "INSERT INTO registry_data.{table}
             (record_id, record_revision, record_lifecycle,
              {active}, {category}, {event_date}, {jurisdiction})
         VALUES ($1::text::uuid, 1, 'active', $2, $3, $4, $5)"
    );
    let rows = [
        (
            "00000000-0000-4000-8000-000000000001",
            true,
            "a",
            today,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000002",
            true,
            "a",
            today,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000003",
            true,
            "b",
            today,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000004",
            true,
            "a",
            prior,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000005",
            true,
            "a",
            prior,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000006",
            true,
            "a",
            prior,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000007",
            true,
            "a",
            prior,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000008",
            true,
            "a",
            prior,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000009",
            true,
            "a",
            prior,
            "south",
        ),
        (
            "00000000-0000-4000-8000-000000000010",
            true,
            "b",
            prior,
            "south",
        ),
    ];
    for (id, value, code, date, boundary) in rows {
        transaction
            .transaction_for_test()
            .execute(&sql, &[&id, &value, &code, &date, &boundary])
            .await
            .expect("seed row inserts through runtime RLS");
    }
    transaction
        .commit()
        .await
        .expect("seed transaction commits");
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1",
        "kind":"RegistryProject",
        "registry":{"id":"statistics-http-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://statistics.example.test"},
        "entities":[{
            "id":"record","primaryDataset":"statistics-http","route":"records","mutationMode":"mutable",
            "fields":[
                {"id":"active","type":"boolean","required":true,"classification":"internal"},
                {"id":"category","type":"vocabulary-code","vocabulary":"category","required":true,"classification":"internal"},
                {"id":"event-date","type":"date","required":true,"classification":"internal"},
                {"id":"jurisdiction","type":"vocabulary-code","vocabulary":"jurisdiction","required":true,"classification":"internal"}
            ]
        }],
        "accessProfiles":[
            {"id":"analyst","principalClaim":"principal","permissions":[{
                "entity":"record","operations":["list"],
                "readableFields":["active","category","event-date","jurisdiction"],
                "filterableFields":["active","category","event-date","jurisdiction"],"allowCount":true,
                "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdictions","operator":"in"}]
            }]},
            {"id":"publisher","principalClaim":"principal","permissions":[{
                "entity":"record","operations":["list"],
                "readableFields":["active","category","event-date","jurisdiction"],
                "filterableFields":["active","category","event-date","jurisdiction"],"allowCount":true,"rowBoundaries":[]
            }]},
            {"id":"seed","principalClaim":"principal","permissions":[{
                "entity":"record","operations":["create"],
                "writableFields":["active","category","event-date","jurisdiction"],"rowBoundaries":[]
            }]},
            {"id":"reader","principalClaim":"principal","permissions":[]}
        ],
        "vocabularies":[
            {"id":"category","values":["a","b"]},
            {"id":"jurisdiction","values":["north","south"]}
        ],
        "statisticalDatasets":[{
            "id":"records-by-category","unit":"record","population":"active eq true",
            "period":{"kind":"flow","field":"event-date","granularity":"month","firstPeriod":"2025-01"},
            "dimensions":["category"],"disclosure":{"minimumCount":5,"roundingBase":5},
            "live":["analyst"],"releases":{"publisher":"publisher","readers":["reader"]}
        }]
    });
    let bytes = serde_json::to_vec(&source).expect("fixture serializes");
    let project = parse_project_json(&bytes).expect("fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}

fn claims(profile: &str, boundaries: bool) -> VerifiedRequestClaims {
    let mut values = BTreeMap::new();
    if boundaries {
        values.insert(
            "jurisdictions".to_owned(),
            VerifiedClaimValue::direct_string_set(["north"])
                .expect("boundary claim is a verified string set"),
        );
    }
    VerifiedRequestClaims::authenticated(
        "principal",
        PRINCIPAL_CANARY,
        BTreeSet::new(),
        None,
        values,
    )
    .unwrap_or_else(|_| panic!("{profile} claims are valid"))
}

async fn publish(
    app: &axum::Router,
    period: &str,
    key: &str,
    status: &str,
    claims: VerifiedRequestClaims,
) -> Response<Body> {
    send(
        app,
        Method::POST,
        &format!(
            "/v1/statistics/records-by-category/releases/{period}/versions?accessProfile=publisher"
        ),
        Some(claims),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", key),
        ],
        serde_json::to_vec(&json!({"status":status})).expect("publish body serializes"),
    )
    .await
}

async fn withdraw(
    app: &axum::Router,
    period: &str,
    version: u64,
    key: &str,
    claims: VerifiedRequestClaims,
) -> Response<Body> {
    send(
        app,
        Method::POST,
        &format!(
            "/v1/statistics/records-by-category/releases/{period}/versions/{version}/withdrawal?accessProfile=publisher"
        ),
        Some(claims),
        &[("content-type", "application/json"), ("idempotency-key", key)],
        serde_json::to_vec(&json!({"reason":"source-data-error"}))
            .expect("withdrawal body serializes"),
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
) -> Response<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(
            HeaderName::from_bytes(name.as_bytes()).expect("header name is valid"),
            *value,
        );
    }
    let mut request = builder.body(Body::from(body)).expect("request builds");
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router returns a response")
}

async fn body_bytes(response: Response<Body>) -> Vec<u8> {
    to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .expect("response body reads")
        .to_vec()
}

async fn body_json(response: Response<Body>) -> Value {
    serde_json::from_slice(&body_bytes(response).await).expect("response is JSON")
}

fn total_cell(document: &Value, period: &str) -> u64 {
    document["cells"]
        .as_array()
        .expect("cells are an array")
        .iter()
        .find(|cell| cell["period"] == period && cell["dimensions"]["category"] == "_T")
        .and_then(|cell| cell["value"].as_u64())
        .expect("period total cell is present")
}

fn month_code(date: NaiveDate) -> String {
    format!("{:04}-{:02}", date.year(), date.month())
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

// SPDX-License-Identifier: Apache-2.0
#![cfg(all(feature = "postgres-test", feature = "tooling"))]

#[path = "support/pilot_acceptance_harness.rs"]
#[allow(dead_code)]
mod pilot_acceptance_harness;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, Response, StatusCode};
use chrono::{Days, Utc};
use pilot_acceptance_harness::{response_json, PilotHarness};
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::audit::RegistryAudit;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordReadService, PostgresStatisticsService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_breg::statistics::{current_period, PeriodGranularity};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tower::Service as _;
use zeroize::Zeroizing;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn facility_statistics_match_count_twins_and_release_evaluation_date() {
    let harness = PilotHarness::start("facility").await;
    let today = Utc::now().date_naive();
    let current = current_period(PeriodGranularity::Month, today).unwrap();
    let prior_date = current.start.checked_sub_days(Days::new(1)).unwrap();
    let prior = current_period(PeriodGranularity::Month, prior_date).unwrap();
    let expiry = prior
        .reference_date
        .checked_add_days(Days::new(91))
        .unwrap();
    assert!(
        expiry
            > prior
                .reference_date
                .checked_add_days(Days::new(90))
                .unwrap()
    );
    assert!(expiry <= today.checked_add_days(Days::new(90)).unwrap());
    let north = harness.token_with_scopes(
        "facility-registry",
        &[("administrative_boundaries", json!(["north-district"]))],
        &["registry:facility:operate"],
    );
    let south = harness.token_with_scopes(
        "facility-registry",
        &[("administrative_boundaries", json!(["south-district"]))],
        &["registry:facility:operate"],
    );
    let publisher =
        harness.token_with_scopes("statistics", &[], &["registry:facility:statistics:publish"]);
    let reader =
        harness.token_with_scopes("statistics", &[], &["registry:facility:statistics:read"]);
    let mut first_north_permit = String::new();
    for (boundary, token) in [("north-district", &north), ("south-district", &south)] {
        let facility = create(&harness,"facilities",token,&format!("facility-{boundary}"),json!({
            "facilityCode":format!("F-{boundary}"),"displayName":boundary,"administrativeBoundary":boundary
        })).await;
        for index in 0..5 {
            let permit = create(&harness,"permits",token,&format!("permit-{boundary}-{index}"),json!({
                "permitNumber":format!("P-{boundary}-{index}"),"facility":facility,
                "permitType":"water-discharge","validFrom":"2025-01-01","validTo":expiry.to_string(),
                "administrativeBoundary":boundary,"importSource":"statistics-test",
                "sourceRecordId":format!("{boundary}-{index}")
            })).await;
            if boundary == "north-district" && index == 0 {
                first_north_permit = permit;
            }
        }
        if boundary == "north-district" {
            // Both boundary cases must be absent from current stock, including margins.
            for (suffix, from, until) in [
                (
                    "expired",
                    "2025-01-01".to_owned(),
                    Some(prior.reference_date.to_string()),
                ),
                ("future", current.end.to_string(), None),
            ] {
                create(&harness,"permits",token,&format!("permit-{suffix}"),json!({
                    "permitNumber":format!("P-{suffix}"),"facility":facility,"permitType":"water-discharge",
                    "validFrom":from,"validTo":until,"administrativeBoundary":boundary,
                    "importSource":"statistics-test","sourceRecordId":suffix
                })).await;
            }
        }
    }
    let mut stock_documents = Vec::new();
    for dataset in [
        "monthly-valid-permits-temporal",
        "monthly-valid-permits-fields",
    ] {
        let live = get(
            &harness,
            &format!(
                "/v1/statistics/{dataset}:live?accessProfile=facility-operator&from={0}&to={0}",
                current.code
            ),
            &north,
        )
        .await;
        assert_count_twins(
            &harness,
            &north,
            if dataset.ends_with("temporal") { "permits:as-of" } else { "permits" },
            &live,
            &format!(
                "permitType ne null and validFrom le '{0}' and (validTo eq null or validTo gt '{0}')",
                current.reference_date
            ),
        )
        .await;
        assert_eq!(cell(&live, "north-district", "true")["value"], 5);
        assert_eq!(cell(&live, "south-district", "_T")["value"], 0);
        let south_live = get(
            &harness,
            &format!("/v1/statistics/{dataset}:live?accessProfile=facility-operator"),
            &south,
        )
        .await;
        assert_eq!(cell(&south_live, "north-district", "_T")["value"], 0);
        assert_eq!(cell(&south_live, "south-district", "true")["value"], 5);
        let past = harness
            .send(
                Method::GET,
                &format!(
                    "/v1/statistics/{dataset}:live?accessProfile=facility-operator&from={0}&to={0}",
                    prior.code
                ),
                Some(&north),
                &[],
                Vec::new(),
            )
            .await;
        assert_eq!(past.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(past).await["code"], "query.invalid");
        stock_documents.push(live);
        let published=harness.send_json(Method::POST,&format!("/v1/statistics/{dataset}/releases/{}/versions?accessProfile=statistics-publisher",prior.code),Some(&publisher),Some(&format!("publish-{dataset}")),json!({"status":"final"})).await;
        assert_eq!(
            published.status(),
            StatusCode::CREATED,
            "{}",
            response_json(published).await
        );
        let released = get(
            &harness,
            &format!(
                "/v1/statistics/{dataset}/releases/{}?accessProfile=statistics-reader",
                prior.code
            ),
            &reader,
        )
        .await;
        // Publication evaluates the derived dimension at the prior reference date,
        // not today: the five permits move from the true cell to the false cell.
        assert_eq!(cell(&released, "north-district", "false")["value"], 5);
        assert_eq!(cell(&released, "north-district", "true")["value"], 0);
        assert_eq!(cell(&released, "south-district", "false")["value"], 5);
        assert_eq!(
            released["periods"][0]["referenceDate"],
            prior.reference_date.to_string()
        );
    }
    assert_eq!(stock_documents[0]["cells"], stock_documents[1]["cells"]);
    let installation=create(&harness,"installations",&north,"installation",json!({
        "installationCode":"I-STATS","permit":first_north_permit,"administrativeBoundary":"north-district",
        "centroid":{"type":"Point","coordinates":[30.5,-9.5]},"areaValue":"1.0000","areaUnit":"hectare",
        "importSource":"statistics-test","sourceRecordId":"installation"
    })).await;
    for (index, quantity) in [(0, Some("5.000")), (1, None)] {
        let mut data = json!({"installation":installation,"administrativeBoundary":"north-district",
            "substanceCode":"nitrogen","periodStart":prior.start.checked_add_days(Days::new(index)).unwrap().to_string(),
            "periodEnd":prior.start.checked_add_days(Days::new(index + 1)).unwrap().to_string()});
        if let Some(quantity) = quantity {
            data["quantityValue"] = json!(quantity);
            data["quantityUnit"] = json!("kilogram");
        }
        create(
            &harness,
            "discharge-reports",
            &north,
            &format!("discharge-{index}"),
            data,
        )
        .await;
    }
    let flow=get(&harness,&format!("/v1/statistics/monthly-discharge-reports:live?accessProfile=facility-operator&from={0}&to={0}",prior.code),&north).await;
    assert_count_twins(
        &harness,
        &north,
        "discharge-reports",
        &flow,
        &format!(
            "substanceCode ne null and periodStart ge '{}' and periodStart lt '{}'",
            prior.start, prior.end
        ),
    )
    .await;
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_vocabulary_population_matches_the_authorized_list_count() {
    let database = postgres_harness::TestDatabase::create(3).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(partial_text_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: "statistics-partial-text-registry",
            database_id: "statistics-partial-text-database",
            label: "package-statistics-partial-text-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    migration_task.abort();

    let today = Utc::now().date_naive();
    let period = current_period(PeriodGranularity::Month, today).expect("current month resolves");
    seed_partial_text_permits(&database, &compiled, period.start, &identity.activation_id).await;
    let app = partial_text_router(
        database.runtime_config.build_pool().expect("pool builds"),
        compiled,
        identity,
        RegistryLockKey::derive("statistics-partial-text-registry").expect("lock key derives"),
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x62; 32].into())
                .expect("audit profile is keyed"),
        ),
    );
    let claims = partial_text_claims();
    let population = "startswith(permitType,'a')";
    let period_filter = format!(
        "{population} and validFrom ge '{}' and validFrom lt '{}'",
        period.start, period.end
    );
    let encoded_filter: String = period_filter
        .bytes()
        .map(|byte| format!("%{byte:02X}"))
        .collect();
    let counted = partial_text_json(
        partial_text_send(
            &app,
            Method::GET,
            &format!(
                "/v1/records/permits?accessProfile=facility-operator&$count=true&$top=1&$filter={encoded_filter}"
            ),
            claims.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(counted["count"], 2);

    let statistics = partial_text_json(
        partial_text_send(
            &app,
            Method::GET,
            &format!(
                "/v1/statistics/monthly-air-permits:live?accessProfile=facility-operator&from={0}&to={0}",
                period.code
            ),
            claims,
        )
        .await,
    )
    .await;
    assert_eq!(statistics["dataset"]["population"], population);
    let total = statistics["cells"]
        .as_array()
        .expect("statistics cells are an array")
        .iter()
        .find(|cell| cell["dimensions"]["administrative-boundary"] == "_T")
        .expect("total cell exists");
    assert_eq!(total["value"], counted["count"]);
    assert_eq!(total["value"], 2);
    database.cleanup().await;
}

fn partial_text_registry() -> registry_breg::CompiledRegistry {
    let source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1",
        "kind":"RegistryProject",
        "registry":{
            "id":"statistics-partial-text-registry","version":"1","defaultLanguage":"en",
            "canonicalBaseIri":"https://statistics-partial-text.example.test"
        },
        "entities":[{
            "id":"permit","primaryDataset":"facility","route":"permits","mutationMode":"mutable",
            "fields":[
                {"id":"permit-type","type":"vocabulary-code","vocabulary":"permit-type","required":true,"classification":"internal"},
                {"id":"valid-from","type":"date","required":true,"classification":"internal"},
                {"id":"administrative-boundary","type":"vocabulary-code","vocabulary":"administrative-boundary","required":true,"classification":"internal"}
            ]
        }],
        "accessProfiles":[{
            "id":"facility-operator","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":[{
                "entity":"permit","operations":["list"],
                "readableFields":["permit-type","valid-from","administrative-boundary"],
                "filterableFields":["permit-type","valid-from","administrative-boundary"],
                "allowCount":true,
                "rowBoundaries":[{"field":"administrative-boundary","claim":"administrative_boundaries","operator":"in"}]
            }]
        }],
        "vocabularies":[
            {"id":"permit-type","values":["air-emissions","water-discharge"]},
            {"id":"administrative-boundary","values":["north-district","south-district"]}
        ],
        "statisticalDatasets":[{
            "id":"monthly-air-permits","unit":"permit","population":"startswith(permitType,'a')",
            "period":{"type":"flow","field":"valid-from","granularity":"month","firstPeriod":"2025-01"},
            "dimensions":["administrative-boundary"],
            "disclosure":{"minimumCount":2,"roundingBase":2},
            "live":["facility-operator"]
        }]
    });
    let bytes = serde_json::to_vec(&source).expect("partial-text fixture serializes");
    let project = parse_project_json(&bytes).expect("partial-text fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("partial-text statistical population compiles")
}

async fn seed_partial_text_permits(
    database: &postgres_harness::TestDatabase,
    registry: &registry_breg::CompiledRegistry,
    valid_from: chrono::NaiveDate,
    active_package_revision: &str,
) {
    let entity = &registry.entities()["permit"];
    let table = quote_stock_identifier(&entity.physical_table);
    let permit_type = quote_stock_identifier(&entity.fields["permit-type"].physical_name);
    let from = quote_stock_identifier(&entity.fields["valid-from"].physical_name);
    let boundary = quote_stock_identifier(&entity.fields["administrative-boundary"].physical_name);
    let sql = format!(
        "INSERT INTO registry_data.{table}
             (record_id, record_revision, record_lifecycle, active_package_revision,
              {permit_type}, {from}, {boundary})
         VALUES ($1::text::uuid, 1, 'active', $5, $2, $3, $4)"
    );
    for (id, kind, jurisdiction) in [
        (
            "00000000-0000-4000-8000-000000000101",
            "air-emissions",
            "north-district",
        ),
        (
            "00000000-0000-4000-8000-000000000102",
            "air-emissions",
            "north-district",
        ),
        (
            "00000000-0000-4000-8000-000000000103",
            "water-discharge",
            "north-district",
        ),
        (
            "00000000-0000-4000-8000-000000000104",
            "air-emissions",
            "south-district",
        ),
    ] {
        database
            .admin
            .execute(
                &sql,
                &[
                    &id,
                    &kind,
                    &valid_from,
                    &jurisdiction,
                    &active_package_revision,
                ],
            )
            .await
            .expect("partial-text permit fixture inserts");
    }
}

fn partial_text_router(
    pool: registry_breg::postgres::RuntimePool,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    audit: RegistryAudit,
) -> axum::Router {
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x63; 32]), Duration::from_secs(300))
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
            Arc::new(PartialTextReady),
            cursors,
        )
        .with_statistics(statistics),
    ))
}

fn partial_text_claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "principal",
        "partial-text-count-twin",
        BTreeSet::new(),
        None,
        BTreeMap::from([(
            "administrative_boundaries".to_owned(),
            VerifiedClaimValue::direct_string_set(["north-district"])
                .expect("boundary claim is a verified string set"),
        )]),
    )
    .expect("partial-text claims are valid")
}

async fn partial_text_send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: VerifiedRequestClaims,
) -> Response<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .expect("partial-text request builds");
    request.extensions_mut().insert(claims);
    let mut app = app.clone();
    app.call(request).await.expect("router returns a response")
}

async fn partial_text_json(response: Response<Body>) -> Value {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("partial-text response reads");
    let value: Value = serde_json::from_slice(&bytes).expect("partial-text response is JSON");
    assert_eq!(status, StatusCode::OK, "{value}");
    value
}

fn quote_stock_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

struct PartialTextReady;

impl ReadinessProbe for PartialTextReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

async fn create(
    harness: &PilotHarness,
    collection: &str,
    token: &str,
    key: &str,
    data: Value,
) -> String {
    let response = harness
        .send_json(
            Method::POST,
            &format!("/v1/records/{collection}?accessProfile=facility-operator"),
            Some(token),
            Some(key),
            json!({"data":data}),
        )
        .await;
    let status = response.status();
    let value = response_json(response).await;
    assert_eq!(status, StatusCode::CREATED, "{collection} {key}: {value}");
    value["data"]["recordIdentifier"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn get(harness: &PilotHarness, uri: &str, token: &str) -> Value {
    let response = harness
        .send(Method::GET, uri, Some(token), &[], Vec::new())
        .await;
    let status = response.status();
    let value = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    value
}

fn cell<'a>(document: &'a Value, boundary: &str, boolean: &str) -> &'a Value {
    document["cells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|cell| {
            cell["dimensions"]["administrative-boundary"] == boundary
                && cell["dimensions"]["expiring-soon"] == boolean
        })
        .unwrap()
}

async fn assert_count_twins(
    harness: &PilotHarness,
    token: &str,
    collection: &str,
    document: &Value,
    population: &str,
) {
    let unit = document["dataset"]["unit"].as_str().unwrap();
    let entity = &harness.registry.entities()[unit];
    for cell in document["cells"].as_array().unwrap() {
        let mut filter = population.to_owned();
        for (field, code) in cell["dimensions"].as_object().unwrap() {
            let code = code.as_str().unwrap();
            if code == "_T" {
                continue;
            }
            let api = &entity
                .stored_fields
                .iter()
                .map(|field| &field.logical)
                .chain(entity.derived_fields.values().map(|field| &field.logical))
                .find(|candidate| candidate.id == *field)
                .unwrap()
                .api_name;
            let literal = match code {
                "_U" => "null".to_owned(),
                "true" | "false" => code.to_owned(),
                _ => format!("'{}'", code.replace('\'', "''")),
            };
            filter.push_str(&format!(" and {api} eq {literal}"));
        }
        let encoded_filter: String = filter.bytes().map(|byte| format!("%{byte:02X}")).collect();
        let mut query =
            format!("accessProfile=facility-operator&$count=true&$top=1&$filter={encoded_filter}");
        if collection.ends_with(":as-of") {
            query.push_str(&format!(
                "&asOf={}T00:00:00Z",
                document["periods"][0]["referenceDate"].as_str().unwrap()
            ));
        }
        let counted = get(harness, &format!("/v1/records/{collection}?{query}"), token).await;
        assert_eq!(cell["value"], counted["count"], "{filter}");
    }
}

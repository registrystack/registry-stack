// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use registry_breg::compiler::{compile_project, compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_json, ModuleAssetSource};
#[cfg(feature = "runtime")]
use registry_breg::package::{compiled_registry_change_set, CompiledRegistryChangeCode};
#[cfg(all(feature = "runtime", feature = "tooling"))]
use registry_breg::tooling::{classify_registry_diff, DiffClassification};
use serde_json::{json, Value};

fn source() -> Value {
    serde_json::from_value(json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {
            "id": "statistics-test",
            "version": "1",
            "defaultLanguage": "en",
            "canonicalBaseIri": "https://statistics.example.test"
        },
        "entities": [{
            "id": "record",
            "primaryDataset": "statistics-test",
            "route": "records",
            "mutationMode": "mutable",
            "fields": [
                {"id":"active","type":"boolean","required":true,"classification":"internal"},
                {"id":"category","type":"vocabulary-code","vocabulary":"category","required":true,"classification":"internal"},
                {"id":"event-date","type":"date","required":true,"classification":"internal"},
                {"id":"valid-from","type":"date","required":true,"classification":"internal"},
                {"id":"valid-to","type":"date","classification":"internal"}
            ],
            "temporal": {"startField":"valid-from","endField":"valid-to"}
        }],
        "accessProfiles": [
            {
                "id":"analyst","principalClaim":"principal","permissions":[{
                    "entity":"record","operations":["list"],
                    "readableFields":["active","category","event-date","valid-from","valid-to"],
                    "filterableFields":["active","category","event-date","valid-from","valid-to"],
                    "allowCount":true,"rowBoundaries":[]
                }]
            },
            {
                "id":"publisher","principalClaim":"principal","permissions":[{
                    "entity":"record","operations":["list"],
                    "readableFields":["active","category","event-date","valid-from","valid-to"],
                    "filterableFields":["active","category","event-date","valid-from","valid-to"],
                    "allowCount":true,"rowBoundaries":[]
                }]
            },
            {"id":"reader","principalClaim":"principal","permissions":[]},
            {"id":"other-reader","principalClaim":"principal","permissions":[]}
        ],
        "vocabularies": [{"id":"category","values":["a","b"]}],
        "statisticalDatasets": [{
            "id":"records-by-category",
            "unit":"record",
            "population":"active eq true",
            "period":{"kind":"flow","field":"event-date","granularity":"month","firstPeriod":"2025-01"},
            "dimensions":["category"],
            "disclosure":{"minimumCount":5,"roundingBase":5},
            "live":["analyst"],
            "releases":{"publisher":"publisher","readers":["reader"]}
        }]
    }))
    .expect("fixture is JSON")
}

fn compile(
    value: &Value,
) -> Result<registry_breg::CompiledRegistry, registry_breg::diagnostics::CompileFailure> {
    let bytes = serde_json::to_vec(value).expect("fixture serializes");
    let project = parse_project_json(&bytes).expect("fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
}

fn compile_with_sql(
    value: &Value,
    sql: &str,
) -> Result<registry_breg::CompiledRegistry, registry_breg::diagnostics::CompileFailure> {
    let bytes = serde_json::to_vec(value).expect("fixture serializes");
    let project = parse_project_json(&bytes).expect("fixture parses");
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "sql/statistics.sql".to_owned(),
            bytes: sql.as_bytes().to_vec(),
        }],
        CompileProfile::Authoring,
    )
}

fn artifact_json(compiled: &registry_breg::CompiledRegistry, path: &str) -> Value {
    serde_json::from_slice(
        &compiled
            .artifacts()
            .get(path)
            .unwrap_or_else(|| panic!("missing artifact {path}"))
            .bytes,
    )
    .unwrap_or_else(|error| panic!("artifact {path} is JSON: {error}"))
}

fn assert_refused(mutator: impl FnOnce(&mut Value), code: &str) {
    let mut value = source();
    mutator(&mut value);
    let failure = compile(&value).expect_err("invalid statistical dataset is refused");
    assert!(
        failure.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == code
                && diagnostic
                    .message
                    .contains("statistical dataset `records-by-category`")
        }),
        "missing {code}: {:?}",
        failure.diagnostics()
    );
}

#[test]
fn statistical_dataset_compiles_with_release_reader_authentication() {
    let compiled = compile(&source()).expect("statistical dataset compiles");
    let dataset = &compiled.statistical_datasets()["records-by-category"];
    assert_eq!(dataset.unit_entity_id, "record");
    assert_eq!(
        dataset.referenced_fields,
        BTreeSet::from([
            "active".to_owned(),
            "category".to_owned(),
            "event-date".to_owned(),
        ])
    );
    assert_eq!(
        dataset.dependency_entities,
        BTreeSet::from(["record".to_owned()])
    );
    assert_eq!(
        dataset.access_profiles["reader"].principal_claim.as_deref(),
        Some("principal")
    );
    assert!(dataset.access_profiles["reader"].operations.is_empty());
    assert!(dataset.definition_digest.starts_with("sha256:"));
}

#[test]
fn statistical_dataset_core_refusals_are_stable_and_actionable() {
    let cases: Vec<(Box<dyn FnOnce(&mut Value)>, &str)> = vec![
        (
            Box::new(|v| v["statisticalDatasets"][0]["unit"] = json!("missing")),
            "statistical_dataset.unit.unknown",
        ),
        (
            Box::new(|v| v["statisticalDatasets"][0]["population"] = json!("active = true")),
            "statistical_dataset.population.invalid",
        ),
        (
            Box::new(|v| v["statisticalDatasets"][0]["period"]["field"] = json!("missing")),
            "statistical_dataset.field.unknown",
        ),
        (
            Box::new(|v| v["statisticalDatasets"][0]["period"]["field"] = json!("category")),
            "statistical_dataset.period.field_type",
        ),
        (
            Box::new(|v| v["statisticalDatasets"][0]["dimensions"] = json!(["event-date"])),
            "statistical_dataset.dimension.type",
        ),
        (
            Box::new(|v| {
                v["statisticalDatasets"][0]["dimensions"] = json!(["category", "category"])
            }),
            "statistical_dataset.dimension.duplicate",
        ),
        (
            Box::new(|v| v["statisticalDatasets"][0]["disclosure"]["minimumCount"] = json!(1)),
            "statistical_dataset.disclosure.minimum_count",
        ),
        (
            Box::new(|v| v["statisticalDatasets"][0]["disclosure"]["roundingBase"] = json!(1)),
            "statistical_dataset.disclosure.rounding_base",
        ),
        (
            Box::new(|v| {
                v["statisticalDatasets"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("disclosure");
            }),
            "statistical_dataset.disclosure.missing",
        ),
        (
            Box::new(|v| v["statisticalDatasets"][0]["live"] = json!(["analyst", "analyst"])),
            "statistical_dataset.profile.duplicate",
        ),
        (
            Box::new(|v| v["statisticalDatasets"][0]["releases"]["readers"] = json!([])),
            "statistical_dataset.releases.readers_empty",
        ),
        (
            Box::new(|v| {
                v["statisticalDatasets"][0]["live"] = json!([]);
                v["statisticalDatasets"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("releases");
            }),
            "statistical_dataset.grants.empty",
        ),
        (
            Box::new(|v| {
                v["accessProfiles"][0]["anonymous"] = json!(true);
                v["accessProfiles"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("principalClaim");
                v["entities"][0]["classification"] = json!("public");
                for field in v["entities"][0]["fields"].as_array_mut().unwrap() {
                    field["classification"] = json!("public");
                }
            }),
            "statistical_dataset.profile.anonymous",
        ),
        (
            Box::new(|v| v["accessProfiles"][0]["permissions"][0]["allowCount"] = json!(false)),
            "statistical_dataset.count_grant.count_required",
        ),
        (
            Box::new(|v| {
                v["accessProfiles"][0]["permissions"][0]["operations"] = json!(["snapshot"])
            }),
            "statistical_dataset.count_grant.list_required",
        ),
        (
            Box::new(|v| {
                v["accessProfiles"][0]["permissions"][0]["filterableFields"] =
                    json!(["active", "category"])
            }),
            "statistical_dataset.count_grant.field_not_filterable",
        ),
        (
            Box::new(|v| v["accessProfiles"][1]["requiredPurposes"] = json!(["reporting"])),
            "statistical_dataset.publisher.caller_dependent",
        ),
        (
            Box::new(|v| {
                v["accessProfiles"][1]["permissions"][0]["rowBoundaries"] =
                    json!([{"field":"category","claim":"categories","operator":"in"}])
            }),
            "statistical_dataset.publisher.caller_dependent",
        ),
    ];
    for (mutator, code) in cases {
        assert_refused(mutator, code);
    }
}

#[test]
fn temporal_and_pair_stock_compile_and_timestamp_period_is_refused() {
    for validity in [
        json!("temporal"),
        json!({"from":"valid-from","until":"valid-to"}),
    ] {
        let mut value = source();
        value["statisticalDatasets"][0]["period"] = json!({
            "kind":"stock","granularity":"month","firstPeriod":"2025-01","validity":validity
        });
        compile(&value).expect("stock validity compiles");
    }
    assert_refused(
        |value| value["entities"][0]["fields"][2]["type"] = json!("timestamp"),
        "statistical_dataset.period.field_type",
    );
}

#[test]
fn definition_digest_excludes_grants_and_first_period_but_covers_values() {
    let baseline = compile(&source()).expect("baseline compiles");
    let baseline_digest = &baseline.statistical_datasets()["records-by-category"].definition_digest;

    let mut grant_change = source();
    grant_change["statisticalDatasets"][0]["live"] = json!(["publisher"]);
    grant_change["statisticalDatasets"][0]["releases"]["readers"] = json!(["other-reader"]);
    grant_change["statisticalDatasets"][0]["period"]["firstPeriod"] = json!("2024-01");
    let compiled = compile(&grant_change).expect("grant-only changes compile");
    assert_eq!(
        baseline_digest,
        &compiled.statistical_datasets()["records-by-category"].definition_digest
    );

    let mut population_change = source();
    population_change["statisticalDatasets"][0]["population"] = json!("active ne false");
    let compiled = compile(&population_change).expect("population change compiles");
    assert_ne!(
        baseline_digest,
        &compiled.statistical_datasets()["records-by-category"].definition_digest
    );
}

#[test]
fn population_uses_api_field_names_and_refuses_invalid_typed_predicates() {
    let mut value = source();
    value["entities"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"long-name","type":"boolean","required":true,"classification":"internal"
        }));
    for profile in [0_usize, 1] {
        for member in ["readableFields", "filterableFields"] {
            value["accessProfiles"][profile]["permissions"][0][member]
                .as_array_mut()
                .unwrap()
                .push(json!("long-name"));
        }
    }
    value["statisticalDatasets"][0]["population"] = json!("longName eq true");
    let compiled = compile(&value).expect("camel-case API field compiles");
    assert!(compiled.statistical_datasets()["records-by-category"]
        .referenced_fields
        .contains("long-name"));

    for population in ["active lt true", "active eq 1", "category eq 'missing'"] {
        assert_refused(
            |value| value["statisticalDatasets"][0]["population"] = json!(population),
            "statistical_dataset.population.invalid",
        );
    }
}

#[test]
fn generated_artifacts_cover_the_effective_model_metadata_and_seven_routes() {
    let compiled = compile(&source()).expect("statistical dataset compiles");
    let effective = artifact_json(&compiled, "compiled/effective-model.json");
    assert_eq!(
        effective["statisticalDatasets"]["records-by-category"]["definitionDigest"],
        compiled.statistical_datasets()["records-by-category"].definition_digest
    );
    assert!(compiled
        .artifacts()
        .get("compiled/statistical-datasets.json")
        .is_some());

    let metadata = artifact_json(&compiled, "generated/metadata/registry.json");
    let dataset = &metadata["statisticalDatasets"][0];
    assert_eq!(dataset["dimensions"][0]["vocabulary"], "category");
    assert_eq!(
        dataset["accessProfiles"]["reader"],
        json!([
            "list_releases",
            "read_latest_release",
            "read_release_version",
            "read_released_series"
        ])
    );

    let openapi = artifact_json(&compiled, "generated/openapi.json");
    let statistical_paths = openapi["paths"]
        .as_object()
        .unwrap()
        .keys()
        .filter(|path| path.starts_with("/v1/statistics/"))
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        statistical_paths,
        BTreeSet::from([
            "/v1/statistics/records-by-category:live".to_owned(),
            "/v1/statistics/records-by-category/releases".to_owned(),
            "/v1/statistics/records-by-category/releases:series".to_owned(),
            "/v1/statistics/records-by-category/releases/{period}".to_owned(),
            "/v1/statistics/records-by-category/releases/{period}/versions".to_owned(),
            "/v1/statistics/records-by-category/releases/{period}/versions/{version}".to_owned(),
            "/v1/statistics/records-by-category/releases/{period}/versions/{version}/withdrawal"
                .to_owned(),
        ])
    );
    assert_eq!(
        openapi["paths"]["/v1/statistics/records-by-category/releases:series"]["get"]["parameters"]
            [2]["required"],
        true
    );
    assert_eq!(
        openapi["paths"]
            ["/v1/statistics/records-by-category/releases/{period}/versions/{version}/withdrawal"]
            ["post"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/StatisticalWithdrawalResponse"
    );
}

#[test]
fn generated_openapi_omits_undeclared_statistical_route_families() {
    let mut live_only = source();
    live_only["statisticalDatasets"][0]
        .as_object_mut()
        .unwrap()
        .remove("releases");
    let compiled = compile(&live_only).expect("live-only dataset compiles");
    let openapi = artifact_json(&compiled, "generated/openapi.json");
    assert!(openapi["paths"]
        .as_object()
        .unwrap()
        .keys()
        .filter(|path| path.starts_with("/v1/statistics/"))
        .all(|path| path.ends_with(":live")));

    let mut released_only = source();
    released_only["statisticalDatasets"][0]["live"] = json!([]);
    let compiled = compile(&released_only).expect("released-only dataset compiles");
    let openapi = artifact_json(&compiled, "generated/openapi.json");
    assert!(!openapi["paths"]
        .as_object()
        .unwrap()
        .contains_key("/v1/statistics/records-by-category:live"));
}

#[test]
#[cfg(feature = "runtime")]
fn package_diff_classifies_statistical_dataset_add_change_and_removal() {
    let with_dataset = compile(&source()).expect("dataset compiles");
    let mut without = source();
    without["statisticalDatasets"] = json!([]);
    let without_dataset = compile(&without).expect("registry without dataset compiles");

    let added = compiled_registry_change_set(&without_dataset, &with_dataset, "sha256:before");
    assert!(added
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::StatisticalDatasetAdded));
    let removed = compiled_registry_change_set(&with_dataset, &without_dataset, "sha256:before");
    assert!(removed
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::StatisticalDatasetRemoved));

    let mut changed_source = source();
    changed_source["statisticalDatasets"][0]["population"] = json!("active ne false");
    let changed_registry = compile(&changed_source).expect("changed dataset compiles");
    let changed = compiled_registry_change_set(&with_dataset, &changed_registry, "sha256:before");
    assert!(changed
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::StatisticalDatasetChanged));
}

#[test]
#[cfg(all(feature = "runtime", feature = "tooling"))]
fn tooling_classifies_statistical_grant_direction_and_definition_review() {
    let baseline = compile(&source()).expect("baseline compiles");
    let mut widened_source = source();
    widened_source["statisticalDatasets"][0]["releases"]["readers"] =
        json!(["reader", "other-reader"]);
    let widened = compile(&widened_source).expect("widened dataset compiles");
    let diff = classify_registry_diff(&baseline, &widened, "sha256:before");
    assert!(diff.changes.iter().any(|change| {
        change.change.code == CompiledRegistryChangeCode::StatisticalDatasetChanged
            && change.classification == DiffClassification::DisclosureWidening
    }));

    let diff = classify_registry_diff(&widened, &baseline, "sha256:before");
    assert!(diff.changes.iter().any(|change| {
        change.change.code == CompiledRegistryChangeCode::StatisticalDatasetChanged
            && change.classification == DiffClassification::DisclosureNarrowing
    }));

    let mut definition_source = source();
    definition_source["statisticalDatasets"][0]["population"] = json!("active ne false");
    let changed = compile(&definition_source).expect("definition change compiles");
    let diff = classify_registry_diff(&baseline, &changed, "sha256:before");
    assert!(diff.changes.iter().any(|change| {
        change.change.code == CompiledRegistryChangeCode::StatisticalDatasetChanged
            && change.classification == DiffClassification::AccessChange
    }));
}

#[test]
fn derived_dimension_records_entity_and_evaluation_date_dependencies() {
    let mut value = source();
    value["entities"][0]["derived"] = json!([{
        "id":"statistics","sql":"sql/statistics.sql","key":"id",
        "fields":[{"id":"evaluated-category","type":"vocabulary-code","vocabulary":"category","values":["a","b"],"classification":"internal"}]
    }]);
    value["entities"].as_array_mut().unwrap().push(json!({
        "id":"lookup","primaryDataset":"statistics-test","route":"lookups","mutationMode":"mutable",
        "fields":[{"id":"flag","type":"boolean","required":true,"classification":"internal"}]
    }));
    for profile in [0_usize, 1] {
        value["accessProfiles"][profile]["permissions"][0]["readableFields"]
            .as_array_mut()
            .unwrap()
            .push(json!("evaluated-category"));
        value["accessProfiles"][profile]["permissions"][0]["filterableFields"]
            .as_array_mut()
            .unwrap()
            .push(json!("evaluated-category"));
    }
    value["accessProfiles"][1]["permissions"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "entity":"lookup","operations":["list"],"readableFields":["flag"],
            "filterableFields":["flag"],"allowCount":true,"rowBoundaries":[]
        }));
    value["statisticalDatasets"][0]["dimensions"] = json!(["evaluated-category"]);
    let sql = "SELECT r.id AS id, CASE WHEN l.flag AND r.event_date <= registry_context.evaluation_date() THEN 'a' ELSE 'b' END AS evaluated_category FROM registry_source.record r JOIN registry_source.lookup l ON l.id = r.id";
    let compiled = compile_with_sql(&value, sql).expect("derived statistical dimension compiles");
    let dataset = &compiled.statistical_datasets()["records-by-category"];
    assert_eq!(
        dataset.dependency_entities,
        BTreeSet::from(["lookup".to_owned(), "record".to_owned()])
    );
    assert!(dataset.evaluation_date_dependent);
    let relation = &compiled.entities()["record"].derived_relations["statistics"];
    assert_eq!(
        relation.source_entities,
        BTreeSet::from(["lookup".to_owned(), "record".to_owned()])
    );
    assert!(relation.uses_evaluation_date);

    let changed_sql = sql.replace("THEN 'a'", "THEN 'b'");
    let changed = compile_with_sql(&value, &changed_sql).expect("changed SQL compiles");
    assert_ne!(
        dataset.definition_digest,
        changed.statistical_datasets()["records-by-category"].definition_digest
    );

    value["accessProfiles"][1]["requiredPurposes"] = json!(["caller-bound"]);
    let failure =
        compile_with_sql(&value, sql).expect_err("caller-dependent dependency is refused");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "statistical_dataset.publisher.caller_dependent"
            && diagnostic.message.contains("dependency entity `lookup`")
    }));
}

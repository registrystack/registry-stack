// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use registry_breg::compiler::{compile_project, compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_json, ModuleAssetSource};
#[cfg(feature = "runtime")]
use registry_breg::package::{
    compiled_registry_change_set, CompiledRegistryChangeClass, CompiledRegistryChangeCode,
};
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

fn source_with_swappable_population_fields() -> Value {
    let mut value = source();
    value["entities"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"archived","apiName":"archived","type":"boolean","required":true,
            "classification":"internal"
        }));
    value["entities"][0]["fields"][0]["apiName"] = json!("active");
    for profile in [0_usize, 1] {
        for member in ["readableFields", "filterableFields"] {
            value["accessProfiles"][profile]["permissions"][0][member]
                .as_array_mut()
                .unwrap()
                .push(json!("archived"));
        }
    }
    value["statisticalDatasets"][0]["population"] = json!("active eq true and archived eq false");
    value
}

fn swap_population_api_names(value: &mut Value) {
    value["entities"][0]["fields"][0]["apiName"] = json!("archived");
    value["entities"][0]["fields"][5]["apiName"] = json!("active");
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

type RefusalCase = (Box<dyn FnOnce(&mut Value)>, &'static str);

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
    let digest = dataset
        .definition_digest
        .strip_prefix("sha256:")
        .expect("definition digest uses the sha256 scheme");
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "definition digest is exactly sha256 followed by 64 lowercase hex characters"
    );
}

#[test]
fn statistical_dataset_core_refusals_are_stable_and_actionable() {
    let cases: Vec<RefusalCase> = vec![
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
                v["statisticalDatasets"][0]["disclosure"]["minimumCount"] =
                    json!(9_007_199_254_740_992_u64)
            }),
            "statistical_dataset.disclosure.minimum_count_exceeded",
        ),
        (
            Box::new(|v| {
                v["statisticalDatasets"][0]["disclosure"]["roundingBase"] =
                    json!(9_007_199_254_740_992_u64)
            }),
            "statistical_dataset.disclosure.rounding_base_exceeded",
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
fn statistical_dataset_refuses_anonymous_live_publisher_and_reader_profiles() {
    for profile_index in [0_usize, 1, 2] {
        assert_refused(
            |value| {
                value["accessProfiles"][profile_index]["anonymous"] = json!(true);
                value["accessProfiles"][profile_index]
                    .as_object_mut()
                    .unwrap()
                    .remove("principalClaim");
                value["entities"][0]["classification"] = json!("public");
                for field in value["entities"][0]["fields"].as_array_mut().unwrap() {
                    field["classification"] = json!("public");
                }
            },
            "statistical_dataset.profile.anonymous",
        );
    }
}

#[test]
fn statistical_dataset_refuses_caller_dependent_publisher_authority() {
    assert_refused(
        |value| {
            value["entities"][0]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "id":"organization","type":"reference","target":"organization",
                    "required":true,"classification":"internal"
                }));
            value["entities"].as_array_mut().unwrap().extend([
                json!({
                    "id":"organization","primaryDataset":"statistics-test","route":"organizations",
                    "mutationMode":"mutable","fields":[
                        {"id":"name","type":"string","maxLength":80,"classification":"internal"}
                    ]
                }),
                json!({
                    "id":"membership","primaryDataset":"statistics-test","route":"memberships",
                    "mutationMode":"mutable","classification":"restricted",
                    "fields":[
                        {"id":"organization","type":"reference","target":"organization","required":true,"classification":"internal"},
                        {"id":"principal","type":"string","maxLength":80,"required":true,"classification":"restricted"},
                        {"id":"active","type":"boolean","required":true,"classification":"internal"}
                    ],
                    "indexes":[{"id":"membership-principal-key","fields":["principal","organization","active"]}],
                    "accessRequirements":{"requiredScopes":["membership:use"]}
                }),
            ]);
            value["accessProfiles"][1]["requiredScopes"] = json!(["membership:use"]);
            value["accessProfiles"][1]["permissions"][0]["membershipBoundaries"] = json!([{
                "field":"organization","membershipEntity":"membership",
                "membershipKeyField":"organization","principalField":"principal","activeField":"active"
            }]);
        },
        "statistical_dataset.publisher.caller_dependent",
    );
    assert_refused(
        |value| {
            value["entities"][0]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "id":"target","type":"reference","target":"target-record",
                    "required":true,"classification":"internal"
                }));
            value["entities"][0]["changeRequest"] = json!({
                "effects":[{
                    "id":"apply-active","target":{"fromField":"target"},"operation":"patch",
                    "set":{"active":{"fromField":"active"}}
                }],
                "review":{"mode":"none"},"onApproved":{"mode":"manual"}
            });
            value["entities"].as_array_mut().unwrap().push(json!({
                "id":"target-record","primaryDataset":"statistics-test","route":"target-records",
                "mutationMode":"mutable","changeControl":{"requiredFor":["patch"]},
                "fields":[
                    {"id":"active","type":"boolean","required":true,"classification":"internal"}
                ]
            }));
            value["accessProfiles"][1]["permissions"][0]["requestVisibility"] = json!("owner");
        },
        "statistical_dataset.publisher.caller_dependent",
    );
    assert_refused(
        |value| {
            value["recipients"] = json!({
                "organizations":[{
                    "id":"publisher-organization","name":"Publisher organization",
                    "contact":"privacy@publisher.example.test","clients":["publisher-client"]
                }],
                "groups":[]
            });
            value["vocabularies"].as_array_mut().unwrap().extend([
                json!({"id":"data-use-purpose","values":["statistics"]}),
                json!({"id":"consent-decision","values":["given","refused","withdrawn"]}),
            ]);
            value["entities"].as_array_mut().unwrap().push(json!({
                "id":"consent-decision","primaryDataset":"statistics-test",
                "route":"consent-decisions","mutationMode":"create_only","classification":"restricted",
                "fields":[
                    {"id":"subject","type":"reference","target":"record","required":true,"classification":"restricted"},
                    {"id":"recipient","type":"vocabulary-code","vocabulary":"registry-recipients","required":true,"classification":"internal"},
                    {"id":"purpose","type":"vocabulary-code","vocabulary":"data-use-purpose","required":true,"classification":"internal"},
                    {"id":"scope","type":"vocabulary-code","vocabulary":"registry-consent-scopes","required":true,"classification":"internal"},
                    {"id":"decision","type":"vocabulary-code","vocabulary":"consent-decision","required":true,"classification":"internal"},
                    {"id":"effective-at","type":"timestamp","required":true,"classification":"internal"},
                    {"id":"expires-at","type":"timestamp","classification":"internal"}
                ],
                "consentRecord":{
                    "subject":"subject","recipient":"recipient","purpose":"purpose","scope":"scope",
                    "decision":{"field":"decision","gives":["given"],"revokes":["refused","withdrawn"],"refusals":["refused"]},
                    "validity":{"from":"effective-at","until":"expires-at","maxDuration":"P365D"}
                }
            }));
            value["accessProfiles"][1]["actorKind"] = json!("service");
            value["accessProfiles"][1]["requesterClients"] = json!(["publisher-client"]);
            value["accessProfiles"][1]["requiredPurposes"] = json!(["statistics"]);
            value["accessProfiles"][1]["permissions"][0]["requireConsent"] =
                json!([{"record":"consent-decision","on":"id"}])
        },
        "statistical_dataset.count_grant.consent",
    );
    assert_refused(
        |value| {
            let boundary = json!({"field":"category","claim":"categories","operator":"in"});
            value["entities"][0]["accessRequirements"] =
                json!({"rowBoundaries":[boundary.clone()]});
            for profile in [0_usize, 1] {
                value["accessProfiles"][profile]["permissions"][0]["rowBoundaries"] =
                    json!([boundary.clone()]);
            }
        },
        "statistical_dataset.publisher.entity_row_boundary",
    );
}

#[test]
fn statistical_dataset_refuses_encrypted_reserved_and_unbounded_dimensions() {
    assert_refused(
        |value| {
            value["entities"][0]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                        "id":"secret","type":"string","maxLength":80,"encrypted":true,
                        "classification":"restricted"
                }));
            for profile in [0_usize, 1] {
                value["accessProfiles"][profile]["permissions"][0]["readableFields"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("secret"));
            }
            value["statisticalDatasets"][0]["population"] =
                json!("active eq true and secret eq 'x'");
        },
        "statistical_dataset.field.encrypted",
    );
    assert_refused(
        |value| value["vocabularies"][0]["values"] = json!(["_reserved", "a"]),
        "statistical_dataset.dimension.code_reserved",
    );

    for id in ["period", "value", "status"] {
        assert_refused(
            |value| {
                value["entities"][0]["fields"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({
                        "id":id,"type":"boolean","required":true,"classification":"internal"
                    }));
                value["statisticalDatasets"][0]["dimensions"] = json!([id]);
            },
            "statistical_dataset.dimension.reserved",
        );
    }

    let codes = (0..100)
        .map(|index| format!("v{index:03}"))
        .collect::<Vec<_>>();
    assert_refused(
        |value| {
            value["vocabularies"][0]["values"] = json!(codes);
            value["vocabularies"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id":"category-two","values":codes}));
            value["entities"][0]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "id":"category-two","type":"vocabulary-code","vocabulary":"category-two",
                    "required":true,"classification":"internal"
                }));
            for profile in [0_usize, 1] {
                for member in ["readableFields", "filterableFields"] {
                    value["accessProfiles"][profile]["permissions"][0][member]
                        .as_array_mut()
                        .unwrap()
                        .push(json!("category-two"));
                }
            }
            value["statisticalDatasets"][0]["dimensions"] = json!(["category", "category-two"]);
        },
        "statistical_dataset.cells.exceeded",
    );
}

#[test]
fn statistical_dimension_reserved_names_follow_emitted_logical_field_ids() {
    let mut value = source();
    for id in ["period-start", "period-end"] {
        value["entities"][0]["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":id,"type":"boolean","required":true,"classification":"internal"
            }));
        for profile in [0_usize, 1] {
            for member in ["readableFields", "filterableFields"] {
                value["accessProfiles"][profile]["permissions"][0][member]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(id));
            }
        }
    }
    value["statisticalDatasets"][0]["dimensions"] = json!(["period-start", "period-end"]);
    let compiled = compile(&value).expect("logical dimension ids do not collide with CSV names");
    assert_eq!(
        compiled.statistical_datasets()["records-by-category"]
            .dimensions
            .iter()
            .map(|dimension| dimension.field.as_str())
            .collect::<Vec<_>>(),
        ["period-start", "period-end"]
    );

    assert_refused(
        |value| {
            value["entities"][0]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "id":"period","apiName":"dimensionPeriod","type":"boolean",
                    "required":true,"classification":"internal"
                }));
            value["statisticalDatasets"][0]["dimensions"] = json!(["period"]);
        },
        "statistical_dataset.dimension.reserved",
    );
}

#[test]
fn statistical_dataset_refuses_release_documents_over_the_eight_mibibyte_cap() {
    assert_refused(
        |value| {
            let mut dimensions = Vec::new();
            for index in 0..13 {
                let field = format!("dimension-{index:02}-{}", "x".repeat(51));
                let code = format!("code-{index:02}-{}", "x".repeat(120));
                value["vocabularies"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"id":field,"values":[code]}));
                value["entities"][0]["fields"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({
                        "id":field,"type":"vocabulary-code","vocabulary":field,
                        "required":true,"classification":"internal"
                    }));
                for profile in [0_usize, 1] {
                    for member in ["readableFields", "filterableFields"] {
                        value["accessProfiles"][profile]["permissions"][0][member]
                            .as_array_mut()
                            .unwrap()
                            .push(json!(field));
                    }
                }
                dimensions.push(field);
            }
            value["statisticalDatasets"][0]["dimensions"] = json!(dimensions);
        },
        "statistical_dataset.document.exceeded",
    );
}

#[test]
fn temporal_and_pair_stock_compile_and_invalid_periods_are_refused() {
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
    assert_refused(
        |value| value["statisticalDatasets"][0]["period"]["firstPeriod"] = json!("2025-13"),
        "statistical_dataset.period.first_period",
    );
    for (granularity, invalid_periods) in [
        (
            "day",
            ["0000-01-01", "-001-01-01", "2025-1-01", "9999-12-31"],
        ),
        ("month", ["0000-01", "-001-01", "2025-1", "9999-12"]),
        ("quarter", ["0000-Q1", "-001-Q1", "2025€", "9999-Q4"]),
        ("year", ["0000", "-001", "２０２５", "9999"]),
    ] {
        for invalid in invalid_periods {
            assert_refused(
                |value| {
                    value["statisticalDatasets"][0]["period"]["granularity"] = json!(granularity);
                    value["statisticalDatasets"][0]["period"]["firstPeriod"] = json!(invalid);
                },
                "statistical_dataset.period.first_period",
            );
        }
    }
    for (granularity, first_period) in [
        ("day", "9999-12-30"),
        ("month", "9999-11"),
        ("quarter", "9999-Q3"),
        ("year", "9998"),
    ] {
        let mut value = source();
        value["statisticalDatasets"][0]["period"]["granularity"] = json!(granularity);
        value["statisticalDatasets"][0]["period"]["firstPeriod"] = json!(first_period);
        compile(&value).expect("the latest period fitting the wire date domain compiles");
    }
    assert_refused(
        |value| {
            value["statisticalDatasets"][0]["period"] = json!({
                "kind":"stock","granularity":"month","firstPeriod":"2025-01","validity":"temporal"
            });
            value["entities"][0]
                .as_object_mut()
                .unwrap()
                .remove("temporal");
        },
        "statistical_dataset.period.temporal_missing",
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
fn definition_digest_binds_population_api_names_to_logical_fields() {
    let baseline_source = source_with_swappable_population_fields();
    let baseline = compile(&baseline_source).expect("two-field population compiles");

    let mut swapped_source = baseline_source.clone();
    swap_population_api_names(&mut swapped_source);
    let swapped = compile(&swapped_source).expect("swapped API names compile");

    let baseline_dataset = &baseline.statistical_datasets()["records-by-category"];
    let swapped_dataset = &swapped.statistical_datasets()["records-by-category"];
    assert_eq!(baseline_dataset.population, swapped_dataset.population);
    assert_eq!(
        baseline_dataset.referenced_fields,
        swapped_dataset.referenced_fields
    );
    assert_ne!(
        baseline_dataset.definition_digest, swapped_dataset.definition_digest,
        "the digest binds each authored API name to the logical field it selects"
    );
}

#[test]
fn definition_digest_binds_referenced_stored_field_definitions() {
    let mut baseline_source = source();
    baseline_source["entities"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .extend([
            json!({
                "id":"score","type":"int64","required":true,"classification":"internal"
            }),
            json!({
                "id":"unused-score","type":"int64","required":true,
                "classification":"internal"
            }),
        ]);
    for profile in [0_usize, 1] {
        for member in ["readableFields", "filterableFields"] {
            baseline_source["accessProfiles"][profile]["permissions"][0][member]
                .as_array_mut()
                .unwrap()
                .extend([json!("score"), json!("unused-score")]);
        }
    }
    baseline_source["statisticalDatasets"][0]["population"] = json!("score eq 1");
    let baseline = compile(&baseline_source).expect("integer population compiles");
    let baseline_digest = &baseline.statistical_datasets()["records-by-category"].definition_digest;

    let mut changed_type_source = baseline_source.clone();
    changed_type_source["entities"][0]["fields"][5] = json!({
        "id":"score","type":"text","maxLength":20,"required":true,
        "classification":"internal"
    });
    let changed_type = compile(&changed_type_source).expect("reviewable text successor compiles");
    assert_ne!(
        baseline_digest,
        &changed_type.statistical_datasets()["records-by-category"].definition_digest,
        "a compiled type change for a population field starts a new release series"
    );

    #[cfg(feature = "runtime")]
    assert!(
        compiled_registry_change_set(&baseline, &changed_type, "sha256:before")
            .changes
            .iter()
            .any(|change| {
                change.code == CompiledRegistryChangeCode::FieldTypeChanged
                    && change.class == CompiledRegistryChangeClass::DestructiveOrIrreversible
            })
    );

    let mut unrelated_type_source = baseline_source;
    unrelated_type_source["entities"][0]["fields"][6] = json!({
        "id":"unused-score","type":"decimal","precision":10,"scale":2,"required":true,
        "classification":"internal"
    });
    let unrelated_type =
        compile(&unrelated_type_source).expect("unreferenced decimal successor compiles");
    assert_eq!(
        baseline_digest,
        &unrelated_type.statistical_datasets()["records-by-category"].definition_digest,
        "an unrelated field definition does not hide the current release series"
    );
}

#[test]
fn definition_digest_binds_derived_output_and_exact_source_field_definitions() {
    let mut baseline_source = source();
    baseline_source["entities"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .extend([
            json!({
                "id":"amount","type":"int64","required":true,"classification":"internal"
            }),
            json!({
                "id":"unused-amount","type":"int64","required":true,
                "classification":"internal"
            }),
        ]);
    baseline_source["entities"][0]["derived"] = json!([{
        "id":"statistics-score","sql":"sql/statistics.sql","key":"id",
        "fields":[{
            "id":"score","type":"int64","classification":"internal"
        }]
    }]);
    for profile in [0_usize, 1] {
        for member in ["readableFields", "filterableFields"] {
            baseline_source["accessProfiles"][profile]["permissions"][0][member]
                .as_array_mut()
                .unwrap()
                .extend([json!("score"), json!("amount"), json!("unused-amount")]);
        }
    }
    baseline_source["statisticalDatasets"][0]["population"] = json!("score eq 1");
    let sql = "SELECT r.id AS id, CASE WHEN r.amount > 1 THEN 2 ELSE 0 END AS score FROM registry_source.record r";
    let baseline =
        compile_with_sql(&baseline_source, sql).expect("derived integer population compiles");
    let baseline_dataset = &baseline.statistical_datasets()["records-by-category"];
    let baseline_relation = &baseline.entities()["record"].derived_relations["statistics-score"];

    let mut changed_output_source = baseline_source.clone();
    changed_output_source["entities"][0]["derived"][0]["fields"][0] = json!({
        "id":"score","type":"text","maxLength":20,
        "classification":"internal"
    });
    let changed_output = compile_with_sql(&changed_output_source, sql)
        .expect("derived text output successor compiles");
    assert_eq!(
        baseline_relation.sql_sha256,
        changed_output.entities()["record"].derived_relations["statistics-score"].sql_sha256
    );
    assert_ne!(
        baseline_dataset.definition_digest,
        changed_output.statistical_datasets()["records-by-category"].definition_digest,
        "a referenced derived output declaration starts a new release series"
    );

    let mut changed_source_type = baseline_source.clone();
    changed_source_type["entities"][0]["fields"][5] = json!({
        "id":"amount","type":"decimal","precision":10,"scale":2,"required":true,
        "classification":"internal"
    });
    let changed_source_type = compile_with_sql(&changed_source_type, sql)
        .expect("derived source type successor compiles");
    assert_ne!(
        baseline_dataset.definition_digest,
        changed_source_type.statistical_datasets()["records-by-category"].definition_digest,
        "a stored field read by derived SQL starts a new release series"
    );

    let mut unrelated_source_type = baseline_source;
    unrelated_source_type["entities"][0]["fields"][6] = json!({
        "id":"unused-amount","type":"decimal","precision":10,"scale":2,"required":true,
        "classification":"internal"
    });
    let unrelated_source_type = compile_with_sql(&unrelated_source_type, sql)
        .expect("unreferenced derived source type successor compiles");
    assert_eq!(
        baseline_dataset.definition_digest,
        unrelated_source_type.statistical_datasets()["records-by-category"].definition_digest,
        "an unrelated source field does not hide the current release series"
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
fn population_in_list_refuses_values_the_runtime_would_read_as_duplicates() {
    let mut distinct = source();
    distinct["statisticalDatasets"][0]["population"] = json!("category in ('a','b')");
    compile(&distinct).expect("a list of distinct values compiles");

    // The runtime compares the text of each value, so a boolean and its
    // quoted spelling are one value.
    for population in ["category in ('a','a')", "active in (true,'true')"] {
        assert_refused(
            |value| value["statisticalDatasets"][0]["population"] = json!(population),
            "statistical_dataset.population.invalid",
        );
    }
}

#[test]
fn population_text_functions_use_partial_query_terms_with_runtime_bounds() {
    let mut vocabulary = source();
    vocabulary["vocabularies"][0]["values"] = json!(["alpha", "beta"]);
    vocabulary["statisticalDatasets"][0]["population"] = json!("startswith(category,'al')");
    compile(&vocabulary).expect("a partial vocabulary-code prefix compiles");

    let mut bounded_string = source();
    bounded_string["entities"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"label","type":"string","minLength":8,"maxLength":12,
            "required":true,"classification":"internal"
        }));
    for profile in [0_usize, 1] {
        for member in ["readableFields", "filterableFields"] {
            bounded_string["accessProfiles"][profile]["permissions"][0][member]
                .as_array_mut()
                .unwrap()
                .push(json!("label"));
        }
    }
    bounded_string["statisticalDatasets"][0]["population"] = json!("contains(label,'a')");
    compile(&bounded_string).expect("a search term shorter than the stored minLength compiles");

    let oversized = "a".repeat(registry_breg::query::MAX_LITERAL_BYTES + 1);
    for population in [
        "startswith(active,'t')".to_owned(),
        "startswith(category,1)".to_owned(),
        "contains(category,'line\nbreak')".to_owned(),
        format!("contains(category,'{oversized}')"),
    ] {
        assert_refused(
            |value| value["statisticalDatasets"][0]["population"] = json!(population),
            "statistical_dataset.population.invalid",
        );
    }

    bounded_string["statisticalDatasets"][0]["population"] =
        json!("contains(label,'thirteenchars')");
    let failure = compile(&bounded_string).expect_err("a term beyond maxLength is refused");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "statistical_dataset.population.invalid"));
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
    assert_eq!(
        dataset["accessProfiles"]["analyst"],
        json!([
            "list_releases",
            "read_latest_release",
            "read_live",
            "read_release_version",
            "read_released_series"
        ])
    );
    assert_eq!(
        dataset["accessProfiles"]["publisher"],
        json!([
            "list_releases",
            "publish_release",
            "read_latest_release",
            "read_release_version",
            "read_released_series",
            "withdraw_release"
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
        openapi["paths"]["/v1/statistics/records-by-category/releases:series"]["get"]
            ["x-registry-accessProfiles"],
        json!(["analyst", "publisher", "reader"])
    );
    let release_access_profile = &openapi["paths"]
        ["/v1/statistics/records-by-category/releases:series"]["get"]["parameters"][0];
    assert_eq!(release_access_profile["name"], "accessProfile");
    assert_eq!(release_access_profile["required"], true);
    assert!(release_access_profile["schema"].get("default").is_none());
    assert_eq!(
        openapi["paths"]["/v1/statistics/records-by-category/releases:series"]["get"]
            ["x-registry-defaultAccessProfile"],
        Value::Null
    );
    let live = &openapi["paths"]["/v1/statistics/records-by-category:live"]["get"];
    assert_eq!(live["parameters"][0]["required"], false);
    assert_eq!(live["parameters"][0]["schema"]["default"], "analyst");
    assert_eq!(live["x-registry-defaultAccessProfile"], "analyst");
    let publish =
        &openapi["paths"]["/v1/statistics/records-by-category/releases/{period}/versions"]["post"];
    assert_eq!(publish["parameters"][0]["required"], false);
    assert_eq!(publish["parameters"][0]["schema"]["default"], "publisher");
    assert_eq!(publish["x-registry-defaultAccessProfile"], "publisher");
    assert_eq!(
        openapi["paths"]
            ["/v1/statistics/records-by-category/releases/{period}/versions/{version}/withdrawal"]
            ["post"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/StatisticalReleaseHeader"
    );
    assert_eq!(
        openapi["components"]["schemas"]["StatisticalDatasetDocument"]["properties"]["live"]
            ["properties"]["evaluatedAt"]["format"],
        "date"
    );
    for path in [
        "/v1/statistics/records-by-category/releases/{period}/versions",
        "/v1/statistics/records-by-category/releases/{period}/versions/{version}/withdrawal",
    ] {
        let idempotency = openapi["paths"][path]["post"]["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|parameter| parameter["name"] == "Idempotency-Key")
            .expect("the mutation declares its idempotency header");
        assert_eq!(idempotency["schema"]["minLength"], 1);
        assert_eq!(idempotency["schema"]["maxLength"], 256);
        assert_eq!(
            idempotency["schema"]["pattern"],
            r"^[\x21-\x2B\x2D-\x3A\x3C-\x7E]+$"
        );
        assert!(idempotency["schema"].get("format").is_none());
    }
    for (path, item) in openapi["paths"].as_object().unwrap() {
        if !path.starts_with("/v1/statistics/") {
            continue;
        }
        let template_parameters = path
            .split('{')
            .skip(1)
            .map(|part| part.split('}').next().unwrap().to_owned())
            .collect::<BTreeSet<_>>();
        for operation in item.as_object().unwrap().values() {
            let declared_parameters = operation["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|parameter| parameter["in"] == "path")
                .map(|parameter| parameter["name"].as_str().unwrap().to_owned())
                .collect::<BTreeSet<_>>();
            assert_eq!(declared_parameters, template_parameters, "{path}");
        }
    }
    assert!(openapi["components"]["schemas"]
        .get("StatisticalWithdrawalResponse")
        .is_none());

    let mut with_default = source();
    with_default["accessProfiles"][2]["default"] = json!(true);
    let compiled = compile(&with_default).expect("configured statistical default compiles");
    let openapi = artifact_json(&compiled, "generated/openapi.json");
    let release = &openapi["paths"]["/v1/statistics/records-by-category/releases"]["get"];
    assert_eq!(release["parameters"][0]["required"], false);
    assert_eq!(release["parameters"][0]["schema"]["default"], "reader");
    assert_eq!(release["x-registry-defaultAccessProfile"], "reader");
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
    let added = added
        .changes
        .iter()
        .find(|change| change.code == CompiledRegistryChangeCode::StatisticalDatasetAdded)
        .expect("statistical dataset addition is classified");
    assert_eq!(
        added.class,
        CompiledRegistryChangeClass::AccessOrDisclosureChange
    );
    let removed = compiled_registry_change_set(&with_dataset, &without_dataset, "sha256:before");
    let removed = removed
        .changes
        .iter()
        .find(|change| change.code == CompiledRegistryChangeCode::StatisticalDatasetRemoved)
        .expect("statistical dataset removal is classified");
    assert_eq!(
        removed.class,
        CompiledRegistryChangeClass::AccessOrDisclosureChange
    );

    let mut changed_source = source();
    changed_source["statisticalDatasets"][0]["population"] = json!("active ne false");
    let changed_registry = compile(&changed_source).expect("changed dataset compiles");
    let changed = compiled_registry_change_set(&with_dataset, &changed_registry, "sha256:before");
    let changed = changed
        .changes
        .iter()
        .find(|change| change.code == CompiledRegistryChangeCode::StatisticalDatasetChanged)
        .expect("statistical dataset definition change is classified");
    assert_eq!(
        changed.class,
        CompiledRegistryChangeClass::AccessOrDisclosureChange
    );
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

    let alias_baseline_source = source_with_swappable_population_fields();
    let alias_baseline = compile(&alias_baseline_source).expect("two-field population compiles");
    let mut swapped_source = alias_baseline_source.clone();
    swap_population_api_names(&mut swapped_source);
    let swapped = compile(&swapped_source).expect("swapped API names compile");
    let changes = compiled_registry_change_set(&alias_baseline, &swapped, "sha256:before");
    assert!(changes
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::StatisticalDatasetChanged));
    let diff = classify_registry_diff(&alias_baseline, &swapped, "sha256:before");
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
    let baseline_digest = dataset.definition_digest.clone();

    let mut additional_read = value.clone();
    additional_read["accessProfiles"][1]["permissions"][1]["operations"] = json!(["get", "list"]);
    let additional_read = compile_with_sql(&additional_read, sql)
        .expect("another ordinary dependency read operation compiles");
    assert_ne!(
        baseline_digest,
        additional_read.statistical_datasets()["records-by-category"].definition_digest,
        "the definition digest binds dependency read operations"
    );

    let mut batch_select = value.clone();
    batch_select["entities"][1]["batch"] = json!({"maximumItems": 10, "maximumBytes": 4096});
    batch_select["accessProfiles"][1]["permissions"][1] = json!({
        "entity":"lookup","operations":["patch","batch"],"writableFields":["flag"],
        "rowBoundaries":[]
    });
    let batch_select = compile_with_sql(&batch_select, sql)
        .expect("batch supplies ordinary dependency SELECT visibility");
    assert_ne!(
        baseline_digest,
        batch_select.statistical_datasets()["records-by-category"].definition_digest,
        "the definition digest binds batch SELECT visibility"
    );

    let mut additional_mutation = value.clone();
    additional_mutation["accessProfiles"][1]["permissions"][1]["operations"] =
        json!(["list", "patch"]);
    additional_mutation["accessProfiles"][1]["permissions"][1]["writableFields"] = json!(["flag"]);
    let additional_mutation = compile_with_sql(&additional_mutation, sql)
        .expect("an unrelated dependency mutation grant compiles");
    assert_eq!(
        baseline_digest,
        additional_mutation.statistical_datasets()["records-by-category"].definition_digest,
        "unrelated mutation grants do not change the definition digest"
    );

    for permission in [
        json!({
            "entity":"lookup","operations":["create"],"writableFields":["flag"],
            "rowBoundaries":[]
        }),
        json!({
            "entity":"lookup","operations":["patch"],"writableFields":["flag"],
            "rowBoundaries":[]
        }),
    ] {
        let mut mutation_only_dependency = value.clone();
        mutation_only_dependency["accessProfiles"][1]["permissions"][1] = permission;
        let failure = compile_with_sql(&mutation_only_dependency, sql)
            .expect_err("a publisher needs an ordinary read operation on every derived dependency");
        assert!(failure.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "statistical_dataset.publisher.dependency_read_required"
                && diagnostic.message.contains("dependency entity `lookup`")
        }));
    }

    let mut missing_dependency_grant = value.clone();
    missing_dependency_grant["accessProfiles"][1]["permissions"]
        .as_array_mut()
        .unwrap()
        .pop();
    let failure = compile_with_sql(&missing_dependency_grant, sql)
        .expect_err("publisher access to every non-unit dependency is required");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "statistical_dataset.publisher.dependency_grant_missing"
            && diagnostic.message.contains("dependency entity `lookup`")
    }));

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

    let long_entity = "l".repeat(64);
    value["entities"][1]["id"] = json!(long_entity.clone());
    value["entities"][1]["route"] = json!("long-lookups");
    value["accessProfiles"][1]["permissions"][1]["entity"] = json!(long_entity.clone());
    let long_sql = sql.replace(
        "registry_source.lookup",
        &format!("registry_source.{long_entity}"),
    );
    let failure = compile_with_sql(&value, &long_sql)
        .expect_err("a long caller-dependent relation remains in the dependency closure");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "statistical_dataset.publisher.caller_dependent"
            && diagnostic
                .message
                .contains(&format!("dependency entity `{long_entity}`"))
    }));
}

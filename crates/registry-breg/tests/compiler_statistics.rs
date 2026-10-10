// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use registry_breg::compiler::{compile_project, compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_json, parse_project_yaml, ModuleAssetSource};
#[cfg(feature = "runtime")]
use registry_breg::package::{
    compiled_registry_change_set, CompiledRegistryChangeClass, CompiledRegistryChangeCode,
};
#[cfg(all(feature = "runtime", feature = "tooling"))]
use registry_breg::tooling::{classify_registry_diff, DiffClassification};
use serde_json::{json, Value};

fn source() -> Value {
    serde_json::from_value(json!({
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {
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
                "id":"analyst","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"entities":[{
                    "entity":"record","operations":["list"],
                    "readableFields":["active","category","event-date","valid-from","valid-to"],
                    "filterableFields":["active","category","event-date","valid-from","valid-to"],
                    "allowCount":true,"rowBoundaries":"unrestricted"
                }], "datasets":[{"dataset":"records-by-category","operations":["read-live","read-releases"]}]}
            },
            {
                "id":"publisher","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"entities":[{
                    "entity":"record","operations":["list"],
                    "readableFields":["active","category","event-date","valid-from","valid-to"],
                    "filterableFields":["active","category","event-date","valid-from","valid-to"],
                    "allowCount":true,"rowBoundaries":"unrestricted"
                }], "datasets":[{"dataset":"records-by-category","operations":["publish","read-releases"]}]}
            },
            {"id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{
                "datasets":[
                    {"dataset":"records-by-category","operations":["read-releases"]}
                ]
            }},
            {"id":"other-reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{}}
        ],
        "vocabularies": [{"id":"category","values":["a","b"]}],
        "statisticalDatasets": [{
            "id":"records-by-category",
            "unit":"record",
            "population":"active eq true",
            "period":{"type":"flow","field":"event-date","granularity":"month","firstPeriod":"2025-01"},
            "dimensions":["category"],
            "disclosure":{"minimumCount":5,"roundingBase":5}
        }]
    }))
    .expect("fixture is JSON")
}

const ANALYST: usize = 0;
const PUBLISHER: usize = 1;
const READER: usize = 2;
const OTHER_READER: usize = 3;

/// Write the operations one profile holds on the dataset. No operation
/// removes the profile's dataset permission.
fn grant(value: &mut Value, profile: usize, operations: &[&str]) {
    value["accessProfiles"][profile]["permissions"]["datasets"] = if operations.is_empty() {
        json!([])
    } else {
        json!([{"dataset":"records-by-category","operations":operations}])
    };
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
            value["accessProfiles"][profile]["permissions"]["entities"][0][member]
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

/// The live profiles, the publisher, and the readers a dataset compiles to.
type CompiledGrants = (Vec<String>, Option<(String, Vec<String>)>);

fn compiled_grants(value: &Value) -> CompiledGrants {
    let compiled = compile(value).expect("the dataset compiles");
    let dataset = &compiled.statistical_datasets()["records-by-category"];
    (
        dataset.live_profiles.iter().cloned().collect(),
        dataset.releases.as_ref().map(|releases| {
            (
                releases.publisher.clone(),
                releases.readers.iter().cloned().collect(),
            )
        }),
    )
}

fn grants(live: &[&str], releases: Option<(&str, &[&str])>) -> CompiledGrants {
    let owned = |profiles: &[&str]| profiles.iter().map(|id| (*id).to_owned()).collect();
    (
        owned(live),
        releases.map(|(publisher, readers)| (publisher.to_owned(), owned(readers))),
    )
}

/// Every diagnostic that refuses a project when it is read, as its code,
/// path, and message.
fn read_refusals(value: &Value) -> Vec<(String, String, String)> {
    parse_project_yaml(&serde_json::to_vec(value).expect("fixture serializes"))
        .expect_err("the project is refused when it is read")
        .diagnostics()
        .iter()
        .map(|diagnostic| {
            (
                diagnostic.code.clone(),
                diagnostic.path.clone(),
                diagnostic.message.clone(),
            )
        })
        .collect()
}

#[test]
fn dataset_permissions_compile_to_the_dataset_grants() {
    let compiled = compile(&source()).expect("the dataset compiles");
    let dataset = &compiled.statistical_datasets()["records-by-category"];
    assert_eq!(
        dataset.access_profiles.keys().collect::<Vec<_>>(),
        ["analyst", "publisher", "reader"],
        "every profile holding a dataset permission authenticates for the dataset"
    );
    assert_eq!(
        compiled_grants(&source()),
        grants(&["analyst"], Some(("publisher", &["reader"])))
    );

    // A profile may hold every operation. The readers are the profiles that
    // hold read-releases alone.
    let mut one_profile = source();
    grant(&mut one_profile, ANALYST, &[]);
    grant(
        &mut one_profile,
        PUBLISHER,
        &["read-live", "publish", "read-releases"],
    );
    grant(&mut one_profile, OTHER_READER, &["read-releases"]);
    assert_eq!(
        compiled_grants(&one_profile),
        grants(
            &["publisher"],
            Some(("publisher", &["other-reader", "reader"]))
        )
    );

    // A dataset no profile publishes has no releases, so its live profiles
    // hold read-live alone.
    let mut live_only = source();
    grant(&mut live_only, ANALYST, &["read-live"]);
    grant(&mut live_only, PUBLISHER, &[]);
    grant(&mut live_only, READER, &[]);
    assert_eq!(compiled_grants(&live_only), grants(&["analyst"], None));

    // The publisher reads what it publishes, so a dataset needs no other
    // release reader.
    let mut publisher_only = source();
    grant(&mut publisher_only, ANALYST, &[]);
    grant(&mut publisher_only, READER, &[]);
    assert_eq!(
        compiled_grants(&publisher_only),
        grants(&[], Some(("publisher", &[])))
    );
}

#[test]
fn access_explanation_states_who_holds_each_dataset_operation() {
    let audience = |value: &Value| {
        let compiled = compile(value).expect("the project compiles");
        serde_json::to_value(registry_breg::access::explain_access(&compiled))
            .expect("the explanation serializes")["statisticalDatasets"]
            .clone()
    };
    assert_eq!(
        audience(&source()),
        json!([{
            "dataset":"records-by-category",
            "readLive":["analyst"],
            "publish":["publisher"],
            "readReleases":["analyst","publisher","reader"]
        }])
    );

    let mut live_only = source();
    grant(&mut live_only, ANALYST, &["read-live"]);
    grant(&mut live_only, PUBLISHER, &[]);
    grant(&mut live_only, READER, &[]);
    assert_eq!(
        audience(&live_only),
        json!([{
            "dataset":"records-by-category",
            "readLive":["analyst"],
            "publish":[],
            "readReleases":[]
        }])
    );

    let mut without = source();
    without["statisticalDatasets"] = json!([]);
    for profile in [ANALYST, PUBLISHER, READER] {
        grant(&mut without, profile, &[]);
    }
    assert_eq!(audience(&without), json!([]));
}

#[test]
fn a_dataset_has_one_publisher() {
    let mut value = source();
    grant(
        &mut value,
        ANALYST,
        &["read-live", "publish", "read-releases"],
    );
    let failure = compile(&value).expect_err("two publishers are refused");
    let [diagnostic] = failure.diagnostics() else {
        panic!("one diagnostic refuses two publishers: {failure:?}");
    };
    assert_eq!(
        diagnostic.code,
        "breg.statistical-dataset.publisher-multiple"
    );
    assert_eq!(
        diagnostic.path,
        "statisticalDatasets[id=records-by-category]"
    );
    for named in [
        "statistical dataset `records-by-category`",
        "`analyst`",
        "`publisher`",
        "one access profile",
    ] {
        assert!(
            diagnostic.message.contains(named),
            "the refusal names {named}: {}",
            diagnostic.message
        );
    }
}

#[test]
fn a_profile_that_reads_live_counts_or_publishes_also_holds_read_releases() {
    for (profile, id, operations) in [
        (ANALYST, "analyst", ["read-live"]),
        (PUBLISHER, "publisher", ["publish"]),
    ] {
        let mut value = source();
        grant(&mut value, profile, &operations);
        let failure = compile(&value).expect_err("a missing read-releases is refused");
        let [diagnostic] = failure.diagnostics() else {
            panic!("one diagnostic refuses the missing read-releases: {failure:?}");
        };
        assert_eq!(
            diagnostic.code,
            "breg.statistical-dataset.read-releases-required"
        );
        for named in [
            "statistical dataset `records-by-category`".to_owned(),
            format!("`{id}`"),
            "add read-releases".to_owned(),
        ] {
            assert!(
                diagnostic.message.contains(&named),
                "the refusal names {named}: {}",
                diagnostic.message
            );
        }
    }
}

#[test]
fn read_releases_is_refused_on_a_dataset_no_profile_publishes() {
    let mut value = source();
    grant(&mut value, PUBLISHER, &[]);
    let failure = compile(&value).expect_err("release readers without a publisher are refused");
    let refused = failure
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    assert_eq!(refused, ["breg.statistical-dataset.publisher-missing"]);
    let message = &failure.diagnostics()[0].message;
    for named in [
        "statistical dataset `records-by-category`",
        "`analyst`",
        "`reader`",
        "grant publish",
        "remove read-releases",
    ] {
        assert!(
            message.contains(named),
            "the refusal names {named}: {message}"
        );
    }
}

#[test]
fn a_dataset_permission_names_its_dataset_as_a_local_identifier() {
    let mut value = source();
    value["accessProfiles"][OTHER_READER]["permissions"] =
        json!({"datasets":[{"dataset":"Records By Region","operations":["read-live"]}]});
    let bytes = serde_json::to_vec(&value).expect("fixture serializes");
    parse_project_json(&bytes).expect_err("a dataset permission names a local identifier");
}

#[test]
fn a_dataset_permission_names_a_declared_dataset() {
    let mut value = source();
    value["accessProfiles"][OTHER_READER]["permissions"] =
        json!({"datasets":[{"dataset":"records-by-region","operations":["read-live"]}]});
    let failure = compile(&value).expect_err("an undeclared dataset is refused");
    let [diagnostic] = failure.diagnostics() else {
        panic!("one diagnostic refuses the undeclared dataset: {failure:?}");
    };
    assert_eq!(
        diagnostic.code,
        "breg.access-profile.permission-dataset-unknown"
    );
    assert_eq!(
        diagnostic.path,
        "project.accessProfiles[id=other-reader].permissions.datasets[dataset=records-by-region].dataset"
    );
    for named in [
        "`other-reader`",
        "`records-by-region`",
        "statisticalDatasets",
    ] {
        assert!(
            diagnostic.message.contains(named),
            "the refusal names {named}: {}",
            diagnostic.message
        );
    }
}

#[test]
fn a_dataset_permission_is_written_with_dataset_operations_and_nothing_else() {
    let dataset_permission = "project.accessProfiles[0].permissions.datasets[0]";
    let cases: [(&str, Value, &str, String, &str); 7] = [
        (
            "/accessProfiles/0/permissions/datasets/0/operations",
            json!(["read-live", "list"]),
            "config.unknown-variant",
            format!("{dataset_permission}.operations[1]"),
            "`read-live`, `publish`, `read-releases`",
        ),
        (
            "/accessProfiles/0/permissions/datasets/0/operations",
            json!([]),
            "config.invalid-value",
            format!("{dataset_permission}.operations"),
            "read-live, publish, or read-releases",
        ),
        (
            "/accessProfiles/0/permissions/datasets/0/readableFields",
            json!(["active"]),
            "config.unknown-key",
            format!("{dataset_permission}.readableFields"),
            "`dataset`, `operations`",
        ),
        (
            "/accessProfiles/0/permissions/datasets/0/rowBoundaries",
            json!("unrestricted"),
            "config.unknown-key",
            format!("{dataset_permission}.rowBoundaries"),
            "`dataset`, `operations`",
        ),
        (
            "/accessProfiles/0/permissions/datasets/0/allowCount",
            json!(true),
            "config.unknown-key",
            format!("{dataset_permission}.allowCount"),
            "`dataset`, `operations`",
        ),
        (
            "/accessProfiles/0/permissions/datasets/0/entity",
            json!("record"),
            "config.unknown-key",
            format!("{dataset_permission}.entity"),
            "`dataset`, `operations`",
        ),
        (
            "/accessProfiles/0/permissions/entities/0/operations",
            json!(["list", "read-releases"]),
            "config.unknown-variant",
            "project.accessProfiles[0].permissions.entities[0].operations[1]".to_owned(),
            "`get`, `lookup`, `list`",
        ),
    ];
    for (pointer, written, code, path, fix) in cases {
        let mut value = source();
        let (parent, member) = pointer.rsplit_once('/').expect("a member pointer");
        value
            .pointer_mut(parent)
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("{parent} is a mapping"))
            .insert(member.to_owned(), written);
        let refused = read_refusals(&value);
        let [(refused_code, refused_path, message)] = refused.as_slice() else {
            panic!("one diagnostic refuses {pointer}: {refused:?}");
        };
        assert_eq!(refused_code, code, "{pointer}");
        assert_eq!(refused_path, &path, "{pointer}");
        assert!(
            message.contains(fix),
            "the refusal of {pointer} names its fix `{fix}`: {message}"
        );
    }
}

#[test]
fn an_unknown_permission_operation_is_refused_with_the_vocabulary_of_its_group() {
    for (group, accepted, refused_elsewhere) in [
        (
            "datasets",
            ["read-live", "publish", "read-releases"].as_slice(),
            ["list", "invoke"].as_slice(),
        ),
        (
            "entities",
            ["get", "list", "invoke"].as_slice(),
            ["read-live", "publish", "read-releases"].as_slice(),
        ),
    ] {
        let mut value = source();
        value["accessProfiles"][0]["permissions"][group][0]["operations"] = json!(["read"]);
        let refused = read_refusals(&value);
        let [(code, path, message)] = refused.as_slice() else {
            panic!("one diagnostic refuses the unknown operation: {refused:?}");
        };
        assert_eq!(code, "config.unknown-variant");
        assert_eq!(
            path,
            &format!("project.accessProfiles[0].permissions.{group}[0].operations[0]")
        );
        for operation in accepted {
            assert!(
                message.contains(operation),
                "the refusal under {group} lists {operation}: {message}"
            );
        }
        for operation in refused_elsewhere {
            assert!(
                !message.contains(operation),
                "the refusal under {group} does not offer {operation}: {message}"
            );
        }
    }
}

#[test]
fn the_removed_dataset_grant_members_are_refused_with_their_new_home_named() {
    for (member, written, named) in [
        ("live", json!(["analyst"]), ["permissions", "read-live"]),
        (
            "releases",
            json!({"publisher":"publisher","readers":["reader"]}),
            ["publish", "read-releases"],
        ),
    ] {
        let mut value = source();
        value["statisticalDatasets"][0][member] = written;
        let refused = read_refusals(&value);
        let [(code, path, message)] = refused.as_slice() else {
            panic!("one diagnostic refuses {member}: {refused:?}");
        };
        assert_eq!(code, "config.removed-key");
        assert_eq!(path, &format!("project.statisticalDatasets[0].{member}"));
        for name in named {
            assert!(
                message.contains(name),
                "the refusal of {member} names {name}: {message}"
            );
        }
    }
}

#[test]
fn a_profile_writes_its_dataset_permissions_back_into_its_permissions() {
    let bytes = serde_json::to_vec(&source()).expect("fixture serializes");
    let project = parse_project_json(&bytes).expect("fixture parses");
    let written = serde_json::to_value(&project).expect("the project serializes");
    assert_eq!(
        written["accessProfiles"][ANALYST]["permissions"]["datasets"],
        json!([{"dataset":"records-by-category","operations":["read-live","read-releases"]}])
    );
    assert_eq!(
        written["accessProfiles"][READER]["permissions"],
        json!({
            "entities":[],
            "actions":[],
            "datasets":[{"dataset":"records-by-category","operations":["read-releases"]}]
        })
    );
    assert!(written["accessProfiles"][ANALYST]
        .get("datasetPermissions")
        .is_none());
    let reread = parse_project_json(&serde_json::to_vec(&written).expect("it serializes"))
        .expect("the written project parses");
    assert_eq!(reread, project);
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
        dataset.access_profiles["reader"].principal_claim,
        "principal"
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
            "breg.statistical-dataset.unit-unknown",
        ),
        (
            Box::new(|v| v["statisticalDatasets"][0]["population"] = json!("active = true")),
            "breg.statistical-dataset.population-invalid",
        ),
        (
            Box::new(|v| v["statisticalDatasets"][0]["period"]["field"] = json!("missing")),
            "breg.statistical-dataset.field-unknown",
        ),
        (
            Box::new(|v| v["statisticalDatasets"][0]["period"]["field"] = json!("category")),
            "breg.statistical-dataset.period-field-type",
        ),
        (
            Box::new(|v| v["statisticalDatasets"][0]["dimensions"] = json!(["event-date"])),
            "breg.statistical-dataset.dimension-type",
        ),
        (
            Box::new(|v| {
                v["statisticalDatasets"][0]["dimensions"] = json!(["category", "category"])
            }),
            "breg.statistical-dataset.dimension-duplicate",
        ),
        (
            Box::new(|v| {
                v["statisticalDatasets"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("disclosure");
            }),
            "breg.statistical-dataset.disclosure-missing",
        ),
        (
            Box::new(|v| {
                let again = v["accessProfiles"][ANALYST]["permissions"]["datasets"][0].clone();
                v["accessProfiles"][ANALYST]["permissions"]["datasets"]
                    .as_array_mut()
                    .unwrap()
                    .push(again);
            }),
            "breg.statistical-dataset.profile-duplicate",
        ),
        (
            Box::new(|v| {
                for profile in [ANALYST, PUBLISHER, READER] {
                    grant(v, profile, &[]);
                }
            }),
            "breg.statistical-dataset.grants-empty",
        ),
        (
            Box::new(|v| {
                v["accessProfiles"][0]["permissions"]["entities"][0]["allowCount"] = json!(false)
            }),
            "breg.statistical-dataset.count-grant-count-required",
        ),
        (
            Box::new(|v| {
                v["accessProfiles"][0]["permissions"]["entities"][0]["operations"] =
                    json!(["snapshot"])
            }),
            "breg.statistical-dataset.count-grant-list-required",
        ),
        (
            Box::new(|v| {
                v["accessProfiles"][0]["permissions"]["entities"][0]["filterableFields"] =
                    json!(["active", "category"])
            }),
            "breg.statistical-dataset.count-grant-field-not-filterable",
        ),
        (
            Box::new(|v| v["accessProfiles"][1]["requiredPurposes"] = json!(["reporting"])),
            "breg.statistical-dataset.publisher-caller-dependent",
        ),
        (
            Box::new(|v| {
                v["accessProfiles"][1]["permissions"]["entities"][0]["rowBoundaries"] =
                    json!([{"field":"category","claim":"categories","operator":"in"}])
            }),
            "breg.statistical-dataset.publisher-caller-dependent",
        ),
    ];
    for (mutator, code) in cases {
        assert_refused(mutator, code);
    }
}

#[test]
fn statistical_disclosure_bounds_are_refused_when_the_project_is_read() {
    for (member, written) in [
        ("minimumCount", json!(1)),
        ("roundingBase", json!(1)),
        ("minimumCount", json!(9_007_199_254_740_992_u64)),
        ("roundingBase", json!(9_007_199_254_740_992_u64)),
    ] {
        let mut value = source();
        value["statisticalDatasets"][0]["disclosure"][member] = written;
        let failure = parse_project_yaml(&serde_json::to_vec(&value).expect("fixture serializes"))
            .expect_err("a disclosure bound outside 2 to 2^53 - 1 is refused");
        let refused = failure
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect::<Vec<_>>();
        let path = format!("project.statisticalDatasets[0].disclosure.{member}");
        assert_eq!(
            refused,
            vec![("config.out-of-range", path.as_str())],
            "{failure:?}"
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
                        {"id":"name","type":"string","maximumLength":80,"classification":"internal"}
                    ]
                }),
                json!({
                    "id":"membership","primaryDataset":"statistics-test","route":"memberships",
                    "mutationMode":"mutable","classification":"restricted",
                    "fields":[
                        {"id":"organization","type":"reference","target":"organization","required":true,"classification":"internal"},
                        {"id":"principal","type":"string","maximumLength":80,"required":true,"classification":"restricted"},
                        {"id":"active","type":"boolean","required":true,"classification":"internal"}
                    ],
                    "indexes":[{"id":"membership-principal-key","fields":["principal","organization","active"]}],
                    "accessRequirements":{"requiredScopes":["membership:use"]}
                }),
            ]);
            value["accessProfiles"][1]["requiredScopes"] = json!(["membership:use"]);
            value["accessProfiles"][1]["permissions"]["entities"][0]["membershipBoundaries"] = json!([{
                "field":"organization","membershipEntity":"membership",
                "membershipKeyField":"organization","principalField":"principal","activeField":"active"
            }]);
        },
        "breg.statistical-dataset.publisher-caller-dependent",
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
                "review":{"type":"none"},"onApproved":{"mode":"manual"}
            });
            value["entities"].as_array_mut().unwrap().push(json!({
                "id":"target-record","primaryDataset":"statistics-test","route":"target-records",
                "mutationMode":"mutable","changeControl":{"requiredFor":["patch"]},
                "fields":[
                    {"id":"active","type":"boolean","required":true,"classification":"internal"}
                ]
            }));
            value["accessProfiles"][1]["permissions"]["entities"][0]["requestVisibility"] =
                json!("owner");
        },
        "breg.statistical-dataset.publisher-caller-dependent",
    );
    assert_refused(
        |value| {
            let boundary = json!({"field":"category","claim":"categories","operator":"in"});
            value["entities"][0]["accessRequirements"] =
                json!({"rowBoundaries":[boundary.clone()]});
            for profile in [0_usize, 1] {
                value["accessProfiles"][profile]["permissions"]["entities"][0]["rowBoundaries"] =
                    json!([boundary.clone()]);
            }
        },
        "breg.statistical-dataset.publisher-entity-row-boundary",
    );
}

#[test]
fn statistical_dataset_refuses_encrypted_processing_fields_and_consent_gated_count_grants() {
    assert_refused(
        |value| {
            value["entities"][0]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                        "id":"secret","type":"string","maximumLength":80,"encrypted":true,
                        "classification":"restricted"
                }));
            for profile in [0_usize, 1] {
                value["accessProfiles"][profile]["permissions"]["entities"][0]["readableFields"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("secret"));
            }
            value["statisticalDatasets"][0]["population"] =
                json!("active eq true and secret eq 'x'");
        },
        "breg.statistical-dataset.field-encrypted",
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
                "route":"consent-decisions","mutationMode":"create-only","classification":"restricted",
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
                    "validity":{"from":"effective-at","until":"expires-at","maximumDurationDays":365}
                }
            }));
            value["accessProfiles"][1]["actorKind"] = json!("service");
            value["accessProfiles"][1]["requesterClients"] = json!(["publisher-client"]);
            value["accessProfiles"][1]["requiredPurposes"] = json!(["statistics"]);
            value["accessProfiles"][1]["permissions"]["entities"][0]["requireConsent"] =
                json!([{"record":"consent-decision","on":"id"}])
        },
        "breg.statistical-dataset.count-grant-consent",
    );
}

#[test]
fn statistical_dataset_refuses_reserved_and_unbounded_dimensions() {
    assert_refused(
        |value| value["vocabularies"][0]["values"] = json!(["_reserved", "a"]),
        "breg.statistical-dataset.dimension-code-reserved",
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
            "breg.statistical-dataset.dimension-reserved",
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
                    value["accessProfiles"][profile]["permissions"]["entities"][0][member]
                        .as_array_mut()
                        .unwrap()
                        .push(json!("category-two"));
                }
            }
            value["statisticalDatasets"][0]["dimensions"] = json!(["category", "category-two"]);
        },
        "breg.statistical-dataset.cells-exceeded",
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
                value["accessProfiles"][profile]["permissions"]["entities"][0][member]
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
        "breg.statistical-dataset.dimension-reserved",
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
                        value["accessProfiles"][profile]["permissions"]["entities"][0][member]
                            .as_array_mut()
                            .unwrap()
                            .push(json!(field));
                    }
                }
                dimensions.push(field);
            }
            value["statisticalDatasets"][0]["dimensions"] = json!(dimensions);
        },
        "breg.statistical-dataset.document-exceeded",
    );
}

#[test]
fn statistical_period_unions_refuse_at_the_member_inside_the_form() {
    let period = "project.statisticalDatasets[0].period";
    let stock = |validity: Value| json!({"type":"stock","granularity":"month","firstPeriod":"2025-01","validity":validity});
    for (written, code, path) in [
        (
            stock(json!(["temporal"])),
            "config.invalid-type",
            format!("{period}.validity"),
        ),
        (
            stock(json!("permanent")),
            "config.unknown-variant",
            format!("{period}.validity"),
        ),
        (
            stock(json!({"from":"valid-from","to":"valid-to"})),
            "config.unknown-key",
            format!("{period}.validity.to"),
        ),
        (
            json!({"type":"flow","granularity":"month","firstPeriod":"2025-01"}),
            "config.missing-key",
            period.to_owned(),
        ),
        (
            json!({"type":"flow","field":"event-date","granularity":"month","firstPeriod":"2025-01","validity":"temporal"}),
            "config.unknown-key",
            format!("{period}.validity"),
        ),
        (
            json!({"type":"snapshot","granularity":"month","firstPeriod":"2025-01"}),
            "config.unknown-variant",
            format!("{period}.type"),
        ),
    ] {
        let mut value = source();
        value["statisticalDatasets"][0]["period"] = written;
        let failure = parse_project_yaml(&serde_json::to_vec(&value).expect("fixture serializes"))
            .expect_err("a malformed period is refused when the project is read");
        let refused = failure
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(refused, vec![(code, path.as_str())], "{failure:?}");
    }
}

#[test]
fn a_period_tagged_by_kind_is_refused_with_its_replacement_named() {
    let mut value = source();
    value["statisticalDatasets"][0]["period"] =
        json!({"kind":"flow","field":"event-date","granularity":"month","firstPeriod":"2025-01"});
    let failure = parse_project_yaml(&serde_json::to_vec(&value).expect("fixture serializes"))
        .expect_err("a period tagged by kind is refused when the project is read");
    let refused = failure
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        refused,
        vec![
            (
                "config.missing-key",
                "project.statisticalDatasets[0].period"
            ),
            (
                "config.removed-key",
                "project.statisticalDatasets[0].period.kind"
            ),
        ],
        "{failure:?}"
    );
    let removed = &failure.diagnostics()[1];
    assert!(
        removed.message.contains("`type`"),
        "the refusal names the member that replaces kind: {removed:?}"
    );
}

#[test]
fn a_dataset_id_outside_the_local_identifier_grammar_is_refused_when_read() {
    let long = "u".repeat(65);
    for written in ["Units", "1-units", "units.by.category", long.as_str()] {
        let mut value = source();
        value["statisticalDatasets"][0]["id"] = json!(written);
        let failure = parse_project_yaml(&serde_json::to_vec(&value).expect("fixture serializes"))
            .expect_err("an id outside the grammar is refused when the project is read");
        let refused = failure
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            refused,
            vec![("config.invalid-value", "project.statisticalDatasets[0].id")],
            "{failure:?}"
        );
        assert!(
            failure
                .diagnostics()
                .iter()
                .all(|diagnostic| !diagnostic.message.contains(written)),
            "the refusal does not repeat the value: {failure:?}"
        );
    }
}

#[test]
fn temporal_and_pair_stock_compile_and_invalid_periods_are_refused() {
    for validity in [
        json!("temporal"),
        json!({"from":"valid-from","until":"valid-to"}),
    ] {
        let mut value = source();
        value["statisticalDatasets"][0]["period"] = json!({
            "type":"stock","granularity":"month","firstPeriod":"2025-01","validity":validity
        });
        compile(&value).expect("stock validity compiles");
    }
    assert_refused(
        |value| value["entities"][0]["fields"][2]["type"] = json!("timestamp"),
        "breg.statistical-dataset.period-field-type",
    );
    assert_refused(
        |value| value["statisticalDatasets"][0]["period"]["firstPeriod"] = json!("2025-13"),
        "breg.statistical-dataset.period-first-period",
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
                "breg.statistical-dataset.period-first-period",
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
                "type":"stock","granularity":"month","firstPeriod":"2025-01","validity":"temporal"
            });
            value["entities"][0]
                .as_object_mut()
                .unwrap()
                .remove("temporal");
        },
        "breg.statistical-dataset.period-temporal-missing",
    );
}

#[test]
fn definition_digest_excludes_grants_and_first_period_but_covers_values() {
    let baseline = compile(&source()).expect("baseline compiles");
    let baseline_digest = &baseline.statistical_datasets()["records-by-category"].definition_digest;

    let mut grant_change = source();
    grant(&mut grant_change, ANALYST, &[]);
    grant(
        &mut grant_change,
        PUBLISHER,
        &["read-live", "publish", "read-releases"],
    );
    grant(&mut grant_change, READER, &[]);
    grant(&mut grant_change, OTHER_READER, &["read-releases"]);
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
            baseline_source["accessProfiles"][profile]["permissions"]["entities"][0][member]
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
        "id":"score","type":"text","maximumLength":20,"required":true,
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
            baseline_source["accessProfiles"][profile]["permissions"]["entities"][0][member]
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
        "id":"score","type":"text","maximumLength":20,
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
            value["accessProfiles"][profile]["permissions"]["entities"][0][member]
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
            "breg.statistical-dataset.population-invalid",
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
            "breg.statistical-dataset.population-invalid",
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
            "id":"label","type":"string","minimumLength":8,"maximumLength":12,
            "required":true,"classification":"internal"
        }));
    for profile in [0_usize, 1] {
        for member in ["readableFields", "filterableFields"] {
            bounded_string["accessProfiles"][profile]["permissions"]["entities"][0][member]
                .as_array_mut()
                .unwrap()
                .push(json!("label"));
        }
    }
    bounded_string["statisticalDatasets"][0]["population"] = json!("contains(label,'a')");
    compile(&bounded_string).expect("a search term shorter than the stored minimumLength compiles");

    let oversized = "a".repeat(registry_breg::query::MAX_LITERAL_BYTES + 1);
    for population in [
        "startswith(active,'t')".to_owned(),
        "startswith(category,1)".to_owned(),
        "contains(category,'line\nbreak')".to_owned(),
        format!("contains(category,'{oversized}')"),
    ] {
        assert_refused(
            |value| value["statisticalDatasets"][0]["population"] = json!(population),
            "breg.statistical-dataset.population-invalid",
        );
    }

    bounded_string["statisticalDatasets"][0]["population"] =
        json!("contains(label,'thirteenchars')");
    let failure = compile(&bounded_string).expect_err("a term beyond maximumLength is refused");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.statistical-dataset.population-invalid"));
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
    grant(&mut live_only, ANALYST, &["read-live"]);
    grant(&mut live_only, PUBLISHER, &[]);
    grant(&mut live_only, READER, &[]);
    let compiled = compile(&live_only).expect("live-only dataset compiles");
    let openapi = artifact_json(&compiled, "generated/openapi.json");
    assert!(openapi["paths"]
        .as_object()
        .unwrap()
        .keys()
        .filter(|path| path.starts_with("/v1/statistics/"))
        .all(|path| path.ends_with(":live")));

    let mut released_only = source();
    grant(&mut released_only, ANALYST, &[]);
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
    for profile in [ANALYST, PUBLISHER, READER] {
        grant(&mut without, profile, &[]);
    }
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
    grant(&mut widened_source, OTHER_READER, &["read-releases"]);
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
        value["accessProfiles"][profile]["permissions"]["entities"][0]["readableFields"]
            .as_array_mut()
            .unwrap()
            .push(json!("evaluated-category"));
        value["accessProfiles"][profile]["permissions"]["entities"][0]["filterableFields"]
            .as_array_mut()
            .unwrap()
            .push(json!("evaluated-category"));
    }
    value["accessProfiles"][1]["permissions"]["entities"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "entity":"lookup","operations":["list"],"readableFields":["flag"],
            "filterableFields":["flag"],"allowCount":true,"rowBoundaries":"unrestricted"
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
    additional_read["accessProfiles"][PUBLISHER]["permissions"]["entities"][1]["operations"] =
        json!(["get", "list"]);
    let additional_read = compile_with_sql(&additional_read, sql)
        .expect("another ordinary dependency read operation compiles");
    assert_ne!(
        baseline_digest,
        additional_read.statistical_datasets()["records-by-category"].definition_digest,
        "the definition digest binds dependency read operations"
    );

    let mut batch_select = value.clone();
    batch_select["entities"][1]["batch"] = json!({"maximumItems": 10, "maximumBytes": 4096});
    batch_select["accessProfiles"][PUBLISHER]["permissions"]["entities"][1] = json!({
        "entity":"lookup","operations":["patch","batch"],"writableFields":["flag"],
        "rowBoundaries":"unrestricted"
    });
    let batch_select = compile_with_sql(&batch_select, sql)
        .expect("batch supplies ordinary dependency SELECT visibility");
    assert_ne!(
        baseline_digest,
        batch_select.statistical_datasets()["records-by-category"].definition_digest,
        "the definition digest binds batch SELECT visibility"
    );

    let mut additional_mutation = value.clone();
    additional_mutation["accessProfiles"][PUBLISHER]["permissions"]["entities"][1]["operations"] =
        json!(["list", "patch"]);
    additional_mutation["accessProfiles"][PUBLISHER]["permissions"]["entities"][1]
        ["writableFields"] = json!(["flag"]);
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
            "rowBoundaries":"unrestricted"
        }),
        json!({
            "entity":"lookup","operations":["patch"],"writableFields":["flag"],
            "rowBoundaries":"unrestricted"
        }),
    ] {
        let mut mutation_only_dependency = value.clone();
        mutation_only_dependency["accessProfiles"][PUBLISHER]["permissions"]["entities"][1] =
            permission;
        let failure = compile_with_sql(&mutation_only_dependency, sql)
            .expect_err("a publisher needs an ordinary read operation on every derived dependency");
        assert!(failure.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "breg.statistical-dataset.publisher-dependency-read-required"
                && diagnostic.message.contains("dependency entity `lookup`")
        }));
    }

    let mut missing_dependency_grant = value.clone();
    missing_dependency_grant["accessProfiles"][1]["permissions"]["entities"]
        .as_array_mut()
        .unwrap()
        .pop();
    let failure = compile_with_sql(&missing_dependency_grant, sql)
        .expect_err("publisher access to every non-unit dependency is required");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "breg.statistical-dataset.publisher-dependency-grant-missing"
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
        diagnostic.code == "breg.statistical-dataset.publisher-caller-dependent"
            && diagnostic.message.contains("dependency entity `lookup`")
    }));

    let long_entity = "l".repeat(64);
    value["entities"][1]["id"] = json!(long_entity.clone());
    value["entities"][1]["route"] = json!("long-lookups");
    value["accessProfiles"][PUBLISHER]["permissions"]["entities"][1]["entity"] =
        json!(long_entity.clone());
    let long_sql = sql.replace(
        "registry_source.lookup",
        &format!("registry_source.{long_entity}"),
    );
    let failure = compile_with_sql(&value, &long_sql)
        .expect_err("a long caller-dependent relation remains in the dependency closure");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "breg.statistical-dataset.publisher-caller-dependent"
            && diagnostic
                .message
                .contains(&format!("dependency entity `{long_entity}`"))
    }));
}

// SPDX-License-Identifier: Apache-2.0

#[path = "support/source_bytes.rs"]
mod source_bytes;

use std::collections::BTreeSet;

use registry_breg::compiler::{compile_project, compile_project_with_assets, CompileProfile};
use registry_breg::contract::{
    parse_module_json, parse_project_json, parse_project_yaml, ModuleAssetSource,
};
use registry_breg::diagnostics::{CompileFailure, Diagnostic, DiagnosticSeverity};
#[cfg(feature = "runtime")]
use registry_breg::package::{
    compiled_registry_change_set, CompiledRegistryChangeClass, CompiledRegistryChangeCode,
};
#[cfg(all(feature = "runtime", feature = "tooling"))]
use registry_breg::tooling::{classify_registry_diff, DiffClassification};
use serde_json::{json, Value};

fn errors(failure: &CompileFailure) -> Vec<&Diagnostic> {
    failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .collect()
}

fn assert_retained_authoring_finding(failure: &CompileFailure) {
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Finding
            && diagnostic.code == "breg.package.identity-missing"
            && diagnostic.path == "project.package"
    }));
}

fn source() -> Value {
    serde_json::from_value(json!({"datasets":[{"id": "statistics-test"}],
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {
            "id": "statistics-test",
            "version": "1",
            "defaultLanguage": "en",
            "canonicalBaseIri": "https://statistics.example.test",
            "timezone": "UTC"
        },
        "recordTypes": {"record": {
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
        }},
        "accessProfiles": {
            "analyst": {"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
                    "recordType":"record","operations":["list"],
                    "readableFields":["active","category","event-date","valid-from","valid-to"],
                    "filterableFields":["active","category","event-date","valid-from","valid-to"],
                    "allowCount":true,"rowBoundaries":"unrestricted"
                }], "datasets":[{"dataset":"records-by-category","operations":["read-live","read-releases"]}]}
            },
            "publisher": {"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
                    "recordType":"record","operations":["list"],
                    "readableFields":["active","category","event-date","valid-from","valid-to"],
                    "filterableFields":["active","category","event-date","valid-from","valid-to"],
                    "allowCount":true,"rowBoundaries":"unrestricted"
                }], "datasets":[{"dataset":"records-by-category","operations":["publish","read-releases"]}]}
            },
            "reader": {"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{
                "datasets":[
                    {"dataset":"records-by-category","operations":["read-releases"]}
                ]
            }},
            "other-reader": {"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{}}
        },
        "vocabularies": [{"id":"category","values":["a","b"]}],
        "statisticalDatasets": [{
            "id":"records-by-category",
            "unit":"record",
            "population":"active eq true",
            "period":{"type":"flow","field":"event-date","granularity":"month","firstPeriod":"2025-01"},
            "dimensions":["category"],
            "disclosure":{"type":"minimum-count-and-rounding","minimumCount":5,"roundingBase":5}
        }]
    }))
    .expect("fixture is JSON")
}

const ANALYST: &str = "analyst";
const PUBLISHER: &str = "publisher";
const READER: &str = "reader";
const OTHER_READER: &str = "other-reader";

/// Write the operations one profile holds on the dataset. No operation
/// removes the profile's dataset permission.
fn grant(value: &mut Value, profile: &str, operations: &[&str]) {
    value["accessProfiles"][profile]["permissions"]["datasets"] = if operations.is_empty() {
        json!([])
    } else {
        json!([{"dataset":"records-by-category","operations":operations}])
    };
}

fn source_with_swappable_population_fields() -> Value {
    let mut value = source();
    value["recordTypes"]["record"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"archived","apiName":"archived","type":"boolean","required":true,
            "classification":"internal"
        }));
    value["recordTypes"]["record"]["fields"][0]["apiName"] = json!("active");
    for profile in [ANALYST, PUBLISHER] {
        for member in ["readableFields", "filterableFields"] {
            value["accessProfiles"][profile]["permissions"]["records"][0][member]
                .as_array_mut()
                .unwrap()
                .push(json!("archived"));
        }
    }
    value["statisticalDatasets"][0]["population"] = json!("active eq true and archived eq false");
    value
}

fn swap_population_api_names(value: &mut Value) {
    value["recordTypes"]["record"]["fields"][0]["apiName"] = json!("archived");
    value["recordTypes"]["record"]["fields"][5]["apiName"] = json!("active");
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
        let mut datasets = serde_json::to_value(registry_breg::access::explain_access(&compiled))
            .expect("the explanation serializes")["statisticalDatasets"]
            .clone();
        for dataset in datasets
            .as_array_mut()
            .expect("dataset inventory is an array")
        {
            let profiles = dataset
                .as_object_mut()
                .unwrap()
                .remove("accessProfiles")
                .unwrap();
            for profile in profiles.as_array().unwrap() {
                assert_eq!(profile["principalClaim"], "principal");
            }
        }
        datasets
    };
    assert_eq!(
        audience(&source()),
        json!([{
            "dataset":"records-by-category",
            "display":{},
            "readLive":["analyst"],
            "readExact":[],
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
            "display":{},
            "readLive":["analyst"],
            "readExact":[],
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
    let errors = errors(&failure);
    let [diagnostic] = errors.as_slice() else {
        panic!("one diagnostic refuses two publishers: {failure:?}");
    };
    assert_retained_authoring_finding(&failure);
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
        let errors = errors(&failure);
        let [diagnostic] = errors.as_slice() else {
            panic!("one diagnostic refuses the missing read-releases: {failure:?}");
        };
        assert_retained_authoring_finding(&failure);
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
    let refused = errors(&failure)
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    assert_eq!(refused, ["breg.statistical-dataset.publisher-missing"]);
    assert_retained_authoring_finding(&failure);
    let message = &errors(&failure)[0].message;
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
    let errors = errors(&failure);
    let [diagnostic] = errors.as_slice() else {
        panic!("one diagnostic refuses the undeclared dataset: {failure:?}");
    };
    assert_retained_authoring_finding(&failure);
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
    let dataset_permission = "project.accessProfiles.analyst.permissions.datasets[0]";
    let cases: [(&str, Value, &str, String, &str); 7] = [
        (
            "/accessProfiles/analyst/permissions/datasets/0/operations",
            json!(["read-live", "list"]),
            "config.unknown-variant",
            format!("{dataset_permission}.operations[1]"),
            "`read-live`, `read-exact`, `publish`, `read-releases`",
        ),
        (
            "/accessProfiles/analyst/permissions/datasets/0/operations",
            json!([]),
            "config.invalid-value",
            format!("{dataset_permission}.operations"),
            "read-live, read-exact, publish, or read-releases",
        ),
        (
            "/accessProfiles/analyst/permissions/datasets/0/readableFields",
            json!(["active"]),
            "config.unknown-key",
            format!("{dataset_permission}.readableFields"),
            "`dataset`, `operations`",
        ),
        (
            "/accessProfiles/analyst/permissions/datasets/0/rowBoundaries",
            json!("unrestricted"),
            "config.unknown-key",
            format!("{dataset_permission}.rowBoundaries"),
            "`dataset`, `operations`",
        ),
        (
            "/accessProfiles/analyst/permissions/datasets/0/allowCount",
            json!(true),
            "config.unknown-key",
            format!("{dataset_permission}.allowCount"),
            "`dataset`, `operations`",
        ),
        (
            "/accessProfiles/analyst/permissions/datasets/0/entity",
            json!("record"),
            "config.unknown-key",
            format!("{dataset_permission}.entity"),
            "`dataset`, `operations`",
        ),
        (
            "/accessProfiles/analyst/permissions/records/0/operations",
            json!(["list", "read-releases"]),
            "config.unknown-variant",
            "project.accessProfiles.analyst.permissions.records[0].operations[1]".to_owned(),
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
            "records",
            ["get", "list", "invoke"].as_slice(),
            ["read-live", "publish", "read-releases"].as_slice(),
        ),
    ] {
        let mut value = source();
        value["accessProfiles"]["analyst"]["permissions"][group][0]["operations"] = json!(["read"]);
        let refused = read_refusals(&value);
        let [(code, path, message)] = refused.as_slice() else {
            panic!("one diagnostic refuses the unknown operation: {refused:?}");
        };
        assert_eq!(code, "config.unknown-variant");
        assert_eq!(
            path,
            &format!("project.accessProfiles.analyst.permissions.{group}[0].operations[0]")
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
            "records":[],
            "proposals":[],
            "actions":[],
            "datasets":[{"dataset":"records-by-category","operations":["read-releases"]}]
        })
    );
    assert!(written["accessProfiles"][ANALYST]
        .get("datasetPermissions")
        .is_none());
    let reread = parse_project_json(&source_bytes::source_bytes(&written))
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
                v["accessProfiles"]["analyst"]["permissions"]["records"][0]["allowCount"] =
                    json!(false)
            }),
            "breg.statistical-dataset.count-grant-count-required",
        ),
        (
            Box::new(|v| {
                v["accessProfiles"]["analyst"]["permissions"]["records"][0]["operations"] =
                    json!(["snapshot"])
            }),
            "breg.statistical-dataset.count-grant-list-required",
        ),
        (
            Box::new(|v| {
                v["accessProfiles"]["analyst"]["permissions"]["records"][0]["filterableFields"] =
                    json!(["active", "category"])
            }),
            "breg.statistical-dataset.count-grant-field-not-filterable",
        ),
        (
            Box::new(|v| {
                v["accessProfiles"]["publisher"]["requiredPurposes"] = json!(["reporting"])
            }),
            "breg.statistical-dataset.publisher-caller-dependent",
        ),
        (
            Box::new(|v| {
                v["accessProfiles"]["publisher"]["permissions"]["records"][0]["rowBoundaries"] =
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
            value["recordTypes"]["record"]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "id":"organization","type":"reference","target":"organization",
                    "required":true,"classification":"internal"
                }));
            value["recordTypes"].as_object_mut().unwrap().extend([
                ("organization".to_owned(), json!({"primaryDataset":"statistics-test","route":"organizations",
                    "mutationMode":"mutable","fields":[
                        {"id":"name","type":"string","maximumLength":80,"classification":"internal"}
                    ]
                })),
                ("membership".to_owned(), json!({"primaryDataset":"statistics-test","route":"memberships",
                    "mutationMode":"mutable","classification":"restricted",
                    "fields":[
                        {"id":"organization","type":"reference","target":"organization","required":true,"classification":"internal"},
                        {"id":"principal","type":"string","maximumLength":80,"required":true,"classification":"restricted"},
                        {"id":"active","type":"boolean","required":true,"classification":"internal"}
                    ],
                    "indexes":[{"id":"membership-principal-key","fields":["principal","organization","active"]}],
                    "accessRequirements":{"requiredScopes":["membership:use"]}
                }))
            ]);
            value["accessProfiles"]["publisher"]["requiredScopes"] = json!(["membership:use"]);
            value["accessProfiles"]["publisher"]["permissions"]["records"][0]
                ["membershipBoundaries"] = json!([{
                "field":"organization","membershipRecordType":"membership",
                "membershipKeyField":"organization","principalField":"principal","activeField":"active"
            }]);
        },
        "breg.statistical-dataset.publisher-caller-dependent",
    );

    assert_refused(
        |value| {
            let boundary = json!({"field":"category","claim":"categories","operator":"in"});
            value["recordTypes"]["record"]["accessRequirements"] =
                json!({"rowBoundaries":[boundary.clone()]});
            for profile in [ANALYST, PUBLISHER] {
                value["accessProfiles"][profile]["permissions"]["records"][0]["rowBoundaries"] =
                    json!([boundary.clone()]);
            }
        },
        "breg.statistical-dataset.publisher-record-type-row-boundary",
    );
}

#[test]
fn statistical_dataset_refuses_encrypted_processing_fields_and_consent_gated_count_grants() {
    assert_refused(
        |value| {
            value["recordTypes"]["record"]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                        "id":"secret","type":"string","maximumLength":80,"encrypted":true,
                        "classification":"restricted"
                }));
            for profile in [ANALYST, PUBLISHER] {
                value["accessProfiles"][profile]["permissions"]["records"][0]["readableFields"]
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
            value["recordTypes"].as_object_mut().unwrap().insert("consent-decision".to_owned(), json!({"primaryDataset":"statistics-test",
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
            value["accessProfiles"]["publisher"]["actorKind"] = json!("service");
            value["accessProfiles"]["publisher"]["requesterClients"] = json!(["publisher-client"]);
            value["accessProfiles"]["publisher"]["requiredPurposes"] = json!(["statistics"]);
            value["accessProfiles"]["publisher"]["permissions"]["records"][0]["requireConsent"] =
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

    for id in ["period", "value", "status", "measure"] {
        assert_refused(
            |value| {
                value["recordTypes"]["record"]["fields"]
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
            value["recordTypes"]["record"]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "id":"category-two","type":"vocabulary-code","vocabulary":"category-two",
                    "required":true,"classification":"internal"
                }));
            for profile in [ANALYST, PUBLISHER] {
                for member in ["readableFields", "filterableFields"] {
                    value["accessProfiles"][profile]["permissions"]["records"][0][member]
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

/// Adds `count` required single-code vocabulary dimensions to the fixture dataset.
fn with_single_code_dimensions(value: &mut Value, count: usize) {
    let mut dimensions = Vec::new();
    for index in 0..count {
        let id = format!("dimension-{index:02}");
        value["vocabularies"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":id,"values":["only"]}));
        value["recordTypes"]["record"]["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":id,"type":"vocabulary-code","vocabulary":id,
                "required":true,"classification":"internal"
            }));
        for profile in [ANALYST, PUBLISHER] {
            for member in ["readableFields", "filterableFields"] {
                value["accessProfiles"][profile]["permissions"]["records"][0][member]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(id));
            }
        }
        dimensions.push(id);
    }
    value["statisticalDatasets"][0]["dimensions"] = json!(dimensions);
}

#[test]
fn a_dataset_declares_at_most_twelve_dimensions() {
    let mut twelve = source();
    with_single_code_dimensions(&mut twelve, 12);
    compile(&twelve).expect("twelve dimensions compile");

    assert_refused(
        |value| with_single_code_dimensions(value, 13),
        "breg.statistical-dataset.dimensions-exceeded",
    );
}

#[test]
fn statistical_dimension_reserved_names_follow_emitted_logical_field_ids() {
    let mut value = source();
    for id in ["period-start", "period-end"] {
        value["recordTypes"]["record"]["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":id,"type":"boolean","required":true,"classification":"internal"
            }));
        for profile in [ANALYST, PUBLISHER] {
            for member in ["readableFields", "filterableFields"] {
                value["accessProfiles"][profile]["permissions"]["records"][0][member]
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
            value["recordTypes"]["record"]["fields"]
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
                value["recordTypes"]["record"]["fields"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({
                        "id":field,"type":"vocabulary-code","vocabulary":field,
                        "required":true,"classification":"internal"
                    }));
                for profile in [ANALYST, PUBLISHER] {
                    for member in ["readableFields", "filterableFields"] {
                        value["accessProfiles"][profile]["permissions"]["records"][0][member]
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
        vec![(
            "config.removed-key",
            "project.statisticalDatasets[0].period.kind"
        ),],
        "{failure:?}"
    );
    let removed = &failure.diagnostics()[0];
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
        |value| value["recordTypes"]["record"]["fields"][2]["type"] = json!("timestamp"),
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
            value["recordTypes"]["record"]
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
    baseline_source["recordTypes"]["record"]["fields"]
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
    for profile in [ANALYST, PUBLISHER] {
        for member in ["readableFields", "filterableFields"] {
            baseline_source["accessProfiles"][profile]["permissions"]["records"][0][member]
                .as_array_mut()
                .unwrap()
                .extend([json!("score"), json!("unused-score")]);
        }
    }
    baseline_source["statisticalDatasets"][0]["population"] = json!("score eq 1");
    let baseline = compile(&baseline_source).expect("integer population compiles");
    let baseline_digest = &baseline.statistical_datasets()["records-by-category"].definition_digest;

    let mut changed_type_source = baseline_source.clone();
    changed_type_source["recordTypes"]["record"]["fields"][5] = json!({
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
    unrelated_type_source["recordTypes"]["record"]["fields"][6] = json!({
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
    baseline_source["recordTypes"]["record"]["fields"]
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
    baseline_source["recordTypes"]["record"]["derived"] = json!([{
        "id":"statistics-score","sql":"sql/statistics.sql","key":"id",
        "fields":[{
            "id":"score","type":"int64","classification":"internal"
        }]
    }]);
    for profile in [ANALYST, PUBLISHER] {
        for member in ["readableFields", "filterableFields"] {
            baseline_source["accessProfiles"][profile]["permissions"]["records"][0][member]
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
    changed_output_source["recordTypes"]["record"]["derived"][0]["fields"][0] = json!({
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
    changed_source_type["recordTypes"]["record"]["fields"][5] = json!({
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
    unrelated_source_type["recordTypes"]["record"]["fields"][6] = json!({
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
    value["recordTypes"]["record"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"long-name","type":"boolean","required":true,"classification":"internal"
        }));
    for profile in [ANALYST, PUBLISHER] {
        for member in ["readableFields", "filterableFields"] {
            value["accessProfiles"][profile]["permissions"]["records"][0][member]
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
    bounded_string["recordTypes"]["record"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"label","type":"string","minimumLength":8,"maximumLength":12,
            "required":true,"classification":"internal"
        }));
    for profile in [ANALYST, PUBLISHER] {
        for member in ["readableFields", "filterableFields"] {
            bounded_string["accessProfiles"][profile]["permissions"]["records"][0][member]
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
            "list-releases",
            "read-latest-release",
            "read-release-version",
            "read-released-series"
        ])
    );
    assert_eq!(
        dataset["accessProfiles"]["analyst"],
        json!([
            "list-releases",
            "read-latest-release",
            "read-live",
            "read-release-version",
            "read-released-series"
        ])
    );
    assert_eq!(
        dataset["accessProfiles"]["publisher"],
        json!([
            "list-releases",
            "publish-release",
            "read-latest-release",
            "read-release-version",
            "read-released-series",
            "withdraw-release"
        ])
    );

    let openapi = artifact_json(&compiled, "generated/openapi.json");
    let expected_operations = BTreeSet::from([
        "read-live",
        "list-releases",
        "read-released-series",
        "read-latest-release",
        "read-release-version",
        "publish-release",
        "withdraw-release",
    ]);
    assert_eq!(
        dataset["accessProfiles"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|value| value.as_array().unwrap())
            .map(|value| value.as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        expected_operations,
    );
    let mut advertised_operations = BTreeSet::new();
    for (path, item) in openapi["paths"].as_object().unwrap() {
        if !path.starts_with("/v1/statistics/") {
            continue;
        }
        for operation in item.as_object().unwrap().values() {
            let name = operation["x-registry-statisticalOperation"]
                .as_str()
                .unwrap();
            assert_eq!(
                operation["operationId"],
                format!("statistics.records-by-category.{name}")
            );
            advertised_operations.insert(name);
        }
    }
    // The dry run is an HTTP operation of the publisher, not an access
    // grant, so metadata does not list it.
    let mut expected_advertised = expected_operations.clone();
    expected_advertised.insert("dry-run-release");
    assert_eq!(advertised_operations, expected_advertised);
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
            "/v1/statistics/records-by-category/releases/{period}/versions:dry-run".to_owned(),
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
    // A dry run reads no stored version, so a withdrawn one never answers it.
    let dry_run_statuses = openapi["paths"]
        ["/v1/statistics/records-by-category/releases/{period}/versions:dry-run"]["post"]
        ["responses"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        dry_run_statuses,
        BTreeSet::from(["200", "400", "401", "404", "409", "415", "422", "500", "503", "504"])
    );
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
    with_default["accessProfiles"]["reader"]["default"] = json!(true);
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
    let mut presented_source = source();
    presented_source["statisticalDatasets"][0]["display"] =
        json!({"label":"Records grouped by category","description":"Presentation only"});
    let presented = compile(&presented_source).expect("presented dataset compiles");
    assert_eq!(
        presented.statistical_datasets()["records-by-category"]
            .display
            .label
            .as_deref(),
        Some("Records grouped by category")
    );
    assert_ne!(baseline.revision(), presented.revision());
    assert!(
        compiled_registry_change_set(&baseline, &presented, "sha256:before")
            .changes
            .iter()
            .all(|change| { change.code != CompiledRegistryChangeCode::StatisticalDatasetChanged }),
        "statistical presentation remains in artifacts without becoming an access change"
    );

    let mut widened_source = source();
    widened_source["statisticalDatasets"][0]["display"] = json!({"label":"Updated presentation"});
    widened_source["accessProfiles"][OTHER_READER]["display"] =
        json!({"label":"Additional reader"});
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
    value["recordTypes"]["record"]["derived"] = json!([{
        "id":"statistics","sql":"sql/statistics.sql","key":"id",
        "fields":[{"id":"evaluated-category","type":"vocabulary-code","vocabulary":"category","values":["a","b"],"classification":"internal"}]
    }]);
    value["recordTypes"].as_object_mut().unwrap().insert(
        "lookup".to_owned(),
        json!({"primaryDataset":"statistics-test","route":"lookups","mutationMode":"mutable",
            "fields":[{"id":"flag","type":"boolean","required":true,"classification":"internal"}]
        }),
    );
    for profile in [ANALYST, PUBLISHER] {
        value["accessProfiles"][profile]["permissions"]["records"][0]["readableFields"]
            .as_array_mut()
            .unwrap()
            .push(json!("evaluated-category"));
        value["accessProfiles"][profile]["permissions"]["records"][0]["filterableFields"]
            .as_array_mut()
            .unwrap()
            .push(json!("evaluated-category"));
    }
    value["accessProfiles"]["publisher"]["permissions"]["records"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "recordType":"lookup","operations":["list"],"readableFields":["flag"],
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
    additional_read["accessProfiles"][PUBLISHER]["permissions"]["records"][1]["operations"] =
        json!(["get", "list"]);
    let additional_read = compile_with_sql(&additional_read, sql)
        .expect("another ordinary dependency read operation compiles");
    assert_ne!(
        baseline_digest,
        additional_read.statistical_datasets()["records-by-category"].definition_digest,
        "the definition digest binds dependency read operations"
    );

    let mut batch_select = value.clone();
    batch_select["recordTypes"]["lookup"]["batch"] =
        json!({"maximumItems": 10, "maximumBytes": 4096});
    batch_select["accessProfiles"][PUBLISHER]["permissions"]["records"][1] = json!({
        "recordType":"lookup","operations":["patch","batch"],"writableFields":["flag"],
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
    additional_mutation["accessProfiles"][PUBLISHER]["permissions"]["records"][1]["operations"] =
        json!(["list", "patch"]);
    additional_mutation["accessProfiles"][PUBLISHER]["permissions"]["records"][1]
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
            "recordType":"lookup","operations":["create"],"writableFields":["flag"],
            "rowBoundaries":"unrestricted"
        }),
        json!({
            "recordType":"lookup","operations":["patch"],"writableFields":["flag"],
            "rowBoundaries":"unrestricted"
        }),
    ] {
        let mut mutation_only_dependency = value.clone();
        mutation_only_dependency["accessProfiles"][PUBLISHER]["permissions"]["records"][1] =
            permission;
        let failure = compile_with_sql(&mutation_only_dependency, sql)
            .expect_err("a publisher needs an ordinary read operation on every derived dependency");
        assert!(failure.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "breg.statistical-dataset.publisher-dependency-read-required"
                && diagnostic.message.contains("dependency entity `lookup`")
        }));
    }

    let mut missing_dependency_grant = value.clone();
    missing_dependency_grant["accessProfiles"]["publisher"]["permissions"]["records"]
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

    value["accessProfiles"]["publisher"]["requiredPurposes"] = json!(["caller-bound"]);
    let failure =
        compile_with_sql(&value, sql).expect_err("caller-dependent dependency is refused");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "breg.statistical-dataset.publisher-caller-dependent"
            && diagnostic.message.contains("dependency entity `lookup`")
    }));

    let long_entity = "l".repeat(64);
    let lookup = value["recordTypes"]
        .as_object_mut()
        .unwrap()
        .remove("lookup")
        .unwrap();
    value["recordTypes"][&long_entity] = lookup;
    value["recordTypes"][&long_entity]["route"] = json!("long-lookups");
    value["accessProfiles"][PUBLISHER]["permissions"]["records"][1]["recordType"] =
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

#[test]
fn a_statistics_dataset_requires_the_registry_timezone_for_its_current_period() {
    let mut value = source();
    value["project"].as_object_mut().unwrap().remove("timezone");
    value["recordTypes"]["record"]
        .as_object_mut()
        .unwrap()
        .remove("temporal");
    let failure = compile(&value).expect_err("the current period needs today");
    let refusals = errors(&failure)
        .into_iter()
        .filter(|diagnostic| diagnostic.code.starts_with("breg.timezone."))
        .collect::<Vec<_>>();
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert_eq!(refusals[0].code, "breg.timezone.required");
    assert_eq!(refusals[0].path, "project.timezone");
    assert!(
        refusals[0].message.contains("records-by-category"),
        "the refusal names the dataset: {}",
        refusals[0].message
    );
}

fn measures_of(compiled: &registry_breg::CompiledRegistry) -> Value {
    serde_json::to_value(&compiled.statistical_datasets()["records-by-category"].measures)
        .expect("measures serialize")
}

#[test]
fn omitted_measures_compile_to_one_count_measure_named_count() {
    let compiled = compile(&source()).expect("a dataset without measures compiles");
    assert_eq!(
        measures_of(&compiled),
        json!([{"id":"count","type":"count"}])
    );
}

#[test]
fn declared_measures_compile_in_declared_order_with_their_ids() {
    let mut value = source();
    value["statisticalDatasets"][0]["measures"] = json!([{"id":"parcels","type":"count"}]);
    let compiled = compile(&value).expect("a declared count measure compiles");
    assert_eq!(
        measures_of(&compiled),
        json!([{"id":"parcels","type":"count"}])
    );
    let metadata = artifact_json(&compiled, "generated/metadata/registry.json");
    assert_eq!(
        metadata["statisticalDatasets"][0]["measures"],
        json!([{"id":"parcels","type":"count"}])
    );
}

#[test]
fn measure_declarations_are_refused_with_stable_codes() {
    assert_refused(
        |v| v["statisticalDatasets"][0]["measures"] = json!([]),
        "breg.statistical-dataset.measures-empty",
    );
    assert_refused(
        |v| {
            v["statisticalDatasets"][0]["measures"] = json!([
                {"id":"parcels","type":"count"},
                {"id":"parcels","type":"count"}
            ])
        },
        "breg.statistical-dataset.measure-duplicate",
    );
    assert_refused(
        |v| {
            v["statisticalDatasets"][0]["measures"] = json!([
                {"id":"parcels","type":"count"},
                {"id":"holdings","type":"count"}
            ])
        },
        "breg.statistical-dataset.measure-count-duplicate",
    );
}

#[test]
fn a_measure_with_an_unknown_type_or_member_or_a_bad_id_does_not_read() {
    for measures in [
        json!([{"id":"parcels","type":"sum"}]),
        json!([{"id":"parcels","type":"count","field":"x"}]),
        json!([{"id":"Parcels","type":"count"}]),
        json!([{"id":"parcels"}]),
        json!([{"type":"count"}]),
    ] {
        let mut value = source();
        value["statisticalDatasets"][0]["measures"] = measures.clone();
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(
            parse_project_json(&bytes).is_err(),
            "{measures} must not read"
        );
    }
}

#[test]
fn definition_digest_covers_the_measures_including_the_defaulted_one() {
    let digest = |value: &Value| {
        compile(value).expect("compiles").statistical_datasets()["records-by-category"]
            .definition_digest
            .clone()
    };
    let omitted = digest(&source());
    let mut spelled = source();
    spelled["statisticalDatasets"][0]["measures"] = json!([{"id":"count","type":"count"}]);
    assert_eq!(
        omitted,
        digest(&spelled),
        "the default is the spelled value"
    );

    let mut renamed = source();
    renamed["statisticalDatasets"][0]["measures"] = json!([{"id":"parcels","type":"count"}]);
    assert_ne!(omitted, digest(&renamed));
}

/// A dataset served live only, over a decimal and an int64 unit field that the
/// analyst reads but cannot filter on.
fn live_measure_source(measures: Value) -> Value {
    let mut value = source();
    value["recordTypes"]["record"]["fields"]
        .as_array_mut()
        .unwrap()
        .extend([
            json!({"id":"amount","type":"decimal","precision":10,"scale":2,"classification":"internal"}),
            json!({"id":"quantity","type":"int64","classification":"internal"}),
        ]);
    value["accessProfiles"][ANALYST]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .unwrap()
        .extend([json!("amount"), json!("quantity")]);
    grant(&mut value, ANALYST, &["read-live"]);
    grant(&mut value, PUBLISHER, &[]);
    grant(&mut value, READER, &[]);
    value["statisticalDatasets"][0]["measures"] = measures;
    value
}

fn live_measure_digest(measures: Value) -> String {
    compile(&live_measure_source(measures))
        .expect("the live dataset compiles")
        .statistical_datasets()["records-by-category"]
        .definition_digest
        .clone()
}

fn assert_measure_refused(measures: Value, code: &str) {
    assert_refused(|value| *value = live_measure_source(measures), code);
}

#[test]
fn a_sum_and_a_mean_compile_with_the_scale_their_field_gives() {
    let compiled = compile(&live_measure_source(json!([
        {"id":"parcels","type":"count"},
        {"id":"total-amount","type":"sum","field":"amount"},
        {"id":"total-units","type":"sum","field":"quantity"},
        {"id":"average-amount","type":"mean","field":"amount","scale":3},
        {"id":"average-units","type":"mean","field":"quantity","scale":0}
    ])))
    .expect("a live sum and mean compile without a filterable measure field");
    assert_eq!(
        measures_of(&compiled),
        json!([
            {"id":"parcels","type":"count"},
            {"id":"total-amount","type":"sum","field":"amount","scale":2},
            {"id":"total-units","type":"sum","field":"quantity","scale":0},
            {"id":"average-amount","type":"mean","field":"amount","scale":3},
            {"id":"average-units","type":"mean","field":"quantity","scale":0}
        ])
    );
    let metadata = artifact_json(&compiled, "generated/metadata/registry.json");
    assert_eq!(
        metadata["statisticalDatasets"][0]["measures"],
        measures_of(&compiled)
    );
    let dataset = &compiled.statistical_datasets()["records-by-category"];
    assert!(dataset.referenced_fields.contains("amount"));
    assert!(dataset.referenced_fields.contains("quantity"));
}

#[test]
fn a_measure_field_is_checked_like_any_field_the_dataset_reads() {
    assert_measure_refused(
        json!([{"id":"total","type":"sum","field":"missing"}]),
        "breg.statistical-dataset.field-unknown",
    );
    assert_refused(
        |value| {
            *value = live_measure_source(json!([{"id":"total","type":"sum","field":"secret"}]));
            value["recordTypes"]["record"]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "id":"secret","type":"string","maximumLength":80,"encrypted":true,
                    "classification":"restricted"
                }));
            value["accessProfiles"][ANALYST]["permissions"]["records"][0]["readableFields"]
                .as_array_mut()
                .unwrap()
                .push(json!("secret"));
        },
        "breg.statistical-dataset.field-encrypted",
    );
    for field in ["category", "active", "event-date"] {
        assert_measure_refused(
            json!([{"id":"total","type":"sum","field":field}]),
            "breg.statistical-dataset.measure-field-type",
        );
        assert_measure_refused(
            json!([{"id":"average","type":"mean","field":field,"scale":1}]),
            "breg.statistical-dataset.measure-field-type",
        );
    }
}

#[test]
fn every_live_reader_of_a_sum_or_mean_must_read_its_field() {
    for measure in [
        json!({"id":"total","type":"sum","field":"amount"}),
        json!({"id":"average","type":"mean","field":"amount","scale":1}),
    ] {
        let mut value = live_measure_source(json!([measure]));
        value["accessProfiles"][ANALYST]["permissions"]["records"][0]["readableFields"] = json!([
            "active",
            "category",
            "event-date",
            "valid-from",
            "valid-to",
            "quantity"
        ]);
        let failure = compile(&value).expect_err("the analyst cannot read the measure field");
        assert!(
            failure.diagnostics().iter().any(|diagnostic| {
                diagnostic.code == "breg.statistical-dataset.measure-field-not-readable"
                    && diagnostic.message.contains("amount")
                    && diagnostic.message.contains("analyst")
            }),
            "{:?}",
            failure.diagnostics()
        );
    }

    // A second live profile that lacks the field is refused as well.
    let mut second = live_measure_source(json!([{"id":"total","type":"sum","field":"amount"}]));
    grant(&mut second, READER, &["read-live"]);
    second["accessProfiles"][READER]["permissions"]["records"] = json!([{
        "recordType":"record","operations":["list"],
        "readableFields":["active","category","event-date","valid-from","valid-to"],
        "filterableFields":["active","category","event-date","valid-from","valid-to"],
        "allowCount":true,"rowBoundaries":"unrestricted"
    }]);
    let failure = compile(&second).expect_err("the second reader cannot read the measure field");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "breg.statistical-dataset.measure-field-not-readable"
            && diagnostic.message.contains("`reader`")
    }));

    // A count needs no readable field.
    let mut count_only = live_measure_source(json!([{"id":"count","type":"count"}]));
    count_only["accessProfiles"][ANALYST]["permissions"]["records"][0]["readableFields"] =
        json!(["active", "category", "event-date", "valid-from", "valid-to"]);
    compile(&count_only).expect("a count reads no measure field");
}

#[test]
fn a_dataset_with_a_sum_or_mean_is_refused_any_release_grant() {
    let measures = json!([
        {"id":"parcels","type":"count"},
        {"id":"total","type":"sum","field":"amount"}
    ]);
    let mut published = live_measure_source(measures.clone());
    grant(&mut published, PUBLISHER, &["publish", "read-releases"]);
    let failure = compile(&published).expect_err("a sum cannot be published");
    let refusal = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.statistical-dataset.sum-release-held")
        .unwrap_or_else(|| panic!("missing refusal: {:?}", failure.diagnostics()));
    assert!(refusal
        .message
        .contains("statistical dataset `records-by-category`"));
    assert!(refusal.message.contains("held"));
    assert!(refusal.message.contains("read-live"));

    let mean = json!([{"id":"average","type":"mean","field":"amount","scale":2}]);
    let mut read_releases = live_measure_source(mean);
    grant(&mut read_releases, ANALYST, &["read-live", "read-releases"]);
    let failure = compile(&read_releases).expect_err("a mean has no releases to read");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "breg.statistical-dataset.measure-release-unsupported"
    }));

    // The same grants over counts alone still compile.
    let mut counts = live_measure_source(json!([{"id":"parcels","type":"count"}]));
    grant(&mut counts, PUBLISHER, &["publish", "read-releases"]);
    grant(&mut counts, ANALYST, &["read-live", "read-releases"]);
    compile(&counts).expect("a count dataset is published");
}

#[test]
fn a_sum_or_mean_that_is_not_well_formed_does_not_read() {
    for measures in [
        json!([{"id":"total","type":"sum"}]),
        json!([{"id":"total","type":"sum","field":"amount","scale":2}]),
        json!([{"id":"average","type":"mean","field":"amount"}]),
        json!([{"id":"average","type":"mean","scale":1}]),
        json!([{"id":"average","type":"mean","field":"amount","scale":-1}]),
        json!([{"id":"average","type":"mean","field":"amount","scale":39}]),
        json!([{"id":"average","type":"mean","field":"amount","scale":"1"}]),
        json!([{"id":"average","type":"mean","field":"amount","scale":1.5}]),
        json!([{"id":"average","type":"mean","field":"amount","scale":1,"extra":true}]),
        json!([{"id":"total","type":"median","field":"amount"}]),
    ] {
        let value = live_measure_source(measures.clone());
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(
            parse_project_json(&bytes).is_err(),
            "{measures} must not read"
        );
    }
    for scale in [0, 38] {
        let value = live_measure_source(
            json!([{"id":"average","type":"mean","field":"amount","scale":scale}]),
        );
        compile(&value).expect("the bounds of scale are admitted");
    }
}

#[test]
fn the_definition_digest_covers_the_type_field_and_scale_of_a_measure() {
    let sum_amount = live_measure_digest(json!([{"id":"m","type":"sum","field":"amount"}]));
    let sum_quantity = live_measure_digest(json!([{"id":"m","type":"sum","field":"quantity"}]));
    let mean_two =
        live_measure_digest(json!([{"id":"m","type":"mean","field":"amount","scale":2}]));
    let mean_three =
        live_measure_digest(json!([{"id":"m","type":"mean","field":"amount","scale":3}]));
    let mean_quantity =
        live_measure_digest(json!([{"id":"m","type":"mean","field":"quantity","scale":2}]));
    let digests = BTreeSet::from([
        sum_amount.clone(),
        sum_quantity,
        mean_two,
        mean_three,
        mean_quantity,
    ]);
    assert_eq!(digests.len(), 5, "every measure change changes the digest");
    assert_eq!(
        sum_amount,
        live_measure_digest(json!([{"id":"m","type":"sum","field":"amount"}])),
        "the digest is stable"
    );
}

#[test]
fn a_measure_field_type_change_changes_the_definition_digest() {
    let measures = json!([{"id":"m","type":"sum","field":"amount"}]);
    let baseline = live_measure_digest(measures.clone());
    let mut changed = live_measure_source(measures);
    changed["recordTypes"]["record"]["fields"][5]["scale"] = json!(3);
    let digest = compile(&changed).unwrap().statistical_datasets()["records-by-category"]
        .definition_digest
        .clone();
    assert_ne!(baseline, digest);
}

const EXACT_NOT_PUBLIC: &str = "breg.statistical-dataset.exact-release-not-public";

/// A register whose every record type and field is public, read live by the
/// analyst and published by the publisher with exact values.
fn public_register_source(measures: Value) -> Value {
    let mut value = source();
    value["recordTypes"]["record"]["classification"] = json!("public");
    let fields = value["recordTypes"]["record"]["fields"]
        .as_array_mut()
        .unwrap();
    fields.extend([
        json!({"id":"amount","type":"decimal","precision":10,"scale":2,"classification":"internal"}),
        json!({"id":"quantity","type":"int64","classification":"internal"}),
    ]);
    for field in fields {
        field["classification"] = json!("public");
    }
    for profile in [ANALYST, PUBLISHER] {
        value["accessProfiles"][profile]["permissions"]["records"][0]["readableFields"]
            .as_array_mut()
            .unwrap()
            .extend([json!("amount"), json!("quantity")]);
    }
    value["statisticalDatasets"][0]["measures"] = measures;
    value["statisticalDatasets"][0]["disclosure"] = json!({"type":"exact-public-values"});
    value
}

fn public_register_measures() -> Value {
    json!([
        {"id":"facilities","type":"count"},
        {"id":"total-amount","type":"sum","field":"amount"},
        {"id":"average-amount","type":"mean","field":"amount","scale":2}
    ])
}

fn exact_not_public(failure: &CompileFailure) -> Vec<&Diagnostic> {
    failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == EXACT_NOT_PUBLIC)
        .collect()
}

fn assert_exact_refusal_names(value: &Value, item: &str, classification: &str) {
    let failure = compile(value).expect_err("a non-public item is refused");
    let refusals = exact_not_public(&failure);
    assert_eq!(refusals.len(), 1, "{item}: {:?}", failure.diagnostics());
    let refusal = refusals[0];
    assert!(
        refusal
            .path
            .ends_with("statisticalDatasets[id=records-by-category].disclosure.type"),
        "{}",
        refusal.path
    );
    assert!(
        refusal.message.contains(&format!("`{item}`"))
            && refusal.message.contains(&format!("`{classification}`"))
            && refusal.message.contains("minimum-count-and-rounding"),
        "{}",
        refusal.message
    );
}

#[test]
fn an_all_public_dataset_compiles_with_exact_values_and_releases() {
    let compiled = compile(&public_register_source(public_register_measures()))
        .expect("an all-public register releases exact values");
    let dataset = &compiled.statistical_datasets()["records-by-category"];
    assert!(dataset.releases.is_some());
    assert_eq!(
        serde_json::to_value(dataset.disclosure).unwrap(),
        json!({"method":"exact-public-values"})
    );
    assert_eq!(measures_of(&compiled).as_array().unwrap().len(), 3);
}

#[test]
fn exact_values_are_refused_per_item_that_is_not_classified_public() {
    let one = |mutate: &dyn Fn(&mut Value)| {
        let mut value = public_register_source(public_register_measures());
        mutate(&mut value);
        value
    };
    let field = |value: &mut Value, id: &str, classification: &str| {
        for candidate in value["recordTypes"]["record"]["fields"]
            .as_array_mut()
            .unwrap()
        {
            if candidate["id"] == id {
                candidate["classification"] = json!(classification);
            }
        }
    };
    assert_exact_refusal_names(
        &one(&|value| value["recordTypes"]["record"]["classification"] = json!("internal")),
        "record",
        "internal",
    );
    assert_exact_refusal_names(
        &one(&|value| field(value, "category", "internal")),
        "category",
        "internal",
    );
    assert_exact_refusal_names(
        &one(&|value| field(value, "amount", "restricted")),
        "amount",
        "restricted",
    );
    assert_exact_refusal_names(
        &one(&|value| field(value, "active", "internal")),
        "active",
        "internal",
    );
    assert_exact_refusal_names(
        &one(&|value| field(value, "event-date", "internal")),
        "event-date",
        "internal",
    );
}

#[test]
fn exact_values_over_an_internal_register_name_every_item_to_reclassify() {
    let mut value = live_measure_source(json!([
        {"id":"facilities","type":"count"},
        {"id":"total-amount","type":"sum","field":"amount"}
    ]));
    value["statisticalDatasets"][0]["disclosure"] = json!({"type":"exact-public-values"});
    let failure = compile(&value).expect_err("an internal register is refused");
    let named = exact_not_public(&failure)
        .iter()
        .map(|diagnostic| {
            ["record", "active", "amount", "category", "event-date"]
                .into_iter()
                .filter(|item| diagnostic.message.contains(&format!("`{item}`")))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    // The dataset is read live only, so the refusal does not depend on a publisher.
    assert_eq!(
        named,
        vec![
            vec!["active"],
            vec!["amount"],
            vec!["category"],
            vec!["event-date"],
            vec!["record"]
        ],
        "{:?}",
        failure.diagnostics()
    );
}

#[test]
fn a_derived_dimension_over_a_non_public_source_entity_is_refused() {
    let mut value = public_register_source(json!([{"id":"facilities","type":"count"}]));
    value["recordTypes"]["record"]["derived"] = json!([{
        "id":"statistics","sql":"sql/statistics.sql","key":"id",
        "fields":[{"id":"evaluated-category","type":"vocabulary-code","vocabulary":"category","values":["a","b"],"classification":"public"}]
    }]);
    value["recordTypes"].as_object_mut().unwrap().insert(
        "lookup".to_owned(),
        json!({"primaryDataset":"statistics-test","route":"lookups","mutationMode":"mutable",
            "classification":"internal",
            "fields":[{"id":"flag","type":"boolean","required":true,"classification":"public"}]
        }),
    );
    for profile in [ANALYST, PUBLISHER] {
        for member in ["readableFields", "filterableFields"] {
            value["accessProfiles"][profile]["permissions"]["records"][0][member]
                .as_array_mut()
                .unwrap()
                .push(json!("evaluated-category"));
        }
    }
    value["accessProfiles"][PUBLISHER]["permissions"]["records"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "recordType":"lookup","operations":["list"],"readableFields":["flag"],
            "filterableFields":["flag"],"allowCount":true,"rowBoundaries":"unrestricted"
        }));
    value["statisticalDatasets"][0]["dimensions"] = json!(["evaluated-category"]);
    let sql = "SELECT r.id AS id, CASE WHEN l.flag THEN 'a' ELSE 'b' END AS evaluated_category FROM registry_source.record r JOIN registry_source.lookup l ON l.id = r.id";
    let failure = compile_with_sql(&value, sql).expect_err("an internal source entity is refused");
    let refusals = exact_not_public(&failure);
    assert_eq!(refusals.len(), 1, "{:?}", failure.diagnostics());
    assert!(
        refusals[0].message.contains("`lookup`") && refusals[0].message.contains("`internal`"),
        "{}",
        refusals[0].message
    );

    value["recordTypes"]["lookup"]["classification"] = json!("public");
    compile_with_sql(&value, sql).expect("a public source entity is admitted");
}

#[test]
fn the_publisher_must_read_the_measure_fields_of_an_exact_release() {
    let mut value = public_register_source(public_register_measures());
    value["accessProfiles"][PUBLISHER]["permissions"]["records"][0]["readableFields"] = json!([
        "active",
        "category",
        "event-date",
        "valid-from",
        "valid-to",
        "quantity"
    ]);
    let failure = compile(&value).expect_err("the publisher cannot read the measure field");
    let refusals = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| {
            diagnostic.code == "breg.statistical-dataset.measure-field-not-readable"
                && diagnostic.message.contains("amount")
                && diagnostic.message.contains("publisher")
        })
        .count();
    assert_eq!(refusals, 1, "{:?}", failure.diagnostics());
}

#[test]
fn minimum_count_and_rounding_still_refuses_a_released_sum_and_names_the_exact_alternative() {
    let mut value = public_register_source(public_register_measures());
    value["statisticalDatasets"][0]["disclosure"] =
        json!({"type":"minimum-count-and-rounding","minimumCount":5,"roundingBase":5});
    let failure = compile(&value).expect_err("a sum cannot be released with rounding");
    let refusal = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| {
            diagnostic.code == "breg.statistical-dataset.measure-release-unsupported"
        })
        .unwrap_or_else(|| panic!("missing refusal: {:?}", failure.diagnostics()));
    assert!(refusal.message.contains("exact-public-values"));
    assert!(exact_not_public(&failure).is_empty());
}

#[test]
fn a_disclosure_block_without_a_type_is_refused_when_the_project_is_read() {
    for disclosure in [
        json!({"minimumCount":5,"roundingBase":5}),
        json!({}),
        json!({"type":"exact-public-values","minimumCount":5}),
        json!({"type":"minimum-count-and-rounding"}),
        json!({"type":"public"}),
    ] {
        let mut value = source();
        value["statisticalDatasets"][0]["disclosure"] = disclosure.clone();
        let refusals = read_refusals(&value);
        assert!(
            refusals
                .iter()
                .any(|(_, path, _)| path.starts_with("project.statisticalDatasets[0].disclosure")),
            "{disclosure}: {refusals:?}"
        );
    }
}

#[test]
fn the_definition_digest_differs_between_disclosure_methods() {
    let digest = |disclosure: Value| {
        let mut value = public_register_source(json!([{"id":"count","type":"count"}]));
        value["statisticalDatasets"][0]["disclosure"] = disclosure;
        compile(&value).expect("compiles").statistical_datasets()["records-by-category"]
            .definition_digest
            .clone()
    };
    let exact = digest(json!({"type":"exact-public-values"}));
    let rounded =
        digest(json!({"type":"minimum-count-and-rounding","minimumCount":5,"roundingBase":5}));
    let other =
        digest(json!({"type":"minimum-count-and-rounding","minimumCount":5,"roundingBase":10}));
    assert_eq!(
        BTreeSet::from([exact, rounded, other]).len(),
        3,
        "the method and its parameters change the digest"
    );
}

const STATISTICIAN: &str = "statistician";

/// A minimum-count dataset with a sum and a mean, no publisher, a profile
/// that reads exact values and holds no record access, and the analyst as
/// the profile the exact reads compute under.
fn exact_source() -> Value {
    let mut value = live_measure_source(json!([
        {"id":"count","type":"count"},
        {"id":"total","type":"sum","field":"amount"},
        {"id":"average","type":"mean","field":"amount","scale":1}
    ]));
    grant(&mut value, ANALYST, &[]);
    value["accessProfiles"]["statistician"] = json!({
        "principalClaim":"principal","requiredScopes":"unrestricted",
        "permissions":{"datasets":[{"dataset":"records-by-category","operations":["read-exact"]}]}
    });
    value["statisticalDatasets"][0]["exactReads"] = json!({"accessProfile":"analyst"});
    value
}

fn assert_exact_refused(mutator: impl FnOnce(&mut Value), code: &str, path: &str) {
    let mut value = exact_source();
    mutator(&mut value);
    let failure = compile(&value).expect_err("the exact reads are refused");
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code && diagnostic.path == path),
        "missing {code} at {path}: {:?}",
        failure.diagnostics()
    );
}

const EXACT: &str = "breg.statistical-dataset.exact-reads";
const ROOT: &str = "statisticalDatasets[id=records-by-category]";

#[test]
fn exact_reads_compile_without_a_publisher_or_record_access() {
    let compiled = compile(&exact_source()).expect("the exact dataset compiles");
    let dataset = &compiled.statistical_datasets()["records-by-category"];
    let exact = dataset.exact_reads.as_ref().expect("exact reads compile");
    assert_eq!(exact.access_profile, "analyst");
    assert_eq!(
        exact.readers.iter().cloned().collect::<Vec<_>>(),
        ["statistician"]
    );
    assert!(dataset.releases.is_none());
    assert!(dataset.live_profiles.is_empty());
    assert!(
        dataset.access_profiles.contains_key("statistician"),
        "the reader authenticates for the dataset"
    );
}

#[test]
fn exact_reads_stay_out_of_the_definition_digest() {
    let with = compile(&exact_source()).unwrap();
    let mut without = exact_source();
    grant(&mut without, STATISTICIAN, &[]);
    grant(&mut without, ANALYST, &["read-live"]);
    without["statisticalDatasets"][0]
        .as_object_mut()
        .unwrap()
        .remove("exactReads");
    let without = compile(&without).unwrap();
    assert_eq!(
        with.statistical_datasets()["records-by-category"].definition_digest,
        without.statistical_datasets()["records-by-category"].definition_digest
    );
}

#[test]
fn exact_reads_are_refused_when_missing_unused_or_unknown() {
    assert_exact_refused(
        |v| {
            v["statisticalDatasets"][0]
                .as_object_mut()
                .unwrap()
                .remove("exactReads");
        },
        &format!("{EXACT}-missing"),
        ROOT,
    );
    assert_exact_refused(
        |v| grant(v, STATISTICIAN, &["read-releases"]),
        &format!("{EXACT}-unused"),
        &format!("{ROOT}.exactReads"),
    );
    assert_exact_refused(
        |v| v["statisticalDatasets"][0]["exactReads"]["accessProfile"] = json!("nobody"),
        &format!("{EXACT}-profile-unknown"),
        &format!("{ROOT}.exactReads.accessProfile"),
    );
}

#[test]
fn the_exact_reads_profile_is_proven_like_a_publisher() {
    let anchor = format!("{ROOT}.exactReads.accessProfile");
    // A caller-dependent anchor.
    assert_exact_refused(
        |v| {
            v["accessProfiles"][ANALYST]["permissions"]["records"][0]["rowBoundaries"] =
                json!([{"field":"category","claim":"categories","operator":"in"}]);
        },
        &format!("{EXACT}-caller-dependent"),
        &anchor,
    );
    // An anchor without the count grant.
    assert_exact_refused(
        |v| v["accessProfiles"][ANALYST]["permissions"]["records"][0]["allowCount"] = json!(false),
        &format!("{EXACT}-count-grant-count-required"),
        &anchor,
    );
    // An anchor that cannot read a sum field.
    assert_exact_refused(
        |v| {
            v["accessProfiles"][ANALYST]["permissions"]["records"][0]["readableFields"] =
                json!(["active", "category", "event-date", "valid-from", "valid-to"]);
        },
        &format!("{EXACT}-measure-field-not-readable"),
        &anchor,
    );
    // The publisher codes keep their meaning.
    let failure = {
        let mut v = exact_source();
        v["accessProfiles"][ANALYST]["permissions"]["records"][0]["allowCount"] = json!(false);
        compile(&v).unwrap_err()
    };
    assert!(failure.diagnostics().iter().all(|diagnostic| {
        !diagnostic.code.contains("publisher")
            && diagnostic.message.contains("exactReads profile `analyst`")
            || !diagnostic.code.starts_with(EXACT)
    }));
}

#[test]
fn measure_ids_that_differ_only_by_a_separator_are_refused() {
    let value = live_measure_source(json!([
        {"id":"mean-amount","type":"mean","field":"amount","scale":1},
        {"id":"mean_amount","type":"mean","field":"quantity","scale":1}
    ]));
    let refusals = read_refusals(&value);
    assert!(
        refusals.iter().any(|(code, path, message)| {
            code == "breg.statistical-dataset.measure-id-collision"
                && path == "project.statisticalDatasets[0].measures[1].id"
                && message.contains("`mean-amount`")
                && message.contains("`mean_amount`")
        }),
        "{refusals:#?}"
    );
}

#[test]
fn a_standing_agent_cannot_read_exact_or_anchor_exact_reads() {
    assert_exact_refused(
        |v| {
            v["accessProfiles"][STATISTICIAN]["actorKind"] = json!("agent");
            v["accessProfiles"][STATISTICIAN]["requesterClients"] = json!(["agent-client"]);
        },
        "breg.access-profile.standing-agent-read-exact-forbidden",
        "project.accessProfiles[id=statistician].permissions.datasets[dataset=records-by-category].operations",
    );
    assert_exact_refused(
        |v| {
            v["accessProfiles"][ANALYST]["actorKind"] = json!("agent");
            v["accessProfiles"][ANALYST]["requesterClients"] = json!(["agent-client"]);
        },
        &format!("{EXACT}-profile-agent"),
        &format!("{ROOT}.exactReads.accessProfile"),
    );
    assert_exact_refused(
        |v| {
            v["accessProfiles"][ANALYST]["actorKind"] = json!("agent");
            v["accessProfiles"][ANALYST]["requesterClients"] = json!(["agent-client"]);
            v["accessProfiles"][ANALYST]["requiredPurposes"] = json!(["statistics"]);
            v["accessProfiles"][ANALYST]["requiredScopes"] = json!(["statistics:read"]);
            v["accessProfiles"][ANALYST]["taskGrant"] =
                json!({"sourceIssuer":"https://issuer.example.test"});
        },
        &format!("{EXACT}-profile-agent"),
        &format!("{ROOT}.exactReads.accessProfile"),
    );
}

/// The exact source with the project profile `stats` (a dataset grant holder
/// with no record permission) and a module contributing the unit profile of the
/// same id. `profile` is merged into the module's profile.
fn exact_source_with_unit_profile(profile: Value) -> (Value, Value) {
    let mut project = exact_source();
    project["modules"] = json!({"stats-module": {"version":"1"}});
    project["accessProfiles"]["stats"] = json!({
        "principalClaim":"principal","requiredScopes":"unrestricted","permissions":{}
    });
    let mut contributed = json!({
        "principalClaim":"principal","requiredScopes":"unrestricted",
        "operations":["list"],
        "readableFields":["active","category","event-date","valid-from","valid-to","amount","quantity"],
        "filterableFields":["active","category","event-date","valid-from","valid-to"],
        "allowCount":true,"rowBoundaries":"unrestricted"
    });
    contributed
        .as_object_mut()
        .unwrap()
        .extend(profile.as_object().unwrap().clone());
    let module = json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
        "kind":"BRegModule","id":"stats-module","version":"1",
        "extendRecordTypes":{"record": {"accessProfiles":{"stats":contributed}}}
    });
    (project, module)
}

fn compile_with_module(
    project: &Value,
    module: &Value,
) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    let project =
        parse_project_json(&serde_json::to_vec(project).unwrap()).expect("project parses");
    let module = parse_module_json(&serde_json::to_vec(module).unwrap()).expect("module parses");
    compile_project(&project, &[module], CompileProfile::Authoring)
}

fn standing_agent_unit_profile() -> Value {
    json!({"actorKind":"agent","requesterClients":["agent-client"]})
}

#[test]
fn exact_reads_resolve_a_profile_a_module_contributes_to_the_unit() {
    let (mut project, module) = exact_source_with_unit_profile(json!({}));
    project["accessProfiles"]
        .as_object_mut()
        .unwrap()
        .remove("stats");
    project["statisticalDatasets"][0]["exactReads"] = json!({"accessProfile":"stats"});
    let compiled = compile_with_module(&project, &module)
        .expect("a unit profile a module contributes anchors exactReads");
    assert_eq!(
        compiled.statistical_datasets()["records-by-category"]
            .exact_reads
            .as_ref()
            .expect("exact reads compile")
            .access_profile,
        "stats"
    );
}

#[test]
fn an_agent_unit_profile_cannot_anchor_exact_reads() {
    let (mut project, module) = exact_source_with_unit_profile(standing_agent_unit_profile());
    project["statisticalDatasets"][0]["exactReads"] = json!({"accessProfile":"stats"});
    let failure =
        compile_with_module(&project, &module).expect_err("an agent unit profile is refused");
    assert!(
        failure.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == format!("{EXACT}-profile-agent")
                && diagnostic.path == format!("{ROOT}.exactReads.accessProfile")
        }),
        "missing the refusal: {:?}",
        failure.diagnostics()
    );

    // A module cannot contribute a task grant, so a unit profile with one is
    // always a project profile's, which the project-profile check covers.
    let (project, module) = exact_source_with_unit_profile(json!({
        "actorKind":"agent","requesterClients":["agent-client"],
        "requiredPurposes":["statistics"],"requiredScopes":["statistics:read"],
        "taskGrant":{
            "sourceIssuer":"https://issuer.example.test",
            "permissions":[{"collection":"records","operations":["list"]}]
        }
    }));
    let failure =
        compile_with_module(&project, &module).expect_err("a module task grant is refused");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.access-profile.task-grant-module-forbidden"));
}

#[test]
fn read_exact_names_the_unit_profile_that_makes_it_a_standing_agent() {
    let (mut project, module) = exact_source_with_unit_profile(standing_agent_unit_profile());
    project["accessProfiles"]["stats"]["permissions"] = json!({
        "datasets":[{"dataset":"records-by-category","operations":["read-exact"]}]
    });
    let failure = compile_with_module(&project, &module)
        .expect_err("a read-exact holder whose unit profile is a standing agent is refused");
    assert!(
        failure.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "breg.access-profile.standing-agent-read-exact-forbidden"
                && diagnostic.path == "recordTypes[id=record].accessProfiles[id=stats]"
        }),
        "missing the refusal at the unit profile: {:?}",
        failure.diagnostics()
    );
}

/// `live_measure_source` plus an `owner` reference field on the unit, which the
/// analyst reads but cannot filter on, to a second record type.
fn distinct_source(measures: Value) -> Value {
    let mut value = live_measure_source(measures);
    value["recordTypes"].as_object_mut().unwrap().insert(
        "owner".to_owned(),
        json!({"primaryDataset":"statistics-test","route":"owners","mutationMode":"mutable",
            "fields":[{"id":"name","type":"string","maximumLength":80,"classification":"internal"}]
        }),
    );
    value["recordTypes"]["record"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"id":"owner","type":"reference","target":"owner","classification":"internal"}),
        );
    value["accessProfiles"][ANALYST]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("owner"));
    value
}

fn distinct_measures() -> Value {
    json!([
        {"id":"parcels","type":"count"},
        {"id":"owners","type":"distinct-count","field":"owner"}
    ])
}

fn assert_distinct_refused(value: &Value, code: &str, path: &str) {
    let failure = compile(value).expect_err("the dataset is refused");
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code && diagnostic.path.ends_with(path)),
        "missing {code} at {path}: {:?}",
        failure.diagnostics()
    );
}

#[test]
fn a_distinct_count_over_a_reference_field_compiles() {
    let compiled = compile(&distinct_source(distinct_measures()))
        .expect("a distinct count over a reference field compiles");
    assert_eq!(
        measures_of(&compiled),
        json!([
            {"id":"parcels","type":"count"},
            {"id":"owners","type":"distinct-count","field":"owner"}
        ])
    );
    let metadata = artifact_json(&compiled, "generated/metadata/registry.json");
    assert_eq!(
        metadata["statisticalDatasets"][0]["measures"],
        measures_of(&compiled)
    );
    assert!(compiled.statistical_datasets()["records-by-category"]
        .referenced_fields
        .contains("owner"));
}

#[test]
fn a_distinct_count_field_must_be_a_known_reference_field() {
    for field in ["category", "amount", "quantity", "active", "event-date"] {
        assert_distinct_refused(
            &distinct_source(json!([{"id":"owners","type":"distinct-count","field":field}])),
            "breg.statistical-dataset.measure-field-type",
            "measures[0].field",
        );
    }
    let failure = compile(&distinct_source(
        json!([{"id":"owners","type":"distinct-count","field":"category"}]),
    ))
    .unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.message.contains("reference")));
    assert_distinct_refused(
        &distinct_source(json!([{"id":"owners","type":"distinct-count","field":"missing"}])),
        "breg.statistical-dataset.field-unknown",
        "",
    );
}

#[test]
fn two_distinct_counts_over_one_field_are_refused_and_over_two_fields_are_not() {
    let mut value = distinct_source(json!([
        {"id":"owners","type":"distinct-count","field":"owner"},
        {"id":"holders","type":"distinct-count","field":"owner"}
    ]));
    assert_distinct_refused(
        &value,
        "breg.statistical-dataset.measure-distinct-count-duplicate",
        "measures[1].field",
    );
    value["recordTypes"]["record"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"id":"agent","type":"reference","target":"owner","classification":"internal"}),
        );
    value["accessProfiles"][ANALYST]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("agent"));
    value["statisticalDatasets"][0]["measures"] = json!([
        {"id":"owners","type":"distinct-count","field":"owner"},
        {"id":"agents","type":"distinct-count","field":"agent"}
    ]);
    compile(&value).expect("distinct counts over different fields compile");
}

#[test]
fn a_distinct_count_limits_the_dataset_to_four_dimensions() {
    let with_dimensions = |measures: Value, count: usize| {
        let mut value = distinct_source(measures);
        let fields = value["recordTypes"]["record"]["fields"]
            .as_array_mut()
            .unwrap();
        let mut names = vec![json!("category")];
        for index in 1..count {
            let id = format!("flag-{index}");
            fields.push(
                json!({"id":id,"type":"boolean","required":true,"classification":"internal"}),
            );
            names.push(json!(id));
        }
        for member in ["readableFields", "filterableFields"] {
            let granted = value["accessProfiles"][ANALYST]["permissions"]["records"][0][member]
                .as_array_mut()
                .unwrap();
            granted.extend(names.iter().skip(1).cloned());
        }
        value["statisticalDatasets"][0]["dimensions"] = json!(names);
        value
    };
    compile(&with_dimensions(distinct_measures(), 4)).expect("four dimensions are accepted");
    let failure = compile(&with_dimensions(distinct_measures(), 5)).expect_err("five are refused");
    let refusal = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.statistical-dataset.non-additive-dimensions")
        .unwrap_or_else(|| panic!("missing refusal: {:?}", failure.diagnostics()));
    assert!(refusal
        .path
        .ends_with("statisticalDatasets[id=records-by-category].dimensions"));
    assert!(refusal.message.contains(
        "a dataset with a distinct count, a percentile or a released sum declares at most 4 dimensions, because its totals are computed over the records, not the base cells"
    ));
    compile(&with_dimensions(
        json!([{"id":"parcels","type":"count"},{"id":"total","type":"sum","field":"amount"}]),
        5,
    ))
    .expect("five dimensions without a distinct count are accepted");
}

#[test]
fn every_live_reader_publisher_and_exact_profile_must_read_a_distinct_count_field() {
    let unreadable = json!(["active", "category", "event-date", "valid-from", "valid-to"]);
    // The live reader.
    let mut live = distinct_source(distinct_measures());
    live["accessProfiles"][ANALYST]["permissions"]["records"][0]["readableFields"] =
        unreadable.clone();
    let failure = compile(&live).expect_err("the analyst cannot read the field");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "breg.statistical-dataset.measure-field-not-readable"
            && diagnostic.message.contains("owner")
            && diagnostic.message.contains("analyst")
    }));
    // The publisher of an exact release.
    let mut published = distinct_source(distinct_measures());
    published["recordTypes"]["record"]["classification"] = json!("public");
    for field in published["recordTypes"]["record"]["fields"]
        .as_array_mut()
        .unwrap()
    {
        field["classification"] = json!("public");
    }
    grant(&mut published, PUBLISHER, &["publish", "read-releases"]);
    published["statisticalDatasets"][0]["disclosure"] = json!({"type":"exact-public-values"});
    published["accessProfiles"][PUBLISHER]["permissions"]["records"][0]["readableFields"] =
        unreadable.clone();
    let failure = compile(&published).expect_err("the publisher cannot read the field");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "breg.statistical-dataset.measure-field-not-readable"
            && diagnostic.message.contains("owner")
            && diagnostic.message.contains("publisher")
    }));
    // The exactReads profile.
    let mut exact = distinct_source(distinct_measures());
    grant(&mut exact, ANALYST, &[]);
    exact["accessProfiles"]["statistician"] = json!({
        "principalClaim":"principal","requiredScopes":"unrestricted",
        "permissions":{"datasets":[{"dataset":"records-by-category","operations":["read-exact"]}]}
    });
    exact["statisticalDatasets"][0]["exactReads"] = json!({"accessProfile":"analyst"});
    compile(&exact).expect("the exactReads profile reads the field");
    exact["accessProfiles"][ANALYST]["permissions"]["records"][0]["readableFields"] = unreadable;
    assert_distinct_refused(
        &exact,
        "breg.statistical-dataset.exact-reads-measure-field-not-readable",
        "exactReads.accessProfile",
    );
}

#[test]
fn a_distinct_count_is_released_with_rounding_but_a_sum_beside_it_is_not() {
    let mut value = distinct_source(distinct_measures());
    grant(&mut value, ANALYST, &["read-live", "read-releases"]);
    grant(&mut value, PUBLISHER, &["publish", "read-releases"]);
    value["accessProfiles"][PUBLISHER]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("owner"));
    compile(&value).expect("a count and a distinct count release with rounding");

    value["statisticalDatasets"][0]["measures"] = json!([
        {"id":"parcels","type":"count"},
        {"id":"owners","type":"distinct-count","field":"owner"},
        {"id":"total","type":"sum","field":"amount"}
    ]);
    let failure = compile(&value).expect_err("a sum cannot be released with rounding");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.statistical-dataset.sum-release-held"));
    assert!(!failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "breg.statistical-dataset.measure-release-unsupported"
    }));
}

#[test]
fn the_publisher_of_a_rounded_release_must_read_a_distinct_count_field() {
    let mut value = distinct_source(distinct_measures());
    grant(&mut value, ANALYST, &["read-live", "read-releases"]);
    grant(&mut value, PUBLISHER, &["publish", "read-releases"]);
    let failure = compile(&value).expect_err("the publisher cannot read the owner field");
    let refusals = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| {
            diagnostic.code == "breg.statistical-dataset.measure-field-not-readable"
                && diagnostic.message.contains("`owner`")
                && diagnostic.message.contains("publisher")
        })
        .count();
    assert_eq!(refusals, 1, "{:?}", failure.diagnostics());
}

#[test]
fn exact_values_name_a_distinct_count_field_that_is_not_public() {
    let mut value = public_register_source(json!([
        {"id":"facilities","type":"count"},
        {"id":"owners","type":"distinct-count","field":"owner"}
    ]));
    value["recordTypes"].as_object_mut().unwrap().insert(
        "owner".to_owned(),
        json!({"classification":"public","primaryDataset":"statistics-test",
            "route":"owners","mutationMode":"mutable",
            "fields":[{"id":"name","type":"string","maximumLength":80,"classification":"public"}]
        }),
    );
    value["recordTypes"]["record"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"owner","type":"reference","target":"owner","classification":"public"}));
    for profile in [ANALYST, PUBLISHER] {
        value["accessProfiles"][profile]["permissions"]["records"][0]["readableFields"]
            .as_array_mut()
            .unwrap()
            .push(json!("owner"));
    }
    compile(&value).expect("a public reference field is released exactly");
    let owner = value["recordTypes"]["record"]["fields"]
        .as_array()
        .unwrap()
        .len()
        - 1;
    value["recordTypes"]["record"]["fields"][owner]["classification"] = json!("internal");
    assert_exact_refusal_names(&value, "owner", "internal");
}

#[test]
fn a_distinct_count_changes_the_definition_digest_and_its_absence_keeps_it() {
    let without = live_measure_digest(json!([{"id":"parcels","type":"count"}]));
    let with = compile(&distinct_source(distinct_measures()))
        .unwrap()
        .statistical_datasets()["records-by-category"]
        .definition_digest
        .clone();
    let other_id = compile(&distinct_source(json!([
        {"id":"parcels","type":"count"},
        {"id":"holders","type":"distinct-count","field":"owner"}
    ])))
    .unwrap()
    .statistical_datasets()["records-by-category"]
        .definition_digest
        .clone();
    assert_eq!(BTreeSet::from([without.clone(), with, other_id]).len(), 3);
    assert_eq!(
        without,
        compile(&distinct_source(json!([{"id":"parcels","type":"count"}])))
            .unwrap()
            .statistical_datasets()["records-by-category"]
            .definition_digest,
        "an unused reference field and record type do not enter a dataset's digest"
    );
}

fn ratio_measures() -> Value {
    json!([
        {"id":"parcels","type":"count"},
        {"id":"total-amount","type":"sum","field":"amount"},
        {"id":"amount-per-parcel","type":"ratio","numerator":"total-amount","denominator":"parcels","scale":2},
        {"id":"median-amount","type":"percentile","field":"amount","percentile":50,"scale":2}
    ])
}

/// A diagnostic with `code` whose path ends with `path`.
fn assert_measure_refused_at(measures: Value, code: &str, path: &str) {
    let failure = compile(&live_measure_source(measures)).expect_err("the dataset is refused");
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code && diagnostic.path.ends_with(path)),
        "missing {code} at {path}: {:?}",
        failure.diagnostics()
    );
}

#[test]
fn a_ratio_and_a_percentile_compile_with_the_scale_they_declare() {
    let compiled = compile(&live_measure_source(ratio_measures()))
        .expect("a live ratio and percentile compile");
    assert_eq!(measures_of(&compiled), ratio_measures_compiled());
    let metadata = artifact_json(&compiled, "generated/metadata/registry.json");
    assert_eq!(
        metadata["statisticalDatasets"][0]["measures"],
        measures_of(&compiled)
    );
    let dataset = &compiled.statistical_datasets()["records-by-category"];
    assert!(dataset.referenced_fields.contains("amount"));
}

fn ratio_measures_compiled() -> Value {
    json!([
        {"id":"parcels","type":"count"},
        {"id":"total-amount","type":"sum","field":"amount","scale":2},
        {"id":"amount-per-parcel","type":"ratio","numerator":"total-amount","denominator":"parcels","scale":2},
        {"id":"median-amount","type":"percentile","field":"amount","percentile":50,"scale":2}
    ])
}

#[test]
fn a_ratio_may_name_an_operand_declared_after_it_and_a_distinct_count_or_sum() {
    let compiled = compile(&distinct_source(json!([
        {"id":"per-owner","type":"ratio","numerator":"parcels","denominator":"owners","scale":3},
        {"id":"parcels","type":"count"},
        {"id":"owners","type":"distinct-count","field":"owner"},
        {"id":"total","type":"sum","field":"amount"},
        {"id":"amount-per-owner","type":"ratio","numerator":"total","denominator":"owners","scale":0}
    ])))
    .expect("operands declared anywhere in the list are found");
    assert_eq!(
        measures_of(&compiled)
            .as_array()
            .unwrap()
            .iter()
            .map(|measure| measure["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>(),
        [
            "per-owner",
            "parcels",
            "owners",
            "total",
            "amount-per-owner"
        ]
    );
}

#[test]
fn a_ratio_operand_is_a_count_distinct_count_or_sum_of_the_same_dataset() {
    let base = |ratio: Value| {
        json!([
            {"id":"parcels","type":"count"},
            {"id":"total","type":"sum","field":"amount"},
            {"id":"average","type":"mean","field":"amount","scale":2},
            {"id":"median","type":"percentile","field":"amount","percentile":50,"scale":2},
            {"id":"other","type":"ratio","numerator":"total","denominator":"parcels","scale":2},
            ratio
        ])
    };
    let code = "breg.statistical-dataset.ratio-operand";
    let ratio = |numerator: &str, denominator: &str| json!({"id":"r","type":"ratio","numerator":numerator,"denominator":denominator,"scale":2});
    for bad in ["average", "median", "other", "missing", "r"] {
        assert_measure_refused_at(base(ratio(bad, "parcels")), code, "measures[5].numerator");
        assert_measure_refused_at(base(ratio("total", bad)), code, "measures[5].denominator");
    }
    // The same measure on both sides is always 1.
    let failure = compile(&live_measure_source(base(ratio("total", "total"))))
        .expect_err("a measure over itself is refused");
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code
                && diagnostic.path.ends_with("measures[5].denominator")
                && diagnostic.message.contains("total")),
        "{:?}",
        failure.diagnostics()
    );
    compile(&live_measure_source(base(ratio("total", "parcels"))))
        .expect("a sum over a count is a ratio");
}

#[test]
fn a_ratio_or_percentile_that_is_not_well_formed_does_not_read() {
    for measures in [
        json!([{"id":"r","type":"ratio","numerator":"a","denominator":"b"}]),
        json!([{"id":"r","type":"ratio","numerator":"a","scale":1}]),
        json!([{"id":"r","type":"ratio","denominator":"b","scale":1}]),
        json!([{"id":"r","type":"ratio","numerator":"a","denominator":"b","scale":39}]),
        json!([{"id":"r","type":"ratio","numerator":"a","denominator":"b","scale":-1}]),
        json!([{"id":"r","type":"ratio","numerator":"a","denominator":"b","scale":1,"field":"amount"}]),
        json!([{"id":"p","type":"percentile","field":"amount","scale":2}]),
        json!([{"id":"p","type":"percentile","percentile":50,"scale":2}]),
        json!([{"id":"p","type":"percentile","field":"amount","percentile":50}]),
        json!([{"id":"p","type":"percentile","field":"amount","percentile":0,"scale":2}]),
        json!([{"id":"p","type":"percentile","field":"amount","percentile":100,"scale":2}]),
        json!([{"id":"p","type":"percentile","field":"amount","percentile":50.5,"scale":2}]),
        json!([{"id":"p","type":"percentile","field":"amount","percentile":"50","scale":2}]),
        json!([{"id":"p","type":"percentile","field":"amount","percentile":50,"scale":39}]),
    ] {
        let value = live_measure_source(measures.clone());
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(
            parse_project_json(&bytes).is_err(),
            "{measures} must not read"
        );
    }
    for (percentile, scale) in [(1, 0), (99, 38)] {
        compile(&live_measure_source(json!([
            {"id":"p","type":"percentile","field":"amount","percentile":percentile,"scale":scale}
        ])))
        .expect("the bounds of percentile and scale are admitted");
    }
}

#[test]
fn a_percentile_field_must_be_int64_or_decimal_and_known() {
    for field in ["category", "active", "event-date"] {
        assert_measure_refused_at(
            json!([{"id":"p","type":"percentile","field":field,"percentile":50,"scale":1}]),
            "breg.statistical-dataset.measure-field-type",
            "measures[0].field",
        );
    }
    assert_measure_refused_at(
        json!([{"id":"p","type":"percentile","field":"missing","percentile":50,"scale":1}]),
        "breg.statistical-dataset.field-unknown",
        "",
    );
    compile(&live_measure_source(json!([
        {"id":"p","type":"percentile","field":"quantity","percentile":90,"scale":0}
    ])))
    .expect("an int64 field has percentiles");
}

#[test]
fn every_reader_of_a_percentile_must_read_its_field() {
    let mut value = live_measure_source(json!([
        {"id":"p","type":"percentile","field":"amount","percentile":50,"scale":2}
    ]));
    value["accessProfiles"][ANALYST]["permissions"]["records"][0]["readableFields"] = json!([
        "active",
        "category",
        "event-date",
        "valid-from",
        "valid-to",
        "quantity"
    ]);
    let failure = compile(&value).expect_err("the analyst cannot read the measure field");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "breg.statistical-dataset.measure-field-not-readable"
            && diagnostic.message.contains("amount")
            && diagnostic.message.contains("analyst")
    }));
}

#[test]
fn a_percentile_limits_the_dataset_to_four_dimensions_and_a_ratio_does_not() {
    let with_dimensions = |measures: Value, count: usize| {
        let mut value = live_measure_source(measures);
        let fields = value["recordTypes"]["record"]["fields"]
            .as_array_mut()
            .unwrap();
        let mut names = vec![json!("category")];
        for index in 1..count {
            let id = format!("flag-{index}");
            fields.push(
                json!({"id":id,"type":"boolean","required":true,"classification":"internal"}),
            );
            names.push(json!(id));
        }
        for member in ["readableFields", "filterableFields"] {
            let granted = value["accessProfiles"][ANALYST]["permissions"]["records"][0][member]
                .as_array_mut()
                .unwrap();
            granted.extend(names.iter().skip(1).cloned());
        }
        value["statisticalDatasets"][0]["dimensions"] = json!(names);
        value
    };
    let median = json!([
        {"id":"parcels","type":"count"},
        {"id":"median","type":"percentile","field":"amount","percentile":50,"scale":2}
    ]);
    compile(&with_dimensions(median.clone(), 4)).expect("four dimensions are accepted");
    let failure = compile(&with_dimensions(median, 5)).expect_err("five are refused");
    let refusal = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.statistical-dataset.non-additive-dimensions")
        .unwrap_or_else(|| panic!("missing refusal: {:?}", failure.diagnostics()));
    assert!(
        refusal
            .message
            .contains("a distinct count, a percentile or a released sum"),
        "{}",
        refusal.message
    );
    compile(&with_dimensions(ratio_measures_without_percentile(), 5))
        .expect("five dimensions over additive measures and a ratio are accepted");
}

fn ratio_measures_without_percentile() -> Value {
    json!([
        {"id":"parcels","type":"count"},
        {"id":"total-amount","type":"sum","field":"amount"},
        {"id":"amount-per-parcel","type":"ratio","numerator":"total-amount","denominator":"parcels","scale":2}
    ])
}

#[test]
fn a_ratio_is_additive_and_a_percentile_is_not() {
    let compiled = compile(&live_measure_source(ratio_measures())).unwrap();
    let measures = &compiled.statistical_datasets()["records-by-category"].measures;
    let additive: Vec<(&str, bool)> = measures
        .iter()
        .map(|measure| (measure.id(), measure.is_additive()))
        .collect();
    assert_eq!(
        additive,
        [
            ("parcels", true),
            ("total-amount", true),
            ("amount-per-parcel", true),
            ("median-amount", false)
        ]
    );
}

#[test]
fn a_released_dataset_with_a_ratio_or_percentile_needs_exact_values() {
    for measure in [
        json!({"id":"per","type":"ratio","numerator":"parcels","denominator":"parcels2","scale":2}),
        json!({"id":"median","type":"percentile","field":"amount","percentile":50,"scale":2}),
    ] {
        let mut measures = vec![
            json!({"id":"parcels","type":"count"}),
            json!({"id":"parcels2","type":"sum","field":"quantity"}),
        ];
        measures.push(measure);
        let mut published = live_measure_source(json!(measures.clone()));
        grant(&mut published, PUBLISHER, &["publish", "read-releases"]);
        let failure = compile(&published).expect_err("a ratio or percentile is not rounded");
        let refusal = failure
            .diagnostics()
            .iter()
            .find(|diagnostic| {
                diagnostic.code == "breg.statistical-dataset.measure-release-unsupported"
            })
            .unwrap_or_else(|| panic!("missing refusal: {:?}", failure.diagnostics()));
        assert!(
            refusal.message.contains("ratio") && refusal.message.contains("percentile"),
            "{}",
            refusal.message
        );

        let exact = public_register_source(json!(measures));
        compile(&exact).expect("an exact-public-values release accepts both");
    }
}

#[test]
fn exact_values_name_a_percentile_field_that_is_not_public() {
    let mut value = public_register_source(json!([
        {"id":"facilities","type":"count"},
        {"id":"median","type":"percentile","field":"amount","percentile":50,"scale":2}
    ]));
    compile(&value).expect("a public field is released exactly");
    let amount = value["recordTypes"]["record"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .position(|field| field["id"] == "amount")
        .unwrap();
    value["recordTypes"]["record"]["fields"][amount]["classification"] = json!("internal");
    assert_exact_refusal_names(&value, "amount", "internal");
}

#[test]
fn the_definition_digest_covers_a_ratio_and_a_percentile_and_their_absence_keeps_it() {
    let without = live_measure_digest(json!([{"id":"parcels","type":"count"}]));
    let digests = BTreeSet::from([
        live_measure_digest(ratio_measures()),
        live_measure_digest(json!([
            {"id":"parcels","type":"count"},
            {"id":"total-amount","type":"sum","field":"amount"},
            {"id":"amount-per-parcel","type":"ratio","numerator":"total-amount","denominator":"parcels","scale":3},
            {"id":"median-amount","type":"percentile","field":"amount","percentile":50,"scale":2}
        ])),
        live_measure_digest(json!([
            {"id":"parcels","type":"count"},
            {"id":"total-amount","type":"sum","field":"amount"},
            {"id":"amount-per-parcel","type":"ratio","numerator":"total-amount","denominator":"parcels","scale":2},
            {"id":"median-amount","type":"percentile","field":"amount","percentile":51,"scale":2}
        ])),
        live_measure_digest(json!([
            {"id":"parcels","type":"count"},
            {"id":"total-amount","type":"sum","field":"amount"},
            {"id":"amount-per-parcel","type":"ratio","numerator":"total-amount","denominator":"parcels","scale":2},
            {"id":"median-amount","type":"percentile","field":"quantity","percentile":50,"scale":2}
        ])),
        without.clone(),
    ]);
    assert_eq!(digests.len(), 5);
    assert_eq!(
        without,
        live_measure_digest(json!([{"id":"parcels","type":"count"}])),
        "a dataset without the new measures keeps its digest"
    );
}

// ---- protected release of sums ----

const HELD: &str = "breg.statistical-dataset.sum-release-held";

fn code(name: &str) -> String {
    format!("breg.statistical-dataset.{name}")
}

/// A dataset releasing a count and two sums with rounding, whose every rule is
/// satisfied: an `owner` contributor the publisher reads, a decimal field that
/// declares a non-negative minimum, an int64 field, and month periods.
fn sum_release_source() -> Value {
    let mut value = distinct_source(json!([
        {"id":"parcels","type":"count"},
        {"id":"total-amount","type":"sum","field":"amount"},
        {"id":"total-units","type":"sum","field":"quantity"}
    ]));
    for field in value["recordTypes"]["record"]["fields"]
        .as_array_mut()
        .unwrap()
    {
        if field["id"] == "amount" {
            field["minimum"] = json!("0.00");
        }
    }
    value["accessProfiles"][PUBLISHER]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .unwrap()
        .extend([json!("owner"), json!("amount"), json!("quantity")]);
    grant(&mut value, ANALYST, &["read-live", "read-releases"]);
    grant(&mut value, PUBLISHER, &["publish", "read-releases"]);
    value["statisticalDatasets"][0]["disclosure"] = json!({
        "type":"minimum-count-and-rounding","minimumCount":5,"roundingBase":5,
        "contributor":{"type":"field","field":"owner"},"dominancePercent":15
    });
    value
}

/// Every diagnostic code of the dataset, in the order reported.
fn codes_of(value: &Value) -> Vec<String> {
    compile(value)
        .expect_err("a sum release is refused")
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .map(|diagnostic| diagnostic.code.clone())
        .collect()
}

fn diagnostic_for(value: &Value, name: &str) -> Diagnostic {
    compile(value)
        .expect_err("the dataset is refused")
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == code(name))
        .cloned()
        .unwrap_or_else(|| panic!("missing {name}"))
}

#[test]
fn a_sum_release_that_meets_every_rule_is_refused_only_by_the_hold() {
    let value = sum_release_source();
    let failure = compile(&value).expect_err("sums are held");
    let all = errors(&failure);
    assert_eq!(all.len(), 1, "{all:?}");
    assert_eq!(all[0].code, HELD);
    assert!(all[0]
        .path
        .ends_with("statisticalDatasets[id=records-by-category].disclosure"));
    assert!(all[0]
        .message
        .contains("held until a statistician has reviewed"));
    assert!(all[0].message.contains("exact-public-values"));
    // each-record is accepted too
    let mut each = sum_release_source();
    each["statisticalDatasets"][0]["disclosure"]["contributor"] = json!({"type":"each-record"});
    assert_eq!(codes_of(&each), vec![HELD.to_owned()]);
}

#[test]
fn every_release_grant_on_a_dataset_with_a_sum_is_held_even_without_a_publisher() {
    let mut read_releases = sum_release_source();
    read_releases["statisticalDatasets"][0]["disclosure"] =
        json!({"type":"minimum-count-and-rounding","minimumCount":5,"roundingBase":5});
    grant(&mut read_releases, PUBLISHER, &[]);
    grant(&mut read_releases, ANALYST, &["read-live", "read-releases"]);
    let codes = codes_of(&read_releases);
    assert!(codes.contains(&HELD.to_owned()), "{codes:?}");
    assert_eq!(codes.last().unwrap(), HELD);
    // no sum-release rule other than the hold needs a publisher
    assert!(
        !codes.contains(&code("disclosure-contributor-missing")),
        "{codes:?}"
    );

    // read-live alone keeps compiling
    let mut live = sum_release_source();
    live["statisticalDatasets"][0]["disclosure"] =
        json!({"type":"minimum-count-and-rounding","minimumCount":5,"roundingBase":5});
    grant(&mut live, PUBLISHER, &[]);
    grant(&mut live, ANALYST, &["read-live"]);
    compile(&live).expect("a live sum compiles");
}

#[test]
fn the_hold_is_the_last_diagnostic_of_a_dataset() {
    let mut value = sum_release_source();
    value["statisticalDatasets"][0]["disclosure"] =
        json!({"type":"minimum-count-and-rounding","minimumCount":5,"roundingBase":5});
    value["statisticalDatasets"][0]["period"]["granularity"] = json!("day");
    let codes = codes_of(&value);
    assert_eq!(codes.last().unwrap(), HELD, "{codes:?}");
    assert!(codes.contains(&code("sum-release-day-granularity")));
}

#[test]
fn a_missing_contributor_or_dominance_is_refused_on_the_disclosure() {
    for (member, name) in [
        ("contributor", "disclosure-contributor-missing"),
        ("dominancePercent", "disclosure-dominance-missing"),
    ] {
        let mut value = sum_release_source();
        value["statisticalDatasets"][0]["disclosure"]
            .as_object_mut()
            .unwrap()
            .remove(member);
        let refusal = diagnostic_for(&value, name);
        assert!(refusal
            .path
            .ends_with("statisticalDatasets[id=records-by-category].disclosure"));
        assert!(refusal
            .message
            .contains("statistical dataset `records-by-category`"));
        assert_eq!(codes_of(&value).last().unwrap(), HELD);
    }
}

#[test]
fn a_contributor_or_dominance_without_a_sum_or_a_publisher_is_refused() {
    let counts = || {
        let mut value = sum_release_source();
        value["statisticalDatasets"][0]["measures"] = json!([{"id":"parcels","type":"count"}]);
        value
    };
    let unpublished = || {
        let mut value = sum_release_source();
        grant(&mut value, PUBLISHER, &[]);
        grant(&mut value, ANALYST, &["read-live"]);
        value
    };
    for (member, name) in [
        ("contributor", "disclosure-contributor-unused"),
        ("dominancePercent", "disclosure-dominance-unused"),
    ] {
        for build in [counts as fn() -> Value, unpublished as fn() -> Value] {
            let mut value = build();
            let disclosure = value["statisticalDatasets"][0]["disclosure"]
                .as_object_mut()
                .unwrap();
            for other in ["contributor", "dominancePercent"] {
                if other != member {
                    disclosure.remove(other);
                }
            }
            let refusal = diagnostic_for(&value, name);
            assert!(refusal
                .path
                .ends_with("statisticalDatasets[id=records-by-category].disclosure"));
        }
    }
    // a count-only dataset with neither member compiles
    compile(&{
        let mut value = counts();
        value["statisticalDatasets"][0]["disclosure"] =
            json!({"type":"minimum-count-and-rounding","minimumCount":5,"roundingBase":5});
        value
    })
    .expect("a count-only release needs neither member");
}

#[test]
fn the_contributor_field_must_exist_be_a_reference_and_be_readable_by_the_publisher() {
    let path = "statisticalDatasets[id=records-by-category].disclosure.contributor.field";
    type Edit = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, Edit, &str)> = vec![
        (
            "unknown",
            Box::new(|value| {
                value["statisticalDatasets"][0]["disclosure"]["contributor"]["field"] =
                    json!("missing");
            }),
            "does not exist",
        ),
        (
            "not a reference",
            Box::new(|value| {
                value["statisticalDatasets"][0]["disclosure"]["contributor"]["field"] =
                    json!("category");
            }),
            "reference",
        ),
        (
            "not readable",
            Box::new(|value| {
                value["accessProfiles"][PUBLISHER]["permissions"]["records"][0]["readableFields"] =
                    json!([
                        "active",
                        "category",
                        "event-date",
                        "valid-from",
                        "valid-to",
                        "amount",
                        "quantity"
                    ]);
            }),
            "readableFields",
        ),
    ];
    let mut messages = BTreeSet::new();
    for (name, mutate, expected) in cases {
        let mut value = sum_release_source();
        mutate(&mut value);
        let failure = compile(&value).expect_err(name);
        let found: Vec<_> = failure
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == code("disclosure-contributor-field"))
            .collect();
        assert_eq!(found.len(), 1, "{name}: {:?}", failure.diagnostics());
        assert!(found[0].path.ends_with(path), "{name}: {}", found[0].path);
        assert!(
            found[0].message.contains(expected),
            "{name}: {}",
            found[0].message
        );
        messages.insert(found[0].message.clone());
    }
    assert_eq!(messages.len(), 3, "one message per cause");
}

#[test]
fn a_summed_decimal_field_must_declare_a_non_negative_minimum() {
    let amount_minimum = |minimum: Option<&str>| {
        let mut value = sum_release_source();
        for field in value["recordTypes"]["record"]["fields"]
            .as_array_mut()
            .unwrap()
        {
            if field["id"] == "amount" {
                match minimum {
                    Some(minimum) => field["minimum"] = json!(minimum),
                    None => {
                        field.as_object_mut().unwrap().remove("minimum");
                    }
                }
            }
        }
        value
    };
    for (minimum, refused) in [
        (None, true),
        (Some("-1.00"), true),
        (Some("0.00"), false),
        (Some("2.50"), false),
    ] {
        let codes = codes_of(&amount_minimum(minimum));
        assert_eq!(
            codes.contains(&code("sum-release-negative-values")),
            refused,
            "{minimum:?}: {codes:?}"
        );
    }
    let refusal = diagnostic_for(&amount_minimum(None), "sum-release-negative-values");
    assert!(refusal
        .path
        .ends_with("statisticalDatasets[id=records-by-category].measures[1]"));
    // the int64 sum declares no bounds and is not refused
    let mut int_only = amount_minimum(None);
    int_only["statisticalDatasets"][0]["measures"] =
        json!([{"id":"total-units","type":"sum","field":"quantity"}]);
    assert!(!codes_of(&int_only).contains(&code("sum-release-negative-values")));
}

#[test]
fn a_day_period_is_refused_for_a_sum_release() {
    let mut value = sum_release_source();
    value["statisticalDatasets"][0]["period"]["granularity"] = json!("day");
    value["statisticalDatasets"][0]["period"]["firstPeriod"] = json!("2025-01-01");
    let refusal = diagnostic_for(&value, "sum-release-day-granularity");
    assert!(refusal
        .path
        .ends_with("statisticalDatasets[id=records-by-category].period"));
    // a count-only release keeps day periods
    let mut counts = source();
    counts["statisticalDatasets"][0]["period"]["granularity"] = json!("day");
    counts["statisticalDatasets"][0]["period"]["firstPeriod"] = json!("2025-01-01");
    compile(&counts).expect("a count release over days compiles");
}

#[test]
fn a_released_sum_limits_the_dataset_to_four_dimensions_and_names_the_three_causes() {
    let with_dimensions = |count: usize| {
        let mut value = sum_release_source();
        let fields = value["recordTypes"]["record"]["fields"]
            .as_array_mut()
            .unwrap();
        let mut names = vec![json!("category")];
        for index in 1..count {
            let id = format!("flag-{index}");
            fields.push(
                json!({"id":id,"type":"boolean","required":true,"classification":"internal"}),
            );
            names.push(json!(id));
        }
        for profile in [ANALYST, PUBLISHER] {
            for member in ["readableFields", "filterableFields"] {
                value["accessProfiles"][profile]["permissions"]["records"][0][member]
                    .as_array_mut()
                    .unwrap()
                    .extend(names.iter().skip(1).cloned());
            }
        }
        value["statisticalDatasets"][0]["dimensions"] = json!(names);
        value
    };
    assert!(!codes_of(&with_dimensions(4)).contains(&code("non-additive-dimensions")));
    let refusal = diagnostic_for(&with_dimensions(5), "non-additive-dimensions");
    assert!(refusal
        .path
        .ends_with("statisticalDatasets[id=records-by-category].dimensions"));
    for cause in ["a distinct count", "a percentile", "a released sum"] {
        assert!(refusal.message.contains(cause), "{}", refusal.message);
    }
    assert!(refusal.message.contains("at most 4 dimensions"));
}

/// The first dataset plus a second one over the same unit, population and sum
/// field, edited by `mutate`, with the same grants.
fn two_sum_releases(mutate: impl FnOnce(&mut Value)) -> Value {
    let mut value = sum_release_source();
    let mut second = value["statisticalDatasets"][0].clone();
    second["id"] = json!("records-second");
    mutate(&mut second);
    value["statisticalDatasets"]
        .as_array_mut()
        .unwrap()
        .push(second);
    for profile in [ANALYST, PUBLISHER] {
        let operations =
            value["accessProfiles"][profile]["permissions"]["datasets"][0]["operations"].clone();
        value["accessProfiles"][profile]["permissions"]["datasets"]
            .as_array_mut()
            .unwrap()
            .push(json!({"dataset":"records-second","operations":operations}));
    }
    value
}

fn released_twice_refusals(value: &Value) -> Vec<Diagnostic> {
    compile(value)
        .expect_err("sums are held")
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == code("sum-field-released-twice"))
        .cloned()
        .collect()
}

/// Any two releases of a sum of one field over one unit share a total, at
/// least the grand total, so whatever their dimensions, populations and
/// granularities the second is refused.
#[test]
fn a_summed_field_released_by_two_datasets_over_one_unit_is_refused_at_the_second() {
    let flag = |value: &mut Value| {
        value["recordTypes"]["record"]["fields"]
            .as_array_mut()
            .unwrap()
            .push(
                json!({"id":"flag","type":"boolean","required":true,"classification":"internal"}),
            );
        for profile in [ANALYST, PUBLISHER] {
            for member in ["readableFields", "filterableFields"] {
                value["accessProfiles"][profile]["permissions"]["records"][0][member]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("flag"));
            }
        }
    };
    // equal dimensions
    let equal = released_twice_refusals(&two_sum_releases(|_| {}));
    assert_eq!(equal.len(), 1);
    assert!(equal[0]
        .path
        .ends_with("statisticalDatasets[id=records-second]"));
    assert!(equal[0].message.contains("records-by-category"));
    // one's dimensions among the other's
    let mut subset = two_sum_releases(|second| second["dimensions"] = json!(["category", "flag"]));
    flag(&mut subset);
    assert_eq!(released_twice_refusals(&subset).len(), 1);
    // the reverse
    let mut reverse = two_sum_releases(|_| {});
    flag(&mut reverse);
    reverse["statisticalDatasets"][0]["dimensions"] = json!(["category", "flag"]);
    assert_eq!(released_twice_refusals(&reverse).len(), 1);
    // disjoint dimensions still share the grand total
    let mut disjoint = two_sum_releases(|second| second["dimensions"] = json!(["flag"]));
    flag(&mut disjoint);
    assert_eq!(released_twice_refusals(&disjoint).len(), 1);
    // a different population
    let different_population =
        two_sum_releases(|second| second["population"] = json!("active eq false"));
    assert_eq!(released_twice_refusals(&different_population).len(), 1);
    // a different granularity
    let different_granularity = two_sum_releases(|second| {
        second["period"] =
            json!({"type":"flow","field":"event-date","granularity":"year","firstPeriod":"2025"});
    });
    assert_eq!(released_twice_refusals(&different_granularity).len(), 1);
    // a different summed field
    let different_field = two_sum_releases(|second| {
        second["measures"] = json!([{"id":"total-amount","type":"sum","field":"amount"}]);
        second["id"] = json!("records-second");
    });
    let mut only_amount = different_field;
    only_amount["statisticalDatasets"][0]["measures"] =
        json!([{"id":"total-units","type":"sum","field":"quantity"}]);
    assert!(released_twice_refusals(&only_amount).is_empty());
}

#[test]
fn a_summed_field_released_over_two_units_is_not_refused() {
    let mut value = two_sum_releases(|second| second["unit"] = json!("record-two"));
    let mut second_type = value["recordTypes"]["record"].clone();
    second_type["route"] = json!("records-two");
    value["recordTypes"]["record-two"] = second_type;
    for profile in [ANALYST, PUBLISHER] {
        let mut records = value["accessProfiles"][profile]["permissions"]["records"][0].clone();
        records["recordType"] = json!("record-two");
        value["accessProfiles"][profile]["permissions"]["records"]
            .as_array_mut()
            .unwrap()
            .push(records);
    }
    assert!(released_twice_refusals(&value).is_empty());
}

#[test]
fn means_ratios_and_percentiles_are_still_refused_for_release_and_name_what_is_carried() {
    for measure in [
        json!({"id":"m","type":"mean","field":"amount","scale":2}),
        json!({"id":"m","type":"ratio","numerator":"parcels","denominator":"owners","scale":2}),
        json!({"id":"m","type":"percentile","field":"amount","percentile":50,"scale":2}),
    ] {
        let mut value = sum_release_source();
        value["statisticalDatasets"][0]["measures"] = json!([
            {"id":"parcels","type":"count"},
            {"id":"owners","type":"distinct-count","field":"owner"},
            measure
        ]);
        value["statisticalDatasets"][0]["disclosure"] =
            json!({"type":"minimum-count-and-rounding","minimumCount":5,"roundingBase":5});
        let refusal = diagnostic_for(&value, "measure-release-unsupported");
        assert!(
            refusal.message.contains("counts, distinct counts"),
            "{}",
            refusal.message
        );
        assert!(refusal.message.contains("exact-public-values"));
        assert!(!codes_of(&value).contains(&HELD.to_owned()));
    }
}

#[test]
fn a_dominance_percent_outside_one_to_one_hundred_is_refused_when_the_project_is_read() {
    for percent in [0, 101] {
        let mut value = sum_release_source();
        value["statisticalDatasets"][0]["disclosure"]["dominancePercent"] = json!(percent);
        let refusals = read_refusals(&value);
        assert!(
            refusals.iter().any(|(_, path, message)| {
                path.contains("dominancePercent") || message.contains("dominancePercent")
            }),
            "{percent}: {refusals:?}"
        );
    }
    let mut value = sum_release_source();
    for percent in [1, 100] {
        value["statisticalDatasets"][0]["disclosure"]["dominancePercent"] = json!(percent);
        assert_eq!(codes_of(&value), vec![HELD.to_owned()]);
    }
}

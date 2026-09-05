// SPDX-License-Identifier: Apache-2.0

use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use serde_json::{json, Value};

const ACCESS_PAGE: &str =
    include_str!("../../../docs/site/src/content/docs/configure/breg-access.mdx");
const WORKFLOW_PAGE: &str =
    include_str!("../../../docs/site/src/content/docs/configure/breg-change-control.mdx");

fn fragment(page: &str, marker: &str) -> Value {
    let fragments: Vec<_> = page
        .split("```yaml\n")
        .skip(1)
        .filter_map(|rest| rest.split_once("\n```").map(|(yaml, _)| yaml))
        .filter(|yaml| yaml.contains(marker))
        .collect();
    assert_eq!(
        fragments.len(),
        1,
        "expected one example containing {marker}"
    );
    serde_norway::from_str(fragments[0]).unwrap()
}

fn field(id: &str) -> Value {
    json!({"id":id,"type":"string","required":true,"maxLength":64,"classification":"internal"})
}

fn entity(id: &str, fields: Vec<Value>) -> Value {
    json!({"id":id,"primaryDataset":"asset-registry","route":format!("{id}s"),
        "mutationMode":"mutable","classification":"internal","fields":fields})
}

fn project(entities: Vec<Value>, profiles: Value) -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject",
        "registry":{"id":"documented-access","version":"0.1.0","defaultLanguage":"en",
            "canonicalBaseIri":"https://documented-access.example.test"},
        "entities":entities,"accessProfiles":profiles
    })
}

fn compile(source: Value) -> CompiledRegistry {
    let parsed = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project(&parsed, &[], CompileProfile::Authoring).unwrap()
}

#[test]
fn documented_access_grants_compile_with_their_declared_default_and_relationships() {
    // Supply only the model that this grant-focused page assumes already exists.
    let profiles = fragment(ACCESS_PAGE, "- id: site-planner")["accessProfiles"].clone();
    let mut site = entity(
        "asset-site",
        vec![field("site-code"), field("label"), field("zone")],
    );
    site["classification"] = json!("public");
    site["fields"][0]["classification"] = json!("public");
    site["fields"][1]["classification"] = json!("public");
    let mut household = entity("household", vec![field("household-code")]);
    household["selectorProfiles"] = json!([{"id":"by-household-code","fields":["household-code"]}]);
    household["readPaths"] =
        json!([{"id":"people","through":"group-membership","to":"person","route":"people"}]);
    let person = entity("person", vec![field("person-code"), field("legal-name")]);
    let membership = entity("group-membership", ["household", "person"].into_iter().map(|id| {
        json!({"id":id,"type":"reference","target":id,"required":true,"classification":"internal"})
    }).collect());
    let compiled = compile(project(vec![site, household, person, membership], profiles));
    assert!(compiled.entities()["asset-site"].access_profiles["site-planner"].default);
}

#[test]
fn documented_correction_has_complete_grants_for_independent_review_stages() {
    let mut entities = fragment(WORKFLOW_PAGE, "- id: placement-correction-request")["entities"]
        .as_array()
        .unwrap()
        .clone();
    entities.extend([
        entity("asset-item", vec![field("asset-code")]),
        entity("asset-site", vec![field("site-code")]),
    ]);
    let profiles = fragment(WORKFLOW_PAGE, "- id: correction-submitter")["accessProfiles"].clone();
    let compiled = compile(project(entities, profiles));
    let request = &compiled.entities()["placement-correction-request"];
    assert!(request.access_profiles["correction-submitter"].default);
    let review = request.change_request.as_ref().unwrap();
    assert_eq!(review.stages.len(), 2);
    assert!(review.stages[1].exclude_previous_reviewers);
}

#[test]
fn task_profile_reference_compiles_and_preserves_separate_read_write_authority() {
    let source: Value = serde_norway::from_str(include_str!(
        "../../../products/breg/examples/access-review/task-profiles/registry.yaml"
    ))
    .unwrap();
    let compiled = compile(source);
    let profiles = &compiled.entities()["record"].access_profiles;
    assert!(!profiles.contains_key("registrar"));
    assert!(profiles["supervisor"].row_boundaries.is_empty());
    assert_eq!(profiles["clerk-reader"].row_boundaries.len(), 1);
    assert_eq!(profiles["clerk-editor"].row_boundaries.len(), 2);
    assert!(profiles["auditor"].revision_access);
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
#[test]
fn task_profile_scenarios_match_documented_admission_without_claiming_row_access() {
    let source: Value = serde_norway::from_str(include_str!(
        "../../../products/breg/examples/access-review/task-profiles/registry.yaml"
    ))
    .unwrap();
    let compiled = compile(source);
    let example = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/examples/access-review/task-profiles");
    for (file, admitted, reason) in [
        ("clerk-read.json", true, "profile_requirements_satisfied"),
        (
            "clerk-edit-own.json",
            true,
            "profile_requirements_satisfied",
        ),
        ("supervisor.json", true, "profile_requirements_satisfied"),
        (
            "auditor-history.json",
            true,
            "profile_requirements_satisfied",
        ),
        (
            "correction-review.json",
            true,
            "profile_requirements_satisfied",
        ),
        (
            "clerk-cannot-select-supervisor.json",
            false,
            "required_scope_missing",
        ),
        ("auditor-cannot-edit.json", false, "operation_not_granted"),
    ] {
        let scenario = serde_json::from_slice(&std::fs::read(example.join(file)).unwrap()).unwrap();
        let preview = registry_breg::access_preview::preview_access(&compiled, scenario).unwrap();
        assert_eq!(preview.admitted, admitted, "{file}");
        assert_eq!(preview.reason, reason, "{file}");
        assert_eq!(preview.record_access, "not_evaluated", "{file}");
        assert!(!preview.credentials_verified, "{file}");
    }
}

#[cfg(feature = "runtime")]
#[test]
fn documented_runtime_config_parses_after_filling_the_package_revision() {
    let page = include_str!("../../../docs/site/src/content/docs/operate/breg.mdx");
    let mut source = fragment(
        page,
        "apiVersion: registry.registrystack.org/breg-runtime/v1alpha1",
    );
    // The operator substitutes the package digest; retain every authored key,
    // kind, token-verifier setting, and secret reference from the example.
    assert_eq!(
        source["package"]["activeRevision"],
        "sha256:<package revision reported by package>"
    );
    source["package"]["activeRevision"] = json!(format!("sha256:{}", "a".repeat(64)));
    registry_breg::runtime_config::parse_runtime_config_with_env(
        &serde_norway::to_string(&source).unwrap(),
        |_| None,
    )
    .expect("documented runtime config parses without resolving secrets or connecting to services");
}

// SPDX-License-Identifier: Apache-2.0
//! Proves the `import` operation compiles as a create-only, ingestion-run
//! capability that change control does not count as a direct write, and that
//! every `breg.import.*` refusal names the grant it concerns.

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::{parse_project_json, Operation};
use registry_breg::diagnostics::CompileFailure;
use registry_breg::CompiledRegistry;
use serde_json::{json, Value};

fn compile(project: &Value) -> Result<CompiledRegistry, CompileFailure> {
    let source = serde_json::to_vec(project).expect("project serializes");
    let project = parse_project_json(&source).expect("source shape parses");
    compile_project(&project, &[], CompileProfile::Authoring)
}

fn codes(failure: &CompileFailure) -> Vec<String> {
    failure
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect()
}

fn diagnostic<'a>(
    failure: &'a CompileFailure,
    code: &str,
) -> &'a registry_breg::diagnostics::Diagnostic {
    failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == code)
        .unwrap_or_else(|| panic!("expected {code:?}, got {:?}", codes(failure)))
}

/// A governed `enrollment` entity loaded by an `import` profile, with a
/// change-request entity whose effect patches enrollments.
fn governed_project(required_for: &[&str], loader_operations: &[&str]) -> Value {
    let mut enrollment = json!({
        "id":"enrollment","primaryDataset":"test-dataset","route":"enrollments","mutationMode":"mutable",
        "batch":{"maximumItems":10,"maximumBytes":65536},
        "fields":[{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}]
    });
    if !required_for.is_empty() {
        enrollment["changeControl"] = json!({"requiredFor": required_for});
    }
    json!({
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{"id":"import-grants","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "entities":[enrollment,{
        "id":"enrollment-change","primaryDataset":"test-dataset","route":"enrollment-changes","mutationMode":"mutable",
        "fields":[
          {"id":"enrollment","type":"reference","target":"enrollment","required":true,"classification":"internal"},
          {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}
        ],
        "changeRequest":{"effects":[{"id":"apply-label","target":{"fromField":"enrollment"},"operation":"patch","set":{"label":{"fromField":"label"}}}],
          "review":{"authority":"casework-main","policyId":"request-review"},"onApproved":{"mode":"manual"}}
      }],
      "accessProfiles":[{
        "id":"loader","principalClaim":"principal","permissions":[{
          "entity":"enrollment","operations":loader_operations,"readableFields":["label"],"writableFields":["label"],
          "rowBoundaries": []
        }]
      },{
        "id":"reviewer","default":true,"principalClaim":"principal","permissions":[{
          "entity":"enrollment-change","operations":["get","submit_request","apply_request"],"readableFields":["enrollment","label"],
          "applyTargets":[{"entity":"enrollment", "rowBoundaries": []}],
          "rowBoundaries": []
        }]
      }]
    })
}

fn route_ids(registry: &CompiledRegistry) -> Vec<String> {
    registry
        .routes()
        .routes
        .iter()
        .map(|route| route.id.clone())
        .collect()
}

#[test]
fn import_is_accepted_on_an_entity_controlled_for_create_and_patch() {
    let registry = compile(&governed_project(&["create", "patch"], &["import"]))
        .expect("import is not a direct write, so change control accepts it");
    let route = registry
        .routes()
        .routes
        .iter()
        .find(|route| route.id == "records.enrollment.import")
        .expect("an import grant compiles an import route");
    assert_eq!(route.operation, Operation::Import);
    assert_eq!(route.path, "/v1/records/enrollments/ingestion-runs");
    assert_eq!(route.access_profiles, vec!["loader".to_owned()]);
    let routes = route_ids(&registry);
    assert!(
        !routes.contains(&"records.enrollment.create".to_owned())
            && !routes.contains(&"records.enrollment.batch".to_owned()),
        "import exposes no item route and no raw batch route: {routes:?}"
    );
}

#[test]
fn batch_is_still_refused_on_a_controlled_entity_and_the_message_suggests_import() {
    let failure = compile(&governed_project(
        &["create", "patch"],
        &["create", "batch"],
    ))
    .expect_err("batch remains a direct write");
    let found = diagnostic(&failure, "breg.change-control.direct-write-grant");
    assert_eq!(
        found.path,
        "entities[id=enrollment].accessProfiles[id=loader].operations"
    );
    assert!(
        found.message.contains("`import`"),
        "the refusal names the governed bulk-load grant: {}",
        found.message
    );
}

#[test]
fn adding_change_control_to_an_imported_entity_removes_no_route() {
    let ungoverned = compile(&ungoverned_project())
        .expect("import is allowed on an entity without change control");
    let governed = compile(&governed_project(&["create", "patch"], &["import"]))
        .expect("a successor that adds change control keeps the import grant");
    assert_eq!(enrollment_routes(&ungoverned), enrollment_routes(&governed));
    assert_eq!(
        enrollment_routes(&governed),
        vec!["records.enrollment.import".to_owned()]
    );
}

/// The first package of the adoption journey: enrollments are loaded through
/// `import` before any change request governs them.
fn ungoverned_project() -> Value {
    let mut project = governed_project(&[], &["import"]);
    project["entities"]
        .as_array_mut()
        .expect("entities")
        .truncate(1);
    project["accessProfiles"]
        .as_array_mut()
        .expect("profiles")
        .truncate(1);
    project["accessProfiles"][0]["default"] = json!(true);
    project
}

fn enrollment_routes(registry: &CompiledRegistry) -> Vec<String> {
    route_ids(registry)
        .into_iter()
        .filter(|id| id.starts_with("records.enrollment."))
        .collect()
}

#[test]
fn import_requires_entity_batch_bounds() {
    let mut project = governed_project(&["patch"], &["import"]);
    project["entities"][0]
        .as_object_mut()
        .expect("entity object")
        .remove("batch");
    let failure = compile(&project).expect_err("an import run needs chunk bounds");
    assert_eq!(
        diagnostic(&failure, "breg.import.batch-bounds-required").path,
        "entities[id=enrollment].accessProfiles[id=loader].operations"
    );
}

#[test]
fn import_refuses_an_anonymous_profile() {
    let mut project = ungoverned_project();
    let loader = project["accessProfiles"][0]
        .as_object_mut()
        .expect("profile object");
    loader.remove("principalClaim");
    loader.insert("anonymous".to_owned(), json!(true));
    let failure = compile(&project).expect_err("runs are creator-scoped");
    assert_eq!(
        diagnostic(&failure, "breg.import.principal-required").path,
        "entities[id=enrollment].accessProfiles[id=loader].operations"
    );
}

#[test]
fn import_beside_batch_on_one_entity_is_refused_as_redundant() {
    let mut project = ungoverned_project();
    project["accessProfiles"]
        .as_array_mut()
        .expect("profiles")
        .push(json!({
            "id":"bulk-writer","principalClaim":"principal","permissions":[{
              "entity":"enrollment","operations":["create","batch"],"readableFields":["label"],"writableFields":["label"],
              "rowBoundaries": []
            }]
        }));
    let failure =
        compile(&project).expect_err("batch beside import leaves the authority bounding nothing");
    assert_eq!(
        diagnostic(&failure, "breg.import.batch-redundant").path,
        "entities[id=enrollment].accessProfiles[id=loader].operations"
    );

    let mut same = ungoverned_project();
    same["accessProfiles"][0]["permissions"][0]["operations"] =
        json!(["create", "batch", "import"]);
    let same_profile =
        compile(&same).expect_err("one profile holding batch and import is refused too");
    assert!(codes(&same_profile).contains(&"breg.import.batch-redundant".to_owned()));
}

#[test]
fn import_is_unavailable_on_a_change_request_entity() {
    let mut project = governed_project(&["patch"], &["import"]);
    project["accessProfiles"][1]["permissions"][0]["operations"] =
        json!(["get", "submit_request", "apply_request", "import"]);
    project["entities"][1]["batch"] = json!({"maximumItems":10,"maximumBytes":65536});
    let failure = compile(&project).expect_err("request drafts are authored, never imported");
    assert!(
        codes(&failure).contains(&"breg.access-profile.operation-unavailable".to_owned()),
        "{:?}",
        codes(&failure)
    );
}

#[test]
fn import_is_a_forbidden_direct_mutation_for_a_task_grant_profile() {
    let mut project = ungoverned_project();
    project["accessProfiles"][0]["taskGrant"] = json!({"sourceIssuer":"https://casework.example"});
    let failure = compile(&project).expect_err("a task grant cannot load records");
    assert!(
        codes(&failure)
            .contains(&"breg.access-profile.task-grant-direct-mutation-forbidden".to_owned()),
        "{:?}",
        codes(&failure)
    );
}

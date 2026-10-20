// SPDX-License-Identifier: Apache-2.0
//! Proves the `import` operation compiles as a create-only, ingestion-run
//! capability that mutation policy does not count as a direct write, and that
//! every `breg.import.*` refusal names the grant it concerns.

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::{parse_project_json, parse_project_yaml, Operation};
use registry_breg::diagnostics::{CompileFailure, DiagnosticSeverity};
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

/// A RecordType loaded through Import even when ordinary writes require Proposals.
fn governed_project(required_for: &[&str], loader_operations: &[&str]) -> Value {
    let mut enrollment = json!({
        "id":"enrollment","primaryDataset":"test-dataset","route":"enrollments","mutationMode":"mutable",
        "batch":{"maximumItems":10,"maximumBytes":65536},
        "fields":[{"id":"label","type":"string","maximumLength":32,"required":true,"classification":"internal"}]
    });
    if !required_for.is_empty() {
        enrollment["mutationPolicy"] = Value::Object(
            required_for
                .iter()
                .map(|operation| ((*operation).to_owned(), json!("proposal-required")))
                .collect(),
        );
    }
    json!({
      "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
      "project":{"id":"import-grants","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "datasets":[{"id":"test-dataset"}], "recordTypes":[enrollment],
      "accessProfiles":[{
        "id":"loader","default":true,"principalClaim":"principal","requiredScopes":"unrestricted",
        "permissions":{"records":[{
          "recordType":"enrollment","operations":loader_operations,"readableFields":["label"],"writableFields":["label"],
          "rowBoundaries":"unrestricted"
        }]}
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
        .expect("import is not a direct write, so mutation policy accepts it");
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
fn import_retains_the_native_proposal_required_mutation_policy() {
    let registry = compile(&governed_project(&["create", "patch"], &["import"]))
        .expect("an import grant keeps the native mutation policy");
    let policy = registry.entities()["enrollment"]
        .change_control
        .as_ref()
        .expect("the compiled RecordType retains the authored policy");
    assert_eq!(
        policy.required_for,
        std::collections::BTreeSet::from([Operation::Create, Operation::Patch])
    );
    assert_eq!(
        enrollment_routes(&registry),
        vec!["records.enrollment.import".to_owned()]
    );
    // This proves the compiled policy and Import-only surface. Runtime tests
    // establish that direct mutations cannot bypass the retained policy.
}

#[test]
fn adding_mutation_policy_to_an_imported_entity_removes_no_route() {
    let ungoverned = compile(&ungoverned_project())
        .expect("import is allowed on an entity without mutation policy");
    let governed = compile(&governed_project(&["create", "patch"], &["import"]))
        .expect("a successor that adds mutation policy keeps the import grant");
    assert_eq!(enrollment_routes(&ungoverned), enrollment_routes(&governed));
    assert_eq!(
        enrollment_routes(&governed),
        vec!["records.enrollment.import".to_owned()]
    );
}

/// The first package of the adoption journey: enrollments are loaded through
/// `import` before ordinary mutations require Proposals.
fn ungoverned_project() -> Value {
    let mut project = governed_project(&[], &["import"]);
    project["recordTypes"]
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
    project["recordTypes"][0]
        .as_object_mut()
        .expect("entity object")
        .remove("batch");
    let failure = compile(&project).expect_err("an import run needs chunk bounds");
    assert_eq!(
        diagnostic(&failure, "breg.import.batch-bounds-required").path,
        "recordTypes[id=enrollment].accessProfiles[id=loader].operations"
    );
}

/// An import run belongs to the principal that created it. A profile cannot
/// be read without a principal claim, so no import grant reaches the compiler
/// without one.
#[test]
fn import_refuses_a_profile_without_a_principal_claim() {
    let mut project = ungoverned_project();
    let loader = project["accessProfiles"][0]
        .as_object_mut()
        .expect("profile object");
    loader.remove("principalClaim");
    let source = serde_json::to_vec(&project).expect("project serializes");
    let failure = parse_project_yaml(&source).expect_err("runs are creator-scoped");
    assert_eq!(
        diagnostic(&failure, "config.missing-key").path,
        "project.accessProfiles[0]"
    );

    let mut project = ungoverned_project();
    project["accessProfiles"][0]["principalClaim"] = json!("");
    let failure = compile(&project).expect_err("runs are creator-scoped");
    let codes = codes(&failure);
    let errors = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    assert!(
        !errors.is_empty()
            && errors
                .iter()
                .all(|code| *code == "breg.access-profile.principal-claim-required"),
        "{codes:?}"
    );
    for (retained, path) in [
        (
            "breg.access.profile-unrestricted-rows",
            "recordTypes[id=enrollment].accessProfiles[id=loader].rowBoundaries",
        ),
        ("breg.package.identity-missing", "project.package"),
    ] {
        assert!(failure.diagnostics().iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Finding
                && diagnostic.code == retained
                && diagnostic.path == path
        }));
    }
}

#[test]
fn import_beside_batch_on_one_entity_is_refused_as_redundant() {
    let mut project = ungoverned_project();
    project["accessProfiles"]
        .as_array_mut()
        .expect("profiles")
        .push(json!({
            "id":"bulk-writer","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"enrollment","operations":["create","batch"],"readableFields":["label"],"writableFields":["label"],
              "rowBoundaries": "unrestricted"
            }]}
        }));
    let failure =
        compile(&project).expect_err("batch beside import leaves the authority bounding nothing");
    assert_eq!(
        diagnostic(&failure, "breg.import.batch-redundant").path,
        "recordTypes[id=enrollment].accessProfiles[id=loader].operations"
    );

    let mut same = ungoverned_project();
    same["accessProfiles"][0]["permissions"]["records"][0]["operations"] =
        json!(["create", "batch", "import"]);
    let same_profile =
        compile(&same).expect_err("one profile holding batch and import is refused too");
    assert!(codes(&same_profile).contains(&"breg.import.batch-redundant".to_owned()));
}

#[test]
fn import_is_unavailable_on_a_proposal_permission() {
    let mut project = ungoverned_project();
    project["accessProfiles"][0]["permissions"]["proposals"] =
        json!([{"action":"correct-enrollment", "operations":["import"]}]);
    let source = serde_json::to_vec(&project).unwrap();
    let failure =
        parse_project_yaml(&source).expect_err("Proposal authority never grants Record import");
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.path
                == "project.accessProfiles[0].permissions.proposals[0].operations[0]"
                && diagnostic.code == "config.unknown-variant"),
        "{:?}",
        failure.diagnostics()
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

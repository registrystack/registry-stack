// SPDX-License-Identifier: Apache-2.0
//! Proves an `import` grant is admitted for create through the durable
//! ingestion-run path only: a client-side plan binds it for create and refuses
//! patch, the legacy direct batch path refuses the plan, and the generated
//! database grants insert the rows without a standing read.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::data::{
    execute_import_chunk, DataError, DataHttpResponse, DataImportCheckpoint, DataImportOperation,
    DataImportPlan,
};
use registry_breg::generated_ddl::{PolicyCommand, TablePrivilege};
use registry_breg::CompiledRegistry;
use serde_json::{json, Value};

fn project(loader_operations: &[&str]) -> Value {
    json!({
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{"id":"import-admission","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "entities":[{
        "id":"enrollment","primaryDataset":"test-dataset","route":"enrollments","mutationMode":"mutable",
        "batch":{"maximumItems":2,"maximumBytes":4096},
        "changeControl":{"requiredFor":["patch"]},
        "fields":[{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}]
      },{
        "id":"enrollment-change","primaryDataset":"test-dataset","route":"enrollment-changes","mutationMode":"mutable",
        "fields":[
          {"id":"enrollment","type":"reference","target":"enrollment","required":true,"classification":"internal"},
          {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}
        ],
        "changeRequest":{"effects":[{"id":"apply-label","target":{"fromField":"enrollment"},"operation":"patch","set":{"label":{"fromField":"label"}}}],
          "review":{"authority":"casework-main","policyId":"request-review"},"onApproved":{"mode":"manual"}}
      }],
      "accessProfiles":[{
        "id":"loader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":[{
          "entity":"enrollment","operations":loader_operations,"readableFields":["label"],"writableFields":["label"],
          "rowBoundaries": "unrestricted"
        }]
      },{
        "id":"reviewer","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":[{
          "entity":"enrollment-change","operations":["get","submit_request","apply_request"],"readableFields":["enrollment","label"],
          "applyTargets":[{"entity":"enrollment", "rowBoundaries": "unrestricted"}],
          "rowBoundaries": "unrestricted"
        }]
      }]
    })
}

fn compile(project: &Value) -> CompiledRegistry {
    let source = serde_json::to_vec(project).expect("project serializes");
    let project = parse_project_json(&source).expect("source shape parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("project compiles")
}

const INPUT: &[u8] = b"{\"operation\":\"create\",\"data\":{\"label\":\"north\"}}\n";

#[test]
fn an_import_grant_plans_a_create_load_and_refuses_patch() {
    let registry = compile(&project(&["import"]));
    let plan = DataImportPlan::from_jsonl(
        &registry,
        "enrollment",
        DataImportOperation::Create,
        "loader",
        INPUT,
    )
    .expect("an import grant admits a create plan");
    assert!(plan.through_import());
    assert_eq!(plan.item_count(), 1);

    let patch = DataImportPlan::from_jsonl(
        &registry,
        "enrollment",
        DataImportOperation::Patch,
        "loader",
        b"{\"operation\":\"patch\",\"recordId\":\"00000000-0000-4000-8000-000000000001\",\"ifMatch\":\"\\\"breg-1\\\"\",\"patch\":[{\"op\":\"replace\",\"path\":\"/label\",\"value\":\"south\"}]}\n",
    );
    assert_eq!(
        patch.expect_err("import is create only"),
        DataError::InvalidBinding
    );
}

#[test]
fn an_import_plan_is_refused_on_the_direct_batch_path() {
    let registry = compile(&project(&["import"]));
    let plan = DataImportPlan::from_jsonl(
        &registry,
        "enrollment",
        DataImportOperation::Create,
        "loader",
        INPUT,
    )
    .expect("an import grant admits a create plan");
    let mut checkpoint =
        DataImportCheckpoint::start(&plan, "package-revision", "schema-fingerprint")
            .expect("checkpoint binds");
    let import_id = checkpoint.import_id().to_owned();
    let mut dispatched = false;
    let outcome = {
        let future = execute_import_chunk(
            &plan,
            &mut checkpoint,
            "package-revision",
            "schema-fingerprint",
            &import_id,
            |_request| {
                dispatched = true;
                async { Err::<DataHttpResponse, ()>(()) }
            },
        );
        let mut future = pin!(future);
        let Poll::Ready(outcome) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("the refusal is decided before any request is dispatched");
        };
        outcome
    };
    assert_eq!(
        outcome.expect_err("an import binding has no raw batch route"),
        DataError::InvalidBinding
    );
    assert!(!dispatched);
}

#[test]
fn a_batch_plan_is_not_an_import_plan() {
    let mut source = project(&["create", "batch"]);
    source["entities"][0]
        .as_object_mut()
        .expect("entity")
        .remove("changeControl");
    source["entities"]
        .as_array_mut()
        .expect("entities")
        .truncate(1);
    source["accessProfiles"]
        .as_array_mut()
        .expect("profiles")
        .truncate(1);
    source["accessProfiles"][0]["default"] = json!(true);
    let registry = compile(&source);
    let plan = DataImportPlan::from_jsonl(
        &registry,
        "enrollment",
        DataImportOperation::Create,
        "loader",
        INPUT,
    )
    .expect("a batch grant admits a create plan");
    assert!(!plan.through_import());
}

#[test]
fn an_import_grant_inserts_without_a_standing_read() {
    let registry = compile(&project(&["import"]));
    let table = registry
        .ddl()
        .tables
        .iter()
        .find(|table| table.entity_id == "enrollment")
        .expect("enrollment table");
    assert!(table.runtime_privileges.contains(&TablePrivilege::Insert));
    let loader = table
        .policies
        .iter()
        .filter(|policy| policy.access_profile == "loader")
        .collect::<Vec<_>>();
    assert_eq!(
        loader
            .iter()
            .filter(|policy| policy.command == PolicyCommand::Insert)
            .count(),
        1,
        "the import profile inserts under its own row policy"
    );
    let reads = loader
        .iter()
        .filter(|policy| policy.command == PolicyCommand::Select)
        .collect::<Vec<_>>();
    assert_eq!(reads.len(), 1, "only the create-returning read: {reads:?}");
    assert!(reads[0]
        .using_expression
        .as_deref()
        .is_some_and(|expression| expression.contains("registry.created_record_id")));
    assert!(loader
        .iter()
        .all(|policy| policy.command != PolicyCommand::Update));
}

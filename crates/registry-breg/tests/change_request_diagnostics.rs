// SPDX-License-Identifier: Apache-2.0
//! Proves change-request diagnostics name the entity, access profile, review
//! stage, or effect they concern, using the same `[id=...]` and index
//! conventions the contract compiler already uses elsewhere.

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::diagnostics::CompileFailure;

fn compile_json(source: &[u8]) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    let project = parse_project_json(source).expect("source shape parses");
    compile_project(&project, &[], CompileProfile::Authoring)
}

fn diagnostic_path<'a>(failure: &'a CompileFailure, code: &str) -> &'a str {
    failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == code)
        .unwrap_or_else(|| {
            panic!(
                "expected a diagnostic with code {code:?}, got {:?}",
                failure
                    .diagnostics()
                    .iter()
                    .map(|d| &d.code)
                    .collect::<Vec<_>>()
            )
        })
        .path
        .as_str()
}

#[test]
fn change_control_direct_write_grant_identifies_entity_and_profile() {
    let failure = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"change-request-diagnostics","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"asset","primaryDataset":"test-dataset","route":"assets","mutationMode":"mutable","changeControl":{"requiredFor":["patch"]},
            "fields":[{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}]
          },{
            "id":"asset-placement-request","primaryDataset":"test-dataset","route":"asset-placement-requests","mutationMode":"mutable",
            "fields":[
              {"id":"asset","type":"reference","target":"asset","required":true,"classification":"internal"},
              {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}
            ],
            "changeRequest":{"effects":[{"id":"apply-label","target":{"fromField":"asset"},"operation":"patch","set":{"label":{"fromField":"label"}}}],
              "review":{"stages":[{"id":"review","approvals":1}]}}
          }],
          "accessProfiles":[{
            "id":"asset-operator","principalClaim":"principal","grants":[{
              "entity":"asset","operations":["get","patch"],"readableFields":["label"],"writableFields":["label"]
            }]
          },{
            "id":"reviewer","default":true,"principalClaim":"principal","grants":[{
              "entity":"asset-placement-request","operations":["get","submit_request","approve_request","reject_request","request_revision","apply_request"],"readableFields":["asset","label"],
              "reviewStages":[{"stage":"review","targets":[{"entity":"asset","readableFields":["label"]}]}],
              "applyTargets":[{"entity":"asset"}]
            }]
          }]
        }"#,
    )
    .expect_err("a controlled mutation operation cannot remain directly granted");
    assert_eq!(
        diagnostic_path(&failure, "change_control.direct_write_grant"),
        "entities[id=asset].accessProfiles[id=asset-operator].operations"
    );
}

#[test]
fn change_control_required_for_empty_identifies_entity() {
    let failure = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"change-request-diagnostics","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"asset","primaryDataset":"test-dataset","route":"assets","mutationMode":"mutable","changeControl":{"requiredFor":[]},
            "fields":[{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}]
          },{
            "id":"asset-placement-request","primaryDataset":"test-dataset","route":"asset-placement-requests","mutationMode":"mutable",
            "fields":[
              {"id":"asset","type":"reference","target":"asset","required":true,"classification":"internal"},
              {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}
            ],
            "changeRequest":{"effects":[{"id":"apply-label","target":{"fromField":"asset"},"operation":"patch","set":{"label":{"fromField":"label"}}}],
              "review":{"stages":[{"id":"review","approvals":1}]}}
          }],
          "accessProfiles":[{
            "id":"reviewer","default":true,"principalClaim":"principal","grants":[{
              "entity":"asset-placement-request","operations":["get","submit_request","approve_request","reject_request","request_revision","apply_request"],"readableFields":["asset","label"],
              "reviewStages":[{"stage":"review","targets":[{"entity":"asset","readableFields":["label"]}]}],
              "applyTargets":[{"entity":"asset"}]
            }]
          }]
        }"#,
    )
    .expect_err("change control must name at least one controlled mutation operation");
    assert_eq!(
        diagnostic_path(&failure, "change_control.required_for.empty"),
        "entities[id=asset].changeControl.requiredFor"
    );
}

#[test]
fn change_request_review_stage_approvals_invalid_identifies_entity_and_stage() {
    let failure = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"change-request-diagnostics","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"asset","primaryDataset":"test-dataset","route":"assets","mutationMode":"mutable","changeControl":{"requiredFor":["patch"]},
            "fields":[{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}]
          },{
            "id":"asset-placement-request","primaryDataset":"test-dataset","route":"asset-placement-requests","mutationMode":"mutable",
            "fields":[
              {"id":"asset","type":"reference","target":"asset","required":true,"classification":"internal"},
              {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}
            ],
            "changeRequest":{"effects":[{"id":"apply-label","target":{"fromField":"asset"},"operation":"patch","set":{"label":{"fromField":"label"}}}],
              "review":{"stages":[{"id":"review","approvals":0}]}}
          }],
          "accessProfiles":[{
            "id":"reviewer","default":true,"principalClaim":"principal","grants":[{
              "entity":"asset-placement-request","operations":["get","submit_request","approve_request","reject_request","request_revision","apply_request"],"readableFields":["asset","label"],
              "reviewStages":[{"stage":"review","targets":[{"entity":"asset","readableFields":["label"]}]}],
              "applyTargets":[{"entity":"asset"}]
            }]
          }]
        }"#,
    )
    .expect_err("review stage approval counts must be within the supported bounds");
    assert_eq!(
        diagnostic_path(&failure, "change_request.review.stage.approvals_invalid"),
        "entities[id=asset-placement-request].changeRequest.review.stages[id=review].approvals"
    );
}

#[test]
fn change_request_effect_paths_use_index_when_id_missing_and_id_when_present() {
    let failure = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"change-request-diagnostics","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"asset","primaryDataset":"test-dataset","route":"assets","mutationMode":"mutable","changeControl":{"requiredFor":["create","patch"]},
            "fields":[{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}]
          },{
            "id":"asset-placement-request","primaryDataset":"test-dataset","route":"asset-placement-requests","mutationMode":"mutable",
            "fields":[
              {"id":"asset","type":"reference","target":"asset","required":true,"classification":"internal"},
              {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}
            ],
            "changeRequest":{"effects":[
              {"target":{"entity":"asset"},"operation":"create"},
              {"id":"apply-label","target":{"fromField":"asset"},"operation":"patch","set":{"nonexistent-field":{"fromField":"label"}}}
            ],"review":{"stages":[{"id":"review","approvals":1}]}}
          }],
          "accessProfiles":[{
            "id":"reviewer","default":true,"principalClaim":"principal","grants":[{
              "entity":"asset-placement-request","operations":["get","submit_request","approve_request","reject_request","request_revision","apply_request"],"readableFields":["asset","label"],
              "reviewStages":[{"stage":"review","targets":[{"entity":"asset","readableFields":["label"]}]}],
              "applyTargets":[{"entity":"asset"}]
            }]
          }]
        }"#,
    )
    .expect_err("missing create id and unknown set field must be refused");
    assert_eq!(
        diagnostic_path(&failure, "change_request.effect.create_id_required"),
        "entities[id=asset-placement-request].changeRequest.effects[0].id"
    );
    assert_eq!(
        diagnostic_path(&failure, "change_request.effect.field_unknown"),
        "entities[id=asset-placement-request].changeRequest.effects[id=apply-label].set[field=nonexistent-field]"
    );
}

#[test]
fn change_request_submit_operation_missing_identifies_entity() {
    let failure = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"change-request-diagnostics","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"asset","primaryDataset":"test-dataset","route":"assets","mutationMode":"mutable","changeControl":{"requiredFor":["patch"]},
            "fields":[{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}]
          },{
            "id":"asset-placement-request","primaryDataset":"test-dataset","route":"asset-placement-requests","mutationMode":"mutable",
            "fields":[
              {"id":"asset","type":"reference","target":"asset","required":true,"classification":"internal"},
              {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}
            ],
            "changeRequest":{"effects":[{"id":"apply-label","target":{"fromField":"asset"},"operation":"patch","set":{"label":{"fromField":"label"}}}],
              "review":{"stages":[{"id":"review","approvals":1}]}}
          }],
          "accessProfiles":[{
            "id":"asset-placement-reader","default":true,"principalClaim":"principal","grants":[{
              "entity":"asset-placement-request","operations":["get"],"readableFields":["asset","label"]
            }]
          }]
        }"#,
    )
    .expect_err("a change-request type requires at least one submit_request grant");
    assert_eq!(
        diagnostic_path(&failure, "change_request.submit_operation.missing"),
        "entities[id=asset-placement-request].accessProfiles[].operations"
    );
}

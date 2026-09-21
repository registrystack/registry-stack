// SPDX-License-Identifier: Apache-2.0
//! An entity's `sourceModule`, and the per-collection `moduleOrigins` side
//! block, name the module that contributed each id a compiled entity carries.
//! This extends the precedent `CompiledAction.source_module` already set:
//! two modules can never declare the same id (every level is a compile
//! error), so provenance is exactly one `Option<String>` per id, `Some`
//! naming a module or absent meaning the project root.

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::{parse_module_json, parse_project_json, RegistryModule};
use registry_breg::model::CompiledEntity;

fn provenance_project() -> registry_breg::contract::RegistryProject {
    parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject",
          "registry":{"id":"module-provenance","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://module-provenance.example.test"},
          "modules":[{"id":"declarer","version":"1"},{"id":"extender","version":"1"}],
          "entities":[{
            "id":"root-case","primaryDataset":"test-dataset","route":"root-cases","mutationMode":"mutable",
            "fields":[{"id":"root-field","type":"string","maxLength":8,"classification":"internal"}]
          }],
          "accessProfiles":[{
            "id":"reader","default":true,"principalClaim":"principal","permissions":[
              {"entity":"root-case","operations":["get"],"readableFields":["root-field"],"rowBoundaries":[]},
              {"entity":"module-case","operations":["get"],"readableFields":["base-field","extra-field"],"rowBoundaries":[]}
            ]
          }]
        }"#,
    )
    .expect("project parses")
}

fn declarer_module() -> RegistryModule {
    parse_module_json(
        br#"{"id":"declarer","version":"1","entities":[{
          "id":"module-case","primaryDataset":"test-dataset","route":"module-cases","mutationMode":"mutable",
          "fields":[{"id":"base-field","type":"string","maxLength":8,"classification":"internal"}],
          "hooks":[{"id":"module-case-created","phase":"after","trigger":"created","projection":["base-field"]}],
          "constraints":[{"kind":"unique","fields":["base-field"]}]
        }]}"#,
    )
    .expect("module parses")
}

fn extender_module() -> RegistryModule {
    parse_module_json(
        br#"{"id":"extender","version":"1","extendEntities":[{
          "entity":"module-case",
          "fields":[{"id":"extra-field","type":"string","maxLength":8,"classification":"internal"}],
          "hooks":[{"id":"module-case-extended","phase":"after","trigger":"created","projection":["extra-field"]}],
          "constraints":[{"kind":"unique","fields":["extra-field"]}]
        }]}"#,
    )
    .expect("module parses")
}

fn compile_fixture() -> registry_breg::CompiledRegistry {
    let project = provenance_project();
    let modules = vec![declarer_module(), extender_module()];
    compile_project(&project, &modules, CompileProfile::Authoring)
        .unwrap_or_else(|failure| panic!("module provenance fixture compiles: {failure:?}"))
}

fn constraint_id_for<'a>(entity: &'a CompiledEntity, field: &str) -> &'a str {
    entity
        .constraints
        .iter()
        .find_map(|(id, constraint)| match constraint {
            registry_breg::contract::ConstraintSource::Unique { fields, .. }
                if fields.len() == 1 && fields[0] == field =>
            {
                Some(id.as_str())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("a unique constraint over `{field}` was compiled"))
}

#[test]
fn entity_declared_by_module_carries_source_module() {
    let compiled = compile_fixture();
    let module_case = compiled
        .entities()
        .get("module-case")
        .expect("module-declared entity compiled");
    assert_eq!(module_case.source_module.as_deref(), Some("declarer"));
}

#[test]
fn entity_declared_at_project_root_omits_source_module_key() {
    let compiled = compile_fixture();
    let root_case = compiled
        .entities()
        .get("root-case")
        .expect("project-root entity compiled");
    assert_eq!(root_case.source_module, None);

    let serialized = serde_json::to_value(root_case).expect("entity serializes");
    assert!(
        serialized.get("sourceModule").is_none(),
        "a project-root entity must not serialize a sourceModule key, got {serialized}"
    );
    assert!(
        serialized.get("moduleOrigins").is_none(),
        "a project-root entity with no module contributions must not serialize a moduleOrigins key, got {serialized}"
    );
}

#[test]
fn extension_attributes_appended_ids_to_the_extending_module_only() {
    let compiled = compile_fixture();
    let module_case = compiled
        .entities()
        .get("module-case")
        .expect("extended entity compiled");

    // The entity is owned by the module that declared it, not the module
    // that later extended it.
    assert_eq!(module_case.source_module.as_deref(), Some("declarer"));

    // The field, hook, and constraint the entity declared itself are
    // attributed to the declaring module.
    assert_eq!(
        module_case.module_origins.fields.get("base-field"),
        Some(&"declarer".to_owned())
    );
    assert_eq!(
        module_case.module_origins.hooks.get("module-case-created"),
        Some(&"declarer".to_owned())
    );
    let base_constraint_id = constraint_id_for(module_case, "base-field");
    assert_eq!(
        module_case
            .module_origins
            .constraints
            .get(base_constraint_id),
        Some(&"declarer".to_owned())
    );

    // The field, hook, and constraint the extension appended are
    // attributed to the extending module, and only to it.
    assert_eq!(
        module_case.module_origins.fields.get("extra-field"),
        Some(&"extender".to_owned())
    );
    assert_eq!(
        module_case.module_origins.hooks.get("module-case-extended"),
        Some(&"extender".to_owned())
    );
    let extra_constraint_id = constraint_id_for(module_case, "extra-field");
    assert_eq!(
        module_case
            .module_origins
            .constraints
            .get(extra_constraint_id),
        Some(&"extender".to_owned())
    );

    // Neither the entity nor its originally-declared ids are attributed to
    // the extending module.
    assert_ne!(
        module_case.module_origins.fields.get("base-field"),
        Some(&"extender".to_owned())
    );
    assert_ne!(
        module_case.module_origins.hooks.get("module-case-created"),
        Some(&"extender".to_owned())
    );
}

#[test]
fn module_free_project_omits_source_module_and_module_origins() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject",
          "registry":{"id":"module-free","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://module-free.example.test"},
          "entities":[{
            "id":"case","primaryDataset":"test-dataset","route":"cases","mutationMode":"mutable",
            "fields":[{"id":"label","type":"string","maxLength":8,"classification":"internal"}],
            "hooks":[{"id":"case-created","phase":"after","trigger":"created","projection":["label"]}],
            "constraints":[{"kind":"unique","fields":["label"]}]
          }],
          "accessProfiles":[{
            "id":"reader","default":true,"principalClaim":"principal","permissions":[
              {"entity":"case","operations":["get"],"readableFields":["label"],"rowBoundaries":[]}
            ]
          }]
        }"#,
    )
    .expect("project parses");

    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .unwrap_or_else(|failure| panic!("module-free fixture compiles: {failure:?}"));
    let case = compiled
        .entities()
        .get("case")
        .expect("module-free entity compiled");

    assert_eq!(case.source_module, None);
    assert!(case.module_origins.is_empty());

    let serialized = serde_json::to_value(case).expect("entity serializes");
    assert!(serialized.get("sourceModule").is_none());
    assert!(serialized.get("moduleOrigins").is_none());
}

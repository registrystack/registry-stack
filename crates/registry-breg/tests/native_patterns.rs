// SPDX-License-Identifier: Apache-2.0

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::{parse_project_json, DerivedFieldSource, FieldSource};
use registry_breg::generated_ddl::field_pattern_constraint_name;
use serde_json::json;

fn project(pattern: Option<&str>) -> registry_breg::contract::RegistryProject {
    let mut value = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"native-patterns","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://patterns.example.test"},
        "manifestProjection":{
            "accessProfile":"reader","classificationCeiling":"internal",
            "catalog":{"baseUrl":"https://patterns.example.test","title":"Native patterns","publisher":{"id":"authority","name":"Authority"}},
            "publicService":{"id":"service","title":"Registry"},
            "datasets":[{"id":"records","title":"Records"}],
            "dataServices":[{"id":"api","title":"API","endpointUrl":"https://patterns.example.test/v1","servesDatasets":["records"]}]
        },
        "entities":[{"id":"entry","primaryDataset":"records","route":"entries","mutationMode":"mutable","classification":"internal",
            "fields":[{"id":"identifier","type":"string","maxLength":100,"classification":"internal"}]}],
        "accessProfiles":[{"id":"reader","default":true,"principalClaim":"sub","grants":[{"entity":"entry","rowBoundaries":[],"operations":["get","list"],"readableFields":["identifier"]}]}]
    });
    if let Some(pattern) = pattern {
        value["entities"][0]["fields"][0]["pattern"] = json!(pattern);
    }
    parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap()
}

#[test]
fn native_pattern_is_persisted_bounded_and_not_a_portable_schema_pattern() {
    let pattern = r"^[0-9]{13}$";
    let registry =
        compile_project(&project(Some(pattern)), &[], CompileProfile::Authoring).unwrap();
    let entity = &registry.entities()["entry"];
    assert_eq!(
        entity.fields["identifier"].pattern.as_deref(),
        Some(pattern)
    );
    let statement = registry
        .ddl()
        .statements
        .iter()
        .find(|s| s.id == "entity.entry.field.identifier.pattern")
        .unwrap();
    assert!(statement
        .sql
        .starts_with("SELECT '' ~ E'^[0-9]{13}$'; ALTER TABLE"));
    assert!(statement
        .sql
        .contains(&field_pattern_constraint_name("entry", "identifier")));
    assert!(!statement.sql.contains("NOT VALID"));
    for artifact in registry.artifacts().entries().values().filter(|a| {
        a.path.ends_with(".json") && (a.path.contains("schema") || a.path.contains("openapi"))
    }) {
        let value: serde_json::Value = serde_json::from_slice(&artifact.bytes).unwrap();
        assert!(
            !value.to_string().contains("[0-9]{13}"),
            "native expressions must not become portable regex constraints"
        );
    }
    // Compilation is deliberately structural: only PostgreSQL validates ARE syntax.
    assert!(compile_project(&project(Some("[")), &[], CompileProfile::Authoring).is_ok());
    assert!(compile_project(&project(Some("")), &[], CompileProfile::Authoring).is_ok());
    for invalid in ["x".repeat(4097), "a\0b".to_owned()] {
        let error =
            compile_project(&project(Some(&invalid)), &[], CompileProfile::Authoring).unwrap_err();
        assert!(error
            .diagnostics()
            .iter()
            .any(|d| d.code == "field.pattern.bounds_invalid"));
        assert!(!format!("{error:?}").contains(&invalid));
    }
}

#[test]
fn patterns_are_rejected_on_derived_and_non_string_fields_and_safely_quoted() {
    for kind in ["boolean", "int64", "uuid", "date"] {
        assert!(serde_json::from_value::<FieldSource>(
            json!({"id":"value","type":kind,"classification":"internal","pattern":"x"})
        )
        .is_err());
    }
    assert!(serde_json::from_value::<DerivedFieldSource>(json!({"id":"value","type":"string","maxLength":20,"classification":"internal","pattern":"x"})).is_err());
    let pattern = "a'\\b";
    let registry =
        compile_project(&project(Some(pattern)), &[], CompileProfile::Authoring).unwrap();
    let sql = &registry
        .ddl()
        .statements
        .iter()
        .find(|s| s.id == "entity.entry.field.identifier.pattern")
        .unwrap()
        .sql;
    assert!(sql.contains("E'a''\\\\b'"));
    assert!(field_pattern_constraint_name("entry", "identifier").len() <= 63);
}

#[cfg(feature = "runtime")]
#[test]
fn native_pattern_evolution_has_stable_identity_and_explicit_reviewed_changes() {
    use registry_breg::package::{
        change_set_to_applicable_migration_plan, compiled_registry_change_set,
        CompiledRegistryChangeClass as Class, CompiledRegistryChangeCode as Code,
    };
    let compile = |p| compile_project(&project(p), &[], CompileProfile::Authoring).unwrap();
    let base = compile(None);
    let added = compile(Some("[0-9]"));
    let changed = compile(Some("^[0-9]{13}$"));
    let prior = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let changes = compiled_registry_change_set(&base, &added, prior);
    assert!(changes
        .changes
        .iter()
        .any(|c| c.code == Code::FieldPatternAdded && c.class == Class::CompatibleAdditive));
    let plan = change_set_to_applicable_migration_plan(&changes).unwrap();
    assert!(plan
        .statements
        .iter()
        .any(|s| s.id == "entity.entry.field.identifier.pattern"));
    assert_eq!(
        added.physical_names().entities["entry"].constraints["pattern:identifier"],
        changed.physical_names().entities["entry"].constraints["pattern:identifier"]
    );
    for (from, to, code) in [
        (&added, &changed, Code::FieldPatternChanged),
        (&changed, &base, Code::FieldPatternRemoved),
    ] {
        let changes = compiled_registry_change_set(from, to, prior);
        assert!(changes
            .changes
            .iter()
            .any(|c| c.code == code && c.class == Class::DestructiveOrIrreversible));
        assert!(change_set_to_applicable_migration_plan(&changes).is_err());
    }
    assert!(compiled_registry_change_set(&added, &added, prior)
        .changes
        .is_empty());
}

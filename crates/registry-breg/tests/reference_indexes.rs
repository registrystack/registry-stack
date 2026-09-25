// SPDX-License-Identifier: Apache-2.0

//! Reference columns carry a compiler-owned btree index, and list filters or
//! sorts without a leading index produce an authoring-only finding.

use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use serde_json::{json, Value};

const UNINDEXED_FILTER: &str = "entity.list.unindexed_filter";
const UNINDEXED_SORT: &str = "entity.list.unindexed_sort";

fn source() -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"reference-index-example","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://reference-index.example.test"},
        "entities":[
          {"id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable","classification":"internal",
           "fields":[{"id":"name","type":"string","maxLength":80,"classification":"internal"}]},
          {"id":"asset","primaryDataset":"test-dataset","route":"assets","mutationMode":"mutable","classification":"internal",
           "fields":[{"id":"site","type":"reference","target":"site","classification":"internal"},
                     {"id":"owner","type":"reference","target":"site","classification":"internal"},
                     {"id":"code","type":"string","maxLength":8,"classification":"internal"}]}],
        "accessProfiles":[{"id":"reader","principalClaim":"registry_principal","requiredScopes":["asset:read"],
          "permissions":[{"entity":"asset","operations":["get","list"],
            "readableFields":["site","owner","code"],"filterableFields":[],"sortableFields":[],
            "rowBoundaries":[{"field":"code","claim":"codes","operator":"in"}]}]}]
    })
}

fn compile(value: &Value, profile: CompileProfile) -> CompiledRegistry {
    compile_project(
        &parse_project_json(&serde_json::to_vec(value).expect("source serializes"))
            .expect("source parses"),
        &[],
        profile,
    )
    .expect("source compiles")
}

fn asset_mut(value: &mut Value) -> &mut Value {
    &mut value["entities"][1]
}

fn statement_sql<'a>(registry: &'a CompiledRegistry, id: &str) -> Option<&'a str> {
    registry
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == id)
        .map(|statement| statement.sql.as_str())
}

fn statement_position(registry: &CompiledRegistry, id: &str) -> usize {
    registry
        .ddl()
        .statements
        .iter()
        .position(|statement| statement.id == id)
        .unwrap_or_else(|| panic!("{id} is emitted"))
}

fn index_findings(registry: &CompiledRegistry) -> Vec<(String, String)> {
    registry
        .findings()
        .iter()
        .filter(|finding| finding.code == UNINDEXED_FILTER || finding.code == UNINDEXED_SORT)
        .map(|finding| (finding.code.clone(), finding.path.clone()))
        .collect()
}

#[test]
fn every_reference_column_gets_a_btree_index_after_its_foreign_key() {
    let registry = compile(&source(), CompileProfile::Authoring);
    let asset = &registry.entities()["asset"];
    let names = &registry.physical_names().entities["asset"];
    for field in ["site", "owner"] {
        let member = format!("reference:{field}");
        assert_eq!(asset.indexes.get(&member), Some(&vec![field.to_owned()]));
        let name = &names.indexes[&member];
        assert!(name.starts_with("breg_ri_asset_"), "{name}");
        assert!(name.len() <= 63, "{name}");
        let id = format!("entity.asset.index.{member}");
        assert_eq!(
            statement_sql(&registry, &id),
            Some(
                format!(
                    "CREATE INDEX \"{name}\" ON registry_data.\"{}\" (\"{}\")",
                    asset.physical_table, asset.fields[field].physical_name
                )
                .as_str()
            )
        );
        assert!(
            statement_position(&registry, &format!("entity.asset.field.{field}.reference"))
                < statement_position(&registry, &id)
        );
    }
    assert_ne!(
        names.indexes["reference:site"],
        names.indexes["reference:owner"]
    );
    assert!(registry.entities()["site"].indexes.is_empty());
    assert!(
        asset.module_origins.indexes.is_empty(),
        "a compiler-owned index has no authored origin"
    );
}

#[test]
fn reference_index_names_stay_within_the_postgres_identifier_limit() {
    let mut value = source();
    let long_entity = "a".repeat(60);
    let long_field = "b".repeat(60);
    value["entities"]
        .as_array_mut()
        .expect("entities")
        .push(json!({"id":long_entity,"primaryDataset":"test-dataset","route":"long-entities","mutationMode":"mutable","classification":"internal",
            "fields":[{"id":long_field,"type":"reference","target":"site","classification":"internal"}]}));
    let registry = compile(&value, CompileProfile::Authoring);
    let name = &registry.physical_names().entities[&long_entity].indexes
        [&format!("reference:{long_field}")];
    assert!(name.len() <= 63, "{name}");
    assert!(name.starts_with("breg_ri_"), "{name}");
}

#[test]
fn a_leading_index_or_whole_table_unique_constraint_replaces_the_reference_index() {
    let mut value = source();
    asset_mut(&mut value)["indexes"] = json!([{"id":"by-site","fields":["site","code"]}]);
    asset_mut(&mut value)["constraints"] =
        json!([{"kind":"unique","id":"owner-code","fields":["owner","code"]}]);
    let registry = compile(&value, CompileProfile::Authoring);
    let asset = &registry.entities()["asset"];
    assert!(!asset.indexes.contains_key("reference:site"));
    assert!(!asset.indexes.contains_key("reference:owner"));
    assert!(!registry.physical_names().entities["asset"]
        .indexes
        .keys()
        .any(|member| member.starts_with("reference:")));
    assert!(!registry
        .ddl()
        .statements
        .iter()
        .any(|statement| statement.id.starts_with("entity.asset.index.reference:")));
    // The foreign keys themselves are unchanged.
    assert!(statement_sql(&registry, "entity.asset.field.site.reference").is_some());
    assert!(statement_sql(&registry, "entity.asset.field.owner.reference").is_some());
}

#[test]
fn trailing_or_partial_coverage_keeps_the_reference_index() {
    let mut value = source();
    asset_mut(&mut value)["indexes"] = json!([{"id":"by-code","fields":["code","site"]}]);
    asset_mut(&mut value)["constraints"] = json!([{"kind":"unique","id":"active-owner","fields":["owner"],
        "when":[{"kind":"active_lifecycle"}]}]);
    let registry = compile(&value, CompileProfile::Authoring);
    let asset = &registry.entities()["asset"];
    assert!(asset.indexes.contains_key("reference:site"));
    assert!(asset.indexes.contains_key("reference:owner"));
}

#[test]
fn unindexed_list_filters_and_sorts_are_authoring_findings_at_the_declaring_field() {
    let mut value = source();
    let permission = &mut value["accessProfiles"][0]["permissions"][0];
    permission["filterableFields"] = json!(["site", "code"]);
    permission["sortableFields"] = json!(["owner", "code"]);

    let registry = compile(&value, CompileProfile::Authoring);
    assert_eq!(
        index_findings(&registry),
        vec![
            (
                UNINDEXED_FILTER.to_owned(),
                "entities[id=asset].accessProfiles[id=reader].filterableFields[field=code]"
                    .to_owned()
            ),
            (
                UNINDEXED_SORT.to_owned(),
                "entities[id=asset].accessProfiles[id=reader].sortableFields[field=code]"
                    .to_owned()
            ),
        ]
    );
    let finding = registry
        .findings()
        .iter()
        .find(|finding| finding.code == UNINDEXED_FILTER)
        .expect("filter finding");
    assert!(
        finding.message.contains("entities[].indexes"),
        "{}",
        finding.message
    );
    assert!(!finding.message.contains("code"), "{}", finding.message);

    let mut indexed = value.clone();
    asset_mut(&mut indexed)["indexes"] = json!([{"id":"by-code","fields":["code"]}]);
    assert!(index_findings(&compile(&indexed, CompileProfile::Authoring)).is_empty());

    let mut unique = value.clone();
    asset_mut(&mut unique)["constraints"] =
        json!([{"kind":"unique","id":"code-unique","fields":["code","site"]}]);
    assert!(index_findings(&compile(&unique, CompileProfile::Authoring)).is_empty());
}

#[test]
fn unindexed_read_path_filters_and_sorts_point_at_the_read_path_grant() {
    let mut value = source();
    value["entities"][0]["readPaths"] =
        json!([{"id":"assets","through":"placement","to":"asset","route":"placed-assets"}]);
    value["entities"]
        .as_array_mut()
        .expect("entities")
        .push(json!({"id":"placement","primaryDataset":"test-dataset","route":"placements","mutationMode":"mutable","classification":"internal",
            "fields":[{"id":"site","type":"reference","target":"site","classification":"internal"},
                      {"id":"asset","type":"reference","target":"asset","classification":"internal"}]}));
    value["accessProfiles"][0]["permissions"]
        .as_array_mut()
        .expect("permissions")
        .push(json!({"entity":"site","operations":["get","list"],"readableFields":["name"],
            "rowBoundaries":[{"field":"name","claim":"names","operator":"in"}],
            "readPaths":[{"path":"assets","readableFields":["code","site"],"filterableFields":["code"],"sortableFields":["site"]}]}));
    let registry = compile(&value, CompileProfile::Authoring);
    assert_eq!(
        index_findings(&registry),
        vec![(
            UNINDEXED_FILTER.to_owned(),
            "entities[id=site].accessProfiles[id=reader].readPaths[path=assets].filterableFields[field=code]"
                .to_owned()
        )]
    );
}

#[test]
fn a_temporal_exclusion_scope_serves_equality_filters_but_not_sorts() {
    let mut value = source();
    let asset = asset_mut(&mut value);
    asset["fields"][1]["required"] = json!(true);
    asset["fields"][2]["required"] = json!(true);
    asset["fields"].as_array_mut().expect("fields").extend([
        json!({"id":"valid-from","type":"date","required":true,"classification":"internal"}),
        json!({"id":"valid-to","type":"date","classification":"internal"}),
    ]);
    asset["temporal"] = json!({"startField":"valid-from","endField":"valid-to"});
    asset["constraints"] = json!([{"kind":"temporal-non-overlap","id":"one-code-at-a-time",
        "scopeFields":["code","owner"],"startField":"valid-from","endField":"valid-to"}]);
    let permission = &mut value["accessProfiles"][0]["permissions"][0];
    permission["readableFields"] = json!(["site", "owner", "code", "valid-from", "valid-to"]);
    permission["filterableFields"] = json!(["code", "owner", "valid-from"]);
    permission["sortableFields"] = json!(["code"]);

    let registry = compile(&value, CompileProfile::Authoring);
    assert_eq!(
        index_findings(&registry),
        vec![
            (
                UNINDEXED_FILTER.to_owned(),
                "entities[id=asset].accessProfiles[id=reader].filterableFields[field=valid-from]"
                    .to_owned()
            ),
            (
                UNINDEXED_SORT.to_owned(),
                "entities[id=asset].accessProfiles[id=reader].sortableFields[field=code]"
                    .to_owned()
            ),
        ],
        "the exclusion index leads with its first scope field only, and a GiST index cannot order a page"
    );
    let asset = &registry.entities()["asset"];
    assert!(
        asset.indexes.contains_key("reference:owner"),
        "a trailing scope field keeps its reference index"
    );
}

#[test]
fn production_compiles_carry_no_index_findings() {
    let mut value = source();
    value["accessProfiles"][0]["permissions"][0]["filterableFields"] = json!(["code"]);
    value["accessProfiles"][0]["permissions"][0]["sortableFields"] = json!(["code"]);
    assert!(!index_findings(&compile(&value, CompileProfile::Authoring)).is_empty());
    value["package"] = json!({"environment":"local","instanceId":"reference-index-instance","sequence":1,"sourceRevision":"reference-index-source"});
    assert!(index_findings(&compile(&value, CompileProfile::Production)).is_empty());
}

#[cfg(feature = "runtime")]
mod migration {
    use registry_breg::package::{
        compiled_registry_change_set, compiled_registry_change_set_from_baseline,
        CompiledRegistryChangeClass, CompiledRegistryChangeCode, CompiledRegistryMigrationBaseline,
    };

    use super::*;

    const PRIOR_REVISION: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn index_changes(
        changes: &[registry_breg::package::CompiledRegistryChange],
    ) -> Vec<(
        CompiledRegistryChangeClass,
        CompiledRegistryChangeCode,
        String,
    )> {
        changes
            .iter()
            .filter(|change| {
                matches!(
                    change.code,
                    CompiledRegistryChangeCode::IndexAdded
                        | CompiledRegistryChangeCode::IndexRemoved
                        | CompiledRegistryChangeCode::IndexChanged
                )
            })
            .map(|change| {
                (
                    change.class,
                    change.code,
                    change.target.member_id.clone().unwrap_or_default(),
                )
            })
            .collect()
    }

    #[test]
    fn a_baseline_activated_without_reference_indexes_gains_them_additively() {
        let candidate = compile(&source(), CompileProfile::Authoring);
        // A predecessor compiled before reference columns were indexed carries
        // neither the index member nor its physical name.
        let mut baseline =
            CompiledRegistryMigrationBaseline::from_compiled(PRIOR_REVISION, &candidate);
        for entity in baseline.entities.values_mut() {
            entity
                .indexes
                .retain(|member, _| !member.starts_with("reference:"));
        }
        for names in baseline.physical_names.entities.values_mut() {
            names
                .indexes
                .retain(|member, _| !member.starts_with("reference:"));
        }
        let change_set =
            compiled_registry_change_set_from_baseline(&baseline, &candidate, PRIOR_REVISION);
        assert_eq!(
            index_changes(&change_set.changes),
            vec![
                (
                    CompiledRegistryChangeClass::CompatibleAdditive,
                    CompiledRegistryChangeCode::IndexAdded,
                    "reference:owner".to_owned()
                ),
                (
                    CompiledRegistryChangeClass::CompatibleAdditive,
                    CompiledRegistryChangeCode::IndexAdded,
                    "reference:site".to_owned()
                ),
            ]
        );
        assert_eq!(change_set.changes.len(), 2, "{:#?}", change_set.changes);
        let plan = change_set
            .migration_plan
            .expect("reference indexes apply without reviewed SQL");
        let ids = plan
            .statements
            .iter()
            .map(|statement| statement.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "entity.asset.index.reference:owner",
                "entity.asset.index.reference:site",
            ]
        );
        assert!(plan
            .statements
            .iter()
            .all(|statement| statement.sql.starts_with("CREATE INDEX \"breg_ri_asset_")));
    }

    #[test]
    fn a_covering_authored_index_drops_the_reference_index_without_review() {
        let previous = compile(&source(), CompileProfile::Authoring);
        let prior_name =
            previous.physical_names().entities["asset"].indexes["reference:site"].clone();
        let mut value = source();
        asset_mut(&mut value)["indexes"] = json!([{"id":"by-site","fields":["site","code"]}]);
        let candidate = compile(&value, CompileProfile::Authoring);

        let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
        assert_eq!(
            index_changes(&change_set.changes),
            vec![
                (
                    CompiledRegistryChangeClass::CompatibleAdditive,
                    CompiledRegistryChangeCode::IndexAdded,
                    "by-site".to_owned()
                ),
                (
                    CompiledRegistryChangeClass::CompatibleAdditive,
                    CompiledRegistryChangeCode::IndexRemoved,
                    "reference:site".to_owned()
                ),
            ]
        );
        let plan = change_set
            .migration_plan
            .expect("replacing a compiler-owned index needs no reviewed SQL");
        let statements = plan
            .statements
            .iter()
            .map(|statement| (statement.id.as_str(), statement.sql.as_str()))
            .collect::<Vec<_>>();
        let drop_sql = format!("DROP INDEX IF EXISTS registry_data.\"{prior_name}\"");
        assert_eq!(
            statements[0],
            ("entity.asset.index.reference:site.drop", drop_sql.as_str())
        );
        assert_eq!(statements[1].0, "entity.asset.index.by-site");
        assert_eq!(statements.len(), 2, "{statements:#?}");
    }

    #[test]
    fn removing_an_authored_index_still_requires_review() {
        let mut value = source();
        asset_mut(&mut value)["indexes"] = json!([{"id":"by-code","fields":["code"]}]);
        let previous = compile(&value, CompileProfile::Authoring);
        let candidate = compile(&source(), CompileProfile::Authoring);
        let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
        assert_eq!(
            index_changes(&change_set.changes),
            vec![(
                CompiledRegistryChangeClass::DestructiveOrIrreversible,
                CompiledRegistryChangeCode::IndexRemoved,
                "by-code".to_owned()
            )]
        );
        assert!(change_set.migration_plan.is_none());
    }
}

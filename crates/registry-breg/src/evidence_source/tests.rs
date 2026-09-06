// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_json, ModuleAssetSource},
};

fn project() -> Value {
    json!({"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject",
        "registry":{"id":"example","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test"},
        "entities":[{"id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"mutable","fields":[
            {"id":"code","type":"string","minLength":1,"maxLength":32,"required":true,"classification":"internal"},
            {"id":"registration-number","type":"string","minLength":1,"maxLength":32,"classification":"internal"},
            {"id":"status","type":"string","maxLength":16,"classification":"internal"},
            {"id":"tenant","type":"string","maxLength":16,"classification":"internal"}],
            "selectorProfiles":[{"id":"by-code","fields":["code"]},{"id":"by-registration-number","fields":["registration-number"]}],
            "derived":[{"id":"status-read","sql":"status.sql","key":"id","execution":"live","fields":[{"id":"active","type":"boolean","classification":"internal"}]}]}],
        "accessProfiles":[{"id":"evidence-source","principalClaim":"principal","requiredScopes":["registry.read"],"grants":[{
            "entity":"record","operations":["lookup"],"readableFields":["code","registration-number","status","active"],
            "lookups":[{"selector":"by-code","valueOrigin":"request"},{"selector":"by-registration-number","valueOrigin":"request"}],
            "rowBoundaries":[{"field":"tenant","claim":"tenant","operator":"equals"}]}]}]})
}

fn compiled(project: &Value, sql: &str) -> CompiledRegistry {
    let source = parse_project_json(&serde_json::to_vec(project).unwrap()).unwrap();
    compile_project_with_assets(
        &source,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "status.sql".into(),
            bytes: sql.as_bytes().to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap()
}

const SQL: &str = "SELECT r.id AS id, r.status = 'active' AS active FROM registry_source.record r";
fn options() -> EvidenceSourceOptions {
    EvidenceSourceOptions {
        access_profile: "evidence-source".into(),
        entity: "record".into(),
        selectors: vec!["by-code".into(), "by-registration-number".into()],
        fields: vec!["status".into()],
        source_id: "registry-status".into(),
        connection: "registry".into(),
    }
}
fn file<'a>(export: &'a EvidenceSourceExport, path: &str) -> &'a [u8] {
    &export
        .artifacts
        .iter()
        .find(|artifact| artifact.path == path)
        .unwrap()
        .bytes
}
fn yaml(export: &EvidenceSourceExport, path: &str) -> Value {
    serde_json::from_slice(file(export, path)).unwrap()
}

fn refused(registry: &CompiledRegistry, options: &EvidenceSourceOptions) -> Diagnostic {
    match export_evidence_source(registry, options) {
        Err(diagnostic) => diagnostic,
        Ok(_) => panic!("the exporter accepted an input it must refuse"),
    }
}

#[test]
fn alternatives_keep_one_route_and_selected_identity_with_stable_inventories() {
    let registry = compiled(&project(), SQL);
    let export = export_evidence_source(&registry, &options()).unwrap();
    let source = yaml(&export, "sources/registry-status.yaml");
    assert_eq!(source["request"]["path"], "/v1/records/records:lookup");
    assert_eq!(source["request"]["method"], "POST");
    assert_eq!(source["connection"], "registry");
    assert!(source.get("authentication").is_none());
    assert!(source.get("baseUrl").is_none());
    assert_eq!(
        source["request"]["selectorInputs"][0]["alternatives"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(export.identity_fields["by-code"], vec!["code"]);
    assert_eq!(
        export.identity_fields["by-registration-number"],
        vec!["registration-number"]
    );
    let script =
        std::str::from_utf8(file(&export, "adapters/registry-status-prepare.rhai")).unwrap();
    assert!(script.contains("value: \"code,status\""));
    assert!(script.contains("value: \"registrationNumber,status\""));
    assert!(!script.contains("code,registrationNumber,status"));
    assert!(script.contains("\"registrationNumber\": subject[\"values\"][\"registration-number\"]"));
    let extract =
        std::str::from_utf8(file(&export, "adapters/registry-status-extract.rhai")).unwrap();
    assert!(extract.contains("fn extract(response, selectors, context)"));
    assert!(
        extract.contains("type_of(record[\"code\"])") && extract.contains("source_protocol_error")
    );
    assert!(extract.find("source_protocol_error").unwrap() < extract.find("facts:").unwrap());
    let facts = yaml(&export, "schemas/registry-status-facts.yaml");
    assert_eq!(facts["required"], json!(["status"]));
    assert!(facts["properties"].get("code").is_none());
    let response = yaml(&export, "schemas/registry-status-response.yaml");
    assert_eq!(
        response["properties"]["data"]["properties"]["domainData"]["properties"]["status"]["type"],
        json!(["string", "null"])
    );
    let manifest = yaml(&export, "source-export.json");
    for entry in manifest["artifacts"].as_array().unwrap() {
        assert_eq!(
            entry["sha256"],
            digest(file(&export, entry["path"].as_str().unwrap()))
        );
    }
    let mut reordered = options();
    reordered.selectors.reverse();
    assert_eq!(
        export.artifacts,
        export_evidence_source(&registry, &reordered)
            .unwrap()
            .artifacts
    );
    assert!(!String::from_utf8(serde_json::to_vec(&manifest).unwrap())
        .unwrap()
        .contains("rowBoundaries"));
}

#[test]
fn consumed_behavior_ignores_unselected_fields_but_reaches_sql_and_authority() {
    let original = project();
    let before = export_evidence_source(&compiled(&original, SQL), &options()).unwrap();
    let mut unrelated = original.clone();
    unrelated["entities"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"note","type":"string","maxLength":64,"classification":"internal"}));
    let after = export_evidence_source(&compiled(&unrelated, SQL), &options()).unwrap();
    assert_eq!(before.behavior_revision, after.behavior_revision);
    assert_ne!(
        yaml(&before, "source-export.json")["provenance"]["packageRevision"],
        yaml(&after, "source-export.json")["provenance"]["packageRevision"]
    );
    let changed_sql =
        "SELECT r.id AS id, r.status <> 'active' AS active FROM registry_source.record r";
    assert_eq!(
        before.behavior_revision,
        export_evidence_source(&compiled(&original, changed_sql), &options())
            .unwrap()
            .behavior_revision
    );
    let mut derived = options();
    derived.fields = vec!["active".into()];
    let derived_before = export_evidence_source(&compiled(&original, SQL), &derived).unwrap();
    assert_ne!(
        derived_before.behavior_revision,
        export_evidence_source(&compiled(&original, changed_sql), &derived)
            .unwrap()
            .behavior_revision
    );
    assert_ne!(
        derived_before.behavior_revision,
        export_evidence_source(&compiled(&unrelated, SQL), &derived)
            .unwrap()
            .behavior_revision
    );
    let mut authority = original.clone();
    authority["accessProfiles"][0]["grants"][0]["rowBoundaries"][0]["claim"] =
        json!("other_tenant");
    assert_ne!(
        before.behavior_revision,
        export_evidence_source(&compiled(&authority, SQL), &options())
            .unwrap()
            .behavior_revision
    );
}

#[test]
fn refuses_ungiven_authority_and_incompatible_selector_semantics() {
    let mut hidden = project();
    hidden["accessProfiles"][0]["grants"][0]["readableFields"] = json!(["status", "active"]);
    assert!(export_evidence_source(&compiled(&hidden, SQL), &options()).is_err());
    let mut claims = project();
    claims["accessProfiles"][0]["grants"][0]["lookups"][0] =
        json!({"selector":"by-code","valueOrigin":"verified_claim","claimMapping":{"code":"code"}});
    assert!(export_evidence_source(&compiled(&claims, SQL), &options()).is_err());
    assert!(selector_schema(&FieldTypeSource::Int64).is_err());
    assert!(selector_schema(&FieldTypeSource::String {
        min_length: 1,
        max_length: 2049
    })
    .is_err());
    let (unicode, maximum) = selector_schema(&FieldTypeSource::String {
        min_length: 5,
        max_length: 20,
    })
    .unwrap();
    assert_eq!(maximum, 80);
    assert_eq!(
        unicode["minimumBytes"], 1,
        "character minimum remains provider-owned; byte count must not silently normalize identity"
    );
    assert_eq!(
        selector_schema(&FieldTypeSource::Boolean).unwrap().0,
        json!({"type":"boolean"})
    );
}

#[test]
fn reached_source_select_authority_is_part_of_consumed_behavior() {
    let mut original = project();
    original["entities"].as_array_mut().unwrap().push(json!({"id":"flag","primaryDataset":"test-dataset","route":"flags","mutationMode":"mutable","fields":[
        {"id":"code","type":"string","maxLength":32,"classification":"internal"},
        {"id":"enabled","type":"boolean","classification":"internal"}]}));
    original["accessProfiles"][0]["grants"].as_array_mut().unwrap().push(json!({"entity":"flag","operations":["get"],"readableFields":["code","enabled"],"rowBoundaries":[]}));
    let sql="SELECT r.id AS id, f.enabled AS active FROM registry_source.record r JOIN registry_source.flag f ON f.code = r.code";
    let mut selection = options();
    selection.fields = vec!["active".into()];
    let before = export_evidence_source(&compiled(&original, sql), &selection).unwrap();
    original["accessProfiles"][0]["grants"][1] = json!({"entity":"flag","operations":["create"],"writableFields":["code","enabled"],"rowBoundaries":[]});
    let after = export_evidence_source(&compiled(&original, sql), &selection).unwrap();
    assert_ne!(
        before.behavior_revision, after.behavior_revision,
        "same source schema and boundaries cannot mask loss of SELECT RLS authority"
    );
}

#[test]
fn scalar_documents_preserve_int64_and_nullable_vocabulary_bounds() {
    let schema = scalar_schema(&FieldTypeSource::Int64).unwrap();
    let artifact = document("schemas/example.yaml".into(), &schema).unwrap();
    let actual: Value = serde_json::from_slice(&artifact.bytes).unwrap();
    assert_eq!(actual["minimum"].as_i64(), Some(i64::MIN));
    assert_eq!(actual["maximum"].as_i64(), Some(i64::MAX));
    assert!(scalar_schema(&FieldTypeSource::String {
        min_length: 1,
        max_length: 65_537
    })
    .is_err());
    assert!(scalar_schema(&FieldTypeSource::Text { max_length: 65_537 }).is_err());
    let mut original = project();
    original["entities"][0]["fields"][2] = json!({"id":"status","type":"vocabulary-code","vocabulary":"status","values":["active","retired"],"classification":"internal"});
    let export = export_evidence_source(&compiled(&original, SQL), &options()).unwrap();
    let response = yaml(&export, "schemas/registry-status-response.yaml");
    let status =
        &response["properties"]["data"]["properties"]["domainData"]["properties"]["status"];
    assert_eq!(status["type"], json!(["string", "null"]));
    assert!(
        status.get("enum").is_none(),
        "fact enum must not prevent nullable source data reaching extraction"
    );
    assert_eq!(
        yaml(&export, "schemas/registry-status-facts.yaml")["properties"]["status"]["enum"],
        json!(["active", "retired"])
    );
}

#[test]
fn refuses_alternative_union_that_exceeds_runtime_projection_bound() {
    let mut original = project();
    let mut selection = options();
    selection.selectors.clear();
    for alternative in 0..5 {
        let selector = format!("s{alternative}");
        let mut fields = Vec::new();
        for index in 0..13 {
            let id = format!("key-{alternative}-{index}");
            original["entities"][0]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id":id,"type":"string","maxLength":1,"classification":"internal"}));
            original["accessProfiles"][0]["grants"][0]["readableFields"]
                .as_array_mut()
                .unwrap()
                .push(json!(id));
            fields.push(id);
        }
        original["entities"][0]["selectorProfiles"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":selector,"fields":fields}));
        original["accessProfiles"][0]["grants"][0]["lookups"]
            .as_array_mut()
            .unwrap()
            .push(json!({"selector":selector,"valueOrigin":"request"}));
        selection.selectors.push(selector);
    }
    assert!(export_evidence_source(&compiled(&original, SQL), &selection).is_err());
}

#[test]
fn emitted_extract_checks_the_returned_identity_by_exact_value_and_scalar_type() {
    let export = export_evidence_source(&compiled(&project(), SQL), &options()).unwrap();
    let extract =
        std::str::from_utf8(file(&export, "adapters/registry-status-extract.rhai")).unwrap();
    // The Evidence adapter, not BReg, rejects a substituted record. The exporter is
    // the only place this check is written, so pin the emitted comparison verbatim.
    assert!(extract.contains(
        "if is_missing(record[\"code\"]) \
         || type_of(record[\"code\"]) != type_of(subject[\"values\"][\"code\"]) \
         || record[\"code\"] != subject[\"values\"][\"code\"] \
         { throw \"source_protocol_error\"; }"
    ));
    assert!(extract.contains(
        "if is_missing(record[\"registrationNumber\"]) \
         || type_of(record[\"registrationNumber\"]) \
            != type_of(subject[\"values\"][\"registration-number\"]) \
         || record[\"registrationNumber\"] != subject[\"values\"][\"registration-number\"] \
         { throw \"source_protocol_error\"; }"
    ));
}

#[test]
fn refuses_change_request_lifecycle_entities() {
    let mut original = project();
    original["entities"][0]["changeControl"] = json!({"requiredFor":["patch"]});
    original["entities"].as_array_mut().unwrap().push(json!({
        "id":"record-request","primaryDataset":"test-dataset","route":"record-requests","mutationMode":"mutable",
        "fields":[
            {"id":"code","type":"string","minLength":1,"maxLength":32,"required":true,"classification":"internal"},
            {"id":"subject","type":"reference","target":"record","required":true,"classification":"internal"},
            {"id":"new-status","type":"string","maxLength":16,"required":true,"classification":"internal"}],
        "selectorProfiles":[{"id":"by-code","fields":["code"]}],
        "changeRequest":{
            "effects":[{"target":{"fromField":"subject"},"operation":"patch","set":{"status":{"fromField":"new-status"}}}],
            "review":{"stages":[{"id":"review","approvals":1}]}}}));
    original["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"record-request-steward","principalClaim":"principal","requiredScopes":["registry.write"],
            "grants":[{"entity":"record-request","rowBoundaries":[],
                "operations":["create","get","submit_request","approve_request","apply_request"],
                "readableFields":["code","subject","new-status"],
                "writableFields":["code","subject","new-status"],
                "reviewStages":[{"stage":"review","targets":[{"entity":"record","readableFields":["status"],"rowBoundaries":[]}]}],
                "applyTargets":[{"entity":"record","rowBoundaries":[]}]}]}));
    original["accessProfiles"][0]["grants"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"entity":"record-request","operations":["lookup"],"readableFields":["code"],
            "lookups":[{"selector":"by-code","valueOrigin":"request"}],"rowBoundaries":[]}),
        );
    let mut selection = options();
    selection.entity = "record-request".into();
    selection.selectors = vec!["by-code".into()];
    selection.fields = vec!["code".into()];
    // The lookup is granted and routed; only the lifecycle shape is refused.
    let diagnostic = refused(&compiled(&original, SQL), &selection);
    assert_eq!(diagnostic.code, "evidence_source.refused");
    assert_eq!(
        diagnostic.message,
        "change-request lifecycle records require a reviewed custom Evidence adapter"
    );
}

#[test]
fn refuses_a_profile_that_does_not_grant_lookup() {
    let mut original = project();
    original["accessProfiles"][0]["grants"][0]["operations"] = json!(["get"]);
    original["accessProfiles"][0]["grants"][0]["lookups"] = json!([]);
    let diagnostic = refused(&compiled(&original, SQL), &options());
    assert_eq!(diagnostic.code, "evidence_source.refused");
    assert_eq!(
        diagnostic.message,
        "the selected profile does not grant lookup; declare and review that authority in BReg first"
    );
}

#[test]
fn refuses_a_lookup_grant_without_a_compiled_lookup_route() {
    let mut compiled_registry = serde_json::to_value(compiled(&project(), SQL)).unwrap();
    compiled_registry["routeInventory"]["routes"]
        .as_array_mut()
        .unwrap()
        .retain(|route| route["operation"] != json!("lookup"));
    let routeless: CompiledRegistry = serde_json::from_value(compiled_registry).unwrap();
    let diagnostic = refused(&routeless, &options());
    assert_eq!(diagnostic.code, "evidence_source.refused");
    assert_eq!(
        diagnostic.message,
        "the compiled profile has no lookup route"
    );
}

#[test]
fn refuses_selector_names_beyond_the_evidence_profile_name_bound() {
    let mut original = project();
    let selector = format!("by-{}", "a".repeat(37));
    original["entities"][0]["selectorProfiles"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":selector,"fields":["code"]}));
    original["accessProfiles"][0]["grants"][0]["lookups"]
        .as_array_mut()
        .unwrap()
        .push(json!({"selector":selector,"valueOrigin":"request"}));
    let mut selection = options();
    selection.selectors = vec![selector];
    let diagnostic = refused(&compiled(&original, SQL), &selection);
    assert_eq!(diagnostic.code, "evidence_source.refused");
    assert_eq!(
        diagnostic.message,
        "the connection/entity/selector names produce a profile longer than 64 bytes; use shorter stable technical names or a custom adapter"
    );
}

#[test]
fn refuses_a_composite_selector_beyond_the_aggregate_selector_bound() {
    let mut original = project();
    let mut fields = Vec::new();
    for index in 0..3 {
        let id = format!("part-{index}");
        original["entities"][0]["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":id,"type":"string","minLength":1,"maxLength":1000,"classification":"internal"}));
        original["accessProfiles"][0]["grants"][0]["readableFields"]
            .as_array_mut()
            .unwrap()
            .push(json!(id));
        fields.push(id);
    }
    original["entities"][0]["selectorProfiles"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"by-parts","fields":fields}));
    original["accessProfiles"][0]["grants"][0]["lookups"]
        .as_array_mut()
        .unwrap()
        .push(json!({"selector":"by-parts","valueOrigin":"request"}));
    let mut selection = options();
    selection.selectors = vec!["by-parts".into()];
    // Each field stays inside the per-selector bound; only their union crosses it.
    let diagnostic = refused(&compiled(&original, SQL), &selection);
    assert_eq!(diagnostic.code, "evidence_source.refused");
    assert_eq!(
        diagnostic.message,
        "the complete composite selector exceeds Evidence's 8192-byte bound"
    );
}

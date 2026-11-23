// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_json, ModuleAssetSource},
};

fn project() -> Value {
    json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"example","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test"},
        "datasets":{"test-dataset": {}},"recordTypes":{"record": {"primaryDataset":"test-dataset","route":"records","mutationMode":"mutable","fields":[
            {"id":"code","type":"string","minimumLength":1,"maximumLength":32,"required":true,"classification":"internal"},
            {"id":"registration-number","type":"string","minimumLength":1,"maximumLength":32,"classification":"internal"},
            {"id":"status","type":"string","maximumLength":16,"classification":"internal"},
            {"id":"tenant","type":"string","maximumLength":16,"classification":"internal"}],
            "selectorProfiles":[{"id":"by-code","fields":["code"]},{"id":"by-registration-number","fields":["registration-number"]}],
            "derived":[{"id":"status-read","sql":"status.sql","key":"id","execution":"live","fields":[{"id":"active","type":"boolean","classification":"internal"}]}]}},
        "accessProfiles":{"evidence-source": {"principalClaim":"principal","requiredScopes":["registry.read"],"permissions":{"records":[{
            "recordType":"record","operations":["lookup"],"readableFields":["code","registration-number","status","active"],
            "lookups":[{"selector":"by-code","valueOrigin":"request"},{"selector":"by-registration-number","valueOrigin":"request"}],
            "rowBoundaries":[{"field":"tenant","claim":"tenant","operator":"equals"}]}]}}}})
}

fn compile(
    project: &Value,
    sql: &str,
) -> Result<CompiledRegistry, crate::diagnostics::CompileFailure> {
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
}

fn compiled(project: &Value, sql: &str) -> CompiledRegistry {
    compile(project, sql).unwrap()
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
        authentication: EvidenceSourceAuthentication::StaticAuthorization,
        required_values: BTreeMap::new(),
        optional_fields: Vec::new(),
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
    assert_eq!(source["pack"]["id"], "registry-status");
    assert_eq!(source["route"], "lookup");
    assert_eq!(source["connection"], "registry");
    assert_eq!(source["acquisitionPosture"], "field-projected");
    let inputs = source["inputs"].as_object().unwrap();
    assert_eq!(
        inputs.keys().collect::<Vec<_>>(),
        [
            "by-code--code",
            "by-registration-number--registration-number"
        ]
    );
    assert_eq!(inputs["by-code--code"]["selector"]["field"], json!("code"));
    assert!(source.get("request").is_none());
    assert_eq!(export.identity_fields["by-code"], vec!["code"]);
    assert_eq!(
        export.identity_fields["by-registration-number"],
        vec!["registration-number"]
    );
    let script = std::str::from_utf8(file(
        &export,
        "adapter-packs/registry-status/scripts/lookup.rhai",
    ))
    .unwrap();
    assert!(script.contains("return \"code,status\""));
    assert!(script.contains("return \"registrationNumber,status\""));
    assert!(!script.contains("code,registrationNumber,status"));
    assert!(script.contains(
        "\"registrationNumber\": inputs[\"by-registration-number--registration-number\"]"
    ));
    assert!(script.contains("fn lookup(exchange)"));
    assert!(script.contains("fn project_response(exchange)"));
    assert!(script.contains("if record[\"status\"] == () { return #{lookup: \"no-match\"}; }"));
    assert!(!script.contains("return #{lookup: \"unresolved\"};"));
    assert!(!script.contains("is_missing("));
    assert!(script.contains("exchange.headers[\"camelhttpresponsecode\"] == 404"));
    assert!(!script.contains("exchange.body.type") && !script.contains("lookup.unresolved"));
    assert!(
        script.contains("type_of(record[\"code\"])") && script.contains("source_protocol_error")
    );
    assert!(script.find("source_protocol_error").unwrap() < script.find("facts:").unwrap());
    let facts = yaml(&export, "adapter-packs/registry-status/schemas/facts.json");
    assert_eq!(facts["required"], json!(["status"]));
    assert!(facts["properties"].get("code").is_none());
    let response = yaml(
        &export,
        "adapter-packs/registry-status/schemas/response.json",
    );
    assert_eq!(
        response["properties"]["data"]["properties"]["domainData"]["properties"]["status"]["type"],
        json!(["string", "null"])
    );
    let pack = yaml(&export, "adapter-packs/registry-status/pack.yaml");
    let steps = pack["sourceRoutes"][0]["steps"].as_array().unwrap();
    let send = steps
        .iter()
        .find_map(|step| step.get("to"))
        .expect("the pack owns the BReg lookup request");
    assert_eq!(send["parameters"]["httpMethod"], "POST");
    assert_eq!(send["parameters"]["path"], "/v1/records/records:lookup");
    assert_eq!(
        send["parameters"]["query"]["accessProfile"]["constant"],
        "evidence-source"
    );
    assert_eq!(
        send["parameters"]["query"]["$select"]["exchangeProperty"],
        "bregSelect"
    );
    assert_eq!(send["parameters"]["body"]["jsonpath"], "$");
    assert_eq!(send["parameters"]["throwExceptionOnFailure"], false);
    let choice = steps
        .iter()
        .find_map(|step| step.get("choice"))
        .expect("the protocol's canonical unresolved sentinel stops the provider path");
    assert_eq!(choice["when"][0]["rhai"]["entrypoint"], "is_unresolved");
    assert_eq!(choice["when"][0]["steps"][0]["stop"], json!({}));
    let projection = steps
        .iter()
        .position(|step| {
            step.get("setBody")
                .and_then(|set_body| set_body.get("rhai"))
                .and_then(|rhai| rhai.get("entrypoint"))
                .is_some_and(|entrypoint| entrypoint == "project_response")
        })
        .expect("the reviewed script projects the provider record");
    let response_gate = steps
        .iter()
        .position(|step| step.get("validateSchema").is_some())
        .expect("the projected provider response is schema-checked");
    let extraction = steps
        .iter()
        .position(|step| {
            step.get("setBody")
                .and_then(|set_body| set_body.get("rhai"))
                .and_then(|rhai| rhai.get("entrypoint"))
                .is_some_and(|entrypoint| entrypoint == "lookup")
        })
        .expect("the checked projection is extracted");
    assert!(projection < response_gate && response_gate < extraction);
    let endpoint = &pack["endpoints"][0];
    assert_eq!(endpoint["authentication"]["type"], "static-authorization");
    assert_eq!(endpoint["hostProtocol"]["id"], "registry-lookup-v1");
    assert_eq!(endpoint["operations"][0]["safeUpstream"], true);
    assert_eq!(endpoint["requestHeaders"], json!(["accept"]));
    assert!(!steps.iter().any(|step| {
        step.get("setHeader")
            .and_then(|header| header.get("name"))
            .is_some_and(|name| name == "Content-Type")
    }));
    let protocol = yaml(
        &export,
        "adapter-packs/registry-status/protocols/registry-lookup.json",
    );
    assert_eq!(
        protocol,
        json!({
            "unresolvedProblem":{
                "status":404,
                "type":crate::problem::ProblemCode::LookupUnresolved.type_uri(),
                "code":"lookup.unresolved"
            },
            "forwardAccessAttribution":false
        })
    );
    let manifest = yaml(&export, "source-export.json");
    assert_eq!(manifest["apiVersion"], EVIDENCE_SOURCE_EXPORT_API_VERSION);
    assert_eq!(manifest["kind"], EVIDENCE_SOURCE_EXPORT_KIND);
    assert!(std::str::from_utf8(file(&export, "source-export.json"))
        .unwrap()
        .starts_with(&format!(
            "{{\"apiVersion\":\"{EVIDENCE_SOURCE_EXPORT_API_VERSION}\",\"kind\":\"{EVIDENCE_SOURCE_EXPORT_KIND}\","
        )));
    for entry in manifest["artifacts"].as_array().unwrap() {
        assert_eq!(
            entry["digest"],
            format!(
                "sha256:{}",
                digest(file(&export, entry["path"].as_str().unwrap()))
            )
        );
    }
    assert!(manifest["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| { entry["path"] == "adapter-packs/registry-status/pack.yaml" }));
    assert!(!manifest["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| {
            entry["path"]
                .as_str()
                .is_some_and(|path| path.starts_with("functions/") || path.starts_with("adapters/"))
        }));
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
fn generated_pack_authentication_is_explicitly_selected() {
    let registry = compiled(&project(), SQL);
    let static_export = export_evidence_source(&registry, &options()).unwrap();
    let mut selected = options();
    selected.authentication = EvidenceSourceAuthentication::Oauth2PrivateKeyJwt;

    let export = export_evidence_source(&registry, &selected).unwrap();
    let pack = yaml(&export, "adapter-packs/registry-status/pack.yaml");
    let manifest = yaml(&export, "source-export.json");

    assert_eq!(
        pack["endpoints"][0]["authentication"],
        json!({"type":"oauth2-private-key-jwt"})
    );
    assert_ne!(export.behavior_revision, static_export.behavior_revision);
    assert_eq!(pack["version"], export.behavior_revision);
    assert_eq!(
        manifest["provenance"]["behaviorRevision"],
        export.behavior_revision
    );
}

#[test]
fn missing_fact_outcome_is_bound_into_behavior_revision() {
    let registry = compiled(&project(), SQL);
    let entity = &registry.entities()["record"];
    let behavior = selected_behavior(
        &registry,
        entity,
        &options(),
        &FactRules {
            required: BTreeMap::new(),
            optional: BTreeSet::new(),
        },
        &BTreeSet::from(["status".into()]),
        vec![],
        Map::new(),
    )
    .unwrap();
    assert_eq!(behavior["missingFactOutcome"], "no-match");

    let revision = format!("sha256:{}", digest(&canonical(&behavior).unwrap()));
    let mut unresolved = behavior;
    unresolved["missingFactOutcome"] = json!("unresolved");
    let unresolved_revision = format!("sha256:{}", digest(&canonical(&unresolved).unwrap()));
    assert_ne!(revision, unresolved_revision);
}

#[test]
fn exported_fragments_match_the_evidence_owned_header_contracts() {
    use registry_evidence_authoring::formats::{
        decode_authored, SELECTOR_FRAGMENT, SOURCE_FRAGMENT,
    };

    let export = export_evidence_source(&compiled(&project(), SQL), &options()).unwrap();
    let decoded = decode_authored::<registry_evidence_authoring::project::Source>(
        "sources/registry-status.yaml",
        file(&export, "sources/registry-status.yaml"),
        &SOURCE_FRAGMENT,
    )
    .expect("the exported Source matches the Evidence-owned format");
    assert_eq!(decoded.value.pack.id.as_str(), "registry-status");
    assert_eq!(decoded.value.route.as_str(), "lookup");

    for artifact in export.artifacts.iter().filter(|artifact| {
        artifact.path.starts_with("selectors/") && artifact.path.ends_with(".yaml")
    }) {
        decode_authored::<Value>(&artifact.path, &artifact.bytes, &SELECTOR_FRAGMENT)
            .expect("the exported selector matches the Evidence-owned format");
    }
}

#[test]
fn the_source_is_spelled_as_evidence_reads_it() {
    let registry = compiled(&project(), SQL);
    let export = export_evidence_source(&registry, &options()).unwrap();
    let source = yaml(&export, "sources/registry-status.yaml");
    assert!(source.get("type").is_none());
    assert!(source.get("request").is_none());
    assert!(source.get("extractScript").is_none());
    assert!(source.get("behaviorRevision").is_none());
}

#[test]
fn logged_entity_export_enables_attribution_and_binds_policy_into_behavior_revision() {
    let original = project();
    let before = export_evidence_source(&compiled(&original, SQL), &options()).unwrap();
    let mut logged = original.clone();
    logged["recordTypes"]["record"]["accessLog"] = json!({
        "subjectField": "code",
        "retentionDays": 90,
        "trustedIntermediaries": ["evidence-service"]
    });
    let after = export_evidence_source(&compiled(&logged, SQL), &options()).unwrap();
    let pack = yaml(&after, "adapter-packs/registry-status/pack.yaml");
    assert_eq!(
        pack["endpoints"][0]["hostProtocol"]["id"],
        "registry-lookup-v1"
    );
    let protocol = yaml(
        &after,
        "adapter-packs/registry-status/protocols/registry-lookup.json",
    );
    assert_eq!(protocol["forwardAccessAttribution"], true);
    assert_ne!(before.behavior_revision, after.behavior_revision);
}

#[test]
fn consumed_behavior_ignores_unselected_fields_but_reaches_sql_and_authority() {
    let original = project();
    let before = export_evidence_source(&compiled(&original, SQL), &options()).unwrap();
    let mut unrelated = original.clone();
    unrelated["recordTypes"]["record"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"note","type":"string","maximumLength":64,"classification":"internal"}));
    let after = export_evidence_source(&compiled(&unrelated, SQL), &options()).unwrap();
    assert_eq!(before.behavior_revision, after.behavior_revision);
    let before_provenance = &yaml(&before, "source-export.json")["provenance"];
    let after_provenance = &yaml(&after, "source-export.json")["provenance"];
    assert!(before_provenance["registryRevision"].is_string());
    assert!(before_provenance.get("packageRevision").is_none());
    assert_ne!(
        before_provenance["registryRevision"],
        after_provenance["registryRevision"]
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
    authority["accessProfiles"]["evidence-source"]["permissions"]["records"][0]["rowBoundaries"]
        [0]["claim"] = json!("other_tenant");
    assert_ne!(
        before.behavior_revision,
        export_evidence_source(&compiled(&authority, SQL), &options())
            .unwrap()
            .behavior_revision
    );
}

fn membership_project() -> Value {
    let mut source = project();
    source["recordTypes"]["record"]["fields"].as_array_mut().unwrap().push(json!({
        "id":"organization","type":"reference","target":"organization","classification":"internal"
    }));
    source["recordTypes"].as_object_mut().unwrap().extend([
        ("organization".to_owned(), json!({"route":"organizations","primaryDataset":"test-dataset","mutationMode":"mutable","fields":[
            {"id":"name","type":"string","maximumLength":80,"classification":"internal"}]})),
        ("membership".to_owned(), json!({"route":"memberships","primaryDataset":"test-dataset","mutationMode":"mutable","fields":[
            {"id":"organization","type":"reference","target":"organization","classification":"internal"},
            {"id":"other-organization","type":"reference","target":"organization","classification":"internal"},
            {"id":"principal","type":"string","maximumLength":80,"classification":"restricted"},
            {"id":"other-principal","type":"string","maximumLength":80,"classification":"restricted"},
            {"id":"active","type":"boolean","classification":"internal"},
            {"id":"other-active","type":"boolean","classification":"internal"}]}))
    ]);
    source["accessProfiles"]["evidence-source"]["permissions"]["records"][0]
        ["membershipBoundaries"] = json!([{
        "field":"organization","membershipRecordType":"membership","membershipKeyField":"organization",
        "principalField":"principal","activeField":"active"
    }]);
    source
}

#[test]
fn membership_behavior_reaches_helper_semantics_source_fields_and_select_authority() {
    let original = membership_project();
    let registry = compiled(&original, SQL);
    let before = export_evidence_source(&registry, &options()).unwrap();
    for (name, value) in [
        ("principalField", "other-principal"),
        ("activeField", "other-active"),
        ("membershipKeyField", "other-organization"),
    ] {
        let mut changed = original.clone();
        changed["accessProfiles"]["evidence-source"]["permissions"]["records"][0]
            ["membershipBoundaries"][0][name] = json!(value);
        let after_registry = compiled(&changed, SQL);
        assert_eq!(
            select_policies(&registry, &registry.entities()["record"], "evidence-source"),
            select_policies(
                &after_registry,
                &after_registry.entities()["record"],
                "evidence-source"
            ),
            "the root policy calls the same stable membership helper"
        );
        assert_ne!(
            before.behavior_revision,
            export_evidence_source(&after_registry, &options())
                .unwrap()
                .behavior_revision,
            "changing {name} must change consumed membership behavior"
        );
    }
    let mut changed_field = original.clone();
    changed_field["recordTypes"]["membership"]["fields"][2]["maximumLength"] = json!(64);
    assert_ne!(
        before.behavior_revision,
        export_evidence_source(&compiled(&changed_field, SQL), &options())
            .unwrap()
            .behavior_revision,
        "the principal field contract is consumed even when helper SQL stays the same"
    );
    let mut changed_policy = original.clone();
    changed_policy["accessProfiles"]["evidence-source"]["permissions"]["records"].as_array_mut().unwrap().push(json!({
        "recordType":"membership","operations":["get"],"readableFields":["active"],"rowBoundaries":"unrestricted"
    }));
    assert_ne!(
        before.behavior_revision,
        export_evidence_source(&compiled(&changed_policy, SQL), &options())
            .unwrap()
            .behavior_revision,
        "effective SELECT rules on the membership source are consumed"
    );
    let mut unrelated = original.clone();
    unrelated["recordTypes"]["membership"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"private-note","type":"string","maximumLength":80,"classification":"restricted"
        }));
    assert_eq!(
        before.behavior_revision,
        export_evidence_source(&compiled(&unrelated, SQL), &options())
            .unwrap()
            .behavior_revision,
        "unrelated membership source fields do not change a stored-field lookup"
    );
    for artifact in &before.artifacts {
        let text = std::str::from_utf8(&artifact.bytes).unwrap();
        assert!(!text.contains("membershipBoundaries") && !text.contains("other-principal"));
    }
}

#[test]
fn reached_derived_source_consumes_its_membership_helper() {
    let mut original = membership_project();
    let reader = &original["accessProfiles"]["evidence-source"]["permissions"]["records"][0];
    let (boundary, row_boundaries) = (
        reader["membershipBoundaries"].clone(),
        reader["rowBoundaries"].clone(),
    );
    original["recordTypes"].as_object_mut().unwrap().insert("flag".to_owned(), json!({"route":"flags","primaryDataset":"test-dataset","mutationMode":"mutable","fields":[
            {"id":"code","type":"string","maximumLength":32,"classification":"internal"},
            {"id":"organization","type":"reference","target":"organization","classification":"internal"},
            {"id":"other-organization","type":"reference","target":"organization","classification":"internal"},
            {"id":"tenant","type":"string","maximumLength":16,"classification":"internal"},
            {"id":"enabled","type":"boolean","classification":"internal"}]
    }));
    original["accessProfiles"]["evidence-source"]["permissions"]["records"].as_array_mut().unwrap().push(json!({
        "recordType":"flag","operations":["get"],"readableFields":["code","enabled"],"rowBoundaries":row_boundaries,
        "membershipBoundaries":boundary
    }));
    let sql = "SELECT r.id AS id, f.enabled AS active FROM registry_source.record r JOIN registry_source.flag f ON f.code = r.code";
    let mut selection = options();
    selection.fields = vec!["active".into()];
    let before = export_evidence_source(&compiled(&original, sql), &selection).unwrap();
    original["accessProfiles"]["evidence-source"]["permissions"]["records"][1]
        ["membershipBoundaries"][0]["field"] = json!("other-organization");
    assert_ne!(
        before.behavior_revision,
        export_evidence_source(&compiled(&original, sql), &selection)
            .unwrap()
            .behavior_revision,
        "membership semantics on a reached source affect the derived answer"
    );
}

#[test]
fn refuses_ungiven_authority_and_incompatible_selector_semantics() {
    let mut hidden = project();
    hidden["accessProfiles"]["evidence-source"]["permissions"]["records"][0]["readableFields"] =
        json!(["status", "active"]);
    assert!(export_evidence_source(&compiled(&hidden, SQL), &options()).is_err());
    let mut claims = project();
    claims["accessProfiles"]["evidence-source"]["permissions"]["records"][0]["lookups"][0] =
        json!({"selector":"by-code","valueOrigin":"verified-claim","claimMapping":{"code":"code"}});
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
fn refuses_a_string_selector_field_that_accepts_the_empty_value() {
    assert!(selector_schema(&FieldTypeSource::String {
        min_length: 0,
        max_length: 32
    })
    .is_err());
    let mut empty_allowed = project();
    // Omitting `minimumLength` defaults it to 0, so `code` accepts the empty value.
    empty_allowed["recordTypes"]["record"]["fields"][0] = json!({"id":"code","type":"string","maximumLength":32,"required":true,"classification":"internal"});
    let diagnostic = refused(&compiled(&empty_allowed, SQL), &options());
    assert_eq!(diagnostic.code, "breg.evidence-source.refused");
    assert!(diagnostic.message.contains("minimumLength"));
    // `alternatives_keep_one_route_and_selected_identity_with_stable_inventories`
    // exports the same fixture with `code` declared at `minimumLength: 1`, so an
    // exact selector field that excludes the empty value still exports.
}

#[test]
fn reached_source_select_authority_is_required_for_consumed_behavior() {
    let mut original = project();
    original["recordTypes"].as_object_mut().unwrap().insert(
        "flag".to_owned(),
        json!({"primaryDataset":"test-dataset","route":"flags","mutationMode":"mutable","fields":[
        {"id":"code","type":"string","maximumLength":32,"classification":"internal"},
        {"id":"tenant","type":"string","maximumLength":16,"classification":"internal"},
        {"id":"enabled","type":"boolean","classification":"internal"}]}),
    );
    let row_boundaries = original["accessProfiles"]["evidence-source"]["permissions"]["records"][0]
        ["rowBoundaries"]
        .clone();
    original["accessProfiles"]["evidence-source"]["permissions"]["records"].as_array_mut().unwrap().push(json!({"recordType":"flag","operations":["get"],"readableFields":["code","enabled"],"rowBoundaries":row_boundaries}));
    let sql = "SELECT r.id AS id, f.enabled AS active FROM registry_source.record r JOIN registry_source.flag f ON f.code = r.code";
    let mut selection = options();
    selection.fields = vec!["active".into()];
    export_evidence_source(&compiled(&original, sql), &selection).unwrap();
    original["accessProfiles"]["evidence-source"]["permissions"]["records"][1] = json!({"recordType":"flag","operations":["create"],"writableFields":["code","enabled"],"rowBoundaries":row_boundaries});
    let failure = compile(&original, sql)
        .expect_err("same source schema and boundaries cannot mask loss of SELECT RLS authority");
    assert!(
        failure.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "breg.disclosure.derived-reads-unreadable-source"
                && diagnostic.path
                    == "recordTypes[id=flag].accessProfiles[id=evidence-source].operations"
        }),
        "{:?}",
        failure.diagnostics()
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
    original["recordTypes"]["record"]["fields"][2] = json!({"id":"status","type":"vocabulary-code","vocabulary":"status","values":["active","retired"],"classification":"internal"});
    let export = export_evidence_source(&compiled(&original, SQL), &options()).unwrap();
    let response = yaml(
        &export,
        "adapter-packs/registry-status/schemas/response.json",
    );
    let status =
        &response["properties"]["data"]["properties"]["domainData"]["properties"]["status"];
    assert_eq!(status["type"], json!(["string", "null"]));
    assert!(
        status.get("enum").is_none(),
        "fact enum must not prevent nullable source data reaching extraction"
    );
    assert_eq!(
        yaml(&export, "adapter-packs/registry-status/schemas/facts.json")["properties"]["status"]
            ["enum"],
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
            original["recordTypes"]["record"]["fields"]
                .as_array_mut()
                .unwrap()
                .push(
                    json!({"id":id,"type":"string","maximumLength":1,"classification":"internal"}),
                );
            original["accessProfiles"]["evidence-source"]["permissions"]["records"][0]
                ["readableFields"]
                .as_array_mut()
                .unwrap()
                .push(json!(id));
            fields.push(id);
        }
        original["recordTypes"]["record"]["selectorProfiles"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":selector,"fields":fields}));
        original["accessProfiles"]["evidence-source"]["permissions"]["records"][0]["lookups"]
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
    let source = yaml(&export, "sources/registry-status.yaml");
    let extract = std::str::from_utf8(file(
        &export,
        "adapter-packs/registry-status/scripts/lookup.rhai",
    ))
    .unwrap();
    let input_for = |field: &str| {
        source["inputs"]
            .as_object()
            .unwrap()
            .iter()
            .find_map(|(input, binding)| {
                (binding["selector"]["field"] == field).then_some(input.as_str())
            })
            .unwrap()
    };
    // The Evidence adapter, not BReg, rejects a substituted record. The exporter is
    // the only place this check is written, so pin the emitted comparison verbatim.
    for (field, api_name) in [
        ("code", "code"),
        ("registration-number", "registrationNumber"),
    ] {
        let input = input_for(field);
        let check = format!(
            "if record[{api_name:?}] == () || type_of(record[{api_name:?}]) != type_of(inputs[{input:?}]) || record[{api_name:?}] != inputs[{input:?}] {{ throw \"source_protocol_error\"; }}"
        );
        assert!(extract.contains(&check), "missing identity check: {check}");
    }
}

#[test]
fn refuses_a_profile_that_does_not_grant_lookup() {
    let mut original = project();
    original["accessProfiles"]["evidence-source"]["permissions"]["records"][0]["operations"] =
        json!(["get"]);
    original["accessProfiles"]["evidence-source"]["permissions"]["records"][0]["lookups"] =
        json!([]);
    let diagnostic = refused(&compiled(&original, SQL), &options());
    assert_eq!(diagnostic.code, "breg.evidence-source.refused");
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
    assert_eq!(diagnostic.code, "breg.evidence-source.refused");
    assert_eq!(
        diagnostic.message,
        "the compiled profile has no lookup route"
    );
}

#[test]
fn long_eligible_selector_names_export_as_stable_distinct_bounded_profiles() {
    let short = export_evidence_source(&compiled(&project(), SQL), &options()).unwrap();
    assert_eq!(
        short.selector_profiles["by-code"],
        "breg-8-registry-6-record-7-by-code"
    );
    let mut original = project();
    let entity = format!("record-{}", "e".repeat(57));
    let first = format!("by-{}a", "s".repeat(60));
    let second = format!("by-{}b", "s".repeat(60));
    original["recordTypes"]["record"]
        .as_object_mut()
        .unwrap()
        .remove("derived");
    original["accessProfiles"]["evidence-source"]["permissions"]["records"][0]["recordType"] =
        json!(entity);
    original["accessProfiles"]["evidence-source"]["permissions"]["records"][0]["readableFields"] =
        json!(["code", "status"]);
    original["recordTypes"]["record"]["selectorProfiles"] = json!([
        {"id":first,"fields":["code"]},{"id":second,"fields":["code"]}]);
    let renamed = original["recordTypes"]
        .as_object_mut()
        .unwrap()
        .remove("record")
        .unwrap();
    original["recordTypes"][&entity] = renamed;
    original["accessProfiles"]["evidence-source"]["permissions"]["records"][0]["lookups"] = json!([
        {"selector":first,"valueOrigin":"request"},{"selector":second,"valueOrigin":"request"}]);
    let source = parse_project_json(&serde_json::to_vec(&original).unwrap()).unwrap();
    let registry =
        crate::compiler::compile_project(&source, &[], CompileProfile::Authoring).unwrap();
    let mut selection = options();
    selection.entity = entity;
    selection.connection = "c".repeat(64);
    selection.selectors = vec![first.clone(), second.clone()];
    let export = export_evidence_source(&registry, &selection).unwrap();
    assert_eq!(
        export.artifacts,
        export_evidence_source(&registry, &selection)
            .unwrap()
            .artifacts
    );
    assert_ne!(
        export.selector_profiles[&first],
        export.selector_profiles[&second]
    );
    let source = yaml(&export, "sources/registry-status.yaml");
    let inputs = source["inputs"].as_object().unwrap();
    assert_eq!(inputs.len(), 2);
    for (input, binding) in inputs {
        assert!(
            input.starts_with("input-"),
            "{input} is over 64 bytes readable"
        );
        assert_eq!(binding["selector"]["field"], json!("code"));
    }
    for profile in export.selector_profiles.values() {
        assert_eq!(profile.len(), 64);
        assert!(local_name(profile));
        assert!(export
            .artifacts
            .iter()
            .any(|artifact| artifact.path == format!("selectors/{profile}.yaml")));
    }
    selection.connection.replace_range(63.., "d");
    let other = export_evidence_source(&registry, &selection).unwrap();
    assert_ne!(
        export.selector_profiles[&first],
        other.selector_profiles[&first]
    );
}

#[test]
fn refuses_a_composite_selector_beyond_the_aggregate_selector_bound() {
    let mut original = project();
    let mut fields = Vec::new();
    for index in 0..3 {
        let id = format!("part-{index}");
        original["recordTypes"]["record"]["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":id,"type":"string","minimumLength":1,"maximumLength":1000,"classification":"internal"}));
        original["accessProfiles"]["evidence-source"]["permissions"]["records"][0]
            ["readableFields"]
            .as_array_mut()
            .unwrap()
            .push(json!(id));
        fields.push(id);
    }
    original["recordTypes"]["record"]["selectorProfiles"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"by-parts","fields":fields}));
    original["accessProfiles"]["evidence-source"]["permissions"]["records"][0]["lookups"]
        .as_array_mut()
        .unwrap()
        .push(json!({"selector":"by-parts","valueOrigin":"request"}));
    let mut selection = options();
    selection.selectors = vec!["by-parts".into()];
    // Each field stays inside the per-selector bound; only their union crosses it.
    let diagnostic = refused(&compiled(&original, SQL), &selection);
    assert_eq!(diagnostic.code, "breg.evidence-source.refused");
    assert_eq!(
        diagnostic.message,
        "the complete composite selector exceeds Evidence's 8192-byte bound"
    );
}

#[test]
fn uuid_selectors_and_facts_preserve_the_uuid_format() {
    let (selector, maximum) = selector_schema(&FieldTypeSource::Uuid).unwrap();
    assert_eq!(selector["type"], "uuid");
    assert_eq!(maximum, 36);
    assert_eq!(
        scalar_schema(&FieldTypeSource::Uuid).unwrap()["format"],
        "uuid"
    );
}

#[test]
fn vocabulary_selector_requires_a_codelist_instead_of_length_only_validation() {
    let kind = FieldTypeSource::VocabularyCode {
        vocabulary: "status".into(),
        values: vec!["active".into(), "retired".into()],
    };
    assert!(
        selector_schema(&kind).is_err(),
        "a vocabulary selector needs its codelist artifact or a refusal"
    );
}

#[test]
fn reference_selectors_and_facts_preserve_the_uuid_format() {
    let kind = FieldTypeSource::Reference {
        target: "record".into(),
        on_delete: Default::default(),
    };
    assert_eq!(selector_schema(&kind).unwrap().0["type"], "uuid");
    assert_eq!(scalar_schema(&kind).unwrap()["format"], "uuid");
}

fn fact_rule_project() -> Value {
    let mut project = project();
    project["recordTypes"]["record"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"area","type":"string","minimumLength":1,"maximumLength":16,"classification":"internal"}));
    project["accessProfiles"]["evidence-source"]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("area"));
    project
}

fn fact_rule_options() -> EvidenceSourceOptions {
    let mut options = options();
    options.fields = vec!["status".into(), "area".into()];
    options.required_values = BTreeMap::from([("status".to_owned(), vec!["active".to_owned()])]);
    options.optional_fields = vec!["area".into()];
    options
}

/// Runs the generated `lookup` entrypoint over a returned record.
fn run_lookup(export: &EvidenceSourceExport, record: Value) -> Value {
    try_lookup(export, record).unwrap()
}

/// As `run_lookup`, with a script error returned as its text.
fn try_lookup(export: &EvidenceSourceExport, record: Value) -> Result<Value, String> {
    let script = std::str::from_utf8(file(
        export,
        "adapter-packs/registry-status/scripts/lookup.rhai",
    ))
    .unwrap();
    let engine = rhai::Engine::new();
    let ast = engine.compile(script).unwrap();
    let exchange = json!({
        "properties": {"bregEvidenceInputs": {"by-code--code": "A1"}},
        "body": {"data": {"domainData": record}}
    });
    let exchange = rhai::serde::to_dynamic(&exchange).unwrap();
    let outcome: rhai::Dynamic = engine
        .call_fn(&mut rhai::Scope::new(), &ast, "lookup", (exchange,))
        .map_err(|error| error.to_string())?;
    Ok(rhai::serde::from_dynamic(&outcome).unwrap())
}

fn fact_rule_export() -> EvidenceSourceExport {
    let mut options = fact_rule_options();
    options.selectors = vec!["by-code".into()];
    export_evidence_source(&compiled(&fact_rule_project(), SQL), &options).unwrap()
}

#[test]
fn a_record_with_an_allowed_value_matches() {
    let outcome = run_lookup(
        &fact_rule_export(),
        json!({"code":"A1","status":"active","area":"N1"}),
    );
    assert_eq!(
        outcome,
        json!({"lookup":"matched","facts":{"status":"active","area":"N1"}})
    );
}

#[test]
fn a_record_outside_the_allowed_values_answers_no_match_not_unresolved() {
    let export = fact_rule_export();
    let inactive = run_lookup(
        &export,
        json!({"code":"A1","status":"suspended","area":"N1"}),
    );
    let missing_fact = run_lookup(&export, json!({"code":"A1","status":null,"area":"N1"}));
    assert_eq!(inactive, json!({"lookup":"no-match"}));
    assert_eq!(inactive, missing_fact);
    // An unknown record is BReg's 404, which the route stops on as an
    // unresolved lookup before `lookup` runs. A refused record is a 200 that
    // reaches `lookup` and answers no match, so Evidence reports the two
    // differently and a caller can tell that the refused record exists.
    let script = std::str::from_utf8(file(
        &export,
        "adapter-packs/registry-status/scripts/lookup.rhai",
    ))
    .unwrap();
    let engine = rhai::Engine::new();
    let ast = engine.compile(script).unwrap();
    let unresolved = |status: u16| -> bool {
        let exchange =
            rhai::serde::to_dynamic(json!({"headers": {"camelhttpresponsecode": status}})).unwrap();
        engine
            .call_fn(&mut rhai::Scope::new(), &ast, "is_unresolved", (exchange,))
            .unwrap()
    };
    assert!(unresolved(404));
    assert!(!unresolved(200));
    assert!(script.find("source_protocol_error").unwrap() < script.find("\"active\"").unwrap());
    assert!(script.find("\"active\"").unwrap() < script.find("let facts").unwrap());
}

#[test]
fn several_allowed_values_each_match() {
    let mut options = fact_rule_options();
    options.selectors = vec!["by-code".into()];
    options.required_values =
        BTreeMap::from([("status".to_owned(), vec!["active".into(), "pending".into()])]);
    let export = export_evidence_source(&compiled(&fact_rule_project(), SQL), &options).unwrap();
    for status in ["active", "pending"] {
        let outcome = run_lookup(&export, json!({"code":"A1","status":status,"area":null}));
        assert_eq!(outcome["lookup"], "matched", "{status}");
    }
    let outcome = run_lookup(&export, json!({"code":"A1","status":"closed","area":null}));
    assert_eq!(outcome, json!({"lookup":"no-match"}));
}

#[test]
fn an_optional_fact_that_is_null_still_matches_and_is_omitted() {
    let outcome = run_lookup(
        &fact_rule_export(),
        json!({"code":"A1","status":"active","area":null}),
    );
    assert_eq!(
        outcome,
        json!({"lookup":"matched","facts":{"status":"active"}})
    );
}

#[test]
fn an_optional_fact_whose_key_is_absent_is_a_protocol_error() {
    let export = fact_rule_export();
    let error = try_lookup(&export, json!({"code":"A1","status":"active"})).unwrap_err();
    assert!(error.contains("source_protocol_error"), "{error}");
    let script = std::str::from_utf8(file(
        &export,
        "adapter-packs/registry-status/scripts/lookup.rhai",
    ))
    .unwrap();
    let contains = script.find("!record.contains(\"area\")").unwrap();
    assert!(script.find("source_protocol_error").unwrap() < contains);
    assert!(contains < script.find("let facts").unwrap());
}

#[test]
fn a_required_fact_that_is_missing_is_still_no_match() {
    let mut options = fact_rule_options();
    options.selectors = vec!["by-code".into()];
    options.required_values.clear();
    options.optional_fields = Vec::new();
    let export = export_evidence_source(&compiled(&fact_rule_project(), SQL), &options).unwrap();
    let outcome = run_lookup(&export, json!({"code":"A1","status":"active"}));
    assert_eq!(outcome, json!({"lookup":"no-match"}));
}

#[test]
fn the_fact_schema_leaves_an_optional_fact_out_of_required() {
    let export = fact_rule_export();
    let facts = yaml(&export, "adapter-packs/registry-status/schemas/facts.json");
    assert_eq!(facts["required"], json!(["status"]));
    assert!(facts["properties"].get("area").is_some());
}

#[test]
fn fact_rules_are_bound_into_the_behavior_revision() {
    let registry = compiled(&fact_rule_project(), SQL);
    let plain = {
        let mut options = fact_rule_options();
        options.required_values.clear();
        options.optional_fields.clear();
        export_evidence_source(&registry, &options).unwrap()
    };
    let guarded = export_evidence_source(&registry, &fact_rule_options()).unwrap();
    let mut other_value = fact_rule_options();
    other_value.required_values =
        BTreeMap::from([("status".to_owned(), vec!["pending".to_owned()])]);
    let other = export_evidence_source(&registry, &other_value).unwrap();
    assert_ne!(plain.behavior_revision, guarded.behavior_revision);
    assert_ne!(guarded.behavior_revision, other.behavior_revision);
}

#[test]
fn refuses_invalid_fact_rules() {
    let registry = compiled(&fact_rule_project(), SQL);
    let require = |field: &str, values: &[&str]| {
        let mut options = fact_rule_options();
        options.optional_fields.clear();
        options.fields = vec!["status".into(), "area".into(), "active".into()];
        options.required_values = BTreeMap::from([(
            field.to_owned(),
            values.iter().map(|value| (*value).to_owned()).collect(),
        )]);
        refused(&registry, &options)
    };
    // A field the generated source does not export as a fact.
    for field in ["code", "unknown"] {
        let refusal = require(field, &["x"]);
        assert_eq!(refusal.code, "breg.evidence-source.refused");
        assert_eq!(refusal.path, "required-values");
    }
    // A value of the wrong type for the field.
    let refusal = require("active", &["yes"]);
    assert_eq!(refusal.path, "required-values");
    assert!(refusal.message.contains("boolean"), "{}", refusal.message);
    let refusal = require("status", &["a-value-longer-than-the-field-allows"]);
    assert_eq!(refusal.path, "required-values");
    // An empty value list.
    let refusal = require("status", &[]);
    assert_eq!(refusal.path, "required-values");
    assert!(refusal.message.contains("at least one"));
    // Both required and optional.
    let mut both = fact_rule_options();
    both.optional_fields = vec!["status".into()];
    let refusal = refused(&registry, &both);
    assert_eq!(refusal.path, "optional-fields");
    assert!(refusal.message.contains("both"));
    // An optional field that is not an exported fact.
    let mut unexported = fact_rule_options();
    unexported.optional_fields = vec!["code".into()];
    assert_eq!(refused(&registry, &unexported).path, "optional-fields");
}

#[test]
fn a_required_value_with_a_control_character_is_refused() {
    // serde_json spells U+0008 and U+000C as `\b` and `\f`, escapes the Rhai
    // parser refuses, and a value read back never needs a control character.
    for kind in [
        FieldTypeSource::String {
            min_length: 0,
            max_length: 16,
        },
        FieldTypeSource::Text { max_length: 16 },
    ] {
        for value in ["a\u{8}b", "a\u{c}b", "a\nb", "a\tb", "a\u{7f}b", "a\u{85}b"] {
            let reason = required_value_literal(&kind, value).unwrap_err();
            assert!(reason.contains("control character"), "{value:?}: {reason}");
        }
    }
}

#[test]
fn a_required_text_value_with_quotes_and_backslashes_still_matches() {
    let mut options = fact_rule_options();
    options.required_values =
        BTreeMap::from([("status".to_owned(), vec![r#"a"b\c'd"#.to_owned()])]);
    let export = export_evidence_source(&compiled(&fact_rule_project(), SQL), &options).unwrap();
    let outcome = run_lookup(
        &export,
        json!({"code":"A1","status":r#"a"b\c'd"#,"area":null}),
    );
    assert_eq!(outcome["lookup"], "matched");
    let outcome = run_lookup(&export, json!({"code":"A1","status":"abcd","area":null}));
    assert_eq!(outcome, json!({"lookup":"no-match"}));
}

#[test]
fn a_required_uuid_or_reference_value_must_be_canonical_lowercase() {
    let reference = FieldTypeSource::Reference {
        target: "organization".into(),
        on_delete: Default::default(),
    };
    for kind in [FieldTypeSource::Uuid, reference] {
        let canonical = "0b6a2f9e-3c4d-4e5f-8a9b-0c1d2e3f4a5b";
        assert_eq!(
            required_value_literal(&kind, canonical).unwrap(),
            json!(canonical).to_string()
        );
        for value in [
            "0B6A2F9E-3C4D-4E5F-8A9B-0C1D2E3F4A5B",
            "0b6a2f9e-3c4d-4e5f-8a9b-0c1d2e3f4A5b",
            "0b6a2f9e3c4d-4e5f-8a9b-0c1d2e3f4a5b-",
            "------------------------------------",
            "0b6a2f9e3c4d4e5f8a9b0c1d2e3f4a5b",
            "{0b6a2f9e-3c4d-4e5f-8a9b-0c1d2e3f4a5b}",
        ] {
            let reason = required_value_literal(&kind, value).unwrap_err();
            assert!(reason.contains("lowercase"), "{value}: {reason}");
        }
    }
}

#[test]
fn a_required_date_value_must_be_a_real_calendar_date() {
    for value in ["2024-02-29", "2026-12-31", "0001-01-01"] {
        assert_eq!(
            required_value_literal(&FieldTypeSource::Date, value).unwrap(),
            json!(value).to_string()
        );
    }
    for value in [
        "2026-02-29",
        "2026-13-01",
        "2026-00-10",
        "2026-04-31",
        "2026-01-00",
        "2026-1-01",
        "26-01-01",
    ] {
        let reason = required_value_literal(&FieldTypeSource::Date, value).unwrap_err();
        assert!(reason.contains("calendar date"), "{value}: {reason}");
    }
}

fn counted_project() -> Value {
    let mut project = fact_rule_project();
    project["recordTypes"]["record"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"visits","type":"int64","classification":"internal"}));
    project["accessProfiles"]["evidence-source"]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("visits"));
    project
}

#[test]
fn the_behavior_revision_binds_the_value_the_lookup_compares_not_its_spelling() {
    let registry = compiled(&counted_project(), SQL);
    let export = |values: &[&str]| {
        let mut options = fact_rule_options();
        options.fields = vec!["status".into(), "area".into(), "visits".into()];
        options.required_values = BTreeMap::from([(
            "visits".to_owned(),
            values.iter().map(|value| (*value).to_owned()).collect(),
        )]);
        export_evidence_source(&registry, &options).unwrap()
    };
    let plain = export(&["7"]);
    for spelling in [&["007"][..], &["+7"], &["7", "007"]] {
        let other = export(spelling);
        assert_eq!(
            other.behavior_revision, plain.behavior_revision,
            "{spelling:?}"
        );
        assert_eq!(other.artifacts, plain.artifacts, "{spelling:?}");
    }
    assert_ne!(export(&["8"]).behavior_revision, plain.behavior_revision);
}

#[test]
fn refuses_an_export_whose_schema_evidence_would_not_read() {
    // The fact schema lists every vocabulary code. Sixteen facts, each a
    // 256-code vocabulary of long codes, pass every per-field bound and still
    // exceed the 256 KiB Evidence reads a schema within.
    let codes = (0..256)
        .map(|index| format!("{index:0>120}"))
        .collect::<Vec<_>>();
    let mut project = project();
    let mut ids = Vec::new();
    for index in 0..16 {
        let id = format!("kind-{index}");
        project["recordTypes"]["record"]["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":id,"type":"vocabulary-code","vocabulary":id,"values":codes,"classification":"internal"}));
        project["accessProfiles"]["evidence-source"]["permissions"]["records"][0]["readableFields"]
            .as_array_mut()
            .unwrap()
            .push(json!(id));
        ids.push(id);
    }
    let registry = compiled(&project, SQL);
    let mut options = options();
    options.fields = ids.clone();
    let refusal = refused(&registry, &options);
    assert_eq!(refusal.code, "breg.evidence-source.refused");
    assert_eq!(refusal.path, "fields");
    assert!(
        refusal.message.contains("262144 bytes"),
        "{}",
        refusal.message
    );
    // Under the bound the same fields export.
    options.fields = ids[..4].to_vec();
    export_evidence_source(&registry, &options).unwrap();
}

/// `fact_rule_project` with a `note` text field long enough for the values
/// `require_notes` asks for.
fn long_note_project() -> Value {
    let mut project = fact_rule_project();
    project["recordTypes"]["record"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"note","type":"text","maximumLength":30000,"classification":"internal"}));
    project["accessProfiles"]["evidence-source"]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("note"));
    project
}

/// Options that require `note` to hold one of distinct values of `lengths`
/// characters.
fn require_notes(lengths: &[usize]) -> EvidenceSourceOptions {
    let mut options = fact_rule_options();
    options.fields = vec!["status".into(), "note".into()];
    options.optional_fields = Vec::new();
    options.required_values = BTreeMap::from([(
        "note".to_owned(),
        lengths
            .iter()
            .zip('a'..)
            .map(|(length, letter)| letter.to_string().repeat(*length))
            .collect(),
    )]);
    options
}

#[test]
fn refuses_an_export_whose_lookup_script_evidence_would_not_read() {
    // The lookup script spells out every allowed value. Three 22,000-character
    // values each fit the field and together exceed the 65,536 bytes Evidence
    // reads a script within.
    let registry = compiled(&long_note_project(), SQL);
    let refusal = refused(&registry, &require_notes(&[22_000, 22_000, 22_000]));
    assert_eq!(refusal.code, "breg.evidence-source.refused");
    assert_eq!(refusal.path, "required-values");
    assert!(
        refusal.message.contains("65536 bytes"),
        "{}",
        refusal.message
    );
    // A script of exactly the bound exports, and one a byte longer does not.
    let script = |export: &EvidenceSourceExport| {
        file(export, "adapter-packs/registry-status/scripts/lookup.rhai").len()
    };
    let shortest = script(&export_evidence_source(&registry, &require_notes(&[1, 1, 1])).unwrap());
    let spare = 65_536 - shortest;
    let mut lengths = [1 + spare / 3, 1 + spare / 3, 1 + spare - 2 * (spare / 3)];
    let at_bound = export_evidence_source(&registry, &require_notes(&lengths)).unwrap();
    assert_eq!(script(&at_bound), 65_536);
    lengths[2] += 1;
    let refusal = refused(&registry, &require_notes(&lengths));
    assert_eq!(refusal.path, "required-values");
    assert!(
        refusal.message.contains("65537 bytes"),
        "{}",
        refusal.message
    );
}

#[cfg(feature = "runtime")]
#[test]
fn the_lookup_script_bound_is_the_one_evidence_loads_pack_scripts_within() {
    assert_eq!(
        EVIDENCE_MAXIMUM_SCRIPT_BYTES,
        registry_adapter_engine::scripts::SCRIPT_PROFILE.maximum_source_bytes
    );
}

#[test]
fn a_boolean_field_accepts_a_boolean_value() {
    let mut options = fact_rule_options();
    options.selectors = vec!["by-code".into()];
    options.fields = vec!["active".into(), "area".into()];
    options.required_values = BTreeMap::from([("active".to_owned(), vec!["true".to_owned()])]);
    let export = export_evidence_source(&compiled(&fact_rule_project(), SQL), &options).unwrap();
    let script = std::str::from_utf8(file(
        &export,
        "adapter-packs/registry-status/scripts/lookup.rhai",
    ))
    .unwrap();
    assert!(script.contains("record[\"active\"] == true"), "{script}");
}

fn pattern_project(pattern: &str) -> Value {
    let mut project = project();
    project["recordTypes"]["record"]["fields"]
        .as_array_mut()
        .unwrap()
        .extend([
            json!({"id":"area","type":"string","minimumLength":2,"maximumLength":20,"pattern":pattern,"classification":"internal"}),
            json!({"id":"amount","type":"decimal","precision":6,"scale":2,"classification":"internal"}),
        ]);
    project["accessProfiles"]["evidence-source"]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .unwrap()
        .extend([json!("area"), json!("amount")]);
    project
}

fn pattern_options() -> EvidenceSourceOptions {
    let mut options = options();
    options.fields = vec!["area".into(), "amount".into()];
    options.selectors = vec!["by-code".into()];
    options
}

const AREA_PATTERN: &str = "^[A-Z0-9]{2,20}$";

#[test]
fn a_declared_field_pattern_reaches_the_fact_and_response_schemas() {
    let export = export_evidence_source(
        &compiled(&pattern_project(AREA_PATTERN), SQL),
        &pattern_options(),
    )
    .unwrap();
    let facts = yaml(&export, "adapter-packs/registry-status/schemas/facts.json");
    let response = yaml(
        &export,
        "adapter-packs/registry-status/schemas/response.json",
    );
    assert_eq!(facts["properties"]["area"]["pattern"], AREA_PATTERN);
    assert_eq!(facts["properties"]["area"]["minLength"], 2);
    assert_eq!(facts["properties"]["area"]["maxLength"], 20);
    assert_eq!(
        response["properties"]["data"]["properties"]["domainData"]["properties"]["area"]["pattern"],
        AREA_PATTERN
    );
}

#[test]
fn a_decimal_fact_states_the_declared_precision_and_scale() {
    let export = export_evidence_source(
        &compiled(&pattern_project(AREA_PATTERN), SQL),
        &pattern_options(),
    )
    .unwrap();
    let facts = yaml(&export, "adapter-packs/registry-status/schemas/facts.json");
    assert_eq!(
        facts["properties"]["amount"]["pattern"],
        "^-?(0|[1-9][0-9]{0,3})\\.[0-9]{2}$"
    );
}

#[test]
fn the_field_pattern_is_bound_into_the_behavior_revision() {
    let revision = |pattern: &str| {
        export_evidence_source(
            &compiled(&pattern_project(pattern), SQL),
            &pattern_options(),
        )
        .unwrap()
        .behavior_revision
    };
    assert_ne!(revision(AREA_PATTERN), revision("^[A-Z]{2,20}$"));
}

#[test]
fn every_fact_pattern_is_bound_into_the_behavior_revision() {
    // A pack version identifies one set of schema bytes, so the behavior
    // material carries each fact's pattern, whether declared or derived.
    let registry = compiled(&pattern_project(AREA_PATTERN), SQL);
    for fields in [["area"], ["amount"], ["status"]] {
        let mut options = pattern_options();
        options.fields = fields.iter().map(|id| id.to_string()).collect();
        let (export, behavior) = export_with_behavior(&registry, &options).unwrap();
        assert_eq!(
            export.behavior_revision,
            format!("sha256:{}", digest(&canonical(&behavior).unwrap()))
        );
        let facts = yaml(&export, "adapter-packs/registry-status/schemas/facts.json");
        let facts = facts["properties"].as_object().unwrap();
        assert_eq!(facts.len(), 1, "{fields:?}");
        for (id, fact) in facts {
            assert_eq!(
                behavior["fields"][id].get("pattern"),
                fact.get("pattern"),
                "fact `{id}`"
            );
        }
    }
}

#[test]
fn a_decimal_precision_or_scale_change_is_a_new_pack_version() {
    let revision = |precision: u8, scale: u8| {
        let mut project = pattern_project(AREA_PATTERN);
        let amount = project["recordTypes"]["record"]["fields"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|field| field["id"] == "amount")
            .unwrap();
        amount["precision"] = json!(precision);
        amount["scale"] = json!(scale);
        export_evidence_source(&compiled(&project, SQL), &pattern_options())
            .unwrap()
            .behavior_revision
    };
    assert_ne!(revision(6, 2), revision(7, 2));
    assert_ne!(revision(6, 2), revision(6, 3));
}

#[test]
fn a_selector_field_pattern_stays_out_of_the_pack() {
    // Only a fact carries its field's pattern. A selector-only field is the
    // caller's input, which the returned identity must equal exactly, so its
    // pattern changes no file and no pack version, and is never refused.
    let export = |pattern: Option<&str>| {
        let mut project = pattern_project(AREA_PATTERN);
        if let Some(pattern) = pattern {
            project["recordTypes"]["record"]["fields"][0]["pattern"] = json!(pattern);
        }
        export_with_behavior(&compiled(&project, SQL), &pattern_options()).unwrap()
    };
    let (plain, plain_behavior) = export(None);
    for pattern in ["^[A-Z][0-9]$", "^\\w+$"] {
        let (patterned, behavior) = export(Some(pattern));
        assert_eq!(
            patterned.behavior_revision, plain.behavior_revision,
            "{pattern}"
        );
        assert_eq!(behavior, plain_behavior, "{pattern}");
        assert_eq!(patterned.artifacts.len(), plain.artifacts.len());
        for artifact in &plain.artifacts {
            let mut expected: Value = serde_json::from_slice(&artifact.bytes)
                .unwrap_or_else(|_| json!(String::from_utf8_lossy(&artifact.bytes)));
            let mut actual: Value = serde_json::from_slice(file(&patterned, &artifact.path))
                .unwrap_or_else(|_| {
                    json!(String::from_utf8_lossy(file(&patterned, &artifact.path)))
                });
            // The compiled registry digest follows every project edit.
            for document in [&mut expected, &mut actual] {
                if let Some(provenance) = document
                    .get_mut("provenance")
                    .and_then(Value::as_object_mut)
                {
                    provenance.remove("registryRevision");
                }
            }
            assert_eq!(actual, expected, "{}", artifact.path);
        }
    }
    let response = yaml(
        &plain,
        "adapter-packs/registry-status/schemas/response.json",
    );
    let returned = &response["properties"]["data"]["properties"]["domainData"]["properties"];
    assert!(returned["code"].get("pattern").is_none());
    assert_eq!(returned["area"]["pattern"], AREA_PATTERN);
}

#[test]
fn refuses_a_pattern_that_only_postgresql_reads_the_same_way() {
    for pattern in ["^[[:alpha:]]{2,20}$", "\\mAB", "(?i)^ab$", "***=^ab$"] {
        let diagnostic = refused(
            &compiled(&pattern_project(pattern), SQL),
            &pattern_options(),
        );
        assert_eq!(diagnostic.path, "fields", "{pattern}");
    }
}

#[path = "../../tests/support/evidence_source_patterns.rs"]
mod pattern_cases;

#[test]
fn the_export_accepts_exactly_the_patterns_both_engines_read_the_same_way() {
    use pattern_cases::{Verdict, CASES};
    for case in CASES {
        // Evidence compiles a pack schema with this draft and format mode
        // (registry-adapter-engine's `evidence.rs`).
        let schema = json!({"type": "string", "pattern": case.pattern});
        let consumer = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .should_validate_formats(true)
            .compile(&schema);
        let agrees = consumer.is_ok_and(|consumer| {
            case.postgres
                .iter()
                .all(|(value, matched)| consumer.is_valid(&json!(value)) == *matched)
        });
        assert_eq!(
            agrees,
            case.verdict != Verdict::Differs,
            "{}: {}",
            case.pattern,
            case.note
        );
        let export = export_evidence_source(
            &compiled(&pattern_project(case.pattern), SQL),
            &pattern_options(),
        );
        match (case.verdict, export) {
            (Verdict::Portable, Ok(export)) => {
                let facts = yaml(&export, "adapter-packs/registry-status/schemas/facts.json");
                assert_eq!(facts["properties"]["area"]["pattern"], case.pattern);
            }
            (Verdict::Portable, Err(diagnostic)) => {
                panic!("{} was refused: {}", case.pattern, diagnostic.message)
            }
            (_, Ok(_)) => panic!("{} was accepted: {}", case.pattern, case.note),
            (_, Err(diagnostic)) => assert_eq!(diagnostic.path, "fields", "{}", case.pattern),
        }
    }
}

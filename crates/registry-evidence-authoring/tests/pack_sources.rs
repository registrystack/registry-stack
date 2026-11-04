//! Source binding grammar shared by authoring tools and unsaved editor buffers.

use registry_evidence_authoring::{compile, project};
use registry_platform_yaml::LocalId;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[test]
fn a_pack_source_needs_no_second_request_or_extraction_program() {
    let binding = json!({
        "pack": {"id": "synthetic-register", "version": "0.1.0"},
        "route": "evidence-record",
        "connection": "register",
        "inputs": {
            "recordId": {
                "selector": {
                    "role": "subject",
                    "profile": "record-by-id",
                    "field": "record-id"
                }
            }
        },
        "acquisitionPosture": "record-transformed"
    });

    let source = serde_json::from_value::<project::Source>(binding.clone())
        .expect("a source selects a reviewed pack route and maps authorized inputs");
    assert_eq!(
        serde_json::to_value(source).expect("serialize the authored source binding"),
        binding
    );
}

#[test]
fn source_input_names_are_the_pack_routes_external_identifiers() {
    let input = json!({
        "selector": {
            "role": "subject",
            "profile": "record-by-id",
            "field": "record-id"
        }
    });
    let source = |name: &str| {
        json!({
            "pack": {"id": "synthetic-register", "version": "0.1.0"},
            "route": "evidence-record",
            "connection": "register",
            "inputs": {(name): input.clone()},
            "acquisitionPosture": "record-transformed"
        })
    };

    serde_json::from_value::<project::Source>(source("recordId"))
        .expect("a pack-defined camelCase input name is preserved");
    assert!(serde_json::from_value::<project::Source>(source(&"x".repeat(513))).is_err());
}

fn project() -> project::EvidenceProject {
    serde_json::from_value(json!({
        "id":"family-evidence",
        "selectorProfiles":{"person-by-id":{"maximumAggregateBytes":64,"fields":{"person-id":{"type":"string","minimumBytes":1,"maximumBytes":64}}}},
        "functions":[{"id":"derive-family","interface":"assertion-derive/v1","source":"functions/derive.rhai"}],
        "sources":{"family":{"pack":{"id":"synthetic-register","version":"0.1.0"},"route":"evidence-family","connection":"register","inputs":{"personId":{"selector":{"role":"person","profile":"person-by-id","field":"person-id"}}},"acquisitionPosture":"record-transformed"}},
        "assertionDefinitions":{"family-status":{"question":"Does the family record match?","semantics":{"requirement":"urn:example:requirement:family","kind":"criterion","evidenceType":"urn:example:evidence:family","referenceFrameworks":["urn:example:framework:family"]},"purpose":"family-check","grantCeiling":{"authorities":["organizational"],"actorKinds":["service"],"valueOrigins":["request"],"audiences":["urn:example:audience:consumer"]},"subjects":[{"role":"person","selectors":["person-by-id"]}],"acquisition":{"source":"family"},"derive":{"function":"derive-family"},"outputs":{"matched":{"concept":"urn:example:concept:matched","type":"boolean"}},"validitySeconds":300,"subjectBinding":"audience-scoped","representations":["signed-jws"]}}
    })).expect("pack-source project")
}

fn scripts() -> BTreeMap<String, String> {
    BTreeMap::from([(
        "functions/derive.rhai".to_owned(),
        "fn derive(facts, selectors, context) { [#{output: \"matched\", value: facts.parents.len > 0}] }".to_owned(),
    )])
}

fn checked_route() -> compile::CheckedPackRoute {
    checked_route_with_inputs(json!({
        "type":"object",
        "additionalProperties":false,
        "required":["personId"],
        "properties":{"personId":{"type":"string","minLength":1,"maxLength":64}}
    }))
}

fn checked_route_with_inputs(inputs_schema: serde_json::Value) -> compile::CheckedPackRoute {
    let facts_schema = json!({
        "type":"object",
        "additionalProperties":false,
        "required":["parents"],
        "properties":{
            "parents":{
                "type":"array",
                "maxItems":4,
                "items":{
                    "type":"object",
                    "additionalProperties":false,
                    "required":["relationship"],
                    "properties":{
                        "relationship":{"type":"string","enum":["mother","father","guardian"]},
                        "verified":{"type":"boolean"}
                    }
                }
            }
        }
    });
    let inputs_bytes = serde_json::to_vec(&inputs_schema).unwrap();
    let facts_bytes = serde_json::to_vec(&facts_schema).unwrap();
    let pack_bytes = serde_json::to_vec(&json!({
        "apiVersion":"id.registrystack.org/formats/adapter/pack/v1alpha1",
        "kind":"AdapterPack",
        "id":"synthetic-register",
        "version":"0.1.0",
        "testedVersions":[],
        "sourceRoutes":[{
            "id":"evidence-family",
            "evidence":{
                "inputsSchema":{"path":"schemas/inputs.schema.json","digest":sha256_uri(&inputs_bytes)},
                "factsSchema":{"path":"schemas/facts.schema.json","digest":sha256_uri(&facts_bytes)}
            }
        }]
    })).unwrap();
    compile::CheckedPackRoute {
        pack: project::PackReference {
            id: LocalId::new("synthetic-register").expect("pack id"),
            version: "0.1.0".to_owned(),
        },
        route: LocalId::new("evidence-family").expect("route id"),
        digest: sha256_uri(&pack_bytes),
        inputs_schema,
        facts_schema,
        acquisition_posture: project::AcquisitionPosture::RecordTransformed,
        pack_bytes,
        artifacts: BTreeMap::from([
            ("schemas/inputs.schema.json".to_owned(), inputs_bytes),
            ("schemas/facts.schema.json".to_owned(), facts_bytes),
        ]),
    }
}

fn sha256_uri(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").unwrap();
    }
    format!("sha256:{hex}")
}

#[test]
fn compiler_requires_and_embeds_the_checked_pack_route_closure() {
    let project = project();
    let missing = compile::compile(&project, &scripts()).expect_err("no legacy lowering");
    assert!(missing
        .iter()
        .any(|finding| finding.code == "source-pack-closure-missing"));

    let route = checked_route();
    let compiled =
        compile::compile_with_pack_routes(&project, &scripts(), std::slice::from_ref(&route))
            .expect("checked pack route compiles");
    assert_eq!(
        compiled.model["sources"]["family"]["pack"]["digest"],
        route.digest
    );
    assert_eq!(
        compiled.model["sources"]["family"]["route"],
        "evidence-family"
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &compiled.artifacts["schemas/source-facts/family.schema.json"]
        )
        .expect("compiled facts schema"),
        route.facts_schema
    );
    assert!(compiled.artifacts.contains_key(&format!(
        "adapter-packs/synthetic-register/{}/pack.yaml",
        route.digest.strip_prefix("sha256:").unwrap()
    )));
}

#[test]
fn source_inputs_must_be_authorized_known_route_inputs() {
    let mut unauthorized_project = project();
    unauthorized_project
        .sources
        .values_mut()
        .next()
        .expect("source")
        .inputs
        .get_mut("personId")
        .expect("binding")
        .selector
        .role = LocalId::new("other").expect("role");
    let findings = project::validate_project(&unauthorized_project);
    assert!(findings
        .iter()
        .any(|finding| finding.code == "source-input-authorization"));

    let mut unknown_input_project = project();
    let source = unknown_input_project
        .sources
        .values_mut()
        .next()
        .expect("source");
    let binding = source.inputs.remove("personId").expect("binding");
    source.inputs.insert("unknown".to_owned(), binding);
    let findings =
        compile::compile_with_pack_routes(&unknown_input_project, &scripts(), &[checked_route()])
            .expect_err("unknown route input");
    assert!(findings
        .iter()
        .any(|finding| finding.code == "source-route-input-required"));
    assert!(findings
        .iter()
        .any(|finding| finding.code == "source-route-input-unknown"));
}

#[test]
fn a_source_must_map_one_complete_route_input_alternative() {
    // The shape the Stack generator emits: no root `required`, one `oneOf`
    // member per lookup key.
    let alternatives = checked_route_with_inputs(json!({
        "type":"object",
        "additionalProperties":false,
        "properties":{
            "personId":{"type":"string","minLength":1,"maxLength":64},
            "householdId":{"type":"string","minLength":1,"maxLength":64},
            "region":{"type":"string","minLength":1,"maxLength":64}
        },
        "oneOf":[
            {"required":["personId"]},
            {"required":["householdId","region"]}
        ]
    }));
    compile::compile_with_pack_routes(&project(), &scripts(), std::slice::from_ref(&alternatives))
        .expect("mapping personId completes one alternative");

    let mut partial_project = project();
    let source = partial_project.sources.values_mut().next().expect("source");
    let binding = source.inputs.remove("personId").expect("binding");
    source.inputs.insert("householdId".to_owned(), binding);
    let findings = compile::compile_with_pack_routes(&partial_project, &scripts(), &[alternatives])
        .expect_err("householdId alone completes no alternative");
    let finding = findings
        .iter()
        .find(|finding| finding.code == "source-route-input-alternative")
        .unwrap_or_else(|| panic!("no alternative finding: {findings:#?}"));
    assert_eq!(finding.field.to_json_pointer(), "/sources/family/inputs");
    assert!(
        finding.message.contains("personId") && finding.message.contains("householdId and region"),
        "{}",
        finding.message
    );
}

#[test]
fn compiler_refuses_unchecked_or_overclaimed_pack_closures() {
    let base_project = project();
    let mut cases = Vec::new();

    let mut open_facts = checked_route();
    open_facts.facts_schema["additionalProperties"] = json!(true);
    cases.push((open_facts, "source-route-facts"));

    let mut mismatched_input = checked_route();
    mismatched_input.inputs_schema["properties"]["personId"]["type"] = json!("integer");
    cases.push((mismatched_input, "source-route-input-type"));

    let mut missing_pack = checked_route();
    missing_pack.pack_bytes.clear();
    cases.push((missing_pack, "source-pack-bytes-missing"));

    let mut forged_posture = checked_route();
    forged_posture.acquisition_posture = project::AcquisitionPosture::FieldProjected;
    cases.push((forged_posture, "source-pack-posture-mismatch"));

    let mut traversal = checked_route();
    traversal
        .artifacts
        .insert("../outside.rhai".to_owned(), b"refused".to_vec());
    cases.push((traversal, "source-pack-artifact-path"));

    for (route, code) in cases {
        let findings = compile::compile_with_pack_routes(&base_project, &scripts(), &[route])
            .expect_err("invalid checked closure");
        assert!(
            findings.iter().any(|finding| finding.code == code),
            "missing {code}: {findings:#?}"
        );
    }

    let mut overclaimed_project = project();
    overclaimed_project
        .sources
        .values_mut()
        .next()
        .unwrap()
        .acquisition_posture = project::AcquisitionPosture::SourceDerived;
    let findings =
        compile::compile_with_pack_routes(&overclaimed_project, &scripts(), &[checked_route()])
            .expect_err("stronger posture claim");
    assert!(findings
        .iter()
        .any(|finding| finding.code == "source-acquisition-posture"));
}

#[test]
fn compiler_rechecks_pack_identity_and_every_pinned_artifact() {
    let base_project = project();
    let mut cases = Vec::new();

    let mut pack_digest = checked_route();
    pack_digest.digest = sha256_uri(b"different pack bytes");
    cases.push((pack_digest, "source-pack-digest"));

    let mut pack_id = checked_route();
    let mut document: serde_json::Value = serde_json::from_slice(&pack_id.pack_bytes).unwrap();
    document["id"] = json!("other-register");
    pack_id.pack_bytes = serde_json::to_vec(&document).unwrap();
    pack_id.digest = sha256_uri(&pack_id.pack_bytes);
    cases.push((pack_id, "source-pack-identity"));

    let mut pack_version = checked_route();
    let mut document: serde_json::Value = serde_json::from_slice(&pack_version.pack_bytes).unwrap();
    document["version"] = json!("0.2.0");
    pack_version.pack_bytes = serde_json::to_vec(&document).unwrap();
    pack_version.digest = sha256_uri(&pack_version.pack_bytes);
    cases.push((pack_version, "source-pack-identity"));

    let mut route_identity = checked_route();
    let mut document: serde_json::Value =
        serde_json::from_slice(&route_identity.pack_bytes).unwrap();
    document["sourceRoutes"][0]["id"] = json!("other-route");
    route_identity.pack_bytes = serde_json::to_vec(&document).unwrap();
    route_identity.digest = sha256_uri(&route_identity.pack_bytes);
    cases.push((route_identity, "source-pack-route-contract"));

    let mut missing_envelope = checked_route();
    let mut document: serde_json::Value =
        serde_json::from_slice(&missing_envelope.pack_bytes).unwrap();
    document.as_object_mut().unwrap().remove("apiVersion");
    document.as_object_mut().unwrap().remove("kind");
    missing_envelope.pack_bytes = serde_json::to_vec(&document).unwrap();
    missing_envelope.digest = sha256_uri(&missing_envelope.pack_bytes);
    cases.push((missing_envelope, "source-pack-document"));

    let mut wrong_envelope = checked_route();
    let mut document: serde_json::Value =
        serde_json::from_slice(&wrong_envelope.pack_bytes).unwrap();
    document["kind"] = json!("AdapterProject");
    wrong_envelope.pack_bytes = serde_json::to_vec(&document).unwrap();
    wrong_envelope.digest = sha256_uri(&wrong_envelope.pack_bytes);
    cases.push((wrong_envelope, "source-pack-document"));

    let mut artifact_digest = checked_route();
    artifact_digest
        .artifacts
        .insert("schemas/facts.schema.json".to_owned(), b"{}".to_vec());
    cases.push((artifact_digest, "source-pack-artifact-digest"));

    let mut schema_value = checked_route();
    schema_value.facts_schema["properties"]["unexpected"] = json!({"type":"boolean"});
    cases.push((schema_value, "source-pack-schema-mismatch"));

    let mut unreferenced = checked_route();
    unreferenced
        .artifacts
        .insert("schemas/extra.schema.json".to_owned(), b"{}".to_vec());
    cases.push((unreferenced, "source-pack-artifact-unreferenced"));

    let mut sqlite_statement = checked_route();
    let statement = b"SELECT id FROM records WHERE id = :id".to_vec();
    let mut document: serde_json::Value =
        serde_json::from_slice(&sqlite_statement.pack_bytes).unwrap();
    document["endpoints"] = json!([{
        "id":"records", "component":"sqlite-extract", "authentication":{"type":"none"}, "maximumResponseBytes":8192,
        "sqliteExtract":{
            "extractProfile":"records",
            "statement":{"path":"queries/records.sql","digest":sha256_uri(&statement)},
            "columns":[{"name":"id","type":"string"}], "parameters":[{"name":"id","required":true}],
            "maximumExtractAgeSeconds":3600,"maximumRows":2,"maximumCellBytes":1024,"maximumStatementSteps":100000,"concurrency":1
        }
    }]);
    sqlite_statement.pack_bytes = serde_json::to_vec(&document).unwrap();
    sqlite_statement.digest = sha256_uri(&sqlite_statement.pack_bytes);
    sqlite_statement.artifacts.insert(
        "queries/records.sql".to_owned(),
        b"SELECT tampered FROM records".to_vec(),
    );
    cases.push((sqlite_statement, "source-pack-artifact-digest"));

    let mut open_api = checked_route();
    let declared =
        br#"{"openapi":"3.1.0","info":{"title":"Synthetic","version":"1"},"paths":{}}"#.to_vec();
    let mut document: serde_json::Value = serde_json::from_slice(&open_api.pack_bytes).unwrap();
    document["openApi"] = json!({"path":"openapi/provider.json","digest":sha256_uri(&declared)});
    open_api.pack_bytes = serde_json::to_vec(&document).unwrap();
    open_api.digest = sha256_uri(&open_api.pack_bytes);
    open_api.artifacts.insert(
        "openapi/provider.json".to_owned(),
        b"{\"openapi\":\"tampered\"}".to_vec(),
    );
    cases.push((open_api, "source-pack-artifact-digest"));

    let mut provider_schema = checked_route();
    let schema = br#"{"type":"array","items":{"type":"string"},"maxItems":2}"#.to_vec();
    let mut document: serde_json::Value =
        serde_json::from_slice(&provider_schema.pack_bytes).unwrap();
    document["sourceRoutes"][0]["steps"] =
        json!([{"validateSchema":{"path":"schemas/provider.json","digest":sha256_uri(&schema)}}]);
    provider_schema.pack_bytes = serde_json::to_vec(&document).unwrap();
    provider_schema.digest = sha256_uri(&provider_schema.pack_bytes);
    provider_schema
        .artifacts
        .insert("schemas/provider.json".to_owned(), b"{}".to_vec());
    cases.push((provider_schema, "source-pack-artifact-digest"));

    for (route, code) in cases {
        let findings = compile::compile_with_pack_routes(&base_project, &scripts(), &[route])
            .expect_err("unverified closure integrity");
        assert!(
            findings.iter().any(|finding| finding.code == code),
            "missing {code}: {findings:#?}"
        );
    }
}

#[test]
fn a_changed_pack_artifact_names_the_digest_to_pin_after_review() {
    let base_project = project();

    let mut schema = checked_route();
    let pinned = sha256_uri(&schema.artifacts["schemas/facts.schema.json"]);
    let edited = b"{}".to_vec();
    let actual = sha256_uri(&edited);
    schema
        .artifacts
        .insert("schemas/facts.schema.json".to_owned(), edited);

    let mut statement = checked_route();
    let pinned_statement = b"SELECT id FROM records WHERE id = :id".to_vec();
    let edited_statement = b"SELECT tampered FROM records".to_vec();
    let mut document: serde_json::Value = serde_json::from_slice(&statement.pack_bytes).unwrap();
    document["endpoints"] = json!([{
        "id":"records", "component":"sqlite-extract", "authentication":{"type":"none"}, "maximumResponseBytes":8192,
        "sqliteExtract":{
            "extractProfile":"records",
            "statement":{"path":"queries/records.sql","digest":sha256_uri(&pinned_statement)},
            "columns":[{"name":"id","type":"string"}], "parameters":[{"name":"id","required":true}],
            "maximumExtractAgeSeconds":3600,"maximumRows":2,"maximumCellBytes":1024,"maximumStatementSteps":100000,"concurrency":1
        }
    }]);
    statement.pack_bytes = serde_json::to_vec(&document).unwrap();
    statement.digest = sha256_uri(&statement.pack_bytes);
    statement
        .artifacts
        .insert("queries/records.sql".to_owned(), edited_statement.clone());

    for (route, path, pinned, actual) in [
        (schema, "schemas/facts.schema.json", pinned, actual),
        (
            statement,
            "queries/records.sql",
            sha256_uri(&pinned_statement),
            sha256_uri(&edited_statement),
        ),
    ] {
        let findings = compile::compile_with_pack_routes(&base_project, &scripts(), &[route])
            .expect_err("a changed artifact is refused");
        let finding = findings
            .iter()
            .find(|finding| finding.code == "source-pack-artifact-digest")
            .unwrap_or_else(|| panic!("no digest finding for {path}: {findings:#?}"));
        for needle in [path, pinned.as_str(), actual.as_str(), "after reviewing"] {
            assert!(
                finding.message.contains(needle),
                "{path}: {needle} missing from: {}",
                finding.message
            );
        }
    }
}

#[test]
fn retired_source_dsl_is_not_a_tolerated_compatibility_shape() {
    let legacy = json!({
        "type":"http-json",
        "connection":"register",
        "acquisitionPosture":"record-transformed",
        "request":{},
        "response":{},
        "extract":{"function":"extract"},
        "facts":{},
        "limits":{}
    });
    assert!(serde_json::from_value::<project::Source>(legacy).is_err());
}

#[test]
fn derivation_is_the_only_authored_function_interface() {
    let derive: project::FunctionInterface =
        serde_json::from_value(json!("assertion-derive/v1")).expect("derivation remains authored");
    assert_eq!(derive, project::FunctionInterface::AssertionDerive);

    for retired in ["source-prepare/v1", "source-extract/v1"] {
        assert!(serde_json::from_value::<project::FunctionInterface>(json!(retired)).is_err());
    }
}

#[test]
fn derivation_inspection_bindings_have_only_the_current_call_contract() {
    let compiled = compile::compile_with_pack_routes(&project(), &scripts(), &[checked_route()])
        .expect("the current checked pack and derivation compile");
    let bindings = compiled.functions[0]["bindings"].as_array().unwrap();
    assert_eq!(bindings.len(), 1);
    let binding = bindings[0].as_object().unwrap();
    assert_eq!(
        binding
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        ["definition", "mode", "inputs", "outputs"]
            .into_iter()
            .collect()
    );
    assert_eq!(binding["definition"], "family-status");
    assert_eq!(binding["mode"], "derive");
    assert_eq!(
        binding["inputs"]["facts"]["properties"]["parents"]["type"],
        "array"
    );
    assert_eq!(binding["outputs"]["type"], "array");
}

#[test]
fn a_project_projection_changes_facts_without_changing_the_source_pack() {
    let mut authored = serde_json::to_value(project()).unwrap();
    authored["sources"]["family"]["projection"] = json!({
        "source": "projections/family.rhai",
        "entrypoint": "project_facts",
        "schema": "schemas/family-facts.json"
    });
    let project: project::EvidenceProject =
        serde_json::from_value(authored).expect("a governed source projection is project-owned");
    let schema = json!({
        "$id": "https://registry.example/schemas/family-facts/1.0.0",
        "type": "object", "additionalProperties": false,
        "required": ["parentCount"],
        "properties": {"parentCount": {"type": "integer", "minimum": 0, "maximum": 16}}
    });
    let mut assets = scripts();
    assets.insert("functions/derive.rhai".to_owned(),
        "fn derive(facts, selectors, context) { [#{output: \"matched\", value: facts.parentCount > 0}] }".to_owned());
    assets.insert(
        "projections/family.rhai".to_owned(),
        "fn project_facts(source) { #{parentCount: source.parents.len} }".to_owned(),
    );
    assets.insert("schemas/family-facts.json".to_owned(), schema.to_string());
    let route = checked_route();
    let original_pack = route.pack_bytes.clone();
    let compiled = compile::compile_with_pack_routes(&project, &assets, &[route])
        .expect("project schema and script compile over the same source pack");
    assert_eq!(compiled.source_facts["family"], schema);
    let source = &compiled.model["sources"]["family"];
    assert_eq!(source["projection"]["entrypoint"], "project_facts");
    let path = source["projection"]["script"].as_str().unwrap();
    assert_eq!(
        compiled.artifacts[path],
        assets["projections/family.rhai"].as_bytes()
    );
    let prefix = source["pack"]["artifactPrefix"].as_str().unwrap();
    assert_eq!(
        compiled.artifacts[&format!("{prefix}/pack.yaml")],
        original_pack
    );
    assert_eq!(
        source["projection"]["digest"],
        sha256_uri(assets["projections/family.rhai"].as_bytes())
    );
}

#[test]
fn a_project_projection_refuses_missing_assets_and_traversal() {
    let mut authored = serde_json::to_value(project()).unwrap();
    authored["sources"]["family"]["projection"] = json!({
        "source": "projections/family.rhai", "entrypoint": "project_facts",
        "schema": "schemas/family-facts.json"
    });
    let project: project::EvidenceProject =
        serde_json::from_value(authored.clone()).expect("projection grammar");
    let findings = compile::compile_with_pack_routes(&project, &scripts(), &[checked_route()])
        .expect_err("missing project assets fail visibly");
    assert!(findings
        .iter()
        .any(|finding| finding.code == "source-projection-asset"));
    authored["sources"]["family"]["projection"]["source"] = json!("../outside.rhai");
    let project: project::EvidenceProject = serde_json::from_value(authored).unwrap();
    assert!(project::validate_project(&project)
        .iter()
        .any(|finding| finding.code == "source-projection-asset"));
}

#[test]
fn a_project_projection_refuses_schemas_the_runtime_cannot_admit() {
    let mut authored = serde_json::to_value(project()).unwrap();
    authored["sources"]["family"]["projection"] = json!({
        "source":"projections/family.rhai", "entrypoint":"project_facts",
        "schema":"schemas/family-facts.json"
    });
    let project: project::EvidenceProject = serde_json::from_value(authored).unwrap();
    let base = json!({
        "$id":"https://registry.example/schemas/family/1.0.0", "type":"object",
        "additionalProperties":false,"required":["parents"],
        "properties":{"parents":{"type":"array","maxItems":16,"items":{"type":"object",
            "additionalProperties":false,"properties":{"name":{"type":"string"}}}}}
    });
    let mut cases = Vec::new();
    let mut missing_id = base.clone();
    missing_id.as_object_mut().unwrap().remove("$id");
    cases.push(missing_id);
    let mut open_nested = base.clone();
    open_nested["properties"]["parents"]["items"]["additionalProperties"] = json!(true);
    cases.push(open_nested);
    let mut unbounded = base.clone();
    unbounded["properties"]["parents"]
        .as_object_mut()
        .unwrap()
        .remove("maxItems");
    cases.push(unbounded);
    let mut remote = base.clone();
    remote["properties"]["parents"] = json!({"$ref":"file:///private/projection-canary.json"});
    cases.push(remote);
    let mut invalid = base.clone();
    invalid["properties"]["parents"]["maxItems"] = json!("16");
    cases.push(invalid);
    for (index, schema) in cases.into_iter().enumerate() {
        let mut assets = scripts();
        assets.insert(
            "projections/family.rhai".to_owned(),
            "fn project_facts(source) { source }".to_owned(),
        );
        assets.insert("schemas/family-facts.json".to_owned(), schema.to_string());
        let findings = compile::compile_with_pack_routes(&project, &assets, &[checked_route()])
            .expect_err(&format!(
                "inadmissible projection schema case {index} must fail authoring"
            ));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "source-projection-schema"));
    }
}

#[test]
fn a_project_projection_refuses_scripts_without_one_unique_unary_entrypoint() {
    let mut authored = serde_json::to_value(project()).unwrap();
    authored["sources"]["family"]["projection"] = json!({
        "source":"projections/family.rhai", "entrypoint":"project_facts",
        "schema":"schemas/family-facts.json"
    });
    let project: project::EvidenceProject = serde_json::from_value(authored).unwrap();
    let schema = json!({
        "$id":"https://registry.example/schemas/family/1.0.0", "type":"object",
        "additionalProperties":false,"required":["parentCount"],
        "properties":{"parentCount":{"type":"integer","minimum":0,"maximum":16}}
    });
    for (script, code) in [
        ("fn project_facts(source) {", "source-projection-compile"),
        (
            "fn another_function(source) { source }",
            "source-projection-signature",
        ),
        (
            "fn project_facts() { #{} }",
            "source-projection-signature",
        ),
        (
            "fn project_facts(source) { source } fn project_facts(source, context) { source }",
            "source-projection-signature",
        ),
        (
            "fn project_facts(record) { record }",
            "source-projection-signature",
        ),
        (
            "private fn project_facts(source) { source }",
            "source-projection-signature",
        ),
        (
            "fn helper(value) { value } fn helper(value, other) { value } fn project_facts(source) { source }",
            "source-projection-signature",
        ),
        (
            "fn project_facts(source) { print(source); source }",
            "source-projection-compile",
        ),
    ] {
        let mut assets = scripts();
        assets.insert("projections/family.rhai".to_owned(), script.to_owned());
        assets.insert("schemas/family-facts.json".to_owned(), schema.to_string());
        let findings = compile::compile_with_pack_routes(&project, &assets, &[checked_route()])
            .expect_err("an inadmissible projection entrypoint must fail authoring");
        assert!(findings.iter().any(|finding| finding.code == code));
    }
}

use registry_evidence_authoring::{
    compile,
    project::{self, FunctionInterface},
    selector, target,
};
use registry_platform_yaml::LocalId;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn project() -> project::EvidenceProject {
    serde_json::from_value(json!({
        "id":"synthetic-evidence", "selectorProfiles":{"person-by-id":{"maximumAggregateBytes":64,"fields":{"person-id":{"type":"string","minimumBytes":1,"maximumBytes":64}}}},
        "functions":[{"id":"derive-status","interface":"assertion-derive/v1","source":"functions/derive.rhai"}],
        "sources":{"person":{"pack":{"id":"synthetic-register","version":"0.1.0"},"route":"evidence-person","connection":"population","inputs":{"personId":{"selector":{"role":"person","profile":"person-by-id","field":"person-id"}}},"acquisitionPosture":"record-transformed"}},
        "assertionDefinitions":{"active-status":{"question":"Is the person active?","semantics":{"requirement":"urn:example:requirement:active","kind":"criterion","evidenceType":"urn:example:evidence:active","referenceFrameworks":["urn:example:framework:status"]},"purpose":"status-verification","grantCeiling":{"authorities":["organizational"],"actorKinds":["service"],"valueOrigins":["request"],"audiences":["urn:example:audience:consumer"]},"subjects":[{"role":"person","selectors":["person-by-id"]}],"acquisition":{"source":"person"},"derive":{"function":"derive-status"},"outputs":{"active":{"concept":"urn:example:concept:active","type":"boolean"}},"validitySeconds":300,"subjectBinding":"audience-scoped","representations":["signed-jws"]}}
    })).unwrap()
}
fn scripts() -> BTreeMap<String, String> {
    BTreeMap::from([("functions/derive.rhai".to_owned(),"// derive is a name\nfn  derive (facts, selectors, context) { [#{output: \"active\", value: facts.active}] }".to_owned())])
}

fn pack_routes() -> Vec<compile::CheckedPackRoute> {
    let inputs_schema = json!({"type":"object","additionalProperties":false,"required":["personId"],"properties":{"personId":{"type":"string","minLength":1,"maxLength":64}}});
    let facts_schema = json!({"type":"object","additionalProperties":false,"required":["active"],"properties":{"active":{"type":"boolean"},"canary":{"type":"string","maxLength":128}}});
    let inputs_bytes = serde_json::to_vec(&inputs_schema).unwrap();
    let facts_bytes = serde_json::to_vec(&facts_schema).unwrap();
    let pack_bytes = serde_json::to_vec(&json!({
        "apiVersion":"id.registrystack.org/formats/adapter/pack/v1alpha1",
        "kind":"AdapterPack",
        "id":"synthetic-register",
        "version":"0.1.0",
        "testedVersions":[],
        "sourceRoutes":[{
            "id":"evidence-person",
            "evidence":{
                "inputsSchema":{"path":"schemas/inputs.schema.json","digest":sha256_uri(&inputs_bytes)},
                "factsSchema":{"path":"schemas/facts.schema.json","digest":sha256_uri(&facts_bytes)}
            }
        }]
    })).unwrap();
    vec![compile::CheckedPackRoute {
        pack: project::PackReference {
            id: LocalId::new("synthetic-register").unwrap(),
            version: "0.1.0".to_owned(),
        },
        route: LocalId::new("evidence-person").unwrap(),
        digest: sha256_uri(&pack_bytes),
        inputs_schema,
        facts_schema,
        acquisition_posture: project::AcquisitionPosture::RecordTransformed,
        pack_bytes,
        artifacts: BTreeMap::from([
            ("schemas/inputs.schema.json".to_owned(), inputs_bytes),
            ("schemas/facts.schema.json".to_owned(), facts_bytes),
        ]),
    }]
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

fn compile_project(
    project: &project::EvidenceProject,
    scripts: &BTreeMap<String, String>,
) -> Result<compile::CompiledProject, Vec<registry_evidence_authoring::Finding>> {
    compile::compile_with_pack_routes(project, scripts, &pack_routes())
}

#[test]
fn normalized_project_compiles_sources_outputs_and_named_functions() {
    let project = project();
    let compiled = compile_project(&project, &scripts()).unwrap();
    assert_eq!(compiled.model["requirements"][0]["handle"], "active-status");
    assert_eq!(
        compiled.model["requirements"][0]["concepts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        compiled.model["sources"]["person"]["route"],
        "evidence-person"
    );
    assert_eq!(
        compiled.model["sources"]["person"]["pack"]["digest"],
        pack_routes()[0].digest
    );
    let script =
        String::from_utf8(compiled.artifacts["derivations/active-status.rhai"].clone()).unwrap();
    assert!(script.contains("fn  authored_derive"));
    assert!(!script.contains("canary"));
    assert_eq!(
        compiled.functions[0]["callSites"][0],
        "/assertionDefinitions/active-status/derive"
    );
}

#[test]
fn constructed_project_display_text_is_checked_before_compilation() {
    let mut project = project();
    let question = "private marker\u{202e}hidden";
    project
        .assertion_definitions
        .values_mut()
        .next()
        .unwrap()
        .question = question.to_owned();

    for findings in [
        project::validate_project(&project),
        compile_project(&project, &scripts()).expect_err("unsafe display text must be refused"),
    ] {
        assert!(findings.iter().any(|finding| {
            finding.code == "definition-question"
                && finding.field.to_json_pointer() == "/assertionDefinitions/active-status/question"
        }));
        assert!(findings
            .iter()
            .all(|finding| !finding.message.contains(question)));
    }
}

#[test]
fn constructed_project_id_collisions_are_checked_before_compilation() {
    let mut project = project();
    let profile = project.selector_profiles[&LocalId::new("person-by-id").unwrap()].clone();
    project
        .selector_profiles
        .insert(LocalId::new("person_by_id").unwrap(), profile);

    for findings in [
        project::validate_project(&project),
        compile_project(&project, &scripts())
            .expect_err("separator-lookalike selector profiles must be refused"),
    ] {
        assert!(findings.iter().any(|finding| {
            finding.code == "selector-profile-id-collision"
                && finding.field.to_json_pointer() == "/selectorProfiles/person_by_id"
        }));
    }
}

#[test]
fn constructed_presentation_fields_share_display_text_validation() {
    type Mutate = fn(&mut project::EvidenceProject, &str);
    let cases: &[(&str, Mutate)] = &[
        ("/label", |project, value| {
            project.label = Some(value.to_owned())
        }),
        (
            "/selectorProfiles/person-by-id/description",
            |project, value| {
                project
                    .selector_profiles
                    .values_mut()
                    .next()
                    .unwrap()
                    .description = Some(value.to_owned());
            },
        ),
        (
            "/selectorProfiles/person-by-id/fields/person-id/label",
            |project, value| {
                let field = project
                    .selector_profiles
                    .values_mut()
                    .next()
                    .unwrap()
                    .fields
                    .values_mut()
                    .next()
                    .unwrap();
                let selector::Field::String { label, .. } = field else {
                    panic!("fixture selector field changed type");
                };
                *label = Some(value.to_owned());
            },
        ),
        ("/functions/0/description", |project, value| {
            project.functions[0].description = Some(value.to_owned());
        }),
        (
            "/assertionDefinitions/active-status/label",
            |project, value| {
                project
                    .assertion_definitions
                    .values_mut()
                    .next()
                    .unwrap()
                    .label = Some(value.to_owned());
            },
        ),
        (
            "/assertionDefinitions/active-status/outputs/active/description",
            |project, value| {
                project
                    .assertion_definitions
                    .values_mut()
                    .next()
                    .unwrap()
                    .outputs
                    .values_mut()
                    .next()
                    .unwrap()
                    .description = Some(value.to_owned());
            },
        ),
        ("/sources/person/label", |project, value| {
            project.sources.values_mut().next().unwrap().label = Some(value.to_owned());
        }),
    ];

    let unsafe_text = "private marker\u{fdd0}hidden";
    for (path, mutate) in cases {
        let mut project = project();
        mutate(&mut project, unsafe_text);
        let findings = project::validate_project(&project);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "display-text"
                    && finding.field.to_json_pointer() == *path)
                .count(),
            1,
            "missing display-text finding at {path}: {findings:#?}"
        );
        assert!(findings
            .iter()
            .all(|finding| !finding.message.contains(unsafe_text)));
    }
}

#[test]
fn constructed_multilingual_display_text_remains_valid() {
    let mut project = project();
    project.label = Some("می\u{200c}خواهم\u{00ad}".to_owned());
    project
        .assertion_definitions
        .values_mut()
        .next()
        .unwrap()
        .question = "العربية \u{200f}Latin".to_owned();

    assert!(project::validate_project(&project).is_empty());
    compile_project(&project, &scripts()).expect("allowed multilingual text compiles");
}

#[test]
fn function_interfaces_are_checked_without_execution() {
    assert!(registry_evidence_authoring::derivation::validate_function(
        "fn derive(a,b,c) {}",
        FunctionInterface::AssertionDerive
    )
    .is_empty());
    assert!(!registry_evidence_authoring::derivation::validate_function(
        "fn derive(a,b,c) {} fn extract(a,b) {}",
        FunctionInterface::AssertionDerive
    )
    .is_empty());
    for retired in ["source-prepare/v1", "source-extract/v1"] {
        assert!(serde_json::from_value::<FunctionInterface>(json!(retired)).is_err());
    }
}

#[test]
fn old_question_envelope_inline_source_and_disclosure_allow_are_rejected() {
    let old = b"apiVersion: id.registrystack.org/formats/evidence/question/v1alpha1\nkind: EvidenceQuestion\nid: old\n";
    assert!(project::read_project("evidence.yaml", old).is_err());
    let mut value = serde_json::to_value(project()).unwrap();
    value["assertionDefinitions"]["active-status"]["disclosure"] = json!({"allow":["active"]});
    assert!(serde_json::from_value::<project::EvidenceProject>(value).is_err());
    let mut value = serde_json::to_value(project()).unwrap();
    value["assertionDefinitions"]["active-status"]["source"] = json!({"operation":"readPerson"});
    assert!(serde_json::from_value::<project::EvidenceProject>(value).is_err());
}

#[test]
fn question_presentation_does_not_change_definition_dependencies() {
    let project = project();
    let before = compile::definition_dependencies(&project, "active-status").unwrap();
    let mut after = project.clone();
    after
        .assertion_definitions
        .values_mut()
        .next()
        .unwrap()
        .question = "Changed presentation".to_owned();
    assert_eq!(
        before,
        compile::definition_dependencies(&after, "active-status").unwrap()
    );
    after.sources.values_mut().next().unwrap().route = LocalId::new("evidence-person-v2").unwrap();
    assert_ne!(
        before,
        compile::definition_dependencies(&after, "active-status").unwrap()
    );
}

#[test]
fn definition_dependencies_ignore_function_declaration_order() {
    let original = project();
    let mut reordered = original.clone();
    reordered.functions.reverse();
    assert_eq!(
        compile::definition_dependencies(&original, "active-status"),
        compile::definition_dependencies(&reordered, "active-status")
    );

    let mut changed = serde_json::to_value(&original).unwrap();
    changed["selectorProfiles"]["person-by-id"]["maximumAggregateBytes"] = json!(65);
    let changed: project::EvidenceProject = serde_json::from_value(changed).unwrap();
    assert_ne!(
        compile::definition_dependencies(&original, "active-status"),
        compile::definition_dependencies(&changed, "active-status")
    );
}

fn authority() -> Value {
    json!({"target":"local","project":"synthetic-evidence","accessProfiles":{"consumer":{"authority":"organizational","actorKind":"service","requesterTags":["consumer"],"grants":[{"definition":"active-status","purpose":"status-verification","audienceFrom":"authenticated-requester","representations":["signed-jws"],"subjectBinding":"audience-scoped","subjects":[{"role":"person","selectorProfile":"person-by-id","valueOrigin":"request"}]}]}}})
}
use serde_json::Value;
#[test]
fn complete_target_grants_resolve_names_without_unioning_permissions() {
    let project = project();
    let authority: target::EvidenceTargetAuthority = serde_json::from_value(authority()).unwrap();
    let compiled = target::compile_authority(&authority, &project).unwrap();
    assert_eq!(compiled["kind"], "EvidenceCompiledTargetAuthority");
    assert_eq!(
        compiled["accessProfiles"]["consumer"]["grants"][0]["requirement"],
        "urn:example:requirement:active"
    );
    assert!(compiled["accessProfiles"]["consumer"]["grants"][0]
        .get("definition")
        .is_none());
    for dimension in ["purpose", "subjectBinding", "audienceFrom"] {
        let mut invalid = serde_json::to_value(&authority).unwrap();
        invalid["accessProfiles"]["consumer"]["grants"][0][dimension] = json!(match dimension {
            "subjectBinding" => "holder-bound",
            _ => "outside-ceiling",
        });
        let decoded = serde_json::from_value::<target::EvidenceTargetAuthority>(invalid);
        if dimension == "audienceFrom" {
            assert!(decoded.is_err());
        } else {
            assert!(!target::validate_authority(&decoded.unwrap(), &project).is_empty());
        }
    }
    let mut invalid = authority;
    invalid
        .access_profiles
        .values_mut()
        .next()
        .unwrap()
        .actor_kind = Some(project::ActorKind::Human);
    assert!(!target::validate_authority(&invalid, &project).is_empty());
}

#[test]
fn acquisition_variants_and_timezone_are_definition_owned() {
    let mut document = serde_json::to_value(project()).unwrap();
    document["assertionDefinitions"]["active-status"]["observationTimezone"] =
        json!("Asia/Bangkok");
    let project: project::EvidenceProject = serde_json::from_value(document.clone()).unwrap();
    let compiled = compile_project(&project, &scripts()).unwrap();
    assert_eq!(
        compiled.model["requirements"][0]["acquisition"],
        json!({"source":"person"})
    );
    assert_eq!(
        compiled.model["requirements"][0]["observationTimezone"],
        "Asia/Bangkok"
    );

    for acquisition in [
        json!({"type":"single","source":"person"}),
        json!({"type":"search-then-fetch","search":"person","fetch":"person-fetch"}),
        json!({"type":"search-then-fetch-set","search":"person","fetch":[{"source":"person-fetch","factInputs":["active"]},{"source":"person-check","factInputs":["active"]}],"maximumAcquisitionMilliseconds":3000}),
    ] {
        let mut retired = document.clone();
        retired["assertionDefinitions"]["active-status"]["acquisition"] = acquisition;
        assert!(serde_json::from_value::<project::EvidenceProject>(retired).is_err());
    }
}

#[test]
fn bounded_outputs_and_sd_jwt_projection_retain_constraints() {
    for output in [
        json!({"concept":"urn:example:out","type":"boolean"}),
        json!({"concept":"urn:example:out","type":"controlled-category","values":["yes","no"]}),
        json!({"concept":"urn:example:out","type":"bounded-integer","minimum":0,"maximum":42}),
        json!({"concept":"urn:example:out","type":"bounded-identifier","prefix":"urn:example:","minimumBytes":12,"maximumBytes":64}),
    ] {
        let mut document = serde_json::to_value(project()).unwrap();
        document["assertionDefinitions"]["active-status"]["outputs"]["active"] = output.clone();
        let project = serde_json::from_value(document).unwrap();
        let compiled = compile_project(&project, &scripts()).unwrap();
        assert_eq!(
            compiled.model["requirements"][0]["concepts"][0]["type"],
            output["type"]
        );
    }
    let mut document = serde_json::to_value(project()).unwrap();
    document["assertionDefinitions"]["active-status"]["outputs"]["active"] = json!({"concept":"urn:example:out","type":"reviewed-structured-value","schema":"schemas/projected.json","maximumSerializedBytes":1024});
    document["assertionDefinitions"]["active-status"]["outputs"]["active"]["sdJwtVc"] =
        json!({"claim":"active","disclosure":"top-level"});
    document["assertionDefinitions"]["active-status"]["representations"] =
        json!(["signed-jws", "sd-jwt-vc", "unsigned-json"]);
    let project = serde_json::from_value(document).unwrap();
    let mut scripts = scripts();
    scripts.insert("schemas/projected.json".to_owned(),json!({"$id":"urn:example:schema:projected","type":"object","required":["active"],"properties":{"active":{"type":"boolean"}},"additionalProperties":false}).to_string());
    let compiled = compile_project(&project, &scripts).unwrap();
    assert_eq!(
        compiled.model["requirements"][0]["concepts"][0]["sdJwtVc"]["claim"],
        "active"
    );
    assert_eq!(
        compiled.model["requirements"][0]["representations"],
        json!(["signed-jws", "sd-jwt-vc", "unsigned-json"])
    );
}

#[test]
fn sqlite_sources_preserve_reviewed_statement_and_execution_bounds() {
    let mut document = serde_json::to_value(project()).unwrap();
    let source = &mut document["sources"]["person"];
    source.as_object_mut().unwrap().remove("connection");
    source["type"] = json!("sqlite-extract");
    source["extractProfile"] = json!("population");
    source["maximumExtractAgeSeconds"] = json!(3600);
    source["request"] = json!({"statement":"queries/person.sql","columns":[{"name":"active","type":"boolean"}],"parameterBindings":{"person_id":{"selector":{"role":"person","profile":"person-by-id","field":"person-id"}}},"maximumRows":2,"maximumCellBytes":1024,"maximumStatementSteps":1000});
    source["response"]["projection"] = json!(["/rows"]);
    assert!(serde_json::from_value::<project::EvidenceProject>(document).is_err());
}

#[test]
fn authenticated_value_origins_task_authority_and_holder_binding_remain_complete() {
    let mut document = serde_json::to_value(project()).unwrap();
    let definition = &mut document["assertionDefinitions"]["active-status"];
    definition["grantCeiling"]["valueOrigins"] =
        json!(["authenticated-context", "authenticated-grant"]);
    definition["subjectBinding"] = json!("holder-bound");
    definition["representations"] = json!(["sd-jwt-vc", "sd-jwt-vc-batch"]);
    let project = serde_json::from_value(document).unwrap();
    let mut document = authority();
    document["accessProfiles"]["consumer"]["requesterClients"] = json!(["task-client"]);
    document["accessProfiles"]["consumer"]["grantSourceIssuer"] =
        json!("https://tasks.example.test");
    document["accessProfiles"]["consumer"]["grants"][0]["representations"] =
        json!(["sd-jwt-vc-batch"]);
    document["accessProfiles"]["consumer"]["grants"][0]["subjectBinding"] = json!("holder-bound");
    let subject = &mut document["accessProfiles"]["consumer"]["grants"][0]["subjects"][0];
    subject["valueOrigin"] = json!("authenticated-grant");
    subject["valueClaims"] = json!({"person-id":"task.context.person_id"});
    let authority = serde_json::from_value(document).unwrap();
    let compiled = target::compile_authority(&authority, &project).unwrap();
    assert_eq!(
        compiled["accessProfiles"]["consumer"]["grantSourceIssuer"],
        "https://tasks.example.test"
    );
    assert_eq!(
        compiled["accessProfiles"]["consumer"]["grants"][0]["subjects"][0]["valueClaims"]
            ["person-id"],
        "task.context.person_id"
    );
    assert_eq!(
        compiled["accessProfiles"]["consumer"]["grants"][0]["subjectBindingModes"],
        json!(["holder-bound"])
    );
}

#[test]
fn missing_named_dependencies_have_exact_field_paths() {
    let mut missing_sources = project();
    missing_sources.sources.clear();
    let findings = project::validate_project(&missing_sources);
    assert!(findings
        .iter()
        .any(|finding| finding.field.to_json_pointer()
            == "/assertionDefinitions/active-status/acquisition/source"));
    let mut project = project();
    project.functions.clear();
    let findings = project::validate_project(&project);
    assert!(findings
        .iter()
        .any(|finding| finding.field.to_json_pointer()
            == "/assertionDefinitions/active-status/derive/function"));
}

#[test]
fn derivations_cannot_read_undeclared_private_facts() {
    let mut scripts = scripts();
    scripts.insert(
        "functions/derive.rhai".to_owned(),
        "fn derive(facts, selectors, context) { [#{output: \"active\", value: facts.unacquired}] }"
            .to_owned(),
    );
    let findings = compile_project(&project(), &scripts).unwrap_err();
    assert!(findings
        .iter()
        .any(|finding| finding.code == "derivation-fact-undeclared"));
}

#[test]
fn source_function_refs_reject_ignored_call_parameters() {
    for field in ["parameters", "selectorInputs"] {
        let mut value = serde_json::to_value(project()).unwrap();
        value["sources"]["person"]["extract"][field] = json!({});
        assert!(serde_json::from_value::<project::EvidenceProject>(value).is_err());
    }
}

#[test]
fn compiler_metadata_exposes_typed_derivation_bindings_and_exact_outputs() {
    let compiled = compile_project(&project(), &scripts()).unwrap();
    let binding = &compiled.functions[0]["bindings"][0];
    assert_eq!(
        binding["outputs"]["items"]["anyOf"][0]["properties"]["output"]["enum"],
        json!(["active"])
    );
    assert_eq!(
        binding["inputs"]["facts"]["properties"]["active"]["type"],
        "boolean"
    );
    assert_eq!(binding["inputs"]["selectors"]["properties"], json!({}));
    assert_eq!(
        binding["inputs"]["context"]["properties"]["parameters"]["properties"],
        json!({})
    );
    assert!(!compiled
        .artifacts
        .contains_key("schemas/source-parameters/person.schema.json"));
}

#[test]
fn private_dates_keep_canonical_format_validation() {
    for kind in ["date", "date-time"] {
        let schema = project::value_schema(&json!({"type":kind}));
        assert_eq!(schema["format"], kind);
        let validator = jsonschema::JSONSchema::options()
            .should_validate_formats(true)
            .compile(&schema)
            .unwrap();
        assert!(!validator.is_valid(&json!("2024-99-99")));
        let good = if kind == "date" {
            "2024-02-29"
        } else {
            "2024-02-29T12:34:56Z"
        };
        assert!(validator.is_valid(&json!(good)));
    }
}

#[test]
fn presentation_metadata_does_not_change_compiled_semantics_or_behavior_dependencies() {
    let original = project();
    let mut edited = serde_json::to_value(&original).unwrap();
    edited["label"] = json!("Friendly project name");
    edited["sources"]["person"]["description"] = json!("Reviewed source explanation");
    edited["functions"][0]["label"] = json!("Extract a person");
    edited["selectorProfiles"]["person-by-id"]["label"] = json!("Person identifier");
    edited["assertionDefinitions"]["active-status"]["description"] = json!("Presentation only");
    edited["assertionDefinitions"]["active-status"]["outputs"]["active"]["label"] = json!("Active");
    let edited: project::EvidenceProject = serde_json::from_value(edited).unwrap();
    let a = compile_project(&original, &scripts()).unwrap();
    let b = compile_project(&edited, &scripts()).unwrap();
    assert_eq!(a.model, b.model);
    assert_eq!(a.artifacts, b.artifacts);
    assert_eq!(
        compile::definition_dependencies(&original, "active-status"),
        compile::definition_dependencies(&edited, "active-status")
    );
}

#[test]
fn malformed_references_return_findings_without_panicking_during_inspection() {
    let mut value = serde_json::to_value(project()).unwrap();
    value["assertionDefinitions"]["active-status"]["acquisition"]["source"] = json!("missing");
    let project: project::EvidenceProject = serde_json::from_value(value).unwrap();
    let findings = compile_project(&project, &scripts()).unwrap_err();
    assert!(findings
        .iter()
        .any(|finding| finding.field.to_json_pointer()
            == "/assertionDefinitions/active-status/acquisition/source"));
}

#[test]
fn retired_source_batch_and_acquisition_capability_wire_is_refused() {
    let mut current = project();
    current.maximum_holder_bound_batch_size = Some(serde_json::from_value(json!(4)).unwrap());
    let compiled =
        compile_project(&current, &scripts()).expect("the current batch ceiling compiles");
    assert_eq!(compiled.model["maximumHolderBoundBatchSize"], 4);

    let mut retired_capability = serde_json::to_value(project()).unwrap();
    retired_capability["acquisitionCapabilities"] = json!(["source-batch"]);
    assert!(serde_json::from_value::<project::EvidenceProject>(retired_capability).is_err());

    let mut retired_source_batch = serde_json::to_value(project()).unwrap();
    retired_source_batch["sources"]["person"]["batch"] = json!({
        "maximumItems":4,
        "prepare":{"function":"batch-prepare"},
        "extract":{"function":"batch-extract"},
        "response":{"projection":["/results/*"],"shape":{
            "type":"object","required":["results"],
            "properties":{"results":{"type":"array","maxItems":4,"items":{
                "type":"object","required":["active"],
                "properties":{"active":{"type":"boolean"}}
            }}}
        }}
    });
    assert!(serde_json::from_value::<project::EvidenceProject>(retired_source_batch).is_err());
}

#[test]
fn colliding_local_ids_retain_distinct_artifacts_and_deterministic_output() {
    let mut value = serde_json::to_value(project()).unwrap();
    value["functions"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"derive-extra","interface":"assertion-derive/v1","source":"functions/derive-extra.rhai"}));
    value["assertionDefinitions"]["active-status"]["outputs"] = json!({
        "active-extra":{
            "concept":"urn:example:concept:first",
            "type":"controlled-category",
            "values":["first"]
        }
    });
    let mut second_definition = value["assertionDefinitions"]["active-status"].clone();
    second_definition["semantics"]["requirement"] = json!("urn:example:requirement:second");
    second_definition["derive"]["function"] = json!("derive-extra");
    second_definition["outputs"] = json!({
        "extra":{
            "concept":"urn:example:concept:second",
            "type":"controlled-category",
            "values":["second"]
        }
    });
    value["assertionDefinitions"]["active-status-active"] = second_definition;
    let project: project::EvidenceProject = serde_json::from_value(value).unwrap();
    let mut scripts = scripts();
    scripts.insert(
        "functions/derive.rhai".to_owned(),
        "fn derive(facts, selectors, context) { [#{output: \"active-extra\", value: \"first\"}] }"
            .to_owned(),
    );
    scripts.insert(
        "functions/derive-extra.rhai".to_owned(),
        "fn derive(facts, selectors, context) { [#{output: \"extra\", value: \"second\"}] }"
            .to_owned(),
    );

    let compiled = compile_project(&project, &scripts).unwrap();
    let repeated = compile_project(&project, &scripts).unwrap();
    assert_eq!(compiled.model, repeated.model);
    assert_eq!(compiled.artifacts, repeated.artifacts);

    let text =
        |path: &str| String::from_utf8(compiled.artifacts[path].clone()).expect("text artifact");
    let first_codelist = compiled.model["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|requirement| requirement["handle"] == "active-status")
        .unwrap()["concepts"][0]["constraints"]["codelist"]
        .as_str()
        .unwrap();
    let second_codelist = compiled.model["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|requirement| requirement["handle"] == "active-status-active")
        .unwrap()["concepts"][0]["constraints"]["codelist"]
        .as_str()
        .unwrap();
    assert_ne!(first_codelist, second_codelist);
    assert!(text(first_codelist).contains("\"first\""));
    assert!(text(second_codelist).contains("\"second\""));
}

#[test]
fn an_authored_asset_cannot_replace_a_generated_artifact() {
    let mut value = serde_json::to_value(project()).unwrap();
    value["assertionDefinitions"]["active-status"]["outputs"]["details"] = json!({
        "concept":"urn:example:concept:details",
        "type":"reviewed-structured-value",
        "schema":"schemas/source-facts/person.schema.json",
        "maximumSerializedBytes":256
    });
    let project: project::EvidenceProject = serde_json::from_value(value).unwrap();
    let mut scripts = scripts();
    scripts.insert(
        "schemas/source-facts/person.schema.json".to_owned(),
        json!({
            "$id":"urn:example:schema:details",
            "type":"object",
            "required":["detail"],
            "properties":{"detail":{"type":"string","maxLength":64}},
            "additionalProperties":false
        })
        .to_string(),
    );

    let findings = compile_project(&project, &scripts).unwrap_err();

    assert!(findings.iter().any(|finding| {
        finding.code == "artifact-path-collision"
            && finding.field.to_json_pointer()
                == "/assertionDefinitions/active-status/outputs/details/schema"
    }));
}

#[test]
fn empty_complete_target_authority_explicitly_revokes_every_profile() {
    let mut value = authority();
    value["accessProfiles"] = json!({});
    value["apiVersion"] = json!(target::AUTHORITY_API_VERSION);
    value["kind"] = json!(target::AUTHORITY_KIND);
    let project = project();
    let decoded =
        target::read_authority("authority.yaml", value.to_string().as_bytes(), &project).unwrap();
    assert_eq!(
        target::compile_authority(&decoded.value, &project).unwrap()["accessProfiles"],
        json!({})
    );
    let mut value = authority();
    value["accessProfiles"]["consumer"]["grants"] = json!([]);
    value["apiVersion"] = json!(target::AUTHORITY_API_VERSION);
    value["kind"] = json!(target::AUTHORITY_KIND);
    assert!(
        target::read_authority("authority.yaml", value.to_string().as_bytes(), &project).is_err()
    );
}

#[test]
#[allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "the test executes Python only to validate generated declarations; the pure library performs no I/O"
)]
fn generated_types_resolve_structured_schemas_and_exact_function_result_shapes() {
    use std::io::Write as _;
    let mut value = serde_json::to_value(project()).unwrap();
    value["assertionDefinitions"]["active-status"]["outputs"]["details"] = json!({"concept":"urn:example:concept:details","type":"reviewed-structured-value","schema":"schemas/details.json","maximumSerializedBytes":2048});
    value["assertionDefinitions"]["active-status"]["derive"]["selectorInputs"] = json!([{"role":"person","alternatives":[{"profile":"person-by-id","fields":["person-id"]}]}]);
    let project: project::EvidenceProject = serde_json::from_value(value).unwrap();
    let mut scripts = scripts();
    scripts.insert("schemas/details.json".to_owned(),json!({"$id":"urn:example:schema:details","type":"object","required":["active"],"additionalProperties":false,"properties":{"active":{"type":"boolean"},"status":{"type":"string","enum":["current","expired"]},"count":{"type":"integer","minimum":0,"maximum":100}}}).to_string());
    let compiled = compile_project(&project, &scripts).unwrap();
    let ts = project::typescript(&project, &compiled);
    assert!(ts.contains("\"details\": { \"fields\": { \"active\": boolean; \"count\"?: number; \"status\"?: \"current\" | \"expired\" }"),"{ts}");
    assert!(ts.contains("ReadonlyArray<{ \"output\": \"active\"; \"value\": boolean } | { \"output\": \"details\""),"{ts}");
    assert!(ts.contains("\"profile\": \"person-by-id\"; \"values\": { \"person-id\": string }"));
    assert!(ts.contains("\"observed_at\": UtcInstant") && ts.contains("\"parameters\": {"));
    assert!(
        ts.find("export interface UtcInstant").unwrap()
            < ts.find("export interface AssertionOutputs").unwrap()
    );
    let py = project::python(&project, &compiled);
    assert!(py.contains("SourceFacts = TypedDict") && py.contains("FunctionBindings = TypedDict"));
    assert!(py.contains("NotRequired[Literal[\"current\", \"expired\"]]"));
    assert!(py.contains("\"output\": Literal[\"details\"]"));
    let mut child=std::process::Command::new("python3").args(["-c","import ast,sys; source=sys.stdin.read(); ast.parse(source); exec(compile(source,'generated-evidence-types','exec'), {})"]).stdin(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().expect("python3 syntax checker");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(py.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn checked_pack_facts_replace_retired_search_then_fetch_fact_closure() {
    let current = project();
    let compiled = compile_project(&current, &scripts()).unwrap();
    let ts = project::typescript(&current, &compiled);
    assert!(ts.contains("\"facts\": { \"active\": boolean"));

    let mut value = serde_json::to_value(project()).unwrap();
    value["sources"]["fetch"] = value["sources"]["person"].clone();
    value["sources"]["person"]["facts"] = json!({"search_only":{"type":"boolean"}});
    value["sources"]["fetch"]["facts"] = json!({"active":{"type":"boolean"}});
    value["functions"].as_array_mut().unwrap().push(json!({"id":"extract-fetch","interface":"source-extract/v1","source":"functions/fetch.rhai"}));
    value["sources"]["fetch"]["extract"] = json!({"function":"extract-fetch"});
    value["assertionDefinitions"]["active-status"]["acquisition"] =
        json!({"type":"search-then-fetch","search":"person","fetch":"fetch"});
    assert!(serde_json::from_value::<project::EvidenceProject>(value).is_err());
}

#[test]
fn malformed_selector_fields_and_derive_inputs_are_refused_before_type_projection() {
    for field in [
        json!({"type":"controlled-code"}),
        json!({"type":"controlled-code","codelist":"codelists/codes.yaml","maximumBytes":32}),
        json!({"type":"string","minimumBytes":1}),
        json!({"type":"boolean","maximumBytes":4}),
    ] {
        let mut value = serde_json::to_value(project()).unwrap();
        value["selectorProfiles"]["person-by-id"]["fields"]["person-id"] = field;
        assert!(serde_json::from_value::<project::EvidenceProject>(value).is_err());
    }
    let mut value = serde_json::to_value(project()).unwrap();
    value["assertionDefinitions"]["active-status"]["derive"]["selectorInputs"] =
        json!([{"role":"person","extra":true}]);
    assert!(serde_json::from_value::<project::EvidenceProject>(value).is_err());
}

#[test]
fn target_authority_conditionals_are_complete_and_actor_omission_is_preserved() {
    for (claims, origin, expected) in [
        (
            Some(json!({"person-id":"claims.id"})),
            "request",
            "authority-request-claims",
        ),
        (None, "authenticated-context", "authority-value-claims"),
        (
            Some(json!({"person-id":"claims..id"})),
            "authenticated-context",
            "authority-claim-path",
        ),
    ] {
        let mut project = project();
        project
            .assertion_definitions
            .values_mut()
            .next()
            .unwrap()
            .grant_ceiling
            .value_origins = serde_json::from_value(json!([origin])).unwrap();
        let mut value = authority();
        let subject = &mut value["accessProfiles"]["consumer"]["grants"][0]["subjects"][0];
        subject["valueOrigin"] = json!(origin);
        if let Some(claims) = claims {
            subject["valueClaims"] = claims;
        }
        let authority = serde_json::from_value(value).unwrap();
        let findings = target::validate_authority(&authority, &project);
        assert!(
            findings.iter().any(|finding| finding.code == expected),
            "{findings:?}"
        );
    }
    let mut value = authority();
    value["accessProfiles"]["consumer"]
        .as_object_mut()
        .unwrap()
        .remove("actorKind");
    let authority = serde_json::from_value(value).unwrap();
    let compiled = target::compile_authority(&authority, &project()).unwrap();
    assert!(compiled["accessProfiles"]["consumer"]
        .get("actorKind")
        .is_none());
    let mut value = serde_json::to_value(authority).unwrap();
    value["accessProfiles"]["consumer"]["requesterClients"] = json!(["unused-client"]);
    value["accessProfiles"]["consumer"]["grantSourceIssuer"] = json!("https://issuer.example.test");
    let authority = serde_json::from_value(value).unwrap();
    assert_eq!(
        target::validate_authority(&authority, &project())
            .iter()
            .filter(|finding| finding.code == "authority-task-only")
            .count(),
        2
    );
}

#[test]
fn unsupported_primitive_list_output_tags_are_never_accepted() {
    for tag in [
        "boolean-list",
        "controlled-category-list",
        "bounded-identifier-list",
        "bounded-integer-list",
        "reviewed-structured-value-list",
    ] {
        let mut value = serde_json::to_value(project()).unwrap();
        value["assertionDefinitions"]["active-status"]["outputs"]["active"]["type"] = json!(tag);
        let project = serde_json::from_value(value).unwrap();
        assert!(compile_project(&project, &scripts())
            .unwrap_err()
            .iter()
            .any(|finding| finding.code == "output-type"));
    }
}

#[test]
fn retired_reused_source_functions_and_prior_fact_contexts_are_refused() {
    let mut value = serde_json::to_value(project()).unwrap();
    value["sources"]["search"] = value["sources"]["person"].clone();
    value["sources"]["search"]["facts"] = json!({"reference":{"type":"string","maximumBytes":64}});
    value["sources"]["search"]["extract"] = json!({"function":"extract-search"});
    value["functions"].as_array_mut().unwrap().push(json!({"id":"extract-search","interface":"source-extract/v1","source":"functions/search.rhai"}));
    value["assertionDefinitions"]["from-search"] =
        value["assertionDefinitions"]["active-status"].clone();
    value["assertionDefinitions"]["from-search"]["semantics"]["requirement"] =
        json!("urn:example:requirement:from-search");
    value["assertionDefinitions"]["from-search"]["acquisition"] =
        json!({"type":"search-then-fetch","search":"search","fetch":"person"});
    assert!(serde_json::from_value::<project::EvidenceProject>(value).is_err());
}

#[test]
fn selector_semantic_bounds_remain_checked_after_typed_decoding() {
    for field in [
        json!({"type":"string","minimumBytes":32,"maximumBytes":16}),
        json!({"type":"string","minimumBytes":1,"maximumBytes":65}),
        json!({"type":"integer","minimum":10,"maximum":1}),
        json!({"type":"integer","minimum":-9_007_199_254_740_992_i64,"maximum":1}),
        json!({"type":"controlled-code","codelist":"outside/codes.yaml","codelistVersion":"1","maximumBytes":32}),
        json!({"type":"controlled-code","codelist":"codelists/codes.yaml","codelistVersion":"","maximumBytes":32}),
        json!({"type":"controlled-code","codelist":"codelists/codes.yaml","codelistVersion":"1","maximumBytes":65}),
    ] {
        let mut value = serde_json::to_value(project()).unwrap();
        value["selectorProfiles"]["person-by-id"]["fields"]["person-id"] = field;
        let project: project::EvidenceProject = serde_json::from_value(value).unwrap();
        let findings = compile_project(&project, &scripts()).unwrap_err();
        assert!(findings
            .iter()
            .any(|finding| finding.code == "selector-field-bounds"
                && finding.field.to_json_pointer()
                    == "/selectorProfiles/person-by-id/fields/person-id"));
    }
}

#[test]
fn typed_selector_fields_round_trip_and_compile_without_presentation() {
    for field in [
        json!({"type":"string","minimumBytes":1,"maximumBytes":64}),
        json!({"type":"date"}),
        json!({"type":"integer","minimum":-42,"maximum":42}),
        json!({"type":"boolean"}),
        json!({"type":"controlled-code","codelist":"codelists/codes.yaml","codelistVersion":"1","maximumBytes":32}),
    ] {
        let mut authored = field.clone();
        authored["label"] = json!("Selector label");
        authored["description"] = json!("Selector explanation");
        let mut value = serde_json::to_value(project()).unwrap();
        value["selectorProfiles"]["person-by-id"]["fields"]["person-id"] = authored.clone();
        let project: project::EvidenceProject = serde_json::from_value(value).unwrap();
        assert_eq!(
            serde_json::to_value(&project).unwrap()["selectorProfiles"]["person-by-id"]["fields"]
                ["person-id"],
            authored
        );
        let mut scripts = scripts();
        scripts.insert("codelists/codes.yaml".to_owned(), "apiVersion: id.registrystack.org/formats/evidence/codelist/v1alpha1\nkind: EvidenceCodelist\nuri: urn:example:codes\nversion: '1'\ntype: code-list\ncodes: [one, two]\n".to_owned());
        if field["type"] == "string" {
            let compiled = compile_project(&project, &scripts).unwrap();
            assert_eq!(
                compiled.model["selectorProfiles"]["person-by-id"]["fields"]["person-id"],
                field
            );
            assert!(!project::typescript(&project, &compiled).is_empty());
        } else {
            assert!(compile_project(&project, &scripts)
                .unwrap_err()
                .iter()
                .any(|finding| finding.code == "source-route-input-type"));
        }
    }
}

use registry_evidence_authoring::{
    compile,
    project::{self, FunctionInterface},
    target,
};
use serde_json::json;
use std::collections::BTreeMap;

fn project() -> project::EvidenceProject {
    serde_json::from_value(json!({
        "id":"synthetic-evidence", "selectorProfiles":{"person-by-id":{"maximumAggregateBytes":64,"fields":{"person-id":{"type":"string","minimumBytes":1,"maximumBytes":64}}}},
        "functions":[{"id":"extract-person","interface":"source-extract/v1","source":"functions/extract.rhai"},{"id":"derive-status","interface":"assertion-derive/v1","source":"functions/derive.rhai"}],
        "sources":{"person":{"type":"http-json","connection":"population","acquisitionPosture":"record-transformed","selectors":[{"role":"person","profiles":["person-by-id"]}],"request":{"method":"GET","path":"/people/{person-id}","pathBindings":{"person-id":{"selector":{"role":"person","profile":"person-by-id","field":"person-id"}}},"fixedHeaders":[]},"response":{"projection":["/active","/canary"],"shape":{"type":"object","required":["active","canary"],"properties":{"active":{"type":"boolean"},"canary":{"type":"string","maximumBytes":128}}},"maximumBytes":4096},"extract":{"function":"extract-person"},"facts":{"active":{"type":"boolean"},"canary":{"type":"string","maximumBytes":128}},"limits":{"attemptTimeoutMilliseconds":2000,"maximumConcurrency":4}}},
        "assertionDefinitions":{"active-status":{"question":"Is the person active?","semantics":{"requirement":"urn:example:requirement:active","kind":"criterion","evidenceType":"urn:example:evidence:active","referenceFrameworks":["urn:example:framework:status"]},"purpose":"status-verification","grantCeiling":{"authorities":["organizational"],"actorKinds":["service"],"valueOrigins":["request"],"audiences":["urn:example:audience:consumer"]},"subjects":[{"role":"person","selectors":["person-by-id"]}],"acquisition":{"type":"single","source":"person"},"derive":{"function":"derive-status"},"outputs":{"active":{"concept":"urn:example:concept:active","type":"boolean"}},"validitySeconds":300,"subjectBinding":"audience-scoped","representations":["signed-jws"]}}
    })).unwrap()
}
fn scripts() -> BTreeMap<String, String> {
    BTreeMap::from([("functions/extract.rhai".to_owned(),"fn extract(response, selectors, context) { #{outcome: \"match\", facts: #{active: response.active, canary: response.canary}} }".to_owned()),("functions/derive.rhai".to_owned(),"// derive is a name\nfn  derive (facts, selectors, context) { [#{output: \"active\", value: facts.active}] }".to_owned())])
}

#[test]
fn normalized_project_compiles_sources_outputs_and_named_functions() {
    let project = project();
    let compiled = compile::compile(&project, &scripts()).unwrap();
    assert_eq!(compiled.model["requirements"][0]["handle"], "active-status");
    assert_eq!(
        compiled.model["requirements"][0]["concepts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        compiled.model["sources"]["person"]["request"]["pathBindings"]["person-id"]["type"],
        "selector"
    );
    let script =
        String::from_utf8(compiled.artifacts["derivations/active-status.rhai"].clone()).unwrap();
    assert!(script.contains("fn  authored_derive"));
    assert!(!script.contains("canary"));
    assert_eq!(
        compiled.functions[0]["callSites"][0],
        "/sources/person/extract"
    );
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
    assert!(!registry_evidence_authoring::derivation::validate_function(
        "fn prepare(a,b,c) {}",
        FunctionInterface::SourcePrepare
    )
    .is_empty());
    assert!(!registry_evidence_authoring::derivation::validate_function(
        "fn extract(a,b) {} fn extract(a,b,c) {}",
        FunctionInterface::SourceExtract
    )
    .is_empty());
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
    after
        .sources
        .values_mut()
        .next()
        .unwrap()
        .response
        .projection
        .push("/extra".to_owned());
    assert_ne!(
        before,
        compile::definition_dependencies(&after, "active-status").unwrap()
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
        let invalid = serde_json::from_value::<target::EvidenceTargetAuthority>(invalid).unwrap();
        assert!(!target::validate_authority(&invalid, &project).is_empty());
    }
    let mut invalid = authority;
    invalid
        .access_profiles
        .values_mut()
        .next()
        .unwrap()
        .actor_kind = "human".to_owned();
    assert!(!target::validate_authority(&invalid, &project).is_empty());
}

#[test]
fn acquisition_variants_and_timezone_are_definition_owned() {
    let mut document = serde_json::to_value(project()).unwrap();
    document["sources"]["person-fetch"] = document["sources"]["person"].clone();
    document["sources"]["person-check"] = document["sources"]["person"].clone();
    for acquisition in [
        json!({"type":"single","source":"person"}),
        json!({"type":"search-then-fetch","search":"person","fetch":"person-fetch"}),
        json!({"type":"search-then-fetch-set","search":"person","fetch":[{"source":"person-fetch","factInputs":["active"]},{"source":"person-check","factInputs":["active"]}],"maximumAcquisitionMilliseconds":3000}),
    ] {
        document["assertionDefinitions"]["active-status"]["acquisition"] = acquisition.clone();
        document["assertionDefinitions"]["active-status"]["observationTimezone"] =
            json!("Asia/Bangkok");
        let project = serde_json::from_value(document.clone()).unwrap();
        let compiled = compile::compile(&project, &scripts()).unwrap();
        assert_eq!(
            compiled.model["requirements"][0]["acquisition"],
            acquisition
        );
        assert_eq!(
            compiled.model["requirements"][0]["observationTimezone"],
            "Asia/Bangkok"
        );
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
        let compiled = compile::compile(&project, &scripts()).unwrap();
        assert_eq!(
            compiled.model["requirements"][0]["concepts"][0]["type"],
            output["type"]
        );
    }
    let mut document = serde_json::to_value(project()).unwrap();
    document["assertionDefinitions"]["active-status"]["outputs"]["active"]["sdJwtVc"] =
        json!({"claim":"active","disclosure":"top-level"});
    document["assertionDefinitions"]["active-status"]["representations"] =
        json!(["signed-jws", "sd-jwt-vc", "unsigned-json"]);
    let project = serde_json::from_value(document).unwrap();
    let compiled = compile::compile(&project, &scripts()).unwrap();
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
    let project = serde_json::from_value(document).unwrap();
    let mut scripts = scripts();
    scripts.insert(
        "queries/person.sql".to_owned(),
        "SELECT active FROM people WHERE person_id = :person_id LIMIT 2".to_owned(),
    );
    let compiled = compile::compile(&project, &scripts).unwrap();
    assert!(compiled.artifacts.contains_key("queries/person.sql"));
    assert_eq!(
        compiled.model["sources"]["person"]["request"]["maximumRows"],
        2
    );
    assert_eq!(
        compiled.model["sources"]["person"]["request"]["maximumConcurrency"],
        4
    );
    assert_eq!(
        compiled.model["sources"]["person"]["maximumExtractAgeSeconds"],
        3600
    );
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
    let findings = compile::compile(&project(), &scripts).unwrap_err();
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
fn compiler_metadata_exposes_typed_function_bindings_and_exact_extract_outcomes() {
    let compiled = compile::compile(&project(), &scripts()).unwrap();
    let binding = &compiled.functions[0]["bindings"][0];
    assert_eq!(
        binding["outputs"]["outcome"]["enum"],
        json!(["match", "no_match", "ambiguous"])
    );
    assert_eq!(binding["outputs"]["facts"]["active"]["type"], "boolean");
    assert_eq!(
        binding["inputs"]["selectors"][0]["profiles"]["person-by-id"]["person-id"]["maxLength"],
        64
    );
    assert_eq!(
        compiled.artifacts["schemas/person-parameters.schema.json"],
        serde_json::to_vec_pretty(
            &json!({"type":"object","additionalProperties":false,"properties":{},"required":[]})
        )
        .unwrap()
    );
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
    let a = compile::compile(&original, &scripts()).unwrap();
    let b = compile::compile(&edited, &scripts()).unwrap();
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
    let findings = compile::compile(&project, &scripts()).unwrap_err();
    assert!(findings
        .iter()
        .any(|finding| finding.field.to_json_pointer()
            == "/assertionDefinitions/active-status/acquisition/source"));
}

#[test]
fn source_batches_compile_named_source_interfaces_and_package_gates() {
    let mut value = serde_json::to_value(project()).unwrap();
    value["acquisitionCapabilities"] = json!(["source-batch"]);
    value["maximumHolderBoundBatchSize"] = json!(4);
    value["functions"].as_array_mut().unwrap().extend([
        json!({"id":"batch-prepare","interface":"source-prepare/v1","source":"functions/batch-prepare.rhai"}),
        json!({"id":"batch-extract","interface":"source-extract/v1","source":"functions/batch-extract.rhai"}),
    ]);
    value["sources"]["person"]["batch"] = json!({"maximumItems":4,"prepare":{"function":"batch-prepare"},"extract":{"function":"batch-extract"},"response":{"projection":["/results/*"],"shape":{"type":"object","required":["results"],"properties":{"results":{"type":"array","maxItems":4,"items":{"type":"object","required":["active"],"properties":{"active":{"type":"boolean"}}}}}}}});
    let project: project::EvidenceProject = serde_json::from_value(value).unwrap();
    let mut scripts = scripts();
    scripts.insert(
        "functions/batch-prepare.rhai".to_owned(),
        "fn prepare(items, context) { #{query:[],body:#{items:items}} }".to_owned(),
    );
    scripts.insert(
        "functions/batch-extract.rhai".to_owned(),
        "fn extract(response, context) { [] }".to_owned(),
    );
    let compiled = compile::compile(&project, &scripts).unwrap();
    assert_eq!(
        compiled.model["acquisitionCapabilities"],
        json!(["source-batch"])
    );
    assert_eq!(compiled.model["maximumHolderBoundBatchSize"], 4);
    assert!(
        String::from_utf8(compiled.artifacts["adapters/person-batch-prepare.rhai"].clone())
            .unwrap()
            .contains("fn prepare_batch")
    );
    assert!(
        String::from_utf8(compiled.artifacts["adapters/person-batch-extract.rhai"].clone())
            .unwrap()
            .contains("fn extract_batch")
    );
    let ts = project::typescript(&project, &compiled);
    let py = project::python(&project, &compiled);
    for text in [&ts, &py] {
        assert!(text.contains("batch-prepare") && text.contains("batch-extract"));
        assert!(text.contains("\"slots\"") && text.contains("\"slot\""));
    }
    let mut invalid = project;
    invalid.acquisition_capabilities = Default::default();
    assert!(compile::compile(&invalid, &scripts).is_err());
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
    let compiled = compile::compile(&project, &scripts).unwrap();
    let ts = project::typescript(&project, &compiled);
    assert!(ts.contains("\"details\": { \"active\": boolean; \"count\"?: number; \"status\"?: \"current\" | \"expired\" }"),"{ts}");
    assert!(ts.contains("ReadonlyArray<{ \"output\": \"active\"; \"value\": boolean } | { \"output\": \"details\""),"{ts}");
    assert!(ts.contains("\"profile\": \"person-by-id\"; \"values\": { \"person-id\": string }"));
    assert!(ts.contains("\"observed_at\": string") && ts.contains("\"parameters\": {"));
    let py = project::python(&project, &compiled);
    assert!(
        py.contains("SourceResponses = TypedDict") && py.contains("FunctionBindings = TypedDict")
    );
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

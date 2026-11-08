//! The `publicCheck` member of an assertion definition and its activation on a
//! target authority.

use registry_evidence_authoring::{
    compile::{self, CheckedPackRoute},
    project::{self, EvidenceProject},
    target, Finding,
};
use registry_platform_yaml::LocalId;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const DEFINITION: &str = "certificate-status";

fn project_value() -> Value {
    json!({
        "id": "certificate-check",
        "selectorProfiles": {"certificate-number": {"maximumAggregateBytes": 32, "fields": {"number": {"type": "string", "minimumBytes": 4, "maximumBytes": 32}}}},
        "functions": [{"id": "derive-certificate-check", "interface": "assertion-derive/v1", "source": "functions/derive.rhai"}],
        "sources": {"certificate-record": {"pack": {"id": "synthetic-register", "version": "1"}, "route": "certificate", "connection": "synthetic-register", "inputs": {"recordId": {"selector": {"role": "certificate", "profile": "certificate-number", "field": "number"}}}, "acquisitionPosture": "record-transformed"}},
        "assertionDefinitions": {DEFINITION: {
            "question": "What is the current status of this certificate?",
            "semantics": {"requirement": "urn:example:requirement:certificate-status:v1", "kind": "information-requirement", "evidenceType": "urn:example:evidence-type:certificate-status:v1", "referenceFrameworks": ["urn:example:framework:certificate-check:v1"]},
            "purpose": "certificate-check",
            "grantCeiling": {"authorities": ["organizational"], "actorKinds": ["service"], "valueOrigins": ["request"], "audiences": ["urn:example:audience:portal"]},
            "subjects": [{"role": "certificate", "selectors": ["certificate-number"]}],
            "acquisition": {"source": "certificate-record"},
            "derive": {"function": "derive-certificate-check"},
            "outputs": {
                "status": {"concept": "urn:example:concept:certificate-status:v1", "type": "controlled-category", "values": ["valid", "suspended", "revoked", "expired"]},
                "printed": {"concept": "urn:example:concept:certificate-printed:v1", "type": "reviewed-structured-value", "schema": "schemas/printed.json", "maximumSerializedBytes": 1024}
            },
            "validitySeconds": 300,
            "subjectBinding": "audience-scoped",
            "representations": ["signed-jws"],
            "publicCheck": {"checkCodeFact": "checkCode", "statusOutput": "status", "fieldsOutput": "printed"}
        }}
    })
}

fn project_with(edit: impl FnOnce(&mut Value)) -> EvidenceProject {
    let mut value = project_value();
    edit(&mut value["assertionDefinitions"][DEFINITION]);
    serde_json::from_value(value).expect("project shape")
}

fn scripts() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("functions/derive.rhai".to_owned(), "fn derive(facts, selectors, context) { [#{output: \"status\", value: \"valid\"}] }".to_owned()),
        ("schemas/printed.json".to_owned(), json!({"$id": "urn:example:schema:printed", "type": "object", "required": ["holder"], "properties": {"holder": {"type": "string", "maxLength": 64}}, "additionalProperties": false}).to_string()),
    ])
}

fn sha256_uri(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut hex = String::new();
    for byte in Sha256::digest(bytes) {
        write!(&mut hex, "{byte:02x}").unwrap();
    }
    format!("sha256:{hex}")
}

fn pack_routes_with(facts: Value, inputs: Value) -> Vec<CheckedPackRoute> {
    let required: Vec<String> = inputs["properties"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let inputs_schema = json!({"type": "object", "additionalProperties": false, "required": required, "properties": inputs["properties"]});
    let facts_schema =
        json!({"type": "object", "additionalProperties": false, "properties": facts});
    let inputs_bytes = serde_json::to_vec(&inputs_schema).unwrap();
    let facts_bytes = serde_json::to_vec(&facts_schema).unwrap();
    let pack_bytes = serde_json::to_vec(&json!({
        "apiVersion": "id.registrystack.org/formats/adapter/pack/v1alpha1", "kind": "AdapterPack", "id": "synthetic-register", "version": "1", "testedVersions": [],
        "sourceRoutes": [{"id": "certificate", "evidence": {
            "inputsSchema": {"path": "schemas/inputs.schema.json", "digest": sha256_uri(&inputs_bytes)},
            "factsSchema": {"path": "schemas/facts.schema.json", "digest": sha256_uri(&facts_bytes)}}}]
    })).unwrap();
    vec![CheckedPackRoute {
        pack: project::PackReference {
            id: LocalId::new("synthetic-register").unwrap(),
            version: "1".to_owned(),
        },
        route: LocalId::new("certificate").unwrap(),
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

fn pack_routes() -> Vec<CheckedPackRoute> {
    pack_routes_with(
        json!({"status": {"type": "string"}, "checkCode": {"type": "string", "pattern": "^[A-Z2-7]{24}$"}}),
        json!({"properties": {"recordId": {"type": "string", "minLength": 4, "maxLength": 32}}}),
    )
}

fn compile_project(project: &EvidenceProject) -> Result<compile::CompiledProject, Vec<Finding>> {
    compile::compile_with_pack_routes(project, &scripts(), &pack_routes())
}

fn codes(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|finding| finding.code).collect()
}

fn only_code(project: &EvidenceProject, code: &str) {
    let findings = project::validate_project(project);
    assert_eq!(codes(&findings), [code], "{findings:?}");
    assert!(!findings[0].message.is_empty());
}

#[test]
fn public_check_parses_compiles_and_is_emitted_into_the_requirement() {
    let project = project_with(|_| {});
    let compiled = compile_project(&project).unwrap();
    assert_eq!(
        compiled.model["requirements"][0]["publicCheck"],
        json!({"checkCodeFact": "checkCode", "statusOutput": "status", "fieldsOutput": "printed"})
    );
}

#[test]
fn a_definition_without_public_check_emits_no_member() {
    let project = project_with(|definition| {
        definition.as_object_mut().unwrap().remove("publicCheck");
    });
    let compiled = compile_project(&project).unwrap();
    assert!(compiled.model["requirements"][0]
        .get("publicCheck")
        .is_none());
}

#[test]
fn an_unknown_member_inside_public_check_is_refused() {
    let mut value = project_value();
    value["assertionDefinitions"][DEFINITION]["publicCheck"]["extra"] = json!(true);
    assert!(serde_json::from_value::<EvidenceProject>(value).is_err());
}

#[test]
fn an_extra_relying_only_output_still_compiles() {
    let project = project_with(|definition| {
        definition["outputs"]["internal"] =
            json!({"concept": "urn:example:concept:internal:v1", "type": "boolean"});
    });
    let compiled = compile_project(&project).unwrap();
    assert_eq!(
        compiled.model["requirements"][0]["concepts"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn refusal_1_status_output_must_be_a_controlled_category_within_the_four_statuses() {
    for edit in [
        json!({"concept": "urn:example:concept:certificate-status:v1", "type": "boolean"}),
        json!({"concept": "urn:example:concept:certificate-status:v1", "type": "controlled-category", "values": ["valid", "pending"]}),
    ] {
        only_code(
            &project_with(|d| d["outputs"]["status"] = edit),
            "public-check-status-output",
        );
    }
    only_code(
        &project_with(|d| d["publicCheck"]["statusOutput"] = json!("absent")),
        "public-check-status-output",
    );
}

#[test]
fn refusal_1_a_subset_of_the_four_statuses_is_accepted() {
    let project = project_with(|d| d["outputs"]["status"]["values"] = json!(["valid", "revoked"]));
    assert!(project::validate_project(&project).is_empty());
}

#[test]
fn refusal_2_fields_output_must_be_a_reviewed_structured_value() {
    only_code(
        &project_with(|d| {
            d["outputs"]["printed"] =
                json!({"concept": "urn:example:concept:certificate-printed:v1", "type": "boolean"})
        }),
        "public-check-fields-output",
    );
    only_code(
        &project_with(|d| d["publicCheck"]["fieldsOutput"] = json!("absent")),
        "public-check-fields-output",
    );
}

#[test]
fn refusal_3_status_and_fields_must_be_different_outputs() {
    let findings = project::validate_project(&project_with(|d| {
        d["publicCheck"]["fieldsOutput"] = json!("status")
    }));
    assert!(
        codes(&findings).contains(&"public-check-same-output"),
        "{findings:?}"
    );
}

#[test]
fn refusal_4_the_certificate_number_is_one_role_one_profile_one_field() {
    only_code(
        &project_with(
            |d| d["subjects"] = json!([{"role": "certificate", "selectors": ["certificate-number"]}, {"role": "holder", "selectors": ["certificate-number"]}]),
        ),
        "public-check-subject-shape",
    );
}

#[test]
fn refusal_4_a_profile_with_two_fields_is_refused() {
    let mut value = project_value();
    value["selectorProfiles"]["certificate-number"]["fields"]["extra"] =
        json!({"type": "string", "minimumBytes": 1, "maximumBytes": 8});
    let project: EvidenceProject = serde_json::from_value(value).unwrap();
    only_code(&project, "public-check-subject-shape");
}

#[test]
fn refusal_4_a_role_with_two_profiles_is_refused() {
    let mut value = project_value();
    value["selectorProfiles"]["second-number"] =
        value["selectorProfiles"]["certificate-number"].clone();
    value["assertionDefinitions"][DEFINITION]["subjects"][0]["selectors"] =
        json!(["certificate-number", "second-number"]);
    let project: EvidenceProject = serde_json::from_value(value).unwrap();
    only_code(&project, "public-check-subject-shape");
}

#[test]
fn refusal_4_a_number_field_the_route_cannot_send_as_text_is_refused() {
    for field in [
        json!({"type": "integer", "minimum": 1, "maximum": 999_999}),
        json!({"type": "boolean"}),
    ] {
        let mut value = project_value();
        value["selectorProfiles"]["certificate-number"]["fields"]["number"] = field;
        let project: EvidenceProject = serde_json::from_value(value).unwrap();
        only_code(&project, "public-check-subject-shape");
    }
}

#[test]
fn refusal_5_the_code_fact_must_be_a_string_fact_the_source_does_not_take_as_input() {
    let project = project_with(|_| {});
    for (facts, inputs) in [
        (
            json!({"status": {"type": "string"}}),
            json!({"properties": {"recordId": {"type": "string", "minLength": 4, "maxLength": 32}}}),
        ),
        (
            json!({"status": {"type": "string"}, "checkCode": {"type": "integer"}}),
            json!({"properties": {"recordId": {"type": "string", "minLength": 4, "maxLength": 32}}}),
        ),
    ] {
        let findings = compile::compile_with_pack_routes(
            &project,
            &scripts(),
            &pack_routes_with(facts, inputs),
        )
        .unwrap_err();
        assert_eq!(codes(&findings), ["public-check-code-fact"], "{findings:?}");
    }
    let mut value = project_value();
    value["sources"]["certificate-record"]["inputs"] = json!({"checkCode": {"selector": {"role": "certificate", "profile": "certificate-number", "field": "number"}}});
    let bound: EvidenceProject = serde_json::from_value(value).unwrap();
    let routes = pack_routes_with(
        json!({"status": {"type": "string"}, "checkCode": {"type": "string"}}),
        json!({"properties": {"checkCode": {"type": "string", "minLength": 4, "maxLength": 32}}}),
    );
    let findings = compile::compile_with_pack_routes(&bound, &scripts(), &routes).unwrap_err();
    assert_eq!(codes(&findings), ["public-check-code-fact"], "{findings:?}");
}

#[test]
fn refusal_6_existence_disclosure_must_stay_collapse_unresolved() {
    only_code(
        &project_with(|d| d["existenceDisclosure"] = json!("reveal")),
        "public-check-existence-disclosure",
    );
}

#[test]
fn refusal_7_the_check_acquires_through_one_source_only() {
    let mut value = project_value();
    value["sources"]["wallet"] = json!({"pack": {"id": "synthetic-register", "version": "1"}, "route": "certificate", "connection": "synthetic-register", "inputs": {}, "acquisitionPosture": "record-transformed"});
    value["selectorProfiles"]["wallet-number"] =
        value["selectorProfiles"]["certificate-number"].clone();
    value["assertionDefinitions"][DEFINITION]["acquisition"] = json!({"source": "certificate-record", "holderPresented": {"source": "wallet", "selectorProfiles": ["wallet-number"]}});
    value["assertionDefinitions"][DEFINITION]["subjects"][0]["selectors"] =
        json!(["certificate-number", "wallet-number"]);
    let project: EvidenceProject = serde_json::from_value(value).unwrap();
    let findings = project::validate_project(&project);
    assert!(
        codes(&findings).contains(&"public-check-acquisition"),
        "{findings:?}"
    );
}

#[test]
fn refusal_8_an_entity_reference_output_is_refused() {
    for (value_type, extra) in [
        (
            "audience-scoped-entity-reference",
            json!({"maximumBytes": 64}),
        ),
        (
            "entity-reference-list",
            json!({"minimumItems": 1, "maximumItems": 2, "unique": true}),
        ),
    ] {
        let project = project_with(|d| {
            let mut output = json!({"concept": "urn:example:concept:owner:v1", "type": value_type});
            for (key, field) in extra.as_object().unwrap() {
                output[key] = field.clone();
            }
            d["outputs"]["owner"] = output;
        });
        only_code(&project, "public-check-entity-reference-output");
    }
}

fn authority_value(public_check: Value) -> Value {
    let mut value =
        json!({"target": "public-check", "project": "certificate-check", "accessProfiles": {}});
    if !public_check.is_null() {
        value["publicCheck"] = public_check;
    }
    value
}

fn read_authority(value: &Value) -> Result<(), Vec<String>> {
    let mut document = value.clone();
    document["apiVersion"] = json!(target::AUTHORITY_API_VERSION);
    document["kind"] = json!(target::AUTHORITY_KIND);
    target::read_authority(
        "authority.yaml",
        document.to_string().as_bytes(),
        &project_with(|_| {}),
    )
    .map(|_| ())
    .map_err(|report| {
        report
            .diagnostics()
            .iter()
            .map(|d| d.code.to_string())
            .collect()
    })
}

#[test]
fn an_empty_profile_authority_with_an_activation_is_accepted_and_compiled() {
    let value = authority_value(json!({"definition": DEFINITION}));
    read_authority(&value).unwrap();
    let project = project_with(|_| {});
    let authority: target::EvidenceTargetAuthority = serde_json::from_value(value).unwrap();
    let compiled = target::compile_authority(&authority, &project).unwrap();
    assert_eq!(compiled["accessProfiles"], json!({}));
    assert_eq!(
        compiled["publicCheck"],
        json!({"requirement": "urn:example:requirement:certificate-status:v1"})
    );
}

#[test]
fn an_authority_without_an_activation_compiles_without_the_member() {
    let authority: target::EvidenceTargetAuthority =
        serde_json::from_value(authority_value(Value::Null)).unwrap();
    let compiled = target::compile_authority(&authority, &project_with(|_| {})).unwrap();
    assert!(compiled.get("publicCheck").is_none());
}

#[test]
fn activating_an_unknown_definition_is_refused() {
    let errors = read_authority(&authority_value(
        json!({"definition": "no-such-definition"}),
    ))
    .unwrap_err();
    assert!(
        errors
            .iter()
            .any(|code| code == "evidence.authority.public-check"),
        "{errors:?}"
    );
}

#[test]
fn activating_a_definition_that_declares_no_public_check_is_refused() {
    let project = project_with(|d| {
        d.as_object_mut().unwrap().remove("publicCheck");
    });
    let authority: target::EvidenceTargetAuthority =
        serde_json::from_value(authority_value(json!({"definition": DEFINITION}))).unwrap();
    let findings = target::validate_authority(&authority, &project);
    assert_eq!(codes(&findings), ["authority-public-check"], "{findings:?}");
}

#[test]
fn the_activation_names_exactly_one_definition_and_nothing_else() {
    for member in [
        json!({"definition": DEFINITION, "extra": 1}),
        json!({}),
        json!([{"definition": DEFINITION}]),
    ] {
        let value = authority_value(member);
        assert!(serde_json::from_value::<target::EvidenceTargetAuthority>(value).is_err());
    }
}

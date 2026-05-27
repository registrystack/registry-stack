// SPDX-License-Identifier: Apache-2.0

use registry_manifest_core::{
    compile_manifest, render_base_dcat, render_breg_dcat_ap, render_catalog, render_cpsv_ap,
    render_dataset_policy_document, render_dcat_profile, render_entity_schema_draft_2020_12,
    render_entity_shacl, render_form_schema_draft_2020_12, render_ogc_records_items,
    render_policy_collection, render_shacl, validate_manifest, MetadataError, MetadataManifest,
};
use serde_json::{json, Value};

#[test]
fn as_needed_update_frequency_maps_to_eu_as_needed_iri() {
    let manifest: MetadataManifest = serde_yml::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: as-needed-freq
  base_url: https://data.example.test
  title: As Needed Frequency
  publisher:
    name: Publisher
  application_profiles:
    - id: bregdcat-ap
      version: "3.0.0"
datasets:
  - id: dataset
    title: Dataset
    update_frequency: as_needed
    entities: []
codelists: []
"#,
    )
    .expect("manifest parses");

    let compiled = compile_manifest(&manifest).expect("compile");
    let breg = render_breg_dcat_ap(&compiled);
    assert_eq!(
        breg["dcat:dataset"][0]["dcterms:accrualPeriodicity"],
        json!("http://publications.europa.eu/resource/authority/frequency/AS_NEEDED"),
        "as_needed update frequency must map to EU frequency/AS_NEEDED, not UNKNOWN"
    );
}

fn fixture(path: &str) -> MetadataManifest {
    let raw = match path {
        "example-civil-registration" => EXAMPLE_CIVIL_REGISTRATION_FIXTURE,
        "example-social-benefits" => EXAMPLE_SOCIAL_BENEFITS_FIXTURE,
        "example-person-schema" => EXAMPLE_PERSON_SCHEMA_FIXTURE,
        "example-benefits-sync" => EXAMPLE_BENEFITS_SYNC_FIXTURE,
        other => panic!("unknown fixture: {other}"),
    };
    serde_yml::from_str(raw).expect("fixture parses")
}

fn service_first_fixture() -> MetadataManifest {
    serde_yml::from_str(include_str!(
        "../../../fixtures/cpsv-ap/health-linked-child-support.metadata.yaml"
    ))
    .expect("service-first fixture parses")
}

fn assert_matches_golden(label: &str, actual: &Value, expected: &str) {
    let expected: Value = serde_json::from_str(expected).expect("golden fixture parses");
    assert_eq!(actual, &expected, "{label} golden fixture mismatch");
}

#[test]
fn cpsv_ap_service_first_fixture_matches_contract_golden() {
    let compiled = compile_manifest(&service_first_fixture()).expect("compile");
    let cpsv = render_cpsv_ap(&compiled);

    assert_matches_golden(
        "CPSV-AP service-first fixture",
        &cpsv,
        include_str!("../../../fixtures/cpsv-ap/health-linked-child-support.cpsv-ap.jsonld"),
    );
    assert!(serde_json::to_string(&cpsv)
        .expect("json serializes")
        .find("cv:hasInputType")
        .is_none());
    assert_eq!(
        cpsv["@context"]["registry_manifest"],
        json!("https://registry-manifest.dev/ns/v1#")
    );

    let graph = cpsv["@graph"].as_array().expect("@graph");
    assert_eq!(
        cpsv["dcterms:hasPart"][0]["@id"],
        "https://child-support.example.gov/services/health-linked-child-support"
    );
    assert!(
        cpsv["dcat:service"]
            .as_array()
            .expect("catalog data services")
            .iter()
            .all(|service| service["@id"]
                != "https://child-support.example.gov/services/health-linked-child-support"),
        "dcat:service must point to dcat:DataService resources, not CPSV public services"
    );
    let service = graph
        .iter()
        .find(|node| {
            node["@id"] == "https://child-support.example.gov/services/health-linked-child-support"
        })
        .expect("service node");
    assert_eq!(service["@type"], "cpsv:PublicService");
    assert_eq!(
        service["cv:hasChannel"][0]["@id"],
        "https://child-support.example.gov/services/health-linked-child-support/channels/online-application"
    );
    assert_eq!(
        service["cv:holdsRequirement"][0]["@id"],
        "https://child-support.example.gov/requirements/child-health-coverage"
    );
    let grouped_list = graph
        .iter()
        .find(|node| {
            node["@id"]
                == "https://child-support.example.gov/requirements/child-health-coverage#coverage-and-residence"
        })
        .expect("grouped evidence type list");
    assert_eq!(grouped_list["@type"], "cccev:EvidenceTypeList");
    assert_eq!(
        grouped_list["cccev:specifiesEvidenceType"]
            .as_array()
            .expect("specified evidence types")
            .len(),
        2,
        "one CCCEV evidence type list must preserve the grouped AND bundle"
    );
    let alternative_list = graph
        .iter()
        .find(|node| {
            node["@id"]
                == "https://child-support.example.gov/requirements/child-health-coverage#combined-support-record"
        })
        .expect("alternative evidence type list");
    assert_eq!(
        alternative_list["cccev:specifiesEvidenceType"][0]["@id"],
        "https://child-support.example.gov/evidence-types/combined-support-record"
    );

    assert!(graph.iter().any(|node| {
        node["@id"] == "https://child-support.example.gov/authorities/child-support-authority"
            && node["@type"] == "cv:PublicOrganisation"
    }));
    assert!(graph.iter().any(|node| {
        node["@id"] == "https://child-support.example.gov/evidence-types/child-health-coverage"
            && node["@type"] == "cccev:EvidenceType"
    }));
    assert!(graph.iter().any(|node| {
        node["@id"] == "https://health.example.gov/data-services/coverage-verification"
            && node["@type"] == "dcat:DataService"
    }));
    assert!(
        graph.iter().any(|node| {
            node["@id"] == "#dataset-health-coverage" && has_json_type(node, "dcat:Dataset")
        }),
        "datasets served by rendered data services must be present in the CPSV graph"
    );
    assert!(graph.iter().any(|node| {
        node["@id"] == "https://child-support.example.gov/forms/child-support-review"
            && node["@type"]
                .as_array()
                .expect("form has type array")
                .iter()
                .any(|kind| kind == "registry_manifest:FormDefinition")
            && node["registry_manifest:validatesWithJsonSchema"]["@id"]
                == "https://child-support.example.gov/metadata/forms/child-support-review-form/schema.json"
            && node["registry_manifest:hasSection"]
                .as_array()
                .expect("form sections")
                .iter()
                .any(|section| section["registry_manifest:repeatable"] == json!(true))
    }));
    let output = graph
        .iter()
        .find(|node| node["@id"] == "#dataset-child-support-cases")
        .expect("produced output dataset");
    assert!(
        output["@type"]
            .as_array()
            .expect("output has type array")
            .iter()
            .any(|kind| kind == "cv:Output"),
        "CPSV-AP output class is in the Core Vocabularies namespace"
    );
    assert!(graph.iter().any(|node| {
        node["@id"] == "https://health.example.gov/services/health-coverage-registry"
            && node["@type"] == "cpsv:PublicService"
            && node["cpsv:produces"] == "#dataset-health-coverage"
    }));
}

fn has_json_type(node: &Value, expected: &str) -> bool {
    match node.get("@type") {
        Some(Value::String(kind)) => kind == expected,
        Some(Value::Array(kinds)) => kinds.iter().any(|kind| kind.as_str() == Some(expected)),
        _ => false,
    }
}

#[test]
fn form_profile_renders_validation_sections_and_schema() {
    let compiled = compile_manifest(&service_first_fixture()).expect("compile");
    let schema = render_form_schema_draft_2020_12(&compiled, "child-support-review-form")
        .expect("form schema renders");

    assert_eq!(
        schema["$id"],
        "https://child-support.example.gov/metadata/forms/child-support-review-form/schema.json"
    );
    assert!(schema["required"]
        .as_array()
        .expect("required")
        .iter()
        .any(|field| field == "supportType"));
    assert_eq!(schema["properties"]["children"]["type"], "array");
    assert_eq!(schema["properties"]["children"]["minItems"], 1);
    assert_eq!(
        schema["properties"]["children"]["items"]["properties"]["childBirthDate"]["format"],
        "date"
    );
}

#[test]
fn validation_rejects_invalid_form_profile_references() {
    let mut manifest = service_first_fixture();
    let form = &mut manifest.forms[0];
    form.validates_with
        .as_mut()
        .expect("fixture validation refs")
        .json_schema = Some("missing-prefix:schema".to_string());
    form.sections[0].fields[0].supports_requirement = Some("missing-requirement".to_string());

    let error = validate_manifest(&manifest).expect_err("invalid form profile rejected");
    match error {
        MetadataError::Validation { errors } => {
            assert!(errors
                .iter()
                .any(|error| error.path == "forms[0].validates_with.json_schema"));
            assert!(errors.iter().any(|error| error
                .path
                .ends_with("sections[0].fields[0].supports_requirement")));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn validation_rejects_service_forms_owned_by_another_service() {
    let mut manifest = service_first_fixture();
    let first = manifest.public_services[0].clone();
    let mut second = first.clone();
    second.id = "other-service".to_string();
    second.iri = Some("https://child-support.example.gov/services/other".to_string());
    second.forms = first.forms.clone();
    manifest.public_services.push(second);

    let error = validate_manifest(&manifest).expect_err("mismatched form owner rejected");
    match error {
        MetadataError::Validation { errors } => assert!(errors.iter().any(|error| {
            error.path == "public_services[1].forms[0]"
                && error
                    .message
                    .contains("forms owned by the same public service")
        })),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn validation_requires_public_service_description() {
    let mut manifest = service_first_fixture();
    manifest.public_services[0].description = None;

    let error = validate_manifest(&manifest).expect_err("missing service description rejected");
    match error {
        MetadataError::Validation { errors } => assert!(errors.iter().any(|error| {
            error.path == "public_services[0].description"
                && error.message.contains("description is required")
        })),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn validates_profile_fixtures() {
    for path in [
        "example-civil-registration",
        "example-social-benefits",
        "example-person-schema",
        "example-benefits-sync",
    ] {
        validate_manifest(&fixture(path)).unwrap_or_else(|error| panic!("{path}: {error:?}"));
    }
}

#[test]
fn validation_reports_manifest_errors() {
    let mut manifest = fixture("example-civil-registration");
    manifest.catalog.base_url = "civil-registration.example.gov".to_string();
    manifest.datasets[0].entities[0].fields[0].name = "PersonId".to_string();
    manifest.datasets[0].entities[0].fields[2].codelist = Some("missing".to_string());
    manifest
        .catalog
        .application_profiles
        .push(registry_manifest_core::ApplicationProfile {
            id: "not-supported".to_string(),
            version: "1".to_string(),
        });
    manifest.datasets[0].entities[0].relationships.push(
        registry_manifest_core::RelationshipManifest {
            name: "bad_relationship".to_string(),
            target_entity: Some("vital_event".to_string()),
            target: None,
            cardinality: Some("sometimes".to_string()),
            role: None,
            concept_uri: None,
        },
    );

    let err = validate_manifest(&manifest).expect_err("manifest should fail validation");
    let MetadataError::Validation { errors } = err else {
        panic!("expected validation errors");
    };
    assert!(errors.iter().any(|error| error.path == "catalog.base_url"));
    assert!(errors
        .iter()
        .any(|error| error.path.ends_with("entities[0].fields[0].name")));
    assert!(errors
        .iter()
        .any(|error| error.path.ends_with("entities[0].fields[2].codelist")));
    assert!(errors
        .iter()
        .any(|error| error.path == "catalog.application_profiles[1].id"));
    assert!(errors
        .iter()
        .any(|error| error.path.ends_with("relationships[0].cardinality")));
}

#[test]
fn validation_rejects_duplicate_entities() {
    let mut manifest = fixture("example-civil-registration");
    let duplicate = manifest.datasets[0].entities[0].clone();
    manifest.datasets[0].entities.push(duplicate);

    let err = validate_manifest(&manifest).expect_err("duplicate entity should fail validation");
    let MetadataError::Validation { errors } = err else {
        panic!("expected validation errors");
    };
    assert!(errors
        .iter()
        .any(|error| error.path.ends_with("entities[2].name")));
}

#[test]
fn validation_rejects_duplicate_evidence_offering_ids_globally() {
    let manifest: MetadataManifest = serde_yml::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: duplicate-offerings
  base_url: https://data.example.test
  title: Duplicate Offerings
  publisher:
    name: Example Authority
requirements:
  - id: requirement
    iri: https://data.example.test/requirements/example
    title: Example requirement
evidence_types:
  - id: evidence
    iri: https://data.example.test/evidence-types/example
    title: Example evidence
    proves: [requirement]
datasets:
  - id: first
    title: First
    entities:
      - name: person
        fields:
          - name: id
            type: string
    evidence_offerings:
      - id: duplicate_evidence
        title: First evidence
        evidence_type: evidence
        issuing_authority:
          id: authority
          name: Authority
          country: ZZ
        entity: person
        lookup_keys: [id]
        access:
          kind: registry-relay-verification
          ruleset: exact
  - id: second
    title: Second
    entities:
      - name: person
        fields:
          - name: id
            type: string
    evidence_offerings:
      - id: duplicate_evidence
        title: Second evidence
        evidence_type: evidence
        issuing_authority:
          id: authority
          name: Authority
          country: ZZ
        entity: person
        lookup_keys: [id]
        access:
          kind: registry-relay-verification
          ruleset: exact
"#,
    )
    .expect("manifest parses");

    let err = validate_manifest(&manifest).expect_err("duplicate offering should fail validation");
    let MetadataError::Validation { errors } = err else {
        panic!("expected validation errors");
    };
    assert!(errors.iter().any(|error| {
        error.path.ends_with("datasets[1].evidence_offerings[0].id")
            && error.message.contains("unique globally")
    }));
}

#[test]
fn validation_rejects_blank_issuing_authority_country() {
    let manifest: MetadataManifest = serde_yml::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: blank-country
  base_url: https://data.example.test
  title: Blank Country
  publisher:
    name: Example Authority
requirements:
  - id: requirement
    iri: https://data.example.test/requirements/example
    title: Example requirement
evidence_types:
  - id: evidence
    iri: https://data.example.test/evidence-types/example
    title: Example evidence
    proves: [requirement]
datasets:
  - id: first
    title: First
    entities:
      - name: person
        fields:
          - name: id
            type: string
    evidence_offerings:
      - id: person_evidence
        title: Person evidence
        evidence_type: evidence
        issuing_authority:
          id: authority
          name: Authority
          country: ""
        entity: person
        lookup_keys: [id]
        access:
          kind: registry-relay-verification
          ruleset: exact
"#,
    )
    .expect("manifest parses");

    let err = validate_manifest(&manifest).expect_err("blank country should fail validation");
    let MetadataError::Validation { errors } = err else {
        panic!("expected validation errors");
    };
    assert!(errors.iter().any(|error| {
        error
            .path
            .ends_with("evidence_offerings[0].issuing_authority.country")
    }));
}

#[test]
fn validation_allows_portable_evidence_access_kinds() {
    let manifest: MetadataManifest = serde_yml::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: portable-access-kind
  base_url: https://data.example.test
  title: Portable Access Kind
  publisher:
    name: Example Authority
requirements:
  - id: requirement
    iri: https://data.example.test/requirements/example
    title: Example requirement
evidence_types:
  - id: evidence
    iri: https://data.example.test/evidence-types/example
    title: Example evidence
    proves: [requirement]
datasets:
  - id: first
    title: First
    entities:
      - name: person
        fields:
          - name: id
            type: string
    evidence_offerings:
      - id: person_evidence
        title: Person evidence
        evidence_type: evidence
        issuing_authority:
          id: authority
          name: Authority
        entity: person
        lookup_keys: [id]
        access:
          kind: partner-api
          ruleset: exact
"#,
    )
    .expect("manifest parses");

    validate_manifest(&manifest).expect("portable access kind validates");
}

#[test]
fn evidence_server_offerings_publish_endpoint_metadata() {
    let manifest: MetadataManifest = serde_yml::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: evidence-discovery
  base_url: https://registry.example.test
  title: Evidence Discovery
  publisher:
    name: Example Authority
requirements:
  - id: smallholder_requirement
    iri: https://registry.example.test/requirements/smallholder
    title: Smallholder requirement
evidence_types:
  - id: smallholder_evidence
    iri: https://registry.example.test/evidence-types/smallholder
    title: Smallholder evidence
    proves: [smallholder_requirement]
datasets:
  - id: farmers
    title: Farmers
    evidence_offerings:
      - id: smallholder_evidence_service
        title: Smallholder evidence service
        evidence_type: smallholder_evidence
        issuing_authority:
          id: agriculture
          name: Ministry of Agriculture
        entity: farmer
        lookup_keys: [national_id]
        access:
          kind: evidence-server
          conforms_to: registry_relay:evidence-server-v1
          endpoint_url: https://evidence.example.test
          discovery_url: https://evidence.example.test/.well-known/evidence-service
          ruleset: smallholder-v1
    entities:
      - name: farmer
        fields:
          - name: national_id
            type: string
"#,
    )
    .expect("manifest parses");

    validate_manifest(&manifest).expect("manifest validates");
    let compiled = compile_manifest(&manifest).expect("manifest compiles");
    let catalog = render_catalog(&compiled);
    assert_eq!(
        catalog["evidence_offerings"][0]["access"]["endpoint_url"],
        json!("https://evidence.example.test")
    );

    let dcat = render_breg_dcat_ap(&compiled);
    let offering = dcat["@graph"]
        .as_array()
        .expect("graph is an array")
        .iter()
        .find(|node| node["dcterms:identifier"] == "smallholder_evidence_service")
        .expect("offering node exists");
    assert_eq!(
        offering["registry_manifest:evidenceService"]["dcat:endpointURL"],
        json!("https://evidence.example.test")
    );

    // Blocker 3: servesEntity IRI must not contain more than one '#' (RFC 3986 §3.5).
    // The base IRI is "#dataset-farmers" which already has '#'; appending "#entity-farmer"
    // creates an invalid double-fragment IRI. The separator must switch to '-' instead.
    let serves_entity = offering["registry_manifest:servesEntity"]
        .as_str()
        .expect("registry_manifest:servesEntity is a string");
    let fragment_count = serves_entity.chars().filter(|&c| c == '#').count();
    assert_eq!(
        fragment_count,
        1,
        "registry_manifest:servesEntity must contain exactly one '#' per RFC 3986 §3.5; got: {serves_entity}"
    );
    assert!(
        serves_entity.contains("entity-farmer"),
        "registry_manifest:servesEntity must still reference the entity name; got: {serves_entity}"
    );
}

fn federated_evaluation_manifest() -> MetadataManifest {
    serde_yml::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: federated-evaluation
  base_url: https://registry.example.test
  title: Federated Evaluation
  publisher:
    name: Example Registry
federation:
  node_id: did:web:registry.example.test
  issuer: https://registry.example.test
  jwks_uri: https://registry.example.test/.well-known/jwks.json
  federation_api: https://registry.example.test/federation
  supported_protocol_versions:
    - registry-witness-federation/v0.1
evaluation_profiles:
  - id: age_eligibility_profile
    ruleset: age-eligibility-v1
    claim_id: age_eligibility
    subject_id_type: national_id
    max_source_observed_age_seconds: 86400
requirements:
  - id: age_requirement
    title: Age requirement
evidence_types:
  - id: age_evidence
    title: Age evidence
    proves: [age_requirement]
datasets:
  - id: residents
    title: Residents
    evidence_offerings:
      - id: age_witness
        title: Age witness
        evidence_type: age_evidence
        issuing_authority:
          id: civil_registry
          name: Civil Registry
        entity: resident
        lookup_keys: [national_id]
        access:
          kind: registry-witness
          conforms_to: registry-witness-federation/v0.1
          endpoint_url: https://witness.example.test/evaluate
          discovery_url: https://witness.example.test/.well-known/registry-witness
          ruleset: age-eligibility-v1
    entities:
      - name: resident
        fields:
          - name: national_id
            type: string
"#,
    )
    .expect("federated evaluation manifest parses")
}

#[test]
fn federated_evaluation_manifest_validates_and_renders_catalog_fields() {
    let manifest = federated_evaluation_manifest();

    validate_manifest(&manifest).expect("federated manifest validates");
    let compiled = compile_manifest(&manifest).expect("federated manifest compiles");
    let catalog = render_catalog(&compiled);

    assert_eq!(
        catalog["federation"]["supported_protocol_versions"][0],
        json!("registry-witness-federation/v0.1")
    );
    assert_eq!(
        catalog["evaluation_profiles"][0]["id"],
        json!("age_eligibility_profile")
    );
    assert_eq!(
        catalog["evidence_offerings"][0]["access"]["ruleset"],
        json!("age-eligibility-v1")
    );
}

#[test]
fn validation_rejects_registry_witness_unresolved_ruleset() {
    let mut manifest = federated_evaluation_manifest();
    manifest.datasets[0].evidence_offerings[0].access.ruleset = "missing_profile".to_string();

    let error = validate_manifest(&manifest).expect_err("unresolved ruleset rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(errors.iter().any(|error| {
        error.path == "datasets[0].evidence_offerings[0].access.ruleset"
            && error
                .message
                .contains("must reference a known evaluation profile")
    }));
}

#[test]
fn validation_rejects_registry_witness_bad_conforms_to() {
    let mut manifest = federated_evaluation_manifest();
    manifest.datasets[0].evidence_offerings[0]
        .access
        .conforms_to = Some("registry_relay:evidence-server-v1".to_string());

    let error = validate_manifest(&manifest).expect_err("bad protocol rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(errors.iter().any(|error| {
        error.path == "datasets[0].evidence_offerings[0].access.conforms_to"
            && error.message.contains("registry-witness-federation/v0.1")
    }));
}

#[test]
fn validation_rejects_duplicate_evaluation_profile_ids() {
    let mut manifest = federated_evaluation_manifest();
    manifest
        .evaluation_profiles
        .push(manifest.evaluation_profiles[0].clone());

    let error = validate_manifest(&manifest).expect_err("duplicate profile rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(errors.iter().any(|error| {
        error.path == "evaluation_profiles[1].id"
            && error
                .message
                .contains("evaluation profile id must be unique")
    }));
}

#[test]
fn validation_rejects_invalid_federation_urls_and_did_web_binding() {
    let mut manifest = federated_evaluation_manifest();
    let federation = manifest.federation.as_mut().expect("federation");
    federation.issuer = "http://registry.example.test".to_string();
    federation.jwks_uri = "http://registry.example.test/.well-known/jwks.json".to_string();
    federation.federation_api = "http://registry.example.test/federation".to_string();
    federation.node_id = "did:web:other.example.test".to_string();

    let error = validate_manifest(&manifest).expect_err("bad federation rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(errors.iter().any(|error| error.path == "federation.issuer"));
    assert!(errors
        .iter()
        .any(|error| error.path == "federation.jwks_uri"));
    assert!(errors
        .iter()
        .any(|error| error.path == "federation.federation_api"));
    assert!(errors.iter().any(|error| {
        error.path == "federation.node_id"
            && error
                .message
                .contains("must bind to federation issuer host")
    }));
}

#[test]
fn policy_manifest_validates_and_renders_odrl_offer() {
    let mut manifest = fixture("example-civil-registration");
    manifest.catalog.participant_id = Some("did:web:civil-registration.example.gov".to_string());
    manifest.datasets[0].policy = Some(registry_manifest_core::DatasetPolicyManifest {
        uid: Some("https://civil-registration.example.gov/datasets/vital-events#offer".to_string()),
        assigner: Some("did:web:civil-registration.example.gov".to_string()),
        profile: vec![
            "https://civil-registration.example.gov/odrl/profile/data-sharing".to_string(),
        ],
        permissions: vec![registry_manifest_core::PolicyRuleManifest {
            action: "odrl:use".to_string(),
            target: None,
            assignee: None,
            constraints: vec![
                registry_manifest_core::PolicyConstraintManifest {
                    left_operand: "odrl:purpose".to_string(),
                    operator: "odrl:isA".to_string(),
                    right_operand: registry_manifest_core::PolicyOperandValue {
                        iri: Some(
                            "https://civil-registration.example.gov/purpose/service-delivery"
                                .to_string(),
                        ),
                        value: None,
                    },
                    unit: None,
                    datatype: None,
                },
                registry_manifest_core::PolicyConstraintManifest {
                    left_operand: "odrl:count".to_string(),
                    operator: "odrl:lteq".to_string(),
                    right_operand: registry_manifest_core::PolicyOperandValue {
                        iri: None,
                        value: Some("10".to_string()),
                    },
                    unit: None,
                    datatype: None,
                },
            ],
            duties: vec![registry_manifest_core::PolicyDutyManifest {
                action: "odrl:attribute".to_string(),
                target: None,
                assignee: None,
                constraints: Vec::new(),
            }],
        }],
        prohibitions: vec![registry_manifest_core::PolicyRuleManifest {
            action: "odrl:sell".to_string(),
            target: None,
            assignee: None,
            constraints: Vec::new(),
            duties: Vec::new(),
        }],
        obligations: Vec::new(),
    });

    validate_manifest(&manifest).expect("policy validates");
    let compiled = compile_manifest(&manifest).expect("compile");
    let dcat = render_base_dcat(&compiled);
    let policy = &dcat["dcat:dataset"][0]["odrl:hasPolicy"];

    assert_eq!(policy["@type"], json!("odrl:Offer"));
    assert_eq!(
        policy["odrl:uid"],
        json!("https://civil-registration.example.gov/datasets/vital-events#offer")
    );
    assert_eq!(
        policy["odrl:assigner"]["@id"],
        json!("did:web:civil-registration.example.gov")
    );
    assert!(policy["odrl:profile"].is_array());
    assert_eq!(
        policy["odrl:permission"][0]["odrl:target"]["@id"],
        json!("#dataset-vital-events")
    );
    assert_eq!(
        policy["odrl:permission"][0]["odrl:action"]["@id"],
        json!("odrl:use")
    );
    assert_eq!(
        policy["odrl:permission"][0]["odrl:constraint"][0]["odrl:leftOperand"]["@id"],
        json!("odrl:purpose")
    );
    assert!(
        dcat["@context"].get("odrl:rightOperand").is_none(),
        "rightOperand must not be globally coerced to @id because literal operands are valid"
    );
    assert_eq!(
        policy["odrl:permission"][0]["odrl:constraint"][1]["odrl:rightOperand"],
        json!("10")
    );
    assert_eq!(
        policy["odrl:permission"][0]["odrl:duty"][0]["odrl:action"]["@id"],
        json!("odrl:attribute")
    );
    assert_eq!(
        policy["odrl:prohibition"][0]["odrl:action"]["@id"],
        json!("odrl:sell")
    );
    assert!(policy.get("odrl:obligation").is_none());
}

#[test]
fn default_policy_is_minimal_and_deterministic() {
    let compiled = compile_manifest(&fixture("example-civil-registration")).expect("compile");
    let dcat = render_base_dcat(&compiled);
    let policy = &dcat["dcat:dataset"][0]["odrl:hasPolicy"];

    assert_eq!(policy["@id"], json!("#policy-vital-events-offer"));
    assert_eq!(policy["odrl:permission"].as_array().unwrap().len(), 1);
    let permission = &policy["odrl:permission"][0];
    assert_eq!(permission["odrl:action"]["@id"], json!("odrl:use"));
    assert_eq!(
        permission["odrl:target"]["@id"],
        json!("#dataset-vital-events")
    );
    assert!(permission.get("odrl:assignee").is_none());
    assert!(permission.get("odrl:constraint").is_none());
    assert!(permission.get("odrl:duty").is_none());
    assert!(policy.get("odrl:prohibition").is_none());
}

#[test]
fn policy_documents_are_dataset_scoped_json_ld() {
    let compiled = compile_manifest(&fixture("example-civil-registration")).expect("compile");

    let collection = render_policy_collection(&compiled);
    assert_eq!(
        collection["@id"],
        json!("https://civil-registration.example.gov/metadata/policies")
    );
    assert_eq!(
        collection["@context"]["odrl"],
        json!("http://www.w3.org/ns/odrl/2/")
    );
    assert_eq!(collection["@graph"].as_array().expect("graph").len(), 1);
    assert_eq!(
        collection["@graph"][0]["odrl:permission"][0]["odrl:target"]["@id"],
        json!("#dataset-vital-events")
    );

    let policy =
        render_dataset_policy_document(&compiled, "vital-events").expect("dataset policy renders");
    assert_eq!(policy["@id"], json!("#policy-vital-events-offer"));
    assert_eq!(policy["@type"], json!("odrl:Offer"));
    assert!(render_dataset_policy_document(&compiled, "missing").is_none());
}

#[test]
fn policy_validation_rejects_ambiguous_or_textual_terms() {
    let mut manifest = fixture("example-civil-registration");
    manifest.datasets[0].policy = Some(registry_manifest_core::DatasetPolicyManifest {
        uid: Some("ftp://example.gov/policy".to_string()),
        assigner: Some("did:web:civil-registration.example.gov".to_string()),
        profile: Vec::new(),
        permissions: vec![registry_manifest_core::PolicyRuleManifest {
            action: "use".to_string(),
            target: None,
            assignee: None,
            constraints: vec![registry_manifest_core::PolicyConstraintManifest {
                left_operand: "odrl:purpose".to_string(),
                operator: "odrl:isA".to_string(),
                right_operand: registry_manifest_core::PolicyOperandValue {
                    iri: None,
                    value: Some("service delivery".to_string()),
                },
                unit: None,
                datatype: None,
            }],
            duties: vec![registry_manifest_core::PolicyDutyManifest {
                action: "attribute".to_string(),
                target: None,
                assignee: None,
                constraints: Vec::new(),
            }],
        }],
        prohibitions: Vec::new(),
        obligations: vec![registry_manifest_core::PolicyDutyManifest {
            action: "odrl:reviewPolicy".to_string(),
            target: None,
            assignee: None,
            constraints: Vec::new(),
        }],
    });

    let err = validate_manifest(&manifest).expect_err("policy should fail validation");
    let MetadataError::Validation { errors } = err else {
        panic!("expected validation errors");
    };
    assert!(errors
        .iter()
        .any(|error| error.path == "datasets[0].policy.uid"));
    assert!(errors
        .iter()
        .any(|error| error.path == "datasets[0].policy.permissions[0].action"));
    assert!(errors.iter().any(|error| {
        error.path == "datasets[0].policy.permissions[0].constraints[0].right_operand"
    }));
    assert!(errors
        .iter()
        .any(|error| error.path == "datasets[0].policy.permissions[0].duties[0].action"));
    assert!(errors
        .iter()
        .any(|error| error.path == "datasets[0].policy.obligations"));
}

#[test]
fn compile_expands_vocabularies_and_codelist_schemes() {
    let compiled = compile_manifest(&fixture("example-civil-registration")).expect("compile");
    let catalog = render_catalog(&compiled);

    assert_matches_golden(
        "catalog",
        &catalog,
        include_str!("fixtures/golden/example-civil-registration.catalog.json"),
    );
    assert_eq!(catalog["id"], json!("example-civil-registration"));
    assert_eq!(
        catalog["profiles"],
        json!([{ "id": "example-civil-registration", "version": "1" }])
    );
    let fields = catalog["datasets"][0]["entities"][0]["fields"]
        .as_array()
        .expect("fields");
    let person_id = fields
        .iter()
        .find(|field| field["name"] == "person_id")
        .expect("person_id field");
    let sex = fields
        .iter()
        .find(|field| field["name"] == "sex")
        .expect("sex field");
    assert_eq!(
        person_id["concepts"][0],
        json!("https://person-schema.example.gov/vocab/Person.identifier")
    );
    assert_eq!(
        sex["codelist_scheme_iri"],
        json!("https://civil-registration.example.gov/codelists/sex")
    );
}

#[test]
fn dcat_profiles_render_separate_artifacts() {
    let compiled = compile_manifest(&fixture("example-civil-registration")).expect("compile");
    let base = render_base_dcat(&compiled);
    let breg = render_breg_dcat_ap(&compiled);

    assert_matches_golden(
        "base DCAT",
        &base,
        include_str!("fixtures/golden/example-civil-registration.base-dcat.json"),
    );
    assert_matches_golden(
        "BRegDCAT-AP",
        &breg,
        include_str!("fixtures/golden/example-civil-registration.breg-dcat-ap.json"),
    );
    assert_eq!(base["@type"], json!("dcat:Catalog"));
    assert!(base.get("sh:shapesGraph").is_none());
    assert_eq!(
        breg["@id"],
        json!("https://civil-registration.example.gov/metadata/dcat.bregdcat-ap.jsonld")
    );
    assert_eq!(
        base["dcterms:identifier"],
        json!("example-civil-registration")
    );
    assert_eq!(
        breg["dcterms:identifier"],
        json!("example-civil-registration")
    );
    let included = breg["@included"].as_array().expect("@included");
    let standard_ids = included
        .iter()
        .filter(|node| node["@type"] == "dcterms:Standard")
        .map(|node| node["@id"].as_str().expect("standard id"))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        included
            .iter()
            .filter(|node| node["@type"] == "dcterms:Standard")
            .count(),
        standard_ids.len(),
        "conformsTo standard nodes must not be duplicated when BReg builds on base DCAT"
    );
    assert!(included.iter().any(|node| {
        node["@id"] == "https://semiceu.github.io/BRegDCAT-AP/releases/3.0.0/"
            && node["@type"] == "dcterms:Standard"
    }));
    assert!(
        !standard_ids.contains("https://spec.openapis.org/oas/v3.1.0"),
        "OpenAPI conformance must only appear when an API artifact is explicitly modeled"
    );
    assert!(
        base["dcat:dataset"][0].get("dcat:distribution").is_none(),
        "base DCAT must not synthesize entity REST distributions"
    );
    assert_eq!(
        render_dcat_profile(&compiled, "bregdcat-ap").unwrap()["@id"],
        breg["@id"]
    );
}

#[test]
fn breg_dcat_emits_standard_public_service_evidence_without_source_truth_claims() {
    let mut manifest = fixture("example-civil-registration");
    manifest.datasets[0].applicable_legislation =
        vec!["http://data.europa.eu/eli/reg/2024/1/oj".to_string()];
    manifest.datasets[0].public_services = vec![registry_manifest_core::PublicServiceManifest {
        id: Some("civil-registration-service".to_string()),
        title: registry_manifest_core::LocalizedText::Plain("Civil registration".to_string()),
        description: Some(registry_manifest_core::LocalizedText::Plain(
            "Public service producing civil registration data".to_string(),
        )),
    }];
    let compiled = compile_manifest(&manifest).expect("compile");
    let breg = render_breg_dcat_ap(&compiled);
    let dataset = &breg["dcat:dataset"][0];

    assert_eq!(
        dataset["dcatap:applicableLegislation"],
        json!(["http://data.europa.eu/eli/reg/2024/1/oj"])
    );
    assert_eq!(
        breg["@context"]["cpsv"],
        json!("http://purl.org/vocab/cpsv#")
    );
    let included = breg["@included"].as_array().expect("@included");
    let service = included
        .iter()
        .find(|node| node["@type"] == "cpsv:PublicService")
        .expect("public service node");
    assert_eq!(service["@id"], json!("civil-registration-service"));
    assert_eq!(service["dcterms:title"], json!("Civil registration"));
    assert_eq!(service["cpsv:produces"], json!("#dataset-vital-events"));
    assert!(
        service["registry_manifest:sourceOfTruth"].is_null(),
        "Registry Relay publishes standard CPSV evidence, not an authority verdict"
    );
}

#[test]
fn shacl_uses_standard_constraint_slots() {
    let compiled = compile_manifest(&fixture("example-civil-registration")).expect("compile");
    let shape = render_entity_shacl(&compiled, "vital-events", "person").expect("shape");
    let properties = shape["shape"]["sh:property"]
        .as_array()
        .expect("properties");
    let person_id = properties
        .iter()
        .find(|property| property["sh:name"] == "person_id")
        .expect("person_id property");
    let sex = properties
        .iter()
        .find(|property| property["sh:name"] == "sex")
        .expect("sex property");

    assert_eq!(person_id["sh:minLength"], json!(1));
    assert_eq!(person_id["sh:maxLength"], json!(64));
    assert_eq!(person_id["sh:pattern"], json!("^[A-Za-z0-9-]+$"));
    assert_eq!(
        sex["skos:inScheme"],
        json!("https://civil-registration.example.gov/codelists/sex")
    );
    let shacl = render_shacl(&compiled);
    assert_matches_golden(
        "SHACL",
        &shacl,
        include_str!("fixtures/golden/example-civil-registration.shacl.json"),
    );
    let graph = shacl["@graph"].as_array().unwrap().clone();
    assert!(graph.iter().any(|node| {
        node["@type"] == "skos:ConceptScheme"
            && node["@id"] == "https://civil-registration.example.gov/codelists/sex"
            && node["rdfs:seeAlso"] == "https://civil-registration.example.gov/codelists/sex.ttl"
    }));
}

#[test]
fn json_schema_renderer_uses_draft_2020_12_and_required_fields() {
    let compiled = compile_manifest(&fixture("example-social-benefits")).expect("compile");
    let schema =
        render_entity_schema_draft_2020_12(&compiled, "social-registry", "enrollment").unwrap();

    assert_matches_golden(
        "entity JSON Schema",
        &schema,
        include_str!("fixtures/golden/example-social-benefits.enrollment.schema.json"),
    );
    assert_eq!(
        schema["$schema"],
        json!("https://json-schema.org/draft/2020-12/schema")
    );
    assert_eq!(
        schema["$id"],
        json!("https://social-protection.example.gov/metadata/schema/social-registry/enrollment/schema.json")
    );
    assert_eq!(
        schema["required"],
        json!(["enrollment_id", "enrollment_status"])
    );
    assert_eq!(
        schema["properties"]["enrollment_status"]["enum"],
        json!(["active", "suspended", "closed"])
    );
}

#[test]
fn breg_dcat_preserves_active_adms_status() {
    let compiled = compile_manifest(&fixture("example-social-benefits")).expect("compile");
    let dcat = render_breg_dcat_ap(&compiled);
    assert_eq!(
        dcat["dcat:dataset"][0]["adms:status"],
        "http://purl.org/adms/status/Active"
    );
}

#[test]
fn breg_dcat_omits_empty_cccev_predicates_on_requirements() {
    let manifest: MetadataManifest = serde_yml::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: minimal-requirement
  base_url: https://data.example.test
  title: Minimal Requirement
  publisher:
    name: Example Authority
  application_profiles:
    - id: bregdcat-ap
      version: "3.0.0"
requirements:
  - id: bare_requirement
    iri: https://data.example.test/requirements/bare
    title: Bare requirement
    description: Requirement without information concepts or reference frameworks.
evidence_types:
  - id: bare_evidence
    iri: https://data.example.test/evidence-types/bare
    title: Bare evidence
    proves:
      - bare_requirement
datasets:
  - id: dataset
    title: Dataset
    entities:
      - name: person
        fields:
          - name: id
            type: string
"#,
    )
    .expect("manifest parses");
    let compiled = compile_manifest(&manifest).expect("compile");
    let dcat = render_breg_dcat_ap(&compiled);
    let graph = dcat["@graph"].as_array().expect("@graph");
    let requirement = graph
        .iter()
        .find(|node| node["@id"] == "https://data.example.test/requirements/bare")
        .expect("requirement node present");
    assert!(
        requirement.get("cccev:hasConcept").is_none(),
        "cccev:hasConcept must be omitted when there are no information concepts, got {requirement}"
    );
    assert!(
        requirement.get("cccev:isDerivedFrom").is_none(),
        "cccev:isDerivedFrom must be omitted when there are no reference frameworks, got {requirement}"
    );
}

#[test]
fn validation_rejects_grouped_evidence_list_that_does_not_prove_requirement() {
    let manifest: MetadataManifest = serde_yml::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: grouped-evidence-validation
  base_url: https://data.example.test
  title: Grouped Evidence Validation
  publisher:
    name: Example Authority
requirements:
  - id: target_requirement
    title: Target requirement
    evidence_type_lists:
      - id: grouped-option
        evidence_types:
          - unrelated_evidence
  - id: unrelated_requirement
    title: Unrelated requirement
evidence_types:
  - id: unrelated_evidence
    title: Unrelated evidence
    proves:
      - unrelated_requirement
"#,
    )
    .expect("manifest parses");

    let error = validate_manifest(&manifest).expect_err("invalid evidence group rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(
        errors.iter().any(|error| {
            error.path == "requirements[0].evidence_type_lists[0].evidence_types[0]"
                && error
                    .message
                    .contains("listed evidence type must prove the owning requirement")
        }),
        "expected grouped evidence validation error, got {errors:#?}"
    );
}

#[test]
fn ogc_records_items_are_link_free() {
    let compiled = compile_manifest(&fixture("example-benefits-sync")).expect("compile");
    let items = render_ogc_records_items(&compiled);

    assert_matches_golden(
        "OGC record body",
        &items,
        include_str!("fixtures/golden/example-benefits-sync.ogc-records-items.json"),
    );
    assert_eq!(items["type"], json!("FeatureCollection"));
    assert_eq!(items["features"][0]["properties"]["type"], json!("Record"));
    assert!(items.get("links").is_none());
    assert!(items["features"][0].get("links").is_none());
}

const EXAMPLE_CIVIL_REGISTRATION_FIXTURE: &str =
    include_str!("../../../profiles/example-civil-registration/fixtures/metadata.yaml");

const EXAMPLE_SOCIAL_BENEFITS_FIXTURE: &str = r#"
schema_version: registry-manifest/v1
catalog:
  id: example-social-benefits
  base_url: https://social-protection.example.gov
  title:
    en: Social Protection Metadata
  publisher:
    name: Social Protection Agency
  application_profiles:
    - id: bregdcat-ap
      version: "3.0.0"
vocabularies:
  benefits: https://social-protection.example.gov/vocab/benefits/
profiles:
  - id: example-social-benefits
    version: "1"
datasets:
  - id: social-registry
    title:
      en: Social Registry
    status: active
    access_rights: restricted
    entities:
      - name: enrollment
        title:
          en: Program Enrollment
        identifiers:
          - name: enrollment_id
            kind: local
        fields:
          - name: enrollment_id
            type: string
            required: true
          - name: enrollment_status
            type: code
            required: true
            codelist: enrollment_status
            constraints:
              in: [active, suspended, closed]
            concepts:
              - benefits:ProgramEnrollment.status
codelists:
  - id: enrollment_status
    scheme_iri: https://social-protection.example.gov/codelists/enrollment-status
    concepts:
      - code: active
      - code: suspended
      - code: closed
"#;

const EXAMPLE_PERSON_SCHEMA_FIXTURE: &str = r#"
schema_version: registry-manifest/v1
catalog:
  id: example-person-schema
  base_url: https://person-schema.example.gov
  title:
    en: Example Person Schema Metadata
  publisher:
    name: Example Person Schema Publisher
vocabularies:
  person: https://person-schema.example.gov/vocab/
profiles:
  - id: example-person-schema
    version: "1"
datasets:
  - id: person-index
    title:
      en: Person Index
    entities:
      - name: person
        identifiers:
          - name: person_id
            kind: local
        fields:
          - name: person_id
            type: string
            required: true
            concepts:
              - person:Person.identifier
codelists: []
"#;

const EXAMPLE_BENEFITS_SYNC_FIXTURE: &str = r#"
schema_version: registry-manifest/v1
catalog:
  id: example-benefits-sync
  base_url: https://dci.example.gov
  title:
    en: Example Benefits Sync Metadata
  publisher:
    name: Disability Registry Authority
  application_profiles:
    - id: bregdcat-ap
      version: "3.0.0"
vocabularies:
  sync: https://benefits-sync.example.gov/vocab/
profiles:
  - id: example-benefits-sync
    version: "1"
datasets:
  - id: disability-registry
    title:
      en: Disability Registry
    entities:
      - name: disabled_person
        identifiers:
          - name: subject_id
            kind: local
        fields:
          - name: subject_id
            type: string
            required: true
          - name: disability_status
            type: code
            required: true
            codelist: disability_status
            concepts:
              - sync:DisabilityRegistry.disabilityStatus
codelists:
  - id: disability_status
    scheme_iri: https://dci.example.gov/codelists/disability-status
    concepts:
      - code: certified
      - code: not_certified
"#;

// SPDX-License-Identifier: Apache-2.0

use registry_metadata_core::{
    compile_manifest, render_base_dcat, render_breg_dcat_ap, render_catalog,
    render_dataset_policy_document, render_dcat_profile, render_entity_schema_draft_2020_12,
    render_entity_shacl, render_ogc_records_items, render_policy_collection, render_shacl,
    validate_manifest, MetadataError, MetadataManifest,
};
use serde_json::{json, Value};

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

fn assert_matches_golden(label: &str, actual: &Value, expected: &str) {
    let expected: Value = serde_json::from_str(expected).expect("golden fixture parses");
    assert_eq!(actual, &expected, "{label} golden fixture mismatch");
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
        .push(registry_metadata_core::ApplicationProfile {
            id: "not-supported".to_string(),
            version: "1".to_string(),
        });
    manifest.datasets[0].entities[0].relationships.push(
        registry_metadata_core::RelationshipManifest {
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
schema_version: registry-metadata/v1
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
schema_version: registry-metadata/v1
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
fn policy_manifest_validates_and_renders_odrl_offer() {
    let mut manifest = fixture("example-civil-registration");
    manifest.catalog.participant_id = Some("did:web:civil-registration.example.gov".to_string());
    manifest.datasets[0].policy = Some(registry_metadata_core::DatasetPolicyManifest {
        uid: Some("https://civil-registration.example.gov/datasets/vital-events#offer".to_string()),
        assigner: Some("did:web:civil-registration.example.gov".to_string()),
        profile: vec![
            "https://civil-registration.example.gov/odrl/profile/data-sharing".to_string(),
        ],
        permissions: vec![registry_metadata_core::PolicyRuleManifest {
            action: "odrl:use".to_string(),
            target: None,
            assignee: None,
            constraints: vec![
                registry_metadata_core::PolicyConstraintManifest {
                    left_operand: "odrl:purpose".to_string(),
                    operator: "odrl:isA".to_string(),
                    right_operand: registry_metadata_core::PolicyOperandValue {
                        iri: Some(
                            "https://civil-registration.example.gov/purpose/service-delivery"
                                .to_string(),
                        ),
                        value: None,
                    },
                    unit: None,
                    datatype: None,
                },
                registry_metadata_core::PolicyConstraintManifest {
                    left_operand: "odrl:count".to_string(),
                    operator: "odrl:lteq".to_string(),
                    right_operand: registry_metadata_core::PolicyOperandValue {
                        iri: None,
                        value: Some("10".to_string()),
                    },
                    unit: None,
                    datatype: None,
                },
            ],
            duties: vec![registry_metadata_core::PolicyDutyManifest {
                action: "odrl:attribute".to_string(),
                target: None,
                assignee: None,
                constraints: Vec::new(),
            }],
        }],
        prohibitions: vec![registry_metadata_core::PolicyRuleManifest {
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
        json!("https://civil-registration.example.gov/datasets/vital-events")
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

    assert_eq!(
        policy["@id"],
        json!("https://civil-registration.example.gov/datasets/vital-events#offer")
    );
    assert_eq!(policy["odrl:permission"].as_array().unwrap().len(), 1);
    let permission = &policy["odrl:permission"][0];
    assert_eq!(permission["odrl:action"]["@id"], json!("odrl:use"));
    assert_eq!(
        permission["odrl:target"]["@id"],
        json!("https://civil-registration.example.gov/datasets/vital-events")
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
        json!("https://civil-registration.example.gov/datasets/vital-events")
    );

    let policy =
        render_dataset_policy_document(&compiled, "vital-events").expect("dataset policy renders");
    assert_eq!(
        policy["@id"],
        json!("https://civil-registration.example.gov/datasets/vital-events#offer")
    );
    assert_eq!(policy["@type"], json!("odrl:Offer"));
    assert!(render_dataset_policy_document(&compiled, "missing").is_none());
}

#[test]
fn policy_validation_rejects_ambiguous_or_textual_terms() {
    let mut manifest = fixture("example-civil-registration");
    manifest.datasets[0].policy = Some(registry_metadata_core::DatasetPolicyManifest {
        uid: Some("ftp://example.gov/policy".to_string()),
        assigner: Some("did:web:civil-registration.example.gov".to_string()),
        profile: Vec::new(),
        permissions: vec![registry_metadata_core::PolicyRuleManifest {
            action: "use".to_string(),
            target: None,
            assignee: None,
            constraints: vec![registry_metadata_core::PolicyConstraintManifest {
                left_operand: "odrl:purpose".to_string(),
                operator: "odrl:isA".to_string(),
                right_operand: registry_metadata_core::PolicyOperandValue {
                    iri: None,
                    value: Some("service delivery".to_string()),
                },
                unit: None,
                datatype: None,
            }],
            duties: vec![registry_metadata_core::PolicyDutyManifest {
                action: "attribute".to_string(),
                target: None,
                assignee: None,
                constraints: Vec::new(),
            }],
        }],
        prohibitions: Vec::new(),
        obligations: vec![registry_metadata_core::PolicyDutyManifest {
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
    assert_eq!(
        included
            .iter()
            .filter(|node| node["@type"] == "dcterms:Standard")
            .count(),
        1,
        "conformsTo standard nodes must not be duplicated when BReg builds on base DCAT"
    );
    assert!(included.iter().any(|node| {
        node["@id"] == "https://semiceu.github.io/BRegDCAT-AP/releases/3.0.0/"
            && node["@type"] == "dcterms:Standard"
    }));
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
    manifest.datasets[0].public_services = vec![registry_metadata_core::PublicServiceManifest {
        id: Some("civil-registration-service".to_string()),
        title: registry_metadata_core::LocalizedText::Plain("Civil registration".to_string()),
        description: Some(registry_metadata_core::LocalizedText::Plain(
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
        service["registry_relay:sourceOfTruth"].is_null(),
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
schema_version: registry-metadata/v1
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
schema_version: registry-metadata/v1
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
schema_version: registry-metadata/v1
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

// SPDX-License-Identifier: Apache-2.0

use registry_metadata_core::{
    compile_manifest, render_base_dcat, render_breg_dcat_ap, render_catalog, render_dcat_profile,
    render_entity_schema_draft_2020_12, render_entity_shacl, render_ogc_records_items,
    render_shacl, validate_manifest, MetadataError, MetadataManifest,
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
        breg["dspace:participantId"],
        json!("https://civil-registration.example.gov/authority")
    );
    assert_eq!(
        render_dcat_profile(&compiled, "bregdcat-ap").unwrap()["@id"],
        breg["@id"]
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

const EXAMPLE_CIVIL_REGISTRATION_FIXTURE: &str = r#"
schema_version: registry-metadata/v1
catalog:
  id: example-civil-registration
  base_url: https://civil-registration.example.gov
  title:
    en: Civil Registration Metadata
  publisher:
    name: Civil Registration Authority
    iri: https://civil-registration.example.gov/authority
    authority_type: eli:PublicAuthority
  participant_id: https://civil-registration.example.gov/authority
  conforms_to:
    - https://semiceu.github.io/BRegDCAT-AP/releases/3.0.0/
  application_profiles:
    - id: bregdcat-ap
      version: "3.0.0"
vocabularies:
  person: https://person-schema.example.gov/vocab/
  civreg: https://civil-registration.example.gov/vocab/
  eli: http://data.europa.eu/eli/ontology#
profiles:
  - id: example-civil-registration
    version: "1"
datasets:
  - id: vital-events
    title:
      en: Vital Events
    status: under_development
    access_rights: restricted
    entities:
      - name: person
        title:
          en: Person
        identifiers:
          - name: person_id
            kind: local
        fields:
          - name: person_id
            type: string
            required: true
            constraints:
              min_length: 1
              max_length: 64
              pattern: "^[A-Za-z0-9-]+$"
            concepts:
              - person:Person.identifier
          - name: birth_date
            type: date
            concepts:
              - person:Person.birthDate
              - civreg:BirthRecord.child.birthDate
          - name: sex
            type: code
            codelist: sex
            concepts:
              - person:Person.sex
      - name: vital_event
        identifiers:
          - name: event_id
            kind: local
        fields:
          - name: event_id
            type: string
            required: true
          - name: event_type
            type: code
            required: true
            codelist: vital_event_type
            constraints:
              in: [birth, death]
codelists:
  - id: sex
    scheme_iri: https://civil-registration.example.gov/codelists/sex
    external_ref: https://civil-registration.example.gov/codelists/sex.ttl
    concepts:
      - code: female
        iri: https://civil-registration.example.gov/codelists/sex/female
        label:
          en: Female
      - code: male
        iri: https://civil-registration.example.gov/codelists/sex/male
        label:
          en: Male
  - id: vital_event_type
    scheme_iri: https://civil-registration.example.gov/codelists/vital-event-type
    concepts:
      - code: birth
      - code: death
"#;

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

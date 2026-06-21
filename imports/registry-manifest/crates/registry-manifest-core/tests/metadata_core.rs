// SPDX-License-Identifier: Apache-2.0

use registry_manifest_core::{
    compile_manifest, compute_evidence_pack_policy_hash, compute_policy_hash, render_base_dcat,
    render_breg_dcat_ap, render_catalog, render_cpsv_ap, render_dataset_policy_document,
    render_dcat_profile, render_entity_schema_draft_2020_12, render_entity_shacl,
    render_evidence_offering, render_form_schema_draft_2020_12, render_ogc_records_items,
    render_policy_collection, render_shacl, validate_manifest, verify_evidence_pack_policy_hash,
    CodelistConcept, CodelistManifest, MetadataError, MetadataManifest, ProfileClaim,
    ODRL_ENFORCEMENT_PROFILE, SUPPORTED_ODRL_ENFORCEMENT_TERMS,
};
use serde_json::{json, Value};

#[test]
fn as_needed_update_frequency_maps_to_eu_as_needed_iri() {
    let manifest: MetadataManifest = serde_yaml_ng::from_str(
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
    serde_yaml_ng::from_str(raw).expect("fixture parses")
}

fn service_first_fixture() -> MetadataManifest {
    serde_yaml_ng::from_str(include_str!(
        "../../../fixtures/cpsv-ap/health-linked-child-support.metadata.yaml"
    ))
    .expect("service-first fixture parses")
}

fn assert_matches_golden(label: &str, actual: &Value, expected: &str) {
    let expected: Value = serde_json::from_str(expected).expect("golden fixture parses");
    assert_eq!(actual, &expected, "{label} golden fixture mismatch");
}

fn minimal_manifest() -> MetadataManifest {
    serde_yaml_ng::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: validation-regression
  base_url: https://registry.example.test
  title: Validation Regression
  publisher:
    name: Publisher
datasets: []
codelists: []
"#,
    )
    .expect("minimal manifest parses")
}

#[test]
fn post_beta_unknown_manifest_fields_parse_and_validate() {
    let raw = r#"
schema_version: registry-manifest/v1
x_post_beta_manifest_note: ignored by beta readers
catalog:
  id: extension-policy
  base_url: https://registry.example.test
  title: Extension Policy
  x_post_beta_catalog_hint: optional future catalog metadata
  publisher:
    name: Publisher
    x_post_beta_publisher_hint: optional future publisher metadata
requirements:
  - id: proof-of-eligibility
    title: Proof of eligibility
evidence_types:
  - id: eligibility-evidence
    title: Eligibility Evidence
    proves: [proof-of-eligibility]
datasets:
  - id: dataset
    title: Dataset
    x_post_beta_dataset_hint: optional future dataset metadata
    entities:
      - name: person
        x_post_beta_entity_hint: optional future entity metadata
        fields:
          - name: id
            type: string
            x_post_beta_field_hint: optional future field metadata
    evidence_offerings:
      - id: eligibility
        title: Eligibility
        evidence_type: eligibility-evidence
        supported_modes: [online, assisted]
        required_subject_binding: strong
        result_format: application/json
        disclosure_profile: minimal
        risk_tier: low
        issuing_authority:
          id: authority
          name: Authority
          country: ZZ
          x_post_beta_authority_hint: optional future authority metadata
        entity: person
        lookup_keys: [id]
        access:
          kind: registry-relay-verification
          ruleset: exact
          x_post_beta_access_hint: optional future access metadata
codelists: []
"#;
    let manifest: MetadataManifest =
        serde_yaml_ng::from_str(raw).expect("unknown optional fields are ignored");

    validate_manifest(&manifest).expect("manifest with unknown optional fields validates");
}

#[test]
fn runtime_only_manifest_fields_are_rejected_before_unknown_fields_are_ignored() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: runtime-only-direct-parse
  base_url: https://registry.example.test
  title: Runtime-only Direct Parse
  publisher:
    name: Publisher
datasets:
  - id: dataset
    title: Dataset
    entities:
      - name: person
        source: people_table
codelists: []
"#;
    let error = serde_yaml_ng::from_str::<MetadataManifest>(raw)
        .expect_err("runtime-only keys are rejected during manifest parsing");

    assert!(
        error.to_string().contains("runtime-only keys"),
        "unexpected parse error: {error}"
    );
    assert!(
        error.to_string().contains("source"),
        "runtime key should be named in parse error: {error}"
    );
}

#[test]
fn secret_bearing_unknown_manifest_fields_are_rejected_before_unknown_fields_are_ignored() {
    for key in [
        "client_secret",
        "password",
        "credentials",
        "api_key",
        "private_key",
        "token",
        "secret",
        "secret_key",
        "password_env",
        "client_secret_env",
        "api_key_env",
        "private_key_env",
        "access_token_env",
        "secretKey",
        "passwordEnv",
        "clientSecretEnv",
        "apiKeyEnv",
    ] {
        let raw = format!(
            r#"
schema_version: registry-manifest/v1
{key}: leaked
catalog:
  id: secret-bearing-direct-parse
  base_url: https://registry.example.test
  title: Secret-bearing Direct Parse
  publisher:
    name: Publisher
datasets: []
codelists: []
"#
        );
        let error = serde_yaml_ng::from_str::<MetadataManifest>(&raw)
            .expect_err("secret-bearing keys are rejected during manifest parsing");

        assert!(
            error.to_string().contains("secret-bearing keys"),
            "unexpected parse error for {key}: {error}"
        );
        assert!(
            error.to_string().contains(key),
            "secret-bearing key should be named in parse error for {key}: {error}"
        );
    }
}

#[test]
fn secret_bearing_extension_map_keys_are_rejected() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: secret-bearing-extension
  base_url: https://registry.example.test
  title: Secret-bearing Extension
  publisher:
    name: Publisher
evaluation_profiles:
  - id: eligibility_profile
    ruleset: eligibility-rules-v1
    claim_id: eligibility
    subject_id_type: national_id
    evidence_pack:
      source_basis:
        partnerCredentials:
          username: partner
          password: leaked
datasets: []
codelists: []
"#;
    let error = serde_yaml_ng::from_str::<MetadataManifest>(raw)
        .expect_err("secret-bearing extension keys are rejected during manifest parsing");

    assert!(
        error.to_string().contains("secret-bearing keys"),
        "unexpected parse error: {error}"
    );
    assert!(
        error.to_string().contains("partnerCredentials"),
        "extension key should be named in parse error: {error}"
    );
    assert!(
        error.to_string().contains("password"),
        "nested secret key should be named in parse error: {error}"
    );
}

#[test]
fn runtime_only_rejection_covers_representative_product_configs() {
    let cases = [
        (
            "relay",
            r#"
datasets:
  - id: civil
    title: Civil Registry
    entities:
      - name: person
        table: people
        fields: []
codelists: []
"#,
            "table",
        ),
        (
            "notary",
            r#"
datasets: []
evidence_types:
  - id: birth-record
    title: Birth Record
    source_connections:
      civil:
        base_url: http://registry-relay:8080
codelists: []
"#,
            "source_connections",
        ),
        (
            "governed",
            r#"
config_trust:
  antirollback_state_path: state/config-antirollback.json
  local_approval_state_path: state/config-approvals.json
datasets: []
codelists: []
"#,
            "config_trust",
        ),
    ];

    for (label, body, expected_key) in cases {
        let raw = format!(
            r#"
schema_version: registry-manifest/v1
catalog:
  id: runtime-only-{label}
  base_url: https://registry.example.test
  title: Runtime-only {label}
  publisher:
    name: Publisher
{body}
"#
        );
        let error = match serde_yaml_ng::from_str::<MetadataManifest>(&raw) {
            Ok(_) => panic!("{label} runtime-only config parsed"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("runtime-only keys"),
            "{label} should fail with runtime-only key error, got: {error}"
        );
        assert!(
            error.to_string().contains(expected_key),
            "{label} should name {expected_key}, got: {error}"
        );
    }
}

fn manifest_with_body(body: &str) -> MetadataManifest {
    serde_yaml_ng::from_str(&format!(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: validation-regression
  base_url: https://registry.example.test
  title: Validation Regression
  publisher:
    name: Publisher
{body}
"#
    ))
    .expect("manifest parses")
}

fn yaml_items(count: usize, mut item: impl FnMut(usize) -> String) -> String {
    (0..count).map(&mut item).collect::<Vec<_>>().join("")
}

fn yaml_uri_list(count: usize, indent: usize) -> String {
    let spaces = " ".repeat(indent);
    yaml_items(count, |index| {
        format!("{spaces}- https://example.test/terms/{index}\n")
    })
}

fn validation_errors(manifest: &MetadataManifest) -> Vec<registry_manifest_core::ValidationError> {
    let err = validate_manifest(manifest).expect_err("manifest should fail validation");
    let MetadataError::Validation { errors } = err else {
        panic!("expected validation errors");
    };
    errors
}

fn assert_has_limit_error(manifest: &MetadataManifest, path: &str, limit: usize) {
    let errors = validation_errors(manifest);
    assert!(
        errors.iter().any(|error| {
            error.path == path && error.message.contains(&format!("at most {limit} items"))
        }),
        "expected limit error at {path}; got {errors:?}"
    );
}

#[test]
fn validation_rejects_collection_counts_above_security_limits() {
    let mut manifest = fixture("example-civil-registration");
    let profile = ProfileClaim {
        id: "profile".to_string(),
        version: "1".to_string(),
    };
    manifest.profiles = (0..65)
        .map(|index| ProfileClaim {
            id: format!("profile-{index}"),
            ..profile.clone()
        })
        .collect();
    assert_has_limit_error(&manifest, "profiles", 64);

    let mut manifest = fixture("example-civil-registration");
    manifest.catalog.conforms_to = (0..65)
        .map(|index| format!("https://example.test/profile/{index}"))
        .collect();
    assert_has_limit_error(&manifest, "catalog.conforms_to", 64);

    let mut manifest = fixture("example-civil-registration");
    manifest.catalog.application_profiles = (0..33)
        .map(|index| registry_manifest_core::ApplicationProfile {
            id: format!("unsupported-{index}"),
            version: "1".to_string(),
        })
        .collect();
    assert_has_limit_error(&manifest, "catalog.application_profiles", 32);

    let mut manifest = service_first_fixture();
    let requirement = manifest.requirements[0].clone();
    manifest.requirements = (0..257)
        .map(|index| registry_manifest_core::RequirementManifest {
            id: format!("requirement-{index}"),
            ..requirement.clone()
        })
        .collect();
    assert_has_limit_error(&manifest, "requirements", 256);

    let mut manifest = fixture("example-civil-registration");
    let entity = manifest.datasets[0].entities[0].clone();
    manifest.datasets[0].entities = (0..257)
        .map(|index| registry_manifest_core::EntityManifest {
            name: format!("entity_{index}"),
            ..entity.clone()
        })
        .collect();
    assert_has_limit_error(&manifest, "datasets[0].entities", 256);

    let mut manifest = fixture("example-civil-registration");
    let field = manifest.datasets[0].entities[0].fields[0].clone();
    manifest.datasets[0].entities[0].fields = (0..513)
        .map(|index| registry_manifest_core::FieldManifest {
            name: format!("field_{index}"),
            ..field.clone()
        })
        .collect();
    assert_has_limit_error(&manifest, "datasets[0].entities[0].fields", 512);

    let mut manifest = fixture("example-civil-registration");
    let target_entity = manifest.datasets[0].entities[0].name.clone();
    manifest.datasets[0].entities[0].relationships = (0..513)
        .map(|index| registry_manifest_core::RelationshipManifest {
            name: format!("relationship_{index}"),
            target_entity: Some(target_entity.clone()),
            target: None,
            cardinality: Some("one".to_string()),
            role: None,
            concept_uri: None,
        })
        .collect();
    assert_has_limit_error(&manifest, "datasets[0].entities[0].relationships", 512);

    let mut manifest = fixture("example-civil-registration");
    let concept = manifest.codelists[0].concepts[0].clone();
    manifest.codelists[0].concepts = (0..1025)
        .map(|index| CodelistConcept {
            code: format!("CODE_{index}"),
            ..concept.clone()
        })
        .collect();
    assert_has_limit_error(&manifest, "codelists[0].concepts", 1024);

    let mut manifest = fixture("example-civil-registration");
    manifest.datasets[0].applicable_legislation = (0..129)
        .map(|index| format!("https://example.test/legislation/{index}"))
        .collect();
    assert_has_limit_error(&manifest, "datasets[0].applicable_legislation", 128);

    let mut manifest = fixture("example-civil-registration");
    manifest.datasets[0].entities[0].fields[0].concepts = (0..129)
        .map(|index| format!("https://example.test/concepts/{index}"))
        .collect();
    assert_has_limit_error(&manifest, "datasets[0].entities[0].fields[0].concepts", 128);
}

#[test]
fn validation_rejects_all_top_level_collection_counts_above_security_limits() {
    let mut manifest = manifest_with_body(&format!(
        "evaluation_profiles:\n{}",
        yaml_items(257, |index| {
            format!(
            "  - id: evaluation-{index}\n    ruleset: ruleset-{index}\n    claim_id: claim\n    subject_id_type: subject\n"
        )
        })
    ));
    assert_has_limit_error(&manifest, "evaluation_profiles", 256);

    manifest = manifest_with_body(&format!(
        "evidence_types:\n{}",
        yaml_items(257, |index| {
            format!("  - id: evidence-{index}\n    title: Evidence {index}\n")
        })
    ));
    assert_has_limit_error(&manifest, "evidence_types", 256);

    manifest = manifest_with_body(&format!(
        "ecosystem_bindings:\n{}",
        yaml_items(257, |index| {
            format!(
                "  - id: binding-{index}\n    version: v1\n    profile: baseline-dpi\n    type: governed-evidence\n"
            )
        })
    ));
    assert_has_limit_error(&manifest, "ecosystem_bindings", 256);

    manifest = manifest_with_body(&format!(
        "authorities:\n{}",
        yaml_items(257, |index| {
            format!("  - id: authority-{index}\n    name: Authority {index}\n")
        })
    ));
    assert_has_limit_error(&manifest, "authorities", 256);

    manifest = manifest_with_body(&format!(
        "public_services:\n{}",
        yaml_items(257, |index| {
            format!("  - id: service-{index}\n    title: Service {index}\n")
        })
    ));
    assert_has_limit_error(&manifest, "public_services", 256);

    manifest = manifest_with_body(&format!(
        "data_services:\n{}",
        yaml_items(257, |index| {
            format!("  - id: data-service-{index}\n    title: Data Service {index}\n")
        })
    ));
    assert_has_limit_error(&manifest, "data_services", 256);

    manifest = manifest_with_body(&format!(
        "forms:\n{}",
        yaml_items(257, |index| {
            format!("  - id: form-{index}\n    title: Form {index}\n    service: service\n")
        })
    ));
    assert_has_limit_error(&manifest, "forms", 256);

    manifest = manifest_with_body(&format!(
        "datasets:\n{}",
        yaml_items(257, |index| {
            format!("  - id: dataset-{index}\n    title: Dataset {index}\n")
        })
    ));
    assert_has_limit_error(&manifest, "datasets", 256);

    manifest = manifest_with_body(&format!(
        "codelists:\n{}",
        yaml_items(257, |index| {
            format!("  - id: codelist-{index}\n    scheme_iri: https://example.test/codelists/{index}\n")
        })
    ));
    assert_has_limit_error(&manifest, "codelists", 256);
}

#[test]
fn validation_rejects_all_uri_list_counts_above_security_limits() {
    let mut manifest = manifest_with_body(&format!(
        "requirements:\n  - id: requirement\n    title: Requirement\n    procedure_contexts:\n{}",
        yaml_uri_list(129, 4)
    ));
    assert_has_limit_error(&manifest, "requirements[0].procedure_contexts", 128);

    manifest = manifest_with_body(&format!(
        "evidence_types:\n  - id: evidence\n    title: Evidence\n    information_concepts:\n{}",
        yaml_uri_list(129, 4)
    ));
    assert_has_limit_error(&manifest, "evidence_types[0].information_concepts", 128);

    manifest = manifest_with_body(&format!(
        "datasets:\n  - id: dataset\n    title: Dataset\n    conforms_to:\n{}",
        yaml_uri_list(129, 4)
    ));
    assert_has_limit_error(&manifest, "datasets[0].conforms_to", 128);

    manifest = manifest_with_body(&format!(
        "datasets:\n  - id: dataset\n    title: Dataset\n    policy:\n      profile:\n{}",
        yaml_uri_list(129, 8)
    ));
    assert_has_limit_error(&manifest, "datasets[0].policy.profile", 128);

    manifest = manifest_with_body(&format!(
        "datasets:\n  - id: dataset\n    title: Dataset\n    evidence_offerings:\n      - id: offering\n        title: Offering\n        evidence_type: evidence\n        issuing_authority:\n          id: authority\n          name: Authority\n        entity: person\n        procedure_contexts:\n{}        access:\n          kind: partner-api\n          ruleset: exact\n",
        yaml_uri_list(129, 10)
    ));
    assert_has_limit_error(
        &manifest,
        "datasets[0].evidence_offerings[0].procedure_contexts",
        128,
    );

    manifest = manifest_with_body(&format!(
        "datasets:\n  - id: dataset\n    title: Dataset\n    evidence_offerings:\n      - id: offering\n        title: Offering\n        evidence_type: evidence\n        issuing_authority:\n          id: authority\n          name: Authority\n        entity: person\n        access:\n          kind: partner-api\n          ruleset: exact\n        policy:\n          purpose:\n{}",
        yaml_uri_list(129, 12)
    ));
    assert_has_limit_error(
        &manifest,
        "datasets[0].evidence_offerings[0].policy.purpose",
        128,
    );
}

#[test]
fn validation_rejects_malformed_http_https_iris_with_real_parser() {
    for namespace in [
        "https://[not-a-host/ns#",
        "https://example.org\\ns#",
        "https://example.org/%zz",
    ] {
        let mut manifest = minimal_manifest();
        manifest
            .vocabularies
            .insert("bad".to_string(), namespace.to_string());
        assert!(
            validation_errors(&manifest)
                .iter()
                .any(|error| error.path == "vocabularies.bad"),
            "{namespace:?} should fail"
        );
    }

    for service_id in [
        "https://[not-a-host/service",
        "https://example.org\\service",
        "https://example.org/%zz",
    ] {
        let raw = format!(
            r#"
schema_version: registry-manifest/v1
catalog:
  id: public-service-validation
  base_url: https://registry.example.test
  title: Public Service Validation
  publisher:
    name: Publisher
datasets:
  - id: dataset
    title: Dataset
    public_services:
      - id: '{service_id}'
        title: Broken
codelists: []
"#
        );
        let manifest: MetadataManifest = serde_yaml_ng::from_str(&raw).expect("manifest parses");
        assert!(
            validation_errors(&manifest)
                .iter()
                .any(|error| error.path == "datasets[0].public_services[0].id"),
            "{service_id:?} should fail"
        );
    }
}

#[test]
fn validation_rejects_malformed_curie_suffixes_after_expansion() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: malformed-curies
  base_url: https://registry.example.test
  title: Malformed CURIEs
  publisher:
    name: Publisher
vocabularies:
  example: https://example.test/ns/
requirements:
  - id: requirement
    title: Requirement
    rdf_type: cccev:%zz
evidence_types:
  - id: evidence
    title: Evidence
    information_concepts:
      - skos:%zz
datasets:
  - id: dataset
    title: Dataset
    entities:
      - name: person
        fields:
          - name: person_id
            type: string
            concepts:
              - example:%zz
codelists: []
"#;
    let manifest: MetadataManifest = serde_yaml_ng::from_str(raw).expect("manifest parses");
    let errors = validation_errors(&manifest);
    for path in [
        "requirements[0].rdf_type",
        "evidence_types[0].information_concepts[0]",
        "datasets[0].entities[0].fields[0].concepts[0]",
    ] {
        assert!(
            errors.iter().any(|error| error.path == path),
            "{path} should fail; got {errors:?}"
        );
    }
}

#[test]
fn manifest_profiles_are_validated_for_publish_safe_ids() {
    let mut manifest = minimal_manifest();
    manifest.profiles = vec![
        ProfileClaim {
            id: "../x".to_string(),
            version: "1".to_string(),
        },
        ProfileClaim {
            id: "/tmp/x".to_string(),
            version: "1".to_string(),
        },
        ProfileClaim {
            id: "blank-version".to_string(),
            version: " ".to_string(),
        },
        ProfileClaim {
            id: "duplicate".to_string(),
            version: "1".to_string(),
        },
        ProfileClaim {
            id: "duplicate".to_string(),
            version: "2".to_string(),
        },
    ];

    let errors = validation_errors(&manifest);
    assert!(errors.iter().any(|error| error.path == "profiles[0].id"));
    assert!(errors.iter().any(|error| error.path == "profiles[1].id"));
    assert!(errors
        .iter()
        .any(|error| error.path == "profiles[2].version"));
    assert!(errors.iter().any(|error| error.path == "profiles[4].id"));
}

#[test]
fn vocabularies_protect_builtins_and_validate_custom_namespaces() {
    for protected in ["cccev", "dcat", "odrl"] {
        let mut manifest = minimal_manifest();
        manifest.vocabularies.insert(
            protected.to_string(),
            "https://attacker.example/ns#".to_string(),
        );
        assert!(
            validation_errors(&manifest)
                .iter()
                .any(|error| error.path == format!("vocabularies.{protected}")),
            "{protected} override should fail"
        );
    }

    for prefix in [
        "example.vocab",
        "example/vocab",
        "Example",
        "example vocab",
        "éxample",
    ] {
        let mut manifest = minimal_manifest();
        manifest
            .vocabularies
            .insert(prefix.to_string(), "https://example.org/ns#".to_string());
        assert!(
            validation_errors(&manifest)
                .iter()
                .any(|error| error.path == format!("vocabularies.{prefix}")),
            "{prefix} prefix should fail"
        );
    }

    for value in [
        "relative/ns#",
        "urn:example:ns",
        "did:web:example",
        "",
        "https://",
    ] {
        let mut manifest = minimal_manifest();
        manifest
            .vocabularies
            .insert("example_vocab".to_string(), value.to_string());
        assert!(
            validation_errors(&manifest)
                .iter()
                .any(|error| error.path == "vocabularies.example_vocab"),
            "{value:?} vocabulary value should fail"
        );
    }

    let mut manifest = minimal_manifest();
    manifest.vocabularies.insert(
        "example_vocab".to_string(),
        "https://example.org/ns#".to_string(),
    );
    manifest.vocabularies.insert(
        "eli".to_string(),
        "http://data.europa.eu/eli/ontology#".to_string(),
    );
    manifest.vocabularies.insert(
        "registry_relay".to_string(),
        "https://registry-relay.dev/".to_string(),
    );
    validate_manifest(&manifest)
        .expect("safe custom vocabulary and identical protected values pass");
}

#[test]
fn expanded_iris_are_sanity_checked_after_curie_expansion() {
    for suffix in [
        "Bad Suffix",
        "Bad<Suffix",
        "Bad>Suffix",
        "Bad\"Suffix",
        "Bad{Suffix",
        "Bad}Suffix",
        "Bad|Suffix",
        "Bad^Suffix",
        "Bad`Suffix",
        "Bad\\u0001Suffix",
    ] {
        let iri = if suffix.contains("\\u") {
            format!("example:{suffix}")
        } else {
            format!("example:{suffix}")
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        };
        let raw = format!(
            r#"
schema_version: registry-manifest/v1
catalog:
  id: iri-sanity
  base_url: https://registry.example.test
  title: IRI Sanity
  publisher:
    name: Publisher
vocabularies:
  example: https://example.org/ns#
requirements:
  - id: eligibility
    title: Eligibility
    rdf_type: "{}"
datasets: []
codelists: []
"#,
            iri
        );
        let manifest: MetadataManifest = serde_yaml_ng::from_str(&raw).expect("manifest parses");
        assert!(
            validation_errors(&manifest)
                .iter()
                .any(|error| error.path == "requirements[0].rdf_type"),
            "{suffix:?} suffix should fail"
        );
    }
}

#[test]
fn builtin_curie_rendering_uses_canonical_namespace() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: builtin-rendering
  base_url: https://registry.example.test
  title: Builtin Rendering
  publisher:
    name: Publisher
requirements:
  - id: eligibility
    title: Eligibility
    rdf_type: cccev:Requirement
datasets: []
codelists: []
"#;
    let manifest: MetadataManifest = serde_yaml_ng::from_str(raw).expect("manifest parses");
    let compiled = compile_manifest(&manifest).expect("manifest compiles");

    assert_eq!(
        compiled.requirement("eligibility").unwrap().rdf_type,
        "http://data.europa.eu/m8g/Requirement"
    );
}

#[test]
fn dataset_public_service_ids_are_structural_identifiers() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: public-service-validation
  base_url: https://registry.example.test
  title: Public Service Validation
  publisher:
    name: Publisher
datasets:
  - id: dataset
    title: Dataset
    public_services:
      - id: relative/path
        title: Relative
      - id: compact:Service
        title: Compact
      - id: urn:example:service
        title: Urn
      - id: did:web:example.gov
        title: Did
      - id: javascript:alert(1)
        title: Javascript
      - id: ../service
        title: Traversal
      - id: "https://example.org/service bad"
        title: Whitespace
      - id: "https://example.org/service<bad>"
        title: Delimiter
      - id: duplicate
        title: Duplicate One
      - id: duplicate
        title: Duplicate Two
codelists: []
"#;
    let manifest: MetadataManifest = serde_yaml_ng::from_str(raw).expect("manifest parses");
    let errors = validation_errors(&manifest);

    for index in 0..8 {
        assert!(
            errors
                .iter()
                .any(|error| error.path == format!("datasets[0].public_services[{index}].id")),
            "public service id {index} should fail"
        );
    }
    assert!(errors
        .iter()
        .any(|error| error.path == "datasets[0].public_services[9].id"));
}

#[test]
fn codelist_concepts_are_validated_and_fallback_ids_are_percent_encoded() {
    let mut manifest = minimal_manifest();
    manifest
        .vocabularies
        .insert("example".to_string(), "https://example.org/ns#".to_string());
    manifest.codelists.push(CodelistManifest {
        id: "status".to_string(),
        scheme_iri: "https://registry.example.test/codelists/status".to_string(),
        version: None,
        valid_from: None,
        valid_to: None,
        external_ref: None,
        concepts: vec![
            CodelistConcept {
                code: " ".to_string(),
                iri: None,
                label: None,
            },
            CodelistConcept {
                code: "bad\u{1}".to_string(),
                iri: None,
                label: None,
            },
            CodelistConcept {
                code: "DUPLICATE".to_string(),
                iri: None,
                label: None,
            },
            CodelistConcept {
                code: "DUPLICATE".to_string(),
                iri: None,
                label: None,
            },
            CodelistConcept {
                code: "BAD_IRI".to_string(),
                iri: Some("example:Bad<Suffix".to_string()),
                label: None,
            },
        ],
    });

    let errors = validation_errors(&manifest);
    for path in [
        "codelists[0].concepts[0].code",
        "codelists[0].concepts[1].code",
        "codelists[0].concepts[3].code",
        "codelists[0].concepts[4].iri",
    ] {
        assert!(errors.iter().any(|error| error.path == path), "{path}");
    }

    let mut manifest = minimal_manifest();
    manifest.codelists.push(CodelistManifest {
        id: "codes".to_string(),
        scheme_iri: "https://registry.example.test/codelists/codes".to_string(),
        version: None,
        valid_from: None,
        valid_to: None,
        external_ref: None,
        concepts: ["US", "USD", "ACTIVE", "01.02", "A/B C?x#y"]
            .into_iter()
            .map(|code| CodelistConcept {
                code: code.to_string(),
                iri: None,
                label: None,
            })
            .collect(),
    });
    validate_manifest(&manifest).expect("real-world concept codes validate");
    let compiled = compile_manifest(&manifest).expect("manifest compiles");
    let shacl = render_shacl(&compiled);
    let scheme = shacl["@graph"]
        .as_array()
        .expect("@graph")
        .iter()
        .find(|node| node["@id"] == "https://registry.example.test/codelists/codes")
        .expect("codelist scheme");
    let concept_ids = scheme["skos:hasTopConcept"]
        .as_array()
        .expect("concepts")
        .iter()
        .map(|concept| concept["@id"].as_str().expect("@id"))
        .collect::<Vec<_>>();
    assert!(concept_ids.contains(&"https://registry.example.test/codelists/codes/US"));
    assert!(concept_ids.contains(&"https://registry.example.test/codelists/codes/USD"));
    assert!(concept_ids.contains(&"https://registry.example.test/codelists/codes/ACTIVE"));
    assert!(concept_ids.contains(&"https://registry.example.test/codelists/codes/01.02"));
    assert!(
        concept_ids.contains(&"https://registry.example.test/codelists/codes/A%2FB%20C%3Fx%23y")
    );
}

#[test]
fn codelist_concept_iris_expand_configured_prefixes() {
    let mut manifest = minimal_manifest();
    manifest.vocabularies.insert(
        "status".to_string(),
        "https://registry.example.test/codelists/status/".to_string(),
    );
    manifest.codelists.push(CodelistManifest {
        id: "status".to_string(),
        scheme_iri: "https://registry.example.test/codelists/status".to_string(),
        version: None,
        valid_from: None,
        valid_to: None,
        external_ref: None,
        concepts: vec![CodelistConcept {
            code: "ACTIVE".to_string(),
            iri: Some("status:active".to_string()),
            label: None,
        }],
    });

    validate_manifest(&manifest).expect("prefixed concept IRI validates");
    let compiled = compile_manifest(&manifest).expect("manifest compiles");
    let shacl = render_shacl(&compiled);
    let scheme = shacl["@graph"]
        .as_array()
        .expect("@graph")
        .iter()
        .find(|node| node["@id"] == "https://registry.example.test/codelists/status")
        .expect("codelist scheme");
    assert_eq!(
        scheme["skos:hasTopConcept"][0]["@id"],
        json!("https://registry.example.test/codelists/status/active")
    );
}

#[test]
fn codelists_carry_version_and_validity_window() {
    let manifest: MetadataManifest = serde_yaml_ng::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: codelist-versioning
  base_url: https://registry.example.test
  title: Codelist Versioning
  publisher:
    name: Publisher
datasets:
  - id: people
    title: People
    entities:
      - name: person
        fields:
          - name: status
            type: code
            codelist: status
codelists:
  - id: status
    scheme_iri: https://registry.example.test/codelists/status
    version: "2026-06-11"
    valid_from: "2026-06-11"
    valid_to: "2027-06-11"
    concepts:
      - code: ACTIVE
"#,
    )
    .expect("manifest parses");

    let compiled = compile_manifest(&manifest).expect("manifest compiles");
    let shacl = render_shacl(&compiled);
    let codelist = shacl["@graph"]
        .as_array()
        .expect("@graph")
        .iter()
        .find(|node| node["@id"] == "https://registry.example.test/codelists/status")
        .expect("codelist node");

    assert_eq!(
        codelist["schema_version"],
        json!("registry-manifest-codelist/v1")
    );
    assert_eq!(codelist["version"], json!("2026-06-11"));
    assert_eq!(codelist["valid_from"], json!("2026-06-11"));
    assert_eq!(codelist["valid_to"], json!("2027-06-11"));
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
        schema["schema_version"],
        json!("registry-manifest-form-json-schema/v1")
    );
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
fn validation_rejects_malicious_profile_claim_ids() {
    let mut manifest = fixture("example-civil-registration");
    manifest
        .profiles
        .push(registry_manifest_core::ProfileClaim {
            id: "../escape".to_string(),
            version: "1".to_string(),
        });
    manifest
        .profiles
        .push(registry_manifest_core::ProfileClaim {
            id: "/tmp/escape".to_string(),
            version: "".to_string(),
        });

    let err = validate_manifest(&manifest).expect_err("bad profile claims rejected");
    let MetadataError::Validation { errors } = err else {
        panic!("expected validation errors");
    };
    assert!(errors.iter().any(|error| error.path == "profiles[1].id"));
    assert!(errors.iter().any(|error| error.path == "profiles[2].id"));
    assert!(errors
        .iter()
        .any(|error| error.path == "profiles[2].version"));
}

#[test]
fn validation_rejects_duplicate_profile_claim_ids() {
    let mut manifest = fixture("example-civil-registration");
    manifest.profiles.push(manifest.profiles[0].clone());

    let err = validate_manifest(&manifest).expect_err("duplicate profile claim rejected");
    let MetadataError::Validation { errors } = err else {
        panic!("expected validation errors");
    };
    assert!(errors
        .iter()
        .any(|error| error.path == "profiles[1].id" && error.message.contains("unique")));
}

#[test]
fn validation_protects_builtin_vocabularies_and_expanded_iris() {
    let mut manifest = fixture("example-civil-registration");
    manifest.vocabularies.insert(
        "cccev".to_string(),
        "https://attacker.example/ns#".to_string(),
    );
    manifest.datasets[0].entities[0].fields[0]
        .concepts
        .push("person:Identifier> <https://attacker.example/evil".to_string());

    let err = validate_manifest(&manifest).expect_err("vocabulary poisoning rejected");
    let MetadataError::Validation { errors } = err else {
        panic!("expected validation errors");
    };
    assert!(errors
        .iter()
        .any(|error| error.path == "vocabularies.cccev"));
    assert!(errors
        .iter()
        .any(|error| error.path.ends_with("entities[0].fields[0].concepts[1]")));
}

#[test]
fn validation_allows_byte_identical_builtin_vocabulary_redeclaration() {
    let mut manifest = fixture("example-civil-registration");
    manifest.vocabularies.insert(
        "eli".to_string(),
        "http://data.europa.eu/eli/ontology#".to_string(),
    );

    validate_manifest(&manifest).expect("byte-identical built-in redeclaration is accepted");
}

#[test]
fn validation_rejects_unsafe_custom_vocabularies() {
    let mut manifest = fixture("example-civil-registration");
    manifest.vocabularies.insert(
        "Bad.Prefix".to_string(),
        "https://example.test/ns#".to_string(),
    );
    manifest
        .vocabularies
        .insert("ok_prefix".to_string(), "urn:example".to_string());

    let err = validate_manifest(&manifest).expect_err("bad custom vocabularies rejected");
    let MetadataError::Validation { errors } = err else {
        panic!("expected validation errors");
    };
    assert!(errors
        .iter()
        .any(|error| error.path == "vocabularies.Bad.Prefix"));
    assert!(errors
        .iter()
        .any(|error| error.path == "vocabularies.ok_prefix"));
}

#[test]
fn validation_allows_safe_custom_vocabulary_expansion() {
    let mut manifest = fixture("example-civil-registration");
    manifest.vocabularies.insert(
        "person".to_string(),
        "https://attacker.example/person#".to_string(),
    );

    let compiled = compile_manifest(&manifest).expect("custom person prefix is accepted");
    let entity = compiled
        .dataset(&manifest.datasets[0].id)
        .expect("dataset")
        .entities
        .get("person")
        .expect("entity");
    assert!(entity.fields["person_id"]
        .concepts
        .iter()
        .any(|iri| iri == "https://attacker.example/person#Person.identifier"));
}

#[test]
fn validation_accepts_cross_origin_dataset_public_service_iris() {
    let manifest = service_first_fixture();
    validate_manifest(&manifest).expect("service-first fixture stays valid");
}

#[test]
fn validation_rejects_bad_dataset_public_service_ids() {
    let mut manifest = service_first_fixture();
    manifest.datasets[1].public_services[0].id = Some("javascript:alert(1)".to_string());
    let duplicate = manifest.datasets[1].public_services[0].clone();
    manifest.datasets[1].public_services.push(duplicate);

    let err = validate_manifest(&manifest).expect_err("bad public service ids rejected");
    let MetadataError::Validation { errors } = err else {
        panic!("expected validation errors");
    };
    assert!(errors
        .iter()
        .any(|error| error.path == "datasets[1].public_services[0].id"));
    assert!(errors
        .iter()
        .any(|error| error.path == "datasets[1].public_services[1].id"));
}

#[test]
fn validation_checks_codelist_concepts_and_preserves_real_world_codes() {
    let manifest: MetadataManifest = serde_yaml_ng::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: codelist-codes
  base_url: https://data.example.test
  title: Codelist Codes
  publisher:
    name: Publisher
datasets: []
codelists:
  - id: statuses
    scheme_iri: https://data.example.test/codelists/statuses
    concepts:
      - code: US
      - code: USD
      - code: ACTIVE
      - code: "01.02"
"#,
    )
    .expect("manifest parses");
    validate_manifest(&manifest).expect("real-world concept codes are accepted");
    let compiled = compile_manifest(&manifest).expect("compile");
    let shacl = render_shacl(&compiled);
    let raw = serde_json::to_string(&shacl).expect("json");
    assert!(raw.contains("https://data.example.test/codelists/statuses/01.02"));
}

#[test]
fn validation_rejects_invalid_codelist_concepts() {
    let manifest: MetadataManifest = serde_yaml_ng::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: bad-codelist
  base_url: https://data.example.test
  title: Bad Codelist
  publisher:
    name: Publisher
datasets: []
codelists:
  - id: statuses
    scheme_iri: https://data.example.test/codelists/statuses
    concepts:
      - code: ""
      - code: duplicate
      - code: duplicate
      - code: bad-iri
        iri: "skos:Concept> <https://attacker.example/evil"
"#,
    )
    .expect("manifest parses");

    let err = validate_manifest(&manifest).expect_err("bad codelist concepts rejected");
    let MetadataError::Validation { errors } = err else {
        panic!("expected validation errors");
    };
    assert!(errors
        .iter()
        .any(|error| error.path == "codelists[0].concepts[0].code"));
    assert!(errors
        .iter()
        .any(|error| error.path == "codelists[0].concepts[2].code"));
    assert!(errors
        .iter()
        .any(|error| error.path == "codelists[0].concepts[3].iri"));
}

#[test]
fn codelist_fallback_ids_percent_encode_unsafe_code_bytes() {
    let manifest: MetadataManifest = serde_yaml_ng::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: encoded-codes
  base_url: https://data.example.test
  title: Encoded Codes
  publisher:
    name: Publisher
datasets: []
codelists:
  - id: statuses
    scheme_iri: https://data.example.test/codelists/statuses
    concepts:
      - code: "A/B value"
"#,
    )
    .expect("manifest parses");
    let compiled = compile_manifest(&manifest).expect("compile");
    let shacl = render_shacl(&compiled);
    let raw = serde_json::to_string(&shacl).expect("json");
    assert!(raw.contains("https://data.example.test/codelists/statuses/A%2FB%20value"));
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
    let manifest: MetadataManifest = serde_yaml_ng::from_str(
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
    let manifest: MetadataManifest = serde_yaml_ng::from_str(
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
    let manifest: MetadataManifest = serde_yaml_ng::from_str(
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
    let manifest: MetadataManifest = serde_yaml_ng::from_str(
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
    serde_yaml_ng::from_str(
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
    - registry-notary-federation/v0.1
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
      - id: age_notary
        title: Age notary
        evidence_type: age_evidence
        issuing_authority:
          id: civil_registry
          name: Civil Registry
        entity: resident
        lookup_keys: [national_id]
        access:
          kind: registry-notary
          conforms_to: registry-notary-federation/v0.1
          endpoint_url: https://notary.example.test/evaluate
          discovery_url: https://notary.example.test/.well-known/registry-notary
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
        json!("registry-notary-federation/v0.1")
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
fn evaluation_profile_evidence_pack_parses_compiles_and_renders_catalog() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: evidence-pack-profile
  base_url: https://registry.example.test
  title: Evidence Pack Profile
  publisher:
    name: Example Registry
evaluation_profiles:
  - id: income_eligibility_profile
    ruleset: income-eligibility-v1
    claim_id: income_eligibility
    subject_id_type: national_id
    evidence_pack:
      policy_id: income-policy
      policy_version: "2026.06"
      policy_hash: sha256:1111111111111111111111111111111111111111111111111111111111111111
      odrl_policy_url: https://policies.example.test/odrl/income-policy.json
datasets: []
codelists: []
"#;
    let manifest: MetadataManifest =
        serde_yaml_ng::from_str(raw).expect("evidence_pack manifest parses");

    validate_manifest(&manifest).expect("evidence_pack manifest validates");
    let profile = &manifest.evaluation_profiles[0];
    let evidence_pack = profile.evidence_pack.as_ref().expect("evidence_pack");
    assert_eq!(evidence_pack.policy_id.as_deref(), Some("income-policy"));
    assert_eq!(evidence_pack.policy_version.as_deref(), Some("2026.06"));
    assert_eq!(
        evidence_pack.policy_hash.as_deref(),
        Some("sha256:1111111111111111111111111111111111111111111111111111111111111111")
    );

    let compiled = compile_manifest(&manifest).expect("evidence_pack manifest compiles");
    let catalog = render_catalog(&compiled);
    assert_eq!(
        catalog["evaluation_profiles"][0]["evidence_pack"]["policy_id"],
        json!("income-policy")
    );
    assert_eq!(
        catalog["evaluation_profiles"][0]["evidence_pack"]["policy_version"],
        json!("2026.06")
    );
    assert_eq!(
        catalog["evaluation_profiles"][0]["evidence_pack"]["policy_hash"],
        json!("sha256:1111111111111111111111111111111111111111111111111111111111111111")
    );
}

#[test]
fn validation_rejects_blank_evidence_pack_policy_fields() {
    for field in ["policy_id", "policy_hash", "policy_version"] {
        let raw = format!(
            r#"
schema_version: registry-manifest/v1
catalog:
  id: blank-evidence-pack
  base_url: https://registry.example.test
  title: Blank Evidence Pack
  publisher:
    name: Example Registry
evaluation_profiles:
  - id: blank_evidence_pack_profile
    ruleset: blank-evidence-pack-v1
    claim_id: blank_evidence_pack
    subject_id_type: national_id
    evidence_pack:
      {field}: "   "
datasets: []
codelists: []
"#
        );
        let manifest: MetadataManifest =
            serde_yaml_ng::from_str(&raw).expect("blank evidence_pack manifest parses");

        let error = validate_manifest(&manifest).expect_err("blank evidence_pack field rejected");
        let MetadataError::Validation { errors } = error else {
            panic!("unexpected error: {error:?}");
        };
        let expected_path = format!("evaluation_profiles[0].evidence_pack.{field}");
        assert!(
            errors.iter().any(|error| {
                error.path == expected_path && error.message.contains("must not be empty")
            }),
            "expected blank field error at {expected_path}; got {errors:?}"
        );
    }
}

#[test]
fn validation_rejects_malformed_evidence_pack_policy_metadata() {
    let cases = [
        (
            "policy_hash",
            "sha256:not-a-digest",
            "evaluation_profiles[0].evidence_pack.policy_hash",
            "sha256:<64 lowercase hex>",
        ),
        (
            "policy_hash",
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "evaluation_profiles[0].evidence_pack.policy_hash",
            "sha256:<64 lowercase hex>",
        ),
        (
            "odrl_policy_url",
            "not-a-url",
            "evaluation_profiles[0].evidence_pack.odrl_policy_url",
            "URL must start",
        ),
        (
            "odrl_policy_url",
            "http://policies.example.test/odrl/policy.json",
            "evaluation_profiles[0].evidence_pack.odrl_policy_url",
            "https://",
        ),
    ];

    for (field, value, expected_path, expected_message) in cases {
        let raw = format!(
            r#"
schema_version: registry-manifest/v1
catalog:
  id: malformed-evidence-pack
  base_url: https://registry.example.test
  title: Malformed Evidence Pack
  publisher:
    name: Example Registry
evaluation_profiles:
  - id: malformed_evidence_pack_profile
    ruleset: malformed-evidence-pack-v1
    claim_id: malformed_evidence_pack
    subject_id_type: national_id
    evidence_pack:
      {field}: "{value}"
datasets: []
codelists: []
"#
        );
        let manifest: MetadataManifest =
            serde_yaml_ng::from_str(&raw).expect("malformed evidence_pack manifest parses");

        let error = validate_manifest(&manifest).expect_err("malformed evidence_pack rejected");
        let MetadataError::Validation { errors } = error else {
            panic!("unexpected error: {error:?}");
        };
        assert!(
            errors.iter().any(|error| {
                error.path == expected_path && error.message.contains(expected_message)
            }),
            "expected malformed field error at {expected_path}; got {errors:?}"
        );
    }
}

#[test]
fn evidence_pack_odrl_policy_url_serializes_when_present() {
    let manifest: MetadataManifest = serde_yaml_ng::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: odrl-policy-url
  base_url: https://registry.example.test
  title: ODRL Policy URL
  publisher:
    name: Example Registry
evaluation_profiles:
  - id: odrl_policy_profile
    ruleset: odrl-policy-v1
    claim_id: odrl_policy
    subject_id_type: national_id
    evidence_pack:
      odrl_policy_url: https://policies.example.test/odrl/policy.json
datasets: []
codelists: []
"#,
    )
    .expect("odrl policy url manifest parses");

    validate_manifest(&manifest).expect("odrl policy url manifest validates");
    let value = serde_json::to_value(&manifest).expect("manifest serializes");
    assert_eq!(
        value["evaluation_profiles"][0]["evidence_pack"]["odrl_policy_url"],
        json!("https://policies.example.test/odrl/policy.json")
    );
}

#[test]
fn evidence_pack_policy_hash_helpers_use_canonical_policy_json() {
    let first = json!({
        "purpose_allowlist": ["benefit_eligibility", "case_review"],
        "freshness": {
            "max_source_observed_age_seconds": 86_400
        },
        "legal_basis": {
            "required": true,
            "allowed": ["public_task"]
        }
    });
    let second = json!({
        "legal_basis": {
            "allowed": ["public_task"],
            "required": true
        },
        "freshness": {
            "max_source_observed_age_seconds": 86_400
        },
        "purpose_allowlist": ["benefit_eligibility", "case_review"]
    });

    let hash = compute_policy_hash(&first).expect("policy hash computes");
    assert_eq!(
        hash,
        compute_policy_hash(&second).expect("policy hash computes after key reorder")
    );
    assert_ne!(
        hash,
        compute_policy_hash(&json!({
            "purpose_allowlist": ["case_review", "benefit_eligibility"],
            "freshness": {
                "max_source_observed_age_seconds": 86_400
            },
            "legal_basis": {
                "required": true,
                "allowed": ["public_task"]
            }
        }))
        .expect("changed policy hash computes")
    );
}

#[test]
fn evidence_pack_policy_hash_helpers_verify_inline_pack_policy() {
    let manifest: MetadataManifest = serde_yaml_ng::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: inline-policy-pack
  base_url: https://registry.example.test
  title: Inline Policy Pack
  publisher:
    name: Example Registry
evaluation_profiles:
  - id: inline_policy_profile
    ruleset: inline-policy-v1
    claim_id: inline_policy
    subject_id_type: national_id
    evidence_pack:
      policy_id: inline-policy
      policy:
        purpose_allowlist:
          - benefit_eligibility
        freshness:
          max_source_observed_age_seconds: 86400
datasets: []
codelists: []
"#,
    )
    .expect("inline policy manifest parses");
    let mut evidence_pack = manifest.evaluation_profiles[0]
        .evidence_pack
        .clone()
        .expect("evidence_pack");

    let computed = compute_evidence_pack_policy_hash(&evidence_pack)
        .expect("pack policy hash computes")
        .expect("inline policy hash");
    assert_eq!(
        verify_evidence_pack_policy_hash(&evidence_pack).expect("hash verify handles missing hash"),
        None
    );

    evidence_pack.policy_hash = Some(computed);
    assert_eq!(
        verify_evidence_pack_policy_hash(&evidence_pack).expect("hash verifies"),
        Some(true)
    );

    evidence_pack.policy_hash =
        Some("sha256:0000000000000000000000000000000000000000000000000000000000000000".into());
    assert_eq!(
        verify_evidence_pack_policy_hash(&evidence_pack).expect("hash mismatch verifies"),
        Some(false)
    );
}

#[test]
fn validation_rejects_inline_evidence_pack_policy_hash_mismatch() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: inline-policy-hash-mismatch
  base_url: https://registry.example.test
  title: Inline Policy Hash Mismatch
  publisher:
    name: Example Registry
evaluation_profiles:
  - id: inline_policy_profile
    ruleset: inline-policy-v1
    claim_id: inline_policy
    subject_id_type: national_id
    evidence_pack:
      policy_id: inline-policy
      policy_hash: sha256:0000000000000000000000000000000000000000000000000000000000000000
      policy:
        purpose_allowlist:
          - benefit_eligibility
        freshness:
          max_source_observed_age_seconds: 86400
datasets: []
codelists: []
"#;
    let manifest: MetadataManifest =
        serde_yaml_ng::from_str(raw).expect("inline policy manifest parses");

    let error = validate_manifest(&manifest).expect_err("policy hash mismatch rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(
        errors.iter().any(|error| {
            error.path == "evaluation_profiles[0].evidence_pack.policy_hash"
                && error.message.contains("does not match")
        }),
        "expected policy_hash mismatch error; got {errors:?}"
    );
}

#[test]
fn ecosystem_bindings_default_empty_for_backwards_compatible_manifests() {
    let manifest = minimal_manifest();

    validate_manifest(&manifest).expect("minimal manifest validates");
    assert!(manifest.ecosystem_bindings.is_empty());

    let compiled = compile_manifest(&manifest).expect("minimal manifest compiles");
    let catalog = render_catalog(&compiled);
    assert!(catalog.get("ecosystem_bindings").is_none());
}

#[test]
fn ecosystem_binding_parses_validates_compiles_and_renders_catalog() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: ecosystem-binding
  base_url: https://registry.example.test
  title: Ecosystem Binding
  publisher:
    name: Example Registry
ecosystem_bindings:
  - id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    title: Baseline DPI
    description: Baseline data proofing interface binding
    vocabulary:
      kind: PublicSchema
      concept_maps:
        person_is_alive: publicschema:Person.isAlive
    request_envelope:
      kind: REST
      media_type: application/json
    response_envelope:
      kind: minimized-json
      media_type: application/json
    transport:
      kind: HTTPS
      trust_connector_required: true
    trust_framework:
      kind: national-pki
      trust_list_url: https://trust.example.test/list.json
    credential_format:
      kind: SD-JWT VC
      profile: registry-evidence/v1
    assurance_model:
      scheme: registry-assurance
      minimum_assurance: substantial
    conformance:
      fixtures:
        - id: success-person-is-alive
          path: fixtures/success/person-is-alive.json
    evidence_pack:
      pack_id: oots-birth-evidence/v1
      pack_version: v1
      source_basis:
        family: oots-common-data-model
        evidence_type: Birth Evidence
      semantic_profile:
        vocabulary: publicschema
        fit: strong
      evidence_envelope:
        identifier: required
        issuing_date: required
        issuing_authority: required
        is_about: required
        is_conformant_to: required
        distribution: one_or_more
      required_gates:
        - purpose
        - jurisdiction
        - legal_basis
        - consent
        - authority_basis
        - requester_identity
        - subject_identity
        - subject_relationship
        - assurance
        - source_binding
        - source_freshness
        - requested_disclosure
        - credential_format
        - route_scope
      allowed_outputs:
        - minimized_json
      policy_id: baseline-policy
      policy_version: "2026.06"
      policy_hash: sha256:54fcbb33655ddd98d628a0342af2ecd891e89067a167092d86e8a38d94552a3f
      source_mapping:
        relay_config_ref: relay/source-bindings/person.yaml
        crosswalk_ref: crosswalk/person-public.yaml
      policy:
        purpose_allowlist:
          - benefit_eligibility
        legal_basis:
          required: true
      fixtures:
        - id: success-person-is-alive
          kind: success
          path: fixtures/success/person-is-alive.json
        - id: denied-purpose
          kind: denial
          path: fixtures/denial/purpose.json
      synthetic_data:
        - id: person-seed
          path: synthetic/person.csv
      odrl_enforcement:
        profile: registry-evidence-gateway-pdp/v1
        constraint_terms:
          - odrl:purpose
          - odrl:spatial
    profiles:
      - id: dcat-ap
        version: "3.0.0"
datasets: []
codelists: []
"#;
    let manifest: MetadataManifest =
        serde_yaml_ng::from_str(raw).expect("ecosystem binding manifest parses");

    validate_manifest(&manifest).expect("ecosystem binding manifest validates");
    let binding = &manifest.ecosystem_bindings[0];
    assert_eq!(binding.id, "baseline-dpi/v1");
    assert_eq!(binding.binding_type, "governed-evidence");
    assert_eq!(binding.profiles[0].id, "dcat-ap");
    assert_eq!(
        binding.vocabulary.as_ref().expect("vocabulary")["kind"],
        json!("PublicSchema")
    );

    let compiled = compile_manifest(&manifest).expect("ecosystem binding manifest compiles");
    let catalog = render_catalog(&compiled);
    assert_eq!(
        catalog["ecosystem_bindings"][0]["id"],
        json!("baseline-dpi/v1")
    );
    assert_eq!(catalog["ecosystem_bindings"][0]["version"], json!("v1"));
    assert_eq!(
        catalog["ecosystem_bindings"][0]["type"],
        json!("governed-evidence")
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["vocabulary"]["concept_maps"]["person_is_alive"],
        json!("publicschema:Person.isAlive")
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["request_envelope"]["kind"],
        json!("REST")
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["response_envelope"]["kind"],
        json!("minimized-json")
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["transport"]["trust_connector_required"],
        json!(true)
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["trust_framework"]["trust_list_url"],
        json!("https://trust.example.test/list.json")
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["credential_format"]["kind"],
        json!("SD-JWT VC")
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["assurance_model"]["minimum_assurance"],
        json!("substantial")
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["conformance"]["fixtures"][0]["id"],
        json!("success-person-is-alive")
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["evidence_pack"]["pack_id"],
        json!("oots-birth-evidence/v1")
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["evidence_pack"]["required_gates"][0],
        json!("purpose")
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["evidence_pack"]["allowed_outputs"],
        json!(["minimized_json"])
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["evidence_pack"]["policy_id"],
        json!("baseline-policy")
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["evidence_pack"]["source_mapping"]["crosswalk_ref"],
        json!("crosswalk/person-public.yaml")
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["evidence_pack"]["policy"]["legal_basis"]["required"],
        json!(true)
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["evidence_pack"]["fixtures"][1]["kind"],
        json!("denial")
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["evidence_pack"]["synthetic_data"][0]["path"],
        json!("synthetic/person.csv")
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["evidence_pack"]["odrl_enforcement"]["profile"],
        json!("registry-evidence-gateway-pdp/v1")
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["evidence_pack"]["odrl_enforcement"]["constraint_terms"],
        json!(["odrl:purpose", "odrl:spatial"])
    );
    assert_eq!(
        catalog["ecosystem_bindings"][0]["profiles"][0]["version"],
        json!("3.0.0")
    );
}

#[test]
fn ecosystem_binding_accepts_every_supported_odrl_enforcement_term() {
    let term_list = SUPPORTED_ODRL_ENFORCEMENT_TERMS
        .iter()
        .map(|term| format!("          - {term}\n"))
        .collect::<String>();
    let raw = format!(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: all-supported-odrl-enforcement
  base_url: https://registry.example.test
  title: All Supported ODRL Enforcement
  publisher:
    name: Example Registry
ecosystem_bindings:
  - id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    evidence_pack:
      pack_id: oots-birth-evidence/v1
      pack_version: v1
      source_basis:
        family: oots-common-data-model
        evidence_type: Birth Evidence
      semantic_profile:
        vocabulary: publicschema
        fit: strong
      evidence_envelope:
        identifier: required
        issuing_date: required
        issuing_authority: required
        is_about: required
        is_conformant_to: required
        distribution: one_or_more
      required_gates:
        - purpose
        - jurisdiction
        - legal_basis
        - consent
        - authority_basis
        - requester_identity
        - subject_identity
        - subject_relationship
        - assurance
        - source_binding
        - source_freshness
        - requested_disclosure
        - credential_format
        - route_scope
      allowed_outputs:
        - minimized_json
      policy_id: baseline-policy
      policy_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
      odrl_enforcement:
        profile: {ODRL_ENFORCEMENT_PROFILE}
        constraint_terms:
{term_list}datasets: []
codelists: []
"#
    );
    let manifest: MetadataManifest =
        serde_yaml_ng::from_str(&raw).expect("supported ODRL manifest parses");

    validate_manifest(&manifest).expect("all supported ODRL terms validate");
    let compiled = compile_manifest(&manifest).expect("all supported ODRL terms compile");
    let catalog = render_catalog(&compiled);
    assert_eq!(
        catalog["ecosystem_bindings"][0]["evidence_pack"]["odrl_enforcement"]["constraint_terms"],
        json!(SUPPORTED_ODRL_ENFORCEMENT_TERMS)
    );
}

#[test]
fn validation_rejects_unsupported_odrl_enforcement_terms() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: unsupported-odrl-enforcement
  base_url: https://registry.example.test
  title: Unsupported ODRL Enforcement
  publisher:
    name: Example Registry
ecosystem_bindings:
  - id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    evidence_pack:
      odrl_enforcement:
        profile: registry-evidence-gateway-pdp/v1
        constraint_terms:
          - odrl:purpose
          - odrl:count
datasets: []
codelists: []
"#;
    let manifest: MetadataManifest =
        serde_yaml_ng::from_str(raw).expect("unsupported ODRL manifest parses");

    let error = validate_manifest(&manifest).expect_err("unsupported ODRL term rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(
        errors.iter().any(|error| {
            error.path == "ecosystem_bindings[0].evidence_pack.odrl_enforcement.constraint_terms[1]"
                && error.message.contains("unsupported ODRL enforcement term")
        }),
        "expected unsupported ODRL enforcement term error; got {errors:?}"
    );
}

#[test]
fn validation_rejects_wrong_governed_evidence_odrl_enforcement_profile() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: wrong-odrl-enforcement-profile
  base_url: https://registry.example.test
  title: Wrong ODRL Enforcement Profile
  publisher:
    name: Example Registry
ecosystem_bindings:
  - id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    evidence_pack:
      policy_id: baseline-policy
      policy_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
      odrl_enforcement:
        profile: registry-evidence-gateway-pdp/v2
        constraint_terms:
          - odrl:purpose
datasets: []
codelists: []
"#;
    let manifest: MetadataManifest =
        serde_yaml_ng::from_str(raw).expect("wrong ODRL profile manifest parses");

    let error = validate_manifest(&manifest).expect_err("wrong ODRL profile rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(
        errors.iter().any(|error| {
            error.path == "ecosystem_bindings[0].evidence_pack.odrl_enforcement.profile"
                && error
                    .message
                    .contains("ODRL enforcement profile must be registry-evidence-gateway-pdp/v1")
        }),
        "expected wrong ODRL enforcement profile error; got {errors:?}"
    );
}

#[test]
fn validation_rejects_governed_evidence_empty_odrl_enforcement_terms() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: empty-odrl-enforcement-terms
  base_url: https://registry.example.test
  title: Empty ODRL Enforcement Terms
  publisher:
    name: Example Registry
ecosystem_bindings:
  - id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    evidence_pack:
      policy_id: baseline-policy
      policy_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
      odrl_enforcement:
        profile: registry-evidence-gateway-pdp/v1
        constraint_terms: []
datasets: []
codelists: []
"#;
    let manifest: MetadataManifest =
        serde_yaml_ng::from_str(raw).expect("empty ODRL terms manifest parses");

    let error = validate_manifest(&manifest).expect_err("empty ODRL terms rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(
        errors.iter().any(|error| {
            error.path == "ecosystem_bindings[0].evidence_pack.odrl_enforcement.constraint_terms"
                && error
                    .message
                    .contains("must list at least one constraint term")
        }),
        "expected empty ODRL enforcement terms error; got {errors:?}"
    );
}

#[test]
fn validation_rejects_governed_evidence_binding_without_odrl_enforcement() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: governed-without-enforcement
  base_url: https://registry.example.test
  title: Governed Without Enforcement
  publisher:
    name: Example Registry
ecosystem_bindings:
  - id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    evidence_pack:
      policy_id: baseline-policy
datasets: []
codelists: []
"#;
    let manifest: MetadataManifest =
        serde_yaml_ng::from_str(raw).expect("governed manifest parses");

    let error = validate_manifest(&manifest).expect_err("missing enforcement profile rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(
        errors.iter().any(|error| {
            error.path == "ecosystem_bindings[0].evidence_pack.odrl_enforcement"
                && error
                    .message
                    .contains("must declare an ODRL enforcement profile")
        }),
        "expected missing ODRL enforcement error; got {errors:?}"
    );
}

#[test]
fn validation_rejects_governed_evidence_binding_without_policy_identity() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: governed-without-policy-identity
  base_url: https://registry.example.test
  title: Governed Without Policy Identity
  publisher:
    name: Example Registry
ecosystem_bindings:
  - id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    evidence_pack:
      odrl_enforcement:
        profile: registry-evidence-gateway-pdp/v1
        constraint_terms:
          - odrl:purpose
datasets: []
codelists: []
"#;
    let manifest: MetadataManifest =
        serde_yaml_ng::from_str(raw).expect("governed manifest parses");

    let error = validate_manifest(&manifest).expect_err("missing policy identity rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(
        errors.iter().any(|error| {
            error.path == "ecosystem_bindings[0].evidence_pack.policy_id"
                && error
                    .message
                    .contains("must declare evidence_pack policy_id")
        }),
        "expected missing policy_id error; got {errors:?}"
    );
    assert!(
        errors.iter().any(|error| {
            error.path == "ecosystem_bindings[0].evidence_pack.policy_hash"
                && error
                    .message
                    .contains("must declare evidence_pack policy_hash")
        }),
        "expected missing policy_hash error; got {errors:?}"
    );
}

#[test]
fn validation_rejects_governed_evidence_binding_without_pack_metadata() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: governed-without-pack-metadata
  base_url: https://registry.example.test
  title: Governed Without Pack Metadata
  publisher:
    name: Example Registry
ecosystem_bindings:
  - id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    evidence_pack:
      policy_id: baseline-policy
      policy_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
      odrl_enforcement:
        profile: registry-evidence-gateway-pdp/v1
        constraint_terms:
          - odrl:purpose
datasets: []
codelists: []
"#;
    let manifest: MetadataManifest =
        serde_yaml_ng::from_str(raw).expect("governed manifest parses");

    let error = validate_manifest(&manifest).expect_err("missing pack metadata rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    for expected_path in [
        "ecosystem_bindings[0].evidence_pack.pack_id",
        "ecosystem_bindings[0].evidence_pack.pack_version",
        "ecosystem_bindings[0].evidence_pack.source_basis",
        "ecosystem_bindings[0].evidence_pack.semantic_profile",
        "ecosystem_bindings[0].evidence_pack.evidence_envelope",
        "ecosystem_bindings[0].evidence_pack.required_gates",
        "ecosystem_bindings[0].evidence_pack.allowed_outputs",
    ] {
        assert!(
            errors.iter().any(|error| error.path == expected_path),
            "expected missing pack metadata error at {expected_path}; got {errors:?}"
        );
    }
}

#[test]
fn validation_rejects_governed_evidence_binding_missing_required_gate() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: governed-missing-required-gate
  base_url: https://registry.example.test
  title: Governed Missing Required Gate
  publisher:
    name: Example Registry
ecosystem_bindings:
  - id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    evidence_pack:
      pack_id: oots-birth-evidence/v1
      pack_version: v1
      source_basis: { family: oots-common-data-model, evidence_type: Birth Evidence }
      semantic_profile: { vocabulary: publicschema, fit: strong }
      evidence_envelope: { identifier: required, distribution: one_or_more }
      required_gates:
        - purpose
      allowed_outputs:
        - minimized_json
      policy_id: baseline-policy
      policy_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
      odrl_enforcement:
        profile: registry-evidence-gateway-pdp/v1
        constraint_terms:
          - odrl:purpose
datasets: []
codelists: []
"#;
    let manifest: MetadataManifest =
        serde_yaml_ng::from_str(raw).expect("governed manifest parses");

    let error = validate_manifest(&manifest).expect_err("missing required gate rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(
        errors.iter().any(|error| {
            error.path == "ecosystem_bindings[0].evidence_pack.required_gates"
                && error.message.contains("jurisdiction")
        }),
        "expected missing jurisdiction gate error; got {errors:?}"
    );
}

#[test]
fn validation_rejects_unsupported_evidence_pack_allowed_output() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: governed-unsupported-output
  base_url: https://registry.example.test
  title: Governed Unsupported Output
  publisher:
    name: Example Registry
ecosystem_bindings:
  - id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    evidence_pack:
      pack_id: oots-birth-evidence/v1
      pack_version: v1
      source_basis: { family: oots-common-data-model, evidence_type: Birth Evidence }
      semantic_profile: { vocabulary: publicschema, fit: strong }
      evidence_envelope: { identifier: required, distribution: one_or_more }
      required_gates:
        - purpose
        - jurisdiction
        - legal_basis
        - consent
        - authority_basis
        - requester_identity
        - subject_identity
        - subject_relationship
        - assurance
        - source_binding
        - source_freshness
        - requested_disclosure
        - credential_format
        - route_scope
      allowed_outputs:
        - sd_jwt_vc
      policy_id: baseline-policy
      policy_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
      odrl_enforcement:
        profile: registry-evidence-gateway-pdp/v1
        constraint_terms:
          - odrl:purpose
datasets: []
codelists: []
"#;
    let manifest: MetadataManifest =
        serde_yaml_ng::from_str(raw).expect("governed manifest parses");

    let error = validate_manifest(&manifest).expect_err("unsupported output rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(
        errors.iter().any(|error| {
            error.path == "ecosystem_bindings[0].evidence_pack.allowed_outputs[0]"
                && error
                    .message
                    .contains("unsupported evidence_pack allowed output")
        }),
        "expected unsupported output error; got {errors:?}"
    );
}

#[test]
fn validation_rejects_unknown_ecosystem_binding_type() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: unknown-ecosystem-binding-type
  base_url: https://registry.example.test
  title: Unknown Ecosystem Binding Type
  publisher:
    name: Example Registry
ecosystem_bindings:
  - id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: "governed-evidence "
    evidence_pack:
      policy_id: baseline-policy
      policy_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
      odrl_enforcement:
        profile: registry-evidence-gateway-pdp/v1
        constraint_terms:
          - odrl:purpose
datasets: []
codelists: []
"#;
    let manifest: MetadataManifest =
        serde_yaml_ng::from_str(raw).expect("ecosystem binding manifest parses");

    let error = validate_manifest(&manifest).expect_err("unknown binding type rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(
        errors.iter().any(|error| {
            error.path == "ecosystem_bindings[0].type"
                && error
                    .message
                    .contains("ecosystem binding type must be governed-evidence")
        }),
        "expected binding type error; got {errors:?}"
    );
}

#[test]
fn ecosystem_binding_blank_fields_are_rejected() {
    for (binding_body, expected_path) in [
        (
            r#"id: "   "
    version: v1
    profile: baseline-dpi
    type: governed-evidence"#,
            "ecosystem_bindings[0].id",
        ),
        (
            r#"id: baseline-dpi/v1
    version: "   "
    profile: baseline-dpi
    type: governed-evidence"#,
            "ecosystem_bindings[0].version",
        ),
        (
            r#"id: baseline-dpi/v1
    version: v1
    profile: "   "
    type: governed-evidence"#,
            "ecosystem_bindings[0].profile",
        ),
        (
            r#"id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: "   ""#,
            "ecosystem_bindings[0].type",
        ),
        (
            r#"id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    title: "   ""#,
            "ecosystem_bindings[0].title",
        ),
        (
            r#"id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    description: "   ""#,
            "ecosystem_bindings[0].description",
        ),
        (
            r#"id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    evidence_pack:
      policy_id: "   ""#,
            "ecosystem_bindings[0].evidence_pack.policy_id",
        ),
        (
            r#"id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    profiles:
      - id: profile
        version: "   ""#,
            "ecosystem_bindings[0].profiles[0].version",
        ),
    ] {
        let raw = format!(
            r#"
schema_version: registry-manifest/v1
catalog:
  id: blank-ecosystem-binding
  base_url: https://registry.example.test
  title: Blank Ecosystem Binding
  publisher:
    name: Example Registry
ecosystem_bindings:
  - {binding_body}
datasets: []
codelists: []
"#
        );
        let manifest: MetadataManifest =
            serde_yaml_ng::from_str(&raw).expect("blank ecosystem binding manifest parses");

        let error =
            validate_manifest(&manifest).expect_err("blank ecosystem binding field rejected");
        let MetadataError::Validation { errors } = error else {
            panic!("unexpected error: {error:?}");
        };
        assert!(
            errors.iter().any(|error| {
                error.path == expected_path && error.message.contains("must not be empty")
            }),
            "expected blank field error at {expected_path}; got {errors:?}"
        );
    }
}

#[test]
fn validation_rejects_registry_notary_unresolved_ruleset() {
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
fn validation_rejects_registry_notary_bad_conforms_to() {
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
            && error.message.contains("registry-notary-federation/v0.1")
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
fn validation_accepts_federation_endpoints_on_issuer_host() {
    let mut manifest = federated_evaluation_manifest();
    let federation = manifest.federation.as_mut().expect("federation");
    federation.issuer = "https://registry.example.test/issuer".to_string();
    federation.jwks_uri = "https://registry.example.test/.well-known/jwks.json".to_string();
    federation.federation_api = "https://registry.example.test/federation".to_string();

    validate_manifest(&manifest).expect("federation endpoints bind to issuer host");
}

#[test]
fn validation_rejects_federation_endpoints_on_cross_hosts() {
    let mut manifest = federated_evaluation_manifest();
    let federation = manifest.federation.as_mut().expect("federation");
    federation.jwks_uri = "https://keys.example.test/.well-known/jwks.json".to_string();
    federation.federation_api = "https://api.example.test/federation".to_string();

    let error = validate_manifest(&manifest).expect_err("cross-host federation endpoints rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(
        errors.iter().any(|error| {
            error.path == "federation.jwks_uri"
                && error
                    .message
                    .contains("must bind to federation issuer host")
        }),
        "expected JWKS host binding error, got: {errors:?}"
    );
    assert!(
        errors.iter().any(|error| {
            error.path == "federation.federation_api"
                && error
                    .message
                    .contains("must bind to federation issuer host")
        }),
        "expected federation API host binding error, got: {errors:?}"
    );
}

#[test]
fn validation_rejects_did_web_port_mismatch_against_issuer() {
    let mut manifest = federated_evaluation_manifest();
    let federation = manifest.federation.as_mut().expect("federation");
    federation.issuer = "https://registry.example.test:9090".to_string();
    federation.jwks_uri = "https://registry.example.test:9090/.well-known/jwks.json".to_string();
    federation.federation_api = "https://registry.example.test:9090/federation".to_string();
    federation.node_id = "did:web:registry.example.test%3A8080".to_string();

    let error = validate_manifest(&manifest).expect_err("port mismatch rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(
        errors.iter().any(|error| {
            error.path == "federation.node_id"
                && error
                    .message
                    .contains("must bind to federation issuer host")
        }),
        "expected DID:web port mismatch to be reported, got: {errors:?}"
    );
}

#[test]
fn validation_rejects_did_web_with_port_against_default_port_issuer() {
    let mut manifest = federated_evaluation_manifest();
    let federation = manifest.federation.as_mut().expect("federation");
    federation.issuer = "https://registry.example.test".to_string();
    federation.jwks_uri = "https://registry.example.test/.well-known/jwks.json".to_string();
    federation.federation_api = "https://registry.example.test/federation".to_string();
    federation.node_id = "did:web:registry.example.test%3A8443".to_string();

    let error = validate_manifest(&manifest).expect_err("asymmetric port rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(
        errors.iter().any(|error| {
            error.path == "federation.node_id"
                && error
                    .message
                    .contains("must bind to federation issuer host")
        }),
        "expected DID:web port-vs-default-port asymmetry to be reported, got: {errors:?}"
    );
}

#[test]
fn validation_rejects_default_port_did_web_against_issuer_with_port() {
    let mut manifest = federated_evaluation_manifest();
    let federation = manifest.federation.as_mut().expect("federation");
    federation.issuer = "https://registry.example.test:8443".to_string();
    federation.jwks_uri = "https://registry.example.test:8443/.well-known/jwks.json".to_string();
    federation.federation_api = "https://registry.example.test:8443/federation".to_string();
    federation.node_id = "did:web:registry.example.test".to_string();

    let error = validate_manifest(&manifest).expect_err("asymmetric port rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(
        errors.iter().any(|error| {
            error.path == "federation.node_id"
                && error
                    .message
                    .contains("must bind to federation issuer host")
        }),
        "expected DID:web default-vs-explicit-port asymmetry to be reported, got: {errors:?}"
    );
}

#[test]
fn validation_accepts_did_web_port_match_against_issuer() {
    let mut manifest = federated_evaluation_manifest();
    let federation = manifest.federation.as_mut().expect("federation");
    federation.issuer = "https://registry.example.test:8443".to_string();
    federation.jwks_uri = "https://registry.example.test:8443/.well-known/jwks.json".to_string();
    federation.federation_api = "https://registry.example.test:8443/federation".to_string();
    federation.node_id = "did:web:registry.example.test%3A8443".to_string();

    validate_manifest(&manifest).expect("matching port binds");
}

#[test]
fn validation_reports_missing_federation_block_once_across_offerings() {
    let mut manifest = federated_evaluation_manifest();
    manifest.federation = None;
    let template = manifest.datasets[0].evidence_offerings[0].clone();
    for index in 1..3 {
        let mut copy = template.clone();
        copy.id = format!("age_notary_{index}");
        manifest.datasets[0].evidence_offerings.push(copy);
    }

    let error = validate_manifest(&manifest).expect_err("missing federation rejected");
    let MetadataError::Validation { errors } = error else {
        panic!("unexpected error: {error:?}");
    };
    let federation_errors = errors
        .iter()
        .filter(|error| {
            error.path == "federation"
                && error
                    .message
                    .contains("registry-notary access requires a top-level federation block")
        })
        .count();
    assert_eq!(
        federation_errors, 1,
        "expected exactly one federation-missing error, got {federation_errors}: {errors:?}"
    );
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
fn generated_manifest_owned_formats_carry_schema_versions() {
    let compiled = compile_manifest(&service_first_fixture()).expect("compile");

    assert_eq!(
        render_catalog(&compiled)["schema_version"],
        json!("registry-manifest-catalog/v1")
    );

    let evidence_offerings = registry_manifest_core::render_evidence_offerings(&compiled);
    assert_eq!(
        evidence_offerings["schema_version"],
        json!("registry-manifest-evidence-offerings/v1")
    );
    assert_eq!(
        render_evidence_offering(&compiled, "health-coverage-evidence-offering")
            .expect("offering renders")["schema_version"],
        json!("registry-manifest-evidence-offering/v1")
    );

    let policy_collection = render_policy_collection(&compiled);
    assert_eq!(
        policy_collection["schema_version"],
        json!("registry-manifest-policy-collection/v1")
    );
    assert_eq!(
        render_dataset_policy_document(&compiled, "child-support-cases").expect("policy renders")
            ["schema_version"],
        json!("registry-manifest-policy/v1")
    );

    assert_eq!(
        render_shacl(&compiled)["schema_version"],
        json!("registry-manifest-shacl/v1")
    );
    assert_eq!(
        render_ogc_records_items(&compiled)["schema_version"],
        json!("registry-manifest-ogc-records/v1")
    );
    assert_eq!(
        render_entity_schema_draft_2020_12(&compiled, "child-support-cases", "case")
            .expect("entity schema renders")["schema_version"],
        json!("registry-manifest-entity-json-schema/v1")
    );
    assert_eq!(
        render_form_schema_draft_2020_12(&compiled, "child-support-review-form")
            .expect("form schema renders")["schema_version"],
        json!("registry-manifest-form-json-schema/v1")
    );
}

fn contains_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(candidate, value)| candidate == key || contains_key(value, key)),
        Value::Array(values) => values.iter().any(|value| contains_key(value, key)),
        _ => false,
    }
}

#[test]
fn standards_profile_outputs_do_not_carry_manifest_schema_versions() {
    let mut manifest = fixture("example-civil-registration");
    manifest.codelists[0].version = Some("2026.1".to_string());
    manifest.codelists[0].valid_from = Some("2026-06-11".to_string());
    manifest.codelists[0].valid_to = Some("2027-06-11".to_string());
    let compiled = compile_manifest(&manifest).expect("compile");

    for (label, document) in [
        ("BRegDCAT-AP", render_breg_dcat_ap(&compiled)),
        ("base DCAT", render_base_dcat(&compiled)),
        ("CPSV-AP", render_cpsv_ap(&compiled)),
        (
            "profile DCAT",
            render_dcat_profile(&compiled, "bregdcat-ap").expect("profile renders"),
        ),
    ] {
        for key in ["schema_version", "version", "valid_from", "valid_to"] {
            assert!(
                !contains_key(&document, key),
                "{label} is standards-owned and must not carry manifest-owned `{key}` markers"
            );
        }
    }
}

#[test]
fn jsonld_context_maps_manifest_version_terms() {
    let compiled = compile_manifest(&fixture("example-civil-registration")).expect("compile");

    for context in [
        render_shacl(&compiled)["@context"].clone(),
        render_policy_collection(&compiled)["@context"].clone(),
        render_dataset_policy_document(&compiled, "vital-events").expect("policy renders")
            ["@context"]
            .clone(),
    ] {
        assert_eq!(
            context["schema_version"],
            json!("registry_manifest:schemaVersion")
        );
        assert_eq!(context["version"], json!("registry_manifest:version"));
        assert_eq!(context["valid_from"], json!("registry_manifest:validFrom"));
        assert_eq!(context["valid_to"], json!("registry_manifest:validTo"));
    }
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
fn breg_dcat_corporate_body_publisher_renders_controlled_scheme_reference() {
    let manifest: MetadataManifest = serde_yaml_ng::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: corporate-body-publisher
  base_url: https://data.example.test
  title: Corporate Body Publisher
  publisher:
    name: Directorate-General for Digital Services
    iri: http://publications.europa.eu/resource/authority/corporate-body/DIGIT
    authority_type: http://purl.org/adms/publishertype/NonProfitOrganisation
datasets:
  - id: dataset
    title: Dataset
    entities: []
"#,
    )
    .expect("manifest parses");
    let compiled = compile_manifest(&manifest).expect("compile");
    let breg = render_breg_dcat_ap(&compiled);

    assert_eq!(
        breg["dcterms:publisher"]["@id"],
        json!("http://publications.europa.eu/resource/authority/corporate-body/DIGIT")
    );
    assert_eq!(
        breg["dcterms:publisher"]["skos:inScheme"],
        json!("http://publications.europa.eu/resource/authority/corporate-body"),
        "BRegDCAT-AP validator profiles expect MDR corporate-body publishers to carry their controlled scheme"
    );
}

#[test]
fn breg_dcat_declares_both_catalog_theme_taxonomies_for_semic_smoke_checks() {
    let compiled = compile_manifest(&fixture("example-civil-registration")).expect("compile");
    let breg = render_breg_dcat_ap(&compiled);

    assert_eq!(
        breg["dcat:themeTaxonomy"],
        json!([
            "http://publications.europa.eu/resource/authority/data-theme",
            "http://eurovoc.europa.eu/100141"
        ]),
        "The BRegDCAT-AP smoke artifact intentionally exposes both EU data-theme and EuroVoc concept schemes"
    );
}

#[test]
fn compiled_metadata_filter_prunes_hidden_codelists() {
    let manifest = manifest_with_body(
        r#"
datasets:
  - id: people
    title: People
    entities:
      - name: public
        title: Public Person
        identifiers:
          - name: id
            kind: local
        fields:
          - name: id
            type: string
            required: true
          - name: public_status
            type: code
            codelist: public_status
      - name: hidden
        title: Hidden Person
        identifiers:
          - name: id
            kind: local
        fields:
          - name: id
            type: string
            required: true
          - name: hidden_status
            type: code
            codelist: hidden_status
codelists:
  - id: public_status
    scheme_iri: https://registry.example.test/codelists/public-status
    concepts:
      - code: active
  - id: hidden_status
    scheme_iri: https://registry.example.test/codelists/hidden-status
    concepts:
      - code: secret
"#,
    );
    let compiled = compile_manifest(&manifest).expect("compile");
    let scoped = compiled.filter(|_dataset, entity| entity.name == "public");
    let shacl = render_shacl(&scoped);
    let raw = serde_json::to_string(&shacl).expect("SHACL serializes");

    assert!(raw.contains("https://registry.example.test/codelists/public-status"));
    assert!(
        !raw.contains("https://registry.example.test/codelists/hidden-status"),
        "filtered metadata must not retain codelists referenced only by hidden entities"
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
    let manifest: MetadataManifest = serde_yaml_ng::from_str(
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
    let manifest: MetadataManifest = serde_yaml_ng::from_str(
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

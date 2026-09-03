// SPDX-License-Identifier: Apache-2.0

use registry_manifest_core::{
    canonicalize_json, compile_manifest, render_base_dcat, render_catalog, source_manifest_digest,
    validate_manifest, MetadataError, MetadataManifest,
};
use serde_json::json;

const MULTI_DATASET_FIXTURE: &str = include_str!(
    "../../../products/manifest/profiles/example-multi-dataset/fixtures/metadata.yaml"
);

fn fixture() -> MetadataManifest {
    serde_yaml_ng::from_str(MULTI_DATASET_FIXTURE).expect("multi-dataset fixture parses")
}

fn validation_paths(manifest: &MetadataManifest) -> Vec<String> {
    let MetadataError::Validation { errors } =
        validate_manifest(manifest).expect_err("manifest must fail validation")
    else {
        panic!("expected validation errors");
    };
    errors.into_iter().map(|error| error.path).collect()
}

#[test]
fn compiles_and_renders_multi_dataset_distribution_graph() {
    let compiled = compile_manifest(&fixture()).expect("fixture compiles");

    assert_eq!(compiled.datasets().count(), 2);
    assert_eq!(compiled.distributions().count(), 1);
    assert_eq!(
        compiled
            .data_service("registry-api")
            .expect("data service")
            .serves_datasets,
        ["legal-entities", "beneficial-ownership"]
    );
    let dataset = compiled.dataset("legal-entities").expect("dataset");
    assert_eq!(
        dataset.iri,
        "https://data.example.test/datasets/legal-entities"
    );
    assert_eq!(dataset.version.as_deref(), Some("2026.1"));

    let dcat = render_base_dcat(&compiled);
    let datasets = dcat["dcat:dataset"].as_array().expect("DCAT datasets");
    let rendered_dataset = datasets
        .iter()
        .find(|dataset| dataset["dcterms:identifier"] == "legal-entities")
        .expect("legal-entities dataset");
    assert_eq!(
        rendered_dataset["@id"],
        "https://data.example.test/datasets/legal-entities"
    );
    assert_eq!(rendered_dataset["dcat:version"], "2026.1");
    let distribution = &rendered_dataset["dcat:distribution"][0];
    assert_eq!(distribution["@type"], "dcat:Distribution");
    assert_eq!(distribution["dcterms:title"], "Legal entities snapshot");
    assert_eq!(
        distribution["dcterms:description"],
        "Deliberate release snapshot of the legal-entities dataset."
    );
    assert_eq!(
        distribution["dcat:accessService"],
        "https://data.example.test/services/registry-api"
    );
    assert_eq!(
        distribution["dcat:accessURL"],
        "https://api.example.test/v1/legal-entities"
    );
    assert_eq!(
        distribution["dcat:downloadURL"],
        json!({ "@id": "https://downloads.example.test/legal-entities.ndjson" })
    );
    assert_eq!(
        distribution["dcat:mediaType"],
        "https://www.iana.org/assignments/media-types/application/x-ndjson"
    );
    assert_eq!(
        distribution["dcterms:format"],
        "http://publications.europa.eu/resource/authority/file-type/NDJSON"
    );
    assert_eq!(dcat["dcat:service"][0]["@type"], "dcat:DataService");
    assert_eq!(
        dcat["dcat:service"][0]["dcat:endpointURL"],
        "https://api.example.test/v1"
    );
    assert_eq!(
        dcat["dcat:service"][0]["dcat:endpointDescription"],
        "https://api.example.test/openapi.json"
    );
    assert_eq!(
        dcat["dcat:service"][0]["dcat:servesDataset"],
        json!([
            { "@id": "https://data.example.test/datasets/legal-entities" },
            { "@id": "#dataset-beneficial-ownership" }
        ])
    );
    assert!(
        !serde_json::to_string(&dcat)
            .expect("DCAT serializes")
            .contains("dcat:CatalogRecord"),
        "operational Registry records must not be modeled as DCAT catalogue records"
    );
}

#[test]
fn media_type_iris_percent_encode_reserved_token_characters() {
    let mut manifest = fixture();
    manifest.distributions[0].media_type = Some("application/vnd.example#snapshot%v1".to_string());
    let compiled = compile_manifest(&manifest).expect("valid media type compiles");
    let dcat = render_base_dcat(&compiled);
    let dataset = dcat["dcat:dataset"]
        .as_array()
        .unwrap()
        .iter()
        .find(|dataset| dataset["dcterms:identifier"] == "legal-entities")
        .unwrap();
    let distribution = &dataset["dcat:distribution"][0];

    assert_eq!(
        distribution["dcat:mediaType"],
        "https://www.iana.org/assignments/media-types/application/vnd.example%23snapshot%25v1"
    );
}

#[test]
fn rejects_duplicate_and_dangling_distribution_relationships() {
    let mut duplicate = fixture();
    duplicate
        .distributions
        .push(duplicate.distributions[0].clone());
    assert!(validation_paths(&duplicate).contains(&"distributions[1].id".to_string()));

    let mut dangling_dataset = fixture();
    dangling_dataset.distributions[0].dataset = "missing-dataset".to_string();
    assert!(validation_paths(&dangling_dataset).contains(&"distributions[0].dataset".to_string()));

    let mut dangling_service = fixture();
    dangling_service.distributions[0].access_service = Some("missing-service".to_string());
    assert!(validation_paths(&dangling_service)
        .contains(&"distributions[0].access_service".to_string()));

    let mut wrong_membership = fixture();
    wrong_membership.distributions[0].dataset = "beneficial-ownership".to_string();
    wrong_membership.data_services[0]
        .serves_datasets
        .retain(|dataset| dataset != "beneficial-ownership");
    assert!(validation_paths(&wrong_membership)
        .contains(&"distributions[0].access_service".to_string()));

    let mut duplicate_membership = fixture();
    duplicate_membership.data_services[0]
        .serves_datasets
        .push("legal-entities".to_string());
    assert!(validation_paths(&duplicate_membership)
        .contains(&"data_services[0].serves_datasets[2]".to_string()));
}

#[test]
fn rejects_data_service_without_dataset_membership() {
    let mut manifest = fixture();
    manifest.data_services[0].serves_datasets.clear();

    assert!(validation_paths(&manifest).contains(&"data_services[0].serves_datasets".to_string()));
}

#[test]
fn rejects_distribution_without_access_and_malformed_optional_fields() {
    let mut no_access = fixture();
    let distribution = &mut no_access.distributions[0];
    distribution.access_service = None;
    distribution.access_url = None;
    distribution.download_url = None;
    assert!(validation_paths(&no_access).contains(&"distributions[0]".to_string()));

    let mut invalid = fixture();
    invalid.datasets[0].iri = Some("relative-dataset".to_string());
    invalid.datasets[0].version = Some(" ".to_string());
    invalid.distributions[0].access_url = Some("/relative".to_string());
    invalid.distributions[0].download_url = Some("https:///missing-host".to_string());
    invalid.distributions[0].media_type = Some("application/json; charset=utf-8".to_string());
    invalid.distributions[0].format = Some("NDJSON".to_string());
    let paths = validation_paths(&invalid);
    for expected in [
        "datasets[0].iri",
        "datasets[0].version",
        "distributions[0].access_url",
        "distributions[0].download_url",
        "distributions[0].media_type",
        "distributions[0].format",
    ] {
        assert!(
            paths.contains(&expected.to_string()),
            "missing {expected}: {paths:?}"
        );
    }
}

#[test]
fn strict_parser_rejects_missing_dataset_and_unknown_distribution_keys() {
    let missing_dataset = MULTI_DATASET_FIXTURE.replace("    dataset: legal-entities\n", "");
    let error = serde_yaml_ng::from_str::<MetadataManifest>(&missing_dataset)
        .expect_err("distribution dataset is required");
    assert!(error.to_string().contains("dataset"), "{error}");

    let unknown = MULTI_DATASET_FIXTURE.replace(
        "    dataset: legal-entities\n",
        "    dataset: legal-entities\n    access_scope: public\n",
    );
    let error = serde_yaml_ng::from_str::<MetadataManifest>(&unknown)
        .expect_err("unknown distribution key must fail");
    assert!(error.to_string().contains("access_scope"), "{error}");
}

#[test]
fn rejects_distribution_collection_above_the_top_level_bound() {
    let mut manifest = fixture();
    let template = manifest.distributions[0].clone();
    manifest.distributions = (0..257)
        .map(|index| {
            let mut distribution = template.clone();
            distribution.id = format!("distribution-{index}");
            distribution.iri = None;
            distribution
        })
        .collect();

    assert!(validation_paths(&manifest).contains(&"distributions".to_string()));
}

#[test]
fn existing_manifest_canonical_bytes_and_digest_are_unchanged() {
    let absent: MetadataManifest = serde_yaml_ng::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: digest-regression
  base_url: https://metadata.example.test
  title: Digest Regression
  publisher:
    name: Publisher
datasets:
  - id: people
    title: People
    entities: []
"#,
    )
    .expect("baseline parses");
    let explicit_empty: MetadataManifest = serde_yaml_ng::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: digest-regression
  base_url: https://metadata.example.test
  title: Digest Regression
  publisher:
    name: Publisher
datasets:
  - id: people
    title: People
    entities: []
distributions: []
"#,
    )
    .expect("empty distributions parses");
    let canonical = canonicalize_json(&serde_json::to_value(&absent).expect("typed JSON"))
        .expect("canonicalizes");
    let empty_canonical =
        canonicalize_json(&serde_json::to_value(&explicit_empty).expect("empty typed JSON"))
            .expect("empty canonicalizes");

    assert_eq!(canonical, empty_canonical);
    assert_eq!(
        String::from_utf8(canonical).expect("canonical UTF-8"),
        "{\"authorities\":[],\"catalog\":{\"application_profiles\":[],\"base_url\":\"https://metadata.example.test\",\"conforms_to\":[],\"description\":null,\"id\":\"digest-regression\",\"participant_id\":null,\"publisher\":{\"authority_type\":null,\"iri\":null,\"name\":\"Publisher\"},\"standards\":{\"dcat\":null,\"json_schema\":null,\"shacl\":null},\"title\":\"Digest Regression\"},\"codelists\":[],\"data_services\":[],\"datasets\":[{\"access_rights\":\"restricted\",\"applicable_legislation\":[],\"conforms_to\":[],\"description\":null,\"entities\":[],\"evidence_offerings\":[],\"id\":\"people\",\"owner\":null,\"policy\":null,\"public_services\":[],\"sensitivity\":\"public\",\"spatial_coverage\":null,\"status\":null,\"title\":\"People\",\"update_frequency\":\"unknown\"}],\"ecosystem_bindings\":[],\"evaluation_profiles\":[],\"evidence_types\":[],\"forms\":[],\"profiles\":[],\"public_services\":[],\"requirements\":[],\"schema_version\":\"registry-manifest/v1\",\"vocabularies\":{}}"
    );
    assert_eq!(
        source_manifest_digest(&absent).expect("digest"),
        "sha256:9588c8ce3418034b1124731fd4c8777634321d516a67c0f89367de6aa71ee980"
    );
}

#[test]
fn non_empty_new_fields_change_digest_deterministically() {
    let baseline = fixture();
    let baseline_digest = source_manifest_digest(&baseline).expect("baseline digest");

    let mut no_distributions = fixture();
    no_distributions.distributions.clear();
    no_distributions.datasets[0].iri = None;
    no_distributions.datasets[0].version = None;
    let old_shape_digest = source_manifest_digest(&no_distributions).expect("old-shape digest");
    assert_ne!(baseline_digest, old_shape_digest);

    let mut dataset_iri_only = no_distributions.clone();
    dataset_iri_only.datasets[0].iri = baseline.datasets[0].iri.clone();
    assert_ne!(
        old_shape_digest,
        source_manifest_digest(&dataset_iri_only).expect("dataset IRI digest")
    );

    let mut dataset_version_only = no_distributions.clone();
    dataset_version_only.datasets[0].version = baseline.datasets[0].version.clone();
    assert_ne!(
        old_shape_digest,
        source_manifest_digest(&dataset_version_only).expect("dataset version digest")
    );

    let mut distribution_only = no_distributions.clone();
    distribution_only.distributions = baseline.distributions.clone();
    assert_ne!(
        old_shape_digest,
        source_manifest_digest(&distribution_only).expect("distribution digest")
    );

    let reparsed: MetadataManifest =
        serde_yaml_ng::from_str(MULTI_DATASET_FIXTURE).expect("fixture reparses");
    assert_eq!(
        baseline_digest,
        source_manifest_digest(&reparsed).expect("reparsed digest")
    );
}

#[test]
fn filtering_preserves_dataset_version_and_prunes_hidden_distributions() {
    let with_entity = MULTI_DATASET_FIXTURE.replacen(
        "    entities: []",
        "    entities:\n      - name: company\n        fields: []",
        1,
    );
    let mut manifest: MetadataManifest =
        serde_yaml_ng::from_str(&with_entity).expect("entity fixture parses");
    let mut hidden_distribution = manifest.distributions[0].clone();
    hidden_distribution.id = "beneficial-ownership-snapshot".to_string();
    hidden_distribution.iri = None;
    hidden_distribution.dataset = "beneficial-ownership".to_string();
    manifest.distributions.push(hidden_distribution);
    let compiled = compile_manifest(&manifest).expect("fixture compiles");
    let visible = compiled.filter(|dataset, _entity| dataset.dataset_id == "legal-entities");

    assert_eq!(visible.datasets().count(), 1);
    assert_eq!(visible.distributions().count(), 1);
    assert_eq!(
        visible
            .dataset("legal-entities")
            .expect("visible dataset")
            .version
            .as_deref(),
        Some("2026.1")
    );
}

#[test]
fn filtered_catalog_and_dcat_do_not_reveal_hidden_dataset_or_service_relationships() {
    let manifest: MetadataManifest = serde_yaml_ng::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: filtered-resource-model
  base_url: https://metadata.example.test
  title: Filtered resource model
  publisher:
    name: Publisher
public_services:
  - id: registry-service
    title: Registry service
    description: Public service metadata retained after filtering.
    produces: [public-dataset, protected-dataset]
    data_services: [shared-api, protected-api]
data_services:
  - id: shared-api
    title: Shared API
    endpoint_url: https://api.example.test/shared
    serves_datasets: [public-dataset, protected-dataset]
  - id: protected-api
    title: Protected API
    endpoint_url: https://api.example.test/protected
    serves_datasets: [protected-dataset]
datasets:
  - id: public-dataset
    title: Public dataset
    entities:
      - name: public-record
        fields: []
  - id: protected-dataset
    title: Protected dataset
    entities:
      - name: protected-record
        fields: []
distributions:
  - id: public-distribution
    dataset: public-dataset
    access_service: shared-api
  - id: protected-distribution
    dataset: protected-dataset
    access_service: protected-api
"#,
    )
    .expect("filter fixture parses");
    let compiled = compile_manifest(&manifest).expect("filter fixture compiles");
    let filtered = compiled.filter(|_dataset, entity| entity.name == "public-record");

    let catalog = render_catalog(&filtered);
    let catalog_bytes = serde_json::to_string(&catalog).expect("catalog serializes");
    assert!(!catalog_bytes.contains("protected-dataset"), "{catalog}");
    assert!(!catalog_bytes.contains("protected-api"), "{catalog}");
    assert_eq!(catalog["datasets"].as_array().unwrap().len(), 1);
    assert_eq!(catalog["data_services"].as_array().unwrap().len(), 1);
    assert_eq!(
        catalog["data_services"][0]["serves_datasets"],
        json!(["public-dataset"])
    );
    assert_eq!(catalog["distributions"].as_array().unwrap().len(), 1);
    assert_eq!(
        catalog["distributions"][0]["access_service"],
        "https://metadata.example.test/metadata/data-services/shared-api"
    );
    assert_eq!(catalog["public_services"].as_array().unwrap().len(), 1);
    assert_eq!(
        catalog["public_services"][0]["produces"],
        json!(["public-dataset"])
    );
    assert_eq!(
        catalog["public_services"][0]["data_services"],
        json!(["shared-api"])
    );
    assert_eq!(
        catalog["public_services"][0]["title"], "Registry service",
        "filtering must preserve unrelated public-service metadata"
    );

    let dcat = render_base_dcat(&filtered);
    let dcat_bytes = serde_json::to_string(&dcat).expect("DCAT serializes");
    assert!(!dcat_bytes.contains("protected-dataset"), "{dcat}");
    assert!(!dcat_bytes.contains("protected-api"), "{dcat}");
    assert_eq!(dcat["dcat:dataset"].as_array().unwrap().len(), 1);
    assert_eq!(dcat["dcat:service"].as_array().unwrap().len(), 1);
    assert_eq!(
        dcat["dcat:service"][0]["dcat:servesDataset"],
        json!([{ "@id": "#dataset-public-dataset" }])
    );
    assert_eq!(
        dcat["dcat:dataset"][0]["dcat:distribution"][0]["dcat:accessService"],
        "https://metadata.example.test/metadata/data-services/shared-api"
    );
}

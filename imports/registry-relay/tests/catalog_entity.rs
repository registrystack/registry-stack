// SPDX-License-Identifier: Apache-2.0
//! Catalog metadata tests for entity-grain JSON and JSON-LD outputs.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::Extension;
use axum_test::TestServer;
use registry_relay::api::{metadata_router, openapi_router};
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use registry_relay::config;
use registry_relay::entity::EntityRegistry;
use registry_relay::metadata::catalog::catalog_document_for_metadata_scopes;
use registry_relay::metadata::shacl::dcat_ap_document_for_metadata_scopes;
use serde_json::Value;
use tempfile::TempDir;

fn write_config(tmp: &TempDir) -> std::path::PathBuf {
    let path = tmp.path().join("catalog_entity.yaml");
    std::fs::write(
        &path,
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Program Data Catalog
  base_url: https://data.example.test/
  publisher: Ministry of Delivery
  participant_id: did:web:data.example.test

vocabularies:
  psc: https://publicschema.org/
  ex: https://example.test/vocab/

auth:
  mode: api_key
  api_keys: []

datasets:
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Social Ministry
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    conforms_to:
      - ex:profiles/social
    defaults:
      refresh:
        mode: manual
    tables:
      - id: households_table
        source:
          type: file
          path: fixtures/social_registry.csv
        primary_key: household_id
        schema:
          strict: true
          fields:
            - name: household_id
              type: string
              nullable: false
              concept_uri: ex:properties/householdId
            - name: region_code
              type: string
              nullable: true
              concept_uri: ex:properties/regionCode
              codelist: ex:codelists/Region
            - name: internal_note
              type: string
              nullable: true
      - id: individuals_table
        source:
          type: file
          path: fixtures/social_registry.csv
        primary_key: individual_id
        schema:
          strict: true
          fields:
            - name: individual_id
              type: string
              nullable: false
            - name: household_id
              type: string
              nullable: false
            - name: age
              type: integer
              nullable: true
    aggregates:
      - id: households_by_region
        title: Households by region
        description: Household count by region
        source_entity: household
        default_group_by:
          - region
        dimensions:
          - id: region
            label: Region
            field: region
        indicators:
          - id: household_count
            label: Households
            function: count
            column: id
            unit_measure: households
        disclosure_control:
          min_group_size: 2
          suppression: omit
    entities:
      - name: household
        title: Household
        description: Registered household
        table: households_table
        concept_uri: psc:concepts/Household
        fields:
          - name: id
            from: household_id
          - name: region
            from: region_code
            concept_uri: ex:properties/region
        relationships:
          - name: members
            kind: has_many
            target: individual
            foreign_key: household_id
            concept_uri: ex:relationships/householdMember
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          evidence_verification_scope: social_registry:evidence_verification
        api:
          default_limit: 100
          max_limit: 1000
          require_purpose_header: true
          allowed_filters:
            - field: region
              ops: [eq, in]
          allowed_expansions: [members]
        aggregates:
          - id: households_by_region
            description: Household count by region
            group_by:
              - region
            measures:
              - name: household_count
                function: count
                column: id
            disclosure_control:
              min_group_size: 2
              suppression: omit
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
          - name: household_id
          - name: age
        relationships:
          - name: household
            kind: belongs_to
            target: household
            foreign_key: household_id
        access:
          metadata_scope: social_registry:individual:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          evidence_verification_scope: social_registry:evidence_verification
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: household_id
              ops: [eq]
          allowed_expansions: [household]

  - id: payments
    title: Payments
    description: Payment records
    owner: Finance Ministry
    sensitivity: confidential
    access_rights: non_public
    update_frequency: weekly
    defaults:
      refresh:
        mode: manual
    tables:
      - id: payments_table
        source:
          type: file
          path: fixtures/payments.csv
        primary_key: payment_id
        schema:
          strict: true
          fields:
            - name: payment_id
              type: string
              nullable: false
    entities:
      - name: payment
        table: payments_table
        fields:
          - name: id
            from: payment_id
        access:
          metadata_scope: payments:metadata
          aggregate_scope: payments:aggregate
          read_scope: payments:rows
        api:
          default_limit: 100
          max_limit: 1000

audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    path
}

fn server() -> TestServer {
    server_with_scopes(&["social_registry:metadata"])
}

fn server_with_scopes(scopes: &[&str]) -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    server_from_config(write_config(&tmp), scopes)
}

fn server_from_config(path: std::path::PathBuf, scopes: &[&str]) -> TestServer {
    let cfg = Arc::new(config::load(&path).expect("config loads"));
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry compiles"));

    TestServer::new(
        metadata_router()
            .merge(openapi_router())
            .layer(Extension(registry))
            .layer(Extension(cfg))
            .layer(Extension(principal(scopes))),
    )
}

fn aggregate_metadata_config(tmp: &TempDir) -> std::path::PathBuf {
    let path = write_config(tmp);
    let mut body = std::fs::read_to_string(&path).expect("read config");
    body = body.replace("households_by_region", "regional_counts");
    body = body.replace("Households by region", "Regional counts");
    body = body.replace("Household count by region", "Regional total");
    body = body.replace(
        "        source_entity: household\n",
        "        source_entity: household\n        access:\n          metadata_scope: social_registry:aggregate_metadata\n          aggregate_scope: social_registry:aggregate_execute\n",
    );
    std::fs::write(&path, body).expect("write aggregate metadata config");
    path
}

#[cfg(feature = "ogcapi-edr")]
fn spatial_aggregate_metadata_config(tmp: &TempDir) -> std::path::PathBuf {
    let path = aggregate_metadata_config(tmp);
    let mut body = std::fs::read_to_string(&path).expect("read config");
    body = body.replace(
        "            - name: region_code\n              type: string\n              nullable: true\n              concept_uri: ex:properties/regionCode\n              codelist: ex:codelists/Region\n",
        "            - name: region_code\n              type: string\n              nullable: true\n              concept_uri: ex:properties/regionCode\n              codelist: ex:codelists/Region\n            - name: area_geojson\n              type: string\n              nullable: true\n",
    );
    body = body.replace(
        "            unit_measure: households\n",
        "            unit_measure: households\n        allowed_filters:\n          - field: region\n            ops: [in]\n        spatial:\n          mode: admin_area\n          collection_id: regional_counts_area\n          dimension: region\n          geometry_entity: household\n          geometry_id_field: region\n          geometry_field: area_geometry\n",
    );
    body = body.replace(
        "          - name: region\n            from: region_code\n            concept_uri: ex:properties/region\n",
        "          - name: region\n            from: region_code\n            concept_uri: ex:properties/region\n          - name: area_geometry\n            from: area_geojson\n",
    );
    std::fs::write(&path, body).expect("write spatial aggregate metadata config");
    path
}

fn aggregate_metadata_docs_for_scopes(
    scopes: &[&str],
) -> (registry_relay::metadata::catalog::CatalogDocument, Value) {
    let tmp = TempDir::new().expect("tempdir");
    let path = aggregate_metadata_config(&tmp);
    let cfg = config::load(&path).expect("config loads");
    let registry = EntityRegistry::from_config(&cfg).expect("registry compiles");
    let scopes = scopes
        .iter()
        .map(|scope| scope.to_string())
        .collect::<std::collections::BTreeSet<_>>();
    (
        catalog_document_for_metadata_scopes(&cfg, &registry, &scopes),
        dcat_ap_document_for_metadata_scopes(&cfg, &registry, &scopes),
    )
}

#[cfg(feature = "ogcapi-edr")]
fn spatial_aggregate_metadata_docs_for_scopes(
    scopes: &[&str],
) -> (registry_relay::metadata::catalog::CatalogDocument, Value) {
    let tmp = TempDir::new().expect("tempdir");
    let path = spatial_aggregate_metadata_config(&tmp);
    let cfg = config::load(&path).expect("config loads");
    let registry = EntityRegistry::from_config(&cfg).expect("registry compiles");
    let scopes = scopes
        .iter()
        .map(|scope| scope.to_string())
        .collect::<std::collections::BTreeSet<_>>();
    (
        catalog_document_for_metadata_scopes(&cfg, &registry, &scopes),
        dcat_ap_document_for_metadata_scopes(&cfg, &registry, &scopes),
    )
}

fn raw_json(value: &Value) -> String {
    serde_json::to_string(value).expect("json serializes")
}

fn aggregate_distribution_by_access_url<'a>(
    distributions: &'a [Value],
    access_url: &str,
) -> &'a Value {
    distributions
        .iter()
        .find(|distribution| distribution["dcat:accessURL"] == access_url)
        .unwrap_or_else(|| panic!("aggregate distribution {access_url}"))
}

fn server_from_config_without_principal(path: std::path::PathBuf) -> TestServer {
    let cfg = Arc::new(config::load(&path).expect("config loads"));
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry compiles"));

    TestServer::new(
        metadata_router()
            .merge(openapi_router())
            .layer(Extension(registry))
            .layer(Extension(cfg)),
    )
}

#[tokio::test]
async fn metadata_catalog_uses_core_renderer_and_scopes_entities() {
    let resp = server().get("/metadata/catalog").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["id"], "registry-relay");
    assert_eq!(body["datasets"][0]["dataset_id"], "social_registry");
    assert_eq!(body["datasets"][0]["entities"].as_array().unwrap().len(), 1);
    let household = &body["datasets"][0]["entities"][0];
    assert_eq!(household["name"], "household");
    assert_eq!(
        household["fields"][1]["codelist_scheme_iri"],
        "https://example.test/vocab/codelists/Region"
    );
    assert!(!serde_json::to_string(&body)
        .expect("metadata serializes")
        .contains("households_table"));
}

#[tokio::test]
async fn metadata_dataset_surfaces_use_scoped_compiled_metadata() {
    let resp = server().get("/metadata/datasets").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let datasets = body["datasets"].as_array().expect("datasets array");
    assert_eq!(datasets.len(), 1);
    assert_eq!(datasets[0]["dataset_id"], "social_registry");
    assert!(datasets
        .iter()
        .all(|dataset| dataset["dataset_id"] != "payments"));
    assert_eq!(datasets[0]["entities"]["household"]["name"], "household");
    assert!(datasets[0]["entities"].get("individual").is_none());

    let detail_resp = server().get("/metadata/datasets/social_registry").await;
    detail_resp.assert_status(StatusCode::OK);
    let detail: Value = detail_resp.json();
    assert_eq!(detail["dataset_id"], "social_registry");
    assert_eq!(detail["entities"]["household"]["primary_key"], "id");
    assert!(serde_json::to_string(&detail)
        .expect("dataset detail serializes")
        .contains("household"));
    assert!(!serde_json::to_string(&detail)
        .expect("dataset detail serializes")
        .contains("households_table"));
}

#[tokio::test]
async fn metadata_entity_surfaces_list_and_describe_visible_entities() {
    let resp = server()
        .get("/metadata/datasets/social_registry/entities")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["dataset_id"], "social_registry");
    let entities = body["entities"].as_array().expect("entities array");
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0]["name"], "household");
    assert!(entities.iter().all(|entity| entity["name"] != "individual"));

    let entity_resp = server()
        .get("/metadata/datasets/social_registry/entities/household")
        .await;
    entity_resp.assert_status(StatusCode::OK);
    let entity: Value = entity_resp.json();
    assert_eq!(entity["name"], "household");
    assert_eq!(
        entity["fields"]["region"]["codelist_scheme_iri"],
        "https://example.test/vocab/codelists/Region"
    );
    assert!(!serde_json::to_string(&entity)
        .expect("entity detail serializes")
        .contains("region_code"));
}

#[tokio::test]
async fn metadata_dataset_surfaces_do_not_reveal_hidden_datasets_or_entities() {
    let hidden_dataset = server().get("/metadata/datasets/payments").await;
    hidden_dataset.assert_status(StatusCode::NOT_FOUND);
    let hidden_dataset_body: Value = hidden_dataset.json();
    assert_eq!(hidden_dataset_body["code"], "schema.unknown_dataset");

    let hidden_entity = server()
        .get("/metadata/datasets/social_registry/entities/individual")
        .await;
    hidden_entity.assert_status(StatusCode::NOT_FOUND);
    let hidden_entity_body: Value = hidden_entity.json();
    assert_eq!(hidden_entity_body["code"], "schema.unknown_resource");
}

#[tokio::test]
async fn metadata_policy_surfaces_are_dataset_scoped_and_json_ld() {
    let resp = server().get("/metadata/policies").await;

    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.header("content-type"), "application/ld+json");
    let body: Value = resp.json();
    assert_eq!(body["@id"], "https://data.example.test/metadata/policies");
    let policies = body["@graph"].as_array().expect("policy graph");
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0]["@id"], "#policy-social_registry-offer");
    assert_eq!(policies[0]["@type"], "odrl:Offer");
    assert_eq!(
        policies[0]["odrl:permission"][0]["odrl:target"]["@id"],
        "#dataset-social_registry"
    );
    assert!(!serde_json::to_string(&body)
        .expect("policies serialize")
        .contains("payments"));
}

#[tokio::test]
async fn metadata_dataset_policy_returns_one_visible_dataset_policy() {
    let resp = server()
        .get("/metadata/datasets/social_registry/policy")
        .await;

    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.header("content-type"), "application/ld+json");
    let body: Value = resp.json();
    assert_eq!(body["@context"]["odrl"], "http://www.w3.org/ns/odrl/2/");
    assert_eq!(body["@id"], "#policy-social_registry-offer");
    assert_eq!(body["odrl:uid"], "#policy-social_registry-offer");
    assert_eq!(
        body["odrl:permission"]
            .as_array()
            .expect("permission")
            .len(),
        1
    );

    let hidden = server().get("/metadata/datasets/payments/policy").await;
    hidden.assert_status(StatusCode::NOT_FOUND);
    let hidden_body: Value = hidden.json();
    assert_eq!(hidden_body["code"], "schema.unknown_dataset");
}

#[tokio::test]
async fn metadata_entity_schema_is_draft_2020_12() {
    let resp = server()
        .get("/metadata/schema/social_registry/household/schema.json")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(
        body["$id"],
        "https://data.example.test/metadata/schema/social_registry/household/schema.json"
    );
    assert_eq!(
        body["properties"]["region"]["x-codelist"],
        "https://example.test/vocab/codelists/Region"
    );
}

#[tokio::test]
async fn metadata_landing_links_resolve_to_profile_dcat() {
    let landing_resp = server().get("/metadata").await;
    landing_resp.assert_status(StatusCode::OK);
    let landing: Value = landing_resp.json();
    let breg_link = landing["links"]
        .as_array()
        .expect("links")
        .iter()
        .find(|link| link["href"] == "/metadata/dcat/bregdcat-ap")
        .expect("bregdcat link");

    let resp = server()
        .get(breg_link["href"].as_str().expect("href string"))
        .await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body["@id"],
        "https://data.example.test/metadata/dcat.bregdcat-ap.jsonld"
    );
}

#[tokio::test]
async fn metadata_routes_enforce_metadata_scope() {
    let resp = server_with_scopes(&[]).get("/metadata/catalog").await;

    resp.assert_status(StatusCode::FORBIDDEN);
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}

#[tokio::test]
async fn legacy_catalog_routes_are_not_mounted() {
    let server = server();

    server
        .get("/catalog")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    server
        .get("/catalog/dcat-ap.jsonld")
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[cfg(feature = "ogcapi-features")]
fn spatial_catalog_server() -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(&tmp);
    let mut body = std::fs::read_to_string(&path).expect("read config");
    body = body.replace(
        "            - name: region_code\n              type: string\n              nullable: true\n              concept_uri: ex:properties/regionCode\n              codelist: ex:codelists/Region\n",
        "            - name: region_code\n              type: string\n              nullable: true\n              concept_uri: ex:properties/regionCode\n              codelist: ex:codelists/Region\n            - name: lon\n              type: number\n              nullable: true\n            - name: lat\n              type: number\n              nullable: true\n",
    );
    body = body.replace(
        "          - name: region\n            from: region_code\n            concept_uri: ex:properties/region\n",
        "          - name: region\n            from: region_code\n            concept_uri: ex:properties/region\n          - name: lon\n          - name: lat\n        spatial:\n          collection_id: households\n          title: Household locations\n          geometry:\n            kind: point\n            longitude_field: lon\n            latitude_field: lat\n            crs: http://www.opengis.net/def/crs/OGC/1.3/CRS84\n",
    );
    std::fs::write(&path, body).expect("write spatial config");
    server_from_config(path, &["social_registry:metadata"])
}

#[cfg(feature = "spdci-api-standards")]
fn spdci_catalog_server() -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(&tmp);
    let mut body = std::fs::read_to_string(&path).expect("read config");
    body = body.replace(
        "auth:\n  mode: api_key\n  api_keys: []\n",
        "auth:\n  mode: api_key\n  api_keys: []\n\nstandards:\n  spdci:\n    registries:\n      sr:\n        dataset: social_registry\n        entity: household\n        registry_type: ns:org:RegistryType:SR\n        record_type: spdci-extensions-social:Group\n        identifiers:\n          REGION: region\n        expression_fields:\n          region: region\n",
    );
    std::fs::write(&path, body).expect("write SP DCI config");
    server_from_config(path, &["social_registry:metadata"])
}

fn principal(scopes: &[&str]) -> Principal {
    Principal {
        principal_id: "test".to_string(),
        scopes: scopes.iter().copied().collect::<ScopeSet>(),
        auth_mode: AuthMode::ApiKey,
    }
}

fn assert_private_metadata_headers(resp: &axum_test::TestResponse) {
    assert_eq!(resp.header("cache-control"), "private, no-store");
    assert_eq!(resp.header("vary"), "Authorization");
}

fn entity<'a>(body: &'a Value, name: &str) -> &'a Value {
    body["datasets"][0]["entities"]
        .as_array()
        .expect("entities array")
        .iter()
        .find(|entity| entity["name"] == name)
        .expect("entity present")
}

#[tokio::test]
async fn scope_filtered_metadata_responses_are_private_no_store() {
    let server = server();

    let catalog = server.get("/metadata/catalog").await;
    catalog.assert_status(StatusCode::OK);
    assert_private_metadata_headers(&catalog);

    let dcat = server.get("/metadata/dcat").await;
    dcat.assert_status(StatusCode::OK);
    assert_private_metadata_headers(&dcat);

    let schema = server
        .get("/metadata/schema/social_registry/household/schema.json")
        .await;
    schema.assert_status(StatusCode::OK);
    assert_private_metadata_headers(&schema);
}

fn assert_structural_dcat_shacl(body: &Value) {
    assert_eq!(body["@type"], "dcat:Catalog");
    assert_eq!(body["@context"]["dcat"], "http://www.w3.org/ns/dcat#");
    assert_eq!(body["@context"]["dcterms"], "http://purl.org/dc/terms/");
    assert!(
        body["@context"]["dct"].is_null(),
        "redundant dct alias must not be present: use dcterms exclusively"
    );
    assert!(
        body["@context"]["dspace"].is_null(),
        "Registry Relay does not publish Dataspace Protocol participant claims"
    );
    assert_eq!(body["@context"]["odrl"], "http://www.w3.org/ns/odrl/2/");
    assert_eq!(body["@context"]["sh"], "http://www.w3.org/ns/shacl#");
    assert_eq!(body["@context"]["xsd"], "http://www.w3.org/2001/XMLSchema#");
    assert_eq!(body["@context"]["dcat:accessService"]["@type"], "@id");
    assert_eq!(body["@context"]["dcat:dataset"]["@type"], "@id");
    assert_eq!(body["@context"]["dcat:distribution"]["@type"], "@id");
    assert_eq!(body["@context"]["dcat:landingPage"]["@type"], "@id");
    assert_eq!(body["@context"]["dcat:mediaType"]["@type"], "@id");
    assert_eq!(body["@context"]["dcat:servesDataset"]["@type"], "@id");
    assert_eq!(body["@context"]["dcat:themeTaxonomy"]["@type"], "@id");
    assert_eq!(body["@context"]["dcterms:format"]["@type"], "@id");
    assert_eq!(body["@context"]["odrl:action"]["@type"], "@id");
    assert_eq!(body["@context"]["odrl:assigner"]["@type"], "@id");
    assert_eq!(body["@context"]["odrl:hasPolicy"]["@type"], "@id");
    assert_eq!(body["@context"]["odrl:leftOperand"]["@type"], "@id");
    assert_eq!(body["@context"]["odrl:operator"]["@type"], "@id");
    assert_eq!(body["@context"]["odrl:profile"]["@type"], "@id");
    assert_eq!(body["@context"]["odrl:target"]["@type"], "@id");
    assert_eq!(body["@context"]["odrl:uid"]["@type"], "@id");
    assert_eq!(body["@context"]["sh:datatype"]["@type"], "@id");
    assert_eq!(body["@context"]["sh:nodeKind"]["@type"], "@id");
    assert_eq!(body["@context"]["sh:path"]["@type"], "@id");
    assert_eq!(body["@context"]["sh:targetClass"]["@type"], "@id");
    assert!(body["dcat:dataset"]
        .as_array()
        .expect("datasets")
        .iter()
        .all(|dataset| {
            dataset["@type"] == "dcat:Dataset"
                && dataset["@id"].is_string()
                && dataset["dcterms:title"].is_string()
                && dataset["dcterms:description"].is_string()
                && dataset["dcat:landingPage"].is_string()
                && dataset["odrl:hasPolicy"]["@type"] == "odrl:Offer"
        }));
    assert!(body["sh:shapesGraph"]
        .as_array()
        .expect("shapes graph")
        .iter()
        .all(|shape| {
            shape["@type"] == "sh:NodeShape"
                && shape["@id"].is_string()
                && shape["sh:targetClass"].is_string()
                && shape["sh:nodeKind"] == "sh:IRI"
                && shape["sh:property"].as_array().is_some_and(|properties| {
                    properties.iter().all(|property| {
                        property["@type"] == "sh:PropertyShape"
                            && property["sh:path"].is_string()
                            && property["sh:name"].is_string()
                            && property["sh:nodeKind"].is_string()
                    })
                })
        }));
}

fn assert_distributions_do_not_contain(body: &Value, needle: &str) {
    let Some(distributions) = body["dcat:dataset"][0]["dcat:distribution"].as_array() else {
        return;
    };
    assert!(!distributions
        .iter()
        .any(|distribution| serde_json::to_string(distribution)
            .expect("distribution serializes")
            .contains(needle)));
}

#[tokio::test]
async fn catalog_lists_entity_grain_metadata_without_hidden_columns() {
    let resp = server().get("/metadata/catalog").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["base_url"], "https://data.example.test");
    assert_eq!(body["datasets"][0]["dataset_id"], "social_registry");
    assert_eq!(body["datasets"].as_array().expect("datasets").len(), 1);
    assert!(body["datasets"][0]["entities"]
        .as_array()
        .expect("entities")
        .iter()
        .all(|entity| entity["name"] != "individual"));
    assert!(body["datasets"]
        .as_array()
        .expect("datasets")
        .iter()
        .all(|dataset| dataset["dataset_id"] != "payments"));
    assert_eq!(
        body["datasets"][0]["conforms_to"][0],
        "https://example.test/vocab/profiles/social"
    );

    let household = entity(&body, "household");
    assert_eq!(household["primary_key"], "id");
    assert_eq!(
        household["concept_uri"],
        "https://publicschema.org/concepts/Household"
    );
    assert_eq!(household["fields"].as_array().expect("fields").len(), 2);
    assert_eq!(household["fields"][1]["name"], "region");
    assert_eq!(household["fields"][1]["type"], "code");
    assert_eq!(household["fields"][1]["required"], false);
    assert_eq!(
        household["fields"][1]["concepts"][0],
        "https://example.test/vocab/properties/region"
    );
    assert_eq!(
        household["fields"][1]["codelist_scheme_iri"],
        "https://example.test/vocab/codelists/Region"
    );
    assert!(household["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .all(|field| field["name"] != "internal_note"));
    assert!(household["relationships"]
        .as_array()
        .expect("relationships")
        .is_empty());
}

#[test]
fn catalog_aggregate_distributions_follow_aggregate_and_source_metadata_scopes() {
    let (catalog, _) = aggregate_metadata_docs_for_scopes(&[
        "social_registry:metadata",
        "social_registry:aggregate_metadata",
    ]);

    let aggregate_distributions = &serde_json::to_value(&catalog).expect("catalog serializes")
        ["datasets"][0]["aggregate_distributions"];
    let distributions = aggregate_distributions
        .as_array()
        .expect("aggregate distributions");
    assert_eq!(distributions.len(), 1);
    assert_eq!(
        distributions[0]["aggregate_url"],
        "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts"
    );
    assert_eq!(
        distributions[0]["metadata_url"],
        "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts/structure"
    );
    assert_eq!(distributions[0]["aggregate_id"], "regional_counts");
    assert_eq!(distributions[0]["title"], "Regional counts");
    assert_eq!(distributions[0]["description"], "Regional total");
    let representations = distributions[0]["representations"]
        .as_array()
        .expect("aggregate representations");
    assert_eq!(representations.len(), 3);
    assert!(representations.iter().any(|representation| {
        representation["format"] == "json"
            && representation["access_url"]
                == "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts?f=json"
            && representation["media_type"] == "application/json"
            && representation["conforms_to"]
                .as_array()
                .expect("json conforms_to")
                .iter()
                .any(|value| value == "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts/structure")
    }));
    assert!(representations.iter().any(|representation| {
        representation["format"] == "sdmx-json"
            && representation["access_url"]
                == "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts?f=sdmx-json"
            && representation["media_type"] == "application/vnd.sdmx.data+json;version=2.1"
            && representation["conforms_to"]
                .as_array()
                .expect("sdmx conforms_to")
                .iter()
                .any(|value| value == "https://json.sdmx.org/2.1/sdmx-json-data-schema.json")
    }));
    assert!(representations.iter().any(|representation| {
        representation["format"] == "csv"
            && representation["access_url"]
                == "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts?f=csv"
            && representation["media_type"] == "text/csv"
            && representation["conforms_to"]
                .as_array()
                .expect("csv conforms_to")
                .iter()
                .any(|value| value == "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts/structure")
    }));

    let (source_only, _) = aggregate_metadata_docs_for_scopes(&["social_registry:metadata"]);
    assert!(source_only.datasets[0].aggregate_distributions.is_empty());

    let (execution_only, _) = aggregate_metadata_docs_for_scopes(&[
        "social_registry:metadata",
        "social_registry:aggregate_execute",
        "social_registry:rows",
    ]);
    assert!(execution_only.datasets[0]
        .aggregate_distributions
        .is_empty());

    let (aggregate_without_source, _) =
        aggregate_metadata_docs_for_scopes(&["social_registry:aggregate_metadata"]);
    assert!(aggregate_without_source.datasets.is_empty());
}

#[test]
fn dcat_aggregate_distributions_are_thin_and_do_not_leak_sources() {
    let (_, dcat) = aggregate_metadata_docs_for_scopes(&[
        "social_registry:metadata",
        "social_registry:aggregate_metadata",
    ]);

    let distributions = dcat["dcat:dataset"][0]["dcat:distribution"]
        .as_array()
        .expect("dcat distributions");
    let native = aggregate_distribution_by_access_url(
        distributions,
        "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts?f=json",
    );
    let sdmx = aggregate_distribution_by_access_url(
        distributions,
        "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts?f=sdmx-json",
    );
    let csv = aggregate_distribution_by_access_url(
        distributions,
        "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts?f=csv",
    );
    assert_eq!(native["@type"], "dcat:Distribution");
    assert_eq!(sdmx["@type"], "dcat:Distribution");
    assert_eq!(csv["@type"], "dcat:Distribution");
    assert_eq!(native["dcterms:title"], "Regional counts native JSON");
    assert_eq!(sdmx["dcterms:title"], "Regional counts SDMX JSON");
    assert_eq!(csv["dcterms:title"], "Regional counts CSV");
    assert_eq!(
        native["dcterms:description"],
        "Regional total as native JSON."
    );
    assert_eq!(sdmx["dcterms:description"], "Regional total as SDMX JSON.");
    assert_eq!(csv["dcterms:description"], "Regional total as CSV.");
    assert_eq!(native["dcterms:format"]["rdfs:label"], "application/json");
    assert_eq!(
        sdmx["dcterms:format"]["rdfs:label"],
        "application/vnd.sdmx.data+json;version=2.1"
    );
    assert_eq!(csv["dcterms:format"]["rdfs:label"], "text/csv");
    assert!(native["dcterms:conformsTo"]
        .as_array()
        .expect("native conforms_to")
        .iter()
        .any(|value| value
            == "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts/structure"));
    assert!(sdmx["dcterms:conformsTo"]
        .as_array()
        .expect("sdmx conforms_to")
        .iter()
        .any(|value| value == "https://json.sdmx.org/2.1/sdmx-json-data-schema.json"));
    assert!(csv["dcterms:conformsTo"]
        .as_array()
        .expect("csv conforms_to")
        .iter()
        .any(|value| value
            == "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts/structure"));
    for aggregate_distribution in [native, sdmx, csv] {
        assert!(aggregate_distribution["dcat:endpointDescription"].is_null());
        assert_eq!(
            aggregate_distribution["dcat:accessService"]["@type"],
            "dcat:DataService"
        );
        assert_eq!(
            aggregate_distribution["dcat:accessService"]["dcat:endpointURL"],
            "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts"
        );
        assert!(aggregate_distribution["dcat:accessService"]["dcat:endpointDescription"].is_null());
    }

    let raw = raw_json(&Value::Array(vec![
        native.clone(),
        sdmx.clone(),
        csv.clone(),
    ]));
    for leaked in [
        "source_entity",
        "household",
        "households_table",
        "individuals_table",
        "fixtures/social_registry.csv",
        "region_code",
        "household_id",
        "individual_id",
        "\"column\"",
    ] {
        assert!(
            !raw.contains(leaked),
            "aggregate distribution leaked internal detail {leaked}: {raw}"
        );
    }

    let (_, source_only_dcat) = aggregate_metadata_docs_for_scopes(&["social_registry:metadata"]);
    assert!(source_only_dcat["dcat:dataset"][0]["dcat:distribution"]
        .as_array()
        .expect("dcat distributions")
        .iter()
        .all(|distribution| distribution["dcat:accessURL"]
            != "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts?f=json"));
}

#[cfg(feature = "ogcapi-edr")]
#[test]
fn spatial_aggregate_catalog_advertises_ogc_edr_representation() {
    let (catalog, _) = spatial_aggregate_metadata_docs_for_scopes(&[
        "social_registry:metadata",
        "social_registry:aggregate_metadata",
    ]);
    let aggregate_distributions = &serde_json::to_value(&catalog).expect("catalog serializes")
        ["datasets"][0]["aggregate_distributions"];
    let distributions = aggregate_distributions
        .as_array()
        .expect("aggregate distributions");
    let representations = distributions[0]["representations"]
        .as_array()
        .expect("aggregate representations");

    assert_eq!(representations.len(), 4);
    let edr = representations
        .iter()
        .find(|representation| representation["format"] == "ogc-edr-area")
        .expect("OGC EDR area representation");
    assert_eq!(
        edr["access_url"],
        "https://data.example.test/ogc/edr/v1/collections/regional_counts_area/area"
    );
    assert_eq!(edr["media_type"], "application/geo+json");
    assert!(edr["conforms_to"]
        .as_array()
        .expect("edr conforms_to")
        .iter()
        .any(|value| value == "http://www.opengis.net/spec/ogcapi-edr-1/1.1/conf/area"));
    assert!(edr["conforms_to"]
        .as_array()
        .expect("edr conforms_to")
        .iter()
        .any(|value| value
            == "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts/structure"));
}

#[cfg(feature = "ogcapi-edr")]
#[test]
fn dcat_spatial_aggregate_includes_ogc_edr_distribution_and_service() {
    let (_, dcat) = spatial_aggregate_metadata_docs_for_scopes(&[
        "social_registry:metadata",
        "social_registry:aggregate_metadata",
    ]);

    let distributions = dcat["dcat:dataset"][0]["dcat:distribution"]
        .as_array()
        .expect("dcat distributions");
    let edr = aggregate_distribution_by_access_url(
        distributions,
        "https://data.example.test/ogc/edr/v1/collections/regional_counts_area/area",
    );

    assert_eq!(edr["@type"], "dcat:Distribution");
    assert_eq!(edr["dcterms:title"], "Regional counts OGC EDR area");
    assert_eq!(edr["dcterms:format"]["rdfs:label"], "application/geo+json");
    assert_eq!(
        edr["dcat:accessService"]["@id"],
        "https://data.example.test/ogc/edr/v1/collections/regional_counts_area/area#aggregate-query-service"
    );
    assert_eq!(
        edr["dcat:accessService"]["dcat:endpointURL"],
        "https://data.example.test/ogc/edr/v1/collections/regional_counts_area/area"
    );
    assert!(edr["dcat:accessService"]["dcterms:conformsTo"]
        .as_array()
        .expect("service conforms_to")
        .iter()
        .any(|value| value == "http://www.opengis.net/spec/ogcapi-edr-1/1.1/conf/area"));
    assert!(edr["dcterms:conformsTo"]
        .as_array()
        .expect("distribution conforms_to")
        .iter()
        .any(|value| value
            == "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts/structure"));
}

#[tokio::test]
async fn public_dcat_includes_visible_aggregate_distributions() {
    let tmp = TempDir::new().expect("tempdir");
    let path = aggregate_metadata_config(&tmp);
    let server = server_from_config(
        path,
        &[
            "social_registry:metadata",
            "social_registry:aggregate_metadata",
        ],
    );

    let resp = server.get("/metadata/dcat").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let distributions = body["dcat:dataset"][0]["dcat:distribution"]
        .as_array()
        .expect("dcat distributions");
    assert!(distributions.iter().any(|distribution| {
        distribution["dcat:accessURL"]
            == "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts?f=json"
    }));
    assert!(distributions.iter().any(|distribution| {
        distribution["dcat:accessURL"]
            == "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts?f=sdmx-json"
    }));
    assert!(distributions.iter().any(|distribution| {
        distribution["dcat:accessURL"]
            == "https://data.example.test/v1/datasets/social_registry/aggregates/regional_counts?f=csv"
    }));
}

#[tokio::test]
async fn dcat_allows_aggregate_metadata_scope_without_entity_metadata_scope() {
    let tmp = TempDir::new().expect("tempdir");
    let path = aggregate_metadata_config(&tmp);
    let server = server_from_config(path, &["social_registry:aggregate_metadata"]);

    let resp = server.get("/metadata/dcat").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body["dcat:dataset"]
            .as_array()
            .expect("dcat dataset array")
            .len(),
        0,
        "aggregate-only metadata scope authorizes DCAT but must not reveal source-backed datasets"
    );
}

#[cfg(not(feature = "ogcapi-features"))]
#[tokio::test]
async fn spatial_config_fails_closed_when_ogc_features_disabled() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(&tmp);
    let mut body = std::fs::read_to_string(&path).expect("read config");
    body = body.replace(
        "            - name: region_code\n              type: string\n              nullable: true\n              concept_uri: ex:properties/regionCode\n              codelist: ex:codelists/Region\n",
        "            - name: region_code\n              type: string\n              nullable: true\n              concept_uri: ex:properties/regionCode\n              codelist: ex:codelists/Region\n            - name: lon\n              type: number\n              nullable: true\n            - name: lat\n              type: number\n              nullable: true\n",
    );
    body = body.replace(
        "          - name: region\n            from: region_code\n            concept_uri: ex:properties/region\n",
        "          - name: region\n            from: region_code\n            concept_uri: ex:properties/region\n          - name: lon\n          - name: lat\n        spatial:\n          collection_id: households\n          title: Household locations\n          geometry:\n            kind: point\n            longitude_field: lon\n            latitude_field: lat\n            crs: http://www.opengis.net/def/crs/OGC/1.3/CRS84\n",
    );
    std::fs::write(&path, body).expect("write spatial config");

    let err = config::load(&path).expect_err("spatial config rejected without OGC feature");
    assert_eq!(err.to_string(), "ogc api features feature disabled");
}

#[cfg(feature = "ogcapi-features")]
#[tokio::test]
async fn portable_metadata_keeps_ogc_runtime_routes_out_of_dcat() {
    let server = spatial_catalog_server();
    let catalog_resp = server.get("/metadata/catalog").await;

    catalog_resp.assert_status(StatusCode::OK);
    let catalog: Value = catalog_resp.json();
    let household = entity(&catalog, "household");
    assert!(household.get("links").is_none());

    let dcat_resp = server.get("/metadata/dcat/bregdcat-ap").await;
    dcat_resp.assert_status(StatusCode::OK);
    let dcat: Value = dcat_resp.json();
    assert_distributions_do_not_contain(&dcat, "/ogc/v1/");
}

#[cfg(feature = "ogcapi-records")]
#[tokio::test]
async fn catalog_and_dcat_advertise_ogc_records_for_visible_datasets() {
    let server = server();

    let catalog_resp = server.get("/metadata/catalog").await;
    catalog_resp.assert_status(StatusCode::OK);
    let catalog: Value = catalog_resp.json();
    assert!(catalog["datasets"][0].get("links").is_none());

    let dcat_resp = server.get("/metadata/dcat/bregdcat-ap").await;
    dcat_resp.assert_status(StatusCode::OK);
    let dcat: Value = dcat_resp.json();
    assert!(dcat["dcat:service"].is_null());
    assert_distributions_do_not_contain(&dcat, "/ogc/v1/records");
}

#[cfg(not(feature = "ogcapi-records"))]
#[tokio::test]
async fn catalog_does_not_advertise_ogc_records_when_feature_is_disabled() {
    let server = server();

    let catalog_resp = server.get("/metadata/catalog").await;
    catalog_resp.assert_status(StatusCode::OK);
    let catalog: Value = catalog_resp.json();
    assert!(catalog["datasets"][0].get("links").is_none());

    let dcat_resp = server.get("/metadata/dcat/bregdcat-ap").await;
    dcat_resp.assert_status(StatusCode::OK);
    let dcat: Value = dcat_resp.json();
    assert_distributions_do_not_contain(&dcat, "/ogc/v1/records");
}

#[cfg(feature = "spdci-api-standards")]
#[tokio::test]
async fn portable_metadata_keeps_spdci_runtime_routes_out_of_dcat() {
    let server = spdci_catalog_server();
    let catalog_resp = server.get("/metadata/catalog").await;

    catalog_resp.assert_status(StatusCode::OK);
    let catalog: Value = catalog_resp.json();
    assert!(catalog["datasets"][0].get("standards").is_none());

    let dcat_resp = server.get("/metadata/dcat/bregdcat-ap").await;
    dcat_resp.assert_status(StatusCode::OK);
    let dcat: Value = dcat_resp.json();
    assert_distributions_do_not_contain(&dcat, "/dci/");
}

// --- BRegDCAT-AP 3.0.0 extension tests ---

fn bregdcat_server() -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(&tmp);
    let mut body = std::fs::read_to_string(&path).expect("read config");
    // Add spatial_coverage and status on the dataset, publisher vocabulary on catalog,
    // and a second dataset with a codelist field to test dct:references.
    // BRegDCAT-AP 2.1.0 checks publisher values against the EU corporate-body
    // scheme and publisher type values against ADMS publishertype.
    body = body.replace(
        "catalog:\n  title: Program Data Catalog\n  base_url: https://data.example.test/\n  publisher: Ministry of Delivery\n  participant_id: did:web:data.example.test",
        "catalog:\n  title: Program Data Catalog\n  base_url: https://data.example.test/\n  publisher: Ministry of Delivery\n  participant_id: did:web:data.example.test\n  publisher_iri: http://publications.europa.eu/resource/authority/corporate-body/DIGIT\n  authority_type: http://purl.org/adms/publishertype/NationalAuthority\n  default_spatial_coverage: http://publications.europa.eu/resource/authority/country/NLD",
    );
    body = body.replace(
        "  - id: social_registry\n    title: Social Registry\n    description: Synthetic registry\n    owner: Social Ministry\n    sensitivity: personal\n    access_rights: restricted\n    update_frequency: monthly",
        "  - id: social_registry\n    title: Social Registry\n    description: Synthetic registry\n    owner: Social Ministry\n    sensitivity: personal\n    access_rights: restricted\n    update_frequency: monthly\n    status: completed\n    spatial_coverage: http://publications.europa.eu/resource/authority/country/BEL",
    );
    std::fs::write(&path, body).expect("write bregdcat config");
    server_from_config(path, &["social_registry:metadata"])
}

fn hidden_codelist_bregdcat_server() -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(&tmp);
    let mut body = std::fs::read_to_string(&path).expect("read config");
    body = body.replace(
        "            - name: age\n              type: integer\n              nullable: true\n",
        "            - name: age\n              type: integer\n              nullable: true\n              codelist: ex:codelists/HiddenAgeBand\n",
    );
    std::fs::write(&path, body).expect("write hidden codelist config");
    server_from_config(path, &["social_registry:metadata"])
}

// Note: `dcterms:identifier` on dcat:Dataset is pre-existing DCAT-AP behavior
// and is implicitly exercised by the BRegDCAT-AP tests below that read other
// `dcterms:*` fields from the same dataset object. It is not BRegDCAT-AP-specific
// and intentionally does not get its own bregdcat_* test.

#[tokio::test]
async fn bregdcat_dataset_has_dct_spatial_from_dataset_config() {
    let resp = bregdcat_server().get("/metadata/dcat/bregdcat-ap").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    // Dataset-level spatial_coverage overrides the catalog default.
    assert_eq!(
        body["dcat:dataset"][0]["dcterms:spatial"],
        "http://publications.europa.eu/resource/authority/country/BEL"
    );
}

#[tokio::test]
async fn bregdcat_dataset_falls_back_to_default_spatial_coverage() {
    // Use a config with no per-dataset spatial_coverage but with a catalog default.
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(&tmp);
    let mut body = std::fs::read_to_string(&path).expect("read config");
    body = body.replace(
        "catalog:\n  title: Program Data Catalog\n  base_url: https://data.example.test/\n  publisher: Ministry of Delivery\n  participant_id: did:web:data.example.test",
        "catalog:\n  title: Program Data Catalog\n  base_url: https://data.example.test/\n  publisher: Ministry of Delivery\n  participant_id: did:web:data.example.test\n  default_spatial_coverage: http://publications.europa.eu/resource/authority/country/NLD",
    );
    std::fs::write(&path, body).expect("write config");
    let resp = server_from_config(path, &["social_registry:metadata"])
        .get("/metadata/dcat/bregdcat-ap")
        .await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body["dcat:dataset"][0]["dcterms:spatial"],
        "http://publications.europa.eu/resource/authority/country/NLD"
    );
}

#[tokio::test]
async fn bregdcat_dataset_omits_dct_spatial_when_not_configured() {
    let resp = server().get("/metadata/dcat/bregdcat-ap").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert!(
        body["dcat:dataset"][0]["dcterms:spatial"].is_null(),
        "dcterms:spatial must be absent when not configured"
    );
}

#[tokio::test]
async fn bregdcat_dataset_adms_status_context_aliases_are_present() {
    // Verifies the JSON-LD `@type: @id` alias for adms:status and the adms
    // namespace binding. URI mapping for each enum variant is covered by
    // `bregdcat_adms_status_emits_canonical_uri_for_each_variant`.
    let resp = bregdcat_server().get("/metadata/dcat/bregdcat-ap").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["@context"]["adms"], "http://www.w3.org/ns/adms#");
    assert_eq!(body["@context"]["adms:status"]["@type"], "@id");
}

async fn dataset_adms_status_for_config_value(yaml_status: &str) -> String {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(&tmp);
    let mut body = std::fs::read_to_string(&path).expect("read config");
    body = body.replace(
        "  - id: social_registry\n    title: Social Registry\n    description: Synthetic registry\n    owner: Social Ministry\n    sensitivity: personal\n    access_rights: restricted\n    update_frequency: monthly",
        &format!(
            "  - id: social_registry\n    title: Social Registry\n    description: Synthetic registry\n    owner: Social Ministry\n    sensitivity: personal\n    access_rights: restricted\n    update_frequency: monthly\n    status: {yaml_status}"
        ),
    );
    std::fs::write(&path, body).expect("write config");
    let resp = server_from_config(path, &["social_registry:metadata"])
        .get("/metadata/dcat/bregdcat-ap")
        .await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    body["dcat:dataset"][0]["adms:status"]
        .as_str()
        .expect("adms:status must be a string IRI")
        .to_string()
}

#[tokio::test]
async fn bregdcat_adms_status_emits_canonical_uri_for_each_variant() {
    // Every AdmsStatus variant must map to its canonical ADMS Status SKOS IRI.
    // Adding a new variant requires updating this table and the emitter match
    // (which is exhaustive, so the compiler will already enforce coverage).
    let cases = [
        ("under_development", "UnderDevelopment"),
        ("completed", "Completed"),
        ("deprecated", "Deprecated"),
        ("withdrawn", "Withdrawn"),
    ];
    for (yaml_value, iri_term) in cases {
        let got = dataset_adms_status_for_config_value(yaml_value).await;
        let expected = format!("http://purl.org/adms/status/{iri_term}");
        assert_eq!(
            got, expected,
            "adms:status for config `status: {yaml_value}` must map to {expected}",
        );
    }
}

#[tokio::test]
async fn bregdcat_adms_status_defaults_to_under_development_when_unset() {
    // When the operator does not declare status, BRegDCAT-AP requires a value;
    // the emitter applies UnderDevelopment as the weakest lifecycle claim.
    let resp = server().get("/metadata/dcat/bregdcat-ap").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body["dcat:dataset"][0]["adms:status"],
        "http://purl.org/adms/status/UnderDevelopment"
    );
}

#[tokio::test]
async fn bregdcat_publisher_has_dct_type_when_authority_type_configured() {
    let resp = bregdcat_server().get("/metadata/dcat/bregdcat-ap").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    // Catalog-level publisher.
    assert_eq!(
        body["dcterms:publisher"]["@id"],
        "http://publications.europa.eu/resource/authority/corporate-body/DIGIT"
    );
    assert_eq!(
        body["dcterms:publisher"]["skos:inScheme"],
        "http://publications.europa.eu/resource/authority/corporate-body"
    );
    assert_eq!(
        body["dcterms:publisher"]["dcterms:type"],
        "http://purl.org/adms/publishertype/NationalAuthority"
    );
    // Dataset-level publisher inherits the same publisher_agent.
    assert_eq!(
        body["dcat:dataset"][0]["dcterms:publisher"]["dcterms:type"],
        "http://purl.org/adms/publishertype/NationalAuthority"
    );
}

#[tokio::test]
async fn bregdcat_publisher_has_no_dct_type_when_not_configured() {
    let resp = server().get("/metadata/dcat/bregdcat-ap").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert!(
        body["dcterms:publisher"]["dcterms:type"].is_null(),
        "dcterms:type must be absent when authority_type is not configured"
    );
}

#[tokio::test]
async fn bregdcat_property_shape_links_codelist_with_skos_scheme() {
    // The portable renderer uses SHACL's field shape plus a standard SKOS
    // scheme link. Dataset-level codelist discovery is covered by
    // `dcterms:references`.
    let resp = server().get("/metadata/dcat/bregdcat-ap").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let shapes = body["sh:shapesGraph"].as_array().expect("shapes");
    let household = shapes
        .iter()
        .find(|s| s["sh:name"] == "household")
        .expect("household shape");
    let region_prop = household["sh:property"]
        .as_array()
        .expect("properties")
        .iter()
        .find(|p| p["sh:name"] == "region")
        .expect("region property");
    assert_eq!(
        region_prop["skos:inScheme"],
        "https://example.test/vocab/codelists/Region"
    );
    assert!(region_prop["registry_relay:codelist"].is_null());
    assert_eq!(
        body["@context"]["skos"],
        "http://www.w3.org/2004/02/skos/core#"
    );
}

#[tokio::test]
async fn bregdcat_dataset_has_dcterms_references_typed_as_concept_schemes() {
    let resp = server().get("/metadata/dcat/bregdcat-ap").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let references = body["dcat:dataset"][0]["dcterms:references"]
        .as_array()
        .expect("dcterms:references must be an array");
    let region_ref = references
        .iter()
        .find(|r| r["@id"] == "https://example.test/vocab/codelists/Region")
        .expect("dcterms:references must include the Region codelist IRI");
    assert_eq!(
        region_ref["@type"], "skos:ConceptScheme",
        "each referenced codelist must be typed as skos:ConceptScheme"
    );
    assert_eq!(region_ref["dcterms:title"], "Region");
    assert_eq!(region_ref["skos:prefLabel"], "Region");
}

#[tokio::test]
async fn scoped_bregdcat_references_only_visible_entity_codelists() {
    let resp = hidden_codelist_bregdcat_server()
        .get("/metadata/dcat/bregdcat-ap")
        .await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let raw = serde_json::to_string(&body).expect("bregdcat serializes");
    assert!(raw.contains("https://example.test/vocab/codelists/Region"));
    assert!(
        !raw.contains("HiddenAgeBand"),
        "hidden entity codelist must not appear in scoped SHACL/DCAT metadata"
    );
}

#[tokio::test]
async fn catalog_returns_etag_and_honors_if_none_match() {
    let server = server();
    let resp = server.get("/metadata/catalog").await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();
    assert!(etag.starts_with(r#""sha256:"#));

    let cached = server
        .get("/metadata/catalog")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::NOT_MODIFIED);
    assert_eq!(cached.header("etag").to_str().expect("etag"), etag);
    assert_private_metadata_headers(&cached);
}

#[tokio::test]
async fn dcat_ap_jsonld_embeds_entity_shacl_shapes() {
    let resp = server().get("/metadata/dcat/bregdcat-ap").await;

    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.header("content-type"), "application/ld+json");
    let body: Value = resp.json();
    assert_eq!(body["@type"], "dcat:Catalog");
    assert_structural_dcat_shacl(&body);
    assert_eq!(body["dcterms:description"], "");
    assert_eq!(
        body["dcat:themeTaxonomy"],
        serde_json::json!([
            "http://publications.europa.eu/resource/authority/data-theme",
            "http://eurovoc.europa.eu/100141"
        ])
    );
    assert_eq!(body["@context"]["foaf"], "http://xmlns.com/foaf/0.1/");
    assert_eq!(body["dcterms:publisher"]["@type"], "foaf:Agent");
    assert_eq!(
        body["dcterms:publisher"]["foaf:name"],
        "Ministry of Delivery"
    );
    assert_eq!(body["dcat:dataset"][0]["@type"], "dcat:Dataset");
    assert_eq!(body["dcat:dataset"].as_array().expect("datasets").len(), 1);
    assert_eq!(
        body["dcat:dataset"][0]["odrl:hasPolicy"]["@id"],
        "#policy-social_registry-offer"
    );
    assert_eq!(
        body["dcat:dataset"][0]["odrl:hasPolicy"]["odrl:uid"],
        "#policy-social_registry-offer"
    );
    assert_eq!(
        body["dcat:dataset"][0]["odrl:hasPolicy"]["odrl:assigner"]["@id"],
        "did:web:data.example.test"
    );
    assert_eq!(
        body["dcat:dataset"][0]["odrl:hasPolicy"]["odrl:permission"][0]["odrl:action"]["@id"],
        "odrl:use"
    );
    assert_eq!(
        body["dcat:dataset"][0]["odrl:hasPolicy"]["odrl:permission"][0]["odrl:target"]["@id"],
        "#dataset-social_registry"
    );
    assert_eq!(
        body["dcat:dataset"][0]["dcterms:publisher"]["@type"],
        "foaf:Agent"
    );
    assert_eq!(
        body["dcat:dataset"][0]["dcterms:accessRights"],
        "http://publications.europa.eu/resource/authority/access-right/RESTRICTED"
    );
    assert_eq!(
        body["dcat:dataset"][0]["dcterms:accrualPeriodicity"],
        "http://publications.europa.eu/resource/authority/frequency/MONTHLY"
    );
    assert!(body["dcat:dataset"][0].get("dcat:distribution").is_none());

    let included = body["@included"].as_array().expect("included nodes");
    assert!(!included.iter().any(|node| {
        node["@id"] == "http://publications.europa.eu/resource/authority/file-type/JSON"
            || node["@id"] == "https://spec.openapis.org/oas/v3.1.0"
    }));

    let shapes = body["sh:shapesGraph"].as_array().expect("shapes graph");
    assert!(shapes.iter().all(|shape| shape["sh:name"] != "individual"));
    let household = shapes
        .iter()
        .find(|shape| shape["sh:name"] == "household")
        .expect("household shape");
    assert_eq!(
        household["sh:targetClass"],
        "https://publicschema.org/concepts/Household"
    );
    assert_eq!(household["registry_manifest:primaryKey"], "id");
    assert!(household["sh:property"]
        .as_array()
        .expect("properties")
        .iter()
        .any(|property| {
            property["sh:path"] == "https://example.test/vocab/properties/region"
                && property["sh:name"] == "region"
                && property["sh:nodeKind"] == "sh:Literal"
                && property["sh:datatype"] == "xsd:string"
                && property["sh:maxCount"] == 1
        }));
    assert!(!household["sh:property"]
        .as_array()
        .expect("properties")
        .iter()
        .any(|property| { property["registry_manifest:targetEntity"] == "individual" }));
}

#[tokio::test]
async fn dcat_ap_filters_same_dataset_sibling_entities_by_metadata_scope() {
    let resp = server_with_scopes(&["social_registry:individual:metadata"])
        .get("/metadata/dcat/bregdcat-ap")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_structural_dcat_shacl(&body);
    assert!(body["dcat:dataset"][0].get("dcat:distribution").is_none());
    let shapes = body["sh:shapesGraph"].as_array().expect("shapes graph");
    assert_eq!(shapes.len(), 1);
    assert_eq!(shapes[0]["sh:name"], "individual");
}

#[tokio::test]
async fn dcat_ap_returns_etag_and_honors_if_none_match() {
    let server = server();
    let resp = server.get("/metadata/dcat/bregdcat-ap").await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();

    let cached = server
        .get("/metadata/dcat/bregdcat-ap")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::NOT_MODIFIED);
    assert_eq!(cached.header("etag").to_str().expect("etag"), etag);
}

#[tokio::test]
async fn generated_catalog_can_run_external_shacl_validation_when_enabled() {
    if std::env::var("REGISTRY_RELAY_RUN_EXTERNAL_SHACL").as_deref() != Ok("1") {
        return;
    }

    let resp = server().get("/metadata/dcat/bregdcat-ap").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();

    let tmp = TempDir::new().expect("tempdir");
    let catalog_path = tmp.path().join("metadata.bregdcat-ap.jsonld");
    std::fs::write(
        &catalog_path,
        serde_json::to_vec_pretty(&body).expect("catalog serializes"),
    )
    .expect("write catalog");

    let output = std::process::Command::new("uv")
        .args([
            "run",
            "--with",
            "pyshacl>=0.27,<0.31",
            "--with",
            "rdflib-jsonld>=0.6",
            "python",
            "scripts/validate_dcat_shacl.py",
            "--catalog",
            catalog_path.to_str().expect("utf-8 temp path"),
        ])
        .output()
        .expect("run external SHACL validation");

    assert!(
        output.status.success(),
        "external SHACL validation failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn export_generated_dcat_ap_catalog_when_path_is_set() {
    let Ok(path) = std::env::var("REGISTRY_RELAY_EXPORT_DCAT_AP_PATH") else {
        return;
    };

    let resp = server().get("/metadata/dcat/bregdcat-ap").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();

    let path = std::path::PathBuf::from(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create export directory");
    }
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&body).expect("catalog serializes"),
    )
    .expect("write exported catalog");
}

#[tokio::test]
async fn openapi_json_includes_visible_entity_semantic_extensions() {
    let resp = server().get("/openapi.json").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["openapi"], "3.1.0");
    assert_eq!(body["info"]["version"], env!("CARGO_PKG_VERSION"));
    assert!(body["paths"]["/v1/datasets/social_registry/entities/household/records"].is_object());
    assert!(body["paths"]["/v1/datasets/social_registry/entities/individual/records"].is_null());
    assert!(body["components"]["schemas"]["Entity_social_registry_individual"].is_null());

    let household = &body["components"]["schemas"]["Entity_social_registry_household"];
    assert_eq!(
        household["x-concept-uri"],
        "https://publicschema.org/concepts/Household"
    );
    assert_eq!(
        household["properties"]["region"]["x-concept-uri"],
        "https://example.test/vocab/properties/region"
    );
    assert_eq!(
        household["properties"]["region"]["x-codelist"],
        "https://example.test/vocab/codelists/Region"
    );
    assert_eq!(
        household["properties"]["members"]["x-concept-uri"],
        "https://example.test/vocab/relationships/householdMember"
    );
    assert_eq!(
        household["properties"]["members"]["x-relationship-kind"],
        "has_many"
    );
    assert_eq!(
        household["properties"]["members"]["x-target-entity"],
        "individual"
    );
}

#[tokio::test]
async fn openapi_json_can_include_all_entities_without_principal_when_configured_public() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(&tmp);
    let raw = std::fs::read_to_string(&path).expect("config is readable");
    std::fs::write(
        &path,
        raw.replace(
            "server:\n  bind: 127.0.0.1:0",
            "server:\n  bind: 127.0.0.1:0\n  openapi_requires_auth: false",
        ),
    )
    .expect("config is writable");
    let resp = server_from_config_without_principal(path)
        .get("/openapi.json")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["openapi"], "3.1.0");
    assert!(body["paths"]["/v1/datasets/social_registry/entities/household/records"].is_object());
    assert!(body["paths"]["/v1/datasets/social_registry/entities/individual/records"].is_object());
}

#[tokio::test]
async fn openapi_json_describes_entity_v1_client_generation_surface() {
    let resp = server().get("/openapi.json").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert!(body["components"]["schemas"]["ProblemDetails"].is_object());
    assert!(body["components"]["schemas"]["Pagination"].is_object());
    assert_eq!(
        body["paths"]["/metadata/policies"]["get"]["operationId"],
        "get_metadata_policies"
    );
    assert_eq!(
        body["paths"]["/metadata/datasets/{dataset_id}/policy"]["get"]["operationId"],
        "get_metadata_dataset_policy"
    );
    assert!(
        body["paths"]["/metadata/datasets/{dataset_id}/policy"]["get"]["responses"]["200"]
            ["content"]["application/ld+json"]["schema"]
            .is_object()
    );

    let collection = &body["components"]["schemas"]["Entity_social_registry_householdCollection"];
    assert_eq!(
        collection["properties"]["data"]["items"]["$ref"],
        "#/components/schemas/Entity_social_registry_household"
    );
    assert_eq!(
        collection["properties"]["pagination"]["$ref"],
        "#/components/schemas/Pagination"
    );

    let collection_get =
        &body["paths"]["/v1/datasets/social_registry/entities/household/records"]["get"];
    assert_eq!(
        collection_get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/Entity_social_registry_householdCollection"
    );
    assert_eq!(
        collection_get["responses"]["default"]["content"]["application/problem+json"]["schema"]
            ["$ref"],
        "#/components/schemas/ProblemDetails"
    );
    let collection_params = collection_get["parameters"].as_array().expect("parameters");
    for name in ["limit", "cursor", "fields", "expand", "region", "region.in"] {
        assert!(
            collection_params
                .iter()
                .any(|parameter| parameter["name"] == name),
            "missing parameter {name}"
        );
    }
    assert!(collection_params
        .iter()
        .any(|parameter| parameter["name"] == "expand"
            && parameter["schema"]["enum"][0] == "members"));

    let record_get =
        &body["paths"]["/v1/datasets/social_registry/entities/household/records/{id}"]["get"];
    assert_eq!(
        record_get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/Entity_social_registry_household"
    );
    assert!(record_get["parameters"]
        .as_array()
        .expect("record parameters")
        .iter()
        .any(|parameter| parameter["name"] == "id" && parameter["in"] == "path"));

    assert!(
        body["paths"]["/v1/datasets/social_registry/entities/household/records/verify"].is_null()
    );
    assert!(body["paths"]["/evidence-offerings/{offering_id}/verifications"].is_null());

    let relationship_get = &body["paths"]
        ["/v1/datasets/social_registry/entities/household/records/{id}/relationships/members"]
        ["get"];
    assert_eq!(
        relationship_get["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
            ["pagination"]["$ref"],
        "#/components/schemas/Pagination"
    );
    assert!(relationship_get["parameters"]
        .as_array()
        .expect("relationship parameters")
        .iter()
        .any(|parameter| parameter["name"] == "cursor"));

    assert_eq!(
        body["paths"]["/v1/datasets/social_registry/aggregates"]["get"]["responses"]["200"]
            ["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/AggregateListResponse"
    );
    assert_eq!(
        body["paths"]["/v1/datasets/social_registry/aggregates/{aggregate_id}"]["get"]["responses"]
            ["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/AggregateResult"
    );
    assert_eq!(
        body["paths"]["/v1/datasets/social_registry/aggregates/{aggregate_id}/query"]["post"]
            ["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/AggregateQueryRequest"
    );
    assert_eq!(
        body["paths"]["/v1/datasets/social_registry/aggregates/{aggregate_id}/metadata"]["get"]
            ["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/AggregateStructure"
    );
    assert_eq!(
        body["paths"]["/v1/datasets/social_registry/aggregates/{aggregate_id}/structure"]["get"]
            ["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/AggregateStructure"
    );
    assert!(
        body["paths"]["/v1/datasets/social_registry/entities/household/records/aggregates"]
            .is_null()
    );
    assert!(body["paths"]["/v1/datasets/social_registry/entities/individual/records"].is_null());
    assert!(body["components"]["schemas"]["Entity_social_registry_individual"].is_null());
}

#[tokio::test]
async fn openapi_json_includes_catalog_response_examples_for_redoc() {
    let resp = server().get("/openapi.json").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();

    let response_example = |path: &str, method: &str, media_type: &str| -> Value {
        let examples = body["paths"][path][method]["responses"]["200"]["content"][media_type]
            ["examples"]
            .as_object()
            .unwrap_or_else(|| panic!("{path} {method} {media_type} missing examples"));
        let first = examples
            .values()
            .next()
            .unwrap_or_else(|| panic!("{path} {method} {media_type} examples empty"));
        first["value"].clone()
    };

    for (path, method, media_type) in [
        ("/metadata", "get", "application/json"),
        ("/metadata/catalog", "get", "application/json"),
        ("/metadata/datasets", "get", "application/json"),
        ("/metadata/datasets/{dataset_id}", "get", "application/json"),
        ("/metadata/evidence-offerings", "get", "application/json"),
        (
            "/metadata/evidence-offerings/{offering_id}",
            "get",
            "application/json",
        ),
        ("/metadata/dcat", "get", "application/ld+json"),
        ("/metadata/dcat/bregdcat-ap", "get", "application/ld+json"),
        ("/metadata/policies", "get", "application/ld+json"),
        (
            "/metadata/datasets/{dataset_id}/policy",
            "get",
            "application/ld+json",
        ),
        ("/v1/datasets", "get", "application/json"),
        ("/v1/datasets/social_registry", "get", "application/json"),
    ] {
        let value = response_example(path, method, media_type);
        assert!(
            value.as_object().is_some_and(|object| !object.is_empty()),
            "{path} {method} should carry a concrete response example, got {value:?}"
        );
    }

    assert_eq!(
        response_example("/v1/datasets", "get", "application/json")["data"][0]["dataset_id"],
        "social_registry"
    );
    assert_eq!(
        response_example("/metadata/dcat/bregdcat-ap", "get", "application/ld+json")
            ["dcat:dataset"][0]["dcterms:title"],
        "Social Registry"
    );
    assert_eq!(
        response_example(
            "/metadata/evidence-offerings/{offering_id}",
            "get",
            "application/json"
        )["id"],
        "benefits_person_evidence"
    );
}

#[cfg(feature = "ogcapi-features")]
#[tokio::test]
async fn openapi_json_includes_ogc_api_features_surface_when_feature_enabled() {
    let resp = server().get("/openapi.json").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();

    for path in [
        "/ogc/v1",
        "/ogc/v1/conformance",
        "/ogc/v1/collections",
        "/ogc/v1/datasets/{dataset_id}/collections",
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}",
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items",
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items/{feature_id}",
    ] {
        assert!(body["paths"][path]["get"].is_object(), "missing {path}");
        assert_eq!(
            body["paths"][path]["get"]["tags"],
            serde_json::json!(["OGC API Features"]),
            "{path} should be grouped under the OGC tag"
        );
    }

    assert_eq!(
        body["paths"]["/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items"]["get"]
            ["responses"]["200"]["content"]["application/geo+json"]["schema"]["$ref"],
        "#/components/schemas/GeoJsonFeatureCollection"
    );
    assert!(body["components"]["schemas"]["OgcCollection"].is_object());
    assert!(body["components"]["schemas"]["GeoJsonFeature"].is_object());
}

#[cfg(feature = "ogcapi-records")]
#[tokio::test]
async fn openapi_json_includes_ogc_api_records_surface_when_feature_enabled() {
    let resp = server().get("/openapi.json").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();

    for path in [
        "/ogc/v1/records",
        "/ogc/v1/records/conformance",
        "/ogc/v1/records/collections",
        "/ogc/v1/records/collections/{collection_id}",
        "/ogc/v1/records/collections/{collection_id}/items",
        "/ogc/v1/records/collections/{collection_id}/items/{record_id}",
    ] {
        assert!(body["paths"][path]["get"].is_object(), "missing {path}");
        assert_eq!(
            body["paths"][path]["get"]["tags"],
            serde_json::json!(["OGC API Records"]),
            "{path} should be grouped under the OGC Records tag"
        );
    }

    assert_eq!(
        body["paths"]["/ogc/v1/records/collections/{collection_id}/items"]["get"]["responses"]
            ["200"]["content"]["application/geo+json"]["schema"]["$ref"],
        "#/components/schemas/OgcRecordCollection"
    );
    assert!(body["components"]["schemas"]["OgcRecord"].is_object());
}

#[tokio::test]
async fn openapi_json_declares_bearer_security_scheme_and_marks_health_and_ready_public() {
    let resp = server().get("/openapi.json").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();

    let scheme = &body["components"]["securitySchemes"]["bearerAuth"];
    assert_eq!(scheme["type"], "http");
    assert_eq!(scheme["scheme"], "bearer");

    assert_eq!(
        body["security"],
        serde_json::json!([{ "bearerAuth": [] }, { "apiKeyAuth": [] }])
    );
    assert_eq!(
        body["components"]["securitySchemes"]["apiKeyAuth"]["in"],
        "header"
    );
    assert_eq!(
        body["components"]["securitySchemes"]["apiKeyAuth"]["name"],
        "X-Api-Key"
    );

    // `/healthz` and `/ready` are on the unauthenticated sub-router in
    // `server::build_app_with_provenance`. Their entries override the
    // document-level requirement so codegen and Scalar's auth panel do
    // not demand a bearer for them.
    assert_eq!(
        body["paths"]["/healthz"]["get"]["security"],
        serde_json::json!([])
    );
    assert_eq!(
        body["paths"]["/ready"]["get"]["security"],
        serde_json::json!([])
    );

    // A protected route should NOT carry its own `security` field; it
    // inherits the document-level requirement. Pick the entity
    // collection route as the representative case.
    assert!(
        body["paths"]["/v1/datasets/social_registry/entities/household/records"]["get"]["security"]
            .is_null(),
        "protected routes should inherit document-level security, not override it"
    );
}

#[tokio::test]
async fn openapi_json_groups_operations_into_sidebar_tags() {
    // Scalar's sidebar groups operations by `tags`. Without this, every
    // entity's operations collapse to identical labels and the sidebar
    // becomes unusable. Each operation gets exactly one tag:
    //   - Service: /healthz, /ready
    //   - Catalog: /metadata/catalog, /datasets, /datasets/{id}, DCAT-AP
    //   - "<dataset> / <entity>": every per-entity operation, including
    // The document-level `tags` array fixes sidebar order.
    let resp = server().get("/openapi.json").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();

    let tags = body["tags"].as_array().expect("tags array");
    let tag_names: Vec<&str> = tags
        .iter()
        .map(|t| t["name"].as_str().expect("tag name string"))
        .collect();
    assert_eq!(tag_names.first().copied(), Some("Service"));
    assert!(tag_names.contains(&"Catalog"));
    assert!(
        tag_names.contains(&"social_registry / household"),
        "tags array should declare the entity section: got {tag_names:?}"
    );

    let entity_tag = "social_registry / household";
    for path in [
        "/v1/datasets/social_registry/entities/household/records",
        "/v1/datasets/social_registry/entities/household/records/{id}",
        "/v1/datasets/social_registry/entities/household/schema",
        "/v1/datasets/social_registry/entities/household/records/{id}/relationships/members",
    ] {
        assert_eq!(
            body["paths"][path]["get"]["tags"],
            serde_json::json!([entity_tag]),
            "{path} should be tagged with {entity_tag}"
        );
    }
    let aggregate_tag = "social_registry / aggregates";
    for (path, method) in [
        ("/v1/datasets/social_registry/aggregates", "get"),
        (
            "/v1/datasets/social_registry/aggregates/{aggregate_id}",
            "get",
        ),
        (
            "/v1/datasets/social_registry/aggregates/{aggregate_id}/query",
            "post",
        ),
        (
            "/v1/datasets/social_registry/aggregates/{aggregate_id}/structure",
            "get",
        ),
        (
            "/v1/datasets/social_registry/aggregates/{aggregate_id}/metadata",
            "get",
        ),
    ] {
        assert_eq!(
            body["paths"][path][method]["tags"],
            serde_json::json!([aggregate_tag]),
            "{path} {method} should be tagged with {aggregate_tag}"
        );
    }

    assert_eq!(
        body["paths"]["/healthz"]["get"]["tags"],
        serde_json::json!(["Service"])
    );
    assert_eq!(
        body["paths"]["/ready"]["get"]["tags"],
        serde_json::json!(["Service"])
    );
    assert_eq!(
        body["paths"]["/metadata/catalog"]["get"]["tags"],
        serde_json::json!(["Catalog"])
    );
    assert_eq!(
        body["paths"]["/metadata/dcat/bregdcat-ap"]["get"]["tags"],
        serde_json::json!(["Catalog"])
    );
    assert_eq!(
        body["paths"]["/v1/datasets"]["get"]["tags"],
        serde_json::json!(["Catalog"])
    );
    assert_eq!(
        body["paths"]["/v1/datasets/social_registry"]["get"]["tags"],
        serde_json::json!(["Catalog"])
    );
}

#[tokio::test]
async fn openapi_json_carries_scalar_friendly_metadata_and_operation_contract() {
    // Asserts the second-pass OpenAPI rewrite: info.summary + contact +
    // Apache-2.0 license; a single server entry with a description;
    // x-tagGroups grouping entity tags by dataset title; x-displayName
    // on entity tags; operationId on every per-entity operation; 3.1
    // nullability via type arrays; 401/403/404 error envelopes; per-op
    // filter parameter descriptions; x-codeSamples on collection and
    // record routes. One test covers the whole contract so a future
    // regression on any prong fails loudly with a single name.
    let resp = server().get("/openapi.json").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();

    // ---- info ----
    let info = &body["info"];
    assert!(
        info["summary"].as_str().is_some_and(|s| !s.is_empty()),
        "info.summary must be a non-empty string (Scalar uses it as the doc subtitle)"
    );
    assert_eq!(info["contact"]["name"], "Ministry of Delivery");
    assert_eq!(info["license"]["name"], "Apache-2.0");
    assert_eq!(info["license"]["identifier"], "Apache-2.0");

    // ---- servers ----
    let servers = body["servers"].as_array().expect("servers array");
    assert_eq!(servers.len(), 1);
    assert!(
        servers[0]["description"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "servers[0].description must be present"
    );

    // ---- x-tagGroups ----
    let groups = body["x-tagGroups"].as_array().expect("x-tagGroups array");
    let group_names: Vec<&str> = groups
        .iter()
        .map(|g| g["name"].as_str().expect("group name"))
        .collect();
    assert_eq!(group_names[0], "Service");
    assert_eq!(group_names[1], "Catalog");
    assert!(
        group_names.contains(&"Social Registry"),
        "x-tagGroups should include a group named after dataset.title 'Social Registry': got {group_names:?}"
    );
    let social_registry_group = groups
        .iter()
        .find(|g| g["name"] == "Social Registry")
        .expect("Social Registry group present");
    let social_registry_tags: Vec<&str> = social_registry_group["tags"]
        .as_array()
        .expect("tags array on group")
        .iter()
        .map(|t| t.as_str().expect("tag string"))
        .collect();
    assert!(
        social_registry_tags.contains(&"social_registry / aggregates"),
        "Social Registry group must include the aggregate tag: got {social_registry_tags:?}"
    );
    assert!(
        social_registry_tags.contains(&"social_registry / household"),
        "Social Registry group must include the household entity tag: got {social_registry_tags:?}"
    );

    // ---- tag x-displayName ----
    let tags = body["tags"].as_array().expect("tags array");
    let household_tag = tags
        .iter()
        .find(|t| t["name"] == "social_registry / household")
        .expect("household tag present");
    assert_eq!(
        household_tag["x-displayName"], "Household",
        "entity tags must surface entity.title via x-displayName"
    );
    let aggregate_tag = tags
        .iter()
        .find(|t| t["name"] == "social_registry / aggregates")
        .expect("aggregate tag present");
    assert_eq!(aggregate_tag["x-displayName"], "Aggregates");

    // ---- operationId on every per-entity op ----
    for (path, expected) in [
        (
            "/v1/datasets/social_registry/entities/household/records",
            "list_social_registry_household_records",
        ),
        (
            "/v1/datasets/social_registry/entities/household/records/{id}",
            "get_social_registry_household_record",
        ),
        (
            "/v1/datasets/social_registry/aggregates",
            "list_social_registry_aggregates",
        ),
        (
            "/v1/datasets/social_registry/aggregates/{aggregate_id}",
            "run_social_registry_aggregate",
        ),
        (
            "/v1/datasets/social_registry/entities/household/schema",
            "get_social_registry_household_field_schema",
        ),
        (
            "/v1/datasets/social_registry/entities/household/records/{id}/relationships/members",
            "get_social_registry_household_members",
        ),
    ] {
        assert_eq!(
            body["paths"][path]["get"]["operationId"], expected,
            "{path} must declare a stable operationId"
        );
    }
    assert!(body["paths"]["/evidence-offerings/{offering_id}/verifications"].is_null());

    // ---- 3.1 nullability for the nullable `region` field ----
    let region =
        &body["components"]["schemas"]["Entity_social_registry_household"]["properties"]["region"];
    assert_eq!(
        region["type"],
        serde_json::json!(["string", "null"]),
        "nullable fields must encode null via OAS 3.1 type arrays, not the 3.0 nullable keyword"
    );
    assert!(
        region["description"]
            .as_str()
            .is_some_and(|s| s.contains("Optional")),
        "synthesized field description should mark nullable fields as Optional: got {:?}",
        region["description"]
    );

    // ---- 401/403 envelope on a protected route, 404 on the record path ----
    let collection_responses = &body["paths"]
        ["/v1/datasets/social_registry/entities/household/records"]["get"]["responses"];
    for code in ["401", "403", "default"] {
        assert_eq!(
            collection_responses[code]["content"]["application/problem+json"]["schema"]["$ref"],
            "#/components/schemas/ProblemDetails",
            "collection responses[{code}] must point at ProblemDetails"
        );
    }
    let record_responses = &body["paths"]
        ["/v1/datasets/social_registry/entities/household/records/{id}"]["get"]["responses"];
    assert_eq!(
        record_responses["404"]["content"]["application/problem+json"]["schema"]["$ref"],
        "#/components/schemas/ProblemDetails",
        "record GET must declare a 404 ProblemDetails response"
    );
    assert!(
        record_responses["404"]["description"]
            .as_str()
            .is_some_and(|s| s.contains("not found")),
        "404 description should mention not-found"
    );

    // ---- per-filter parameter descriptions ----
    let collection_params = body["paths"]
        ["/v1/datasets/social_registry/entities/household/records"]["get"]["parameters"]
        .as_array()
        .expect("collection parameters");
    let region_eq = collection_params
        .iter()
        .find(|p| p["name"] == "region")
        .expect("region eq filter param");
    let region_in = collection_params
        .iter()
        .find(|p| p["name"] == "region.in")
        .expect("region.in filter param");
    let eq_desc = region_eq["description"]
        .as_str()
        .expect("eq description string");
    let in_desc = region_in["description"]
        .as_str()
        .expect("in description string");
    assert!(
        eq_desc.contains("exact match"),
        "eq filter description should mention exact match: {eq_desc:?}"
    );
    assert!(
        in_desc.contains("comma-separated"),
        "in filter description should mention comma-separated values: {in_desc:?}"
    );
    assert_ne!(
        eq_desc, in_desc,
        "eq and in must carry distinct descriptions"
    );

    // ---- x-codeSamples on collection and record ----
    for path in [
        "/v1/datasets/social_registry/entities/household/records",
        "/v1/datasets/social_registry/entities/household/records/{id}",
    ] {
        let samples = body["paths"][path]["get"]["x-codeSamples"]
            .as_array()
            .unwrap_or_else(|| panic!("x-codeSamples array on {path}"));
        let langs: Vec<&str> = samples
            .iter()
            .map(|s| s["lang"].as_str().expect("sample lang"))
            .collect();
        assert!(
            langs.contains(&"Shell"),
            "{path} must include a Shell sample: {langs:?}"
        );
        assert!(
            langs.contains(&"Python"),
            "{path} must include a Python sample: {langs:?}"
        );
    }

    // ---- Data-Purpose header parameter on purpose-required routes ----
    // The household entity is configured with `require_purpose_header:
    // true`. Every route the gateway gates with `auth.purpose_required`
    // must declare the header in OpenAPI so Scalar can render an
    // editable field and generated clients can carry it through. Routes
    // that the gateway does NOT gate (metadata schema, aggregates list)
    // must not declare it, so codegen doesn't force callers to send it.
    let purpose_param = |path: &str| -> Option<Value> {
        body["paths"][path]["get"]["parameters"]
            .as_array()
            .and_then(|params| {
                params
                    .iter()
                    .find(|p| {
                        p["in"] == "header"
                            && p["name"]
                                .as_str()
                                .is_some_and(|n| n.eq_ignore_ascii_case("Data-Purpose"))
                    })
                    .cloned()
            })
    };
    for gated in [
        "/v1/datasets/social_registry/entities/household/records",
        "/v1/datasets/social_registry/entities/household/records/{id}",
        "/v1/datasets/social_registry/entities/household/records/{id}/relationships/members",
    ] {
        let param = purpose_param(gated)
            .unwrap_or_else(|| panic!("{gated} must declare the Data-Purpose header parameter"));
        assert_eq!(param["required"], serde_json::json!(true), "{gated}");
        assert_eq!(param["schema"]["type"], "string", "{gated}");
        assert_eq!(param["schema"]["minLength"], 1, "{gated}");
    }
    for ungated in [
        "/v1/datasets/social_registry/entities/household/schema",
        "/v1/datasets/social_registry/aggregates",
    ] {
        assert!(
            purpose_param(ungated).is_none(),
            "{ungated} does not enforce purpose; OpenAPI must not declare the header"
        );
    }
}

#[tokio::test]
async fn catalog_filters_entities_inside_same_dataset_by_metadata_scope() {
    let resp = server_with_scopes(&["social_registry:individual:metadata"])
        .get("/metadata/catalog")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["datasets"].as_array().expect("datasets").len(), 1);
    let entities = body["datasets"][0]["entities"]
        .as_array()
        .expect("entities");
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0]["name"], "individual");
}

#[tokio::test]
async fn evidence_verification_only_scope_cannot_read_catalog() {
    let resp = server_with_scopes(&["social_registry:evidence_verification"])
        .get("/metadata/catalog")
        .await;

    resp.assert_status(StatusCode::FORBIDDEN);
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}

#[tokio::test]
async fn metadata_scope_for_one_dataset_cannot_read_other_dataset_schema() {
    let resp = server()
        .get("/metadata/schema/payments/payment/schema.json")
        .await;

    resp.assert_status(StatusCode::NOT_FOUND);
    let body: Value = resp.json();
    assert_eq!(body["code"], "schema.unknown_resource");
}

#[tokio::test]
async fn relationship_concept_uri_with_unknown_prefix_is_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(&tmp);
    let mut body = std::fs::read_to_string(&path).expect("read config");
    body = body.replace(
        "concept_uri: ex:relationships/householdMember",
        "concept_uri: missing:relationships/householdMember",
    );
    std::fs::write(&path, body).expect("rewrite config");

    let err = config::load(&path).expect_err("config rejects unknown relationship URI prefix");
    assert_eq!(err.code(), "config.validation_error");
}

#[tokio::test]
async fn single_entity_schema_returns_not_found_for_unknown_entity() {
    let resp = server()
        .get("/metadata/schema/social_registry/missing/schema.json")
        .await;

    resp.assert_status(StatusCode::NOT_FOUND);
    let body: Value = resp.json();
    assert_eq!(body["code"], "schema.unknown_resource");
}

#[tokio::test]
async fn entity_scoped_catalog_includes_aggregates_of_visible_entities() {
    use registry_relay::metadata::catalog::catalog_document_for_entity_ids;

    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(&tmp);
    let cfg = config::load(&path).expect("config loads");
    let registry = EntityRegistry::from_config(&cfg).expect("registry compiles");

    // The household entity is the source_entity of households_by_region, so an
    // entity-scoped catalog for it must surface that aggregate distribution.
    let household_ids: std::collections::BTreeSet<(String, String)> =
        [("social_registry".to_string(), "household".to_string())]
            .into_iter()
            .collect();
    let doc = catalog_document_for_entity_ids(&cfg, &registry, &household_ids);
    let social_registry = doc
        .datasets
        .iter()
        .find(|dataset| dataset.dataset_id == "social_registry")
        .expect("social_registry dataset is visible");
    assert!(
        social_registry
            .aggregate_distributions
            .iter()
            .any(|distribution| distribution.aggregate_id == "households_by_region"),
        "household-scoped catalog must include the household aggregate distribution"
    );

    // The individual entity does not own households_by_region, so scoping to it
    // must not surface that aggregate.
    let individual_ids: std::collections::BTreeSet<(String, String)> =
        [("social_registry".to_string(), "individual".to_string())]
            .into_iter()
            .collect();
    let individual_doc = catalog_document_for_entity_ids(&cfg, &registry, &individual_ids);
    let individual_dataset = individual_doc
        .datasets
        .iter()
        .find(|dataset| dataset.dataset_id == "social_registry")
        .expect("social_registry dataset is visible for individual scope");
    assert!(
        !individual_dataset
            .aggregate_distributions
            .iter()
            .any(|distribution| distribution.aggregate_id == "households_by_region"),
        "individual-scoped catalog must not include the household aggregate"
    );
}

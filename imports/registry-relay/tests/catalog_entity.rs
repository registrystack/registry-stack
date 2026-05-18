// SPDX-License-Identifier: Apache-2.0
//! Catalog metadata tests for entity-grain JSON and JSON-LD outputs.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::Extension;
use axum_test::TestServer;
use registry_relay::api::{catalog_router, openapi_router};
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use registry_relay::config;
use registry_relay::entity::EntityRegistry;
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
    source:
      type: file
      path: fixtures/social_registry.csv
    refresh:
      mode: manual
    tables:
      - id: households_table
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
          verify_scope: social_registry:verify
          bulk_export_scope: social_registry:bulk_export
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
          verify_scope: social_registry:verify
          bulk_export_scope: social_registry:bulk_export
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
    source:
      type: file
      path: fixtures/payments.csv
    refresh:
      mode: manual
    tables:
      - id: payments_table
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
          verify_scope: payments:verify
          bulk_export_scope: payments:bulk_export
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
        catalog_router::<()>()
            .merge(openapi_router())
            .layer(Extension(registry))
            .layer(Extension(cfg))
            .layer(Extension(principal(scopes))),
    )
}

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

fn entity<'a>(body: &'a Value, name: &str) -> &'a Value {
    body["datasets"][0]["entities"]
        .as_array()
        .expect("entities array")
        .iter()
        .find(|entity| entity["name"] == name)
        .expect("entity present")
}

fn assert_structural_dcat_shacl(body: &Value) {
    assert_eq!(body["@type"], "dcat:Catalog");
    assert_eq!(body["@context"]["dcat"], "http://www.w3.org/ns/dcat#");
    assert_eq!(body["@context"]["dct"], "http://purl.org/dc/terms/");
    assert_eq!(body["@context"]["dcterms"], "http://purl.org/dc/terms/");
    assert_eq!(
        body["@context"]["dspace"],
        "https://w3id.org/dspace/2025/1/"
    );
    assert_eq!(body["@context"]["odrl"], "http://www.w3.org/ns/odrl/2/");
    assert_eq!(body["@context"]["sh"], "http://www.w3.org/ns/shacl#");
    assert_eq!(body["@context"]["dcat:accessService"]["@type"], "@id");
    assert_eq!(body["@context"]["dcat:endpointURL"]["@type"], "@id");
    assert_eq!(body["@context"]["dct:format"]["@type"], "@id");
    assert_eq!(body["@context"]["odrl:action"]["@type"], "@id");
    assert_eq!(body["@context"]["odrl:hasPolicy"]["@type"], "@id");
    assert_eq!(body["@context"]["sh:path"]["@type"], "@id");
    assert_eq!(body["@context"]["sh:targetClass"]["@type"], "@id");
    assert_eq!(body["@context"]["dcat:accessURL"]["@type"], "@id");
    assert_eq!(body["@context"]["dcat:downloadURL"]["@type"], "@id");
    assert!(body["dcat:dataset"]
        .as_array()
        .expect("datasets")
        .iter()
        .all(|dataset| {
            dataset["@type"] == "dcat:Dataset"
                && dataset["@id"].is_string()
                && dataset["dcterms:title"].is_string()
                && dataset["odrl:hasPolicy"]["@type"] == "odrl:Offer"
                && dataset["dcat:distribution"].is_array()
        }));
    assert!(body["sh:shapesGraph"]
        .as_array()
        .expect("shapes graph")
        .iter()
        .all(|shape| {
            shape["@type"] == "sh:NodeShape"
                && shape["@id"].is_string()
                && shape["sh:targetClass"].is_string()
                && shape["sh:property"].as_array().is_some_and(|properties| {
                    properties.iter().all(|property| {
                        property["@type"] == "sh:PropertyShape"
                            && property["sh:path"].is_string()
                            && property["sh:name"].is_string()
                    })
                })
        }));
}

#[tokio::test]
async fn catalog_lists_entity_grain_metadata_without_hidden_columns() {
    let resp = server().get("/catalog").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["base_url"], "https://data.example.test");
    assert_eq!(
        body["links"]["dcat_ap"],
        "https://data.example.test/catalog/dcat-ap.jsonld"
    );
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
    assert_eq!(
        household["links"]["collection"],
        "https://data.example.test/datasets/social_registry/household"
    );
    assert_eq!(household["fields"].as_array().expect("fields").len(), 2);
    assert_eq!(household["fields"][1]["name"], "region");
    assert_eq!(household["fields"][1]["type"], "string");
    assert_eq!(household["fields"][1]["nullable"], true);
    assert_eq!(
        household["fields"][1]["concept_uri"],
        "https://example.test/vocab/properties/region"
    );
    assert_eq!(
        household["fields"][1]["codelist"],
        "https://example.test/vocab/codelists/Region"
    );
    assert!(household["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .all(|field| field["name"] != "internal_note"));
    assert_eq!(household["relationships"][0]["kind"], "has_many");
    assert_eq!(household["relationships"][0]["target"], "individual");
}

#[cfg(not(feature = "ogcapi-features"))]
#[tokio::test]
async fn catalog_does_not_advertise_ogc_links_when_feature_is_disabled() {
    let server = spatial_catalog_server();

    let catalog_resp = server.get("/catalog").await;
    catalog_resp.assert_status(StatusCode::OK);
    let catalog: Value = catalog_resp.json();
    let household = entity(&catalog, "household");
    assert!(household["links"].get("ogc_collection").is_none());
    assert!(household["links"].get("ogc_items").is_none());

    let dcat_resp = server.get("/catalog/dcat-ap.jsonld").await;
    dcat_resp.assert_status(StatusCode::OK);
    let dcat: Value = dcat_resp.json();
    let distributions = dcat["dcat:dataset"][0]["dcat:distribution"]
        .as_array()
        .expect("distributions");
    assert!(distributions.iter().all(|distribution| {
        distribution["dcat:accessService"]["dspace:dataServiceType"]
            != "registry_relay:ogc-api-features"
    }));
}

#[cfg(feature = "ogcapi-features")]
#[tokio::test]
async fn catalog_and_dcat_advertise_ogc_links_for_spatial_entities() {
    let server = spatial_catalog_server();
    let catalog_resp = server.get("/catalog").await;

    catalog_resp.assert_status(StatusCode::OK);
    let catalog: Value = catalog_resp.json();
    assert_eq!(
        catalog["datasets"][0]["links"]["ogc_collections"],
        "https://data.example.test/ogc/v1/datasets/social_registry/collections"
    );
    assert_eq!(
        catalog["datasets"][0]["standards"]["ogc_api_features"]["collections"],
        "https://data.example.test/ogc/v1/datasets/social_registry/collections"
    );
    let household = entity(&catalog, "household");
    assert_eq!(
        household["links"]["ogc_collection"],
        "https://data.example.test/ogc/v1/datasets/social_registry/collections/households"
    );
    assert_eq!(
        household["links"]["ogc_items"],
        "https://data.example.test/ogc/v1/datasets/social_registry/collections/households/items"
    );

    let dcat_resp = server.get("/catalog/dcat-ap.jsonld").await;
    dcat_resp.assert_status(StatusCode::OK);
    let dcat: Value = dcat_resp.json();
    let distributions = dcat["dcat:dataset"][0]["dcat:distribution"]
        .as_array()
        .expect("distributions");
    let dataset_ogc = distributions
        .iter()
        .find(|distribution| {
            distribution["dcat:accessService"]["dspace:dataServiceType"]
                == "registry_relay:ogc-api-features"
                && distribution["dcat:accessURL"]
                    == "https://data.example.test/ogc/v1/datasets/social_registry/collections"
        })
        .expect("dataset OGC distribution");
    assert_eq!(
        dataset_ogc["dcat:accessService"]["dcat:servesDataset"],
        "https://data.example.test/datasets/social_registry"
    );
    let entity_ogc = distributions
        .iter()
        .find(|distribution| {
            distribution["dcat:accessService"]["dspace:dataServiceType"]
                == "registry_relay:ogc-api-features"
                && distribution["dcat:accessURL"]
                    == "https://data.example.test/ogc/v1/datasets/social_registry/collections/households"
        })
        .expect("entity OGC distribution");
    assert_eq!(
        entity_ogc["dcat:accessURL"],
        "https://data.example.test/ogc/v1/datasets/social_registry/collections/households"
    );
    assert_eq!(
        entity_ogc["dcat:downloadURL"],
        "https://data.example.test/ogc/v1/datasets/social_registry/collections/households/items"
    );
}

#[cfg(feature = "spdci-api-standards")]
#[tokio::test]
async fn catalog_and_dcat_advertise_spdci_services_for_bound_datasets() {
    let server = spdci_catalog_server();
    let catalog_resp = server.get("/catalog").await;

    catalog_resp.assert_status(StatusCode::OK);
    let catalog: Value = catalog_resp.json();
    let registry = &catalog["datasets"][0]["standards"]["spdci"]["registries"][0];
    assert_eq!(registry["registry"], "sr");
    assert_eq!(registry["entity"], "household");
    assert_eq!(
        registry["sync_search"],
        "https://data.example.test/dci/sr/registry/sync/search"
    );

    let dcat_resp = server.get("/catalog/dcat-ap.jsonld").await;
    dcat_resp.assert_status(StatusCode::OK);
    let dcat: Value = dcat_resp.json();
    let distributions = dcat["dcat:dataset"][0]["dcat:distribution"]
        .as_array()
        .expect("distributions");
    let spdci = distributions
        .iter()
        .find(|distribution| {
            distribution["dcat:accessService"]["dspace:dataServiceType"]
                == "registry_relay:spdci-sync"
        })
        .expect("SP DCI distribution");
    assert_eq!(
        spdci["dcat:accessService"]["dcat:endpointURL"],
        "https://data.example.test/dci/sr/registry/sync/search"
    );
    assert_eq!(
        spdci["dcat:accessService"]["dcat:servesDataset"],
        "https://data.example.test/datasets/social_registry"
    );
    assert_eq!(
        spdci["dcat:accessService"]["registry_relay:registryName"],
        "sr"
    );
}

#[tokio::test]
async fn catalog_returns_etag_and_honors_if_none_match() {
    let server = server();
    let resp = server.get("/catalog").await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();
    assert!(etag.starts_with(r#""sha256:"#));

    let cached = server
        .get("/catalog")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::NOT_MODIFIED);
    assert_eq!(cached.header("etag").to_str().expect("etag"), etag);
}

#[tokio::test]
async fn dcat_ap_jsonld_embeds_entity_shacl_shapes() {
    let resp = server().get("/catalog/dcat-ap.jsonld").await;

    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.header("content-type"), "application/ld+json");
    let body: Value = resp.json();
    assert_eq!(body["@type"], "dcat:Catalog");
    assert_eq!(body["dspace:participantId"], "did:web:data.example.test");
    assert_structural_dcat_shacl(&body);
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
        "https://data.example.test/datasets/social_registry#offer"
    );
    assert_eq!(
        body["dcat:dataset"][0]["odrl:hasPolicy"]["odrl:permission"][0]["odrl:action"]["@id"],
        "odrl:use"
    );
    assert!(
        body["dcat:dataset"][0]["odrl:hasPolicy"]["target"].is_null(),
        "DSP dataset offers must not carry an explicit target"
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
    let distribution = &body["dcat:dataset"][0]["dcat:distribution"][0];
    assert_eq!(
        distribution["dct:format"]["@id"],
        "registry_relay:HttpData-PULL"
    );
    assert_eq!(
        distribution["dcat:accessService"]["@type"],
        "dcat:DataService"
    );
    assert_eq!(
        distribution["dcat:accessService"]["dspace:dataServiceType"],
        "registry_relay:entity-rest"
    );
    assert_eq!(
        distribution["dcat:accessService"]["dcat:endpointURL"],
        "https://data.example.test/datasets/social_registry/household"
    );

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
    assert_eq!(household["registry_relay:primaryKey"], "id");
    assert!(household["sh:property"]
        .as_array()
        .expect("properties")
        .iter()
        .any(|property| {
            property["sh:path"] == "https://example.test/vocab/properties/region"
                && property["sh:name"] == "region"
        }));
    assert!(household["sh:property"]
        .as_array()
        .expect("properties")
        .iter()
        .any(|property| {
            property["sh:path"] == "https://example.test/vocab/relationships/householdMember"
                && property["registry_relay:targetEntity"] == "individual"
        }));
}

#[tokio::test]
async fn dcat_ap_filters_same_dataset_sibling_entities_by_metadata_scope() {
    let resp = server_with_scopes(&["social_registry:individual:metadata"])
        .get("/catalog/dcat-ap.jsonld")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_structural_dcat_shacl(&body);
    let distributions = body["dcat:dataset"][0]["dcat:distribution"]
        .as_array()
        .expect("distributions");
    assert_eq!(distributions.len(), 1);
    assert_eq!(
        distributions[0]["dcat:accessURL"],
        "https://data.example.test/datasets/social_registry/individual"
    );
    let shapes = body["sh:shapesGraph"].as_array().expect("shapes graph");
    assert_eq!(shapes.len(), 1);
    assert_eq!(shapes[0]["sh:name"], "individual");
}

#[tokio::test]
async fn dcat_ap_returns_etag_and_honors_if_none_match() {
    let server = server();
    let resp = server.get("/catalog/dcat-ap.jsonld").await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();

    let cached = server
        .get("/catalog/dcat-ap.jsonld")
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

    let resp = server().get("/catalog/dcat-ap.jsonld").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();

    let tmp = TempDir::new().expect("tempdir");
    let catalog_path = tmp.path().join("catalog.dcat-ap.jsonld");
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
async fn single_entity_schema_jsonld_returns_schema_and_shape() {
    let resp = server()
        .get("/catalog/datasets/social_registry/household/schema.jsonld")
        .await;

    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.header("content-type"), "application/ld+json");
    let body: Value = resp.json();
    assert_eq!(body["schema"]["dataset_id"], "social_registry");
    assert_eq!(body["schema"]["entity"], "household");
    assert_eq!(body["schema"]["relationships"][0]["target"], "individual");
    assert_eq!(body["shape"]["@type"], "sh:NodeShape");
}

#[tokio::test]
async fn openapi_json_includes_visible_entity_semantic_extensions() {
    let resp = server().get("/openapi.json").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["openapi"], "3.1.0");
    assert_eq!(body["info"]["version"], env!("CARGO_PKG_VERSION"));
    assert!(body["paths"]["/datasets/social_registry/household"].is_object());
    assert!(body["paths"]["/datasets/social_registry/individual"].is_null());
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
async fn openapi_json_describes_entity_v1_client_generation_surface() {
    let resp = server().get("/openapi.json").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert!(body["components"]["schemas"]["ProblemDetails"].is_object());
    assert!(body["components"]["schemas"]["Pagination"].is_object());

    let collection = &body["components"]["schemas"]["Entity_social_registry_householdCollection"];
    assert_eq!(
        collection["properties"]["data"]["items"]["$ref"],
        "#/components/schemas/Entity_social_registry_household"
    );
    assert_eq!(
        collection["properties"]["pagination"]["$ref"],
        "#/components/schemas/Pagination"
    );

    let collection_get = &body["paths"]["/datasets/social_registry/household"]["get"];
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

    let record_get = &body["paths"]["/datasets/social_registry/household/{id}"]["get"];
    assert_eq!(
        record_get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/Entity_social_registry_household"
    );
    assert!(record_get["parameters"]
        .as_array()
        .expect("record parameters")
        .iter()
        .any(|parameter| parameter["name"] == "id" && parameter["in"] == "path"));

    let verify_get = &body["paths"]["/datasets/social_registry/household/verify"]["get"];
    assert_eq!(
        verify_get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/VerifyResponse"
    );
    assert!(verify_get["parameters"]
        .as_array()
        .expect("verify parameters")
        .iter()
        .any(|parameter| parameter["name"] == "id" && parameter["in"] == "query"));

    let relationship_get =
        &body["paths"]["/datasets/social_registry/household/{id}/members"]["get"];
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
        body["paths"]["/datasets/social_registry/household/aggregates"]["get"]["responses"]["200"]
            ["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/AggregateListResponse"
    );
    assert_eq!(
        body["paths"]["/datasets/social_registry/household/aggregates/{aggregate_id}"]["get"]
            ["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/AggregateResult"
    );
    assert!(body["paths"]["/datasets/social_registry/individual"].is_null());
    assert!(body["components"]["schemas"]["Entity_social_registry_individual"].is_null());
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

#[tokio::test]
async fn openapi_json_declares_bearer_security_scheme_and_marks_health_and_ready_public() {
    let resp = server().get("/openapi.json").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();

    let scheme = &body["components"]["securitySchemes"]["bearerAuth"];
    assert_eq!(scheme["type"], "http");
    assert_eq!(scheme["scheme"], "bearer");

    assert_eq!(body["security"], serde_json::json!([{ "bearerAuth": [] }]));

    // `/health` and `/ready` are on the unauthenticated sub-router in
    // `server::build_app_with_provenance`. Their entries override the
    // document-level requirement so codegen and Scalar's auth panel do
    // not demand a bearer for them.
    assert_eq!(
        body["paths"]["/health"]["get"]["security"],
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
        body["paths"]["/datasets/social_registry/household"]["get"]["security"].is_null(),
        "protected routes should inherit document-level security, not override it"
    );
}

#[tokio::test]
async fn openapi_json_groups_operations_into_sidebar_tags() {
    // Scalar's sidebar groups operations by `tags`. Without this, every
    // entity's operations collapse to identical labels and the sidebar
    // becomes unusable. Each operation gets exactly one tag:
    //   - Service: /health, /ready
    //   - Catalog: /catalog, /datasets, /datasets/{id}, DCAT-AP
    //   - "<dataset> / <entity>": every per-entity operation, including
    //     the per-entity SHACL shape under /catalog/datasets/...
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
        "/datasets/social_registry/household",
        "/datasets/social_registry/household/{id}",
        "/datasets/social_registry/household/schema",
        "/datasets/social_registry/household/verify",
        "/datasets/social_registry/household/aggregates",
        "/datasets/social_registry/household/aggregates/{aggregate_id}",
        "/datasets/social_registry/household/{id}/members",
        "/catalog/datasets/social_registry/household/schema.jsonld",
    ] {
        assert_eq!(
            body["paths"][path]["get"]["tags"],
            serde_json::json!([entity_tag]),
            "{path} should be tagged with {entity_tag}"
        );
    }

    assert_eq!(
        body["paths"]["/health"]["get"]["tags"],
        serde_json::json!(["Service"])
    );
    assert_eq!(
        body["paths"]["/ready"]["get"]["tags"],
        serde_json::json!(["Service"])
    );
    assert_eq!(
        body["paths"]["/catalog"]["get"]["tags"],
        serde_json::json!(["Catalog"])
    );
    assert_eq!(
        body["paths"]["/catalog/dcat-ap.jsonld"]["get"]["tags"],
        serde_json::json!(["Catalog"])
    );
    assert_eq!(
        body["paths"]["/datasets"]["get"]["tags"],
        serde_json::json!(["Catalog"])
    );
    assert_eq!(
        body["paths"]["/datasets/social_registry"]["get"]["tags"],
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

    // ---- operationId on every per-entity op ----
    for (path, expected) in [
        (
            "/datasets/social_registry/household",
            "list_social_registry_household_records",
        ),
        (
            "/datasets/social_registry/household/{id}",
            "get_social_registry_household_record",
        ),
        (
            "/datasets/social_registry/household/verify",
            "verify_social_registry_household_record",
        ),
        (
            "/datasets/social_registry/household/aggregates",
            "list_social_registry_household_aggregates",
        ),
        (
            "/datasets/social_registry/household/aggregates/{aggregate_id}",
            "run_social_registry_household_aggregate",
        ),
        (
            "/datasets/social_registry/household/schema",
            "get_social_registry_household_field_schema",
        ),
        (
            "/datasets/social_registry/household/{id}/members",
            "get_social_registry_household_members",
        ),
        (
            "/catalog/datasets/social_registry/household/schema.jsonld",
            "get_social_registry_household_shacl_shape",
        ),
    ] {
        assert_eq!(
            body["paths"][path]["get"]["operationId"], expected,
            "{path} must declare a stable operationId"
        );
    }

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
    let collection_responses =
        &body["paths"]["/datasets/social_registry/household"]["get"]["responses"];
    for code in ["401", "403", "default"] {
        assert_eq!(
            collection_responses[code]["content"]["application/problem+json"]["schema"]["$ref"],
            "#/components/schemas/ProblemDetails",
            "collection responses[{code}] must point at ProblemDetails"
        );
    }
    let record_responses =
        &body["paths"]["/datasets/social_registry/household/{id}"]["get"]["responses"];
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
    let collection_params = body["paths"]["/datasets/social_registry/household"]["get"]
        ["parameters"]
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
        "/datasets/social_registry/household",
        "/datasets/social_registry/household/{id}",
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
        "/datasets/social_registry/household",
        "/datasets/social_registry/household/{id}",
        "/datasets/social_registry/household/verify",
        "/datasets/social_registry/household/{id}/members",
    ] {
        let param = purpose_param(gated)
            .unwrap_or_else(|| panic!("{gated} must declare the Data-Purpose header parameter"));
        assert_eq!(param["required"], serde_json::json!(true), "{gated}");
        assert_eq!(param["schema"]["type"], "string", "{gated}");
        assert_eq!(param["schema"]["minLength"], 1, "{gated}");
    }
    for ungated in [
        "/datasets/social_registry/household/schema",
        "/datasets/social_registry/household/aggregates",
    ] {
        assert!(
            purpose_param(ungated).is_none(),
            "{ungated} does not enforce purpose; OpenAPI must not declare the header"
        );
    }
}

#[tokio::test]
async fn single_entity_schema_jsonld_returns_etag_and_honors_if_none_match() {
    let server = server();
    let resp = server
        .get("/catalog/datasets/social_registry/household/schema.jsonld")
        .await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();

    let cached = server
        .get("/catalog/datasets/social_registry/household/schema.jsonld")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::NOT_MODIFIED);
    assert_eq!(cached.header("etag").to_str().expect("etag"), etag);
}

#[tokio::test]
async fn catalog_filters_entities_inside_same_dataset_by_metadata_scope() {
    let resp = server_with_scopes(&["social_registry:individual:metadata"])
        .get("/catalog")
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
async fn verify_only_scope_cannot_read_catalog() {
    let resp = server_with_scopes(&["social_registry:verify"])
        .get("/catalog")
        .await;

    resp.assert_status(StatusCode::FORBIDDEN);
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}

#[tokio::test]
async fn metadata_scope_for_one_dataset_cannot_read_other_dataset_schema() {
    let resp = server()
        .get("/catalog/datasets/payments/payment/schema.jsonld")
        .await;

    resp.assert_status(StatusCode::FORBIDDEN);
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
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
        .get("/catalog/datasets/social_registry/missing/schema.jsonld")
        .await;

    resp.assert_status(StatusCode::NOT_FOUND);
    let body: Value = resp.json();
    assert_eq!(body["code"], "schema.unknown_resource");
}

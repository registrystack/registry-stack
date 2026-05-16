// SPDX-License-Identifier: Apache-2.0
//! Catalog metadata tests for entity-grain JSON and JSON-LD outputs.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::Extension;
use axum_test::TestServer;
use data_gate::api::{catalog_router, openapi_router};
use data_gate::auth::{AuthMode, Principal, ScopeSet};
use data_gate::config;
use data_gate::entity::EntityRegistry;
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
    let cfg = Arc::new(config::load(&write_config(&tmp)).expect("config loads"));
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry compiles"));

    TestServer::new(
        catalog_router::<()>()
            .merge(openapi_router())
            .layer(Extension(registry))
            .layer(Extension(cfg))
            .layer(Extension(principal(scopes))),
    )
}

fn principal(scopes: &[&str]) -> Principal {
    Principal {
        api_key_id: "test".to_string(),
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
    assert_eq!(distribution["dct:format"]["@id"], "data_gate:HttpData-PULL");
    assert_eq!(
        distribution["dcat:accessService"]["@type"],
        "dcat:DataService"
    );
    assert_eq!(
        distribution["dcat:accessService"]["dspace:dataServiceType"],
        "data_gate:entity-rest"
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
    assert_eq!(household["data_gate:primaryKey"], "id");
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
                && property["data_gate:targetEntity"] == "individual"
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
    if std::env::var("DATAGATE_RUN_EXTERNAL_SHACL").as_deref() != Ok("1") {
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

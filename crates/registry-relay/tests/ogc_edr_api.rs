// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "ogcapi-edr")]

use std::sync::Arc;

use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::Extension;
use axum_test::TestServer;
use datafusion::arrow::array::StringArray;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use registry_relay::api::edr_router;
use registry_relay::audit::{audit_layer, AuditPipeline, InMemorySink};
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use registry_relay::config::{self, DatasetId, ResourceId};
use registry_relay::entity::EntityRegistry;
use registry_relay::ingest::table_name;
use registry_relay::query::{AggregateQueryEngine, EntityQueryEngine};
use serde_json::{json, Value};
use tempfile::TempDir;

fn principal(scopes: &[&str]) -> Principal {
    principal_with_id(scopes, "test-principal")
}

fn principal_with_id(scopes: &[&str], principal_id: &str) -> Principal {
    Principal {
        principal_id: principal_id.to_string(),
        scopes: scopes.iter().copied().collect::<ScopeSet>(),
        auth_mode: AuthMode::ApiKey,
    }
}

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

fn server(scopes: &[&str]) -> TestServer {
    server_with_options(scopes, false, true, 100)
}

fn server_with_options(
    scopes: &[&str],
    require_purpose_header: bool,
    include_spatial_filter: bool,
    max_geometry_vertices: u32,
) -> TestServer {
    server_from_config(
        scopes,
        edr_config_yaml(
            require_purpose_header,
            include_spatial_filter,
            max_geometry_vertices,
            false,
        ),
    )
}

fn server_with_aggregate_only_execution(scopes: &[&str]) -> TestServer {
    server_from_config(
        scopes,
        edr_config_yaml_with_geometry_read_scope(
            false,
            true,
            100,
            true,
            "social_registry:geometry",
        )
        .replace("min_group_size: 1", "min_group_size: 2"),
    )
}

fn server_with_source_entity_api_extra(
    scopes: &[&str],
    require_purpose_header: bool,
    entity_api_extra: &str,
) -> TestServer {
    let yaml = edr_config_yaml(require_purpose_header, true, 100, false).replacen(
        &format!(
            "          require_purpose_header: {}\n",
            if require_purpose_header {
                "true"
            } else {
                "false"
            }
        ),
        &format!(
            "          require_purpose_header: {}\n{}",
            if require_purpose_header {
                "true"
            } else {
                "false"
            },
            entity_api_extra
        ),
        1,
    );
    server_from_config(scopes, yaml)
}

fn server_with_aggregate_only_source_entity_api_extra(
    scopes: &[&str],
    entity_api_extra: &str,
) -> TestServer {
    let yaml = edr_config_yaml_with_geometry_read_scope(
        false,
        true,
        100,
        true,
        "social_registry:geometry",
    )
    .replace("min_group_size: 1", "min_group_size: 2")
    .replacen(
        "          require_purpose_header: false\n",
        &format!("          require_purpose_header: false\n{entity_api_extra}"),
        1,
    );
    server_from_config(scopes, yaml)
}

fn server_with_geometry_entity_api_extra_and_principal_id(
    scopes: &[&str],
    geometry_entity_api_extra: &str,
    principal_id: &str,
) -> TestServer {
    let mut yaml = edr_config_yaml_with_geometry_read_scope(
        false,
        true,
        100,
        true,
        "social_registry:geometry",
    )
    .replace("min_group_size: 1", "min_group_size: 2");
    let marker = "          max_limit: 10000\n";
    let insert_at = yaml.rfind(marker).expect("municipality api max_limit") + marker.len();
    yaml.insert_str(insert_at, geometry_entity_api_extra);
    server_from_config_with_principal_id(scopes, yaml, principal_id)
}

fn server_with_source_entity_api_extra_and_audit(
    scopes: &[&str],
    require_purpose_header: bool,
    entity_api_extra: &str,
) -> (TestServer, InMemorySink) {
    let yaml = edr_config_yaml(require_purpose_header, true, 100, false).replacen(
        &format!(
            "          require_purpose_header: {}\n",
            if require_purpose_header {
                "true"
            } else {
                "false"
            }
        ),
        &format!(
            "          require_purpose_header: {}\n{}",
            if require_purpose_header {
                "true"
            } else {
                "false"
            },
            entity_api_extra
        ),
        1,
    );
    server_from_config_with_audit(scopes, yaml)
}

fn server_from_config(scopes: &[&str], yaml: String) -> TestServer {
    server_from_config_with_principal_id(scopes, yaml, "test-principal")
}

fn server_from_config_with_principal_id(
    scopes: &[&str],
    yaml: String,
    principal_id: &str,
) -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("ogc_edr.yaml");
    std::fs::write(&config_path, yaml).expect("write config");
    let cfg = Arc::new(
        config::load(&config_path)
            .unwrap_or_else(|err| panic!("config loads for {}: {err:?}", config_path.display())),
    );
    std::mem::forget(tmp);

    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());
    register_individuals(&ctx);
    register_municipalities(&ctx);

    let entity_query = Arc::new(EntityQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
    ));
    let aggregate_query = Arc::new(AggregateQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
        Arc::clone(&cfg),
    ));

    TestServer::new(
        edr_router::<()>()
            .layer(Extension(entity_query))
            .layer(Extension(aggregate_query))
            .layer(Extension(registry))
            .layer(Extension(cfg))
            .layer(Extension(principal_with_id(scopes, principal_id))),
    )
}

fn server_from_config_with_audit(scopes: &[&str], yaml: String) -> (TestServer, InMemorySink) {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("ogc_edr.yaml");
    std::fs::write(&config_path, yaml).expect("write config");
    let cfg = Arc::new(
        config::load(&config_path)
            .unwrap_or_else(|err| panic!("config loads for {}: {err:?}", config_path.display())),
    );
    std::mem::forget(tmp);

    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());
    register_individuals(&ctx);
    register_municipalities(&ctx);

    let entity_query = Arc::new(EntityQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
    ));
    let aggregate_query = Arc::new(AggregateQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
        Arc::clone(&cfg),
    ));
    let audit_sink = InMemorySink::new();
    let audit_pipeline: Arc<AuditPipeline> = AuditPipeline::from_sink(audit_sink.clone());

    let app = edr_router::<()>()
        .layer(Extension(entity_query))
        .layer(Extension(aggregate_query))
        .layer(Extension(registry))
        .layer(Extension(cfg))
        .layer(Extension(principal(scopes)))
        .layer(from_fn(audit_layer))
        .layer(Extension(audit_pipeline));

    (TestServer::new(app), audit_sink)
}

fn audit_record_from_envelope(line: &str) -> Value {
    let envelope: Value = serde_json::from_str(line.trim_end()).expect("valid audit envelope JSON");
    envelope["record"].clone()
}

fn edr_config_yaml(
    require_purpose_header: bool,
    include_spatial_filter: bool,
    max_geometry_vertices: u32,
    aggregate_only_execution: bool,
) -> String {
    edr_config_yaml_with_geometry_read_scope(
        require_purpose_header,
        include_spatial_filter,
        max_geometry_vertices,
        aggregate_only_execution,
        "social_registry:rows",
    )
}

fn edr_config_yaml_with_geometry_read_scope(
    require_purpose_header: bool,
    include_spatial_filter: bool,
    max_geometry_vertices: u32,
    aggregate_only_execution: bool,
    geometry_read_scope: &str,
) -> String {
    let spatial_filter = if include_spatial_filter {
        r#"          - field: municipality
            ops: [eq, in]"#
    } else {
        "          []"
    };
    r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test

deployment:
  profile: local

vocabularies: {}

auth:
  mode: api_key
  api_keys: []

audit:
  sink: stdout
  format: jsonl

datasets:
  - id: social_registry
    title: Social Registry
    description: Synthetic social registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    defaults:
      refresh:
        mode: manual
    tables:
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
            - name: municipality_code
              type: string
              nullable: false
      - id: municipalities_table
        source:
          type: file
          path: fixtures/municipalities.csv
        primary_key: code
        schema:
          strict: true
          fields:
            - name: code
              type: string
              nullable: false
            - name: geometry
              type: string
              nullable: false
    aggregates:
      - id: beneficiaries_by_municipality
        title: Beneficiaries by municipality
        description: Beneficiary count by municipality
        source_entity: individual
        access:
          aggregate_only_execution: __AGGREGATE_ONLY_EXECUTION__
        default_group_by:
          - municipality
        dimensions:
          - id: municipality
            label: Municipality
            field: municipality
        indicators:
          - id: individual_count
            label: Individuals
            function: count
            column: id
            unit_measure: people
        allowed_filters:
__SPATIAL_FILTER__
        disclosure_control:
          min_group_size: 1
          suppression: "null"
        spatial:
          mode: admin_area
          dimension: municipality
          geometry_entity: municipality
          geometry_id_field: code
          geometry_field: geometry
          max_geometry_vertices: __MAX_GEOMETRY_VERTICES__
    entities:
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
          - name: municipality
            from: municipality_code
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 10000
          require_purpose_header: __REQUIRE_PURPOSE_HEADER__
      - name: municipality
        table: municipalities_table
        fields:
          - name: code
          - name: geometry
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: __GEOMETRY_READ_SCOPE__
        api:
          default_limit: 100
          max_limit: 10000
"#
    .replace("__SPATIAL_FILTER__", spatial_filter)
    .replace(
        "__MAX_GEOMETRY_VERTICES__",
        &max_geometry_vertices.to_string(),
    )
    .replace(
        "__REQUIRE_PURPOSE_HEADER__",
        if require_purpose_header {
            "true"
        } else {
            "false"
        },
    )
    .replace(
        "__AGGREGATE_ONLY_EXECUTION__",
        if aggregate_only_execution {
            "true"
        } else {
            "false"
        },
    )
    .replace("__GEOMETRY_READ_SCOPE__", geometry_read_scope)
}

fn register_individuals(ctx: &SessionContext) {
    let schema = Arc::new(Schema::new(vec![
        Field::new("individual_id", DataType::Utf8, false),
        Field::new("municipality_code", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["ind-1", "ind-2", "ind-3"])),
            Arc::new(StringArray::from(vec!["mun-1", "mun-1", "mun-2"])),
        ],
    )
    .expect("individual batch");
    let table = MemTable::try_new(schema, vec![vec![batch]]).expect("individual table");
    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("individuals_table");
    ctx.register_table(table_name(&dataset, &resource), Arc::new(table))
        .expect("register individuals");
}

fn register_municipalities(ctx: &SessionContext) {
    let schema = Arc::new(Schema::new(vec![
        Field::new("code", DataType::Utf8, false),
        Field::new("geometry", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["mun-1", "mun-2"])),
            Arc::new(StringArray::from(vec![
                r#"{"type":"Polygon","coordinates":[[[0,0],[1,0],[1,1],[0,1],[0,0]]]}"#,
                r#"{"type":"Polygon","coordinates":[[[2,0],[3,0],[3,1],[2,1],[2,0]]]}"#,
            ])),
        ],
    )
    .expect("municipality batch");
    let table = MemTable::try_new(schema, vec![vec![batch]]).expect("municipality table");
    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("municipalities_table");
    ctx.register_table(table_name(&dataset, &resource), Arc::new(table))
        .expect("register municipalities");
}

#[tokio::test]
async fn landing_conformance_and_collections_are_metadata_scoped() {
    let server = server(&["social_registry:metadata"]);

    let landing = server.get("/ogc/edr/v1").await;
    landing.assert_status_ok();
    let body: Value = landing.json();
    assert_eq!(body["title"], "Registry Relay OGC EDR API");

    let conformance = server.get("/ogc/edr/v1/conformance").await;
    conformance.assert_status_ok();
    let body: Value = conformance.json();
    let conforms_to = body["conformsTo"].as_array().expect("conformsTo");
    assert!(conforms_to.iter().any(|value| value
        .as_str()
        .is_some_and(|uri| uri.ends_with("/conf/area"))));
    assert!(!conforms_to.iter().any(|value| value
        .as_str()
        .is_some_and(|uri| uri.ends_with("/conf/position") || uri.ends_with("/conf/radius"))));

    let collections = server.get("/ogc/edr/v1/collections").await;
    collections.assert_status_ok();
    let body: Value = collections.json();
    assert_eq!(
        body["collections"][0]["id"],
        "social_registry_beneficiaries_by_municipality"
    );
}

#[tokio::test]
async fn area_get_wkt_returns_grouped_admin_features() {
    let server = server(&[
        "social_registry:metadata",
        "social_registry:aggregate",
        "social_registry:rows",
    ]);

    let resp = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param(
            "coords",
            "POLYGON ((-0.5 -0.5, 1.5 -0.5, 1.5 1.5, -0.5 1.5, -0.5 -0.5))",
        )
        .add_query_param("parameter-name", "individual_count")
        .add_query_param("group_by", "municipality")
        .add_query_param("f", "geojson")
        .await;

    if !resp.status_code().is_success() {
        panic!("unexpected area GET response: {}", resp.text());
    }
    assert_eq!(
        resp.header("content-type").to_str().unwrap_or(""),
        "application/geo+json"
    );
    let body: Value = resp.json();
    assert_eq!(body["type"], "FeatureCollection");
    assert_eq!(body["dataset_id"], "social_registry");
    assert_eq!(body["aggregate_id"], "beneficiaries_by_municipality");
    assert!(body.get("crs").is_none());
    assert!(
        body["disclosure_control"].get("suppressed_rows").is_none(),
        "legacy suppressed_rows key must be absent from the EDR disclosure block"
    );
    assert!(
        body["disclosure_control"]
            .get("suppressed_observations")
            .is_some(),
        "suppressed_observations must be present in the EDR disclosure block"
    );
    let features = body["features"].as_array().expect("features");
    assert_eq!(features.len(), 1);
    assert_eq!(features[0]["properties"]["municipality"], "mun-1");
    assert_eq!(features[0]["properties"]["individual_count"], 2);
    assert_eq!(features[0]["properties"]["_min_cell_size"], 1);
    assert_eq!(features[0]["geometry"]["type"], "Polygon");
}

#[tokio::test]
async fn area_post_geojson_returns_single_submitted_geometry_feature() {
    let server = server(&[
        "social_registry:metadata",
        "social_registry:aggregate",
        "social_registry:rows",
    ]);

    let resp = server
        .post("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .json(&json!({
            "type": "Feature",
            "properties": {
                "measures": ["individual_count"],
                "filters": { "municipality": "mun-2" }
            },
            "geometry": {
            "type": "Polygon",
            "coordinates": [[[-0.5, -0.5], [3.5, -0.5], [3.5, 1.5], [-0.5, 1.5], [-0.5, -0.5]]]
            }
        }))
        .await;

    if !resp.status_code().is_success() {
        panic!("unexpected area POST response: {}", resp.text());
    }
    let body: Value = resp.json();
    assert!(body.get("crs").is_none());
    assert_eq!(body["schema"]["measures"][0]["id"], "individual_count");
    assert!(body["schema"].get("indicators").is_none());
    let features = body["features"].as_array().expect("features");
    assert_eq!(features.len(), 1);
    assert_eq!(features[0]["geometry"]["type"], "Polygon");
    assert_eq!(features[0]["properties"]["individual_count"], 1);
    assert_eq!(features[0]["properties"]["_suppressed"], false);
}

#[tokio::test]
async fn area_enforces_source_entity_purpose_header() {
    let policy = r#"          governed_policy:
            permitted_purposes:
              - capacity planning
            trusted_context: {}
"#;
    let server = server_with_source_entity_api_extra(
        &[
            "social_registry:metadata",
            "social_registry:aggregate",
            "social_registry:rows",
        ],
        true,
        policy,
    );

    let missing = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .await;
    missing.assert_status_bad_request();
    assert_eq!(missing.json::<Value>()["code"], "auth.purpose_required");

    let blank = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .add_header("data-purpose", "   ")
        .await;
    blank.assert_status_bad_request();
    assert_eq!(blank.json::<Value>()["code"], "auth.purpose_required");

    let denied = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .add_header("data-purpose", "casework")
        .await;
    denied.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(denied.json::<Value>()["code"], "pdp.purpose_not_permitted");

    let ok = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .add_header("data-purpose", "capacity planning")
        .await;
    ok.assert_status_ok();
}

#[tokio::test]
async fn area_governed_denial_audit_records_pdp_provenance() {
    let policy = r#"          governed_policy:
            permitted_purposes:
              - capacity planning
            trusted_context: {}
"#;
    let (server, audit_sink) = server_with_source_entity_api_extra_and_audit(
        &[
            "social_registry:metadata",
            "social_registry:aggregate",
            "social_registry:rows",
        ],
        false,
        policy,
    );

    let response = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .add_header("data-purpose", "casework")
        .await;

    response.assert_status_forbidden();
    assert_eq!(
        response.json::<Value>()["code"],
        "pdp.purpose_not_permitted"
    );

    let records = audit_sink.snapshot();
    assert_eq!(
        records.len(),
        1,
        "denied governed EDR area request emits one audit record"
    );
    let record = audit_record_from_envelope(&records[0]);
    assert_eq!(
        record["path"],
        "/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area"
    );
    assert_eq!(record["dataset_id"], "social_registry");
    assert_eq!(record["aggregate_id"], "beneficiaries_by_municipality");
    assert_eq!(
        record["collection_id"],
        "social_registry_beneficiaries_by_municipality"
    );
    assert_eq!(record["purpose"], "casework");
    assert_eq!(record["status_code"], 403);
    assert_eq!(record["error_code"], "pdp.purpose_not_permitted");
    assert_eq!(
        record["pdp_policy_id"],
        "relay.entity.individual.purpose-required"
    );
    assert!(
        record["pdp_policy_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() == 71),
        "audit record should include a stable sha256 PDP policy hash: {record}"
    );
    assert_eq!(
        record["pdp_evaluated_rule_ids"],
        json!([
            "entity-purpose-required:individual.policy_identity",
            "entity-purpose-required:individual.purpose"
        ])
    );
}

#[tokio::test]
async fn area_applies_source_entity_governed_redaction_to_feature_properties() {
    let policy = r#"          governed_policy:
            permitted_purposes:
              - capacity planning
            redaction_fields: [individual_count]
            trusted_context: {}
"#;
    let server = server_with_source_entity_api_extra(
        &[
            "social_registry:metadata",
            "social_registry:aggregate",
            "social_registry:rows",
        ],
        false,
        policy,
    );

    let response = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .add_query_param("parameter-name", "individual_count")
        .add_query_param("group_by", "municipality")
        .add_header("data-purpose", "capacity planning")
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    let features = body["features"].as_array().expect("features");
    assert_eq!(features.len(), 1);
    assert_eq!(features[0]["properties"]["municipality"], "mun-1");
    assert!(
        features[0]["properties"].get("individual_count").is_none(),
        "redacted aggregate measure must not be present in EDR feature properties"
    );
}

#[tokio::test]
async fn area_rejects_unsupported_response_format_with_aggregate_code() {
    let server = server(&[
        "social_registry:metadata",
        "social_registry:aggregate",
        "social_registry:rows",
    ]);

    let resp = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .add_query_param("f", "xml")
        .await;

    resp.assert_status_bad_request();
    assert_eq!(resp.json::<Value>()["code"], "aggregate.format_unsupported");
}

#[tokio::test]
async fn area_rejects_oversized_request_geometry() {
    let server = server_with_options(
        &[
            "social_registry:metadata",
            "social_registry:aggregate",
            "social_registry:rows",
        ],
        false,
        true,
        5,
    );

    let resp = server
        .post("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .json(&json!({
            "type": "Polygon",
            "coordinates": [[
                [0.0, 0.0],
                [1.0, 0.0],
                [1.0, 1.0],
                [0.5, 1.5],
                [0.0, 1.0],
                [0.0, 0.0]
            ]]
        }))
        .await;

    resp.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(resp.json::<Value>()["code"], "spatial.geometry_too_large");
}

#[tokio::test]
async fn area_no_matching_admin_geometry_returns_empty_feature_collection() {
    let server = server(&[
        "social_registry:metadata",
        "social_registry:aggregate",
        "social_registry:rows",
    ]);

    let resp = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((10 10, 11 10, 11 11, 10 11, 10 10))")
        .add_query_param("parameter-name", "individual_count")
        .add_query_param("group_by", "municipality")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["type"], "FeatureCollection");
    assert!(body["features"].as_array().expect("features").is_empty());
}

#[test]
fn spatial_aggregate_requires_in_filter_on_area_dimension() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("ogc_edr_invalid.yaml");
    std::fs::write(&config_path, edr_config_yaml(false, false, 100, false)).expect("write config");

    config::load(&config_path).expect_err("spatial aggregate without in filter is rejected");
}

#[tokio::test]
async fn area_requires_aggregate_scope() {
    let server = server(&["social_registry:metadata"]);

    let resp = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .await;

    resp.assert_status_forbidden();
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}

#[tokio::test]
async fn area_requires_source_entity_read_scope() {
    let server = server(&["social_registry:metadata", "social_registry:aggregate"]);

    let resp = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .await;

    resp.assert_status_forbidden();
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}

#[tokio::test]
async fn area_requires_geometry_entity_read_scope() {
    let server = server_from_config(
        &[
            "social_registry:metadata",
            "social_registry:aggregate",
            "social_registry:rows",
        ],
        edr_config_yaml_with_geometry_read_scope(
            false,
            true,
            100,
            false,
            "social_registry:geometry",
        ),
    );

    let resp = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .await;

    resp.assert_status_forbidden();
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}

#[tokio::test]
async fn area_aggregate_only_execution_requires_geometry_entity_read_scope() {
    let server = server_with_aggregate_only_execution(&[
        "social_registry:metadata",
        "social_registry:aggregate",
    ]);

    let resp = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .add_query_param("parameter-name", "individual_count")
        .add_query_param("group_by", "municipality")
        .await;

    resp.assert_status_forbidden();
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}

#[tokio::test]
async fn area_allows_aggregate_only_execution_when_explicitly_configured() {
    let server = server_with_aggregate_only_execution(&[
        "social_registry:metadata",
        "social_registry:aggregate",
        "social_registry:geometry",
    ]);

    let resp = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .add_query_param("parameter-name", "individual_count")
        .add_query_param("group_by", "municipality")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    let features = body["features"].as_array().expect("features");
    assert_eq!(features.len(), 1);
    assert_eq!(features[0]["properties"]["municipality"], "mun-1");
    assert_eq!(features[0]["properties"]["individual_count"], 2);
}

#[tokio::test]
async fn area_geometry_scan_uses_principal_bound_required_filter() {
    let server = server_with_geometry_entity_api_extra_and_principal_id(
        &[
            "social_registry:metadata",
            "social_registry:aggregate",
            "social_registry:geometry",
        ],
        r#"          required_filters:
            - code
          required_filter_bindings:
            - field: code
              source: principal_id
"#,
        "mun-1",
    );

    let resp = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .add_query_param("parameter-name", "individual_count")
        .add_query_param("group_by", "municipality")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    let features = body["features"].as_array().expect("features");
    assert_eq!(features.len(), 1);
    assert_eq!(features[0]["properties"]["municipality"], "mun-1");
    assert_eq!(features[0]["properties"]["individual_count"], 2);
}

#[tokio::test]
async fn area_aggregate_only_governed_policy_uses_aggregate_checked_scope() {
    let policy = r#"          governed_policy:
            permitted_purposes:
              - capacity planning
            trusted_context: {}
"#;
    let server = server_with_aggregate_only_source_entity_api_extra(
        &[
            "social_registry:metadata",
            "social_registry:aggregate",
            "social_registry:geometry",
        ],
        policy,
    );

    let resp = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .add_query_param("parameter-name", "individual_count")
        .add_query_param("group_by", "municipality")
        .add_header("data-purpose", "capacity planning")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    let features = body["features"].as_array().expect("features");
    assert_eq!(features.len(), 1);
    assert_eq!(features[0]["properties"]["municipality"], "mun-1");
    assert_eq!(features[0]["properties"]["individual_count"], 2);
}

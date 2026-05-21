// SPDX-License-Identifier: Apache-2.0
//! OGC spatial config validation tests.

use registry_relay::config::{SpatialGeometryConfig, CRS84};
use registry_relay::entity::EntityRegistry;
use tempfile::TempDir;

fn write_config(tmp: &TempDir, body: &str) -> std::path::PathBuf {
    let path = tmp.path().join("ogc.yaml");
    std::fs::write(&path, body).expect("write config");
    path
}

fn base_config(datasets: &str) -> String {
    format!(
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test

vocabularies: {{}}

auth:
  mode: api_key
  api_keys: []

datasets:
{datasets}

audit:
  sink: stdout
  format: jsonl
"#
    )
}

fn civic_dataset(dataset_id: &str, entity_name: &str, spatial: &str) -> String {
    format!(
        r#"
  - id: {dataset_id}
    title: Civic Registry
    description: Synthetic civic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    defaults:
      refresh:
        mode: manual
    tables:
      - id: facilities_table
        source:
          type: file
          path: fixtures/civic_registry.xlsx
        primary_key: facility_id
        schema:
          strict: true
          fields:
            - name: facility_id
              type: string
              nullable: false
            - name: lon
              type: number
              nullable: true
            - name: lat
              type: number
              nullable: true
            - name: bbox_min_x
              type: number
              nullable: true
            - name: bbox_min_y
              type: number
              nullable: true
            - name: bbox_max_x
              type: number
              nullable: true
            - name: bbox_max_y
              type: number
              nullable: true
            - name: geometry
              type: string
              nullable: true
            - name: updated_at
              type: timestamp
              nullable: true
            - name: label
              type: string
              nullable: true
    entities:
      - name: {entity_name}
        table: facilities_table
        fields:
          - name: id
            from: facility_id
          - name: lon
          - name: lat
          - name: bbox_min_x
          - name: bbox_min_y
          - name: bbox_max_x
          - name: bbox_max_y
          - name: geometry
          - name: updated_at
          - name: label
        access:
          metadata_scope: {dataset_id}:metadata
          aggregate_scope: {dataset_id}:aggregate
          read_scope: {dataset_id}:rows
        api:
          default_limit: 100
          max_limit: 1000
{spatial}
"#
    )
}

fn valid_point_spatial() -> String {
    format!(
        r#"        spatial:
          collection_id: facilities
          title: Public facilities
          description: Public facility locations.
          geometry:
            kind: point
            longitude_field: lon
            latitude_field: lat
            crs: {CRS84}
          datetime_field: updated_at
          max_bbox_degrees: 5.0
          max_geometry_vertices: 10000
"#
    )
}

fn load_config(
    datasets: &str,
) -> Result<registry_relay::config::Config, registry_relay::error::Error> {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(&tmp, &base_config(datasets));
    registry_relay::config::load(&path)
}

#[test]
fn point_spatial_config_loads_and_compiles_into_entity_model() {
    let config = load_config(&civic_dataset(
        "civic_registry",
        "facility",
        &valid_point_spatial(),
    ))
    .expect("spatial config loads");
    let registry = EntityRegistry::from_config(&config).expect("entity registry compiles");
    let entity = registry
        .dataset("civic_registry")
        .and_then(|dataset| dataset.entity("facility"))
        .expect("facility entity");
    let spatial = entity.spatial.as_ref().expect("spatial model");

    assert_eq!(spatial.collection_id, "facilities");
    assert_eq!(spatial.max_bbox_degrees, 5.0);
    assert_eq!(spatial.max_geometry_vertices, 10_000);
    assert_eq!(spatial.datetime_field.as_deref(), Some("updated_at"));
    assert!(matches!(
        spatial.geometry,
        SpatialGeometryConfig::Point { .. }
    ));
}

#[test]
fn collection_id_defaults_to_entity_name_and_may_repeat_across_datasets() {
    let spatial = format!(
        r#"        spatial:
          geometry:
            kind: point
            longitude_field: lon
            latitude_field: lat
            crs: {CRS84}
"#
    );
    let datasets = format!(
        "{}\n{}",
        civic_dataset("civic_registry", "facility", &spatial),
        civic_dataset("other_registry", "facility", &spatial)
    );
    let config = load_config(&datasets).expect("spatial config loads");
    let registry = EntityRegistry::from_config(&config).expect("entity registry compiles");

    for dataset_id in ["civic_registry", "other_registry"] {
        let spatial = registry
            .dataset(dataset_id)
            .and_then(|dataset| dataset.entity("facility"))
            .and_then(|entity| entity.spatial.as_ref())
            .expect("spatial model");
        assert_eq!(spatial.collection_id, "facility");
        assert_eq!(spatial.max_bbox_degrees, 5.0);
        assert_eq!(spatial.max_geometry_vertices, 10_000);
    }
}

#[test]
fn duplicate_collection_id_within_dataset_is_rejected() {
    let first = civic_dataset("civic_registry", "facility", &valid_point_spatial());
    let second_entity = r#"
      - name: parcel
        table: facilities_table
        fields:
          - name: id
            from: facility_id
          - name: lon
          - name: lat
        access:
          metadata_scope: civic_registry:metadata
          aggregate_scope: civic_registry:aggregate
          read_scope: civic_registry:rows
        api:
          default_limit: 100
          max_limit: 1000
        spatial:
          collection_id: facilities
          geometry:
            kind: point
            longitude_field: lon
            latitude_field: lat
            crs: http://www.opengis.net/def/crs/OGC/1.3/CRS84
"#;
    let dataset = format!("{first}{second_entity}");
    let err = load_config(&dataset).expect_err("duplicate collection id rejected");
    assert_eq!(err.code(), "config.duplicate_id");
}

#[test]
fn non_crs84_geometry_is_rejected() {
    let invalid = valid_point_spatial().replace(CRS84, "EPSG:4326");
    let err = load_config(&civic_dataset("civic_registry", "facility", &invalid))
        .expect_err("non CRS84 rejected");
    assert_eq!(err.code(), "config.validation_error");
}

#[test]
fn point_fields_must_be_numeric_and_exposed() {
    let non_numeric =
        valid_point_spatial().replace("longitude_field: lon", "longitude_field: label");
    let err = load_config(&civic_dataset("civic_registry", "facility", &non_numeric))
        .expect_err("non numeric longitude rejected");
    assert_eq!(err.code(), "config.validation_error");

    let hidden =
        valid_point_spatial().replace("latitude_field: lat", "latitude_field: missing_lat");
    let err = load_config(&civic_dataset("civic_registry", "facility", &hidden))
        .expect_err("missing latitude rejected");
    assert_eq!(err.code(), "config.validation_error");
}

#[test]
fn geojson_bbox_and_datetime_fields_are_validated() {
    let valid = format!(
        r#"        spatial:
          collection_id: parcels
          geometry:
            kind: geojson
            field: geometry
            crs: {CRS84}
          bbox_fields:
            min_x: bbox_min_x
            min_y: bbox_min_y
            max_x: bbox_max_x
            max_y: bbox_max_y
          datetime_field: updated_at
"#
    );
    load_config(&civic_dataset("civic_registry", "facility", &valid))
        .expect("valid geojson spatial config loads");

    let bad_bbox = valid.replace("min_x: bbox_min_x", "min_x: label");
    let err = load_config(&civic_dataset("civic_registry", "facility", &bad_bbox))
        .expect_err("non numeric bbox rejected");
    assert_eq!(err.code(), "config.validation_error");

    let bad_datetime = valid.replace("datetime_field: updated_at", "datetime_field: label");
    let err = load_config(&civic_dataset("civic_registry", "facility", &bad_datetime))
        .expect_err("non temporal datetime rejected");
    assert_eq!(err.code(), "config.validation_error");
}

#[test]
fn spatial_caps_must_be_positive() {
    let invalid_bbox =
        valid_point_spatial().replace("max_bbox_degrees: 5.0", "max_bbox_degrees: 0");
    let err = load_config(&civic_dataset("civic_registry", "facility", &invalid_bbox))
        .expect_err("zero bbox cap rejected");
    assert_eq!(err.code(), "config.validation_error");

    let invalid_vertices =
        valid_point_spatial().replace("max_geometry_vertices: 10000", "max_geometry_vertices: 0");
    let err = load_config(&civic_dataset(
        "civic_registry",
        "facility",
        &invalid_vertices,
    ))
    .expect_err("zero geometry vertex cap rejected");
    assert_eq!(err.code(), "config.validation_error");
}

#[test]
fn spatial_config_rejects_unknown_fields() {
    let invalid = valid_point_spatial().replace(
        "max_geometry_vertices: 10000",
        "max_geometry_vertices: 10000\n          unexpected: true",
    );
    let err = load_config(&civic_dataset("civic_registry", "facility", &invalid))
        .expect_err("unknown spatial field rejected by serde");
    assert_eq!(err.code(), "config.parse_error");
}

#[test]
fn tagged_geometry_rejects_extra_or_missing_source_fields() {
    let extra = valid_point_spatial().replace(
        "latitude_field: lat",
        "latitude_field: lat\n            field: geometry",
    );
    let err = load_config(&civic_dataset("civic_registry", "facility", &extra))
        .expect_err("extra point geometry source rejected");
    assert_eq!(err.code(), "config.parse_error");

    let missing = valid_point_spatial().replace("            longitude_field: lon\n", "");
    let err = load_config(&civic_dataset("civic_registry", "facility", &missing))
        .expect_err("missing point geometry source rejected");
    assert_eq!(err.code(), "config.parse_error");
}

#[test]
fn wkt_and_wkb_parse_but_are_rejected_for_phase_one() {
    for kind in ["wkt", "wkb"] {
        let spatial = format!(
            r#"        spatial:
          collection_id: parcels_{kind}
          geometry:
            kind: {kind}
            field: geometry
            crs: {CRS84}
"#
        );
        let err = load_config(&civic_dataset("civic_registry", "facility", &spatial))
            .expect_err("reserved geometry kind rejected");
        assert_eq!(err.code(), "config.validation_error");
    }
}

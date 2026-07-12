// SPDX-License-Identifier: Apache-2.0
//! Guardrails for binaries built without optional OGC API surfaces.

use tempfile::TempDir;

#[cfg(any(
    not(feature = "ogcapi-features"),
    all(
        feature = "ogcapi-features",
        feature = "ogcapi-edr",
        feature = "ogcapi-records"
    )
))]
const CRS84: &str = "http://www.opengis.net/def/crs/OGC/1.3/CRS84";
const OGC_RECORDS_CORE: &str = "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/record-core";

fn write_config(tmp: &TempDir, body: &str) -> std::path::PathBuf {
    let path = tmp.path().join("ogcapi_feature_flag.yaml");
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

deployment:
  profile: local

vocabularies: {{}}

auth:
  mode: api_key
  api_keys: []

audit:
  sink: stdout
  format: jsonl

datasets:
{datasets}
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

#[cfg(any(
    not(feature = "ogcapi-features"),
    all(
        feature = "ogcapi-features",
        feature = "ogcapi-edr",
        feature = "ogcapi-records"
    )
))]
fn spatial_dataset() -> String {
    format!(
        r#"
  - id: civic_registry
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
    entities:
      - name: facility
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
            crs: {CRS84}
"#
    )
}

fn edr_dataset() -> String {
    r#"
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
          - field: municipality
            ops: [eq, in]
        disclosure_control:
          min_group_size: 1
          suppression: "null"
        spatial:
          mode: admin_area
          dimension: municipality
          geometry_entity: municipality
          geometry_id_field: code
          geometry_field: geometry
          max_geometry_vertices: 10000
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
          max_limit: 1000
      - name: municipality
        table: municipalities_table
        fields:
          - name: code
          - name: geometry
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000
"#
    .to_string()
}

fn records_dataset() -> String {
    format!(
        r#"
  - id: catalog_registry
    title: Catalog Registry
    description: Synthetic catalog registry
    owner: Test
    sensitivity: internal
    access_rights: public
    update_frequency: monthly
    conforms_to:
      - {OGC_RECORDS_CORE}
    defaults:
      refresh:
        mode: manual
    tables:
      - id: records_table
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
      - name: catalog_record
        table: records_table
        fields:
          - name: id
            from: payment_id
        access:
          metadata_scope: catalog_registry:metadata
          aggregate_scope: catalog_registry:aggregate
          read_scope: catalog_registry:rows
        api:
          default_limit: 100
          max_limit: 1000
"#
    )
}

#[cfg(not(feature = "ogcapi-features"))]
#[test]
fn spatial_config_requires_ogcapi_features_feature() {
    let err =
        load_config(&spatial_dataset()).expect_err("feature-disabled binary must reject spatial");
    assert_eq!(err.code(), "ogcapi.features.config.feature_disabled");
}

#[cfg(not(feature = "ogcapi-edr"))]
#[test]
fn aggregate_spatial_config_requires_ogcapi_edr_feature() {
    let err = load_config(&edr_dataset())
        .expect_err("feature-disabled binary must reject aggregate spatial");
    assert_eq!(err.code(), "ogcapi.edr.config.feature_disabled");
}

#[cfg(not(feature = "ogcapi-records"))]
#[test]
fn ogc_records_conformance_config_requires_ogcapi_records_feature() {
    let err = load_config(&records_dataset())
        .expect_err("feature-disabled binary must reject OGC Records config");
    assert_eq!(err.code(), "ogcapi.records.config.feature_disabled");
}

#[cfg(all(
    feature = "ogcapi-features",
    feature = "ogcapi-edr",
    feature = "ogcapi-records"
))]
#[test]
fn all_ogc_feature_configs_load_when_features_are_enabled() {
    load_config(&format!(
        "{}\n{}\n{}",
        spatial_dataset(),
        edr_dataset(),
        records_dataset()
    ))
    .expect("all OGC configs load with their features enabled");
}
